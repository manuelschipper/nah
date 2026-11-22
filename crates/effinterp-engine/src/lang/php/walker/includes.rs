//! PHP includes resolved through supplied sources with once and cycle semantics.

use std::collections::HashMap;

use effinterp_proto::{BoundaryClass, BoundaryReason, ResourceExpr, ResourceIdentity, Subject};
use tree_sitter::Node;

use crate::nest::{SourceResolution, Transition};
use crate::paths::{join_file, parent_dir};
use crate::{SourcePurpose, SourceRefusal};

use super::super::analyze_file;
use super::super::syntax::{arg_nodes, child_kind, literal_string, text};
use super::PhpWalker;
use super::resource_recovery::resource_fs_path;

/// The include-graph cwd anchored to the source root, so `__DIR__` composes
/// with `..` correctly whether the analysis root was handed an absolute or a
/// repo-relative directory.
fn anchored(cwd: &str) -> String {
    if cwd.starts_with('/') {
        cwd.to_string()
    } else {
        format!("/{cwd}")
    }
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// Execute a `require`/`include` (`once` for the `_once` forms): evaluate
    /// the path statically, apply once/cycle semantics, and analyze the
    /// included file as a budget-bounded nested invocation so its effects
    /// chain back through the include site. A dynamic or unresolvable path is
    /// a typed boundary, never silence.
    pub(super) fn follow_php_include(
        &mut self,
        n: Node<'a>,
        once: bool,
        env: &HashMap<String, ResourceExpr>,
    ) {
        let mut c = n.walk();
        let expr = n.named_children(&mut c).next();
        // A URL target is fetched and its body run as PHP when
        // `allow_url_include` is on, which a `-d` option or an unobserved
        // php.ini can set; the fetched source is not analyzed.
        if let Some(target) = expr
            && literal_string(target, self.src).is_some_and(|url| {
                ["http://", "https://", "ftp://"].iter().any(|scheme| {
                    url.get(..scheme.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
                })
            })
        {
            let request = self.net_slot(Some(target), env, n);
            let execution = self.emit(
                self.interpreter_effect("process.code_execution", ("source", "argument")),
                n,
            );
            self.record_transfer(request, execution);
            self.opaque_with_detail(
                BoundaryReason::UNRESOLVED_INCLUDE,
                BoundaryClass::Unresolved,
                n,
                Some("remote included source is not analyzed".to_string()),
            );
            return;
        }
        let Some(spec) = expr.and_then(|e| self.resolve_php_source_path(e, env)) else {
            self.opaque(
                BoundaryReason::DYNAMIC_INCLUDE,
                BoundaryClass::Unresolved,
                n,
            );
            return;
        };
        let Some(path) = join_file(self.source_cwd, &spec).map(|p| anchored(&p)) else {
            self.opaque(
                BoundaryReason::UNRESOLVED_INCLUDE,
                BoundaryClass::Unresolved,
                n,
            );
            return;
        };
        // PHP tracks every included file; a `_once` form skips a file any
        // earlier include already loaded.
        if once && self.inc.included.contains(&path) {
            return;
        }
        if self.inc.stack.iter().any(|p| p == &path) {
            self.opaque(BoundaryReason::INCLUDE_CYCLE, BoundaryClass::Limit, n);
            return;
        }
        let (origin, source) = match self.nest.resolve_source_file(
            self.builder,
            &path,
            SourcePurpose::DependencySource,
            "php",
        ) {
            SourceResolution::Source { origin, source } => (origin, source),
            SourceResolution::Refused(SourceRefusal::Limit { limit }) => {
                self.builder.note_saturated(limit);
                return;
            }
            SourceResolution::Refused(SourceRefusal::Unavailable(reason)) => {
                self.opaque_with_detail(
                    BoundaryReason::UNRESOLVED_INCLUDE,
                    BoundaryClass::Unresolved,
                    n,
                    Some(format!("included source unavailable: {}", reason.as_str())),
                );
                return;
            }
            SourceResolution::UnsupportedEncoding => {
                self.opaque_with_detail(
                    BoundaryReason::UNRESOLVED_INCLUDE,
                    BoundaryClass::Unresolved,
                    n,
                    Some("included source is not valid UTF-8".to_string()),
                );
                return;
            }
            SourceResolution::AlreadySelected => return,
            SourceResolution::Unavailable => {
                self.opaque(
                    BoundaryReason::UNRESOLVED_INCLUDE,
                    BoundaryClass::Unresolved,
                    n,
                );
                return;
            }
        };
        // Invocation analysis composes calls into included functions itself;
        // repository indexing links them in its composer.
        if self.builder.current_execution_is_launched_source() {
            self.nest.dependency_calls.record_followed(
                crate::dependency_calls::DependencyRequestKey {
                    source_cwd: self.nest.current_source_cwd(),
                    language: "php",
                    specifier: path.clone(),
                },
                crate::dependency_calls::FollowedDependency {
                    launch: self.builder.current_dependency_launch(),
                    path: origin.clone(),
                    source: source.clone(),
                    digest: effinterp_proto::content_digest(source.as_bytes()),
                    lang: crate::Lang::Php,
                },
            );
        }
        let dir = parent_dir(&path);
        let site = self.span(n);
        let cwd_resource = self.builder.current_execution_cwd();
        let Some(frame) = self.nest.begin(
            self.builder,
            Transition::file(Subject::Source {
                dialect: None,
                language: "php".to_string(),
                source: source.clone(),
                cwd: self.runtime_cwd.map(str::to_string),
                context: Default::default(),
            })
            .origin(origin)
            .cwd(cwd_resource, self.cwd_node),
            &[site],
            self.depth,
        ) else {
            return;
        };
        let node = frame.scope;
        self.inc.included.insert(path.clone());
        self.inc.stack.push(path);
        analyze_file(
            self.builder,
            self.nest,
            &source,
            Some(&dir),
            self.runtime_cwd,
            self.cwd_node,
            Some(node),
            self.depth + 1,
            self.inc,
            false,
        );
        self.inc.stack.pop();
        frame.end(self.builder);
    }

    /// Statically evaluate an include-path expression: string literals, `.`
    /// concatenation, `__DIR__`, `dirname(...)`, `define()`d constants, and
    /// variables bound to concrete paths. None means the path is dynamic.
    /// `__DIR__` evaluates anchored (leading slash) so `..` composes against
    /// it even when the analysis root's cwd is repo-relative.
    pub(super) fn resolve_php_source_path(
        &self,
        n: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<String> {
        match n.kind() {
            "string" | "encapsed_string" => literal_string(n, self.src),
            "parenthesized_expression" => self.resolve_php_source_path(n.named_child(0)?, env),
            "name" => match text(n, self.src) {
                "__DIR__" => self.source_cwd.map(anchored),
                other => self.inc.consts.get(other).cloned(),
            },
            "variable_name" => {
                let name = child_kind(n, "name").map(|x| text(x, self.src))?;
                match self.locals.get(name).or_else(|| env.get(name)) {
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    }) => Some(path.clone()),
                    _ => None,
                }
            }
            "member_access_expression" => resource_fs_path(&self.this_property_value(n)?),
            "class_constant_access_expression" => resource_fs_path(&self.class_constant_value(n)?),
            "scoped_property_access_expression" => {
                resource_fs_path(&self.static_property_value(n)?)
            }
            "binary_expression" => {
                let mut path = String::new();
                let mut stack = vec![n];
                while let Some(part) = stack.pop() {
                    if part.kind() == "binary_expression" {
                        if part
                            .child_by_field_name("operator")
                            .map(|operator| text(operator, self.src))
                            != Some(".")
                        {
                            return None;
                        }
                        let mut cursor = part.walk();
                        let children: Vec<Node> = part.named_children(&mut cursor).collect();
                        stack.extend(children.into_iter().rev());
                    } else {
                        path.push_str(&self.resolve_php_source_path(part, env)?);
                    }
                }
                Some(path)
            }
            "function_call_expression" => {
                if child_kind(n, "name").map(|x| text(x, self.src)) != Some("dirname") {
                    return None;
                }
                let [arg] = arg_nodes(n)[..] else { return None };
                if arg.kind() == "name" && text(arg, self.src) == "__FILE__" {
                    // dirname(__FILE__) is the including file's directory.
                    return self.source_cwd.map(anchored);
                }
                Some(parent_dir(&self.resolve_php_source_path(arg, env)?))
            }
            _ => None,
        }
    }
}
