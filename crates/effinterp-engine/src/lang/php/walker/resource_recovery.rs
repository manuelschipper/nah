//! Recover PHP values as symbolic resources before assigning sink context.

use std::collections::{BTreeMap, HashMap, HashSet};

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use tree_sitter::Node;

use crate::summary::{contains_unresolved, has_text_concat};
use crate::value::{fs_path_resource, parse_url_endpoint, unresolved_resource};

use super::super::file_context::resolve_php_class_name;
use super::super::syntax::{
    arg_nodes, callable_name, child_kind, literal_string, scoped_value_parts, text, this_property,
    variable_name,
};
use super::PhpWalker;

/// The network endpoint of an absolute URL (one with a `://` scheme); `None`
/// for a relative or unparseable one, which callers leave unresolved.
pub(in crate::lang::php) fn absolute_url_endpoint(url: &str) -> Option<ResourceExpr> {
    if !url.contains("://") {
        return None;
    }
    parse_url_endpoint(url).map(|identity| ResourceExpr::Concrete { identity })
}

/// Recover values using the caller's bindings, before applying a sink's working directory.
pub(in crate::lang::php) fn recover_php_expression(
    n: Node,
    src: &str,
    env: &HashMap<String, ResourceExpr>,
) -> ResourceExpr {
    match n.kind() {
        "string" | "encapsed_string" => match literal_string(n, src) {
            Some(s) => fs_path_resource(&s),
            None if n.kind() == "encapsed_string" => {
                let mut parts = Vec::new();
                let mut cursor = n.walk();
                for part in n.named_children(&mut cursor) {
                    match part.kind() {
                        "string_content" | "escape_sequence" => {
                            parts.push(fs_path_resource(text(part, src)))
                        }
                        _ => parts.push(recover_php_expression(part, src, env)),
                    }
                }
                text_concat(parts)
            }
            None => unresolved_resource("filesystem"),
        },
        "variable_name" => {
            let name = child_kind(n, "name").map(|x| text(x, src)).unwrap_or("");
            env.get(name)
                .cloned()
                .unwrap_or(unresolved_resource("filesystem"))
        }
        "binary_expression" => {
            // Concatenation `a . b` -> Join of the parts. Any other binary
            // operator is not a path expression (and must not re-enter
            // collect_concat, which would recurse on this same node).
            let op = n
                .child_by_field_name("operator")
                .map(|o| text(o, src))
                .unwrap_or("");
            if op != "." {
                return unresolved_resource("filesystem");
            }
            let mut parts = Vec::new();
            collect_concat(n, src, env, &mut parts);
            text_concat(parts)
        }
        "function_call_expression" => match callable_name(n, src).as_deref() {
            Some("getenv") => arg_nodes(n)
                .first()
                .and_then(|argument| literal_string(*argument, src))
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Environment { name })
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            Some("sprintf") => resolve_sprintf(n, src, |argument| {
                recover_php_expression(argument, src, env)
            })
            .unwrap_or_else(|| unresolved_resource("filesystem")),
            _ => unresolved_resource("filesystem"),
        },
        _ => unresolved_resource("filesystem"),
    }
}

/// A `sprintf` path whose literal format uses only plain `%s` substitutions,
/// joined as text. `resolve` supplies each argument's value in the caller's
/// context; any other `%` syntax, a count mismatch, or an unresolved argument
/// rejects the call.
fn resolve_sprintf<'a>(
    node: Node<'a>,
    src: &str,
    mut resolve: impl FnMut(Node<'a>) -> ResourceExpr,
) -> Option<ResourceExpr> {
    let args = arg_nodes(node);
    let format = args
        .first()
        .and_then(|argument| literal_string(*argument, src))?;
    let literals: Vec<&str> = format.split("%s").collect();
    if literals.iter().any(|literal| literal.contains('%')) || literals.len() != args.len() {
        return None;
    }
    let mut parts = Vec::new();
    for (index, literal) in literals.iter().enumerate() {
        if !literal.is_empty() {
            parts.push(fs_path_resource(literal));
        }
        if let Some(argument) = args.get(index + 1) {
            let value = resolve(*argument);
            if contains_unresolved(&value) {
                return None;
            }
            parts.push(value);
        }
    }
    Some(text_concat(parts))
}

fn collect_concat(
    n: Node,
    src: &str,
    env: &HashMap<String, ResourceExpr>,
    out: &mut Vec<ResourceExpr>,
) {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        if n.kind() == "binary_expression" {
            let op = n
                .child_by_field_name("operator")
                .map(|o| text(o, src))
                .unwrap_or("");
            if op == "." {
                let mut c = n.walk();
                let children: Vec<Node> = n.named_children(&mut c).collect();
                for ch in children.into_iter().rev() {
                    stack.push(ch);
                }
                continue;
            }
        }
        out.push(recover_php_expression(n, src, env));
    }
}

/// Textual concatenation keeps the separators PHP wrote between the parts.
pub(super) fn text_concat(mut parts: Vec<ResourceExpr>) -> ResourceExpr {
    match parts.len() {
        0 => return fs_path_resource(""),
        1 => return parts.pop().unwrap(),
        _ => {}
    }
    let mut text = String::new();
    for part in &parts {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = part
        else {
            for part in &mut parts {
                if let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } = part
                {
                    *part = ResourceExpr::Literal {
                        value: path.clone(),
                    };
                }
            }
            // Keep textual concatenation distinct from path joining after argument binding.
            parts.insert(
                0,
                ResourceExpr::Literal {
                    value: String::new(),
                },
            );
            return ResourceExpr::Join { parts };
        };
        text.push_str(path);
    }
    fs_path_resource(&text)
}

/// A textual concatenation whose parts are now all literal is one path.
pub(super) fn fold_host_path(resource: ResourceExpr) -> ResourceExpr {
    match &resource {
        ResourceExpr::Literal { value } => fs_path_resource(value),
        ResourceExpr::Join { parts }
            if has_text_concat(&resource)
                && parts
                    .iter()
                    .all(|part| matches!(part, ResourceExpr::Literal { .. })) =>
        {
            fs_path_resource(
                &parts
                    .iter()
                    .filter_map(|part| match part {
                        ResourceExpr::Literal { value } => Some(value.as_str()),
                        _ => None,
                    })
                    .collect::<String>(),
            )
        }
        _ => resource,
    }
}

pub(super) fn resource_fs_path(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

pub(super) fn poisoned_php_reference(
    node: Node,
    poisoned: &HashSet<String>,
    src: &str,
) -> Option<String> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_name"
            && let Some(name) = child_kind(node, "name").map(|name| text(name, src))
            && poisoned.contains(name)
        {
            return Some(name.to_string());
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    pub(super) fn is_url(&self, arg: Option<Node<'a>>) -> bool {
        let Some(arg) = arg else { return false };
        if literal_string(arg, self.src).is_some_and(|url| url.contains("://")) {
            return true;
        }
        if arg.kind() != "encapsed_string" {
            return false;
        }
        arg.named_child(0)
            .filter(|part| matches!(part.kind(), "string_content" | "escape_sequence"))
            .is_some_and(|part| text(part, self.src).contains("://"))
    }

    pub(super) fn url_resource(
        &self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
    ) -> ResourceExpr {
        let unresolved = || unresolved_resource("network");
        let Some(arg) = arg else { return unresolved() };
        if let Some(url) = literal_string(arg, self.src) {
            return absolute_url_endpoint(&url).unwrap_or_else(unresolved);
        }
        if arg.kind() == "encapsed_string" {
            let mut values = env.clone();
            values.extend(self.locals.clone());
            if !self.php_interpolation_environment(arg, &values).is_empty() {
                return arg
                    .named_child(0)
                    .filter(|part| matches!(part.kind(), "string_content" | "escape_sequence"))
                    .and_then(|part| absolute_url_endpoint(text(part, self.src)))
                    .unwrap_or_else(unresolved);
            }
            return absolute_url_endpoint(&self.interpolate(arg, &values))
                .unwrap_or_else(unresolved);
        }
        let mut values = env.clone();
        values.extend(self.locals.clone());
        match self.resolve_value(arg, &values) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => absolute_url_endpoint(&path).unwrap_or_else(unresolved),
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme,
                        port,
                        path,
                    },
            } => ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme,
                    port,
                    path,
                },
            },
            _ => unresolved(),
        }
    }

    pub(super) fn is_network_handle(&self, arg: Node<'a>) -> bool {
        variable_name(arg, self.src).is_some_and(|name| self.network_handles.contains_key(name))
    }

    /// Mask unresolved PHP locals so the shell cannot read their names from the host environment.
    pub(super) fn php_interpolation_environment(
        &self,
        node: Node<'a>,
        values: &HashMap<String, ResourceExpr>,
    ) -> BTreeMap<String, Option<ResourceExpr>> {
        let mut environment = BTreeMap::new();
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "variable_name"
                && let Some(name) = child_kind(node, "name").map(|name| text(name, self.src))
                && !matches!(
                    values.get(name),
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { .. },
                    })
                )
            {
                environment.insert(name.to_string(), None);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        environment
    }

    /// Build a string from an encapsed_string, substituting `$var` with a bound
    /// param's concrete path when known, else keeping `$var` literally.
    pub(super) fn interpolate(&self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) -> String {
        let mut out = String::new();
        let mut c = n.walk();
        for part in n.named_children(&mut c) {
            match part.kind() {
                "string_content" | "escape_sequence" => out.push_str(text(part, self.src)),
                "variable_name" => {
                    let name = child_kind(part, "name")
                        .map(|x| text(x, self.src))
                        .unwrap_or("");
                    match env.get(name) {
                        Some(ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        }) => out.push_str(path),
                        _ => {
                            out.push('$');
                            out.push_str(name);
                        }
                    }
                }
                _ => out.push_str(text(part, self.src)),
            }
        }
        out
    }

    /// Resolve a filesystem sink expression, anchoring the completed path to
    /// the runtime cwd only when its first concrete segment is relative.
    pub(super) fn resolve_php_filesystem_sink(
        &self,
        n: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> ResourceExpr {
        let mut values = env.clone();
        values.extend(self.locals.clone());
        let mut resource = self.resolve_value(n, &values);
        if contains_unresolved(&resource)
            && let Some(path) = self.resolve_php_source_path(n, &values)
        {
            resource = fs_path_resource(&path);
        }
        let resource =
            effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix);
        let cwd = self
            .runtime_cwd_resource
            .as_ref()
            .map(|_| ResourceExpr::Parameter {
                name: "cwd".to_string(),
            });
        if let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &resource
        {
            return crate::paths::resolve_fs_path_with_cwd(path, cwd);
        }
        if let ResourceExpr::Join { parts } = &resource
            && matches!(
                parts.first(),
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                }) if !effinterp_proto::is_absolute_path(path, effinterp_proto::PathPlatform::Posix)
            )
        {
            return ResourceExpr::Join {
                parts: vec![
                    cwd.unwrap_or_else(|| ResourceExpr::Parameter {
                        name: "cwd".to_string(),
                    }),
                    resource,
                ],
            };
        }
        resource
    }

    pub(super) fn recover_php_argument(
        &self,
        node: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> ResourceExpr {
        let mut values = env.clone();
        values.extend(self.locals.clone());
        let value = self.resolve_value(node, &values);
        if contains_unresolved(&value)
            && let Some(path) = self.resolve_php_source_path(node, &values)
        {
            return fs_path_resource(&path);
        }
        value
    }

    fn resolve_value(&self, node: Node<'a>, env: &HashMap<String, ResourceExpr>) -> ResourceExpr {
        match node.kind() {
            "member_access_expression" => self
                .this_property_value(node)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            "class_constant_access_expression" => self
                .class_constant_value(node)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            "scoped_property_access_expression" => self
                .static_property_value(node)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .map(|operator| text(operator, self.src))
                    == Some(".") =>
            {
                let mut parts = Vec::new();
                let mut stack = vec![node];
                while let Some(part) = stack.pop() {
                    if part.kind() == "binary_expression"
                        && part
                            .child_by_field_name("operator")
                            .map(|operator| text(operator, self.src))
                            == Some(".")
                    {
                        let mut cursor = part.walk();
                        let children: Vec<Node> = part.named_children(&mut cursor).collect();
                        stack.extend(children.into_iter().rev());
                    } else {
                        parts.push(self.resolve_value(part, env));
                    }
                }
                text_concat(parts)
            }
            "encapsed_string" if literal_string(node, self.src).is_none() => {
                let mut parts = Vec::new();
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
                    match part.kind() {
                        "string_content" | "escape_sequence" => {
                            parts.push(fs_path_resource(text(part, self.src)))
                        }
                        _ => parts.push(self.resolve_value(part, env)),
                    }
                }
                text_concat(parts)
            }
            "function_call_expression" => self
                .resolve_function_value(node, env)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            _ => recover_php_expression(node, self.src, env),
        }
    }

    fn resolve_function_value(
        &self,
        node: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<ResourceExpr> {
        match callable_name(node, self.src)?.as_str() {
            "getenv" => arg_nodes(node)
                .first()
                .and_then(|argument| literal_string(*argument, self.src))
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Environment { name }),
            "sprintf" => {
                resolve_sprintf(node, self.src, |argument| self.resolve_value(argument, env))
            }
            "dirname" => self
                .resolve_php_source_path(node, env)
                .map(|path| fs_path_resource(&path)),
            _ => None,
        }
    }

    pub(super) fn this_property_value(&self, node: Node<'a>) -> Option<ResourceExpr> {
        let property = this_property(node, self.src)?;
        let class = self.current_class.as_ref()?;
        self.inc.props.get(class)?.get(&property).cloned()
    }

    pub(super) fn class_constant_value(&self, node: Node<'a>) -> Option<ResourceExpr> {
        let (scope, name) = scoped_value_parts(node, self.src)?;
        let class = match scope.as_str() {
            "self" | "static" => self.current_class.clone()?,
            other => resolve_php_class_name(&self.ctx, other),
        };
        self.ctx.consts.get(&class)?.get(&name).cloned()
    }

    pub(super) fn static_property_value(&self, node: Node<'a>) -> Option<ResourceExpr> {
        let (scope, name) = scoped_value_parts(node, self.src)?;
        let class = match scope.as_str() {
            "self" | "static" => self.current_class.clone()?,
            other => resolve_php_class_name(&self.ctx, other),
        };
        self.ctx.static_props.get(&class)?.get(&name).cloned()
    }
}
