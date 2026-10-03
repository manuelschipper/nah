//! Python filesystem path lowering: how a path expression, string
//! concatenation or literal becomes a filesystem resource.

use effinterp_proto::{PathPlatform, ResourceExpr, normalize_resource};
use rustpython_parser::ast;
use rustpython_parser::ast::Expr;

use crate::paths::resolve_fs_path;
use crate::summary::substitute_resource_expr;
use crate::value::unresolved_resource;
use crate::{SemanticValue, SemanticValueKind};

use super::definitions::contains_literal;
use super::resolve::str_literal;
use super::{PythonWalker, callee_written, expression_uses_name, resolve};

impl PythonWalker<'_, '_> {
    /// Resolve an expression used as a filesystem path, then substitute the
    /// current scope (constants and tracked locals) so a bare name bound to a
    /// resource resolves to it rather than staying a free parameter.
    pub(super) fn resolve_fs(&self, expr: &Expr) -> ResourceExpr {
        if self.path_expression_uses_widened_binding(expr)
            || self.concatenation_uses_unbounded_binding(expr)
        {
            return unresolved_resource("filesystem");
        }
        // `abspath` and `normpath` only normalize their argument's spelling,
        // which already resolves against the working directory.
        if let Expr::Call(call) = expr
            && call.args.len() == 1
            && call.keywords.is_empty()
            && matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("os.path.abspath" | "os.path.normpath")
            )
        {
            return self.resolve_fs(&call.args[0]);
        }
        // The bytes or str spelling of a path names the same file.
        if let Expr::Call(call) = expr
            && let [path] = call.args.as_slice()
            && call.keywords.is_empty()
            && matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("os.fsencode" | "os.fsdecode")
            )
        {
            return self.resolve_fs(path);
        }
        if let Expr::Call(call) = expr
            && call.args.len() == 1
            && call.keywords.is_empty()
            && let Expr::Attribute(method) = call.func.as_ref()
            && matches!(method.attr.as_str(), "with_name" | "with_suffix")
        {
            let base = self.resolve_fs(&method.value);
            let transformed = if method.attr.as_str() == "with_name" {
                resolve::concrete_path_transform(base, &call.args[0], |path, value| {
                    path.set_file_name(value);
                })
            } else {
                resolve::concrete_path_transform(base, &call.args[0], |path, value| {
                    path.set_extension(value.strip_prefix('.').unwrap_or(value));
                })
            };
            if let Some(resource) = transformed {
                return self.lower_fs_literal(resource);
            }
        }
        if let Some(call) = self.executed_local_call(expr)
            && let Some(resource) = self.call_return_resource(call)
        {
            return self.lower_fs_literal(resource);
        }
        if let Some(resource) = self.collection_item(expr) {
            return self.lower_fs_literal(resource);
        }
        if let Some(resource) = self.lowered_concatenation(expr) {
            let resource = substitute_resource_expr(&resource, &self.var_scope);
            let ResourceExpr::Join { parts } = resource else {
                return self.lower_fs_literal(resource);
            };
            return self.lower_fs_literal(crate::value::sink_typed_concat(
                parts,
                "filesystem",
                self.cwd.as_deref().map(|cwd| resolve_fs_path(cwd, None)),
            ));
        }
        let resource = substitute_resource_expr(&self.fs_resource(expr), &self.var_scope);
        let resource = if Self::path_expression_expands_user(expr) {
            resolve::expanduser_resource(resource)
        } else {
            resource
        };
        let resource = if self.is_path_value(expr) {
            resolve::normalize_pathlib_resource(resource)
        } else {
            resource
        };
        let resource = self.lower_fs_literal(resource);
        if self.capture.is_none()
            && matches!(expr, Expr::Name(_))
            && matches!(resource, ResourceExpr::Parameter { .. })
        {
            self.free_resource_parameter.set(true);
        }
        resource
    }

    pub(super) fn path_expression_uses_widened_binding(&self, expr: &Expr) -> bool {
        if matches!(expr, Expr::Name(name) if self.widened_vars.contains(name.id.as_str())) {
            return true;
        }
        let recognized_call = matches!(expr, Expr::Call(call)
            if callee_written(&call.func).as_deref() == Some("str")
                || self.imports.resolve_callee(&call.func).as_deref() == Some("os.path.join"));
        (self.is_path_value(expr) || recognized_call)
            && expression_uses_name(expr, &self.widened_vars)
    }

    pub(super) fn path_expression_expands_user(expr: &Expr) -> bool {
        match expr {
            Expr::Call(call) => {
                if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "str") {
                    return call
                        .args
                        .first()
                        .is_some_and(Self::path_expression_expands_user);
                }
                let Expr::Attribute(method) = call.func.as_ref() else {
                    return false;
                };
                method.attr.as_str() == "expanduser"
                    || Self::path_expression_expands_user(&method.value)
            }
            Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
                Self::path_expression_expands_user(&binary.left)
            }
            Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => {
                Self::path_expression_expands_user(&attribute.value)
            }
            Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
            {
                let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                    unreachable!();
                };
                Self::path_expression_expands_user(&attribute.value)
            }
            _ => false,
        }
    }

    pub(super) fn lowered_concatenation(&self, expr: &Expr) -> Option<ResourceExpr> {
        if self.concatenation_uses_unbounded_binding(expr) {
            return None;
        }
        resolve::concatenated_resource(
            expr,
            &self.imports,
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
        )
        .or_else(|| {
            let Expr::Name(name) = expr else {
                return None;
            };
            if !self.concatenated_vars.contains(name.id.as_str()) {
                return None;
            }
            self.var_scope.get(name.id.as_str()).cloned()
        })
    }

    pub(super) fn concatenation_uses_unbounded_binding(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Name(name) => self.unbounded_string_vars.contains(name.id.as_str()),
            Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
                self.concatenation_uses_unbounded_binding(&binary.left)
                    || self.concatenation_uses_unbounded_binding(&binary.right)
            }
            Expr::JoinedStr(joined) => joined.values.iter().any(|value| match value {
                Expr::FormattedValue(formatted) => {
                    self.concatenation_uses_unbounded_binding(&formatted.value)
                }
                _ => false,
            }),
            _ => false,
        }
    }

    pub(super) fn string_binding_is_unbounded(&self, expr: &Expr, resolved: bool) -> bool {
        match expr {
            Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
                self.lowered_concatenation(expr).is_none()
            }
            Expr::JoinedStr(_) => self.lowered_concatenation(expr).is_none(),
            Expr::Name(name) => self.unbounded_string_vars.contains(name.id.as_str()),
            Expr::Constant(_) => str_literal(expr).is_none(),
            Expr::Attribute(_) | Expr::Subscript(_) => false,
            Expr::Call(call) => {
                !resolved
                    && !matches!(callee_written(&call.func).as_deref(), Some("input"))
                    && !matches!(
                        self.imports.resolve_callee(&call.func).as_deref(),
                        Some("os.getenv" | "os.environ.get")
                    )
            }
            _ => !resolved,
        }
    }

    pub(super) fn source_string_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        if let Some(resource) = self.lowered_concatenation(expr) {
            return Some(resource);
        }
        if let Some(ResourceExpr::Join { mut parts }) = resolve::concatenated_part_resource(
            expr,
            &self.imports,
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
        ) && parts.len() == 1
            && matches!(parts.first(), Some(ResourceExpr::Environment { .. }))
        {
            return parts.pop();
        }
        if let Some(value) = str_literal(expr) {
            return matches!(
                SemanticValue::source_literal(value.clone()).kind,
                SemanticValueKind::Endpoint { .. }
            )
            .then_some(ResourceExpr::Literal { value });
        }
        let Expr::Name(name) = expr else {
            return None;
        };
        match self.var_scope.get(name.id.as_str()) {
            Some(resource @ ResourceExpr::Literal { .. }) => Some(resource.clone()),
            _ => None,
        }
    }

    pub(super) fn fs_resource(&self, expr: &Expr) -> ResourceExpr {
        if let Some(resource) = self.modeled_path(expr) {
            return resource;
        }
        if self.current_class.is_some()
            && let Expr::Attribute(attribute) = expr
            && matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
        {
            return ResourceExpr::Parameter {
                name: format!("self.{}", attribute.attr),
            };
        }
        resolve::fs_resource(
            expr,
            &self.imports,
            self.cwd.as_deref(),
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
            &self.path_vars,
        )
    }

    pub(super) fn lower_fs_literal(&self, resource: ResourceExpr) -> ResourceExpr {
        match resource {
            ResourceExpr::Literal { value } => resolve_fs_path(&value, self.cwd.as_deref()),
            ResourceExpr::Join { parts } => {
                let resource = ResourceExpr::Join { parts };
                let resource =
                    if contains_literal(&resource) && !crate::summary::has_text_concat(&resource) {
                        let ResourceExpr::Join { parts } = resource else {
                            unreachable!();
                        };
                        crate::value::sink_typed_join(parts, "filesystem")
                    } else {
                        resource
                    };
                let resource = normalize_resource(resource, PathPlatform::Posix);
                match resource {
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    } if !effinterp_proto::is_absolute_path(&path, PathPlatform::Posix) => {
                        resolve_fs_path(&path, self.cwd.as_deref())
                    }
                    ResourceExpr::Join { parts }
                        if matches!(
                            parts.first(),
                            Some(ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path },
                            }) if !effinterp_proto::is_absolute_path(path, PathPlatform::Posix)
                        ) =>
                    {
                        let cwd = self
                            .cwd
                            .as_deref()
                            .map(|cwd| ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath {
                                    path: effinterp_proto::normalize_path(cwd, PathPlatform::Posix),
                                },
                            })
                            .unwrap_or_else(|| ResourceExpr::Parameter {
                                name: "cwd".to_string(),
                            });
                        normalize_resource(
                            ResourceExpr::Join {
                                parts: std::iter::once(cwd).chain(parts).collect(),
                            },
                            PathPlatform::Posix,
                        )
                    }
                    resource => resource,
                }
            }
            other => other,
        }
    }
}
