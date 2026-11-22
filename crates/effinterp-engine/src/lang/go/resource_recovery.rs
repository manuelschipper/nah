//! Go resource recovery at filesystem and network sinks.

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use gosyn::ast::Expression;
use gosyn::token::Operator;

use crate::SemanticValueKind;
use crate::value::{sink_typed_join, typed_concat, unresolved_resource, url_endpoint_resource};

use super::call_resolution::GoCallee;
use super::model::string_of;
use super::semantic_values::exact_go_property_value;
use super::summary::{is_str_lit, unquote_go_string};
use super::walker::GoWalker;

impl GoWalker<'_, '_> {
    /// Recover a Go filesystem resource, preserving parameters for call-site substitution.
    pub(super) fn go_filesystem_resource(&self, expr: &Expression) -> ResourceExpr {
        match expr {
            Expression::BasicLit(lit) if is_str_lit(lit) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: unquote_go_string(&lit.value),
                },
            },
            Expression::Ident(id) => match self.params.get(&id.name) {
                Some(bound) => bound.clone(),
                None => self
                    .resource_values
                    .get(&id.name)
                    .cloned()
                    .or_else(|| {
                        self.values
                            .get(&id.name)
                            .and_then(|value| match &value.kind {
                                SemanticValueKind::Literal(path) => Some(ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path: path.clone() },
                                }),
                                SemanticValueKind::Join(_) => {
                                    Some(typed_concat(vec![value.lower_resource()], "filesystem"))
                                }
                                SemanticValueKind::Union(_)
                                | SemanticValueKind::Path { .. }
                                | SemanticValueKind::Environment(_)
                                | SemanticValueKind::Property { .. }
                                | SemanticValueKind::Pattern { .. }
                                | SemanticValueKind::Resource(_) => {
                                    Some(value.lower_resource_for_domain("filesystem"))
                                }
                                _ => None,
                            })
                    })
                    .or_else(|| {
                        (!self.local_vars.contains(&id.name) && self.fact_scope.is_some()).then(
                            || ResourceExpr::Parameter {
                                name: id.name.clone(),
                            },
                        )
                    })
                    .unwrap_or(unresolved_resource("filesystem")),
            },
            Expression::Selector(selector) => {
                if let Expression::Ident(receiver) = &*selector.x
                    && let Some(value) = self.values.get(&receiver.name).and_then(|value| {
                        exact_go_property_value(value, &selector.sel.name, self.value_limits)
                    })
                {
                    return value.lower_resource_for_domain("filesystem");
                }
                if let Expression::Ident(receiver) = &*selector.x
                    && self.fact_function.split_once('.').is_some_and(|(typ, _)| {
                        self.go_receiver_type(&receiver.name).as_deref() == Some(typ)
                    })
                {
                    return ResourceExpr::Parameter {
                        name: selector.sel.name.clone(),
                    };
                }
                self.go_semantic_value(expr)
                    .map(|value| value.lower_resource_for_domain("filesystem"))
                    .unwrap_or(unresolved_resource("filesystem"))
            }
            Expression::Paren(p) => self.go_filesystem_resource(&p.expr),
            Expression::Operation(operation)
                if operation.op == Operator::Arrow && operation.y.is_none() =>
            {
                self.go_channel_receive_resource(expr)
                    .unwrap_or(unresolved_resource("filesystem"))
            }
            // String concatenation is typed by the filesystem sink.
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                typed_concat(
                    vec![
                        self.concatenation_part(&operation.x, "filesystem"),
                        self.concatenation_part(operation.y.as_ref().unwrap(), "filesystem"),
                    ],
                    "filesystem",
                )
            }
            // filepath.Join(a, b, ...) -> Join.
            Expression::Call(call) => {
                if let GoCallee::Pkg { path, method, .. } = self.resolve_go_callee(&call.func)
                    && path == "path/filepath"
                    && method == "Join"
                {
                    let parts: Vec<ResourceExpr> = call
                        .args
                        .iter()
                        .map(|arg| self.concatenation_part(arg, "filesystem"))
                        .collect();
                    if !parts.is_empty() {
                        // Summary parameters must survive until call-site binding.
                        if parts
                            .iter()
                            .all(|part| matches!(part, ResourceExpr::Parameter { .. }))
                        {
                            return ResourceExpr::Join { parts };
                        }
                        return sink_typed_join(parts, "filesystem");
                    }
                }
                unresolved_resource("filesystem")
            }
            _ => unresolved_resource("filesystem"),
        }
    }

    /// Recover a Go network resource, keeping the family when the endpoint cannot be resolved.
    pub(super) fn go_network_resource(&self, expr: &Expression) -> ResourceExpr {
        match expr {
            Expression::BasicLit(literal) if is_str_lit(literal) => {
                url_endpoint_resource(&unquote_go_string(&literal.value))
            }
            Expression::Paren(paren) => self.go_network_resource(&paren.expr),
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                sink_typed_join(
                    vec![
                        self.concatenation_part(&operation.x, "network"),
                        self.concatenation_part(operation.y.as_ref().unwrap(), "network"),
                    ],
                    "network",
                )
            }
            _ => self
                .go_semantic_value(expr)
                .and_then(|value| match value.kind {
                    SemanticValueKind::Literal(value) => Some(url_endpoint_resource(&value)),
                    SemanticValueKind::Join(_) => {
                        Some(sink_typed_join(vec![value.lower_resource()], "network"))
                    }
                    SemanticValueKind::Endpoint { .. }
                    | SemanticValueKind::Resource(ResourceIdentity::NetworkEndpoint { .. }) => {
                        Some(value.lower_resource_for_domain("network"))
                    }
                    _ => None,
                })
                .unwrap_or(unresolved_resource("network")),
        }
    }

    fn concatenation_part(&self, expr: &Expression, domain: &str) -> ResourceExpr {
        match expr {
            Expression::BasicLit(literal) if is_str_lit(literal) => ResourceExpr::Literal {
                value: unquote_go_string(&literal.value),
            },
            Expression::Paren(paren) => self.concatenation_part(&paren.expr, domain),
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                ResourceExpr::Join {
                    parts: vec![
                        self.concatenation_part(&operation.x, domain),
                        self.concatenation_part(operation.y.as_ref().unwrap(), domain),
                    ],
                }
            }
            Expression::Call(call)
                if matches!(
                    self.resolve_go_callee(&call.func),
                    GoCallee::Pkg { ref path, ref method, .. }
                        if path == "os" && matches!(method.as_str(), "Getenv" | "LookupEnv")
                ) =>
            {
                call.args
                    .first()
                    .and_then(string_of)
                    .filter(|name| !name.is_empty())
                    .map(|name| ResourceExpr::Environment { name })
                    .unwrap_or(unresolved_resource("environment"))
            }
            _ if domain == "filesystem" => self.go_filesystem_resource(expr),
            _ => self
                .go_semantic_value(expr)
                .and_then(|value| match value.kind {
                    SemanticValueKind::Literal(_)
                    | SemanticValueKind::Environment(_)
                    | SemanticValueKind::Path { .. }
                    | SemanticValueKind::Endpoint { .. }
                    | SemanticValueKind::Property { .. }
                    | SemanticValueKind::Join(_)
                    | SemanticValueKind::Pattern { .. }
                    | SemanticValueKind::Resource(_) => Some(value.lower_resource()),
                    SemanticValueKind::Unresolved { ref family, .. } if family == "environment" => {
                        Some(value.lower_resource())
                    }
                    _ => None,
                })
                .unwrap_or(unresolved_resource("value")),
        }
    }
}
