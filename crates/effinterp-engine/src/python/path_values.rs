//! Python path values: whether an expression evaluates to a `pathlib` path
//! object, and the resource a path iteration yields.

use effinterp_proto::ResourceExpr;
use rustpython_parser::ast::{self, Expr};

use crate::value::unresolved_resource;

use super::resolve::str_literal;
use super::{
    PythonWalker, is_branch_mixed_path_method, is_path_method, is_path_specific_method,
    python_call_argument,
};

impl PythonWalker<'_, '_> {
    pub(super) fn is_path_value(&self, value: &Expr) -> bool {
        match value {
            Expr::Name(name) => self.path_vars.contains(name.id.as_str()),
            Expr::Call(call) => {
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "pathlib.Path"
                            | "pathlib.PurePath"
                            | "pathlib.PosixPath"
                            | "pathlib.PurePosixPath"
                            | "pathlib.Path.home"
                            | "pathlib.PosixPath.home"
                            | "pathlib.Path.cwd"
                            | "pathlib.PosixPath.cwd"
                    )
                }) {
                    return true;
                }
                matches!(call.func.as_ref(), Expr::Attribute(method)
                    if matches!(method.attr.as_str(),
                        "resolve" | "absolute" | "expanduser" | "joinpath" | "with_suffix" | "with_name")
                        && self.is_path_value(&method.value))
            }
            Expr::Attribute(attribute)
                if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
                    && self.is_current_path_attr(attribute.attr.as_str()) =>
            {
                true
            }
            Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => {
                self.is_path_value(&attribute.value)
            }
            Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
            {
                let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                    unreachable!();
                };
                self.is_path_value(&attribute.value)
            }
            Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
                self.is_path_value(&binary.left)
            }
            _ => false,
        }
    }

    pub(super) fn may_be_path_value(&self, value: &Expr) -> bool {
        self.is_path_value(value)
            || matches!(value, Expr::IfExp(conditional)
                if self.may_be_path_value(&conditional.body)
                    || self.may_be_path_value(&conditional.orelse))
    }

    pub(super) fn is_branch_mixed_path_value(&self, value: &Expr) -> bool {
        match value {
            Expr::Name(name) => self.branch_mixed_path_vars.contains(name.id.as_str()),
            Expr::Call(call) => {
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "pathlib.Path"
                            | "pathlib.PurePath"
                            | "pathlib.PosixPath"
                            | "pathlib.PurePosixPath"
                            | "pathlib.Path.home"
                            | "pathlib.PosixPath.home"
                            | "pathlib.Path.cwd"
                            | "pathlib.PosixPath.cwd"
                    )
                }) {
                    return false;
                }
                matches!(call.func.as_ref(), Expr::Attribute(method)
                    if matches!(method.attr.as_str(),
                        "resolve" | "absolute" | "expanduser" | "joinpath" | "with_suffix" | "with_name")
                        && self.is_branch_mixed_path_value(&method.value))
            }
            Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => {
                self.is_branch_mixed_path_value(&attribute.value)
            }
            Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
            {
                let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                    unreachable!();
                };
                self.is_branch_mixed_path_value(&attribute.value)
            }
            Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
                self.is_branch_mixed_path_value(&binary.left)
            }
            _ => false,
        }
    }

    pub(super) fn is_current_path_attr(&self, attr: &str) -> bool {
        self.current_class.as_ref().is_some_and(|class| {
            self.path_attrs.iter().any(|(owner, name, ty)| {
                owner == class
                    && name == attr
                    && self.imports.resolve_written(ty).is_some_and(|ty| {
                        matches!(
                            ty.as_str(),
                            "pathlib.Path"
                                | "pathlib.PurePath"
                                | "pathlib.PosixPath"
                                | "pathlib.PurePosixPath"
                        )
                    })
            })
        })
    }

    pub(super) fn is_path_method_receiver(&self, method: &str, receiver: &Expr) -> bool {
        if !is_path_method(method) {
            return false;
        }
        if self.is_branch_mixed_path_value(receiver) && !is_branch_mixed_path_method(method) {
            return false;
        }
        self.is_path_value(receiver)
            || is_path_specific_method(method)
                && matches!(receiver, Expr::Attribute(attribute)
                if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
                    && self.current_class.as_ref().is_some_and(|class| {
                        self.attr_values.iter().any(|value| {
                            value.owner == *class
                                && value.attr == attribute.attr.as_str()
                                && matches!(value.value.as_ref(), Expr::Name(_))
                        })
                    }))
    }

    pub(super) fn path_iter_resource(&self, value: &Expr) -> Option<ResourceExpr> {
        let value = match value {
            Expr::Call(call)
                if self.imports.resolve_callee(&call.func).as_deref() == Some("sorted") =>
            {
                python_call_argument(call, 0, "iterable")?
            }
            _ => value,
        };
        let Expr::Call(call) = value else { return None };
        let Expr::Attribute(method) = call.func.as_ref() else {
            return None;
        };
        if !matches!(method.attr.as_str(), "glob" | "rglob" | "iterdir")
            || !self.is_path_value(&method.value)
        {
            return None;
        }
        let glob = match method.attr.as_str() {
            "iterdir" => Some("*".to_string()),
            "rglob" => python_call_argument(call, 0, "pattern")
                .and_then(str_literal)
                .map(|pattern| format!("**/{pattern}")),
            _ => python_call_argument(call, 0, "pattern").and_then(str_literal),
        };
        let member = glob
            .map(|glob| ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            })
            .unwrap_or_else(|| unresolved_resource("filesystem"));
        Some(ResourceExpr::Join {
            parts: vec![self.resolve_fs(&method.value), member],
        })
    }
}
