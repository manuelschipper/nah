//! Python file handles.
//! A write through a tracked handle refers to the original open effect, so its bytes can be attached there.

use effinterp_proto::{ProvenanceRef, ResourceExpr};
use rustpython_parser::ast;
use rustpython_parser::ast::{Constant, Expr};
use rustpython_parser::text_size::TextRange;

use super::PythonWalker;
use super::call_resolution::python_call_argument;
use super::resolve::str_literal;

/// Formatting options preserve the serialized members only when their values
/// are literal and their separators/indentation still produce valid JSON.
fn json_dump_formatting(keywords: &[ast::Keyword]) -> bool {
    keywords.iter().all(
        |keyword| match keyword.arg.as_ref().map(|name| name.as_str()) {
            Some("indent") => matches!(&keyword.value, Expr::Constant(value)
                if matches!(&value.value, Constant::None | Constant::Int(_) | Constant::Bool(_))
                    || matches!(&value.value, Constant::Str(text)
                        if text.chars().all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n')))),
            Some("sort_keys") => matches!(&keyword.value, Expr::Constant(value)
                if matches!(value.value, Constant::Bool(_))),
            Some("separators") => {
                let values = match &keyword.value {
                    Expr::Tuple(tuple) => &tuple.elts,
                    Expr::List(list) => &list.elts,
                    _ => return false,
                };
                values.len() == 2
                    && values.iter().zip([",", ":"]).all(|(value, separator)| {
                        str_literal(value).is_some_and(|text| {
                            text.trim_matches([' ', '\t', '\r', '\n']) == separator
                        })
                    })
            }
            _ => false,
        },
    )
}

/// Only literal JSON data is admitted, so capturing a dump cannot hide calls
/// that evaluate its dictionary keys, values, or output file arguments.
fn json_literal(expr: &Expr, depth: usize) -> Option<serde_json::Value> {
    if depth >= 64 {
        return None;
    }
    match expr {
        Expr::Constant(constant) => match &constant.value {
            Constant::None => Some(serde_json::Value::Null),
            Constant::Bool(value) => Some((*value).into()),
            Constant::Str(value) => Some(value.clone().into()),
            Constant::Int(value) => serde_json::from_str(&value.to_string()).ok(),
            Constant::Float(value) => serde_json::Number::from_f64(*value).map(Into::into),
            _ => None,
        },
        Expr::Dict(dict) => dict
            .keys
            .iter()
            .zip(&dict.values)
            .map(|(key, value)| {
                Some((str_literal(key.as_ref()?)?, json_literal(value, depth + 1)?))
            })
            .collect::<Option<serde_json::Map<_, _>>>()
            .map(Into::into),
        Expr::List(list) => list
            .elts
            .iter()
            .map(|value| json_literal(value, depth + 1))
            .collect::<Option<Vec<_>>>()
            .map(Into::into),
        _ => None,
    }
}

/// How an `os.open` descriptor writes: not at all, from the start of the
/// file, or only at its end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OsOpenWrite {
    None,
    Replace,
    Append,
}

impl PythonWalker<'_, '_> {
    /// `open(path, mode)` / `io.open(...)` — read/write/append from the mode.
    pub(super) fn builtin_open(&mut self, call: &ast::ExprCall, span: TextRange) {
        let Some(path) = call.args.first() else {
            return;
        };
        let resource = self.resolve_fs(path);
        let node = self.span_node(span);
        if matches!(resource, ResourceExpr::Unresolved { .. })
            && self.lowered_concatenation(path).is_none()
        {
            self.opaque_boundary("filesystem argument is not statically bounded", node);
        }
        // Builtin `open(path, mode)` — the mode is the second positional arg.
        self.open_by_mode(call, 1, resource, node);
    }

    /// Bind `name` to the file object `value` evaluates to: a call, whose
    /// write `name.write(data)` marks once the walk records it in
    /// `open_writes` (a binary-mode `open`, `io.open` or `Path.open`), or a
    /// name already bound to one (`g = f`).
    pub(super) fn bind_write_handle(&mut self, name: &str, value: &Expr) {
        let call = match value {
            Expr::Call(call) => Some(call.range),
            Expr::Name(other) => self.write_handles.get(other.id.as_str()).copied(),
            _ => None,
        };
        if let Some(call) = call {
            self.write_handles.insert(name.to_string(), call);
        }
    }

    /// The write effect of the binary-mode file object `receiver` names:
    /// an `open(...)` call itself or a name bound to one.
    pub(super) fn handle_write(&self, receiver: &Expr) -> Option<u32> {
        let call = match receiver {
            Expr::Call(call) => call.range,
            Expr::Name(name) => *self.write_handles.get(name.id.as_str())?,
            _ => return None,
        };
        self.open_writes.get(&call).copied()
    }

    /// Emit read/write effects on `resource` from an open-style call's mode
    /// argument (positional `mode_index` or the `mode=` keyword, defaulting to
    /// "r"). Shared by the builtin `open` and `pathlib.Path(p).open(mode)`,
    /// whose mode arguments sit at different positions. A mode that is
    /// neither a literal nor a name bound to one decides nothing about the
    /// access, so it leaves a boundary instead of a guessed read.
    pub(super) fn open_by_mode(
        &mut self,
        call: &ast::ExprCall,
        mode_index: usize,
        resource: ResourceExpr,
        node: ProvenanceRef,
    ) {
        let mode = match python_call_argument(call, mode_index, "mode") {
            None => "r".to_string(),
            Some(mode) => match self.known_string(mode) {
                Some(mode) => mode,
                None => {
                    self.opaque_boundary("open mode is not statically bounded", node);
                    return;
                }
            },
        };
        let write = mode.contains(['w', 'a', 'x', '+']);
        let read = mode.contains('r') || mode.contains('+');
        if read {
            let read = self.emit("filesystem.read", resource.clone(), &[], node);
            self.set_effect_string_attribute(read, "access_purpose", "program_input");
        }
        if write {
            let attrs: &[(&str, bool)] = if mode.contains('a') {
                &[("append", true)]
            } else {
                &[]
            };
            let write = self.emit("filesystem.write", resource, attrs, node);
            // Only a binary file object stores the bytes `write` is given.
            if mode.contains('b')
                && let Some(write) = write
            {
                self.open_writes.insert(call.range, write);
            }
        }
    }

    /// The file `open(P).read()` reads whole, in a read mode: the source an
    /// `exec` of it runs.
    pub(super) fn whole_file_read(&self, expr: &Expr) -> Option<ResourceExpr> {
        let Expr::Call(read) = expr else {
            return None;
        };
        let Expr::Attribute(method) = read.func.as_ref() else {
            return None;
        };
        let Expr::Call(open) = method.value.as_ref() else {
            return None;
        };
        let mode = open.args.get(1).map(str_literal);
        (method.attr.as_str() == "read"
            && read.args.is_empty()
            && read.keywords.is_empty()
            && matches!(
                self.imports.resolve_callee(&open.func).as_deref(),
                Some("open" | "io.open")
            )
            && open.args.len() <= 2
            && open.keywords.iter().all(|keyword| {
                keyword
                    .arg
                    .as_ref()
                    .is_some_and(|arg| arg.as_str() == "encoding")
            })
            && mode.is_none_or(|mode| matches!(mode.as_deref(), Some("r" | "rt" | "rb"))))
        .then(|| open.args.first().map(|path| self.resolve_fs(path)))
        .flatten()
    }

    /// `os.open(path, flags)`: the access mode and creation flags decide
    /// whether the descriptor reads, writes, or both.
    pub(super) fn os_open(&mut self, call: &ast::ExprCall, span: TextRange) {
        let Some(path) = call.args.first() else {
            return;
        };
        let resource = self.resolve_fs(path);
        let node = self.span_node(span);
        if matches!(resource, ResourceExpr::Unresolved { .. })
            && self.lowered_concatenation(path).is_none()
        {
            self.opaque_boundary("filesystem argument is not statically bounded", node);
        }
        let Some((read, write)) =
            python_call_argument(call, 1, "flags").and_then(|flags| self.os_open_access(flags))
        else {
            self.opaque_boundary("os.open flags are not statically bounded", node);
            return;
        };
        if read {
            let read = self.emit("filesystem.read", resource.clone(), &[], node);
            self.set_effect_string_attribute(read, "access_purpose", "program_input");
        }
        if write != OsOpenWrite::None {
            let append: &[(&str, bool)] = if write == OsOpenWrite::Append {
                &[("append", true)]
            } else {
                &[]
            };
            self.emit("filesystem.write", resource, append, node);
        }
    }

    /// Whether `os.open` flags read and how they write, from `os.O_*` names
    /// joined by `|`. `O_RDONLY` is zero, so read is the absence of a write
    /// access mode; creating or truncating counts as a write.
    fn os_open_access(&self, flags: &Expr) -> Option<(bool, OsOpenWrite)> {
        let mut names = Vec::new();
        let mut pending = vec![flags];
        while let Some(expr) = pending.pop() {
            match expr {
                Expr::BinOp(ast::ExprBinOp {
                    left,
                    op: ast::Operator::BitOr,
                    right,
                    ..
                }) => pending.extend([left.as_ref(), right.as_ref()]),
                _ => names.push(self.imports.resolve_callee(expr)?),
            }
        }
        let mut access = None;
        let mut write = OsOpenWrite::None;
        for name in &names {
            match name.strip_prefix("os.")? {
                "O_RDONLY" => access = access.or(Some((true, false))),
                "O_WRONLY" => access = Some((false, true)),
                "O_RDWR" => access = Some((true, true)),
                "O_APPEND" => write = OsOpenWrite::Append,
                "O_CREAT" | "O_TRUNC" | "O_EXCL" if write == OsOpenWrite::None => {
                    write = OsOpenWrite::Replace;
                }
                "O_CREAT" | "O_TRUNC" | "O_EXCL" => {}
                "O_CLOEXEC" | "O_NOFOLLOW" | "O_NONBLOCK" | "O_NOCTTY" | "O_SYNC" | "O_DSYNC"
                | "O_DIRECTORY" | "O_BINARY" | "O_NOINHERIT" => {}
                _ => return None,
            }
        }
        let (read, writes) = access.unwrap_or((true, false));
        match write {
            OsOpenWrite::None if writes => write = OsOpenWrite::Replace,
            // Appending needs a write access mode.
            OsOpenWrite::Append if !writes => write = OsOpenWrite::None,
            _ => {}
        }
        Some((read, write))
    }

    pub(super) fn json_dump_to_open(
        &mut self,
        call: &ast::ExprCall,
        open: &ast::ExprCall,
        span: TextRange,
    ) -> bool {
        if self.imports.resolve_callee(&call.func).as_deref() == Some("json.dump")
            && call.args.len() == 2
            && json_dump_formatting(&call.keywords)
            && let Some(fields) = json_literal(&call.args[0], 0)
            && matches!(
                self.imports.resolve_callee(&open.func).as_deref(),
                Some("open" | "io.open")
            )
            && open
                .args
                .iter()
                .chain(open.keywords.iter().map(|keyword| &keyword.value))
                .all(|argument| {
                    matches!(argument, Expr::Constant(_)) || self.known_string(argument).is_some()
                })
            && let Some(path) = python_call_argument(open, 0, "file")
            && self.known_string(path).is_some()
            && python_call_argument(open, 1, "mode")
                .and_then(|mode| self.known_string(mode))
                .is_some_and(|mode| matches!(mode.as_str(), "w" | "wt" | "x" | "xt"))
        {
            let resource = self.resolve_fs(path);
            let node = self.span_node(span);
            let write = self.emit("filesystem.write", resource, &[("truncate", true)], node);
            self.set_effect_string_attribute(write, "written_json_fields", &fields.to_string());
            return true;
        }
        false
    }
}
