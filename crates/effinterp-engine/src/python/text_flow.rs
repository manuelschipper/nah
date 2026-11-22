//! Python text flow.
//! Only the expression parts carried into the result count as producers.

use rustpython_parser::ast;
use rustpython_parser::ast::Expr;
use rustpython_parser::text_size::TextRange;

use super::call_resolution::python_call_argument;
use super::control;
use super::literal_values::{ElementKey, element_key};

/// The `str.format` arguments a literal `template` puts in its result:
/// those its replacement fields name, by position, by auto-numbering or by
/// keyword. `None` when the template does not parse or the call unpacks
/// arguments, so which are used is not established.
fn format_arguments<'e>(template: &str, call: &'e ast::ExprCall) -> Option<Vec<&'e Expr>> {
    if call.args.iter().any(Expr::is_starred_expr)
        || call.keywords.iter().any(|keyword| keyword.arg.is_none())
    {
        return None;
    }
    let mut used = Vec::new();
    let mut auto = 0;
    format_fields(template, &mut |field: &str| {
        let argument = if field.is_empty() {
            auto += 1;
            call.args.get(auto - 1)
        } else if let Ok(index) = field.parse::<usize>() {
            call.args.get(index)
        } else {
            call.keywords
                .iter()
                .find(|keyword| keyword.arg.as_deref() == Some(field))
                .map(|keyword| &keyword.value)
        };
        used.extend(argument);
    })?;
    Some(used)
}

/// Call `field` with the argument name of each replacement field of a
/// `str.format` template, including those nested in a format spec: empty for
/// `{}`, digits for `{0}`, an identifier for `{name}`. `None` on an
/// unbalanced brace.
fn format_fields(template: &str, field: &mut dyn FnMut(&str)) -> Option<()> {
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' if bytes.get(index + 1) == Some(&b'{') => index += 2,
            b'}' if bytes.get(index + 1) == Some(&b'}') => index += 2,
            b'}' => return None,
            b'{' => {
                let mut depth = 1;
                let mut end = index + 1;
                while end < bytes.len() {
                    match bytes[end] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 {
                        break;
                    }
                    end += 1;
                }
                if depth != 0 {
                    return None;
                }
                let inner = &template[index + 1..end];
                let (name, spec) = match inner.find(':') {
                    Some(colon) => (&inner[..colon], &inner[colon + 1..]),
                    None => (inner, ""),
                };
                let name = name.split('!').next().unwrap_or_default();
                field(name.split(['.', '[']).next().unwrap_or_default());
                format_fields(spec, field)?;
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    Some(())
}

/// The `print` arguments whose text it writes: every positional argument,
/// `end`, and `sep` when it separates more than one value.
pub(super) fn print_emitted(call: &ast::ExprCall) -> Vec<&Expr> {
    let separated = call.args.len() > 1
        || call
            .args
            .iter()
            .any(|argument| matches!(argument, Expr::Starred(_)));
    call.args
        .iter()
        .chain(
            call.keywords
                .iter()
                .filter_map(|keyword| match keyword.arg.as_deref() {
                    Some("end") => Some(&keyword.value),
                    Some("sep") if separated => Some(&keyword.value),
                    _ => None,
                }),
        )
        .collect()
}

/// `str` and `bytes` methods whose result is text of the receiver and the
/// arguments, and the methods that read an open file or response.
const TEXT_METHODS: &[&str] = &[
    "capitalize",
    "casefold",
    "center",
    "decode",
    "encode",
    "expandtabs",
    "format",
    "format_map",
    "hex",
    "join",
    "ljust",
    "lower",
    "lstrip",
    "partition",
    "read",
    "readline",
    "readlines",
    "removeprefix",
    "removesuffix",
    "replace",
    "rjust",
    "rpartition",
    "rsplit",
    "rstrip",
    "split",
    "splitlines",
    "strip",
    "swapcase",
    "title",
    "translate",
    "upper",
    "zfill",
];

/// Builtins and standard encoders whose result is their arguments' text in
/// another form. Digests and lengths are not here: they do not disclose it.
const TEXT_FUNCTIONS: &[&str] = &[
    "ascii",
    "base64.b16encode",
    "base64.b32encode",
    "base64.b64encode",
    "base64.b85encode",
    "base64.encodebytes",
    "base64.standard_b64encode",
    "base64.urlsafe_b64encode",
    "binascii.b2a_base64",
    "binascii.b2a_hex",
    "binascii.hexlify",
    "bytearray",
    "bytes",
    "format",
    "json.dumps",
    "list",
    "os.path.join",
    "repr",
    "reversed",
    "sorted",
    "str",
    "tuple",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "urllib.parse.urlencode",
];

/// The subexpressions whose text an expression's value is built from, when
/// it only transforms text: `+` and `%`, an f-string, a string method on a
/// value (`key.strip()`, `"{}".format(key)`), and a
/// builtin or encoder in [`TEXT_FUNCTIONS`]. `resolve` names an imported or
/// builtin callee; a method it resolves is a module's function, not a
/// string's.
pub(super) fn text_parts<'e>(
    expr: &'e Expr,
    resolve: &dyn Fn(&Expr) -> Option<String>,
) -> Option<Vec<&'e Expr>> {
    match expr {
        Expr::BinOp(binary) if matches!(binary.op, ast::Operator::Add | ast::Operator::Mod) => {
            Some(vec![&binary.left, &binary.right])
        }
        Expr::JoinedStr(joined) => Some(joined.values.iter().collect()),
        Expr::FormattedValue(formatted) => Some(vec![&formatted.value]),
        Expr::Call(call) => text_call_parts(call, resolve),
        _ => None,
    }
}

/// [`text_parts`] of a call: its arguments, after the receiver of a method.
/// A literal `format` template passes on only the arguments its fields use.
pub(super) fn text_call_parts<'e>(
    call: &'e ast::ExprCall,
    resolve: &dyn Fn(&Expr) -> Option<String>,
) -> Option<Vec<&'e Expr>> {
    let arguments = call
        .args
        .iter()
        .chain(call.keywords.iter().map(|keyword| &keyword.value));
    match (resolve(&call.func), call.func.as_ref()) {
        (Some(callee), _) => TEXT_FUNCTIONS
            .contains(&callee.as_str())
            .then(|| arguments.collect()),
        (None, Expr::Attribute(attribute)) => {
            TEXT_METHODS.contains(&attribute.attr.as_str()).then(|| {
                let used = match (attribute.attr.as_str(), attribute.value.as_ref()) {
                    ("format", Expr::Constant(template)) => match &template.value {
                        ast::Constant::Str(template) => format_arguments(template, call),
                        _ => None,
                    },
                    _ => None,
                };
                std::iter::once(attribute.value.as_ref())
                    .chain(used.unwrap_or_else(|| arguments.collect()))
                    .collect()
            })
        }
        _ => None,
    }
}

/// What [`value_spine`] found an expression's value to be produced by.
#[derive(Default)]
pub(super) struct ValueSpine<'e> {
    /// Spans of the calls on the spine.
    pub(super) spans: Vec<TextRange>,
    /// The same-file calls whose returned value it passes.
    pub(super) locals: Vec<&'e ast::ExprCall>,
    /// The locals it names.
    pub(super) names: Vec<&'e str>,
    /// The elements it selects from a named container by a literal subscript.
    pub(super) elements: Vec<(&'e str, ElementKey)>,
}

/// The call spans and local names an expression's value is produced by, as
/// the def-use walk reads it: the call itself, the receiver call a wrapper
/// such as `open(p).read()` passes through, a response's `.text`/`.content`,
/// the elements and keys of a literal container, the element or value a
/// subscript reads, the parts of a text transformation (see
/// [`text_parts`]), the source of a `compile`, and the arms of a
/// conditional expression its literal test does not rule out. A call to a
/// local function or method (`is_local`) is not on the spine, because the
/// reads inside it need not be what it returns; it goes to `locals`, whose
/// summary says what it returns.
pub(super) fn value_spine<'e>(
    expr: &'e Expr,
    is_local: &dyn Fn(&Expr) -> bool,
    resolve: &dyn Fn(&Expr) -> Option<String>,
    out: &mut ValueSpine<'e>,
) {
    let mut parts: Vec<&'e Expr> = Vec::new();
    match expr {
        Expr::Name(name) => out.names.push(name.id.as_str()),
        Expr::Call(call) if is_local(&call.func) => out.locals.push(call),
        Expr::Call(call) => {
            out.spans.push(call.range);
            if resolve(&call.func).as_deref() == Some("compile") {
                // A code object carries its source, not its filename or mode.
                parts.extend(python_call_argument(call, 0, "source"));
            } else if let Some(text) = text_call_parts(call, resolve) {
                parts = text;
            } else if let Expr::Attribute(attribute) = call.func.as_ref()
                && matches!(attribute.value.as_ref(), Expr::Call(_))
            {
                parts.push(&attribute.value);
            }
        }
        Expr::Attribute(attribute) if matches!(attribute.attr.as_str(), "text" | "content") => {
            parts.push(&attribute.value);
        }
        // `os.environ["NAME"]` is the read of that variable.
        Expr::Subscript(subscript)
            if resolve(&subscript.value).as_deref() == Some("os.environ") =>
        {
            out.spans.push(subscript.range);
        }
        // A literal subscript of a name selects one element; any other
        // subscript or slice may be any part of the value.
        Expr::Subscript(subscript) => {
            match (subscript.value.as_ref(), element_key(&subscript.slice)) {
                (Expr::Name(name), Some(key)) => out.elements.push((name.id.as_str(), key)),
                _ => parts.push(&subscript.value),
            }
        }
        Expr::List(list) => parts.extend(&list.elts),
        Expr::Tuple(tuple) => parts.extend(&tuple.elts),
        Expr::Set(set) => parts.extend(&set.elts),
        Expr::Dict(dict) => parts.extend(dict.keys.iter().flatten().chain(&dict.values)),
        Expr::Starred(starred) => parts.push(&starred.value),
        Expr::IfExp(branch) => match control::truthy(&branch.test) {
            Some(true) => parts.push(&branch.body),
            Some(false) => parts.push(&branch.orelse),
            None => parts.extend([branch.body.as_ref(), branch.orelse.as_ref()]),
        },
        // `a or b` and `a and b` are one of their operands.
        Expr::BoolOp(operands) => parts.extend(&operands.values),
        _ => parts.extend(text_parts(expr, resolve).into_iter().flatten()),
    }
    for part in parts {
        value_spine(part, is_local, resolve, out);
    }
}
