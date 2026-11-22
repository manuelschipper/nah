use std::collections::HashMap;

use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::module_summary::ClassEntry;

use super::syntax::{
    ruby_ast_children, ruby_constant_last_segment, ruby_constant_path,
    ruby_instance_variable_target, ruby_local_variable_target,
};

/// A local is either a class reference (`engine_class = Foo::Bar`) or an
/// instance of a named class (`engine = Foo::Bar.new`).
#[derive(Clone, Debug)]
pub(super) enum RubyReceiverType {
    Class(String),
    Instance(String),
}

/// Track Ruby receiver types in assignments, skipping nested method and class definitions.
pub(super) fn scan_ruby_receiver_types(
    node: &Node,
    class: &str,
    params: &[String],
    locals: &mut HashMap<String, RubyReceiverType>,
    entry: &mut ClassEntry,
) {
    match node {
        Node::Lvasgn(a) => {
            if let Some(v) = a.value.as_deref() {
                scan_ruby_receiver_types(v, class, params, locals, entry);
                match ruby_expression_receiver_type(v, locals, params, Some(class), entry) {
                    Some(ty) => {
                        locals.insert(a.name.clone(), ty);
                    }
                    None => {
                        locals.remove(&a.name);
                    }
                }
            }
        }
        Node::Ivasgn(a) => {
            if let Some(v) = a.value.as_deref() {
                scan_ruby_receiver_types(v, class, params, locals, entry);
                record_ivar(&a.name, v, params, locals, Some(class), entry);
            }
        }
        Node::OrAsgn(a) => scan_op_asgn(&a.recv, &a.value, class, params, locals, entry),
        Node::AndAsgn(a) => scan_op_asgn(&a.recv, &a.value, class, params, locals, entry),
        Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_) => {}
        _ => {
            for child in ruby_ast_children(node) {
                scan_ruby_receiver_types(child, class, params, locals, entry);
            }
        }
    }
}

fn scan_op_asgn(
    recv: &Node,
    value: &Node,
    class: &str,
    params: &[String],
    locals: &mut HashMap<String, RubyReceiverType>,
    entry: &mut ClassEntry,
) {
    scan_ruby_receiver_types(value, class, params, locals, entry);
    if let Some(attr) = ruby_instance_variable_target(recv) {
        record_ivar_named(&attr, value, params, locals, Some(class), entry);
    }
    if let Some(name) = ruby_local_variable_target(recv)
        && let Some(ty) = ruby_expression_receiver_type(value, locals, params, Some(class), entry)
    {
        locals.insert(name, ty);
    }
}

fn record_ivar(
    raw: &str,
    value: &Node,
    params: &[String],
    locals: &HashMap<String, RubyReceiverType>,
    enclosing: Option<&str>,
    entry: &mut ClassEntry,
) {
    record_ivar_named(
        raw.trim_start_matches('@'),
        value,
        params,
        locals,
        enclosing,
        entry,
    );
}

fn record_ivar_named(
    attr: &str,
    value: &Node,
    params: &[String],
    locals: &HashMap<String, RubyReceiverType>,
    enclosing: Option<&str>,
    entry: &mut ClassEntry,
) {
    if let Node::Lvar(v) = value
        && params.contains(&v.name)
    {
        entry.attr_params.retain(|(x, _)| x != attr);
        entry.attr_classes.retain(|(x, _)| x != attr);
        entry.attr_params.push((attr.to_string(), v.name.clone()));
        return;
    }
    if let Some(RubyReceiverType::Instance(c)) =
        ruby_expression_receiver_type(value, locals, params, enclosing, entry)
    {
        entry.attr_params.retain(|(x, _)| x != attr);
        entry.attr_classes.retain(|(x, _)| x != attr);
        entry.attr_classes.push((attr.to_string(), c));
    }
}

/// Infer a Ruby return class only when at least one instance class is recovered
/// and all recovered classes agree.
pub(super) fn infer_ruby_return_class(
    body: &Node,
    class: &str,
    params: &[String],
    entry: &ClassEntry,
) -> Option<String> {
    let mut locals = HashMap::new();
    let mut scratch = entry.clone();
    scan_ruby_receiver_types(body, class, params, &mut locals, &mut scratch);
    let mut types = Vec::new();
    collect_return_types(body, &locals, params, Some(class), entry, &mut types);
    let last = last_expr(body);
    if !matches!(last, Node::Return(_))
        && let Some(RubyReceiverType::Instance(c)) =
            ruby_expression_receiver_type(last, &locals, params, Some(class), entry)
    {
        types.push(c);
    }
    let first = types.first()?.clone();
    types.iter().all(|t| *t == first).then_some(first)
}

fn collect_return_types(
    node: &Node,
    locals: &HashMap<String, RubyReceiverType>,
    params: &[String],
    enclosing: Option<&str>,
    entry: &ClassEntry,
    out: &mut Vec<String>,
) {
    if let Node::Return(r) = node {
        if let Some(arg) = r.args.first()
            && let Some(RubyReceiverType::Instance(c)) =
                ruby_expression_receiver_type(arg, locals, params, enclosing, entry)
        {
            out.push(c);
        }
        return;
    }
    if matches!(
        node,
        Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_)
    ) {
        return;
    }
    for child in ruby_ast_children(node) {
        collect_return_types(child, locals, params, enclosing, entry, out);
    }
}

fn last_expr(node: &Node) -> &Node {
    match node {
        Node::Begin(b) => b.statements.last().map(last_expr).unwrap_or(node),
        Node::KwBegin(b) => b.statements.last().map(last_expr).unwrap_or(node),
        other => other,
    }
}

fn expr_type_seq(
    stmts: &[Node],
    locals: &HashMap<String, RubyReceiverType>,
    params: &[String],
    enclosing: Option<&str>,
    entry: &ClassEntry,
) -> Option<RubyReceiverType> {
    let mut acc = locals.clone();
    let mut scratch = entry.clone();
    let class = enclosing.unwrap_or("");
    for stmt in stmts {
        scan_ruby_receiver_types(stmt, class, params, &mut acc, &mut scratch);
    }
    stmts
        .last()
        .and_then(|n| ruby_expression_receiver_type(n, &acc, params, enclosing, entry))
}

/// Recover a receiver's class from local and instance bindings available at the expression.
pub(super) fn ruby_expression_receiver_type(
    node: &Node,
    locals: &HashMap<String, RubyReceiverType>,
    params: &[String],
    enclosing: Option<&str>,
    entry: &ClassEntry,
) -> Option<RubyReceiverType> {
    match node {
        Node::Const(_) => ruby_constant_path(node)
            .map(|p| RubyReceiverType::Class(ruby_receiver_type_name(&p, enclosing))),
        Node::Send(s) if s.method_name == "new" => {
            ctor_class(s, locals, enclosing).map(RubyReceiverType::Instance)
        }
        Node::Send(s) if s.recv.is_none() && s.method_name == "Pathname" => {
            Some(RubyReceiverType::Instance("Pathname".to_string()))
        }
        Node::Send(s)
            if matches!(
                s.method_name.as_str(),
                "+" | "/" | "join" | "expand_path" | "realpath"
            ) =>
        {
            match s.recv.as_deref().and_then(|recv| {
                ruby_expression_receiver_type(recv, locals, params, enclosing, entry)
            }) {
                Some(RubyReceiverType::Instance(class)) if class == "Pathname" => {
                    Some(RubyReceiverType::Instance(class))
                }
                _ => None,
            }
        }
        Node::Lvar(v) => locals.get(&v.name).cloned(),
        Node::Ivar(v) => {
            let attr = v.name.trim_start_matches('@');
            entry
                .attr_classes
                .iter()
                .find(|(a, _)| a == attr)
                .map(|(_, c)| RubyReceiverType::Instance(c.clone()))
        }
        Node::Begin(b) => expr_type_seq(&b.statements, locals, params, enclosing, entry),
        Node::KwBegin(b) => expr_type_seq(&b.statements, locals, params, enclosing, entry),
        Node::OrAsgn(a) => {
            ruby_expression_receiver_type(&a.value, locals, params, enclosing, entry)
        }
        Node::AndAsgn(a) => {
            ruby_expression_receiver_type(&a.value, locals, params, enclosing, entry)
        }
        Node::Ivasgn(a) => a
            .value
            .as_deref()
            .and_then(|v| ruby_expression_receiver_type(v, locals, params, enclosing, entry)),
        Node::Lvasgn(a) => a
            .value
            .as_deref()
            .and_then(|v| ruby_expression_receiver_type(v, locals, params, enclosing, entry)),
        _ => None,
    }
}

fn ctor_class(
    s: &Send,
    locals: &HashMap<String, RubyReceiverType>,
    enclosing: Option<&str>,
) -> Option<String> {
    if let Some(path) = s.recv.as_deref().and_then(ruby_constant_path) {
        return Some(ruby_receiver_type_name(&path, enclosing));
    }
    if let Some(Node::Lvar(v)) = s.recv.as_deref()
        && let Some(RubyReceiverType::Class(c)) = locals.get(&v.name)
    {
        return Some(c.clone());
    }
    None
}

/// Preserve a qualified constant path unless its last segment equals the
/// enclosing class; then use the parent segment so `Foo::Engine::CLI`
/// constructed inside `CLI` types as `Engine` rather than colliding.
pub(super) fn ruby_receiver_type_name(path: &str, enclosing: Option<&str>) -> String {
    let last = ruby_constant_last_segment(path).to_string();
    if enclosing == Some(last.as_str())
        && let Some((parent, _)) = path.rsplit_once("::")
    {
        return ruby_constant_last_segment(parent).to_string();
    }
    if path.contains("::") {
        path.to_string()
    } else {
        last
    }
}
