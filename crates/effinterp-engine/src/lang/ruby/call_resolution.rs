use std::collections::HashSet;

use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::ObjectIdentity;
use crate::module_summary::CallEdge;

use super::file_context::RubyFileContext;
use super::load_path;
use super::syntax::ruby_constant_path;

/// Name a receiver call for a boundary only when the file and load path leave its dispatch unmodeled.
pub(super) fn unmodeled_ruby_receiver_call(send: &Send, ctx: &RubyFileContext) -> Option<String> {
    if load_path::inert_call(send)
        || ctx
            .load_path
            .inert
            .contains(&(send.expression_l.begin, send.expression_l.end))
    {
        return None;
    }
    // `File.join` only concatenates path strings.
    if send.method_name == "join"
        && send.recv.as_deref().and_then(ruby_constant_path).as_deref() == Some("File")
    {
        return None;
    }
    let mut receiver = send.recv.as_deref()?;
    let mut methods = vec![send.method_name.as_str()];
    while let Node::Send(inner) = receiver {
        methods.push(inner.method_name.as_str());
        let Some(next) = inner.recv.as_deref() else {
            methods.reverse();
            return Some(methods.join("."));
        };
        receiver = next;
    }
    let name = match receiver {
        Node::Lvar(value) => value.name.clone(),
        Node::Ivar(value) => value.name.clone(),
        Node::Self_(_) => "self".to_string(),
        _ => ruby_constant_path(receiver).unwrap_or_else(|| "<expression>".to_string()),
    };
    if ctx
        .classes
        .iter()
        .chain(&ctx.exact_classes)
        .any(|class| class.name == name)
    {
        return None;
    }
    methods.reverse();
    Some(format!("{name}.{}", methods.join(".")))
}

/// The same-file def a call edge resolves to, if any: a qualified or bare
/// callee defined here, or the constructor of a locally defined class.
pub(super) fn resolve_same_file_ruby_call(
    ctx: &RubyFileContext,
    edge: &CallEdge,
) -> Option<String> {
    if let Some(ObjectIdentity::Class { name, .. }) = edge.receiver_identity() {
        if edge.callee == *name {
            let init = format!("{name}.__init__");
            return ctx
                .method_definition(&init)
                .map(|_| init)
                .or_else(|| resolve_ruby_receiver_method(ctx, name, "initialize"));
        }
        // A method on a typed receiver: resolve through the receiver's class
        // and same-file bases (a subclass inherits the parent's commands).
        if let Some((_, method)) = edge.callee.rsplit_once('.') {
            return resolve_ruby_receiver_method(ctx, name, method);
        }
        return None;
    }
    if let Some(ObjectIdentity::ModuleBinding { name, .. }) = edge.receiver_identity()
        && let Some((_, method)) = edge.callee.rsplit_once('.')
    {
        return resolve_ruby_receiver_method(ctx, name, method);
    }
    if edge.receiver.is_some() {
        return None;
    }
    ctx.method_definition(&edge.callee)
        .map(|_| edge.callee.clone())
}

/// Search the receiver's exact class and its same-file bases in lookup order.
pub(super) fn resolve_ruby_receiver_method(
    ctx: &RubyFileContext,
    class: &str,
    method: &str,
) -> Option<String> {
    let mut seen = HashSet::new();
    let mut stack = vec![class.to_string()];
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let qualified = format!("{name}.{method}");
        if ctx.method_definition(&qualified).is_some() {
            return Some(qualified);
        }
        if let Some(entry) = ctx
            .exact_classes
            .iter()
            .find(|class| class.name == name)
            .or_else(|| ctx.classes.iter().find(|class| class.name == name))
        {
            for base in entry.bases.iter().rev() {
                stack.push(local_base(ctx, &name, base));
            }
        }
    }
    None
}

fn local_base(ctx: &RubyFileContext, owner: &str, base: &str) -> String {
    if base.contains("::") {
        return base.to_string();
    }
    if let Some((namespace, _)) = owner.rsplit_once("::") {
        let qualified = format!("{namespace}::{base}");
        if ctx
            .exact_classes
            .iter()
            .any(|class| class.name == qualified)
        {
            return qualified;
        }
    }
    base.to_string()
}
