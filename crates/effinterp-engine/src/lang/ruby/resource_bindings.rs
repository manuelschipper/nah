use std::collections::{HashMap, HashSet};

use effinterp_proto::ResourceExpr;
use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::ValueArgument;
use crate::summary::contains_unresolved;
use crate::value::{bind_arguments, unresolved_resource};

use super::file_context::RubyFileContext;
use super::model::{self, resolve, value_arguments};
use super::receiver_types::ruby_receiver_type_name;
use super::syntax::{ruby_ast_children, ruby_constant_path};

/// Bind only named arguments the Ruby method declares as keywords.
pub(super) fn bind_ruby_call_resources(
    params: &[String],
    keywords: &HashSet<String>,
    arguments: &[ValueArgument],
) -> HashMap<String, ResourceExpr> {
    let arguments: Vec<_> = arguments
        .iter()
        .filter(|argument| {
            argument
                .name
                .as_ref()
                .is_none_or(|name| keywords.contains(name))
        })
        .cloned()
        .collect();
    bind_arguments(params, &arguments)
        .into_iter()
        .map(|(name, value)| (name, value.lower_resource()))
        .collect()
}

pub(super) fn constructor_instance(
    node: &Node,
    caller_env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
) -> Option<HashMap<String, ResourceExpr>> {
    let Node::Send(send) = node else {
        return None;
    };
    if send.method_name != "new" {
        return None;
    }
    let class = ruby_receiver_type_name(
        &send.recv.as_deref().and_then(ruby_constant_path)?,
        enclosing,
    );
    let definition = ctx.method_definition(&format!("{class}.initialize"))?;
    let mut bindings = bind_ruby_call_resources(
        &definition.params,
        &definition.keywords,
        &value_arguments(&send.args, caller_env, cwd),
    );
    for (name, default) in &definition.defaults {
        bindings
            .entry(name.clone())
            .or_insert_with(|| resolve(default, caller_env, cwd));
    }
    let mut values = HashMap::new();
    let body = definition.body.as_deref()?;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if let Node::Ivasgn(assignment) = node
            && let Some(value) = assignment.value.as_deref()
        {
            let resolved = resolve(value, &bindings, cwd);
            if !contains_unresolved(&resolved) {
                values.insert(assignment.name.clone(), resolved);
            }
        }
        if !matches!(
            node,
            Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_)
        ) {
            stack.extend(ruby_ast_children(node));
        }
    }
    Some(values)
}

pub(super) fn instance_bindings(
    send: &Send,
    instances: &HashMap<String, HashMap<String, ResourceExpr>>,
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
) -> HashMap<String, ResourceExpr> {
    match send.recv.as_deref() {
        Some(Node::Lvar(local)) => instances.get(&local.name).cloned().unwrap_or_default(),
        Some(node @ Node::Send(_)) => {
            constructor_instance(node, env, cwd, enclosing, ctx).unwrap_or_default()
        }
        None | Some(Node::Self_(_)) => env
            .iter()
            .filter(|(name, _)| name.starts_with('@'))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        _ => HashMap::new(),
    }
}

pub(super) fn unresolved_instance_parameters(resource: &mut ResourceExpr) {
    match resource {
        ResourceExpr::Parameter { name } if name.starts_with('@') => {
            *resource = unresolved_resource("filesystem");
        }
        ResourceExpr::Join { parts } => {
            for part in parts {
                unresolved_instance_parameters(part);
            }
        }
        ResourceExpr::Union { alternatives } => {
            for alternative in alternatives {
                unresolved_instance_parameters(alternative);
            }
        }
        ResourceExpr::Property { base, .. } => unresolved_instance_parameters(base),
        _ => {}
    }
}

/// Record what an assignment to `name` leaves it holding. A conditional
/// assignment of anything else may be skipped, so an earlier body may remain.
pub(super) fn note_remote_body(
    bodies: &mut HashMap<String, ResourceExpr>,
    name: &str,
    body: Option<ResourceExpr>,
    guarded: bool,
) {
    match body {
        Some(endpoint) => {
            bodies.insert(name.to_string(), endpoint);
        }
        None if !guarded => {
            bodies.remove(name);
        }
        None => {}
    }
}

/// A local assigned a decoder's result may hold decoded text; an unguarded
/// assignment of anything else replaces it.
pub(super) fn note_decoded_local(
    locals: &mut HashSet<String>,
    name: &str,
    value: &Node,
    guarded: bool,
) {
    if model::decoded(value) {
        locals.insert(name.to_string());
    } else if !guarded {
        locals.remove(name);
    }
}

pub(super) fn store_binding(
    env: &mut HashMap<String, ResourceExpr>,
    poisoned: &mut HashSet<String>,
    name: &str,
    value: ResourceExpr,
    guarded: bool,
) {
    let conflict = guarded && env.get(name).is_some_and(|current| current != &value);
    if conflict || contains_unresolved(&value) {
        env.insert(name.to_string(), unresolved_resource("filesystem"));
        poisoned.insert(name.to_string());
    } else {
        env.insert(name.to_string(), value);
        poisoned.remove(name);
    }
}

pub(super) fn remove_assignment_bindings(
    node: &Node,
    env: &mut HashMap<String, ResourceExpr>,
    poisoned: &mut HashSet<String>,
) {
    match node {
        Node::Lvar(local) => {
            env.remove(&local.name);
            poisoned.remove(&local.name);
        }
        Node::Lvasgn(local) => {
            env.remove(&local.name);
            poisoned.remove(&local.name);
        }
        Node::Ivar(variable) => {
            env.remove(&variable.name);
            poisoned.remove(&variable.name);
        }
        Node::Ivasgn(variable) => {
            env.remove(&variable.name);
            poisoned.remove(&variable.name);
        }
        _ => {
            for child in ruby_ast_children(node) {
                remove_assignment_bindings(child, env, poisoned);
            }
        }
    }
}
