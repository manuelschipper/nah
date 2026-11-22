//! PHP environment reads and writes, including superglobals and host values.

use effinterp_proto::{
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};
use tree_sitter::Node;

use crate::value::unresolved_resource;

use super::super::syntax::{child_kind, literal_string, text};
use super::PhpWalker;

/// Recover a subscript's superglobal name and key without deciding whether it is read or written.
pub(in crate::lang::php) fn superglobal_resource(
    n: Node,
    src: &str,
) -> Option<(String, ResourceExpr)> {
    if n.kind() != "subscript_expression" {
        return None;
    }
    let mut cursor = n.walk();
    let mut named = n.named_children(&mut cursor);
    let (Some(base), Some(index)) = (named.next(), named.next()) else {
        return None;
    };
    if base.kind() != "variable_name" {
        return None;
    }
    let name = child_kind(base, "name").map(|name| text(name, src).to_string())?;
    let resource = literal_string(index, src)
        .filter(|name| !name.is_empty())
        .map(|name| ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        })
        .unwrap_or(unresolved_resource("environment"));
    Some((name, resource))
}

/// Whether an environment subscript is being assigned or unset rather than read.
fn is_environment_mutation_target(n: Node) -> bool {
    n.parent().is_some_and(|p| {
        (p.kind() == "assignment_expression"
            && p.child_by_field_name("left")
                .is_some_and(|l| l.id() == n.id()))
            || p.kind() == "unset_statement"
    })
}

fn server_request_key(name: &str) -> bool {
    [
        "HTTP_", "REQUEST_", "REMOTE_", "SERVER_", "SCRIPT_", "CONTENT_", "AUTH_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        || matches!(
            name,
            "QUERY_STRING"
                | "PHP_SELF"
                | "PATH_INFO"
                | "DOCUMENT_ROOT"
                | "HTTPS"
                | "GATEWAY_INTERFACE"
        )
}

pub(in crate::lang::php) fn env_effect(arg: Option<Node>, src: &str, op: &str) -> Effect {
    let resource = arg
        .and_then(|a| literal_string(a, src))
        .map(|name| {
            // putenv("X=Y") carries name=value; getenv("X") carries the name.
            name.split('=').next().unwrap_or(&name).to_string()
        })
        .filter(|name| !name.is_empty())
        .map(|name| ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        })
        .unwrap_or(unresolved_resource("environment"));
    environment_effect_with_operation(op, resource, false)
}

pub(in crate::lang::php) fn putenv_effect(arg: Option<Node>, src: &str) -> Effect {
    let unset = arg
        .and_then(|argument| literal_string(argument, src))
        .is_some_and(|value| !value.contains('='));
    let mut effect = env_effect(arg, src, "environment.write");
    if unset {
        effect
            .attributes
            .insert("unset".to_string(), effinterp_proto::AttrValue::Bool(true));
    }
    effect
}

pub(in crate::lang::php) fn environment_effect(resource: ResourceExpr, unset: bool) -> Effect {
    environment_effect_with_operation("environment.write", resource, unset)
}

fn environment_effect_with_operation(op: &str, resource: ResourceExpr, unset: bool) -> Effect {
    Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(op),
        resource,
        attributes: unset
            .then(|| ("unset".to_string(), effinterp_proto::AttrValue::Bool(true)))
            .into_iter()
            .collect(),
        modality: Modality::May,
        execution: effinterp_proto::ExecutionNodeRef(0),
        condition: None,
        realm: Default::default(),
        provenance: vec![],
    }
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// `$_ENV['NAME']` / `$_SERVER['NAME']` read as an environment read. The
    /// same node shape is also how a write (`$_ENV['NAME'] = ...`) reaches
    /// this call via the generic recursion, so a subscript on the left of an
    /// assignment is skipped rather than reported as a read.
    pub(super) fn read_php_superglobal(&mut self, n: Node<'a>) {
        if is_environment_mutation_target(n) {
            return;
        }
        let Some((name, resource)) = superglobal_resource(n, self.src) else {
            return;
        };
        if name != "_ENV" && name != "_SERVER" {
            return;
        }
        if name == "_SERVER"
            && matches!(&resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } if server_request_key(name))
        {
            return;
        }
        self.emit(
            Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("environment.read"),
                resource,
                attributes: Default::default(),
                modality: Modality::May,
                execution: effinterp_proto::ExecutionNodeRef(0),
                condition: None,
                realm: Default::default(),
                provenance: vec![],
            },
            n,
        );
    }

    /// Replace `getenv(...)` references with the values the enclosing
    /// execution or host supplied, so `getenv("HOME")."/x"` names the same
    /// file as the path written out. Reports whether any was replaced.
    pub(super) fn resolve_host_environment(
        &mut self,
        resource: &mut ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) -> bool {
        match resource {
            ResourceExpr::Environment { name } => {
                let Some(value) = self.host_environment_value(name) else {
                    return false;
                };
                let node = self.nest.current_environment_node(name).unwrap_or_else(|| {
                    self.builder.node(
                        ProvenanceKind::HostContext {
                            name: format!("env.{name}"),
                        },
                        &[],
                    )
                });
                provenance.push(node);
                *resource = value;
                true
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => parts.iter_mut().fold(false, |replaced, part| {
                self.resolve_host_environment(part, provenance) || replaced
            }),
            _ => false,
        }
    }

    /// The effective value of one environment name, preferring an override the
    /// enclosing execution established over the value the host supplied.
    fn host_environment_value(&self, name: &str) -> Option<ResourceExpr> {
        if self.environment_rewritten || self.nest.current_environment_unsets().contains(name) {
            return None;
        }
        if let Some(value) = self
            .nest
            .environments
            .borrow()
            .last()
            .and_then(|environment| environment.get(name))
        {
            return value.clone();
        }
        self.nest
            .context
            .and_then(|context| context.env.get(name))
            .map(|value| ResourceExpr::Literal {
                value: value.clone(),
            })
    }
}
