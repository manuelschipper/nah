//! Parameterized PHP body effects and their control-flow sites.

use std::collections::HashMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, Modality, Operation,
    ResourceExpr, ResourceIdentity,
};
use tree_sitter::Node;

use crate::SemanticValue;
use crate::builder::KNOWN_DOMAINS;
use crate::control_flow::{
    ControlCaps, ControlExit, ControlFact, ControlFlow, ControlStack, SiteFacts,
};
use crate::lang::conditions::tree_condition;
use crate::lang::tree_sitter_nodes::node_span;
use crate::summary::has_text_concat;
use crate::value::unresolved_resource;

use super::super::syntax::{arg_nodes, callable_name, child_kind, literal_string, text};
use super::super::walker::environment::{
    env_effect, environment_effect, putenv_effect, superglobal_resource,
};
use super::super::walker::resource_recovery::{absolute_url_endpoint, recover_php_expression};
use super::super::{DEFAULT_MAX_PHP_NODES, DOMAINS, control};

/// Summarize a function body's parameterized effects and boundaries. Subprocess
/// spawns cannot nest inside a stored summary, so they also become an
/// `uncomposed_subprocess` boundary.
pub(super) fn summarize_body(
    body: Option<Node>,
    params: &[String],
    src: &str,
) -> (Vec<Effect>, Vec<Boundary>, ControlFlow) {
    let _walk = crate::limits::summary_walk();
    let param_env: HashMap<String, ResourceExpr> = params
        .iter()
        .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
        .collect();
    let Some(body) = body else {
        return (Vec::new(), Vec::new(), ControlFlow::widened());
    };
    let mut c = body.walk();
    let children: Vec<Node> = body.named_children(&mut c).collect();
    let mut control = ControlStack::default();
    let limits = crate::AnalysisLimits::default();
    control.enter(
        src,
        true,
        Default::default(),
        0,
        0,
        None,
        ControlCaps {
            nodes: limits.max_causal_nodes,
            work: limits.max_causal_pairs,
        },
        |graph| control::build_php_control_flow(graph, &children, src),
    );
    let mut cap = PhpCaptureWalker {
        control,
        effects: Vec::new(),
        boundaries: Vec::new(),
        env: param_env,
        src,
        nodes: crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES),
        truncated: false,
    };
    for ch in &children {
        cap.walk(*ch);
    }
    if cap.truncated {
        cap.control.widen();
    }
    let finished = cap.control.leave(0).expect("PHP summary frame");
    if let Some(limit) = finished.refused {
        cap.boundaries.push(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
            provenance: Vec::new(),
            limit: Some(limit.to_string()),
            detail: Some("PHP summary control flow widened".to_string()),
            affected_resource: None,
            callee: None,
        });
    }
    (cap.effects, cap.boundaries, finished.flow)
}

struct PhpCaptureWalker<'a> {
    control: ControlStack,
    effects: Vec<Effect>,
    boundaries: Vec<Boundary>,
    env: HashMap<String, ResourceExpr>,
    src: &'a str,
    nodes: u64,
    truncated: bool,
}

impl<'a> PhpCaptureWalker<'a> {
    fn walk(&mut self, n: Node<'a>) {
        // Same left-deep `.` hazard as PhpWalker::exec.
        let mut stack = vec![n];
        while let Some(n) = stack.pop() {
            if self.nodes == 0 || !crate::limits::summary_step() {
                if !self.truncated {
                    self.truncated = true;
                    self.boundaries.push(Boundary {
                        reason: BoundaryReason::PARTIAL_ANALYSIS,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                        provenance: vec![],
                        limit: Some("max_php_nodes".to_string()),
                        detail: Some("php summary walk node budget exhausted".to_string()),
                    });
                }
                return;
            }
            self.nodes -= 1;
            let effect_start = self.effects.len();
            match n.kind() {
                "function_definition" | "method_declaration" | "class_declaration" => continue,
                "function_call_expression" => self.capture_php_summary_call(n),
                "assignment_expression" => {
                    if let Some(left) = n.child_by_field_name("left")
                        && let Some((name, resource)) = superglobal_resource(left, self.src)
                        && name == "_ENV"
                    {
                        self.effects.push(environment_effect(resource, false));
                    }
                }
                "unset_statement" => {
                    let mut cursor = n.walk();
                    for target in n.named_children(&mut cursor) {
                        if let Some((name, resource)) = superglobal_resource(target, self.src)
                            && name == "_ENV"
                        {
                            self.effects.push(environment_effect(resource, true));
                        }
                    }
                }
                "member_call_expression" | "scoped_call_expression" => {
                    let method = child_kind(n, "name")
                        .map(|m| text(m, self.src))
                        .unwrap_or("");
                    if matches!(method, "exec" | "query" | "prepare") {
                        self.boundaries.push(Boundary {
                            reason: BoundaryReason::UNCOMPOSED_QUERY,
                            class: BoundaryClass::Unmodeled,
                            scope: BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("database")],
                            provenance: vec![],
                            limit: None,
                            detail: None,
                        });
                    }
                }
                _ => {}
            }
            let direct_sink = (n.kind() == "function_call_expression"
                && callable_name(n, self.src).as_deref() == Some("unlink"))
                || matches!(n.kind(), "assignment_expression" | "unset_statement");
            if direct_sink {
                self.control.register(
                    self.src,
                    true,
                    node_span(n),
                    SiteFacts::known(
                        (effect_start..self.effects.len())
                            .map(|slot| ControlFact::Effect(slot as u32))
                            .collect(),
                    ),
                );
            } else if matches!(
                n.kind(),
                "require_expression"
                    | "require_once_expression"
                    | "include_expression"
                    | "include_once_expression"
            ) && let Some(module) = n
                .named_child(0)
                .and_then(|value| literal_string(value, self.src))
            {
                let mut facts = SiteFacts::known(Vec::new());
                facts.exit = Some(ControlExit::Import { module });
                self.control.register(self.src, true, node_span(n), facts);
            }
            let guard = (self.effects.len() != effect_start)
                .then(|| tree_condition(self.src, n))
                .flatten();
            for effect in &mut self.effects[effect_start..] {
                effect.condition = effinterp_proto::Condition::compose(
                    effect.condition.iter().chain(guard.iter()),
                );
            }
            let mut c = n.walk();
            let children: Vec<Node> = n.named_children(&mut c).collect();
            for ch in children.into_iter().rev() {
                stack.push(ch);
            }
        }
    }
}

impl<'a> PhpCaptureWalker<'a> {
    fn capture_php_summary_call(&mut self, n: Node<'a>) {
        let Some(name_node) = child_kind(n, "name") else {
            self.boundaries.push(Boundary {
                reason: BoundaryReason::DYNAMIC_CALL,
                class: BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: n.child_by_field_name("function").map(|function| {
                    effinterp_proto::CalleeReference {
                        module: "php".to_string(),
                        symbol: text(function, self.src).to_string(),
                    }
                }),
                domains: KNOWN_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: Vec::new(),
                limit: None,
                detail: Some(format!(
                    "dynamic call at {}..{}",
                    n.start_byte(),
                    n.end_byte()
                )),
            });
            return;
        };
        let fname = text(name_node, self.src);
        let args = arg_nodes(n);
        if fname == "file_get_contents"
            && let Some(resource) = args
                .first()
                .and_then(|arg| literal_string(*arg, self.src))
                .and_then(|url| absolute_url_endpoint(&url))
        {
            self.push_effect("network.request", resource);
            return;
        }
        if matches!(fname, "fsockopen" | "pfsockopen" | "stream_socket_client") {
            let resource = args
                .first()
                .and_then(|arg| literal_string(*arg, self.src))
                .and_then(|url| absolute_url_endpoint(&url))
                .unwrap_or(unresolved_resource("network"));
            self.push_effect("network.request", resource);
            return;
        }
        if fname == "curl_exec" {
            self.push_effect("network.request", unresolved_resource("network"));
            return;
        }
        if matches!(fname, "curl_init" | "curl_setopt") {
            return;
        }
        if fname == "getenv" {
            self.effects.push(env_effect(
                args.first().copied(),
                self.src,
                "environment.read",
            ));
            return;
        }
        if fname == "putenv" {
            self.effects
                .push(putenv_effect(args.first().copied(), self.src));
            return;
        }
        // Filesystem/effect builtins contribute parameterized effects.
        let op = match fname {
            "unlink" | "rmdir" => Some("filesystem.delete"),
            "mkdir" => Some("filesystem.create"),
            "file_put_contents" => Some("filesystem.write"),
            "readfile" | "file_get_contents" => Some("filesystem.read"),
            _ => None,
        };
        if let Some(op) = op {
            let resource = args
                .first()
                .map(|a| recover_php_expression(*a, self.src, &self.env))
                .unwrap_or(unresolved_resource("filesystem"));
            self.push_effect(op, resource);
            return;
        }
        if matches!(
            fname,
            "system" | "exec" | "shell_exec" | "passthru" | "proc_open" | "popen"
        ) {
            let resource = args
                .first()
                .and_then(|arg| literal_string(*arg, self.src))
                .and_then(|command| command.split_whitespace().next().map(str::to_string))
                .map(|executable| ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable,
                        path: None,
                        argv: Vec::new(),
                        cwd: None,
                    },
                })
                .unwrap_or(unresolved_resource("process"));
            self.push_effect("process.exec", resource.clone());
            self.boundaries.push(Boundary {
                reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
                class: BoundaryClass::Unmodeled,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: Some(resource),
                callee: None,
                domains: vec![Domain::new("process")],
                provenance: vec![],
                limit: None,
                detail: None,
            });
        }
    }

    fn push_effect(&mut self, operation: &str, resource: ResourceExpr) {
        let mut effect = Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: None,
            realm: Default::default(),
            provenance: vec![],
        };
        if !has_text_concat(&effect.resource) {
            let value = SemanticValue::from(&effect.resource);
            crate::lower_effect_value(&mut effect, &value);
        }
        self.effects.push(effect);
    }
}
