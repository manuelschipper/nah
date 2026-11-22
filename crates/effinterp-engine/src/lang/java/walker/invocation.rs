//! Calls reached during Java execution, from local methods to nested invocations.

use super::super::call_resolution::{is_java_type_name, jdk_receiver_type};
use super::super::callbacks::{
    callback_bindings, callback_method, callbacks_execute_at, java_callback_arguments,
    lambda_param_names, method_reference_parts, recover_java_callback_inputs,
};
use super::super::model::{
    ModeledOp, ModeledTransfer, filter_file_stream_ops, http_verb_of_expr, identity_java_call,
    is_reflection, model_creation, model_ops, model_transfer, network_operation,
};
use super::super::resource_recovery::{
    invocation_string_argument, is_unresolved, iterable_element, java_network_sink,
    recover_java_arguments, recover_typed_java_resource,
};
use super::super::syntax::{
    bare_java_type, first_argument, java_node_text, receiver_identifier, unquote_java_string,
};
use super::super::{JAVA_DOMAINS, MAX_CALL_DEPTH};
use super::{JavaMethodFrame, JavaWalker};
use crate::builder::PlanBuilder;
use crate::external::{ALL_DOMAINS, Domains, ExternalCall, classify_java_call};
use crate::lang::conditions;
use crate::nest::{Transition, word_resource};
use crate::summary::bind_positional;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ResourceExpr, ResourceIdentity,
    SqlConnection, SqlDialect, Subject,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// A local method candidate carries its declaring class, parameter bindings,
/// optional varargs name, and body node.
type JavaMethodCandidate<'a> = (
    String,
    Vec<String>,
    Vec<(String, String)>,
    Option<String>,
    Node<'a>,
);

impl<'a> JavaWalker<'a> {
    /// Follow all same-file methods of `class` named `name` with `args` bound.
    fn follow_local(
        &mut self,
        builder: &mut PlanBuilder,
        class: &str,
        name: &str,
        n: Node<'a>,
        frame: &JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) -> bool {
        let args =
            recover_java_arguments(n, self.src, &frame.env, &self.file.constants, &frame.types);
        let guard = conditions::tree_condition(
            std::str::from_utf8(self.src).expect("parsed UTF-8 source"),
            n,
        );
        if let Some(guard) = &guard {
            builder.push_condition(guard.clone());
        }
        let previous = builder.enter_condition_call(&effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
            &(self.src, n.start_byte(), n.end_byte()),
        ));
        let result = self
            .follow_local_with_args(builder, class, name, &args, Some(&frame.instance), visiting)
            .0;
        builder.leave_condition_call(previous);
        if guard.is_some() {
            builder.pop_condition();
        }
        result
    }

    fn follow_local_with_args(
        &mut self,
        builder: &mut PlanBuilder,
        class: &str,
        name: &str,
        args: &[ResourceExpr],
        instance: Option<&HashMap<String, ResourceExpr>>,
        visiting: &mut HashSet<usize>,
    ) -> (bool, HashMap<String, ResourceExpr>) {
        let candidates: Vec<JavaMethodCandidate<'a>> = self
            .file
            .resolve_local_java_methods(class, name, Some(args.len()))
            .iter()
            .map(|m| {
                (
                    m.class.clone(),
                    m.params.iter().map(|p| p.name.clone()).collect(),
                    m.params
                        .iter()
                        .map(|p| (p.name.clone(), p.ty.clone()))
                        .collect(),
                    m.params
                        .last()
                        .filter(|param| param.varargs)
                        .map(|param| param.name.clone()),
                    m.body,
                )
            })
            .collect();
        if candidates.is_empty() {
            return (false, instance.cloned().unwrap_or_default());
        }
        let mut result = instance.cloned().unwrap_or_default();
        for (mclass, param_names, param_types, varargs, body) in candidates {
            if visiting.contains(&body.id()) {
                self.boundary(
                    builder,
                    body,
                    BoundaryReason::RECURSIVE_CALL,
                    BoundaryClass::Unresolved,
                    &format!("recursive call to {mclass}.{name}"),
                    &JAVA_DOMAINS,
                );
                continue;
            }
            if self.depth + visiting.len() as u64 >= MAX_CALL_DEPTH {
                self.control_unknowns += 1;
                let node = self.node(builder, body);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: JAVA_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![node],
                    limit: Some("max_java_call_depth".to_string()),
                    detail: Some(format!("call to {mclass}.{name}")),
                });
                return (true, result);
            }
            let bindings = bind_positional(&param_names, args);
            let mut env = instance.cloned().unwrap_or_default();
            env.extend(bindings);
            let mut arrays = HashMap::new();
            if let Some(varargs) = varargs {
                let index = param_names.len().saturating_sub(1);
                arrays.insert(varargs, args.get(index..).unwrap_or(&[]).to_vec());
            }
            let mut giveups: HashSet<String> = instance
                .into_iter()
                .flat_map(|values| values.iter())
                .filter(|(_, value)| is_unresolved(value))
                .map(|(field, _)| field.clone())
                .collect();
            for param in &param_names {
                giveups.remove(param);
            }
            let types = self
                .file
                .class(&mclass)
                .into_iter()
                .flat_map(|class| {
                    class
                        .fields
                        .iter()
                        .map(|(name, ty)| (format!("this.{name}"), ty.clone()))
                })
                .chain(param_types.into_iter())
                .collect();
            let mut callee_frame = JavaMethodFrame {
                env,
                types,
                news: HashMap::new(),
                arrays,
                process_argv: HashMap::new(),
                process_cwd: HashMap::new(),
                allocations: HashMap::new(),
                callbacks: HashMap::new(),
                locals: param_names.into_iter().collect(),
                finals: HashSet::new(),
                tracked: HashSet::new(),
                giveups,
                poisoned: HashSet::new(),
                http_verbs: HashMap::new(),
                instance: instance.cloned().unwrap_or_default(),
                class: mclass,
                constructor: name == "__init__",
            };
            visiting.insert(body.id());
            self.control_body(builder, body, |ctx, builder| {
                ctx.walk_calls(builder, body, &mut callee_frame, visiting)
            });
            visiting.remove(&body.id());
            result.extend(callee_frame.instance);
        }
        (true, result)
    }

    fn field_type(&self, class: &str, name: &str) -> Option<String> {
        self.file.class(class)?.fields.get(name).cloned()
    }

    /// Follows same-file candidates before considering modeled JDK calls.
    pub(super) fn handle_invocation(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        let Some(name) = n
            .child_by_field_name("name")
            .map(|x| java_node_text(x, self.src))
        else {
            return;
        };
        let recv = n.child_by_field_name("object");

        if let Some(recv) = recv
            && recv.kind() == "identifier"
            && matches!(name, "run" | "call" | "apply" | "accept" | "get")
            && let Some(callbacks) = frame.callbacks.get(java_node_text(recv, self.src)).cloned()
        {
            let inputs =
                recover_java_arguments(n, self.src, &frame.env, &self.file.constants, &frame.types);
            for callback in callbacks {
                self.execute_callback(builder, callback, &inputs, frame, visiting);
            }
            return;
        }

        let file_element = (name == "forEach")
            .then(|| {
                recv.and_then(|receiver| {
                    iterable_element(receiver, self.src, &frame.env, &self.file.constants)
                })
            })
            .flatten();
        if callbacks_execute_at(n, name, self.src) {
            let inputs = file_element
                .clone()
                .map(|element| vec![element])
                .unwrap_or_else(|| {
                    recover_java_callback_inputs(n, self.file, self.src, &frame.env, &frame.types)
                });
            for callback in java_callback_arguments(n) {
                self.execute_callback_values(builder, callback, &inputs, frame, visiting);
            }
            for callback in callback_bindings(n, self.src, &frame.callbacks) {
                self.execute_callback_values(builder, callback, &inputs, frame, visiting);
            }
        }

        // Bare call (or `this.m()`): same-file methods take precedence over
        // static imports.
        let bare = recv.is_none() || recv.is_some_and(|r| r.kind() == "this");
        if bare {
            let class = frame.class.clone();
            if self.follow_local(builder, &class, name, n, frame, visiting) {
                return;
            }
            let Some(class) = self.file.static_import_class(name).map(str::to_string) else {
                if !callback_method(name) {
                    for callback in java_callback_arguments(n) {
                        self.execute_callback_values(builder, callback, &[], frame, visiting);
                    }
                    for callback in callback_bindings(n, self.src, &frame.callbacks) {
                        self.execute_callback_values(builder, callback, &[], frame, visiting);
                    }
                }
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    name,
                    ALL_DOMAINS,
                );
                return;
            };
            if !class.starts_with("java.") && !class.starts_with("jdk.") {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    &format!("{class}.{name}"),
                    ALL_DOMAINS,
                );
                return;
            }
            let ty = bare_java_type(&class);
            if is_reflection(Some(&ty), name) {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNMODELED_DYNAMIC_CODE,
                    BoundaryClass::Unresolved,
                    "java reflection",
                    ALL_DOMAINS,
                );
                return;
            }
            let args =
                recover_java_arguments(n, self.src, &frame.env, &self.file.constants, &frame.types);
            if identity_java_call(&ty, name, n, self.src) {
                return;
            }
            if let Some(ops) = model_ops(&ty, name, unresolved_resource("filesystem"), &args) {
                let ops = filter_file_stream_ops(ops, &ty, name, n, self.src, &frame.types);
                self.emit_giveup_boundaries(builder, n, frame, &ops);
                self.emit_ops(builder, n, ops, model_transfer(&ty, name));
            } else if let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&class, name)
            {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::EXTERNAL_UNMODELED,
                    BoundaryClass::Unmodeled,
                    &format!("{class}.{name} is an unmodeled JDK call"),
                    domains,
                );
            }
            return;
        }
        let recv = recv.unwrap();
        self.track_process_mutations(n, name, recv, frame);

        // A typed receiver naming a same-file class (static call, declared
        // local/param/field, or `new X(...)`): follow within the file.
        let mut followed = false;
        for ty in self.same_file_receivers(recv, frame) {
            let creations = self.receiver_creations(recv, frame, &ty);
            if creations.is_empty() {
                followed |= self.follow_local(builder, &ty, name, n, frame, visiting);
                continue;
            }
            for creation in creations {
                self.ensure_instance(builder, creation, frame, visiting);
                let args = recover_java_arguments(
                    n,
                    self.src,
                    &frame.env,
                    &self.file.constants,
                    &frame.types,
                );
                let instance = frame.allocations.get(&creation.id()).cloned();
                followed |= self
                    .follow_local_with_args(builder, &ty, name, &args, instance.as_ref(), visiting)
                    .0;
            }
        }
        if followed {
            return;
        }

        if name == "setRequestMethod"
            && let Some(receiver) = receiver_identifier(recv, self.src)
        {
            let verb = invocation_string_argument(n, self.src, &self.file.constants)
                .unwrap_or_else(|| "GET".to_string());
            frame.http_verbs.insert(receiver.to_string(), verb);
        }

        let modeled = self.model(n, name, recv, frame);
        if matches!(modeled, None | Some(JavaModeledCall::Boundary(..))) && !callback_method(name) {
            for callback in java_callback_arguments(n) {
                self.execute_callback_values(builder, callback, &[], frame, visiting);
            }
            for callback in callback_bindings(n, self.src, &frame.callbacks) {
                self.execute_callback_values(builder, callback, &[], frame, visiting);
            }
        }
        match modeled {
            Some(JavaModeledCall::Ops(ops, transfer)) => {
                self.emit_giveup_boundaries(builder, n, frame, &ops);
                self.emit_ops(builder, n, ops, transfer);
            }
            Some(JavaModeledCall::Shell(cmd)) => {
                let node = self.node(builder, n);
                self.nest.nest(
                    builder,
                    Transition::file(Subject::Shell {
                        source: cmd,
                        cwd: self.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .source_cwd(self.nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
                    .cwd(
                        builder.current_execution_cwd(),
                        self.nest.current_cwd_node(),
                    ),
                    &[node],
                    self.depth,
                );
            }
            Some(JavaModeledCall::Exec(args)) => {
                let node = self.node(builder, n);
                let words: Vec<Word> = args.iter().map(expr_to_word).collect();
                if words.is_empty()
                    || words.first().is_none_or(|word| {
                        word.as_literal()
                            .is_none_or(|text| text.is_empty() || text == "?")
                    })
                {
                    self.emit(
                        builder,
                        n,
                        "process.exec",
                        unresolved_resource("process"),
                        None,
                    );
                    self.boundary(
                        builder,
                        n,
                        BoundaryReason::UNRESOLVED_CALL,
                        BoundaryClass::Unresolved,
                        "ProcessBuilder.start with an unknown argv",
                        ALL_DOMAINS,
                    );
                } else {
                    let cwd =
                        self.process_builder_cwd(recv, frame)
                            .and_then(|resource| match resource {
                                ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                } => Some(path),
                                ResourceExpr::Literal { value } => Some(value),
                                _ => None,
                            });
                    self.nest.nest(
                        builder,
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .exec_cwd(cwd.as_deref().or(self.cwd))
                            .cwd(
                                builder.current_execution_cwd(),
                                (self.nest.current_runtime_cwd().as_deref()
                                    == cwd.as_deref().or(self.cwd))
                                .then(|| self.nest.current_cwd_node())
                                .flatten(),
                            )
                            .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                        &[node],
                        self.depth,
                    );
                }
            }
            Some(JavaModeledCall::Sql(sql)) => {
                let node = self.node(builder, n);
                self.nest.nest(
                    builder,
                    Transition::file(Subject::Sql {
                        source: sql,
                        dialect: SqlDialect::Generic,
                        connection: SqlConnection::default(),
                    })
                    .source_cwd(self.nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
                    .cwd(
                        builder.current_execution_cwd(),
                        self.nest.current_cwd_node(),
                    ),
                    &[node],
                    self.depth,
                );
            }
            Some(JavaModeledCall::Boundary(reason, class, detail, domains)) => {
                self.boundary(builder, n, reason, class, &detail, domains);
            }
            None => {
                self.boundary(
                    builder,
                    n,
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    java_node_text(n, self.src),
                    ALL_DOMAINS,
                );
            }
        }
    }

    fn execute_callback(
        &mut self,
        builder: &mut PlanBuilder,
        callback: Node<'a>,
        inputs: &[ResourceExpr],
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        // A callback runs under the control of the call that runs it.
        self.control_unknowns += 1;
        match callback.kind() {
            "lambda_expression" => {
                if let Some(body) = callback.child_by_field_name("body") {
                    let mut callback_frame = frame.clone();
                    for (name, value) in lambda_param_names(callback, self.src)
                        .into_iter()
                        .zip(inputs.iter().cloned())
                    {
                        callback_frame.env.insert(name, value);
                    }
                    if self.depth + visiting.len() as u64 >= MAX_CALL_DEPTH
                        || !visiting.insert(body.id())
                    {
                        return;
                    }
                    self.walk_calls(builder, body, &mut callback_frame, visiting);
                    visiting.remove(&body.id());
                }
            }
            "method_reference" => {
                if let Some((receiver, name)) = method_reference_parts(callback, self.src) {
                    if let Some(ty) = self
                        .file
                        .jdk_fqn(receiver)
                        .map(|_| bare_java_type(receiver))
                        && let Some(ops) =
                            model_ops(&ty, name, unresolved_resource("filesystem"), inputs)
                    {
                        self.emit_ops(builder, callback, ops, model_transfer(&ty, name));
                        return;
                    }
                    let class = if receiver == "this" {
                        frame.class.clone()
                    } else {
                        frame
                            .types
                            .get(receiver)
                            .cloned()
                            .unwrap_or_else(|| bare_java_type(receiver))
                    };
                    if self.file.class(&class).is_some() {
                        self.follow_local_with_args(builder, &class, name, inputs, None, visiting);
                    }
                }
            }
            _ => {}
        }
    }

    fn execute_callback_values(
        &mut self,
        builder: &mut PlanBuilder,
        callback: Node<'a>,
        inputs: &[ResourceExpr],
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        if inputs.is_empty() {
            self.execute_callback(builder, callback, &[], frame, visiting);
            return;
        }
        for input in inputs {
            self.execute_callback(
                builder,
                callback,
                std::slice::from_ref(input),
                frame,
                visiting,
            );
        }
    }

    /// The bare name of a same-file class the receiver statically refers to.
    fn same_file_receivers(&self, recv: Node, frame: &JavaMethodFrame) -> Vec<String> {
        let candidates = match recv.kind() {
            "identifier" => {
                let id = java_node_text(recv, self.src);
                frame
                    .news
                    .get(id)
                    .map(|creations| {
                        creations
                            .iter()
                            .filter_map(|creation| {
                                creation
                                    .child_by_field_name("type")
                                    .map(|ty| bare_java_type(java_node_text(ty, self.src)))
                            })
                            .collect()
                    })
                    .filter(|types: &Vec<String>| !types.is_empty())
                    .or_else(|| frame.types.get(id).cloned().map(|ty| vec![ty]))
                    .or_else(|| self.field_type(&frame.class, id).map(|ty| vec![ty]))
                    .or_else(|| is_java_type_name(id).then(|| vec![id.to_string()]))
                    .unwrap_or_default()
            }
            "object_creation_expression" => recv
                .child_by_field_name("type")
                .map(|t| vec![bare_java_type(java_node_text(t, self.src))])
                .unwrap_or_default(),
            _ => return Vec::new(),
        };
        let mut classes = Vec::new();
        for ty in candidates {
            if self.file.class(&ty).is_some() && !classes.contains(&ty) {
                classes.push(ty);
            }
        }
        classes
    }

    fn receiver_creations(
        &self,
        recv: Node<'a>,
        frame: &JavaMethodFrame<'a>,
        ty: &str,
    ) -> Vec<Node<'a>> {
        match recv.kind() {
            "object_creation_expression" => vec![recv],
            "identifier" => frame
                .news
                .get(java_node_text(recv, self.src))
                .into_iter()
                .flatten()
                .copied()
                .filter(|creation| {
                    creation
                        .child_by_field_name("type")
                        .is_some_and(|node| bare_java_type(java_node_text(node, self.src)) == ty)
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn ensure_instance(
        &mut self,
        builder: &mut PlanBuilder,
        creation: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        if frame.allocations.contains_key(&creation.id()) {
            return;
        }
        let Some(ty) = creation
            .child_by_field_name("type")
            .map(|node| bare_java_type(java_node_text(node, self.src)))
        else {
            return;
        };
        let Some(class) = self.file.class(&ty) else {
            return;
        };
        let initial = class.field_literals.clone();
        let args = recover_java_arguments(
            creation,
            self.src,
            &frame.env,
            &self.file.constants,
            &frame.types,
        );
        let (_, instance) =
            self.follow_local_with_args(builder, &ty, "__init__", &args, Some(&initial), visiting);
        frame.allocations.insert(creation.id(), instance);
    }

    /// Runs a same-file constructor before considering a modeled JDK allocation.
    pub(super) fn handle_creation(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        let Some(raw) = n
            .child_by_field_name("type")
            .map(|t| java_node_text(t, self.src).to_string())
        else {
            return;
        };
        let ty = bare_java_type(&raw);
        let args =
            recover_java_arguments(n, self.src, &frame.env, &self.file.constants, &frame.types);
        if let Some(ops) = model_creation(&ty, &args) {
            self.emit_giveup_boundaries(builder, n, frame, &ops);
            for (op, res, attr) in ops {
                self.emit(builder, n, op, res, attr);
            }
            return;
        }
        // Same-file constructor: execute it.
        if self.file.class(&ty).is_some() {
            self.ensure_instance(builder, n, frame, visiting);
            return;
        }
        // URL and URI objects are values; their effects occur at network sinks.
        if matches!(ty.as_str(), "URL" | "URI") && self.file.jdk_fqn(&raw).is_some() {
            return;
        }
        // An unmodeled creation of an effectful JDK type stays loud.
        if let Some(fqn) = self.file.jdk_fqn(&raw)
            && let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, "new")
        {
            self.boundary(
                builder,
                n,
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                &format!("new {ty} is an unmodeled JDK call"),
                domains,
            );
        } else if self.file.jdk_fqn(&raw).is_none() {
            // A class outside this file and the JDK runs unknown code.
            self.control_unknowns += 1;
        }
    }

    fn model(
        &mut self,
        n: Node,
        name: &str,
        recv: Node,
        frame: &JavaMethodFrame,
    ) -> Option<JavaModeledCall> {
        // new ProcessBuilder(cmd, args...).start()/.run() — the argv is the
        // ProcessBuilder constructor's arguments, not this call's.
        let recv_type = jdk_receiver_type(recv, self.src, self.file, &frame.class, &frame.types);
        if matches!(name, "start" | "run")
            && (recv_type.as_deref() == Some("ProcessBuilder")
                || (recv.kind() == "object_creation_expression"
                    && recv.child_by_field_name("type").is_some_and(|t| {
                        bare_java_type(java_node_text(t, self.src)) == "ProcessBuilder"
                    })))
        {
            return Some(JavaModeledCall::Exec(
                self.process_builder_argv(recv, frame),
            ));
        }

        let args =
            recover_java_arguments(n, self.src, &frame.env, &self.file.constants, &frame.types);

        if recv_type.as_deref() == Some("Runtime") && name == "exec" {
            let first = first_argument(n);
            let argv = first
                .map(|argument| self.argv_from_expr(argument, frame))
                .unwrap_or_default();
            let array_local = first.is_some_and(|argument| {
                argument.kind() == "identifier"
                    && frame
                        .arrays
                        .contains_key(java_node_text(argument, self.src))
            });
            return Some(
                if is_array_arg(n, self.src) || array_local || argv.len() > 1 {
                    JavaModeledCall::Exec(if argv.is_empty() { args } else { argv })
                } else {
                    match string_literal_of(n, self.src) {
                        Some(cmd) => JavaModeledCall::Shell(cmd),
                        None => JavaModeledCall::Boundary(
                            BoundaryReason::UNRESOLVED_CALL,
                            BoundaryClass::Unresolved,
                            "Runtime.exec with a non-literal command".to_string(),
                            ALL_DOMAINS,
                        ),
                    }
                },
            );
        }

        if is_reflection(recv_type.as_deref(), name) {
            return Some(JavaModeledCall::Boundary(
                BoundaryReason::UNMODELED_DYNAMIC_CODE,
                BoundaryClass::Unresolved,
                "java reflection".to_string(),
                ALL_DOMAINS,
            ));
        }

        // JDBC: resolve by method name + a SQL-looking literal argument.
        if matches!(
            name,
            "executeUpdate" | "executeQuery" | "execute" | "prepareStatement" | "prepareCall"
        ) && let Some(sql) = sql_literal(&args)
        {
            return Some(JavaModeledCall::Sql(sql));
        }

        let ty = recv_type?;
        let recv_res = self.receiver_resource(recv, &frame.env, &frame.types);
        if identity_java_call(&ty, name, n, self.src) {
            return Some(JavaModeledCall::Ops(Vec::new(), None));
        }
        if ty == "HttpURLConnection"
            && matches!(
                name,
                "setRequestMethod"
                    | "getResponseCode"
                    | "connect"
                    | "getInputStream"
                    | "getOutputStream"
            )
        {
            let verb = receiver_identifier(recv, self.src)
                .and_then(|receiver| frame.http_verbs.get(receiver))
                .map(String::as_str);
            return Some(JavaModeledCall::Ops(
                vec![(network_operation(verb), java_network_sink(recv_res), None)],
                None,
            ));
        }
        if ty == "HttpClient" && matches!(name, "send" | "sendAsync") {
            let request = args
                .first()
                .cloned()
                .map(java_network_sink)
                .unwrap_or(unresolved_resource("network"));
            let verb = first_argument(n).and_then(|argument| {
                http_verb_of_expr(argument, self.src, &frame.http_verbs, &self.file.constants)
            });
            return Some(JavaModeledCall::Ops(
                vec![(network_operation(verb.as_deref()), request, None)],
                None,
            ));
        }
        if let Some(ops) = model_ops(&ty, name, recv_res, &args) {
            return Some(JavaModeledCall::Ops(
                filter_file_stream_ops(ops, &ty, name, n, self.src, &frame.types),
                model_transfer(&ty, name),
            ));
        }
        // Unmodeled call on an effectful JDK type: loud in the domains that
        // type can reach, never silent.
        let fqn = self
            .file
            .jdk_fqn(java_node_text(recv, self.src))
            .or_else(|| self.file.type_fqn(&ty))?;
        if let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, name) {
            return Some(JavaModeledCall::Boundary(
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                format!("{fqn}.{name} is an unmodeled JDK call"),
                domains,
            ));
        }
        matches!(classify_java_call(&fqn, name), Some(ExternalCall::Inert))
            .then(|| JavaModeledCall::Ops(Vec::new(), None))
    }

    /// The resource a receiver expression denotes (for `File`-style APIs):
    /// `new File(p)` resolves to `p`, a typed local to its symbolic name.
    fn receiver_resource(
        &self,
        recv: Node,
        env: &HashMap<String, ResourceExpr>,
        types: &HashMap<String, String>,
    ) -> ResourceExpr {
        recover_typed_java_resource(recv, self.src, env, &self.file.constants, types)
    }
}

enum JavaModeledCall {
    /// Modeled effects, plus the transfer whose endpoints they contain.
    Ops(Vec<ModeledOp>, Option<ModeledTransfer>),
    Shell(String),
    Exec(Vec<ResourceExpr>),
    Sql(String),
    Boundary(BoundaryReason, BoundaryClass, String, Domains),
}

/// Whether a Runtime.exec call was passed a String[] (array) argument.
fn is_array_arg(n: Node, src: &[u8]) -> bool {
    n.child_by_field_name("arguments")
        .map(|a| {
            let mut c = a.walk();
            a.named_children(&mut c).any(|x| {
                matches!(x.kind(), "array_creation_expression")
                    || java_node_text(x, src).contains('[')
            })
        })
        .unwrap_or(false)
}

/// The first string-literal argument's content, if any.
fn string_literal_of(n: Node, src: &[u8]) -> Option<String> {
    let a = n.child_by_field_name("arguments")?;
    let mut c = a.walk();
    a.named_children(&mut c)
        .find(|x| x.kind() == "string_literal")
        .map(|x| unquote_java_string(java_node_text(x, src)))
}

fn sql_literal(args: &[ResourceExpr]) -> Option<String> {
    // The SQL argument surfaces as a concrete "fs path" from recover_java_resource's
    // string handling; treat a concrete string starting with a SQL keyword.
    for a in args {
        if let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = a
        {
            let up = path.trim_start().to_ascii_uppercase();
            if [
                "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TRUNCATE",
                "WITH", "MERGE",
            ]
            .iter()
            .any(|kw| up.starts_with(kw))
            {
                return Some(path.clone());
            }
        }
    }
    None
}

fn expr_to_word(e: &ResourceExpr) -> Word {
    match e {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}
