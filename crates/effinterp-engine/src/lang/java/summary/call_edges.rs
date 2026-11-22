//! Java summary call edges and the receiver evidence they carry.

use super::super::call_resolution::{JAVA_LANG, is_java_type_name, jdk_receiver_type};
use super::super::callbacks::{
    callback_bindings, callbacks_execute_at, java_callback_arguments, lambda_param_names,
    method_reference_parts, recover_java_callback_inputs,
};
use super::super::model::{
    filter_file_stream_ops, http_verb_of_expr, identity_java_call, is_reflection, model_creation,
    model_ops, model_transfer, network_operation,
};
use super::super::resource_recovery::{
    invocation_string_argument, iterable_element, java_network_sink, recover_java_arguments,
    recover_typed_java_resource,
};
use super::super::syntax::{bare_java_type, first_argument, java_node_text, receiver_identifier};
use super::JavaSummaryWalker;
use crate::external::{ALL_DOMAINS, ExternalCall, classify_java_call};
use crate::module_summary::{CallEdge, call_results};
use crate::value::unresolved_resource;
use crate::{
    ObjectIdentity, SemanticValue, TypeRef, ValueArgument, ValueOrigin, merge_arguments,
    positional_arguments,
};
use effinterp_proto::{BoundaryClass, BoundaryReason, ResourceExpr};
use tree_sitter::Node;

impl<'a> JavaSummaryWalker<'a> {
    /// The instance-typed call arguments, by positional index.
    fn obj_args_of(&mut self, n: Node) -> Vec<ValueArgument> {
        if !self.active_object_arguments.insert(n.id()) {
            return Vec::new();
        }
        let Some(a) = n.child_by_field_name("arguments") else {
            self.active_object_arguments.remove(&n.id());
            return Vec::new();
        };
        let mut c = a.walk();
        let mut out = Vec::new();
        for (i, arg) in a.named_children(&mut c).enumerate() {
            if let Some(instance) = self.instance_of_expr(arg) {
                out.push(ValueArgument {
                    name: None,
                    index: i,
                    value: instance,
                });
            }
        }
        self.active_object_arguments.remove(&n.id());
        out
    }

    /// An argument expression with unambiguous instance provenance.
    fn instance_of_expr(&mut self, expr: Node) -> Option<SemanticValue> {
        match expr.kind() {
            "object_creation_expression" => {
                let ty = expr
                    .child_by_field_name("type")
                    .map(|t| bare_java_type(java_node_text(t, self.src)))?;
                if !self.file.is_repo_class_candidate(&ty) {
                    return None;
                }
                self.reference_type(&ty);
                let ctor = self.obj_args_of(expr);
                let origin = self.origin_for_node(expr);
                Some(
                    SemanticValue::object(ObjectIdentity::Class {
                        name: ty,
                        constructor: ctor,
                    })
                    .with_origin(Some(origin))
                    .with_type(self.repo_type_ref(expr)),
                )
            }
            "identifier" => {
                let id = java_node_text(expr, self.src);
                if self.param_names.iter().any(|p| p == id) {
                    let ty = self.types.get(id)?;
                    return self.file.is_repo_class_candidate(ty).then(|| {
                        SemanticValue::object(ObjectIdentity::Parameter {
                            name: id.to_string(),
                            fallback: Some(ty.to_string()),
                        })
                    });
                }
                if let Some(ty) = self.types.get(id).cloned() {
                    if !self.file.is_repo_class_candidate(&ty) {
                        return None;
                    }
                    self.reference_type(&ty);
                    let ctor = self
                        .news
                        .get(id)
                        .and_then(|candidates| candidates.first().copied())
                        .map(|n| self.obj_args_of(n))
                        .unwrap_or_default();
                    let origin = self
                        .news
                        .get(id)
                        .and_then(|candidates| candidates.first().copied())
                        .map(|n| self.origin_for_node(n))
                        .or_else(|| self.local_origins.get(id).cloned());
                    return Some(
                        SemanticValue::object(ObjectIdentity::Class {
                            name: ty,
                            constructor: ctor,
                        })
                        .with_origin(origin)
                        .with_type(
                            self.news
                                .get(id)
                                .and_then(|candidates| candidates.first().copied())
                                .and_then(|n| self.repo_type_ref(n)),
                        ),
                    );
                }
                if self.field_type(id).is_some() {
                    return Some(SemanticValue::object(ObjectIdentity::ReceiverProperty(
                        id.to_string(),
                    )));
                }
                None
            }
            "field_access" => {
                let obj = expr.child_by_field_name("object")?;
                if obj.kind() != "this" {
                    return None;
                }
                let field = expr.child_by_field_name("field")?;
                Some(SemanticValue::object(ObjectIdentity::ReceiverProperty(
                    java_node_text(field, self.src).to_string(),
                )))
            }
            _ => None,
        }
    }

    fn field_type(&self, name: &str) -> Option<String> {
        self.file.class(&self.class)?.fields.get(name).cloned()
    }

    fn receiver_types(&self, id: &str) -> Vec<String> {
        if let Some(creations) = self.news.get(id) {
            let mut types = Vec::new();
            for ty in creations.iter().filter_map(|creation| {
                creation
                    .child_by_field_name("type")
                    .map(|ty| bare_java_type(java_node_text(ty, self.src)))
            }) {
                if !types.contains(&ty) {
                    types.push(ty);
                }
            }
            if !types.is_empty() {
                return types;
            }
        }
        self.types
            .get(id)
            .cloned()
            .or_else(|| self.field_type(id))
            .into_iter()
            .collect()
    }

    fn news_for_type(&self, id: &str, ty: &str) -> Option<Node<'a>> {
        self.news.get(id)?.iter().copied().find(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|node| bare_java_type(java_node_text(node, self.src)) == ty)
        })
    }

    /// Note a referenced type name for implicit same-package binding synthesis.
    fn reference_type(&mut self, ty: &str) {
        if is_java_type_name(ty)
            && !self.file.imports.contains_key(ty)
            && self.file.class(ty).is_none()
            && !JAVA_LANG.contains(&ty)
        {
            self.implicit.insert(ty.to_string());
        }
    }

    fn push_edge(&mut self, mut edge: CallEdge) {
        if self.edges.len() < 128 {
            if edge.results.is_empty() {
                edge.results = call_results(Vec::new(), Some(self.next_origin()), None);
            } else if edge.results[0].value.evidence.origin.is_none() {
                edge.results[0].value.evidence.origin = Some(self.next_origin());
            }
            self.edges.push(edge);
        }
    }

    fn next_origin(&mut self) -> ValueOrigin {
        let origin = ValueOrigin::Site {
            file: self.fact_file.to_string(),
            function: self.fact_function.to_string(),
            ordinal: self.site_ordinal,
            result_index: 0,
        };
        self.site_ordinal += 1;
        origin
    }

    pub(super) fn origin_for_node(&mut self, node: Node) -> ValueOrigin {
        if let Some(origin) = self.site_origins.get(&node.id()) {
            return origin.clone();
        }
        let origin = self.next_origin();
        self.site_origins.insert(node.id(), origin.clone());
        origin
    }

    fn repo_type_ref(&self, expr: Node) -> Option<TypeRef> {
        let ty = expr
            .child_by_field_name("type")
            .map(|node| bare_java_type(java_node_text(node, self.src)))?;
        self.file.class(&ty).is_some().then(|| TypeRef::Repo {
            file: self.fact_file.to_string(),
            name: ty,
        })
    }

    fn push_local(&mut self, key: String, args: Vec<ResourceExpr>) {
        if self.locals.len() < 128 {
            self.locals.push((key, args, self.edges.len() as u32));
        }
    }

    /// The key of a same-file method a bare call resolves to.
    fn local_method_key(&self, name: &str, arity: usize) -> Option<String> {
        self.file
            .resolve_local_java_methods(&self.class, name, Some(arity))
            .first()
            .map(|method| format!("{}.{name}", method.class))
    }

    /// Records Java call edges even for same-file calls whose effects will be inlined.
    pub(super) fn invocation(&mut self, n: Node<'a>) {
        let Some(name) = n
            .child_by_field_name("name")
            .map(|x| java_node_text(x, self.src).to_string())
        else {
            return;
        };
        let recv = n.child_by_field_name("object");

        if let Some(recv) = recv
            && recv.kind() == "identifier"
            && matches!(name.as_str(), "run" | "call" | "apply" | "accept" | "get")
            && let Some(callbacks) = self.callbacks.get(java_node_text(recv, self.src)).cloned()
        {
            let inputs =
                recover_java_arguments(n, self.src, &self.env, &self.file.constants, &self.types);
            for callback in callbacks {
                self.capture_callback(callback, &inputs);
            }
            return;
        }

        let file_element = (name == "forEach")
            .then(|| {
                recv.and_then(|receiver| {
                    iterable_element(receiver, self.src, &self.env, &self.file.constants)
                })
            })
            .flatten();
        if callbacks_execute_at(n, &name, self.src) {
            let inputs = file_element
                .clone()
                .map(|element| vec![element])
                .unwrap_or_else(|| {
                    recover_java_callback_inputs(n, self.file, self.src, &self.env, &self.types)
                });
            for callback in java_callback_arguments(n) {
                self.capture_callback_values(callback, &inputs);
            }
            for callback in callback_bindings(n, self.src, &self.callbacks) {
                self.capture_callback_values(callback, &inputs);
            }
        }

        // Bare call (or `this.m()`).
        if recv.is_none() || recv.is_some_and(|r| r.kind() == "this") {
            let args =
                recover_java_arguments(n, self.src, &self.env, &self.file.constants, &self.types);
            let obj_args = self.obj_args_of(n);
            if let Some(key) = self.local_method_key(&name, args.len()) {
                self.push_local(key.clone(), args.clone());
                let mut arguments = positional_arguments(args);
                merge_arguments(&mut arguments, obj_args);
                self.push_edge(CallEdge {
                    callee: key,
                    arguments,
                    ..Default::default()
                });
                return;
            }
            if let Some(class) = self.file.static_import_class(&name).map(str::to_string) {
                if class.starts_with("java.") || class.starts_with("jdk.") {
                    self.jdk_call(&bare_java_type(&class), &name, n, n);
                } else {
                    self.push_boundary(
                        BoundaryReason::UNRESOLVED_CALL,
                        BoundaryClass::Unresolved,
                        java_node_text(n, self.src).to_string(),
                        ALL_DOMAINS,
                        Some(n),
                    );
                }
                return;
            }
            // Possibly inherited from a base in another file: dispatch through
            // the receiver instance at composition time.
            if self
                .file
                .class(&self.class)
                .is_some_and(|c| !c.bases.is_empty())
            {
                let mut arguments = positional_arguments(args);
                merge_arguments(&mut arguments, obj_args);
                self.push_edge(CallEdge {
                    callee: format!("this.{name}"),
                    arguments,
                    receiver: Some(SemanticValue::object(ObjectIdentity::Receiver)),
                    ..Default::default()
                });
            } else {
                self.push_boundary(
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    java_node_text(n, self.src).to_string(),
                    ALL_DOMAINS,
                    Some(n),
                );
            }
            return;
        }
        let recv = recv.unwrap();

        if name == "setRequestMethod"
            && let Some(receiver) = receiver_identifier(recv, self.src)
        {
            let verb = invocation_string_argument(n, self.src, &self.file.constants)
                .unwrap_or_else(|| "GET".to_string());
            self.http_verbs.insert(receiver.to_string(), verb);
        }

        match recv.kind() {
            "identifier" => {
                let id = java_node_text(recv, self.src).to_string();
                let receiver_types = self.receiver_types(&id);
                if !receiver_types.is_empty() {
                    for ty in receiver_types {
                        self.typed_receiver_call(&id, &ty, &name, n, recv);
                    }
                } else if self.file.class(&id).is_some() {
                    // Same-file static call.
                    let key = format!("{id}.{name}");
                    let args = recover_java_arguments(
                        n,
                        self.src,
                        &self.env,
                        &self.file.constants,
                        &self.types,
                    );
                    let obj_args = self.obj_args_of(n);
                    if self
                        .file
                        .methods
                        .iter()
                        .any(|m| m.class == id && m.name == name)
                    {
                        self.push_local(key.clone(), args.clone());
                    }
                    let mut arguments = positional_arguments(args);
                    merge_arguments(&mut arguments, obj_args);
                    self.push_edge(CallEdge {
                        callee: key,
                        arguments,
                        ..Default::default()
                    });
                } else if is_java_type_name(&id) {
                    if self.file.is_jdk(&id) {
                        self.jdk_call(&id, &name, n, recv);
                        if self.file.wildcard_type_fqn(&id).is_some()
                            && !self.file.imports.contains_key(&id)
                        {
                            self.reference_type(&id);
                            let args = recover_java_arguments(
                                n,
                                self.src,
                                &self.env,
                                &self.file.constants,
                                &self.types,
                            );
                            let obj_args = self.obj_args_of(n);
                            let mut arguments = positional_arguments(args);
                            merge_arguments(&mut arguments, obj_args);
                            self.push_edge(CallEdge {
                                callee: format!("{id}.{name}"),
                                arguments,
                                ..Default::default()
                            });
                        }
                    } else {
                        // Imported or same-package class: a static cross-file
                        // call edge.
                        self.reference_type(&id);
                        let args = recover_java_arguments(
                            n,
                            self.src,
                            &self.env,
                            &self.file.constants,
                            &self.types,
                        );
                        let obj_args = self.obj_args_of(n);
                        let mut arguments = positional_arguments(args);
                        merge_arguments(&mut arguments, obj_args);
                        self.push_edge(CallEdge {
                            callee: format!("{id}.{name}"),
                            arguments,
                            ..Default::default()
                        });
                    }
                } else {
                    self.push_boundary(
                        BoundaryReason::DYNAMIC_DISPATCH,
                        BoundaryClass::Unresolved,
                        java_node_text(n, self.src).to_string(),
                        ALL_DOMAINS,
                        Some(n),
                    );
                }
            }
            "object_creation_expression" => {
                let Some(raw) = recv
                    .child_by_field_name("type")
                    .map(|t| java_node_text(t, self.src).to_string())
                else {
                    return;
                };
                let ty = bare_java_type(&raw);
                if self.file.jdk_fqn(&raw).is_some() {
                    self.jdk_call(&ty, &name, n, recv);
                } else if self.file.is_repo_class_candidate(&ty) {
                    self.reference_type(&ty);
                    let args = recover_java_arguments(
                        n,
                        self.src,
                        &self.env,
                        &self.file.constants,
                        &self.types,
                    );
                    let obj_args = self.obj_args_of(n);
                    let ctor = self.obj_args_of(recv);
                    let origin = self.origin_for_node(recv);
                    let receiver = SemanticValue::object(ObjectIdentity::Class {
                        name: ty.clone(),
                        constructor: ctor,
                    })
                    .with_origin(Some(origin))
                    .with_type(self.repo_type_ref(recv));
                    let mut arguments = positional_arguments(args);
                    merge_arguments(&mut arguments, obj_args);
                    self.push_edge(CallEdge {
                        callee: format!("{ty}.{name}"),
                        arguments,
                        receiver: Some(receiver),
                        ..Default::default()
                    });
                }
            }
            "field_access" => {
                let obj = recv.child_by_field_name("object");
                if obj.is_some_and(|o| o.kind() == "this") {
                    if let Some(field) = recv
                        .child_by_field_name("field")
                        .map(|f| java_node_text(f, self.src).to_string())
                        && let Some(ty) = self.field_type(&field)
                    {
                        self.typed_receiver_call(&field, &ty, &name, n, recv);
                    }
                    return;
                }
                // Fully-qualified or nested JDK receiver.
                let whole = java_node_text(recv, self.src);
                let head = whole.split('.').next().unwrap_or(whole);
                if whole.starts_with("java") || self.file.is_jdk(head) {
                    self.jdk_call(&bare_java_type(whole), &name, n, recv);
                }
            }
            "method_invocation" | "cast_expression" | "parenthesized_expression" => {
                if let Some(ty) =
                    jdk_receiver_type(recv, self.src, self.file, &self.class, &self.types)
                {
                    self.jdk_call(&ty, &name, n, recv);
                } else {
                    self.push_boundary(
                        BoundaryReason::DYNAMIC_DISPATCH,
                        BoundaryClass::Unresolved,
                        java_node_text(n, self.src).to_string(),
                        ALL_DOMAINS,
                        Some(n),
                    );
                }
            }
            _ => self.push_boundary(
                BoundaryReason::DYNAMIC_DISPATCH,
                BoundaryClass::Unresolved,
                java_node_text(n, self.src).to_string(),
                ALL_DOMAINS,
                Some(n),
            ),
        }
    }

    /// A call on a receiver with a declared type: model it when the type is a
    /// JDK API, emit a dispatch edge when it names a repo class.
    fn typed_receiver_call(&mut self, id: &str, ty: &str, name: &str, n: Node<'a>, recv: Node<'a>) {
        if self.file.is_jdk(ty) {
            self.jdk_call(ty, name, n, recv);
            return;
        }
        if !self.file.is_repo_class_candidate(ty) {
            return;
        }
        self.reference_type(ty);
        let args =
            recover_java_arguments(n, self.src, &self.env, &self.file.constants, &self.types);
        let obj_args = self.obj_args_of(n);
        let receiver = if self.param_names.iter().any(|p| p == id) {
            SemanticValue::object(ObjectIdentity::Parameter {
                name: id.to_string(),
                fallback: Some(ty.to_string()),
            })
        } else if self.types.contains_key(id) {
            let creation = self.news_for_type(id, ty);
            let ctor = self
                .news_for_type(id, ty)
                .map(|c| self.obj_args_of(c))
                .unwrap_or_default();
            let origin = creation
                .map(|node| self.origin_for_node(node))
                .or_else(|| self.local_origins.get(id).cloned());
            SemanticValue::object(ObjectIdentity::Class {
                name: ty.to_string(),
                constructor: ctor,
            })
            .with_origin(origin)
            .with_type(creation.and_then(|node| self.repo_type_ref(node)))
        } else {
            SemanticValue::object(ObjectIdentity::ReceiverProperty(id.to_string()))
        };
        let mut arguments = positional_arguments(args);
        merge_arguments(&mut arguments, obj_args);
        self.push_edge(CallEdge {
            callee: format!("{id}.{name}"),
            arguments,
            receiver: Some(receiver),
            ..Default::default()
        });
    }

    /// Model a call whose receiver is a JDK type; unmodeled calls into
    /// effectful packages stay loud, curated-inert types stay quiet.
    fn jdk_call(&mut self, ty: &str, name: &str, n: Node<'a>, recv: Node<'a>) {
        let args =
            recover_java_arguments(n, self.src, &self.env, &self.file.constants, &self.types);
        if is_reflection(Some(ty), name) {
            self.push_boundary(
                BoundaryReason::UNMODELED_DYNAMIC_CODE,
                BoundaryClass::Unresolved,
                format!("java reflection: {ty}.{name}"),
                ALL_DOMAINS,
                Some(n),
            );
            return;
        }
        if ty == "Runtime" && name == "exec" {
            self.push_effects(
                vec![(
                    "process.exec",
                    args.first()
                        .cloned()
                        .unwrap_or(unresolved_resource("process")),
                    None,
                )],
                None,
            );
            return;
        }
        if ty == "ProcessBuilder" && matches!(name, "start" | "run") {
            let res = recv
                .child_by_field_name("arguments")
                .and_then(|a| a.named_child(0))
                .map(|x| {
                    recover_typed_java_resource(
                        x,
                        self.src,
                        &self.env,
                        &self.file.constants,
                        &self.types,
                    )
                })
                .unwrap_or(unresolved_resource("process"));
            self.push_effects(vec![("process.exec", res, None)], None);
            return;
        }
        let recv_res = recover_typed_java_resource(
            recv,
            self.src,
            &self.env,
            &self.file.constants,
            &self.types,
        );
        if identity_java_call(ty, name, n, self.src) {
            return;
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
                .and_then(|receiver| self.http_verbs.get(receiver))
                .map(String::as_str);
            let ops = vec![(network_operation(verb), java_network_sink(recv_res), None)];
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, None);
            return;
        }
        if ty == "HttpClient" && matches!(name, "send" | "sendAsync") {
            let request = args
                .first()
                .cloned()
                .map(java_network_sink)
                .unwrap_or(unresolved_resource("network"));
            let verb = first_argument(n).and_then(|argument| {
                http_verb_of_expr(argument, self.src, &self.http_verbs, &self.file.constants)
            });
            let ops = vec![(network_operation(verb.as_deref()), request, None)];
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, None);
            return;
        }
        if let Some(ops) = model_ops(ty, name, recv_res, &args) {
            let ops = filter_file_stream_ops(ops, ty, name, n, self.src, &self.types);
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, model_transfer(ty, name));
            return;
        }
        if let Some(fqn) = self.file.type_fqn(ty)
            && let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, name)
        {
            self.push_boundary(
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                format!("{fqn}.{name} is an unmodeled JDK call"),
                domains,
                Some(n),
            );
        }
    }

    /// Records Java constructor edges and their typed argument evidence.
    pub(super) fn creation(&mut self, n: Node<'a>) {
        let Some(raw) = n
            .child_by_field_name("type")
            .map(|t| java_node_text(t, self.src).to_string())
        else {
            return;
        };
        let ty = bare_java_type(&raw);
        let args =
            recover_java_arguments(n, self.src, &self.env, &self.file.constants, &self.types);
        if let Some(ops) = model_creation(&ty, &args) {
            self.push_giveup_boundaries(n, &ops);
            self.push_effects(ops, None);
            return;
        }
        if self.file.class(&ty).is_some() {
            // Same-file constructor: inline its effects and walk its edges.
            if self
                .file
                .methods
                .iter()
                .any(|m| m.class == ty && m.name == "__init__")
            {
                self.push_local(format!("{ty}.__init__"), args.clone());
            }
            let ctor = self.obj_args_of(n);
            let origin = self.origin_for_node(n);
            let receiver = SemanticValue::object(ObjectIdentity::Class {
                name: ty.clone(),
                constructor: ctor,
            })
            .with_origin(Some(origin.clone()))
            .with_type(self.repo_type_ref(n));
            self.push_edge(CallEdge {
                callee: ty.clone(),
                arguments: positional_arguments(args),
                receiver: Some(receiver),
                results: call_results(Vec::new(), Some(origin), None),
                ..Default::default()
            });
            return;
        }
        if matches!(ty.as_str(), "URL" | "URI") && self.file.jdk_fqn(&raw).is_some() {
            return;
        }
        if let Some(fqn) = self.file.jdk_fqn(&raw) {
            if let Some(ExternalCall::Unmodeled(domains)) = classify_java_call(&fqn, "new") {
                self.push_boundary(
                    BoundaryReason::EXTERNAL_UNMODELED,
                    BoundaryClass::Unmodeled,
                    format!("new {ty} is an unmodeled JDK call"),
                    domains,
                    Some(n),
                );
            }
            return;
        }
        if self.file.is_repo_class_candidate(&ty) {
            // Cross-file constructor execution.
            self.reference_type(&ty);
            let ctor = self.obj_args_of(n);
            let origin = self.origin_for_node(n);
            let receiver = SemanticValue::object(ObjectIdentity::Class {
                name: ty.clone(),
                constructor: ctor,
            })
            .with_origin(Some(origin.clone()));
            self.push_edge(CallEdge {
                callee: ty.clone(),
                arguments: positional_arguments(args),
                receiver: Some(receiver),
                results: call_results(Vec::new(), Some(origin), None),
                ..Default::default()
            });
        }
    }

    fn capture_callback_values(&mut self, callback: Node<'a>, inputs: &[ResourceExpr]) {
        if inputs.is_empty() {
            self.capture_callback(callback, &[]);
            return;
        }
        for input in inputs {
            self.capture_callback(callback, std::slice::from_ref(input));
        }
    }

    fn capture_callback(&mut self, callback: Node<'a>, inputs: &[ResourceExpr]) {
        self.callback_visits += 1;
        match callback.kind() {
            "lambda_expression" => {
                if let Some(body) = callback.child_by_field_name("body") {
                    if !self.active_callbacks.insert(body.id()) {
                        return;
                    }
                    let env = self.env.clone();
                    for (name, value) in lambda_param_names(callback, self.src)
                        .into_iter()
                        .zip(inputs.iter().cloned())
                    {
                        self.env.insert(name, value);
                    }
                    self.walk(body);
                    self.env = env;
                    self.active_callbacks.remove(&body.id());
                }
            }
            "method_reference" => {
                if let Some((receiver, name)) = method_reference_parts(callback, self.src)
                    && let Some(ty) = self
                        .file
                        .jdk_fqn(receiver)
                        .map(|_| bare_java_type(receiver))
                    && let Some(ops) =
                        model_ops(&ty, name, unresolved_resource("filesystem"), inputs)
                {
                    self.push_effects(ops, model_transfer(&ty, name));
                } else if let Some((receiver, name)) = method_reference_parts(callback, self.src) {
                    let class = if receiver == "this" {
                        self.class.clone()
                    } else {
                        self.types
                            .get(receiver)
                            .cloned()
                            .unwrap_or_else(|| bare_java_type(receiver))
                    };
                    let key = format!("{class}.{name}");
                    if self
                        .file
                        .methods
                        .iter()
                        .any(|method| method.class == class && method.name == name)
                    {
                        self.push_local(key.clone(), inputs.to_vec());
                    } else if !self.file.is_repo_class_candidate(&class) {
                        return;
                    } else {
                        self.reference_type(&class);
                    }
                    self.push_edge(CallEdge {
                        callee: key,
                        arguments: positional_arguments(inputs.to_vec()),
                        ..Default::default()
                    });
                }
            }
            _ => {}
        }
    }
}
