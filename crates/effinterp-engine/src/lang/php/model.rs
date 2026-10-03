use std::collections::HashMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ResourceExpr, ResourceIdentity, Subject,
};
use tree_sitter::Node;

use crate::SemanticValue;
use crate::builder::KNOWN_DOMAINS;
use crate::lang::frontend::MAX_CALLBACK_VALUES;
use crate::nest::Transition;
use crate::summary::{contains_unresolved, has_text_concat};
use crate::value::{parse_url_endpoint, unresolved_resource};

use super::{
    PhpCaptureWalker, PhpWalker, arg_nodes, array_values, callable_name, child_kind,
    literal_string, named_argument, poisoned_php_reference, resolve_expr, text, variable_name,
};

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// Model a known PHP builtin; returns Some(()) if it claimed the call.
    pub(super) fn builtin(
        &mut self,
        fname: &str,
        args: &[Node<'a>],
        n: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<()> {
        match fname {
            // PHP 8 refuses a literal for proc_open's by-reference `$pipes`
            // before the process starts.
            "proc_open"
                if args.get(2).is_some_and(|pipes| {
                    matches!(
                        pipes.kind(),
                        "array_creation_expression"
                            | "string"
                            | "encapsed_string"
                            | "integer"
                            | "float"
                            | "boolean"
                            | "null"
                    )
                }) => {}
            "system" | "exec" | "shell_exec" | "passthru" | "proc_open" | "popen" => {
                let command = named_argument(n, "command", self.src).or(args.first().copied());
                match self.command_string(command, env) {
                    Some((cmd, environment)) => {
                        self.nest_shell(cmd, n, environment, matches!(fname, "exec" | "shell_exec"))
                    }
                    None => self.opaque(
                        BoundaryReason::UNRESOLVED_COMMAND,
                        BoundaryClass::Unresolved,
                        n,
                    ),
                }
            }
            "call_user_func" | "call_user_func_array" => {
                if fname == "call_user_func"
                    && let Some(function) = args
                        .first()
                        .and_then(|arg| literal_string(*arg, self.src))
                        .map(|function| function.to_ascii_lowercase())
                    && !self.functions.contains_key(&function)
                    && !function.contains('\\')
                    && !matches!(
                        function.as_str(),
                        "call_user_func" | "call_user_func_array" | "eval" | "assert"
                    )
                    && self.builtin(&function, &args[1..], n, env).is_some()
                {
                    return Some(());
                }
                let callable_args: Vec<ResourceExpr> = if fname == "call_user_func" {
                    args.iter()
                        .skip(1)
                        .map(|argument| self.resolve_argument(*argument, env))
                        .collect()
                } else {
                    args.get(1)
                        .map(|array| {
                            array_values(*array)
                                .into_iter()
                                .map(|argument| self.resolve_argument(argument, env))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                if !args
                    .first()
                    .is_some_and(|callable| self.invoke_callable(*callable, &callable_args, n, env))
                {
                    self.opaque(BoundaryReason::DYNAMIC_CALL, BoundaryClass::Unresolved, n);
                }
            }
            "array_map" | "array_walk" | "usort" => {
                let (array, callable) = if fname == "array_map" {
                    (args.get(1), args.first())
                } else {
                    (args.first(), args.get(1))
                };
                let mut values: Vec<ResourceExpr> = array
                    .map(|array| {
                        array_values(*array)
                            .into_iter()
                            .map(|argument| self.resolve_argument(argument, env))
                            .collect()
                    })
                    .unwrap_or_default();
                if values.len() > MAX_CALLBACK_VALUES {
                    values.truncate(MAX_CALLBACK_VALUES);
                    values.push(unresolved_resource("value"));
                }
                if let Some(callable) = callable {
                    if values.is_empty() {
                        self.invoke_callable(*callable, &[], n, env);
                    } else if fname == "usort" && values.len() > 1 {
                        for pair in values.windows(2) {
                            self.invoke_callable(*callable, pair, n, env);
                        }
                    } else {
                        for value in &values {
                            self.invoke_callable(*callable, std::slice::from_ref(value), n, env);
                        }
                    }
                }
            }
            "eval" => {
                let source = args.first().and_then(|arg| literal_string(*arg, self.src));
                let Some(source) =
                    source.filter(|_| self.functions.is_empty() && self.ctx.namespace.is_none())
                else {
                    // The code the argument evaluates to runs in this
                    // interpreter; a modeled producer of that value binds to
                    // this execution when the walk reaches it.
                    let execution = self.emit(
                        self.interpreter_effect("process.code_execution", ("source", "argument")),
                        n,
                    );
                    if let (Some(argument), Some(execution)) = (args.first(), execution) {
                        self.eval_code.insert(argument.id(), execution);
                    }
                    self.opaque(
                        BoundaryReason::UNMODELED_DYNAMIC_CODE,
                        BoundaryClass::Unresolved,
                        n,
                    );
                    return Some(());
                };
                let node = self.span(n);
                self.nest.nest(
                    self.builder,
                    Transition::file(Subject::Source {
                        dialect: None,
                        language: "php".to_string(),
                        source: format!("<?php {source}"),
                        cwd: self.runtime_cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .source_cwd(self.source_cwd)
                    .runtime_cwd(self.runtime_cwd)
                    .cwd(self.runtime_cwd_resource.clone(), self.cwd_node),
                    &[node],
                    self.depth,
                );
                // Eval can replace caller-local values and callable bindings.
                self.locals.clear();
                self.vars.clear();
                self.closures.clear();
                self.network_handles.clear();
            }
            // Whether the operand is valid base64 is not asserted.
            "base64_decode" => {
                let decode = self.emit_applying(
                    self.interpreter_effect("process.stream_transform", ("transform", "decode")),
                    n,
                    Some("php/base64@v0"),
                );
                self.evaluated(n, decode);
            }
            "assert" => self.opaque(
                BoundaryReason::UNMODELED_DYNAMIC_CODE,
                BoundaryClass::Unresolved,
                n,
            ),
            "unlink" | "rmdir" => self.fs(args.first().copied(), env, "filesystem.delete", n, None),
            "chmod" => {
                let effect =
                    self.fs_slot(args.first().copied(), env, "filesystem.metadata", n, None);
                if let Some(effect) = effect {
                    self.builder
                        .set_effect_string_attribute(effect as usize, "action", "chmod");
                }
            }
            "mkdir" => self.fs(args.first().copied(), env, "filesystem.create", n, None),
            "file_put_contents" => {
                let append = args
                    .get(2)
                    .is_some_and(|a| text(*a, self.src).contains("FILE_APPEND"));
                self.fs(
                    args.first().copied(),
                    env,
                    "filesystem.write",
                    n,
                    append.then_some("append"),
                )
            }
            "readfile" | "file" => {
                if self.is_url(args.first().copied()) {
                    self.net(args.first().copied(), env, n);
                } else {
                    self.program_input(args.first().copied(), env, n);
                }
            }
            "fread" => {
                if !args.first().is_some_and(|arg| self.is_network_handle(*arg)) {
                    self.fs(args.first().copied(), env, "filesystem.read", n, None);
                }
            }
            // Metadata probes still read the filesystem.
            "file_exists" | "is_file" | "is_dir" | "is_readable" | "is_writable" | "is_link"
            | "filesize" | "filemtime" => self.fs(
                args.first().copied(),
                env,
                "filesystem.read",
                n,
                Some("metadata"),
            ),
            "tempnam" => self.fs(args.first().copied(), env, "filesystem.create", n, None),
            "fwrite" | "fputs" => {
                if !args.first().is_some_and(|arg| self.is_network_handle(*arg)) {
                    self.fs(args.first().copied(), env, "filesystem.write", n, None);
                }
            }
            "touch" => self.fs(args.first().copied(), env, "filesystem.write", n, None),
            "scandir" | "opendir" => {
                self.fs(args.first().copied(), env, "filesystem.read", n, None)
            }
            "glob" => {
                let resource = args
                    .first()
                    .and_then(|a| literal_string(*a, self.src))
                    .map(|pattern| {
                        crate::paths::resolve_fs_word_with_cwd(
                            &crate::word::Word::new(vec![crate::word::WordPart::Glob(pattern)]),
                            self.runtime_cwd_resource.clone(),
                        )
                    })
                    .unwrap_or(unresolved_resource("filesystem"));
                self.emit(
                    Effect {
                        request_assurance: effinterp_proto::RequestAssurance::Conservative,
                        id: Default::default(),
                        operation: Operation::new("filesystem.read"),
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
            "file_get_contents" => {
                // A URL argument is a network read; otherwise a file read.
                if self.is_url(args.first().copied()) {
                    let request = self.net_slot(args.first().copied(), env, n);
                    self.evaluated(n, request);
                    if let (Some(context), Some(request)) = (args.get(2), request)
                        && matches!(self.url_resource(args.first().copied(), env),
                            ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { scheme: Some(scheme), .. } }
                                if matches!(scheme.as_str(), "http" | "https"))
                    {
                        let body = if callable_name(*context, self.src).as_deref()
                            == Some("stream_context_create")
                            && !self.functions.contains_key("stream_context_create")
                        {
                            self.examined_contexts.insert(context.id());
                            arg_nodes(*context)
                                .first()
                                .copied()
                                .and_then(|options| array_field(options, "http", self.src))
                                .and_then(|http| match http {
                                    Some(http) => array_field(http, "content", self.src),
                                    None => Some(None),
                                })
                        } else {
                            None
                        };
                        let mut requests = vec![request];
                        if matches!(body, Some(Some(_)))
                            && let Some(upload) = self.emit_network(
                                self.url_resource(args.first().copied(), env),
                                n,
                                "network.upload",
                            )
                        {
                            requests.push(upload);
                        }
                        if let Some(Some(body)) = body
                            && callable_name(body, self.src).as_deref() == Some("file_get_contents")
                            && !self.functions.contains_key("file_get_contents")
                            && !self.is_url(arg_nodes(body).first().copied())
                        {
                            self.request_bodies.insert(body.id(), requests);
                        } else if body.is_none_or(|body| {
                            body.is_some_and(|body| literal_string(body, self.src).is_none())
                        }) {
                            self.opaque(
                                BoundaryReason::DYNAMIC_SOURCE,
                                BoundaryClass::Unresolved,
                                *context,
                            );
                        }
                    }
                } else {
                    self.program_input(args.first().copied(), env, n);
                }
            }
            "stream_context_create" if self.examined_contexts.contains(&n.id()) => {}
            "fopen" => {
                if self.is_url(args.first().copied()) {
                    self.net(args.first().copied(), env, n);
                    return Some(());
                }
                let write = args
                    .get(1)
                    .and_then(|a| literal_string(*a, self.src))
                    .is_some_and(|m| m.contains(['w', 'a', 'x', 'c', '+']));
                if write {
                    self.fs(args.first().copied(), env, "filesystem.write", n, None);
                } else {
                    self.program_input(args.first().copied(), env, n);
                }
            }
            // A proven rename moves the source entry: the source entry is
            // deleted and the destination entry written, with no source
            // content read to invent. `filesystem.move` is the semantic layer.
            "rename" => {
                self.fs(args.first().copied(), env, "filesystem.move", n, None);
                let source = self.fs_slot(args.first().copied(), env, "filesystem.delete", n, None);
                let destination =
                    self.fs_slot(args.get(1).copied(), env, "filesystem.write", n, None);
                self.record_transfer(source, destination);
            }
            // A copy reads the source and writes the destination; a URL source
            // is a network read-side endpoint instead of a local one.
            "copy" => {
                let source = if self.is_url(args.first().copied()) {
                    self.net_slot(args.first().copied(), env, n)
                } else {
                    self.fs_slot(args.first().copied(), env, "filesystem.read", n, None)
                };
                let destination =
                    self.fs_slot(args.get(1).copied(), env, "filesystem.write", n, None);
                self.record_transfer(source, destination);
            }
            "getenv" => {
                self.emit(
                    env_effect(args.first().copied(), self.src, "environment.read"),
                    n,
                );
            }
            "putenv" => {
                self.emit(putenv_effect(args.first().copied(), self.src), n);
            }
            "fsockopen" | "pfsockopen" | "stream_socket_client" => {
                self.net(args.first().copied(), env, n)
            }
            "curl_init" => {}
            "curl_exec" => {
                let resource = args
                    .first()
                    .and_then(|arg| variable_name(*arg, self.src))
                    .and_then(|handle| self.network_handles.get(handle))
                    .cloned()
                    .unwrap_or(unresolved_resource("network"));
                self.emit_network(resource, n, "network.request");
            }
            "curl_setopt" => {
                if args.get(1).map(|a| text(*a, self.src)) == Some("CURLOPT_URL")
                    && let Some(handle) = args
                        .first()
                        .and_then(|arg| variable_name(*arg, self.src))
                        .map(str::to_string)
                {
                    let resource = self.url_resource(args.get(2).copied(), env);
                    self.network_handles.insert(handle, resource);
                }
            }
            "define" => {
                // Record a statically-evaluable string constant: it may name
                // an include path later (`define('ROOT', dirname(__DIR__))`).
                if let (Some(name), Some(value)) = (
                    args.first().and_then(|a| literal_string(*a, self.src)),
                    args.get(1).and_then(|v| self.static_path(*v, env)),
                ) {
                    self.inc.consts.insert(name, value);
                }
            }
            "mysqli_query" | "mysql_query" => {
                // mysqli_query($conn, "SQL") | mysql_query("SQL")
                let sql = if fname == "mysqli_query" {
                    args.get(1)
                } else {
                    args.first()
                };
                self.nest_sql(sql.copied(), n);
            }
            _ => return None,
        }
        Some(())
    }

    /// `attr` names a boolean attribute set to true on the effect (`append`
    /// for appending writes, `metadata` for stat-flavored probes).
    fn fs(
        &mut self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
        op: &str,
        site: Node<'a>,
        attr: Option<&str>,
    ) {
        self.fs_slot(arg, env, op, site, attr);
    }

    /// A read of `arg`'s contents into the program, which may print them, as
    /// Python's `open(path).read()` is.
    fn program_input(
        &mut self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
        site: Node<'a>,
    ) {
        if let Some(effect) = self.fs_slot(arg, env, "filesystem.read", site, None) {
            self.builder.set_effect_string_attribute(
                effect as usize,
                "access_purpose",
                "program_input",
            );
            if let Some(requests) = self.request_bodies.remove(&site.id()) {
                for request in requests {
                    self.record_transfer(Some(effect), Some(request));
                }
            }
        }
    }

    /// A filesystem effect on `arg`. The returned slot lets a transfer emitter
    /// pair the endpoint it just produced.
    fn fs_slot(
        &mut self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
        op: &str,
        site: Node<'a>,
        attr: Option<&str>,
    ) -> Option<u32> {
        let poisoned =
            arg.and_then(|argument| poisoned_php_reference(argument, &self.poisoned, self.src));
        let resource = match arg {
            Some(a) => self.resolve(a, env),
            None => unresolved_resource("filesystem"),
        };
        let mut effect = Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(op),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: None,
            realm: Default::default(),
            provenance: vec![],
        };
        if let Some(name) = attr {
            effect
                .attributes
                .insert(name.to_string(), effinterp_proto::AttrValue::Bool(true));
        }
        if contains_unresolved(&effect.resource)
            && let Some(name) = poisoned
        {
            let node = self.span(site);
            self.builder.boundary(Boundary {
                reason: BoundaryReason::UNMODELED_DYNAMIC,
                class: BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: Some(unresolved_resource("filesystem")),
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![node],
                limit: None,
                detail: Some(format!("php binding {name} could not be resolved")),
            });
            self.builder
                .declare_coverage(Domain::new("filesystem"), CoverageLevel::Partial);
        }
        self.emit(effect, site)
    }

    fn net(&mut self, arg: Option<Node<'a>>, env: &HashMap<String, ResourceExpr>, site: Node<'a>) {
        self.net_slot(arg, env, site);
    }

    /// A network request effect on `arg`, reporting its plan slot.
    pub(super) fn net_slot(
        &mut self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
        site: Node<'a>,
    ) -> Option<u32> {
        let resource = self.url_resource(arg, env);
        self.emit_network(resource, site, "network.request")
    }

    /// An effect on the interpreter process running this source, carrying one
    /// string attribute.
    pub(super) fn interpreter_effect(
        &self,
        operation: &str,
        (name, value): (&str, &str),
    ) -> Effect {
        let resource = match self.builder.launching_command() {
            Some(command) => ResourceExpr::Concrete {
                identity: crate::paths::process_identity_with_cwd(
                    &[crate::word::Word::literal(command)],
                    self.builder.current_execution_cwd(),
                ),
            },
            None => unresolved_resource("process"),
        };
        Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: [(
                name.to_string(),
                effinterp_proto::AttrValue::String(value.to_string()),
            )]
            .into_iter()
            .collect(),
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: None,
            realm: Default::default(),
            provenance: vec![],
        }
    }

    /// A call whose value is an `eval`'s whole argument transfers the effect
    /// producing that value into the evaluated code.
    fn evaluated(&mut self, call: Node<'a>, producer: Option<u32>) {
        let execution = self.eval_code.remove(&call.id());
        self.record_transfer(producer, execution);
    }

    fn emit_network(
        &mut self,
        resource: ResourceExpr,
        site: Node<'a>,
        operation: &str,
    ) -> Option<u32> {
        self.emit(
            Effect {
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
            },
            site,
        )
    }
}

fn env_effect(arg: Option<Node>, src: &str, op: &str) -> Effect {
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

fn putenv_effect(arg: Option<Node>, src: &str) -> Effect {
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

pub(super) fn environment_effect(resource: ResourceExpr, unset: bool) -> Effect {
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

pub(super) fn endpoint(url: &str) -> Option<ResourceExpr> {
    if !url.contains("://") {
        return None;
    }
    parse_url_endpoint(url).map(|identity| ResourceExpr::Concrete { identity })
}

impl<'a> PhpCaptureWalker<'a> {
    pub(super) fn call(&mut self, n: Node<'a>) {
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
                .and_then(|url| endpoint(&url))
        {
            self.push_effect("network.request", resource);
            return;
        }
        if matches!(fname, "fsockopen" | "pfsockopen" | "stream_socket_client") {
            let resource = args
                .first()
                .and_then(|arg| literal_string(*arg, self.src))
                .and_then(|url| endpoint(&url))
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
                .map(|a| resolve_expr(*a, self.src, &self.env))
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

/// The last value, or proven absence, of a literal PHP array key.
/// Outer None means dynamic keys, unpacking, or a nonliteral array prevent proof.
fn array_field<'a>(array: Node<'a>, key: &str, src: &str) -> Option<Option<Node<'a>>> {
    if array.kind() != "array_creation_expression" {
        return None;
    }
    let mut value = None;
    let mut cursor = array.walk();
    for entry in array.named_children(&mut cursor) {
        if entry.kind() == "comment" {
            continue;
        }
        if entry.kind() != "array_element_initializer" {
            return None;
        }
        let mut cursor = entry.walk();
        let fields: Vec<_> = entry.named_children(&mut cursor).collect();
        let [name, item] = fields.as_slice() else {
            return None;
        };
        if literal_string(*name, src)?.as_str() == key {
            value = Some(*item);
        }
    }
    Some(value)
}
