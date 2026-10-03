//! Modeled effects for Go standard-library and selected external APIs.

use std::collections::HashSet;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ProvenanceRef, ResourceExpr, ResourceIdentity, SqlConnection, SqlDialect, Subject,
};
use gosyn::ast::Expression;

use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};
use crate::{SemanticValue, SemanticValueKind};

use super::summary::{is_str_lit, unquote};
use super::{GoWalker, Out};
use crate::nest::{Transition, word_resource};

impl GoWalker<'_, '_> {
    pub(super) fn model_call(
        &mut self,
        path: &str,
        method: &str,
        args: &[Expression],
        node: ProvenanceRef,
    ) {
        let pkg = path.rsplit('/').next().unwrap_or(path);
        // These contracts do no external work beyond the callbacks walked at
        // the call site. Filesystem walkers still need their own effect model.
        if !go_callback_positions(path, method).is_empty()
            && !matches!(path, "path/filepath" | "io/fs")
        {
            return;
        }
        match (path, pkg, method) {
            ("gopkg.in/ini.v1", _, "Load") => self.fs(args, 0, "filesystem.read", &[], node),
            ("syscall", _, "Exec") => self.process(args, 0, node),
            ("os", _, "Remove") => self.fs(args, 0, "filesystem.delete", &[], node),
            ("os", _, "RemoveAll") => {
                self.fs(args, 0, "filesystem.delete", &[("recursive", true)], node)
            }
            ("os", _, "Mkdir") => self.fs(args, 0, "filesystem.create", &[], node),
            ("os", _, "MkdirAll") => {
                self.fs(args, 0, "filesystem.create", &[("parents", true)], node)
            }
            ("os", _, "Create") => self.fs(args, 0, "filesystem.write", &[], node),
            ("os", _, "Open") => self.fs(args, 0, "filesystem.read", &[], node),
            ("os", _, "OpenFile") => self.open_file(args, node),
            ("os", _, "WriteFile") => self.fs(args, 0, "filesystem.write", &[], node),
            // CreateTemp(dir, pattern): a fresh temp file, path never literal.
            ("os", _, "CreateTemp") => self.emit(
                "filesystem.write",
                unresolved_resource("filesystem"),
                &[],
                node,
            ),
            ("os" | "io/ioutil", _, "ReadFile") => self.fs(args, 0, "filesystem.read", &[], node),
            ("io/ioutil", _, "WriteFile") => self.fs(args, 0, "filesystem.write", &[], node),
            // A proven rename moves the source entry: the source entry is
            // deleted and the destination entry written, with no source
            // content read to invent. `filesystem.move` is the semantic layer.
            ("os", _, "Rename") => self.rename_transfer(args, node),
            ("os", _, "Getenv" | "LookupEnv") => self.env(args, "environment.read", node),
            ("os", _, "Setenv") => self.env(args, "environment.write", node),
            ("os/exec", _, "Command" | "CommandContext") => {
                self.exec_command(path, method, args, node)
            }
            ("net/http", _, "Get" | "Post" | "Head" | "NewRequest") => {
                self.http(method, args, node)
            }
            ("net", _, "Dial" | "DialTimeout" | "Dialer.Dial") => {
                self.net_socket(args, 0, 1, "network.connect", node)
            }
            ("net", _, "DialContext" | "Dialer.DialContext") => {
                self.net_socket(args, 1, 2, "network.connect", node)
            }
            ("net", _, "Listen" | "ListenPacket") => {
                self.net_socket(args, 0, 1, "network.listen", node)
            }
            ("database/sql", _, "Query" | "Exec" | "QueryRow") => self.sql(args, node),
            ("database/sql", _, "ExecContext" | "QueryContext" | "QueryRowContext") => {
                self.sql(args.get(1..).unwrap_or_default(), node)
            }
            ("database/sql", _, "Open" | "OpenDB" | "Begin" | "BeginTx" | "Conn") => {}
            // No model arm matched. An unmodeled call into an effectful stdlib
            // package (`os.Chtimes`, `net.Dial`) must stay loud — "external"
            // says where the code lives, not that it is effect-free. Only
            // an exact inert contract can make an unmatched call quiet.
            _ => match crate::external::classify_go_call(path, method) {
                Some(crate::external::ExternalCall::Inert) => {}
                Some(crate::external::ExternalCall::Unmodeled(domains)) => {
                    self.unmodeled_external(&format!("{path}.{method}"), domains, node, false)
                }
                _ => self.unmodeled_external(
                    &format!("{path}.{method}"),
                    crate::external::ALL_DOMAINS,
                    node,
                    false,
                ),
            },
        }
    }

    /// Preserve the callee and call occurrence when no model bounds its work.
    /// Unknown behavior defaults to every domain.
    pub(super) fn unmodeled_external(
        &mut self,
        name: &str,
        domains: crate::external::Domains,
        node: ProvenanceRef,
        source_call: bool,
    ) {
        for d in domains {
            self.out_coverage(Domain::new(*d), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason: if source_call {
                BoundaryReason::UNRESOLVED_CALL
            } else {
                BoundaryReason::EXTERNAL_UNMODELED
            },
            class: if source_call {
                BoundaryClass::Unresolved
            } else {
                BoundaryClass::Unmodeled
            },
            scope: effinterp_proto::BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: name
                    .rsplit_once('.')
                    .map_or(self.fact_function.as_str(), |(module, _)| module)
                    .to_string(),
                symbol: name
                    .rsplit_once('.')
                    .map_or(name, |(_, symbol)| symbol)
                    .to_string(),
            }),
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call to unmodeled {name}")),
        });
    }

    fn fs(
        &mut self,
        args: &[Expression],
        index: usize,
        op: &str,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) {
        self.fs_slot(args, index, op, attrs, node);
    }

    /// A filesystem op on the argument at `index`. The returned slot lets a
    /// transfer emitter pair the endpoint it just produced.
    fn fs_slot(
        &mut self,
        args: &[Expression],
        index: usize,
        op: &str,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) -> Option<u32> {
        let resource = args
            .get(index)
            .map(|a| self.fs_arg(a))
            .unwrap_or(unresolved_resource("filesystem"));
        self.emit_slot(op, resource, attrs, node)
    }

    /// `os.Rename` moves the source entry: the source entry is deleted and the
    /// destination entry written, with no source content read to invent.
    /// `filesystem.move` remains the semantic layer over that pair.
    fn rename_transfer(&mut self, args: &[Expression], node: ProvenanceRef) {
        self.fs(args, 0, "filesystem.move", &[], node);
        let source = self.fs_slot(args, 0, "filesystem.delete", &[], node);
        let destination = self.fs_slot(args, 1, "filesystem.write", &[], node);
        self.record_transfer(source, destination);
    }

    fn env(&mut self, args: &[Expression], op: &str, node: ProvenanceRef) {
        let resource = match args.first().and_then(string_of) {
            Some(name) if !name.is_empty() => ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            },
            _ => unresolved_resource("environment"),
        };
        self.emit(op, resource, &[], node);
    }

    fn process(&mut self, args: &[Expression], index: usize, node: ProvenanceRef) {
        let resource = match args.get(index).and_then(string_of) {
            Some(program) if !program.is_empty() => ResourceExpr::Concrete {
                identity: ResourceIdentity::Process {
                    executable: program.rsplit('/').next().unwrap_or(&program).to_string(),
                    path: program.contains('/').then_some(program),
                    argv: args[index + 1..]
                        .iter()
                        .map(|argument| {
                            string_of(argument)
                                .or_else(|| self.literal_value(argument))
                                .map(|value| ResourceExpr::Literal { value })
                                .unwrap_or(unresolved_resource("process_argument"))
                        })
                        .collect(),
                    cwd: None,
                },
            },
            _ => unresolved_resource("process"),
        };
        self.emit("process.exec", resource, &[], node);
    }

    /// `os.OpenFile(path, flag, perm)`: the flag argument (an `os.O_*` bitmask,
    /// combined with `|`) decides whether this is a read or a write, and
    /// whether it appends.
    fn open_file(&mut self, args: &[Expression], node: ProvenanceRef) {
        let mut flags = HashSet::new();
        if let Some(flag_arg) = args.get(1) {
            self.collect_openfile_flags(flag_arg, &mut flags);
        }
        let append = flags.contains("O_APPEND");
        let write = append
            || flags.contains("O_WRONLY")
            || flags.contains("O_RDWR")
            || flags.contains("O_CREATE")
            || flags.contains("O_TRUNC");
        let op = if write {
            "filesystem.write"
        } else {
            "filesystem.read"
        };
        let attrs: &[(&str, bool)] = if append { &[("append", true)] } else { &[] };
        self.fs(args, 0, op, attrs, node);
    }

    /// Collect `os.O_*` flag names referenced by a (possibly `|`-combined)
    /// flag expression, resolving `os` through the file's imports.
    fn collect_openfile_flags(&self, expr: &Expression, out: &mut HashSet<String>) {
        match expr {
            Expression::Selector(sel) => {
                if let Expression::Ident(pkg) = &*sel.x
                    && self.imports.get(&pkg.name).map(String::as_str) == Some("os")
                {
                    out.insert(sel.sel.name.clone());
                }
            }
            Expression::Operation(op) => {
                self.collect_openfile_flags(&op.x, out);
                if let Some(y) = &op.y {
                    self.collect_openfile_flags(y, out);
                }
            }
            Expression::Paren(p) => self.collect_openfile_flags(&p.expr, out),
            _ => {}
        }
    }

    fn http(&mut self, method: &str, args: &[Expression], node: ProvenanceRef) {
        // NewRequest(method, url, body): url is arg 1; others: url is arg 0.
        let url_index = if method == "NewRequest" { 1 } else { 0 };
        let resource = args
            .get(url_index)
            .map(|url| self.network_arg(url))
            .unwrap_or(unresolved_resource("network"));
        // Post sends a body; NewRequest's verb (arg 0, if literal) decides
        // between a request and an upload the same way. Everything else
        // (Get/Head) is a plain request.
        let op = match method {
            "Post" => "network.upload",
            "NewRequest" => match args.first().and_then(string_of).as_deref() {
                Some("POST" | "PUT" | "PATCH") => "network.upload",
                _ => "network.request",
            },
            _ => "network.request",
        };
        self.emit(op, resource, &[], node);
    }

    fn net_socket(
        &mut self,
        args: &[Expression],
        network_index: usize,
        address_index: usize,
        operation: &str,
        node: ProvenanceRef,
    ) {
        let network = args
            .get(network_index)
            .and_then(|value| string_of(value).or_else(|| self.literal_value(value)));
        let address = args
            .get(address_index)
            .and_then(|value| string_of(value).or_else(|| self.literal_value(value)));
        let resource = address
            .as_deref()
            .map(|address| network_endpoint(network.as_deref(), address))
            .or_else(|| args.get(address_index).map(|value| self.network_arg(value)))
            .unwrap_or(unresolved_resource("network"));
        self.emit(operation, resource, &[], node);
        if operation == "network.listen"
            && let Some(socket) = unix_socket_file(network.as_deref(), address.as_deref())
        {
            self.emit("filesystem.create", socket, &[], node);
        }
    }

    fn literal_value(&self, expression: &Expression) -> Option<String> {
        match self.value_of(expression)?.kind {
            SemanticValueKind::Literal(value) => Some(value),
            _ => None,
        }
    }

    fn sql(&mut self, args: &[Expression], node: ProvenanceRef) {
        // db.Query/Exec("SQL", ...): the query is the first string argument.
        match args.first().and_then(string_of) {
            Some(sql) => self.nest_subject(
                Subject::Sql {
                    source: sql,
                    dialect: SqlDialect::Generic,
                    connection: SqlConnection::default(),
                },
                node,
            ),
            None => self.opaque(
                BoundaryReason::UNCOMPOSED_SQL,
                BoundaryClass::Unmodeled,
                "database",
                node,
            ),
        }
    }

    fn exec_command(&mut self, path: &str, method: &str, args: &[Expression], node: ProvenanceRef) {
        // exec.CommandContext(ctx, name, args...) has a leading context arg.
        let start = if method == "CommandContext" { 1 } else { 0 };
        let _ = path;
        let argv: Vec<Word> = args[start.min(args.len())..]
            .iter()
            .map(|arg| match string_of(arg) {
                Some(value) => Word::literal(value),
                None => Word::new(vec![WordPart::Unknown]),
            })
            .collect();
        if argv.is_empty() {
            self.opaque(
                BoundaryReason::UNCOMPOSED_SUBPROCESS,
                BoundaryClass::Unmodeled,
                "process",
                node,
            );
            return;
        }
        match &mut self.out {
            Out::Plan {
                builder,
                nest,
                cwd,
                depth,
                ..
            } => nest.nest(
                builder,
                Transition::exec(argv.iter().map(word_resource).collect(), argv.to_vec())
                    .exec_cwd(*cwd)
                    .cwd(
                        builder.current_execution_cwd(),
                        (nest.current_runtime_cwd().as_deref() == *cwd)
                            .then(|| nest.current_cwd_node())
                            .flatten(),
                    )
                    .runtime_cwd(nest.current_runtime_cwd().as_deref()),
                &[node],
                *depth,
            ),
            Out::Capture(_) => {
                self.process(args, start, node);
                self.opaque(
                    BoundaryReason::UNCOMPOSED_SUBPROCESS,
                    BoundaryClass::Unmodeled,
                    "process",
                    node,
                );
            }
        }
    }
}

/// The argument positions in which a standard-library entry point invokes a
/// function value it is handed. Unknown callers separately retain possibly
/// invoked callback bodies; these positions describe supported contracts.
pub(crate) fn go_callback_positions(path: &str, method: &str) -> &'static [usize] {
    match (path, method) {
        ("sort", "Slice" | "SliceStable" | "SliceIsSorted" | "Search" | "Find") => &[1],
        (
            "slices",
            "SortFunc" | "SortStableFunc" | "IsSortedFunc" | "IndexFunc" | "ContainsFunc"
            | "CompactFunc" | "DeleteFunc" | "MaxFunc" | "MinFunc",
        ) => &[1],
        // A sequence consumer runs the `iter.Seq` it is handed (that function
        // is the loop body's producer): `slices.Sorted(seq)` and
        // `slices.SortedFunc(seq, cmp)` invoke both the sequence and the
        // comparison.
        ("slices", "Sorted" | "Collect") => &[0],
        ("slices", "SortedFunc" | "SortedStableFunc") => &[0, 1],
        ("slices", "AppendSeq") => &[1],
        ("maps", "Collect") => &[0],
        ("maps", "Insert") => &[1],
        // `slices.EqualFunc(s1, s2, eq)`, `slices.CompareFunc(s1, s2, cmp)` and
        // `slices.BinarySearchFunc(s, target, cmp)` take their callback third.
        ("slices", "EqualFunc" | "CompareFunc" | "BinarySearchFunc") => &[2],
        ("maps", "DeleteFunc") => &[1],
        ("maps", "EqualFunc") => &[2],
        ("strings" | "bytes", "Map") => &[0],
        (
            "strings" | "bytes",
            "FieldsFunc" | "FieldsFuncSeq" | "IndexFunc" | "LastIndexFunc" | "ContainsFunc"
            | "TrimFunc" | "TrimLeftFunc" | "TrimRightFunc",
        ) => &[1],
        // `sync.Once.Do` and `sync.Map.Range`, reached through a receiver
        // declared with the package's type. `sync.OnceFunc` and friends only
        // wrap their argument; it runs when the returned function is called,
        // which `deferred_callback_value` follows instead.
        ("sync", "Do" | "Range") => &[0],
        ("time", "AfterFunc") => &[1],
        ("context", "AfterFunc") => &[1],
        ("path/filepath", "Walk" | "WalkDir") => &[1],
        // `fs.WalkDir(fsys, root, fn)` carries the filesystem first.
        ("io/fs", "WalkDir") => &[2],
        ("net/http", "HandleFunc") => &[1],
        // `(*http.Server).RegisterOnShutdown(f)` runs `f` when the server stops.
        ("net/http", "RegisterOnShutdown") => &[0],
        // `runtime.SetFinalizer(obj, fn)` and `runtime.AddCleanup(ptr, cleanup,
        // arg)` both run their callback later, off the registering goroutine.
        ("runtime", "SetFinalizer" | "AddCleanup") => &[1],
        ("flag", "Visit" | "VisitAll") => &[0],
        ("flag", "Func" | "BoolFunc") => &[2],
        _ => &[],
    }
}

/// The literal string value of an expression, if it is a string literal.
pub(super) fn string_of(expr: &Expression) -> Option<String> {
    match expr {
        Expression::BasicLit(lit) if is_str_lit(lit) => Some(unquote(&lit.value)),
        Expression::Paren(p) => string_of(&p.expr),
        _ => None,
    }
}

/// The socket file a `net.Listen` bind creates. A unix network creates the
/// file at its address; an unknown network may be a unix one, so the file it
/// would create stays an unresolved filesystem resource instead of a precise
/// negative in that domain. A known non-unix network creates no file.
pub(super) fn unix_socket_file(
    network: Option<&str>,
    address: Option<&str>,
) -> Option<ResourceExpr> {
    match (network, address) {
        (Some(network), _) if !network.starts_with("unix") => None,
        (Some(_), Some(path)) => Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: path.to_string(),
            },
        }),
        _ => Some(unresolved_resource("filesystem")),
    }
}

pub(super) fn network_endpoint(network: Option<&str>, address: &str) -> ResourceExpr {
    let scheme = network.map(str::to_string);
    if network.is_some_and(|network| network.starts_with("unix")) {
        // A unix socket's address is the endpoint's host. Repeating it as the
        // path renders it twice (`unix:///tmp/sock/tmp/sock`), and the
        // filesystem.create effect this bind also emits already carries the
        // socket path as a filesystem identity.
        return ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: address.to_string(),
                scheme,
                port: None,
                path: None,
            },
        };
    }
    let (host, port) = address
        .strip_prefix('[')
        .and_then(|address| address.split_once("]:"))
        .map(|(host, port)| (host.to_string(), port.parse().ok()))
        .or_else(|| {
            address
                .rsplit_once(':')
                .map(|(host, port)| (host.to_string(), port.parse().ok()))
        })
        .unwrap_or_else(|| (address.to_string(), None));
    let host = if host.is_empty() {
        "*".to_string()
    } else {
        host
    };
    ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host,
            scheme,
            port,
            path: None,
        },
    }
}

/// Effects of a call to an external Go package member `module.member` with the
/// given argument values, or `None` when that member is not modeled.
pub fn go_external_effects(
    module: &str,
    member: &str,
    arguments: &[SemanticValue],
) -> Option<Vec<Effect>> {
    if module == "net" && matches!(member, "Dial" | "DialTimeout" | "Listen" | "ListenPacket") {
        let network = arguments.first().and_then(semantic_string);
        let address = arguments.get(1).and_then(semantic_string);
        let resource = address
            .as_deref()
            .map(|address| network_endpoint(network.as_deref(), address))
            .unwrap_or(unresolved_resource("network"));
        let mut effects = vec![go_effect(
            if matches!(member, "Listen" | "ListenPacket") {
                "network.listen"
            } else {
                "network.connect"
            },
            resource,
        )];
        if matches!(member, "Listen" | "ListenPacket")
            && let Some(socket) = unix_socket_file(network.as_deref(), address.as_deref())
        {
            effects.push(go_effect("filesystem.create", socket));
        }
        return Some(effects);
    }
    if module != "os/exec" || !matches!(member, "Command" | "CommandContext") {
        return None;
    }
    let start = usize::from(member == "CommandContext");
    let executable = arguments.get(start)?;
    let executables = match &executable.kind {
        SemanticValueKind::Union(values) => values.iter().collect::<Vec<_>>(),
        _ => vec![executable],
    };
    let environment_executable = executables
        .iter()
        .any(|value| matches!(&value.kind, SemanticValueKind::Environment(_)));
    let mut base_argv = Vec::new();
    for argument in &arguments[start + 1..] {
        flatten_go_argv(argument, &mut base_argv);
    }
    let mut effects = Vec::new();
    for executable in executables {
        let (executable, path, shell_from_environment) = match &executable.kind {
            SemanticValueKind::Literal(path)
            | SemanticValueKind::Executable(path)
            | SemanticValueKind::Path {
                source: Some(path), ..
            } => (
                path.rsplit('/').next().unwrap_or(path).to_string(),
                path.contains('/').then(|| path.clone()),
                false,
            ),
            SemanticValueKind::Resource(ResourceIdentity::FsPath { path }) => (
                path.rsplit('/').next().unwrap_or(path).to_string(),
                path.contains('/').then(|| path.clone()),
                false,
            ),
            SemanticValueKind::Environment(name) => (format!("${name}"), None, true),
            _ => {
                effects.push(go_effect("process.exec", unresolved_resource("process")));
                continue;
            }
        };
        let mut argv = base_argv.clone();
        if let Some(command) = argv
            .iter_mut()
            .skip_while(
                |argument| !matches!(argument, ResourceExpr::Literal { value } if value == "-c"),
            )
            .nth(1)
            && (environment_executable
                || shell_from_environment
                || !matches!(command, ResourceExpr::Literal { .. }))
        {
            *command = unresolved_resource("process_command");
        }
        effects.push(go_effect(
            "process.exec",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process {
                    executable,
                    path,
                    argv,
                    cwd: None,
                },
            },
        ));
    }
    Some(effects)
}

fn semantic_string(value: &SemanticValue) -> Option<String> {
    match &value.kind {
        SemanticValueKind::Literal(value) | SemanticValueKind::Executable(value) => {
            Some(value.clone())
        }
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } => Some(value.clone()),
        SemanticValueKind::Resource(ResourceIdentity::FsPath { path }) => Some(path.clone()),
        _ => None,
    }
}

fn flatten_go_argv(value: &SemanticValue, output: &mut Vec<ResourceExpr>) {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => {
            for element in elements {
                flatten_go_argv(element, output);
            }
        }
        SemanticValueKind::Literal(value)
        | SemanticValueKind::Executable(value)
        | SemanticValueKind::Path {
            source: Some(value),
            ..
        } => output.push(ResourceExpr::Literal {
            value: value.clone(),
        }),
        SemanticValueKind::Resource(ResourceIdentity::FsPath { path }) => {
            output.push(ResourceExpr::Literal {
                value: path.clone(),
            })
        }
        _ => output.push(value.lower_resource()),
    }
}

fn go_effect(operation: &str, resource: ResourceExpr) -> Effect {
    Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        execution: effinterp_proto::ExecutionNodeRef(0),
        condition: None,
        realm: effinterp_proto::ExecutionRealm::Host,
        provenance: Vec::new(),
    }
}
