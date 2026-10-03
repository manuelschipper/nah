//! Modeled Python standard-library and HTTP client APIs.
//!
//! This module owns API classification and effect construction. The parent
//! module keeps parsing, execution reachability, and dataflow walking.

use effinterp_proto::{
    AttrValue, Effect, Modality, Operation, PathPlatform, ProvenanceRef, ResourceExpr,
    ResourceFamily, ResourceIdentity, normalize_resource,
};
use rustpython_parser::ast::{self, Constant, Expr, Stmt};
use rustpython_parser::text_size::TextRange;

use super::resolve::{self, host_endpoint, net_resource, str_literal};
use super::{
    DeferredArgv, PythonWalker, collect_returns, int_literal, keyword_bool, keyword_str,
    program_argv, python_call_argument, resource_command_string, shell_program,
};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::substitute_resource_expr;
use crate::value::unresolved_resource;
use crate::word::Word;
use crate::{ObjectIdentity, SemanticValue, SemanticValueKind, TypeRef, ValueArgument};

pub(super) fn python_external_type(path: &str) -> Option<TypeRef> {
    let path = match path {
        "requests.session" => "requests.Session",
        "argparse.ArgumentParser"
        | "requests.Session"
        | "pathlib.Path"
        | "pathlib.PurePath"
        | "pathlib.PosixPath"
        | "pathlib.PurePosixPath"
        | "pathlib.WindowsPath"
        | "httpx.Client"
        | "httpx.AsyncClient" => path,
        _ => return None,
    };
    Some(TypeRef::External {
        path: path.to_string(),
    })
}

/// Effects of methods on instances whose constructor has an exact external
/// type. The caller supplies the receiver resource separately because method
/// arguments do not contain a `pathlib.Path` object's constructed path.
pub(super) fn external_method_effects(
    receiver_type: &str,
    method: &str,
    receiver_resource: Option<ResourceExpr>,
    args: &[ValueArgument],
) -> Option<Vec<Effect>> {
    let effect = |operation: &str, resource: ResourceExpr| Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: Vec::new(),
    };
    match receiver_type {
        "requests.Session" | "httpx.Client" | "httpx.AsyncClient" => {
            let (operation, endpoint) = match method {
                "post" | "put" | "patch" => ("network.upload", Some((0, "url"))),
                "delete" | "get" | "head" | "options" => ("network.request", Some((0, "url"))),
                "request" => (
                    python_external_argument(args, 0, "method")
                        .as_ref()
                        .and_then(|argument| match argument {
                            ResourceExpr::Literal { value }
                            | ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path: value },
                            } => Some(net_op(value)),
                            _ => None,
                        })
                        .unwrap_or("network.request"),
                    Some((1, "url")),
                ),
                // requests and httpx both accept a prepared request here, not a URL.
                "send" => ("network.request", None),
                _ => return None,
            };
            Some(vec![effect(
                operation,
                endpoint
                    .and_then(|(index, name)| python_external_argument(args, index, name))
                    .map(python_network_resource)
                    .unwrap_or_else(|| unresolved_resource("network")),
            )])
        }
        "pathlib.Path"
        | "pathlib.PurePath"
        | "pathlib.PosixPath"
        | "pathlib.PurePosixPath"
        | "pathlib.WindowsPath" => {
            let resource = receiver_resource.unwrap_or_else(|| unresolved_resource("filesystem"));
            if method == "open" {
                let mode_argument = python_external_argument(args, 0, "mode");
                let mode = mode_argument
                    .as_ref()
                    .and_then(|argument| match argument {
                        ResourceExpr::Literal { value }
                        | ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: value },
                        } => Some(value.as_str()),
                        _ => None,
                    })
                    .unwrap_or("r");
                let mut effects = Vec::new();
                if mode.contains('r') || mode.contains('+') {
                    let mut read = effect("filesystem.read", resource.clone());
                    read.attributes.insert(
                        "access_purpose".into(),
                        AttrValue::String("program_input".into()),
                    );
                    effects.push(read);
                }
                if mode.contains(['w', 'a', 'x', '+']) {
                    let mut write = effect("filesystem.write", resource);
                    if mode.contains('a') {
                        write
                            .attributes
                            .insert("append".into(), AttrValue::Bool(true));
                    }
                    effects.push(write);
                }
                return Some(effects);
            }
            match method {
                "read_text" | "read_bytes" => {
                    let mut read = effect("filesystem.read", resource);
                    read.attributes.insert(
                        "access_purpose".into(),
                        AttrValue::String("program_input".into()),
                    );
                    Some(vec![read])
                }
                "write_text" | "write_bytes" => {
                    let mut write = effect("filesystem.write", resource);
                    write
                        .attributes
                        .insert("disclosure".into(), AttrValue::String("contents".into()));
                    Some(vec![write])
                }
                "touch" => Some(vec![effect("filesystem.write", resource)]),
                "mkdir" => {
                    let mut create = effect("filesystem.create", resource);
                    if python_external_bool(args, "parents") == Some(true) {
                        create
                            .attributes
                            .insert("parents".into(), AttrValue::Bool(true));
                    }
                    Some(vec![create])
                }
                "unlink" | "rmdir" => Some(vec![effect("filesystem.delete", resource)]),
                "rename" | "replace" => {
                    let mut destination = effect(
                        "filesystem.write",
                        python_external_argument(args, 0, "target")
                            .unwrap_or_else(|| unresolved_resource("filesystem")),
                    );
                    destination
                        .attributes
                        .insert("disclosure".into(), AttrValue::String("contents".into()));
                    Some(vec![effect("filesystem.move", resource), destination])
                }
                "exists" | "is_file" | "is_dir" | "stat" => {
                    let mut read = effect("filesystem.read", resource);
                    read.attributes
                        .insert("metadata".into(), AttrValue::Bool(true));
                    Some(vec![read])
                }
                // The same permission change `os.chmod` states.
                "chmod" => {
                    let mut change = effect("filesystem.metadata", resource);
                    change
                        .attributes
                        .insert("action".into(), AttrValue::String("chmod".into()));
                    Some(vec![change])
                }
                "iterdir" => {
                    let mut read = effect("filesystem.read", resource);
                    read.attributes.insert(
                        "access_purpose".into(),
                        AttrValue::String("program_input".into()),
                    );
                    Some(vec![read])
                }
                "glob" | "rglob" => {
                    let glob =
                        python_external_argument(args, 0, "pattern").and_then(
                            |value| match value {
                                ResourceExpr::Literal { value }
                                | ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path: value },
                                } => Some(value),
                                _ => None,
                            },
                        );
                    let pattern = match (&resource, glob) {
                        (
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path },
                            },
                            Some(glob),
                        ) => ResourceExpr::Pattern {
                            pattern: effinterp_proto::ResourcePattern::FsPath {
                                glob: pathlib_glob_pattern(path, &glob, method == "rglob"),
                            },
                        },
                        _ => resource,
                    };
                    let mut read = effect("filesystem.read", pattern);
                    read.attributes.insert(
                        "access_purpose".into(),
                        AttrValue::String("program_input".into()),
                    );
                    Some(vec![read])
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn python_external_bool(args: &[ValueArgument], name: &str) -> Option<bool> {
    let value = args
        .iter()
        .find(|argument| argument.name.as_deref() == Some(name))?
        .value
        .lower_resource();
    match value {
        ResourceExpr::Literal { value } => value.parse().ok(),
        _ => None,
    }
}

pub(super) fn path_object_resource(value: &SemanticValue) -> Option<ResourceExpr> {
    if !matches!(
        &value.evidence.ty,
        Some(TypeRef::External { path })
            if matches!(
                path.as_str(),
                "pathlib.Path"
                    | "pathlib.PurePath"
                    | "pathlib.PosixPath"
                    | "pathlib.PurePosixPath"
            )
    ) {
        return None;
    }
    let ObjectIdentity::Class { constructor, .. } = &value.as_object()?.identity else {
        return None;
    };
    let mut parts = Vec::new();
    for (index, argument) in constructor.iter().enumerate() {
        let resource = if index > 0
            && let SemanticValueKind::Path {
                source: Some(source),
                ..
            } = &argument.value.kind
        {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: source.clone(),
                },
            }
        } else {
            path_object_resource(&argument.value).unwrap_or_else(|| argument.value.lower_resource())
        };
        parts.push(resource);
    }
    match parts.len() {
        0 => None,
        1 => parts.pop(),
        _ => Some(normalize_resource(
            ResourceExpr::Join { parts },
            PathPlatform::Posix,
        )),
    }
}

/// The world-write, setuid and setgid bits an integer-literal chmod mode sets.
/// A mode that is not a literal states none of them.
fn chmod_grants(mode: Option<&Expr>) -> Vec<(&'static str, bool)> {
    let Some(mode) = mode.and_then(int_literal) else {
        return Vec::new();
    };
    crate::permission_mode::granted(crate::permission_mode::numeric(mode.into()))
        .map(|name| (name, true))
        .collect()
}

fn python_external_argument(
    args: &[ValueArgument],
    index: usize,
    name: &str,
) -> Option<ResourceExpr> {
    args.iter()
        .find(|argument| argument.name.is_none() && argument.index == index)
        .or_else(|| {
            args.iter()
                .find(|argument| argument.name.as_deref() == Some(name))
        })
        .map(|argument| argument.value.lower_resource())
}

fn python_network_resource(resource: ResourceExpr) -> ResourceExpr {
    match resource {
        resource @ ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { .. },
        }
        | resource @ ResourceExpr::Parameter { .. } => resource,
        ResourceExpr::Literal { value } => {
            match SemanticValue::source_literal(value).lower_resource() {
                resource @ ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { .. },
                } => resource,
                _ => ResourceExpr::Unresolved {
                    family: ResourceFamily::new("network"),
                },
            }
        }
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives
                .into_iter()
                .map(python_network_resource)
                .collect(),
        },
        ResourceExpr::Join { parts } => crate::value::sink_typed_join(parts, "network"),
        _ => ResourceExpr::Unresolved {
            family: ResourceFamily::new("network"),
        },
    }
}

/// The kind of network object a receiver expression evaluates to, so a method
/// call on it can be classified. Constructed via `constructor_kind`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiverKind {
    /// A `requests`/`httpx` session or client: methods are HTTP verbs.
    HttpClient,
    /// An `http.client.HTTP(S)Connection`: `.request(method, url)` hits `host`.
    HttpConnection,
    /// A `socket.socket()`: `.connect((host, port))` opens the endpoint.
    Socket,
    /// A `socket.socket(AF_UNIX)`: `.connect(path)` opens a Unix endpoint.
    UnixSocket,
    /// An asyncio event loop (`asyncio.get_running_loop()`):
    /// `.create_connection(...)` opens an endpoint.
    EventLoop,
}

/// A constructed network object bound to a receiver, with the endpoint fixed at
/// construction when known (the host of an `HTTPConnection`); clients and
/// sockets carry the endpoint per-call instead, leaving `host` unresolved.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Receiver {
    kind: ReceiverKind,
    host: ResourceExpr,
}

/// Map a constructor's canonical dotted path to the network object it builds,
/// or None if it constructs nothing we model.
fn constructor_kind(canon: &str) -> Option<ReceiverKind> {
    match canon {
        "requests.Session" | "requests.session" | "httpx.Client" | "httpx.AsyncClient" => {
            Some(ReceiverKind::HttpClient)
        }
        "http.client.HTTPConnection" | "http.client.HTTPSConnection" => {
            Some(ReceiverKind::HttpConnection)
        }
        "socket.socket" => Some(ReceiverKind::Socket),
        "asyncio.get_running_loop" | "asyncio.get_event_loop" | "asyncio.new_event_loop" => {
            Some(ReceiverKind::EventLoop)
        }
        _ => None,
    }
}

/// Classify an HTTP verb into an effect operation: data-bearing verbs upload,
/// everything else is a plain request.
fn net_op(verb: &str) -> &'static str {
    match verb.to_ascii_lowercase().as_str() {
        "post" | "put" | "patch" => "network.upload",
        _ => "network.request",
    }
}

impl PythonWalker<'_, '_> {
    /// Model one known Python effect API call. Returns false when the call
    /// belongs to local or unmodeled code and the execution walker must handle it.
    pub(super) fn model_call(&mut self, call: &ast::ExprCall, span: TextRange) -> bool {
        if let Expr::Attribute(attr) = call.func.as_ref()
            && self.is_path_method_receiver(attr.attr.as_str(), &attr.value)
        {
            let resource = self.resolve_fs(&attr.value);
            self.path_resource_method(attr.attr.as_str(), call, resource, span);
            return true;
        }
        if let Some((method, resource)) = self.typed_path_call(call) {
            self.path_resource_method(&method, call, resource, span);
            return true;
        }

        // A method on a constructed network object such as a requests session
        // or socket is modeled from the receiver kind.
        if let Expr::Attribute(attr) = call.func.as_ref()
            && let Some(receiver) = self.net_receiver(&attr.value)
        {
            let method = attr.attr.as_str();
            let handled = match receiver.kind {
                ReceiverKind::HttpClient => matches!(
                    method,
                    "get"
                        | "post"
                        | "put"
                        | "delete"
                        | "patch"
                        | "head"
                        | "options"
                        | "request"
                        | "send"
                        | "stream"
                ),
                ReceiverKind::HttpConnection => method == "request",
                ReceiverKind::Socket | ReceiverKind::UnixSocket => method == "connect",
                ReceiverKind::EventLoop => matches!(
                    method,
                    "create_connection"
                        | "create_unix_connection"
                        | "create_server"
                        | "create_unix_server"
                        | "create_datagram_endpoint"
                ),
            };
            if handled {
                self.net_method(&receiver, method, call, span);
                return true;
            }
        }

        let Some(name) = self.imports.resolve_callee(&call.func) else {
            return false;
        };
        if self.stdlib_resource_call(call, &name, span) {
            return true;
        }
        match name.as_str() {
            "open" | "io.open" | "io.FileIO" => self.builtin_open(call, span),
            "os.open" => self.os_open(call, span),
            // A literal `eval`/`exec` body is source this frontend can read, so
            // it is entered like any other nested program, as is a literal
            // compiled in place. Only a string the runtime supplies stays
            // opaque. Explicit globals/locals change which names the body
            // sees, so they keep it opaque too.
            "eval" | "exec" => {
                let body =
                    (call.args.len() == 1 && call.keywords.is_empty() && self.capture.is_none())
                        .then(|| {
                            call.args.first().and_then(|arg| {
                                str_literal(arg).or_else(|| self.compiled_literal(arg))
                            })
                        })
                        .flatten();
                match body {
                    Some(source) => self.nest_python_source(&source, span),
                    None => {
                        self.opaque_call(&name, span);
                        self.dynamic_code_execution(span);
                    }
                }
            }
            // A literal module name is an ordinary import, not dynamic code.
            "__import__"
                if call.keywords.is_empty()
                    && call.args.len() == 1
                    && call.args.first().and_then(str_literal).is_some() => {}
            // Compiling literal source runs nothing; running the code object
            // is the `exec`/`eval` that receives it.
            "compile" if literal_compile_source(call).is_some() => {}
            "__import__" | "compile" | "os.exec" => self.opaque_call(&name, span),
            // `os.removedirs` also prunes parents that become empty; only the
            // named leaf is certain to go.
            "os.remove" | "os.unlink" | "os.rmdir" | "os.removedirs" => {
                self.fs_op(call, 0, "filesystem.delete", &[], span);
            }
            "os.mkdir" => {
                self.fs_op(call, 0, "filesystem.create", &[], span);
            }
            "os.makedirs" => {
                self.fs_op(call, 0, "filesystem.create", &[("parents", true)], span);
            }
            // A proven rename moves the source entry: no source content read
            // is invented. `filesystem.move` stays the semantic layer.
            // Like `mv`, a rename takes the whole entry: a directory's tree.
            "os.rename" | "os.replace" => {
                self.fs_op(call, 0, "filesystem.move", &[("recursive", true)], span);
                let source = self.fs_op(call, 0, "filesystem.delete", &[], span);
                let destination = self.fs_op(call, 1, "filesystem.write", &[], span);
                self.set_effect_string_attribute(destination, "disclosure", "contents");
                self.record_exact_transfer(source, destination);
            }
            "os.chmod" => {
                let grants = chmod_grants(python_call_argument(call, 1, "mode"));
                let effect = self.fs_op(call, 0, "filesystem.metadata", &grants, span);
                self.set_effect_action(effect, "chmod");
            }
            "os.chown" => {
                let effect = self.fs_op(call, 0, "filesystem.metadata", &[], span);
                self.set_effect_action(effect, "chown");
            }
            // `lchown` is `chown` on a symlink itself rather than its target.
            "os.lchown" => {
                let effect = self.fs_op(call, 0, "filesystem.metadata", &[], span);
                self.set_effect_action(effect, "chown");
            }
            "os.chdir" => self.os_chdir(call, span),
            "os.execl" | "os.execle" | "os.execlp" | "os.execlpe" | "os.execv" | "os.execve"
            | "os.execvp" | "os.execvpe" | "os.spawnl" | "os.spawnle" | "os.spawnlp"
            | "os.spawnlpe" | "os.spawnv" | "os.spawnve" | "os.spawnvp" | "os.spawnvpe"
            | "os.posix_spawn" | "os.posix_spawnp" => self.os_exec(&name, call, span),
            // A hard link creates a second name for the source inode, so keep
            // the same metadata source and exact relation as `ln`. A symbolic
            // link records only its kind on the new directory entry.
            "os.link" | "os.symlink" => {
                let symbolic = name == "os.symlink";
                let destination =
                    self.fs_op(call, 1, "filesystem.create", &[("symlink", symbolic)], span);
                if !symbolic
                    && call.args.first().is_some_and(|source| {
                        matches!(
                            self.resolve_fs(source),
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { .. }
                            }
                        )
                    })
                {
                    let source =
                        self.fs_op(call, 0, "filesystem.read", &[("metadata", true)], span);
                    self.record_exact_transfer(source, destination);
                }
            }
            // Stat probes are metadata reads, not metadata mutations.
            "os.stat" | "os.lstat" => {
                self.fs_op(call, 0, "filesystem.read", &[("metadata", true)], span);
            }
            "os.listdir" | "os.scandir" => {
                self.fs_op(call, 0, "filesystem.read", &[], span);
            }
            "os.truncate" => {
                self.fs_op(call, 0, "filesystem.write", &[], span);
            }
            "shutil.rmtree" => {
                self.fs_op(call, 0, "filesystem.delete", &[("recursive", true)], span);
            }
            // A copy reads the source and writes the destination; the source
            // entry survives, so there is no source delete.
            "shutil.copy" | "shutil.copy2" | "shutil.copyfile" | "shutil.copytree" => {
                let source = self.fs_op(call, 0, "filesystem.read", &[], span);
                let destination = self.fs_op(call, 1, "filesystem.write", &[], span);
                self.set_effect_string_attribute(destination, "disclosure", "contents");
                self.record_exact_transfer(source, destination);
            }
            // `shutil.move` is a general move utility: it may rename the entry
            // or copy the content and delete the source. The entry mutation is
            // paired, and the possible copy read is paired as the content
            // relation without being required by the move itself.
            "shutil.move" => {
                self.fs_op(call, 0, "filesystem.move", &[], span);
                let read = self.fs_op(call, 0, "filesystem.read", &[], span);
                let deleted = self.fs_op(call, 0, "filesystem.delete", &[], span);
                let destination = self.fs_op(call, 1, "filesystem.write", &[], span);
                self.set_effect_string_attribute(destination, "disclosure", "contents");
                self.record_exact_transfer(deleted, destination);
                self.record_exact_transfer(read, destination);
            }
            "os.getenv"
            | "os.environ.get"
            | "os.putenv"
            | "os.unsetenv"
            | "os.setenv"
            | "os.environ.pop"
            | "os.environ.setdefault"
            | "os.environ.clear" => self.env_op(&name, call, span),
            "os.environ.update" => self.env_update(call, span),
            "print" if self.prints_environ(call) => self.print_environ(span),
            "base64.b64decode" | "base64.standard_b64decode" | "base64.urlsafe_b64decode" => {
                self.base64_decode(span)
            }
            "os.system" | "os.popen" => self.os_system(call, span),
            "subprocess.run"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "subprocess.Popen" => {
                // Popen's first parameter is `args`, so it may also be passed by name.
                let args = python_call_argument(call, 0, "args");
                self.subprocess(
                    call,
                    args,
                    keyword_bool(call, "shell").unwrap_or(false),
                    span,
                )
            }
            // Both always run `cmd` through the shell.
            "subprocess.getoutput" | "subprocess.getstatusoutput" => {
                self.subprocess(call, python_call_argument(call, 0, "cmd"), true, span)
            }
            "asyncio.create_subprocess_exec"
            | "asyncio.subprocess.create_subprocess_exec"
            | "asyncio.create_subprocess_shell"
            | "asyncio.subprocess.create_subprocess_shell" => {
                self.asyncio_subprocess(&name, call, span)
            }
            "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.delete"
            | "requests.patch"
            | "requests.head"
            | "requests.options"
            | "requests.request"
            | "httpx.get"
            | "httpx.post"
            | "httpx.put"
            | "httpx.delete"
            | "httpx.patch"
            | "httpx.head"
            | "httpx.options"
            | "httpx.request"
            | "httpx.stream"
            | "urllib.request.urlopen" => self.network(&name, call, span),
            "urllib.request.urlretrieve" => self.urlretrieve(call, span),
            "asyncio.run"
            | "asyncio.gather"
            | "asyncio.wait"
            | "asyncio.wait_for"
            | "asyncio.as_completed"
            | "asyncio.create_task"
            | "asyncio.ensure_future"
            | "asyncio.run_coroutine_threadsafe" => {}
            "pathlib.Path"
            | "pathlib.PurePath"
            | "pathlib.PosixPath"
            | "pathlib.PurePosixPath"
            | "pathlib.Path.home"
            | "pathlib.PosixPath.home"
            | "pathlib.Path.cwd"
            | "pathlib.PosixPath.cwd" => {}
            _ => return false,
        }
        true
    }

    fn resolve_net(&self, expr: &Expr) -> ResourceExpr {
        if matches!(expr, Expr::Name(name) if self.widened_vars.contains(name.id.as_str()))
            || self.concatenation_uses_unbounded_binding(expr)
        {
            return unresolved_resource("network");
        }
        let resource = self
            .source_string_resource(expr)
            .unwrap_or_else(|| net_resource(expr));
        let resource = substitute_resource_expr(&resource, &self.var_scope);
        // A function summary cannot type the join until its leading parameter
        // has been replaced by the caller's URL.
        if self.capture.is_some()
            && self.current_function.is_some()
            && matches!(&resource, ResourceExpr::Join { .. })
        {
            resource
        } else {
            python_network_resource(resource)
        }
    }

    fn resolve_process_arg(&self, expr: &Expr) -> ResourceExpr {
        str_literal(expr)
            .map(|value| ResourceExpr::Literal { value })
            .unwrap_or_else(|| resolve::symbolic(expr, "process"))
    }

    /// `open(path, mode)` / `io.open(...)` — read/write/append from the mode.
    fn builtin_open(&mut self, call: &ast::ExprCall, span: TextRange) {
        let Some(path) = call.args.first() else {
            return;
        };
        let resource = self.resolve_fs(path);
        let node = self.span_node(span);
        if matches!(resource, ResourceExpr::Unresolved { .. })
            && self.lowered_concatenation(path).is_none()
        {
            self.opaque_boundary("filesystem argument is not statically bounded", node);
        }
        // Builtin `open(path, mode)` — the mode is the second positional arg.
        self.open_by_mode(call, 1, resource, node);
    }

    /// Emit read/write effects on `resource` from an open-style call's mode
    /// argument (positional `mode_index` or the `mode=` keyword, defaulting to
    /// "r"). Shared by the builtin `open` and `pathlib.Path(p).open(mode)`,
    /// whose mode arguments sit at different positions.
    fn open_by_mode(
        &mut self,
        call: &ast::ExprCall,
        mode_index: usize,
        resource: ResourceExpr,
        node: ProvenanceRef,
    ) {
        let mode = call
            .args
            .get(mode_index)
            .and_then(str_literal)
            .or_else(|| keyword_str(call, "mode"))
            .unwrap_or_else(|| "r".to_string());
        let write = mode.contains(['w', 'a', 'x', '+']);
        let read = mode.contains('r') || mode.contains('+');
        if read {
            let read = self.emit("filesystem.read", resource.clone(), &[], node);
            self.set_effect_string_attribute(read, "access_purpose", "program_input");
        }
        if write {
            let attrs: &[(&str, bool)] = if mode.contains('a') {
                &[("append", true)]
            } else {
                &[]
            };
            self.emit("filesystem.write", resource, attrs, node);
        }
    }

    /// A filesystem op on the argument at `index`. The returned slot lets a
    /// transfer emitter pair the endpoint it just produced.
    fn fs_op(
        &mut self,
        call: &ast::ExprCall,
        index: usize,
        operation: &str,
        attrs: &[(&str, bool)],
        span: TextRange,
    ) -> Option<u32> {
        let arg = call.args.get(index)?;
        let lowered_concatenation = self.lowered_concatenation(arg).is_some();
        let resource = self.resolve_fs(arg);
        let node = self.span_node(span);
        if matches!(resource, ResourceExpr::Unresolved { .. }) && !lowered_concatenation {
            self.opaque_boundary("filesystem argument is not statically bounded", node);
        }
        let effect = self.emit(operation, resource, attrs, node);
        if operation == "filesystem.read"
            && !attrs.iter().any(|(name, on)| *name == "metadata" && *on)
        {
            self.set_effect_string_attribute(effect, "access_purpose", "program_input");
        }
        effect
    }

    fn set_effect_string_attribute(&mut self, effect: Option<u32>, name: &str, value: &str) {
        let Some(effect) = effect else {
            return;
        };
        if let Some(capture) = self.capture.as_mut() {
            capture.effects[effect as usize]
                .attributes
                .insert(name.into(), AttrValue::String(value.into()));
        } else {
            self.builder
                .set_effect_string_attribute(effect as usize, name, value);
        }
    }

    fn set_effect_action(&mut self, effect: Option<u32>, action: &str) {
        self.set_effect_string_attribute(effect, "action", action);
    }

    fn record_exact_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        let (Some(source), Some(destination)) = (source, destination) else {
            return;
        };
        let binding = TransferBinding::exact(source, destination);
        match self.capture.as_mut() {
            Some(capture) => {
                if !capture.transfers.contains(&binding) {
                    capture.transfers.push(binding);
                }
            }
            None => self.builder.transfer_binding(binding),
        }
    }

    fn path_resource_method(
        &mut self,
        method: &str,
        call: &ast::ExprCall,
        resource: ResourceExpr,
        span: TextRange,
    ) {
        let node = self.span_node(span);
        if method == "read_text" && !self.safe_codec(call) {
            self.emit_unresolved_call(
                "pathlib.Path.read_text codec",
                effinterp_proto::BoundaryReason::EXTERNAL_UNMODELED,
                effinterp_proto::BoundaryClass::Unmodeled,
                crate::external::ALL_DOMAINS,
                span,
                super::python_callee_reference("pathlib.Path.read_text"),
            );
        }
        if matches!(resource, ResourceExpr::Unresolved { .. }) {
            self.opaque_boundary("filesystem argument is not statically bounded", node);
        }
        // Every arm reports the slot it emitted; only the transfer arm pairs
        // them, so the rest are discarded here.
        let _emitted = match method {
            "read_text" | "read_bytes" => {
                let read = self.emit("filesystem.read", resource, &[], node);
                self.set_effect_string_attribute(read, "access_purpose", "program_input");
                read
            }
            "write_text" | "write_bytes" => {
                let write = self.emit("filesystem.write", resource, &[], node);
                self.set_effect_string_attribute(write, "disclosure", "contents");
                write
            }
            "touch" => self.emit("filesystem.write", resource, &[], node),
            // `Path(p).open(mode)` — the mode is this call's first argument.
            "open" => {
                self.open_by_mode(call, 0, resource, node);
                None
            }
            "unlink" | "rmdir" => self.emit("filesystem.delete", resource, &[], node),
            "mkdir" => self.emit(
                "filesystem.create",
                resource,
                &[("parents", keyword_bool(call, "parents").unwrap_or(false))],
                node,
            ),
            // A proven rename moves the source entry: the source entry is
            // deleted and the destination entry written, with no source
            // content read to invent. `filesystem.move` stays as the semantic
            // layer over that pair and does not pair a second time.
            "rename" | "replace" => {
                self.emit(
                    "filesystem.move",
                    resource.clone(),
                    &[("recursive", true)],
                    node,
                );
                let source = self.emit("filesystem.delete", resource, &[], node);
                let destination = python_call_argument(call, 0, "target").and_then(|target| {
                    let target = self.resolve_fs(target);
                    self.emit("filesystem.write", target, &[], node)
                });
                self.set_effect_string_attribute(destination, "disclosure", "contents");
                self.record_exact_transfer(source, destination);
                destination
            }
            "exists" | "is_file" | "is_dir" | "stat" => {
                self.emit("filesystem.read", resource, &[("metadata", true)], node)
            }
            // The same permission change `os.chmod` states.
            "chmod" => {
                let grants = chmod_grants(python_call_argument(call, 0, "mode"));
                let effect = self.emit("filesystem.metadata", resource, &grants, node);
                self.set_effect_action(effect, "chmod");
                effect
            }
            // `link.symlink_to(target)` and `link.hardlink_to(target)` create
            // the receiver as a new entry, mirroring `os.symlink(target, link)`
            // and `os.link(target, link)`: a hard link also reads the target's
            // inode metadata and pairs it with the new name.
            "symlink_to" => self.emit("filesystem.create", resource, &[("symlink", true)], node),
            "hardlink_to" => {
                let destination =
                    self.emit("filesystem.create", resource, &[("symlink", false)], node);
                if let Some(target) = python_call_argument(call, 0, "target") {
                    let target = self.resolve_fs(target);
                    if matches!(
                        target,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. }
                        }
                    ) {
                        let source =
                            self.emit("filesystem.read", target, &[("metadata", true)], node);
                        self.record_exact_transfer(source, destination);
                    }
                }
                destination
            }
            "iterdir" => {
                let read = self.emit("filesystem.read", resource, &[], node);
                self.set_effect_string_attribute(read, "access_purpose", "program_input");
                read
            }
            "glob" | "rglob" => {
                let glob = python_call_argument(call, 0, "pattern").and_then(str_literal);
                let pattern = match (&resource, glob) {
                    (
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        },
                        Some(glob),
                    ) => Some(ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::FsPath {
                            glob: pathlib_glob_pattern(path, &glob, method == "rglob"),
                        },
                    }),
                    _ => None,
                }
                .unwrap_or(resource);
                let read = self.emit("filesystem.read", pattern, &[], node);
                self.set_effect_string_attribute(read, "access_purpose", "program_input");
                read
            }
            _ => None,
        };
    }

    pub(super) fn typed_path_call(&self, call: &ast::ExprCall) -> Option<(String, ResourceExpr)> {
        let Expr::Attribute(method) = call.func.as_ref() else {
            return None;
        };
        let resource = match method.value.as_ref() {
            Expr::Name(name) if self.current_path_params.contains(name.id.as_str()) => {
                ResourceExpr::Parameter {
                    name: name.id.to_string(),
                }
            }
            Expr::Attribute(attr) if matches!(attr.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self") => {
                self.is_current_path_attr(attr.attr.as_str())
                    .then(|| ResourceExpr::Parameter {
                        name: format!("self.{}", attr.attr),
                    })?
            }
            _ => return None,
        };
        Some((method.attr.to_string(), resource))
    }

    fn env_op(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        let operation = if name == "os.getenv" || name == "os.environ.get" {
            "environment.read"
        } else {
            "environment.write"
        };
        let resource = call
            .args
            .first()
            .and_then(|arg| {
                str_literal(arg).or_else(|| {
                    let Expr::Attribute(attr) = arg else {
                        return None;
                    };
                    let class = match attr.value.as_ref() {
                        Expr::Name(name) if name.id.as_str() == "self" => {
                            self.current_class.as_ref()?
                        }
                        Expr::Name(name) => name.id.as_str(),
                        _ => return None,
                    };
                    self.class_strings
                        .get(&(class.to_string(), attr.attr.to_string()))
                        .cloned()
                })
            })
            .filter(|name| !name.is_empty())
            .map(|name| ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            })
            .unwrap_or_else(|| unresolved_resource("environment"));
        let node = self.span_node(span);
        let unset = matches!(name, "os.unsetenv" | "os.environ.pop" | "os.environ.clear");
        self.emit(operation, resource, &[("unset", unset)], node);
    }

    fn env_update(&mut self, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        for argument in &call.args {
            let Expr::Dict(dict) = argument else {
                self.emit(
                    "environment.write",
                    unresolved_resource("environment"),
                    &[],
                    node,
                );
                continue;
            };
            for key in &dict.keys {
                let resource = key
                    .as_ref()
                    .and_then(str_literal)
                    .filter(|name| !name.is_empty())
                    .map(|name| ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name },
                    })
                    .unwrap_or_else(|| unresolved_resource("environment"));
                self.emit("environment.write", resource, &[], node);
            }
        }
        for keyword in &call.keywords {
            let resource = keyword
                .arg
                .as_ref()
                .map(|name| name.to_string())
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                })
                .unwrap_or_else(|| unresolved_resource("environment"));
            self.emit("environment.write", resource, &[], node);
        }
    }

    /// `os.environ[k] = v` — an environment write via subscript assignment.
    pub(super) fn env_subscript_write(&mut self, target: &Expr, unset: bool) {
        let Expr::Subscript(sub) = target else {
            return;
        };
        if self.imports.resolve_callee(&sub.value).as_deref() != Some("os.environ") {
            return;
        }
        let resource = str_literal(&sub.slice)
            .filter(|name| !name.is_empty())
            .map(|name| ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            })
            .unwrap_or_else(|| unresolved_resource("environment"));
        let node = self.span_node(sub.range);
        self.emit("environment.write", resource, &[("unset", unset)], node);
    }

    /// A base64 decoder runs inside the interpreter executing this source, so
    /// that interpreter process performs the transform. The transform is
    /// exact; whether the operand is valid base64 is not asserted.
    fn base64_decode(&mut self, span: TextRange) {
        let node = self.span_node(span);
        let resource = self.interpreter_resource();
        self.emit_request(
            "process.stream_transform",
            resource,
            std::collections::BTreeMap::from([(
                "transform".to_string(),
                AttrValue::String("decode".to_string()),
            )]),
            node,
            Some("python/base64@v0"),
        );
    }

    /// `print(os.environ)` writes every variable's name and value to stdout.
    fn prints_environ(&self, call: &ast::ExprCall) -> bool {
        self.imports.ordinary_stdout()
            && !call.args.is_empty()
            && call
                .args
                .iter()
                .all(|arg| self.imports.resolve_callee(arg).as_deref() == Some("os.environ"))
            && call.keywords.iter().all(|kw| {
                kw.arg.as_deref() == Some("file")
                    && self.imports.resolve_callee(&kw.value).as_deref() == Some("sys.stdout")
            })
    }

    /// Every variable in this execution's environment reaches stdout, including
    /// any a wrapper such as `doppler run` injected, so their values flow into
    /// the read the way they do for `env`.
    fn print_environ(&mut self, span: TextRange) {
        let node = self.span_node(span);
        let effect = self.emit_request(
            "environment.read",
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::EnvironmentVariable {
                    name_glob: "*".into(),
                },
            },
            std::collections::BTreeMap::from([(
                "output".to_string(),
                AttrValue::String("stdout".to_string()),
            )]),
            node,
            None,
        );
        let Some(effect) = effect.filter(|_| self.capture.is_none()) else {
            return;
        };
        let unsets = self.nest.current_environment_unsets();
        let mut values = self
            .nest
            .environments
            .borrow()
            .last()
            .into_iter()
            .flat_map(|environment| environment.keys())
            .filter(|name| !unsets.contains(*name))
            .filter_map(|name| self.nest.current_environment_node(name))
            .collect::<Vec<_>>();
        values.extend(self.nest.injected_environment_node());
        self.builder
            .bind_environment_value_producers(effect, &values);
    }

    /// `exec`/`eval` of source this frontend cannot read runs it in the
    /// interpreter executing this program. The code itself stays opaque (the
    /// caller's boundary); this effect is the sink the argument's bytes reach,
    /// the way a shell `eval` of a runtime string is.
    fn dynamic_code_execution(&mut self, span: TextRange) {
        let node = self.span_node(span);
        let resource = self.interpreter_resource();
        self.emit_request(
            "process.code_execution",
            resource,
            std::collections::BTreeMap::from([(
                "source".to_string(),
                AttrValue::String("argument".to_string()),
            )]),
            node,
            None,
        );
    }

    /// The interpreter process executing this source, when the launch names it.
    fn interpreter_resource(&self) -> ResourceExpr {
        match self
            .import_search
            .as_ref()
            .and_then(|search| search.executable.as_deref())
        {
            Some(executable) => ResourceExpr::Concrete {
                identity: crate::paths::process_identity_with_cwd(
                    &[Word::literal(executable)],
                    self.builder.current_execution_cwd(),
                ),
            },
            None => unresolved_resource("process"),
        }
    }

    /// The source of `compile(<literal>, <literal filename>, <mode>)` when the
    /// callee is the builtin `compile`.
    fn compiled_literal(&self, expr: &Expr) -> Option<String> {
        let Expr::Call(call) = expr else {
            return None;
        };
        (self.imports.resolve_callee(&call.func).as_deref() == Some("compile"))
            .then(|| literal_compile_source(call))
            .flatten()
    }

    /// The text a shell receives from a base64 decoder applied to a literal,
    /// optionally followed by `.decode()`. A literal that does not decode
    /// raises before any shell starts, so it yields no command.
    fn decoded_literal(&self, expr: &Expr) -> Option<String> {
        let Expr::Call(call) = expr else {
            return None;
        };
        if let Expr::Attribute(attr) = call.func.as_ref()
            && attr.attr.as_str() == "decode"
        {
            return (self.safe_method_result(call, 0) == Some(ExactValue::Text))
                .then(|| self.decoded_literal(&attr.value))
                .flatten();
        }
        let urlsafe = match self.imports.resolve_callee(&call.func)?.as_str() {
            "base64.b64decode" | "base64.standard_b64decode" => false,
            "base64.urlsafe_b64decode" => true,
            _ => return None,
        };
        let [operand] = call.args.as_slice() else {
            return None;
        };
        if !call.keywords.is_empty() {
            return None;
        }
        let encoded = match operand {
            Expr::Constant(constant) => match &constant.value {
                Constant::Str(text) => text.as_bytes().to_vec(),
                Constant::Bytes(bytes) => bytes.clone(),
                _ => return None,
            },
            _ => return None,
        };
        String::from_utf8(decode_base64(&encoded, urlsafe)?).ok()
    }

    /// `os.open(path, flags)`: the access mode and creation flags decide
    /// whether the descriptor reads, writes, or both.
    fn os_open(&mut self, call: &ast::ExprCall, span: TextRange) {
        let Some(path) = call.args.first() else {
            return;
        };
        let resource = self.resolve_fs(path);
        let node = self.span_node(span);
        if matches!(resource, ResourceExpr::Unresolved { .. })
            && self.lowered_concatenation(path).is_none()
        {
            self.opaque_boundary("filesystem argument is not statically bounded", node);
        }
        let Some((read, write)) =
            python_call_argument(call, 1, "flags").and_then(|flags| self.os_open_access(flags))
        else {
            self.opaque_boundary("os.open flags are not statically bounded", node);
            return;
        };
        if read {
            let read = self.emit("filesystem.read", resource.clone(), &[], node);
            self.set_effect_string_attribute(read, "access_purpose", "program_input");
        }
        if write != OsOpenWrite::None {
            let append: &[(&str, bool)] = if write == OsOpenWrite::Append {
                &[("append", true)]
            } else {
                &[]
            };
            self.emit("filesystem.write", resource, append, node);
        }
    }

    /// Whether `os.open` flags read and how they write, from `os.O_*` names
    /// joined by `|`. `O_RDONLY` is zero, so read is the absence of a write
    /// access mode; creating or truncating counts as a write.
    fn os_open_access(&self, flags: &Expr) -> Option<(bool, OsOpenWrite)> {
        let mut names = Vec::new();
        let mut pending = vec![flags];
        while let Some(expr) = pending.pop() {
            match expr {
                Expr::BinOp(ast::ExprBinOp {
                    left,
                    op: ast::Operator::BitOr,
                    right,
                    ..
                }) => pending.extend([left.as_ref(), right.as_ref()]),
                _ => names.push(self.imports.resolve_callee(expr)?),
            }
        }
        let mut access = None;
        let mut write = OsOpenWrite::None;
        for name in &names {
            match name.strip_prefix("os.")? {
                "O_RDONLY" => access = access.or(Some((true, false))),
                "O_WRONLY" => access = Some((false, true)),
                "O_RDWR" => access = Some((true, true)),
                "O_APPEND" => write = OsOpenWrite::Append,
                "O_CREAT" | "O_TRUNC" | "O_EXCL" if write == OsOpenWrite::None => {
                    write = OsOpenWrite::Replace;
                }
                "O_CREAT" | "O_TRUNC" | "O_EXCL" => {}
                "O_CLOEXEC" | "O_NOFOLLOW" | "O_NONBLOCK" | "O_NOCTTY" | "O_SYNC" | "O_DSYNC"
                | "O_DIRECTORY" | "O_BINARY" | "O_NOINHERIT" => {}
                _ => return None,
            }
        }
        let (read, writes) = access.unwrap_or((true, false));
        match write {
            OsOpenWrite::None if writes => write = OsOpenWrite::Replace,
            // Appending needs a write access mode.
            OsOpenWrite::Append if !writes => write = OsOpenWrite::None,
            _ => {}
        }
        Some((read, write))
    }

    /// `os.chdir(path)` moves the rest of the program, and every child it
    /// starts, into `path`. A function summary cannot carry the target to its
    /// callers, so inside one the directory becomes unknown, and stays unknown
    /// for the walk that continues after it.
    fn os_chdir(&mut self, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        let resource = match call.args.first() {
            Some(path) if self.capture.is_none() => self.resolve_fs(path),
            _ => unresolved_resource("filesystem"),
        };
        self.cwd = match &resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path.clone()),
            _ => {
                self.opaque_boundary("os.chdir target is not statically bounded", node);
                None
            }
        };
        self.cwd_node = Some(node);
        self.chdir = Some(resource);
    }

    /// `os.exec*(file, ...)` replaces this process with `file` run on the
    /// given argv: `l` forms spell argv as trailing arguments and `v` forms
    /// as one sequence; `e` forms end with the new environment.
    /// `os.spawn*(mode, file, ...)` launches `file` the same way after a wait
    /// mode, and `os.posix_spawn[p](path, argv, env, ...)` is a `v` form.
    fn os_exec(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        let (form, args) = if let Some(form) = name.strip_prefix("os.spawn") {
            (form, call.args.get(1..).unwrap_or_default())
        } else if name.starts_with("os.posix_spawn") {
            ("v", call.args.as_slice())
        } else {
            (name.trim_start_matches("os.exec"), call.args.as_slice())
        };
        let posix_spawn = name.starts_with("os.posix_spawn");
        // posix_spawn's keywords only adjust the child's process attributes,
        // except `file_actions`, which may open, close or duplicate its files.
        // A `**mapping` may supply it unless literal keys prove it does not.
        if posix_spawn
            && call.keywords.iter().any(|keyword| match keyword.arg.as_ref() {
                Some(arg) => {
                    arg.as_str() == "file_actions"
                        && !matches!(&keyword.value, Expr::Constant(c) if c.value == Constant::None)
                }
                None => !matches!(&keyword.value, Expr::Dict(dict) if dict.keys.iter().all(|key| {
                    key.as_ref()
                        .and_then(str_literal)
                        .is_some_and(|key| key != "file_actions")
                })),
            })
        {
            self.opaque_boundary("os.posix_spawn file_actions are not modeled", node);
        }
        let environment = usize::from(form.ends_with('e'));
        let elements: Option<Vec<Expr>> = if form.starts_with('l') {
            args.get(1..args.len().saturating_sub(environment))
                .map(<[Expr]>::to_vec)
        } else {
            match args.get(1) {
                Some(Expr::List(ast::ExprList { elts, .. }))
                | Some(Expr::Tuple(ast::ExprTuple { elts, .. })) => Some(elts.clone()),
                _ => None,
            }
        };
        let (Some(file), Some(elements), true) = (
            args.first(),
            elements,
            (posix_spawn || call.keywords.is_empty())
                && !args.iter().any(|arg| matches!(arg, Expr::Starred(_))),
        ) else {
            let sequence = args
                .get(1)
                .filter(|_| form.starts_with('v'))
                .and_then(|argv| self.static_sequence(argv));
            match (args.first().and_then(str_literal), sequence) {
                (Some(program), Some(argv)) if !argv.is_empty() => {
                    let argv = program_argv(Some(&ResourceExpr::Literal { value: program }), argv);
                    self.exec_replacement(argv, false, node);
                }
                _ => {
                    self.emit_process_unresolved(node);
                    self.opaque_boundary("os.exec with non-literal argv", node);
                }
            }
            return;
        };
        if elements.is_empty() {
            // CPython refuses an empty argv before running the program.
            return;
        }
        let mut symbolic = str_literal(file).is_none();
        let program = self.resolve_process_arg(file);
        let mut argv = Vec::new();
        for (index, element) in elements.iter().enumerate() {
            match str_literal(element) {
                Some(value) => argv.push(ResourceExpr::Literal { value }),
                None => {
                    // argv[0] only matters as a multi-call binary's applet,
                    // which that binary's model bounds when it is unknown.
                    if index > 0 && (self.capture.is_none() || !matches!(element, Expr::Name(_))) {
                        symbolic = true;
                    }
                    argv.push(self.resolve_process_arg(element));
                }
            }
        }
        self.exec_replacement(program_argv(Some(&program), argv), symbolic, node);
    }

    /// The new program an `os.exec*` call runs in this process's place. Its
    /// first word is the file exec selects, not the argv[0] it is shown.
    fn exec_replacement(&mut self, argv: Vec<ResourceExpr>, symbolic: bool, node: ProvenanceRef) {
        self.defer_or_nest_exec(
            DeferredArgv::Words(argv),
            self.cwd.clone(),
            self.chdir
                .clone()
                .or_else(|| self.builder.current_execution_cwd()),
            self.cwd_node,
            node,
            symbolic,
            "os.exec argv has non-literal elements",
        );
    }

    /// `os.system("cmd")` / `os.popen("cmd")` → nested shell.
    pub(super) fn os_system(&mut self, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        let Some(first) = call.args.first() else {
            self.emit_process_unresolved(node);
            return;
        };
        if self.decoded_shell(
            first,
            None,
            self.cwd.clone(),
            self.chdir.clone(),
            self.cwd_node,
            node,
        ) {
            return;
        }
        let source = str_literal(first)
            .map(|cmd| ResourceExpr::Literal { value: cmd })
            .unwrap_or_else(|| resolve::symbolic(first, "process"));
        self.defer_or_nest_shell(
            source,
            self.cwd.clone(),
            self.chdir.clone(),
            self.cwd_node,
            node,
            None,
            "os.system with non-literal command",
        );
    }

    /// A shell command decoded from a literal runs as `/bin/sh -c`'s argument,
    /// so the shell's own code execution is where the decoded bytes land,
    /// whatever the command then does. Reports whether `command` was one.
    fn decoded_shell(
        &mut self,
        command: &Expr,
        shell: Option<ResourceExpr>,
        cwd: Option<String>,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
        node: ProvenanceRef,
    ) -> bool {
        if str_literal(command).is_some() {
            return false;
        }
        let Some(decoded) = self.decoded_literal(command) else {
            return false;
        };
        self.defer_or_nest_exec(
            DeferredArgv::Words(vec![
                shell_program(shell.as_ref()),
                ResourceExpr::Literal {
                    value: "-c".to_string(),
                },
                ResourceExpr::Literal { value: decoded },
            ]),
            cwd,
            cwd_resource,
            cwd_node,
            node,
            false,
            "decoded shell command",
        );
        true
    }

    /// `asyncio.create_subprocess_exec` and `_shell` return a coroutine that
    /// launches nothing until it is awaited or scheduled. A coroutine an
    /// expression statement discards never runs. Any other coroutine is
    /// lowered where it is made, with the arguments evaluated there; unless it
    /// is awaited or handed straight to a scheduler, it may never run, which
    /// a boundary records. The process starts in the working directory
    /// current when the coroutine runs, which is where it is made only when
    /// it runs to completion there; a scheduled coroutine may run after later
    /// statements. Where the source may change that directory in between, it
    /// is unresolved, and so is a relative `cwd=`, which joins onto it; an
    /// absolute `cwd=` does not depend on it.
    /// `create_subprocess_exec(program, *args, **kwds)` spells argv as
    /// positional arguments and hands its keywords to Popen.
    fn asyncio_subprocess(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        if self.discarded_call == Some(call.range) {
            return;
        }
        let node = self.span_node(span);
        if !self.eagerly_executes_call(call.range) {
            self.opaque_boundary(
                "asyncio subprocess coroutine is not awaited or scheduled where it is made, so it may not run",
                node,
            );
        }
        let mut ambient = None;
        let mut launch = std::borrow::Cow::Borrowed(call);
        if self.source_changes_cwd
            && !self.synchronously_executes_call(call.range)
            && !python_call_argument(call, usize::MAX, "cwd")
                .is_some_and(|cwd| self.absolute_path_literal(cwd))
        {
            ambient = Some((
                std::mem::take(&mut self.cwd),
                self.chdir.replace(unresolved_resource("filesystem")),
            ));
            // A bound value was resolved against the directory current when
            // it was bound, so any `cwd=` but an absolute literal is left to
            // the unresolved launch directory.
            launch
                .to_mut()
                .keywords
                .retain(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) != Some("cwd"));
            self.opaque_boundary(
                "asyncio subprocess coroutine may run after a working-directory change, so the directory it inherits is unresolved",
                node,
            );
        }
        let launch = launch.as_ref();
        if name.ends_with("create_subprocess_shell") {
            self.subprocess(launch, python_call_argument(launch, 0, "cmd"), true, span);
        } else {
            let argv = Expr::List(ast::ExprList {
                range: call.range,
                elts: call.args.clone(),
                ctx: ast::ExprContext::Load,
            });
            self.subprocess(launch, Some(&argv), false, span);
        }
        if let Some((cwd, chdir)) = ambient {
            self.cwd = cwd;
            self.chdir = chdir;
        }
    }

    /// An absolute path spelled in place: a string literal, or one
    /// wrapped in a `pathlib` path or `os.fsencode`.
    fn absolute_path_literal(&self, expr: &Expr) -> bool {
        let literal = match expr {
            Expr::Call(call)
                if call.keywords.is_empty()
                    && matches!(
                        self.imports.resolve_callee(&call.func).as_deref(),
                        Some(
                            "pathlib.Path"
                                | "pathlib.PurePath"
                                | "pathlib.PosixPath"
                                | "pathlib.PurePosixPath"
                                | "os.fsencode"
                        )
                    ) =>
            {
                match call.args.as_slice() {
                    [argument] => argument,
                    _ => return false,
                }
            }
            _ => expr,
        };
        str_literal(literal).is_some_and(|path| path.starts_with('/'))
    }

    /// `subprocess.run(args, shell=...)` → nested exec or shell. `args` is
    /// the call's argv or command string, and `shell` whether it runs through
    /// the shell.
    fn subprocess(
        &mut self,
        call: &ast::ExprCall,
        args: Option<&Expr>,
        shell: bool,
        span: TextRange,
    ) {
        let node = self.span_node(span);
        // `executable=` names the program that runs: the shell in place of
        // `/bin/sh` for a `shell=True` command, otherwise the program in place
        // of argv[0], which only becomes the name that program is shown.
        let executable = call
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("executable"))
            .filter(|keyword| {
                !matches!(
                    &keyword.value,
                    Expr::Constant(constant) if constant.value == Constant::None
                )
            })
            .map(|keyword| {
                str_literal(&keyword.value)
                    .map(|value| ResourceExpr::Literal { value })
                    .unwrap_or_else(|| {
                        substitute_resource_expr(
                            &resolve::symbolic(&keyword.value, "process"),
                            &self.var_scope,
                        )
                    })
            });
        let explicit_cwd = call
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("cwd"))
            .filter(|keyword| {
                !matches!(
                    &keyword.value,
                    Expr::Constant(constant) if constant.value == Constant::None
                )
            });
        let explicit_cwd_resource = explicit_cwd.map(|keyword| self.resolve_fs(&keyword.value));
        let cwd = match &explicit_cwd_resource {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path.clone()),
            Some(_) => None,
            None => self.cwd.clone(),
        };
        let cwd_resource = explicit_cwd_resource
            .clone()
            .or_else(|| self.chdir.clone())
            .or_else(|| self.builder.current_execution_cwd());
        let cwd_node = match &explicit_cwd_resource {
            Some(resource) if fs_resource_uses_cwd(resource) => self.cwd_node,
            Some(_) => None,
            None => self.cwd_node,
        };
        let Some(first) = args else {
            self.emit_process_unresolved(node);
            return;
        };
        // An `executable=` this frontend cannot resolve leaves argv[0] (or
        // `/bin/sh` for a shell command) as the conservative program below,
        // bounded because the call may run another program.
        let program = executable.as_ref().and_then(resource_command_string);
        if executable.is_some() && program.is_none() {
            self.opaque_boundary("subprocess executable= is not a literal program", node);
        }
        let program = program
            .filter(|_| !shell)
            .map(|value| ResourceExpr::Literal { value });
        // With `shell=True`, `executable=` replaces `/bin/sh`: that program
        // receives `-c` and the command string.
        let executable_program = call
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("executable"))
            .map(|keyword| &keyword.value)
            .filter(|value| {
                !matches!(value, Expr::Constant(constant) if constant.value == Constant::None)
            });
        // A shell override keeps the shell path, which resolves bound names
        // and picks the dialect; any other program just receives `-c`.
        let selects_shell = executable
            .as_ref()
            .and_then(resource_command_string)
            .is_none_or(|program| {
                matches!(
                    program.rsplit('/').next(),
                    Some("sh" | "bash" | "dash" | "zsh" | "ash" | "ksh")
                )
            });
        if shell
            && !selects_shell
            && let Some(executable) = executable_program
        {
            let program = str_literal(executable);
            let command = str_literal(first);
            let symbolic = program.is_none() || command.is_none();
            self.defer_or_nest_exec(
                DeferredArgv::Words(vec![
                    program
                        .map(|value| ResourceExpr::Literal { value })
                        .unwrap_or_else(|| resolve::symbolic(executable, "process")),
                    ResourceExpr::Literal { value: "-c".into() },
                    command
                        .map(|value| ResourceExpr::Literal { value })
                        .unwrap_or_else(|| resolve::symbolic(first, "process")),
                ]),
                cwd,
                cwd_resource,
                cwd_node,
                node,
                symbolic,
                "subprocess executable= with non-literal program or command",
            );
            return;
        }
        if shell {
            if self.decoded_shell(
                first,
                executable.clone(),
                cwd.clone(),
                cwd_resource.clone(),
                cwd_node,
                node,
            ) {
                return;
            }
            let source = str_literal(first)
                .map(|cmd| ResourceExpr::Literal { value: cmd })
                .unwrap_or_else(|| resolve::symbolic(first, "process"));
            self.defer_or_nest_shell(
                source,
                cwd,
                cwd_resource,
                cwd_node,
                node,
                executable,
                "subprocess(shell=True) with non-literal command",
            );
            return;
        }
        if let Some(words) = self.shlex_split_words(first) {
            self.defer_or_nest_exec(
                DeferredArgv::Words(program_argv(
                    program.as_ref(),
                    words
                        .into_iter()
                        .map(|word| ResourceExpr::Literal {
                            value: word.render_raw(),
                        })
                        .collect(),
                )),
                cwd,
                cwd_resource,
                cwd_node,
                node,
                false,
                "subprocess argv has non-literal elements",
            );
            return;
        }
        match first {
            Expr::List(ast::ExprList { elts, .. }) | Expr::Tuple(ast::ExprTuple { elts, .. }) => {
                let mut argv = Vec::new();
                let mut symbolic_arg = false;
                for elt in elts {
                    match str_literal(elt) {
                        Some(value) => argv.push(ResourceExpr::Literal { value }),
                        None => {
                            if self.capture.is_none() || !matches!(elt, Expr::Name(_)) {
                                symbolic_arg = true;
                            }
                            argv.push(self.resolve_process_arg(elt));
                        }
                    }
                }
                if argv.is_empty() {
                    self.emit_process_unresolved(node);
                    return;
                }
                self.defer_or_nest_exec(
                    DeferredArgv::Words(program_argv(program.as_ref(), argv)),
                    cwd,
                    cwd_resource,
                    cwd_node,
                    node,
                    symbolic_arg,
                    "subprocess argv has non-literal elements",
                );
            }
            Expr::Name(_) if self.static_sequence(first).is_some() => {
                let argv = self.static_sequence(first).unwrap();
                self.defer_or_nest_exec(
                    DeferredArgv::Words(program_argv(program.as_ref(), argv)),
                    cwd,
                    cwd_resource,
                    cwd_node,
                    node,
                    false,
                    "subprocess argv has non-literal elements",
                );
            }
            _ => match str_literal(first) {
                Some(shown) => self.defer_or_nest_exec(
                    DeferredArgv::Words(program_argv(
                        program.as_ref(),
                        vec![ResourceExpr::Literal { value: shown }],
                    )),
                    cwd,
                    cwd_resource,
                    cwd_node,
                    node,
                    false,
                    "subprocess with non-literal command",
                ),
                None if self.capture.is_some() => {
                    // argv[0] is not separable from a whole-argv value, so the
                    // named program cannot take its place.
                    if program.is_some() {
                        self.opaque_boundary(
                            "subprocess executable= with a non-literal argv",
                            node,
                        );
                    }
                    self.defer_or_nest_exec(
                        DeferredArgv::Sequence(self.resolve_process_arg(first)),
                        cwd,
                        cwd_resource,
                        cwd_node,
                        node,
                        false,
                        "subprocess with non-literal command",
                    )
                }
                None => {
                    self.emit_process_unresolved(node);
                    self.opaque_boundary("subprocess with non-literal command", node);
                }
            },
        }
    }

    fn shlex_split_words(&self, expr: &Expr) -> Option<Vec<Word>> {
        let Expr::Call(call) = expr else {
            return None;
        };
        let canon = self.imports.resolve_callee(&call.func)?;
        if canon != "shlex.split" {
            return None;
        }
        let cmd = call.args.first().and_then(str_literal)?;
        crate::shell::split_literal_words(&cmd)
    }

    /// A module-level HTTP call (`requests.get`, `httpx.post`,
    /// `urllib.request.urlopen`, ...). The verb is the method segment of the
    /// canonical name; for `.request(method, url)` the URL is the second
    /// argument and the verb the first literal argument.
    fn network(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        if name == "urllib.request.urlopen"
            && let Some(argument) = call.args.first()
            && let Some(ModeledValue::Request { url, upload }) = self.modeled_value(argument)
        {
            let body = python_call_argument(call, 1, "data")
                .is_some_and(|arg| !matches!(arg, Expr::Constant(c) if c.value == Constant::None));
            let node = self.span_node(span);
            self.emit(
                if upload || body {
                    "network.upload"
                } else {
                    "network.request"
                },
                url,
                &[],
                node,
            );
            return;
        }
        let method = name.rsplit('.').next().unwrap_or(name);
        let (url_expr, verb) = if method == "request" {
            (call.args.get(1), call.args.first().and_then(str_literal))
        } else {
            (call.args.first(), None)
        };
        let resource = url_expr
            .map(|a| self.resolve_net(a))
            .unwrap_or_else(|| unresolved_resource("network"));
        let node = self.span_node(span);
        let operation = if name == "urllib.request.urlopen"
            && python_call_argument(call, 1, "data")
                .is_some_and(|arg| !matches!(arg, Expr::Constant(c) if c.value == Constant::None))
        {
            "network.upload"
        } else {
            net_op(verb.as_deref().unwrap_or(method))
        };
        self.emit(operation, resource, &[], node);
    }

    /// `urllib.request.urlretrieve(url, filename)` downloads `url` and writes it
    /// to `filename`; both endpoints are recorded when literal, and the file
    /// holds exactly the downloaded bytes for whatever later reads it.
    fn urlretrieve(&mut self, call: &ast::ExprCall, span: TextRange) {
        let url = call
            .args
            .first()
            .map(|a| self.resolve_net(a))
            .unwrap_or_else(|| unresolved_resource("network"));
        let node = self.span_node(span);
        let download = self.emit("network.download", url, &[], node);
        if let Some(dest) = call.args.get(1) {
            let resource = self.resolve_fs(dest);
            let destination = self.emit("filesystem.write", resource, &[], node);
            self.record_exact_transfer(download, destination);
        }
    }

    /// Resolve a receiver expression to the network object it evaluates to: a
    /// constructor call (`requests.Session()`), or a name bound to one.
    pub(super) fn net_receiver(&self, expr: &Expr) -> Option<Receiver> {
        match expr {
            Expr::Call(inner) => {
                if let Some(canon) = self.imports.resolve_callee(&inner.func)
                    && let Some(kind) = constructor_kind(&canon)
                {
                    let kind = if kind == ReceiverKind::Socket
                        && inner
                            .args
                            .first()
                            .or_else(|| {
                                inner.keywords.iter().find_map(|keyword| {
                                    (keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("family"))
                                        .then_some(&keyword.value)
                                })
                            })
                            .and_then(|family| self.imports.resolve_callee(family))
                            .as_deref()
                            == Some("socket.AF_UNIX")
                    {
                        ReceiverKind::UnixSocket
                    } else {
                        kind
                    };
                    let host = match kind {
                        // An HTTP(S)Connection fixes its host (and optional port)
                        // at construction; clients and sockets carry it per-call.
                        ReceiverKind::HttpConnection => self.conn_host(inner),
                        _ => unresolved_resource("network"),
                    };
                    return Some(Receiver { kind, host });
                }
                // A call into a local helper that returns a constructed network
                // object (`s = build_requests_session()`): adopt its return kind.
                // The endpoint is carried per-call, so the host stays unresolved.
                if let Expr::Name(n) = inner.func.as_ref()
                    && let Some(kind) = self.return_receivers.get(n.id.as_str()).copied()
                {
                    return Some(Receiver {
                        kind,
                        host: unresolved_resource("network"),
                    });
                }
                None
            }
            Expr::Name(n) => self.sessions.get(n.id.as_str()).cloned(),
            _ => None,
        }
    }

    /// The network-object kind the function returns, when every `return` yields
    /// the same constructed receiver (a `requests.Session()`, a local bound to
    /// one, or a call into another helper that returns one). Conservative: a
    /// bare `return`, no returns, or disagreeing kinds yield None.
    pub(super) fn infer_return_receiver(&self, body: &[Stmt]) -> Option<ReceiverKind> {
        let mut values = Vec::new();
        let mut saw_bare = false;
        collect_returns(body, &mut values, &mut saw_bare);
        if saw_bare || values.is_empty() {
            return None;
        }
        let first = self.net_receiver(values[0]).map(|r| r.kind)?;
        values[1..]
            .iter()
            .all(|v| self.net_receiver(v).map(|r| r.kind) == Some(first))
            .then_some(first)
    }

    /// The endpoint of an `HTTPConnection(host, port)` constructor.
    fn conn_host(&self, ctor: &ast::ExprCall) -> ResourceExpr {
        match ctor.args.first().and_then(str_literal) {
            Some(host) => host_endpoint(&host, ctor.args.get(1).and_then(int_literal)),
            None => unresolved_resource("network"),
        }
    }

    /// A method call on a constructed network object.
    fn net_method(&mut self, recv: &Receiver, method: &str, call: &ast::ExprCall, span: TextRange) {
        let node = self.span_node(span);
        match recv.kind {
            ReceiverKind::HttpClient => match method {
                "get" | "post" | "put" | "delete" | "patch" | "head" | "options" => {
                    let resource = call
                        .args
                        .first()
                        .map(|a| self.resolve_net(a))
                        .unwrap_or_else(|| unresolved_resource("network"));
                    self.emit(net_op(method), resource, &[], node);
                }
                "request" | "send" | "stream" => {
                    let resource = call
                        .args
                        .get(1)
                        .map(|a| self.resolve_net(a))
                        .unwrap_or_else(|| unresolved_resource("network"));
                    let verb = call.args.first().and_then(str_literal);
                    self.emit(
                        net_op(verb.as_deref().unwrap_or("request")),
                        resource,
                        &[],
                        node,
                    );
                }
                _ => {}
            },
            ReceiverKind::HttpConnection => {
                if method == "request" {
                    let verb = call.args.first().and_then(str_literal);
                    self.emit(
                        net_op(verb.as_deref().unwrap_or("request")),
                        recv.host.clone(),
                        &[],
                        node,
                    );
                }
            }
            ReceiverKind::Socket => {
                if method == "connect" {
                    let resource = call
                        .args
                        .first()
                        .map(|a| self.socket_addr(a))
                        .unwrap_or_else(|| unresolved_resource("network"));
                    self.emit("network.request", resource, &[], node);
                }
            }
            ReceiverKind::UnixSocket => {
                if method == "connect" {
                    let resource = call
                        .args
                        .first()
                        .and_then(str_literal)
                        .map(|path| ResourceExpr::Concrete {
                            identity: ResourceIdentity::NetworkEndpoint {
                                host: path,
                                scheme: Some("unix".to_string()),
                                port: None,
                                path: None,
                            },
                        })
                        .unwrap_or_else(|| unresolved_resource("network"));
                    self.emit("network.request", resource, &[], node);
                }
            }
            ReceiverKind::EventLoop => match method {
                "create_connection" | "create_unix_connection" => {
                    self.emit("network.request", unresolved_resource("network"), &[], node);
                }
                "create_server" | "create_unix_server" | "create_datagram_endpoint" => {
                    self.emit("network.listen", unresolved_resource("network"), &[], node);
                }
                _ => {}
            },
        }
    }

    /// The endpoint of a `socket.connect((host, port))` address tuple.
    fn socket_addr(&self, arg: &Expr) -> ResourceExpr {
        if let Expr::Tuple(t) = arg
            && let Some(host) = t.elts.first().and_then(str_literal)
        {
            return host_endpoint(&host, t.elts.get(1).and_then(int_literal));
        }
        self.resolve_net(arg)
    }

    fn opaque_call(&mut self, name: &str, span: TextRange) {
        let node = self.span_node(span);
        self.opaque_boundary(&format!("dynamic call: {name}"), node);
    }
}

fn pathlib_glob_pattern(path: &str, glob: &str, recursive: bool) -> String {
    let root = crate::paths::escape_fs_glob_path(path.trim_end_matches('/'));
    if effinterp_proto::validate_glob(glob).is_err() {
        if !recursive && let Some((prefix, _)) = effinterp_proto::glob_parent_prefix(glob) {
            let prefix = crate::paths::normalize_path(&format!("{path}/{prefix}"));
            return format!(
                "{}/**",
                crate::paths::escape_fs_glob_path(prefix.trim_end_matches('/'))
            );
        }
        // Recursive searches traverse ** before the operand's parent segments;
        // keep that unsupported traversal visible to resource validation.
        return if recursive {
            format!("{root}/**/{glob}")
        } else {
            format!("{root}/{glob}")
        };
    }
    // Pathlib wildcards include hidden names. The shared segment wildcards do
    // not, so retain all descendants as a conservative set for these calls.
    if glob.contains(['*', '?', '[']) {
        format!("{root}/**")
    } else {
        let literal = crate::paths::escape_fs_glob_path(glob);
        if recursive {
            format!("{root}/**/{literal}")
        } else {
            format!("{root}/{literal}")
        }
    }
}

/// How an `os.open` descriptor writes: not at all, from the start of the
/// file, or only at its end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OsOpenWrite {
    None,
    Replace,
    Append,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExactValue {
    Text,
    Bytes,
    Number,
    Data,
    Sequence,
    BuiltinType,
    BuiltinCallable,
}

/// Decode base64 the way CPython's non-validating `b64decode` does: characters
/// outside the alphabet are discarded, and the data must be complete or
/// completed by exactly its padding. `urlsafe` first maps `-`/`_` to `+`/`/`.
fn decode_base64(encoded: &[u8], urlsafe: bool) -> Option<Vec<u8>> {
    let mut sextets = Vec::new();
    let mut padding = 0;
    for &byte in encoded {
        let byte = match byte {
            b'-' if urlsafe => b'+',
            b'_' if urlsafe => b'/',
            byte => byte,
        };
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            _ => continue,
        };
        if padding > 0 {
            return None;
        }
        sextets.push(value);
    }
    let complete = match sextets.len() % 4 {
        0 => padding == 0,
        2 => padding == 2,
        3 => padding == 1,
        _ => false,
    };
    if !complete {
        return None;
    }
    let mut decoded = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        let bits = chunk
            .iter()
            .fold(0u32, |bits, &sextet| (bits << 6) | u32::from(sextet))
            << (6 * (4 - chunk.len()));
        decoded.extend_from_slice(&bits.to_be_bytes()[1..chunk.len()]);
    }
    Some(decoded)
}

// Signature and operand checks are deliberately separate from import identity.
fn supported_signature(call: &ast::ExprCall, min: usize, max: usize, keywords: &[&str]) -> bool {
    let mut seen = std::collections::HashSet::new();
    (min..=max).contains(&call.args.len())
        && !call.args.iter().any(|arg| matches!(arg, Expr::Starred(_)))
        && call.keywords.iter().all(|kw| {
            kw.arg
                .as_ref()
                .is_some_and(|name| keywords.contains(&name.as_str()) && seen.insert(name.as_str()))
        })
}

impl PythonWalker<'_, '_> {
    fn exact_value(&self, expr: &Expr, depth: usize) -> Option<ExactValue> {
        if depth > 32 {
            return None;
        }
        let next = |expr: &Expr| self.exact_value(expr, depth + 1);
        match expr {
            Expr::Constant(c) => Some(match c.value {
                Constant::Str(_) => ExactValue::Text,
                Constant::Bytes(_) => ExactValue::Bytes,
                Constant::Int(_)
                | Constant::Float(_)
                | Constant::Bool(_)
                | Constant::Complex { .. } => ExactValue::Number,
                _ => ExactValue::Data,
            }),
            Expr::Name(name) => {
                if let Some(value) = self.modeled_values.get(name.id.as_str()) {
                    return match value {
                        ModeledValue::Text => Some(ExactValue::Text),
                        ModeledValue::Bytes => Some(ExactValue::Bytes),
                        ModeledValue::Number => Some(ExactValue::Number),
                        ModeledValue::BuiltinData => Some(ExactValue::Data),
                        ModeledValue::Temporary { kind, .. } if kind == "tempfile.mkdtemp" => {
                            Some(ExactValue::Text)
                        }
                        _ => None,
                    };
                }
                if self.widened_vars.contains(name.id.as_str())
                    || self.path_vars.contains(name.id.as_str())
                {
                    return None;
                }
                if matches!(
                    self.var_scope.get(name.id.as_str()),
                    Some(ResourceExpr::Literal { .. })
                ) {
                    return Some(ExactValue::Text);
                }
                self.imports
                    .resolve_callee(expr)
                    .filter(|name| {
                        matches!(
                            name.as_str(),
                            "str"
                                | "bytes"
                                | "int"
                                | "float"
                                | "bool"
                                | "list"
                                | "dict"
                                | "tuple"
                                | "set"
                                | "frozenset"
                                | "object"
                                | "type"
                        )
                    })
                    .map(|_| ExactValue::BuiltinType)
            }
            Expr::List(list) => list
                .elts
                .iter()
                .all(|e| next(e).is_some())
                .then_some(ExactValue::Sequence),
            Expr::Tuple(tuple) => tuple
                .elts
                .iter()
                .all(|e| next(e).is_some())
                .then_some(ExactValue::Sequence),
            Expr::Set(set) => set
                .elts
                .iter()
                .all(|e| next(e).is_some())
                .then_some(ExactValue::Sequence),
            Expr::Dict(dict) => (dict
                .keys
                .iter()
                .all(|e| e.as_ref().is_some_and(|e| next(e).is_some()))
                && dict.values.iter().all(|e| next(e).is_some()))
            .then_some(ExactValue::Data),
            Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
                let left = next(&binary.left)?;
                (Some(left) == next(&binary.right)
                    && matches!(
                        left,
                        ExactValue::Text | ExactValue::Bytes | ExactValue::Number
                    ))
                .then_some(left)
            }
            Expr::Call(call) => {
                if self.static_getattr_target(call).is_some() {
                    return Some(ExactValue::BuiltinCallable);
                }
                // A base64 decoder returns a new `bytes` object or raises,
                // whatever its operand is.
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "base64.b64decode"
                            | "base64.standard_b64decode"
                            | "base64.urlsafe_b64decode"
                    )
                }) {
                    return Some(ExactValue::Bytes);
                }
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "os.remove"
                            | "os.unlink"
                            | "os.rmdir"
                            | "os.mkdir"
                            | "os.makedirs"
                            | "os.rename"
                            | "os.replace"
                            | "os.chmod"
                            | "os.chown"
                            | "os.truncate"
                    )
                }) && call
                    .args
                    .iter()
                    .chain(call.keywords.iter().map(|keyword| &keyword.value))
                    .all(|argument| next(argument).is_some())
                {
                    return Some(ExactValue::Data);
                }
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(name.as_str(), "os.path.expanduser" | "os.path.expandvars")
                }) && self
                    .modeled_path(expr)
                    .is_some_and(|resource| !matches!(resource, ResourceExpr::Unresolved { .. }))
                {
                    return Some(ExactValue::Text);
                }
                if let Expr::Attribute(attr) = call.func.as_ref() {
                    if matches!(attr.attr.as_str(), "read" | "readline")
                        && supported_signature(call, 0, 1, &[])
                        && self.modeled_value(&attr.value) == Some(ModeledValue::FileContext)
                    {
                        return Some(ExactValue::Data);
                    }
                    // Constructor evidence is required; an annotation is not an exact runtime type.
                    if self.exact_path_receiver(&attr.value, depth + 1) {
                        if attr.attr.as_str() == "read_bytes"
                            && supported_signature(call, 0, 0, &[])
                        {
                            return Some(ExactValue::Bytes);
                        }
                        if attr.attr.as_str() == "read_text"
                            && supported_signature(call, 0, 0, &["encoding", "errors"])
                            && self.safe_codec(call)
                        {
                            return Some(ExactValue::Text);
                        }
                    }
                    if let Some(result) = self.safe_method_result(call, depth + 1) {
                        return Some(result);
                    }
                }
                if !self.safe_call_at(call, depth + 1) {
                    return None;
                }
                let name = self.imports.resolve_callee(&call.func)?;
                if matches!(
                    name.as_str(),
                    "re.escape"
                        | "os.fspath"
                        | "os.path.join"
                        | "os.path.dirname"
                        | "os.path.basename"
                        | "os.path.normpath"
                        | "os.path.abspath"
                        | "os.path.relpath"
                ) {
                    return call.args.first().and_then(next);
                }
                Some(match name.as_str() {
                    "str" | "repr" | "format" | "chr" | "json.dumps" | "time.strftime"
                    | "os.getcwd" => ExactValue::Text,
                    "bytes" => ExactValue::Bytes,
                    "list" | "tuple" | "set" | "frozenset" | "sorted" | "range" | "zip"
                    | "enumerate" | "reversed" | "iter" => ExactValue::Sequence,
                    "int" | "float" | "bool" | "len" | "abs" | "round" | "sum" | "hash" | "id"
                    | "ord" | "pow" | "time.time" | "time.monotonic" | "time.perf_counter" => {
                        ExactValue::Number
                    }
                    "dict" | "json.loads" => ExactValue::Data,
                    _ => return None,
                })
            }
            _ => None,
        }
    }

    fn exact_path_receiver(&self, expr: &Expr, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        match expr {
            Expr::Name(name) => {
                self.modeled_values.get(name.id.as_str()) == Some(&ModeledValue::Path)
            }
            Expr::Call(call) => self
                .imports
                .resolve_callee(&call.func)
                .is_some_and(|name| matches!(name.as_str(), "pathlib.Path" | "pathlib.PosixPath")),
            _ => false,
        }
    }

    fn safe_codec(&self, call: &ast::ExprCall) -> bool {
        call.args.iter().enumerate().all(|(i, arg)| {
            str_literal(arg).is_some_and(|s| {
                if i == 0 {
                    matches!(s.as_str(), "utf-8" | "utf8" | "ascii" | "latin-1")
                } else {
                    matches!(s.as_str(), "strict" | "ignore" | "replace")
                }
            })
        }) && call.keywords.iter().all(|kw| {
            str_literal(&kw.value).is_some_and(|s| match kw.arg.as_ref().map(|s| s.as_str()) {
                Some("encoding") => matches!(s.as_str(), "utf-8" | "utf8" | "ascii" | "latin-1"),
                Some("errors") => matches!(s.as_str(), "strict" | "ignore" | "replace"),
                _ => false,
            })
        })
    }

    fn safe_method_result(&self, call: &ast::ExprCall, depth: usize) -> Option<ExactValue> {
        if depth > 32 {
            return None;
        }
        let Expr::Attribute(attr) = call.func.as_ref() else {
            return None;
        };
        let receiver = self.exact_value(&attr.value, depth + 1)?;
        if !matches!(receiver, ExactValue::Text | ExactValue::Bytes) {
            return None;
        }
        let same = |arg: &Expr| self.exact_value(arg, depth + 1) == Some(receiver);
        match attr.attr.as_str() {
            "strip" | "lstrip" | "rstrip"
                if supported_signature(call, 0, 1, &[]) && call.args.iter().all(same) =>
            {
                Some(receiver)
            }
            "replace"
                if supported_signature(call, 2, 3, &[])
                    && call.args[..2].iter().all(same)
                    && call.args.get(2).is_none_or(|a| {
                        self.exact_value(a, depth + 1) == Some(ExactValue::Number)
                    }) =>
            {
                Some(receiver)
            }
            "splitlines"
                if supported_signature(call, 0, 1, &["keepends"])
                    && call
                        .args
                        .iter()
                        .chain(call.keywords.iter().map(|kw| &kw.value))
                        .all(|a| self.exact_value(a, depth + 1) == Some(ExactValue::Number)) =>
            {
                Some(ExactValue::Sequence)
            }
            "decode"
                if receiver == ExactValue::Bytes
                    && supported_signature(call, 0, 2, &["encoding", "errors"])
                    && self.safe_codec(call) =>
            {
                Some(ExactValue::Text)
            }
            _ => None,
        }
    }

    pub(super) fn safe_python_method(&self, call: &ast::ExprCall) -> bool {
        self.safe_method_result(call, 0).is_some()
    }

    pub(super) fn python_operands_safe(&self, call: &ast::ExprCall) -> bool {
        call.args
            .iter()
            .chain(call.keywords.iter().map(|kw| &kw.value))
            .all(|arg| self.exact_value(arg, 0).is_some())
    }

    pub(super) fn safe_python_call(&self, call: &ast::ExprCall) -> bool {
        self.safe_call_at(call, 0)
    }

    fn static_getattr_target(&self, call: &ast::ExprCall) -> Option<String> {
        if call.args.len() != 2
            || !call.keywords.is_empty()
            || self.imports.resolve_callee(&call.func).as_deref() != Some("getattr")
        {
            return None;
        }
        let target = self.imports.resolve_callee(&Expr::Call(call.clone()))?;
        matches!(
            target.as_str(),
            "os.remove"
                | "os.unlink"
                | "os.rmdir"
                | "os.mkdir"
                | "os.makedirs"
                | "os.rename"
                | "os.replace"
                | "os.chmod"
                | "os.chown"
                | "os.truncate"
        )
        .then_some(target)
    }

    fn safe_call_at(&self, call: &ast::ExprCall, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        let Some(name) = self.imports.resolve_callee(&call.func) else {
            return false;
        };
        let name = name.strip_prefix("builtins.").unwrap_or(&name);
        let positional: &[&str] = match name {
            "re.compile" => &["pattern", "flags"],
            "re.search" | "re.match" | "re.fullmatch" => &["pattern", "string", "flags"],
            "logging.getLogger" => &["name"],
            _ => &[],
        };
        if call.keywords.iter().any(|kw| {
            kw.arg.as_ref().is_some_and(|key| {
                positional
                    .iter()
                    .take(call.args.len())
                    .any(|name| *name == key.as_str())
            })
        }) {
            return false;
        }
        let signature = |min, max, keywords: &[&str]| supported_signature(call, min, max, keywords);
        let value = |arg: &Expr| self.exact_value(arg, depth + 1);
        let safe = || {
            call.args
                .iter()
                .chain(call.keywords.iter().map(|kw| &kw.value))
                .all(|arg| value(arg).is_some())
        };
        let text = || {
            call.args
                .iter()
                .all(|arg| matches!(value(arg), Some(ExactValue::Text | ExactValue::Bytes)))
        };
        match name {
            "print" => {
                signature(0, usize::MAX, &["sep", "end", "file", "flush"])
                    && (call
                        .keywords
                        .iter()
                        .any(|kw| kw.arg.as_deref() == Some("file"))
                        || self.imports.ordinary_stdout())
                    && call.args.iter().all(|arg| value(arg).is_some())
                    && call
                        .keywords
                        .iter()
                        .all(|kw| match kw.arg.as_ref().map(|n| n.as_str()) {
                            Some("file") => {
                                self.imports.resolve_callee(&kw.value).is_some_and(|name| {
                                    matches!(name.as_str(), "sys.stdout" | "sys.stderr")
                                })
                            }
                            Some("sep" | "end") => value(&kw.value) == Some(ExactValue::Text),
                            Some("flush") => value(&kw.value) == Some(ExactValue::Number),
                            _ => false,
                        })
            }
            "len" | "repr" | "hash" | "id" | "iter" | "reversed" | "any" | "all" | "abs"
            | "chr" | "ord" | "callable" => signature(1, 1, &[]) && safe(),
            "str" | "int" | "float" | "bool" | "list" | "set" | "frozenset" | "tuple" => {
                signature(0, 1, &[]) && safe()
            }
            "dict" => {
                call.args.len() <= 1
                    && !call.args.iter().any(|arg| matches!(arg, Expr::Starred(_)))
                    && call.keywords.iter().all(|keyword| keyword.arg.is_some())
                    && safe()
            }
            "getattr" => self.static_getattr_target(call).is_some(),
            "bytes" | "bytearray" => signature(0, 1, &[]) && safe(),
            "sorted" => signature(1, 1, &["reverse"]) && safe(),
            "enumerate" | "round" | "sum" | "format" | "next" => signature(1, 2, &[]) && safe(),
            "range" | "slice" => signature(1, 3, &[]) && safe(),
            "min" | "max" => signature(1, usize::MAX, &[]) && safe(),
            "zip" => signature(0, usize::MAX, &["strict"]) && safe(),
            "divmod" | "hasattr" => signature(2, 2, &[]) && safe(),
            "pow" => signature(2, 3, &[]) && safe(),
            "type" => signature(1, 1, &[]) && safe(),
            "object" => signature(0, 0, &[]),
            "isinstance" | "issubclass" => {
                signature(2, 2, &[])
                    && safe()
                    && value(&call.args[1]) == Some(ExactValue::BuiltinType)
            }
            "os.path.join" => signature(1, usize::MAX, &[]) && text(),
            "os.fspath" | "os.path.dirname" | "os.path.basename" | "os.path.split"
            | "os.path.splitext" | "os.path.normpath" | "os.path.abspath" | "os.path.isabs" => {
                signature(1, 1, &[]) && text()
            }
            "os.path.relpath" => signature(1, 2, &[]) && text(),
            "os.getcwd" | "os.getpid" | "os.getuid" | "os.geteuid" | "os.cpu_count"
            | "time.time" | "time.monotonic" | "time.perf_counter" => signature(0, 0, &[]),
            "json.dumps" => {
                signature(
                    1,
                    1,
                    &[
                        "skipkeys",
                        "ensure_ascii",
                        "check_circular",
                        "allow_nan",
                        "indent",
                        "separators",
                        "sort_keys",
                    ],
                ) && safe()
            }
            "json.loads" => signature(1, 1, &[]) && text(),
            "re.compile" => {
                signature(1, 2, &["flags"])
                    && matches!(
                        call.args.first().and_then(value),
                        Some(ExactValue::Text | ExactValue::Bytes)
                    )
                    && safe()
            }
            "re.search" | "re.match" | "re.fullmatch" => {
                signature(2, 3, &["flags"])
                    && call.args[..2]
                        .iter()
                        .all(|arg| matches!(value(arg), Some(ExactValue::Text | ExactValue::Bytes)))
                    && safe()
            }
            "re.escape" => signature(1, 1, &[]) && text(),
            "time.sleep" => signature(1, 1, &[]) && safe(),
            "time.strftime" => signature(1, 2, &[]) && safe(),
            "logging.getLogger" => signature(0, 1, &["name"]) && safe(),
            "argparse.ArgumentParser" => {
                signature(
                    0,
                    0,
                    &[
                        "prog",
                        "usage",
                        "description",
                        "epilog",
                        "prefix_chars",
                        "fromfile_prefix_chars",
                        "argument_default",
                        "conflict_handler",
                        "add_help",
                        "allow_abbrev",
                        "exit_on_error",
                    ],
                ) && safe()
            }
            "sys.path.append" => signature(1, 1, &[]) && text(),
            "sys.path.insert" => {
                signature(2, 2, &[])
                    && value(&call.args[0]) == Some(ExactValue::Number)
                    && value(&call.args[1]) == Some(ExactValue::Text)
            }
            "http.client.HTTPConnection"
            | "http.client.HTTPSConnection"
            | "httpx.Client"
            | "httpx.AsyncClient"
            | "requests.Session" => signature(0, 2, &[]) && safe(),
            "sys.exit" => signature(0, 1, &[]) && safe(),
            _ => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum ModeledValue {
    Text,
    Bytes,
    Path,
    FileContext,
    HttpResponse,
    EntryPoints,
    Number,
    BuiltinData,
    Request {
        url: ResourceExpr,
        upload: bool,
    },
    Temporary {
        resource: ResourceExpr,
        kind: String,
    },
}

impl PythonWalker<'_, '_> {
    pub(super) fn modeled_value(&self, expr: &Expr) -> Option<ModeledValue> {
        if let Expr::Constant(c) = expr {
            return match c.value {
                Constant::Bytes(_) => Some(ModeledValue::Bytes),
                Constant::Int(_) | Constant::Float(_) | Constant::Bool(_) => {
                    Some(ModeledValue::Number)
                }
                _ => None,
            };
        }
        if let Expr::Name(name) = expr {
            return self.modeled_values.get(name.id.as_str()).cloned();
        }
        let Expr::Call(call) = expr else {
            return self.exact_value(expr, 0).and_then(|value| {
                matches!(value, ExactValue::Data | ExactValue::Sequence)
                    .then_some(ModeledValue::BuiltinData)
            });
        };
        if let Some(name) = self.imports.resolve_callee(&call.func) {
            if matches!(name.as_str(), "open" | "io.open") {
                return Some(ModeledValue::FileContext);
            }
            if name == "importlib.metadata.entry_points" {
                return Some(ModeledValue::EntryPoints);
            }
            if name == "urllib.request.urlopen" {
                return Some(ModeledValue::HttpResponse);
            }
            if matches!(name.as_str(), "pathlib.Path" | "pathlib.PosixPath") {
                return Some(ModeledValue::Path);
            }
            if name == "urllib.request.Request" {
                if !supported_signature(
                    call,
                    1,
                    6,
                    &[
                        "data",
                        "headers",
                        "origin_req_host",
                        "unverifiable",
                        "method",
                    ],
                ) || self.exact_value(&call.args[0], 0) != Some(ExactValue::Text)
                    || !call
                        .args
                        .iter()
                        .chain(call.keywords.iter().map(|kw| &kw.value))
                        .all(|arg| self.exact_value(arg, 0).is_some())
                {
                    return None;
                }
                let data = python_call_argument(call, 1, "data");
                let has_body = data.is_some_and(
                    |arg| !matches!(arg, Expr::Constant(c) if c.value == Constant::None),
                );
                let method = python_call_argument(call, 5, "method");
                let upload = if let Some(method) = method {
                    net_op(&str_literal(method)?) == "network.upload" || has_body
                } else {
                    has_body
                };
                let url = self.resolve_net(&call.args[0]);
                if matches!(url, ResourceExpr::Unresolved { .. }) {
                    return None;
                }
                return Some(ModeledValue::Request { url, upload });
            }
            if matches!(
                name.as_str(),
                "tempfile.mkdtemp"
                    | "tempfile.mkstemp"
                    | "tempfile.TemporaryDirectory"
                    | "tempfile.NamedTemporaryFile"
            ) {
                let resource = self.temporary_resource(call, &name)?;
                return Some(ModeledValue::Temporary {
                    resource,
                    kind: name,
                });
            }
        }
        match self.exact_value(expr, 0)? {
            ExactValue::Text => Some(ModeledValue::Text),
            ExactValue::Bytes => Some(ModeledValue::Bytes),
            ExactValue::Number => Some(ModeledValue::Number),
            ExactValue::Data | ExactValue::Sequence => Some(ModeledValue::BuiltinData),
            _ => None,
        }
    }

    fn temporary_resource(&self, call: &ast::ExprCall, name: &str) -> Option<ResourceExpr> {
        let named = name == "tempfile.NamedTemporaryFile";
        let (suffix_index, prefix_index, dir_index) = if named { (4, 5, 6) } else { (0, 1, 2) };
        let (max, keywords, positional): (usize, &[&str], &[&str]) = match name {
            "tempfile.mkdtemp" => (
                3,
                &["suffix", "prefix", "dir"],
                &["suffix", "prefix", "dir"],
            ),
            "tempfile.mkstemp" => (
                4,
                &["suffix", "prefix", "dir", "text"],
                &["suffix", "prefix", "dir", "text"],
            ),
            "tempfile.TemporaryDirectory" => (
                3,
                &["suffix", "prefix", "dir", "ignore_cleanup_errors", "delete"],
                &["suffix", "prefix", "dir"],
            ),
            "tempfile.NamedTemporaryFile" => (
                8,
                &[
                    "mode",
                    "buffering",
                    "encoding",
                    "newline",
                    "suffix",
                    "prefix",
                    "dir",
                    "delete",
                    "errors",
                    "delete_on_close",
                ],
                &[
                    "mode",
                    "buffering",
                    "encoding",
                    "newline",
                    "suffix",
                    "prefix",
                    "dir",
                    "delete",
                ],
            ),
            _ => return None,
        };
        if !supported_signature(call, 0, max, keywords)
            || call.keywords.iter().any(|kw| {
                kw.arg
                    .as_ref()
                    .is_some_and(|key| positional[..call.args.len()].contains(&key.as_str()))
            })
        {
            return None;
        }
        if named
            && let Some(mode) = python_call_argument(call, 0, "mode")
            && !str_literal(mode).is_some_and(|mode| {
                matches!(
                    mode.as_str(),
                    "r" | "rb"
                        | "r+"
                        | "r+b"
                        | "rb+"
                        | "w"
                        | "wb"
                        | "w+"
                        | "w+b"
                        | "wb+"
                        | "a"
                        | "ab"
                        | "a+"
                        | "a+b"
                        | "ab+"
                        | "x"
                        | "xb"
                        | "x+"
                        | "x+b"
                        | "xb+"
                )
            })
        {
            return None;
        }
        if !call
            .args
            .iter()
            .chain(call.keywords.iter().map(|kw| &kw.value))
            .all(|arg| self.exact_value(arg, 0).is_some())
        {
            return None;
        }
        let literal = |index, key, default: &str| -> Option<String> {
            python_call_argument(call, index, key)
                .map(str_literal)
                .unwrap_or_else(|| Some(default.to_string()))
        };
        let prefix = literal(prefix_index, "prefix", "tmp")?;
        let suffix = literal(suffix_index, "suffix", "")?;
        // Keep only a bounded name component; metacharacters must not widen a generated name.
        if prefix
            .chars()
            .chain(suffix.chars())
            .any(|c| matches!(c, '/' | '*' | '?' | '[' | ']'))
        {
            return None;
        }
        let root = python_call_argument(call, dir_index, "dir")
            .map(|arg| self.resolve_fs(arg))
            .unwrap_or_else(|| ResourceExpr::Environment {
                name: "TMPDIR".into(),
            });
        let pattern = ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: format!("{prefix}*{suffix}"),
            },
        };
        Some(ResourceExpr::Join {
            parts: vec![root, pattern],
        })
    }

    pub(super) fn modeled_path(&self, expr: &Expr) -> Option<ResourceExpr> {
        if let Expr::Name(name) = expr
            && matches!(self.modeled_values.get(name.id.as_str()), Some(ModeledValue::Temporary { kind, .. }) if kind != "tempfile.mkdtemp")
        {
            return Some(unresolved_resource("filesystem"));
        }
        if let Expr::Call(call) = expr {
            let name = self.imports.resolve_callee(&call.func)?;
            if matches!(name.as_str(), "os.path.expanduser" | "os.path.expandvars")
                && supported_signature(call, 1, 1, &[])
            {
                let raw = match &call.args[0] {
                    Expr::Name(name) => match self.var_scope.get(name.id.as_str())? {
                        ResourceExpr::Literal { value } => value.clone(),
                        _ => return None,
                    },
                    arg => str_literal(arg)?,
                };
                return if name == "os.path.expanduser" {
                    Some(resolve::expanduser_resource(ResourceExpr::Literal {
                        value: raw,
                    }))
                } else {
                    resolve::expandvars_resource(&raw)
                };
            }
            if name == "tempfile.mkdtemp" {
                return self.temporary_resource(call, &name);
            }
        }
        if let Expr::Subscript(subscript) = expr
            && int_literal(&subscript.slice) == Some(1)
            && let Some(ModeledValue::Temporary { resource, kind }) =
                self.modeled_value(&subscript.value)
            && kind == "tempfile.mkstemp"
        {
            return Some(resource);
        }
        if let Expr::Attribute(attr) = expr
            && attr.attr.as_str() == "name"
            && let Some(ModeledValue::Temporary { resource, kind }) =
                self.modeled_value(&attr.value)
            && matches!(
                kind.as_str(),
                "tempfile.NamedTemporaryFile" | "tempfile.TemporaryDirectory"
            )
        {
            return Some(resource);
        }
        None
    }

    pub(super) fn temporary_context_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        match self.modeled_value(expr)? {
            ModeledValue::Temporary { resource, kind } if kind == "tempfile.TemporaryDirectory" => {
                Some(resource)
            }
            _ => None,
        }
    }

    pub(super) fn modeled_context(&self, expr: &Expr) -> bool {
        if matches!(
            self.modeled_value(expr),
            Some(ModeledValue::FileContext | ModeledValue::HttpResponse)
        ) {
            return true;
        }
        let Expr::Call(call) = expr else {
            return false;
        };
        if let Expr::Attribute(attr) = call.func.as_ref() {
            return attr.attr.as_str() == "open" && self.exact_path_receiver(&attr.value, 0);
        }
        false
    }

    fn stdlib_resource_call(&mut self, call: &ast::ExprCall, name: &str, span: TextRange) -> bool {
        let node = self.span_node(span);
        match name {
            "os.path.expanduser" | "os.path.expandvars" => {
                let Some(resource) = self.modeled_path(&Expr::Call(call.clone())) else {
                    return false;
                };
                if matches!(resource, ResourceExpr::Unresolved { .. }) {
                    return false;
                }
                fn names(resource: &ResourceExpr, out: &mut std::collections::BTreeSet<String>) {
                    match resource {
                        ResourceExpr::Environment { name } => {
                            out.insert(name.clone());
                        }
                        ResourceExpr::Join { parts } => {
                            for part in parts {
                                names(part, out);
                            }
                        }
                        _ => {}
                    }
                }
                let mut env = std::collections::BTreeSet::new();
                names(&resource, &mut env);
                for name in env {
                    self.emit(
                        "environment.read",
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable { name },
                        },
                        &[],
                        node,
                    );
                }
            }
            "os.path.exists" | "os.path.isfile" | "os.path.isdir" | "os.path.getsize"
            | "os.path.getmtime" => {
                if !supported_signature(call, 1, 1, &[]) {
                    return false;
                }
                self.fs_op(call, 0, "filesystem.read", &[("metadata", true)], span);
                if !matches!(
                    self.exact_value(&call.args[0], 0),
                    Some(ExactValue::Text | ExactValue::Bytes)
                ) && !self.is_path_value(&call.args[0])
                {
                    return false;
                }
            }
            "glob.glob" | "glob.iglob" | "os.walk" => {
                let keywords: &[&str] = if name == "os.walk" {
                    &["topdown", "followlinks"]
                } else {
                    &["recursive", "include_hidden", "root_dir"]
                };
                if !supported_signature(call, 1, 1, keywords) {
                    return false;
                }
                // Shared glob patterns exclude hidden segments. Do not claim
                // that they cover Python's include_hidden traversal.
                if call.keywords.iter().any(|kw| {
                    kw.arg
                        .as_ref()
                        .is_some_and(|name| name.as_str() == "include_hidden")
                }) && keyword_bool(call, "include_hidden") != Some(false)
                {
                    return false;
                }
                if call
                    .keywords
                    .iter()
                    .any(|kw| self.exact_value(&kw.value, 0).is_none())
                {
                    return false;
                }
                // iglob and walk execute only through an iteration protocol.
                if name != "glob.glob" && !self.executes_deferred_call(span) {
                    return false;
                }
                let resource = if name == "os.walk" {
                    self.resolve_fs(&call.args[0])
                } else if let Some(pattern) = str_literal(&call.args[0]) {
                    let root = match python_call_argument(call, 1, "root_dir") {
                        Some(argument) => {
                            let Some(root) = str_literal(argument) else {
                                return false;
                            };
                            Some(root)
                        }
                        None => self.cwd.clone(),
                    };
                    ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::FsPath {
                            glob: if pattern.starts_with('/') {
                                pattern
                            } else {
                                format!("{}/{pattern}", root.as_deref().unwrap_or("."))
                            },
                        },
                    }
                } else {
                    return false;
                };
                self.emit(
                    "filesystem.read",
                    resource,
                    &[(
                        "recursive",
                        name == "os.walk" || keyword_bool(call, "recursive") == Some(true),
                    )],
                    node,
                );
                if self.exact_value(&call.args[0], 0).is_none() {
                    return false;
                }
            }
            "tempfile.mkdtemp"
            | "tempfile.mkstemp"
            | "tempfile.TemporaryDirectory"
            | "tempfile.NamedTemporaryFile" => {
                let Some(resource) = self.temporary_resource(call, name) else {
                    return false;
                };
                self.emit("filesystem.create", resource, &[], node);
                // Cleanup remains visible, including destructor-driven cleanup.
                if matches!(
                    name,
                    "tempfile.TemporaryDirectory" | "tempfile.NamedTemporaryFile"
                ) {
                    return false;
                }
            }
            "zipfile.ZipFile" => {
                if !supported_signature(call, 1, 2, &["mode"])
                    || (call.args.len() == 2 && !call.keywords.is_empty())
                {
                    return false;
                }
                if !matches!(
                    self.exact_value(&call.args[0], 0),
                    Some(ExactValue::Text | ExactValue::Bytes)
                ) && !self.exact_path_receiver(&call.args[0], 0)
                {
                    return false;
                }
                let mode = python_call_argument(call, 1, "mode")
                    .map(str_literal)
                    .unwrap_or_else(|| Some("r".into()));
                let Some(mode) = mode else {
                    return false;
                };
                let operation = match mode.as_str() {
                    "r" => "filesystem.read",
                    "w" | "x" => "filesystem.write",
                    "a" => "filesystem.write",
                    _ => return false,
                };
                self.fs_op(call, 0, operation, &[], span);
                if mode == "a" {
                    self.fs_op(call, 0, "filesystem.read", &[], span);
                }
                if self.exact_value(&call.args[0], 0).is_none() {
                    return false;
                }
            }
            "shutil.which" => {
                if !supported_signature(call, 1, 1, &["mode", "path"]) {
                    return false;
                }
                if !self.python_operands_safe(call)
                    || self.exact_value(&call.args[0], 0) != Some(ExactValue::Text)
                {
                    return false;
                }
                let command = match &call.args[0] {
                    Expr::Name(name) => match self.var_scope.get(name.id.as_str()) {
                        Some(ResourceExpr::Literal { value }) => Some(value.clone()),
                        _ => None,
                    },
                    argument => str_literal(argument),
                };
                let direct = command
                    .as_ref()
                    .is_some_and(|command| command.contains('/'));
                if !direct
                    && !call
                        .keywords
                        .iter()
                        .any(|kw| kw.arg.as_ref().is_some_and(|name| name.as_str() == "path"))
                {
                    self.emit(
                        "environment.read",
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable {
                                name: "PATH".into(),
                            },
                        },
                        &[],
                        node,
                    );
                }
                if direct {
                    self.fs_op(call, 0, "filesystem.read", &[("metadata", true)], span);
                } else if let Some(command) = command
                    && let Some(paths) = python_call_argument(call, 2, "path").and_then(str_literal)
                    && paths.split(':').count() <= 64
                {
                    if paths.is_empty() {
                        return true;
                    }
                    for directory in paths.split(':') {
                        let candidate = if directory.is_empty() {
                            command.clone()
                        } else {
                            format!("{directory}/{command}")
                        };
                        let resource =
                            crate::paths::resolve_fs_path(&candidate, self.cwd.as_deref());
                        self.emit("filesystem.read", resource, &[("metadata", true)], node);
                    }
                } else {
                    self.emit_unresolved_call(
                        name,
                        effinterp_proto::BoundaryReason::EXTERNAL_UNMODELED,
                        effinterp_proto::BoundaryClass::Unmodeled,
                        &["filesystem"],
                        span,
                        super::python_callee_reference(name),
                    );
                }
            }
            "os.kill" | "os.killpg" => {
                if !supported_signature(call, 2, 2, &[]) {
                    return false;
                }
                self.emit(
                    "process.signal",
                    resolve::symbolic(&call.args[0], "process"),
                    &[],
                    node,
                );
                if call
                    .args
                    .iter()
                    .any(|arg| self.exact_value(arg, 0).is_none())
                {
                    return false;
                }
            }
            "urllib.request.Request" => {
                return self.modeled_value(&Expr::Call(call.clone())).is_some();
            }
            _ => return false,
        }
        true
    }
}

/// The source of `compile(source, filename, mode)` when all three are literals
/// and the mode is one `compile` accepts, so the code object runs exactly that
/// source. Keywords such as `flags` stay outside this form.
fn literal_compile_source(call: &ast::ExprCall) -> Option<String> {
    let [source, filename, mode] = call.args.as_slice() else {
        return None;
    };
    (call.keywords.is_empty()
        && str_literal(filename).is_some()
        && matches!(
            str_literal(mode).as_deref(),
            Some("exec" | "eval" | "single")
        ))
    .then(|| str_literal(source))
    .flatten()
}
