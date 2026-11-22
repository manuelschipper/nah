//! Modeled Python standard-library and HTTP client APIs.
//!
//! This module owns API classification and effect construction. The parent
//! module keeps parsing, execution reachability, and dataflow walking.

use effinterp_proto::{
    AttrValue, Effect, Modality, Operation, PathPlatform, ProvenanceRef, ResourceExpr,
    ResourceIdentity, normalize_resource,
};
use rustpython_parser::ast::{self, Constant, Expr, Stmt};
use rustpython_parser::text_size::TextRange;

use super::ipython::ipython_flatten_literal;
use super::resolve::{self, host_endpoint, net_resource, str_literal};

use super::PythonWalker;
use super::call_resolution::{keyword_bool, python_call_argument};
use super::definitions::collect_returns;
use super::literal_values::int_literal;

use super::decoders::is_python_stream_decoder;
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
                        .insert("truncate".into(), AttrValue::Bool(true));
                    write
                        .attributes
                        .insert("disclosure".into(), AttrValue::String("contents".into()));
                    if let Some(ResourceExpr::Literal { value }) =
                        python_external_argument(args, 0, "data")
                    {
                        write
                            .attributes
                            .insert("written_content".into(), AttrValue::String(value));
                    }
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
                                narrowing: Default::default(),
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

/// `CDLL(None)` is the process C library. A libc soname is the same library.
fn libc_handle(expr: &Expr) -> bool {
    match expr {
        Expr::Constant(constant) => match &constant.value {
            Constant::None => true,
            Constant::Str(name) => {
                let name = name.rsplit('/').next().unwrap_or(name);
                matches!(
                    name,
                    "c" | "libc"
                        | "libc.so"
                        | "libc.so.6"
                        | "libc.so.1"
                        | "libc.dylib"
                        | "libSystem.B.dylib"
                ) || name.starts_with("libc.so.")
            }
            _ => false,
        },
        _ => false,
    }
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
                _ => unresolved_resource("network"),
            }
        }
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives
                .into_iter()
                .map(python_network_resource)
                .collect(),
        },
        ResourceExpr::Join { parts } => crate::value::sink_typed_join(parts, "network"),
        _ => unresolved_resource("network"),
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
        if self.memory_tar_call(call) {
            return true;
        }
        if self.model_ctypes_libc(call, span) {
            return true;
        }
        // A modeled receiver leaf skips the receiver's argument walk. Only use
        // it for known strings and literal operands; other forms must retain
        // the ordinary walk of nested calls and arguments.
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && attribute.attr.as_str() == "write"
            && let Expr::Call(open) = attribute.value.as_ref()
            && open
                .args
                .iter()
                .chain(open.keywords.iter().map(|keyword| &keyword.value))
                .all(|argument| {
                    matches!(argument, Expr::Constant(_)) || self.known_string(argument).is_some()
                })
            && call.args.len() == 1
            && call.keywords.is_empty()
            && matches!(
                self.imports.resolve_callee(&open.func).as_deref(),
                Some("open" | "io.open")
            )
            && let Some(path) = python_call_argument(open, 0, "file")
            && self.known_string(path).is_some()
            && let Some(mode) =
                python_call_argument(open, 1, "mode").and_then(|mode| self.known_string(mode))
            && mode.contains(['w', 'a', 'x', '+'])
            && let Some(data) = call.args.first()
            && let content = self.known_string(data)
            && (content.is_some() || self.memory_bytes(data).is_some())
        {
            let resource = self.resolve_fs(path);
            let node = self.span_node(span);
            let write = self.emit(
                "filesystem.write",
                resource,
                &[
                    ("truncate", mode.contains(['w', 'x'])),
                    ("append", mode.contains('a')),
                ],
                node,
            );
            match content {
                Some(content) => {
                    self.set_effect_string_attribute(write, "written_content", &content)
                }
                // A text-mode file object rejects bytes.
                None if mode.contains('b') => self.mark_embedded_archive(write, data),
                None => {}
            }
            return true;
        }
        // `f.write(data)` on a binary file object, bound or chained; a
        // closed one writes nothing.
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && let [data] = call.args.as_slice()
            && attribute.attr.as_str() == "write"
            && let Some(write) = self.handle_write(&attribute.value)
        {
            self.mark_embedded_archive(Some(write), data);
        }
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && let Expr::Name(handle) = attribute.value.as_ref()
            && attribute.attr.as_str() == "close"
        {
            self.write_handles.remove(handle.id.as_str());
        }
        // A closed socket is no longer a connection.
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && let Expr::Name(socket) = attribute.value.as_ref()
            && matches!(attribute.attr.as_str(), "close" | "detach")
        {
            self.connected_sockets.remove(socket.id.as_str());
        }
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
        if name == "json.dump"
            && let Some(Expr::Call(open)) = call.args.get(1)
            && self.json_dump_to_open(call, open, span)
        {
            return true;
        }
        if self.stdlib_resource_call(call, &name, span) {
            return true;
        }
        let printed_environ = self.printed_environ(&name, call);
        self.given_environ_printed(&name, call);
        match name.as_str() {
            "open" | "io.open" | "io.FileIO" => self.builtin_open(call, span),
            "os.open" => self.os_open(call, span),
            // A literal `eval`/`exec` body is source this frontend can read, so
            // it is entered like any other nested program, as is a literal
            // compiled in place and a file read whole (`exec(open(P).read())`).
            // Only a string the runtime supplies stays opaque. Explicit
            // globals/locals change which names the body sees, so they keep it
            // opaque too.
            "eval" | "exec" => {
                let plain =
                    call.args.len() == 1 && call.keywords.is_empty() && self.capture.is_none();
                let body = plain
                    .then(|| {
                        call.args
                            .first()
                            .and_then(|arg| str_literal(arg).or_else(|| self.compiled_literal(arg)))
                    })
                    .flatten();
                let file = plain
                    .then(|| call.args.first().and_then(|arg| self.whole_file_read(arg)))
                    .flatten();
                match (body, file) {
                    (Some(source), _) => self.nest_python_source(&source, span),
                    (None, Some(path)) if self.nest_python_file(&path, span, false) => {}
                    _ => {
                        self.opaque_call(&name, span);
                        self.dynamic_code_execution(span);
                    }
                }
            }
            // `runpy.run_path(P)` runs the file P names in this process.
            "runpy.run_path" => {
                let path = (self.capture.is_none() && call.args.len() + call.keywords.len() == 1)
                    .then(|| python_call_argument(call, 0, "path_name"))
                    .flatten()
                    .map(|path| self.resolve_fs(path));
                if !path.is_some_and(|path| self.nest_python_file(&path, span, true)) {
                    self.opaque_call(&name, span);
                    self.dynamic_code_execution(span);
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
            _ if printed_environ.is_some() => {
                self.environ_printed(printed_environ.unwrap_or_default(), span)
            }
            _ if is_python_stream_decoder(&name) => self.stream_decode(span, &name),
            "os.system" | "os.popen" => self.os_system(call, span),
            "os.dup2" if self.capture.is_none() && self.socket_onto_stdin(call) => {
                let endpoint =
                    python_call_argument(call, 0, "fd").and_then(|fd| self.socket_fileno(fd));
                let node = self.span_node(span);
                self.stdin_connection =
                    endpoint.and_then(|endpoint| self.emit("network.connect", endpoint, &[], node));
            }
            // Any other `os.dup2` onto descriptor 0 replaces that input.
            "os.dup2" if python_call_argument(call, 1, "fd2").and_then(int_literal) == Some(0) => {
                self.stdin_connection = None;
                return false;
            }
            // `pty.spawn(argv)` runs the program on a new terminal and copies
            // this process's standard input to it. The argv is modeled even
            // without a connection; terminal setup and callbacks retain the
            // call's boundary.
            "pty.spawn" => {
                self.subprocess(call, python_call_argument(call, 0, "argv"), false, span);
                return false;
            }
            "subprocess.run"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "subprocess.Popen" => {
                // Popen's first parameter is `args`, so it may also be passed by name.
                let args = python_call_argument(call, 0, "args");
                // `stdin=` replaces the input the child would inherit: with a
                // connected socket, and otherwise with something that is not
                // the connection standard input was replaced with.
                let inherited = self.stdin_connection;
                let stdin = call
                    .keywords
                    .iter()
                    .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some("stdin"));
                if let Some(stdin) = stdin {
                    let endpoint =
                        self.socket_fileno(&stdin.value)
                            .or_else(|| match &stdin.value {
                                Expr::Name(name) => {
                                    self.connected_sockets.get(name.id.as_str()).cloned()
                                }
                                _ => None,
                            });
                    let node = self.span_node(span);
                    self.stdin_connection = endpoint
                        .filter(|_| self.capture.is_none())
                        .and_then(|endpoint| self.emit("network.connect", endpoint, &[], node));
                }
                self.subprocess(
                    call,
                    args,
                    keyword_bool(call, "shell").unwrap_or(false),
                    span,
                );
                self.stdin_connection = inherited;
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

    /// Mark `write` when `data` is bytes the request's own code spells that
    /// hold a compressed or archived stream (`crate::embedded_archive`). A
    /// script on disk, such as an installer that unpacks its bundled
    /// archive, is the user's code and is not marked.
    fn mark_embedded_archive(&mut self, write: Option<u32>, data: &Expr) {
        let node = self.span_node(rustpython_parser::ast::Ranged::range(data));
        if self.builder.source_from_subject(Some(node))
            && let Some(format) = self
                .memory_bytes(data)
                .and_then(|bytes| crate::embedded_archive::format(&bytes))
        {
            self.set_effect_string_attribute(write, crate::embedded_archive::ATTRIBUTE, format);
        }
    }

    /// The string `expr` evaluates to, when every part of it is known: a
    /// literal, an f-string or `+` concatenation whose parts lower to
    /// literals as path lowering does, or a name bound to one of those.
    pub(super) fn known_string(&self, expr: &Expr) -> Option<String> {
        if let Some(value) = str_literal(expr) {
            return Some(value);
        }
        let resource = match self.lowered_concatenation(expr) {
            Some(resource) => resource,
            None => {
                let Expr::Name(name) = expr else {
                    return None;
                };
                if self.widened_vars.contains(name.id.as_str()) {
                    return None;
                }
                self.var_scope.get(name.id.as_str())?.clone()
            }
        };
        // Names inside the concatenation lower to parameters; bind the ones
        // this scope knows. Any part still symbolic leaves no known string.
        ipython_flatten_literal(&substitute_resource_expr(&resource, &self.var_scope))
    }

    /// A filesystem op on the argument at `index`. The returned slot lets a
    /// transfer emitter pair the endpoint it just produced.
    pub(super) fn fs_op(
        &mut self,
        call: &ast::ExprCall,
        index: usize,
        operation: &str,
        attrs: &[(&str, bool)],
        span: TextRange,
    ) -> Option<u32> {
        let arg = call.args.get(index)?;
        let lowered_concatenation = self.lowered_concatenation(arg).is_some();
        let resource = match self.data_file_key(arg) {
            Some(path) => crate::paths::resolve_fs_path(&path, self.cwd.as_deref()),
            None => self.resolve_fs(arg),
        };
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

    pub(super) fn set_effect_string_attribute(
        &mut self,
        effect: Option<u32>,
        name: &str,
        value: &str,
    ) {
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

    pub(super) fn set_effect_action(&mut self, effect: Option<u32>, action: &str) {
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
                super::call_resolution::python_callee_reference("pathlib.Path.read_text"),
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
                let write = self.emit("filesystem.write", resource, &[("truncate", true)], node);
                self.set_effect_string_attribute(write, "disclosure", "contents");
                if let Some(data) = python_call_argument(call, 0, "data") {
                    match str_literal(data) {
                        Some(content) => {
                            self.set_effect_string_attribute(write, "written_content", &content)
                        }
                        // `write_text` rejects bytes.
                        None if method == "write_bytes" => self.mark_embedded_archive(write, data),
                        None => {}
                    }
                }
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
                            narrowing: Default::default(),
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

    /// Every variable in this execution's environment reaches stdout, including
    /// any a wrapper such as `doppler run` injected, so their values flow into
    /// the read the way they do for `env`.
    pub(super) fn print_environ(&mut self, span: TextRange) {
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
    pub(super) fn interpreter_resource(&self) -> ResourceExpr {
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

    /// A module-level HTTP call (`requests.get`, `httpx.post`,
    /// `urllib.request.urlopen`, ...). The verb is the method segment of the
    /// canonical name; for the verb-first `.request(method, url)` and
    /// `.stream(method, url)` the URL is the second argument and the verb the
    /// first literal argument. Either may be passed by keyword.
    fn network(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        if name == "urllib.request.urlopen"
            && let Some(argument) = python_call_argument(call, 0, "url")
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
        let (url_expr, verb) = if matches!(method, "request" | "stream") {
            (
                python_call_argument(call, 1, "url"),
                python_call_argument(call, 0, "method").and_then(str_literal),
            )
        } else {
            (python_call_argument(call, 0, "url"), None)
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
                    let resource = python_call_argument(call, 0, "url")
                        .map(|a| self.resolve_net(a))
                        .unwrap_or_else(|| unresolved_resource("network"));
                    self.emit(net_op(method), resource, &[], node);
                }
                "request" | "send" | "stream" => {
                    let resource = python_call_argument(call, 1, "url")
                        .map(|a| self.resolve_net(a))
                        .unwrap_or_else(|| unresolved_resource("network"));
                    let verb = python_call_argument(call, 0, "method").and_then(str_literal);
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
                    if let Expr::Attribute(attribute) = call.func.as_ref()
                        && let Expr::Name(socket) = attribute.value.as_ref()
                    {
                        self.connected_sockets
                            .insert(socket.id.to_string(), resource.clone());
                    }
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

    /// The endpoint of the connected socket whose descriptor `expr` is:
    /// `s.fileno()`.
    fn socket_fileno(&self, expr: &Expr) -> Option<ResourceExpr> {
        let Expr::Call(call) = expr else {
            return None;
        };
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return None;
        };
        let Expr::Name(socket) = attribute.value.as_ref() else {
            return None;
        };
        (attribute.attr.as_str() == "fileno" && call.args.is_empty())
            .then(|| self.connected_sockets.get(socket.id.as_str()).cloned())
            .flatten()
    }

    /// Whether `os.dup2(fd, fd2)` puts a connected socket on descriptor 0.
    /// The target is a literal 0, or the variable of a loop over a literal
    /// sequence holding 0 when the call runs on every pass, as in `for fd in
    /// (0, 1, 2): os.dup2(s.fileno(), fd)`. A loop walked once per value
    /// binds the variable, so only the pass that holds 0 counts.
    fn socket_onto_stdin(&self, call: &ast::ExprCall) -> bool {
        let (Some(descriptor), Some(target)) = (
            python_call_argument(call, 0, "fd"),
            python_call_argument(call, 1, "fd2"),
        ) else {
            return false;
        };
        let stdin = match target {
            Expr::Name(name) => {
                self.zero_loop_calls
                    .get(&u32::from(call.range.start()))
                    .map(String::as_str)
                    == Some(name.id.as_str())
                    && match self.var_scope.get(name.id.as_str()) {
                        Some(ResourceExpr::Literal { value }) => value == "0",
                        _ => true,
                    }
            }
            target => int_literal(target) == Some(0),
        };
        stdin && self.socket_fileno(descriptor).is_some()
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

    /// `ctypes.CDLL(None).chmod` and `.system` are libc once the library
    /// argument is `None` or a libc soname and the path or command is known.
    /// An unknown argument keeps a boundary and does not also become an
    /// unresolved attribute call. A different library is left to the walker.
    fn model_ctypes_libc(&mut self, call: &ast::ExprCall, span: TextRange) -> bool {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return false;
        };
        let function = attribute.attr.as_str();
        if !matches!(function, "chmod" | "system") {
            return false;
        }
        let Expr::Call(loader) = attribute.value.as_ref() else {
            return false;
        };
        let Some(name) = self.imports.resolve_callee(&loader.func) else {
            return false;
        };
        if !matches!(name.as_str(), "ctypes.CDLL" | "ctypes.cdll.LoadLibrary") {
            return false;
        }
        let Some(library) = python_call_argument(loader, 0, "name") else {
            return false;
        };
        if !libc_handle(library) {
            return false;
        }
        let node = self.span_node(span);
        match function {
            "chmod" => self.ctypes_chmod(call, node),
            "system" => self.ctypes_system(call, node),
            _ => {}
        }
        true
    }

    fn ctypes_chmod(&mut self, call: &ast::ExprCall, node: ProvenanceRef) {
        let Some(path) = call.args.first().and_then(|path| self.ctypes_path(path)) else {
            self.opaque_boundary("ctypes chmod path is not a literal", node);
            return;
        };
        let grants = chmod_grants(call.args.get(1));
        let effect = self.emit("filesystem.metadata", path, &grants, node);
        self.set_effect_action(effect, "chmod");
    }

    fn ctypes_system(&mut self, call: &ast::ExprCall, node: ProvenanceRef) {
        let Some(command) = call
            .args
            .first()
            .and_then(|command| self.ctypes_command(command))
        else {
            self.opaque_boundary("ctypes system command is not a literal", node);
            return;
        };
        self.defer_or_nest_shell(
            ResourceExpr::Literal { value: command },
            self.cwd.clone(),
            self.chdir.clone(),
            self.cwd_node,
            node,
            None,
            "ctypes system command is not a literal",
        );
    }

    fn ctypes_path(&self, expr: &Expr) -> Option<ResourceExpr> {
        if let Expr::Constant(constant) = expr
            && let Constant::Bytes(bytes) = &constant.value
        {
            let text = std::str::from_utf8(bytes).ok()?;
            return Some(crate::paths::resolve_fs_path(text, self.cwd.as_deref()));
        }
        // A name or other expression is not the path libc receives. Resolving
        // it would record an unbound name instead of this call's own boundary.
        if str_literal(expr).is_none() && self.known_string(expr).is_none() {
            return None;
        }
        let resource = self.resolve_fs(expr);
        matches!(
            resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { .. }
            }
        )
        .then_some(resource)
    }

    fn ctypes_command(&self, expr: &Expr) -> Option<String> {
        if let Some(text) = str_literal(expr).or_else(|| self.known_string(expr)) {
            return Some(text);
        }
        if let Expr::Constant(constant) = expr
            && let Constant::Bytes(bytes) = &constant.value
        {
            return String::from_utf8(bytes.clone()).ok();
        }
        None
    }

    pub(super) fn opaque_call(&mut self, name: &str, span: TextRange) {
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ExactValue {
    Text,
    Bytes,
    Number,
    Data,
    Sequence,
    BuiltinType,
    BuiltinCallable,
}

// Signature and operand checks are deliberately separate from import identity.
pub(super) fn supported_signature(
    call: &ast::ExprCall,
    min: usize,
    max: usize,
    keywords: &[&str],
) -> bool {
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
                        ModeledValue::Bytes | ModeledValue::KnownBytes(_) => {
                            Some(ExactValue::Bytes)
                        }
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
                    "dict" | "json.loads" | "json.load" | "yaml.safe_load" => ExactValue::Data,
                    _ => return None,
                })
            }
            // A literal key selects a plain value from plain data.
            Expr::Subscript(subscript)
                if next(&subscript.value) == Some(ExactValue::Data)
                    && matches!(
                        next(&subscript.slice),
                        Some(ExactValue::Text | ExactValue::Number)
                    ) =>
            {
                Some(ExactValue::Data)
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

    pub(super) fn safe_method_result(
        &self,
        call: &ast::ExprCall,
        depth: usize,
    ) -> Option<ExactValue> {
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
            // Parsing a file `open` reads in text mode does nothing else; the
            // read is the `open` call's own effect.
            "json.load" | "yaml.safe_load" => {
                signature(1, 1, &[])
                    && matches!(&call.args[0], Expr::Call(open)
                    if self.imports.resolve_callee(&open.func).as_deref() == Some("open")
                        && open.keywords.is_empty()
                        && match open.args.as_slice() {
                            [path] => value(path) == Some(ExactValue::Text),
                            [path, mode] => {
                                value(path) == Some(ExactValue::Text)
                                    && matches!(str_literal(mode).as_deref(), Some("r" | "rt"))
                            }
                            _ => false,
                        })
            }
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
    KnownBytes(std::rc::Rc<Vec<u8>>),
    MemoryTar(super::memory_tar::MemoryTarValue),
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
        if let Some(value) = self.memory_tar_value(expr, 0) {
            return Some(ModeledValue::MemoryTar(value));
        }
        if let Expr::Constant(c) = expr {
            return match &c.value {
                Constant::Bytes(_) => Some(
                    self.memory_bytes(expr)
                        .map(ModeledValue::KnownBytes)
                        .unwrap_or(ModeledValue::Bytes),
                ),
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
        if let Some(bytes) = self.decoded_literal_bytes(call) {
            return Some(ModeledValue::KnownBytes(std::rc::Rc::new(bytes)));
        }
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
                narrowing: Default::default(),
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
                            narrowing: Default::default(),
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
                // A temporary name is one no file held: the create cannot
                // reach an existing file. A summary's effects are not yet
                // plan effects, so only a direct call is marked.
                if let Some(slot) = self.emit("filesystem.create", resource, &[], node)
                    && self.capture.is_none()
                {
                    self.builder.note_fresh_create(slot);
                }
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
                        super::call_resolution::python_callee_reference(name),
                    );
                }
            }
            "os.kill" | "os.killpg" => {
                if !supported_signature(call, 2, 2, &[]) {
                    return false;
                }
                self.emit(
                    "process.signal",
                    resolve::symbolic_resource(&call.args[0], "process"),
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
