//! Modeled Node.js and JavaScript runtime APIs.
//!
//! This module owns API classification and effect construction. The parent
//! module keeps parsing, execution reachability, and dataflow walking.

use std::collections::HashMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
    Subject,
};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, CallExpression, Expression, ObjectExpression,
    ObjectPropertyKind,
};
use oxc_span::{GetSpan, Span};

use super::aggregate_source_string_members::{SOURCE_SPREAD_TAIL, source_wildcard_key};
use super::source_string_state::SourceStringState;
use super::{
    EffectVisitor, ObjectPropertyProjection, argument_expr, is_create_server,
    logical_call_argument, object_property, object_property_projection, resolve, unparen,
};
use crate::SemanticValue;
use crate::builder::RuntimeShell;
use crate::nest::{Transition, word_resource};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

/// The JavaScript runtime executing a program, from the command that launched
/// it. Deno and Bun expose their own globals; Deno has no `require`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum JsRuntime {
    Node,
    Deno,
    Bun,
}

impl JsRuntime {
    pub(super) fn launched_by(command: Option<&str>) -> Self {
        // The launch records the spelling typed, such as `DENO` or `bun.exe`.
        let command = command
            .map(|command| crate::models::folded_program(command).unwrap_or(command.to_string()));
        match command.as_deref() {
            Some("deno") => Self::Deno,
            Some("bun") => Self::Bun,
            _ => Self::Node,
        }
    }
}

/// The `fs` function a Deno or Bun file API performs.
fn runtime_fs_function(module: &str, function: &str) -> Option<&'static str> {
    Some(match (module, function) {
        ("deno", "remove") => "rm",
        ("deno", "removeSync") => "rmSync",
        ("deno", "writeFile" | "writeTextFile") | ("bun", "write") => "writeFile",
        ("deno", "writeFileSync" | "writeTextFileSync") => "writeFileSync",
        ("bun", "file.delete") => "unlink",
        _ => return None,
    })
}

#[derive(Clone)]
pub(super) enum StaticOptionValue {
    Bool(bool),
    String(String),
    /// A property whose value is not a literal.
    Unresolved,
}

#[derive(Clone, Default)]
pub(super) struct ObjectLiteral {
    pub(super) values: HashMap<String, StaticOptionValue>,
    pub(super) env_keys: Vec<Option<String>>,
    /// A computed key or unknown spread may have set any property that
    /// `values` does not name.
    pub(super) open: bool,
}

pub(super) type ObjectLiteralBindings = HashMap<String, ObjectLiteral>;

pub(super) fn network_source_literal(value: &str) -> ResourceExpr {
    let resource = SemanticValue::source_literal(value).lower_resource();
    if matches!(
        resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { .. }
        }
    ) {
        resource
    } else {
        unresolved_resource("network")
    }
}

pub(super) fn object_literal(
    expr: &Expression<'_>,
    bindings: &ObjectLiteralBindings,
) -> Option<ObjectLiteral> {
    object_literal_resolving(expr, bindings, &|_| None)
}

/// `object_literal`, taking a property value `string` resolves as that
/// string, such as a name bound to a string constant.
pub(super) fn object_literal_resolving<'a>(
    expr: &Expression<'a>,
    bindings: &ObjectLiteralBindings,
    string: &dyn Fn(&Expression<'a>) -> Option<String>,
) -> Option<ObjectLiteral> {
    let Expression::ObjectExpression(object) = unparen(expr) else {
        return None;
    };
    Some(object_literal_properties(object, bindings, string))
}

fn object_literal_properties<'a>(
    object: &ObjectExpression<'a>,
    bindings: &ObjectLiteralBindings,
    string: &dyn Fn(&Expression<'a>) -> Option<String>,
) -> ObjectLiteral {
    let mut literal = ObjectLiteral::default();
    for property in &object.properties {
        match property {
            ObjectPropertyKind::ObjectProperty(property) => {
                let Some(key) = property.key.static_name() else {
                    literal.values.clear();
                    literal.env_keys.push(None);
                    literal.open = true;
                    continue;
                };
                literal.env_keys.push(Some(key.to_string()));
                let value = match unparen(&property.value) {
                    Expression::BooleanLiteral(value) => StaticOptionValue::Bool(value.value),
                    // Node treats an unset option like `false`.
                    Expression::NullLiteral(_) => StaticOptionValue::Bool(false),
                    Expression::Identifier(id) if id.name == "undefined" => {
                        StaticOptionValue::Bool(false)
                    }
                    Expression::StringLiteral(value) => {
                        StaticOptionValue::String(value.value.to_string())
                    }
                    value => string(value).map_or(StaticOptionValue::Unresolved, |value| {
                        StaticOptionValue::String(value)
                    }),
                };
                literal.values.insert(key.to_string(), value);
            }
            ObjectPropertyKind::SpreadProperty(spread) => {
                let nested;
                let spread = match unparen(&spread.argument) {
                    Expression::Identifier(id) => bindings.get(id.name.as_str()),
                    Expression::ObjectExpression(object) => {
                        nested = object_literal_properties(object, bindings, string);
                        Some(&nested)
                    }
                    _ => None,
                };
                if let Some(spread) = spread {
                    // An open object may override any earlier property.
                    if spread.open {
                        literal.values.clear();
                    }
                    literal.values.extend(spread.values.clone());
                    literal.env_keys.extend(spread.env_keys.clone());
                    literal.open |= spread.open;
                } else {
                    literal.values.clear();
                    literal.env_keys.push(None);
                    literal.open = true;
                }
            }
        }
    }
    literal
}

pub(super) fn object_assigns_process_env(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(callee) = unparen(&call.callee) else {
        return false;
    };
    if callee.property.name.as_str() != "assign"
        || !matches!(unparen(&callee.object), Expression::Identifier(id) if id.name == "Object")
    {
        return false;
    }
    logical_call_argument(&call.arguments, 0)
        .and_then(|(target, _)| target)
        .is_some_and(resolve::is_process_env)
}

pub(super) fn object_env_keys(
    expr: &Expression<'_>,
    bindings: &ObjectLiteralBindings,
) -> Option<Vec<Option<String>>> {
    match unparen(expr) {
        Expression::Identifier(id) => bindings
            .get(id.name.as_str())
            .map(|literal| literal.env_keys.clone()),
        Expression::ObjectExpression(_) => {
            object_literal(expr, bindings).map(|literal| literal.env_keys)
        }
        _ => None,
    }
}

/// Runtime bindings guaranteed by ECMAScript, plus Node's `process` receiver.
pub(super) const RUNTIME_GLOBALS: &[&str] = &[
    "AggregateError",
    "Array",
    "ArrayBuffer",
    "AsyncDisposableStack",
    "Atomics",
    "BigInt",
    "BigInt64Array",
    "BigUint64Array",
    "Boolean",
    "DataView",
    "Date",
    "DisposableStack",
    "Error",
    "EvalError",
    "FinalizationRegistry",
    "Float16Array",
    "Float32Array",
    "Float64Array",
    "Function",
    "Infinity",
    "Int16Array",
    "Int32Array",
    "Int8Array",
    "Intl",
    "Iterator",
    "JSON",
    "Map",
    "Math",
    "NaN",
    "Number",
    "Object",
    "Promise",
    "Proxy",
    "RangeError",
    "ReferenceError",
    "Reflect",
    "RegExp",
    "Set",
    "SharedArrayBuffer",
    "String",
    "SuppressedError",
    "Symbol",
    "SyntaxError",
    "TypeError",
    "URIError",
    "Uint16Array",
    "Uint32Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "WeakMap",
    "WeakRef",
    "WeakSet",
    "WebAssembly",
    "decodeURI",
    "decodeURIComponent",
    "encodeURI",
    "encodeURIComponent",
    "escape",
    "eval",
    "globalThis",
    "isFinite",
    "isNaN",
    "parseFloat",
    "parseInt",
    "process",
    "undefined",
    "unescape",
];

/// Callee bases whose calls are known to have no external effect, so an
/// unresolved-call boundary would be noise. `require` is a binding, not an
/// effect; the rest are pure language/runtime built-ins.
const INERT_CALLEES: [&str; 22] = [
    "require",
    "console",
    "Math",
    "JSON",
    "Object",
    "Array",
    "String",
    "Number",
    "Boolean",
    "Symbol",
    "Buffer",
    "Promise",
    "Date",
    "RegExp",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "parseInt",
    "parseFloat",
    "isNaN",
    "isFinite",
];

/// Indexed `source_env` members recovered as exec argv. Past this count the
/// remaining words become one `Unknown` so a truncated tail is not dropped
/// silently.
const TRACKED_ARGV_INDEX_LIMIT: usize = 32;

pub(super) fn external_effects(
    module: &str,
    function: &str,
    args: &[ResourceExpr],
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
    let arg = |i: usize, family: &str| args.get(i).cloned().unwrap_or(unresolved_resource(family));
    match module {
        "fs" | "fs/promises" => {
            let (operation, append) = fs_operation(function)?;
            let target = if fs_takes_descriptor(function) {
                unresolved_resource("filesystem")
            } else {
                arg(0, "filesystem")
            };
            let mut first = effect(operation, target);
            if fs_program_input(function) {
                first.attributes.insert(
                    "access_purpose".to_string(),
                    AttrValue::String("program_input".into()),
                );
            }
            if fs_content_output(function) {
                first.attributes.insert(
                    "disclosure".to_string(),
                    AttrValue::String("contents".into()),
                );
            }
            if append {
                first
                    .attributes
                    .insert("append".to_string(), effinterp_proto::AttrValue::Bool(true));
            }
            if let Some(action) = fs_metadata_action(function) {
                first.attributes.insert(
                    "action".to_string(),
                    effinterp_proto::AttrValue::String(action.into()),
                );
            }
            let mut out = vec![first];
            // A rename's source entry delete is the atomic endpoint the
            // `filesystem.move` layer stands for.
            if fs_transfer(function) == Some(FsTransferSource::EntryDelete) {
                out.push(effect("filesystem.delete", arg(0, "filesystem")));
            }
            if let Some(op) = fs_dest_operation(function) {
                let mut destination = effect(op, arg(1, "filesystem"));
                destination.attributes.insert(
                    "disclosure".to_string(),
                    AttrValue::String("contents".into()),
                );
                out.push(destination);
            }
            Some(out)
        }
        "child_process" => matches!(
            function,
            "exec" | "execSync" | "execFile" | "execFileSync" | "spawn" | "spawnSync" | "fork"
        )
        .then(|| vec![effect("process.exec", unresolved_resource("process"))]),
        "node-fetch" | "node-fetch-native" | "__global__" => (function == "fetch")
            .then(|| vec![effect("network.request", unresolved_resource("network"))]),
        _ => None,
    }
}

/// These path operations reject non-string values without invoking conversion hooks.
pub(super) fn is_inert_module_call(
    module: &str,
    function: &str,
    _call: &CallExpression<'_>,
) -> bool {
    // `Bun.file(path)` only names the file; its methods act on it.
    (module == "bun" && function == "file")
        || module == "path"
            && matches!(
                function,
                "join"
                    | "resolve"
                    | "dirname"
                    | "basename"
                    | "extname"
                    | "normalize"
                    | "isAbsolute"
                    | "relative"
            )
}

pub(super) fn has_call_model(module: &str, function: &str, call: &CallExpression<'_>) -> bool {
    match module {
        "fs" | "fs/promises" => {
            let minimum = if fs_dest_operation(function).is_some()
                || matches!(
                    function,
                    "writeFile" | "writeFileSync" | "appendFile" | "appendFileSync"
                ) {
                2
            } else {
                1
            };
            let minimum = if is_fs_link(function) { 2 } else { minimum };
            (fs_operation(function).is_some() || is_fs_link(function))
                && super::logical_call_argument_count(&call.arguments)
                    .is_none_or(|count| count >= minimum)
        }
        "child_process" => matches!(
            function,
            "exec" | "execSync" | "execFile" | "execFileSync" | "spawn" | "spawnSync" | "fork"
        ),
        "tinyexec" | "execa" => matches!(function, "x" | "exec" | "execa" | "execaSync"),
        "deno" | "bun" => match runtime_fs_function(module, function) {
            // The deleted path is the argument of the `Bun.file(path)` receiver.
            Some("unlink") => true,
            Some(function) => has_call_model("fs", function, call),
            None => matches!(
                function,
                "Command.output" | "Command.outputSync" | "Command.spawn" | "spawn" | "spawnSync"
            ),
        },
        "http" | "https" => matches!(function, "request" | "get"),
        "__global__" | "node-fetch" | "node-fetch-native" => function == "fetch",
        _ => false,
    }
}

/// `vm` functions that take their first argument as code: the `runIn*`
/// family runs it, `compileFunction` only compiles it.
fn is_vm_code_call(module: &str, function: &str) -> bool {
    module == "vm"
        && matches!(
            function,
            "runInThisContext" | "runInNewContext" | "runInContext" | "compileFunction"
        )
}

/// Node built-in modules are runtime-owned rather than selected from a
/// file-backed dependency.
pub(crate) fn is_node_builtin_module(specifier: &str) -> bool {
    specifier.starts_with("node:")
        || matches!(
            specifier,
            "_http_agent"
                | "_http_client"
                | "_http_common"
                | "_http_incoming"
                | "_http_outgoing"
                | "_http_server"
                | "_stream_duplex"
                | "_stream_passthrough"
                | "_stream_readable"
                | "_stream_transform"
                | "_stream_wrap"
                | "_stream_writable"
                | "_tls_common"
                | "_tls_wrap"
                | "assert"
                | "assert/strict"
                | "async_hooks"
                | "buffer"
                | "child_process"
                | "cluster"
                | "console"
                | "constants"
                | "crypto"
                | "dgram"
                | "diagnostics_channel"
                | "dns"
                | "dns/promises"
                | "domain"
                | "events"
                | "fs"
                | "fs/promises"
                | "http"
                | "http2"
                | "https"
                | "inspector"
                | "inspector/promises"
                | "module"
                | "net"
                | "os"
                | "path"
                | "path/posix"
                | "path/win32"
                | "perf_hooks"
                | "process"
                | "punycode"
                | "querystring"
                | "readline"
                | "readline/promises"
                | "repl"
                | "stream"
                | "stream/consumers"
                | "stream/promises"
                | "stream/web"
                | "string_decoder"
                | "sys"
                | "timers"
                | "timers/promises"
                | "tls"
                | "trace_events"
                | "tty"
                | "url"
                | "util"
                | "util/types"
                | "v8"
                | "vm"
                | "wasi"
                | "worker_threads"
                | "zlib"
        )
}

/// The `(operation, appends)` an `fs` API function performs on its first path
/// argument, or None if it is not a modeled path-targeting call. Shared by the
/// execution frontend and the summary extractor so the taxonomy lives in one
/// place.
pub(super) fn fs_operation(function: &str) -> Option<(&'static str, bool)> {
    Some(match function {
        "readFile" | "readFileSync" | "read" | "createReadStream" | "open" | "openSync" => {
            ("filesystem.read", false)
        }
        "chmod" | "chmodSync" | "lchmod" | "lchmodSync" | "fchmod" | "fchmodSync" | "chown"
        | "chownSync" => ("filesystem.metadata", false),
        "writeFile" | "writeFileSync" | "createWriteStream" | "truncate" | "truncateSync" => {
            ("filesystem.write", false)
        }
        "appendFile" | "appendFileSync" => ("filesystem.write", true),
        "unlink" | "unlinkSync" | "rm" | "rmSync" | "rmdir" | "rmdirSync" => {
            ("filesystem.delete", false)
        }
        "mkdir" | "mkdirSync" | "mkdtemp" => ("filesystem.create", false),
        // A rename moves the source entry; `filesystem.move` is the semantic
        // layer over the source-delete / destination-write pair.
        "rename" | "renameSync" => ("filesystem.move", false),
        "copyFile" | "copyFileSync" | "cp" | "cpSync" => ("filesystem.read", false),
        _ => return None,
    })
}

/// `link(existingPath, newPath)` and `symlink(target, path)` create their
/// second argument; they stay out of [`fs_operation`], whose effect lands on
/// the first argument.
fn is_fs_link(function: &str) -> bool {
    matches!(function, "link" | "linkSync" | "symlink" | "symlinkSync")
}

fn fs_program_input(function: &str) -> bool {
    matches!(
        function,
        "readFile"
            | "readFileSync"
            | "read"
            | "createReadStream"
            | "copyFile"
            | "copyFileSync"
            | "cp"
            | "cpSync"
    )
}

fn fs_content_output(function: &str) -> bool {
    matches!(
        function,
        "writeFile" | "writeFileSync" | "appendFile" | "appendFileSync"
    )
}

fn fs_metadata_action(function: &str) -> Option<&'static str> {
    match function {
        "chmod" | "chmodSync" | "lchmod" | "lchmodSync" | "fchmod" | "fchmodSync" => Some("chmod"),
        "chown" | "chownSync" => Some("chown"),
        _ => None,
    }
}

/// `fchmod(fd, mode)` changes the file an open descriptor names, which the
/// model does not track, so its effect lands on an unresolved file.
fn fs_takes_descriptor(function: &str) -> bool {
    matches!(function, "fchmod" | "fchmodSync")
}

/// The mode a literal chmod `mode` argument sets. Node reads a number as the
/// mode and a string of octal digits in base 8, and rejects other strings.
fn fs_literal_mode(mode: &Expression<'_>) -> Option<u32> {
    match unparen(mode) {
        Expression::NumericLiteral(literal)
            if literal.value.fract() == 0.0
                && (0.0..=f64::from(u32::MAX)).contains(&literal.value) =>
        {
            Some(literal.value as u32)
        }
        Expression::StringLiteral(literal)
            if literal
                .value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'7')) =>
        {
            u32::from_str_radix(&literal.value, 8).ok()
        }
        _ => None,
    }
}

/// The `(read, write)` access `fs.open` takes on its path, from the literal
/// flags argument. Node defaults to `"r"`; `w`, `a`, and `x` write, and `+`
/// adds the access the leading letter did not select.
pub(super) fn fs_open_access(flags: Option<&str>) -> (bool, bool) {
    let flags = flags.unwrap_or("r");
    (
        flags.contains('r') || flags.contains('+'),
        flags.contains(['w', 'a', 'x', '+']),
    )
}

/// Which source-side interaction anchors an `fs` transfer's pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FsTransferSource {
    /// A proven rename deletes the source directory entry and invents no
    /// source content read.
    EntryDelete,
    /// A copy reads the source content and leaves the source entry in place.
    ContentRead,
}

/// The transfer an `fs` function performs from its first (source) path
/// argument to its second (destination) path argument, or `None` when the
/// function is not a transfer.
pub(super) fn fs_transfer(function: &str) -> Option<FsTransferSource> {
    match function {
        "rename" | "renameSync" => Some(FsTransferSource::EntryDelete),
        "copyFile" | "copyFileSync" | "cp" | "cpSync" => Some(FsTransferSource::ContentRead),
        _ => None,
    }
}

/// Whether an `fs` function also writes a second (destination) path, and the
/// operation to record for it.
pub(super) fn fs_dest_operation(function: &str) -> Option<&'static str> {
    fs_transfer(function).map(|_| "filesystem.write")
}

/// The argument containing recursive options for filesystem calls that
/// support them.
pub(super) fn fs_recursive_options(function: &str) -> Option<usize> {
    match function {
        "rm" | "rmSync" | "rmdir" | "rmdirSync" => Some(1),
        "cp" | "cpSync" => Some(2),
        _ => None,
    }
}

impl<'a> EffectVisitor<'_, 'a> {
    /// The cwd the program runs in now: a proven chdir's target, else the
    /// runtime cwd it started with.
    fn current_cwd(&self) -> Option<&str> {
        self.chdir.as_deref().or(self.runtime_cwd)
    }

    /// Point a child execution at the directory a proven chdir entered. That
    /// directory has no repository namespace.
    fn after_chdir(&self, transition: Transition) -> Transition {
        match &self.chdir {
            Some(_) => transition
                .source_cwd(None)
                .runtime_cwd(None)
                .cwd(self.runtime_cwd_resource.clone(), self.cwd_node),
            None => transition,
        }
    }

    /// Move the program into `path`. Bindings that named a path relative to the
    /// old cwd are re-anchored to the new one; a cwd-relative binding whose
    /// relative form was not kept can no longer be resolved.
    fn enter_directory(&mut self, path: String, span: Span) {
        let cwd = crate::paths::resolve_fs_path_with_cwd(&path, None);
        let substitution = HashMap::from([("cwd".to_string(), cwd.clone())]);
        for name in self.param_env.keys().cloned().collect::<Vec<_>>() {
            match self.cwd_param_env.get(&name) {
                Some(relative) if fs_resource_uses_cwd(relative) => {
                    let rebased = effinterp_proto::normalize_resource(
                        crate::summary::substitute_resource_expr(relative, &substitution),
                        effinterp_proto::PathPlatform::Posix,
                    );
                    self.param_env.insert(name, rebased);
                }
                Some(_) => {}
                None => {
                    self.param_env.remove(&name);
                }
            }
        }
        self.sync_module_source_strings();
        self.cwd_node = Some(self.span_node(span));
        self.runtime_cwd_resource = Some(cwd);
        self.chdir = Some(path);
    }

    /// The absolute directory `process.chdir(target)` (or Deno's `Deno.chdir`)
    /// enters when the walk can
    /// prove it: a literal target reached at module scope under no condition
    /// of this program. Any other chdir stays an unresolved call, since later
    /// relative paths would no longer have a single cwd.
    fn proven_chdir(&self, call: &CallExpression<'a>) -> Option<String> {
        let Expression::StaticMemberExpression(member) = unparen(&call.callee) else {
            return None;
        };
        let Expression::Identifier(receiver) = unparen(&member.object) else {
            return None;
        };
        let owned = match receiver.name.as_str() {
            "process" => {
                self.process_runtime && !self.bindings.member_was_reassigned("process.chdir")
            }
            name => self.runtime_global(name) == Some("deno"),
        };
        if member.property.name != "chdir"
            || !owned
            || self.function_depth != 0
            || self.builder.condition_depth() != self.entry_condition_depth
            || call.arguments.len() != 1
        {
            return None;
        }
        let target = self.expr_to_word(argument_expr(&call.arguments[0])?);
        match crate::paths::resolve_fs_path_with_cwd(
            target.as_literal()?,
            self.runtime_cwd_resource.clone(),
        ) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if path.starts_with('/') => Some(path),
            _ => None,
        }
    }

    pub(super) fn resolve_effect_callee(
        &self,
        callee: &Expression<'a>,
    ) -> Option<super::ModuleCall> {
        if matches!(unparen(callee), Expression::Identifier(id)
            if id.name.as_str() == "fetch"
                && self.active_bodies.last().is_some_and(|body| body.local_names.contains("fetch")))
        {
            return None;
        }
        if inert_base_name(callee).is_some_and(|name| {
            self.active_bodies
                .last()
                .is_some_and(|body| body.local_names.contains(name))
        }) {
            return None;
        }
        self.runtime_global_callee(callee)
            .or_else(|| resolve::resolve_callee(callee, self.bindings))
    }

    /// A call on the runtime's own global the program does not rebind:
    /// `Deno.removeSync(...)` under Deno, `Bun.write(...)` under Bun, and the
    /// chained `Bun.file(path).delete()` and `new Deno.Command(...).output()`.
    fn runtime_global_callee(&self, callee: &Expression<'a>) -> Option<super::ModuleCall> {
        let Expression::StaticMemberExpression(member) = unparen(callee) else {
            return None;
        };
        let method = member.property.name.as_str();
        let (receiver, function) = match unparen(&member.object) {
            Expression::Identifier(receiver) => (receiver, method.to_string()),
            Expression::CallExpression(inner) => {
                let Expression::StaticMemberExpression(factory) = unparen(&inner.callee) else {
                    return None;
                };
                let Expression::Identifier(receiver) = unparen(&factory.object) else {
                    return None;
                };
                (receiver, format!("{}.{method}", factory.property.name))
            }
            Expression::NewExpression(inner) => {
                let Expression::StaticMemberExpression(class) = unparen(&inner.callee) else {
                    return None;
                };
                let Expression::Identifier(receiver) = unparen(&class.object) else {
                    return None;
                };
                (receiver, format!("{}.{method}", class.property.name))
            }
            _ => return None,
        };
        let module = self.runtime_global(receiver.name.as_str())?;
        Some(super::ModuleCall {
            module: module.to_string(),
            function,
        })
    }

    /// The model module for `name` when it is the running runtime's global.
    fn runtime_global(&self, name: &str) -> Option<&'static str> {
        let module = match (name, self.runtime) {
            ("Deno", JsRuntime::Deno) => "deno",
            ("Bun", JsRuntime::Bun) => "bun",
            _ => return None,
        };
        let rebound = self.bindings.declared.contains(name)
            || self
                .active_bodies
                .iter()
                .any(|body| body.local_names.contains(name));
        (!rebound).then_some(module)
    }

    /// Quiet calls require a runtime binding or an exact inert member contract.
    pub(super) fn is_quiet_callee(&self, call: &CallExpression<'a>) -> bool {
        let callee = &call.callee;
        if self
            .resolve_effect_callee(callee)
            .is_some_and(|c| is_inert_module_call(&c.module, &c.function, call))
        {
            return true;
        }
        if self.is_quiet_promise_callee(callee) {
            return true;
        }
        // `os.homedir()` evaluates to `$HOME` once the host supplies it or a
        // literal write before it assigns it; without either the result is
        // the account's home, which stays unresolved.
        if super::is_home_directory_call(call, self.bindings)
            && match resolve::literal_env_read("HOME", call.span.start) {
                Some(resolve::LiteralEnvRead::Value(_)) => true,
                Some(resolve::LiteralEnvRead::Unknown) => false,
                _ => self.host_environment_value("HOME").is_some(),
            }
        {
            return true;
        }
        if let Some(base) = inert_base_name(callee)
            && (self.bindings.declared.contains(base)
                || self
                    .active_bodies
                    .last()
                    .is_some_and(|body| body.local_names.contains(base)))
        {
            return false;
        }
        if is_inert_callee(callee) || resolve::is_get_builtin_module(callee) {
            return true;
        }
        false
    }

    pub(super) fn is_quiet_promise_callee(&self, callee: &Expression<'a>) -> bool {
        let Expression::StaticMemberExpression(member) = unparen(callee) else {
            return false;
        };
        matches!(member.property.name.as_str(), "then" | "catch" | "finally")
            && self.is_known_promise(&member.object, 0)
    }

    fn is_known_promise(&self, expr: &Expression<'a>, depth: u32) -> bool {
        if depth >= 8 {
            return false;
        }
        match unparen(expr) {
            Expression::CallExpression(call) => {
                if self.bindings.dynamic_imports.is_quiet_call(call) {
                    return true;
                }
                if let Some(callee) = self.resolve_effect_callee(&call.callee)
                    && (callee.module == "fs/promises"
                        || callee.module == "node-fetch"
                        || callee.module == "node-fetch-native"
                        || (callee.module == "__global__" && callee.function == "fetch")
                        || (callee.module == "fs" && callee.function.starts_with("promises.")))
                {
                    return true;
                }
                let Expression::StaticMemberExpression(member) = unparen(&call.callee) else {
                    return false;
                };
                matches!(member.property.name.as_str(), "then" | "catch" | "finally")
                    && self.is_known_promise(&member.object, depth + 1)
            }
            Expression::NewExpression(new_expr) => matches!(
                unparen(&new_expr.callee),
                Expression::Identifier(id) if id.name == "Promise"
            ),
            Expression::ImportExpression(_) => true,
            _ => false,
        }
    }

    /// Whether this callee resolves to a modeled effect API or dynamic-exec
    /// (which `model_call` already handled), so it needs no unresolved marker.
    pub(super) fn is_modeled_call(&self, call: &CallExpression<'a>) -> bool {
        if resolve::dynamic_exec(&call.callee).is_some() || self.proven_chdir(call).is_some() {
            return true;
        }
        self.resolve_effect_callee(&call.callee).is_some_and(|c| {
            has_call_model(&c.module, &c.function, call) || is_vm_code_call(&c.module, &c.function)
        })
    }

    /// Code the runtime supplies at an `eval`-like sink runs in this process.
    /// The code itself stays unknown, so the sink keeps its dynamic-code
    /// boundary; the execution lets a flow into the code argument, such as a
    /// fetched response body, be seen.
    pub(super) fn dynamic_code_execution(&mut self, span: Span, detail: &str) {
        self.opaque(span, detail);
        self.code_execution(span);
    }

    /// The code arguments of an expression that compiles a function without
    /// running it: `new Function(...)`, `Function(...)` or
    /// `vm.compileFunction(...)`. The code runs where the result is called.
    pub(super) fn compiled_code<'e>(
        &self,
        expr: &'e Expression<'a>,
    ) -> Option<&'e [oxc_ast::ast::Argument<'a>]> {
        match unparen(expr) {
            Expression::NewExpression(new_expr)
                if self.bindings.is_runtime_code(&new_expr.callee)
                    && resolve::is_function_constructor(new_expr)
                    && !self
                        .bindings
                        .dynamic_imports
                        .is_transparent_constructor(new_expr) =>
            {
                Some(&new_expr.arguments)
            }
            Expression::CallExpression(call)
                if self.bindings.is_runtime_code(&call.callee)
                    && resolve::dynamic_exec(&call.callee) == Some("Function") =>
            {
                Some(&call.arguments)
            }
            Expression::CallExpression(call)
                if self
                    .resolve_effect_callee(&call.callee)
                    .is_some_and(|c| c.module == "vm" && c.function == "compileFunction") =>
            {
                Some(&call.arguments)
            }
            _ => None,
        }
    }

    /// Whether an expression is a fetch `Response` object: the awaited or
    /// settled result of a `fetch` call, or a local holding one.
    pub(super) fn response_kind(&self, expr: &Expression<'a>) -> Option<super::ResponseKind> {
        match unparen(expr) {
            Expression::AwaitExpression(awaited) => self.response_kind(&awaited.argument),
            Expression::Identifier(id) => self.response_vars.get(id.name.as_str()).copied(),
            Expression::CallExpression(call) => self
                .resolve_effect_callee(&call.callee)
                .is_some_and(|callee| {
                    callee.function == "fetch"
                        && matches!(
                            callee.module.as_str(),
                            "__global__" | "node-fetch" | "node-fetch-native"
                        )
                })
                .then_some(super::ResponseKind::Fetch),
            _ => None,
        }
    }

    /// Code reaching `eval`-like sinks runs inside the interpreter process
    /// that runs this program, such as `node`.
    pub(super) fn code_execution(&mut self, span: Span) {
        let node = self.span_node(span);
        let resource = self.interpreter_resource();
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.code_execution"),
            resource,
            attributes: [("source".to_string(), AttrValue::String("argument".into()))]
                .into_iter()
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    /// The interpreter process running this program, such as `node`.
    fn interpreter_resource(&self) -> ResourceExpr {
        match self.builder.launching_command() {
            Some(command) => ResourceExpr::Concrete {
                identity: crate::paths::process_identity_with_cwd(
                    &[crate::word::Word::literal(command)],
                    self.builder.current_execution_cwd(),
                ),
            },
            None => unresolved_resource("process"),
        }
    }

    /// `Buffer.from(text, "base64")` (or `"base64url"`) and `atob(text)`
    /// decode base64 text. A program-local `Buffer` or `atob` is some other
    /// function.
    fn decodes_base64(&self, call: &CallExpression<'a>) -> bool {
        let local = |name: &str| {
            self.active_bodies
                .last()
                .is_some_and(|body| body.local_names.contains(name))
        };
        match unparen(&call.callee) {
            Expression::StaticMemberExpression(member) => {
                matches!(unparen(&member.object), Expression::Identifier(id)
                    if id.name.as_str() == "Buffer" && !local("Buffer"))
                    && member.property.name.as_str() == "from"
                    && matches!(
                        call.arguments.get(1).and_then(argument_expr).map(unparen),
                        Some(Expression::StringLiteral(encoding))
                            if matches!(encoding.value.as_str(), "base64" | "base64url")
                    )
            }
            Expression::Identifier(id) => {
                id.name.as_str() == "atob" && !local("atob") && call.arguments.len() == 1
            }
            _ => false,
        }
    }

    /// A base64 decoder runs inside the interpreter executing this program,
    /// so that interpreter performs the transform. Whether the operand is
    /// valid base64 is not asserted.
    fn base64_decode(&mut self, span: Span) {
        let node = self.span_node(span);
        let model = self.builder.node(
            ProvenanceKind::ModelApplication {
                model: "js/base64@v0".to_string(),
            },
            &[node],
        );
        let resource = self.interpreter_resource();
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new("process.stream_transform"),
            resource,
            attributes: [("transform".to_string(), AttrValue::String("decode".into()))]
                .into_iter()
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node, model],
        });
    }

    pub(super) fn model_call(
        &mut self,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) {
        if self.decodes_base64(call) {
            self.base64_decode(call.span);
            return;
        }
        // eval / Function / dynamic require are unrecoverable code execution.
        if let Some(kind) = resolve::dynamic_exec(&call.callee) {
            // A literal `eval` body is source this frontend can read, so it
            // is entered like any other nested program. Only a string the
            // runtime supplies stays opaque.
            let body = (kind == "eval")
                .then(|| call.arguments.first().and_then(argument_expr))
                .flatten()
                .map(|expr| self.expr_to_word(expr));
            let runs = kind == "eval"
                && self.bindings.is_runtime_code(&call.callee)
                && call
                    .arguments
                    .first()
                    .and_then(argument_expr)
                    .is_none_or(|code| self.response_kind(code).is_none());
            match body.as_ref().and_then(Word::as_literal) {
                Some(source) => self.nest_eval_source(source, call.span),
                None if runs => self.dynamic_code_execution(call.span, kind),
                // `Function(...)` compiles only; a replaced `eval` is unknown,
                // and a `Response` object is not the fetched source.
                None => self.opaque(call.span, kind),
            }
            return;
        }
        if let Some(path) = self.proven_chdir(call) {
            self.enter_directory(path, call.span);
            return;
        }
        if object_assigns_process_env(call) {
            if !self.process_runtime {
                self.unsupported_process_receiver(call.span);
                return;
            }
            for argument in call.arguments.iter().skip(1) {
                let Some(keys) = argument
                    .as_expression()
                    .and_then(|source| object_env_keys(source, &self.object_literal_vars))
                else {
                    self.unknown_env_effect("environment.write", false, call.span);
                    continue;
                };
                for key in keys {
                    match key {
                        Some(name) => self.env_effect("environment.write", &name, false, call.span),
                        None => self.unknown_env_effect("environment.write", false, call.span),
                    }
                }
            }
            return;
        }
        // `server.listen(port)` on a tracked server handle (or directly on a
        // `createServer(...)` chain) binds a listening socket.
        if let Expression::StaticMemberExpression(m) = unparen(&call.callee)
            && m.property.name.as_str() == "listen"
            && self.is_server_handle(&m.object)
        {
            let node = self.span_node(call.span);
            self.builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("network.listen"),
                resource: unresolved_resource("network"),
                attributes: Default::default(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![node],
            });
            return;
        }
        let Some(callee) = self.resolve_effect_callee(&call.callee) else {
            return;
        };
        if callee.module == "vm" && callee.function == "compileFunction" {
            self.opaque(call.span, "vm code");
            return;
        }
        if is_vm_code_call(&callee.module, &callee.function) {
            let body = call
                .arguments
                .first()
                .and_then(argument_expr)
                .map(|expr| self.expr_to_word(expr));
            match body.as_ref().and_then(Word::as_literal) {
                Some(source) => self.nest_eval_source(source, call.span),
                None => self.dynamic_code_execution(call.span, "vm code"),
            }
            return;
        }
        if !has_call_model(&callee.module, &callee.function, call) {
            return;
        }
        match callee.module.as_str() {
            "fs" | "fs/promises" => self.fs_call(&callee.function, call, argument_states),
            "child_process" => self.child_process_call(&callee.function, call),
            // Popular subprocess packages with an execFile-shaped API
            // (`x(cmd, args)` / `execa(cmd, args)`).
            "tinyexec" | "execa"
                if matches!(
                    callee.function.as_str(),
                    "x" | "exec" | "execa" | "execaSync"
                ) =>
            {
                self.child_process_call("execFile", call)
            }
            "http" | "https" if matches!(callee.function.as_str(), "request" | "get") => {
                self.network_call(&callee.function, call, argument_states)
            }
            "__global__" if callee.function == "fetch" => {
                self.network_call("fetch", call, argument_states)
            }
            "deno" | "bun" => self.runtime_call(&callee, call, argument_states),
            "node-fetch" | "node-fetch-native" if callee.function == "fetch" => {
                self.network_call("fetch", call, argument_states)
            }
            _ => {}
        }
    }

    fn fs_call(
        &mut self,
        function: &str,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) {
        if is_fs_link(function) {
            self.fs_link_call(function, call, argument_states);
            return;
        }
        let Some((operation, append)) = fs_operation(function) else {
            return;
        };
        if call.arguments.is_empty() {
            return;
        }
        if matches!(function, "open" | "openSync") {
            self.fs_open_call(call, argument_states);
            return;
        }
        let target = logical_call_argument(&call.arguments, 0);
        if target.is_some_and(|(expr, _)| expr.is_none())
            && self.logical_call_argument_has_concatenation(&call.arguments, 0, argument_states)
        {
            self.unmodeled_dynamic(
                call.span,
                "filesystem argument concatenation is not statically bounded",
            );
        }
        let (resource, node) = if fs_takes_descriptor(function) {
            let resource = unresolved_resource("filesystem");
            (resource, self.span_node(call.span))
        } else {
            let (resource, uses_cwd, host_environment) = self.arg_fs_resource(
                target.and_then(|(expr, _)| expr),
                target.and_then(|(_, syntax_index)| argument_states.get(syntax_index)),
            );
            (
                resource,
                self.fs_span_node(call.span, uses_cwd, &host_environment),
            )
        };
        let mut attributes = std::collections::BTreeMap::new();
        if append {
            attributes.insert("append".to_string(), effinterp_proto::AttrValue::Bool(true));
        }
        if let Some(action) = fs_metadata_action(function) {
            attributes.insert(
                "action".to_string(),
                effinterp_proto::AttrValue::String(action.into()),
            );
        }
        if fs_metadata_action(function) == Some("chmod") {
            match logical_call_argument(&call.arguments, 1)
                .and_then(|(mode, _)| mode)
                .and_then(fs_literal_mode)
            {
                Some(mode) => attributes.extend(
                    crate::permission_mode::granted(crate::permission_mode::numeric(mode))
                        .map(|grant| (grant.to_string(), AttrValue::Bool(true))),
                ),
                None => self.unmodeled_dynamic(
                    call.span,
                    "chmod mode is not a literal, so the permissions it grants are unknown",
                ),
            }
        }
        if fs_program_input(function) {
            attributes.insert(
                "access_purpose".to_string(),
                AttrValue::String("program_input".into()),
            );
        }
        if fs_content_output(function) {
            attributes.insert(
                "disclosure".to_string(),
                AttrValue::String("contents".into()),
            );
        }
        let recursive = fs_recursive_options(function).is_some_and(|index| {
            call_option_true(call, index, "recursive", &self.object_literal_vars)
        });
        let dest_operation = fs_dest_operation(function);
        // Like `mv`, a rename takes the whole entry: a directory's tree.
        if recursive && dest_operation.is_none()
            || fs_transfer(function) == Some(FsTransferSource::EntryDelete)
        {
            attributes.insert(
                "recursive".to_string(),
                effinterp_proto::AttrValue::Bool(true),
            );
        }
        // Rename/copy also affect a second path.
        let first_slot = self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: resource.clone(),
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
        // A copy pairs its source content read; a rename pairs the source
        // entry delete the `filesystem.move` layer stands for.
        let source_slot = match fs_transfer(function) {
            Some(FsTransferSource::ContentRead) => first_slot,
            Some(FsTransferSource::EntryDelete) => self.builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("filesystem.delete"),
                resource,
                attributes: Default::default(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![node],
            }),
            None => None,
        };
        if let Some(op) = dest_operation
            && let Some((dest, syntax_index)) = logical_call_argument(&call.arguments, 1)
        {
            if dest.is_none()
                && self.logical_call_argument_has_concatenation(&call.arguments, 1, argument_states)
            {
                self.unmodeled_dynamic(
                    call.span,
                    "filesystem argument concatenation is not statically bounded",
                );
            }
            let (resource, uses_cwd, host_environment) =
                self.arg_fs_resource(dest, argument_states.get(syntax_index));
            let node = self.fs_span_node(call.span, uses_cwd, &host_environment);
            let mut destination_attributes = std::collections::BTreeMap::from([(
                "disclosure".to_string(),
                AttrValue::String("contents".into()),
            )]);
            if recursive {
                destination_attributes.insert("recursive".to_string(), AttrValue::Bool(true));
            }
            let destination_slot = self.builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new(op),
                resource,
                attributes: destination_attributes,
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![node],
            });
            if let (Some(source), Some(destination)) = (source_slot, destination_slot) {
                self.builder
                    .transfer_binding(TransferBinding::exact(source, destination));
            }
        }
    }

    fn child_process_call(&mut self, function: &str, call: &CallExpression<'a>) {
        let node = self.span_node(call.span);
        match function {
            "fork" => {
                self.builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new("process.exec"),
                    resource: unresolved_resource("process"),
                    attributes: Default::default(),
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: vec![node],
                });
                self.unresolved_call(call.span, "fork child behavior", Some(&call.callee));
            }
            "exec" | "execSync" => {
                let expr = call.arguments.first().and_then(argument_expr);
                let command = expr.map(|expr| self.expr_to_word(expr));
                let (cmd, node) = match command.as_ref().and_then(Word::as_literal) {
                    Some(cmd) => (cmd.to_string(), node),
                    None => match expr.map(|expr| self.environment_command(expr)) {
                        Some(Ok((cmd, host_environment))) => {
                            (cmd, self.fs_span_node(call.span, false, &host_environment))
                        }
                        Some(Err(variables)) => {
                            self.opaque_needing(
                                call.span,
                                "child_process with non-literal command",
                                variables,
                            );
                            return;
                        }
                        None => {
                            self.opaque(call.span, "child_process with non-literal command");
                            return;
                        }
                    },
                };
                let Some(cwd) = self.child_cwd(call, 1) else {
                    self.opaque(call.span, "child_process cwd option is not a literal path");
                    return;
                };
                let shell = self.child_shell(call, 1).runtime_shell();
                self.nest_child_shell(cmd, node, cwd, shell);
            }
            "execFile" | "execFileSync" | "spawn" | "spawnSync" => {
                let options_index = subprocess_options_index(call, &self.object_literal_vars);
                let Some(cwd) = self.child_cwd(call, options_index) else {
                    self.opaque(call.span, "child_process cwd option is not a literal path");
                    return;
                };
                // Only a shell the options provably disable runs the file as argv.
                let shell = self.child_shell(call, options_index);
                let file = call.arguments.first();
                let file_word = file
                    .and_then(argument_expr)
                    .map(|expr| self.expr_to_word(expr));
                let Some(file_word) = file_word else {
                    self.opaque(call.span, "child_process with non-literal file");
                    return;
                };
                let mut words = vec![file_word];
                // With a shell, the second argument is argv only when the
                // options come third.
                let argv = call
                    .arguments
                    .get(1)
                    .filter(|_| shell == ShellOption::Disabled || options_index == 2);
                match argv {
                    Some(Argument::ArrayExpression(arr)) => {
                        words.extend(self.argv_words_from_array_elements(&arr.elements));
                    }
                    Some(arg) => {
                        if let Some(expr) = argument_expr(arg) {
                            if let Some(extra) = self.tracked_argv_words(expr) {
                                words.extend(extra);
                            } else {
                                words.push(Word::new(vec![WordPart::Unknown]));
                            }
                        } else {
                            words.push(Word::new(vec![WordPart::Unknown]));
                        }
                    }
                    None => {}
                }
                if shell != ShellOption::Disabled {
                    // The shell runs the file and its arguments joined by spaces.
                    let Some(source) = words
                        .iter()
                        .map(Word::as_literal)
                        .collect::<Option<Vec<_>>>()
                    else {
                        self.opaque(call.span, "child_process shell with non-literal command");
                        return;
                    };
                    self.nest_child_shell(source.join(" "), node, cwd, shell.runtime_shell());
                    return;
                }
                self.nest_child_argv(&words, node, cwd);
            }
            _ => {}
        }
    }

    /// Deno and Bun file and subprocess APIs. File calls share the `fs` model;
    /// `Bun.file(path).delete()` deletes the receiver's path.
    fn runtime_call(
        &mut self,
        callee: &super::ModuleCall,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) {
        if let Some(function) = runtime_fs_function(&callee.module, &callee.function) {
            match unparen(&call.callee) {
                Expression::StaticMemberExpression(member) if function == "unlink" => {
                    if let Expression::CallExpression(file) = unparen(&member.object) {
                        self.fs_call(function, file, &[]);
                    }
                }
                _ => self.fs_call(function, call, argument_states),
            }
            return;
        }
        let (argv, options) = match callee.function.as_str() {
            // `new Deno.Command(command, { args: [...] }).output()`
            "Command.output" | "Command.outputSync" | "Command.spawn" => {
                let Expression::StaticMemberExpression(member) = unparen(&call.callee) else {
                    return;
                };
                let Expression::NewExpression(command) = unparen(&member.object) else {
                    return;
                };
                let program = command.arguments.first().and_then(argument_expr);
                let options = command.arguments.get(1).and_then(argument_expr);
                let args = match options.map(|options| object_property_projection(options, "args"))
                {
                    None | Some(ObjectPropertyProjection::Missing) => Some(Vec::new()),
                    Some(ObjectPropertyProjection::Value(Expression::ArrayExpression(args))) => {
                        Some(self.argv_words_from_array_elements(&args.elements))
                    }
                    Some(_) => None,
                };
                let argv = program
                    .zip(args)
                    .map(|(program, args)| [vec![self.expr_to_word(program)], args].concat());
                (argv, options)
            }
            // `Bun.spawn([...], options)` or `Bun.spawn({ cmd: [...], ... })`
            _ => {
                let first = call.arguments.first().and_then(argument_expr);
                let (command, options) = match first.map(unparen) {
                    Some(Expression::ObjectExpression(_)) => {
                        (first.and_then(|first| object_property(first, "cmd")), first)
                    }
                    _ => (first, call.arguments.get(1).and_then(argument_expr)),
                };
                let argv = match command.map(unparen) {
                    Some(Expression::ArrayExpression(argv)) if !argv.elements.is_empty() => {
                        Some(self.argv_words_from_array_elements(&argv.elements))
                    }
                    _ => None,
                };
                (argv, options)
            }
        };
        let Some(argv) = argv else {
            self.opaque(call.span, "runtime subprocess with non-literal argv");
            return;
        };
        let Some(cwd) = self.options_cwd(options) else {
            self.opaque(
                call.span,
                "runtime subprocess cwd option is not a literal path",
            );
            return;
        };
        let node = self.span_node(call.span);
        self.nest_child_argv(&argv, node, cwd);
    }

    /// What a `child_process` `shell` option in the call's `index` argument
    /// selects, resolving names bound to strings.
    fn child_shell(&self, call: &CallExpression<'a>, index: usize) -> ShellOption {
        call_option_shell(call, index, &self.object_literal_vars, &|value| {
            self.expr_to_word(value).as_literal().map(str::to_string)
        })
    }

    /// The directory a `child_process` `cwd` option in the call's `index`
    /// argument starts the child in; see `options_cwd`. That argument may be a
    /// callback instead, and an options object bound to a name keeps only
    /// whether it names a cwd.
    fn child_cwd(&self, call: &CallExpression<'a>, index: usize) -> Option<Option<String>> {
        match logical_call_argument(&call.arguments, index)
            .and_then(|(expr, _)| expr)
            .map(unparen)
        {
            Some(Expression::Identifier(id))
                if self
                    .object_literal_vars
                    .get(id.name.as_str())
                    .is_some_and(|object| object.values.contains_key("cwd")) =>
            {
                None
            }
            Some(options @ Expression::ObjectExpression(_)) => self.options_cwd(Some(options)),
            _ => Some(None),
        }
    }

    /// The directory a subprocess `cwd` option starts the child in:
    /// `Some(None)` when the options name no cwd, so the child inherits the
    /// program's, and `Some(Some(dir))` for a literal path resolved against the
    /// program's current cwd. A cwd that is not a literal path is `None`: the
    /// child's relative paths then have no known directory.
    fn options_cwd(&self, options: Option<&Expression<'a>>) -> Option<Option<String>> {
        let value = match options.map(|options| object_property_projection(options, "cwd")) {
            None | Some(ObjectPropertyProjection::Missing) => return Some(None),
            Some(ObjectPropertyProjection::Value(value)) => value,
            Some(ObjectPropertyProjection::Unbounded) => return None,
        };
        if matches!(unparen(value), Expression::Identifier(id) if id.name == "undefined")
            || matches!(unparen(value), Expression::NullLiteral(_))
        {
            return Some(None);
        }
        match crate::paths::resolve_fs_path_with_cwd(
            self.expr_to_word(value).as_literal()?,
            self.runtime_cwd_resource.clone(),
        ) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if path.starts_with('/') => Some(Some(path)),
            _ => None,
        }
    }

    /// Start a child in `cwd` when a subprocess option names one, otherwise in
    /// the program's current cwd. An option's directory, like a proven chdir's,
    /// has no repository namespace.
    fn child_transition(
        &self,
        transition: Transition,
        cwd: Option<String>,
        node: ProvenanceRef,
    ) -> Transition {
        match cwd {
            Some(cwd) => transition
                .exec_cwd(Some(&cwd))
                .source_cwd(None)
                .runtime_cwd(None)
                .cwd(
                    crate::paths::resolve_fs_path_with_cwd(&cwd, None),
                    Some(node),
                ),
            None => self.after_chdir(transition),
        }
    }

    /// Whether the host shows `path` absent and this plan has not changed it.
    /// A child whose cwd is absent fails to spawn with ENOENT and never runs.
    fn host_path_missing(&self, path: &str) -> bool {
        matches!(
            self.builder.written_source(path, |_, _| false),
            crate::builder::WrittenSource::Host
        ) && matches!(
            self.builder.budget().observe_path(path),
            effinterp_proto::ObservationOutcome::Path(fact)
                if fact.kind == effinterp_proto::PathKind::Missing
        )
    }

    /// Run `source` in a child shell started from `cwd` or the program's current cwd.
    fn nest_child_shell(
        &mut self,
        source: String,
        node: ProvenanceRef,
        cwd: Option<String>,
        shell: Option<RuntimeShell>,
    ) {
        if cwd
            .as_deref()
            .is_some_and(|cwd| self.host_path_missing(cwd))
        {
            return;
        }
        let transition = self.child_transition(
            Transition::file(Subject::Shell {
                source,
                cwd: cwd
                    .clone()
                    .or_else(|| self.current_cwd().map(str::to_string)),
                context: Default::default(),
            })
            .runtime_shell(shell)
            .source_cwd(self.nest.current_runtime_cwd().as_deref())
            .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
            .cwd(
                self.builder.current_execution_cwd(),
                self.nest.current_cwd_node(),
            ),
            cwd,
            node,
        );
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    /// Launch `words` as a child process started from `cwd` or the program's current cwd.
    fn nest_child_argv(&mut self, words: &[Word], node: ProvenanceRef, cwd: Option<String>) {
        if cwd
            .as_deref()
            .is_some_and(|cwd| self.host_path_missing(cwd))
        {
            return;
        }
        let transition = self.child_transition(
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(self.current_cwd())
                .cwd(
                    self.builder.current_execution_cwd(),
                    (self.nest.current_runtime_cwd().as_deref() == self.runtime_cwd)
                        .then(|| self.nest.current_cwd_node())
                        .flatten(),
                )
                .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
            cwd,
            node,
        );
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    fn argv_words_from_array_elements(&self, elements: &[ArrayExpressionElement<'a>]) -> Vec<Word> {
        let mut words = Vec::new();
        for element in elements {
            match element {
                ArrayExpressionElement::SpreadElement(spread) => {
                    words.extend(self.argv_words_from_spread(&spread.argument));
                }
                ArrayExpressionElement::Elision(_) => {
                    words.push(Word::new(vec![WordPart::Unknown]));
                }
                element => {
                    if let Some(expr) = element.as_expression() {
                        words.push(self.expr_to_word(expr));
                    } else {
                        words.push(Word::new(vec![WordPart::Unknown]));
                    }
                }
            }
        }
        words
    }

    fn argv_words_from_spread(&self, expr: &Expression<'a>) -> Vec<Word> {
        match unparen(expr) {
            Expression::ArrayExpression(arr) => self.argv_words_from_array_elements(&arr.elements),
            expr => self
                .tracked_argv_words(expr)
                .unwrap_or_else(|| vec![Word::new(vec![WordPart::Unknown])]),
        }
    }

    fn consecutive_argv_words(&self, prefix: &str) -> Vec<Word> {
        let mut words = Vec::new();
        for index in 0..TRACKED_ARGV_INDEX_LIMIT {
            let key = format!("{prefix}{index}");
            match self.source_env.get(&key) {
                Some(resource) => words.push(resource_to_word(resource)),
                None if self.unbounded_source_env.contains(&key) => {
                    words.push(Word::new(vec![WordPart::Unknown]));
                }
                None => break,
            }
        }
        // A recovered-but-oversized argv must not drop the tail silently:
        // one Unknown word lets the command model degrade its own domains.
        if words.len() == TRACKED_ARGV_INDEX_LIMIT {
            let overflow = format!("{prefix}{TRACKED_ARGV_INDEX_LIMIT}");
            if self.source_env.contains_key(&overflow)
                || self.unbounded_source_env.contains(&overflow)
            {
                words.push(Word::new(vec![WordPart::Unknown]));
            }
        }
        words
    }

    fn tracked_argv_words(&self, expr: &Expression<'a>) -> Option<Vec<Word>> {
        let Expression::Identifier(id) = unparen(expr) else {
            return None;
        };
        let name = id.name.as_str();
        let mut words = self.consecutive_argv_words(&format!("{name}."));
        let tail = self.consecutive_argv_words(&format!("{name}.{SOURCE_SPREAD_TAIL}."));
        let wildcard = source_wildcard_key(name);
        let unknown_spread = self.unbounded_source_env.contains(&wildcard)
            || self.source_env.contains_key(&wildcard)
            || !tail.is_empty();
        if unknown_spread {
            // Keep a visible hole for the unknown-length spread, then any
            // literals that followed it, so neither side is dropped silently.
            words.push(Word::new(vec![WordPart::Unknown]));
            words.extend(tail);
        }
        if words.is_empty() { None } else { Some(words) }
    }

    pub(super) fn expr_to_word(&self, expr: &Expression<'a>) -> Word {
        if !self.builder.current_execution_argv().is_empty()
            && let Some(resource) = super::source_string::source_string_resource(
                expr,
                &self.source_env,
                &self.unbounded_source_env,
                self.process_runtime,
                &self.evaluated_source_strings,
            )
        {
            return crate::nest::argument_word(&resource);
        }
        match unparen(expr) {
            Expression::StringLiteral(s) => Word::literal(s.value.as_str()),
            Expression::TemplateLiteral(t) if t.expressions.is_empty() => {
                resolve::cooked_template_string(t)
                    .map(Word::literal)
                    .unwrap_or_else(|| Word::new(vec![WordPart::Unknown]))
            }
            Expression::Identifier(id) => {
                if let Some(resource) = super::source_string::source_string_resource(
                    expr,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                ) {
                    return resource_to_word(&resource);
                }
                match self.param_env.get(id.name.as_str()) {
                    Some(resource) => resource_to_word(resource),
                    None => Word::new(vec![WordPart::Unknown]),
                }
            }
            _ => Word::new(vec![WordPart::Unknown]),
        }
    }

    /// Whether an expression evaluates to a server handle: a tracked local, or
    /// a direct `<x>.createServer(...)` chain.
    fn is_server_handle(&self, expr: &Expression<'a>) -> bool {
        match unparen(expr) {
            Expression::Identifier(id) => self.server_vars.contains(id.name.as_str()),
            other => is_create_server(other),
        }
    }

    fn network_call(
        &mut self,
        function: &str,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) {
        let node = self.span_node(call.span);
        let argument = logical_call_argument(&call.arguments, 0);
        let argument_state =
            argument.and_then(|(_, syntax_index)| argument_states.get(syntax_index));
        let resource = match argument.and_then(|(expr, _)| expr) {
            Some(expr) => match self.sink_string_concatenation(expr, "network", argument_state) {
                Some(resource) => resource,
                None => {
                    if self.is_string_concatenation_at(expr, argument_state) {
                        self.unmodeled_dynamic(
                            call.span,
                            "network argument concatenation is not statically bounded",
                        );
                    }
                    match unparen(expr) {
                        Expression::Identifier(id) => argument_state
                            .map_or(&self.source_env, |state| &state.source_env)
                            .get(id.name.as_str())
                            .and_then(|resource| match resource {
                                ResourceExpr::Literal { value } => {
                                    Some(network_source_literal(value))
                                }
                                _ => None,
                            })
                            .unwrap_or_else(|| resolve::url_resource(expr)),
                        _ => resolve::url_resource(expr),
                    }
                }
            },
            _ => {
                if self.logical_call_argument_has_concatenation(&call.arguments, 0, argument_states)
                {
                    self.unmodeled_dynamic(
                        call.span,
                        "network argument concatenation is not statically bounded",
                    );
                }
                unresolved_resource("network")
            }
        };
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(network_call_operation(function, call)),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    pub(super) fn env_effect(&mut self, operation: &str, name: &str, unset: bool, span: Span) {
        if name.is_empty() {
            self.unknown_env_effect(operation, unset, span);
            return;
        }
        let node = self.span_node(span);
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            },
            attributes: unset
                .then(|| ("unset".to_string(), AttrValue::Bool(true)))
                .into_iter()
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    pub(super) fn unknown_env_effect(&mut self, operation: &str, unset: bool, span: Span) {
        let node = self.span_node(span);
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: unresolved_resource("environment"),
            attributes: unset
                .then(|| ("unset".to_string(), AttrValue::Bool(true)))
                .into_iter()
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    /// A whole-environment read (`process.env` handed to a callee).
    pub(super) fn whole_env_read(&mut self, span: Span) {
        let node = self.span_node(span);
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: unresolved_resource("environment"),
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    pub(super) fn unsupported_process_receiver(&mut self, span: Span) {
        if self.unsupported_process_receiver_reported {
            return;
        }
        self.unsupported_process_receiver_reported = true;
        let node = self.span_node(span);
        self.builder
            .declare_coverage(Domain::new("environment"), CoverageLevel::Partial);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: vec![node],
            limit: None,
            detail: Some("process receiver is not runtime-backed".to_string()),
        });
    }

    /// Enter source this program evaluates at runtime as a nested program of
    /// the same language and dialect.
    fn nest_eval_source(&mut self, source: &str, span: Span) {
        let node = self.span_node(span);
        let transition = self.after_chdir(
            Transition::file(Subject::Source {
                language: "js".to_string(),
                dialect: Some(self.dialect),
                source: source.to_string(),
                cwd: self.current_cwd().map(str::to_string),
                context: Default::default(),
            })
            .source_cwd(self.nest.current_source_cwd().as_deref())
            .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
            .cwd(
                self.builder.current_execution_cwd(),
                self.nest.current_cwd_node(),
            ),
        );
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    /// `fs.open(path, flags)` opens the path for reading, writing, or both.
    /// The signature is `open(path[, flags[, mode]], callback)`, so a function
    /// in the flags position means the call took Node's `"r"` default. Any
    /// other unrecoverable flags value leaves the access undecided.
    fn fs_open_call(&mut self, call: &CallExpression<'a>, argument_states: &[SourceStringState]) {
        let target = logical_call_argument(&call.arguments, 0);
        let (resource, uses_cwd, host_environment) = self.arg_fs_resource(
            target.and_then(|(expr, _)| expr),
            target.and_then(|(_, syntax_index)| argument_states.get(syntax_index)),
        );
        let node = self.fs_span_node(call.span, uses_cwd, &host_environment);
        let given = logical_call_argument(&call.arguments, 1).and_then(|(expr, _)| expr);
        let flags = given.and_then(|expr| self.expr_to_word(expr).as_literal().map(str::to_string));
        if flags.is_none()
            && given.is_some_and(|expr| {
                !matches!(
                    unparen(expr),
                    Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
                )
            })
        {
            self.unmodeled_dynamic(call.span, "fs.open flags are not statically bounded");
        }
        let (read, write) = fs_open_access(flags.as_deref());
        if read {
            self.fs_effect("filesystem.read", resource.clone(), false, node);
        }
        if write {
            self.fs_effect(
                "filesystem.write",
                resource,
                flags.as_deref().is_some_and(|flags| flags.contains('a')),
                node,
            );
        }
    }

    /// A hard link creates a second name for the source inode, so it keeps
    /// the same metadata source and exact relation as `ln`. A symbolic link
    /// records only its kind on the new directory entry.
    fn fs_link_call(
        &mut self,
        function: &str,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) {
        let symbolic = function.starts_with("symlink");
        let [source, destination] = [0, 1].map(|index| {
            let argument = logical_call_argument(&call.arguments, index);
            if argument.is_some_and(|(expr, _)| expr.is_none())
                && self.logical_call_argument_has_concatenation(
                    &call.arguments,
                    index,
                    argument_states,
                )
            {
                self.unmodeled_dynamic(
                    call.span,
                    "filesystem argument concatenation is not statically bounded",
                );
            }
            self.arg_fs_resource(
                argument.and_then(|(expr, _)| expr),
                argument.and_then(|(_, syntax_index)| argument_states.get(syntax_index)),
            )
        });
        let (destination, uses_cwd, host_environment) = destination;
        let node = self.fs_span_node(call.span, uses_cwd, &host_environment);
        let destination = self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("filesystem.create"),
            resource: destination,
            attributes: symbolic
                .then(|| ("symlink".to_string(), AttrValue::Bool(true)))
                .into_iter()
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
        let (source, uses_cwd, host_environment) = source;
        if symbolic
            || !matches!(
                source,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { .. }
                }
            )
        {
            return;
        }
        let node = self.fs_span_node(call.span, uses_cwd, &host_environment);
        let source = self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("filesystem.read"),
            resource: source,
            attributes: [("metadata".to_string(), AttrValue::Bool(true))].into(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
        if let (Some(source), Some(destination)) = (source, destination) {
            self.builder
                .transfer_binding(TransferBinding::exact(source, destination));
        }
    }

    fn fs_effect(
        &mut self,
        operation: &str,
        resource: ResourceExpr,
        append: bool,
        node: ProvenanceRef,
    ) {
        self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: append
                .then(|| ("append".to_string(), AttrValue::Bool(true)))
                .into_iter()
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    /// Replace an environment reference with the value the host supplied for
    /// it, so a path built from `process.env.HOME` resolves as precisely as
    /// the same path written out. Every substituted name contributes the
    /// provenance of the binding it came from.
    fn resolve_host_environment(
        &mut self,
        resource: &mut ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) {
        match resource {
            ResourceExpr::Environment { name } => {
                let Some(value) = self.host_environment_value(name) else {
                    return;
                };
                if let Some(node) = self.nest.current_environment_node(name) {
                    provenance.push(node);
                } else {
                    provenance.push(self.builder.node(
                        ProvenanceKind::HostContext {
                            name: format!("env.{name}"),
                        },
                        &[],
                    ));
                }
                *resource = value;
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                for part in parts {
                    self.resolve_host_environment(part, provenance);
                }
            }
            ResourceExpr::Property { base, .. } => self.resolve_host_environment(base, provenance),
            _ => {}
        }
    }

    /// A shell command string built from literals and environment values,
    /// such as `"rm -rf " + os.homedir()`. Its text, with the host-context
    /// nodes it read, once the host supplies every variable in it; otherwise
    /// the variables still unsupplied, so the host can be asked for them.
    fn environment_command(
        &mut self,
        expr: &Expression<'a>,
    ) -> Result<(String, Vec<ProvenanceRef>), Vec<String>> {
        let Some(mut resource) = super::source_string::source_string_resource(
            expr,
            &self.source_env,
            &self.unbounded_source_env,
            self.process_runtime,
            &self.evaluated_source_strings,
        ) else {
            return Err(Vec::new());
        };
        let mut provenance = Vec::new();
        self.resolve_host_environment(&mut resource, &mut provenance);
        let parts = match resource {
            ResourceExpr::Join { parts } => parts,
            resource => vec![resource],
        };
        let mut text = String::new();
        let mut unsupplied = Vec::new();
        let mut unknown = false;
        for part in parts {
            match part {
                ResourceExpr::Literal { value } => text.push_str(&value),
                ResourceExpr::Environment { name } => unsupplied.push(name),
                _ => unknown = true,
            }
        }
        match (unknown, unsupplied.is_empty()) {
            (false, true) => Ok((text, provenance)),
            (false, false) => Err(unsupplied),
            (true, _) => Err(Vec::new()),
        }
    }

    /// The effective value of one environment name, preferring an override the
    /// enclosing execution established over the value the host supplied.
    fn host_environment_value(&self, name: &str) -> Option<ResourceExpr> {
        // Under literal writes alone, a variable still symbolic here was read
        // before every write to it, so it holds the host's value.
        if (self.bindings.environment_is_rewritten()
            && !self.bindings.environment_rewrites_are_literal())
            || self.nest.current_environment_unsets().contains(name)
        {
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

    fn arg_fs_resource(
        &mut self,
        expr: Option<&Expression<'a>>,
        state: Option<&SourceStringState>,
    ) -> (ResourceExpr, bool, Vec<ProvenanceRef>) {
        let (resource, uses_cwd) = self.arg_fs_resource_expr(expr, state);
        let mut resource = resource;
        let mut provenance = Vec::new();
        self.resolve_host_environment(&mut resource, &mut provenance);
        resource = match resource {
            // A whole-path variable the host supplied is the path itself. One
            // it did not supply stays symbolic, which asks the host for it.
            ResourceExpr::Literal { value } if !provenance.is_empty() => {
                crate::paths::resolve_fs_path_with_cwd(&value, self.runtime_cwd_resource.clone())
            }
            resource if !provenance.is_empty() => {
                effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix)
            }
            resource => resource,
        };
        (resource, uses_cwd, provenance)
    }

    fn arg_fs_resource_expr(
        &mut self,
        expr: Option<&Expression<'a>>,
        state: Option<&SourceStringState>,
    ) -> (ResourceExpr, bool) {
        match expr {
            Some(expr) => {
                let resource = match self.sink_string_concatenation(expr, "filesystem", state) {
                    Some(resource) => resource,
                    None => {
                        if self.is_string_concatenation_at(expr, state) {
                            self.unmodeled_dynamic(
                                expr.span(),
                                "filesystem argument concatenation is not statically bounded",
                            );
                        }
                        resolve::fs_resource(
                            expr,
                            self.runtime_cwd_resource.clone(),
                            self.source_cwd,
                            state.map_or(&self.param_env, |state| &state.param_env),
                            self.bindings,
                        )
                    }
                };
                let without_cwd = resolve::fs_resource(
                    expr,
                    None,
                    self.source_cwd,
                    &self.cwd_param_env,
                    self.bindings,
                );
                (resource, fs_resource_uses_cwd(&without_cwd))
            }
            None => (unresolved_resource("filesystem"), false),
        }
    }

    fn fs_span_node(
        &mut self,
        span: Span,
        uses_cwd: bool,
        host_environment: &[ProvenanceRef],
    ) -> ProvenanceRef {
        let mut antecedents = self.scope.as_slice().to_vec();
        if uses_cwd {
            antecedents.extend(self.cwd_node);
        }
        antecedents.extend_from_slice(host_environment);
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: span.start,
                end: span.end,
            },
            &antecedents,
        )
    }
}

/// Classify modeled JavaScript HTTP calls by their literal method or request body.
fn network_call_operation(function: &str, call: &CallExpression<'_>) -> &'static str {
    let options = match function {
        "fetch" => call.arguments.get(1).and_then(argument_expr),
        "request" => call
            .arguments
            .first()
            .and_then(argument_expr)
            .filter(|expr| matches!(unparen(expr), Expression::ObjectExpression(_)))
            .or_else(|| call.arguments.get(1).and_then(argument_expr)),
        _ => None,
    };
    let uploads = options.is_some_and(|options| {
        object_property(options, "method")
            .and_then(|method| match unparen(method) {
                Expression::StringLiteral(value) => Some(value.value.as_str()),
                _ => None,
            })
            .is_some_and(|method| {
                ["POST", "PUT", "PATCH"]
                    .iter()
                    .any(|write| method.eq_ignore_ascii_case(write))
            })
            || object_property(options, "body").is_some()
    });
    if uploads {
        "network.upload"
    } else {
        "network.request"
    }
}

/// Whether a callee's base is a known-inert built-in (see `INERT_CALLEES`).
pub(super) fn is_inert_callee(callee: &Expression) -> bool {
    match callee {
        Expression::Identifier(id) => INERT_CALLEES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(m) => is_inert_base(&m.object),
        Expression::ComputedMemberExpression(_) => false,
        _ => false,
    }
}

fn is_inert_base(obj: &Expression) -> bool {
    match unparen(obj) {
        Expression::Identifier(id) => INERT_CALLEES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(m) => is_inert_base(&m.object),
        Expression::ComputedMemberExpression(_) => false,
        // `Promise.resolve().then(...)` — chain off an inert base.
        Expression::CallExpression(c) => {
            !matches!(unparen(&c.callee), Expression::Identifier(id) if id.name == "require")
                && is_inert_base(&c.callee)
        }
        _ => false,
    }
}

fn resource_to_word(expr: &ResourceExpr) -> Word {
    match expr {
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

/// Whether call argument `index` resolves to an options object with `{ key: true }`.
pub(super) fn call_option_true(
    call: &CallExpression,
    index: usize,
    key: &str,
    bindings: &ObjectLiteralBindings,
) -> bool {
    call_option(call, index, key, bindings)
        .is_some_and(|value| matches!(value, StaticOptionValue::Bool(true)))
}

fn call_option<'a>(
    call: &'a CallExpression<'a>,
    index: usize,
    key: &str,
    bindings: &ObjectLiteralBindings,
) -> Option<StaticOptionValue> {
    let expr = logical_call_argument(&call.arguments, index)?.0?;
    match unparen(expr) {
        Expression::Identifier(id) => bindings
            .get(id.name.as_str())
            .and_then(|o| o.values.get(key))
            .cloned(),
        Expression::ObjectExpression(_) => object_literal(expr, bindings)?.values.get(key).cloned(),
        _ => None,
    }
}

/// The argument holding a `spawn` or `execFile` call's options: the second
/// is the argv when it is an array or a name not bound to an options object.
pub(super) fn subprocess_options_index(
    call: &CallExpression<'_>,
    bindings: &ObjectLiteralBindings,
) -> usize {
    if logical_call_argument(&call.arguments, 1)
        .and_then(|(expr, _)| expr)
        .is_some_and(|expr| match unparen(expr) {
            Expression::ArrayExpression(_) => true,
            Expression::Identifier(id) => !bindings.contains_key(id.name.as_str()),
            _ => false,
        })
    {
        2
    } else {
        1
    }
}

/// What a `child_process` `shell` option selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ShellOption {
    /// No shell for `spawn` and `execFile`; `/bin/sh` for `exec`: the option
    /// is absent, false, or the argument is a callback.
    Disabled,
    /// `shell: true`: `/bin/sh`.
    Default,
    /// A literal shell program.
    Program(String),
    /// A value Nah cannot recover, which may enable a shell or not.
    Unresolved,
}

impl ShellOption {
    /// The shell selected in place of `/bin/sh`, when a shell runs.
    pub(super) fn runtime_shell(self) -> Option<RuntimeShell> {
        match self {
            Self::Disabled | Self::Default => None,
            Self::Program(program) => Some(RuntimeShell::Program(program)),
            Self::Unresolved => Some(RuntimeShell::Unresolved),
        }
    }
}

/// The `shell` option in call argument `index`. A property is known only
/// when no later open spread could override it; `string` resolves a value
/// such as a name bound to a string.
pub(super) fn call_option_shell<'a>(
    call: &CallExpression<'a>,
    index: usize,
    bindings: &ObjectLiteralBindings,
    string: &dyn Fn(&Expression<'a>) -> Option<String>,
) -> ShellOption {
    let Some(options) = logical_call_argument(&call.arguments, index)
        .and_then(|(expr, _)| expr)
        .map(unparen)
    else {
        return ShellOption::Disabled;
    };
    let value = match options {
        Expression::Identifier(id) => {
            let Some(object) = bindings.get(id.name.as_str()) else {
                return ShellOption::Unresolved;
            };
            return match object.values.get("shell") {
                Some(StaticOptionValue::Bool(true)) => ShellOption::Default,
                Some(StaticOptionValue::Bool(false)) => ShellOption::Disabled,
                Some(StaticOptionValue::String(shell)) => ShellOption::Program(shell.clone()),
                Some(StaticOptionValue::Unresolved) => ShellOption::Unresolved,
                None if object.open => ShellOption::Unresolved,
                None => ShellOption::Disabled,
            };
        }
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            return ShellOption::Disabled;
        }
        options => match object_property_projection(options, "shell") {
            ObjectPropertyProjection::Value(value) => value,
            ObjectPropertyProjection::Missing => return ShellOption::Disabled,
            ObjectPropertyProjection::Unbounded => return ShellOption::Unresolved,
        },
    };
    match unparen(value) {
        Expression::BooleanLiteral(value) if value.value => ShellOption::Default,
        Expression::BooleanLiteral(_) | Expression::NullLiteral(_) => ShellOption::Disabled,
        Expression::Identifier(id) if id.name == "undefined" => ShellOption::Disabled,
        Expression::StringLiteral(value) => ShellOption::Program(value.value.to_string()),
        value => string(value).map_or(ShellOption::Unresolved, ShellOption::Program),
    }
}

pub(super) fn shell_command_source(call: &CallExpression<'_>) -> Option<String> {
    let mut words = vec![literal_string(call.arguments.first()?.as_expression()?)?];
    if let Some(Expression::ArrayExpression(arguments)) = call
        .arguments
        .get(1)
        .and_then(Argument::as_expression)
        .map(unparen)
    {
        for argument in &arguments.elements {
            words.push(literal_string(argument.as_expression()?)?);
        }
    }
    Some(words.join(" "))
}

fn literal_string(expr: &Expression<'_>) -> Option<String> {
    match unparen(expr) {
        Expression::StringLiteral(value) => Some(value.value.as_str().to_string()),
        Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
            resolve::cooked_template_string(value)
        }
        _ => None,
    }
}

pub(super) fn inert_base_name<'a>(expr: &'a Expression<'_>) -> Option<&'a str> {
    match unparen(expr) {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(m) => inert_base_name(&m.object),
        Expression::ComputedMemberExpression(m) => inert_base_name(&m.object),
        Expression::CallExpression(c) => inert_base_name(&c.callee),
        _ => None,
    }
}
