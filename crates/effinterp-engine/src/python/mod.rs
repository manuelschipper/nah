//! Effect-directed Python frontend.
//!
//! Parses Python source with `rustpython-parser` (v0.4; the newer `ruff`
//! parser requires a toolchain past this workspace's pin) and walks the AST
//! for calls into known effect APIs — `open`, `os`, `shutil`, `pathlib`,
//! `subprocess`, `requests`/`urllib`. It does not interpret Python; it follows
//! only what reaches an effect boundary, keeps non-literal arguments symbolic,
//! and records an explicit boundary for anything dynamic (`eval`, `exec`,
//! `getattr`, `__import__`).

mod argv;
mod control;
mod imports;
pub(crate) mod ipython;
mod model;
mod registration;
mod resolve;
mod runtime;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
pub(crate) use imports::{PythonImportCache, PythonImportSearch};
pub(crate) use runtime::runtime_imports;
mod summary;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference,
    CoverageLevel, Domain, Effect, ExecutionEdgeKind, Modality, Operation, PathPlatform,
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceFamily, ResourceIdentity, Subject,
    normalize_resource,
};
use rustpython_parser::ast::{self, Constant, Expr, Ranged, Stmt};
use rustpython_parser::{Parse, text_size::TextRange};

use crate::builder::{PlanBuilder, RuntimeShell};
use crate::control_flow::{ControlExit, ControlFact, ControlFlow, Requirements, SiteFacts};
use crate::external::{PYTHON_MODELED_ROOTS, is_python_stdlib};
use crate::flow::StageWriter;
use crate::module_summary::{CallEdge, ClassEntry, ImportBinding, call_results};
use crate::nest::{Nest, Transition, word_resource};
use crate::paths::{fs_resource_uses_cwd, resolve_fs_path};
use crate::resource_transfer::TransferBinding;
use crate::summary::{Summary, substitute_resource_expr};
use crate::word::{Word, WordPart};
use crate::{
    ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef, ValueArgument,
    ValueOrigin, bind_arguments, merge_arguments, positional_arguments, substitute_value,
};
use model::{Receiver, ReceiverKind, path_object_resource};
use resolve::{Imports, str_literal};

/// Effect domains this frontend can surface. Calls the walker cannot classify
/// downgrade their reachable domains at the call site.
const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

/// Members made visible by star imports from modules owned by this frontend.
const STAR_EXPORTS: &[(&str, &[&str])] = &[
    (
        "os",
        &[
            "remove",
            "unlink",
            "rmdir",
            "removedirs",
            "mkdir",
            "makedirs",
            "rename",
            "replace",
            "chmod",
            "chown",
            "lchown",
            "chdir",
            "stat",
            "lstat",
            "listdir",
            "scandir",
            "truncate",
            "getenv",
            "environ",
            "putenv",
            "unsetenv",
            "setenv",
            "system",
            "popen",
            "exec",
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
            "posix_spawn",
            "posix_spawnp",
        ],
    ),
    (
        "shutil",
        &["rmtree", "copy", "copy2", "copyfile", "copytree", "move"],
    ),
    (
        "subprocess",
        &[
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "getoutput",
            "getstatusoutput",
        ],
    ),
    (
        "pathlib",
        &["Path", "PurePath", "PosixPath", "PurePosixPath"],
    ),
    (
        "requests",
        &[
            "get", "post", "put", "delete", "patch", "head", "options", "request", "Session",
            "session",
        ],
    ),
    (
        "httpx",
        &[
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "head",
            "options",
            "request",
            "stream",
            "Client",
            "AsyncClient",
        ],
    ),
    ("urllib.request", &["urlopen", "urlretrieve"]),
];

fn star_exports(module: &str) -> Option<&'static [&'static str]> {
    STAR_EXPORTS
        .iter()
        .find_map(|(name, exports)| (*name == module).then_some(*exports))
}

/// Cap on effects retained in one function summary, so a pathological function
/// (or an unconverged recursive one) cannot make a summary grow without bound.
const MAX_SUMMARY_EFFECTS: usize = 128;
const MAX_SUMMARY_BOUNDARIES: usize = 128;

/// A module-level function definition: name, parameter names, body.
struct Def {
    name: String,
    local_name: String,
    parent: Option<String>,
    params: Vec<String>,
    // Includes variadic and implicit receiver names omitted from call binding.
    parameter_bindings: Vec<String>,
    positional_param_count: usize,
    callable_defaults: Vec<Option<String>>,
    param_defaults: Vec<Option<Rc<Expr>>>,
    param_types: Vec<(String, String)>,
    owner: Option<String>,
    body: Rc<Vec<Stmt>>,
    parameter_attr_writes: Vec<(String, String)>,
    decorators: Vec<String>,
    is_async: bool,
    is_generator: bool,
}

#[derive(Clone)]
struct InitAttrValue {
    owner: String,
    attr: String,
    value: Rc<Expr>,
}

/// Effects, boundaries, and coverage collected while summarizing a function
/// body (instead of emitting them to the plan). `calls` records the function's
/// direct calls to user functions (local or imported) for cross-file linking.
#[derive(Default)]
struct Capture {
    rebound_callables: HashSet<String>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    effect_models: Vec<Vec<String>>,
    source_spans: Vec<TextRange>,
    boundaries: Vec<Boundary>,
    coverage: Vec<(Domain, CoverageLevel)>,
    calls: Vec<CallEdge>,
    /// Caller parameters whose attributes are written through local calls.
    parameter_attr_writes: Vec<(String, String)>,
    /// Resource returned on every path, inferred while local bindings remain live.
    returns: Option<ResourceExpr>,
    /// The network-object kind the function returns, when every `return` yields
    /// the same constructed receiver — so `s = make_session()` binds `s`.
    return_receiver: Option<ReceiverKind>,
    /// Per-tuple-element class of the returned value when every return yields
    /// the same unambiguously constructed class(es). See
    /// [`crate::module_summary::FunctionEntry::returns_instances`].
    returns_instances: Vec<Option<String>>,
    /// Per-tuple-element exact external type of the returned instance.
    return_types: Vec<Option<TypeRef>>,
    /// Per-tuple-element local binding returned on every path.
    return_bindings: Vec<Option<String>>,
    /// Same-file subprocesses nested at the call site after substitution.
    deferred_spawns: Vec<DeferredSpawn>,
    /// The body's resolved control flow over `effects` and `calls`.
    control_flow: ControlFlow,
    /// What the body guarantees to a same-file caller.
    requirements: Option<Requirements>,
    /// Local names and the `effects` slots whose bytes their value may
    /// carry, for an output call in the body.
    print_vars: std::collections::HashMap<String, Vec<u32>>,
    /// `effects` slots a `print` in the body writes to stdout, each with the
    /// print's condition within the body.
    stdout: Vec<PrintedEffects>,
}

/// Summary effect slots whose bytes reach stdout, on the paths the condition
/// allows.
type PrintedEffects = (Vec<u32>, Option<effinterp_proto::Condition>);

/// How a call's evaluation was modeled, for its control-flow site.
enum CallControl {
    /// A modeled API or inert builtin: it returns, producing what it produced.
    Modeled,
    /// A same-file callee applied through its summary.
    Local,
    /// Code nothing models, which may complete the invocation.
    Opaque,
}

/// A subprocess captured inside a function summary. Same-file calls substitute
/// parameter bindings and nest; cross-file summaries materialize today's
/// `process.exec` plus `uncomposed_subprocess`.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum DeferredSpawn {
    Exec {
        argv: DeferredArgv,
        cwd: Option<ResourceExpr>,
        cwd_uses_ambient: bool,
    },
    Shell {
        source: ResourceExpr,
        cwd: Option<ResourceExpr>,
        cwd_uses_ambient: bool,
        /// The shell `executable=` names in place of `/bin/sh`.
        shell: Option<ResourceExpr>,
        dynamic_detail: String,
    },
    /// A command the program runs in its own process through a command
    /// model's dispatcher (Django's `execute_from_command_line`). Its words
    /// come from the launch argv, never from a parameter.
    Command { argv: Vec<String> },
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum DeferredArgv {
    /// Explicit argv words (`subprocess.run(["git", cmd])`).
    Words(Vec<ResourceExpr>),
    /// The whole argv is one value (`subprocess.run(cmd)`).
    Sequence(ResourceExpr),
}

/// Cap on call edges retained per function, to bound extraction output.
const MAX_CALL_EDGES: usize = 128;

/// Effects of methods on instances whose constructor has an exact external
/// Python type. The receiver resource is supplied separately from arguments.
pub fn python_external_method_effects(
    receiver_type: &str,
    method: &str,
    receiver_resource: Option<ResourceExpr>,
    args: &[ValueArgument],
) -> Option<Vec<Effect>> {
    model::external_method_effects(receiver_type, method, receiver_resource, args)
}

/// Whether an `if` test is `TYPE_CHECKING` / `typing.TYPE_CHECKING` — a block
/// the interpreter never executes (it exists for the type checker only).
fn is_type_checking_test(test: &Expr) -> bool {
    match test {
        Expr::Name(n) => n.id.as_str() == "TYPE_CHECKING",
        Expr::Attribute(a) => a.attr.as_str() == "TYPE_CHECKING",
        _ => false,
    }
}

/// Whether an `if` test is the `__name__ == "__main__"` entrypoint guard.
fn is_main_guard_test(test: &Expr) -> bool {
    let Expr::Compare(cmp) = test else {
        return false;
    };
    let [right] = cmp.comparators.as_slice() else {
        return false;
    };
    cmp.ops.as_slice() == [ast::CmpOp::Eq]
        && ((matches!(cmp.left.as_ref(), Expr::Name(n) if n.id.as_str() == "__name__")
            && str_literal(right).as_deref() == Some("__main__"))
            || (matches!(right, Expr::Name(n) if n.id.as_str() == "__name__")
                && str_literal(&cmp.left).as_deref() == Some("__main__")))
}

/// Split top-level statements into those the module executes on import and
/// those under a `__main__` guard (entrypoint-only). TYPE_CHECKING bodies are
/// dropped entirely; each guard's `else` arm executes on import.
/// The `print` arguments whose text it writes: every positional argument,
/// `end`, and `sep` when it separates more than one value.
fn print_emitted(call: &ast::ExprCall) -> Vec<&Expr> {
    let separated = call.args.len() > 1
        || call
            .args
            .iter()
            .any(|argument| matches!(argument, Expr::Starred(_)));
    call.args
        .iter()
        .chain(
            call.keywords
                .iter()
                .filter_map(|keyword| match keyword.arg.as_deref() {
                    Some("end") => Some(&keyword.value),
                    Some("sep") if separated => Some(&keyword.value),
                    _ => None,
                }),
        )
        .collect()
}

/// The call spans and local names an expression's value is produced by, as
/// the def-use walk reads it: the call itself, the receiver call a wrapper
/// such as `open(p).read()` passes through, a response's `.text`/`.content`,
/// and the elements of a literal container.
fn value_spine<'e>(expr: &'e Expr, spans: &mut Vec<TextRange>, names: &mut Vec<&'e str>) {
    match expr {
        Expr::Name(name) => names.push(name.id.as_str()),
        Expr::Call(call) => {
            spans.push(call.range);
            if let Expr::Attribute(attribute) = call.func.as_ref()
                && matches!(attribute.value.as_ref(), Expr::Call(_))
            {
                value_spine(&attribute.value, spans, names);
            }
        }
        Expr::Attribute(attribute) if matches!(attribute.attr.as_str(), "text" | "content") => {
            value_spine(&attribute.value, spans, names);
        }
        Expr::List(list) => list.elts.iter().for_each(|e| value_spine(e, spans, names)),
        Expr::Tuple(tuple) => tuple.elts.iter().for_each(|e| value_spine(e, spans, names)),
        Expr::Set(set) => set.elts.iter().for_each(|e| value_spine(e, spans, names)),
        Expr::Dict(dict) => dict
            .values
            .iter()
            .for_each(|e| value_spine(e, spans, names)),
        Expr::Starred(starred) => value_spine(&starred.value, spans, names),
        _ => {}
    }
}

fn partition_top_level(body: &[Stmt]) -> (Vec<Stmt>, Vec<Stmt>) {
    let mut import_stmts = Vec::new();
    let mut main_stmts = Vec::new();
    for stmt in body {
        if let Stmt::If(s) = stmt {
            if is_type_checking_test(&s.test) {
                import_stmts.extend(s.orelse.iter().cloned());
                continue;
            }
            if is_main_guard_test(&s.test) {
                main_stmts.extend(s.body.iter().cloned());
                import_stmts.extend(s.orelse.iter().cloned());
                continue;
            }
        }
        import_stmts.push(stmt.clone());
    }
    (import_stmts, main_stmts)
}

/// The import bindings a module establishes, in source order, split by when
/// they execute: eager bindings run at import time (module-level statements,
/// including conditional blocks and class bodies), scoped bindings run only
/// when a function runs (function-local imports, main-guard imports).
/// Relative imports keep their leading dots (`from .util import y` → module
/// ".util") so the repository resolver can interpret relativity.
///
/// Scoped imports are collected because the repository resolver has no
/// per-scope import view — it matches a call edge's callee against these flat
/// lists — so `def f(): from pkg.mod import g; g()` must surface `g` or a call
/// to it can never resolve cross-file. Eager bindings take precedence over
/// scoped bindings, while a later unconditional eager import replaces the
/// earlier binding. Distinct control-flow alternatives are retained so the
/// linker can reject ambiguity.
/// Imports inside `if TYPE_CHECKING:` never execute and are excluded from both
/// lists.
fn extract_imports(body: &[Stmt]) -> (Vec<ImportBinding>, Vec<ImportBinding>, HashSet<String>) {
    let mut eager = Vec::new();
    let mut scoped = Vec::new();
    let mut seen = HashSet::new();
    let mut import_bound = HashSet::new();
    collect_imports_split(
        body,
        false,
        false,
        true,
        true,
        &mut eager,
        &mut seen,
        &mut import_bound,
    );
    collect_imports_split(
        body,
        false,
        false,
        false,
        true,
        &mut scoped,
        &mut seen,
        &mut import_bound,
    );
    (eager, scoped, import_bound)
}

/// One traversal of the statement tree collecting import bindings whose
/// execution timing matches `want_eager`: `in_scoped` flips to true inside
/// function bodies and main-guard blocks (those imports run at call/entrypoint
/// time), and TYPE_CHECKING bodies are skipped entirely.
#[allow(clippy::too_many_arguments)]
fn collect_imports_split(
    body: &[Stmt],
    in_scoped: bool,
    alternative: bool,
    want_eager: bool,
    module_scope: bool,
    out: &mut Vec<ImportBinding>,
    seen: &mut HashSet<String>,
    import_bound: &mut HashSet<String>,
) {
    let descend = |bodies: &[&[Stmt]],
                   scoped: bool,
                   alternative: bool,
                   module_scope: bool,
                   out: &mut Vec<ImportBinding>,
                   seen: &mut HashSet<String>,
                   import_bound: &mut HashSet<String>| {
        for b in bodies {
            collect_imports_split(
                b,
                scoped,
                alternative,
                want_eager,
                module_scope,
                out,
                seen,
                import_bound,
            );
        }
    };
    for stmt in body {
        if in_scoped != want_eager {
            push_import_binding(
                stmt,
                alternative,
                want_eager && module_scope,
                out,
                seen,
                import_bound,
            );
        }
        match stmt {
            Stmt::FunctionDef(f) => descend(
                &[&f.body],
                true,
                alternative,
                false,
                out,
                seen,
                import_bound,
            ),
            Stmt::AsyncFunctionDef(f) => descend(
                &[&f.body],
                true,
                alternative,
                false,
                out,
                seen,
                import_bound,
            ),
            Stmt::ClassDef(c) => descend(
                &[&c.body],
                in_scoped,
                alternative,
                false,
                out,
                seen,
                import_bound,
            ),
            Stmt::If(s) => {
                if is_type_checking_test(&s.test) {
                    descend(
                        &[&s.orelse],
                        in_scoped,
                        alternative,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                } else if is_main_guard_test(&s.test) {
                    descend(
                        &[&s.body],
                        true,
                        alternative,
                        false,
                        out,
                        seen,
                        import_bound,
                    );
                    descend(
                        &[&s.orelse],
                        in_scoped,
                        alternative,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                } else {
                    descend(
                        &[&s.body, &s.orelse],
                        in_scoped,
                        true,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                }
            }
            Stmt::For(s) => descend(
                &[&s.body, &s.orelse],
                in_scoped,
                true,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::AsyncFor(s) => descend(
                &[&s.body, &s.orelse],
                in_scoped,
                true,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::While(s) => descend(
                &[&s.body, &s.orelse],
                in_scoped,
                true,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::With(s) => descend(
                &[&s.body],
                in_scoped,
                alternative,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::AsyncWith(s) => descend(
                &[&s.body],
                in_scoped,
                alternative,
                module_scope,
                out,
                seen,
                import_bound,
            ),
            Stmt::Try(s) => {
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    descend(
                        &[&h.body],
                        in_scoped,
                        true,
                        module_scope,
                        out,
                        seen,
                        import_bound,
                    );
                }
                descend(
                    &[&s.body, &s.orelse],
                    in_scoped,
                    true,
                    module_scope,
                    out,
                    seen,
                    import_bound,
                );
                descend(
                    &[&s.finalbody],
                    in_scoped,
                    alternative,
                    module_scope,
                    out,
                    seen,
                    import_bound,
                );
            }
            _ => {}
        }
    }
}

/// Append the bindings a single `import` / `from ... import` statement
/// establishes. A local already bound by an unconditional import is skipped;
/// distinct control-flow alternatives are retained for linker ambiguity.
fn push_import_binding(
    stmt: &Stmt,
    alternative: bool,
    replace: bool,
    out: &mut Vec<ImportBinding>,
    seen: &mut HashSet<String>,
    import_bound: &mut HashSet<String>,
) {
    match stmt {
        Stmt::Import(import) => {
            for alias in &import.names {
                let module = alias.name.to_string();
                let local = alias
                    .asname
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| module.split('.').next().unwrap_or(&module).to_string());
                let binding = ImportBinding {
                    local,
                    module,
                    imported: None,
                };
                if replace && !alternative {
                    import_bound.insert(binding.local.clone());
                }
                record_import_binding(binding, alternative, replace, out, seen);
            }
        }
        Stmt::ImportFrom(from) => {
            let level = from.level.as_ref().map(|l| l.to_usize()).unwrap_or(0);
            let base = from
                .module
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_default();
            let module = format!("{}{base}", ".".repeat(level));
            for alias in &from.names {
                if alias.name.as_str() == "*" {
                    let binding = ImportBinding {
                        local: "*".to_string(),
                        module: module.clone(),
                        imported: None,
                    };
                    if alternative {
                        if !out.contains(&binding) {
                            out.push(binding.clone());
                        }
                        // Keep conditional star imports distinguishable from a
                        // single unconditional star for linker precedence.
                        out.push(binding);
                    } else if !out.contains(&binding) {
                        out.push(binding);
                    }
                    continue;
                }
                let imported = alias.name.to_string();
                let local = alias
                    .asname
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| imported.clone());
                let binding = ImportBinding {
                    local,
                    module: module.clone(),
                    imported: Some(imported),
                };
                if replace && !alternative {
                    import_bound.insert(binding.local.clone());
                }
                record_import_binding(binding, alternative, replace, out, seen);
            }
        }
        Stmt::FunctionDef(function) if replace && !alternative => {
            clear_import_binding(function.name.as_str(), out, seen);
            import_bound.remove(function.name.as_str());
        }
        Stmt::AsyncFunctionDef(function) if replace && !alternative => {
            clear_import_binding(function.name.as_str(), out, seen);
            import_bound.remove(function.name.as_str());
        }
        Stmt::ClassDef(class) if replace && !alternative => {
            clear_import_binding(class.name.as_str(), out, seen);
            import_bound.remove(class.name.as_str());
        }
        Stmt::Assign(assign) if replace && !alternative => {
            let alias = match assign.value.as_ref() {
                Expr::Name(name) if import_bound.contains(name.id.as_str()) => {
                    import_alias(&assign.value, out)
                }
                _ => None,
            };
            for target in &assign.targets {
                if let Expr::Name(target) = target {
                    clear_import_binding(target.id.as_str(), out, seen);
                    import_bound.remove(target.id.as_str());
                    if let Some(mut binding) = alias.clone() {
                        binding.local = target.id.to_string();
                        import_bound.insert(binding.local.clone());
                        record_import_binding(binding, false, true, out, seen);
                    }
                }
            }
        }
        Stmt::AnnAssign(assign) if replace && !alternative => {
            if let Expr::Name(target) = assign.target.as_ref() {
                let alias = assign
                    .value
                    .as_deref()
                    .filter(|value| {
                        matches!(value, Expr::Name(name)
                            if import_bound.contains(name.id.as_str()))
                    })
                    .and_then(|value| import_alias(value, out));
                clear_import_binding(target.id.as_str(), out, seen);
                import_bound.remove(target.id.as_str());
                if let Some(mut binding) = alias {
                    binding.local = target.id.to_string();
                    import_bound.insert(binding.local.clone());
                    record_import_binding(binding, false, true, out, seen);
                }
            }
        }
        Stmt::AugAssign(assign) if replace && !alternative => {
            if let Expr::Name(target) = assign.target.as_ref() {
                clear_import_binding(target.id.as_str(), out, seen);
                import_bound.remove(target.id.as_str());
            }
        }
        _ => {}
    }
}

fn import_alias(value: &Expr, imports: &[ImportBinding]) -> Option<ImportBinding> {
    let Expr::Name(name) = value else {
        return None;
    };
    imports
        .iter()
        .rev()
        .find(|binding| binding.local == name.id.as_str())
        .cloned()
}

fn clear_import_binding(local: &str, out: &mut Vec<ImportBinding>, seen: &mut HashSet<String>) {
    out.retain(|binding| binding.local != local);
    seen.remove(local);
}

fn record_import_binding(
    binding: ImportBinding,
    alternative: bool,
    replace: bool,
    out: &mut Vec<ImportBinding>,
    seen: &mut HashSet<String>,
) {
    let local_in_output = out.iter().any(|existing| existing.local == binding.local);
    if alternative {
        if (!seen.contains(&binding.local) || local_in_output) && !out.contains(&binding) {
            seen.insert(binding.local.clone());
            out.push(binding);
        }
    } else if seen.insert(binding.local.clone()) {
        out.push(binding);
    } else if replace && local_in_output {
        out.retain(|existing| existing.local != binding.local);
        out.push(binding);
    }
}

fn import_from_module(from: &ast::StmtImportFrom) -> String {
    let level = from
        .level
        .as_ref()
        .map(|level| level.to_usize())
        .unwrap_or(0);
    let base = from
        .module
        .as_ref()
        .map(|module| module.to_string())
        .unwrap_or_default();
    format!("{}{base}", ".".repeat(level))
}

/// The callee of a call as written: a bare name or a dotted attribute chain
/// (`wipe`, `util.wipe`). None for anything more complex (a call result, a
/// subscript), which is never a cross-file linking candidate.
fn callee_written(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str().to_string()),
        Expr::Attribute(a) => {
            let base = callee_written(&a.value)?;
            Some(format!("{base}.{}", a.attr.as_str()))
        }
        _ => None,
    }
}

pub(crate) fn registrations(
    source: &str,
    file: &str,
    max_bytes: u64,
) -> Result<Vec<crate::Registration>, &'static str> {
    let suite = ast::Suite::parse(source, file).map_err(|_| "parse_error: registration scan")?;
    registration::fastapi_registrations(&suite, file, max_bytes)
}

pub(crate) struct PythonFrontend {
    ipython: Option<ipython::CellActions>,
    /// A Prime Agent kernel cell, whose namespace holds the runtime's `bash`
    /// helper.
    prime_agent: bool,
}

#[allow(non_upper_case_globals)]
pub(crate) const PythonFrontend: PythonFrontend = PythonFrontend {
    ipython: None,
    prime_agent: false,
};

impl PythonFrontend {
    fn ipython(actions: ipython::CellActions) -> Self {
        Self {
            ipython: Some(actions),
            prime_agent: false,
        }
    }

    pub(crate) fn prime_agent() -> Self {
        Self {
            ipython: None,
            prime_agent: true,
        }
    }
}

impl Frontend for PythonFrontend {
    const LANGUAGE: &'static str = "python";
    const DOMAINS: &'static [&'static str] = &DOMAINS;
    type Ast<'a> = ast::Suite;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        match ast::Suite::parse(source, "<python>") {
            Ok(ast) => ParseOutcome {
                ast: Some(ast),
                failure: None,
            },
            Err(err) => ParseOutcome {
                ast: None,
                failure: Some(ParseFailure {
                    detail: err.to_string(),
                }),
            },
        }
    }
    fn parse_failure(
        &self,
        builder: &mut PlanBuilder,
        scope: Option<ProvenanceRef>,
        failure: &ParseFailure,
    ) {
        boundary(
            builder,
            scope,
            BoundaryReason::PARSE_ERROR,
            BoundaryClass::ParseFailure,
            None,
            Some(failure.detail.clone()),
        );
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        suite: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let source = input.source;
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        // Imported modules use the same import-time statement partition as
        // summaries. Keep the original source bytes and ranges for provenance.
        let selected_registration = nest.registration.is_some() && builder.execution_depth() == 1;
        let import_stmts;
        let suite = if builder.current_execution_is_dependency() || selected_registration {
            import_stmts = partition_top_level(suite).0;
            &import_stmts
        } else {
            suite
        };
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        if depth == 0 {
            boundary(
                builder,
                scope,
                BoundaryReason::FRONTEND_PARTIAL,
                BoundaryClass::Unmodeled,
                None,
                Some("python frontend models selected effect APIs".to_string()),
            );
        }

        // Collect module-level function definitions. A defined-but-never-called
        // function is summarized but contributes effects only where a call to it
        // is actually reached during execution.
        let (mut walker, classes) = Walker::for_execution(
            builder,
            nest,
            source,
            cwd,
            cwd_node,
            scope,
            depth,
            suite,
            self.ipython.clone(),
        );
        let declared_callables: Vec<String> = walker
            .defs
            .iter()
            .filter(|def| def.parent.is_none() && (def.owner.is_none() || def.name.contains('.')))
            .map(|def| def.name.clone())
            .collect();
        // Only the cell itself runs in the kernel namespace; modules it imports
        // have their own globals.
        walker.prime_bash = self.prime_agent
            && !walker.builder.current_execution_is_dependency()
            && prime_bash_owned(suite);
        let first_effect = walker.builder.effects_len();
        walker.import_search = nest.python_import_search.borrow_mut().take().or_else(|| {
            (walker.builder.execution_depth() == 1)
                .then(|| imports::root_import_search(nest))
                .flatten()
        });
        // Seed imports and module constants before execution. Calls infer their
        // own summaries, so uncalled declarations cannot starve an execution root.
        walker.collect_imports(suite);
        control::collect_bound(suite, &mut walker.module_binds);
        walker.collect_consts(suite);
        walker.var_scope = walker.consts.clone();
        walker.concatenated_vars = walker.const_concatenations.clone();
        walker.unbounded_string_vars = walker.const_unbounded_strings.clone();
        let (framework_roots, framework_decorators, registration_limit) = python_framework_roots(
            suite,
            &walker.defs,
            &classes,
            &walker.imports,
            nest.limits.max_analysis_bytes,
        );
        if let Some(limit) = registration_limit {
            walker.builder.note_saturated_at(limit, None);
        }
        walker.framework_decorators = framework_decorators;
        walker.builder.control_enter(source, false, |graph| {
            control::build(
                graph,
                suite,
                control::Entry::Main,
                &std::collections::HashSet::new(),
            )
        });
        walker.walk_body(suite);
        walker.builder.control_leave();
        for root in framework_roots
            .into_iter()
            .filter(|_| !selected_registration)
        {
            walker.apply_local_root(&root);
        }
        walker.stage_writer.commit(walker.builder);
        let entered_callables = walker.entered_callables;
        let free_resource_parameter = walker.free_resource_parameter.get();
        drop(walker);
        if free_resource_parameter {
            boundary(
                builder,
                scope,
                BoundaryReason::FRONTEND_PARTIAL,
                BoundaryClass::Unmodeled,
                None,
                Some("effect resource depends on an unbound Python name".to_string()),
            );
        }
        WalkOutcome {
            declared_callables: if !declared_callables.is_empty()
                && !entered_callables
                && builder.effects_len() == first_effect
            {
                declared_callables
            } else {
                Vec::new()
            },
        }
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summary::summarize_ast(source, ast, file, scope)
    }
}

impl<'a, 'b> Walker<'a, 'b> {
    /// An execution-mode walker over one parsed module, before imports,
    /// constants, or import search are seeded.
    #[allow(clippy::too_many_arguments)]
    fn for_execution(
        builder: &'b mut PlanBuilder,
        nest: &'a Nest<'a>,
        source: &'a str,
        cwd: Option<&'a str>,
        cwd_node: Option<ProvenanceRef>,
        scope: Option<ProvenanceRef>,
        depth: u64,
        suite: &ast::Suite,
        ipython: Option<ipython::CellActions>,
    ) -> (Self, Vec<ClassEntry>) {
        let max_nodes = nest.limits.max_python_nodes;
        let registration_spans =
            match registration::fastapi_registrations(suite, "", nest.limits.max_analysis_bytes) {
                Ok(registrations) => registrations
                    .into_iter()
                    .flat_map(|registration| registration.spans)
                    .collect(),
                Err(limit) => {
                    builder.note_saturated_at(limit, None);
                    HashSet::new()
                }
            };
        let mut defs: Vec<Def> = Vec::new();
        collect_defs(suite, &mut defs);
        let (classes, attr_values) = collect_classes(suite);
        let walker = Walker {
            builder,
            nest,
            source,
            condition_source: effinterp_proto::ConditionSource::new(source),
            cwd: cwd.map(str::to_string),
            cwd_node,
            chdir: None,
            scope,
            depth,
            imports: Imports::default(),
            defs,
            summaries: std::collections::HashMap::new(),
            demand_summaries: true,
            summary_in_progress: HashSet::new(),
            summary_cycles: HashSet::new(),
            summary_refining: false,
            summary_spans: std::collections::HashMap::new(),
            decorated_summaries: std::collections::HashMap::new(),
            spawn_summaries: std::collections::HashMap::new(),
            consts: std::collections::HashMap::new(),
            shared_vars: HashSet::new(),
            const_concatenations: HashSet::new(),
            const_unbounded_strings: HashSet::new(),
            var_scope: std::collections::HashMap::new(),
            path_vars: HashSet::new(),
            branch_mixed_path_vars: HashSet::new(),
            concatenated_vars: HashSet::new(),
            unbounded_string_vars: HashSet::new(),
            collections: std::collections::HashMap::new(),
            widened_vars: HashSet::new(),
            sessions: std::collections::HashMap::new(),
            modeled_values: std::collections::HashMap::new(),
            return_receivers: std::collections::HashMap::new(),
            return_instances: std::collections::HashMap::new(),
            summary_instances: std::collections::HashMap::new(),
            instance_sequences: std::collections::HashMap::new(),
            capture: None,
            capture_condition_depth: 0,
            entered_callables: false,
            framework_decorators: HashSet::new(),
            registration_spans,
            reported_unresolved: HashSet::new(),
            nodes_left: max_nodes,
            node_budget_hit: false,
            free_resource_parameter: Cell::new(false),
            walk_depth: 0,
            flow_vars: std::collections::HashMap::new(),
            stage_writer: StageWriter::default(),
            current_params: Vec::new(),
            current_function: None,
            current_path_params: HashSet::new(),
            current_class: None,
            class_names: classes.iter().map(|c| c.name.clone()).collect(),
            class_bases: collect_class_bases(&classes),
            path_attrs: collect_path_attrs(&classes),
            attr_values,
            class_strings: collect_class_strings(suite),
            class_sets: collect_class_sets(suite),
            class_set_vars: std::collections::HashMap::new(),
            instance_vars: std::collections::HashMap::new(),
            instance_attr_rebindings: std::collections::HashMap::new(),
            bound_vars: HashSet::new(),
            receiver_rebindings: HashSet::new(),
            pending_binds: None,
            discarded_call: None,
            source_changes_cwd: source_changes_cwd(source, ipython.as_ref()),
            eager_call: None,
            synchronous_call: None,
            deferred_containers: std::collections::HashMap::new(),
            deferred_vars: std::collections::HashMap::new(),
            pending_deferred_container: None,
            fact_file: String::new(),
            fact_scope: None,
            fact_function: String::new(),
            site_ordinal: Cell::new(0),
            site_origins: RefCell::new(std::collections::HashMap::new()),
            module_capture: false,
            execute_deferred: false,
            deferred_call: None,
            import_search: None,
            imported_summaries: std::collections::HashMap::new(),
            control_applications: Vec::new(),
            summary_requirements: std::collections::HashMap::new(),
            summary_stdout: std::collections::HashMap::new(),
            module_binds: HashSet::new(),
            environment_rewritten: false,
            ipython: ipython.map(|cell| IpythonState {
                actions: cell.actions,
                bindings: Default::default(),
                environment: Default::default(),
                environment_nodes: Default::default(),
                get_ipython_owned: true,
            }),
            prime_bash: false,
        };
        (walker, classes)
    }
}

fn python_framework_roots(
    body: &[Stmt],
    defs: &[Def],
    classes: &[ClassEntry],
    imports: &Imports,
    max_bytes: u64,
) -> (Vec<String>, HashSet<String>, Option<&'static str>) {
    const APP_CONSTRUCTORS: [&str; 4] = [
        "typer.Typer",
        "flask.Flask",
        "flask.Blueprint",
        "click.Group",
    ];
    const APP_DECORATORS: [&str; 8] = [
        "command", "callback", "route", "get", "post", "put", "delete", "patch",
    ];

    let declared: HashSet<&str> = defs
        .iter()
        .filter(|def| def.parent.is_none() && def.owner.is_none())
        .map(|def| def.name.as_str())
        .chain(classes.iter().map(|class| class.name.as_str()))
        .collect();
    let import_resolves = |written: &str, expected: &[&str]| {
        let root = written.split('.').next().unwrap_or(written);
        !declared.contains(root)
            && imports
                .resolve_written(written)
                .is_some_and(|resolved| expected.contains(&resolved.as_str()))
    };
    let mut apps = HashSet::new();
    for stmt in body {
        let Stmt::Assign(assign) = stmt else { continue };
        let [Expr::Name(binding)] = assign.targets.as_slice() else {
            continue;
        };
        let Expr::Call(call) = assign.value.as_ref() else {
            continue;
        };
        let Some(callee) = callee_written(&call.func) else {
            continue;
        };
        if import_resolves(&callee, &APP_CONSTRUCTORS) {
            apps.insert(binding.id.to_string());
        }
    }
    for def in defs.iter().filter(|def| def.parent.is_none()) {
        if def.owner.is_none()
            && def.decorators.iter().any(|decorator| {
                let written = decorator.strip_suffix("()").unwrap_or(decorator);
                import_resolves(written, &["click.group"])
            })
        {
            apps.insert(def.name.clone());
        }
    }

    let mut roots = Vec::new();
    let mut framework_decorators = HashSet::new();
    for def in defs.iter().filter(|def| def.parent.is_none()) {
        let matched_decorators: Vec<String> = def
            .decorators
            .iter()
            .filter(|decorator| {
                let written = decorator.strip_suffix("()").unwrap_or(decorator);
                import_resolves(written, &["click.command", "click.group"])
                    || written.rsplit_once('.').is_some_and(|(receiver, method)| {
                        apps.contains(receiver) && APP_DECORATORS.contains(&method)
                    })
            })
            .cloned()
            .collect();
        let decorated = !matched_decorators.is_empty();
        framework_decorators.extend(matched_decorators);
        let django = def.owner.as_deref().is_some_and(|owner| {
            def.name == format!("{owner}.handle")
                && classes.iter().any(|class| {
                    class.name == owner
                        && class.bases.iter().any(|base| {
                            import_resolves(base, &["django.core.management.base.BaseCommand"])
                        })
                })
        });
        if (decorated || django) && !roots.contains(&def.name) {
            roots.push(def.name.clone());
        }
    }
    let registrations = match registration::fastapi_registrations(body, "", max_bytes) {
        Ok(registrations) => registrations,
        Err(limit) => return (roots, framework_decorators, Some(limit)),
    };
    for registration in registrations {
        if !roots.contains(&registration.primary_handler) {
            roots.push(registration.primary_handler.clone());
        }
        if let Some(def) = defs
            .iter()
            .find(|def| def.name == registration.primary_handler)
        {
            for decorator in &def.decorators {
                if decorator
                    .strip_suffix("()")
                    .unwrap_or(decorator)
                    .strip_prefix(&format!("{}.", registration.owner))
                    .is_some_and(|method| {
                        matches!(
                            method,
                            "get"
                                | "post"
                                | "put"
                                | "delete"
                                | "patch"
                                | "head"
                                | "options"
                                | "trace"
                                | "api_route"
                                | "route"
                        )
                    })
                {
                    framework_decorators.insert(decorator.clone());
                }
            }
        }
    }
    (roots, framework_decorators, None)
}

/// Register function definitions by name, params, and body. Module-level
/// functions come first; class methods are also registered (as `Class.method`,
/// the bare method name when free, and `Class` for `__init__`) so
/// `self.method()`, `Class.method()`, and `Class()` can be followed. The first
/// definition of a name wins.
fn collect_defs(body: &[Stmt], defs: &mut Vec<Def>) {
    for stmt in body {
        match stmt {
            Stmt::FunctionDef(f) => {
                let name = f.name.to_string();
                push_def(
                    defs,
                    name.clone(),
                    param_names(&f.args),
                    parameter_bindings(&f.args),
                    positional_param_count(&f.args),
                    callable_defaults(&f.args),
                    param_defaults(&f.args),
                    param_types(&f.args),
                    None,
                    &f.body,
                    false,
                );
                set_decorators(defs, &name, &f.decorator_list);
                collect_closures(&f.body, &name, None, defs);
            }
            Stmt::AsyncFunctionDef(f) => {
                let name = f.name.to_string();
                push_def(
                    defs,
                    name.clone(),
                    param_names(&f.args),
                    parameter_bindings(&f.args),
                    positional_param_count(&f.args),
                    callable_defaults(&f.args),
                    param_defaults(&f.args),
                    param_types(&f.args),
                    None,
                    &f.body,
                    true,
                );
                set_decorators(defs, &name, &f.decorator_list);
                collect_closures(&f.body, &name, None, defs);
            }
            Stmt::ClassDef(c) => {
                for item in &c.body {
                    let (name, args, fn_body, decorators, is_async) = match item {
                        Stmt::FunctionDef(f) => (
                            f.name.to_string(),
                            &f.args,
                            &f.body,
                            &f.decorator_list,
                            false,
                        ),
                        Stmt::AsyncFunctionDef(f) => (
                            f.name.to_string(),
                            &f.args,
                            &f.body,
                            &f.decorator_list,
                            true,
                        ),
                        _ => continue,
                    };
                    // Drop the implicit receiver so `self._read(p)` binds `p`.
                    let params = method_params(args);
                    let types = method_param_types(args);
                    let owner = Some(c.name.to_string());
                    push_def(
                        defs,
                        format!("{}.{name}", c.name),
                        params.clone(),
                        parameter_bindings(args),
                        method_positional_param_count(args),
                        method_callable_defaults(args),
                        method_param_defaults(args),
                        types.clone(),
                        owner.clone(),
                        fn_body,
                        is_async,
                    );
                    set_decorators(defs, &format!("{}.{name}", c.name), decorators);
                    collect_closures(fn_body, &format!("{}.{name}", c.name), owner.clone(), defs);
                    push_def(
                        defs,
                        name.clone(),
                        params.clone(),
                        parameter_bindings(args),
                        method_positional_param_count(args),
                        method_callable_defaults(args),
                        method_param_defaults(args),
                        types.clone(),
                        owner.clone(),
                        fn_body,
                        is_async,
                    );
                    set_decorators(defs, &name, decorators);
                    collect_closures(fn_body, &name, owner.clone(), defs);
                    if name == "__init__" {
                        push_def(
                            defs,
                            c.name.to_string(),
                            params,
                            parameter_bindings(args),
                            method_positional_param_count(args),
                            method_callable_defaults(args),
                            method_param_defaults(args),
                            types,
                            owner,
                            fn_body,
                            is_async,
                        );
                        set_decorators(defs, c.name.as_str(), decorators);
                        collect_closures(fn_body, c.name.as_str(), Some(c.name.to_string()), defs);
                    }
                }
            }
            // A def nested in module-level control flow (websockets guards its
            // `get_version` behind `if not released:`) is still a module-level
            // function once the block runs; function bodies are NOT descended,
            // so a closure never registers as a module def.
            Stmt::If(s) => {
                collect_defs(&s.body, defs);
                collect_defs(&s.orelse, defs);
            }
            Stmt::Try(s) => {
                collect_defs(&s.body, defs);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_defs(&h.body, defs);
                }
                collect_defs(&s.orelse, defs);
                collect_defs(&s.finalbody, defs);
            }
            Stmt::With(s) => collect_defs(&s.body, defs),
            _ => {}
        }
    }
}

/// Top-level class definitions: declared bases (as written) and the instance
/// attributes `__init__` binds to a constructor parameter or to a direct
/// constructor call — the only unambiguous attribute-typing sources.
fn collect_classes(body: &[Stmt]) -> (Vec<ClassEntry>, Vec<InitAttrValue>) {
    let mut out = Vec::new();
    let mut values = Vec::new();
    for stmt in body {
        let Stmt::ClassDef(c) = stmt else { continue };
        let bases = c.bases.iter().filter_map(callee_written).collect();
        let mut attr_params = Vec::new();
        let mut attr_classes = Vec::new();
        let mut attr_values = Vec::new();
        let init = c.body.iter().find_map(|item| match item {
            Stmt::FunctionDef(f) if f.name.as_str() == "__init__" => Some((&f.args, &f.body)),
            Stmt::AsyncFunctionDef(f) if f.name.as_str() == "__init__" => Some((&f.args, &f.body)),
            _ => None,
        });
        if let Some((args, init_body)) = init {
            let params = method_params(args);
            collect_init_attrs(
                init_body,
                &params,
                &mut attr_params,
                &mut attr_classes,
                &mut attr_values,
            );
            let mut reassigned = HashSet::new();
            for item in &c.body {
                match item {
                    Stmt::FunctionDef(function) if function.name.as_str() != "__init__" => {
                        collect_receiver_attr_writes(&function.body, "self", &mut reassigned);
                    }
                    Stmt::AsyncFunctionDef(function) if function.name.as_str() != "__init__" => {
                        collect_receiver_attr_writes(&function.body, "self", &mut reassigned);
                    }
                    _ => {}
                }
            }
            attr_values.retain(|(attr, _)| !reassigned.contains(attr));
            let types = method_param_types(args);
            for (attr, param) in &attr_params {
                if let Some((_, ty)) = types.iter().find(|(name, _)| name == param)
                    && !attr_classes.iter().any(|(name, _)| name == attr)
                {
                    attr_classes.push((attr.clone(), ty.clone()));
                }
            }
        }
        out.push(ClassEntry {
            name: c.name.to_string(),
            bases,
            attr_params,
            attr_classes,
            ..Default::default()
        });
        values.extend(attr_values.into_iter().map(|(attr, value)| InitAttrValue {
            owner: c.name.to_string(),
            attr,
            value,
        }));
    }
    (out, values)
}

/// Walk an `__init__` body for `self.attr = <param>` and `self.attr = Cls(...)`
/// assignments (following control flow, not nested defs). The last definite
/// write wins; branch disagreement and opaque reassignment drop the attribute.
fn collect_init_attrs(
    body: &[Stmt],
    params: &[String],
    attr_params: &mut Vec<(String, String)>,
    attr_classes: &mut Vec<(String, String)>,
    attr_values: &mut Vec<(String, Rc<Expr>)>,
) {
    for stmt in body {
        match stmt {
            Stmt::Assign(a) => {
                let direct_attr = match a.targets.as_slice() {
                    [Expr::Attribute(target)] if matches!(target.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self") => {
                        Some(target.attr.to_string())
                    }
                    _ => None,
                };
                let prior_class = direct_attr.as_ref().and_then(|attr| {
                    attr_classes
                        .iter()
                        .find(|(name, _)| name == attr)
                        .map(|(_, ty)| ty.clone())
                });
                let prior_value = direct_attr.as_ref().and_then(|attr| {
                    attr_values
                        .iter()
                        .find(|(name, _)| name == attr)
                        .map(|(_, value)| Rc::clone(value))
                });
                for target in &a.targets {
                    drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                }
                let Some(attr) = direct_attr else {
                    continue;
                };
                match a.value.as_ref() {
                    Expr::Name(v) if params.iter().any(|p| p == v.id.as_str()) => {
                        attr_params.push((attr.clone(), v.id.to_string()));
                    }
                    Expr::Call(call) => {
                        let preserves_attr = matches!(call.func.as_ref(), Expr::Attribute(method)
                            if matches!(method.value.as_ref(), Expr::Attribute(receiver)
                                if receiver.attr.as_str() == attr
                                    && matches!(receiver.value.as_ref(), Expr::Name(name)
                                        if name.id.as_str() == "self")));
                        if preserves_attr {
                            if let Some(ty) = prior_class {
                                attr_classes.push((attr.clone(), ty));
                            }
                            if let Some(value) = prior_value {
                                attr_values.push((attr.clone(), value));
                            }
                        } else if let Some(name) = callee_written(&call.func) {
                            if name.rsplit('.').next() == Some("Path")
                                && let [Expr::Name(value)] = call.args.as_slice()
                                && params.iter().any(|param| param == value.id.as_str())
                            {
                                attr_params.push((attr.clone(), value.id.to_string()));
                            }
                            attr_classes.push((attr.clone(), name));
                        }
                    }
                    _ => {}
                }
                if is_init_attr_value(&a.value, params)
                    && !attr_values.iter().any(|(name, _)| *name == attr)
                {
                    attr_values.push((attr.clone(), Rc::new(a.value.as_ref().clone())));
                }
            }
            Stmt::Delete(s) => {
                for target in &s.targets {
                    drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                }
            }
            Stmt::If(s) => {
                let mut body_params = attr_params.clone();
                let mut body_classes = attr_classes.clone();
                let mut body_values = attr_values.clone();
                let mut else_params = attr_params.clone();
                let mut else_classes = attr_classes.clone();
                let mut else_values = attr_values.clone();
                collect_init_attrs(
                    &s.body,
                    params,
                    &mut body_params,
                    &mut body_classes,
                    &mut body_values,
                );
                collect_init_attrs(
                    &s.orelse,
                    params,
                    &mut else_params,
                    &mut else_classes,
                    &mut else_values,
                );
                retain_init_attr_agreement(attr_params, &body_params, &else_params);
                retain_init_attr_agreement(attr_classes, &body_classes, &else_classes);
                retain_init_attr_agreement(attr_values, &body_values, &else_values);
            }
            Stmt::AugAssign(s) => {
                drop_init_attr_targets(&s.target, attr_params, attr_classes, attr_values);
            }
            Stmt::For(s) => {
                drop_init_attr_targets(&s.target, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
            }
            Stmt::AsyncFor(s) => {
                drop_init_attr_targets(&s.target, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
            }
            Stmt::While(s) => {
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
            }
            Stmt::With(s) => {
                for item in &s.items {
                    if let Some(target) = &item.optional_vars {
                        drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                    }
                }
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values)
            }
            Stmt::AsyncWith(s) => {
                for item in &s.items {
                    if let Some(target) = &item.optional_vars {
                        drop_init_attr_targets(target, attr_params, attr_classes, attr_values);
                    }
                }
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values)
            }
            Stmt::Try(s) => {
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_init_attrs(&h.body, params, attr_params, attr_classes, attr_values);
                }
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.finalbody, params, attr_params, attr_classes, attr_values);
            }
            Stmt::TryStar(s) => {
                collect_init_attrs(&s.body, params, attr_params, attr_classes, attr_values);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_init_attrs(&h.body, params, attr_params, attr_classes, attr_values);
                }
                collect_init_attrs(&s.orelse, params, attr_params, attr_classes, attr_values);
                collect_init_attrs(&s.finalbody, params, attr_params, attr_classes, attr_values);
            }
            Stmt::Match(s) => {
                for case in &s.cases {
                    let mut case_params = attr_params.clone();
                    let mut case_classes = attr_classes.clone();
                    let mut case_values = attr_values.clone();
                    collect_init_attrs(
                        &case.body,
                        params,
                        &mut case_params,
                        &mut case_classes,
                        &mut case_values,
                    );
                    attr_params.retain(|entry| case_params.contains(entry));
                    attr_classes.retain(|entry| case_classes.contains(entry));
                    attr_values.retain(|entry| case_values.contains(entry));
                }
            }
            _ => {}
        }
    }
}

fn drop_init_attr_targets(
    target: &Expr,
    attr_params: &mut Vec<(String, String)>,
    attr_classes: &mut Vec<(String, String)>,
    attr_values: &mut Vec<(String, Rc<Expr>)>,
) {
    let targets = receiver_attr_target_names(target, "self");
    attr_params.retain(|(attr, _)| !targets.contains(attr));
    attr_classes.retain(|(attr, _)| !targets.contains(attr));
    attr_values.retain(|(attr, _)| !targets.contains(attr));
}

fn receiver_attr_target_names(target: &Expr, receiver: &str) -> Vec<String> {
    match target {
        Expr::Attribute(attribute) if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == receiver) =>
        {
            vec![attribute.attr.to_string()]
        }
        Expr::List(list) => list
            .elts
            .iter()
            .flat_map(|element| receiver_attr_target_names(element, receiver))
            .collect(),
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .flat_map(|element| receiver_attr_target_names(element, receiver))
            .collect(),
        Expr::Starred(starred) => receiver_attr_target_names(&starred.value, receiver),
        _ => Vec::new(),
    }
}

fn retain_init_attr_agreement<T: Clone + PartialEq>(target: &mut Vec<T>, body: &[T], orelse: &[T]) {
    target.clear();
    target.extend(body.iter().filter(|entry| orelse.contains(entry)).cloned());
}

fn is_init_attr_value(expr: &Expr, params: &[String]) -> bool {
    if str_literal(expr).is_some()
        || matches!(expr, Expr::Name(name) if params.iter().any(|param| param == name.id.as_str()))
        || matches!(expr, Expr::Subscript(subscript) if callee_written(&subscript.value).as_deref() == Some("os.environ"))
    {
        return true;
    }
    match expr {
        Expr::Call(call) => {
            callee_written(&call.func).is_some_and(|name| {
                matches!(
                    name.rsplit('.').next(),
                    Some("Path" | "PurePath" | "PosixPath" | "PurePosixPath")
                )
            }) || matches!(call.func.as_ref(), Expr::Attribute(method) if is_init_attr_value(&method.value, params))
        }
        Expr::Attribute(attribute) => is_init_attr_value(&attribute.value, params),
        Expr::Subscript(subscript) => is_init_attr_value(&subscript.value, params),
        Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
            is_init_attr_value(&binary.left, params)
        }
        _ => false,
    }
}

fn collect_receiver_attr_target_writes(
    target: &Expr,
    receivers: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    for receiver in receivers {
        out.extend(receiver_attr_target_names(target, receiver));
    }
}

fn collect_receiver_alias_attr_writes(
    body: &[Stmt],
    receivers: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    for stmt in body {
        match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_receiver_attr_target_writes(target, receivers, out);
                }
                if let Expr::Name(source) = assign.value.as_ref()
                    && receivers.contains(source.id.as_str())
                {
                    receivers.extend(assign.targets.iter().filter_map(|target| match target {
                        Expr::Name(name) => Some(name.id.to_string()),
                        _ => None,
                    }));
                }
            }
            Stmt::Delete(stmt) => {
                for target in &stmt.targets {
                    collect_receiver_attr_target_writes(target, receivers, out);
                }
            }
            Stmt::AnnAssign(assign) => {
                collect_receiver_attr_target_writes(&assign.target, receivers, out);
                if let Expr::Name(target) = assign.target.as_ref()
                    && let Some(Expr::Name(source)) = assign.value.as_deref()
                    && receivers.contains(source.id.as_str())
                {
                    receivers.insert(target.id.to_string());
                }
            }
            Stmt::AugAssign(assign) => {
                collect_receiver_attr_target_writes(&assign.target, receivers, out);
            }
            Stmt::If(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::For(stmt) => {
                collect_receiver_attr_target_writes(&stmt.target, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::AsyncFor(stmt) => {
                collect_receiver_attr_target_writes(&stmt.target, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::While(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
            }
            Stmt::With(stmt) => {
                for item in &stmt.items {
                    if let Some(target) = &item.optional_vars {
                        collect_receiver_attr_target_writes(target, receivers, out);
                    }
                }
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
            }
            Stmt::AsyncWith(stmt) => {
                for item in &stmt.items {
                    if let Some(target) = &item.optional_vars {
                        collect_receiver_attr_target_writes(target, receivers, out);
                    }
                }
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
            }
            Stmt::Try(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    collect_receiver_alias_attr_writes(&handler.body, receivers, out);
                }
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.finalbody, receivers, out);
            }
            Stmt::TryStar(stmt) => {
                collect_receiver_alias_attr_writes(&stmt.body, receivers, out);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    collect_receiver_alias_attr_writes(&handler.body, receivers, out);
                }
                collect_receiver_alias_attr_writes(&stmt.orelse, receivers, out);
                collect_receiver_alias_attr_writes(&stmt.finalbody, receivers, out);
            }
            Stmt::Match(stmt) => {
                for case in &stmt.cases {
                    collect_receiver_alias_attr_writes(&case.body, receivers, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_receiver_attr_writes(body: &[Stmt], receiver: &str, out: &mut HashSet<String>) {
    let mut receivers = HashSet::from([receiver.to_string()]);
    collect_receiver_alias_attr_writes(body, &mut receivers, out);
}

fn parameter_attr_writes(params: &[String], body: &[Stmt]) -> Vec<(String, String)> {
    let mut writes = Vec::new();
    for param in params {
        let mut attrs = HashSet::new();
        collect_receiver_attr_writes(body, param, &mut attrs);
        writes.extend(attrs.into_iter().map(|attr| (param.clone(), attr)));
    }
    writes.sort();
    writes
}

#[allow(clippy::too_many_arguments)]
fn push_def(
    defs: &mut Vec<Def>,
    name: String,
    params: Vec<String>,
    parameter_bindings: Vec<String>,
    positional_param_count: usize,
    callable_defaults: Vec<Option<String>>,
    param_defaults: Vec<Option<Rc<Expr>>>,
    param_types: Vec<(String, String)>,
    owner: Option<String>,
    body: &[Stmt],
    is_async: bool,
) {
    if !defs.iter().any(|d| d.name == name) {
        let parameter_attr_writes = parameter_attr_writes(&params, body);
        let local_name = name.clone();
        defs.push(Def {
            name,
            local_name,
            parent: None,
            params,
            parameter_bindings,
            positional_param_count,
            callable_defaults,
            param_defaults,
            param_types,
            owner,
            body: Rc::new(body.to_vec()),
            parameter_attr_writes,
            decorators: Vec::new(),
            is_async,
            is_generator: body_has_yield(body),
        });
    }
}

fn decorator_names(decorators: &[Expr]) -> Vec<String> {
    decorators
        .iter()
        .map(|decorator| match decorator {
            Expr::Call(call) => callee_written(&call.func)
                .map(|name| format!("{name}()"))
                .unwrap_or_else(|| "<dynamic>".to_string()),
            _ => callee_written(decorator).unwrap_or_else(|| "<dynamic>".to_string()),
        })
        .collect()
}

fn set_decorators(defs: &mut [Def], name: &str, decorators: &[Expr]) {
    if let Some(def) = defs.iter_mut().find(|def| def.name == name) {
        def.decorators = decorator_names(decorators);
    }
}

fn collect_closures(body: &[Stmt], parent: &str, owner: Option<String>, defs: &mut Vec<Def>) {
    for stmt in body {
        let (name, args, nested, is_async) = match stmt {
            Stmt::FunctionDef(function) => (
                function.name.to_string(),
                &function.args,
                &function.body,
                false,
            ),
            Stmt::AsyncFunctionDef(function) => (
                function.name.to_string(),
                &function.args,
                &function.body,
                true,
            ),
            Stmt::If(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::For(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::AsyncFor(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::While(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                continue;
            }
            Stmt::With(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                continue;
            }
            Stmt::AsyncWith(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                continue;
            }
            Stmt::Try(stmt) => {
                collect_closures(&stmt.body, parent, owner.clone(), defs);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    collect_closures(&handler.body, parent, owner.clone(), defs);
                }
                collect_closures(&stmt.orelse, parent, owner.clone(), defs);
                collect_closures(&stmt.finalbody, parent, owner.clone(), defs);
                continue;
            }
            _ => continue,
        };
        let key = format!("{parent}.<locals>.{name}");
        if !defs.iter().any(|def| def.name == key) {
            let params = param_names(args);
            let parameter_attr_writes = parameter_attr_writes(&params, nested);
            defs.push(Def {
                name: key.clone(),
                local_name: name,
                parent: Some(parent.to_string()),
                params,
                parameter_bindings: parameter_bindings(args),
                positional_param_count: positional_param_count(args),
                callable_defaults: callable_defaults(args),
                param_defaults: param_defaults(args),
                param_types: param_types(args),
                owner: owner.clone(),
                body: Rc::new(nested.to_vec()),
                parameter_attr_writes,
                decorators: match stmt {
                    Stmt::FunctionDef(function) => decorator_names(&function.decorator_list),
                    Stmt::AsyncFunctionDef(function) => decorator_names(&function.decorator_list),
                    _ => Vec::new(),
                },
                is_async,
                is_generator: body_has_yield(nested),
            });
            collect_closures(nested, &key, owner.clone(), defs);
        }
    }
}

fn method_params(args: &ast::Arguments) -> Vec<String> {
    let names = param_names(args);
    match names.first().map(String::as_str) {
        Some("self" | "cls") => names.into_iter().skip(1).collect(),
        _ => names,
    }
}

fn positional_param_count(args: &ast::Arguments) -> usize {
    args.posonlyargs.len() + args.args.len()
}

fn method_positional_param_count(args: &ast::Arguments) -> usize {
    match param_names(args).first().map(String::as_str) {
        Some("self" | "cls") => positional_param_count(args).saturating_sub(1),
        _ => positional_param_count(args),
    }
}

fn callable_defaults(args: &ast::Arguments) -> Vec<Option<String>> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|arg| arg.default.as_deref().and_then(callee_written))
        .collect()
}

fn param_defaults(args: &ast::Arguments) -> Vec<Option<Rc<Expr>>> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|arg| {
            arg.default
                .as_deref()
                .map(|default| Rc::new(default.clone()))
        })
        .collect()
}

fn method_callable_defaults(args: &ast::Arguments) -> Vec<Option<String>> {
    let defaults = callable_defaults(args);
    match param_names(args).first().map(String::as_str) {
        Some("self" | "cls") => defaults.into_iter().skip(1).collect(),
        _ => defaults,
    }
}

fn method_param_defaults(args: &ast::Arguments) -> Vec<Option<Rc<Expr>>> {
    let defaults = param_defaults(args);
    match param_names(args).first().map(String::as_str) {
        Some("self" | "cls") => defaults.into_iter().skip(1).collect(),
        _ => defaults,
    }
}

fn param_types(args: &ast::Arguments) -> Vec<(String, String)> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .filter_map(|arg| {
            let annotation = arg.def.annotation.as_deref()?;
            Some((arg.def.arg.to_string(), callee_written(annotation)?))
        })
        .collect()
}

fn method_param_types(args: &ast::Arguments) -> Vec<(String, String)> {
    let mut types = param_types(args);
    if matches!(
        param_names(args).first().map(String::as_str),
        Some("self" | "cls")
    ) {
        types.retain(|(name, _)| !matches!(name.as_str(), "self" | "cls"));
    }
    types
}

fn collect_path_attrs(classes: &[ClassEntry]) -> Vec<(String, String, String)> {
    classes
        .iter()
        .flat_map(|class| {
            class
                .attr_classes
                .iter()
                .map(|(attr, ty)| (class.name.clone(), attr.clone(), ty.clone()))
        })
        .collect()
}

fn collect_class_bases(classes: &[ClassEntry]) -> std::collections::HashMap<String, Vec<String>> {
    classes
        .iter()
        .map(|class| (class.name.clone(), class.bases.clone()))
        .collect()
}

fn collect_class_strings(body: &[Stmt]) -> std::collections::HashMap<(String, String), String> {
    let mut out = std::collections::HashMap::new();
    for stmt in body {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        for item in &class.body {
            match item {
                Stmt::Assign(assign) => {
                    let [Expr::Name(name)] = assign.targets.as_slice() else {
                        continue;
                    };
                    if let Some(value) = str_literal(&assign.value) {
                        out.insert((class.name.to_string(), name.id.to_string()), value);
                    }
                }
                Stmt::AnnAssign(assign) => {
                    let Expr::Name(name) = assign.target.as_ref() else {
                        continue;
                    };
                    if let Some(value) = assign.value.as_deref().and_then(str_literal) {
                        out.insert((class.name.to_string(), name.id.to_string()), value);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn collect_class_sets(body: &[Stmt]) -> std::collections::HashMap<String, Vec<String>> {
    fn tuple_names(value: &Expr) -> Option<Vec<String>> {
        let Expr::Tuple(tuple) = value else {
            return None;
        };
        let names: Vec<String> = tuple
            .elts
            .iter()
            .map(callee_written)
            .collect::<Option<_>>()?;
        (!names.is_empty()).then_some(names)
    }

    let mut out = std::collections::HashMap::new();
    for stmt in body {
        match stmt {
            Stmt::Assign(assign) => {
                let [Expr::Name(name)] = assign.targets.as_slice() else {
                    continue;
                };
                if let Some(names) = tuple_names(&assign.value) {
                    out.insert(name.id.to_string(), names);
                }
            }
            Stmt::AnnAssign(assign) => {
                let Expr::Name(name) = assign.target.as_ref() else {
                    continue;
                };
                if let Some(names) = assign.value.as_deref().and_then(tuple_names) {
                    out.insert(name.id.to_string(), names);
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether a resolved resource carries usable information (anything but a
/// widened unknown). A free parameter is usable — `def f(p): return p` returns
/// its argument.
fn is_resolvable(expr: &ResourceExpr) -> bool {
    !matches!(expr, ResourceExpr::Unresolved { .. })
}

fn contains_literal(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Literal { .. } => true,
        ResourceExpr::Join { parts } => parts.iter().any(contains_literal),
        _ => false,
    }
}

/// Gather the value expressions of every `return` reachable in a function body
/// (following control flow, not descending into nested defs/classes). Sets
/// `saw_bare` when a valueless `return` is seen — the function does not always
/// return a value, so return-value inference must give up.
fn collect_returns<'a>(body: &'a [Stmt], out: &mut Vec<&'a Expr>, saw_bare: &mut bool) {
    for stmt in body {
        match stmt {
            Stmt::Return(r) => match &r.value {
                Some(v) => out.push(v),
                None => *saw_bare = true,
            },
            Stmt::If(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::For(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::AsyncFor(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::While(s) => {
                collect_returns(&s.body, out, saw_bare);
                collect_returns(&s.orelse, out, saw_bare);
            }
            Stmt::With(s) => collect_returns(&s.body, out, saw_bare),
            Stmt::AsyncWith(s) => collect_returns(&s.body, out, saw_bare),
            Stmt::Try(s) => {
                collect_returns(&s.body, out, saw_bare);
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_returns(&h.body, out, saw_bare);
                }
                collect_returns(&s.orelse, out, saw_bare);
                collect_returns(&s.finalbody, out, saw_bare);
            }
            // Nested functions and classes are separate scopes.
            _ => {}
        }
    }
}

fn body_has_yield(body: &[Stmt]) -> bool {
    fn expression_has_yield(root: &Expr) -> bool {
        let mut stack = vec![root];
        while let Some(expr) = stack.pop() {
            if matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_)) {
                return true;
            }
            stack.extend(child_exprs(expr));
        }
        false
    }

    for stmt in body {
        let found = match stmt {
            Stmt::Expr(expr) => expression_has_yield(&expr.value),
            Stmt::Assign(assign) => expression_has_yield(&assign.value),
            Stmt::AnnAssign(assign) => assign.value.as_deref().is_some_and(expression_has_yield),
            Stmt::Return(ret) => ret.value.as_deref().is_some_and(expression_has_yield),
            Stmt::If(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::For(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::AsyncFor(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::While(stmt) => body_has_yield(&stmt.body) || body_has_yield(&stmt.orelse),
            Stmt::With(stmt) => body_has_yield(&stmt.body),
            Stmt::AsyncWith(stmt) => body_has_yield(&stmt.body),
            Stmt::Try(stmt) => {
                body_has_yield(&stmt.body)
                    || stmt.handlers.iter().any(|handler| {
                        let ast::ExceptHandler::ExceptHandler(handler) = handler;
                        body_has_yield(&handler.body)
                    })
                    || body_has_yield(&stmt.orelse)
                    || body_has_yield(&stmt.finalbody)
            }
            // A nested function or class owns its own generator protocol.
            _ => false,
        };
        if found {
            return true;
        }
    }
    false
}

fn parameter_bindings(args: &ast::Arguments) -> Vec<String> {
    param_names(args)
        .into_iter()
        .chain(
            args.vararg
                .iter()
                .chain(&args.kwarg)
                .map(|arg| arg.arg.to_string()),
        )
        .collect()
}

/// Positional parameter names of a function, in order.
fn param_names(args: &ast::Arguments) -> Vec<String> {
    args.posonlyargs
        .iter()
        .chain(args.args.iter())
        .chain(args.kwonlyargs.iter())
        .map(|a| a.def.arg.to_string())
        .collect()
}

struct Walker<'a, 'b> {
    builder: &'b mut PlanBuilder,
    nest: &'a Nest<'a>,
    source: &'a str,
    condition_source: effinterp_proto::ConditionSource,
    cwd: Option<String>,
    cwd_node: Option<ProvenanceRef>,
    /// The directory the program last moved to with `os.chdir`, which later
    /// children start in instead of the launch cwd; unresolved when the
    /// target, or the branch that ran it, is unknown.
    chdir: Option<ResourceExpr>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    imports: Imports,
    /// Module-level functions, for summarizing and applying calls into them.
    defs: Vec<Def>,
    /// Computed function summaries, keyed by name.
    summaries: std::collections::HashMap<String, Summary>,
    demand_summaries: bool,
    summary_in_progress: HashSet<String>,
    summary_cycles: HashSet<String>,
    summary_refining: bool,
    summary_spans: std::collections::HashMap<String, Vec<TextRange>>,
    /// Body summaries retained behind decorator gates for repository composition.
    decorated_summaries: std::collections::HashMap<String, Summary>,
    /// Deferred subprocesses for same-file summary application, keyed by name.
    spawn_summaries: std::collections::HashMap<String, Vec<DeferredSpawn>>,
    /// Module-level path constants (`ROOT = "/var/cache"`), resolved once.
    consts: std::collections::HashMap<String, ResourceExpr>,
    shared_vars: HashSet<String>,
    /// Module constants whose value came from Python string concatenation.
    const_concatenations: HashSet<String>,
    /// Module constants that cannot be used as bounded string components.
    const_unbounded_strings: HashSet<String>,
    /// Names in the current scope resolved to a resource expression: seeded
    /// from `consts`, then extended as locals are assigned a resolvable value
    /// or the substituted return of a summarized function. A bare name that
    /// appears here resolves to its bound resource instead of a free parameter.
    var_scope: std::collections::HashMap<String, ResourceExpr>,
    /// Names whose current value is rooted in a pathlib constructor or one of
    /// its path-producing operations.
    path_vars: HashSet<String>,
    /// Path receiver names whose control-flow alternatives include a non-path
    /// value, so only unambiguous pathlib methods may dispatch at the join.
    branch_mixed_path_vars: HashSet<String>,
    /// Current bindings whose resource was lowered from `+` or an f-string.
    concatenated_vars: HashSet<String>,
    /// Current bindings that cannot be used as bounded string components.
    unbounded_string_vars: HashSet<String>,
    /// Exact finite sequence or mapping values retained from literal
    /// containers and bounded comprehensions.
    collections: std::collections::HashMap<String, StaticContainer>,
    /// Names whose control-flow alternatives disagree. A later effect use
    /// widens rather than treating the name like a free parameter.
    widened_vars: HashSet<String>,
    /// Local names bound to a constructed network object (`s =
    /// requests.Session()`, `conn = http.client.HTTPConnection(host)`), so a
    /// later `s.get(url)` / `conn.request(...)` resolves to a network effect.
    sessions: std::collections::HashMap<String, Receiver>,
    modeled_values: std::collections::HashMap<String, model::ModeledValue>,
    /// Local functions that return a constructed network object, by name, so a
    /// call `s = build_requests_session()` binds `s` to a session even though
    /// the constructor is hidden behind the helper's return.
    return_receivers: std::collections::HashMap<String, ReceiverKind>,
    /// Exact class returned by a same-file factory on every return path.
    return_instances: std::collections::HashMap<String, String>,
    /// Module receiver environment used by the current summary fixpoint.
    summary_instances: std::collections::HashMap<String, SemanticValue>,
    /// Constructor identities in finite, locally bound iterables.
    instance_sequences: std::collections::HashMap<String, Vec<Option<SemanticValue>>>,
    /// When set, effects/boundaries/coverage are collected into this buffer
    /// (summary inference) instead of emitted to the plan (execution).
    capture: Option<Capture>,
    capture_condition_depth: usize,
    /// Whether module execution entered any declared function or method.
    entered_callables: bool,
    /// Import-grounded framework decorators that preserve their function body.
    framework_decorators: HashSet<String>,
    registration_spans: HashSet<(u32, u32)>,
    /// Unresolved callees already reported, to bound boundary output.
    reported_unresolved: HashSet<(String, TextRange)>,
    nodes_left: u64,
    node_budget_hit: bool,
    /// An effect argument read a name that this execution never bound.
    free_resource_parameter: Cell<bool>,
    walk_depth: u32,
    /// Local names bound to the flow stage whose produced value they hold, so a
    /// later use of the name as a call argument wires a def-use edge. Reassigning
    /// the name to a non-producer drops the binding.
    flow_vars: std::collections::HashMap<String, usize>,
    /// Buffered flow stages and edges (local stage ids), committed to the plan
    /// only when at least one edge formed — a plan with no def-use keeps its
    /// graph omitted and serializes unchanged.
    stage_writer: StageWriter,
    /// Parameter names of the function whose body is currently being captured,
    /// so a call to a parameter can be recorded as a callback-shaped edge.
    current_params: Vec<String>,
    /// Internal identity of the function currently being summarized. Nested
    /// closure names resolve only inside their lexical parent.
    current_function: Option<String>,
    /// Parameters whose exact annotation resolves to `pathlib.Path`.
    current_path_params: HashSet<String>,
    /// Class owning the function currently being captured.
    current_class: Option<String>,
    /// Names of classes defined at this module's top level, for classifying
    /// constructor calls and class-qualified method receivers.
    class_names: HashSet<String>,
    /// Written bases of each local class, used for exact `super().method()`.
    class_bases: std::collections::HashMap<String, Vec<String>>,
    /// Instance attributes initialized by a direct constructor call.
    path_attrs: Vec<(String, String, String)>,
    /// Resource-valued instance attributes assigned by local class initializers.
    attr_values: Vec<InitAttrValue>,
    /// Literal string constants declared directly on a class.
    class_strings: std::collections::HashMap<(String, String), String>,
    /// Module constants that are finite tuples of written class names.
    class_sets: std::collections::HashMap<String, Vec<String>>,
    /// Loop variables currently ranging over one of those finite tuples.
    class_set_vars: std::collections::HashMap<String, Vec<String>>,
    /// Capture mode: locals bound to an unambiguous constructor (`loader =
    /// DataLoader()`, `cli = cls(args)`), so method calls and arguments carry
    /// a typed receiver/instance.
    instance_vars: std::collections::HashMap<String, SemanticValue>,
    /// Constructor-derived attributes invalidated by writes through a tracked
    /// local instance.
    instance_attr_rebindings: std::collections::HashMap<String, HashSet<String>>,
    /// Capture mode: locals assigned from a user-call result, typed at
    /// composition time via the callee's `returns_instances`.
    bound_vars: HashSet<String>,
    /// Receiver names explicitly rebound while joining alternative branches.
    receiver_rebindings: HashSet<String>,
    /// Capture mode: the assignment currently being walked, keyed by its RHS
    /// call's span — the recorded edge for that call gets these `binds`.
    pending_binds: Option<(TextRange, Vec<(usize, String)>)>,
    /// Capture mode: exact call edges stored directly in a literal container.
    deferred_containers: std::collections::HashMap<String, Vec<usize>>,
    /// Capture mode: loop variables currently bound to those container elements.
    deferred_vars: std::collections::HashMap<String, Vec<usize>>,
    /// The literal-container assignment currently being walked.
    pending_deferred_container: Option<(String, Vec<TextRange>)>,
    /// The call an expression statement discards, so a coroutine it makes
    /// never runs.
    discarded_call: Option<TextRange>,
    /// Whether this source may change the working directory anywhere, so a
    /// coroutine run after it is made may inherit another directory.
    source_changes_cwd: bool,
    /// Repository context for deterministic Effect IR facts. Plan-only walks
    /// leave the scope absent because they do not emit module summaries.
    fact_file: String,
    fact_scope: Option<ScopeKey>,
    fact_function: String,
    site_ordinal: Cell<u32>,
    site_origins: RefCell<std::collections::HashMap<TextRange, ValueOrigin>>,
    module_capture: bool,
    /// True while an await, iteration, or context-manager protocol executes a
    /// deferred async/generator body.
    execute_deferred: bool,
    /// The exact outer call whose result is consumed. Non-call deferred roots
    /// leave this unset; local generators are handled separately.
    deferred_call: Option<TextRange>,
    /// A consumed call that is awaited or handed straight to a scheduler that
    /// runs it (`asyncio.run`, `create_task`, `gather`, ...), rather than to a
    /// lazy wrapper such as `wait_for` whose own coroutine may never run.
    eager_call: Option<TextRange>,
    /// An eager call consumed where it is made (awaited, or passed to
    /// `asyncio.run` or `run_until_complete`), so it runs before anything
    /// after it; a scheduled one may run after later statements.
    synchronous_call: Option<TextRange>,
    /// Launch search roots for invocation import traversal. None keeps imports
    /// as dependency-request boundaries (repository indexing links modules).
    import_search: Option<imports::PythonImportSearch>,
    /// Summaries of imported functions reached by calls, keyed by
    /// [`imports::imported_summary_key`].
    imported_summaries: std::collections::HashMap<String, Rc<imports::ImportedFunction>>,
    /// Guarantees of summaries applied since the enclosing call began.
    control_applications: Vec<SiteFacts>,
    /// What each current summary guarantees to a same-file caller.
    summary_requirements: std::collections::HashMap<String, Requirements>,
    /// The summary effects each callable prints to stdout.
    summary_stdout: std::collections::HashMap<String, Vec<PrintedEffects>>,
    /// Module-level names that shadow builtins, including assignments and imports.
    module_binds: HashSet<String>,
    /// Whether the program has replaced an environment value, after which a
    /// value the host supplied no longer describes what a read sees.
    environment_rewritten: bool,
    ipython: Option<IpythonState>,
    /// Whether a bare `bash(...)` call is Prime Agent's injected shell helper.
    prime_bash: bool,
}

struct IpythonState {
    actions: std::collections::BTreeMap<u32, Vec<ipython::Action>>,
    bindings: std::collections::HashMap<String, ResourceExpr>,
    environment: std::collections::BTreeMap<String, Option<ResourceExpr>>,
    environment_nodes: std::collections::BTreeMap<String, ProvenanceRef>,
    get_ipython_owned: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct StaticResource {
    resource: ResourceExpr,
    is_path: bool,
}

#[derive(Clone, PartialEq, Eq)]
enum StaticContainer {
    Sequence(Vec<StaticResource>),
    Mapping(std::collections::HashMap<String, StaticResource>),
}

/// The construct that selects which arm `walk_branches` executes.
#[derive(Clone, Copy)]
struct BranchGuard {
    range: TextRange,
    kind: effinterp_proto::ConditionKind,
    boolean: bool,
    /// How many leading arms run unconditionally, matching the other frontends:
    /// a `try` body always executes, and only its handlers are selected.
    unguarded_arms: usize,
}

impl BranchGuard {
    /// One construct selects exactly one arm, so every arm is guarded.
    fn selection(range: TextRange, kind: effinterp_proto::ConditionKind, boolean: bool) -> Self {
        Self {
            range,
            kind,
            boolean,
            unguarded_arms: 0,
        }
    }

    /// A `try` statement: arm 0 is its body and each later arm is one handler
    /// selected by an exception the analysis does not resolve.
    fn exception_handlers(range: TextRange) -> Self {
        Self {
            range,
            kind: effinterp_proto::ConditionKind::UnresolvedExecution,
            boolean: false,
            unguarded_arms: 1,
        }
    }
}

impl Walker<'_, '_> {
    fn charge_steps(&mut self, steps: u64, span: (u32, u32)) -> bool {
        crate::limits::summary_steps(steps).unwrap_or_else(|| {
            crate::nest::charge_analysis_steps(self.builder, self.nest.budget, steps, Some(span))
        })
    }

    /// Charge one node against the frontend cap and the whole-analysis step
    /// budget; false once either is exhausted.
    fn charge(&mut self, range: TextRange) -> bool {
        let span = (u32::from(range.start()), u32::from(range.end()));
        if self.demand_summaries && self.capture.is_some() && self.nodes_left == 0 {
            if !self.node_budget_hit {
                self.node_budget_hit = true;
                let node = self.span_node(range);
                self.out_boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    affected_resource: None,
                    callee: None,
                    provenance: vec![node],
                    limit: Some("max_python_nodes".into()),
                    detail: self.current_function.clone(),
                });
            }
            return false;
        }
        if !self.charge_steps(1, span) {
            self.node_budget_hit = true;
            return false;
        }
        if self.nodes_left == 0 {
            if !self.node_budget_hit {
                self.node_budget_hit = true;
                boundary(
                    self.builder,
                    self.scope,
                    BoundaryReason::LIMIT_SATURATED,
                    BoundaryClass::Limit,
                    Some("max_python_nodes"),
                    None,
                );
            }
            return false;
        }
        self.nodes_left -= 1;
        true
    }

    fn walk_body(&mut self, body: &[Stmt]) {
        let depth = self.builder.condition_depth();
        for stmt in body {
            if self.node_budget_hit {
                break;
            }
            self.walk_stmt(stmt);
            if let Stmt::If(branch) = stmt {
                let stops = |body: &[Stmt]| {
                    matches!(
                        body.last(),
                        Some(Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_))
                    )
                };
                let yes = stops(&branch.body);
                let no = stops(&branch.orelse);
                if yes != no {
                    let arm = u32::from(yes);
                    self.builder
                        .push_condition(self.builder.source_condition_path(
                            effinterp_proto::Condition::from_source_with_digest(
                                self.source,
                                self.condition_source.digest().to_string(),
                                effinterp_proto::ByteSpan {
                                    start: branch.range.start().into(),
                                    end: branch.range.end().into(),
                                },
                                effinterp_proto::ConditionKind::Branch,
                                arm,
                                2,
                                true,
                                true,
                            ),
                        ));
                }
            }
        }
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    /// Walk the alternative bodies of a conditionally-executed construct (an
    /// `if`'s arms, a loop body, the arms of a `try`) so a def-use binding
    /// created or killed inside does not leak past the join. A variable a branch
    /// assigns has no single unambiguous producer at the join — the branch may
    /// not have run, or a sibling branch may assign it differently — so its
    /// tracking is dropped there. Each arm starts from the pre-construct binding
    /// state (arms are alternatives); within-arm producer→consumer edges still
    /// form during the walk. Resource and container bindings survive only when
    /// every arm produces the same exact value. A receiver or call-result
    /// binding introduced in one arm may survive untouched alternatives, but
    /// any explicit rebinding drops it.
    fn walk_branches(
        &mut self,
        branches: &[(&[Stmt], Option<&str>, Option<&Expr>)],
        guard: Option<BranchGuard>,
    ) {
        let entry_flow = self.flow_vars.clone();
        let entry_vars = self.var_scope.clone();
        let entry_path_vars = self.path_vars.clone();
        let entry_branch_mixed_path_vars = self.branch_mixed_path_vars.clone();
        let entry_concatenated = self.concatenated_vars.clone();
        let entry_unbounded_strings = self.unbounded_string_vars.clone();
        let entry_widened = self.widened_vars.clone();
        let entry_collections = self.collections.clone();
        let entry_instance_sequences = self.instance_sequences.clone();
        let mut instance_sequence_states = Vec::new();
        let entry_sessions = self.sessions.clone();
        let entry_modeled = self.modeled_values.clone();
        let mut modeled_states = Vec::new();
        let entry_instances = self.instance_vars.clone();
        let entry_instance_attr_rebindings = self.instance_attr_rebindings.clone();
        let entry_bound = self.bound_vars.clone();
        let entry_receiver_rebindings = self.receiver_rebindings.clone();
        let entry_deferred_containers = self.deferred_containers.clone();
        let entry_deferred_vars = self.deferred_vars.clone();
        let entry_cwd = (self.cwd.clone(), self.chdir.clone());
        let mut cwd_states = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        let mut var_states = Vec::new();
        let mut path_var_states = Vec::new();
        let mut branch_mixed_path_var_states = Vec::new();
        let mut concatenated_states = Vec::new();
        let mut unbounded_string_states = Vec::new();
        let mut widened_states = Vec::new();
        let mut collection_states = Vec::new();
        let mut session_states = Vec::new();
        let mut instance_states = Vec::new();
        let mut instance_attr_rebinding_states = Vec::new();
        let mut bound_states = Vec::new();
        let mut receiver_rebinding_states = Vec::new();
        let mut deferred_container_states = Vec::new();
        let mut deferred_var_states = Vec::new();
        for (arm, (body, rebound_path, test)) in branches.iter().enumerate() {
            self.flow_vars = entry_flow.clone();
            self.var_scope = entry_vars.clone();
            self.path_vars = entry_path_vars.clone();
            self.branch_mixed_path_vars = entry_branch_mixed_path_vars.clone();
            self.concatenated_vars = entry_concatenated.clone();
            self.unbounded_string_vars = entry_unbounded_strings.clone();
            self.widened_vars = entry_widened.clone();
            self.collections = entry_collections.clone();
            self.instance_sequences = entry_instance_sequences.clone();
            self.sessions = entry_sessions.clone();
            self.modeled_values = entry_modeled.clone();
            self.instance_vars = entry_instances.clone();
            self.instance_attr_rebindings = entry_instance_attr_rebindings.clone();
            self.bound_vars = entry_bound.clone();
            self.receiver_rebindings.clear();
            self.deferred_containers = entry_deferred_containers.clone();
            self.deferred_vars = entry_deferred_vars.clone();
            (self.cwd, self.chdir) = entry_cwd.clone();
            if let Some(name) = rebound_path {
                self.invalidate_rebound_name(name);
            }
            if let Some(test) = test {
                self.walk_expr(test);
            }
            let condition = guard
                .filter(|guard| arm >= guard.unguarded_arms)
                .map(|guard| {
                    self.builder.source_condition_path(
                        effinterp_proto::Condition::from_source_with_digest(
                            self.source,
                            self.condition_source.digest().to_string(),
                            effinterp_proto::ByteSpan {
                                start: guard.range.start().into(),
                                end: guard.range.end().into(),
                            },
                            guard.kind,
                            arm as u32,
                            branches.len().max(2) as u32,
                            true,
                            guard.boolean,
                        ),
                    )
                });
            let guarded = condition.is_some();
            if let Some(condition) = condition {
                self.builder.push_condition(condition);
            }
            self.walk_body(body);
            if guarded {
                self.builder.pop_condition();
            }
            if self.capture.is_none() {
                for name in self.flow_vars.keys().chain(entry_flow.keys()) {
                    if self.flow_vars.get(name) != entry_flow.get(name) && !touched.contains(name) {
                        touched.push(name.clone());
                    }
                }
            }
            var_states.push(self.var_scope.clone());
            path_var_states.push(self.path_vars.clone());
            branch_mixed_path_var_states.push(self.branch_mixed_path_vars.clone());
            concatenated_states.push(self.concatenated_vars.clone());
            unbounded_string_states.push(self.unbounded_string_vars.clone());
            widened_states.push(self.widened_vars.clone());
            collection_states.push(self.collections.clone());
            instance_sequence_states.push(self.instance_sequences.clone());
            session_states.push(self.sessions.clone());
            modeled_states.push(self.modeled_values.clone());
            instance_states.push(self.instance_vars.clone());
            instance_attr_rebinding_states.push(self.instance_attr_rebindings.clone());
            bound_states.push(self.bound_vars.clone());
            receiver_rebinding_states.push(self.receiver_rebindings.clone());
            deferred_container_states.push(self.deferred_containers.clone());
            deferred_var_states.push(self.deferred_vars.clone());
            cwd_states.push((self.cwd.clone(), self.chdir.clone()));
        }
        // Arms that leave the program in different directories leave it in an
        // unknown one.
        if cwd_states.iter().any(|state| *state != cwd_states[0]) {
            self.cwd = None;
            self.chdir = Some(unresolved("filesystem"));
        }
        self.flow_vars = entry_flow;
        for name in touched {
            self.flow_vars.remove(&name);
        }
        let mut all_var_names = BTreeSet::new();
        for state in &var_states {
            all_var_names.extend(state.keys().cloned());
        }
        self.var_scope = var_states
            .last()
            .cloned()
            .unwrap_or_else(|| entry_vars.clone());
        self.var_scope.retain(|name, value| {
            var_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.path_vars.clear();
        for state in &path_var_states {
            self.path_vars.extend(state.iter().cloned());
        }
        self.branch_mixed_path_vars.clear();
        for state in branch_mixed_path_var_states {
            self.branch_mixed_path_vars.extend(state);
        }
        for name in &self.path_vars {
            let entry_holds_non_path = !entry_path_vars.contains(name)
                && (entry_vars.contains_key(name)
                    || entry_receiver_rebindings.contains(name)
                    || self.current_function.as_ref().is_some_and(|function| {
                        self.defs
                            .iter()
                            .find(|def| def.name == function.as_str())
                            .is_some_and(|def| def.params.contains(name))
                    }));
            if path_var_states
                .iter()
                .zip(&receiver_rebinding_states)
                .any(|(paths, rebound)| {
                    !paths.contains(name) && (entry_holds_non_path || rebound.contains(name))
                })
            {
                self.branch_mixed_path_vars.insert(name.clone());
            }
        }
        self.concatenated_vars = concatenated_states
            .last()
            .cloned()
            .unwrap_or(entry_concatenated);
        self.concatenated_vars
            .retain(|name| concatenated_states.iter().all(|state| state.contains(name)));
        self.unbounded_string_vars.clear();
        for state in unbounded_string_states {
            self.unbounded_string_vars.extend(state);
        }
        self.widened_vars = entry_widened;
        for state in widened_states {
            self.widened_vars.extend(state);
        }
        for name in all_var_names {
            let mut values = var_states.iter().map(|state| state.get(&name));
            let first = values.next().flatten();
            if first.is_none() || values.any(|value| value != first) {
                self.widened_vars.insert(name);
            }
        }
        self.collections = collection_states.pop().unwrap_or(entry_collections);
        self.collections.retain(|name, value| {
            collection_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.instance_sequences = instance_sequence_states
            .pop()
            .unwrap_or(entry_instance_sequences);
        self.instance_sequences.retain(|name, value| {
            instance_sequence_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.modeled_values = modeled_states.pop().unwrap_or(entry_modeled);
        self.modeled_values.retain(|name, value| {
            modeled_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.sessions = session_states.pop().unwrap_or(entry_sessions);
        self.sessions.retain(|name, value| {
            session_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        let mut joined_instances = std::collections::HashMap::new();
        let mut ambiguous_instances = HashSet::new();
        for state in &instance_states {
            for (name, value) in state {
                match joined_instances.get(name) {
                    None => {
                        joined_instances.insert(name.clone(), value.clone());
                    }
                    Some(previous) if previous == value => {}
                    Some(_) => {
                        ambiguous_instances.insert(name.clone());
                    }
                }
            }
        }
        joined_instances.retain(|name, _| {
            !ambiguous_instances.contains(name)
                && instance_states
                    .iter()
                    .zip(&receiver_rebinding_states)
                    .all(|(state, rebound)| state.contains_key(name) || !rebound.contains(name))
        });
        self.instance_vars = joined_instances;
        self.instance_attr_rebindings.clear();
        for state in instance_attr_rebinding_states {
            for (name, attrs) in state {
                self.instance_attr_rebindings
                    .entry(name)
                    .or_default()
                    .extend(attrs);
            }
        }
        let mut joined_bound = entry_bound;
        for state in &bound_states {
            joined_bound.extend(state.iter().cloned());
        }
        joined_bound.retain(|name| {
            bound_states
                .iter()
                .zip(&receiver_rebinding_states)
                .all(|(state, rebound)| state.contains(name) || !rebound.contains(name))
        });
        self.bound_vars = joined_bound;
        self.receiver_rebindings = entry_receiver_rebindings;
        for state in receiver_rebinding_states {
            self.receiver_rebindings.extend(state);
        }
        self.deferred_containers = deferred_container_states
            .pop()
            .unwrap_or(entry_deferred_containers);
        self.deferred_containers.retain(|name, value| {
            deferred_container_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
        self.deferred_vars = deferred_var_states.pop().unwrap_or(entry_deferred_vars);
        self.deferred_vars.retain(|name, value| {
            deferred_var_states
                .iter()
                .all(|state| state.get(name) == Some(value))
        });
    }

    fn walk_stmt(&mut self, stmt: &Stmt) {
        if !self.charge(stmt.range()) {
            return;
        }
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        self.walk_depth += 1;
        self.walk_stmt_inner(stmt);
        self.walk_depth -= 1;
    }

    fn partial_walk(&mut self) {
        if self.node_budget_hit {
            return;
        }
        self.node_budget_hit = true;
        boundary(
            self.builder,
            self.scope,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            Some("max_walk_depth"),
            Some("python walk depth bound reached".to_string()),
        );
    }

    fn invalidate_rebound_name(&mut self, name: &str) {
        if name == "get_ipython"
            && let Some(state) = self.ipython.as_mut()
        {
            state.get_ipython_owned = false;
        }
        self.imports.shadow(name);
        self.modeled_values.remove(name);
        self.clear_bound_receiver(name);
        self.var_scope.remove(name);
        self.collections.remove(name);
        if self.path_vars.contains(name) {
            self.widened_vars.insert(name.to_string());
        }
        self.concatenated_vars.remove(name);
        self.unbounded_string_vars.remove(name);
    }

    fn invalidate_rebound_target(&mut self, target: &Expr) {
        for name in rebound_target_names(target) {
            self.invalidate_rebound_name(&name);
        }
    }

    fn walk_assignment_target(&mut self, target: &Expr) {
        let mut targets = vec![target];
        while let Some(target) = targets.pop() {
            match target {
                Expr::Attribute(attribute) => self.walk_expr(&attribute.value),
                Expr::Subscript(subscript) => {
                    self.walk_expr(&subscript.value);
                    self.walk_expr(&subscript.slice);
                }
                Expr::Tuple(tuple) => targets.extend(tuple.elts.iter().rev()),
                Expr::List(list) => targets.extend(list.elts.iter().rev()),
                Expr::Starred(starred) => targets.push(&starred.value),
                _ => {}
            }
            if self.imports.is_namespace_write(target) {
                self.imports.namespace_mutated = true;
                self.invalidate_namespace_values();
                self.emit_unresolved_call(
                    "namespace mutation",
                    BoundaryReason::DYNAMIC_DISPATCH,
                    BoundaryClass::Unresolved,
                    crate::external::ALL_DOMAINS,
                    target.range(),
                    None,
                );
            } else if let Expr::Attribute(_) = target
                && let Some(name) = self.imports.resolve_callee(target)
            {
                self.imports.shadow(&name);
            }
        }
    }

    fn record_namespace_escape(&mut self, expr: &Expr) {
        if !self.imports.namespace_mutated && self.imports.is_namespace_value(expr) {
            self.imports.namespace_mutated = true;
            self.invalidate_namespace_values();
            self.emit_unresolved_call(
                "namespace escape",
                BoundaryReason::DYNAMIC_DISPATCH,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                expr.range(),
                None,
            );
        }
    }

    fn invalidate_namespace_values(&mut self) {
        // Reflective namespace writes can replace any tracked binding. The
        // summary does not transfer their replacement values back to callers.
        let names: HashSet<_> = self
            .var_scope
            .keys()
            .chain(self.consts.keys())
            .chain(self.modeled_values.keys())
            .chain(self.instance_vars.keys())
            .cloned()
            .collect();
        for name in names {
            self.invalidate_rebound_name(&name);
        }
        self.consts.clear();
    }

    fn invalidate_shared_vars(&mut self) {
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        // Calls can reach global/nonlocal writes whose values are not transferred
        // back through summaries or unresolved dispatch boundaries.
        for name in self.shared_vars.clone() {
            self.invalidate_rebound_name(&name);
        }
    }

    fn invalidate_loop_bindings(&mut self, body: &[Stmt]) {
        let mut names = rebound_body_names(body, false);
        names.extend(self.shared_vars.iter().cloned());
        // Mutable values can change through an alias on an earlier iteration.
        names.extend(
            self.modeled_values
                .iter()
                .filter(|(_, value)| {
                    matches!(
                        value,
                        model::ModeledValue::BuiltinData | model::ModeledValue::Request { .. }
                    )
                })
                .map(|(name, _)| name.clone()),
        );
        for name in names {
            self.invalidate_rebound_name(&name);
        }
    }

    fn walk_for(&mut self, target: &Expr, iter: &Expr, body: &[Stmt], orelse: &[Stmt]) {
        self.walk_deferred(iter);
        let path_iter_resource = self.path_iter_resource(iter);
        let static_values = self.static_iter_resources(iter);
        let static_instances = self.static_iter_instances(iter);
        let loop_name = match target {
            Expr::Name(name) => Some(name.id.to_string()),
            _ => None,
        };
        let prior_classes = loop_name
            .as_ref()
            .and_then(|name| self.class_set_vars.remove(name));
        let prior_deferred = loop_name
            .as_ref()
            .and_then(|name| self.deferred_vars.remove(name));
        if let (Some(loop_name), Expr::Name(iter)) = (&loop_name, iter)
            && let Some(classes) = self.class_sets.get(iter.id.as_str())
        {
            self.class_set_vars
                .insert(loop_name.clone(), classes.clone());
        }
        if let (Some(loop_name), Expr::Name(iter)) = (&loop_name, iter)
            && let Some(calls) = self.deferred_containers.get(iter.id.as_str())
        {
            self.deferred_vars.insert(loop_name.clone(), calls.clone());
        }
        self.invalidate_loop_bindings(body);
        self.walk_assignment_target(target);
        self.invalidate_rebound_target(target);
        if let Some(loop_name) = &loop_name
            && let Some(receiver) = &path_iter_resource
        {
            self.clear_bound_receiver(loop_name);
            self.var_scope.insert(loop_name.clone(), receiver.clone());
            self.path_vars.insert(loop_name.clone());
            self.branch_mixed_path_vars.remove(loop_name);
            self.widened_vars.remove(loop_name);
        }
        if path_iter_resource.is_none() && (loop_name.is_none() || static_values.is_none()) {
            self.invalidate_rebound_target(target);
        }

        if let Some(name) = &loop_name
            && let Some(values) = static_values
        {
            let instances = static_instances.unwrap_or_default();
            let prior_flow = self.flow_vars.clone();
            for (index, value) in values.into_iter().enumerate() {
                self.modeled_values.remove(name);
                self.clear_bound_receiver(name);
                self.widened_vars.remove(name);
                self.concatenated_vars.remove(name);
                self.unbounded_string_vars.remove(name);
                self.var_scope.insert(name.clone(), value.resource);
                if value.is_path {
                    self.path_vars.insert(name.clone());
                } else {
                    self.path_vars.remove(name);
                }
                self.branch_mixed_path_vars.remove(name);
                if let Some(instance) = instances.get(index).cloned().flatten() {
                    self.instance_vars.insert(name.clone(), instance);
                }
                self.walk_body(body);
            }
            self.flow_vars = prior_flow;
            self.walk_body(orelse);
        } else if let Some(name) = &loop_name
            && let Some(instances) = static_instances
            && instances.iter().any(Option::is_some)
        {
            let prior_flow = self.flow_vars.clone();
            for instance in instances {
                self.invalidate_rebound_name(name);
                if let Some(instance) = instance {
                    self.instance_vars.insert(name.clone(), instance);
                }
                self.walk_body(body);
            }
            self.flow_vars = prior_flow;
            self.walk_body(orelse);
        } else {
            self.walk_branches(
                &[(body, None, None), (orelse, None, None)],
                Some(BranchGuard::selection(
                    iter.range(),
                    effinterp_proto::ConditionKind::Loop,
                    false,
                )),
            );
        }

        if let Some(loop_name) = loop_name {
            self.class_set_vars.remove(&loop_name);
            if let Some(prior) = prior_classes {
                self.class_set_vars.insert(loop_name.clone(), prior);
            }
            self.deferred_vars.remove(&loop_name);
            if let Some(prior) = prior_deferred {
                self.deferred_vars.insert(loop_name, prior);
            }
        }
    }

    fn bind_context(&mut self, item: &ast::WithItem) {
        let resource = self
            .temporary_context_resource(&item.context_expr)
            .or_else(|| self.context_resource(&item.context_expr));
        self.bind_context_resource(item, resource);
    }

    fn bind_context_resource(&mut self, item: &ast::WithItem, resource: Option<ResourceExpr>) {
        let Some(target) = item.optional_vars.as_deref() else {
            return;
        };
        self.walk_assignment_target(target);
        let Expr::Name(target) = target else {
            self.invalidate_rebound_target(target);
            return;
        };
        let name = target.id.to_string();
        self.clear_bound_receiver(&name);
        match resource {
            Some(resource) => {
                self.var_scope.insert(name.clone(), resource);
                self.widened_vars.remove(&name);
                self.path_vars.remove(&name);
                self.branch_mixed_path_vars.remove(&name);
            }
            None => {
                self.var_scope.remove(&name);
                self.widened_vars.insert(name.clone());
                self.path_vars.remove(&name);
                self.branch_mixed_path_vars.remove(&name);
            }
        }
        self.concatenated_vars.remove(&name);
        self.unbounded_string_vars.remove(&name);
        self.collections.remove(&name);
        match self.net_receiver(&item.context_expr) {
            Some(receiver) => {
                self.sessions.insert(name.clone(), receiver);
            }
            None => {
                self.sessions.remove(&name);
                self.modeled_values.remove(&name);
            }
        }
        if let Expr::Call(call) = &item.context_expr
            && matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("open" | "io.open")
            )
            && let Some(instance) = self.ctor_class(call)
        {
            self.instance_vars.insert(name.clone(), instance);
        }
        if let Some(value) = self.modeled_value(&item.context_expr)
            && matches!(&value, model::ModeledValue::Temporary { kind, .. } if kind == "tempfile.NamedTemporaryFile")
        {
            self.modeled_values.insert(name.clone(), value);
        }
        if self.capture.is_some()
            && let Expr::Call(call) = &item.context_expr
            && self.imports.resolve_callee(&call.func).as_deref() == Some("asyncio.TaskGroup")
            && let Some(instance) = self.ctor_class(call)
        {
            self.instance_vars.insert(name, instance);
        }
        self.imports.shadow(target.id.as_str());
    }

    fn local_context(&self, expr: &Expr) -> Option<(String, SemanticValue, TextRange)> {
        let (receiver, span) = match expr {
            Expr::Call(call) => (self.ctor_class(call)?, call.range),
            Expr::Name(name) => (
                self.instance_vars.get(name.id.as_str())?.clone(),
                name.range,
            ),
            _ => return None,
        };
        let ObjectIdentity::Class { name, .. } = &receiver.as_object()?.identity else {
            return None;
        };
        let name = name.clone();
        self.defs
            .iter()
            .any(|def| def.name == format!("{name}.__enter__"))
            .then_some((name, receiver, span))
    }

    fn walk_with(&mut self, items: &[ast::WithItem], body: &[Stmt]) {
        let mut contexts = Vec::new();
        for item in items {
            // Entering a context does not consume a filesystem iterator.
            if matches!(&item.context_expr, Expr::Call(call)
                if matches!(self.imports.resolve_callee(&call.func).as_deref(),
                    Some("glob.iglob" | "os.walk")))
            {
                self.walk_expr(&item.context_expr);
            } else {
                self.walk_deferred(&item.context_expr);
            }
            let (enter, suppress) = control::context_spans(item);
            let capture = self.capture.is_some();
            if let Some((class, receiver, span)) = self.local_context(&item.context_expr) {
                let applications = std::mem::take(&mut self.control_applications);
                let resource = self.apply_context_method(&class, "__enter__", &receiver, span);
                let entered = std::mem::replace(&mut self.control_applications, applications);
                if let [entered] = entered.as_slice() {
                    self.builder
                        .control_site(self.source, capture, enter, entered.clone());
                }
                self.bind_context_resource(item, resource);
                contexts.push((class, receiver, span));
            } else {
                let modeled = self.modeled_context(&item.context_expr)
                    || self.context_resource(&item.context_expr).is_some()
                    || matches!(&item.context_expr, Expr::Call(call) if self.imports.resolve_callee(&call.func).as_deref().is_some_and(|name| matches!(name, "open" | "io.open")));
                let file = matches!(&item.context_expr, Expr::Call(call) if self.imports.resolve_callee(&call.func).as_deref().is_some_and(|name| matches!(name, "open" | "io.open")));
                if file {
                    // A file object neither runs code on entry nor swallows
                    // exceptions on exit.
                    self.builder.control_site(
                        self.source,
                        capture,
                        enter,
                        SiteFacts::known(Vec::new()),
                    );
                    self.builder.control_site(
                        self.source,
                        capture,
                        suppress,
                        SiteFacts {
                            returns: false,
                            ..SiteFacts::default()
                        },
                    );
                }
                self.bind_context(item);
                if !modeled {
                    let name = callee_written(&item.context_expr).unwrap_or_else(|| {
                        self.source[usize::from(item.context_expr.range().start())
                            ..usize::from(item.context_expr.range().end())]
                            .to_string()
                    });
                    self.emit_unresolved_call(
                        &name,
                        BoundaryReason::DYNAMIC_DISPATCH,
                        BoundaryClass::Unresolved,
                        crate::external::ALL_DOMAINS,
                        item.context_expr.range(),
                        Some(CalleeReference {
                            module: name.clone(),
                            symbol: "__enter__/__exit__".to_string(),
                        }),
                    );
                }
            }
        }
        self.walk_body(body);
        for (class, receiver, span) in contexts.into_iter().rev() {
            self.apply_context_method(&class, "__exit__", &receiver, span);
        }
    }

    fn context_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        let Expr::Call(call) = expr else { return None };
        let name = self.local_callee(&call.func)?;
        let def = self.defs.iter().find(|def| def.name == name)?;
        let is_contextmanager = def.decorators.iter().any(|decorator| {
            matches!(
                self.imports
                    .resolve_written(decorator)
                    .unwrap_or_else(|| decorator.clone())
                    .as_str(),
                "contextlib.contextmanager" | "contextlib.asynccontextmanager"
            )
        });
        if !is_contextmanager {
            return None;
        }
        let values = self.static_iter_values(expr)?;
        let [value] = values.as_slice() else {
            return None;
        };
        Some(value.clone())
    }

    /// Importing an unmodeled module runs its top level, which may complete
    /// the invocation; a repository view can discharge a resolved module.
    fn register_import(&mut self, modules: &[&str], span: TextRange) {
        let unmodeled: Vec<_> = modules
            .iter()
            .filter(|module| !is_python_stdlib(module.split('.').next().unwrap_or(module)))
            .collect();
        let mut facts = SiteFacts::known(Vec::new());
        facts.exit = match unmodeled.as_slice() {
            [] => None,
            [module] => Some(ControlExit::Import {
                module: module.to_string(),
            }),
            _ => Some(ControlExit::Unknown),
        };
        self.builder.control_site(
            self.source,
            self.capture.is_some(),
            control::span(span),
            facts,
        );
    }

    fn import_boundary(&mut self, module: &str, span: TextRange) {
        if !crate::external::is_python_stdlib(module.split('.').next().unwrap_or(module))
            && !crate::LIFECYCLE_CATALOG.iter().any(|model| {
                model.lang == Some(crate::Lang::Python)
                    && model
                        .sigs
                        .iter()
                        .any(|sig| sig.component.is_some() && sig.import_path == Some(module))
            })
        {
            self.emit_unresolved_call(
                module,
                BoundaryReason::UNMODELED_IMPORT,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                span,
                Some(CalleeReference {
                    module: module.to_string(),
                    symbol: "__module_init__".to_string(),
                }),
            );
        }
    }

    fn walk_stmt_inner(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(import) => {
                let modules: Vec<_> = import
                    .names
                    .iter()
                    .map(|alias| alias.name.as_str())
                    .collect();
                self.register_import(&modules, import.range);
                for alias in &import.names {
                    if !self.import_python_module(alias.name.as_str(), &[], import.range) {
                        self.import_boundary(alias.name.as_str(), import.range);
                    }
                    let name = alias.asname.as_deref().unwrap_or_else(|| {
                        alias
                            .name
                            .as_str()
                            .split('.')
                            .next()
                            .unwrap_or(alias.name.as_str())
                    });
                    self.invalidate_rebound_name(name);
                    self.add_import(alias.name.as_str(), alias.asname.as_deref());
                }
            }
            Stmt::ImportFrom(from) => {
                let module = import_from_module(from);
                self.register_import(&[&module], from.range);
                let members: Vec<&str> = from
                    .names
                    .iter()
                    .map(|alias| alias.name.as_str())
                    .filter(|name| *name != "*")
                    .collect();
                if !self.import_python_module(&module, &members, from.range) {
                    self.import_boundary(&module, from.range);
                }
                if from.names.iter().any(|a| a.name.as_str() == "*") {
                    if let Some(exports) = star_exports(&module) {
                        for member in exports {
                            self.invalidate_rebound_name(member);
                            self.add_from_import(&module, member, None);
                        }
                    } else {
                        boundary(
                            self.builder,
                            self.scope,
                            BoundaryReason::UNMODELED_IMPORT,
                            BoundaryClass::Unmodeled,
                            None,
                            Some(format!("from {module} import *")),
                        );
                    }
                    return;
                }
                for alias in &from.names {
                    self.invalidate_rebound_name(
                        alias.asname.as_deref().unwrap_or(alias.name.as_str()),
                    );
                    self.add_from_import(&module, alias.name.as_str(), alias.asname.as_deref());
                }
            }
            Stmt::Assign(assign) => {
                // Any assignment to a bare name shadows a tracked import.
                for target in &assign.targets {
                    if let Expr::Name(n) = target {
                        self.imports.shadow(n.id.as_str());
                        self.widened_vars.remove(n.id.as_str());
                    }
                    if let Expr::Subscript(subscript) = target
                        && let Expr::Name(name) = subscript.value.as_ref()
                    {
                        self.invalidate_collection(name.id.as_str());
                    }
                    self.env_subscript_write(target, false);
                }
                // Track every bare name in `q = target = value` so a resource
                // returned by a helper (or a literal path) flows to later uses.
                // Other target shapes drop stale tracking for their bound names,
                // then restore exact static unpack bindings.
                let names: Vec<_> = assign
                    .targets
                    .iter()
                    .filter_map(|target| match target {
                        Expr::Name(name) => Some(name.id.to_string()),
                        _ => None,
                    })
                    .collect();
                for target in &assign.targets {
                    self.ipython_invalidate_getter_target(target);
                }
                if names.iter().any(|name| name == "get_ipython")
                    && let Some(state) = self.ipython.as_mut()
                {
                    state.get_ipython_owned = false;
                }
                if !self.bind_assigned_names(&names, &assign.value) {
                    return;
                }
                for target in &assign.targets {
                    self.walk_assignment_target(target);
                }
                if names.len() != assign.targets.len() {
                    let unpack = self.static_unpack(&assign.targets, &assign.value);
                    for target in &assign.targets {
                        if !matches!(target, Expr::Name(_)) {
                            self.invalidate_rebound_target(target);
                        }
                    }
                    if let Some(bindings) = unpack {
                        self.track_unpack(bindings);
                    }
                }
                // Track constructed receivers in both execution and capture;
                // capture additionally consumes the pending result binding.
                self.track_assign(assign);
                self.flow_assign(assign.targets.as_slice(), &assign.value);
                self.track_instance_attr_assignments(&assign.targets);
                self.ipython_track_assignment(&names, &assign.value);
                self.pending_binds = None;
                self.pending_deferred_container = None;
            }
            // `x: T = f()` is executed like `x = f()` — the annotation is not
            // a skip. Console-script mains often bind a constructor-chained
            // call this way (`code: int = App().run()`).
            Stmt::AnnAssign(assign) => {
                self.ipython_invalidate_getter_target(&assign.target);
                if let Expr::Name(n) = assign.target.as_ref() {
                    self.imports.shadow(n.id.as_str());
                    self.widened_vars.remove(n.id.as_str());
                }
                self.env_subscript_write(&assign.target, false);
                let Some(value) = &assign.value else {
                    return;
                };
                if let Expr::Name(target) = assign.target.as_ref()
                    && !self.bind_assigned_names(&[target.id.to_string()], value)
                {
                    return;
                }
                self.walk_assignment_target(&assign.target);
                self.track_named_value(assign.target.as_ref(), value);
                self.flow_assign(std::slice::from_ref(assign.target.as_ref()), value);
                self.track_instance_attr_assignments(std::slice::from_ref(assign.target.as_ref()));
                if let Expr::Name(target) = assign.target.as_ref() {
                    self.ipython_track_assignment(&[target.id.to_string()], value);
                }
                self.pending_binds = None;
                self.pending_deferred_container = None;
            }
            Stmt::AugAssign(assign) => {
                self.ipython_invalidate_getter_target(&assign.target);
                self.walk_assignment_target(&assign.target);
                self.flow_expr(&assign.value);
                self.track_instance_attr_assignments(std::slice::from_ref(assign.target.as_ref()));
                let Expr::Name(target) = assign.target.as_ref() else {
                    return;
                };
                let name = target.id.to_string();
                self.clear_bound_receiver(&name);
                self.imports.shadow(&name);
                self.widened_vars.remove(&name);
                let part = (assign.op == ast::Operator::Add
                    && !self.unbounded_string_vars.contains(&name)
                    && !self.concatenation_uses_unbounded_binding(&assign.value))
                .then(|| {
                    resolve::concatenated_part_resource(
                        &assign.value,
                        &self.imports,
                        (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
                    )
                })
                .flatten()
                .map(|part| substitute_resource_expr(&part, &self.var_scope));
                match (self.var_scope.get(&name).cloned(), part) {
                    (Some(previous), Some(part)) => {
                        self.var_scope.insert(
                            name.clone(),
                            ResourceExpr::Join {
                                parts: vec![previous, part],
                            },
                        );
                        self.concatenated_vars.insert(name.clone());
                        self.unbounded_string_vars.remove(&name);
                    }
                    _ if self.path_vars.contains(&name) => {
                        self.invalidate_rebound_name(&name);
                    }
                    _ => {
                        self.var_scope.remove(&name);
                        self.path_vars.remove(&name);
                        self.branch_mixed_path_vars.remove(&name);
                        self.concatenated_vars.remove(&name);
                        self.unbounded_string_vars.insert(name.clone());
                    }
                }
                self.collections.remove(&name);
                self.sessions.remove(&name);
                self.modeled_values.remove(&name);
                self.flow_vars.remove(&name);
                self.pending_binds = None;
                self.pending_deferred_container = None;
                if let Expr::Name(target) = assign.target.as_ref()
                    && let Some(state) = self.ipython.as_mut()
                {
                    state.bindings.remove(target.id.as_str());
                }
            }
            Stmt::Expr(expr) => {
                if !self.ipython_sentinel(expr) {
                    self.discarded_call = match expr.value.as_ref() {
                        Expr::Call(call) => Some(call.range),
                        _ => None,
                    };
                    self.flow_expr(&expr.value);
                    self.discarded_call = None;
                }
            }
            // A function definition does not execute its body; the body's
            // effects only count if execution reaches a call to it (see
            // `follow_def`). Defining a function shadows any tracked import
            // of the same name.
            Stmt::FunctionDef(f) => {
                for decorator in &f.decorator_list {
                    self.apply_decorator(decorator);
                }
                self.imports.shadow(f.name.as_str());
                self.invalidate_rebound_name(f.name.as_str());
                self.receiver_rebindings.remove(f.name.as_str());
            }
            Stmt::AsyncFunctionDef(f) => {
                for decorator in &f.decorator_list {
                    self.apply_decorator(decorator);
                }
                self.imports.shadow(f.name.as_str());
                self.invalidate_rebound_name(f.name.as_str());
                self.receiver_rebindings.remove(f.name.as_str());
            }
            // A class body executes at definition time; nested method
            // definitions within it are themselves no-ops.
            Stmt::ClassDef(c) => {
                for decorator in &c.decorator_list {
                    self.apply_decorator(decorator);
                }
                self.imports.shadow(c.name.as_str());
                // Class-body path bindings are local to the class namespace.
                let outer_var_scope = self.var_scope.clone();
                let outer_modeled_values = self.modeled_values.clone();
                let outer_path_vars = self.path_vars.clone();
                let outer_branch_mixed_path_vars = self.branch_mixed_path_vars.clone();
                let outer_widened_vars = self.widened_vars.clone();
                let outer_concatenated_vars = self.concatenated_vars.clone();
                let outer_unbounded_string_vars = self.unbounded_string_vars.clone();
                let outer_instance_vars = self.instance_vars.clone();
                let outer_bound_vars = self.bound_vars.clone();
                let outer_receiver_rebindings = self.receiver_rebindings.clone();
                self.walk_body(&c.body);
                self.var_scope = outer_var_scope;
                self.modeled_values = outer_modeled_values;
                self.path_vars = outer_path_vars;
                self.branch_mixed_path_vars = outer_branch_mixed_path_vars;
                self.widened_vars = outer_widened_vars;
                self.concatenated_vars = outer_concatenated_vars;
                self.unbounded_string_vars = outer_unbounded_string_vars;
                self.instance_vars = outer_instance_vars;
                self.bound_vars = outer_bound_vars;
                self.receiver_rebindings = outer_receiver_rebindings;
                // Class-local bindings are restored above, but class execution can
                // rebind shared names directly or through an unknown callback.
                self.invalidate_shared_vars();
                self.invalidate_rebound_name(c.name.as_str());
                self.receiver_rebindings.remove(c.name.as_str());
            }
            // A launched program runs as `__main__`, so its module-level
            // entrypoint guard selects the body, as its control flow records.
            // An imported module keeps the guard as an ordinary branch.
            Stmt::If(s)
                if self.capture.is_none()
                    && self.current_function.is_none()
                    && is_main_guard_test(&s.test)
                    && !self.builder.current_execution_is_dependency() =>
            {
                self.walk_body(&s.body);
            }
            // A constant test selects one arm; the other never runs.
            Stmt::If(s) if control::truthy(&s.test).is_some() => {
                if control::truthy(&s.test) == Some(true) {
                    self.walk_body(&s.body);
                } else {
                    self.walk_body(&s.orelse);
                }
            }
            Stmt::If(s) => {
                self.walk_expr(&s.test);
                self.walk_branches(
                    &[
                        (s.body.as_slice(), None, None),
                        (s.orelse.as_slice(), None, None),
                    ],
                    Some(BranchGuard::selection(
                        s.range,
                        effinterp_proto::ConditionKind::Branch,
                        true,
                    )),
                );
            }
            Stmt::For(s) => self.walk_for(&s.target, &s.iter, &s.body, &s.orelse),
            Stmt::AsyncFor(s) => self.walk_for(&s.target, &s.iter, &s.body, &s.orelse),
            Stmt::While(s) => {
                // A single body walk represents every iteration, including back-edges.
                self.invalidate_loop_bindings(&s.body);
                self.walk_expr(&s.test);
                self.walk_branches(
                    &[
                        (s.body.as_slice(), None, None),
                        (s.orelse.as_slice(), None, None),
                    ],
                    Some(BranchGuard::selection(
                        s.range,
                        effinterp_proto::ConditionKind::Loop,
                        false,
                    )),
                );
            }
            Stmt::Match(s) => {
                self.walk_expr(&s.subject);
                for case in &s.cases {
                    for name in rebound_pattern_names(&case.pattern) {
                        self.invalidate_rebound_name(&name);
                    }
                }
                let mut branches: Vec<(&[Stmt], Option<&str>, Option<&Expr>)> = s
                    .cases
                    .iter()
                    .map(|case| (case.body.as_slice(), None, case.guard.as_deref()))
                    .collect();
                let exhaustive = s.cases.iter().any(|case| case.guard.is_none() && matches!(&case.pattern, ast::Pattern::MatchAs(pattern) if pattern.pattern.is_none()));
                if !exhaustive {
                    branches.push((&[], None, None));
                }
                self.walk_branches(
                    &branches,
                    Some(BranchGuard::selection(
                        s.range,
                        effinterp_proto::ConditionKind::Branch,
                        false,
                    )),
                );
            }
            Stmt::With(s) => {
                self.walk_with(&s.items, &s.body);
            }
            Stmt::AsyncWith(s) => {
                self.walk_with(&s.items, &s.body);
            }
            Stmt::Try(s) => {
                let mut branches: Vec<(&[Stmt], Option<&str>, Option<&Expr>)> =
                    vec![(s.body.as_slice(), None, None)];
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    branches.push((
                        h.body.as_slice(),
                        h.name.as_ref().map(|name| name.as_str()),
                        None,
                    ));
                }
                self.walk_branches(&branches, Some(BranchGuard::exception_handlers(s.range)));
                self.walk_body(&s.orelse);
                self.walk_body(&s.finalbody);
            }
            Stmt::TryStar(s) => {
                let mut branches: Vec<(&[Stmt], Option<&str>, Option<&Expr>)> =
                    vec![(s.body.as_slice(), None, None)];
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    branches.push((
                        h.body.as_slice(),
                        h.name.as_ref().map(|name| name.as_str()),
                        None,
                    ));
                }
                self.walk_branches(&branches, Some(BranchGuard::exception_handlers(s.range)));
                self.walk_body(&s.orelse);
                self.walk_body(&s.finalbody);
            }
            Stmt::Delete(s) => {
                for target in &s.targets {
                    self.ipython_invalidate_getter_target(target);
                    self.walk_assignment_target(target);
                    self.env_subscript_write(target, true);
                    self.track_instance_attr_assignments(std::slice::from_ref(target));
                    self.invalidate_rebound_target(target);
                    if let Expr::Name(target) = target
                        && let Some(state) = self.ipython.as_mut()
                    {
                        state.bindings.remove(target.id.as_str());
                    }
                }
            }
            Stmt::Raise(s) => {
                if let Some(exc) = &s.exc {
                    self.walk_expr(exc);
                }
                if let Some(cause) = &s.cause {
                    self.walk_expr(cause);
                }
            }
            Stmt::Return(s) => {
                if let Some(value) = &s.value {
                    self.walk_expr(value);
                }
            }
            _ => {}
        }
    }

    fn walk_expr(&mut self, expr: &Expr) {
        // Keep guarded expression spines iterative as well as ordinary expressions.
        enum Work<'a> {
            Expr(&'a Expr),
            AttributeBase(&'a Expr),
            Push(&'a Expr, effinterp_proto::ConditionKind, u32),
            Pop(usize),
        }
        let initial_depth = self.builder.condition_depth();
        let mut stack = vec![Work::Expr(expr)];
        while let Some(work) = stack.pop() {
            let attribute_base = matches!(work, Work::AttributeBase(_));
            let expr = match work {
                Work::Expr(expr) | Work::AttributeBase(expr) => expr,
                Work::Push(origin, kind, arm) => {
                    let condition = self.builder.source_condition_path(
                        effinterp_proto::Condition::from_source_with_digest(
                            self.source,
                            self.condition_source.digest().to_string(),
                            effinterp_proto::ByteSpan {
                                start: origin.range().start().into(),
                                end: origin.range().end().into(),
                            },
                            kind,
                            arm,
                            2,
                            true,
                            true,
                        ),
                    );
                    self.builder.push_condition(condition);
                    continue;
                }
                Work::Pop(count) => {
                    for _ in 0..count {
                        self.builder.pop_condition();
                    }
                    continue;
                }
            };
            if !self.charge(expr.range()) {
                break;
            }
            if !attribute_base {
                self.record_namespace_escape(expr);
            }
            if let Expr::IfExp(branch) = expr {
                for (arm, body) in [(1, branch.orelse.as_ref()), (0, branch.body.as_ref())] {
                    stack.push(Work::Pop(1));
                    stack.push(Work::Expr(body));
                    stack.push(Work::Push(
                        expr,
                        effinterp_proto::ConditionKind::Branch,
                        arm,
                    ));
                }
                stack.push(Work::Expr(&branch.test));
                continue;
            }
            if let Expr::BoolOp(branch) = expr {
                stack.push(Work::Pop(branch.values.len().saturating_sub(1)));
                for (index, body) in branch.values.iter().enumerate().rev() {
                    stack.push(Work::Expr(body));
                    if index > 0 {
                        stack.push(Work::Push(
                            &branch.values[index - 1],
                            effinterp_proto::ConditionKind::ShortCircuit,
                            u32::from(matches!(branch.op, ast::BoolOp::Or)),
                        ));
                    }
                }
                continue;
            }
            if let Expr::Await(awaited) = expr {
                self.record_await_dispatch(awaited);
                self.walk_eager(&awaited.value, true);
                continue;
            }
            if let Expr::NamedExpr(named) = expr {
                self.walk_expr(&named.value);
                let Expr::Name(target) = named.target.as_ref() else {
                    continue;
                };
                let name = target.id.as_str();
                self.imports.shadow(name);
                let instance = match named.value.as_ref() {
                    Expr::Name(source) => self.instance_vars.get(source.id.as_str()).cloned(),
                    _ => None,
                };
                self.clear_bound_receiver(name);
                let was_path = self.path_vars.contains(name);
                let branch_mixed_path = self.is_branch_mixed_path_value(&named.value);
                match self.tracked_value(&named.value) {
                    Some(resource) => {
                        self.var_scope.insert(name.to_string(), resource);
                        self.widened_vars.remove(name);
                        if self.is_path_value(&named.value) {
                            self.path_vars.insert(name.to_string());
                        } else {
                            self.path_vars.remove(name);
                        }
                        if self.is_path_value(&named.value) && branch_mixed_path {
                            self.branch_mixed_path_vars.insert(name.to_string());
                        } else {
                            self.branch_mixed_path_vars.remove(name);
                        }
                    }
                    None if was_path || self.may_be_path_value(&named.value) => {
                        self.invalidate_rebound_name(name);
                    }
                    None => {
                        self.var_scope.remove(name);
                        self.path_vars.remove(name);
                        self.branch_mixed_path_vars.remove(name);
                    }
                }
                self.concatenated_vars.remove(name);
                self.unbounded_string_vars.remove(name);
                if let Some(instance) = instance {
                    self.instance_vars.insert(name.to_string(), instance);
                }
                continue;
            }
            let walked_comprehension = match expr {
                Expr::ListComp(comprehension) => {
                    self.walk_comprehension(&comprehension.elt, None, &comprehension.generators)
                }
                Expr::SetComp(comprehension) => {
                    self.walk_comprehension(&comprehension.elt, None, &comprehension.generators)
                }
                Expr::GeneratorExp(comprehension) if self.execute_deferred => {
                    self.walk_comprehension(&comprehension.elt, None, &comprehension.generators)
                }
                Expr::GeneratorExp(comprehension) => {
                    if let Some(generator) = comprehension.generators.first() {
                        self.walk_expr(&generator.iter);
                    }
                    true
                }
                Expr::DictComp(comprehension) => self.walk_comprehension(
                    &comprehension.key,
                    Some(&comprehension.value),
                    &comprehension.generators,
                ),
                _ => false,
            };
            if walked_comprehension {
                continue;
            }
            if let Expr::Call(call) = expr {
                if let Expr::Attribute(attribute) = call.func.as_ref()
                    && attribute.attr.as_str() == "__await__"
                {
                    self.call(call);
                    self.walk_deferred(&attribute.value);
                    for argument in &call.args {
                        self.walk_expr(argument);
                    }
                    for keyword in &call.keywords {
                        self.walk_expr(&keyword.value);
                    }
                    continue;
                }
                if self.deferred_consumer(call) {
                    self.call(call);
                    self.walk_expr(&call.func);
                    self.walk_consumed_arguments(call);
                    continue;
                }
                if self.capture.is_some()
                    && self.imports.resolve_callee(&call.func).as_deref() == Some("print")
                    && self.prints_to_stdout(call)
                {
                    self.capture_print(call);
                    continue;
                }
                self.call(call);
            }
            // `os.environ["X"]` in expression position is an environment read
            // (writes are handled on assignment targets, which are not walked as
            // expressions).
            if let Expr::Subscript(sub) = expr
                && self.imports.resolve_callee(&sub.value).as_deref() == Some("os.environ")
            {
                let resource = str_literal(&sub.slice)
                    .filter(|name| !name.is_empty())
                    .map(|name| ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name },
                    })
                    .unwrap_or_else(|| unresolved("environment"));
                let node = self.span_node(sub.range);
                self.emit("environment.read", resource, &[], node);
            }
            for child in child_exprs(expr).into_iter().rev() {
                // Reading a module attribute does not itself escape its owner.
                stack.push(if matches!(expr, Expr::Attribute(_)) {
                    Work::AttributeBase(child)
                } else {
                    Work::Expr(child)
                });
            }
        }
        while self.builder.condition_depth() > initial_depth {
            self.builder.pop_condition();
        }
    }

    fn record_await_dispatch(&mut self, awaited: &ast::ExprAwait) {
        if self.capture.is_none() {
            return;
        }
        let Expr::Call(inner) = awaited.value.as_ref() else {
            return;
        };
        let Some(iref) = self.ctor_class(inner) else {
            return;
        };
        let Some(ObjectIdentity::Class { name, .. }) =
            iref.as_object().map(|object| &object.identity)
        else {
            return;
        };
        let edge = CallEdge {
            callee: format!("{name}.__await__"),
            awaited: true,
            receiver: Some(iref),
            ..Default::default()
        };
        if let Some(cap) = self.capture.as_mut()
            && cap.calls.len() < MAX_CALL_EDGES
        {
            cap.calls.push(edge);
        }
    }

    fn walk_deferred(&mut self, expr: &Expr) {
        let deferred_indices = match expr {
            Expr::Name(name) => self.deferred_vars.get(name.id.as_str()),
            Expr::Starred(starred) => match starred.value.as_ref() {
                Expr::Name(name) => self.deferred_containers.get(name.id.as_str()),
                _ => None,
            },
            _ => None,
        }
        .cloned();
        if let Some(indices) = deferred_indices
            && let Some(capture) = self.capture.as_mut()
        {
            for index in indices {
                if let Some(edge) = capture.calls.get_mut(index) {
                    edge.awaited = true;
                }
            }
        }
        if let Expr::Name(name) = expr
            && self.bound_vars.contains(name.id.as_str())
            && let Some(capture) = self.capture.as_mut()
            && let Some(edge) = capture.calls.iter_mut().rev().find(|edge| {
                edge.result_bindings()
                    .any(|(_, binding)| binding == name.id.as_str())
            })
        {
            edge.awaited = true;
        }
        let prior = std::mem::replace(&mut self.execute_deferred, true);
        let root = match expr {
            Expr::Call(call) => Some(call.range),
            _ => None,
        };
        let prior_call = std::mem::replace(&mut self.deferred_call, root);
        self.walk_expr(expr);
        self.deferred_call = prior_call;
        self.execute_deferred = prior;
    }

    /// Walk the values a `deferred_consumer` call consumes.
    fn walk_consumed_arguments(&mut self, call: &ast::ExprCall) {
        let eager = self.eager_consumer(call);
        let synchronous = self.synchronous_consumer(call);
        for value in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
        {
            if eager {
                self.walk_eager(value, synchronous);
            } else {
                self.walk_deferred(value);
            }
        }
    }

    /// Walk a deferred value that is awaited or scheduled to run;
    /// `synchronous` when it runs to completion right there.
    fn walk_eager(&mut self, expr: &Expr, synchronous: bool) {
        let root = match expr {
            Expr::Call(call) => Some(call.range),
            _ => None,
        };
        let prior = std::mem::replace(&mut self.eager_call, root);
        let prior_synchronous =
            std::mem::replace(&mut self.synchronous_call, root.filter(|_| synchronous));
        self.walk_deferred(expr);
        self.eager_call = prior;
        self.synchronous_call = prior_synchronous;
    }

    /// Whether a consumed call runs to completion where it is made.
    pub(super) fn synchronously_executes_call(&self, range: TextRange) -> bool {
        self.eagerly_executes_call(range) && self.synchronous_call == Some(range)
    }

    /// Eager consumers that run their coroutine to completion before
    /// returning, rather than scheduling it.
    fn synchronous_consumer(&self, call: &ast::ExprCall) -> bool {
        self.imports.resolve_callee(&call.func).as_deref() == Some("asyncio.run")
            || matches!(call.func.as_ref(), Expr::Attribute(attribute)
                if attribute.attr.as_str() == "run_until_complete")
                && self.deferred_receiver_consumer(call)
    }

    /// Whether a consumed call is awaited or scheduled to run.
    pub(super) fn eagerly_executes_call(&self, range: TextRange) -> bool {
        self.executes_deferred_call(range) && self.eager_call == Some(range)
    }

    /// Consumers that run or schedule the coroutines they receive; the lazy
    /// ones (`wait_for`, `wait`, ...) only wrap them in another coroutine.
    fn eager_consumer(&self, call: &ast::ExprCall) -> bool {
        matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some(
                "asyncio.run" | "asyncio.create_task" | "asyncio.ensure_future" | "asyncio.gather"
            )
        ) || self.deferred_receiver_consumer(call)
    }

    fn executes_deferred_call(&self, range: TextRange) -> bool {
        self.execute_deferred && self.deferred_call == Some(range)
    }

    fn deferred_consumer(&self, call: &ast::ExprCall) -> bool {
        let canonical = self.imports.resolve_callee(&call.func);
        matches!(
            canonical.as_deref(),
            Some(
                "asyncio.run"
                    | "asyncio.gather"
                    | "asyncio.wait"
                    | "asyncio.wait_for"
                    | "asyncio.as_completed"
                    | "asyncio.create_task"
                    | "asyncio.ensure_future"
                    | "asyncio.run_coroutine_threadsafe"
            )
        ) || matches!(
            canonical.as_deref(),
            Some("next" | "list" | "tuple" | "set" | "sorted")
        ) || self.deferred_receiver_consumer(call)
    }

    fn deferred_receiver_consumer(&self, call: &ast::ExprCall) -> bool {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return false;
        };
        let receiver = self.instance_of_expr(&attribute.value);
        let Some(ObjectIdentity::Class { name, .. }) = receiver
            .as_ref()
            .and_then(SemanticValue::as_object)
            .map(|object| &object.identity)
        else {
            return false;
        };
        let canonical = self
            .imports
            .resolve_written(name)
            .unwrap_or_else(|| name.clone());
        matches!(
            (canonical.as_str(), attribute.attr.as_str()),
            (
                "asyncio.new_event_loop" | "asyncio.get_event_loop",
                "run_until_complete"
            ) | (
                "asyncio.new_event_loop" | "asyncio.get_event_loop" | "asyncio.get_running_loop",
                "create_task"
            ) | ("asyncio.TaskGroup", "create_task")
        )
    }

    fn walk_comprehension(
        &mut self,
        element: &Expr,
        value: Option<&Expr>,
        generators: &[ast::Comprehension],
    ) -> bool {
        let [generator] = generators else {
            return self.walk_untracked_comprehension(element, value, generators);
        };
        let Expr::Name(target) = &generator.target else {
            return self.walk_untracked_comprehension(element, value, generators);
        };
        let Some(values) = self.static_resources(&generator.iter) else {
            return self.walk_untracked_comprehension(element, value, generators);
        };
        self.walk_expr(&generator.iter);
        let name = target.id.to_string();
        let prior = self.var_scope.get(&name).cloned();
        let prior_path = self.path_vars.contains(&name);
        let prior_branch_mixed_path = self.branch_mixed_path_vars.contains(&name);
        let prior_concatenated = self.concatenated_vars.contains(&name);
        let prior_unbounded_string = self.unbounded_string_vars.contains(&name);
        let prior_widened = self.widened_vars.contains(&name);
        let prior_instance = self.instance_vars.get(&name).cloned();
        let prior_bound = self.bound_vars.contains(&name);
        let prior_receiver_rebinding = self.receiver_rebindings.contains(&name);
        let prior_modeled = self.modeled_values.remove(&name);
        let mut prior_imports = self.imports.clone();
        self.imports.shadow(&name);
        for item in values {
            self.modeled_values.remove(&name);
            self.clear_bound_receiver(&name);
            self.widened_vars.remove(&name);
            self.concatenated_vars.remove(&name);
            self.unbounded_string_vars.remove(&name);
            self.var_scope.insert(name.clone(), item.resource);
            if item.is_path {
                self.path_vars.insert(name.clone());
            } else {
                self.path_vars.remove(&name);
            }
            self.branch_mixed_path_vars.remove(&name);
            for condition in &generator.ifs {
                self.walk_expr(condition);
            }
            self.walk_expr(element);
            if let Some(value) = value {
                self.walk_expr(value);
            }
        }
        prior_imports.namespace_mutated |= self.imports.namespace_mutated;
        self.imports = prior_imports;
        self.modeled_values.remove(&name);
        if let Some(value) = prior_modeled {
            self.modeled_values.insert(name.clone(), value);
        }
        match prior {
            Some(value) => {
                self.var_scope.insert(name.clone(), value);
            }
            None => {
                self.var_scope.remove(&name);
            }
        }
        if prior_path {
            self.path_vars.insert(name.clone());
        } else {
            self.path_vars.remove(&name);
        }
        if prior_branch_mixed_path {
            self.branch_mixed_path_vars.insert(name.clone());
        } else {
            self.branch_mixed_path_vars.remove(&name);
        }
        if prior_widened {
            self.widened_vars.insert(name.clone());
        } else {
            self.widened_vars.remove(&name);
        }
        if prior_concatenated {
            self.concatenated_vars.insert(name.clone());
        } else {
            self.concatenated_vars.remove(&name);
        }
        if prior_unbounded_string {
            self.unbounded_string_vars.insert(name.clone());
        } else {
            self.unbounded_string_vars.remove(&name);
        }
        match prior_instance {
            Some(instance) => {
                self.instance_vars.insert(name.clone(), instance);
            }
            None => {
                self.instance_vars.remove(&name);
            }
        }
        if prior_bound {
            self.bound_vars.insert(name.clone());
        } else {
            self.bound_vars.remove(&name);
        }
        if prior_receiver_rebinding {
            self.receiver_rebindings.insert(name);
        } else {
            self.receiver_rebindings.remove(&name);
        }
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        true
    }

    fn walk_untracked_comprehension(
        &mut self,
        element: &Expr,
        value: Option<&Expr>,
        generators: &[ast::Comprehension],
    ) -> bool {
        let mut prior_imports = self.imports.clone();
        let names: BTreeSet<_> = generators
            .iter()
            .flat_map(|generator| rebound_target_names(&generator.target))
            .collect();
        let prior: Vec<_> = names
            .into_iter()
            .map(|name| {
                (
                    name.clone(),
                    self.var_scope.get(&name).cloned(),
                    self.modeled_values.get(&name).cloned(),
                    self.path_vars.contains(&name),
                    self.branch_mixed_path_vars.contains(&name),
                    self.widened_vars.contains(&name),
                    self.concatenated_vars.contains(&name),
                    self.unbounded_string_vars.contains(&name),
                    self.instance_vars.get(&name).cloned(),
                    self.bound_vars.contains(&name),
                    self.receiver_rebindings.contains(&name),
                )
            })
            .collect();
        for generator in generators {
            self.walk_expr(&generator.iter);
            self.walk_assignment_target(&generator.target);
            self.invalidate_rebound_target(&generator.target);
            for condition in &generator.ifs {
                self.walk_expr(condition);
            }
        }
        self.walk_expr(element);
        if let Some(value) = value {
            self.walk_expr(value);
        }
        prior_imports.namespace_mutated |= self.imports.namespace_mutated;
        self.imports = prior_imports;
        for (
            name,
            resource,
            modeled,
            path,
            branch_mixed_path,
            widened,
            concatenated,
            unbounded_string,
            instance,
            bound,
            receiver_rebinding,
        ) in prior
        {
            self.modeled_values.remove(&name);
            if let Some(value) = modeled {
                self.modeled_values.insert(name.clone(), value);
            }
            match resource {
                Some(resource) => {
                    self.var_scope.insert(name.clone(), resource);
                }
                None => {
                    self.var_scope.remove(&name);
                }
            }
            if path {
                self.path_vars.insert(name.clone());
            } else {
                self.path_vars.remove(&name);
            }
            if branch_mixed_path {
                self.branch_mixed_path_vars.insert(name.clone());
            } else {
                self.branch_mixed_path_vars.remove(&name);
            }
            if widened {
                self.widened_vars.insert(name.clone());
            } else {
                self.widened_vars.remove(&name);
            }
            if concatenated {
                self.concatenated_vars.insert(name.clone());
            } else {
                self.concatenated_vars.remove(&name);
            }
            if unbounded_string {
                self.unbounded_string_vars.insert(name.clone());
            } else {
                self.unbounded_string_vars.remove(&name);
            }
            match instance {
                Some(instance) => {
                    self.instance_vars.insert(name.clone(), instance);
                }
                None => {
                    self.instance_vars.remove(&name);
                }
            }
            if bound {
                self.bound_vars.insert(name.clone());
            } else {
                self.bound_vars.remove(&name);
            }
            if receiver_rebinding {
                self.receiver_rebindings.insert(name);
            } else {
                self.receiver_rebindings.remove(&name);
            }
        }
        if self.imports.namespace_mutated {
            self.invalidate_namespace_values();
        }
        true
    }

    // --- Intra-function dataflow (def-use) ---
    //
    // An expression that produces an effect is a flow stage; the value it
    // returns is its `Value` port. Tracking `var = <producer>` remembers the
    // stage, and a later use of `var` as an argument to another producing call
    // emits a `data_flow` edge from the producer's `Value` to the consumer's
    // `Arg(n)`.
    // Conservative and structural: local variables within this walk only, no
    // aliasing, container-element, or cross-function return propagation.

    /// Handle an assignment's value in dataflow-tracking mode: walk it for
    /// effects, then bind (or drop) the target name's producer stage.
    fn flow_assign(&mut self, targets: &[Expr], value: &Expr) {
        if self.capture.is_some() {
            let effects = self.capture_value(value);
            for target in targets {
                if let Expr::Name(name) = target {
                    let carried = if targets.len() == 1 {
                        effects.clone()
                    } else {
                        Vec::new()
                    };
                    self.capture_assign(name.id.as_str(), carried);
                }
            }
            return;
        }
        let stage = self.flow_expr(value);
        if let [Expr::Name(t)] = targets {
            match stage {
                Some(s) => {
                    self.flow_vars.insert(t.id.as_str().to_string(), s);
                }
                None => {
                    // Reassignment to a non-producer drops the binding.
                    self.flow_vars.remove(t.id.as_str());
                }
            }
        } else {
            for target in targets {
                if let Expr::Name(n) = target {
                    self.flow_vars.remove(n.id.as_str());
                }
            }
        }
    }

    /// Walk an expression for effects while tracking dataflow, returning the
    /// flow stage whose produced value this expression evaluates to, if any.
    /// In capture (summary) mode dataflow is inactive — flow lives on the real
    /// plan only — so it falls back to plain effect emission.
    fn flow_expr(&mut self, expr: &Expr) -> Option<usize> {
        if self.capture.is_some() {
            self.walk_expr(expr);
            return None;
        }
        match expr {
            // A bare name evaluates to its tracked producer's value.
            Expr::Name(n) => {
                self.record_namespace_escape(expr);
                self.flow_vars.get(n.id.as_str()).copied()
            }
            Expr::Call(call) => self.flow_call(call),
            // A `.text`/`.content` attribute (a `requests`/`httpx` response
            // body) carries its receiver's value.
            Expr::Attribute(attr) if matches!(attr.attr.as_str(), "text" | "content") => {
                self.flow_expr(&attr.value)
            }
            Expr::Subscript(sub)
                if self.imports.resolve_callee(&sub.value).as_deref() == Some("os.environ") =>
            {
                let before = self.builder.effects_len();
                self.walk_expr(expr);
                let after = self.builder.effects_len();
                self.new_stage(sub.range, before, after)
            }
            Expr::Dict(_) | Expr::List(_) | Expr::Tuple(_) | Expr::Set(_) | Expr::Starred(_) => {
                let mut producers = Vec::new();
                self.collect_flow_producers(expr, &mut producers);
                if producers.len() == 1 {
                    Some(producers[0])
                } else {
                    None
                }
            }
            // A shape we do not thread dataflow through; emit effects normally.
            _ => {
                self.walk_expr(expr);
                None
            }
        }
    }

    /// Walk a call, creating a stage for the effects it produces and wiring
    /// def-use edges from its tracked arguments.
    fn flow_call(&mut self, call: &ast::ExprCall) -> Option<usize> {
        if !self.charge(call.range) {
            return None;
        }
        if matches!(
            self.modeled_value(&Expr::Call(call.clone())),
            Some(model::ModeledValue::Request { .. })
        ) {
            self.call(call);
            let mut producers = Vec::new();
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|kw| &kw.value))
            {
                self.collect_flow_producers(argument, &mut producers);
            }
            if producers.len() <= 1 {
                return producers.first().copied();
            }
            let node = self.span_node(call.range);
            let stage = self.stage_writer.join_values(node, &producers);
            return Some(stage);
        }
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && attribute.attr.as_str() == "__await__"
        {
            self.call(call);
            self.walk_deferred(&attribute.value);
            for argument in &call.args {
                self.walk_expr(argument);
            }
            for keyword in &call.keywords {
                self.walk_expr(&keyword.value);
            }
            return None;
        }
        if self.deferred_consumer(call) {
            self.call(call);
            self.walk_consumed_arguments(call);
            return None;
        }
        // A code object compiled from runtime source carries that source to
        // the `exec`/`eval` that runs it. Only the source is code; the filename
        // and options are not.
        let callee = self.imports.resolve_callee(&call.func);
        if callee.as_deref() == Some("compile") {
            self.call(call);
            let source = python_call_argument(call, 0, "source");
            let mut producer = None;
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                let stage = self.flow_expr(argument);
                if source.is_some_and(|source| std::ptr::eq(source, argument)) {
                    producer = stage;
                }
            }
            return producer;
        }
        // `exec`/`eval` run only their source argument (positional-only);
        // values passed in globals or locals are data the code may read, not
        // code, so they are walked without reaching the execution.
        if matches!(callee.as_deref(), Some("exec" | "eval")) {
            let before = self.builder.effects_len();
            self.call(call);
            let after = self.builder.effects_len();
            self.walk_expr(&call.func);
            let stage = self.new_stage(call.range, before, after);
            let source = call.args.first();
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                let mut producers = Vec::new();
                self.collect_flow_producers(argument, &mut producers);
                if let Some(stage) = stage
                    && source.is_some_and(|source| std::ptr::eq(source, argument))
                {
                    for producer in producers {
                        self.stage_writer.add_edge(producer, stage, 0);
                    }
                }
            }
            return stage;
        }
        // A method/attribute call whose receiver is itself a call is either a
        // modeled leaf (`pathlib.Path(p).read_text()`,
        // `requests.Session().get(u)` — `call()` emits the effect) or a
        // pass-through wrapper (`open(p).read()`) whose producer is the
        // receiver call. A local class constructor must execute before its
        // method even when both calls produce effects.
        if let Expr::Attribute(attr) = call.func.as_ref()
            && matches!(attr.value.as_ref(), Expr::Call(_))
        {
            let local_constructor_receiver = self.local_callee(&call.func).is_some();
            if local_constructor_receiver {
                self.flow_expr(&attr.value);
            }
            let before = self.builder.effects_len();
            self.call(call);
            let after = self.builder.effects_len();
            if after > before {
                let stage = self.new_stage(call.range, before, after);
                self.wire_args(call, stage);
                return stage;
            }
            // Wrapper: the value flows from the receiver call.
            let producer = if local_constructor_receiver {
                None
            } else {
                self.flow_expr(attr.value.as_ref())
            };
            for arg in &call.args {
                self.flow_expr(arg);
            }
            for kw in &call.keywords {
                self.flow_expr(&kw.value);
            }
            return producer;
        }
        // A call into a local user function composes that function's effects at
        // this site, but the value it returns is not tracked to any single
        // effect (the function may read a file yet return something unrelated),
        // so it is not a def-use producer and its arguments are not wired.
        let is_local_fn = matches!(call.func.as_ref(), Expr::Name(n)
            if self.imports.resolve_callee(&call.func).is_none()
                && self.defs.iter().any(|d| d.name == n.id.as_str()));
        // An ordinary call: it may itself produce effects (a stage) and may
        // consume tracked variables through its arguments.
        let before = self.builder.effects_len();
        self.call(call);
        let after = self.builder.effects_len();
        // Walk the callee's own subexpressions for effect parity (never a
        // producer here — the receiver-is-call shape is handled above).
        self.walk_expr(&call.func);
        if is_local_fn {
            // Still walk arguments for nested effects, but wire nothing.
            self.wire_args(call, None);
            return None;
        }
        let stage = self.new_stage(call.range, before, after);
        if stage.is_none() && callee.as_deref() == Some("print") && self.prints_to_stdout(call) {
            let emitted = print_emitted(call);
            let mut producers = Vec::new();
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|keyword| &keyword.value))
            {
                if emitted.iter().any(|value| std::ptr::eq(*value, argument)) {
                    self.collect_flow_producers(argument, &mut producers);
                } else {
                    self.walk_expr(argument);
                }
            }
            if !producers.is_empty() {
                let node = self.span_node(call.range);
                let execution = self.builder.current_execution();
                let condition = self.builder.condition_since(self.capture_condition_depth);
                self.stage_writer
                    .print_to_stdout(node, execution, &producers, condition);
            }
            return None;
        }
        self.wire_args(call, stage);
        stage
    }

    /// `print` writes its arguments to this program's own stdout: no `file`,
    /// `file=None`, or `file=sys.stdout`.
    fn prints_to_stdout(&self, call: &ast::ExprCall) -> bool {
        self.imports.ordinary_stdout()
            && call.keywords.iter().all(|keyword| {
                keyword.arg.as_deref() != Some("file")
                    || matches!(&keyword.value, Expr::Constant(constant)
                        if matches!(constant.value, ast::Constant::None))
                    || self.imports.resolve_callee(&keyword.value).as_deref() == Some("sys.stdout")
            })
    }

    /// Walk a `print` inside a function being summarized: record the body's
    /// effects whose bytes its emitted values carry, with its condition, so a
    /// caller connects them to its own stdout.
    fn capture_print(&mut self, call: &ast::ExprCall) {
        self.call(call);
        self.walk_expr(&call.func);
        let emitted = print_emitted(call);
        let mut printed = Vec::new();
        for argument in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
        {
            if emitted.iter().any(|value| std::ptr::eq(*value, argument)) {
                printed.extend(self.capture_value(argument));
            } else {
                self.walk_expr(argument);
            }
        }
        printed.sort_unstable();
        printed.dedup();
        let condition = self.builder.condition_since(self.capture_condition_depth);
        if let Some(capture) = self.capture.as_mut()
            && !printed.is_empty()
        {
            capture.stdout.push((printed, condition));
        }
    }

    /// Walk an expression inside a function being summarized, returning the
    /// body's effects whose bytes its value carries: those of the calls on its
    /// value spine (see [`value_spine`]) and of the locals it names.
    fn capture_value(&mut self, expr: &Expr) -> Vec<u32> {
        let before = self
            .capture
            .as_ref()
            .map_or(0, |capture| capture.effects.len());
        self.walk_expr(expr);
        let mut spans = Vec::new();
        let mut names = Vec::new();
        value_spine(expr, &mut spans, &mut names);
        let Some(capture) = self.capture.as_ref() else {
            return Vec::new();
        };
        let mut effects = (before..capture.effects.len())
            .filter(|&slot| {
                capture.effects[slot].provenance.iter().any(|reference| {
                    capture
                        .source_spans
                        .get(reference.0 as usize)
                        .is_some_and(|span| spans.contains(span))
                })
            })
            .map(|slot| slot as u32)
            .collect::<Vec<_>>();
        for name in names {
            effects.extend(capture.print_vars.get(name).into_iter().flatten());
        }
        effects
    }

    /// Bind a summarized body's local to the effects its assigned value
    /// carries. A conditional assignment adds to what the local may hold;
    /// only an unconditional one replaces it.
    fn capture_assign(&mut self, name: &str, effects: Vec<u32>) {
        let conditional = self
            .builder
            .condition_since(self.capture_condition_depth)
            .is_some();
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        let mut held = if conditional {
            capture.print_vars.remove(name).unwrap_or_default()
        } else {
            Vec::new()
        };
        held.extend(effects);
        held.sort_unstable();
        held.dedup();
        if held.is_empty() {
            capture.print_vars.remove(name);
        } else {
            capture.print_vars.insert(name.to_string(), held);
        }
    }

    /// Buffer a flow stage for the effects in `[before, after)`, binding each
    /// effect to the stage's `Value` port. None when the expression produced none.
    fn new_stage(&mut self, range: TextRange, before: usize, after: usize) -> Option<usize> {
        if after <= before {
            return None;
        }
        let node = self.span_node(range);
        let id = self.stage_writer.new_stage(node, before, after)?;
        Some(id)
    }

    /// Walk a call's arguments for effects and dataflow, emitting an edge into
    /// `consumer` for each argument that carries a tracked producer's value.
    /// Positional arguments index first, then keyword arguments, in order.
    fn wire_args(&mut self, call: &ast::ExprCall, consumer: Option<usize>) {
        for (idx, arg) in call
            .args
            .iter()
            .chain(call.keywords.iter().map(|keyword| &keyword.value))
            .enumerate()
        {
            let mut producers = Vec::new();
            self.collect_flow_producers(arg, &mut producers);
            if let Some(consumer) = consumer {
                for producer in producers {
                    self.stage_writer.add_edge(producer, consumer, idx as u32);
                }
            }
        }
    }

    /// Walk container values and collect every flow producer nested directly in them.
    fn collect_flow_producers(&mut self, expr: &Expr, producers: &mut Vec<usize>) {
        match expr {
            Expr::Dict(dict) => {
                for key in dict.keys.iter().flatten() {
                    self.walk_expr(key);
                }
                for value in &dict.values {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::List(list) => {
                for value in &list.elts {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::Tuple(tuple) => {
                for value in &tuple.elts {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::Set(set) => {
                for value in &set.elts {
                    self.collect_flow_producers(value, producers);
                }
            }
            Expr::Starred(starred) => self.collect_flow_producers(&starred.value, producers),
            _ => {
                if let Some(producer) = self.flow_expr(expr)
                    && !producers.contains(&producer)
                {
                    producers.push(producer);
                }
            }
        }
    }

    fn apply_decorator(&mut self, decorator: &Expr) {
        self.walk_expr(decorator);
        let applications = std::mem::take(&mut self.control_applications);
        let facts = self.apply_decorator_inner(decorator);
        self.control_applications = applications;
        self.builder.control_site(
            self.source,
            self.capture.is_some(),
            control::decorator_span(decorator),
            facts,
        );
    }

    fn apply_decorator_inner(&mut self, decorator: &Expr) -> SiteFacts {
        let written = decorator_names(std::slice::from_ref(decorator)).remove(0);
        if self.decorator_is_transparent(&written) {
            return SiteFacts::known(Vec::new());
        }
        if let Some(name) = self.local_callee(decorator) {
            self.apply_local_arguments(&name, &[], decorator.range());
            match std::mem::take(&mut self.control_applications).as_slice() {
                [application] => application.clone(),
                _ => SiteFacts::unknown(),
            }
        } else {
            let name = self.imports.resolve_callee(decorator).unwrap_or(written);
            self.emit_unresolved_call(
                &name,
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                decorator.range(),
                python_callee_reference(&name).or_else(|| {
                    Some(CalleeReference {
                        module: "python".into(),
                        symbol: name.clone(),
                    })
                }),
            );
            SiteFacts::unknown()
        }
    }

    /// Evaluate a call and register what it establishes at its site: the
    /// occurrences a modeled API produced, a local callee's guarantees, or
    /// unknown code that may complete the invocation.
    fn call(&mut self, call: &ast::ExprCall) {
        let capture = self.capture.is_some();
        let since = self.builder.control_registered();
        let effects = self.control_effects_len();
        let calls = self.capture.as_ref().map_or(0, |cap| cap.calls.len());
        let applications = std::mem::take(&mut self.control_applications);
        let control = self.call_inner(call);
        let applied = std::mem::replace(&mut self.control_applications, applications);
        let call_return =
            matches!(&control, CallControl::Local | CallControl::Opaque) && applied.len() <= 1;
        let direct_sink = matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some("os.remove" | "os.unlink" | "os.getenv" | "os.putenv" | "os.unsetenv")
        );
        let mut facts = match control {
            CallControl::Modeled if applied.is_empty() && direct_sink => SiteFacts::known(
                self.builder
                    .control_own_effects(effects..self.control_effects_len()),
            ),
            CallControl::Modeled if applied.is_empty() => SiteFacts::known(Vec::new()),
            CallControl::Local if applied.len() == 1 => applied.into_iter().next().unwrap(),
            // Callbacks run under the API's own control, and several
            // applications at one call are alternatives or wrappers.
            CallControl::Modeled | CallControl::Local | CallControl::Opaque => SiteFacts::unknown(),
        };
        if matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some("sys.exit" | "exit" | "quit" | "os._exit" | "os.abort")
        ) {
            facts.returns = false;
            facts.exit = None;
            facts.throws = !matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("os._exit" | "os.abort")
            );
            if facts.throws {
                facts.thrown =
                    crate::control_flow::Exn::named(crate::control_flow::Symbol::py("SystemExit"));
            }
        }
        // One recorded edge is this call; several are dispatch alternatives.
        facts.call_return = call_return && facts.returns;
        if let Some(cap) = &self.capture
            && cap.calls.len() == calls + 1
        {
            facts.facts.push(ControlFact::Call(calls as u32));
            facts.throw_facts.push(ControlFact::Call(calls as u32));
            // The callee name resolved to an edge; lookup does not throw.
            facts.reference_known = true;
        }
        self.builder.control_site_since(
            self.source,
            capture,
            control::span(call.range),
            since,
            facts,
        );
    }

    fn control_effects_len(&self) -> usize {
        match &self.capture {
            Some(cap) => cap.effects.len(),
            None => self.builder.effects_len(),
        }
    }

    fn call_inner(&mut self, call: &ast::ExprCall) -> CallControl {
        self.prepare_call_summaries(&call.func);
        for argument in &call.args {
            self.prepare_call_summaries(argument);
        }
        for keyword in &call.keywords {
            self.prepare_call_summaries(&keyword.value);
        }
        let span = call.range;
        if !self.safe_python_call(call) && !self.safe_python_method(call) {
            self.modeled_values
                .retain(|_, value| !matches!(value, model::ModeledValue::BuiltinData));
        }
        if self.ipython_call(call) {
            return CallControl::Modeled;
        }
        if self.prime_bash
            && !self.imports.namespace_mutated
            && matches!(call.func.as_ref(), Expr::Name(name) if is_prime_bash_name(name.id.as_str()))
            && matches!(call.args.as_slice(), [argument] if !matches!(argument, Expr::Starred(_)))
            && call.keywords.is_empty()
        {
            // `bash(command)` runs `command` through the kernel's shell.
            self.os_system(call, span);
            return CallControl::Modeled;
        }
        if let Some(class) = callee_written(&call.func)
            && self.class_names.contains(&class)
            && self
                .defs
                .iter()
                .any(|def| def.name == format!("{class}.__del__"))
        {
            self.apply_local_arguments(&format!("{class}.__del__"), &[], span);
        }
        if let Expr::Attribute(attribute) = call.func.as_ref()
            && matches!(
                attribute.attr.as_str(),
                "append"
                    | "extend"
                    | "insert"
                    | "pop"
                    | "remove"
                    | "clear"
                    | "update"
                    | "setdefault"
            )
            && let Expr::Name(name) = attribute.value.as_ref()
        {
            self.invalidate_collection(name.id.as_str());
        }
        // In capture mode, record a user-function call edge (local or imported)
        // for cross-file linking, in addition to the effect handling below.
        if self.capture.is_some() {
            // Reserve the enclosing call before deriving receiver/argument
            // instances. Nested constructors then follow it lexically and
            // reuse the same Site when their own edge is visited later.
            let origin = self.site_origin(call.range, 0);
            if let Some(edges) = self.finite_class_edges(call) {
                let binds = if let Some((range, _)) = &self.pending_binds
                    && *range == call.range
                    && let Some((_, targets)) = self.pending_binds.take()
                {
                    for (_, name) in &targets {
                        self.bound_vars.insert(name.clone());
                    }
                    targets
                } else {
                    Vec::new()
                };
                for mut edge in edges {
                    edge.awaited = self.executes_deferred_call(call.range);
                    edge.results =
                        call_results(binds.clone(), Some(origin.clone()), self.call_type(call));
                    let pushed = if let Some(cap) = self.capture.as_mut()
                        && cap.calls.len() < MAX_CALL_EDGES
                    {
                        let index = cap.calls.len();
                        cap.calls.push(edge);
                        Some(index)
                    } else {
                        None
                    };
                    if let Some(index) = pushed
                        && let Some((name, ranges)) = &self.pending_deferred_container
                        && ranges.contains(&call.range)
                    {
                        self.deferred_containers
                            .entry(name.clone())
                            .or_default()
                            .push(index);
                    }
                }
            } else if let Some(mut edge) = self.call_edge(call) {
                edge.awaited = self.executes_deferred_call(call.range);
                let mut binds = Vec::new();
                // The enclosing assignment binds this call's result: record the
                // bound locals on the edge (typed at composition time via the
                // callee's `returns_instances`).
                if let Some((range, _)) = &self.pending_binds
                    && *range == call.range
                    && let Some((_, targets)) = self.pending_binds.take()
                {
                    for (_, name) in &targets {
                        self.bound_vars.insert(name.clone());
                    }
                    binds = targets;
                }
                edge.results = call_results(binds, Some(origin), self.call_type(call));
                let pushed = if let Some(cap) = self.capture.as_mut()
                    && cap.calls.len() < MAX_CALL_EDGES
                {
                    let index = cap.calls.len();
                    cap.calls.push(edge);
                    Some(index)
                } else {
                    None
                };
                if let Some(index) = pushed
                    && let Some((name, ranges)) = &self.pending_deferred_container
                    && ranges.contains(&call.range)
                {
                    self.deferred_containers
                        .entry(name.clone())
                        .or_default()
                        .push(index);
                }
            }
        }
        if let Some(name) = self.imports.resolve_local_callee(&call.func) {
            if self.apply_imported_call(&name, call, span) {
                return CallControl::Modeled;
            }
            self.emit_unresolved_call(
                &name,
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                span,
                python_callee_reference(&name),
            );
            return CallControl::Opaque;
        }
        if self.imports.resolve_callee(&call.func).as_deref() == Some("getattr")
            && self.local_callee(&Expr::Call(call.clone())).is_some()
        {
            return CallControl::Opaque;
        }
        if self.importlib_boundary(call) || self.component_lifecycle_call(call) {
            return CallControl::Opaque;
        }
        if self.safe_python_method(call) || self.model_call(call, span) {
            return CallControl::Modeled;
        }
        if let Expr::Attribute(attr) = call.func.as_ref()
            && matches!(attr.attr.as_str(), "read" | "readline" | "readlines")
            && self.modeled_value(&attr.value) == Some(model::ModeledValue::FileContext)
        {
            return CallControl::Modeled;
        }
        if let Expr::Attribute(attr) = call.func.as_ref()
            && matches!(
                attr.attr.as_str(),
                "write" | "writelines" | "read" | "readline" | "readlines" | "close" | "flush"
            )
            && self
                .instance_class_name(&attr.value)
                .is_some_and(|class| matches!(class.as_str(), "open" | "io.open"))
        {
            return CallControl::Modeled;
        }

        // Unknown code can mutate a Request through an alias or a global.
        // Keep its endpoint only across calls whose behavior is accounted for.
        if !matches!(
            self.imports.resolve_callee(&call.func).as_deref(),
            Some("urllib.request.Request" | "urllib.request.urlopen")
        ) && !self.safe_python_call(call)
        {
            self.modeled_values
                .retain(|_, value| !matches!(value, model::ModeledValue::Request { .. }));
        }
        let Some(name) = self.imports.resolve_callee(&call.func) else {
            // Follow known same-file receivers; an unknown receiver with a
            // local method candidate needs an explicit dispatch boundary.
            if let Some(id) = self.local_callee(&call.func) {
                let def = self.defs.iter().find(|def| def.name == id);
                let deferred = def.is_some_and(|def| def.is_async || def.is_generator);
                let consumed_generator =
                    self.execute_deferred && def.is_some_and(|def| def.is_generator);
                if self.executes_deferred_call(call.range) || consumed_generator || !deferred {
                    self.apply_local(&id, call, span);
                    return CallControl::Local;
                }
                // Creating a coroutine or generator runs none of its body.
                return CallControl::Modeled;
            } else {
                let name = callee_written(&call.func).unwrap_or_else(|| {
                    self.source[usize::from(call.func.range().start())
                        ..usize::from(call.func.range().end())]
                        .to_string()
                });
                self.emit_unresolved_call(
                    &name,
                    BoundaryReason::DYNAMIC_DISPATCH,
                    BoundaryClass::Unresolved,
                    crate::external::ALL_DOMAINS,
                    span,
                    Some(CalleeReference {
                        module: "python".to_string(),
                        symbol: name.clone(),
                    }),
                );
            }
            return CallControl::Opaque;
        };
        if self.safe_python_call(call) {
            return CallControl::Modeled;
        }
        let arity = (!call.args.iter().any(|arg| matches!(arg, Expr::Starred(_)))
            && call.keywords.iter().all(|kw| kw.arg.is_some()))
        .then_some(call.args.len());
        if name == "django.core.management.execute_from_command_line" {
            self.django_management_call(call, span);
        }
        self.unresolved_call(&name, arity, span, self.python_operands_safe(call))
    }

    /// `execute_from_command_line` runs the management command its argument
    /// vector names after the program name, as `django-admin` does. A vector
    /// Nah cannot recover runs no command it can name, and says so. The call
    /// itself stays unresolved: the command runs project code.
    fn django_management_call(&mut self, call: &ast::ExprCall, span: TextRange) {
        let launch = self.builder.current_execution_argv();
        let launch = launch
            .get(1..)
            .unwrap_or_default()
            .iter()
            .map(|word| match word {
                ResourceExpr::Literal { value } => Some(value.clone()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let words = match argv::argument_vector(&self.imports, self.source, call, launch) {
            argv::ArgumentVector::Known(words) => words,
            argv::ArgumentVector::Symbolic => return,
            argv::ArgumentVector::Unknown => {
                let node = self.span_node(span);
                for domain in crate::external::ALL_DOMAINS {
                    self.out_coverage(Domain::new(*domain), CoverageLevel::Partial);
                }
                self.out_boundary(Boundary {
                    reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: crate::external::ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: vec![node],
                    limit: None,
                    detail: Some(
                        "sys.argv or the argument vector is changed or shared where Nah cannot \
                         recover it; the management command execute_from_command_line runs is \
                         unknown"
                            .to_string(),
                    ),
                });
                return;
            }
        };
        let argv = std::iter::once("django-admin".to_string())
            .chain(words)
            .collect();
        let node = self.span_node(span);
        self.apply_deferred_spawn(
            DeferredSpawn::Command { argv },
            &std::collections::HashMap::new(),
            node,
            span,
        );
    }

    fn importlib_boundary(&mut self, call: &ast::ExprCall) -> bool {
        let canonical = if let Expr::Attribute(attr) = call.func.as_ref()
            && attr.attr.as_str() == "select"
            && self.modeled_value(&attr.value) == Some(model::ModeledValue::EntryPoints)
        {
            "importlib.metadata.entry_points".to_string()
        } else if let Some(canonical) = callee_written(&call.func)
            .and_then(|written| self.imports.resolve_import_written(&written))
        {
            canonical
        } else {
            return false;
        };
        let (label, value) = match canonical.as_str() {
            "importlib.util.spec_from_file_location" => {
                ("plugin path", python_call_argument(call, 1, "location"))
            }
            "importlib.metadata.entry_points" => (
                "entry-point group",
                python_call_argument(call, usize::MAX, "group"),
            ),
            "importlib.import_module"
                if python_call_argument(call, 0, "name")
                    .is_none_or(|value| str_literal(value).is_none()) =>
            {
                ("dynamic module", python_call_argument(call, 0, "name"))
            }
            _ => return false,
        };
        let detail = value
            .map(|value| {
                if label != "plugin path"
                    && let Some(literal) = str_literal(value)
                {
                    return literal.to_string();
                }
                let resource = if label != "plugin path" {
                    substitute_resource_expr(&self.fs_resource(value), &self.var_scope)
                } else {
                    self.resolve_fs(value)
                };
                python_plugin_path_pattern(&resource).unwrap_or_else(|| {
                    self.source
                        [usize::from(value.range().start())..usize::from(value.range().end())]
                        .to_string()
                })
            })
            .unwrap_or_else(|| "unspecified".to_string());
        let node = self.span_node(call.range);
        self.out_boundary(Boundary {
            reason: BoundaryReason::CROSS_MODULE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: (label == "plugin path")
                .then(|| value.map(|value| self.resolve_fs(value)))
                .flatten(),
            callee: python_callee_reference(&canonical),
            domains: crate::external::ALL_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("{canonical}: {label} {detail}")),
        });
        true
    }

    fn component_lifecycle_call(&mut self, call: &ast::ExprCall) -> bool {
        let Some(canonical) = self.imports.resolve_callee(&call.func) else {
            return false;
        };
        let Some((model, sig)) = crate::LIFECYCLE_CATALOG.iter().find_map(|model| {
            model
                .component_signature(&canonical)
                .map(|sig| (model, sig))
        }) else {
            return false;
        };
        let index = sig.component.unwrap();
        let component = python_call_argument(call, index, sig.params[0]);
        let name = component.and_then(callee_written);
        let class = name.as_ref().filter(|name| {
            self.class_names.contains(*name) && !self.receiver_rebindings.contains(*name)
        });
        let alternatives = component.is_none() || class.is_some();
        let roots: Vec<_> = if let Some(class) = class {
            self.defs
                .iter()
                .filter(|def| {
                    def.parent.is_none()
                        && def.owner.as_ref() == Some(class)
                        && def
                            .name
                            .strip_prefix(&format!("{class}."))
                            .is_some_and(|method| !method.starts_with('_'))
                })
                .map(|def| def.name.clone())
                .collect()
        } else if let Some(component) = component {
            (self.imports.resolve_callee(component).is_none()
                && self.imports.resolve_local_callee(component).is_none()
                && name
                    .as_ref()
                    .is_none_or(|name| !self.receiver_rebindings.contains(name)))
            .then(|| self.local_callee(component))
            .flatten()
            .into_iter()
            .collect()
        } else {
            self.defs
                .iter()
                .filter(|def| {
                    def.parent.is_none()
                        && def.owner.is_none()
                        && !self.receiver_rebindings.contains(&def.name)
                })
                .map(|def| def.name.clone())
                .collect()
        };
        if roots.is_empty()
            && self.fact_scope.is_none()
            && let Some(component) = component
            && let Some(canonical) = self
                .imports
                .resolve_local_callee(component)
                .or_else(|| self.imports.resolve_callee(component))
        {
            let invocation = ast::ExprCall {
                range: call.range,
                func: Box::new(component.clone()),
                args: Vec::new(),
                keywords: Vec::new(),
            };
            if self.apply_imported_call(&canonical, &invocation, call.range) {
                return true;
            }
        }
        if component.is_none() || roots.is_empty() {
            self.emit_unresolved_call(
                &if component.is_none() {
                    format!(
                        "{} component dispatch: {} module-level callable candidates",
                        model.id,
                        roots.len()
                    )
                } else {
                    format!(
                        "{} component dispatch: unresolved component{}",
                        model.id,
                        name.as_ref()
                            .map(|name| format!(" {name}"))
                            .unwrap_or_default()
                    )
                },
                BoundaryReason::DYNAMIC_DISPATCH,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                call.range,
                None,
            );
        }
        // Repository capture retains the lifecycle call; composition owns activation.
        if self.fact_scope.is_some() {
            return true;
        }
        let count = roots.len() as u32;
        for (arm, root) in roots.iter().enumerate() {
            if alternatives {
                self.builder.push_condition(self.builder.source_condition(
                    self.source,
                    effinterp_proto::ByteSpan {
                        start: call.range.start().into(),
                        end: call.range.end().into(),
                    },
                    effinterp_proto::ConditionKind::Branch,
                    arm as u32,
                    count.max(2),
                    true,
                    true,
                ));
            }
            self.apply_local_arguments(root, &[], call.range);
            if alternatives {
                self.builder.pop_condition();
            }
        }
        true
    }

    /// Decide whether a call is an outgoing user-function edge (a cross-file
    /// linking candidate), returning it with arguments resolved in the caller's
    /// scope. Modeled effect APIs and dynamic builtins contribute effects, not
    /// edges, and return None.
    fn call_edge(&self, call: &ast::ExprCall) -> Option<CallEdge> {
        if self
            .registration_spans
            .contains(&(call.range.start().to_u32(), call.range.end().to_u32()))
        {
            return None;
        }
        if self.safe_python_method(call) {
            return None;
        }
        if self.deferred_consumer(call) {
            return None;
        }
        if let Expr::Attribute(attr) = call.func.as_ref()
            && self.is_path_method_receiver(attr.attr.as_str(), &attr.value)
        {
            return None;
        }
        if self.typed_path_call(call).is_some() {
            return None;
        }
        // `Class().method(...)` has no dotted written name (the base is a
        // call). Recover it from the constructor so composition can dispatch
        // `App().run()` through the constructed class.
        let mut ctor_recv = None;
        let callee = match callee_written(&call.func) {
            Some(c) => c,
            None => {
                let Expr::Attribute(attr) = call.func.as_ref() else {
                    return None;
                };
                let Expr::Call(inner) = attr.value.as_ref() else {
                    return None;
                };
                let iref = if matches!(inner.func.as_ref(), Expr::Name(name) if name.id.as_str() == "super")
                {
                    let owner = self.current_class.as_ref()?;
                    let base = self.class_bases.get(owner)?.first()?.clone();
                    SemanticValue::object(ObjectIdentity::Class {
                        name: base,
                        constructor: Vec::new(),
                    })
                } else {
                    self.ctor_class(inner)?
                };
                let name = match iref.as_object().map(|object| &object.identity) {
                    Some(ObjectIdentity::Class { name, .. }) => name.clone(),
                    Some(ObjectIdentity::DynamicClass) => "cls".to_string(),
                    _ => return None,
                };
                ctor_recv = Some(iref);
                format!("{name}.{}", attr.attr.as_str())
            }
        };
        let component_lifecycle =
            self.imports
                .resolve_callee(&call.func)
                .is_some_and(|canonical| {
                    crate::LIFECYCLE_CATALOG
                        .iter()
                        .any(|model| model.component_signature(&canonical).is_some())
                });
        let callback = |arg: &Expr| {
            if component_lifecycle {
                (self.imports.resolve_callee(arg).is_none()
                    && self.imports.resolve_local_callee(arg).is_none()
                    && callee_written(arg)
                        .is_none_or(|name| !self.receiver_rebindings.contains(&name)))
                .then(|| self.local_callee(arg))
                .flatten()
            } else {
                self.local_fn_name(arg)
            }
        };
        let mut extra_arguments = Vec::new();
        for (i, arg) in call.args.iter().enumerate() {
            if let Some(func) = callback(arg) {
                extra_arguments.push(ValueArgument {
                    name: None,
                    index: i,
                    value: SemanticValue::callable(func),
                });
            }
        }
        for kw in &call.keywords {
            let Some(param) = kw.arg.as_ref() else {
                continue;
            };
            if let Some(func) = callback(&kw.value) {
                extra_arguments.push(ValueArgument {
                    name: Some(param.to_string()),
                    index: 0,
                    value: SemanticValue::callable(func),
                });
            }
        }
        let mut recv = ctor_recv;
        let local_import = self.imports.resolve_local_callee(&call.func);
        match self
            .imports
            .resolve_callee(&call.func)
            .or_else(|| local_import.clone())
        {
            // Resolves through a tracked import: a modeled root or dynamic
            // builtin is an effect/boundary, not an edge; any other module is a
            // user function reached across files.
            Some(canon) => {
                let root = canon.split('.').next().unwrap_or(&canon);
                if local_import.is_none()
                    && (PYTHON_MODELED_ROOTS.contains(&root)
                        || resolve::is_builtin(&canon)
                        || is_builtin_effect(&canon))
                {
                    return None;
                }
                recv = self.recv_of(&call.func);
            }
            // Not a tracked import: a bare name bound to a module-level
            // function or to a parameter of the current function (a callback
            // site) is an edge; a `cls(...)` constructor or a method call on
            // an unambiguous receiver is a typed-dispatch edge; a call that
            // cannot be resolved at all still carries an edge when it is
            // handed local functions as arguments (argparse's
            // `p.set_defaults(func=_cmd_x)`), so the composer can treat the
            // registered callbacks as may-invoked; anything else is effectless.
            None if recv.is_none() => match call.func.as_ref() {
                Expr::Name(n) if n.id.as_str() == "cls" => {
                    recv = Some(SemanticValue::object(ObjectIdentity::DynamicClass))
                }
                Expr::Name(n)
                    if self.defs.iter().any(|d| d.name == n.id.as_str())
                        || self.current_params.iter().any(|p| p == n.id.as_str())
                        || self.class_names.contains(n.id.as_str()) => {}
                _ => {
                    recv = self.recv_of(&call.func);
                    if recv.is_none() && extra_arguments.is_empty() {
                        return None;
                    }
                }
            },
            None => {}
        }
        let mut arguments = self.value_args_of(call);
        merge_arguments(&mut arguments, extra_arguments);
        Some(CallEdge {
            condition: self.builder.condition_since(self.capture_condition_depth),
            call_site: Some(
                self.condition_source
                    .call_site(&(u32::from(call.range.start()), u32::from(call.range.end()))),
            ),
            callee,
            arguments,
            awaited: false,
            effects_propagated: false,
            external_inert: self
                .safe_python_call(call)
                .then(|| self.imports.resolve_callee(&call.func))
                .flatten(),
            lifecycle_registration: false,
            dynamic_target: false,
            callee_span: None,
            receiver: recv,
            results: Vec::new(),
            writes: Vec::new(),
        })
    }

    /// Expand `for cls in CLASSES: cls(arg)` only when `CLASSES` is a static
    /// tuple of written class names. Each constructor remains tied to its exact
    /// import; composition discards tuple members that are not real classes.
    fn finite_class_edges(&self, call: &ast::ExprCall) -> Option<Vec<CallEdge>> {
        let Expr::Name(callee) = call.func.as_ref() else {
            return None;
        };
        let classes = self.class_set_vars.get(callee.id.as_str())?;
        let arguments = self.value_args_of(call);
        Some(
            classes
                .iter()
                .map(|name| CallEdge {
                    condition: None,
                    call_site: None,
                    callee: name.clone(),
                    arguments: arguments.clone(),
                    awaited: false,
                    effects_propagated: false,
                    external_inert: self
                        .safe_python_call(call)
                        .then(|| self.imports.resolve_callee(&call.func))
                        .flatten(),
                    lifecycle_registration: false,
                    dynamic_target: false,
                    callee_span: None,
                    receiver: Some(SemanticValue::object(ObjectIdentity::Class {
                        name: name.clone(),
                        constructor: arguments.clone(),
                    })),
                    results: Vec::new(),
                    writes: Vec::new(),
                })
                .collect(),
        )
    }

    /// Track receiver typing for an assignment being walked in capture mode:
    /// `x = ClassName(...)` / `x = cls(...)` types `x` directly; any other
    /// call RHS marks the (possibly tuple-unpacked) targets so the recorded
    /// edge carries `binds`. Reassignment drops stale typing.
    fn track_assign(&mut self, assign: &ast::StmtAssign) {
        self.track_bound_call(&assign.targets, &assign.value);
    }

    /// Same binding as a plain assignment for a single annotated target.
    fn track_named_value(&mut self, target: &Expr, value: &Expr) {
        self.track_bound_call(std::slice::from_ref(target), value);
    }

    fn clear_bound_receiver(&mut self, name: &str) {
        self.modeled_values.remove(name);
        self.receiver_rebindings.insert(name.to_string());
        self.instance_vars.remove(name);
        self.instance_sequences.remove(name);
        self.bound_vars.remove(name);
    }

    fn clear_bound_value(&mut self, name: &str) {
        self.clear_bound_receiver(name);
        self.deferred_containers.remove(name);
        self.deferred_vars.remove(name);
    }

    fn track_instance_attr_assignments(&mut self, targets: &[Expr]) {
        for target in targets {
            for name in rebound_target_names(target) {
                self.instance_attr_rebindings.remove(&name);
                if let Some(attrs) = self.invalidated_instance_attrs(&name) {
                    self.instance_attr_rebindings.insert(name, attrs);
                }
            }
            self.track_instance_attr_assignment(target);
        }
    }

    fn track_instance_attr_rebinding(&mut self, receiver: &str, attr: &str) {
        if let Some(value) = self.modeled_values.remove(receiver) {
            self.modeled_values.retain(|_, other| *other != value);
        }
        let Some(instance) = self.instance_vars.get(receiver) else {
            return;
        };
        let aliases: Vec<_> = self
            .instance_vars
            .iter()
            .filter(|(_, value)| *value == instance)
            .map(|(name, _)| name.clone())
            .collect();
        for receiver in aliases {
            self.instance_attr_rebindings
                .entry(receiver)
                .or_default()
                .insert(attr.to_string());
        }
    }

    fn invalidated_instance_attrs(&self, receiver: &str) -> Option<HashSet<String>> {
        let instance = self.instance_vars.get(receiver)?;
        let attrs: HashSet<_> = self
            .instance_vars
            .iter()
            .filter(|(_, value)| *value == instance)
            .filter_map(|(name, _)| self.instance_attr_rebindings.get(name))
            .flatten()
            .cloned()
            .collect();
        (!attrs.is_empty()).then_some(attrs)
    }

    fn track_instance_attr_assignment(&mut self, target: &Expr) {
        match target {
            Expr::Attribute(attribute) => {
                let Expr::Name(receiver) = attribute.value.as_ref() else {
                    return;
                };
                self.track_instance_attr_rebinding(receiver.id.as_str(), attribute.attr.as_str());
            }
            Expr::List(list) => {
                self.track_instance_attr_assignments(&list.elts);
            }
            Expr::Tuple(tuple) => {
                self.track_instance_attr_assignments(&tuple.elts);
            }
            Expr::Starred(starred) => {
                self.track_instance_attr_assignment(&starred.value);
            }
            _ => {}
        }
    }

    /// Copy constructor identity from a simple name alias, including chained
    /// `u = t = s` and static unpack `src, dst = store, backup`.
    fn instance_source_aliases(
        &self,
        targets: &[Expr],
        value: &Expr,
    ) -> Vec<(String, SemanticValue)> {
        let mut aliases = Vec::new();
        if let Expr::Name(source) = value
            && let Some(instance) = self.instance_vars.get(source.id.as_str())
        {
            for target in targets {
                if let Expr::Name(name) = target {
                    aliases.push((name.id.to_string(), instance.clone()));
                }
            }
        }
        if let Some(target_elts) = unpack_assignment_elements(targets)
            && let Some(value_elts) = sequence_expr_elements(value)
            && target_elts.len() == value_elts.len()
        {
            for (target, value) in target_elts.iter().zip(value_elts) {
                let Expr::Name(name) = target else {
                    continue;
                };
                let Expr::Name(source) = value else {
                    continue;
                };
                if let Some(instance) = self.instance_vars.get(source.id.as_str()) {
                    aliases.push((name.id.to_string(), instance.clone()));
                }
            }
        }
        aliases
    }

    fn track_bound_call(&mut self, targets: &[Expr], value: &Expr) {
        // The resource assignment already established these exact values.
        let modeled: Vec<_> = targets
            .iter()
            .filter_map(|target| {
                let Expr::Name(name) = target else {
                    return None;
                };
                self.modeled_values
                    .get(name.id.as_str())
                    .cloned()
                    .map(|value| (name.id.to_string(), value))
            })
            .collect();
        self.pending_binds = None;
        self.pending_deferred_container = None;
        let instance_aliases = self.instance_source_aliases(targets, value);
        let instances = self.static_iter_instances(value);
        let targets: Vec<(usize, String)> = match targets {
            [Expr::Name(n)] => vec![(0, n.id.to_string())],
            [Expr::Tuple(t)] => t
                .elts
                .iter()
                .enumerate()
                .filter_map(|(i, e)| match e {
                    Expr::Name(n) => Some((i, n.id.to_string())),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        for (_, name) in &targets {
            self.clear_bound_value(name);
        }
        for (name, _) in &instance_aliases {
            if !targets.iter().any(|(_, target)| target == name) {
                self.clear_bound_value(name);
            }
        }
        self.modeled_values.extend(modeled);
        if let Some(instances) = instances
            && let [(0, name)] = targets.as_slice()
        {
            self.instance_sequences.insert(name.clone(), instances);
        }
        let Expr::Call(call) = value else {
            if let [(0, name)] = targets.as_slice() {
                let elements = match value {
                    Expr::List(list) => Some(list.elts.as_slice()),
                    Expr::Tuple(tuple) => Some(tuple.elts.as_slice()),
                    Expr::Set(set) => Some(set.elts.as_slice()),
                    _ => None,
                };
                let ranges: Vec<_> = elements
                    .into_iter()
                    .flatten()
                    .filter_map(|element| match element {
                        Expr::Call(call) => Some(call.range),
                        _ => None,
                    })
                    .collect();
                if !ranges.is_empty() {
                    self.deferred_containers.insert(name.clone(), Vec::new());
                    self.pending_deferred_container = Some((name.clone(), ranges));
                }
            }
            for (name, instance) in instance_aliases {
                self.instance_vars.insert(name, instance);
            }
            return;
        };
        if targets.is_empty() {
            return;
        }
        if let Some(mut iref) = self.instance_value(value)
            && targets.len() == 1
        {
            if self.module_capture
                && self.call_type(call).is_some()
                && let Some(scope) = &self.fact_scope
            {
                iref = SemanticValue::object(ObjectIdentity::ModuleBinding {
                    scope: scope.clone(),
                    name: targets[0].1.clone(),
                })
                .with_type(self.call_type(call));
            }
            self.instance_vars.insert(targets[0].1.clone(), iref);
        }
        // Always record the result binding: an imported name classified as a
        // possible constructor may turn out to be a function, in which case
        // the local is typed by the call's returned instance instead.
        self.pending_binds = Some((call.range, targets));
    }

    /// The instance a constructor call produces, when the callee is an
    /// unambiguous class reference: `cls(...)`, a locally defined class, or an
    /// imported name (verified to be a class at composition time).
    fn ctor_class(&self, call: &ast::ExprCall) -> Option<SemanticValue> {
        // Builtin value construction must not participate in user-class dispatch.
        if let Some(canonical) = self.imports.resolve_callee(&call.func)
            && canonical != "open"
            && resolve::is_builtin(canonical.strip_prefix("builtins.").unwrap_or(&canonical))
        {
            return None;
        }
        if matches!(call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "cls") {
            return Some(SemanticValue::object(ObjectIdentity::DynamicClass));
        }
        // A modeled path function such as `os.path.expanduser` returns the
        // path it resolves, not an instance that would replace that value.
        if self.modeled_path(&Expr::Call(call.clone())).is_some() {
            return None;
        }
        let name = callee_written(&call.func)?;
        // A local class, or an imported name (whether the import is actually a
        // class is verified at composition time against the target's class
        // table — a function never matches, so nothing is invented).
        if !self.class_names.contains(&name) && self.imports.resolve_callee(&call.func).is_none() {
            return None;
        }
        let origin = self.site_origin(call.range, 0);
        let constructor = self.value_args_of(call);
        Some(
            SemanticValue::object(ObjectIdentity::Class { name, constructor })
                .with_origin(Some(origin))
                .with_type(self.call_type(call)),
        )
    }

    fn value_args_of(&self, call: &ast::ExprCall) -> Vec<ValueArgument> {
        let mut arguments = self.resolved_value_args_of(call);
        let mkdir_call = matches!(call.func.as_ref(), Expr::Attribute(method)
            if method.attr.as_str() == "mkdir");
        if mkdir_call
            && let Some(keyword) = call
                .keywords
                .iter()
                .find(|keyword| keyword.arg.as_ref().map(|name| name.as_str()) == Some("parents"))
            && let Expr::Constant(constant) = &keyword.value
            && let Constant::Bool(value) = constant.value
            && let Some(argument) = arguments
                .iter_mut()
                .find(|argument| argument.name.as_deref() == Some("parents"))
        {
            argument.value = SemanticValue::literal(value.to_string());
        }
        arguments
    }

    fn resolved_value_args_of(&self, call: &ast::ExprCall) -> Vec<ValueArgument> {
        let mut arguments =
            positional_arguments(call.args.iter().map(|arg| self.resolve_value(arg)));
        arguments.extend(call.keywords.iter().filter_map(|keyword| {
            keyword.arg.as_ref().map(|name| {
                ValueArgument::keyword(name.to_string(), 0, self.resolve_value(&keyword.value))
            })
        }));
        merge_arguments(&mut arguments, self.obj_args_of(call));
        arguments
    }

    /// The instance-typed arguments of a call, positional and keyword.
    fn obj_args_of(&self, call: &ast::ExprCall) -> Vec<ValueArgument> {
        let mut out = Vec::new();
        for (i, arg) in call.args.iter().enumerate() {
            if let Some(instance) = self.instance_of_expr(arg) {
                if matches!(
                    instance.as_object().map(|object| &object.identity),
                    Some(ObjectIdentity::Parameter { .. })
                ) {
                    continue;
                }
                out.push(ValueArgument {
                    name: None,
                    index: i,
                    value: instance,
                });
            }
        }
        for kw in &call.keywords {
            let Some(param) = kw.arg.as_ref() else {
                continue;
            };
            if let Some(instance) = self.instance_of_expr(&kw.value) {
                if matches!(
                    instance.as_object().map(|object| &object.identity),
                    Some(ObjectIdentity::Parameter { .. })
                ) {
                    continue;
                }
                out.push(ValueArgument {
                    name: Some(param.to_string()),
                    index: 0,
                    value: instance,
                });
            }
        }
        out
    }

    /// An expression's instance reference, when its provenance is unambiguous.
    fn instance_of_expr(&self, expr: &Expr) -> Option<SemanticValue> {
        match expr {
            Expr::Name(n) => {
                let id = n.id.as_str();
                if id == "self" {
                    return Some(SemanticValue::object(ObjectIdentity::Receiver));
                }
                if id == "cls" {
                    return Some(SemanticValue::object(ObjectIdentity::DynamicClass));
                }
                if let Some(iref) = self.instance_vars.get(id) {
                    return Some(iref.clone());
                }
                if self.class_names.contains(id) {
                    return Some(SemanticValue::object(ObjectIdentity::Class {
                        name: id.to_string(),
                        constructor: Vec::new(),
                    }));
                }
                if self.current_params.iter().any(|p| p == id) {
                    return Some(SemanticValue::object(ObjectIdentity::Parameter {
                        name: id.to_string(),
                        fallback: None,
                    }));
                }
                self.bound_vars
                    .contains(id)
                    .then(|| {
                        SemanticValue::object(ObjectIdentity::Local {
                            name: id.to_string(),
                            fallback: None,
                        })
                    })
                    .or_else(|| self.imported_module_var(expr))
            }
            Expr::Attribute(a) => match a.value.as_ref() {
                Expr::Name(n) if n.id.as_str() == "self" => Some(SemanticValue::object(
                    ObjectIdentity::ReceiverProperty(a.attr.to_string()),
                )),
                _ => None,
            },
            Expr::Call(call) => self.ctor_class(call),
            _ => None,
        }
    }

    /// The receiver of a method call, when its class provenance is
    /// unambiguous: `self.m()`, `cls.m()`, `Class.m()` (a locally defined
    /// class), a constructor-typed or call-bound local, a parameter, or a
    /// one-level `self.attr.m()`.
    fn recv_of(&self, func: &Expr) -> Option<SemanticValue> {
        let Expr::Attribute(attr) = func else {
            return None;
        };
        match attr.value.as_ref() {
            Expr::Name(n) if n.id.as_str() == "self" => {
                Some(SemanticValue::object(ObjectIdentity::Receiver))
            }
            Expr::Name(n) if n.id.as_str() == "cls" => {
                Some(SemanticValue::object(ObjectIdentity::DynamicClass))
            }
            Expr::Name(n) if self.class_names.contains(n.id.as_str()) => {
                Some(SemanticValue::object(ObjectIdentity::Class {
                    name: n.id.to_string(),
                    constructor: Vec::new(),
                }))
            }
            // A plain Name: a constructor-typed local, parameter, or
            // call-bound local.
            Expr::Name(_) => self
                .instance_of_expr(attr.value.as_ref())
                .or_else(|| self.imported_module_var(attr.value.as_ref())),
            Expr::Attribute(inner) => match inner.value.as_ref() {
                Expr::Name(n) if n.id.as_str() == "self" => Some(SemanticValue::object(
                    ObjectIdentity::ReceiverProperty(inner.attr.to_string()),
                )),
                _ => self.imported_module_var(attr.value.as_ref()),
            },
            _ => self.imported_module_var(attr.value.as_ref()),
        }
    }

    fn imported_module_var(&self, expr: &Expr) -> Option<SemanticValue> {
        let canonical = self.imports.resolve_callee(expr)?;
        let (module, name) = canonical.rsplit_once('.')?;
        let module = self.imported_module_key(module)?;
        Some(
            SemanticValue::object(ObjectIdentity::ModuleBinding {
                scope: ScopeKey::Module { key: module },
                name: name.to_string(),
            })
            .with_type(model::python_external_type(&canonical)),
        )
    }

    fn imported_module_key(&self, module: &str) -> Option<String> {
        let level = module.bytes().take_while(|byte| *byte == b'.').count();
        if level == 0 {
            return Some(module.to_string());
        }
        let ScopeKey::Module { key } = self.fact_scope.as_ref()? else {
            return None;
        };
        let mut parts: Vec<&str> = key.split('.').collect();
        if !self.fact_file.ends_with("__init__.py") {
            parts.pop()?;
        }
        for _ in 1..level {
            parts.pop()?;
        }
        let suffix = &module[level..];
        if !suffix.is_empty() {
            parts.extend(suffix.split('.'));
        }
        (!parts.is_empty()).then(|| parts.join("."))
    }

    fn call_type(&self, call: &ast::ExprCall) -> Option<TypeRef> {
        self.imports
            .resolve_callee(&call.func)
            .as_deref()
            .and_then(model::python_external_type)
    }

    fn site_origin(&self, range: TextRange, result_index: usize) -> ValueOrigin {
        if let Some(ValueOrigin::Site {
            file,
            function,
            ordinal,
            ..
        }) = self.site_origins.borrow().get(&range)
        {
            return ValueOrigin::Site {
                file: file.clone(),
                function: function.clone(),
                ordinal: *ordinal,
                result_index,
            };
        }
        let ordinal = self.site_ordinal.get();
        self.site_ordinal.set(ordinal + 1);
        let origin = ValueOrigin::Site {
            file: self.fact_file.clone(),
            function: self.fact_function.clone(),
            ordinal,
            result_index,
        };
        self.site_origins.borrow_mut().insert(
            range,
            ValueOrigin::Site {
                file: self.fact_file.clone(),
                function: self.fact_function.clone(),
                ordinal,
                result_index: 0,
            },
        );
        origin
    }

    /// Per-tuple-element class of the returned value when every return yields
    /// the same unambiguously constructed class(es); empty when unknown.
    fn infer_returns_instances(&self, body: &[Stmt]) -> Vec<Option<String>> {
        let mut exprs = Vec::new();
        let mut saw_bare = false;
        collect_returns(body, &mut exprs, &mut saw_bare);
        if saw_bare {
            return Vec::new();
        }
        let mut result: Option<Vec<Option<String>>> = None;
        for expr in exprs {
            let elts: Vec<&Expr> = match expr {
                Expr::Tuple(t) => t.elts.iter().collect(),
                other => vec![other],
            };
            let classes: Vec<Option<String>> =
                elts.iter().map(|e| self.instance_class_name(e)).collect();
            match &result {
                None => result = Some(classes),
                Some(prev) if *prev == classes => {}
                _ => return Vec::new(),
            }
        }
        let out = result.unwrap_or_default();
        if out.iter().all(Option::is_none) {
            return Vec::new();
        }
        out
    }

    fn infer_return_types(&self, body: &[Stmt]) -> Vec<Option<TypeRef>> {
        let mut exprs = Vec::new();
        let mut saw_bare = false;
        collect_returns(body, &mut exprs, &mut saw_bare);
        if saw_bare {
            return Vec::new();
        }
        let mut result: Option<Vec<Option<TypeRef>>> = None;
        for expr in exprs {
            let elts: Vec<&Expr> = match expr {
                Expr::Tuple(tuple) => tuple.elts.iter().collect(),
                other => vec![other],
            };
            let types: Vec<_> = elts
                .iter()
                .map(|expr| {
                    self.instance_value(expr)
                        .and_then(|value| value.evidence.ty)
                })
                .collect();
            match &result {
                None => result = Some(types),
                Some(previous) if *previous == types => {}
                _ => return Vec::new(),
            }
        }
        let result = result.unwrap_or_default();
        if result.iter().all(Option::is_none) {
            Vec::new()
        } else {
            result
        }
    }

    fn infer_return_bindings(&self, body: &[Stmt]) -> Vec<Option<String>> {
        let mut exprs = Vec::new();
        let mut saw_bare = false;
        collect_returns(body, &mut exprs, &mut saw_bare);
        if saw_bare {
            return Vec::new();
        }
        let mut result: Option<Vec<Option<String>>> = None;
        for expr in exprs {
            let elts: Vec<&Expr> = match expr {
                Expr::Tuple(tuple) => tuple.elts.iter().collect(),
                other => vec![other],
            };
            let bindings: Vec<Option<String>> = elts
                .iter()
                .map(|expr| match expr {
                    Expr::Name(name) => Some(name.id.to_string()),
                    _ => None,
                })
                .collect();
            match &mut result {
                None => result = Some(bindings),
                Some(previous) if previous.len() == bindings.len() => {
                    for (old, new) in previous.iter_mut().zip(bindings) {
                        if *old != new {
                            *old = None;
                        }
                    }
                }
                Some(previous) => previous.clear(),
            }
        }
        let result = result.unwrap_or_default();
        if result.iter().all(Option::is_none) {
            Vec::new()
        } else {
            result
        }
    }

    /// The class (as written) an expression's value was constructed from, for
    /// return-instance inference: a constructor-typed local or a direct
    /// constructor call.
    fn instance_class_name(&self, expr: &Expr) -> Option<String> {
        let value = self.instance_value(expr)?;
        let ObjectIdentity::Class { name, .. } = &value.as_object()?.identity else {
            return None;
        };
        Some(name.clone())
    }

    fn instance_value(&self, expr: &Expr) -> Option<SemanticValue> {
        match expr {
            Expr::Name(n) => self.instance_vars.get(n.id.as_str()).cloned(),
            Expr::Call(call) => self.ctor_class(call).or_else(|| {
                let name = self.local_callee(&call.func)?;
                let class = self.return_instances.get(&name)?;
                Some(SemanticValue::object(ObjectIdentity::Class {
                    name: class.clone(),
                    constructor: Vec::new(),
                }))
            }),
            _ => None,
        }
    }

    /// A bare name that resolves to a module-level function in this file.
    fn local_fn_name(&self, expr: &Expr) -> Option<String> {
        let has = |n: &str| self.defs.iter().any(|d| d.name == n);
        match expr {
            Expr::Name(n) => {
                let id = n.id.as_str();
                if let Some(parent) = &self.current_function
                    && let Some(def) = self
                        .defs
                        .iter()
                        .find(|def| def.parent.as_deref() == Some(parent) && def.local_name == id)
                {
                    return Some(def.name.clone());
                }
                has(id).then(|| id.to_string())
            }
            // `self.boot` / `App.boot` passed to a registrar (`add_listener`,
            // `add_command`) is the same local function as a bare `boot`.
            Expr::Attribute(a) => {
                let method = a.attr.as_str();
                match a.value.as_ref() {
                    Expr::Name(n) if matches!(n.id.as_str(), "self" | "cls") => {
                        has(method).then(|| method.to_string())
                    }
                    Expr::Name(n) => {
                        let qualified = format!("{}.{method}", n.id);
                        if has(&qualified) {
                            Some(qualified)
                        } else {
                            has(method).then(|| method.to_string())
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// A call target that is a function defined in this file: a bare name,
    /// `self.method` / `cls.method`, `Class.method`, or a `Class()` constructor.
    fn local_callee(&self, func: &Expr) -> Option<String> {
        let has = |n: &str| self.defs.iter().any(|d| d.name == n);
        match func {
            Expr::Name(n) => {
                let id = n.id.as_str();
                if let Some(parent) = &self.current_function
                    && let Some(def) = self
                        .defs
                        .iter()
                        .find(|def| def.parent.as_deref() == Some(parent) && def.local_name == id)
                {
                    return Some(def.name.clone());
                }
                if has(id) {
                    return Some(id.to_string());
                }
                let init = format!("{id}.__init__");
                has(&init).then_some(init)
            }
            Expr::Attribute(attr) => {
                let method = attr.attr.as_str();
                match attr.value.as_ref() {
                    Expr::Name(n) if matches!(n.id.as_str(), "self" | "cls") => {
                        has(method).then(|| method.to_string())
                    }
                    Expr::Name(n) => {
                        if let Some(ObjectIdentity::Class { name, .. }) = self
                            .instance_vars
                            .get(n.id.as_str())
                            .and_then(SemanticValue::as_object)
                            .map(|object| &object.identity)
                        {
                            let qualified = format!("{name}.{method}");
                            if has(&qualified) {
                                return Some(qualified);
                            }
                        }
                        let qualified = format!("{}.{method}", n.id);
                        has(&qualified).then_some(qualified)
                    }
                    Expr::Call(_) => {
                        let receiver = self.instance_value(&attr.value)?;
                        let ObjectIdentity::Class { name, .. } = &receiver.as_object()?.identity
                        else {
                            return None;
                        };
                        let qualified = format!("{name}.{method}");
                        has(&qualified).then_some(qualified)
                    }
                    _ => None,
                }
            }
            Expr::Subscript(subscript) => {
                let key = str_literal(&subscript.slice)?;
                let Expr::Dict(dict) = subscript.value.as_ref() else {
                    return None;
                };
                let value =
                    dict.keys
                        .iter()
                        .zip(&dict.values)
                        .rev()
                        .find_map(|(candidate, value)| {
                            (candidate.as_ref().and_then(str_literal).as_deref()
                                == Some(key.as_str()))
                            .then_some(value)
                        })?;
                self.local_callee(value)
            }
            Expr::Call(call) => {
                if self.imports.resolve_callee(&call.func).as_deref() == Some("getattr")
                    && call.args.len() == 2
                    && call.keywords.is_empty()
                {
                    let class = self.instance_class_name(&call.args[0])?;
                    let member = str_literal(&call.args[1])?;
                    let name = format!("{class}.{member}");
                    return has(&name).then_some(name);
                }
                let producer = self.local_callee(&call.func)?;
                let definition = self
                    .defs
                    .iter()
                    .find(|def| def.name == producer && !def.is_async && !def.is_generator)?;
                let Stmt::Return(returned) = definition.body.last()? else {
                    return None;
                };
                let Expr::Name(returned) = returned.value.as_deref()? else {
                    return None;
                };
                self.defs
                    .iter()
                    .find(|def| {
                        def.parent.as_deref() == Some(producer.as_str())
                            && def.local_name == returned.id.as_str()
                    })
                    .map(|def| def.name.clone())
            }
            _ => None,
        }
    }

    /// Seed the import scope from module-level `import` / `from ... import`
    /// statements — including those inside module-level control flow (a
    /// version guard's `import subprocess`) — so summary inference (which runs
    /// before the execution walk) can resolve effect APIs. Function bodies are
    /// not descended: their imports are scoped and handled during the walk.
    /// Shadowing is still handled in execution order.
    fn collect_imports(&mut self, body: &[Stmt]) {
        for stmt in body {
            match stmt {
                Stmt::Import(import) => {
                    for alias in &import.names {
                        self.add_import(alias.name.as_str(), alias.asname.as_deref());
                    }
                }
                Stmt::ImportFrom(from) => {
                    let module = import_from_module(from);
                    for alias in &from.names {
                        if alias.name.as_str() == "*" {
                            if let Some(exports) = star_exports(&module) {
                                for member in exports {
                                    self.add_from_import(&module, member, None);
                                }
                            }
                            continue;
                        }
                        self.add_from_import(&module, alias.name.as_str(), alias.asname.as_deref());
                    }
                }
                Stmt::If(s) => {
                    self.collect_imports(&s.body);
                    self.collect_imports(&s.orelse);
                }
                Stmt::Try(s) => {
                    self.collect_imports(&s.body);
                    for handler in &s.handlers {
                        let ast::ExceptHandler::ExceptHandler(h) = handler;
                        self.collect_imports(&h.body);
                    }
                    self.collect_imports(&s.orelse);
                    self.collect_imports(&s.finalbody);
                }
                Stmt::With(s) => self.collect_imports(&s.body),
                _ => {}
            }
        }
    }

    fn add_import(&mut self, module: &str, alias: Option<&str>) {
        self.imports.add_import(module, alias);
        if self.local_python_module(module) {
            self.imports
                .mark_local(alias.unwrap_or_else(|| module.split('.').next().unwrap_or(module)));
        }
    }

    fn add_from_import(&mut self, module: &str, member: &str, alias: Option<&str>) {
        self.imports.add_from(module, member, alias);
        if self.local_python_module(module) {
            self.imports.mark_local(alias.unwrap_or(member));
        }
    }

    /// Match the repository linker's absolute-import search order before a
    /// stdlib-shaped name can claim external ownership.
    fn local_python_module(&mut self, module: &str) -> bool {
        if self.nest.resolver.is_none() {
            return false;
        }
        if let Some(resolved) = self.traversed_python_module(module) {
            return resolved;
        }
        let root = module.split('.').next().unwrap_or(module);
        if root.is_empty() {
            if self.builder.current_execution_is_selected_input() {
                self.nest.record_dependency_request(self.builder, module);
            }
            return false;
        }
        let source_cwd = self.nest.current_source_cwd();
        let local = [Some(""), Some("src"), source_cwd.as_deref()]
            .into_iter()
            .flatten()
            .flat_map(|base| {
                let prefix = if base.is_empty() {
                    root.to_string()
                } else {
                    format!("{base}/{root}")
                };
                [format!("{prefix}.py"), format!("{prefix}/__init__.py")]
            })
            .any(|path| {
                // Ownership probes use the admitted directory inventory, not source bytes.
                let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
                let directory = if parent.is_empty() {
                    ".".to_string()
                } else {
                    format!("{parent}/.")
                };
                self.nest
                    .source_siblings(&directory)
                    .is_some_and(|files| files.contains(&path))
            });
        if self.builder.current_execution_is_selected_input() {
            if local || !is_python_stdlib(root) {
                self.nest.record_dependency_request(self.builder, module);
            }
            return false;
        }
        local
    }

    /// Record module-level `NAME = <path>` constants whose value resolves to a
    /// usable resource (a literal path, an `os.path.join`, an f-string). Later
    /// occurrences win. Used to resolve a constant referenced inside a helper's
    /// return or effect (e.g. `join(ROOT, t)`).
    fn collect_consts(&mut self, body: &[Stmt]) {
        self.shared_vars = rebound_body_names(body, true);
        for stmt in body {
            let Stmt::Assign(assign) = stmt else { continue };
            let [Expr::Name(target)] = assign.targets.as_slice() else {
                continue;
            };
            if self.shared_vars.contains(target.id.as_str()) {
                continue;
            }
            let resolved = str_literal(&assign.value)
                .map(|value| ResourceExpr::Literal { value })
                .or_else(|| self.source_string_resource(&assign.value))
                .unwrap_or_else(|| self.fs_resource(&assign.value));
            let name = target.id.as_str().to_string();
            let unbounded_string =
                self.string_binding_is_unbounded(&assign.value, is_resolvable(&resolved));
            if unbounded_string {
                self.const_unbounded_strings.insert(name.clone());
                self.unbounded_string_vars.insert(name.clone());
            } else {
                self.const_unbounded_strings.remove(&name);
                self.unbounded_string_vars.remove(&name);
            }
            if is_resolvable(&resolved) && !unbounded_string {
                if self.lowered_concatenation(&assign.value).is_some() {
                    self.const_concatenations.insert(name.clone());
                } else {
                    self.const_concatenations.remove(&name);
                }
                self.consts.insert(name, resolved);
            } else {
                self.const_concatenations.remove(&name);
                self.consts.remove(&name);
            }
            if self.is_path_value(&assign.value) {
                self.path_vars.insert(target.id.to_string());
            } else {
                self.path_vars.remove(target.id.as_str());
            }
            self.branch_mixed_path_vars.remove(target.id.as_str());
        }
    }

    /// Resolve an expression used as a filesystem path, then substitute the
    /// current scope (constants and tracked locals) so a bare name bound to a
    /// resource resolves to it rather than staying a free parameter.
    fn resolve_fs(&self, expr: &Expr) -> ResourceExpr {
        if self.path_expression_uses_widened_binding(expr)
            || self.concatenation_uses_unbounded_binding(expr)
        {
            return unresolved("filesystem");
        }
        // `abspath` and `normpath` only normalize their argument's spelling,
        // which already resolves against the working directory.
        if let Expr::Call(call) = expr
            && call.args.len() == 1
            && call.keywords.is_empty()
            && matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("os.path.abspath" | "os.path.normpath")
            )
        {
            return self.resolve_fs(&call.args[0]);
        }
        // The bytes or str spelling of a path names the same file.
        if let Expr::Call(call) = expr
            && let [path] = call.args.as_slice()
            && call.keywords.is_empty()
            && matches!(
                self.imports.resolve_callee(&call.func).as_deref(),
                Some("os.fsencode" | "os.fsdecode")
            )
        {
            return self.resolve_fs(path);
        }
        if let Expr::Call(call) = expr
            && call.args.len() == 1
            && call.keywords.is_empty()
            && let Expr::Attribute(method) = call.func.as_ref()
            && matches!(method.attr.as_str(), "with_name" | "with_suffix")
        {
            let base = self.resolve_fs(&method.value);
            let transformed = if method.attr.as_str() == "with_name" {
                resolve::concrete_path_transform(base, &call.args[0], |path, value| {
                    path.set_file_name(value);
                })
            } else {
                resolve::concrete_path_transform(base, &call.args[0], |path, value| {
                    path.set_extension(value.strip_prefix('.').unwrap_or(value));
                })
            };
            if let Some(resource) = transformed {
                return self.lower_fs_literal(resource);
            }
        }
        if let Some(call) = self.executed_local_call(expr)
            && let Some(resource) = self.call_return_resource(call)
        {
            return self.lower_fs_literal(resource);
        }
        if let Some(resource) = self.collection_item(expr) {
            return self.lower_fs_literal(resource);
        }
        if let Some(resource) = self.lowered_concatenation(expr) {
            let resource = substitute_resource_expr(&resource, &self.var_scope);
            let ResourceExpr::Join { parts } = resource else {
                return self.lower_fs_literal(resource);
            };
            return self.lower_fs_literal(crate::value::sink_typed_concat(
                parts,
                "filesystem",
                self.cwd.as_deref().map(|cwd| resolve_fs_path(cwd, None)),
            ));
        }
        let resource = substitute_resource_expr(&self.fs_resource(expr), &self.var_scope);
        let resource = if Self::path_expression_expands_user(expr) {
            resolve::expanduser_resource(resource)
        } else {
            resource
        };
        let resource = if self.is_path_value(expr) {
            resolve::normalize_pathlib_resource(resource)
        } else {
            resource
        };
        let resource = self.lower_fs_literal(resource);
        if self.capture.is_none()
            && matches!(expr, Expr::Name(_))
            && matches!(resource, ResourceExpr::Parameter { .. })
        {
            self.free_resource_parameter.set(true);
        }
        resource
    }

    fn path_expression_uses_widened_binding(&self, expr: &Expr) -> bool {
        if matches!(expr, Expr::Name(name) if self.widened_vars.contains(name.id.as_str())) {
            return true;
        }
        let recognized_call = matches!(expr, Expr::Call(call)
            if callee_written(&call.func).as_deref() == Some("str")
                || self.imports.resolve_callee(&call.func).as_deref() == Some("os.path.join"));
        (self.is_path_value(expr) || recognized_call)
            && expression_uses_name(expr, &self.widened_vars)
    }

    fn path_expression_expands_user(expr: &Expr) -> bool {
        match expr {
            Expr::Call(call) => {
                if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "str") {
                    return call
                        .args
                        .first()
                        .is_some_and(Self::path_expression_expands_user);
                }
                let Expr::Attribute(method) = call.func.as_ref() else {
                    return false;
                };
                method.attr.as_str() == "expanduser"
                    || Self::path_expression_expands_user(&method.value)
            }
            Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
                Self::path_expression_expands_user(&binary.left)
            }
            Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => {
                Self::path_expression_expands_user(&attribute.value)
            }
            Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
            {
                let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                    unreachable!();
                };
                Self::path_expression_expands_user(&attribute.value)
            }
            _ => false,
        }
    }

    fn lowered_concatenation(&self, expr: &Expr) -> Option<ResourceExpr> {
        if self.concatenation_uses_unbounded_binding(expr) {
            return None;
        }
        resolve::concatenated_resource(
            expr,
            &self.imports,
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
        )
        .or_else(|| {
            let Expr::Name(name) = expr else {
                return None;
            };
            if !self.concatenated_vars.contains(name.id.as_str()) {
                return None;
            }
            self.var_scope.get(name.id.as_str()).cloned()
        })
    }

    fn concatenation_uses_unbounded_binding(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Name(name) => self.unbounded_string_vars.contains(name.id.as_str()),
            Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
                self.concatenation_uses_unbounded_binding(&binary.left)
                    || self.concatenation_uses_unbounded_binding(&binary.right)
            }
            Expr::JoinedStr(joined) => joined.values.iter().any(|value| match value {
                Expr::FormattedValue(formatted) => {
                    self.concatenation_uses_unbounded_binding(&formatted.value)
                }
                _ => false,
            }),
            _ => false,
        }
    }

    fn string_binding_is_unbounded(&self, expr: &Expr, resolved: bool) -> bool {
        match expr {
            Expr::BinOp(binary) if binary.op == ast::Operator::Add => {
                self.lowered_concatenation(expr).is_none()
            }
            Expr::JoinedStr(_) => self.lowered_concatenation(expr).is_none(),
            Expr::Name(name) => self.unbounded_string_vars.contains(name.id.as_str()),
            Expr::Constant(_) => str_literal(expr).is_none(),
            Expr::Attribute(_) | Expr::Subscript(_) => false,
            Expr::Call(call) => {
                !resolved
                    && !matches!(callee_written(&call.func).as_deref(), Some("input"))
                    && !matches!(
                        self.imports.resolve_callee(&call.func).as_deref(),
                        Some("os.getenv" | "os.environ.get")
                    )
            }
            _ => !resolved,
        }
    }

    fn source_string_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        if let Some(resource) = self.lowered_concatenation(expr) {
            return Some(resource);
        }
        if let Some(ResourceExpr::Join { mut parts }) = resolve::concatenated_part_resource(
            expr,
            &self.imports,
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
        ) && parts.len() == 1
            && matches!(parts.first(), Some(ResourceExpr::Environment { .. }))
        {
            return parts.pop();
        }
        if let Some(value) = str_literal(expr) {
            return matches!(
                SemanticValue::source_literal(value.clone()).kind,
                SemanticValueKind::Endpoint { .. }
            )
            .then_some(ResourceExpr::Literal { value });
        }
        let Expr::Name(name) = expr else {
            return None;
        };
        match self.var_scope.get(name.id.as_str()) {
            Some(resource @ ResourceExpr::Literal { .. }) => Some(resource.clone()),
            _ => None,
        }
    }

    fn fs_resource(&self, expr: &Expr) -> ResourceExpr {
        if let Some(resource) = self.modeled_path(expr) {
            return resource;
        }
        if self.current_class.is_some()
            && let Expr::Attribute(attribute) = expr
            && matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
        {
            return ResourceExpr::Parameter {
                name: format!("self.{}", attribute.attr),
            };
        }
        resolve::fs_resource(
            expr,
            &self.imports,
            self.cwd.as_deref(),
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
            &self.path_vars,
        )
    }

    fn lower_fs_literal(&self, resource: ResourceExpr) -> ResourceExpr {
        match resource {
            ResourceExpr::Literal { value } => resolve_fs_path(&value, self.cwd.as_deref()),
            ResourceExpr::Join { parts } => {
                let resource = ResourceExpr::Join { parts };
                let resource =
                    if contains_literal(&resource) && !crate::summary::has_text_concat(&resource) {
                        let ResourceExpr::Join { parts } = resource else {
                            unreachable!();
                        };
                        crate::value::sink_typed_join(parts, "filesystem")
                    } else {
                        resource
                    };
                let resource = normalize_resource(resource, PathPlatform::Posix);
                match resource {
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    } if !effinterp_proto::is_absolute_path(&path, PathPlatform::Posix) => {
                        resolve_fs_path(&path, self.cwd.as_deref())
                    }
                    ResourceExpr::Join { parts }
                        if matches!(
                            parts.first(),
                            Some(ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath { path },
                            }) if !effinterp_proto::is_absolute_path(path, PathPlatform::Posix)
                        ) =>
                    {
                        let cwd = self
                            .cwd
                            .as_deref()
                            .map(|cwd| ResourceExpr::Concrete {
                                identity: effinterp_proto::ResourceIdentity::FsPath {
                                    path: effinterp_proto::normalize_path(cwd, PathPlatform::Posix),
                                },
                            })
                            .unwrap_or_else(|| ResourceExpr::Parameter {
                                name: "cwd".to_string(),
                            });
                        normalize_resource(
                            ResourceExpr::Join {
                                parts: std::iter::once(cwd).chain(parts).collect(),
                            },
                            PathPlatform::Posix,
                        )
                    }
                    resource => resource,
                }
            }
            other => other,
        }
    }

    fn collection_item(&self, expr: &Expr) -> Option<ResourceExpr> {
        let Expr::Subscript(subscript) = expr else {
            return None;
        };
        let Expr::Name(name) = subscript.value.as_ref() else {
            return None;
        };
        match self.collections.get(name.id.as_str())? {
            StaticContainer::Sequence(values) => values
                .get(int_literal(&subscript.slice)? as usize)
                .map(|value| value.resource.clone()),
            StaticContainer::Mapping(values) => values
                .get(&str_literal(&subscript.slice)?)
                .map(|value| value.resource.clone()),
        }
    }

    fn invalidate_collection(&mut self, name: &str) {
        // Containers may share nested mutable values even when their outer shapes differ.
        self.modeled_values
            .retain(|_, value| !matches!(value, model::ModeledValue::BuiltinData));
        if let Some(instances) = self.instance_sequences.remove(name) {
            self.instance_sequences
                .retain(|_, candidate| candidate != &instances);
        }
        self.deferred_containers.remove(name);
        let Some(value) = self.collections.remove(name) else {
            return;
        };
        self.collections.retain(|_, candidate| candidate != &value);
    }

    fn static_container(&self, expr: &Expr) -> Option<StaticContainer> {
        let sequence = |elts: &[Expr]| {
            if elts.len() > self.nest.limits.value_limits().max_cardinality {
                return None;
            }
            elts.iter()
                .map(|expr| {
                    let resource = if let Some(value) = str_literal(expr) {
                        ResourceExpr::Literal { value }
                    } else {
                        let resource = self.resolve_fs(expr);
                        if !is_resolvable(&resource) {
                            return None;
                        }
                        resource
                    };
                    Some(StaticResource {
                        resource,
                        is_path: self.is_path_value(expr),
                    })
                })
                .collect::<Option<Vec<_>>>()
                .map(StaticContainer::Sequence)
        };
        match expr {
            Expr::List(list) => sequence(&list.elts),
            Expr::Tuple(tuple) => sequence(&tuple.elts),
            Expr::Set(set) => sequence(&set.elts),
            Expr::Dict(dict) => {
                if dict.values.len() > self.nest.limits.value_limits().max_cardinality {
                    return None;
                }
                let mut values = std::collections::HashMap::new();
                for (key, value) in dict.keys.iter().zip(&dict.values) {
                    let key = str_literal(key.as_ref()?)?;
                    let resource = str_literal(value)
                        .map(|value| ResourceExpr::Literal { value })
                        .unwrap_or_else(|| self.resolve_fs(value));
                    if !is_resolvable(&resource) {
                        return None;
                    }
                    values.insert(
                        key,
                        StaticResource {
                            resource,
                            is_path: self.is_path_value(value),
                        },
                    );
                }
                Some(StaticContainer::Mapping(values))
            }
            Expr::ListComp(comprehension) => self
                .static_comprehension_values(&comprehension.elt, &comprehension.generators)
                .map(StaticContainer::Sequence),
            Expr::SetComp(comprehension) => self
                .static_comprehension_values(&comprehension.elt, &comprehension.generators)
                .map(StaticContainer::Sequence),
            Expr::GeneratorExp(comprehension) => self
                .static_comprehension_values(&comprehension.elt, &comprehension.generators)
                .map(StaticContainer::Sequence),
            Expr::Call(call)
                if matches!(
                    callee_written(&call.func).as_deref(),
                    Some("list" | "tuple" | "set")
                ) =>
            {
                let value = call.args.first()?;
                self.static_resources(value)
                    .or_else(|| self.static_iter_resources(value))
                    .map(StaticContainer::Sequence)
            }
            Expr::Name(name) => self.collections.get(name.id.as_str()).cloned(),
            _ => None,
        }
    }

    fn static_comprehension_values(
        &self,
        element: &Expr,
        generators: &[ast::Comprehension],
    ) -> Option<Vec<StaticResource>> {
        let [generator] = generators else {
            return None;
        };
        if !generator.ifs.is_empty() {
            return None;
        }
        let Expr::Name(target) = &generator.target else {
            return None;
        };
        let target_name = target.id.to_string();
        let target_names = HashSet::from([target_name.clone()]);
        let element_uses_target = expression_uses_name(element, &target_names);
        let mut scope = self.var_scope.clone();
        self.static_resources(&generator.iter)?
            .into_iter()
            .map(|value| {
                let target_is_path = value.is_path;
                scope.insert(target_name.clone(), value.resource);
                let resource = substitute_resource_expr(&self.fs_resource(element), &scope);
                is_resolvable(&resource).then_some(StaticResource {
                    resource,
                    is_path: match element {
                        Expr::Name(name) if name.id.as_str() == target_name => target_is_path,
                        _ if element_uses_target => false,
                        _ => self.is_path_value(element),
                    },
                })
            })
            .collect()
    }

    fn static_sequence(&self, expr: &Expr) -> Option<Vec<ResourceExpr>> {
        self.static_resources(expr)
            .map(|values| values.into_iter().map(|value| value.resource).collect())
    }

    fn static_resources(&self, expr: &Expr) -> Option<Vec<StaticResource>> {
        if let Some(model::ModeledValue::Temporary { resource, kind }) = self.modeled_value(expr)
            && kind == "tempfile.mkstemp"
        {
            return Some(vec![
                StaticResource {
                    resource: unresolved("process"),
                    is_path: false,
                },
                StaticResource {
                    resource,
                    is_path: false,
                },
            ]);
        }
        match self.static_container(expr)? {
            StaticContainer::Sequence(values) => Some(values),
            StaticContainer::Mapping(_) => None,
        }
    }

    fn static_iter_resources(&self, expr: &Expr) -> Option<Vec<StaticResource>> {
        if let Some(values) = self.static_resources(expr) {
            return Some(values);
        }
        let Expr::Call(call) = expr else {
            return None;
        };
        let name = self.local_callee(&call.func)?;
        let def = self
            .defs
            .iter()
            .find(|def| def.name == name && def.is_generator)?;
        let arguments = positional_arguments(call.args.iter().map(|arg| self.resolve_value(arg)));
        let bindings = bind_python_arguments(&def.params, def.positional_param_count, &arguments);
        let mut scope = self.consts.clone();
        scope.extend(
            bindings
                .into_iter()
                .map(|(name, value)| (name, value.lower_resource())),
        );
        let mut values = Vec::new();
        self.collect_generator_values(&def.body, &mut scope, &mut values)?;
        Some(
            values
                .into_iter()
                .map(|resource| StaticResource {
                    resource,
                    is_path: false,
                })
                .collect(),
        )
    }

    /// Constructor identities of a statically listed loop iterable, in AST order.
    fn static_iter_instances(&self, iter: &Expr) -> Option<Vec<Option<SemanticValue>>> {
        let elts = match iter {
            Expr::Name(name) => return self.instance_sequences.get(name.id.as_str()).cloned(),
            Expr::List(list) => list.elts.as_slice(),
            Expr::Tuple(tuple) => tuple.elts.as_slice(),
            Expr::Set(set) => set.elts.as_slice(),
            _ => return None,
        };
        if elts.len() > self.nest.limits.value_limits().max_cardinality {
            return None;
        }
        Some(elts.iter().map(|expr| self.instance_value(expr)).collect())
    }

    fn static_iter_values(&self, expr: &Expr) -> Option<Vec<ResourceExpr>> {
        self.static_iter_resources(expr)
            .map(|values| values.into_iter().map(|value| value.resource).collect())
    }

    fn static_sequence_in_scope(
        &self,
        expr: &Expr,
        scope: &std::collections::HashMap<String, ResourceExpr>,
    ) -> Option<Vec<ResourceExpr>> {
        let elts = match expr {
            Expr::List(list) => &list.elts,
            Expr::Tuple(tuple) => &tuple.elts,
            Expr::Set(set) => &set.elts,
            Expr::Name(name) => {
                let StaticContainer::Sequence(values) = self.collections.get(name.id.as_str())?
                else {
                    return None;
                };
                return Some(values.iter().map(|value| value.resource.clone()).collect());
            }
            _ => return None,
        };
        if elts.len() > self.nest.limits.value_limits().max_cardinality {
            return None;
        }
        elts.iter()
            .map(|expr| {
                if let Some(value) = str_literal(expr) {
                    return Some(ResourceExpr::Literal { value });
                }
                let value = substitute_resource_expr(&self.fs_resource(expr), scope);
                is_resolvable(&value).then_some(value)
            })
            .collect()
    }

    /// Recover yielded resources only through statically finite generator
    /// paths. The boolean reports an encountered `return`, which terminates an
    /// enclosing finite loop as well as the current statement list.
    fn collect_generator_values(
        &self,
        body: &[Stmt],
        scope: &mut std::collections::HashMap<String, ResourceExpr>,
        out: &mut Vec<ResourceExpr>,
    ) -> Option<bool> {
        for stmt in body {
            match stmt {
                Stmt::Expr(stmt) => match stmt.value.as_ref() {
                    Expr::Yield(yielded) => {
                        if let Some(expr) = &yielded.value {
                            let value = substitute_resource_expr(&self.fs_resource(expr), scope);
                            if !is_resolvable(&value) {
                                return None;
                            }
                            out.push(self.lower_fs_literal(value));
                        }
                    }
                    Expr::YieldFrom(yielded) => {
                        out.extend(
                            self.static_sequence_in_scope(&yielded.value, scope)?
                                .into_iter()
                                .map(|value| self.lower_fs_literal(value)),
                        );
                    }
                    _ => {}
                },
                Stmt::Assign(assign) => {
                    let [Expr::Name(name)] = assign.targets.as_slice() else {
                        return None;
                    };
                    let value = substitute_resource_expr(&self.fs_resource(&assign.value), scope);
                    if !is_resolvable(&value) {
                        return None;
                    }
                    scope.insert(name.id.to_string(), value);
                }
                Stmt::AnnAssign(assign) => {
                    let Expr::Name(name) = assign.target.as_ref() else {
                        return None;
                    };
                    let value = assign.value.as_deref()?;
                    let value = substitute_resource_expr(&self.fs_resource(value), scope);
                    if !is_resolvable(&value) {
                        return None;
                    }
                    scope.insert(name.id.to_string(), value);
                }
                Stmt::For(stmt) => {
                    let Expr::Name(target) = stmt.target.as_ref() else {
                        return None;
                    };
                    let values = self.static_sequence_in_scope(&stmt.iter, scope)?;
                    for value in values {
                        scope.insert(target.id.to_string(), value);
                        if self.collect_generator_values(&stmt.body, scope, out)? {
                            return Some(true);
                        }
                    }
                    if self.collect_generator_values(&stmt.orelse, scope, out)? {
                        return Some(true);
                    }
                }
                Stmt::With(stmt) => {
                    if self.collect_generator_values(&stmt.body, scope, out)? {
                        return Some(true);
                    }
                }
                Stmt::Return(_) => return Some(true),
                Stmt::Pass(_) => {}
                // A branch, unbounded loop, break, or other dynamic statement
                // cannot prove one finite sequence of yielded resources.
                _ => return None,
            }
            if out.len() > self.nest.limits.value_limits().max_cardinality {
                return None;
            }
        }
        Some(false)
    }

    // Return and receiver inference precedes effect emission at an assignment or
    // sink. Prepare only the calls in that expression, innermost first.
    fn prepare_call_summaries(&mut self, value: &Expr) {
        if !self.demand_summaries {
            return;
        }
        let mut stack = vec![(value, false)];
        while let Some((expr, visited)) = stack.pop() {
            if visited {
                if let Expr::Call(call) = expr
                    && let Some(name) = self.local_callee(&call.func)
                {
                    self.ensure_summary(&name);
                }
            } else {
                if !self.charge(expr.range()) {
                    break;
                }
                stack.push((expr, true));
                stack.extend(
                    child_exprs(expr)
                        .into_iter()
                        .rev()
                        .map(|child| (child, false)),
                );
            }
        }
    }

    /// Bind each assigned name to the same evaluated resource. Chained
    /// assignment evaluates `value` once; an untrackable path RHS widens.
    fn bind_assigned_names(&mut self, names: &[String], value: &Expr) -> bool {
        if names.is_empty() {
            return true;
        }
        self.prepare_call_summaries(value);
        let path_value = self.is_path_value(value);
        let path_candidate = self.may_be_path_value(value);
        let branch_mixed_path = self.is_branch_mixed_path_value(value);
        let concatenated = self.lowered_concatenation(value).is_some();
        let was_paths: Vec<bool> = names
            .iter()
            .map(|name| self.path_vars.contains(name))
            .collect();
        let tracked = self.tracked_value(value);
        if self.node_budget_hit {
            return false;
        }
        let unbounded_string = self.string_binding_is_unbounded(value, tracked.is_some());
        let session = self.net_receiver(value);
        let modeled = self.modeled_value(value);
        let container = self.static_container(value);
        for (name, was_path) in names.iter().zip(was_paths) {
            self.modeled_values.remove(name);
            if let Some(value) = &modeled {
                self.modeled_values.insert(name.clone(), value.clone());
            }
            match &tracked {
                Some(res) => {
                    self.var_scope.insert(name.clone(), res.clone());
                    if path_value {
                        self.path_vars.insert(name.clone());
                    } else {
                        self.path_vars.remove(name);
                    }
                    if path_value && branch_mixed_path {
                        self.branch_mixed_path_vars.insert(name.clone());
                    } else {
                        self.branch_mixed_path_vars.remove(name);
                    }
                    if concatenated {
                        self.concatenated_vars.insert(name.clone());
                    } else {
                        self.concatenated_vars.remove(name);
                    }
                }
                None => {
                    self.var_scope.remove(name);
                    self.concatenated_vars.remove(name);
                    if was_path || path_candidate {
                        self.path_vars.insert(name.clone());
                        self.widened_vars.insert(name.clone());
                        if path_candidate && branch_mixed_path {
                            self.branch_mixed_path_vars.insert(name.clone());
                        }
                    } else {
                        self.path_vars.remove(name);
                        self.branch_mixed_path_vars.remove(name);
                    }
                }
            }
            if unbounded_string {
                self.unbounded_string_vars.insert(name.clone());
            } else {
                self.unbounded_string_vars.remove(name);
            }
            match &session {
                Some(recv) => {
                    self.sessions.insert(name.clone(), recv.clone());
                }
                None => {
                    self.sessions.remove(name);
                }
            }
            match &container {
                Some(container) => {
                    self.collections.insert(name.clone(), container.clone());
                }
                None => {
                    self.collections.remove(name);
                }
            }
        }
        true
    }

    fn static_unpack(
        &self,
        targets: &[Expr],
        value: &Expr,
    ) -> Option<Vec<(String, StaticResource)>> {
        let [target] = targets else { return None };
        let names: Vec<String> = match target {
            Expr::Tuple(tuple) => tuple
                .elts
                .iter()
                .map(|expr| match expr {
                    Expr::Name(name) => Some(name.id.to_string()),
                    _ => None,
                })
                .collect::<Option<_>>()?,
            Expr::List(list) => list
                .elts
                .iter()
                .map(|expr| match expr {
                    Expr::Name(name) => Some(name.id.to_string()),
                    _ => None,
                })
                .collect::<Option<_>>()?,
            _ => return None,
        };
        let values = self.static_resources(value)?;
        if names.len() != values.len() {
            return None;
        }
        Some(names.into_iter().zip(values).collect())
    }

    fn track_unpack(&mut self, bindings: Vec<(String, StaticResource)>) {
        for (name, value) in bindings {
            self.widened_vars.remove(&name);
            self.concatenated_vars.remove(&name);
            self.unbounded_string_vars.remove(&name);
            self.var_scope.insert(name.clone(), value.resource);
            if value.is_path {
                self.path_vars.insert(name.clone());
            } else {
                self.path_vars.remove(&name);
            }
            self.branch_mixed_path_vars.remove(&name);
        }
    }

    fn resolve_value(&self, expr: &Expr) -> SemanticValue {
        let resolved = self
            .source_string_resource(expr)
            .map(|resource| substitute_resource_expr(&resource, &self.var_scope))
            .unwrap_or_else(|| self.resolve_fs(expr));
        let Some(source) = str_literal(expr) else {
            return SemanticValue::from(resolved);
        };
        if self.cwd.is_none() {
            return SemanticValue::source_literal(source);
        }
        let parts = match resolved {
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } => vec![SemanticValue::literal(path)],
            ResourceExpr::Join { parts } => parts.into_iter().map(SemanticValue::from).collect(),
            other => return SemanticValue::from(other),
        };
        SemanticValue::new(SemanticValueKind::Path {
            parts,
            source: Some(source),
        })
    }

    /// The resource a variable refers to after an assignment, or None to drop
    /// any stale tracking for it: the substituted return of a call into a
    /// summarized local function, otherwise the value resolved as a path.
    fn tracked_value(&mut self, value: &Expr) -> Option<ResourceExpr> {
        if let Some(resource) = self.modeled_path(value) {
            return Some(resource);
        }
        if let Some(value) = str_literal(value) {
            return Some(ResourceExpr::Literal { value });
        }
        if let Expr::Call(call) = value
            && callee_written(&call.func).as_deref() == Some("next")
            && let Some(iter) = call.args.first()
        {
            return self
                .static_sequence(iter)
                .or_else(|| self.static_iter_values(iter))?
                .into_iter()
                .next();
        }
        if let Some(call) = self.executed_local_call(value)
            && let Some(name) = self.local_callee(&call.func)
        {
            let bindings = self.call_bindings(&name, call);
            if let Some(returns) = self
                .summaries
                .get(&name)
                .and_then(|summary| summary.returns.as_ref())
            {
                let mut visited = 0;
                let substituted = crate::substitute_value_counted(
                    returns,
                    &bindings,
                    self.nest.limits.value_limits(),
                    &mut visited,
                );
                let range = value.range();
                let span = (u32::from(range.start()), u32::from(range.end()));
                if !self.charge_steps(visited, span) {
                    self.node_budget_hit = true;
                    return None;
                }
                return Some(substituted.lower_resource());
            }
        }
        if let Some(resource) = self.source_string_resource(value) {
            return Some(substitute_resource_expr(&resource, &self.var_scope));
        }
        if matches!(value, Expr::Call(call)
            if matches!(call.func.as_ref(), Expr::Attribute(method)
                if matches!(method.attr.as_str(), "with_name" | "with_suffix")))
        {
            let resolved = self.resolve_fs(value);
            return is_resolvable(&resolved).then_some(resolved);
        }
        let resolved =
            if self.is_path_value(value) && !self.path_expression_uses_widened_binding(value) {
                let resource = substitute_resource_expr(&self.fs_resource(value), &self.var_scope);
                let resource = if Self::path_expression_expands_user(value) {
                    resolve::expanduser_resource(resource)
                } else {
                    resource
                };
                resolve::normalize_pathlib_resource(resource)
            } else {
                self.resolve_fs(value)
            };
        is_resolvable(&resolved).then_some(resolved)
    }

    fn call_return_resource(&self, call: &ast::ExprCall) -> Option<ResourceExpr> {
        let name = self.local_callee(&call.func)?;
        let summary = self.summaries.get(&name)?;
        let returns = summary.returns.as_ref()?;
        let bindings = self.call_bindings(&name, call);
        Some(substitute_value(returns, &bindings, self.nest.limits.value_limits()).lower_resource())
    }

    fn call_bindings(
        &self,
        name: &str,
        call: &ast::ExprCall,
    ) -> std::collections::HashMap<String, SemanticValue> {
        let Some(def) = self.defs.iter().find(|def| def.name == name) else {
            return std::collections::HashMap::new();
        };
        let mut arguments = self.resolved_value_args_of(call);
        for argument in &mut arguments {
            if let Some(resource) = path_object_resource(&argument.value) {
                argument.value = SemanticValue::from(resource);
            }
        }
        let mut bindings = self.bind_with_defaults(
            &def.params,
            def.positional_param_count,
            &def.param_defaults,
            &arguments,
            !call
                .args
                .iter()
                .any(|argument| matches!(argument, Expr::Starred(_))),
            !call.keywords.iter().any(|keyword| keyword.arg.is_none()),
        );
        overlay_sequence_bindings(&mut bindings, &def.params, call, self);
        let Some(owner) = def.owner.as_deref() else {
            return bindings;
        };
        let invalidated_attrs = match call.func.as_ref() {
            Expr::Attribute(method) => match method.value.as_ref() {
                Expr::Name(receiver) => self.invalidated_instance_attrs(receiver.id.as_str()),
                _ => None,
            },
            _ => None,
        };
        let receiver = match call.func.as_ref() {
            Expr::Attribute(method) => self.instance_value(&method.value),
            _ if callee_written(&call.func).as_deref() == Some(owner) => self.ctor_class(call),
            _ => None,
        };
        if let Some(receiver) = receiver {
            self.bind_receiver_attrs(owner, &receiver, invalidated_attrs.as_ref(), &mut bindings);
        }
        bindings
    }

    fn bind_receiver_attrs(
        &self,
        owner: &str,
        receiver: &SemanticValue,
        invalidated_attrs: Option<&HashSet<String>>,
        bindings: &mut std::collections::HashMap<String, SemanticValue>,
    ) {
        let Some(ObjectIdentity::Class { constructor, .. }) =
            receiver.as_object().map(|object| &object.identity)
        else {
            return;
        };
        let Some(init) = self.defs.iter().find(|candidate| candidate.name == owner) else {
            return;
        };
        let mut init_bindings = self.bind_with_defaults(
            &init.params,
            init.positional_param_count,
            &init.param_defaults,
            constructor,
            true,
            true,
        );
        for value in init_bindings.values_mut() {
            if let Some(resource) = path_object_resource(value) {
                *value = SemanticValue::from(resource);
            }
        }
        let mut module_consts = self.consts.clone();
        for param in &init.params {
            module_consts.remove(param);
        }
        for attr in self.attr_values.iter().filter(|attribute| {
            attribute.owner == owner
                && invalidated_attrs.is_none_or(|attrs| !attrs.contains(&attribute.attr))
        }) {
            let resource = resolve::fs_resource(
                &attr.value,
                &self.imports,
                self.cwd.as_deref(),
                (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
                &self.path_vars,
            );
            let value = SemanticValue::from(
                self.lower_fs_literal(substitute_resource_expr(&resource, &module_consts)),
            );
            let value = substitute_value(&value, &init_bindings, self.nest.limits.value_limits());
            if !matches!(value.kind, SemanticValueKind::Unresolved { .. }) {
                bindings.insert(format!("self.{}", attr.attr), value);
            }
        }
    }

    fn bind_with_defaults(
        &self,
        params: &[String],
        positional_param_count: usize,
        defaults: &[Option<Rc<Expr>>],
        arguments: &[ValueArgument],
        apply_positional_defaults: bool,
        apply_keyword_defaults: bool,
    ) -> std::collections::HashMap<String, SemanticValue> {
        let mut bindings = bind_python_arguments(params, positional_param_count, arguments);
        for (index, (param, default)) in params.iter().zip(defaults).enumerate() {
            if bindings.contains_key(param) {
                continue;
            }
            if !apply_keyword_defaults
                || (!apply_positional_defaults && index < positional_param_count)
            {
                continue;
            }
            let Some(default) = default else { continue };
            let value = self.module_value(default);
            if !matches!(value.kind, SemanticValueKind::Unresolved { .. }) {
                bindings.insert(param.clone(), value);
            }
        }
        bindings
    }

    fn module_value(&self, expr: &Expr) -> SemanticValue {
        let resource = resolve::fs_resource(
            expr,
            &self.imports,
            self.cwd.as_deref(),
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
            &self.path_vars,
        );
        SemanticValue::from(
            self.lower_fs_literal(substitute_resource_expr(&resource, &self.consts)),
        )
    }

    fn is_path_value(&self, value: &Expr) -> bool {
        match value {
            Expr::Name(name) => self.path_vars.contains(name.id.as_str()),
            Expr::Call(call) => {
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "pathlib.Path"
                            | "pathlib.PurePath"
                            | "pathlib.PosixPath"
                            | "pathlib.PurePosixPath"
                            | "pathlib.Path.home"
                            | "pathlib.PosixPath.home"
                            | "pathlib.Path.cwd"
                            | "pathlib.PosixPath.cwd"
                    )
                }) {
                    return true;
                }
                matches!(call.func.as_ref(), Expr::Attribute(method)
                    if matches!(method.attr.as_str(),
                        "resolve" | "absolute" | "expanduser" | "joinpath" | "with_suffix" | "with_name")
                        && self.is_path_value(&method.value))
            }
            Expr::Attribute(attribute)
                if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
                    && self.is_current_path_attr(attribute.attr.as_str()) =>
            {
                true
            }
            Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => {
                self.is_path_value(&attribute.value)
            }
            Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
            {
                let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                    unreachable!();
                };
                self.is_path_value(&attribute.value)
            }
            Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
                self.is_path_value(&binary.left)
            }
            _ => false,
        }
    }

    fn may_be_path_value(&self, value: &Expr) -> bool {
        self.is_path_value(value)
            || matches!(value, Expr::IfExp(conditional)
                if self.may_be_path_value(&conditional.body)
                    || self.may_be_path_value(&conditional.orelse))
    }

    fn is_branch_mixed_path_value(&self, value: &Expr) -> bool {
        match value {
            Expr::Name(name) => self.branch_mixed_path_vars.contains(name.id.as_str()),
            Expr::Call(call) => {
                if self.imports.resolve_callee(&call.func).is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "pathlib.Path"
                            | "pathlib.PurePath"
                            | "pathlib.PosixPath"
                            | "pathlib.PurePosixPath"
                            | "pathlib.Path.home"
                            | "pathlib.PosixPath.home"
                            | "pathlib.Path.cwd"
                            | "pathlib.PosixPath.cwd"
                    )
                }) {
                    return false;
                }
                matches!(call.func.as_ref(), Expr::Attribute(method)
                    if matches!(method.attr.as_str(),
                        "resolve" | "absolute" | "expanduser" | "joinpath" | "with_suffix" | "with_name")
                        && self.is_branch_mixed_path_value(&method.value))
            }
            Expr::Attribute(attribute) if attribute.attr.as_str() == "parent" => {
                self.is_branch_mixed_path_value(&attribute.value)
            }
            Expr::Subscript(subscript) if matches!(subscript.value.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "parents") =>
            {
                let Expr::Attribute(attribute) = subscript.value.as_ref() else {
                    unreachable!();
                };
                self.is_branch_mixed_path_value(&attribute.value)
            }
            Expr::BinOp(binary) if binary.op == ast::Operator::Div => {
                self.is_branch_mixed_path_value(&binary.left)
            }
            _ => false,
        }
    }

    fn is_current_path_attr(&self, attr: &str) -> bool {
        self.current_class.as_ref().is_some_and(|class| {
            self.path_attrs.iter().any(|(owner, name, ty)| {
                owner == class
                    && name == attr
                    && self.imports.resolve_written(ty).is_some_and(|ty| {
                        matches!(
                            ty.as_str(),
                            "pathlib.Path"
                                | "pathlib.PurePath"
                                | "pathlib.PosixPath"
                                | "pathlib.PurePosixPath"
                        )
                    })
            })
        })
    }

    fn is_path_method_receiver(&self, method: &str, receiver: &Expr) -> bool {
        if !is_path_method(method) {
            return false;
        }
        if self.is_branch_mixed_path_value(receiver) && !is_branch_mixed_path_method(method) {
            return false;
        }
        self.is_path_value(receiver)
            || is_path_specific_method(method)
                && matches!(receiver, Expr::Attribute(attribute)
                if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
                    && self.current_class.as_ref().is_some_and(|class| {
                        self.attr_values.iter().any(|value| {
                            value.owner == *class
                                && value.attr == attribute.attr.as_str()
                                && matches!(value.value.as_ref(), Expr::Name(_))
                        })
                    }))
    }

    fn path_iter_resource(&self, value: &Expr) -> Option<ResourceExpr> {
        let value = match value {
            Expr::Call(call)
                if self.imports.resolve_callee(&call.func).as_deref() == Some("sorted") =>
            {
                python_call_argument(call, 0, "iterable")?
            }
            _ => value,
        };
        let Expr::Call(call) = value else { return None };
        let Expr::Attribute(method) = call.func.as_ref() else {
            return None;
        };
        if !matches!(method.attr.as_str(), "glob" | "rglob" | "iterdir")
            || !self.is_path_value(&method.value)
        {
            return None;
        }
        let glob = match method.attr.as_str() {
            "iterdir" => Some("*".to_string()),
            "rglob" => python_call_argument(call, 0, "pattern")
                .and_then(str_literal)
                .map(|pattern| format!("**/{pattern}")),
            _ => python_call_argument(call, 0, "pattern").and_then(str_literal),
        };
        let member = glob
            .map(|glob| ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            })
            .unwrap_or_else(|| unresolved("filesystem"));
        Some(ResourceExpr::Join {
            parts: vec![self.resolve_fs(&method.value), member],
        })
    }

    fn executed_local_call<'c>(&self, value: &'c Expr) -> Option<&'c ast::ExprCall> {
        match value {
            Expr::Await(awaited) => match awaited.value.as_ref() {
                Expr::Call(call) => Some(call),
                _ => None,
            },
            Expr::Call(call)
                if matches!(
                    self.imports.resolve_callee(&call.func).as_deref(),
                    Some("asyncio.run" | "asyncio.wait_for")
                ) =>
            {
                match call.args.first() {
                    Some(Expr::Call(inner)) => Some(inner),
                    _ => None,
                }
            }
            Expr::Call(call) => {
                let name = self.local_callee(&call.func)?;
                let deferred = self
                    .defs
                    .iter()
                    .find(|def| def.name == name)
                    .is_some_and(|def| def.is_async || def.is_generator);
                (!deferred).then_some(call)
            }
            _ => None,
        }
    }

    /// The function's return value as a resource expression in terms of its
    /// parameters, when every `return` resolves to the same usable resource.
    /// Divergent, absent, or unresolvable returns yield None.
    fn infer_return(&self, body: &[Stmt]) -> Option<ResourceExpr> {
        let mut values = Vec::new();
        let mut saw_bare = false;
        collect_returns(body, &mut values, &mut saw_bare);
        // A valueless return means the function does not always return a path.
        if saw_bare || values.is_empty() {
            return None;
        }
        let mut resolved: Vec<ResourceExpr> = values
            .iter()
            .map(|value| {
                let resolved = self.resolve_fs(value);
                if is_resolvable(&resolved) {
                    resolved
                } else {
                    // Filesystem sink typing widens a join made only of parameters.
                    // Return summaries retain those parts for caller substitution.
                    self.source_string_resource(value)
                        .map(|resource| substitute_resource_expr(&resource, &self.var_scope))
                        .unwrap_or(resolved)
                }
            })
            .collect();
        let first = resolved.remove(0);
        if !is_resolvable(&first) || resolved.iter().any(|r| *r != first) {
            return None;
        }
        Some(first)
    }

    /// Apply a called function's summary at a call site: resolve the actual
    /// arguments in the caller's scope, bind them to the callee's parameters,
    /// and emit (or, in capture mode, collect) the specialized effects.
    fn apply_local(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        self.ensure_summary(name);
        let mut bindings = self.call_bindings(name, call);
        if let Expr::Call(producer_call) = call.func.as_ref()
            && let Some(producer) = self.local_callee(&producer_call.func)
        {
            let mut captures = self.call_bindings(&producer, producer_call);
            captures.extend(bindings);
            bindings = captures;
        }
        self.apply_summary(name, &bindings, span);
        let wrappers: Vec<_> = self
            .defs
            .iter()
            .find(|def| def.name == name)
            .into_iter()
            .flat_map(|def| &def.decorators)
            .filter(|decorator| !self.decorator_is_transparent(decorator))
            .filter_map(|decorator| {
                self.defs
                    .iter()
                    .find(|def| def.name == decorator.trim_end_matches("()"))
            })
            .filter_map(|decorator| self.returned_inner(decorator))
            .filter(|(wrapper, _, _)| !wrapper.is_async && !wrapper.is_generator)
            .map(|(wrapper, _, _)| wrapper.name.clone())
            .collect();
        for wrapper in wrappers {
            // An opaque wrapper need not preserve the decorated signature.
            self.apply_local_arguments(&wrapper, &[], span);
        }
        let Some(def) = self.defs.iter().find(|def| def.name == name) else {
            return;
        };
        let writes = def.parameter_attr_writes.clone();
        let params = def.params.clone();
        let positional_param_count = def.positional_param_count;
        let caller_params = self
            .current_function
            .as_deref()
            .and_then(|name| self.defs.iter().find(|def| def.name == name))
            .map(|def| def.params.clone())
            .unwrap_or_default();
        for (param, attr) in writes {
            let Some(index) = params.iter().position(|candidate| candidate == &param) else {
                continue;
            };
            let argument = if index < positional_param_count {
                python_call_argument(call, index, &param)
            } else {
                call.keywords
                    .iter()
                    .find(|keyword| {
                        keyword.arg.as_ref().map(|name| name.as_str()) == Some(param.as_str())
                    })
                    .map(|keyword| &keyword.value)
            };
            if let Some(Expr::Name(receiver)) = argument {
                self.track_instance_attr_rebinding(receiver.id.as_str(), &attr);
                let propagated = (receiver.id.to_string(), attr);
                if caller_params.contains(&propagated.0)
                    && let Some(capture) = self.capture.as_mut()
                    && !capture.parameter_attr_writes.contains(&propagated)
                {
                    capture.parameter_attr_writes.push(propagated);
                }
            }
        }
    }

    fn apply_local_root(&mut self, name: &str) {
        let span = self
            .defs
            .iter()
            .find(|def| def.name == name)
            .and_then(|def| def.body.first())
            .map(Ranged::range)
            .unwrap_or_default();
        self.apply_local_arguments(name, &[], span);
    }

    fn apply_local_arguments(&mut self, name: &str, arguments: &[ValueArgument], span: TextRange) {
        self.ensure_summary(name);
        let Some(summary) = self.summaries.get(name) else {
            return;
        };
        let bindings = bind_arguments(&summary.params, arguments);
        self.apply_summary(name, &bindings, span);
    }

    fn apply_context_method(
        &mut self,
        class: &str,
        method: &str,
        receiver: &SemanticValue,
        span: TextRange,
    ) -> Option<ResourceExpr> {
        let name = format!("{class}.{method}");
        self.ensure_summary(&name);
        let def = self.defs.iter().find(|def| def.name == name)?;
        let mut bindings = self.bind_with_defaults(
            &def.params,
            def.positional_param_count,
            &def.param_defaults,
            &[],
            true,
            true,
        );
        self.bind_receiver_attrs(class, receiver, None, &mut bindings);
        let returned = self
            .summaries
            .get(&name)
            .and_then(|summary| summary.returns.as_ref())
            .map(|returns| {
                substitute_value(returns, &bindings, self.nest.limits.value_limits())
                    .lower_resource()
            });
        self.apply_summary(&name, &bindings, span);
        returned
    }

    fn apply_summary(
        &mut self,
        name: &str,
        bindings: &std::collections::HashMap<String, SemanticValue>,
        span: TextRange,
    ) {
        self.ensure_summary(name);
        self.invalidate_shared_vars();
        let Some((summary, spawns)) = self
            .summaries
            .get(name)
            .cloned()
            .map(|summary| {
                let spawns = self.spawn_summaries.get(name).cloned().unwrap_or_default();
                (summary, spawns)
            })
            .or_else(|| self.imported_summary(name))
        else {
            return;
        };
        if self.capture.is_none() {
            self.entered_callables = true;
        }
        let node = self.span_node(span);
        // Slots this call site's copies landed in, so the callee's recorded
        // transfer pairings survive substitution and nesting.
        let mut slots: Vec<Option<u32>> = Vec::with_capacity(summary.effects.len());
        for (index, effect) in summary.effects.iter().enumerate() {
            let mut specialized = effect.clone();
            if let Some(condition) = &mut specialized.condition {
                condition.rebind(
                    &self
                        .condition_source
                        .call_site(&(u32::from(span.start()), u32::from(span.end()))),
                );
            }
            specialized.condition = effinterp_proto::Condition::compose(
                specialized.condition.iter().chain(
                    self.builder
                        .condition_since(self.capture_condition_depth)
                        .iter(),
                ),
            );
            let mut visited = 0;
            let value = crate::substitute_value_counted(
                &SemanticValue::from(&effect.resource),
                bindings,
                self.nest.limits.value_limits(),
                &mut visited,
            );
            if !self.charge_steps(visited, (u32::from(span.start()), u32::from(span.end()))) {
                self.node_budget_hit = true;
                return;
            }
            // Keep network joins neutral while one function summary is folded
            // into another; the outer call site supplies the final URL anchor.
            if self.capture.is_some()
                && self.current_function.is_some()
                && specialized.operation.domain() == "network"
                && matches!(&value.kind, SemanticValueKind::Join(_))
            {
                specialized.resource = value.lower_resource();
            } else {
                crate::lower_effect_value(&mut specialized, &value);
            }
            specialized.provenance = vec![node];
            if self
                .capture
                .as_ref()
                .is_some_and(|cap| cap.effects.len() < MAX_SUMMARY_EFFECTS)
                && !crate::nest::charge_analysis_bytes(
                    self.builder,
                    self.nest.budget,
                    crate::limits::retained_bytes(&specialized),
                    Some((span.start().into(), span.end().into())),
                )
            {
                return;
            }
            match self.capture.as_mut() {
                Some(cap) if cap.effects.len() < MAX_SUMMARY_EFFECTS => {
                    cap.effects.push(specialized);
                    cap.effect_models.push(
                        summary
                            .effect_models
                            .get(index)
                            .cloned()
                            .unwrap_or_default(),
                    );
                    slots.push(Some(cap.effects.len() as u32 - 1));
                }
                Some(_) => slots.push(None),
                None => {
                    // The call site is where the host environment applies, as
                    // for an effect emitted directly: `$HOME` passed into a
                    // function resolves exactly as `~` written at the call.
                    // A relative path passed in likewise names a file under
                    // the call site's cwd.
                    if specialized.operation.domain() == "filesystem" {
                        if let Some(cwd) = &self.cwd
                            && fs_resource_uses_cwd(&specialized.resource)
                        {
                            let cwd = std::collections::HashMap::from([(
                                "cwd".to_string(),
                                resolve_fs_path(cwd, None),
                            )]);
                            specialized.resource = normalize_resource(
                                substitute_resource_expr(&specialized.resource, &cwd),
                                PathPlatform::Posix,
                            );
                            specialized.provenance.extend(self.cwd_node);
                        }
                        specialized.resource = self.resolve_host_path(
                            specialized.resource.clone(),
                            &mut specialized.provenance,
                        );
                    }
                    if specialized.operation.as_str() == "environment.write" {
                        self.environment_rewritten = true;
                    }
                    for model in summary.effect_models.get(index).into_iter().flatten() {
                        let application = self.builder.node(
                            ProvenanceKind::ModelApplication {
                                model: model.clone(),
                            },
                            &[node],
                        );
                        specialized.provenance.push(application);
                    }
                    slots.push(self.builder.effect(specialized));
                }
            }
        }
        for binding in &summary.transfers {
            let (Some(Some(source)), Some(Some(destination))) = (
                slots.get(binding.source as usize),
                slots.get(binding.destination as usize),
            ) else {
                continue;
            };
            self.record_transfer(Some(*source), Some(*destination));
        }
        // What the callee prints reaches this program's stdout when this call
        // runs and the callee reaches its print.
        for (printed, condition) in self.summary_stdout.get(name).cloned().unwrap_or_default() {
            let printed = printed
                .iter()
                .filter_map(|slot| slots.get(*slot as usize).copied().flatten())
                .collect::<Vec<_>>();
            if printed.is_empty() {
                continue;
            }
            let mut condition = condition;
            if let Some(condition) = &mut condition {
                condition.rebind(
                    &self
                        .condition_source
                        .call_site(&(u32::from(span.start()), u32::from(span.end()))),
                );
            }
            let condition = effinterp_proto::Condition::compose(
                condition.iter().chain(
                    self.builder
                        .condition_since(self.capture_condition_depth)
                        .iter(),
                ),
            );
            match self.capture.as_mut() {
                Some(capture) => capture.stdout.push((printed, condition)),
                None => {
                    let execution = self.builder.current_execution();
                    crate::flow::effects_to_stdout(
                        self.builder,
                        execution,
                        printed,
                        effinterp_proto::CausalAssurance::Conservative,
                        condition,
                        vec![node],
                    );
                }
            }
        }
        // A summary still converging in a recursive group proves nothing yet.
        let application = match self.summary_requirements.get(name) {
            Some(requirements)
                if !self.summary_in_progress.contains(name)
                    && !self.summary_cycles.contains(name) =>
            {
                SiteFacts::call(requirements, |fact| match fact {
                    ControlFact::Effect(index) => slots
                        .get(index as usize)
                        .copied()
                        .flatten()
                        .map(ControlFact::Effect),
                    ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
                })
            }
            _ => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
        let source_spans = self.summary_spans.get(name).cloned().unwrap_or_default();
        for boundary in &summary.boundaries {
            if self.capture.as_ref().is_some_and(|cap| {
                cap.boundaries.iter().any(|old| {
                    old.reason == boundary.reason
                        && old.limit == boundary.limit
                        && old.callee == boundary.callee
                        && old.detail == boundary.detail
                })
            }) {
                continue;
            }
            let mut b = boundary.clone();
            if b.reason == BoundaryReason::CROSS_MODULE
                && let Some(resource) = &b.affected_resource
            {
                let specialized = crate::substitute_value(
                    &SemanticValue::from(resource),
                    bindings,
                    self.nest.limits.value_limits(),
                )
                .lower_resource();
                if specialized != *resource
                    && let Some(path) = python_plugin_path_pattern(&specialized)
                {
                    b.detail = Some(format!(
                        "{}; recovered path {path}",
                        b.detail
                            .as_deref()
                            .unwrap_or_default()
                            .split("; recovered path ")
                            .next()
                            .unwrap_or_default()
                    ));
                }
                b.affected_resource = Some(specialized);
            }
            b.provenance = vec![node];
            for reference in &boundary.provenance {
                if let Some(span) = source_spans.get(reference.0 as usize) {
                    b.provenance.push(self.span_node(*span));
                }
            }
            self.out_boundary(b);
        }
        for (domain, level) in &summary.coverage {
            self.out_coverage(domain.clone(), *level);
        }
        for spawn in spawns {
            self.apply_deferred_spawn(spawn, bindings, node, span);
        }
    }

    /// Record a call that resolved through a tracked import but matched no
    /// model arm or the operand safety check. It remains a loud boundary:
    /// module provenance alone never
    /// implies effect coverage. A callee whose module is not recognized as
    /// external stays the internal `unresolved_call` boundary across every
    /// domain, since nothing bounds what it can reach. Deduplicated by callee
    /// and source occurrence.
    fn unresolved_call(
        &mut self,
        name: &str,
        arity: Option<usize>,
        span: TextRange,
        operands_safe: bool,
    ) -> CallControl {
        let (reason, class, domains) = match crate::external::classify_python_call(name, arity) {
            Some(crate::external::ExternalCall::Unmodeled(domains)) => (
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                if operands_safe {
                    domains
                } else {
                    crate::external::ALL_DOMAINS
                },
            ),
            Some(_) => (
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                crate::external::ALL_DOMAINS,
            ),
            None => (
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
            ),
        };
        let callee = python_callee_reference(name).or_else(|| {
            resolve::is_builtin(name).then(|| CalleeReference {
                module: "builtins".into(),
                symbol: name.into(),
            })
        });
        self.emit_unresolved_call(name, reason, class, domains, span, callee);
        CallControl::Opaque
    }

    fn emit_unresolved_call(
        &mut self,
        name: &str,
        reason: BoundaryReason,
        class: BoundaryClass,
        domains: crate::external::Domains,
        span: TextRange,
        callee: Option<CalleeReference>,
    ) {
        self.invalidate_shared_vars();
        if !self.reported_unresolved.insert((name.to_string(), span)) {
            return;
        }
        let node = self.span_node(span);
        for domain in domains {
            self.out_coverage(Domain::new(*domain), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee,
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call to unmodeled {name}")),
        });
    }
    fn ipython_sentinel(&mut self, statement: &ast::StmtExpr) -> bool {
        let start = u32::from(statement.range.start());
        let Some(actions) = self
            .ipython
            .as_mut()
            .and_then(|state| state.actions.remove(&start))
        else {
            return false;
        };
        for action in actions {
            self.ipython_action(action, statement.range);
        }
        true
    }

    fn ipython_action(&mut self, action: ipython::Action, span: TextRange) {
        match action {
            ipython::Action::Shell { command, capture } => {
                self.ipython_shell(&command, capture, span)
            }
            ipython::Action::LineMagic { name, arguments } => {
                self.ipython_line_magic(&name, &arguments, span)
            }
            ipython::Action::CellMagic {
                name,
                arguments,
                body,
                body_offset,
            } => self.ipython_cell_magic(&name, &arguments, &body, body_offset, span),
        }
    }

    fn ipython_call(&mut self, call: &ast::ExprCall) -> bool {
        if !self
            .ipython
            .as_ref()
            .is_some_and(|state| state.get_ipython_owned)
        {
            return false;
        }
        if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "get_ipython")
            && call.args.is_empty()
            && call.keywords.is_empty()
        {
            return true;
        }
        let Expr::Attribute(method) = call.func.as_ref() else {
            return false;
        };
        let Expr::Call(receiver) = method.value.as_ref() else {
            return false;
        };
        if !matches!(receiver.func.as_ref(), Expr::Name(name) if name.id.as_str() == "get_ipython")
            || !receiver.args.is_empty()
            || !receiver.keywords.is_empty()
            || !call.keywords.is_empty()
        {
            return false;
        }
        match method.attr.as_str() {
            "system" | "getoutput" if call.args.len() == 1 => {
                let command = self
                    .ipython_expr_text(&call.args[0])
                    .unwrap_or_else(|| ipython_unresolved_expression(&call.args[0]));
                self.ipython_shell(&command, method.attr.as_str() == "getoutput", call.range);
                true
            }
            "run_line_magic" if call.args.len() == 2 => {
                let Some(name) = self.ipython_expr_text(&call.args[0]) else {
                    let node = self.span_node(call.range);
                    self.ipython_boundary(
                        BoundaryReason::UNMODELED_DYNAMIC,
                        BoundaryClass::Unresolved,
                        "IPython line magic name is unresolved".to_string(),
                        node,
                    );
                    return true;
                };
                let arguments = self
                    .ipython_expr_text(&call.args[1])
                    .unwrap_or_else(|| ipython_unresolved_expression(&call.args[1]));
                self.ipython_line_magic(&name, &arguments, call.range);
                true
            }
            "run_cell_magic" if call.args.len() == 3 => {
                let Some(name) = self.ipython_expr_text(&call.args[0]) else {
                    let node = self.span_node(call.range);
                    self.ipython_boundary(
                        BoundaryReason::UNMODELED_DYNAMIC,
                        BoundaryClass::Unresolved,
                        "IPython cell magic name is unresolved".to_string(),
                        node,
                    );
                    return true;
                };
                let arguments = self
                    .ipython_expr_text(&call.args[1])
                    .unwrap_or_else(|| ipython_unresolved_expression(&call.args[1]));
                let Some(body) = self.ipython_expr_text(&call.args[2]) else {
                    let node = self.span_node(call.range);
                    self.ipython_boundary(
                        BoundaryReason::UNMODELED_DYNAMIC,
                        BoundaryClass::Unresolved,
                        format!("IPython cell magic %{name} body is unresolved"),
                        node,
                    );
                    return true;
                };
                self.ipython_cell_magic(&name, &arguments, &body, 0, call.range);
                true
            }
            _ => false,
        }
    }

    fn ipython_invalidate_getter_target(&mut self, target: &Expr) {
        if ipython_getter_target(target)
            && let Some(state) = self.ipython.as_mut()
        {
            state.get_ipython_owned = false;
        }
    }

    fn ipython_track_assignment(&mut self, names: &[String], value: &Expr) {
        if self.ipython.is_none() || self.capture.is_some() || self.current_function.is_some() {
            return;
        }
        let resource = self.ipython_expr_resource(value);
        let Some(state) = self.ipython.as_mut() else {
            return;
        };
        for name in names {
            if let Some(resource) = &resource {
                state.bindings.insert(name.clone(), resource.clone());
            } else {
                state.bindings.remove(name);
            }
        }
    }

    fn ipython_expr_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        if let Some(value) = ipython_constant_text(expr) {
            return Some(ResourceExpr::Literal { value });
        }
        if let Expr::Name(name) = expr {
            return self
                .ipython
                .as_ref()?
                .bindings
                .get(name.id.as_str())
                .cloned();
        }
        let resource = resolve::concatenated_part_resource(
            expr,
            &self.imports,
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
        )?;
        let bindings = &self.ipython.as_ref()?.bindings;
        let resource = substitute_resource_expr(&resource, bindings);
        ipython_flatten_literal(&resource).map(|value| ResourceExpr::Literal { value })
    }

    fn ipython_expr_text(&self, expr: &Expr) -> Option<String> {
        self.ipython_expr_resource(expr)
            .as_ref()
            .and_then(ipython_flatten_literal)
    }

    fn ipython_shell(&mut self, command: &str, _capture: bool, span: TextRange) {
        let node = self.span_node(span);
        let (command, unresolved) = self.ipython_interpolate(command);
        self.ipython_nest_subject(
            Subject::Shell {
                source: command,
                cwd: self.cwd.clone(),
                context: Default::default(),
            },
            node,
            0,
        );
        for name in unresolved {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                format!("IPython unresolved word: {name}"),
                node,
            );
        }
    }

    fn ipython_interpolate(&self, command: &str) -> (String, Vec<String>) {
        let bindings = self
            .ipython
            .as_ref()
            .map(|state| &state.bindings)
            .expect("IPython action has state");
        let bytes = command.as_bytes();
        let mut output = String::with_capacity(command.len());
        let mut unresolved = Vec::new();
        let mut offset = 0;
        let mut single_quoted = false;
        while offset < bytes.len() {
            if bytes[offset] == b'\'' {
                single_quoted = !single_quoted;
                output.push('\'');
                offset += 1;
                continue;
            }
            if bytes[offset] == b'{'
                && bytes.get(offset + 1) != Some(&b'{')
                && let Some(end) = bytes[offset + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|end| offset + end + 1)
            {
                let expression = &command[offset + 1..end];
                if let Ok(expr) = ast::Expr::parse(expression, "<ipython-interpolation>")
                    && let Some(value) = self.ipython_expr_text(&expr)
                {
                    output.push_str(&value);
                } else {
                    let name = interpolation_name(expression);
                    output.push_str("${");
                    output.push_str(&name);
                    output.push('}');
                    unresolved.push(expression.to_string());
                }
                offset = end + 1;
                continue;
            }
            if bytes[offset] == b'$' && !single_quoted {
                if bytes.get(offset + 1) == Some(&b'$') {
                    output.push('$');
                    offset += 2;
                    continue;
                }
                let (start, end, consumed) = if bytes.get(offset + 1) == Some(&b'{') {
                    let start = offset + 2;
                    let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == b'}')
                    else {
                        output.push('$');
                        offset += 1;
                        continue;
                    };
                    let end = start + relative_end;
                    (start, end, end + 1)
                } else {
                    let start = offset + 1;
                    let mut end = start;
                    while bytes
                        .get(end)
                        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    {
                        end += 1;
                    }
                    if end == start {
                        output.push('$');
                        offset += 1;
                        continue;
                    }
                    (start, end, end)
                };
                let name = &command[start..end];
                if let Some(value) = bindings.get(name).and_then(ipython_flatten_literal) {
                    output.push_str(&value);
                } else {
                    output.push_str("${");
                    output.push_str(name);
                    output.push('}');
                    unresolved.push(name.to_string());
                }
                offset = consumed;
                continue;
            }
            let character = command[offset..]
                .chars()
                .next()
                .expect("character boundary");
            output.push(character);
            offset += character.len_utf8();
        }
        (output, unresolved)
    }

    fn ipython_line_magic(&mut self, name: &str, arguments: &str, span: TextRange) {
        match name {
            "system" | "sx" | "sc" => self.ipython_shell(arguments, name != "system", span),
            "cd" => self.ipython_change_directory(arguments, span),
            "run" => self.ipython_run(arguments, span),
            "env" => self.ipython_set_environment(arguments, span),
            "pip" | "conda" => self.ipython_package_manager(name, arguments, span),
            "time" | "timeit" if arguments.starts_with("!!") => {
                self.ipython_shell(&arguments[2..], true, span)
            }
            "time" | "timeit" if arguments.starts_with('!') => {
                self.ipython_shell(&arguments[1..], false, span)
            }
            "time" | "timeit" if !arguments.is_empty() => {
                let node = self.span_node(span);
                self.ipython_nest_source("python", None, arguments, 0, node);
            }
            name if ipython_noop_magic(name) => {}
            _ => {
                let node = self.span_node(span);
                self.ipython_boundary(
                    BoundaryReason::UNKNOWN_IPYTHON_MAGIC,
                    BoundaryClass::Unsupported,
                    format!("unrecognized IPython magic %{name}"),
                    node,
                );
            }
        }
    }

    fn ipython_cell_magic(
        &mut self,
        name: &str,
        arguments: &str,
        body: &str,
        body_offset: usize,
        span: TextRange,
    ) {
        let node = self.span_node(span);
        match name {
            "bash" | "sh" => {
                self.ipython_magic_options(name, arguments, node);
                self.ipython_nest_subject(
                    Subject::Shell {
                        source: body.to_string(),
                        cwd: self.cwd.clone(),
                        context: Default::default(),
                    },
                    node,
                    body_offset,
                );
            }
            "script" => {
                let words = ipython_split_words(arguments);
                let Some(interpreter) = words.first() else {
                    self.ipython_boundary(
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unsupported,
                        "IPython %%script has no interpreter".to_string(),
                        node,
                    );
                    return;
                };
                self.ipython_magic_options(interpreter, &words[1..].join(" "), node);
                if matches!(interpreter.as_str(), "bash" | "sh") {
                    self.ipython_nest_subject(
                        Subject::Shell {
                            source: body.to_string(),
                            cwd: self.cwd.clone(),
                            context: Default::default(),
                        },
                        node,
                        body_offset,
                    );
                } else if let Some((language, dialect)) = ipython_script_language(interpreter) {
                    self.ipython_nest_source(language, dialect, body, body_offset, node);
                } else {
                    self.ipython_boundary(
                        BoundaryReason::UNSUPPORTED_SOURCE,
                        BoundaryClass::Unsupported,
                        format!("unmodeled IPython %%script interpreter {interpreter}"),
                        node,
                    );
                }
            }
            "writefile" => {
                let words = ipython_split_words(arguments);
                let mut path = None;
                for word in words {
                    if word == "-a" || word == "--append" {
                        continue;
                    }
                    if word.starts_with('-') {
                        self.ipython_boundary(
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unsupported,
                            format!("unknown IPython %%writefile option {word}"),
                            node,
                        );
                    } else if path.is_none() {
                        path = Some(word);
                    }
                }
                if let Some(path) = path {
                    let resource = resolve_fs_path(&path, self.cwd.as_deref());
                    self.emit("filesystem.write", resource, &[], node);
                } else {
                    self.ipython_boundary(
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unsupported,
                        "IPython %%writefile has no path".to_string(),
                        node,
                    );
                }
            }
            "time" | "timeit" | "capture" => self.ipython_nest_source(
                "python",
                Some(effinterp_proto::SourceDialect::Ipython),
                body,
                body_offset,
                node,
            ),
            name if ipython_noop_magic(name) => {}
            _ => self.ipython_boundary(
                BoundaryReason::UNKNOWN_IPYTHON_MAGIC,
                BoundaryClass::Unsupported,
                format!("unrecognized IPython cell magic %%{name}"),
                node,
            ),
        }
    }

    fn ipython_magic_options(&mut self, magic: &str, arguments: &str, node: ProvenanceRef) {
        for option in ipython_split_words(arguments) {
            if ipython_known_magic_option(&option) {
                continue;
            }
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                format!("unknown IPython %%{magic} option {option}"),
                node,
            );
        }
    }

    fn ipython_change_directory(&mut self, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let (directory, unresolved) = self.ipython_interpolate(arguments.trim());
        if directory.is_empty() || !unresolved.is_empty() {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                "IPython %cd directory is unresolved".to_string(),
                node,
            );
            self.cwd = None;
            self.cwd_node = Some(node);
            return;
        }
        let resource = resolve_fs_path(&directory, self.cwd.as_deref());
        self.cwd = resource_path_string(&resource);
        self.cwd_node = Some(node);
    }

    fn ipython_set_environment(&mut self, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let Some((name, value)) = arguments.split_once('=') else {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                "IPython %env requires NAME=value".to_string(),
                node,
            );
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                "IPython %env has an empty name".to_string(),
                node,
            );
            return;
        }
        let (value, unresolved_names) = self.ipython_interpolate(value.trim());
        let resource = if unresolved_names.is_empty() {
            ResourceExpr::Literal { value }
        } else {
            unresolved("value")
        };
        if let Some(state) = self.ipython.as_mut() {
            state
                .environment
                .insert(name.to_string(), Some(resource.clone()));
            state.environment_nodes.insert(name.to_string(), node);
        }
        self.emit(
            "environment.write",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            },
            &[],
            node,
        );
    }

    fn ipython_run(&mut self, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let mut words = ipython_split_words(arguments);
        while words.first().is_some_and(|word| ipython_run_option(word)) {
            words.remove(0);
        }
        if words.is_empty() {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                "IPython %run has no script".to_string(),
                node,
            );
            return;
        }
        words.insert(0, "python".to_string());
        self.ipython_exec(words, node);
    }

    fn ipython_package_manager(&mut self, name: &str, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let mut words = ipython_split_words(arguments);
        words.insert(0, name.to_string());
        self.ipython_exec(words, node);
    }

    fn ipython_exec(&mut self, raw_words: Vec<String>, node: ProvenanceRef) {
        let mut words = Vec::with_capacity(raw_words.len());
        let mut resources = Vec::with_capacity(raw_words.len());
        for raw in raw_words {
            let (value, unresolved_names) = self.ipython_interpolate(&raw);
            if unresolved_names.is_empty() {
                let word = Word::literal(value.clone());
                words.push(word);
                resources.push(ResourceExpr::Literal { value });
            } else {
                words.push(Word::new(vec![WordPart::Unknown]));
                resources.push(unresolved("process"));
                for name in unresolved_names {
                    self.ipython_boundary(
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unresolved,
                        format!("IPython unresolved word: {name}"),
                        node,
                    );
                }
            }
        }
        let cwd_resource = self.ipython_cwd_resource();
        let mut transition = Transition::exec(resources, words)
            .exec_cwd(self.cwd.as_deref())
            .runtime_cwd(self.cwd.as_deref())
            .cwd(cwd_resource, self.cwd_node)
            .kind(ExecutionEdgeKind::Launch);
        transition = self.ipython_environment(transition);
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    fn ipython_nest_source(
        &mut self,
        language: &str,
        dialect: Option<effinterp_proto::SourceDialect>,
        source: &str,
        source_offset: usize,
        node: ProvenanceRef,
    ) {
        self.ipython_nest_subject(
            Subject::Source {
                language: language.to_string(),
                dialect,
                source: source.to_string(),
                cwd: self.cwd.clone(),
                context: Default::default(),
            },
            node,
            source_offset,
        );
    }

    fn ipython_nest_subject(
        &mut self,
        subject: Subject,
        node: ProvenanceRef,
        source_offset: usize,
    ) {
        if self.capture.is_some() {
            self.nest(subject, node, self.ipython_cwd_resource(), self.cwd_node);
            return;
        }
        let source_cwd = self.nest.current_source_cwd();
        let cwd = self.cwd.clone();
        let mut transition = Transition::file(subject)
            .source_cwd(source_cwd.as_deref())
            .runtime_cwd(cwd.as_deref())
            .cwd(self.ipython_cwd_resource(), self.cwd_node)
            .source_span_offset(source_offset);
        transition = self.ipython_environment(transition);
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    fn ipython_environment(&self, transition: Transition) -> Transition {
        let Some(state) = &self.ipython else {
            return transition;
        };
        transition.environment(
            state.environment.clone(),
            state.environment_nodes.clone(),
            Default::default(),
        )
    }

    fn ipython_cwd_resource(&self) -> Option<ResourceExpr> {
        self.cwd.as_ref().map(|cwd| ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: cwd.clone() },
        })
    }

    fn ipython_boundary(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: String,
        node: ProvenanceRef,
    ) {
        for domain in DOMAINS {
            self.out_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail),
        });
    }

    // --- emission helpers ---

    /// A provenance node for a source span. During summary capture the range
    /// is retained for model matching, while plan provenance is replaced at
    /// each call site.
    fn span_node(&mut self, range: TextRange) -> ProvenanceRef {
        if let Some(capture) = self.capture.as_mut() {
            if let Some(index) = capture.source_spans.iter().position(|span| *span == range) {
                return ProvenanceRef(index as u32);
            }
            let reference = ProvenanceRef(capture.source_spans.len() as u32);
            capture.source_spans.push(range);
            return reference;
        }
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: u32::from(range.start()),
                end: u32::from(range.end()),
            },
            self.scope.as_slice(),
        )
    }

    /// Replace an environment reference with the value the host supplied for
    /// it, so a path built from `$HOME` or `~` resolves as precisely as the
    /// same path written out. Every substituted name contributes the
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

    /// A filesystem resource with the host environment applied. A path read
    /// whole from the environment (`~` alone) lowers exactly as the same path
    /// written out, so it names the file it reaches rather than a string.
    fn resolve_host_path(
        &mut self,
        mut resource: ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) -> ResourceExpr {
        let before = provenance.len();
        self.resolve_host_environment(&mut resource, provenance);
        if provenance.len() == before {
            return resource;
        }
        match normalize_resource(resource, PathPlatform::Posix) {
            literal @ ResourceExpr::Literal { .. } => self.lower_fs_literal(literal),
            resource => resource,
        }
    }

    /// The effective value of one environment name, preferring an override the
    /// enclosing execution established over the value the host supplied.
    fn host_environment_value(&self, name: &str) -> Option<ResourceExpr> {
        if let Some(value) = self
            .ipython
            .as_ref()
            .and_then(|state| state.environment.get(name))
        {
            return value.clone();
        }
        if self.environment_rewritten
            || self.imports.namespace_mutated
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

    fn emit(
        &mut self,
        operation: &str,
        resource: ResourceExpr,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) -> Option<u32> {
        let attributes = attrs
            .iter()
            .filter(|(_, on)| *on)
            .map(|(k, _)| (k.to_string(), AttrValue::Bool(true)))
            .collect();
        self.emit_request(operation, resource, attributes, node, None)
    }

    /// `emit` for an API whose `model` certifies the request exactly. The
    /// attributes are fixed here because a later rewrite discards that proof.
    fn emit_request(
        &mut self,
        operation: &str,
        resource: ResourceExpr,
        attributes: std::collections::BTreeMap<String, AttrValue>,
        node: ProvenanceRef,
        model: Option<&str>,
    ) -> Option<u32> {
        let mut provenance = vec![node];
        if let Some(model) = model
            && self.capture.is_none()
        {
            provenance.push(self.builder.node(
                ProvenanceKind::ModelApplication {
                    model: model.to_string(),
                },
                &[node],
            ));
        }
        let mut resource = resource;
        if operation.starts_with("filesystem.") {
            if fs_resource_uses_cwd(&resource) {
                provenance.extend(self.cwd_node);
            }
            resource = self.resolve_host_path(resource, &mut provenance);
        }
        if operation == "environment.write" {
            self.environment_rewritten = true;
        }
        let effect = Effect {
            request_assurance: match model {
                Some(_) => effinterp_proto::RequestAssurance::Exact,
                None => effinterp_proto::RequestAssurance::Conservative,
            },
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: self.builder.condition_since(self.capture_condition_depth),
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        };
        if self
            .capture
            .as_ref()
            .is_some_and(|cap| cap.effects.len() < MAX_SUMMARY_EFFECTS)
            && !crate::nest::charge_analysis_bytes(
                self.builder,
                self.nest.budget,
                crate::limits::retained_bytes(&effect),
                self.callable_span(),
            )
        {
            return None;
        }
        match self.capture.as_mut() {
            Some(cap) => {
                if cap.effects.len() < MAX_SUMMARY_EFFECTS {
                    cap.effects.push(effect);
                    cap.effect_models
                        .push(model.into_iter().map(str::to_string).collect());
                    Some(cap.effects.len() as u32 - 1)
                } else {
                    None
                }
            }
            None => self.builder.effect(effect),
        }
    }

    /// Record that `source` is the source side of one modeled transfer whose
    /// destination side is `destination`, in whichever effect list received
    /// them.
    fn record_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        let (Some(source), Some(destination)) = (source, destination) else {
            return;
        };
        let binding = TransferBinding::new(source, destination);
        match self.capture.as_mut() {
            Some(cap) => {
                if !cap.transfers.contains(&binding) {
                    cap.transfers.push(binding);
                }
            }
            None => self.builder.transfer_binding(binding),
        }
    }

    fn callable_span(&self) -> Option<(u32, u32)> {
        let name = self.current_function.as_ref()?;
        let span = self
            .defs
            .iter()
            .find(|def| &def.name == name)?
            .body
            .first()?
            .range();
        Some((span.start().into(), span.end().into()))
    }

    /// Emit a boundary to the plan, or collect it into the active summary.
    fn out_boundary(&mut self, boundary: Boundary) {
        let span = self.callable_span();
        match self.capture.as_mut() {
            Some(cap) => {
                if cap.boundaries.len() >= MAX_SUMMARY_BOUNDARIES {
                    if boundary.class != BoundaryClass::Limit {
                        return;
                    }
                    // Keep the callable's refusal when its opaque-call buffer is full.
                    cap.boundaries.pop();
                }
                if crate::nest::charge_analysis_bytes(
                    self.builder,
                    self.nest.budget,
                    crate::limits::boundary_retained_bytes(&boundary),
                    span,
                ) {
                    cap.boundaries.push(boundary);
                }
            }
            None => {
                self.builder.boundary(boundary);
            }
        }
    }

    /// Declare coverage on the plan, or record it on the active summary.
    fn out_coverage(&mut self, domain: Domain, level: CoverageLevel) {
        match self.capture.as_mut() {
            Some(cap) => {
                if !cap.coverage.contains(&(domain.clone(), level)) {
                    cap.coverage.push((domain, level));
                }
            }
            None => self.builder.declare_coverage(domain, level),
        }
    }

    fn emit_process_unresolved(&mut self, node: ProvenanceRef) {
        self.emit(
            "process.exec",
            ResourceExpr::Unresolved {
                family: ResourceFamily::new("process"),
            },
            &[],
            node,
        );
    }

    fn nest(
        &mut self,
        subject: Subject,
        node: ProvenanceRef,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
    ) {
        if self.capture.is_some() {
            let spawn = match &subject {
                Subject::Exec { argv, .. } => DeferredSpawn::Exec {
                    argv: DeferredArgv::Words(
                        argv.iter()
                            .map(|value| match value.as_str() {
                                "?" => unresolved("process"),
                                _ => ResourceExpr::Literal {
                                    value: value.clone(),
                                },
                            })
                            .collect(),
                    ),
                    cwd: cwd_resource.clone(),
                    cwd_uses_ambient: cwd_node.is_some(),
                },
                Subject::Shell { source, .. } => DeferredSpawn::Shell {
                    source: ResourceExpr::Literal {
                        value: source.clone(),
                    },
                    cwd: cwd_resource.clone(),
                    cwd_uses_ambient: cwd_node.is_some(),
                    shell: None,
                    dynamic_detail: "subprocess with non-literal command".to_string(),
                },
                _ => DeferredSpawn::Exec {
                    argv: DeferredArgv::Words(Vec::new()),
                    cwd: cwd_resource.clone(),
                    cwd_uses_ambient: cwd_node.is_some(),
                },
            };
            self.push_deferred_spawn(spawn);
            return;
        }
        let source_cwd = self.nest.current_source_cwd();
        {
            let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
            self.nest.nest(
                self.builder,
                Transition::file(subject)
                    .source_cwd(source_cwd.as_deref())
                    .runtime_cwd(runtime_cwd.as_deref())
                    .cwd(cwd_resource, cwd_node),
                &[node],
                self.depth,
            );
        };
    }

    fn opaque_boundary(&mut self, detail: &str, node: ProvenanceRef) {
        for domain in DOMAINS {
            self.out_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }

    fn push_deferred_spawn(&mut self, spawn: DeferredSpawn) {
        let span = self.callable_span();
        if let Some(cap) = self.capture.as_mut()
            && cap.deferred_spawns.len() < MAX_SUMMARY_EFFECTS
            && !cap.deferred_spawns.contains(&spawn)
        {
            let bytes = crate::limits::NODE_BYTES
                + match &spawn {
                    DeferredSpawn::Exec { argv, cwd, .. } => {
                        let argv_bytes = match argv {
                            DeferredArgv::Words(words) => {
                                crate::limits::NODE_BYTES
                                    + words.iter().map(crate::limits::resource_bytes).sum::<u64>()
                            }
                            DeferredArgv::Sequence(value) => crate::limits::resource_bytes(value),
                        };
                        argv_bytes + cwd.as_ref().map_or(0, crate::limits::resource_bytes)
                    }
                    DeferredSpawn::Shell {
                        source,
                        cwd,
                        shell,
                        dynamic_detail,
                        ..
                    } => {
                        crate::limits::resource_bytes(source)
                            + cwd.as_ref().map_or(0, crate::limits::resource_bytes)
                            + shell.as_ref().map_or(0, crate::limits::resource_bytes)
                            + dynamic_detail.len() as u64
                    }
                    DeferredSpawn::Command { argv } => {
                        argv.iter().map(|word| word.len() as u64).sum::<u64>()
                    }
                };
            if crate::nest::charge_analysis_bytes(self.builder, self.nest.budget, bytes, span) {
                cap.deferred_spawns.push(spawn);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn defer_or_nest_exec(
        &mut self,
        argv: DeferredArgv,
        cwd: Option<String>,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
        node: ProvenanceRef,
        symbolic_arg: bool,
        symbolic_detail: &str,
    ) {
        if self.capture.is_some() {
            self.push_deferred_spawn(DeferredSpawn::Exec {
                argv,
                cwd: cwd_resource,
                cwd_uses_ambient: cwd_node.is_some(),
            });
            return;
        }
        let words = argv_to_words(
            &argv,
            &std::collections::HashMap::new(),
            self.nest.limits.value_limits(),
        );
        if words.is_empty() {
            self.emit_process_unresolved(node);
            return;
        }
        self.nest.nest(
            self.builder,
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(cwd.as_deref())
                .cwd(cwd_resource, cwd_node)
                .runtime_cwd(cwd.as_deref())
                .kind(ExecutionEdgeKind::Launch),
            &[node],
            self.depth,
        );
        if symbolic_arg {
            self.opaque_boundary(symbolic_detail, node);
        }
    }

    /// Enter source this program evaluates at runtime as a nested program of
    /// the same language.
    fn nest_python_source(&mut self, source: &str, span: TextRange) {
        let node = self.span_node(span);
        self.nest(
            Subject::Source {
                language: "python".to_string(),
                dialect: None,
                source: source.to_string(),
                cwd: self.cwd.clone(),
                context: Default::default(),
            },
            node,
            None,
            self.cwd_node,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn defer_or_nest_shell(
        &mut self,
        source: ResourceExpr,
        cwd: Option<String>,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
        node: ProvenanceRef,
        shell: Option<ResourceExpr>,
        dynamic_detail: &str,
    ) {
        if self.capture.is_some() {
            self.push_deferred_spawn(DeferredSpawn::Shell {
                source,
                cwd: cwd_resource,
                cwd_uses_ambient: cwd_node.is_some(),
                shell,
                dynamic_detail: dynamic_detail.to_string(),
            });
            return;
        }
        match resource_command_string(&source) {
            Some(cmd) => {
                let subject = Subject::Shell {
                    source: cmd,
                    cwd,
                    context: Default::default(),
                };
                let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
                self.nest.nest(
                    self.builder,
                    Transition::file(subject)
                        .source_cwd(self.nest.current_source_cwd().as_deref())
                        .runtime_cwd(runtime_cwd.as_deref())
                        .cwd(cwd_resource, cwd_node)
                        .runtime_shell(shell.as_ref().map(|shell| {
                            resource_command_string(shell)
                                .map_or(RuntimeShell::Unresolved, RuntimeShell::Program)
                        })),
                    &[node],
                    self.depth,
                );
            }
            // The shell runs a command this frontend cannot recover as its
            // `-c` script; the shell model reports that script as unrecoverable.
            None => self.defer_or_nest_exec(
                DeferredArgv::Words(vec![
                    shell_program(shell.as_ref()),
                    ResourceExpr::Literal {
                        value: "-c".to_string(),
                    },
                    unresolved("process"),
                ]),
                cwd,
                cwd_resource,
                cwd_node,
                node,
                false,
                dynamic_detail,
            ),
        }
    }

    fn apply_deferred_spawn(
        &mut self,
        spawn: DeferredSpawn,
        bindings: &std::collections::HashMap<String, SemanticValue>,
        node: ProvenanceRef,
        span: TextRange,
    ) {
        let spawn = substitute_deferred_spawn(spawn, bindings, self.nest.limits.value_limits());
        if self.capture.is_some() {
            self.push_deferred_spawn(spawn);
            return;
        }
        match spawn {
            DeferredSpawn::Exec {
                argv,
                cwd,
                cwd_uses_ambient,
            } => {
                let words = argv_to_words(&argv, bindings, self.nest.limits.value_limits());
                if words.is_empty() {
                    self.emit_process_unresolved(node);
                    return;
                }
                let cwd_resource = cwd.clone();
                let cwd_path = cwd_resource.as_ref().and_then(resource_path_string);
                let cwd_node = if cwd_uses_ambient {
                    self.cwd_node
                } else {
                    cwd_resource
                        .as_ref()
                        .is_some_and(fs_resource_uses_cwd)
                        .then_some(self.cwd_node)
                        .flatten()
                };
                if !self.charge_steps(1, (u32::from(span.start()), u32::from(span.end()))) {
                    self.node_budget_hit = true;
                    return;
                }
                self.nest.nest(
                    self.builder,
                    Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                        .exec_cwd(cwd_path.as_deref())
                        .cwd(cwd_resource, cwd_node)
                        .runtime_cwd(cwd_path.as_deref())
                        .kind(ExecutionEdgeKind::Launch),
                    &[node],
                    self.depth,
                );
            }
            DeferredSpawn::Shell {
                source,
                cwd,
                cwd_uses_ambient,
                shell,
                dynamic_detail,
            } => {
                let cwd_resource = cwd.clone();
                let cwd_path = cwd_resource.as_ref().and_then(resource_path_string);
                let cwd_node = cwd_uses_ambient.then_some(self.cwd_node).flatten();
                self.defer_or_nest_shell(
                    source,
                    cwd_path,
                    cwd_resource,
                    cwd_node,
                    node,
                    shell,
                    &dynamic_detail,
                );
            }
            DeferredSpawn::Command { argv } => {
                if !self.charge_steps(1, (u32::from(span.start()), u32::from(span.end()))) {
                    self.node_budget_hit = true;
                    return;
                }
                let argv = argv.into_iter().map(Word::literal).collect::<Vec<_>>();
                let runtime_cwd = self.nest.current_runtime_cwd();
                crate::models::apply_in_process_command(
                    self.builder,
                    self.nest,
                    &argv,
                    self.cwd.as_deref(),
                    runtime_cwd.as_deref(),
                    node,
                    self.depth,
                );
            }
        }
    }
}

/// The program a runtime runs a shell command string with: `/bin/sh` unless
/// the call selected another shell.
pub(super) fn shell_program(shell: Option<&ResourceExpr>) -> ResourceExpr {
    shell.cloned().unwrap_or_else(|| ResourceExpr::Literal {
        value: "/bin/sh".to_string(),
    })
}

fn unresolved(family: &str) -> ResourceExpr {
    ResourceExpr::Unresolved {
        family: ResourceFamily::new(family),
    }
}

fn ipython_constant_text(expr: &Expr) -> Option<String> {
    let Expr::Constant(constant) = expr else {
        return None;
    };
    match &constant.value {
        Constant::Str(value) => Some(value.clone()),
        Constant::Int(value) => Some(value.to_string()),
        Constant::Float(value) => Some(value.to_string()),
        Constant::Bool(value) => Some(if *value { "True" } else { "False" }.to_string()),
        Constant::None => Some("None".to_string()),
        _ => None,
    }
}

fn ipython_flatten_literal(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Join { parts } => {
            let mut output = String::new();
            for part in parts {
                output.push_str(&ipython_flatten_literal(part)?);
            }
            Some(output)
        }
        _ => None,
    }
}

/// Whether `name` is the identifier Python binds for `bash`. Python compares
/// identifiers after NFKC normalization, so `ｂａｓｈ = print` rebinds it.
fn is_prime_bash_name(name: &str) -> bool {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfkc().normalize(name) == "bash"
}

/// Whether every reference to `bash` in a Prime Agent cell is a call of the
/// helper the kernel injects. Any binding, deletion, parameter, alias,
/// attribute of that name, star import, reach into a namespace (`globals()`,
/// `exec`, `__dict__`, `getattr`, a three-argument `type`, ...), or class whose
/// metaclass could supply its own namespace anywhere in the cell could replace
/// it, so none of them proves the helper.
fn prime_bash_owned(suite: &ast::Suite) -> bool {
    use rustpython_parser::ast::fold::{self, Fold};
    use rustpython_parser::text_size::TextRange;

    struct Ownership {
        owned: bool,
        callees: HashSet<TextRange>,
        /// Classes the cell defines, and the bases its classes name; a base
        /// defined elsewhere may carry a metaclass.
        classes: HashSet<String>,
        bases: Vec<String>,
    }
    impl Ownership {
        fn bind(&mut self, name: Option<&ast::Identifier>) {
            if name.is_some_and(|name| is_prime_bash_name(name.as_str())) {
                self.owned = false;
            }
        }
    }
    fn nfkc(name: &str) -> String {
        icu_normalizer::ComposingNormalizerBorrowed::new_nfkc()
            .normalize(name)
            .into_owned()
    }
    // Names and attributes that reach a module namespace or run code in it.
    fn reaches_namespace(name: &str) -> bool {
        matches!(
            nfkc(name).as_str(),
            "globals"
                | "locals"
                | "vars"
                | "exec"
                | "eval"
                | "compile"
                | "setattr"
                | "delattr"
                | "getattr"
                | "__import__"
                | "__builtins__"
                | "__main__"
                | "builtins"
        )
    }
    fn reaches_namespace_attribute(attribute: &str) -> bool {
        matches!(
            nfkc(attribute).as_str(),
            "__dict__"
                | "__globals__"
                | "__builtins__"
                | "__setattr__"
                | "__delattr__"
                | "__getattribute__"
                | "f_globals"
                | "f_locals"
                | "f_builtins"
        )
    }
    impl Fold<TextRange> for Ownership {
        type TargetU = TextRange;
        type Error = std::convert::Infallible;
        type UserContext = ();
        fn will_map_user(&mut self, _: &TextRange) {}
        fn map_user(&mut self, user: TextRange, _: ()) -> Result<TextRange, Self::Error> {
            Ok(user)
        }
        fn fold_stmt(&mut self, node: Stmt) -> Result<Stmt, Self::Error> {
            match &node {
                Stmt::FunctionDef(def) => self.bind(Some(&def.name)),
                Stmt::AsyncFunctionDef(def) => self.bind(Some(&def.name)),
                Stmt::ClassDef(def) => {
                    self.bind(Some(&def.name));
                    self.classes.insert(nfkc(def.name.as_str()));
                    // `metaclass=`, or `**` that may carry it, can give the body
                    // a namespace of its own.
                    if !def.keywords.is_empty() {
                        self.owned = false;
                    }
                    for base in &def.bases {
                        match base {
                            Expr::Name(name) => self.bases.push(nfkc(name.id.as_str())),
                            _ => self.owned = false,
                        }
                    }
                }
                Stmt::ImportFrom(import) => {
                    if import
                        .module
                        .as_ref()
                        .is_some_and(|module| module.as_str().split('.').any(reaches_namespace))
                    {
                        self.owned = false;
                    }
                }
                Stmt::Global(ast::StmtGlobal { names, .. })
                | Stmt::Nonlocal(ast::StmtNonlocal { names, .. }) => {
                    names.iter().for_each(|name| self.bind(Some(name)))
                }
                _ => {}
            }
            fold::fold_stmt(self, node)
        }
        fn fold_expr(&mut self, node: Expr) -> Result<Expr, Self::Error> {
            match &node {
                // Parentheses leave no node, so `(bash)(...)` is this call too.
                Expr::Call(call) => {
                    if let Expr::Name(name) = call.func.as_ref() {
                        self.callees.insert(name.range);
                        // `type(name, bases, namespace)` builds a class, such as
                        // a metaclass, outside any class statement.
                        if nfkc(name.id.as_str()) == "type" && call.args.len() == 3 {
                            self.owned = false;
                        }
                    }
                }
                Expr::Name(name) => {
                    if (is_prime_bash_name(name.id.as_str()) && !self.callees.contains(&name.range))
                        || reaches_namespace(name.id.as_str())
                    {
                        self.owned = false;
                    }
                }
                Expr::Attribute(attribute) => {
                    if is_prime_bash_name(attribute.attr.as_str())
                        || reaches_namespace_attribute(attribute.attr.as_str())
                    {
                        self.owned = false;
                    }
                }
                _ => {}
            }
            fold::fold_expr(self, node)
        }
        fn fold_arg(&mut self, node: ast::Arg) -> Result<ast::Arg, Self::Error> {
            self.bind(Some(&node.arg));
            fold::fold_arg(self, node)
        }
        fn fold_alias(&mut self, node: ast::Alias) -> Result<ast::Alias, Self::Error> {
            let bound = node.asname.as_ref().unwrap_or(&node.name);
            let top = bound.as_str().split('.').next().unwrap_or_default();
            // An alias renames a facility without changing what it reaches.
            if top == "*"
                || is_prime_bash_name(top)
                || reaches_namespace(top)
                || node.name.as_str().split('.').any(reaches_namespace)
            {
                self.owned = false;
            }
            fold::fold_alias(self, node)
        }
        fn fold_excepthandler(
            &mut self,
            node: ast::ExceptHandler,
        ) -> Result<ast::ExceptHandler, Self::Error> {
            let ast::ExceptHandler::ExceptHandler(handler) = &node;
            self.bind(handler.name.as_ref());
            fold::fold_excepthandler(self, node)
        }
        fn fold_pattern(&mut self, node: ast::Pattern) -> Result<ast::Pattern, Self::Error> {
            match &node {
                ast::Pattern::MatchAs(pattern) => self.bind(pattern.name.as_ref()),
                ast::Pattern::MatchStar(pattern) => self.bind(pattern.name.as_ref()),
                ast::Pattern::MatchMapping(pattern) => self.bind(pattern.rest.as_ref()),
                _ => {}
            }
            fold::fold_pattern(self, node)
        }
        fn fold_type_param(&mut self, node: ast::TypeParam) -> Result<ast::TypeParam, Self::Error> {
            match &node {
                ast::TypeParam::TypeVar(param) => self.bind(Some(&param.name)),
                ast::TypeParam::ParamSpec(param) => self.bind(Some(&param.name)),
                ast::TypeParam::TypeVarTuple(param) => self.bind(Some(&param.name)),
            }
            fold::fold_type_param(self, node)
        }
    }

    let mut ownership = Ownership {
        owned: true,
        callees: HashSet::new(),
        classes: HashSet::new(),
        bases: Vec::new(),
    };
    let Ok(_) = ownership.fold(suite.clone());
    ownership.owned
        && ownership
            .bases
            .iter()
            .all(|base| ownership.classes.contains(base))
}

fn ipython_unresolved_expression(expr: &Expr) -> String {
    match expr {
        Expr::Name(name) => format!("${{{}}}", name.id),
        _ => "${IPYTHON_UNRESOLVED}".to_string(),
    }
}

fn ipython_getter_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "get_ipython")
            && call.args.is_empty()
            && call.keywords.is_empty())
}

fn ipython_getter_target(target: &Expr) -> bool {
    match target {
        Expr::Name(name) => name.id.as_str() == "get_ipython",
        Expr::Attribute(attribute) => ipython_getter_call(&attribute.value),
        Expr::Tuple(tuple) => tuple.elts.iter().any(ipython_getter_target),
        Expr::List(list) => list.elts.iter().any(ipython_getter_target),
        Expr::Starred(starred) => ipython_getter_target(&starred.value),
        _ => false,
    }
}

fn interpolation_name(expression: &str) -> String {
    let name = expression.trim();
    let mut bytes = name.bytes();
    if bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        name.to_string()
    } else {
        "IPYTHON_UNRESOLVED".to_string()
    }
}

fn ipython_split_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn ipython_known_magic_option(option: &str) -> bool {
    matches!(
        option,
        "--no-raise-error"
            | "--noprofile"
            | "--norc"
            | "--verbose"
            | "-e"
            | "-E"
            | "-u"
            | "-v"
            | "-x"
            | "-vx"
            | "-xv"
            | "-O"
            | "-OO"
            | "-B"
            | "-I"
            | "-s"
            | "-S"
    )
}

fn ipython_run_option(option: &str) -> bool {
    matches!(option, "-i" | "-n" | "-e" | "-G" | "-d" | "-t")
}

fn ipython_noop_magic(name: &str) -> bool {
    matches!(
        name,
        "load"
            | "history"
            | "hist"
            | "dirs"
            | "magic"
            | "page"
            | "matplotlib"
            | "load_ext"
            | "autoreload"
            | "pylab"
            | "precision"
            | "colors"
            | "pwd"
            | "tb"
            | "who"
            | "who_ls"
            | "whos"
            | "xmode"
            | "lsmagic"
            | "quickref"
            | "pdef"
            | "pdoc"
            | "pinfo"
            | "pinfo2"
            | "psource"
            | "pycat"
            | "pfile"
            | "psearch"
    )
}

fn ipython_script_language(
    interpreter: &str,
) -> Option<(&'static str, Option<effinterp_proto::SourceDialect>)> {
    let interpreter = interpreter.rsplit('/').next().unwrap_or(interpreter);
    match interpreter {
        "python" | "python2" | "python3" => Some(("python", None)),
        "ipython" | "ipython3" => Some(("python", Some(effinterp_proto::SourceDialect::Ipython))),
        "node" | "nodejs" | "javascript" | "js" => {
            Some(("js", Some(effinterp_proto::SourceDialect::Js)))
        }
        "ts-node" | "tsx" | "typescript" => Some(("js", Some(effinterp_proto::SourceDialect::Ts))),
        "ruby" => Some(("ruby", None)),
        "perl" => Some(("perl", None)),
        "php" => Some(("php", None)),
        "lua" => Some(("lua", None)),
        "R" | "Rscript" => Some(("r", None)),
        "julia" => Some(("julia", None)),
        "pwsh" | "powershell" => Some(("powershell", None)),
        _ => None,
    }
}

fn overlay_sequence_bindings(
    bindings: &mut std::collections::HashMap<String, SemanticValue>,
    params: &[String],
    call: &ast::ExprCall,
    walker: &Walker<'_, '_>,
) {
    for (index, arg) in call.args.iter().enumerate() {
        let Some(param) = params.get(index) else {
            continue;
        };
        let Some(values) = walker.static_sequence(arg) else {
            continue;
        };
        bindings.insert(
            param.clone(),
            SemanticValue::new(SemanticValueKind::Collection {
                elements: values.into_iter().map(SemanticValue::from).collect(),
                properties: std::collections::BTreeMap::new(),
            }),
        );
    }
}

pub(super) fn substitute_deferred_spawn(
    spawn: DeferredSpawn,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> DeferredSpawn {
    match spawn {
        DeferredSpawn::Exec {
            argv,
            cwd,
            cwd_uses_ambient,
        } => DeferredSpawn::Exec {
            argv: substitute_argv(argv, bindings, value_limits),
            cwd: cwd.map(|cwd| substitute_resource(&cwd, bindings, value_limits)),
            cwd_uses_ambient,
        },
        DeferredSpawn::Shell {
            source,
            cwd,
            cwd_uses_ambient,
            shell,
            dynamic_detail,
        } => DeferredSpawn::Shell {
            source: substitute_resource(&source, bindings, value_limits),
            cwd: cwd.map(|cwd| substitute_resource(&cwd, bindings, value_limits)),
            cwd_uses_ambient,
            shell: shell.map(|shell| substitute_resource(&shell, bindings, value_limits)),
            dynamic_detail,
        },
        DeferredSpawn::Command { argv } => DeferredSpawn::Command { argv },
    }
}

fn substitute_argv(
    argv: DeferredArgv,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> DeferredArgv {
    match argv {
        DeferredArgv::Words(words) => DeferredArgv::Words(
            words
                .into_iter()
                .map(|word| substitute_resource(&word, bindings, value_limits))
                .collect(),
        ),
        DeferredArgv::Sequence(value) => {
            match flatten_sequence(&substitute_value_of(&value, bindings, value_limits)) {
                Some(words) => DeferredArgv::Words(words),
                None => DeferredArgv::Sequence(substitute_resource(&value, bindings, value_limits)),
            }
        }
    }
}

fn substitute_resource(
    expr: &ResourceExpr,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> ResourceExpr {
    crate::substitute_value(&SemanticValue::from(expr), bindings, value_limits).lower_resource()
}

fn substitute_value_of(
    expr: &ResourceExpr,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> SemanticValue {
    crate::substitute_value(&SemanticValue::from(expr), bindings, value_limits)
}

fn argv_to_words(
    argv: &DeferredArgv,
    bindings: &std::collections::HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> Vec<Word> {
    match argv {
        DeferredArgv::Words(words) => words.iter().map(resource_to_word).collect(),
        DeferredArgv::Sequence(value) => {
            let substituted = substitute_value_of(value, bindings, value_limits);
            if let Some(parts) = flatten_sequence(&substituted) {
                return parts.iter().map(resource_to_word).collect();
            }
            let word = resource_to_word(&substituted.lower_resource());
            if word.as_literal() == Some("") {
                Vec::new()
            } else {
                vec![word]
            }
        }
    }
}

fn flatten_sequence(value: &SemanticValue) -> Option<Vec<ResourceExpr>> {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => Some(
            elements
                .iter()
                .map(|element| element.lower_resource())
                .collect(),
        ),
        _ => None,
    }
}

fn resource_to_word(expr: &ResourceExpr) -> Word {
    match expr {
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        ResourceExpr::Join { parts }
            if parts.iter().all(|part| {
                matches!(
                    part,
                    ResourceExpr::Literal { .. }
                        | ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. },
                        }
                )
            }) =>
        {
            let mut text = String::new();
            for part in parts {
                match part {
                    ResourceExpr::Literal { value } => text.push_str(value),
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => text.push_str(path),
                    _ => {}
                }
            }
            Word::literal(text)
        }
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

/// The argv a launch runs when the call names its program apart from the
/// argv[0] that program is shown (`executable=`, the file of `os.exec*`): the
/// program takes argv[0]'s place. A multi-call binary picks its applet from
/// the argv[0] it is shown, so that applet becomes its first operand.
pub(super) fn program_argv(
    program: Option<&ResourceExpr>,
    mut argv: Vec<ResourceExpr>,
) -> Vec<ResourceExpr> {
    let (Some(program), Some(first)) = (program, argv.first_mut()) else {
        return argv;
    };
    let shown = std::mem::replace(first, program.clone());
    let Some(multicall) = resource_command_string(program)
        .and_then(|path| MultiCall::named(path.rsplit('/').next().unwrap_or(&path)))
    else {
        return argv;
    };
    match resource_command_string(&shown).map(|name| multicall.applet(&name)) {
        Some(Applet::Named(value)) => argv.insert(1, ResourceExpr::Literal { value }),
        Some(Applet::FromArgv1) => {}
        // Neither binary runs the other: the name selects no applet, and the
        // binary's model bounds an applet it cannot read, like an unread one.
        Some(Applet::Foreign) => argv.insert(1, unresolved("process")),
        None => argv.insert(1, shown),
    }
    argv
}

/// What the argv[0] a multi-call binary is shown selects.
enum Applet {
    Named(String),
    /// The binary's own dispatcher name, which takes the applet from argv[1].
    FromArgv1,
    /// The other multi-call binary's dispatcher name, which is no applet.
    Foreign,
}

/// A multi-call binary, identified by its executable's name. Each has its
/// own rule for the applet the argv[0] it is shown selects.
enum MultiCall {
    BusyBox,
    Toybox,
}

impl MultiCall {
    fn named(name: &str) -> Option<Self> {
        match name {
            "busybox" => Some(Self::BusyBox),
            "toybox" => Some(Self::Toybox),
            _ => None,
        }
    }

    /// The applet `shown` selects.
    fn applet(&self, shown: &str) -> Applet {
        let (name, dispatcher, foreign) = match self {
            // libbb/appletlib.c: drop one leading `-` (a login shell's
            // argv[0]), take the basename, and treat any name prefixed
            // `busybox` as the dispatcher.
            Self::BusyBox => (
                shown.strip_prefix('-').unwrap_or(shown),
                "busybox",
                "toybox",
            ),
            // main.c: toy_find() looks up the basename, and the multiplexer's
            // name `toybox` matches as a prefix. No `-` is dropped.
            Self::Toybox => (shown, "toybox", "busybox"),
        };
        let name = name.rsplit('/').next().unwrap_or(name);
        if name.starts_with(dispatcher) {
            Applet::FromArgv1
        } else if name.starts_with(foreign) {
            Applet::Foreign
        } else {
            Applet::Named(name.to_string())
        }
    }
}

fn resource_command_string(expr: &ResourceExpr) -> Option<String> {
    match expr {
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

/// Render a recovered plugin path pattern, retaining symbolic path components explicitly.
pub fn python_plugin_path_pattern(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Parameter { name } => Some(format!("<{name}>")),
        ResourceExpr::Property { base, name } => {
            Some(format!("{}.{}", python_plugin_path_pattern(base)?, name))
        }
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } => Some(glob.clone()),
        ResourceExpr::Join { parts } => {
            let parts: Option<Vec<_>> = parts.iter().map(python_plugin_path_pattern).collect();
            Some(parts?.join("/"))
        }
        _ => None,
    }
}

fn resource_path_string(expr: &ResourceExpr) -> Option<String> {
    match expr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        ResourceExpr::Literal { value } => Some(value.clone()),
        _ => None,
    }
}

pub(super) fn materialize_deferred_spawns(
    spawns: &[DeferredSpawn],
) -> (Vec<Effect>, Vec<Boundary>) {
    let mut effects = Vec::new();
    let mut boundaries = Vec::new();
    for spawn in spawns {
        let resource = match spawn {
            DeferredSpawn::Exec {
                argv: DeferredArgv::Words(words),
                cwd,
                ..
            } => materialized_exec_resource(words, cwd.as_ref()),
            DeferredSpawn::Exec {
                argv: DeferredArgv::Sequence(_),
                ..
            }
            | DeferredSpawn::Shell { .. } => unresolved("process"),
            // No process starts; the call's own unresolved boundary is
            // already among the summary's boundaries.
            DeferredSpawn::Command { .. } => continue,
        };
        effects.push(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.exec"),
            resource: resource.clone(),
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
        boundaries.push(Boundary {
            reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(resource),
            callee: None,
            domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some("subprocess spawned inside a summarized function".to_string()),
        });
    }
    (effects, boundaries)
}

fn materialized_exec_resource(words: &[ResourceExpr], cwd: Option<&ResourceExpr>) -> ResourceExpr {
    let Some(program) = words.first().and_then(resource_command_string) else {
        return unresolved("process");
    };
    if program.is_empty() || program == "?" {
        return unresolved("process");
    }
    let executable = program.rsplit('/').next().unwrap_or(&program);
    if executable.is_empty() {
        return unresolved("process");
    }
    let path = program
        .contains('/')
        .then(|| match crate::paths::resolve_fs_path(&program, None) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path),
            _ => None,
        })
        .flatten();
    ResourceExpr::Concrete {
        identity: ResourceIdentity::Process {
            executable: executable.to_string(),
            path,
            argv: words.iter().skip(1).cloned().collect(),
            cwd: cwd.cloned().map(Box::new),
        },
    }
}

fn python_callee_reference(name: &str) -> Option<CalleeReference> {
    let (module, symbol) = name.rsplit_once('.')?;
    (!module.is_empty() && !symbol.is_empty()).then(|| CalleeReference {
        module: module.to_string(),
        symbol: symbol.to_string(),
    })
}

/// Whether a resolved callee is a modeled builtin or dynamic construct (an
/// effect or boundary), rather than a user function to link across files.
fn is_builtin_effect(canon: &str) -> bool {
    matches!(
        canon,
        "open" | "eval" | "exec" | "__import__" | "compile" | "os.exec"
    )
}

fn is_path_method(method: &str) -> bool {
    matches!(
        method,
        "resolve"
            | "absolute"
            | "expanduser"
            | "joinpath"
            | "with_suffix"
            | "with_name"
            | "read_text"
            | "read_bytes"
            | "write_text"
            | "write_bytes"
            | "touch"
            | "open"
            | "unlink"
            | "rmdir"
            | "mkdir"
            | "rename"
            | "replace"
            | "exists"
            | "is_file"
            | "is_dir"
            | "stat"
            | "chmod"
            | "symlink_to"
            | "hardlink_to"
            | "iterdir"
            | "glob"
            | "rglob"
    )
}

fn is_path_specific_method(method: &str) -> bool {
    matches!(
        method,
        "read_text" | "read_bytes" | "write_text" | "write_bytes"
    )
}

fn is_branch_mixed_path_method(method: &str) -> bool {
    is_path_method(method) && !matches!(method, "open" | "replace")
}

fn keyword_str(call: &ast::ExprCall, name: &str) -> Option<String> {
    call.keywords
        .iter()
        .find(|k| k.arg.as_ref().map(|a| a.as_str()) == Some(name))
        .and_then(|k| str_literal(&k.value))
}

/// A small non-negative integer literal (a port number), when the expression
/// is one and fits a `u16`.
fn int_literal(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Constant(c) => match &c.value {
            Constant::Int(i) => i.to_string().parse::<u16>().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// A textual superset of the working-directory changes a Python source can
/// make: `os.chdir`, `os.fchdir` and `contextlib.chdir` all spell `chdir`, and
/// IPython changes it through its `cd` magic, as a cell line or through the
/// `magic` APIs.
fn source_changes_cwd(source: &str, ipython: Option<&ipython::CellActions>) -> bool {
    source.contains("chdir")
        || ipython.is_some_and(|cell| {
            source.contains("magic")
                || cell.actions.values().flatten().any(|action| {
                    matches!(action, ipython::Action::LineMagic { name, .. } if name == "cd")
                })
        })
}

fn keyword_bool(call: &ast::ExprCall, name: &str) -> Option<bool> {
    call.keywords
        .iter()
        .find(|k| k.arg.as_ref().map(|a| a.as_str()) == Some(name))
        .and_then(|k| match &k.value {
            Expr::Constant(c) => match c.value {
                Constant::Bool(b) => Some(b),
                _ => None,
            },
            _ => None,
        })
}

fn python_call_argument<'a>(call: &'a ast::ExprCall, index: usize, name: &str) -> Option<&'a Expr> {
    call.args.get(index).or_else(|| {
        call.keywords
            .iter()
            .find(|keyword| keyword.arg.as_ref().map(|arg| arg.as_str()) == Some(name))
            .map(|keyword| &keyword.value)
    })
}

fn bind_python_arguments(
    params: &[String],
    positional_param_count: usize,
    arguments: &[ValueArgument],
) -> std::collections::HashMap<String, SemanticValue> {
    let arguments: Vec<_> = arguments
        .iter()
        .filter(|argument| argument.name.is_some() || argument.index < positional_param_count)
        .cloned()
        .collect();
    bind_arguments(params, &arguments)
}

fn unpack_assignment_elements(targets: &[Expr]) -> Option<&[Expr]> {
    match targets {
        [Expr::Tuple(tuple)] => Some(tuple.elts.as_slice()),
        [Expr::List(list)] => Some(list.elts.as_slice()),
        _ => None,
    }
}

fn sequence_expr_elements(expr: &Expr) -> Option<&[Expr]> {
    match expr {
        Expr::Tuple(tuple) => Some(tuple.elts.as_slice()),
        Expr::List(list) => Some(list.elts.as_slice()),
        _ => None,
    }
}

// Collect possible writes without evaluating them. Loop entry drops these bindings
// because a later iteration can observe any write in the body. Shared declarations
// also prevent module constants from surviving writes through called helpers.
fn rebound_body_names(body: &[Stmt], shared_only: bool) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut statements: Vec<_> = body.iter().collect();
    let mut expressions = Vec::new();
    while let Some(stmt) = statements.pop() {
        match stmt {
            Stmt::Assign(s) => {
                expressions.extend(s.targets.iter());
                expressions.push(&s.value);
            }
            Stmt::AnnAssign(s) => {
                if let Some(value) = &s.value {
                    expressions.extend([s.target.as_ref(), value.as_ref()]);
                }
            }
            Stmt::AugAssign(s) => expressions.extend([s.target.as_ref(), s.value.as_ref()]),
            Stmt::Delete(s) => expressions.extend(s.targets.iter()),
            Stmt::Expr(s) => expressions.push(&s.value),
            Stmt::If(s) => {
                expressions.push(&s.test);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::While(s) => {
                expressions.push(&s.test);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::For(s) => {
                expressions.extend([s.target.as_ref(), s.iter.as_ref()]);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::AsyncFor(s) => {
                expressions.extend([s.target.as_ref(), s.iter.as_ref()]);
                statements.extend(s.body.iter().chain(&s.orelse));
            }
            Stmt::With(s) => {
                for item in &s.items {
                    expressions.extend(item.optional_vars.as_deref());
                    expressions.push(&item.context_expr);
                }
                statements.extend(&s.body);
            }
            Stmt::AsyncWith(s) => {
                for item in &s.items {
                    expressions.extend(item.optional_vars.as_deref());
                    expressions.push(&item.context_expr);
                }
                statements.extend(&s.body);
            }
            Stmt::Try(s) => {
                statements.extend(s.body.iter().chain(&s.orelse).chain(&s.finalbody));
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    if !shared_only {
                        names.extend(h.name.iter().map(ToString::to_string));
                    }
                    statements.extend(&h.body);
                }
            }
            Stmt::TryStar(s) => {
                statements.extend(s.body.iter().chain(&s.orelse).chain(&s.finalbody));
                for handler in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    if !shared_only {
                        names.extend(h.name.iter().map(ToString::to_string));
                    }
                    statements.extend(&h.body);
                }
            }
            Stmt::Match(s) => {
                expressions.push(&s.subject);
                for case in &s.cases {
                    if !shared_only {
                        names.extend(rebound_pattern_names(&case.pattern));
                    }
                    expressions.extend(case.guard.as_deref());
                    statements.extend(&case.body);
                }
            }
            Stmt::FunctionDef(s) => {
                if shared_only {
                    statements.extend(&s.body);
                } else {
                    names.insert(s.name.to_string());
                }
            }
            Stmt::AsyncFunctionDef(s) => {
                if shared_only {
                    statements.extend(&s.body);
                } else {
                    names.insert(s.name.to_string());
                }
            }
            Stmt::ClassDef(s) => {
                if shared_only {
                    statements.extend(&s.body);
                } else {
                    names.insert(s.name.to_string());
                }
            }
            Stmt::Import(s) if !shared_only => names.extend(s.names.iter().map(|a| {
                a.asname
                    .as_deref()
                    .unwrap_or(a.name.split('.').next().unwrap())
                    .to_string()
            })),
            Stmt::ImportFrom(s) if !shared_only => names.extend(
                s.names
                    .iter()
                    .map(|a| a.asname.as_deref().unwrap_or(a.name.as_str()).to_string()),
            ),
            Stmt::Global(s) => names.extend(s.names.iter().map(ToString::to_string)),
            Stmt::Nonlocal(s) => names.extend(s.names.iter().map(ToString::to_string)),
            _ => {}
        }
    }
    if !shared_only {
        while let Some(expr) = expressions.pop() {
            match expr {
                Expr::Name(name)
                    if matches!(name.ctx, ast::ExprContext::Store | ast::ExprContext::Del) =>
                {
                    names.insert(name.id.to_string());
                }
                Expr::NamedExpr(named) => names.extend(rebound_target_names(&named.target)),
                Expr::Subscript(subscript)
                    if matches!(
                        subscript.ctx,
                        ast::ExprContext::Store | ast::ExprContext::Del
                    ) =>
                {
                    names.extend(rebound_target_names(&subscript.value));
                }
                _ => {}
            }
            expressions.extend(child_exprs(expr));
        }
    }
    names
}

fn rebound_target_names(target: &Expr) -> Vec<String> {
    match target {
        Expr::Name(name) => vec![name.id.to_string()],
        Expr::List(list) => list.elts.iter().flat_map(rebound_target_names).collect(),
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(rebound_target_names).collect(),
        Expr::Starred(starred) => rebound_target_names(&starred.value),
        _ => Vec::new(),
    }
}

fn rebound_pattern_names(pattern: &ast::Pattern) -> Vec<String> {
    match pattern {
        ast::Pattern::MatchSequence(sequence) => sequence
            .patterns
            .iter()
            .flat_map(rebound_pattern_names)
            .collect(),
        ast::Pattern::MatchMapping(mapping) => mapping
            .patterns
            .iter()
            .flat_map(rebound_pattern_names)
            .chain(mapping.rest.iter().map(ToString::to_string))
            .collect(),
        ast::Pattern::MatchClass(class) => class
            .patterns
            .iter()
            .chain(&class.kwd_patterns)
            .flat_map(rebound_pattern_names)
            .collect(),
        ast::Pattern::MatchStar(star) => star.name.iter().map(ToString::to_string).collect(),
        ast::Pattern::MatchAs(as_pattern) => as_pattern
            .pattern
            .iter()
            .flat_map(|pattern| rebound_pattern_names(pattern))
            .chain(as_pattern.name.iter().map(ToString::to_string))
            .collect(),
        ast::Pattern::MatchOr(or) => or.patterns.iter().flat_map(rebound_pattern_names).collect(),
        ast::Pattern::MatchValue(_) | ast::Pattern::MatchSingleton(_) => Vec::new(),
    }
}

fn boundary(
    builder: &mut PlanBuilder,
    scope: Option<ProvenanceRef>,
    reason: BoundaryReason,
    class: BoundaryClass,
    limit_name: Option<&str>,
    detail: Option<String>,
) {
    builder.boundary(Boundary {
        reason,
        class,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: scope.as_slice().to_vec(),
        limit: limit_name.map(str::to_string),
        detail,
    });
}

/// The immediate child expressions of `expr` that may themselves contain
/// effect calls. Deliberately partial: only the shapes that commonly wrap a
/// call (arguments, containers, operators, comprehensions).
fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut out: Vec<&Expr> = Vec::new();
    match expr {
        Expr::Call(c) => {
            out.push(&c.func);
            out.extend(c.args.iter());
            out.extend(c.keywords.iter().map(|k| &k.value));
        }
        Expr::BoolOp(b) => out.extend(b.values.iter()),
        Expr::BinOp(b) => {
            out.push(&b.left);
            out.push(&b.right);
        }
        Expr::UnaryOp(u) => out.push(&u.operand),
        Expr::IfExp(e) => {
            out.push(&e.test);
            out.push(&e.body);
            out.push(&e.orelse);
        }
        Expr::List(l) => out.extend(l.elts.iter()),
        Expr::Tuple(t) => out.extend(t.elts.iter()),
        Expr::Set(s) => out.extend(s.elts.iter()),
        Expr::Await(a) => out.push(&a.value),
        Expr::Starred(s) => out.push(&s.value),
        Expr::Subscript(s) => out.push(&s.value),
        Expr::Attribute(a) => out.push(&a.value),
        Expr::Compare(c) => {
            out.push(&c.left);
            out.extend(c.comparators.iter());
        }
        Expr::NamedExpr(n) => out.push(&n.value),
        Expr::Dict(d) => {
            out.extend(d.keys.iter().flatten());
            out.extend(d.values.iter());
        }
        Expr::JoinedStr(j) => out.extend(j.values.iter()),
        Expr::FormattedValue(f) => out.push(&f.value),
        Expr::Yield(y) => out.extend(y.value.as_deref()),
        Expr::YieldFrom(y) => out.push(&y.value),
        Expr::ListComp(c) => {
            out.push(&c.elt);
            out.extend(comprehension_exprs(&c.generators));
        }
        Expr::SetComp(c) => {
            out.push(&c.elt);
            out.extend(comprehension_exprs(&c.generators));
        }
        Expr::GeneratorExp(c) => {
            out.push(&c.elt);
            out.extend(comprehension_exprs(&c.generators));
        }
        Expr::DictComp(c) => {
            out.push(&c.key);
            out.push(&c.value);
            out.extend(comprehension_exprs(&c.generators));
        }
        _ => {}
    }
    out
}

fn expression_uses_name(expr: &Expr, names: &HashSet<String>) -> bool {
    matches!(expr, Expr::Name(name) if names.contains(name.id.as_str()))
        || child_exprs(expr)
            .into_iter()
            .any(|child| expression_uses_name(child, names))
}

/// The executed subexpressions of comprehension generators: each iterable and
/// filter condition (the bound target is a binding pattern, not evaluated).
fn comprehension_exprs(generators: &[ast::Comprehension]) -> Vec<&Expr> {
    let mut out = Vec::new();
    for g in generators {
        out.push(&g.iter);
        out.extend(g.ifs.iter());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eager and scoped bindings merged — the resolver's view.
    fn imports(src: &str) -> Vec<ImportBinding> {
        let suite = ast::Suite::parse(src, "<test>").unwrap();
        let (mut eager, scoped, _) = extract_imports(&suite);
        eager.extend(scoped);
        eager
    }

    #[test]
    fn collects_function_local_imports() {
        let src = "\
def run():
    from lib.fs import wipe
    wipe(\"/x\")
";
        let b = imports(src)
            .into_iter()
            .find(|b| b.local == "wipe")
            .expect("function-local import is collected");
        assert_eq!(b.module, "lib.fs");
        assert_eq!(b.imported.as_deref(), Some("wipe"));
    }

    #[test]
    fn collects_imports_in_nested_blocks() {
        // Inside a def, inside a try, inside an if — every depth is reached.
        let src = "\
def main():
    try:
        from httpie.core import main
    except KeyboardInterrupt:
        from httpie.status import ExitStatus
if True:
    import sys
";
        let got = imports(src);
        assert!(
            got.iter()
                .any(|b| b.local == "main" && b.module == "httpie.core")
        );
        assert!(
            got.iter()
                .any(|b| b.local == "ExitStatus" && b.module == "httpie.status")
        );
        assert!(got.iter().any(|b| b.local == "sys" && b.module == "sys"));
    }

    #[test]
    fn module_level_import_wins_dedup() {
        // A module-level binding of `x` is not overwritten by a function-local
        // one of the same name.
        let src = "\
from top import x
def f():
    from other import x
    x()
";
        let got = imports(src);
        let bindings: Vec<_> = got.iter().filter(|b| b.local == "x").collect();
        assert_eq!(
            bindings.len(),
            1,
            "no double-binding of the same local name"
        );
        assert_eq!(bindings[0].module, "top");
    }

    #[test]
    fn conditional_imports_preserve_every_binding() {
        let got =
            imports("if FLAG:\n    from right import wipe\nelse:\n    from wrong import wipe\n");
        let bindings: Vec<_> = got
            .iter()
            .filter(|binding| binding.local == "wipe")
            .collect();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].module, "right");
        assert_eq!(bindings[1].module, "wrong");
    }

    #[test]
    fn later_unconditional_import_replaces_the_same_local() {
        let got = imports("from wrong import wipe\nfrom right import wipe\n");
        let bindings: Vec<_> = got
            .iter()
            .filter(|binding| binding.local == "wipe")
            .collect();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].module, "right");
    }

    #[test]
    fn wildcard_import_is_retained_for_export_resolution() {
        let got = imports("from impl import *\n");
        assert_eq!(
            got,
            [ImportBinding {
                local: "*".to_string(),
                module: "impl".to_string(),
                imported: None,
            }]
        );
    }
}
