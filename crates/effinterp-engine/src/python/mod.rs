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
mod call_resolution;
mod control;
mod dataflow_capture;
mod definitions;
mod effect_emission;
mod fs_path_lowering;
mod import_bindings;
mod imports;
mod instance_tracking;
pub(crate) mod ipython;
mod model;
mod path_values;
mod registration;
mod resolve;
mod returns;
mod runtime;
mod static_containers;
mod summary_application;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
use crate::value::unresolved_resource;
pub(crate) use imports::{PythonImportCache, PythonImportSearch};
pub(crate) use runtime::runtime_imports;
mod summary;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference, CoverageLevel, Domain,
    Effect, Modality, Operation, PathPlatform, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity, normalize_resource,
};
use rustpython_parser::ast::{self, Constant, Expr, Ranged, Stmt};
use rustpython_parser::{Parse, text_size::TextRange};

use crate::builder::PlanBuilder;
use crate::control_flow::{ControlExit, ControlFlow, Requirements, SiteFacts};
use crate::external::is_python_stdlib;
use crate::flow::StageWriter;
use crate::module_summary::{CallEdge, ClassEntry};
use crate::nest::Nest;
use crate::resource_transfer::TransferBinding;
use crate::summary::{Summary, is_resolvable, substitute_resource_expr};
use crate::word::{Word, WordPart};
use crate::{
    ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef, ValueArgument,
    ValueOrigin, bind_arguments, substitute_value,
};
use definitions::{
    collect_class_bases, collect_class_sets, collect_class_strings, collect_classes, collect_defs,
    collect_path_attrs, collect_returns, decorator_names,
};
use import_bindings::import_from_module;
use model::{Receiver, ReceiverKind, path_object_resource};
use resolve::{PythonImportNames, str_literal};

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
struct PythonSummaryCapture {
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
    /// `effects` slots a `print` in the body writes to stdout.
    stdout: Vec<u32>,
    /// The body's reachable returns, by statement range, with the
    /// parameter guards on each path (see [`returns::reachable_returns`]).
    live_returns: std::collections::HashMap<TextRange, Vec<returns::ReturnPathGuard>>,
    /// Locals that may still hold a value the caller passed, with the
    /// parameters that value came from: each parameter starts as its own,
    /// and `x = p` makes `x` hold `p`'s argument too.
    params: std::collections::HashMap<String, Vec<String>>,
    /// What each reachable `return` in the body passes back.
    returned: Vec<ReturnSite>,
    /// What each same-file call in the body returns, by the call's span.
    call_returns: std::collections::HashMap<TextRange, Vec<CallReturn>>,
}

/// What one reachable `return` passes back to a caller: the effects whose
/// bytes its value carries and the parameters whose argument it returns,
/// when its path's parameter guards hold.
#[derive(Clone, PartialEq)]
struct ReturnSite {
    guards: Vec<returns::ReturnPathGuard>,
    effects: Vec<u32>,
    params: Vec<String>,
}

/// A return site of `callee` as one call site received it, its effects
/// mapped to the caller's slots.
#[derive(Clone)]
struct CallReturn {
    callee: String,
    site: ReturnSite,
}

/// The argument a call binds to one parameter of a same-file callable.
enum PythonBoundArgument {
    /// The call's argument at this position among its positional and then
    /// keyword arguments.
    Index(usize),
    Default(Rc<Expr>),
    /// Unpacked arguments may bind it.
    Unknown,
    Missing,
}

/// A call's positional arguments, then its keyword values.
fn call_arguments(call: &ast::ExprCall) -> Vec<&Expr> {
    call.args
        .iter()
        .chain(call.keywords.iter().map(|keyword| &keyword.value))
        .collect()
}

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
/// the elements and keys of a literal container, and the arms of a
/// conditional expression its literal test does not rule out. A call to a
/// local function or method (`is_local`) is not on the spine, because the
/// reads inside it need not be what it returns; it goes to `locals`, whose
/// summary says what it returns.
fn value_spine<'e>(
    expr: &'e Expr,
    is_local: &dyn Fn(&Expr) -> bool,
    spans: &mut Vec<TextRange>,
    locals: &mut Vec<&'e ast::ExprCall>,
    names: &mut Vec<&'e str>,
) {
    let mut spine = |e: &'e Expr| value_spine(e, is_local, spans, locals, names);
    match expr {
        Expr::Name(name) => names.push(name.id.as_str()),
        Expr::Call(call) if is_local(&call.func) => locals.push(call),
        Expr::Call(call) => {
            spans.push(call.range);
            if let Expr::Attribute(attribute) = call.func.as_ref()
                && matches!(attribute.value.as_ref(), Expr::Call(_))
            {
                value_spine(&attribute.value, is_local, spans, locals, names);
            }
        }
        Expr::Attribute(attribute) if matches!(attribute.attr.as_str(), "text" | "content") => {
            spine(&attribute.value);
        }
        Expr::List(list) => list.elts.iter().for_each(spine),
        Expr::Tuple(tuple) => tuple.elts.iter().for_each(spine),
        Expr::Set(set) => set.elts.iter().for_each(spine),
        Expr::Dict(dict) => dict
            .keys
            .iter()
            .flatten()
            .chain(&dict.values)
            .for_each(spine),
        Expr::Starred(starred) => spine(&starred.value),
        Expr::IfExp(branch) => match control::truthy(&branch.test) {
            Some(true) => spine(&branch.body),
            Some(false) => spine(&branch.orelse),
            None => {
                spine(&branch.body);
                spine(&branch.orelse);
            }
        },
        _ => {}
    }
}

/// A literal that iterates at least once: a nonempty string or a container
/// display with at least one element and no unpacking.
fn literal_nonempty(iter: &Expr) -> bool {
    let elements = match iter {
        Expr::List(list) => &list.elts,
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::Set(set) => &set.elts,
        Expr::Dict(dict) => return dict.keys.iter().any(Option::is_some),
        Expr::Constant(constant) => {
            return matches!(&constant.value, ast::Constant::Str(text) if !text.is_empty());
        }
        _ => return false,
    };
    !elements.is_empty()
        && !elements
            .iter()
            .any(|element| matches!(element, Expr::Starred(_)))
}

/// The names of a `a, b = p, q` target each paired with its element of a
/// literal value of the same length, when neither side unpacks with `*`.
fn literal_unpack<'v>(target: &Expr, value: &'v Expr) -> Vec<(String, &'v Expr)> {
    let names = match target {
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::List(list) => &list.elts,
        _ => return Vec::new(),
    };
    let elements = match value {
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::List(list) => &list.elts,
        _ => return Vec::new(),
    };
    if names.len() != elements.len()
        || elements
            .iter()
            .any(|element| matches!(element, Expr::Starred(_)))
    {
        return Vec::new();
    }
    names
        .iter()
        .zip(elements)
        .filter_map(|(name, element)| match name {
            Expr::Name(name) => Some((name.id.to_string(), element)),
            _ => None,
        })
        .collect()
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
        python_boundary(
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
            python_boundary(
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
        let (mut walker, classes) = PythonWalker::for_execution(
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
            python_boundary(
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

impl<'a, 'b> PythonWalker<'a, 'b> {
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
        let walker = PythonWalker {
            builder,
            nest,
            source,
            condition_source: effinterp_proto::ConditionSource::new(source),
            cwd: cwd.map(str::to_string),
            cwd_node,
            chdir: None,
            scope,
            depth,
            imports: PythonImportNames::default(),
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
            summary_returns: std::collections::HashMap::new(),
            call_returns: std::collections::HashMap::new(),
            module_binds: HashSet::new(),
            environment_rewritten: false,
            ipython: ipython.map(|cell| ipython::IpythonState {
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
    imports: &PythonImportNames,
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

struct PythonWalker<'a, 'b> {
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
    imports: PythonImportNames,
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
    capture: Option<PythonSummaryCapture>,
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
    summary_stdout: std::collections::HashMap<String, Vec<u32>>,
    /// What each callable's reachable returns pass back.
    summary_returns: std::collections::HashMap<String, Vec<ReturnSite>>,
    /// What each same-file call walked outside a summary returns, in plan
    /// effects, by the call's span, until its value is bound.
    call_returns: std::collections::HashMap<TextRange, Vec<CallReturn>>,
    /// Module-level names that shadow builtins, including assignments and imports.
    module_binds: HashSet<String>,
    /// Whether the program has replaced an environment value, after which a
    /// value the host supplied no longer describes what a read sees.
    environment_rewritten: bool,
    ipython: Option<ipython::IpythonState>,
    /// Whether a bare `bash(...)` call is Prime Agent's injected shell helper.
    prime_bash: bool,
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

impl PythonWalker<'_, '_> {
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
                python_boundary(
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
            self.chdir = Some(unresolved_resource("filesystem"));
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
        python_boundary(
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
        let before = self.capture.as_ref().map(|capture| capture.effects.len());
        self.walk_deferred(iter);
        // In a summarized body a single loop target holds an element of
        // `iter`: an item of a list, a line of a file, a key of a dict.
        // Unpacked targets are not projected.
        let element = before.map(|before| match (target, iter) {
            (Expr::Name(_), Expr::Dict(dict)) => dict
                .keys
                .iter()
                .flatten()
                .flat_map(|key| self.carried_effects(key, before))
                .collect(),
            (Expr::Name(_), _) => self.carried_effects(iter, before),
            _ => Vec::new(),
        });
        let rebound = rebound_target_names(target);
        let prior_printed = self.printed_by(&rebound);
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
        if let Some(element) = element {
            self.rebind_printed(&rebound, &element);
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
        // After the loop the target may still hold its prior value, unless a
        // nonempty literal proves the loop ran and no enclosing branch can be
        // skipped.
        if !literal_nonempty(iter) || self.capture_conditional() {
            self.restore_printed(prior_printed);
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
        if self.capture.is_some() {
            self.rebind_printed(&rebound_target_names(target), &[]);
        }
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
        let rebound: Vec<_> = items
            .iter()
            .filter_map(|item| item.optional_vars.as_deref())
            .flat_map(rebound_target_names)
            .collect();
        let prior_printed = self.printed_by(&rebound);
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
        // Paths skipping an enclosing branch keep the targets' prior values.
        if self.capture_conditional() {
            self.restore_printed(prior_printed);
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
                        python_boundary(
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
                    let mut effects = self.capture_value(value);
                    effects.sort_unstable();
                    effects.dedup();
                    let params = self.returned_params(value);
                    if let Some(capture) = self.capture.as_mut()
                        && let Some(guards) = capture.live_returns.get(&s.range)
                        && !(effects.is_empty() && params.is_empty())
                    {
                        let site = ReturnSite {
                            guards: guards.clone(),
                            effects,
                            params,
                        };
                        if !capture.returned.contains(&site) {
                            capture.returned.push(site);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_expr(&mut self, expr: &Expr) {
        // Keep guarded expression spines iterative as well as ordinary expressions.
        enum PythonExprWork<'a> {
            Expr(&'a Expr),
            AttributeBase(&'a Expr),
            Push(&'a Expr, effinterp_proto::ConditionKind, u32),
            Pop(usize),
        }
        let initial_depth = self.builder.condition_depth();
        let mut stack = vec![PythonExprWork::Expr(expr)];
        while let Some(work) = stack.pop() {
            let attribute_base = matches!(work, PythonExprWork::AttributeBase(_));
            let expr = match work {
                PythonExprWork::Expr(expr) | PythonExprWork::AttributeBase(expr) => expr,
                PythonExprWork::Push(origin, kind, arm) => {
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
                PythonExprWork::Pop(count) => {
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
                    stack.push(PythonExprWork::Pop(1));
                    stack.push(PythonExprWork::Expr(body));
                    stack.push(PythonExprWork::Push(
                        expr,
                        effinterp_proto::ConditionKind::Branch,
                        arm,
                    ));
                }
                stack.push(PythonExprWork::Expr(&branch.test));
                continue;
            }
            if let Expr::BoolOp(branch) = expr {
                stack.push(PythonExprWork::Pop(branch.values.len().saturating_sub(1)));
                for (index, body) in branch.values.iter().enumerate().rev() {
                    stack.push(PythonExprWork::Expr(body));
                    if index > 0 {
                        stack.push(PythonExprWork::Push(
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
                    .unwrap_or_else(|| unresolved_resource("environment"));
                let node = self.span_node(sub.range);
                self.emit("environment.read", resource, &[], node);
            }
            for child in child_exprs(expr).into_iter().rev() {
                // Reading a module attribute does not itself escape its owner.
                stack.push(if matches!(expr, Expr::Attribute(_)) {
                    PythonExprWork::AttributeBase(child)
                } else {
                    PythonExprWork::Expr(child)
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
}

/// The program a runtime runs a shell command string with: `/bin/sh` unless
/// the call selected another shell.
pub(super) fn shell_program(shell: Option<&ResourceExpr>) -> ResourceExpr {
    shell.cloned().unwrap_or_else(|| ResourceExpr::Literal {
        value: "/bin/sh".to_string(),
    })
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

fn overlay_sequence_bindings(
    bindings: &mut std::collections::HashMap<String, SemanticValue>,
    params: &[String],
    call: &ast::ExprCall,
    walker: &PythonWalker<'_, '_>,
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
        Some(Applet::Foreign) => argv.insert(1, unresolved_resource("process")),
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
            | DeferredSpawn::Shell { .. } => unresolved_resource("process"),
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
        return unresolved_resource("process");
    };
    if program.is_empty() || program == "?" {
        return unresolved_resource("process");
    }
    let executable = program.rsplit('/').next().unwrap_or(&program);
    if executable.is_empty() {
        return unresolved_resource("process");
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

fn python_boundary(
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
