//! Effect-directed Go frontend.
//!
//! Parses Go source with the pure-Rust `gosyn` parser (v0.2) and walks the AST
//! for calls into effect-relevant standard-library packages — `os`, `os/exec`,
//! `io/ioutil`, `net/http`, `database/sql`. It does not interpret Go; it follows
//! only what reaches an effect boundary, keeps non-literal arguments symbolic,
//! resolves a call to a modeled API only when the qualifying identifier is an
//! imported effect package (ownership), and records an explicit boundary for
//! anything dynamic (`reflect`, `plugin`, `unsafe`).
//!
//! ## Execution, not source presence
//!
//! The plan describes what EXECUTING the file does: package-level variable
//! initializers, `init` functions, and `main`, following calls into locally
//! defined functions via a within-file call graph. A defined-but-never-reached
//! function contributes nothing to execution; its parameterized summary is
//! still exposed through [`crate::module_summary::module_summaries`] for cross-file composition.

mod control;
mod model;
mod summary;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
pub use model::go_external_effects;

pub(crate) use model::go_callback_positions;
use model::string_of;
use summary::{
    BlockWrites, EscapedCallables, GoFunc, Imports, addressed_name, allocated_class,
    assigned_outer_names, assignment_base_name, collect_funcs, collect_imports, compute_summaries,
    constructed_class, construction_site, declared_callable_names, declared_type_names,
    escaped_address_names, escaped_callables, field_types, function_locals, go_dispatch_contracts,
    init_names, is_callback_field, is_str_lit, literal_function_name, named_type, named_type_ref,
    package_var_names, reassigned_names, returns_instances, unambiguous, unquote,
};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
    Subject,
};
use gosyn::ast::{BlockStmt, DeclStmt, Declaration, Element, Expression, File, FuncLit, Statement};
use gosyn::token::Operator;

use crate::builder::PlanBuilder;
use crate::control_flow::{
    ControlCaps, ControlExit, ControlFact, ControlFlow, ControlStack, SiteFacts,
};
use crate::module_summary::{CallEdge, DispatchContract, call_results};
use crate::nest::{Nest, Transition};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::{Summary, bind_positional, substitute_resource_expr};
use crate::value::{
    anchor_fs_text_concat, sink_typed_join, typed_concat, unresolved_resource,
    url_endpoint_resource,
};
use crate::{
    CallableValue, ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef,
    ValueArgument, ValueOrigin, join_branches, merge_arguments, positional_arguments,
};

/// Effect domains this frontend can surface. Declared partial after a parse:
/// only a subset of Go's effect surface is modeled.
const GO_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

/// Summary fixpoint iterations before freezing (recursion terminates anyway).
const MAX_SUMMARY_ITERS: usize = 5;
/// Cap on effects/edges retained per summary.
const MAX_SUMMARY_ITEMS: usize = 128;

pub(crate) fn registrations(
    source: &str,
    path: &str,
    max_bytes: u64,
) -> Result<Vec<crate::Registration>, &'static str> {
    let file = gosyn::parse_source(source).map_err(|_| "parse_error: registration scan")?;
    let imports = collect_imports(&file);
    let mut funcs = collect_funcs(&file);
    let (registrations, _, limit) =
        summary::cobra_registrations(&file, &imports, &mut funcs, path, max_bytes);
    match limit {
        Some(limit) => Err(limit),
        None => Ok(registrations),
    }
}

pub(crate) struct GoFrontend;

impl Frontend for GoFrontend {
    const LANGUAGE: &'static str = "go";
    const DOMAINS: &'static [&'static str] = &GO_DOMAINS;
    type Ast<'a> = gosyn::ast::File;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        match gosyn::parse_source(source) {
            Ok(ast) => ParseOutcome {
                ast: Some(ast),
                failure: None,
            },
            Err(_) => ParseOutcome {
                ast: None,
                failure: Some(ParseFailure {
                    detail: "go source did not parse".to_string(),
                }),
            },
        }
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        file: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        let selected_registration = nest.registration.is_some() && builder.execution_depth() == 1;
        let imports = collect_imports(file);
        let mut funcs = collect_funcs(file);
        let (_, callback_roots, registration_limit) = summary::cobra_registrations(
            file,
            &imports,
            &mut funcs,
            "",
            nest.limits.max_analysis_bytes,
        );
        if let Some(limit) = registration_limit {
            builder.note_saturated_at(limit, None);
        }
        let declared_callables = declared_callable_names(file, &funcs);
        let dispatch_contracts = go_dispatch_contracts(file, &imports, file.pkg_name.name.as_str());
        let summaries = compute_summaries(
            input.source,
            &imports,
            &funcs,
            &dispatch_contracts,
            Some(file),
            "",
            None,
            Some((builder, nest.budget)),
            nest.limits.value_limits(),
        );

        builder.boundary(Boundary {
            reason: BoundaryReason::FRONTEND_PARTIAL,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: GO_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: scope.as_slice().to_vec(),
            limit: None,
            detail: Some("go frontend models selected effect APIs".to_string()),
        });

        let max_nodes = nest.limits.max_go_nodes;
        let first_effect = builder.effects_len();
        let entry_names: Vec<String> = init_names(file)
            .into_iter()
            .chain((!selected_registration).then(|| "main".to_string()))
            .filter(|name| funcs.contains_key(name))
            .collect();
        let import_spans: Vec<_> = file
            .imports
            .iter()
            .filter(|import| !crate::external::is_go_stdlib(&unquote(&import.path.value)))
            .map(control::import_span)
            .collect();
        {
            let bodies: Vec<&BlockStmt> =
                entry_names.iter().map(|name| &funcs[name].body).collect();
            builder.control_enter(input.source, false, |graph| {
                control::build_program(graph, file, &import_spans, &bodies)
            });
        }
        let condition_source = effinterp_proto::ConditionSource::new(input.source);
        let mut w = GoWalker {
            value_limits: nest.limits.value_limits(),
            source: input.source,
            condition_source: &condition_source,
            conditions: Vec::new(),
            out: Out::Plan {
                builder,
                nest,
                cwd,
                cwd_node,
                depth,
            },
            analysis_budget: None,
            imports: &imports,
            funcs: &funcs,
            summaries: &summaries,
            params: HashMap::new(),
            local_types: HashMap::new(),
            dispatch_contracts: &dispatch_contracts,
            scope,
            following: HashSet::new(),
            entered_callables: HashSet::new(),
            callback_roots,
            struct_fields: summary::struct_field_types(file),
            package_constants: HashMap::new(),
            package_types: HashMap::new(),
            collect_edges: false,
            capture_external_effects: false,
            binds_next_call: Vec::new(),
            current_binds: Vec::new(),
            nodes: 0,
            max_nodes,
            walk_depth: 0,
            truncated: false,
            fact_file: String::new(),
            fact_scope: None,
            fact_function: String::new(),
            repo_types: declared_type_names(file),
            site_ordinal: 0,
            package_vars: HashSet::new(),
            local_origins: HashMap::new(),
            instance_aliases: HashMap::new(),
            construction_origins: HashMap::new(),
            bound_vars: HashSet::new(),
            local_vars: HashSet::new(),
            channel_values: HashMap::new(),
            resource_values: HashMap::new(),
            values: HashMap::new(),
            local_scopes: Vec::new(),
            pending_writes: Vec::new(),
            address_aliases: HashMap::new(),
            reassigned_scopes: Vec::new(),
            aliased_scopes: Vec::new(),
            called_scopes: Vec::new(),
            escaped_scopes: Vec::new(),
            control_applications: Vec::new(),
        };
        for import in &file.imports {
            let path = unquote(&import.path.value);
            if !crate::external::is_go_stdlib(&path) {
                let node = w.node((
                    import.path.pos as u32,
                    (import.path.pos + import.path.value.len()) as u32,
                ));
                w.out_boundary(Boundary {
                    reason: BoundaryReason::UNMODELED_IMPORT,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: Some(effinterp_proto::CalleeReference {
                        module: path.clone(),
                        symbol: "__module_init__".to_string(),
                    }),
                    domains: crate::external::ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: vec![node],
                    limit: None,
                    detail: Some(format!("package initialization for {path}")),
                });
                w.control_register(
                    control::import_span(import),
                    SiteFacts {
                        exit: Some(ControlExit::Import { module: path }),
                        ..SiteFacts::known(Vec::new())
                    },
                );
            }
        }
        // Execution roots: package-level var initializers, then init(), then main().
        w.walk_var_initializers(file);
        // The initializers ran, but their values do not survive into the functions:
        // any file of the package - including this one, in an init() or a callee -
        // may assign a package variable before the walked function reads it, and a
        // single-file walk cannot order those assignments. Composition, which sees
        // the whole package and every assignment to the name, decides whether the
        // declaration is the package's value.
        for name in package_var_names(file) {
            w.values.remove(&name);
        }
        for name in entry_names {
            if let Some(f) = funcs.get(&name) {
                w.entered_callables.insert(name.clone());
                w.fact_function = name.clone();
                w.local_types.extend(f.types.clone());
                w.control_enter(&f.body);
                w.walk_block(&f.body);
                w.control_leave();
                if let Some(application) = w.control_applications.pop() {
                    w.control_register(control::body_span(&f.body), application);
                }
            }
        }
        if selected_registration {
            w.callback_roots.clear();
        }
        while let Some(name) = w.callback_roots.pop_first() {
            if !w.entered_callables.contains(&name)
                && let Some(function) = funcs.get(&name)
            {
                let node = w.node((function.body.pos.0 as u32, function.body.pos.1 as u32));
                w.call_local(&name, &[], node, None, false, None);
            }
        }
        w.control_applications.clear();
        if let Out::Plan { builder, .. } = &mut w.out {
            builder.control_leave();
        }
        let entered_callables = !w.entered_callables.is_empty();
        drop(w);
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
        value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summary::summarize_ast(source, ast, file, scope, value_limits)
    }
}

// ---------------------------------------------------------------------------
// The walker: emits to the plan (execution) or collects into a summary.

#[derive(Default)]
struct Capture {
    control: ControlStack,
    flow: ControlFlow,
    call_sites: BTreeMap<crate::control_flow::Span, u32>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    coverage: Vec<(Domain, CoverageLevel)>,
    edges: Vec<CallEdge>,
    returns: Vec<SemanticValue>,
}

enum Out<'a, 'b> {
    Plan {
        builder: &'a mut PlanBuilder,
        nest: &'a Nest<'b>,
        cwd: Option<&'a str>,
        cwd_node: Option<ProvenanceRef>,
        depth: u64,
    },
    Capture(&'a mut Capture),
}

/// The caller bindings one call may overwrite, split by how: storage handed to
/// the callee, which may be replaced wholesale, and the receiver of a method,
/// which is assigned through in place.
struct CallWrites {
    handed: Vec<String>,
    receiver: Vec<String>,
}

impl CallWrites {
    fn names(&self) -> Vec<String> {
        let mut names = self.handed.clone();
        for name in &self.receiver {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }
}

struct GoWalker<'a, 'b> {
    value_limits: crate::ValueLimits,
    source: &'a str,
    condition_source: &'a effinterp_proto::ConditionSource,
    conditions: Vec<effinterp_proto::Condition>,
    out: Out<'a, 'b>,
    /// Summary walks performed during a live analysis debit the same global
    /// step pool as the plan-emitting walk. Repository summary extraction has
    /// no plan budget and leaves this empty.
    analysis_budget: Option<(&'a mut PlanBuilder, &'b crate::nest::Budget)>,
    imports: &'a Imports,
    funcs: &'a HashMap<String, GoFunc>,
    summaries: &'a HashMap<String, Summary>,
    params: HashMap<String, ResourceExpr>,
    /// Local / parameter / receiver name -> named type as written. Seeded from
    /// declared types and updated by composite-literal assignment.
    local_types: HashMap<String, String>,
    /// Interface contracts used only by single-file analysis to keep deferred
    /// repository dispatch explicit. Module summaries leave this empty because
    /// the linker resolves their bounded candidate sets.
    dispatch_contracts: &'a [DispatchContract],
    scope: Option<ProvenanceRef>,
    /// Local functions currently being inlined, to break recursion.
    following: HashSet<String>,
    /// Functions and methods entered while building the live execution plan.
    entered_callables: HashSet<String>,
    callback_roots: BTreeSet<String>,
    struct_fields: HashMap<String, String>,
    package_constants: HashMap<String, SemanticValue>,
    package_types: HashMap<String, String>,
    /// When set, local calls are recorded as edges (for module_summaries)
    /// instead of being inlined.
    collect_edges: bool,
    /// Package initializer capture needs both ordinary call facts and the
    /// modeled direct effects that run before init bodies.
    capture_external_effects: bool,
    /// Locals receiving the next top-level call's results (`x, err :=
    /// f(...)`), attached to that call's edge so the composer can type them
    /// from the callee's constructed returns.
    binds_next_call: Vec<(usize, String)>,
    /// The binds for the call edge currently being recorded.
    current_binds: Vec<(usize, String)>,
    nodes: u64,
    max_nodes: u64,
    walk_depth: u32,
    truncated: bool,
    fact_file: String,
    fact_scope: Option<ScopeKey>,
    fact_function: String,
    repo_types: HashSet<String>,
    site_ordinal: u32,
    package_vars: HashSet<String>,
    local_origins: HashMap<String, ValueOrigin>,
    instance_aliases: HashMap<String, SemanticValue>,
    construction_origins: HashMap<(usize, usize), ValueOrigin>,
    bound_vars: HashSet<String>,
    local_vars: HashSet<String>,
    channel_values: HashMap<String, ResourceExpr>,
    resource_values: HashMap<String, ResourceExpr>,
    values: HashMap<String, SemanticValue>,
    local_scopes: Vec<HashMap<String, LocalBinding>>,
    /// Caller bindings the call currently being recorded may overwrite,
    /// attached to its edge so composition invalidates them too.
    pending_writes: Vec<String>,
    /// `p := &cfg`: a name -> the binding whose storage it addresses, so a
    /// write through the pointer invalidates the variable as well.
    address_aliases: HashMap<String, String>,
    /// Per open block, the names it reassigns anywhere below: what a deferred
    /// or concurrent body reads at a moment this walk cannot order.
    reassigned_scopes: Vec<HashSet<String>>,
    /// Per open block, the pointers its text binds, wherever it binds them: a
    /// write through one reaches the same storage from an out-of-order body
    /// even when the pointer is bound after that body's statement.
    aliased_scopes: Vec<Vec<(String, String)>>,
    /// Per open block, the calls its text states. A call writes the storage it
    /// is handed and the receiver it assigns through, which reaches an
    /// out-of-order body wherever the block states the call.
    called_scopes: Vec<Vec<gosyn::ast::Call>>,
    /// Per open block, the callables its text hands to storage this walk does
    /// not follow. One of them runs at a moment nothing here can order, so
    /// what it writes — a method value's receiver above all — reaches an
    /// out-of-order body wherever the block states the escape.
    escaped_scopes: Vec<EscapedCallables>,
    /// Guarantees of bodies entered since the enclosing call began.
    control_applications: Vec<SiteFacts>,
}

fn restore_map_entry<T>(map: &mut HashMap<String, T>, name: &str, value: Option<T>) {
    match value {
        Some(value) => {
            map.insert(name.to_string(), value);
        }
        None => {
            map.remove(name);
        }
    }
}

/// The exact value an object holds under `name`, whether it was assigned as a
/// property or supplied as a named field of the composite literal that built it.
fn exact_property(
    value: &SemanticValue,
    name: &str,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    // A branch that reassigns a field joins the objects into a union, and the
    // read is exact when every alternative answers it: the field holds one of a
    // finite set, which stays explicit instead of collapsing to an opaque
    // property the walk can no longer see a callable in.
    if let SemanticValueKind::Union(alternatives) = &value.kind {
        let values = alternatives
            .iter()
            .map(|alternative| exact_property(alternative, name, value_limits))
            .collect::<Option<Vec<_>>>()?;
        return Some(join_branches(values, value_limits));
    }
    let SemanticValueKind::Object(object) = &value.kind else {
        return None;
    };
    if let Some(property) = object.properties.get(name) {
        return Some(property.clone());
    }
    let ObjectIdentity::Class { constructor, .. } = &object.identity else {
        return None;
    };
    constructor
        .iter()
        .find(|argument| argument.name.as_deref() == Some(name))
        .map(|argument| argument.value.clone())
}

/// The value a `range` binds per iteration when the ranged expression is a
/// collection this walk knows: one of its elements, or nothing when it is empty
/// (an empty literal runs no iteration at all).
fn collection_element_value(
    value: SemanticValue,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    let SemanticValueKind::Collection { elements, .. } = value.kind else {
        return None;
    };
    (!elements.is_empty()).then(|| join_branches(elements, value_limits))
}

fn merge_value_maps(
    left: HashMap<String, SemanticValue>,
    right: HashMap<String, SemanticValue>,
    value_limits: crate::ValueLimits,
) -> HashMap<String, SemanticValue> {
    let names: HashSet<_> = left.keys().chain(right.keys()).cloned().collect();
    names
        .into_iter()
        .filter_map(|name| match (left.get(&name), right.get(&name)) {
            (Some(left), Some(right)) => Some((
                name,
                if left == right {
                    left.clone()
                } else {
                    join_branches([left.clone(), right.clone()], value_limits)
                },
            )),
            _ => None,
        })
        .collect()
}

/// Join the value maps produced by the clauses of a `switch` or `select`.
/// Without a default clause no clause need run, so the pre-branch values are an
/// outcome of their own.
fn join_clause_values(
    before: HashMap<String, SemanticValue>,
    outcomes: Vec<HashMap<String, SemanticValue>>,
    has_default: bool,
    value_limits: crate::ValueLimits,
) -> HashMap<String, SemanticValue> {
    let Some(merged) = outcomes
        .into_iter()
        .reduce(|left, right| merge_value_maps(left, right, value_limits))
    else {
        return before;
    };
    if has_default {
        merged
    } else {
        merge_value_maps(before, merged, value_limits)
    }
}

struct LocalBinding {
    was_local: bool,
    typ: Option<String>,
    origin: Option<ValueOrigin>,
    alias: Option<SemanticValue>,
    channel_value: Option<ResourceExpr>,
    resource_value: Option<ResourceExpr>,
    value: Option<SemanticValue>,
    was_bound: bool,
}

/// Go predeclared functions and type-conversion names a bare call can target
/// without naming repo code.
const GO_BUILTINS: [&str; 34] = [
    "make", "len", "cap", "append", "new", "delete", "copy", "close", "panic", "recover", "print",
    "println", "min", "max", "clear", "complex", "real", "imag", "string", "bool", "byte", "rune",
    "error", "any", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32",
    "uint64",
];
const GO_PREDECLARED_VALUES: [&str; 4] = ["nil", "true", "false", "iota"];

/// Predeclared type names. No package declares them, so a method call on one
/// reaches no body this repository could write.
const GO_PREDECLARED_TYPES: [&str; 22] = [
    "bool",
    "string",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
    "byte",
    "rune",
    "float32",
    "float64",
    "complex64",
    "complex128",
    "error",
    "any",
    "comparable",
];

/// Which package-level values a walk may read as exact.
///
/// A package `var`'s initializer describes only its declaration: any file of
/// the package may assign the name before the walked function runs, and a
/// single-file walk cannot see its siblings. So a function walk reads constants
/// only, and leaves a variable for composition, which knows the whole package
/// and refuses to substitute a name the package rebinds. The walk over the
/// package initializers themselves reads both, so the file still publishes each
/// variable's declared value for composition to judge.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PackageValues {
    Constants,
    Declarations,
}

impl GoWalker<'_, '_> {
    fn walk_var_initializers(&mut self, file: &File) {
        self.bind_package_state(file, PackageValues::Declarations);
        let variables: HashSet<_> = package_var_names(file).into_iter().collect();
        self.package_constants = self
            .values
            .iter()
            .filter(|(name, _)| !variables.contains(*name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        self.package_types = self.local_types.clone();
        for decl in &file.decl {
            if let Declaration::Variable(v) = decl {
                for spec in &v.specs {
                    if spec.values.is_empty()
                        && let Some(ty) = spec.typ.as_ref().and_then(named_type)
                    {
                        for name in &spec.name {
                            self.record_declared_construction(&name.name, &ty);
                        }
                    }
                    for (name, value) in spec.name.iter().zip(&spec.values) {
                        self.record_construction(&name.name, value);
                    }
                    for value in &spec.values {
                        self.walk_expr(value);
                    }
                }
            }
        }
    }

    /// Bind package-level declared and constructed types for function walks.
    fn bind_package_state(&mut self, file: &File, values: PackageValues) {
        for decl in &file.decl {
            let Declaration::Variable(v) = decl else {
                continue;
            };
            for spec in &v.specs {
                let decl_ty = spec.typ.as_ref().and_then(named_type);
                self.package_vars
                    .extend(spec.name.iter().map(|id| id.name.clone()));
                for (id, value) in spec.name.iter().zip(&spec.values) {
                    if self.local_vars.contains(&id.name) {
                        continue;
                    }
                    if let Some(ty) = constructed_class(value)
                        .or_else(|| self.assigned_class(value))
                        .or_else(|| decl_ty.clone())
                    {
                        self.local_types.insert(id.name.clone(), ty);
                    }
                }
                if spec.values.is_empty()
                    && let Some(ty) = &decl_ty
                {
                    for id in &spec.name {
                        if !self.local_vars.contains(&id.name) {
                            self.local_types.insert(id.name.clone(), ty.clone());
                        }
                    }
                }
            }
        }
        for decl in &file.decl {
            match decl {
                Declaration::Variable(declaration) => {
                    for spec in &declaration.specs {
                        self.package_vars
                            .extend(spec.name.iter().map(|id| id.name.clone()));
                        if values != PackageValues::Declarations {
                            continue;
                        }
                        for (id, value) in spec.name.iter().zip(&spec.values) {
                            if !self.local_vars.contains(&id.name) {
                                self.bind_value(&Expression::Ident(id.clone()), value);
                            }
                        }
                    }
                }
                Declaration::Const(declaration) => {
                    // A const spec that omits its expression list repeats the
                    // previous one (`const ( first = "/x"; second )`). Only a
                    // plain literal is repeated: `const ( a = iota; b )` gives
                    // b a value of its own.
                    let mut carried: &[Expression] = &[];
                    for spec in &declaration.specs {
                        self.package_vars
                            .extend(spec.name.iter().map(|id| id.name.clone()));
                        let values = if spec.values.is_empty() {
                            if !carried.iter().all(|v| matches!(v, Expression::BasicLit(_))) {
                                continue;
                            }
                            carried
                        } else {
                            carried = &spec.values;
                            &spec.values
                        };
                        for (id, value) in spec.name.iter().zip(values) {
                            if !self.local_vars.contains(&id.name) {
                                self.bind_value(&Expression::Ident(id.clone()), value);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn walk_block(&mut self, block: &BlockStmt) {
        let condition_depth = self.conditions.len();
        self.begin_local_scope();
        let mut writes = BlockWrites::default();
        reassigned_names(&block.list, &mut writes, 0);
        self.aliased_scopes.push(writes.alias_pairs());
        self.called_scopes.push(std::mem::take(&mut writes.calls));
        self.escaped_scopes
            .push(std::mem::take(&mut writes.callables));
        self.reassigned_scopes.push(writes.names);
        for stmt in &block.list {
            self.walk_stmt(stmt);
            if let Statement::If(branch) = stmt
                && matches!(branch.body.list.last(), Some(Statement::Return(_)))
            {
                self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: branch.pos as u32,
                        end: branch.body.pos.1 as u32,
                    },
                    effinterp_proto::ConditionKind::Branch,
                    1,
                    2,
                    true,
                    true,
                ));
            }
        }
        self.reassigned_scopes.pop();
        self.escaped_scopes.pop();
        self.called_scopes.pop();
        self.aliased_scopes.pop();
        self.end_local_scope();
        self.conditions.truncate(condition_depth);
    }

    fn begin_local_scope(&mut self) {
        self.local_scopes.push(HashMap::new());
    }

    fn end_local_scope(&mut self) {
        let bindings = self.local_scopes.pop().unwrap();
        for (name, binding) in bindings {
            if binding.was_local {
                self.local_vars.insert(name.clone());
            } else {
                self.local_vars.remove(&name);
            }
            restore_map_entry(&mut self.local_types, &name, binding.typ);
            restore_map_entry(&mut self.local_origins, &name, binding.origin);
            restore_map_entry(&mut self.instance_aliases, &name, binding.alias);
            restore_map_entry(&mut self.channel_values, &name, binding.channel_value);
            restore_map_entry(&mut self.resource_values, &name, binding.resource_value);
            restore_map_entry(&mut self.values, &name, binding.value);
            if binding.was_bound {
                self.bound_vars.insert(name.clone());
            } else {
                self.bound_vars.remove(&name);
            }
        }
    }

    /// Walk a literal with its parameters shadowing package and outer bindings.
    fn walk_function_literal(&mut self, literal: &FuncLit) {
        let types = field_types(&literal.typ.params);
        let mut shadowed = Vec::new();
        for name in literal
            .typ
            .params
            .list
            .iter()
            .flat_map(|field| field.name.iter().map(|id| id.name.clone()))
        {
            shadowed.push((
                name.clone(),
                self.local_vars.contains(&name),
                self.params.remove(&name),
                self.local_types.remove(&name),
                self.local_origins.remove(&name),
                self.instance_aliases.remove(&name),
                self.channel_values.remove(&name),
                self.resource_values.remove(&name),
                self.values.remove(&name),
                self.bound_vars.remove(&name),
            ));
            self.local_vars.insert(name.clone());
            self.params
                .insert(name.clone(), ResourceExpr::Parameter { name: name.clone() });
            self.values
                .insert(name.clone(), SemanticValue::parameter(&name));
            self.channel_values
                .insert(name.clone(), unresolved_resource("filesystem"));
            if let Some(typ) = types.get(&name) {
                self.local_types.insert(name, typ.clone());
            }
        }

        self.control_enter(&literal.body);
        self.walk_block(&literal.body);
        self.control_leave();

        for (
            name,
            was_local,
            param,
            typ,
            origin,
            alias,
            channel_value,
            resource_value,
            value,
            was_bound,
        ) in shadowed
        {
            if was_local {
                self.local_vars.insert(name.clone());
            } else {
                self.local_vars.remove(&name);
            }
            restore_map_entry(&mut self.params, &name, param);
            restore_map_entry(&mut self.local_types, &name, typ);
            restore_map_entry(&mut self.local_origins, &name, origin);
            restore_map_entry(&mut self.instance_aliases, &name, alias);
            restore_map_entry(&mut self.channel_values, &name, channel_value);
            restore_map_entry(&mut self.resource_values, &name, resource_value);
            restore_map_entry(&mut self.values, &name, value);
            if was_bound {
                self.bound_vars.insert(name.clone());
            } else {
                self.bound_vars.remove(&name);
            }
        }
    }

    fn walk_stmt(&mut self, stmt: &Statement) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        self.walk_depth += 1;
        self.walk_stmt_inner(stmt);
        self.walk_depth -= 1;
    }

    fn partial_walk(&mut self) {
        match &mut self.out {
            Out::Plan { builder, .. } => builder.control_widen(),
            Out::Capture(cap) => cap.control.widen(),
        }
        if self.truncated {
            return;
        }
        self.truncated = true;
        self.out_boundary(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: GO_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: self.scope.as_slice().to_vec(),
            limit: Some("max_walk_depth".to_string()),
            detail: Some("go walk depth bound reached".to_string()),
        });
        for d in GO_DOMAINS {
            self.out_coverage(Domain::new(d), CoverageLevel::Partial);
        }
    }

    fn walk_stmt_inner(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Expr(e) => self.walk_expr(&e.expr),
            Statement::Assign(a) => {
                let mut shadowed_names = HashSet::new();
                if a.op == Operator::Define {
                    for left in &a.left {
                        if let Expression::Ident(id) = left
                            && self.bind_local_name(&id.name)
                        {
                            shadowed_names.insert(id.name.clone());
                        }
                    }
                }
                // `x, err := f(...)`: remember which locals receive the call's
                // results, so its edge can type them from the callee's
                // constructed returns.
                if self.collect_edges
                    && a.right.len() == 1
                    && matches!(a.right[0], Expression::Call(_))
                {
                    self.binds_next_call = a
                        .left
                        .iter()
                        .enumerate()
                        .filter_map(|(i, l)| match l {
                            Expression::Ident(id) if id.name != "_" => Some((i, id.name.clone())),
                            _ => None,
                        })
                        .collect();
                    self.bound_vars
                        .extend(self.binds_next_call.iter().map(|(_, name)| name.clone()));
                }
                for (left, right) in a.left.iter().zip(&a.right) {
                    if let Expression::Ident(id) = left {
                        self.record_construction(&id.name, right);
                    }
                }
                for e in &a.right {
                    self.walk_expr(e);
                }
                self.binds_next_call.clear();
                for (left, right) in a.left.iter().zip(&a.right) {
                    // `m[k] = &c` / `h.C = &c` store the address in storage no
                    // name of this walk addresses; only `p = &c` is tracked.
                    if !matches!(left, Expression::Ident(_)) {
                        self.escape_addresses(right, false);
                    }
                    if !self.tracked_closure_binding(left, right) {
                        self.escape_callables(right, false);
                    }
                    self.bind_channel_alias(left, right, &shadowed_names);
                    self.bind_type(left, right);
                    self.bind_address_alias(left, right);
                    self.bind_resource(left, right);
                    self.bind_value(left, right);
                    self.invalidate_written_storage(left);
                }
                for left in a.left.iter().skip(a.right.len()) {
                    let Expression::Ident(id) = left else {
                        continue;
                    };
                    if id.name == "_" {
                        continue;
                    }
                    self.channel_values
                        .insert(id.name.clone(), unresolved_resource("filesystem"));
                    self.resource_values.remove(&id.name);
                    self.values.remove(&id.name);
                }
            }
            Statement::Declaration(DeclStmt::Variable(d)) => {
                for spec in &d.specs {
                    let mut shadowed_names = HashSet::new();
                    for id in &spec.name {
                        if self.bind_local_name(&id.name) {
                            shadowed_names.insert(id.name.clone());
                        }
                    }
                    let decl_ty = spec.typ.as_ref().and_then(named_type);
                    if spec.values.is_empty()
                        && let Some(ty) = &decl_ty
                    {
                        for name in &spec.name {
                            self.record_declared_origin(&name.name, ty);
                        }
                    }
                    if self.collect_edges
                        && spec.values.len() == 1
                        && matches!(spec.values[0], Expression::Call(_))
                    {
                        self.binds_next_call = spec
                            .name
                            .iter()
                            .enumerate()
                            .filter(|(_, id)| id.name != "_")
                            .map(|(i, id)| (i, id.name.clone()))
                            .collect();
                        self.bound_vars
                            .extend(self.binds_next_call.iter().map(|(_, name)| name.clone()));
                    }
                    for (name, value) in spec.name.iter().zip(&spec.values) {
                        self.record_construction(&name.name, value);
                    }
                    for value in &spec.values {
                        self.walk_expr(value);
                    }
                    self.binds_next_call.clear();
                    for (id, value) in spec.name.iter().zip(&spec.values) {
                        self.bind_channel_alias(
                            &Expression::Ident(id.clone()),
                            value,
                            &shadowed_names,
                        );
                        if let Some(ty) = constructed_class(value)
                            .or_else(|| self.assigned_class(value))
                            .or_else(|| decl_ty.clone())
                        {
                            self.local_types.insert(id.name.clone(), ty);
                        }
                        if !self.tracked_closure_binding(&Expression::Ident(id.clone()), value) {
                            self.escape_callables(value, false);
                        }
                        self.bind_address_alias(&Expression::Ident(id.clone()), value);
                        self.bind_resource(&Expression::Ident(id.clone()), value);
                        self.bind_value(&Expression::Ident(id.clone()), value);
                    }
                    if spec.values.is_empty()
                        && let Some(ty) = decl_ty
                    {
                        for id in &spec.name {
                            self.local_types.insert(id.name.clone(), ty.clone());
                        }
                    }
                }
            }
            Statement::Return(r) => {
                if r.ret.len() == 1
                    && let Some(value) = self.value_of(&r.ret[0])
                    && let Out::Capture(capture) = &mut self.out
                {
                    capture.returns.push(value);
                }
                for e in &r.ret {
                    self.walk_expr(e);
                }
            }
            Statement::If(i) => {
                self.begin_local_scope();
                if let Some(init) = &i.init {
                    self.walk_stmt(init);
                }
                self.walk_expr(&i.cond);
                let before = self.values.clone();
                let condition = effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: i.pos as u32,
                        end: i.body.pos.1 as u32,
                    },
                    effinterp_proto::ConditionKind::Branch,
                    0,
                    2,
                    true,
                    true,
                );
                self.push_condition(condition);
                self.walk_block(&i.body);
                self.conditions.pop();
                let body = self.values.clone();
                self.values = before.clone();
                if let Some(e) = &i.else_ {
                    self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                        self.source,
                        self.condition_source.digest().to_string(),
                        effinterp_proto::ByteSpan {
                            start: i.pos as u32,
                            end: i.body.pos.1 as u32,
                        },
                        effinterp_proto::ConditionKind::Branch,
                        1,
                        2,
                        true,
                        true,
                    ));
                    self.walk_stmt(e);
                    self.conditions.pop();
                }
                self.values = merge_value_maps(body, self.values.clone(), self.value_limits);
                self.end_local_scope();
            }
            Statement::For(f) => {
                self.begin_local_scope();
                if let Some(init) = &f.init {
                    self.walk_stmt(init);
                }
                if let Some(cond) = &f.cond {
                    self.walk_stmt(cond);
                }
                let before = self.values.clone();
                self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: f.body.pos.0 as u32,
                        end: f.body.pos.1 as u32,
                    },
                    effinterp_proto::ConditionKind::Loop,
                    0,
                    2,
                    true,
                    false,
                ));
                self.walk_block(&f.body);
                self.conditions.pop();
                if let Some(post) = &f.post {
                    self.walk_stmt(post);
                }
                self.values = merge_value_maps(before, self.values.clone(), self.value_limits);
                self.end_local_scope();
            }
            Statement::Range(r) => {
                self.begin_local_scope();
                self.walk_expr(&r.expr);
                // The pre-loop values are an outcome of their own: a range over
                // an empty collection runs no iteration, so a name the assign
                // form rebinds still holds what it held before the loop.
                let before = self.values.clone();
                if let Some((_, op)) = r.op {
                    // Each iteration rebinds the key and the value, so inside
                    // the body whatever they held before the loop is gone: the
                    // element of a known collection when the range names one,
                    // unknown otherwise.
                    let element = r
                        .value
                        .as_ref()
                        .and_then(|_| self.value_of(&r.expr))
                        .and_then(|value| collection_element_value(value, self.value_limits));
                    for expr in [r.key.as_ref(), r.value.as_ref()].into_iter().flatten() {
                        if let Expression::Ident(id) = expr {
                            if op == Operator::Define {
                                self.bind_local_name(&id.name);
                            }
                            if id.name != "_" {
                                self.channel_values
                                    .insert(id.name.clone(), unresolved_resource("filesystem"));
                                self.resource_values.remove(&id.name);
                                // The assign form rebinds a name that outlives
                                // the loop, so it must stay in the value map to
                                // be joined with its pre-loop value afterwards;
                                // the define form's name leaves with the scope.
                                if op == Operator::Define {
                                    self.values.remove(&id.name);
                                } else {
                                    self.values.insert(
                                        id.name.clone(),
                                        SemanticValue::unresolved("range_element"),
                                    );
                                }
                            }
                        }
                    }
                    if let Some(Expression::Ident(id)) = r.value.as_ref()
                        && id.name != "_"
                        && let Some(element) = element
                    {
                        self.values.insert(id.name.clone(), element);
                    }
                }
                self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: r.body.pos.0 as u32,
                        end: r.body.pos.1 as u32,
                    },
                    effinterp_proto::ConditionKind::Loop,
                    0,
                    2,
                    true,
                    false,
                ));
                self.walk_block(&r.body);
                self.conditions.pop();
                self.values = merge_value_maps(before, self.values.clone(), self.value_limits);
                self.end_local_scope();
            }
            Statement::Label(label) => self.walk_stmt(&label.stmt),
            Statement::Block(b) => self.walk_block(b),
            Statement::Go(g) => self.walk_deferred_call(&g.call, true),
            Statement::Defer(d) => {
                let facts = if self.deferred_may_recover(&d.call) {
                    SiteFacts::unknown()
                } else {
                    SiteFacts::known(Vec::new())
                };
                self.control_register(control::defer_span(d.pos), facts);
                self.walk_deferred_call(&d.call, false)
            }
            Statement::Send(send) => {
                self.walk_expr(&send.chan);
                self.walk_expr(&send.value);
                // A channel carries the address to a receiver this walk does
                // not follow.
                self.escape_addresses(&send.value, false);
                self.escape_callables(&send.value, false);
                self.widen_escaped_channel(&send.value);
                if let Some(channel) = channel_name(&send.chan) {
                    let value = self.fs_arg(&send.value);
                    match self.channel_values.get(channel) {
                        Some(previous) if previous != &value => {
                            self.channel_values
                                .insert(channel.to_string(), unresolved_resource("filesystem"));
                        }
                        None => {
                            self.channel_values.insert(channel.to_string(), value);
                        }
                        _ => {}
                    }
                } else {
                    self.widen_escaped_channel(&send.chan);
                }
            }
            Statement::Switch(s) => {
                self.begin_local_scope();
                if let Some(init) = &s.init {
                    self.walk_stmt(init);
                }
                if let Some(tag) = &s.tag {
                    self.walk_expr(tag);
                }
                let before = self.values.clone();
                let mut outcomes = Vec::new();
                let mut has_default = false;
                for (arm, clause) in s.block.body.iter().enumerate() {
                    has_default |= clause.list.is_empty();
                    self.values = before.clone();
                    self.begin_local_scope();
                    for expression in &clause.list {
                        self.walk_expr(expression);
                    }
                    self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                        self.source,
                        self.condition_source.digest().to_string(),
                        effinterp_proto::ByteSpan {
                            start: s.pos as u32,
                            end: s.block.pos.1 as u32,
                        },
                        effinterp_proto::ConditionKind::Branch,
                        arm as u32,
                        s.block.body.len() as u32
                            + u32::from(!s.block.body.iter().any(|c| c.list.is_empty())),
                        true,
                        false,
                    ));
                    for st in clause.body.iter() {
                        self.walk_stmt(st);
                    }
                    self.conditions.pop();
                    self.end_local_scope();
                    outcomes.push(self.values.clone());
                }
                self.values = join_clause_values(before, outcomes, has_default, self.value_limits);
                self.end_local_scope();
            }
            Statement::TypeSwitch(s) => {
                self.begin_local_scope();
                if let Some(init) = &s.init {
                    self.walk_stmt(init);
                }
                if let Some(tag) = &s.tag {
                    self.walk_stmt(tag);
                }
                let before = self.values.clone();
                let mut outcomes = Vec::new();
                let mut has_default = false;
                for (arm, clause) in s.block.body.iter().enumerate() {
                    has_default |= clause.list.is_empty();
                    self.values = before.clone();
                    self.begin_local_scope();
                    self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                        self.source,
                        self.condition_source.digest().to_string(),
                        effinterp_proto::ByteSpan {
                            start: s.pos as u32,
                            end: s.block.pos.1 as u32,
                        },
                        effinterp_proto::ConditionKind::Branch,
                        arm as u32,
                        s.block.body.len() as u32
                            + u32::from(!s.block.body.iter().any(|c| c.list.is_empty())),
                        true,
                        false,
                    ));
                    for st in clause.body.iter() {
                        self.walk_stmt(st);
                    }
                    self.conditions.pop();
                    self.end_local_scope();
                    outcomes.push(self.values.clone());
                }
                self.values = join_clause_values(before, outcomes, has_default, self.value_limits);
                self.end_local_scope();
            }
            Statement::Select(select) => {
                self.begin_local_scope();
                let before = self.values.clone();
                let mut outcomes = Vec::new();
                for (arm, clause) in select.body.body.iter().enumerate() {
                    self.values = before.clone();
                    self.begin_local_scope();
                    if let Some(comm) = &clause.comm {
                        match &**comm {
                            Statement::Send(send) => {
                                self.walk_expr(&send.chan);
                                self.walk_expr(&send.value);
                                self.widen_escaped_channel(&send.chan);
                                self.widen_escaped_channel(&send.value);
                            }
                            statement => self.walk_stmt(statement),
                        }
                    }
                    self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                        self.source,
                        self.condition_source.digest().to_string(),
                        effinterp_proto::ByteSpan {
                            start: select.body.pos.0 as u32,
                            end: select.body.pos.1 as u32,
                        },
                        effinterp_proto::ConditionKind::Dispatch,
                        arm as u32,
                        select.body.body.len() as u32,
                        true,
                        false,
                    ));
                    for statement in clause.body.iter() {
                        self.walk_stmt(statement);
                    }
                    self.conditions.pop();
                    self.end_local_scope();
                    outcomes.push(self.values.clone());
                }
                // A select without clauses blocks forever; otherwise exactly one
                // clause runs, so the pre-select values are not an outcome.
                self.values = join_clause_values(before, outcomes, true, self.value_limits);
                self.end_local_scope();
            }
            Statement::IncDec(inc_dec) => self.walk_expr(&inc_dec.expr),
            Statement::Declaration(DeclStmt::Const(declaration)) => {
                for expression in declaration.specs.iter().flat_map(|spec| &spec.values) {
                    self.walk_expr(expression);
                }
            }
            Statement::Empty(_)
            | Statement::Branch(_)
            | Statement::Declaration(DeclStmt::Type(_)) => {}
        }
    }

    fn walk_expr(&mut self, expr: &Expression) {
        self.escape_addresses(expr, true);
        self.escape_callables(expr, true);
        // Iterative: left-deep `+` / `&&` spines overflow the process stack
        // before the node cap can fire. Nested calls still go through
        // walk_call, which is depth-bounded separately.
        enum Work<'a> {
            Expr(&'a Expression),
            Push(&'a Expression, bool),
            Pop,
        }
        let initial_depth = self.conditions.len();
        let mut stack = vec![Work::Expr(expr)];
        while let Some(work) = stack.pop() {
            let expr = match work {
                Work::Expr(expr) => expr,
                Work::Push(origin, positive) => {
                    let (start, end) = expression_pos(origin);
                    self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                        self.source,
                        self.condition_source.digest().to_string(),
                        effinterp_proto::ByteSpan { start, end },
                        effinterp_proto::ConditionKind::ShortCircuit,
                        u32::from(!positive),
                        2,
                        true,
                        true,
                    ));
                    continue;
                }
                Work::Pop => {
                    self.conditions.pop();
                    continue;
                }
            };
            if self.over_node_budget(expression_pos(expr)) {
                self.partial_nodes();
                break;
            }
            match expr {
                Expression::Call(call) => self.walk_call(call),
                Expression::Paren(p) => stack.push(Work::Expr(&p.expr)),
                Expression::Operation(op) => {
                    if let Some(y) = &op.y {
                        if matches!(op.op, Operator::AndAnd | Operator::OrOr) {
                            stack.push(Work::Pop);
                            stack.push(Work::Expr(y));
                            stack.push(Work::Push(&op.x, op.op == Operator::AndAnd));
                        } else {
                            stack.push(Work::Expr(y));
                        }
                    }
                    stack.push(Work::Expr(&op.x));
                }
                Expression::Star(s) => stack.push(Work::Expr(&s.right)),
                Expression::Index(i) => {
                    stack.push(Work::Expr(&i.index));
                    stack.push(Work::Expr(&i.left));
                }
                Expression::IndexList(i) => {
                    for index in i.indices.iter().rev() {
                        stack.push(Work::Expr(index));
                    }
                    stack.push(Work::Expr(&i.left));
                }
                Expression::TypeAssert(t) => stack.push(Work::Expr(&t.left)),
                Expression::CompositeLit(cl) => {
                    self.record_inline_construction(expr);
                    self.walk_literal_value(&cl.val, 0);
                }
                _ => {}
            }
        }
        self.conditions.truncate(initial_depth);
    }

    /// One node against the frontend cap (`max_go_nodes`) and the shared
    /// analysis step budget; true means the walk must stop. Repository-only
    /// capture walks have no plan budget and obey only the frontend cap.
    fn over_node_budget(&mut self, span: (u32, u32)) -> bool {
        let charged = match &mut self.out {
            Out::Plan { builder, nest, .. } => {
                crate::nest::charge_analysis_steps(builder, nest.budget, 1, Some(span))
            }
            Out::Capture(_) => match &mut self.analysis_budget {
                Some((builder, budget)) => {
                    crate::nest::charge_analysis_steps(builder, budget, 1, Some(span))
                }
                None => true,
            },
        };
        if !charged {
            return true;
        }
        self.nodes += 1;
        !crate::limits::summary_step() || self.nodes > self.max_nodes
    }

    fn partial_nodes(&mut self) {
        let analysis_steps_saturated = match &self.out {
            Out::Plan { nest, .. } => nest.budget.steps_saturated(),
            Out::Capture(_) => self
                .analysis_budget
                .as_ref()
                .is_some_and(|(_, budget)| budget.steps_saturated()),
        };
        if analysis_steps_saturated {
            return;
        }
        if self.truncated {
            return;
        }
        self.truncated = true;
        self.out_boundary(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: GO_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: self.scope.as_slice().to_vec(),
            limit: Some("max_go_nodes".to_string()),
            detail: Some("go walk node budget exhausted".to_string()),
        });
        for d in GO_DOMAINS {
            self.out_coverage(Domain::new(d), CoverageLevel::Partial);
        }
    }

    fn walk_literal_value(&mut self, val: &gosyn::ast::LiteralValue, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        for kv in &val.values {
            match &kv.val {
                Element::Expr(Expression::FuncLit(_)) => {}
                Element::Expr(e) => self.walk_expr(e),
                Element::LitValue(inner) => self.walk_literal_value(inner, depth + 1),
            }
        }
    }

    fn bind_local_name(&mut self, name: &str) -> bool {
        if name == "_" {
            return false;
        }
        let binding = LocalBinding {
            was_local: self.local_vars.contains(name),
            typ: self.local_types.get(name).cloned(),
            origin: self.local_origins.get(name).cloned(),
            alias: self.instance_aliases.get(name).cloned(),
            channel_value: self.channel_values.get(name).cloned(),
            resource_value: self.resource_values.get(name).cloned(),
            value: self.values.get(name).cloned(),
            was_bound: self.bound_vars.contains(name),
        };
        let shadowed =
            self.local_scopes
                .last_mut()
                .is_some_and(|scope| match scope.entry(name.to_string()) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(binding);
                        true
                    }
                    std::collections::hash_map::Entry::Occupied(_) => false,
                });
        self.local_vars.insert(name.to_string());
        self.local_types.remove(name);
        self.local_origins.remove(name);
        self.instance_aliases.remove(name);
        self.channel_values.remove(name);
        self.resource_values.remove(name);
        self.values.remove(name);
        self.bound_vars.remove(name);
        self.address_aliases.remove(name);
        shadowed
    }

    /// Assignment provenance: a composite literal, a copy of an already-typed
    /// local, or an address of one types the destination for later method
    /// dispatch.
    fn bind_type(&mut self, left: &Expression, right: &Expression) {
        let Expression::Ident(id) = left else {
            return;
        };
        let alias = match right {
            Expression::Ident(src) if self.local_types.contains_key(&src.name) => {
                Some(self.recv_ref(&src.name))
            }
            _ => None,
        };
        let ty = constructed_class(right).or_else(|| self.assigned_class(right));
        if let Some(ty) = ty {
            self.local_types.insert(id.name.clone(), ty);
        }
        match alias {
            Some(instance) => {
                self.instance_aliases.insert(id.name.clone(), instance);
            }
            None => {
                self.instance_aliases.remove(&id.name);
            }
        }
    }

    /// `p := &cfg` makes `p` a second name for `cfg`'s storage: a callee that
    /// writes through the pointer leaves the variable stale too. Copying such
    /// a pointer (`q := p`) hands the same storage to a third name, so the copy
    /// joins the group; a copy of anything else is a value Go duplicates.
    fn bind_address_alias(&mut self, left: &Expression, right: &Expression) {
        let Expression::Ident(id) = left else {
            return;
        };
        self.address_aliases.remove(&id.name);
        let Some(target) = addressed_name(right).or_else(|| match right {
            Expression::Ident(src) if self.address_aliases.contains_key(&src.name) => {
                Some(src.name.clone())
            }
            _ => None,
        }) else {
            return;
        };
        if target != id.name {
            self.address_aliases.insert(id.name.clone(), target);
        }
    }

    /// A deferred call runs when the enclosing function returns, and a
    /// goroutine at a moment nothing in this walk observes. Neither reads the
    /// caller's bindings where it is written: a name an enclosing block
    /// reassigns holds no known value inside the callable's body, so the body
    /// is walked without it. Nothing the body writes reaches the statements
    /// that follow either — the deferred one runs after all of them, so they
    /// keep the values they had, while the concurrent one may run at any point
    /// among them, which costs the caller its exact view of what it assigns.
    fn walk_deferred_call(&mut self, call: &gosyn::ast::Call, concurrent: bool) {
        let escaped = if concurrent {
            self.escaped_storage_names(&call.func, false)
        } else {
            Vec::new()
        };
        let mut target = &*call.func;
        while let Expression::Paren(paren) = target {
            target = &paren.expr;
        }
        let values = self.values.clone();
        let resource_values = self.resource_values.clone();
        if let Expression::FuncLit(literal) = target {
            // The body's own calls are part of the enclosing block's stated
            // set, because another out-of-order body is unordered against
            // them; this one is not, so they are held out of its widening.
            let mut own = BlockWrites::default();
            reassigned_names(&literal.body.list, &mut own, 0);
            let own_calls: HashSet<(usize, usize)> =
                own.calls.iter().map(|call| call.pos).collect();
            // Only an immediately invoked literal is walked here; every other
            // target reaches a summary, which already answers for the bindings
            // it captured. The call's arguments are evaluated where the
            // statement stands, and widening them alongside the body costs
            // only precision.
            // A write through a pointer names the pointer, so every other
            // name over that same storage loses its value here too. The
            // enclosing blocks' text answers for the pointers, not the aliases
            // bound so far: the write is unordered against this body, and so
            // is the statement that binds the pointer it goes through.
            let mut names: Vec<String> = self.reassigned_scopes.iter().flatten().cloned().collect();
            for name in self
                .stated_call_writes(&own_calls)
                .into_iter()
                .chain(self.stated_callable_writes())
            {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            let stated: Vec<(String, String)> =
                self.aliased_scopes.iter().flatten().cloned().collect();
            let reassigned: Vec<String> = self.with_stated_storage(names, &stated);
            for name in reassigned {
                self.values.remove(&name);
                self.resource_values.remove(&name);
            }
        }
        self.walk_call(call);
        self.values = values;
        self.resource_values = resource_values;
        self.invalidate_escaped_storage(escaped);
    }

    /// `&x` handed to storage this walk does not follow — a composite literal,
    /// a collection element, an operand of some larger expression — is a second
    /// name for `x` that nothing here can track, so a later write through it
    /// would leave `x` stale. Only the direct forms are tracked (`p := &x` and
    /// a copy of `p`), so every other address costs `x` its exact contents. A
    /// direct call argument is exempt: `escaped_call_arguments` governs it with
    /// the callee's own write behaviour.
    fn escape_addresses(&mut self, expr: &Expression, exempt: bool) {
        let mut escaped = Vec::new();
        escaped_address_names(expr, exempt, &mut escaped, 0);
        self.invalidate_escaped_storage(escaped);
    }

    /// A callable handed to storage this walk does not follow runs where
    /// nothing here can see it, so what it writes of the caller's own bindings
    /// is stale from that point on: a function literal writes the outer names
    /// its body assigns, and a method value writes its receiver when the method
    /// assigns through it. `exempt` marks the positions the walk still follows,
    /// exactly as `escape_addresses` marks them for `&x`.
    fn escape_callables(&mut self, expr: &Expression, exempt: bool) {
        let names = self.escaped_storage_names(expr, exempt);
        self.invalidate_escaped_storage(names);
    }

    /// The caller bindings the callables in an expression may write once the
    /// expression hands them over.
    fn escaped_storage_names(&self, expr: &Expression, exempt: bool) -> Vec<String> {
        let mut escaped = EscapedCallables::default();
        escaped_callables(expr, exempt, &mut escaped, 0);
        self.escaped_callable_names(&escaped)
    }

    /// The caller bindings the callables the enclosing blocks hand over may
    /// write. A method value is the one that names a binding of its own: `run
    /// = b.Set` stores a second name for `b`'s storage, so a body this walk
    /// cannot place in program order reads `b` at a moment the method's write
    /// is not ordered against, exactly as it reads a name the block assigns.
    fn stated_callable_writes(&self) -> Vec<String> {
        let mut escaped = EscapedCallables::default();
        for scope in &self.escaped_scopes {
            escaped.merge(scope);
        }
        self.escaped_callable_names(&escaped)
    }

    /// Resolve handed-over callables to the caller bindings they write, which
    /// only this file's own declarations can answer.
    fn escaped_callable_names(&self, escaped: &EscapedCallables) -> Vec<String> {
        let mut names = escaped.closure_writes.clone();
        for name in &escaped.named_values {
            // A name this file registered a closure under carries that
            // closure's writes wherever it is stored, exactly as the literal
            // does; every other name holds nothing this walk can follow.
            let writes = self
                .named_func(name)
                .filter(|function| function.is_closure)
                .map(|function| function.assigns_outer.clone())
                .unwrap_or_default();
            for write in writes {
                if !names.contains(&write) {
                    names.push(write);
                }
            }
        }
        for (recv, method) in &escaped.method_values {
            // Only a method this file declares answers: every other selector of
            // this shape is a field read, which hands over the field's value
            // and not the storage behind it.
            if self
                .typed_method_key(recv, method)
                .and_then(|key| self.funcs.get(&key))
                .is_some_and(|function| function.writes_receiver)
                && !names.contains(recv)
            {
                names.push(recv.clone());
            }
        }
        names
    }

    /// A function literal bound to a plain name the file registered that
    /// closure under is the one callable the walk keeps following: `call_local`
    /// applies its writes where `f()` runs. Bound anywhere else — a field, a
    /// map entry, or a name a package function or a second closure already
    /// holds — it reaches a call site nothing here can connect to this body.
    fn tracked_closure_binding(&self, left: &Expression, right: &Expression) -> bool {
        let Expression::Ident(id) = left else {
            return false;
        };
        !matches!(right, Expression::FuncLit(_))
            || self
                .named_func(&id.name)
                .is_some_and(|function| function.is_closure)
    }

    /// Drop everything a binding held once storage it names may be written
    /// where the walk cannot see it.
    fn invalidate_escaped_storage(&mut self, names: Vec<String>) {
        if names.is_empty() {
            return;
        }
        for name in self.with_aliased_storage(names) {
            self.values.remove(&name);
            self.resource_values.remove(&name);
            self.local_origins.remove(&name);
            self.instance_aliases.remove(&name);
        }
    }

    /// The function a bare call name reaches, when this file binds exactly one
    /// body to it.
    fn named_func(&self, name: &str) -> Option<&GoFunc> {
        unambiguous(self.funcs, name)
    }

    /// A write reached THROUGH a name assigns storage the name only refers to,
    /// and another name may refer to the same storage: after `p := &c`,
    /// `p.Path = v` writes `c` too. `bind_value` keeps the written name exact
    /// for the one form it can follow (`x.f = v` on a plain name); every other
    /// name over that storage, and every form it cannot follow (`*p = v`,
    /// `(*p).f = v`, `xs[i] = v`), loses its exact contents.
    fn invalidate_written_storage(&mut self, target: &Expression) {
        if matches!(target, Expression::Ident(_)) {
            return;
        }
        let Some(base) = assignment_base_name(target) else {
            return;
        };
        let followed = matches!(target, Expression::Selector(selector)
            if matches!(&*selector.x, Expression::Ident(_)));
        for name in self.with_aliased_storage(vec![base.clone()]) {
            if followed && name == base {
                continue;
            }
            self.values.remove(&name);
            self.resource_values.remove(&name);
        }
    }

    fn bind_resource(&mut self, left: &Expression, right: &Expression) {
        let Expression::Ident(name) = left else {
            return;
        };
        if let Some(resource) = self.received_resource(right) {
            self.resource_values.insert(name.name.clone(), resource);
        } else {
            self.resource_values.remove(&name.name);
        }
    }

    fn bind_value(&mut self, left: &Expression, right: &Expression) {
        if !self.collect_edges
            && self.fact_scope.is_none()
            && let Expression::Selector(selector) = left
            && let Expression::Ident(base) = &*selector.x
            && self.package_vars.contains(&base.name)
            && is_callback_field(&selector.sel.name)
        {
            match right {
                Expression::Ident(name) if self.named_func(&name.name).is_some() => {
                    self.callback_roots.insert(name.name.clone());
                }
                Expression::FuncLit(literal) => {
                    self.callback_roots.insert(literal_function_name(literal));
                }
                _ => {}
            }
        }
        match left {
            Expression::Ident(name) if name.name != "_" => {
                let value = match right {
                    Expression::FuncLit(_) if self.named_func(&name.name).is_some() => {
                        Some(SemanticValue::callable(&name.name))
                    }
                    Expression::Call(call) => self
                        .deferred_callback_value(call)
                        .or_else(|| self.value_of(right)),
                    _ => self.value_of(right),
                }
                .or_else(|| {
                    matches!(right, Expression::Call(_)).then(|| SemanticValue::symbol(&name.name))
                });
                if let Some(value) = value {
                    self.values.insert(name.name.clone(), value);
                } else {
                    self.values.remove(&name.name);
                }
            }
            Expression::Selector(selector) => {
                let Expression::Ident(base) = &*selector.x else {
                    return;
                };
                let Some(value) = self.value_of(right) else {
                    return;
                };
                if let Some(base) = self.values.get_mut(&base.name)
                    && let SemanticValueKind::Object(object) = &mut base.kind
                {
                    object.properties.insert(selector.sel.name.clone(), value);
                }
            }
            _ => {}
        }
    }

    fn value_of(&self, expr: &Expression) -> Option<SemanticValue> {
        match expr {
            Expression::BasicLit(literal) if is_str_lit(literal) => {
                Some(SemanticValue::literal(unquote(&literal.value)))
            }
            Expression::Ident(ident) => self.values.get(&ident.name).cloned().or_else(|| {
                if self.named_func(&ident.name).is_some() {
                    Some(SemanticValue::callable(&ident.name))
                } else if self.local_vars.contains(&ident.name) {
                    Some(SemanticValue::symbol(&ident.name))
                } else if !GO_PREDECLARED_VALUES.contains(&ident.name.as_str())
                    && let Some(scope) = &self.fact_scope
                {
                    Some(SemanticValue::object(ObjectIdentity::ModuleBinding {
                        scope: scope.clone(),
                        name: ident.name.clone(),
                    }))
                } else {
                    None
                }
            }),
            Expression::Paren(paren) => self.value_of(&paren.expr),
            Expression::Operation(operation) if operation.y.is_none() => {
                self.value_of(&operation.x)
            }
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                // Keep the additive spine iterative because generated Go can be thousands deep.
                let mut expressions: Vec<&Expression> =
                    vec![operation.y.as_ref().unwrap().as_ref(), operation.x.as_ref()];
                let mut parts = Vec::new();
                while let Some(expression) = expressions.pop() {
                    match expression {
                        Expression::Paren(paren) => expressions.push(paren.expr.as_ref()),
                        Expression::Operation(operation)
                            if operation.op == Operator::Add && operation.y.is_some() =>
                        {
                            expressions.push(operation.y.as_ref().unwrap().as_ref());
                            expressions.push(operation.x.as_ref());
                        }
                        _ => parts.push(self.value_of(expression)?),
                    }
                }
                if parts.iter().any(|value| {
                    matches!(
                        &value.kind,
                        SemanticValueKind::Environment(_) | SemanticValueKind::Join(_)
                    ) || matches!(
                        &value.kind,
                        SemanticValueKind::Unresolved { family, .. } if family == "environment"
                    )
                }) {
                    Some(SemanticValue::new(SemanticValueKind::Join(parts)))
                } else {
                    None
                }
            }
            Expression::Star(star) => self.value_of(&star.right),
            Expression::Selector(selector) => {
                if let Expression::Ident(package) = &*selector.x
                    && (self.imports.contains_key(&package.name)
                        || self
                            .named_func(&format!("{}.{}", package.name, selector.sel.name))
                            .is_some())
                {
                    let name = format!("{}.{}", package.name, selector.sel.name);
                    return Some(if self.fact_scope.is_none() {
                        SemanticValue::callable(name)
                    } else {
                        SemanticValue::symbol(name)
                    });
                }
                if let Expression::Ident(receiver) = &*selector.x
                    && let Some(value) = self.values.get(&receiver.name).and_then(|value| {
                        exact_property(value, &selector.sel.name, self.value_limits)
                    })
                {
                    return Some(value);
                }
                if let Expression::Ident(receiver) = &*selector.x
                    && self.fact_function.split_once('.').is_some_and(|(typ, _)| {
                        self.dispatch_type(&receiver.name).as_deref() == Some(typ)
                    })
                {
                    return Some(SemanticValue::parameter(&selector.sel.name));
                }
                let base = match &*selector.x {
                    Expression::Ident(ident) => {
                        // An object whose field this walk knows exactly answers
                        // the read exactly, so a callable stored in a struct
                        // stays reachable when it is passed on.
                        if let Some(property) = self.values.get(&ident.name).and_then(|value| {
                            exact_property(value, &selector.sel.name, self.value_limits)
                        }) {
                            return Some(property);
                        }
                        self.recv_ref(&ident.name)
                    }
                    expression => self.value_of(expression)?,
                };
                Some(SemanticValue::new(SemanticValueKind::Property {
                    base: Box::new(base),
                    name: selector.sel.name.clone(),
                }))
            }
            Expression::Index(index) => {
                let value = self.value_of(&index.left)?;
                if let Expression::BasicLit(key) = &*index.index
                    && is_str_lit(key)
                    && let SemanticValueKind::Collection { properties, .. } = &value.kind
                {
                    return properties.get(&unquote(&key.value)).cloned();
                }
                let index = match &*index.index {
                    Expression::BasicLit(literal) => literal.value.parse::<usize>().ok()?,
                    _ => return None,
                };
                match value.kind {
                    SemanticValueKind::Collection { elements, .. } => elements.get(index).cloned(),
                    _ => None,
                }
            }
            Expression::CompositeLit(literal) => {
                if matches!(&*literal.typ, Expression::TypeMap(_)) {
                    let properties = literal
                        .val
                        .values
                        .iter()
                        .filter_map(|field| {
                            let Some(Element::Expr(key)) = &field.key else {
                                return None;
                            };
                            let Element::Expr(value) = &field.val else {
                                return None;
                            };
                            Some((string_of(key)?, self.value_of(value)?))
                        })
                        .collect();
                    return Some(SemanticValue::new(SemanticValueKind::Collection {
                        elements: Vec::new(),
                        properties,
                    }));
                }
                if matches!(
                    &*literal.typ,
                    Expression::TypeSlice(_) | Expression::TypeArray(_)
                ) {
                    return Some(self.collection_value(&literal.val));
                }
                let name = constructed_class(expr)?;
                let arguments = literal
                    .val
                    .values
                    .iter()
                    .enumerate()
                    .filter_map(|(index, field)| {
                        let value = match &field.val {
                            Element::Expr(value) => self.value_of(value)?,
                            Element::LitValue(value) => self.collection_value(value),
                        };
                        let name = match field.key.as_ref() {
                            Some(Element::Expr(Expression::Ident(name))) => Some(name.name.clone()),
                            _ => None,
                        };
                        Some(ValueArgument { name, index, value })
                    })
                    .collect();
                Some(
                    SemanticValue::object(ObjectIdentity::Class {
                        name: name.clone(),
                        constructor: arguments,
                    })
                    .with_type(self.type_ref(&name)),
                )
            }
            Expression::FuncLit(literal) => {
                if self.fact_scope.is_none() {
                    Some(
                        SemanticValue::new(SemanticValueKind::Callable(CallableValue::Closure {
                            name: literal_function_name(literal),
                            captures: self
                                .values
                                .iter()
                                .map(|(name, value)| (name.clone(), value.clone()))
                                .collect(),
                        }))
                        .canonicalize(self.value_limits),
                    )
                } else {
                    Some(SemanticValue::callable(literal_function_name(literal)))
                }
            }
            Expression::Call(call) => {
                if let Callee::Pkg { path, method, .. } = self.resolve_callee(&call.func)
                    && path == "os"
                    && matches!(method.as_str(), "Getenv" | "LookupEnv")
                {
                    return Some(
                        call.args
                            .first()
                            .and_then(string_of)
                            .filter(|name| !name.is_empty())
                            .map(|name| SemanticValue::new(SemanticValueKind::Environment(name)))
                            .unwrap_or_else(|| SemanticValue::unresolved("environment")),
                    );
                }
                if self.fact_scope.is_none()
                    && let Callee::Local(name) = self.resolve_callee(&call.func)
                    && let Some(summary) = self.summaries.get(&name)
                    && let Some(value) = &summary.returns
                {
                    let bindings = summary
                        .params
                        .iter()
                        .zip(&call.args)
                        .filter_map(|(name, arg)| Some((name.clone(), self.value_of(arg)?)))
                        .collect();
                    return Some(crate::substitute_value(value, &bindings, self.value_limits));
                }
                if matches!(&*call.func, Expression::Ident(ident) if ident.name == "append") {
                    let mut elements = Vec::new();
                    for argument in &call.args {
                        let value = self.value_of(argument)?;
                        match value.kind {
                            SemanticValueKind::Collection {
                                elements: nested, ..
                            } => elements.extend(nested),
                            _ => elements.push(value),
                        }
                    }
                    return Some(SemanticValue::new(SemanticValueKind::Collection {
                        elements,
                        properties: BTreeMap::new(),
                    }));
                }
                None
            }
            _ => None,
        }
    }

    fn collection_value(&self, literal: &gosyn::ast::LiteralValue) -> SemanticValue {
        SemanticValue::new(SemanticValueKind::Collection {
            elements: literal
                .values
                .iter()
                .filter_map(|element| match &element.val {
                    Element::Expr(value) => self.value_of(value),
                    Element::LitValue(value) => Some(self.collection_value(value)),
                })
                .collect(),
            properties: BTreeMap::new(),
        })
    }

    fn bind_channel_alias(
        &mut self,
        left: &Expression,
        right: &Expression,
        shadowed_names: &HashSet<String>,
    ) {
        if let Some(right_name) = channel_name(right) {
            if shadowed_names.contains(right_name)
                && let Some(binding) = self
                    .local_scopes
                    .last_mut()
                    .and_then(|scope| scope.get_mut(right_name))
            {
                binding.channel_value = Some(unresolved_resource("filesystem"));
            }
            self.widen_escaped_channel(right);
            self.widen_escaped_channel(left);
        } else if let Expression::CompositeLit(literal) = right {
            self.widen_channels_in_literal(&literal.val, 0);
            if let Some(left) = channel_name(left) {
                self.channel_values.remove(left);
            }
        } else if let Expression::Operation(operation) = right
            && operation.op == Operator::And
            && operation.y.is_none()
            && let Expression::CompositeLit(literal) = &*operation.x
        {
            self.widen_channels_in_literal(&literal.val, 0);
            if let Some(left) = channel_name(left) {
                self.channel_values.remove(left);
            }
        } else if let Some(left) = channel_name(left) {
            if fresh_channel_expression(right) {
                self.channel_values.remove(left);
            } else if computed_channel_expression(right) {
                self.channel_values
                    .insert(left.to_string(), unresolved_resource("filesystem"));
            } else {
                self.channel_values.remove(left);
            }
        }
    }

    fn received_resource(&self, expr: &Expression) -> Option<ResourceExpr> {
        match expr {
            Expression::Paren(paren) => self.received_resource(&paren.expr),
            Expression::Operation(operation)
                if operation.op == Operator::Arrow && operation.y.is_none() =>
            {
                channel_name(&operation.x).and_then(|channel| {
                    if !self.local_vars.contains(channel) {
                        Some(unresolved_resource("filesystem"))
                    } else {
                        self.channel_values.get(channel).cloned()
                    }
                })
            }
            _ => None,
        }
    }

    /// The declared or assigned receiver type. Interface implementation sets
    /// are repository facts resolved by the linker, not selected per file.
    fn dispatch_type(&self, recv: &str) -> Option<String> {
        self.local_types.get(recv).cloned().or_else(|| {
            let (base, field) = recv.split_once('.')?;
            let typ = self.local_types.get(base)?;
            self.struct_fields.get(&format!("{typ}.{field}")).cloned()
        })
    }

    fn recv_ref(&self, recv: &str) -> SemanticValue {
        if let Some((base, attr)) = recv.split_once('.') {
            let receiver_type = self
                .fact_function
                .split_once('.')
                .map(|(receiver, _)| receiver);
            if receiver_type
                .is_some_and(|receiver| self.dispatch_type(base).as_deref() == Some(receiver))
            {
                return SemanticValue::object(ObjectIdentity::ReceiverProperty(attr.to_string()));
            }
            return SemanticValue::object(ObjectIdentity::LocalProperty {
                name: base.to_string(),
                property: attr.to_string(),
            });
        }
        if self.bound_vars.contains(recv) {
            return SemanticValue::object(ObjectIdentity::Local {
                name: recv.to_string(),
                fallback: self.dispatch_type(recv),
            });
        }
        if self.params.contains_key(recv) && !self.fact_function.starts_with("func#") {
            return SemanticValue::object(ObjectIdentity::Parameter {
                name: recv.to_string(),
                fallback: self.dispatch_type(recv),
            });
        }
        if let Some(instance) = self.instance_aliases.get(recv) {
            return instance.clone();
        }
        let typ = self.dispatch_type(recv);
        if !self.local_vars.contains(recv)
            && !GO_PREDECLARED_VALUES.contains(&recv)
            && (self.package_vars.contains(recv)
                || (self.fact_scope.is_some() && typ.is_none() && !self.params.contains_key(recv)))
            && let Some(scope) = &self.fact_scope
        {
            return SemanticValue::object(ObjectIdentity::ModuleBinding {
                scope: scope.clone(),
                name: recv.to_string(),
            })
            .with_type(typ.as_deref().and_then(|ty| self.type_ref(ty)));
        }
        match typ {
            Some(typ) => SemanticValue::object(ObjectIdentity::Class {
                name: typ,
                constructor: Vec::new(),
            })
            .with_origin(self.local_origins.get(recv).cloned())
            .with_type(
                self.dispatch_type(recv)
                    .as_deref()
                    .and_then(|ty| self.type_ref(ty)),
            ),
            None => SemanticValue::object(ObjectIdentity::Local {
                name: recv.to_string(),
                fallback: None,
            }),
        }
    }

    fn type_ref(&self, typ: &str) -> Option<TypeRef> {
        named_type_ref(self.imports, &self.repo_types, &self.fact_file, typ)
    }

    fn next_origin(&mut self) -> ValueOrigin {
        let origin = ValueOrigin::Site {
            file: self.fact_file.clone(),
            function: self.fact_function.clone(),
            ordinal: self.site_ordinal,
            result_index: 0,
        };
        self.site_ordinal += 1;
        origin
    }

    fn record_construction(&mut self, name: &str, value: &Expression) {
        if !self.collect_edges {
            return;
        }
        let Some((site, class)) = construction_site(value) else {
            return;
        };
        let origin = if let Some(origin) = self.construction_origins.get(&site) {
            origin.clone()
        } else {
            let origin = self.next_origin();
            self.construction_origins.insert(site, origin.clone());
            origin
        };
        let ty = self.type_ref(&class);
        let mut arguments = self.seed_fn_args(value);
        merge_arguments(&mut arguments, self.struct_field_args(value));
        if self.local_vars.contains(name) || !self.package_vars.contains(name) {
            self.local_origins.insert(name.to_string(), origin.clone());
        }
        if let Out::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(CallEdge {
                condition: effinterp_proto::Condition::compose(&self.conditions),
                call_site: Some(self.condition_source.call_site(&(self.site_ordinal,))),
                callee: class,
                arguments,
                results: call_results(vec![(0, name.to_string())], Some(origin), ty),
                ..Default::default()
            });
        }
    }

    fn record_declared_construction(&mut self, name: &str, class: &str) {
        if !self.collect_edges || name == "_" || GO_BUILTINS.contains(&class) {
            return;
        }
        let origin = self.next_origin();
        let ty = self.type_ref(class);
        if self.local_vars.contains(name) || !self.package_vars.contains(name) {
            self.local_origins.insert(name.to_string(), origin.clone());
        }
        if let Out::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(CallEdge {
                condition: effinterp_proto::Condition::compose(&self.conditions),
                call_site: Some(self.condition_source.call_site(&(self.site_ordinal,))),
                callee: class.to_string(),
                results: call_results(vec![(0, name.to_string())], Some(origin), ty),
                ..Default::default()
            });
        }
    }

    fn record_declared_origin(&mut self, name: &str, class: &str) {
        if !self.collect_edges || name == "_" || GO_BUILTINS.contains(&class) {
            return;
        }
        let origin = self.next_origin();
        self.local_origins.insert(name.to_string(), origin);
    }

    fn seed_fn_args(&self, expr: &Expression) -> Vec<ValueArgument> {
        let literal = match expr {
            Expression::Paren(p) => return self.seed_fn_args(&p.expr),
            Expression::Operation(op) if op.y.is_none() => return self.seed_fn_args(&op.x),
            Expression::Star(star) => return self.seed_fn_args(&star.right),
            Expression::CompositeLit(literal) => &literal.val,
            _ => return Vec::new(),
        };
        let mut out = Vec::new();
        self.collect_seed_fn_args(literal, &mut out, 0);
        out
    }

    fn struct_field_args(&self, expr: &Expression) -> Vec<ValueArgument> {
        let literal = match expr {
            Expression::Paren(paren) => return self.struct_field_args(&paren.expr),
            Expression::Operation(operation) if operation.y.is_none() => {
                return self.struct_field_args(&operation.x);
            }
            Expression::Star(star) => return self.struct_field_args(&star.right),
            Expression::CompositeLit(literal) => &literal.val,
            _ => return Vec::new(),
        };
        literal
            .values
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                let name = match field.key.as_ref()? {
                    Element::Expr(Expression::Ident(id)) => id.name.clone(),
                    _ => return None,
                };
                if is_callback_field(&name) {
                    return None;
                }
                let instance = match &field.val {
                    Element::Expr(Expression::Ident(id))
                        if !GO_PREDECLARED_VALUES.contains(&id.name.as_str()) =>
                    {
                        self.arg_ref(&id.name)
                    }
                    _ => return None,
                };
                Some(ValueArgument {
                    name: Some(name),
                    index,
                    value: instance,
                })
            })
            .collect()
    }

    fn collect_seed_fn_args(
        &self,
        literal: &gosyn::ast::LiteralValue,
        out: &mut Vec<ValueArgument>,
        depth: u32,
    ) {
        if depth >= MAX_WALK_DEPTH || out.len() >= MAX_SUMMARY_ITEMS {
            return;
        }
        for field in &literal.values {
            let callback = (|| {
                let key = match field.key.as_ref()? {
                    Element::Expr(Expression::Ident(id)) => id.name.clone(),
                    _ => return None,
                };
                if !is_callback_field(&key) {
                    return None;
                }
                let func = match &field.val {
                    Element::Expr(Expression::Ident(id)) => id.name.clone(),
                    Element::Expr(Expression::FuncLit(literal)) => {
                        let name = literal_function_name(literal);
                        if !self.funcs.contains_key(&name) {
                            return None;
                        }
                        name
                    }
                    _ => return None,
                };
                Some(ValueArgument {
                    name: Some(key),
                    index: 0,
                    value: SemanticValue::callable(func),
                })
            })();
            if let Some(callback) = callback {
                out.push(callback);
            }
            match &field.val {
                Element::Expr(Expression::CompositeLit(nested)) => {
                    self.collect_seed_fn_args(&nested.val, out, depth + 1)
                }
                Element::LitValue(nested) => self.collect_seed_fn_args(nested, out, depth + 1),
                _ => {}
            }
        }
    }

    fn obj_args(&mut self, args: &[Expression]) -> Vec<ValueArgument> {
        args.iter()
            .enumerate()
            .filter_map(|(index, arg)| {
                let value = match arg {
                    Expression::Ident(id) if GO_PREDECLARED_VALUES.contains(&id.name.as_str()) => {
                        return None;
                    }
                    Expression::Ident(id) if self.named_func(&id.name).is_some() => {
                        SemanticValue::callable(&id.name)
                    }
                    Expression::Ident(id)
                        if self.package_vars.contains(&id.name)
                            && !self.local_vars.contains(&id.name) =>
                    {
                        self.arg_ref(&id.name)
                    }
                    Expression::Ident(id) => self
                        .values
                        .get(&id.name)
                        .cloned()
                        .unwrap_or_else(|| self.arg_ref(&id.name)),
                    _ => self
                        .record_inline_construction(arg)
                        .or_else(|| self.value_of(arg))?,
                };
                if matches!(&value.kind, SemanticValueKind::Literal(_)) {
                    return None;
                }
                Some(ValueArgument {
                    name: None,
                    index,
                    value,
                })
            })
            .collect()
    }

    fn arg_ref(&self, name: &str) -> SemanticValue {
        if self.params.contains_key(name) {
            SemanticValue::object(ObjectIdentity::Parameter {
                name: name.to_string(),
                fallback: self.dispatch_type(name),
            })
        } else {
            self.recv_ref(name)
        }
    }

    fn record_inline_construction(&mut self, expr: &Expression) -> Option<SemanticValue> {
        if !self.collect_edges {
            return None;
        }
        let (site, name) = construction_site(expr)?;
        let (origin, emit) = if let Some(origin) = self.construction_origins.get(&site) {
            (origin.clone(), false)
        } else {
            let origin = self.next_origin();
            self.construction_origins.insert(site, origin.clone());
            (origin, true)
        };
        let ty = self.type_ref(&name);
        let mut arguments = self.seed_fn_args(expr);
        merge_arguments(&mut arguments, self.struct_field_args(expr));
        let edge = CallEdge {
            callee: name.clone(),
            arguments,
            results: call_results(Vec::new(), Some(origin.clone()), ty.clone()),
            ..Default::default()
        };
        if emit
            && let Out::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(edge);
        }
        Some(
            SemanticValue::object(ObjectIdentity::Class {
                name,
                constructor: Vec::new(),
            })
            .with_origin(Some(origin))
            .with_type(ty),
        )
    }

    /// `NewExecutor().Run(cmd)` runs a method on a value no name holds, so the
    /// selector resolves to nothing and the call is silent. Binding the
    /// constructor's result to a synthetic local makes the method dispatch
    /// exactly as `e := NewExecutor(); e.Run(cmd)` does: the constructor's edge
    /// types that local, and the method's edge carries it as the receiver.
    /// A chained standard-library call (`exec.Command(...).Run()`) is left
    /// alone: the inner call is what the engine models.
    fn bind_chained_receiver(&mut self, func: &Expression) -> Option<String> {
        let Expression::Selector(selector) = func else {
            return None;
        };
        let inner = receiver_call(&selector.x)?;
        let target = match self.resolve_callee(&inner.func) {
            Callee::Local(name) | Callee::MaybeSibling(name) => Some(name),
            // A constructor in another package of this repository or in a
            // dependency: this file cannot name its returned type, but the
            // package that declares it does, so composition types the result.
            Callee::Pkg { path, .. } if !crate::external::is_go_stdlib(&path) => None,
            _ => return None,
        };
        let (line, column) = call_pos(inner);
        let recv = format!("$recv#{line}:{column}");
        let class = target
            .as_deref()
            .and_then(|target| self.named_func(target))
            .and_then(|function| {
                returns_instances(&function.body)
                    .into_iter()
                    .next()
                    .flatten()
            });
        self.local_vars.insert(recv.clone());
        self.bound_vars.insert(recv.clone());
        match class {
            Some(class) => {
                self.local_types.insert(recv.clone(), class);
            }
            None => {
                self.local_types.remove(&recv);
            }
        }
        Some(recv)
    }

    /// The type a call to a function of this file constructs, when every
    /// `return` in its body agrees on one.
    fn returned_instance(&self, func: &Expression) -> Option<String> {
        let target = match self.resolve_callee(func) {
            Callee::Local(name) | Callee::MaybeSibling(name) => name,
            _ => return None,
        };
        returns_instances(&self.named_func(&target)?.body)
            .into_iter()
            .next()
            .flatten()
    }

    /// The type an assigned expression names for later method dispatch, when
    /// no composite literal states one: a copy of an already-typed local, the
    /// local an address points at (`s := &b` dispatches on `b`'s type), an
    /// allocation (`s := new(Box)`), or a constructor of this file
    /// (`e := NewExecutor()`).
    fn assigned_class(&self, right: &Expression) -> Option<String> {
        match right {
            Expression::Paren(paren) => self.assigned_class(&paren.expr),
            Expression::Operation(operation)
                if operation.op == Operator::And && operation.y.is_none() =>
            {
                self.assigned_class(&operation.x)
            }
            Expression::Ident(src) => self.local_types.get(&src.name).cloned(),
            Expression::Call(call) => allocated_class(&call.func, &call.args)
                .or_else(|| self.sql_constructor(&call.func))
                .or_else(|| self.returned_instance(&call.func)),
            _ => None,
        }
    }

    fn sql_constructor(&self, func: &Expression) -> Option<String> {
        match self.resolve_callee(func) {
            Callee::Pkg {
                path,
                method,
                local,
            } if path == "database/sql" && matches!(method.as_str(), "Open" | "OpenDB") => {
                Some(format!("{local}.DB"))
            }
            Callee::Method { recv, method }
                if self.imported_receiver(&recv).as_deref() == Some("database/sql") =>
            {
                let typ = self.dispatch_type(&recv)?;
                let (pkg, base) = typ.split_once('.')?;
                match (base, method.as_str()) {
                    ("DB", "Begin" | "BeginTx") | ("Conn", "BeginTx") => Some(format!("{pkg}.Tx")),
                    ("DB", "Conn") => Some(format!("{pkg}.Conn")),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn typed_method_key(&self, recv: &str, method: &str) -> Option<String> {
        self.method_key_of_type(&self.dispatch_type(recv)?, method)
    }

    /// The declaration key a method call on a value of this type dispatches to,
    /// when this file declares that method.
    fn method_key_of_type(&self, typ: &str, method: &str) -> Option<String> {
        let base = typ.rsplit('.').next().unwrap_or(typ);
        let key = format!("{base}.{method}");
        self.funcs.contains_key(&key).then_some(key)
    }

    /// The type a method call dispatches on when the question is what the call
    /// writes rather than what it does: a `defer` or `go` body is unordered
    /// against the statement that binds its receiver, so `s := &b` stated
    /// anywhere in an enclosing block answers for `s` with `b`'s type.
    fn stated_receiver_type(&self, recv: &str) -> Option<String> {
        self.dispatch_type(recv).or_else(|| {
            self.aliased_scopes
                .iter()
                .flatten()
                .find(|(pointer, _)| pointer == recv)
                .and_then(|(_, target)| self.dispatch_type(target))
        })
    }

    fn unresolved_interface(&mut self, recv: &str, method: &str, node: ProvenanceRef) {
        let Some(typ) = self.local_types.get(recv) else {
            return;
        };
        if !self
            .dispatch_contracts
            .iter()
            .any(|contract| contract.name == *typ && contract.methods.iter().any(|m| m == method))
        {
            return;
        }
        self.out_boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_INTERFACE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: GO_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!(
                "interface {typ} method {method:?} requires repository dispatch"
            )),
        });
    }

    /// The import path of the package that declares a method receiver's type
    /// (`var once sync.Once`), which makes `once.Do(...)` that package's call.
    fn imported_receiver(&self, recv: &str) -> Option<String> {
        let typ = self.dispatch_type(recv)?;
        let (local, _) = typ.split_once('.')?;
        self.imports.get(local).cloned()
    }

    /// Whether a call names the standard library, whose behaviour this engine
    /// knows: it runs the callbacks it is handed, and nothing downstream will
    /// enter it to find out.
    fn stdlib_target(&self, path: &str, method: &str) -> bool {
        crate::external::classify_go_call(path, method).is_some()
    }

    /// The callback positions of a standard-library call, resolving a method
    /// through its receiver's declared package type (`var once sync.Once`).
    fn callback_positions(&self, callee: &Callee) -> &'static [usize] {
        match callee {
            Callee::Pkg { path, method, .. } => go_callback_positions(path, method),
            Callee::Method { recv, method } => self
                .imported_receiver(recv)
                .map_or(&[][..], |path| go_callback_positions(&path, method)),
            _ => &[],
        }
    }

    /// The callable a standard-library wrapper returns rather than invokes:
    /// `sync.OnceFunc(cleanup)` runs `cleanup` when the value it returns is
    /// called, so the value carries the callable to that call site.
    fn deferred_callback_value(&self, call: &gosyn::ast::Call) -> Option<SemanticValue> {
        let Callee::Pkg { path, method, .. } = self.resolve_callee(&call.func) else {
            return None;
        };
        if path != "sync" || !matches!(method.as_str(), "OnceFunc" | "OnceValue" | "OnceValues") {
            return None;
        }
        let value = self.value_of(call.args.first()?)?;
        crate::contains_callable(&value).then_some(value)
    }

    /// Every function this file declares that the value may hold, or nothing
    /// when any alternative is a callable this file cannot name.
    fn named_callables(&self, value: &SemanticValue) -> Option<Vec<String>> {
        match &value.kind {
            SemanticValueKind::Callable(
                CallableValue::Function { name } | CallableValue::Closure { name, .. },
            ) if self.named_func(name).is_some() => Some(vec![name.clone()]),
            SemanticValueKind::Union(alternatives) => {
                let names = alternatives
                    .iter()
                    .map(|alternative| self.named_callables(alternative))
                    .collect::<Option<Vec<_>>>()?;
                Some(names.into_iter().flatten().collect())
            }
            _ => None,
        }
    }

    /// A function value passed to an imported-package call is a callback that
    /// package may invoke (`once.Do(func() {...})`, `sort.Slice(xs, less)`):
    /// walk it here, since the package itself is never entered. Only a shape
    /// this file can name is walked — a literal, a function declared here, or
    /// another package's function; whether it walked one is the caller's cue
    /// that any remaining callable escaped unaccounted for.
    fn fire_callback_arg(&mut self, arg: &Expression, span: (u32, u32), sequence: bool) -> bool {
        if let Expression::Call(call) = arg
            && let Callee::Pkg { path, method, .. } = self.resolve_callee(&call.func)
            && path == "slices"
            && matches!(method.as_str(), "Values" | "All" | "Backward")
        {
            return true;
        }
        if let Expression::FuncLit(literal) = arg {
            self.walk_function_literal(literal);
            return true;
        }
        if !matches!(arg, Expression::Ident(_) | Expression::Selector(_)) {
            return false;
        }
        // A callable read out of a struct field (`h.less`) names its target
        // exactly even though the expression is a selector, not a call target.
        // A branch may leave a finite set of them, and each one may run.
        if let Some(names) = self
            .value_of(arg)
            .and_then(|value| self.named_callables(&value))
        {
            let node = self.node(span);
            for name in names {
                self.call_local(&name, &[], node, None, sequence, None);
            }
            return true;
        }
        match self.resolve_callee(arg) {
            Callee::Local(name) => {
                let node = self.node(span);
                self.call_local(&name, &[], node, None, sequence, None);
                true
            }
            Callee::Pkg {
                path,
                method,
                local,
            } => {
                if self.collect_edges {
                    self.record_edge(&format!("{local}.{method}"), Vec::new(), Vec::new(), None);
                } else {
                    let node = self.node(span);
                    self.model_call(&path, &method, &[], node);
                }
                true
            }
            // A Go package spans its whole directory, so a callback may be
            // declared in a sibling file this walk never sees. Recorded as a
            // call edge, exactly as a direct call to that name is, so
            // composition resolves it against the package and enters it.
            Callee::MaybeSibling(name) if self.collect_edges => {
                self.record_edge(&name, Vec::new(), Vec::new(), None);
                true
            }
            // A callback named by a local binding (a function-typed parameter,
            // a variable): composition resolves it through the value bound to
            // that name, never through a package function spelled the same.
            Callee::Dynamic(name) if self.collect_edges => {
                self.record_dynamic_edge(&name, Vec::new(), Vec::new(), None);
                true
            }
            _ => false,
        }
    }

    fn walk_call(&mut self, call: &gosyn::ast::Call) {
        let depth = if let Out::Plan { builder, .. } = &mut self.out {
            let depth = builder.condition_depth();
            for condition in &self.conditions {
                builder.push_bound_condition(condition.clone());
            }
            Some(depth)
        } else {
            None
        };
        self.walk_call_inner(call);
        if let (Some(depth), Out::Plan { builder, .. }) = (depth, &mut self.out) {
            while builder.condition_depth() > depth {
                builder.pop_condition();
            }
        }
    }

    fn walk_call_inner(&mut self, call: &gosyn::ast::Call) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        if self.over_node_budget(call_pos(call)) {
            self.partial_nodes();
            return;
        }
        self.walk_depth += 1;
        let control_since = self.control_registered();
        let control_saved = std::mem::take(&mut self.control_applications);
        // The enclosing assignment's binds belong to THIS call, not to calls
        // nested in its arguments.
        let binds = std::mem::take(&mut self.binds_next_call);
        // Reserve the enclosing call's Site before descending into its receiver
        // or arguments so ordinals follow lexical source order.
        let origin = self.collect_edges.then(|| self.next_origin());
        // An immediately-invoked literal (`defer func() {...}()`) executes.
        if let Expression::FuncLit(fl) = &*call.func {
            self.walk_function_literal(fl);
        }
        let control_immediate = self.control_applications.len();
        // Recurse into sub-expressions first (method chains like
        // exec.Command(...).Run() carry the effectful Command as func.x, and
        // arguments may themselves be effect calls). A receiver that is itself
        // a call is bound to a synthetic local first, so that call's own edge
        // records the local as its result and the method can dispatch on it.
        let chained_receiver = self.bind_chained_receiver(&call.func);
        if let Expression::Selector(sel) = &*call.func {
            if let Some(recv) = &chained_receiver {
                self.binds_next_call = vec![(0, recv.clone())];
            }
            self.walk_expr(&sel.x);
            self.binds_next_call.clear();
        } else if !matches!(&*call.func, Expression::FuncLit(_)) {
            self.walk_expr(&call.func);
        }
        for arg in &call.args {
            self.widen_escaped_channel(arg);
            self.walk_expr(arg);
        }

        self.current_binds = binds;
        let node = self.node(call_pos(call));
        let mut callee = self.resolve_callee(&call.func);
        if let (Callee::Unknown, Some(recv), Expression::Selector(sel)) =
            (&callee, &chained_receiver, &*call.func)
        {
            callee = Callee::Method {
                recv: recv.clone(),
                method: sel.sel.name.clone(),
            };
        }
        // A standard-library call is entered by no later stage: neither this
        // file nor composition walks into `sort.Slice` or `sync.Once.Do`, so a
        // callable one of them invokes is accounted for here, as may-executed.
        // Only the argument positions such an entry point is known to call are
        // walked — every other argument is data, and passing a function value
        // as data (`fmt.Println(cleanup)`) is not a call. A call into an
        // unknown target is handled by the unknown-caller pass below instead:
        // outside a fact scope it walks the target's function arguments as
        // may-executed, and the target keeps its own unresolved boundary.
        let external_callee = match &callee {
            Callee::Pkg { path, method, .. } => self.stdlib_target(path, method),
            Callee::Method { recv, method } => self
                .imported_receiver(recv)
                .is_some_and(|path| self.stdlib_target(&path, method)),
            _ => false,
        };
        // A callable this file cannot name (one arriving through a parameter,
        // a field, or a bound method) is walked by nobody, here or later.
        let mut escaped_callable = false;
        let callbacks = self.callback_positions(&callee);
        let mut entered: HashSet<usize> = HashSet::new();
        for index in callbacks {
            let Some(arg) = call.args.get(*index) else {
                continue;
            };
            if self.fire_callback_arg(arg, call_pos(call), matches!(&callee, Callee::Pkg { path, method, .. } if matches!((path.as_str(), method.as_str(), *index), ("slices", "Sorted" | "Collect" | "SortedFunc" | "SortedStableFunc", 0) | ("slices", "AppendSeq", 1) | ("maps", "Collect", 0) | ("maps", "Insert", 1)))) {
                entered.insert(*index);
            } else {
                escaped_callable = true;
            }
        }
        // Unknown callees may invoke any function argument. Keep the local
        // may-effects as well as the caller's unresolved boundary.
        let unknown_caller = match &callee {
            Callee::Local(_) => false,
            Callee::Pkg { path, method, .. }
                if path == "fmt"
                    && matches!(
                        method.as_str(),
                        "Print"
                            | "Println"
                            | "Printf"
                            | "Sprint"
                            | "Sprintln"
                            | "Sprintf"
                            | "Fprint"
                            | "Fprintln"
                            | "Fprintf"
                    ) =>
            {
                false
            }
            Callee::Pkg { path, method, .. } => !matches!(
                crate::external::classify_go_call(path, method),
                Some(crate::external::ExternalCall::Inert | crate::external::ExternalCall::Modeled)
            ),
            _ => true,
        };
        if unknown_caller
            && self.fact_scope.is_none()
            && !matches!(&*call.func, Expression::Ident(id) if GO_BUILTINS.contains(&id.name.as_str()) && !self.local_vars.contains(&id.name))
        {
            for (index, argument) in call.args.iter().enumerate() {
                if !entered.contains(&index)
                    && (matches!(argument, Expression::FuncLit(_))
                        || self
                            .value_of(argument)
                            .is_some_and(|value| crate::contains_callable(&value)))
                    && self.fire_callback_arg(argument, call_pos(call), false)
                {
                    entered.insert(index);
                }
            }
        }
        // A callable handed to a call this walk does not enter runs at a moment
        // nothing here observes, so the caller's bindings it assigns are stale
        // once the call returns. An argument the walk did enter above already
        // applied its writes exactly.
        let escaped_closures = self.escaped_argument_closures(&call.args, &entered);
        if !self.collect_edges
            && (escaped_callable
                || (!external_callee
                    && matches!(
                        &callee,
                        Callee::MaybeSibling(_)
                            | Callee::Dynamic(_)
                            | Callee::Method { .. }
                            | Callee::Unknown
                    )
                    && call.args.iter().any(|argument| {
                        self.value_of(argument)
                            .is_some_and(|value| crate::contains_callable(&value))
                    })))
        {
            self.out_boundary(Boundary {
                reason: BoundaryReason::ESCAPED_CALLABLE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: GO_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(
                    "callable passed to a call target this file cannot follow".to_string(),
                ),
            });
        }
        // Go hands a callee the caller's own storage for a pointer, a slice,
        // or a map, so a call may write what the caller holds. A body this file
        // can read names the parameters it writes through; a target it cannot
        // read may write through any of them.
        let escaped_arguments = self.escaped_call_arguments(&callee, &call.args);
        let written_names = escaped_arguments.names();
        self.pending_writes = written_names.clone();
        let control_callbacks = self.control_applications.len();
        let control_kind = self.call_control_kind(&callee, &call.func);
        let effects_before = self.effects_len();
        let calls_before = match &self.out {
            Out::Capture(cap) => cap.edges.len(),
            Out::Plan { .. } => 0,
        };
        match callee {
            Callee::Pkg {
                path,
                method,
                local,
            } => {
                // In edge-collection mode a call on an imported package qualifier
                // (`pkg.Func()`) is a cross-package call edge — the repo layer
                // resolves it to the package's file or emits an honest boundary
                // (quiet only for modeled or explicitly-inert stdlib calls).
                // Recording it is what lets composition leave `main` into
                // another package.
                if self.collect_edges {
                    let arg_exprs: Vec<ResourceExpr> =
                        call.args.iter().map(|a| self.fs_arg(a)).collect();
                    let obj_args = self.obj_args(&call.args);
                    self.record_edge(
                        &format!("{local}.{method}"),
                        arg_exprs,
                        obj_args,
                        origin.clone(),
                    );
                    if self.capture_external_effects {
                        self.model_call(&path, &method, &call.args, node);
                    }
                } else {
                    self.model_call(&path, &method, &call.args, node);
                }
            }
            Callee::Local(name) => {
                self.call_local(&name, &call.args, node, origin.clone(), false, None)
            }
            // A bare name defined in no local function: possibly a function in
            // a SIBLING file of the same package (a Go package spans the whole
            // directory). Recorded as an edge for the repo layer to resolve —
            // or drop — against the package's other files.
            Callee::MaybeSibling(name) => {
                if self.collect_edges {
                    self.record_call_edge(&name, call, origin.clone(), false);
                } else {
                    self.unmodeled_external(&name, crate::external::ALL_DOMAINS, node, true);
                }
            }
            // A call through a locally bound name is recorded the same way,
            // but marked so composition follows only the bound value.
            Callee::Dynamic(name) => {
                if self.collect_edges {
                    self.record_call_edge(&name, call, origin.clone(), true);
                } else if self.fact_scope.is_some() {
                    if !self.fire_callback_arg(&call.func, call_pos(call), false) {
                        self.unmodeled_external(&name, crate::external::ALL_DOMAINS, node, true);
                    }
                } else if !self.dispatch_callable_value(&call.func, &call.args, node)
                    && !self.fire_callback_arg(&call.func, call_pos(call), false)
                {
                    self.unresolved_callable(&name, node);
                }
            }
            // A method on a local variable: recorded with the receiver so the
            // composer can dispatch it when the variable is typed by an
            // unambiguous constructor's returns, a declared parameter type, or
            // a composite-literal assignment. An untyped receiver never
            // dispatches. Interface candidate cardinality is resolved across
            // the repository by the linker.
            Callee::Method { recv, method } => {
                if !self.collect_edges {
                    self.unresolved_interface(&recv, &method, node);
                }
                if self.collect_edges {
                    let arg_exprs: Vec<ResourceExpr> =
                        call.args.iter().map(|a| self.fs_arg(a)).collect();
                    let iref = self.recv_ref(&recv);
                    let mut obj_args = self.obj_args(&call.args);
                    if let Some(value) = self
                        .values
                        .get(&recv)
                        .and_then(|value| exact_property(value, &method, self.value_limits))
                    {
                        obj_args.push(ValueArgument {
                            name: Some("$callee".to_string()),
                            index: usize::MAX,
                            value,
                        });
                    }
                    let origin = origin.clone().unwrap();
                    let binds = std::mem::take(&mut self.current_binds);
                    let mut arguments = positional_arguments(arg_exprs);
                    merge_arguments(&mut arguments, obj_args);
                    if let Out::Capture(cap) = &mut self.out
                        && cap.edges.len() < MAX_SUMMARY_ITEMS
                    {
                        cap.edges.push(CallEdge {
                            callee: format!("{recv}.{method}"),
                            arguments,
                            receiver: Some(iref),
                            results: call_results(binds, Some(origin), None),
                            writes: std::mem::take(&mut self.pending_writes),
                            ..Default::default()
                        });
                    }
                } else if self.fire_cobra_callbacks(&recv, &method, node) {
                } else if let Some(path) = self.imported_receiver(&recv) {
                    if path == "database/sql"
                        && !self.dispatch_type(&recv).is_some_and(|typ| {
                            matches!(typ.rsplit('.').next(), Some("DB" | "Tx" | "Conn"))
                        })
                    {
                        self.unmodeled_external(
                            &format!("{recv}.{method}"),
                            &["database"],
                            node,
                            false,
                        );
                    } else {
                        self.model_call(&path, &method, &call.args, node);
                    }
                } else if let Some(key) = self.typed_method_key(&recv, &method) {
                    let receiver = self.values.get(&recv).cloned();
                    self.call_local(&key, &call.args, node, origin.clone(), false, receiver);
                } else {
                    self.unmodeled_external(
                        &format!("{recv}.{method}"),
                        crate::external::ALL_DOMAINS,
                        node,
                        true,
                    );
                }
            }
            Callee::Unknown => {
                if !matches!(&*call.func, Expression::FuncLit(_))
                    && !matches!(&*call.func, Expression::Ident(id) if GO_BUILTINS.contains(&id.name.as_str()) && !self.local_vars.contains(&id.name))
                {
                    self.unmodeled_external(
                        &go_callee_name(&call.func),
                        crate::external::ALL_DOMAINS,
                        node,
                        true,
                    );
                }
            }
        }
        self.pending_writes.clear();
        let applied = std::mem::replace(&mut self.control_applications, control_saved);
        let mut facts = self.call_control(
            control_kind,
            applied,
            control_immediate..control_callbacks,
            entered.len(),
            escaped_callable,
            effects_before..self.effects_len(),
        );
        facts.call_return = matches!(control_kind, GoCall::Local | GoCall::Opaque)
            && control_immediate == control_callbacks
            && !escaped_callable;
        if let Out::Capture(cap) = &mut self.out
            && cap.edges.len() == calls_before + 1
        {
            facts.facts.push(ControlFact::Call(calls_before as u32));
            cap.call_sites
                .insert(control::call_span(call), calls_before as u32);
        }
        self.control_register_since(control::call_span(call), control_since, facts);
        for name in written_names {
            self.values.remove(&name);
            self.resource_values.remove(&name);
        }
        self.invalidate_escaped_storage(escaped_closures);
        for name in escaped_arguments.handed {
            // The declared type still holds — only what the binding contains is
            // stale — so the construction identity goes and the type stays. A
            // method writes through the object the receiver already names, so
            // that one keeps its identity: only its contents are stale.
            self.local_origins.remove(&name);
            self.instance_aliases.remove(&name);
        }
        self.current_binds.clear();
        self.walk_depth -= 1;
    }

    /// How a resolved call behaves at its control-flow site.
    fn call_control_kind(&self, callee: &Callee, func: &Expression) -> GoCall {
        match callee {
            Callee::Pkg { path, method, .. } => match (path.as_str(), method.as_str()) {
                ("os", "Exit") => GoCall::Exit,
                (
                    "os",
                    "Remove" | "RemoveAll" | "Getenv" | "LookupEnv" | "Setenv" | "Unsetenv"
                    | "Clearenv",
                ) => GoCall::Sink,
                ("log", "Fatal" | "Fatalf" | "Fatalln" | "Panic" | "Panicf" | "Panicln")
                | ("runtime", "Goexit") => GoCall::Exit,
                ("fmt", "Print" | "Println" | "Printf" | "Sprint" | "Sprintln" | "Sprintf") => {
                    GoCall::Modeled
                }
                _ if matches!(
                    crate::external::classify_go_call(path, method),
                    Some(
                        crate::external::ExternalCall::Inert
                            | crate::external::ExternalCall::Modeled
                    )
                ) =>
                {
                    GoCall::Modeled
                }
                _ => GoCall::Opaque,
            },
            Callee::Local(_) | Callee::Dynamic(_) => GoCall::Local,
            Callee::Method { recv, method } => match self.imported_receiver(recv) {
                Some(path)
                    if crate::external::is_go_stdlib(&path)
                        && matches!(
                            crate::external::classify_go_call(&path, method),
                            Some(
                                crate::external::ExternalCall::Inert
                                    | crate::external::ExternalCall::Modeled
                            )
                        ) =>
                {
                    GoCall::Modeled
                }
                None if self.typed_method_key(recv, method).is_some() => GoCall::Local,
                _ => GoCall::Opaque,
            },
            Callee::MaybeSibling(_) => GoCall::Opaque,
            Callee::Unknown => match func {
                Expression::FuncLit(_) => GoCall::Local,
                Expression::Ident(id)
                    if GO_BUILTINS.contains(&id.name.as_str())
                        && !self.local_vars.contains(&id.name) =>
                {
                    if id.name == "panic" {
                        GoCall::Exit
                    } else {
                        GoCall::Modeled
                    }
                }
                _ => GoCall::Opaque,
            },
        }
    }

    /// What a call establishes at its site. Only a proven sink's own
    /// occurrences or one directly entered body's guarantees count; callbacks
    /// run under the callee's control, so they can only add an unknown exit.
    fn call_control(
        &self,
        kind: GoCall,
        applied: Vec<SiteFacts>,
        callbacks: std::ops::Range<usize>,
        entered: usize,
        escaped_callable: bool,
        modeled: std::ops::Range<usize>,
    ) -> SiteFacts {
        let slots = || match &self.out {
            Out::Plan { builder, .. } => builder.control_own_effects(modeled.clone()),
            Out::Capture(_) => modeled
                .clone()
                .map(|slot| ControlFact::Effect(slot as u32))
                .collect(),
        };
        let callback_facts = &applied[callbacks.clone()];
        let direct: Vec<&SiteFacts> = applied[..callbacks.start]
            .iter()
            .chain(&applied[callbacks.end..])
            .collect();
        let mut facts = match (kind, direct.as_slice()) {
            (GoCall::Sink, []) => SiteFacts::known(slots()),
            (GoCall::Modeled, []) => SiteFacts::known(Vec::new()),
            (GoCall::Local, [entered]) => (*entered).clone(),
            (GoCall::Exit, []) => SiteFacts {
                returns: false,
                ..SiteFacts::known(slots())
            },
            _ => SiteFacts::unknown(),
        };
        if escaped_callable
            || callback_facts.len() != entered
            || callback_facts
                .iter()
                .any(|callback| callback.exit.is_some() || callback.widen)
        {
            facts.exit = Some(ControlExit::Unknown);
        }
        facts
    }

    /// Whether a deferred call may recover a panic into a normal return.
    fn deferred_may_recover(&self, call: &gosyn::ast::Call) -> bool {
        let mut target = &*call.func;
        while let Expression::Paren(paren) = target {
            target = &paren.expr;
        }
        let body_recovers =
            |function: Option<&GoFunc>| function.is_none_or(|f| control::calls_recover(&f.body));
        match target {
            Expression::FuncLit(literal) => control::calls_recover(&literal.body),
            Expression::Ident(id)
                if GO_BUILTINS.contains(&id.name.as_str())
                    && !self.local_vars.contains(&id.name) =>
            {
                id.name == "recover"
            }
            _ => match self.resolve_callee(target) {
                Callee::Pkg { path, .. } => !crate::external::is_go_stdlib(&path),
                Callee::Local(name) => body_recovers(self.named_func(&name)),
                Callee::Method { recv, method } => match self.imported_receiver(&recv) {
                    Some(path) => !crate::external::is_go_stdlib(&path),
                    None => match self.typed_method_key(&recv, &method) {
                        Some(key) => body_recovers(self.funcs.get(&key)),
                        None => true,
                    },
                },
                _ => true,
            },
        }
    }

    fn effects_len(&self) -> usize {
        match &self.out {
            Out::Plan { builder, .. } => builder.effects_len(),
            Out::Capture(cap) => cap.effects.len(),
        }
    }

    /// Begin a body's control-flow frame over plan or summary effect slots.
    fn control_enter(&mut self, body: &BlockStmt) {
        match &mut self.out {
            Out::Plan { builder, .. } => builder.control_enter(self.source, false, |graph| {
                control::build_function(graph, body)
            }),
            Out::Capture(cap) => {
                let limits = crate::AnalysisLimits::default();
                let (budget, caps) = match &self.analysis_budget {
                    Some((builder, _)) => (Some(builder.budget()), builder.control_caps()),
                    None => (
                        None,
                        ControlCaps {
                            nodes: limits.max_causal_nodes,
                            work: limits.max_causal_pairs,
                        },
                    ),
                };
                cap.control.enter(
                    self.source,
                    true,
                    Default::default(),
                    0,
                    0,
                    budget,
                    caps,
                    |graph| control::build_function(graph, body),
                );
            }
        }
    }

    /// Finish the body's frame and record what it guarantees to its caller.
    fn control_leave(&mut self) {
        let finished = match &mut self.out {
            Out::Plan { builder, .. } => builder.control_leave(),
            Out::Capture(cap) => cap.control.leave(0).inspect(|finished| {
                if let Some(limit) = finished.refused {
                    cap.boundaries.push(Boundary {
                        reason: BoundaryReason::LIMIT_SATURATED,
                        class: BoundaryClass::Limit,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: GO_DOMAINS
                            .iter()
                            .map(|domain| Domain::new(*domain))
                            .collect(),
                        provenance: Vec::new(),
                        limit: Some(limit.to_string()),
                        detail: Some("go summary control flow widened".to_string()),
                    });
                }
                cap.flow = finished.flow.clone();
            }),
        };
        self.control_applications
            .push(finished.map_or_else(SiteFacts::unknown, |finished| {
                SiteFacts::call(&finished.requirements, Some)
            }));
    }

    fn control_registered(&self) -> usize {
        match &self.out {
            Out::Plan { builder, .. } => builder.control_registered(),
            Out::Capture(cap) => cap.control.registered(),
        }
    }

    fn control_register(&mut self, span: crate::control_flow::Span, facts: SiteFacts) {
        match &mut self.out {
            Out::Plan { builder, .. } => builder.control_site(self.source, false, span, facts),
            Out::Capture(cap) => cap.control.register(self.source, true, span, facts),
        }
    }

    fn control_register_since(
        &mut self,
        span: crate::control_flow::Span,
        since: usize,
        facts: SiteFacts,
    ) {
        match &mut self.out {
            Out::Plan { builder, .. } => {
                builder.control_site_since(self.source, false, span, since, facts)
            }
            Out::Capture(cap) => cap
                .control
                .register_since(self.source, true, span, since, facts),
        }
    }

    fn unresolved_callable(&mut self, name: &str, node: ProvenanceRef) {
        self.out_boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: self.fact_function.clone(),
                symbol: name.to_string(),
            }),
            domains: GO_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call through unresolved callable value {name}")),
        });
    }

    fn dispatch_callable_value(
        &mut self,
        func: &Expression,
        args: &[Expression],
        node: ProvenanceRef,
    ) -> bool {
        let Some(value) = self.value_of(func) else {
            return false;
        };
        let (name, captures) = match value.kind {
            SemanticValueKind::Callable(CallableValue::Function { name }) => {
                (name, BTreeMap::new())
            }
            SemanticValueKind::Callable(CallableValue::Closure { name, captures }) => {
                (name, captures)
            }
            _ => return false,
        };
        if let Some((pkg, method)) = name.split_once('.')
            && let Some(path) = self.imports.get(pkg).cloned()
        {
            self.model_call(&path, method, args, node);
            return true;
        }
        if self.named_func(&name).is_none() {
            return false;
        }
        let saved = self.values.clone();
        self.values.extend(captures);
        let (receiver, args) = if self
            .named_func(&name)
            .is_some_and(|function| function.receiver.is_some())
        {
            (
                args.first().and_then(|arg| self.value_of(arg)),
                args.get(1..).unwrap_or_default(),
            )
        } else {
            (None, args)
        };
        self.call_local(&name, args, node, None, false, receiver);
        self.values = saved;
        true
    }

    fn fire_cobra_callbacks(&mut self, recv: &str, method: &str, node: ProvenanceRef) -> bool {
        if !matches!(&self.out, Out::Plan { .. }) || !matches!(method, "Execute" | "ExecuteContext")
        {
            return false;
        }
        let Some(value) = self.values.get(recv).cloned() else {
            return false;
        };
        let SemanticValueKind::Object(object) = &value.kind else {
            return false;
        };
        let ObjectIdentity::Class { name, constructor } = &object.identity else {
            return false;
        };
        let Some((package, typ)) = name.split_once('.') else {
            return false;
        };
        if typ != "Command"
            || self.imports.get(package).map(String::as_str) != Some("github.com/spf13/cobra")
        {
            return false;
        }
        let mut fields: Vec<String> = object
            .properties
            .keys()
            .chain(
                constructor
                    .iter()
                    .filter_map(|argument| argument.name.as_ref()),
            )
            .filter(|name| is_callback_field(name))
            .cloned()
            .collect();
        fields.sort();
        fields.dedup();
        for field in fields {
            let Some(names) = exact_property(&value, &field, self.value_limits)
                .and_then(|callback| self.named_callables(&callback))
            else {
                continue;
            };
            for name in names {
                self.call_local(&name, &[], node, None, false, None);
            }
        }
        true
    }

    /// What the callables handed to a call may write of the caller's own
    /// bindings. A literal argument carries its body here; a name carries a
    /// closure this file registered under it. A callable this file cannot name
    /// says nothing about what it writes, and the call's own `escaped_callable`
    /// boundary already reports that it followed none. Callables nested below
    /// an argument escaped where `walk_expr` saw them stored.
    fn escaped_argument_closures(
        &self,
        args: &[Expression],
        entered: &HashSet<usize>,
    ) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for (index, argument) in args.iter().enumerate() {
            if entered.contains(&index) {
                continue;
            }
            let mut argument = argument;
            while let Expression::Paren(paren) = argument {
                argument = &paren.expr;
            }
            let writes: Vec<String> = match argument {
                Expression::FuncLit(literal) => {
                    assigned_outer_names(&literal.body, function_locals(&literal.typ))
                        .into_iter()
                        .collect()
                }
                other => self
                    .value_of(other)
                    .and_then(|value| self.named_callables(&value))
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|name| self.named_func(name))
                    .filter(|function| function.is_closure)
                    .flat_map(|function| function.assigns_outer.iter().cloned())
                    .collect(),
            };
            for name in writes {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        names
    }

    /// The caller bindings a call may overwrite: an argument that hands the
    /// callee the caller's own storage, in a position the callee writes
    /// through. A callee this file cannot read is assumed to write every one.
    fn escaped_call_arguments(&self, callee: &Callee, args: &[Expression]) -> CallWrites {
        let known = match callee {
            Callee::Local(name) => self.named_func(name),
            Callee::Method { recv, method } => self
                .typed_method_key(recv, method)
                .and_then(|key| self.funcs.get(&key)),
            _ => None,
        };
        let handed: Vec<String> = args
            .iter()
            .enumerate()
            .filter(|(index, _)| match known {
                Some(function) => function.writes_through.get(*index).copied().unwrap_or(true),
                None => true,
            })
            .filter_map(|(_, argument)| self.escaping_argument_name(argument))
            .collect();
        // A pointer receiver is the caller's own storage exactly as a pointer
        // argument is, so a method that assigns through it costs the caller its
        // exact view of the variable it was called on.
        let receiver = match callee {
            Callee::Method { recv, method }
                if !recv.contains('.') && self.method_writes_receiver(recv, method) =>
            {
                vec![recv.clone()]
            }
            _ => Vec::new(),
        };
        CallWrites {
            handed: self.with_aliased_storage(handed),
            receiver: self.with_aliased_storage(receiver),
        }
    }

    /// Whether a method call may assign through its receiver: a method this
    /// file declares answers for itself, one declared in a sibling file of the
    /// same package cannot be read and may write anything, and a call through a
    /// callable field hands the receiver to nobody.
    fn method_writes_receiver(&self, recv: &str, method: &str) -> bool {
        let typ = self.stated_receiver_type(recv);
        if let Some(key) = typ
            .as_deref()
            .and_then(|typ| self.method_key_of_type(typ, method))
        {
            return self
                .funcs
                .get(&key)
                .is_some_and(|function| function.writes_receiver);
        }
        if self
            .values
            .get(recv)
            .and_then(|value| exact_property(value, method, self.value_limits))
            .is_some_and(|value| crate::contains_callable(&value))
        {
            return false;
        }
        // A method whose body this walk cannot read may assign through its
        // receiver: an unqualified type names this package, so a sibling
        // file's method is as unreadable as one this file declares but whose
        // body it does not hold, and a qualified one names another package of
        // this repository or a dependency, whose method bodies this file does
        // not hold either. The standard library is the exception: the engine
        // models those receiver identities itself.
        typ.is_some_and(|typ| match typ.split_once('.') {
            Some((pkg, _)) => self
                .imports
                .get(pkg)
                .is_some_and(|path| !crate::external::is_go_stdlib(path)),
            None => !GO_PREDECLARED_TYPES.contains(&typ.as_str()),
        })
    }

    /// The caller bindings the calls of the enclosing blocks write: the storage
    /// each hands its callee, and the receiver of each method that assigns
    /// through it. A callable this walk cannot place in program order is no
    /// more ordered against those writes than against the block's own
    /// assignments, so it reads none of the names they reach.
    ///
    /// The callee and the values are read where the out-of-order statement
    /// stands, which is where the body's captured bindings were made; a call
    /// the block states below it is answered by the same bindings.
    ///
    /// `own` names the calls of the body being walked, by source position. A
    /// body is ordered against itself: what it hands its own callees is written
    /// where it reads it, so those calls cost it nothing.
    fn stated_call_writes(&self, own: &HashSet<(usize, usize)>) -> Vec<String> {
        self.called_scopes
            .iter()
            .flatten()
            .filter(|call| !own.contains(&call.pos))
            .flat_map(|call| {
                self.escaped_call_arguments(&self.resolve_callee(&call.func), &call.args)
                    .names()
            })
            .collect()
    }

    /// The names an invalidation reaches: those handed over, plus every name
    /// that addresses the same storage (`p := &cfg` makes `p` and `cfg` one
    /// binding as far as a write through either is concerned).
    fn with_aliased_storage(&self, names: Vec<String>) -> Vec<String> {
        self.with_stated_storage(names, &[])
    }

    /// The same, plus the pointers `stated` names: alias pairs read from a
    /// block's text rather than from the bindings this walk has reached.
    fn with_stated_storage(&self, names: Vec<String>, stated: &[(String, String)]) -> Vec<String> {
        let mut out = names;
        let mut index = 0;
        while index < out.len() {
            let name = out[index].clone();
            let aliases: Vec<String> = self
                .address_aliases
                .iter()
                .chain(stated.iter().map(|(pointer, target)| (pointer, target)))
                .filter(|(pointer, target)| **pointer == name || **target == name)
                .flat_map(|(pointer, target)| [pointer.clone(), target.clone()])
                .collect();
            for alias in aliases {
                if !out.contains(&alias) {
                    out.push(alias);
                }
            }
            index += 1;
        }
        out
    }

    /// The caller binding an argument hands over: the name behind an explicit
    /// `&x`, or one holding a composite value Go passes by reference.
    fn escaping_argument_name(&self, argument: &Expression) -> Option<String> {
        let (target, addressed) = match argument {
            Expression::Operation(operation)
                if operation.op == Operator::And && operation.y.is_none() =>
            {
                (&*operation.x, true)
            }
            other => (other, false),
        };
        let name = assignment_base_name(target)?;
        if addressed {
            return Some(name);
        }
        matches!(
            self.values.get(&name).map(|value| &value.kind),
            Some(
                SemanticValueKind::Object(_)
                    | SemanticValueKind::Collection { .. }
                    | SemanticValueKind::Union(_)
            )
        )
        .then_some(name)
    }

    /// Enter local bodies with call-site values in a plan; summaries and edges serve composition.
    fn call_local(
        &mut self,
        name: &str,
        args: &[Expression],
        node: ProvenanceRef,
        origin: Option<ValueOrigin>,
        sequence: bool,
        receiver: Option<SemanticValue>,
    ) {
        let closure_body = self
            .named_func(name)
            .filter(|function| function.is_closure)
            .map(|function| (function.body.clone(), function.assigns_outer.clone()));
        if let Some((body, assigns_outer)) = closure_body {
            // A closure assigns the bindings it captured when it runs, so the
            // caller's exact view of a name it writes does not survive the call.
            for captured in assigns_outer {
                self.values.remove(&captured);
                self.resource_values.remove(&captured);
            }
            self.widen_channels_in_block(&body, 0);
            for value in self.channel_values.values_mut() {
                *value = unresolved_resource("filesystem");
            }
        }
        if self.collect_edges {
            let arg_exprs: Vec<ResourceExpr> = args.iter().map(|a| self.fs_arg(a)).collect();
            let obj_args = self.obj_args(args);
            self.record_edge(name, arg_exprs, obj_args, origin);
            return;
        }
        // Break recursion: a function already being inlined is not re-entered.
        if self.following.contains(name) {
            return;
        }
        if matches!(&self.out, Out::Plan { .. })
            && !sequence
            && let Some(function) = self.named_func(name).cloned()
        {
            // Ordinary functions see package bindings; closures also see their captured values.
            let mut values = if function.is_closure {
                self.values.clone()
            } else {
                self.package_constants.clone()
            };
            let mut params = HashMap::new();
            for param in &function.params {
                params.insert(
                    param.clone(),
                    ResourceExpr::Parameter {
                        name: param.clone(),
                    },
                );
                values.insert(param.clone(), SemanticValue::parameter(param));
            }
            for (param, arg) in function.params.iter().zip(args) {
                params.insert(param.clone(), self.fs_arg(arg));
                values.insert(
                    param.clone(),
                    // Function-typed parameter dispatch belongs to the repository composer.
                    self.value_of(arg)
                        .filter(|value| !crate::contains_callable(value))
                        .unwrap_or_else(|| SemanticValue::parameter(param)),
                );
            }
            if let Some(name) = &function.receiver
                && let Some(receiver) = receiver
            {
                values.insert(name.clone(), receiver);
            }
            let saved_params = std::mem::replace(&mut self.params, params);
            let saved_values = std::mem::replace(&mut self.values, values);
            let saved_types = self.local_types.clone();
            let saved_resources = self.resource_values.clone();
            if !function.is_closure {
                self.local_types = self.package_types.clone();
                self.resource_values.clear();
            }
            self.local_types.extend(function.types.clone());
            let saved_locals = std::mem::replace(&mut self.local_vars, function.locals.clone());
            let saved_function = std::mem::replace(&mut self.fact_function, name.to_string());
            self.entered_callables.insert(name.to_string());
            self.following.insert(name.to_string());
            let previous_call = if let Out::Plan { builder, .. } = &mut self.out {
                Some(
                    builder.enter_condition_call(
                        &self
                            .condition_source
                            .call_site(&(builder.source_span(&[node]), &origin)),
                    ),
                )
            } else {
                None
            };
            if function.is_closure {
                self.push_condition(effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: function.body.pos.0 as u32,
                        end: function.body.pos.1 as u32,
                    },
                    effinterp_proto::ConditionKind::Dispatch,
                    0,
                    2,
                    true,
                    false,
                ));
            }
            self.control_enter(&function.body);
            self.walk_block(&function.body);
            self.control_leave();
            if function.is_closure {
                self.conditions.pop();
            }
            if let (Some(previous), Out::Plan { builder, .. }) = (previous_call, &mut self.out) {
                builder.leave_condition_call(previous);
            }
            self.following.remove(name);
            self.fact_function = saved_function;
            self.local_vars = saved_locals;
            self.local_types = saved_types;
            self.resource_values = saved_resources;
            self.values = saved_values;
            self.params = saved_params;
            return;
        }
        let Some(summary) = self.summaries.get(name) else {
            // A bare-name call to something not defined locally: unknown.
            return;
        };
        if matches!(&self.out, Out::Plan { .. }) {
            self.entered_callables.insert(name.to_string());
        }
        let arg_exprs: Vec<ResourceExpr> = args.iter().map(|a| self.fs_arg(a)).collect();
        let bindings = bind_positional(&summary.params, &arg_exprs);
        let effects = summary.effects.clone();
        let requirements = match &mut self.out {
            Out::Capture(cap) => Some(cap.control.requirements(&summary.control_flow)),
            Out::Plan { .. } => None,
        };
        let transfers = summary.transfers.clone();
        let mut boundaries = summary.boundaries.clone();
        // A standard sequence collector supplies its own effect-free yield
        // callback. Retract only this function's first parameter invocation.
        if sequence && let Some(parameter) = summary.params.first() {
            boundaries.retain(|boundary| {
                !boundary
                    .callee
                    .as_ref()
                    .is_some_and(|callee| callee.module == name && callee.symbol == *parameter)
            });
        }
        let coverage: Vec<_> = summary
            .coverage
            .iter()
            .filter(|(domain, _)| {
                !sequence
                    || boundaries
                        .iter()
                        .any(|boundary| boundary.domains.contains(domain))
            })
            .cloned()
            .collect();
        let mut slots = Vec::with_capacity(effects.len());
        for effect in &effects {
            let mut specialized = effect.clone();
            specialized.resource = substitute_resource_expr(&effect.resource, &bindings);
            specialized.provenance = vec![node];
            slots.push(self.emit_effect(specialized));
        }
        for binding in &transfers {
            let (Some(source), Some(destination)) = (
                slots.get(binding.source as usize).copied().flatten(),
                slots.get(binding.destination as usize).copied().flatten(),
            ) else {
                continue;
            };
            self.record_transfer(Some(source), Some(destination));
        }
        if let Some(requirements) = requirements {
            self.control_applications
                .push(SiteFacts::call(&requirements, |fact| match fact {
                    ControlFact::Effect(slot) => slots
                        .get(slot as usize)
                        .copied()
                        .flatten()
                        .map(ControlFact::Effect),
                    ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
                }));
        }
        for b in boundaries {
            let mut b = b;
            b.provenance = vec![node];
            self.out_boundary(b);
        }
        for (d, l) in coverage {
            self.out_coverage(d, l);
        }
    }

    fn widen_escaped_channel(&mut self, expr: &Expression) {
        self.widen_escaped_channel_at(expr, 0);
    }

    fn widen_escaped_channel_at(&mut self, expr: &Expression, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        match expr {
            Expression::Ident(ident) => {
                self.channel_values
                    .insert(ident.name.clone(), unresolved_resource("filesystem"));
            }
            Expression::Paren(paren) => self.widen_escaped_channel_at(&paren.expr, depth + 1),
            Expression::Operation(operation)
                if operation.op == Operator::Arrow && operation.y.is_none() => {}
            Expression::Operation(operation) => {
                self.widen_escaped_channel_at(&operation.x, depth + 1);
                if let Some(right) = &operation.y {
                    self.widen_escaped_channel_at(right, depth + 1);
                }
            }
            Expression::Star(star) => self.widen_escaped_channel_at(&star.right, depth + 1),
            Expression::Call(call) => {
                for argument in &call.args {
                    self.widen_escaped_channel_at(argument, depth + 1);
                }
            }
            Expression::Selector(selector) => self.widen_escaped_channel_at(&selector.x, depth + 1),
            Expression::Index(index) => self.widen_escaped_channel_at(&index.left, depth + 1),
            Expression::IndexList(index) => self.widen_escaped_channel_at(&index.left, depth + 1),
            Expression::TypeAssert(assertion) => {
                self.widen_escaped_channel_at(&assertion.left, depth + 1)
            }
            Expression::CompositeLit(literal) => {
                self.widen_channels_in_literal(&literal.val, depth + 1);
            }
            Expression::List(expressions) => {
                for expression in expressions {
                    self.widen_escaped_channel_at(expression, depth + 1);
                }
            }
            Expression::FuncLit(literal) => self.widen_channels_in_block(&literal.body, depth + 1),
            _ => {}
        }
    }

    fn widen_channels_in_literal(&mut self, literal: &gosyn::ast::LiteralValue, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        for element in &literal.values {
            match &element.val {
                Element::Expr(expression) => self.widen_escaped_channel_at(expression, depth + 1),
                Element::LitValue(literal) => self.widen_channels_in_literal(literal, depth + 1),
            }
        }
    }

    fn widen_channels_in_block(&mut self, block: &BlockStmt, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        for statement in &block.list {
            self.widen_channels_in_statement(statement, depth + 1);
        }
    }

    fn widen_channels_in_statement(&mut self, statement: &Statement, depth: u32) {
        if depth >= MAX_WALK_DEPTH {
            self.partial_walk();
            return;
        }
        match statement {
            Statement::Send(send) => {
                self.widen_escaped_channel_at(&send.chan, depth + 1);
                self.widen_escaped_channel_at(&send.value, depth + 1);
            }
            Statement::Expr(expression) => {
                if let Expression::Call(call) = &expression.expr {
                    for argument in &call.args {
                        self.widen_escaped_channel_at(argument, depth + 1);
                    }
                }
            }
            Statement::Go(go_) => {
                for argument in &go_.call.args {
                    self.widen_escaped_channel_at(argument, depth + 1);
                }
            }
            Statement::Defer(defer) => {
                for argument in &defer.call.args {
                    self.widen_escaped_channel_at(argument, depth + 1);
                }
            }
            Statement::Assign(assign) => {
                for expression in &assign.right {
                    if channel_name(expression).is_some()
                        || matches!(
                            expression,
                            Expression::CompositeLit(_) | Expression::FuncLit(_)
                        )
                    {
                        self.widen_escaped_channel_at(expression, depth + 1);
                    }
                }
            }
            Statement::Declaration(DeclStmt::Variable(declaration)) => {
                for expression in declaration.specs.iter().flat_map(|spec| &spec.values) {
                    if channel_name(expression).is_some()
                        || matches!(
                            expression,
                            Expression::CompositeLit(_) | Expression::FuncLit(_)
                        )
                    {
                        self.widen_escaped_channel_at(expression, depth + 1);
                    }
                }
            }
            Statement::Return(return_) => {
                for expression in &return_.ret {
                    self.widen_escaped_channel_at(expression, depth + 1);
                }
            }
            Statement::If(if_) => {
                if let Some(init) = &if_.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                self.widen_channels_in_block(&if_.body, depth + 1);
                if let Some(else_) = &if_.else_ {
                    self.widen_channels_in_statement(else_, depth + 1);
                }
            }
            Statement::For(for_) => {
                if let Some(init) = &for_.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                if let Some(cond) = &for_.cond {
                    self.widen_channels_in_statement(cond, depth + 1);
                }
                self.widen_channels_in_block(&for_.body, depth + 1);
                if let Some(post) = &for_.post {
                    self.widen_channels_in_statement(post, depth + 1);
                }
            }
            Statement::Range(range) => self.widen_channels_in_block(&range.body, depth + 1),
            Statement::Label(label) => self.widen_channels_in_statement(&label.stmt, depth + 1),
            Statement::Block(block) => self.widen_channels_in_block(block, depth + 1),
            Statement::Switch(switch) => {
                if let Some(init) = &switch.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                for clause in &switch.block.body {
                    for statement in clause.body.iter() {
                        self.widen_channels_in_statement(statement, depth + 1);
                    }
                }
            }
            Statement::TypeSwitch(switch) => {
                if let Some(init) = &switch.init {
                    self.widen_channels_in_statement(init, depth + 1);
                }
                if let Some(tag) = &switch.tag {
                    self.widen_channels_in_statement(tag, depth + 1);
                }
                for clause in &switch.block.body {
                    for statement in clause.body.iter() {
                        self.widen_channels_in_statement(statement, depth + 1);
                    }
                }
            }
            Statement::Select(select) => {
                for clause in &select.body.body {
                    if let Some(comm) = &clause.comm {
                        self.widen_channels_in_statement(comm, depth + 1);
                    }
                    for statement in clause.body.iter() {
                        self.widen_channels_in_statement(statement, depth + 1);
                    }
                }
            }
            Statement::Empty(_)
            | Statement::IncDec(_)
            | Statement::Branch(_)
            | Statement::Declaration(DeclStmt::Type(_) | DeclStmt::Const(_)) => {}
        }
    }

    // ---- callee / argument resolution ----

    fn resolve_callee(&self, func: &Expression) -> Callee {
        match func {
            Expression::Ident(id) => {
                // A symbol names a local binding, never a callable this file or
                // its package declares, so only a callable value names a target.
                let bound = self
                    .values
                    .get(&id.name)
                    .and_then(|value| match &value.kind {
                        SemanticValueKind::Callable(CallableValue::Function { name }) => {
                            Some(name.as_str())
                        }
                        _ => None,
                    });
                // A local variable or parameter shadows every package and
                // sibling symbol spelled the same way.
                let shadowed = self.local_vars.contains(&id.name);
                if let Some((local, method)) = bound.and_then(|name| name.split_once('.'))
                    && let Some(path) = self.imports.get(local)
                {
                    Callee::Pkg {
                        path: path.clone(),
                        method: method.to_string(),
                        local: local.to_string(),
                    }
                } else if !self.collect_edges
                    && self.fact_scope.is_none()
                    && bound
                        .is_some_and(|name| name.contains('.') && self.named_func(name).is_some())
                {
                    Callee::Dynamic(id.name.clone())
                } else if let Some(name) = bound
                    && self.named_func(name).is_some()
                {
                    Callee::Local(name.to_string())
                } else if let Some(name) = bound {
                    Callee::MaybeSibling(name.to_string())
                } else if shadowed {
                    Callee::Dynamic(id.name.clone())
                } else if self.named_func(&id.name).is_some() {
                    Callee::Local(id.name.clone())
                } else if !GO_BUILTINS.contains(&id.name.as_str()) {
                    // Not defined in this file, not a builtin/conversion, not
                    // a builtin: a candidate for a same-package sibling file
                    // or a callable parameter resolved by composition.
                    Callee::MaybeSibling(id.name.clone())
                } else {
                    Callee::Unknown
                }
            }
            Expression::Selector(sel) => {
                if let Expression::Ident(pkg) = &*sel.x {
                    if let Some(path) = self.imports.get(&pkg.name) {
                        return Callee::Pkg {
                            path: path.clone(),
                            method: sel.sel.name.clone(),
                            local: pkg.name.clone(),
                        };
                    }
                    // A method on a local variable — dispatchable only if the
                    // composer can type the receiver from a constructor.
                    return Callee::Method {
                        recv: pkg.name.clone(),
                        method: sel.sel.name.clone(),
                    };
                }
                // A method on a freshly constructed package type —
                // `(&net.Dialer{}).DialContext(...)` — resolves through the
                // literal's qualified type as `Type.Method`.
                if let Some((local, path, typ)) = self.composite_pkg_type(&sel.x) {
                    return Callee::Pkg {
                        path,
                        method: format!("{typ}.{}", sel.sel.name),
                        local,
                    };
                }
                if let Expression::Selector(receiver) = &*sel.x
                    && let Expression::Ident(base) = &*receiver.x
                {
                    return Callee::Method {
                        recv: format!("{}.{}", base.name, receiver.sel.name),
                        method: sel.sel.name.clone(),
                    };
                }
                Callee::Unknown
            }
            Expression::Paren(p) => self.resolve_callee(&p.expr),
            Expression::Index(index)
                if !self.collect_edges
                    && self.fact_scope.is_none()
                    && matches!(self.resolve_callee(&index.left), Callee::Dynamic(_)) =>
            {
                Callee::Dynamic(go_callee_name(&index.left))
            }
            Expression::Index(index) => self.resolve_callee(&index.left),
            Expression::IndexList(index) => self.resolve_callee(&index.left),
            _ => Callee::Unknown,
        }
    }

    /// The imported package and type name of a composite literal receiver
    /// (`&net.Dialer{}` through `&`, `*`, parens): (local qualifier, import
    /// path, type name).
    fn composite_pkg_type(&self, expr: &Expression) -> Option<(String, String, String)> {
        match expr {
            Expression::Paren(p) => self.composite_pkg_type(&p.expr),
            Expression::Operation(op) if op.y.is_none() => self.composite_pkg_type(&op.x),
            Expression::Star(s) => self.composite_pkg_type(&s.right),
            Expression::CompositeLit(cl) => {
                if let Expression::Selector(sel) = &*cl.typ
                    && let Expression::Ident(pkg) = &*sel.x
                {
                    let path = self.imports.get(&pkg.name)?;
                    return Some((pkg.name.clone(), path.clone(), sel.sel.name.clone()));
                }
                None
            }
            _ => None,
        }
    }

    /// Resolve an argument expression to a resource expression.
    fn fs_arg(&self, expr: &Expression) -> ResourceExpr {
        match expr {
            Expression::BasicLit(lit) if is_str_lit(lit) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: unquote(&lit.value),
                },
            },
            Expression::Ident(id) => match self.params.get(&id.name) {
                Some(bound) => bound.clone(),
                None => self
                    .resource_values
                    .get(&id.name)
                    .cloned()
                    .or_else(|| {
                        self.values
                            .get(&id.name)
                            .and_then(|value| match &value.kind {
                                SemanticValueKind::Literal(path) => Some(ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path: path.clone() },
                                }),
                                SemanticValueKind::Join(_) => {
                                    Some(typed_concat(vec![value.lower_resource()], "filesystem"))
                                }
                                SemanticValueKind::Union(_)
                                | SemanticValueKind::Path { .. }
                                | SemanticValueKind::Environment(_)
                                | SemanticValueKind::Property { .. }
                                | SemanticValueKind::Pattern { .. }
                                | SemanticValueKind::Resource(_) => {
                                    Some(value.lower_resource_for_domain("filesystem"))
                                }
                                _ => None,
                            })
                    })
                    .or_else(|| {
                        (!self.local_vars.contains(&id.name) && self.fact_scope.is_some()).then(
                            || ResourceExpr::Parameter {
                                name: id.name.clone(),
                            },
                        )
                    })
                    .unwrap_or(unresolved_resource("filesystem")),
            },
            Expression::Selector(selector) => {
                if let Expression::Ident(receiver) = &*selector.x
                    && let Some(value) = self.values.get(&receiver.name).and_then(|value| {
                        exact_property(value, &selector.sel.name, self.value_limits)
                    })
                {
                    return value.lower_resource_for_domain("filesystem");
                }
                if let Expression::Ident(receiver) = &*selector.x
                    && self.fact_function.split_once('.').is_some_and(|(typ, _)| {
                        self.dispatch_type(&receiver.name).as_deref() == Some(typ)
                    })
                {
                    return ResourceExpr::Parameter {
                        name: selector.sel.name.clone(),
                    };
                }
                self.value_of(expr)
                    .map(|value| value.lower_resource_for_domain("filesystem"))
                    .unwrap_or(unresolved_resource("filesystem"))
            }
            Expression::Paren(p) => self.fs_arg(&p.expr),
            Expression::Operation(operation)
                if operation.op == Operator::Arrow && operation.y.is_none() =>
            {
                self.received_resource(expr)
                    .unwrap_or(unresolved_resource("filesystem"))
            }
            // String concatenation is typed by the filesystem sink.
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                typed_concat(
                    vec![
                        self.concatenation_part(&operation.x, "filesystem"),
                        self.concatenation_part(operation.y.as_ref().unwrap(), "filesystem"),
                    ],
                    "filesystem",
                )
            }
            // filepath.Join(a, b, ...) -> Join.
            Expression::Call(call) => {
                if let Callee::Pkg { path, method, .. } = self.resolve_callee(&call.func)
                    && path == "path/filepath"
                    && method == "Join"
                {
                    let parts: Vec<ResourceExpr> = call
                        .args
                        .iter()
                        .map(|arg| self.concatenation_part(arg, "filesystem"))
                        .collect();
                    if !parts.is_empty() {
                        // Summary parameters must survive until call-site binding.
                        if parts
                            .iter()
                            .all(|part| matches!(part, ResourceExpr::Parameter { .. }))
                        {
                            return ResourceExpr::Join { parts };
                        }
                        return sink_typed_join(parts, "filesystem");
                    }
                }
                unresolved_resource("filesystem")
            }
            _ => unresolved_resource("filesystem"),
        }
    }

    fn network_arg(&self, expr: &Expression) -> ResourceExpr {
        match expr {
            Expression::BasicLit(literal) if is_str_lit(literal) => {
                url_endpoint_resource(&unquote(&literal.value))
            }
            Expression::Paren(paren) => self.network_arg(&paren.expr),
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                sink_typed_join(
                    vec![
                        self.concatenation_part(&operation.x, "network"),
                        self.concatenation_part(operation.y.as_ref().unwrap(), "network"),
                    ],
                    "network",
                )
            }
            _ => self
                .value_of(expr)
                .and_then(|value| match value.kind {
                    SemanticValueKind::Literal(value) => Some(url_endpoint_resource(&value)),
                    SemanticValueKind::Join(_) => {
                        Some(sink_typed_join(vec![value.lower_resource()], "network"))
                    }
                    SemanticValueKind::Endpoint { .. }
                    | SemanticValueKind::Resource(ResourceIdentity::NetworkEndpoint { .. }) => {
                        Some(value.lower_resource_for_domain("network"))
                    }
                    _ => None,
                })
                .unwrap_or(unresolved_resource("network")),
        }
    }

    fn concatenation_part(&self, expr: &Expression, domain: &str) -> ResourceExpr {
        match expr {
            Expression::BasicLit(literal) if is_str_lit(literal) => ResourceExpr::Literal {
                value: unquote(&literal.value),
            },
            Expression::Paren(paren) => self.concatenation_part(&paren.expr, domain),
            Expression::Operation(operation)
                if operation.op == Operator::Add && operation.y.is_some() =>
            {
                ResourceExpr::Join {
                    parts: vec![
                        self.concatenation_part(&operation.x, domain),
                        self.concatenation_part(operation.y.as_ref().unwrap(), domain),
                    ],
                }
            }
            Expression::Call(call)
                if matches!(
                    self.resolve_callee(&call.func),
                    Callee::Pkg { ref path, ref method, .. }
                        if path == "os" && matches!(method.as_str(), "Getenv" | "LookupEnv")
                ) =>
            {
                call.args
                    .first()
                    .and_then(string_of)
                    .filter(|name| !name.is_empty())
                    .map(|name| ResourceExpr::Environment { name })
                    .unwrap_or(unresolved_resource("environment"))
            }
            _ if domain == "filesystem" => self.fs_arg(expr),
            _ => self
                .value_of(expr)
                .and_then(|value| match value.kind {
                    SemanticValueKind::Literal(_)
                    | SemanticValueKind::Environment(_)
                    | SemanticValueKind::Path { .. }
                    | SemanticValueKind::Endpoint { .. }
                    | SemanticValueKind::Property { .. }
                    | SemanticValueKind::Join(_)
                    | SemanticValueKind::Pattern { .. }
                    | SemanticValueKind::Resource(_) => Some(value.lower_resource()),
                    SemanticValueKind::Unresolved { ref family, .. } if family == "environment" => {
                        Some(value.lower_resource())
                    }
                    _ => None,
                })
                .unwrap_or(unresolved_resource("value")),
        }
    }

    // ---- output plumbing (plan vs capture) ----

    fn node(&mut self, span: (u32, u32)) -> ProvenanceRef {
        match &mut self.out {
            Out::Plan { builder, .. } => builder.node(
                ProvenanceKind::SourceSpan {
                    start: span.0,
                    end: span.1,
                },
                self.scope.as_slice(),
            ),
            // Capture provenance is filled at apply time; a sentinel is fine.
            Out::Capture(_) => ProvenanceRef(0),
        }
    }

    fn emit(
        &mut self,
        op: &str,
        resource: ResourceExpr,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) {
        self.emit_slot(op, resource, attrs, node);
    }

    /// Emit one effect from an attribute list and report its slot.
    fn emit_slot(
        &mut self,
        op: &str,
        resource: ResourceExpr,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) -> Option<u32> {
        let attributes = attrs
            .iter()
            .filter(|(_, on)| *on)
            .map(|(k, _)| (k.to_string(), AttrValue::Bool(true)))
            .collect();
        self.emit_effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(op),
            resource,
            attributes,
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: None,
            realm: effinterp_proto::ExecutionRealm::Host,
            provenance: vec![node],
        })
    }

    fn push_condition(&mut self, condition: effinterp_proto::Condition) {
        let mut condition = Some(condition);
        if let Out::Plan { builder, .. } = &mut self.out {
            builder.bind_source_condition(&mut condition);
        }
        self.conditions.push(condition.unwrap());
    }

    /// Emit one effect and report its slot in the receiving effect list, so a
    /// transfer emitter can pair the endpoints it just produced.
    fn emit_effect(&mut self, mut effect: Effect) -> Option<u32> {
        effect.condition = effinterp_proto::Condition::compose(
            effect.condition.iter().chain(self.conditions.iter()),
        );
        if effect.operation.domain() == "filesystem" {
            effect.resource = anchor_fs_text_concat(
                effect.resource,
                match &self.out {
                    Out::Plan { cwd, .. } => {
                        cwd.map(|cwd| crate::paths::resolve_fs_path(cwd, None))
                    }
                    Out::Capture(_) => None,
                },
            );
        }
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        let uses_cwd =
            effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource);
        match &mut self.out {
            Out::Plan {
                builder, cwd_node, ..
            } => {
                if uses_cwd {
                    effect.provenance.extend(*cwd_node);
                }
                builder.effect(effect)
            }
            Out::Capture(cap) => {
                if cap.effects.len() < MAX_SUMMARY_ITEMS {
                    cap.effects.push(effect);
                    Some(cap.effects.len() as u32 - 1)
                } else {
                    None
                }
            }
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
        match &mut self.out {
            Out::Plan { builder, .. } => builder.transfer_binding(binding),
            Out::Capture(cap) => {
                if !cap.transfers.contains(&binding) {
                    cap.transfers.push(binding);
                }
            }
        }
    }

    fn record_edge(
        &mut self,
        callee: &str,
        args: Vec<ResourceExpr>,
        obj_args: Vec<ValueArgument>,
        origin: Option<ValueOrigin>,
    ) {
        self.push_edge(callee, args, obj_args, origin, false);
    }

    /// The call edge of a bare name: its arguments, plus the value bound to
    /// the name itself when this file knows one.
    fn record_call_edge(
        &mut self,
        name: &str,
        call: &gosyn::ast::Call,
        origin: Option<ValueOrigin>,
        dynamic: bool,
    ) {
        let arg_exprs: Vec<ResourceExpr> = call.args.iter().map(|a| self.fs_arg(a)).collect();
        let mut obj_args = self.obj_args(&call.args);
        // A symbol names a local binding, which composition can only resolve by
        // name — and that name belongs to the local scope, not the package.
        if let Some(value) = self.values.get(name).filter(|value| {
            !matches!(&value.kind, SemanticValueKind::Symbol(symbol)
                if self.local_vars.contains(symbol))
        }) {
            obj_args.push(ValueArgument {
                name: Some("$callee".to_string()),
                index: usize::MAX,
                value: value.clone(),
            });
        }
        self.push_edge(name, arg_exprs, obj_args, origin, dynamic);
    }

    /// A call through a locally bound name: composition may follow the value
    /// bound to it, but must never resolve the name against the package.
    fn record_dynamic_edge(
        &mut self,
        callee: &str,
        args: Vec<ResourceExpr>,
        obj_args: Vec<ValueArgument>,
        origin: Option<ValueOrigin>,
    ) {
        self.push_edge(callee, args, obj_args, origin, true);
    }

    fn push_edge(
        &mut self,
        callee: &str,
        args: Vec<ResourceExpr>,
        obj_args: Vec<ValueArgument>,
        origin: Option<ValueOrigin>,
        dynamic_target: bool,
    ) {
        let binds = std::mem::take(&mut self.current_binds);
        let writes = std::mem::take(&mut self.pending_writes);
        let origin = origin.unwrap_or_else(|| self.next_origin());
        let mut arguments = positional_arguments(args);
        merge_arguments(&mut arguments, obj_args);
        if let Out::Capture(cap) = &mut self.out
            && cap.edges.len() < MAX_SUMMARY_ITEMS
        {
            cap.edges.push(CallEdge {
                condition: effinterp_proto::Condition::compose(&self.conditions),
                call_site: Some(self.condition_source.call_site(&(self.site_ordinal,))),
                callee: callee.to_string(),
                arguments,
                results: call_results(binds, Some(origin), None),
                dynamic_target,
                writes,
                ..Default::default()
            });
        }
    }

    fn out_boundary(&mut self, boundary: Boundary) {
        match &mut self.out {
            Out::Plan { builder, .. } => {
                builder.boundary(boundary);
            }
            Out::Capture(cap) => cap.boundaries.push(boundary),
        }
    }

    fn out_coverage(&mut self, domain: Domain, level: CoverageLevel) {
        match &mut self.out {
            Out::Plan { builder, .. } => builder.declare_coverage(domain, level),
            Out::Capture(cap) => cap.coverage.push((domain, level)),
        }
    }

    fn nest_subject(&mut self, subject: Subject, node: ProvenanceRef) {
        match &mut self.out {
            Out::Plan {
                builder,
                nest,
                depth,
                ..
            } => nest.nest(
                builder,
                Transition::file(subject)
                    .source_cwd(nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(nest.current_runtime_cwd().as_deref())
                    .cwd(builder.current_execution_cwd(), nest.current_cwd_node()),
                &[node],
                *depth,
            ),
            // A subprocess/SQL inside a summarized function needs the call
            // site's bindings to compose; record it as an opaque boundary.
            Out::Capture(_) => self.opaque(
                BoundaryReason::UNCOMPOSED_SUBPROCESS,
                BoundaryClass::Unmodeled,
                "process",
                node,
            ),
        }
    }

    fn opaque(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        domain: &str,
        node: ProvenanceRef,
    ) {
        self.out_boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new(domain)],
            provenance: vec![node],
            limit: None,
            detail: None,
        });
    }
}

/// How the frontend evaluated a call, for its control-flow site.
#[derive(Clone, Copy)]
enum GoCall {
    /// A direct interaction whose local reachability is explicitly known.
    Sink,
    /// A modeled or known-inert standard-library call.
    Modeled,
    /// A body this file declares, entered at the call.
    Local,
    /// A call that never returns; `unknown` when it may end the program
    /// successfully.
    Exit,
    /// Code the frontend cannot see.
    Opaque,
}

enum Callee {
    Pkg {
        path: String,
        method: String,
        /// The imported package's local qualifier as written (`ghcmd`), used to
        /// form the `pkg.Func` call edge the repo layer resolves via imports.
        local: String,
    },
    Local(String),
    /// A bare call defined in no local function: may live in a sibling file of
    /// the same package. The repo layer resolves or drops it.
    MaybeSibling(String),
    /// A call through a local binding (`handler := makeHandler(); handler()`,
    /// or a function-typed parameter). Only the value bound to that name may
    /// resolve it; the name itself belongs to the local scope.
    Dynamic(String),
    /// A method call on a local variable (`h.CreateTempFile()`), dispatched at
    /// composition time through the receiver's constructor-typed class.
    Method {
        recv: String,
        method: String,
    },
    Unknown,
}

/// The call a method's receiver is, through `&`, `*` and parens:
/// `NewExecutor().Run(...)`, `(&newCfg()).Save()`.
fn receiver_call(expr: &Expression) -> Option<&gosyn::ast::Call> {
    match expr {
        Expression::Call(call) => Some(call),
        Expression::Paren(paren) => receiver_call(&paren.expr),
        Expression::Star(star) => receiver_call(&star.right),
        Expression::Operation(operation) if operation.y.is_none() => receiver_call(&operation.x),
        _ => None,
    }
}

fn go_callee_name(mut expression: &Expression) -> String {
    let mut suffix = Vec::new();
    for _ in 0..MAX_WALK_DEPTH {
        match expression {
            Expression::Ident(name) => {
                return format!(
                    "{}{}",
                    name.name,
                    suffix.into_iter().rev().collect::<String>()
                );
            }
            Expression::Selector(selector) => {
                suffix.push(format!(".{}", selector.sel.name));
                expression = &selector.x;
            }
            Expression::Call(call) => {
                suffix.push("()".to_string());
                expression = &call.func;
            }
            Expression::Paren(paren) => expression = &paren.expr,
            Expression::Star(star) => expression = &star.right,
            Expression::Index(index) => {
                suffix.push("[?]".to_string());
                expression = &index.left;
            }
            _ => break,
        }
    }
    "<dynamic>".to_string()
}

fn call_pos(call: &gosyn::ast::Call) -> (u32, u32) {
    (call.pos.0 as u32, call.pos.1 as u32)
}

fn expression_pos(expr: &Expression) -> (u32, u32) {
    let start = match expr {
        Expression::List(values) => values.first().map(Expression::pos).unwrap_or(0),
        _ => expr.pos(),
    } as u32;
    (start, start.saturating_add(1))
}

fn channel_name(expr: &Expression) -> Option<&str> {
    match expr {
        Expression::Ident(ident) => Some(&ident.name),
        Expression::Paren(paren) => channel_name(&paren.expr),
        _ => None,
    }
}

fn fresh_channel_expression(expr: &Expression) -> bool {
    match expr {
        Expression::Call(call) => {
            matches!(&*call.func, Expression::Ident(ident) if ident.name == "make")
                && matches!(call.args.first(), Some(Expression::TypeChannel(_)))
        }
        Expression::Paren(paren) => fresh_channel_expression(&paren.expr),
        _ => false,
    }
}

fn computed_channel_expression(expr: &Expression) -> bool {
    match expr {
        Expression::Paren(paren) => computed_channel_expression(&paren.expr),
        Expression::Call(_) => true,
        Expression::Selector(_)
        | Expression::Index(_)
        | Expression::IndexList(_)
        | Expression::TypeAssert(_)
        | Expression::Star(_) => true,
        Expression::Operation(operation) => {
            operation.op == Operator::Arrow && operation.y.is_none()
        }
        _ => false,
    }
}
