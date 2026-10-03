//! Effect-directed Rust frontend, parsed with `syn` (native, no MSRV concern).
//!
//! It walks Rust source for calls that reach an external-resource boundary —
//! `std::fs`, `std::net`, `std::process::Command`, `std::env`, and a few common
//! crates —
//! resolving them by `use` path so a method on an unknown value never triggers
//! a model. It does not interpret Rust; it follows only what reaches an effect,
//! keeps non-literal arguments symbolic, and records an explicit boundary for
//! anything it cannot resolve (macros it can't expand, dynamic dispatch,
//! `unsafe`). Bounded declarative entry macros (`path::bin!(crate)`,
//! `main!(crate)`, `entry!(crate)`) are treated as a `fn main` that hands off
//! to the named crate — not a general macro expander.
//!
//! ## Execution, not source presence
//!
//! `analyze` describes what EXECUTING the source does: effects reachable from
//! `fn main` through a within-file call graph. A defined-but-uncalled function
//! contributes nothing to execution — it contributes a *callable* summary
//! instead (see [`crate::module_summary::module_summaries`]), so the repository can specialize it with
//! a caller's arguments across files.

mod control;
mod model;
mod summary;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
pub(crate) use model::DEFERRED_COMMAND;

use model::{
    CallKind, RustSinkDomain, RustSinkGiveUp, RustSinkResolution, arg_resource, base_effect,
    call_argument_resource, classify_call, command_effect, command_receiver, env_effect_struct,
    fs_effect_struct, git_effect_struct, git_resource, is_indirect_call, is_known_api,
    net_addr_effect_struct, net_effect_struct, polls_future_argument, resolve_rust_command_cwd,
    resolve_rust_env_name, resolve_rust_sink, rust_sink_boundary, rust_sink_detail,
    rust_unwalked_call_value, semantic_bindings, semantic_word,
};
use summary::{
    base_type_ident, generic_dispatch_types, outer_type_ident, receiver_type_ref,
    return_value_path, rust_dispatch_signature, rust_signature_type, type_idents,
};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ExecutionEdgeKind, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Expr, FnArg, ImplItem, Item, Local, Pat, Stmt, UseTree};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::SiteFacts;
use crate::module_summary::{CallEdge, ClassEntry, DispatchImpl, DispatchSignature, ImportBinding};
use crate::nest::{Nest, Transition, word_resource};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::{bind_positional, substitute_resource_expr};
use crate::word::{Word, WordPart};
use crate::{
    CallableValue, ObjectIdentity, ObjectValue, SemanticValue, SemanticValueKind, TypeRef,
    ValueLimits, canonical_rust_std_type, join_branches, property_access, substitute_value,
    substitute_value_counted,
};

/// Effect domains this frontend can surface.
const RUST_DOMAINS: [&str; 5] = ["environment", "filesystem", "git", "network", "process"];

/// Cap on AST nodes visited, so pathological input stays bounded.
use crate::limits::DEFAULT_MAX_RUST_NODES;
const MAX_VALUE_DEPTH: usize = 48;

/// Deepest chain of local-function summaries composed, guarding recursion on
/// top of the per-analysis visiting set.
const MAX_CALL_DEPTH: usize = 64;

/// Well-known standard-library constructors, converters, and control functions
/// that carry no effect. When a call resolves to none of the modeled effects
/// and is not a local function, these names are treated as effectless rather
/// than as an unresolved-call boundary. Real code is dense with `Ok`/`Err`/
/// `drop`, and reporting each as unresolved degrades every domain to Partial
/// and drowns the genuine signal. Every name here is a pure/formatting/terminal
/// operation that cannot reach a filesystem, process, network, or environment
/// effect; anything that plausibly could (fs/process/net) is deliberately
/// excluded so it still raises a boundary.
const EFFECTLESS_CALLS: &[&str] = &[
    // Result / Option constructors and variants.
    "Ok",
    "Err",
    "Some",
    "None",
    // Pure constructors and conversions commonly written as associated calls.
    "new",
    "with_capacity",
    "from",
    "from_utf8",
    // Value drop is a no-op for our effect domains.
    "drop",
    // Common pure conversions / accessors that also appear as free calls.
    "default",
    "into",
    "to_string",
    "to_owned",
    "clone",
    "as_ref",
    "as_str",
    // Panic-on-None/Err unwrappers: control flow only, no modeled effect.
    "unwrap",
    "expect",
    // Iterator construction and collection: pure.
    "iter",
    "collect",
    // In-memory formatting (the `format!`-style helper, not the macro).
    "format",
    // Assertions: control flow / panics only.
    "assert",
    "assert_eq",
    "assert_ne",
];

/// True if a bare single-segment call names a known-effectless std constructor,
/// converter, or control function (see [`EFFECTLESS_CALLS`]).
fn is_effectless_call(name: &str) -> bool {
    EFFECTLESS_CALLS.contains(&name)
}

/// True when a comment-masked source line is a bounded declarative entry
/// macro: `path::bin!(ident)`, `main!(ident)`, or `entry!(ident)`. Discovery
/// uses this so a binary whose `fn main` exists only after expansion is still
/// a program entry.
pub(crate) fn is_entry_macro_line(trimmed: &str) -> bool {
    let t = trimmed.trim_end().trim_end_matches(';').trim_end();
    let Some(idx) = t.find("!(") else {
        return false;
    };
    if !t.ends_with(')') {
        return false;
    }
    let head = &t[..idx];
    if !head
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        return false;
    }
    let name = head.rsplit("::").next().unwrap_or(head);
    matches!(name, "bin" | "main" | "entry")
}

// ---------------------------------------------------------------------------
// Bounded declarative entry macros
// ---------------------------------------------------------------------------

/// A crate/module handoff produced by `bin!` / `main!` / `entry!`.
struct EntryHandoff {
    crate_path: Vec<String>,
    func: String,
}

fn entry_macro_func(name: &str) -> Option<&'static str> {
    match name {
        "bin" => Some("uumain"),
        "main" => Some("main"),
        "entry" => Some("run"),
        _ => None,
    }
}

fn parse_entry_macro(mac: &syn::ItemMacro) -> Option<EntryHandoff> {
    let name = mac.mac.path.segments.last()?.ident.to_string();
    let func = entry_macro_func(&name)?.to_string();
    let crate_path = parse_handoff_path(&mac.mac.tokens)?;
    Some(EntryHandoff { crate_path, func })
}

/// The crate/module path the macro names: a single ident, a `foo::bar` path,
/// or the first path before a comma (`bin!(uu_cat, no_flush)`).
fn parse_handoff_path(tokens: &proc_macro2::TokenStream) -> Option<Vec<String>> {
    if let Ok(path) = syn::parse2::<syn::Path>(tokens.clone()) {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if !segs.is_empty() {
            return Some(segs);
        }
    }
    let mut segs = Vec::new();
    for tt in tokens.clone() {
        match tt {
            proc_macro2::TokenTree::Ident(id) => segs.push(id.to_string()),
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => break,
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ':' => {}
            _ if segs.is_empty() => return None,
            _ => {}
        }
    }
    (!segs.is_empty()).then_some(segs)
}

fn entry_handoffs(file: &syn::File) -> Vec<EntryHandoff> {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Macro(m) => parse_entry_macro(m),
            _ => None,
        })
        .collect()
}

fn handoff_call(h: &EntryHandoff) -> (CallEdge, ImportBinding) {
    let mut module = h.crate_path.clone();
    module.push(h.func.clone());
    (
        CallEdge {
            callee: h.func.clone(),
            ..Default::default()
        },
        ImportBinding {
            local: h.func.clone(),
            module: module.join("::"),
            imported: Some(h.func.clone()),
        },
    )
}

fn is_include_macro(mac: &syn::Macro) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|s| s.ident == "include")
}

fn has_drop_impl(file: &syn::File) -> bool {
    struct DropImpl(bool);
    impl<'ast> Visit<'ast> for DropImpl {
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            self.0 |= item.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Drop")
            });
            syn::visit::visit_item_impl(self, item);
        }
    }
    let mut visitor = DropImpl(false);
    visitor.visit_file(file);
    visitor.0
}

fn record_unexpanded_includes(
    builder: &mut PlanBuilder,
    file: &syn::File,
    scope: Option<ProvenanceRef>,
) {
    for item in &file.items {
        let Item::Macro(m) = item else {
            continue;
        };
        if !is_include_macro(&m.mac) {
            continue;
        }
        for domain in RUST_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        let node = builder.node(
            ProvenanceKind::ModelApplication {
                model: "rust/std@v0".to_string(),
            },
            scope.as_slice(),
        );
        let tokens = m.mac.tokens.to_string();
        let detail = if tokens.contains("OUT_DIR") {
            "include! of generated OUT_DIR source is not expanded"
        } else {
            "include! is not expanded"
        };
        builder.boundary(Boundary {
            reason: BoundaryReason::UNEXPANDED_MACRO,
            class: BoundaryClass::Unsupported,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: RUST_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

pub(crate) struct RustFrontend;

impl Frontend for RustFrontend {
    const LANGUAGE: &'static str = "rust";
    const DOMAINS: &'static [&'static str] = &RUST_DOMAINS;
    type Ast<'a> = syn::File;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        match syn::parse_file(source) {
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
        for domain in RUST_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::PARSE_ERROR,
            class: BoundaryClass::ParseFailure,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: RUST_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: scope.as_slice().to_vec(),
            limit: None,
            detail: Some(failure.detail.clone()),
        });
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        file: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let source = input.source;
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        if builder.current_execution_is_selected_input() {
            for item in &file.items {
                match item {
                    Item::Mod(module) if module.content.is_none() => {
                        nest.record_dependency_request(builder, &module.ident.to_string());
                    }
                    Item::ExternCrate(dependency)
                        if !matches!(
                            dependency.ident.to_string().as_str(),
                            "std" | "core" | "alloc"
                        ) =>
                    {
                        nest.record_dependency_request(builder, &dependency.ident.to_string());
                    }
                    _ => {}
                }
            }
        }

        let uses = Resolver::from_file(file, source);
        let fns = collect_fns(file, &uses);
        record_unexpanded_includes(builder, file, scope);
        let first_effect = builder.effects_len();
        let has_execution_root = fns.get("main").is_some();

        // Execution is what `fn main` reaches; a library file (no main) executes
        // nothing, but its functions still surface as callable summaries. A
        // declarative entry macro is a cross-file handoff, not in-file execution.
        if let Some(main) = fns.get("main") {
            let (value_facts, value_steps) = rust_value_facts_counted(
                std::iter::once("main"),
                &fns,
                &uses,
                nest.limits.value_limits(),
            );
            let range = main.body.span().byte_range();
            if !crate::nest::charge_analysis_steps(
                builder,
                nest.budget,
                value_steps,
                Some((range.start as u32, range.end as u32)),
            ) {
                return WalkOutcome::default();
            }
            let mut ex = Executor {
                builder,
                source,
                nest,
                uses: &main.uses,
                fns: &fns,
                cwd,
                cwd_node,
                scope,
                depth,
                nodes: 0,
                visiting: HashSet::new(),
                closures: HashMap::new(),
                futures: HashMap::new(),
                receiver_types: HashMap::new(),
                receiver_fields: HashMap::new(),
                value_facts: value_facts_or_default(&value_facts, "main"),
                all_value_facts: &value_facts,
            };
            ex.builder.control_enter(source, false, |graph| {
                control::build(graph, main.body, has_drop_impl(file));
            });
            ex.walk_block(main.body, &empty(), &HashMap::new(), &mut HashSet::new());
            if has_drop_impl(file) {
                ex.unresolved("Drop cleanup on normal return or unwinding");
            }
            ex.builder.control_leave();
        }
        let declared_callables = if !fns.order.is_empty()
            && !has_execution_root
            && builder.effects_len() == first_effect
        {
            fns.order.clone()
        } else {
            Vec::new()
        };
        for domain in RUST_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        WalkOutcome { declared_callables }
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        _file: &str,
        _scope: crate::ScopeKey,
        value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summary::summarize_ast(source, ast, value_limits)
    }
}

// ---------------------------------------------------------------------------
// Function collection
// ---------------------------------------------------------------------------

struct FnDef<'a> {
    params: Vec<String>,
    /// Declared base-type ident per parameter (through `&`/`Vec`/`Option`/
    /// `Box`/`Result` wrappers), when a single identifier names it. This is
    /// what lets a method call on a parameter dispatch by its declared type.
    param_types: HashMap<String, String>,
    /// Proven outer receiver types, kept separately from peeled element types.
    param_receiver_types: HashMap<String, TypeRef>,
    receiver_shadow_types: HashSet<String>,
    body: &'a Block,
    /// The impl type for a method (`impl App` -> "App"); None for free fns.
    impl_type: Option<String>,
    /// Trait and canonical receiver named by an `impl Trait for Type` block.
    dispatch_impl: Option<DispatchImpl>,
    dispatch_signature: DispatchSignature,
    is_async: bool,
    /// The class the function returns, when the return type's base ident is
    /// `Self`, the impl type, or a struct/enum defined in this file.
    ret_class: Option<String>,
    /// Canonical identity for an externally defined returned class.
    ret_type: Option<TypeRef>,
    /// File imports overlaid with every `use` item in this function body.
    uses: Resolver,
}

#[derive(Clone)]
struct ClosureDef {
    params: Vec<String>,
    body: Expr,
}

fn future_def(expr: &Expr, fns: &Fns<'_>) -> Option<Expr> {
    match expr {
        Expr::Async(_) => Some(expr.clone()),
        Expr::Call(call) => {
            let segments = path_segments(&call.func)?;
            (segments.len() == 1
                && fns
                    .get(&segments[0])
                    .is_some_and(|function| function.is_async))
            .then(|| expr.clone())
        }
        Expr::Group(group) => future_def(&group.expr, fns),
        Expr::Paren(paren) => future_def(&paren.expr, fns),
        _ => None,
    }
}

fn bound_future(expr: &Expr, fns: &Fns<'_>, futures: &HashMap<String, Expr>) -> Option<Expr> {
    future_def(expr, fns).or_else(|| future_name(expr).and_then(|name| futures.get(&name).cloned()))
}

fn future_eager_arguments<'a>(expr: &'a Expr, fns: &Fns<'_>) -> Vec<&'a Expr> {
    match expr {
        Expr::Call(call) => {
            let Some(segments) = path_segments(&call.func) else {
                return Vec::new();
            };
            if segments.len() == 1
                && fns
                    .get(&segments[0])
                    .is_some_and(|function| function.is_async)
            {
                call.args.iter().collect()
            } else {
                Vec::new()
            }
        }
        Expr::Group(group) => future_eager_arguments(&group.expr, fns),
        Expr::Paren(paren) => future_eager_arguments(&paren.expr, fns),
        _ => Vec::new(),
    }
}

fn future_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Group(group) => future_name(&group.expr),
        Expr::Paren(paren) => future_name(&paren.expr),
        Expr::Path(path) => single_ident(&path.path),
        _ => None,
    }
}

fn closure_def(expr: &Expr) -> Option<ClosureDef> {
    let closure = closure_expr(expr)?;
    Some(ClosureDef {
        params: closure.inputs.iter().filter_map(pat_ident).collect(),
        body: (*closure.body).clone(),
    })
}

fn closure_expr(expr: &Expr) -> Option<&syn::ExprClosure> {
    match expr {
        Expr::Closure(closure) => Some(closure),
        Expr::Paren(paren) => closure_expr(&paren.expr),
        Expr::Group(group) => closure_expr(&group.expr),
        _ => None,
    }
}

#[derive(Default)]
struct ClosureCaptureVisitor {
    names: HashSet<String>,
}

impl<'ast> Visit<'ast> for ClosureCaptureVisitor {
    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let mut nested = ClosureCaptureVisitor::default();
        nested.visit_expr(&closure.body);
        let unit_variants = HashMap::new();
        for input in &closure.inputs {
            let mut names = Vec::new();
            rust_pattern_binding_names(input, &mut names, &unit_variants);
            for name in names {
                nested.names.remove(&name);
            }
        }
        self.names.extend(nested.names);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(name) = single_ident(&path.path) {
            self.names.insert(name);
        }
    }

    fn visit_macro(&mut self, macro_: &'ast syn::Macro) {
        collect_token_idents(macro_.tokens.clone(), &mut self.names);
    }
}

fn collect_token_idents(tokens: proc_macro2::TokenStream, names: &mut HashSet<String>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Group(group) => collect_token_idents(group.stream(), names),
            proc_macro2::TokenTree::Ident(ident) => {
                names.insert(ident.to_string());
            }
            _ => {}
        }
    }
}

fn closure_captures(expr: &Expr, state: &ValueState) -> Option<HashSet<String>> {
    let closure = closure_expr(expr)?;
    let mut visitor = ClosureCaptureVisitor::default();
    visitor.visit_expr(&closure.body);
    let unit_variants = HashMap::new();
    for input in &closure.inputs {
        let mut names = Vec::new();
        rust_pattern_binding_names(input, &mut names, &unit_variants);
        for name in names {
            visitor.names.remove(&name);
        }
    }
    visitor
        .names
        .retain(|name| state.values.contains_key(name) || state.commands.contains_key(name));
    Some(visitor.names)
}

fn called_closure_captures(expr: &Expr, state: &ValueState) -> Option<HashSet<String>> {
    closure_captures(expr, state)
        .or_else(|| future_name(expr).and_then(|name| state.closures.get(&name).cloned()))
}

struct LoopFactVisitor<'a> {
    tracked_keys: &'a HashSet<ExprKey>,
    changed_bindings: &'a HashSet<String>,
    scopes: Vec<HashMap<String, bool>>,
    widened: HashSet<ExprKey>,
}

impl LoopFactVisitor<'_> {
    fn is_tainted(&self, name: &str) -> bool {
        for scope in self.scopes.iter().rev() {
            if let Some(tainted) = scope.get(name) {
                return *tainted;
            }
        }
        self.changed_bindings.contains(name)
    }

    fn expr_tainted(&self, expr: &Expr) -> bool {
        let mut names = ClosureCaptureVisitor::default();
        names.visit_expr(expr);
        names.names.iter().any(|name| self.is_tainted(name))
    }

    fn bind_pattern(&mut self, pattern: &Pat, tainted: bool) {
        let mut names = Vec::new();
        rust_pattern_binding_names(pattern, &mut names, &HashMap::new());
        if let Some(scope) = self.scopes.last_mut() {
            for name in names {
                scope.insert(name, tainted);
            }
        }
    }

    fn taint(&mut self, name: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), true);
                return;
            }
        }
    }
}

impl<'ast> Visit<'ast> for LoopFactVisitor<'_> {
    fn visit_item(&mut self, _: &'ast Item) {}

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}

    fn visit_block(&mut self, block: &'ast Block) {
        self.scopes.push(HashMap::new());
        syn::visit::visit_block(self, block);
        self.scopes.pop();
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
        let tainted = local
            .init
            .as_ref()
            .is_some_and(|init| self.expr_tainted(&init.expr));
        self.bind_pattern(&local.pat, tainted);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, assign);
        if self.expr_tainted(&assign.right)
            && let Some(name) = mutated_base_ident(&assign.left)
        {
            self.taint(&name);
        }
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        syn::visit::visit_expr_binary(self, binary);
        if is_compound_assignment(&binary.op)
            && self.expr_tainted(&binary.right)
            && let Some(name) = mutated_base_ident(&binary.left)
        {
            self.taint(&name);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        let method = call.method.to_string();
        if matches!(method.as_str(), "arg" | "args")
            && call.args.iter().any(|argument| self.expr_tainted(argument))
            && let Some(name) = chain_base_ident(&call.receiver)
        {
            self.taint(&name);
        }
    }

    fn visit_expr_for_loop(&mut self, loop_: &'ast syn::ExprForLoop) {
        self.visit_expr(&loop_.expr);
        self.scopes.push(HashMap::new());
        self.bind_pattern(&loop_.pat, self.expr_tainted(&loop_.expr));
        self.visit_block(&loop_.body);
        self.scopes.pop();
    }

    fn visit_expr_while(&mut self, loop_: &'ast syn::ExprWhile) {
        if let Expr::Let(let_) = &*loop_.cond {
            self.visit_expr(&let_.expr);
            self.scopes.push(HashMap::new());
            self.bind_pattern(&let_.pat, self.expr_tainted(&let_.expr));
            self.visit_block(&loop_.body);
            self.scopes.pop();
        } else {
            syn::visit::visit_expr_while(self, loop_);
        }
    }

    fn visit_expr_if(&mut self, if_: &'ast syn::ExprIf) {
        if let Expr::Let(let_) = &*if_.cond {
            self.visit_expr(&let_.expr);
            self.scopes.push(HashMap::new());
            self.bind_pattern(&let_.pat, self.expr_tainted(&let_.expr));
            self.visit_block(&if_.then_branch);
            self.scopes.pop();
            if let Some((_, else_)) = &if_.else_branch {
                self.visit_expr(else_);
            }
        } else {
            syn::visit::visit_expr_if(self, if_);
        }
    }

    fn visit_expr_match(&mut self, match_: &'ast syn::ExprMatch) {
        self.visit_expr(&match_.expr);
        let tainted = self.expr_tainted(&match_.expr);
        for arm in &match_.arms {
            self.scopes.push(HashMap::new());
            self.bind_pattern(&arm.pat, tainted);
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            self.scopes.pop();
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        let key = expr_key(expr);
        if self.tracked_keys.contains(&key) && self.expr_tainted(expr) {
            self.widened.insert(key);
        }
        syn::visit::visit_expr(self, expr);
    }
}

impl FnDef<'_> {
    /// Parameters mapped to symbolic `Parameter` expressions, for summarizing.
    fn param_env(&self) -> HashMap<String, ResourceExpr> {
        self.params
            .iter()
            .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
            .collect()
    }

    /// Parameter names declared as `std::process::Command` in `uses`' scope.
    fn command_params(&self, uses: &Resolver) -> HashSet<String> {
        self.param_types
            .iter()
            .filter(|(_, t)| uses.resolve(&[(*t).clone()]) == "std::process::Command")
            .map(|(p, _)| p.clone())
            .collect()
    }
}

struct Fns<'a> {
    /// Free functions keyed by bare name; impl methods keyed `Type.method`
    /// (the form instance dispatch resolves at composition time).
    map: HashMap<String, FnDef<'a>>,
    order: Vec<String>,
    /// Structs/enums defined in the file, with struct fields' declared types
    /// as attribute classes.
    classes: Vec<ClassEntry>,
    class_receiver_types: HashMap<String, HashMap<String, TypeRef>>,
    unit_variants: HashMap<String, String>,
    consts: HashMap<String, String>,
}

impl<'a> Fns<'a> {
    fn get(&self, name: &str) -> Option<&FnDef<'a>> {
        self.map.get(name)
    }
}

fn collect_fns<'a>(file: &'a syn::File, uses: &Resolver) -> Fns<'a> {
    let mut classes = Vec::new();
    let consts = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item) => str_lit(&item.expr).map(|value| (item.ident.to_string(), value)),
            Item::Static(item) => str_lit(&item.expr).map(|value| (item.ident.to_string(), value)),
            _ => None,
        })
        .collect();
    let mut declared_unit_variants = HashMap::<String, HashSet<String>>::new();
    for item in &file.items {
        match item {
            Item::Struct(s) => {
                let attr_classes = s
                    .fields
                    .iter()
                    .filter_map(|f| {
                        let name = f.ident.as_ref()?.to_string();
                        let ty = base_type_ident(&f.ty)?;
                        Some((name, ty))
                    })
                    .collect();
                classes.push(ClassEntry {
                    name: s.ident.to_string(),
                    attr_classes,
                    ..Default::default()
                });
            }
            Item::Enum(e) => {
                declared_unit_variants.insert(
                    e.ident.to_string(),
                    e.variants
                        .iter()
                        .filter(|variant| matches!(variant.fields, syn::Fields::Unit))
                        .map(|variant| variant.ident.to_string())
                        .collect(),
                );
                classes.push(ClassEntry {
                    name: e.ident.to_string(),
                    ..Default::default()
                });
            }
            Item::Trait(t) => classes.push(ClassEntry {
                name: t.ident.to_string(),
                ..Default::default()
            }),
            _ => {}
        }
    }
    let mut unit_variants = HashMap::from([("None".to_string(), "None".to_string())]);
    for glob in &uses.globs {
        if let Some(variants) = glob
            .last()
            .and_then(|enum_name| declared_unit_variants.get(enum_name))
        {
            unit_variants.extend(
                variants
                    .iter()
                    .map(|variant| (variant.clone(), variant.clone())),
            );
        }
    }
    for (alias, path) in &uses.aliases {
        let Some(variant) = path
            .last()
            .zip(path.iter().rev().nth(1))
            .filter(|(variant, owner)| {
                declared_unit_variants
                    .get(*owner)
                    .is_some_and(|variants| variants.contains(*variant))
            })
            .map(|(variant, _)| variant)
        else {
            continue;
        };
        unit_variants.insert(alias.clone(), variant.clone());
    }
    let mut class_names: HashSet<String> = classes.iter().map(|c| c.name.clone()).collect();
    class_names.extend(file.items.iter().filter_map(|item| match item {
        Item::Type(alias) => Some(alias.ident.to_string()),
        _ => None,
    }));
    let class_receiver_types = file
        .items
        .iter()
        .filter_map(|item| {
            let Item::Struct(item) = item else {
                return None;
            };
            let mut shadowed = class_names.clone();
            shadowed.extend(
                item.generics
                    .type_params()
                    .map(|param| param.ident.to_string()),
            );
            let fields = item
                .fields
                .iter()
                .filter_map(|field| {
                    Some((
                        field.ident.as_ref()?.to_string(),
                        receiver_type_ref(&field.ty, uses, &shadowed)?,
                    ))
                })
                .collect();
            Some((item.ident.to_string(), fields))
        })
        .collect();

    let mut map = HashMap::new();
    let mut order = Vec::new();
    for item in &file.items {
        match item {
            Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                add_fn(
                    &mut map,
                    &mut order,
                    name,
                    &f.sig,
                    &f.block,
                    None,
                    None,
                    &class_names,
                    uses,
                    None,
                );
            }
            Item::Impl(im) => {
                let Some(impl_type) = outer_type_ident(&im.self_ty) else {
                    continue;
                };
                let impl_generics: HashMap<_, _> = im
                    .generics
                    .type_params()
                    .enumerate()
                    .map(|(index, param)| (param.ident.to_string(), format!("$impl{index}")))
                    .collect();
                let mut impl_shadowed = class_names.clone();
                impl_shadowed.extend(
                    im.generics
                        .type_params()
                        .map(|param| param.ident.to_string()),
                );
                let dispatch_impl = im
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| path.segments.last())
                    .map(|segment| DispatchImpl {
                        contract: segment.ident.to_string(),
                        receiver: receiver_type_ref(&im.self_ty, uses, &impl_shadowed)
                            .and_then(|ty| match ty {
                                TypeRef::External { path } => Some(path),
                                TypeRef::Repo { .. } => None,
                            })
                            .unwrap_or_else(|| {
                                impl_generics.get(&impl_type).cloned().unwrap_or_else(|| {
                                    uses.resolve(std::slice::from_ref(&impl_type))
                                })
                            }),
                        type_arguments: match &segment.arguments {
                            syn::PathArguments::AngleBracketed(arguments) => arguments
                                .args
                                .iter()
                                .map(|argument| match argument {
                                    syn::GenericArgument::Type(ty) => {
                                        rust_signature_type(ty, uses, &impl_generics)
                                    }
                                    syn::GenericArgument::Lifetime(_) => "'_".to_string(),
                                    _ => "<unsupported>".to_string(),
                                })
                                .collect(),
                            _ => Vec::new(),
                        },
                    });
                for it in &im.items {
                    if let ImplItem::Fn(m) = it {
                        let name = format!("{impl_type}.{}", m.sig.ident);
                        add_fn(
                            &mut map,
                            &mut order,
                            name,
                            &m.sig,
                            &m.block,
                            Some(impl_type.clone()),
                            dispatch_impl.clone(),
                            &class_names,
                            uses,
                            Some(&impl_generics),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    collect_inline_mod_fns(
        &file.items,
        &mut Vec::new(),
        &mut map,
        &mut order,
        &class_names,
        uses,
    );
    Fns {
        map,
        order,
        classes,
        class_receiver_types,
        unit_variants,
        consts,
    }
}

fn collect_inline_mod_fns<'a>(
    items: &'a [Item],
    prefix: &mut Vec<String>,
    map: &mut HashMap<String, FnDef<'a>>,
    order: &mut Vec<String>,
    class_names: &HashSet<String>,
    uses: &Resolver,
) {
    for item in items {
        let Item::Mod(module) = item else { continue };
        let Some((_, nested)) = &module.content else {
            continue;
        };
        prefix.push(module.ident.to_string());
        for item in nested {
            if let Item::Fn(function) = item {
                let name = format!("{}::{}", prefix.join("::"), function.sig.ident);
                add_fn(
                    map,
                    order,
                    name,
                    &function.sig,
                    &function.block,
                    None,
                    None,
                    class_names,
                    uses,
                    None,
                );
            }
        }
        collect_inline_mod_fns(nested, prefix, map, order, class_names, uses);
        prefix.pop();
    }
}

#[allow(clippy::too_many_arguments)]
fn add_fn<'a>(
    map: &mut HashMap<String, FnDef<'a>>,
    order: &mut Vec<String>,
    name: String,
    sig: &'a syn::Signature,
    block: &'a Block,
    impl_type: Option<String>,
    dispatch_impl: Option<DispatchImpl>,
    class_names: &HashSet<String>,
    uses: &Resolver,
    parent_generics: Option<&HashMap<String, String>>,
) {
    if map.contains_key(&name) {
        return; // keep the first definition; deterministic
    }
    let mut params = Vec::new();
    let mut param_types = HashMap::new();
    let mut param_receiver_types = HashMap::new();
    let mut receiver_shadow_types = class_names.clone();
    receiver_shadow_types.extend(
        sig.generics
            .type_params()
            .map(|param| param.ident.to_string()),
    );
    if let Some(parent_generics) = parent_generics {
        receiver_shadow_types.extend(parent_generics.keys().cloned());
    }
    let generic_types = generic_dispatch_types(sig);
    for arg in &sig.inputs {
        if let FnArg::Typed(pt) = arg
            && let Pat::Ident(id) = &*pt.pat
        {
            let pname = id.ident.to_string();
            if let Some(ty) = base_type_ident(&pt.ty) {
                param_types.insert(pname.clone(), generic_types.get(&ty).cloned().unwrap_or(ty));
            }
            if let Some(ty) = receiver_type_ref(&pt.ty, uses, &receiver_shadow_types) {
                param_receiver_types.insert(pname.clone(), ty);
            }
            params.push(pname);
        }
    }
    // The returned class: `Self`/the impl type when the return type mentions
    // it, else the single file-local class it names — searched through generic
    // arguments so `ConfigResult<Config>` still types as `Config`.
    let mut ret_type = None;
    let ret_class = match &sig.output {
        syn::ReturnType::Type(_, ty) => {
            let mut ids = Vec::new();
            type_idents(ty, &mut ids);
            if ids.iter().any(|i| i == "Self") {
                impl_type.clone()
            } else if let Some(t) = impl_type.as_ref().filter(|t| ids.contains(t)) {
                Some(t.clone())
            } else {
                let mut matches = ids.iter().filter(|i| class_names.contains(*i));
                match (matches.next(), matches.next()) {
                    (Some(t), None) => Some(t.clone()),
                    _ => return_value_path(ty).and_then(|path| {
                        let name = path.last()?.clone();
                        let identity = uses.resolve(&path);
                        if identity != name
                            && !identity.starts_with("crate::")
                            && !identity.starts_with("self::")
                            && !identity.starts_with("super::")
                        {
                            ret_type = Some(TypeRef::External { path: identity });
                            Some(name)
                        } else {
                            None
                        }
                    }),
                }
            }
        }
        syn::ReturnType::Default => None,
    };
    let dispatch_signature = rust_dispatch_signature(
        sig,
        uses,
        dispatch_impl.as_ref().and(impl_type.as_deref()),
        parent_generics,
    );
    let function_uses = uses.with_function_body(block);
    order.push(name.clone());
    map.insert(
        name,
        FnDef {
            params,
            param_types,
            param_receiver_types,
            receiver_shadow_types,
            body: block,
            impl_type,
            dispatch_impl,
            dispatch_signature,
            is_async: sig.asyncness.is_some(),
            ret_class,
            ret_type,
            uses: function_uses,
        },
    );
}

// ---------------------------------------------------------------------------
// Use-path resolution (ownership)
// ---------------------------------------------------------------------------

/// Maps a local alias to the full path it refers to, so `remove_dir_all(..)`,
/// `fs::remove_dir_all(..)`, and `std::fs::remove_dir_all(..)` all resolve to
/// the same API. Glob prefixes let a bare name resolve through `use std::fs::*`.
#[derive(Clone, Default)]
struct Resolver {
    guards: std::rc::Rc<crate::guards::GuardRegions>,
    source_id: u64,
    /// alias -> full path segments (e.g. "fs" -> ["std","fs"]).
    aliases: HashMap<String, Vec<String>>,
    /// glob prefixes (e.g. ["std","fs"] from `use std::fs::*`).
    globs: Vec<Vec<String>>,
    /// import bindings in source order, for module_summaries.
    imports: Vec<ImportBinding>,
    /// Public imports forwarded by this module.
    exports: Vec<ImportBinding>,
}

impl Resolver {
    fn from_file(file: &syn::File, source: &str) -> Self {
        let mut r = Resolver {
            source_id: source.bytes().fold(0xcbf29ce484222325, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
            }),
            ..Resolver::default()
        };
        r.guards = std::rc::Rc::new(rust_guard_regions(file, source));
        for item in &file.items {
            match item {
                Item::Use(u) => r.walk_use(&u.tree, &mut Vec::new(), is_exported(&u.vis)),
                Item::ExternCrate(ext) => r.bind_extern_crate(ext),
                _ => {}
            }
        }
        r
    }

    /// `extern crate grep_cli as cli` binds `cli` like a `use` alias. A `pub`
    /// item is also a module export (`imported: None`) so a crate root can
    /// re-export another workspace crate as a path segment.
    fn bind_extern_crate(&mut self, ext: &syn::ItemExternCrate) {
        let crate_name = ext.ident.to_string();
        if crate_name == "self" || matches!(crate_name.as_str(), "std" | "core" | "alloc") {
            return;
        }
        let alias = ext
            .rename
            .as_ref()
            .map(|(_, ident)| ident.to_string())
            .unwrap_or_else(|| crate_name.clone());
        self.aliases.insert(alias.clone(), vec![crate_name.clone()]);
        if is_exported(&ext.vis) {
            self.exports.push(ImportBinding {
                local: alias,
                module: crate_name,
                imported: None,
            });
        }
    }

    fn walk_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>, exported: bool) {
        match tree {
            UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.walk_use(&p.tree, prefix, exported);
                prefix.pop();
            }
            UseTree::Name(n) => {
                let name = n.ident.to_string();
                if name == "self" {
                    if let Some(alias) = prefix.last().cloned() {
                        self.bind(alias, prefix.clone(), exported);
                    }
                } else {
                    let mut full = prefix.clone();
                    full.push(name.clone());
                    self.bind(name, full, exported);
                }
            }
            UseTree::Rename(rn) => {
                let mut full = prefix.clone();
                if rn.ident != "self" {
                    full.push(rn.ident.to_string());
                }
                self.bind(rn.rename.to_string(), full, exported);
            }
            UseTree::Group(g) => {
                for item in &g.items {
                    self.walk_use(item, prefix, exported);
                }
            }
            UseTree::Glob(_) => {
                self.globs.push(prefix.clone());
                // Exposed as a `*` binding so the repo layer can resolve names
                // through the glob target's own definitions and re-exports
                // (`use super::*` against a `lib.rs` re-export hub).
                let binding = ImportBinding {
                    local: "*".to_string(),
                    module: prefix.join("::"),
                    imported: None,
                };
                self.imports.push(binding.clone());
                if exported {
                    self.exports.push(binding);
                }
            }
        }
    }

    fn bind(&mut self, alias: String, full: Vec<String>, exported: bool) {
        let binding = ImportBinding {
            local: alias.clone(),
            module: full.join("::"),
            imported: full.last().cloned(),
        };
        self.imports.push(binding.clone());
        if exported {
            self.exports.push(binding);
        }
        self.aliases.insert(alias, full);
    }

    fn with_function_body(&self, body: &Block) -> Self {
        let mut local = Resolver {
            source_id: self.source_id,
            guards: self.guards.clone(),
            ..Resolver::default()
        };
        FunctionUseCollector {
            resolver: &mut local,
        }
        .visit_block(body);

        let mut aliases = self.aliases.clone();
        aliases.extend(local.aliases);
        local.aliases = aliases;
        local.globs.extend(self.globs.iter().cloned());
        local.imports = self.imports.clone();
        local.exports = self.exports.clone();
        local
    }

    /// Resolve a call path's segments to a canonical `a::b::c` string.
    fn resolve(&self, segs: &[String]) -> String {
        if segs.is_empty() {
            return String::new();
        }
        // Leading crate roots are already canonical.
        const ROOTS: [&str; 6] = ["std", "core", "alloc", "crate", "self", "super"];
        if ROOTS.contains(&segs[0].as_str()) {
            return segs.join("::");
        }
        if let Some(full) = self.aliases.get(&segs[0]) {
            let mut out = full.clone();
            out.extend_from_slice(&segs[1..]);
            return out.join("::");
        }
        // A bare name may have come through a glob import.
        if segs.len() == 1 {
            for g in &self.globs {
                let mut cand = g.clone();
                cand.push(segs[0].clone());
                if is_known_api(&cand.join("::")) {
                    return cand.join("::");
                }
            }
        }
        // A well-known std module or type reaching this file through a glob
        // re-export hub (`use super::*` against a lib.rs `pub(crate) use
        // std::{env, fs, process::Command, ...}`) resolves as std — the
        // pattern `just` uses throughout.
        if !self.globs.is_empty() {
            let prefix: Option<&[&str]> = match segs[0].as_str() {
                "env" | "fs" | "io" | "net" | "path" | "process" | "thread" => Some(&["std"]),
                "Command" => Some(&["std", "process"]),
                "File" | "OpenOptions" => Some(&["std", "fs"]),
                "TcpStream" | "TcpListener" => Some(&["std", "net"]),
                _ => None,
            };
            if let Some(prefix) = prefix {
                let mut out: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
                out.extend_from_slice(segs);
                return out.join("::");
            }
        }
        segs.join("::")
    }

    fn imports(&self) -> Vec<ImportBinding> {
        self.imports.clone()
    }

    fn exports(&self) -> Vec<ImportBinding> {
        self.exports.clone()
    }

    /// True when `name` is a named `use` binding in this file.
    fn is_imported(&self, name: &str) -> bool {
        self.aliases.contains_key(name)
    }

    fn path_is_imported(&self, segments: &[String]) -> bool {
        segments.first().is_some_and(|root| {
            self.aliases.contains_key(root) || matches!(root.as_str(), "std" | "core" | "alloc")
        })
    }
}

struct FunctionUseCollector<'a> {
    resolver: &'a mut Resolver,
}

impl<'ast> Visit<'ast> for FunctionUseCollector<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.resolver.walk_use(&item.tree, &mut Vec::new(), false);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}

    fn visit_item_mod(&mut self, _item: &'ast syn::ItemMod) {}
}

fn is_exported(visibility: &syn::Visibility) -> bool {
    match visibility {
        syn::Visibility::Public(_) => true,
        syn::Visibility::Restricted(restricted) => !restricted.path.is_ident("self"),
        syn::Visibility::Inherited => false,
    }
}

type ExprKey = (usize, usize);

#[derive(Clone, Default, PartialEq, Eq)]
struct CommandCandidates {
    values: Vec<Vec<SemanticValue>>,
    cwd: Option<SemanticValue>,
    widened: bool,
}

#[derive(Clone, Default)]
struct ValueState {
    values: HashMap<String, SemanticValue>,
    commands: HashMap<String, CommandCandidates>,
    closures: HashMap<String, HashSet<String>>,
}

#[derive(Clone, Default)]
struct ValueFacts {
    expressions: HashMap<ExprKey, SemanticValue>,
    commands: HashMap<ExprKey, CommandCandidates>,
    returns: Option<SemanticValue>,
}

static DEFAULT_VALUE_FACTS: LazyLock<ValueFacts> = LazyLock::new(ValueFacts::default);

fn value_facts_or_default<'a>(
    facts: &'a HashMap<String, ValueFacts>,
    name: &str,
) -> &'a ValueFacts {
    facts.get(name).unwrap_or(&DEFAULT_VALUE_FACTS)
}

fn unresolved_value_facts() -> ValueFacts {
    ValueFacts {
        returns: Some(SemanticValue::unresolved("value")),
        ..ValueFacts::default()
    }
}

fn expr_key(expr: &Expr) -> ExprKey {
    span_key(expr)
}

fn span_key(node: &impl Spanned) -> ExprKey {
    let range = node.span().byte_range();
    (range.start, range.end)
}

fn rust_value_facts<'a>(
    names: impl IntoIterator<Item = &'a str>,
    fns: &Fns<'_>,
    uses: &Resolver,
    value_limits: crate::ValueLimits,
) -> HashMap<String, ValueFacts> {
    rust_value_facts_counted(names, fns, uses, value_limits).0
}

fn rust_value_facts_counted<'a>(
    names: impl IntoIterator<Item = &'a str>,
    fns: &Fns<'_>,
    uses: &Resolver,
    value_limits: crate::ValueLimits,
) -> (HashMap<String, ValueFacts>, u64) {
    let mut visiting = HashSet::new();
    let mut cache = HashMap::new();
    let mut value_steps = 0;
    let mut total_nodes = 0u64;
    for name in names {
        let _walk = crate::limits::summary_walk();
        let mut nodes = 0;
        infer_rust_value_facts(
            name,
            fns,
            uses,
            &mut visiting,
            &mut cache,
            &mut nodes,
            &mut value_steps,
            0,
            value_limits,
        );
        total_nodes = total_nodes.saturating_add(nodes);
    }
    // Execution walks every match arm, including arms value analysis can prove
    // unreachable, so every declared local function needs a safe fact entry.
    for name in &fns.order {
        cache.entry(name.clone()).or_default();
    }
    let steps = total_nodes.saturating_add(value_steps);
    crate::limits::note_summary_value_steps(steps);
    (cache, steps)
}

#[allow(clippy::too_many_arguments)]
fn infer_rust_value_facts(
    name: &str,
    fns: &Fns<'_>,
    _uses: &Resolver,
    visiting: &mut HashSet<String>,
    cache: &mut HashMap<String, ValueFacts>,
    nodes: &mut u64,
    value_steps: &mut u64,
    depth: usize,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    if let Some(facts) = cache.get(name) {
        return facts.returns.clone();
    }
    let Some(function) = fns.get(name) else {
        cache.insert(name.to_string(), ValueFacts::default());
        return None;
    };
    if *nodes >= crate::limits::invocation_node_limit(DEFAULT_MAX_RUST_NODES) {
        let facts = unresolved_value_facts();
        let returns = facts.returns.clone();
        cache.insert(name.to_string(), facts);
        return returns;
    }
    if depth >= MAX_CALL_DEPTH || !visiting.insert(name.to_string()) {
        let facts = unresolved_value_facts();
        let returns = facts.returns.clone();
        cache.insert(name.to_string(), facts);
        return returns;
    }
    let mut analyzer = ValueAnalyzer {
        value_limits,
        function: name,
        fns,
        uses: &function.uses,
        visiting,
        cache,
        nodes,
        value_steps,
        depth,
        facts: ValueFacts::default(),
        return_values: Vec::new(),
        value_depth: 0,
    };
    let mut state = ValueState::default();
    state.values.extend(
        fns.consts
            .iter()
            .map(|(name, value)| (name.clone(), SemanticValue::literal(value.clone()))),
    );
    for parameter in &function.params {
        state.values.insert(
            parameter.clone(),
            SemanticValue::parameter(parameter)
                .with_type(function.param_receiver_types.get(parameter).cloned()),
        );
    }
    if let Some(impl_type) = &function.impl_type {
        let properties = fns
            .classes
            .iter()
            .find(|class| class.name == *impl_type)
            .into_iter()
            .flat_map(|class| class.attr_classes.iter())
            .map(|(field, _)| (field.clone(), SemanticValue::parameter(field)))
            .collect();
        state.values.insert(
            "self".to_string(),
            object_value(impl_type.clone(), properties),
        );
    }
    let tail = analyzer.block(function.body, &mut state);
    if !is_never(&tail) && !is_unknown_unit(&tail) {
        analyzer.return_values.push(tail);
    }
    if !analyzer.return_values.is_empty() {
        analyzer.facts.returns = Some(join_branches(analyzer.return_values, value_limits));
    }
    analyzer.visiting.remove(name);
    let facts = std::mem::take(&mut analyzer.facts);
    let returns = facts.returns.clone();
    analyzer.cache.insert(name.to_string(), facts);
    returns
}

struct ValueAnalyzer<'a, 'b> {
    value_limits: crate::ValueLimits,
    function: &'a str,
    fns: &'a Fns<'a>,
    uses: &'a Resolver,
    visiting: &'b mut HashSet<String>,
    cache: &'b mut HashMap<String, ValueFacts>,
    nodes: &'b mut u64,
    value_steps: &'b mut u64,
    depth: usize,
    facts: ValueFacts,
    return_values: Vec<SemanticValue>,
    value_depth: usize,
}

impl ValueAnalyzer<'_, '_> {
    fn block(&mut self, block: &Block, state: &mut ValueState) -> SemanticValue {
        let mut tail = SemanticValue::unresolved("unit");
        let mut scoped_bindings = HashMap::new();
        for statement in &block.stmts {
            match statement {
                Stmt::Local(local) => {
                    save_pattern_bindings(
                        &local.pat,
                        state,
                        &mut scoped_bindings,
                        &self.fns.unit_variants,
                    );
                    let Some(init) = &local.init else { continue };
                    let closure = called_closure_captures(&init.expr, state);
                    let mut command_state =
                        bound_command_chain_appends_arguments(&init.expr, state)
                            .then(|| state.clone());
                    let value = self.expr(&init.expr, state);
                    let value = if is_unresolved_value(&value)
                        && pat_ident(&local.pat).is_some()
                        && let Some((start, end)) =
                            cross_file_value_call_key(&init.expr, self.fns, self.uses)
                    {
                        let symbol = SemanticValue::symbol(self.call_scope((start, end)));
                        self.facts.expressions.insert((start, end), symbol.clone());
                        symbol
                    } else {
                        value
                    };
                    let group = self.branch_group(&init.expr);
                    bind_rust_pattern(
                        &local.pat,
                        &value,
                        state,
                        &group,
                        None,
                        &self.fns.unit_variants,
                        self.value_limits,
                    );
                    if let Some(name) = pat_ident(&local.pat) {
                        let command_state = command_state.as_mut().unwrap_or(&mut *state);
                        if let Some(commands) = self.command_candidates(&init.expr, command_state) {
                            invalidate_command_alias_source(&init.expr, &name, state);
                            state.commands.insert(name.clone(), commands);
                        } else {
                            state.commands.remove(&name);
                        }
                        if let Some(captures) = closure {
                            state.closures.insert(name, captures);
                        } else {
                            state.closures.remove(&name);
                        }
                    }
                    if let Some(diverge) = &init.diverge {
                        self.expr(&diverge.1, state);
                    }
                    tail = SemanticValue::unresolved("unit");
                }
                Stmt::Expr(expr, semi) => {
                    tail = self.expr(expr, state);
                    if semi.is_some() {
                        tail = SemanticValue::unresolved("unit");
                    }
                    if is_never(&tail) {
                        break;
                    }
                }
                Stmt::Macro(macro_) => {
                    self.macro_value(&macro_.mac, state);
                    tail = SemanticValue::unresolved("unit");
                }
                Stmt::Item(_) => {}
            }
        }
        restore_scope_bindings(state, scoped_bindings);
        tail
    }

    fn expr(&mut self, expr: &Expr, state: &mut ValueState) -> SemanticValue {
        if over_budget(self.nodes) || self.value_depth >= MAX_VALUE_DEPTH {
            let value = SemanticValue::unresolved("value");
            self.facts.expressions.insert(expr_key(expr), value.clone());
            return value;
        }
        self.value_depth += 1;
        let value = match expr {
            Expr::Lit(literal) => match &literal.lit {
                syn::Lit::Str(value) => SemanticValue::literal(value.value()),
                syn::Lit::Char(value) => SemanticValue::literal(value.value().to_string()),
                syn::Lit::ByteStr(value) => {
                    SemanticValue::literal(String::from_utf8_lossy(&value.value()).into_owned())
                }
                syn::Lit::Int(value) => SemanticValue::literal(value.base10_digits()),
                _ => SemanticValue::unresolved("scalar"),
            },
            Expr::Path(path) => rust_path_value(path, state),
            Expr::Reference(reference) => {
                let value = self.expr(&reference.expr, state);
                if reference.mutability.is_some()
                    && let Some(name) = mutated_base_ident(&reference.expr)
                {
                    invalidate_value_binding(state, &name);
                }
                value
            }
            Expr::Paren(paren) => self.expr(&paren.expr, state),
            Expr::Group(group) => self.expr(&group.expr, state),
            Expr::Try(try_) => peel_rust_wrapper(
                self.expr(&try_.expr, state),
                &["Ok", "Some"],
                self.value_limits,
            ),
            Expr::Await(await_) => self.expr(&await_.base, state),
            Expr::Unary(unary) => self.expr(&unary.expr, state),
            Expr::Cast(cast) => self.expr(&cast.expr, state),
            Expr::Array(array) => collection_value(
                array
                    .elems
                    .iter()
                    .map(|element| self.expr(element, state))
                    .collect(),
            ),
            Expr::Tuple(tuple) => collection_value(
                tuple
                    .elems
                    .iter()
                    .map(|element| self.expr(element, state))
                    .collect(),
            ),
            Expr::Struct(struct_) => {
                let mut properties = BTreeMap::new();
                if let Some(rest) = &struct_.rest
                    && let SemanticValueKind::Object(object) = self.expr(rest, state).kind
                {
                    properties = object.properties;
                }
                for field in &struct_.fields {
                    let name = match &field.member {
                        syn::Member::Named(name) => name.to_string(),
                        syn::Member::Unnamed(index) => index.index.to_string(),
                    };
                    properties.insert(name, self.expr(&field.expr, state));
                }
                object_value(
                    struct_
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                        .unwrap_or_default(),
                    properties,
                )
            }
            Expr::Field(field) => {
                let base = self.expr(&field.base, state);
                let name = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                rust_property_access(&base, &name, self.value_limits)
            }
            Expr::Index(index) => {
                let base = self.expr(&index.expr, state);
                let position = integer_literal(&index.index);
                match (&base.kind, position) {
                    (SemanticValueKind::Collection { elements, .. }, Some(position)) => elements
                        .get(position)
                        .cloned()
                        .unwrap_or_else(|| SemanticValue::unresolved("collection_element")),
                    _ => SemanticValue::unresolved("collection_element"),
                }
            }
            Expr::Macro(macro_) => self.macro_value(&macro_.mac, state),
            Expr::Call(call) => self.call_value(call, state),
            Expr::MethodCall(call) => self.method_value(expr, call, state),
            Expr::Block(block) => {
                let mut inner = state.clone();
                let value = self.block(&block.block, &mut inner);
                *state = inner;
                value
            }
            Expr::Unsafe(block) => {
                let mut inner = state.clone();
                let value = self.block(&block.block, &mut inner);
                *state = inner;
                value
            }
            Expr::If(if_) => self.if_value(if_, state),
            Expr::Match(match_) => self.match_value(match_, state),
            Expr::Assign(assign) => {
                let closure = called_closure_captures(&assign.right, state);
                let mut command_state = bound_command_chain_appends_arguments(&assign.right, state)
                    .then(|| state.clone());
                let value = self.expr(&assign.right, state);
                if let Expr::Path(path) = &*assign.left
                    && let Some(name) = single_ident(&path.path)
                {
                    state.values.insert(name.clone(), value.clone());
                    let command_state = command_state.as_mut().unwrap_or(&mut *state);
                    if let Some(commands) = self.command_candidates(&assign.right, command_state) {
                        invalidate_command_alias_source(&assign.right, &name, state);
                        state.commands.insert(name.clone(), commands);
                    } else {
                        state.commands.remove(&name);
                    }
                    if let Some(captures) = closure {
                        state.closures.insert(name, captures);
                    } else {
                        state.closures.remove(&name);
                    }
                } else if let Some(name) = mutated_base_ident(&assign.left) {
                    invalidate_value_binding(state, &name);
                }
                value
            }
            Expr::Binary(binary) if is_compound_assignment(&binary.op) => {
                self.expr(&binary.left, state);
                self.expr(&binary.right, state);
                if let Some(name) = mutated_base_ident(&binary.left) {
                    invalidate_value_binding(state, &name);
                }
                SemanticValue::unresolved("mutated_value")
            }
            Expr::Return(return_) => {
                let value = return_
                    .expr
                    .as_deref()
                    .map(|value| self.expr(value, state))
                    .unwrap_or_else(|| SemanticValue::unresolved("unit"));
                if !is_unknown_unit(&value) {
                    self.return_values.push(value);
                }
                never_value()
            }
            Expr::Break(_) | Expr::Continue(_) => never_value(),
            Expr::Loop(loop_) => {
                let original = state.clone();
                let mut inner = state.clone();
                self.block(&loop_.body, &mut inner);
                widen_loop_facts(
                    &mut self.facts,
                    &loop_.body,
                    &original,
                    &inner,
                    None,
                    self.value_limits,
                );
                *state = widen_loop_state(&original, &inner, self.value_limits);
                SemanticValue::unresolved("loop")
            }
            Expr::ForLoop(loop_) => {
                let iter = self.expr(&loop_.expr, state);
                let original = state.clone();
                let mut inner = state.clone();
                let mut scoped_bindings = HashMap::new();
                save_pattern_bindings(
                    &loop_.pat,
                    &inner,
                    &mut scoped_bindings,
                    &self.fns.unit_variants,
                );
                let group = self.branch_group(&loop_.expr);
                bind_rust_pattern(
                    &loop_.pat,
                    &collection_element(&iter, self.value_limits),
                    &mut inner,
                    &group,
                    None,
                    &self.fns.unit_variants,
                    self.value_limits,
                );
                self.block(&loop_.body, &mut inner);
                restore_scope_bindings(&mut inner, scoped_bindings);
                widen_loop_facts(
                    &mut self.facts,
                    &loop_.body,
                    &original,
                    &inner,
                    Some((&loop_.pat, &*loop_.expr)),
                    self.value_limits,
                );
                *state = widen_loop_state(&original, &inner, self.value_limits);
                SemanticValue::unresolved("unit")
            }
            Expr::While(loop_) => {
                if let Expr::Let(let_) = &*loop_.cond {
                    let matched = self.expr(&let_.expr, state);
                    let original = state.clone();
                    let mut inner = original.clone();
                    let mut scoped_bindings = HashMap::new();
                    save_pattern_bindings(
                        &let_.pat,
                        &inner,
                        &mut scoped_bindings,
                        &self.fns.unit_variants,
                    );
                    let group = self.branch_group(&let_.expr);
                    let matched_pattern = bind_rust_pattern(
                        &let_.pat,
                        &matched,
                        &mut inner,
                        &group,
                        None,
                        &self.fns.unit_variants,
                        self.value_limits,
                    );
                    let ambiguous_pattern = !matched_pattern
                        && rust_pattern_match_is_ambiguous(
                            &let_.pat,
                            &matched,
                            &self.fns.unit_variants,
                        );
                    if ambiguous_pattern {
                        bind_unknown_patterns(
                            std::iter::once(&*let_.pat),
                            &mut inner,
                            &group,
                            None,
                            &self.fns.unit_variants,
                            self.value_limits,
                        );
                    }
                    if matched_pattern || ambiguous_pattern {
                        self.block(&loop_.body, &mut inner);
                        restore_scope_bindings(&mut inner, scoped_bindings);
                        widen_loop_facts(
                            &mut self.facts,
                            &loop_.body,
                            &original,
                            &inner,
                            Some((&let_.pat, &*let_.expr)),
                            self.value_limits,
                        );
                        *state = widen_loop_state(&original, &inner, self.value_limits);
                    } else {
                        *state = original;
                    }
                } else {
                    self.expr(&loop_.cond, state);
                    let original = state.clone();
                    let mut inner = state.clone();
                    self.block(&loop_.body, &mut inner);
                    widen_loop_facts(
                        &mut self.facts,
                        &loop_.body,
                        &original,
                        &inner,
                        None,
                        self.value_limits,
                    );
                    *state = widen_loop_state(&original, &inner, self.value_limits);
                }
                SemanticValue::unresolved("unit")
            }
            _ => {
                for child in child_exprs(expr) {
                    self.expr(child, state);
                }
                SemanticValue::unresolved("value")
            }
        }
        .canonicalize_counted(self.value_limits, self.value_steps);
        self.value_depth -= 1;
        self.facts.expressions.insert(expr_key(expr), value.clone());
        value
    }

    fn macro_value(&mut self, macro_: &syn::Macro, state: &mut ValueState) -> SemanticValue {
        let name = macro_
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let Ok(elements) = macro_
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        else {
            return SemanticValue::unresolved("macro_value");
        };
        if name == "vec" {
            return collection_value(
                elements
                    .iter()
                    .map(|element| self.expr(element, state))
                    .collect(),
            );
        }
        if name == "format" {
            let Some(Expr::Lit(template)) = elements.first() else {
                for element in &elements {
                    self.expr(element, state);
                }
                return SemanticValue::unresolved("macro_value");
            };
            let syn::Lit::Str(template) = &template.lit else {
                for element in &elements {
                    self.expr(element, state);
                }
                return SemanticValue::unresolved("macro_value");
            };
            let mut arguments = Vec::new();
            let mut named = HashMap::new();
            for element in elements.iter().skip(1) {
                if let Expr::Assign(assign) = element
                    && let Expr::Path(path) = &*assign.left
                    && let Some(name) = single_ident(&path.path)
                {
                    let value = self.expr(&assign.right, state);
                    named.insert(name, rust_unwalked_call_value(&assign.right, value));
                } else {
                    let value = self.expr(element, state);
                    arguments.push(rust_unwalked_call_value(element, value));
                }
            }
            return format_value(&template.value(), &arguments, &named, state);
        }
        for element in &elements {
            self.expr(element, state);
            if let Some(name) = mutated_base_ident(element) {
                invalidate_value_binding(state, &name);
            }
        }
        SemanticValue::unresolved("macro_value")
    }

    fn call_value(&mut self, call: &syn::ExprCall, state: &mut ValueState) -> SemanticValue {
        let captures: HashSet<_> = call
            .args
            .iter()
            .filter_map(|argument| called_closure_captures(argument, state))
            .flatten()
            .collect();
        let arguments: Vec<_> = call
            .args
            .iter()
            .map(|argument| self.expr(argument, state))
            .collect();
        for name in captures {
            invalidate_value_binding(state, &name);
        }
        if let Some(captures) = called_closure_captures(&call.func, state) {
            for name in captures {
                invalidate_value_binding(state, &name);
            }
            return SemanticValue::unresolved("closure_result");
        }
        let Some(segments) = path_segments(&call.func) else {
            return SemanticValue::unresolved("call");
        };
        let resolved = self.uses.resolve(&segments);
        let last = segments.last().map(String::as_str).unwrap_or_default();
        if matches!(resolved.as_str(), "std::env::var" | "std::env::var_os") {
            return call
                .args
                .first()
                .and_then(str_lit)
                .filter(|name| !name.is_empty())
                .map(|name| SemanticValue::new(SemanticValueKind::Environment(name)))
                .unwrap_or_else(|| SemanticValue::unresolved("environment"));
        }
        if matches!(last, "Ok" | "Err" | "Some") {
            return variant_value(last, arguments);
        }
        if last == "None" {
            return variant_value(last, Vec::new());
        }
        if matches!(last, "from" | "from_ref" | "new")
            && resolved
                .split("::")
                .any(|part| matches!(part, "String" | "Path" | "PathBuf" | "Box" | "Rc" | "Arc"))
        {
            let value = arguments
                .into_iter()
                .next()
                .unwrap_or_else(|| SemanticValue::unresolved("value"));
            return if let Some(ty) = rust_path_constructor_type(&resolved) {
                value.with_type(Some(ty))
            } else {
                value
            };
        }
        if resolved.ends_with("Vec::new") {
            return collection_value(Vec::new());
        }
        if resolved == "shell_words::split" {
            return arguments
                .first()
                .map(|value| split_shell_value(value, self.value_limits))
                .unwrap_or_else(|| SemanticValue::unresolved("collection"));
        }
        let local = match segments.as_slice() {
            [name] => Some(name.clone()),
            [typ, method] => Some(format!("{typ}.{method}")),
            _ => None,
        };
        if let Some(local) = local
            && let Some(function) = self.fns.get(&local)
        {
            let returns = infer_rust_value_facts(
                &local,
                self.fns,
                self.uses,
                self.visiting,
                self.cache,
                self.nodes,
                self.value_steps,
                self.depth + 1,
                self.value_limits,
            );
            if let Some(value) = returns {
                let value = scope_rust_branch_groups(&value, &self.call_scope(span_key(call)));
                let bindings: HashMap<_, _> =
                    function.params.iter().cloned().zip(arguments).collect();
                return substitute_value_counted(
                    &value,
                    &bindings,
                    self.value_limits,
                    self.value_steps,
                );
            }
        }
        if resolved == "grep_cli::resolve_binary" {
            return variant_value(
                "Ok",
                vec![
                    arguments
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| SemanticValue::unresolved("text")),
                ],
            );
        }
        if last.chars().next().is_some_and(char::is_uppercase) {
            return variant_value(last, arguments);
        }
        SemanticValue::unresolved("call")
    }

    fn method_value(
        &mut self,
        whole: &Expr,
        call: &syn::ExprMethodCall,
        state: &mut ValueState,
    ) -> SemanticValue {
        let method = call.method.to_string();
        let mut command_state = matches!(
            method.as_str(),
            "arg" | "args" | "current_dir" | "spawn" | "output" | "status"
        )
        .then(|| state.clone());
        let captures: HashSet<_> = call
            .args
            .iter()
            .filter_map(|argument| called_closure_captures(argument, state))
            .flatten()
            .collect();
        let receiver = self.expr(&call.receiver, state);
        let arguments: Vec<_> = call
            .args
            .iter()
            .map(|argument| self.expr(argument, state))
            .collect();
        for name in captures {
            invalidate_value_binding(state, &name);
        }
        let commands = command_state
            .as_mut()
            .and_then(|state| self.command_candidates(&call.receiver, state));
        if matches!(method.as_str(), "spawn" | "output" | "status")
            && let Some(commands) = commands.as_ref()
        {
            self.facts
                .commands
                .insert(expr_key(whole), commands.clone());
            return SemanticValue::unresolved("process_result");
        }
        if matches!(method.as_str(), "arg" | "args" | "current_dir")
            && let Some(mut commands) = commands
        {
            if method == "arg" {
                if let Some(argument) = arguments.first() {
                    append_command_argument(&mut commands, argument, self.value_limits);
                }
            } else if method == "args"
                && let Some(argument) = arguments.first()
            {
                append_command_arguments(&mut commands, argument, self.value_limits);
            } else if let Some((argument_expr, argument)) = call.args.first().zip(arguments.first())
            {
                commands.cwd = Some(rust_unwalked_call_value(argument_expr, argument.clone()));
            }
            if let Some(name) = chain_base_ident(&call.receiver)
                && state.commands.contains_key(&name)
            {
                state.commands.insert(name, commands.clone());
            }
            return command_marker(commands);
        }
        match method.as_str() {
            "unwrap" | "expect" | "ok" => {
                peel_rust_wrapper(receiver, &["Ok", "Some"], self.value_limits)
            }
            "map_err" | "clone" | "as_ref" | "as_mut" | "as_str" | "to_owned" | "to_string"
            | "as_path" | "to_path_buf" | "into" | "iter" | "into_iter" => receiver,
            "to_vec" => receiver,
            "split_first" => split_first_value(&receiver, self.value_limits),
            "join" if rust_std_path_receiver(&receiver) => arguments
                .first()
                .map(|argument| rust_path_join(&receiver, argument))
                .unwrap_or_else(|| SemanticValue::unresolved("filesystem")),
            "push" => {
                if let Expr::Path(path) = &*call.receiver
                    && let Some(name) = single_ident(&path.path)
                    && let Some(argument) = arguments.first()
                    && rust_std_path_receiver(&receiver)
                    && rust_path_value_is_trackable(&receiver)
                {
                    state
                        .values
                        .insert(name, rust_path_join(&receiver, argument));
                } else if let Some(name) = mutated_base_ident(&call.receiver) {
                    invalidate_value_binding(state, &name);
                }
                SemanticValue::unresolved("unit")
            }
            "parent" if rust_std_path_receiver(&receiver) => rust_path_parent(&receiver),
            "with_extension" if rust_std_path_receiver(&receiver) => arguments
                .first()
                .map(|extension| rust_path_with_extension(&receiver, extension))
                .unwrap_or_else(|| SemanticValue::unresolved("filesystem")),
            "with_file_name" if rust_std_path_receiver(&receiver) => arguments
                .first()
                .map(|name| rust_path_with_file_name(&receiver, name))
                .unwrap_or_else(|| SemanticValue::unresolved("filesystem")),
            _ => {
                if let Some(name) = mutated_base_ident(&call.receiver)
                    && (!state.commands.contains_key(&name)
                        || !command_method_preserves_executable_and_argv(&method))
                {
                    invalidate_value_binding(state, &name);
                }
                SemanticValue::unresolved("method_result")
            }
        }
    }

    fn if_value(&mut self, if_: &syn::ExprIf, state: &mut ValueState) -> SemanticValue {
        let mut scoped_bindings = HashMap::new();
        let original;
        let mut then_state;
        let matched_pattern;
        let ambiguous_pattern;
        if let Expr::Let(let_) = &*if_.cond {
            let matched = self.expr(&let_.expr, state);
            original = state.clone();
            then_state = original.clone();
            save_pattern_bindings(
                &let_.pat,
                &then_state,
                &mut scoped_bindings,
                &self.fns.unit_variants,
            );
            let group = self.branch_group(&let_.expr);
            matched_pattern = bind_rust_pattern(
                &let_.pat,
                &matched,
                &mut then_state,
                &group,
                None,
                &self.fns.unit_variants,
                self.value_limits,
            );
            ambiguous_pattern = !matched_pattern
                && rust_pattern_match_is_ambiguous(&let_.pat, &matched, &self.fns.unit_variants);
            if ambiguous_pattern {
                bind_unknown_patterns(
                    std::iter::once(&*let_.pat),
                    &mut then_state,
                    &group,
                    None,
                    &self.fns.unit_variants,
                    self.value_limits,
                );
            }
        } else {
            self.expr(&if_.cond, state);
            original = state.clone();
            then_state = original.clone();
            matched_pattern = true;
            ambiguous_pattern = false;
        }
        let then = (matched_pattern || ambiguous_pattern).then(|| {
            let value = self.block(&if_.then_branch, &mut then_state);
            restore_scope_bindings(&mut then_state, scoped_bindings);
            (
                if ambiguous_pattern {
                    SemanticValue::unresolved("if_let")
                } else {
                    value
                },
                then_state,
            )
        });
        let (else_value, else_state) = match &if_.else_branch {
            Some((_, expression)) => {
                let mut else_state = original.clone();
                let value = self.expr(expression, &mut else_state);
                (value, else_state)
            }
            None => (SemanticValue::unresolved("unit"), original),
        };
        if let Some((then_value, then_state)) = then {
            *state = join_value_states([then_state, else_state], self.value_limits);
            join_live_values([then_value, else_value], self.value_limits)
        } else {
            *state = else_state;
            else_value
        }
    }

    fn match_value(&mut self, match_: &syn::ExprMatch, state: &mut ValueState) -> SemanticValue {
        let matched = self.expr(&match_.expr, state);
        let group = self.branch_group(&match_.expr);
        let original = state.clone();
        let mut values = Vec::new();
        let mut states = Vec::new();
        for arm in &match_.arms {
            let mut arm_state = original.clone();
            let mut scoped_bindings = HashMap::new();
            save_pattern_bindings(
                &arm.pat,
                &arm_state,
                &mut scoped_bindings,
                &self.fns.unit_variants,
            );
            let matched_pattern = bind_rust_pattern(
                &arm.pat,
                &matched,
                &mut arm_state,
                &group,
                None,
                &self.fns.unit_variants,
                self.value_limits,
            );
            let ambiguous_pattern = !matched_pattern
                && rust_pattern_match_is_ambiguous(&arm.pat, &matched, &self.fns.unit_variants);
            if !matched_pattern && !ambiguous_pattern {
                continue;
            }
            if let Some((_, guard)) = &arm.guard {
                self.expr(guard, &mut arm_state);
            }
            let value = self.expr(&arm.body, &mut arm_state);
            if !is_never(&value) {
                values.push(if ambiguous_pattern {
                    SemanticValue::unresolved("match_arm")
                } else {
                    value
                });
                restore_scope_bindings(&mut arm_state, scoped_bindings);
                states.push(arm_state);
            }
        }
        if !states.is_empty() {
            *state = join_value_states(states, self.value_limits);
        }
        join_live_values(values, self.value_limits)
    }

    fn branch_group(&self, expr: &Expr) -> String {
        format!(
            "__effinterp_rust_branch:{}",
            self.call_scope(expr_key(expr))
        )
    }

    fn call_scope(&self, (start, end): ExprKey) -> String {
        format!(
            "__effinterp_rust_call:{:016x}:{}:{start}:{end}",
            self.uses.source_id, self.function
        )
    }

    fn command_candidates(
        &mut self,
        expr: &Expr,
        state: &mut ValueState,
    ) -> Option<CommandCandidates> {
        match expr {
            Expr::Path(path) => {
                single_ident(&path.path).and_then(|name| state.commands.get(&name).cloned())
            }
            Expr::Reference(reference) => self.command_candidates(&reference.expr, state),
            Expr::Paren(paren) => self.command_candidates(&paren.expr, state),
            Expr::Group(group) => self.command_candidates(&group.expr, state),
            Expr::Try(try_) => self.command_candidates(&try_.expr, state),
            Expr::MethodCall(call) => {
                let method = call.method.to_string();
                let mut commands = self.command_candidates(&call.receiver, state)?;
                match method.as_str() {
                    "arg" => {
                        if let Some(argument) = call.args.first() {
                            let value = self.expr(argument, state);
                            append_command_argument(&mut commands, &value, self.value_limits);
                        }
                    }
                    "args" => {
                        if let Some(argument) = call.args.first() {
                            let value = self.expr(argument, state);
                            append_command_arguments(&mut commands, &value, self.value_limits);
                        }
                    }
                    "current_dir" => {
                        if let Some(argument) = call.args.first() {
                            let value = self.expr(argument, state);
                            commands.cwd = Some(rust_unwalked_call_value(argument, value));
                        }
                    }
                    method if command_method_preserves_executable_and_argv(method) => {}
                    _ => return None,
                }
                Some(commands)
            }
            Expr::Call(call) => {
                let segments = path_segments(&call.func)?;
                (self.uses.resolve(&segments) == "std::process::Command::new").then(|| {
                    call.args
                        .first()
                        .map(|argument| {
                            command_heads(&self.expr(argument, state), self.value_limits)
                        })
                        .unwrap_or_else(|| CommandCandidates {
                            values: vec![vec![SemanticValue::unresolved("process")]],
                            cwd: None,
                            widened: false,
                        })
                })
            }
            _ => None,
        }
    }
}

fn format_value(
    template: &str,
    positional: &[SemanticValue],
    named: &HashMap<String, SemanticValue>,
    state: &ValueState,
) -> SemanticValue {
    if template.contains("{{") || template.contains("}}") {
        return SemanticValue::unresolved("macro_value");
    }
    let mut parts = Vec::new();
    let mut rest = template;
    let mut positional_index = 0;
    let mut has_literal = false;
    while let Some(open) = rest.find('{') {
        let literal = &rest[..open];
        if literal.contains('}') {
            return SemanticValue::unresolved("macro_value");
        }
        if !literal.is_empty() {
            has_literal = true;
            parts.push(SemanticValue::literal(literal));
        }
        let placeholder = &rest[open + 1..];
        let Some(close) = placeholder.find('}') else {
            return SemanticValue::unresolved("macro_value");
        };
        let name = &placeholder[..close];
        let value = if name.is_empty() {
            let Some(value) = positional.get(positional_index) else {
                return SemanticValue::unresolved("macro_value");
            };
            positional_index += 1;
            value.clone()
        } else if rust_format_ident(name) {
            named
                .get(name)
                .or_else(|| state.values.get(name))
                .cloned()
                .unwrap_or_else(|| SemanticValue::unresolved("value"))
        } else {
            return SemanticValue::unresolved("macro_value");
        };
        parts.push(value);
        rest = &placeholder[close + 1..];
    }
    if rest.contains('}') {
        return SemanticValue::unresolved("macro_value");
    }
    if !rest.is_empty() {
        has_literal = true;
        parts.push(SemanticValue::literal(rest));
    }
    if !has_literal {
        return SemanticValue::unresolved("macro_value");
    }
    SemanticValue::new(SemanticValueKind::Join(parts))
}

fn rust_format_ident(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && chars.all(|character| character == '_' || character.is_alphanumeric())
}

fn rust_path_literal(value: &SemanticValue) -> Option<&str> {
    match &value.kind {
        SemanticValueKind::Literal(value) => Some(value),
        SemanticValueKind::Path {
            source: Some(value),
            ..
        } => Some(value),
        _ => None,
    }
}

fn rust_path_value_is_trackable(value: &SemanticValue) -> bool {
    match &value.kind {
        SemanticValueKind::Literal(_)
        | SemanticValueKind::Path { .. }
        | SemanticValueKind::Environment(_)
        | SemanticValueKind::Parameter(_)
        | SemanticValueKind::Join(_) => true,
        SemanticValueKind::Alias { value, .. } => rust_path_value_is_trackable(value),
        SemanticValueKind::Union(values) => values.iter().all(rust_path_value_is_trackable),
        _ => false,
    }
}

fn rust_path_constructor_type(resolved: &str) -> Option<TypeRef> {
    let (receiver, _) = resolved.rsplit_once("::")?;
    let path = canonical_rust_std_type(receiver)?;
    matches!(path.as_str(), "std::path::Path" | "std::path::PathBuf")
        .then_some(TypeRef::External { path })
}

fn rust_std_path_receiver(value: &SemanticValue) -> bool {
    if matches!(
        &value.evidence.ty,
        Some(TypeRef::External { path })
            if matches!(path.as_str(), "std::path::Path" | "std::path::PathBuf")
    ) {
        return true;
    }
    match &value.kind {
        SemanticValueKind::Alias { value, .. } | SemanticValueKind::Exception(value) => {
            rust_std_path_receiver(value)
        }
        SemanticValueKind::Union(values) => values.iter().all(rust_std_path_receiver),
        _ => false,
    }
}

fn rust_path_join(value: &SemanticValue, part: &SemanticValue) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Join(vec![value.clone(), part.clone()]))
        .with_type(value.evidence.ty.clone())
}

fn rust_path_parent(value: &SemanticValue) -> SemanticValue {
    let Some(path) = rust_path_literal(value) else {
        return SemanticValue::unresolved("filesystem");
    };
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() && path.starts_with('/') {
        return SemanticValue::literal("/").with_type(value.evidence.ty.clone());
    }
    let Some((parent, _)) = trimmed.rsplit_once('/') else {
        return SemanticValue::unresolved("filesystem");
    };
    let parent = if parent.is_empty() && path.starts_with('/') {
        "/"
    } else {
        parent
    };
    if parent.is_empty() {
        SemanticValue::unresolved("filesystem")
    } else {
        SemanticValue::literal(parent).with_type(value.evidence.ty.clone())
    }
}

fn rust_path_with_extension(value: &SemanticValue, extension: &SemanticValue) -> SemanticValue {
    let (Some(path), Some(extension)) = (rust_path_literal(value), rust_path_literal(extension))
    else {
        return SemanticValue::unresolved("filesystem");
    };
    SemanticValue::literal(
        std::path::Path::new(path)
            .with_extension(extension)
            .to_string_lossy()
            .into_owned(),
    )
    .with_type(value.evidence.ty.clone())
}

fn rust_path_with_file_name(value: &SemanticValue, name: &SemanticValue) -> SemanticValue {
    let (Some(path), Some(name)) = (rust_path_literal(value), rust_path_literal(name)) else {
        return SemanticValue::unresolved("filesystem");
    };
    SemanticValue::literal(
        std::path::Path::new(path)
            .with_file_name(name)
            .to_string_lossy()
            .into_owned(),
    )
    .with_type(value.evidence.ty.clone())
}

fn command_method_preserves_executable_and_argv(method: &str) -> bool {
    matches!(
        method,
        "env"
            | "envs"
            | "env_clear"
            | "env_remove"
            | "current_dir"
            | "stdin"
            | "stdout"
            | "stderr"
            | "uid"
            | "gid"
            | "groups"
            | "process_group"
    )
}

fn rust_path_value(path: &syn::ExprPath, state: &ValueState) -> SemanticValue {
    if let Some(name) = single_ident(&path.path) {
        return state
            .values
            .get(&name)
            .cloned()
            .unwrap_or_else(|| SemanticValue::unresolved("value"));
    }
    let segments: Vec<_> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let last = segments.last().cloned().unwrap_or_default();
    if last.chars().next().is_some_and(char::is_uppercase) {
        variant_value(&last, Vec::new())
    } else {
        SemanticValue::unresolved("value")
    }
}

fn object_value(name: String, properties: BTreeMap<String, SemanticValue>) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Object(ObjectValue {
        identity: ObjectIdentity::Class {
            name,
            constructor: Vec::new(),
        },
        properties,
    }))
}

fn variant_value(name: &str, values: Vec<SemanticValue>) -> SemanticValue {
    object_value(
        name.to_string(),
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
    )
}

fn collection_value(elements: Vec<SemanticValue>) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Collection {
        elements,
        properties: BTreeMap::new(),
    })
}

fn rust_property_access(value: &SemanticValue, name: &str, limits: ValueLimits) -> SemanticValue {
    match &value.kind {
        SemanticValueKind::Alias {
            name: branch,
            value,
        } if is_rust_branch(branch) => {
            rust_branch_value(branch, rust_property_access(value, name, limits))
        }
        SemanticValueKind::Union(alternatives) => join_branches(
            alternatives
                .iter()
                .map(|alternative| rust_property_access(alternative, name, limits)),
            limits,
        ),
        _ => property_access(value, name, limits),
    }
}

fn collection_element(value: &SemanticValue, value_limits: crate::ValueLimits) -> SemanticValue {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => {
            join_live_values(elements.clone(), value_limits)
        }
        SemanticValueKind::Union(alternatives) => join_live_values(
            alternatives
                .iter()
                .map(|value| collection_element(value, value_limits))
                .collect::<Vec<_>>(),
            value_limits,
        ),
        SemanticValueKind::Alias {
            name: branch,
            value,
        } if is_rust_branch(branch) => {
            rust_branch_value(branch, collection_element(value, value_limits))
        }
        _ => SemanticValue::unresolved("collection_element"),
    }
}

fn peel_rust_wrapper(
    value: SemanticValue,
    variants: &[&str],
    value_limits: crate::ValueLimits,
) -> SemanticValue {
    match value.kind {
        SemanticValueKind::Alias { name, value } if is_rust_branch(&name) => {
            rust_branch_value(&name, peel_rust_wrapper(*value, variants, value_limits))
        }
        SemanticValueKind::Object(object) => {
            let name = match &object.identity {
                ObjectIdentity::Class { name, .. } => name.as_str(),
                _ => return SemanticValue::new(SemanticValueKind::Object(object)),
            };
            if variants.contains(&name) {
                object
                    .properties
                    .get("0")
                    .cloned()
                    .unwrap_or_else(|| SemanticValue::unresolved("wrapped_value"))
            } else {
                SemanticValue::new(SemanticValueKind::Object(object))
            }
        }
        SemanticValueKind::Union(alternatives) => join_live_values(
            alternatives
                .into_iter()
                .map(|alternative| peel_rust_wrapper(alternative, variants, value_limits))
                .collect::<Vec<_>>(),
            value_limits,
        ),
        _ => value,
    }
}

fn split_shell_value(value: &SemanticValue, value_limits: crate::ValueLimits) -> SemanticValue {
    match &value.kind {
        SemanticValueKind::Literal(text)
            if !text.is_empty() && !text.chars().any(char::is_whitespace) =>
        {
            collection_value(vec![SemanticValue::literal(text)])
        }
        SemanticValueKind::Literal(_) => SemanticValue::unresolved("collection"),
        SemanticValueKind::Union(alternatives) => join_live_values(
            alternatives
                .iter()
                .map(|value| split_shell_value(value, value_limits))
                .collect::<Vec<_>>(),
            value_limits,
        ),
        SemanticValueKind::Alias {
            name: branch,
            value,
        } if is_rust_branch(branch) => {
            rust_branch_value(branch, split_shell_value(value, value_limits))
        }
        _ => SemanticValue::unresolved("collection"),
    }
}

fn split_first_value(value: &SemanticValue, value_limits: crate::ValueLimits) -> SemanticValue {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } if !elements.is_empty() => variant_value(
            "Some",
            vec![collection_value(vec![
                elements[0].clone(),
                collection_value(elements[1..].to_vec()),
            ])],
        ),
        SemanticValueKind::Collection { .. } => variant_value("None", Vec::new()),
        SemanticValueKind::Union(alternatives) => join_live_values(
            alternatives
                .iter()
                .map(|value| split_first_value(value, value_limits))
                .collect::<Vec<_>>(),
            value_limits,
        ),
        SemanticValueKind::Alias {
            name: branch,
            value,
        } if is_rust_branch(branch) => {
            rust_branch_value(branch, split_first_value(value, value_limits))
        }
        _ => SemanticValue::unresolved("option"),
    }
}

/// A resolved same-file callee: its path, the argument expressions, and the
/// receiver's field bindings when the call goes through a value.
type InFileCall<'b> = (String, Vec<&'b Expr>, Option<HashMap<String, ResourceExpr>>);

type ScopedBindings = HashMap<
    String,
    (
        Option<SemanticValue>,
        Option<CommandCandidates>,
        Option<HashSet<String>>,
    ),
>;

fn save_pattern_bindings(
    pattern: &Pat,
    state: &ValueState,
    saved: &mut ScopedBindings,
    unit_variants: &HashMap<String, String>,
) {
    let mut names = Vec::new();
    rust_pattern_binding_names(pattern, &mut names, unit_variants);
    for name in names {
        saved.entry(name.clone()).or_insert_with(|| {
            (
                state.values.get(&name).cloned(),
                state.commands.get(&name).cloned(),
                state.closures.get(&name).cloned(),
            )
        });
    }
}

fn rust_pattern_binding_names(
    pattern: &Pat,
    names: &mut Vec<String>,
    unit_variants: &HashMap<String, String>,
) {
    match pattern {
        Pat::Ident(identifier) if unit_variant_pattern(identifier, unit_variants).is_none() => {
            names.push(identifier.ident.to_string());
            if let Some((_, subpattern)) = &identifier.subpat {
                rust_pattern_binding_names(subpattern, names, unit_variants);
            }
        }
        Pat::Type(typed) => rust_pattern_binding_names(&typed.pat, names, unit_variants),
        Pat::Reference(reference) => {
            rust_pattern_binding_names(&reference.pat, names, unit_variants);
        }
        Pat::Paren(paren) => rust_pattern_binding_names(&paren.pat, names, unit_variants),
        Pat::Tuple(tuple) => {
            for pattern in &tuple.elems {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        Pat::TupleStruct(tuple) => {
            for pattern in &tuple.elems {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        Pat::Struct(struct_) => {
            for field in &struct_.fields {
                rust_pattern_binding_names(&field.pat, names, unit_variants);
            }
        }
        Pat::Slice(slice) => {
            for pattern in &slice.elems {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        Pat::Or(or_) => {
            for pattern in &or_.cases {
                rust_pattern_binding_names(pattern, names, unit_variants);
            }
        }
        _ => {}
    }
}

fn unit_variant_pattern<'a>(
    identifier: &syn::PatIdent,
    unit_variants: &'a HashMap<String, String>,
) -> Option<&'a str> {
    (identifier.by_ref.is_none() && identifier.mutability.is_none() && identifier.subpat.is_none())
        .then(|| unit_variants.get(&identifier.ident.to_string()))
        .flatten()
        .map(String::as_str)
}

fn restore_scope_bindings(state: &mut ValueState, saved: ScopedBindings) {
    for (name, (value, commands, closure)) in saved {
        if let Some(value) = value {
            state.values.insert(name.clone(), value);
        } else {
            state.values.remove(&name);
        }
        if let Some(commands) = commands {
            state.commands.insert(name.clone(), commands);
        } else {
            state.commands.remove(&name);
        }
        if let Some(closure) = closure {
            state.closures.insert(name, closure);
        } else {
            state.closures.remove(&name);
        }
    }
}

fn bind_rust_pattern(
    pattern: &Pat,
    value: &SemanticValue,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    if let SemanticValueKind::Alias { name: alias, value } = &value.kind
        && is_rust_branch(alias)
    {
        let before = state.values.clone();
        let matched = bind_rust_pattern(
            pattern,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
        if matched {
            for (name, value) in &mut state.values {
                if before.get(name) != Some(value) {
                    *value = rust_branch_value(alias, value.clone());
                }
            }
        }
        return matched;
    }
    if let SemanticValueKind::Union(alternatives) = &value.kind {
        let mut matches = Vec::new();
        for (index, alternative) in alternatives.iter().enumerate() {
            let choice = branch
                .map(|branch| format!("{branch}.{index}"))
                .unwrap_or_else(|| index.to_string());
            let mut alternative_state = state.clone();
            if bind_rust_pattern(
                pattern,
                alternative,
                &mut alternative_state,
                group,
                Some(&choice),
                unit_variants,
                value_limits,
            ) {
                matches.push(alternative_state);
            }
        }
        if matches.is_empty() {
            return false;
        }
        *state = join_value_states(matches, value_limits);
        return true;
    }
    match pattern {
        Pat::Ident(identifier) => {
            if let Some(expected) = unit_variant_pattern(identifier, unit_variants) {
                return variant_properties(value, Some(expected)).is_some()
                    || is_unresolved_value(value);
            }
            let value = branch
                .map(|branch| rust_branch_value(&format!("{group}:{branch}"), value.clone()))
                .unwrap_or_else(|| value.clone());
            state
                .values
                .insert(identifier.ident.to_string(), value.clone());
            if let Some((_, subpattern)) = &identifier.subpat {
                bind_rust_pattern(
                    subpattern,
                    &value,
                    state,
                    group,
                    branch,
                    unit_variants,
                    value_limits,
                )
            } else {
                true
            }
        }
        Pat::Type(typed) => bind_rust_pattern(
            &typed.pat,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::Reference(reference) => bind_rust_pattern(
            &reference.pat,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::Paren(paren) => bind_rust_pattern(
            &paren.pat,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::Tuple(tuple) => bind_pattern_elements(
            &tuple.elems,
            value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        ),
        Pat::TupleStruct(tuple) => {
            let expected = tuple
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            let Some(properties) = variant_properties(value, expected.as_deref()) else {
                if is_symbolic_value(value) && tuple.elems.len() == 1 {
                    return bind_rust_pattern(
                        &tuple.elems[0],
                        value,
                        state,
                        group,
                        branch,
                        unit_variants,
                        value_limits,
                    );
                }
                return is_unresolved_value(value)
                    && bind_unknown_patterns(
                        tuple.elems.iter(),
                        state,
                        group,
                        branch,
                        unit_variants,
                        value_limits,
                    );
            };
            bind_pattern_properties(
                tuple.elems.iter(),
                properties,
                state,
                group,
                branch,
                unit_variants,
                value_limits,
            )
        }
        Pat::Struct(struct_) => {
            let expected = struct_
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            let Some(properties) = variant_properties(value, expected.as_deref()) else {
                return is_unresolved_value(value)
                    && bind_unknown_patterns(
                        struct_.fields.iter().map(|field| &*field.pat),
                        state,
                        group,
                        branch,
                        unit_variants,
                        value_limits,
                    );
            };
            for field in &struct_.fields {
                let name = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                let field_value = properties
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| SemanticValue::unresolved("field"));
                bind_rust_pattern(
                    &field.pat,
                    &field_value,
                    state,
                    group,
                    branch,
                    unit_variants,
                    value_limits,
                );
            }
            true
        }
        Pat::Path(path) => {
            let expected = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            variant_properties(value, expected.as_deref()).is_some() || is_unresolved_value(value)
        }
        Pat::Or(or_) => or_.cases.iter().any(|case| {
            let mut case_state = state.clone();
            if bind_rust_pattern(
                case,
                value,
                &mut case_state,
                group,
                branch,
                unit_variants,
                value_limits,
            ) {
                *state = case_state;
                true
            } else {
                false
            }
        }),
        Pat::Wild(_) | Pat::Rest(_) => true,
        _ => is_unresolved_value(value),
    }
}

// A failed binding is either a proven variant mismatch or a pattern shape this
// value layer cannot decide. The latter keeps an unresolved match alternative.
fn rust_pattern_match_is_ambiguous(
    pattern: &Pat,
    value: &SemanticValue,
    unit_variants: &HashMap<String, String>,
) -> bool {
    match &value.kind {
        SemanticValueKind::Alias { value, .. } => {
            return rust_pattern_match_is_ambiguous(pattern, value, unit_variants);
        }
        SemanticValueKind::Union(alternatives) => {
            return alternatives
                .iter()
                .any(|value| rust_pattern_match_is_ambiguous(pattern, value, unit_variants));
        }
        _ => {}
    }
    match pattern {
        Pat::Type(typed) => rust_pattern_match_is_ambiguous(&typed.pat, value, unit_variants),
        Pat::Reference(reference) => {
            rust_pattern_match_is_ambiguous(&reference.pat, value, unit_variants)
        }
        Pat::Paren(paren) => rust_pattern_match_is_ambiguous(&paren.pat, value, unit_variants),
        Pat::Or(or_) => or_
            .cases
            .iter()
            .any(|case| rust_pattern_match_is_ambiguous(case, value, unit_variants)),
        Pat::Ident(identifier) if unit_variant_pattern(identifier, unit_variants).is_some() => {
            !matches!(value.kind, SemanticValueKind::Object(_))
        }
        Pat::Path(_) | Pat::Struct(_) | Pat::TupleStruct(_)
            if matches!(value.kind, SemanticValueKind::Object(_)) =>
        {
            false
        }
        Pat::Ident(_) | Pat::Wild(_) | Pat::Rest(_) => false,
        _ => true,
    }
}

fn bind_pattern_elements(
    patterns: &syn::punctuated::Punctuated<Pat, syn::Token![,]>,
    value: &SemanticValue,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    let SemanticValueKind::Collection { elements, .. } = &value.kind else {
        return is_unresolved_value(value)
            && bind_unknown_patterns(
                patterns.iter(),
                state,
                group,
                branch,
                unit_variants,
                value_limits,
            );
    };
    for (index, pattern) in patterns.iter().enumerate() {
        let element = elements
            .get(index)
            .cloned()
            .unwrap_or_else(|| SemanticValue::unresolved("collection_element"));
        bind_rust_pattern(
            pattern,
            &element,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
    }
    true
}

fn bind_pattern_properties<'a>(
    patterns: impl Iterator<Item = &'a Pat>,
    properties: &BTreeMap<String, SemanticValue>,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    for (index, pattern) in patterns.enumerate() {
        let value = properties
            .get(&index.to_string())
            .cloned()
            .unwrap_or_else(|| SemanticValue::unresolved("variant_value"));
        bind_rust_pattern(
            pattern,
            &value,
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
    }
    true
}

fn bind_unknown_patterns<'a>(
    patterns: impl Iterator<Item = &'a Pat>,
    state: &mut ValueState,
    group: &str,
    branch: Option<&str>,
    unit_variants: &HashMap<String, String>,
    value_limits: crate::ValueLimits,
) -> bool {
    for pattern in patterns {
        bind_rust_pattern(
            pattern,
            &SemanticValue::unresolved("value"),
            state,
            group,
            branch,
            unit_variants,
            value_limits,
        );
    }
    true
}

fn variant_properties<'a>(
    value: &'a SemanticValue,
    expected: Option<&str>,
) -> Option<&'a BTreeMap<String, SemanticValue>> {
    let SemanticValueKind::Object(object) = &value.kind else {
        return None;
    };
    match &object.identity {
        ObjectIdentity::Class { name, .. } if expected.is_none_or(|expected| expected == name) => {
            Some(&object.properties)
        }
        _ => None,
    }
}

fn join_live_values(
    values: impl IntoIterator<Item = SemanticValue>,
    value_limits: crate::ValueLimits,
) -> SemanticValue {
    let values: Vec<_> = values
        .into_iter()
        .filter(|value| !is_never(value))
        .collect();
    if values.is_empty() {
        never_value()
    } else {
        join_branches(values, value_limits)
    }
}

fn join_value_states(
    states: impl IntoIterator<Item = ValueState>,
    value_limits: crate::ValueLimits,
) -> ValueState {
    let states: Vec<_> = states.into_iter().collect();
    let mut out = ValueState::default();
    let names: HashSet<_> = states
        .iter()
        .flat_map(|state| state.values.keys().cloned())
        .collect();
    for name in names {
        let values: Vec<_> = states
            .iter()
            .filter_map(|state| state.values.get(&name).cloned())
            .collect();
        if !values.is_empty() {
            out.values
                .insert(name, join_live_values(values, value_limits));
        }
    }
    for state in states {
        for (name, candidates) in state.commands {
            let target = out.commands.entry(name).or_default();
            target.cwd = if target.values.is_empty() {
                candidates.cwd
            } else {
                merge_command_cwds(target.cwd.take(), candidates.cwd, value_limits)
            };
            target.values.extend(candidates.values);
            target.widened |= candidates.widened;
            dedup_commands(target, value_limits);
        }
        for (name, captures) in state.closures {
            out.closures.entry(name).or_default().extend(captures);
        }
    }
    out
}

fn invalidate_value_binding(state: &mut ValueState, name: &str) {
    state
        .values
        .insert(name.to_string(), SemanticValue::unresolved("mutated_value"));
    state.commands.remove(name);
    state.closures.remove(name);
}

fn widen_loop_state(
    original: &ValueState,
    inner: &ValueState,
    value_limits: crate::ValueLimits,
) -> ValueState {
    // A single body walk cannot enumerate iteration counts. Keep the
    // zero-iteration state and make every changed binding explicitly wider.
    let mut out = original.clone();
    for (name, value) in &original.values {
        if inner.values.get(name) != Some(value) {
            out.values.insert(
                name.clone(),
                join_live_values(
                    [value.clone(), SemanticValue::unresolved("loop_value")],
                    value_limits,
                ),
            );
        }
    }
    for (name, commands) in &original.commands {
        if inner.commands.get(name) != Some(commands) {
            let target = out.commands.get_mut(name).expect("original command");
            if let Some(inner) = inner.commands.get(name) {
                target.values.extend(inner.values.clone());
                if target.cwd != inner.cwd {
                    target.cwd = Some(join_live_values(
                        [
                            target
                                .cwd
                                .clone()
                                .unwrap_or_else(|| SemanticValue::unresolved("command_cwd")),
                            SemanticValue::unresolved("loop_value"),
                        ],
                        value_limits,
                    ));
                }
            }
            target.widened = true;
            dedup_commands(target, value_limits);
        }
    }
    out
}

fn widen_loop_facts(
    facts: &mut ValueFacts,
    body: &Block,
    original: &ValueState,
    inner: &ValueState,
    pattern: Option<(&Pat, &Expr)>,
    value_limits: crate::ValueLimits,
) {
    let tracked_keys = facts
        .expressions
        .keys()
        .chain(facts.commands.keys())
        .copied()
        .collect();
    for key in widened_loop_fact_keys(&tracked_keys, body, original, inner, pattern) {
        if facts.expressions.contains_key(&key) {
            facts
                .expressions
                .insert(key, SemanticValue::unresolved("loop_value"));
        }
        if let Some(command) = facts.commands.get_mut(&key) {
            command.widened = true;
            dedup_commands(command, value_limits);
        }
    }
}

fn widened_loop_fact_keys(
    tracked_keys: &HashSet<ExprKey>,
    body: &Block,
    original: &ValueState,
    inner: &ValueState,
    pattern: Option<(&Pat, &Expr)>,
) -> HashSet<ExprKey> {
    // Scope restore drops body-local names before this diff, so a fact that
    // reads an alias of a changed outer binding would otherwise stay exact.
    let changed_bindings: HashSet<_> = original
        .values
        .keys()
        .chain(inner.values.keys())
        .filter(|name| original.values.get(*name) != inner.values.get(*name))
        .chain(
            original
                .commands
                .keys()
                .chain(inner.commands.keys())
                .filter(|name| original.commands.get(*name) != inner.commands.get(*name)),
        )
        .cloned()
        .collect();
    if changed_bindings.is_empty() {
        return HashSet::new();
    }
    let mut visitor = LoopFactVisitor {
        tracked_keys,
        changed_bindings: &changed_bindings,
        scopes: Vec::new(),
        widened: HashSet::new(),
    };
    if let Some((pattern, source)) = pattern {
        let tainted = visitor.expr_tainted(source);
        visitor.scopes.push(HashMap::new());
        visitor.bind_pattern(pattern, tainted);
    }
    visitor.visit_block(body);
    visitor.widened
}

fn command_heads(value: &SemanticValue, value_limits: crate::ValueLimits) -> CommandCandidates {
    let mut commands = CommandCandidates::default();
    match &value.kind {
        SemanticValueKind::Union(alternatives) => {
            for alternative in alternatives {
                let branch = command_heads(alternative, value_limits);
                commands.values.extend(branch.values);
                commands.widened |= branch.widened;
            }
        }
        _ => commands.values.push(vec![value.clone()]),
    }
    dedup_commands(&mut commands, value_limits);
    commands
}

fn merge_command_cwds(
    left: Option<SemanticValue>,
    right: Option<SemanticValue>,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    match (left, right) {
        (Some(left), Some(right)) => Some(join_live_values([left, right], value_limits)),
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(join_live_values(
            [value, SemanticValue::unresolved("command_cwd")],
            value_limits,
        )),
    }
}

fn is_rust_branch(name: &str) -> bool {
    name.starts_with("__effinterp_rust_branch:")
}

fn rust_branch_value(name: &str, value: SemanticValue) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Alias {
        name: name.to_string(),
        value: Box::new(value),
    })
}

pub(super) fn scope_rust_branch_groups(value: &SemanticValue, scope: &str) -> SemanticValue {
    let mut value = value.clone();
    scope_rust_branch_groups_at(&mut value, scope);
    if let SemanticValueKind::Union(alternatives) = &mut value.kind {
        for (choice, alternative) in alternatives.iter_mut().enumerate() {
            *alternative = rust_branch_value(
                &format!("__effinterp_rust_branch:{scope}:return:{choice}"),
                alternative.clone(),
            );
        }
    }
    value
}

fn scope_rust_branch_groups_at(value: &mut SemanticValue, scope: &str) {
    match &mut value.kind {
        SemanticValueKind::Union(values)
        | SemanticValueKind::Path { parts: values, .. }
        | SemanticValueKind::Join(values) => {
            for value in values {
                scope_rust_branch_groups_at(value, scope);
            }
        }
        SemanticValueKind::Process { argv, cwd, .. } => {
            for value in argv {
                scope_rust_branch_groups_at(value, scope);
            }
            if let Some(value) = cwd {
                scope_rust_branch_groups_at(value, scope);
            }
        }
        SemanticValueKind::Cwd(value) | SemanticValueKind::Exception(value) => {
            scope_rust_branch_groups_at(value, scope);
        }
        SemanticValueKind::Collection {
            elements,
            properties,
        } => {
            for value in elements {
                scope_rust_branch_groups_at(value, scope);
            }
            for value in properties.values_mut() {
                scope_rust_branch_groups_at(value, scope);
            }
        }
        SemanticValueKind::Property { base, .. } => {
            scope_rust_branch_groups_at(base, scope);
        }
        SemanticValueKind::Object(object) => {
            if let ObjectIdentity::Class { constructor, .. } = &mut object.identity {
                for argument in constructor {
                    scope_rust_branch_groups_at(&mut argument.value, scope);
                }
            }
            for value in object.properties.values_mut() {
                scope_rust_branch_groups_at(value, scope);
            }
        }
        SemanticValueKind::Callable(CallableValue::Closure { captures, .. }) => {
            for value in captures.values_mut() {
                scope_rust_branch_groups_at(value, scope);
            }
        }
        SemanticValueKind::Callable(CallableValue::BoundMethod { receiver, .. }) => {
            scope_rust_branch_groups_at(receiver, scope);
        }
        SemanticValueKind::Alias { name, value } => {
            let scoped = name
                .strip_prefix("__effinterp_rust_branch:")
                .and_then(|branch| branch.rsplit_once(':'))
                .map(|(group, choice)| format!("__effinterp_rust_branch:{scope}:{group}:{choice}"));
            if let Some(scoped) = scoped {
                *name = scoped;
            }
            scope_rust_branch_groups_at(value, scope);
        }
        _ => {}
    }
}

fn rust_branch_tags(value: &SemanticValue, tags: &mut BTreeMap<String, String>) {
    if let SemanticValueKind::Alias { name, value } = &value.kind {
        if let Some(branch) = name.strip_prefix("__effinterp_rust_branch:")
            && let Some((group, choice)) = branch.rsplit_once(':')
        {
            tags.insert(group.to_string(), choice.to_string());
        }
        rust_branch_tags(value, tags);
    }
}

fn command_branch_compatible(command: &[SemanticValue], value: &SemanticValue) -> bool {
    let mut command_tags = BTreeMap::new();
    for word in command {
        rust_branch_tags(word, &mut command_tags);
    }
    let mut value_tags = BTreeMap::new();
    rust_branch_tags(value, &mut value_tags);
    value_tags.iter().all(|(group, choice)| {
        command_tags
            .get(group)
            .is_none_or(|command_choice| command_choice == choice)
    })
}

fn append_command_argument(
    commands: &mut CommandCandidates,
    value: &SemanticValue,
    value_limits: crate::ValueLimits,
) {
    let alternatives = match &value.kind {
        SemanticValueKind::Union(alternatives) => alternatives.clone(),
        _ => vec![value.clone()],
    };
    let mut expanded = Vec::new();
    for command in &commands.values {
        for alternative in &alternatives {
            if !command_branch_compatible(command, alternative) {
                continue;
            }
            let mut command = command.clone();
            command.push(alternative.clone());
            expanded.push(command);
        }
    }
    commands.values = expanded;
    dedup_commands(commands, value_limits);
}

fn append_command_arguments(
    commands: &mut CommandCandidates,
    value: &SemanticValue,
    value_limits: crate::ValueLimits,
) {
    match &value.kind {
        SemanticValueKind::Collection { elements, .. } => {
            for element in elements {
                append_command_argument(commands, element, value_limits);
            }
        }
        SemanticValueKind::Union(alternatives) => {
            let original = commands.clone();
            let mut expanded = CommandCandidates {
                values: Vec::new(),
                cwd: original.cwd.clone(),
                widened: original.widened,
            };
            for alternative in alternatives {
                let mut branch = CommandCandidates {
                    values: original
                        .values
                        .iter()
                        .filter(|command| command_branch_compatible(command, alternative))
                        .cloned()
                        .collect(),
                    cwd: original.cwd.clone(),
                    widened: false,
                };
                append_command_arguments(&mut branch, alternative, value_limits);
                expanded.values.extend(branch.values);
                expanded.widened |= branch.widened;
            }
            *commands = expanded;
            dedup_commands(commands, value_limits);
        }
        SemanticValueKind::Alias {
            name: branch,
            value,
        } if is_rust_branch(branch) => match &value.kind {
            SemanticValueKind::Collection { elements, .. } => {
                commands.values.retain(|command| {
                    command_branch_compatible(
                        command,
                        &rust_branch_value(branch, value.as_ref().clone()),
                    )
                });
                for element in elements {
                    append_command_argument(
                        commands,
                        &rust_branch_value(branch, element.clone()),
                        value_limits,
                    );
                }
            }
            SemanticValueKind::Union(alternatives) => {
                append_command_arguments(
                    commands,
                    &SemanticValue::new(SemanticValueKind::Union(
                        alternatives
                            .iter()
                            .cloned()
                            .map(|value| rust_branch_value(branch, value))
                            .collect(),
                    )),
                    value_limits,
                );
            }
            SemanticValueKind::Alias { name, .. } if is_rust_branch(name) => {
                append_command_arguments(commands, value, value_limits);
            }
            _ => {
                commands.values.retain(|command| {
                    command_branch_compatible(
                        command,
                        &rust_branch_value(branch, value.as_ref().clone()),
                    )
                });
                let spread = SemanticValue::new(SemanticValueKind::Alias {
                    name: "rust_args".to_string(),
                    value: Box::new(rust_branch_value(branch, value.as_ref().clone())),
                });
                for command in &mut commands.values {
                    command.push(spread.clone());
                }
            }
        },
        _ => {
            let spread = SemanticValue::new(SemanticValueKind::Alias {
                name: "rust_args".to_string(),
                value: Box::new(value.clone()),
            });
            for command in &mut commands.values {
                command.push(spread.clone());
            }
        }
    }
}

fn dedup_commands(commands: &mut CommandCandidates, value_limits: crate::ValueLimits) {
    commands
        .values
        .sort_by_key(|command| format!("{command:?}"));
    commands.values.dedup();
    let limit = value_limits.max_cardinality;
    if commands.values.len() > limit {
        commands.widened = true;
    }
    if commands.widened {
        commands.values.truncate(limit.saturating_sub(1));
    }
}

fn command_marker(commands: CommandCandidates) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Alias {
        name: "rust_command".to_string(),
        value: Box::new(collection_value(
            commands
                .values
                .into_iter()
                .map(collection_value)
                .collect::<Vec<_>>(),
        )),
    })
}

fn cross_file_value_call_key(expr: &Expr, fns: &Fns<'_>, uses: &Resolver) -> Option<ExprKey> {
    match expr {
        Expr::Try(try_) => cross_file_value_call_key(&try_.expr, fns, uses),
        Expr::Paren(paren) => cross_file_value_call_key(&paren.expr, fns, uses),
        Expr::Reference(reference) => cross_file_value_call_key(&reference.expr, fns, uses),
        Expr::MethodCall(call) if PEEL_METHODS.contains(&call.method.to_string().as_str()) => {
            cross_file_value_call_key(&call.receiver, fns, uses)
        }
        Expr::Match(match_) if match_preserves_scrutinee(match_, &fns.unit_variants) => {
            cross_file_value_call_key(&match_.expr, fns, uses)
        }
        Expr::Match(match_) => {
            let mut selected = None;
            for arm in &match_.arms {
                if expression_diverges(&arm.body) {
                    continue;
                }
                let key = cross_file_value_call_key(&arm.body, fns, uses)?;
                if selected.is_some_and(|selected| selected != key) {
                    return None;
                }
                selected = Some(key);
            }
            selected
        }
        Expr::Block(block) => block
            .block
            .stmts
            .last()
            .and_then(|statement| match statement {
                Stmt::Expr(expr, _) => cross_file_value_call_key(expr, fns, uses),
                _ => None,
            }),
        Expr::Call(call) => {
            let segments = path_segments(&call.func)?;
            let resolved = uses.resolve(&segments);
            let local = match segments.as_slice() {
                [name] => fns.get(name).is_some(),
                [typ, method] => fns.get(&format!("{typ}.{method}")).is_some(),
                _ => false,
            };
            (!local
                && !is_known_api(&resolved)
                && !resolved.starts_with("std::")
                && resolved != "shell_words::split"
                && resolved != "grep_cli::resolve_binary"
                && !is_effectless_call(segments.last().map(String::as_str).unwrap_or_default()))
            .then(|| expr_key(expr))
        }
        _ => None,
    }
}

fn match_preserves_scrutinee(
    match_: &syn::ExprMatch,
    unit_variants: &HashMap<String, String>,
) -> bool {
    let mut found_identity = false;
    for arm in &match_.arms {
        if expression_diverges(&arm.body) {
            continue;
        }
        let Some(name) = transparent_value_ident(&arm.body) else {
            return false;
        };
        if !pattern_preserves_value(&arm.pat, &name, unit_variants) {
            return false;
        }
        found_identity = true;
    }
    found_identity
}

fn pattern_preserves_value(
    pattern: &Pat,
    name: &str,
    unit_variants: &HashMap<String, String>,
) -> bool {
    match pattern {
        Pat::Ident(identifier) => {
            unit_variant_pattern(identifier, unit_variants).is_none()
                && identifier.ident == name
                && identifier.subpat.is_none()
        }
        Pat::Type(typed) => pattern_preserves_value(&typed.pat, name, unit_variants),
        Pat::Reference(reference) => pattern_preserves_value(&reference.pat, name, unit_variants),
        Pat::Paren(paren) => pattern_preserves_value(&paren.pat, name, unit_variants),
        Pat::TupleStruct(tuple) => {
            matches!(
                tuple.path.segments.last().map(|segment| segment.ident.to_string()),
                Some(variant) if matches!(variant.as_str(), "Ok" | "Some")
            ) && tuple.elems.len() == 1
                && pattern_preserves_value(&tuple.elems[0], name, unit_variants)
        }
        _ => false,
    }
}

fn transparent_value_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => single_ident(&path.path),
        Expr::Paren(paren) => transparent_value_ident(&paren.expr),
        Expr::Group(group) => transparent_value_ident(&group.expr),
        Expr::Reference(reference) => transparent_value_ident(&reference.expr),
        Expr::Try(try_) => transparent_value_ident(&try_.expr),
        Expr::MethodCall(call) if PEEL_METHODS.contains(&call.method.to_string().as_str()) => {
            transparent_value_ident(&call.receiver)
        }
        Expr::Block(block) => block
            .block
            .stmts
            .last()
            .and_then(|statement| match statement {
                Stmt::Expr(expr, None) => transparent_value_ident(expr),
                _ => None,
            }),
        _ => None,
    }
}

fn expression_diverges(expr: &Expr) -> bool {
    match expr {
        Expr::Return(_) | Expr::Break(_) | Expr::Continue(_) => true,
        Expr::Paren(paren) => expression_diverges(&paren.expr),
        Expr::Group(group) => expression_diverges(&group.expr),
        Expr::Block(block) => block
            .block
            .stmts
            .last()
            .is_some_and(|statement| match statement {
                Stmt::Expr(expr, _) => expression_diverges(expr),
                _ => false,
            }),
        _ => false,
    }
}

fn is_unresolved_value(value: &SemanticValue) -> bool {
    matches!(value.kind, SemanticValueKind::Unresolved { .. })
}

fn is_symbolic_value(value: &SemanticValue) -> bool {
    matches!(
        value.kind,
        SemanticValueKind::Symbol(_)
            | SemanticValueKind::Parameter(_)
            | SemanticValueKind::Environment(_)
    )
}

fn is_unknown_unit(value: &SemanticValue) -> bool {
    matches!(&value.kind, SemanticValueKind::Unresolved { family, .. } if family == "unit")
}

fn never_value() -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Alias {
        name: "rust_never".to_string(),
        value: Box::new(SemanticValue::unresolved("value")),
    })
}

fn is_never(value: &SemanticValue) -> bool {
    matches!(&value.kind, SemanticValueKind::Alias { name, .. } if name == "rust_never")
}

fn integer_literal(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => value.base10_parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Execution (from main)
// ---------------------------------------------------------------------------

struct Executor<'a> {
    builder: &'a mut PlanBuilder,
    source: &'a str,
    nest: &'a Nest<'a>,
    uses: &'a Resolver,
    fns: &'a Fns<'a>,
    cwd: Option<&'a str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    nodes: u64,
    /// Functions currently on the execution stack, so recursion terminates.
    visiting: HashSet<String>,
    closures: HashMap<String, ClosureDef>,
    futures: HashMap<String, Expr>,
    receiver_types: HashMap<String, String>,
    receiver_fields: HashMap<String, HashMap<String, ResourceExpr>>,
    value_facts: &'a ValueFacts,
    all_value_facts: &'a HashMap<String, ValueFacts>,
}

impl Executor<'_> {
    /// One node against the frontend cap (`max_rust_nodes`) and the shared
    /// analysis step budget; true means the walk must stop.
    fn over_node_budget(&mut self, span: (u32, u32)) -> bool {
        if !crate::nest::charge_analysis_steps(self.builder, self.nest.budget, 1, Some(span)) {
            return true;
        }
        self.nodes += 1;
        self.nodes > self.nest.limits.max_rust_nodes
    }

    fn walk_block(
        &mut self,
        block: &Block,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        cmds: &mut HashSet<String>,
    ) {
        for stmt in &block.stmts {
            let range = stmt.span().byte_range();
            if self.over_node_budget((range.start as u32, range.end as u32)) {
                self.partial_nodes();
                return;
            }
            match stmt {
                Stmt::Expr(e, _) => self.walk_expr(e, params, env, cmds),
                Stmt::Local(local @ Local { init: Some(li), .. }) => {
                    if let Some(name) = pat_ident(&local.pat) {
                        if let Some((receiver, fields)) = self.receiver_value(&li.expr, params, env)
                        {
                            self.receiver_types.insert(name.clone(), receiver);
                            self.receiver_fields.insert(name.clone(), fields);
                        } else {
                            self.receiver_types.remove(&name);
                            self.receiver_fields.remove(&name);
                        }
                        if let Some(closure) = closure_def(&li.expr) {
                            self.futures.remove(&name);
                            self.closures.insert(name, closure);
                            continue;
                        }
                        self.closures.remove(&name);
                        if let Some(future) = bound_future(&li.expr, self.fns, &self.futures) {
                            for argument in future_eager_arguments(&li.expr, self.fns) {
                                self.walk_expr(argument, params, env, cmds);
                            }
                            self.futures.insert(name, future);
                            continue;
                        }
                        self.futures.remove(&name);
                        if command_receiver(&li.expr, self.uses, cmds) {
                            cmds.insert(name);
                        }
                    }
                    self.walk_expr(&li.expr, params, env, cmds)
                }
                _ => {}
            }
        }
    }

    fn walk_expr(
        &mut self,
        expr: &Expr,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        cmds: &mut HashSet<String>,
    ) {
        self.walk_expr_at(expr, params, env, cmds, false);
    }

    fn walk_expr_at(
        &mut self,
        expr: &Expr,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        cmds: &mut HashSet<String>,
        root_awaited: bool,
    ) {
        self.walk_expr_at_state(expr, params, env, cmds, root_awaited, false);
    }

    fn walk_expr_at_state(
        &mut self,
        expr: &Expr,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        cmds: &mut HashSet<String>,
        root_awaited: bool,
        root_arguments_evaluated: bool,
    ) {
        let depth = self.builder.condition_depth();
        self.walk_guarded_exprs(
            expr,
            params,
            env,
            cmds,
            root_awaited,
            root_arguments_evaluated,
        );
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    fn walk_guarded_exprs(
        &mut self,
        expr: &Expr,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        cmds: &mut HashSet<String>,
        root_awaited: bool,
        root_arguments_evaluated: bool,
    ) {
        let mut stack = vec![(expr, root_awaited, root_arguments_evaluated)];
        let depth = self.builder.condition_depth();
        while let Some((expr, awaited, arguments_evaluated)) = stack.pop() {
            while self.builder.condition_depth() > depth {
                self.builder.pop_condition();
            }
            let range = expr.span().byte_range();
            if let Some(condition) = self.uses.guards.at(effinterp_proto::ByteSpan {
                start: range.start as u32,
                end: range.end as u32,
            }) {
                self.builder.push_condition(condition);
            }
            if self.over_node_budget((range.start as u32, range.end as u32)) {
                self.partial_nodes();
                return;
            }
            match expr {
                Expr::Await(await_) => {
                    if let Some(name) = future_name(&await_.base)
                        && let Some(future) = self.futures.get(&name).cloned()
                    {
                        self.walk_expr_at_state(&future, params, env, cmds, true, true);
                        continue;
                    }
                    stack.push((&await_.base, true, false));
                    continue;
                }
                Expr::Path(_) => {
                    if let Some(name) = future_name(expr)
                        && let Some(future) = self.futures.get(&name).cloned()
                    {
                        self.walk_expr_at_state(&future, params, env, cmds, awaited, true);
                        continue;
                    }
                }
                Expr::Async(async_) if awaited => {
                    self.walk_block(&async_.block, params, env, cmds);
                    continue;
                }
                Expr::Async(_) => {
                    self.unresolved("async block whose future is not known to be polled");
                    continue;
                }
                Expr::Closure(_) => continue,
                Expr::Assign(assign) => {
                    if let Expr::Path(path) = assign.left.as_ref()
                        && let Some(name) = single_ident(&path.path)
                    {
                        if let Some((receiver, fields)) =
                            self.receiver_value(&assign.right, params, env)
                        {
                            self.receiver_types.insert(name.clone(), receiver);
                            self.receiver_fields.insert(name, fields);
                        } else {
                            self.receiver_types.remove(&name);
                            self.receiver_fields.remove(&name);
                        }
                    }
                }
                _ => {}
            }
            let polls_future = polls_future_argument(expr, self.uses);
            if !arguments_evaluated {
                for argument in call_arg_exprs(expr) {
                    if let Expr::Path(path) = argument
                        && let Some(name) = single_ident(&path.path)
                    {
                        if let Some(closure) = self.closures.get(&name).cloned() {
                            self.call_closure(&name, &closure, &[], params, env, cmds);
                        } else if let Some(function) = self.fns.get(&name) {
                            if function.is_async {
                                self.unresolved("escaped async callback");
                            } else {
                                self.call_local(&name, &[], params, env, None);
                            }
                        }
                    }
                }
            }
            if is_indirect_call(expr) {
                self.unresolved("indirect callable expression");
            }
            if let Some(handled) = classify_call(expr, self.uses, cmds) {
                let first_effect = self.builder.effects_len();
                let mut control_facts = SiteFacts::unknown();
                match handled {
                    CallKind::Fs {
                        operation,
                        recursive,
                        arg,
                    } => {
                        let resolution = resolve_rust_sink(
                            arg,
                            self.value_facts,
                            env,
                            arg_resource(arg, params),
                            RustSinkDomain::Filesystem,
                            self.nest.limits.value_limits(),
                        );
                        let node = self.emit(
                            expr,
                            fs_effect_struct(operation, recursive, resolution.resource.clone()),
                        );
                        // Reaching a direct delete attempts the interaction;
                        // exact resource resolution is not the proof.
                        if operation == "filesystem.delete" {
                            control_facts = SiteFacts::known(
                                self.builder
                                    .control_own_effects(first_effect..self.builder.effects_len()),
                            );
                        }
                        if let Some(give_up) = resolution.give_up {
                            self.emit_sink_boundary(
                                node,
                                give_up,
                                "filesystem",
                                resolution.resource,
                                rust_sink_detail(arg, give_up, "filesystem"),
                            );
                        }
                    }
                    CallKind::Git {
                        operation,
                        field,
                        arg,
                    } => {
                        self.emit(
                            expr,
                            git_effect_struct(operation, git_resource(arg, params, field)),
                        );
                    }
                    CallKind::Env { operation, arg } => {
                        self.emit(
                            expr,
                            env_effect_struct(
                                operation,
                                resolve_rust_env_name(
                                    arg,
                                    self.value_facts,
                                    env,
                                    self.nest.limits.value_limits(),
                                ),
                            ),
                        );
                    }
                    CallKind::Net { arg } => {
                        let resolution = resolve_rust_sink(
                            arg,
                            self.value_facts,
                            env,
                            net_effect_struct(arg, params).resource,
                            RustSinkDomain::Network,
                            self.nest.limits.value_limits(),
                        );
                        let node = self.emit(
                            expr,
                            base_effect("network.request", resolution.resource.clone()),
                        );
                        if let Some(give_up) = resolution.give_up {
                            self.emit_sink_boundary(
                                node,
                                give_up,
                                "network",
                                resolution.resource,
                                rust_sink_detail(arg, give_up, "network"),
                            );
                        }
                    }
                    CallKind::NetAddr { operation, arg } => {
                        let resolution = resolve_rust_sink(
                            arg,
                            self.value_facts,
                            env,
                            net_addr_effect_struct(operation, arg, params).resource,
                            RustSinkDomain::NetworkAddress,
                            self.nest.limits.value_limits(),
                        );
                        let node =
                            self.emit(expr, base_effect(operation, resolution.resource.clone()));
                        if let Some(give_up) = resolution.give_up {
                            self.emit_sink_boundary(
                                node,
                                give_up,
                                "network",
                                resolution.resource,
                                rust_sink_detail(arg, give_up, "network"),
                            );
                        }
                    }
                    // `std::fs::copy` reads the source and writes the
                    // destination; `std::fs::rename` moves the source entry
                    // instead, under the `filesystem.move` semantic layer.
                    CallKind::Copy { src, dst } => {
                        self.emit_fs_transfer(expr, env, params, src, dst, false)
                    }
                    CallKind::Rename { src, dst } => {
                        self.emit_fs_transfer(expr, env, params, src, dst, true)
                    }
                    CallKind::Command { argv } => {
                        if let Some(commands) = self.value_facts.commands.get(&expr_key(expr)) {
                            let bindings = semantic_bindings(env);
                            let commands = commands.clone();
                            let cwd = commands.cwd.as_ref().map(|cwd| {
                                resolve_rust_command_cwd(cwd, env, self.nest.limits.value_limits())
                            });
                            let mut cwd_node = None;
                            for command in commands.values {
                                let mut words = Vec::with_capacity(command.len());
                                for value in &command {
                                    let mut visited = 0;
                                    let value = substitute_value_counted(
                                        value,
                                        &bindings,
                                        self.nest.limits.value_limits(),
                                        &mut visited,
                                    );
                                    if !crate::nest::charge_analysis_steps(
                                        self.builder,
                                        self.nest.budget,
                                        visited,
                                        Some((range.start as u32, range.end as u32)),
                                    ) {
                                        return;
                                    }
                                    words.push(semantic_word(&value));
                                }
                                cwd_node = self.spawn(words, cwd.as_ref());
                            }
                            if let Some(cwd) = cwd
                                && let (Some(node), Some(give_up)) = (cwd_node, cwd.give_up)
                            {
                                self.emit_sink_boundary(
                                    node,
                                    give_up,
                                    "filesystem",
                                    cwd.resource,
                                    "Command::current_dir value could not be lowered for filesystem"
                                        .to_string(),
                                );
                            }
                            if commands.widened {
                                self.emit(
                                    expr,
                                    command_effect(&[Word::new(vec![WordPart::Unknown])]),
                                );
                                self.builder.boundary(simple_boundary(
                                    BoundaryReason::VALUE_WIDENED,
                                    BoundaryClass::Unresolved,
                                    &["process"],
                                    "rust command candidates widened",
                                ));
                            }
                        } else {
                            self.spawn(argv, None);
                        }
                    }
                    CallKind::Local { name, args } => {
                        let caller_condition = self.uses.guards.at(effinterp_proto::ByteSpan {
                            start: range.start as u32,
                            end: range.end as u32,
                        });
                        if let Some(condition) = &caller_condition {
                            self.builder.push_condition(condition.clone());
                        }
                        let previous_call =
                            self.builder
                                .enter_condition_call(&effinterp_proto::stable_hash(
                                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                                    &(self.uses.source_id, range.start, range.end),
                                ));
                        if let Some(closure) = self.closures.get(&name).cloned() {
                            control_facts =
                                self.call_closure(&name, &closure, &args, params, env, cmds);
                        } else if self
                            .fns
                            .get(&name)
                            .is_some_and(|function| function.is_async)
                            && !awaited
                        {
                            self.unresolved(&format!(
                                "async function {name:?} whose future is not known to be polled"
                            ));
                        } else {
                            control_facts = self.call_local(&name, &args, params, env, None);
                        }
                        self.builder.leave_condition_call(previous_call);
                        if caller_condition.is_some() {
                            self.builder.pop_condition();
                        }
                    }
                }
                self.builder
                    .control_site(self.source, false, control::span(expr), control_facts);
                if !arguments_evaluated {
                    for sub in call_arg_exprs(expr).into_iter().rev() {
                        stack.push((
                            closure_expr(sub)
                                .map(|closure| &*closure.body)
                                .unwrap_or(sub),
                            polls_future,
                            false,
                        ));
                    }
                }
                continue;
            }
            if let Some((name, args, receiver)) = self.in_file_call(expr, params, env) {
                let caller_condition = self.uses.guards.at(effinterp_proto::ByteSpan {
                    start: range.start as u32,
                    end: range.end as u32,
                });
                if let Some(condition) = &caller_condition {
                    self.builder.push_condition(condition.clone());
                }
                let previous_call =
                    self.builder
                        .enter_condition_call(&effinterp_proto::stable_hash(
                            effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                            &(self.uses.source_id, range.start, range.end),
                        ));
                let facts = self.call_local(&name, &args, params, env, receiver);
                self.builder
                    .control_site(self.source, false, control::span(expr), facts);
                self.builder.leave_condition_call(previous_call);
                if caller_condition.is_some() {
                    self.builder.pop_condition();
                }
                if !arguments_evaluated {
                    for sub in call_arg_exprs(expr).into_iter().rev() {
                        stack.push((sub, polls_future, false));
                    }
                    if let Expr::MethodCall(call) = expr {
                        stack.push((&call.receiver, polls_future, false));
                    }
                }
                continue;
            }
            if polls_future {
                if !arguments_evaluated {
                    for argument in call_arg_exprs(expr).into_iter().rev() {
                        stack.push((
                            closure_expr(argument)
                                .map(|closure| &*closure.body)
                                .unwrap_or(argument),
                            true,
                            false,
                        ));
                    }
                }
                continue;
            }
            if let Expr::Call(call) = expr
                && let Some(segments) = path_segments(&call.func)
                && self.uses.resolve(&segments).starts_with("std::")
                && !matches!(
                    crate::external::classify_rust_call(&self.uses.resolve(&segments)),
                    Some(crate::external::ExternalCall::Inert)
                )
                && !(matches!(
                    self.uses.resolve(&segments).as_str(),
                    "std::process::Command::new"
                        | "std::fs::OpenOptions::new"
                        | "std::fs::File::options"
                ) && model::rust_api_has_required_arguments(
                    &self.uses.resolve(&segments),
                    call.args.len(),
                ))
            {
                self.unresolved(&self.uses.resolve(&segments));
                for argument in &call.args {
                    self.walk_expr(
                        closure_expr(argument).map(|c| &*c.body).unwrap_or(argument),
                        params,
                        env,
                        cmds,
                    );
                }
                continue;
            }
            if let Expr::Call(call) = expr
                && let Some(segments) = path_segments(&call.func)
                && segments.len() > 1
                && !self.uses.path_is_imported(&segments)
                && !is_effectless_call(segments.last().map(String::as_str).unwrap_or_default())
            {
                self.unresolved(&segments.join("::"));
                if !arguments_evaluated {
                    for argument in call.args.iter().rev() {
                        stack.push((argument, polls_future, false));
                    }
                }
                continue;
            }
            for child in child_exprs(expr).into_iter().rev() {
                stack.push((child, polls_future, arguments_evaluated));
            }
        }
    }

    fn in_file_call<'b>(
        &self,
        expr: &'b Expr,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<InFileCall<'b>> {
        match expr {
            Expr::Call(call) => {
                let segments = path_segments(&call.func)?;
                if segments.len() < 2 {
                    return None;
                }
                let module = segments.join("::");
                let associated = if segments.len() == 2 {
                    Some(format!("{}.{}", segments.first()?, segments.last()?))
                } else {
                    None
                };
                let name = if self.fns.get(&module).is_some() {
                    module
                } else if associated
                    .as_ref()
                    .is_some_and(|associated| self.fns.get(associated).is_some())
                {
                    associated?
                } else {
                    return None;
                };
                Some((name, call.args.iter().collect(), None))
            }
            Expr::MethodCall(call) => {
                let (receiver_type, fields) = self.receiver_value(&call.receiver, params, env)?;
                let name = format!("{receiver_type}.{}", call.method);
                self.fns
                    .get(&name)
                    .is_some()
                    .then(|| (name, call.args.iter().collect(), Some(fields)))
            }
            _ => None,
        }
    }

    fn receiver_value(
        &self,
        expr: &Expr,
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<(String, HashMap<String, ResourceExpr>)> {
        match expr {
            Expr::Paren(paren) => self.receiver_value(&paren.expr, params, env),
            Expr::Group(group) => self.receiver_value(&group.expr, params, env),
            Expr::Reference(reference) => self.receiver_value(&reference.expr, params, env),
            Expr::Try(try_) => self.receiver_value(&try_.expr, params, env),
            Expr::Path(path) => {
                let name = single_ident(&path.path)?;
                Some((
                    self.receiver_types.get(&name)?.clone(),
                    self.receiver_fields.get(&name).cloned().unwrap_or_default(),
                ))
            }
            Expr::Struct(struct_) => {
                let receiver = struct_.path.segments.last()?.ident.to_string();
                if !self.fns.classes.iter().any(|class| class.name == receiver) {
                    return None;
                }
                let fields = struct_
                    .fields
                    .iter()
                    .filter_map(|field| {
                        let syn::Member::Named(name) = &field.member else {
                            return None;
                        };
                        Some((
                            name.to_string(),
                            substitute_resource_expr(
                                &call_argument_resource(&field.expr, params),
                                env,
                            ),
                        ))
                    })
                    .collect();
                Some((receiver, fields))
            }
            Expr::Call(call) => {
                let segments = path_segments(&call.func)?;
                let name = format!(
                    "{}.{}",
                    segments.get(segments.len().checked_sub(2)?)?,
                    segments.last()?
                );
                let function = self.fns.get(&name)?;
                let receiver = function.ret_class.clone()?;
                let mut bindings = HashMap::new();
                for (parameter, argument) in function.params.iter().zip(&call.args) {
                    bindings.insert(
                        parameter.clone(),
                        SemanticValue::from(substitute_resource_expr(
                            &call_argument_resource(argument, params),
                            env,
                        )),
                    );
                }
                let fields = self
                    .all_value_facts
                    .get(&name)
                    .and_then(|facts| facts.returns.as_ref())
                    .and_then(|value| {
                        let value =
                            substitute_value(value, &bindings, self.nest.limits.value_limits());
                        let SemanticValueKind::Object(object) = value.kind else {
                            return None;
                        };
                        Some(
                            object
                                .properties
                                .into_iter()
                                .map(|(name, value)| (name, value.lower_resource()))
                                .collect(),
                        )
                    })
                    .unwrap_or_default();
                Some((receiver, fields))
            }
            _ => None,
        }
    }

    fn call_closure(
        &mut self,
        name: &str,
        closure: &ClosureDef,
        args: &[&Expr],
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        cmds: &mut HashSet<String>,
    ) -> SiteFacts {
        let marker = format!("closure::{name}");
        if self.visiting.len() >= MAX_CALL_DEPTH || !self.visiting.insert(marker.clone()) {
            self.unresolved("recursive closure call");
            return SiteFacts::widened();
        }
        let arg_exprs: Vec<_> = args
            .iter()
            .map(|arg| substitute_resource_expr(&arg_resource(arg, params), env))
            .collect();
        let mut closure_params = params.clone();
        closure_params.extend(closure.params.iter().cloned());
        let mut closure_env = env.clone();
        closure_env.extend(bind_positional(&closure.params, &arg_exprs));
        self.builder.control_enter(self.source, false, |graph| {
            control::build_expr(graph, &closure.body);
        });
        match &closure.body {
            Expr::Block(block) => {
                let caller_cmds = cmds.clone();
                let caller_closures = self.closures.clone();
                let caller_futures = self.futures.clone();
                self.walk_block(&block.block, &closure_params, &closure_env, cmds);
                *cmds = caller_cmds;
                self.closures = caller_closures;
                self.futures = caller_futures;
            }
            body => self.walk_expr(body, &closure_params, &closure_env, cmds),
        }
        self.visiting.remove(&marker);
        self.builder
            .control_leave()
            .map_or_else(SiteFacts::unknown, |finished| {
                SiteFacts::call(&finished.requirements, Some)
            })
    }

    fn partial_nodes(&mut self) {
        self.builder.control_widen();
        if self.nest.budget.steps_saturated() {
            return;
        }
        for domain in RUST_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        let node = self.node();
        self.builder.boundary(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: RUST_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: Some("max_rust_nodes".to_string()),
            detail: Some("rust walk node budget exhausted".to_string()),
        });
    }

    fn emit(&mut self, expr: &Expr, effect: Effect) -> ProvenanceRef {
        self.emit_slot(expr, effect).0
    }

    /// Emit one effect and return its model-application provenance node
    /// together with the plan slot it landed in.
    fn emit_slot(&mut self, expr: &Expr, effect: Effect) -> (ProvenanceRef, Option<u32>) {
        let range = expr.span().byte_range();
        let source = self.builder.node(
            ProvenanceKind::SourceSpan {
                start: range.start as u32,
                end: range.end as u32,
            },
            self.scope.as_slice(),
        );
        let node = self.builder.node(
            ProvenanceKind::ModelApplication {
                model: "rust/std@v0".to_string(),
            },
            &[source],
        );
        let mut e = effect;
        let mut guard = self.uses.guards.at(effinterp_proto::ByteSpan {
            start: range.start as u32,
            end: range.end as u32,
        });
        self.builder.bind_source_condition(&mut guard);
        e.condition = effinterp_proto::Condition::compose(e.condition.iter().chain(guard.iter()));
        let value = SemanticValue::from(&e.resource);
        crate::lower_effect_value(&mut e, &value);
        e.provenance = vec![node];
        if e.operation.domain() == "filesystem" && fs_resource_uses_cwd(&e.resource) {
            e.provenance.extend(self.cwd_node);
        }
        let slot = self.builder.effect(e);
        (node, slot)
    }

    fn node(&mut self) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::ModelApplication {
                model: "rust/std@v0".to_string(),
            },
            self.scope.as_slice(),
        )
    }

    fn spawn(
        &mut self,
        argv: Vec<Word>,
        cwd: Option<&RustSinkResolution>,
    ) -> Option<ProvenanceRef> {
        if argv.is_empty() {
            return None;
        }
        let node = self.node();
        if let Some(cwd) = cwd {
            let concrete = match &cwd.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some(path.as_str()),
                _ => None,
            };
            let cwd_node = fs_resource_uses_cwd(&cwd.resource)
                .then_some(self.cwd_node)
                .flatten();
            self.nest.nest(
                self.builder,
                Transition::exec(argv.iter().map(word_resource).collect(), argv.to_vec())
                    .exec_cwd(concrete)
                    .cwd(Some(cwd.resource.clone()), cwd_node)
                    .runtime_cwd(self.cwd)
                    .kind(ExecutionEdgeKind::Launch),
                &[node],
                self.depth,
            );
        } else {
            self.nest.nest(
                self.builder,
                Transition::exec(argv.iter().map(word_resource).collect(), argv.to_vec())
                    .exec_cwd(self.cwd)
                    .cwd(
                        self.builder.current_execution_cwd(),
                        (self.nest.current_runtime_cwd().as_deref() == self.cwd)
                            .then(|| self.nest.current_cwd_node())
                            .flatten(),
                    )
                    .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                &[node],
                self.depth,
            );
        }
        Some(node)
    }

    /// `std::fs::copy` reads the source and writes the destination;
    /// `std::fs::rename` moves the source entry instead, under the
    /// `filesystem.move` semantic layer. Either way the source-side endpoint
    /// pairs with the destination write as one recorded transfer.
    fn emit_fs_transfer(
        &mut self,
        expr: &Expr,
        env: &HashMap<String, ResourceExpr>,
        params: &HashSet<String>,
        src: &Expr,
        dst: &Expr,
        rename: bool,
    ) {
        let source_operations: &[&str] = if rename {
            &["filesystem.move", "filesystem.delete"]
        } else {
            &["filesystem.read"]
        };
        let mut source = None;
        let mut destination = None;
        for (arg, operations) in [(src, source_operations), (dst, &["filesystem.write"][..])] {
            let resolution = resolve_rust_sink(
                arg,
                self.value_facts,
                env,
                arg_resource(arg, params),
                RustSinkDomain::Filesystem,
                self.nest.limits.value_limits(),
            );
            let mut node = None;
            for operation in operations {
                let (emitted, slot) = self.emit_slot(
                    expr,
                    fs_effect_struct(operation, false, resolution.resource.clone()),
                );
                node = Some(emitted);
                // The pairing anchor is the atomic endpoint: the source entry
                // delete for a rename, the source content read for a copy.
                if *operation == "filesystem.write" {
                    destination = slot;
                } else if *operation != "filesystem.move" {
                    source = slot;
                }
            }
            if let Some(give_up) = resolution.give_up
                && let Some(node) = node
            {
                self.emit_sink_boundary(
                    node,
                    give_up,
                    "filesystem",
                    resolution.resource,
                    rust_sink_detail(arg, give_up, "filesystem"),
                );
            }
        }
        if let (Some(source), Some(destination)) = (source, destination) {
            self.builder
                .transfer_binding(TransferBinding::new(source, destination));
        }
    }

    fn emit_sink_boundary(
        &mut self,
        node: ProvenanceRef,
        give_up: RustSinkGiveUp,
        domain: &'static str,
        resource: ResourceExpr,
        detail: String,
    ) {
        self.builder
            .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        let mut boundary = rust_sink_boundary(give_up, domain, resource, detail);
        boundary.provenance = vec![node];
        self.builder.boundary(boundary);
    }

    /// Execution follows a call into a locally defined function by walking its
    /// body under an environment binding the callee's parameters to the call's
    /// argument expressions. Unlike applying a stored summary, this composes a
    /// subprocess spawned anywhere in the call graph, not just in main.
    fn call_local(
        &mut self,
        name: &str,
        args: &[&Expr],
        params: &HashSet<String>,
        env: &HashMap<String, ResourceExpr>,
        receiver: Option<HashMap<String, ResourceExpr>>,
    ) -> SiteFacts {
        let Some(callee) = self.fns.get(name) else {
            // A known-effectless std constructor/converter/control call is not a
            // boundary; only genuinely unmodeled calls degrade coverage. A
            // named import is a cross-file call — composition follows it.
            let resolved = self.uses.resolve(&[name.to_string()]);
            if resolved.starts_with("std::") {
                if !matches!(
                    crate::external::classify_rust_call(&resolved),
                    Some(crate::external::ExternalCall::Inert)
                ) {
                    self.unresolved(&resolved);
                }
            } else if !is_effectless_call(name) && !self.uses.is_imported(name) {
                self.unresolved(name);
            }
            return SiteFacts::unknown();
        };
        if self.visiting.len() >= MAX_CALL_DEPTH || !self.visiting.insert(name.to_string()) {
            self.unresolved(&format!("recursive or exhausted call {name}"));
            return SiteFacts::widened();
        }
        let arg_exprs: Vec<ResourceExpr> = args
            .iter()
            .map(|a| substitute_resource_expr(&call_argument_resource(a, params), env))
            .collect();
        let mut callee_params: HashSet<String> = callee.params.iter().cloned().collect();
        let mut new_env = bind_positional(&callee.params, &arg_exprs);
        let receiver = receiver.unwrap_or_default();
        let receiver_env: HashMap<String, ResourceExpr> = receiver
            .iter()
            .map(|(name, value)| (format!("self.{name}"), value.clone()))
            .collect();
        callee_params.extend(receiver_env.keys().cloned());
        new_env.extend(receiver_env);
        let mut callee_cmds = callee.command_params(&callee.uses);
        let caller_closures = std::mem::take(&mut self.closures);
        let caller_futures = std::mem::take(&mut self.futures);
        let caller_receiver_types = std::mem::take(&mut self.receiver_types);
        let caller_receiver_fields = std::mem::take(&mut self.receiver_fields);
        if let Some(impl_type) = &callee.impl_type {
            self.receiver_types
                .insert("self".to_string(), impl_type.clone());
            self.receiver_fields.insert("self".to_string(), receiver);
        }
        let caller_value_facts = std::mem::replace(
            &mut self.value_facts,
            value_facts_or_default(self.all_value_facts, name),
        );
        let caller_uses = std::mem::replace(&mut self.uses, &callee.uses);
        self.builder.control_enter(self.source, false, |graph| {
            control::build(graph, callee.body, false);
        });
        self.walk_block(callee.body, &callee_params, &new_env, &mut callee_cmds);
        let facts = self
            .builder
            .control_leave()
            .map_or_else(SiteFacts::unknown, |finished| {
                SiteFacts::call(&finished.requirements, Some)
            });
        self.uses = caller_uses;
        self.value_facts = caller_value_facts;
        self.closures = caller_closures;
        self.futures = caller_futures;
        self.receiver_types = caller_receiver_types;
        self.receiver_fields = caller_receiver_fields;
        self.visiting.remove(name);
        facts
    }

    fn unresolved(&mut self, name: &str) {
        for domain in KNOWN_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        let node = self.node();
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: name
                    .rsplit_once("::")
                    .map_or_else(String::new, |(module, _)| module.to_string()),
                symbol: name.rsplit("::").next().unwrap_or(name).to_string(),
            }),
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call to unmodeled {name}")),
        });
    }
}

// ---------------------------------------------------------------------------
// Shared walker helpers
// ---------------------------------------------------------------------------

/// Result/Option adapters that pass the underlying success value through, so a
/// `let x = Type::new(...).map_err(..)?` still types `x` (and carries the bind)
/// from the inner constructor call.
const PEEL_METHODS: &[&str] = &[
    "map_err",
    "unwrap",
    "expect",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "ok",
    "clone",
    "as_ref",
    "as_mut",
    "to_owned",
];

fn peels_outer_receiver_type(method: &str) -> bool {
    matches!(
        method,
        "unwrap" | "expect" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default" | "ok"
    )
}

/// The base identifier a method chain hangs off (`preprocessors` in
/// `preprocessors.iter().try_for_each(..)`), for element-typing closures.
fn chain_base_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => chain_base_ident(&m.receiver),
        Expr::Reference(r) => chain_base_ident(&r.expr),
        Expr::Paren(p) => chain_base_ident(&p.expr),
        Expr::Try(t) => chain_base_ident(&t.expr),
        Expr::Path(p) => single_ident(&p.path),
        _ => None,
    }
}

fn bound_command_chain_appends_arguments(expr: &Expr, state: &ValueState) -> bool {
    match expr {
        Expr::MethodCall(call) => {
            (matches!(call.method.to_string().as_str(), "arg" | "args")
                && chain_base_ident(&call.receiver)
                    .is_some_and(|name| state.commands.contains_key(&name)))
                || bound_command_chain_appends_arguments(&call.receiver, state)
        }
        Expr::Reference(reference) => bound_command_chain_appends_arguments(&reference.expr, state),
        Expr::Paren(paren) => bound_command_chain_appends_arguments(&paren.expr, state),
        Expr::Group(group) => bound_command_chain_appends_arguments(&group.expr, state),
        Expr::Try(try_) => bound_command_chain_appends_arguments(&try_.expr, state),
        _ => false,
    }
}

fn invalidate_command_alias_source(expr: &Expr, binding: &str, state: &mut ValueState) {
    let source = match expr {
        Expr::MethodCall(call)
            if !matches!(
                call.method.to_string().as_str(),
                "spawn" | "output" | "status"
            ) =>
        {
            chain_base_ident(&call.receiver)
        }
        Expr::Path(path) => single_ident(&path.path),
        Expr::Paren(paren) => {
            invalidate_command_alias_source(&paren.expr, binding, state);
            return;
        }
        Expr::Group(group) => {
            invalidate_command_alias_source(&group.expr, binding, state);
            return;
        }
        Expr::Try(try_) => {
            invalidate_command_alias_source(&try_.expr, binding, state);
            return;
        }
        _ => None,
    };
    if let Some(source) = source
        && source != binding
        && state.commands.contains_key(&source)
    {
        invalidate_value_binding(state, &source);
    }
}

fn mutated_base_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Field(field) => mutated_base_ident(&field.base),
        Expr::Index(index) => mutated_base_ident(&index.expr),
        Expr::MethodCall(call) => mutated_base_ident(&call.receiver),
        Expr::Reference(reference) => mutated_base_ident(&reference.expr),
        Expr::Paren(paren) => mutated_base_ident(&paren.expr),
        Expr::Group(group) => mutated_base_ident(&group.expr),
        Expr::Try(try_) => mutated_base_ident(&try_.expr),
        Expr::Path(path) => single_ident(&path.path),
        _ => None,
    }
}

fn is_compound_assignment(operator: &syn::BinOp) -> bool {
    matches!(
        operator,
        syn::BinOp::AddAssign(_)
            | syn::BinOp::SubAssign(_)
            | syn::BinOp::MulAssign(_)
            | syn::BinOp::DivAssign(_)
            | syn::BinOp::RemAssign(_)
            | syn::BinOp::BitXorAssign(_)
            | syn::BinOp::BitAndAssign(_)
            | syn::BinOp::BitOrAssign(_)
            | syn::BinOp::ShlAssign(_)
            | syn::BinOp::ShrAssign(_)
    )
}

// ---------------------------------------------------------------------------
// syn helpers
// ---------------------------------------------------------------------------

fn path_segments(expr: &Expr) -> Option<Vec<String>> {
    if let Expr::Path(p) = expr {
        Some(
            p.path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
        )
    } else {
        None
    }
}

/// The single identifier a `let` pattern binds, looking through a type
/// ascription (`let x: T = ...`) and by-ref/mut markers.
fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(id) => Some(id.ident.to_string()),
        Pat::Type(pt) => pat_ident(&pt.pat),
        Pat::Reference(r) => pat_ident(&r.pat),
        _ => None,
    }
}

fn single_ident(path: &syn::Path) -> Option<String> {
    if path.segments.len() == 1 {
        Some(path.segments[0].ident.to_string())
    } else {
        None
    }
}

fn str_lit(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        Expr::Reference(r) => str_lit(&r.expr),
        _ => None,
    }
}

/// The argument expressions of a call/method-call, for recursing to find
/// nested effects (e.g. `remove_file(compute_path())`).
fn call_arg_exprs(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Call(c) => c.args.iter().collect(),
        Expr::MethodCall(m) => m.args.iter().collect(),
        _ => Vec::new(),
    }
}

/// Sub-expressions to recurse into for a generic (non-effect) expression.
/// Deliberately broad but bounded. Constructing a closure or async block does
/// not execute its body. Call and method arguments may invoke a closure, while
/// direct closure bindings and awaited async blocks are handled by the walkers.
fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut out: Vec<&Expr> = Vec::new();
    match expr {
        Expr::Closure(_) | Expr::Async(_) => {}
        Expr::Call(c) => {
            if let Some(closure) = closure_expr(&c.func) {
                out.push(&closure.body);
            } else {
                out.push(&c.func);
            }
            for arg in &c.args {
                if let Expr::Closure(closure) = arg {
                    out.push(&closure.body);
                } else {
                    out.push(arg);
                }
            }
        }
        Expr::MethodCall(m) => {
            out.push(&m.receiver);
            for arg in &m.args {
                if let Expr::Closure(closure) = arg {
                    out.push(&closure.body);
                } else {
                    out.push(arg);
                }
            }
        }
        Expr::Binary(b) => {
            out.push(&b.left);
            out.push(&b.right);
        }
        Expr::Unary(u) => out.push(&u.expr),
        Expr::Reference(r) => out.push(&r.expr),
        Expr::Paren(p) => out.push(&p.expr),
        Expr::Group(g) => out.push(&g.expr),
        Expr::Field(f) => out.push(&f.base),
        Expr::Index(i) => {
            out.push(&i.expr);
            out.push(&i.index);
        }
        Expr::Try(t) => out.push(&t.expr),
        Expr::Await(a) => out.push(&a.base),
        Expr::Cast(c) => out.push(&c.expr),
        Expr::Assign(a) => {
            out.push(&a.left);
            out.push(&a.right);
        }
        Expr::Let(l) => out.push(&l.expr),
        Expr::If(i) => {
            out.push(&i.cond);
            out.extend(block_exprs(&i.then_branch));
            if let Some((_, else_e)) = &i.else_branch {
                out.push(else_e);
            }
        }
        Expr::While(w) => {
            out.push(&w.cond);
            out.extend(block_exprs(&w.body));
        }
        Expr::ForLoop(f) => {
            out.push(&f.expr);
            out.extend(block_exprs(&f.body));
        }
        Expr::Loop(l) => out.extend(block_exprs(&l.body)),
        Expr::Block(b) => out.extend(block_exprs(&b.block)),
        Expr::Unsafe(u) => out.extend(block_exprs(&u.block)),
        Expr::Match(m) => {
            out.push(&m.expr);
            for arm in &m.arms {
                out.push(&arm.body);
            }
        }
        Expr::Return(r) => {
            if let Some(e) = &r.expr {
                out.push(e);
            }
        }
        Expr::Array(a) => out.extend(a.elems.iter()),
        Expr::Tuple(t) => out.extend(t.elems.iter()),
        Expr::Struct(s) => {
            for f in &s.fields {
                out.push(&f.expr);
            }
        }
        _ => {}
    }
    out
}

fn block_exprs(block: &Block) -> Vec<&Expr> {
    let mut out = Vec::new();
    for stmt in &block.stmts {
        match stmt {
            Stmt::Expr(e, _) => out.push(e),
            Stmt::Local(Local { init: Some(li), .. }) => out.push(&li.expr),
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

fn empty() -> HashSet<String> {
    HashSet::new()
}

fn over_budget(nodes: &mut u64) -> bool {
    if !crate::limits::summary_step() {
        return true;
    }
    *nodes += 1;
    *nodes > crate::limits::invocation_node_limit(DEFAULT_MAX_RUST_NODES)
}

fn simple_boundary(
    reason: BoundaryReason,
    class: BoundaryClass,
    domains: &[&str],
    detail: &str,
) -> Boundary {
    Boundary {
        reason,
        class,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|d| Domain::new(*d)).collect(),
        provenance: Vec::new(),
        limit: None,
        detail: Some(detail.to_string()),
    }
}
fn rust_guard_regions(file: &syn::File, source: &str) -> crate::guards::GuardRegions {
    use effinterp_proto::{ByteSpan, ConditionKind};
    use syn::visit::Visit;
    fn span(value: impl Spanned) -> ByteSpan {
        let r = value.span().byte_range();
        ByteSpan {
            start: r.start as u32,
            end: r.end as u32,
        }
    }
    struct Collector<'a> {
        depth: usize,
        source: &'a str,
        guards: crate::guards::GuardRegions,
    }
    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_block(&mut self, block: &'ast Block) {
            let stops = |body: &Block| {
                matches!(
                    body.stmts.last(),
                    Some(Stmt::Expr(
                        Expr::Return(_) | Expr::Break(_) | Expr::Continue(_),
                        _
                    ))
                )
            };
            for stmt in &block.stmts {
                if let Stmt::Expr(Expr::If(branch), _) = stmt {
                    let yes = stops(&branch.then_branch);
                    let no = branch
                        .else_branch
                        .as_ref()
                        .is_some_and(|(_, e)| match e.as_ref() {
                            Expr::Block(b) => stops(&b.block),
                            Expr::Return(_) => true,
                            _ => false,
                        });
                    if yes != no {
                        self.guards.add(
                            self.source,
                            span(branch),
                            ByteSpan {
                                start: span(branch).end,
                                end: span(block).end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
            syn::visit::visit_block(self, block);
        }
        fn visit_expr(&mut self, expr: &'ast Expr) {
            if self.depth >= MAX_WALK_DEPTH as usize {
                self.guards.widen();
                return;
            }
            self.depth += 1;
            let origin = span(expr);
            match expr {
                Expr::If(i) => {
                    self.guards.add(
                        self.source,
                        origin,
                        span(&i.then_branch),
                        ConditionKind::Branch,
                        0,
                        2,
                        true,
                    );
                    if let Some((_, other)) = &i.else_branch {
                        self.guards.add(
                            self.source,
                            origin,
                            span(other),
                            ConditionKind::Branch,
                            1,
                            2,
                            true,
                        );
                    }
                }
                Expr::Closure(i) => self.guards.add(
                    self.source,
                    origin,
                    span(&i.body),
                    ConditionKind::Dispatch,
                    0,
                    2,
                    false,
                ),
                Expr::While(i) => self.guards.add(
                    self.source,
                    origin,
                    span(&i.body),
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                ),
                Expr::ForLoop(i) => self.guards.add(
                    self.source,
                    origin,
                    span(&i.body),
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                ),
                Expr::Match(i) => {
                    for (arm, body) in i.arms.iter().enumerate() {
                        self.guards.add(
                            self.source,
                            origin,
                            span(&body.body),
                            ConditionKind::Branch,
                            arm as u32,
                            i.arms.len() as u32
                                + u32::from(!i.arms.iter().any(|arm| {
                                    arm.guard.is_none() && matches!(arm.pat, syn::Pat::Wild(_))
                                })),
                            false,
                        );
                    }
                }
                Expr::Binary(i) if matches!(i.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                    self.guards.add(
                        self.source,
                        origin,
                        span(&i.right),
                        ConditionKind::ShortCircuit,
                        u32::from(matches!(i.op, syn::BinOp::Or(_))),
                        2,
                        true,
                    )
                }
                _ => (),
            }
            syn::visit::visit_expr(self, expr);
            self.depth -= 1;
        }
    }
    let mut collector = Collector {
        depth: 0,
        source,
        guards: Default::default(),
    };
    collector.visit_file(file);
    collector.guards
}
