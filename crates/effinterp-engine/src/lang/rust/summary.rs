use super::model::{
    CallKind, RustSinkDomain, arg_resource, base_effect, call_argument_resource, classify_call,
    command_effect, command_receiver, command_template_effect, env_effect_struct, fs_effect_struct,
    git_effect_struct, git_resource, is_indirect_call, is_known_api, net_addr_effect_struct,
    net_effect_struct, open_options_mode, polls_future_argument, resolve_rust_command_cwd,
    resolve_rust_env_name, resolve_rust_sink, rust_sink_boundary, rust_sink_detail,
    semantic_bindings,
};
use std::collections::{BTreeMap, HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, ResourceExpr,
};
use syn::spanned::Spanned;
use syn::{Block, Expr, Item, Local, Pat, Stmt};

use crate::control_flow::{ControlCaps, ControlFact, ControlStack, SiteFacts};
use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::module_summary::{CallEdge, FunctionEntry, ImportBinding, ModuleSummary, call_results};
use crate::resource_transfer::TransferBinding;
use crate::summary::{Summary, bind_positional, substitute_resource_expr};
use crate::word::{Word, WordPart};
use crate::{
    ObjectIdentity, SemanticValue, TypeRef, ValueArgument, merge_arguments, positional_arguments,
    substitute_value,
};

use super::call_resolution::dispatch_types::{
    PEEL_METHODS, base_type_ident, peels_outer_receiver_type, receiver_type_ref,
    receiver_type_ref_from_path, rust_dispatch_contracts, rust_dispatch_type_aliases,
};
use super::call_resolution::{
    RustFunction, RustFunctions, RustUseResolver, collect_rust_functions, is_effectless_rust_call,
    is_exported,
};
use super::control::{self, has_drop_impl};
use super::deferred_calls::{
    RustClosure, bound_future, closure_def, future_eager_arguments, future_name,
};
use super::macros::{entry_handoffs, handoff_call};
use super::model;
use super::syntax::{
    block_exprs, call_arg_exprs, chain_base_ident, child_exprs, closure_expr, pat_ident,
    path_segments, single_ident,
};
use super::value_facts::{
    RustValueFacts, cross_file_value_call_key, expr_key, is_unresolved_value,
    match_preserves_scrutinee, rust_value_facts, span_key, value_facts_or_default,
};
use super::{MAX_CALL_DEPTH, RUST_DOMAINS, over_budget, simple_boundary};

// ControlStack matches source allocations, so every capture uses this stable key.
static CAPTURE_SOURCE: &str = "rust-summary";

/// Summarize Rust callables even when their bodies are unreachable from main.
pub(super) fn summarize_ast(
    source: &str,
    file: &syn::File,
    value_limits: crate::ValueLimits,
) -> ModuleSummary {
    let uses = RustUseResolver::from_file(file, source);
    let fns = collect_rust_functions(file, &uses);
    let value_facts = rust_value_facts(
        std::iter::once("main").chain(fns.order.iter().map(String::as_str)),
        &fns,
        &uses,
        value_limits,
    );
    let mut summaries = summarize_all(&fns, &uses, &value_facts, value_limits);
    if has_drop_impl(file) {
        for summary in summaries.values_mut() {
            summary.control_flow = crate::control_flow::ControlFlow::widened();
            summary.boundaries.push(simple_boundary(
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                &RUST_DOMAINS,
                "Drop cleanup on normal return or unwinding",
            ));
        }
    }

    // Path-qualified cross-file calls synthesize whole-path import bindings so the
    // repo layer can resolve them via `resolve_rust`; collected across every
    // function alongside its call edges.
    let mut synth_imports: Vec<ImportBinding> = Vec::new();

    let mut functions: Vec<FunctionEntry> = Vec::new();
    for name in &fns.order {
        let (Some(summary), Some(f)) = (summaries.get(name), fns.get(name)) else {
            continue;
        };
        let mut edges = Vec::new();
        let mut sites = BTreeMap::new();
        {
            let _walk = crate::limits::summary_walk();
            let mut nodes = 0u64;
            let mut collector = EdgeCollector {
                uses: &f.uses,
                fns: &fns,
                out: &mut edges,
                sites: &mut sites,
                synth: &mut synth_imports,
                nodes: &mut nodes,
                visited: HashSet::new(),
                value_facts: value_facts_or_default(&value_facts, name),
                all_value_facts: &value_facts,
            };
            let mut scope = EdgeScope::for_fn(f, &f.uses);
            collector.walk_block(f.body, &mut scope);
        }
        let mut summary = summary.clone();
        summary.control_flow.bind_calls(&sites);
        functions.push(FunctionEntry {
            name: name.clone(),
            visibility: crate::CallableVisibility::Public,
            is_async: f.is_async,
            decorator_shape: Default::default(),
            decorator_gate: Vec::new(),
            summary,
            positional_param_count: None,
            calls: edges,
            callable_defaults: Vec::new(),
            parameter_type_narrowing: Vec::new(),
            returns_instances: f
                .ret_class
                .clone()
                .map(|c| vec![Some(c)])
                .unwrap_or_default(),
            return_types: f
                .ret_type
                .clone()
                .map(|ty| vec![Some(ty)])
                .unwrap_or_default(),
            return_bindings: Vec::new(),
            dispatch_impl: f.dispatch_impl.clone(),
            dispatch_signature: Some(f.dispatch_signature.clone()),
            lexical_span: None,
        });
    }

    // Execution starts at `fn main`; its direct calls are the roots a repository
    // composition follows across files (as with the Java/Go frontends). Static
    // and const initializers (`Lazy::new(|| ...)` closures included) run when
    // the module is used, so their calls join the module roots as may-effects.
    let mut module_calls = Vec::new();
    let mut module_sites = BTreeMap::new();
    {
        let _walk = crate::limits::summary_walk();
        let mut nodes = 0u64;
        let mut collector = EdgeCollector {
            uses: fns.get("main").map(|main| &main.uses).unwrap_or(&uses),
            fns: &fns,
            out: &mut module_calls,
            sites: &mut module_sites,
            synth: &mut synth_imports,
            nodes: &mut nodes,
            visited: HashSet::new(),
            value_facts: value_facts_or_default(&value_facts, "main"),
            all_value_facts: &value_facts,
        };
        if let Some(main) = fns.get("main") {
            let mut scope = EdgeScope::for_fn(main, &main.uses);
            collector.walk_block(main.body, &mut scope);
        }
        collector.uses = &uses;
        for item in &file.items {
            let init = match item {
                Item::Static(s) => &s.expr,
                Item::Const(c) => &c.expr,
                _ => continue,
            };
            let mut scope = EdgeScope::default();
            collector.walk_expr(init, &mut scope, None);
        }
    }

    // `foo::bin!(crate_ident)` (and `main!`/`entry!`) writes `fn main` only
    // after expansion. With no source `fn main`, the handoff is the file's
    // execution root so composition can enter the named crate.
    if fns.get("main").is_none() {
        let handoffs = entry_handoffs(file);
        if !handoffs.is_empty() {
            let mut calls = Vec::new();
            for h in &handoffs {
                let (edge, import) = handoff_call(h);
                calls.push(edge);
                if !synth_imports
                    .iter()
                    .any(|i| i.local == import.local && i.module == import.module)
                {
                    synth_imports.push(import);
                }
            }
            functions.push(FunctionEntry {
                name: "main".to_string(),
                visibility: crate::CallableVisibility::Public,
                is_async: false,
                decorator_shape: Default::default(),
                decorator_gate: Vec::new(),
                summary: Summary::pure(),
                positional_param_count: None,
                calls: calls.clone(),
                callable_defaults: Vec::new(),
                parameter_type_narrowing: Vec::new(),
                returns_instances: Vec::new(),
                return_types: Vec::new(),
                return_bindings: Vec::new(),
                dispatch_impl: None,
                dispatch_signature: None,
                lexical_span: None,
            });
            module_calls.extend(calls);
        }
    }

    let mut imports = uses.imports();
    for binding in synth_imports {
        if !imports.iter().any(|i| i.local == binding.local) {
            imports.push(binding);
        }
    }

    let mut exported_definitions: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if is_exported(&function.vis) => {
                Some(function.sig.ident.to_string())
            }
            Item::Struct(item) if is_exported(&item.vis) => Some(item.ident.to_string()),
            Item::Enum(item) if is_exported(&item.vis) => Some(item.ident.to_string()),
            Item::Trait(item) if is_exported(&item.vis) => Some(item.ident.to_string()),
            Item::Type(item) if is_exported(&item.vis) => Some(item.ident.to_string()),
            _ => None,
        })
        .map(|name| (name.clone(), name))
        .collect();
    exported_definitions.sort();
    exported_definitions.dedup();

    let module_control_flow = if file
        .items
        .iter()
        .any(|item| matches!(item, Item::Static(_) | Item::Const(_)))
    {
        crate::control_flow::ControlFlow::widened()
    } else if let Some(main) = functions.iter().find(|function| function.name == "main") {
        main.summary.control_flow.calls_only()
    } else {
        crate::control_flow::ControlFlow::empty_body()
    };
    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            explicit_exports: true,
            dispatch: crate::DispatchStyle::Trait,
            ..Default::default()
        },
        functions,
        module_calls,
        module_control_flow,
        imports,
        exports: uses.exports(),
        exported_definitions,
        classes: fns.classes.clone(),
        dispatch_contracts: rust_dispatch_contracts(file, &uses),
        dispatch_type_aliases: rust_dispatch_type_aliases(file, &uses),
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |edge| {
        !edge.callee.contains('.') && !edge.callee.contains("::")
    });
    summary
}

// ---------------------------------------------------------------------------
// Summary inference
// ---------------------------------------------------------------------------

fn summarize_all<'a>(
    fns: &RustFunctions<'a>,
    uses: &RustUseResolver,
    value_facts: &HashMap<String, RustValueFacts>,
    value_limits: crate::ValueLimits,
) -> HashMap<String, Summary> {
    let mut out = HashMap::new();
    for name in &fns.order {
        let mut visiting = HashSet::new();
        let _walk = crate::limits::summary_walk();
        let mut nodes = 0u64;
        let s = summarize_fn(
            name,
            fns,
            uses,
            value_facts,
            &mut visiting,
            &mut nodes,
            0,
            value_limits,
        );
        out.insert(name.clone(), s);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn summarize_fn(
    name: &str,
    fns: &RustFunctions,
    _uses: &RustUseResolver,
    all_value_facts: &HashMap<String, RustValueFacts>,
    visiting: &mut HashSet<String>,
    nodes: &mut u64,
    depth: usize,
    value_limits: crate::ValueLimits,
) -> Summary {
    let Some(f) = fns.get(name) else {
        return Summary::pure();
    };
    if depth >= MAX_CALL_DEPTH || !visiting.insert(name.to_string()) {
        let mut summary = Summary::pure();
        summary.boundaries.push(simple_boundary(
            BoundaryReason::UNRESOLVED_CALL,
            BoundaryClass::Unresolved,
            &RUST_DOMAINS,
            "recursive or exhausted call",
        ));
        return summary;
    }
    let value_facts = value_facts_or_default(all_value_facts, name);
    let uses = &f.uses;
    let mut control = ControlStack::default();
    let limits = crate::AnalysisLimits::default();
    control.enter(
        CAPTURE_SOURCE,
        true,
        Default::default(),
        0,
        0,
        None,
        ControlCaps {
            nodes: limits.max_causal_nodes,
            work: limits.max_causal_pairs,
        },
        |graph| control::build(graph, f.body, false),
    );
    let mut sm = Summarizer {
        control,
        value_limits,
        fns,
        uses,
        params: f.params.iter().cloned().collect(),
        cmds: f.command_params(uses),
        closures: HashMap::new(),
        futures: HashMap::new(),
        effects: Vec::new(),
        transfers: Vec::new(),
        boundaries: Vec::new(),
        visiting,
        nodes,
        depth,
        value_facts,
        all_value_facts,
    };
    let env = f.param_env();
    sm.walk_block(f.body, &env);
    let control_flow = sm.leave_control().flow;
    let effects = sm.effects;
    let transfers = sm.transfers;
    let boundaries = sm.boundaries;
    visiting.remove(name);

    let command_candidates_widened = boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "value_widened"
            && boundary.domains.iter().any(|domain| domain.0 == "process")
    });
    let coverage = RUST_DOMAINS
        .iter()
        .map(|d| {
            (
                Domain::new(*d),
                if *d == "process" && command_candidates_widened {
                    CoverageLevel::Partial
                } else {
                    CoverageLevel::Full
                },
            )
        })
        .collect();
    Summary {
        control_flow,
        params: f.params.clone(),
        effects,
        effect_models: Vec::new(),
        transfers,
        returns: value_facts.returns.clone(),
        boundaries,
        coverage,
    }
}

/// Walks a function body accumulating parameterized effects (not emitting to a
/// plan). Local calls inline the callee's summary substituted with the call's
/// argument expressions; a subprocess spawn cannot be composed into a stored
/// summary, so it is recorded as a boundary.
struct Summarizer<'a, 'b> {
    control: ControlStack,
    value_limits: crate::ValueLimits,
    fns: &'a RustFunctions<'a>,
    uses: &'a RustUseResolver,
    params: HashSet<String>,
    /// Names holding a `std::process::Command` (declared parameters and
    /// `let`-bound builder chains), so a split spawn still models.
    cmds: HashSet<String>,
    closures: HashMap<String, RustClosure>,
    futures: HashMap<String, Expr>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    visiting: &'b mut HashSet<String>,
    nodes: &'b mut u64,
    depth: usize,
    value_facts: &'a RustValueFacts,
    all_value_facts: &'a HashMap<String, RustValueFacts>,
}

impl Summarizer<'_, '_> {
    fn leave_control(&mut self) -> crate::control_flow::Finished {
        let finished = self.control.leave(0).expect("Rust summary frame");
        if let Some(limit) = finished.refused {
            let mut boundary = simple_boundary(
                BoundaryReason::LIMIT_SATURATED,
                BoundaryClass::Limit,
                &RUST_DOMAINS,
                "Rust summary control flow widened",
            );
            boundary.limit = Some(limit.to_string());
            self.boundaries.push(boundary);
        }
        finished
    }

    fn walk_block(&mut self, block: &Block, env: &HashMap<String, ResourceExpr>) {
        for stmt in &block.stmts {
            self.walk_stmt(stmt, env);
        }
    }

    fn walk_stmt(&mut self, stmt: &Stmt, env: &HashMap<String, ResourceExpr>) {
        if over_budget(self.nodes) {
            self.partial_nodes();
            return;
        }
        match stmt {
            Stmt::Expr(e, _) => self.walk_expr(e, env),
            Stmt::Local(local @ Local { init: Some(li), .. }) => {
                if let Some(name) = pat_ident(&local.pat) {
                    if let Some(closure) = closure_def(&li.expr) {
                        self.futures.remove(&name);
                        self.closures.insert(name, closure);
                        return;
                    }
                    self.closures.remove(&name);
                    if let Some(future) = bound_future(&li.expr, self.fns, &self.futures) {
                        for argument in future_eager_arguments(&li.expr, self.fns) {
                            self.walk_expr(argument, env);
                        }
                        self.futures.insert(name, future);
                        return;
                    }
                    self.futures.remove(&name);
                    if command_receiver(&li.expr, self.uses, &self.cmds) {
                        self.cmds.insert(name);
                    }
                }
                self.walk_expr(&li.expr, env)
            }
            _ => {}
        }
    }

    fn walk_expr(&mut self, expr: &Expr, env: &HashMap<String, ResourceExpr>) {
        self.walk_expr_at(expr, env, false);
    }

    fn walk_expr_at(
        &mut self,
        expr: &Expr,
        env: &HashMap<String, ResourceExpr>,
        root_awaited: bool,
    ) {
        self.walk_expr_at_state(expr, env, root_awaited, false);
    }

    fn walk_expr_at_state(
        &mut self,
        expr: &Expr,
        env: &HashMap<String, ResourceExpr>,
        root_awaited: bool,
        root_arguments_evaluated: bool,
    ) {
        // Iterative: left-deep `+` / call spines overflow the process stack
        // before the node cap can fire.
        let mut stack = vec![(expr, root_awaited, root_arguments_evaluated)];
        while let Some((expr, awaited, arguments_evaluated)) = stack.pop() {
            if over_budget(self.nodes) {
                self.partial_nodes();
                return;
            }
            match expr {
                Expr::Await(await_) => {
                    if let Some(name) = future_name(&await_.base)
                        && let Some(future) = self.futures.get(&name).cloned()
                    {
                        self.walk_expr_at_state(&future, env, true, true);
                        continue;
                    }
                    stack.push((&await_.base, true, false));
                    continue;
                }
                Expr::Path(_) => {
                    if let Some(name) = future_name(expr)
                        && let Some(future) = self.futures.get(&name).cloned()
                    {
                        self.walk_expr_at_state(&future, env, awaited, true);
                        continue;
                    }
                }
                Expr::Async(async_) if awaited => {
                    self.walk_block(&async_.block, env);
                    continue;
                }
                Expr::Async(_) => {
                    self.boundaries.push(simple_boundary(
                        BoundaryReason::UNRESOLVED_CALL,
                        BoundaryClass::Unresolved,
                        &RUST_DOMAINS,
                        "async block is not known to be polled",
                    ));
                    continue;
                }
                Expr::Closure(_) => continue,
                _ => {}
            }
            let polls_future = polls_future_argument(expr, self.uses);
            if is_indirect_call(expr) {
                self.boundaries.push(simple_boundary(
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    &RUST_DOMAINS,
                    "indirect callable expression cannot be resolved",
                ));
            }
            // Effect calls contribute a parameterized effect; local calls inline a
            // substituted summary; everything else walks children generically.
            if !arguments_evaluated {
                for argument in call_arg_exprs(expr) {
                    if let Expr::Path(path) = argument
                        && let Some(name) = single_ident(&path.path)
                    {
                        if let Some(closure) = self.closures.get(&name).cloned() {
                            self.call_closure(&name, &closure, &[], env);
                        } else if self.fns.get(&name).is_some_and(|f| !f.is_async) {
                            self.inline_local(&name, &[], env, expr);
                        }
                    }
                }
            }
            if let Expr::Call(call) = expr
                && let Some(segments) = path_segments(&call.func)
                && is_known_api(&self.uses.resolve_use_path(&segments))
                && !model::rust_api_has_required_arguments(
                    &self.uses.resolve_use_path(&segments),
                    call.args.len(),
                )
            {
                self.boundaries.push(simple_boundary(
                    BoundaryReason::UNRESOLVED_CALL,
                    BoundaryClass::Unresolved,
                    &RUST_DOMAINS,
                    "unsupported standard-library argument shape",
                ));
            }
            if let Some(handled) = classify_call(expr, self.uses, &self.cmds) {
                let effect_start = self.effects.len();
                let direct_delete = matches!(
                    &handled,
                    CallKind::Fs {
                        operation: "filesystem.delete",
                        ..
                    }
                );
                let mut facts = SiteFacts::unknown();
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
                            arg_resource(arg, &self.params),
                            RustSinkDomain::Filesystem,
                            self.value_limits,
                        );
                        self.effects.push(fs_effect_struct(
                            operation,
                            recursive,
                            resolution.resource.clone(),
                        ));
                        if let Some(give_up) = resolution.give_up {
                            self.boundaries.push(rust_sink_boundary(
                                give_up,
                                "filesystem",
                                resolution.resource,
                                rust_sink_detail(arg, give_up, "filesystem"),
                            ));
                        }
                    }
                    CallKind::Git {
                        operation,
                        field,
                        arg,
                    } => self.effects.push(git_effect_struct(
                        operation,
                        git_resource(arg, &self.params, field),
                    )),
                    CallKind::Env { operation, arg } => {
                        self.effects.push(env_effect_struct(
                            operation,
                            resolve_rust_env_name(arg, self.value_facts, env, self.value_limits),
                        ));
                    }
                    CallKind::Net { arg } => {
                        let resolution = resolve_rust_sink(
                            arg,
                            self.value_facts,
                            env,
                            net_effect_struct(arg, &self.params).resource,
                            RustSinkDomain::Network,
                            self.value_limits,
                        );
                        self.effects
                            .push(base_effect("network.request", resolution.resource.clone()));
                        if let Some(give_up) = resolution.give_up {
                            self.boundaries.push(rust_sink_boundary(
                                give_up,
                                "network",
                                resolution.resource,
                                rust_sink_detail(arg, give_up, "network"),
                            ));
                        }
                    }
                    CallKind::NetAddr { operation, arg } => {
                        let resolution = resolve_rust_sink(
                            arg,
                            self.value_facts,
                            env,
                            net_addr_effect_struct(operation, arg, &self.params).resource,
                            RustSinkDomain::NetworkAddress,
                            self.value_limits,
                        );
                        self.effects
                            .push(base_effect(operation, resolution.resource.clone()));
                        if let Some(give_up) = resolution.give_up {
                            self.boundaries.push(rust_sink_boundary(
                                give_up,
                                "network",
                                resolution.resource,
                                rust_sink_detail(arg, give_up, "network"),
                            ));
                        }
                    }
                    // `std::fs::copy` reads the source and writes the
                    // destination; `std::fs::rename` moves the source entry
                    // instead, under the `filesystem.move` semantic layer.
                    CallKind::Copy { src, dst } | CallKind::Rename { src, dst } => {
                        let rename = matches!(handled, CallKind::Rename { .. });
                        let src_resolution = resolve_rust_sink(
                            src,
                            self.value_facts,
                            env,
                            arg_resource(src, &self.params),
                            RustSinkDomain::Filesystem,
                            self.value_limits,
                        );
                        let dst_resolution = resolve_rust_sink(
                            dst,
                            self.value_facts,
                            env,
                            arg_resource(dst, &self.params),
                            RustSinkDomain::Filesystem,
                            self.value_limits,
                        );
                        if rename {
                            self.effects.push(fs_effect_struct(
                                "filesystem.move",
                                false,
                                src_resolution.resource.clone(),
                            ));
                        }
                        self.effects.push(fs_effect_struct(
                            if rename {
                                "filesystem.delete"
                            } else {
                                "filesystem.read"
                            },
                            false,
                            src_resolution.resource.clone(),
                        ));
                        let source = self.effects.len() as u32 - 1;
                        self.effects.push(fs_effect_struct(
                            "filesystem.write",
                            false,
                            dst_resolution.resource.clone(),
                        ));
                        self.transfers
                            .push(TransferBinding::new(source, self.effects.len() as u32 - 1));
                        for (expr, resolution) in [(src, src_resolution), (dst, dst_resolution)] {
                            if let Some(give_up) = resolution.give_up {
                                self.boundaries.push(rust_sink_boundary(
                                    give_up,
                                    "filesystem",
                                    resolution.resource,
                                    rust_sink_detail(expr, give_up, "filesystem"),
                                ));
                            }
                        }
                    }
                    CallKind::Command { argv } => {
                        // The exec itself is a summary effect; the nested command
                        // analysis cannot compose into a stored summary, so that
                        // remains a boundary.
                        let mut effects = Vec::new();
                        if let Some(commands) = self.value_facts.commands.get(&expr_key(expr)) {
                            let bindings = semantic_bindings(env);
                            let cwd = commands
                                .cwd
                                .as_ref()
                                .map(|cwd| resolve_rust_command_cwd(cwd, env, self.value_limits));
                            effects.extend(commands.values.iter().map(|command| {
                                let command = command
                                    .iter()
                                    .map(|value| {
                                        substitute_value(value, &bindings, self.value_limits)
                                    })
                                    .collect::<Vec<_>>();
                                command_template_effect(
                                    &command,
                                    cwd.as_ref().map(|cwd| cwd.resource.clone()),
                                )
                            }));
                            if let Some(cwd) = cwd
                                && let Some(give_up) = cwd.give_up
                            {
                                self.boundaries.push(rust_sink_boundary(
                                    give_up,
                                    "filesystem",
                                    cwd.resource,
                                    "Command::current_dir value could not be lowered for filesystem"
                                        .to_string(),
                                ));
                            }
                            if commands.widened {
                                effects.push(command_effect(&[Word::new(vec![WordPart::Unknown])]));
                                self.boundaries.push(simple_boundary(
                                    BoundaryReason::VALUE_WIDENED,
                                    BoundaryClass::Unresolved,
                                    &["process"],
                                    "rust command candidates widened",
                                ));
                            }
                        } else {
                            effects.push(command_effect(&argv));
                        }
                        for effect in effects {
                            let mut boundary = simple_boundary(
                                BoundaryReason::UNCOMPOSED_SUBPROCESS,
                                BoundaryClass::Unmodeled,
                                &RUST_DOMAINS,
                                "subprocess spawned inside a summarized function",
                            );
                            boundary.affected_resource = Some(effect.resource.clone());
                            self.effects.push(effect);
                            self.boundaries.push(boundary);
                        }
                    }
                    CallKind::Local { name, args } => {
                        if let Some(closure) = self.closures.get(&name).cloned() {
                            facts = self.call_closure(&name, &closure, &args, env);
                        } else if self
                            .fns
                            .get(&name)
                            .is_some_and(|function| function.is_async)
                            && !awaited
                        {
                            self.boundaries.push(simple_boundary(
                                BoundaryReason::UNRESOLVED_CALL,
                                BoundaryClass::Unresolved,
                                &RUST_DOMAINS,
                                &format!("async function {name:?} is not known to be polled"),
                            ));
                        } else {
                            facts = self.inline_local(&name, &args, env, expr);
                        }
                    }
                }
                if direct_delete {
                    facts = SiteFacts::known(
                        (effect_start..self.effects.len())
                            .map(|slot| ControlFact::Effect(slot as u32))
                            .collect(),
                    );
                }
                self.control
                    .register(CAPTURE_SOURCE, true, control::span(expr), facts);
                let range = expr.span().byte_range();
                let guard = self.uses.guards.at(effinterp_proto::ByteSpan {
                    start: range.start as u32,
                    end: range.end as u32,
                });
                for effect in &mut self.effects[effect_start..] {
                    effect.condition = effinterp_proto::Condition::compose(
                        effect.condition.iter().chain(guard.iter()),
                    );
                }
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
            for child in child_exprs(expr).into_iter().rev() {
                stack.push((child, polls_future, arguments_evaluated));
            }
        }
    }

    fn call_closure(
        &mut self,
        name: &str,
        closure: &RustClosure,
        args: &[&Expr],
        env: &HashMap<String, ResourceExpr>,
    ) -> SiteFacts {
        let marker = format!("closure::{name}");
        if self.visiting.len() >= MAX_CALL_DEPTH || !self.visiting.insert(marker.clone()) {
            self.boundaries.push(simple_boundary(
                BoundaryReason::RECURSIVE_CALL,
                BoundaryClass::Limit,
                &["filesystem", "process"],
                "recursive closure call widened",
            ));
            return SiteFacts::unknown();
        }
        let arg_exprs: Vec<_> = args
            .iter()
            .map(|arg| substitute_resource_expr(&arg_resource(arg, &self.params), env))
            .collect();
        let mut closure_env = env.clone();
        closure_env.extend(bind_positional(&closure.params, &arg_exprs));
        let new_params: Vec<_> = closure
            .params
            .iter()
            .filter(|param| self.params.insert((*param).clone()))
            .cloned()
            .collect();
        let limits = crate::AnalysisLimits::default();
        self.control.enter(
            CAPTURE_SOURCE,
            true,
            Default::default(),
            0,
            0,
            None,
            ControlCaps {
                nodes: limits.max_causal_nodes,
                work: limits.max_causal_pairs,
            },
            |graph| control::build_expr(graph, &closure.body),
        );
        match &closure.body {
            Expr::Block(block) => {
                let caller_cmds = self.cmds.clone();
                let caller_closures = self.closures.clone();
                let caller_futures = self.futures.clone();
                self.walk_block(&block.block, &closure_env);
                self.cmds = caller_cmds;
                self.closures = caller_closures;
                self.futures = caller_futures;
            }
            body => self.walk_expr(body, &closure_env),
        }
        for param in new_params {
            self.params.remove(&param);
        }
        self.visiting.remove(&marker);
        let finished = self.leave_control();
        SiteFacts::call(&finished.requirements, Some)
    }

    fn partial_nodes(&mut self) {
        self.control.widen();
        if self
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "partial_analysis")
        {
            return;
        }
        let mut boundary = simple_boundary(
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &RUST_DOMAINS,
            "rust summary walk node budget exhausted",
        );
        boundary.limit = Some("max_rust_nodes".to_string());
        self.boundaries.push(boundary);
    }

    fn inline_local(
        &mut self,
        name: &str,
        args: &[&Expr],
        env: &HashMap<String, ResourceExpr>,
        site: &Expr,
    ) -> SiteFacts {
        let Some(callee) = self.fns.get(name) else {
            return SiteFacts::unknown();
        };
        if self.depth + 1 >= MAX_CALL_DEPTH || self.visiting.contains(name) {
            self.boundaries.push(simple_boundary(
                BoundaryReason::RECURSIVE_CALL,
                BoundaryClass::Limit,
                &["filesystem", "process"],
                "recursive local call widened",
            ));
            return SiteFacts::unknown();
        }
        // Resolve the call's arguments in the current parameter scope, then
        // apply the callee's summary specialized to them.
        let arg_exprs: Vec<ResourceExpr> = args
            .iter()
            .map(|a| substitute_resource_expr(&call_argument_resource(a, &self.params), env))
            .collect();
        let sub = summarize_fn(
            name,
            self.fns,
            self.uses,
            self.all_value_facts,
            self.visiting,
            self.nodes,
            self.depth + 1,
            self.value_limits,
        );
        let bindings = bind_positional(&callee.params, &arg_exprs);
        let base = self.effects.len() as u32;
        for e in &sub.effects {
            let mut e2 = e.clone();
            if let Some(condition) = &mut e2.condition {
                let range = site.span().byte_range();
                condition.rebind(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.uses.source_id, range.start, range.end),
                ));
            }
            e2.resource = substitute_resource_expr(&e.resource, &bindings);
            let value = SemanticValue::from(&e2.resource);
            crate::lower_effect_value(&mut e2, &value);
            self.effects.push(e2);
        }
        self.transfers
            .extend(sub.transfers.iter().map(|binding| binding.shifted(base)));
        self.boundaries.extend(sub.boundaries.iter().cloned());
        let requirements = self.control.requirements(&sub.control_flow);
        SiteFacts::call(&requirements, |fact| match fact {
            ControlFact::Effect(slot) => Some(ControlFact::Effect(base + slot)),
            ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
        })
    }
}

// ---------------------------------------------------------------------------
// Call-edge collection (for module_summaries)
// ---------------------------------------------------------------------------

/// True-prelude types whose associated calls (`String::new`, `Vec::from`) are
/// std, not repo items — no edge and no boundary when the name has no binding.
const PRELUDE_TYPES: &[&str] = &[
    "String", "Vec", "Box", "Option", "Result", "Some", "None", "Ok", "Err", "Default", "Clone",
    "Copy", "Drop", "From", "Into", "TryFrom", "TryInto", "Iterator", "ToString",
];

/// Per-function scope for edge collection: the impl type (for `Self::`), the
/// declared parameter types, and locals typed by constructor calls (including
/// associated constructors such as `Type::from_args`), explicit annotations,
/// or iteration over a typed collection.
#[derive(Clone, Default)]
struct EdgeScope {
    self_ty: Option<String>,
    params: HashSet<String>,
    param_types: HashMap<String, String>,
    param_receiver_types: HashMap<String, TypeRef>,
    receiver_shadow_types: HashSet<String>,
    var_types: HashMap<String, String>,
    var_receiver_types: HashMap<String, TypeRef>,
    /// Names holding a `std::process::Command`, so their builder chains are
    /// recognized as modeled effect chains rather than dispatch edges.
    cmds: HashSet<String>,
    closures: HashMap<String, RustClosure>,
    futures: HashMap<String, Expr>,
    future_edges: HashMap<String, usize>,
}

impl EdgeScope {
    fn for_fn(f: &RustFunction, uses: &RustUseResolver) -> EdgeScope {
        EdgeScope {
            self_ty: f.impl_type.clone(),
            params: f.params.iter().cloned().collect(),
            param_types: f.param_types.clone(),
            param_receiver_types: f.param_receiver_types.clone(),
            receiver_shadow_types: f.receiver_shadow_types.clone(),
            var_types: HashMap::new(),
            var_receiver_types: HashMap::new(),
            cmds: f.command_params(uses),
            closures: HashMap::new(),
            futures: HashMap::new(),
            future_edges: HashMap::new(),
        }
    }

    /// The class a name is known to hold, from declared parameter types or
    /// typed locals.
    fn type_of(&self, name: &str) -> Option<&String> {
        self.var_types
            .get(name)
            .or_else(|| self.param_types.get(name))
    }

    fn receiver_type_of(&self, name: &str) -> Option<&TypeRef> {
        self.var_receiver_types
            .get(name)
            .or_else(|| self.param_receiver_types.get(name))
    }
}

/// Collects a function's outgoing call edges: cross-file function calls,
/// `Type::method` static calls, and method calls with their receiver typing —
/// the substrate the repo layer dispatches at composition time. A same-file
/// bare call does not add an edge (its in-file effects are already inlined
/// into the summary), but its body IS walked so a cross-file call reached only
/// THROUGH a local helper still surfaces on the calling function's edge set.
struct EdgeCollector<'a, 'b> {
    uses: &'a RustUseResolver,
    fns: &'a RustFunctions<'a>,
    out: &'b mut Vec<CallEdge>,
    sites: &'b mut BTreeMap<crate::control_flow::Span, u32>,
    synth: &'b mut Vec<ImportBinding>,
    nodes: &'b mut u64,
    visited: HashSet<String>,
    value_facts: &'a RustValueFacts,
    all_value_facts: &'a HashMap<String, RustValueFacts>,
}

impl EdgeCollector<'_, '_> {
    fn walk_block(&mut self, block: &Block, scope: &mut EdgeScope) {
        for stmt in &block.stmts {
            if over_budget(self.nodes) {
                return;
            }
            match stmt {
                Stmt::Expr(e, _) => self.walk_expr(e, scope, None),
                Stmt::Local(local @ Local { init: Some(li), .. }) => {
                    let bind = pat_ident(&local.pat);
                    if let Some(name) = &bind {
                        scope.futures.remove(name);
                        scope.future_edges.remove(name);
                        if let Some(closure) = closure_def(&li.expr) {
                            scope.closures.insert(name.clone(), closure);
                            continue;
                        }
                        scope.closures.remove(name);
                        if let Some(future) = bound_future(&li.expr, self.fns, &scope.futures) {
                            for argument in future_eager_arguments(&li.expr, self.fns) {
                                self.walk_expr(argument, scope, None);
                            }
                            scope.futures.insert(name.clone(), future);
                            continue;
                        }
                        // `let x: T = ...` annotation, or a constructor call
                        // (`Type::new` / `Type::from_args`, wrappers peeled).
                        scope.var_receiver_types.remove(name);
                        if let Pat::Type(pt) = &local.pat
                            && let Some(t) = base_type_ident(&pt.ty)
                        {
                            scope.var_types.insert(name.clone(), t);
                        } else if let Some(t) =
                            ctor_type(&li.expr, self.uses, scope, Some(self.fns))
                        {
                            scope.var_types.insert(name.clone(), t);
                        }
                        if let Pat::Type(pt) = &local.pat {
                            if let Some(ty) =
                                receiver_type_ref(&pt.ty, self.uses, &scope.receiver_shadow_types)
                            {
                                scope.var_receiver_types.insert(name.clone(), ty);
                            }
                        } else if let Some(ty) = constructor_receiver_type(
                            &li.expr,
                            self.uses,
                            &scope.receiver_shadow_types,
                        ) {
                            scope.var_receiver_types.insert(name.clone(), ty);
                        }
                        if command_receiver(&li.expr, self.uses, &scope.cmds) {
                            scope.cmds.insert(name.clone());
                        }
                    }
                    let edge_start = self.out.len();
                    self.walk_expr(&li.expr, scope, bind.as_deref());
                    if let Some(name) = bind
                        && let Some(offset) = self.out[edge_start..].iter().position(|edge| {
                            edge.result_bindings().any(|(_, binding)| binding == name)
                        })
                    {
                        scope.future_edges.insert(name, edge_start + offset);
                    }
                }
                _ => {}
            }
        }
    }

    fn walk_expr(&mut self, expr: &Expr, scope: &mut EdgeScope, bind: Option<&str>) {
        self.walk_expr_at(expr, scope, bind, 0, false);
    }

    fn walk_call_arg(&mut self, expr: &Expr, scope: &mut EdgeScope, polled: bool) {
        match closure_expr(expr) {
            Some(closure) => self.walk_expr(&closure.body, scope, None),
            None => self.walk_expr_at(expr, scope, None, 0, polled),
        }
    }

    fn walk_expr_at(
        &mut self,
        expr: &Expr,
        scope: &mut EdgeScope,
        bind: Option<&str>,
        depth: u32,
        awaited: bool,
    ) {
        self.walk_expr_at_state(expr, scope, bind, depth, awaited, false);
    }

    fn walk_expr_at_state(
        &mut self,
        expr: &Expr,
        scope: &mut EdgeScope,
        bind: Option<&str>,
        depth: u32,
        awaited: bool,
        arguments_evaluated: bool,
    ) {
        let start = self.out.len();
        self.walk_expr_at_state_inner(expr, scope, bind, depth, awaited, arguments_evaluated);
        let range = expr.span().byte_range();
        let guard = self.uses.guards.at(effinterp_proto::ByteSpan {
            start: range.start as u32,
            end: range.end as u32,
        });
        let single = self.out.len() == start + 1;
        for (offset, edge) in self.out[start..].iter_mut().enumerate() {
            edge.condition =
                effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
            if edge.call_site.is_none() {
                if single && matches!(expr, Expr::Call(_) | Expr::MethodCall(_)) {
                    self.sites
                        .insert(control::span(expr), (start + offset) as u32);
                }
                edge.call_site = Some(effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.uses.source_id, range.start, range.end),
                ));
            }
        }
    }

    fn walk_expr_at_state_inner(
        &mut self,
        expr: &Expr,
        scope: &mut EdgeScope,
        bind: Option<&str>,
        depth: u32,
        awaited: bool,
        arguments_evaluated: bool,
    ) {
        if over_budget(self.nodes) || depth >= MAX_WALK_DEPTH {
            return;
        }
        match expr {
            // Wrappers pass the bind through to the underlying call.
            Expr::Try(t) => {
                return self.walk_expr_at_state(
                    &t.expr,
                    scope,
                    bind,
                    depth + 1,
                    awaited,
                    arguments_evaluated,
                );
            }
            Expr::Paren(p) => {
                return self.walk_expr_at_state(
                    &p.expr,
                    scope,
                    bind,
                    depth + 1,
                    awaited,
                    arguments_evaluated,
                );
            }
            Expr::Reference(r) => {
                return self.walk_expr_at_state(
                    &r.expr,
                    scope,
                    bind,
                    depth + 1,
                    awaited,
                    arguments_evaluated,
                );
            }
            Expr::Await(a) => {
                if let Some(name) = future_name(&a.base) {
                    if let Some(future) = scope.futures.get(&name).cloned() {
                        return self.walk_expr_at_state(
                            &future,
                            scope,
                            bind,
                            depth + 1,
                            true,
                            true,
                        );
                    }
                    if let Some(index) = scope.future_edges.get(&name).copied() {
                        let edge = &mut self.out[index];
                        edge.awaited = true;
                        if let Some(binding) = bind {
                            for result in &mut edge.results {
                                if result.index == 0 {
                                    result.binding = Some(binding.to_string());
                                }
                            }
                        }
                        return;
                    }
                }
                return self.walk_expr_at(&a.base, scope, bind, depth + 1, true);
            }
            Expr::Path(_) => {
                if let Some(name) = future_name(expr)
                    && let Some(future) = scope.futures.get(&name).cloned()
                {
                    return self.walk_expr_at_state(&future, scope, bind, depth + 1, awaited, true);
                }
                if awaited
                    && let Some(name) = future_name(expr)
                    && let Some(index) = scope.future_edges.get(&name).copied()
                {
                    let edge = &mut self.out[index];
                    edge.awaited = true;
                    if let Some(binding) = bind {
                        for result in &mut edge.results {
                            if result.index == 0 {
                                result.binding = Some(binding.to_string());
                            }
                        }
                    }
                    return;
                }
            }
            Expr::Async(async_) if awaited => {
                self.walk_block(&async_.block, scope);
                return;
            }
            Expr::Async(_) | Expr::Closure(_) => return,
            Expr::Call(c) => {
                if let Some(segs) = path_segments(&c.func) {
                    self.path_call(c, &segs, scope, bind, awaited);
                    if !arguments_evaluated {
                        let polled = polls_future_argument(expr, self.uses);
                        for a in &c.args {
                            self.walk_call_arg(a, scope, polled);
                        }
                    }
                    return;
                }
            }
            Expr::MethodCall(m) => {
                self.method_call(m, scope, bind, awaited);
                return;
            }
            // Nested blocks (match/if arms) must type their `let` locals so a
            // `let exa = Exa { .. }; exa.run()` inside `Ok(options) => { .. }`
            // still constructs a typed receiver.
            Expr::Block(b) => {
                self.walk_block(&b.block, scope);
                return;
            }
            Expr::Unsafe(u) => {
                self.walk_block(&u.block, scope);
                return;
            }
            Expr::If(i) => {
                self.walk_expr_at(&i.cond, scope, None, depth + 1, false);
                self.walk_block(&i.then_branch, scope);
                if let Some((_, else_e)) = &i.else_branch {
                    self.walk_expr_at(else_e, scope, None, depth + 1, false);
                }
                return;
            }
            Expr::Match(m) => {
                let preserves_scrutinee = match_preserves_scrutinee(m, &self.fns.unit_variants);
                let selected = (!preserves_scrutinee)
                    .then(|| cross_file_value_call_key(expr, self.fns, self.uses))
                    .flatten();
                self.walk_expr_at(
                    &m.expr,
                    scope,
                    preserves_scrutinee.then_some(bind).flatten(),
                    depth + 1,
                    false,
                );
                for arm in &m.arms {
                    let arm_bind = selected
                        .filter(|selected| {
                            cross_file_value_call_key(&arm.body, self.fns, self.uses)
                                == Some(*selected)
                        })
                        .and(bind);
                    self.walk_expr_at(&arm.body, scope, arm_bind, depth + 1, false);
                }
                return;
            }
            // Iterating a typed collection types the loop variable
            // (`for input in inputs` with `inputs: Vec<Input>`).
            Expr::ForLoop(f) => {
                if let Some(var) = pat_ident(&f.pat)
                    && let Some(src) = chain_base_ident(&f.expr)
                    && let Some(t) = scope.type_of(&src).cloned()
                {
                    scope.var_types.insert(var, t);
                }
                self.walk_expr_at(&f.expr, scope, None, depth + 1, false);
                for e in block_exprs(&f.body) {
                    self.walk_expr_at(e, scope, None, depth + 1, false);
                }
                return;
            }
            _ => {}
        }
        for child in child_exprs(expr) {
            self.walk_expr_at_state(child, scope, None, depth + 1, false, arguments_evaluated);
        }
    }

    /// A `path(...)` call: a bare local/cross-file function, a `Type::method`
    /// static call, or a module-qualified function.
    fn path_call(
        &mut self,
        c: &syn::ExprCall,
        segs: &[String],
        scope: &mut EdgeScope,
        bind: Option<&str>,
        awaited: bool,
    ) {
        let resolved = self.uses.resolve_use_path(segs);
        if is_known_api(&resolved)
            && model::rust_api_has_required_arguments(&resolved, c.args.len())
        {
            return; // modeled effect: already in the summary, never an edge
        }
        let rsegs: Vec<&str> = resolved.split("::").collect();
        if matches!(rsegs[0], "std" | "core" | "alloc") {
            if rsegs
                .iter()
                .all(|s| !s.chars().next().is_some_and(char::is_uppercase))
                || !matches!(
                    crate::external::classify_rust_call(&resolved),
                    Some(crate::external::ExternalCall::Inert)
                )
            {
                let fn_name = (*rsegs.last().unwrap()).to_string();
                self.synth.push(ImportBinding {
                    local: fn_name.clone(),
                    module: resolved.clone(),
                    imported: Some(fn_name.clone()),
                });
                self.out.push(CallEdge {
                    callee: fn_name,
                    awaited,
                    ..Default::default()
                });
            }
            return;
        }
        let args: Vec<&Expr> = c.args.iter().collect();
        if segs.len() == 1 && rsegs.len() == 1 {
            let name = &segs[0];
            if let Some(closure) = scope.closures.get(name).cloned() {
                let marker = format!("closure::{name}");
                if self.visited.len() >= MAX_CALL_DEPTH || !self.visited.insert(marker.clone()) {
                    return;
                }
                let mut inner = scope.clone();
                for (param, argument) in closure.params.iter().zip(&c.args) {
                    if let Some(base) = chain_base_ident(argument)
                        && let Some(typ) = scope.type_of(&base).cloned()
                    {
                        inner.var_types.insert(param.clone(), typ);
                    }
                }
                self.walk_expr(&closure.body, &mut inner, bind);
                self.visited.remove(&marker);
            } else if let Some(def) = self.fns.get(name) {
                // Same-file helper: descend so its cross-file edges propagate.
                if (!def.is_async || awaited) && self.visited.insert(name.clone()) {
                    let caller_uses = std::mem::replace(&mut self.uses, &def.uses);
                    let mut inner = EdgeScope::for_fn(def, &def.uses);
                    let caller_facts = std::mem::replace(
                        &mut self.value_facts,
                        value_facts_or_default(self.all_value_facts, name),
                    );
                    self.walk_block(def.body, &mut inner);
                    self.value_facts = caller_facts;
                    self.uses = caller_uses;
                }
            } else if !is_effectless_rust_call(name) && !PRELUDE_TYPES.contains(&name.as_str()) {
                let result = self.value_facts.expressions.get(&span_key(c)).cloned();
                self.edge(name.clone(), &args, None, scope, bind, awaited, result);
            }
            return;
        }
        // The first uppercase segment splits the path into module / type.
        let type_pos = rsegs
            .iter()
            .position(|s| s.chars().next().is_some_and(char::is_uppercase));
        match type_pos {
            Some(p) if p + 1 == rsegs.len() - 1 => {
                let method = rsegs[p + 1];
                if method.chars().next().is_some_and(char::is_uppercase) {
                    return; // `Enum::Variant(..)`: a value constructor, inert
                }
                // Prefer the call-site type ident so `use theme::Options as
                // ThemeOptions; ThemeOptions::deduce()` stays ThemeOptions
                // and does not collide with a same-named local `Options`.
                let type_name = if rsegs[p] == "Self" || segs.iter().any(|s| s == "Self") {
                    match &scope.self_ty {
                        Some(t) => t.clone(),
                        None => return,
                    }
                } else if let Some(local) = segs
                    .iter()
                    .rev()
                    .nth(1)
                    .filter(|s| s.chars().next().is_some_and(char::is_uppercase))
                {
                    local.clone()
                } else {
                    rsegs[p].to_string()
                };
                // An unbound prelude type (`String::new`) is std, not repo.
                if p == 0 && resolved == segs.join("::") && PRELUDE_TYPES.contains(&rsegs[0]) {
                    return;
                }
                if p > 0 && !self.uses.is_imported(&type_name) {
                    self.synth.push(ImportBinding {
                        local: type_name.clone(),
                        module: rsegs[..=p].join("::"),
                        imported: Some(rsegs[p].to_string()),
                    });
                }
                self.edge(
                    format!("{type_name}.{method}"),
                    &args,
                    None,
                    scope,
                    bind,
                    awaited,
                    self.value_facts.expressions.get(&span_key(c)).cloned(),
                );
            }
            Some(_) => {} // deeper nested type path: not resolvable
            None => {
                // All-lowercase module path (`crate::util::wipe`,
                // `pager::get_pager`): record the bare function name and
                // synthesize a whole-path import for `resolve_rust`.
                let fn_name = (*rsegs.last().unwrap()).to_string();
                self.synth.push(ImportBinding {
                    local: fn_name.clone(),
                    module: resolved.clone(),
                    imported: Some(fn_name.clone()),
                });
                self.edge(
                    fn_name,
                    &args,
                    None,
                    scope,
                    bind,
                    awaited,
                    self.value_facts.expressions.get(&span_key(c)).cloned(),
                );
            }
        }
    }

    /// A `recv.method(...)` call: typed receivers dispatch at composition time;
    /// modeled builder chains (Command spawns, OpenOptions opens) and pure
    /// adapters record nothing.
    fn method_call(
        &mut self,
        m: &syn::ExprMethodCall,
        scope: &mut EdgeScope,
        bind: Option<&str>,
        awaited: bool,
    ) {
        let method = m.method.to_string();
        let effect_chain = (matches!(
            method.as_str(),
            "arg"
                | "args"
                | "env"
                | "envs"
                | "env_clear"
                | "current_dir"
                | "stdin"
                | "stdout"
                | "stderr"
                | "spawn"
                | "output"
                | "status"
        ) && command_receiver(&m.receiver, self.uses, &scope.cmds))
            || (method == "open" && open_options_mode(&m.receiver, self.uses).is_some());
        // A closure argument on a typed chain base carries the base's element
        // type into the closure's single parameter (`preprocessors.iter()
        // .try_for_each(|p| ...)`, `config.and_then(|config| ...)`).
        if let Some(base) = chain_base_ident(&m.receiver)
            && let Some(t) = scope.type_of(&base).cloned()
        {
            for a in &m.args {
                if let Expr::Closure(cl) = a
                    && cl.inputs.len() == 1
                    && let Some(p) = pat_ident(&cl.inputs[0])
                {
                    scope.var_types.insert(p, t.clone());
                }
            }
        }
        let pass_through = PEEL_METHODS.contains(&method.as_str());
        if !effect_chain {
            let args: Vec<&Expr> = m.args.iter().collect();
            let recv = receiver_ref(&m.receiver, scope, self.uses, self.fns);
            match recv {
                Some((label, instance)) => {
                    self.edge(
                        format!("{label}.{method}"),
                        &args,
                        Some(instance),
                        scope,
                        bind,
                        awaited,
                        self.value_facts.expressions.get(&span_key(m)).cloned(),
                    );
                }
                None => {
                    // Retain the unresolved edge for an explicit boundary;
                    // its unknown receiver cannot activate a dispatch target.
                    self.edge(
                        format!("?.{method}"),
                        &args,
                        Some(SemanticValue::object(ObjectIdentity::Local {
                            name: "?".to_string(),
                            fallback: None,
                        })),
                        scope,
                        bind,
                        awaited,
                        self.value_facts.expressions.get(&span_key(m)).cloned(),
                    );
                }
            }
        }
        self.walk_expr(&m.receiver, scope, pass_through.then_some(bind).flatten());
        for a in &m.args {
            self.walk_call_arg(a, scope, false);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn edge(
        &mut self,
        callee: String,
        args: &[&Expr],
        receiver: Option<SemanticValue>,
        scope: &EdgeScope,
        bind: Option<&str>,
        awaited: bool,
        result: Option<SemanticValue>,
    ) {
        let arg_exprs: Vec<_> = args
            .iter()
            .map(|argument| {
                let resource = SemanticValue::from(arg_resource(argument, &scope.params));
                if is_unresolved_value(&resource) {
                    self.value_facts
                        .expressions
                        .get(&expr_key(argument))
                        .cloned()
                        .unwrap_or(resource)
                } else {
                    resource
                }
            })
            .collect();
        let mut arguments = positional_arguments(arg_exprs);
        let objects = obj_args(args, scope, self.uses, self.fns)
            .into_iter()
            .filter(|object| {
                arguments
                    .iter()
                    .find(|argument| argument.index == object.index && argument.name == object.name)
                    .is_none_or(|argument| is_unresolved_value(&argument.value))
            })
            .collect();
        merge_arguments(&mut arguments, objects);
        let mut results = call_results(
            bind.map(|value| vec![(0, value.to_string())])
                .unwrap_or_default(),
            None,
            None,
        );
        if let Some(result) = result.filter(|value| !is_unresolved_value(value))
            && let Some(first) = results.first_mut()
        {
            first.value = result;
        }
        self.out.push(CallEdge {
            callee,
            arguments,
            awaited,
            receiver,
            results,
            ..Default::default()
        });
    }
}

/// Associated functions that construct `Type` (`Type::new`, `Type::from_args`,
/// `Type::deduce`). A same-file return type is authoritative and wins over
/// this name list; a helper like `Type::filename() -> String` must not type
/// the local as `Type`.
fn is_assoc_ctor(method: &str) -> bool {
    matches!(
        method,
        "new" | "default" | "parse" | "create" | "build" | "deduce" | "from"
    ) || method.starts_with("from_")
        || method.starts_with("try_from")
        || method.starts_with("with_")
}

fn constructor_receiver_type(
    expr: &Expr,
    uses: &RustUseResolver,
    class_names: &HashSet<String>,
) -> Option<TypeRef> {
    match expr {
        Expr::Try(try_) => constructor_receiver_type(&try_.expr, uses, class_names),
        Expr::Paren(paren) => constructor_receiver_type(&paren.expr, uses, class_names),
        Expr::Reference(reference) => constructor_receiver_type(&reference.expr, uses, class_names),
        Expr::MethodCall(method) if PEEL_METHODS.contains(&method.method.to_string().as_str()) => {
            constructor_receiver_type(&method.receiver, uses, class_names)
        }
        Expr::Call(call) => {
            let segments = path_segments(&call.func)?;
            let method = segments.last()?;
            if segments.len() < 2 || !is_assoc_ctor(method) {
                return None;
            }
            receiver_type_ref_from_path(&segments[..segments.len() - 1], uses, class_names)
        }
        _ => None,
    }
}

/// The class an initializer expression constructs, for typing a `let` local:
/// a struct literal, a same-file associated function that returns the type,
/// or a cross-file associated constructor (`Type::new` / `Type::from_args`).
/// `Self` resolves to the enclosing impl type. Wrappers are peeled.
fn ctor_type(
    expr: &Expr,
    uses: &RustUseResolver,
    scope: &EdgeScope,
    fns: Option<&RustFunctions>,
) -> Option<String> {
    match expr {
        Expr::Try(t) => ctor_type(&t.expr, uses, scope, fns),
        Expr::Paren(p) => ctor_type(&p.expr, uses, scope, fns),
        Expr::Reference(r) => ctor_type(&r.expr, uses, scope, fns),
        Expr::Await(a) => ctor_type(&a.base, uses, scope, fns),
        Expr::MethodCall(m) if PEEL_METHODS.contains(&m.method.to_string().as_str()) => {
            ctor_type(&m.receiver, uses, scope, fns)
        }
        Expr::Struct(s) => {
            let t = s.path.segments.last()?.ident.to_string();
            (!PRELUDE_TYPES.contains(&t.as_str())).then_some(t)
        }
        Expr::Call(c) => {
            let segs = path_segments(&c.func)?;
            let (head, method) = match segs.len() {
                2 => (segs[0].as_str(), segs[1].as_str()),
                n if n > 2 => (segs[n - 2].as_str(), segs[n - 1].as_str()),
                _ => return None,
            };
            if method.chars().next().is_some_and(char::is_uppercase) {
                return None; // `Enum::Variant(...)`
            }
            let type_name = if head == "Self" {
                scope.self_ty.clone()?
            } else {
                head.to_string()
            };
            if !type_name.chars().next().is_some_and(char::is_uppercase)
                || PRELUDE_TYPES.contains(&type_name.as_str())
                || uses.resolve_use_path(&segs).starts_with("std::")
            {
                return None;
            }
            if let Some(fns) = fns {
                let key = format!("{type_name}.{method}");
                if let Some(ret) = fns.get(&key).and_then(|d| d.ret_class.clone()) {
                    return Some(ret);
                }
                if fns.get(&key).is_some() {
                    return None; // same-file, known not to return the type
                }
            }
            is_assoc_ctor(method).then_some(type_name)
        }
        _ => None,
    }
}

/// How a method receiver refers to an instance, when its provenance is
/// unambiguous: `self`, a declared/typed name, `self.attr`, `var.attr`, or a
/// direct `Type::new(...)` constructor chain. None for opaque receivers.
fn receiver_type_name(ty: &TypeRef) -> String {
    match ty {
        TypeRef::Repo { name, .. } => name.clone(),
        TypeRef::External { path } => path
            .rsplit("::")
            .find(|part| !part.is_empty())
            .unwrap_or(path)
            .to_string(),
    }
}

fn receiver_ref(
    expr: &Expr,
    scope: &EdgeScope,
    uses: &RustUseResolver,
    fns: &RustFunctions<'_>,
) -> Option<(String, SemanticValue)> {
    match expr {
        Expr::Try(t) => {
            let (label, mut receiver) = receiver_ref(&t.expr, scope, uses, fns)?;
            receiver.evidence.ty = None;
            Some((label, receiver))
        }
        Expr::Paren(p) => receiver_ref(&p.expr, scope, uses, fns),
        Expr::Reference(r) => receiver_ref(&r.expr, scope, uses, fns),
        // A pass-through adapter keeps the receiver's identity
        // (`commit.clone().preprocess(..)`).
        Expr::MethodCall(m) if PEEL_METHODS.contains(&m.method.to_string().as_str()) => {
            let (label, mut receiver) = receiver_ref(&m.receiver, scope, uses, fns)?;
            if peels_outer_receiver_type(&m.method.to_string()) {
                receiver.evidence.ty = None;
            }
            Some((label, receiver))
        }
        Expr::Path(p) => {
            let name = single_ident(&p.path)?;
            if name == "self" {
                return Some((
                    "self".to_string(),
                    SemanticValue::object(ObjectIdentity::Receiver),
                ));
            }
            if let Some(t) = scope.type_of(&name) {
                return Some((
                    t.clone(),
                    SemanticValue::object(ObjectIdentity::Class {
                        name: t.clone(),
                        constructor: Vec::new(),
                    })
                    .with_type(scope.receiver_type_of(&name).cloned()),
                ));
            }
            if let Some(ty) = scope.receiver_type_of(&name) {
                let label = receiver_type_name(ty);
                return Some((
                    label.clone(),
                    SemanticValue::object(ObjectIdentity::Class {
                        name: label,
                        constructor: Vec::new(),
                    })
                    .with_type(Some(ty.clone())),
                ));
            }
            if scope.cmds.contains(&name) {
                return Some((
                    "Command".to_string(),
                    SemanticValue::object(ObjectIdentity::Class {
                        name: "Command".to_string(),
                        constructor: Vec::new(),
                    })
                    .with_type(Some(TypeRef::External {
                        path: "std::process::Command".to_string(),
                    })),
                ));
            }
            if scope.params.contains(&name) {
                return Some((
                    name.clone(),
                    SemanticValue::object(ObjectIdentity::Parameter {
                        name,
                        fallback: None,
                    }),
                ));
            }
            Some((
                name.clone(),
                SemanticValue::object(ObjectIdentity::Local {
                    name,
                    fallback: None,
                }),
            ))
        }
        Expr::Field(f) => {
            let attr = match &f.member {
                syn::Member::Named(id) => id.to_string(),
                syn::Member::Unnamed(_) => return None,
            };
            match &*f.base {
                Expr::Path(p) => {
                    let base = single_ident(&p.path)?;
                    let receiver_type = if base == "self" {
                        scope.self_ty.as_ref().and_then(|class| {
                            fns.class_receiver_types
                                .get(class)
                                .and_then(|fields| fields.get(&attr))
                                .cloned()
                        })
                    } else {
                        scope.type_of(&base).and_then(|class| {
                            fns.class_receiver_types
                                .get(class)
                                .and_then(|fields| fields.get(&attr))
                                .cloned()
                        })
                    };
                    if base == "self" {
                        Some((
                            format!("self.{attr}"),
                            SemanticValue::object(ObjectIdentity::ReceiverProperty(attr))
                                .with_type(receiver_type),
                        ))
                    } else {
                        Some((
                            format!("{base}.{attr}"),
                            SemanticValue::object(ObjectIdentity::LocalProperty {
                                name: base,
                                property: attr,
                            })
                            .with_type(receiver_type),
                        ))
                    }
                }
                _ => None,
            }
        }
        // `Type::new(a, b).method(...)`: the receiver is a fresh instance.
        Expr::Call(c) => {
            let segs = path_segments(&c.func)?;
            if segs.len() < 2 || !is_assoc_ctor(segs.last()?) {
                return None;
            }
            let type_path = &segs[..segs.len() - 1];
            let head = type_path.last()?;
            let t = if head == "Self" {
                scope.self_ty.clone()?
            } else if head.chars().next().is_some_and(char::is_uppercase) {
                head.clone()
            } else {
                return None;
            };
            let receiver_type =
                receiver_type_ref_from_path(type_path, uses, &scope.receiver_shadow_types);
            Some((
                t.clone(),
                SemanticValue::object(ObjectIdentity::Class {
                    name: t,
                    constructor: Vec::new(),
                })
                .with_type(receiver_type),
            ))
        }
        _ => None,
    }
}

/// Call arguments that carry a typed instance into the callee, by positional
/// index: `self`, typed names, `self.attr`, and direct constructors.
fn obj_args(
    args: &[&Expr],
    scope: &EdgeScope,
    uses: &RustUseResolver,
    fns: &RustFunctions<'_>,
) -> Vec<ValueArgument> {
    args.iter()
        .enumerate()
        .filter_map(|(index, a)| {
            let (_, instance) = receiver_ref(a, scope, uses, fns)?;
            // A bare untyped Var argument carries no typing worth recording.
            if matches!(
                instance.as_object().map(|object| &object.identity),
                Some(ObjectIdentity::Local { name, .. }) if name == "?"
            ) {
                return None;
            }
            Some(ValueArgument {
                name: None,
                index,
                value: instance,
            })
        })
        .collect()
}
