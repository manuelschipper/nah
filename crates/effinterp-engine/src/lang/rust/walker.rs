//! Rust execution walk, grounded in the functions reached from main.

use std::collections::{HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ExecutionEdgeKind, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};
use syn::spanned::Spanned;
use syn::{Block, Expr, Item, Local, Stmt};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::SiteFacts;
use crate::lang::frontend::{FrontendInput, WalkOutcome};
use crate::nest::{Nest, Transition, word_resource};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::{bind_positional, substitute_resource_expr};
use crate::word::{Word, WordPart};
use crate::{SemanticValue, SemanticValueKind, substitute_value, substitute_value_counted};

use super::call_resolution::{
    RustFunctions, RustUseResolver, collect_rust_functions, is_effectless_rust_call,
};
use super::control::{self, has_drop_impl};
use super::deferred_calls::{
    RustClosure, bound_future, closure_def, future_eager_arguments, future_name,
};
use super::macros::record_unexpanded_includes;
use super::model::{
    self, CallKind, RustSinkDomain, RustSinkGiveUp, RustSinkResolution, arg_resource, base_effect,
    call_argument_resource, classify_call, command_effect, command_receiver, env_effect_struct,
    fs_effect_struct, git_effect_struct, git_resource, is_indirect_call, net_addr_effect_struct,
    net_effect_struct, polls_future_argument, resolve_rust_command_cwd, resolve_rust_env_name,
    resolve_rust_sink, rust_sink_boundary, rust_sink_detail, semantic_bindings, semantic_word,
};
use super::syntax::{
    call_arg_exprs, child_exprs, closure_expr, pat_ident, path_segments, single_ident,
};
use super::value_facts::{
    RustValueFacts, expr_key, rust_value_facts_counted, value_facts_or_default,
};
use super::{MAX_CALL_DEPTH, RUST_DOMAINS, simple_boundary};

/// Walk only effects reachable from Rust main. A library without main exposes callable summaries.
pub(super) fn walk_rust_file(
    builder: &mut PlanBuilder,
    nest: &Nest,
    input: &FrontendInput,
    file: &syn::File,
) -> WalkOutcome {
    let source = input.source;
    let cwd = input.runtime_cwd;
    let cwd_node = input.cwd_node;
    let scope = input.scope;
    let depth = input.depth;
    if builder.current_execution_is_launched_source() {
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

    let uses = RustUseResolver::from_file(file, source);
    let fns = collect_rust_functions(file, &uses);
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
        let mut ex = RustWalker {
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
    let declared_callables =
        if !fns.order.is_empty() && !has_execution_root && builder.effects_len() == first_effect {
            fns.order.clone()
        } else {
            Vec::new()
        };
    for domain in RUST_DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    WalkOutcome { declared_callables }
}

/// A resolved same-file callee: its path, the argument expressions, and the
/// receiver's field bindings when the call goes through a value.
type InFileCall<'b> = (String, Vec<&'b Expr>, Option<HashMap<String, ResourceExpr>>);

struct RustWalker<'a> {
    builder: &'a mut PlanBuilder,
    source: &'a str,
    nest: &'a Nest<'a>,
    uses: &'a RustUseResolver,
    fns: &'a RustFunctions<'a>,
    cwd: Option<&'a str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    nodes: u64,
    /// Functions currently on the execution stack, so recursion terminates.
    visiting: HashSet<String>,
    closures: HashMap<String, RustClosure>,
    futures: HashMap<String, Expr>,
    receiver_types: HashMap<String, String>,
    receiver_fields: HashMap<String, HashMap<String, ResourceExpr>>,
    value_facts: &'a RustValueFacts,
    all_value_facts: &'a HashMap<String, RustValueFacts>,
}

impl RustWalker<'_> {
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
                && self.uses.resolve_use_path(&segments).starts_with("std::")
                && !matches!(
                    crate::external::classify_rust_call(&self.uses.resolve_use_path(&segments)),
                    Some(crate::external::ExternalCall::Inert)
                )
                && !(matches!(
                    self.uses.resolve_use_path(&segments).as_str(),
                    "std::process::Command::new"
                        | "std::fs::OpenOptions::new"
                        | "std::fs::File::options"
                ) && model::rust_api_has_required_arguments(
                    &self.uses.resolve_use_path(&segments),
                    call.args.len(),
                ))
            {
                self.unresolved(&self.uses.resolve_use_path(&segments));
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
                && !is_effectless_rust_call(segments.last().map(String::as_str).unwrap_or_default())
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
        closure: &RustClosure,
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
            let resolved = self.uses.resolve_use_path(&[name.to_string()]);
            if resolved.starts_with("std::") {
                if !matches!(
                    crate::external::classify_rust_call(&resolved),
                    Some(crate::external::ExternalCall::Inert)
                ) {
                    self.unresolved(&resolved);
                }
            } else if !is_effectless_rust_call(name) && !self.uses.is_imported(name) {
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

fn empty() -> HashSet<String> {
    HashSet::new()
}
