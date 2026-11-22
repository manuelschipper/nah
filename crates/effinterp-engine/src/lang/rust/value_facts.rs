//! Rust value facts shared by the execution and summary walks.

mod command_candidates;
mod loop_widening;
mod pattern_bindings;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Expr, Stmt};

use crate::{
    CallableValue, ObjectIdentity, ObjectValue, SemanticValue, SemanticValueKind, TypeRef,
    ValueLimits, canonical_rust_std_type, join_branches, property_access, substitute_value_counted,
};

pub(super) use self::command_candidates::command_method_preserves_executable_and_argv;
use self::command_candidates::{
    RustCommandCandidates, append_command_argument, append_command_arguments,
    bound_command_chain_appends_arguments, command_marker, dedup_commands,
    invalidate_command_alias_source, merge_command_cwds,
};
use self::loop_widening::{widen_loop_facts, widen_loop_state};
pub(super) use self::pattern_bindings::match_preserves_scrutinee;
use self::pattern_bindings::{
    bind_rust_pattern, bind_unknown_patterns, restore_scope_bindings, rust_pattern_binding_names,
    rust_pattern_match_is_ambiguous, save_pattern_bindings,
};
use super::call_resolution::dispatch_types::PEEL_METHODS;
use super::call_resolution::{RustFunctions, RustUseResolver, is_effectless_rust_call};
use super::deferred_calls::future_name;
use super::model::{is_known_api, rust_unwalked_call_value};
use super::syntax::{
    chain_base_ident, child_exprs, closure_expr, is_compound_assignment, mutated_base_ident,
    pat_ident, path_segments, single_ident, str_lit,
};
use super::{DEFAULT_MAX_RUST_NODES, MAX_CALL_DEPTH, MAX_VALUE_DEPTH, over_budget};

type ExprKey = (usize, usize);

#[derive(Clone, Default)]
struct ValueState {
    values: HashMap<String, SemanticValue>,
    commands: HashMap<String, RustCommandCandidates>,
    closures: HashMap<String, HashSet<String>>,
}

#[derive(Clone, Default)]
pub(super) struct RustValueFacts {
    pub(super) expressions: HashMap<ExprKey, SemanticValue>,
    pub(super) commands: HashMap<ExprKey, RustCommandCandidates>,
    pub(super) returns: Option<SemanticValue>,
}

static DEFAULT_VALUE_FACTS: LazyLock<RustValueFacts> = LazyLock::new(RustValueFacts::default);

pub(super) fn value_facts_or_default<'a>(
    facts: &'a HashMap<String, RustValueFacts>,
    name: &str,
) -> &'a RustValueFacts {
    facts.get(name).unwrap_or(&DEFAULT_VALUE_FACTS)
}

fn unresolved_value_facts() -> RustValueFacts {
    RustValueFacts {
        returns: Some(SemanticValue::unresolved("value")),
        ..RustValueFacts::default()
    }
}

pub(super) fn expr_key(expr: &Expr) -> ExprKey {
    span_key(expr)
}

pub(super) fn span_key(node: &impl Spanned) -> ExprKey {
    let range = node.span().byte_range();
    (range.start, range.end)
}

pub(super) fn rust_value_facts<'a>(
    names: impl IntoIterator<Item = &'a str>,
    fns: &RustFunctions<'_>,
    uses: &RustUseResolver,
    value_limits: crate::ValueLimits,
) -> HashMap<String, RustValueFacts> {
    rust_value_facts_counted(names, fns, uses, value_limits).0
}

/// Count the work to compute cached Rust value facts once per local function.
pub(super) fn rust_value_facts_counted<'a>(
    names: impl IntoIterator<Item = &'a str>,
    fns: &RustFunctions<'_>,
    uses: &RustUseResolver,
    value_limits: crate::ValueLimits,
) -> (HashMap<String, RustValueFacts>, u64) {
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
    fns: &RustFunctions<'_>,
    _uses: &RustUseResolver,
    visiting: &mut HashSet<String>,
    cache: &mut HashMap<String, RustValueFacts>,
    nodes: &mut u64,
    value_steps: &mut u64,
    depth: usize,
    value_limits: crate::ValueLimits,
) -> Option<SemanticValue> {
    if let Some(facts) = cache.get(name) {
        return facts.returns.clone();
    }
    let Some(function) = fns.get(name) else {
        cache.insert(name.to_string(), RustValueFacts::default());
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
    let mut analyzer = RustValueAnalyzer {
        value_limits,
        function: name,
        fns,
        uses: &function.uses,
        visiting,
        cache,
        nodes,
        value_steps,
        depth,
        facts: RustValueFacts::default(),
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

struct RustValueAnalyzer<'a, 'b> {
    value_limits: crate::ValueLimits,
    function: &'a str,
    fns: &'a RustFunctions<'a>,
    uses: &'a RustUseResolver,
    visiting: &'b mut HashSet<String>,
    cache: &'b mut HashMap<String, RustValueFacts>,
    nodes: &'b mut u64,
    value_steps: &'b mut u64,
    depth: usize,
    facts: RustValueFacts,
    return_values: Vec<SemanticValue>,
    value_depth: usize,
}

impl RustValueAnalyzer<'_, '_> {
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
        let resolved = self.uses.resolve_use_path(&segments);
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

pub(super) fn rust_path_literal(value: &SemanticValue) -> Option<&str> {
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

pub(super) fn is_rust_branch(name: &str) -> bool {
    name.starts_with("__effinterp_rust_branch:")
}

fn rust_branch_value(name: &str, value: SemanticValue) -> SemanticValue {
    SemanticValue::new(SemanticValueKind::Alias {
        name: name.to_string(),
        value: Box::new(value),
    })
}

/// Scope Rust branch groups to one call site so alternatives from separate calls stay independent.
pub(in crate::lang) fn scope_rust_branch_groups(
    value: &SemanticValue,
    scope: &str,
) -> SemanticValue {
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

pub(super) fn cross_file_value_call_key(
    expr: &Expr,
    fns: &RustFunctions<'_>,
    uses: &RustUseResolver,
) -> Option<ExprKey> {
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
            let resolved = uses.resolve_use_path(&segments);
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
                && !is_effectless_rust_call(
                    segments.last().map(String::as_str).unwrap_or_default(),
                ))
            .then(|| expr_key(expr))
        }
        _ => None,
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

pub(super) fn is_unresolved_value(value: &SemanticValue) -> bool {
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
