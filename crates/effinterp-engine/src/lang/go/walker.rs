//! The Go AST walk in evaluation order, with lexical scopes and walk budgets.

use std::collections::{BTreeSet, HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
    ResourceExpr,
};
use gosyn::ast::{BlockStmt, DeclStmt, Element, Expression, FuncLit, Statement};
use gosyn::token::Operator;

use crate::builder::PlanBuilder;
use crate::control_flow::SiteFacts;
use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::module_summary::DispatchContract;
use crate::summary::Summary;
use crate::value::unresolved_resource;
use crate::{ScopeKey, SemanticValue, SemanticValueKind, ValueOrigin, join_branches};

use super::summary::{
    BlockWrites, EscapedCallables, GoFunc, GoImports, constructed_class, field_types, named_type,
    reassigned_names,
};
use super::walk_output::GoWalkOutput;
use super::{GO_DOMAINS, control};

/// State for one Go walk, with lexical bindings local to that walk.
pub(super) struct GoWalker<'a, 'b> {
    pub(super) value_limits: crate::ValueLimits,
    pub(super) source: &'a str,
    pub(super) condition_source: &'a effinterp_proto::ConditionSource,
    pub(super) conditions: Vec<effinterp_proto::Condition>,
    pub(super) out: GoWalkOutput<'a, 'b>,
    /// Summary walks performed during a live analysis debit the same global
    /// step pool as the plan-emitting walk. Repository summary extraction has
    /// no plan budget and leaves this empty.
    pub(super) analysis_budget: Option<(&'a mut PlanBuilder, &'b crate::nest::Budget)>,
    pub(super) imports: &'a GoImports,
    pub(super) funcs: &'a HashMap<String, GoFunc>,
    pub(super) summaries: &'a HashMap<String, Summary>,
    pub(super) params: HashMap<String, ResourceExpr>,
    /// Local / parameter / receiver name -> named type as written. Seeded from
    /// declared types and updated by composite-literal assignment.
    pub(super) local_types: HashMap<String, String>,
    /// Interface contracts used only by single-file analysis to keep deferred
    /// repository dispatch explicit. Module summaries leave this empty because
    /// the linker resolves their bounded candidate sets.
    pub(super) dispatch_contracts: &'a [DispatchContract],
    pub(super) scope: Option<ProvenanceRef>,
    /// Local functions currently being inlined, to break recursion.
    pub(super) following: HashSet<String>,
    /// Functions and methods entered while building the live execution plan.
    pub(super) entered_callables: HashSet<String>,
    pub(super) callback_roots: BTreeSet<String>,
    pub(super) struct_fields: HashMap<String, String>,
    pub(super) package_constants: HashMap<String, SemanticValue>,
    pub(super) package_types: HashMap<String, String>,
    /// When set, local calls are recorded as edges (for module_summaries)
    /// instead of being inlined.
    pub(super) collect_edges: bool,
    /// Package initializer capture needs both ordinary call facts and the
    /// modeled direct effects that run before init bodies.
    pub(super) capture_external_effects: bool,
    /// Locals receiving the next top-level call's results (`x, err :=
    /// f(...)`), attached to that call's edge so the composer can type them
    /// from the callee's constructed returns.
    pub(super) binds_next_call: Vec<(usize, String)>,
    /// The binds for the call edge currently being recorded.
    pub(super) current_binds: Vec<(usize, String)>,
    pub(super) nodes: u64,
    pub(super) max_nodes: u64,
    pub(super) walk_depth: u32,
    pub(super) truncated: bool,
    pub(super) fact_file: String,
    pub(super) fact_scope: Option<ScopeKey>,
    pub(super) fact_function: String,
    pub(super) repo_types: HashSet<String>,
    pub(super) site_ordinal: u32,
    pub(super) package_vars: HashSet<String>,
    pub(super) local_origins: HashMap<String, ValueOrigin>,
    pub(super) instance_aliases: HashMap<String, SemanticValue>,
    pub(super) construction_origins: HashMap<(usize, usize), ValueOrigin>,
    pub(super) bound_vars: HashSet<String>,
    pub(super) local_vars: HashSet<String>,
    pub(super) channel_values: HashMap<String, ResourceExpr>,
    pub(super) resource_values: HashMap<String, ResourceExpr>,
    pub(super) values: HashMap<String, SemanticValue>,
    pub(super) local_scopes: Vec<HashMap<String, GoLocalBinding>>,
    /// Caller bindings the call currently being recorded may overwrite,
    /// attached to its edge so composition invalidates them too.
    pub(super) pending_writes: Vec<String>,
    /// `p := &cfg`: a name -> the binding whose storage it addresses, so a
    /// write through the pointer invalidates the variable as well.
    pub(super) address_aliases: HashMap<String, String>,
    /// Per open block, the names it reassigns anywhere below: what a deferred
    /// or concurrent body reads at a moment this walk cannot order.
    pub(super) reassigned_scopes: Vec<HashSet<String>>,
    /// Per open block, the pointers its text binds, wherever it binds them: a
    /// write through one reaches the same storage from an out-of-order body
    /// even when the pointer is bound after that body's statement.
    pub(super) aliased_scopes: Vec<Vec<(String, String)>>,
    /// Per open block, the calls its text states. A call writes the storage it
    /// is handed and the receiver it assigns through, which reaches an
    /// out-of-order body wherever the block states the call.
    pub(super) called_scopes: Vec<Vec<gosyn::ast::Call>>,
    /// Per open block, the callables its text hands to storage this walk does
    /// not follow. One of them runs at a moment nothing here can order, so
    /// what it writes — a method value's receiver above all — reaches an
    /// out-of-order body wherever the block states the escape.
    pub(super) escaped_scopes: Vec<EscapedCallables>,
    /// Guarantees of bodies entered since the enclosing call began.
    pub(super) control_applications: Vec<SiteFacts>,
}

pub(super) struct GoLocalBinding {
    was_local: bool,
    typ: Option<String>,
    origin: Option<ValueOrigin>,
    alias: Option<SemanticValue>,
    pub(super) channel_value: Option<ResourceExpr>,
    resource_value: Option<ResourceExpr>,
    value: Option<SemanticValue>,
    was_bound: bool,
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

fn expression_pos(expr: &Expression) -> (u32, u32) {
    let start = match expr {
        Expression::List(values) => values.first().map(Expression::pos).unwrap_or(0),
        _ => expr.pos(),
    } as u32;
    (start, start.saturating_add(1))
}

impl GoWalker<'_, '_> {
    /// Walk Go statements in order and restore bindings shadowed by the block.
    pub(super) fn walk_go_block(&mut self, block: &BlockStmt) {
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
    pub(super) fn walk_function_literal(&mut self, literal: &FuncLit) {
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
        self.walk_go_block(&literal.body);
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

    pub(super) fn partial_walk(&mut self) {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => builder.control_widen(),
            GoWalkOutput::Capture(cap) => cap.control.widen(),
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
            Statement::Expr(e) => self.walk_go_expression(&e.expr),
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
                    self.walk_go_expression(e);
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
                    self.bind_go_receiver_type(left, right);
                    self.bind_address_alias(left, right);
                    self.bind_go_channel_receive(left, right);
                    self.bind_go_semantic_value(left, right);
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
                        self.walk_go_expression(value);
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
                        self.bind_go_channel_receive(&Expression::Ident(id.clone()), value);
                        self.bind_go_semantic_value(&Expression::Ident(id.clone()), value);
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
                    && let Some(value) = self.go_semantic_value(&r.ret[0])
                    && let GoWalkOutput::Capture(capture) = &mut self.out
                {
                    capture.returns.push(value);
                }
                for e in &r.ret {
                    self.walk_go_expression(e);
                }
            }
            Statement::If(i) => {
                self.begin_local_scope();
                if let Some(init) = &i.init {
                    self.walk_stmt(init);
                }
                self.walk_go_expression(&i.cond);
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
                self.walk_go_block(&i.body);
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
                self.walk_go_block(&f.body);
                self.conditions.pop();
                if let Some(post) = &f.post {
                    self.walk_stmt(post);
                }
                self.values = merge_value_maps(before, self.values.clone(), self.value_limits);
                self.end_local_scope();
            }
            Statement::Range(r) => {
                self.begin_local_scope();
                self.walk_go_expression(&r.expr);
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
                        .and_then(|_| self.go_semantic_value(&r.expr))
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
                self.walk_go_block(&r.body);
                self.conditions.pop();
                self.values = merge_value_maps(before, self.values.clone(), self.value_limits);
                self.end_local_scope();
            }
            Statement::Label(label) => self.walk_stmt(&label.stmt),
            Statement::Block(b) => self.walk_go_block(b),
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
            Statement::Send(send) => self.walk_go_channel_send(send),
            Statement::Switch(s) => {
                self.begin_local_scope();
                if let Some(init) = &s.init {
                    self.walk_stmt(init);
                }
                if let Some(tag) = &s.tag {
                    self.walk_go_expression(tag);
                }
                let before = self.values.clone();
                let mut outcomes = Vec::new();
                let mut has_default = false;
                for (arm, clause) in s.block.body.iter().enumerate() {
                    has_default |= clause.list.is_empty();
                    self.values = before.clone();
                    self.begin_local_scope();
                    for expression in &clause.list {
                        self.walk_go_expression(expression);
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
                                self.walk_go_expression(&send.chan);
                                self.walk_go_expression(&send.value);
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
            Statement::IncDec(inc_dec) => self.walk_go_expression(&inc_dec.expr),
            Statement::Declaration(DeclStmt::Const(declaration)) => {
                for expression in declaration.specs.iter().flat_map(|spec| &spec.values) {
                    self.walk_go_expression(expression);
                }
            }
            Statement::Empty(_)
            | Statement::Branch(_)
            | Statement::Declaration(DeclStmt::Type(_)) => {}
        }
    }

    pub(super) fn walk_go_expression(&mut self, expr: &Expression) {
        self.escape_addresses(expr, true);
        self.escape_callables(expr, true);
        // Iterative: left-deep `+` / `&&` spines overflow the process stack
        // before the node cap can fire. Nested calls still go through
        // walk_go_call, which is depth-bounded separately.
        enum GoExprWork<'a> {
            Expr(&'a Expression),
            Push(&'a Expression, bool),
            Pop,
        }
        let initial_depth = self.conditions.len();
        let mut stack = vec![GoExprWork::Expr(expr)];
        while let Some(work) = stack.pop() {
            let expr = match work {
                GoExprWork::Expr(expr) => expr,
                GoExprWork::Push(origin, positive) => {
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
                GoExprWork::Pop => {
                    self.conditions.pop();
                    continue;
                }
            };
            if self.over_node_budget(expression_pos(expr)) {
                self.partial_nodes();
                break;
            }
            match expr {
                Expression::Call(call) => self.walk_go_call(call),
                Expression::Paren(p) => stack.push(GoExprWork::Expr(&p.expr)),
                Expression::Operation(op) => {
                    if let Some(y) = &op.y {
                        if matches!(op.op, Operator::AndAnd | Operator::OrOr) {
                            stack.push(GoExprWork::Pop);
                            stack.push(GoExprWork::Expr(y));
                            stack.push(GoExprWork::Push(&op.x, op.op == Operator::AndAnd));
                        } else {
                            stack.push(GoExprWork::Expr(y));
                        }
                    }
                    stack.push(GoExprWork::Expr(&op.x));
                }
                Expression::Star(s) => stack.push(GoExprWork::Expr(&s.right)),
                Expression::Index(i) => {
                    stack.push(GoExprWork::Expr(&i.index));
                    stack.push(GoExprWork::Expr(&i.left));
                }
                Expression::IndexList(i) => {
                    for index in i.indices.iter().rev() {
                        stack.push(GoExprWork::Expr(index));
                    }
                    stack.push(GoExprWork::Expr(&i.left));
                }
                Expression::TypeAssert(t) => stack.push(GoExprWork::Expr(&t.left)),
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
    pub(super) fn over_node_budget(&mut self, span: (u32, u32)) -> bool {
        let charged = match &mut self.out {
            GoWalkOutput::Plan { builder, nest, .. } => {
                crate::nest::charge_analysis_steps(builder, nest.budget, 1, Some(span))
            }
            GoWalkOutput::Capture(_) => match &mut self.analysis_budget {
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

    pub(super) fn partial_nodes(&mut self) {
        let analysis_steps_saturated = match &self.out {
            GoWalkOutput::Plan { nest, .. } => nest.budget.steps_saturated(),
            GoWalkOutput::Capture(_) => self
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
                Element::Expr(e) => self.walk_go_expression(e),
                Element::LitValue(inner) => self.walk_literal_value(inner, depth + 1),
            }
        }
    }

    fn bind_local_name(&mut self, name: &str) -> bool {
        if name == "_" {
            return false;
        }
        let binding = GoLocalBinding {
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
}
