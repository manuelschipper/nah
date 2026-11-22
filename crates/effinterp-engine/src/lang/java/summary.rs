//! Java module summaries for cross-file composition.
//!
//! Summaries follow the compose conventions the Python frontend established:
//! functions are named `Cls.method` (constructors `Cls.__init__`), classes
//! carry `ClassEntry` tables, and method calls carry a semantic object receiver
//! only when its provenance is unambiguous (declared type, `new X(...)`,
//! parameter, field), and same-package classes are reachable through
//! synthesized import bindings (`pkg.Cls`) — Java's implicit same-package
//! visibility mapped onto the import machinery. Same-file calls are inlined
//! into the caller's summary (compose enters same-file callees edges-only).

mod call_edges;
mod inlining;
#[cfg(test)]
mod tests;

use super::call_resolution::{JAVA_LANG, is_java_type_name, jdk_receiver_type};
use super::callbacks::push_node_candidate;
use super::declarations::{JavaFile, assigned_instance_field, collect_java_declarations};
use super::local_bindings::{
    assigned_local, is_guarded_java_assignment, local_mutations, tracked_giveups_in,
    tracked_initializer, tracked_local_type,
};
use super::model::{ModeledOp, ModeledTransfer, http_verb_of_expr, op_attributes};
use super::resource_recovery::{is_unresolved, iterable_element, recover_typed_java_resource};
use super::syntax::{bare_java_type, java_node_text};
use super::{JAVA_DOMAINS, MAX_SUMMARY_BOUNDARIES, MAX_SUMMARY_EFFECTS, control};
use crate::control_flow::{ControlCaps, ControlFact, ControlFlow, ControlStack, SiteFacts};
use crate::external::{ALL_DOMAINS, Domains};
use crate::lang::conditions;
use crate::lang::tree_sitter_nodes::node_span;
use crate::module_summary::{
    CallEdge, ClassEntry, DispatchContract, FunctionEntry, ImportBinding, ModuleSummary,
};
use crate::resource_transfer::TransferBinding;
use crate::summary::Summary;
use crate::value::unresolved_resource;
use crate::{ScopeKey, SemanticValue, ValueOrigin};
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    Modality, Operation, ResourceExpr,
};
use inlining::{JavaInlinedSummary, inline_java_summary};
use std::collections::{BTreeMap, HashMap, HashSet};
use tree_sitter::{Node, Tree};

/// Exports Java method summaries for cross-file composition, including unreached methods.
pub(super) fn summarize_ast(
    source: &str,
    tree: &Tree,
    fact_file: &str,
    _fact_scope: ScopeKey,
) -> ModuleSummary {
    let src = source.as_bytes();
    let root = tree.root_node();
    let file = collect_java_declarations(root, src);

    // JavaSummaryDraft per-method surfaces, merged by `Cls.method` (overloads unioned).
    let static_code = control::runs_static_code(root, 0);
    let mut raws: BTreeMap<String, JavaSummaryDraft> = BTreeMap::new();
    let mut attr_params: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut attr_classes: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut implicit: HashSet<String> = HashSet::new();
    let mut site_ordinals: HashMap<String, u32> = HashMap::new();
    for m in &file.methods {
        let _walk = crate::limits::summary_walk();
        let key = format!("{}.{}", m.class, m.name);
        let site_ordinal = site_ordinals.get(&key).copied().unwrap_or_default();
        let mut env: HashMap<String, ResourceExpr> = file
            .class(&m.class)
            .into_iter()
            .flat_map(|class| class.fields.keys())
            .map(|field| {
                (
                    field.clone(),
                    ResourceExpr::Parameter {
                        name: field.clone(),
                    },
                )
            })
            .collect();
        if let Some(class) = file.class(&m.class) {
            // Constructor parameters are outside every method summary's parameter
            // scope, so dependent fields must remain symbolic.
            env.extend(
                class
                    .field_values
                    .iter()
                    .filter(|(_, value)| !references_parameter(value))
                    .map(|(field, value)| (field.clone(), value.clone())),
            );
        }
        env.extend(m.params.iter().map(|param| {
            (
                param.name.clone(),
                ResourceExpr::Parameter {
                    name: param.name.clone(),
                },
            )
        }));
        let mut giveups: HashSet<String> = file
            .class(&m.class)
            .into_iter()
            .flat_map(|class| class.unstable_constructor_fields.iter())
            .filter(|field| env.get(*field).is_some_and(is_unresolved))
            .cloned()
            .collect();
        for param in &m.params {
            giveups.remove(&param.name);
        }
        let mut control = ControlStack::default();
        let limits = crate::AnalysisLimits::default();
        control.enter(
            source,
            true,
            Default::default(),
            0,
            0,
            None,
            ControlCaps {
                nodes: limits.max_causal_nodes,
                work: limits.max_causal_pairs,
            },
            |graph| control::build_body(graph, m.body, source),
        );
        let mut col = JavaSummaryWalker {
            control,
            call_sites: BTreeMap::new(),
            callback_visits: 0,
            file: &file,
            src,
            class: m.class.clone(),
            param_names: m.params.iter().map(|p| p.name.clone()).collect(),
            env,
            types: file
                .class(&m.class)
                .into_iter()
                .flat_map(|class| {
                    class
                        .fields
                        .iter()
                        .map(|(name, ty)| (format!("this.{name}"), ty.clone()))
                })
                .chain(m.params.iter().map(|p| (p.name.clone(), p.ty.clone())))
                .collect(),
            news: HashMap::new(),
            callbacks: HashMap::new(),
            local_names: m.params.iter().map(|param| param.name.clone()).collect(),
            finals: HashSet::new(),
            tracked: HashSet::new(),
            giveups,
            poisoned: HashSet::new(),
            http_verbs: HashMap::new(),
            active_callbacks: HashSet::new(),
            active_object_arguments: HashSet::new(),
            effects: Vec::new(),
            transfers: Vec::new(),
            boundaries: Vec::new(),
            locals: Vec::new(),
            edges: Vec::new(),
            attr_params: Vec::new(),
            attr_classes: Vec::new(),
            implicit: HashSet::new(),
            nodes: 0,
            fact_file,
            fact_function: &key,
            site_ordinal,
            site_origins: HashMap::new(),
            local_origins: HashMap::new(),
        };
        col.walk(m.body);
        let finished = col.control.leave(0).expect("Java summary frame");
        let mut flow = finished.flow;
        flow.bind_calls(&col.call_sites);
        if let Some(limit) = finished.refused {
            col.boundaries.push(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                domains: JAVA_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: Vec::new(),
                limit: Some(limit.to_string()),
                detail: Some("Java summary control flow widened".to_string()),
                affected_resource: None,
                callee: None,
            });
        }
        site_ordinals.insert(key.clone(), col.site_ordinal);
        if m.name == "__init__" {
            attr_params
                .entry(m.class.clone())
                .or_default()
                .append(&mut col.attr_params);
            attr_classes
                .entry(m.class.clone())
                .or_default()
                .append(&mut col.attr_classes);
        }
        implicit.extend(col.implicit);
        let overloaded = raws.contains_key(&key);
        let raw = raws.entry(key.clone()).or_insert_with(|| JavaSummaryDraft {
            params: Vec::new(),
            ..JavaSummaryDraft::default()
        });
        raw.control_flow = if overloaded || static_code {
            ControlFlow::widened()
        } else {
            flow
        };
        if m.params.len() > raw.params.len() {
            raw.params = m.params.iter().map(|p| p.name.clone()).collect();
        }
        let base = raw.effects.len() as u32;
        raw.effects.append(&mut col.effects);
        raw.transfers
            .extend(col.transfers.iter().map(|binding| binding.shifted(base)));
        raw.boundaries.append(&mut col.boundaries);
        raw.locals.append(&mut col.locals);
        raw.edges.append(&mut col.edges);
    }

    // Inline same-file calls' effects and boundaries into each caller's
    // summary (compose enters same-file callees edges-only).
    let keys: Vec<String> = raws.keys().cloned().collect();
    let mut memo: HashMap<String, JavaInlinedSummary> = HashMap::new();
    for key in &keys {
        let mut visiting = HashSet::new();
        inline_java_summary(key, &raws, &mut memo, &mut visiting);
    }

    let coverage: Vec<(Domain, CoverageLevel)> = JAVA_DOMAINS
        .iter()
        .map(|d| (Domain::new(*d), CoverageLevel::Partial))
        .collect();
    let mut functions = Vec::new();
    for (key, raw) in &raws {
        let inlined = memo.get(key).cloned().unwrap_or_default();
        let edges = raw.edges.clone();
        functions.push(FunctionEntry {
            name: key.clone(),
            summary: Summary {
                control_flow: inlined.control_flow,
                params: raw.params.clone(),
                effects: inlined.effects,
                effect_models: Vec::new(),
                transfers: inlined.transfers,
                returns: None,
                boundaries: inlined.boundaries,
                coverage: coverage.clone(),
            },
            calls: edges,
            ..Default::default()
        });
    }

    // Executing the file means running `main`: its calls are the entrypoint
    // roots (main_calls, not module_calls — importing a Java class runs
    // nothing).
    let mut main_calls: Vec<CallEdge> = Vec::new();
    for f in &functions {
        if f.name.ends_with(".main") {
            main_calls.extend(f.calls.iter().cloned());
        }
    }
    let mains: Vec<_> = functions
        .iter()
        .filter(|function| function.name.ends_with(".main"))
        .collect();
    let main_control_flow = if !static_code && mains.len() == 1 {
        mains[0].summary.control_flow.calls_only()
    } else {
        ControlFlow::widened()
    };

    let classes: Vec<ClassEntry> = file
        .classes
        .iter()
        .map(|c| {
            let mut ac: Vec<(String, String)> =
                attr_classes.get(&c.name).cloned().unwrap_or_default();
            ac.extend(c.field_news.iter().cloned());
            ClassEntry {
                name: c.name.clone(),
                bases: c.bases.clone(),
                attr_params: attr_params.get(&c.name).cloned().unwrap_or_default(),
                attr_classes: ac,
                ..Default::default()
            }
        })
        .collect();
    let dispatch_contracts: Vec<DispatchContract> = file
        .classes
        .iter()
        .filter(|class| class.is_interface)
        .filter_map(|class| {
            let mut methods = class.methods.clone();
            methods.sort();
            methods.dedup();
            (!methods.is_empty()).then(|| DispatchContract {
                name: class.name.clone(),
                methods,
                method_signatures: Vec::new(),
            })
        })
        .collect();

    for base in file.classes.iter().flat_map(|class| &class.bases) {
        if is_java_type_name(base) && !JAVA_LANG.contains(&base.as_str()) {
            implicit.insert(base.clone());
        }
    }

    // Explicit imports plus synthesized same-package bindings for referenced
    // unimported type names — Java's implicit same-package visibility mapped
    // onto the import machinery. All Java bindings are whole-class
    // (`imported: None`); the FQN is the module.
    let mut imports: Vec<ImportBinding> = file
        .imports
        .iter()
        .map(|(local, fqn)| ImportBinding {
            local: local.clone(),
            module: fqn.clone(),
            imported: None,
        })
        .collect();
    for name in &implicit {
        if file.imports.contains_key(name) || file.class(name).is_some() {
            continue;
        }
        let module = if file.package.is_empty() {
            name.clone()
        } else {
            format!("{}.{name}", file.package)
        };
        imports.push(ImportBinding {
            local: name.clone(),
            module,
            imported: None,
        });
    }
    imports.sort_by(|a, b| a.local.cmp(&b.local));

    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            dispatch: crate::DispatchStyle::Nominal,
            ..Default::default()
        },
        functions,
        module_calls: Vec::new(),
        main_calls,
        main_control_flow,
        module_control_flow: if static_code {
            ControlFlow::widened()
        } else {
            ControlFlow::empty_body()
        },
        imports,
        classes,
        dispatch_contracts,
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |_| true);
    summary
}

fn references_parameter(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Parameter { .. } => true,
        ResourceExpr::Property { base, .. } => references_parameter(base),
        ResourceExpr::Join { parts } => parts.iter().any(references_parameter),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(references_parameter),
        _ => false,
    }
}

#[derive(Default)]
struct JavaSummaryDraft {
    control_flow: ControlFlow,
    params: Vec<String>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    /// Same-file calls to inline: callee, arguments, and caller edge slot.
    locals: Vec<(String, Vec<ResourceExpr>, u32)>,
    edges: Vec<CallEdge>,
}

/// Per-method summary collector: modeled effects (parameterized by the
/// method's own parameters), same-file calls to inline, and cross-file call
/// edges with typed receivers.
struct JavaSummaryWalker<'a> {
    control: ControlStack,
    call_sites: BTreeMap<crate::control_flow::Span, u32>,
    callback_visits: usize,
    file: &'a JavaFile<'a>,
    src: &'a [u8],
    class: String,
    param_names: Vec<String>,
    env: HashMap<String, ResourceExpr>,
    types: HashMap<String, String>,
    news: HashMap<String, Vec<Node<'a>>>,
    callbacks: HashMap<String, Vec<Node<'a>>>,
    local_names: HashSet<String>,
    finals: HashSet<String>,
    tracked: HashSet<String>,
    giveups: HashSet<String>,
    poisoned: HashSet<String>,
    http_verbs: HashMap<String, String>,
    active_callbacks: HashSet<usize>,
    active_object_arguments: HashSet<usize>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    locals: Vec<(String, Vec<ResourceExpr>, u32)>,
    edges: Vec<CallEdge>,
    attr_params: Vec<(String, String)>,
    attr_classes: Vec<(String, String)>,
    implicit: HashSet<String>,
    nodes: u64,
    fact_file: &'a str,
    fact_function: &'a str,
    site_ordinal: u32,
    site_origins: HashMap<usize, ValueOrigin>,
    local_origins: HashMap<String, ValueOrigin>,
}

impl<'a> JavaSummaryWalker<'a> {
    fn walk(&mut self, n: Node<'a>) {
        // Same left-deep `+` hazard as `walk_calls`: checkstyle ships a
        // 39k-concat test fixture that used to abort summarization.
        let mut stack = vec![n];
        while let Some(n) = stack.pop() {
            self.nodes += 1;
            if !crate::limits::summary_step() {
                self.control.widen();
                let boundary_index = self.boundaries.len();
                self.push_boundary(
                    BoundaryReason::PARTIAL_ANALYSIS,
                    BoundaryClass::Unmodeled,
                    "java summary walk node budget exhausted".to_string(),
                    ALL_DOMAINS,
                    Some(n),
                );
                if let Some(boundary) = self.boundaries.get_mut(boundary_index)
                    && boundary.reason == BoundaryReason::PARTIAL_ANALYSIS
                    && boundary.limit.is_none()
                {
                    boundary.limit = Some("max_java_nodes".to_string());
                }
                return;
            }
            let k = n.kind();
            if matches!(
                k,
                "method_declaration"
                    | "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "class_body"
                    | "lambda_expression"
            ) {
                continue;
            }
            let effect_start = self.effects.len();
            let edge_start = self.edges.len();
            let boundary_start = self.boundaries.len();
            let callbacks = self.callback_visits;
            match k {
                "local_variable_declaration" => self.record_local(n),
                "enhanced_for_statement" => self.record_enhanced_for(n),
                "method_invocation" => self.invocation(n),
                "object_creation_expression" => self.creation(n),
                "assignment_expression" => {
                    self.record_callback_assignment(n);
                    self.attr_assignment(n);
                }
                "update_expression" => self.record_update(n),
                _ => {}
            }
            let source = std::str::from_utf8(self.src).expect("parsed UTF-8 source");
            if self.active_callbacks.is_empty() && callbacks == self.callback_visits {
                let span = node_span(n);
                if self.edges.len() == edge_start + 1 {
                    self.call_sites.insert(span, edge_start as u32);
                    let mut facts = SiteFacts::unknown();
                    facts.call_return =
                        k == "method_invocation" && self.boundaries.len() == boundary_start;
                    self.control.register(source, true, span, facts);
                } else if k == "method_invocation"
                    && self.edges.len() == edge_start
                    && self.boundaries.len() == boundary_start
                {
                    let jdk = n.child_by_field_name("object").and_then(|object| {
                        jdk_receiver_type(object, self.src, self.file, &self.class, &self.types)
                    });
                    if let Some(jdk) = jdk {
                        let name = n
                            .child_by_field_name("name")
                            .map(|name| java_node_text(name, self.src))
                            .unwrap_or("");
                        let direct_delete =
                            jdk == "Files" && matches!(name, "delete" | "deleteIfExists");
                        let facts = if direct_delete {
                            (effect_start..self.effects.len())
                                .map(|slot| ControlFact::Effect(slot as u32))
                                .collect()
                        } else {
                            Vec::new()
                        };
                        self.control
                            .register(source, true, span, SiteFacts::known(facts));
                    }
                }
            }
            let guard = (self.effects.len() != effect_start || self.edges.len() != edge_start)
                .then(|| conditions::tree_condition(source, n))
                .flatten();
            for effect in &mut self.effects[effect_start..] {
                effect.condition = effinterp_proto::Condition::compose(
                    effect.condition.iter().chain(guard.iter()),
                );
            }
            for edge in &mut self.edges[edge_start..] {
                edge.condition =
                    effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
                if edge.call_site.is_none() {
                    edge.call_site = Some(effinterp_proto::stable_hash(
                        effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                        &(source, n.start_byte(), n.end_byte()),
                    ));
                }
            }
            let mut cursor = n.walk();
            let children: Vec<Node<'a>> = n.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn record_local(&mut self, n: Node<'a>) {
        let Some(ty) = n
            .child_by_field_name("type")
            .map(|t| bare_java_type(java_node_text(t, self.src)))
        else {
            return;
        };
        let is_final = n
            .named_children(&mut n.walk())
            .find(|child| child.kind() == "modifiers")
            .is_some_and(|modifiers| java_node_text(modifiers, self.src).contains("final"));
        let mut c = n.walk();
        for decl in n
            .named_children(&mut c)
            .filter(|d| d.kind() == "variable_declarator")
        {
            let Some(name) = decl
                .child_by_field_name("name")
                .map(|x| java_node_text(x, self.src).to_string())
            else {
                continue;
            };
            self.local_names.insert(name.clone());
            self.callbacks.remove(&name);
            self.news.remove(&name);
            self.env.remove(&name);
            self.http_verbs.remove(&name);
            self.tracked.remove(&name);
            self.giveups.remove(&name);
            self.poisoned.remove(&name);
            if is_final {
                self.finals.insert(name.clone());
            } else {
                self.finals.remove(&name);
            }
            if ty == "var" {
                self.types.remove(&name);
                self.local_origins.remove(&name);
            }
            if let Some(value) = decl.child_by_field_name("value") {
                if matches!(value.kind(), "lambda_expression" | "method_reference") {
                    self.callbacks.insert(name.clone(), vec![value]);
                }
                if value.kind() == "object_creation_expression" {
                    self.news.insert(name.clone(), vec![value]);
                    if ty == "var"
                        && let Some(t) = value.child_by_field_name("type")
                    {
                        self.types
                            .insert(name.clone(), bare_java_type(java_node_text(t, self.src)));
                    }
                }
                if tracked_local_type(&ty)
                    || matches!(ty.as_str(), "HttpURLConnection" | "HttpRequest")
                {
                    if tracked_initializer(value, self.src, &self.file.constants) {
                        let resolved = recover_typed_java_resource(
                            value,
                            self.src,
                            &self.env,
                            &self.file.constants,
                            &self.types,
                        );
                        self.tracked.insert(name.clone());
                        if is_unresolved(&resolved) {
                            self.giveups.insert(name.clone());
                        }
                        self.env.insert(name.clone(), resolved);
                    }
                    if let Some(verb) =
                        http_verb_of_expr(value, self.src, &self.http_verbs, &self.file.constants)
                    {
                        self.http_verbs.insert(name.clone(), verb);
                    }
                }
            }
            if ty != "var" {
                self.types.insert(name.clone(), ty.clone());
                if self.file.is_repo_class_candidate(&ty) && !self.news.contains_key(&name) {
                    let origin = self.origin_for_node(decl);
                    self.local_origins.insert(name.clone(), origin);
                }
            }
            if self.tracked.contains(&name) {
                let mutations = local_mutations(n, &name, self.src);
                if (!is_final && mutations.reassigned) || mutations.array_element_assigned {
                    poison_summary_local(&name, self);
                }
            }
        }
    }

    fn record_enhanced_for(&mut self, n: Node<'a>) {
        let (Some(ty), Some(name), Some(value)) = (
            n.child_by_field_name("type"),
            n.child_by_field_name("name"),
            n.child_by_field_name("value"),
        ) else {
            return;
        };
        let name = java_node_text(name, self.src).to_string();
        self.local_names.insert(name.clone());
        self.types
            .insert(name.clone(), bare_java_type(java_node_text(ty, self.src)));
        self.env.remove(&name);
        self.tracked.remove(&name);
        self.giveups.remove(&name);
        if let Some(element) = iterable_element(value, self.src, &self.env, &self.file.constants) {
            self.tracked.insert(name.clone());
            if is_unresolved(&element) {
                self.giveups.insert(name.clone());
            }
            self.env.insert(name.clone(), element);
            let mutations = local_mutations(n, &name, self.src);
            if mutations.reassigned || mutations.array_element_assigned {
                poison_summary_local(&name, self);
            }
        }
    }

    fn record_update(&mut self, n: Node<'a>) {
        let Some(target) = n.named_child(0) else {
            return;
        };
        if target.kind() == "identifier" {
            let name = java_node_text(target, self.src);
            if self.tracked.contains(name) && !self.finals.contains(name) {
                poison_summary_local(name, self);
            }
        }
    }

    fn record_callback_assignment(&mut self, n: Node<'a>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let Some((name, array_element)) = assigned_local(left, self.src) else {
            return;
        };
        if self.tracked.contains(&name) && (array_element || !self.finals.contains(&name)) {
            poison_summary_local(&name, self);
        }
        if array_element {
            return;
        }
        let guarded = is_guarded_java_assignment(n, self.src);
        if !guarded {
            self.callbacks.remove(&name);
            self.news.remove(&name);
        }
        let truncated = if matches!(right.kind(), "lambda_expression" | "method_reference") {
            push_node_candidate(&mut self.callbacks, name.clone(), right)
        } else if right.kind() == "object_creation_expression" {
            push_node_candidate(&mut self.news, name, right)
        } else {
            false
        };
        if truncated {
            self.push_candidate_limit_boundary();
        }
    }

    /// `this.f = <param>` / `this.f = new X(...)` in a constructor: the class
    /// table's attribute typing sources.
    fn attr_assignment(&mut self, n: Node<'a>) {
        let Some(right) = n.child_by_field_name("right") else {
            return;
        };
        let Some(class) = self.file.class(&self.class) else {
            return;
        };
        let Some(field) = assigned_instance_field(n, class, &self.local_names, self.src) else {
            return;
        };
        if class.mutable_fields.contains(&field) {
            return;
        }
        match right.kind() {
            "identifier" => {
                let id = java_node_text(right, self.src);
                if self.param_names.iter().any(|p| p == id) {
                    self.attr_params.push((field, id.to_string()));
                }
            }
            "object_creation_expression" => {
                if let Some(t) = right.child_by_field_name("type") {
                    self.attr_classes
                        .push((field, bare_java_type(java_node_text(t, self.src))));
                }
            }
            _ => {}
        }
    }

    /// Collect modeled effects and pair the transfer endpoints the model
    /// named, so the summary carries the pairing to every call site.
    fn push_effects(&mut self, ops: Vec<ModeledOp>, transfer: Option<ModeledTransfer>) {
        let mut emitted = Vec::with_capacity(ops.len());
        for (op, res, attr) in ops {
            if self.effects.len() >= MAX_SUMMARY_EFFECTS {
                break;
            }
            let mut effect = Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new(op),
                resource: res,
                attributes: op_attributes(attr),
                modality: Modality::May,
                execution: effinterp_proto::ExecutionNodeRef(0),
                condition: None,
                realm: Default::default(),
                provenance: Vec::new(),
            };
            let value = SemanticValue::from(&effect.resource);
            crate::lower_effect_value(&mut effect, &value);
            self.effects.push(effect);
            emitted.push((op, self.effects.len() as u32 - 1));
        }
        let Some(transfer) = transfer else {
            return;
        };
        let find = |operation: &str| {
            emitted
                .iter()
                .find(|(op, _)| *op == operation)
                .map(|(_, slot)| *slot)
        };
        if let (Some(source), Some(destination)) =
            (find(transfer.source), find(transfer.destination))
        {
            let binding = TransferBinding::new(source, destination);
            if !self.transfers.contains(&binding) {
                self.transfers.push(binding);
            }
        }
    }

    fn push_boundary(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: String,
        domains: Domains,
        site: Option<Node<'a>>,
    ) {
        if self.boundaries.len() >= MAX_SUMMARY_BOUNDARIES {
            if self.boundaries.len() == MAX_SUMMARY_BOUNDARIES {
                self.boundaries.push(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: Vec::new(),
                    limit: Some("max_java_summary_boundaries".to_string()),
                    detail: None,
                });
            }
            return;
        }
        self.boundaries.push(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: site.and_then(|site| {
                site.child_by_field_name("name")
                    .map(|name| effinterp_proto::CalleeReference {
                        module: site
                            .child_by_field_name("object")
                            .map_or(self.class.as_str(), |object| {
                                java_node_text(object, self.src)
                            })
                            .to_string(),
                        symbol: java_node_text(name, self.src).to_string(),
                    })
            }),
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some(site.map_or_else(
                || detail.clone(),
                |site| format!("{detail} at {}..{}", site.start_byte(), site.end_byte()),
            )),
        });
    }

    fn push_giveup_boundaries(&mut self, sink: Node, ops: &[ModeledOp]) {
        let mut names = tracked_giveups_in(sink, self.src, &self.giveups);
        names.sort();
        names.dedup();
        for name in names {
            let mut domains: Vec<&str> = ops
                .iter()
                .map(|(operation, _, _)| operation.split('.').next().unwrap_or("filesystem"))
                .collect();
            domains.sort();
            domains.dedup();
            for domain in domains {
                let detail = format!("java local {name} value is unmodeled");
                if self.boundaries.len() >= MAX_SUMMARY_BOUNDARIES
                    || self.boundaries.iter().any(|boundary| {
                        boundary.detail.as_deref() == Some(detail.as_str())
                            && boundary.domains == vec![Domain::new(domain)]
                    })
                {
                    continue;
                }
                self.boundaries.push(Boundary {
                    reason: BoundaryReason::UNMODELED_DYNAMIC,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(unresolved_resource(domain)),
                    callee: None,
                    domains: vec![Domain::new(domain)],
                    provenance: Vec::new(),
                    limit: None,
                    detail: Some(detail),
                });
            }
        }
    }

    fn push_candidate_limit_boundary(&mut self) {
        let detail = "java callback or receiver candidate limit exceeded";
        if self.boundaries.len() >= MAX_SUMMARY_BOUNDARIES
            || self
                .boundaries
                .iter()
                .any(|boundary| boundary.detail.as_deref() == Some(detail))
        {
            return;
        }
        self.boundaries.push(Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JAVA_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: Some("max_callback_values".to_string()),
            detail: Some(detail.to_string()),
        });
    }
}

fn poison_summary_local(name: &str, context: &mut JavaSummaryWalker<'_>) {
    context.poisoned.insert(name.to_string());
    context.giveups.insert(name.to_string());
    context
        .env
        .insert(name.to_string(), unresolved_resource("filesystem"));
}
