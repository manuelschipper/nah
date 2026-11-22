//! Java execution walk, method frames, and effect emission.

mod invocation;
mod process_builder;

use super::callbacks::push_node_candidate;
use super::declarations::{
    JavaFile, JavaMethod, assigned_instance_field, collect_java_declarations,
};
use super::local_bindings::{
    assigned_local, is_guarded_java_assignment, local_mutations, tracked_giveups_in,
    tracked_initializer, tracked_local_type,
};
use super::model::{ModeledOp, ModeledTransfer, http_verb_of_expr, op_attributes};
use super::resource_recovery::{is_unresolved, iterable_element, recover_typed_java_resource};
use super::syntax::{bare_java_type, java_node_text};
use super::{JAVA_DOMAINS, control};
use crate::SemanticValue;
use crate::builder::PlanBuilder;
use crate::control_flow::SiteFacts;
use crate::external::{ALL_DOMAINS, Domains};
use crate::lang::conditions;
use crate::lang::frontend::{FrontendInput, WalkOutcome};
use crate::lang::tree_sitter_nodes::node_span;
use crate::nest::Nest;
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr,
};
use process_builder::invalidate_argv_local;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

/// Plans Java execution from main and recognized framework roots.
pub(super) fn walk_java_execution(
    builder: &mut PlanBuilder,
    nest: &Nest,
    input: &FrontendInput,
    tree: &Tree,
) -> WalkOutcome {
    let source = input.source;
    let cwd = input.runtime_cwd;
    let cwd_node = input.cwd_node;
    let scope = input.scope;
    let depth = input.depth;
    let src = source.as_bytes();
    let root = tree.root_node();
    let file = collect_java_declarations(root, src);

    builder.boundary(Boundary {
        reason: BoundaryReason::FRONTEND_PARTIAL,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: JAVA_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: scope.as_slice().to_vec(),
        limit: None,
        detail: Some("java frontend models selected effect APIs".to_string()),
    });

    let declared_callables: Vec<String> = file
        .methods
        .iter()
        .map(|method| format!("{}.{}", method.class, method.name))
        .collect();
    let first_effect = builder.effects_len();
    let mut ctx = JavaWalker {
        src,
        file: &file,
        nest,
        cwd,
        cwd_node,
        scope,
        depth,
        max_nodes: nest.limits.max_java_nodes,
        nodes: 0,
        fallback_boundaries: 0,
        candidate_limit_reported: false,
        truncated: false,
        source,
        control_applications: Vec::new(),
        control_unknowns: 0,
    };
    // Execution roots: every `main` plus the fixed set of framework-owned
    // methods whose annotation or containing class proves invocation.
    let roots: Vec<&JavaMethod> = file
        .methods
        .iter()
        .filter(|method| method.name == "main" || is_java_framework_root(&file, method))
        .collect();
    let entered_callables = !roots.is_empty();
    let mains: Vec<Node> = roots
        .iter()
        .filter(|method| method.name == "main")
        .map(|method| method.body)
        .collect();
    let main = match mains.as_slice() {
        [main] => Some(*main),
        _ => None,
    };
    builder.control_enter(source, false, |graph| {
        control::build_program(graph, root, main, source)
    });
    for m in roots {
        let mut visiting = HashSet::new();
        visiting.insert(m.body.id());
        let mut frame = JavaMethodFrame {
            env: m
                .params
                .iter()
                .map(|param| {
                    (
                        param.name.clone(),
                        ResourceExpr::Parameter {
                            name: param.name.clone(),
                        },
                    )
                })
                .collect(),
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
            arrays: HashMap::new(),
            process_argv: HashMap::new(),
            process_cwd: HashMap::new(),
            allocations: HashMap::new(),
            callbacks: HashMap::new(),
            locals: m.params.iter().map(|param| param.name.clone()).collect(),
            finals: HashSet::new(),
            tracked: HashSet::new(),
            giveups: HashSet::new(),
            poisoned: HashSet::new(),
            http_verbs: HashMap::new(),
            instance: HashMap::new(),
            class: m.class.clone(),
            constructor: false,
        };
        if Some(m.body) == main {
            ctx.control_body(builder, m.body, |ctx, builder| {
                ctx.walk_calls(builder, m.body, &mut frame, &mut visiting)
            });
            if let Some(application) = ctx.control_applications.pop() {
                builder.control_site(source, false, node_span(m.body), application);
            }
        } else {
            ctx.walk_calls(builder, m.body, &mut frame, &mut visiting);
        }
    }
    builder.control_leave();
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

fn is_java_framework_root(file: &JavaFile<'_>, method: &JavaMethod<'_>) -> bool {
    const TEST: [&str; 2] = ["org.junit.Test", "org.junit.jupiter.api.Test"];
    const TASK_ACTION: [&str; 1] = ["org.gradle.api.tasks.TaskAction"];
    const SCHEDULED: [&str; 1] = ["org.springframework.scheduling.annotation.Scheduled"];
    const POST_CONSTRUCT: [&str; 2] = [
        "javax.annotation.PostConstruct",
        "jakarta.annotation.PostConstruct",
    ];

    let annotated = method.annotations.iter().any(|annotation| {
        java_framework_name(file, annotation, "Test", &TEST)
            || java_framework_name(file, annotation, "TaskAction", &TASK_ACTION)
            || java_framework_name(file, annotation, "Scheduled", &SCHEDULED)
            || java_framework_name(file, annotation, "PostConstruct", &POST_CONSTRUCT)
    });
    if annotated {
        return true;
    }
    let Some(class) = file.class(&method.class) else {
        return false;
    };
    let has_base = |simple: &str, canonical: &[&str]| {
        class
            .bases
            .iter()
            .any(|base| java_framework_name(file, base, simple, canonical))
    };
    method.name == "execute" && has_base("AbstractMojo", &["org.apache.maven.plugin.AbstractMojo"])
        || matches!(method.name.as_str(), "onEnable" | "onDisable")
            && has_base("JavaPlugin", &["org.bukkit.plugin.java.JavaPlugin"])
        || matches!(method.name.as_str(), "call" | "run")
            && class.annotations.iter().any(|annotation| {
                java_framework_name(
                    file,
                    annotation,
                    "Command",
                    &["picocli.CommandLine.Command"],
                )
            })
            && (has_base("Callable", &["java.util.concurrent.Callable"])
                || has_base("Runnable", &["java.lang.Runnable"]))
        || method.name == "run"
            && (has_base(
                "CommandLineRunner",
                &["org.springframework.boot.CommandLineRunner"],
            ) || has_base(
                "ApplicationRunner",
                &["org.springframework.boot.ApplicationRunner"],
            ))
}

fn java_framework_name(
    file: &JavaFile<'_>,
    written: &str,
    simple: &str,
    canonical: &[&str],
) -> bool {
    let actual = written.rsplit('.').next().unwrap_or(written);
    if actual != simple || file.class(simple).is_some() {
        return false;
    }
    if written.contains('.') {
        return canonical.contains(&written);
    }
    file.imports
        .get(simple)
        .is_none_or(|resolved| canonical.contains(&resolved.as_str()))
}

/// Per-method execution frame: parameter value bindings, declared types of
/// locals and parameters, and locals' `new X(...)` initializers.
#[derive(Clone)]
struct JavaMethodFrame<'a> {
    env: HashMap<String, ResourceExpr>,
    types: HashMap<String, String>,
    news: HashMap<String, Vec<Node<'a>>>,
    arrays: HashMap<String, Vec<ResourceExpr>>,
    process_argv: HashMap<String, Vec<ResourceExpr>>,
    process_cwd: HashMap<String, ResourceExpr>,
    // Constructor state is reusable only within this method execution.
    allocations: HashMap<usize, HashMap<String, ResourceExpr>>,
    callbacks: HashMap<String, Vec<Node<'a>>>,
    locals: HashSet<String>,
    finals: HashSet<String>,
    tracked: HashSet<String>,
    giveups: HashSet<String>,
    poisoned: HashSet<String>,
    http_verbs: HashMap<String, String>,
    instance: HashMap<String, ResourceExpr>,
    class: String,
    constructor: bool,
}

struct JavaWalker<'a> {
    src: &'a [u8],
    file: &'a JavaFile<'a>,
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    max_nodes: u64,
    nodes: u64,
    fallback_boundaries: u32,
    candidate_limit_reported: bool,
    truncated: bool,
    source: &'a str,
    /// Guarantees of bodies entered since the enclosing call began.
    control_applications: Vec<SiteFacts>,
    /// Constructs met in the current body that may run unknown code: an
    /// unresolved call's boundary or a callback run under a callee.
    control_unknowns: usize,
}

impl<'a> JavaWalker<'a> {
    /// Evaluate an invocation or creation and register what it establishes.
    fn control_call(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        run: impl FnOnce(&mut Self, &mut PlanBuilder),
    ) {
        let since = builder.control_registered();
        let before = builder.effects_len();
        let unknowns = self.control_unknowns;
        let saved = std::mem::take(&mut self.control_applications);
        run(self, builder);
        let applied = std::mem::replace(&mut self.control_applications, saved);
        let clean = self.control_unknowns == unknowns;
        let direct_delete = n.kind() == "method_invocation"
            && n.child_by_field_name("name").is_some_and(|name| {
                matches!(java_node_text(name, self.src), "delete" | "deleteIfExists")
            })
            && n.child_by_field_name("object").is_some_and(|object| {
                java_node_text(object, self.src).rsplit('.').next() == Some("Files")
            });
        let mut facts = match applied.as_slice() {
            [] if clean && direct_delete => {
                SiteFacts::known(builder.control_own_effects(before..builder.effects_len()))
            }
            [] if clean => SiteFacts::known(Vec::new()),
            [entered] if clean => entered.clone(),
            _ => SiteFacts::unknown(),
        };
        let exits = n.kind() == "method_invocation"
            && n.child_by_field_name("name")
                .is_some_and(|name| matches!(java_node_text(name, self.src), "exit" | "halt"))
            && n.child_by_field_name("object").is_some_and(|object| {
                matches!(
                    java_node_text(object, self.src),
                    "System" | "Runtime.getRuntime()"
                )
            });
        if exits {
            facts.returns = false;
            facts.exit = None;
        }
        builder.control_site_since(self.source, false, node_span(n), since, facts);
    }

    /// Walk a method body in its own control-flow frame.
    fn control_body(
        &mut self,
        builder: &mut PlanBuilder,
        body: Node<'a>,
        run: impl FnOnce(&mut Self, &mut PlanBuilder),
    ) {
        let unknowns = self.control_unknowns;
        builder.control_enter(self.source, false, |graph| {
            control::build_body(graph, body, self.source)
        });
        run(self, builder);
        let application = match builder.control_leave() {
            Some(finished) => SiteFacts::call(&finished.requirements, Some),
            None => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
        self.control_unknowns = unknowns;
    }

    fn node(&self, builder: &mut PlanBuilder, n: Node) -> ProvenanceRef {
        builder.node(
            ProvenanceKind::SourceSpan {
                start: n.start_byte() as u32,
                end: n.end_byte() as u32,
            },
            self.scope.as_slice(),
        )
    }

    fn walk_calls(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        let depth = builder.condition_depth();
        self.walk_call_nodes(builder, n, frame, visiting);
        while builder.condition_depth() > depth {
            builder.pop_condition();
        }
    }

    fn walk_call_nodes(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
        visiting: &mut HashSet<usize>,
    ) {
        // Iterative: Java `+` is a left-deep binary_expression tree, one
        // frame per operator. A 20k concat overflows an 8MiB stack before
        // the node cap can fire.
        let mut stack = vec![n];
        let depth = builder.condition_depth();
        while let Some(n) = stack.pop() {
            while builder.condition_depth() > depth {
                builder.pop_condition();
            }
            if matches!(
                n.kind(),
                "method_invocation" | "object_creation_expression" | "assignment_expression"
            ) && let Some(condition) =
                conditions::tree_condition(std::str::from_utf8(self.src).unwrap(), n)
            {
                builder.push_condition(condition);
            }
            if !crate::nest::charge_analysis_steps(
                builder,
                self.nest.budget,
                1,
                Some((n.start_byte() as u32, n.end_byte() as u32)),
            ) {
                self.truncated = true;
                return;
            }
            self.nodes += 1;
            if self.nodes > self.max_nodes {
                if !self.truncated {
                    self.truncated = true;
                    if let Some(node) = self.boundary_node(builder, n) {
                        builder.boundary_with_coverage(
                            Boundary {
                                reason: BoundaryReason::PARTIAL_ANALYSIS,
                                class: BoundaryClass::Unmodeled,
                                scope: BoundaryScope::Invocation,
                                affected_resource: None,
                                callee: None,
                                domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                                provenance: vec![node],
                                limit: Some("max_java_nodes".to_string()),
                                detail: Some("java walk node budget exhausted".to_string()),
                            },
                            CoverageLevel::Partial,
                        );
                    }
                }
                return;
            }
            // Do not visit_java_syntax into nested declarations (anonymous class bodies
            // included) or lambdas while executing.
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
            if k == "local_variable_declaration" {
                self.record_local(n, frame);
            }
            if k == "enhanced_for_statement" {
                self.record_enhanced_for(n, frame);
            }
            if k == "assignment_expression" {
                self.record_callback_assignment(builder, n, frame);
            }
            if k == "update_expression" {
                self.record_update(n, frame);
            }
            if k == "method_invocation" {
                self.control_call(builder, n, |ctx, builder| {
                    ctx.handle_invocation(builder, n, frame, visiting)
                });
            }
            if k == "object_creation_expression" {
                self.control_call(builder, n, |ctx, builder| {
                    ctx.handle_creation(builder, n, frame, visiting)
                });
            }
            let mut cursor = n.walk();
            let children: Vec<Node<'a>> = n.children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn record_local(&self, n: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
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
            frame.locals.insert(name.clone());
            frame.callbacks.remove(&name);
            frame.news.remove(&name);
            frame.arrays.remove(&name);
            frame.process_argv.remove(&name);
            frame.process_cwd.remove(&name);
            frame.env.remove(&name);
            frame.http_verbs.remove(&name);
            frame.tracked.remove(&name);
            frame.giveups.remove(&name);
            frame.poisoned.remove(&name);
            if is_final {
                frame.finals.insert(name.clone());
            } else {
                frame.finals.remove(&name);
            }
            if ty == "var" {
                frame.types.remove(&name);
            }
            if let Some(value) = decl.child_by_field_name("value") {
                if matches!(value.kind(), "lambda_expression" | "method_reference") {
                    frame.callbacks.insert(name.clone(), vec![value]);
                }
                if value.kind() == "object_creation_expression" {
                    frame.news.insert(name.clone(), vec![value]);
                    if ty == "var"
                        && let Some(t) = value.child_by_field_name("type")
                    {
                        frame
                            .types
                            .insert(name.clone(), bare_java_type(java_node_text(t, self.src)));
                    }
                    if bare_java_type(
                        value
                            .child_by_field_name("type")
                            .map(|t| java_node_text(t, self.src))
                            .unwrap_or(""),
                    ) == "ProcessBuilder"
                    {
                        let argv = self.argv_from_creation(value, frame);
                        if !argv.is_empty() {
                            frame.process_argv.insert(name.clone(), argv);
                        }
                    }
                    if matches!(
                        bare_java_type(
                            value
                                .child_by_field_name("type")
                                .map(|t| java_node_text(t, self.src))
                                .unwrap_or(""),
                        )
                        .as_str(),
                        "ArrayList" | "LinkedList"
                    ) {
                        let argv = self.argv_from_expr(value, frame);
                        if !argv.is_empty() {
                            frame.arrays.insert(name.clone(), argv);
                        }
                    }
                }
                let argv = self.argv_from_expr(value, frame);
                if !argv.is_empty()
                    && (ty.contains("[]")
                        || matches!(ty.as_str(), "List" | "ArrayList" | "String[]" | "var")
                        || value.kind() == "array_initializer"
                        || value.kind() == "array_creation_expression")
                {
                    frame.arrays.insert(name.clone(), argv);
                }
                if tracked_local_type(&ty)
                    || matches!(ty.as_str(), "HttpURLConnection" | "HttpRequest")
                {
                    if tracked_initializer(value, self.src, &self.file.constants) {
                        let resolved = recover_typed_java_resource(
                            value,
                            self.src,
                            &frame.env,
                            &self.file.constants,
                            &frame.types,
                        );
                        frame.tracked.insert(name.clone());
                        if is_unresolved(&resolved) {
                            frame.giveups.insert(name.clone());
                        }
                        frame.env.insert(name.clone(), resolved);
                    }
                    if let Some(verb) =
                        http_verb_of_expr(value, self.src, &frame.http_verbs, &self.file.constants)
                    {
                        frame.http_verbs.insert(name.clone(), verb);
                    }
                }
            }
            if ty != "var" {
                frame.types.insert(name.clone(), ty.clone());
            }
            if frame.tracked.contains(&name) {
                let mutations = local_mutations(n, &name, self.src);
                if (!is_final && mutations.reassigned) || mutations.array_element_assigned {
                    poison_local(&name, frame);
                }
            }
        }
    }

    fn record_enhanced_for(&self, n: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
        let (Some(ty), Some(name), Some(value)) = (
            n.child_by_field_name("type"),
            n.child_by_field_name("name"),
            n.child_by_field_name("value"),
        ) else {
            return;
        };
        let name = java_node_text(name, self.src).to_string();
        frame.locals.insert(name.clone());
        frame
            .types
            .insert(name.clone(), bare_java_type(java_node_text(ty, self.src)));
        frame.env.remove(&name);
        frame.tracked.remove(&name);
        frame.giveups.remove(&name);
        if let Some(element) = iterable_element(value, self.src, &frame.env, &self.file.constants) {
            frame.tracked.insert(name.clone());
            if is_unresolved(&element) {
                frame.giveups.insert(name.clone());
            }
            frame.env.insert(name.clone(), element);
            let mutations = local_mutations(n, &name, self.src);
            if mutations.reassigned || mutations.array_element_assigned {
                poison_local(&name, frame);
            }
        }
    }

    fn record_update(&self, n: Node<'a>, frame: &mut JavaMethodFrame<'a>) {
        let Some(target) = n.named_child(0) else {
            return;
        };
        if target.kind() == "identifier" {
            let name = java_node_text(target, self.src);
            if frame.tracked.contains(name) && !frame.finals.contains(name) {
                poison_local(name, frame);
            }
        }
    }

    fn record_callback_assignment(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
    ) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        if frame.constructor
            && let Some(class) = self.file.class(&frame.class)
            && let Some(field) = assigned_instance_field(n, class, &frame.locals, self.src)
            && !class.mutable_fields.contains(&field)
        {
            let value = if class.unstable_constructor_fields.contains(&field) {
                frame.giveups.insert(field.clone());
                unresolved_resource("filesystem")
            } else {
                recover_typed_java_resource(
                    right,
                    self.src,
                    &frame.env,
                    &self.file.constants,
                    &frame.types,
                )
            };
            frame.env.insert(field.clone(), value.clone());
            frame.instance.insert(field, value);
            return;
        }
        let Some((name, array_element)) = assigned_local(left, self.src) else {
            return;
        };
        if frame.tracked.contains(&name) && (array_element || !frame.finals.contains(&name)) {
            poison_local(&name, frame);
        }
        if array_element {
            // Element writes invalidate recovered argv words.
            invalidate_argv_local(&name, frame);
            return;
        }
        let guarded = is_guarded_java_assignment(n, self.src);
        if !guarded {
            frame.callbacks.remove(&name);
            frame.news.remove(&name);
        }
        // Reassignment must not keep the discarded first argv as fact.
        invalidate_argv_local(&name, frame);
        if !guarded {
            self.bind_assigned_argv(&name, right, frame);
        }
        let truncated = if matches!(right.kind(), "lambda_expression" | "method_reference") {
            push_node_candidate(&mut frame.callbacks, name.clone(), right)
        } else if right.kind() == "object_creation_expression" {
            push_node_candidate(&mut frame.news, name, right)
        } else {
            false
        };
        if truncated && !self.candidate_limit_reported {
            self.candidate_limit_reported = true;
            self.candidate_limit(builder, n);
        }
    }

    fn boundary_node(&mut self, builder: &mut PlanBuilder, n: Node) -> Option<ProvenanceRef> {
        if self.fallback_boundaries >= 32 {
            if self.fallback_boundaries == 32 {
                self.fallback_boundaries += 1;
                let node = self.node(builder, n);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: ALL_DOMAINS
                        .iter()
                        .map(|domain| Domain::new(*domain))
                        .collect(),
                    provenance: vec![node],
                    limit: Some("max_java_call_boundaries".to_string()),
                    detail: None,
                });
            }
            return None;
        }
        self.fallback_boundaries += 1;
        let node = self.node(builder, n);
        Some(node)
    }

    fn boundary(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: &str,
        domains: Domains,
    ) {
        self.control_unknowns += 1;
        let Some(node) = self.boundary_node(builder, n) else {
            return;
        };
        builder.boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: n
                .child_by_field_name("name")
                .map(|name| effinterp_proto::CalleeReference {
                    module: n
                        .child_by_field_name("object")
                        .map_or("java", |object| java_node_text(object, self.src))
                        .to_string(),
                    symbol: java_node_text(name, self.src).to_string(),
                }),
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
        for d in domains {
            builder.declare_coverage(Domain::new(*d), CoverageLevel::Partial);
        }
    }

    fn emit_giveup_boundaries(
        &mut self,
        builder: &mut PlanBuilder,
        sink: Node,
        frame: &JavaMethodFrame,
        ops: &[ModeledOp],
    ) {
        let mut names = tracked_giveups_in(sink, self.src, &frame.giveups);
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
                self.boundary_with_resource(
                    builder,
                    sink,
                    BoundaryReason::UNMODELED_DYNAMIC,
                    &format!("java local {name} value is unmodeled"),
                    domain,
                );
            }
        }
    }

    fn boundary_with_resource(
        &mut self,
        builder: &mut PlanBuilder,
        n: Node,
        reason: BoundaryReason,
        detail: &str,
        domain: &'static str,
    ) {
        let Some(node) = self.boundary_node(builder, n) else {
            return;
        };
        builder.boundary(Boundary {
            reason,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(unresolved_resource(domain)),
            callee: None,
            domains: vec![Domain::new(domain)],
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }

    fn candidate_limit(&mut self, builder: &mut PlanBuilder, n: Node) {
        let Some(node) = self.boundary_node(builder, n) else {
            return;
        };
        builder.boundary(Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: ALL_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: Some("max_callback_values".to_string()),
            detail: Some("java callback or receiver candidate limit exceeded".to_string()),
        });
        builder.global_opacity(CoverageLevel::Partial);
    }

    /// Emit modeled effects and pair the transfer endpoints the model named,
    /// so a source-to-destination movement is recorded where it is lowered.
    fn emit_ops(
        &self,
        builder: &mut PlanBuilder,
        n: Node,
        ops: Vec<ModeledOp>,
        transfer: Option<ModeledTransfer>,
    ) {
        let mut emitted = Vec::with_capacity(ops.len());
        for (op, resource, attr) in ops {
            let slot = self.emit(builder, n, op, resource, attr);
            emitted.push((op, slot));
        }
        let Some(transfer) = transfer else {
            return;
        };
        let find = |operation: &str| {
            emitted
                .iter()
                .find(|(op, _)| *op == operation)
                .and_then(|(_, slot)| *slot)
        };
        if let (Some(source), Some(destination)) =
            (find(transfer.source), find(transfer.destination))
        {
            builder.transfer_binding(TransferBinding::new(source, destination));
        }
    }

    fn emit(
        &self,
        builder: &mut PlanBuilder,
        n: Node,
        op: &str,
        resource: ResourceExpr,
        attr: Option<&'static str>,
    ) -> Option<u32> {
        let node = self.node(builder, n);
        let mut effect = Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(op),
            resource,
            attributes: op_attributes(attr),
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: conditions::tree_condition(
                std::str::from_utf8(self.src).expect("parsed UTF-8 source"),
                n,
            ),
            realm: Default::default(),
            provenance: vec![node],
        };
        builder.bind_source_condition(&mut effect.condition);
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        if effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource) {
            effect.provenance.extend(self.cwd_node);
        }
        builder.effect(effect)
    }
}

fn poison_local(name: &str, frame: &mut JavaMethodFrame<'_>) {
    frame.poisoned.insert(name.to_string());
    frame.giveups.insert(name.to_string());
    frame
        .env
        .insert(name.to_string(), unresolved_resource("filesystem"));
    invalidate_argv_local(name, frame);
}
