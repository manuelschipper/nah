//! PHP constructor and method dispatch across local and PSR-4 classes.

use std::collections::{HashMap, HashSet};

use effinterp_proto::{BoundaryClass, BoundaryReason, ProvenanceRef, ResourceExpr, Subject};
use tree_sitter::Node;

use crate::builder::PlanBuilder;
use crate::nest::{Nest, SourceResolution, Transition};
use crate::paths::{join_file, parent_dir};
use crate::summary::contains_unresolved;
use crate::{SourcePurpose, SourceRefusal};

use super::super::file_context::{
    PhpFileContext, collect_php_file_context, php_constructed_class, resolve_php_class_name,
};
use super::super::parse;
use super::super::syntax::{arg_nodes, child_kind, param_names, text, this_property};
use super::super::{CALL_DEPTH_LIMIT, CLASS_CHAIN_LIMIT};
use super::call_resolution::{bind_php_params, collect_php_functions};
use super::{PhpCall, PhpSourceState, PhpWalker};

/// Framework template methods: `parent::run` on a class extending the vendored
/// Symfony Console Application re-enters the subclass through `doRun`, so the
/// effects it performs before command dispatch surface instead of vanishing
/// behind the external parent.
const TEMPLATE_CALLBACKS: &[(&str, &str, &str)] =
    &[("Symfony\\Component\\Console\\Application", "run", "doRun")];

/// Seed console entry methods only for classes with a recognized framework base.
pub(super) fn php_framework_roots<'a>(
    root: Node<'a>,
    source: &str,
    ctx: &PhpFileContext,
) -> Vec<(String, String, Node<'a>)> {
    const COMMAND_BASES: [&str; 2] = [
        "Illuminate\\Console\\Command",
        "Symfony\\Component\\Console\\Command\\Command",
    ];
    let mut roots = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_declaration"
            && let Some(short) = child_kind(node, "name")
            && let Some(base) = child_kind(node, "base_clause").and_then(|base| {
                base.named_children(&mut base.walk())
                    .find(|child| matches!(child.kind(), "name" | "qualified_name"))
            })
            && COMMAND_BASES.contains(&resolve_php_class_name(ctx, text(base, source)).as_str())
        {
            let class = resolve_php_class_name(ctx, text(short, source));
            for method in ["handle", "execute", "__invoke"] {
                if find_method_in(node, source, method).is_some() {
                    roots.push((class.clone(), method.to_string(), node));
                }
            }
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    roots
}

/// Outcome of trying to run one class's method in its defining file.
enum PhpMethodRun {
    Ran,
    /// The class is declared there but the method is not; `parent` is its
    /// resolved base class, where lookup continues.
    ClassWithoutMethod {
        parent: Option<String>,
        traits: Vec<String>,
    },
    Missing,
}

/// Execute `class::method` (or its constructor) in `source`, the file PSR-4
/// resolution mapped the class to, as a budget-bounded nested invocation.
/// Mirrors the include edge: effects attribute to `path`, and the method body
/// runs with the file's own namespace/imports context.
#[allow(clippy::too_many_arguments)]
fn run_php_class_method(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    path: &str,
    provenance: &[ProvenanceRef],
    depth: u64,
    cwd_node: Option<ProvenanceRef>,
    inc: &mut PhpSourceState,
    class: &str,
    method: &str,
    args: &[ResourceExpr],
) -> PhpMethodRun {
    let Some(tree) = parse(source) else {
        return PhpMethodRun::Missing;
    };
    let root = tree.root_node();
    let ctx = collect_php_file_context(root, source);
    inc.consts.extend(ctx.top_consts.clone());
    let current_class = resolve_php_class_name(&ctx, class);
    let Some((class_node, parent_raw)) = find_class(root, source, class) else {
        return PhpMethodRun::Missing;
    };
    let parent = parent_raw.map(|p| resolve_php_class_name(&ctx, &p));
    let Some((params, body)) = find_method_in(class_node, source, method) else {
        let traits = class_traits(class_node, source)
            .into_iter()
            .map(|name| resolve_php_class_name(&ctx, &name))
            .collect();
        return PhpMethodRun::ClassWithoutMethod { parent, traits };
    };
    // One analysis per (file, class, method, argument shape): repeats add no
    // information, and the stack check breaks recursion cycles.
    let key = format!("{path}#{class}#{method}#{args:?}");
    if inc.dispatch_stack.iter().any(|k| k == &key) || !inc.dispatched.insert(key.clone()) {
        return PhpMethodRun::Ran;
    }
    let dir = parent_dir(path);
    let runtime_cwd = nest.current_runtime_cwd();
    let cwd_resource = builder.current_execution_cwd();
    let Some(frame) = nest.begin(
        builder,
        Transition::file(Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: source.to_string(),
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        })
        .origin(path.to_string())
        .cwd(cwd_resource, cwd_node),
        provenance,
        depth,
    ) else {
        return PhpMethodRun::Ran;
    };
    let node = frame.scope;
    inc.dispatch_stack.push(key);
    let functions = collect_php_functions(root, source);
    let runtime_cwd_resource = builder.current_execution_cwd();
    let mut w = PhpWalker {
        control_applications: Vec::new(),
        builder,
        nest,
        src: source,
        root,
        source_cwd: Some(&dir),
        runtime_cwd: runtime_cwd.as_deref(),
        runtime_cwd_resource,
        cwd_node,
        scope: Some(node),
        depth: depth + 1,
        functions: &functions,
        following: HashSet::new(),
        entered_callables: HashSet::new(),
        call_depth: 0,
        nodes: nest.limits.max_php_nodes,
        reported: HashSet::new(),
        inc,
        ctx,
        current_class: Some(current_class.clone()),
        class_parent: parent,
        vars: HashMap::new(),
        locals: HashMap::new(),
        network_handles: HashMap::new(),
        eval_code: HashMap::new(),
        request_bodies: HashMap::new(),
        examined_contexts: HashSet::new(),
        poisoned: HashSet::new(),
        closures: HashMap::new(),
        handled_closures: HashSet::new(),
        active_closures: HashSet::new(),
        truncated: false,
        environment_rewritten: false,
        printed_captures: HashSet::new(),
        captured_outputs: HashMap::new(),
        capture_locals: HashMap::new(),
        truth_locals: HashMap::new(),
        globals_written: false,
        global_facts: None,
    };
    let env = bind_php_params(&params, args);
    if method == "__construct" {
        w.record_constructor_props(&current_class, body, &env);
    }
    let mut c = body.walk();
    let children: Vec<Node> = body.named_children(&mut c).collect();
    w.exec_statements(&children, &env);
    w.inc.dispatch_stack.pop();
    frame.end(builder);
    PhpMethodRun::Ran
}

/// The class declaration named `class` and its base class as written.
fn find_class<'a>(root: Node<'a>, src: &str, class: &str) -> Option<(Node<'a>, Option<String>)> {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "class_declaration" | "trait_declaration")
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == class)
        {
            let parent = child_kind(n, "base_clause").and_then(|b| {
                let mut c = b.walk();
                b.named_children(&mut c)
                    .find(|x| matches!(x.kind(), "name" | "qualified_name"))
                    .map(|x| text(x, src).to_string())
            });
            return Some((n, parent));
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            stack.push(ch);
        }
    }
    None
}

fn class_traits(class_node: Node, src: &str) -> Vec<String> {
    let Some(body) = class_node.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut traits = Vec::new();
    let mut cursor = body.walk();
    for declaration in body
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "use_declaration")
    {
        let mut cursor = declaration.walk();
        traits.extend(
            declaration
                .named_children(&mut cursor)
                .filter(|node| matches!(node.kind(), "name" | "qualified_name"))
                .map(|node| text(node, src).to_string()),
        );
    }
    traits
}

/// `method`'s parameters and body within a class declaration (abstract
/// bodiless methods do not count).
fn find_method_in<'a>(
    class_node: Node<'a>,
    src: &str,
    method: &str,
) -> Option<(Vec<String>, Node<'a>)> {
    let body = class_node.child_by_field_name("body")?;
    let mut c = body.walk();
    for m in body.named_children(&mut c) {
        if m.kind() == "method_declaration"
            && m.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == method)
            && let Some(mb) = child_kind(m, "compound_statement")
        {
            let params = child_kind(m, "formal_parameters")
                .map(|p| param_names(p, src))
                .unwrap_or_default();
            return Some((params, mb));
        }
    }
    None
}

/// Conventional PSR-4 paths for `Foo\Bar\Baz`: each suffix under `src/`,
/// `lib/`, and the repo root. First existing file that declares the FQN wins.
fn psr4_layout_paths(fqcn: &str) -> Vec<String> {
    let parts: Vec<&str> = fqcn.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for start in 0..parts.len() {
        let rest = parts[start..].join("/");
        out.push(format!("/src/{rest}.php"));
        out.push(format!("/lib/{rest}.php"));
        out.push(format!("/{rest}.php"));
    }
    out
}

fn file_declares_class(source: &str, fqcn: &str) -> bool {
    let Some(tree) = parse(source) else {
        return false;
    };
    let root = tree.root_node();
    let ctx = collect_php_file_context(root, source);
    let (ns, short) = match fqcn.rsplit_once('\\') {
        Some((n, s)) => (Some(n), s),
        None => (None, fqcn),
    };
    ctx.namespace.as_deref() == ns && find_class(root, source, short).is_some()
}

/// The `autoload.psr-4` map of the root composer.json (namespace prefix ->
/// source dir), longest prefix first. Empty when there is no resolver, no
/// composer.json, or no PSR-4 autoload section.
fn load_psr4(nest: &Nest, builder: &mut PlanBuilder) -> Vec<(String, String)> {
    let SourceResolution::Source { source: src, .. } =
        nest.resolve_source(builder, "/composer.json", SourcePurpose::DependencySource)
    else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&src) else {
        return Vec::new();
    };
    let Some(map) = v
        .get("autoload")
        .and_then(|a| a.get("psr-4"))
        .and_then(|m| m.as_object())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (prefix, dirs) in map {
        match dirs {
            serde_json::Value::String(d) => out.push((prefix.clone(), d.clone())),
            serde_json::Value::Array(list) => {
                for d in list.iter().filter_map(|d| d.as_str()) {
                    out.push((prefix.clone(), d.to_string()));
                }
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.cmp(b)));
    out
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// Enter class bodies only for known receivers and statically named methods.
    pub(super) fn dispatch_php_method_call(
        &mut self,
        n: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) {
        // By field, not kind: a scoped call's scope is also a `name` node.
        let method = n
            .child_by_field_name("name")
            .filter(|m| m.kind() == "name")
            .map(|m| text(m, self.src).to_string())
            .unwrap_or_default();
        let args = arg_nodes(n);
        self.invoke_callback_arguments(&args, n, env, None);
        // Statically-typed dispatch: `$this`/`self`/`static` reach the current
        // file's methods, `parent` the resolved base class, `X::m()` and
        // `$var->m()` (a variable constructed from a resolvable class) the
        // named class. Untyped receivers never dispatch.
        if !method.is_empty() {
            let args: Vec<ResourceExpr> = args
                .iter()
                .map(|argument| self.recover_php_argument(*argument, env))
                .collect();
            if n.kind() == "member_call_expression" {
                if let Some(obj) = n.child_by_field_name("object") {
                    if let Some(class) = self.member_receiver_class(obj)
                        && (self.dispatch_local_php_method(&class, &method, &args, n)
                            || self.dispatch_psr4_php_method(&class, &method, &args, n))
                    {
                        return;
                    }
                    if obj.kind() != "variable_name" {
                        // Dynamic and nested receivers retain their existing
                        // unmodeled behavior below.
                    } else {
                        let var = child_kind(obj, "name")
                            .map(|x| text(x, self.src))
                            .unwrap_or("");
                        if var == "this" {
                            if let Some(class) = self.current_class.clone()
                                && self.dispatch_local_php_method(&class, &method, &args, n)
                            {
                                return;
                            }
                            if let Some(p) = self.class_parent.clone()
                                && self.dispatch_psr4_php_method(&p, &method, &args, n)
                            {
                                return;
                            }
                            // Unknown `$this` method: inherited from an external
                            // parent; effectless like unknown plain calls.
                        } else if let Some(classes) = self.vars.get(var).cloned() {
                            let mut dispatched = false;
                            for fq in classes {
                                dispatched |= self
                                    .dispatch_local_php_method(&fq, &method, &args, n)
                                    || self.dispatch_psr4_php_method(&fq, &method, &args, n);
                            }
                            if dispatched {
                                return;
                            }
                        }
                    }
                }
            } else if let Some(scope) = n.child_by_field_name("scope") {
                match scope.kind() {
                    "relative_scope" => match text(scope, self.src) {
                        "self" | "static" => {
                            if let Some(class) = self.current_class.clone()
                                && self.dispatch_local_php_method(&class, &method, &args, n)
                            {
                                return;
                            }
                        }
                        "parent" => {
                            self.parent_call(&method, &args, n);
                            return;
                        }
                        _ => {}
                    },
                    "name" | "qualified_name" => {
                        let raw = text(scope, self.src);
                        let fq = resolve_php_class_name(&self.ctx, raw);
                        if self.dispatch_local_php_method(&fq, &method, &args, n) {
                            return;
                        }
                        if self.resolve_php_class_file(&fq).is_some() {
                            self.dispatch_psr4_php_method(&fq, &method, &args, n);
                        } else {
                            self.opaque(
                                BoundaryReason::EXTERNAL_UNMODELED,
                                BoundaryClass::Unmodeled,
                                n,
                            );
                        }
                        return;
                    }
                    _ => {}
                }
            }
        }
        // `$obj->exec("SQL")` / `Class::query("SQL")`: PHP is dynamic, so any
        // exec/query/prepare with a SQL-looking literal is treated as a query.
        if matches!(
            method.as_str(),
            "exec" | "query" | "prepare" | "executeQuery" | "executeStatement"
        ) {
            self.nest_sql(arg_nodes(n).first().copied(), n);
        }
    }

    fn member_receiver_class(&self, mut node: Node<'a>) -> Option<String> {
        while node.kind() == "parenthesized_expression" {
            node = node.named_child(0)?;
        }
        if node.kind() == "object_creation_expression" {
            return php_constructed_class(node, self.src, &self.ctx);
        }
        if node.kind() != "scoped_call_expression" {
            return None;
        }
        let scope = node.child_by_field_name("scope")?;
        if !matches!(scope.kind(), "name" | "qualified_name") {
            return None;
        }
        let class = resolve_php_class_name(&self.ctx, text(scope, self.src));
        let method = node
            .child_by_field_name("name")
            .map(|name| text(name, self.src))?;
        let (class_node, _) = self.local_class(&class)?;
        self.local_method_return_class(class_node, method)
    }

    fn local_method_return_class(&self, class: Node<'a>, method: &str) -> Option<String> {
        let body = class.child_by_field_name("body")?;
        let declaration = body.named_children(&mut body.walk()).find(|candidate| {
            candidate.kind() == "method_declaration"
                && candidate
                    .child_by_field_name("name")
                    .is_some_and(|name| text(name, self.src) == method)
        })?;
        let method_body = child_kind(declaration, "compound_statement")?;
        let mut returned = Vec::new();
        let mut stack = vec![method_body];
        while let Some(node) = stack.pop() {
            if node.kind() == "return_statement" {
                let value = node.named_child(0)?;
                let mut value = value;
                while value.kind() == "parenthesized_expression" {
                    value = value.named_child(0)?;
                }
                if value.kind() != "object_creation_expression" {
                    return None;
                }
                let raw = value
                    .named_children(&mut value.walk())
                    .find(|child| {
                        matches!(child.kind(), "name" | "qualified_name" | "relative_scope")
                    })
                    .map(|name| text(name, self.src))?;
                let class_name = if matches!(raw, "self" | "static") {
                    child_kind(class, "name")
                        .map(|name| resolve_php_class_name(&self.ctx, text(name, self.src)))?
                } else {
                    resolve_php_class_name(&self.ctx, raw)
                };
                returned.push(class_name);
                continue;
            }
            if matches!(
                node.kind(),
                "function_definition"
                    | "method_declaration"
                    | "anonymous_function"
                    | "arrow_function"
            ) && node.id() != method_body.id()
            {
                continue;
            }
            let mut cursor = node.walk();
            let children: Vec<Node> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
        let first = returned.first()?.clone();
        returned
            .iter()
            .all(|class| class == &first)
            .then_some(first)
    }

    /// `parent::m(...)`: dispatch into the resolved base class; when the base
    /// is external, a curated framework template callback re-enters this class
    /// (Symfony's `run` -> `doRun`); otherwise the call stays a loud boundary.
    fn parent_call(&mut self, method: &str, args: &[ResourceExpr], n: Node<'a>) {
        let Some(p) = self.class_parent.clone() else {
            return;
        };
        if self.dispatch_local_php_method(&p, method, args, n)
            || self.resolve_php_class_file(&p).is_some()
                && self.dispatch_psr4_php_method(&p, method, args, n)
        {
            return;
        }
        if let Some((_, _, cb)) = TEMPLATE_CALLBACKS
            .iter()
            .find(|(cls, m, _)| *cls == p && *m == method)
            && let Some(class) = self.current_class.clone()
            && self.dispatch_local_php_method(&class, cb, &[], n)
        {
            return;
        }
        self.opaque(
            BoundaryReason::EXTERNAL_UNMODELED,
            BoundaryClass::Unmodeled,
            n,
        );
    }

    /// `new X(...)`: run the constructor of a statically-named, PSR-4
    /// resolvable class; a vendored class is an external boundary and a
    /// dynamic class name a typed boundary.
    pub(super) fn dispatch_php_constructor(
        &mut self,
        n: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> PhpCall {
        let mut c = n.walk();
        let Some(cn) = n
            .named_children(&mut c)
            .find(|x| matches!(x.kind(), "name" | "qualified_name"))
        else {
            let mut c2 = n.walk();
            if n.named_children(&mut c2)
                .any(|x| matches!(x.kind(), "variable_name" | "dynamic_variable_name"))
            {
                self.opaque(BoundaryReason::DYNAMIC_CLASS, BoundaryClass::Unresolved, n);
            }
            return PhpCall::Opaque;
        };
        let raw = text(cn, self.src).to_string();
        let args: Vec<ResourceExpr> = arg_nodes(n)
            .iter()
            .map(|argument| self.recover_php_argument(*argument, env))
            .collect();
        let fq = resolve_php_class_name(&self.ctx, &raw);
        // A same-file class with no constructor anywhere in reach runs none.
        let constructorless = self.local_class(&fq).is_some_and(|(class, parent)| {
            parent.is_none()
                && class_traits(class, self.src).is_empty()
                && find_method_in(class, self.src, "__construct").is_none()
        });
        if self.dispatch_local_php_method(&fq, "__construct", &args, n) {
            return if constructorless {
                PhpCall::Modeled
            } else {
                PhpCall::Entered
            };
        }
        if self.resolve_php_class_file(&fq).is_some() {
            // The constructor may be absent (or inherited): the instance is
            // still typed; dispatch runs whatever constructor the chain has.
            self.dispatch_psr4_php_method(&fq, "__construct", &args, n);
            PhpCall::Opaque
        } else {
            self.opaque(
                BoundaryReason::EXTERNAL_UNMODELED,
                BoundaryClass::Unmodeled,
                n,
            );
            PhpCall::Opaque
        }
    }

    pub(super) fn local_class(&self, fqcn: &str) -> Option<(Node<'a>, Option<String>)> {
        let class = fqcn.rsplit('\\').next().unwrap_or(fqcn);
        if resolve_php_class_name(&self.ctx, class) != fqcn {
            return None;
        }
        find_class(self.root, self.src, class)
    }

    pub(super) fn dispatch_local_php_method(
        &mut self,
        fqcn: &str,
        method: &str,
        args: &[ResourceExpr],
        site: Node<'a>,
    ) -> bool {
        self.dispatch_local_inner(fqcn, method, args, site, &mut HashSet::new(), 0)
    }

    fn dispatch_local_inner(
        &mut self,
        fqcn: &str,
        method: &str,
        args: &[ResourceExpr],
        site: Node<'a>,
        seen: &mut HashSet<String>,
        depth: u64,
    ) -> bool {
        if depth >= CLASS_CHAIN_LIMIT || !seen.insert(fqcn.to_string()) {
            return true;
        }
        let Some((class_node, parent_raw)) = self.local_class(fqcn) else {
            return false;
        };
        if let Some((params, body)) = find_method_in(class_node, self.src, method) {
            let parent = parent_raw.map(|name| resolve_php_class_name(&self.ctx, &name));
            self.run_local_method(fqcn, method, &params, body, parent, args);
            return true;
        }
        for name in class_traits(class_node, self.src) {
            let trait_name = resolve_php_class_name(&self.ctx, &name);
            if self.dispatch_local_inner(&trait_name, method, args, site, seen, depth + 1)
                || self.dispatch_psr4_php_method(&trait_name, method, args, site)
            {
                return true;
            }
        }
        if let Some(parent) = parent_raw.map(|name| resolve_php_class_name(&self.ctx, &name)) {
            return self.dispatch_local_inner(&parent, method, args, site, seen, depth + 1)
                || self.dispatch_psr4_php_method(&parent, method, args, site);
        }
        method == "__construct"
    }

    fn run_local_method(
        &mut self,
        fqcn: &str,
        method: &str,
        params: &[String],
        body: Node<'a>,
        parent: Option<String>,
        args: &[ResourceExpr],
    ) {
        let key = format!("{fqcn}::{method}");
        if self.call_depth >= CALL_DEPTH_LIMIT || !self.following.insert(key.clone()) {
            return;
        }
        self.entered_callables.insert(key.clone());
        self.call_depth += 1;
        let caller_closures = std::mem::take(&mut self.closures);
        let caller_vars = std::mem::take(&mut self.vars);
        let caller_locals = std::mem::take(&mut self.locals);
        let caller_network_handles = std::mem::take(&mut self.network_handles);
        let caller_poisoned = std::mem::take(&mut self.poisoned);
        let caller_captures = std::mem::take(&mut self.capture_locals);
        let caller_truths = std::mem::take(&mut self.truth_locals);
        let caller_globals_written = std::mem::take(&mut self.globals_written);
        let outermost = self.enter_facts(&caller_captures, &caller_truths);
        let caller_class = self.current_class.replace(fqcn.to_string());
        let caller_parent = std::mem::replace(&mut self.class_parent, parent);
        let env = bind_php_params(params, args);
        if method == "__construct" {
            self.record_constructor_props(fqcn, body, &env);
        }
        let mut cursor = body.walk();
        let statements: Vec<Node> = body.named_children(&mut cursor).collect();
        self.control_body(body, |w| w.exec_statements(&statements, &env));
        self.class_parent = caller_parent;
        self.current_class = caller_class;
        self.vars = caller_vars;
        self.locals = caller_locals;
        self.network_handles = caller_network_handles;
        self.poisoned = caller_poisoned;
        self.closures = caller_closures;
        self.restore_facts(caller_captures, caller_truths, caller_globals_written);
        if outermost {
            self.global_facts = None;
        }
        self.call_depth -= 1;
        self.following.remove(&key);
    }

    fn record_constructor_props(
        &mut self,
        fqcn: &str,
        body: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) {
        let mut values = HashMap::new();
        if let Some(method) = body.parent()
            && let Some(parameters) = child_kind(method, "formal_parameters")
        {
            let mut cursor = parameters.walk();
            for parameter in parameters
                .named_children(&mut cursor)
                .filter(|parameter| parameter.kind() == "property_promotion_parameter")
            {
                let Some(variable) = parameter.child_by_field_name("name") else {
                    continue;
                };
                let Some(name) = child_kind(variable, "name").map(|name| text(name, self.src))
                else {
                    continue;
                };
                if let Some(value) = env.get(name) {
                    values.insert(name.to_string(), value.clone());
                }
            }
        }
        let mut stack = vec![body];
        while let Some(node) = stack.pop() {
            if node.kind() == "assignment_expression"
                && let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                )
                && let Some(property) = this_property(left, self.src)
                && matches!(right.kind(), "string" | "encapsed_string" | "variable_name")
            {
                let value = self.recover_php_argument(right, env);
                if !contains_unresolved(&value) {
                    values.insert(property, value);
                }
            }
            if !matches!(
                node.kind(),
                "function_definition"
                    | "method_declaration"
                    | "anonymous_function"
                    | "arrow_function"
                    | "class_declaration"
            ) || node.id() == body.id()
            {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
        self.inc.props.insert(fqcn.to_string(), values);
    }

    /// Run `fqcn::method` where the class (or an own-namespace ancestor
    /// declaring the method) resolves to a repo file. True when a defining
    /// file was found — even if the specific method body was absent along a
    /// fully-own chain that ends without it.
    pub(super) fn dispatch_psr4_php_method(
        &mut self,
        fqcn: &str,
        method: &str,
        args: &[ResourceExpr],
        site: Node<'a>,
    ) -> bool {
        let site_ref = self.span(site);
        let mut cur = fqcn.to_string();
        for _ in 0..CLASS_CHAIN_LIMIT {
            let Some((path, source)) = self.resolve_php_class_file(&cur) else {
                return false;
            };
            match run_php_class_method(
                self.builder,
                self.nest,
                &source,
                &path,
                &[site_ref],
                self.depth,
                self.cwd_node,
                self.inc,
                cur.rsplit('\\').next().unwrap_or(&cur),
                method,
                args,
            ) {
                PhpMethodRun::Ran => return true,
                PhpMethodRun::ClassWithoutMethod { parent, traits } => {
                    for trait_name in traits {
                        if self.dispatch_psr4_php_method(&trait_name, method, args, site) {
                            return true;
                        }
                    }
                    if let Some(parent) = parent {
                        cur = parent;
                    } else {
                        return method == "__construct";
                    }
                }
                PhpMethodRun::Missing => return method == "__construct",
            }
        }
        true
    }

    /// The repo file defining `fqcn`: composer.json `autoload.psr-4` first,
    /// then conventional `src/` / `lib/` PSR-4 layout. A layout candidate is
    /// accepted only when the file declares that FQN, so a stray `src/Foo.php`
    /// cannot satisfy `Vendor\Foo`. A prefix match whose file is absent (a
    /// vendored package) stays unresolved.
    pub(super) fn resolve_php_class_file(&mut self, fqcn: &str) -> Option<(String, String)> {
        if self.inc.psr4.is_none() {
            self.inc.psr4 = Some(load_psr4(self.nest, self.builder));
        }
        let entries = self.inc.psr4.clone().unwrap_or_default();
        for (prefix, dir) in entries {
            let Some(rest) = fqcn.strip_prefix(&prefix) else {
                continue;
            };
            let sep = if dir.ends_with('/') { "" } else { "/" };
            let rel = format!("/{dir}{sep}{}.php", rest.replace('\\', "/"));
            let Some(path) = join_file(None, &rel) else {
                continue;
            };
            if let Some(source) = self.file_source(&path) {
                return Some((path, source));
            }
        }
        for path in psr4_layout_paths(fqcn) {
            if let Some(source) = self.file_source(&path)
                && file_declares_class(&source, fqcn)
            {
                return Some((path, source));
            }
        }
        None
    }

    fn file_source(&mut self, path: &str) -> Option<String> {
        if let Some(hit) = self.inc.sources.get(path) {
            return hit.clone();
        }
        let got =
            match self
                .nest
                .resolve_source(self.builder, path, SourcePurpose::DependencySource)
            {
                SourceResolution::Source { source, .. } => Some(source),
                SourceResolution::Refused(SourceRefusal::Limit { limit }) => {
                    self.builder.note_saturated(limit);
                    None
                }
                _ => None,
            };
        self.inc.sources.insert(path.to_string(), got.clone());
        got
    }
}
