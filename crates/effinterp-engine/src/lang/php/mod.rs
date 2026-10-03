//! Effect-directed PHP frontend.
//!
//! Parses PHP with `tree-sitter-php` (builds on this toolchain) and walks the
//! CST for calls that reach an effect boundary: process (`system`/`exec`/
//! `shell_exec`/`passthru`/`proc_open`/`popen`/backticks), filesystem
//! (`unlink`, `file_put_contents`, `fopen`, `file_get_contents`, `fread`,
//! `fwrite`, `fputs`, `file`, `mkdir`, `rmdir`, `rename`, `copy`, `touch`,
//! `readfile`, `scandir`, `glob`, `opendir`), network (`fsockopen`,
//! `stream_socket_client`, `curl_init`/`curl_exec`/`curl_setopt`,
//! `file_get_contents` on a URL), env (`getenv`/`putenv`, `$_ENV`/`$_SERVER`
//! reads), and SQL through `->exec/->query/->prepare` and
//! `mysqli_query`/`mysql_query`. It does not interpret PHP; it follows only
//! what reaches an effect, keeps non-literal arguments symbolic, and records
//! an explicit boundary for anything dynamic (`eval`, variable functions,
//! `call_user_func`).
//!
//! Execution vs. source presence: the plan describes what EXECUTING the file
//! does — top-level statements plus functions reached from them via a
//! within-file call graph. A defined-but-never-called function is not executed.
//! `module_summaries` exposes each top-level function's parameterized summary,
//! its user-function call edges, and its `require`/`include` bindings.
//!
//! `require`/`include` (and their `_once` forms) whose paths evaluate
//! statically (literals, `.` concatenation, `__DIR__`, `dirname(__FILE__)`,
//! `define()`d constants, variables bound to concrete paths) are followed
//! through the caller-supplied source resolver as budget-bounded nested
//! invocations, with once-only and cycle semantics; a dynamic or unresolvable
//! path is a typed boundary.
//!
//! Classes: `new X()` and statically-named method calls (`X::m()`, `$var->m()`
//! on a variable constructed from a resolvable class, `$this`/`self`/`parent`)
//! dispatch into the named class. The repo's OWN classes resolve through the
//! root `composer.json` `autoload.psr-4` mapping, then conventional `src/` /
//! `lib/` PSR-4 layout (a file is accepted only when it declares that FQN),
//! and are entered as nested invocations of the defining file (constructor
//! and method bodies); a class that maps to no repo file is a vendored/
//! external boundary, and a dynamic class name is a typed boundary. Untyped
//! receivers never dispatch.

mod control;
mod model;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_CALLBACK_VALUES, ParseFailure, ParseOutcome, WalkOutcome,
};
use crate::value::unresolved_resource;
use std::collections::{BTreeMap, HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceFamily,
    ResourceIdentity, Subject,
};
use tree_sitter::Node;

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::{
    ControlCaps, ControlExit, ControlFact, ControlFlow, ControlStack, SiteFacts,
};
use crate::module_summary::{
    CallEdge, ClassEntry, FunctionEntry, ImportBinding, ModuleSummary, call_results,
};
use crate::nest::{Nest, SourceResolution, Transition};
use crate::paths::{fs_resource_uses_cwd, join_file, parent_dir};
use crate::resource_transfer::TransferBinding;
use crate::summary::{Summary, bind_positional, has_text_concat, substitute_resource_expr};
use crate::value::parse_url_endpoint;
use crate::{
    ObjectIdentity, SemanticValue, SemanticValueKind, SourcePurpose, SourceRefusal, ValueArgument,
    merge_arguments, positional_arguments,
};

const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];
use crate::limits::DEFAULT_MAX_PHP_NODES;
const CALL_DEPTH_LIMIT: u64 = 64;
const MAX_COMMAND_REGISTRY_VALUES: usize = 64;
/// Bound on classes visited while resolving one method through inheritance.
const CLASS_CHAIN_LIMIT: u64 = 8;

/// Framework template methods: `parent::run` on a class extending the vendored
/// Symfony Console Application re-enters the subclass through `doRun`, so the
/// effects it performs before command dispatch surface instead of vanishing
/// behind the external parent.
const TEMPLATE_CALLBACKS: &[(&str, &str, &str)] =
    &[("Symfony\\Component\\Console\\Application", "run", "doRun")];

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

/// A top-level function definition (name -> params + body node id via a re-find).
struct Fn<'a> {
    params: Vec<String>,
    body: Node<'a>,
}

#[derive(Clone)]
struct Closure<'a> {
    params: Vec<String>,
    body: Node<'a>,
    uses: Vec<String>,
}

fn text<'a>(n: Node, src: &'a str) -> &'a str {
    n.utf8_text(src.as_bytes()).unwrap_or("")
}

/// A named child with the given kind (tree-sitter-php fields are not always
/// present across versions, so navigate by kind).
fn child_kind<'a>(n: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut c = n.walk();
    n.named_children(&mut c).find(|ch| ch.kind() == kind)
}

fn guarded_assignment(n: Node, src: &str) -> bool {
    let mut parent = n.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) {
            return false;
        }
        if matches!(
            node.kind(),
            "if_statement"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "foreach_statement"
                | "switch_statement"
                | "conditional_expression"
                | "try_statement"
                | "catch_clause"
                | "finally_clause"
                | "match_expression"
        ) || node.kind() == "binary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(text(operator, src), "&&" | "||" | "and" | "or" | "xor")
                })
        {
            return true;
        }
        parent = node.parent();
    }
    false
}

fn collect_functions<'a>(root: Node<'a>, src: &str) -> HashMap<String, Fn<'a>> {
    let mut out = HashMap::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if (n.kind() == "function_definition" || n.kind() == "method_declaration")
            && let (Some(name), Some(body)) =
                (child_kind(n, "name"), child_kind(n, "compound_statement"))
        {
            let params = child_kind(n, "formal_parameters")
                .map(|p| param_names(p, src))
                .unwrap_or_default();
            out.entry(text(name, src).to_string())
                .or_insert(Fn { params, body });
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            // Do not descend into function bodies when collecting siblings;
            // nested functions are rare and handled as separate entries only
            // at the same scan (they are still reachable here via the stack).
            stack.push(ch);
        }
    }
    out
}

fn param_names(params: Node, src: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut c = params.walk();
    for p in params.named_children(&mut c) {
        if matches!(
            p.kind(),
            "simple_parameter" | "variadic_parameter" | "property_promotion_parameter"
        ) && let Some(v) = child_kind(p, "variable_name")
            && let Some(name) = child_kind(v, "name")
        {
            names.push(text(name, src).to_string());
        }
    }
    names
}

fn bind_php_params(params: &[String], args: &[ResourceExpr]) -> HashMap<String, ResourceExpr> {
    let mut env: HashMap<_, _> = params
        .iter()
        .map(|name| (name.clone(), ResourceExpr::Parameter { name: name.clone() }))
        .collect();
    env.extend(
        bind_positional(params, args)
            .into_iter()
            .filter(|(_, value)| !contains_unresolved(value)),
    );
    env
}

fn closure_uses(node: Node, src: &str) -> Vec<String> {
    let Some(clause) = child_kind(node, "anonymous_function_use_clause") else {
        return Vec::new();
    };
    let mut cursor = clause.walk();
    clause
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "variable_name")
        .filter_map(|variable| child_kind(variable, "name"))
        .map(|name| text(name, src).to_string())
        .collect()
}

/// State shared across one analysis's include graph: files already included
/// (once-only semantics), the chain currently being included (cycle
/// detection), `define()`d string constants (PHP constants are global, so
/// a constant defined by a wrapper resolves paths in the files it includes),
/// the lazily-loaded PSR-4 class map, and the class-method dispatch memo.
#[derive(Default)]
pub(crate) struct IncludeState {
    included: HashSet<String>,
    stack: Vec<String>,
    consts: HashMap<String, String>,
    /// `autoload.psr-4` of the root composer.json (prefix -> dir), longest
    /// prefix first; None until first needed.
    psr4: Option<Vec<(String, String)>>,
    /// Resolved-source cache for class files (repeated dispatch re-parses,
    /// but reads each file once).
    sources: HashMap<String, Option<String>>,
    /// Class-method dispatches already analyzed (`path#class#method#args`).
    dispatched: HashSet<String>,
    /// Dispatches currently executing, for recursion cycles.
    dispatch_stack: Vec<String>,
    /// Last constructor-derived instance-property values for each class.
    props: HashMap<String, HashMap<String, ResourceExpr>>,
}

/// Per-file naming context: the file's namespace, its `use` imports
/// (alias -> fully-qualified name), and the classes it declares.
#[derive(Default)]
struct FileCtx {
    namespace: Option<String>,
    uses: HashMap<String, String>,
    consts: HashMap<String, HashMap<String, ResourceExpr>>,
    static_props: HashMap<String, HashMap<String, ResourceExpr>>,
    top_consts: HashMap<String, String>,
}

fn file_ctx(root: Node, src: &str) -> FileCtx {
    let mut ctx = FileCtx::default();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "namespace_definition" => {
                if ctx.namespace.is_none()
                    && let Some(name) = n.child_by_field_name("name")
                {
                    ctx.namespace = Some(text(name, src).to_string());
                }
            }
            "namespace_use_declaration" => {
                // `use function`/`use const` imports are not class names.
                if n.child_by_field_name("type").is_none() {
                    let prefix = child_kind(n, "namespace_name").map(|p| text(p, src).to_string());
                    let mut clauses: Vec<Node> = Vec::new();
                    let mut c = n.walk();
                    for ch in n.named_children(&mut c) {
                        match ch.kind() {
                            "namespace_use_clause" => clauses.push(ch),
                            "namespace_use_group" => {
                                let mut g = ch.walk();
                                clauses.extend(
                                    ch.named_children(&mut g)
                                        .filter(|x| x.kind() == "namespace_use_clause"),
                                );
                            }
                            _ => {}
                        }
                    }
                    for clause in clauses {
                        let Some(target_node) = clause
                            .named_children(&mut clause.walk())
                            .find(|x| matches!(x.kind(), "name" | "qualified_name"))
                        else {
                            continue;
                        };
                        let mut target =
                            text(target_node, src).trim_start_matches('\\').to_string();
                        if let Some(p) = &prefix {
                            target = format!("{p}\\{target}");
                        }
                        let alias = clause
                            .child_by_field_name("alias")
                            .map(|a| text(a, src).to_string())
                            .unwrap_or_else(|| {
                                target.rsplit('\\').next().unwrap_or(&target).to_string()
                            });
                        ctx.uses.insert(alias, target);
                    }
                }
            }
            _ => {}
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            stack.push(ch);
        }
    }
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, owner)) = stack.pop() {
        let owner = if matches!(node.kind(), "class_declaration" | "trait_declaration") {
            child_kind(node, "name").map(|name| {
                let name = text(name, src);
                match &ctx.namespace {
                    Some(namespace) => format!("{namespace}\\{name}"),
                    None => name.to_string(),
                }
            })
        } else {
            owner
        };
        if matches!(node.kind(), "function_definition" | "method_declaration") {
            continue;
        }
        if node.kind() == "const_declaration" {
            let mut cursor = node.walk();
            for element in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "const_element")
            {
                let mut element_cursor = element.walk();
                let mut children = element.named_children(&mut element_cursor);
                let Some(name) = children.find(|child| child.kind() == "name") else {
                    continue;
                };
                let Some(value) = element
                    .named_children(&mut element.walk())
                    .find(|child| child.id() != name.id())
                    .and_then(|value| literal_path_expr(value, src))
                else {
                    continue;
                };
                if let Some(owner) = &owner {
                    ctx.consts
                        .entry(owner.clone())
                        .or_default()
                        .insert(text(name, src).to_string(), fs_path(&value));
                } else {
                    ctx.top_consts.insert(text(name, src).to_string(), value);
                }
            }
        }
        if node.kind() == "property_declaration"
            && child_kind(node, "static_modifier").is_some()
            && let Some(owner) = &owner
        {
            let mut cursor = node.walk();
            for element in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "property_element")
            {
                let Some(variable) = element.child_by_field_name("name") else {
                    continue;
                };
                let Some(value) = element
                    .child_by_field_name("default_value")
                    .and_then(|value| literal_path_expr(value, src))
                else {
                    continue;
                };
                let Some(name) = child_kind(variable, "name") else {
                    continue;
                };
                ctx.static_props
                    .entry(owner.clone())
                    .or_default()
                    .insert(text(name, src).to_string(), fs_path(&value));
            }
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push((child, owner.clone()));
        }
    }
    ctx
}

fn literal_path_expr(node: Node, src: &str) -> Option<String> {
    let mut value = String::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if let Some(part) = literal_string(node, src) {
            value.push_str(&part);
            continue;
        }
        if node.kind() != "binary_expression"
            || node
                .child_by_field_name("operator")
                .map(|operator| text(operator, src))
                != Some(".")
        {
            return None;
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Some(value)
}

/// Resolve a class name as written to a fully-qualified name: a leading `\`
/// is absolute; otherwise the first segment resolves through the file's
/// imports, then the file's namespace.
fn resolve_class_text(ctx: &FileCtx, raw: &str) -> String {
    if let Some(abs) = raw.strip_prefix('\\') {
        return abs.to_string();
    }
    let first = raw.split('\\').next().unwrap_or(raw);
    if let Some(u) = ctx.uses.get(first) {
        return format!("{u}{}", &raw[first.len()..]);
    }
    match &ctx.namespace {
        Some(ns) => format!("{ns}\\{raw}"),
        None => raw.to_string(),
    }
}

/// The include-graph cwd anchored to the source root, so `__DIR__` composes
/// with `..` correctly whether the analysis root was handed an absolute or a
/// repo-relative directory.
fn anchored(cwd: &str) -> String {
    if cwd.starts_with('/') {
        cwd.to_string()
    } else {
        format!("/{cwd}")
    }
}

pub(crate) struct PhpFrontend<'a> {
    inc: std::cell::RefCell<&'a mut IncludeState>,
    root_file: bool,
}

impl Frontend for PhpFrontend<'_> {
    const LANGUAGE: &'static str = "php";
    const DOMAINS: &'static [&'static str] = &DOMAINS;
    type Ast<'a>
        = tree_sitter::Tree
    where
        Self: 'a;

    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let ast = parse(source);
        let detail = match &ast {
            None => Some("could not parse php"),
            Some(tree) if tree.root_node().has_error() => Some("php source has syntax errors"),
            Some(_) => None,
        };
        ParseOutcome {
            ast,
            failure: detail.map(|detail| ParseFailure {
                detail: detail.to_string(),
            }),
        }
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        tree: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let source = input.source;
        let source_cwd = input.source_cwd;
        let runtime_cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        let root_file = self.root_file;
        let mut inc = self.inc.borrow_mut();
        let inc = &mut **inc;
        let root = tree.root_node();
        if root_file
            && root
                .named_children(&mut root.walk())
                .all(|child| child.kind() == "text")
        {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNSUPPORTED_SOURCE,
                    class: BoundaryClass::ParseFailure,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: scope.as_slice().to_vec(),
                    limit: None,
                    detail: Some("php source has no <?php open tag".to_string()),
                },
                CoverageLevel::None,
            );
            return WalkOutcome::default();
        }
        let functions = collect_functions(root, source);
        let declared_callables = root_file.then(|| declared_callable_names(root, source));
        let ctx = file_ctx(root, source);
        inc.consts.extend(ctx.top_consts.clone());
        let runtime_cwd_resource = builder.current_execution_cwd();
        let first_effect = builder.effects_len();
        let mut c = root.walk();
        let children: Vec<Node> = root.named_children(&mut c).collect();
        builder.control_enter(source, false, |graph| {
            control::build(graph, &children, source)
        });
        let mut w = PhpWalker {
            control_applications: Vec::new(),
            builder,
            nest,
            src: source,
            root,
            source_cwd,
            runtime_cwd,
            runtime_cwd_resource,
            cwd_node,
            scope,
            depth,
            functions: &functions,
            following: HashSet::new(),
            entered_callables: HashSet::new(),
            call_depth: 0,
            nodes: nest.limits.max_php_nodes,
            reported: HashSet::new(),
            inc,
            ctx,
            current_class: None,
            class_parent: None,
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
        // Execute the top level: statements outside any function definition.
        w.exec_statements(&children, &HashMap::new());
        w.builder.control_leave();
        if root_file {
            for (class, method, site) in php_framework_roots(root, source, &w.ctx) {
                w.dispatch_local(&class, &method, &[], site);
            }
        }
        let entered_callables = !w.entered_callables.is_empty();
        drop(w);
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        WalkOutcome {
            declared_callables: declared_callables
                .filter(|names| {
                    !names.is_empty() && !entered_callables && builder.effects_len() == first_effect
                })
                .unwrap_or_default(),
        }
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        _file: &str,
        _scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> ModuleSummary {
        summarize_ast(source, ast)
    }
}

impl<'a> PhpFrontend<'a> {
    pub(crate) fn new(inc: &'a mut IncludeState) -> Self {
        Self {
            inc: std::cell::RefCell::new(inc),
            root_file: true,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_file(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    source_cwd: Option<&str>,
    runtime_cwd: Option<&str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    inc: &mut IncludeState,
    root_file: bool,
) {
    crate::lang::frontend::run(
        &PhpFrontend {
            inc: std::cell::RefCell::new(inc),
            root_file,
        },
        builder,
        nest,
        FrontendInput {
            source,
            source_cwd,
            runtime_cwd,
            cwd_node,
            scope,
            depth,
        },
    );
}

fn php_framework_roots<'a>(
    root: Node<'a>,
    source: &str,
    ctx: &FileCtx,
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
            && COMMAND_BASES.contains(&resolve_class_text(ctx, text(base, source)).as_str())
        {
            let class = resolve_class_text(ctx, text(short, source));
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

fn declared_callable_names(root: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, owner)) = stack.pop() {
        let class_name = matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "trait_declaration"
        )
        .then(|| child_kind(node, "name").map(|name| text(name, source).to_string()))
        .flatten();
        if matches!(node.kind(), "function_definition" | "method_declaration")
            && let Some(name) = child_kind(node, "name")
        {
            let name = text(name, source);
            let name = if node.kind() == "method_declaration" {
                owner
                    .as_deref()
                    .map_or_else(|| name.to_string(), |owner| format!("{owner}.{name}"))
            } else {
                name.to_string()
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
        let owner = class_name.or(owner);
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push((child, owner.clone()));
        }
    }
    names
}

/// Outcome of trying to run one class's method in its defining file.
enum MethodRun {
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
fn run_class_method(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    path: &str,
    provenance: &[ProvenanceRef],
    depth: u64,
    cwd_node: Option<ProvenanceRef>,
    inc: &mut IncludeState,
    class: &str,
    method: &str,
    args: &[ResourceExpr],
) -> MethodRun {
    let Some(tree) = parse(source) else {
        return MethodRun::Missing;
    };
    let root = tree.root_node();
    let ctx = file_ctx(root, source);
    inc.consts.extend(ctx.top_consts.clone());
    let current_class = resolve_class_text(&ctx, class);
    let Some((class_node, parent_raw)) = find_class(root, source, class) else {
        return MethodRun::Missing;
    };
    let parent = parent_raw.map(|p| resolve_class_text(&ctx, &p));
    let Some((params, body)) = find_method_in(class_node, source, method) else {
        let traits = class_traits(class_node, source)
            .into_iter()
            .map(|name| resolve_class_text(&ctx, &name))
            .collect();
        return MethodRun::ClassWithoutMethod { parent, traits };
    };
    // One analysis per (file, class, method, argument shape): repeats add no
    // information, and the stack check breaks recursion cycles.
    let key = format!("{path}#{class}#{method}#{args:?}");
    if inc.dispatch_stack.iter().any(|k| k == &key) || !inc.dispatched.insert(key.clone()) {
        return MethodRun::Ran;
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
        return MethodRun::Ran;
    };
    let node = frame.scope;
    inc.dispatch_stack.push(key);
    let functions = collect_functions(root, source);
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
    MethodRun::Ran
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

struct PhpWalker<'a, 'b> {
    builder: &'b mut PlanBuilder,
    nest: &'b Nest<'b>,
    src: &'a str,
    root: Node<'a>,
    source_cwd: Option<&'a str>,
    runtime_cwd: Option<&'a str>,
    runtime_cwd_resource: Option<ResourceExpr>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    functions: &'b HashMap<String, Fn<'a>>,
    following: HashSet<String>,
    entered_callables: HashSet<String>,
    call_depth: u64,
    nodes: u64,
    reported: HashSet<String>,
    inc: &'b mut IncludeState,
    ctx: FileCtx,
    /// Exact class whose method is currently executing in this file.
    current_class: Option<String>,
    /// Resolved base class of the class whose method is executing.
    class_parent: Option<String>,
    /// Variables holding instances of resolvable classes (`$x = new C()`).
    vars: HashMap<String, Vec<String>>,
    locals: HashMap<String, ResourceExpr>,
    /// Locals bound to network handles and their connection/request endpoint.
    network_handles: HashMap<String, ResourceExpr>,
    /// The argument expressions of `eval`s this walk has entered, by node id,
    /// with the code execution each one's value becomes.
    eval_code: HashMap<usize, u32>,
    /// Inline content expressions whose bytes an HTTP stream sends.
    request_bodies: HashMap<usize, Vec<u32>>,
    /// Inline contexts whose HTTP content was examined by file_get_contents.
    examined_contexts: HashSet<usize>,
    poisoned: HashSet<String>,
    /// Locals holding exact anonymous or arrow-function bodies.
    closures: HashMap<String, Vec<Closure<'a>>>,
    /// Closure nodes already deferred or invoked through exact evidence.
    handled_closures: HashSet<usize>,
    active_closures: HashSet<usize>,
    truncated: bool,
    /// Guarantees of bodies entered since the enclosing call began.
    control_applications: Vec<SiteFacts>,
    /// The program wrote the environment, so a value the host supplied may no
    /// longer be what a later `getenv` returns.
    environment_rewritten: bool,
    /// Capture sites a later output call prints: their commands run with the
    /// program's stdout instead of a captured one.
    printed_captures: HashSet<(usize, usize)>,
    /// Each captured command's child execution and the stdout it would have
    /// inherited, so printing the captured value can reconnect it.
    captured_outputs: HashMap<
        (usize, usize),
        (
            effinterp_proto::ExecutionNodeRef,
            Option<effinterp_proto::ExecutionStreamRef>,
        ),
    >,
    /// Capture sites whose output a local may hold, each with whether the
    /// local holds those bytes verbatim.
    capture_locals: HashMap<String, Vec<HeldCapture>>,
    /// Locals whose last definite assignment was a literal, with its PHP
    /// truth value, so `print_r`'s return mode can be read from them.
    truth_locals: HashMap<String, bool>,
    /// Code since the enclosing call began wrote through `global` or
    /// `$GLOBALS`, so the caller's value facts may be stale.
    globals_written: bool,
    /// Inside a call, the top-level scope's value facts as the outermost call
    /// began, which a `global` declaration binds to.
    global_facts: Option<ValueFacts>,
}

/// How the walker evaluated a call, for its control-flow site.
#[derive(Clone, Copy)]
enum PhpCall {
    /// A direct builtin interaction with explicit local reachability evidence.
    Sink,
    /// A modeled builtin that runs no user code.
    Modeled,
    /// A dispatch whose one entered body answers for the call.
    Entered,
    /// Code the walker cannot see.
    Opaque,
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// Evaluate a call-like construct and register what it establishes.
    fn control_call(&mut self, n: Node<'a>, run: impl FnOnce(&mut Self) -> PhpCall) {
        let since = self.builder.control_registered();
        let before = self.builder.effects_len();
        let saved = std::mem::take(&mut self.control_applications);
        let kind = run(self);
        let applied = std::mem::replace(&mut self.control_applications, saved);
        let facts = match (kind, applied.as_slice()) {
            (PhpCall::Sink, []) => SiteFacts::known(
                self.builder
                    .control_own_effects(before..self.builder.effects_len()),
            ),
            (PhpCall::Modeled, []) => SiteFacts::known(Vec::new()),
            (PhpCall::Entered, [entered]) => entered.clone(),
            _ => SiteFacts::unknown(),
        };
        self.builder
            .control_site_since(self.src, false, control::span(n), since, facts);
    }

    /// A construct whose own modeled occurrences are all it reaches.
    fn control_modeled(&mut self, n: Node<'a>, run: impl FnOnce(&mut Self)) {
        self.control_call(n, |walker| {
            run(walker);
            PhpCall::Modeled
        });
    }

    /// Run a callable body in its own control-flow frame.
    fn control_body(&mut self, body: Node<'a>, run: impl FnOnce(&mut Self)) {
        self.builder.control_enter(self.src, false, |graph| {
            let statements: Vec<Node> = if body.kind() == "compound_statement" {
                let mut cursor = body.walk();
                body.named_children(&mut cursor).collect()
            } else {
                vec![body]
            };
            control::build(graph, &statements, self.src)
        });
        run(self);
        let application = match self.builder.control_leave() {
            Some(finished) => SiteFacts::call(&finished.requirements, Some),
            None => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
    }

    fn exec_statements(&mut self, nodes: &[Node<'a>], env: &HashMap<String, ResourceExpr>) {
        for n in nodes {
            self.exec(*n, env);
        }
    }

    fn exec(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        let depth = self.builder.condition_depth();
        self.exec_nodes(n, env);
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    fn exec_nodes(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        // Iterative: PHP `.` and nested statements are left-deep CST spines.
        // A 20k concat overflows an 8MiB stack before the node cap can fire.
        let mut stack = vec![n];
        let depth = self.builder.condition_depth();
        while let Some(n) = stack.pop() {
            while self.builder.condition_depth() > depth {
                self.builder.pop_condition();
            }
            let executes = matches!(
                n.kind(),
                "anonymous_function"
                    | "arrow_function"
                    | "function_call_expression"
                    | "member_call_expression"
                    | "scoped_call_expression"
                    | "object_creation_expression"
                    | "assignment_expression"
                    | "augmented_assignment_expression"
                    | "unset_statement"
                    | "subscript_expression"
                    | "shell_command_expression"
                    | "require_expression"
                    | "include_expression"
                    | "require_once_expression"
                    | "include_once_expression"
            ) || n.kind() == "variable_name" && !self.closures.is_empty();
            if executes && let Some(condition) = super::conditions::tree_condition(self.src, n) {
                self.builder.push_condition(condition);
            }
            if !crate::nest::charge_analysis_steps(
                self.builder,
                self.nest.budget,
                1,
                Some((n.start_byte() as u32, n.end_byte() as u32)),
            ) {
                self.truncated = true;
                return;
            }
            if self.nodes == 0 || !crate::limits::summary_step() {
                if !self.truncated {
                    self.truncated = true;
                    self.opaque(
                        BoundaryReason::PARTIAL_ANALYSIS,
                        BoundaryClass::Unmodeled,
                        n,
                    );
                }
                return;
            }
            self.nodes -= 1;
            if prints_to_stdout(n, self.src) {
                self.print_captures(n);
            }
            if n.kind() == "assignment_expression"
                && let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                )
                && left.kind() == "variable_name"
            {
                // A definite assignment replaces what the local held; a
                // conditional one may leave the earlier output in place.
                let (spans, locals) = capture_sources(right, self.src);
                let mut held = spans;
                for (local, exact) in locals {
                    held.extend(
                        self.capture_locals
                            .get(&local)
                            .into_iter()
                            .flatten()
                            .map(|&(span, verbatim)| (span, exact && verbatim)),
                    );
                }
                let name = text(left, self.src).to_string();
                let conditional = super::conditions::tree_condition(self.src, n).is_some();
                if conditional {
                    held.extend(self.capture_locals.get(&name).cloned().unwrap_or_default());
                }
                match literal_truth(right, self.src).filter(|_| !conditional) {
                    Some(truth) => self.truth_locals.insert(name.clone(), truth),
                    None => self.truth_locals.remove(&name),
                };
                self.capture_locals.insert(name, held);
            }
            self.forget_written(n);
            if n.kind() == "unset_statement" {
                let mut cursor = n.walk();
                for variable in n.named_children(&mut cursor) {
                    self.capture_locals.remove(text(variable, self.src));
                    self.truth_locals.remove(text(variable, self.src));
                }
            }
            // Named declarations execute only through `follow`. Exact stored
            // closures stay deferred; other closure literals remain bounded
            // callback candidates, preserving effects without name guessing.
            match n.kind() {
                "function_definition"
                | "method_declaration"
                | "class_declaration"
                | "interface_declaration"
                | "trait_declaration" => continue,
                "anonymous_function" | "arrow_function" => {
                    if !self.handled_closures.contains(&n.id())
                        && let Some(body) = n.child_by_field_name("body")
                    {
                        let params = n
                            .child_by_field_name("parameters")
                            .map(|parameters| param_names(parameters, self.src))
                            .unwrap_or_default();
                        self.run_closure(
                            &Closure {
                                params,
                                body,
                                uses: closure_uses(n, self.src),
                            },
                            &[],
                        );
                    }
                    continue;
                }
                "function_call_expression" => self.control_call(n, |w| w.call(n, env)),
                "member_call_expression" | "scoped_call_expression" => self.control_call(n, |w| {
                    w.method_call(n, env);
                    PhpCall::Entered
                }),
                "object_creation_expression" => self.control_call(n, |w| w.new_object(n, env)),
                "assignment_expression" => self.control_modeled(n, |w| w.assign(n, env)),
                "augmented_assignment_expression" => {
                    self.control_modeled(n, |w| w.augmented_assign(n, env))
                }
                "unset_statement" => self.unset(n),
                "global_declaration" | "static_variable_declaration" => {
                    self.poison_declared_locals(n)
                }
                "variable_name" => self.run_escaped_closure(n),
                "subscript_expression" => self.control_modeled(n, |w| w.superglobal(n)),
                "shell_command_expression" => self.control_modeled(n, |w| {
                    let mut values = env.clone();
                    values.extend(w.locals.clone());
                    let cmd = w.interpolate(n, &values);
                    let environment = w.shell_local_environment(n, &values);
                    w.nest_shell(cmd, n, environment, true);
                }),
                "require_expression" | "include_expression" => {
                    self.include(n, false, env);
                    continue;
                }
                "require_once_expression" | "include_once_expression" => {
                    self.include(n, true, env);
                    continue;
                }
                _ => {}
            }
            let mut c = n.walk();
            let children: Vec<Node> = n.named_children(&mut c).collect();
            for ch in children.into_iter().rev() {
                stack.push(ch);
            }
        }
    }

    fn call(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) -> PhpCall {
        let Some(fname) = callable_name(n, self.src) else {
            if let Some(function) = n.child_by_field_name("function") {
                let args: Vec<ResourceExpr> = arg_nodes(n)
                    .iter()
                    .map(|argument| self.resolve_argument(*argument, env))
                    .collect();
                if self.invoke_callable(function, &args, n, env) {
                    return PhpCall::Entered;
                }
            }
            // An unbound variable function or computed callee is dynamic.
            self.opaque(BoundaryReason::DYNAMIC_CALL, BoundaryClass::Unresolved, n);
            return PhpCall::Opaque;
        };
        let args: Vec<Node> = arg_nodes(n);

        // tree-sitter-php parses these language constructs as ordinary calls,
        // but they only inspect their arguments and can never invoke a closure.
        if matches!(fname.as_str(), "isset" | "empty") {
            return PhpCall::Modeled;
        }

        // A written `Ns\fn()` is a static name, not a dynamic callee. Follow
        // a same-file function when the namespace matches; an include-defined
        // function is a later edge.
        let local = fname.rsplit('\\').next().unwrap_or(&fname).to_string();
        if self.functions.contains_key(&local) && same_namespace(&self.ctx, &fname) {
            let bound: Vec<ResourceExpr> = args
                .iter()
                .map(|argument| self.resolve_argument(*argument, env))
                .collect();
            self.follow(&local, &bound, n);
            return PhpCall::Entered;
        }

        // Effect builtins are unqualified (`unlink`, `getenv`). A namespaced
        // call is never a PHP builtin. PHP function names are case-insensitive.
        let builtin = fname.to_ascii_lowercase();
        if !fname.contains('\\')
            && let Some(()) = self.builtin(&builtin, &args, n, env)
        {
            // These run callables or code the model does not follow.
            return match builtin.as_str() {
                "unlink" => PhpCall::Sink,
                "call_user_func" | "call_user_func_array" => PhpCall::Entered,
                "array_map" | "array_walk" | "usort" | "eval" | "assert" => PhpCall::Opaque,
                _ => PhpCall::Modeled,
            };
        }
        let array_callback = match fname.as_str() {
            "array_filter" | "preg_replace_callback" => Some(1),
            "header_register_callback"
            | "ob_start"
            | "register_shutdown_function"
            | "register_tick_function"
            | "set_error_handler"
            | "set_exception_handler"
            | "spl_autoload_register" => Some(0),
            _ => None,
        };
        self.invoke_callback_arguments(&args, n, env, array_callback);
        if !fname.contains('\\') && array_callback.is_none() {
            let arguments: Vec<_> = args
                .iter()
                .enumerate()
                .map(|(index, argument)| crate::ValueArgument {
                    name: None,
                    index,
                    value: crate::SemanticValue::from(self.resolve_argument(*argument, env)),
                })
                .collect();
            let site = self.span(n);
            if crate::dependency_calls::apply_global_dependency_call(
                self.builder,
                self.nest,
                "php",
                &fname,
                &arguments,
                site,
            ) {
                return PhpCall::Opaque;
            }
        }
        self.opaque(
            BoundaryReason::UNRESOLVED_CALL,
            BoundaryClass::Unresolved,
            n,
        );
        PhpCall::Opaque
    }

    fn invoke_callable(
        &mut self,
        callable: Node<'a>,
        args: &[ResourceExpr],
        site: Node<'a>,
        _env: &HashMap<String, ResourceExpr>,
    ) -> bool {
        if callable.kind() == "parenthesized_expression"
            && let Some(inner) = callable.named_child(0)
        {
            return self.invoke_callable(inner, args, site, _env);
        }
        if matches!(callable.kind(), "anonymous_function" | "arrow_function")
            && let Some(body) = callable.child_by_field_name("body")
        {
            self.handled_closures.insert(callable.id());
            let params = callable
                .child_by_field_name("parameters")
                .map(|parameters| param_names(parameters, self.src))
                .unwrap_or_default();
            self.run_closure(
                &Closure {
                    params,
                    body,
                    uses: closure_uses(callable, self.src),
                },
                args,
            );
            return true;
        }
        if callable.kind() == "variable_name"
            && let Some(name) = child_kind(callable, "name").map(|name| text(name, self.src))
            && let Some(closures) = self.closures.get(name).cloned()
        {
            for closure in closures {
                self.run_closure(&closure, args);
            }
            return true;
        }
        if let Some(function) = literal_string(callable, self.src)
            && self.functions.contains_key(&function)
        {
            self.follow(&function, args, site);
            return true;
        }
        let Some((receiver, method)) = callable_array(callable, self.src) else {
            return false;
        };
        if let Some(variable) = receiver.strip_prefix('$')
            && let Some(classes) = self.vars.get(variable).cloned()
        {
            let mut dispatched = false;
            for class in classes {
                dispatched |= self.dispatch_local(&class, &method, args, site)
                    || self.dispatch(&class, &method, args, site);
            }
            return dispatched;
        }
        let class = resolve_class_text(&self.ctx, receiver.trim_end_matches("::class"));
        self.dispatch_local(&class, &method, args, site)
            || self.class_file(&class).is_some() && self.dispatch(&class, &method, args, site)
    }

    fn invoke_callback_arguments(
        &mut self,
        args: &[Node<'a>],
        site: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
        array_callback: Option<usize>,
    ) {
        for callable in args
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, argument)| {
                (matches!(
                    argument.kind(),
                    "anonymous_function" | "arrow_function" | "variable_name"
                ) || array_callback == Some(index))
                .then_some(argument)
            })
        {
            self.invoke_callable(callable, &[], site, env);
        }
    }

    fn method_call(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
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
                .map(|argument| self.resolve_argument(*argument, env))
                .collect();
            if n.kind() == "member_call_expression" {
                if let Some(obj) = n.child_by_field_name("object") {
                    if let Some(class) = self.member_receiver_class(obj)
                        && (self.dispatch_local(&class, &method, &args, n)
                            || self.dispatch(&class, &method, &args, n))
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
                                && self.dispatch_local(&class, &method, &args, n)
                            {
                                return;
                            }
                            if let Some(p) = self.class_parent.clone()
                                && self.dispatch(&p, &method, &args, n)
                            {
                                return;
                            }
                            // Unknown `$this` method: inherited from an external
                            // parent; effectless like unknown plain calls.
                        } else if let Some(classes) = self.vars.get(var).cloned() {
                            let mut dispatched = false;
                            for fq in classes {
                                dispatched |= self.dispatch_local(&fq, &method, &args, n)
                                    || self.dispatch(&fq, &method, &args, n);
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
                                && self.dispatch_local(&class, &method, &args, n)
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
                        let fq = resolve_class_text(&self.ctx, raw);
                        if self.dispatch_local(&fq, &method, &args, n) {
                            return;
                        }
                        if self.class_file(&fq).is_some() {
                            self.dispatch(&fq, &method, &args, n);
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
            return new_class(node, self.src, &self.ctx);
        }
        if node.kind() != "scoped_call_expression" {
            return None;
        }
        let scope = node.child_by_field_name("scope")?;
        if !matches!(scope.kind(), "name" | "qualified_name") {
            return None;
        }
        let class = resolve_class_text(&self.ctx, text(scope, self.src));
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
                        .map(|name| resolve_class_text(&self.ctx, text(name, self.src)))?
                } else {
                    resolve_class_text(&self.ctx, raw)
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
        if self.dispatch_local(&p, method, args, n)
            || self.class_file(&p).is_some() && self.dispatch(&p, method, args, n)
        {
            return;
        }
        if let Some((_, _, cb)) = TEMPLATE_CALLBACKS
            .iter()
            .find(|(cls, m, _)| *cls == p && *m == method)
            && let Some(class) = self.current_class.clone()
            && self.dispatch_local(&class, cb, &[], n)
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
    fn new_object(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) -> PhpCall {
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
            .map(|argument| self.resolve_argument(*argument, env))
            .collect();
        let fq = resolve_class_text(&self.ctx, &raw);
        // A same-file class with no constructor anywhere in reach runs none.
        let constructorless = self.local_class(&fq).is_some_and(|(class, parent)| {
            parent.is_none()
                && class_traits(class, self.src).is_empty()
                && find_method_in(class, self.src, "__construct").is_none()
        });
        if self.dispatch_local(&fq, "__construct", &args, n) {
            return if constructorless {
                PhpCall::Modeled
            } else {
                PhpCall::Entered
            };
        }
        if self.class_file(&fq).is_some() {
            // The constructor may be absent (or inherited): the instance is
            // still typed; dispatch runs whatever constructor the chain has.
            self.dispatch(&fq, "__construct", &args, n);
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

    /// `$x = new C(...)`: remember the variable's class so later `$x->m()`
    /// calls dispatch. The construction itself is handled when the walk
    /// reaches the `new` expression.
    fn assign(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        if let Some((name, resource)) = superglobal_resource(left, self.src)
            && name == "_ENV"
        {
            self.emit(model::environment_effect(resource, false), n);
        }
        if left.kind() != "variable_name" {
            return;
        }
        let Some(var) = child_kind(left, "name").map(|x| text(x, self.src).to_string()) else {
            return;
        };
        let guarded = guarded_assignment(n, self.src);
        let network_handle = (right.kind() == "function_call_expression")
            .then(|| callable_name(right, self.src))
            .flatten()
            .and_then(|name| match name.as_str() {
                "curl_init" | "fsockopen" | "pfsockopen" | "stream_socket_client" => {
                    Some(self.url_resource(arg_nodes(right).first().copied(), env))
                }
                "fopen" if self.is_url(arg_nodes(right).first().copied()) => {
                    Some(self.url_resource(arg_nodes(right).first().copied(), env))
                }
                _ => None,
            });
        let supported = matches!(
            right.kind(),
            "string"
                | "encapsed_string"
                | "binary_expression"
                | "name"
                | "variable_name"
                | "member_access_expression"
                | "class_constant_access_expression"
                | "scoped_property_access_expression"
        ) || right.kind() == "function_call_expression"
            && callable_name(right, self.src)
                .is_some_and(|name| matches!(name.as_str(), "getenv" | "dirname" | "sprintf"));
        let mut value = if supported {
            self.resolve_argument(right, env)
        } else {
            unresolved_resource("filesystem")
        };
        if guarded
            && self
                .locals
                .get(&var)
                .or_else(|| env.get(&var))
                .is_some_and(|current| current != &value)
        {
            value = unresolved_resource("filesystem");
        }
        self.store_local(&var, value, guarded);
        if !guarded {
            self.vars.remove(&var);
            self.closures.remove(&var);
            match network_handle {
                Some(resource) => {
                    self.network_handles.insert(var.clone(), resource);
                }
                None => {
                    self.network_handles.remove(&var);
                }
            }
        }
        if matches!(right.kind(), "anonymous_function" | "arrow_function")
            && let Some(body) = right.child_by_field_name("body")
        {
            self.handled_closures.insert(right.id());
            let params = right
                .child_by_field_name("parameters")
                .map(|parameters| param_names(parameters, self.src))
                .unwrap_or_default();
            let closures = self.closures.entry(var).or_default();
            let duplicate = closures
                .iter()
                .any(|closure| closure.body.id() == body.id());
            let truncated = !duplicate && closures.len() >= MAX_CALLBACK_VALUES;
            if !duplicate && !truncated {
                closures.push(Closure {
                    params,
                    body,
                    uses: closure_uses(right, self.src),
                });
            }
            if truncated {
                self.candidate_limit(n);
            }
            return;
        }
        if right.kind() != "object_creation_expression" {
            return;
        }
        let mut c = right.walk();
        let Some(cn) = right
            .named_children(&mut c)
            .find(|x| matches!(x.kind(), "name" | "qualified_name"))
        else {
            return;
        };
        let raw = text(cn, self.src);
        let fq = resolve_class_text(&self.ctx, raw);
        if self.local_class(&fq).is_some() || self.class_file(&fq).is_some() {
            let classes = self.vars.entry(var).or_default();
            let duplicate = classes.contains(&fq);
            let truncated = !duplicate && classes.len() >= MAX_CALLBACK_VALUES;
            if !duplicate && !truncated {
                classes.push(fq);
            }
            if truncated {
                self.candidate_limit(n);
            }
        }
    }

    fn unset(&mut self, n: Node<'a>) {
        let mut cursor = n.walk();
        for target in n.named_children(&mut cursor) {
            if let Some((name, resource)) = superglobal_resource(target, self.src)
                && name == "_ENV"
            {
                self.emit(model::environment_effect(resource, true), n);
            }
        }
    }

    fn augmented_assign(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        let (Some(left), Some(right), Some(operator)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
            n.child_by_field_name("operator"),
        ) else {
            return;
        };
        if left.kind() != "variable_name" {
            return;
        }
        let Some(name) = child_kind(left, "name").map(|name| text(name, self.src).to_string())
        else {
            return;
        };
        if text(operator, self.src) != ".=" {
            self.store_local(&name, unresolved_resource("filesystem"), false);
            return;
        }
        let old = self
            .locals
            .get(&name)
            .cloned()
            .or_else(|| env.get(&name).cloned())
            .unwrap_or_else(|| unresolved_resource("filesystem"));
        let guarded = guarded_assignment(n, self.src);
        let mut value = text_concat(vec![old, self.resolve_argument(right, env)]);
        if guarded
            && self
                .locals
                .get(&name)
                .or_else(|| env.get(&name))
                .is_some_and(|current| current != &value)
        {
            value = unresolved_resource("filesystem");
        }
        self.store_local(&name, value, guarded);
    }

    fn poison_declared_locals(&mut self, node: Node<'a>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "variable_name"
                && let Some(name) = child_kind(node, "name")
            {
                self.store_local(
                    text(name, self.src),
                    unresolved_resource("filesystem"),
                    false,
                );
                continue;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }

    fn store_local(&mut self, name: &str, value: ResourceExpr, guarded: bool) {
        let conflict = guarded
            && self
                .locals
                .get(name)
                .is_some_and(|current| current != &value);
        if conflict || contains_unresolved(&value) {
            self.locals
                .insert(name.to_string(), unresolved_resource("filesystem"));
            self.poisoned.insert(name.to_string());
        } else {
            self.locals.insert(name.to_string(), value);
            self.poisoned.remove(name);
        }
    }

    /// Snapshot the top-level scope's value facts as the outermost call
    /// begins; says whether this call is that one.
    fn enter_facts(
        &mut self,
        captures: &HashMap<String, Vec<HeldCapture>>,
        truths: &HashMap<String, bool>,
    ) -> bool {
        let outermost = self.global_facts.is_none();
        if outermost {
            self.global_facts = Some((captures.clone(), truths.clone()));
        }
        outermost
    }

    /// Return to the caller's value facts after a call. A callee that wrote
    /// through `global` or `$GLOBALS` may have changed them.
    fn restore_facts(
        &mut self,
        captures: HashMap<String, Vec<HeldCapture>>,
        truths: HashMap<String, bool>,
        globals_written: bool,
    ) {
        let written = self.globals_written;
        self.capture_locals = captures;
        self.truth_locals = truths;
        self.globals_written = globals_written || written;
        if written {
            self.forget_facts(None);
        }
    }

    fn run_closure(&mut self, closure: &Closure<'a>, args: &[ResourceExpr]) {
        let key = closure.body.id();
        if !self.active_closures.insert(key) {
            return;
        }
        let caller_locals = std::mem::take(&mut self.locals);
        let caller_network_handles = std::mem::take(&mut self.network_handles);
        let caller_poisoned = std::mem::take(&mut self.poisoned);
        let caller_captures = std::mem::take(&mut self.capture_locals);
        let caller_truths = std::mem::take(&mut self.truth_locals);
        let caller_globals_written = std::mem::take(&mut self.globals_written);
        let outermost = self.enter_facts(&caller_captures, &caller_truths);
        // A closure starts with copies of the values it uses.
        for name in &closure.uses {
            let local = format!("${name}");
            if let Some(held) = caller_captures.get(&local) {
                self.capture_locals.insert(local.clone(), held.clone());
            }
            if let Some(truth) = caller_truths.get(&local) {
                self.truth_locals.insert(local, *truth);
            }
        }
        self.locals = closure
            .uses
            .iter()
            .filter_map(|name| {
                caller_locals
                    .get(name)
                    .cloned()
                    .map(|value| (name.clone(), value))
            })
            .collect();
        self.network_handles = closure
            .uses
            .iter()
            .filter_map(|name| {
                caller_network_handles
                    .get(name)
                    .cloned()
                    .map(|value| (name.clone(), value))
            })
            .collect();
        self.poisoned = closure
            .uses
            .iter()
            .filter(|name| caller_poisoned.contains(*name))
            .cloned()
            .collect();
        let env = bind_php_params(&closure.params, args);
        if closure.body.kind() == "compound_statement" {
            let mut cursor = closure.body.walk();
            let statements: Vec<Node> = closure.body.named_children(&mut cursor).collect();
            self.exec_statements(&statements, &env);
        } else {
            self.exec(closure.body, &env);
        }
        self.locals = caller_locals;
        self.network_handles = caller_network_handles;
        self.poisoned = caller_poisoned;
        self.restore_facts(caller_captures, caller_truths, caller_globals_written);
        if outermost {
            self.global_facts = None;
        }
        // A `use (&$x)` binding writes the caller's local.
        if let Some(clause) = closure
            .body
            .parent()
            .and_then(|function| child_kind(function, "anonymous_function_use_clause"))
        {
            let mut cursor = clause.walk();
            let shared: Vec<String> = clause
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "by_ref")
                .filter_map(|by_ref| child_kind(by_ref, "variable_name"))
                .map(|variable| text(variable, self.src).to_string())
                .collect();
            self.forget_facts(Some(&shared));
        }
        self.active_closures.remove(&key);
    }

    fn run_escaped_closure(&mut self, n: Node<'a>) {
        let mut current = n;
        while let Some(parent) = current.parent() {
            if matches!(
                parent.kind(),
                "unset_statement" | "isset_expression" | "empty_expression"
            ) {
                return;
            }
            if parent.kind() == "function_call_expression"
                && callable_name(parent, self.src)
                    .is_some_and(|name| matches!(name.as_str(), "isset" | "empty"))
            {
                return;
            }
            if parent.kind() == "binary_expression"
                && parent
                    .child_by_field_name("operator")
                    .is_some_and(|operator| {
                        matches!(
                            text(operator, self.src),
                            "==" | "==="
                                | "!="
                                | "!=="
                                | "<"
                                | ">"
                                | "<="
                                | ">="
                                | "<=>"
                                | "&&"
                                | "||"
                                | "and"
                                | "or"
                                | "xor"
                        )
                    })
            {
                return;
            }
            if matches!(
                parent.kind(),
                "if_statement"
                    | "while_statement"
                    | "do_statement"
                    | "for_statement"
                    | "conditional_expression"
            ) && parent
                .child_by_field_name("condition")
                .is_some_and(|condition| {
                    condition.start_byte() <= n.start_byte() && condition.end_byte() >= n.end_byte()
                })
            {
                return;
            }
            if parent.kind() == "parenthesized_expression" {
                current = parent;
                continue;
            }
            if parent.kind() == "assignment_expression"
                && parent
                    .child_by_field_name("left")
                    .is_some_and(|left| left.id() == current.id())
                || parent.kind() == "function_call_expression"
                    && parent
                        .child_by_field_name("function")
                        .is_some_and(|function| function.id() == current.id())
                || matches!(parent.kind(), "argument" | "arguments")
            {
                return;
            }
            break;
        }
        let Some(name) = child_kind(n, "name").map(|name| text(name, self.src)) else {
            return;
        };
        if let Some(closures) = self.closures.get(name).cloned() {
            for closure in closures {
                self.run_closure(&closure, &[]);
            }
        }
    }

    fn local_class(&self, fqcn: &str) -> Option<(Node<'a>, Option<String>)> {
        let class = fqcn.rsplit('\\').next().unwrap_or(fqcn);
        if resolve_class_text(&self.ctx, class) != fqcn {
            return None;
        }
        find_class(self.root, self.src, class)
    }

    fn dispatch_local(
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
            let parent = parent_raw.map(|name| resolve_class_text(&self.ctx, &name));
            self.run_local_method(fqcn, method, &params, body, parent, args);
            return true;
        }
        for name in class_traits(class_node, self.src) {
            let trait_name = resolve_class_text(&self.ctx, &name);
            if self.dispatch_local_inner(&trait_name, method, args, site, seen, depth + 1)
                || self.dispatch(&trait_name, method, args, site)
            {
                return true;
            }
        }
        if let Some(parent) = parent_raw.map(|name| resolve_class_text(&self.ctx, &name)) {
            return self.dispatch_local_inner(&parent, method, args, site, seen, depth + 1)
                || self.dispatch(&parent, method, args, site);
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
                let value = self.resolve_argument(right, env);
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
    fn dispatch(
        &mut self,
        fqcn: &str,
        method: &str,
        args: &[ResourceExpr],
        site: Node<'a>,
    ) -> bool {
        let site_ref = self.span(site);
        let mut cur = fqcn.to_string();
        for _ in 0..CLASS_CHAIN_LIMIT {
            let Some((path, source)) = self.class_file(&cur) else {
                return false;
            };
            match run_class_method(
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
                MethodRun::Ran => return true,
                MethodRun::ClassWithoutMethod { parent, traits } => {
                    for trait_name in traits {
                        if self.dispatch(&trait_name, method, args, site) {
                            return true;
                        }
                    }
                    if let Some(parent) = parent {
                        cur = parent;
                    } else {
                        return method == "__construct";
                    }
                }
                MethodRun::Missing => return method == "__construct",
            }
        }
        true
    }

    /// The repo file defining `fqcn`: composer.json `autoload.psr-4` first,
    /// then conventional `src/` / `lib/` PSR-4 layout. A layout candidate is
    /// accepted only when the file declares that FQN, so a stray `src/Foo.php`
    /// cannot satisfy `Vendor\Foo`. A prefix match whose file is absent (a
    /// vendored package) stays unresolved.
    fn class_file(&mut self, fqcn: &str) -> Option<(String, String)> {
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

    /// `$_ENV['NAME']` / `$_SERVER['NAME']` read as an environment read. The
    /// same node shape is also how a write (`$_ENV['NAME'] = ...`) reaches
    /// this call via the generic recursion, so a subscript on the left of an
    /// assignment is skipped rather than reported as a read.
    fn superglobal(&mut self, n: Node<'a>) {
        if is_environment_mutation_target(n) {
            return;
        }
        let Some((name, resource)) = superglobal_resource(n, self.src) else {
            return;
        };
        if name != "_ENV" && name != "_SERVER" {
            return;
        }
        if name == "_SERVER"
            && matches!(&resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } if server_request_key(name))
        {
            return;
        }
        self.emit(
            Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("environment.read"),
                resource,
                attributes: Default::default(),
                modality: Modality::May,
                execution: effinterp_proto::ExecutionNodeRef(0),
                condition: None,
                realm: Default::default(),
                provenance: vec![],
            },
            n,
        );
    }

    /// Execute a `require`/`include` (`once` for the `_once` forms): evaluate
    /// the path statically, apply once/cycle semantics, and analyze the
    /// included file as a budget-bounded nested invocation so its effects
    /// chain back through the include site. A dynamic or unresolvable path is
    /// a typed boundary, never silence.
    fn include(&mut self, n: Node<'a>, once: bool, env: &HashMap<String, ResourceExpr>) {
        let mut c = n.walk();
        let expr = n.named_children(&mut c).next();
        // A URL target is fetched and its body run as PHP when
        // `allow_url_include` is on, which a `-d` option or an unobserved
        // php.ini can set; the fetched source is not analyzed.
        if let Some(target) = expr
            && literal_string(target, self.src).is_some_and(|url| {
                ["http://", "https://", "ftp://"].iter().any(|scheme| {
                    url.get(..scheme.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
                })
            })
        {
            let request = self.net_slot(Some(target), env, n);
            let execution = self.emit(
                self.interpreter_effect("process.code_execution", ("source", "argument")),
                n,
            );
            self.record_transfer(request, execution);
            self.opaque_with_detail(
                BoundaryReason::UNRESOLVED_INCLUDE,
                BoundaryClass::Unresolved,
                n,
                Some("remote included source is not analyzed".to_string()),
            );
            return;
        }
        let Some(spec) = expr.and_then(|e| self.static_path(e, env)) else {
            self.opaque(
                BoundaryReason::DYNAMIC_INCLUDE,
                BoundaryClass::Unresolved,
                n,
            );
            return;
        };
        let Some(path) = join_file(self.source_cwd, &spec).map(|p| anchored(&p)) else {
            self.opaque(
                BoundaryReason::UNRESOLVED_INCLUDE,
                BoundaryClass::Unresolved,
                n,
            );
            return;
        };
        // PHP tracks every included file; a `_once` form skips a file any
        // earlier include already loaded.
        if once && self.inc.included.contains(&path) {
            return;
        }
        if self.inc.stack.iter().any(|p| p == &path) {
            self.opaque(BoundaryReason::INCLUDE_CYCLE, BoundaryClass::Limit, n);
            return;
        }
        let (origin, source) = match self.nest.resolve_source_file(
            self.builder,
            &path,
            SourcePurpose::DependencySource,
            "php",
        ) {
            SourceResolution::Source { origin, source } => (origin, source),
            SourceResolution::Refused(SourceRefusal::Limit { limit }) => {
                self.builder.note_saturated(limit);
                return;
            }
            SourceResolution::Refused(SourceRefusal::Unavailable(reason)) => {
                self.opaque_with_detail(
                    BoundaryReason::UNRESOLVED_INCLUDE,
                    BoundaryClass::Unresolved,
                    n,
                    Some(format!("included source unavailable: {}", reason.as_str())),
                );
                return;
            }
            SourceResolution::UnsupportedEncoding => {
                self.opaque_with_detail(
                    BoundaryReason::UNRESOLVED_INCLUDE,
                    BoundaryClass::Unresolved,
                    n,
                    Some("included source is not valid UTF-8".to_string()),
                );
                return;
            }
            SourceResolution::AlreadySelected => return,
            SourceResolution::Unavailable => {
                self.opaque(
                    BoundaryReason::UNRESOLVED_INCLUDE,
                    BoundaryClass::Unresolved,
                    n,
                );
                return;
            }
        };
        // Invocation analysis composes calls into included functions itself;
        // repository indexing links them in its composer.
        if self.builder.current_execution_is_selected_input() {
            self.nest.dependency_calls.record_followed(
                crate::dependency_calls::DependencyRequestKey {
                    source_cwd: self.nest.current_source_cwd(),
                    language: "php",
                    specifier: path.clone(),
                },
                crate::dependency_calls::FollowedDependency {
                    launch: self.builder.current_dependency_launch(),
                    path: origin.clone(),
                    source: source.clone(),
                    digest: effinterp_proto::content_digest(source.as_bytes()),
                    lang: crate::Lang::Php,
                },
            );
        }
        let dir = parent_dir(&path);
        let site = self.span(n);
        let cwd_resource = self.builder.current_execution_cwd();
        let Some(frame) = self.nest.begin(
            self.builder,
            Transition::file(Subject::Source {
                dialect: None,
                language: "php".to_string(),
                source: source.clone(),
                cwd: self.runtime_cwd.map(str::to_string),
                context: Default::default(),
            })
            .origin(origin)
            .cwd(cwd_resource, self.cwd_node),
            &[site],
            self.depth,
        ) else {
            return;
        };
        let node = frame.scope;
        self.inc.included.insert(path.clone());
        self.inc.stack.push(path);
        analyze_file(
            self.builder,
            self.nest,
            &source,
            Some(&dir),
            self.runtime_cwd,
            self.cwd_node,
            Some(node),
            self.depth + 1,
            self.inc,
            false,
        );
        self.inc.stack.pop();
        frame.end(self.builder);
    }

    /// Statically evaluate an include-path expression: string literals, `.`
    /// concatenation, `__DIR__`, `dirname(...)`, `define()`d constants, and
    /// variables bound to concrete paths. None means the path is dynamic.
    /// `__DIR__` evaluates anchored (leading slash) so `..` composes against
    /// it even when the analysis root's cwd is repo-relative.
    fn static_path(&self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) -> Option<String> {
        match n.kind() {
            "string" | "encapsed_string" => literal_string(n, self.src),
            "parenthesized_expression" => self.static_path(n.named_child(0)?, env),
            "name" => match text(n, self.src) {
                "__DIR__" => self.source_cwd.map(anchored),
                other => self.inc.consts.get(other).cloned(),
            },
            "variable_name" => {
                let name = child_kind(n, "name").map(|x| text(x, self.src))?;
                match self.locals.get(name).or_else(|| env.get(name)) {
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    }) => Some(path.clone()),
                    _ => None,
                }
            }
            "member_access_expression" => concrete_fs_path(&self.this_property_value(n)?),
            "class_constant_access_expression" => concrete_fs_path(&self.class_constant_value(n)?),
            "scoped_property_access_expression" => {
                concrete_fs_path(&self.static_property_value(n)?)
            }
            "binary_expression" => {
                let mut path = String::new();
                let mut stack = vec![n];
                while let Some(part) = stack.pop() {
                    if part.kind() == "binary_expression" {
                        if part
                            .child_by_field_name("operator")
                            .map(|operator| text(operator, self.src))
                            != Some(".")
                        {
                            return None;
                        }
                        let mut cursor = part.walk();
                        let children: Vec<Node> = part.named_children(&mut cursor).collect();
                        stack.extend(children.into_iter().rev());
                    } else {
                        path.push_str(&self.static_path(part, env)?);
                    }
                }
                Some(path)
            }
            "function_call_expression" => {
                if child_kind(n, "name").map(|x| text(x, self.src)) != Some("dirname") {
                    return None;
                }
                let [arg] = arg_nodes(n)[..] else { return None };
                if arg.kind() == "name" && text(arg, self.src) == "__FILE__" {
                    // dirname(__FILE__) is the including file's directory.
                    return self.source_cwd.map(anchored);
                }
                Some(parent_dir(&self.static_path(arg, env)?))
            }
            _ => None,
        }
    }

    fn follow(&mut self, name: &str, args: &[ResourceExpr], site: Node<'a>) {
        if self.call_depth >= CALL_DEPTH_LIMIT || !self.following.insert(name.to_string()) {
            return;
        }
        self.call_depth += 1;
        let previous_call = self
            .builder
            .enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(self.src, site.start_byte(), site.end_byte()),
            ));
        let caller_closures = std::mem::take(&mut self.closures);
        let caller_vars = std::mem::take(&mut self.vars);
        let caller_locals = std::mem::take(&mut self.locals);
        let caller_network_handles = std::mem::take(&mut self.network_handles);
        let caller_poisoned = std::mem::take(&mut self.poisoned);
        let caller_captures = std::mem::take(&mut self.capture_locals);
        let caller_truths = std::mem::take(&mut self.truth_locals);
        let caller_globals_written = std::mem::take(&mut self.globals_written);
        let outermost = self.enter_facts(&caller_captures, &caller_truths);
        let caller_class = self.current_class.take();
        let caller_parent = self.class_parent.take();
        if let Some(f) = self.functions.get(name) {
            self.entered_callables.insert(name.to_string());
            let env = bind_php_params(&f.params, args);
            let body = f.body;
            let _ = site;
            let mut c = body.walk();
            let children: Vec<Node> = body.named_children(&mut c).collect();
            self.control_body(body, |w| w.exec_statements(&children, &env));
        }
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
        self.following.remove(name);
        self.builder.leave_condition_call(previous_call);
    }

    /// A `captured` command returns its stdout to the program, as backticks,
    /// `shell_exec` and `exec` do, so it does not reach the program's stdout.
    fn nest_shell(
        &mut self,
        cmd: String,
        site: Node<'a>,
        environment: BTreeMap<String, Option<ResourceExpr>>,
        captured: bool,
    ) {
        let node = self.span(site);
        let source_cwd = self.nest.current_source_cwd();
        let span = (site.start_byte(), site.end_byte());
        let captured = captured && !self.printed_captures.contains(&span);
        let child = self.builder.next_execution();
        let inherited_stdout = self.builder.inherited_execution_streams().stdout;
        {
            let subject = Subject::Shell {
                source: cmd,
                cwd: self.runtime_cwd.map(str::to_string),
                context: Default::default(),
            };
            let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
            let mut transition = Transition::file(subject)
                .source_cwd(source_cwd.as_deref())
                .runtime_cwd(runtime_cwd.as_deref())
                .cwd(self.runtime_cwd_resource.clone(), self.cwd_node)
                .environment(environment, BTreeMap::new(), Default::default());
            if captured {
                transition = transition.streams(effinterp_proto::ExecutionStreams {
                    stdout: None,
                    ..self.builder.inherited_execution_streams()
                });
            }
            self.nest
                .nest(self.builder, transition, &[node], self.depth);
        };
        if captured && child != self.builder.next_execution() {
            self.captured_outputs
                .insert(span, (child, inherited_stdout));
        }
    }

    /// An output call prints its arguments to the program's stdout. Its
    /// capture sites, which run after it in this walk, keep that stdout, and a
    /// local holding earlier captured output reconnects that command's stdout.
    /// When this reading cannot tell whether captured bytes are printed
    /// verbatim (a format it cannot follow, an unknown `print_r` mode), the
    /// call raises a boundary instead of an exact flow.
    fn print_captures(&mut self, call: Node<'a>) {
        let args = arg_nodes(call);
        let (printed, exact) = match call.kind() {
            "echo_statement" | "print_intrinsic" => {
                let mut cursor = call.walk();
                (call.named_children(&mut cursor).collect(), true)
            }
            _ if callable_name(call, self.src)
                .is_some_and(|name| name.eq_ignore_ascii_case("printf")) =>
            {
                match formatted_arguments(&args, self.src) {
                    Some(printed) => (printed, true),
                    None => (args, false),
                }
            }
            // `print_r($value, true)` returns the text instead of printing it.
            _ => match args.get(1).map(|mode| self.mode_truth(*mode)) {
                Some(Some(true)) => return,
                Some(None) => (args.into_iter().take(1).collect(), false),
                None | Some(Some(false)) => (args.into_iter().take(1).collect(), true),
            },
        };
        let mut uncertain = false;
        for expression in printed {
            let (spans, locals) = capture_sources(expression, self.src);
            for (span, verbatim) in spans {
                if exact && verbatim {
                    self.printed_captures.insert(span);
                } else {
                    uncertain = true;
                }
            }
            for (local, verbatim) in locals {
                for (span, held) in self.capture_locals.get(&local).cloned().unwrap_or_default() {
                    if !(exact && verbatim && held) {
                        uncertain = true;
                    } else if let Some((child, stdout)) = self.captured_outputs.get(&span).cloned()
                    {
                        self.builder.set_execution_stdout(child, stdout);
                    }
                }
            }
        }
        if uncertain {
            self.opaque(
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                call,
            );
        }
    }

    /// Value facts hold only while this scope's straight-line code is their
    /// only writer. A construct that may write locals this walk does not
    /// model forgets the facts about them.
    fn forget_written(&mut self, n: Node<'a>) {
        let variables = |node: Node| -> Vec<String> {
            let mut names = Vec::new();
            let mut stack = vec![node];
            while let Some(node) = stack.pop() {
                if node.kind() == "variable_name" {
                    names.push(text(node, self.src).to_string());
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            names
        };
        match n.kind() {
            // Included code, `eval` and variable variables run in or name
            // this scope.
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression"
            | "dynamic_variable_name" => self.forget_facts(None),
            "variable_name" if text(n, self.src) == "$GLOBALS" => {
                self.globals_written = true;
                self.forget_facts(None);
            }
            // `global $x` binds the top-level `$x`: its facts as the calls
            // began, unless code since then wrote globals.
            "global_declaration" if self.global_facts.is_some() => {
                let stale = self.globals_written;
                self.globals_written = true;
                let names = variables(n);
                self.forget_facts(Some(&names));
                if let Some((captures, truths)) = &self.global_facts {
                    for name in names {
                        if let Some(held) = captures.get(&name) {
                            let held = held.iter().map(|&(span, exact)| (span, exact && !stale));
                            self.capture_locals.insert(name.clone(), held.collect());
                        }
                        match truths.get(&name) {
                            Some(truth) if !stale => self.truth_locals.insert(name, *truth),
                            _ => self.truth_locals.remove(&name),
                        };
                    }
                }
            }
            // An alias lets a later write through either name change both.
            "reference_assignment_expression" => self.forget_facts(Some(&variables(n))),
            "function_call_expression"
                if callable_name(n, self.src).is_some_and(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "extract" | "parse_str" | "mb_parse_str" | "compact" | "eval"
                    )
                }) =>
            {
                self.forget_facts(None)
            }
            _ => {}
        }
        // Writes a literal truth value does not survive: compound and
        // element assignments, increments, destructuring, loop and catch
        // variables, statics, and variables a call may take by reference.
        let written = match n.kind() {
            "augmented_assignment_expression" | "update_expression" | "list_literal" => {
                variables(n)
            }
            "assignment_expression" => n
                .child_by_field_name("left")
                .filter(|left| left.kind() != "variable_name")
                .map(variables)
                .unwrap_or_default(),
            "foreach_statement" | "catch_clause" | "static_variable_declaration" => {
                let body = n.child_by_field_name("body").map(|body| body.id());
                let mut cursor = n.walk();
                n.named_children(&mut cursor)
                    .filter(|child| Some(child.id()) != body)
                    .flat_map(variables)
                    .collect()
            }
            "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression"
                if !callable_name(n, self.src).is_some_and(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "print_r" | "printf" | "sprintf"
                    )
                }) =>
            {
                arg_nodes(n)
                    .into_iter()
                    .filter(|arg| arg.kind() == "variable_name")
                    .map(|arg| text(arg, self.src).to_string())
                    .collect()
            }
            _ => Vec::new(),
        };
        for name in written {
            self.truth_locals.remove(&name);
        }
    }

    /// Forget the facts about `names`, or about every local: a truth value
    /// becomes unknown, and output a local held may or may not still be
    /// there, so printing it raises a boundary.
    fn forget_facts(&mut self, names: Option<&[String]>) {
        match names {
            None => {
                self.truth_locals.clear();
                for held in self.capture_locals.values_mut() {
                    held.iter_mut().for_each(|capture| capture.1 = false);
                }
            }
            Some(names) => {
                for name in names {
                    self.truth_locals.remove(name);
                    if let Some(held) = self.capture_locals.get_mut(name) {
                        held.iter_mut().for_each(|capture| capture.1 = false);
                    }
                }
            }
        }
    }

    /// The PHP truth value of a literal or of a local a definite assignment
    /// gave a literal.
    fn mode_truth(&self, mode: Node) -> Option<bool> {
        literal_truth(mode, self.src).or_else(|| {
            (mode.kind() == "variable_name")
                .then(|| self.truth_locals.get(text(mode, self.src)).copied())
                .flatten()
        })
    }

    fn nest_sql(&mut self, arg: Option<Node<'a>>, site: Node<'a>) {
        match arg.and_then(|a| literal_string(a, self.src)) {
            Some(sql) => {
                let node = self.span(site);
                self.nest.nest(
                    self.builder,
                    Transition::file(Subject::Sql {
                        source: sql,
                        dialect: effinterp_proto::SqlDialect::Mysql,
                        connection: Default::default(),
                    })
                    .source_cwd(self.nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(self.nest.current_runtime_cwd().as_deref())
                    .cwd(
                        self.builder.current_execution_cwd(),
                        self.nest.current_cwd_node(),
                    ),
                    &[node],
                    self.depth,
                );
            }
            None => self.opaque(
                BoundaryReason::UNRESOLVED_SQL,
                BoundaryClass::Unresolved,
                site,
            ),
        }
    }

    fn is_url(&self, arg: Option<Node<'a>>) -> bool {
        let Some(arg) = arg else { return false };
        if literal_string(arg, self.src).is_some_and(|url| url.contains("://")) {
            return true;
        }
        if arg.kind() != "encapsed_string" {
            return false;
        }
        arg.named_child(0)
            .filter(|part| matches!(part.kind(), "string_content" | "escape_sequence"))
            .is_some_and(|part| text(part, self.src).contains("://"))
    }

    fn url_resource(
        &self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
    ) -> ResourceExpr {
        let unresolved = || ResourceExpr::Unresolved {
            family: ResourceFamily::new("network"),
        };
        let Some(arg) = arg else { return unresolved() };
        if let Some(url) = literal_string(arg, self.src) {
            return model::endpoint(&url).unwrap_or_else(unresolved);
        }
        if arg.kind() == "encapsed_string" {
            let mut values = env.clone();
            values.extend(self.locals.clone());
            if !self.shell_local_environment(arg, &values).is_empty() {
                return arg
                    .named_child(0)
                    .filter(|part| matches!(part.kind(), "string_content" | "escape_sequence"))
                    .and_then(|part| model::endpoint(text(part, self.src)))
                    .unwrap_or_else(unresolved);
            }
            return model::endpoint(&self.interpolate(arg, &values)).unwrap_or_else(unresolved);
        }
        let mut values = env.clone();
        values.extend(self.locals.clone());
        match self.resolve_value(arg, &values) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => model::endpoint(&path).unwrap_or_else(unresolved),
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme,
                        port,
                        path,
                    },
            } => ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme,
                    port,
                    path,
                },
            },
            _ => unresolved(),
        }
    }

    fn is_network_handle(&self, arg: Node<'a>) -> bool {
        variable_name(arg, self.src).is_some_and(|name| self.network_handles.contains_key(name))
    }

    /// A shell command string: a literal string, or an interpolated string with
    /// concrete params substituted (unknown `$vars` left for the shell frontend).
    fn command_string(
        &self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<(String, BTreeMap<String, Option<ResourceExpr>>)> {
        let a = arg?;
        let mut values = env.clone();
        values.extend(self.locals.clone());
        match a.kind() {
            "string" => literal_string(a, self.src).map(|cmd| (cmd, BTreeMap::new())),
            // A `$cmd` bound to literal text.
            "variable_name" => {
                match child_kind(a, "name").and_then(|name| values.get(text(name, self.src))) {
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    }) => Some((path.clone(), BTreeMap::new())),
                    _ => None,
                }
            }
            "encapsed_string" => Some((
                self.interpolate(a, &values),
                self.shell_local_environment(a, &values),
            )),
            _ => None,
        }
    }

    fn shell_local_environment(
        &self,
        node: Node<'a>,
        values: &HashMap<String, ResourceExpr>,
    ) -> BTreeMap<String, Option<ResourceExpr>> {
        let mut environment = BTreeMap::new();
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "variable_name"
                && let Some(name) = child_kind(node, "name").map(|name| text(name, self.src))
                && !matches!(
                    values.get(name),
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { .. },
                    })
                )
            {
                environment.insert(name.to_string(), None);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        environment
    }

    /// Build a string from an encapsed_string, substituting `$var` with a bound
    /// param's concrete path when known, else keeping `$var` literally.
    fn interpolate(&self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) -> String {
        let mut out = String::new();
        let mut c = n.walk();
        for part in n.named_children(&mut c) {
            match part.kind() {
                "string_content" | "escape_sequence" => out.push_str(text(part, self.src)),
                "variable_name" => {
                    let name = child_kind(part, "name")
                        .map(|x| text(x, self.src))
                        .unwrap_or("");
                    match env.get(name) {
                        Some(ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        }) => out.push_str(path),
                        _ => {
                            out.push('$');
                            out.push_str(name);
                        }
                    }
                }
                _ => out.push_str(text(part, self.src)),
            }
        }
        out
    }

    /// Resolve a filesystem sink expression, anchoring the completed path to
    /// the runtime cwd only when its first concrete segment is relative.
    fn resolve(&self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) -> ResourceExpr {
        let mut values = env.clone();
        values.extend(self.locals.clone());
        let mut resource = self.resolve_value(n, &values);
        if contains_unresolved(&resource)
            && let Some(path) = self.static_path(n, &values)
        {
            resource = fs_path(&path);
        }
        let resource =
            effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix);
        let cwd = self
            .runtime_cwd_resource
            .as_ref()
            .map(|_| ResourceExpr::Parameter {
                name: "cwd".to_string(),
            });
        if let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &resource
        {
            return crate::paths::resolve_fs_path_with_cwd(path, cwd);
        }
        if let ResourceExpr::Join { parts } = &resource
            && matches!(
                parts.first(),
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                }) if !effinterp_proto::is_absolute_path(path, effinterp_proto::PathPlatform::Posix)
            )
        {
            return ResourceExpr::Join {
                parts: vec![
                    cwd.unwrap_or_else(|| ResourceExpr::Parameter {
                        name: "cwd".to_string(),
                    }),
                    resource,
                ],
            };
        }
        resource
    }

    fn resolve_argument(
        &self,
        node: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> ResourceExpr {
        let mut values = env.clone();
        values.extend(self.locals.clone());
        let value = self.resolve_value(node, &values);
        if contains_unresolved(&value)
            && let Some(path) = self.static_path(node, &values)
        {
            return fs_path(&path);
        }
        value
    }

    fn resolve_value(&self, node: Node<'a>, env: &HashMap<String, ResourceExpr>) -> ResourceExpr {
        match node.kind() {
            "member_access_expression" => self
                .this_property_value(node)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            "class_constant_access_expression" => self
                .class_constant_value(node)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            "scoped_property_access_expression" => self
                .static_property_value(node)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .map(|operator| text(operator, self.src))
                    == Some(".") =>
            {
                let mut parts = Vec::new();
                let mut stack = vec![node];
                while let Some(part) = stack.pop() {
                    if part.kind() == "binary_expression"
                        && part
                            .child_by_field_name("operator")
                            .map(|operator| text(operator, self.src))
                            == Some(".")
                    {
                        let mut cursor = part.walk();
                        let children: Vec<Node> = part.named_children(&mut cursor).collect();
                        stack.extend(children.into_iter().rev());
                    } else {
                        parts.push(self.resolve_value(part, env));
                    }
                }
                text_concat(parts)
            }
            "encapsed_string" if literal_string(node, self.src).is_none() => {
                let mut parts = Vec::new();
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
                    match part.kind() {
                        "string_content" | "escape_sequence" => {
                            parts.push(fs_path(text(part, self.src)))
                        }
                        _ => parts.push(self.resolve_value(part, env)),
                    }
                }
                text_concat(parts)
            }
            "function_call_expression" => self
                .resolve_function_value(node, env)
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            _ => resolve_expr(node, self.src, env),
        }
    }

    fn resolve_function_value(
        &self,
        node: Node<'a>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<ResourceExpr> {
        match callable_name(node, self.src)?.as_str() {
            "getenv" => arg_nodes(node)
                .first()
                .and_then(|argument| literal_string(*argument, self.src))
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Environment { name }),
            "sprintf" => {
                resolve_sprintf(node, self.src, |argument| self.resolve_value(argument, env))
            }
            "dirname" => self.static_path(node, env).map(|path| fs_path(&path)),
            _ => None,
        }
    }

    fn this_property_value(&self, node: Node<'a>) -> Option<ResourceExpr> {
        let property = this_property(node, self.src)?;
        let class = self.current_class.as_ref()?;
        self.inc.props.get(class)?.get(&property).cloned()
    }

    fn class_constant_value(&self, node: Node<'a>) -> Option<ResourceExpr> {
        let (scope, name) = scoped_value_parts(node, self.src)?;
        let class = match scope.as_str() {
            "self" | "static" => self.current_class.clone()?,
            other => resolve_class_text(&self.ctx, other),
        };
        self.ctx.consts.get(&class)?.get(&name).cloned()
    }

    fn static_property_value(&self, node: Node<'a>) -> Option<ResourceExpr> {
        let (scope, name) = scoped_value_parts(node, self.src)?;
        let class = match scope.as_str() {
            "self" | "static" => self.current_class.clone()?,
            other => resolve_class_text(&self.ctx, other),
        };
        self.ctx.static_props.get(&class)?.get(&name).cloned()
    }

    /// Emit one effect and report its plan slot, so a transfer emitter can
    /// pair the endpoints it just produced.
    fn emit(&mut self, effect: Effect, site: Node<'a>) -> Option<u32> {
        self.emit_applying(effect, site, None)
    }

    /// `emit`, attributing the effect to the named model's application.
    fn emit_applying(
        &mut self,
        mut effect: Effect,
        site: Node<'a>,
        model: Option<&str>,
    ) -> Option<u32> {
        let mut guard = super::conditions::tree_condition(self.src, site);
        self.builder.bind_source_condition(&mut guard);
        effect.condition =
            effinterp_proto::Condition::compose(effect.condition.iter().chain(guard.iter()));
        let mut environment_nodes = Vec::new();
        if effect.operation.as_str() == "environment.write" {
            self.environment_rewritten = true;
        } else if effect.operation.domain() == "filesystem"
            && self.resolve_host_environment(&mut effect.resource, &mut environment_nodes)
        {
            effect.resource = fold_host_path(effect.resource);
        }
        let uses_cwd =
            effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource);
        if uses_cwd && let Some(cwd) = &self.runtime_cwd_resource {
            effect.resource = substitute_resource_expr(
                &effect.resource,
                &HashMap::from([("cwd".to_string(), cwd.clone())]),
            );
        }
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        let node = self.span(site);
        effect.provenance = vec![node];
        effect.provenance.extend(model.map(|model| {
            self.builder.node(
                ProvenanceKind::ModelApplication {
                    model: model.to_string(),
                },
                &[node],
            )
        }));
        effect.provenance.extend(environment_nodes);
        if uses_cwd {
            effect.provenance.extend(self.cwd_node);
        }
        self.builder.effect(effect)
    }

    /// Replace `getenv(...)` references with the values the enclosing
    /// execution or host supplied, so `getenv("HOME")."/x"` names the same
    /// file as the path written out. Reports whether any was replaced.
    fn resolve_host_environment(
        &mut self,
        resource: &mut ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) -> bool {
        match resource {
            ResourceExpr::Environment { name } => {
                let Some(value) = self.host_environment_value(name) else {
                    return false;
                };
                let node = self.nest.current_environment_node(name).unwrap_or_else(|| {
                    self.builder.node(
                        ProvenanceKind::HostContext {
                            name: format!("env.{name}"),
                        },
                        &[],
                    )
                });
                provenance.push(node);
                *resource = value;
                true
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => parts.iter_mut().fold(false, |replaced, part| {
                self.resolve_host_environment(part, provenance) || replaced
            }),
            _ => false,
        }
    }

    /// The effective value of one environment name, preferring an override the
    /// enclosing execution established over the value the host supplied.
    fn host_environment_value(&self, name: &str) -> Option<ResourceExpr> {
        if self.environment_rewritten || self.nest.current_environment_unsets().contains(name) {
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

    /// Record that `source` is the source side of one modeled transfer whose
    /// destination side is `destination`.
    fn record_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        if let (Some(source), Some(destination)) = (source, destination) {
            self.builder
                .transfer_binding(TransferBinding::new(source, destination));
        }
    }

    fn span(&mut self, n: Node<'a>) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: n.start_byte() as u32,
                end: n.end_byte() as u32,
            },
            self.scope.as_slice(),
        )
    }

    fn opaque(&mut self, reason: BoundaryReason, class: BoundaryClass, site: Node<'a>) {
        self.opaque_with_detail(reason, class, site, None);
    }

    fn opaque_with_detail(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        site: Node<'a>,
        detail: Option<String>,
    ) {
        if !self
            .reported
            .insert(format!("{reason}:{}", site.start_byte()))
        {
            return;
        }
        let node = self.span(site);
        self.builder.boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: site.child_by_field_name("function").map(|function| {
                effinterp_proto::CalleeReference {
                    module: "php".to_string(),
                    symbol: text(function, self.src).to_string(),
                }
            }),
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail,
        });
        for d in KNOWN_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(d), CoverageLevel::Partial);
        }
    }

    fn candidate_limit(&mut self, site: Node<'a>) {
        if !self
            .reported
            .insert("dynamic_dispatch:candidate_limit".to_string())
        {
            return;
        }
        let node = self.span(site);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::DYNAMIC_DISPATCH,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: Some("max_callback_values".to_string()),
            detail: Some("php callback or receiver candidate limit exceeded".to_string()),
        });
        for d in KNOWN_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(d), CoverageLevel::Partial);
        }
    }
}

/// A construct that writes its arguments to the program's standard output.
fn prints_to_stdout(n: Node, src: &str) -> bool {
    match n.kind() {
        "echo_statement" | "print_intrinsic" => true,
        "function_call_expression" => matches!(
            callable_name(n, src)
                .map(|name| name.to_ascii_lowercase())
                .as_deref(),
            Some("printf" | "print_r")
        ),
        _ => false,
    }
}

/// The arguments of a `printf`-style call whose text the output contains: a
/// literal format's plain `%s` arguments. `None` when the format is not a
/// literal this reading follows.
fn formatted_arguments<'a>(args: &[Node<'a>], src: &str) -> Option<Vec<Node<'a>>> {
    let format = literal_string(*args.first()?, src)?;
    let indices = crate::lang::frontend::format_text_arguments(
        &format,
        &[
            'b', 'c', 'd', 'e', 'E', 'f', 'F', 'g', 'G', 'h', 'H', 'o', 'u', 'x', 'X',
        ],
    )?;
    Some(
        indices
            .into_iter()
            .filter_map(|index| args.get(index + 1).copied())
            .collect(),
    )
}

/// The truth value PHP gives a literal: `true`/`false`/`null`, a number, or
/// a string, looking through parentheses.
fn literal_truth(node: Node, src: &str) -> Option<bool> {
    match node.kind() {
        "parenthesized_expression" => literal_truth(node.named_child(0)?, src),
        "boolean" | "null" => Some(text(node, src).eq_ignore_ascii_case("true")),
        "integer" | "float" => text(node, src)
            .parse::<f64>()
            .ok()
            .map(|value| value != 0.0),
        _ => literal_string(node, src).map(|value| !value.is_empty() && value != "0"),
    }
}

/// A capture site's span, with whether a value holds its bytes verbatim.
type HeldCapture = ((usize, usize), bool);

/// A scope's captured output by local, and its locals' literal truth values.
type ValueFacts = (HashMap<String, Vec<HeldCapture>>, HashMap<String, bool>);

/// The capture sites (backticks, `shell_exec`, `exec`) and local names whose
/// bytes an expression's value carries. Only forms that keep the text pass
/// them on: interpolation, `.` concatenation, a branch's result, whitespace
/// trimming and string conversion. A length, a comparison or any other
/// computation over captured output does not carry its bytes.
fn capture_sources(node: Node, src: &str) -> (Vec<HeldCapture>, Vec<(String, bool)>) {
    let mut spans = Vec::new();
    let mut locals = Vec::new();
    // Each source is paired with whether its bytes reach the value verbatim;
    // a format this reading cannot follow may or may not print them.
    let mut stack = vec![(node, true)];
    while let Some((node, exact)) = stack.pop() {
        match node.kind() {
            "shell_command_expression" => spans.push(((node.start_byte(), node.end_byte()), exact)),
            "variable_name" => locals.push((text(node, src).to_string(), exact)),
            "function_call_expression" => {
                let args = arg_nodes(node);
                match callable_name(node, src)
                    .map(|name| name.to_ascii_lowercase())
                    .as_deref()
                {
                    Some("shell_exec" | "exec") => {
                        spans.push(((node.start_byte(), node.end_byte()), exact))
                    }
                    Some("trim" | "ltrim" | "rtrim" | "strval") => {
                        stack.extend(args.first().map(|arg| (*arg, exact)))
                    }
                    Some("sprintf") => match formatted_arguments(&args, src) {
                        Some(printed) => stack.extend(printed.into_iter().map(|arg| (arg, exact))),
                        None => stack.extend(args.into_iter().map(|arg| (arg, false))),
                    },
                    _ => {}
                }
            }
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| matches!(text(operator, src), "." | "??")) =>
            {
                stack.extend(node.child_by_field_name("left").map(|side| (side, exact)));
                stack.extend(node.child_by_field_name("right").map(|side| (side, exact)));
            }
            "conditional_expression" => {
                // `a ?: b` yields `a` itself when it is truthy.
                match node.child_by_field_name("body") {
                    Some(body) => stack.push((body, exact)),
                    None => stack.extend(
                        node.child_by_field_name("condition")
                            .map(|condition| (condition, exact)),
                    ),
                }
                stack.extend(
                    node.child_by_field_name("alternative")
                        .map(|alternative| (alternative, exact)),
                );
            }
            "encapsed_string" | "heredoc" | "heredoc_body" | "parenthesized_expression" => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).map(|child| (child, exact)));
            }
            _ => {}
        }
    }
    (spans, locals)
}

/// Callee of a function call: a bare `name` or a written `qualified_name`.
/// Variable / computed callees are None (dynamic).
fn callable_name(n: Node, src: &str) -> Option<String> {
    let node = n
        .child_by_field_name("function")
        .filter(|f| matches!(f.kind(), "name" | "qualified_name"))
        .or_else(|| child_kind(n, "name"))
        .or_else(|| child_kind(n, "qualified_name"))?;
    Some(text(node, src).trim_start_matches('\\').to_string())
}

fn callable_array(n: Node, src: &str) -> Option<(String, String)> {
    if n.kind() != "array_creation_expression" {
        return None;
    }
    let mut cursor = n.walk();
    let values: Vec<Node> = n
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "array_element_initializer")
        .filter_map(|element| {
            let mut cursor = element.walk();
            element.named_children(&mut cursor).last()
        })
        .collect();
    let receiver = values.first().map(|value| {
        literal_string(*value, src).unwrap_or_else(|| text(*value, src).to_string())
    })?;
    let method = values
        .get(1)
        .and_then(|value| literal_string(*value, src))?;
    Some((receiver, method))
}

fn array_values(n: Node) -> Vec<Node> {
    if n.kind() != "array_creation_expression" {
        return Vec::new();
    }
    let mut cursor = n.walk();
    n.named_children(&mut cursor)
        .filter(|child| child.kind() == "array_element_initializer")
        .filter_map(|element| {
            let mut cursor = element.walk();
            element.named_children(&mut cursor).last()
        })
        .collect()
}

/// A bare name lives in the current file's function table. `Ns\fn` matches
/// only when this file declared that namespace.
fn same_namespace(ctx: &FileCtx, fname: &str) -> bool {
    match fname.rsplit_once('\\') {
        None => true,
        Some((ns, _)) => ctx.namespace.as_deref() == Some(ns),
    }
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
    let ctx = file_ctx(root, source);
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

fn superglobal_resource(n: Node, src: &str) -> Option<(String, ResourceExpr)> {
    if n.kind() != "subscript_expression" {
        return None;
    }
    let mut cursor = n.walk();
    let mut named = n.named_children(&mut cursor);
    let (Some(base), Some(index)) = (named.next(), named.next()) else {
        return None;
    };
    if base.kind() != "variable_name" {
        return None;
    }
    let name = child_kind(base, "name").map(|name| text(name, src).to_string())?;
    let resource = literal_string(index, src)
        .filter(|name| !name.is_empty())
        .map(|name| ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        })
        .unwrap_or(ResourceExpr::Unresolved {
            family: ResourceFamily::new("environment"),
        });
    Some((name, resource))
}

/// Whether an environment subscript is being assigned or unset rather than read.
fn is_environment_mutation_target(n: Node) -> bool {
    n.parent().is_some_and(|p| {
        (p.kind() == "assignment_expression"
            && p.child_by_field_name("left")
                .is_some_and(|l| l.id() == n.id()))
            || p.kind() == "unset_statement"
    })
}

fn arg_nodes<'a>(call: Node<'a>) -> Vec<Node<'a>> {
    let Some(args) = child_kind(call, "arguments") else {
        return Vec::new();
    };
    let mut c = args.walk();
    args.named_children(&mut c)
        .filter_map(|a| {
            if a.kind() == "argument" {
                // The value follows an optional `name:` and `&` modifier.
                let mut cc = a.walk();
                a.named_children(&mut cc).last()
            } else {
                Some(a)
            }
        })
        .collect()
}

/// The value of a call's `name:` argument; named arguments may appear in any
/// order.
fn named_argument<'a>(call: Node<'a>, name: &str, src: &str) -> Option<Node<'a>> {
    let args = child_kind(call, "arguments")?;
    let mut c = args.walk();
    args.named_children(&mut c)
        .filter(|a| a.kind() == "argument")
        .find(|a| {
            a.child_by_field_name("name")
                .is_some_and(|argument| text(argument, src) == name)
        })
        .and_then(|a| {
            let mut cc = a.walk();
            a.named_children(&mut cc).last()
        })
}

/// The first static string literal in `n`'s subtree, in pre-order. Used to pull
/// the path out of a `require`/`include` whose argument is a concatenation
/// (`__DIR__ . '/util.php'`) rather than a bare literal.
fn first_string_literal(n: Node, src: &str) -> Option<String> {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        if let Some(s) = literal_string(n, src) {
            return Some(s);
        }
        let mut c = n.walk();
        let children: Vec<Node> = n.named_children(&mut c).collect();
        for ch in children.into_iter().rev() {
            stack.push(ch);
        }
    }
    None
}

/// A single-quoted `string` or a fully-literal `encapsed_string` (no
/// interpolation) as a Rust string, else None.
fn literal_string(n: Node, src: &str) -> Option<String> {
    if !matches!(n.kind(), "string" | "encapsed_string") {
        return None;
    }
    let mut cursor = n.walk();
    if n.named_children(&mut cursor)
        .any(|part| !matches!(part.kind(), "string_content" | "escape_sequence"))
    {
        return None;
    }
    let raw = text(n, src).as_bytes();
    let quote = *raw.first()?;
    if !matches!(quote, b'\'' | b'"') || raw.last() != Some(&quote) {
        return None;
    }
    let mut bytes = raw.get(1..raw.len() - 1)?.iter().copied().peekable();
    let mut out = Vec::new();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        let escaped = bytes.next()?;
        if quote == b'\'' {
            if !matches!(escaped, b'\'' | b'\\') {
                out.push(b'\\');
            }
            out.push(escaped);
            continue;
        }
        match escaped {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'e' => out.push(27),
            b'f' => out.push(12),
            b'\\' | b'$' | b'"' => out.push(escaped),
            b'x' if bytes.peek().is_some_and(u8::is_ascii_hexdigit) => {
                let mut value = 0;
                for _ in 0..2 {
                    let Some(digit) = bytes.peek().and_then(|b| (*b as char).to_digit(16)) else {
                        break;
                    };
                    bytes.next();
                    value = value * 16 + digit as u8;
                }
                out.push(value);
            }
            b'0'..=b'7' => {
                let mut value = escaped - b'0';
                for _ in 0..2 {
                    let Some(digit @ b'0'..=b'7') = bytes.peek().copied() else {
                        break;
                    };
                    bytes.next();
                    value = value.wrapping_mul(8).wrapping_add(digit - b'0');
                }
                out.push(value);
            }
            b'u' if bytes.peek() == Some(&b'{') => {
                bytes.next();
                let mut value = 0u32;
                let mut digits = 0;
                loop {
                    let digit = bytes.next()?;
                    if digit == b'}' {
                        break;
                    }
                    value = value
                        .checked_mul(16)?
                        .checked_add((digit as char).to_digit(16)?)?;
                    digits += 1;
                }
                if digits == 0 {
                    return None;
                }
                let mut buffer = [0; 4];
                out.extend_from_slice(char::from_u32(value)?.encode_utf8(&mut buffer).as_bytes());
            }
            other => out.extend_from_slice(&[b'\\', other]),
        }
    }
    String::from_utf8(out).ok()
}

fn resolve_expr(n: Node, src: &str, env: &HashMap<String, ResourceExpr>) -> ResourceExpr {
    match n.kind() {
        "string" | "encapsed_string" => match literal_string(n, src) {
            Some(s) => fs_path(&s),
            None if n.kind() == "encapsed_string" => {
                let mut parts = Vec::new();
                let mut cursor = n.walk();
                for part in n.named_children(&mut cursor) {
                    match part.kind() {
                        "string_content" | "escape_sequence" => {
                            parts.push(fs_path(text(part, src)))
                        }
                        _ => parts.push(resolve_expr(part, src, env)),
                    }
                }
                text_concat(parts)
            }
            None => unresolved_resource("filesystem"),
        },
        "variable_name" => {
            let name = child_kind(n, "name").map(|x| text(x, src)).unwrap_or("");
            env.get(name).cloned().unwrap_or(ResourceExpr::Unresolved {
                family: ResourceFamily::new("filesystem"),
            })
        }
        "binary_expression" => {
            // Concatenation `a . b` -> Join of the parts. Any other binary
            // operator is not a path expression (and must not re-enter
            // collect_concat, which would recurse on this same node).
            let op = n
                .child_by_field_name("operator")
                .map(|o| text(o, src))
                .unwrap_or("");
            if op != "." {
                return ResourceExpr::Unresolved {
                    family: ResourceFamily::new("filesystem"),
                };
            }
            let mut parts = Vec::new();
            collect_concat(n, src, env, &mut parts);
            text_concat(parts)
        }
        "function_call_expression" => match callable_name(n, src).as_deref() {
            Some("getenv") => arg_nodes(n)
                .first()
                .and_then(|argument| literal_string(*argument, src))
                .filter(|name| !name.is_empty())
                .map(|name| ResourceExpr::Environment { name })
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            Some("sprintf") => resolve_sprintf(n, src, |argument| resolve_expr(argument, src, env))
                .unwrap_or_else(|| unresolved_resource("filesystem")),
            _ => unresolved_resource("filesystem"),
        },
        _ => unresolved_resource("filesystem"),
    }
}

/// A `sprintf` path whose literal format uses only plain `%s` substitutions,
/// joined as text. `resolve` supplies each argument's value in the caller's
/// context; any other `%` syntax, a count mismatch, or an unresolved argument
/// rejects the call.
fn resolve_sprintf<'a>(
    node: Node<'a>,
    src: &str,
    mut resolve: impl FnMut(Node<'a>) -> ResourceExpr,
) -> Option<ResourceExpr> {
    let args = arg_nodes(node);
    let format = args
        .first()
        .and_then(|argument| literal_string(*argument, src))?;
    let literals: Vec<&str> = format.split("%s").collect();
    if literals.iter().any(|literal| literal.contains('%')) || literals.len() != args.len() {
        return None;
    }
    let mut parts = Vec::new();
    for (index, literal) in literals.iter().enumerate() {
        if !literal.is_empty() {
            parts.push(fs_path(literal));
        }
        if let Some(argument) = args.get(index + 1) {
            let value = resolve(*argument);
            if contains_unresolved(&value) {
                return None;
            }
            parts.push(value);
        }
    }
    Some(text_concat(parts))
}

fn collect_concat(
    n: Node,
    src: &str,
    env: &HashMap<String, ResourceExpr>,
    out: &mut Vec<ResourceExpr>,
) {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        if n.kind() == "binary_expression" {
            let op = n
                .child_by_field_name("operator")
                .map(|o| text(o, src))
                .unwrap_or("");
            if op == "." {
                let mut c = n.walk();
                let children: Vec<Node> = n.named_children(&mut c).collect();
                for ch in children.into_iter().rev() {
                    stack.push(ch);
                }
                continue;
            }
        }
        out.push(resolve_expr(n, src, env));
    }
}

fn fs_path(s: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: s.to_string(),
        },
    }
}

fn text_concat(mut parts: Vec<ResourceExpr>) -> ResourceExpr {
    match parts.len() {
        0 => return fs_path(""),
        1 => return parts.pop().unwrap(),
        _ => {}
    }
    let mut text = String::new();
    for part in &parts {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = part
        else {
            for part in &mut parts {
                if let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } = part
                {
                    *part = ResourceExpr::Literal {
                        value: path.clone(),
                    };
                }
            }
            // Keep textual concatenation distinct from path joining after argument binding.
            parts.insert(
                0,
                ResourceExpr::Literal {
                    value: String::new(),
                },
            );
            return ResourceExpr::Join { parts };
        };
        text.push_str(path);
    }
    fs_path(&text)
}

/// A textual concatenation whose parts are now all literal is one path.
fn fold_host_path(resource: ResourceExpr) -> ResourceExpr {
    match &resource {
        ResourceExpr::Literal { value } => fs_path(value),
        ResourceExpr::Join { parts }
            if has_text_concat(&resource)
                && parts
                    .iter()
                    .all(|part| matches!(part, ResourceExpr::Literal { .. })) =>
        {
            fs_path(
                &parts
                    .iter()
                    .filter_map(|part| match part {
                        ResourceExpr::Literal { value } => Some(value.as_str()),
                        _ => None,
                    })
                    .collect::<String>(),
            )
        }
        _ => resource,
    }
}

fn contains_unresolved(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Unresolved { .. } => true,
        ResourceExpr::Join { parts } => parts.iter().any(contains_unresolved),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(contains_unresolved),
        ResourceExpr::Property { base, .. } => contains_unresolved(base),
        _ => false,
    }
}

fn concrete_fs_path(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

fn poisoned_php_reference(node: Node, poisoned: &HashSet<String>, src: &str) -> Option<String> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_name"
            && let Some(name) = child_kind(node, "name").map(|name| text(name, src))
            && poisoned.contains(name)
        {
            return Some(name.to_string());
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

// ---- module_summaries (cross-file extraction) ----

fn summarize_ast(source: &str, tree: &tree_sitter::Tree) -> ModuleSummary {
    let root = tree.root_node();
    let ctx = file_ctx(root, source);
    let classes = php_classes(root, source, &ctx);
    let mut functions = Vec::new();
    // Deterministic order: source order of top-level function definitions.
    let mut c = root.walk();
    for stmt in root.named_children(&mut c) {
        if stmt.kind() == "function_definition"
            && let Some(name_node) = child_kind(stmt, "name")
        {
            let name = text(name_node, source).to_string();
            let params = child_kind(stmt, "formal_parameters")
                .map(|p| param_names(p, source))
                .unwrap_or_default();
            let body = child_kind(stmt, "compound_statement");
            let (effects, boundaries, mut control_flow) = summarize_body(body, &params, source);
            let mut calls = PhpCalls::new(source, &ctx, &params, HashMap::new());
            if let Some(body) = body {
                calls.walk_body(body);
            }
            let (returns_instances, return_bindings) = calls.returned_instance();
            control_flow.bind_calls(&calls.sites);
            functions.push(FunctionEntry {
                name,
                summary: Summary {
                    control_flow,
                    params: params.clone(),
                    effects,
                    effect_models: Vec::new(),
                    transfers: Vec::new(),
                    returns: None,
                    boundaries,
                    coverage: DOMAINS
                        .iter()
                        .map(|d| (Domain::new(*d), CoverageLevel::Full))
                        .collect(),
                },
                calls: calls.edges,
                returns_instances,
                return_bindings,
                ..Default::default()
            });
        }
    }

    for class in &classes {
        for method in &class.methods {
            let key = format!("{}.{}", class.entry.name, method.name);
            let (effects, boundaries, mut control_flow) =
                summarize_body(Some(method.body), &method.params, source);
            let mut calls = PhpCalls::new(source, &ctx, &method.params, method.param_types.clone());
            calls.walk_body(method.body);
            let (returns_instances, return_bindings) = calls.returned_instance();
            control_flow.bind_calls(&calls.sites);
            functions.push(FunctionEntry {
                name: key,
                summary: Summary {
                    control_flow,
                    params: method.params.clone(),
                    effects,
                    effect_models: Vec::new(),
                    transfers: Vec::new(),
                    returns: None,
                    boundaries,
                    coverage: DOMAINS
                        .iter()
                        .map(|d| (Domain::new(*d), CoverageLevel::Full))
                        .collect(),
                },
                calls: calls.edges,
                returns_instances,
                return_bindings,
                ..Default::default()
            });
        }
    }

    for class in &classes {
        if class.entry.bases.as_slice() != [SYMFONY_CONSOLE_APPLICATION] {
            continue;
        }
        let Some(defaults) = functions
            .iter_mut()
            .find(|function| function.name == format!("{}.getDefaultCommands", class.entry.name))
        else {
            continue;
        };
        let Some(method) = class
            .methods
            .iter()
            .find(|method| method.name == "getDefaultCommands")
        else {
            continue;
        };
        let mut calls = PhpCalls::new(source, &ctx, &method.params, method.param_types.clone());
        calls.walk_body(method.body);
        if calls.registry_saturated {
            defaults.summary.boundaries.push(dynamic_dispatch_boundary(
                "php command registry candidate limit exceeded",
            ));
        }
        if calls.registry_dynamic {
            defaults.summary.boundaries.push(dynamic_dispatch_boundary(
                "php command registry contains an unresolved candidate",
            ));
        }
        if !calls.registry_saturated && !calls.returned_objects.is_empty() {
            defaults.calls.push(CallEdge {
                callee: "this.getDefaultCommands".to_string(),
                arguments: calls
                    .returned_objects
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| ValueArgument {
                        name: None,
                        index,
                        value,
                    })
                    .collect(),
                lifecycle_registration: true,
                receiver: Some(SemanticValue::object(ObjectIdentity::Receiver)),
                ..Default::default()
            });
        }
        let call_defaults = CallEdge {
            callee: "this.getDefaultCommands".to_string(),
            effects_propagated: false,
            receiver: Some(SemanticValue::object(ObjectIdentity::Receiver)),
            ..Default::default()
        };
        if !functions
            .iter()
            .any(|function| function.name == format!("{}.run", class.entry.name))
        {
            functions.push(FunctionEntry {
                name: format!("{}.run", class.entry.name),
                summary: Summary {
                    coverage: DOMAINS
                        .iter()
                        .map(|d| (Domain::new(*d), CoverageLevel::Full))
                        .collect(),
                    ..Default::default()
                },
                calls: vec![call_defaults],
                ..Default::default()
            });
        }
    }

    // Top-level (module) calls to user functions.
    let mut mc = root.walk();
    let top: Vec<Node> = root.named_children(&mut mc).collect();
    let mut module = PhpCalls::new(source, &ctx, &[], HashMap::new());
    for node in &top {
        module.walk(*node);
    }
    let (_, boundaries, mut module_control_flow) = summarize_body(Some(root), &[], source);
    module_control_flow.bind_calls(&module.sites);
    let module_control_flow = module_control_flow.calls_only();
    let module_calls = module.edges;

    let imports = extract_imports(root, source);
    let exports = imports
        .iter()
        .map(|binding| ImportBinding {
            local: "*".to_string(),
            module: binding.module.clone(),
            imported: None,
        })
        .collect();
    let mut summary = ModuleSummary {
        functions,
        module_calls,
        module_control_flow,
        module_boundaries: boundaries
            .into_iter()
            .filter(|boundary| boundary.limit.is_some())
            .collect(),
        imports,
        exports,
        classes: classes.into_iter().map(|class| class.entry).collect(),
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |edge| {
        edge.callee != "this.getDefaultCommands" || edge.lifecycle_registration
    });
    summary
}

const SYMFONY_CONSOLE_APPLICATION: &str = "Symfony\\Component\\Console\\Application";

struct PhpClass<'a> {
    entry: ClassEntry,
    methods: Vec<PhpMethod<'a>>,
}

struct PhpMethod<'a> {
    name: String,
    params: Vec<String>,
    param_types: HashMap<String, String>,
    body: Node<'a>,
}

fn php_classes<'a>(root: Node<'a>, src: &str, ctx: &FileCtx) -> Vec<PhpClass<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_declaration" {
            let Some(short) = node.child_by_field_name("name") else {
                continue;
            };
            let name = resolve_class_text(ctx, text(short, src));
            let bases = child_kind(node, "base_clause")
                .and_then(|base| {
                    let mut cursor = base.walk();
                    base.named_children(&mut cursor)
                        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
                        .map(|child| resolve_class_text(ctx, text(child, src)))
                })
                .into_iter()
                .collect();
            let mut methods = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for method in body
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "method_declaration")
                {
                    let (Some(method_name), Some(method_body)) = (
                        method.child_by_field_name("name"),
                        child_kind(method, "compound_statement"),
                    ) else {
                        continue;
                    };
                    let parameters = child_kind(method, "formal_parameters");
                    let params = parameters
                        .map(|parameters| param_names(parameters, src))
                        .unwrap_or_default();
                    methods.push(PhpMethod {
                        name: text(method_name, src).to_string(),
                        params,
                        param_types: parameters
                            .map(|parameters| php_param_types(parameters, src, ctx))
                            .unwrap_or_default(),
                        body: method_body,
                    });
                }
            }
            let constructor = methods.iter().find(|method| method.name == "__construct");
            let mut attr_params = Vec::new();
            let mut attr_classes = Vec::new();
            if let Some(constructor) = constructor {
                collect_constructor_attrs(
                    constructor.body,
                    src,
                    ctx,
                    &constructor.params,
                    &mut attr_params,
                    &mut attr_classes,
                );
            }
            out.push(PhpClass {
                entry: ClassEntry {
                    name,
                    bases,
                    attr_params,
                    attr_classes,
                    ..Default::default()
                },
                methods,
            });
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out.sort_by(|left, right| left.entry.name.cmp(&right.entry.name));
    out
}

fn php_param_types(parameters: Node, src: &str, ctx: &FileCtx) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        let Some(variable) = child_kind(parameter, "variable_name")
            .and_then(|variable| child_kind(variable, "name"))
        else {
            continue;
        };
        let mut type_cursor = parameter.walk();
        let Some(ty) = parameter.named_children(&mut type_cursor).find(|child| {
            matches!(
                child.kind(),
                "named_type" | "name" | "qualified_name" | "optional_type"
            )
        }) else {
            continue;
        };
        let written = text(ty, src).trim_start_matches('?');
        if !written.is_empty() {
            out.insert(
                text(variable, src).to_string(),
                resolve_class_text(ctx, written),
            );
        }
    }
    out
}

fn collect_constructor_attrs(
    body: Node,
    src: &str,
    ctx: &FileCtx,
    params: &[String],
    attr_params: &mut Vec<(String, String)>,
    attr_classes: &mut Vec<(String, String)>,
) {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.kind() == "assignment_expression" {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            if let Some(property) = this_property(left, src) {
                if let Some(variable) = variable_name(right, src)
                    && params.iter().any(|param| param == variable)
                {
                    attr_params.push((property, variable.to_string()));
                } else if let Some(class) = new_class(right, src, ctx) {
                    attr_classes.push((property, class));
                }
            }
        }
        if matches!(
            node.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) && node.id() != body.id()
        {
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    attr_params.sort();
    attr_params.dedup();
    attr_classes.sort();
    attr_classes.dedup();
}

fn this_property(node: Node, src: &str) -> Option<String> {
    if node.kind() != "member_access_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    (variable_name(object, src) == Some("this"))
        .then(|| {
            node.child_by_field_name("name")
                .map(|name| text(name, src).to_string())
        })
        .flatten()
}

fn scoped_value_parts(node: Node, src: &str) -> Option<(String, String)> {
    let scope = node.child_by_field_name("scope").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).next()
    })?;
    let name = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).last()
    })?;
    let name = if name.kind() == "variable_name" {
        child_kind(name, "name").map(|name| text(name, src))?
    } else {
        text(name, src)
    };
    Some((
        text(scope, src).trim_start_matches('\\').to_string(),
        name.trim_start_matches('$').to_string(),
    ))
}

fn variable_name<'a>(node: Node, src: &'a str) -> Option<&'a str> {
    (node.kind() == "variable_name")
        .then(|| child_kind(node, "name").map(|name| text(name, src)))
        .flatten()
}

fn new_class(node: Node, src: &str, ctx: &FileCtx) -> Option<String> {
    if node.kind() != "object_creation_expression" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
        .map(|class| resolve_class_text(ctx, text(class, src)))
}

struct PhpCalls<'a, 'b> {
    sites: BTreeMap<crate::control_flow::Span, u32>,
    src: &'a str,
    ctx: &'b FileCtx,
    params: HashSet<String>,
    param_types: HashMap<String, String>,
    vars: HashMap<String, SemanticValue>,
    call_vars: HashSet<String>,
    arrays: HashMap<String, Vec<SemanticValue>>,
    dynamic_arrays: HashSet<String>,
    saturated_arrays: HashSet<String>,
    edges: Vec<CallEdge>,
    returns: Vec<(Option<String>, Option<String>)>,
    returned_objects: Vec<SemanticValue>,
    registry_saturated: bool,
    registry_dynamic: bool,
}

impl<'a, 'b> PhpCalls<'a, 'b> {
    fn new(
        src: &'a str,
        ctx: &'b FileCtx,
        params: &[String],
        param_types: HashMap<String, String>,
    ) -> Self {
        Self {
            src,
            ctx,
            sites: BTreeMap::new(),
            params: params.iter().cloned().collect(),
            param_types,
            vars: HashMap::new(),
            call_vars: HashSet::new(),
            arrays: HashMap::new(),
            dynamic_arrays: HashSet::new(),
            saturated_arrays: HashSet::new(),
            edges: Vec::new(),
            returns: Vec::new(),
            returned_objects: Vec::new(),
            registry_saturated: false,
            registry_dynamic: false,
        }
    }

    fn walk_body(&mut self, body: Node<'a>) {
        let _walk = crate::limits::summary_walk();
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            self.walk(child);
        }
    }

    fn walk(&mut self, node: Node<'a>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if !crate::limits::summary_step() {
                return;
            }
            let start = self.edges.len();
            match node.kind() {
                "function_definition"
                | "method_declaration"
                | "class_declaration"
                | "anonymous_function"
                | "arrow_function" => continue,
                "assignment_expression" => self.assignment(node),
                "object_creation_expression" => self.creation(node),
                "member_call_expression" | "scoped_call_expression" => self.method_call(node),
                "function_call_expression" => self.function_call(node),
                "return_statement" => self.return_statement(node),
                _ => {}
            }
            if self.edges.len() == start + 1 {
                self.sites.insert(control::span(node), start as u32);
            }
            let guard = (self.edges.len() != start)
                .then(|| super::conditions::tree_condition(self.src, node))
                .flatten();
            for edge in &mut self.edges[start..] {
                edge.condition =
                    effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
                if edge.call_site.is_none() {
                    edge.call_site = Some(effinterp_proto::stable_hash(
                        effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                        &(self.src, node.start_byte(), node.end_byte()),
                    ));
                }
            }
            let mut cursor = node.walk();
            let children: Vec<Node> = node.named_children(&mut cursor).collect();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    fn assignment(&mut self, node: Node<'a>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        if let Some(name) = variable_name(left, self.src).map(str::to_string) {
            self.vars.remove(&name);
            self.call_vars.remove(&name);
            self.arrays.remove(&name);
            self.dynamic_arrays.remove(&name);
            self.saturated_arrays.remove(&name);
            let array_like = right.kind() == "array_creation_expression"
                || (right.kind() == "function_call_expression"
                    && callable_name(right, self.src).as_deref() == Some("array_merge"));
            if self.registry_value_is_dynamic(right) {
                self.dynamic_arrays.insert(name.clone());
            }
            if let Some(value) = self.instance(right) {
                self.vars.insert(name.clone(), value);
            }
            if matches!(
                right.kind(),
                "function_call_expression" | "member_call_expression" | "scoped_call_expression"
            ) {
                self.call_vars.insert(name.clone());
            }
            let values = self.array_objects(right);
            if array_like {
                if values.len() > MAX_COMMAND_REGISTRY_VALUES {
                    self.saturated_arrays.insert(name.clone());
                }
                self.arrays.insert(name, values);
            }
            return;
        }
        if left.kind() == "subscript_expression"
            && let Some(base) = left.named_child(0)
            && let Some(name) = variable_name(base, self.src)
        {
            let Some(value) = self.instance(right) else {
                self.dynamic_arrays.insert(name.to_string());
                return;
            };
            let values = self.arrays.entry(name.to_string()).or_default();
            if values.len() >= MAX_COMMAND_REGISTRY_VALUES {
                values.clear();
                self.saturated_arrays.insert(name.to_string());
            } else {
                values.push(value);
            }
        }
    }

    fn creation(&mut self, node: Node<'a>) {
        let Some(receiver) = self.instance(node) else {
            return;
        };
        let Some(ObjectIdentity::Class { name, .. }) =
            receiver.as_object().map(|object| &object.identity)
        else {
            return;
        };
        let mut arguments = positional_arguments(self.resource_args(node));
        merge_arguments(&mut arguments, self.object_args(node));
        let binding = assigned_variable(node, self.src);
        self.edges.push(CallEdge {
            callee: name.clone(),
            arguments,
            receiver: Some(receiver),
            results: call_results(
                binding.into_iter().map(|binding| (0, binding)).collect(),
                None,
                None,
            ),
            ..Default::default()
        });
    }

    fn method_call(&mut self, node: Node<'a>) {
        let Some(method) = node
            .child_by_field_name("name")
            .filter(|name| name.kind() == "name")
            .map(|name| text(name, self.src).to_string())
        else {
            return;
        };
        let receiver = if node.kind() == "member_call_expression" {
            node.child_by_field_name("object")
                .and_then(|object| self.instance(object))
        } else {
            let scope = node.child_by_field_name("scope");
            match scope.map(|scope| (scope.kind(), text(scope, self.src))) {
                Some(("relative_scope", "parent")) => return,
                Some(("relative_scope", "self" | "static")) => {
                    Some(SemanticValue::object(ObjectIdentity::Receiver))
                }
                Some(("name" | "qualified_name", class)) => {
                    Some(SemanticValue::object(ObjectIdentity::Class {
                        name: resolve_class_text(self.ctx, class),
                        constructor: Vec::new(),
                    }))
                }
                _ => None,
            }
        };
        let Some(receiver) = receiver else {
            return;
        };
        let mut arguments = positional_arguments(self.resource_args(node));
        merge_arguments(&mut arguments, self.object_args(node));
        self.edges.push(CallEdge {
            callee: format!("receiver.{method}"),
            arguments,
            receiver: Some(receiver),
            results: call_results(
                assigned_variable(node, self.src)
                    .into_iter()
                    .map(|binding| (0, binding))
                    .collect(),
                None,
                None,
            ),
            ..Default::default()
        });
    }

    fn function_call(&mut self, node: Node<'a>) {
        let Some(name) = callable_name(node, self.src) else {
            return;
        };
        if php_summary_builtin(&name) {
            return;
        }
        let mut arguments = positional_arguments(self.resource_args(node));
        merge_arguments(&mut arguments, self.object_args(node));
        self.edges.push(CallEdge {
            callee: name,
            arguments,
            results: call_results(
                assigned_variable(node, self.src)
                    .into_iter()
                    .map(|binding| (0, binding))
                    .collect(),
                None,
                None,
            ),
            ..Default::default()
        });
    }

    fn return_statement(&mut self, node: Node<'a>) {
        let Some(value) = node.named_child(0) else {
            return;
        };
        let binding = variable_name(value, self.src).map(str::to_string);
        let class = self
            .instance(value)
            .and_then(|instance| match instance.kind {
                SemanticValueKind::Object(object) => match object.identity {
                    ObjectIdentity::Class { name, .. } => Some(name),
                    _ => binding
                        .as_ref()
                        .and_then(|name| self.vars.get(name))
                        .and_then(|value| value.as_object())
                        .and_then(|object| match &object.identity {
                            ObjectIdentity::Class { name, .. } => Some(name.clone()),
                            _ => None,
                        }),
                },
                _ => None,
            });
        self.returns.push((class, binding));
        if !self.registry_array_value(value) {
            self.registry_dynamic = true;
            return;
        }
        let values = self.array_objects(value);
        if self.registry_value_is_saturated(value) {
            self.registry_saturated = true;
        }
        if self.registry_value_is_dynamic(value) {
            self.registry_dynamic = true;
        }
        if self.returned_objects.len() + values.len() > MAX_COMMAND_REGISTRY_VALUES {
            self.returned_objects.clear();
            self.registry_saturated = true;
        } else if !self.registry_saturated {
            self.returned_objects.extend(values);
        }
    }

    fn returned_instance(&self) -> (Vec<Option<String>>, Vec<Option<String>>) {
        let Some((class, binding)) = self.returns.first() else {
            return (Vec::new(), Vec::new());
        };
        if class.is_none()
            || self
                .returns
                .iter()
                .any(|candidate| candidate.0 != *class || candidate.1 != *binding)
        {
            return (Vec::new(), Vec::new());
        }
        (vec![class.clone()], vec![binding.clone()])
    }

    fn instance(&self, node: Node<'a>) -> Option<SemanticValue> {
        self.instance_with_depth(node, CALL_DEPTH_LIMIT)
    }

    fn instance_with_depth(
        &self,
        mut node: Node<'a>,
        constructor_depth: u64,
    ) -> Option<SemanticValue> {
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while node.kind() == "parenthesized_expression" {
            if nodes == 0 || !crate::limits::summary_step() {
                return None;
            }
            nodes -= 1;
            node = node.named_child(0)?;
        }
        match node.kind() {
            "object_creation_expression" => {
                let class = new_class(node, self.src, self.ctx)?;
                Some(SemanticValue::object(ObjectIdentity::Class {
                    name: class,
                    constructor: if constructor_depth > 0 {
                        self.object_args_with_depth(node, constructor_depth - 1)
                    } else {
                        Default::default()
                    },
                }))
            }
            "variable_name" => {
                let name = variable_name(node, self.src)?;
                if name == "this" {
                    return Some(SemanticValue::object(ObjectIdentity::Receiver));
                }
                self.vars
                    .get(name)
                    .cloned()
                    .or_else(|| {
                        self.call_vars.contains(name).then(|| {
                            SemanticValue::object(ObjectIdentity::Local {
                                name: name.to_string(),
                                fallback: None,
                            })
                        })
                    })
                    .or_else(|| {
                        self.params.contains(name).then(|| {
                            SemanticValue::object(ObjectIdentity::Parameter {
                                name: name.to_string(),
                                fallback: self.param_types.get(name).cloned(),
                            })
                        })
                    })
            }
            "member_access_expression" => this_property(node, self.src)
                .map(ObjectIdentity::ReceiverProperty)
                .map(SemanticValue::object),
            _ => None,
        }
    }

    fn array_objects(&self, node: Node<'a>) -> Vec<SemanticValue> {
        let mut objects = Vec::new();
        let mut stack = vec![node];
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while let Some(node) = stack.pop() {
            if nodes == 0 || objects.len() > MAX_COMMAND_REGISTRY_VALUES {
                break;
            }
            nodes -= 1;
            match node.kind() {
                "array_creation_expression" => {
                    for value in array_values(node) {
                        if let Some(value) = self.instance(value) {
                            objects.push(value);
                            if objects.len() > MAX_COMMAND_REGISTRY_VALUES {
                                break;
                            }
                        }
                    }
                }
                "variable_name" => {
                    if let Some(values) =
                        variable_name(node, self.src).and_then(|name| self.arrays.get(name))
                    {
                        for value in values {
                            objects.push(value.clone());
                            if objects.len() > MAX_COMMAND_REGISTRY_VALUES {
                                break;
                            }
                        }
                    }
                }
                "function_call_expression"
                    if callable_name(node, self.src).as_deref() == Some("array_merge") =>
                {
                    let arguments = arg_nodes(node);
                    stack.extend(arguments.into_iter().rev());
                }
                "parenthesized_expression" => {
                    if let Some(value) = node.named_child(0) {
                        stack.push(value);
                    }
                }
                _ => objects.extend(self.instance(node)),
            }
        }
        objects
    }

    fn registry_array_value(&self, mut node: Node<'a>) -> bool {
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while node.kind() == "parenthesized_expression" {
            if nodes == 0 || !crate::limits::summary_step() {
                return false;
            }
            nodes -= 1;
            let Some(value) = node.named_child(0) else {
                return false;
            };
            node = value;
        }
        match node.kind() {
            "array_creation_expression" => true,
            "variable_name" => {
                variable_name(node, self.src).is_some_and(|name| self.arrays.contains_key(name))
            }
            "function_call_expression" => {
                callable_name(node, self.src).as_deref() == Some("array_merge")
            }
            _ => false,
        }
    }

    fn registry_value_is_dynamic(&self, node: Node<'a>) -> bool {
        let mut stack = vec![node];
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while let Some(node) = stack.pop() {
            if nodes == 0 || !crate::limits::summary_step() {
                return true;
            }
            nodes -= 1;
            match node.kind() {
                "array_creation_expression" => {
                    if array_values(node)
                        .into_iter()
                        .any(|value| self.instance(value).is_none())
                    {
                        return true;
                    }
                }
                "variable_name" => {
                    if variable_name(node, self.src).is_some_and(|name| {
                        self.dynamic_arrays.contains(name)
                            || (!self.arrays.contains_key(name) && !self.vars.contains_key(name))
                    }) {
                        return true;
                    }
                }
                "function_call_expression"
                    if callable_name(node, self.src).as_deref() == Some("array_merge") =>
                {
                    stack.extend(arg_nodes(node));
                }
                "object_creation_expression" => {
                    if new_class(node, self.src, self.ctx).is_none() {
                        return true;
                    }
                }
                "parenthesized_expression" => {
                    let Some(value) = node.named_child(0) else {
                        return true;
                    };
                    stack.push(value);
                }
                _ if self.instance(node).is_none() => return true,
                _ => {}
            }
        }
        false
    }

    fn registry_value_is_saturated(&self, node: Node<'a>) -> bool {
        let mut stack = vec![node];
        let mut nodes = crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES);
        while let Some(node) = stack.pop() {
            if nodes == 0 || !crate::limits::summary_step() {
                return true;
            }
            nodes -= 1;
            match node.kind() {
                "variable_name"
                    if variable_name(node, self.src)
                        .is_some_and(|name| self.saturated_arrays.contains(name)) =>
                {
                    return true;
                }
                "function_call_expression"
                    if callable_name(node, self.src).as_deref() == Some("array_merge") =>
                {
                    stack.extend(arg_nodes(node));
                }
                "parenthesized_expression" => {
                    if let Some(value) = node.named_child(0) {
                        stack.push(value);
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn resource_args(&self, node: Node<'a>) -> Vec<ResourceExpr> {
        let env: HashMap<String, ResourceExpr> = self
            .params
            .iter()
            .map(|name| (name.clone(), ResourceExpr::Parameter { name: name.clone() }))
            .collect();
        arg_nodes(node)
            .into_iter()
            .map(|argument| resolve_expr(argument, self.src, &env))
            .collect()
    }

    fn object_args(&self, node: Node<'a>) -> Vec<ValueArgument> {
        self.object_args_with_depth(node, CALL_DEPTH_LIMIT)
    }

    fn object_args_with_depth(&self, node: Node<'a>, depth: u64) -> Vec<ValueArgument> {
        arg_nodes(node)
            .into_iter()
            .enumerate()
            .filter_map(|(index, argument)| {
                self.instance_with_depth(argument, depth)
                    .map(|value| ValueArgument {
                        name: None,
                        index,
                        value,
                    })
            })
            .collect()
    }
}

fn server_request_key(name: &str) -> bool {
    [
        "HTTP_", "REQUEST_", "REMOTE_", "SERVER_", "SCRIPT_", "CONTENT_", "AUTH_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        || matches!(
            name,
            "QUERY_STRING"
                | "PHP_SELF"
                | "PATH_INFO"
                | "DOCUMENT_ROOT"
                | "HTTPS"
                | "GATEWAY_INTERFACE"
        )
}

fn assigned_variable(node: Node, src: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "assignment_expression"
        || parent
            .child_by_field_name("right")
            .is_none_or(|right| right.id() != node.id())
    {
        return None;
    }
    parent
        .child_by_field_name("left")
        .and_then(|left| variable_name(left, src))
        .map(str::to_string)
}

fn php_summary_builtin(name: &str) -> bool {
    matches!(
        name,
        "array_merge"
            | "array_filter"
            | "array_map"
            | "array_walk"
            | "assert"
            | "call_user_func"
            | "call_user_func_array"
            | "chmod"
            | "copy"
            | "curl_exec"
            | "curl_init"
            | "curl_setopt"
            | "define"
            | "empty"
            | "eval"
            | "exec"
            | "file"
            | "file_exists"
            | "file_get_contents"
            | "file_put_contents"
            | "fopen"
            | "fputs"
            | "fread"
            | "fsockopen"
            | "fwrite"
            | "getenv"
            | "glob"
            | "is_dir"
            | "is_file"
            | "isset"
            | "mkdir"
            | "mysqli_query"
            | "mysql_query"
            | "opendir"
            | "passthru"
            | "pfsockopen"
            | "popen"
            | "preg_replace_callback"
            | "proc_open"
            | "putenv"
            | "readfile"
            | "register_shutdown_function"
            | "rename"
            | "rmdir"
            | "scandir"
            | "shell_exec"
            | "stream_socket_client"
            | "system"
            | "tempnam"
            | "touch"
            | "unlink"
            | "usort"
    )
}

fn dynamic_dispatch_boundary(detail: &str) -> Boundary {
    Boundary {
        reason: BoundaryReason::DYNAMIC_DISPATCH,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: Vec::new(),
        limit: Some("max_php_command_registry_values".to_string()),
        detail: Some(detail.to_string()),
    }
}

fn extract_imports(root: Node, src: &str) -> Vec<ImportBinding> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) {
            continue;
        }
        if matches!(
            n.kind(),
            "if_statement"
                | "else_clause"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "foreach_statement"
                | "switch_statement"
                | "case_statement"
                | "default_statement"
                | "try_statement"
                | "catch_clause"
                | "finally_clause"
                | "conditional_expression"
                | "match_expression"
        ) {
            continue;
        }
        if matches!(
            n.kind(),
            "require_expression"
                | "require_once_expression"
                | "include_expression"
                | "include_once_expression"
        ) {
            // The path may be a bare literal (`require 'util.php'`) or the
            // idiomatic `__DIR__ . '/util.php'` concatenation, so take the
            // first static string literal anywhere in the require's subtree.
            if let Some(path) = first_string_literal(n, src) {
                let local = path.rsplit('/').next().unwrap_or(&path).to_string();
                out.push(ImportBinding {
                    local,
                    module: path,
                    imported: None,
                });
            }
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            stack.push(ch);
        }
    }
    out
}

/// Summarize a function body's parameterized effects and boundaries. Subprocess
/// spawns cannot nest inside a stored summary, so they also become an
/// `uncomposed_subprocess` boundary.
fn summarize_body(
    body: Option<Node>,
    params: &[String],
    src: &str,
) -> (Vec<Effect>, Vec<Boundary>, ControlFlow) {
    let _walk = crate::limits::summary_walk();
    let param_env: HashMap<String, ResourceExpr> = params
        .iter()
        .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
        .collect();
    let Some(body) = body else {
        return (Vec::new(), Vec::new(), ControlFlow::widened());
    };
    let mut c = body.walk();
    let children: Vec<Node> = body.named_children(&mut c).collect();
    let mut control = ControlStack::default();
    let limits = crate::AnalysisLimits::default();
    control.enter(
        src,
        true,
        Default::default(),
        0,
        0,
        None,
        ControlCaps {
            nodes: limits.max_causal_nodes,
            work: limits.max_causal_pairs,
        },
        |graph| control::build(graph, &children, src),
    );
    let mut cap = Cap {
        control,
        effects: Vec::new(),
        boundaries: Vec::new(),
        env: param_env,
        src,
        nodes: crate::limits::invocation_node_limit(DEFAULT_MAX_PHP_NODES),
        truncated: false,
    };
    for ch in &children {
        cap.walk(*ch);
    }
    if cap.truncated {
        cap.control.widen();
    }
    let finished = cap.control.leave(0).expect("PHP summary frame");
    if let Some(limit) = finished.refused {
        cap.boundaries.push(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
            provenance: Vec::new(),
            limit: Some(limit.to_string()),
            detail: Some("PHP summary control flow widened".to_string()),
            affected_resource: None,
            callee: None,
        });
    }
    (cap.effects, cap.boundaries, finished.flow)
}

struct Cap<'a> {
    control: ControlStack,
    effects: Vec<Effect>,
    boundaries: Vec<Boundary>,
    env: HashMap<String, ResourceExpr>,
    src: &'a str,
    nodes: u64,
    truncated: bool,
}

impl<'a> Cap<'a> {
    fn walk(&mut self, n: Node<'a>) {
        // Same left-deep `.` hazard as PhpWalker::exec.
        let mut stack = vec![n];
        while let Some(n) = stack.pop() {
            if self.nodes == 0 || !crate::limits::summary_step() {
                if !self.truncated {
                    self.truncated = true;
                    self.boundaries.push(Boundary {
                        reason: BoundaryReason::PARTIAL_ANALYSIS,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                        provenance: vec![],
                        limit: Some("max_php_nodes".to_string()),
                        detail: Some("php summary walk node budget exhausted".to_string()),
                    });
                }
                return;
            }
            self.nodes -= 1;
            let effect_start = self.effects.len();
            match n.kind() {
                "function_definition" | "method_declaration" | "class_declaration" => continue,
                "function_call_expression" => self.call(n),
                "assignment_expression" => {
                    if let Some(left) = n.child_by_field_name("left")
                        && let Some((name, resource)) = superglobal_resource(left, self.src)
                        && name == "_ENV"
                    {
                        self.effects
                            .push(model::environment_effect(resource, false));
                    }
                }
                "unset_statement" => {
                    let mut cursor = n.walk();
                    for target in n.named_children(&mut cursor) {
                        if let Some((name, resource)) = superglobal_resource(target, self.src)
                            && name == "_ENV"
                        {
                            self.effects.push(model::environment_effect(resource, true));
                        }
                    }
                }
                "member_call_expression" | "scoped_call_expression" => {
                    let method = child_kind(n, "name")
                        .map(|m| text(m, self.src))
                        .unwrap_or("");
                    if matches!(method, "exec" | "query" | "prepare") {
                        self.boundaries.push(Boundary {
                            reason: BoundaryReason::UNCOMPOSED_QUERY,
                            class: BoundaryClass::Unmodeled,
                            scope: BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("database")],
                            provenance: vec![],
                            limit: None,
                            detail: None,
                        });
                    }
                }
                _ => {}
            }
            let direct_sink = (n.kind() == "function_call_expression"
                && callable_name(n, self.src).as_deref() == Some("unlink"))
                || matches!(n.kind(), "assignment_expression" | "unset_statement");
            if direct_sink {
                self.control.register(
                    self.src,
                    true,
                    control::span(n),
                    SiteFacts::known(
                        (effect_start..self.effects.len())
                            .map(|slot| ControlFact::Effect(slot as u32))
                            .collect(),
                    ),
                );
            } else if matches!(
                n.kind(),
                "require_expression"
                    | "require_once_expression"
                    | "include_expression"
                    | "include_once_expression"
            ) && let Some(module) = n
                .named_child(0)
                .and_then(|value| literal_string(value, self.src))
            {
                let mut facts = SiteFacts::known(Vec::new());
                facts.exit = Some(ControlExit::Import { module });
                self.control
                    .register(self.src, true, control::span(n), facts);
            }
            let guard = (self.effects.len() != effect_start)
                .then(|| super::conditions::tree_condition(self.src, n))
                .flatten();
            for effect in &mut self.effects[effect_start..] {
                effect.condition = effinterp_proto::Condition::compose(
                    effect.condition.iter().chain(guard.iter()),
                );
            }
            let mut c = n.walk();
            let children: Vec<Node> = n.named_children(&mut c).collect();
            for ch in children.into_iter().rev() {
                stack.push(ch);
            }
        }
    }
}
