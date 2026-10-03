//! Effect-directed Ruby frontend.
//!
//! Parses Ruby with `lib-ruby-parser` (a mature Rust port of the MRI parser)
//! and walks the AST for calls that reach an effect boundary — `system`/
//! backticks/`exec`/`spawn`, `File`/`FileUtils`/`Dir`/`IO`/`Open3`, `ENV`,
//! `Net::HTTP`. It does not interpret Ruby; it follows only what reaches an
//! effect, keeps non-literal arguments symbolic, and records an explicit
//! boundary for anything dynamic (`eval`, `send`, `define_method`).
//!
//! Like the Python and JS frontends it distinguishes module EXECUTION (top-
//! level statements plus methods reached by a call) from the callable surface
//! (per-`def` parameterized summaries exposed through `module_summaries`), and
//! specializes a called method's effects with the caller's arguments.
//!
//! Methods defined inside `module`/`class` bodies (including `def self.x` and
//! `class << self`) are registered under `Class.method` — the same qualified
//! naming the Python frontend uses — with `initialize` also registered as
//! `Class.__init__` so the composer's constructor lookup finds it. Call edges
//! carry receivers (`Cls.new(...)`, chained `Cls.new(...).m`, `@ivar.m`,
//! ctor-typed locals) so the repository layer can dispatch them through Ruby's
//! flat, require-based namespace.

mod control;
mod load_path;
mod model;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
use crate::value::unresolved_resource;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance, CoverageLevel, Domain,
    Effect, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity, Subject,
};
use lib_ruby_parser::Node;
use lib_ruby_parser::{Parser, ParserOptions, nodes::Send};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::{ControlExit, ControlFact, ControlStack, Requirements, SiteFacts};
use crate::module_summary::{CallEdge, ClassEntry, FunctionEntry, ImportBinding, ModuleSummary};
use crate::nest::{Nest, Transition, word_resource};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::{
    Summary, bind_positional, contains_unresolved, has_text_concat, substitute_resource_expr,
};
use crate::value::bind_arguments;
use crate::word::{Word, WordPart};
use crate::{
    CallableValue, ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, ValueArgument,
};
use model::{
    Modeled, Scope, apply_live_assign, assigned_proc, candidate_limit_boundary, constant_env,
    effect, env_index_read, env_key, exe, fs_path, guarded_ruby_children, invoked_procs,
    literal_str, model, network_sink, passed_procs, poison_boundary, poisoned_send_reference,
    push_proc, resolve, spawn_of_parts, value_arguments, yielded_argument_sets,
};

const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];
use crate::limits::DEFAULT_MAX_RUBY_NODES;
/// Bound on the same-file inline stack (recursive/mutually recursive methods).
const MAX_INLINE_DEPTH: usize = 16;
const MAX_CALL_SITE_APPLICATIONS: usize = 64;

/// Parse Ruby source into an AST root, or None on a catastrophic parse or when
/// the source nests deeper than the walk limit.
///
/// lib-ruby-parser descends recursively, and even dropping a deeply nested
/// `Box<Node>` recurses once per level, so a source nested past the native
/// stack overflows the whole hook. The nesting pre-check refuses such source
/// before the AST is ever built, which the callers surface as a limit
/// boundary; every caller already treats `None` as an unanalyzable parse.
fn parse(source: &str) -> Option<Box<Node>> {
    if ruby_nesting_exceeds(source) {
        return None;
    }
    let source = mask_embedded_documents(source);
    let options = ParserOptions {
        buffer_name: "(ruby)".to_string(),
        record_tokens: false,
        ..Default::default()
    };
    Parser::new(source.as_bytes(), options).do_parse().ast
}

/// Whether Ruby source nests deeper than the walk limit anywhere; see
/// [`crate::lang::depth::ruby_nesting_exceeds`].
fn ruby_nesting_exceeds(source: &str) -> bool {
    crate::lang::depth::ruby_nesting_exceeds(source)
}

/// lib-ruby-parser rejects a final `=end` without a trailing newline even
/// though MRI accepts it. Mask complete embedded-document regions while
/// preserving byte offsets so the AST and source provenance stay aligned.
fn mask_embedded_documents(source: &str) -> Cow<'_, str> {
    let marker = |line: &str, name: &str| {
        line.strip_prefix(name)
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))
    };
    let mut spans = Vec::new();
    let mut opened = None;
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let text = line.trim_end_matches(['\r', '\n']);
        if opened.is_none() && marker(text, "=begin") {
            opened = Some(offset);
        }
        offset += line.len();
        if opened.is_some() && marker(text, "=end") {
            spans.push((opened.take().unwrap(), offset));
        }
    }
    if let Some(line) = source.get(offset..)
        && !line.is_empty()
    {
        if opened.is_none() && marker(line, "=begin") {
            opened = Some(offset);
        }
        if opened.is_some() && marker(line, "=end") {
            spans.push((opened.take().unwrap(), source.len()));
        }
    }
    if spans.is_empty() || opened.is_some() {
        return Cow::Borrowed(source);
    }
    let mut masked = source.as_bytes().to_vec();
    for (start, end) in spans {
        for byte in &mut masked[start..end] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
        masked[start..start + 3].copy_from_slice(b"nil");
    }
    Cow::Owned(String::from_utf8(masked).unwrap())
}

/// Classify parsed Ruby top-level statements; malformed source leaves discovery unknown.
pub fn ruby_runs_top_level(source: &str) -> Option<bool> {
    if ruby_nesting_exceeds(source) {
        return None;
    }
    let source = mask_embedded_documents(source);
    let result = Parser::new(source.as_bytes(), ParserOptions::default()).do_parse();
    if result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.is_error())
    {
        return None;
    }
    fn declaration(node: &Node) -> bool {
        match node {
            Node::Class(_)
            | Node::Module(_)
            | Node::Def(_)
            | Node::Defs(_)
            | Node::SClass(_)
            | Node::Casgn(_)
            | Node::Str(_) => true,
            Node::Send(send) => {
                if send.recv.is_none() {
                    return matches!(
                        send.method_name.as_str(),
                        "require"
                            | "require_relative"
                            | "load"
                            | "autoload"
                            | "sig"
                            | "private_constant"
                            | "module_function"
                            | "requires_ancestor"
                            | "include"
                            | "extend"
                            | "private"
                            | "public"
                            | "protected"
                    ) || send.method_name.starts_with("attr_");
                }
                let receiver = match send.recv.as_deref() {
                    Some(Node::Send(inner))
                        if inner.method_name == "singleton_class" && inner.args.is_empty() =>
                    {
                        inner.recv.as_deref()
                    }
                    receiver => receiver,
                };
                matches!(receiver, Some(Node::Const(_)))
                    && matches!(send.method_name.as_str(), "prepend" | "include" | "extend")
            }
            Node::Block(block) => matches!(block.call.as_ref(), Node::Send(send)
                if send.recv.is_none() && send.method_name == "sig"),
            _ => false,
        }
    }
    Some(result.ast.as_deref().is_some_and(|root| {
        top_statements(root)
            .into_iter()
            .any(|node| !declaration(node))
    }))
}

/// The statements a node introduces at its own level (a `Begin` sequence, or a
/// single statement).
fn top_statements(root: &Node) -> Vec<&Node> {
    match root {
        Node::Begin(b) => b.statements.iter().collect(),
        other => vec![other],
    }
}

/// One registered method: its lookup key (`Class.method`, the bare name, or
/// `Class.__init__` for a constructor), parameters, body, and defining class.
struct RDef {
    key: String,
    /// True for the source-written name, false for lookup aliases.
    declared: bool,
    params: Vec<String>,
    defaults: HashMap<String, Rc<Node>>,
    keywords: HashSet<String>,
    body: Option<Rc<Node>>,
    class: Option<String>,
}

#[derive(Clone)]
struct ProcDef {
    params: Vec<String>,
    body: Rc<Node>,
}

/// A file's definitions: methods (qualified and bare keys, first definition
/// wins) and the classes/modules that declare them.
#[derive(Default)]
struct RubyFileContext {
    literal_builtins: bool,
    exception_builtins: bool,
    source_digest: String,
    guards: crate::guards::GuardRegions,
    defs: Vec<RDef>,
    classes: Vec<ClassEntry>,
    exact_defs: Vec<RDef>,
    exact_classes: Vec<ClassEntry>,
    /// Public instance methods of each class, in definition order.
    pub_methods: HashMap<String, Vec<String>>,
    /// Classes whose body used a command-table DSL (`desc`, ...).
    command_dsl: HashSet<String>,
    /// Class → command/template method names (filled after collect).
    commands: HashMap<String, Vec<String>>,
    /// Qualified method → constructed class that method returns.
    returns: HashMap<String, String>,
    /// Methods hidden by Ruby `private`/`protected` visibility sections.
    internal: HashSet<String>,
    consts: HashMap<String, ResourceExpr>,
    rake_dsl: bool,
    load_path: load_path::LoadPathEvidence,
}

impl RubyFileContext {
    fn def(&self, key: &str) -> Option<&RDef> {
        self.exact_defs
            .iter()
            .find(|d| d.key == key)
            .or_else(|| self.defs.iter().find(|d| d.key == key))
    }

    fn register(
        &mut self,
        class: Option<&str>,
        name: &str,
        args: &Option<Box<Node>>,
        body: &Option<Box<Node>>,
    ) {
        let (params, defaults, keywords) = param_metadata(args);
        let body: Option<Rc<Node>> = body.as_deref().cloned().map(Rc::new);
        let mut keys: Vec<String> = Vec::new();
        match class {
            Some(c) => {
                keys.push(format!("{c}.{name}"));
                if name == "initialize" {
                    keys.push(format!("{c}.__init__"));
                }
                keys.push(name.to_string());
            }
            None => keys.push(name.to_string()),
        }
        for (index, key) in keys.into_iter().enumerate() {
            if self.def(&key).is_none() {
                self.defs.push(RDef {
                    key,
                    declared: index == 0,
                    params: params.clone(),
                    defaults: defaults.clone(),
                    keywords: keywords.clone(),
                    body: body.clone(),
                    class: class.map(str::to_string),
                });
            }
        }
    }

    fn register_exact(
        &mut self,
        class: &str,
        name: &str,
        args: &Option<Box<Node>>,
        body: &Option<Box<Node>>,
    ) {
        let (params, defaults, keywords) = param_metadata(args);
        let body = body.as_deref().cloned().map(Rc::new);
        let mut keys = vec![format!("{class}.{name}")];
        if name == "initialize" {
            keys.push(format!("{class}.__init__"));
        }
        for (index, key) in keys.into_iter().enumerate() {
            if self
                .exact_defs
                .iter()
                .all(|definition| definition.key != key)
            {
                self.exact_defs.push(RDef {
                    key,
                    declared: index == 0,
                    params: params.clone(),
                    defaults: defaults.clone(),
                    keywords: keywords.clone(),
                    body: body.clone(),
                    class: Some(class.to_string()),
                });
            }
        }
    }
}

/// A local is either a class reference (`engine_class = Foo::Bar`) or an
/// instance of a named class (`engine = Foo::Bar.new`).
#[derive(Clone, Debug)]
enum LocalTy {
    Class(String),
    Instance(String),
}

/// Collect definitions from a file: top-level defs, plus methods inside
/// `module`/`class` bodies (`def`, `def self.x`, `class << self`), each class
/// or module contributing a [`ClassEntry`]. Nesting uses the innermost
/// constant name (`ColorLS::Flags` registers as `Flags`), matching how call
/// edges name their heads.
fn collect(node: &Node, ctx: &mut RubyFileContext) {
    collect_at(node, ctx, 0);
}

fn collect_at(node: &Node, ctx: &mut RubyFileContext, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    match node {
        Node::Begin(b) => {
            for stmt in &b.statements {
                collect_at(stmt, ctx, depth + 1);
            }
        }
        Node::Class(c) => {
            let Some(name) = const_last_of(&c.name) else {
                return;
            };
            let mut entry = ClassEntry {
                name: name.clone(),
                bases: Vec::new(),
                attr_params: Vec::new(),
                attr_classes: Vec::new(),
                ..Default::default()
            };
            if let Some(sup) = &c.superclass
                && let Some(base) = const_last_of(sup)
            {
                entry.bases.push(base);
            }
            if let Some(body) = &c.body {
                collect_class_body_at(body, &mut entry, ctx, depth + 1, false, false);
            }
            collect_attr_types(&name, &mut entry, ctx);
            ctx.classes.push(entry);
        }
        Node::Module(m) => {
            let Some(name) = const_last_of(&m.name) else {
                return;
            };
            let mut entry = ClassEntry {
                name: name.clone(),
                ..Default::default()
            };
            if let Some(body) = &m.body {
                collect_class_body_at(body, &mut entry, ctx, depth + 1, false, false);
            }
            ctx.classes.push(entry);
        }
        Node::Def(d) => ctx.register(None, &d.name, &d.args, &d.body),
        Node::Defs(d) => ctx.register(None, &d.name, &d.args, &d.body),
        Node::Casgn(assignment) => collect_constant(assignment, None, ctx),
        _ => {}
    }
}

/// Collect a class/module body: methods register under the class, nested
/// classes/modules recurse independently, `include`/`extend` add mixin bases.
/// `hidden` marks methods that are not command-table entries (`private`,
/// `no_tasks` / `no_commands`).
fn collect_class_body_at(
    node: &Node,
    entry: &mut ClassEntry,
    ctx: &mut RubyFileContext,
    depth: u32,
    hidden: bool,
    internal: bool,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    match node {
        Node::Begin(b) => {
            let mut section_hidden = hidden;
            let mut section_internal = internal;
            for stmt in &b.statements {
                if let Node::Send(s) = stmt
                    && s.recv.is_none()
                {
                    match s.method_name.as_str() {
                        "private" | "protected" if s.args.is_empty() => {
                            section_hidden = true;
                            section_internal = true;
                            continue;
                        }
                        "public" if s.args.is_empty() => {
                            section_hidden = false;
                            section_internal = false;
                            continue;
                        }
                        "desc" | "method_option" | "class_option" | "map" => {
                            ctx.command_dsl.insert(entry.name.clone());
                        }
                        _ => {}
                    }
                }
                collect_class_body_at(
                    stmt,
                    entry,
                    ctx,
                    depth + 1,
                    section_hidden,
                    section_internal,
                );
            }
        }
        Node::Def(d) => {
            let bare_was_defined = ctx.def(&d.name).is_some();
            let qualified = format!("{}.{}", entry.name, d.name);
            let qualified_was_defined = ctx.def(&qualified).is_some();
            ctx.register(Some(&entry.name), &d.name, &d.args, &d.body);
            if internal {
                if !bare_was_defined {
                    ctx.internal.insert(d.name.clone());
                }
                if !qualified_was_defined {
                    ctx.internal.insert(qualified);
                }
            }
            if !hidden && !is_skipped_command(&d.name) {
                let methods = ctx.pub_methods.entry(entry.name.clone()).or_default();
                if !methods.iter().any(|m| m == &d.name) {
                    methods.push(d.name.clone());
                }
            }
        }
        // `def self.x` — a class method; same qualified naming.
        Node::Defs(d) => {
            ctx.register(Some(&entry.name), &d.name, &d.args, &d.body);
        }
        // `class << self` — its defs are class methods of the enclosing class.
        Node::SClass(s) => {
            if matches!(&*s.expr, Node::Self_(_))
                && let Some(body) = &s.body
            {
                collect_class_body_at(body, entry, ctx, depth + 1, true, false);
            }
        }
        Node::Send(s)
            if s.recv.is_none() && matches!(s.method_name.as_str(), "include" | "extend") =>
        {
            for arg in &s.args {
                if let Some(base) = const_last_of(arg) {
                    entry.bases.push(base);
                }
            }
        }
        Node::Send(s)
            if s.recv.is_none()
                && matches!(
                    s.method_name.as_str(),
                    "desc" | "method_option" | "class_option" | "map"
                ) =>
        {
            ctx.command_dsl.insert(entry.name.clone());
        }
        // A class-level DSL block (`no_commands do ... end`) wraps ordinary
        // method definitions. Helpers inside `no_tasks`/`no_commands` are not
        // command-table entries.
        Node::Block(b) => {
            if let Node::Send(s) = &*b.call
                && s.recv.is_none()
                && matches!(
                    s.method_name.as_str(),
                    "desc" | "method_option" | "class_option" | "map"
                )
            {
                ctx.command_dsl.insert(entry.name.clone());
            }
            let hide = hidden || is_hide_block(&b.call);
            if let Some(body) = &b.body {
                collect_class_body_at(body, entry, ctx, depth + 1, hide, internal);
            }
        }
        Node::Casgn(assignment) => collect_constant(assignment, Some(&entry.name), ctx),
        Node::Class(_) | Node::Module(_) => collect_at(node, ctx, depth + 1),
        _ => {}
    }
}

fn collect_constant(
    assignment: &lib_ruby_parser::nodes::Casgn,
    owner: Option<&str>,
    ctx: &mut RubyFileContext,
) {
    let Some(value) = assignment.value.as_deref() else {
        return;
    };
    let Some(resolved) = constant_resource(value) else {
        return;
    };
    let name = match assignment.scope.as_deref().and_then(constant_path) {
        Some(scope) => format!("{scope}::{}", assignment.name),
        None => owner.map_or_else(
            || assignment.name.clone(),
            |owner| format!("{owner}::{}", assignment.name),
        ),
    };
    ctx.consts.insert(name, resolved);
}

fn constant_resource(node: &Node) -> Option<ResourceExpr> {
    match node {
        Node::Str(string) => Some(fs_path(&string.value.to_string_lossy())),
        Node::Dstr(string) => literal_parts(&string.parts).map(|value| fs_path(&value)),
        Node::Send(send)
            if send.recv.as_deref().and_then(constant_path).as_deref() == Some("File")
                && send.method_name == "join"
                && !send.args.is_empty() =>
        {
            let parts = send
                .args
                .iter()
                .map(|argument| literal_str(argument).map(|value| fs_path(&value)))
                .collect::<Option<Vec<_>>>()?;
            Some(ResourceExpr::Join { parts })
        }
        _ => None,
    }
}

fn is_hide_block(call: &Node) -> bool {
    matches!(
        call,
        Node::Send(s) if s.recv.is_none()
            && matches!(s.method_name.as_str(), "no_tasks" | "no_commands" | "private" | "protected")
    )
}

fn is_skipped_command(name: &str) -> bool {
    matches!(
        name,
        "initialize" | "method_missing" | "respond_to_missing?"
    )
}

/// Fill a class entry's instance-attribute typing from every method: `@attr =
/// <param>` and `@attr = Cls.new(...)` / `@attr ||= Cls.new(...)` (including
/// `begin`/`end` values), plus locals forwarded into the ivar. Attribute
/// names are stored without the `@`, matching `SelfAttr` receivers.
fn collect_attr_types(class: &str, entry: &mut ClassEntry, ctx: &RubyFileContext) {
    for i in 0..ctx.defs.len() {
        let (params, body, def_class) = {
            let d = &ctx.defs[i];
            (d.params.clone(), d.body.clone(), d.class.clone())
        };
        if def_class.as_deref() != Some(class) {
            continue;
        }
        let Some(body) = body else {
            continue;
        };
        let mut locals = HashMap::new();
        scan_types(&body, class, &params, &mut locals, entry);
    }
}

fn scan_types(
    node: &Node,
    class: &str,
    params: &[String],
    locals: &mut HashMap<String, LocalTy>,
    entry: &mut ClassEntry,
) {
    match node {
        Node::Lvasgn(a) => {
            if let Some(v) = a.value.as_deref() {
                scan_types(v, class, params, locals, entry);
                match expr_type(v, locals, params, Some(class), entry) {
                    Some(ty) => {
                        locals.insert(a.name.clone(), ty);
                    }
                    None => {
                        locals.remove(&a.name);
                    }
                }
            }
        }
        Node::Ivasgn(a) => {
            if let Some(v) = a.value.as_deref() {
                scan_types(v, class, params, locals, entry);
                record_ivar(&a.name, v, params, locals, Some(class), entry);
            }
        }
        Node::OrAsgn(a) => scan_op_asgn(&a.recv, &a.value, class, params, locals, entry),
        Node::AndAsgn(a) => scan_op_asgn(&a.recv, &a.value, class, params, locals, entry),
        Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_) => {}
        _ => {
            for child in children(node) {
                scan_types(child, class, params, locals, entry);
            }
        }
    }
}

fn scan_op_asgn(
    recv: &Node,
    value: &Node,
    class: &str,
    params: &[String],
    locals: &mut HashMap<String, LocalTy>,
    entry: &mut ClassEntry,
) {
    scan_types(value, class, params, locals, entry);
    if let Some(attr) = ivar_target(recv) {
        record_ivar_named(&attr, value, params, locals, Some(class), entry);
    }
    if let Some(name) = lvar_target(recv)
        && let Some(ty) = expr_type(value, locals, params, Some(class), entry)
    {
        locals.insert(name, ty);
    }
}

fn ivar_target(node: &Node) -> Option<String> {
    match node {
        Node::Ivar(v) => Some(v.name.trim_start_matches('@').to_string()),
        Node::Ivasgn(v) => Some(v.name.trim_start_matches('@').to_string()),
        _ => None,
    }
}

fn lvar_target(node: &Node) -> Option<String> {
    match node {
        Node::Lvar(v) => Some(v.name.clone()),
        Node::Lvasgn(v) => Some(v.name.clone()),
        _ => None,
    }
}

fn record_ivar(
    raw: &str,
    value: &Node,
    params: &[String],
    locals: &HashMap<String, LocalTy>,
    enclosing: Option<&str>,
    entry: &mut ClassEntry,
) {
    record_ivar_named(
        raw.trim_start_matches('@'),
        value,
        params,
        locals,
        enclosing,
        entry,
    );
}

fn record_ivar_named(
    attr: &str,
    value: &Node,
    params: &[String],
    locals: &HashMap<String, LocalTy>,
    enclosing: Option<&str>,
    entry: &mut ClassEntry,
) {
    if let Node::Lvar(v) = value
        && params.contains(&v.name)
    {
        entry.attr_params.retain(|(x, _)| x != attr);
        entry.attr_classes.retain(|(x, _)| x != attr);
        entry.attr_params.push((attr.to_string(), v.name.clone()));
        return;
    }
    if let Some(LocalTy::Instance(c)) = expr_type(value, locals, params, enclosing, entry) {
        entry.attr_params.retain(|(x, _)| x != attr);
        entry.attr_classes.retain(|(x, _)| x != attr);
        entry.attr_classes.push((attr.to_string(), c));
    }
}

/// After every class is collected: mark command-table and template-base
/// methods, inherit command lists through same-file bases, and infer method
/// return classes from constructor/ivar bodies.
fn finish_collect(ctx: &mut RubyFileContext) {
    let names: Vec<String> = ctx.classes.iter().map(|c| c.name.clone()).collect();
    for name in &names {
        if !ctx.command_dsl.contains(name) && !is_template_class(ctx, name) {
            continue;
        }
        if let Some(methods) = ctx.pub_methods.get(name).cloned() {
            ctx.commands
                .entry(name.clone())
                .or_default()
                .extend(methods);
        }
    }
    inherit_commands(ctx);
    infer_all_returns(ctx);
}

fn is_template_class(ctx: &RubyFileContext, name: &str) -> bool {
    last_seg(name) == "Base"
        || ctx
            .classes
            .iter()
            .any(|c| c.name == name && c.bases.iter().any(|b| last_seg(b) == "Base"))
}

fn inherit_commands(ctx: &mut RubyFileContext) {
    for _ in 0..16 {
        let mut changed = false;
        let snapshot: Vec<(String, Vec<String>)> = ctx
            .classes
            .iter()
            .map(|c| (c.name.clone(), c.bases.clone()))
            .collect();
        for (name, bases) in snapshot {
            let mut inherited = Vec::new();
            let mut from_table = false;
            for base in &bases {
                if ctx.commands.contains_key(base) || ctx.command_dsl.contains(base) {
                    from_table = true;
                    if let Some(ms) = ctx.commands.get(base) {
                        inherited.extend(ms.clone());
                    }
                }
            }
            if !from_table {
                continue;
            }
            let entry = ctx.commands.entry(name.clone()).or_default();
            if let Some(pubm) = ctx.pub_methods.get(&name) {
                for m in pubm {
                    if !entry.contains(m) {
                        entry.push(m.clone());
                        changed = true;
                    }
                }
            }
            for m in inherited {
                if !entry.contains(&m) {
                    entry.push(m);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn infer_all_returns(ctx: &mut RubyFileContext) {
    let mut returns = HashMap::new();
    let empty = ClassEntry::default();
    for d in &ctx.defs {
        let Some(class) = &d.class else {
            continue;
        };
        let Some(body) = &d.body else {
            continue;
        };
        let entry = ctx
            .classes
            .iter()
            .find(|c| c.name == *class)
            .unwrap_or(&empty);
        if let Some(cls) = infer_return(body, class, &d.params, entry) {
            returns.insert(d.key.clone(), cls);
        }
    }
    ctx.returns = returns;
}

fn infer_return(body: &Node, class: &str, params: &[String], entry: &ClassEntry) -> Option<String> {
    let mut locals = HashMap::new();
    let mut scratch = entry.clone();
    scan_types(body, class, params, &mut locals, &mut scratch);
    let mut types = Vec::new();
    collect_return_types(body, &locals, params, Some(class), entry, &mut types);
    let last = last_expr(body);
    if !matches!(last, Node::Return(_))
        && let Some(LocalTy::Instance(c)) = expr_type(last, &locals, params, Some(class), entry)
    {
        types.push(c);
    }
    let first = types.first()?.clone();
    types.iter().all(|t| *t == first).then_some(first)
}

fn collect_return_types(
    node: &Node,
    locals: &HashMap<String, LocalTy>,
    params: &[String],
    enclosing: Option<&str>,
    entry: &ClassEntry,
    out: &mut Vec<String>,
) {
    if let Node::Return(r) = node {
        if let Some(arg) = r.args.first()
            && let Some(LocalTy::Instance(c)) = expr_type(arg, locals, params, enclosing, entry)
        {
            out.push(c);
        }
        return;
    }
    if matches!(
        node,
        Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_)
    ) {
        return;
    }
    for child in children(node) {
        collect_return_types(child, locals, params, enclosing, entry, out);
    }
}

fn last_expr(node: &Node) -> &Node {
    match node {
        Node::Begin(b) => b.statements.last().map(last_expr).unwrap_or(node),
        Node::KwBegin(b) => b.statements.last().map(last_expr).unwrap_or(node),
        other => other,
    }
}

fn expr_type_seq(
    stmts: &[Node],
    locals: &HashMap<String, LocalTy>,
    params: &[String],
    enclosing: Option<&str>,
    entry: &ClassEntry,
) -> Option<LocalTy> {
    let mut acc = locals.clone();
    let mut scratch = entry.clone();
    let class = enclosing.unwrap_or("");
    for stmt in stmts {
        scan_types(stmt, class, params, &mut acc, &mut scratch);
    }
    stmts
        .last()
        .and_then(|n| expr_type(n, &acc, params, enclosing, entry))
}

fn expr_type(
    node: &Node,
    locals: &HashMap<String, LocalTy>,
    params: &[String],
    enclosing: Option<&str>,
    entry: &ClassEntry,
) -> Option<LocalTy> {
    match node {
        Node::Const(_) => constant_path(node).map(|p| LocalTy::Class(type_name(&p, enclosing))),
        Node::Send(s) if s.method_name == "new" => {
            ctor_class(s, locals, enclosing).map(LocalTy::Instance)
        }
        Node::Send(s) if s.recv.is_none() && s.method_name == "Pathname" => {
            Some(LocalTy::Instance("Pathname".to_string()))
        }
        Node::Send(s)
            if matches!(
                s.method_name.as_str(),
                "+" | "/" | "join" | "expand_path" | "realpath"
            ) =>
        {
            match s
                .recv
                .as_deref()
                .and_then(|recv| expr_type(recv, locals, params, enclosing, entry))
            {
                Some(LocalTy::Instance(class)) if class == "Pathname" => {
                    Some(LocalTy::Instance(class))
                }
                _ => None,
            }
        }
        Node::Lvar(v) => locals.get(&v.name).cloned(),
        Node::Ivar(v) => {
            let attr = v.name.trim_start_matches('@');
            entry
                .attr_classes
                .iter()
                .find(|(a, _)| a == attr)
                .map(|(_, c)| LocalTy::Instance(c.clone()))
        }
        Node::Begin(b) => expr_type_seq(&b.statements, locals, params, enclosing, entry),
        Node::KwBegin(b) => expr_type_seq(&b.statements, locals, params, enclosing, entry),
        Node::OrAsgn(a) => expr_type(&a.value, locals, params, enclosing, entry),
        Node::AndAsgn(a) => expr_type(&a.value, locals, params, enclosing, entry),
        Node::Ivasgn(a) => a
            .value
            .as_deref()
            .and_then(|v| expr_type(v, locals, params, enclosing, entry)),
        Node::Lvasgn(a) => a
            .value
            .as_deref()
            .and_then(|v| expr_type(v, locals, params, enclosing, entry)),
        _ => None,
    }
}

fn ctor_class(
    s: &Send,
    locals: &HashMap<String, LocalTy>,
    enclosing: Option<&str>,
) -> Option<String> {
    if let Some(path) = s.recv.as_deref().and_then(constant_path) {
        return Some(type_name(&path, enclosing));
    }
    if let Some(Node::Lvar(v)) = s.recv.as_deref()
        && let Some(LocalTy::Class(c)) = locals.get(&v.name)
    {
        return Some(c.clone());
    }
    None
}

fn last_seg(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

/// Preserve a qualified constant path unless its last segment equals the
/// enclosing class; then use the parent segment so `Foo::Engine::CLI`
/// constructed inside `CLI` types as `Engine` rather than colliding.
fn type_name(path: &str, enclosing: Option<&str>) -> String {
    let last = last_seg(path).to_string();
    if enclosing == Some(last.as_str())
        && let Some((parent, _)) = path.rsplit_once("::")
    {
        return last_seg(parent).to_string();
    }
    if path.contains("::") {
        path.to_string()
    } else {
        last
    }
}

fn unmodeled_receiver_call(send: &Send, ctx: &RubyFileContext) -> Option<String> {
    if load_path::inert_call(send)
        || ctx
            .load_path
            .inert
            .contains(&(send.expression_l.begin, send.expression_l.end))
    {
        return None;
    }
    // `File.join` only concatenates path strings.
    if send.method_name == "join"
        && send.recv.as_deref().and_then(constant_path).as_deref() == Some("File")
    {
        return None;
    }
    let mut receiver = send.recv.as_deref()?;
    let mut methods = vec![send.method_name.as_str()];
    while let Node::Send(inner) = receiver {
        methods.push(inner.method_name.as_str());
        let Some(next) = inner.recv.as_deref() else {
            methods.reverse();
            return Some(methods.join("."));
        };
        receiver = next;
    }
    let name = match receiver {
        Node::Lvar(value) => value.name.clone(),
        Node::Ivar(value) => value.name.clone(),
        Node::Self_(_) => "self".to_string(),
        _ => constant_path(receiver).unwrap_or_else(|| "<expression>".to_string()),
    };
    if ctx
        .classes
        .iter()
        .chain(&ctx.exact_classes)
        .any(|class| class.name == name)
    {
        return None;
    }
    methods.reverse();
    Some(format!("{name}.{}", methods.join(".")))
}

/// Parameter names of a `def` argument list (positional, optional, keyword).
fn param_names(args: &Option<Box<Node>>) -> Vec<String> {
    param_metadata(args).0
}

fn param_metadata(
    args: &Option<Box<Node>>,
) -> (Vec<String>, HashMap<String, Rc<Node>>, HashSet<String>) {
    let mut names = Vec::new();
    let mut defaults = HashMap::new();
    let mut keywords = HashSet::new();
    if let Some(node) = args
        && let Node::Args(a) = &**node
    {
        for arg in &a.args {
            match arg {
                Node::Arg(x) => names.push(x.name.clone()),
                Node::Procarg0(x) => {
                    names.extend(x.args.iter().filter_map(|arg| match arg {
                        Node::Arg(arg) => Some(arg.name.clone()),
                        _ => None,
                    }));
                }
                Node::Optarg(x) => {
                    names.push(x.name.clone());
                    defaults.insert(x.name.clone(), Rc::new((*x.default).clone()));
                }
                Node::Kwarg(x) => {
                    names.push(x.name.clone());
                    keywords.insert(x.name.clone());
                }
                Node::Kwoptarg(x) => {
                    names.push(x.name.clone());
                    defaults.insert(x.name.clone(), Rc::new((*x.default).clone()));
                    keywords.insert(x.name.clone());
                }
                _ => {}
            }
        }
    }
    (names, defaults, keywords)
}

/// The last segment of a constant path node (`ColorLS::Flags` -> `Flags`).
fn const_last_of(node: &Node) -> Option<String> {
    match node {
        Node::Const(c) => Some(c.name.clone()),
        _ => None,
    }
}

/// A call that writes its arguments to the program's standard output.
fn prints_to_stdout(s: &Send) -> bool {
    let stdout_receiver = match s.recv.as_deref() {
        None => true,
        Some(Node::Gvar(global)) => global.name == "$stdout",
        Some(Node::Const(constant)) => constant.scope.is_none() && constant.name == "STDOUT",
        _ => false,
    };
    stdout_receiver
        && match s.method_name.as_str() {
            "puts" | "print" | "p" | "pp" | "printf" => true,
            "write" | "<<" => s.recv.is_some(),
            _ => false,
        }
}

/// A `File`/`IO` call that returns a whole file's text, which an output call
/// printing it writes out byte for byte.
fn file_read_call(call: &Send) -> bool {
    matches!(
        call.recv.as_deref().and_then(constant_path).as_deref(),
        Some("File" | "IO")
    ) && matches!(call.method_name.as_str(), "read" | "binread")
}

/// The arguments of a `printf`-style call whose text the output contains: a
/// literal format's plain `%s` arguments. `None` when the format is not a
/// literal this reading follows.
fn formatted_arguments(args: &[Node]) -> Option<Vec<&Node>> {
    let Some(Node::Str(format)) = args.first() else {
        return None;
    };
    let indices = crate::lang::frontend::format_text_arguments(
        &format.value.to_string_lossy(),
        &[
            'a', 'A', 'b', 'B', 'c', 'd', 'e', 'E', 'f', 'g', 'G', 'i', 'o', 'u', 'x', 'X',
        ],
    )?;
    Some(
        indices
            .into_iter()
            .filter_map(|index| args.get(index + 1))
            .collect(),
    )
}

/// A backtick's span, with whether a value holds its bytes verbatim.
type HeldCapture = ((usize, usize), bool);

/// The backtick spans and local names whose bytes an expression's value
/// carries. Only forms that keep the text pass them on: interpolation,
/// concatenation, a branch's result, whitespace trimming and conversions to a
/// string. A length, a predicate or any other computation over captured
/// output does not carry its bytes. Each source is paired with whether its
/// bytes reach the value verbatim; a format this reading cannot follow may or
/// may not print them.
fn capture_sources(node: &Node) -> (Vec<HeldCapture>, Vec<(String, bool)>) {
    let mut spans = Vec::new();
    let mut locals = Vec::new();
    let mut stack = vec![(node, true)];
    while let Some((node, exact)) = stack.pop() {
        let mut next: Vec<&Node> = Vec::new();
        match node {
            Node::Xstr(x) => spans.push(((x.expression_l.begin, x.expression_l.end), exact)),
            Node::XHeredoc(x) => spans.push(((x.expression_l.begin, x.expression_l.end), exact)),
            Node::Lvar(local) => locals.push((local.name.clone(), exact)),
            Node::Dstr(string) => next.extend(string.parts.iter()),
            Node::Heredoc(string) => next.extend(string.parts.iter()),
            Node::Array(array) => next.extend(array.elements.iter()),
            Node::Begin(begin) => next.extend(begin.statements.last()),
            Node::IfTernary(branch) => next.extend([&*branch.if_true, &*branch.if_false]),
            Node::If(branch) => next.extend(
                branch
                    .if_true
                    .as_deref()
                    .into_iter()
                    .chain(branch.if_false.as_deref()),
            ),
            Node::Or(or) => next.extend([&*or.lhs, &*or.rhs]),
            // Captured text is truthy, so `a && b` yields `b`.
            Node::And(and) => next.push(&and.rhs),
            Node::Send(send) => match (send.recv.as_deref(), send.method_name.as_str()) {
                (
                    Some(receiver),
                    "strip" | "lstrip" | "rstrip" | "chomp" | "to_s" | "to_str" | "dup" | "freeze"
                    | "itself",
                ) if send.args.is_empty() => next.push(receiver),
                (Some(receiver), "+") => {
                    next.push(receiver);
                    next.extend(send.args.iter());
                }
                (None, "format" | "sprintf") => match formatted_arguments(&send.args) {
                    Some(printed) => next.extend(printed),
                    None => stack.extend(send.args.iter().map(|arg| (arg, false))),
                },
                _ => {}
            },
            _ => {}
        }
        stack.extend(next.into_iter().map(|child| (child, exact)));
    }
    (spans, locals)
}

/// The `::`-joined name a constant node spells, e.g. `File`, `Net::HTTP`. A
/// nonconstant scope, including a leading `::`, is dropped rather than
/// resolved; this is spelling only, not namespace lookup.
fn constant_path(node: &Node) -> Option<String> {
    let Node::Const(constant) = node else {
        return None;
    };
    Some(match constant.scope.as_deref().and_then(constant_path) {
        Some(base) => format!("{base}::{}", constant.name),
        None => constant.name.clone(),
    })
}

fn qualified_class_definitions(root: &Node) -> Vec<(String, String)> {
    fn collect(node: &Node, namespace: Option<&str>, out: &mut Vec<(String, String)>) {
        match node {
            Node::Begin(begin) => {
                for statement in &begin.statements {
                    collect(statement, namespace, out);
                }
            }
            Node::Class(class) => {
                let Some(written) = constant_path(&class.name) else {
                    return;
                };
                let qualified = if written.contains("::") {
                    written
                } else if let Some(namespace) = namespace {
                    format!("{namespace}::{written}")
                } else {
                    written
                };
                out.push((qualified.clone(), const_last_of(&class.name).unwrap()));
                if let Some(body) = &class.body {
                    collect(body, Some(&qualified), out);
                }
            }
            Node::Module(module) => {
                let Some(written) = constant_path(&module.name) else {
                    return;
                };
                let qualified = if written.contains("::") {
                    written
                } else if let Some(namespace) = namespace {
                    format!("{namespace}::{written}")
                } else {
                    written
                };
                out.push((qualified.clone(), const_last_of(&module.name).unwrap()));
                if let Some(body) = &module.body {
                    collect(body, Some(&qualified), out);
                }
            }
            _ => {}
        }
    }

    let mut definitions = Vec::new();
    collect(root, None, &mut definitions);
    definitions.sort();
    definitions.dedup();
    definitions
}

fn collect_exact(node: &Node, namespace: Option<&str>, ctx: &mut RubyFileContext, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    match node {
        Node::Begin(begin) => {
            for statement in &begin.statements {
                collect_exact(statement, namespace, ctx, depth + 1);
            }
        }
        Node::Class(class) => {
            let Some(written) = constant_path(&class.name) else {
                return;
            };
            let qualified = qualify_constant(namespace, &written);
            let mut entry = ClassEntry {
                name: qualified.clone(),
                bases: class
                    .superclass
                    .as_deref()
                    .and_then(constant_path)
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            if let Some(body) = &class.body {
                collect_exact_class_body(body, &mut entry, ctx, depth + 1);
            }
            ctx.exact_classes.push(entry);
        }
        Node::Module(module) => {
            let Some(written) = constant_path(&module.name) else {
                return;
            };
            let qualified = qualify_constant(namespace, &written);
            let mut entry = ClassEntry {
                name: qualified,
                ..Default::default()
            };
            if let Some(body) = &module.body {
                collect_exact_class_body(body, &mut entry, ctx, depth + 1);
            }
            ctx.exact_classes.push(entry);
        }
        _ => {}
    }
}

fn collect_exact_class_body(
    node: &Node,
    entry: &mut ClassEntry,
    ctx: &mut RubyFileContext,
    depth: u32,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    match node {
        Node::Begin(begin) => {
            for statement in &begin.statements {
                collect_exact_class_body(statement, entry, ctx, depth + 1);
            }
        }
        Node::Def(definition) => ctx.register_exact(
            &entry.name,
            &definition.name,
            &definition.args,
            &definition.body,
        ),
        Node::Defs(definition) => ctx.register_exact(
            &entry.name,
            &definition.name,
            &definition.args,
            &definition.body,
        ),
        Node::SClass(singleton) => {
            if matches!(&*singleton.expr, Node::Self_(_))
                && let Some(body) = &singleton.body
            {
                collect_exact_class_body(body, entry, ctx, depth + 1);
            }
        }
        Node::Send(send)
            if send.recv.is_none() && matches!(send.method_name.as_str(), "include" | "extend") =>
        {
            entry
                .bases
                .extend(send.args.iter().filter_map(constant_path));
        }
        Node::Block(block) => {
            if let Some(body) = &block.body {
                collect_exact_class_body(body, entry, ctx, depth + 1);
            }
        }
        Node::Class(_) | Node::Module(_) => {
            collect_exact(node, Some(&entry.name), ctx, depth + 1);
        }
        _ => {}
    }
}

fn qualify_constant(namespace: Option<&str>, written: &str) -> String {
    if written.contains("::") {
        written.to_string()
    } else if let Some(namespace) = namespace {
        format!("{namespace}::{written}")
    } else {
        written.to_string()
    }
}

pub(crate) struct RubyFrontend;

impl Frontend for RubyFrontend {
    const LANGUAGE: &'static str = "ruby";
    const DOMAINS: &'static [&'static str] = &DOMAINS;
    type Ast<'a> = Box<Node>;
    fn nesting_exceeds(&self, source: &str) -> bool {
        ruby_nesting_exceeds(source)
    }
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let ast = parse(source);
        let failure = ast.is_none().then(|| ParseFailure {
            detail: "Ruby source did not parse".to_string(),
        });
        ParseOutcome { ast, failure }
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        root: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        if builder.current_execution_is_selected_input() {
            for import in extract_imports(root, nest.resolver.is_some()) {
                if crate::classify_ruby_require(&import.module).is_none() {
                    nest.follow_dependency(builder, &import.module, "ruby");
                }
            }
        }
        let mut ctx = RubyFileContext {
            literal_builtins: literal_builtins(root, MAX_INLINE_DEPTH),
            exception_builtins: exception_builtins(root, input.source.len()),
            source_digest: effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
                &input.source,
            ),
            guards: ruby_guard_regions(root, input.source),
            load_path: load_path::extract(root),
            ..RubyFileContext::default()
        };
        for stmt in top_statements(root) {
            collect(stmt, &mut ctx);
            collect_exact(stmt, None, &mut ctx, 0);
        }
        ctx.rake_dsl = has_rake_dsl(root);
        finish_collect(&mut ctx);
        // Launch values describe entry state; source-level mutation invalidates them.
        let mut argv = builder.current_execution_argv();
        if !argv.is_empty() {
            let mut pending = vec![root.as_ref()];
            for _ in 0..nest.limits.max_ruby_nodes {
                let Some(node) = pending.pop() else {
                    break;
                };
                let changes_argv = match node {
                    Node::Casgn(assignment) => assignment.name == "ARGV",
                    Node::IndexAsgn(assignment) => {
                        constant_path(&assignment.recv).as_deref() == Some("ARGV")
                    }
                    Node::Send(call) => {
                        call.recv.as_deref().and_then(constant_path).as_deref() == Some("ARGV")
                    }
                    _ => false,
                };
                if changes_argv {
                    argv = &[];
                    break;
                }
                pending.extend(children(node));
            }
            if !pending.is_empty() {
                argv = &[];
            }
        }
        for (index, value) in argv.iter().skip(2).enumerate() {
            ctx.consts.insert(format!("ARGV[{index}]"), value.clone());
        }
        let declared_callables: Vec<String> = ctx
            .defs
            .iter()
            .filter(|definition| definition.declared)
            .map(|definition| definition.key.clone())
            .collect();

        let first_effect = builder.effects_len();
        let statements = top_statements(root);
        builder.control_enter(input.source, false, |graph| {
            control::build(graph, &statements, ctx.exception_builtins)
        });
        let mut w = RubyWalker {
            source: input.source,
            builder,
            nest,
            cwd,
            cwd_node,
            scope,
            depth,
            ctx: &ctx,
            env: ctx.consts.clone(),
            vars: HashMap::new(),
            class_refs: HashMap::new(),
            ivars: HashMap::new(),
            instances: HashMap::new(),
            remote_bodies: HashMap::new(),
            poisoned: HashSet::new(),
            procs: HashMap::new(),
            active_procs: HashSet::new(),
            captures: HashMap::new(),
            applications: HashMap::new(),
            nodes_left: nest.limits.max_ruby_nodes,
            truncated: false,
            candidate_limit_reported: false,
            call_site_limit_reported: false,
            environment_rewritten: false,
            printed_captures: HashSet::new(),
            printed_reads: HashMap::new(),
            read_effects: HashMap::new(),
            request_bodies: HashMap::new(),
            read_locals: HashMap::new(),
            captured_outputs: HashMap::new(),
            capture_locals: HashMap::new(),
            post_loop_assignments: HashMap::new(),
        };
        for stmt in statements {
            w.stmt(stmt);
        }
        w.builder.control_leave();
        let shadows_thor = ctx.classes.iter().any(|class| class.name == "Thor");
        if !shadows_thor {
            for class in ctx
                .classes
                .iter()
                .filter(|class| class.bases.iter().any(|base| last_seg(base) == "Thor"))
            {
                for method in ctx.pub_methods.get(&class.name).into_iter().flatten() {
                    w.follow_root(&format!("{}.{}", class.name, method));
                }
            }
        }
        let entered_callables = !w.applications.is_empty();
        drop(w);
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
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
        _file: &str,
        _scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summarize_ast(source, ast)
    }
}

fn has_rake_dsl(node: &Node) -> bool {
    match node {
        Node::Send(send) => {
            send.recv.is_none()
                && matches!(
                    send.method_name.as_str(),
                    "task" | "namespace" | "file" | "directory"
                )
        }
        Node::Begin(begin) => begin.statements.iter().any(has_rake_dsl),
        Node::Block(block) => {
            has_rake_dsl(&block.call) || block.body.as_deref().is_some_and(has_rake_dsl)
        }
        _ => false,
    }
}

pub(super) fn summarize_ast(source: &str, root: &Node) -> ModuleSummary {
    let mut ctx = RubyFileContext {
        literal_builtins: literal_builtins(root, MAX_INLINE_DEPTH),
        exception_builtins: exception_builtins(root, source.len()),
        source_digest: effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
            &source,
        ),
        guards: ruby_guard_regions(root, source),
        load_path: load_path::extract(root),
        ..RubyFileContext::default()
    };
    for stmt in top_statements(root) {
        collect(stmt, &mut ctx);
        collect_exact(stmt, None, &mut ctx, 0);
    }
    ctx.rake_dsl = has_rake_dsl(root);
    finish_collect(&mut ctx);
    let exported_definitions = qualified_class_definitions(root);

    let mut functions = Vec::new();
    for i in 0..ctx.defs.len() {
        let (key, params, body, class) = {
            let d = &ctx.defs[i];
            (
                d.key.clone(),
                d.params.clone(),
                d.body.clone(),
                d.class.clone(),
            )
        };
        let cap = capture(body.as_deref(), &params, class.as_deref(), &ctx);
        let returns_instances = ctx
            .returns
            .get(&key)
            .cloned()
            .map(|c| vec![Some(c)])
            .unwrap_or_default();
        let visibility = if ctx.internal.contains(&key) {
            crate::CallableVisibility::Internal
        } else {
            crate::CallableVisibility::Public
        };
        functions.push(FunctionEntry {
            name: key,
            visibility,
            summary: Summary {
                control_flow: cap.control_flow,
                params,
                effects: {
                    let mut effects = cap.effects;
                    effects.extend(cap.spawns.iter().map(|(spawn, guard)| {
                        let mut effect = materialize_ruby_spawn(spawn);
                        effect.condition = guard.clone();
                        effect
                    }));
                    effects
                },
                effect_models: Vec::new(),
                transfers: cap.transfers,
                returns: None,
                boundaries: cap.boundaries,
                coverage: DOMAINS
                    .iter()
                    .map(|dm| (Domain::new(*dm), CoverageLevel::Full))
                    .collect(),
            },
            calls: cap.calls,
            returns_instances,
            ..Default::default()
        });
    }

    // Top-level (module-execution) calls, in an empty parameter scope. Class,
    // module and singleton-class bodies execute when defined and are
    // descended; method definition bodies are not.
    let module_capture = capture(Some(root), &[], None, &ctx);
    let mut module_calls = module_capture.calls;
    let module_control_flow = module_capture.control_flow.calls_only();
    module_calls.extend(command_registration_edges(&ctx));

    let imports = extract_imports(root, true);
    let scoped_imports = extract_autoloads(root);
    let exports = imports
        .iter()
        .map(|binding| ImportBinding {
            local: "*".to_string(),
            module: binding.module.clone(),
            imported: None,
        })
        .collect();
    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            global_class_lookup: true,
            ..Default::default()
        },
        functions,
        module_calls,
        module_control_flow,
        module_effects: {
            let mut effects = module_capture.effects;
            effects.extend(module_capture.spawns.iter().map(|(spawn, guard)| {
                let mut effect = materialize_ruby_spawn(spawn);
                effect.condition = guard.clone();
                effect
            }));
            effects
        },
        module_transfers: module_capture.transfers,
        module_boundaries: module_capture.boundaries,
        imports,
        scoped_imports,
        load_path_roots: ctx.load_path.roots,
        exports,
        exported_definitions,
        classes: ctx.classes,
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |_| true);
    summary
}

/// Thor turns each public method in a command-table class into a callback at
/// class-definition time. Keep the class receiver on every registration so
/// repository composition can require the same class identity at dispatch.
fn command_registration_edges(ctx: &RubyFileContext) -> Vec<CallEdge> {
    let mut out = Vec::new();
    for class in &ctx.classes {
        let Some(methods) = ctx.commands.get(&class.name) else {
            continue;
        };
        for method in methods {
            let callback = format!("{}.{}", class.name, method);
            if out.iter().any(|edge: &CallEdge| {
                edge.arguments.first().is_some_and(|argument| {
                    matches!(
                        &argument.value.kind,
                        SemanticValueKind::Callable(CallableValue::Function { name })
                            if name == &callback
                    )
                })
            }) {
                continue;
            }
            out.push(CallEdge {
                callee: "desc".to_string(),
                arguments: vec![ValueArgument {
                    name: Some("command".to_string()),
                    index: 0,
                    value: SemanticValue::callable(callback),
                }],
                lifecycle_registration: true,
                receiver: Some(SemanticValue::object(ObjectIdentity::ModuleBinding {
                    scope: ScopeKey::Module { key: String::new() },
                    name: class.name.clone(),
                })),
                ..Default::default()
            });
        }
    }
    out
}

/// Literal gem dependencies and gemspec require paths; dynamic declarations carry no evidence.
pub fn ruby_package_metadata(source: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut paths = Vec::new();
    let mut gems = Vec::new();
    let Some(root) = parse(source) else {
        return (paths, gems);
    };
    let mut pending = vec![(root.as_ref(), 0)];
    let mut visited = 0;
    while let Some((node, depth)) = pending.pop() {
        visited += 1;
        if visited > DEFAULT_MAX_RUBY_NODES || depth >= MAX_WALK_DEPTH {
            break;
        }
        if let Node::Send(send) = node {
            if send.method_name == "require_paths="
                && send.recv.is_some()
                && let [Node::Array(array)] = send.args.as_slice()
            {
                paths.extend(array.elements.iter().filter_map(literal_str));
            }
            if ((send.method_name == "gem" && send.recv.is_none())
                || (matches!(
                    send.method_name.as_str(),
                    "add_dependency" | "add_runtime_dependency"
                ) && send.recv.is_some()))
                && let Some(name) = send.args.first().and_then(literal_str)
            {
                gems.push((
                    name,
                    send.args.get(1).and_then(literal_str).unwrap_or_default(),
                ));
            }
        }
        if !matches!(node, Node::Def(_) | Node::Defs(_)) {
            pending.extend(children(node).into_iter().map(|child| (child, depth + 1)));
        }
    }
    (paths, gems)
}

/// `require`/`require_relative` bindings, in source order (top level and
/// directly inside `module` bodies).
fn extract_imports(root: &Node, relative_paths: bool) -> Vec<ImportBinding> {
    let mut out = Vec::new();
    collect_imports(root, &mut out, relative_paths);
    out
}

fn collect_imports(node: &Node, out: &mut Vec<ImportBinding>, relative_paths: bool) {
    match node {
        Node::Begin(b) => {
            for stmt in &b.statements {
                collect_imports(stmt, out, relative_paths);
            }
        }
        Node::Module(m) => {
            if let Some(body) = &m.body {
                collect_imports(body, out, relative_paths);
            }
        }
        Node::Send(s)
            if s.recv.is_none()
                && matches!(
                    s.method_name.as_str(),
                    "require" | "require_relative" | "load"
                ) =>
        {
            if let Some(Node::Str(lit)) = s.args.first() {
                let mut module = lit.value.to_string_lossy();
                if relative_paths
                    && matches!(s.method_name.as_str(), "require_relative" | "load")
                    && !module.starts_with("./")
                    && !module.starts_with("../")
                    && !module.starts_with('/')
                {
                    module = format!("./{module}");
                }
                let local = module.rsplit('/').next().unwrap_or(&module).to_string();
                out.push(ImportBinding {
                    local,
                    module,
                    imported: None,
                });
            }
        }
        _ => {}
    }
}

fn extract_autoloads(root: &Node) -> Vec<ImportBinding> {
    fn collect(node: &Node, out: &mut Vec<ImportBinding>) {
        match node {
            Node::Begin(begin) => {
                for statement in &begin.statements {
                    collect(statement, out);
                }
            }
            Node::Module(module) => {
                if let Some(body) = &module.body {
                    collect(body, out);
                }
            }
            Node::Send(send) if send.method_name == "autoload" => {
                if let (Some(Node::Sym(name)), Some(Node::Str(path))) =
                    (send.args.first(), send.args.get(1))
                {
                    out.push(ImportBinding {
                        local: name.name.to_string_lossy(),
                        module: path.value.to_string_lossy(),
                        imported: None,
                    });
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    collect(root, &mut out);
    out
}

/// The literal command of a backtick / %x{} string, or None when it contains
/// interpolation (not statically recoverable).
fn literal_parts(parts: &[Node]) -> Option<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            Node::Str(s) => out.push_str(&s.value.to_string_lossy()),
            _ => return None,
        }
    }
    Some(out)
}

/// How a send reached what it reached, for its control-flow site.
enum SendControl {
    /// Only the send's own modeled occurrences, filled in by the caller.
    Own(SiteFacts),
    /// A same-file callee's guarantees.
    Applied(SiteFacts),
    Unknown,
}

impl SendControl {
    fn modeled(send: &Send) -> Self {
        let facts = SiteFacts::known(Vec::new());
        if send.recv.as_deref().and_then(constant_path).as_deref() == Some("File")
            && send.method_name == "delete"
        {
            Self::Own(facts)
        } else {
            Self::Applied(facts)
        }
    }

    fn with_unknown_exit(self) -> Self {
        match self {
            Self::Own(mut facts) | Self::Applied(mut facts) => {
                facts.exit = Some(ControlExit::Unknown);
                facts.call_return = false;
                Self::Applied(SiteFacts {
                    facts: Vec::new(),
                    throw_facts: Vec::new(),
                    ..facts
                })
            }
            Self::Unknown => Self::Unknown,
        }
    }

    /// `exec` replaces the process; other spawns return to the caller.
    fn spawn(send: &Send) -> Self {
        if send.method_name == "exec" {
            Self::Own(SiteFacts {
                returns: false,
                ..SiteFacts::unknown()
            })
        } else {
            Self::Own(SiteFacts::known(Vec::new()))
        }
    }

    /// A send the model leaves alone: receiver-less builtins return unless
    /// they raise or exit; anything with a receiver may run unknown code.
    fn builtin(send: &Send, builtin_names: bool) -> Self {
        if control::exits(send) {
            let throws = send.method_name != "exit!";
            let thrown = if throws
                && send.recv.is_none()
                && matches!(send.method_name.as_str(), "raise" | "fail")
            {
                control::raise_exn(send, builtin_names)
            } else {
                crate::control_flow::Exn::Unknown
            };
            Self::Own(SiteFacts {
                returns: false,
                throws,
                thrown,
                ..SiteFacts::default()
            })
        } else if send.recv.is_none() {
            Self::Own(SiteFacts::known(Vec::new()))
        } else {
            Self::Unknown
        }
    }
}

/// Registrations of summary walks share one frame key per capture stack.
static CAPTURE_SOURCE: &str = "ruby capture";

/// Effects/boundaries/calls captured while summarizing a method body.
#[derive(Clone, Default)]
struct Capture {
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    calls: Vec<CallEdge>,
    spawns: Vec<(Modeled, Option<effinterp_proto::Condition>)>,
    /// What the body guarantees over `effects` slots, when it was walked.
    control: Option<Requirements>,
    control_flow: crate::control_flow::ControlFlow,
}

/// Summarize a body with its parameters bound to symbolic Parameter nodes.
fn capture(
    body: Option<&Node>,
    params: &[String],
    class: Option<&str>,
    ctx: &RubyFileContext,
) -> Capture {
    let _walk = crate::limits::summary_walk();
    let mut cap = Capture::default();
    let Some(node) = body else {
        return cap;
    };
    let mut env = constant_env(ctx, class);
    env.extend(
        params
            .iter()
            .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() })),
    );
    if let Some(class) = class {
        env.extend(class_ivar_names(ctx, class).into_iter().map(|name| {
            let parameter = format!("@{name}");
            (
                parameter.clone(),
                ResourceExpr::Parameter { name: parameter },
            )
        }));
    }
    let mut stack = Vec::new();
    let mut nodes_left = crate::limits::invocation_node_limit(DEFAULT_MAX_RUBY_NODES);
    let mut control = ControlStack::default();
    capture_into(
        node,
        &env,
        class,
        ctx,
        &mut stack,
        &mut nodes_left,
        &mut control,
        &mut cap,
    );
    cap
}

/// Capture a body into `cap`, sharing the inline stack and node budget with
/// the enclosing capture so recursive same-file inlining terminates.
#[allow(clippy::too_many_arguments)]
fn capture_into(
    body: &Node,
    env: &HashMap<String, ResourceExpr>,
    class: Option<&str>,
    ctx: &RubyFileContext,
    stack: &mut Vec<String>,
    nodes_left: &mut u64,
    control: &mut ControlStack,
    cap: &mut Capture,
) {
    let statements = top_statements(body);
    control.enter(
        CAPTURE_SOURCE,
        true,
        Default::default(),
        0,
        0,
        None,
        control::summary_caps(),
        |graph| control::build(graph, &statements, ctx.exception_builtins),
    );
    let mut c = RubyCaptureWalker {
        cap,
        env: env.clone(),
        class,
        ctx,
        vars: HashMap::new(),
        class_refs: HashMap::new(),
        ivars: HashMap::new(),
        instances: HashMap::new(),
        remote_bodies: HashMap::new(),
        poisoned: HashSet::new(),
        procs: HashMap::new(),
        active_procs: HashSet::new(),
        stack,
        nodes_left,
        control,
    };
    for stmt in statements {
        c.stmt(stmt);
    }
    let exhausted = *c.nodes_left == 0;
    let finished = c.control.leave(0);
    if let Some(finished) = finished.filter(|_| !exhausted) {
        cap.control = Some(finished.requirements);
        cap.control_flow = finished.flow;
    } else {
        cap.control = None;
        cap.control_flow = crate::control_flow::ControlFlow::widened();
    }
}

/// Capture-mode walker: collects a method's parameterized effects and edges
/// without a live plan.
struct RubyCaptureWalker<'a> {
    cap: &'a mut Capture,
    env: HashMap<String, ResourceExpr>,
    class: Option<&'a str>,
    ctx: &'a RubyFileContext,
    /// Locals typed by a direct constructor (`x = Cls.new(...)`).
    vars: HashMap<String, Vec<String>>,
    /// Locals bound to a class (`engine_class = Foo::Bar`).
    class_refs: HashMap<String, String>,
    /// Instance variables typed in this body (`@engine ||= ...`).
    ivars: HashMap<String, Vec<String>>,
    instances: HashMap<String, HashMap<String, ResourceExpr>>,
    /// Locals holding a web response body, with the endpoint it came from.
    remote_bodies: HashMap<String, ResourceExpr>,
    poisoned: HashSet<String>,
    /// Deferred `proc`/`lambda` bodies keyed by their local binding.
    procs: HashMap<String, Vec<ProcDef>>,
    active_procs: HashSet<usize>,
    stack: &'a mut Vec<String>,
    nodes_left: &'a mut u64,
    control: &'a mut ControlStack,
}

impl RubyCaptureWalker<'_> {
    fn stmt(&mut self, node: &Node) {
        // Iterative: left-deep `+` / `&&` / Send spines overflow the process
        // stack before the node cap can fire.
        let mut stack = vec![(node, false)];
        while let Some((node, guarded)) = stack.pop() {
            if *self.nodes_left == 0 || !crate::limits::summary_step() {
                self.control.widen();
                if !self
                    .cap
                    .boundaries
                    .iter()
                    .any(|b| b.reason.as_str() == "partial_analysis")
                {
                    self.cap.boundaries.push(Boundary {
                        reason: BoundaryReason::PARTIAL_ANALYSIS,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                        provenance: Vec::new(),
                        limit: Some("max_ruby_nodes".to_string()),
                        detail: Some("ruby summary walk node budget exhausted".to_string()),
                    });
                }
                return;
            }
            *self.nodes_left -= 1;
            let guarded = guarded || matches!(node, Node::OrAsgn(_) | Node::AndAsgn(_));
            let effect_start = self.cap.effects.len();
            let call_start = self.cap.calls.len();
            let spawn_start = self.cap.spawns.len();
            let control_since = self.control.registered();
            match node {
                Node::Send(s) => self.send(s),
                Node::Index(ix) => {
                    if let Some(e) = env_index_read(ix) {
                        self.cap.effects.push(e);
                    }
                }
                Node::IndexAsgn(ix) => {
                    if constant_path(&ix.recv).as_deref() == Some("ENV") {
                        self.cap.effects.push(effect(
                            "environment.write",
                            env_key(&ix.indexes),
                            false,
                        ));
                    }
                }
                // Backticks / %x{...} / heredoc backticks run a shell command.
                Node::Xstr(x) => self.spawned(spawn_of_parts(&x.parts)),
                Node::XHeredoc(x) => self.spawned(spawn_of_parts(&x.parts)),
                Node::Lvasgn(_) | Node::Ivasgn(_) | Node::OrAsgn(_) | Node::AndAsgn(_) => {
                    if self.note_assign(node, guarded) {
                        self.candidate_limit();
                    }
                    if let Node::Lvasgn(assignment) = node {
                        if let Some(value) = assignment.value.as_deref() {
                            note_remote_body(
                                &mut self.remote_bodies,
                                &assignment.name,
                                model::remote_body(value, &self.env, None),
                                guarded,
                            );
                            let resolved = resolve(value, &self.env, None);
                            store_binding(
                                &mut self.env,
                                &mut self.poisoned,
                                &assignment.name,
                                resolved,
                                guarded,
                            );
                            if guarded {
                                self.instances.remove(&assignment.name);
                            } else if let Some(instance) =
                                constructor_instance(value, &self.env, None, self.class, self.ctx)
                            {
                                self.instances.insert(assignment.name.clone(), instance);
                            } else {
                                self.instances.remove(&assignment.name);
                            }
                        }
                        if !guarded {
                            self.procs.remove(&assignment.name);
                        }
                    }
                    if let Node::Ivasgn(assignment) = node
                        && let Some(value) = assignment.value.as_deref()
                    {
                        let resolved = resolve(value, &self.env, None);
                        store_binding(
                            &mut self.env,
                            &mut self.poisoned,
                            &assignment.name,
                            resolved,
                            guarded,
                        );
                    }
                    if let Some((name, body)) = assigned_proc(node)
                        && push_proc(&mut self.procs, name, body)
                    {
                        self.candidate_limit();
                    }
                }
                Node::Masgn(assignment) => {
                    remove_assignment_bindings(&assignment.lhs, &mut self.env, &mut self.poisoned);
                }
                Node::OpAsgn(assignment) => {
                    remove_assignment_bindings(&assignment.recv, &mut self.env, &mut self.poisoned);
                }
                _ => {}
            }
            if matches!(
                node,
                Node::Index(_) | Node::IndexAsgn(_) | Node::Xstr(_) | Node::XHeredoc(_)
            ) {
                let facts = SiteFacts::known(
                    (effect_start..self.cap.effects.len())
                        .map(|slot| ControlFact::Effect(slot as u32))
                        .collect(),
                );
                self.control.register_since(
                    CAPTURE_SOURCE,
                    true,
                    control::span(node),
                    control_since,
                    facts,
                );
            }
            // Class bodies execute here; methods are summarized separately.
            let range = node.expression();
            let guard = self.ctx.guards.at(effinterp_proto::ByteSpan {
                start: range.begin as u32,
                end: range.end as u32,
            });
            for effect in &mut self.cap.effects[effect_start..] {
                effect.condition = effinterp_proto::Condition::compose(
                    effect.condition.iter().chain(guard.iter()),
                );
            }
            for (_, condition) in &mut self.cap.spawns[spawn_start..] {
                *condition =
                    effinterp_proto::Condition::compose(condition.iter().chain(guard.iter()));
            }
            for edge in &mut self.cap.calls[call_start..] {
                edge.condition =
                    effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
                if edge.call_site.is_none() {
                    edge.call_site = Some(effinterp_proto::stable_hash(
                        effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                        &(&self.ctx.source_digest, range.begin, range.end),
                    ));
                }
            }
            if assigned_proc(node).is_none() && !matches!(node, Node::Def(_) | Node::Defs(_)) {
                let guarded = guarded || guarded_ruby_children(node);
                for child in children(node).into_iter().rev() {
                    stack.push((child, guarded));
                }
            }
        }
    }

    fn send(&mut self, s: &Send) {
        let since = self.control.registered();
        let before = self.cap.effects.len();
        let calls = self.cap.calls.len();
        let mut facts = match self.send_inner(s) {
            SendControl::Own(mut facts) => {
                facts.facts = (before..self.cap.effects.len())
                    .map(|slot| ControlFact::Effect(slot as u32))
                    .collect();
                facts.throw_facts = facts.facts.clone();
                facts
            }
            SendControl::Applied(facts) => facts,
            SendControl::Unknown => SiteFacts::unknown(),
        };
        if s.recv.is_none()
            && matches!(
                s.method_name.as_str(),
                "require" | "require_relative" | "load"
            )
        {
            facts.exit = Some(match s.args.first() {
                Some(Node::Str(literal)) => {
                    let mut module = literal.value.to_string_lossy();
                    if matches!(s.method_name.as_str(), "require_relative" | "load")
                        && !module.starts_with("./")
                        && !module.starts_with("../")
                        && !module.starts_with('/')
                    {
                        module = format!("./{module}");
                    }
                    ControlExit::Import { module }
                }
                _ => ControlExit::Unknown,
            });
            facts.call_return = false;
        }
        // Multiple edges at one send are dispatch alternatives, not several
        // calls that every completion reaches.
        if self.cap.calls.len() == calls + 1 {
            facts.facts.push(ControlFact::Call(calls as u32));
            facts.throw_facts.push(ControlFact::Call(calls as u32));
        }
        self.control
            .register_since(CAPTURE_SOURCE, true, control::send_span(s), since, facts);
    }

    fn send_inner(&mut self, s: &Send) -> SendControl {
        let invoked = invoked_procs(s, &self.procs);
        if !invoked.is_empty() {
            let args: Vec<ResourceExpr> = s
                .args
                .iter()
                .map(|argument| resolve(argument, &self.env, None))
                .collect();
            for proc_def in invoked {
                self.run_proc(&proc_def, &args);
            }
            return SendControl::Unknown;
        }
        let argument_sets = yielded_argument_sets(s, &self.env, None);
        let passed = passed_procs(s, &self.procs);
        let callbacks = !passed.is_empty();
        for proc_def in passed {
            for args in &argument_sets {
                self.run_proc(&proc_def, args);
            }
        }
        let control = self.send_modeled(s);
        if callbacks {
            return control.with_unknown_exit();
        }
        control
    }

    fn send_modeled(&mut self, s: &Send) -> SendControl {
        let scope = Scope {
            env: &self.env,
            cwd: None,
            class: self.class,
            ctx: self.ctx,
            vars: &self.vars,
            class_refs: &self.class_refs,
            ivars: &self.ivars,
            remote_bodies: &self.remote_bodies,
        };
        match model(s, &scope) {
            Modeled::Effects {
                effects,
                transfers,
                boundary,
            } => {
                if let Some(name) = poisoned_send_reference(s, &self.poisoned)
                    && let Some(domain) = effects
                        .iter()
                        .find(|effect| contains_unresolved(&effect.resource))
                        .map(|effect| effect.operation.domain().to_string())
                {
                    self.cap.boundaries.push(poison_boundary(&name, &domain));
                }
                self.cap.boundaries.extend(boundary);
                let base = self.cap.effects.len() as u32;
                self.cap.effects.extend(effects);
                self.cap
                    .transfers
                    .extend(transfers.into_iter().map(|binding| binding.shifted(base)));
                SendControl::modeled(s)
            }
            Modeled::LiteralEval(_) => {
                // Captures cannot transfer the eval lexical scope to a nested source.
                self.cap.boundaries.push(model::dyn_boundary("eval"));
                SendControl::Unknown
            }
            Modeled::RemoteEval(url) => {
                let base = self.cap.effects.len() as u32;
                self.cap.effects.extend(model::remote_eval_effects(url));
                self.cap
                    .transfers
                    .push(TransferBinding::new(base, base + 1));
                self.cap.boundaries.push(model::dyn_boundary("eval"));
                SendControl::Unknown
            }
            Modeled::DecodedEval => {
                let base = self.cap.effects.len() as u32;
                let (decode, execution) = model::decoded_eval_effects();
                self.cap.effects.extend([decode, execution]);
                self.cap
                    .transfers
                    .push(TransferBinding::new(base, base + 1));
                self.cap.boundaries.push(model::dyn_boundary("eval"));
                SendControl::Unknown
            }
            Modeled::Boundary(b) => {
                self.cap.boundaries.push(b);
                SendControl::Unknown
            }
            spawned @ (Modeled::ShellSpawn { .. }
            | Modeled::ExecSpawn { .. }
            | Modeled::SpawnUnresolved(_)) => {
                self.spawned(spawned);
                // The launched command's occurrences are not summary slots.
                match SendControl::spawn(s) {
                    SendControl::Own(facts) => SendControl::Applied(facts),
                    other => other,
                }
            }
            Modeled::Calls(edges) => {
                let mut applied = Vec::with_capacity(edges.len());
                for edge in edges {
                    applied.push(self.inline_local(&edge, s));
                    self.cap.calls.push(edge);
                }
                match (applied.len(), applied.pop()) {
                    (1, Some(Some(facts))) => SendControl::Applied(facts),
                    (1, Some(None)) => SendControl::Applied(SiteFacts {
                        call_return: true,
                        ..SiteFacts::unknown()
                    }),
                    _ => SendControl::Unknown,
                }
            }
            Modeled::None => {
                if let Some(callee) = unmodeled_receiver_call(s, self.ctx) {
                    self.cap.boundaries.push(Boundary {
                        reason: BoundaryReason::UNRESOLVED_CALL,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: Some(effinterp_proto::CalleeReference {
                            module: "ruby".to_string(),
                            symbol: callee.clone(),
                        }),
                        domains: KNOWN_DOMAINS
                            .iter()
                            .map(|domain| Domain::new(*domain))
                            .collect(),
                        provenance: Vec::new(),
                        limit: None,
                        detail: Some(format!(
                            "call to unmodeled {callee} at {}..{}",
                            s.expression_l.begin, s.expression_l.end
                        )),
                    });
                    SendControl::Unknown
                } else {
                    SendControl::builtin(s, self.ctx.exception_builtins)
                }
            }
        }
    }

    fn run_proc(&mut self, proc_def: &ProcDef, args: &[ResourceExpr]) {
        let key = Rc::as_ptr(&proc_def.body) as usize;
        if !self.active_procs.insert(key) {
            return;
        }
        let mut env = self.env.clone();
        env.extend(bind_positional(&proc_def.params, args));
        let previous = std::mem::replace(&mut self.env, env);
        self.stmt(&proc_def.body);
        self.env = previous;
        self.active_procs.remove(&key);
    }

    /// A subprocess inside a summarized method: recorded as a process.exec
    /// effect on the summary (the nested command is not composed here — the
    /// executable name is kept when statically known).
    fn spawned(&mut self, m: Modeled) {
        if matches!(
            m,
            Modeled::ShellSpawn { .. } | Modeled::ExecSpawn { .. } | Modeled::SpawnUnresolved(_)
        ) {
            self.cap.spawns.push((m, None));
        }
    }

    /// Fold a same-file callee's (substituted) effects into this summary, so
    /// a method's summary is self-contained. Cross-file edges are left to the
    /// repository composer, which skips effect collection for same-file
    /// dispatch precisely because of this inlining.
    /// Returns the callee's guarantees over this summary's slots.
    fn inline_local(&mut self, edge: &CallEdge, send: &Send) -> Option<SiteFacts> {
        let def_key = local_key(self.ctx, edge)?;
        if self.stack.len() >= MAX_INLINE_DEPTH || self.stack.contains(&def_key) {
            return None;
        }
        let (params, defaults, keywords, body, class) = {
            let d = self.ctx.def(&def_key).expect("local_key checked");
            (
                d.params.clone(),
                d.defaults.clone(),
                d.keywords.clone(),
                d.body.clone(),
                d.class.clone(),
            )
        };
        let body = body?;
        self.stack.push(def_key);
        let mut bindings = resource_bindings(&params, &keywords, &edge.arguments);
        for (name, default) in defaults {
            if let std::collections::hash_map::Entry::Vacant(e) = bindings.entry(name) {
                self.stmt(&default);
                e.insert(resolve(&default, &self.env, None));
            }
        }
        bindings.extend(instance_bindings(
            send,
            &self.instances,
            &self.env,
            None,
            self.class,
            self.ctx,
        ));
        let mut inner = Capture::default();
        let mut inner_env = constant_env(self.ctx, class.as_deref());
        inner_env.extend(
            params
                .iter()
                .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() })),
        );
        if let Some(class) = class.as_deref() {
            inner_env.extend(class_ivar_names(self.ctx, class).into_iter().map(|name| {
                let parameter = format!("@{name}");
                (
                    parameter.clone(),
                    ResourceExpr::Parameter { name: parameter },
                )
            }));
        }
        capture_into(
            &body,
            &inner_env,
            class.as_deref(),
            self.ctx,
            self.stack,
            self.nodes_left,
            self.control,
            &mut inner,
        );
        self.stack.pop();
        let base = self.cap.effects.len() as u32;
        let applied = inner.control.as_ref().map(|requirements| {
            SiteFacts::call(requirements, |fact| match fact {
                ControlFact::Effect(index) => Some(ControlFact::Effect(base + index)),
                ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
            })
        });
        for mut e in inner.effects {
            e.resource = substitute_resource_expr(&e.resource, &bindings);
            unresolved_instance_parameters(&mut e.resource);
            if e.operation.domain() == "network" {
                e.resource = network_sink(e.resource);
            }
            if !has_text_concat(&e.resource) {
                let value = SemanticValue::from(&e.resource);
                crate::lower_effect_value(&mut e, &value);
            }
            if let Some(condition) = &mut e.condition {
                condition.rebind(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(
                        &self.ctx.source_digest,
                        send.expression_l.begin,
                        send.expression_l.end,
                    ),
                ));
            }
            self.cap.effects.push(e);
        }
        self.cap.transfers.extend(
            inner
                .transfers
                .into_iter()
                .map(|binding| binding.shifted(base)),
        );
        self.cap.boundaries.extend(inner.boundaries);
        for (spawn, mut condition) in inner.spawns {
            if let Some(condition) = &mut condition {
                condition.rebind(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(
                        &self.ctx.source_digest,
                        send.expression_l.begin,
                        send.expression_l.end,
                    ),
                ));
            }
            self.cap
                .spawns
                .push((substitute_modeled_spawn(spawn, &bindings), condition));
        }
        applied
    }

    fn note_assign(&mut self, node: &Node, guarded: bool) -> bool {
        apply_live_assign(
            node,
            &mut self.vars,
            &mut self.class_refs,
            &mut self.ivars,
            self.class,
            self.ctx,
            guarded,
        )
    }

    fn candidate_limit(&mut self) {
        if !self.cap.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "dynamic_dispatch"
                && boundary.limit.as_deref() == Some("max_callback_values")
        }) {
            self.cap.boundaries.push(candidate_limit_boundary());
        }
    }
}

/// The same-file def a call edge resolves to, if any: a qualified or bare
/// callee defined here, or the constructor of a locally defined class.
fn local_key(ctx: &RubyFileContext, edge: &CallEdge) -> Option<String> {
    if let Some(ObjectIdentity::Class { name, .. }) = edge.receiver_identity() {
        if edge.callee == *name {
            let init = format!("{name}.__init__");
            return ctx
                .def(&init)
                .map(|_| init)
                .or_else(|| local_method(ctx, name, "initialize"));
        }
        // A method on a typed receiver: resolve through the receiver's class
        // and same-file bases (a subclass inherits the parent's commands).
        if let Some((_, method)) = edge.callee.rsplit_once('.') {
            return local_method(ctx, name, method);
        }
        return None;
    }
    if let Some(ObjectIdentity::ModuleBinding { name, .. }) = edge.receiver_identity()
        && let Some((_, method)) = edge.callee.rsplit_once('.')
    {
        return local_method(ctx, name, method);
    }
    if edge.receiver.is_some() {
        return None;
    }
    ctx.def(&edge.callee).map(|_| edge.callee.clone())
}

fn local_method(ctx: &RubyFileContext, class: &str, method: &str) -> Option<String> {
    let mut seen = HashSet::new();
    let mut stack = vec![class.to_string()];
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let qualified = format!("{name}.{method}");
        if ctx.def(&qualified).is_some() {
            return Some(qualified);
        }
        if let Some(entry) = ctx
            .exact_classes
            .iter()
            .find(|class| class.name == name)
            .or_else(|| ctx.classes.iter().find(|class| class.name == name))
        {
            for base in entry.bases.iter().rev() {
                stack.push(local_base(ctx, &name, base));
            }
        }
    }
    None
}

fn local_base(ctx: &RubyFileContext, owner: &str, base: &str) -> String {
    if base.contains("::") {
        return base.to_string();
    }
    if let Some((namespace, _)) = owner.rsplit_once("::") {
        let qualified = format!("{namespace}::{base}");
        if ctx
            .exact_classes
            .iter()
            .any(|class| class.name == qualified)
        {
            return qualified;
        }
    }
    base.to_string()
}

fn resource_bindings(
    params: &[String],
    keywords: &HashSet<String>,
    arguments: &[ValueArgument],
) -> HashMap<String, ResourceExpr> {
    let arguments: Vec<_> = arguments
        .iter()
        .filter(|argument| {
            argument
                .name
                .as_ref()
                .is_none_or(|name| keywords.contains(name))
        })
        .cloned()
        .collect();
    bind_arguments(params, &arguments)
        .into_iter()
        .map(|(name, value)| (name, value.lower_resource()))
        .collect()
}

fn class_ivar_names(ctx: &RubyFileContext, class: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    if let Some(definition) = ctx.def(&format!("{class}.initialize"))
        && let Some(body) = &definition.body
    {
        let mut stack = vec![body.as_ref()];
        while let Some(node) = stack.pop() {
            if let Node::Ivasgn(assignment) = node {
                names.insert(assignment.name.trim_start_matches('@').to_string());
            }
            if !matches!(
                node,
                Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_)
            ) {
                stack.extend(children(node));
            }
        }
    }
    names
}

fn constructor_instance(
    node: &Node,
    caller_env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
) -> Option<HashMap<String, ResourceExpr>> {
    let Node::Send(send) = node else {
        return None;
    };
    if send.method_name != "new" {
        return None;
    }
    let class = type_name(&send.recv.as_deref().and_then(constant_path)?, enclosing);
    let definition = ctx.def(&format!("{class}.initialize"))?;
    let mut bindings = resource_bindings(
        &definition.params,
        &definition.keywords,
        &value_arguments(&send.args, caller_env, cwd),
    );
    for (name, default) in &definition.defaults {
        bindings
            .entry(name.clone())
            .or_insert_with(|| resolve(default, caller_env, cwd));
    }
    let mut values = HashMap::new();
    let body = definition.body.as_deref()?;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if let Node::Ivasgn(assignment) = node
            && let Some(value) = assignment.value.as_deref()
        {
            let resolved = resolve(value, &bindings, cwd);
            if !contains_unresolved(&resolved) {
                values.insert(assignment.name.clone(), resolved);
            }
        }
        if !matches!(
            node,
            Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_)
        ) {
            stack.extend(children(node));
        }
    }
    Some(values)
}

fn instance_bindings(
    send: &Send,
    instances: &HashMap<String, HashMap<String, ResourceExpr>>,
    env: &HashMap<String, ResourceExpr>,
    cwd: Option<&str>,
    enclosing: Option<&str>,
    ctx: &RubyFileContext,
) -> HashMap<String, ResourceExpr> {
    match send.recv.as_deref() {
        Some(Node::Lvar(local)) => instances.get(&local.name).cloned().unwrap_or_default(),
        Some(node @ Node::Send(_)) => {
            constructor_instance(node, env, cwd, enclosing, ctx).unwrap_or_default()
        }
        None | Some(Node::Self_(_)) => env
            .iter()
            .filter(|(name, _)| name.starts_with('@'))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        _ => HashMap::new(),
    }
}

fn rendered_bindings(bindings: &HashMap<String, ResourceExpr>) -> String {
    let mut entries: Vec<_> = bindings.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    format!("{entries:?}")
}

fn unresolved_instance_parameters(resource: &mut ResourceExpr) {
    match resource {
        ResourceExpr::Parameter { name } if name.starts_with('@') => {
            *resource = unresolved_resource("filesystem");
        }
        ResourceExpr::Join { parts } => {
            for part in parts {
                unresolved_instance_parameters(part);
            }
        }
        ResourceExpr::Union { alternatives } => {
            for alternative in alternatives {
                unresolved_instance_parameters(alternative);
            }
        }
        ResourceExpr::Property { base, .. } => unresolved_instance_parameters(base),
        _ => {}
    }
}

/// Record what an assignment to `name` leaves it holding. A conditional
/// assignment of anything else may be skipped, so an earlier body may remain.
fn note_remote_body(
    bodies: &mut HashMap<String, ResourceExpr>,
    name: &str,
    body: Option<ResourceExpr>,
    guarded: bool,
) {
    match body {
        Some(endpoint) => {
            bodies.insert(name.to_string(), endpoint);
        }
        None if !guarded => {
            bodies.remove(name);
        }
        None => {}
    }
}

fn store_binding(
    env: &mut HashMap<String, ResourceExpr>,
    poisoned: &mut HashSet<String>,
    name: &str,
    value: ResourceExpr,
    guarded: bool,
) {
    let conflict = guarded && env.get(name).is_some_and(|current| current != &value);
    if conflict || contains_unresolved(&value) {
        env.insert(name.to_string(), unresolved_resource("filesystem"));
        poisoned.insert(name.to_string());
    } else {
        env.insert(name.to_string(), value);
        poisoned.remove(name);
    }
}

fn remove_assignment_bindings(
    node: &Node,
    env: &mut HashMap<String, ResourceExpr>,
    poisoned: &mut HashSet<String>,
) {
    match node {
        Node::Lvar(local) => {
            env.remove(&local.name);
            poisoned.remove(&local.name);
        }
        Node::Lvasgn(local) => {
            env.remove(&local.name);
            poisoned.remove(&local.name);
        }
        Node::Ivar(variable) => {
            env.remove(&variable.name);
            poisoned.remove(&variable.name);
        }
        Node::Ivasgn(variable) => {
            env.remove(&variable.name);
            poisoned.remove(&variable.name);
        }
        _ => {
            for child in children(node) {
                remove_assignment_bindings(child, env, poisoned);
            }
        }
    }
}

/// Live-plan walker for module execution.
struct RubyWalker<'a> {
    source: &'a str,
    builder: &'a mut PlanBuilder,
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    ctx: &'a RubyFileContext,
    env: HashMap<String, ResourceExpr>,
    vars: HashMap<String, Vec<String>>,
    class_refs: HashMap<String, String>,
    ivars: HashMap<String, Vec<String>>,
    instances: HashMap<String, HashMap<String, ResourceExpr>>,
    /// Locals holding a web response body, with the endpoint it came from.
    remote_bodies: HashMap<String, ResourceExpr>,
    poisoned: HashSet<String>,
    procs: HashMap<String, Vec<ProcDef>>,
    active_procs: HashSet<usize>,
    captures: HashMap<String, Rc<Capture>>,
    applications: HashMap<String, HashSet<String>>,
    nodes_left: u64,
    truncated: bool,
    candidate_limit_reported: bool,
    call_site_limit_reported: bool,
    /// The program wrote `ENV`, so later reads no longer see the host values.
    environment_rewritten: bool,
    /// Backtick spans a later output call prints: they run with the
    /// program's stdout instead of a captured one.
    printed_captures: HashSet<(usize, usize)>,
    /// `File.read`-style call spans an output call prints, and whether it
    /// prints them verbatim (`Exact`) or as `inspect` escapes them
    /// (`Conservative`): the file's bytes reach the program's stdout.
    printed_reads: HashMap<(usize, usize), effinterp_proto::CausalAssurance>,
    /// The read effects each walked `File.read`-style call emitted.
    read_effects: HashMap<(usize, usize), Vec<u32>>,
    /// Requests consuming the bytes of an inline file read, keyed by read span.
    request_bodies: HashMap<(usize, usize), Vec<u32>>,
    /// The `File.read`-style call spans whose bytes each local may hold. A
    /// guarded assignment adds to what the local held; only an unguarded one
    /// replaces it.
    read_locals: HashMap<String, BTreeSet<(usize, usize)>>,
    /// Each captured backtick's child execution and the stdout it would
    /// have inherited, so printing the captured value can reconnect it.
    captured_outputs: HashMap<
        (usize, usize),
        (
            effinterp_proto::ExecutionNodeRef,
            Option<effinterp_proto::ExecutionStreamRef>,
        ),
    >,
    /// Backtick spans whose output a local holds, each with whether the local
    /// holds those bytes verbatim.
    capture_locals: HashMap<String, Vec<HeldCapture>>,
    /// Local assignments a reached `begin … end while`/`until` body's first
    /// iteration reaches, by start offset. The body runs at least once, so a
    /// `true` one replaces the output a local held; a `false` one sits in a
    /// rescue or ensure body, so the earlier output may or may not remain.
    /// Later iterations keep them guarded for value resolution.
    post_loop_assignments: HashMap<usize, bool>,
}

impl RubyWalker<'_> {
    fn follow_root(&mut self, key: &str) {
        let Some(definition) = self.ctx.def(key) else {
            return;
        };
        let params = definition.params.clone();
        let body = definition.body.clone();
        let class = definition.class.clone();
        let Some(body) = body else { return };
        let bindings: HashMap<String, ResourceExpr> = params
            .iter()
            .map(|name| (name.clone(), ResourceExpr::Parameter { name: name.clone() }))
            .collect();
        let application = rendered_bindings(&bindings);
        if !self
            .applications
            .entry(key.to_string())
            .or_default()
            .insert(application)
        {
            return;
        }
        let inner = self
            .captures
            .entry(key.to_string())
            .or_insert_with(|| Rc::new(capture(Some(&body), &params, class.as_deref(), self.ctx)))
            .clone();
        let expression = body.expression();
        let mut slots = Vec::with_capacity(inner.effects.len());
        for mut effect in inner.effects.iter().cloned() {
            effect.resource = substitute_resource_expr(&effect.resource, &bindings);
            unresolved_instance_parameters(&mut effect.resource);
            if effect.operation.domain() == "network" {
                effect.resource = network_sink(effect.resource);
            }
            slots.push(self.emit(effect, expression.begin, expression.end));
        }
        crate::summary::replay_transfers(self.builder, &inner.transfers, &slots);
        for (spawn, condition) in inner.spawns.iter().cloned() {
            self.spawn_guarded(
                substitute_modeled_spawn(spawn, &bindings),
                condition,
                expression.begin,
                expression.end,
            );
        }
        for boundary in inner.boundaries.iter().cloned() {
            self.builder.boundary(boundary);
        }
    }

    fn stmt(&mut self, node: &Node) {
        let depth = self.builder.condition_depth();
        self.stmt_nodes(node);
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    fn stmt_nodes(&mut self, node: &Node) {
        let mut stack = vec![(node, false)];
        let depth = self.builder.condition_depth();
        while let Some((node, guarded)) = stack.pop() {
            while self.builder.condition_depth() > depth {
                self.builder.pop_condition();
            }
            let expression = node.expression();
            if let Some(condition) = self.ctx.guards.at(effinterp_proto::ByteSpan {
                start: expression.begin as u32,
                end: expression.end as u32,
            }) {
                self.builder.push_condition(condition);
            }
            if !crate::nest::charge_analysis_steps(
                self.builder,
                self.nest.budget,
                1,
                Some((expression.begin as u32, expression.end as u32)),
            ) {
                self.truncated = true;
                return;
            }
            if self.nodes_left == 0 {
                if !self.truncated {
                    self.truncated = true;
                    self.builder.boundary(Boundary {
                        reason: BoundaryReason::PARTIAL_ANALYSIS,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                        provenance: self.scope.as_slice().to_vec(),
                        limit: Some("max_ruby_nodes".to_string()),
                        detail: Some("ruby walk node budget exhausted".to_string()),
                    });
                }
                return;
            }
            self.nodes_left -= 1;
            let guarded = guarded || matches!(node, Node::OrAsgn(_) | Node::AndAsgn(_));
            if !guarded
                && let Node::WhilePost(lib_ruby_parser::nodes::WhilePost { body, .. })
                | Node::UntilPost(lib_ruby_parser::nodes::UntilPost { body, .. }) = node
                && let Node::KwBegin(block) = &**body
            {
                first_iteration_assignments(&block.statements, &mut self.post_loop_assignments);
            }
            let control_since = self.builder.control_registered();
            let control_effects = self.builder.effects_len();
            // An array literal's `each` runs its block once per element, as
            // it runs a proc passed with `&`. The block's proc rebindings are
            // left to the walk below, which keeps the earlier procs reachable.
            if let Node::Block(block) = node
                && let Node::Send(call) = &*block.call
                && call.method_name == "each"
                && call.args.is_empty()
                && matches!(call.recv.as_deref(), Some(Node::Array(array)) if !array.elements.is_empty())
                && let Some(body) = block.body.as_deref()
            {
                let proc_def = ProcDef {
                    params: param_names(&block.args),
                    body: Rc::new(body.clone()),
                };
                let procs = self.procs.clone();
                for args in yielded_argument_sets(call, &self.env, self.cwd) {
                    self.run_proc(&proc_def, &args);
                }
                self.procs = procs;
            }
            match node {
                Node::Send(s) => {
                    if prints_to_stdout(s) {
                        // `p` and `pp` print `inspect`, a quoted rendering of
                        // the text rather than its bytes.
                        let printed = match s.method_name.as_str() {
                            "printf" => formatted_arguments(&s.args),
                            "p" | "pp" => None,
                            _ => Some(s.args.iter().collect()),
                        };
                        let (arguments, assurance) = match &printed {
                            Some(printed) => (printed.clone(), CausalAssurance::Exact),
                            None => (s.args.iter().collect(), CausalAssurance::Conservative),
                        };
                        self.print_reads(&arguments, assurance, s);
                        match printed {
                            Some(printed) => self.print_captures(&printed, true, s),
                            None => {
                                self.print_captures(&s.args.iter().collect::<Vec<_>>(), false, s)
                            }
                        }
                    }
                    let before = self.builder.effects_len();
                    self.send(s);
                    let span = (s.expression_l.begin, s.expression_l.end);
                    if s.method_name == "post"
                        && s.recv.as_deref().and_then(constant_path).as_deref() == Some("Net::HTTP")
                    {
                        let requests: Vec<_> = (before..self.builder.effects_len())
                            .filter(|slot| {
                                matches!(
                                    self.builder.effect_operation(*slot),
                                    Some("network.request" | "network.upload")
                                )
                            })
                            .map(|slot| slot as u32)
                            .collect();
                        match s.args.get(1) {
                            Some(Node::Send(read)) if file_read_call(read) => {
                                self.request_bodies.insert(
                                    (read.expression_l.begin, read.expression_l.end),
                                    requests,
                                );
                            }
                            Some(Node::Lvar(local)) => {
                                let reads = self
                                    .read_locals
                                    .get(&local.name)
                                    .into_iter()
                                    .flatten()
                                    .filter_map(|span| self.read_effects.get(span))
                                    .flatten()
                                    .copied()
                                    .collect::<BTreeSet<_>>();
                                for read in reads {
                                    for request in &requests {
                                        self.builder
                                            .transfer_binding(TransferBinding::new(read, *request));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if file_read_call(s) {
                        let reads = (before..self.builder.effects_len())
                            .filter(|effect| {
                                self.builder.effect_operation(*effect) == Some("filesystem.read")
                            })
                            .map(|effect| effect as u32)
                            .collect::<Vec<_>>();
                        if let Some(assurance) = self.printed_reads.get(&span).copied() {
                            self.bind_reads_to_stdout(reads.clone(), assurance, span);
                        }
                        if let Some(requests) = self.request_bodies.remove(&span) {
                            for read in &reads {
                                for request in &requests {
                                    self.builder
                                        .transfer_binding(TransferBinding::new(*read, *request));
                                }
                            }
                        }
                        self.read_effects.insert(span, reads);
                    }
                }
                Node::Index(ix) => {
                    if let Some(e) = env_index_read(ix) {
                        self.emit(e, ix.expression_l.begin, ix.expression_l.end);
                    }
                }
                Node::IndexAsgn(ix) => {
                    if constant_path(&ix.recv).as_deref() == Some("ENV") {
                        self.emit(
                            effect("environment.write", env_key(&ix.indexes), false),
                            ix.expression_l.begin,
                            ix.expression_l.end,
                        );
                    }
                }
                // Backticks / %x{...} run a shell command, like system().
                Node::Xstr(x) => {
                    let m = spawn_of_parts(&x.parts);
                    let span = (x.expression_l.begin, x.expression_l.end);
                    let captured = !self.printed_captures.contains(&span);
                    self.spawned(m, span.0, span.1, captured);
                }
                Node::XHeredoc(x) => {
                    let m = spawn_of_parts(&x.parts);
                    let span = (x.expression_l.begin, x.expression_l.end);
                    let captured = !self.printed_captures.contains(&span);
                    self.spawned(m, span.0, span.1, captured);
                }
                Node::Lvasgn(_) | Node::Ivasgn(_) | Node::OrAsgn(_) | Node::AndAsgn(_) => {
                    if apply_live_assign(
                        node,
                        &mut self.vars,
                        &mut self.class_refs,
                        &mut self.ivars,
                        None,
                        self.ctx,
                        guarded,
                    ) {
                        self.candidate_limit();
                    }
                    if let Node::Lvasgn(assignment) = node {
                        if let Some(value) = assignment.value.as_deref() {
                            // `y = x` copies the bytes of every read `x` may hold.
                            let assigned = match value {
                                Node::Send(read) if file_read_call(read) => BTreeSet::from([(
                                    read.expression_l.begin,
                                    read.expression_l.end,
                                )]),
                                Node::Lvar(source) => self
                                    .read_locals
                                    .get(&source.name)
                                    .cloned()
                                    .unwrap_or_default(),
                                _ => BTreeSet::new(),
                            };
                            // A guarded assignment may not run, so the
                            // earlier reads may still be what it holds.
                            let mut held = if guarded {
                                self.read_locals
                                    .remove(&assignment.name)
                                    .unwrap_or_default()
                            } else {
                                BTreeSet::new()
                            };
                            held.extend(assigned);
                            if held.is_empty() {
                                self.read_locals.remove(&assignment.name);
                            } else {
                                self.read_locals.insert(assignment.name.clone(), held);
                            }
                            let (mut held, locals) = capture_sources(value);
                            for (local, exact) in locals {
                                held.extend(
                                    self.capture_locals
                                        .get(&local)
                                        .into_iter()
                                        .flatten()
                                        .map(|&(span, verbatim)| (span, exact && verbatim)),
                                );
                            }
                            let earlier = self
                                .capture_locals
                                .get(&assignment.name)
                                .cloned()
                                .unwrap_or_default();
                            match self
                                .post_loop_assignments
                                .get(&assignment.expression_l.begin)
                            {
                                Some(true) => {}
                                Some(false) => {
                                    held.extend(earlier.into_iter().map(|(span, _)| (span, false)))
                                }
                                None if guarded => held.extend(earlier),
                                None => {}
                            }
                            self.capture_locals.insert(assignment.name.clone(), held);
                            note_remote_body(
                                &mut self.remote_bodies,
                                &assignment.name,
                                model::remote_body(value, &self.env, self.cwd),
                                guarded,
                            );
                            let resolved = resolve(value, &self.env, self.cwd);
                            store_binding(
                                &mut self.env,
                                &mut self.poisoned,
                                &assignment.name,
                                resolved,
                                guarded,
                            );
                            if guarded {
                                self.instances.remove(&assignment.name);
                            } else if let Some(instance) =
                                constructor_instance(value, &self.env, self.cwd, None, self.ctx)
                            {
                                self.instances.insert(assignment.name.clone(), instance);
                            } else {
                                self.instances.remove(&assignment.name);
                            }
                        }
                        if !guarded {
                            self.procs.remove(&assignment.name);
                        }
                    }
                    if let Node::Ivasgn(assignment) = node
                        && let Some(value) = assignment.value.as_deref()
                    {
                        let resolved = resolve(value, &self.env, self.cwd);
                        store_binding(
                            &mut self.env,
                            &mut self.poisoned,
                            &assignment.name,
                            resolved,
                            guarded,
                        );
                    }
                    if let Some((name, body)) = assigned_proc(node)
                        && push_proc(&mut self.procs, name, body)
                    {
                        self.candidate_limit();
                    }
                }
                Node::Masgn(assignment) => {
                    remove_assignment_bindings(&assignment.lhs, &mut self.env, &mut self.poisoned);
                }
                Node::OpAsgn(assignment) => {
                    remove_assignment_bindings(&assignment.recv, &mut self.env, &mut self.poisoned);
                }
                _ => {}
            }
            if matches!(
                node,
                Node::Index(_) | Node::IndexAsgn(_) | Node::Xstr(_) | Node::XHeredoc(_)
            ) {
                let facts = SiteFacts::known(
                    self.builder
                        .control_own_effects(control_effects..self.builder.effects_len()),
                );
                self.builder.control_site_since(
                    self.source,
                    false,
                    control::span(node),
                    control_since,
                    facts,
                );
            }
            // Class bodies execute when defined; method bodies execute only
            // when reached through their call edges.
            if assigned_proc(node).is_none() && !matches!(node, Node::Def(_) | Node::Defs(_)) {
                // A literal test selects one arm; the other never runs.
                let literal = match node {
                    Node::If(branch) => control::constant_truth(&branch.cond).map(|truth| {
                        (
                            &branch.cond,
                            if truth {
                                &branch.if_true
                            } else {
                                &branch.if_false
                            },
                        )
                    }),
                    Node::IfMod(branch) => control::constant_truth(&branch.cond).map(|truth| {
                        (
                            &branch.cond,
                            if truth {
                                &branch.if_true
                            } else {
                                &branch.if_false
                            },
                        )
                    }),
                    _ => None,
                };
                if let Some((test, arm)) = literal {
                    if let Some(arm) = arm.as_deref() {
                        stack.push((arm, guarded));
                    }
                    stack.push((test, guarded));
                } else {
                    let guarded = guarded || guarded_ruby_children(node);
                    for child in children(node).into_iter().rev() {
                        stack.push((child, guarded));
                    }
                }
            }
        }
    }

    /// Evaluate a send and register what it establishes at its site.
    fn send(&mut self, s: &Send) {
        let since = self.builder.control_registered();
        let before = self.builder.effects_len();
        let facts = match self.send_inner(s) {
            SendControl::Own(mut facts) => {
                facts.facts = self
                    .builder
                    .control_own_effects(before..self.builder.effects_len());
                facts.throw_facts = facts.facts.clone();
                facts
            }
            SendControl::Applied(facts) => facts,
            SendControl::Unknown => SiteFacts::unknown(),
        };
        self.builder
            .control_site_since(self.source, false, control::send_span(s), since, facts);
    }

    fn send_inner(&mut self, s: &Send) -> SendControl {
        let invoked = invoked_procs(s, &self.procs);
        if !invoked.is_empty() {
            let args: Vec<ResourceExpr> = s
                .args
                .iter()
                .map(|argument| resolve(argument, &self.env, self.cwd))
                .collect();
            for proc_def in invoked {
                self.run_proc(&proc_def, &args);
            }
            return SendControl::Unknown;
        }
        let argument_sets = yielded_argument_sets(s, &self.env, self.cwd);
        let passed = passed_procs(s, &self.procs);
        let callbacks = !passed.is_empty();
        for proc_def in passed {
            for args in &argument_sets {
                self.run_proc(&proc_def, args);
            }
        }
        let control = self.send_modeled(s);
        if callbacks {
            // Procs passed along run under the callee's control.
            return control.with_unknown_exit();
        }
        control
    }

    fn send_modeled(&mut self, s: &Send) -> SendControl {
        let scope = Scope {
            env: &self.env,
            cwd: self.cwd,
            class: None,
            ctx: self.ctx,
            vars: &self.vars,
            class_refs: &self.class_refs,
            ivars: &self.ivars,
            remote_bodies: &self.remote_bodies,
        };
        let begin = s.expression_l.begin;
        let end = s.expression_l.end;
        match model(s, &scope) {
            Modeled::Effects {
                effects,
                transfers,
                boundary: unknown,
            } => {
                if let Some(name) = poisoned_send_reference(s, &self.poisoned)
                    && let Some(domain) = effects
                        .iter()
                        .find(|effect| contains_unresolved(&effect.resource))
                        .map(|effect| effect.operation.domain().to_string())
                {
                    let mut boundary = poison_boundary(&name, &domain);
                    boundary.provenance = vec![self.span(begin, end)];
                    self.builder.boundary(boundary);
                }
                if let Some(mut boundary) = unknown {
                    boundary.provenance.push(self.span(begin, end));
                    self.builder.boundary(boundary);
                }
                let slots: Vec<Option<u32>> = effects
                    .into_iter()
                    .map(|e| self.emit(e, begin, end))
                    .collect();
                crate::summary::replay_transfers(self.builder, &transfers, &slots);
                SendControl::modeled(s)
            }
            Modeled::LiteralEval(source) => {
                let site = self.span(begin, end);
                self.nest.nest(
                    self.builder,
                    Transition::file(Subject::Source {
                        dialect: None,
                        language: "ruby".to_string(),
                        source,
                        cwd: self.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .source_cwd(self.nest.current_source_cwd().as_deref())
                    .runtime_cwd(self.cwd)
                    .cwd(self.builder.current_execution_cwd(), self.cwd_node),
                    &[site],
                    self.depth,
                );
                // Eval shares locals with its caller; nested analysis does not
                // return updated bindings, so previous values are no longer proof.
                self.env.clear();
                self.vars.clear();
                self.class_refs.clear();
                self.ivars.clear();
                self.instances.clear();
                self.remote_bodies.clear();
                self.procs.clear();
                SendControl::Unknown
            }
            Modeled::DecodedEval => {
                let (decode, execution) = model::decoded_eval_effects();
                let slots = [
                    self.emit_applying(decode, begin, end, Some("ruby/base64@v0")),
                    self.emit(execution, begin, end),
                ];
                crate::summary::replay_transfers(
                    self.builder,
                    &[TransferBinding::new(0, 1)],
                    &slots,
                );
                let mut boundary = model::dyn_boundary("eval");
                boundary.provenance.push(self.span(begin, end));
                self.builder.boundary(boundary);
                SendControl::Unknown
            }
            Modeled::RemoteEval(url) => {
                let slots: Vec<Option<u32>> = model::remote_eval_effects(url)
                    .into_iter()
                    .map(|e| self.emit(e, begin, end))
                    .collect();
                crate::summary::replay_transfers(
                    self.builder,
                    &[TransferBinding::new(0, 1)],
                    &slots,
                );
                let mut boundary = model::dyn_boundary("eval");
                boundary.provenance.push(self.span(begin, end));
                self.builder.boundary(boundary);
                SendControl::Unknown
            }
            // A require this launch followed by path is composed, not opaque.
            Modeled::Boundary(_)
                if extract_imports(&Node::Send(s.clone()), true)
                    .first()
                    .is_some_and(|import| {
                        self.nest.dependency_calls.is_followed(
                            &crate::dependency_calls::DependencyRequestKey {
                                source_cwd: self.nest.current_source_cwd(),
                                language: "ruby",
                                specifier: import.module.clone(),
                            },
                            self.builder.current_dependency_launch(),
                        )
                    }) =>
            {
                SendControl::Unknown
            }
            Modeled::Boundary(mut b) => {
                b.provenance.push(self.span(begin, end));
                self.builder.boundary(b);
                SendControl::Unknown
            }
            spawned @ (Modeled::ShellSpawn { .. }
            | Modeled::ExecSpawn { .. }
            | Modeled::SpawnUnresolved(_)) => {
                self.spawned(spawned, begin, end, false);
                SendControl::spawn(s)
            }
            Modeled::Calls(edges) => {
                let mut applied: Vec<Option<SiteFacts>> =
                    edges.iter().map(|edge| self.follow(edge, s)).collect();
                match (applied.len(), applied.pop()) {
                    (1, Some(Some(facts))) => SendControl::Applied(facts),
                    _ => SendControl::Unknown,
                }
            }
            Modeled::None => {
                if let Some(callee) = unmodeled_receiver_call(s, self.ctx) {
                    let arguments = model::value_arguments(&s.args, &self.env, self.cwd);
                    let site = self.span(begin, end);
                    if !crate::dependency_calls::apply_global_dependency_call(
                        self.builder,
                        self.nest,
                        "ruby",
                        &callee,
                        &arguments,
                        site,
                    ) {
                        self.unresolved_call(&callee, s);
                    }
                    // A dependency call is still an external call: its control
                    // is not modeled either way.
                    SendControl::Unknown
                } else {
                    SendControl::builtin(s, self.ctx.exception_builtins)
                }
            }
        }
    }

    fn run_proc(&mut self, proc_def: &ProcDef, args: &[ResourceExpr]) {
        let key = Rc::as_ptr(&proc_def.body) as usize;
        if !self.active_procs.insert(key) {
            return;
        }
        let mut env = self.env.clone();
        env.extend(bind_positional(&proc_def.params, args));
        let previous = std::mem::replace(&mut self.env, env);
        self.stmt(&proc_def.body);
        self.env = previous;
        self.active_procs.remove(&key);
    }

    /// A nested spawn at execution level: literal commands nest a full
    /// sub-analysis; a dynamic command is a process.exec on an unresolved (or
    /// name-only) executable.
    fn spawn_guarded(
        &mut self,
        spawn: Modeled,
        mut condition: Option<effinterp_proto::Condition>,
        begin: usize,
        end: usize,
    ) {
        if let Some(guard) = &mut condition {
            guard.rebind(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(&self.ctx.source_digest, begin, end),
            ));
            self.builder.push_condition(guard.clone());
        }
        self.spawned(spawn, begin, end, false);
        if condition.is_some() {
            self.builder.pop_condition();
        }
    }

    /// `captured` spawns return their stdout to the program as a value, as
    /// backticks do, so it does not reach the program's own stdout.
    fn spawned(&mut self, m: Modeled, begin: usize, end: usize, captured: bool) {
        let stdout = match &m {
            Modeled::ShellSpawn { stdout, .. } | Modeled::ExecSpawn { stdout, .. } => {
                stdout.clone()
            }
            _ => None,
        };
        let child = self.builder.next_execution();
        let inherited_stdout = self.builder.inherited_execution_streams().stdout;
        let captured_streams =
            (captured || stdout.is_some()).then(|| effinterp_proto::ExecutionStreams {
                stdout: None,
                ..self.builder.inherited_execution_streams()
            });
        let capture = |transition: Transition| match captured_streams.clone() {
            Some(streams) => transition.streams(streams),
            None => transition,
        };
        match m {
            Modeled::ShellSpawn { source, cwd, .. } => {
                let node = self.span(begin, end);
                let cwd_path = resource_cwd_path(&cwd).or_else(|| self.cwd.map(str::to_string));
                match resource_command_text(&source) {
                    Some(cmd) => {
                        let source_cwd = self.nest.current_source_cwd();
                        {
                            let subject = Subject::Shell {
                                source: cmd,
                                cwd: cwd_path,
                                context: Default::default(),
                            };
                            let runtime_cwd =
                                crate::nest::subject_cwd(&subject).map(str::to_string);
                            self.nest.nest(
                                self.builder,
                                capture(
                                    Transition::file(subject)
                                        .source_cwd(source_cwd.as_deref())
                                        .runtime_cwd(runtime_cwd.as_deref())
                                        .cwd(cwd, None),
                                ),
                                &[node],
                                self.depth,
                            );
                        };
                    }
                    None => {
                        if let Some(exe_name) = resource_leading_text(&source) {
                            {
                                let words: &[Word] = &[Word::literal(exe_name)];
                                self.nest.nest(
                                    self.builder,
                                    capture(
                                        Transition::exec(
                                            words.iter().map(word_resource).collect(),
                                            words.to_vec(),
                                        )
                                        .exec_cwd(cwd_path.as_deref().or(self.cwd))
                                        .cwd(
                                            self.builder.current_execution_cwd(),
                                            (self.nest.current_runtime_cwd().as_deref()
                                                == cwd_path.as_deref().or(self.cwd))
                                            .then(|| self.nest.current_cwd_node())
                                            .flatten(),
                                        )
                                        .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                                    ),
                                    &[node],
                                    self.depth,
                                )
                            };
                        } else {
                            self.emit(effect("process.exec", exe(None), false), begin, end);
                        }
                    }
                }
            }
            Modeled::ExecSpawn { argv, cwd, .. } => {
                let node = self.span(begin, end);
                let words: Vec<Word> = argv
                    .iter()
                    .map(|argument| {
                        if self.builder.current_execution_argv().is_empty() {
                            ruby_resource_to_word(argument)
                        } else {
                            crate::nest::argument_word(argument)
                        }
                    })
                    .collect();
                let cwd_path = resource_cwd_path(&cwd);
                self.nest.nest(
                    self.builder,
                    capture(
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .exec_cwd(cwd_path.as_deref().or(self.cwd))
                            .cwd(
                                self.builder.current_execution_cwd(),
                                (self.nest.current_runtime_cwd().as_deref()
                                    == cwd_path.as_deref().or(self.cwd))
                                .then(|| self.nest.current_cwd_node())
                                .flatten(),
                            )
                            .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                    ),
                    &[node],
                    self.depth,
                );
            }
            Modeled::SpawnUnresolved(argv0) => {
                self.emit(
                    effect("process.exec", exe(argv0.as_deref()), false),
                    begin,
                    end,
                );
            }
            _ => {}
        }
        if captured && child != self.builder.next_execution() {
            self.captured_outputs
                .insert((begin, end), (child, inherited_stdout));
        }
        // `out:` opens the file and hands it to the child as its stdout.
        if let Some(path) = stdout
            && child != self.builder.next_execution()
        {
            self.builder.push_execution(child);
            let write = self.emit(effect("filesystem.write", path, false), begin, end);
            self.builder.pop_execution();
            let Some(write) = write else { return };
            let node = self.span(begin, end);
            self.builder.flow_stage(crate::flow::FlowStage {
                execution: Some(child),
                effects: vec![write],
                bindings: vec![crate::flow::PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: crate::flow::BindEnd::Port(effinterp_proto::Port::Stdout),
                    to: crate::flow::BindEnd::Effect(write),
                }],
                provenance: vec![node],
            });
        }
    }

    /// An output call prints these arguments. A `File.read`-style call among
    /// them binds its reads once the walk reaches it; a local that last held
    /// one binds the reads that call already emitted.
    fn print_reads(&mut self, args: &[&Node], assurance: CausalAssurance, call: &Send) {
        for argument in args {
            match argument {
                Node::Send(read) if file_read_call(read) => {
                    self.printed_reads
                        .insert((read.expression_l.begin, read.expression_l.end), assurance);
                }
                Node::Lvar(local) => {
                    let reads = self
                        .read_locals
                        .get(&local.name)
                        .into_iter()
                        .flatten()
                        .filter_map(|span| self.read_effects.get(span))
                        .flatten()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    self.bind_reads_to_stdout(
                        reads,
                        assurance,
                        (call.expression_l.begin, call.expression_l.end),
                    );
                }
                _ => {}
            }
        }
    }

    /// These file reads send their bytes to the program's stdout.
    fn bind_reads_to_stdout(
        &mut self,
        reads: Vec<u32>,
        assurance: CausalAssurance,
        (begin, end): (usize, usize),
    ) {
        if reads.is_empty() {
            return;
        }
        let node = self.span(begin, end);
        self.builder.flow_stage(crate::flow::FlowStage {
            execution: Some(self.builder.current_execution()),
            bindings: reads
                .iter()
                .map(|read| crate::flow::PortBinding {
                    assurance,
                    from: crate::flow::BindEnd::Effect(*read),
                    to: crate::flow::BindEnd::Port(effinterp_proto::Port::Stdout),
                })
                .collect(),
            effects: reads,
            provenance: vec![node],
        });
    }

    /// An output call prints these arguments to the program's stdout. Its
    /// backticks, which run after it in this walk, keep that stdout, and a
    /// local holding earlier captured output reconnects that command's stdout.
    /// When the call does not print its arguments `exact`ly, as with a format
    /// this reading cannot follow, captured output raises a boundary instead
    /// of an exact flow.
    fn print_captures(&mut self, args: &[&Node], exact: bool, call: &Send) {
        let mut uncertain = false;
        for argument in args {
            let (spans, locals) = capture_sources(argument);
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
            let node = self.span(call.expression_l.begin, call.expression_l.end);
            self.builder.boundary(Boundary {
                reason: BoundaryReason::DYNAMIC_SOURCE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![node],
                limit: None,
                detail: None,
            });
        }
    }

    /// Apply a same-file callee's summary at a send; its guarantees when
    /// its occurrences were emitted here.
    fn follow(&mut self, edge: &CallEdge, s: &Send) -> Option<SiteFacts> {
        let Some(key) = local_key(self.ctx, edge) else {
            // A bare call or a constant's singleton method may name a global
            // definition from a required file.
            if edge.receiver.as_ref().is_none_or(|receiver| {
                matches!(
                    receiver.as_object().map(|object| &object.identity),
                    Some(ObjectIdentity::ModuleBinding { .. })
                )
            }) {
                let site = self.span(s.expression_l.begin, s.expression_l.end);
                if crate::dependency_calls::apply_global_dependency_call(
                    self.builder,
                    self.nest,
                    "ruby",
                    &edge.callee,
                    &edge.arguments,
                    site,
                ) {
                    return None;
                }
            }
            if edge.receiver.is_none() && !edge.callee.contains('.') {
                self.unresolved_call(&edge.callee, s);
            } else {
                let callee =
                    unmodeled_receiver_call(s, self.ctx).unwrap_or_else(|| edge.callee.clone());
                self.unresolved_call(&callee, s);
            }
            return None;
        };
        let (params, defaults, keywords, body, class) = {
            let d = self.ctx.def(&key).expect("local_key checked");
            (
                d.params.clone(),
                d.defaults.clone(),
                d.keywords.clone(),
                d.body.clone(),
                d.class.clone(),
            )
        };
        let mut bindings = resource_bindings(&params, &keywords, &edge.arguments);
        let mut default_effects = Vec::new();
        for (name, default) in defaults {
            if let std::collections::hash_map::Entry::Vacant(e) = bindings.entry(name) {
                e.insert(resolve(&default, &self.env, self.cwd));
                default_effects.push(default);
            }
        }
        bindings.extend(instance_bindings(
            s,
            &self.instances,
            &self.env,
            self.cwd,
            None,
            self.ctx,
        ));
        let inner = self
            .captures
            .entry(key.clone())
            .or_insert_with(|| {
                Rc::new(capture(
                    body.as_deref(),
                    &params,
                    class.as_deref(),
                    self.ctx,
                ))
            })
            .clone();
        let mut application = rendered_bindings(&bindings);
        if inner
            .effects
            .iter()
            .any(|effect| effect.condition.is_some())
            || inner
                .spawns
                .iter()
                .any(|(_, condition)| condition.is_some())
            || self.builder.current_condition().is_some()
        {
            application.push_str(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(
                    s.expression_l.begin,
                    s.expression_l.end,
                    self.builder
                        .current_condition()
                        .as_ref()
                        .map(effinterp_proto::Condition::identity),
                ),
            ));
        }
        let applications = self.applications.entry(key.clone()).or_default();
        if applications.contains(&application) {
            return None;
        }
        if applications.len() >= MAX_CALL_SITE_APPLICATIONS {
            if !self.call_site_limit_reported {
                self.call_site_limit_reported = true;
                self.builder.boundary(Boundary {
                    reason: BoundaryReason::PARTIAL_ANALYSIS,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
                    provenance: self.scope.as_slice().to_vec(),
                    limit: Some("max_ruby_call_sites".to_string()),
                    detail: Some("ruby call-site application limit exceeded".to_string()),
                });
            }
            return None;
        }
        applications.insert(application);
        for default in default_effects {
            self.stmt(&default);
        }
        let mut slots = Vec::with_capacity(inner.effects.len());
        for mut e in inner.effects.iter().cloned() {
            e.resource = substitute_resource_expr(&e.resource, &bindings);
            unresolved_instance_parameters(&mut e.resource);
            if e.operation.domain() == "network" {
                e.resource = network_sink(e.resource);
            }
            slots.push(self.emit(e, s.expression_l.begin, s.expression_l.end));
        }
        crate::summary::replay_transfers(self.builder, &inner.transfers, &slots);
        for b in inner.boundaries.iter().cloned() {
            self.builder.boundary(b);
        }
        for (spawn, condition) in inner.spawns.iter().cloned() {
            self.spawn_guarded(
                substitute_modeled_spawn(spawn, &bindings),
                condition,
                s.expression_l.begin,
                s.expression_l.end,
            );
        }
        // Follow the callee's own local edges one level down (chained local
        // calls are already inlined into its captured effects).
        inner.control.as_ref().map(|requirements| {
            SiteFacts::call(requirements, |fact| match fact {
                ControlFact::Effect(index) => slots
                    .get(index as usize)
                    .copied()
                    .flatten()
                    .map(ControlFact::Effect),
                ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
            })
        })
    }

    fn unresolved_call(&mut self, callee: &str, s: &Send) {
        let node = self.span(s.expression_l.begin, s.expression_l.end);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: "ruby".to_string(),
                symbol: callee.to_string(),
            }),
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!(
                "call to unmodeled {callee} at {}..{}",
                s.expression_l.begin, s.expression_l.end
            )),
        });
    }

    fn candidate_limit(&mut self) {
        if self.candidate_limit_reported {
            return;
        }
        self.candidate_limit_reported = true;
        let mut boundary = candidate_limit_boundary();
        boundary.provenance = self.scope.as_slice().to_vec();
        self.builder.boundary(boundary);
    }

    /// Emit one effect and report its plan slot, so a transfer emitter can
    /// pair the endpoints it just produced.
    fn emit(&mut self, effect: Effect, begin: usize, end: usize) -> Option<u32> {
        self.emit_applying(effect, begin, end, None)
    }

    /// `emit`, attributing the effect to the named model's application.
    fn emit_applying(
        &mut self,
        mut effect: Effect,
        begin: usize,
        end: usize,
        model: Option<&str>,
    ) -> Option<u32> {
        if let Some(condition) = &mut effect.condition {
            condition.rebind(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(&self.ctx.source_digest, begin, end),
            ));
        }
        let guard = self.ctx.guards.at(effinterp_proto::ByteSpan {
            start: begin as u32,
            end: end as u32,
        });
        effect.condition =
            effinterp_proto::Condition::compose(effect.condition.iter().chain(guard.iter()));
        let mut environment_nodes = Vec::new();
        if effect.operation.as_str() == "environment.write" {
            self.environment_rewritten = true;
        } else if effect.operation.domain() == "filesystem" {
            effect.resource = self.resolve_host_path(effect.resource, &mut environment_nodes);
        }
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        let node = self.span(begin, end);
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
        if effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource) {
            effect.provenance.extend(self.cwd_node);
            // A relative path names a file under the process's working
            // directory; bind it when the invocation states that directory,
            // as `File.expand_path` already does.
            if let Some(cwd) = self.cwd {
                effect.resource = substitute_resource_expr(
                    &effect.resource,
                    &HashMap::from([("cwd".to_string(), fs_path(cwd))]),
                );
            }
        }
        self.builder.effect(effect)
    }

    /// A filesystem path with `ENV[...]` references replaced by the values the
    /// enclosing execution or host supplied, so `File.join(ENV["HOME"], x)`
    /// names the same file as the path written out.
    fn resolve_host_path(
        &mut self,
        mut resource: ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) -> ResourceExpr {
        let before = provenance.len();
        self.resolve_host_environment(&mut resource, provenance);
        if provenance.len() == before {
            return resource;
        }
        match effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix) {
            ResourceExpr::Literal { value } => fs_path(&value),
            resource => resource,
        }
    }

    fn resolve_host_environment(
        &mut self,
        resource: &mut ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) {
        match resource {
            ResourceExpr::Environment { name } => {
                let Some(value) = self.host_environment_value(name) else {
                    return;
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
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                for part in parts {
                    self.resolve_host_environment(part, provenance);
                }
            }
            _ => {}
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

    fn span(&mut self, begin: usize, end: usize) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: begin as u32,
                end: end as u32,
            },
            self.scope.as_slice(),
        )
    }
}

fn ruby_resource_to_word(expr: &ResourceExpr) -> Word {
    match expr {
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

fn resource_command_text(expr: &ResourceExpr) -> Option<String> {
    match expr {
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

fn resource_leading_text(expr: &ResourceExpr) -> Option<String> {
    resource_command_text(expr)?
        .split_whitespace()
        .next()
        .filter(|word| !word.is_empty())
        .map(str::to_string)
}

fn resource_cwd_path(cwd: &Option<ResourceExpr>) -> Option<String> {
    cwd.as_ref().and_then(resource_command_text)
}

fn substitute_modeled_spawn(spawn: Modeled, bindings: &HashMap<String, ResourceExpr>) -> Modeled {
    match spawn {
        Modeled::ShellSpawn {
            source,
            cwd,
            stdout,
        } => Modeled::ShellSpawn {
            source: substitute_resource_expr(&source, bindings),
            cwd: cwd.map(|cwd| substitute_resource_expr(&cwd, bindings)),
            stdout: stdout.map(|stdout| substitute_resource_expr(&stdout, bindings)),
        },
        Modeled::ExecSpawn { argv, cwd, stdout } => Modeled::ExecSpawn {
            argv: argv
                .into_iter()
                .map(|word| substitute_resource_expr(&word, bindings))
                .collect(),
            cwd: cwd.map(|cwd| substitute_resource_expr(&cwd, bindings)),
            stdout: stdout.map(|stdout| substitute_resource_expr(&stdout, bindings)),
        },
        other => other,
    }
}

fn materialize_ruby_spawn(spawn: &Modeled) -> Effect {
    let resource = match spawn {
        Modeled::ShellSpawn { source, .. } => resource_command_text(source)
            .as_deref()
            .map(model::shell_exe)
            .unwrap_or_else(|| exe(None)),
        Modeled::ExecSpawn { argv, .. } => argv
            .first()
            .and_then(resource_command_text)
            .map(|name| exe(Some(&name)))
            .unwrap_or_else(|| exe(None)),
        Modeled::SpawnUnresolved(argv0) => exe(argv0.as_deref()),
        _ => exe(None),
    };
    effect("process.exec", resource, false)
}

// Nested source starts with builtin bindings only when the enclosing source
// cannot replace them. Refuse lexical definitions rather than losing their scope.
fn literal_builtins(root: &Node, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let mut pending = vec![root];
    for _ in 0..DEFAULT_MAX_RUBY_NODES {
        let Some(node) = pending.pop() else {
            return true;
        };
        match node {
            Node::Str(string) if string.value.to_string().is_err() => return false,
            Node::Casgn(_)
            | Node::Class(_)
            | Node::Module(_)
            | Node::SClass(_)
            | Node::Def(_)
            | Node::Defs(_) => return false,
            Node::Send(send)
                if matches!(
                    send.method_name.as_str(),
                    "const_set"
                        | "remove_const"
                        | "define_method"
                        | "define_singleton_method"
                        | "class_eval"
                        | "module_eval"
                        | "instance_eval"
                        | "load"
                        | "autoload"
                ) =>
            {
                return false;
            }
            Node::Send(send) if send.method_name == "eval" => {
                let Some(source) = send.args.first().and_then(literal_str) else {
                    return false;
                };
                if ruby_nesting_exceeds(&source) {
                    return false;
                }
                let parsed = Parser::new(source.as_bytes(), ParserOptions::default()).do_parse();
                if parsed
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.is_error())
                    || !parsed
                        .ast
                        .as_deref()
                        .is_some_and(|root| literal_builtins(root, depth - 1))
                {
                    return false;
                }
            }
            _ => {}
        }
        pending.extend(children(node));
    }
    false
}

// Constant writes anywhere in the file invalidate builtin exception spellings
// in stored bodies too. Refuse the proof if the scan cannot finish.
fn exception_builtins(root: &Node, bytes: usize) -> bool {
    let limit = crate::AnalysisLimits::default().max_causal_pairs as usize;
    if bytes > limit {
        return false;
    }
    let mut pending = vec![root];
    let mut work = 0;
    while let Some(node) = pending.pop() {
        work += 1;
        if work > limit || !crate::limits::summary_step() {
            return false;
        }
        match node {
            Node::Casgn(_) | Node::Class(_) | Node::Module(_) => return false,
            Node::Send(send)
                if matches!(
                    send.method_name.as_str(),
                    "const_set" | "remove_const" | "autoload"
                ) =>
            {
                return false;
            }
            Node::Def(def) => pending.extend(def.body.as_deref()),
            Node::Defs(def) => pending.extend(def.body.as_deref()),
            _ => pending.extend(children(node)),
        }
        if pending.len() > limit.saturating_sub(work) {
            return false;
        }
    }
    true
}

/// Record the local assignments a post-test loop body's first iteration
/// definitely reaches through sequential statements and nested `begin`
/// bodies, and mark those in rescue or ensure bodies as uncertain. A `next`,
/// `break`, `redo` or `return` may skip what follows it, so collection stops
/// there; the return value says whether it did not.
fn first_iteration_assignments(statements: &[Node], out: &mut HashMap<usize, bool>) -> bool {
    for statement in statements {
        match statement {
            Node::KwBegin(block) => {
                if !first_iteration_assignments(&block.statements, out) {
                    return false;
                }
            }
            Node::Rescue(_) | Node::Ensure(_) => {
                let mut stack = vec![statement];
                while let Some(node) = stack.pop() {
                    if let Node::Lvasgn(assignment) = node {
                        out.entry(assignment.expression_l.begin).or_insert(false);
                    }
                    stack.extend(children(node));
                }
                if leaves_iteration(statement) {
                    return false;
                }
            }
            _ if leaves_iteration(statement) => return false,
            Node::Lvasgn(assignment) => {
                out.insert(assignment.expression_l.begin, true);
            }
            _ => {}
        }
    }
    true
}

fn leaves_iteration(node: &Node) -> bool {
    matches!(
        node,
        Node::Next(_) | Node::Break(_) | Node::Redo(_) | Node::Return(_)
    ) || children(node).into_iter().any(leaves_iteration)
}

/// Direct child nodes of `node` that may contain further statements/calls.
/// Class, module and singleton-class bodies are included because they execute
/// when defined; method definition bodies are absent, left to the callers that
/// summarize or enter them.
fn children(node: &Node) -> Vec<&Node> {
    fn push_opt<'a>(out: &mut Vec<&'a Node>, n: &'a Option<Box<Node>>) {
        if let Some(n) = n {
            out.push(n);
        }
    }
    let mut out: Vec<&Node> = Vec::new();
    match node {
        Node::Begin(b) => out.extend(b.statements.iter()),
        Node::KwBegin(b) => out.extend(b.statements.iter()),
        Node::Send(s) => {
            if let Some(r) = &s.recv {
                out.push(r);
            }
            out.extend(s.args.iter());
        }
        Node::CSend(s) => {
            out.push(&s.recv);
            out.extend(s.args.iter());
        }
        Node::Block(b) => {
            out.push(&b.call);
            push_opt(&mut out, &b.body);
        }
        Node::Numblock(b) => {
            out.push(&b.call);
            out.push(&b.body);
        }
        Node::If(i) => {
            out.push(&i.cond);
            push_opt(&mut out, &i.if_true);
            push_opt(&mut out, &i.if_false);
        }
        Node::IfMod(i) => {
            out.push(&i.cond);
            push_opt(&mut out, &i.if_true);
            push_opt(&mut out, &i.if_false);
        }
        Node::IfTernary(i) => {
            out.push(&i.cond);
            out.push(&i.if_true);
            out.push(&i.if_false);
        }
        Node::While(w) => {
            out.push(&w.cond);
            push_opt(&mut out, &w.body);
        }
        Node::WhilePost(w) => {
            out.push(&w.cond);
            out.push(&w.body);
        }
        Node::Until(w) => {
            out.push(&w.cond);
            push_opt(&mut out, &w.body);
        }
        Node::UntilPost(w) => {
            out.push(&w.cond);
            out.push(&w.body);
        }
        Node::For(f) => {
            out.push(&f.iteratee);
            push_opt(&mut out, &f.body);
        }
        Node::Case(c) => {
            push_opt(&mut out, &c.expr);
            out.extend(c.when_bodies.iter());
            push_opt(&mut out, &c.else_body);
        }
        Node::When(w) => {
            out.extend(w.patterns.iter());
            push_opt(&mut out, &w.body);
        }
        Node::Rescue(r) => {
            push_opt(&mut out, &r.body);
            out.extend(r.rescue_bodies.iter());
            push_opt(&mut out, &r.else_);
        }
        Node::RescueBody(r) => push_opt(&mut out, &r.body),
        Node::Ensure(e) => {
            push_opt(&mut out, &e.body);
            push_opt(&mut out, &e.ensure);
        }
        Node::Module(m) => push_opt(&mut out, &m.body),
        Node::Class(class) => {
            push_opt(&mut out, &class.superclass);
            push_opt(&mut out, &class.body);
        }
        Node::SClass(class) => {
            out.push(&class.expr);
            push_opt(&mut out, &class.body);
        }
        Node::Xstr(x) => out.extend(x.parts.iter()),
        Node::XHeredoc(x) => out.extend(x.parts.iter()),
        Node::Dstr(d) => out.extend(d.parts.iter()),
        Node::Heredoc(h) => out.extend(h.parts.iter()),
        Node::Regexp(r) => out.extend(r.parts.iter()),
        Node::Array(a) => out.extend(a.elements.iter()),
        Node::Hash(h) => out.extend(h.pairs.iter()),
        Node::Kwargs(k) => out.extend(k.pairs.iter()),
        Node::Pair(p) => {
            out.push(&p.key);
            out.push(&p.value);
        }
        Node::Lvasgn(a) => push_opt(&mut out, &a.value),
        Node::Ivasgn(a) => push_opt(&mut out, &a.value),
        Node::Gvasgn(a) => push_opt(&mut out, &a.value),
        Node::Cvasgn(a) => push_opt(&mut out, &a.value),
        Node::Casgn(a) => push_opt(&mut out, &a.value),
        Node::Masgn(a) => out.push(&a.rhs),
        Node::OpAsgn(a) => {
            out.push(&a.recv);
            out.push(&a.value);
        }
        Node::OrAsgn(a) => {
            out.push(&a.recv);
            out.push(&a.value);
        }
        Node::AndAsgn(a) => {
            out.push(&a.recv);
            out.push(&a.value);
        }
        Node::And(a) => {
            out.push(&a.lhs);
            out.push(&a.rhs);
        }
        Node::Or(o) => {
            out.push(&o.lhs);
            out.push(&o.rhs);
        }
        Node::Return(r) => out.extend(r.args.iter()),
        Node::Yield(y) => out.extend(y.args.iter()),
        Node::Super(s) => out.extend(s.args.iter()),
        Node::Splat(s) => push_opt(&mut out, &s.value),
        Node::Kwsplat(k) => out.push(&k.value),
        Node::BlockPass(b) => push_opt(&mut out, &b.value),
        Node::Defined(d) => out.push(&d.value),
        Node::Index(ix) => {
            out.push(&ix.recv);
            out.extend(ix.indexes.iter());
        }
        Node::IndexAsgn(ix) => {
            out.push(&ix.recv);
            out.extend(ix.indexes.iter());
            push_opt(&mut out, &ix.value);
        }
        Node::Irange(r) => {
            push_opt(&mut out, &r.left);
            push_opt(&mut out, &r.right);
        }
        Node::Erange(r) => {
            push_opt(&mut out, &r.left);
            push_opt(&mut out, &r.right);
        }
        _ => {}
    }
    out
}

fn ruby_guard_regions(root: &Node, source: &str) -> crate::guards::GuardRegions {
    use effinterp_proto::{ByteSpan, ConditionKind};
    fn span(node: &Node) -> ByteSpan {
        let r = node.expression();
        ByteSpan {
            start: r.begin as u32,
            end: r.end as u32,
        }
    }
    let mut guards = crate::guards::GuardRegions::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let statements = match node {
            Node::Begin(b) => Some(&b.statements),
            Node::KwBegin(b) => Some(&b.statements),
            _ => None,
        };
        if let Some(statements) = statements {
            for statement in statements {
                let branches = match statement {
                    Node::If(branch) => Some((&branch.if_true, &branch.if_false)),
                    Node::IfMod(branch) => Some((&branch.if_true, &branch.if_false)),
                    _ => None,
                };
                if let Some((if_true, if_false)) = branches {
                    let yes = if_true.as_deref().is_some_and(ruby_stops);
                    let no = if_false.as_deref().is_some_and(ruby_stops);
                    if yes != no {
                        guards.add(
                            source,
                            span(statement),
                            ByteSpan {
                                start: span(statement).end,
                                end: span(node).end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
        }
        let mut add = |region: &Node, kind, arm, arms, boolean| {
            guards.add(source, span(node), span(region), kind, arm, arms, boolean)
        };
        match node {
            Node::Def(d) => {
                if let Some(body) = &d.body {
                    stack.push(body);
                }
            }
            Node::Defs(d) => {
                if let Some(body) = &d.body {
                    stack.push(body);
                }
            }
            Node::Class(c) => {
                if let Some(body) = &c.body {
                    stack.push(body);
                }
            }
            Node::Module(m) => {
                if let Some(body) = &m.body {
                    stack.push(body);
                }
            }
            Node::Block(b) => {
                if let Some(body) = &b.body {
                    add(body, ConditionKind::Dispatch, 0, 2, false);
                }
            }
            Node::Numblock(b) => add(&b.body, ConditionKind::Dispatch, 0, 2, false),
            Node::If(i) => {
                if let Some(n) = &i.if_true {
                    add(n, ConditionKind::Branch, 0, 2, true);
                }
                if let Some(n) = &i.if_false {
                    add(n, ConditionKind::Branch, 1, 2, true);
                }
            }
            Node::IfMod(i) => {
                if let Some(n) = &i.if_true {
                    add(n, ConditionKind::Branch, 0, 2, true);
                }
                if let Some(n) = &i.if_false {
                    add(n, ConditionKind::Branch, 1, 2, true);
                }
            }
            Node::IfTernary(i) => {
                add(&i.if_true, ConditionKind::Branch, 0, 2, true);
                add(&i.if_false, ConditionKind::Branch, 1, 2, true);
            }
            Node::While(i) => {
                if let Some(n) = &i.body {
                    add(n, ConditionKind::Loop, 0, 2, false);
                }
            }
            Node::Until(i) => {
                if let Some(n) = &i.body {
                    add(n, ConditionKind::Loop, 0, 2, false);
                }
            }
            Node::For(i) => {
                if let Some(n) = &i.body {
                    add(n, ConditionKind::Loop, 0, 2, false);
                }
            }
            Node::RescueBody(i) => {
                if let Some(body) = &i.body {
                    add(body, ConditionKind::UnresolvedExecution, 0, 2, false);
                }
            }
            Node::And(i) => add(&i.rhs, ConditionKind::ShortCircuit, 0, 2, true),
            Node::Or(i) => add(&i.rhs, ConditionKind::ShortCircuit, 1, 2, true),
            Node::Case(i) => {
                for (arm, body) in i.when_bodies.iter().enumerate() {
                    add(
                        body,
                        ConditionKind::Branch,
                        arm as u32,
                        i.when_bodies.len() as u32 + 1,
                        false,
                    );
                }
                if let Some(n) = &i.else_body {
                    add(
                        n,
                        ConditionKind::Branch,
                        i.when_bodies.len() as u32,
                        i.when_bodies.len() as u32 + 1,
                        false,
                    );
                }
            }
            _ => (),
        }
        stack.extend(children(node));
    }
    guards
}

fn ruby_stops(mut node: &Node) -> bool {
    for _ in 0..16 {
        match node {
            Node::Return(_) | Node::Break(_) | Node::Next(_) => return true,
            Node::Begin(b) => {
                if let Some(last) = b.statements.last() {
                    node = last;
                } else {
                    return false;
                }
            }
            _ => return false,
        }
    }
    false
}
