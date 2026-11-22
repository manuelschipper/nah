//! Methods defined inside `module`/`class` bodies (including `def self.x` and
//! `class << self`) are registered under `Class.method` — the same qualified
//! naming the Python frontend uses — with `initialize` also registered as
//! `Class.__init__` so the composer's constructor lookup finds it. Call edges
//! carry receivers (`Cls.new(...)`, chained `Cls.new(...).m`, `@ivar.m`,
//! ctor-typed locals) so the repository layer can dispatch them through Ruby's
//! flat, require-based namespace.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::ResourceExpr;
use lib_ruby_parser::{Node, Parser, ParserOptions};

use crate::lang::depth::ruby_nesting_exceeds;
use crate::lang::frontend::MAX_WALK_DEPTH;
use crate::limits::DEFAULT_MAX_RUBY_NODES;
use crate::module_summary::ClassEntry;
use crate::value::fs_path_resource;

use super::guard_regions::ruby_guard_regions;
use super::receiver_types::{infer_ruby_return_class, scan_ruby_receiver_types};
use super::syntax::{
    ruby_ast_children, ruby_constant_last_segment, ruby_constant_name, ruby_constant_path,
    ruby_literal_string, ruby_literal_string_parts, ruby_parameter_metadata, ruby_top_statements,
};
use super::{MAX_INLINE_DEPTH, load_path};

/// One registered method: its lookup key (`Class.method`, the bare name, or
/// `Class.__init__` for a constructor), parameters, body, and defining class.
pub(super) struct RubyMethodDefinition {
    pub(super) key: String,
    /// True for the source-written name, false for lookup aliases.
    pub(super) declared: bool,
    pub(super) params: Vec<String>,
    pub(super) defaults: HashMap<String, Rc<Node>>,
    pub(super) keywords: HashSet<String>,
    pub(super) body: Option<Rc<Node>>,
    pub(super) class: Option<String>,
}

/// A file's definitions: methods (qualified and bare keys, first definition
/// wins) and the classes/modules that declare them.
#[derive(Default)]
pub(super) struct RubyFileContext {
    pub(super) literal_builtins: bool,
    pub(super) exception_builtins: bool,
    pub(super) source_digest: String,
    pub(super) guards: crate::guards::GuardRegions,
    pub(super) defs: Vec<RubyMethodDefinition>,
    pub(super) classes: Vec<ClassEntry>,
    exact_defs: Vec<RubyMethodDefinition>,
    pub(super) exact_classes: Vec<ClassEntry>,
    /// Public instance methods of each class, in definition order.
    pub(super) pub_methods: HashMap<String, Vec<String>>,
    /// Classes whose body used a command-table DSL (`desc`, ...).
    command_dsl: HashSet<String>,
    /// Class → command/template method names (filled after collect).
    pub(super) commands: HashMap<String, Vec<String>>,
    /// Qualified method → constructed class that method returns.
    pub(super) returns: HashMap<String, String>,
    /// Methods hidden by Ruby `private`/`protected` visibility sections.
    pub(super) internal: HashSet<String>,
    pub(super) consts: HashMap<String, ResourceExpr>,
    pub(super) rake_dsl: bool,
    pub(super) load_path: load_path::LoadPathEvidence,
}

impl RubyFileContext {
    /// Collect file evidence before either walk can resolve a same-file call.
    pub(super) fn collect(source: &str, root: &Node) -> Self {
        let mut ctx = Self {
            literal_builtins: literal_builtins(root, MAX_INLINE_DEPTH),
            exception_builtins: exception_builtins(root, source.len()),
            source_digest: effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
                &source,
            ),
            guards: ruby_guard_regions(root, source),
            load_path: load_path::extract(root),
            ..Self::default()
        };
        for stmt in ruby_top_statements(root) {
            collect_definitions(stmt, &mut ctx);
            collect_exact(stmt, None, &mut ctx, 0);
        }
        ctx.rake_dsl = has_rake_dsl(root);
        finish_collect(&mut ctx);
        ctx
    }

    /// Prefer the exact namespace over the corresponding bare lookup key.
    pub(super) fn method_definition(&self, key: &str) -> Option<&RubyMethodDefinition> {
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
        let (params, defaults, keywords) = ruby_parameter_metadata(args);
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
            if self.method_definition(&key).is_none() {
                self.defs.push(RubyMethodDefinition {
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
        let (params, defaults, keywords) = ruby_parameter_metadata(args);
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
                self.exact_defs.push(RubyMethodDefinition {
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

/// Collect definitions from a file: top-level defs, plus methods inside
/// `module`/`class` bodies (`def`, `def self.x`, `class << self`), each class
/// or module contributing a [`ClassEntry`]. Nesting uses the innermost
/// constant name (`ColorLS::Flags` registers as `Flags`), matching how call
/// edges name their heads.
fn collect_definitions(node: &Node, ctx: &mut RubyFileContext) {
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
            let Some(name) = ruby_constant_name(&c.name) else {
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
                && let Some(base) = ruby_constant_name(sup)
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
            let Some(name) = ruby_constant_name(&m.name) else {
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
            let bare_was_defined = ctx.method_definition(&d.name).is_some();
            let qualified = format!("{}.{}", entry.name, d.name);
            let qualified_was_defined = ctx.method_definition(&qualified).is_some();
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
                if let Some(base) = ruby_constant_name(arg) {
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
    let name = match assignment.scope.as_deref().and_then(ruby_constant_path) {
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
        Node::Str(string) => Some(fs_path_resource(&string.value.to_string_lossy())),
        Node::Dstr(string) => {
            ruby_literal_string_parts(&string.parts).map(|value| fs_path_resource(&value))
        }
        Node::Send(send)
            if send.recv.as_deref().and_then(ruby_constant_path).as_deref() == Some("File")
                && send.method_name == "join"
                && !send.args.is_empty() =>
        {
            let parts = send
                .args
                .iter()
                .map(|argument| ruby_literal_string(argument).map(|value| fs_path_resource(&value)))
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
        scan_ruby_receiver_types(&body, class, &params, &mut locals, entry);
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
    ruby_constant_last_segment(name) == "Base"
        || ctx.classes.iter().any(|c| {
            c.name == name
                && c.bases
                    .iter()
                    .any(|b| ruby_constant_last_segment(b) == "Base")
        })
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
        if let Some(cls) = infer_ruby_return_class(body, class, &d.params, entry) {
            returns.insert(d.key.clone(), cls);
        }
    }
    ctx.returns = returns;
}

/// List source-qualified class and module names separately from their bare lookup keys.
pub(super) fn qualified_class_definitions(root: &Node) -> Vec<(String, String)> {
    fn collect(node: &Node, namespace: Option<&str>, out: &mut Vec<(String, String)>) {
        match node {
            Node::Begin(begin) => {
                for statement in &begin.statements {
                    collect(statement, namespace, out);
                }
            }
            Node::Class(class) => {
                let Some(written) = ruby_constant_path(&class.name) else {
                    return;
                };
                let qualified = if written.contains("::") {
                    written
                } else if let Some(namespace) = namespace {
                    format!("{namespace}::{written}")
                } else {
                    written
                };
                out.push((qualified.clone(), ruby_constant_name(&class.name).unwrap()));
                if let Some(body) = &class.body {
                    collect(body, Some(&qualified), out);
                }
            }
            Node::Module(module) => {
                let Some(written) = ruby_constant_path(&module.name) else {
                    return;
                };
                let qualified = if written.contains("::") {
                    written
                } else if let Some(namespace) = namespace {
                    format!("{namespace}::{written}")
                } else {
                    written
                };
                out.push((qualified.clone(), ruby_constant_name(&module.name).unwrap()));
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
            let Some(written) = ruby_constant_path(&class.name) else {
                return;
            };
            let qualified = qualify_constant(namespace, &written);
            let mut entry = ClassEntry {
                name: qualified.clone(),
                bases: class
                    .superclass
                    .as_deref()
                    .and_then(ruby_constant_path)
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
            let Some(written) = ruby_constant_path(&module.name) else {
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
                .extend(send.args.iter().filter_map(ruby_constant_path));
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
                let Some(source) = send.args.first().and_then(ruby_literal_string) else {
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
        pending.extend(ruby_ast_children(node));
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
            _ => pending.extend(ruby_ast_children(node)),
        }
        if pending.len() > limit.saturating_sub(work) {
            return false;
        }
    }
    true
}
