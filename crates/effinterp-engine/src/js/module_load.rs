//! One owner for "this code may load a module".
//!
//! Static `import` and `export ... from`, `import()`, `require` and its
//! aliases, `.call` / `.apply` / `.bind` (also when read off the loader and
//! later invoked on it), `module.require`, `createRequire`, and
//! `require.resolve` followed by a load are classified here. The effect
//! walk follows a module this classification names, and records a dependency
//! gap for every other loader use. A shape the owner does not know how to
//! name is a gap, so a decision cannot claim full coverage of a module it
//! did not read.
//!
//! An ordinary method named `call` or `apply` is not a loader use.
//!
//! Where production reads it: the effect walk
//! (`JsWalker::follow_module` in `ast_visit.rs`) follows each named
//! module through `Nest::follow_dependency`
//! (`crate::nest::dependency_sources`), which finds the file by a modeled
//! path search whose limits it states; a repository module summary
//! (`summary_load_sites::LoadSites`) records each named module as an import
//! and each unnamed load as a gap; and effect-API resolution reads
//! `loaded_literals`, so `require.call(null, 'fs').rmSync` is `fs`.
//!
//! Narrower recognizers of a literal load remain outside this owner:
//! `resolve::require_module` names the API module a value is bound to,
//! `resolve::DynamicImportFacts` binds a literal `import()`'s namespace to
//! the names its callback receives, and the summary's `ImportCollector`
//! (`summarize.rs`) binds the names a `require('literal')` declares.
//! `LoadSites` adds every other load this owner names.

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{
    BindingPattern, CallExpression, Expression, ImportDeclaration, ImportDeclarationSpecifier,
    Statement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::SymbolId;
use oxc_span::Span;

use super::call_arguments::{logical_call_argument, logical_call_argument_count};
use super::expression_values::{sequence_callee_value, unparen};
use super::identifier_references::global_reference_spans;
use super::literal_members::array_element;
use super::resolve;
use crate::lang::frontend::MAX_WALK_DEPTH;

/// What a loader call does with its arguments.
#[derive(Clone, Debug)]
pub(super) enum SpecifierSource {
    /// The specifier is this logical argument.
    Argument(usize),
    /// The specifier is the first element of the array at this logical argument
    /// (`require.apply(receiver, [specifier])`).
    Apply(usize),
    /// The specifier is already known (`require.bind(receiver, './file.js')`).
    Known(String),
    /// The call reaches the loader, and the module cannot be named.
    Gap,
}

/// Every loader call in one program, and the literal modules those calls name.
pub(super) struct ModuleLoads {
    /// A call's full span. The start alone collides: `require('fs').rmSync(path)`
    /// begins at the same offset as the inner `require`.
    calls: HashMap<(u32, u32), SpecifierSource>,
    /// Call span → canonical module name, when the specifier is a literal.
    /// Effect-API resolution reads this so `require.call(null, 'fs')` is `fs`.
    pub(super) loaded_literals: HashMap<(u32, u32), String>,
    /// Identifier span → module specifier bound by `require.resolve`.
    paths: HashMap<u32, String>,
    /// `require.resolve(...)` call span → the specifier it returns.
    resolves: HashMap<(u32, u32), String>,
    /// `loader.bind(...)` calls. The later call is the load.
    binds: HashSet<(u32, u32)>,
    /// `createRequire(...)` calls. They build a loader and are not themselves
    /// a module load, so a walk that follows modules does not leave them
    /// unresolved.
    factories: HashSet<(u32, u32)>,
    /// A loader call whose relative specifiers resolve from somewhere other
    /// than the enclosing source. Absent means the enclosing source.
    bases: HashMap<(u32, u32), LoadBase>,
    /// A loader value passed into a call this owner does not itself classify.
    /// The walk follows the named module, or records a dependency gap.
    escapes: HashMap<(u32, u32), LoaderEscape>,
    /// A loader stored where a later read cannot name it: a computed
    /// property, an array, or a container passed into another call. The walk
    /// records a dependency gap at this span.
    stored_gaps: HashSet<(u32, u32)>,
}

/// Where a `createRequire` loader resolves a relative specifier.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LoadBase {
    /// `import.meta.url` and `__filename`: the file that contains the call.
    Enclosing,
    /// Directory of the filename passed to `createRequire`.
    Dir(String),
    /// The filename is not a path this owner can name. A relative load is a gap.
    Unknown,
}

/// A loader handed to another call, such as `Promise.resolve(path).then(require)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LoaderEscape {
    /// The callback is invoked with this specifier, already resolved against
    /// the loader's base.
    Follow(String),
    /// The loader escapes and the module it would load cannot be named.
    Gap,
}

impl ModuleLoads {
    /// How the loader call at this full call span names its module. `None`
    /// means the call is not a module load.
    pub(super) fn call(&self, span: (u32, u32)) -> Option<&SpecifierSource> {
        self.calls.get(&span)
    }

    /// `createRequire(...)` at this span builds a loader and loads nothing.
    pub(super) fn is_factory(&self, span: (u32, u32)) -> bool {
        self.factories.contains(&span)
    }

    /// `loader.resolve(literal)` named a module. The load is the effect.
    pub(super) fn recorded_resolve(&self, span: (u32, u32)) -> bool {
        self.resolves.contains_key(&span)
    }

    /// `loader.bind(...)` fixed or forwarded a loader. The later call is the load.
    pub(super) fn recorded_bind(&self, span: (u32, u32)) -> bool {
        self.binds.contains(&span)
    }

    /// Rewrite a specifier for a loader whose base is not the enclosing source.
    /// An unknown base drops a relative specifier so the walk records a gap
    /// instead of reading the enclosing file.
    pub(super) fn rebase(&self, span: (u32, u32), specifier: Option<String>) -> Option<String> {
        match self.bases.get(&span) {
            Some(base) => rebase_specifier(Some(base), specifier),
            None => specifier,
        }
    }

    /// A loader passed as an argument of the call at this span.
    pub(super) fn escape(&self, span: (u32, u32)) -> Option<&LoaderEscape> {
        self.escapes.get(&span)
    }

    /// A loader was stored at this span and this owner cannot name the later
    /// read. The walk records a dependency gap.
    pub(super) fn stored_gap(&self, span: (u32, u32)) -> bool {
        self.stored_gaps.contains(&span)
    }

    /// A specifier this expression already spells out: a resolved path
    /// binding, or `require.resolve('./file.js')`.
    pub(super) fn resolved_specifier(&self, expr: &Expression<'_>) -> Option<String> {
        match sequence_callee_value(expr) {
            Expression::Identifier(id) => self.paths.get(&id.span.start).cloned(),
            Expression::CallExpression(call) => self
                .resolves
                .get(&(call.span.start, call.span.end))
                .cloned(),
            _ => None,
        }
    }
}

/// The module a static `import` declaration names, including an
/// `import type`. The effect walk follows every declaration, since
/// TypeScript can preserve a load even when it erases every specifier in it;
/// a reader that wants only runtime loads checks `import_kind` itself, as
/// `runtime_imports` does.
pub(super) fn static_import<'a>(import: &'a ImportDeclaration<'a>) -> &'a str {
    import.source.value.as_str()
}

/// The module an `export { ... } from` re-export loads; `None` for an
/// `export` of local names, which loads nothing.
pub(super) fn static_export_named<'a>(
    export: &'a oxc_ast::ast::ExportNamedDeclaration<'a>,
) -> Option<&'a str> {
    export.source.as_ref().map(|source| source.value.as_str())
}

/// The module an `export * from` re-export loads.
pub(super) fn static_export_all<'a>(export: &'a oxc_ast::ast::ExportAllDeclaration<'a>) -> &'a str {
    export.source.value.as_str()
}

/// A static module load statement (`import`, or `export ... from`) and the
/// module it names. These load before any statement of the program
/// runs, so the control graph places them at its entry.
pub(super) fn static_load<'a>(statement: &'a Statement<'a>) -> Option<(Span, &'a str)> {
    match statement {
        Statement::ImportDeclaration(import) => Some((import.span, static_import(import))),
        Statement::ExportAllDeclaration(export) => Some((export.span, static_export_all(export))),
        Statement::ExportNamedDeclaration(export) => {
            static_export_named(export).map(|module| (export.span, module))
        }
        _ => None,
    }
}

/// Classify every loader use in one program. `require_shadowed` says the
/// global `require` is not the runtime's loader; `source_cwd` is the
/// enclosing file's directory, against which a `require.resolve` of a
/// relative specifier is made absolute. Without an absolute one, that result
/// is not named.
pub(super) fn collect(
    program: &oxc_ast::ast::Program<'_>,
    semantic: &oxc_semantic::Semantic<'_>,
    require_shadowed: bool,
    global_require_spans: &HashSet<u32>,
    source_cwd: Option<String>,
) -> ModuleLoads {
    let mut sets = Sets {
        loaders: if require_shadowed {
            HashSet::new()
        } else {
            global_require_spans.clone()
        },
        fixed: HashMap::new(),
        fixed_gap: HashSet::new(),
        methods: HashMap::new(),
        forwards: HashMap::new(),
        factories: HashSet::new(),
        namespaces: HashSet::new(),
        module_objects: HashSet::new(),
        module_uncertain: HashSet::new(),
        reflect: global_reference_spans(semantic, "Reflect"),
        promise: global_reference_spans(semantic, "Promise"),
        filenames: global_reference_spans(semantic, "__filename"),
        source_cwd,
        bases: HashMap::new(),
        paths: HashMap::new(),
        properties: HashMap::new(),
        seen: HashSet::new(),
    };
    let (module_spans, module_written) = unresolved_references(semantic, "module");
    if module_written {
        sets.module_uncertain = module_spans;
    } else {
        sets.module_objects = module_spans;
    }
    seed_imports(program, semantic, &mut sets);

    let mut escaped = Vec::new();
    for _ in 0..8 {
        let mut found = Vec::new();
        let mut writes = Vec::new();
        escaped.clear();
        let mut finder = Finder {
            sets: &sets,
            semantic,
            found: &mut found,
            writes: &mut writes,
            escaped: &mut escaped,
            depth: 0,
        };
        finder.visit_program(program);
        let before = sets.loaders.len()
            + sets.bases.len()
            + sets.factories.len()
            + sets.namespaces.len()
            + sets.paths.len()
            + sets.fixed.len()
            + sets.fixed_gap.len()
            + sets.methods.len()
            + sets.forwards.len()
            + sets.properties.len();
        for (symbol, kind) in found {
            if !sets.seen.insert(symbol) || !stable(semantic.scoping(), symbol) {
                continue;
            }
            let spans = reference_spans(semantic, symbol);
            match kind {
                AliasKind::Loader => sets.loaders.extend(spans),
                AliasKind::Based(base) => {
                    for span in spans {
                        sets.loaders.insert(span);
                        sets.bases.insert(span, base.clone());
                    }
                }
                AliasKind::Factory => sets.factories.extend(spans),
                AliasKind::Namespace => sets.namespaces.extend(spans),
                AliasKind::Path(specifier) => {
                    for span in spans {
                        sets.paths.insert(span, specifier.clone());
                    }
                }
                AliasKind::Fixed(specifier) => {
                    for span in spans {
                        sets.fixed.insert(span, specifier.clone());
                    }
                }
                AliasKind::FixedUnknown => sets.fixed_gap.extend(spans),
                AliasKind::Method(method) => {
                    for span in spans {
                        sets.methods.insert(span, method);
                    }
                }
                AliasKind::Forward(source, base) => {
                    for span in spans {
                        sets.forwards.insert(span, (source.clone(), base.clone()));
                    }
                }
            }
        }
        let collected = property_slots(&writes, semantic);
        escaped.extend(collected.unstable);
        sets.properties = collected.properties;
        let after = sets.loaders.len()
            + sets.bases.len()
            + sets.factories.len()
            + sets.namespaces.len()
            + sets.paths.len()
            + sets.fixed.len()
            + sets.fixed_gap.len()
            + sets.methods.len()
            + sets.forwards.len()
            + sets.properties.len();
        if after == before {
            break;
        }
    }

    let mut loads = ModuleLoads {
        calls: HashMap::new(),
        loaded_literals: HashMap::new(),
        paths: sets.paths.clone(),
        resolves: HashMap::new(),
        binds: HashSet::new(),
        factories: HashSet::new(),
        bases: HashMap::new(),
        escapes: HashMap::new(),
        stored_gaps: escaped.into_iter().collect(),
    };
    let mut classify = Classify {
        sets: &sets,
        loads: &mut loads,
        depth: 0,
    };
    classify.visit_program(program);
    loads
}

struct Sets {
    loaders: HashSet<u32>,
    fixed: HashMap<u32, String>,
    fixed_gap: HashSet<u32>,
    methods: HashMap<u32, Method>,
    forwards: HashMap<u32, (SpecifierSource, LoadBase)>,
    factories: HashSet<u32>,
    namespaces: HashSet<u32>,
    module_objects: HashSet<u32>,
    module_uncertain: HashSet<u32>,
    reflect: HashSet<u32>,
    promise: HashSet<u32>,
    filenames: HashSet<u32>,
    source_cwd: Option<String>,
    bases: HashMap<u32, LoadBase>,
    paths: HashMap<u32, String>,
    /// Object-binding reference span and property name. A loader kept on
    /// that property, or `Uncertain` when the writes disagree.
    properties: HashMap<(u32, String), Slot>,
    seen: HashSet<SymbolId>,
}

/// A loader stored on one object property.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slot {
    Loader(LoadBase),
    /// More than one write, or a write this owner cannot name. A use is a gap.
    Uncertain,
}

enum AliasKind {
    Loader,
    Based(LoadBase),
    Factory,
    Namespace,
    Path(String),
    Fixed(String),
    FixedUnknown,
    Method(Method),
    Forward(SpecifierSource, LoadBase),
}

/// `Function.prototype.call`, `apply` or `bind`, read off a loader
/// (`const c = require.call`). What it loads depends on the receiver it is
/// later invoked on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Call,
    Apply,
    Bind,
}

impl Method {
    fn named(name: &str) -> Option<Method> {
        match name {
            "call" => Some(Method::Call),
            "apply" => Some(Method::Apply),
            "bind" => Some(Method::Bind),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Method::Call => "call",
            Method::Apply => "apply",
            Method::Bind => "bind",
        }
    }
}

/// What a loader-bearing value loads when it is called.
#[derive(Clone, Debug)]
enum Receiver {
    /// The loader itself: the first argument is the specifier.
    Loader(LoadBase),
    /// A bind that fixed this specifier, already resolved against its base.
    Fixed(String),
    /// A loader-bearing value whose module cannot be named: a bind of an
    /// unnamed specifier, or a property whose writes disagree. A call is a gap.
    Unknown,
    /// A bound `call` or `apply` (`require.call.bind(require)`): the
    /// specifier comes from this argument of the later call.
    Forward(SpecifierSource, LoadBase),
}

/// Spans of every reference to the global `require`, written or not. A write
/// to `require` can run after a call, be skipped, or leave a loader in place,
/// so literal requests through unbound references are still loads. Lexically
/// shadowed calls do not reach the loader.
pub(super) fn global_require_spans(semantic: &oxc_semantic::Semantic<'_>) -> HashSet<u32> {
    unresolved_references(semantic, "require").0
}

/// Spans of the references to `name` that no scope binds, and whether any of
/// them writes it.
fn unresolved_references(
    semantic: &oxc_semantic::Semantic<'_>,
    name: &str,
) -> (HashSet<u32>, bool) {
    let scoping = semantic.scoping();
    let Some(references) = scoping.root_unresolved_references().get(name) else {
        return (HashSet::new(), false);
    };
    let mut spans = HashSet::new();
    let mut written = false;
    for reference in references {
        let reference = scoping.get_reference(*reference);
        written |= reference.is_write();
        spans.insert(semantic.reference_span(reference).start);
    }
    (spans, written)
}

fn reference_spans(semantic: &oxc_semantic::Semantic<'_>, symbol: SymbolId) -> Vec<u32> {
    let scoping = semantic.scoping();
    scoping
        .get_resolved_reference_ids(symbol)
        .iter()
        .map(|reference| {
            semantic
                .reference_span(scoping.get_reference(*reference))
                .start
        })
        .collect()
}

fn stable(scoping: &oxc_semantic::Scoping, symbol: SymbolId) -> bool {
    scoping.symbol_flags(symbol).is_const_variable()
        || scoping
            .get_resolved_reference_ids(symbol)
            .iter()
            .all(|reference| !scoping.get_reference(*reference).is_write())
}

fn seed_imports(
    program: &oxc_ast::ast::Program<'_>,
    semantic: &oxc_semantic::Semantic<'_>,
    sets: &mut Sets,
) {
    let mut found = Vec::new();
    let mut seeder = ImportSeeder {
        found: &mut found,
        depth: 0,
    };
    seeder.visit_program(program);
    for (symbol, kind) in found {
        // An import binding cannot be assigned. Its references are the factory
        // or the namespace for the whole program.
        if !sets.seen.insert(symbol) {
            continue;
        }
        let spans = reference_spans(semantic, symbol);
        match kind {
            SeedKind::Factory => sets.factories.extend(spans),
            SeedKind::Namespace => sets.namespaces.extend(spans),
        }
    }
}

enum SeedKind {
    Factory,
    Namespace,
}

struct ImportSeeder<'s> {
    found: &'s mut Vec<(SymbolId, SeedKind)>,
    depth: u32,
}

impl<'a> Visit<'a> for ImportSeeder<'_> {
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if self.depth >= MAX_WALK_DEPTH || !is_module_builtin(it.source.value.as_str()) {
            return;
        }
        let Some(specifiers) = &it.specifiers else {
            return;
        };
        for specifier in specifiers {
            match specifier {
                ImportDeclarationSpecifier::ImportSpecifier(specifier) => {
                    if specifier.import_kind.is_value()
                        && specifier.imported.name().as_str() == "createRequire"
                        && let Some(symbol) = specifier.local.symbol_id.get()
                    {
                        self.found.push((symbol, SeedKind::Factory));
                    }
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                    if let Some(symbol) = specifier.local.symbol_id.get() {
                        self.found.push((symbol, SeedKind::Namespace));
                    }
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                    if let Some(symbol) = specifier.local.symbol_id.get() {
                        self.found.push((symbol, SeedKind::Namespace));
                    }
                }
            }
        }
    }

    fn visit_statement(&mut self, it: &oxc_ast::ast::Statement<'a>) {
        if self.depth >= MAX_WALK_DEPTH {
            return;
        }
        self.depth += 1;
        walk::walk_statement(self, it);
        self.depth -= 1;
    }
}

fn is_module_builtin(specifier: &str) -> bool {
    matches!(specifier, "module" | "node:module")
}

struct PropertyWrite {
    symbol: SymbolId,
    name: String,
    slot: Option<Slot>,
    span: (u32, u32),
}

struct Finder<'a, 's> {
    sets: &'s Sets,
    semantic: &'s oxc_semantic::Semantic<'a>,
    found: &'s mut Vec<(SymbolId, AliasKind)>,
    writes: &'s mut Vec<PropertyWrite>,
    escaped: &'s mut Vec<(u32, u32)>,
    depth: u32,
}

impl<'a> Visit<'a> for Finder<'a, '_> {
    fn visit_statement(&mut self, it: &oxc_ast::ast::Statement<'a>) {
        if self.depth >= MAX_WALK_DEPTH {
            return;
        }
        self.depth += 1;
        walk::walk_statement(self, it);
        self.depth -= 1;
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.depth >= MAX_WALK_DEPTH {
            return;
        }
        if let Expression::ObjectExpression(object) = it {
            let literal = literal_slots(object, self.sets);
            if literal.loose || (literal.open && literal.contains_loader) {
                self.escaped.push((object.span.start, object.span.end));
            }
        }
        if let Expression::ArrayExpression(array) = it
            && array_contains_loader(array, self.sets)
        {
            self.escaped.push((array.span.start, array.span.end));
        }
        self.depth += 1;
        walk::walk_expression(self, it);
        self.depth -= 1;
    }

    fn visit_assignment_expression(&mut self, it: &oxc_ast::ast::AssignmentExpression<'a>) {
        self.note_assignment(it);
        walk::walk_assignment_expression(self, it);
    }

    fn visit_return_statement(&mut self, it: &oxc_ast::ast::ReturnStatement<'a>) {
        if it
            .argument
            .as_ref()
            .is_some_and(|argument| contains_stored_loader(argument, self.sets))
        {
            self.escaped.push((it.span.start, it.span.end));
        }
        walk::walk_return_statement(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &oxc_ast::ast::VariableDeclarator<'a>) {
        let Some(init) = &it.init else {
            walk::walk_variable_declarator(self, it);
            return;
        };
        let carried = match (&it.id, sequence_callee_value(init)) {
            (BindingPattern::BindingIdentifier(id), Expression::ObjectExpression(object)) => {
                let literal = literal_slots(object, self.sets);
                if !literal.loose
                    && !literal.open
                    && let Some(symbol) = id.symbol_id.get()
                {
                    for (name, slot) in &literal.slots {
                        self.writes.push(PropertyWrite {
                            symbol,
                            name: name.clone(),
                            slot: Some(slot.clone()),
                            span: (object.span.start, object.span.end),
                        });
                    }
                    Some((object.span.start, object.span.end))
                } else {
                    None
                }
            }
            _ => None,
        };
        let first_alias = self.found.len();
        match &it.id {
            BindingPattern::BindingIdentifier(id) => {
                if let Some(symbol) = id.symbol_id.get()
                    && let Some(kind) = alias_kind(init, self.sets)
                {
                    self.found.push((symbol, kind));
                }
            }
            BindingPattern::ObjectPattern(pattern)
                if is_module_namespace_value(init, self.sets) =>
            {
                for property in &pattern.properties {
                    if property.key.static_name().as_deref() == Some("createRequire")
                        && let BindingPattern::BindingIdentifier(id) = &property.value
                        && let Some(symbol) = id.symbol_id.get()
                    {
                        self.found.push((symbol, AliasKind::Factory));
                    }
                }
            }
            BindingPattern::ObjectPattern(pattern) => {
                for property in &pattern.properties {
                    let name = property.key.static_name();
                    let Some(name) = name.as_deref() else {
                        continue;
                    };
                    let BindingPattern::BindingIdentifier(id) = &property.value else {
                        continue;
                    };
                    let Some(symbol) = id.symbol_id.get() else {
                        continue;
                    };
                    let Some(kind) = destructured_loader(init, name, self.sets) else {
                        continue;
                    };
                    self.found.push((symbol, kind));
                }
            }
            _ => {}
        }
        let aliases = &self.found[first_alias..];
        if aliases.iter().any(|(symbol, kind)| {
            !matches!(kind, AliasKind::Path(_)) && !stable(self.semantic.scoping(), *symbol)
        }) || (aliases.is_empty()
            && carried.is_none()
            && (!matches!(&it.id, BindingPattern::BindingIdentifier(_))
                || !matches!(sequence_callee_value(init), Expression::CallExpression(_)))
            && !matches!(stored_value(init, self.sets), Stored::Plain))
        {
            self.escaped.push((it.span.start, it.span.end));
        }
        // A binding of the loader does not hide nested calls in its initializer.
        walk::walk_variable_declarator(self, it);
        // The initializer's own object is carried. Nested objects stay gaps.
        if let Some(span) = carried {
            self.escaped.retain(|item| *item != span);
        }
    }
}

impl Finder<'_, '_> {
    fn note_assignment(&mut self, it: &oxc_ast::ast::AssignmentExpression<'_>) {
        let span = (it.span.start, it.span.end);
        if !it.operator.is_assign() {
            if !matches!(stored_value(&it.right, self.sets), Stored::Plain) {
                self.escaped.push(span);
            }
            return;
        }
        let Some((symbol, name)) = assigned_property(it, self.semantic) else {
            // Reassigning the global loader to itself creates no new binding.
            let keeps_require = matches!(
                (&it.left, sequence_callee_value(&it.right)),
                (oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(left),
                 Expression::Identifier(right))
                    if left.name == "require" && right.name == "require"
                        && self.sets.loaders.contains(&left.span.start)
                        && self.sets.loaders.contains(&right.span.start)
            );
            if !keeps_require && !matches!(stored_value(&it.right, self.sets), Stored::Plain) {
                self.escaped.push(span);
            }
            return;
        };
        if !stable(self.semantic.scoping(), symbol) {
            if !matches!(stored_value(&it.right, self.sets), Stored::Plain) {
                self.escaped.push(span);
            }
            return;
        }
        match stored_value(&it.right, self.sets) {
            Stored::Slot(slot) => self.writes.push(PropertyWrite {
                symbol,
                name,
                slot: Some(slot),
                span,
            }),
            Stored::Escape => {
                self.escaped.push(span);
                self.writes.push(PropertyWrite {
                    symbol,
                    name,
                    slot: None,
                    span,
                });
            }
            Stored::Plain => self.writes.push(PropertyWrite {
                symbol,
                name,
                slot: None,
                span,
            }),
        }
    }
}

struct LiteralSlots {
    open: bool,
    /// A factory, a nested container, or another value this owner does not
    /// carry. The object itself is a dependency gap.
    loose: bool,
    contains_loader: bool,
    slots: Vec<(String, Slot)>,
}

enum Stored {
    Slot(Slot),
    /// A loader-related value this owner does not carry through the write.
    Escape,
    Plain,
}

fn literal_slots(object: &oxc_ast::ast::ObjectExpression<'_>, sets: &Sets) -> LiteralSlots {
    let mut out = LiteralSlots {
        open: false,
        loose: false,
        contains_loader: false,
        slots: Vec::new(),
    };
    for property in &object.properties {
        match property {
            oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                out.open = true;
                if contains_stored_loader(&spread.argument, sets) {
                    out.contains_loader = true;
                }
            }
            oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                let Some(name) = property.key.static_name() else {
                    out.open = true;
                    if contains_stored_loader(&property.value, sets) {
                        out.contains_loader = true;
                    }
                    continue;
                };
                let name = name.to_string();
                match stored_value(&property.value, sets) {
                    Stored::Slot(slot) => {
                        out.contains_loader = true;
                        out.slots.retain(|(key, _)| key != &name);
                        out.slots.push((name, slot));
                    }
                    Stored::Escape => {
                        out.contains_loader = true;
                        out.loose = true;
                        out.slots.retain(|(key, _)| key != &name);
                    }
                    Stored::Plain => {
                        out.slots.retain(|(key, _)| key != &name);
                    }
                }
            }
        }
    }
    out
}

fn stored_value(expr: &Expression<'_>, sets: &Sets) -> Stored {
    match alias_kind(expr, sets) {
        Some(AliasKind::Loader) => Stored::Slot(Slot::Loader(LoadBase::Enclosing)),
        Some(AliasKind::Based(base)) => Stored::Slot(Slot::Loader(base)),
        Some(AliasKind::Fixed(_) | AliasKind::FixedUnknown | AliasKind::Forward(..)) => {
            Stored::Slot(Slot::Uncertain)
        }
        Some(AliasKind::Factory | AliasKind::Namespace) => Stored::Escape,
        // `Function.prototype.call` loads nothing until it is invoked on a
        // loader, and that loader is then itself an argument.
        Some(AliasKind::Path(_) | AliasKind::Method(_)) => Stored::Plain,
        None if contains_stored_loader(expr, sets) => Stored::Escape,
        None => Stored::Plain,
    }
}

fn contains_stored_loader(expr: &Expression<'_>, sets: &Sets) -> bool {
    match sequence_callee_value(expr) {
        Expression::ObjectExpression(object) => {
            let literal = literal_slots(object, sets);
            literal.contains_loader || literal.loose
        }
        Expression::ArrayExpression(array) => array_contains_loader(array, sets),
        Expression::CallExpression(call) => {
            receiver(expr, sets).is_some()
                || call.arguments.iter().any(|argument| {
                    argument
                        .as_expression()
                        .is_some_and(|expr| contains_stored_loader(expr, sets))
                })
        }
        Expression::ConditionalExpression(cond) => {
            contains_stored_loader(&cond.consequent, sets)
                || contains_stored_loader(&cond.alternate, sets)
        }
        Expression::LogicalExpression(logical) => {
            contains_stored_loader(&logical.left, sets)
                || contains_stored_loader(&logical.right, sets)
        }
        Expression::AssignmentExpression(assignment) => {
            contains_stored_loader(&assignment.right, sets)
        }
        Expression::Identifier(id)
            if sets
                .properties
                .keys()
                .any(|(span, _)| *span == id.span.start) =>
        {
            true
        }
        other => receiver(other, sets).is_some(),
    }
}

fn array_contains_loader(array: &oxc_ast::ast::ArrayExpression<'_>, sets: &Sets) -> bool {
    array.elements.iter().any(|element| match element {
        oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
            contains_stored_loader(&spread.argument, sets)
        }
        oxc_ast::ast::ArrayExpressionElement::Elision(_) => false,
        element => element
            .as_expression()
            .is_some_and(|expr| contains_stored_loader(expr, sets)),
    })
}

fn assigned_property(
    it: &oxc_ast::ast::AssignmentExpression<'_>,
    semantic: &oxc_semantic::Semantic<'_>,
) -> Option<(SymbolId, String)> {
    let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) = &it.left else {
        return None;
    };
    let Expression::Identifier(id) = sequence_callee_value(&member.object) else {
        return None;
    };
    let symbol = reference_symbol(semantic, id)?;
    Some((symbol, member.property.name.to_string()))
}

fn reference_symbol(
    semantic: &oxc_semantic::Semantic<'_>,
    id: &oxc_ast::ast::IdentifierReference<'_>,
) -> Option<SymbolId> {
    semantic
        .scoping()
        .get_reference(id.reference_id.get()?)
        .symbol_id()
}

struct CollectedProperties {
    properties: HashMap<(u32, String), Slot>,
    unstable: Vec<(u32, u32)>,
}

fn property_slots(
    writes: &[PropertyWrite],
    semantic: &oxc_semantic::Semantic<'_>,
) -> CollectedProperties {
    let mut grouped: HashMap<(SymbolId, String), Vec<&PropertyWrite>> = HashMap::new();
    for write in writes {
        grouped
            .entry((write.symbol, write.name.clone()))
            .or_default()
            .push(write);
    }
    let mut properties = HashMap::new();
    let mut unstable = Vec::new();
    for ((symbol, name), group) in grouped {
        let Some(slot) = merge_slots(group.iter().map(|write| write.slot.clone())) else {
            continue;
        };
        if !stable(semantic.scoping(), symbol) {
            unstable.extend(
                group
                    .iter()
                    .filter(|write| write.slot.is_some())
                    .map(|write| write.span),
            );
            continue;
        }
        for span in reference_spans(semantic, symbol) {
            properties.insert((span, name.clone()), slot.clone());
        }
    }
    CollectedProperties {
        properties,
        unstable,
    }
}

fn merge_slots(slots: impl Iterator<Item = Option<Slot>>) -> Option<Slot> {
    let mut loader: Option<LoadBase> = None;
    let mut saw_loader = false;
    let mut saw_clear = false;
    for slot in slots {
        match slot {
            Some(Slot::Uncertain) => return Some(Slot::Uncertain),
            Some(Slot::Loader(base)) => {
                saw_loader = true;
                match &loader {
                    None => loader = Some(base),
                    Some(existing) if existing == &base => {}
                    Some(_) => return Some(Slot::Uncertain),
                }
            }
            None => saw_clear = true,
        }
    }
    if saw_loader && saw_clear {
        return Some(Slot::Uncertain);
    }
    loader.map(Slot::Loader)
}

fn destructured_loader(init: &Expression<'_>, name: &str, sets: &Sets) -> Option<AliasKind> {
    if let Some(method) = loader_method(init, name, sets) {
        return Some(AliasKind::Method(method));
    }
    let slot = property_slot_named(init, name, sets)?;
    Some(match slot {
        Slot::Loader(LoadBase::Enclosing) => AliasKind::Loader,
        Slot::Loader(base) => AliasKind::Based(base),
        Slot::Uncertain => AliasKind::FixedUnknown,
    })
}

fn property_slot(expr: &Expression<'_>, sets: &Sets) -> Option<Slot> {
    let (object, name) = member(expr)?;
    property_slot_named(object, name?.as_str(), sets)
}

fn property_slot_named(object: &Expression<'_>, name: &str, sets: &Sets) -> Option<Slot> {
    match sequence_callee_value(object) {
        Expression::Identifier(id) => sets
            .properties
            .get(&(id.span.start, name.to_string()))
            .cloned(),
        Expression::ObjectExpression(object) => {
            let literal = literal_slots(object, sets);
            if literal.open || literal.loose {
                return (literal.contains_loader || literal.loose).then_some(Slot::Uncertain);
            }
            literal
                .slots
                .into_iter()
                .find(|(key, _)| key == name)
                .map(|(_, slot)| slot)
        }
        _ => None,
    }
}

fn alias_kind(init: &Expression<'_>, sets: &Sets) -> Option<AliasKind> {
    // `module` was written, so `module.require` may not be the loader. A
    // binding of it fails closed on every call.
    if uncertain_module_require(init, sets) {
        return Some(AliasKind::FixedUnknown);
    }
    if let Some(receiver) = receiver(init, sets) {
        return Some(match receiver {
            Receiver::Loader(LoadBase::Enclosing) => AliasKind::Loader,
            Receiver::Loader(base) => AliasKind::Based(base),
            Receiver::Fixed(specifier) => AliasKind::Fixed(specifier),
            Receiver::Unknown => AliasKind::FixedUnknown,
            Receiver::Forward(source, base) => AliasKind::Forward(source, base),
        });
    }
    if is_factory_value(init, sets) {
        return Some(AliasKind::Factory);
    }
    if is_module_namespace_value(init, sets) {
        return Some(AliasKind::Namespace);
    }
    if let Expression::Identifier(id) = sequence_callee_value(init)
        && let Some(specifier) = sets.paths.get(&id.span.start)
    {
        return Some(AliasKind::Path(specifier.clone()));
    }
    if let Some(method) = method_value(init, sets) {
        return Some(AliasKind::Method(method));
    }
    let Expression::CallExpression(call) = sequence_callee_value(init) else {
        return None;
    };
    resolve_specifier(call, sets).map(AliasKind::Path)
}

/// The loader-bearing value this expression evaluates to. Every way of
/// invoking a loader, passing it on or binding it asks this one question, so
/// a value's specifier and its uncertainty reach every use.
fn receiver(expr: &Expression<'_>, sets: &Sets) -> Option<Receiver> {
    match property_slot(expr, sets) {
        Some(Slot::Loader(base)) => return Some(Receiver::Loader(base)),
        Some(Slot::Uncertain) => return Some(Receiver::Unknown),
        None => {}
    }
    match sequence_callee_value(expr) {
        Expression::Identifier(id) => {
            let span = id.span.start;
            if let Some(specifier) = sets.fixed.get(&span) {
                Some(Receiver::Fixed(specifier.clone()))
            } else if sets.fixed_gap.contains(&span) {
                Some(Receiver::Unknown)
            } else if let Some((source, base)) = sets.forwards.get(&span) {
                Some(Receiver::Forward(source.clone(), base.clone()))
            } else if let Some(base) = sets.bases.get(&span) {
                Some(Receiver::Loader(base.clone()))
            } else if sets.loaders.contains(&span) {
                Some(Receiver::Loader(LoadBase::Enclosing))
            } else {
                None
            }
        }
        Expression::CallExpression(call) if is_create_require_call(call, sets) => {
            Some(Receiver::Loader(create_require_base(call, sets)))
        }
        Expression::CallExpression(call) => bind_result(call, sets),
        other if module_require_function(other, sets) => {
            Some(Receiver::Loader(LoadBase::Enclosing))
        }
        _ => None,
    }
}

/// `require.call` and the like, or a binding of one.
fn method_value(expr: &Expression<'_>, sets: &Sets) -> Option<Method> {
    match sequence_callee_value(expr) {
        Expression::Identifier(id) => sets.methods.get(&id.span.start).copied(),
        other => {
            let (object, name) = member(other)?;
            loader_method(object, name?.as_str(), sets)
        }
    }
}

/// A loader's own `call`, `apply` or `bind`. A property whose writes
/// disagree may not hold a function, so its method is not named; a loader
/// invoked through it is then an argument, which records a gap.
fn loader_method(object: &Expression<'_>, name: &str, sets: &Sets) -> Option<Method> {
    match receiver(object, sets)? {
        Receiver::Unknown => None,
        _ => Method::named(name),
    }
}

fn module_require_function(expr: &Expression<'_>, sets: &Sets) -> bool {
    let Some((object, name)) = member(expr) else {
        return false;
    };
    name.as_deref() == Some("require") && is_module_object(object, sets)
}

fn is_module_object(expr: &Expression<'_>, sets: &Sets) -> bool {
    matches!(sequence_callee_value(expr), Expression::Identifier(id)
        if sets.module_objects.contains(&id.span.start))
}

fn is_factory_value(expr: &Expression<'_>, sets: &Sets) -> bool {
    match sequence_callee_value(expr) {
        Expression::Identifier(id) => sets.factories.contains(&id.span.start),
        other => {
            let Some((object, name)) = member(other) else {
                return false;
            };
            // `module.createRequire` is the CommonJS factory; an import of
            // the builtin `module` module exposes the same function.
            name.as_deref() == Some("createRequire")
                && (is_module_namespace_value(object, sets) || is_module_object(object, sets))
        }
    }
}

fn is_module_namespace_value(expr: &Expression<'_>, sets: &Sets) -> bool {
    match sequence_callee_value(expr) {
        Expression::Identifier(id) => sets.namespaces.contains(&id.span.start),
        Expression::CallExpression(call) => module_builtin_call(call, sets),
        other => resolve::dynamic_import_module(other).as_deref() == Some("module"),
    }
}

fn module_builtin_call(call: &CallExpression<'_>, sets: &Sets) -> bool {
    let Expression::Identifier(id) = sequence_callee_value(&call.callee) else {
        return false;
    };
    if !sets.loaders.contains(&id.span.start) {
        return false;
    }
    literal_specifier(call, 0, sets).is_some_and(|specifier| is_module_builtin(&specifier))
}

fn is_create_require_call(call: &CallExpression<'_>, sets: &Sets) -> bool {
    is_factory_value(&call.callee, sets)
}

fn uncertain_module_require(expr: &Expression<'_>, sets: &Sets) -> bool {
    let Some((object, name)) = member(expr) else {
        return false;
    };
    name.as_deref() == Some("require") && is_uncertain_module(object, sets)
}

/// The function a bind of a loader-bearing value returns.
fn bind_result(call: &CallExpression<'_>, sets: &Sets) -> Option<Receiver> {
    let (object, name) = member(&call.callee)?;
    match (name.as_deref(), method_value(object, sets)) {
        // `require.call.bind(require)`: the method is bound to the loader.
        (Some("bind"), Some(method)) => {
            let (target, _) = logical_call_argument(&call.arguments, 0)?;
            Some(bound_method(method, receiver(target?, sets)?, call, sets))
        }
        (Some("bind"), None) => Some(bind_of(receiver(object, sets)?, call, 0, sets)),
        // `bind.call(require, null)` is `require.bind(null)`.
        (Some("call"), Some(Method::Bind)) => {
            let (target, _) = logical_call_argument(&call.arguments, 0)?;
            Some(bind_of(receiver(target?, sets)?, call, 1, sets))
        }
        _ => None,
    }
}

/// `receiver.bind(this, ...)`, whose arguments start at logical argument
/// `first` of `call`. A bind of the receiver alone forwards the later call's
/// first argument. A bound specifier is loaded from the receiver's base when
/// it is relative. A further bind keeps the specifier an earlier bind fixed:
/// `require.bind(null, './file.js').bind(null)()` still loads that file.
fn bind_of(receiver: Receiver, call: &CallExpression<'_>, first: usize, sets: &Sets) -> Receiver {
    match receiver {
        Receiver::Loader(base) => match logical_call_argument(&call.arguments, first + 1) {
            None => Receiver::Loader(base),
            Some((Some(argument), _)) => literal_expr(argument, sets)
                .and_then(|specifier| rebase_specifier(Some(&base), Some(specifier)))
                .map_or(Receiver::Unknown, Receiver::Fixed),
            Some((None, _)) => Receiver::Unknown,
        },
        Receiver::Fixed(specifier) => Receiver::Fixed(specifier),
        // A bound `call` bound again shifts its arguments. This owner does
        // not follow that, so the later call is a gap.
        Receiver::Unknown | Receiver::Forward(..) => Receiver::Unknown,
    }
}

/// `method.bind(receiver, ...)`. A bound `call` is `receiver.bind(...)` once
/// it binds a `this` too. Bound to the receiver alone, `call` and `apply`
/// read the specifier from the later call's second argument.
fn bound_method(
    method: Method,
    receiver: Receiver,
    call: &CallExpression<'_>,
    sets: &Sets,
) -> Receiver {
    let receiver_only = logical_call_argument(&call.arguments, 1).is_none();
    match (method, receiver) {
        (Method::Call, receiver) if !receiver_only => bind_of(receiver, call, 1, sets),
        (Method::Call, Receiver::Loader(base)) => {
            Receiver::Forward(SpecifierSource::Argument(1), base)
        }
        (Method::Apply, Receiver::Loader(base)) if receiver_only => {
            Receiver::Forward(SpecifierSource::Apply(1), base)
        }
        (Method::Call | Method::Apply, Receiver::Fixed(specifier)) => Receiver::Fixed(specifier),
        _ => Receiver::Unknown,
    }
}

fn resolve_specifier(call: &CallExpression<'_>, sets: &Sets) -> Option<String> {
    let (object, name) = member(&call.callee)?;
    // Options can redirect the lookup to a different directory.
    if name.as_deref() != Some("resolve") || logical_call_argument_count(&call.arguments) != Some(1)
    {
        return None;
    }
    let base = load_base(object, sets)?;
    let specifier = literal_specifier(call, 0, sets)?;
    // The result belongs to the resolving loader's directory. Passing on a
    // relative spelling would make another loader search its own directory.
    if base == LoadBase::Enclosing && is_relative_specifier(&specifier) {
        let dir = sets
            .source_cwd
            .as_deref()
            .filter(|dir| dir.starts_with('/'))?;
        return Some(crate::paths::join_cwd(dir, &specifier));
    }
    rebase_specifier(Some(&base), Some(specifier))
}

fn literal_specifier(call: &CallExpression<'_>, index: usize, sets: &Sets) -> Option<String> {
    let (argument, _) = logical_call_argument(&call.arguments, index)?;
    literal_expr(argument?, sets)
}

fn literal_expr(expr: &Expression<'_>, sets: &Sets) -> Option<String> {
    match sequence_callee_value(expr) {
        Expression::Identifier(id) => sets.paths.get(&id.span.start).cloned(),
        Expression::CallExpression(call) => resolve_specifier(call, sets),
        other => literal_text(other),
    }
}

fn literal_text(expr: &Expression<'_>) -> Option<String> {
    match sequence_callee_value(expr) {
        Expression::StringLiteral(literal) => Some(literal.value.to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            resolve::cooked_template_string(template)
        }
        _ => None,
    }
}

fn member<'a>(expr: &'a Expression<'a>) -> Option<(&'a Expression<'a>, Option<String>)> {
    let member = sequence_callee_value(expr).get_member_expr()?;
    let name = member
        .static_property_name()
        .map(str::to_string)
        .or_else(|| match member {
            oxc_ast::ast::MemberExpression::ComputedMemberExpression(computed) => {
                template_property(&computed.expression)
            }
            _ => None,
        });
    Some((member.object(), name))
}

fn template_property(expr: &Expression<'_>) -> Option<String> {
    match unparen(expr) {
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            resolve::cooked_template_string(template)
        }
        _ => None,
    }
}

struct Classify<'a, 's> {
    sets: &'s Sets,
    loads: &'a mut ModuleLoads,
    depth: u32,
}

impl<'a> Visit<'a> for Classify<'_, '_> {
    fn visit_statement(&mut self, it: &oxc_ast::ast::Statement<'a>) {
        if self.depth >= MAX_WALK_DEPTH {
            return;
        }
        self.depth += 1;
        walk::walk_statement(self, it);
        self.depth -= 1;
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.depth >= MAX_WALK_DEPTH {
            return;
        }
        self.depth += 1;
        walk::walk_expression(self, it);
        self.depth -= 1;
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if self.depth >= MAX_WALK_DEPTH {
            return;
        }
        // `visit_expression` already counts this call. Counting it again
        // would stop classifying a `require` the effect walk still enters.
        walk::walk_call_expression(self, it);
        let key = (it.span.start, it.span.end);
        if is_create_require_call(it, self.sets) {
            self.loads.factories.insert(key);
        }
        if let Some(specifier) = resolve_specifier(it, self.sets) {
            self.loads.resolves.insert(key, specifier);
        }
        if bind_result(it, self.sets).is_some() {
            self.loads.binds.insert(key);
        }
        if let Some(escape) = loader_escape(it, self.sets) {
            self.loads.escapes.insert(key, escape);
        }
        let Some((source, base)) = classify_call(it, self.sets) else {
            return;
        };
        if !matches!(base, LoadBase::Enclosing) {
            self.loads.bases.insert(key, base);
        }
        if let Some(specifier) = named_specifier(it, &source, self.sets) {
            self.loads
                .loaded_literals
                .insert(key, resolve::canonical_module(&specifier));
        }
        self.loads.calls.insert(key, source);
    }
}

fn named_specifier(
    call: &CallExpression<'_>,
    source: &SpecifierSource,
    sets: &Sets,
) -> Option<String> {
    match source {
        SpecifierSource::Known(specifier) => Some(specifier.clone()),
        SpecifierSource::Gap => None,
        SpecifierSource::Argument(index) => literal_specifier(call, *index, sets),
        SpecifierSource::Apply(index) => {
            let (argument, _) = logical_call_argument(&call.arguments, *index)?;
            let element = array_first(argument?)?;
            literal_expr(element, sets)
        }
    }
}

fn array_first<'a>(expr: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    array_element(expr, 0)
}

/// Classify one call, and the base its relative specifier resolves from. A
/// method of the loader that is not `call`, `apply`, `bind`, or `resolve` is
/// a gap: an unrecognized loader use never falls through to full coverage.
fn classify_call(call: &CallExpression<'_>, sets: &Sets) -> Option<(SpecifierSource, LoadBase)> {
    let callee = sequence_callee_value(&call.callee);
    if let Some(receiver) = receiver(callee, sets) {
        return Some(match receiver {
            Receiver::Loader(base) => (SpecifierSource::Argument(0), base),
            Receiver::Fixed(specifier) => (SpecifierSource::Known(specifier), LoadBase::Enclosing),
            Receiver::Unknown => (SpecifierSource::Gap, LoadBase::Enclosing),
            Receiver::Forward(source, base) => (source, base),
        });
    }
    let (object, name) = member(callee)?;
    // `Reflect.apply(loader, this, args)` is `loader.apply(this, args)`, and
    // `call.call(loader, this, specifier)` is `loader.call(this, specifier)`.
    let method = match (name.as_deref(), sequence_callee_value(object)) {
        (Some("apply"), Expression::Identifier(id)) if sets.reflect.contains(&id.span.start) => {
            Some(Method::Apply)
        }
        (Some("call"), object) => method_value(object, sets),
        _ => None,
    };
    if let Some(method) = method {
        let (target, _) = logical_call_argument(&call.arguments, 0)?;
        return method_load(receiver(target?, sets)?, Some(method.name()), 1);
    }
    if let Some(receiver) = receiver(object, sets) {
        return method_load(receiver, name.as_deref(), 0);
    }
    if name.as_deref() == Some("require") && is_uncertain_module(object, sets) {
        return Some((SpecifierSource::Gap, LoadBase::Enclosing));
    }
    None
}

/// `receiver.name(...)`, whose own arguments start at logical argument
/// `first`.
fn method_load(
    receiver: Receiver,
    name: Option<&str>,
    first: usize,
) -> Option<(SpecifierSource, LoadBase)> {
    Some(match (receiver, name) {
        // `bind` and `resolve` produce a function or a path. The load is the
        // later call, classified from that result.
        (_, Some("bind")) | (Receiver::Loader(_), Some("resolve")) => return None,
        (Receiver::Loader(base), Some("call")) => (SpecifierSource::Argument(first + 1), base),
        (Receiver::Loader(base), Some("apply")) => (SpecifierSource::Apply(first + 1), base),
        (Receiver::Fixed(specifier), Some("call" | "apply")) => {
            (SpecifierSource::Known(specifier), LoadBase::Enclosing)
        }
        // Any other call on the loader, and any call through a value whose
        // module is not named, is a use this owner does not name.
        _ => (SpecifierSource::Gap, LoadBase::Enclosing),
    })
}

fn is_uncertain_module(expr: &Expression<'_>, sets: &Sets) -> bool {
    matches!(sequence_callee_value(expr), Expression::Identifier(id)
        if sets.module_uncertain.contains(&id.span.start))
}

/// The resolution base of a loader expression, when it is a loader.
fn load_base(expr: &Expression<'_>, sets: &Sets) -> Option<LoadBase> {
    match receiver(expr, sets)? {
        Receiver::Loader(base) => Some(base),
        _ => None,
    }
}

fn create_require_base(call: &CallExpression<'_>, sets: &Sets) -> LoadBase {
    let Some((Some(argument), _)) = logical_call_argument(&call.arguments, 0) else {
        return LoadBase::Unknown;
    };
    if enclosing_module_filename(argument, sets) {
        return LoadBase::Enclosing;
    }
    // A require.resolve result is a lookup request until the module is read.
    // Its spelling alone does not establish the new loader's directory.
    let Some(specifier) = literal_text(argument) else {
        return LoadBase::Unknown;
    };
    if let Some(path) = file_url_path(&specifier) {
        return LoadBase::Dir(crate::paths::parent_dir(&path));
    }
    if specifier.starts_with('/') {
        return LoadBase::Dir(crate::paths::parent_dir(&specifier));
    }
    // A relative string is not a filename `createRequire` accepts.
    LoadBase::Unknown
}

fn enclosing_module_filename(expr: &Expression<'_>, sets: &Sets) -> bool {
    match sequence_callee_value(expr) {
        // `import.meta.url` is the enclosing module. `import.meta` itself is
        // the meta object, which `createRequire` does not accept as a filename.
        Expression::StaticMemberExpression(member) => {
            member.property.name == "url" && is_import_meta(&member.object)
        }
        Expression::Identifier(id) => {
            id.name == "__filename" && sets.filenames.contains(&id.span.start)
        }
        _ => false,
    }
}

fn is_import_meta(expr: &Expression<'_>) -> bool {
    let Expression::MetaProperty(meta) = sequence_callee_value(expr) else {
        return false;
    };
    meta.meta.name == "import" && meta.property.name == "meta"
}

fn file_url_path(specifier: &str) -> Option<String> {
    let rest = specifier.strip_prefix("file://")?;
    // A query or fragment is not a path this owner can separate from the file.
    if rest.contains('?') || rest.contains('#') {
        return None;
    }
    let path = rest.strip_prefix("localhost").unwrap_or(rest);
    if !path.starts_with('/') {
        return None;
    }
    // Node's fileURLToPath percent-decodes the path and rejects an encoded
    // slash or backslash. Keeping the escapes would follow a different file.
    decode_file_url_path(path)
}

fn decode_file_url_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return None;
        }
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = hex(bytes[index + 1])?;
        let low = hex(bytes[index + 2])?;
        let byte = high * 16 + low;
        if byte == b'/' || byte == b'\\' {
            return None;
        }
        decoded.push(byte);
        index += 3;
    }
    let path = String::from_utf8(decoded).ok()?;
    path.starts_with('/').then_some(path)
}

fn is_relative_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../")
}

fn is_absolute_specifier(specifier: &str) -> bool {
    specifier.starts_with('/')
}

fn rebase_specifier(base: Option<&LoadBase>, specifier: Option<String>) -> Option<String> {
    let specifier = specifier?;
    match base {
        None | Some(LoadBase::Enclosing) => Some(specifier),
        Some(LoadBase::Dir(dir)) if is_relative_specifier(&specifier) => {
            Some(crate::paths::join_cwd(dir, &specifier))
        }
        Some(LoadBase::Dir(_)) => Some(specifier),
        Some(LoadBase::Unknown) if is_absolute_specifier(&specifier) => Some(specifier),
        Some(LoadBase::Unknown) => None,
    }
}

/// A loader value passed as an argument. The call itself being the load, or
/// a bind of it, is not an escape. A fulfilled
/// `Promise.resolve(specifier).then(loader)` names the module; every other
/// escape is a dependency gap.
fn loader_escape(call: &CallExpression<'_>, sets: &Sets) -> Option<LoaderEscape> {
    if classify_call(call, sets).is_some() || bind_result(call, sets).is_some() {
        return None;
    }
    let loader = call
        .arguments
        .iter()
        .enumerate()
        .find_map(|(index, argument)| Some((index, receiver(argument.as_expression()?, sets)?)));
    if let Some((index, loader)) = loader {
        // Only the first `then` callback runs on fulfilment.
        let resolve = promise_resolve_then(call, sets).filter(|_| index == 0);
        return Some(match (loader, resolve) {
            (Receiver::Loader(base), Some(resolve)) => literal_specifier(resolve, 0, sets)
                .and_then(|specifier| rebase_specifier(Some(&base), Some(specifier)))
                .map_or(LoaderEscape::Gap, LoaderEscape::Follow),
            // A fixed bind ignores the value. The promise fulfils when the
            // value is absent or a literal string.
            (Receiver::Fixed(specifier), Some(resolve))
                if logical_call_argument_count(&resolve.arguments) == Some(0)
                    || literal_specifier(resolve, 0, sets).is_some() =>
            {
                LoaderEscape::Follow(specifier)
            }
            _ => LoaderEscape::Gap,
        });
    }
    // `{ load: require }` passed into a call, or an object that holds one.
    // The loader leaves this owner without a name.
    let buried = call.arguments.iter().any(|argument| {
        argument
            .as_expression()
            .is_some_and(|expr| contains_stored_loader(expr, sets))
    });
    buried.then_some(LoaderEscape::Gap)
}

/// The `Promise.resolve(...)` call of `Promise.resolve(...).then(...)`.
fn promise_resolve_then<'a>(
    call: &'a CallExpression<'a>,
    sets: &Sets,
) -> Option<&'a CallExpression<'a>> {
    let (object, name) = member(&call.callee)?;
    if name.as_deref() != Some("then") {
        return None;
    }
    let Expression::CallExpression(resolve) = sequence_callee_value(object) else {
        return None;
    };
    let (receiver, method) = member(&resolve.callee)?;
    if method.as_deref() != Some("resolve") {
        return None;
    }
    let Expression::Identifier(id) = sequence_callee_value(receiver) else {
        return None;
    };
    sets.promise.contains(&id.span.start).then_some(resolve)
}

/// An import-equals declaration names a module when it uses `require`.
pub(super) fn import_equals_specifier<'a>(
    decl: &'a oxc_ast::ast::TSImportEqualsDeclaration<'a>,
) -> Option<&'a str> {
    match &decl.module_reference {
        oxc_ast::ast::TSModuleReference::ExternalModuleReference(external) => {
            Some(external.expression.value.as_str())
        }
        _ => None,
    }
}
