//! The runtime's own `console`: the references that reach it, the bindings
//! that may hold one of its methods, the places it escapes as a value, and
//! the function values that provably print nothing.

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
    CallExpression, Class, ComputedMemberExpression, Expression, ExpressionStatement, Function,
    FunctionBody, IdentifierReference, NewExpression, Statement, StaticMemberExpression,
    TaggedTemplateExpression, VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};

use super::{global_reference_spans, unparen};
use crate::lang::frontend::MAX_WALK_DEPTH;

/// The `console` methods that write to stdout before any assignment.
pub(super) const STDOUT_METHODS: [&str; 3] = ["log", "info", "debug"];

/// Alias discovery repeats to follow chains such as `const d = c`; a longer
/// chain is simply not followed.
const MAX_ALIAS_ROUNDS: usize = 8;

#[derive(Default)]
pub(super) struct ConsoleAliases {
    /// Spans of the references that reach the runtime's own `console`: ones
    /// no enclosing scope binds, and those of a `const` bound to it, directly
    /// or through another such `const`, whatever it is named.
    objects: HashSet<u32>,
    /// Spans of the `console` references no enclosing scope binds.
    globals: HashSet<u32>,
    /// Spans of the references that reach the runtime's own `globalThis`.
    global_this: HashSet<u32>,
    /// Bindings whose initializer reads the console or another such
    /// binding, so they may hold one of its methods, by the span start of
    /// the bound name.
    pub(super) bindings: HashMap<u32, oxc_semantic::SymbolId>,
    /// Span starts of every reference to those bindings, writes included.
    pub(super) references: HashMap<u32, oxc_semantic::SymbolId>,
    /// Span starts of the references to never reassigned function
    /// declarations and `const` bindings whose function does nothing (see
    /// [`ConsoleAliases::silent_function`]).
    pub(super) silent: HashSet<u32>,
    /// Span starts of the references where the console or `globalThis` is
    /// used as a value other than the object of a member access, the
    /// initializer of a `const` alias, or the argument of a call that only
    /// inspects it, where code Nah does not follow may rewrite its methods.
    pub(super) escapes: HashSet<u32>,
    /// Spans of the references that reach the runtime's own `Object`.
    object_globals: HashSet<u32>,
}

impl ConsoleAliases {
    /// Whether `expression` is the runtime's console object: a reference
    /// that reaches it, or `globalThis.console`.
    pub(super) fn is_console(&self, expression: &Expression<'_>) -> bool {
        match unparen(expression) {
            Expression::Identifier(id) => self.objects.contains(&id.span.start),
            Expression::StaticMemberExpression(member) => {
                member.property.name == "console" && self.is_global_this(&member.object)
            }
            Expression::ComputedMemberExpression(member) => {
                matches!(&member.expression, Expression::StringLiteral(name) if name.value == "console")
                    && self.is_global_this(&member.object)
            }
            _ => false,
        }
    }

    /// Whether `expression` names the runtime console as `console` with no
    /// enclosing binding, the one spelling through which an assignment
    /// counts as silencing a method, as code Nah does not follow (a module
    /// it loads, an `eval`) could undo a write made through any other.
    pub(super) fn is_global_console(&self, expression: &Expression<'_>) -> bool {
        matches!(unparen(expression), Expression::Identifier(id)
            if self.globals.contains(&id.span.start))
    }

    /// A function value that cannot write to stdout when called: a function
    /// or arrow literal whose body acts only by calls that cannot (see
    /// [`Self::inert_call`]).
    pub(super) fn silent_function(&self, expression: &Expression<'_>) -> bool {
        match unparen(expression) {
            Expression::ArrowFunctionExpression(function) => self.silent_body(&function.body),
            Expression::FunctionExpression(function) => function
                .body
                .as_ref()
                .is_some_and(|body| self.silent_body(body)),
            _ => false,
        }
    }

    /// A function body that constructs and assigns nothing and whose calls
    /// are all [`Self::inert_call`]s.
    fn silent_body(&self, body: &FunctionBody<'_>) -> bool {
        struct Acts<'a> {
            aliases: &'a ConsoleAliases,
            hit: bool,
        }
        impl<'a> Visit<'a> for Acts<'_> {
            fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
                if self.aliases.inert_call(it) {
                    for argument in &it.arguments {
                        self.visit_argument(argument);
                    }
                } else {
                    self.hit = true;
                }
            }
            fn visit_new_expression(&mut self, _it: &NewExpression<'a>) {
                self.hit = true;
            }
            fn visit_tagged_template_expression(&mut self, _it: &TaggedTemplateExpression<'a>) {
                self.hit = true;
            }
            fn visit_expression(&mut self, it: &Expression<'a>) {
                if matches!(
                    it,
                    Expression::AssignmentExpression(_)
                        | Expression::UpdateExpression(_)
                        | Expression::ImportExpression(_)
                        | Expression::AwaitExpression(_)
                        | Expression::YieldExpression(_)
                ) {
                    self.hit = true;
                } else {
                    walk::walk_expression(self, it);
                }
            }
        }
        let mut acts = Acts {
            aliases: self,
            hit: false,
        };
        acts.visit_function_body(body);
        !acts.hit
    }

    /// A call that writes nothing and changes no console method:
    /// `Object.keys`, `values` or `entries`. Any write, even to a file,
    /// may reach stdout through a path Nah does not resolve.
    fn inert_call(&self, call: &CallExpression<'_>) -> bool {
        matches!(unparen(&call.callee), Expression::StaticMemberExpression(callee)
            if matches!(unparen(&callee.object), Expression::Identifier(id)
                if self.object_globals.contains(&id.span.start))
                && matches!(callee.property.name.as_str(), "keys" | "values" | "entries"))
    }

    fn is_global_this(&self, expression: &Expression<'_>) -> bool {
        matches!(unparen(expression), Expression::Identifier(id)
            if self.global_this.contains(&id.span.start))
    }

    /// The method a member access reads from the runtime's console:
    /// `console.log` or `console["log"]`.
    pub(super) fn method<'e>(&self, expression: &'e Expression<'_>) -> Option<&'e str> {
        match unparen(expression) {
            Expression::StaticMemberExpression(member) if self.is_console(&member.object) => {
                Some(member.property.name.as_str())
            }
            Expression::ComputedMemberExpression(member) if self.is_console(&member.object) => {
                match &member.expression {
                    Expression::StringLiteral(name) => Some(name.value.as_str()),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

pub(super) fn console_aliases(
    program: &oxc_ast::ast::Program<'_>,
    semantic: &oxc_semantic::Semantic<'_>,
) -> ConsoleAliases {
    let scoping = semantic.scoping();
    let references_of = |symbol| {
        scoping
            .get_resolved_reference_ids(symbol)
            .iter()
            .map(|reference| {
                semantic
                    .reference_span(scoping.get_reference(*reference))
                    .start
            })
            .collect::<Vec<_>>()
    };
    let globals = global_reference_spans(semantic, "console");
    let mut aliases = ConsoleAliases {
        objects: globals.clone(),
        globals,
        global_this: global_reference_spans(semantic, "globalThis"),
        object_globals: global_reference_spans(semantic, "Object"),
        ..ConsoleAliases::default()
    };
    for _ in 0..MAX_ALIAS_ROUNDS {
        let mut objects = Collect::new(&aliases, scoping, Find::Objects);
        objects.visit_program(program);
        let before = aliases.objects.len();
        for (_, symbol) in objects.found {
            if scoping.symbol_flags(symbol).is_const_variable() {
                aliases.objects.extend(references_of(symbol));
            }
        }
        if aliases.objects.len() == before {
            break;
        }
    }
    for _ in 0..MAX_ALIAS_ROUNDS {
        let mut bindings = Collect::new(&aliases, scoping, Find::Methods);
        bindings.visit_program(program);
        let before = aliases.bindings.len();
        for (span, symbol) in bindings.found {
            if aliases.bindings.insert(span, symbol).is_none() {
                for reference in references_of(symbol) {
                    aliases.references.insert(reference, symbol);
                }
            }
        }
        if aliases.bindings.len() == before {
            break;
        }
    }
    let mut silent = SilentBindings {
        aliases: &aliases,
        found: Vec::new(),
    };
    silent.visit_program(program);
    let silent = silent.found;
    for symbol in silent {
        let references = scoping
            .get_resolved_reference_ids(symbol)
            .iter()
            .map(|reference| scoping.get_reference(*reference))
            .collect::<Vec<_>>();
        if references.iter().all(|reference| !reference.is_write()) {
            aliases.silent.extend(
                references
                    .into_iter()
                    .map(|reference| semantic.reference_span(reference).start),
            );
        }
    }
    let mut escapes = Collect::new(&aliases, scoping, Find::Escapes);
    escapes.visit_program(program);
    aliases.escapes = escapes.escapes;
    aliases
}

/// Function declarations and `const` bindings whose function does nothing.
struct SilentBindings<'a> {
    aliases: &'a ConsoleAliases,
    found: Vec<oxc_semantic::SymbolId>,
}

impl<'a> Visit<'a> for SilentBindings<'_> {
    fn visit_function(&mut self, it: &Function<'a>, flags: oxc_semantic::ScopeFlags) {
        if let (Some(id), Some(body)) = (&it.id, &it.body)
            && it.is_declaration()
            && self.aliases.silent_body(body)
            && let Some(symbol) = id.symbol_id.get()
        {
            self.found.push(symbol);
        }
        walk::walk_function(self, it, flags);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if it.kind == VariableDeclarationKind::Const
            && let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init)
            && self.aliases.silent_function(init)
            && let Some(symbol) = id.symbol_id.get()
        {
            self.found.push(symbol);
        }
        walk::walk_variable_declarator(self, it);
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Find {
    /// `const` bindings initialized to the console object.
    Objects,
    /// Bindings initialized or assigned from the console or another found
    /// binding.
    Methods,
    /// Uses of the console or `globalThis` as a value.
    Escapes,
}

struct Collect<'c> {
    aliases: &'c ConsoleAliases,
    scoping: &'c oxc_semantic::Scoping,
    find: Find,
    found: Vec<(u32, oxc_semantic::SymbolId)>,
    escapes: HashSet<u32>,
    /// The span start of the call an expression statement discards.
    discarded: Option<u32>,
    depth: u32,
}

impl<'c> Collect<'c> {
    fn new(aliases: &'c ConsoleAliases, scoping: &'c oxc_semantic::Scoping, find: Find) -> Self {
        Self {
            aliases,
            scoping,
            find,
            found: Vec::new(),
            escapes: HashSet::new(),
            discarded: None,
            depth: 0,
        }
    }

    /// Whether `expression` reads the console, `globalThis`, or a binding
    /// found so far, outside the functions and classes it defines.
    fn reads_console(&self, expression: &Expression<'_>) -> bool {
        struct Reads<'r> {
            aliases: &'r ConsoleAliases,
            hit: bool,
        }
        impl<'a> Visit<'a> for Reads<'_> {
            fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
                let span = it.span.start;
                self.hit |= self.aliases.objects.contains(&span)
                    || self.aliases.global_this.contains(&span)
                    || self.aliases.references.contains_key(&span);
            }
            fn visit_function(&mut self, _it: &Function<'a>, _flags: oxc_semantic::ScopeFlags) {}
            fn visit_arrow_function_expression(&mut self, _it: &ArrowFunctionExpression<'a>) {}
            fn visit_class(&mut self, _it: &Class<'a>) {}
        }
        let mut reads = Reads {
            aliases: self.aliases,
            hit: false,
        };
        reads.visit_expression(expression);
        reads.hit
    }
}

impl<'a> Visit<'a> for Collect<'_> {
    fn visit_statement(&mut self, it: &Statement<'a>) {
        // Past the depth limit an alias or escape is simply not recognized.
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

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        let Some(init) = &it.init else {
            walk::walk_variable_declarator(self, it);
            return;
        };
        let console = self.aliases.is_console(init);
        match (&it.id, self.find) {
            (BindingPattern::BindingIdentifier(alias), Find::Objects) => {
                if console && let Some(symbol) = alias.symbol_id.get() {
                    self.found.push((alias.span.start, symbol));
                }
            }
            (BindingPattern::BindingIdentifier(alias), Find::Methods) => {
                if self.reads_console(init)
                    && let Some(symbol) = alias.symbol_id.get()
                {
                    self.found.push((alias.span.start, symbol));
                }
            }
            (BindingPattern::ObjectPattern(pattern), Find::Methods) if console => {
                for property in &pattern.properties {
                    if let BindingPattern::BindingIdentifier(alias) = &property.value
                        && let Some(symbol) = alias.symbol_id.get()
                    {
                        self.found.push((alias.span.start, symbol));
                    }
                }
            }
            _ => {}
        }
        // A `const` alias of the console or a destructuring read of its
        // methods does not let the console escape.
        let alias = it.kind == VariableDeclarationKind::Const
            && matches!(it.id, BindingPattern::BindingIdentifier(_));
        let destructured = matches!(it.id, BindingPattern::ObjectPattern(_));
        if console && (alias || destructured) {
            self.visit_binding_pattern(&it.id);
        } else {
            walk::walk_variable_declarator(self, it);
        }
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        if let Expression::CallExpression(call) = unparen(&it.expression) {
            self.discarded = Some(call.span.start);
        }
        walk::walk_expression_statement(self, it);
    }

    // The console passed to a call that only inspects it, to a silent
    // function whose result is discarded, or as a console method's `.bind`
    // receiver does not escape.
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let inspects = self.aliases.inert_call(it)
            || (self.discarded == Some(it.span.start)
                && matches!(unparen(&it.callee), Expression::Identifier(id)
                    if self.aliases.silent.contains(&id.span.start)))
            || matches!(unparen(&it.callee), Expression::StaticMemberExpression(member)
                if member.property.name == "bind"
                    && (self.aliases.method(&member.object).is_some()
                        || matches!(unparen(&member.object), Expression::Identifier(id)
                            if self.aliases.references.contains_key(&id.span.start))));
        if self.find != Find::Escapes || !inspects {
            walk::walk_call_expression(self, it);
            return;
        }
        self.visit_expression(&it.callee);
        for argument in &it.arguments {
            match argument.as_expression() {
                Some(value)
                    if self.aliases.is_console(value) || self.aliases.is_global_this(value) => {}
                _ => self.visit_argument(argument),
            }
        }
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if self.find == Find::Methods
            && let AssignmentTarget::AssignmentTargetIdentifier(alias) = &it.left
            && self.reads_console(&it.right)
            && let Some(reference) = alias.reference_id.get()
            && let Some(symbol) = self.scoping.get_reference(reference).symbol_id()
        {
            self.found
                .push((self.scoping.symbol_span(symbol).start, symbol));
        }
        walk::walk_assignment_expression(self, it);
    }

    // The object of a member access does not escape. A member access
    // reached here is not itself an object, so `globalThis.console` here is
    // the console used as a value.
    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if self.aliases.is_global_this(&it.object) {
            if self.find == Find::Escapes && it.property.name == "console" {
                self.escapes.insert(it.span.start);
            }
            return;
        }
        if !self.aliases.is_console(&it.object) {
            walk::walk_static_member_expression(self, it);
        }
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        if self.aliases.is_global_this(&it.object) {
            if self.find == Find::Escapes
                && !matches!(&it.expression, Expression::StringLiteral(name) if name.value != "console")
            {
                self.escapes.insert(it.span.start);
            }
            self.visit_expression(&it.expression);
            return;
        }
        if self.aliases.is_console(&it.object) {
            self.visit_expression(&it.expression);
            return;
        }
        walk::walk_computed_member_expression(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        let span = it.span.start;
        if self.find == Find::Escapes
            && (self.aliases.objects.contains(&span) || self.aliases.global_this.contains(&span))
        {
            self.escapes.insert(span);
        }
    }
}
