//! JavaScript scope bindings: which names a program, function or loop binds,
//! what each is bound to, and which writes rebind them.

use super::*;

/// What a bare callee name binds to at its call site.
#[derive(Clone, Copy)]
pub(super) enum CalleeBinding {
    /// The function whose body has this span, declared once and never
    /// reassigned.
    Function((u32, u32)),
    /// A parameter, a variable of another value, a class, or a name declared
    /// more than once or reassigned: the called body is not known.
    Opaque,
    /// A name declared more than once or reassigned where some value it
    /// takes is a function or a name: a callback through it is not known.
    Rebound,
}

#[derive(Default)]
pub(super) struct Bindings {
    pub(super) readonly_writes: Option<HashSet<u32>>,
    pub(super) guards: crate::guards::GuardRegions,
    pub(super) source_digest: String,
    /// local name -> module it aliases (namespace/default import, or
    /// `const x = require('m')`).
    pub(super) namespaces: HashMap<String, String>,
    /// Default-import locals, distinguished from namespace imports when a
    /// member call needs a repository callee identity.
    pub(super) default_imports: HashSet<String>,
    /// How each identifier reference binds, by its span start: a callee or a
    /// callback passed by name. A name absent here is an import, a `require`
    /// binding, or a global. Filled for module summaries only.
    pub(super) reference_bindings: HashMap<u32, CalleeBinding>,
    /// Array iteration receivers (`roots.forEach(cb)`) whose symbol is a
    /// never-rebound array literal read only by iteration methods, by
    /// reference span start -> the declaring binding's span start.
    pub(super) fixed_arrays: HashMap<u32, u32>,
    /// `import * as x` locals. The namespace object is not callable, unlike a
    /// default import or a `require` result. An import binding cannot be
    /// rebound, so entries are never removed.
    pub(super) namespace_imports: HashSet<String>,
    /// local name -> (module, imported name) for named imports/destructuring.
    pub(super) named: HashMap<String, (String, String)>,
    /// Stable module local -> imported constructor or factory called to
    /// produce it (`const tool = new Bash()` / `const tool = createTool()`).
    pub(super) member_producers: HashMap<String, String>,
    /// Member paths replaced anywhere in the module. A replaced path also
    /// invalidates calls below it, such as `tools.bash = other` invalidating
    /// `tools.bash.execute()`.
    pub(super) reassigned_member_paths: HashSet<String>,
    /// Names declared in module scope, used to distinguish shadowed globals.
    pub(super) declared: HashSet<String>,
    /// Whether `require` is not the runtime's module loader: Deno evaluates
    /// inline code without one, and a module-scope binding replaces it.
    pub(super) require_shadowed: bool,
    /// Stable module-scope object literals available to function summaries.
    pub(super) object_literal_vars: model::ObjectLiteralBindings,
    /// Stable module-scope string literals available to function summaries.
    pub(super) source_literals: HashMap<String, String>,
    /// Spans of `process.env.X` that are assignment targets, so the read
    /// visitor does not also count them.
    pub(super) env_write_spans: HashSet<u32>,
    /// The environment writes whose value is known where they run: a
    /// module-scope statement `process.env.NAME = "literal"`, which runs
    /// unconditionally and in source order before any later module-scope
    /// statement. Target span start -> (name, value).
    pub(super) literal_env_writes: HashMap<u32, (String, String)>,
    /// Environment names the module reads or writes through `process.env`.
    pub(super) env_names: HashSet<String>,
    /// Spans of every function, parameters included, and class body, whose
    /// code can run after any module-scope statement.
    pub(super) body_spans: Vec<(u32, u32)>,
    /// Whether the runtime's environment names are case-sensitive and
    /// `os.homedir()` reads `$HOME`, as on POSIX hosts.
    pub(super) posix_environment: bool,
    /// Spans of every `process.env` reference, and of those that are the base
    /// of a member access. A reference that is not such a base hands the whole
    /// environment out, where it can be rewritten.
    pub(super) process_env_spans: HashSet<u32>,
    pub(super) process_env_member_bases: HashSet<u32>,
    /// Spans of the references that reach the runtime's own `process`: ones
    /// no enclosing scope binds, and those of a `const` bound to it.
    pub(super) global_process_spans: HashSet<u32>,
    /// The references that reach the runtime's own `console`, the bindings
    /// that may hold its methods, and where it escapes.
    pub(super) console: console::ConsoleAliases,
    /// Spans of the `eval` and `Function` references that reach the
    /// runtime's own, which no scope binds and the program never replaces.
    pub(super) runtime_code_spans: HashSet<u32>,
    /// Whether a promise handler's leading `throw` is known to reject its
    /// chain; see [`throws_reject`].
    pub(super) throws_reject: bool,
    /// Span starts of the classes nothing can instantiate, so their instance
    /// field initializers never run; see [`uninstantiated_class_spans`].
    pub(super) uninstantiated_classes: HashSet<u32>,
    /// Locals destructured out of `process` as its `env` (`const {env} =
    /// process`), and the spans where one is the object of a member access.
    pub(super) env_aliases: HashSet<String>,
    pub(super) env_alias_member_bases: HashSet<u32>,
    pub(super) env_alias_spans: Vec<(String, u32)>,
    /// A write or escape the other fields do not record: an update or
    /// computed write of an environment member, a write through an alias,
    /// `process` or its computed `env` handed to a call, or a walk that
    /// stopped before seeing every reference.
    pub(super) environment_uncertain: bool,
    pub(super) process_bindings: u32,
    pub(super) runtime_process_bindings: u32,
    pub(super) process_reassigned: bool,
    pub(super) function_depth: u32,
    /// TypeScript namespace and global declarations do not bind the enclosing
    /// runtime scope, even when declarations inside omit `declare`.
    pub(super) type_scope_depth: u32,
    pub(super) statement_depth: u32,
    pub(super) walk_depth: u32,
    pub(super) dynamic_imports: resolve::DynamicImportFacts,
}

impl Bindings {
    /// [`resolve::bound_module`], except that a `require` call names no module
    /// when `require` is not the runtime's loader.
    fn bound_module(&self, expr: &Expression) -> Option<String> {
        if self.require_shadowed && resolve::require_module(expr).is_some() {
            return None;
        }
        resolve::bound_module(expr).or_else(|| match expr {
            // `require('fs').promises`, or `.promises` of a bound `fs`.
            Expression::StaticMemberExpression(_) => resolve::module_of(expr, self),
            _ => None,
        })
    }

    pub(super) fn process_runtime(&self) -> bool {
        !self.process_reassigned
            && (self.process_bindings == 0
                || (self.process_bindings == 1 && self.runtime_process_bindings == 1))
    }

    pub(super) fn member_was_reassigned(&self, name: &str) -> bool {
        self.reassigned_member_paths.iter().any(|reassigned| {
            name == reassigned
                || name
                    .strip_prefix(reassigned)
                    .is_some_and(|suffix| suffix.starts_with('.'))
        })
    }

    /// Whether `expr` names the runtime's own `eval` or `Function`.
    pub(super) fn is_runtime_code(&self, expr: &Expression) -> bool {
        matches!(unparen(expr), Expression::Identifier(id)
            if self.runtime_code_spans.contains(&id.span.start))
    }

    fn is_global_process(&self, expr: &Expression) -> bool {
        matches!(unparen(expr), Expression::Identifier(id)
            if self.global_process_spans.contains(&id.span.start))
    }

    /// Whether an expression is the runtime's environment object:
    /// `process.env`, `process["env"]`, or a local destructured as `env`.
    fn is_environment_object(&self, expr: &Expression) -> bool {
        match unparen(expr) {
            Expression::StaticMemberExpression(member) => {
                member.property.name.as_str() == "env" && self.is_global_process(&member.object)
            }
            Expression::ComputedMemberExpression(member) => {
                matches!(&member.expression, Expression::StringLiteral(key) if key.value == "env")
                    && self.is_global_process(&member.object)
            }
            Expression::Identifier(id) => self.env_aliases.contains(id.name.as_str()),
            _ => false,
        }
    }

    /// `process.env.NAME = "value"` (or `process.env["NAME"]`) as a whole
    /// statement: the target's span start, the name and the value.
    fn literal_env_write(&self, statement: &Statement) -> Option<(u32, String, String)> {
        let Statement::ExpressionStatement(statement) = statement else {
            return None;
        };
        let Expression::AssignmentExpression(assignment) = &statement.expression else {
            return None;
        };
        if !assignment.operator.is_assign() {
            return None;
        }
        let member = assignment.left.as_member_expression()?;
        if !matches!(unparen(member.object()), Expression::StaticMemberExpression(env)
            if env.property.name.as_str() == "env" && self.is_global_process(&env.object))
        {
            return None;
        }
        let name = member.static_property_name()?.to_string();
        let value = match unparen(&assignment.right) {
            Expression::StringLiteral(value) => value.value.as_str().to_string(),
            Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
                resolve::cooked_template_string(value)?
            }
            _ => return None,
        };
        (!name.is_empty()).then(|| (member.span().start, name, value))
    }

    /// Whether writing `member` can change an environment value: a member of
    /// the environment object, or a `process` member whose key is `env` or
    /// unknown, or a member below one such as `process[key].HOME`.
    fn writes_environment(&self, member: &MemberExpression) -> bool {
        let unknown_process_member = |expr: &Expression| match unparen(expr) {
            Expression::ComputedMemberExpression(inner) => {
                self.is_global_process(&inner.object)
                    && !matches!(&inner.expression, Expression::StringLiteral(key) if key.value != "env")
            }
            _ => false,
        };
        self.is_environment_object(member.object())
            || unknown_process_member(member.object())
            || matches!(member, MemberExpression::ComputedMemberExpression(inner)
                if self.is_global_process(&inner.object)
                    && !matches!(&inner.expression, Expression::StringLiteral(key) if key.value != "env"))
    }

    /// `process` or its environment handed to a call, such as
    /// `Object.assign(process["env"], ...)` or `f(process)`, can be rewritten
    /// there. A static `process.env` argument is recorded separately.
    fn note_escaping_arguments(&mut self, arguments: &[Argument]) {
        if arguments
            .iter()
            .filter_map(Argument::as_expression)
            .any(|argument| {
                self.is_global_process(argument) || self.is_environment_object(argument)
            })
        {
            self.environment_uncertain = true;
        }
    }

    /// Whether the module can replace an environment value before it is read,
    /// so a value the host supplied no longer describes what the program sees.
    pub(super) fn environment_is_rewritten(&self) -> bool {
        !self.env_write_spans.is_empty() || self.environment_rewritten_otherwise()
    }

    /// Whether every rewrite of the environment is a literal module-scope
    /// write, so module-scope code sees each value at its point in the
    /// source; see [`Bindings::literal_env_writes`].
    pub(super) fn environment_rewrites_are_literal(&self) -> bool {
        // A name that differs from another only in case may be the same
        // variable, as on Windows; `os.homedir()` reads `HOME`.
        let mut folded = HashMap::new();
        let case_collision = self
            .env_names
            .iter()
            .map(String::as_str)
            .chain(["HOME"])
            .any(|name| {
                folded
                    .insert(name.to_ascii_uppercase(), name)
                    .is_some_and(|other| other != name)
            });
        self.posix_environment
            && !case_collision
            && !self.literal_env_writes.is_empty()
            && self
                .env_write_spans
                .iter()
                .all(|span| self.literal_env_writes.contains_key(span))
            && !self.environment_rewritten_otherwise()
    }

    fn environment_rewritten_otherwise(&self) -> bool {
        self.environment_uncertain
            || self.env_alias_spans.iter().any(|(name, span)| {
                self.env_aliases.contains(name) && !self.env_alias_member_bases.contains(span)
            })
            || self.member_was_reassigned("process.env")
            || self
                .process_env_spans
                .iter()
                .any(|span| !self.process_env_member_bases.contains(span))
    }
}

impl<'a> Visit<'a> for Bindings {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.environment_uncertain = true;
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.environment_uncertain = true;
            return;
        }
        self.walk_depth += 1;
        let module_scope =
            self.function_depth == 0 && self.type_scope_depth == 0 && self.statement_depth == 0;
        self.statement_depth += 1;
        if module_scope {
            match it {
                Statement::ExportNamedDeclaration(export) => {
                    if let Some(declaration) = &export.declaration {
                        collect_scope_binding_names(declaration, true, &mut self.declared);
                    }
                }
                Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        if let Some(id) = &function.id {
                            self.declared.insert(id.name.as_str().to_string());
                        }
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                        if let Some(id) = &class.id {
                            self.declared.insert(id.name.as_str().to_string());
                        }
                    }
                    _ => {}
                },
                _ => {
                    if let Some(declaration) = it.as_declaration() {
                        collect_scope_binding_names(declaration, true, &mut self.declared);
                    }
                }
            }
            if self.type_scope_depth == 0
                && let Some((span, name, value)) = self.literal_env_write(it)
            {
                self.literal_env_writes.insert(span, (name, value));
            }
            match it.as_declaration() {
                Some(Declaration::FunctionDeclaration(function))
                    if function
                        .id
                        .as_ref()
                        .is_some_and(|id| id.name.as_str() == "process") =>
                {
                    self.process_bindings += 1;
                }
                Some(Declaration::ClassDeclaration(class))
                    if class
                        .id
                        .as_ref()
                        .is_some_and(|id| id.name.as_str() == "process") =>
                {
                    self.process_bindings += 1;
                }
                _ => {}
            }
        }
        walk::walk_statement(self, it);
        self.statement_depth -= 1;
        self.walk_depth -= 1;
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if self.type_scope_depth > 0 {
            return;
        }
        let module = resolve::canonical_module(it.source.value.as_str());
        if let Some(specifiers) = &it.specifiers {
            for spec in specifiers {
                match spec {
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        self.declared.insert(s.local.name.as_str().to_string());
                        if s.local.name.as_str() == "process" {
                            self.process_bindings += 1;
                            self.runtime_process_bindings += u32::from(
                                module == "process" && s.imported.name().as_str() == "default",
                            );
                        }
                        self.named.insert(
                            s.local.name.as_str().to_string(),
                            (module.clone(), s.imported.name().as_str().to_string()),
                        );
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        self.declared.insert(s.local.name.as_str().to_string());
                        if s.local.name.as_str() == "process" {
                            self.process_bindings += 1;
                            self.runtime_process_bindings += u32::from(module == "process");
                        }
                        self.namespaces
                            .insert(s.local.name.as_str().to_string(), module.clone());
                        self.default_imports
                            .insert(s.local.name.as_str().to_string());
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        self.declared.insert(s.local.name.as_str().to_string());
                        if s.local.name.as_str() == "process" {
                            self.process_bindings += 1;
                            self.runtime_process_bindings += u32::from(module == "process");
                        }
                        self.namespaces
                            .insert(s.local.name.as_str().to_string(), module.clone());
                        self.namespace_imports
                            .insert(s.local.name.as_str().to_string());
                    }
                }
            }
        }
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if !it.declare {
            walk::walk_variable_declaration(self, it);
        }
    }

    fn visit_ts_module_declaration(&mut self, it: &oxc_ast::ast::TSModuleDeclaration<'a>) {
        self.type_scope_depth += 1;
        walk::walk_ts_module_declaration(self, it);
        self.type_scope_depth -= 1;
    }

    fn visit_ts_global_declaration(&mut self, it: &oxc_ast::ast::TSGlobalDeclaration<'a>) {
        self.type_scope_depth += 1;
        walk::walk_ts_global_declaration(self, it);
        self.type_scope_depth -= 1;
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init
            && self.is_global_process(init)
            && let BindingPattern::ObjectPattern(pattern) = &it.id
        {
            for property in &pattern.properties {
                if property.key.static_name().is_some_and(|key| key == "env")
                    && let BindingPattern::BindingIdentifier(alias) = &property.value
                {
                    self.env_aliases.insert(alias.name.to_string());
                }
            }
        }
        if self.function_depth == 0 && self.type_scope_depth == 0 {
            clear_bound_pattern(
                &it.id,
                &mut self.namespaces,
                &mut self.named,
                &mut self.default_imports,
                &mut self.member_producers,
            );
            if self.statement_depth == 1 {
                let mut names = HashSet::new();
                collect_binding_names(&it.id, &mut names);
                self.declared.extend(names.iter().cloned());
                for name in &names {
                    self.object_literal_vars.remove(name);
                    self.source_literals.remove(name);
                }
                if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init) {
                    if let Some(object) = model::object_literal(init, &self.object_literal_vars) {
                        self.object_literal_vars
                            .insert(id.name.as_str().to_string(), object);
                    }
                    let source = match unparen(init) {
                        Expression::StringLiteral(value) => Some(value.value.as_str().to_string()),
                        Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
                            resolve::cooked_template_string(value)
                        }
                        _ => None,
                    };
                    if let Some(source) = source {
                        self.source_literals
                            .insert(id.name.as_str().to_string(), source);
                    }
                    if let Some(producer) = member_producer(init) {
                        self.member_producers
                            .insert(id.name.as_str().to_string(), producer);
                    }
                }
            }
            if binding_declares(&it.id, "process") {
                self.process_bindings += 1;
                if matches!(&it.id, BindingPattern::BindingIdentifier(id) if id.name.as_str() == "process")
                    && it
                        .init
                        .as_ref()
                        .and_then(|init| self.bound_module(init))
                        .is_some_and(|module| module == "process")
                {
                    self.runtime_process_bindings += 1;
                }
            }
        }
        if let Some(init) = &it.init
            && let Some(module) = self.bound_module(init)
        {
            use oxc_ast::ast::BindingPattern;
            match &it.id {
                BindingPattern::BindingIdentifier(id) => {
                    self.namespaces.insert(id.name.as_str().to_string(), module);
                }
                BindingPattern::ObjectPattern(obj) => {
                    for prop in &obj.properties {
                        if let (Some(key), BindingPattern::BindingIdentifier(local)) =
                            (prop.key.static_name(), &prop.value)
                        {
                            self.named.insert(
                                local.name.as_str().to_string(),
                                (module.clone(), key.to_string()),
                            );
                        }
                    }
                }
                _ => {}
            }
        } else if let (Some(init), BindingPattern::BindingIdentifier(local)) = (&it.init, &it.id)
            && let Expression::StaticMemberExpression(member) = unparen(init)
            && let Some(module) = resolve::module_of(&member.object, self)
        {
            // `const rm = fs.rmSync` names the module's function as
            // `const { rmSync: rm } = fs` does.
            self.named.insert(
                local.name.as_str().to_string(),
                (module, member.property.name.as_str().to_string()),
            );
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if !matches!(
            it,
            AssignmentTarget::AssignmentTargetIdentifier(_)
                | AssignmentTarget::ArrayAssignmentTarget(_)
                | AssignmentTarget::ObjectAssignmentTarget(_)
        ) && let Some(name) = assignment_target_write_binding_name(it)
        {
            self.reassigned_member_paths.insert(name);
        }
        if self.function_depth == 0
            && self.type_scope_depth == 0
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = it
        {
            self.namespaces.remove(id.name.as_str());
            self.named.remove(id.name.as_str());
            self.default_imports.remove(id.name.as_str());
            self.member_producers.remove(id.name.as_str());
            self.object_literal_vars.remove(id.name.as_str());
            self.source_literals.remove(id.name.as_str());
            if id.name.as_str() == "process" {
                self.process_reassigned = true;
            }
        }
        if let AssignmentTarget::StaticMemberExpression(m) = it
            && resolve::process_env_name(m).is_some()
        {
            self.env_write_spans.insert(m.span.start);
        }
        if let AssignmentTarget::ComputedMemberExpression(m) = it
            && resolve::is_process_env(&m.object)
        {
            self.env_write_spans.insert(m.span.start);
        }
        if let Some(member) = it.as_member_expression()
            && self.writes_environment(member)
            && !self.literal_env_writes.contains_key(&member.span().start)
        {
            self.environment_uncertain = true;
        }
        walk::walk_assignment_target(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'a>) {
        if self.env_aliases.contains(it.name.as_str()) || it.name.as_str() == "env" {
            self.env_alias_spans
                .push((it.name.to_string(), it.span.start));
        }
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        if let Some(member) = it.argument.as_member_expression()
            && self.writes_environment(member)
        {
            self.environment_uncertain = true;
        }
        walk::walk_update_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.note_escaping_arguments(&it.arguments);
        walk::walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.note_escaping_arguments(&it.arguments);
        walk::walk_new_expression(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if let Expression::Identifier(object) = unparen(&it.object) {
            self.env_alias_member_bases.insert(object.span.start);
        }
        if it.property.name.as_str() == "env" && resolve::is_process_object(&it.object) {
            self.process_env_spans.insert(it.span.start);
        }
        if let Some(name) = resolve::process_env_name(it) {
            self.env_names.insert(name);
        }
        if resolve::is_process_env(&it.object) {
            self.process_env_member_bases.insert(it.object.span().start);
        }
        walk::walk_static_member_expression(self, it);
    }

    fn visit_computed_member_expression(
        &mut self,
        it: &oxc_ast::ast::ComputedMemberExpression<'a>,
    ) {
        if resolve::is_process_env(&it.object) {
            self.process_env_member_bases.insert(it.object.span().start);
            if let Some(name) = literal_property_name(&it.expression) {
                self.env_names.insert(name);
            }
        }
        if let Expression::Identifier(object) = unparen(&it.object) {
            self.env_alias_member_bases.insert(object.span.start);
        }
        walk::walk_computed_member_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        if it.operator.as_str() == "delete"
            && let Some(member) = unparen(&it.argument).as_member_expression()
            && self.writes_environment(member)
        {
            self.environment_uncertain = true;
        }
        if it.operator.as_str() == "delete" {
            match unparen(&it.argument) {
                Expression::StaticMemberExpression(member)
                    if resolve::process_env_name(member).is_some() =>
                {
                    self.env_write_spans.insert(member.span.start);
                }
                Expression::ComputedMemberExpression(member)
                    if resolve::is_process_env(&member.object) =>
                {
                    self.env_write_spans.insert(member.span.start);
                }
                _ => {}
            }
        }
        walk::walk_unary_expression(self, it);
    }

    // A whole function, parameters included: default values run at the call.
    fn visit_function(&mut self, it: &oxc_ast::ast::Function<'a>, flags: oxc_semantic::ScopeFlags) {
        self.body_spans.push((it.span.start, it.span.end));
        walk::walk_function(self, it, flags);
    }

    fn visit_arrow_function_expression(&mut self, it: &oxc_ast::ast::ArrowFunctionExpression<'a>) {
        self.body_spans.push((it.span.start, it.span.end));
        walk::walk_arrow_function_expression(self, it);
    }

    fn visit_function_body(&mut self, it: &oxc_ast::ast::FunctionBody<'a>) {
        self.function_depth += 1;
        walk::walk_function_body(self, it);
        self.function_depth -= 1;
    }

    fn visit_class_body(&mut self, it: &ClassBody<'a>) {
        self.body_spans.push((it.span.start, it.span.end));
        walk::walk_class_body(self, it);
    }
}

/// Whether a binding pattern, destructuring included, declares `name`.
pub(super) fn binding_declares(pattern: &BindingPattern<'_>, name: &str) -> bool {
    match pattern {
        BindingPattern::BindingIdentifier(id) => id.name.as_str() == name,
        BindingPattern::ObjectPattern(object) => {
            object
                .properties
                .iter()
                .any(|property| binding_declares(&property.value, name))
                || object
                    .rest
                    .as_ref()
                    .is_some_and(|rest| binding_declares(&rest.argument, name))
        }
        BindingPattern::ArrayPattern(array) => {
            array
                .elements
                .iter()
                .flatten()
                .any(|element| binding_declares(element, name))
                || array
                    .rest
                    .as_ref()
                    .is_some_and(|rest| binding_declares(&rest.argument, name))
        }
        BindingPattern::AssignmentPattern(assignment) => binding_declares(&assignment.left, name),
    }
}

pub(in crate::js) fn collect_binding_names(
    pattern: &BindingPattern<'_>,
    names: &mut HashSet<String>,
) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            names.insert(id.name.as_str().to_string());
        }
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                collect_binding_names(&property.value, names);
            }
            if let Some(rest) = &object.rest {
                collect_binding_names(&rest.argument, names);
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in array.elements.iter().flatten() {
                collect_binding_names(element, names);
            }
            if let Some(rest) = &array.rest {
                collect_binding_names(&rest.argument, names);
            }
        }
        BindingPattern::AssignmentPattern(assignment) => {
            collect_binding_names(&assignment.left, names)
        }
    }
}

pub(super) fn collect_scope_binding_names(
    declaration: &Declaration<'_>,
    include_var: bool,
    names: &mut HashSet<String>,
) {
    match declaration {
        Declaration::VariableDeclaration(declaration)
            if include_var || declaration.kind != VariableDeclarationKind::Var =>
        {
            for declarator in &declaration.declarations {
                collect_binding_names(&declarator.id, names);
            }
        }
        Declaration::FunctionDeclaration(function) => {
            if let Some(id) = &function.id {
                names.insert(id.name.as_str().to_string());
            }
        }
        Declaration::ClassDeclaration(class) => {
            if let Some(id) = &class.id {
                names.insert(id.name.as_str().to_string());
            }
        }
        _ => {}
    }
}

#[derive(Default)]
pub(super) struct AssignmentTargetBindings {
    pub(super) names: HashSet<String>,
}

impl<'a> Visit<'a> for AssignmentTargetBindings {
    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if let Some(name) = assignment_target_write_binding_name(it) {
            self.names.insert(name);
            return;
        }
        match it {
            AssignmentTarget::ArrayAssignmentTarget(array) => {
                walk::walk_array_assignment_target(self, array)
            }
            AssignmentTarget::ObjectAssignmentTarget(object) => {
                walk::walk_object_assignment_target(self, object)
            }
            _ => {}
        }
    }

    fn visit_assignment_target_maybe_default(
        &mut self,
        it: &oxc_ast::ast::AssignmentTargetMaybeDefault<'a>,
    ) {
        match it {
            oxc_ast::ast::AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(default) => {
                self.visit_assignment_target(&default.binding)
            }
            _ => self.visit_assignment_target(it.to_assignment_target()),
        }
    }

    fn visit_assignment_target_property_identifier(
        &mut self,
        it: &oxc_ast::ast::AssignmentTargetPropertyIdentifier<'a>,
    ) {
        self.names.insert(it.binding.name.as_str().to_string());
    }

    fn visit_assignment_target_property_property(
        &mut self,
        it: &oxc_ast::ast::AssignmentTargetPropertyProperty<'a>,
    ) {
        self.visit_assignment_target_maybe_default(&it.binding);
    }
}

#[derive(Default)]
struct FunctionVarBindings {
    names: HashSet<String>,
}

impl<'a> Visit<'a> for FunctionVarBindings {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind == VariableDeclarationKind::Var {
            for declarator in &it.declarations {
                collect_binding_names(&declarator.id, &mut self.names);
            }
        }
        walk::walk_variable_declaration(self, it);
    }

    fn visit_function_body(&mut self, _it: &FunctionBody<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

struct LoopBindingWrites<'f, 'a> {
    names: HashSet<String>,
    shadowed: Vec<HashSet<String>>,
    functions: &'f FnTable<'a>,
    callable_env: CallableEnv,
    visiting: HashSet<u32>,
}

impl<'f, 'a> LoopBindingWrites<'f, 'a> {
    fn new(functions: &'f FnTable<'a>, callable_env: CallableEnv) -> Self {
        Self {
            names: HashSet::new(),
            shadowed: Vec::new(),
            functions,
            callable_env,
            visiting: HashSet::new(),
        }
    }

    fn is_shadowed(&self, name: &str) -> bool {
        self.shadowed.iter().rev().any(|scope| scope.contains(name))
    }

    fn record(&mut self, names: impl IntoIterator<Item = String>) {
        for name in names {
            if !self.is_shadowed(&name) {
                self.names.insert(name);
            }
        }
    }

    fn enter_scope(&mut self, names: HashSet<String>) {
        self.shadowed.push(names);
    }

    fn leave_scope(&mut self) {
        self.shadowed.pop();
    }

    fn visit_called_function(&mut self, function: &collect::FnInfo<'a>) {
        if function.is_generator {
            return;
        }
        let mut local_names = function_local_binding_names(function.body);
        local_names.extend(function.param_bindings.iter().cloned());
        local_names.extend(function.self_binding.iter().cloned());
        self.visit_called_body(function.body, local_names);
    }

    fn visit_inline_function(
        &mut self,
        body: &FunctionBody<'a>,
        params: &FormalParameters<'a>,
        self_binding: Option<&str>,
        generator: bool,
    ) {
        if generator {
            return;
        }
        let mut local_names = function_local_binding_names(body);
        for parameter in &params.items {
            collect_binding_names(&parameter.pattern, &mut local_names);
        }
        if let Some(rest) = &params.rest {
            collect_binding_names(&rest.rest.argument, &mut local_names);
        }
        if let Some(name) = self_binding {
            local_names.insert(name.to_string());
        }
        self.visit_called_body(body, local_names);
    }

    fn visit_called_body(&mut self, body: &FunctionBody<'a>, local_names: HashSet<String>) {
        if self.visiting.len() as u32 >= MAX_WALK_DEPTH || !self.visiting.insert(body.span.start) {
            return;
        }
        let saved_shadowed = std::mem::take(&mut self.shadowed);
        let saved_callable_env = std::mem::take(&mut self.callable_env);
        self.callable_env = saved_callable_env.clone();
        for name in &local_names {
            self.callable_env.remove(name);
        }
        self.shadowed.push(local_names.clone());
        for statement in &body.statements {
            self.visit_statement(statement);
        }
        let body_callable_env = std::mem::take(&mut self.callable_env);
        self.callable_env = saved_callable_env;
        for name in self
            .callable_env
            .keys()
            .chain(body_callable_env.keys())
            .filter(|name| {
                !local_names.contains(*name)
                    && self.callable_env.get(*name) != body_callable_env.get(*name)
            })
            .cloned()
            .collect::<HashSet<_>>()
        {
            self.callable_env.insert(name, CallableBinding::Unbounded);
        }
        self.shadowed = saved_shadowed;
        self.visiting.remove(&body.span.start);
    }

    fn visit_callback(&mut self, expression: &Expression<'a>) {
        match unparen(expression) {
            Expression::FunctionExpression(function) => {
                if let Some(body) = &function.body {
                    self.visit_inline_function(
                        body,
                        &function.params,
                        function.id.as_ref().map(|id| id.name.as_str()),
                        function.generator,
                    );
                }
            }
            Expression::ArrowFunctionExpression(function) => {
                self.visit_inline_function(&function.body, &function.params, None, false)
            }
            Expression::Identifier(id) => {
                if let Some(function) = resolve_callable(
                    self.functions,
                    &self.callable_env,
                    id.name.as_str(),
                    id.span,
                ) {
                    self.visit_called_function(function);
                }
            }
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            self.visit_callback(&property.value)
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            self.visit_callback(&spread.argument)
                        }
                    }
                }
            }
            Expression::ArrayExpression(array) => {
                for element in &array.elements {
                    if let Some(expression) = element.as_expression() {
                        self.visit_callback(expression);
                    }
                }
            }
            Expression::AwaitExpression(awaited) => self.visit_callback(&awaited.argument),
            _ => {}
        }
    }
}

impl<'f, 'a> Visit<'a> for LoopBindingWrites<'f, 'a> {
    fn visit_assignment_expression(&mut self, it: &oxc_ast::ast::AssignmentExpression<'a>) {
        walk::walk_assignment_expression(self, it);
        let mut bindings = AssignmentTargetBindings::default();
        bindings.visit_assignment_target(&it.left);
        self.record(bindings.names);
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left {
            let binding = if it.operator.is_assign()
                && matches!(
                    unparen(&it.right),
                    Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
                )
                && collect::resolve_assignment(self.functions, id.name.as_str(), it.span.start)
                    .is_some()
            {
                CallableBinding::Assigned(it.span.start)
            } else {
                CallableBinding::Unbounded
            };
            self.callable_env
                .insert(id.name.as_str().to_string(), binding);
        }
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        if let Some(name) = simple_assignment_target_write_binding_name(&it.argument) {
            self.record([name.clone()]);
            self.callable_env.insert(name, CallableBinding::Unbounded);
        }
        walk::walk_update_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        walk::walk_unary_expression(self, it);
        if it.operator.as_str() == "delete"
            && let Some(name) = expression_write_binding_name(&it.argument)
        {
            self.record([name.clone()]);
            self.callable_env.insert(name, CallableBinding::Unbounded);
        }
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        walk::walk_variable_declarator(self, it);
        if let BindingPattern::BindingIdentifier(id) = &it.id {
            let binding =
                if it.init.as_ref().is_some_and(|init| {
                    matches!(
                        unparen(init),
                        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
                    )
                }) && collect::resolve_declarator(self.functions, id.name.as_str(), it.span.end)
                    .is_some()
                {
                    CallableBinding::Declarator(it.span.end)
                } else {
                    CallableBinding::Unbounded
                };
            self.callable_env
                .insert(id.name.as_str().to_string(), binding);
        }
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        walk::walk_call_expression(self, it);
        self.record(aggregate_mutation_target_bindings(it));
        match unparen(&it.callee) {
            Expression::FunctionExpression(function) => {
                if let Some(body) = &function.body {
                    self.visit_inline_function(
                        body,
                        &function.params,
                        function.id.as_ref().map(|id| id.name.as_str()),
                        function.generator,
                    );
                }
            }
            Expression::ArrowFunctionExpression(function) => {
                self.visit_inline_function(&function.body, &function.params, None, false)
            }
            Expression::Identifier(id) => {
                if let Some(function) = resolve_callable(
                    self.functions,
                    &self.callable_env,
                    id.name.as_str(),
                    it.span,
                ) {
                    self.visit_called_function(function);
                }
            }
            _ => {}
        }
        for argument in &it.arguments {
            if let Some(expression) = argument.as_expression() {
                self.visit_callback(expression);
            }
        }
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind == VariableDeclarationKind::Var {
            let mut names = HashSet::new();
            for declarator in &it.declarations {
                collect_binding_names(&declarator.id, &mut names);
            }
            self.record(names);
        }
        walk::walk_variable_declaration(self, it);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        let mut names = HashSet::new();
        for statement in &it.body {
            if let Some(declaration) = statement.as_declaration() {
                collect_scope_binding_names(declaration, false, &mut names);
            }
        }
        self.enter_scope(names);
        walk::walk_block_statement(self, it);
        self.leave_scope();
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        let mut names = HashSet::new();
        if let Some(param) = &it.param {
            collect_binding_names(&param.pattern, &mut names);
        }
        self.enter_scope(names);
        walk::walk_catch_clause(self, it);
        self.leave_scope();
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        let mut names = HashSet::new();
        if let Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(declaration)) = &it.init
            && declaration.kind != VariableDeclarationKind::Var
        {
            for declarator in &declaration.declarations {
                collect_binding_names(&declarator.id, &mut names);
            }
        }
        self.enter_scope(names);
        walk::walk_for_statement(self, it);
        self.leave_scope();
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.enter_scope(loop_left_lexical_names(&it.left));
        walk::walk_for_of_statement(self, it);
        self.leave_scope();
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.enter_scope(loop_left_lexical_names(&it.left));
        walk::walk_for_in_statement(self, it);
        self.leave_scope();
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        let mut names = HashSet::new();
        for case in &it.cases {
            for statement in &case.consequent {
                if let Some(declaration) = statement.as_declaration() {
                    collect_scope_binding_names(declaration, false, &mut names);
                }
            }
        }
        self.enter_scope(names);
        walk::walk_switch_statement(self, it);
        self.leave_scope();
    }

    fn visit_function_body(&mut self, _it: &FunctionBody<'a>) {}
}

fn loop_left_lexical_names(left: &oxc_ast::ast::ForStatementLeft<'_>) -> HashSet<String> {
    let mut names = HashSet::new();
    if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) = left
        && declaration.kind != VariableDeclarationKind::Var
    {
        for declarator in &declaration.declarations {
            collect_binding_names(&declarator.id, &mut names);
        }
    }
    names
}

pub(super) fn loop_binding_writes<'a>(
    body: &Statement<'a>,
    test: Option<&Expression<'a>>,
    update: Option<&Expression<'a>>,
    shadowed: HashSet<String>,
    functions: &FnTable<'a>,
    callable_env: &CallableEnv,
) -> HashSet<String> {
    let mut writes = LoopBindingWrites::new(functions, callable_env.clone());
    writes.enter_scope(shadowed);
    writes.visit_statement(body);
    if let Some(test) = test {
        writes.visit_expression(test);
    }
    if let Some(update) = update {
        writes.visit_expression(update);
    }
    writes.names
}

pub(super) fn function_local_binding_names(body: &FunctionBody<'_>) -> HashSet<String> {
    let mut names = HashSet::new();
    for statement in &body.statements {
        if let Some(declaration) = statement.as_declaration() {
            collect_scope_binding_names(declaration, true, &mut names);
        }
    }
    let mut var_bindings = FunctionVarBindings::default();
    for statement in &body.statements {
        var_bindings.visit_statement(statement);
    }
    names.extend(var_bindings.names);
    names
}
