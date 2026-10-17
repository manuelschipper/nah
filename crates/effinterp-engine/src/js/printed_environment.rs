//! Environment values a Node program prints: which `environment.read`
//! effects reach the program's own stdout, and when the value printed is the
//! whole environment (`console.log(process.env)`), as `printenv` prints it.
//! A printed read is marked `output: stdout`; passing the environment on
//! (`spawn(cmd, { env: process.env })`) prints nothing and is not marked.
//! What the program writes to stderr reaches the transcript as its stdout
//! does, so it counts as printed here, as the shell counts `printenv >&2`.
//!
//! The whole environment is followed as a value with a shape, because the
//! shape decides what printing it shows: `Object.keys` lists names, an
//! entry's first element is a name, and the object itself coerces to
//! `[object Object]` in text. A binding holds a shape for as long as that
//! binding does: a parameter takes its argument's, and a function body's
//! assignment to an enclosing binding reaches the caller.

use effinterp_proto::{
    AttrValue, Effect, Modality, Operation, ResourceExpr, ResourceIdentity, ResourcePattern,
};
use oxc_ast::ast::{
    Argument, AssignmentTarget, BindingPattern, CallExpression, Expression, FunctionBody, Statement,
};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use super::bindings::collect_binding_names;
use super::{
    AssignmentTargetBindings, EffectVisitor, console_printed_arguments, literal_truth, resolve,
    unparen,
};

/// How deep a printed expression is read for the environment it carries.
const MAX_DEPTH: u32 = 16;

/// What a value taken from the environment is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EnvironmentShape {
    /// `process.env` or a copy: an object of every variable.
    Mapping,
    /// Its `[name, value]` entries.
    Entries,
    /// One `[name, value]` entry: `entry[0]` is the name.
    Pair,
    /// Names only, one or a list: printing them shows no value.
    Names,
    /// Values in a list or an object.
    Values,
    /// Text built from values, which a stream `write` accepts.
    Text,
    /// An object, or a list of objects, with the environment inside it
    /// (`{ env: process.env }`): inspected or serialized it shows values,
    /// coerced to text it is `[object Object]`.
    Holder,
}

impl EnvironmentShape {
    /// Whether `console.log` of the value shows variable values.
    fn discloses(self) -> bool {
        self != Self::Names
    }

    /// Whether text built from the value shows variable values: the object
    /// itself coerces to `[object Object]`.
    fn renders(self) -> bool {
        matches!(self, Self::Entries | Self::Pair | Self::Values | Self::Text)
    }
}

/// Names a callback binds while its result is read: what each holds of
/// the environment, or nothing for a parameter that shadows an outer name.
type Scope = Vec<(String, Option<EnvironmentShape>)>;

/// Array methods whose result keeps every element of the array.
const KEEPS_ELEMENTS: &[&str] = &["flat", "reverse", "sort", "toReversed", "toSorted"];

/// Methods whose result is text of the whole array or string they are
/// called on.
const RENDERS: &[&str] = &[
    "join",
    "normalize",
    "padEnd",
    "padStart",
    "toLowerCase",
    "toString",
    "toUpperCase",
    "trim",
    "trimEnd",
    "trimStart",
];

/// Either of two shapes a value may be.
fn either(
    left: Option<EnvironmentShape>,
    right: Option<EnvironmentShape>,
) -> Option<EnvironmentShape> {
    match (left, right) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(_), Some(_)) => Some(EnvironmentShape::Values),
        (shape, None) | (None, shape) => shape,
    }
}

/// The parameters and the returned expression of an inline callback: an
/// arrow with an expression body, or a function whose body is one `return`.
fn inline_callback<'b, 'a>(
    argument: Option<&'b Argument<'a>>,
) -> Option<(&'b oxc_ast::ast::FormalParameters<'a>, &'b Expression<'a>)> {
    let (params, body): (_, &FunctionBody) = match unparen(argument?.as_expression()?) {
        Expression::ArrowFunctionExpression(arrow) => (&arrow.params, &arrow.body),
        Expression::FunctionExpression(function) => (&function.params, function.body.as_ref()?),
        _ => return None,
    };
    let [statement] = body.statements.as_slice() else {
        return None;
    };
    let returned = match statement {
        Statement::ExpressionStatement(statement) => &statement.expression,
        Statement::ReturnStatement(statement) => statement.argument.as_ref()?,
        _ => return None,
    };
    Some((params, returned))
}

/// Whether a function body made only of plain statements assigns `name`,
/// so the assignment certainly ran when the body did.
pub(super) fn assigns_unconditionally(body: &FunctionBody<'_>, name: &str) -> bool {
    let mut assigns = false;
    for statement in &body.statements {
        match statement {
            Statement::ExpressionStatement(statement) => {
                assigns |= matches!(unparen(&statement.expression),
                    Expression::AssignmentExpression(assignment)
                        if assignment.operator.is_assign()
                            && matches!(&assignment.left,
                                AssignmentTarget::AssignmentTargetIdentifier(target)
                                    if target.name == name));
            }
            Statement::VariableDeclaration(_) | Statement::FunctionDeclaration(_) => {}
            _ => return false,
        }
    }
    assigns
}

impl<'a> EffectVisitor<'_, 'a> {
    /// Remember the `environment.read` effects among those the new `stage`
    /// carries, in `[before, after)`.
    pub(super) fn note_environment_stage(&mut self, stage: usize, before: usize, after: usize) {
        let reads: Vec<u32> = (before..after)
            .filter(|effect| self.builder.effect_operation(*effect) == Some("environment.read"))
            .map(|effect| effect as u32)
            .collect();
        if !reads.is_empty() {
            self.environment_stages.insert(stage, reads);
        }
    }

    /// A `stage` joining `producers` carries the environment reads they do.
    pub(super) fn join_environment_stages(&mut self, stage: usize, producers: &[usize]) {
        let reads: Vec<u32> = producers
            .iter()
            .filter_map(|producer| self.environment_stages.get(producer))
            .flatten()
            .copied()
            .collect();
        if !reads.is_empty() {
            self.environment_stages.insert(stage, reads);
        }
    }

    /// State that the named variables `producers` read reached stdout. A
    /// read whose name is not known (`process.env[name]`) is left alone:
    /// it prints one variable, and nothing says which.
    pub(super) fn mark_printed_environment(&mut self, producers: &[usize]) {
        let reads: Vec<u32> = producers
            .iter()
            .filter_map(|producer| self.environment_stages.get(producer))
            .flatten()
            .copied()
            .collect();
        for effect in reads {
            if matches!(
                self.builder.effect_resource(effect as usize),
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { .. }
                })
            ) {
                self.builder
                    .set_effect_string_attribute(effect as usize, "output", "stdout");
            }
        }
    }

    /// The values a call writes to this program's stderr: what
    /// `console.error`, `console.warn`, `console.trace` or
    /// `process.stderr.write` is given. A console method the program has
    /// assigned, or may have through an escaped console, is not read.
    pub(super) fn stderr_written<'b>(
        &self,
        call: &'b CallExpression<'a>,
    ) -> Option<Vec<&'b Expression<'a>>> {
        let console = self
            .bindings
            .console
            .method(&call.callee)
            .is_some_and(|method| {
                matches!(method, "error" | "warn" | "trace")
                    && !self.console_assignments.iter().any(|assignment| {
                        assignment
                            .method
                            .as_deref()
                            .is_none_or(|assigned| assigned == method)
                    })
            });
        let stream = matches!(unparen(&call.callee), Expression::StaticMemberExpression(write)
            if write.property.name == "write"
                && matches!(unparen(&write.object), Expression::StaticMemberExpression(stderr)
                    if stderr.property.name == "stderr"
                        && resolve::is_process_object(&stderr.object)));
        (console || stream).then(|| console_printed_arguments(&call.arguments))
    }

    /// Whether `call` prints the values of the whole environment: a console
    /// method given a value that shows them, or a stream `write` given text
    /// built from them.
    pub(super) fn prints_whole_environment(&self, call: &CallExpression<'a>) -> bool {
        let Some(written) = self
            .stdout_written(call)
            .or_else(|| self.stderr_written(call))
        else {
            return false;
        };
        // A stream's `write` takes text and throws on anything else.
        let write = self.bindings.console.method(&call.callee).is_none()
            && matches!(unparen(&call.callee), Expression::StaticMemberExpression(_));
        written.into_iter().any(|value| {
            self.environment_shape(value, &Scope::new(), 0)
                .is_some_and(|shape| {
                    if write {
                        shape == EnvironmentShape::Text
                    } else {
                        shape.discloses()
                    }
                })
        })
    }

    /// What `expr` holds of the environment, if anything.
    fn environment_shape(
        &self,
        expr: &Expression<'a>,
        scope: &Scope,
        depth: u32,
    ) -> Option<EnvironmentShape> {
        if depth >= MAX_DEPTH {
            return None;
        }
        let shape = |part: &Expression<'a>| self.environment_shape(part, scope, depth + 1);
        // Text or a container built from parts shows the values they show.
        let built = |parts: &mut dyn Iterator<Item = Option<EnvironmentShape>>, text: bool| {
            if text {
                parts
                    .flatten()
                    .any(EnvironmentShape::renders)
                    .then_some(EnvironmentShape::Text)
            } else {
                parts
                    .flatten()
                    .any(EnvironmentShape::discloses)
                    .then_some(EnvironmentShape::Values)
            }
        };
        match unparen(expr) {
            // Not an object the program put in the environment's place.
            expr if resolve::is_process_env(expr) => (self.process_runtime
                && !self.bindings.member_was_reassigned("process.env"))
            .then_some(EnvironmentShape::Mapping),
            Expression::Identifier(id) => {
                match scope
                    .iter()
                    .rev()
                    .find(|(bound, _)| *bound == id.name.as_str())
                {
                    Some((_, held)) => *held,
                    None => self.environment_holds.get(id.name.as_str()).copied(),
                }
            }
            Expression::AwaitExpression(awaited) => shape(&awaited.argument),
            // The arm a literal test selects, else either.
            Expression::ConditionalExpression(branch) => match literal_truth(&branch.test) {
                Some(true) => shape(&branch.consequent),
                Some(false) => shape(&branch.alternate),
                None => either(shape(&branch.consequent), shape(&branch.alternate)),
            },
            Expression::LogicalExpression(logical) => match logical.operator {
                // `a && b` is `b` unless `a` is falsy, and a value from the
                // environment that is falsy is empty.
                // A literal `a` that is falsy is the result itself.
                oxc_ast::ast::LogicalOperator::And => (literal_truth(&logical.left) != Some(false))
                    .then(|| shape(&logical.right))
                    .flatten(),
                // `a || b` and `a ?? b` are `a` when it is a value from the
                // environment, which is never nullish and falsy only empty.
                oxc_ast::ast::LogicalOperator::Or => shape(&logical.left).or_else(|| {
                    (literal_truth(&logical.left) != Some(true))
                        .then(|| shape(&logical.right))
                        .flatten()
                }),
                oxc_ast::ast::LogicalOperator::Coalesce => shape(&logical.left).or_else(|| {
                    let left = unparen(&logical.left);
                    (matches!(left, Expression::NullLiteral(_)) || !left.is_literal())
                        .then(|| shape(&logical.right))
                        .flatten()
                }),
            },
            Expression::BinaryExpression(sum)
                if sum.operator == oxc_ast::ast::BinaryOperator::Addition =>
            {
                built(&mut [shape(&sum.left), shape(&sum.right)].into_iter(), true)
            }
            Expression::TemplateLiteral(template) => {
                built(&mut template.expressions.iter().map(shape), true)
            }
            Expression::ObjectExpression(object) => {
                let mut copies = false;
                let mut contains = false;
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            contains |=
                                shape(&property.value).is_some_and(EnvironmentShape::discloses);
                        }
                        // `{ ...process.env, CI: "1" }` is a copy.
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            copies |= shape(&spread.argument) == Some(EnvironmentShape::Mapping);
                        }
                    }
                }
                if copies {
                    Some(EnvironmentShape::Mapping)
                } else {
                    contains.then_some(EnvironmentShape::Holder)
                }
            }
            Expression::ArrayExpression(array) => match array.elements.as_slice() {
                // `[...entries]` is a copy.
                [oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread)] => {
                    shape(&spread.argument).filter(|copied| *copied != EnvironmentShape::Mapping)
                }
                // A list of text renders as its elements do; a list of
                // objects renders each as `[object Object]`.
                elements => {
                    let held: Vec<EnvironmentShape> = elements
                        .iter()
                        .filter_map(|element| match element {
                            oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                                shape(&spread.argument)
                                    .filter(|spread| *spread != EnvironmentShape::Mapping)
                            }
                            element => element.as_expression().and_then(shape),
                        })
                        .filter(|held| held.discloses())
                        .collect();
                    if held.iter().any(|held| held.renders()) {
                        Some(EnvironmentShape::Values)
                    } else {
                        (!held.is_empty()).then_some(EnvironmentShape::Holder)
                    }
                }
            },
            Expression::ComputedMemberExpression(member) => match shape(&member.object)? {
                // `env[name]` for a name taken from the environment.
                EnvironmentShape::Mapping => (shape(&member.expression)
                    == Some(EnvironmentShape::Names))
                .then_some(EnvironmentShape::Values),
                // An entry is `[name, value]` and nothing more.
                EnvironmentShape::Pair => match unparen(&member.expression) {
                    Expression::NumericLiteral(index) if index.value == 0.0 => {
                        Some(EnvironmentShape::Names)
                    }
                    Expression::NumericLiteral(index) if index.value == 1.0 => {
                        Some(EnvironmentShape::Text)
                    }
                    _ => None,
                },
                _ => None,
            },
            Expression::CallExpression(call) => self.call_environment_shape(call, scope, depth),
            _ => None,
        }
    }

    /// What a call's value holds of the environment.
    fn call_environment_shape(
        &self,
        call: &CallExpression<'a>,
        scope: &Scope,
        depth: u32,
    ) -> Option<EnvironmentShape> {
        let shape = |part: &Expression<'a>| self.environment_shape(part, scope, depth + 1);
        let Expression::StaticMemberExpression(member) = unparen(&call.callee) else {
            return None;
        };
        let method = member.property.name.as_str();
        let object = unparen(&member.object);
        let mut arguments = call.arguments.iter().filter_map(Argument::as_expression);
        // A method the program assigned is not the runtime's.
        if let Expression::Identifier(id) = object
            && self
                .bindings
                .member_was_reassigned(&format!("{}.{method}", id.name))
        {
            return None;
        }
        let global = |name: &str| matches!(object, Expression::Identifier(id) if id.name == name);
        // The runtime's own `Object`, not a binding of that name.
        if matches!(object, Expression::Identifier(id)
            if self.bindings.console.object_globals.contains(&id.span.start))
        {
            let first = arguments.next().and_then(shape);
            return match (method, first) {
                ("entries", Some(EnvironmentShape::Mapping)) => Some(EnvironmentShape::Entries),
                ("values", Some(EnvironmentShape::Mapping)) => Some(EnvironmentShape::Values),
                ("keys", Some(EnvironmentShape::Mapping)) => Some(EnvironmentShape::Names),
                ("fromEntries", Some(EnvironmentShape::Entries)) => Some(EnvironmentShape::Mapping),
                ("freeze", first) => first,
                ("assign", first) => (first == Some(EnvironmentShape::Mapping)
                    || arguments.any(|source| shape(source) == Some(EnvironmentShape::Mapping)))
                .then_some(EnvironmentShape::Mapping),
                _ => None,
            };
        }
        if matches!(method, "map" | "flatMap") {
            return self.mapped_environment_shape(call, object, scope, depth);
        }
        // `entry.slice(1)` keeps the value, `entry.slice(0, 1)` the name.
        if method == "slice" && shape(object) == Some(EnvironmentShape::Pair) {
            // A bound is truncated to an integer, and a negative one
            // counts back from the pair's end (`-0` is 0).
            let mut bound = |default: f64| {
                let literal = match arguments.next().map(unparen) {
                    None => return Some(default),
                    Some(Expression::NumericLiteral(index)) => index.value,
                    Some(Expression::UnaryExpression(negated))
                        if negated.operator == oxc_ast::ast::UnaryOperator::UnaryNegation =>
                    {
                        match unparen(&negated.argument) {
                            Expression::NumericLiteral(back) => -back.value,
                            _ => return None,
                        }
                    }
                    Some(_) => return None,
                };
                let whole = literal.trunc();
                Some(if whole < 0.0 {
                    (2.0 + whole).max(0.0)
                } else {
                    whole
                })
            };
            let (start, end) = (bound(0.0)?, bound(2.0)?);
            return if start <= 1.0 && end > 1.0 {
                Some(EnvironmentShape::Values)
            } else {
                (start <= 0.0 && end > 0.0).then_some(EnvironmentShape::Names)
            };
        }
        if KEEPS_ELEMENTS.contains(&method) {
            return shape(object).filter(|kept| *kept != EnvironmentShape::Mapping);
        }
        // `JSON.stringify(env)`: every property, unless a replacer selects.
        if global("JSON") && method == "stringify" && self.bindings.is_runtime_text(object) {
            let value = arguments.next().and_then(shape);
            let selects = arguments.next().is_some_and(|replacer| {
                !matches!(unparen(replacer), Expression::NullLiteral(_))
                    && !matches!(unparen(replacer), Expression::Identifier(id)
                        if id.name == "undefined")
            });
            return value
                .filter(|value| value.discloses() && !selects)
                .map(|_| EnvironmentShape::Text);
        }
        if matches!(method, "format" | "inspect")
            && resolve::module_of(object, self.bindings).as_deref() == Some("util")
        {
            return arguments
                .any(|argument| shape(argument).is_some_and(EnvironmentShape::discloses))
                .then_some(EnvironmentShape::Text);
        }
        (RENDERS.contains(&method) && shape(object).is_some_and(EnvironmentShape::renders))
            .then_some(EnvironmentShape::Text)
    }

    /// What `receiver.map(callback)` holds: the callback's parameter is
    /// bound to what an element of the receiver is, and its returned
    /// expression read with that. A callback defined elsewhere, or one with
    /// more than a returned expression, is not read.
    fn mapped_environment_shape(
        &self,
        call: &CallExpression<'a>,
        receiver: &Expression<'a>,
        scope: &Scope,
        depth: u32,
    ) -> Option<EnvironmentShape> {
        let iterated = self.environment_shape(receiver, scope, depth + 1)?;
        let (params, returned) = inline_callback(call.arguments.first())?;
        let mut scope = scope.clone();
        // Every parameter shadows an outer name, whatever it is bound to.
        let mut shadowed = std::collections::HashSet::new();
        for parameter in &params.items {
            collect_binding_names(&parameter.pattern, &mut shadowed);
        }
        scope.extend(shadowed.into_iter().map(|name| (name, None)));
        let mut bind = |pattern: &BindingPattern<'a>, shape| {
            let mut names = std::collections::HashSet::new();
            collect_binding_names(pattern, &mut names);
            scope.extend(names.into_iter().map(|name| (name, Some(shape))));
        };
        match (
            iterated,
            params.items.first().map(|element| &element.pattern),
        ) {
            (EnvironmentShape::Entries, Some(BindingPattern::ArrayPattern(pair))) => {
                // An entry is `[name, value]`: a later element is undefined.
                for (element, shape) in pair
                    .elements
                    .iter()
                    .zip([EnvironmentShape::Names, EnvironmentShape::Text])
                {
                    if let Some(element) = element {
                        bind(element, shape);
                    }
                }
                // `[...all]` takes the entry, `[name, ...values]` the value,
                // and a rest after both takes nothing.
                if let Some(rest) = &pair.rest {
                    match pair.elements.len() {
                        0 => bind(&rest.argument, EnvironmentShape::Pair),
                        1 => bind(&rest.argument, EnvironmentShape::Values),
                        _ => {}
                    }
                }
            }
            (EnvironmentShape::Entries, Some(pattern @ BindingPattern::BindingIdentifier(_))) => {
                bind(pattern, EnvironmentShape::Pair);
            }
            (EnvironmentShape::Values, Some(pattern @ BindingPattern::BindingIdentifier(_))) => {
                bind(pattern, EnvironmentShape::Text);
            }
            (EnvironmentShape::Names, Some(pattern @ BindingPattern::BindingIdentifier(_))) => {
                bind(pattern, EnvironmentShape::Names);
            }
            _ => {}
        }
        match self.environment_shape(returned, &scope, depth + 1)? {
            EnvironmentShape::Names => Some(EnvironmentShape::Names),
            _ => Some(EnvironmentShape::Values),
        }
    }

    /// Bind `name` to what the value it now holds is of the environment.
    pub(super) fn bind_environment(&mut self, name: &str, value: &Expression<'a>) {
        match self.environment_shape(value, &Scope::new(), 0) {
            Some(shape) => self.environment_holds.insert(name.to_string(), shape),
            None => self.environment_holds.remove(name),
        };
    }

    /// The names an assignment target or a declaration rebinds no longer
    /// hold what they held of the environment.
    pub(super) fn end_environment<'n>(&mut self, names: impl IntoIterator<Item = &'n String>) {
        for name in names {
            self.environment_holds.remove(name);
        }
    }

    /// A destructuring assignment rebinds every name in its target.
    pub(super) fn end_assigned_environment(&mut self, target: &AssignmentTarget<'a>) {
        if self.environment_holds.is_empty() {
            return;
        }
        let mut bindings = AssignmentTargetBindings::default();
        bindings.visit_assignment_target(target);
        self.end_environment(&bindings.names);
    }

    /// A call binds `argument` to the parameter `pattern` of the body at
    /// `body`: the parameter holds what the argument does, once the body is
    /// entered.
    pub(super) fn bind_environment_parameter(
        &mut self,
        body: u32,
        pattern: &BindingPattern<'a>,
        argument: Option<&Expression<'a>>,
    ) {
        let (BindingPattern::BindingIdentifier(parameter), Some(argument)) = (pattern, argument)
        else {
            return;
        };
        let Some(shape) = self.environment_shape(argument, &Scope::new(), 0) else {
            return;
        };
        match self.environment_params.as_mut() {
            Some((pending, params)) if *pending == body => {
                params.push((parameter.name.to_string(), shape));
            }
            _ => {
                self.environment_params = Some((body, vec![(parameter.name.to_string(), shape)]));
            }
        }
    }

    /// Every variable in this execution's environment reaches stdout,
    /// including any a wrapper such as `doppler run` injected, so their
    /// values flow into the read the way they do for `printenv`.
    pub(super) fn print_whole_environment(&mut self, span: Span) {
        let node = self.span_node(span);
        let effect = self.builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Pattern {
                pattern: ResourcePattern::EnvironmentVariable {
                    name_glob: "*".into(),
                },
            },
            attributes: [(
                "output".to_string(),
                AttrValue::String("stdout".to_string()),
            )]
            .into_iter()
            .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![node],
        });
        let Some(effect) = effect else {
            return;
        };
        let unsets = self.nest.current_environment_unsets();
        let mut values = self
            .nest
            .environments
            .borrow()
            .last()
            .into_iter()
            .flat_map(|environment| environment.keys())
            .filter(|name| !unsets.contains(*name))
            .filter_map(|name| self.nest.current_environment_node(name))
            .collect::<Vec<_>>();
        values.extend(self.nest.injected_environment_node());
        self.builder
            .bind_environment_value_producers(effect, &values);
    }
}
