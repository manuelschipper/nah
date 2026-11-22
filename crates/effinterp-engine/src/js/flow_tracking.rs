//! JavaScript def-use flow tracking: the flow stage an expression produces,
//! which stage each binding, pattern element and object property currently
//! holds, and how those slots join after a branch.

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{Argument, Expression};
use oxc_span::{GetSpan, Span};

use super::binding_paths::expression_flow_key;
use super::expression_values::{literal_truth, unparen};
use super::literal_members::{array_element, array_literal_len, object_property};
use super::printed_environment::EnvironmentShape;
use super::walker::JsWalker;
use super::{MAX_FLOW_SLOTS, resolve};

/// What outer bindings held while a nested scope redeclared their names
/// (`let key = read(); { let key = "ok" }`): put back when that scope ends,
/// since the names then mean the outer bindings again.
pub(super) struct ShadowedBindings {
    names: Vec<String>,
    vars: Vec<(String, usize)>,
    slots: Vec<String>,
    shapes: Vec<(String, FlowShape)>,
    responses: Vec<(String, ResponseKind)>,
    environment: Vec<(String, EnvironmentShape)>,
    /// Whether the outer bindings are the live ones for now, and this
    /// holds the scope's own: see `view_bindings_from`.
    outer_live: bool,
}

impl<'a> JsWalker<'_, 'a> {
    /// Begin the scope at `span`, which declares `names` itself: its
    /// bindings start out holding nothing, and what the outer bindings of
    /// those names hold is kept until [`Self::unshadow_bindings`].
    pub(super) fn shadow_bindings(&mut self, span: Span, names: &HashSet<String>) {
        let mut names: Vec<String> = names.iter().cloned().collect();
        names.sort_unstable();
        let saved = self.take_bindings(names);
        self.shadowed_bindings.push((span, saved));
    }

    /// End the innermost scope begun by [`Self::shadow_bindings`]: its
    /// names mean the outer bindings again, holding what they did.
    pub(super) fn unshadow_bindings(&mut self) {
        if let Some((_, saved)) = self.shadowed_bindings.pop() {
            self.put_bindings(saved);
        }
    }

    /// Make the live bindings the ones a body at `body` means: for each
    /// redeclaring scope being walked, the scope's own names if the body is
    /// written inside it, else the outer bindings of those names
    /// (`{ let key = "ok"; load() }`). A scope already showing the right
    /// ones, because a caller of this body switched it, is left alone.
    /// Returns the scopes switched, for [`Self::restore_bindings_view`].
    pub(super) fn view_bindings_from(&mut self, body: Span) -> Vec<usize> {
        let inside = |scope: Span| scope.start <= body.start && body.end <= scope.end;
        let mut switched = Vec::new();
        // Outward from the innermost scope, then inward from the outermost,
        // so each exchange meets the bindings its scope saved.
        for index in (0..self.shadowed_bindings.len()).rev() {
            let (scope, saved) = &self.shadowed_bindings[index];
            if !saved.outer_live && !inside(*scope) {
                self.exchange_shadowed_bindings(index);
                switched.push(index);
            }
        }
        for index in 0..self.shadowed_bindings.len() {
            let (scope, saved) = &self.shadowed_bindings[index];
            if saved.outer_live && inside(*scope) {
                self.exchange_shadowed_bindings(index);
                switched.push(index);
            }
        }
        switched
    }

    /// Undo [`Self::view_bindings_from`] when its body ends.
    pub(super) fn restore_bindings_view(&mut self, switched: Vec<usize>) {
        for index in switched.into_iter().rev() {
            self.exchange_shadowed_bindings(index);
        }
    }

    /// Exchange the live bindings of the scope `index` of
    /// `shadowed_bindings` with the ones it holds.
    fn exchange_shadowed_bindings(&mut self, index: usize) {
        let names = self.shadowed_bindings[index].1.names.clone();
        let mut hidden = self.take_bindings(names);
        hidden.outer_live = !self.shadowed_bindings[index].1.outer_live;
        let shown = std::mem::replace(&mut self.shadowed_bindings[index].1, hidden);
        self.put_bindings(shown);
    }

    /// Take what the bindings `names` hold, leaving them holding nothing.
    fn take_bindings(&mut self, names: Vec<String>) -> ShadowedBindings {
        let of_names = |key: &str| {
            names.iter().any(|name| {
                key.strip_prefix(name.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
            })
        };
        let saved = ShadowedBindings {
            vars: (self.flow_vars.iter())
                .filter(|(key, _)| of_names(key))
                .map(|(key, stage)| (key.clone(), *stage))
                .collect(),
            slots: (self.flow_slots.iter())
                .filter(|key| of_names(key))
                .cloned()
                .collect(),
            shapes: (self.flow_shapes.iter())
                .filter(|(key, _)| of_names(key))
                .map(|(key, shape)| (key.clone(), *shape))
                .collect(),
            responses: (names.iter())
                .filter_map(|name| Some((name.clone(), *self.response_vars.get(name)?)))
                .collect(),
            environment: (names.iter())
                .filter_map(|name| Some((name.clone(), *self.environment_holds.get(name)?)))
                .collect(),
            names,
            outer_live: false,
        };
        self.drop_bindings(&saved.names);
        saved
    }

    /// Give the bindings of `saved` back what they held.
    fn put_bindings(&mut self, saved: ShadowedBindings) {
        self.drop_bindings(&saved.names);
        self.environment_holds.extend(saved.environment);
        self.response_vars.extend(saved.responses);
        if self.flow_slots_saturated {
            return;
        }
        self.flow_vars.extend(saved.vars);
        self.flow_slots.extend(saved.slots);
        self.flow_shapes.extend(saved.shapes);
    }

    /// Forget what the bindings `names` hold, leaving compiled locals to
    /// the scope that restores them.
    fn drop_bindings(&mut self, names: &[String]) {
        for name in names {
            let compiled = self.compiled_vars.remove(name);
            self.kill_flow_name(name);
            self.compiled_vars
                .extend(compiled.map(|compiled| (name.clone(), compiled)));
            self.environment_holds.remove(name);
        }
    }

    /// Buffer a flow stage for the effects an expression at `span` produced in
    /// `[before, after)`, binding each to the stage's `Value` port and recording
    /// the span so the stage can be linked. None when the expression produced none.
    pub(super) fn new_stage(&mut self, span: Span, before: usize, after: usize) -> Option<usize> {
        if after <= before {
            return None;
        }
        let node = self.span_node(span);
        let id = self.stage_writer.new_stage(node, before, after)?;
        self.stage_by_span.insert(span.start, id);
        self.note_environment_stage(id, before, after);
        Some(id)
    }

    /// Restore def-use tracking to its pre-block state after a conditionally-
    /// executed construct, dropping any name whose producer binding changed
    /// inside (added, reassigned, or killed): at the join it is ambiguous. Names
    /// untouched by the block keep their binding.
    pub(super) fn flow_entry(&self) -> FlowEntry {
        FlowEntry {
            vars: self.flow_vars.clone(),
            slots: self.flow_slots.clone(),
            shapes: self.flow_shapes.clone(),
            compiled: self.compiled_vars.clone(),
        }
    }

    pub(super) fn flow_join(&mut self, entry: FlowEntry) {
        // A compiled local the construct may not have rebound stays callable
        // as compiled code, alongside any it may have bound.
        for (name, (depth, producers)) in entry.compiled {
            let joined = self
                .compiled_vars
                .entry(name)
                .or_insert_with(|| (depth, Vec::new()));
            for producer in producers {
                push_unique(&mut joined.1, producer);
            }
        }
        if self.flow_slots_saturated {
            self.flow_vars.clear();
            self.flow_slots.clear();
            self.flow_shapes.clear();
            return;
        }
        let FlowEntry {
            vars: entry_vars,
            slots: entry_slots,
            shapes: entry_shapes,
            ..
        } = entry;
        let mut result = entry_vars.clone();
        for (name, stage) in &self.flow_vars {
            if entry_vars.get(name) != Some(stage) {
                result.remove(name);
            }
        }
        for name in entry_vars.keys() {
            if !self.flow_vars.contains_key(name) {
                result.remove(name);
            }
        }
        self.flow_vars = result;
        self.flow_slots = entry_slots
            .intersection(&self.flow_slots)
            .cloned()
            .collect();
        self.flow_shapes
            .retain(|name, shape| entry_shapes.get(name) == Some(shape));
    }

    /// The producer stage an initializer/assigned value evaluates to. Await,
    /// local aliases, exact property/index reads, and value-preserving promise
    /// operations keep the same producer.
    pub(super) fn init_producer(&self, init: &Expression<'a>) -> Option<usize> {
        self.init_producer_at(init, 0)
    }

    pub(super) fn init_producer_at(&self, init: &Expression<'a>, depth: u32) -> Option<usize> {
        if depth >= 8 {
            return None;
        }
        match unparen(init) {
            Expression::CallExpression(call) => {
                if let Some(stage) = self.stage_by_span.get(&call.span.start) {
                    return Some(*stage);
                }
                if let Expression::StaticMemberExpression(member) = unparen(&call.callee)
                    && matches!(
                        member.property.name.as_str(),
                        // A response body read settles with the response's own
                        // bytes, as does rendering accumulated chunks as text.
                        "finally"
                            | "text"
                            | "json"
                            | "arrayBuffer"
                            | "blob"
                            | "bytes"
                            | "toString"
                            | "join"
                    )
                {
                    // A response object renders as `[object ...]`, not its body.
                    if matches!(member.property.name.as_str(), "toString" | "join")
                        && self.response_kind(&member.object).is_some()
                    {
                        return None;
                    }
                    return self.init_producer_at(&member.object, depth + 1);
                }
                // `Buffer.concat(chunks)` joins the accumulated chunks.
                if let Expression::StaticMemberExpression(member) = unparen(&call.callee)
                    && member.property.name.as_str() == "concat"
                    && matches!(unparen(&member.object), Expression::Identifier(id) if id.name.as_str() == "Buffer")
                    && let Some(chunks) = call.arguments.first().and_then(Argument::as_expression)
                {
                    return self.init_producer_at(chunks, depth + 1);
                }
                None
            }
            Expression::AwaitExpression(a) => self.init_producer_at(&a.argument, depth + 1),
            Expression::Identifier(_) => {
                expression_flow_key(init).and_then(|name| self.flow_vars.get(&name).copied())
            }
            Expression::StaticMemberExpression(member) => self
                .stage_by_span
                .get(&member.span.start)
                .copied()
                .or_else(|| {
                    expression_flow_key(init).and_then(|name| self.flow_vars.get(&name).copied())
                }),
            Expression::ComputedMemberExpression(member) => self
                .stage_by_span
                .get(&member.span.start)
                .copied()
                .or_else(|| {
                    expression_flow_key(init).and_then(|name| self.flow_vars.get(&name).copied())
                }),
            _ => None,
        }
    }

    pub(super) fn bind_flow_pattern(
        &mut self,
        pattern: &oxc_ast::ast::BindingPattern<'a>,
        init: &Expression<'a>,
    ) {
        use oxc_ast::ast::BindingPattern;
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                self.bind_flow_name(id.name.as_str(), init);
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.bind_flow_pattern(&assignment.left, init);
            }
            BindingPattern::ArrayPattern(array) => {
                for (index, element) in array.elements.iter().enumerate() {
                    let Some(element) = element else { continue };
                    if let Some(value) = array_element(init, index) {
                        self.bind_flow_pattern(element, value);
                    } else if let Some(base) = expression_flow_key(init) {
                        self.bind_flow_pattern_from_key(element, &format!("{base}.{index}"));
                    } else {
                        self.kill_flow_pattern(element);
                    }
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    let Some(key) = property.key.static_name() else {
                        self.kill_flow_pattern(&property.value);
                        continue;
                    };
                    if let Some(value) = object_property(init, &key) {
                        self.bind_flow_pattern(&property.value, value);
                    } else if let Some(base) = expression_flow_key(init) {
                        self.bind_flow_pattern_from_key(&property.value, &format!("{base}.{key}"));
                    } else {
                        self.kill_flow_pattern(&property.value);
                    }
                }
            }
        }
    }

    pub(super) fn bind_flow_pattern_from_key(
        &mut self,
        pattern: &oxc_ast::ast::BindingPattern<'a>,
        source: &str,
    ) {
        use oxc_ast::ast::BindingPattern;
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                let target = id.name.as_str();
                self.kill_flow_name(target);
                self.copy_flow_prefix(source, target, true);
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.bind_flow_pattern_from_key(&assignment.left, source);
            }
            BindingPattern::ArrayPattern(array) => {
                for (index, element) in array.elements.iter().enumerate() {
                    if let Some(element) = element {
                        self.bind_flow_pattern_from_key(element, &format!("{source}.{index}"));
                    }
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    if let Some(key) = property.key.static_name() {
                        self.bind_flow_pattern_from_key(
                            &property.value,
                            &format!("{source}.{key}"),
                        );
                    } else {
                        self.kill_flow_pattern(&property.value);
                    }
                }
            }
        }
    }

    pub(super) fn kill_flow_pattern(&mut self, pattern: &oxc_ast::ast::BindingPattern<'a>) {
        use oxc_ast::ast::BindingPattern;
        match pattern {
            BindingPattern::BindingIdentifier(id) => self.kill_flow_name(id.name.as_str()),
            BindingPattern::AssignmentPattern(assignment) => {
                self.kill_flow_pattern(&assignment.left)
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.kill_flow_pattern(element);
                }
                if let Some(rest) = &array.rest {
                    self.kill_flow_pattern(&rest.argument);
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.kill_flow_pattern(&property.value);
                }
                if let Some(rest) = &object.rest {
                    self.kill_flow_pattern(&rest.argument);
                }
            }
        }
    }

    pub(super) fn bind_flow_name(&mut self, name: &str, init: &Expression<'a>) {
        self.kill_flow_name(name);
        if let Some(code) = self.compiled_code(init) {
            let producers = self.code_producers(code);
            self.compiled_vars
                .insert(name.to_string(), (self.active_bodies.len(), producers));
        }
        if self.flow_slots_saturated {
            return;
        }
        if !self.insert_flow_slot(name.to_string()) {
            return;
        }
        if let Some(stage) = self
            .init_producer(init)
            .or_else(|| self.built_text_producer(init))
        {
            self.flow_vars.insert(name.to_string(), stage);
        }
        if let Some(response) = self.response_kind(init) {
            self.response_vars.insert(name.to_string(), response);
        }
        if let Some(source) = expression_flow_key(init) {
            self.copy_flow_prefix(&source, name, true);
        }
        self.bind_flow_properties(name, init);
    }

    pub(super) fn bind_flow_properties(&mut self, name: &str, init: &Expression<'a>) {
        if self.flow_slots_saturated {
            return;
        }
        match unparen(init) {
            Expression::AwaitExpression(awaited) => {
                self.bind_flow_properties(name, &awaited.argument)
            }
            Expression::ObjectExpression(object) => {
                let mut exact = true;
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            if let Some(key) = property.key.static_name() {
                                self.bind_flow_name(&format!("{name}.{key}"), &property.value);
                            } else {
                                self.kill_flow_name(name);
                                if !self.insert_flow_slot(name.to_string()) {
                                    return;
                                }
                                exact = false;
                            }
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            if let Some(source) = expression_flow_key(&spread.argument) {
                                if self.flow_shapes.get(&source) == Some(&FlowShape::Object) {
                                    self.copy_flow_prefix(&source, name, false);
                                } else {
                                    self.kill_flow_name(name);
                                    if !self.insert_flow_slot(name.to_string()) {
                                        return;
                                    }
                                    exact = false;
                                }
                            } else if matches!(
                                unparen(&spread.argument),
                                Expression::ObjectExpression(_)
                            ) {
                                self.bind_flow_properties(name, &spread.argument);
                                exact &= self.flow_shapes.get(name) == Some(&FlowShape::Object);
                            } else {
                                self.kill_flow_name(name);
                                if !self.insert_flow_slot(name.to_string()) {
                                    return;
                                }
                                exact = false;
                            }
                        }
                    }
                }
                if self.flow_slots_saturated {
                    return;
                }
                if exact {
                    self.flow_shapes.insert(name.to_string(), FlowShape::Object);
                } else {
                    self.flow_shapes.remove(name);
                }
            }
            Expression::ArrayExpression(array) => {
                let mut target = 0;
                for element in &array.elements {
                    match element {
                        oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                            if let Some(len) = array_literal_len(&spread.argument) {
                                for index in 0..len {
                                    let target_key = format!("{name}.{}", target + index);
                                    if let Some(value) = array_element(&spread.argument, index) {
                                        self.bind_flow_name(&target_key, value);
                                    } else {
                                        self.kill_flow_name(&target_key);
                                        if !self.insert_flow_slot(target_key) {
                                            return;
                                        }
                                    }
                                }
                                target += len;
                            } else if let Some(source) = expression_flow_key(&spread.argument)
                                && let Some(FlowShape::Array(len)) =
                                    self.flow_shapes.get(&source).copied()
                            {
                                let prefix = format!("{source}.");
                                let mut slots: Vec<_> = self
                                    .flow_slots
                                    .iter()
                                    .filter_map(|key| {
                                        let suffix = key.strip_prefix(&prefix)?;
                                        let (index, rest) = suffix
                                            .split_once('.')
                                            .map_or((suffix, ""), |(index, rest)| (index, rest));
                                        Some((
                                            index.parse::<usize>().ok()?,
                                            rest.to_string(),
                                            key.clone(),
                                        ))
                                    })
                                    .collect();
                                slots.sort_by(|left, right| {
                                    (left.0, left.1.matches('.').count())
                                        .cmp(&(right.0, right.1.matches('.').count()))
                                });
                                for (index, rest, source_key) in slots {
                                    let target_key = if rest.is_empty() {
                                        format!("{name}.{}", target + index)
                                    } else {
                                        format!("{name}.{}.{rest}", target + index)
                                    };
                                    self.kill_flow_name(&target_key);
                                    if !self.insert_flow_slot(target_key.clone()) {
                                        break;
                                    }
                                    if let Some(stage) = self.flow_vars.get(&source_key).copied() {
                                        self.flow_vars.insert(target_key, stage);
                                    }
                                }
                                if self.flow_slots_saturated {
                                    return;
                                }
                                let copied_shapes: Vec<_> = self
                                    .flow_shapes
                                    .iter()
                                    .filter_map(|(key, shape)| {
                                        let suffix = key.strip_prefix(&prefix)?;
                                        let (index, rest) = suffix
                                            .split_once('.')
                                            .map_or((suffix, ""), |(index, rest)| (index, rest));
                                        let index = index.parse::<usize>().ok()?;
                                        let key = if rest.is_empty() {
                                            format!("{name}.{}", target + index)
                                        } else {
                                            format!("{name}.{}.{rest}", target + index)
                                        };
                                        Some((key, *shape))
                                    })
                                    .collect();
                                for (key, shape) in copied_shapes {
                                    self.flow_shapes.insert(key, shape);
                                }
                                target += len;
                            } else {
                                self.kill_flow_name(name);
                                return;
                            }
                        }
                        oxc_ast::ast::ArrayExpressionElement::Elision(_) => {
                            let target_key = format!("{name}.{target}");
                            self.kill_flow_name(&target_key);
                            if !self.insert_flow_slot(target_key) {
                                return;
                            }
                            target += 1;
                        }
                        element => {
                            if let Some(expr) = element.as_expression() {
                                self.bind_flow_name(&format!("{name}.{target}"), expr);
                            }
                            target += 1;
                        }
                    }
                }
                if !self.flow_slots_saturated {
                    self.flow_shapes
                        .insert(name.to_string(), FlowShape::Array(target));
                }
            }
            _ => {}
        }
    }

    pub(super) fn kill_flow_name(&mut self, name: &str) {
        self.response_vars.remove(name);
        self.compiled_vars.remove(name);
        if self.flow_slots_saturated {
            return;
        }
        let prefix = format!("{name}.");
        self.flow_vars
            .retain(|key, _| key != name && !key.starts_with(&prefix));
        self.flow_slots
            .retain(|key| key != name && !key.starts_with(&prefix));
        self.flow_shapes
            .retain(|key, _| key != name && !key.starts_with(&prefix));
    }

    pub(super) fn copy_flow_prefix(&mut self, source: &str, target: &str, include_root: bool) {
        if self.flow_slots_saturated {
            return;
        }
        let prefix = format!("{source}.");
        let mut copied: Vec<_> = self
            .flow_slots
            .iter()
            .filter_map(|key| {
                if key == source {
                    include_root.then(|| (target.to_string(), key.clone()))
                } else {
                    key.strip_prefix(&prefix)
                        .map(|suffix| (format!("{target}.{suffix}"), key.clone()))
                }
            })
            .collect();
        let copied_shapes: Vec<_> = self
            .flow_shapes
            .iter()
            .filter_map(|(key, shape)| {
                if key == source {
                    include_root.then(|| (target.to_string(), *shape))
                } else {
                    key.strip_prefix(&prefix)
                        .map(|suffix| (format!("{target}.{suffix}"), *shape))
                }
            })
            .collect();
        copied.sort_by_key(|(key, _)| key.matches('.').count());
        for (target_key, source_key) in copied {
            self.kill_flow_name(&target_key);
            if !self.insert_flow_slot(target_key.clone()) {
                break;
            }
            if let Some(stage) = self.flow_vars.get(&source_key).copied() {
                self.flow_vars.insert(target_key, stage);
            }
        }
        if self.flow_slots_saturated {
            return;
        }
        for (target_key, shape) in copied_shapes {
            self.flow_shapes.insert(target_key, shape);
        }
    }

    pub(super) fn insert_flow_slot(&mut self, key: String) -> bool {
        if self.flow_slots.contains(&key) {
            return true;
        }
        if self.flow_slots.len() >= MAX_FLOW_SLOTS {
            self.flow_slots_saturated = true;
            self.flow_vars.clear();
            self.flow_slots.clear();
            self.flow_shapes.clear();
            self.builder.note_causality_saturated("max_js_causal_slots");
            return false;
        }
        self.flow_slots.insert(key);
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FlowShape {
    Object,
    Array(usize),
}

/// What a local holding a response object is: a fetch `Response`, which
/// yields its bytes through a body read such as `.text()`, or the message an
/// `http(s).get` response handler receives, which streams them to `data`
/// listeners.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseKind {
    Fetch,
    Message,
}

/// The property values `JSON.stringify(value, keys)` serializes when `value`
/// is an object literal and `keys` a literal list of names: the properties
/// the list keeps. `None` when either hides which those are.
fn kept_properties<'b, 'a>(
    value: &'b Expression<'a>,
    keys: &'b Expression<'a>,
) -> Option<Vec<&'b Expression<'a>>> {
    let (Expression::ObjectExpression(object), Expression::ArrayExpression(keys)) =
        (unparen(value), unparen(keys))
    else {
        return None;
    };
    let keys = keys
        .elements
        .iter()
        .map(|key| match key.as_expression().map(unparen) {
            Some(Expression::StringLiteral(key)) => Some(key.value.as_str()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let mut kept = Vec::new();
    for property in &object.properties {
        let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property else {
            return None;
        };
        let name = property.key.static_name().filter(|_| !property.computed)?;
        if keys.contains(&name.as_ref()) {
            kept.push(&property.value);
        }
    }
    Some(kept)
}

/// Def-use tracking at the entry of a conditionally executed construct.
pub(super) struct FlowEntry {
    vars: HashMap<String, usize>,
    slots: HashSet<String>,
    shapes: HashMap<String, FlowShape>,
    compiled: HashMap<String, (usize, Vec<usize>)>,
}

impl<'a> JsWalker<'_, 'a> {
    // --- Intra-function dataflow (def-use) ---
    //
    // A call that produces an effect is a flow stage; the value it returns is
    // its `Value` port. `const d = <producer>` remembers the stage, and a later
    // use of `d` as (or within) an argument to another producing call emits a
    // `data_flow` edge from the producer's `Value` to the consumer's `Arg(n)`.
    // Conservative and structural: local variables within this walk only.

    /// The producers flowing into the code arguments of a compile expression.
    pub(super) fn code_producers(&self, code: &[Argument<'a>]) -> Vec<usize> {
        let mut producers = Vec::new();
        for argument in code.iter().filter_map(Argument::as_expression) {
            self.collect_producers(argument, &mut producers);
        }
        producers
    }

    /// The code producers of a compiled local a call names, unless a body
    /// entered since its binding declares the same name.
    pub(super) fn compiled_local(&self, callee: &Expression<'a>) -> Option<Vec<usize>> {
        let Expression::Identifier(id) = unparen(callee) else {
            return None;
        };
        let (depth, producers) = self.compiled_vars.get(id.name.as_str())?;
        let shadowed = self
            .active_bodies
            .iter()
            .skip(*depth)
            .any(|body| body.local_names.contains(id.name.as_str()));
        (!shadowed).then(|| producers.clone())
    }

    /// Wire def-use edges into `consumer` from each argument that carries a
    /// tracked variable's value or a producer call nested directly in it.
    pub(super) fn wire_arguments(&mut self, arguments: &[Argument<'a>], consumer: usize) {
        for (idx, arg) in arguments.iter().enumerate() {
            if let Some(expr) = arg.as_expression() {
                let mut producers = Vec::new();
                self.collect_producers(expr, &mut producers);
                for producer in producers {
                    self.stage_writer.add_edge(producer, consumer, idx as u32);
                }
            }
        }
    }

    /// The receiver and arguments a call builds its text from, when it only
    /// transforms text: a string method on a value (`key.trim()`,
    /// `lines.join("\n")`), or a conversion such as `JSON.stringify(v)`,
    /// `String(v)` or `Buffer.from(v)`. A response object renders as
    /// `[object ...]`, not its body.
    fn text_call_parts<'b>(
        &self,
        call: &'b oxc_ast::ast::CallExpression<'a>,
    ) -> Option<Vec<&'b Expression<'a>>> {
        const METHODS: &[&str] = &[
            "at",
            "charAt",
            "concat",
            "join",
            "normalize",
            "padEnd",
            "padStart",
            "repeat",
            "replace",
            "replaceAll",
            "slice",
            "split",
            "substr",
            "substring",
            "toLowerCase",
            "toString",
            "toUpperCase",
            "trim",
            "trimEnd",
            "trimStart",
        ];
        // The methods whose arguments are written into the text; the rest
        // take positions, counts and patterns.
        const WRITTEN: &[&str] = &[
            "concat",
            "join",
            "padEnd",
            "padStart",
            "replace",
            "replaceAll",
        ];
        let mut arguments = call.arguments.iter().filter_map(Argument::as_expression);
        match unparen(&call.callee) {
            // A converter the program binds or replaces is its own function.
            callee @ Expression::Identifier(function) => (function.name != "JSON"
                && function.name != "Buffer"
                && self.bindings.is_runtime_text(callee))
            .then(|| arguments.collect()),
            Expression::StaticMemberExpression(member) => {
                let method = member.property.name.as_str();
                let object = unparen(&member.object);
                let name = match object {
                    Expression::Identifier(object) => object.name.as_str(),
                    _ => "",
                };
                if name == "JSON" && method == "stringify" && self.bindings.is_runtime_text(object)
                {
                    let value = arguments.next()?;
                    let replacer = arguments.next();
                    return Some(
                        match replacer.and_then(|keys| kept_properties(value, keys)) {
                            Some(kept) => kept,
                            // A replacer that is not a literal key list may
                            // return any text of its own.
                            None => std::iter::once(value)
                                .chain(replacer)
                                .chain(arguments)
                                .collect(),
                        },
                    );
                }
                if name == "Buffer"
                    && method == "from"
                    && (self.bindings.is_runtime_text(object)
                        || self
                            .bindings
                            .named
                            .get(name)
                            .is_some_and(|(module, imported)| {
                                module == "buffer" && imported == "Buffer"
                            }))
                {
                    return Some(arguments.take(1).collect());
                }
                if matches!(method, "format" | "inspect")
                    && resolve::module_of(object, self.bindings).as_deref() == Some("util")
                {
                    return Some(arguments.collect());
                }
                // An object literal's method of the same name is the
                // program's own function, not the string method.
                let own_method = expression_flow_key(object)
                    .is_some_and(|key| self.flow_shapes.get(&key) == Some(&FlowShape::Object));
                (METHODS.contains(&method) && !own_method && self.response_kind(object).is_none())
                    .then(|| {
                        std::iter::once(object)
                            .chain(arguments.filter(|_| WRITTEN.contains(&method)))
                            .collect()
                    })
            }
            _ => None,
        }
    }

    /// The stage a binding initialized with built text holds: a join of
    /// what its parts carry, since the text is not the same bytes.
    fn built_text_producer(&mut self, init: &Expression<'a>) -> Option<usize> {
        let built = match unparen(init) {
            Expression::BinaryExpression(sum) => {
                sum.operator == oxc_ast::ast::BinaryOperator::Addition
            }
            Expression::TemplateLiteral(_) => true,
            Expression::CallExpression(call) => self.text_call_parts(call).is_some(),
            Expression::ConditionalExpression(_) | Expression::LogicalExpression(_) => true,
            _ => false,
        };
        if !built {
            return None;
        }
        let mut producers = Vec::new();
        self.collect_producers(init, &mut producers);
        if producers.is_empty() {
            return None;
        }
        let node = self.span_node(init.span());
        let stage = self.stage_writer.join_values(node, &producers);
        self.join_environment_stages(stage, &producers);
        Some(stage)
    }

    /// Collect the producer stages an argument expression references: tracked
    /// variable identifiers and producer calls nested in it (through object
    /// property values, array elements, template holes, `+` and text
    /// transformations). Otherwise shallow: no descent into other nested
    /// call arguments or member chains.
    pub(super) fn collect_producers(&self, expr: &Expression<'a>, out: &mut Vec<usize>) {
        match unparen(expr) {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                let prefix = format!("{name}.");
                for stage in self
                    .flow_vars
                    .iter()
                    .filter(|(key, _)| *key == name || key.starts_with(&prefix))
                    .map(|(_, stage)| *stage)
                {
                    push_unique(out, stage);
                }
            }
            // A length is a count, not the value's bytes.
            Expression::StaticMemberExpression(member) if member.property.name == "length" => {}
            Expression::StaticMemberExpression(member) => {
                if let Some(&stage) = self.stage_by_span.get(&member.span.start) {
                    push_unique(out, stage);
                } else if let Some(name) = expression_flow_key(expr)
                    && let Some(&stage) = self.flow_vars.get(&name)
                {
                    push_unique(out, stage);
                }
            }
            Expression::ComputedMemberExpression(member) => {
                if let Some(&stage) = self.stage_by_span.get(&member.span.start) {
                    push_unique(out, stage);
                } else if let Some(name) = expression_flow_key(expr)
                    && let Some(&stage) = self.flow_vars.get(&name)
                {
                    push_unique(out, stage);
                }
            }
            Expression::AwaitExpression(awaited) => self.collect_producers(&awaited.argument, out),
            // `c ? a : b` is either arm a literal test does not rule out.
            Expression::ConditionalExpression(branch) => {
                let test = literal_truth(&branch.test);
                if test != Some(false) {
                    self.collect_producers(&branch.consequent, out);
                }
                if test != Some(true) {
                    self.collect_producers(&branch.alternate, out);
                }
            }
            // `a || b`, `a && b` and `a ?? b` are either operand.
            Expression::LogicalExpression(logical) => {
                self.collect_producers(&logical.left, out);
                self.collect_producers(&logical.right, out);
            }
            Expression::CallExpression(call) => {
                if let Some(stage) = self.init_producer(expr) {
                    push_unique(out, stage);
                } else if let Some(parts) = self.text_call_parts(call) {
                    for part in parts {
                        self.collect_producers(part, out);
                    }
                }
            }
            // `"key=" + key` is text of both operands.
            Expression::BinaryExpression(sum)
                if sum.operator == oxc_ast::ast::BinaryOperator::Addition =>
            {
                self.collect_producers(&sum.left, out);
                self.collect_producers(&sum.right, out);
            }
            Expression::ObjectExpression(o) => {
                for p in &o.properties {
                    match p {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) => {
                            self.collect_producers(&prop.value, out);
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            self.collect_producers(&spread.argument, out);
                        }
                    }
                }
            }
            Expression::ArrayExpression(a) => {
                for el in &a.elements {
                    match el {
                        oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                            self.collect_producers(&spread.argument, out)
                        }
                        _ => {
                            if let Some(e) = el.as_expression() {
                                self.collect_producers(e, out);
                            }
                        }
                    }
                }
            }
            Expression::TemplateLiteral(t) => {
                for e in &t.expressions {
                    self.collect_producers(e, out);
                }
            }
            _ => {}
        }
    }
}

/// Push `value` into `out` if not already present (small sets, linear scan).
fn push_unique(out: &mut Vec<usize>, value: usize) {
    if !out.contains(&value) {
        out.push(value);
    }
}
