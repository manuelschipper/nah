//! JavaScript def-use flow tracking: the flow stage an expression produces,
//! which stage each binding, pattern element and object property currently
//! holds, and how those slots join after a branch.

use oxc_ast::ast::{Argument, Expression};
use oxc_span::Span;

use super::{
    EffectVisitor, FlowEntry, FlowShape, MAX_FLOW_SLOTS, array_element, array_literal_len,
    expression_flow_key, object_property, push_unique, unparen,
};

impl<'a> EffectVisitor<'_, 'a> {
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
        if let Some(stage) = self.init_producer(init) {
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
