//! JavaScript require, eval, nested drafts, and property descriptors.

use super::*;

impl Interpreter<'_> {
    pub(super) fn require(&mut self, arguments: Arguments) -> Value {
        if !arguments.complete || arguments.values.len() != 1 {
            self.complete = false;
            return Value::Unknown;
        }
        let value =
            arguments
                .values
                .first()
                .and_then(value_string)
                .map_or(Value::Unknown, |source| match source {
                    "module" | "node:module" => Value::NodeModule,
                    source => module_from_source(source).map_or(Value::Unknown, Value::Module),
                });
        if value == Value::Unknown {
            self.complete = false;
        }
        value
    }

    pub(super) fn eval_source(&mut self, arguments: Arguments, state: &mut State) -> Value {
        if !arguments.complete {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        let Some(value) = arguments.values.first() else {
            return Value::Undefined;
        };
        let source = match value {
            Value::String(source) => source,
            Value::Unknown | Value::UnknownModuleMember(_) | Value::UnknownReceiver(_) => {
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                return Value::Unknown;
            }
            value => return value.clone(),
        };
        if !self.budget.enter_dynamic_source(source.len()) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        if self.depth + 1 >= 16 {
            self.report.refuse(InlineRefusal::RecursionLimit);
            self.complete = false;
            state.widen();
            return Value::Unknown;
        }
        let module = match super::super::parser::javascript(source) {
            Ok(module) if module.executable() && named_children(module.root()).next().is_none() => {
                return Value::Undefined;
            }
            Ok(module) if module.executable() => module,
            Ok(_) => return Value::SynchronousThrow,
            Err(InlineRefusal::StructureIncomplete | InlineRefusal::StructureMismatch) => {
                return Value::SynchronousThrow;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                self.complete = false;
                state.widen();
                return Value::Unknown;
            }
        };
        let mutates = source_mutates(module.root());
        let mut nested = Interpreter {
            source,
            home: self.home,
            platform: self.platform,
            depth: self.depth + 1,
            profile: Profile {
                syntax: SyntaxProfile::JavaScript,
                ..self.profile
            },
            strict: self.strict
                || strict_directive(module.root(), source)
                || source_is_module(module.root()),
            report: InlineReport::default(),
            draft: LanguageDraft::default(),
            complete: true,
            budget: Budget::default(),
            return_value: Value::Undefined,
            conditional_depth: self.conditional_depth,
            catchable_depth: self.catchable_depth,
            execution_dominators: Vec::new(),
            awaited_call: None,
            async_frames: Vec::new(),
        };
        let mut nested_state = state.clone();
        nested.hoist_vars(module.root(), &mut nested_state);
        let nested_control = nested.exec_sequence(module.root(), &mut nested_state, false, 0);
        let failed = nested.budget.refusal.is_some();
        if let Some(refusal) = nested.budget.refusal {
            nested.report.refuse(refusal);
            nested.draft.set_partial();
        }
        if !nested.complete {
            nested.draft.set_partial();
        }
        self.report.extend(nested.report);
        self.merge_nested_draft(&nested.draft, &nested.execution_dominators);
        self.complete &= nested.complete;
        self.budget.absorb(nested.budget);
        if mutates || failed {
            state.widen();
        } else {
            *state = nested_state;
        }
        match nested_control {
            Control::Next => Value::DynamicEvalResult,
            Control::Throw | Control::Return | Control::Break | Control::Continue => {
                Value::SynchronousThrow
            }
            Control::Diverge => Value::Divergent,
        }
    }

    pub(super) fn merge_nested_draft(
        &mut self,
        nested: &LanguageDraft,
        nested_dominators: &[usize],
    ) {
        if !nested.complete() {
            self.draft.set_partial();
        }
        for refusal in nested.refusals() {
            self.draft.refuse(*refusal);
        }
        let external_dominators = self.execution_dominators.clone();
        let mut ordinals = Vec::with_capacity(nested.language_safety_calls().len());
        for call in nested.language_safety_calls() {
            let mut dominators = external_dominators.clone();
            dominators.extend(
                call.execution_dominators()
                    .iter()
                    .filter_map(|ordinal| ordinals.get(*ordinal).copied().flatten()),
            );
            dominators.sort_unstable();
            dominators.dedup();
            let call = LanguageCall::new(
                call.kind(),
                call.input().clone(),
                call.filesystems().to_vec(),
                call.endpoint().map(str::to_owned),
                call.conditional_depth(),
                dominators,
            );
            ordinals.push(self.draft.push_call(call));
        }
        for flow in nested.language_safety_flows() {
            if let (Some(Some(from)), Some(Some(to))) =
                (ordinals.get(flow.from()), ordinals.get(flow.to()))
            {
                self.draft.push_flow(*from, *to);
            }
        }
        self.execution_dominators.extend(
            nested_dominators
                .iter()
                .filter_map(|ordinal| ordinals.get(*ordinal).copied().flatten()),
        );
        self.execution_dominators.sort_unstable();
        self.execution_dominators.dedup();
    }

    pub(super) fn materialize_property_descriptor(
        &mut self,
        descriptor: Value,
        state: &mut State,
        call_depth: usize,
    ) -> Result<Value, Value> {
        let Value::Object(mut properties) = descriptor else {
            return Ok(descriptor);
        };
        for property in [
            "enumerable",
            "configurable",
            "value",
            "writable",
            "get",
            "set",
        ] {
            let value = match properties.get(property).cloned() {
                Some(Value::AccessorGetter(getter)) => self.call_local(
                    &getter,
                    Arguments {
                        values: Vec::new(),
                        complete: true,
                        uncertain_from: None,
                        assembly_branches: Vec::new(),
                    },
                    state,
                    call_depth,
                    false,
                ),
                Some(Value::Accessor) => Value::Undefined,
                _ => continue,
            };
            if abrupt_value(&value) {
                return Err(value);
            }
            properties.insert(property.to_owned(), value);
        }
        Ok(Value::Object(properties))
    }
}
