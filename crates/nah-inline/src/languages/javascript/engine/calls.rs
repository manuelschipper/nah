//! JavaScript calls, construction, dynamic functions, and argument evaluation.

use super::*;

impl Interpreter<'_> {
    pub(super) fn call(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let awaited = self.awaited_call == Some(node as *const HirNode as usize);
        let function = node.child(HirField::Function);
        let direct_receiver = function.is_some_and(direct_receiver_expression);
        let tagged_template = node
            .child(HirField::Arguments)
            .is_some_and(|arguments| arguments.kind() == HirKind::TemplateString);
        let callable = function.map_or(Value::Unknown, |function| {
            self.eval(function, state, call_depth)
        });
        if abrupt_value(&callable) {
            return callable;
        }
        let mut arguments = node.child(HirField::Arguments).map_or_else(
            || Arguments {
                values: Vec::new(),
                complete: false,
                assembly_branches: Vec::new(),
            },
            |arguments| self.arguments(arguments, state, call_depth),
        );
        let mut branches = std::mem::take(&mut arguments.assembly_branches);
        let value = (|| {
            if let Some(value) = arguments.values.iter().find(|value| abrupt_value(value)) {
                return value.clone();
            }
            let selective_define_property =
                matches!(&callable, Value::Known(KnownFunction::DefineProperty));
            if !selective_define_property {
                for value in &arguments.values {
                    state.invalidate_node_module_escape(value);
                }
            }
            match callable {
                Value::Invalid => Value::SynchronousThrow,
                Value::SynchronousThrow | Value::Divergent => callable,
                Value::Promise | Value::RejectedPromise => Value::SynchronousThrow,
                callable if exact_non_callable(&callable) => Value::SynchronousThrow,
                Value::Require => self.require(arguments),
                Value::NodeModuleMember(NodeModuleMember::IsBuiltin) => Value::Unknown,
                Value::NodeModuleMember(
                    member @ (NodeModuleMember::Load | NodeModuleMember::Require),
                ) => {
                    debug_assert!(node_module_loader_hook(member));
                    let loaded = self.require(arguments);
                    state.invalidate_node_module_loader();
                    self.complete = false;
                    match loaded {
                        Value::Module(module) => Value::LoadedModule(module),
                        value => value,
                    }
                }
                Value::NodeModuleMember(member) => {
                    debug_assert!(node_module_loader_hook(member));
                    state.invalidate_node_module_loader();
                    self.complete = false;
                    Value::Unknown
                }
                Value::Eval => self.eval_source(arguments, state),
                Value::DenoCommandConstructor => Value::SynchronousThrow,
                Value::DynamicEvalResult => {
                    self.complete = false;
                    self.draft.set_partial();
                    state.widen();
                    Value::Unknown
                }
                Value::FunctionConstructor => self.dynamic_function(arguments, state),
                Value::DynamicFunction(body) => {
                    self.call_dynamic_function(body.as_deref(), arguments, state)
                }
                Value::Known(function)
                    if direct_receiver_required(&function) && !direct_receiver =>
                {
                    Value::SynchronousThrow
                }
                Value::Known(function) => {
                    self.call_known(function, arguments, state, call_depth, tagged_template)
                }
                Value::Function(function) => {
                    self.call_local(&function, arguments, state, call_depth, awaited)
                }
                Value::UnknownModuleMember(module) => {
                    state.invalidate_module(module);
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.complete = false;
                    Value::Unknown
                }
                Value::UnknownReceiver(receiver) => {
                    state.invalidate_value(&receiver);
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.complete = false;
                    Value::Unknown
                }
                _ => {
                    for value in &arguments.values {
                        state.invalidate_value(value);
                    }
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.complete = false;
                    Value::Unknown
                }
            }
        })();
        self.close_assembly_branches(state, &mut branches);
        value
    }

    pub(super) fn construct(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        let constructor_node = node.child(HirField::Constructor);
        let constructor = constructor_node.map_or(Value::Unknown, |constructor| {
            self.eval(constructor, state, call_depth)
        });
        if abrupt_value(&constructor) {
            return constructor;
        }
        let mut arguments = node.child(HirField::Arguments).map_or_else(
            || Arguments {
                values: Vec::new(),
                complete: false,
                assembly_branches: Vec::new(),
            },
            |arguments| self.arguments(arguments, state, call_depth),
        );
        let mut branches = std::mem::take(&mut arguments.assembly_branches);
        let value = (|| {
            if let Some(value) = arguments.values.iter().find(|value| abrupt_value(value)) {
                return value.clone();
            }
            if constructor == Value::DenoCommandConstructor {
                let summary =
                    deno_command(&arguments, state.prototype_integrity_known, self.platform);
                let summary = attach_deno_command_source(summary, &arguments);
                return match summary {
                    RuntimeCallSummary::Effect(argv) => Value::DenoCommand(argv),
                    RuntimeCallSummary::EffectPartial(argv) => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::DenoCommand(argv)
                    }
                    RuntimeCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    RuntimeCallSummary::Invalid => Value::Invalid,
                };
            }
            if constructor == Value::Invalid {
                return Value::Invalid;
            }
            if constructor == Value::DynamicEvalResult {
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                return Value::Unknown;
            }
            if constructor == Value::FunctionConstructor {
                return self.dynamic_function(arguments, state);
            }
            if let Value::DynamicFunction(body) = constructor {
                let value = self.call_dynamic_function(body.as_deref(), arguments, state);
                return if abrupt_value(&value) {
                    value
                } else {
                    Value::Object(BTreeMap::new())
                };
            }
            if let Value::Known(function) = constructor {
                return match function {
                    KnownFunction::Deno(member) if deno_member_constructible(member) => {
                        let value = self.call_known(
                            KnownFunction::Deno(member),
                            arguments,
                            state,
                            call_depth,
                            false,
                        );
                        if abrupt_value(&value) || member == DenoMember::WriteTextFile {
                            value
                        } else {
                            Value::Object(BTreeMap::new())
                        }
                    }
                    KnownFunction::BunShell => {
                        self.complete = false;
                        self.draft.set_partial();
                        state.widen();
                        Value::Unknown
                    }
                    KnownFunction::Deno(_)
                    | KnownFunction::DenoCommand(_, _)
                    | KnownFunction::Bun(_)
                    | KnownFunction::BunFile(_, _)
                    | KnownFunction::OpenClaw(_)
                    | KnownFunction::ProcessChdir => Value::SynchronousThrow,
                    function => {
                        for value in &arguments.values {
                            state.invalidate_value(value);
                        }
                        state.cwd = NestedExecutionCwd::Unknown;
                        self.complete = false;
                        let _ = function;
                        Value::Unknown
                    }
                };
            }
            if matches!(constructor, Value::Promise | Value::RejectedPromise) {
                return Value::SynchronousThrow;
            }
            for value in &arguments.values {
                state.invalidate_value(value);
            }
            state.cwd = NestedExecutionCwd::Unknown;
            self.complete = false;
            Value::Unknown
        })();
        self.close_assembly_branches(state, &mut branches);
        value
    }

    pub(super) fn dynamic_function(&mut self, arguments: Arguments, state: &mut State) -> Value {
        if !arguments.complete {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        }
        let Some(values) = arguments
            .values
            .iter()
            .map(string_coercion)
            .collect::<Option<Vec<_>>>()
        else {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        };
        let (parameters, body) = values
            .split_last()
            .map_or((&[][..], ""), |(body, parameters)| {
                (parameters, body.as_str())
            });
        let Some(parameter_bytes) = parameters.iter().try_fold(0usize, |bytes, parameter| {
            bytes.checked_add(parameter.len())?.checked_add(1)
        }) else {
            self.budget.refuse();
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        };
        let Some(source_bytes) = parameter_bytes.checked_add(body.len()) else {
            self.budget.refuse();
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        };
        if !self.budget.enter_dynamic_source(source_bytes) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        }
        match super::super::parser::javascript_dynamic_function(parameters, body) {
            Ok(true) => {
                let body = parameters.is_empty().then(|| body.to_owned());
                Value::DynamicFunction(body)
            }
            Ok(false)
            | Err(InlineRefusal::StructureIncomplete | InlineRefusal::StructureMismatch) => {
                Value::SynchronousThrow
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                Value::DynamicFunction(None)
            }
        }
    }

    pub(super) fn call_dynamic_function(
        &mut self,
        body: Option<&str>,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        let Some(body) = body else {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        };
        if !arguments.complete || !self.budget.enter_dynamic_source(body.len()) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        if self.depth + 1 >= 16 {
            self.report.refuse(InlineRefusal::RecursionLimit);
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        let module = match super::super::parser::javascript_function_body(body) {
            Ok(module) if module.executable() => module,
            Ok(_) | Err(InlineRefusal::StructureIncomplete | InlineRefusal::StructureMismatch) => {
                return Value::SynchronousThrow;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                return Value::Unknown;
            }
        };
        let mut nested = Interpreter {
            source: body,
            home: self.home,
            platform: self.platform,
            depth: self.depth + 1,
            profile: Profile {
                syntax: SyntaxProfile::JavaScript,
                ..self.profile
            },
            strict: strict_directive(module.root(), body),
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
        let mut nested_state = state.dynamic_global(self.profile.ownership);
        nested_state.push_scope(true);
        nested.hoist_vars(module.root(), &mut nested_state);
        let control = nested.exec_sequence(module.root(), &mut nested_state, false, 0);
        nested_state.pop_scope();
        let failed = nested.budget.refusal.is_some();
        if let Some(refusal) = nested.budget.refusal {
            nested.report.refuse(refusal);
            nested.draft.set_partial();
        }
        if !nested.complete {
            nested.draft.set_partial();
        }
        let return_value = nested.return_value.clone();
        self.report.extend(nested.report);
        self.merge_nested_draft(&nested.draft, &nested.execution_dominators);
        self.complete &= nested.complete;
        self.budget.absorb(nested.budget);
        if source_mutates(module.root()) || failed || !nested.complete {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
        }
        let value = match control {
            Control::Next => Value::Undefined,
            Control::Return => return_value,
            Control::Throw => Value::SynchronousThrow,
            Control::Diverge => Value::Divergent,
            Control::Break | Control::Continue => Value::SynchronousThrow,
        };
        if contains_local_function(&value) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            Value::Unknown
        } else {
            value
        }
    }

    pub(super) fn arguments(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Arguments {
        let mut arguments = Arguments {
            values: Vec::new(),
            complete: !delimited_has_hole(node, self.source),
            assembly_branches: Vec::new(),
        };
        let mut branches = Vec::new();
        for child in named_children(node) {
            if child.kind() == HirKind::SpreadElement {
                let value = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                if abrupt_value(&value) {
                    arguments.values.push(value);
                    break;
                }
                if exact_non_iterable(&value) {
                    arguments.values.push(Value::SynchronousThrow);
                    break;
                }
                match value {
                    Value::Array(values)
                        if arguments.values.len() + values.len() <= MAX_COLLECTION_ITEMS =>
                    {
                        arguments.values.extend(values);
                    }
                    Value::String(value)
                        if arguments.values.len() + value.chars().count()
                            <= MAX_COLLECTION_ITEMS =>
                    {
                        arguments
                            .values
                            .extend(value.chars().map(|value| Value::String(value.to_string())));
                    }
                    Value::Array(_) | Value::String(_) => arguments.complete = false,
                    _ => {
                        arguments.complete = false;
                        self.start_assembly_branch(state, &mut branches);
                    }
                }
            } else {
                let value = self.eval(child, state, call_depth);
                let abrupt = abrupt_value(&value);
                arguments.values.push(value);
                if abrupt {
                    break;
                }
            }
            if arguments.values.len() > MAX_COLLECTION_ITEMS {
                arguments.complete = false;
                arguments.values.truncate(MAX_COLLECTION_ITEMS);
                self.budget.refuse();
                break;
            }
        }
        if !arguments.complete {
            self.complete = false;
        }
        arguments.assembly_branches = branches;
        arguments
    }
}
