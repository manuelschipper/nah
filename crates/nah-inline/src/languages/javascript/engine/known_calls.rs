//! Dispatches proven owned JavaScript runtime APIs to reviewed semantics.

use super::*;

impl Interpreter<'_> {
    pub(super) fn call_known(
        &mut self,
        function: KnownFunction,
        mut arguments: Arguments,
        state: &mut State,
        call_depth: usize,
        _tagged_template: bool,
    ) -> Value {
        match function {
            KnownFunction::DefineProperty => {
                let target = arguments.values.first().cloned().unwrap_or(Value::Unknown);
                if invalid_define_property_target(&target) {
                    return Value::SynchronousThrow;
                }
                if arguments.complete
                    && let Some(descriptor) = arguments.values.get(2).cloned()
                {
                    match self.materialize_property_descriptor(descriptor, state, call_depth) {
                        Ok(descriptor) => arguments.values[2] = descriptor,
                        Err(value) => return value,
                    }
                }
                if arguments.complete
                    && (arguments.values.len() < 3
                        || arguments
                            .values
                            .get(2)
                            .is_some_and(invalid_property_descriptor))
                {
                    return Value::SynchronousThrow;
                }
                if arguments.complete
                    && let Some(property) = node_define_property_target(&arguments)
                    && state.node_properties.get(&property).is_some_and(|current| {
                        arguments.values.get(2).is_some_and(|descriptor| {
                            invalid_node_property_redefinition(current, descriptor)
                        })
                    })
                {
                    return Value::SynchronousThrow;
                }
                if arguments.complete && invalid_node_prototype_constructor_definition(&arguments) {
                    return Value::SynchronousThrow;
                }
                self.complete = false;
                if arguments.values.first().is_none_or(unknown_value) {
                    state.prototype_integrity_known = false;
                }
                let reviewed_node_definition = arguments.complete
                    && arguments.values.len() >= 3
                    && node_define_property_target(&arguments).is_some();
                if !reviewed_node_definition {
                    for value in arguments.values.iter().skip(1) {
                        state.invalidate_node_module_escape(value);
                    }
                }
                if let Some(Value::NodeModule) = arguments.values.first() {
                    if arguments.complete && arguments.values.len() >= 3 {
                        if let Some(property) = arguments.values.get(1).and_then(value_string)
                            && let Some(property) = node_module_property(property)
                        {
                            self.define_node_property(property, &arguments, state);
                        } else if arguments.values.get(1).and_then(value_string).is_none() {
                            state.invalidate_node_module_properties();
                        }
                    } else {
                        state.invalidate_node_module_properties();
                    }
                } else if let Some(Value::NodeModulePrototype) = arguments.values.first() {
                    if arguments.complete && arguments.values.len() >= 3 {
                        if arguments.values.get(1).and_then(value_string) == Some("require") {
                            self.define_node_property(
                                NodeProperty::PrototypeRequire,
                                &arguments,
                                state,
                            );
                        } else if arguments.values.get(1).and_then(value_string).is_none() {
                            state.invalidate_node_module_properties();
                        }
                    } else {
                        state.invalidate_node_module_properties();
                    }
                } else if let Some(Value::CommonJsModule) = arguments.values.first() {
                    if arguments.complete && arguments.values.len() >= 3 {
                        if let Some(property) = arguments.values.get(1).and_then(value_string)
                            && let Some(property) = commonjs_module_property(property)
                        {
                            self.define_node_property(property, &arguments, state);
                        } else if arguments.values.get(1).and_then(value_string).is_none() {
                            state.invalidate_node_module_properties();
                        }
                    } else {
                        state.invalidate_node_module_properties();
                    }
                } else if let Some(Value::Object(_) | Value::Array(_)) = arguments.values.first() {
                    if arguments.complete
                        && arguments.values.len() >= 3
                        && arguments.values.get(1).and_then(value_string).is_some()
                    {
                        state.forget_container(&arguments.values[0]);
                    } else {
                        state.invalidate_value(&arguments.values[0]);
                    }
                } else if let Some(Value::Module(module)) = arguments.values.first() {
                    if arguments.complete
                        && arguments.values.len() >= 3
                        && let Some(property) = arguments.values.get(1).and_then(value_string)
                        && let Some(member) = module_member(*module, property)
                    {
                        state.owned_members.remove(&(*module, member));
                    } else {
                        state.invalidate_module(*module);
                    }
                } else if let Some(value) = arguments.values.first() {
                    state.invalidate_value(value);
                }
                target
            }
            KnownFunction::SetPrototypeOf => {
                self.complete = false;
                self.draft.set_partial();
                state.prototype_integrity_known = false;
                arguments.values.first().cloned().unwrap_or(Value::Unknown)
            }
            KnownFunction::Fs(module, member) => {
                match summarize_fs_call(module, member, &arguments) {
                    FsCallSummary::Effect(filesystems) => {
                        let ordinal = self.emit_call(
                            LanguageCallKind::DirectFile,
                            fs_callable(module, member),
                            &arguments,
                            state,
                            filesystems,
                        );
                        if fs_callback_unmodeled(module, member) {
                            self.complete = false;
                            self.draft.set_partial();
                            if let Some(Value::Function(callback)) = arguments.values.last() {
                                self.analyze_callback(callback, state, call_depth, ordinal);
                            }
                        }
                    }
                    FsCallSummary::EffectPartial(filesystems) => {
                        self.emit_call(
                            LanguageCallKind::DirectFile,
                            fs_callable(module, member),
                            &arguments,
                            state,
                            filesystems,
                        );
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Invalid => {}
                }
                fs_return_value(module, member)
            }
            KnownFunction::ProcessChdir => {
                if !arguments.complete || arguments.values.len() != 1 {
                    return Value::SynchronousThrow;
                }
                match &arguments.values[0] {
                    Value::String(path) if !path.is_empty() && !path.contains('\0') => {
                        self.emit_call(
                            LanguageCallKind::LocalUtility,
                            "process.chdir",
                            &arguments,
                            state,
                            Vec::new(),
                        );
                        state.cwd = state.cwd.changed(path, self.platform);
                        Value::Undefined
                    }
                    value if unknown_value(value) => {
                        self.complete = false;
                        self.draft.set_partial();
                        state.cwd = NestedExecutionCwd::Unknown;
                        Value::Unknown
                    }
                    _ => Value::SynchronousThrow,
                }
            }
            KnownFunction::Child(member) => {
                match summarize_child_call(member, &arguments, self.platform, &state.cwd) {
                    ChildCallSummary::Call {
                        kind,
                        execution,
                        callback,
                        partial,
                    } => {
                        let ordinal = self.emit_call(
                            kind,
                            child_callable(member),
                            &arguments,
                            state,
                            Vec::new(),
                        );
                        match execution {
                            ChildExecution::Command { argv, cwd } => {
                                super::super::super::common::add_exact_argv_at(
                                    &mut self.report,
                                    argv,
                                    cwd,
                                    false,
                                );
                            }
                            ChildExecution::Bash { code, cwd } => {
                                super::super::super::common::add_exact_shell_program_at(
                                    &mut self.report,
                                    "bash",
                                    &code,
                                    cwd,
                                    false,
                                );
                            }
                            ChildExecution::OpaqueShell { program, code, cwd } => {
                                super::super::super::common::add_exact_shell_program_at(
                                    &mut self.report,
                                    &program,
                                    &code,
                                    cwd,
                                    false,
                                );
                            }
                            ChildExecution::None => {}
                        }
                        if let Some(index) = callback
                            && let Some(Value::Function(callback)) = arguments.values.get(index)
                        {
                            self.analyze_callback(callback, state, call_depth, ordinal);
                        }
                        if partial {
                            self.complete = false;
                            self.draft.set_partial();
                        }
                        Value::Object(BTreeMap::new())
                    }
                    ChildCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    ChildCallSummary::Invalid => Value::Unknown,
                }
            }
            KnownFunction::Deno(DenoMember::Chdir) => {
                if !arguments.complete || arguments.values.len() != 1 {
                    return Value::SynchronousThrow;
                }
                match &arguments.values[0] {
                    Value::String(path) if !path.is_empty() && !path.contains('\0') => {
                        self.emit_call(
                            LanguageCallKind::LocalUtility,
                            "Deno.chdir",
                            &arguments,
                            state,
                            Vec::new(),
                        );
                        state.cwd = state.cwd.changed(path, self.platform);
                        Value::Undefined
                    }
                    value if unknown_value(value) => {
                        self.complete = false;
                        self.draft.set_partial();
                        state.cwd = NestedExecutionCwd::Unknown;
                        Value::Unknown
                    }
                    _ => Value::SynchronousThrow,
                }
            }
            KnownFunction::Deno(member) => {
                let summary =
                    summarize_deno_call(member, &arguments, state.prototype_integrity_known);
                match summary {
                    FsCallSummary::Effect(filesystems) => {
                        self.emit_call(
                            LanguageCallKind::DirectFile,
                            deno_callable(member),
                            &arguments,
                            state,
                            filesystems,
                        );
                    }
                    FsCallSummary::EffectPartial(filesystems) => {
                        self.emit_call(
                            LanguageCallKind::DirectFile,
                            deno_callable(member),
                            &arguments,
                            state,
                            filesystems,
                        );
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Invalid if deno_member_synchronous(member) => {
                        return Value::SynchronousThrow;
                    }
                    FsCallSummary::Invalid => return Value::RejectedPromise,
                }
                if deno_member_synchronous(member) {
                    Value::Unknown
                } else {
                    Value::Promise
                }
            }
            KnownFunction::DenoCommand(member, command) => {
                if !arguments.complete {
                    self.complete = false;
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                let command = match refresh_deno_command(
                    command,
                    state.prototype_integrity_known,
                    self.platform,
                ) {
                    RuntimeCallSummary::Effect(command) => command,
                    RuntimeCallSummary::EffectPartial(command) => {
                        self.complete = false;
                        self.draft.set_partial();
                        command
                    }
                    RuntimeCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        return Value::Unknown;
                    }
                    RuntimeCallSummary::Invalid => return Value::SynchronousThrow,
                };
                let cwd = match &command.cwd {
                    NestedExecutionCwd::Inherited => state.cwd.clone(),
                    NestedExecutionCwd::Path(path) => state.cwd.changed(path, self.platform),
                    NestedExecutionCwd::Unknown => NestedExecutionCwd::Unknown,
                };
                let context_exact = command.context_exact && cwd != NestedExecutionCwd::Unknown;
                let evidence = Arguments {
                    values: vec![command.argv.as_ref().map_or(Value::Unknown, |argv| {
                        Value::Array(argv.iter().cloned().map(Value::String).collect())
                    })],
                    complete: true,
                    assembly_branches: Vec::new(),
                };
                let certainty = if member == DenoCommandMember::Spawn {
                    command.spawn
                } else {
                    command.output
                };
                if certainty == ExecutionCertainty::Known {
                    self.emit_call(
                        LanguageCallKind::LocalUtility,
                        deno_command_callable(member),
                        &evidence,
                        state,
                        Vec::new(),
                    );
                    if context_exact && let Some(argv) = command.argv.clone() {
                        let stdout_inherited = if member == DenoCommandMember::Spawn {
                            command.spawn_stdout_inherited
                        } else {
                            command.output_stdout_inherited
                        };
                        if stdout_inherited {
                            super::super::super::common::add_exact_argv_at(
                                &mut self.report,
                                argv,
                                cwd.clone(),
                                true,
                            );
                        } else {
                            super::super::super::common::add_exact_argv_at(
                                &mut self.report,
                                argv,
                                cwd.clone(),
                                false,
                            );
                        }
                    }
                } else if certainty == ExecutionCertainty::Unknown {
                    self.emit_call(
                        LanguageCallKind::LocalUtility,
                        deno_command_callable(member),
                        &evidence,
                        state,
                        Vec::new(),
                    );
                    self.complete = false;
                    self.draft.set_partial();
                } else {
                    return Value::SynchronousThrow;
                }
                if certainty == ExecutionCertainty::Known
                    && (!context_exact || command.argv.is_none())
                {
                    self.complete = false;
                    self.draft.set_partial();
                }
                let throws_after_effect = match member {
                    DenoCommandMember::Spawn => command.spawn_throws_after_effect,
                    DenoCommandMember::Output => command.output_throws_after_effect,
                    DenoCommandMember::OutputSync => false,
                };
                if throws_after_effect {
                    return Value::SynchronousThrow;
                }
                if member == DenoCommandMember::Output {
                    Value::Promise
                } else {
                    Value::Object(BTreeMap::new())
                }
            }
            KnownFunction::Bun(member) => match member {
                BunMember::File => match bun_file(&arguments, state.prototype_integrity_known) {
                    RuntimeCallSummary::Effect(path) => Value::BunFile(path),
                    RuntimeCallSummary::EffectPartial(path) => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::BunFile(path)
                    }
                    RuntimeCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    RuntimeCallSummary::Invalid => Value::SynchronousThrow,
                },
                BunMember::Spawn | BunMember::SpawnSync => {
                    match bun_spawn_argv(
                        &arguments,
                        state.prototype_integrity_known,
                        &state.cwd,
                        self.platform,
                    ) {
                        RuntimeCallSummary::Effect(summary) => {
                            self.emit_call(
                                LanguageCallKind::LocalUtility,
                                bun_callable(member),
                                &arguments,
                                state,
                                Vec::new(),
                            );
                            if summary.context_exact
                                && let Some(argv) = summary.argv
                            {
                                super::super::super::common::add_exact_argv_at(
                                    &mut self.report,
                                    argv,
                                    summary.cwd,
                                    summary.stdout_inherited,
                                );
                            } else {
                                self.complete = false;
                                self.draft.set_partial();
                            }
                            Value::Object(BTreeMap::new())
                        }
                        RuntimeCallSummary::EffectPartial(_summary) => {
                            self.emit_call(
                                LanguageCallKind::LocalUtility,
                                bun_callable(member),
                                &arguments,
                                state,
                                Vec::new(),
                            );
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Object(BTreeMap::new())
                        }
                        RuntimeCallSummary::Partial => {
                            self.emit_call(
                                LanguageCallKind::LocalUtility,
                                bun_callable(member),
                                &arguments,
                                state,
                                Vec::new(),
                            );
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Object(BTreeMap::new())
                        }
                        RuntimeCallSummary::Invalid => Value::SynchronousThrow,
                    }
                }
                BunMember::Write => {
                    match summarize_bun_write(&arguments, state.prototype_integrity_known) {
                        FsCallSummary::Effect(filesystems) => {
                            self.emit_call(
                                LanguageCallKind::DirectFile,
                                bun_callable(member),
                                &arguments,
                                state,
                                filesystems,
                            );
                            Value::Promise
                        }
                        FsCallSummary::EffectPartial(filesystems) => {
                            self.emit_call(
                                LanguageCallKind::DirectFile,
                                bun_callable(member),
                                &arguments,
                                state,
                                filesystems,
                            );
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Promise
                        }
                        FsCallSummary::Partial => {
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Promise
                        }
                        FsCallSummary::Invalid => Value::SynchronousThrow,
                    }
                }
            },
            KnownFunction::BunFile(member, path) => {
                if !arguments.complete {
                    self.complete = false;
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                let operation = if member == BunFileMember::Delete {
                    FilesystemOperation::Delete
                } else {
                    FilesystemOperation::Read
                };
                self.emit_call(
                    LanguageCallKind::DirectFile,
                    bun_file_callable(member),
                    &arguments,
                    state,
                    vec![LanguageFilesystem::new(path, operation, false)],
                );
                Value::Promise
            }
            KnownFunction::BunShell => {
                self.complete = false;
                self.draft.set_partial();
                Value::Promise
            }
            KnownFunction::OpenClaw(member) => match summarize_openclaw_call(&arguments) {
                RuntimeCallSummary::Partial => {
                    let _ = member;
                    self.complete = false;
                    self.draft.set_partial();
                    Value::Promise
                }
                RuntimeCallSummary::Effect(()) | RuntimeCallSummary::EffectPartial(()) => {
                    Value::Promise
                }
                RuntimeCallSummary::Invalid => Value::RejectedPromise,
            },
        }
    }
}
