//! Dispatches proven owned Python APIs to their reviewed runtime semantics.

use super::*;

impl Interpreter<'_> {
    pub(super) fn call_known(
        &mut self,
        function: KnownFunction,
        arguments: Arguments,
        state: &mut State,
        depth: usize,
    ) -> Value {
        match function {
            KnownFunction::GetIpython => {
                if arguments.complete
                    && arguments.positional.is_empty()
                    && arguments.keywords.is_empty()
                    && !state.invalid_modules.contains(&Module::Ipython)
                {
                    Value::Module(Module::Ipython)
                } else {
                    Value::Unknown
                }
            }
            KnownFunction::ShutilRmtree => {
                let keyword_only = if before_python3_minor(self.program, 3) {
                    &[] as &[_]
                } else if python3_minor(self.program).is_some_and(|minor| minor < 12) {
                    &["dir_fd"] as &[_]
                } else {
                    &["onexc", "dir_fd"] as &[_]
                };
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    1,
                    &["path", "ignore_errors", "onerror"],
                    0,
                    keyword_only,
                )) || !possible_path_argument(&arguments, 0, "path")
                    || !self.admit_index_value(argument(&arguments, 4, "dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let filesystem = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 0, "path", FilesystemOperation::Delete, true),
                    &arguments,
                    Some("dir_fd"),
                    None,
                );
                self.emit_filesystem_call("shutil.rmtree", &arguments, state, vec![filesystem]);
                if let Some(path) = one_argument(&arguments, "path").and_then(value_string) {
                    self.add_destructive_target(path);
                }
                Value::None
            }
            KnownFunction::OsChdir => {
                if !self.admit_call_shape(call_shape(&arguments, 1, &["path"], 0, &[]))
                    || !self.admit_value(nonempty_path_admission(argument(&arguments, 0, "path")))
                {
                    return Value::Unknown;
                }
                if argument(&arguments, 0, "path")
                    .and_then(value_string)
                    .is_some_and(|path| path.contains('\0'))
                {
                    self.pending_control = Some(Control::Raise);
                    return Value::Unknown;
                }
                self.emit_call(
                    LanguageCallKind::LocalUtility,
                    "os.chdir",
                    &arguments,
                    state,
                    Vec::new(),
                    None,
                );
                if let Some(path) = argument(&arguments, 0, "path").and_then(value_string) {
                    state.cwd = state.cwd.changed(path, self.input.platform);
                } else {
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.draft.set_partial();
                }
                Value::None
            }
            KnownFunction::OsSystem => {
                if !valid_call_shape(&arguments, 1, &["command"])
                    || required_argument(&arguments, 0, "command").is_none()
                    || !possible_scalar_argument(&arguments, 0, "command")
                {
                    return Value::Unknown;
                }
                if let Some(value) = one_argument(&arguments, "command") {
                    if decoded(value) {
                        self.report
                            .push(Finding::exact(FindingKind::DecodedExecution));
                    }
                    if let Some(code) = value_string(value)
                        && self.input.platform != Platform::Windows
                    {
                        self.push_shell(code, state.cwd.clone(), true);
                    }
                }
                self.emit_call(
                    LanguageCallKind::EvaluatedShell,
                    "os.system",
                    &arguments,
                    state,
                    Vec::new(),
                    None,
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::OsPopen => {
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    1,
                    &["cmd", "mode", "buffering"],
                    0,
                    &[],
                )) || !self.admit_value(text_admission(argument(&arguments, 0, "cmd")))
                    || !self.admit_value(popen_mode_admission(argument(&arguments, 1, "mode")))
                    || !self.admit_value(popen_buffering_admission(argument(
                        &arguments,
                        2,
                        "buffering",
                    )))
                {
                    return Value::Unknown;
                }
                if let Some(value) = argument(&arguments, 0, "cmd") {
                    if decoded(value) {
                        self.report
                            .push(Finding::exact(FindingKind::DecodedExecution));
                    }
                    if let Some(code) = value_string(value)
                        && self.input.platform != Platform::Windows
                    {
                        self.push_shell(code, state.cwd.clone(), false);
                    }
                }
                self.emit_call(
                    LanguageCallKind::EvaluatedShell,
                    "os.popen",
                    &arguments,
                    state,
                    Vec::new(),
                    None,
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::IpythonSystem
            | KnownFunction::IpythonGetoutput
            | KnownFunction::IpythonSyntaxSystem
            | KnownFunction::IpythonSyntaxGetoutput => {
                let syntactic = matches!(
                    function,
                    KnownFunction::IpythonSyntaxSystem | KnownFunction::IpythonSyntaxGetoutput
                );
                if !syntactic && (!self.complete || state.cwd == NestedExecutionCwd::Unknown) {
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                if syntactic && state.cwd == NestedExecutionCwd::Unknown {
                    self.draft.set_partial();
                }
                let stdout_inherited = matches!(
                    function,
                    KnownFunction::IpythonSystem | KnownFunction::IpythonSyntaxSystem
                ) && !self.ipython_capture;
                if arguments.complete
                    && arguments.positional.len() == 1
                    && arguments.keywords.is_empty()
                    && let Some(code) = arguments.positional.first().and_then(value_string)
                    && if syntactic {
                        super::super::super::ipython::exact_prepared_shell_command(code)
                    } else {
                        super::super::super::ipython::exact_shell_command(code)
                    }
                    && self.input.platform != Platform::Windows
                {
                    match state.ipython_shell {
                        IpythonShell::Bash => self.push_shell_program(
                            "bash",
                            code,
                            state.cwd.clone(),
                            stdout_inherited,
                        ),
                        IpythonShell::Sh => {
                            self.push_shell_program("sh", code, state.cwd.clone(), stdout_inherited)
                        }
                        IpythonShell::Unknown => self.draft.set_partial(),
                    }
                    let origin = self.emit_call(
                        LanguageCallKind::EvaluatedShell,
                        if stdout_inherited {
                            "ipython.system"
                        } else {
                            "ipython.getoutput"
                        },
                        &arguments,
                        state,
                        Vec::new(),
                        None,
                    );
                    state.bindings.insert("_exit_code".into(), Value::Unknown);
                    return if stdout_inherited {
                        Value::None
                    } else {
                        origin.map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
                    };
                }
                self.draft.set_partial();
                Value::Unknown
            }
            KnownFunction::IpythonCell | KnownFunction::IpythonSyntaxCell => {
                let syntactic = function == KnownFunction::IpythonSyntaxCell;
                if !syntactic && (!self.complete || state.cwd == NestedExecutionCwd::Unknown) {
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                if syntactic && state.cwd == NestedExecutionCwd::Unknown {
                    self.draft.set_partial();
                }
                let program = arguments.positional.first().and_then(value_string);
                let line = arguments.positional.get(1).and_then(value_string);
                let code = arguments.positional.get(2).and_then(value_string);
                if arguments.complete
                    && arguments.positional.len() == 3
                    && arguments.keywords.is_empty()
                    && matches!(program, Some("bash" | "sh"))
                    && line.is_some_and(|line| {
                        line.is_empty()
                            || syntactic
                                && super::super::super::ipython::reviewed_bash_magic_line(line)
                    })
                    && let (Some(program), Some(code)) = (program, code)
                    && self.input.platform != Platform::Windows
                {
                    if program == "bash" || syntactic {
                        self.push_shell_program(
                            program,
                            code,
                            state.cwd.clone(),
                            !self.ipython_capture,
                        );
                    } else {
                        self.draft.set_partial();
                    }
                    self.emit_call(
                        LanguageCallKind::EvaluatedShell,
                        "ipython.run_cell_magic",
                        &arguments,
                        state,
                        Vec::new(),
                        None,
                    );
                    state.bindings.insert("_exit_code".into(), Value::Unknown);
                    return Value::None;
                }
                self.draft.set_partial();
                Value::Unknown
            }
            KnownFunction::OsExec(kind) => {
                if !self.admit_call_shape(os_exec_call_shape(kind, &arguments))
                    || !self.admit_value(os_exec_admission(kind, &arguments, state))
                {
                    return Value::Unknown;
                }
                let callable = os_exec_callable(kind);
                self.emit_call(
                    LanguageCallKind::LocalUtility,
                    callable,
                    &arguments,
                    state,
                    Vec::new(),
                    None,
                );
                self.os_exec(kind, &arguments, state);
                self.pending_control = Some(Control::Raise);
                Value::None
            }
            KnownFunction::Subprocess(kind) => {
                if required_argument(&arguments, 0, "args").is_none()
                    || arguments.positional.len() > 1
                    || !valid_subprocess_shape(&arguments)
                {
                    return Value::Unknown;
                }
                match subprocess_bufsize_admission(argument(&arguments, 1, "bufsize")) {
                    ValueAdmission::Exact => {}
                    ValueAdmission::Possible => {
                        self.draft.set_partial();
                        return Value::Unknown;
                    }
                    ValueAdmission::Invalid => {
                        self.pending_control = Some(Control::Raise);
                        return Value::Unknown;
                    }
                }
                if invalid_subprocess_options(kind, &arguments) {
                    self.pending_control = Some(Control::Raise);
                    return Value::Unknown;
                }
                let command = required_argument(&arguments, 0, "args")
                    .expect("required subprocess argument was checked");
                let shell = subprocess_shell(&arguments);
                if !self.admit_value(subprocess_command_admission(command, state, shell)) {
                    return Value::Unknown;
                }
                let origin = if let Some(shell) = shell {
                    self.emit_call(
                        if shell {
                            LanguageCallKind::EvaluatedShell
                        } else {
                            LanguageCallKind::LocalUtility
                        },
                        subprocess_callable(kind),
                        &arguments,
                        state,
                        Vec::new(),
                        None,
                    )
                } else {
                    self.draft.set_partial();
                    None
                };
                if !self.subprocess(kind, &arguments, state) {
                    self.draft.set_partial();
                }
                origin.map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::Eval | KnownFunction::Exec => {
                if let Some(isolated) = dynamic_arguments(function, &arguments)
                    && let Some(value) = arguments.positional.first()
                {
                    let exact_source = matches!(value, Value::String(_) | Value::Compiled { .. });
                    let mode = if function == KnownFunction::Eval {
                        CodeMode::Eval
                    } else {
                        CodeMode::Exec
                    };
                    if isolated {
                        let mut isolated_state = State::default();
                        self.dynamic_execution(value.clone(), mode, &mut isolated_state, depth);
                        propagate_invalid_modules(&isolated_state.invalid_modules, state);
                        state.cwd =
                            compose_cwd(&state.cwd, &isolated_state.cwd, self.input.platform);
                    } else {
                        self.dynamic_execution(value.clone(), mode, state, depth);
                    }
                    if !exact_source {
                        state.cwd = NestedExecutionCwd::Unknown;
                    }
                }
                Value::Unknown
            }
            KnownFunction::Compile => {
                if !arguments.complete
                    || arguments.positional.len() != 3
                    || !arguments.keywords.is_empty()
                {
                    return Value::Unknown;
                }
                let source = &arguments.positional[0];
                let filename = &arguments.positional[1];
                let mode = &arguments.positional[2];
                if !self.admit_value(compile_source_admission(source))
                    || !self.admit_value(path_admission(Some(filename)))
                    || !self.admit_value(text_admission(Some(mode)))
                {
                    return Value::Unknown;
                }
                let Some(mode) = value_text(mode).and_then(code_mode) else {
                    if value_text(mode).is_some() {
                        self.pending_control = Some(Control::Raise);
                    }
                    return Value::Unknown;
                };
                if let Some(source) =
                    value_text(source).and_then(|source| bounded_owned(source, &mut self.budget))
                {
                    return Value::Compiled { source, mode };
                }
                Value::Unknown
            }
            KnownFunction::Base64Decode => {
                let value = arguments
                    .positional
                    .first()
                    .cloned()
                    .unwrap_or(Value::Unknown);
                Value::Decoded(Box::new(match value {
                    Value::String(value) => {
                        decode_base64(&value).map_or(Value::Unknown, Value::Bytes)
                    }
                    Value::Bytes(value) => std::str::from_utf8(&value)
                        .ok()
                        .and_then(decode_base64)
                        .map_or(Value::Unknown, Value::Bytes),
                    _ => Value::Unknown,
                }))
            }
            KnownFunction::Path => {
                if !arguments.complete
                    || !arguments.keywords.is_empty()
                    || arguments.positional.len() != 1
                {
                    return Value::Unknown;
                }
                arguments
                    .positional
                    .first()
                    .and_then(value_string)
                    .and_then(|path| bounded_owned(path, &mut self.budget))
                    .map_or(Value::Unknown, Value::Path)
            }
            KnownFunction::PathHome => {
                if arguments.positional.is_empty()
                    && arguments.keywords.is_empty()
                    && !state.invalid_modules.contains(&Module::Environment)
                {
                    bounded_owned(self.input.home, &mut self.budget)
                        .map_or(Value::Unknown, Value::Path)
                } else {
                    Value::Unknown
                }
            }
            KnownFunction::PathJoin => {
                let mut joined = String::new();
                for part in &arguments.positional {
                    let Some(part) = value_string(part) else {
                        return Value::Unknown;
                    };
                    let Some(value) = join_path(joined, part, &mut self.budget) else {
                        return Value::Unknown;
                    };
                    joined = value;
                }
                Value::String(joined)
            }
            KnownFunction::OsExpanduser => {
                if state.invalid_modules.contains(&Module::Environment) {
                    Value::Unknown
                } else {
                    arguments
                        .positional
                        .first()
                        .and_then(value_string)
                        .and_then(|path| expand_home(path, self.input.home, &mut self.budget))
                        .map_or(Value::Unknown, Value::String)
                }
            }
            KnownFunction::OsAbspath => arguments
                .positional
                .first()
                .and_then(value_string)
                .filter(|path| is_absolute(path, self.input.platform))
                .and_then(|path| bounded_owned(path, &mut self.budget))
                .map_or(Value::Unknown, Value::String),
            KnownFunction::OsRealpath => Value::Unknown,
            KnownFunction::OsGetenv => {
                if !self.admit_call_shape(call_shape(&arguments, 1, &["key", "default"], 0, &[])) {
                    return Value::Unknown;
                }
                let key = argument(&arguments, 0, "key");
                if !self.admit_value(text_admission(key)) {
                    return Value::Unknown;
                }
                if state.invalid_modules.contains(&Module::Environment) {
                    Value::Unknown
                } else {
                    key.and_then(value_text)
                        .filter(|name| *name == "HOME")
                        .and_then(|_| bounded_owned(self.input.home, &mut self.budget))
                        .map_or(Value::Unknown, Value::String)
                }
            }
            KnownFunction::Getattr => {
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    2,
                    &["object", "name", "default"],
                    3,
                    &[],
                )) {
                    return Value::Unknown;
                }
                let name = arguments.positional.get(1);
                if !self.admit_value(text_admission(name)) {
                    return Value::Unknown;
                }
                if let Some(attribute) = name.and_then(value_text)
                    && let Some(value) = arguments.positional.first()
                {
                    return match value {
                        Value::Module(module) => {
                            module_attribute(*module, attribute).unwrap_or(Value::Unknown)
                        }
                        _ => Value::Unknown,
                    };
                }
                Value::Unknown
            }
            KnownFunction::Setattr => {
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    3,
                    &["object", "name", "value"],
                    3,
                    &[],
                )) {
                    return Value::Unknown;
                }
                let target = &arguments.positional[0];
                let name = &arguments.positional[1];
                match (target, name) {
                    (
                        Value::Module(Module::Sys),
                        Value::String(name) | Value::ImplicitString(name),
                    ) if name == "modules" => {
                        invalidate_import_ownership(state);
                        self.draft.set_partial();
                    }
                    (Value::Module(Module::Sys), Value::Unknown | Value::Produced(_)) => {
                        invalidate_import_ownership(state);
                        self.draft.set_partial();
                    }
                    (Value::Module(module), Value::String(_) | Value::ImplicitString(_)) => {
                        invalidate_module(*module, state);
                        self.complete = false;
                    }
                    (_, Value::Unknown | Value::Produced(_)) => self.complete = false,
                    (_, Value::String(_) | Value::ImplicitString(_)) => self.complete = false,
                    _ => self.pending_control = Some(Control::Raise),
                }
                Value::None
            }
            KnownFunction::Import => {
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    1,
                    &["name", "globals", "locals", "fromlist", "level"],
                    0,
                    &[],
                )) {
                    return Value::Unknown;
                }
                let name = argument(&arguments, 0, "name");
                let level = argument(&arguments, 4, "level");
                if !self.admit_value(text_admission(name))
                    || !self.admit_value(import_level_admission(level))
                {
                    return Value::Unknown;
                }
                if name.and_then(value_text) == Some("") {
                    self.pending_control = Some(Control::Raise);
                    return Value::Unknown;
                }
                if matches!(level, Some(Value::Int(value)) if *value > 0)
                    || matches!(level, Some(Value::Bool(true)))
                {
                    if matches!(
                        argument(&arguments, 1, "globals"),
                        None | Some(Value::None | Value::EmptyDictionary)
                    ) {
                        self.pending_control = Some(Control::Raise);
                    } else {
                        self.draft.set_partial();
                    }
                    return Value::Unknown;
                }
                name.and_then(value_text)
                    .and_then(module_value)
                    .map(|value| retain_owned_module(value, state))
                    .unwrap_or(Value::Unknown)
            }
            KnownFunction::ShutilWhich => Value::Unknown,
            KnownFunction::Request(kind) => {
                if !self.admit_call_shape(request_call_shape(kind, &arguments, self.program))
                    || !possible_scalar_argument(&arguments, 0, request_url_keyword(kind))
                {
                    return Value::Unknown;
                }
                let callable = request_callable(kind);
                let endpoint = argument(&arguments, 0, request_url_keyword(kind))
                    .and_then(value_string)
                    .map(str::to_owned);
                let mut filesystems = Vec::new();
                if kind == RequestKind::UrlRetrieve {
                    filesystems.push(filesystem_argument(
                        &arguments,
                        1,
                        "filename",
                        FilesystemOperation::Write,
                        false,
                    ));
                }
                self.emit_call(
                    LanguageCallKind::NetworkTransfer,
                    callable,
                    &arguments,
                    state,
                    filesystems,
                    endpoint,
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::Open | KnownFunction::IoFile => {
                let (max_positional, keywords) = if function == KnownFunction::Open {
                    (
                        8,
                        &[
                            "file",
                            "mode",
                            "buffering",
                            "encoding",
                            "errors",
                            "newline",
                            "closefd",
                            "opener",
                        ][..],
                    )
                } else {
                    (4, &["file", "mode", "closefd", "opener"][..])
                };
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    1,
                    &keywords[..max_positional],
                    0,
                    &keywords[max_positional..],
                )) || !self.admit_value(open_target_admission(argument(&arguments, 0, "file")))
                    || !self.admit_value(open_mode_admission(
                        argument(&arguments, 1, "mode"),
                        function == KnownFunction::IoFile,
                    ))
                    || function == KnownFunction::Open
                        && !self.admit_index_value(argument(&arguments, 2, "buffering"), false)
                {
                    return Value::Unknown;
                }
                let callable = if function == KnownFunction::Open {
                    "builtins.open"
                } else {
                    "io.fileio"
                };
                let Some(operations) = open_operations(&arguments) else {
                    self.draft.set_partial();
                    return Value::Unknown;
                };
                if operations.is_empty() {
                    self.pending_control = Some(Control::Raise);
                    return Value::Unknown;
                }
                let filesystems = operations
                    .into_iter()
                    .map(|operation| filesystem_argument(&arguments, 0, "file", operation, false))
                    .collect();
                let result = self
                    .emit_filesystem_call(callable, &arguments, state, filesystems)
                    .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]));
                if function == KnownFunction::Open && text_open_is_unbuffered(&arguments) {
                    self.pending_control = Some(Control::Raise);
                }
                result
            }
            KnownFunction::OsRemove | KnownFunction::OsUnlink | KnownFunction::OsRmdir => {
                let callable = match function {
                    KnownFunction::OsRemove => "os.remove",
                    KnownFunction::OsUnlink => "os.unlink",
                    KnownFunction::OsRmdir => "os.rmdir",
                    _ => unreachable!(),
                };
                if !self.admit_call_shape(os_dir_fd_call_shape(
                    &arguments,
                    self.program,
                    1,
                    &["path"],
                    &["dir_fd"],
                )) || !possible_path_argument(&arguments, 0, "path")
                    || !self.admit_index_value(argument(&arguments, 1, "dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let filesystem = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 0, "path", FilesystemOperation::Delete, false),
                    &arguments,
                    Some("dir_fd"),
                    None,
                );
                self.emit_filesystem_call(callable, &arguments, state, vec![filesystem]);
                Value::None
            }
            KnownFunction::OsRemovedirs => {
                if !self.admit_call_shape(call_shape(&arguments, 1, &["name"], 0, &[]))
                    || !possible_path_argument(&arguments, 0, "name")
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    "os.removedirs",
                    &arguments,
                    state,
                    vec![filesystem_argument(
                        &arguments,
                        0,
                        "name",
                        FilesystemOperation::Delete,
                        true,
                    )],
                );
                Value::None
            }
            KnownFunction::OsMkdir => {
                if !self.admit_call_shape(os_dir_fd_call_shape(
                    &arguments,
                    self.program,
                    1,
                    &["path", "mode"],
                    &["dir_fd"],
                )) || !possible_path_argument(&arguments, 0, "path")
                    || !self.admit_index_value(argument(&arguments, 1, "mode"), false)
                    || !self.admit_index_value(argument(&arguments, 2, "dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let filesystem = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 0, "path", FilesystemOperation::Write, false)
                        .metadata(),
                    &arguments,
                    Some("dir_fd"),
                    None,
                );
                self.emit_filesystem_call("os.mkdir", &arguments, state, vec![filesystem]);
                Value::None
            }
            KnownFunction::OsMakedirs | KnownFunction::OsTruncate => {
                let (callable, keyword, recursive, required, max_positional, keywords) =
                    match function {
                        KnownFunction::OsMakedirs => (
                            "os.makedirs",
                            "name",
                            true,
                            1,
                            3,
                            &["name", "mode", "exist_ok"] as &[_],
                        ),
                        KnownFunction::OsTruncate => (
                            "os.truncate",
                            "path",
                            false,
                            2,
                            2,
                            &["path", "length"] as &[_],
                        ),
                        _ => unreachable!(),
                    };
                if !valid_call_shape(&arguments, max_positional, keywords)
                    || (0..required).any(|position| {
                        let name = keywords[position];
                        required_argument(&arguments, position, name).is_none()
                    })
                    || !possible_path_argument(&arguments, 0, keyword)
                {
                    return Value::Unknown;
                }
                if function == KnownFunction::OsTruncate
                    && !self.admit_index_value(argument(&arguments, 1, "length"), false)
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    callable,
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            0,
                            keyword,
                            FilesystemOperation::Write,
                            recursive,
                        )
                        .metadata_if(function != KnownFunction::OsTruncate),
                    ],
                );
                Value::None
            }
            KnownFunction::ShutilCopy(kind) => {
                if !self.admit_call_shape(shutil_copy_call_shape(kind, &arguments, self.program))
                    || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                {
                    return Value::Unknown;
                }
                if matches!(kind, CopyKind::Copy | CopyKind::Copy2) {
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                let recursive = kind == CopyKind::Copytree;
                let metadata = matches!(kind, CopyKind::Copymode | CopyKind::Copystat);
                self.emit_filesystem_call(
                    shutil_copy_callable(kind),
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            0,
                            "src",
                            FilesystemOperation::Read,
                            recursive,
                        )
                        .metadata_if(metadata),
                        filesystem_argument(
                            &arguments,
                            1,
                            "dst",
                            FilesystemOperation::Write,
                            recursive,
                        )
                        .metadata_if(metadata)
                        .protects_descendants_if(metadata),
                    ],
                );
                Value::Unknown
            }
            KnownFunction::OsChmod | KnownFunction::OsChown | KnownFunction::OsLchown => {
                let (callable, shape, dir_fd) = match function {
                    KnownFunction::OsChmod => (
                        "os.chmod",
                        os_dir_fd_call_shape(
                            &arguments,
                            self.program,
                            2,
                            &["path", "mode"],
                            &["dir_fd", "follow_symlinks"],
                        ),
                        Some("dir_fd"),
                    ),
                    KnownFunction::OsChown => (
                        "os.chown",
                        os_dir_fd_call_shape(
                            &arguments,
                            self.program,
                            3,
                            &["path", "uid", "gid"],
                            &["dir_fd", "follow_symlinks"],
                        ),
                        Some("dir_fd"),
                    ),
                    KnownFunction::OsLchown => {
                        let positional_only = if before_python3_minor(self.program, 5) {
                            3
                        } else {
                            0
                        };
                        (
                            "os.lchown",
                            call_shape(
                                &arguments,
                                3,
                                &["path", "uid", "gid"],
                                positional_only,
                                &[],
                            ),
                            None,
                        )
                    }
                    _ => unreachable!(),
                };
                if !self.admit_call_shape(shape) || !possible_path_argument(&arguments, 0, "path") {
                    return Value::Unknown;
                }
                let index_values = match function {
                    KnownFunction::OsChmod => [
                        (argument(&arguments, 1, "mode"), false),
                        (argument(&arguments, 2, "dir_fd"), true),
                        (None, true),
                    ],
                    KnownFunction::OsChown => [
                        (argument(&arguments, 1, "uid"), false),
                        (argument(&arguments, 2, "gid"), false),
                        (argument(&arguments, 3, "dir_fd"), true),
                    ],
                    KnownFunction::OsLchown => [
                        (argument(&arguments, 1, "uid"), false),
                        (argument(&arguments, 2, "gid"), false),
                        (None, true),
                    ],
                    _ => unreachable!(),
                };
                if index_values
                    .into_iter()
                    .any(|(value, none_allowed)| !self.admit_index_value(value, none_allowed))
                {
                    return Value::Unknown;
                }
                let no_follow = match function {
                    KnownFunction::OsChmod => {
                        argument(&arguments, 3, "follow_symlinks").and_then(exact_bool)
                            == Some(false)
                    }
                    KnownFunction::OsChown => {
                        argument(&arguments, 4, "follow_symlinks").and_then(exact_bool)
                            == Some(false)
                    }
                    KnownFunction::OsLchown => true,
                    _ => unreachable!(),
                };
                let filesystem = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 0, "path", FilesystemOperation::Write, false)
                        .metadata()
                        .protects_descendants()
                        .without_final_symlink_follow_if(no_follow),
                    &arguments,
                    dir_fd,
                    None,
                );
                self.emit_filesystem_call(callable, &arguments, state, vec![filesystem]);
                Value::None
            }
            KnownFunction::OsRename | KnownFunction::OsReplace => {
                let callable = match function {
                    KnownFunction::OsRename => "os.rename",
                    KnownFunction::OsReplace => "os.replace",
                    _ => unreachable!(),
                };
                let shape = if function == KnownFunction::OsReplace
                    && before_python3_minor(self.program, 3)
                {
                    CallShape::Invalid
                } else {
                    os_dir_fd_call_shape(
                        &arguments,
                        self.program,
                        2,
                        &["src", "dst"],
                        &["src_dir_fd", "dst_dir_fd"],
                    )
                };
                if !self.admit_call_shape(shape)
                    || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                    || !self.admit_index_value(argument(&arguments, 2, "src_dir_fd"), true)
                    || !self.admit_index_value(argument(&arguments, 3, "dst_dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let identity = argument(&arguments, 0, "src")
                    .and_then(value_string)
                    .map(str::to_owned);
                let source = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 0, "src", FilesystemOperation::Delete, false),
                    &arguments,
                    Some("src_dir_fd"),
                    None,
                );
                let destination = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 1, "dst", FilesystemOperation::Write, false)
                        .identity(identity, false)
                        .protects_descendants()
                        .without_final_symlink_follow(),
                    &arguments,
                    Some("dst_dir_fd"),
                    Some("src_dir_fd"),
                );
                self.emit_filesystem_call(callable, &arguments, state, vec![source, destination]);
                Value::None
            }
            KnownFunction::ShutilMove => {
                if !self.admit_call_shape(shutil_move_call_shape(&arguments, self.program))
                    || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                {
                    return Value::Unknown;
                }
                self.draft.set_partial();
                Value::Unknown
            }
            KnownFunction::OsLink => {
                if !self.admit_call_shape(os_dir_fd_call_shape(
                    &arguments,
                    self.program,
                    2,
                    &["src", "dst"],
                    &["src_dir_fd", "dst_dir_fd", "follow_symlinks"],
                )) || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                    || !self.admit_index_value(argument(&arguments, 2, "src_dir_fd"), true)
                    || !self.admit_index_value(argument(&arguments, 3, "dst_dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let identity = argument(&arguments, 0, "src")
                    .and_then(value_string)
                    .map(str::to_owned);
                let follows_symlinks = argument(&arguments, 4, "follow_symlinks")
                    .and_then(exact_bool)
                    .unwrap_or(true);
                let source = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 0, "src", FilesystemOperation::Write, false)
                        .metadata()
                        .without_final_symlink_follow_if(!follows_symlinks),
                    &arguments,
                    Some("src_dir_fd"),
                    None,
                );
                let destination = self.filesystem_at_dir_fds(
                    filesystem_argument(&arguments, 1, "dst", FilesystemOperation::Write, false)
                        .observed_identity(identity, true, follows_symlinks),
                    &arguments,
                    Some("dst_dir_fd"),
                    Some("src_dir_fd"),
                );
                self.emit_filesystem_call("os.link", &arguments, state, vec![source, destination]);
                Value::None
            }
            KnownFunction::OsSymlink => {
                let (shape, destination_keyword, dir_fd) = if before_python3_minor(self.program, 2)
                {
                    (
                        call_shape(&arguments, 2, &["src", "dst"], 2, &[]),
                        "dst",
                        None,
                    )
                } else if python3_minor(self.program) == Some(2) {
                    if self.input.platform == Platform::Windows {
                        (
                            call_shape(
                                &arguments,
                                2,
                                &["src", "dest", "target_is_directory"],
                                0,
                                &[],
                            ),
                            "dest",
                            None,
                        )
                    } else {
                        (
                            call_shape(&arguments, 2, &["src", "dst"], 2, &[]),
                            "dst",
                            None,
                        )
                    }
                } else {
                    (
                        call_shape(
                            &arguments,
                            2,
                            &["src", "dst", "target_is_directory"],
                            0,
                            &["dir_fd"],
                        ),
                        "dst",
                        Some("dir_fd"),
                    )
                };
                if !self.admit_call_shape(shape)
                    || !self.admit_value(path_admission(argument(&arguments, 0, "src")))
                    || !self.admit_value(path_admission(argument(
                        &arguments,
                        1,
                        destination_keyword,
                    )))
                    || !self.admit_index_value(argument(&arguments, 3, "dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let filesystem = self.filesystem_at_dir_fds(
                    filesystem_argument(
                        &arguments,
                        1,
                        destination_keyword,
                        FilesystemOperation::Write,
                        false,
                    )
                    .metadata()
                    .without_final_symlink_follow(),
                    &arguments,
                    dir_fd,
                    None,
                );
                self.emit_filesystem_call("os.symlink", &arguments, state, vec![filesystem]);
                Value::None
            }
            KnownFunction::OsOpen => {
                if !self.admit_call_shape(os_dir_fd_call_shape(
                    &arguments,
                    self.program,
                    2,
                    &["path", "flags", "mode"],
                    &["dir_fd"],
                )) || !possible_path_argument(&arguments, 0, "path")
                    || !self.admit_index_value(argument(&arguments, 1, "flags"), false)
                    || !self.admit_index_value(argument(&arguments, 2, "mode"), false)
                    || !self.admit_index_value(argument(&arguments, 3, "dir_fd"), true)
                {
                    return Value::Unknown;
                }
                let Some(flags) = argument(&arguments, 1, "flags").and_then(exact_index) else {
                    self.draft.set_partial();
                    return Value::Unknown;
                };
                let access = flags & 3;
                if access == 3 {
                    return Value::Unknown;
                }
                let mut filesystems = Vec::new();
                if matches!(access, 0 | 2) {
                    filesystems.push(self.filesystem_at_dir_fds(
                        filesystem_argument(
                            &arguments,
                            0,
                            "path",
                            FilesystemOperation::Read,
                            false,
                        ),
                        &arguments,
                        Some("dir_fd"),
                        None,
                    ));
                }
                if matches!(access, 1 | 2)
                    || flags & os_open_mutation_flags(self.input.platform) != 0
                {
                    filesystems.push(self.filesystem_at_dir_fds(
                        filesystem_argument(
                            &arguments,
                            0,
                            "path",
                            FilesystemOperation::Write,
                            false,
                        ),
                        &arguments,
                        Some("dir_fd"),
                        None,
                    ));
                }
                if filesystems.is_empty() {
                    return Value::Unknown;
                }
                self.emit_filesystem_call("os.open", &arguments, state, filesystems)
                    .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
        }
    }
}
