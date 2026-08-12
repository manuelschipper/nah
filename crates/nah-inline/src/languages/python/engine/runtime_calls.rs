//! Emits Python runtime effects, local calls, child processes, and dynamic source.

use super::*;

impl Interpreter<'_> {
    pub(super) fn emit_filesystem_call(
        &mut self,
        callable: &str,
        arguments: &Arguments,
        state: &State,
        filesystems: Vec<LanguageFilesystem>,
    ) -> Option<usize> {
        self.emit_call(
            LanguageCallKind::DirectFile,
            callable,
            arguments,
            state,
            filesystems,
            None,
        )
    }

    pub(super) fn filesystem_at_dir_fds(
        &mut self,
        mut filesystem: LanguageFilesystem,
        arguments: &Arguments,
        requested_dir_fd: Option<&str>,
        identity_dir_fd: Option<&str>,
    ) -> LanguageFilesystem {
        let mut unresolved = false;
        if requested_dir_fd.is_some_and(|name| dir_fd_changes_base(arguments, name))
            && filesystem
                .requested()
                .is_some_and(|path| !is_absolute(path, self.input.platform))
        {
            filesystem = filesystem.without_requested();
            unresolved = true;
        }
        if identity_dir_fd.is_some_and(|name| dir_fd_changes_base(arguments, name))
            && filesystem
                .identity_path()
                .is_some_and(|path| !is_absolute(path, self.input.platform))
        {
            filesystem = filesystem.without_identity();
            unresolved = true;
        }
        if unresolved {
            self.draft.set_partial();
        }
        filesystem
    }

    pub(super) fn emit_call(
        &mut self,
        kind: LanguageCallKind,
        callable: &str,
        arguments: &Arguments,
        state: &State,
        filesystems: Vec<LanguageFilesystem>,
        endpoint: Option<String>,
    ) -> Option<usize> {
        let mut unresolved_filesystem = false;
        let filesystems = filesystems
            .into_iter()
            .map(|mut filesystem| {
                if let Some(requested) = filesystem.requested().map(str::to_owned)
                    && !is_absolute(&requested, self.input.platform)
                {
                    if let Some(requested) = state.cwd.resolve(&requested, self.input.platform) {
                        filesystem = filesystem.with_requested(requested);
                    } else {
                        filesystem = filesystem.without_requested();
                        unresolved_filesystem = true;
                    }
                }
                if let Some(identity) = filesystem.identity_path().map(str::to_owned)
                    && !is_absolute(&identity, self.input.platform)
                {
                    if let Some(identity) = state.cwd.resolve(&identity, self.input.platform) {
                        filesystem = filesystem.with_identity(identity);
                    } else {
                        filesystem = filesystem.without_identity();
                        unresolved_filesystem = true;
                    }
                }
                filesystem
            })
            .collect::<Vec<_>>();
        let input = language_call_input(callable, arguments, state);
        if !input.complete()
            || unresolved_filesystem
            || filesystems
                .iter()
                .any(|filesystem| filesystem.requested().is_none())
            || kind == LanguageCallKind::NetworkTransfer && endpoint.is_none()
        {
            self.draft.set_partial();
        }
        let origins = argument_origins(arguments, state);
        let call = LanguageCall::new(
            kind,
            input,
            filesystems,
            endpoint,
            self.conditional_depth,
            self.execution_dominators.clone(),
        );
        let ordinal = self.draft.push_call(call)?;
        if self.conditional_depth > 0 {
            self.execution_dominators.push(ordinal);
        }
        for origin in origins {
            self.draft.push_flow(origin, ordinal);
        }
        Some(ordinal)
    }

    pub(super) fn call_local(
        &mut self,
        function: usize,
        arguments: Arguments,
        state: &mut State,
        depth: usize,
    ) -> Value {
        if depth >= MAX_CALL_DEPTH {
            self.budget.refusal = Some(InlineRefusal::RecursionLimit);
            return Value::Unknown;
        }
        let Some(function) = state.functions.get(function).cloned() else {
            return Value::Unknown;
        };
        if self.call_stack.contains(&function.name) {
            self.complete = false;
            self.pending_control = Some(Control::Diverge);
            return Value::Unknown;
        }
        let Some(parameters) = function.parameters.as_deref() else {
            self.complete = false;
            return Value::Unknown;
        };
        let bindings = match bind_arguments(parameters, &arguments) {
            ArgumentBindings::Bound(bindings) => bindings,
            ArgumentBindings::Invalid => {
                self.pending_control = Some(Control::Raise);
                return Value::Unknown;
            }
            ArgumentBindings::Incomplete => {
                self.complete = false;
                return Value::Unknown;
            }
        };
        let mut local = state.clone();
        let globals = global_names(&function.body, &function.source);
        for name in assigned_names(&function.body, &function.source) {
            if !globals.contains(&name) {
                local.bindings.insert(name, Value::Unknown);
            }
        }
        for (name, value) in bindings {
            local.bindings.insert(name, value);
        }
        self.call_stack.push(function.name);
        let outer_source = std::mem::replace(&mut self.source, function.source);
        let control = self.exec_block(&function.body, &mut local, depth + 1);
        let result = match &control {
            Control::Return(value) => value.clone(),
            _ => Value::None,
        };
        self.source = outer_source;
        self.call_stack.pop();
        for (cell, local_cell) in state.cells.iter_mut().zip(local.cells) {
            *cell = local_cell;
        }
        propagate_invalid_modules(&local.invalid_modules, state);
        state.cwd = local.cwd;
        for name in globals {
            state.bindings.insert(name, Value::Unknown);
        }
        if matches!(control, Control::Raise | Control::Diverge) {
            self.pending_control = Some(control);
        }
        result
    }

    pub(super) fn call_path_method(
        &mut self,
        path: String,
        method: &str,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        match method {
            "with_name" => {
                if !self.admit_call_shape(call_shape(&arguments, 1, &["name"], 0, &[])) {
                    return Value::Unknown;
                }
                let name = argument(&arguments, 0, "name");
                if !self.admit_value(text_admission(name)) {
                    return Value::Unknown;
                }
                if !path_has_name(&path, self.input.platform) {
                    self.pending_control = Some(Control::Raise);
                    return Value::Unknown;
                }
                name.and_then(value_text).map_or(Value::Unknown, |name| {
                    if name.is_empty()
                        || name == "."
                        || name.contains('/')
                        || self.input.platform == Platform::Windows
                            && (name.contains('\\') || name.contains(':'))
                    {
                        self.pending_control = Some(Control::Raise);
                        return Value::Unknown;
                    }
                    let parent = path
                        .rsplit_once(['/', '\\'])
                        .map_or("", |(parent, _)| parent);
                    join_path(parent.to_owned(), name, &mut self.budget)
                        .map_or(Value::Unknown, Value::Path)
                })
            }
            "joinpath" => {
                let mut joined = path;
                for value in &arguments.positional {
                    let Some(value) = value_string(value) else {
                        return Value::Unknown;
                    };
                    let Some(value) = join_path(joined, value, &mut self.budget) else {
                        return Value::Unknown;
                    };
                    joined = value;
                }
                Value::Path(joined)
            }
            "expanduser" if !state.invalid_modules.contains(&Module::Environment) => {
                expand_home(&path, self.input.home, &mut self.budget)
                    .map_or(Value::Unknown, Value::Path)
            }
            "expanduser" => Value::Unknown,
            "resolve" | "absolute" => Value::Unknown,
            "read_text" | "read_bytes" => {
                let valid = if method == "read_text" {
                    valid_call_shape(&arguments, 3, &["encoding", "errors", "newline"])
                } else {
                    valid_call_shape(&arguments, 0, &[])
                };
                if !valid {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![LanguageFilesystem::new(
                        Some(path),
                        FilesystemOperation::Read,
                        false,
                    )],
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            "write_text" | "write_bytes" | "touch" | "mkdir" | "chmod" | "lchmod" => {
                let shape = match method {
                    "write_text" => call_shape(
                        &arguments,
                        1,
                        &["data", "encoding", "errors", "newline"],
                        0,
                        &[],
                    ),
                    "write_bytes" => call_shape(&arguments, 1, &["data"], 0, &[]),
                    "touch" => call_shape(&arguments, 0, &["mode", "exist_ok"], 0, &[]),
                    "mkdir" => call_shape(&arguments, 0, &["mode", "parents", "exist_ok"], 0, &[]),
                    "chmod" => call_shape(&arguments, 1, &["mode", "follow_symlinks"], 0, &[]),
                    "lchmod" => call_shape(&arguments, 1, &["mode"], 0, &[]),
                    _ => unreachable!(),
                };
                if !self.admit_call_shape(shape) {
                    return Value::Unknown;
                }
                let payload = argument(&arguments, 0, "data");
                if (method == "write_text" && !self.admit_value(text_admission(payload)))
                    || (method == "write_bytes" && !self.admit_value(bytes_admission(payload)))
                {
                    return Value::Unknown;
                }
                if matches!(method, "mkdir" | "chmod" | "lchmod")
                    && !self.admit_index_value(argument(&arguments, 0, "mode"), false)
                {
                    return Value::Unknown;
                }
                let no_follow = method == "lchmod"
                    || method == "chmod"
                        && argument(&arguments, 1, "follow_symlinks").and_then(exact_bool)
                            == Some(false);
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(
                            Some(path),
                            FilesystemOperation::Write,
                            method == "mkdir"
                                && argument(&arguments, 1, "parents")
                                    .and_then(exact_bool)
                                    .unwrap_or(false),
                        )
                        .metadata_if(matches!(method, "touch" | "mkdir" | "chmod" | "lchmod"))
                        .protects_descendants_if(matches!(method, "chmod" | "lchmod"))
                        .without_final_symlink_follow_if(no_follow),
                    ],
                );
                Value::None
            }
            "unlink" | "rmdir" => {
                let valid = if method == "unlink" {
                    valid_call_shape(&arguments, 1, &["missing_ok"])
                } else {
                    valid_call_shape(&arguments, 0, &[])
                };
                if !valid {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![LanguageFilesystem::new(
                        Some(path),
                        FilesystemOperation::Delete,
                        false,
                    )],
                );
                Value::None
            }
            "rename" | "replace" => {
                if !self.admit_call_shape(call_shape(&arguments, 1, &["target"], 0, &[]))
                    || !possible_path_argument(&arguments, 0, "target")
                {
                    return Value::Unknown;
                }
                let target = argument(&arguments, 0, "target")
                    .and_then(value_string)
                    .map(str::to_owned);
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(
                            Some(path.clone()),
                            FilesystemOperation::Delete,
                            false,
                        ),
                        LanguageFilesystem::new(target.clone(), FilesystemOperation::Write, false)
                            .identity(Some(path), false)
                            .protects_descendants()
                            .without_final_symlink_follow(),
                    ],
                );
                target.map_or(Value::Unknown, Value::Path)
            }
            "hardlink_to" | "link_to" => {
                if !valid_call_shape(&arguments, 1, &["target"])
                    || required_argument(&arguments, 0, "target").is_none()
                    || !possible_path_argument(&arguments, 0, "target")
                {
                    return Value::Unknown;
                }
                let target = argument(&arguments, 0, "target")
                    .and_then(value_string)
                    .map(str::to_owned);
                let (destination, identity) = if method == "hardlink_to" {
                    (Some(path), target)
                } else {
                    (target, Some(path))
                };
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(
                            identity.clone(),
                            FilesystemOperation::Write,
                            false,
                        )
                        .metadata(),
                        LanguageFilesystem::new(destination, FilesystemOperation::Write, false)
                            .observed_identity(identity, true, true),
                    ],
                );
                Value::None
            }
            "symlink_to" => {
                if !self.admit_call_shape(call_shape(
                    &arguments,
                    1,
                    &["target", "target_is_directory"],
                    0,
                    &[],
                )) || !self.admit_value(path_admission(argument(&arguments, 0, "target")))
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    "pathlib.path.symlink_to",
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(Some(path), FilesystemOperation::Write, false)
                            .metadata()
                            .without_final_symlink_follow(),
                    ],
                );
                Value::None
            }
            _ => Value::Unknown,
        }
    }

    pub(super) fn call_cell_method(
        &mut self,
        cell: usize,
        method: &str,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        if method == "append"
            && arguments.complete
            && arguments.keywords.is_empty()
            && arguments.positional.len() == 1
            && let Some(value) = state.cells.get_mut(cell)
        {
            match value {
                Cell::Sequence { values, .. } => {
                    let bytes = values_bytes(values).and_then(|bytes| {
                        value_bytes(&arguments.positional[0])
                            .and_then(|added| bytes.checked_add(added))
                    });
                    if values.len() < MAX_COLLECTION_ITEMS && self.budget.admit_value_bytes(bytes) {
                        values.push(arguments.positional[0].clone());
                    } else {
                        *value = Cell::Unknown;
                        self.budget.refuse_work();
                    }
                }
                Cell::Unknown => {}
            }
            return Value::None;
        }
        if method == "extend"
            && arguments.complete
            && arguments.keywords.is_empty()
            && arguments.positional.len() == 1
        {
            let extension = sequence_values(&arguments.positional[0], state).map(Vec::from);
            if let Some(value) = state.cells.get_mut(cell) {
                match extension {
                    Some(extension) => match value {
                        Cell::Sequence { values, .. } => {
                            let items = values.len().checked_add(extension.len());
                            let bytes = values_bytes(values).and_then(|bytes| {
                                values_bytes(&extension).and_then(|added| bytes.checked_add(added))
                            });
                            if items.is_some_and(|items| items <= MAX_COLLECTION_ITEMS)
                                && self.budget.admit_value_bytes(bytes)
                            {
                                values.extend(extension);
                            } else {
                                *value = Cell::Unknown;
                                self.budget.refuse_work();
                            }
                        }
                        Cell::Unknown => {}
                    },
                    None => {
                        if matches!(value, Cell::Sequence { .. }) {
                            *value = Cell::Unknown;
                        }
                    }
                }
                return Value::None;
            }
        }
        if let Some(value) = state.cells.get_mut(cell) {
            *value = Cell::Unknown;
        }
        self.complete = false;
        Value::Unknown
    }

    pub(super) fn call_string_method(
        &mut self,
        value: String,
        method: &str,
        arguments: Arguments,
    ) -> Value {
        match method {
            "encode" if arguments.positional.is_empty() => Value::Bytes(value.into_bytes()),
            "format" => {
                let mut formatted = value;
                for argument in arguments.positional {
                    let Some(display) = display_value(&argument) else {
                        return Value::Unknown;
                    };
                    if !formatted.contains("{}") {
                        continue;
                    }
                    if !self.budget.admit_value_bytes(
                        formatted
                            .len()
                            .checked_sub(2)
                            .and_then(|bytes| bytes.checked_add(display.len())),
                    ) {
                        return Value::Unknown;
                    }
                    formatted = formatted.replacen("{}", &display, 1);
                }
                Value::String(formatted)
            }
            _ => Value::Unknown,
        }
    }

    pub(super) fn call_bytes_method(
        &mut self,
        value: Vec<u8>,
        method: &str,
        arguments: Arguments,
    ) -> Value {
        if method == "decode" && arguments.positional.len() <= 1 {
            String::from_utf8(value).map_or(Value::Unknown, Value::String)
        } else {
            Value::Unknown
        }
    }

    pub(super) fn subprocess(
        &mut self,
        kind: SubprocessKind,
        arguments: &Arguments,
        state: &State,
    ) -> bool {
        let Some(command) = argument(arguments, 0, "args") else {
            return false;
        };
        if subprocess_shell(arguments) == Some(true) && decoded(command) {
            self.report
                .push(Finding::exact(FindingKind::DecodedExecution));
        }
        let Some((shell, stdout_inherited, cwd)) =
            subprocess_options(kind, arguments, state, self.input.platform)
        else {
            return false;
        };
        let nested_before = self.report.nested_executions().len();
        if shell {
            let code = value_string(command).or_else(|| {
                sequence_values(command, state)
                    .and_then(|values| values.first())
                    .and_then(value_string)
            });
            if let Some(code) = code
                && self.input.platform != Platform::Windows
            {
                self.push_shell(code, cwd, stdout_inherited);
            }
        } else if let Some(argv) = argv_value(command, state, &mut self.budget) {
            self.push_command(argv, cwd, stdout_inherited);
        }
        self.report.nested_executions().len() > nested_before
    }

    pub(super) fn os_exec(&mut self, kind: StringKind, arguments: &Arguments, state: &State) {
        let argv = match kind {
            StringKind::Execl | StringKind::Execlp
                if arguments.keywords.is_empty()
                    && arguments.positional.len() >= 2
                    && arguments
                        .positional
                        .iter()
                        .all(|value| value_string(value).is_some()) =>
            {
                let values = std::iter::once(value_string(&arguments.positional[0]))
                    .chain(arguments.positional[2..].iter().map(value_string));
                let Some(argv) = bounded_strings(values, &mut self.budget) else {
                    return;
                };
                argv
            }
            StringKind::Execv | StringKind::Execvp
                if arguments.keywords.is_empty() && arguments.positional.len() == 2 =>
            {
                let Some(program) = value_string(&arguments.positional[0]) else {
                    return;
                };
                let Some(argv) = argv_value(&arguments.positional[1], state, &mut self.budget)
                else {
                    return;
                };
                if argv.is_empty() {
                    return;
                }
                std::iter::once(program.to_owned())
                    .chain(argv.into_iter().skip(1))
                    .collect()
            }
            _ => return,
        };
        self.push_command(argv, state.cwd.clone(), true);
    }

    pub(super) fn push_shell(
        &mut self,
        code: &str,
        cwd: NestedExecutionCwd,
        stdout_inherited: bool,
    ) {
        self.push_shell_program("sh", code, cwd, stdout_inherited);
    }

    pub(super) fn push_shell_program(
        &mut self,
        program: &str,
        code: &str,
        cwd: NestedExecutionCwd,
        stdout_inherited: bool,
    ) {
        if !self.budget.admit_value_bytes(Some(code.len())) {
            return;
        }
        self.report.push_nested_execution(NestedExecution::Shell {
            program: program.to_owned(),
            code: code.to_owned(),
            cwd,
            stdout_inherited,
        });
    }

    pub(super) fn push_command(
        &mut self,
        argv: Vec<String>,
        cwd: NestedExecutionCwd,
        stdout_inherited: bool,
    ) {
        let bytes = argv
            .iter()
            .try_fold(0usize, |bytes, value| bytes.checked_add(value.len()));
        if argv.len() > MAX_COLLECTION_ITEMS || !self.budget.admit_value_bytes(bytes) {
            self.budget.refuse_work();
            return;
        }
        self.report.push_nested_execution(NestedExecution::Command {
            argv,
            cwd,
            stdout_inherited,
        });
    }

    pub(super) fn dynamic_execution(
        &mut self,
        value: Value,
        string_mode: CodeMode,
        state: &mut State,
        depth: usize,
    ) {
        let (source, mode) = match value {
            Value::String(source) => (source, string_mode),
            Value::Compiled { source, mode } => (source, mode),
            _ => return,
        };
        if source.len() > crate::SOURCE_LIMIT {
            self.report.refuse(InlineRefusal::SourceLimit);
            return;
        }
        if !self.budget.enter_dynamic_source(source.len()) {
            return;
        }
        if depth >= MAX_CALL_DEPTH {
            self.budget.refusal = Some(InlineRefusal::RecursionLimit);
            return;
        }
        let module = match super::super::parser::lower(&source, self.program) {
            Ok(module) if !module.opaque() => module,
            Ok(_) => {
                self.complete = false;
                return;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                return;
            }
        };
        let mut statements = named_children(module.root());
        let first = statements.next();
        if matches!(mode, CodeMode::Eval | CodeMode::Single) && statements.next().is_some() {
            self.complete = false;
            return;
        }
        if mode == CodeMode::Single && first.is_none() {
            self.complete = false;
            return;
        }
        let expression = if mode == CodeMode::Eval {
            let Some(statement) = first.filter(|node| node.kind() == HirKind::ExpressionStatement)
            else {
                self.complete = false;
                return;
            };
            let mut expressions = named_children(statement);
            let expression = expressions.next();
            if expression.is_none() || expressions.next().is_some() {
                self.complete = false;
                return;
            }
            expression
        } else {
            None
        };
        let outer = std::mem::replace(&mut self.source, Arc::from(source));
        let mut control = Control::Next;
        if let Some(expression) = expression {
            self.eval(expression, state, depth + 1);
        } else if mode != CodeMode::Single || first.is_some() {
            control = self.exec_block(module.root(), state, depth + 1);
        }
        self.source = outer;
        if control != Control::Next {
            self.pending_control = Some(control);
        }
    }
}
