use std::collections::BTreeSet;

use nah_proto::{
    action::{FilesystemOperation, InvocationInput},
    ctx::Platform,
};
use serde_json::json;

use crate::{
    Finding, FindingKind, InlineInput, InlineReport, LanguageAnalysis, LanguageCall,
    LanguageCallKind, LanguageDraft, LanguageFilesystem, ProtectionInput,
};

use super::common::{add_exact_argv, with_typed_protection};

#[derive(Clone, Debug)]
struct Token {
    value: String,
    exact: bool,
    quoted: bool,
}

#[derive(Clone, Debug)]
enum Lexeme {
    Word(Token),
    Pipe,
    Redirect,
}

#[derive(Default)]
struct Arguments {
    positional: Vec<Token>,
    parameters: Vec<Parameter>,
    complete: bool,
}

struct Parameter {
    name: String,
    value: Option<Token>,
    attached: Option<String>,
}

struct Interpreter<'a, 'p> {
    program: String,
    input: InlineInput<'a>,
    protection: Option<&'p ProtectionInput<'a>>,
    depth: usize,
    report: InlineReport,
    draft: LanguageDraft,
    shadowed: BTreeSet<String>,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    interpret_effects(program, input, protection, depth).into_report()
}

pub(super) fn interpret_effects<'a>(
    program: &str,
    input: &InlineInput<'a>,
    protection: Option<&ProtectionInput<'a>>,
    depth: usize,
) -> LanguageAnalysis {
    let (stripped_code, comments_complete) = strip_comments(input.code);
    let code_without_continuations = code_without_powershell_line_continuations(&stripped_code);
    let code = code_without_continuations
        .as_deref()
        .unwrap_or(&stripped_code);
    let analyzed_input = InlineInput { code, ..*input };
    let mut interpreter = Interpreter {
        program: program.to_owned(),
        input: analyzed_input,
        protection,
        depth,
        report: InlineReport::default(),
        draft: LanguageDraft::default(),
        shadowed: BTreeSet::new(),
    };
    if !comments_complete {
        interpreter.draft.set_partial();
    }
    if code_without_continuations.is_some() {
        interpreter.draft.set_partial();
    }
    for statement in statements(code) {
        interpreter.interpret_statement(statement);
    }
    let report = with_typed_protection(
        interpreter.report,
        program,
        &analyzed_input,
        protection,
        &interpreter.draft,
    );
    LanguageAnalysis::new(report, interpreter.draft)
}

impl Interpreter<'_, '_> {
    fn interpret_statement(&mut self, statement: &str) {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            return;
        }
        let lowercase = trimmed.to_ascii_lowercase();
        if definition_or_resolution_mutation(&lowercase, self.input.platform) {
            self.shadowed.extend(shadowed_commands(
                trimmed,
                self.input.home,
                self.input.platform,
            ));
            self.draft.set_partial();
            return;
        }
        if self.interpret_webclient(trimmed) {
            return;
        }
        if dynamic_statement(trimmed, &lowercase) {
            self.draft.set_partial();
        }
        let Some((lexemes, bindings_complete)) = lex(trimmed, self.input.home) else {
            self.draft.set_partial();
            return;
        };
        if !bindings_complete {
            self.draft.set_partial();
        }
        let mut segment = Vec::new();
        for lexeme in lexemes {
            if matches!(lexeme, Lexeme::Pipe) {
                self.interpret_segment(&segment);
                segment.clear();
            } else {
                segment.push(lexeme);
            }
        }
        self.interpret_segment(&segment);
    }

    fn interpret_segment(&mut self, lexemes: &[Lexeme]) {
        let mut words = Vec::new();
        let mut index = 0;
        while index < lexemes.len() {
            match &lexemes[index] {
                Lexeme::Word(token) => words.push(token.clone()),
                Lexeme::Redirect => {
                    let target = match lexemes.get(index + 1) {
                        Some(Lexeme::Word(target)) => {
                            index += 1;
                            Some(target.clone())
                        }
                        _ => None,
                    };
                    if target
                        .as_ref()
                        .is_some_and(|target| target.exact && stream_merge(&target.value))
                    {
                        index += 1;
                        continue;
                    }
                    let filesystem = target
                        .as_ref()
                        .map(|target| {
                            self.filesystem(target, FilesystemOperation::Write, false, true)
                        })
                        .unwrap_or_else(|| {
                            LanguageFilesystem::new(None, FilesystemOperation::Write, false)
                        });
                    self.emit(
                        LanguageCallKind::DirectFile,
                        "redirection",
                        target.as_ref().into_iter(),
                        vec![filesystem],
                        None,
                        target.as_ref().is_some_and(|target| target.exact),
                    );
                }
                Lexeme::Pipe => unreachable!("pipeline is split before interpretation"),
            }
            index += 1;
        }
        let Some((first, remaining)) = words.split_first() else {
            return;
        };
        if first.quoted && remaining.is_empty() {
            return;
        }
        if !first.exact {
            self.draft.set_partial();
            return;
        }
        let (command, command_arguments) = if first.value == "&" {
            let Some((command, arguments)) = remaining.split_first() else {
                self.draft.set_partial();
                return;
            };
            (command, arguments)
        } else {
            (first, remaining)
        };
        if !command.exact {
            self.draft.set_partial();
            return;
        }
        let raw_command = command.value.to_ascii_lowercase();
        if self.shadowed.contains(&raw_command) {
            self.draft.set_partial();
            return;
        }
        match canonical_command(&raw_command, self.input.platform) {
            CanonicalCommand::RemoveItem => self.remove_item(command_arguments),
            CanonicalCommand::MoveItem => self.move_item(command_arguments),
            CanonicalCommand::GetContent => {
                self.content_call("get-content", command_arguments, FilesystemOperation::Read)
            }
            CanonicalCommand::SetContent => {
                self.content_call("set-content", command_arguments, FilesystemOperation::Write)
            }
            CanonicalCommand::AddContent => {
                self.content_call("add-content", command_arguments, FilesystemOperation::Write)
            }
            CanonicalCommand::ClearContent => self.content_call(
                "clear-content",
                command_arguments,
                FilesystemOperation::Write,
            ),
            CanonicalCommand::OutFile => self.out_file(command_arguments),
            CanonicalCommand::InvokeWebRequest => {
                self.web_request("invoke-webrequest", command_arguments, true)
            }
            CanonicalCommand::InvokeRestMethod => {
                self.web_request("invoke-restmethod", command_arguments, true)
            }
            CanonicalCommand::CurlAlias => self.web_request(&raw_command, command_arguments, false),
            CanonicalCommand::InvokeExpression => self.invoke_expression(command_arguments),
            CanonicalCommand::StartProcess => self.start_process(command_arguments),
            CanonicalCommand::NoEffect => self.emit(
                LanguageCallKind::LocalUtility,
                &raw_command,
                command_arguments.iter(),
                Vec::new(),
                None,
                command_arguments.iter().all(|token| token.exact),
            ),
            CanonicalCommand::External if exact_external(&command.value) => {
                self.external(command, command_arguments)
            }
            CanonicalCommand::External => self.draft.set_partial(),
        }
    }

    fn remove_item(&mut self, tokens: &[Token]) {
        let arguments = parse_arguments(tokens, remove_parameter);
        let what_if = switch_enabled(&arguments, "whatif");
        let recurse = switch_enabled(&arguments, "recurse") || switch_enabled(&arguments, "r");
        let path_parameter_set = path_targets(&arguments);
        let path_parameter_set_complete = path_parameter_set.is_some();
        let (targets, literal) = path_parameter_set.unwrap_or_default();
        let positionals_complete = arguments.positional.len() <= 1;
        let filesystems = if what_if || !path_parameter_set_complete {
            Vec::new()
        } else {
            targets
                .iter()
                .map(|target| {
                    self.filesystem(target, FilesystemOperation::Delete, recurse, literal)
                })
                .collect()
        };
        self.emit(
            LanguageCallKind::DirectFile,
            "remove-item",
            tokens.iter(),
            filesystems,
            None,
            arguments.complete
                && path_parameter_set_complete
                && positionals_complete
                && (!targets.is_empty() || what_if),
        );
    }

    fn move_item(&mut self, tokens: &[Token]) {
        let arguments = parse_arguments(tokens, move_parameter);
        let what_if = switch_enabled(&arguments, "whatif");
        let path_parameter_set = path_targets(&arguments);
        let path_parameter_set_complete = path_parameter_set.is_some();
        let (sources, literal) = path_parameter_set.unwrap_or_default();
        let source = sources.first().copied();
        let named_source = parameter_value(&arguments, &["path", "literalpath"]).is_some();
        let named_destination = parameter_value(&arguments, &["destination"]);
        let destination = named_destination
            .or_else(|| arguments.positional.get(if named_source { 0 } else { 1 }));
        let positionals_complete = arguments.positional.len()
            <= usize::from(!named_source) + usize::from(named_destination.is_none());
        let filesystems = if what_if || !path_parameter_set_complete {
            Vec::new()
        } else {
            let mut filesystems = vec![source.map_or_else(
                || LanguageFilesystem::new(None, FilesystemOperation::Delete, false),
                |source| self.filesystem(source, FilesystemOperation::Delete, false, literal),
            )];
            filesystems.push(
                destination
                    .map_or_else(
                        || LanguageFilesystem::new(None, FilesystemOperation::Write, false),
                        |destination| {
                            self.filesystem(destination, FilesystemOperation::Write, false, true)
                        },
                    )
                    .identity(
                        source
                            .filter(|source| source.exact)
                            .map(|source| source.value.clone()),
                        false,
                    )
                    .protects_descendants()
                    .without_final_symlink_follow(),
            );
            filesystems
        };
        self.emit(
            LanguageCallKind::DirectFile,
            "move-item",
            tokens.iter(),
            filesystems,
            None,
            arguments.complete
                && path_parameter_set_complete
                && positionals_complete
                && (source.is_some() && destination.is_some() || what_if),
        );
    }

    fn content_call(&mut self, callable: &str, tokens: &[Token], operation: FilesystemOperation) {
        let arguments = parse_arguments(tokens, content_parameter);
        let what_if = switch_enabled(&arguments, "whatif");
        let path_parameter_set = path_targets(&arguments);
        let path_parameter_set_complete = path_parameter_set.is_some();
        let (targets, literal) = path_parameter_set.unwrap_or_default();
        let target = targets.first().copied();
        let filesystems = if what_if || !path_parameter_set_complete {
            Vec::new()
        } else {
            vec![target.map_or_else(
                || LanguageFilesystem::new(None, operation, false),
                |target| self.filesystem(target, operation, false, literal),
            )]
        };
        self.emit(
            LanguageCallKind::DirectFile,
            callable,
            tokens.iter(),
            filesystems,
            None,
            arguments.complete && path_parameter_set_complete && (target.is_some() || what_if),
        );
    }

    fn out_file(&mut self, tokens: &[Token]) {
        let arguments = parse_arguments(tokens, out_file_parameter);
        let what_if = switch_enabled(&arguments, "whatif");
        let target =
            parameter_value(&arguments, &["filepath"]).or_else(|| arguments.positional.first());
        let filesystems = if what_if {
            Vec::new()
        } else {
            vec![target.map_or_else(
                || LanguageFilesystem::new(None, FilesystemOperation::Write, false),
                |target| self.filesystem(target, FilesystemOperation::Write, false, true),
            )]
        };
        self.emit(
            LanguageCallKind::DirectFile,
            "out-file",
            tokens.iter(),
            filesystems,
            None,
            arguments.complete && (target.is_some() || what_if),
        );
    }

    fn web_request(&mut self, callable: &str, tokens: &[Token], resolved_cmdlet: bool) {
        let arguments = parse_arguments(tokens, web_parameter);
        let endpoint = parameter_value(&arguments, &["uri"])
            .or_else(|| arguments.positional.first())
            .filter(|token| token.exact)
            .map(|token| token.value.clone());
        let filesystems = if resolved_cmdlet {
            parameter_value(&arguments, &["outfile"])
                .map(|target| {
                    vec![self.filesystem(target, FilesystemOperation::Write, false, true)]
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        self.emit(
            LanguageCallKind::NetworkTransfer,
            callable,
            tokens.iter(),
            filesystems,
            endpoint,
            resolved_cmdlet && arguments.complete,
        );
    }

    fn invoke_expression(&mut self, tokens: &[Token]) {
        let arguments = parse_arguments(tokens, invoke_expression_parameter);
        let code = parameter_value(&arguments, &["command"])
            .or_else(|| arguments.positional.first())
            .filter(|code| code.exact);
        self.emit(
            LanguageCallKind::EvaluatedShell,
            "invoke-expression",
            tokens.iter(),
            Vec::new(),
            None,
            arguments.complete && code.is_some(),
        );
        let Some(code) = code else {
            self.draft.set_partial();
            return;
        };
        let nested = crate::interpret_language_effects_at(
            InlineInput {
                code: &code.value,
                ..self.input
            },
            self.protection,
            self.depth + 1,
        );
        let (report, draft) = nested.into_parts();
        self.report.extend(report);
        self.draft.extend(draft);
    }

    fn start_process(&mut self, tokens: &[Token]) {
        let arguments = parse_arguments(tokens, start_process_parameter);
        let simulated = switch_enabled(&arguments, "whatif");
        let supported = arguments
            .parameters
            .iter()
            .all(|parameter| matches!(parameter.name.as_str(), "filepath" | "argumentlist"));
        let program =
            parameter_value(&arguments, &["filepath"]).or_else(|| arguments.positional.first());
        let mut argv = Vec::new();
        if let Some(program) = program.filter(|program| program.exact) {
            argv.push(program.value.clone());
            if let Some(argument) =
                parameter_value(&arguments, &["argumentlist"]).filter(|argument| argument.exact)
            {
                argv.push(argument.value.clone());
            }
        }
        let complete = arguments.complete && supported && !argv.is_empty();
        self.emit(
            LanguageCallKind::LocalUtility,
            "start-process",
            tokens.iter(),
            Vec::new(),
            None,
            complete,
        );
        if complete && !simulated {
            add_exact_argv(&mut self.report, argv);
        }
    }

    fn external(&mut self, command: &Token, arguments: &[Token]) {
        let complete = command.exact && arguments.iter().all(|argument| argument.exact);
        self.emit(
            LanguageCallKind::LocalUtility,
            &command.value,
            arguments.iter(),
            Vec::new(),
            None,
            complete,
        );
        if complete {
            add_exact_argv(
                &mut self.report,
                std::iter::once(command.value.clone())
                    .chain(arguments.iter().map(|argument| argument.value.clone()))
                    .collect(),
            );
        }
    }

    fn interpret_webclient(&mut self, statement: &str) -> bool {
        let lowercase = statement.to_ascii_lowercase();
        if !lowercase.contains("system.net.webclient") && !lowercase.contains("net.webclient") {
            return false;
        }
        let methods = [
            (".downloadfile(", "webclient.downloadfile", true),
            (".downloadstring(", "webclient.downloadstring", false),
            (".downloaddata(", "webclient.downloaddata", false),
            (".openread(", "webclient.openread", false),
        ];
        let Some((method_offset, needle, callable, writes_file)) =
            methods.iter().find_map(|(needle, callable, writes_file)| {
                lowercase
                    .find(needle)
                    .map(|offset| (offset, *needle, *callable, *writes_file))
            })
        else {
            self.draft.set_partial();
            return true;
        };
        let receiver = lowercase[..method_offset]
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !reviewed_webclient_receiver(receiver.trim()) {
            self.draft.set_partial();
            return true;
        }
        let offset = method_offset + needle.len();
        let Some(end) = matching_parenthesis(statement, offset) else {
            self.draft.set_partial();
            return true;
        };
        if !statement[end + 1..].trim().is_empty() {
            self.draft.set_partial();
            return true;
        }
        let Some((lexemes, _)) = lex(&statement[offset..end], self.input.home) else {
            self.draft.set_partial();
            return true;
        };
        let arguments = lexemes
            .into_iter()
            .filter_map(|lexeme| match lexeme {
                Lexeme::Word(token) => Some(token),
                Lexeme::Pipe | Lexeme::Redirect => None,
            })
            .collect::<Vec<_>>();
        let endpoint = arguments
            .first()
            .filter(|argument| argument.exact)
            .map(|argument| argument.value.clone());
        let filesystems = if writes_file {
            vec![arguments.get(1).map_or_else(
                || LanguageFilesystem::new(None, FilesystemOperation::Write, false),
                |target| self.filesystem(target, FilesystemOperation::Write, false, true),
            )]
        } else {
            Vec::new()
        };
        let complete = arguments.len() == if writes_file { 2 } else { 1 }
            && arguments.iter().all(|argument| argument.exact)
            && endpoint.is_some()
            && (!writes_file || arguments.get(1).is_some());
        self.emit(
            LanguageCallKind::NetworkTransfer,
            callable,
            arguments.iter(),
            filesystems,
            endpoint,
            complete,
        );
        true
    }

    fn filesystem(
        &mut self,
        token: &Token,
        operation: FilesystemOperation,
        recursive: bool,
        literal: bool,
    ) -> LanguageFilesystem {
        let requested = token.exact.then(|| token.value.clone());
        if operation == FilesystemOperation::Delete && recursive {
            if requested.as_deref().is_some_and(windows_or_posix_root) {
                self.report
                    .push(Finding::exact(FindingKind::RootDestruction));
            }
            if requested
                .as_deref()
                .is_some_and(|requested| requested.eq_ignore_ascii_case(self.input.home))
            {
                self.report
                    .push(Finding::exact(FindingKind::HomeDestruction));
            }
        }
        LanguageFilesystem::new(requested, operation, recursive)
            .pattern_if(!literal && token.exact && path_pattern(&token.value))
    }

    fn emit<'t>(
        &mut self,
        kind: LanguageCallKind,
        callable: &str,
        arguments: impl Iterator<Item = &'t Token>,
        filesystems: Vec<LanguageFilesystem>,
        endpoint: Option<String>,
        mut complete: bool,
    ) {
        let arguments = arguments.collect::<Vec<_>>();
        complete &= arguments.iter().all(|argument| argument.exact)
            && filesystems
                .iter()
                .all(|filesystem| filesystem.requested().is_some())
            && (kind != LanguageCallKind::NetworkTransfer || endpoint.is_some());
        if !complete {
            self.draft.set_partial();
        }
        let input = InvocationInput::native(
            json!({
                "v": 1,
                "language": "powershell",
                "dialect": self.program,
                "callable": callable,
                "argv": arguments
                    .iter()
                    .map(|argument| argument.exact.then(|| argument.value.clone()))
                    .collect::<Vec<_>>(),
            }),
            complete,
        );
        self.draft.push_call(LanguageCall::new(
            kind,
            input,
            filesystems,
            endpoint,
            0,
            Vec::new(),
        ));
    }
}

#[derive(Clone, Copy)]
enum CanonicalCommand {
    RemoveItem,
    MoveItem,
    GetContent,
    SetContent,
    AddContent,
    ClearContent,
    OutFile,
    InvokeWebRequest,
    InvokeRestMethod,
    CurlAlias,
    InvokeExpression,
    StartProcess,
    NoEffect,
    External,
}

fn canonical_command(command: &str, platform: Platform) -> CanonicalCommand {
    match command {
        "remove-item" | "ri" | "rm" => CanonicalCommand::RemoveItem,
        "rmdir" | "del" | "erase" | "rd" if platform == Platform::Windows => {
            CanonicalCommand::RemoveItem
        }
        "move-item" | "mi" | "mv" | "move" => CanonicalCommand::MoveItem,
        "get-content" | "gc" | "cat" => CanonicalCommand::GetContent,
        "type" if platform == Platform::Windows => CanonicalCommand::GetContent,
        "set-content" | "sc" => CanonicalCommand::SetContent,
        "add-content" | "ac" => CanonicalCommand::AddContent,
        "clear-content" | "clc" => CanonicalCommand::ClearContent,
        "out-file" => CanonicalCommand::OutFile,
        "invoke-webrequest" | "iwr" => CanonicalCommand::InvokeWebRequest,
        "invoke-restmethod" | "irm" => CanonicalCommand::InvokeRestMethod,
        "curl" | "wget" => CanonicalCommand::CurlAlias,
        "invoke-expression" | "iex" => CanonicalCommand::InvokeExpression,
        "start-process" | "saps" | "start" => CanonicalCommand::StartProcess,
        "write-output" | "echo" | "write-host" => CanonicalCommand::NoEffect,
        _ => CanonicalCommand::External,
    }
}

fn statements(code: &str) -> Vec<&str> {
    let bytes = code.as_bytes();
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        if let Some(active) = quote {
            if bytes[index] == b'`' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if bytes[index] == active {
                if active == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'`' && index + 1 < bytes.len() {
            let escaped = code[index + 1..]
                .chars()
                .next()
                .expect("index is inside the source");
            index += 1 + escaped.len_utf8();
            continue;
        }
        match bytes[index] {
            b'\'' | b'"' => quote = Some(bytes[index]),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b';' | b'\n' if depth == 0 => {
                result.push(&code[start..index]);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    result.push(&code[start..]);
    result
}

fn code_without_powershell_line_continuations(code: &str) -> Option<String> {
    let bytes = code.as_bytes();
    let mut result = String::with_capacity(code.len());
    let mut segment_start = 0;
    let mut quote = None;
    let mut index = 0;
    while index < bytes.len() {
        if quote == Some(b'\'') {
            if bytes[index] == b'\'' {
                if bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'`' {
            let continuation_len = if bytes.get(index + 1) == Some(&b'\n') {
                Some(2)
            } else if bytes.get(index + 1) == Some(&b'\r') && bytes.get(index + 2) == Some(&b'\n') {
                Some(3)
            } else {
                None
            };
            if let Some(continuation_len) = continuation_len {
                result.push_str(&code[segment_start..index]);
                index += continuation_len;
                segment_start = index;
                continue;
            }
            index += usize::from(index + 1 < bytes.len()) + 1;
            continue;
        }
        if let Some(active) = quote {
            if bytes[index] == active {
                quote = None;
            }
        } else if matches!(bytes[index], b'\'' | b'"') {
            quote = Some(bytes[index]);
        }
        index += 1;
    }
    if segment_start == 0 {
        return None;
    }
    result.push_str(&code[segment_start..]);
    Some(result)
}

fn strip_comments(code: &str) -> (String, bool) {
    let bytes = code.as_bytes();
    let mut output = String::with_capacity(code.len());
    let mut quote = None;
    let mut block = false;
    let mut index = 0;
    while index < bytes.len() {
        if block {
            if bytes[index..].starts_with(b"#>") {
                output.push_str("  ");
                index += 2;
                block = false;
            } else {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        if let Some(active) = quote {
            if bytes[index] == b'`' && index + 1 < bytes.len() {
                output.push('`');
                index += 1;
                let character = code[index..]
                    .chars()
                    .next()
                    .expect("index is inside the source");
                output.push(character);
                index += character.len_utf8();
                continue;
            }
            if bytes[index] == active {
                quote = None;
            }
            let character = code[index..]
                .chars()
                .next()
                .expect("index is inside the source");
            output.push(character);
            index += character.len_utf8();
            continue;
        }
        if bytes[index..].starts_with(b"<#") && comment_token_starts(bytes, index) {
            output.push_str("  ");
            index += 2;
            block = true;
            continue;
        }
        if bytes[index] == b'#' && comment_token_starts(bytes, index) {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"') {
            quote = Some(bytes[index]);
        }
        let character = code[index..]
            .chars()
            .next()
            .expect("index is inside the source");
        output.push(character);
        index += character.len_utf8();
    }
    (output, !block)
}

fn lex(source: &str, home: &str) -> Option<(Vec<Lexeme>, bool)> {
    let bytes = source.as_bytes();
    let mut lexemes = Vec::new();
    let mut bindings_complete = true;
    let mut index = 0;
    while index < bytes.len() {
        while let Some(byte) = bytes.get(index) {
            if *byte == b',' {
                bindings_complete = false;
            } else if !byte.is_ascii_whitespace() {
                break;
            }
            index += 1;
        }
        let Some(byte) = bytes.get(index).copied() else {
            break;
        };
        if byte == b'#' {
            break;
        }
        if byte == b'|' {
            if bytes.get(index + 1) == Some(&b'|') {
                return None;
            }
            lexemes.push(Lexeme::Pipe);
            index += 1;
            continue;
        }
        if byte == b'>' || redirect_prefix(bytes, index) {
            if byte != b'>' {
                index += 1;
            }
            index += 1;
            if bytes.get(index) == Some(&b'>') {
                index += 1;
            }
            lexemes.push(Lexeme::Redirect);
            continue;
        }
        let mut value = String::new();
        let mut exact = true;
        let mut quoted = false;
        let mut quote = None;
        // PowerShell expands `$` only outside single quotes and backtick
        // escapes, so exactness is decided per segment: a token such as
        // `'C:\Users\test'$rest` is literal up to the quote and still
        // expands afterwards.
        let mut live_expansion = false;
        let mut expansion_starts_token = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if let Some(active) = quote {
                if byte == b'`' && index + 1 < bytes.len() {
                    let character = source[index + 1..].chars().next()?;
                    value.push(character);
                    index += 1 + character.len_utf8();
                    continue;
                }
                if byte == active {
                    if active == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                        value.push('\'');
                        index += 2;
                        continue;
                    }
                    quote = None;
                    index += 1;
                    continue;
                }
                if active == b'"' && byte == b'$' {
                    expansion_starts_token |= value.is_empty();
                    live_expansion = true;
                }
                let character = source[index..].chars().next()?;
                value.push(character);
                index += character.len_utf8();
                continue;
            }
            match byte {
                b'\'' | b'"' => {
                    quoted = true;
                    quote = Some(byte);
                    index += 1;
                }
                b'`' if index + 1 < bytes.len() => {
                    let character = source[index + 1..].chars().next()?;
                    value.push(character);
                    index += 1 + character.len_utf8();
                }
                b'|' | b',' | b'>' => break,
                byte if byte.is_ascii_whitespace() => break,
                _ => {
                    if byte == b'$' {
                        expansion_starts_token |= value.is_empty();
                        live_expansion = true;
                    }
                    let character = source[index..].chars().next()?;
                    value.push(character);
                    index += character.len_utf8();
                }
            }
        }
        if quote.is_some() {
            return None;
        }
        if let Some(resolved) = resolve_static_home_reference(&value, home, expansion_starts_token)
        {
            value = resolved;
            exact = true;
        } else if (live_expansion && !static_boolean_parameter(&value)) || value.starts_with('@') {
            exact = false;
        }
        if !value.is_empty() {
            lexemes.push(Lexeme::Word(Token {
                value,
                exact,
                quoted,
            }));
        }
    }
    Some((lexemes, bindings_complete))
}

fn comment_token_starts(bytes: &[u8], index: usize) -> bool {
    index == 0
        || bytes[index - 1].is_ascii_whitespace()
        || matches!(
            bytes[index - 1],
            b';' | b'|' | b'&' | b'(' | b')' | b'{' | b'}' | b',' | b'>'
        )
}

fn redirect_prefix(bytes: &[u8], index: usize) -> bool {
    bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'*')
        && bytes.get(index + 1) == Some(&b'>')
}

fn stream_merge(target: &str) -> bool {
    target
        .strip_prefix('&')
        .is_some_and(|stream| stream.len() == 1 && stream.as_bytes()[0].is_ascii_digit())
}

/// Resolves a PowerShell token that names the declared home through the
/// provider `~` or a recognized home variable. `expansion_starts_token` states
/// whether the token begins with a live expansion, so quoted or escaped
/// lookalikes stay literal. Any further `$` in the remainder leaves the token
/// unresolved rather than inventing a concrete path.
fn resolve_static_home_reference(
    value: &str,
    home: &str,
    expansion_starts_token: bool,
) -> Option<String> {
    let mut suffix = static_home_suffix(value, "~");
    if suffix.is_none() && expansion_starts_token {
        suffix = ["${home}", "$env:userprofile", "$home"]
            .into_iter()
            .find_map(|prefix| static_home_suffix(value, prefix));
    }
    suffix
        .filter(|suffix| !suffix.contains('$'))
        .map(|suffix| format!("{home}{suffix}"))
}

fn static_home_suffix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let suffix = &value[prefix.len()..];
    matches!(suffix.as_bytes().first(), None | Some(b'/') | Some(b'\\')).then_some(suffix)
}

fn static_boolean_parameter(value: &str) -> bool {
    value
        .split_once(':')
        .is_some_and(|(_, value)| matches!(value.to_ascii_lowercase().as_str(), "$true" | "$false"))
}

fn parse_arguments(
    tokens: &[Token],
    parameter_kind: fn(&str) -> Option<(&'static str, bool)>,
) -> Arguments {
    let mut parsed = Arguments {
        complete: true,
        ..Arguments::default()
    };
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token.exact
            && let Some(parameter) = token.value.strip_prefix('-')
            && !parameter.is_empty()
        {
            let (name, attached) = parameter
                .split_once(':')
                .map_or((parameter, None), |(name, value)| {
                    (name, Some(value.to_owned()))
                });
            let written = name.to_ascii_lowercase();
            match parameter_kind(&written) {
                Some((name, true)) => {
                    parsed.complete &= static_switch_value(attached.as_deref()).is_some();
                    parsed.parameters.push(Parameter {
                        name: name.to_owned(),
                        value: None,
                        attached,
                    });
                }
                Some((name, false)) => {
                    let value = attached
                        .as_ref()
                        .map(|value| Token {
                            value: value.clone(),
                            exact: !value.contains('$'),
                            quoted: false,
                        })
                        .or_else(|| {
                            let value = tokens.get(index + 1)?;
                            index += 1;
                            Some(value.clone())
                        });
                    parsed.complete &= value.is_some();
                    parsed.parameters.push(Parameter {
                        name: name.to_owned(),
                        value,
                        attached,
                    });
                }
                None => {
                    parsed.complete = false;
                    if tokens
                        .get(index + 1)
                        .is_some_and(|next| !next.value.starts_with('-'))
                    {
                        index += 1;
                    }
                }
            }
        } else {
            parsed.complete &= token.exact;
            parsed.positional.push(token.clone());
        }
        index += 1;
    }
    parsed
}

fn remove_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(
        name,
        &[
            "recurse", "r", "force", "whatif", "confirm", "verbose", "debug",
        ],
        &[
            "path",
            "literalpath",
            "filter",
            "include",
            "exclude",
            "erroraction",
        ],
    )
}

fn move_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(
        name,
        &["force", "whatif", "confirm", "verbose", "debug"],
        &[
            "path",
            "literalpath",
            "destination",
            "filter",
            "include",
            "exclude",
            "erroraction",
        ],
    )
}

fn content_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(
        name,
        &[
            "force",
            "whatif",
            "confirm",
            "raw",
            "tail",
            "wait",
            "nonewline",
            "passthru",
            "verbose",
            "debug",
        ],
        &[
            "path",
            "literalpath",
            "value",
            "filter",
            "include",
            "exclude",
            "encoding",
            "erroraction",
            "totalcount",
            "readcount",
            "delimiter",
        ],
    )
}

fn out_file_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(
        name,
        &[
            "append",
            "force",
            "nonewline",
            "noclobber",
            "whatif",
            "confirm",
            "verbose",
            "debug",
        ],
        &[
            "filepath",
            "encoding",
            "width",
            "inputobject",
            "erroraction",
        ],
    )
}

fn web_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(
        name,
        &[
            "usebasicparsing",
            "disablekeepalive",
            "skipcertificatecheck",
            "skipheadervalidation",
            "preserveauthorizationonredirect",
            "resume",
            "passthru",
            "verbose",
            "debug",
        ],
        &[
            "uri",
            "outfile",
            "method",
            "headers",
            "body",
            "contenttype",
            "credential",
            "timeoutsec",
            "maximumredirection",
            "useragent",
            "websession",
            "sessionvariable",
            "proxy",
            "proxycredential",
            "erroraction",
        ],
    )
}

fn invoke_expression_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(name, &[], &["command"])
}

fn start_process_parameter(name: &str) -> Option<(&'static str, bool)> {
    parameter(
        name,
        &[
            "nonewwindow",
            "wait",
            "passthru",
            "loaduserprofile",
            "whatif",
            "confirm",
        ],
        &[
            "filepath",
            "argumentlist",
            "workingdirectory",
            "verb",
            "windowstyle",
            "erroraction",
        ],
    )
}

/// Binds a written PowerShell parameter name to the modeled parameter it
/// names, reporting whether that parameter is a switch (`true`) or takes a
/// value (`false`). PowerShell also binds an unambiguous parameter-name prefix
/// such as `-Rec`, so a prefix matching exactly one modeled name resolves to
/// that name. Shared common parameters also participate in ambiguity even when
/// the command-specific model does not otherwise consume them.
fn parameter(
    name: &str,
    switches: &'static [&'static str],
    values: &'static [&'static str],
) -> Option<(&'static str, bool)> {
    if let Some(switch) = switches.iter().find(|candidate| **candidate == name) {
        return Some((switch, true));
    }
    if let Some(value) = values.iter().find(|candidate| **candidate == name) {
        return Some((value, false));
    }
    let mut resolved = None;
    for (candidate, switch) in switches
        .iter()
        .map(|candidate| (*candidate, true))
        .chain(values.iter().map(|candidate| (*candidate, false)))
    {
        if candidate.starts_with(name) {
            if resolved.is_some() {
                return None;
            }
            resolved = Some((candidate, switch));
        }
    }
    let (resolved_name, _) = resolved?;
    if POWERSHELL_COMMON_PARAMETERS
        .iter()
        .any(|candidate| *candidate != resolved_name && candidate.starts_with(name))
    {
        return None;
    }
    resolved
}

const POWERSHELL_COMMON_PARAMETERS: &[&str] = &[
    "debug",
    "erroraction",
    "errorvariable",
    "informationaction",
    "informationvariable",
    "outbuffer",
    "outvariable",
    "pipelinevariable",
    "progressaction",
    "verbose",
    "warningaction",
    "warningvariable",
];

fn parameter_value<'a>(arguments: &'a Arguments, names: &[&str]) -> Option<&'a Token> {
    arguments
        .parameters
        .iter()
        .find(|parameter| names.contains(&parameter.name.as_str()))
        .and_then(|parameter| parameter.value.as_ref())
}

/// Collects the path operands of a path cmdlet and reports whether they were
/// bound literally. `-Path` and `-LiteralPath` select mutually exclusive
/// parameter sets. Only the first positional operand is a path: the second
/// positional operand binds `-Filter`, not another target.
fn path_targets(arguments: &Arguments) -> Option<(Vec<&Token>, bool)> {
    match (
        parameter_value(arguments, &["path"]),
        parameter_value(arguments, &["literalpath"]),
    ) {
        (Some(_), Some(_)) => None,
        (Some(value), None) => Some((vec![value], false)),
        (None, Some(value)) => Some((vec![value], true)),
        (None, None) => Some((arguments.positional.first().into_iter().collect(), false)),
    }
}

fn switch_enabled(arguments: &Arguments, name: &str) -> bool {
    arguments.parameters.iter().any(|parameter| {
        parameter.name == name && static_switch_value(parameter.attached.as_deref()) == Some(true)
    })
}

fn static_switch_value(attached: Option<&str>) -> Option<bool> {
    match attached {
        None => Some(true),
        Some(value) if value.eq_ignore_ascii_case("$true") => Some(true),
        Some(value) if value.eq_ignore_ascii_case("$false") => Some(false),
        Some(_) => None,
    }
}

fn dynamic_statement(source: &str, lowercase: &str) -> bool {
    source.contains("$(")
        || source.contains("@(")
        || source.contains("@{")
        || source.contains("&&")
        || source.contains("||")
        || source.contains(['{', '}'])
        || lowercase
            .split_ascii_whitespace()
            .next()
            .is_some_and(|command| {
                matches!(
                    command,
                    "if" | "elseif"
                        | "else"
                        | "foreach"
                        | "for"
                        | "while"
                        | "switch"
                        | "try"
                        | "catch"
                        | "finally"
                        | "trap"
                        | "do"
                        | "class"
                )
            })
        || source.trim_start().starts_with('$') && source.contains('=')
        || source.contains("::") && !lowercase.contains("system.net.webclient")
        || lowercase.contains("new-object") && !lowercase.contains("webclient")
}

fn definition_or_resolution_mutation(lowercase: &str, platform: Platform) -> bool {
    let trimmed = lowercase.trim_start();
    let command = trimmed.split_ascii_whitespace().next();
    trimmed.starts_with("function ")
        || trimmed.starts_with("filter ")
        || trimmed.starts_with("set-alias ")
        || trimmed.starts_with("new-alias ")
        || matches!(command, Some("set-item" | "si"))
            && (trimmed.contains("alias:") || trimmed.contains("function:"))
        || trimmed
            .split_ascii_whitespace()
            .next()
            .is_some_and(|command| {
                matches!(
                    canonical_command(command, platform),
                    CanonicalCommand::RemoveItem
                )
            })
            && trimmed.contains("alias:")
}

fn shadowed_commands(code: &str, home: &str, platform: Platform) -> BTreeSet<String> {
    let mut shadowed = BTreeSet::new();
    for statement in statements(code) {
        let Some((lexemes, _)) = lex(statement, home) else {
            continue;
        };
        let tokens = lexemes
            .into_iter()
            .filter_map(|lexeme| match lexeme {
                Lexeme::Word(token) => Some(token),
                Lexeme::Pipe | Lexeme::Redirect => None,
            })
            .collect::<Vec<_>>();
        let what_if = tokens.split_first().is_some_and(|(command, arguments)| {
            let raw_command = command.value.to_ascii_lowercase();
            let arguments = match canonical_command(&raw_command, platform) {
                CanonicalCommand::RemoveItem => parse_arguments(arguments, remove_parameter),
                _ if matches!(raw_command.as_str(), "set-item" | "si") => {
                    parse_arguments(arguments, content_parameter)
                }
                _ => return false,
            };
            switch_enabled(&arguments, "whatif")
        });
        if what_if {
            continue;
        }
        let words = tokens
            .iter()
            .map(|token| token.value.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if words.first().is_some_and(|word| {
            matches!(
                canonical_command(word, platform),
                CanonicalCommand::RemoveItem
            )
        }) {
            shadowed.extend(words[1..].iter().filter_map(|word| {
                word.strip_prefix("alias:")
                    .map(|name| name.trim_start_matches(['\\', '/']))
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            }));
        }
        if words
            .first()
            .is_some_and(|word| matches!(word.as_str(), "set-item" | "si"))
        {
            let target = words[1..]
                .windows(2)
                .find_map(|pair| {
                    matches!(pair[0].as_str(), "-path" | "-literalpath").then_some(pair[1].as_str())
                })
                .or_else(|| {
                    words[1..].iter().find_map(|word| {
                        word.strip_prefix("-path:")
                            .or_else(|| word.strip_prefix("-literalpath:"))
                    })
                })
                .or_else(|| {
                    words[1..]
                        .iter()
                        .find(|word| !word.starts_with('-'))
                        .map(String::as_str)
                });
            shadowed.extend(target.into_iter().filter_map(|target| {
                ["alias:", "function:"].into_iter().find_map(|provider| {
                    target
                        .strip_prefix(provider)
                        .map(|name| name.trim_start_matches(['\\', '/']))
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                })
            }));
        }
        match words.as_slice() {
            [kind, name, ..] if matches!(kind.as_str(), "function" | "filter") => {
                shadowed.insert(name.trim_matches(['{', '}']).to_owned());
            }
            [kind, flag, name, ..]
                if matches!(kind.as_str(), "set-alias" | "new-alias")
                    && flag.eq_ignore_ascii_case("-name") =>
            {
                shadowed.insert(name.clone());
            }
            [kind, name, ..] if matches!(kind.as_str(), "set-alias" | "new-alias") => {
                shadowed.insert(name.clone());
            }
            _ => {}
        }
    }
    shadowed
        .into_iter()
        .flat_map(|name| {
            let canonical = canonical_command(&name, platform);
            std::iter::once(name).chain(command_names(canonical).map(str::to_owned))
        })
        .collect()
}

fn reviewed_webclient_receiver(receiver: &str) -> bool {
    matches!(
        receiver,
        "(new-object system.net.webclient)"
            | "(new-object net.webclient)"
            | "(new-object -typename system.net.webclient)"
            | "(new-object -typename net.webclient)"
            | "[system.net.webclient]::new()"
            | "[net.webclient]::new()"
    )
}

fn command_names(command: CanonicalCommand) -> impl Iterator<Item = &'static str> {
    let names: &[&str] = match command {
        CanonicalCommand::RemoveItem => &["remove-item", "ri", "rm", "rmdir", "del", "erase", "rd"],
        CanonicalCommand::MoveItem => &["move-item", "mi", "mv", "move"],
        CanonicalCommand::GetContent => &["get-content", "gc", "cat", "type"],
        CanonicalCommand::SetContent => &["set-content", "sc"],
        CanonicalCommand::AddContent => &["add-content", "ac"],
        CanonicalCommand::ClearContent => &["clear-content", "clc"],
        CanonicalCommand::InvokeWebRequest => &["invoke-webrequest", "iwr"],
        CanonicalCommand::InvokeRestMethod => &["invoke-restmethod", "irm"],
        CanonicalCommand::InvokeExpression => &["invoke-expression", "iex"],
        CanonicalCommand::StartProcess => &["start-process", "saps", "start"],
        _ => &[],
    };
    names.iter().copied()
}

fn exact_external(command: &str) -> bool {
    let lowercase = command.to_ascii_lowercase();
    [".exe", ".com"]
        .iter()
        .any(|suffix| lowercase.ends_with(suffix))
        || lowercase.contains(['/', '\\'])
        || matches!(
            lowercase.as_str(),
            "git" | "nah" | "cmd" | "powershell" | "pwsh"
        )
}

fn path_pattern(path: &str) -> bool {
    path.contains(['*', '?', '['])
}

fn windows_or_posix_root(path: &str) -> bool {
    let path = path.trim_end_matches(['/', '\\']);
    path.is_empty()
        || path.len() == 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':'
}

fn matching_parenthesis(source: &str, arguments_start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 1usize;
    let mut quote = None;
    let mut index = arguments_start;
    while index < bytes.len() {
        if let Some(active) = quote {
            if bytes[index] == b'`' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if bytes[index] == active {
                quote = None;
            }
        } else {
            match bytes[index] {
                b'\'' | b'"' => quote = Some(bytes[index]),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use nah_proto::ctx::Platform;

    fn analysis(program: &str, code: &str) -> LanguageAnalysis {
        interpret_effects(
            program,
            &InlineInput {
                program,
                code,
                home: r"C:\Users\test",
                platform: Platform::Windows,
            },
            None,
            0,
        )
    }

    #[test]
    fn filters_do_not_consume_remove_item_targets() {
        let analysis = analysis("pwsh", "Remove-Item -Filter '/' -Recurse 'safe'");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            Some("safe")
        );
        assert!(
            !analysis
                .report()
                .contains_exact(FindingKind::RootDestruction)
        );
    }

    #[test]
    fn user_functions_remove_builtin_ownership() {
        let analysis = analysis(
            "pwsh",
            r"function Remove-Item {}; Remove-Item -Recurse 'C:\'",
        );
        assert!(analysis.draft().calls().is_empty());
        assert!(!analysis.draft().complete());
    }
}
