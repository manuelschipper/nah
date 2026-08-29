use nah_proto::action::{FilesystemOperation, InvocationInput};
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
}

#[derive(Clone, Debug)]
enum Lexeme {
    Word(Token),
    Redirect,
}

struct Interpreter<'a> {
    input: InlineInput<'a>,
    report: InlineReport,
    draft: LanguageDraft,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    _depth: usize,
) -> InlineReport {
    interpret_effects(program, input, protection, 0).into_report()
}

pub(super) fn interpret_effects(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    _depth: usize,
) -> LanguageAnalysis {
    let mut interpreter = Interpreter {
        input: *input,
        report: InlineReport::default(),
        draft: LanguageDraft::default(),
    };
    if has_cmd_line_continuation(input.code) {
        interpreter.draft.set_partial();
        let report = with_typed_protection(
            interpreter.report,
            program,
            input,
            protection,
            &interpreter.draft,
        );
        return LanguageAnalysis::new(report, interpreter.draft);
    }
    let (commands, complete) = commands(input.code);
    if !complete {
        interpreter.draft.set_partial();
    }
    for command in commands {
        interpreter.interpret_command(command);
    }
    let report = with_typed_protection(
        interpreter.report,
        program,
        input,
        protection,
        &interpreter.draft,
    );
    LanguageAnalysis::new(report, interpreter.draft)
}

fn has_cmd_line_continuation(code: &str) -> bool {
    code.contains("^\n") || code.contains("^\r\n")
}

impl Interpreter<'_> {
    fn interpret_command(&mut self, source: &str) {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            return;
        }
        let lowercase = trimmed.to_ascii_lowercase();
        if dynamic_command(trimmed, &lowercase) {
            self.draft.set_partial();
        }
        let Some(lexemes) = lex(trimmed) else {
            self.draft.set_partial();
            return;
        };
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
                    self.emit(
                        LanguageCallKind::DirectFile,
                        "redirection",
                        target.as_ref().into_iter(),
                        vec![target.as_ref().map_or_else(
                            || LanguageFilesystem::new(None, FilesystemOperation::Write, false),
                            |target| {
                                LanguageFilesystem::new(
                                    target.exact.then(|| target.value.clone()),
                                    FilesystemOperation::Write,
                                    false,
                                )
                            },
                        )],
                        None,
                        target.as_ref().is_some_and(|target| target.exact),
                    );
                }
            }
            index += 1;
        }
        let Some((command, arguments)) = words.split_first() else {
            return;
        };
        if !command.exact {
            self.draft.set_partial();
            return;
        }
        let lowercase = command.value.to_ascii_lowercase();
        match lowercase.trim_end_matches(".exe") {
            "del" | "erase" => self.delete(arguments),
            "rd" | "rmdir" => self.remove_directory(arguments),
            "move" => self.move_path(arguments),
            "type" => self.read_files(arguments),
            "certutil" if reviewed_certutil(arguments).is_some() => self.certutil(arguments),
            "echo" | "rem" | "ver" | "cls" | "cd" | "chdir" => self.emit(
                LanguageCallKind::LocalUtility,
                &lowercase,
                arguments.iter(),
                Vec::new(),
                None,
                arguments.iter().all(|argument| argument.exact),
            ),
            _ if exact_external(&command.value) => self.external(command, arguments),
            _ => self.draft.set_partial(),
        }
    }

    fn delete(&mut self, arguments: &[Token]) {
        let recursive = arguments
            .iter()
            .any(|argument| argument.exact && argument.value.eq_ignore_ascii_case("/s"));
        let targets = arguments
            .iter()
            .filter(|argument| !del_option(argument))
            .collect::<Vec<_>>();
        let filesystems = targets
            .iter()
            .map(|target| {
                LanguageFilesystem::new(
                    target.exact.then(|| target.value.clone()),
                    FilesystemOperation::Delete,
                    recursive,
                )
                .pattern_if(target.exact && path_pattern(&target.value))
                .file_only()
            })
            .collect();
        self.emit(
            LanguageCallKind::DirectFile,
            "del",
            arguments.iter(),
            filesystems,
            None,
            !targets.is_empty() && arguments.iter().all(|argument| argument.exact),
        );
    }

    fn remove_directory(&mut self, arguments: &[Token]) {
        let recursive = arguments
            .iter()
            .any(|argument| argument.exact && argument.value.eq_ignore_ascii_case("/s"));
        let targets = arguments
            .iter()
            .filter(|argument| !rd_option(argument))
            .collect::<Vec<_>>();
        let filesystems = targets
            .iter()
            .map(|target| {
                if recursive && target.exact {
                    self.add_destructive_target(&target.value);
                }
                LanguageFilesystem::new(
                    target.exact.then(|| target.value.clone()),
                    FilesystemOperation::Delete,
                    recursive,
                )
            })
            .collect();
        self.emit(
            LanguageCallKind::DirectFile,
            "rmdir",
            arguments.iter(),
            filesystems,
            None,
            !targets.is_empty() && arguments.iter().all(|argument| argument.exact),
        );
    }

    fn move_path(&mut self, arguments: &[Token]) {
        let paths = arguments
            .iter()
            .filter(|argument| !move_option(argument))
            .collect::<Vec<_>>();
        let source = paths.first().copied();
        let destination = paths.get(1).copied();
        let filesystems = vec![
            source.map_or_else(
                || LanguageFilesystem::new(None, FilesystemOperation::Delete, false),
                |source| {
                    LanguageFilesystem::new(
                        source.exact.then(|| source.value.clone()),
                        FilesystemOperation::Delete,
                        false,
                    )
                    .pattern_if(source.exact && path_pattern(&source.value))
                },
            ),
            destination
                .map_or_else(
                    || LanguageFilesystem::new(None, FilesystemOperation::Write, false),
                    |destination| {
                        LanguageFilesystem::new(
                            destination.exact.then(|| destination.value.clone()),
                            FilesystemOperation::Write,
                            false,
                        )
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
        ];
        self.emit(
            LanguageCallKind::DirectFile,
            "move",
            arguments.iter(),
            filesystems,
            None,
            source.is_some()
                && destination.is_some()
                && paths.len() == 2
                && arguments.iter().all(|argument| argument.exact)
                && arguments
                    .iter()
                    .filter(|argument| move_option(argument))
                    .all(|argument| {
                        matches!(argument.value.to_ascii_lowercase().as_str(), "/y" | "/-y")
                    }),
        );
    }

    fn read_files(&mut self, arguments: &[Token]) {
        let filesystems = arguments
            .iter()
            .map(|target| {
                LanguageFilesystem::new(
                    target.exact.then(|| target.value.clone()),
                    FilesystemOperation::Read,
                    false,
                )
                .pattern_if(target.exact && path_pattern(&target.value))
            })
            .collect();
        self.emit(
            LanguageCallKind::DirectFile,
            "type",
            arguments.iter(),
            filesystems,
            None,
            !arguments.is_empty() && arguments.iter().all(|argument| argument.exact),
        );
    }

    fn certutil(&mut self, arguments: &[Token]) {
        let (endpoint, target) = reviewed_certutil(arguments)
            .expect("certutil was admitted only after its reviewed shape matched");
        self.emit(
            LanguageCallKind::NetworkTransfer,
            "certutil.urlcache",
            arguments.iter(),
            vec![LanguageFilesystem::new(
                target.exact.then(|| target.value.clone()),
                FilesystemOperation::Write,
                false,
            )],
            endpoint.exact.then(|| endpoint.value.clone()),
            endpoint.exact && target.exact,
        );
    }

    fn external(&mut self, command: &Token, arguments: &[Token]) {
        let complete = arguments.iter().all(|argument| argument.exact);
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

    fn add_destructive_target(&mut self, target: &str) {
        if windows_root(target) {
            self.report
                .push(Finding::exact(FindingKind::RootDestruction));
        }
        if target.eq_ignore_ascii_case(self.input.home) {
            self.report
                .push(Finding::exact(FindingKind::HomeDestruction));
        }
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
        self.draft.push_call(LanguageCall::new(
            kind,
            InvocationInput::native(
                json!({
                    "v": 1,
                    "language": "cmd",
                    "callable": callable,
                    "argv": arguments
                        .iter()
                        .map(|argument| argument.exact.then(|| argument.value.clone()))
                        .collect::<Vec<_>>(),
                }),
                complete,
            ),
            filesystems,
            endpoint,
            0,
            Vec::new(),
        ));
    }
}

fn commands(source: &str) -> (Vec<&str>, bool) {
    let bytes = source.as_bytes();
    let mut commands = Vec::new();
    let mut complete = true;
    let mut quote = false;
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'^' && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if bytes[index] == b'"' {
            quote = !quote;
            index += 1;
            continue;
        }
        if !quote && matches!(bytes[index], b'&' | b'|' | b'\n') {
            complete &= bytes[index] == b'&' && bytes.get(index + 1) != Some(&b'&')
                || bytes[index] == b'\n';
            commands.push(&source[start..index]);
            if bytes.get(index + 1) == Some(&bytes[index]) {
                index += 1;
            }
            start = index + 1;
        }
        index += 1;
    }
    commands.push(&source[start..]);
    (commands, complete && !quote)
}

fn lex(source: &str) -> Option<Vec<Lexeme>> {
    let bytes = source.as_bytes();
    let mut lexemes = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        let Some(byte) = bytes.get(index).copied() else {
            break;
        };
        if byte == b'>' || byte == b'1' && bytes.get(index + 1) == Some(&b'>') {
            if byte == b'1' {
                index += 1;
            }
            index += 1;
            if bytes.get(index) == Some(&b'>') {
                index += 1;
            }
            lexemes.push(Lexeme::Redirect);
            continue;
        }
        if byte.is_ascii_digit() && bytes.get(index + 1) == Some(&b'>') {
            return None;
        }
        let mut value = String::new();
        let mut quote = false;
        while index < bytes.len() {
            match bytes[index] {
                b'^' if index + 1 < bytes.len() => {
                    let character = source[index + 1..].chars().next()?;
                    value.push(character);
                    index += 1 + character.len_utf8();
                }
                b'"' => {
                    quote = !quote;
                    index += 1;
                }
                b'>' if !quote => break,
                byte if !quote && byte.is_ascii_whitespace() => break,
                _ => {
                    let character = source[index..].chars().next()?;
                    value.push(character);
                    index += character.len_utf8();
                }
            }
        }
        if quote {
            return None;
        }
        if !value.is_empty() {
            let exact = !value.contains('%') && !value.contains('!');
            lexemes.push(Lexeme::Word(Token { value, exact }));
        }
    }
    Some(lexemes)
}

fn dynamic_command(source: &str, lowercase: &str) -> bool {
    source.contains(['%', '!'])
        || source.contains(['(', ')'])
        || lowercase
            .split_ascii_whitespace()
            .next()
            .is_some_and(|command| {
                matches!(
                    command,
                    "for" | "if" | "goto" | "call" | "setlocal" | "endlocal" | "shift"
                ) || command.starts_with(':')
            })
}

fn del_option(token: &Token) -> bool {
    let option = token.value.to_ascii_lowercase();
    token.exact
        && (matches!(option.as_str(), "/p" | "/f" | "/s" | "/q") || option.starts_with("/a"))
}

fn rd_option(token: &Token) -> bool {
    token.exact && matches!(token.value.to_ascii_lowercase().as_str(), "/s" | "/q")
}

fn move_option(token: &Token) -> bool {
    token.exact && matches!(token.value.to_ascii_lowercase().as_str(), "/y" | "/-y")
}

fn reviewed_certutil(arguments: &[Token]) -> Option<(&Token, &Token)> {
    let options = arguments
        .iter()
        .filter(|argument| argument.value.starts_with('-'))
        .map(|argument| argument.value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if !options.iter().any(|option| option == "-urlcache")
        || !options.iter().any(|option| option == "-f")
        || options
            .iter()
            .any(|option| !matches!(option.as_str(), "-urlcache" | "-f" | "-split"))
    {
        return None;
    }
    let operands = arguments
        .iter()
        .filter(|argument| !argument.value.starts_with('-'))
        .collect::<Vec<_>>();
    match operands.as_slice() {
        [endpoint, target] => Some((*endpoint, *target)),
        _ => None,
    }
}

fn exact_external(command: &str) -> bool {
    let lowercase = command.to_ascii_lowercase();
    [".exe", ".com", ".cmd", ".bat"]
        .iter()
        .any(|suffix| lowercase.ends_with(suffix))
        || lowercase.contains(['/', '\\'])
        || matches!(
            lowercase.as_str(),
            "git" | "nah" | "cmd" | "powershell" | "pwsh"
        )
}

fn path_pattern(path: &str) -> bool {
    path.contains(['*', '?'])
}

fn windows_root(path: &str) -> bool {
    let path = path.trim_end_matches(['/', '\\']);
    path.len() == 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;
    use nah_proto::ctx::Platform;

    fn analysis(code: &str) -> LanguageAnalysis {
        interpret_effects(
            "cmd",
            &InlineInput {
                program: "cmd",
                code,
                home: r"C:\Users\test",
                platform: Platform::Windows,
            },
            None,
            0,
        )
    }

    #[test]
    fn directory_commands_keep_recursive_and_file_only_boundaries() {
        let rd = analysis(r"rd C:\tmp");
        assert!(!rd.draft().calls()[0].filesystems()[0].recursive());

        let del = analysis(r"del /s C:\tmp\*");
        assert!(del.draft().calls()[0].filesystems()[0].recursive());
        assert!(del.draft().calls()[0].filesystems()[0].file_only_target());
    }
}
