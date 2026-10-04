//! The Windows command interpreter's literal command line. The line splits at
//! its unquoted `&`, `&&`, `||` and `|`, and each command's words must be
//! recoverable after `^` escaping, quoting, and `%NAME%` expansion from the
//! supplied environment. Built-in file commands are modeled here, a
//! `powershell`/`pwsh` head nests its source as PowerShell, and any other
//! program is handed to the command models as a nested invocation. cmd's
//! other internal commands and foreign grammars end that command's walk in a
//! boundary, as do blocks and delayed expansion, each naming the construct.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, PathPlatform, ProvenanceKind, ProvenanceRef, RequestAssurance,
    ResourceExpr, ResourceIdentity, filesystem_path,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, Transition, word_resource};

/// Domains this frontend models. Anything outside them stays unclaimed.
const DOMAINS: [&str; 3] = ["environment", "filesystem", "process"];

/// Switches each deletion command accepts. `/s` is the recursive selector.
const DEL_SWITCHES: [&str; 5] = ["p", "f", "s", "q", "a"];
const RD_SWITCHES: [&str; 2] = ["s", "q"];
const COPY_SWITCHES: [&str; 6] = ["a", "b", "d", "v", "y", "z"];

/// Command lines nested through an interpreter this line starts.
const MAX_NESTED_SOURCE_DEPTH: u32 = 4;

/// The interpreter's own commands that this grammar does not model. cmd runs
/// each of them itself instead of searching PATH, so their effects are not a
/// program the command models can own.
const INTERNAL: [&str; 26] = [
    "assoc", "break", "call", "cls", "color", "date", "dir", "endlocal", "for", "ftype", "goto",
    "if", "path", "pause", "popd", "prompt", "pushd", "set", "setlocal", "shift", "start", "time",
    "title", "ver", "verify", "vol",
];

/// Programs in Microsoft's Windows Commands reference that share a name with a
/// modeled tool but not its option grammar — Windows `sort` writes with `/O`,
/// `find` takes a search string rather than a root, `timeout` counts with `/T`.
/// Reading their lines with the other tool's grammar would misname operands,
/// so they keep the boundary the rest of the unmodeled surface gets.
const FOREIGN_GRAMMAR: [&str; 11] = [
    "at", "find", "ftp", "more", "mount", "netstat", "print", "shutdown", "sort", "timeout",
    "whoami",
];

pub(super) fn analyze(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    scope: Option<ProvenanceRef>,
) {
    let node = builder.node(
        ProvenanceKind::SourceSpan {
            start: 0,
            end: source.len() as u32,
        },
        scope.as_slice(),
    );
    if source.len() as u64 > nest.limits.max_source_bytes {
        builder.boundary(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: Some("max_source_bytes".into()),
            detail: None,
        });
        return;
    }
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    let mut walk = CmdWalk {
        nest,
        cwd,
        node,
        depth: 0,
        understood: true,
    };
    walk.line(builder, source);
    if walk.understood {
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

/// Analyze a command line reached from another frontend. Returns whether the
/// line was understood; the caller that nests it declares the coverage.
pub(super) fn nested(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let mut walk = CmdWalk {
        nest,
        cwd,
        node,
        depth,
        understood: true,
    };
    walk.line(builder, source);
    walk.understood
}

struct CmdWalk<'a> {
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    node: ProvenanceRef,
    depth: u32,
    understood: bool,
}

impl CmdWalk<'_> {
    fn line(&mut self, builder: &mut PlanBuilder, source: &str) {
        let (commands, partial) = commands(source);
        if partial {
            self.understood = false;
            builder.boundary(Boundary {
                reason: BoundaryReason::MODEL_COVERAGE,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![self.node],
                limit: None,
                detail: Some(
                    "cmd `&&`, `||` or `|` decides at runtime which commands run, and where".into(),
                ),
            });
        }
        if commands.len() > 1 && commands.iter().any(|command| command.trim().is_empty()) {
            return self.boundary(builder, "cmd command separator has an empty command");
        }
        for command in commands {
            let line = match self.words(builder, command) {
                Ok(line) => line,
                Err(detail) => {
                    self.boundary(builder, detail);
                    continue;
                }
            };
            if let Err(detail) = self.apply(builder, &line) {
                self.boundary(builder, detail);
            }
        }
    }

    fn apply(&mut self, builder: &mut PlanBuilder, line: &Line) -> Result<(), String> {
        for redirect in &line.redirects {
            match redirect.operation {
                CmdRedirection::Read => {
                    self.effect(builder, "filesystem.read", &redirect.target, &[])?
                }
                CmdRedirection::Write => {
                    self.effect(builder, "filesystem.write", &redirect.target, &[])?
                }
                CmdRedirection::Append => self.effect(
                    builder,
                    "filesystem.write",
                    &redirect.target,
                    &[("append", true)],
                )?,
            };
        }
        let Some((head, operands)) = line.words.split_first() else {
            // A line that only redirects still creates its target.
            return Ok(());
        };
        let Some(head) = head.text() else {
            return Err("cmd command name is not a recoverable string".into());
        };
        let head = head.to_ascii_lowercase();
        // cmd appends the PATHEXT extensions when it searches, so a program
        // named with one is the same command as the bare name.
        let program = head
            .strip_suffix(".exe")
            .or_else(|| head.strip_suffix(".com"))
            .unwrap_or(&head);
        match head.as_str() {
            "del" | "erase" => {
                let (recursive, operands) = switches(operands, &DEL_SWITCHES)?;
                self.each(builder, &operands, "filesystem.delete", recursive)
            }
            "rd" | "rmdir" => {
                let (recursive, operands) = switches(operands, &RD_SWITCHES)?;
                self.each(builder, &operands, "filesystem.delete", recursive)
            }
            "md" | "mkdir" => {
                let (_, operands) = switches(operands, &[])?;
                self.each(builder, &operands, "filesystem.create", false)
            }
            "type" => {
                let (_, operands) = switches(operands, &[])?;
                self.each(builder, &operands, "filesystem.read", false)
            }
            "copy" => {
                let (_, operands) = switches(operands, &COPY_SWITCHES)?;
                let [source, target] = operands.as_slice() else {
                    return Err("cmd copy does not name one source and one target".into());
                };
                self.effect(builder, "filesystem.read", source, &[])?;
                self.effect(builder, "filesystem.write", target, &[])?;
                Ok(())
            }
            "move" | "ren" | "rename" => {
                let (_, operands) = switches(operands, &["y"])?;
                let [source, target] = operands.as_slice() else {
                    return Err("cmd move does not name one source and one target".into());
                };
                self.effect(builder, "filesystem.move", source, &[])?;
                self.effect(builder, "filesystem.delete", source, &[])?;
                // `ren` names the new entry inside the source's directory.
                let target = if head.eq_ignore_ascii_case("move") {
                    target.clone()
                } else {
                    sibling(source, target)?
                };
                self.effect(builder, "filesystem.write", &target, &[])?;
                Ok(())
            }
            "mklink" => self.mklink(builder, operands),
            "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
                self.nested_powershell(builder, &head, operands)
            }
            "echo" | "rem" | "exit" | "cd" | "chdir" => Ok(()),
            _ if INTERNAL.contains(&program) || FOREIGN_GRAMMAR.contains(&program) => Err(format!(
                "cmd command {program:?} is outside the literal built-in grammar"
            )),
            _ => self.external(builder, line),
        }
    }

    /// A head outside the built-in grammar names a program cmd launches with
    /// the operands parsed here. The command models own what that program
    /// does, so the nested invocation declares its own coverage; an unmodeled
    /// program keeps the boundary the registry raises for it.
    fn external(&mut self, builder: &mut PlanBuilder, line: &Line) -> Result<(), String> {
        let words = line
            .words
            .iter()
            .map(|word| {
                crate::word::Word::new(
                    word.0
                        .iter()
                        .map(|part| match part {
                            CmdWordPart::Text(text) => crate::word::WordPart::Literal(text.clone()),
                            CmdWordPart::Env(name) => crate::word::WordPart::Env(name.clone()),
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        self.nest.nest(
            builder,
            Transition::exec(words.iter().map(word_resource).collect(), words)
                .exec_cwd(self.cwd)
                .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
            &[self.node],
            builder.execution_depth(),
        );
        Ok(())
    }

    /// `powershell -Command SOURCE` runs the rest of the line as PowerShell.
    fn nested_powershell(
        &mut self,
        builder: &mut PlanBuilder,
        executable: &str,
        operands: &[CmdWord],
    ) -> Result<(), String> {
        let arguments = operands
            .iter()
            .map(CmdWord::text)
            .collect::<Option<Vec<_>>>()
            .ok_or("cmd PowerShell invocation has a symbolic argument")?;
        // PowerShell's own command-line parameters accept an unambiguous
        // prefix; -Command takes the whole remaining command line as source.
        let command = arguments
            .iter()
            .position(|argument| {
                argument.len() > 1
                    && argument.starts_with('-')
                    && "command".starts_with(&argument[1..].to_ascii_lowercase())
            })
            .ok_or("cmd PowerShell invocation passes no inline command")?;
        super::powershell::interpreter_exec(builder, self.node, executable);
        if self.depth >= MAX_NESTED_SOURCE_DEPTH {
            self.understood = false;
            builder.boundary(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![self.node],
                limit: Some("max_execution_depth".into()),
                detail: None,
            });
            return Ok(());
        }
        let source = arguments[command + 1..].join(" ");
        self.understood &= super::powershell::nested(
            builder,
            self.nest,
            &source,
            self.cwd,
            self.node,
            self.depth + 1,
        );
        Ok(())
    }

    /// `mklink /h LINK TARGET` gives the target's file a second name, so it
    /// keeps the same metadata source and exact relation as `ln`. The symbolic
    /// link and junction forms stay outside the grammar.
    fn mklink(&mut self, builder: &mut PlanBuilder, operands: &[CmdWord]) -> Result<(), String> {
        let (link, target) = match operands {
            [switch, link, target]
                if switch
                    .text()
                    .is_some_and(|switch| switch.eq_ignore_ascii_case("/h")) =>
            {
                (link, target)
            }
            _ => return Err("cmd mklink creates a link other than a hard link".into()),
        };
        let created = self.effect(builder, "filesystem.create", link, &[("symlink", false)])?;
        let source = self.effect(builder, "filesystem.read", target, &[("metadata", true)])?;
        if let (Some(source), Some(created)) = (source, created) {
            builder.transfer_binding(crate::TransferBinding::exact(source, created));
        }
        Ok(())
    }

    fn each(
        &mut self,
        builder: &mut PlanBuilder,
        operands: &[CmdWord],
        operation: &str,
        recursive: bool,
    ) -> Result<(), String> {
        if operands.is_empty() {
            return Err("cmd command has no literal operand".into());
        }
        let attributes: &[(&str, bool)] = if operation == "filesystem.delete" {
            &[("recursive", recursive)]
        } else {
            &[]
        };
        for operand in operands {
            self.effect(builder, operation, operand, attributes)?;
        }
        Ok(())
    }

    fn effect(
        &mut self,
        builder: &mut PlanBuilder,
        operation: &str,
        word: &CmdWord,
        attributes: &[(&str, bool)],
    ) -> Result<Option<u32>, String> {
        let resource = self.resource(word)?;
        let mut provenance = vec![self.node];
        if operation == "filesystem.delete" {
            provenance.push(builder.node(
                ProvenanceKind::ModelApplication {
                    model: "windows/cmd-delete@v1".into(),
                },
                &[self.node],
            ));
        }
        Ok(builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: attributes
                .iter()
                .map(|(name, value)| ((*name).to_string(), AttrValue::Bool(*value)))
                .collect(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance,
        }))
    }

    /// The text that names the operand's provider: the operand itself when it
    /// is rooted, otherwise the working directory it resolves against.
    fn provider(&self, word: &CmdWord) -> Option<String> {
        match word.text() {
            Some(text) if text.starts_with('/') || windows_provider(&text) => Some(text),
            _ => self.cwd.map(str::to_string),
        }
    }

    fn resource(&self, word: &CmdWord) -> Result<ResourceExpr, String> {
        let provider = self.provider(word);
        // A UNC operand names a share on another host, and the canonical path
        // form keeps no host of its own, so that provider stays open.
        if provider
            .as_deref()
            .is_some_and(|provider| provider.starts_with("\\\\"))
        {
            return Err("cmd UNC path operands are not resolved".into());
        }
        // A drive letter selects the Windows dialect; anything else resolves
        // in the working directory's own.
        let platform = if provider.as_deref().is_some_and(windows_provider) {
            PathPlatform::Windows
        } else {
            PathPlatform::Posix
        };
        match word.text() {
            Some(path) if !path.is_empty() => {
                let resolved = filesystem_path(
                    &path,
                    self.cwd.map(|cwd| filesystem_path(cwd, None, platform)),
                    platform,
                );
                // cmd expands wildcards itself, so the operand selects a set.
                match (&resolved, path.contains(['*', '?'])) {
                    (
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        },
                        true,
                    ) => Ok(ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::FsPath {
                            glob: path.clone(),
                            narrowing: Default::default(),
                        },
                    }),
                    _ => Ok(resolved),
                }
            }
            Some(_) => Err("cmd operand is not a recoverable path".into()),
            None => Ok(ResourceExpr::Join {
                parts: word
                    .0
                    .iter()
                    .map(|part| match part {
                        CmdWordPart::Text(text) => ResourceExpr::Literal {
                            value: text.clone(),
                        },
                        CmdWordPart::Env(name) => ResourceExpr::Environment { name: name.clone() },
                    })
                    .collect(),
            }),
        }
    }

    /// Tokenize one command line, expanding `%NAME%` from the supplied
    /// environment and recording each expansion as an environment read.
    fn words(&mut self, builder: &mut PlanBuilder, source: &str) -> Result<Line, String> {
        let mut line = Line::default();
        let mut current = CmdWord::default();
        let mut started = false;
        let mut quoted = false;
        let mut pending: Option<CmdRedirection> = None;
        let mut rest = source;
        while let Some(character) = rest.chars().next() {
            rest = &rest[character.len_utf8()..];
            if quoted {
                if character == '"' {
                    quoted = false;
                } else if character == '%' {
                    self.expand(builder, &mut current, &mut rest)?;
                } else {
                    current.push(character);
                }
                continue;
            }
            match character {
                '"' => {
                    quoted = true;
                    started = true;
                }
                '^' => {
                    let escaped = rest.chars().next().ok_or("cmd escape is truncated")?;
                    rest = &rest[escaped.len_utf8()..];
                    // A caret before the line terminator continues the line:
                    // the terminator is removed rather than becoming text.
                    if escaped == '\r' || escaped == '\n' {
                        if escaped == '\r' {
                            rest = rest.strip_prefix('\n').unwrap_or(rest);
                        }
                        continue;
                    }
                    current.push(escaped);
                    started = true;
                }
                '%' => {
                    self.expand(builder, &mut current, &mut rest)?;
                    started = true;
                }
                '(' | ')' | '!' => {
                    return Err("cmd command line opens a block or delays expansion".to_string());
                }
                '<' | '>' => {
                    let append = character == '>' && rest.starts_with('>');
                    if append {
                        rest = &rest[1..];
                    }
                    if started {
                        push_word(&mut line, &mut current, &mut started, &mut pending);
                    }
                    pending = Some(match (character, append) {
                        ('<', _) => CmdRedirection::Read,
                        (_, true) => CmdRedirection::Append,
                        _ => CmdRedirection::Write,
                    });
                }
                character if character.is_whitespace() => {
                    if started {
                        push_word(&mut line, &mut current, &mut started, &mut pending);
                    }
                }
                // A trailing stream selector belongs to the redirection.
                character => {
                    if character.is_ascii_digit() && rest.starts_with(['<', '>']) && !started {
                        continue;
                    }
                    current.push(character);
                    started = true;
                }
            }
        }
        if quoted {
            return Err("cmd quoted argument is unterminated".into());
        }
        if started {
            push_word(&mut line, &mut current, &mut started, &mut pending);
        }
        if pending.is_some() {
            return Err("cmd redirection has no target".into());
        }
        Ok(line)
    }

    /// Expand one `%NAME%` reference. An unterminated `%` is a literal percent.
    fn expand(
        &mut self,
        builder: &mut PlanBuilder,
        word: &mut CmdWord,
        rest: &mut &str,
    ) -> Result<(), String> {
        let name_end = rest
            .char_indices()
            .take_while(|(_, c)| *c != '%' && !c.is_whitespace())
            .count();
        let Some(name) = rest
            .get(..name_end)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '(' || c == ')')
            })
            .filter(|name| rest[name.len()..].starts_with('%'))
        else {
            word.push('%');
            return Ok(());
        };
        let name = name.to_string();
        *rest = &rest[name.len() + 1..];
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: name.clone() },
            },
            attributes: Default::default(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance: vec![self.node],
        });
        // The supplied environment is not a proven inventory, so a name it
        // does not carry stays symbolic rather than expanding to nothing.
        match self.nest.environment_value(&name) {
            Some(ResourceExpr::Literal { value }) => word.0.push(CmdWordPart::Text(value)),
            _ => word.0.push(CmdWordPart::Env(name)),
        }
        Ok(())
    }

    fn boundary(&mut self, builder: &mut PlanBuilder, detail: impl Into<String>) {
        self.understood = false;
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unsupported,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![self.node],
            limit: None,
            detail: Some(detail.into()),
        });
    }
}

/// Split a line at its unquoted command separators, and report whether one of
/// them leaves which commands run, or in which process, to runtime: `&&` and
/// `||` run the next command only on the previous one's exit status, and `|`
/// runs each side in a child cmd of its own. `&` runs both unconditionally.
fn commands(source: &str) -> (Vec<&str>, bool) {
    let bytes = source.as_bytes();
    let mut commands = Vec::new();
    let mut partial = false;
    let mut quoted = false;
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => quoted = !quoted,
            b'^' if !quoted => index += 1,
            separator @ (b'&' | b'|') if !quoted => {
                commands.push(&source[start..index]);
                let doubled = bytes.get(index + 1) == Some(&separator);
                partial |= separator == b'|' || doubled;
                if doubled {
                    index += 1;
                }
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    commands.push(source.get(start..).unwrap_or_default());
    (commands, partial)
}

fn push_word(
    line: &mut Line,
    word: &mut CmdWord,
    started: &mut bool,
    pending: &mut Option<CmdRedirection>,
) {
    let word = std::mem::take(word);
    *started = false;
    match pending.take() {
        Some(operation) => line.redirects.push(Redirect {
            operation,
            target: word,
        }),
        None => line.words.push(word),
    }
}

/// Split switches from operands. A `/` word is a switch only when it names one
/// letter, optionally with a `:value`; any other `/` word is a path operand.
fn switches(words: &[CmdWord], accepted: &[&str]) -> Result<(bool, Vec<CmdWord>), String> {
    let mut recursive = false;
    let mut operands = Vec::new();
    for word in words {
        let switch = word
            .text()
            .and_then(|text| text.strip_prefix('/').map(str::to_string))
            .map(|switch| {
                switch
                    .split_once(':')
                    .map_or(switch.clone(), |(name, _)| name.to_string())
            })
            .filter(|switch| switch.len() == 1 && switch.starts_with(char::is_alphabetic));
        let Some(switch) = switch else {
            operands.push(word.clone());
            continue;
        };
        let switch = switch.to_ascii_lowercase();
        if !accepted.contains(&switch.as_str()) {
            return Err(format!("cmd switch /{switch} is not modeled here"));
        }
        recursive |= switch == "s";
    }
    Ok((recursive, operands))
}

/// `ren` names its target inside the source entry's directory.
fn sibling(source: &CmdWord, target: &CmdWord) -> Result<CmdWord, String> {
    let (source, target) = match (source.text(), target.text()) {
        (Some(source), Some(target)) => (source, target),
        _ => return Err("cmd rename operands are not recoverable strings".into()),
    };
    if target.contains(['/', '\\']) {
        return Err("cmd rename target is a path, not a name".into());
    }
    let parent = source
        .rfind(['/', '\\'])
        .ok_or("cmd rename source has no directory")?;
    Ok(CmdWord(vec![CmdWordPart::Text(format!(
        "{}{target}",
        &source[..parent + 1]
    ))]))
}

/// Whether the text names a Windows drive or UNC provider.
fn windows_provider(text: &str) -> bool {
    text.starts_with("\\\\")
        || (text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && (text.get(1..3) == Some(":\\") || text.get(1..3) == Some(":/")))
}

#[derive(Default)]
struct Line {
    words: Vec<CmdWord>,
    redirects: Vec<Redirect>,
}

struct Redirect {
    operation: CmdRedirection,
    target: CmdWord,
}

enum CmdRedirection {
    Read,
    Write,
    Append,
}

#[derive(Default, Clone)]
struct CmdWord(Vec<CmdWordPart>);

#[derive(Clone)]
enum CmdWordPart {
    Text(String),
    Env(String),
}

impl CmdWord {
    fn push(&mut self, character: char) {
        match self.0.last_mut() {
            Some(CmdWordPart::Text(text)) => text.push(character),
            _ => self.0.push(CmdWordPart::Text(character.to_string())),
        }
    }

    fn text(&self) -> Option<String> {
        self.0
            .iter()
            .map(|part| match part {
                CmdWordPart::Text(text) => Some(text.as_str()),
                CmdWordPart::Env(_) => None,
            })
            .collect()
    }
}
