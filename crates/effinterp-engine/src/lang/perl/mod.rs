mod launcher;

pub(crate) use launcher::{Perl, versioned_interpreter};

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity,
};

use super::source_text::{nest_argv, nest_shell};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, charge_analysis_bytes, charge_analysis_steps};
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;

#[derive(Clone, Default)]
pub(crate) struct Imports {
    copy_loaded: bool,
    path_loaded: bool,
    names: BTreeSet<String>,
}

impl Imports {
    /// A `-MModule=a,b` or `-mModule` launcher option.
    fn add(&mut self, value: &str, import: bool) -> Result<(), String> {
        let (module, names) = value
            .split_once('=')
            .map_or((value, None), |(m, n)| (m, Some(n)));
        let names = names.map(|names| names.split(',').collect::<Vec<_>>());
        match names {
            Some(names) => self.import(module, Some(&names)),
            None if import => self.import(module, None),
            None => self.import(module, Some(&[])),
        }
    }

    /// Load `module` and import `names`, or its default export list when None.
    fn import(&mut self, module: &str, names: Option<&[&str]>) -> Result<(), String> {
        // (default exports, names importable on request)
        let (defaults, optional): (&[&str], &[&str]) = match module {
            "File::Copy" => {
                self.copy_loaded = true;
                (&["copy", "move"], &[])
            }
            "File::Path" => {
                self.path_loaded = true;
                (&["mkpath", "rmtree"], &["make_path", "remove_tree"])
            }
            "Fcntl" => (
                &[
                    "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL",
                ],
                &[],
            ),
            "MIME::Base64" => (
                &["encode_base64", "decode_base64"],
                &["encoded_base64_length", "decoded_base64_length"],
            ),
            _ => return Err(format!("Perl module import {module:?} is not modeled")),
        };
        let Some(names) = names else {
            self.names
                .extend(defaults.iter().map(|name| (*name).into()));
            return Ok(());
        };
        for name in names {
            if module == "Fcntl" && *name == ":DEFAULT" {
                self.names
                    .extend(defaults.iter().map(|name| (*name).into()));
            } else if defaults.contains(name) || optional.contains(name) {
                self.names.insert((*name).into());
            } else {
                return Err(format!("Perl {module} import {name:?} is not modeled"));
            }
        }
        Ok(())
    }

    /// Whether `name` resolves to the module function it is imported from.
    fn owns(&self, name: &str) -> bool {
        self.names.contains(name)
            || (name.starts_with("File::Copy::") && self.copy_loaded)
            || (name.starts_with("File::Path::") && self.path_loaded)
    }
}

/// Why the launcher or compiler stopped. A limit is reported as saturation of
/// that limit; a refusal's detail becomes the source's boundary.
pub(crate) enum PerlFailure {
    /// Decoded strings, or concatenated `-e` source, exceed `max_source_bytes`.
    SourceBytes,
    /// Retained values exceed `max_analysis_bytes`.
    AnalysisBytes,
    /// Compiled statements exceed `max_analysis_steps`.
    AnalysisSteps,
    /// The program is outside the bounded grammar, for the stated reason.
    Refused(String),
}

impl From<String> for PerlFailure {
    fn from(detail: String) -> Self {
        Self::Refused(detail)
    }
}

impl From<&str> for PerlFailure {
    fn from(detail: &str) -> Self {
        Self::Refused(detail.into())
    }
}

pub(crate) fn boundary(builder: &mut PlanBuilder, node: ProvenanceRef, detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::DYNAMIC_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![node],
        limit: None,
        detail: Some(detail.into()),
    });
}

pub(crate) fn analyze(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    scope: Option<ProvenanceRef>,
    imports: &Imports,
    depth: u64,
) {
    if source.len() as u64 > nest.limits.max_source_bytes {
        builder.note_saturated_at("max_source_bytes", None);
        return;
    }
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    // Charge before allocating tokens, decoded values, and pending effects.
    if !charge_analysis_steps(builder, nest.budget, source.len() as u64, None)
        || !charge_analysis_bytes(
            builder,
            nest.budget,
            (source.len() as u64).saturating_mul(64),
            None,
        )
    {
        return;
    }
    let node = builder.node(
        ProvenanceKind::SourceSpan {
            start: 0,
            end: source.len() as u32,
        },
        scope.as_slice(),
    );
    let mut environment_nodes = Vec::new();
    let mut environment_names = BTreeSet::new();
    let mut env = |name: &str| {
        environment_names.insert(name.to_string());
        if nest.current_environment_unsets().contains(name) {
            return None;
        }
        if let Some(node) = nest.current_environment_node(name) {
            environment_nodes.push(node);
        }
        if let Some(value) = nest
            .environments
            .borrow()
            .last()
            .and_then(|values| values.get(name))
        {
            return match value {
                Some(ResourceExpr::Literal { value }) => Some(value.clone()),
                _ => None,
            };
        }
        nest.context
            .and_then(|context| context.env.get(name))
            .cloned()
    };
    // Compile the whole bounded program before publishing any source effects:
    // later declarations or syntax can change the meaning of earlier calls.
    let max_bytes = nest.limits.max_source_bytes as usize;
    let parsed = tokenize(source, max_bytes, &mut env).and_then(|(tokens, stop)| {
        program(&tokens, stop, imports, nest.budget, max_bytes, &mut env)
    });
    for name in environment_names {
        let mut provenance = vec![node];
        provenance.extend(environment_nodes.iter().copied());
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            },
            attributes: Default::default(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance,
        });
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    }
    match parsed {
        Ok((steps, transfers, refusals)) => {
            let mut provenance = vec![node];
            provenance.extend(environment_nodes);
            provenance.extend(nest.current_cwd_node());
            let mut slots = Vec::with_capacity(steps.len());
            for step in steps {
                let pending = match step {
                    Pending::Effect(pending) => pending,
                    Pending::Shell { command, captured } => {
                        nest_shell(builder, nest, command, cwd, node, depth, captured);
                        slots.push(None);
                        continue;
                    }
                    Pending::Argv(argv) => {
                        nest_argv(builder, nest, &argv, cwd, node, depth);
                        slots.push(None);
                        continue;
                    }
                    Pending::DecodedEval => {
                        decoded_eval(builder, node);
                        slots.push(None);
                        continue;
                    }
                };
                let mut attributes = std::collections::BTreeMap::new();
                if let Some(purpose) = pending.access_purpose {
                    attributes.insert(
                        "access_purpose".to_string(),
                        AttrValue::String(purpose.to_string()),
                    );
                }
                if let Some(disclosure) = pending.disclosure {
                    attributes.insert(
                        "disclosure".to_string(),
                        AttrValue::String(disclosure.to_string()),
                    );
                }
                if let Some(action) = pending.action {
                    attributes.insert("action".to_string(), AttrValue::String(action.to_string()));
                }
                if pending.recursive {
                    attributes.insert("recursive".to_string(), AttrValue::Bool(true));
                }
                for grant in pending.grants {
                    attributes.insert(grant.to_string(), AttrValue::Bool(true));
                }
                slots.push(builder.effect(Effect {
                    id: Default::default(),
                    operation: Operation::new(pending.operation),
                    resource:
                        crate::paths::resolve_fs_path_with_cwd(
                            &pending.path,
                            builder.current_execution_cwd().or_else(|| {
                                cwd.map(|cwd| crate::paths::resolve_fs_path(cwd, None))
                            }),
                        ),
                    attributes,
                    modality: Modality::May,
                    request_assurance: RequestAssurance::Exact,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: Default::default(),
                    provenance: provenance.clone(),
                }));
            }
            for transfer in transfers {
                if let (Some(source), Some(destination)) = (
                    slots.get(transfer.source as usize).copied().flatten(),
                    slots.get(transfer.destination as usize).copied().flatten(),
                ) {
                    builder.transfer_binding(TransferBinding::exact(source, destination));
                }
            }
            for detail in &refusals {
                boundary(builder, node, detail);
            }
            if refusals.is_empty() {
                for domain in ["filesystem", "process"] {
                    builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
                }
            }
        }
        Err(PerlFailure::SourceBytes) => {
            builder.note_saturated_at("max_source_bytes", None);
        }
        Err(PerlFailure::AnalysisBytes) => {
            builder.note_saturated_at("max_analysis_bytes", None);
        }
        Err(PerlFailure::AnalysisSteps) => {
            builder.note_saturated_at("max_analysis_steps", None);
        }
        Err(PerlFailure::Refused(detail)) => boundary(builder, node, &detail),
    }
}

/// The interpreter decodes the text and runs the result as its own code: the
/// decode is a stream transform whose output is the code the eval executes.
fn decoded_eval(builder: &mut PlanBuilder, node: ProvenanceRef) {
    let resource = match builder.launching_command() {
        Some(command) => ResourceExpr::Concrete {
            identity: crate::paths::process_identity_with_cwd(
                &[crate::word::Word::literal(command)],
                builder.current_execution_cwd(),
            ),
        },
        None => unresolved_resource("process"),
    };
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: "perl/mime-base64@v0".to_string(),
        },
        &[node],
    );
    let decode = builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("process.stream_transform"),
        resource: resource.clone(),
        attributes: [("transform".to_string(), AttrValue::String("decode".into()))]
            .into_iter()
            .collect(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node, model],
    });
    let execution = builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("process.code_execution"),
        resource,
        attributes: [("source".to_string(), AttrValue::String("argument".into()))]
            .into_iter()
            .collect(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Conservative,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node],
    });
    if let (Some(decode), Some(execution)) = (decode, execution) {
        builder.flow_stage(crate::flow::FlowStage {
            execution: Some(builder.current_execution()),
            effects: vec![decode, execution],
            bindings: vec![crate::flow::PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: crate::flow::BindEnd::Effect(decode),
                to: crate::flow::BindEnd::Effect(execution),
            }],
            provenance: vec![node],
        });
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Text(String),
    Name(String),
    Variable(String),
    Number(String),
    Punct(char),
    /// A backtick string: its interpolated text runs as shell source.
    Command(String),
    /// A string or variable whose value is runtime-selected, and why.
    Unknown(String),
    /// A `qw` word list.
    Words(Vec<String>),
}

/// Words that declare code which runs at compile time, or subs and imports
/// that take effect for the whole unit, before any of its statements run.
const COMPILE_TIME: [&str; 12] = [
    "BEGIN",
    "CHECK",
    "INIT",
    "UNITCHECK",
    "END",
    "use",
    "no",
    "sub",
    "require",
    "package",
    "__DATA__",
    "__END__",
];

/// Whether `text` holds a word that could start compile-time code.
fn compile_time_word(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| COMPILE_TIME.contains(&word))
}

/// Lex `source`. Lexing stops at the first construct whose extent it cannot
/// establish, such as a pattern, heredoc, quote-like operator or unterminated
/// string: the tokens then keep only the statements completed before it, and
/// the reason stands for the rest. A construct that can change the meaning of
/// the whole program at compile time refuses it outright, and so does any word
/// in the unlexed rest that could start one.
fn tokenize(
    source: &str,
    max_bytes: usize,
    env: &mut impl FnMut(&str) -> Option<String>,
) -> Result<(Vec<Token>, Option<String>), PerlFailure> {
    if source.starts_with("#!") {
        return Err("Perl shebang switches can change inline execution semantics".into());
    }
    let mut tokens = Vec::new();
    let mut rest = source;
    let mut string_bytes = 0;
    let mut unlexed;
    let stop = loop {
        unlexed = rest;
        let Some(c) = rest.chars().next() else {
            break None;
        };
        if c.is_whitespace() {
            rest = &rest[c.len_utf8()..];
        } else if c == '#' {
            rest = rest.find('\n').map_or("", |end| &rest[end..]);
        } else if c == '='
            && (rest.len() == source.len()
                || source.as_bytes()[source.len() - rest.len() - 1] == b'\n')
        {
            match pod_tail(rest) {
                Ok(tail) => rest = tail,
                Err(detail) => break Some(detail),
            }
        } else if matches!(c, '`' | '\'' | '"') {
            rest = &rest[1..];
            match quoted(&mut rest, c, max_bytes - string_bytes, env) {
                Ok(Ok(text)) => {
                    string_bytes += text.len();
                    tokens.push(if c == '`' {
                        Token::Command(text)
                    } else {
                        Token::Text(text)
                    });
                }
                Ok(Err(detail)) => {
                    // Interpolation can hold code, compiled with the program.
                    if c != '\'' && compile_time_word(&unlexed[..unlexed.len() - rest.len()]) {
                        return Err(
                            "Perl interpolated code may declare compile-time code or subs".into(),
                        );
                    }
                    tokens.push(Token::Unknown(detail));
                }
                Err(PerlFailure::Refused(detail)) => break Some(detail),
                Err(failure) => return Err(failure),
            }
        } else if c == '$' {
            rest = &rest[1..];
            if let Some(key) = rest.strip_prefix("ENV{") {
                // `$ENV{NAME}` with a bare or plainly quoted key reads the
                // environment like its interpolated form.
                let Some(end) = key.find('}') else {
                    break Some("Perl environment subscript is unterminated".into());
                };
                let name = match &key.as_bytes()[..end] {
                    [b'"' | b'\'', .., b'"' | b'\'']
                        if key.as_bytes()[0] == key.as_bytes()[end - 1] =>
                    {
                        &key[1..end - 1]
                    }
                    _ => &key[..end],
                };
                rest = &key[end + 1..];
                if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                {
                    tokens.push(Token::Unknown(
                        "Perl environment key is not a literal name".into(),
                    ));
                    continue;
                }
                let Some(value) = env(name) else {
                    tokens.push(Token::Unknown(format!(
                        "Perl environment value {name:?} is not supplied"
                    )));
                    continue;
                };
                if value.len() > max_bytes - string_bytes {
                    return Err(PerlFailure::SourceBytes);
                }
                string_bytes += value.len();
                tokens.push(Token::Text(value));
                continue;
            }
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            if end == 0 || rest.as_bytes()[0].is_ascii_digit() {
                // Skip a special variable's name, so `$'`, `$"` or `$#` does
                // not open a string or comment.
                let skip = match rest.chars().next() {
                    Some(c) if c.is_ascii_digit() => end,
                    Some(c)
                        if c.is_ascii_punctuation()
                            && !matches!(c, '{' | '$' | ';' | '(' | ')' | ',') =>
                    {
                        1
                    }
                    _ => 0,
                };
                rest = &rest[skip..];
                tokens.push(Token::Unknown(
                    "Perl special or runtime-selected variable is not modeled".into(),
                ));
                continue;
            }
            tokens.push(Token::Variable(rest[..end].into()));
            rest = &rest[end..];
        } else if c.is_ascii_alphabetic() || c == '_' {
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != ':')
                .unwrap_or(rest.len());
            let name = &rest[..end];
            if matches!(
                name,
                "BEGIN"
                    | "CHECK"
                    | "INIT"
                    | "UNITCHECK"
                    | "END"
                    | "require"
                    | "package"
                    | "__DATA__"
                    | "__END__"
            ) {
                return Err(format!(
                    "Perl {name} construct is outside the bounded literal grammar"
                )
                .into());
            }
            rest = &rest[end..];
            // A quote-like operator's delimiters can enclose any text.
            if matches!(
                name,
                "q" | "qq" | "qw" | "qx" | "qr" | "m" | "s" | "tr" | "y"
            ) {
                let next = rest.trim_start();
                let delimited = match next.chars().next() {
                    None => false,
                    Some('=') => !next[1..].starts_with('>'),
                    Some(c) => !(c.is_alphanumeric() || matches!(c, '_' | ',' | ';' | ')' | '}')),
                };
                // A word list is data: one token, never statements.
                if delimited && name == "qw" {
                    let open = next.chars().next().unwrap();
                    let close = match open {
                        '(' => ')',
                        '[' => ']',
                        '{' => '}',
                        '<' => '>',
                        other => other,
                    };
                    let body = &next[open.len_utf8()..];
                    let mut depth = 0u32;
                    let mut escaped = false;
                    let end = body.char_indices().find(|&(_, c)| {
                        // A backslash escapes a delimiter or another backslash.
                        if std::mem::take(&mut escaped) {
                            return false;
                        }
                        if c == '\\' {
                            escaped = true;
                            return false;
                        }
                        if c == close && depth == 0 {
                            return true;
                        }
                        if c == close {
                            depth -= 1;
                        } else if c == open && open != close {
                            depth += 1;
                        }
                        false
                    });
                    let Some((end, _)) = end else {
                        break Some("Perl qw word list is unterminated".into());
                    };
                    tokens.push(Token::Words(
                        body[..end].split_whitespace().map(str::to_string).collect(),
                    ));
                    rest = &body[end + close.len_utf8()..];
                    continue;
                }
                if delimited {
                    break Some(format!(
                        "Perl {name} quote-like operator is outside the bounded literal grammar"
                    ));
                }
            }
            tokens.push(Token::Name(name.into()));
        } else if c.is_ascii_digit() {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            tokens.push(Token::Number(rest[..end].into()));
            rest = &rest[end..];
        } else if rest.starts_with("//") {
            // Only defined-or; a lone slash may start a pattern.
            tokens.extend([Token::Punct('/'), Token::Punct('/')]);
            rest = &rest[2..];
        } else if matches!(
            c,
            '(' | ')'
                | ','
                | ';'
                | '='
                | '|'
                | '{'
                | '}'
                | '.'
                | '-'
                | '+'
                | '*'
                | '!'
                | '>'
                | '&'
                | '%'
                | '@'
                | '['
                | ']'
                | '\\'
                | '?'
                | ':'
                | '~'
                | '^'
        ) || (c == '<' && !rest.starts_with("<<"))
        {
            tokens.push(Token::Punct(c));
            rest = &rest[1..];
        } else {
            break Some(format!(
                "Perl token {c:?} is outside the bounded literal grammar"
            ));
        }
    };
    if stop.is_some() {
        if compile_time_word(unlexed) {
            return Err("Perl source Nah cannot lex may declare compile-time code or subs".into());
        }
        let mut depth = 0i64;
        let mut complete = 0;
        for (index, token) in tokens.iter().enumerate() {
            match token {
                Token::Punct('{') => depth += 1,
                Token::Punct('}') => depth -= 1,
                Token::Punct(';') if depth == 0 => complete = index + 1,
                _ => {}
            }
        }
        tokens.truncate(complete);
    }
    Ok((tokens, stop))
}

fn pod_tail(source: &str) -> Result<&str, String> {
    let first_end = source.find('\n').map_or(source.len(), |index| index + 1);
    let first = source[..first_end].trim_end_matches(['\r', '\n']);
    let directive = first
        .strip_prefix('=')
        .and_then(|line| line.split_whitespace().next())
        .filter(|directive| {
            !directive.is_empty() && directive.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
        .ok_or("Perl line-leading equals syntax is outside the bounded literal grammar")?;
    if directive == "cut" {
        return Err("Perl POD terminator has no opening directive".into());
    }
    let mut consumed = first_end;
    while consumed < source.len() {
        let line_len = source[consumed..]
            .find('\n')
            .map_or(source.len() - consumed, |index| index + 1);
        let line = source[consumed..consumed + line_len].trim_end_matches(['\r', '\n']);
        consumed += line_len;
        if line
            .strip_prefix("=cut")
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))
        {
            return Ok(&source[consumed..]);
        }
    }
    Err("Perl POD section is unterminated".into())
}

/// The string up to the closing `quote`, or why its value is runtime-selected.
/// Only an unterminated string or the byte limit fails.
fn quoted(
    rest: &mut &str,
    quote: char,
    max_bytes: usize,
    env: &mut impl FnMut(&str) -> Option<String>,
) -> Result<Result<String, String>, PerlFailure> {
    // Without `use utf8`, Perl source strings and hex escapes are bytes.
    // Upgrade-to-Unicode operations remain outside this grammar.
    let mut value = Vec::new();
    let mut unknown = None;
    while let Some(c) = rest.chars().next() {
        *rest = &rest[c.len_utf8()..];
        if value.len() > max_bytes {
            return Err(PerlFailure::SourceBytes);
        }
        if c == quote {
            return Ok(match unknown {
                Some(detail) => Err(detail),
                None => String::from_utf8(value)
                    .map_err(|_| "Perl path contains non-UTF-8 bytes".to_string()),
            });
        }
        if c == '\\' {
            let escape = rest
                .chars()
                .next()
                .ok_or("Perl string escape is unterminated")?;
            *rest = &rest[escape.len_utf8()..];
            if quote == '\'' {
                if !matches!(escape, '\\' | '\'') {
                    value.push(b'\\');
                }
                value.extend_from_slice(escape.encode_utf8(&mut [0; 4]).as_bytes());
                continue;
            }
            let byte = match escape {
                '\\' | '"' | '`' | '$' | '@' => Ok(escape as u8),
                'n' => Ok(b'\n'),
                'r' => Ok(b'\r'),
                't' => Ok(b'\t'),
                'f' => Ok(12),
                'b' => Ok(8),
                'a' => Ok(7),
                'e' => Ok(27),
                'x' => {
                    let digits = if rest.starts_with('{') {
                        rest.find('}').map(|end| {
                            let digits = &rest[1..end];
                            *rest = &rest[end + 1..];
                            digits
                        })
                    } else {
                        let end = rest
                            .bytes()
                            .take(2)
                            .take_while(u8::is_ascii_hexdigit)
                            .count();
                        let digits = &rest[..end];
                        *rest = &rest[end..];
                        Some(digits)
                    };
                    digits
                        .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                        .ok_or_else(|| {
                            "Perl hex escape requires unmodeled Unicode upgrade semantics".into()
                        })
                }
                _ => Err(format!("Perl string escape \\{escape} is not modeled")),
            };
            match byte {
                Ok(byte) => value.push(byte),
                Err(detail) => {
                    unknown.get_or_insert(detail);
                }
            }
        } else if quote != '\'' && c == '$' {
            let Some(end) = rest.strip_prefix("ENV{").and_then(|_| rest.find('}')) else {
                unknown.get_or_insert_with(|| {
                    "Perl interpolated variable has no proven environment value".into()
                });
                continue;
            };
            let name = &rest[4..end];
            *rest = &rest[end + 1..];
            if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                unknown.get_or_insert_with(|| "Perl environment key is not a literal name".into());
                continue;
            }
            let Some(expansion) = env(name) else {
                unknown.get_or_insert_with(|| {
                    format!("Perl environment value {name:?} is not supplied")
                });
                continue;
            };
            if expansion.len() > max_bytes.saturating_sub(value.len()) {
                return Err(PerlFailure::SourceBytes);
            }
            value.extend_from_slice(expansion.as_bytes());
        } else if quote != '\'' && c == '@' {
            unknown.get_or_insert_with(|| "Perl array interpolation is runtime-selected".into());
        } else {
            value.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
    Err("Perl quoted string is unterminated".into())
}

struct PendingEffect {
    operation: &'static str,
    path: String,
    access_purpose: Option<&'static str>,
    disclosure: Option<&'static str>,
    action: Option<&'static str>,
    recursive: bool,
    /// The permission grants a literal chmod mode sets.
    grants: Vec<&'static str>,
}

impl PendingEffect {
    fn new(operation: &'static str, path: String) -> Self {
        Self {
            operation,
            path,
            access_purpose: None,
            disclosure: None,
            action: None,
            recursive: false,
            grants: Vec::new(),
        }
    }
}

/// One program step, published in source order once the whole program compiles.
enum Pending {
    Effect(PendingEffect),
    /// `system STRING`, `exec STRING` or a backtick: the string is `sh -c`
    /// source. A backtick captures the child's stdout as its value.
    Shell {
        command: String,
        captured: bool,
    },
    /// `system LIST` or `exec LIST`: an exact argv run without a shell.
    Argv(Vec<String>),
    /// `eval(decode_base64(...))`: MIME::Base64 decodes text that the string
    /// `eval` then runs as Perl.
    DecodedEval,
}

/// The program's steps and transfers, and why each refused statement was refused.
type Compiled = (Vec<Pending>, Vec<TransferBinding>, BTreeSet<String>);

/// Builtins and module functions this grammar models. A user `sub` with one of
/// these names makes calls to it ambiguous, so the program is not claimed.
const MODELED_NAMES: [&str; 17] = [
    "unlink",
    "truncate",
    "rmdir",
    "mkdir",
    "chmod",
    "rename",
    "copy",
    "move",
    "open",
    "sysopen",
    "system",
    "exec",
    "eval",
    "remove_tree",
    "rmtree",
    "mkpath",
    "make_path",
];

/// Named sub calls and string `eval`s nest at most this deep.
const MAX_CALL_DEPTH: u32 = 8;

/// Logical operators and statement modifiers nest at most this deep.
const MAX_NESTING: u32 = 64;

enum Statement<'t> {
    Sub(&'t str, &'t [Token]),
    Simple(&'t [Token]),
}

/// Split tokens into `;`-terminated statements and named `sub NAME { ... }`
/// definitions. Any other brace stays inside its statement and is refused there.
fn statements(tokens: &[Token]) -> Result<Vec<Statement<'_>>, String> {
    let mut statements = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if let [Token::Name(sub), Token::Name(name), Token::Punct('{'), ..] = &tokens[i..]
            && sub == "sub"
        {
            let close = i + 2 + matching_brace(&tokens[i + 2..])?;
            statements.push(Statement::Sub(name, &tokens[i + 3..close]));
            i = close + 1;
            continue;
        }
        let mut depth = 0u32;
        let mut end = i;
        while end < tokens.len() {
            match tokens[end] {
                Token::Punct('{') => depth += 1,
                Token::Punct('}') => {
                    depth = depth.checked_sub(1).ok_or("Perl braces are unbalanced")?
                }
                Token::Punct(';') if depth == 0 => break,
                _ => {}
            }
            end += 1;
        }
        if depth != 0 {
            return Err("Perl braces are unbalanced".into());
        }
        if end > i {
            statements.push(Statement::Simple(&tokens[i..end]));
        }
        i = end + 1;
    }
    Ok(statements)
}

/// Index of the brace closing the one that opens `tokens`.
fn matching_brace(tokens: &[Token]) -> Result<usize, String> {
    let mut depth = 0u32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Punct('{') => depth += 1,
            Token::Punct('}') => {
                depth -= 1;
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => {}
        }
    }
    Err("Perl sub body is unterminated".into())
}

/// `use strict`, `use warnings`, or a modeled module with an optional
/// `qw(...)`, string or empty import list.
fn use_statement(tokens: &[Token], imports: &mut Imports) -> Result<(), String> {
    let [Token::Name(module), list @ ..] = tokens else {
        return Err("Perl use statement names no module".into());
    };
    if matches!(module.as_str(), "strict" | "warnings") && list.is_empty() {
        return Ok(());
    }
    if let [Token::Words(words)] = list {
        let names = words.iter().map(String::as_str).collect::<Vec<_>>();
        return imports.import(module, Some(&names));
    }
    let list = match list {
        [Token::Punct('('), inner @ .., Token::Punct(')')] => inner,
        other => other,
    };
    if list.is_empty() {
        return imports.import(module, if tokens.len() == 1 { None } else { Some(&[]) });
    }
    let mut names = Vec::new();
    for token in list {
        match token {
            Token::Name(name) | Token::Text(name) => names.push(name.as_str()),
            Token::Punct(',') => {}
            _ => return Err("Perl use import list is not a literal name list".into()),
        }
    }
    imports.import(module, Some(&names))
}

struct Compiler<'a, 'e> {
    imports: Imports,
    budget: &'a crate::nest::Budget,
    max_bytes: usize,
    env: &'e mut dyn FnMut(&str) -> Option<String>,
    subs: BTreeMap<String, Vec<Token>>,
    active_subs: BTreeSet<String>,
    variables: BTreeMap<String, String>,
    pending: Vec<Pending>,
    transfers: Vec<TransferBinding>,
    refusals: BTreeSet<String>,
    /// A refused statement could change any later fact (the cwd, the
    /// environment, a sub, or whether execution continues), so nothing after
    /// it is compiled.
    halted: bool,
    /// How many enclosing operands may not run.
    conditional: u32,
    /// How many operator splits enclose the statement being compiled.
    nesting: u32,
    depth: u32,
}

fn program(
    tokens: &[Token],
    stop: Option<String>,
    imports: &Imports,
    budget: &crate::nest::Budget,
    max_bytes: usize,
    env: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Compiled, PerlFailure> {
    let mut compiler = Compiler {
        imports: imports.clone(),
        budget,
        max_bytes,
        env,
        subs: BTreeMap::new(),
        active_subs: BTreeSet::new(),
        variables: BTreeMap::new(),
        pending: Vec::new(),
        transfers: Vec::new(),
        refusals: stop.into_iter().collect(),
        halted: false,
        conditional: 0,
        nesting: 0,
        depth: 0,
    };
    compiler.unit(tokens)?;
    Ok((compiler.pending, compiler.transfers, compiler.refusals))
}

impl Compiler<'_, '_> {
    /// Compile one unit (the program or an `eval` string). Named subs and `use`
    /// imports take effect at compile time, before any statement runs.
    fn unit(&mut self, tokens: &[Token]) -> Result<(), PerlFailure> {
        let statements = statements(tokens)?;
        for statement in &statements {
            match statement {
                Statement::Sub(name, body) => {
                    if MODELED_NAMES.contains(name)
                        || self.imports.owns(name)
                        || self.subs.contains_key(*name)
                    {
                        return Err(
                            format!("Perl sub {name} redefines a modeled or earlier name").into(),
                        );
                    }
                    self.subs.insert((*name).to_string(), body.to_vec());
                }
                Statement::Simple([Token::Name(keyword), rest @ ..]) if keyword == "use" => {
                    use_statement(rest, &mut self.imports)?;
                }
                // `no` unimports at compile time; only pragmas are known inert.
                Statement::Simple([Token::Name(keyword), rest @ ..]) if keyword == "no" => {
                    if !matches!(rest, [Token::Name(pragma)] if matches!(pragma.as_str(), "strict" | "warnings"))
                    {
                        return Err(
                            "Perl no statement is outside the bounded literal grammar".into()
                        );
                    }
                }
                Statement::Simple(_) => {}
            }
        }
        for statement in statements {
            match statement {
                Statement::Simple([Token::Name(keyword), ..])
                    if matches!(keyword.as_str(), "use" | "no") => {}
                Statement::Simple(statement) => self.run(statement)?,
                Statement::Sub(..) => {}
            }
        }
        Ok(())
    }

    /// Compile one statement. A refused statement publishes nothing itself and
    /// leaves a boundary; the statements before it keep their effects. Only a
    /// statement that cannot change later facts lets compilation continue.
    fn run(&mut self, statement: &[Token]) -> Result<(), PerlFailure> {
        if self.halted {
            return Ok(());
        }
        match self.statement(statement) {
            Err(PerlFailure::Refused(detail)) => {
                self.refusals.insert(detail);
                self.halted = !inert(statement, self.conditional > 0);
                Ok(())
            }
            result => result,
        }
    }

    /// Compile an operand that may not run: a variable it binds has no known
    /// value afterwards.
    fn maybe(&mut self, tokens: &[Token]) -> Result<(), PerlFailure> {
        let outer = self.variables.clone();
        self.conditional += 1;
        let result = self.run(tokens);
        self.conditional -= 1;
        let inner = std::mem::replace(&mut self.variables, outer);
        self.variables
            .retain(|name, value| inner.get(name) == Some(value));
        result
    }

    /// `left OPERATOR right`: the first operand always runs, and the other
    /// runs unless a constant first operand rules it out. Both `xor` operands run.
    fn logical(
        &mut self,
        left: &[Token],
        operator: &str,
        right: &[Token],
    ) -> Result<(), PerlFailure> {
        if self.nesting >= MAX_NESTING {
            return Err("Perl operator chain nests too deeply to model".into());
        }
        self.nesting += 1;
        let result = self.operands(left, operator, right);
        self.nesting -= 1;
        result
    }

    fn operands(
        &mut self,
        left: &[Token],
        operator: &str,
        right: &[Token],
    ) -> Result<(), PerlFailure> {
        // A statement modifier evaluates its condition first.
        let (first, then) = if matches!(operator, "if" | "unless") {
            (right, left)
        } else {
            (left, right)
        };
        if operator == "xor" {
            if constant(first).is_none() {
                self.run(first)?;
            }
            return self.run(then);
        }
        let Some((defined, truth)) = constant(first) else {
            self.run(first)?;
            return self.maybe(then);
        };
        let runs = match operator {
            "if" | "and" | "&&" => truth,
            "//" => !defined,
            _ => !truth,
        };
        if runs { self.run(then) } else { Ok(()) }
    }

    fn statement(&mut self, statement: &[Token]) -> Result<(), PerlFailure> {
        if !self.budget.try_charge_steps(statement.len() as u64) {
            return Err(PerlFailure::AnalysisSteps);
        }
        // A constant expression, including a short-circuit chain that stops
        // at a constant, does nothing.
        if constant(statement).is_some() {
            return Ok(());
        }
        if let Some((left, operator, right)) = split(statement)
            && (operator.starts_with(char::is_alphabetic)
                || call_end(left) == Some(left.len())
                || constant(left).is_some())
        {
            return self.logical(left, operator, right);
        }
        if statement.contains(&Token::Punct('{')) {
            return Err(
                "Perl block, hash or anonymous sub is outside the bounded literal grammar".into(),
            );
        }
        let budget = self.budget;
        let binding = statement
            .strip_prefix(&[Token::Name("my".into())])
            .unwrap_or(statement);
        match binding {
            [
                Token::Variable(name),
                Token::Punct('='),
                Token::Command(command),
            ] => {
                // The captured output is runtime data, never a literal.
                self.variables.remove(name);
                self.pending.push(Pending::Shell {
                    command: command.clone(),
                    captured: true,
                });
                return Ok(());
            }
            [Token::Variable(name), Token::Punct('='), value] => {
                let value = literal(std::slice::from_ref(value), &self.variables, budget)?;
                self.variables.insert(name.clone(), value);
                return Ok(());
            }
            _ => {}
        }
        if let [Token::Command(command)] = statement {
            self.pending.push(Pending::Shell {
                command: command.clone(),
                captured: true,
            });
            return Ok(());
        }
        let Some(Token::Name(name)) = statement.first() else {
            return Err(
                "Perl statement is not a literal binding or supported filesystem call".into(),
            );
        };
        // `name(...)` is a whole call whatever operators follow it.
        if let Some(end) = call_end(statement)
            && end < statement.len()
        {
            self.statement(&statement[..end])?;
            let rest = &statement[end..];
            if rest
                .iter()
                .all(|token| matches!(token, Token::Punct(_) | Token::Number(_) | Token::Text(_)))
            {
                return Ok(());
            }
            return Err(format!(
                "Perl expression after the {name} call is outside the bounded literal grammar"
            )
            .into());
        }
        let mut args = &statement[1..];
        if args.first() == Some(&Token::Punct('(')) && args.last() == Some(&Token::Punct(')')) {
            args = &args[1..args.len() - 1];
        }
        let args: Vec<_> = if args.is_empty() {
            Vec::new()
        } else {
            args.split(|token| *token == Token::Punct(',')).collect()
        };
        if let Some(body) = self.subs.get(name).cloned() {
            return self.call(name, &body, &args);
        }
        if matches!(name.as_str(), "open" | "sysopen")
            && let Some(Token::Variable(name)) = args.first().and_then(|arg| arg.last())
        {
            // A filehandle replaces a scalar value; it is no longer a path.
            self.variables.remove(name);
        }
        let variables = &self.variables;
        let path = |i: usize| -> Result<String, PerlFailure> {
            let path = literal(
                args.get(i).ok_or("Perl call lacks a required path")?,
                variables,
                budget,
            )?;
            if path.is_empty() || path.contains('\0') {
                return Err("Perl path is empty or contains NUL".into());
            }
            Ok(path)
        };
        let imports = &self.imports;
        let effects = &mut self.pending;
        let transfers = &mut self.transfers;
        match name.as_str() {
            // Perl evaluates every argument before the call, and one that
            // cannot be established may prevent it, so no path is published
            // until all are known.
            "unlink" => {
                let paths = (0..args.len()).map(path).collect::<Result<Vec<_>, _>>()?;
                for path in paths {
                    effects.push(Pending::Effect(PendingEffect::new(
                        "filesystem.delete",
                        path,
                    )));
                }
            }
            "rmdir" if args.len() == 1 => effects.push(Pending::Effect(PendingEffect::new(
                "filesystem.delete",
                path(0)?,
            ))),
            "mkdir" if args.len() == 1 || (args.len() == 2 && numeric(args[1])) => effects.push(
                Pending::Effect(PendingEffect::new("filesystem.create", path(0)?)),
            ),
            // A mode the grammar cannot evaluate still leaves the change to
            // the established paths, so it is kept with a boundary. Only a
            // plain variable is known to change nothing else; any other
            // expression may, so nothing after it is compiled.
            // A malformed number (`099`) fails to compile, so nothing runs.
            "chmod"
                if args.len() >= 2
                    && balanced(args[0])
                    && (numeric(args[0]) || !matches!(args[0], [Token::Number(_)])) =>
            {
                let paths = (1..args.len()).map(path).collect::<Result<Vec<_>, _>>()?;
                let grants = match args[0] {
                    [Token::Number(mode)] => crate::permission_mode::granted(
                        crate::permission_mode::numeric(perl_number(mode)?),
                    )
                    .collect(),
                    mode => {
                        self.refusals.insert(
                            "Perl chmod mode is not a numeric literal, so the permissions it grants are unknown"
                                .into(),
                        );
                        if !matches!(mode, [Token::Variable(_)]) {
                            self.halted = true;
                        }
                        Vec::new()
                    }
                };
                for path in paths {
                    let mut metadata = PendingEffect::new("filesystem.metadata", path);
                    metadata.action = Some("chmod");
                    metadata.grants = grants.clone();
                    effects.push(Pending::Effect(metadata));
                }
            }
            "rename" | "copy" | "move" | "File::Copy::copy" | "File::Copy::move"
                if args.len() == 2 =>
            {
                if name != "rename" && !imports.owns(name) {
                    return Err(format!("Perl {name} has no File::Copy import ownership").into());
                }
                let source = path(0)?;
                let destination = path(1)?;
                if name != "rename" {
                    let source_slot = effects.len() as u32;
                    let mut read = PendingEffect::new("filesystem.read", source.clone());
                    if name.ends_with("copy") {
                        read.access_purpose = Some("program_input");
                    }
                    effects.push(Pending::Effect(read));
                    if name.ends_with("copy") {
                        let destination_slot = effects.len() as u32;
                        transfers.push(TransferBinding::exact(source_slot, destination_slot));
                    }
                }
                if !name.ends_with("copy") {
                    effects.push(Pending::Effect(PendingEffect::new(
                        "filesystem.move",
                        source.clone(),
                    )));
                    effects.push(Pending::Effect(PendingEffect::new(
                        "filesystem.delete",
                        source,
                    )));
                }
                let mut write = PendingEffect::new("filesystem.write", destination);
                if name.ends_with("copy") {
                    write.disclosure = Some("contents");
                }
                effects.push(Pending::Effect(write));
            }
            "open" if matches!(args.len(), 2 | 3) && handle(args[0]) => {
                let value = literal(args[1], variables, budget)?;
                let (mode, path) = if args.len() == 3 {
                    (value.as_str(), path(2)?)
                } else {
                    let value = value.trim();
                    let mode = ["+>>", "+>", "+<", ">>", ">", "<"]
                        .into_iter()
                        .find(|mode| value.starts_with(mode))
                        .ok_or("Perl two-argument open has no explicit filesystem mode")?;
                    let path = value[mode.len()..].trim();
                    if path.is_empty()
                        || path.contains('\0')
                        || path.starts_with(['&', '|'])
                        || path.ends_with('|')
                    {
                        return Err("Perl two-argument open selects a stream or pipe".into());
                    }
                    (mode, path.to_string())
                };
                let (read, write) = match mode {
                    "<" => (true, false),
                    ">" | ">>" => (false, true),
                    "+<" | "+>" | "+>>" => (true, true),
                    _ => {
                        return Err(
                            "Perl open mode does not establish a plain filesystem access".into(),
                        );
                    }
                };
                if path == "-" {
                    return Err("Perl open path selects a standard stream".into());
                }
                // A handle opened for reading hands the file's contents to
                // the program, as Python's `open(path).read()` does; `+>`
                // truncates first, so no prior contents are read.
                if read {
                    let mut read = PendingEffect::new("filesystem.read", path.clone());
                    if mode != "+>" {
                        read.access_purpose = Some("program_input");
                    }
                    effects.push(Pending::Effect(read));
                }
                if write {
                    effects.push(Pending::Effect(PendingEffect::new(
                        "filesystem.write",
                        path,
                    )));
                }
            }
            "sysopen"
                if (args.len() == 3 || (args.len() == 4 && numeric(args[3])))
                    && handle(args[0]) =>
            {
                let path = path(1)?;
                let mut flags = BTreeSet::new();
                for flag in args[2].split(|token| *token == Token::Punct('|')) {
                    let [Token::Name(flag)] = flag else {
                        return Err("Perl sysopen flags are runtime-selected".into());
                    };
                    if !flag.starts_with("O_") || !imports.owns(flag) {
                        return Err(format!(
                            "Perl sysopen flag {flag:?} has no Fcntl import ownership"
                        )
                        .into());
                    }
                    flags.insert(flag.as_str());
                }
                let modes = ["O_RDONLY", "O_WRONLY", "O_RDWR"]
                    .iter()
                    .filter(|flag| flags.contains(**flag))
                    .count();
                if modes != 1 {
                    return Err("Perl sysopen flags do not establish one access mode".into());
                }
                if !flags.contains("O_WRONLY") {
                    let mut read = PendingEffect::new("filesystem.read", path.clone());
                    if !flags.contains("O_TRUNC") {
                        read.access_purpose = Some("program_input");
                    }
                    effects.push(Pending::Effect(read));
                }
                if flags
                    .iter()
                    .any(|flag| matches!(*flag, "O_WRONLY" | "O_RDWR" | "O_CREAT" | "O_TRUNC"))
                {
                    effects.push(Pending::Effect(PendingEffect::new(
                        "filesystem.write",
                        path,
                    )));
                }
            }
            "remove_tree" | "rmtree" | "File::Path::remove_tree" | "File::Path::rmtree"
                if !args.is_empty() && imports.owns(name) =>
            {
                let paths = (0..args.len()).map(path).collect::<Result<Vec<_>, _>>()?;
                for path in paths {
                    let mut delete = PendingEffect::new("filesystem.delete", path);
                    delete.recursive = true;
                    effects.push(Pending::Effect(delete));
                }
            }
            "truncate" if args.len() == 2 && numeric(args[1]) => effects.push(Pending::Effect(
                PendingEffect::new("filesystem.write", path(0)?),
            )),
            "system" | "exec" if args.len() == 1 => {
                let command = literal(args[0], variables, budget)?;
                effects.push(Pending::Shell {
                    command,
                    captured: false,
                });
            }
            "system" | "exec" if args.len() > 1 => {
                let argv = args
                    .iter()
                    .map(|arg| literal(arg, variables, budget))
                    .collect::<Result<Vec<_>, _>>()?;
                effects.push(Pending::Argv(argv));
            }
            // The decoded source is not read here: whatever it does may
            // change any later fact, so nothing after it is compiled.
            "eval" if args.len() == 1 && decodes_base64(args[0], imports) => {
                effects.push(Pending::DecodedEval);
                self.refusals
                    .insert("Perl eval of MIME::Base64-decoded text is not analyzed".into());
                self.halted = true;
            }
            "eval" if args.len() == 1 => {
                let source = literal(args[0], variables, budget)?;
                return self.eval(&source);
            }
            _ => {
                return Err(format!(
                    "Perl {name} call or argument shape is outside the bounded literal grammar"
                )
                .into());
            }
        }
        Ok(())
    }

    /// Run a named sub's body. Its argument list must be literal, and any
    /// variable it rebinds is no longer a known literal afterwards.
    fn call(&mut self, name: &str, body: &[Token], args: &[&[Token]]) -> Result<(), PerlFailure> {
        for arg in args {
            literal(arg, &self.variables, self.budget)?;
        }
        if self.depth >= MAX_CALL_DEPTH || !self.active_subs.insert(name.to_string()) {
            return Err(format!("Perl sub {name} recursion is not modeled").into());
        }
        let outer = self.variables.clone();
        self.depth += 1;
        let result = statements(body)
            .map_err(PerlFailure::Refused)
            .and_then(|statements| {
                statements
                    .into_iter()
                    .try_for_each(|statement| match statement {
                        Statement::Simple(statement) => self.run(statement),
                        Statement::Sub(..) => Err("Perl nested named sub is not modeled".into()),
                    })
            });
        self.depth -= 1;
        self.active_subs.remove(name);
        let inner = std::mem::replace(&mut self.variables, outer);
        self.variables
            .retain(|name, value| inner.get(name) == Some(value));
        result
    }

    /// String `eval` compiles and runs a literal as Perl in the current scope.
    fn eval(&mut self, source: &str) -> Result<(), PerlFailure> {
        if self.depth >= MAX_CALL_DEPTH {
            return Err("Perl eval nesting is not modeled".into());
        }
        if !self
            .budget
            .try_charge_bytes((source.len() as u64).saturating_mul(64))
        {
            return Err(PerlFailure::AnalysisBytes);
        }
        let (tokens, stop) = tokenize(source, self.max_bytes, &mut self.env)?;
        self.depth += 1;
        let result = self.unit(&tokens);
        self.depth -= 1;
        result?;
        // The unlexed rest of the eval refuses the eval statement itself.
        stop.map_or(Ok(()), |detail| Err(detail.into()))
    }
}

/// `decode_base64(...)` as imported from MIME::Base64, with one argument.
fn decodes_base64(tokens: &[Token], imports: &Imports) -> bool {
    matches!(
        tokens,
        [Token::Name(name), Token::Punct('('), argument @ .., Token::Punct(')')]
            if name == "decode_base64" && imports.owns(name) && balanced(argument)
                && !argument.contains(&Token::Punct(','))
    )
}

fn literal(
    tokens: &[Token],
    variables: &BTreeMap<String, String>,
    budget: &crate::nest::Budget,
) -> Result<String, PerlFailure> {
    // A `.` concatenation of literal operands is itself literal.
    let mut value = String::new();
    for operand in tokens.split(|token| *token == Token::Punct('.')) {
        value.push_str(match operand {
            [Token::Text(value)] => value,
            [Token::Variable(name)] => variables
                .get(name)
                .ok_or_else(|| format!("Perl variable ${name} has no literal binding"))?,
            [Token::Unknown(detail)] => return Err(detail.clone().into()),
            _ => return Err("Perl path or value is a runtime-selected expression".into()),
        });
    }
    // A move can retain this path in three pending effects plus the binding.
    if !budget.try_charge_bytes((value.len() as u64).saturating_mul(4)) {
        return Err(PerlFailure::AnalysisBytes);
    }
    Ok(value)
}

/// Whether an argument's parentheses, brackets and braces balance. Arguments
/// are split at every comma, so an unbalanced one spans a nested list.
fn balanced(tokens: &[Token]) -> bool {
    let mut depth = 0_i32;
    for token in tokens {
        match token {
            Token::Punct('(' | '[' | '{') => depth += 1,
            Token::Punct(')' | ']' | '}') => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0 && !tokens.is_empty()
}

/// The value of a numeric literal token: octal when it has a leading zero.
fn perl_number(value: &str) -> Result<u32, PerlFailure> {
    let radix = if value.starts_with('0') { 8 } else { 10 };
    u32::from_str_radix(value, radix).map_err(|_| "Perl numeric literal is out of range".into())
}

fn numeric(tokens: &[Token]) -> bool {
    matches!(tokens, [Token::Number(value)] if !value.starts_with('0') || value.bytes().all(|c| matches!(c, b'0'..=b'7')))
}

/// A lexical, scalar or bareword filehandle.
fn handle(tokens: &[Token]) -> bool {
    matches!(tokens, [Token::Variable(_) | Token::Name(_)])
        || matches!(tokens, [Token::Name(my), Token::Variable(_)] if my == "my")
}

/// Whether a refused statement leaves every later fact intact: output or
/// closing a handle, or a `die`/`exit` that may not run, whose arguments are
/// only literals and plain variables. An unconditional `die` or `exit` ends
/// the program, unless an enclosing `eval` catches it.
fn inert(statement: &[Token], conditional: bool) -> bool {
    let [Token::Name(name), args @ ..] = statement else {
        return false;
    };
    let output = matches!(name.as_str(), "print" | "say" | "warn" | "close");
    (output || (conditional && matches!(name.as_str(), "die" | "exit")))
        && args.iter().all(|token| {
            matches!(
                token,
                Token::Text(_)
                    | Token::Number(_)
                    | Token::Variable(_)
                    | Token::Punct(',' | '(' | ')' | '.')
            )
        })
}

/// The end of the `name(...)` call that opens `tokens`.
fn call_end(tokens: &[Token]) -> Option<usize> {
    let [Token::Name(_), Token::Punct('('), ..] = tokens else {
        return None;
    };
    let mut depth = 0u32;
    for (index, token) in tokens.iter().enumerate().skip(1) {
        match token {
            Token::Punct('(') => depth += 1,
            Token::Punct(')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Constant expressions longer than this are not folded.
const MAX_CONSTANT_TOKENS: usize = 256;

/// A constant operand's definedness and truth: a literal, an `xor` of
/// constants, or a short-circuit chain that stops at a constant. The right operand is read only when it runs,
/// so `1 or unlink(...)` is the constant `1`.
fn constant(tokens: &[Token]) -> Option<(bool, bool)> {
    match tokens {
        [Token::Number(value)] => Some((true, value.bytes().any(|byte| byte != b'0'))),
        [Token::Text(value)] => Some((true, !value.is_empty() && value != "0")),
        [Token::Name(undef)] if undef == "undef" => Some((false, false)),
        _ if tokens.len() > MAX_CONSTANT_TOKENS => None,
        _ => {
            let (left, operator, right) = split(tokens)?;
            let value = constant(left)?;
            if operator == "xor" {
                // Both operands run; the result is defined.
                return Some((true, value.1 != constant(right)?.1));
            }
            let stops = match operator {
                "or" | "||" => value.1,
                "and" | "&&" => !value.1,
                "//" => value.0,
                _ => return None,
            };
            if stops { Some(value) } else { constant(right) }
        }
    }
}

/// Split at the lowest-precedence operator outside parentheses and braces:
/// an `if` or `unless` modifier, then `or` or `xor`, `and`, `||` or `//`, and
/// `&&`.
/// The split is structural: a symbolic operator binds tighter than a list
/// operator or assignment, so a caller accepts it only after a whole call or a
/// constant.
fn split(statement: &[Token]) -> Option<(&[Token], &'static str, &[Token])> {
    let mut last: [Option<(usize, &'static str)>; 5] = [None; 5];
    let mut depth = 0i64;
    for (index, token) in statement.iter().enumerate() {
        let found = match token {
            Token::Punct('(' | '{') => {
                depth += 1;
                None
            }
            Token::Punct(')' | '}') => {
                depth -= 1;
                None
            }
            _ if depth != 0 || index == 0 => None,
            Token::Name(name) => match name.as_str() {
                "if" => Some((0, "if")),
                "unless" => Some((0, "unless")),
                "or" => Some((1, "or")),
                "xor" => Some((1, "xor")),
                "and" => Some((2, "and")),
                _ => None,
            },
            Token::Punct(c @ ('|' | '/' | '&'))
                if statement.get(index + 1) == Some(&Token::Punct(*c))
                    && statement.get(index - 1) != Some(&Token::Punct(*c)) =>
            {
                match c {
                    '|' => Some((3, "||")),
                    '/' => Some((3, "//")),
                    _ => Some((4, "&&")),
                }
            }
            _ => None,
        };
        // The operators are left-associative, so the last one groups last.
        if let Some((class, operator)) = found {
            last[class] = Some((index, operator));
        }
    }
    let (index, operator) = last.into_iter().flatten().next()?;
    // A word operator is one token; a symbolic one is two.
    let symbolic = !operator.starts_with(char::is_alphabetic);
    let (left, right) = (
        &statement[..index],
        &statement[index + 1 + usize::from(symbolic)..],
    );
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left, operator, right))
}
