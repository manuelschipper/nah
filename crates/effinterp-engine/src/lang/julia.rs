//! Julia's literal inline grammar. A program is accepted only when it is a
//! straight-line sequence of standard-library calls whose arguments are
//! recoverable string literals, `ENV` reads, `homedir()`, or `joinpath`/`*`
//! compositions of those. Zero-argument `function NAME() ... end` definitions
//! run their body where they are called, `eval(Meta.parse("..."))` runs one
//! literal statement, and `run(`...`)` executes its command literal as an
//! exact argument vector. Every other construct ends the walk in one typed
//! boundary naming it.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity, filesystem_path,
};

use super::source_text::{drive_letter_platform, elide_detail, nest_argv, take_accepted_chars};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, charge_analysis_steps};

/// Domains this frontend models. Anything outside them stays unclaimed.
const DOMAINS: [&str; 3] = ["environment", "filesystem", "process"];

/// Names `apply` models. A program defining one of them shadows the library
/// function, so the definition is outside the grammar.
const MODELED: [&str; 16] = [
    "rm",
    "mv",
    "cp",
    "write",
    "read",
    "readlines",
    "readchomp",
    "touch",
    "mkdir",
    "mkpath",
    "open",
    "println",
    "print",
    "exit",
    "run",
    "eval",
];

/// How deeply function calls and `eval` may nest before the walk refuses.
const MAX_CALL_DEPTH: u32 = 8;

pub(super) fn analyze(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    scope: Option<ProvenanceRef>,
    depth: u64,
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
    let mut walk = JuliaWalk {
        nest,
        cwd,
        node,
        depth,
        functions: BTreeMap::new(),
        active: BTreeSet::new(),
        call_depth: 0,
        understood: true,
    };
    walk.program(builder, source);
    if walk.understood {
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

struct JuliaWalk<'a> {
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    node: ProvenanceRef,
    /// Execution depth a `run` command runs at.
    depth: u64,
    /// Bodies of the zero-argument functions defined so far, one statement each.
    functions: BTreeMap<String, Vec<String>>,
    /// Functions whose body is running, so recursion is refused.
    active: BTreeSet<String>,
    call_depth: u32,
    understood: bool,
}

impl JuliaWalk<'_> {
    /// Stops at the first construct outside the grammar so no statement after
    /// an unexplained one is claimed.
    fn program(&mut self, builder: &mut PlanBuilder, source: &str) {
        match statements(source) {
            Ok(statements) => self.run(builder, statements),
            Err(detail) => self.boundary(builder, detail),
        }
    }

    fn run(&mut self, builder: &mut PlanBuilder, statements: Vec<String>) {
        let mut statements = statements.into_iter();
        while let Some(statement) = statements.next() {
            if self.nest.budget.timed_out() {
                builder.note_deadline();
                return;
            }
            // Called functions and `eval` repeat work, so every statement is charged.
            if !charge_analysis_steps(builder, self.nest.budget, statement.len() as u64, None) {
                self.understood = false;
                return;
            }
            if let Some(header) = statement.trim().strip_prefix("function ") {
                if let Err(detail) = self.define(header, &mut statements) {
                    return self.boundary(builder, detail);
                }
                continue;
            }
            match call(&statement) {
                Ok(call) => {
                    if let Err(detail) = self.apply(builder, &call) {
                        return self.boundary(builder, detail);
                    }
                }
                Err(detail) => return self.boundary(builder, detail),
            }
            if !self.understood {
                return;
            }
        }
    }

    /// Record `function NAME()`'s body up to its `end`. Every body statement
    /// must be a call, so no nested block can close the function early.
    fn define(
        &mut self,
        header: &str,
        statements: &mut impl Iterator<Item = String>,
    ) -> Result<(), String> {
        let name = header
            .trim()
            .strip_suffix("()")
            .filter(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '!')
                    && !name.starts_with(|c: char| c.is_ascii_digit())
            })
            .ok_or("julia function with parameters is outside the literal grammar")?;
        if MODELED.contains(&name) || self.functions.contains_key(name) {
            return Err(format!("julia function {name} redefines a known function"));
        }
        let mut body = Vec::new();
        for statement in statements.by_ref() {
            if statement.trim() == "end" {
                self.functions.insert(name.to_string(), body);
                return Ok(());
            }
            call(&statement)?;
            body.push(statement);
        }
        Err(format!("julia function {name} has no end"))
    }

    /// Run a called function's body, or one `eval`'d statement, in place.
    fn nested(
        &mut self,
        builder: &mut PlanBuilder,
        name: Option<&str>,
        statements: Vec<String>,
    ) -> Result<(), String> {
        if self.call_depth >= MAX_CALL_DEPTH
            || name.is_some_and(|name| !self.active.insert(name.to_string()))
        {
            return Err("julia recursion is not modeled".into());
        }
        self.call_depth += 1;
        self.run(builder, statements);
        self.call_depth -= 1;
        if let Some(name) = name {
            self.active.remove(name);
        }
        Ok(())
    }

    fn apply(&mut self, builder: &mut PlanBuilder, call: &JuliaCall) -> Result<(), String> {
        if let Some(body) = self.functions.get(&call.callee).cloned() {
            if !call.arguments.is_empty() {
                return Err(format!("julia call to {} has arguments", call.callee));
            }
            return self.nested(builder, Some(&call.callee), body);
        }
        let positional = call.positional();
        match (call.callee.as_str(), positional.len()) {
            // `Meta.parse` reads exactly one expression.
            ("eval", _) if call.arguments.len() == 1 => {
                let Some(source) = arguments(call.arguments[0].raw.trim(), "Meta.parse")? else {
                    return Err("julia eval of anything but Meta.parse is not modeled".into());
                };
                let Some(source) = value(&source)
                    .ok()
                    .and_then(|source| self.text(builder, &source))
                else {
                    return Err("julia Meta.parse source is not a recoverable string".into());
                };
                let statements = statements(&source)?;
                if statements.len() != 1 {
                    return Err("julia Meta.parse source is not one expression".into());
                }
                self.nested(builder, None, statements)
            }
            ("run", _) => {
                let mut command = None;
                for argument in &call.arguments {
                    match argument.keyword.as_deref() {
                        None if command.is_none() => command = Some(argument.raw.trim()),
                        Some("wait") if matches!(argument.raw.trim(), "true" | "false") => {}
                        _ => return Err("julia run arguments are not modeled".into()),
                    }
                }
                let argv = command_literal(command.unwrap_or_default())?;
                nest_argv(builder, self.nest, &argv, self.cwd, self.node, self.depth);
                Ok(())
            }
            ("rm" | "Base.rm", 1) => {
                let recursive = call.keyword("recursive") == Some("true");
                self.effect(
                    builder,
                    "filesystem.delete",
                    positional[0],
                    &[("recursive", recursive)],
                )
            }
            ("mv" | "Base.mv", 2) => {
                self.effect(builder, "filesystem.move", positional[0], &[])?;
                self.effect(builder, "filesystem.delete", positional[0], &[])?;
                self.effect(builder, "filesystem.write", positional[1], &[])
            }
            ("cp" | "Base.cp", 2) => {
                self.effect(builder, "filesystem.read", positional[0], &[])?;
                self.effect(builder, "filesystem.write", positional[1], &[])
            }
            ("write", 2) => self.effect(builder, "filesystem.write", positional[0], &[]),
            ("read", 1 | 2) => self.effect(builder, "filesystem.read", positional[0], &[]),
            ("readlines" | "readchomp", 1) => {
                self.effect(builder, "filesystem.read", positional[0], &[])
            }
            ("touch", 1) => self.effect(builder, "filesystem.write", positional[0], &[]),
            ("mkdir" | "mkpath", 1) => {
                self.effect(builder, "filesystem.create", positional[0], &[])
            }
            ("open", 1) => self.effect(builder, "filesystem.read", positional[0], &[]),
            ("open", 2) => {
                let Some(mode) = self.text(builder, positional[1]) else {
                    return Err("julia open mode is not a recoverable string".into());
                };
                let update = mode.ends_with('+');
                match mode.trim_end_matches('+') {
                    "r" => {
                        self.effect(builder, "filesystem.read", positional[0], &[])?;
                        if update {
                            self.effect(builder, "filesystem.write", positional[0], &[])?;
                        }
                        Ok(())
                    }
                    "w" | "a" => {
                        let append = mode.starts_with('a');
                        self.effect(
                            builder,
                            "filesystem.write",
                            positional[0],
                            &[("append", append)],
                        )?;
                        if update {
                            self.effect(builder, "filesystem.read", positional[0], &[])?;
                        }
                        Ok(())
                    }
                    _ => Err(format!("julia open mode {mode:?} is not modeled")),
                }
            }
            ("println" | "print" | "exit", _) => Ok(()),
            (callee, count) => Err(format!(
                "julia call to {callee} with {count} positional arguments is outside the literal grammar"
            )),
        }
    }

    fn effect(
        &mut self,
        builder: &mut PlanBuilder,
        operation: &str,
        value: &JuliaValue,
        attributes: &[(&str, bool)],
    ) -> Result<(), String> {
        let Some(resource) = self.resource(builder, value) else {
            return Err("julia path argument is not a recoverable string".into());
        };
        builder.effect(Effect {
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
            provenance: vec![self.node],
        });
        Ok(())
    }

    fn text(&mut self, builder: &mut PlanBuilder, value: &JuliaValue) -> Option<String> {
        let mut text = String::new();
        for part in &value.0 {
            match part {
                JuliaValuePart::Text(literal) => text.push_str(literal),
                JuliaValuePart::Env(name) => match self.env(builder, name) {
                    Some(ResourceExpr::Literal { value }) => text.push_str(&value),
                    _ => return None,
                },
            }
        }
        Some(text)
    }

    fn resource(&mut self, builder: &mut PlanBuilder, value: &JuliaValue) -> Option<ResourceExpr> {
        let mut parts = Vec::new();
        for part in &value.0 {
            match part {
                JuliaValuePart::Text(literal) => parts.push(ResourceExpr::Literal {
                    value: literal.clone(),
                }),
                JuliaValuePart::Env(name) => parts.push(
                    self.env(builder, name)
                        .unwrap_or(ResourceExpr::Environment { name: name.clone() }),
                ),
            }
        }
        let literal = parts
            .iter()
            .map(|part| match part {
                ResourceExpr::Literal { value } => Some(value.as_str()),
                _ => None,
            })
            .collect::<Option<String>>();
        match literal {
            Some(path) if !path.is_empty() => {
                let platform = drive_letter_platform(&path, self.cwd);
                Some(filesystem_path(
                    &path,
                    self.cwd.map(|cwd| filesystem_path(cwd, None, platform)),
                    platform,
                ))
            }
            Some(_) => None,
            None => Some(ResourceExpr::Join { parts }),
        }
    }

    /// `ENV[...]` and `homedir()` are environment reads whatever they resolve to.
    fn env(&mut self, builder: &mut PlanBuilder, name: &str) -> Option<ResourceExpr> {
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            },
            attributes: Default::default(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance: vec![self.node],
        });
        self.nest.environment_value(name)
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

struct JuliaCall {
    callee: String,
    arguments: Vec<JuliaArgument>,
}

struct JuliaArgument {
    keyword: Option<String>,
    /// Raw text, kept for keyword comparisons that are not path values.
    raw: String,
    value: Option<JuliaValue>,
}

impl JuliaCall {
    fn positional(&self) -> Vec<&JuliaValue> {
        self.arguments
            .iter()
            .filter(|argument| argument.keyword.is_none())
            .filter_map(|argument| argument.value.as_ref())
            .collect()
    }

    fn keyword(&self, name: &str) -> Option<&str> {
        self.arguments
            .iter()
            .find(|argument| argument.keyword.as_deref() == Some(name))
            .map(|argument| argument.raw.trim())
    }
}

struct JuliaValue(Vec<JuliaValuePart>);

enum JuliaValuePart {
    Text(String),
    Env(String),
}

/// Split a program into statements. Only straight-line code is accepted.
fn statements(source: &str) -> Result<Vec<String>, String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut rest = source;
    let mut depth = 0u32;
    while let Some(character) = rest.chars().next() {
        if character == '#' {
            if rest.starts_with("#=") {
                let (comment, tail) = block_comment(rest)?;
                if depth == 0 {
                    for _ in comment.bytes().filter(|byte| *byte == b'\n') {
                        statements.push(std::mem::take(&mut current));
                    }
                } else {
                    current.push(' ');
                }
                rest = tail;
                continue;
            }
            rest = &rest[rest.find('\n').unwrap_or(rest.len())..];
            continue;
        }
        if character == '"' || character == '`' {
            if rest.starts_with("\"\"\"") || rest.starts_with("```") {
                return Err("julia triple-quoted strings are not modeled".into());
            }
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.checked_sub(1).ok_or("julia program is unbalanced")?,
            _ => {}
        }
        if depth == 0 && (character == ';' || character == '\n') {
            statements.push(std::mem::take(&mut current));
            rest = &rest[character.len_utf8()..];
            continue;
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    if depth != 0 {
        return Err("julia program is unbalanced".into());
    }
    statements.push(current);
    Ok(statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect())
}

/// Consume a nestable Julia `#= ... =#` block comment.
fn block_comment(source: &str) -> Result<(&str, &str), String> {
    let mut depth = 0u32;
    let mut index = 0usize;
    while index < source.len() {
        if source[index..].starts_with("#=") {
            depth += 1;
            index += 2;
        } else if source[index..].starts_with("=#") {
            depth = depth
                .checked_sub(1)
                .ok_or("julia block comment is unbalanced")?;
            index += 2;
            if depth == 0 {
                return Ok((&source[..index], &source[index..]));
            }
        } else {
            index += source[index..].chars().next().unwrap().len_utf8();
        }
    }
    Err("julia block comment is unterminated".into())
}

/// Consume one `"..."` string or `` `...` `` command literal.
fn quoted(source: &str) -> Result<(&str, &str), String> {
    let bytes = source.as_bytes();
    let quote = bytes[0];
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return Ok((&source[..index + 1], &source[index + 1..])),
            _ => index += 1,
        }
    }
    Err("julia string literal is unterminated".into())
}

/// Split a `` `...` `` command literal into its argument vector the way Julia
/// does: whitespace separates words, quotes and `\` escapes group them.
/// Interpolation and the characters Julia requires quoted are refused.
fn command_literal(literal: &str) -> Result<Vec<String>, String> {
    let body = literal
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .ok_or("julia run argument is not a command literal")?;
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = body.chars();
    while let Some(character) = chars.next() {
        match character {
            ' ' | '\t' | '\n' => words.extend(word.take()),
            '\'' => {
                let text = word.get_or_insert_default();
                loop {
                    match chars.next().ok_or("julia command quote is unterminated")? {
                        '\'' => break,
                        other => text.push(other),
                    }
                }
            }
            '"' => {
                let text = word.get_or_insert_default();
                loop {
                    match chars.next().ok_or("julia command quote is unterminated")? {
                        '"' => break,
                        '$' => return Err("julia command interpolation is not modeled".into()),
                        '\\' => match chars.next().ok_or("julia command escape is truncated")? {
                            escaped @ ('\\' | '"' | '$' | '`') => text.push(escaped),
                            other => {
                                text.push('\\');
                                text.push(other);
                            }
                        },
                        other => text.push(other),
                    }
                }
            }
            '\\' => word
                .get_or_insert_default()
                .push(chars.next().ok_or("julia command escape is truncated")?),
            '$' => return Err("julia command interpolation is not modeled".into()),
            special if "#{}()[]<>|&*?~;".contains(special) => {
                return Err(format!("julia command character {special} is not modeled"));
            }
            other => word.get_or_insert_default().push(other),
        }
    }
    words.extend(word);
    if words.is_empty() {
        return Err("julia command literal is empty".into());
    }
    Ok(words)
}

/// Parse one statement as `name(arguments)`. Julia's keyword arguments follow
/// either a `;` inside the call or a `name=` prefix.
fn call(statement: &str) -> Result<JuliaCall, String> {
    let statement = statement.trim();
    let open = statement.find('(').ok_or("julia statement is not a call")?;
    let callee = statement[..open].trim();
    if callee.is_empty()
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '!')
        || callee.starts_with(|c: char| c.is_ascii_digit())
        || callee.split('.').any(str::is_empty)
    {
        return Err(format!(
            "julia statement {:?} is outside the literal call grammar",
            elide_detail(statement)
        ));
    }
    let (arguments, rest) = balanced(&statement[open..])?;
    if !rest.trim().is_empty() {
        return Err(format!(
            "julia call tail {:?} is outside the literal call grammar",
            elide_detail(rest)
        ));
    }
    let mut parsed = Vec::new();
    let mut keyword_section = false;
    for (separator, argument) in split(arguments)? {
        keyword_section |= separator == ';';
        let (keyword, raw) = match argument.split_once('=') {
            Some((name, tail))
                if !name.trim().is_empty()
                    && name
                        .trim()
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !tail.starts_with('=') =>
            {
                (Some(name.trim().to_string()), tail.to_string())
            }
            _ if keyword_section => (Some(argument.trim().to_string()), argument.clone()),
            _ => (None, argument.clone()),
        };
        let value = value(&raw).ok();
        parsed.push(JuliaArgument {
            keyword,
            raw,
            value,
        });
    }
    Ok(JuliaCall {
        callee: callee.to_string(),
        arguments: parsed,
    })
}

fn balanced(source: &str) -> Result<(&str, &str), String> {
    let mut depth = 0u32;
    let mut rest = source;
    let mut index = 0;
    while let Some(character) = rest.chars().next() {
        if character == '"' || character == '`' {
            let (literal, tail) = quoted(rest)?;
            index += literal.len();
            rest = tail;
            continue;
        }
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&source[1..index], &source[index + 1..]));
                }
            }
            _ => {}
        }
        index += character.len_utf8();
        rest = &rest[character.len_utf8()..];
    }
    Err("julia call is unbalanced".into())
}

/// Split an argument list on top-level `,` and `;`, keeping each separator.
fn split(source: &str) -> Result<Vec<(char, String)>, String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut separator = ',';
    let mut depth = 0u32;
    let mut rest = source;
    while let Some(character) = rest.chars().next() {
        if character == '"' || character == '`' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' | ';' if depth == 0 => {
                arguments.push((separator, std::mem::take(&mut current)));
                separator = character;
                rest = &rest[1..];
                continue;
            }
            _ => {}
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    if !current.trim().is_empty() || !arguments.is_empty() {
        arguments.push((separator, current));
    }
    Ok(arguments)
}

/// A value is a `*` product of string literals, `ENV[...]` reads, `homedir()`,
/// and `joinpath`/`expanduser` compositions of those.
fn value(source: &str) -> Result<JuliaValue, String> {
    let mut parts = Vec::new();
    for term in product(source)? {
        let term = term.trim();
        if term.starts_with('"') {
            parts.extend(interpolated(term)?);
        } else if let Some(name) = env_index(term)? {
            parts.push(JuliaValuePart::Env(name));
        } else if term == "homedir()" {
            parts.push(JuliaValuePart::Env("HOME".into()));
        } else if let Some(inner) = arguments(term, "joinpath")? {
            let mut first = true;
            for (_, argument) in split(&inner)? {
                if !first {
                    parts.push(JuliaValuePart::Text("/".into()));
                }
                first = false;
                parts.extend(value(&argument)?.0);
            }
        } else if let Some(inner) = arguments(term, "expanduser")? {
            parts.extend(expanded(value(&inner)?.0));
        } else {
            return Err(format!(
                "julia value {:?} is outside the literal expression grammar",
                elide_detail(term)
            ));
        }
    }
    parts.retain(|part| !matches!(part, JuliaValuePart::Text(text) if text.is_empty()));
    if parts.is_empty() {
        return Err("julia value is empty".into());
    }
    Ok(JuliaValue(parts))
}

/// `expanduser` is the only Julia path function that resolves a leading `~`.
fn expanded(mut parts: Vec<JuliaValuePart>) -> Vec<JuliaValuePart> {
    if let Some(JuliaValuePart::Text(first)) = parts.first_mut()
        && let Some(tail) = first.strip_prefix('~')
        && (tail.is_empty() || tail.starts_with('/'))
    {
        *first = tail.to_string();
        parts.insert(0, JuliaValuePart::Env("HOME".into()));
    }
    parts
}

/// The literal name of an `ENV["NAME"]` read, when the term is one.
fn env_index(term: &str) -> Result<Option<String>, String> {
    let Some(index) = term.strip_prefix("ENV") else {
        return Ok(None);
    };
    let name = index
        .trim_start()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or("julia ENV index is not a literal")?
        .trim();
    if !name.starts_with('"') {
        return Err("julia ENV name is not a literal".into());
    }
    Ok(Some(unescape(name)?))
}

/// The argument text of `callee(...)`, when the term is exactly that call.
fn arguments(term: &str, callee: &str) -> Result<Option<String>, String> {
    let Some(rest) = term.strip_prefix(callee) else {
        return Ok(None);
    };
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        return Ok(None);
    }
    let (inner, tail) = balanced(rest)?;
    if !tail.trim().is_empty() {
        return Err("julia path call tail is not modeled".into());
    }
    Ok(Some(inner.to_string()))
}

/// Split one value on top-level `*` string concatenation operators.
fn product(source: &str) -> Result<Vec<String>, String> {
    let mut terms = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    let mut rest = source;
    while let Some(character) = rest.chars().next() {
        if character == '"' || character == '`' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '*' if depth == 0 => {
                terms.push(std::mem::take(&mut current));
                rest = &rest[1..];
                continue;
            }
            _ => {}
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    terms.push(current);
    Ok(terms)
}

/// Decode one Julia string literal, keeping `$(ENV["NAME"])` interpolations as
/// environment parts. Any other interpolation is not recoverable.
fn interpolated(literal: &str) -> Result<Vec<JuliaValuePart>, String> {
    let body = literal
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or("julia string literal is unterminated")?;
    let mut parts = Vec::new();
    let mut rest = body;
    let mut current = String::new();
    while let Some(character) = rest.chars().next() {
        if character == '$' {
            let inner = rest[1..]
                .strip_prefix("(ENV[")
                .and_then(|rest| rest.split_once("])"))
                .ok_or("julia string interpolation is not a recoverable value")?;
            let name = inner.0.trim();
            if !name.starts_with('"') {
                return Err("julia ENV name is not a literal".into());
            }
            parts.push(JuliaValuePart::Text(std::mem::take(&mut current)));
            parts.push(JuliaValuePart::Env(unescape(name)?));
            rest = inner.1;
            continue;
        }
        if character != '\\' {
            current.push(character);
            rest = &rest[character.len_utf8()..];
            continue;
        }
        rest = &rest[1..];
        let escape = rest.chars().next().ok_or("julia escape is truncated")?;
        rest = &rest[escape.len_utf8()..];
        match escape {
            'a' => current.push('\u{7}'),
            'b' => current.push('\u{8}'),
            'f' => current.push('\u{c}'),
            'n' => current.push('\n'),
            'r' => current.push('\r'),
            't' => current.push('\t'),
            'v' => current.push('\u{b}'),
            '\\' | '"' | '\'' | '$' => current.push(escape),
            'x' => current.push(decode(
                &take_accepted_chars(&mut rest, 2, |c| c.is_ascii_hexdigit()),
                16,
            )?),
            'u' => current.push(decode(
                &take_accepted_chars(&mut rest, 4, |c| c.is_ascii_hexdigit()),
                16,
            )?),
            'U' => current.push(decode(
                &take_accepted_chars(&mut rest, 8, |c| c.is_ascii_hexdigit()),
                16,
            )?),
            digit if digit.is_digit(8) => {
                let mut digits = digit.to_string();
                digits.push_str(&take_accepted_chars(&mut rest, 2, |c| c.is_digit(8)));
                current.push(decode(&digits, 8)?);
            }
            other => return Err(format!("julia escape \\{other} is not modeled")),
        }
    }
    parts.push(JuliaValuePart::Text(current));
    Ok(parts)
}

fn unescape(literal: &str) -> Result<String, String> {
    match interpolated(literal)?.as_slice() {
        [JuliaValuePart::Text(text)] => Ok(text.clone()),
        _ => Err("julia interpolated string is not a literal here".into()),
    }
}

fn decode(digits: &str, radix: u32) -> Result<char, String> {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .ok_or_else(|| format!("julia escape {digits:?} is not a character"))
}
