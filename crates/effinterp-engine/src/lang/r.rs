//! R's literal inline grammar. A program is accepted only when it is a
//! straight-line sequence of standard-library calls and `name <- value`
//! bindings whose values are recoverable string literals, bound names,
//! `Sys.getenv` reads, or `file.path`/`paste0` compositions of those.
//! `system`/`system2` run their command as shell source, and
//! `eval(parse(text = ...))` runs a literal as R in the same walk. Every other
//! construct ends the walk in one typed boundary naming it.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity, filesystem_path,
};

use super::source_text::{drive_letter_platform, elide_detail, nest_shell, take_accepted_chars};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, charge_analysis_bytes, charge_analysis_steps};
use crate::resource_transfer::TransferBinding;

/// Domains this frontend models. Anything outside them stays unclaimed.
const DOMAINS: [&str; 3] = ["environment", "filesystem", "process"];

/// How deeply `eval(parse(text = ...))` may nest before the walk refuses.
const MAX_EVAL_DEPTH: u32 = 8;

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
    let mut walk = RWalk {
        nest,
        cwd,
        node,
        depth,
        bindings: BTreeMap::new(),
        eval_depth: 0,
        understood: true,
        glob: false,
    };
    walk.program(builder, source);
    if walk.understood {
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

struct RWalk<'a> {
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    node: ProvenanceRef,
    /// Execution depth a nested `system` command runs at.
    depth: u64,
    /// Top-level `name <- value` bindings, in program order.
    bindings: BTreeMap<String, RValue>,
    eval_depth: u32,
    understood: bool,
    /// Whether the call being applied expands wildcards in its operands.
    glob: bool,
}

impl RWalk<'_> {
    /// Stops at the first construct outside the grammar so no statement after
    /// an unexplained one is claimed.
    fn program(&mut self, builder: &mut PlanBuilder, source: &str) {
        let statements = match statements(source) {
            Ok(statements) => statements,
            Err(detail) => return self.boundary(builder, detail),
        };
        for statement in statements {
            if self.nest.budget.timed_out() {
                builder.note_deadline();
                return;
            }
            // `eval` and bindings can repeat work, so every statement is charged.
            if !charge_analysis_steps(builder, self.nest.budget, statement.len() as u64, None) {
                self.understood = false;
                return;
            }
            if let Some((name, source)) = assignment(&statement) {
                match value(source, &self.bindings) {
                    Ok(bound) => {
                        let bytes = bound.0.iter().map(RValuePart::len).sum::<usize>() as u64;
                        if !charge_analysis_bytes(builder, self.nest.budget, bytes, None) {
                            self.understood = false;
                            return;
                        }
                        self.bindings.insert(name.to_string(), bound);
                    }
                    Err(detail) => return self.boundary(builder, detail),
                }
                continue;
            }
            match call(&statement, &self.bindings) {
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

    fn apply(&mut self, builder: &mut PlanBuilder, call: &RCall) -> Result<(), String> {
        let positional = call.positional();
        match (call.callee.as_str(), positional.len()) {
            // Every R file function resolves a leading `~` through HOME.
            ("unlink", count) if count > 0 || call.named("x").is_some() => {
                let recursive = call.named("recursive").map(str::trim) == Some("TRUE");
                let targets = match call.named("x") {
                    Some(_) => vec![
                        call.named_value("x")
                            .ok_or("R path argument is not a recoverable string")?,
                    ],
                    None => positional,
                };
                for target in &targets {
                    // `unlink` is the one R file function that expands wildcards.
                    self.glob = true;
                    let emitted = self.effect(
                        builder,
                        "filesystem.delete",
                        target,
                        &[("recursive", recursive)],
                    );
                    self.glob = false;
                    emitted?;
                }
                Ok(())
            }
            ("file.remove", 1..) => {
                for target in &positional {
                    self.effect(builder, "filesystem.delete", target, &[])?;
                }
                Ok(())
            }
            ("file.create", 1..) | ("dir.create", 1) => {
                for target in &positional {
                    self.effect(builder, "filesystem.create", target, &[])?;
                }
                Ok(())
            }
            ("writeLines", _) | ("writeChar", _) | ("writeBin", _) => {
                let Some(target) = call.argument(1, "con") else {
                    return Err("R connection argument is not supplied".into());
                };
                self.emit_effect(
                    builder,
                    "filesystem.write",
                    target,
                    &[],
                    Some(("disclosure", "contents")),
                )
                .map(drop)
            }
            ("saveRDS", _) => {
                let Some(target) = call.argument(1, "file") else {
                    return Err("R file argument is not supplied".into());
                };
                self.emit_effect(
                    builder,
                    "filesystem.write",
                    target,
                    &[],
                    Some(("disclosure", "contents")),
                )
                .map(drop)
            }
            ("cat", _) | ("write", _) | ("write.csv", _) | ("save", _) => {
                let Some(target) = call.named_value("file") else {
                    // Without a file argument the output reaches the console.
                    return Ok(());
                };
                let append = call.named("append").map(str::trim) == Some("TRUE");
                self.emit_effect(
                    builder,
                    "filesystem.write",
                    target,
                    &[("append", append)],
                    Some(("disclosure", "contents")),
                )
                .map(drop)
            }
            ("file.copy", 2..) => {
                let source = self.emit_effect(
                    builder,
                    "filesystem.read",
                    positional[0],
                    &[],
                    Some(("access_purpose", "program_input")),
                )?;
                let destination = self.emit_effect(
                    builder,
                    "filesystem.write",
                    positional[1],
                    &[],
                    Some(("disclosure", "contents")),
                )?;
                if let (Some(source), Some(destination)) = (source, destination) {
                    builder.transfer_binding(TransferBinding::exact(source, destination));
                }
                Ok(())
            }
            ("file.rename", 2..) => {
                self.effect(builder, "filesystem.move", positional[0], &[])?;
                let source =
                    self.emit_effect(builder, "filesystem.delete", positional[0], &[], None)?;
                let destination = self.emit_effect(
                    builder,
                    "filesystem.write",
                    positional[1],
                    &[],
                    Some(("disclosure", "contents")),
                )?;
                if let (Some(source), Some(destination)) = (source, destination) {
                    builder.transfer_binding(TransferBinding::exact(source, destination));
                }
                Ok(())
            }
            ("file.append", 2..) => {
                let source = self.emit_effect(
                    builder,
                    "filesystem.read",
                    positional[1],
                    &[],
                    Some(("access_purpose", "program_input")),
                )?;
                let destination = self.emit_effect(
                    builder,
                    "filesystem.write",
                    positional[0],
                    &[("append", true)],
                    Some(("disclosure", "contents")),
                )?;
                if let (Some(source), Some(destination)) = (source, destination) {
                    builder.transfer_binding(TransferBinding::exact(source, destination));
                }
                Ok(())
            }
            ("readLines", _) | ("readRDS", _) | ("read.csv", _) | ("scan", _) => {
                let Some(target) = call.argument(0, "file").or_else(|| call.named_value("con"))
                else {
                    return Err("R input connection is not supplied".into());
                };
                self.emit_effect(
                    builder,
                    "filesystem.read",
                    target,
                    &[],
                    Some(("access_purpose", "program_input")),
                )
                .map(drop)
            }
            // On Unix `system` runs its command through `sh -c`; the options
            // only redirect or capture the command's output.
            ("system", _) => {
                call.operands_recoverable(&["command"])?;
                let mut command = self.command_text(builder, call.argument(0, "command"))?;
                let mut captured = false;
                for argument in &call.arguments {
                    match argument.name.as_deref() {
                        None | Some("command") => {}
                        Some(name @ ("intern" | "ignore.stdout" | "ignore.stderr" | "wait")) => {
                            let flag = argument.raw.trim();
                            if flag != "TRUE" && flag != "FALSE" {
                                return Err(format!("R system {name} is not a literal flag"));
                            }
                            match (name, flag) {
                                // `intern = TRUE` returns the output as a value.
                                ("intern", "TRUE") => captured = true,
                                ("ignore.stdout", "TRUE") => command.push_str(" >/dev/null"),
                                ("ignore.stderr", "TRUE") => command.push_str(" 2>/dev/null"),
                                _ => {}
                            }
                        }
                        Some(name) => return Err(format!("R system option {name} is not modeled")),
                    }
                }
                if call.unnamed() > 1 {
                    return Err("R system positional options are not modeled".into());
                }
                nest_shell(
                    builder, self.nest, command, self.cwd, self.node, self.depth, captured,
                );
                Ok(())
            }
            // `system2` pastes the quoted command and its unquoted `args` text
            // into one `sh -c` command line.
            ("system2", _) => {
                call.operands_recoverable(&["command", "args"])?;
                let command = self.command_text(builder, call.argument(0, "command"))?;
                if command.contains('\'') {
                    return Err("R system2 command quoting is not modeled".into());
                }
                let mut line = format!("'{command}'");
                if call.named("args").is_some() || call.unnamed() > 1 {
                    let args = self.command_text(builder, call.argument(1, "args"))?;
                    line.push(' ');
                    line.push_str(&args);
                }
                for argument in &call.arguments {
                    match argument.name.as_deref() {
                        None | Some("command" | "args") => {}
                        Some("wait") if matches!(argument.raw.trim(), "TRUE" | "FALSE") => {}
                        Some(name) => {
                            return Err(format!("R system2 option {name} is not modeled"));
                        }
                    }
                }
                if call.unnamed() > 2 {
                    return Err("R system2 positional options are not modeled".into());
                }
                nest_shell(
                    builder, self.nest, line, self.cwd, self.node, self.depth, false,
                );
                Ok(())
            }
            // `eval(parse(text = "..."))` runs the literal as R in this program.
            ("eval", _) if call.arguments.len() == 1 => {
                let parse = self::call(&call.arguments[0].raw, &self.bindings)?;
                let [argument] = parse.arguments.as_slice() else {
                    return Err("R eval of a parse with options is not modeled".into());
                };
                if parse.callee != "parse" || argument.name.as_deref() != Some("text") {
                    return Err("R eval of anything but parse(text = ...) is not modeled".into());
                }
                let source = self.command_text(builder, argument.value.as_ref())?;
                if self.eval_depth >= MAX_EVAL_DEPTH {
                    return Err("R eval nesting is not modeled".into());
                }
                self.eval_depth += 1;
                self.program(builder, &source);
                self.eval_depth -= 1;
                Ok(())
            }
            ("print" | "message" | "Sys.setenv" | "invisible" | "q", _) => Ok(()),
            (callee, count) => Err(format!(
                "R call to {callee} with {count} positional arguments is outside the literal grammar"
            )),
        }
    }

    /// The literal text of a command or source argument.
    fn command_text(
        &mut self,
        builder: &mut PlanBuilder,
        value: Option<&RValue>,
    ) -> Result<String, String> {
        let value = value.ok_or("R command argument is not a recoverable string")?;
        let mut text = String::new();
        for part in &value.0 {
            match part {
                RValuePart::Text(literal) => text.push_str(literal),
                RValuePart::Env(name) => match self.env(builder, name) {
                    Some(ResourceExpr::Literal { value }) => text.push_str(&value),
                    _ => return Err("R command reads an unknown environment value".into()),
                },
            }
        }
        Ok(text)
    }

    fn effect(
        &mut self,
        builder: &mut PlanBuilder,
        operation: &str,
        value: &RValue,
        attributes: &[(&str, bool)],
    ) -> Result<(), String> {
        self.emit_effect(builder, operation, value, attributes, None)
            .map(drop)
    }

    fn emit_effect(
        &mut self,
        builder: &mut PlanBuilder,
        operation: &str,
        value: &RValue,
        attributes: &[(&str, bool)],
        semantic_attribute: Option<(&str, &str)>,
    ) -> Result<Option<u32>, String> {
        let Some(resource) = self.resource(builder, value) else {
            return Err("R path argument is not a recoverable string".into());
        };
        let mut attributes = attributes
            .iter()
            .map(|(name, value)| ((*name).to_string(), AttrValue::Bool(*value)))
            .collect::<std::collections::BTreeMap<_, _>>();
        if let Some((name, value)) = semantic_attribute {
            attributes.insert(name.into(), AttrValue::String(value.into()));
        }
        Ok(builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance: vec![self.node],
        }))
    }

    fn resource(&mut self, builder: &mut PlanBuilder, value: &RValue) -> Option<ResourceExpr> {
        let mut parts = Vec::new();
        for part in tilde_expanded(&value.0) {
            match part {
                RValuePart::Text(literal) => parts.push(ResourceExpr::Literal { value: literal }),
                RValuePart::Env(name) => parts.push(
                    self.env(builder, &name)
                        .unwrap_or(ResourceExpr::Environment { name }),
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
                let resolved = filesystem_path(
                    &path,
                    self.cwd.map(|cwd| filesystem_path(cwd, None, platform)),
                    platform,
                );
                match (&resolved, self.glob && path.contains(['*', '?'])) {
                    (
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        },
                        true,
                    ) => Some(ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::FsPath { glob: path.clone() },
                    }),
                    _ => Some(resolved),
                }
            }
            Some(_) => None,
            None => Some(ResourceExpr::Join { parts }),
        }
    }

    /// `Sys.getenv` is an environment read whatever the value resolves to.
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

/// R's file functions resolve a leading `~` through the home directory.
fn tilde_expanded(parts: &[RValuePart]) -> Vec<RValuePart> {
    let mut parts = parts
        .iter()
        .map(|part| match part {
            RValuePart::Text(text) => RValuePart::Text(text.clone()),
            RValuePart::Env(name) => RValuePart::Env(name.clone()),
        })
        .collect::<Vec<_>>();
    if let Some(RValuePart::Text(first)) = parts.first_mut()
        && let Some(tail) = first.strip_prefix('~')
        && (tail.is_empty() || tail.starts_with('/'))
    {
        *first = tail.to_string();
        parts.insert(0, RValuePart::Env("HOME".into()));
    }
    parts
}

struct RCall {
    callee: String,
    arguments: Vec<Argument>,
}

struct Argument {
    name: Option<String>,
    raw: String,
    value: Option<RValue>,
}

impl RCall {
    fn positional(&self) -> Vec<&RValue> {
        self.arguments
            .iter()
            .filter(|argument| argument.name.is_none())
            .filter_map(|argument| argument.value.as_ref())
            .collect()
    }

    fn unnamed(&self) -> usize {
        self.arguments
            .iter()
            .filter(|argument| argument.name.is_none())
            .count()
    }

    /// Positional arguments and the named `operands` must all be recoverable
    /// values, so none is silently skipped when R matches them by position.
    fn operands_recoverable(&self, operands: &[&str]) -> Result<(), String> {
        let unrecoverable = self.arguments.iter().any(|argument| {
            argument.value.is_none()
                && argument
                    .name
                    .as_deref()
                    .is_none_or(|name| operands.contains(&name))
        });
        if unrecoverable {
            return Err(format!(
                "R {} operand is not a recoverable string",
                self.callee
            ));
        }
        Ok(())
    }

    fn named(&self, name: &str) -> Option<&str> {
        self.arguments
            .iter()
            .find(|argument| argument.name.as_deref() == Some(name))
            .map(|argument| argument.raw.as_str())
    }

    fn named_value(&self, name: &str) -> Option<&RValue> {
        self.arguments
            .iter()
            .find(|argument| argument.name.as_deref() == Some(name))
            .and_then(|argument| argument.value.as_ref())
    }

    /// R binds by name first, then by position among the unnamed arguments.
    fn argument(&self, index: usize, name: &str) -> Option<&RValue> {
        self.named_value(name)
            .or_else(|| self.positional().get(index).copied())
    }
}

#[derive(Clone)]
struct RValue(Vec<RValuePart>);

#[derive(Clone)]
enum RValuePart {
    Text(String),
    Env(String),
}

impl RValuePart {
    fn len(&self) -> usize {
        match self {
            RValuePart::Text(text) | RValuePart::Env(text) => text.len(),
        }
    }
}

/// The name and value source of a top-level `name <- value` binding.
fn assignment(statement: &str) -> Option<(&str, &str)> {
    let statement = statement.trim();
    let end = statement
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
        .unwrap_or(statement.len());
    let name = &statement[..end];
    let source = statement[end..].trim_start().strip_prefix("<-")?;
    (!name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit() || c == '_'))
        .then_some((name, source))
}

/// Split a program into statements. Only straight-line code is accepted.
fn statements(source: &str) -> Result<Vec<String>, String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut rest = source;
    let mut depth = 0u32;
    while let Some(character) = rest.chars().next() {
        if character == '#' {
            rest = &rest[rest.find('\n').unwrap_or(rest.len())..];
            continue;
        }
        if character == '"' || character == '\'' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1).ok_or("R program is unbalanced")?,
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
        return Err("R program is unbalanced".into());
    }
    statements.push(current);
    Ok(statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect())
}

fn quoted(source: &str) -> Result<(&str, &str), String> {
    let quote = source.as_bytes()[0];
    let bytes = source.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return Ok((&source[..index + 1], &source[index + 1..])),
            _ => index += 1,
        }
    }
    Err("R string literal is unterminated".into())
}

/// Parse one statement as `name(arguments)`, allowing a namespace qualifier.
fn call(statement: &str, bindings: &BTreeMap<String, RValue>) -> Result<RCall, String> {
    let statement = statement.trim();
    let open = statement.find('(').ok_or("R statement is not a call")?;
    let callee = statement[..open]
        .trim()
        .rsplit("::")
        .next()
        .expect("nonempty split")
        .trim();
    if callee.is_empty()
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        || callee.starts_with(|c: char| c.is_ascii_digit())
    {
        return Err(format!(
            "R statement {:?} is outside the literal call grammar",
            elide_detail(statement)
        ));
    }
    let (arguments, rest) = balanced(&statement[open..])?;
    if !rest.trim().is_empty() {
        return Err(format!(
            "R call tail {:?} is outside the literal call grammar",
            elide_detail(rest)
        ));
    }
    let arguments = split(arguments)?
        .into_iter()
        .map(|argument| {
            let (name, raw) = match argument.split_once('=') {
                Some((name, tail))
                    if !name.trim().is_empty()
                        && name
                            .trim()
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
                        && !tail.starts_with('=') =>
                {
                    (Some(name.trim().to_string()), tail.to_string())
                }
                _ => (None, argument),
            };
            let value = value(&raw, bindings).ok();
            Argument { name, raw, value }
        })
        .collect();
    Ok(RCall {
        callee: callee.to_string(),
        arguments,
    })
}

fn balanced(source: &str) -> Result<(&str, &str), String> {
    let mut depth = 0u32;
    let mut rest = source;
    let mut index = 0;
    while let Some(character) = rest.chars().next() {
        if character == '"' || character == '\'' {
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
    Err("R call is unbalanced".into())
}

fn split(source: &str) -> Result<Vec<String>, String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    let mut rest = source;
    while let Some(character) = rest.chars().next() {
        if character == '"' || character == '\'' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                arguments.push(std::mem::take(&mut current));
                rest = &rest[1..];
                continue;
            }
            _ => {}
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    if !current.trim().is_empty() || !arguments.is_empty() {
        arguments.push(current);
    }
    Ok(arguments)
}

/// A value is a string literal, a bound name, a `Sys.getenv` read, or a
/// `file.path`/`paste0` composition of those.
fn value(source: &str, bindings: &BTreeMap<String, RValue>) -> Result<RValue, String> {
    let term = source.trim();
    if term.starts_with('"') || term.starts_with('\'') {
        return Ok(RValue(vec![RValuePart::Text(unescape(term)?)]));
    }
    if let Some(bound) = bindings.get(term) {
        return Ok(bound.clone());
    }
    if let Some(inner) = arguments(term, "Sys.getenv")? {
        let name = inner.trim();
        if !(name.starts_with('"') || name.starts_with('\'')) {
            return Err("R Sys.getenv name is not a literal".into());
        }
        return Ok(RValue(vec![RValuePart::Env(unescape(name)?)]));
    }
    if let Some(inner) = arguments(term, "path.expand")? {
        return Ok(RValue(tilde_expanded(&value(&inner, bindings)?.0)));
    }
    for (callee, separator) in [("file.path", "/"), ("paste0", "")] {
        let Some(inner) = arguments(term, callee)? else {
            continue;
        };
        let mut parts = Vec::new();
        for argument in split(&inner)? {
            if !parts.is_empty() {
                parts.push(RValuePart::Text(separator.to_string()));
            }
            parts.extend(value(&argument, bindings)?.0);
        }
        if parts.is_empty() {
            return Err("R path composition has no arguments".into());
        }
        return Ok(RValue(parts));
    }
    Err(format!(
        "R value {:?} is outside the literal expression grammar",
        elide_detail(term)
    ))
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
        return Err("R path call tail is not modeled".into());
    }
    Ok(Some(inner.to_string()))
}

/// Decode one R string literal. R numeric escapes are octal (`\nnn`) and
/// hexadecimal (`\xhh`); `\uxxxx` and `\Uxxxxxxxx` are code points.
fn unescape(literal: &str) -> Result<String, String> {
    let quote = literal.as_bytes()[0] as char;
    let body = literal
        .strip_prefix(quote)
        .and_then(|rest| rest.strip_suffix(quote))
        .ok_or("R string literal is unterminated")?;
    let mut text = String::new();
    let mut rest = body;
    while let Some(character) = rest.chars().next() {
        if character != '\\' {
            text.push(character);
            rest = &rest[character.len_utf8()..];
            continue;
        }
        rest = &rest[1..];
        let escape = rest.chars().next().ok_or("R escape is truncated")?;
        rest = &rest[escape.len_utf8()..];
        match escape {
            'a' => text.push('\u{7}'),
            'b' => text.push('\u{8}'),
            'f' => text.push('\u{c}'),
            'n' => text.push('\n'),
            'r' => text.push('\r'),
            't' => text.push('\t'),
            'v' => text.push('\u{b}'),
            '\\' | '"' | '\'' | '`' => text.push(escape),
            'x' => text.push(decode(
                &take_accepted_chars(&mut rest, 2, |c| c.is_ascii_hexdigit()),
                16,
            )?),
            'u' | 'U' => {
                let width = if escape == 'u' { 4 } else { 8 };
                let digits = match rest.strip_prefix('{') {
                    Some(braced) => {
                        let (digits, tail) = braced
                            .split_once('}')
                            .ok_or("R code point escape is truncated")?;
                        rest = tail;
                        digits.to_string()
                    }
                    None => take_accepted_chars(&mut rest, width, |c| c.is_ascii_hexdigit()),
                };
                text.push(decode(&digits, 16)?);
            }
            digit if digit.is_digit(8) => {
                let mut digits = digit.to_string();
                digits.push_str(&take_accepted_chars(&mut rest, 2, |c| c.is_digit(8)));
                text.push(decode(&digits, 8)?);
            }
            other => return Err(format!("R escape \\{other} is not modeled")),
        }
    }
    Ok(text)
}

fn decode(digits: &str, radix: u32) -> Result<char, String> {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .ok_or_else(|| format!("R escape {digits:?} is not a character"))
}
