//! Swift's literal inline grammar for `swift -e`. A program is accepted only
//! when every statement is `import Foundation` or a `FileManager.default` file
//! call whose path arguments are string literals, `NSHomeDirectory()`, or `+`
//! concatenations of those. The throwing calls must be marked `try`, `try?` or
//! `try!`, and every FileManager call must follow `import Foundation`.
//!
//! Swift declarations are visible to the whole file, so a later
//! `class FileManager`, `func NSHomeDirectory()` or any other statement outside
//! the grammar could change what an earlier call means. The program is
//! therefore parsed completely before any effect is emitted, and one statement
//! outside the grammar withholds every effect behind one typed boundary.
//! Closures, `removeItem(at: URL)` and `Process()` are outside the grammar.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity, filesystem_path,
};

use super::source_text::{drive_letter_platform, elide_detail};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::Nest;
use crate::resource_transfer::TransferBinding;

/// Domains this frontend models. Anything outside them stays unclaimed.
const DOMAINS: [&str; 3] = ["environment", "filesystem", "process"];

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
    let calls = match program(source) {
        Ok(calls) => calls,
        Err(detail) => {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unsupported,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(detail),
            });
            return;
        }
    };
    let mut walk = Walk { nest, cwd, node };
    for call in &calls {
        walk.apply(builder, call);
    }
    for domain in DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
}

struct Walk<'a> {
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    node: ProvenanceRef,
}

impl Walk<'_> {
    fn apply(&mut self, builder: &mut PlanBuilder, call: &Call) {
        match call {
            // `removeItem` deletes a directory together with its contents.
            Call::Remove(path) => {
                self.effect(
                    builder,
                    "filesystem.delete",
                    path,
                    &[("recursive", true)],
                    None,
                );
            }
            Call::Move(from, to) => {
                self.effect(builder, "filesystem.move", from, &[], None);
                let source = self.effect(builder, "filesystem.delete", from, &[], None);
                let destination = self.effect(
                    builder,
                    "filesystem.write",
                    to,
                    &[],
                    Some(("disclosure", "contents")),
                );
                self.transfer(builder, source, destination);
            }
            Call::Copy(from, to) => {
                let source = self.effect(
                    builder,
                    "filesystem.read",
                    from,
                    &[],
                    Some(("access_purpose", "program_input")),
                );
                let destination = self.effect(
                    builder,
                    "filesystem.write",
                    to,
                    &[],
                    Some(("disclosure", "contents")),
                );
                self.transfer(builder, source, destination);
            }
            Call::CreateFile(path) => {
                self.effect(builder, "filesystem.write", path, &[], None);
            }
            Call::CreateDirectory(path) => {
                self.effect(builder, "filesystem.create", path, &[], None);
            }
        }
    }

    /// A move or copy carries the source's contents to the destination.
    fn transfer(
        &mut self,
        builder: &mut PlanBuilder,
        source: Option<u32>,
        destination: Option<u32>,
    ) {
        if let (Some(source), Some(destination)) = (source, destination) {
            builder.transfer_binding(TransferBinding::exact(source, destination));
        }
    }

    fn effect(
        &mut self,
        builder: &mut PlanBuilder,
        operation: &str,
        value: &[Part],
        attributes: &[(&str, bool)],
        semantic_attribute: Option<(&str, &str)>,
    ) -> Option<u32> {
        let resource = self.resource(builder, value);
        let mut attributes = attributes
            .iter()
            .map(|(name, value)| ((*name).to_string(), AttrValue::Bool(*value)))
            .collect::<std::collections::BTreeMap<_, _>>();
        if let Some((name, value)) = semantic_attribute {
            attributes.insert(name.into(), AttrValue::String(value.into()));
        }
        builder.effect(Effect {
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
        })
    }

    fn resource(&mut self, builder: &mut PlanBuilder, value: &[Part]) -> ResourceExpr {
        let mut parts = Vec::new();
        for part in value {
            match part {
                Part::Text(literal) => parts.push(ResourceExpr::Literal {
                    value: literal.clone(),
                }),
                Part::Home => parts.push(self.home(builder).unwrap_or(ResourceExpr::Environment {
                    name: "HOME".into(),
                })),
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
            Some(path) => {
                let platform = drive_letter_platform(&path, self.cwd);
                filesystem_path(
                    &path,
                    self.cwd.map(|cwd| filesystem_path(cwd, None, platform)),
                    platform,
                )
            }
            None => ResourceExpr::Join { parts },
        }
    }

    /// `NSHomeDirectory()` reads HOME whatever it resolves to.
    fn home(&mut self, builder: &mut PlanBuilder) -> Option<ResourceExpr> {
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: "HOME".into(),
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
        self.nest.environment_value("HOME")
    }
}

/// A modeled `FileManager.default` call with its path operands.
enum Call {
    Remove(Vec<Part>),
    Move(Vec<Part>, Vec<Part>),
    Copy(Vec<Part>, Vec<Part>),
    CreateFile(Vec<Part>),
    CreateDirectory(Vec<Part>),
}

enum Part {
    Text(String),
    Home,
}

/// Parse the whole program, or name the first statement outside the grammar.
fn program(source: &str) -> Result<Vec<Call>, String> {
    let mut foundation = false;
    let mut calls = Vec::new();
    for statement in statements(source)? {
        let statement = statement.trim();
        if statement == "import Foundation" {
            foundation = true;
            continue;
        }
        let (tried, rest) = match statement.split_once(char::is_whitespace) {
            Some(("try" | "try?" | "try!", rest)) => (true, rest.trim_start()),
            _ => (false, statement),
        };
        let Some(rest) = rest.strip_prefix("FileManager.default.") else {
            return Err(format!(
                "swift statement {:?} is outside the literal grammar",
                elide_detail(statement)
            ));
        };
        if !foundation {
            return Err("swift FileManager is used before import Foundation".into());
        }
        let open = rest
            .find('(')
            .ok_or("swift FileManager member is not a call")?;
        let method = &rest[..open];
        let (arguments, tail) = balanced(&rest[open..])?;
        if !tail.trim().is_empty() {
            return Err(format!(
                "swift call tail {:?} is outside the literal grammar",
                elide_detail(tail)
            ));
        }
        let arguments = labeled(arguments)?;
        let labels = arguments
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>();
        // Only `createFile` does not throw; Swift rejects an unmarked throwing call.
        let throws = method != "createFile";
        if throws && !tried {
            return Err(format!("swift throwing call {method} is not marked try"));
        }
        let call = match (method, labels.as_slice()) {
            ("removeItem", ["atPath"]) => Call::Remove(value(&arguments[0].1)?),
            ("moveItem", ["atPath", "toPath"]) => {
                Call::Move(value(&arguments[0].1)?, value(&arguments[1].1)?)
            }
            ("copyItem", ["atPath", "toPath"]) => {
                Call::Copy(value(&arguments[0].1)?, value(&arguments[1].1)?)
            }
            ("createFile", ["atPath", "contents"] | ["atPath", "contents", "attributes"])
                if arguments[1..].iter().all(|(_, value)| value == "nil") =>
            {
                Call::CreateFile(value(&arguments[0].1)?)
            }
            (
                "createDirectory",
                ["atPath", "withIntermediateDirectories"]
                | ["atPath", "withIntermediateDirectories", "attributes"],
            ) if matches!(arguments[1].1.as_str(), "true" | "false")
                && arguments.get(2).is_none_or(|(_, value)| value == "nil") =>
            {
                Call::CreateDirectory(value(&arguments[0].1)?)
            }
            _ => {
                return Err(format!(
                    "swift FileManager.{method}({}) is not modeled",
                    labels
                        .iter()
                        .map(|label| format!("{label}:"))
                        .collect::<String>()
                ));
            }
        };
        calls.push(call);
    }
    Ok(calls)
}

/// Split a program into statements on top-level newlines and `;`, dropping
/// `//` and nestable `/* */` comments.
fn statements(source: &str) -> Result<Vec<String>, String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut rest = source;
    let mut depth = 0u32;
    while let Some(character) = rest.chars().next() {
        if rest.starts_with("//") {
            rest = &rest[rest.find('\n').unwrap_or(rest.len())..];
            continue;
        }
        if rest.starts_with("/*") {
            rest = block_comment(rest)?;
            current.push(' ');
            continue;
        }
        if character == '"' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1).ok_or("swift program is unbalanced")?,
            _ => {}
        }
        if depth == 0 && (character == ';' || character == '\n') {
            statements.push(std::mem::take(&mut current));
            rest = &rest[1..];
            continue;
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    if depth != 0 {
        return Err("swift program is unbalanced".into());
    }
    statements.push(current);
    Ok(statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect())
}

/// The source after a nestable `/* ... */` comment.
fn block_comment(source: &str) -> Result<&str, String> {
    let mut depth = 0u32;
    let mut index = 0usize;
    while index < source.len() {
        if source[index..].starts_with("/*") {
            depth += 1;
            index += 2;
        } else if source[index..].starts_with("*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return Ok(&source[index..]);
            }
        } else {
            index += source[index..].chars().next().unwrap().len_utf8();
        }
    }
    Err("swift block comment is unterminated".into())
}

/// Consume one `"..."` string literal. Multiline and raw strings are refused.
fn quoted(source: &str) -> Result<(&str, &str), String> {
    if source.starts_with("\"\"\"") {
        return Err("swift multiline strings are not modeled".into());
    }
    let bytes = source.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Ok((&source[..index + 1], &source[index + 1..])),
            b'\n' => break,
            _ => index += 1,
        }
    }
    Err("swift string literal is unterminated".into())
}

fn balanced(source: &str) -> Result<(&str, &str), String> {
    let mut depth = 0u32;
    let mut rest = source;
    let mut index = 0;
    while let Some(character) = rest.chars().next() {
        if character == '"' {
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
    Err("swift call is unbalanced".into())
}

/// Split an argument list into `label: value` pairs. Swift argument labels are
/// case-sensitive, so they are kept exactly as written.
fn labeled(source: &str) -> Result<Vec<(String, String)>, String> {
    let mut arguments = Vec::new();
    for argument in split(source, ',')? {
        let (label, value) = argument
            .split_once(':')
            .ok_or("swift argument has no label")?;
        let label = label.trim();
        if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err("swift argument label is not an identifier".into());
        }
        arguments.push((label.to_string(), value.trim().to_string()));
    }
    Ok(arguments)
}

/// Split on a top-level separator outside strings and brackets.
fn split(source: &str, separator: char) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    let mut rest = source;
    while let Some(character) = rest.chars().next() {
        if character == '"' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ if character == separator && depth == 0 => {
                parts.push(std::mem::take(&mut current));
                rest = &rest[1..];
                continue;
            }
            _ => {}
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    if !current.trim().is_empty() || !parts.is_empty() {
        parts.push(current);
    }
    Ok(parts)
}

/// A path value is a `+` concatenation of string literals and
/// `NSHomeDirectory()`.
fn value(source: &str) -> Result<Vec<Part>, String> {
    let mut parts = Vec::new();
    for term in split(source, '+')? {
        let term = term.trim();
        if term == "NSHomeDirectory()" {
            parts.push(Part::Home);
        } else if term.starts_with('"') {
            parts.push(Part::Text(unescape(term)?));
        } else {
            return Err(format!(
                "swift value {:?} is outside the literal expression grammar",
                elide_detail(term)
            ));
        }
    }
    if parts
        .iter()
        .all(|part| matches!(part, Part::Text(text) if text.is_empty()))
    {
        return Err("swift path is empty".into());
    }
    Ok(parts)
}

/// Decode one Swift string literal. Interpolation `\(...)` is refused.
fn unescape(literal: &str) -> Result<String, String> {
    let body = literal
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or("swift string literal is unterminated")?;
    let mut text = String::new();
    let mut rest = body;
    while let Some(character) = rest.chars().next() {
        rest = &rest[character.len_utf8()..];
        if character != '\\' {
            text.push(character);
            continue;
        }
        let escape = rest.chars().next().ok_or("swift escape is truncated")?;
        rest = &rest[escape.len_utf8()..];
        match escape {
            '0' => text.push('\0'),
            'n' => text.push('\n'),
            'r' => text.push('\r'),
            't' => text.push('\t'),
            '\\' | '"' | '\'' => text.push(escape),
            'u' => {
                let (digits, tail) = rest
                    .strip_prefix('{')
                    .and_then(|braced| braced.split_once('}'))
                    .ok_or("swift unicode escape is truncated")?;
                rest = tail;
                text.push(
                    u32::from_str_radix(digits, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .ok_or("swift unicode escape is not a character")?,
                );
            }
            '(' => return Err("swift string interpolation is not modeled".into()),
            other => return Err(format!("swift escape \\{other} is not modeled")),
        }
    }
    Ok(text)
}
