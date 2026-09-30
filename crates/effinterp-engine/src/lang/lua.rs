//! Lua's literal inline grammar. A chunk is accepted only when it is a
//! straight-line sequence of standard-library calls whose arguments are
//! recoverable string literals, environment reads, or concatenations of those,
//! plus `name = {}` replacements of a global and `function name(params) ...
//! end` definitions, whose bodies are walked where they are called with their
//! parameters bound to the call's arguments.
//! Every other construct — a branch, a binding, a call through a value — ends
//! the walk in one typed boundary naming it.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity, filesystem_path,
};

use super::source_text::{drive_letter_platform, elide_detail, nest_shell, take_accepted_chars};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::Nest;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Chunks reached through `load`/`loadstring` nest at most this deep.
const MAX_LOAD_DEPTH: u32 = 4;

/// Domains this frontend models. Anything outside them stays unclaimed.
const DOMAINS: [&str; 3] = ["environment", "filesystem", "process"];

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
    let mut walk = Walk {
        nest,
        cwd,
        node,
        depth,
        globals: Default::default(),
        locals: Vec::new(),
        functions: Vec::new(),
        values: Vec::new(),
        understood: true,
    };
    walk.chunk(builder, source, 0);
    // A body no call reached is not analyzed, as in the other frontends.
    let uncalled = walk
        .functions
        .iter()
        .filter(|function| !function.called)
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();
    for name in uncalled {
        walk.boundary(
            builder,
            format!("lua function {name} is never called, so its body is not analyzed"),
        );
    }
    if walk.understood {
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

struct Walk<'a> {
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    node: ProvenanceRef,
    depth: u64,
    /// Global names a definition or `name = {}` bound. A replaced name no
    /// longer reaches the standard library; earlier calls already did.
    globals: Frame,
    /// The locals visible here, one frame per declaration, innermost last.
    /// A function's body sees the frames visible where it was defined, shared
    /// as Lua upvalues are, so a later assignment to one reaches the body.
    locals: Vec<Frame>,
    /// Every function defined so far.
    functions: Vec<Function>,
    /// Every argument value bound to a parameter so far.
    values: Vec<Value>,
    understood: bool,
}

type Frame = Rc<RefCell<BTreeMap<String, Binding>>>;

#[derive(Clone, Copy)]
enum Binding {
    /// An index into [`Walk::functions`].
    Function(usize),
    /// Replaced by an empty table.
    Replaced,
    /// A parameter; an index into [`Walk::values`].
    Value(usize),
}

struct Function {
    name: String,
    params: Vec<String>,
    body: String,
    /// The local frames visible at the definition.
    captured: Vec<Frame>,
    called: bool,
}

impl Walk<'_> {
    /// Walk a straight-line chunk. Stops at the first construct outside the
    /// grammar so no statement after an unexplained one is claimed. Returns
    /// whether the chunk ran to its end.
    fn chunk(&mut self, builder: &mut PlanBuilder, source: &str, depth: u32) -> bool {
        let statements = match statements(source) {
            Ok(statements) => statements,
            Err(detail) => {
                self.boundary(builder, detail);
                return false;
            }
        };
        for statement in statements {
            if self.nest.budget.timed_out() {
                builder.note_deadline();
                return false;
            }
            if let Some((local, name)) = replacement(&statement) {
                self.bind(local, name, Binding::Replaced);
                continue;
            }
            // A definition rebinds the name, so later calls reach its body.
            if let Some((local, name, params, body)) = definition(&statement) {
                let index = self.functions.len();
                self.bind(local, name, Binding::Function(index));
                self.functions.push(Function {
                    name: name.to_string(),
                    params,
                    body: body.to_string(),
                    captured: self.locals.clone(),
                    called: false,
                });
                continue;
            }
            let applied = call(&statement).and_then(|call| self.apply(builder, &call, depth));
            match applied {
                Ok(true) => {}
                // The nested walk already recorded why it stopped.
                Ok(false) => return false,
                Err(detail) => {
                    self.boundary(builder, detail);
                    return false;
                }
            }
        }
        true
    }

    /// A `local` declaration opens a new frame that ends with its block.
    /// Any other binding assigns the innermost visible local of that name, or
    /// else the global.
    fn bind(&mut self, local: bool, name: &str, binding: Binding) {
        let declared = BTreeMap::from([(name.to_string(), binding)]);
        if local {
            self.locals.push(Rc::new(RefCell::new(declared)));
            return;
        }
        let frame = self
            .locals
            .iter()
            .rev()
            .find(|frame| frame.borrow().contains_key(name))
            .unwrap_or(&self.globals);
        frame.borrow_mut().extend(declared);
    }

    fn lookup(&self, name: &str) -> Option<Binding> {
        self.locals
            .iter()
            .rev()
            .chain(std::iter::once(&self.globals))
            .find_map(|frame| frame.borrow().get(name).copied())
    }

    /// Walk `source` as a block seeing the locals `scopes`, then restore the
    /// caller's, dropping every local the block declared.
    fn walk_block(
        &mut self,
        builder: &mut PlanBuilder,
        source: &str,
        scopes: Vec<Frame>,
        depth: u32,
    ) -> bool {
        let caller = std::mem::replace(&mut self.locals, scopes);
        let completed = self.chunk(builder, source, depth);
        self.locals = caller;
        completed
    }

    /// Apply one call. Returns whether it returned; a nested body that
    /// stopped has recorded its own boundary.
    fn apply(
        &mut self,
        builder: &mut PlanBuilder,
        call: &Call,
        depth: u32,
    ) -> Result<bool, String> {
        let call = &Call {
            callee: call.callee.clone(),
            arguments: call
                .arguments
                .iter()
                .map(|argument| self.close(argument))
                .collect::<Result<_, _>>()?,
            invoked: call.invoked,
        };
        let root = call.callee.split('.').next().unwrap_or_default();
        match self.lookup(root) {
            Some(Binding::Replaced) => {
                return Err(format!("lua global {root} was replaced before this call"));
            }
            Some(Binding::Value(_)) => {
                return Err(format!("lua call through parameter {root} is not modeled"));
            }
            Some(Binding::Function(index)) => {
                if call.callee != root
                    || call.arguments.len() != self.functions[index].params.len()
                    || call.invoked
                {
                    return Err(format!(
                        "lua call through function {root} is outside the literal grammar"
                    ));
                }
                if depth >= MAX_LOAD_DEPTH {
                    return Err("lua function call nesting limit reached".into());
                }
                let function = &mut self.functions[index];
                function.called = true;
                let (params, body, mut scopes) = (
                    function.params.clone(),
                    function.body.clone(),
                    function.captured.clone(),
                );
                // Each call binds its parameters as fresh locals of the body.
                let mut frame = BTreeMap::new();
                for (param, argument) in params.into_iter().zip(&call.arguments) {
                    frame.insert(param, Binding::Value(self.values.len()));
                    self.values.push(Value(argument.0.clone()));
                }
                scopes.push(Rc::new(RefCell::new(frame)));
                return Ok(self.walk_block(builder, &body, scopes, depth + 1));
            }
            None => {}
        }
        if matches!(call.callee.as_str(), "load" | "loadstring")
            && call.arguments.len() == 1
            && call.invoked
        {
            let Some(source) = self.text(builder, &call.arguments[0]) else {
                return Err("lua load chunk is not a recoverable string".into());
            };
            if depth >= MAX_LOAD_DEPTH {
                return Err("lua load nesting limit reached".into());
            }
            // A loaded chunk sees globals only, not the caller's locals.
            return Ok(self.walk_block(builder, &source, Vec::new(), depth + 1));
        }
        self.library(builder, call).map(|()| true)
    }

    /// Apply a standard-library call.
    fn library(&mut self, builder: &mut PlanBuilder, call: &Call) -> Result<(), String> {
        match (call.callee.as_str(), call.arguments.len()) {
            ("os.execute", 1) | ("io.popen", 1 | 2) => {
                let Some(command) = self.text(builder, &call.arguments[0]) else {
                    return Err(format!(
                        "lua {} command is not a recoverable string",
                        call.callee
                    ));
                };
                let mut captured = call.callee == "io.popen";
                if let Some(mode) = call.arguments.get(1) {
                    let mode = self.text(builder, mode);
                    if !matches!(mode.as_deref(), Some("r" | "w")) {
                        return Err("lua io.popen mode is not modeled".into());
                    }
                    // A "w" pipe feeds the child's stdin; its stdout stays inherited.
                    captured = mode.as_deref() == Some("r");
                }
                nest_shell(
                    builder, self.nest, command, self.cwd, self.node, self.depth, captured,
                );
                Ok(())
            }
            ("os.remove", 1) => self.effect(builder, "filesystem.delete", &call.arguments[0], &[]),
            ("os.rename", 2) => {
                self.effect(builder, "filesystem.move", &call.arguments[0], &[])?;
                self.effect(builder, "filesystem.delete", &call.arguments[0], &[])?;
                self.effect(builder, "filesystem.write", &call.arguments[1], &[])
            }
            ("io.lines" | "io.input", 1) => {
                self.effect(builder, "filesystem.read", &call.arguments[0], &[])
            }
            ("io.output", 1) => self.effect(builder, "filesystem.write", &call.arguments[0], &[]),
            ("io.open", 1) => self.effect(builder, "filesystem.read", &call.arguments[0], &[]),
            ("io.open", 2) => {
                let Some(mode) = self.text(builder, &call.arguments[1]) else {
                    return Err("lua io.open mode is not a recoverable string".into());
                };
                let mode = mode.trim_end_matches('b');
                let update = mode.ends_with('+');
                let path = &call.arguments[0];
                match mode.trim_end_matches('+') {
                    "r" => {
                        self.effect(builder, "filesystem.read", path, &[])?;
                        if update {
                            self.effect(builder, "filesystem.write", path, &[])?;
                        }
                        Ok(())
                    }
                    "w" | "a" => {
                        let append = mode.starts_with('a');
                        self.effect(builder, "filesystem.write", path, &[("append", append)])?;
                        if update {
                            self.effect(builder, "filesystem.read", path, &[])?;
                        }
                        Ok(())
                    }
                    _ => Err(format!("lua io.open mode {mode:?} is not modeled")),
                }
            }
            // Writes to the default output file reach stdout, not a path.
            ("print" | "io.write" | "io.read" | "os.exit" | "os.time" | "os.clock", _) => Ok(()),
            (callee, count) => Err(format!(
                "lua call to {callee} with {count} arguments is outside the literal grammar"
            )),
        }
    }

    fn effect(
        &mut self,
        builder: &mut PlanBuilder,
        operation: &str,
        value: &Value,
        attributes: &[(&str, bool)],
    ) -> Result<(), String> {
        let Some(resource) = self.resource(builder, value) else {
            return Err("lua path argument is not a recoverable string".into());
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

    /// `value` with each parameter name replaced by the argument it is bound
    /// to here, so it no longer depends on the scope.
    fn close(&self, value: &Value) -> Result<Value, String> {
        let mut parts = Vec::new();
        for part in &value.0 {
            match part {
                Part::Name(name) => match self.lookup(name) {
                    Some(Binding::Value(index)) => parts.extend(self.values[index].0.clone()),
                    _ => return Err(format!("lua name {name} is not a bound parameter")),
                },
                part => parts.push(part.clone()),
            }
        }
        Ok(Value(parts))
    }

    /// Fully literal text, with every environment read recorded.
    fn text(&mut self, builder: &mut PlanBuilder, value: &Value) -> Option<String> {
        let mut text = String::new();
        for part in &value.0 {
            match part {
                Part::Text(literal) => text.push_str(literal),
                Part::Env(name) => match self.env(builder, name) {
                    Some(ResourceExpr::Literal { value }) => text.push_str(&value),
                    _ => return None,
                },
                // Closed by `apply` before any value is used.
                Part::Name(_) => return None,
            }
        }
        Some(text)
    }

    /// A path resource: concrete when every part resolves, symbolic otherwise.
    fn resource(&mut self, builder: &mut PlanBuilder, value: &Value) -> Option<ResourceExpr> {
        let mut parts = Vec::new();
        for part in &value.0 {
            match part {
                Part::Text(literal) => parts.push(ResourceExpr::Literal {
                    value: literal.clone(),
                }),
                Part::Env(name) => parts.push(
                    self.env(builder, name)
                        .unwrap_or(ResourceExpr::Environment { name: name.clone() }),
                ),
                Part::Name(_) => return None,
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

    /// `os.getenv` is an environment read whatever the value resolves to.
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

struct Call {
    callee: String,
    arguments: Vec<Value>,
    /// `load("...")()` calls the compiled chunk immediately.
    invoked: bool,
}

struct Value(Vec<Part>);

#[derive(Clone)]
enum Part {
    Text(String),
    Env(String),
    /// A name, which must be a parameter bound where the value is used.
    Name(String),
}

/// Split a chunk into statements. Only straight-line code is accepted: a
/// keyword, an assignment, or an unbalanced delimiter ends the grammar. A
/// function definition is kept whole, through its matching `end`.
fn statements(source: &str) -> Result<Vec<String>, String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut rest = source;
    let mut depth = 0u32;
    while let Some(character) = rest.chars().next() {
        if depth == 0
            && current.trim().is_empty()
            && let Some(length) = function_block_len(rest)?
        {
            current.clear();
            statements.push(rest[..length].to_string());
            rest = &rest[length..];
            continue;
        }
        if character == '-' && rest.starts_with("--") {
            if let Some((_, tail)) = long_bracket(&rest[2..])? {
                rest = tail;
            } else {
                let end = rest.find('\n').unwrap_or(rest.len());
                rest = &rest[end..];
            }
            continue;
        }
        if character == '"' || character == '\'' {
            let (literal, tail) = quoted(rest)?;
            current.push_str(literal);
            rest = tail;
            continue;
        }
        if let Some((literal, tail)) = long_bracket(rest)? {
            current.push_str(literal);
            rest = tail;
            continue;
        }
        if character == '(' {
            depth += 1;
        }
        if character == ')' {
            depth = depth.checked_sub(1).ok_or("lua chunk is unbalanced")?;
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
        return Err("lua chunk is unbalanced".into());
    }
    statements.push(current);
    Ok(statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect())
}

/// Consume one quoted literal, returning its raw text and the remainder.
fn quoted(source: &str) -> Result<(&str, &str), String> {
    let quote = source.as_bytes()[0];
    let mut index = 1;
    let bytes = source.as_bytes();
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return Ok((&source[..index + 1], &source[index + 1..])),
            _ => index += 1,
        }
    }
    Err("lua string literal is unterminated".into())
}

/// Consume one Lua long-bracket literal (`[[...]]`, `[=[...]=]`, ...).
fn long_bracket(source: &str) -> Result<Option<(&str, &str)>, String> {
    let Some(after_open) = source.strip_prefix('[') else {
        return Ok(None);
    };
    let equals = after_open.bytes().take_while(|byte| *byte == b'=').count();
    if after_open.as_bytes().get(equals) != Some(&b'[') {
        return Ok(None);
    }
    let open_len = equals + 2;
    let close = format!("]{}]", "=".repeat(equals));
    let end = source[open_len..]
        .find(&close)
        .map(|offset| open_len + offset + close.len())
        .ok_or("lua long-bracket literal is unterminated")?;
    Ok(Some((&source[..end], &source[end..])))
}

fn long_string(literal: &str) -> Result<String, String> {
    let Some((whole, tail)) = long_bracket(literal)? else {
        return Err("lua long string literal is malformed".into());
    };
    if !tail.is_empty() || whole.len() != literal.len() {
        return Err("lua long string literal has trailing syntax".into());
    }
    let after_open = &literal[1..];
    let equals = after_open.bytes().take_while(|byte| *byte == b'=').count();
    let open_len = equals + 2;
    let close_len = equals + 2;
    let content = &literal[open_len..literal.len() - close_len];
    Ok(content
        .strip_prefix("\r\n")
        .or_else(|| content.strip_prefix('\n'))
        .unwrap_or(content)
        .to_string())
}

/// The byte length of a `[local] function ... end` block at the start of
/// `source`, found by matching Lua's block keywords outside strings and
/// comments. None when `source` does not start one.
fn function_block_len(source: &str) -> Result<Option<usize>, String> {
    let start = source
        .strip_prefix("local")
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .map_or(source, str::trim_start);
    let Some(after) = start.strip_prefix("function") else {
        return Ok(None);
    };
    if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
        return Ok(None);
    }
    let mut rest = after;
    let mut blocks = 1u32;
    while let Some(character) = rest.chars().next() {
        if rest.starts_with("--") {
            rest = match long_bracket(&rest[2..])? {
                Some((_, tail)) => tail,
                None => &rest[rest.find('\n').unwrap_or(rest.len())..],
            };
            continue;
        }
        if character == '"' || character == '\'' {
            rest = quoted(rest)?.1;
            continue;
        }
        if let Some((_, tail)) = long_bracket(rest)? {
            rest = tail;
            continue;
        }
        if character.is_ascii_alphabetic() || character == '_' {
            let word_len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            match &rest[..word_len] {
                "function" | "if" | "do" | "repeat" => blocks += 1,
                "end" | "until" => {
                    blocks -= 1;
                    if blocks == 0 {
                        return Ok(Some(source.len() - rest.len() + word_len));
                    }
                }
                _ => {}
            }
            rest = &rest[word_len..];
            continue;
        }
        rest = &rest[character.len_utf8()..];
    }
    Err("lua function definition has no matching end".into())
}

/// Whether a `[local] function name(params) ... end` definition is local,
/// with its name, parameter names and body.
fn definition(statement: &str) -> Option<(bool, &str, Vec<String>, &str)> {
    let statement = statement.trim();
    let local = statement
        .strip_prefix("local")
        .filter(|rest| rest.starts_with(char::is_whitespace));
    let statement = local.map_or(statement, str::trim_start);
    let rest = statement.strip_prefix("function")?.trim_start();
    let name_len = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, rest) = rest.split_at(name_len);
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let (params, body) = rest.trim_start().strip_prefix('(')?.split_once(')')?;
    let params = params
        .split(',')
        .map(str::trim)
        .filter(|param| !param.is_empty())
        .map(|param| is_name(param).then(|| param.to_string()))
        .collect::<Option<Vec<_>>>()?;
    Some((local.is_some(), name, params, body.strip_suffix("end")?))
}

/// A Lua name that is not a reserved word or a literal.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(|c: char| c.is_ascii_digit())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !matches!(
            text,
            "and"
                | "break"
                | "do"
                | "else"
                | "elseif"
                | "end"
                | "false"
                | "for"
                | "function"
                | "goto"
                | "if"
                | "in"
                | "local"
                | "nil"
                | "not"
                | "or"
                | "repeat"
                | "return"
                | "then"
                | "true"
                | "until"
                | "while"
        )
}

/// Whether a `[local] name = {}` statement is local, with the name it binds
/// to an empty table.
fn replacement(statement: &str) -> Option<(bool, &str)> {
    let statement = statement.trim();
    let local = statement.strip_prefix("local ");
    let statement = local.unwrap_or(statement);
    let (name, value) = statement.split_once('=')?;
    let name = name.trim();
    (value.trim() == "{}"
        && !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit()))
    .then_some((local.is_some(), name))
}

/// Parse one statement as `name(arguments)` or `load(argument)()`.
fn call(statement: &str) -> Result<Call, String> {
    let statement = statement.trim();
    let open = statement.find('(').ok_or("lua statement is not a call")?;
    let callee = statement[..open].trim();
    if callee.is_empty()
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        || callee.starts_with(|c: char| c.is_ascii_digit())
        || callee.split('.').any(str::is_empty)
    {
        return Err(format!(
            "lua statement {:?} is outside the literal call grammar",
            elide_detail(statement)
        ));
    }
    let (arguments, rest) = balanced(&statement[open..])?;
    let invoked = match rest.trim() {
        "" => false,
        "()" => true,
        _ => {
            return Err(format!(
                "lua call tail {:?} is outside the literal call grammar",
                elide_detail(rest)
            ));
        }
    };
    Ok(Call {
        callee: callee.to_string(),
        arguments: split(arguments)?
            .iter()
            .map(|argument| value(argument))
            .collect::<Result<Vec<_>, _>>()?,
        invoked,
    })
}

/// Text inside the leading parenthesis, plus everything after its match.
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
        if let Some((literal, tail)) = long_bracket(rest)? {
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
    Err("lua call is unbalanced".into())
}

/// Split an argument list on top-level commas.
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
        if let Some((literal, tail)) = long_bracket(rest)? {
            current.push_str(literal);
            rest = tail;
            continue;
        }
        match character {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth = depth.saturating_sub(1),
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

/// A value is a `..` concatenation of string literals, `os.getenv` reads and
/// names.
fn value(source: &str) -> Result<Value, String> {
    let mut parts = Vec::new();
    for term in concatenation(source)? {
        let term = term.trim();
        if term.starts_with('"') || term.starts_with('\'') {
            parts.push(Part::Text(unescape(term)?));
            continue;
        }
        if term.starts_with('[') {
            parts.push(Part::Text(long_string(term)?));
            continue;
        }
        if is_name(term) {
            parts.push(Part::Name(term.to_string()));
            continue;
        }
        let name = term
            .strip_prefix("os.getenv")
            .map(str::trim_start)
            .filter(|rest| rest.starts_with('('))
            .ok_or_else(|| {
                format!(
                    "lua value {:?} is outside the literal expression grammar",
                    elide_detail(term)
                )
            })?;
        let (inner, rest) = balanced(name)?;
        if !rest.trim().is_empty() {
            return Err("lua os.getenv call tail is not modeled".into());
        }
        let inner = inner.trim();
        if !(inner.starts_with('"') || inner.starts_with('\'')) {
            return Err("lua os.getenv name is not a literal".into());
        }
        parts.push(Part::Env(unescape(inner)?));
    }
    if parts.is_empty() {
        return Err("lua value is empty".into());
    }
    Ok(Value(parts))
}

/// Split one value on top-level `..` concatenation operators.
fn concatenation(source: &str) -> Result<Vec<String>, String> {
    let mut terms = Vec::new();
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
        if let Some((literal, tail)) = long_bracket(rest)? {
            current.push_str(literal);
            rest = tail;
            continue;
        }
        if depth == 0 && rest.starts_with("..") && !rest.starts_with("...") {
            terms.push(std::mem::take(&mut current));
            rest = &rest[2..];
            continue;
        }
        match character {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        current.push(character);
        rest = &rest[character.len_utf8()..];
    }
    terms.push(current);
    Ok(terms)
}

/// Decode one Lua short string literal. Lua numeric escapes are decimal
/// (`\ddd`) and hexadecimal (`\xhh`); `\u{h...}` is a code point.
fn unescape(literal: &str) -> Result<String, String> {
    let quote = literal.as_bytes()[0];
    let body = literal
        .strip_prefix(quote as char)
        .and_then(|rest| rest.strip_suffix(quote as char))
        .ok_or("lua string literal is unterminated")?;
    let mut text = String::new();
    let mut rest = body;
    while let Some(character) = rest.chars().next() {
        if character != '\\' {
            text.push(character);
            rest = &rest[character.len_utf8()..];
            continue;
        }
        rest = &rest[1..];
        let escape = rest.chars().next().ok_or("lua escape is truncated")?;
        rest = &rest[escape.len_utf8()..];
        match escape {
            'a' => text.push('\u{7}'),
            'b' => text.push('\u{8}'),
            'f' => text.push('\u{c}'),
            'n' => text.push('\n'),
            'r' => text.push('\r'),
            't' => text.push('\t'),
            'v' => text.push('\u{b}'),
            '\\' | '"' | '\'' | '\n' => text.push(if escape == '\n' { '\n' } else { escape }),
            'x' => {
                let digits = take_accepted_chars(&mut rest, 2, |c| c.is_ascii_hexdigit());
                if digits.len() != 2 {
                    return Err("lua hexadecimal escape is truncated".into());
                }
                text.push(decode(&digits, 16)?);
            }
            'z' => rest = rest.trim_start(),
            'u' => {
                let inner = rest
                    .strip_prefix('{')
                    .and_then(|rest| rest.split_once('}'))
                    .ok_or("lua code point escape is truncated")?;
                text.push(decode(inner.0, 16)?);
                rest = inner.1;
            }
            digit if digit.is_ascii_digit() => {
                let mut digits = digit.to_string();
                digits.push_str(&take_accepted_chars(&mut rest, 2, |c| c.is_ascii_digit()));
                text.push(decode(&digits, 10)?);
            }
            other => return Err(format!("lua escape \\{other} is not modeled")),
        }
    }
    Ok(text)
}

fn decode(digits: &str, radix: u32) -> Result<char, String> {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .ok_or_else(|| format!("lua escape {digits:?} is not a character"))
}
