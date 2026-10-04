//! The Perl statement compiler: turns a token stream into the program's
//! pending steps in source order, tracking literal bindings, filehandles,
//! named subs, string `eval` and the values an HTTP::Tiny request carries.

use std::collections::{BTreeMap, BTreeSet};

use crate::resource_transfer::TransferBinding;

mod http_tiny;

use super::token_shapes::{
    brackets_balance, call_end, constant_operand, decodes_base64, is_filehandle, numeric_tokens,
    perl_literal_text, perl_number, refused_statement_is_inert, split_at_lowest_operator,
};
use super::tokenize::{PerlToken, tokenize};
use super::{PerlFailure, PerlImports};

/// One filesystem effect a compiled statement states, held until the whole
/// program compiles.
pub(super) struct PerlPendingEffect {
    pub(super) operation: &'static str,
    pub(super) path: String,
    pub(super) access_purpose: Option<&'static str>,
    pub(super) disclosure: Option<&'static str>,
    pub(super) action: Option<&'static str>,
    pub(super) recursive: bool,
    /// The permission grants a literal chmod mode sets.
    pub(super) grants: Vec<&'static str>,
}

impl PerlPendingEffect {
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
pub(super) enum PerlPendingStep {
    Effect(PerlPendingEffect),
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
    /// An HTTP::Tiny request to a literal URL.
    Request {
        operation: &'static str,
        url: String,
    },
    /// `eval`, `system` or `exec` of an HTTP response body: code the request
    /// received, run by this interpreter or, for `shell`, by a shell.
    RemoteCode {
        shell: bool,
    },
    /// `print` of the bytes the step at this slot read or received: they
    /// reach standard output.
    Output(u32),
    /// `do FILE` or `require FILE`: the file at this path is read and run as
    /// Perl.
    Load(String),
}

/// A value the grammar tracks besides literal text. A slot is the index of a
/// pending step.
#[derive(Clone, PartialEq)]
enum PerlObject {
    /// The `HTTP::Tiny` class name.
    Class,
    /// An `HTTP::Tiny` client.
    Client,
    /// The response to the request at this slot.
    Response(u32),
    /// A response's `{content}`: the bytes the request at this slot received.
    Content(u32),
    /// A filehandle opened for reading by the `filesystem.read` at this slot.
    Handle(u32),
    /// Bytes read from the file the `filesystem.read` at this slot opened.
    FileData(u32),
    /// A value whose contents the grammar does not follow, such as a
    /// response's status.
    Opaque,
}

/// The program's steps and transfers, and why each refused statement was refused.
type Compiled = (Vec<PerlPendingStep>, Vec<TransferBinding>, BTreeSet<String>);

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

/// One top-level statement: a named `sub` with its body, or any other
/// statement up to its `;`.
enum PerlStatement<'t> {
    Sub(&'t str, &'t [PerlToken]),
    Simple(&'t [PerlToken]),
}

/// Split tokens into `;`-terminated statements and named `sub NAME { ... }`
/// definitions. Any other brace stays inside its statement and is refused there.
fn statements(tokens: &[PerlToken]) -> Result<Vec<PerlStatement<'_>>, String> {
    let mut statements = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if let [
            PerlToken::Name(sub),
            PerlToken::Name(name),
            PerlToken::Punct('{'),
            ..,
        ] = &tokens[i..]
            && sub == "sub"
        {
            let close = i + 2 + matching_brace(&tokens[i + 2..])?;
            statements.push(PerlStatement::Sub(name, &tokens[i + 3..close]));
            i = close + 1;
            continue;
        }
        let mut depth = 0u32;
        let mut end = i;
        while end < tokens.len() {
            match tokens[end] {
                PerlToken::Punct('{') => depth += 1,
                PerlToken::Punct('}') => {
                    depth = depth.checked_sub(1).ok_or("Perl braces are unbalanced")?
                }
                PerlToken::Punct(';') if depth == 0 => break,
                _ => {}
            }
            end += 1;
        }
        if depth != 0 {
            return Err("Perl braces are unbalanced".into());
        }
        if end > i {
            statements.push(PerlStatement::Simple(&tokens[i..end]));
        }
        i = end + 1;
    }
    Ok(statements)
}

/// Index of the brace closing the one that opens `tokens`.
fn matching_brace(tokens: &[PerlToken]) -> Result<usize, String> {
    let mut depth = 0u32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            PerlToken::Punct('{') => depth += 1,
            PerlToken::Punct('}') => {
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
fn use_statement(tokens: &[PerlToken], imports: &mut PerlImports) -> Result<(), String> {
    let [PerlToken::Name(module), list @ ..] = tokens else {
        return Err("Perl use statement names no module".into());
    };
    if matches!(module.as_str(), "strict" | "warnings") && list.is_empty() {
        return Ok(());
    }
    if let [PerlToken::Words(words)] = list {
        let names = words.iter().map(String::as_str).collect::<Vec<_>>();
        return imports.import(module, Some(&names));
    }
    let list = match list {
        [PerlToken::Punct('('), inner @ .., PerlToken::Punct(')')] => inner,
        other => other,
    };
    if list.is_empty() {
        return imports.import(module, if tokens.len() == 1 { None } else { Some(&[]) });
    }
    let mut names = Vec::new();
    for token in list {
        match token {
            PerlToken::Name(name) | PerlToken::Text(name) => names.push(name.as_str()),
            PerlToken::Punct(',') => {}
            _ => return Err("Perl use import list is not a literal name list".into()),
        }
    }
    imports.import(module, Some(&names))
}

/// The Perl statement compiler and what it tracks across statements:
/// literal variable bindings, tracked values, named subs, and the pending
/// steps, transfers and refusals it has produced.
struct PerlCompiler<'a, 'e> {
    imports: PerlImports,
    budget: &'a crate::nest::Budget,
    max_bytes: usize,
    env: &'e mut dyn FnMut(&str) -> Option<String>,
    subs: BTreeMap<String, Vec<PerlToken>>,
    active_subs: BTreeSet<String>,
    variables: BTreeMap<String, String>,
    /// Variables bound to a tracked value rather than literal text.
    objects: BTreeMap<String, PerlObject>,
    pending: Vec<PerlPendingStep>,
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

/// Compile a tokenized Perl program. `stop` is the lexer's refusal, if lexing
/// ended early; `env` reads one host environment variable.
pub(super) fn compile_perl_program(
    tokens: &[PerlToken],
    stop: Option<String>,
    imports: &PerlImports,
    budget: &crate::nest::Budget,
    max_bytes: usize,
    env: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Compiled, PerlFailure> {
    let mut compiler = PerlCompiler {
        imports: imports.clone(),
        budget,
        max_bytes,
        env,
        subs: BTreeMap::new(),
        active_subs: BTreeSet::new(),
        variables: BTreeMap::new(),
        objects: BTreeMap::new(),
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

impl PerlCompiler<'_, '_> {
    /// Compile one unit (the program or an `eval` string). Named subs and `use`
    /// imports take effect at compile time, before any statement runs.
    fn unit(&mut self, tokens: &[PerlToken]) -> Result<(), PerlFailure> {
        let statements = statements(tokens)?;
        for statement in &statements {
            match statement {
                PerlStatement::Sub(name, body) => {
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
                PerlStatement::Simple([PerlToken::Name(keyword), rest @ ..])
                    if keyword == "use" =>
                {
                    use_statement(rest, &mut self.imports)?;
                }
                // `no` unimports at compile time; only pragmas are known inert.
                PerlStatement::Simple([PerlToken::Name(keyword), rest @ ..]) if keyword == "no" => {
                    if !matches!(rest, [PerlToken::Name(pragma)] if matches!(pragma.as_str(), "strict" | "warnings"))
                    {
                        return Err(
                            "Perl no statement is outside the bounded literal grammar".into()
                        );
                    }
                }
                PerlStatement::Simple(_) => {}
            }
        }
        for statement in statements {
            match statement {
                PerlStatement::Simple([PerlToken::Name(keyword), ..])
                    if matches!(keyword.as_str(), "use" | "no") => {}
                PerlStatement::Simple(statement) => self.run(statement)?,
                PerlStatement::Sub(..) => {}
            }
        }
        Ok(())
    }

    /// Compile one statement. A refused statement publishes nothing itself and
    /// leaves a boundary; the statements before it keep their effects. Only a
    /// statement that cannot change later facts lets compilation continue.
    fn run(&mut self, statement: &[PerlToken]) -> Result<(), PerlFailure> {
        if self.halted {
            return Ok(());
        }
        match self.statement(statement) {
            Err(PerlFailure::Refused(detail)) => {
                self.refusals.insert(detail);
                self.halted = !refused_statement_is_inert(statement, self.conditional > 0);
                Ok(())
            }
            result => result,
        }
    }

    /// Compile an operand that may not run: a variable it binds has no known
    /// value afterwards.
    fn maybe(&mut self, tokens: &[PerlToken]) -> Result<(), PerlFailure> {
        let outer = (self.variables.clone(), self.objects.clone());
        self.conditional += 1;
        let result = self.run(tokens);
        self.conditional -= 1;
        self.restore_bindings(outer);
        result
    }

    /// Return to the bindings held before code that may not have run, keeping
    /// only those it left unchanged.
    fn restore_bindings(
        &mut self,
        outer: (BTreeMap<String, String>, BTreeMap<String, PerlObject>),
    ) {
        let variables = std::mem::replace(&mut self.variables, outer.0);
        self.variables
            .retain(|name, value| variables.get(name) == Some(value));
        let objects = std::mem::replace(&mut self.objects, outer.1);
        self.objects
            .retain(|name, value| objects.get(name) == Some(value));
    }

    /// `left OPERATOR right`: the first operand always runs, and the other
    /// runs unless a constant first operand rules it out. Both `xor` operands run.
    fn logical(
        &mut self,
        left: &[PerlToken],
        operator: &str,
        right: &[PerlToken],
    ) -> Result<(), PerlFailure> {
        if self.nesting >= MAX_NESTING {
            return Err("Perl operator chain nests too deeply to model".into());
        }
        self.nesting += 1;
        let result = self.operands(left, operator, right);
        self.nesting -= 1;
        result
    }

    /// Compile `left OPERATOR right` or a statement modifier in evaluation
    /// order. A constant first operand decides whether the other runs at all;
    /// otherwise the other operand may not run.
    fn operands(
        &mut self,
        left: &[PerlToken],
        operator: &str,
        right: &[PerlToken],
    ) -> Result<(), PerlFailure> {
        // A statement modifier evaluates its condition first.
        let (first, then) = if matches!(operator, "if" | "unless") {
            (right, left)
        } else {
            (left, right)
        };
        if operator == "xor" {
            if constant_operand(first).is_none() {
                self.run(first)?;
            }
            return self.run(then);
        }
        let Some((defined, truth)) = constant_operand(first) else {
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

    /// Compile one simple statement: charge the step budget, fold constants,
    /// split logical operators and statement modifiers, then model the
    /// builtin, module call or tracked value the statement names.
    fn statement(&mut self, statement: &[PerlToken]) -> Result<(), PerlFailure> {
        if !self.budget.try_charge_steps(statement.len() as u64) {
            return Err(PerlFailure::AnalysisSteps);
        }
        // A constant expression, including a short-circuit chain that stops
        // at a constant, does nothing.
        if constant_operand(statement).is_some() {
            return Ok(());
        }
        if let Some((left, operator, right)) = split_at_lowest_operator(statement)
            && (operator.starts_with(char::is_alphabetic)
                || call_end(left) == Some(left.len())
                || constant_operand(left).is_some())
        {
            return self.logical(left, operator, right);
        }
        if let Some(result) = self.tracked_value_statement(statement) {
            return result;
        }
        if statement.contains(&PerlToken::Punct('{')) {
            return Err(
                "Perl block, hash or anonymous sub is outside the bounded literal grammar".into(),
            );
        }
        let budget = self.budget;
        let binding = statement
            .strip_prefix(&[PerlToken::Name("my".into())])
            .unwrap_or(statement);
        match binding {
            [
                PerlToken::Variable(name),
                PerlToken::Punct('='),
                PerlToken::Command(command),
            ] => {
                // The captured output is runtime data, never a literal.
                self.variables.remove(name);
                self.objects.remove(name);
                self.pending.push(PerlPendingStep::Shell {
                    command: command.clone(),
                    captured: true,
                });
                return Ok(());
            }
            [PerlToken::Variable(name), PerlToken::Punct('='), value] => {
                let value =
                    perl_literal_text(std::slice::from_ref(value), &self.variables, budget)?;
                self.objects.remove(name);
                self.variables.insert(name.clone(), value);
                return Ok(());
            }
            _ => {}
        }
        if let [PerlToken::Command(command)] = statement {
            self.pending.push(PerlPendingStep::Shell {
                command: command.clone(),
                captured: true,
            });
            return Ok(());
        }
        let Some(PerlToken::Name(name)) = statement.first() else {
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
            if rest.iter().all(|token| {
                matches!(
                    token,
                    PerlToken::Punct(_) | PerlToken::Number(_) | PerlToken::Text(_)
                )
            }) {
                return Ok(());
            }
            return Err(format!(
                "Perl expression after the {name} call is outside the bounded literal grammar"
            )
            .into());
        }
        let mut args = &statement[1..];
        if args.first() == Some(&PerlToken::Punct('('))
            && args.last() == Some(&PerlToken::Punct(')'))
        {
            args = &args[1..args.len() - 1];
        }
        let args: Vec<_> = if args.is_empty() {
            Vec::new()
        } else {
            args.split(|token| *token == PerlToken::Punct(','))
                .collect()
        };
        if let Some(body) = self.subs.get(name).cloned() {
            return self.call(name, &body, &args);
        }
        let mut opened = None;
        if matches!(name.as_str(), "open" | "sysopen")
            && let Some(PerlToken::Variable(name)) = args.first().and_then(|arg| arg.last())
        {
            // A filehandle replaces a scalar value; it is no longer a path.
            self.variables.remove(name);
            self.objects.remove(name);
            opened = Some(name);
        }
        let objects = &mut self.objects;
        let variables = &self.variables;
        let path = |i: usize| -> Result<String, PerlFailure> {
            let path = perl_literal_text(
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
                    effects.push(PerlPendingStep::Effect(PerlPendingEffect::new(
                        "filesystem.delete",
                        path,
                    )));
                }
            }
            "rmdir" if args.len() == 1 => effects.push(PerlPendingStep::Effect(
                PerlPendingEffect::new("filesystem.delete", path(0)?),
            )),
            "mkdir" if args.len() == 1 || (args.len() == 2 && numeric_tokens(args[1])) => effects
                .push(PerlPendingStep::Effect(PerlPendingEffect::new(
                    "filesystem.create",
                    path(0)?,
                ))),
            // A mode the grammar cannot evaluate still leaves the change to
            // the established paths, so it is kept with a boundary. Only a
            // plain variable is known to change nothing else; any other
            // expression may, so nothing after it is compiled.
            // A malformed number (`099`) fails to compile, so nothing runs.
            "chmod"
                if args.len() >= 2
                    && brackets_balance(args[0])
                    && (numeric_tokens(args[0]) || !matches!(args[0], [PerlToken::Number(_)])) =>
            {
                let paths = (1..args.len()).map(path).collect::<Result<Vec<_>, _>>()?;
                let grants = match args[0] {
                    [PerlToken::Number(mode)] => crate::permission_mode::granted(
                        crate::permission_mode::numeric(perl_number(mode)?),
                    )
                    .collect(),
                    mode => {
                        self.refusals.insert(
                            "Perl chmod mode is not a numeric literal, so the permissions it grants are unknown"
                                .into(),
                        );
                        if !matches!(mode, [PerlToken::Variable(_)]) {
                            self.halted = true;
                        }
                        Vec::new()
                    }
                };
                for path in paths {
                    let mut metadata = PerlPendingEffect::new("filesystem.metadata", path);
                    metadata.action = Some("chmod");
                    metadata.grants = grants.clone();
                    effects.push(PerlPendingStep::Effect(metadata));
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
                    let mut read = PerlPendingEffect::new("filesystem.read", source.clone());
                    if name.ends_with("copy") {
                        read.access_purpose = Some("program_input");
                    }
                    effects.push(PerlPendingStep::Effect(read));
                    if name.ends_with("copy") {
                        let destination_slot = effects.len() as u32;
                        transfers.push(TransferBinding::exact(source_slot, destination_slot));
                    }
                }
                if !name.ends_with("copy") {
                    effects.push(PerlPendingStep::Effect(PerlPendingEffect::new(
                        "filesystem.move",
                        source.clone(),
                    )));
                    effects.push(PerlPendingStep::Effect(PerlPendingEffect::new(
                        "filesystem.delete",
                        source,
                    )));
                }
                let mut write = PerlPendingEffect::new("filesystem.write", destination);
                if name.ends_with("copy") {
                    write.disclosure = Some("contents");
                }
                effects.push(PerlPendingStep::Effect(write));
            }
            "open" if matches!(args.len(), 2 | 3) && is_filehandle(args[0]) => {
                let value = perl_literal_text(args[1], variables, budget)?;
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
                    let mut read = PerlPendingEffect::new("filesystem.read", path.clone());
                    if mode != "+>" {
                        read.access_purpose = Some("program_input");
                        // What `<$handle>` later reads is this file's contents.
                        if let Some(handle) = opened {
                            objects
                                .insert(handle.clone(), PerlObject::Handle(effects.len() as u32));
                        }
                    }
                    effects.push(PerlPendingStep::Effect(read));
                }
                if write {
                    effects.push(PerlPendingStep::Effect(PerlPendingEffect::new(
                        "filesystem.write",
                        path,
                    )));
                }
            }
            "sysopen"
                if (args.len() == 3 || (args.len() == 4 && numeric_tokens(args[3])))
                    && is_filehandle(args[0]) =>
            {
                let path = path(1)?;
                let mut flags = BTreeSet::new();
                for flag in args[2].split(|token| *token == PerlToken::Punct('|')) {
                    let [PerlToken::Name(flag)] = flag else {
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
                    let mut read = PerlPendingEffect::new("filesystem.read", path.clone());
                    if !flags.contains("O_TRUNC") {
                        read.access_purpose = Some("program_input");
                    }
                    effects.push(PerlPendingStep::Effect(read));
                }
                if flags
                    .iter()
                    .any(|flag| matches!(*flag, "O_WRONLY" | "O_RDWR" | "O_CREAT" | "O_TRUNC"))
                {
                    effects.push(PerlPendingStep::Effect(PerlPendingEffect::new(
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
                    let mut delete = PerlPendingEffect::new("filesystem.delete", path);
                    delete.recursive = true;
                    effects.push(PerlPendingStep::Effect(delete));
                }
            }
            "truncate" if args.len() == 2 && numeric_tokens(args[1]) => effects.push(
                PerlPendingStep::Effect(PerlPendingEffect::new("filesystem.write", path(0)?)),
            ),
            "system" | "exec" if args.len() == 1 => {
                let command = perl_literal_text(args[0], variables, budget)?;
                effects.push(PerlPendingStep::Shell {
                    command,
                    captured: false,
                });
            }
            "system" | "exec" if args.len() > 1 => {
                let argv = args
                    .iter()
                    .map(|arg| perl_literal_text(arg, variables, budget))
                    .collect::<Result<Vec<_>, _>>()?;
                effects.push(PerlPendingStep::Argv(argv));
            }
            // `do FILE` and `require FILE` run a file as Perl. A path that
            // names a directory is that file; any other is searched in
            // `@INC`. The file's source is not read here: whatever it does
            // may change any later fact, so nothing after it is compiled.
            "do" | "require" if args.len() == 1 => {
                let path = path(0)?;
                if !["/", "./", "../"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                {
                    return Err(format!("Perl {name} searches @INC for its file").into());
                }
                effects.push(PerlPendingStep::Load(path));
                self.refusals
                    .insert(format!("Perl file loaded by {name} is not analyzed"));
                self.halted = true;
            }
            // The decoded source is not read here: whatever it does may
            // change any later fact, so nothing after it is compiled.
            "eval" if args.len() == 1 && decodes_base64(args[0], imports) => {
                effects.push(PerlPendingStep::DecodedEval);
                self.refusals
                    .insert("Perl eval of MIME::Base64-decoded text is not analyzed".into());
                self.halted = true;
            }
            "eval" if args.len() == 1 => {
                let source = perl_literal_text(args[0], variables, budget)?;
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

    /// Whether `tokens` is an expression over tracked values: an HTTP::Tiny
    /// method chain, a tracked variable, a `<$handle>` read or a `do` block.
    fn is_tracked_value(&self, tokens: &[PerlToken]) -> bool {
        match tokens {
            [
                PerlToken::Name(class),
                PerlToken::Punct('-'),
                PerlToken::Punct('>'),
                ..,
            ] => class == "HTTP::Tiny" && self.imports.http_loaded,
            [PerlToken::Variable(name)]
            | [
                PerlToken::Variable(name),
                PerlToken::Punct('-'),
                PerlToken::Punct('>'),
                ..,
            ] => self.objects.contains_key(name),
            [
                PerlToken::Punct('<'),
                PerlToken::Variable(name),
                PerlToken::Punct('>'),
            ] => {
                matches!(self.objects.get(name), Some(PerlObject::Handle(_)))
            }
            [PerlToken::Name(keyword), PerlToken::Punct('{'), ..] => {
                keyword == "do" && matching_brace(&tokens[1..]) == Ok(tokens.len() - 2)
            }
            _ => false,
        }
    }

    /// A statement over tracked values, or `None` for any other statement:
    /// a binding, an `eval`, `system` or `exec` of a response body, a `print`
    /// of received or read bytes, a bare expression, or `local $/`, which
    /// only changes how `<$handle>` splits what it reads.
    fn tracked_value_statement(
        &mut self,
        statement: &[PerlToken],
    ) -> Option<Result<(), PerlFailure>> {
        if let [PerlToken::Name(local), PerlToken::Special('/'), rest @ ..] = statement
            && local == "local"
            && matches!(rest, [] | [PerlToken::Punct('='), PerlToken::Name(_)])
            && rest
                .last()
                .is_none_or(|value| *value == PerlToken::Name("undef".into()))
        {
            return Some(Ok(()));
        }
        let binding = statement
            .strip_prefix(&[PerlToken::Name("my".into())])
            .unwrap_or(statement);
        if let [PerlToken::Variable(name), PerlToken::Punct('='), value @ ..] = binding
            && self.is_tracked_value(value)
        {
            self.variables.remove(name);
            self.objects.remove(name);
            return Some(self.tracked_value(value).map(|value| {
                if value != PerlObject::Opaque {
                    self.objects.insert(name.clone(), value);
                }
            }));
        }
        if let [PerlToken::Name(name), argument @ ..] = statement
            && matches!(name.as_str(), "eval" | "system" | "exec" | "print" | "say")
        {
            let argument = match argument {
                [PerlToken::Punct('('), inner @ .., PerlToken::Punct(')')]
                    if call_end(statement) == Some(statement.len()) =>
                {
                    inner
                }
                other => other,
            };
            if !self.is_tracked_value(argument) {
                return None;
            }
            return Some(self.tracked_value(argument).and_then(|value| {
                if matches!(name.as_str(), "print" | "say") {
                    if let PerlObject::Content(source) | PerlObject::FileData(source) = value {
                        self.pending.push(PerlPendingStep::Output(source));
                    }
                    return Ok(());
                }
                let PerlObject::Content(request) = value else {
                    return Err(format!("Perl {name} of a runtime value is not analyzed").into());
                };
                // The received source is not read here: whatever it does
                // may change any later fact, so nothing after it is compiled.
                self.transfers
                    .push(TransferBinding::new(request, self.pending.len() as u32));
                self.pending.push(PerlPendingStep::RemoteCode {
                    shell: name != "eval",
                });
                self.refusals.insert(format!(
                    "Perl {name} of an HTTP response body is not analyzed"
                ));
                self.halted = true;
                Ok(())
            }));
        }
        self.is_tracked_value(statement)
            .then(|| self.tracked_value(statement).map(|_| ()))
    }

    /// Evaluate an expression `is_tracked_value` accepts, publishing the requests
    /// and reads it performs.
    fn tracked_value(&mut self, tokens: &[PerlToken]) -> Result<PerlObject, PerlFailure> {
        if self.nesting >= MAX_NESTING {
            return Err("Perl expression nests too deeply to model".into());
        }
        match tokens {
            [
                PerlToken::Punct('<'),
                PerlToken::Variable(name),
                PerlToken::Punct('>'),
            ] => {
                return match self.objects.get(name) {
                    Some(PerlObject::Handle(read)) => Ok(PerlObject::FileData(*read)),
                    _ => Err("Perl readline handle is not a file opened for reading".into()),
                };
            }
            [
                PerlToken::Name(keyword),
                PerlToken::Punct('{'),
                body @ ..,
                PerlToken::Punct('}'),
            ] if keyword == "do" => {
                self.nesting += 1;
                let result = self.do_block_value(body);
                self.nesting -= 1;
                return result;
            }
            _ => {}
        }
        let (mut value, mut rest) = match tokens {
            [PerlToken::Name(class), rest @ ..] if class == "HTTP::Tiny" => {
                (PerlObject::Class, rest)
            }
            [PerlToken::Variable(name), rest @ ..] => (
                self.objects
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("Perl variable ${name} holds no tracked value"))?,
                rest,
            ),
            _ => return Err("Perl expression is outside the bounded literal grammar".into()),
        };
        while let [PerlToken::Punct('-'), PerlToken::Punct('>'), after @ ..] = rest {
            match after {
                [
                    PerlToken::Punct('{'),
                    PerlToken::Name(key) | PerlToken::Text(key),
                    PerlToken::Punct('}'),
                    tail @ ..,
                ] => {
                    value = match value {
                        PerlObject::Response(request) if key == "content" => {
                            PerlObject::Content(request)
                        }
                        PerlObject::Response(_) => PerlObject::Opaque,
                        _ => {
                            return Err(
                                "Perl subscript of an untracked value is not modeled".into()
                            );
                        }
                    };
                    rest = tail;
                }
                [PerlToken::Name(method), tail @ ..] => {
                    let (arguments, tail) = match call_end(after) {
                        Some(end) => (&after[2..end - 1], &after[end..]),
                        None => (&[][..], tail),
                    };
                    value = self.http_tiny_method_call(&value, method, arguments)?;
                    rest = tail;
                }
                _ => break,
            }
        }
        if !rest.is_empty() {
            return Err(
                "Perl expression over a tracked value is outside the bounded literal grammar"
                    .into(),
            );
        }
        Ok(value)
    }

    /// A `do { ... }` block: its statements run in order and the last one is
    /// its value.
    fn do_block_value(&mut self, body: &[PerlToken]) -> Result<PerlObject, PerlFailure> {
        let statements = statements(body)?;
        let mut value = PerlObject::Opaque;
        for (index, statement) in statements.iter().enumerate() {
            let PerlStatement::Simple(statement) = statement else {
                return Err("Perl nested named sub is not modeled".into());
            };
            if index + 1 == statements.len() && self.is_tracked_value(statement) {
                value = self.tracked_value(statement)?;
            } else {
                self.statement(statement)?;
            }
        }
        Ok(value)
    }

    /// Run a named sub's body. Its argument list must be literal, and any
    /// variable it rebinds is no longer a known literal afterwards.
    fn call(
        &mut self,
        name: &str,
        body: &[PerlToken],
        args: &[&[PerlToken]],
    ) -> Result<(), PerlFailure> {
        for arg in args {
            perl_literal_text(arg, &self.variables, self.budget)?;
        }
        if self.depth >= MAX_CALL_DEPTH || !self.active_subs.insert(name.to_string()) {
            return Err(format!("Perl sub {name} recursion is not modeled").into());
        }
        let outer = (self.variables.clone(), self.objects.clone());
        self.depth += 1;
        let result = statements(body)
            .map_err(PerlFailure::Refused)
            .and_then(|statements| {
                statements
                    .into_iter()
                    .try_for_each(|statement| match statement {
                        PerlStatement::Simple(statement) => self.run(statement),
                        PerlStatement::Sub(..) => {
                            Err("Perl nested named sub is not modeled".into())
                        }
                    })
            });
        self.depth -= 1;
        self.active_subs.remove(name);
        self.restore_bindings(outer);
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
