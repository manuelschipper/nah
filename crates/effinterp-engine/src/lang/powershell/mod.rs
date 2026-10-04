//! The PowerShell frontend: walks a script statement by statement, tracking
//! what the session changed (aliases, functions, location, variable content),
//! and dispatches each command to its cmdlet model or to a native program.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    Modality, Operation, ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, Transition, word_resource};
use crate::word::Word;

mod cmdlet_parameters;
mod copy_or_move_item;
mod file_cmdlets;
mod item_landing;
mod path_resolution;
mod ps_words;
mod remove_item;
mod web_requests;
mod wildcards;

use cmdlet_parameters::{
    COPY_ITEM, Cmdlet, FILE_CMDLETS, MOVE_ITEM, NEW_ITEM, PsBoundParameters, REMOVE_ITEM,
    RENAME_ITEM, SET_ALIAS, SET_LOCATION, START_PROCESS, WEB_REQUEST, WRITE_HOST, WRITE_OUTPUT,
    bind,
};
use copy_or_move_item::move_item;
use file_cmdlets::{file_cmdlet, new_item};
use path_resolution::{absolute_filesystem_path, expand_environment_words, resolved_path};
use ps_words::{PsRedirection, PsWord, Variable, statements, variable, words};
use remove_item::removal;
use web_requests::{
    Remote, invoked_remote_content, invoked_scriptblock_content, remote_content, remote_execution,
    scriptblock_create, web_request, webclient_download,
};

/// Statements nested through `Invoke-Expression` that themselves nest again.
const MAX_NESTED_SOURCE_DEPTH: u32 = 4;

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
        let mut boundary = unsupported(node);
        boundary.reason = BoundaryReason::LIMIT_SATURATED;
        boundary.class = BoundaryClass::Limit;
        boundary.limit = Some("max_source_bytes".into());
        builder.boundary(boundary);
        return;
    }
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    if nested(builder, nest, source, cwd, node, 0) {
        for domain in ["filesystem", "process"] {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

/// Analyze PowerShell source reached from another frontend. Returns whether
/// every statement was understood; a caller that nests this source only claims
/// full coverage when it was.
pub(super) fn nested(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    // The script-block reader (`scriptblock_create`) recurses once per grouping
    // parenthesis, so source nested past the native stack overflows the hook.
    // Refuse it before reading with a partial-analysis boundary; the rest of
    // the command still analyzes and coverage stays partial.
    if grouping_depth_exceeds(source) {
        let mut boundary = unsupported(node);
        boundary.reason = BoundaryReason::PARTIAL_ANALYSIS;
        boundary.class = BoundaryClass::Unmodeled;
        boundary.detail = Some("PowerShell source nesting exceeds the walk limit".into());
        builder.boundary(boundary);
        return false;
    }
    script(
        builder,
        nest,
        &mut Session::default(),
        source,
        cwd,
        node,
        depth,
    )
}

/// Whether the bracket nesting of PowerShell source exceeds the walk limit,
/// skipping the string and comment forms [`statements`] recognizes so their
/// contents never count. Conservative: it only ever over-counts.
fn grouping_depth_exceeds(source: &str) -> bool {
    let mut depth: u32 = 0;
    let mut quote: Option<char> = None;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(open) = quote {
            if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '`' => {
                characters.next();
            }
            '<' if characters.peek() == Some(&'#') => {
                characters.next();
                let mut previous = None;
                for character in characters.by_ref() {
                    if previous == Some('#') && character == '>' {
                        break;
                    }
                    previous = Some(character);
                }
            }
            '#' => {
                while characters
                    .next_if(|next| !matches!(next, '\n' | '\r'))
                    .is_some()
                {}
            }
            '(' | '[' | '{' => {
                depth += 1;
                if depth > crate::lang::frontend::MAX_WALK_DEPTH {
                    return true;
                }
            }
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// What earlier statements of one PowerShell session changed about how later
/// ones resolve. `Invoke-Expression` runs in the caller's scope, so it shares
/// the session of the source that invokes it.
#[derive(Default)]
struct Session {
    /// Command names (lowercase) that a function, alias or alias removal
    /// defined anew, so they no longer name the built-in this grammar models.
    shadowed: Vec<String>,
    /// Alias names a definition or removal changed, so the built-in alias of
    /// that name no longer applies.
    aliases: Vec<String>,
    /// Names a function or filter definition bound.
    functions: Vec<String>,
    /// Variables (lowercase) that `$name = Get-Content PATH` assigned, with
    /// the effect slot of that file read.
    contents: Vec<(String, u32)>,
    /// Variables (lowercase) that `$name = [scriptblock]::Create(DOWNLOAD)`
    /// assigned, with the URL of the download when it is literal.
    remote_blocks: Vec<(String, Option<String>)>,
    /// Whether an earlier statement may have changed the current location,
    /// which relative paths resolve against. It starts as the invocation
    /// directory.
    location_moved: bool,
}

impl Session {
    fn shadow(&mut self, name: &str) {
        self.shadowed.push(name.to_ascii_lowercase());
    }

    fn define_alias(&mut self, name: &str) {
        self.shadow(name);
        self.aliases.push(name.to_ascii_lowercase());
    }

    fn define_function(&mut self, name: &str) {
        self.shadow(name);
        self.functions.push(name.to_ascii_lowercase());
    }

    /// Whether `name` runs the built-in `cmdlet`. PowerShell resolves an
    /// alias before a function, and a function before a cmdlet
    /// (about_Command_Precedence): a function named like a surviving
    /// built-in alias does not replace it, while one named like the alias's
    /// cmdlet does.
    fn runs_cmdlet(&self, name: &str, cmdlet: &str) -> bool {
        let changed =
            |list: &[String], name: &str| list.iter().any(|entry| entry.eq_ignore_ascii_case(name));
        if changed(&self.aliases, name) {
            return false;
        }
        let target = resolved_command(name);
        let aliased = !target.eq_ignore_ascii_case(name);
        target.eq_ignore_ascii_case(cmdlet)
            && !changed(&self.aliases, target)
            && !changed(&self.functions, target)
            && (aliased || !changed(&self.functions, name))
    }

    fn shadows(&self, name: &str) -> bool {
        self.shadowed
            .iter()
            .any(|shadowed| shadowed.eq_ignore_ascii_case(name))
    }

    /// The file read whose content an unquoted `$name` word holds.
    fn content(&self, word: &PsWord) -> Option<u32> {
        let name = word.text.strip_prefix('$').filter(|_| !word.quoted)?;
        self.contents
            .iter()
            .rev()
            .find(|(bound, _)| bound.eq_ignore_ascii_case(name))
            .map(|(_, slot)| *slot)
    }
}

fn script(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    source: &str,
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let statements = match statements(source) {
        Ok(statements) => statements,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let mut complete = true;
    let mut statements = statements.into_iter().peekable();
    while let Some((source, piped)) = statements.next() {
        // Downloaded content piped into Invoke-Expression runs as code.
        if piped
            && let Some((sink, _)) = statements.peek()
            && session.runs_cmdlet(sink.trim(), "Invoke-Expression")
            && let Some(remote) = remote_content(builder, nest, session, &source, node)
        {
            statements.next();
            if let Remote::Content(url) = remote {
                remote_execution(builder, url, node);
            }
            session.contents.clear();
            session.location_moved = true;
            complete = false;
            continue;
        }
        if !statement(builder, nest, session, &source, piped, cwd, node, depth) {
            // A statement the grammar did not fully read may have assigned
            // any variable, so no content binding survives it. It may also
            // have changed the current location.
            session.contents.clear();
            session.location_moved = true;
            complete = false;
        }
    }
    complete
}

/// The common parameters that store a cmdlet's output or messages in a
/// variable (about_CommonParameters).
const VARIABLE_PARAMETERS: &[&str] = &[
    "OutVariable",
    "ErrorVariable",
    "WarningVariable",
    "InformationVariable",
    "PipelineVariable",
];

/// Drop the content bindings that a bound cmdlet's variable-writing common
/// parameters replace once it has run. A `+name` value appends, so the
/// variable keeps its content. A variable name the grammar cannot read may
/// replace any binding, which is a boundary.
fn variable_writes(
    builder: &mut PlanBuilder,
    session: &mut Session,
    bound: &PsBoundParameters,
    node: ProvenanceRef,
) -> bool {
    let mut complete = true;
    for parameter in VARIABLE_PARAMETERS {
        let Some(values) = bound.values(parameter) else {
            continue;
        };
        let name = match values {
            [value] => value
                .strip_prefix('+')
                .map_or((false, value.as_str()), |name| (true, name)),
            _ => (false, ""),
        };
        match name {
            (true, name) if identifier(name) => {}
            (false, name) if identifier(name) => session
                .contents
                .retain(|(bound, _)| !bound.eq_ignore_ascii_case(name)),
            _ => {
                session.contents.clear();
                powershell_boundary(
                    builder,
                    node,
                    "PowerShell common parameter writes a variable the grammar cannot name",
                );
                complete = false;
            }
        }
    }
    complete
}

/// Whether `name` is a plain variable name.
fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Whether a word is an unquoted `$name` naming a variable the script
/// assigns itself.
fn session_variable(word: &PsWord) -> bool {
    !word.quoted
        && word.text.strip_prefix('$').is_some_and(|name| {
            identifier(name) && matches!(variable(name), Some((Variable::Session, _)))
        })
}

fn unsupported(node: ProvenanceRef) -> Boundary {
    Boundary {
        reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        class: BoundaryClass::Unsupported,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![node],
        limit: None,
        detail: None,
    }
}

fn powershell_boundary(builder: &mut PlanBuilder, node: ProvenanceRef, detail: &str) {
    let mut boundary = unsupported(node);
    boundary.detail = Some(detail.into());
    builder.boundary(boundary);
}

#[allow(clippy::too_many_arguments)]
fn statement(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    statement: &str,
    piped: bool,
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    // A function or filter definition replaces whatever its name resolved
    // to. Its body runs only when called, and a call to it is refused below.
    if let Some(name) = ps_function_definition(statement) {
        session.define_function(name);
        powershell_boundary(
            builder,
            node,
            "PowerShell function definition is not modeled",
        );
        return false;
    }
    // The power cmdlets are modeled as a whole statement rather than through
    // the command grammar below.
    if crate::models::system::powershell_power(builder, statement, node) {
        return true;
    }
    if let Some(complete) = webclient_download(builder, nest, statement, node) {
        return complete;
    }
    if let Some(remote) = invoked_remote_content(builder, nest, session, statement, node)
        .or_else(|| invoked_scriptblock_content(builder, nest, session, statement, node))
    {
        if let Remote::Content(url) = remote {
            remote_execution(builder, url, node);
        }
        return false;
    }
    // An assignment replaces what the variable held before. Only the output
    // of Get-Content is modeled; any other command stays a boundary below.
    if let Some((name, command)) = assignment(statement) {
        session
            .contents
            .retain(|(bound, _)| !bound.eq_ignore_ascii_case(name));
        session
            .remote_blocks
            .retain(|(bound, _)| !bound.eq_ignore_ascii_case(name));
        // The block only compiles here; a later statement may run it.
        if let Some((argument, after)) = scriptblock_create(command)
            && after.trim().is_empty()
            && let Some(Remote::Content(url)) =
                remote_content(builder, nest, session, argument, node)
        {
            session.remote_blocks.push((name.to_ascii_lowercase(), url));
        }
        if let Some(complete) =
            content_assignment(builder, nest, session, name, command, piped, cwd, node)
        {
            return complete;
        }
        // A preference variable set to a constant changes only how later
        // commands report and stop; it writes nothing.
        if !piped && preference(name) && constant_value(command) {
            return true;
        }
    }
    // The call operator `&` runs the command its operand names, which may be
    // a quoted string.
    let (call, statement) = match statement.trim_start().strip_prefix('&') {
        Some(rest)
            if rest.starts_with(|character: char| {
                character.is_whitespace() || matches!(character, '\'' | '"')
            }) =>
        {
            (true, rest)
        }
        _ => (false, statement),
    };
    let mut parsed = match words(statement) {
        Ok(parsed) => parsed,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    // A web request reads its own `$name` arguments, so it can still send a
    // body whose content is unknown.
    let requests_web = parsed.words.first().is_some_and(|head| {
        let command = resolved_command(&head.text);
        command.eq_ignore_ascii_case("Invoke-WebRequest")
            || command.eq_ignore_ascii_case("Invoke-RestMethod")
    });
    if !expand_environment_words(builder, nest, session, requests_web, &mut parsed, node) {
        return false;
    }
    let mut complete = true;
    let location = cwd.filter(|_| !session.location_moved);
    for redirection in &parsed.redirections {
        complete &= redirected_write(builder, nest, redirection, location, node);
    }
    let Some(head) = parsed.words.first() else {
        // A statement that only redirects still creates the file it names.
        return complete;
    };
    if head.quoted && !call {
        powershell_boundary(
            builder,
            node,
            "PowerShell command name is a quoted expression",
        );
        return false;
    }
    let arguments = &parsed.words[1..];
    let command = resolved_command(&head.text);
    if moves_location(&head.text) {
        session.location_moved = true;
    }
    if session.shadows(&head.text) || session.shadows(command) {
        powershell_boundary(
            builder,
            node,
            "PowerShell command is redefined earlier in the source",
        );
        return false;
    }
    let dispatched = dispatch_command(
        builder,
        nest,
        session,
        command,
        &parsed.words,
        requests_web,
        cwd,
        node,
        depth,
    );
    // A cmdlet writes its common-parameter variables once it has run, so the
    // request above still read what they held before.
    let written = cmdlet(command)
        .and_then(|cmdlet| bind(arguments, cmdlet).ok())
        .is_none_or(|bound| variable_writes(builder, session, &bound, node));
    dispatched && written && complete
}

/// Whether a command may change the current location: the location cmdlets
/// and their aliases, and a script, which runs in the same session.
fn moves_location(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "set-location"
            | "push-location"
            | "pop-location"
            | "cd"
            | "chdir"
            | "sl"
            | "pushd"
            | "popd"
            | "."
    ) || name.ends_with(".ps1")
}

/// The command a name runs, after the built-in aliases.
fn resolved_command(name: &str) -> &str {
    ALIASES
        .iter()
        .find(|(alias, _)| alias.eq_ignore_ascii_case(name))
        .map_or(name, |(_, cmdlet)| *cmdlet)
}

/// The parameters of a cmdlet this grammar binds.
fn cmdlet(command: &str) -> Option<&'static Cmdlet> {
    let named = |name: &str| command.eq_ignore_ascii_case(name);
    if let Some(file) = FILE_CMDLETS
        .iter()
        .find(|file| file.cmdlet.name.eq_ignore_ascii_case(command))
    {
        return Some(&file.cmdlet);
    }
    Some(match () {
        _ if named("Remove-Item") => &REMOVE_ITEM,
        _ if named("Copy-Item") => &COPY_ITEM,
        _ if named("Move-Item") => &MOVE_ITEM,
        _ if named("Rename-Item") => &RENAME_ITEM,
        _ if named("New-Item") => &NEW_ITEM,
        _ if named("Invoke-WebRequest") || named("Invoke-RestMethod") => &WEB_REQUEST,
        _ if named("Start-Process") => &START_PROCESS,
        _ if named("Set-Alias") || named("New-Alias") => &SET_ALIAS,
        _ if named("Write-Output") => &WRITE_OUTPUT,
        _ if named("Write-Host") => &WRITE_HOST,
        _ if named("Set-Location") => &SET_LOCATION,
        _ => return None,
    })
}

/// Run one parsed command: `words` is its name followed by its arguments.
#[allow(clippy::too_many_arguments)]
fn dispatch_command(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    command: &str,
    words: &[PsWord],
    requests_web: bool,
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let arguments = &words[1..];
    let location = cwd.filter(|_| !session.location_moved);
    let file = FILE_CMDLETS
        .iter()
        .find(|file| file.cmdlet.name.eq_ignore_ascii_case(command));
    if !requests_web
        && arguments
            .iter()
            .any(|argument| session.content(argument).is_some())
    {
        powershell_boundary(
            builder,
            node,
            "PowerShell file content variable reaches an unmodeled parameter",
        );
        return false;
    }
    if let Some(file) = file {
        return file_cmdlet(builder, nest, arguments, location, node, file, false).0;
    }
    if command.eq_ignore_ascii_case("Remove-Item") {
        return removal(builder, nest, session, arguments, location, node);
    }
    if command.eq_ignore_ascii_case("Copy-Item")
        || command.eq_ignore_ascii_case("Move-Item")
        || command.eq_ignore_ascii_case("Rename-Item")
    {
        return move_item(builder, nest, arguments, location, node, command);
    }
    if command.eq_ignore_ascii_case("New-Item") {
        return new_item(builder, nest, arguments, location, node);
    }
    if requests_web {
        return web_request(builder, nest, session, arguments, location, node);
    }
    if command.eq_ignore_ascii_case("Start-Process") {
        return start_process(builder, nest, arguments, cwd, node, depth);
    }
    if command.eq_ignore_ascii_case("Set-Alias") || command.eq_ignore_ascii_case("New-Alias") {
        return set_alias(builder, session, arguments, node);
    }
    if command.eq_ignore_ascii_case("Invoke-Expression") {
        return invoke_expression(builder, nest, session, arguments, cwd, node, depth);
    }
    if command.eq_ignore_ascii_case("Write-Output") {
        // Write-Output puts its arguments on the success stream. A file it
        // reaches is named by a redirection, which the caller models; its
        // arguments are bound only for the variables they write.
        if let Err(detail) = bind(arguments, &WRITE_OUTPUT) {
            powershell_boundary(builder, node, detail);
            return false;
        }
        return true;
    }
    // Write-Host writes only to the host display, and Set-Location only
    // moves the current location, which the caller already tracks. Neither
    // writes a file.
    if let Some(quiet) = [&WRITE_HOST, &SET_LOCATION]
        .into_iter()
        .find(|cmdlet| cmdlet.name.eq_ignore_ascii_case(command))
    {
        if let Err(detail) = bind(arguments, quiet) {
            powershell_boundary(builder, node, detail);
            return false;
        }
        return true;
    }
    // PowerShell resolves a name as an alias, then a function or cmdlet, and
    // only then a program on the path (about_Command_Precedence). A Verb-Noun
    // name this grammar does not model stays a boundary instead of becoming a
    // program invocation the command models would read with another grammar.
    if command.contains('-') {
        powershell_boundary(
            builder,
            node,
            "PowerShell cmdlet is outside the modeled grammar",
        );
        return false;
    }
    program(builder, nest, words, cwd, node, depth)
}

/// `$name = COMMAND`: the variable a statement assigns and the command whose
/// output it stores.
fn assignment(statement: &str) -> Option<(&str, &str)> {
    let rest = statement.trim_start().strip_prefix('$')?;
    let end = rest
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(rest.len());
    let (name, rest) = rest.split_at(end);
    let command = rest.trim_start().strip_prefix('=')?;
    (matches!(variable(name), Some((Variable::Session, _))) && !command.starts_with('='))
        .then_some((name, command))
}

/// The preference variables (about_Preference_Variables) that govern how
/// commands report progress and errors.
fn preference(name: &str) -> bool {
    [
        "ErrorActionPreference",
        "ProgressPreference",
        "VerbosePreference",
        "WarningPreference",
        "InformationPreference",
        "DebugPreference",
    ]
    .iter()
    .any(|preference| preference.eq_ignore_ascii_case(name))
}

/// Whether an assigned value is a constant: a single-quoted string, or one
/// double-quoted or bare word with no expansion or expression.
fn constant_value(value: &str) -> bool {
    let value = value.trim();
    let inner = match value.as_bytes().first() {
        Some(b'\'') | Some(b'"') => value
            .strip_prefix(&value[..1])
            .and_then(|rest| rest.strip_suffix(&value[..1])),
        _ => Some(value),
    };
    inner.is_some_and(|inner| {
        !inner.is_empty()
            && inner
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

/// `$name = Get-Content PATH` reads PATH into the variable instead of the
/// output. Returns `None` when the command is not Get-Content. Where the
/// command pipes into another, the variable holds the pipeline's final
/// output instead, which is not modeled: the read stays and nothing binds.
#[allow(clippy::too_many_arguments)]
fn content_assignment(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    name: &str,
    command: &str,
    piped: bool,
    cwd: Option<&str>,
    node: ProvenanceRef,
) -> Option<bool> {
    let mut parsed = words(command).ok()?;
    let head = parsed.words.first()?;
    let cmdlet = ALIASES
        .iter()
        .find(|(alias, _)| alias.eq_ignore_ascii_case(&head.text))
        .map_or(head.text.as_str(), |(_, cmdlet)| *cmdlet);
    let file = FILE_CMDLETS.iter().find(|file| {
        file.cmdlet.name.eq_ignore_ascii_case(cmdlet) && file.operation == "filesystem.read"
    })?;
    if head.quoted
        || !parsed.redirections.is_empty()
        || session.shadows(&head.text)
        || session.shadows(cmdlet)
    {
        return None;
    }
    if !expand_environment_words(builder, nest, session, false, &mut parsed, node) {
        return Some(false);
    }
    let arguments = &parsed.words[1..];
    let location = cwd.filter(|_| !session.location_moved);
    let (complete, reads) = file_cmdlet(builder, nest, arguments, location, node, file, true);
    // The cmdlet's own variable writes land before the assignment stores its
    // output, so `$c = Get-Content PATH -OutVariable c` still holds PATH.
    let written = bind(arguments, &file.cmdlet)
        .is_ok_and(|bound| variable_writes(builder, session, &bound, node));
    if piped {
        powershell_boundary(
            builder,
            node,
            "PowerShell assignment captures the output of a pipeline",
        );
        return Some(false);
    }
    if let [read] = reads[..] {
        session.contents.push((name.to_string(), read));
    }
    Some(complete && written)
}

/// The name a `function` or `filter` statement defines.
fn ps_function_definition(statement: &str) -> Option<&str> {
    let statement = statement.trim_start();
    let keyword = statement.split(char::is_whitespace).next()?;
    if !keyword.eq_ignore_ascii_case("function") && !keyword.eq_ignore_ascii_case("filter") {
        return None;
    }
    let rest = statement[keyword.len()..].trim_start();
    let end = rest
        .find(|character: char| character.is_whitespace() || matches!(character, '{' | '('))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The built-in aliases PowerShell defines for the cmdlets this grammar
/// reaches a conclusion about (about_Aliases). An alias names exactly one
/// cmdlet, so resolving it first keeps one grammar per cmdlet. `curl` and
/// `wget` are aliases of `Invoke-WebRequest` in Windows PowerShell, which is
/// why they do not name the native downloader of the same name.
const ALIASES: &[(&str, &str)] = &[
    ("ac", "Add-Content"),
    ("clc", "Clear-Content"),
    ("copy", "Copy-Item"),
    ("cp", "Copy-Item"),
    ("cpi", "Copy-Item"),
    ("curl", "Invoke-WebRequest"),
    ("del", "Remove-Item"),
    ("echo", "Write-Output"),
    ("erase", "Remove-Item"),
    ("gc", "Get-Content"),
    ("icm", "Invoke-Command"),
    ("iex", "Invoke-Expression"),
    ("irm", "Invoke-RestMethod"),
    ("iwr", "Invoke-WebRequest"),
    ("mi", "Move-Item"),
    ("move", "Move-Item"),
    ("mv", "Move-Item"),
    ("nal", "New-Alias"),
    ("rd", "Remove-Item"),
    ("ri", "Remove-Item"),
    ("rm", "Remove-Item"),
    ("rmdir", "Remove-Item"),
    ("rni", "Rename-Item"),
    ("sal", "Set-Alias"),
    ("saps", "Start-Process"),
    ("wget", "Invoke-WebRequest"),
    ("write", "Write-Output"),
];

/// A program the source starts with the given words: `cmd` runs its command
/// line through the cmd grammar, and any other program is a native command.
fn program(
    builder: &mut PlanBuilder,
    nest: &Nest,
    words: &[PsWord],
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let (head, arguments) = words.split_first().expect("a program has a name");
    // PowerShell passes each element of a collection to a program as an
    // argument of its own, which the words below do not model.
    if words.iter().any(|word| !word.elements.is_empty()) {
        powershell_boundary(
            builder,
            node,
            "PowerShell collection argument to a program is not modeled",
        );
        return false;
    }
    if matches!(
        executable_name(&head.text).to_ascii_lowercase().as_str(),
        "cmd"
    ) {
        return nested_cmd(builder, nest, arguments, cwd, node, depth);
    }
    native(builder, nest, words, cwd, node);
    true
}

/// A head that is neither an alias nor a cmdlet name is a native command:
/// PowerShell finds the program on its path and starts it with the words
/// parsed here. The command models own what that program does, so the nested
/// invocation declares its own coverage and an unmodeled program keeps the
/// boundary the registry raises for it.
fn native(
    builder: &mut PlanBuilder,
    nest: &Nest,
    words: &[PsWord],
    cwd: Option<&str>,
    node: ProvenanceRef,
) {
    // PowerShell finds a native command through PATHEXT, so on Windows a
    // program named with its executable extension is the command of the same
    // bare name.
    let windows = cwd.is_some_and(|cwd| absolute_filesystem_path(cwd, None) == Some(true));
    let words = words
        .iter()
        .enumerate()
        .map(|(index, word)| {
            if index == 0 && windows {
                Word::literal(executable_name(&word.text))
            } else {
                Word::literal(word.text.clone())
            }
        })
        .collect::<Vec<_>>();
    nest.nest(
        builder,
        Transition::exec(words.iter().map(word_resource).collect(), words)
            .exec_cwd(cwd)
            .runtime_cwd(nest.current_runtime_cwd().as_deref()),
        &[node],
        builder.execution_depth(),
    );
}

/// A redirection that names a file writes it; `2>&1` merges one stream into
/// another and touches no file.
fn redirected_write(
    builder: &mut PlanBuilder,
    nest: &Nest,
    redirection: &PsRedirection,
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let Some(target) = &redirection.target else {
        return true;
    };
    let Some(resource) = resolved_path(
        builder,
        nest,
        &target.text,
        true,
        location,
        node,
        "redirection",
    ) else {
        return false;
    };
    builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("filesystem.write"),
        resource,
        attributes: if redirection.append {
            [("append".into(), effinterp_proto::AttrValue::Bool(true))].into()
        } else {
            Default::default()
        },
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node],
    });
    true
}

fn invoke_expression(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    arguments: &[PsWord],
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let [argument] = arguments else {
        powershell_boundary(
            builder,
            node,
            "PowerShell Invoke-Expression has no single literal statement",
        );
        return false;
    };
    if depth >= MAX_NESTED_SOURCE_DEPTH {
        let mut saturated = unsupported(node);
        saturated.reason = BoundaryReason::LIMIT_SATURATED;
        saturated.class = BoundaryClass::Limit;
        saturated.limit = Some("max_execution_depth".into());
        builder.boundary(saturated);
        return false;
    }
    if !argument.elements.is_empty() {
        powershell_boundary(
            builder,
            node,
            "PowerShell Invoke-Expression has no single literal statement",
        );
        return false;
    }
    script(builder, nest, session, &argument.text, cwd, node, depth + 1)
}

/// `cmd /c ...` from PowerShell starts the Windows command interpreter with
/// the remaining words as its command line.
fn nested_cmd(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let Some((switch, command)) = arguments.split_first() else {
        powershell_boundary(
            builder,
            node,
            "PowerShell cmd invocation has no command line",
        );
        return false;
    };
    if switch.quoted || !matches!(switch.text.to_ascii_lowercase().as_str(), "/c" | "/k") {
        powershell_boundary(
            builder,
            node,
            "PowerShell cmd invocation does not pass a command line",
        );
        return false;
    }
    interpreter_exec(builder, node, "cmd");
    let command = command
        .iter()
        .map(|word| word.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    if depth >= MAX_NESTED_SOURCE_DEPTH {
        let mut saturated = unsupported(node);
        saturated.reason = BoundaryReason::LIMIT_SATURATED;
        saturated.class = BoundaryClass::Limit;
        saturated.limit = Some("max_execution_depth".into());
        builder.boundary(saturated);
        return false;
    }
    super::cmd::nested(builder, nest, &command, cwd, node, depth + 1)
}

/// The interpreter a nested command line starts. Its arguments are the nested
/// source, which the nested analysis reports on its own.
pub(super) fn interpreter_exec(builder: &mut PlanBuilder, node: ProvenanceRef, executable: &str) {
    builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("process.exec"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: executable.to_string(),
                path: None,
                argv: Vec::new(),
                cwd: None,
            },
        },
        attributes: Default::default(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node],
    });
}

/// The program a Windows executable name selects. `PATHEXT` appends the
/// extension when PowerShell searches, so the extension names no other
/// program than the bare name does.
fn executable_name(text: &str) -> &str {
    let lowercase = text.to_ascii_lowercase();
    [".exe", ".com"]
        .iter()
        .find(|extension| lowercase.ends_with(*extension))
        .map_or(text, |extension| &text[..text.len() - extension.len()])
}

/// `Start-Process -FilePath PROGRAM -ArgumentList ARGS` starts PROGRAM with a
/// command line that joins ARGS with spaces, which the program splits again.
fn start_process(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u32,
) -> bool {
    let bound = match bind(arguments, &START_PROCESS) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let program_name = match bound.value("FilePath") {
        Ok(Some(program)) => program,
        _ => {
            powershell_boundary(
                builder,
                node,
                "PowerShell Start-Process does not name one program",
            );
            return false;
        }
    };
    let command_line = bound.values("ArgumentList").unwrap_or_default().join(" ");
    // A double quote groups words in the program's own command-line parsing,
    // which this split does not model.
    if command_line.contains('"') {
        powershell_boundary(
            builder,
            node,
            "PowerShell Start-Process argument list quotes its words",
        );
        return false;
    }
    if bound.switch("WhatIf") {
        return bound.complete(builder, node, "Start-Process");
    }
    let complete = bound.complete(builder, node, "Start-Process");
    let words = std::iter::once(program_name)
        .chain(command_line.split_whitespace())
        .map(|text| PsWord {
            text: text.to_string(),
            quoted: false,
            leading_quote: false,
            expandable: false,
            elements: Vec::new(),
        })
        .collect::<Vec<_>>();
    program(builder, nest, &words, cwd, node, depth) && complete
}

/// `Set-Alias NAME VALUE` makes NAME resolve to VALUE from then on.
fn set_alias(
    builder: &mut PlanBuilder,
    session: &mut Session,
    arguments: &[PsWord],
    node: ProvenanceRef,
) -> bool {
    let bound = match bind(arguments, &SET_ALIAS) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let Ok(Some(name)) = bound.value("Name") else {
        powershell_boundary(builder, node, "PowerShell alias definition names no alias");
        return false;
    };
    if !bound.switch("WhatIf") {
        session.define_alias(name);
    }
    bound.complete(builder, node, "Set-Alias")
}
