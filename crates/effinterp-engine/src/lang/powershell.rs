use std::collections::BTreeSet;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ListedEntry, Modality, ObservationOutcome, Operation, PathKind, PathPlatform, ProvenanceKind,
    ProvenanceRef, RequestAssurance, ResourceExpr, ResourceIdentity, ResourcePattern,
    filesystem_path, normalize_path,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Nest, Transition, word_resource};
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;
use crate::word::Word;

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

/// A filesystem resource for a Windows or POSIX path that a command expanded
/// as a wildcard, or took literally.
pub(super) fn path_resource(path: &str, windows: bool, wildcards: bool) -> ResourceExpr {
    let path = filesystem_provider_path(path);
    let local;
    let path = if windows && path.starts_with("\\\\") {
        let parts = path
            .trim_start_matches('\\')
            .splitn(3, '\\')
            .collect::<Vec<_>>();
        if parts.len() == 3
            && parts[0].eq_ignore_ascii_case("localhost")
            && parts[1].len() == 2
            && parts[1].as_bytes()[0].is_ascii_alphabetic()
            && parts[1].ends_with('$')
        {
            local = format!("{}:\\{}", &parts[1][..1], parts[2]);
            &local
        } else {
            path
        }
    } else {
        path
    };
    let platform = if windows {
        PathPlatform::Windows
    } else {
        PathPlatform::Posix
    };
    if wildcards && path.contains(['*', '?', '[']) {
        return ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath {
                glob: normalize_path(path, platform),
                narrowing: Default::default(),
            },
        };
    }
    filesystem_path(path, None, platform)
}

/// Remove only a named filesystem provider; registry and environment
/// qualifiers must remain unresolved as filesystem paths.
fn filesystem_provider_path(path: &str) -> &str {
    path.split_once("::")
        .filter(|(provider, _)| {
            provider.eq_ignore_ascii_case("FileSystem")
                || provider.eq_ignore_ascii_case("Microsoft.PowerShell.Core\\FileSystem")
        })
        .map_or(path, |(_, path)| path)
}

/// Whether a path establishes an absolute filesystem location.
pub(super) fn absolute_filesystem_path(path: &str, cwd: Option<&str>) -> Option<bool> {
    let path = filesystem_provider_path(path);
    if path.starts_with("\\\\") {
        let mut parts = path.trim_start_matches('\\').split('\\');
        return (parts
            .next()
            .is_some_and(|part| !part.is_empty() && !matches!(part, "?" | "."))
            && parts.next().is_some_and(|part| !part.is_empty()))
        .then_some(true);
    }
    let windows = path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && (path.get(1..3) == Some(":\\") || path.get(1..3) == Some(":/"))
        && !path[2..].contains(':');
    let posix = path.starts_with('/') && !cwd.is_some_and(|cwd| cwd.contains(':'));
    (windows || posix).then_some(windows)
}

/// `$HOME` of the analyzed host, which PowerShell expands `~` to. A Windows
/// environment usually has no `HOME`; there PowerShell takes the home
/// directory from `USERPROFILE` instead. Whichever of the two is set decides,
/// so a `HOME` this analysis cannot recover does not fall through to the other.
pub(super) fn home(nest: &Nest) -> Option<String> {
    ["HOME", "USERPROFILE"]
        .into_iter()
        .find_map(|name| environment(nest, name))
        .flatten()
}

/// One environment variable of the analyzed host: `None` where it is not set,
/// `Some(None)` where it is set to a value this analysis cannot recover.
fn environment(nest: &Nest, name: &str) -> Option<Option<String>> {
    if nest.current_environment_unsets().contains(name) {
        return None;
    }
    let current = nest
        .environments
        .borrow()
        .last()
        .and_then(|environment| environment.get(name).cloned());
    if let Some(value) = current {
        return Some(match value {
            Some(ResourceExpr::Literal { value }) => Some(value),
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path),
            _ => None,
        });
    }
    nest.context
        .and_then(|context| context.env.get(name))
        .cloned()
        .map(Some)
}

fn expand_environment_words(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    requests_web: bool,
    statement: &mut PsStatement,
    node: ProvenanceRef,
) -> bool {
    let mut complete = true;
    for word in statement.words.iter_mut().chain(
        statement
            .redirections
            .iter_mut()
            .filter_map(|redirection| redirection.target.as_mut()),
    ) {
        // A variable holding file content stays for the parameter that
        // consumes it, and a web request reads its own variables.
        if !word.expandable
            || session.content(word).is_some()
            || requests_web && session_variable(word)
        {
            continue;
        }
        match expand_home_variable(builder, nest, &word.text, node) {
            Ok(text) => word.text = text,
            Err(detail) => {
                powershell_boundary(builder, node, detail);
                complete = false;
            }
        }
    }
    complete
}

fn expand_home_variable(
    builder: &mut PlanBuilder,
    nest: &Nest,
    text: &str,
    node: ProvenanceRef,
) -> Result<String, &'static str> {
    let mut expanded = String::new();
    let mut rest = text;
    let mut read = Vec::new();
    let mut environment_read_once = |builder: &mut PlanBuilder, name: &str| {
        if !read.iter().any(|read: &String| read == name) {
            ps_environment_read(builder, node, name);
            read.push(name.to_string());
        }
    };
    while let Some(start) = rest.find('$') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let (found, length) =
            variable(after).ok_or("PowerShell expandable string contains an unmodeled variable")?;
        let token = &rest[start..start + 1 + length];
        rest = &after[length..];
        match found {
            // A switch value stays the literal the parameter binder reads.
            Variable::Boolean => expanded.push_str(token),
            // `$HOME` is PowerShell's automatic variable for the user's home
            // directory: HOME where the host sets it, otherwise USERPROFILE.
            Variable::Home => {
                environment_read_once(builder, "HOME");
                if environment(nest, "HOME").is_none() {
                    environment_read_once(builder, "USERPROFILE");
                }
                expanded.push_str(
                    &home(nest).ok_or("PowerShell HOME is not supplied by the host environment")?,
                );
            }
            Variable::Session => {
                return Err("PowerShell expandable string contains an unmodeled variable");
            }
            Variable::Environment(name) => {
                environment_read_once(builder, name);
                expanded.push_str(&environment(nest, name).flatten().ok_or(
                    "PowerShell environment variable is not supplied by the host environment",
                )?);
            }
        }
    }
    expanded.push_str(rest);
    builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    Ok(expanded)
}

enum Variable<'a> {
    Home,
    Environment(&'a str),
    /// `$true` or `$false`.
    Boolean,
    /// A variable the script itself assigns. Its value is known only where
    /// the session recorded the assignment.
    Session,
}

/// The variable named after a `$`, and how many bytes name it: `HOME`, an
/// environment variable `env:NAME`, `true` or `false`, or a session variable,
/// each optionally in braces. Any other drive-qualified name is not read.
fn variable(text: &str) -> Option<(Variable<'_>, usize)> {
    let identifier = |text: &str| {
        text.find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(text.len())
    };
    let (name, length) = match text.strip_prefix('{') {
        Some(braced) => {
            let end = braced.find('}')?;
            (&braced[..end], end + 2)
        }
        None => {
            let mut end = identifier(text);
            if text[..end].eq_ignore_ascii_case("env") && text[end..].starts_with(':') {
                end += 1 + identifier(&text[end + 1..]);
            }
            (&text[..end], end)
        }
    };
    let found = match name.split_once(':') {
        Some((drive, name))
            if drive.eq_ignore_ascii_case("env")
                && !name.is_empty()
                && identifier(name) == name.len() =>
        {
            Variable::Environment(name)
        }
        Some(_) => return None,
        None if name.eq_ignore_ascii_case("HOME") => Variable::Home,
        None if name.eq_ignore_ascii_case("true") || name.eq_ignore_ascii_case("false") => {
            Variable::Boolean
        }
        None if !name.is_empty() && identifier(name) == name.len() => Variable::Session,
        None => return None,
    };
    Some((found, length))
}

fn ps_environment_read(builder: &mut PlanBuilder, node: ProvenanceRef, name: &str) {
    builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("environment.read"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
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

fn removal(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &mut Session,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let bound = match bind(arguments, &REMOVE_ITEM) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let (paths, wildcards) = match bound.paths("Path") {
        Ok(Some(paths)) => paths,
        Ok(None) => {
            powershell_boundary(builder, node, "PowerShell Remove-Item has no literal path");
            return false;
        }
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let what_if = bound.switch("WhatIf");
    // Removing an item of the alias or function drive deletes that
    // definition, so the name stops resolving to what it named.
    let definitions = paths
        .iter()
        .filter_map(|path| {
            let (drive, name) = path.split_once(':')?;
            let alias = drive.eq_ignore_ascii_case("alias");
            (alias || drive.eq_ignore_ascii_case("function"))
                .then(|| (alias, name.trim_start_matches(['\\', '/'])))
        })
        .collect::<Vec<_>>();
    if !definitions.is_empty() {
        if !what_if {
            for (alias, name) in definitions {
                if alias {
                    session.define_alias(name);
                } else {
                    session.shadow(name);
                }
            }
        }
        return bound.complete(builder, node, "Remove-Item");
    }
    // -WhatIf reports the deletion instead of performing it.
    if what_if {
        return bound.complete(builder, node, "Remove-Item");
    }
    let mut complete = bound.complete(builder, node, "Remove-Item") & single(builder, node, paths);
    let recursive = bound.switch("Recurse");
    // -Include, -Exclude and -Filter admit items by name. A wildcard removes
    // the entries they admit among those the host lists for it, as a filtered
    // Move-Item's source departs (`admitted_entries`). Under -Recurse an
    // entry -Exclude leaves in place is not entered, and each admitted entry
    // is removed with everything beneath it. Whether -Include and -Filter
    // also find entries beneath one they do not admit, and how the filters
    // apply to a path without a wildcard, is not established: the removal
    // then names everything the path does, and a boundary says the filters
    // were not applied.
    let filters = [
        bound.values("Include"),
        bound.values("Exclude"),
        bound.values("Filter"),
    ];
    let filtered = filters.iter().any(Option::is_some);
    let admits = |name: &str, fold: bool| filters_admit(&filters, name, fold);
    let force = bound.switch("Force");
    let unmodeled_before = builder.budget().unmodeled_steps();
    let mut removed = Vec::new();
    for path in paths {
        let Some(resource) = resolved_path(
            builder,
            nest,
            path,
            wildcards,
            location,
            node,
            "Remove-Item",
        ) else {
            complete = false;
            continue;
        };
        // PowerShell refuses to remove the current location or one of its
        // ancestors (RemoveItemInUse) before it touches any child, whatever
        // -Recurse and -Force say.
        if location.is_some_and(|location| names_location_or_ancestor(&resource, location)) {
            continue;
        }
        if !filtered {
            removed.push(resource);
            continue;
        }
        // Every host question is asked before any removal: a removal leaves
        // the host's later answers undecided.
        let admitted = match &resource {
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            } if (!recursive || filters[0].is_none() && filters[2].is_none())
                && builder.is_host_realm() =>
            {
                let root = wildcard_root(glob).to_string();
                let depth = Some(glob_components_below(glob, &root));
                let outcome = builder
                    .budget()
                    .observe_listing(&root, depth, unmodeled_before);
                builder.node(
                    ProvenanceKind::HostObservation {
                        query: effinterp_proto::ObservationQuery::Listing { path: root, depth },
                        outcome: outcome.clone(),
                    },
                    &[node],
                );
                match outcome {
                    ObservationOutcome::Listing(listing) => {
                        admitted_entries(glob, &listing.entries, force, &admits)
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        match admitted {
            Some(paths) => removed.extend(paths.into_iter().map(|path| ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            })),
            None => {
                complete = false;
                powershell_boundary(
                    builder,
                    node,
                    "PowerShell Remove-Item filters are not applied to what it removes",
                );
                removed.push(resource);
            }
        }
    }
    for resource in removed {
        filesystem_effect(
            builder,
            "filesystem.delete",
            resource,
            [(
                "recursive".into(),
                effinterp_proto::AttrValue::Bool(recursive),
            )]
            .into(),
            node,
            "powershell/remove-item@v1",
        );
    }
    complete
}

/// Whether -Include, -Exclude and -Filter (`filters`, in that order) admit
/// an entry `name`, matched without regard to case under `fold`; `None`
/// where a pattern cannot be matched.
fn filters_admit(filters: &[Option<&[String]>; 3], name: &str, fold: bool) -> Option<bool> {
    let matches = |patterns: &[String]| -> Option<bool> {
        for pattern in patterns {
            if wildcard_match(pattern, name, fold)? {
                return Some(true);
            }
        }
        Some(false)
    };
    let [include, exclude, filter] = filters;
    Some(
        include.map_or(Some(true), matches)?
            && !exclude.map_or(Some(false), matches)?
            && filter.map_or(Some(true), matches)?,
    )
}

/// Whether `resource` is the one path `location` names or one of its
/// ancestors. Windows compares paths without case.
fn names_location_or_ancestor(resource: &ResourceExpr, location: &str) -> bool {
    let (
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        },
        Some(windows),
    ) = (resource, absolute_filesystem_path(location, None))
    else {
        return false;
    };
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: location },
    } = path_resource(location, windows, false)
    else {
        return false;
    };
    let (path, location) = if windows {
        (path.to_ascii_lowercase(), location.to_ascii_lowercase())
    } else {
        (path.clone(), location)
    };
    let path = path.trim_end_matches('/');
    location == path
        || location
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A cmdlet whose whole effect is one access to each path it binds, and the
/// effect slots it recorded. An `assigned` Get-Content stores the content in
/// a variable rather than writing it to the output.
fn file_cmdlet(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
    file: &FileCmdlet,
    assigned: bool,
) -> (bool, Vec<u32>) {
    let cmdlet = &file.cmdlet;
    let bound = match bind(arguments, cmdlet) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return (false, Vec::new());
        }
    };
    let path_parameter = cmdlet.positions[0];
    let (paths, wildcards) = match bound.paths(path_parameter) {
        Ok(Some(paths)) => paths,
        Ok(None) => {
            powershell_boundary(
                builder,
                node,
                &format!("PowerShell {} has no literal path", cmdlet.name),
            );
            return (false, Vec::new());
        }
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return (false, Vec::new());
        }
    };
    if bound.switch("WhatIf") {
        return (bound.complete(builder, node, cmdlet.name), Vec::new());
    }
    let mut complete = bound.complete(builder, node, cmdlet.name) & single(builder, node, paths);
    let mut attributes = crate::models::common::Attrs::new();
    if cmdlet.name.eq_ignore_ascii_case("Add-Content") || bound.switch("Append") {
        attributes.insert("append".into(), effinterp_proto::AttrValue::Bool(true));
    }
    // Get-Content writes the file's contents to its output.
    if file.operation == "filesystem.read" && !assigned {
        attributes.extend(crate::models::common::program_output_attrs());
    }
    // Out-File's -FilePath names one file; it does not expand wildcards.
    let wildcards = wildcards && path_parameter == "Path";
    let mut slots = Vec::new();
    for path in paths {
        let Some(resource) =
            resolved_path(builder, nest, path, wildcards, location, node, cmdlet.name)
        else {
            complete = false;
            continue;
        };
        slots.extend(filesystem_effect(
            builder,
            file.operation,
            resource,
            attributes.clone(),
            node,
            file.model,
        ));
    }
    (complete, slots)
}

/// `Move-Item` and `Rename-Item` remove each source entry and create it under
/// the destination name; `Rename-Item`'s new name stays in the source's
/// directory. `Copy-Item` reads each source and leaves it in place.
///
/// An existing destination directory receives each named source under the
/// source's own name, and a move or recursive copy also lands everything
/// beneath that entry. A move onto an existing entry is established only as
/// a file it replaces under -Force. What lands beneath a landing is read from
/// the host's listing of the source (`landed_entries`), and each landed entry
/// is a write of its own; where a wildcard's established selection lands only
/// inside the destination, or nowhere, the destination write states
/// `entries_only`. A listing the host does not give leaves the landing
/// written and an observation boundary. A source that does not
/// resolve still leaves the destination it names established.
fn move_item(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
    command: &str,
) -> bool {
    use effinterp_proto::{Fact, ObservationQuery, ObservationRefusal};
    // Steps before this one the analysis could not model on the filesystem;
    // the gaps this command records about itself come after.
    let unmodeled_before = builder.budget().unmodeled_steps();
    let rename = command.eq_ignore_ascii_case("Rename-Item");
    let copy = command.eq_ignore_ascii_case("Copy-Item");
    let (cmdlet, model) = if rename {
        (&RENAME_ITEM, "powershell/rename-item@v1")
    } else if copy {
        (&COPY_ITEM, "powershell/copy-item@v1")
    } else {
        (&MOVE_ITEM, "powershell/move-item@v1")
    };
    let bound = match bind(arguments, cmdlet) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let (sources, wildcards) = match bound.paths("Path") {
        Ok(Some((paths, wildcards))) if !paths.is_empty() && (!rename || paths.len() == 1) => {
            (paths, wildcards)
        }
        Ok(_) => {
            powershell_boundary(
                builder,
                node,
                &format!("PowerShell {command} does not name its source"),
            );
            return false;
        }
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    // A path qualified by another provider (HKLM:\, Env:) names an item of
    // that provider's store, not a file. PowerShell processes each source on
    // its own, so the filesystem sources still land.
    let items = sources
        .iter()
        .map(|source| filesystem_item(source))
        .collect::<Vec<_>>();
    let foreign = items.iter().any(Option::is_none);
    if foreign {
        powershell_boundary(
            builder,
            node,
            &format!("PowerShell {command} source is outside the filesystem provider"),
        );
    }
    if items.iter().all(Option::is_none) {
        return false;
    }
    if bound.switch("WhatIf") {
        return bound.complete(builder, node, command);
    }
    let mut complete = bound.complete(builder, node, command) && !foreign;
    let recursive = copy && bound.switch("Recurse");
    let recursive_attributes = || -> crate::models::common::Attrs {
        if recursive {
            [("recursive".into(), effinterp_proto::AttrValue::Bool(true))].into()
        } else {
            Default::default()
        }
    };
    let destination = match bound.value(cmdlet.positions[1]) {
        Ok(Some(name)) if rename => {
            // The new name is an entry of the source's directory.
            let source = items[0].unwrap_or_default();
            match source.rfind(['\\', '/']) {
                Some(parent) if !name.contains(['\\', '/']) => {
                    Some(format!("{}{name}", &source[..parent + 1]))
                }
                _ => None,
            }
        }
        Ok(destination) => destination.map(|destination| {
            filesystem_item(destination)
                .unwrap_or(destination)
                .to_string()
        }),
        Err(_) => None,
    };
    let destination_unread = destination.is_none();
    // Every host question is asked before any source effect: a wildcard's
    // removal leaves the host's later answers undecided.
    let target = destination.and_then(|destination| {
        let resource = resolved_path(builder, nest, &destination, false, location, node, command)?;
        let directory = observed_directory(builder, &resource, node);
        Some((destination, resource, directory))
    });
    let force = bound.switch("Force");
    // A moved directory brings everything beneath it, as a recursive copy
    // does.
    let tree = recursive || !copy;
    // -Container:$false copies the files beneath a source without the
    // directories that hold them, which is not modeled.
    let flattens = copy && bound.bound("Container") && !bound.switch("Container");
    if flattens {
        complete = false;
        powershell_boundary(
            builder,
            node,
            "PowerShell Copy-Item -Container:$false flattens what it copies, which is not modeled",
        );
    }
    // -Include, -Exclude and -Filter admit items by name before a copy
    // recurses into them. A named item they do not admit is not copied or
    // moved at all; whether they also choose among what a named directory
    // holds is not established (`landed_entries`).
    let filters = [
        bound.values("Include"),
        bound.values("Exclude"),
        bound.values("Filter"),
    ];
    let filtered = filters.iter().any(Option::is_some);
    // `fold` matches without regard to case. Whether PowerShell folds case
    // for these names off Windows is not established, so callers ask both.
    let admits = |name: &str, fold: bool| filters_admit(&filters, name, fold);
    // Whether -Exclude names an entry, whatever -Include and -Filter say.
    let excludes = |name: &str, fold: bool| -> Option<bool> {
        for pattern in filters[1].unwrap_or_default() {
            if wildcard_match(pattern, name, fold)? {
                return Some(true);
            }
        }
        Some(false)
    };
    // The resource each source names, if it resolved and was not left out.
    let mut resolved = Vec::new();
    let mut left_out = vec![false; items.len()];
    for (index, item) in items.iter().enumerate() {
        let Some(source) = item else {
            resolved.push(None);
            continue;
        };
        let Some(resource) =
            resolved_path(builder, nest, source, wildcards, location, node, command)
        else {
            complete = false;
            resolved.push(None);
            continue;
        };
        // PowerShell refuses to move or rename the current location or one
        // of its ancestors (MoveItemInUse, RenameItemInUse), as it refuses to
        // remove them. A copy leaves the source in place.
        if !copy && location.is_some_and(|location| names_location_or_ancestor(&resource, location))
        {
            left_out[index] = true;
            resolved.push(None);
            continue;
        }
        // A filtered wildcard departs as the entries its filters admit, once
        // the host has listed them (`admitted` below).
        if filtered && !matches!(resource, ResourceExpr::Pattern { .. }) {
            // Windows folds case; elsewhere both readings are asked.
            let windows = matches!(
                &resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } if drive_rooted(path)
            );
            let admitted = entry_name(source)
                .and_then(|name| Some((admits(name, true)?, admits(name, windows)?)));
            match admitted {
                Some((true, true)) => {}
                Some((false, false)) => {
                    // -Include and -Filter may pass over a named directory
                    // and choose among what it holds, or not apply to a path
                    // without a wildcard at all. Unless -Exclude names it,
                    // a directory that brings its tree is kept, with what
                    // lands left to `landed_entries`.
                    let excluded = entry_name(source).is_none_or(|name| {
                        excludes(name, true) != Some(false)
                            || excludes(name, windows) != Some(false)
                    });
                    let directory = match &resource {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } => match builder.budget().observe_path(path) {
                            ObservationOutcome::Path(fact) => {
                                let kind = match &fact.followed {
                                    Fact::Known(target) => target.kind.known().copied(),
                                    Fact::Unavailable(_) => Some(fact.kind),
                                };
                                kind.is_none_or(|kind| kind == PathKind::Directory)
                            }
                            _ => true,
                        },
                        _ => true,
                    };
                    if excluded || !tree || !directory {
                        left_out[index] = true;
                        resolved.push(None);
                        continue;
                    }
                    complete = false;
                    builder.boundary(model_gap(
                        node,
                        format!(
                            "PowerShell {command} -Include or -Filter does not match a named directory, and whether it still copies what the directory holds is not established"
                        ),
                    ));
                }
                // Admitted under one case rule only: the source is kept.
                Some(_) => {
                    complete = false;
                    builder.boundary(model_gap(
                        node,
                        format!(
                            "PowerShell {command} filters admit a named source only under one case rule, which is not modeled"
                        ),
                    ));
                }
                None => {
                    complete = false;
                    powershell_boundary(
                        builder,
                        node,
                        &format!(
                            "PowerShell {command} filters could not be matched against a named source"
                        ),
                    );
                }
            }
        }
        resolved.push(Some(resource));
    }
    // A destination matters only for a source that is moved or copied.
    if destination_unread && resolved.iter().any(Option::is_some) {
        powershell_boundary(
            builder,
            node,
            &format!("PowerShell {command} destination is not one literal path"),
        );
    }
    // What each source is, as the host saw it. The view no longer describes
    // a source this command changed earlier.
    let observations = builder.budget().observations.is_some();
    let roots = resolved
        .iter()
        .map(|left| match left {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path.clone()),
            Some(ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            }) => Some(wildcard_root(glob).to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let facts = roots
        .iter()
        .map(|root| {
            let root = root.as_ref()?;
            observations.then(|| builder.budget().observe_path(root))
        })
        .collect::<Vec<_>>();
    let current = |index: usize| {
        !matches!(
            facts[index],
            Some(ObservationOutcome::Refused(
                ObservationRefusal::Stale | ObservationRefusal::Ambiguous
            ))
        )
    };
    let source_kind = |index: usize| match &facts[index] {
        Some(ObservationOutcome::Path(fact)) => match &fact.followed {
            Fact::Known(target) => target.kind.known().copied(),
            Fact::Unavailable(_) => (fact.kind != PathKind::Symlink).then_some(fact.kind),
        },
        _ => None,
    };
    let wildcard = |index: usize| matches!(resolved[index], Some(ResourceExpr::Pattern { .. }));
    // A wildcard's entries land inside an existing directory, and elsewhere
    // replace or become the destination; what it selects is read from the
    // host's listing of the directory it selects beneath. A source this
    // command changed earlier, or a flattened copy, holds what the host did
    // not see, so the destination stays written instead.
    let mirrors_wildcard = |index: usize| wildcard(index) && current(index) && !flattens;
    // What each directory whose entries land holds, asked before any source
    // effect for the same reason.
    let listings = (0..resolved.len())
        .map(|index| {
            let root = roots[index].as_ref()?;
            let lands = !rename
                && target.is_some()
                && builder.is_host_realm()
                && (mirrors_wildcard(index) || tree && current(index) && !flattens);
            if !lands || source_kind(index) != Some(PathKind::Directory) {
                return None;
            }
            // A copy without -Recurse lands only what the wildcard's own
            // components reach. So does a move as modeled: a moved file holds
            // nothing, and a moved directory is not established anyway.
            let depth = match &resolved[index] {
                Some(ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { glob, .. },
                }) if !recursive => Some(glob_components_below(glob, root)),
                _ => None,
            };
            let outcome = builder
                .budget()
                .observe_listing(root, depth, unmodeled_before);
            builder.node(
                ProvenanceKind::HostObservation {
                    query: ObservationQuery::Listing {
                        path: root.clone(),
                        depth,
                    },
                    outcome: outcome.clone(),
                },
                &[node],
            );
            Some(outcome)
        })
        .collect::<Vec<_>>();
    if !rename && (0..resolved.len()).any(|index| resolved[index].is_some() && !current(index)) {
        complete = false;
        powershell_boundary(
            builder,
            node,
            &format!(
                "PowerShell {command} source changed earlier in the command, so what it holds is not modeled"
            ),
        );
    }
    // The entries a filtered wildcard reads or removes: those the listing
    // shows its pattern matches and its filters admit. Where the listing or a
    // reading of it leaves that open, the departure names every entry the
    // wildcard matches, including those the filters leave in place.
    let mut admitted = vec![None; resolved.len()];
    for index in 0..resolved.len() {
        let Some(ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob, .. },
        }) = &resolved[index]
        else {
            continue;
        };
        if !filtered {
            continue;
        }
        admitted[index] = match &listings[index] {
            Some(ObservationOutcome::Listing(listing)) => {
                admitted_entries(glob, &listing.entries, force, &admits)
            }
            _ => None,
        };
        if admitted[index].is_none() {
            complete = false;
            powershell_boundary(
                builder,
                node,
                &format!(
                    "PowerShell {command} filters are not applied to the source it reads or removes"
                ),
            );
        }
    }
    // Where each named source lands: under its own name in an existing
    // directory, as the destination itself where it is not one, and where
    // the host did not say which, possibly either. A move onto an existing
    // entry fails, replaces it (a file under -Force) or, across volumes,
    // merges into it; only a replaced file is established.
    let mut landings = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let (Some(source), Some((destination, resource, directory))) = (item, &target) else {
            landings.push(None);
            continue;
        };
        if rename || left_out[index] || wildcard(index) {
            landings.push(None);
            continue;
        }
        if *directory == Some(false) {
            landings.push(Some((resource.clone(), true)));
            continue;
        }
        let Some(name) = entry_name(source) else {
            landings.push(None);
            continue;
        };
        let separator = if destination.contains('\\') {
            '\\'
        } else {
            '/'
        };
        let child = format!(
            "{}{separator}{name}",
            destination.trim_end_matches(['\\', '/'])
        );
        let Some(landing) = resolved_path(builder, nest, &child, false, location, node, command)
        else {
            landings.push(None);
            continue;
        };
        // What already occupies the landing: `Some(None)` where nothing
        // does, `None` where the host did not answer. A link is what it
        // names, as PowerShell's File.Exists sees it.
        let occupant = match (&landing, copy || *directory != Some(true)) {
            (
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                },
                false,
            ) if observations && path.starts_with('/') => {
                match builder.budget().observe_path(path) {
                    ObservationOutcome::Path(fact) => match fact.kind {
                        PathKind::Missing => Some(None),
                        PathKind::Symlink => match &fact.followed {
                            Fact::Known(target) => target.kind.known().copied().map(Some),
                            Fact::Unavailable(_) => None,
                        },
                        kind => Some(Some(kind)),
                    },
                    ObservationOutcome::Listing(_) | ObservationOutcome::Refused(_) => None,
                }
            }
            _ => Some(None),
        };
        match occupant {
            Some(None) => landings.push(Some((landing, true))),
            // -Force replaces an existing file with a file, never a
            // directory.
            Some(Some(PathKind::File)) if force && source_kind(index) == Some(PathKind::File) => {
                landings.push(Some((landing, false)));
            }
            _ => {
                complete = false;
                powershell_boundary(
                    builder,
                    node,
                    &format!(
                        "PowerShell {command} destination entry exists or is unobserved, so whether the move fails, replaces or merges is not established"
                    ),
                );
                landings.push(None);
            }
        }
    }
    // The effect each source's content leaves through.
    let mut departures = Vec::new();
    for (resource, admitted) in resolved.iter().zip(&admitted) {
        let Some(resource) = resource.clone() else {
            departures.push(None);
            continue;
        };
        let resource = match admitted.as_deref() {
            None => resource,
            // Nothing the wildcard matches is admitted, so nothing departs.
            Some([]) => {
                departures.push(None);
                continue;
            }
            Some([path]) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: path.clone() },
            },
            Some(paths) => ResourceExpr::Union {
                alternatives: paths
                    .iter()
                    .map(|path| ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: path.clone() },
                    })
                    .collect(),
            },
        };
        departures.push(if copy {
            filesystem_effect(
                builder,
                "filesystem.read",
                resource,
                recursive_attributes(),
                node,
                model,
            )
        } else {
            let moved = filesystem_effect(
                builder,
                "filesystem.move",
                resource.clone(),
                Default::default(),
                node,
                model,
            );
            filesystem_effect(
                builder,
                "filesystem.delete",
                resource,
                Default::default(),
                node,
                model,
            );
            moved
        });
    }
    let Some((_, resource, directory)) = target else {
        return false;
    };
    let landing_path = |landing: &ResourceExpr| match landing {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    };
    // What each source lands beneath or instead of its landing: a wildcard
    // beneath the destination, a named source that brings its tree beneath
    // the entry it lands as.
    let shape = LandingShape {
        moves: !copy,
        tree,
        force,
        inside: directory == Some(true),
        filtered,
        admits: &admits,
        excludes: &excludes,
    };
    let landed = (0..items.len())
        .map(|index| {
            if rename || !builder.is_host_realm() {
                return None;
            }
            match &resolved[index] {
                Some(ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { glob, .. },
                }) if mirrors_wildcard(index) => Some(landed_entries(
                    Some((glob, wildcard_root(glob))),
                    source_kind(index),
                    listings[index].as_ref(),
                    &landing_path(&resource)?,
                    &shape,
                )),
                Some(ResourceExpr::Concrete { .. }) if tree && current(index) && !flattens => {
                    let (landing, true) = landings[index].as_ref()? else {
                        return None;
                    };
                    Some(landed_entries(
                        None,
                        source_kind(index),
                        listings[index].as_ref(),
                        &landing_path(landing)?,
                        &shape,
                    ))
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let withdrawn = |index: usize| {
        landed[index]
            .as_ref()
            .is_some_and(|landed| landed.withdrawn)
    };
    // The destination itself is written for every source but a wildcard whose
    // established selection lands only inside it, or nowhere.
    let written = if rename
        || (0..items.len())
            .any(|index| items[index].is_some() && !left_out[index] && !withdrawn(index))
    {
        filesystem_effect(
            builder,
            "filesystem.write",
            resource.clone(),
            recursive_attributes(),
            node,
            model,
        )
    } else {
        None
    };
    // A wildcard whose selection lands only inside the destination still
    // adds entries to it, and that write is the one endpoint its departure
    // reaches. `entries_only` states that the destination itself is not
    // what it writes: the entries are the writes listed beside it.
    let entries_written = if (0..items.len()).any(withdrawn) {
        let mut attributes = recursive_attributes();
        attributes.insert(
            "entries_only".into(),
            effinterp_proto::AttrValue::Bool(true),
        );
        filesystem_effect(
            builder,
            "filesystem.write",
            resource.clone(),
            attributes,
            node,
            model,
        )
    } else {
        None
    };
    for (index, departed) in departures.iter().enumerate() {
        let endpoint = if withdrawn(index) {
            entries_written
        } else {
            written
        };
        if let (Some(departed), Some(endpoint)) = (departed, endpoint) {
            builder.transfer_binding(TransferBinding::new(*departed, endpoint));
        }
    }
    if rename {
        return complete;
    }
    for (index, departed) in departures.iter().enumerate() {
        if !wildcard(index)
            && let Some((landing, _)) = &landings[index]
            && *landing != resource
        {
            let landed = filesystem_effect(
                builder,
                "filesystem.write",
                landing.clone(),
                recursive_attributes(),
                node,
                model,
            );
            // A move's one modeled endpoint is the destination it names; the
            // bridge reads several transfer destinations as an unknown
            // endpoint.
            if copy && let (Some(departed), Some(landed)) = (departed, landed) {
                builder.transfer_binding(TransferBinding::new(*departed, landed));
            }
        }
        let Some(landed) = &landed[index] else {
            continue;
        };
        let mut gaps = Vec::new();
        match landed.established {
            Ok(()) if landed.paths.len() > MAX_LANDED_ENTRIES => gaps.push(Unestablished::Model(
                "lands more entries than are written one by one, so its landing's subtree is written",
            )),
            Ok(()) => {}
            Err(gap) => gaps.push(gap),
        }
        if landed.uncertain {
            gaps.push(Unestablished::Model(
                "selects entries whose case or hidden-item matching on this host is not established, so every entry it may select is written",
            ));
        }
        for gap in gaps {
            complete = false;
            builder.boundary_with_coverage(
                match gap {
                    Unestablished::Unobserved => Boundary {
                        reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                        detail: Some(format!(
                            "PowerShell {command} source listing is unavailable, so what lands is not established"
                        )),
                        ..model_gap(node, String::new())
                    },
                    Unestablished::Model(why) => {
                        model_gap(node, format!("PowerShell {command} source {why}"))
                    }
                },
                CoverageLevel::Partial,
            );
        }
        // A source holding more than the engine lands one by one may write
        // anything beneath its landing.
        let overflow = (landed.paths.len() > MAX_LANDED_ENTRIES).then(|| ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath {
                glob: format!(
                    "{}/**",
                    crate::paths::escape_fs_glob_path(landed.landing.trim_end_matches('/'))
                ),
                narrowing: Default::default(),
            },
        });
        let resources = match overflow {
            Some(subtree) => vec![subtree],
            None => landed
                .paths
                .iter()
                .map(|path| ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: path.clone() },
                })
                .collect(),
        };
        for landed_resource in resources {
            let entry = filesystem_effect(
                builder,
                "filesystem.write",
                landed_resource,
                Default::default(),
                node,
                model,
            );
            if copy && let (Some(departed), Some(entry)) = (departed, entry) {
                builder.transfer_binding(TransferBinding::new(*departed, entry));
            }
        }
    }
    complete
}

/// How a copy or move lands what one source holds.
struct LandingShape<'a> {
    moves: bool,
    /// Everything beneath a landed directory lands too.
    tree: bool,
    /// A wildcard selects hidden entries, and a move replaces an existing
    /// file, only under -Force.
    force: bool,
    /// The destination is an existing directory, so a wildcard's entries land
    /// inside it under their own names.
    inside: bool,
    /// -Include, -Exclude or -Filter is given.
    filtered: bool,
    /// Whether those filters admit an entry name; `None` where the name
    /// cannot be matched.
    admits: &'a dyn Fn(&str, bool) -> Option<bool>,
    /// Whether -Exclude alone names an entry.
    excludes: &'a dyn Fn(&str, bool) -> Option<bool>,
}

/// Most entries one source lands as writes of their own. Past it the landing's
/// whole subtree is written instead, so a large tree cannot spend the effect
/// budget that later commands need.
const MAX_LANDED_ENTRIES: usize = 1024;

/// What one copied or moved source lands.
struct Landed {
    /// Where the source's entries land beneath.
    landing: String,
    /// Every path an entry of the source is written to.
    paths: BTreeSet<String>,
    /// The listing establishes everything that lands. Otherwise the landing
    /// stays written, `paths` are only the entries known to land, and the
    /// error says why.
    established: Result<(), Unestablished>,
    /// Only entries are written, not the landing itself: an established
    /// wildcard selection lands only inside it, or is empty.
    withdrawn: bool,
    /// An entry is selected only under one reading of PowerShell's case or
    /// hidden-item rule on this host, and is written.
    uncertain: bool,
}

/// Why a copy or move does not establish what lands.
#[derive(Clone, Copy, Debug)]
enum Unestablished {
    /// The host did not list the source.
    Unobserved,
    /// The listing is in hand, and what the command makes of it is not
    /// modeled; the text completes "PowerShell <command> source ...".
    Model(&'static str),
}

/// A filesystem boundary for what a command does that is not modeled.
fn model_gap(node: ProvenanceRef, detail: String) -> Boundary {
    Boundary {
        reason: BoundaryReason::MODEL_COVERAGE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("filesystem")],
        provenance: vec![node],
        limit: None,
        detail: Some(detail),
    }
}

/// The entries a copy or move lands, from the host's listing of its source:
/// `kind` is what the source (a wildcard's root) is, `listing` the host's
/// answer for it when it is a directory.
///
/// A named source lands at `landing`, and everything beneath it at the same
/// relative path. Whether the filters also choose among what a named
/// directory holds is not established: an entry they admit, beneath
/// directories -Exclude does not name, lands either way, and any other is
/// left open. A
/// wildcard (`pattern`, the glob and the directory it selects beneath)
/// selects each entry the whole pattern matches and the filters admit. Inside
/// an existing directory each lands under its own name, with everything
/// beneath it under `tree`; a moved entry lands only as a file replacing what
/// is there under -Force, since a moved directory fails or merges on an
/// existing one. Elsewhere the entries replace or become the landing, which
/// is not modeled. A link or special file is not modeled either: what lands
/// for it depends on how the command treats it.
fn landed_entries(
    pattern: Option<(&str, &str)>,
    kind: Option<PathKind>,
    listing: Option<&ObservationOutcome>,
    landing: &str,
    shape: &LandingShape<'_>,
) -> Landed {
    let open = |gap| Landed {
        landing: landing.to_owned(),
        paths: BTreeSet::new(),
        established: Err(gap),
        withdrawn: false,
        uncertain: false,
    };
    // Only a directory holds entries; a file or a missing entry holds none.
    let entries: &[ListedEntry] = match (kind, listing) {
        (Some(PathKind::Directory), Some(ObservationOutcome::Listing(fact))) => &fact.entries,
        (Some(PathKind::Directory), _) | (None, _) => return open(Unestablished::Unobserved),
        (Some(_), _) => &[],
    };
    let join = |relative: &str| format!("{}/{relative}", landing.trim_end_matches('/'));
    let special = |entry: &ListedEntry| !matches!(entry.kind, PathKind::File | PathKind::Directory);
    const SPECIAL: Unestablished =
        Unestablished::Model("reaches a link or special entry, whose copy or move is not modeled");
    let beneath = |root: &str| {
        let prefix = format!("{root}/");
        entries
            .iter()
            .filter(move |entry| entry.path.starts_with(&prefix))
    };
    let Some((glob, root)) = pattern else {
        let admitted = |entry: &&ListedEntry| {
            let (above, name) = entry.path.rsplit_once('/').unwrap_or(("", &entry.path));
            !shape.filtered
                || (shape.admits)(name, true) == Some(true)
                    && (shape.admits)(name, false) == Some(true)
                    && above
                        .split('/')
                        .filter(|name| !name.is_empty())
                        .all(|name| {
                            (shape.excludes)(name, true) == Some(false)
                                && (shape.excludes)(name, false) == Some(false)
                        })
        };
        return Landed {
            paths: entries
                .iter()
                .filter(admitted)
                .map(|entry| join(&entry.path))
                .collect(),
            established: if !entries.iter().all(|entry| admitted(&entry)) {
                Err(Unestablished::Model(
                    "holds entries its filters may leave out, which is not modeled",
                ))
            } else if entries.iter().any(special) {
                Err(SPECIAL)
            } else {
                Ok(())
            },
            ..open(Unestablished::Unobserved)
        };
    };
    let mut landed = Landed {
        established: Ok(()),
        ..open(Unestablished::Unobserved)
    };
    let unestablished = |landed: &mut Landed, gap| {
        if landed.established.is_ok() {
            landed.established = Err(gap);
        }
    };
    let mut selected = false;
    for entry in entries {
        let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
        let Some(selection) = wildcard_selects(glob, root, entry, shape.force, shape.admits) else {
            return open(Unestablished::Model(
                "wildcard or filters could not be matched, which is not modeled",
            ));
        };
        let Some(uncertain) = selection else {
            continue;
        };
        landed.uncertain |= uncertain;
        selected = true;
        if !shape.inside {
            continue;
        }
        if special(entry) || shape.tree && beneath(&entry.path).any(special) {
            unestablished(&mut landed, SPECIAL);
        }
        if shape.moves {
            if shape.force && entry.kind == PathKind::File {
                landed.paths.insert(join(name));
            } else {
                unestablished(
                    &mut landed,
                    Unestablished::Model(
                        "moves an entry that fails, replaces or merges with what the destination holds, which is not modeled",
                    ),
                );
            }
            continue;
        }
        landed.paths.insert(join(name));
        if shape.tree {
            landed.paths.extend(
                beneath(&entry.path)
                    .map(|below| join(&format!("{name}{}", &below.path[entry.path.len()..]))),
            );
        }
    }
    if selected && !shape.inside {
        unestablished(
            &mut landed,
            Unestablished::Model("entries replace or become the destination, which is not modeled"),
        );
    }
    landed.withdrawn = landed.established.is_ok() && (shape.inside || !selected);
    landed
}

/// Whether the wildcard `glob`, which selects beneath `root`, and the filters
/// select a listed entry: `Some(None)` where they do not, and otherwise
/// whether they do only under one reading of PowerShell's case or hidden-item
/// rule on this host. `None` where the wildcard or a filter cannot be matched.
///
/// A drive-rooted wildcard is matched as Windows matches it: without regard
/// to case, and with hidden items marked by an attribute the listing does not
/// carry. Elsewhere a dot name is hidden unless `force`, and whether case is
/// folded is not established, so both readings are asked.
fn wildcard_selects(
    glob: &str,
    root: &str,
    entry: &ListedEntry,
    force: bool,
    admits: &dyn Fn(&str, bool) -> Option<bool>,
) -> Option<Option<bool>> {
    let windows = drive_rooted(glob);
    let root_components = glob_components_below(glob, root) as usize;
    let patterns = glob.split('/').collect::<Vec<_>>();
    let patterns = &patterns[patterns.len() - root_components.min(patterns.len())..];
    let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
    let components = entry.path.split('/').collect::<Vec<_>>();
    if components.len() != patterns.len() {
        return Some(None);
    }
    // Whether a component a wildcard selects is a dot name, the pattern
    // itself starting with a `.` or not.
    let dotted = |spelled: bool| {
        !force
            && components.iter().zip(patterns).any(|(component, pattern)| {
                component.starts_with('.')
                    && pattern.contains(['*', '?', '['])
                    && pattern.starts_with('.') == spelled
            })
    };
    let reading = |fold: bool| -> Option<bool> {
        for (component, pattern) in components.iter().zip(patterns) {
            if !wildcard_match(pattern, component, fold)? {
                return Some(false);
            }
        }
        admits(name, fold)
    };
    let (folded, exact) = (reading(true)?, reading(windows)?);
    // Off Windows a wildcard hides dot names; whether a pattern that spells
    // the dot, as `.*`, still hides them is not established, so such an entry
    // is selected and marked uncertain.
    let hidden = dotted(false);
    if !(folded || exact) || hidden && !windows {
        return Some(None);
    }
    Some(Some(folded != exact || dotted(true) || hidden && windows))
}

/// Most entries a filtered wildcard departs as one by one. Past it the
/// departure names the wildcard itself.
const MAX_ADMITTED_ENTRIES: usize = 64;

/// The paths of the listed `entries` that the wildcard `glob` matches and the
/// filters admit. `None` where that is not established: a reading of the
/// wildcard, the filters or the host's case or hidden-item rule is open, or
/// more entries are admitted than depart one by one.
fn admitted_entries(
    glob: &str,
    entries: &[ListedEntry],
    force: bool,
    admits: &dyn Fn(&str, bool) -> Option<bool>,
) -> Option<Vec<String>> {
    let root = wildcard_root(glob);
    let mut paths = Vec::new();
    for entry in entries {
        match wildcard_selects(glob, root, entry, force, admits)? {
            None => {}
            Some(true) => return None,
            Some(false) if paths.len() == MAX_ADMITTED_ENTRIES => return None,
            Some(false) => paths.push(format!("{}/{}", root.trim_end_matches('/'), entry.path)),
        }
    }
    Some(paths)
}

/// Whether `path` is rooted at a Windows drive, as `C:/`.
fn drive_rooted(path: &str) -> bool {
    path.as_bytes().get(1) == Some(&b':')
}

/// How many path components `glob` has below its wildcard root `root`.
fn glob_components_below(glob: &str, root: &str) -> u32 {
    glob[root.len().min(glob.len())..]
        .trim_start_matches('/')
        .split('/')
        .count() as u32
}

/// PowerShell's wildcard language (about_Wildcards) over one path
/// component: `*` any run, `?` one character, `[abc]` and `[a-c]` one of a
/// set, and a backtick escaping the next character. A bracket set has no
/// negation: `[!e]` is `!` or `e`. `fold` compares without regard to case.
/// `None` for an unterminated set, which PowerShell rejects.
fn wildcard_match(pattern: &str, text: &str, fold: bool) -> Option<bool> {
    enum WildcardToken {
        Any,
        One,
        Set(Vec<(char, char)>),
        Literal(char),
    }
    let same = |a: char, b: char| {
        if fold {
            a.to_lowercase().eq(b.to_lowercase())
        } else {
            a == b
        }
    };
    let mut tokens = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        tokens.push(match c {
            '*' => WildcardToken::Any,
            '?' => WildcardToken::One,
            '`' => WildcardToken::Literal(chars.next().unwrap_or('`')),
            '[' => {
                // Each member, and whether it was escaped.
                let mut members = Vec::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        ']' => {
                            closed = true;
                            break;
                        }
                        '`' => members.push((chars.next()?, true)),
                        c => members.push((c, false)),
                    }
                }
                if !closed {
                    return None;
                }
                let mut set = Vec::new();
                let mut index = 0;
                while index < members.len() {
                    // An unescaped `-` between two members is a range.
                    if members.get(index + 1) == Some(&('-', false)) && index + 2 < members.len() {
                        set.push((members[index].0, members[index + 2].0));
                        index += 3;
                    } else {
                        set.push((members[index].0, members[index].0));
                        index += 1;
                    }
                }
                WildcardToken::Set(set)
            }
            c => WildcardToken::Literal(c),
        });
    }
    let text = text.chars().collect::<Vec<_>>();
    // matched[j]: the tokens so far can match the first j characters.
    let mut matched = vec![false; text.len() + 1];
    matched[0] = true;
    for token in &tokens {
        let mut next = vec![false; text.len() + 1];
        for j in 0..=text.len() {
            match token {
                WildcardToken::Any => next[j] = matched[j] || j > 0 && next[j - 1],
                _ if j == 0 => {}
                WildcardToken::One => next[j] = matched[j - 1],
                WildcardToken::Literal(c) => next[j] = matched[j - 1] && same(*c, text[j - 1]),
                WildcardToken::Set(set) => {
                    let c = text[j - 1];
                    next[j] = matched[j - 1]
                        && set.iter().any(|&(low, high)| {
                            same(low, c)
                                || same(high, c)
                                || (low..=high).contains(&c)
                                || fold
                                    && c.to_lowercase()
                                        .chain(c.to_uppercase())
                                        .any(|c| (low..=high).contains(&c))
                        });
                }
            }
        }
        matched = next;
    }
    Some(matched[text.len()])
}

/// Whether the host says a destination is a directory, or a link to one.
/// `None` where it was not asked or did not answer.
fn observed_directory(
    builder: &mut PlanBuilder,
    resource: &ResourceExpr,
    node: ProvenanceRef,
) -> Option<bool> {
    use effinterp_proto::{Fact, ObservationOutcome, ObservationQuery, PathKind};
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = resource
    else {
        return None;
    };
    let budget = builder.budget();
    if budget.observations.is_none() || !builder.is_host_realm() || !path.starts_with('/') {
        return None;
    }
    let outcome = budget.observe_path(path);
    builder.node(
        ProvenanceKind::HostObservation {
            query: ObservationQuery::Path { path: path.clone() },
            outcome: outcome.clone(),
        },
        &[node],
    );
    match outcome {
        ObservationOutcome::Path(fact) => Some(match &fact.followed {
            Fact::Known(target) => target.kind == Fact::Known(PathKind::Directory),
            Fact::Unavailable(_) => fact.kind == PathKind::Directory,
        }),
        ObservationOutcome::Listing(_) | ObservationOutcome::Refused(_) => None,
    }
}

/// The filesystem path an item path names: the path itself, or the rest of a
/// path qualified by the FileSystem provider. `None` for a path qualified by
/// another provider.
fn filesystem_item(path: &str) -> Option<&str> {
    for provider in ["Microsoft.PowerShell.Core\\FileSystem::", "FileSystem::"] {
        if path
            .get(..provider.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(provider))
        {
            return Some(&path[provider.len()..]);
        }
    }
    (!path.contains(':') || absolute_filesystem_path(path, None).is_some()).then_some(path)
}

/// The directory a wildcard selects entries beneath: the path up to the
/// component holding its first wildcard.
fn wildcard_root(glob: &str) -> &str {
    let first = glob.find(['*', '?', '[']).unwrap_or(glob.len());
    match glob[..first].rfind('/') {
        Some(0) | None => "/",
        Some(end) => &glob[..end],
    }
}

/// The name a source entry keeps when it lands in a directory: its last
/// path component.
fn entry_name(source: &str) -> Option<&str> {
    let name = source
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()?;
    (!name.is_empty() && name != "." && name != ".." && name != "~").then_some(name)
}

/// `New-Item -ItemType HardLink` gives the target's file a second name, so
/// writing through the created entry changes the target.
fn new_item(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let bound = match bind(arguments, &NEW_ITEM) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let hard_link =
        matches!(bound.value("ItemType"), Ok(Some(kind)) if kind.eq_ignore_ascii_case("HardLink"));
    // -Target is an alias of -Value.
    let target = match (bound.value("Target"), bound.value("Value")) {
        (Ok(Some(target)), Ok(None)) | (Ok(None), Ok(Some(target))) => Some(target),
        _ => None,
    };
    let (Some(target), Ok(Some(link)), true) = (target, bound.value("Path"), hard_link) else {
        powershell_boundary(
            builder,
            node,
            "PowerShell New-Item is outside the modeled hard-link grammar",
        );
        return false;
    };
    if bound.switch("WhatIf") {
        return bound.complete(builder, node, "New-Item");
    }
    let complete = bound.complete(builder, node, "New-Item");
    let (Some(target), Some(link)) = (
        resolved_path(builder, nest, target, false, location, node, "New-Item"),
        resolved_path(builder, nest, link, false, location, node, "New-Item"),
    ) else {
        return false;
    };
    let source = filesystem_effect(
        builder,
        "filesystem.read",
        target,
        [("metadata".into(), effinterp_proto::AttrValue::Bool(true))].into(),
        node,
        "powershell/new-item-hardlink@v1",
    );
    let created = filesystem_effect(
        builder,
        "filesystem.create",
        link,
        [("symlink".into(), effinterp_proto::AttrValue::Bool(false))].into(),
        node,
        "powershell/new-item-hardlink@v1",
    );
    if let (Some(source), Some(created)) = (source, created) {
        builder.transfer_binding(TransferBinding::exact(source, created));
    }
    complete
}

/// `Invoke-WebRequest` and `Invoke-RestMethod` with `-OutFile` store the
/// response body in that file; with `-InFile` or `-Body` and a POST, PUT or
/// PATCH method they send that file or value to the URI.
fn web_request(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let bound = match bind(arguments, &WEB_REQUEST) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    // Only -Body and the common variable parameters read a `$name`
    // argument here; anywhere else its value is unknown.
    let readable = ["Body"]
        .iter()
        .chain(VARIABLE_PARAMETERS)
        .filter_map(|parameter| bound.word(parameter))
        .collect::<Vec<_>>();
    if arguments
        .iter()
        .enumerate()
        .any(|(index, argument)| session_variable(argument) && !readable.contains(&index))
    {
        powershell_boundary(
            builder,
            node,
            "PowerShell web request argument is a variable the grammar cannot read",
        );
        return false;
    }
    if bound.bound("InFile") || bound.bound("Body") {
        return upload(builder, nest, session, arguments, &bound, location, node);
    }
    let (Ok(Some(uri)), Ok(Some(file))) = (bound.value("Uri"), bound.value("OutFile")) else {
        powershell_boundary(
            builder,
            node,
            "PowerShell web request does not name one URI and one -OutFile",
        );
        return false;
    };
    let complete = bound.complete(builder, node, "Invoke-WebRequest");
    download(
        builder,
        nest,
        uri,
        file,
        location,
        node,
        "powershell/invoke-webrequest@v1",
    ) && complete
}

/// A web request that sends `-InFile`'s file or `-Body`'s value to its URI.
/// The body's source is the file `-InFile` reads, or the Get-Content read a
/// `-Body $name` variable holds; a literal body has none.
fn upload(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    arguments: &[PsWord],
    bound: &PsBoundParameters,
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let method = bound.value("Method").ok().flatten();
    if !method.is_some_and(|method| {
        ["Post", "Put", "Patch"]
            .iter()
            .any(|upload| upload.eq_ignore_ascii_case(method))
    }) {
        powershell_boundary(
            builder,
            node,
            "PowerShell web request body is sent without a POST, PUT or PATCH method",
        );
        return false;
    }
    let (Ok(Some(uri)), Ok(in_file), Ok(body)) = (
        bound.value("Uri"),
        bound.value("InFile"),
        bound.value("Body"),
    ) else {
        powershell_boundary(
            builder,
            node,
            "PowerShell web request does not name one URI and one body",
        );
        return false;
    };
    if bound.bound("OutFile") || in_file.is_some() && body.is_some() {
        powershell_boundary(
            builder,
            node,
            "PowerShell web request combines -InFile, -Body or -OutFile",
        );
        return false;
    }
    let mut complete = bound.complete(builder, node, "Invoke-WebRequest");
    let model = "powershell/invoke-webrequest-upload@v1";
    let source = match (in_file, body) {
        (Some(file), _) => {
            let Some(resource) =
                resolved_path(builder, nest, file, false, location, node, "upload")
            else {
                return false;
            };
            filesystem_effect(
                builder,
                "filesystem.read",
                resource,
                crate::models::common::program_input_attrs(),
                node,
                model,
            )
        }
        (None, Some(_)) => match bound.word("Body").map(|index| &arguments[index]) {
            // The request is still sent; only what its body carries is
            // unknown.
            Some(body) if session_variable(body) => {
                let content = session.content(body);
                if content.is_none() {
                    powershell_boundary(
                        builder,
                        node,
                        "PowerShell web request body is a variable the grammar cannot read",
                    );
                    complete = false;
                }
                content
            }
            _ => None,
        },
        (None, None) => None,
    };
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: model.into(),
        },
        &[node],
    );
    let endpoint = match crate::value::parse_url_endpoint(uri) {
        Some(identity) => ResourceExpr::Concrete { identity },
        None => unresolved_resource("network"),
    };
    let sent = builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("network.upload"),
        resource: endpoint,
        attributes: Default::default(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node, model],
    });
    if let (Some(source), Some(sent)) = (source, sent) {
        builder.transfer_binding(TransferBinding::new(source, sent));
    }
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    complete
}

/// The `System.Net.WebClient` constructions whose `DownloadFile` call this
/// grammar reads, written in lowercase with single spaces.
const WEBCLIENT_RECEIVERS: &[&str] = &[
    "(new-object system.net.webclient)",
    "(new-object net.webclient)",
    "(new-object -typename system.net.webclient)",
    "(new-object -typename net.webclient)",
    "[system.net.webclient]::new()",
    "[net.webclient]::new()",
];

/// `(New-Object System.Net.WebClient).DownloadFile(URL, FILE)` stores the
/// response body in FILE. Returns `None` for any other statement.
fn webclient_download(
    builder: &mut PlanBuilder,
    nest: &Nest,
    statement: &str,
    node: ProvenanceRef,
) -> Option<bool> {
    let statement = statement.trim();
    let lowercase = statement.to_ascii_lowercase();
    let (receiver, call) = lowercase.split_once(".downloadfile(")?;
    let receiver = receiver
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if !WEBCLIENT_RECEIVERS.contains(&receiver.as_str()) {
        return None;
    }
    // Lowercasing keeps every byte offset, so the call's arguments are the
    // same span of the original statement.
    let arguments = statement[statement.len() - call.len()..]
        .strip_suffix(')')
        .map(|arguments| word(arguments.trim()));
    let elements = match &arguments {
        Some(Ok((word, rest))) if rest.is_empty() && word.quoted && !word.expandable => {
            word.elements.as_slice()
        }
        _ => &[],
    };
    let [url, file] = elements else {
        powershell_boundary(
            builder,
            node,
            "PowerShell WebClient.DownloadFile does not pass two literal strings",
        );
        return Some(false);
    };
    // .NET resolves a relative file against the process directory, which
    // the current location does not set.
    Some(download(
        builder,
        nest,
        url,
        file,
        None,
        node,
        "powershell/webclient-downloadfile@v1",
    ))
}

/// A download expression [`remote_content`] recognized.
enum Remote {
    /// A web response body, from the literal URL when there is one.
    Content(Option<String>),
    /// Nested past the unwrap limit; the limit boundary is recorded.
    Saturated,
}

/// `Invoke-Expression (DOWNLOAD)`: the downloaded content passed as the code
/// argument.
fn invoked_remote_content(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    statement: &str,
    node: ProvenanceRef,
) -> Option<Remote> {
    let statement = statement.trim();
    let name_len = statement
        .find(|character: char| character.is_whitespace() || character == '(')
        .unwrap_or(statement.len());
    let (name, argument) = statement.split_at(name_len);
    if !session.runs_cmdlet(name, "Invoke-Expression") {
        return None;
    }
    let argument = argument.trim();
    let argument = argument
        .strip_prefix('-')
        .and_then(|rest| {
            let (parameter, value) = rest.split_once(char::is_whitespace)?;
            "Command"
                .get(..parameter.len())
                .is_some_and(|prefix| {
                    !parameter.is_empty() && prefix.eq_ignore_ascii_case(parameter)
                })
                .then_some(value.trim_start())
        })
        .unwrap_or(argument);
    // Only an argument in expression mode is evaluated before it is passed.
    if !argument.starts_with('(') && !argument.starts_with("$(") {
        return None;
    }
    remote_content(builder, nest, session, argument, node)
}

/// The value of an expression that is a web response body: a web request
/// without `-OutFile`, its `.Content`, or `WebClient.DownloadString`, inside
/// any `(...)` or `$(...)`. `None` for any other expression. Each unwrapped
/// layer is charged to the analysis budget and the layers are bounded by
/// `max_value_depth`, past which the expression is left unexplained.
fn remote_content(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    expression: &str,
    node: ProvenanceRef,
) -> Option<Remote> {
    let mut expression = expression.trim();
    let mut layers = 0;
    loop {
        if !crate::nest::charge_analysis_steps(builder, nest.budget, 1, None) {
            return Some(Remote::Saturated);
        }
        let lowercase = expression.to_ascii_lowercase();
        let inner = match parenthesized(expression) {
            Some(inner) => Some(inner),
            None => match lowercase.strip_suffix(".content") {
                Some(receiver) => Some(parenthesized(&expression[..receiver.len()])?),
                None => None,
            },
        };
        let Some(inner) = inner else { break };
        layers += 1;
        if layers > nest.limits.max_value_depth {
            let mut saturated = unsupported(node);
            saturated.reason = BoundaryReason::LIMIT_SATURATED;
            saturated.class = BoundaryClass::Limit;
            saturated.limit = Some("max_value_depth".into());
            builder.boundary(saturated);
            return Some(Remote::Saturated);
        }
        expression = inner.trim();
    }
    let lowercase = expression.to_ascii_lowercase();
    if let Some((receiver, call)) = lowercase.split_once(".downloadstring(") {
        let receiver = receiver
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !WEBCLIENT_RECEIVERS.contains(&receiver.as_str()) {
            return None;
        }
        let argument = expression[expression.len() - call.len()..].strip_suffix(')')?;
        return Some(Remote::Content(match word(argument.trim()) {
            Ok((url, rest)) if rest.is_empty() && url.quoted && !url.expandable => Some(url.text),
            _ => None,
        }));
    }
    let parsed = words(expression).ok()?;
    let (head, arguments) = parsed.words.split_first()?;
    if !parsed.redirections.is_empty()
        || head.quoted
        || !(session.runs_cmdlet(&head.text, "Invoke-WebRequest")
            || session.runs_cmdlet(&head.text, "Invoke-RestMethod"))
    {
        return None;
    }
    // A request that sends a body keeps the upload grammar, and one that
    // stores the response in a file returns none of it.
    let bound = bind(arguments, &WEB_REQUEST).ok()?;
    if bound.unbound > 0
        || ["OutFile", "InFile", "Body"]
            .iter()
            .any(|name| bound.bound(name))
    {
        return None;
    }
    let uri = bound.value("Uri").ok()??;
    Some(Remote::Content(
        (!uri.contains('$')).then(|| uri.to_string()),
    ))
}

/// The inside of `(...)` or `$(...)` when the parentheses enclose the whole
/// expression.
fn parenthesized(expression: &str) -> Option<&str> {
    leading_group(expression)
        .filter(|(_, rest)| rest.is_empty())
        .map(|(inner, _)| inner)
}

/// The inside of the `(...)` or `$(...)` that opens `expression`, and the text
/// after its closing parenthesis.
fn leading_group(expression: &str) -> Option<(&str, &str)> {
    let inner = expression
        .strip_prefix("$(")
        .or_else(|| expression.strip_prefix('('))?;
    let mut depth = 1u32;
    let mut quote = None;
    for (index, character) in inner.char_indices() {
        match (quote, character) {
            (Some(open), _) if character == open => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(character),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return Some((&inner[..index], &inner[index + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

/// The spellings of the ScriptBlock type; `System.` is implied in a type name.
const SCRIPTBLOCK_TYPES: &[&str] = &[
    "[scriptblock]",
    "[management.automation.scriptblock]",
    "[system.management.automation.scriptblock]",
];

/// A downloaded script block that runs. The block is
/// `[scriptblock]::Create(DOWNLOAD)`, possibly grouped, or a variable an
/// earlier statement assigned one to. It runs under `&` or `.`, with or
/// without arguments; through `.Invoke()`, `.InvokeReturnAsIs()` or
/// `.InvokeWithContext()`; or as the script block of a local
/// `Invoke-Command`. `Create` only compiles its string; the call and
/// dot-source operators, the invoke methods and Invoke-Command run it
/// (about_Operators, ScriptBlock.Create, ScriptBlock.InvokeWithContext,
/// Invoke-Command).
fn invoked_scriptblock_content(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    statement: &str,
    node: ProvenanceRef,
) -> Option<Remote> {
    let statement = statement.trim();
    let name_len = statement
        .find(|character: char| character.is_whitespace() || character == '(')
        .unwrap_or(statement.len());
    let (name, arguments) = statement.split_at(name_len);
    let block = match statement.strip_prefix(['&', '.']) {
        // Arguments after the block are passed to it.
        Some(rest)
            if rest.starts_with(|character: char| {
                character.is_whitespace() || matches!(character, '(' | '$')
            }) =>
        {
            let (block, after) = scriptblock(session, rest)?;
            (after.is_empty() || after.starts_with(char::is_whitespace)).then_some(block)?
        }
        _ if session.runs_cmdlet(name, "Invoke-Command") => {
            let arguments = arguments.trim_start();
            let block = arguments
                .split_once(char::is_whitespace)
                .filter(|(parameter, _)| {
                    ["-ScriptBlock", "-Command"]
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(parameter))
                })
                .map_or(arguments, |(_, block)| block);
            let (block, after) = scriptblock(session, block)?;
            // Only the block's own parameters may follow; any other, such
            // as a computer, session or container, may run it somewhere else.
            // A negative number is an argument value, not a parameter.
            after
                .split_whitespace()
                .filter(|token| {
                    token
                        .strip_prefix('-')
                        .is_some_and(|name| !name.starts_with(|c: char| c.is_ascii_digit()))
                })
                .all(|parameter| {
                    ["-ArgumentList", "-Args", "-NoNewScope"]
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(parameter))
                })
                .then_some(block)?
        }
        _ => {
            let (block, after) = scriptblock(session, statement)?;
            let after = after.trim_start().to_ascii_lowercase();
            [".invoke(", ".invokereturnasis(", ".invokewithcontext("]
                .iter()
                .any(|method| after.starts_with(method))
                .then_some(block)?
        }
    };
    match block {
        Block::Create(argument) => remote_content(builder, nest, session, argument, node),
        Block::Variable(url) => Some(Remote::Content(url)),
    }
}

/// A script block expression.
enum Block<'a> {
    /// `[scriptblock]::Create(...)` of this string argument.
    Create(&'a str),
    /// A variable holding a block compiled from a download of this URL.
    Variable(Option<String>),
}

/// The script block that opens `expression`, and the text after it.
fn scriptblock<'a>(session: &Session, expression: &'a str) -> Option<(Block<'a>, &'a str)> {
    let expression = expression.trim_start();
    let Some(rest) = expression.strip_prefix('$') else {
        let (argument, after) = scriptblock_create(expression)?;
        return Some((Block::Create(argument), after));
    };
    let end = rest
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(rest.len());
    let (name, after) = rest.split_at(end);
    let (_, url) = session
        .remote_blocks
        .iter()
        .rev()
        .find(|(bound, _)| bound.eq_ignore_ascii_case(name))?;
    Some((Block::Variable(url.clone()), after))
}

/// The string argument of a `[scriptblock]::Create(...)` call that opens
/// `expression`, possibly inside grouping parentheses, and the text after it.
fn scriptblock_create(expression: &str) -> Option<(&str, &str)> {
    let expression = expression.trim_start();
    if expression.starts_with('(') {
        let (group, after) = leading_group(expression)?;
        let (argument, rest) = scriptblock_create(group)?;
        return rest.trim().is_empty().then_some((argument, after));
    }
    let lowercase = expression.to_ascii_lowercase();
    let rest = SCRIPTBLOCK_TYPES
        .iter()
        .find_map(|name| lowercase.strip_prefix(name))?
        .trim_start()
        .strip_prefix("::create")?
        .trim_start();
    let call = &expression[expression.len() - rest.len()..];
    call.starts_with('(').then(|| leading_group(call))?
}

/// Code a web response carries, run by `Invoke-Expression` in this session.
/// The code itself is unknown, so the session is too once it has run.
fn remote_execution(builder: &mut PlanBuilder, url: Option<String>, node: ProvenanceRef) {
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: "powershell/invoke-expression-download@v1".into(),
        },
        &[node],
    );
    let effect = |operation: &str, resource, attributes| Effect {
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node, model],
    };
    let endpoint = match url.as_deref().and_then(crate::value::parse_url_endpoint) {
        Some(identity) => ResourceExpr::Concrete { identity },
        None => unresolved_resource("network"),
    };
    let source = builder.effect(effect("network.download", endpoint, Default::default()));
    // Invoke-Expression runs the content inside the PowerShell process itself.
    let interpreter = match builder.launching_command() {
        Some(command) => ResourceExpr::Concrete {
            identity: crate::paths::process_identity_with_cwd(
                &[crate::word::Word::literal(command)],
                builder.current_execution_cwd(),
            ),
        },
        None => unresolved_resource("process"),
    };
    let execution = builder.effect(effect(
        "process.code_execution",
        interpreter,
        [(
            "source".to_string(),
            effinterp_proto::AttrValue::String("argument".into()),
        )]
        .into_iter()
        .collect(),
    ));
    if let (Some(source), Some(execution)) = (source, execution) {
        builder.transfer_binding(TransferBinding::new(source, execution));
    }
    let mut code = unsupported(node);
    code.reason = BoundaryReason::UNMODELED_DYNAMIC_CODE;
    code.class = BoundaryClass::Unresolved;
    code.detail = Some("PowerShell Invoke-Expression runs downloaded code".into());
    builder.boundary(code);
}

/// A download of `url` whose body is written to `file`.
fn download(
    builder: &mut PlanBuilder,
    nest: &Nest,
    url: &str,
    file: &str,
    location: Option<&str>,
    node: ProvenanceRef,
    model: &str,
) -> bool {
    let Some(written) = resolved_path(builder, nest, file, false, location, node, "download")
    else {
        return false;
    };
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: model.into(),
        },
        &[node],
    );
    let effect = |operation: &str, resource, attributes| Effect {
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node, model],
    };
    let endpoint = match crate::value::parse_url_endpoint(url) {
        Some(identity) => ResourceExpr::Concrete { identity },
        None => unresolved_resource("network"),
    };
    let source = builder.effect(effect("network.download", endpoint, Default::default()));
    let destination = builder.effect(effect(
        "filesystem.write",
        written,
        crate::models::common::program_output_attrs(),
    ));
    if let (Some(source), Some(destination)) = (source, destination) {
        builder.transfer_binding(TransferBinding::new(source, destination));
    }
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    true
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

/// Resolve one bound path to the filesystem resource it names, raising the
/// boundary that says why not where it does not name one. A relative path
/// names an item under `location`, the current filesystem location where it
/// is known. A drive or provider qualifier (`Env:`, `HKLM:`) or a rooted path
/// is not relative to it.
fn resolved_path(
    builder: &mut PlanBuilder,
    nest: &Nest,
    path: &str,
    wildcards: bool,
    location: Option<&str>,
    node: ProvenanceRef,
    command: &str,
) -> Option<ResourceExpr> {
    let Some(path) = expand_home(builder, nest, path, node) else {
        powershell_boundary(
            builder,
            node,
            "PowerShell ~ has no home directory in the host context",
        );
        return None;
    };
    let path = match location {
        Some(location)
            if absolute_filesystem_path(&path, None).is_none()
                && !path.contains(':')
                && !path.starts_with(['/', '\\']) =>
        {
            match absolute_filesystem_path(location, None) {
                Some(true) => format!("{}\\{path}", location.trim_end_matches(['/', '\\'])),
                // PowerShell also separates paths with `\` on a POSIX host.
                _ => format!(
                    "{}/{}",
                    location.trim_end_matches('/'),
                    path.replace('\\', "/")
                ),
            }
        }
        _ => path,
    };
    let Some(windows) = absolute_filesystem_path(&path, None) else {
        powershell_boundary(
            builder,
            node,
            &format!(
                "PowerShell {command} path does not establish an absolute filesystem provider"
            ),
        );
        return None;
    };
    Some(path_resource(&path, windows, wildcards))
}

fn filesystem_effect(
    builder: &mut PlanBuilder,
    operation: &str,
    resource: ResourceExpr,
    attributes: crate::models::common::Attrs,
    node: ProvenanceRef,
    model: &str,
) -> Option<u32> {
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: model.into(),
        },
        &[node],
    );
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
        provenance: vec![node, model],
    })
}

/// `~` and `~\rest` name the home directory of the analyzed host.
fn expand_home(
    builder: &mut PlanBuilder,
    nest: &Nest,
    path: &str,
    node: ProvenanceRef,
) -> Option<String> {
    let rest = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(['\\', '/']) => rest,
        _ => return Some(path.to_string()),
    };
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: "powershell/home-expansion@v1".into(),
        },
        &[node],
    );
    for name in ["HOME", "USERPROFILE"] {
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
            },
            attributes: Default::default(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance: vec![node, model],
        });
    }
    builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    Some(format!("{}{rest}", home(nest)?))
}

/// Raise a boundary where a collection binds several paths: PowerShell
/// accesses each of them, but the grammar does not model the collection's
/// own evaluation.
fn single(builder: &mut PlanBuilder, node: ProvenanceRef, paths: &[String]) -> bool {
    if paths.len() > 1 {
        powershell_boundary(
            builder,
            node,
            "PowerShell collection argument binds several paths",
        );
        return false;
    }
    true
}

enum Parameter {
    Switch(&'static str),
    Valued(&'static str),
}

/// One cmdlet's parameters: its switches, its value parameters, and the value
/// parameters its positional arguments bind, in position order.
struct Cmdlet {
    name: &'static str,
    switches: &'static [&'static str],
    values: &'static [&'static str],
    positions: &'static [&'static str],
}

/// A cmdlet whose whole effect is one filesystem access to each path it
/// binds. Its first position names that path.
struct FileCmdlet {
    cmdlet: Cmdlet,
    operation: &'static str,
    model: &'static str,
}

/// The common parameters every cmdlet binds (about_CommonParameters), with
/// the risk-mitigation switches.
const COMMON_SWITCHES: &[&str] = &["WhatIf", "Confirm", "Verbose", "Debug"];
const COMMON_VALUES: &[&str] = &[
    "ErrorAction",
    "WarningAction",
    "InformationAction",
    "ProgressAction",
    "ErrorVariable",
    "WarningVariable",
    "InformationVariable",
    "OutVariable",
    "OutBuffer",
    "PipelineVariable",
];

const ITEM_PATHS: &[&str] = &[
    "Path",
    "LiteralPath",
    "Filter",
    "Include",
    "Exclude",
    "Stream",
    "Credential",
];

const REMOVE_ITEM: Cmdlet = Cmdlet {
    name: "Remove-Item",
    switches: &["Recurse", "Force"],
    values: ITEM_PATHS,
    positions: &["Path"],
};

const CONTENT_VALUES: &[&str] = &[
    "Path",
    "LiteralPath",
    "Value",
    "Encoding",
    "Filter",
    "Include",
    "Exclude",
    "Stream",
    "Credential",
];

const FILE_CMDLETS: &[FileCmdlet] = &[
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Clear-Content",
            switches: &["Force", "NoNewline"],
            values: ITEM_PATHS,
            positions: &["Path"],
        },
        operation: "filesystem.write",
        model: "powershell/clear-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Set-Content",
            switches: &["Force", "NoNewline", "PassThru", "AsByteStream"],
            values: CONTENT_VALUES,
            positions: &["Path", "Value"],
        },
        operation: "filesystem.write",
        model: "powershell/set-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Add-Content",
            switches: &["Force", "NoNewline", "PassThru", "AsByteStream"],
            values: CONTENT_VALUES,
            positions: &["Path", "Value"],
        },
        operation: "filesystem.write",
        model: "powershell/add-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Get-Content",
            switches: &["Force", "Raw", "Wait", "AsByteStream"],
            values: &[
                "Path",
                "LiteralPath",
                "ReadCount",
                "TotalCount",
                "Tail",
                "Delimiter",
                "Encoding",
                "Filter",
                "Include",
                "Exclude",
                "Stream",
                "Credential",
            ],
            positions: &["Path"],
        },
        operation: "filesystem.read",
        model: "powershell/get-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Out-File",
            switches: &["Append", "Force", "NoClobber", "NoNewline"],
            values: &[
                "FilePath",
                "LiteralPath",
                "Encoding",
                "Width",
                "InputObject",
            ],
            positions: &["FilePath", "Encoding"],
        },
        operation: "filesystem.write",
        model: "powershell/out-file@v1",
    },
];

const COPY_ITEM: Cmdlet = Cmdlet {
    name: "Copy-Item",
    switches: &["Container", "Force", "PassThru", "Recurse"],
    values: &[
        "Path",
        "LiteralPath",
        "Destination",
        "Filter",
        "Include",
        "Exclude",
        "Credential",
    ],
    positions: &["Path", "Destination"],
};

const MOVE_ITEM: Cmdlet = Cmdlet {
    name: "Move-Item",
    switches: &["Force", "PassThru"],
    values: &[
        "Path",
        "LiteralPath",
        "Destination",
        "Filter",
        "Include",
        "Exclude",
        "Credential",
    ],
    positions: &["Path", "Destination"],
};

const RENAME_ITEM: Cmdlet = Cmdlet {
    name: "Rename-Item",
    switches: &["Force", "PassThru"],
    values: &["Path", "LiteralPath", "NewName", "Credential"],
    positions: &["Path", "NewName"],
};

const NEW_ITEM: Cmdlet = Cmdlet {
    name: "New-Item",
    switches: &["Force"],
    values: &["Path", "ItemType", "Value", "Target", "Credential"],
    positions: &["Path"],
};

const WEB_REQUEST: Cmdlet = Cmdlet {
    name: "Invoke-WebRequest",
    switches: &["UseBasicParsing", "PassThru"],
    values: &["Uri", "OutFile", "Method", "Body", "InFile"],
    positions: &["Uri"],
};

const WRITE_OUTPUT: Cmdlet = Cmdlet {
    name: "Write-Output",
    switches: &["NoEnumerate"],
    values: &["InputObject"],
    positions: &["InputObject"],
};

const WRITE_HOST: Cmdlet = Cmdlet {
    name: "Write-Host",
    switches: &["NoNewline"],
    values: &["Object", "Separator", "ForegroundColor", "BackgroundColor"],
    positions: &["Object"],
};

const SET_LOCATION: Cmdlet = Cmdlet {
    name: "Set-Location",
    switches: &["PassThru"],
    values: &["Path", "LiteralPath", "StackName"],
    positions: &["Path"],
};

const START_PROCESS: Cmdlet = Cmdlet {
    name: "Start-Process",
    switches: &["Wait", "NoNewWindow", "PassThru"],
    values: &["FilePath", "ArgumentList"],
    positions: &["FilePath", "ArgumentList"],
};

const SET_ALIAS: Cmdlet = Cmdlet {
    name: "Set-Alias",
    switches: &["Force", "PassThru"],
    values: &["Name", "Value", "Description", "Option", "Scope"],
    positions: &["Name", "Value"],
};

/// The parameters one invocation bound.
#[derive(Default)]
struct PsBoundParameters {
    switches: Vec<(&'static str, bool)>,
    values: Vec<(&'static str, Vec<String>)>,
    /// The argument word each value parameter bound, where its value is a
    /// word of its own rather than attached as `-Name:value`.
    words: Vec<(&'static str, usize)>,
    /// Positional arguments no positional parameter was left to bind.
    unbound: usize,
}

impl PsBoundParameters {
    fn bound(&self, name: &str) -> bool {
        self.switches.iter().any(|(bound, _)| *bound == name)
            || self.values.iter().any(|(bound, _)| *bound == name)
    }

    fn switch(&self, name: &str) -> bool {
        self.switches
            .iter()
            .any(|(bound, value)| *bound == name && *value)
    }

    fn word(&self, name: &str) -> Option<usize> {
        self.words
            .iter()
            .find(|(bound, _)| *bound == name)
            .map(|(_, index)| *index)
    }

    fn values(&self, name: &str) -> Option<&[String]> {
        self.values
            .iter()
            .find(|(bound, _)| *bound == name)
            .map(|(_, values)| values.as_slice())
    }

    fn value(&self, name: &str) -> Result<Option<&str>, &'static str> {
        match self.values(name) {
            None => Ok(None),
            Some([value]) => Ok(Some(value)),
            Some(_) => Err("PowerShell parameter binds a collection"),
        }
    }

    /// The paths the wildcard path parameter or `-LiteralPath` binds, and
    /// whether they expand wildcards. The two belong to different parameter
    /// sets, so binding both is an error PowerShell raises before running.
    fn paths(&self, parameter: &str) -> Result<Option<(&[String], bool)>, &'static str> {
        match (self.values(parameter), self.values("LiteralPath")) {
            (Some(_), Some(_)) => Err("PowerShell binds a path and a literal path"),
            (Some(paths), None) => Ok(Some((paths, true))),
            (None, Some(paths)) => Ok(Some((paths, false))),
            (None, None) => Ok(None),
        }
    }

    /// Raise the boundary for positional arguments nothing bound, and return
    /// whether there were none.
    fn complete(&self, builder: &mut PlanBuilder, node: ProvenanceRef, command: &str) -> bool {
        if self.unbound > 0 {
            powershell_boundary(
                builder,
                node,
                &format!("PowerShell {command} has an unbound operand"),
            );
            return false;
        }
        true
    }
}

/// Bind one cmdlet's arguments as PowerShell does: named parameters first,
/// including `-Name:value` with the value attached, then positional arguments
/// in position order. An argument that fails to bind stops the cmdlet from
/// running, so it is an error rather than a partial binding.
fn bind(arguments: &[PsWord], cmdlet: &Cmdlet) -> Result<PsBoundParameters, &'static str> {
    let mut bound = PsBoundParameters::default();
    let mut positional = Vec::new();
    let mut arguments = arguments.iter().enumerate();
    while let Some((index, argument)) = arguments.next() {
        let name = match argument.text.strip_prefix('-') {
            Some(name)
                if !name.is_empty()
                    && (!argument.quoted || !argument.leading_quote && name.contains(':')) =>
            {
                name
            }
            _ => {
                positional.push((index, argument));
                continue;
            }
        };
        let (name, attached) = match name.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (name, None),
        };
        match parameter(name, cmdlet)? {
            Parameter::Switch(name) => {
                let value = match attached {
                    None => true,
                    // `-Name:'$true'` passes a string, which PowerShell
                    // refuses to bind to a switch.
                    Some(_) if argument.quoted => {
                        return Err("PowerShell switch value is not a literal boolean");
                    }
                    Some(value) if value.eq_ignore_ascii_case("$true") => true,
                    Some(value) if value.eq_ignore_ascii_case("$false") => false,
                    Some(_) => return Err("PowerShell switch value is not a literal boolean"),
                };
                if bound.bound(name) {
                    return Err("PowerShell parameter is bound more than once");
                }
                bound.switches.push((name, value));
            }
            Parameter::Valued(name) => {
                let values = match attached {
                    Some(value) if !value.is_empty() => vec![value.to_string()],
                    _ => {
                        let (index, value) = arguments
                            .next()
                            .ok_or("PowerShell parameter has no value")?;
                        bound.words.push((name, index));
                        value.values()
                    }
                };
                if bound.bound(name) {
                    return Err("PowerShell parameter is bound more than once");
                }
                bound.values.push((name, values));
            }
        }
    }
    let positions = cmdlet
        .positions
        .iter()
        .copied()
        // -LiteralPath takes the place of the wildcard path parameter in its
        // own parameter set, so no positional argument binds that one.
        .filter(|name| {
            !(bound.bound(name)
                || bound.bound("LiteralPath") && matches!(*name, "Path" | "FilePath"))
        })
        .collect::<Vec<_>>();
    for (position, (index, argument)) in positional.into_iter().enumerate() {
        match positions.get(position) {
            Some(name) => {
                bound.values.push((name, argument.values()));
                bound.words.push((name, index));
            }
            None => bound.unbound += 1,
        }
    }
    Ok(bound)
}

/// The parameter a written name binds. PowerShell accepts any prefix that
/// names exactly one of the cmdlet's parameters.
fn parameter(name: &str, cmdlet: &Cmdlet) -> Result<Parameter, &'static str> {
    let candidates = cmdlet
        .switches
        .iter()
        .chain(COMMON_SWITCHES)
        .map(|candidate| (true, *candidate))
        .chain(
            cmdlet
                .values
                .iter()
                .chain(COMMON_VALUES)
                .map(|candidate| (false, *candidate)),
        );
    let parameter = |(switch, candidate): (bool, &'static str)| {
        if switch {
            Parameter::Switch(candidate)
        } else {
            Parameter::Valued(candidate)
        }
    };
    if let Some(exact) = candidates
        .clone()
        .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name))
    {
        return Ok(parameter(exact));
    }
    let mut prefixed = candidates.filter(|(_, candidate)| {
        candidate.len() > name.len() && candidate[..name.len()].eq_ignore_ascii_case(name)
    });
    match (prefixed.next(), prefixed.next()) {
        (Some(candidate), None) => Ok(parameter(candidate)),
        (Some(_), Some(_)) => Err("PowerShell parameter name is ambiguous"),
        _ => Err("PowerShell parameter name is unknown"),
    }
}

/// The commands of the source: its statements and each element of their
/// pipelines, with comments removed and line continuations joined.
/// Each command is returned with whether it pipes into the next one.
fn statements(source: &str) -> Result<Vec<(String, bool)>, &'static str> {
    if source.contains(['\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}']) {
        return Err("PowerShell smart-quote delimiters are not modeled");
    }
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    // A `#` opens a comment only where a token can start.
    let mut token_start = true;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(open) = quote {
            current.push(character);
            if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                current.push(character);
                token_start = false;
            }
            '`' => {
                if characters
                    .next_if(|next| matches!(next, '\n' | '\r'))
                    .is_some()
                {
                    while characters
                        .next_if(|next| matches!(next, '\n' | '\r'))
                        .is_some()
                    {}
                } else {
                    // An escaped character is literal, so an escaped `;` or
                    // `|` stays inside its statement.
                    current.push('`');
                    current.extend(characters.next());
                    token_start = false;
                }
            }
            '#' if token_start => {
                while characters
                    .next_if(|next| !matches!(next, '\n' | '\r'))
                    .is_some()
                {}
            }
            // `<# … #>` comments out everything between its delimiters, across
            // as many lines as it spans, and does not nest.
            '<' if token_start && characters.peek() == Some(&'#') => {
                characters.next();
                let mut previous = None;
                let mut closed = false;
                for character in characters.by_ref() {
                    if previous == Some('#') && character == '>' {
                        closed = true;
                        break;
                    }
                    previous = Some(character);
                }
                if !closed {
                    return Err("PowerShell block comment is unterminated");
                }
            }
            // `||` chains pipelines conditionally, which is not modeled; the
            // word grammar refuses it.
            '|' if characters.peek() == Some(&'|') => {
                current.push('|');
                current.extend(characters.next());
                token_start = false;
            }
            // Each element of a pipeline is a command of its own; what one
            // passes to the next adds input, not a different command.
            ';' | '|' | '\n' | '\r' => {
                statements.push((std::mem::take(&mut current), character == '|'));
                token_start = true;
            }
            character if character.is_whitespace() => {
                current.push(character);
                token_start = true;
            }
            character => {
                current.push(character);
                token_start = false;
            }
        }
    }
    if quote.is_some() {
        return Err("PowerShell quoted argument is unterminated");
    }
    statements.push((current, false));
    statements.retain(|(statement, _)| !statement.trim().is_empty());
    Ok(statements)
}

struct PsWord {
    text: String,
    quoted: bool,
    /// Whether the word starts with a quoted segment. `-Name:'value'` quotes
    /// only its value, so it still names a parameter.
    leading_quote: bool,
    expandable: bool,
    /// The elements of a comma collection; empty for a single value.
    elements: Vec<String>,
}

impl PsWord {
    /// The values the word binds to a parameter.
    fn values(&self) -> Vec<String> {
        if self.elements.is_empty() {
            vec![self.text.clone()]
        } else {
            self.elements.clone()
        }
    }
}

/// One statement's command words and the files its redirections write.
#[derive(Default)]
struct PsStatement {
    words: Vec<PsWord>,
    redirections: Vec<PsRedirection>,
}

struct PsRedirection {
    /// `>>` adds to the file; `>` replaces it.
    append: bool,
    /// The file the stream writes, or `None` where the operator merges the
    /// stream into another one instead (`2>&1`).
    target: Option<PsWord>,
}

/// Split one statement into its words and redirections, refusing any expansion
/// or expression operator whose value the literal grammar cannot recover.
fn words(statement: &str) -> Result<PsStatement, &'static str> {
    let mut parsed = PsStatement::default();
    let mut rest = statement.trim();
    while !rest.is_empty() {
        if let Some((redirection, remainder)) = redirection(rest)? {
            parsed.redirections.push(redirection);
            rest = remainder.trim_start();
            continue;
        }
        let (word, remainder) = word(rest)?;
        parsed.words.push(word);
        rest = remainder.trim_start();
    }
    Ok(parsed)
}

/// A redirection operator: a stream selector (`1`-`6`, or `*` for every
/// stream) that only counts where a token starts, `>` or `>>`, and then either
/// `&1`/`&2` — which names no file — or the file the stream writes. The
/// operator also ends the word it runs into, so `Write-Output x>file`
/// redirects rather than naming a word `x>file`.
fn redirection(rest: &str) -> Result<Option<(PsRedirection, &str)>, &'static str> {
    let stream_selected = matches!(rest.as_bytes().first(), Some(b'*' | b'1'..=b'6'));
    let Some(after) = rest[usize::from(stream_selected)..].strip_prefix('>') else {
        return Ok(None);
    };
    let (append, after) = match after.strip_prefix('>') {
        Some(after) => (true, after),
        None => (false, after),
    };
    if let Some(merged) = after.strip_prefix('&') {
        // Only `>&1` and `>&2` merge streams; `>>&` is not an operator.
        let Some(stream) = merged.strip_prefix(['1', '2']).filter(|_| !append) else {
            return Err("PowerShell redirection merges an unrecognized stream");
        };
        return Ok(Some((
            PsRedirection {
                append,
                target: None,
            },
            stream,
        )));
    }
    let after = after.trim_start();
    if after.is_empty() {
        return Err("PowerShell redirection names no file");
    }
    let (target, after) = word(after)?;
    if !target.elements.is_empty() {
        return Err("PowerShell redirection names a collection");
    }
    Ok(Some((
        PsRedirection {
            append,
            target: Some(target),
        },
        after,
    )))
}

/// One word. Segments that touch concatenate into one argument
/// (about_parsing), so `"C:\Users\test"$rest` is a single word; the word ends
/// at whitespace or at the redirection operator that follows it. Elements
/// joined by commas form one collection argument.
fn word(rest: &str) -> Result<(PsWord, &str), &'static str> {
    let mut text = String::new();
    let mut elements = Vec::new();
    let mut quoted = false;
    let mut expandable = false;
    // A single-quoted segment keeps its `$` literal, so a word that also has
    // an expandable segment cannot be expanded as one string.
    let mut literal_dollar = false;
    let leading_quote = rest.starts_with(['\'', '"']);
    let mut rest = rest;
    let mut first = true;
    loop {
        match rest.chars().next() {
            Some(quote @ ('\'' | '"')) => {
                let body = &rest[1..];
                let Some(end) = body.find(quote) else {
                    return Err("PowerShell quoted argument is unterminated");
                };
                let segment = &body[..end];
                if quote == '"' && segment.contains('`') {
                    return Err("PowerShell expandable string contains an escape");
                }
                rest = &body[end + 1..];
                if rest.starts_with(quote) {
                    // A doubled delimiter escapes the quote character itself.
                    return Err("PowerShell quoted argument escapes its delimiter");
                }
                text.push_str(segment);
                quoted = true;
                if segment.contains('$') {
                    if quote == '"' {
                        expandable = true;
                    } else {
                        literal_dollar = true;
                    }
                }
            }
            Some(',') if !first => {
                elements.push(std::mem::take(&mut text));
                rest = rest[1..].trim_start();
                if rest.is_empty() {
                    return Err("PowerShell collection has no element after its comma");
                }
                continue;
            }
            _ => {
                let end = rest
                    .find(|character: char| {
                        character.is_whitespace() || matches!(character, '>' | '\'' | '"' | ',')
                    })
                    .unwrap_or(rest.len());
                let segment = &rest[..end];
                if segment.is_empty() {
                    return Err(
                        "PowerShell argument contains an expansion, comment, or expression operator",
                    );
                }
                let mut scan = segment;
                while let Some(index) =
                    scan.find(['$', '`', '|', '&', '(', ')', '{', '}', '@', '<'])
                {
                    let after = &scan[index + 1..];
                    let Some((_, length)) =
                        variable(after).filter(|_| scan[index..].starts_with('$'))
                    else {
                        return Err(
                            "PowerShell argument contains an expansion, comment, or expression operator",
                        );
                    };
                    scan = &after[length..];
                }
                text.push_str(segment);
                expandable |= segment.contains('$');
                rest = &rest[end..];
            }
        }
        first = false;
        if rest.is_empty() || rest.starts_with(char::is_whitespace) || rest.starts_with('>') {
            break;
        }
    }
    if literal_dollar && expandable {
        return Err("PowerShell argument concatenates a literal and an expandable dollar");
    }
    if !elements.is_empty() {
        if expandable {
            return Err("PowerShell collection element contains an expansion");
        }
        elements.push(std::mem::take(&mut text));
        text = elements.join(",");
    }
    Ok((
        PsWord {
            text,
            quoted,
            leading_quote,
            expandable,
            elements,
        },
        rest,
    ))
}
