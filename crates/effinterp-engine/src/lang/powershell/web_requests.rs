//! PowerShell web requests and the code they carry: `Invoke-WebRequest` and
//! `Invoke-RestMethod` downloads and uploads, `System.Net.WebClient`
//! downloads, and remote content run by `Invoke-Expression` or a script block.

use effinterp_proto::{
    BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ProvenanceKind, ProvenanceRef, RequestAssurance, ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::nest::Nest;
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;

use super::cmdlet_parameters::{PsBoundParameters, WEB_REQUEST, bind};
use super::path_resolution::{filesystem_effect, resolved_path};
use super::ps_words::{PsWord, word, words};
use super::{Session, VARIABLE_PARAMETERS, powershell_boundary, session_variable, unsupported};

/// `Invoke-WebRequest` and `Invoke-RestMethod` with `-OutFile` store the
/// response body in that file; with `-InFile` or `-Body` and a POST, PUT or
/// PATCH method they send that file or value to the URI.
pub(super) fn web_request(
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
pub(super) fn webclient_download(
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
pub(super) enum Remote {
    /// A web response body, from the literal URL when there is one.
    Content(Option<String>),
    /// Nested past the unwrap limit; the limit boundary is recorded.
    Saturated,
}

/// `Invoke-Expression (DOWNLOAD)`: the downloaded content passed as the code
/// argument.
pub(super) fn invoked_remote_content(
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
pub(super) fn remote_content(
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
pub(super) fn invoked_scriptblock_content(
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
pub(super) fn scriptblock_create(expression: &str) -> Option<(&str, &str)> {
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
pub(super) fn remote_execution(
    builder: &mut PlanBuilder,
    url: Option<String>,
    node: ProvenanceRef,
) {
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
