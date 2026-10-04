//! Network command models: curl, wget, netcat, socat and mail. The corpus's
//! dominant secret-exfil shapes are curl uploads (`-d @file`,
//! `--data-binary @-`, `--upload-file`), so upload recognition is the
//! load-bearing part of these models.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use std::collections::BTreeMap;

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, scan, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, arg_node, code_execution, fs_arg_effect, fs_arg_node, fs_full_no_spawn,
    opaque_source_with_provenance, operand_effect, program_input_attrs, program_output_attrs,
    symbolic_expr, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::resource_transfer::TransferBinding;
use crate::value::{parse_url_endpoint, unresolved_resource};
use crate::word::{Word, WordPart};

pub(super) fn network_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Curl),
        Box::new(Wget),
        Box::new(Netcat),
        Box::new(Socat),
        Box::new(Mail),
        Box::new(DnsLookup),
    ]
}

/// Parse a literal URL-ish operand into a structured endpoint. curl and
/// wget both accept scheme-less URLs.
pub(super) fn parse_endpoint(text: &str) -> Option<ResourceIdentity> {
    let (scheme, rest) = match text.split_once("://") {
        Some((s, r)) => (Some(s.to_string()), r),
        None => (None, text),
    };
    let scp_style = scheme.is_none()
        && rest
            .split_once(':')
            .is_some_and(|(authority, path)| authority.contains('@') && !path.is_empty());
    if scp_style {
        let (authority, path) = rest.split_once(':').unwrap();
        let host = authority.rsplit('@').next().unwrap_or(authority);
        if host.is_empty() {
            return None;
        }
        return Some(ResourceIdentity::NetworkEndpoint {
            host: host.to_string(),
            scheme,
            port: None,
            path: Some(path.to_string()),
        });
    }
    let identity = parse_url_endpoint(text)?;
    let ResourceIdentity::NetworkEndpoint { host, .. } = &identity else {
        unreachable!()
    };
    if scheme.is_none() && !host.contains('.') && host != "localhost" {
        return None;
    }
    Some(identity)
}

/// A curl or wget URL operand. Both tools prefix a scheme-less operand with
/// `http://`, so a single hostname label such as `intranet` names that host
/// even though [`parse_endpoint`] does not accept it from arbitrary text.
fn transfer_endpoint(url: &str) -> Option<ResourceIdentity> {
    parse_endpoint(url).or_else(|| {
        if url.contains("://") {
            return None;
        }
        let identity = parse_url_endpoint(url)?;
        let ResourceIdentity::NetworkEndpoint { host, .. } = &identity else {
            return None;
        };
        (host.as_bytes()[0].is_ascii_alphanumeric()
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then_some(identity)
    })
}

/// Whether an output option names the program's own standard output: `-`, or
/// `/dev/stdout`, which the system resolves to the descriptor socat, curl or
/// wget already writes its stream to.
fn names_stdout(value: Option<&str>) -> bool {
    matches!(value, Some("-" | "/dev/stdout"))
}

fn endpoint_expr(word: &Word) -> ResourceExpr {
    match word.as_literal().and_then(transfer_endpoint) {
        Some(identity) => ResourceExpr::Concrete { identity },
        None => unresolved_resource("network"),
    }
}

/// What a `file://` operand names. curl's FILE protocol opens the path
/// itself — no socket, no server — and accepts only an empty or `localhost`
/// authority for it. Any other authority names neither a file curl reads nor
/// an endpoint it reaches.
enum FileUrl {
    Local(String),
    Foreign,
}

fn file_url(word: &Word) -> Option<FileUrl> {
    let text = word.as_literal()?;
    let rest = text
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("file://"))
        .map(|_| &text[7..])?;
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
        return Some(FileUrl::Foreign);
    }
    Some(FileUrl::Local(path.to_string()))
}

/// The local side of a `file://` transfer: curl reads the named path for a
/// download and writes it for an upload, both as ordinary file access.
fn local_file_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    path: &str,
    uploading: bool,
) -> Option<u32> {
    let word = Word::literal(path);
    // A percent-encoded or query-bearing spelling names a different file than
    // its literal bytes do, so it stays unresolved within its family.
    let resource = if path.starts_with('/') && !path.contains(['%', '?', '#']) {
        ctx.resolve_fs_word(&word)
    } else {
        unresolved_resource("filesystem")
    };
    let (operation, attributes) = if uploading {
        ("filesystem.write", program_output_attrs())
    } else {
        ("filesystem.read", program_input_attrs())
    };
    fs_arg_effect(
        builder, ctx, model_node, index, &word, operation, resource, attributes,
    )
}

fn url_basename(word: &Word) -> Option<String> {
    let text = word.as_literal()?;
    let rest = text.split_once("://").map_or(text, |(_, r)| r);
    let name = rest
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty() && *n != rest)?;
    Some(name.split(['?', '#']).next().unwrap_or(name).to_string())
}

fn network_full(builder: &mut PlanBuilder) {
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
}

/// filesystem.read for an `@file` reference in curl data/form values.
fn at_file_read(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    value: &Word,
    flag: &str,
) {
    let multipart = matches!(flag, "-F" | "--form");
    let urlencode = flag == "--data-urlencode";
    let head = value.literal_prefix();
    // The name=content form takes precedence over name@file for URL encoding.
    if urlencode && head.contains('=') {
        return;
    }
    // An unknown marker can select a file even when no literal @ is present.
    let payload_start = if multipart {
        head.find('=').map_or(head.len(), |index| index + 1)
    } else if urlencode {
        head.find('@').unwrap_or(head.len())
    } else {
        0
    };
    if value.as_literal().is_none() && (multipart || payload_start >= head.len()) {
        let arg = arg_node(builder, ctx, index);
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![arg, model_node],
            limit: None,
            detail: Some("curl payload syntax may select file input".into()),
        });
    }
    if head.as_bytes().get(payload_start) != Some(&b'@')
        && !(multipart && head.as_bytes().get(payload_start) == Some(&b'<'))
    {
        return;
    }
    let mut parts = value.parts.clone();
    if let Some(WordPart::Literal(first)) = parts.first_mut() {
        first.drain(..payload_start + 1);
        if first.is_empty() {
            parts.remove(0);
        }
    }
    // curl's form grammar separates files with `,` and ends them at `;`
    // (MIME controls), except inside a double-quoted name, where `\"` and
    // `\\` escape the quote and backslash.
    let mut paths = vec![Vec::new()];
    let literal_form = multipart
        .then(|| Word::new(parts.clone()).as_literal().map(str::to_string))
        .flatten();
    if let Some(text) = literal_form {
        paths = form_file_names(&text)
            .into_iter()
            .map(|name| vec![WordPart::Literal(name)])
            .collect();
    } else {
        let mut quoted = false;
        'parts: for part in parts {
            if multipart && let WordPart::Literal(text) = &part {
                let mut fragment = String::new();
                let mut chars = text.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' if quoted => match chars.next() {
                            Some(escaped @ ('"' | '\\')) => fragment.push(escaped),
                            Some(other) => {
                                fragment.push(c);
                                fragment.push(other);
                            }
                            None => fragment.push(c),
                        },
                        '"' if quoted => quoted = false,
                        '"' if fragment.is_empty() && paths.last().unwrap().is_empty() => {
                            quoted = true
                        }
                        ',' if !quoted => {
                            paths
                                .last_mut()
                                .unwrap()
                                .push(WordPart::Literal(std::mem::take(&mut fragment)));
                            paths.push(Vec::new());
                        }
                        ';' if !quoted => {
                            paths.last_mut().unwrap().push(WordPart::Literal(fragment));
                            break 'parts;
                        }
                        _ => fragment.push(c),
                    }
                }
                paths.last_mut().unwrap().push(WordPart::Literal(fragment));
            } else {
                paths.last_mut().unwrap().push(part);
            }
        }
    }
    for parts in paths {
        let path = Word::new(parts);
        if path.as_literal() != Some("-") {
            // curl sends the file's contents, so the payload it reads is the
            // one the final path component points at.
            crate::models::common::content_read_effect(
                builder,
                ctx,
                model_node,
                index,
                &path,
                program_input_attrs(),
            );
        }
    }
}

/// The files a literal `-F name=@...` list names. curl reads each
/// comma-separated word up to a `;` that starts its attributes; a word that
/// opens with `"` runs to the closing quote, with `\"` and `\\` escaped,
/// and anything after that quote up to the next separator is dropped.
fn form_file_names(mut rest: &str) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        let quoted = rest.strip_prefix('"').and_then(|quoted| {
            let mut name = String::new();
            let mut characters = quoted.char_indices();
            while let Some((offset, character)) = characters.next() {
                match character {
                    '"' => {
                        let tail = &quoted[offset + 1..];
                        return Some((name, &tail[tail.find([',', ';']).unwrap_or(tail.len())..]));
                    }
                    '\\' if matches!(quoted[offset + 1..].chars().next(), Some('\\' | '"')) => {
                        name.push(characters.next().unwrap().1);
                    }
                    character => name.push(character),
                }
            }
            None
        });
        let (name, tail) = quoted.unwrap_or_else(|| {
            let end = rest.find([',', ';']).unwrap_or(rest.len());
            (rest[..end].to_string(), &rest[end..])
        });
        names.push(name);
        match tail.strip_prefix(',') {
            Some(next) => rest = next,
            None => return names,
        }
    }
}

struct Curl;

const CURL_UPLOAD_FLAGS: &[&str] = &[
    "-d",
    "--data",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--data-ascii",
    "--json",
    "-F",
    "--form",
    "--form-string",
    "-T",
    "--upload-file",
];

const CURL_CONFIG_FLAGS: &[&str] = &["--cacert", "--capath", "--cert", "--key", "-K", "--config"];

const CURL_HEADER_FLAGS: &[&str] = &[
    "-H",
    "--header",
    "-u",
    "--user",
    "-b",
    "--cookie",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
];

const CURL_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "-d",
        "--data",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--data-ascii",
        "--json",
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "-o",
        "--output",
        "--output-dir",
        "-H",
        "--header",
        "-X",
        "--request",
        "-u",
        "--user",
        "-A",
        "--user-agent",
        "-e",
        "--referer",
        "--url",
        "-x",
        "--proxy",
        "--connect-timeout",
        "--max-time",
        "--retry",
        "--retry-delay",
        "-w",
        "--write-out",
        "--cacert",
        "--capath",
        "--cert",
        "--key",
        "-b",
        "--cookie",
        "-c",
        "--cookie-jar",
        "--resolve",
        "-K",
        "--config",
        "-m",
        "--limit-rate",
        "-r",
        "--range",
        "--max-filesize",
        "--netrc-file",
    ],
    known_flags: &[
        "--netrc",
        "--netrc-optional",
        "-s",
        "-S",
        "-f",
        "--fail",
        "-L",
        "--location",
        "-k",
        "--insecure",
        "-v",
        "--verbose",
        "-i",
        "--include",
        "-I",
        "--head",
        "-O",
        "--remote-name",
        "--compressed",
        "--silent",
        "--show-error",
        "-4",
        "-6",
        "-g",
        "--globoff",
        "-N",
        "--no-buffer",
        "-#",
        "--progress-bar",
        "--http1.1",
        "--http2",
        "-J",
        "--remote-header-name",
        "--no-remote-header-name",
        "--no-clobber",
        "--clobber",
    ],
};

fn curl_toggle(scanned: &Scanned<'_>, enable: &[&str], disable: &[&str]) -> bool {
    scanned
        .flags
        .iter()
        .rev()
        .find_map(|flag| {
            enable
                .contains(&flag.name)
                .then_some(true)
                .or_else(|| disable.contains(&flag.name).then_some(false))
        })
        .unwrap_or(false)
}

fn curl_download_destination(
    builder: &mut PlanBuilder,
    base: ResourceExpr,
    remote_header_name: bool,
    no_clobber: bool,
) -> ResourceExpr {
    let selected = if remote_header_name {
        ResourceExpr::Property {
            base: Box::new(base),
            name: "curl_content_disposition_or_remote_name".into(),
        }
    } else {
        base
    };
    let destination_is_absent = no_clobber
        && matches!(
            &selected,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path.starts_with('/')
                && matches!(
                    builder.budget().observe_path(path),
                    effinterp_proto::ObservationOutcome::Path(fact)
                        if fact.kind == effinterp_proto::PathKind::Missing
                )
        );
    if no_clobber && !destination_is_absent {
        ResourceExpr::Property {
            base: Box::new(selected),
            name: "curl_no_clobber_available_filename".into(),
        }
    } else {
        selected
    }
}

fn curl_download_attributes(remote_header_name: bool, no_clobber: bool) -> Attrs {
    let mut attributes = program_output_attrs();
    if remote_header_name {
        attributes.insert("remote_header_name".into(), AttrValue::Bool(true));
    }
    if no_clobber {
        attributes.insert("no_clobber".into(), AttrValue::Bool(true));
    }
    attributes
}

pub(crate) struct CurlFlowInfo {
    pub(crate) assurance: effinterp_proto::CausalAssurance,
    pub(crate) stdin_upload: bool,
    pub(crate) body_read_arguments: Vec<u32>,
    pub(crate) body_value_arguments: Vec<u32>,
    pub(crate) header_arguments: Vec<u32>,
    /// Positions of `-H @file` values, under either scan's indexing: curl
    /// sends the lines it reads from that file.
    pub(crate) header_read_arguments: Vec<u32>,
    /// TLS material and cookie-file values. Producer fallback must not carry
    /// these onto the request; they configure the transfer rather than supply
    /// its body or headers.
    pub(crate) config_arguments: Vec<u32>,
    /// Output-path values (`-o`, `--output`, `--output-dir`). They name a
    /// local destination, not bytes the request sends, so the fallback must
    /// not bind them onto the request's network effect.
    pub(crate) output_value_arguments: Vec<u32>,
    /// Argument positions of URL operands curl serves from the local
    /// filesystem. Their reads carry the bytes a network response otherwise
    /// would.
    pub(crate) local_file_arguments: Vec<u32>,
    pub(crate) outputs: Vec<CurlFlowOutput>,
}

#[derive(Clone, Copy)]
pub(crate) enum CurlFlowOutput {
    Argument(u32),
    RemoteName,
    Stdout,
}

/// Stream destinations derived from the same option-aware scan as curl's effects.
pub(crate) fn curl_flow_info(words: &[Word]) -> CurlFlowInfo {
    let scanned = scan(words, &CURL_FLAG_SPEC);
    let value_scanned = scan_with_value_indices(words, &CURL_FLAG_SPEC, true);
    let mut body_read_arguments = scanned
        .values_of(CURL_UPLOAD_FLAGS)
        .into_iter()
        .map(|(index, _)| index)
        .chain(
            value_scanned
                .values_of(CURL_UPLOAD_FLAGS)
                .into_iter()
                .map(|(index, _)| index),
        )
        .collect::<Vec<_>>();
    body_read_arguments.sort_unstable();
    body_read_arguments.dedup();
    let stdin_upload = scanned.flags.iter().any(|flag| {
        let value = flag.value.as_ref().and_then(Word::as_literal);
        match flag.name {
            "-T" | "--upload-file" => value == Some("-"),
            "-d" | "--data" | "--data-binary" | "--data-ascii" | "--json" => value == Some("@-"),
            "-F" | "--form" => value
                .and_then(|value| value.split_once('='))
                .is_some_and(|(_, value)| value == "@-"),
            // A config read from stdin sends its options with the request.
            "-K" | "--config" => value == Some("-"),
            _ => false,
        }
    });
    let outputs = scanned
        .flags
        .iter()
        .filter_map(|flag| match flag.name {
            "-o" | "--output" => Some(
                if names_stdout(flag.value.as_ref().and_then(Word::as_literal)) {
                    CurlFlowOutput::Stdout
                } else {
                    CurlFlowOutput::Argument(flag.index)
                },
            ),
            "-O" | "--remote-name" => Some(CurlFlowOutput::RemoteName),
            _ => None,
        })
        .collect();
    let header_arguments = value_scanned
        .flags
        .iter()
        .filter(|flag| CURL_HEADER_FLAGS.contains(&flag.name))
        .filter(|flag| {
            !matches!(flag.name, "-b" | "--cookie")
                || flag
                    .value
                    .as_ref()
                    .and_then(Word::as_literal)
                    .is_none_or(|value| value.contains('='))
        })
        .filter_map(|flag| flag.value_index)
        .collect::<Vec<_>>();
    let mut header_read_arguments = [&scanned, &value_scanned]
        .into_iter()
        .flat_map(|scan| scan.values_of(&["-H", "--header"]))
        .filter(|(_, value)| value.literal_prefix().starts_with('@'))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    header_read_arguments.sort_unstable();
    header_read_arguments.dedup();
    let mut config_arguments = value_scanned
        .values_of(CURL_CONFIG_FLAGS)
        .into_iter()
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    for (index, _) in value_scanned.values_of(&["-b", "--cookie"]) {
        if !header_arguments.contains(&index) {
            config_arguments.push(index);
        }
    }
    let mut local_file_arguments = scanned
        .operands
        .iter()
        .filter(|(_, word)| matches!(file_url(word), Some(FileUrl::Local(_))))
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    for flag in scanned.flags.iter().filter(|flag| flag.name == "--url") {
        let Some(value) = flag.value.as_ref() else {
            continue;
        };
        if matches!(file_url(value), Some(FileUrl::Local(_))) {
            // Which of the two the effect carries depends on how the model
            // scanned its arguments, so both name this URL.
            local_file_arguments.push(flag.index);
            local_file_arguments.extend(flag.value_index);
        }
    }
    // This proof covers one request with one body source and one destination.
    // Other accepted options still need an audit of their byte-routing semantics.
    let audited = scanned.unknown_flags.is_empty()
        && words.iter().all(|word| word.as_literal().is_some())
        && scanned.operands.len() + scanned.values_of(&["--url"]).len() == 1
        && scanned
            .operands
            .iter()
            .map(|(_, word)| *word)
            .chain(
                scanned
                    .values_of(&["--url"])
                    .into_iter()
                    .map(|(_, word)| word),
            )
            .all(|word| {
                word.as_literal().is_some_and(|url| {
                    parse_endpoint(url).is_some()
                        && !url.contains(['{', '}', '[', ']'])
                        && (!scanned.has(&["-F", "--form"])
                            || if let Some((scheme, _)) = url.split_once("://") {
                                scheme.eq_ignore_ascii_case("http")
                                    || scheme.eq_ignore_ascii_case("https")
                            } else {
                                !url.contains([':', '@'])
                                    && !["ftp.", "dict.", "ldap.", "imap.", "pop3.", "smtp."]
                                        .iter()
                                        .any(|prefix| url.to_ascii_lowercase().starts_with(prefix))
                            })
                })
            })
        && scanned
            .flags
            .iter()
            .filter(|flag| CURL_UPLOAD_FLAGS.contains(&flag.name))
            .count()
            <= 1
        && scanned
            .flags
            .iter()
            .filter(|flag| matches!(flag.name, "-o" | "--output" | "-O" | "--remote-name"))
            .count()
            <= 1
        && scanned.flags.iter().all(|flag| match flag.name {
            "-s" | "--silent" | "-S" | "--show-error" | "-f" | "--fail" | "-L" | "--location"
            | "-k" | "--insecure" | "-O" | "--remote-name" => true,
            "-d" | "--data" | "--data-binary" | "--data-ascii" | "--json" => flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .is_some_and(|value| !stdin_upload || value == "@-"),
            "-F" | "--form" => flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .and_then(|value| value.split_once('='))
                .is_some_and(|(name, value)| {
                    // This is the unquoted file-list grammar also used by
                    // at_file_read; MIME controls and escaped names need their
                    // own parser before their selected reads can be certified.
                    !name.is_empty()
                        && !value.contains([';', '"', '\\', '\n', '\r'])
                        && value
                            .strip_prefix('@')
                            .or_else(|| value.strip_prefix('<'))
                            .is_some_and(|files| {
                                (value.starts_with('@') || !files.contains(','))
                                    && files
                                        .split(',')
                                        .all(|file| !file.is_empty() && file.trim() == file)
                                    && (!files.split(',').any(|file| file == "-")
                                        || files == "-" && value.starts_with('@'))
                            })
                }),
            // curl sends each line of a header file as a request header.
            "-H" | "--header" => flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .and_then(|value| value.strip_prefix('@'))
                .is_some_and(|file| !file.is_empty() && file != "-"),
            "-T" | "--upload-file" | "-o" | "--output" | "--url" => flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .is_some_and(|value| !value.is_empty()),
            _ => false,
        });
    CurlFlowInfo {
        assurance: if audited {
            effinterp_proto::CausalAssurance::Exact
        } else {
            effinterp_proto::CausalAssurance::Conservative
        },
        stdin_upload,
        body_read_arguments,
        body_value_arguments: value_scanned
            .values_of(CURL_UPLOAD_FLAGS)
            .into_iter()
            .map(|(index, _)| index)
            .collect(),
        header_arguments,
        header_read_arguments,
        config_arguments,
        output_value_arguments: value_scanned
            .values_of(&["-o", "--output", "--output-dir"])
            .into_iter()
            .map(|(index, _)| index)
            .collect(),
        local_file_arguments,
        outputs,
    }
}

/// Record one source-to-destination transfer pairing when both endpoint
/// effects were retained.
fn record_transfer(
    builder: &mut PlanBuilder,
    source: Option<u32>,
    destination: Option<u32>,
    assurance: effinterp_proto::CausalAssurance,
) {
    if let (Some(source), Some(destination)) = (source, destination) {
        builder.transfer_binding(if assurance == effinterp_proto::CausalAssurance::Exact {
            TransferBinding::exact(source, destination)
        } else {
            TransferBinding::new(source, destination)
        });
    }
}

impl CommandModel for Curl {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "filesystem", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "net/curl@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["curl"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let transfer_assurance = curl_flow_info(ctx.argv).assurance;
        let scanned = scan_with_value_indices(
            ctx.argv,
            &CURL_FLAG_SPEC,
            ctx.tracks_host_context_environment(),
        );
        // Headers read from a file carry that file's bytes to the server as
        // surely as a body does.
        let uploading = scanned.has(CURL_UPLOAD_FLAGS)
            || scanned
                .values_of(&["-H", "--header"])
                .iter()
                .any(|(_, value)| value.literal_prefix().starts_with('@'));
        let remote_header_name = curl_toggle(
            &scanned,
            &["-J", "--remote-header-name"],
            &["--no-remote-header-name"],
        );
        let no_clobber = curl_toggle(&scanned, &["--no-clobber"], &["--clobber"]);
        // A real output destination (`-o file`, `-O`) makes its paired response
        // a download; an absent selector or `-o -` leaves that response on stdout.
        let outputs = scanned
            .flags
            .iter()
            .filter(|flag| matches!(flag.name, "-o" | "--output" | "-O" | "--remote-name"))
            .collect::<Vec<_>>();

        // Local files fed into the request body.
        for flag in [
            "-d",
            "--data",
            "--data-binary",
            "--data-ascii",
            "--data-urlencode",
            // `--json` is `--data-binary` with JSON headers (curl 7.82).
            "--json",
            "-F",
            "--form",
        ] {
            for (index, value) in scanned
                .flags
                .iter()
                .filter(|candidate| candidate.name == flag)
                .filter_map(|candidate| Some((candidate.value_index?, candidate.value.as_ref()?)))
            {
                at_file_read(builder, ctx, model_node, index, value, flag);
            }
        }
        // Upload sources, in flag order: curl pairs the nth `-T` with the nth
        // URL, so their slots stay positional rather than crossing operands.
        let mut upload_reads: Vec<Option<u32>> = Vec::new();
        for (index, value) in scanned.values_of(&["-T", "--upload-file"]) {
            upload_reads.push(if value.as_literal() != Some("-") {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    value,
                    "filesystem.read",
                    program_input_attrs(),
                )
            } else {
                None
            });
        }
        for (index, value) in scanned.values_of(&["--cacert", "--cert", "--key"]) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                value,
                "filesystem.read",
                Default::default(),
            );
        }
        // -b takes a cookie string (contains =) or a cookie file.
        for (index, value) in scanned.values_of(&["-b", "--cookie"]) {
            if value.as_literal().is_none_or(|t| !t.contains('=')) {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    value,
                    "filesystem.read",
                    Default::default(),
                );
            }
        }
        // Files curl opens as program input: a config file (`-K`/`--config`),
        // an `@file` header, and a `.netrc` credential store. curl reads their
        // bytes to configure or authenticate the request, so a secret named
        // here is disclosed even though it is not the request body.
        let mut config_reads = Vec::new();
        let mut stdin_config = false;
        for flag in scanned
            .flags
            .iter()
            .filter(|flag| matches!(flag.name, "-K" | "--config" | "--netrc-file"))
        {
            let (Some(index), Some(value)) = (flag.value_index, flag.value.as_ref()) else {
                continue;
            };
            if value.as_literal() == Some("-") {
                stdin_config |= flag.name != "--netrc-file";
            } else {
                let read = operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    value,
                    "filesystem.read",
                    program_input_attrs(),
                );
                // A computed config name carries its own value into the
                // read, not file bytes; only a named file is followed out.
                if flag.name != "--netrc-file" && value.as_literal().is_some() {
                    config_reads.push(read);
                }
            }
        }
        for (index, value) in scanned.values_of(CURL_HEADER_FLAGS) {
            if let Some(file) = value.as_literal().and_then(|text| text.strip_prefix('@'))
                && file != "-"
            {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    &Word::literal(file),
                    "filesystem.read",
                    program_input_attrs(),
                );
            }
        }
        // `--netrc`/`--netrc-optional` authenticate from the user's `~/.netrc`.
        // An unknown HOME stays symbolic so the host can be asked for it.
        let mut netrc_read = None;
        let netrc = match ctx.environment_value("HOME") {
            Some(ResourceExpr::Literal { value }) if value.starts_with('/') => {
                Some(ctx.resolve_fs_word(&Word::literal(crate::paths::join_cwd(&value, ".netrc"))))
            }
            None if !ctx.nest.current_environment_unsets().contains("HOME") => {
                Some(ResourceExpr::Join {
                    parts: vec![
                        ResourceExpr::Environment {
                            name: "HOME".into(),
                        },
                        ResourceExpr::Literal {
                            value: "/.netrc".into(),
                        },
                    ],
                })
            }
            _ => None,
        };
        if scanned.has(&["--netrc", "--netrc-optional"])
            && let Some(resource) = netrc
        {
            let mut provenance = vec![model_node];
            if let Some(input) = ctx.nest.current_environment_node("HOME") {
                provenance.push(input);
            }
            netrc_read = builder.effect(Effect {
                id: Default::default(),
                operation: Operation::new("filesystem.read"),
                resource,
                attributes: program_input_attrs(),
                modality: Modality::MustOnSuccess,
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: Default::default(),
                provenance,
            });
        }

        // Response destinations. Only `-o`/`--output` is a download
        // destination; a cookie jar is written but is not the response body.
        // Keyed by the flag's own token position so the URL loop can find the
        // destination its output flag named.
        let mut output_writes: BTreeMap<u32, Option<u32>> = BTreeMap::new();
        let destination_names = ["-o", "--output", "-c", "--cookie-jar"];
        let destination_flags = scanned
            .flags
            .iter()
            .filter(|flag| destination_names.contains(&flag.name) && flag.value.is_some())
            .map(|flag| flag.index)
            .collect::<Vec<_>>();
        for (flag_index, (index, value)) in destination_flags
            .into_iter()
            .zip(scanned.values_of(&destination_names))
        {
            if !names_stdout(value.as_literal()) {
                let output = scanned
                    .flags
                    .iter()
                    .any(|flag| flag.index == flag_index && matches!(flag.name, "-o" | "--output"));
                let base = match value.as_literal() {
                    Some(path)
                        if ctx.cwd.is_some_and(|cwd| {
                            cwd.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                                && matches!(cwd.as_bytes().get(1..3), Some(b":\\" | b":/"))
                        }) && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                            && matches!(path.as_bytes().get(1..3), Some(b":\\" | b":/")) =>
                    {
                        effinterp_proto::filesystem_path(
                            path,
                            None,
                            effinterp_proto::PathPlatform::Windows,
                        )
                    }
                    _ => ctx.resolve_fs_word(value),
                };
                let resource = if output {
                    curl_download_destination(builder, base, false, no_clobber)
                } else {
                    base
                };
                let slot = fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    value,
                    "filesystem.write",
                    resource,
                    if output {
                        curl_download_attributes(false, no_clobber)
                    } else {
                        Default::default()
                    },
                );
                output_writes.insert(flag_index, slot);
            }
        }

        // Requests.
        let mut request_attrs: Attrs = Attrs::new();
        if let Some(method) = scanned
            .value_of(&["-X", "--request"])
            .and_then(|w| w.as_literal())
        {
            request_attrs.insert("method".into(), AttrValue::String(method.to_string()));
        } else if scanned.has(&["-I", "--head"]) {
            request_attrs.insert("method".into(), AttrValue::String("HEAD".to_string()));
        }
        let mut urls: Vec<(u32, &Word)> = scanned
            .operands
            .iter()
            .map(|(i, w)| (*i, *w))
            .chain(scanned.values_of(&["--url"]))
            .collect();
        urls.sort_by_key(|(index, _)| *index);
        let method_flags = scanned
            .flags
            .iter()
            .filter(|flag| matches!(flag.name, "-X" | "--request"))
            .collect::<Vec<_>>();
        let delete_request = scanned.unknown_flags.is_empty()
            && method_flags.len() == 1
            && method_flags[0].value.as_ref().and_then(Word::as_literal) == Some("DELETE")
            && urls.len() == 1
            && !scanned.has(&[
                "-I",
                "--head",
                "-K",
                "--config",
                "-L",
                "--location",
                "--retry",
            ]);
        let forge_delete_attributes = delete_request
            .then(|| {
                let url = urls[0].1.as_literal()?;
                if url.contains(['{', '}', '[', ']']) {
                    return None;
                }
                let ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme: Some(scheme),
                    port: None,
                    path: Some(path),
                } = parse_endpoint(url)?
                else {
                    return None;
                };
                (scheme.eq_ignore_ascii_case("https"))
                    .then(|| {
                        crate::models::registry::forge_repository_delete_attributes(&host, &path)
                    })
                    .flatten()
            })
            .flatten();
        // One request to a Vault HTTP API KV destroy route: a DELETE of
        // `/v1/<mount>/metadata/<secret>`, or a POST or PUT of a body to
        // `/v1/<mount>/destroy/<secret>`; without a body naming versions
        // Vault destroys nothing. curl sends a body with POST when `-X` names
        // no method. The route alone does not name Vault: Consul and other
        // APIs share `/v1/<name>/destroy/...`. The request must also carry a
        // Vault header or go to `$VAULT_ADDR`, the address Vault's own tools
        // read: an unknown value in the URL, or a known one it starts with.
        let body = scanned.has(&[
            "-d",
            "--data",
            "--data-binary",
            "--data-ascii",
            "--data-raw",
            "--data-urlencode",
            "--json",
        ]) && !scanned.has(&[
            "-G",
            "--get",
            "-T",
            "--upload-file",
            "-F",
            "--form",
            "--form-string",
        ]);
        let method = match method_flags[..] {
            [flag] => flag.value.as_ref().and_then(Word::as_literal),
            [] if body => Some("POST"),
            _ => None,
        };
        let vault_header = scanned
            .values_of(&["-H", "--header"])
            .iter()
            .any(|(_, value)| {
                value
                    .literal_prefix()
                    .split_once(':')
                    .is_some_and(|(name, _)| {
                        ["X-Vault-Token", "X-Vault-Namespace", "X-Vault-Request"]
                            .iter()
                            .any(|vault| name.trim().eq_ignore_ascii_case(vault))
                    })
            });
        let vault_destroy = (scanned.unknown_flags.is_empty()
            && urls.len() == 1
            && !scanned.has(&[
                "-I",
                "--head",
                "-K",
                "--config",
                "-L",
                "--location",
                "--retry",
            ]))
        .then(|| {
            let delete = match method? {
                "DELETE" => true,
                "POST" | "PUT" if body => false,
                _ => return None,
            };
            let path = match urls[0].1.parts.as_slice() {
                [WordPart::Env(name), WordPart::Literal(rest)] if name == "VAULT_ADDR" => {
                    rest.clone()
                }
                [WordPart::Literal(url)]
                    if vault_header
                        || matches!(
                            ctx.environment_value("VAULT_ADDR"),
                            Some(ResourceExpr::Literal { value })
                                if !value.trim_end_matches('/').is_empty()
                                    && url.strip_prefix(value.trim_end_matches('/'))
                                        .is_some_and(|rest| rest.starts_with('/'))
                        ) =>
                {
                    if url.contains(['{', '}', '[', ']']) {
                        return None;
                    }
                    let ResourceIdentity::NetworkEndpoint {
                        scheme,
                        path: Some(path),
                        ..
                    } = parse_endpoint(url)?
                    else {
                        return None;
                    };
                    if scheme.is_some_and(|scheme| {
                        !scheme.eq_ignore_ascii_case("http")
                            && !scheme.eq_ignore_ascii_case("https")
                    }) {
                        return None;
                    }
                    path
                }
                _ => return None,
            };
            if path.contains(['{', '}', '[', ']']) {
                return None;
            }
            let path = path.split(['?', '#']).next()?.strip_prefix("/v1/")?;
            super::credential::vault_kv_destroy_target(path, delete).map(|target| (target, delete))
        })
        .flatten();
        if let Some((target, delete)) = vault_destroy {
            super::credential::vault_http_destroy(builder, ctx, model_node, target, delete);
        }
        // One PATCH of GitHub's ref route updates a ref. A body read from a
        // file or config, sent as a form, or moved to the query is not read
        // here, so its force stays unknown. A POST to an Elasticsearch delete
        // route takes its body the same way.
        if scanned.unknown_flags.is_empty()
            && matches!(method, Some("PATCH" | "POST"))
            && urls.len() == 1
        {
            let bodies = scanned
                .flags
                .iter()
                .filter(|flag| {
                    matches!(
                        flag.name,
                        "-d" | "--data"
                            | "--data-binary"
                            | "--data-ascii"
                            | "--data-raw"
                            | "--json"
                    )
                })
                .collect::<Vec<_>>();
            let unread_body = scanned.has(&[
                "-G",
                "--get",
                "-K",
                "--config",
                "--data-urlencode",
                "-F",
                "--form",
                "--form-string",
                "-T",
                "--upload-file",
            ]);
            // curl joins several bodies with `&` and reads an `@file` body
            // from that file; only `--data-raw` sends a leading `@` as text.
            let body = match bodies.as_slice() {
                [flag] if !unread_body => flag.value.as_ref().filter(|value| {
                    flag.name == "--data-raw" || !value.literal_prefix().starts_with('@')
                }),
                _ => None,
            };
            if method == Some("POST") {
                super::datastore::elasticsearch_request(builder, ctx, model_node, urls[0], body);
            } else if unread_body || !bodies.is_empty() {
                super::gh_refs::curl_ref_request(builder, ctx, model_node, urls[0], body);
            }
        }
        let mut configured_requests = Vec::new();
        for (position, (index, url)) in urls.iter().enumerate() {
            let output = outputs.get(position).copied();
            let downloading = output.is_some_and(|flag| {
                matches!(flag.name, "-O" | "--remote-name")
                    || flag
                        .value
                        .as_ref()
                        .is_some_and(|value| !names_stdout(value.as_literal()))
            });
            let operation = if uploading {
                "network.upload"
            } else if downloading {
                "network.download"
            } else {
                "network.request"
            };
            let endpoint = match file_url(url) {
                Some(FileUrl::Foreign) => {
                    let arg = arg_node(builder, ctx, *index);
                    builder.boundary(Boundary {
                        reason: BoundaryReason::UNRESOLVED_TRANSFER_TARGET,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem"), Domain::new("network")],
                        provenance: vec![arg, model_node],
                        limit: None,
                        detail: Some(format!(
                            "file URL names a non-local authority (arg {index})"
                        )),
                    });
                    continue;
                }
                Some(FileUrl::Local(path)) => {
                    local_file_effect(builder, ctx, model_node, *index, &path, uploading)
                }
                None => {
                    let resource = endpoint_expr(url);
                    if let Some(attributes) = forge_delete_attributes.clone() {
                        let arg = arg_node(builder, ctx, *index);
                        builder.effect(Effect {
                            id: Default::default(),
                            operation: Operation::new("network.delete_request"),
                            resource,
                            attributes,
                            modality: Modality::MustOnSuccess,
                            request_assurance: effinterp_proto::RequestAssurance::Exact,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: Default::default(),
                            provenance: vec![arg, model_node],
                        })
                    } else {
                        let request = arg_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            if delete_request {
                                "network.delete_request"
                            } else {
                                operation
                            },
                            resource.clone(),
                            request_attrs.clone(),
                        );
                        configured_requests.push((*index, resource.clone()));
                        // curl sends the login of a `.netrc` entry that
                        // matches this host. Whether one matches is not
                        // established, so the credential upload is a May
                        // effect of its own beside the request.
                        if netrc_read.is_some() {
                            let upload = arg_effect(
                                builder,
                                ctx,
                                model_node,
                                *index,
                                "network.upload",
                                resource,
                                Attrs::from([(
                                    "purpose".into(),
                                    AttrValue::String("authentication".into()),
                                )]),
                            );
                            record_transfer(
                                builder,
                                netrc_read,
                                upload,
                                effinterp_proto::CausalAssurance::Conservative,
                            );
                        }
                        request
                    }
                }
            };
            if output.is_some_and(|flag| matches!(flag.name, "-O" | "--remote-name")) {
                let dest_word = url_basename(url)
                    .map(Word::literal)
                    .unwrap_or_else(|| Word::literal("."));
                let base = match url_basename(url) {
                    Some(_) => ctx.resolve_fs_word(&dest_word),
                    None => unresolved_resource("filesystem"),
                };
                let dest = curl_download_destination(builder, base, remote_header_name, no_clobber);
                let written = fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &dest_word,
                    "filesystem.write",
                    dest,
                    curl_download_attributes(remote_header_name, no_clobber),
                );
                record_transfer(builder, endpoint, written, transfer_assurance);
            } else if downloading {
                // `-o file`: the response body reaches the file this URL's
                // own output flag names.
                let written = output
                    .and_then(|flag| output_writes.get(&flag.index).copied())
                    .flatten();
                record_transfer(builder, endpoint, written, transfer_assurance);
            }
            if uploading {
                // With one upload source and several URLs every URL receives
                // it; otherwise the nth source pairs with the nth URL.
                let source = if upload_reads.len() == 1 {
                    upload_reads[0]
                } else {
                    upload_reads.get(position).copied().flatten()
                };
                record_transfer(
                    builder,
                    source,
                    endpoint,
                    effinterp_proto::CausalAssurance::Conservative,
                );
            }
        }

        // A config's options (`header`, `user`, `data`) go out with each
        // request. Which ones it holds is not read, so its bytes reach the
        // host as a May upload: from the named file, or from stdin, which the
        // stream analysis routes to every upload. They follow the requests so
        // that each response still pairs with its own output.
        for (index, resource) in configured_requests {
            let sources = config_reads
                .iter()
                .copied()
                .filter(Option::is_some)
                .chain(stdin_config.then_some(None));
            for read in sources {
                let upload = arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "network.upload",
                    resource.clone(),
                    Attrs::from([("purpose".into(), AttrValue::String("configuration".into()))]),
                );
                record_transfer(
                    builder,
                    read,
                    upload,
                    effinterp_proto::CausalAssurance::Conservative,
                );
            }
        }
        fs_full_no_spawn(builder);
        network_full(builder);
        config_boundary(builder, model_node, &scanned, &["-K", "--config"], "curl");
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "network"],
            &scanned.unknown_flags,
        );
    }
}

/// A config/input file can introduce URLs and outputs the static analysis
/// cannot see.
fn config_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    scanned: &Scanned,
    flags: &[&str],
    tool: &str,
) {
    for (index, value) in scanned.values_of(flags) {
        let shown = value.as_literal().unwrap_or("<dynamic>");
        builder.boundary(Boundary {
            reason: BoundaryReason::UNREAD_CONFIG,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem"), Domain::new("network")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!(
                "{tool} options loaded from {shown:?} (arg {index})"
            )),
        });
    }
}

struct Wget;

const WGET_BODY_DATA_FLAGS: &[&str] = &["--post-data", "--body-data"];
const WGET_BODY_FILE_FLAGS: &[&str] = &["--post-file", "--body-file"];
const WGET_UPLOAD_FLAGS: &[&str] = &["--post-data", "--post-file", "--body-data", "--body-file"];
const WGET_HEADER_FLAGS: &[&str] = &["--header", "--user", "--password"];
const WGET_CONFIG_FLAGS: &[&str] = &[
    "--ca-certificate",
    "--certificate",
    "--private-key",
    "--load-cookies",
    "--config",
];
const WGET_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    // wget parses long options with getopt_long, which accepts an unambiguous
    // prefix of an option name.
    allow_abbreviation: true,
    value_flags: &[
        "-O",
        "--output-document",
        "-P",
        "--directory-prefix",
        "-i",
        "--input-file",
        "--post-data",
        "--post-file",
        "--body-data",
        "--body-file",
        "-o",
        "--output-file",
        "-a",
        "--append-output",
        "--header",
        "-U",
        "--user-agent",
        "-t",
        "--tries",
        "-T",
        "--timeout",
        "--limit-rate",
        "--load-cookies",
        "--save-cookies",
        "--ca-certificate",
        "--certificate",
        "--private-key",
        "--config",
        "--method",
        "--user",
        "--password",
        "--http-user",
        "--http-password",
        "-A",
        "--accept",
        "-R",
        "--reject",
        "--domains",
        "--exclude-domains",
        "-l",
        "--level",
        "-e",
        "--execute",
        "-w",
        "--wait",
    ],
    known_flags: &[
        "-q",
        "--quiet",
        "-c",
        "--continue",
        "-b",
        "--background",
        "-N",
        "--timestamping",
        "-r",
        "--recursive",
        "-m",
        "--mirror",
        "-k",
        "--convert-links",
        "-p",
        "--page-requisites",
        "-np",
        "--no-parent",
        "-nd",
        "--no-directories",
        "-x",
        "--force-directories",
        "-nH",
        "--no-host-directories",
        "-4",
        "-6",
        "--no-check-certificate",
        "-S",
        "--server-response",
        "--spider",
        "-nv",
        "--no-verbose",
        "-nc",
        "--no-clobber",
        "-H",
        "--span-hosts",
    ],
};

pub(crate) struct WgetFlowInfo {
    pub(crate) assurance: effinterp_proto::CausalAssurance,
    pub(crate) stdout_download: bool,
    /// `--post-file=-`/`--body-file=-` send wget's standard input as the body.
    pub(crate) stdin_upload: bool,
    pub(crate) body_read_arguments: Vec<u32>,
    pub(crate) body_value_arguments: Vec<u32>,
    pub(crate) header_arguments: Vec<u32>,
    /// TLS material and cookie-file values. Producer fallback must not carry
    /// these onto the request; they configure the transfer rather than supply
    /// its body or headers.
    pub(crate) config_arguments: Vec<u32>,
    /// Output-path values (`-O`, `-P`, `-o`, `-a`). Local destinations and log
    /// files, not bytes wget sends, so the fallback must not bind them onto
    /// the request's network effect.
    pub(crate) output_value_arguments: Vec<u32>,
}

pub(crate) fn wget_flow_info(words: &[Word]) -> WgetFlowInfo {
    let scanned = scan(words, &WGET_FLAG_SPEC);
    let value_scanned = scan_with_value_indices(words, &WGET_FLAG_SPEC, true);
    let mut body_read_arguments = scanned
        .values_of(WGET_UPLOAD_FLAGS)
        .into_iter()
        .map(|(index, _)| index)
        .chain(
            value_scanned
                .values_of(WGET_UPLOAD_FLAGS)
                .into_iter()
                .map(|(index, _)| index),
        )
        .collect::<Vec<_>>();
    body_read_arguments.sort_unstable();
    body_read_arguments.dedup();
    let body_flags = scanned
        .flags
        .iter()
        .filter(|flag| WGET_UPLOAD_FLAGS.contains(&flag.name))
        .collect::<Vec<_>>();
    let method_flags = scanned
        .flags
        .iter()
        .filter(|flag| flag.name == "--method")
        .collect::<Vec<_>>();
    let output_flags = scanned
        .flags
        .iter()
        .filter(|flag| matches!(flag.name, "-O" | "--output-document"))
        .collect::<Vec<_>>();
    let stdout_download = output_flags
        .last()
        .is_some_and(|flag| names_stdout(flag.value.as_ref().and_then(Word::as_literal)));
    let stdin_upload = scanned
        .values_of(WGET_BODY_FILE_FLAGS)
        .iter()
        .any(|(_, value)| value.as_literal() == Some("-"));
    let direct_url = (scanned.operands.len() == 1)
        .then(|| scanned.operands[0].1.as_literal())
        .flatten()
        .filter(|url| !url.contains(['{', '}', '[', ']']))
        .and_then(|url| parse_endpoint(url).map(|endpoint| (url, endpoint)));
    let one_wget_url = direct_url.as_ref().is_some_and(|(url, endpoint)| {
        let ResourceIdentity::NetworkEndpoint { scheme, .. } = endpoint else {
            return false;
        };
        scheme.as_deref().is_some_and(|scheme| {
            ["http", "https", "ftp", "ftps"]
                .iter()
                .any(|supported| scheme.eq_ignore_ascii_case(supported))
        }) || scheme.is_none() && !url.contains([':', '@'])
    });
    let one_http_url = direct_url.as_ref().is_some_and(|(url, endpoint)| {
        let ResourceIdentity::NetworkEndpoint { scheme, .. } = endpoint else {
            return false;
        };
        scheme.as_deref().is_some_and(|scheme| {
            ["http", "https"]
                .iter()
                .any(|supported| scheme.eq_ignore_ascii_case(supported))
        }) || scheme.is_none() && !url.contains([':', '@'])
    });
    let literal_value = |flag: &&crate::models::args::Flag<'_>| {
        flag.value
            .as_ref()
            .and_then(Word::as_literal)
            .is_some_and(|value| !value.is_empty())
    };
    let quiet_flag = |flag: &crate::models::args::Flag<'_>| {
        flag.value.is_none()
            && (flag.name == "-q"
                || words.get(flag.index as usize).and_then(Word::as_literal) == Some("--quiet"))
    };
    let reviewed_method = method_flags.len() == 1
        && method_flags[0]
            .value
            .as_ref()
            .and_then(Word::as_literal)
            .is_some_and(|method| matches!(method, "POST" | "PUT" | "PATCH"));
    let common = scanned.unknown_flags.is_empty()
        && words.iter().all(|word| word.as_literal().is_some())
        && one_wget_url;
    let audited_download = common
        && body_flags.is_empty()
        && output_flags.len() == 1
        && literal_value(&output_flags[0])
        && scanned.flags.iter().all(|flag| match flag.name {
            "-q" | "--quiet" => quiet_flag(flag),
            "-O" | "--output-document" => literal_value(&flag),
            _ => false,
        });
    let audited_body = common
        && one_http_url
        && body_flags.len() == 1
        && output_flags.len() <= 1
        && literal_value(&body_flags[0])
        && if matches!(body_flags[0].name, "--post-data" | "--post-file") {
            method_flags.is_empty()
        } else {
            reviewed_method
        }
        && scanned.flags.iter().all(|flag| match flag.name {
            "-q" | "--quiet" => quiet_flag(flag),
            name if WGET_UPLOAD_FLAGS.contains(&name) => true,
            "--method" => true,
            "-O" | "--output-document" => literal_value(&flag),
            _ => false,
        });
    WgetFlowInfo {
        assurance: if audited_download || audited_body {
            effinterp_proto::CausalAssurance::Exact
        } else {
            effinterp_proto::CausalAssurance::Conservative
        },
        stdout_download,
        stdin_upload,
        body_read_arguments,
        body_value_arguments: value_scanned
            .values_of(WGET_BODY_DATA_FLAGS)
            .into_iter()
            .map(|(index, _)| index)
            .collect(),
        header_arguments: value_scanned
            .values_of(WGET_HEADER_FLAGS)
            .into_iter()
            .map(|(index, _)| index)
            .collect(),
        config_arguments: value_scanned
            .values_of(WGET_CONFIG_FLAGS)
            .into_iter()
            .map(|(index, _)| index)
            .collect(),
        output_value_arguments: value_scanned
            .values_of(&[
                "-O",
                "--output-document",
                "-o",
                "--output-file",
                "-a",
                "--append-output",
                "-P",
                "--directory-prefix",
            ])
            .into_iter()
            .map(|(index, _)| index)
            .collect(),
    }
}

impl CommandModel for Wget {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "net/wget@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["wget"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let transfer_assurance = wget_flow_info(ctx.argv).assurance;
        let scanned = scan_with_value_indices(
            ctx.argv,
            &WGET_FLAG_SPEC,
            ctx.tracks_host_context_environment(),
        );
        let uploading = scanned.has(WGET_UPLOAD_FLAGS);
        let spider = scanned.has(&["--spider"]);

        // An upload body read pairs with the URL it is sent to; a cookie jar
        // read is not a transfer source.
        let mut upload_reads: Vec<Option<u32>> = Vec::new();
        let upload_files = scanned.values_of(WGET_BODY_FILE_FLAGS);
        for (index, value) in scanned.values_of(&["--post-file", "--body-file", "--load-cookies"]) {
            let is_upload = upload_files
                .iter()
                .any(|(upload_index, _)| *upload_index == index);
            // `--post-file=-`/`--body-file=-` send standard input rather than a
            // file, so its bytes arrive through the stdin port, not a read here.
            if is_upload && value.as_literal() == Some("-") {
                continue;
            }
            let slot = operand_effect(
                builder,
                ctx,
                model_node,
                index,
                value,
                "filesystem.read",
                if is_upload {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
            if is_upload {
                upload_reads.push(slot);
            }
        }
        for (index, value) in scanned.values_of(&[
            "--save-cookies",
            "-o",
            "--output-file",
            "-a",
            "--append-output",
        ]) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                value,
                "filesystem.write",
                Default::default(),
            );
        }

        let explicit_output = scanned
            .values_of(&["-O", "--output-document"])
            .into_iter()
            .last();
        let prefix = scanned
            .values_of(&["-P", "--directory-prefix"])
            .into_iter()
            .last();
        for (position, (index, url)) in scanned.operands.iter().enumerate() {
            let operation = if uploading {
                "network.upload"
            } else {
                "network.download"
            };
            let endpoint = arg_effect(
                builder,
                ctx,
                model_node,
                *index,
                operation,
                endpoint_expr(url),
                Default::default(),
            );
            if uploading {
                // One body is sent to every URL; otherwise each body pairs
                // with the URL at its own position.
                let source = if upload_reads.len() == 1 {
                    upload_reads[0]
                } else {
                    upload_reads.get(position).copied().flatten()
                };
                record_transfer(
                    builder,
                    source,
                    endpoint,
                    effinterp_proto::CausalAssurance::Conservative,
                );
            }
            if spider {
                continue;
            }
            let (dest, target_index, target_word, cites_url) = match explicit_output {
                Some((_, output)) if names_stdout(output.as_literal()) => continue,
                Some((output_index, output)) => (
                    ctx.resolve_fs_word(output),
                    output_index,
                    output.clone(),
                    false,
                ),
                None => {
                    let name = if url.as_literal().is_some() {
                        Word::literal(url_basename(url).unwrap_or_else(|| "index.html".to_string()))
                    } else {
                        Word::new(vec![WordPart::Literal(String::new()), WordPart::Unknown])
                    };
                    match prefix {
                        Some((prefix_index, dir)) => (
                            crate::models::fsutils::dest_in_dir(
                                dir,
                                &name,
                                ctx.cwd_resource(),
                                ctx.nest.path_platform,
                            ),
                            prefix_index,
                            dir.clone(),
                            true,
                        ),
                        None => (ctx.resolve_fs_word(&name), *index, name, false),
                    }
                }
            };
            let written = if ctx.tracks_host_context_environment() {
                let mut provenance = vec![fs_arg_node(builder, ctx, target_index, &target_word)];
                if cites_url {
                    provenance.push(arg_node(builder, ctx, *index));
                }
                provenance.push(model_node);
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new("filesystem.write"),
                    resource: dest,
                    attributes: program_output_attrs(),
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance,
                })
            } else {
                fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &target_word,
                    "filesystem.write",
                    dest,
                    program_output_attrs(),
                )
            };
            if !uploading {
                record_transfer(builder, endpoint, written, transfer_assurance);
            }
        }

        // URLs loaded from a file are downloads the plan cannot enumerate.
        for (index, value) in scanned.values_of(&["-i", "--input-file"]) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                value,
                "filesystem.read",
                Default::default(),
            );
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.download",
                unresolved_resource("network"),
                Default::default(),
            );
            builder.boundary(Boundary {
                reason: BoundaryReason::UNREAD_CONFIG,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("network")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("wget URL list loaded from a file".to_string()),
            });
        }
        if scanned.value_of(&["-e", "--execute"]).is_some() {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNREAD_CONFIG,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("network")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("wget -e injects wgetrc commands".to_string()),
            });
        }

        fs_full_no_spawn(builder);
        network_full(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "network"],
            &scanned.unknown_flags,
        );
    }
}

struct Netcat;

struct SocketSession {
    index: u32,
    endpoint: ResourceExpr,
    port: u16,
    protocol: &'static str,
    listen: bool,
    receive: bool,
    send: bool,
    handler: Option<(u32, bool, Word)>,
}

// nc implementations disagree about what -e names and about listening with
// -p: netcat-traditional and Ncat run the program -e names, while OpenBSD's
// TLS build reads it as a certificate name and rejects -p beside -l. The
// reading that acts is modeled, since its effects are a superset and each
// one stays a `may`.
fn socket_session(argv: &[Word]) -> Result<Option<SocketSession>, &'static str> {
    let ncat = argv
        .first()
        .and_then(Word::as_literal)
        .and_then(|name| name.rsplit('/').next())
        == Some("ncat");
    let flags: &[&str] = if ncat {
        &[
            "-4",
            "-6",
            "-l",
            "--listen",
            "-u",
            "--udp",
            "-v",
            "--verbose",
            "-n",
            "--nodns",
            "-z",
            "--zero",
            "--send-only",
            "--recv-only",
            "-h",
            "--help",
            "--version",
        ]
    } else {
        &["-4", "-6", "-l", "-u", "-v", "-n", "-z", "-d", "-h"]
    };
    // -e hands its value to exec, -c to a shell; Ncat spells both long too.
    let handler_flags: &[&str] = if ncat {
        &["--exec", "-e", "--sh-exec", "-c"]
    } else {
        &["-e", "-c"]
    };
    // -p names the local port; in listen mode it is the port bound when no
    // port operand names one.
    let value_flags: &[&str] = if ncat {
        &["--exec", "-e", "--sh-exec", "-c", "-p", "--source-port"]
    } else {
        &["-e", "-c", "-p"]
    };
    let parsed = scan_with_value_indices(
        argv,
        &FlagSpec {
            value_flags,
            known_flags: flags,
            allow_abbreviation: false,
        },
        true,
    );
    if !parsed.unknown_flags.is_empty()
        || parsed.flags.iter().any(|flag| {
            if value_flags.contains(&flag.name) {
                flag.value.is_none()
            } else {
                argv[flag.index as usize].literal_prefix().contains('=')
            }
        })
    {
        return Err("network socket options or handler dialect are unmodeled");
    }
    if parsed.has(&["-h", "--help", "--version"]) {
        return Ok(None);
    }
    let listen = parsed.has(&["-l", "--listen"]);
    let scan = parsed.has(&["-z", "--zero"]);
    if listen && scan
        || parsed.has(&["-4"]) && parsed.has(&["-6"])
        || parsed.has(&["--send-only"]) && parsed.has(&["--recv-only"])
    {
        return Err("network socket options conflict");
    }
    let handlers: Vec<_> = parsed
        .flags
        .iter()
        .filter(|flag| handler_flags.contains(&flag.name))
        .collect();
    if handlers.len() > 1
        || !handlers.is_empty() && (scan || parsed.has(&["--send-only", "--recv-only"]))
    {
        return Err("Ncat handler options conflict or require unmodeled stream selection");
    }
    let handler = handlers.first().map(|flag| {
        (
            flag.value_index.unwrap_or(flag.index),
            matches!(flag.name, "--sh-exec" | "-c"),
            flag.value.clone().unwrap(),
        )
    });
    let local_port = parsed.value_of(&["-p", "--source-port"]);
    let (index, host, port_word) = match (listen, parsed.operands.as_slice()) {
        (false, [(index, host), (_, port)]) | (true, [(index, host), (_, port)]) => {
            (*index, Some(*host), Some(*port))
        }
        (true, [(index, port)]) => (*index, None, Some(*port)),
        (false, [(index, host)]) if ncat => (*index, Some(*host), None),
        (true, []) if ncat || local_port.is_some() => (0, None, local_port),
        // Given neither a destination host and port nor a listening port,
        // nc prints its usage and exits before opening anything. A literal
        // argv is the whole operand list, so that is settled here.
        _ if argv.iter().all(|word| word.as_literal().is_some()) => return Ok(None),
        _ => return Err("network socket destination or listening port is unresolved"),
    };
    let port = match port_word {
        Some(word) => match word.as_literal().and_then(|text| text.parse::<u16>().ok()) {
            Some(port) if port != 0 => port,
            _ => return Err("network socket service or port range is unmodeled"),
        },
        None => 31337,
    };
    if host.is_some_and(|word| word.as_literal() == Some("")) {
        return Err("network socket host is empty");
    }
    if let Some(host) = host.and_then(Word::as_literal) {
        let address = host.parse::<std::net::IpAddr>();
        if parsed.has(&["-n", "--nodns"]) && address.is_err()
            || parsed.has(&["-4"]) && matches!(address, Ok(std::net::IpAddr::V6(_)))
            || parsed.has(&["-6"]) && matches!(address, Ok(std::net::IpAddr::V4(_)))
        {
            return Err("network socket host conflicts with numeric or address-family options");
        }
    }
    let scheme = if parsed.has(&["-u", "--udp"]) {
        "udp"
    } else {
        "tcp"
    };
    let endpoint = match host {
        Some(host) => match host.as_literal() {
            Some(host) => ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: host.into(),
                    scheme: Some(scheme.into()),
                    port: Some(port),
                    path: None,
                },
            },
            None => ResourceExpr::Join {
                parts: vec![
                    crate::models::common::remote_endpoint(host.parts.clone(), scheme),
                    ResourceExpr::Literal {
                        value: format!(":{port}"),
                    },
                ],
            },
        },
        None => unresolved_resource("network"),
    };
    Ok(Some(SocketSession {
        index,
        endpoint,
        port,
        protocol: scheme,
        handler,
        listen,
        receive: !scan && !parsed.has(&["--send-only"]),
        send: !scan && !parsed.has(&["-d", "--recv-only"]),
    }))
}

impl CommandModel for Netcat {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }
    fn id(&self) -> &'static str {
        "network/netcat@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["nc", "netcat", "ncat"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        use crate::models::{ModelBindingEnd, ModelCausalBinding};
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::Port;
        let Ok(Some(session)) = socket_session(argv) else {
            return Vec::new();
        };
        if session.handler.is_some() {
            return Vec::new();
        }
        // Plain TCP sessions wire stdin/stdout to their peer. This proves
        // the byte relation, not a successful connection or any bytes sent.
        let assurance =
            if session.protocol == "tcp" && argv.iter().all(|word| word.as_literal().is_some()) {
                effinterp_proto::CausalAssurance::Exact
            } else {
                effinterp_proto::CausalAssurance::Conservative
            };
        let mut bindings = Vec::new();
        if session.receive {
            bindings.push(ModelCausalBinding {
                assurance,
                from: ModelBindingEnd::Effect {
                    operation: "network.download".into(),
                    selection: EffectSelection::All,
                },
                to: ModelBindingEnd::Port(Port::Stdout),
            });
        }
        if session.send {
            bindings.push(ModelCausalBinding {
                assurance,
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: EffectSelection::All,
                },
            });
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let session = match socket_session(ctx.argv) {
            Ok(Some(session)) => session,
            Ok(None) => return,
            Err(detail) => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("network"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(detail.into()),
                });
                return;
            }
        };
        let attributes = BTreeMap::from([
            ("listen".into(), AttrValue::Bool(session.listen)),
            ("port".into(), AttrValue::String(session.port.to_string())),
            (
                "protocol".into(),
                AttrValue::String(session.protocol.into()),
            ),
        ]);
        arg_effect(
            builder,
            ctx,
            model_node,
            session.index,
            if session.listen {
                "network.listen"
            } else {
                "network.connect"
            },
            session.endpoint.clone(),
            attributes.clone(),
        );
        // A listener's local bind address does not identify its future peer.
        let peer = if session.listen {
            unresolved_resource("network")
        } else {
            session.endpoint
        };
        let input = session
            .receive
            .then(|| {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    session.index,
                    "network.download",
                    peer.clone(),
                    attributes.clone(),
                )
            })
            .flatten();
        let output = session
            .send
            .then(|| {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    session.index,
                    "network.upload",
                    peer,
                    attributes,
                )
            })
            .flatten();
        if let Some((index, shell, command)) = session.handler {
            let argument = arg_node(builder, ctx, index);
            let subject = command.as_literal().and_then(|text| {
                if shell {
                    Some(effinterp_proto::Subject::Shell {
                        source: text.into(),
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                } else {
                    split_ncat_command(text).map(|argv| effinterp_proto::Subject::Exec {
                        argv,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                }
            });
            if let Some(subject) = subject {
                connected_handler(
                    builder,
                    ctx,
                    &[model_node, argument],
                    subject,
                    input,
                    output,
                    [
                        "NCAT_REMOTE_ADDR",
                        "NCAT_REMOTE_PORT",
                        "NCAT_LOCAL_ADDR",
                        "NCAT_LOCAL_PORT",
                        "NCAT_PROTO",
                    ]
                    .into_iter()
                    .map(|name| {
                        let value = if name == "NCAT_PROTO" {
                            ResourceExpr::Literal {
                                value: session.protocol.into(),
                            }
                        } else {
                            unresolved_resource("value")
                        };
                        (name.to_string(), Some(value))
                    })
                    .collect(),
                    false,
                    ctx.runtime_cwd,
                );
            } else {
                socket_handler_boundary(
                    builder,
                    &[model_node, argument],
                    "Ncat handler command is not statically recoverable",
                );
            }
        }
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    }
}

// Ncat's POSIX cmdline_split treats quotes literally; only backslashes escape.
fn split_ncat_command(text: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut word = String::new();
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch.is_ascii_whitespace() {
            if !word.is_empty() {
                args.push(std::mem::take(&mut word));
            }
        } else {
            word.push(ch);
        }
    }
    if escaped {
        return None;
    }
    if !word.is_empty() {
        args.push(word);
    }
    (!args.is_empty()).then_some(args)
}

/// A program name whose basename is a POSIX shell, so attaching a network
/// connection to it hands the peer an interactive shell.
fn is_shell_program(program: &str) -> bool {
    matches!(
        program.rsplit('/').next(),
        Some("sh" | "bash" | "dash" | "zsh" | "ash" | "ksh" | "mksh")
    )
}

fn socket_handler_boundary(builder: &mut PlanBuilder, provenance: &[ProvenanceRef], detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: crate::builder::KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: provenance.to_vec(),
        limit: None,
        detail: Some(detail.into()),
    });
}

// Handler stdin/stdout belong to the connection, not the launcher's terminal.
// Effects remain optional: establishing a socket does not prove a peer arrives.
#[allow(clippy::too_many_arguments)]
fn connected_handler(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    subject: effinterp_proto::Subject,
    input: Option<u32>,
    output: Option<u32>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    stderr_to_output: bool,
    // The directory the handler starts in, as a repository- or host-anchored
    // base for resolving its script source. `None` means the handler's cwd is
    // unknown, so a relative source cannot be found rather than falling back to
    // the parent's file.
    runtime_cwd: Option<&str>,
) {
    use crate::flow::{BindEnd, FlowStage, PortBinding};
    use effinterp_proto::{ExecutionEdgeKind, ExecutionStreams, Port};
    // With socat's `stderr` option the handler's standard error is the
    // connection, not socat's own.
    let stderr = if stderr_to_output {
        Default::default()
    } else {
        builder.inherited_execution_streams().stderr
    };
    // A handler that changes directory (`chdir=`) starts there, not in
    // socat's own cwd.
    let subject_cwd = match &subject {
        effinterp_proto::Subject::Exec { cwd, .. }
        | effinterp_proto::Subject::Shell { cwd, .. } => cwd.as_deref(),
        _ => ctx.cwd,
    };
    let cwd = match subject_cwd {
        Some(path) if subject_cwd != ctx.cwd => Some(ctx.resolve_fs_word(&Word::literal(path))),
        _ => ctx.cwd_resource(),
    };
    let transition = crate::nest::Transition::file(subject.clone())
        .kind(ExecutionEdgeKind::Launch)
        .cwd(cwd, ctx.cwd_node)
        .runtime_cwd(runtime_cwd)
        .environment(environment, BTreeMap::new(), Default::default())
        .streams(ExecutionStreams {
            stderr,
            ..Default::default()
        });
    let Some(frame) = ctx.nest.begin(builder, transition, provenance, ctx.depth) else {
        return;
    };
    crate::nest::analyze_subject(
        builder,
        ctx.nest,
        &subject,
        Some(frame.scope),
        ctx.cwd_node,
        ctx.depth + 1,
    );
    let mut bindings = Vec::new();
    if let Some(effect) = input {
        bindings.push(PortBinding {
            assurance: effinterp_proto::CausalAssurance::Exact,
            from: BindEnd::Effect(effect),
            to: BindEnd::Port(Port::Stdin),
        });
    }
    if let Some(effect) = output {
        let ports = if stderr_to_output {
            &[Port::Stdout, Port::Stderr][..]
        } else {
            &[Port::Stdout][..]
        };
        for port in ports {
            bindings.push(PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: BindEnd::Port(port.clone()),
                to: BindEnd::Effect(effect),
            });
        }
    }
    builder.flow_stage(FlowStage {
        execution: Some(frame.execution),
        effects: input.into_iter().chain(output).collect(),
        bindings,
        provenance: provenance.to_vec(),
    });
    frame.end(builder);
}

struct Mail;

const MAIL_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    value_flags: &["-a", "-b", "-c", "-q", "-r", "-s", "-S"],
    known_flags: &["-E", "-i", "-I", "-n", "-N", "-v", "-~"],
    allow_abbreviation: false,
};

/// The recipient operands of a `mail` send. Options are skipped by the
/// mailx option letters, which all take their value as a separate word;
/// anything else leaves the invocation unmodeled rather than guessed.
fn mail_recipients(argv: &[Word]) -> Result<Vec<(u32, Word)>, &'static str> {
    // `-t` takes the recipients from the message header instead of argv, and
    // `-f`/`-u` open a mailbox to read rather than send.
    let parsed = scan(argv, &MAIL_FLAG_SPEC);
    if !parsed.unknown_flags.is_empty() {
        return Err("mail options are unmodeled");
    }
    Ok(parsed
        .operands
        .iter()
        .map(|(index, word)| (*index, (*word).clone()))
        .collect())
}

impl CommandModel for Mail {
    fn domains(&self) -> &'static [&'static str] {
        &["network", "process"]
    }
    fn id(&self) -> &'static str {
        "network/mail@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["mail", "mailx"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        use crate::models::{ModelBindingEnd, ModelCausalBinding};
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::Port;
        let Ok(recipients) = mail_recipients(argv) else {
            return Vec::new();
        };
        if recipients.is_empty() {
            return Vec::new();
        }
        // `-s` changes only the subject. Other recognized options can add
        // message sources, recipients, or configuration and stay conservative.
        let parsed = scan(argv, &MAIL_FLAG_SPEC);
        let exact = parsed.flags.iter().all(|flag| flag.name == "-s")
            && recipients.iter().all(|(_, word)| {
                word.as_literal().is_some_and(|address| {
                    address.contains('@')
                        && !address.starts_with('-')
                        && !address.contains(['/', '|', ',', ';', '<', '>', ' ', '\t', '\n'])
                })
            });
        vec![ModelCausalBinding {
            assurance: if exact {
                effinterp_proto::CausalAssurance::Exact
            } else {
                effinterp_proto::CausalAssurance::Conservative
            },
            from: ModelBindingEnd::Port(Port::Stdin),
            to: ModelBindingEnd::Effect {
                operation: "network.upload".into(),
                selection: EffectSelection::All,
            },
        }]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let recipients = match mail_recipients(ctx.argv) {
            Ok(recipients) if recipients.is_empty() => {
                // Without a recipient `mail` opens a mailbox instead of sending.
                Err("mail without a recipient reads a mailbox")
            }
            other => other,
        };
        let recipients = match recipients {
            Ok(recipients) => recipients,
            Err(detail) => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("network"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(detail.into()),
                });
                return;
            }
        };
        for (index, word) in recipients {
            // A recipient address names the mailbox the body is delivered to;
            // the transport that carries it there is the host's own.
            let address = match word.as_literal() {
                Some(text) => ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host: text.to_string(),
                        scheme: None,
                        port: None,
                        path: None,
                    },
                },
                None => symbolic_expr(&word, "network"),
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.upload",
                address,
                Default::default(),
            );
        }
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    }
}

/// `dig`, `nslookup` and `host`: a DNS lookup sends each name it asks about
/// to the servers it asks.
struct DnsLookup;

/// Record types and classes `dig` and `host` accept as bare operands beside
/// the name being looked up.
const DNS_RECORD_WORDS: &[&str] = &[
    "a", "aaaa", "any", "axfr", "caa", "ch", "cname", "dnskey", "ds", "hs", "in", "mx", "naptr",
    "ns", "ptr", "soa", "srv", "txt",
];

/// The `dig` options a DNS lookup is read through; any other leaves it
/// unmodeled.
const DIG_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    value_flags: &["-b", "-c", "-p", "-q", "-t"],
    known_flags: &["-4", "-6", "-m", "-r", "-u"],
    allow_abbreviation: false,
};

/// The `host` options a DNS lookup is read through; any other leaves it
/// unmodeled.
const HOST_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    value_flags: &["-c", "-N", "-R", "-t", "-W"],
    known_flags: &["-4", "-6", "-a", "-d", "-r", "-s", "-T", "-U", "-v", "-w"],
    allow_abbreviation: false,
};

/// The words of a DNS lookup that leave the machine: each name asked about
/// and each server asked. A lookup's name is itself data sent to whoever
/// serves that zone, so every one is a request endpoint. Options this does
/// not know leave the invocation unmodeled: `dig -f` reads names from a
/// file, `-x` builds a reverse name, `-k`/`-y` load keys.
fn dns_lookup_endpoints(argv: &[Word]) -> Result<Vec<(u32, Word)>, &'static str> {
    let command = argv[0]
        .as_literal()
        .and_then(|name| name.rsplit('/').next());
    let mut endpoints: Vec<(u32, Word)> = if command == Some("nslookup") {
        // Every nslookup option is one `-name[=value]` word; a lone `-`
        // starts the interactive mode, which takes its queries from stdin.
        if argv[1..].iter().any(|word| word.as_literal() == Some("-")) {
            return Err("interactive nslookup reads its queries from stdin");
        }
        argv.iter()
            .enumerate()
            .skip(1)
            .filter(|(_, word)| !word.as_literal().is_some_and(|text| text.starts_with('-')))
            .map(|(index, word)| (index as u32, word.clone()))
            .collect()
    } else {
        let dig = command == Some("dig");
        let parsed = scan(argv, if dig { &DIG_FLAG_SPEC } else { &HOST_FLAG_SPEC });
        if !parsed.unknown_flags.is_empty() {
            return Err("DNS lookup options are unmodeled");
        }
        let mut endpoints: Vec<(u32, Word)> = parsed
            .flags
            .iter()
            .filter(|flag| dig && flag.name == "-q")
            .filter_map(|flag| Some((flag.index, flag.value.clone()?)))
            .collect();
        endpoints.extend(
            parsed
                .operands
                .iter()
                // `+short` and its kin are dig query options.
                .filter(|(_, word)| !(dig && word.as_literal().is_some_and(|t| t.starts_with('+'))))
                .map(|(index, word)| (*index, (*word).clone())),
        );
        endpoints
    };
    endpoints.retain(|(_, word)| {
        !word
            .as_literal()
            .is_some_and(|text| DNS_RECORD_WORDS.contains(&text.to_ascii_lowercase().as_str()))
    });
    if endpoints.is_empty() {
        return Err("DNS lookup names no query");
    }
    Ok(endpoints)
}

impl CommandModel for DnsLookup {
    fn domains(&self) -> &'static [&'static str] {
        &["network", "process"]
    }
    fn id(&self) -> &'static str {
        "network/dns-lookup@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["dig", "nslookup", "host"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let endpoints = match dns_lookup_endpoints(ctx.argv) {
            Ok(endpoints) => endpoints,
            Err(detail) => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("network"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(detail.into()),
                });
                return;
            }
        };
        for (index, word) in endpoints {
            let endpoint = match word.as_literal() {
                // dig spells the server to ask as `@server`.
                Some(text) => ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host: text.trim_start_matches('@').to_string(),
                        scheme: None,
                        port: None,
                        path: None,
                    },
                },
                None => symbolic_expr(&word, "network"),
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.request",
                endpoint,
                Default::default(),
            );
        }
        // The lookup also goes to the host's configured resolver, and
        // resolv.conf and `~/.digrc` are not read.
        builder.boundary(Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("network")],
            provenance: vec![model_node],
            limit: None,
            detail: Some("resolver configuration is not read".to_string()),
        });
    }
}

struct Socat;

/// One end of a socat address: what it names and how bytes cross it.
#[derive(Clone)]
enum SocatEnd {
    /// A file, named pipe, or generic open; `readable`/`writable` follow the
    /// address keyword.
    File {
        word: Word,
        resource: ResourceExpr,
        readable: bool,
        writable: bool,
        /// `PIPE:<name>` and `FIFO:<name>` create a named pipe when nothing
        /// is there to open.
        creates_fifo: bool,
    },
    Socket {
        resource: ResourceExpr,
        protocol: &'static str,
        listen: bool,
        address: String,
        proxy: Option<ResourceExpr>,
    },
    /// `EXEC` runs argv directly; `SYSTEM` and `SHELL:` hand the text to a
    /// shell. `stderr` sends the handler's standard error to the connection
    /// as well, and `chdir` is the directory the handler starts in.
    Handler {
        shell: bool,
        command: String,
        stderr: bool,
        chdir: Option<String>,
    },
    /// socat's own standard descriptors: `reads` names the standard
    /// descriptor its input comes from, and `writes` the one its output goes
    /// to.
    Stdio {
        reads: Option<u32>,
        writes: Option<u32>,
    },
}

/// A socat address operand. `read!!write` names the reading and writing ends
/// separately; every other address is both ends.
struct SocatAddress {
    read: SocatEnd,
    write: SocatEnd,
    /// True when `read!!write` named the two ends separately.
    dual: bool,
}

/// Socket address keywords, longest spelling first so `TCP-LISTEN` is not
/// read as `TCP`.
const SOCAT_SOCKETS: [(&str, &str, bool); 29] = [
    ("DCCP4-CONNECT", "dccp", false),
    ("DCCP6-CONNECT", "dccp", false),
    ("DCCP-CONNECT", "dccp", false),
    ("DCCP4-LISTEN", "dccp", true),
    ("DCCP6-LISTEN", "dccp", true),
    ("DCCP-LISTEN", "dccp", true),
    ("DCCP4", "dccp", false),
    ("DCCP6", "dccp", false),
    ("DCCP", "dccp", false),
    ("TCP4-CONNECT", "tcp", false),
    ("TCP6-CONNECT", "tcp", false),
    ("TCP-CONNECT", "tcp", false),
    ("TCP4-LISTEN", "tcp", true),
    ("TCP6-LISTEN", "tcp", true),
    ("TCP-LISTEN", "tcp", true),
    ("TCP4", "tcp", false),
    ("TCP6", "tcp", false),
    ("TCP", "tcp", false),
    ("UDP4-CONNECT", "udp", false),
    ("UDP6-CONNECT", "udp", false),
    ("UDP-CONNECT", "udp", false),
    ("UDP-SENDTO", "udp", false),
    ("UDP4-LISTEN", "udp", true),
    ("UDP6-LISTEN", "udp", true),
    ("UDP-LISTEN", "udp", true),
    ("UDP4", "udp", false),
    ("UDP6", "udp", false),
    ("UDP", "udp", false),
    ("VSOCK-CONNECT", "vsock", false),
];

/// TLS address keywords, with the transport under them and whether they
/// listen. `SSL` and `SSL-L` are socat's aliases.
const SOCAT_TLS_SOCKETS: [(&str, &str, bool); 7] = [
    ("OPENSSL-CONNECT", "tcp", false),
    ("OPENSSL-LISTEN", "tcp", true),
    ("OPENSSL-DTLS-CLIENT", "udp", false),
    ("OPENSSL-DTLS-SERVER", "udp", true),
    ("OPENSSL", "tcp", false),
    ("SSL-L", "tcp", true),
    ("SSL", "tcp", false),
];

/// TLS address options. They configure the handshake (certificates, peer
/// verification, ciphers, protocol versions) and change neither the endpoint
/// nor where the connection's bytes go. Each may also be spelled with an
/// `openssl-` prefix. `min-proto-version`/`max-proto-version` are the
/// manual's names for `min-version`/`max-version`.
const SOCAT_TLS_OPTIONS: [&str; 28] = [
    "cafile",
    "capath",
    "cert",
    "certificate",
    "cipher",
    "cipherlist",
    "ciphers",
    "cn",
    "commonname",
    "compress",
    "dh",
    "dhparam",
    "dhparams",
    "egd",
    "fips",
    "key",
    "max-proto-version",
    "max-version",
    "maxfraglen",
    "maxsendfrag",
    "method",
    "min-proto-version",
    "min-version",
    "no-sni",
    "nosni",
    "pseudo",
    "snihost",
    "verify",
];

/// Socket options that change how the socket is set up or how many
/// connections it serves, but neither the endpoint nor where the
/// connection's bytes go. `fork` serves each connection in a child, which
/// repeats the same effects; `bind` picks the local address, not the peer.
/// `range` and `tcpwrap` restrict admitted peers without changing routing.
const SOCAT_SOCKET_OPTIONS: [&str; 14] = [
    "backlog",
    "bind",
    "fork",
    "keepalive",
    "max-children",
    "nodelay",
    "range",
    "reuseaddr",
    "reuseport",
    "so-keepalive",
    "so-reuseaddr",
    "so-reuseport",
    "tcp-nodelay",
    "tcpwrap",
];

/// File address keywords and the directions they carry.
const SOCAT_FILES: [(&str, bool, bool); 7] = [
    ("CREAT", false, true),
    ("CREATE", false, true),
    ("FIFO", true, true),
    ("FILE", true, true),
    ("GOPEN", true, true),
    ("OPEN", true, true),
    ("PIPE", true, true),
];

/// The keyword of an address, matched case-insensitively as socat does.
fn socat_keyword<'a>(head: &str, keywords: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    keywords.into_iter().find(|keyword| {
        head.len() > keyword.len()
            && head.as_bytes()[keyword.len()] == b':'
            && head[..keyword.len()].eq_ignore_ascii_case(keyword)
    })
}

/// Resolve socat's address lexer: `\` escapes, `"` and `'` quote, and the
/// first unquoted comma starts the address options. Returns the value and
/// its options.
fn socat_fields(text: &str) -> Option<(String, Vec<String>)> {
    let mut fields = socat_lex_fields(text, ',', false)?;
    let value = fields.remove(0);
    Some((value, fields))
}

/// `colons` admits unquoted colons, which separate address parameters but
/// are ordinary characters in an option value (`cipher=HIGH:!aNULL`).
fn socat_lex_fields(text: &str, separator: char, colons: bool) -> Option<Vec<String>> {
    let mut fields = vec![String::new()];
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                started = true;
                fields.last_mut()?.push(match characters.next()? {
                    '0' => return None,
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'f' => '\x0c',
                    'v' => '\x0b',
                    'a' => '\x07',
                    'b' => '\x08',
                    escaped => escaped,
                });
            }
            '"' | '\'' if quote.is_none() => {
                quote = Some(character);
                started = true;
            }
            _ if Some(character) == quote => quote = None,
            // An option value carries a bracketed IPv6 address literally
            // (`bind=[::1]:4444`); elsewhere brackets open nested address
            // syntax this lexer does not model.
            '[' | ']' if quote.is_none() && colons => {
                fields.last_mut()?.push(character);
                started = true;
            }
            // Nested address syntax needs socat's recursive lexer. Bound it.
            '(' | '[' | '{' if quote.is_none() => return None,
            ':' if quote.is_none() && separator == ',' && !colons => return None,
            _ if character == separator && quote.is_none() => {
                if separator != ' ' || started {
                    fields.push(String::new());
                    started = false;
                }
            }
            _ => {
                fields.last_mut()?.push(character);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if separator == ' ' && !started {
        fields.pop();
    }
    Some(fields)
}

/// Split a socket address value into its host parts and trailing port.
fn socat_endpoint_parts(value: &Word) -> Option<(Vec<WordPart>, String)> {
    let (last, head) = value.parts.split_last()?;
    let WordPart::Literal(tail) = last else {
        return None;
    };
    let (before, port) = tail.rsplit_once(':')?;
    let mut host = head.to_vec();
    if !before.is_empty() {
        host.push(WordPart::Literal(before.to_string()));
    }
    (!port.is_empty()).then(|| (host, port.to_string()))
}

fn socat_endpoint(value: &Word, protocol: &str, listen: bool) -> Option<ResourceExpr> {
    if listen {
        return Some(unresolved_resource("network"));
    }
    let (host, port) = socat_endpoint_parts(value)?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    // A host the shell expanded to nothing names no endpoint this model can
    // state; socat still connects, to whatever its resolver gives it.
    if host.is_empty() {
        return Some(unresolved_resource("network"));
    }
    let host = Word::new(host);
    match host.as_literal() {
        Some(host) if !host.contains([':', '[', ']']) => Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: host.into(),
                scheme: Some(protocol.into()),
                port: Some(port),
                path: None,
            },
        }),
        Some(_) => None,
        None => Some(ResourceExpr::Join {
            parts: vec![
                crate::models::common::remote_endpoint(host.parts.clone(), protocol),
                ResourceExpr::Literal {
                    value: format!(":{port}"),
                },
            ],
        }),
    }
}

/// Parse one socat address operand.
fn socat_address(word: &Word, ctx: &InvocationCtx) -> Result<SocatAddress, &'static str> {
    if let Some(text) = word.as_literal()
        && let Some((read, write)) = text.split_once("!!")
    {
        if text.contains(['\\', '\'', '"']) {
            return Err("socat quoted dual-address delimiters are unmodeled");
        }
        return Ok(SocatAddress {
            read: socat_end(&Word::literal(read), ctx)?,
            write: socat_end(&Word::literal(write), ctx)?,
            dual: true,
        });
    }
    let end = socat_end(word, ctx)?;
    Ok(SocatAddress {
        read: end.clone(),
        write: end,
        dual: false,
    })
}

/// socat's lexer resolves `\` escapes before it matches the address keyword,
/// so `T\CP-LISTEN:4444` names `TCP-LISTEN`. Unescape a keyword whose escapes
/// only hide name characters; the value after the colon is left as written.
fn socat_unescaped_keyword(word: &Word) -> Option<Word> {
    let text = word.as_literal()?;
    let end = text.find([':', ',']).unwrap_or(text.len());
    let head = &text[..end];
    if !head.contains('\\') {
        return None;
    }
    let mut keyword = String::new();
    let mut characters = head.chars();
    while let Some(character) = characters.next() {
        let character = match character {
            '\\' => characters.next()?,
            other => other,
        };
        if !(character.is_ascii_alphanumeric() || character == '-') {
            return None;
        }
        keyword.push(character);
    }
    Some(Word::literal(format!("{keyword}{}", &text[end..])))
}

/// Address keywords whose value is a command socat runs on the connection.
const SOCAT_HANDLERS: [&str; 3] = ["EXEC", "SYSTEM", "SHELL"];

fn socat_end(word: &Word, ctx: &InvocationCtx) -> Result<SocatEnd, &'static str> {
    // A bracket that matched no file (`bind=[::1]`) reaches socat as its
    // literal text; the shell only expands a glob that hit a name. Recover the
    // address from a word whose only non-literal parts are such unexpanded
    // globs, so an IPv6 bind value is read like any other option value.
    if word.as_literal().is_none()
        && word
            .parts
            .iter()
            .any(|part| matches!(part, WordPart::Glob(_)))
        && word
            .parts
            .iter()
            .all(|part| matches!(part, WordPart::Literal(_) | WordPart::Glob(_)))
    {
        return socat_end(&Word::literal(word.render_raw()), ctx);
    }
    if let Some(unescaped) = socat_unescaped_keyword(word) {
        return socat_end(&unescaped, ctx);
    }
    let head = word.literal_prefix();
    if word.as_literal() == Some("SHELL") {
        return Ok(SocatEnd::Handler {
            shell: false,
            command: "sh".into(),
            stderr: false,
            chdir: None,
        });
    }
    // `SHELL[:command]` runs the address through the user's login shell, or
    // opens an interactive shell when no command follows. `shell=` selects the
    // shell binary; any other address option is unmodeled.
    if head
        .strip_prefix("SHELL")
        .is_some_and(|rest| rest.starts_with(','))
    {
        let text = word.as_literal().ok_or("socat SHELL command is symbolic")?;
        let (_, options) =
            socat_fields(&text["SHELL".len()..]).ok_or("socat SHELL quoting is unmodeled")?;
        for option in &options {
            if !option.starts_with("shell=") {
                return Err("socat SHELL address options are unmodeled");
            }
        }
        return Ok(SocatEnd::Handler {
            shell: true,
            command: "sh".into(),
            stderr: false,
            chdir: None,
        });
    }
    if let Some(keyword) = socat_keyword(head, SOCAT_HANDLERS.into_iter()) {
        let Some(text) = word.as_literal() else {
            return Err("socat handler command is symbolic");
        };
        let raw = &text[keyword.len() + 1..];
        let (command, options) =
            socat_fields(raw).ok_or("socat handler quoting is not recoverable")?;
        if command.is_empty() {
            return Err("socat handler address options are unmodeled");
        }
        // Option names are case-insensitive booleans: bare means on, and a
        // value is an integer read like strtoul's base 0. `pty` and `pipes`
        // only change the transport, which still joins the connection to the
        // handler's stdin and stdout. `fdin`/`fdout` would move the
        // connection to other descriptors and stay unmodeled.
        let mut stderr = false;
        let mut chdir = None;
        for option in &options {
            let (name, value) = option
                .split_once('=')
                .map_or((option.as_str(), None), |(name, value)| (name, Some(value)));
            // The handler's child changes into `chdir` before it runs.
            if name.eq_ignore_ascii_case("chdir") {
                chdir = Some(
                    value
                        .filter(|value| !value.is_empty())
                        .ok_or("socat handler address options are unmodeled")?
                        .to_string(),
                );
                continue;
            }
            let enabled = match value {
                None => true,
                Some(value) => {
                    socat_fd_number(value).ok_or("socat handler address options are unmodeled")?
                        != 0
                }
            };
            if name.eq_ignore_ascii_case("stderr") {
                stderr = enabled;
            } else if !["pty", "pipes"]
                .iter()
                .any(|transport| name.eq_ignore_ascii_case(transport))
            {
                return Err("socat handler address options are unmodeled");
            }
        }
        return Ok(SocatEnd::Handler {
            shell: !keyword.eq_ignore_ascii_case("EXEC"),
            command,
            stderr,
            chdir,
        });
    }
    if let Some(keyword) = socat_keyword(head, ["PROXY"].into_iter()) {
        let text = word.as_literal().ok_or("socat proxy address is symbolic")?;
        let (proxy, target) = text[keyword.len() + 1..]
            .split_once(':')
            .ok_or("socat proxy target is missing")?;
        if proxy.is_empty() || text.contains([',', '\\', '\'', '"', '[', ']']) {
            return Err("socat proxy address options or quoting are unmodeled");
        }
        let resource = socat_endpoint(&Word::literal(target), "tcp", false)
            .ok_or("socat proxy target is unmodeled")?;
        return Ok(SocatEnd::Socket {
            resource,
            protocol: "tcp",
            listen: false,
            address: text.to_string(),
            proxy: Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: proxy.to_string(),
                    scheme: Some("tcp".into()),
                    port: Some(8080),
                    path: None,
                },
            }),
        });
    }
    // TLS addresses are socket addresses whose options also configure the
    // handshake; the connection's bytes flow as they do over TCP or UDP.
    let socket = socat_keyword(head, SOCAT_SOCKETS.iter().map(|(name, _, _)| *name))
        .map(|keyword| (keyword, &SOCAT_SOCKETS[..], false))
        .or_else(|| {
            socat_keyword(head, SOCAT_TLS_SOCKETS.iter().map(|(name, _, _)| *name))
                .map(|keyword| (keyword, &SOCAT_TLS_SOCKETS[..], true))
        });
    if let Some((keyword, table, tls)) = socket {
        let (protocol, listen) = table
            .iter()
            .find(|(name, _, _)| *name == keyword)
            .map(|(_, protocol, listen)| (*protocol, *listen))
            .expect("keyword comes from the table");
        let value = super::args::strip_literal_prefix(word, keyword.len() + 1);
        let value = match value.as_literal() {
            Some(text) => {
                // The endpoint keeps its `host:port` colon, so only the
                // options after the first comma go through the lexer.
                let (value, options) = match text.split_once(',') {
                    Some((value, options)) => (
                        value,
                        socat_lex_fields(options, ',', true)
                            .ok_or("socat peer address quoting is unmodeled")?,
                    ),
                    None => (text, Vec::new()),
                };
                if value.contains(['\\', '\'', '"']) || value.contains("!!") {
                    return Err("socat peer address quoting is unmodeled");
                }
                for option in &options {
                    // socat skips empty separators, so a trailing or doubled
                    // comma leaves no option to model.
                    if option.is_empty() {
                        continue;
                    }
                    let name = option.split_once('=').map_or(option.as_str(), |(name, _)| name);
                    let known = |options: &[&str], name: &str| {
                        options.iter().any(|known| known.eq_ignore_ascii_case(name))
                    };
                    let tls_name = name
                        .get(..8)
                        .filter(|prefix| prefix.eq_ignore_ascii_case("openssl-"))
                        .map_or(name, |_| &name[8..]);
                    if !(known(&SOCAT_SOCKET_OPTIONS, name)
                        || tls && known(&SOCAT_TLS_OPTIONS, tls_name))
                    {
                        return Err("socat peer address options are unmodeled");
                    }
                }
                Word::literal(value)
            }
            None if value.parts.iter().any(|part| {
                matches!(part, WordPart::Literal(text) if text.contains([',', '\\', '\'', '"']))
            }) =>
            {
                return Err("socat peer address options or quoting are unmodeled");
            }
            None => value,
        };
        let resource =
            socat_endpoint(&value, protocol, listen).ok_or("socat peer address is unmodeled")?;
        return Ok(SocatEnd::Socket {
            resource,
            protocol,
            listen,
            address: value.as_literal().unwrap_or_default().to_string(),
            proxy: None,
        });
    }
    // `FD:<n>` names a descriptor, and a bare number does the same. The three
    // standard descriptors are socat's own stdin, stdout, and stderr, so a
    // pipe on one connects there; any higher descriptor was opened by the
    // shell, and where it leads is the shell's to say.
    if socat_keyword(head, ["FD"].into_iter()).is_some()
        || (word
            .as_literal()
            .is_some_and(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())))
    {
        if let Some(descriptor) = socat_std_descriptor(word) {
            return Ok(SocatEnd::Stdio {
                reads: Some(descriptor),
                writes: Some(descriptor),
            });
        }
        let path = socat_descriptor_path(word).ok_or("socat descriptor number is unmodeled")?;
        let resource = crate::paths::resolve_fs_word_with_cwd(&path, ctx.cwd_resource());
        return Ok(SocatEnd::File {
            word: path,
            resource,
            readable: true,
            writable: true,
            creates_fifo: false,
        });
    }
    let (keyword, readable, writable) =
        match socat_keyword(head, SOCAT_FILES.iter().map(|(name, _, _)| *name)) {
            Some(keyword) => SOCAT_FILES
                .iter()
                .find(|(name, _, _)| *name == keyword)
                .map(|(name, readable, writable)| (Some(*name), *readable, *writable))
                .expect("keyword comes from the table"),
            None if head == "-" && word.as_literal() == Some("-") => {
                return Ok(SocatEnd::Stdio {
                    reads: Some(0),
                    writes: Some(1),
                });
            }
            None if ["STDIO", "STDIN", "STDOUT"]
                .iter()
                .any(|name| word.as_literal().is_some_and(|text| text == *name)) =>
            {
                return Ok(SocatEnd::Stdio {
                    reads: (word.as_literal() != Some("STDOUT")).then_some(0),
                    writes: (word.as_literal() != Some("STDIN")).then_some(1),
                });
            }
            // Without a keyword socat opens a file name; a bare word is one of
            // socat's own no-value addresses, which this model does not carry.
            None if !head.contains(':')
                && word
                    .parts
                    .iter()
                    .any(|part| matches!(part, WordPart::Literal(text) if text.contains('/'))) =>
            {
                (None, true, true)
            }
            None => return Err("socat address family is unmodeled"),
        };
    let value = match keyword {
        Some(keyword) => super::args::strip_literal_prefix(word, keyword.len() + 1),
        None => word.clone(),
    };
    let mut path = value.clone();
    if let Some(text) = value.as_literal() {
        let (value, options) = socat_fields(text).ok_or("socat address quoting is unmodeled")?;
        let mut directory = None;
        for option in &options {
            match option.split_once('=') {
                Some((name, value)) if name.eq_ignore_ascii_case("chdir") => {
                    directory = Some(value.to_string());
                }
                _ => return Err("socat address options are unmodeled"),
            }
        }
        path = match directory {
            // socat changes directory before opening, so a relative name
            // resolves under it.
            Some(directory) if !value.starts_with('/') => {
                Word::literal(format!("{directory}/{value}"))
            }
            _ => Word::literal(value),
        };
    } else if value.parts.iter().any(
        |part| matches!(part, WordPart::Literal(text) if text.contains([',', '\\', '\'', '"'])),
    ) {
        return Err("socat address options are unmodeled");
    }
    if path.parts.is_empty() {
        return Err("socat address names no file");
    }
    let resource = crate::paths::resolve_fs_word_with_cwd(&path, ctx.cwd_resource());
    Ok(SocatEnd::File {
        word: path,
        resource,
        readable,
        writable,
        creates_fifo: matches!(keyword, Some("PIPE" | "FIFO")),
    })
}

/// Where bytes enter or leave socat at one address end.
#[derive(Clone)]
enum SocatSlot {
    Effect(u32),
    Port(effinterp_proto::Port),
}

#[derive(Default)]
struct SocatEnds {
    source: Option<SocatSlot>,
    sink: Option<SocatSlot>,
    attachment: Option<u32>,
}

/// Emit the effects one address end carries in the directions it is used.
fn socat_end_effects(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    end: &SocatEnd,
    source: bool,
    sink: bool,
) -> SocatEnds {
    let mut ends = SocatEnds::default();
    if !source && !sink {
        return ends;
    }
    match end {
        SocatEnd::File {
            word,
            resource,
            readable,
            writable,
            creates_fifo,
        } => {
            // The pipe is the same request `mkfifo` makes, so a later writer
            // of the name feeds this reader. An entry the host already shows
            // there is opened as it is.
            let present = matches!(
                resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } if path.starts_with('/')
                    && matches!(
                        builder.budget().observe_path(path),
                        effinterp_proto::ObservationOutcome::Path(fact)
                            if fact.kind != effinterp_proto::PathKind::Missing
                    )
            );
            if *creates_fifo && !present {
                let arg = fs_arg_node(builder, ctx, index, word);
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Exact,
                    id: Default::default(),
                    operation: Operation::new("filesystem.create"),
                    resource: resource.clone(),
                    attributes: Attrs::from([("fifo".into(), AttrValue::Bool(true))]),
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: Default::default(),
                    provenance: vec![arg, model_node],
                });
            }
            if source && *readable {
                ends.source = fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    word,
                    "filesystem.read",
                    resource.clone(),
                    program_input_attrs(),
                )
                .map(SocatSlot::Effect);
            }
            if sink && *writable {
                ends.sink = fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    word,
                    "filesystem.write",
                    resource.clone(),
                    program_output_attrs(),
                )
                .map(SocatSlot::Effect);
            }
        }
        SocatEnd::Socket {
            resource,
            protocol,
            listen,
            address,
            proxy,
        } => {
            let attributes = BTreeMap::from([
                ("protocol".into(), AttrValue::String((*protocol).into())),
                ("listen".into(), AttrValue::Bool(*listen)),
                ("address".into(), AttrValue::String(address.clone())),
            ]);
            let attachment = arg_effect(
                builder,
                ctx,
                model_node,
                index,
                if *listen {
                    "network.listen"
                } else {
                    "network.connect"
                },
                proxy.clone().unwrap_or_else(|| resource.clone()),
                attributes.clone(),
            );
            if !*listen {
                ends.attachment = attachment;
            }
            // A listener's bind address does not identify its future peer.
            let peer = if *listen {
                unresolved_resource("network")
            } else {
                resource.clone()
            };
            if source {
                ends.source = arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "network.download",
                    peer.clone(),
                    attributes.clone(),
                )
                .map(SocatSlot::Effect);
            }
            if sink {
                ends.sink = arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "network.upload",
                    peer,
                    attributes,
                )
                .map(SocatSlot::Effect);
            }
        }
        SocatEnd::Stdio { reads, writes } => {
            // Standard input is read and standard output and error are written
            // through socat's own streams. Any other direction goes wherever
            // the shell pointed the descriptor (`2<&0`), so the shell binds
            // that access to it.
            let descriptor_access = |builder: &mut PlanBuilder, descriptor: u32, operation| {
                let word = Word::literal(format!("/dev/fd/{descriptor}"));
                let resource = crate::paths::resolve_fs_word_with_cwd(&word, ctx.cwd_resource());
                let attributes = if operation == "filesystem.read" {
                    program_input_attrs()
                } else {
                    program_output_attrs()
                };
                fs_arg_effect(
                    builder, ctx, model_node, index, &word, operation, resource, attributes,
                )
                .map(SocatSlot::Effect)
            };
            if source {
                ends.source = match reads {
                    Some(0) => Some(SocatSlot::Port(effinterp_proto::Port::Stdin)),
                    Some(descriptor) => descriptor_access(builder, *descriptor, "filesystem.read"),
                    None => None,
                };
            }
            if sink {
                ends.sink = match writes {
                    Some(1) => Some(SocatSlot::Port(effinterp_proto::Port::Stdout)),
                    Some(2) => Some(SocatSlot::Port(effinterp_proto::Port::Stderr)),
                    Some(descriptor) => descriptor_access(builder, *descriptor, "filesystem.write"),
                    None => None,
                };
            }
        }
        SocatEnd::Handler { .. } => {}
    }
    ends
}

impl CommandModel for Socat {
    fn id(&self) -> &'static str {
        "network/socat@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["socat"]
    }
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn descriptor_operands(&self, argv: &[Word]) -> Vec<(u32, Word)> {
        argv.iter()
            .enumerate()
            .flat_map(|(index, word)| {
                socat_address_ends(word)
                    .into_iter()
                    .filter_map(move |end| Some((index as u32, socat_descriptor_path(&end)?)))
            })
            .collect()
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let parsed = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                value_flags: &[],
                known_flags: &["-u", "-U", "-d", "-h", "-V"],
                allow_abbreviation: false,
            },
            true,
        );
        if parsed.has(&["-h", "-V"]) {
            return;
        }
        if !parsed.unknown_flags.is_empty()
            || parsed
                .flags
                .iter()
                .any(|flag| ctx.argv[flag.index as usize].literal_prefix().contains('='))
            || parsed.has(&["-u"]) && parsed.has(&["-U"])
            || parsed.operands.len() != 2
        {
            socket_handler_boundary(
                builder,
                &[model_node],
                "socat options or address count are unmodeled",
            );
            return;
        }
        let mut addresses = Vec::new();
        for (index, word) in &parsed.operands {
            match socat_address(word, ctx) {
                Ok(address) => addresses.push((*index, address)),
                Err(detail) => {
                    let argument = arg_node(builder, ctx, *index);
                    if word.as_literal().is_none()
                        && socat_keyword(word.literal_prefix(), SOCAT_HANDLERS.into_iter())
                            .is_some()
                    {
                        code_execution(
                            effinterp_proto::RequestAssurance::Conservative,
                            builder,
                            ctx,
                            model_node,
                            Some(*index),
                            "argument",
                            Default::default(),
                        );
                        opaque_source_with_provenance(
                            builder,
                            &[model_node, argument],
                            &["environment", "filesystem", "network", "process"],
                            detail,
                        );
                    } else {
                        socket_handler_boundary(builder, &[model_node, argument], detail);
                    }
                    return;
                }
            }
        }
        // `-u` keeps only address 1 -> address 2, `-U` only the reverse.
        let unidirectional = parsed.has(&["-u"]);
        let reversed = parsed.has(&["-U"]);
        let feeds = [!reversed, !unidirectional];
        let drains = [!unidirectional, !reversed];

        let handlers = addresses
            .iter()
            .enumerate()
            .filter(|(_, (_, address))| {
                matches!(address.read, SocatEnd::Handler { .. })
                    || matches!(address.write, SocatEnd::Handler { .. })
            })
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        if handlers.len() > 1 {
            socket_handler_boundary(
                builder,
                &[model_node],
                "socat relays between two handlers are unmodeled",
            );
            return;
        }

        let mut ends: Vec<SocatEnds> = Vec::new();
        for (position, (index, address)) in addresses.iter().enumerate() {
            if address.dual {
                let mut read = socat_end_effects(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &address.read,
                    feeds[position],
                    false,
                );
                let write = socat_end_effects(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &address.write,
                    false,
                    drains[position],
                );
                read.sink = write.sink;
                ends.push(read);
            } else {
                ends.push(socat_end_effects(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &address.read,
                    feeds[position],
                    drains[position],
                ));
            }
        }

        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);

        // A handler keeps both of its descriptors under `-u` and `-U`; the
        // flags only stop socat relaying one direction, so the unused one
        // carries no bytes and the ports below stay bound in the direction
        // the flags kept.
        if let [position] = handlers[..] {
            let (index, address) = &addresses[position];
            let SocatEnd::Handler {
                shell,
                command,
                stderr,
                chdir,
            } = &address.read
            else {
                return;
            };
            let cwd = match (chdir, ctx.cwd) {
                (Some(dir), Some(cwd)) => Some(crate::paths::join_cwd(cwd, dir)),
                (Some(dir), None) if dir.starts_with('/') => Some(dir.clone()),
                (Some(_), None) => None,
                (None, cwd) => cwd.map(str::to_string),
            };
            // The handler's script source resolves under the same chdir; an
            // unknown base stays unknown rather than finding the parent's file.
            let runtime_cwd = match (chdir, ctx.runtime_cwd) {
                (Some(dir), Some(base)) => Some(crate::paths::join_cwd(base, dir)),
                (Some(dir), None) if dir.starts_with('/') => Some(dir.clone()),
                (Some(_), None) => None,
                (None, base) => base.map(str::to_string),
            };
            let other = 1 - position;
            let argument = arg_node(builder, ctx, *index);
            // A `SYSTEM`/`SHELL` command that is a lone shell binary launches an
            // interactive shell on the connection, so model it through the shell
            // program directly (as `EXEC` does) rather than as a script whose
            // only line names that binary.
            let lone_shell = socat_exec_argv(command)
                .is_some_and(|argv| argv.len() == 1 && is_shell_program(&argv[0]));
            // A shell handler whose program the handler's own shell computes
            // (`SYSTEM:'$CMD'`) runs code this analysis cannot read, attached
            // to the connection like any shell socat starts.
            let dynamic = *shell
                && socat_exec_argv(command)
                    .and_then(|argv| argv.into_iter().next())
                    .is_some_and(|program| program.contains(['$', '`']));
            let subject = if dynamic {
                effinterp_proto::Subject::Exec {
                    argv: vec!["sh".into()],
                    cwd: cwd.clone(),
                    context: Default::default(),
                }
            } else if *shell && !lone_shell {
                effinterp_proto::Subject::Shell {
                    source: command.clone(),
                    cwd: cwd.clone(),
                    context: Default::default(),
                }
            } else {
                let Some(argv) = socat_exec_argv(command) else {
                    socket_handler_boundary(
                        builder,
                        &[model_node, argument],
                        "socat EXEC command quoting is not recoverable",
                    );
                    return;
                };
                if argv.is_empty() {
                    return;
                }
                effinterp_proto::Subject::Exec {
                    argv,
                    cwd: cwd.clone(),
                    context: Default::default(),
                }
            };
            // A `SYSTEM`/`SHELL` handler always runs `sh -c`, and an `EXEC`
            // handler that runs a shell binary attaches one too: in both the
            // connection's own bytes are the shell's input.
            let attached_shell = *shell
                || matches!(
                    &subject,
                    effinterp_proto::Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|program| is_shell_program(program))
                );
            // Under `-u`/`-U` the connection may only receive the handler's
            // output; then its bytes never reach the shell's input.
            let input = (attached_shell && feeds[other])
                .then_some(ends[other].attachment)
                .flatten()
                .or_else(|| match &ends[other].source {
                    Some(SocatSlot::Effect(effect)) => Some(*effect),
                    _ => None,
                });
            let output = match &ends[other].sink {
                Some(SocatSlot::Effect(effect)) => Some(*effect),
                _ => None,
            };
            connected_handler(
                builder,
                ctx,
                &[model_node, argument],
                subject,
                input,
                output,
                BTreeMap::new(),
                *stderr,
                runtime_cwd.as_deref(),
            );
            if dynamic {
                code_execution(
                    effinterp_proto::RequestAssurance::Exact,
                    builder,
                    ctx,
                    model_node,
                    Some(*index),
                    "argument",
                    [(
                        "derivation".to_string(),
                        AttrValue::String("unresolved_command".into()),
                    )]
                    .into_iter()
                    .collect(),
                );
            }
            return;
        }

        // Without a handler socat relays bytes between the two addresses.
        let mut bindings = Vec::new();
        let mut effects = Vec::new();
        for (from, to) in [(0usize, 1usize), (1, 0)] {
            let (Some(source), Some(sink)) = (ends[from].source.clone(), ends[to].sink.clone())
            else {
                continue;
            };
            bindings.push(crate::flow::PortBinding {
                assurance: if builder.execution_is_exact(builder.current_execution())
                    && ctx.argv.iter().all(|word| word.as_literal().is_some())
                {
                    effinterp_proto::CausalAssurance::Exact
                } else {
                    effinterp_proto::CausalAssurance::Conservative
                },
                from: socat_bind_end(&source),
                to: socat_bind_end(&sink),
            });
            for slot in [&source, &sink] {
                if let SocatSlot::Effect(effect) = slot {
                    effects.push(*effect);
                }
            }
        }
        if bindings.is_empty() {
            return;
        }
        effects.sort_unstable();
        effects.dedup();
        builder.flow_stage(crate::flow::FlowStage {
            execution: Some(builder.current_execution()),
            effects,
            bindings,
            provenance: vec![model_node],
        });
    }
}

fn socat_bind_end(slot: &SocatSlot) -> crate::flow::BindEnd {
    match slot {
        SocatSlot::Effect(effect) => crate::flow::BindEnd::Effect(*effect),
        SocatSlot::Port(port) => crate::flow::BindEnd::Port(port.clone()),
    }
}

/// The ordinary `/dev/fd/N` name for an `FD:<fdnum>` or bare-number address,
/// which names a descriptor the caller already opened. socat converts the
/// number with strtoul base 0 and refuses trailing text, so `0x3`, `03` and
/// `3` all name descriptor 3. Where the descriptor leads is the shell's to say.
fn socat_descriptor_path(word: &Word) -> Option<Word> {
    let value = match socat_keyword(word.literal_prefix(), ["FD"].into_iter()) {
        Some(keyword) => super::args::strip_literal_prefix(word, keyword.len() + 1),
        None if word.as_literal().is_some_and(|text| {
            !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
        }) =>
        {
            word.clone()
        }
        None => return None,
    };
    let mut parts = vec![WordPart::Literal("/dev/fd/".to_string())];
    match value.as_literal() {
        Some(text) => {
            parts.push(WordPart::Literal(socat_fd_number(text)?.to_string()));
        }
        None => parts.extend(value.parts.iter().cloned()),
    }
    Some(Word::new(parts))
}

/// socat converts a descriptor number with strtoul base 0, so `0x3`, `03` and
/// `3` all name descriptor 3.
fn socat_fd_number(text: &str) -> Option<u32> {
    let (digits, radix) = match text.as_bytes() {
        [b'0', b'x' | b'X', ..] => (&text[2..], 16),
        [b'0', ..] if text.len() > 1 => (&text[1..], 8),
        _ => (text, 10),
    };
    u32::from_str_radix(digits, radix).ok()
}

/// The descriptor number an `FD:<n>` or bare-number address names, when it is
/// one of the three standard descriptors.
fn socat_std_descriptor(word: &Word) -> Option<u32> {
    let text = word.as_literal()?;
    let number = match socat_keyword(text, ["FD"].into_iter()) {
        Some(keyword) => socat_fd_number(&text[keyword.len() + 1..])?,
        None => socat_fd_number(text)?,
    };
    (number <= 2).then_some(number)
}

/// The address ends one operand carries: `read!!write` names two, and every
/// other address names one.
fn socat_address_ends(word: &Word) -> Vec<Word> {
    match word.as_literal().and_then(|text| text.split_once("!!")) {
        Some((read, write)) => vec![Word::literal(read), Word::literal(write)],
        None => vec![word.clone()],
    }
}

/// The second socat lexical pass splits EXEC argv on spaces and removes
/// another layer of quoting/escapes. It does not interpret shell operators.
fn socat_exec_argv(command: &str) -> Option<Vec<String>> {
    socat_lex_fields(command, ' ', false)
}

/// httpie and its xh port send the files their request items name. The
/// promoted `http` document models the URL, stdin body and response; this
/// wrapper adds the file reads each upload carries.
pub(super) fn with_request_item_files(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(RequestItemFiles { owner })
}

struct RequestItemFiles {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for RequestItemFiles {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let start = builder.effects_len();
        // The document's one positional is the URL, so it reads a METHOD word
        // as the URL; it is given the argv without that word. A symbolic word
        // before it might be the URL, so it is then left as it is.
        match httpie_operands(ctx.argv) {
            (operands, true)
                if ctx.argv[1..operands[0].0]
                    .iter()
                    .all(|word| word.as_literal().is_some()) =>
            {
                let method = operands[0].0;
                let argv = ctx
                    .argv
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != method)
                    .map(|(_, word)| word.clone())
                    .collect::<Vec<_>>();
                let provenance = (0..ctx.argv.len())
                    .filter(|index| *index != method)
                    .map(|index| ctx.argv_provenance_at(builder, index))
                    .collect::<Vec<_>>();
                let ctx = InvocationCtx {
                    argv: &argv,
                    stdin: ctx.stdin,
                    argv_provenance: Some(&provenance),
                    cwd: ctx.cwd,
                    cwd_resource: ctx.cwd_resource.clone(),
                    runtime_cwd: ctx.runtime_cwd,
                    scope: ctx.scope,
                    cwd_node: ctx.cwd_node,
                    nest: ctx.nest,
                    depth: ctx.depth,
                    model_stack: ctx.model_stack.clone(),
                };
                self.owner.apply(builder, &ctx, model_node);
            }
            _ => self.owner.apply(builder, ctx, model_node),
        }
        let uploads = (start..builder.effects_len())
            .filter(|&index| builder.effect_operation(index) == Some("network.upload"))
            .collect::<Vec<_>>();
        if uploads.is_empty() {
            return;
        }
        for (index, path) in request_item_files(ctx.argv) {
            let Some(read) = crate::models::common::content_read_effect(
                builder,
                ctx,
                model_node,
                index as u32,
                &Word::literal(path),
                program_input_attrs(),
            ) else {
                continue;
            };
            for &upload in &uploads {
                builder.transfer_binding(TransferBinding::new(read, upload as u32));
            }
        }
    }
}

/// httpie and xh options that take the next word as their value.
const HTTPIE_VALUE_FLAGS: &[&str] = &[
    "-a",
    "--auth",
    "-A",
    "--auth-type",
    "-o",
    "--output",
    "-p",
    "--print",
    "-P",
    "--history-print",
    "-s",
    "--style",
    "--session",
    "--session-read-only",
    "--verify",
    "--cert",
    "--cert-key",
    "--cert-key-pass",
    "--ssl",
    "--ciphers",
    "--proxy",
    "--timeout",
    "--max-redirects",
    "--max-headers",
    "--pretty",
    "--format-options",
    "--boundary",
    "--raw",
    "--response-charset",
    "--response-mime",
    "--default-scheme",
    "--unix-socket",
    "--http-version",
    "--resolve",
    "--interface",
    "--bearer",
];

/// The literal operands of an httpie/xh invocation, by argv index, and
/// whether the first is the METHOD. As httpie guesses: a word before the URL
/// is the METHOD, unless the word after it is a request item, which makes
/// that first word the URL. A word with a scheme (`https://…`) or httpie's
/// `:PORT` localhost shorthand is a URL, not a header item.
fn httpie_operands(argv: &[Word]) -> (Vec<(usize, &str)>, bool) {
    let mut operands = Vec::new();
    let mut index = 1;
    while index < argv.len() {
        let Some(word) = argv[index].as_literal() else {
            index += 1;
            continue;
        };
        if word.len() > 1 && word.starts_with('-') && !word.starts_with("-@") {
            index += if HTTPIE_VALUE_FLAGS.contains(&word) {
                2
            } else {
                1
            };
            continue;
        }
        operands.push((index, word));
        index += 1;
    }
    let method = operands.len() > 1
        && operands[0]
            .1
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        && (request_item_separator(operands[1].1).is_none()
            || operands[1].1.contains("://")
            || operands[1].1.starts_with(':'));
    (operands, method)
}

/// A request item's separator and its position: the first one in the item,
/// the longest at that position.
fn request_item_separator(item: &str) -> Option<(usize, &'static str)> {
    item.char_indices().find_map(|(at, _)| {
        [":=@", "=@", "==", ":=", "@", "=", ":"]
            .into_iter()
            .find(|separator| item[at..].starts_with(separator))
            .map(|separator| (at, separator))
    })
}

/// The files a literal httpie/xh invocation's request items send, by argv
/// index: `field=@file` and `field:=@file` embed a file's contents,
/// `field@file` uploads it as a form file, and a bare `@file` is the body.
/// Items follow the optional METHOD and the URL. Escaped separators are not
/// read.
fn request_item_files(argv: &[Word]) -> Vec<(usize, &str)> {
    let (operands, method) = httpie_operands(argv);
    operands
        .into_iter()
        .skip(if method { 2 } else { 1 })
        .filter(|(_, item)| !item.contains('\\'))
        .filter_map(|(index, item)| {
            let (at, separator) = request_item_separator(item)?;
            let path = &item[at + separator.len()..];
            let path = match separator {
                ":=@" | "=@" => path,
                // A form file may carry `;type=MIME` after its path.
                "@" => path.split(';').next().unwrap_or(path),
                _ => return None,
            };
            (!path.is_empty()).then_some((index, path))
        })
        .collect()
}

/// sftp reads batch commands from stdin, or from `-b -`, and each `put`
/// uploads a local file over the session the promoted `sftp` document
/// connects. This wrapper adds those uploads when the commands are literal.
pub(super) fn with_batch_uploads(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(SftpBatchUploads { owner })
}

struct SftpBatchUploads {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for SftpBatchUploads {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let start = builder.effects_len();
        self.owner.apply(builder, ctx, model_node);
        let Some(session) = (start..builder.effects_len())
            .find(|&index| builder.effect_operation(index) == Some("network.connect"))
            .and_then(|index| builder.effect_resource(index).cloned())
        else {
            return;
        };
        let destination = sftp_destination(ctx.argv);
        // An IPv6 address in brackets holds colons of its own.
        if let Some((index, path)) = destination.and_then(|(index, word)| {
            let (host, path) = word.as_literal()?.split_once(':')?;
            (!host.contains('[')).then_some((index, path))
        }) {
            let provenance = vec![arg_node(builder, ctx, index as u32), model_node];
            sftp_retrieve(builder, ctx, &provenance, &session, path, None, false);
        }
        // `-b FILE` or `-bFILE`.
        let batch_file = ctx
            .argv
            .iter()
            .enumerate()
            .skip(1)
            .find_map(
                |(index, word)| match word.as_literal()?.strip_prefix("-b")? {
                    "" => Some((index + 1, ctx.argv.get(index + 1).cloned())),
                    attached => Some((index, Some(Word::literal(attached)))),
                },
            );
        match batch_file {
            Some((_, Some(word))) if word.as_literal() == Some("-") => {}
            Some((index, word)) => {
                sftp_unobserved_batch(builder, ctx, model_node, &session, index, word.as_ref());
                return;
            }
            None => {}
        }
        let (Some(commands), Some(stdin)) = (ctx.stdin_literal(), ctx.stdin) else {
            return;
        };
        let mut provenance = vec![model_node];
        provenance.extend(stdin.provenance.iter().copied());
        let unmodeled = |builder: &mut PlanBuilder, domains: &[&str], detail: &str| {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: domains.iter().copied().map(Domain::new).collect(),
                provenance: provenance.clone(),
                limit: None,
                detail: Some(detail.into()),
            });
        };
        for line in commands.lines() {
            // A leading `-` ignores the command's failure and `@` its echo.
            let mut words = line
                .trim()
                .trim_start_matches(['-', '@'])
                .split_whitespace();
            let command = words.next();
            match command {
                Some("put" | "reput" | "get" | "reget") => {}
                // A changed local directory moves every later relative path.
                Some("lcd") => {
                    unmodeled(
                        builder,
                        &["filesystem", "network"],
                        "sftp batch lcd moves the local paths of later commands",
                    );
                    break;
                }
                Some(command) if command.starts_with('!') => {
                    unmodeled(
                        builder,
                        &["filesystem", "network", "process"],
                        "sftp batch runs a local shell command",
                    );
                    continue;
                }
                Some("lmkdir") => {
                    unmodeled(
                        builder,
                        &["filesystem"],
                        "sftp batch command writes local files",
                    );
                    continue;
                }
                _ => continue,
            }
            let mut recursive = false;
            let mut paths = Vec::new();
            for word in words {
                match word.strip_prefix('-') {
                    Some(options) if paths.is_empty() => recursive |= options.contains(['r', 'R']),
                    _ => paths.push(word),
                }
            }
            if paths
                .iter()
                .any(|path| path.contains(['*', '?', '[', '"', '\'', '\\']))
            {
                unmodeled(
                    builder,
                    &["filesystem", "network"],
                    "sftp batch transfer of a pattern or quoted path",
                );
                continue;
            }
            if matches!(command, Some("get" | "reget")) {
                if let Some(remote) = paths.first() {
                    sftp_retrieve(
                        builder,
                        ctx,
                        &provenance,
                        &session,
                        remote,
                        paths.get(1).copied(),
                        recursive,
                    );
                }
                continue;
            }
            let Some(local) = paths.first() else { continue };
            let mut attributes = program_input_attrs();
            if recursive {
                attributes.insert("recursive".into(), AttrValue::Bool(true));
            }
            let read = builder.effect(sftp_effect(
                &provenance,
                "filesystem.read",
                ctx.resolve_fs_word(&Word::literal(*local)),
                attributes,
            ));
            let upload = builder.effect(sftp_effect(
                &provenance,
                "network.upload",
                session.clone(),
                Attrs::new(),
            ));
            if let (Some(read), Some(upload)) = (read, upload) {
                builder.transfer_binding(TransferBinding::new(read, upload));
            }
        }
    }
}

fn sftp_effect(
    provenance: &[ProvenanceRef],
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) -> Effect {
    Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: provenance.to_vec(),
    }
}

/// sftp options that take the next word as their value.
const SFTP_VALUE_FLAGS: &[&str] = &[
    "-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S", "-s", "-X",
];

/// The destination operand of an sftp invocation, by argv index: the first
/// word that is neither an option nor an option's value.
fn sftp_destination(argv: &[Word]) -> Option<(usize, &Word)> {
    let mut index = 1;
    while let Some(word) = argv.get(index) {
        match word.as_literal() {
            Some(flag) if flag.len() > 1 && flag.starts_with('-') => {
                index += if SFTP_VALUE_FLAGS.contains(&flag) {
                    2
                } else {
                    1
                };
            }
            _ => return Some((index, word)),
        }
    }
    None
}

/// sftp retrieves a remote file named by `[user@]host:path`, or by a batch
/// `get REMOTE [LOCAL]`, into LOCAL or, without one, the working directory
/// under the file's own name. A path ending in `/` names a directory, which
/// the destination form opens instead of retrieving; a pattern retrieves
/// entries whose names are unknown.
fn sftp_retrieve(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    session: &ResourceExpr,
    remote: &str,
    local: Option<&str>,
    recursive: bool,
) {
    let name = remote.rsplit('/').next().unwrap_or(remote);
    if remote.contains(['*', '?', '[']) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem"), Domain::new("network")],
            provenance: provenance.to_vec(),
            limit: None,
            detail: Some("sftp retrieval of a remote pattern writes unnamed local files".into()),
        });
        return;
    }
    if matches!(name, "" | "." | ".." | "~") {
        return;
    }
    // A LOCAL that names a directory receives the file under its own name.
    // Only `.`, `..` and a trailing `/` spell one; any other LOCAL may be an
    // existing directory, so both places may be written.
    let locals = match local {
        Some(directory @ ("." | "..")) => vec![format!("{directory}/{name}")],
        Some(directory) if directory.ends_with('/') => vec![format!("{directory}{name}")],
        Some(local) => vec![local.to_string(), format!("{local}/{name}")],
        None => vec![name.to_string()],
    };
    let mut attributes = program_output_attrs();
    if recursive {
        attributes.insert("recursive".into(), AttrValue::Bool(true));
    }
    let Some(download) = builder.effect(sftp_effect(
        provenance,
        "network.download",
        session.clone(),
        Attrs::new(),
    )) else {
        return;
    };
    for local in locals {
        if let Some(write) = builder.effect(sftp_effect(
            provenance,
            "filesystem.write",
            ctx.resolve_fs_word(&Word::literal(local)),
            attributes.clone(),
        )) {
            builder.transfer_binding(TransferBinding::new(download, write));
        }
    }
}

/// `sftp -b FILE` runs the commands in FILE, whose content this analysis
/// does not see: the session may upload any local file and write any local
/// path, so it carries an upload of unknown content and a boundary.
fn sftp_unobserved_batch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    session: &ResourceExpr,
    index: usize,
    word: Option<&Word>,
) {
    if let Some(word) = word {
        fs_arg_effect(
            builder,
            ctx,
            model_node,
            index as u32,
            word,
            "filesystem.read",
            ctx.resolve_fs_word(word),
            program_input_attrs(),
        );
    }
    let provenance = [model_node];
    builder.effect(sftp_effect(
        &provenance,
        "network.upload",
        session.clone(),
        Attrs::new(),
    ));
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("filesystem"),
                Domain::new("network"),
                Domain::new("process"),
            ],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "sftp batch file commands are not observed; what they upload and write is unknown"
                    .into(),
            ),
        },
        CoverageLevel::Partial,
    );
}
