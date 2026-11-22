use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, Modality,
    Operation, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, scan, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, arg_node, fs_arg_effect, fs_full_no_spawn, operand_effect,
    program_input_attrs, program_output_attrs, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

use super::http_transfer::{
    declare_full_network_coverage, http_transfer_endpoint_expr, names_stdout, record_http_transfer,
    url_basename,
};
use super::network_endpoint::parse_network_endpoint_operand;

/// Curl selects each output for one URL, in command-line order.
pub(super) struct Curl;

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

/// The operands and output selectors that can carry bytes through curl.
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

/// Where one curl response is sent. An argument selector holds its argv index.
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
                    parse_network_endpoint_operand(url).is_some()
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
                } = parse_network_endpoint_operand(url)?
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
                    } = parse_network_endpoint_operand(url)?
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
            crate::models::credential::vault_kv_destroy_target(path, delete)
                .map(|target| (target, delete))
        })
        .flatten();
        if let Some((target, delete)) = vault_destroy {
            crate::models::credential::vault_http_destroy(builder, ctx, model_node, target, delete);
        }
        // One PATCH of GitHub's ref route updates a ref. A body read from a
        // file or config, sent as a form, or moved to the query is not read
        // here, so its force stays unknown. A POST to an Elasticsearch delete
        // route takes its body the same way.
        if scanned.unknown_flags.is_empty() && method == Some("DELETE") && urls.len() == 1 {
            crate::models::datastore::elasticsearch_index_delete(builder, ctx, model_node, urls[0]);
        }
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
                crate::models::datastore::elasticsearch_post_delete(
                    builder, ctx, model_node, urls[0], body,
                );
            } else if unread_body || !bodies.is_empty() {
                crate::models::gh_refs::curl_ref_request(builder, ctx, model_node, urls[0], body);
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
                    let resource = http_transfer_endpoint_expr(url);
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
                            record_http_transfer(
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
                record_http_transfer(builder, endpoint, written, transfer_assurance);
            } else if downloading {
                // `-o file`: the response body reaches the file this URL's
                // own output flag names.
                let written = output
                    .and_then(|flag| output_writes.get(&flag.index).copied())
                    .flatten();
                record_http_transfer(builder, endpoint, written, transfer_assurance);
            }
            if uploading {
                // With one upload source and several URLs every URL receives
                // it; otherwise the nth source pairs with the nth URL.
                let source = if upload_reads.len() == 1 {
                    upload_reads[0]
                } else {
                    upload_reads.get(position).copied().flatten()
                };
                record_http_transfer(
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
                record_http_transfer(
                    builder,
                    read,
                    upload,
                    effinterp_proto::CausalAssurance::Conservative,
                );
            }
        }
        fs_full_no_spawn(builder);
        declare_full_network_coverage(builder);
        curl_config_boundary(builder, model_node, &scanned, &["-K", "--config"]);
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
fn curl_config_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    scanned: &Scanned,
    flags: &[&str],
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
            detail: Some(format!("curl options loaded from {shown:?} (arg {index})")),
        });
    }
}
