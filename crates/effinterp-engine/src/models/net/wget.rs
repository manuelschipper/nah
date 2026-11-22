use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, Modality, Operation,
    ProvenanceRef, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan, scan_with_value_indices};
use crate::models::common::{
    arg_effect, arg_node, fs_arg_effect, fs_arg_node, fs_full_no_spawn, operand_effect,
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

/// Wget writes downloads to a local file unless the output option selects standard output.
pub(super) struct Wget;

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

/// The wget operands that supply request bytes or select a local destination.
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

/// Classify wget flow operands with the same option grammar as the effect model.
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
    // `--spider` checks that the page exists and downloads nothing, so no
    // body reaches the named output, standard output included. A recursive
    // spider still fetches pages to follow their links.
    let spider =
        scanned.has(&["--spider"]) && !scanned.has(&["-r", "--recursive", "-m", "--mirror"]);
    let stdout_download = !spider
        && output_flags
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
        .and_then(|url| parse_network_endpoint_operand(url).map(|endpoint| (url, endpoint)));
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
                http_transfer_endpoint_expr(url),
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
                record_http_transfer(
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
                record_http_transfer(builder, endpoint, written, transfer_assurance);
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
        declare_full_network_coverage(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "network"],
            &scanned.unknown_flags,
        );
    }
}
