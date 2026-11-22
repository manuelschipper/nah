mod mongo_shell_script;
mod mongo_shell_statements;

use effinterp_proto::{BoundaryClass, BoundaryReason, CoverageLevel, Domain, ProvenanceRef};

use self::mongo_shell_script::{
    analyze_mongo_shell_script, direct_mongo_shell_command, emit_mongo_shell_command,
};
use super::datastore_effects::datastore_connect_effect;
use super::mongo_address::{mongo_host, parse_mongo_address};
use crate::SourcePurpose;
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{arg_node, boundary};
use crate::models::db::client_file_operand_effect;
use crate::models::{CommandModel, InvocationCtx, source_refusal_detail};
use crate::nest::SourceResolution;
use crate::word::Word;

/// Model `mongo` and `mongosh` invocations. Inline evaluations run before script files.
pub(super) struct MongoShell;

impl CommandModel for MongoShell {
    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "mongo/mongosh@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mongo", "mongosh"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let argv = ctx.argv;
        let mut evals = Vec::new();
        // Script files the shell loads after its --eval scripts.
        let mut files: Vec<(usize, Word)> = Vec::new();
        let mut shell = false;
        let mut nodb = false;
        let mut unknown = Vec::new();
        let mut address: Option<(usize, &Word)> = None;
        let mut host: Option<(usize, &Word)> = None;
        let mut index = 1;
        while index < argv.len() {
            let word = &argv[index];
            let Some(text) = word.as_literal() else {
                if address.is_none() {
                    address = Some((index, word));
                } else {
                    files.push((index, word.clone()));
                }
                index += 1;
                continue;
            };
            let (name, attached) = match text.split_once('=') {
                Some((name, value)) if name.starts_with("--") => (name, Some(value)),
                _ => (text, None),
            };
            match name {
                "-h" | "--help" | "--version" | "--build-info" => return,
                "--eval" | "--host" | "-f" | "--file" => {
                    let (value_index, value) = match attached {
                        Some(_) => (index, None),
                        None => (index + 1, argv.get(index + 1)),
                    };
                    match name {
                        "--eval" => evals.push((value_index, value.cloned(), attached)),
                        "--host" => {
                            if let Some(value) = value {
                                host = Some((value_index, value));
                            }
                        }
                        _ => files.extend(match attached {
                            Some(path) => Some((index, Word::literal(path))),
                            None => value.map(|value| (value_index, value.clone())),
                        }),
                    }
                    index = value_index + 1;
                }
                "--json" => {
                    if attached.is_none()
                        && matches!(
                            argv.get(index + 1).and_then(Word::as_literal),
                            Some("canonical" | "relaxed")
                        )
                    {
                        index += 1;
                    }
                    index += 1;
                }
                "--shell" => {
                    shell = true;
                    index += 1;
                }
                "--nodb" => {
                    nodb = true;
                    index += 1;
                }
                _ if MONGO_VALUE_FLAGS.contains(&name) => {
                    index += if attached.is_some() { 1 } else { 2 };
                }
                _ if MONGO_BOOL_FLAGS.contains(&name) => index += 1,
                _ if text.starts_with('-') && text != "-" => {
                    unknown.push((index as u32, text.to_string()));
                    index += 1;
                }
                _ if text.ends_with(".js") => {
                    files.push((index, word.clone()));
                    index += 1;
                }
                _ => {
                    if address.is_none() {
                        address = Some((index, word));
                    } else {
                        files.push((index, word.clone()));
                    }
                    index += 1;
                }
            }
        }

        // The target: server and database the shell's `db` starts bound to.
        let mut target = MongoTarget::default();
        let mut scope_indices = Vec::new();
        if let Some((index, word)) = address {
            scope_indices.push(index);
            // mongosh connects to `test` when the address names no database.
            match word.as_literal().map(parse_mongo_address) {
                Some((server, database)) => {
                    target.server = server;
                    target.database = Some(database.unwrap_or_else(|| "test".into()));
                }
                None => target.database = None,
            }
        } else {
            target.database = Some("test".into());
        }
        if let Some((index, word)) = host {
            scope_indices.push(index);
            target.server = word.as_literal().and_then(mongo_host);
        }
        // Unknown options may consume the operand read as the address, and
        // --nodb leaves `db` unbound until the script connects.
        target.known = unknown.is_empty() && !nodb;
        crate::models::common::unrecognized_arguments_boundary(
            builder,
            model_node,
            &["database", "network"],
            &unknown,
        );
        if let Some(server) = &target.server {
            let mut provenance = vec![model_node];
            for index in &scope_indices {
                provenance.push(arg_node(builder, ctx, *index as u32));
            }
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
            datastore_connect_effect(builder, provenance, server, "mongodb");
        }

        let mut scripts = Vec::new();
        for (value_index, value, attached) in evals {
            let source = match (attached, &value) {
                (Some(text), _) => Some(text.to_string()),
                (None, Some(word)) => word.as_literal().map(str::to_string),
                (None, None) => None,
            };
            match source {
                Some(source) => {
                    let arg = arg_node(builder, ctx, value_index as u32);
                    scripts.push((source, vec![arg, model_node], true));
                }
                None => mongo_opaque(builder, model_node, "mongo shell --eval is not literal"),
            }
        }
        let has_files = !files.is_empty();
        for (index, file) in files {
            let read = client_file_operand_effect(
                builder,
                ctx,
                model_node,
                index as u32,
                &file,
                "filesystem.read",
            );
            let Some(path) = file.as_literal() else {
                mongo_opaque(
                    builder,
                    model_node,
                    "mongo shell script file is not literal",
                );
                continue;
            };
            if let Some(source) = mongo_script_file(builder, ctx, model_node, path) {
                // This read stands in for the selection's own program-input
                // read, which the builder skips once the resource is read.
                if let Some(read) = read {
                    builder.set_effect_string_attribute(
                        read as usize,
                        "access_purpose",
                        "program_input",
                    );
                }
                let arg = arg_node(builder, ctx, index as u32);
                scripts.push((source, vec![arg, model_node], false));
            }
        }
        if scripts.is_empty() && !has_files {
            // `< FILE` runs the file as piped input; the shell's redirection
            // already records reading it.
            if let Some(stdin) = ctx.stdin
                && let Some(file) = &stdin.file
            {
                let mut provenance = vec![model_node];
                provenance.extend(stdin.provenance.iter().copied());
                match file.as_literal() {
                    Some(path) => {
                        if let Some(source) = mongo_script_file(builder, ctx, model_node, path) {
                            scripts.push((source, provenance, false));
                        }
                    }
                    None => mongo_opaque(
                        builder,
                        model_node,
                        "stdin mongo shell script is not statically recoverable",
                    ),
                }
            } else if let Some(source) = ctx.stdin_literal() {
                let mut provenance = vec![model_node];
                provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
                // The shell reads piped input line by line, not as one
                // evaluation.
                scripts.push((source.to_string(), provenance, false));
            } else if ctx.stdin.is_some() {
                mongo_opaque(
                    builder,
                    model_node,
                    "stdin mongo shell script is not statically recoverable",
                );
            } else {
                mongo_opaque(builder, model_node, "interactive mongo shell session");
            }
        } else if shell {
            mongo_opaque(builder, model_node, "interactive mongo shell session");
        }
        for (source, provenance, evaluation) in scripts {
            builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
            if evaluation && let Some((command, arguments)) = direct_mongo_shell_command(&source) {
                emit_mongo_shell_command(
                    builder,
                    model_node,
                    &provenance,
                    &mut target,
                    command,
                    &arguments,
                );
                continue;
            }
            analyze_mongo_shell_script(builder, ctx, model_node, &source, &provenance, &mut target);
        }
    }
}

const MONGO_VALUE_FLAGS: &[&str] = &[
    "--port",
    "-u",
    "--username",
    "-p",
    "--password",
    "--authenticationDatabase",
    "--authenticationMechanism",
    "--awsIamSessionToken",
    "--gssapiServiceName",
    "--gssapiHostName",
    "--sspiHostnameCanonicalization",
    "--sspiRealmOverride",
    "--tlsCAFile",
    "--tlsCertificateKeyFile",
    "--tlsCertificateKeyFilePassword",
    "--tlsCRLFile",
    "--tlsCertificateSelector",
    "--tlsDisabledProtocols",
    "--sslCAFile",
    "--sslPEMKeyFile",
    "--sslPEMKeyPassword",
    "--sslCRLFile",
    "--awsAccessKeyId",
    "--awsSecretAccessKey",
    "--awsSessionToken",
    "--keyVaultNamespace",
    "--kmsURL",
    "--apiVersion",
    "--cryptSharedLibPath",
    "--csfleLibraryPath",
    "--oidcFlows",
    "--oidcRedirectUri",
    "--browser",
];

const MONGO_BOOL_FLAGS: &[&str] = &[
    "--quiet",
    "--norc",
    "--verbose",
    "--tls",
    "--ssl",
    "--retryWrites",
    "--tlsAllowInvalidCertificates",
    "--tlsAllowInvalidHostnames",
    "--tlsFIPSMode",
    "--tlsUseSystemCA",
    "--sslAllowInvalidCertificates",
    "--sslAllowInvalidHostnames",
    "--apiStrict",
    "--apiDeprecationErrors",
    "--ipv6",
    "--oidcDumpTokens",
    "--oidcTrustedEndpoint",
    "--oidcNoNonce",
    "--deepInspect",
];

/// The text of a script file the shell runs, read through source
/// observation. None, behind a boundary, when it is not available.
fn mongo_script_file(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    path: &str,
) -> Option<String> {
    let unavailable = "mongo shell script file contents are unavailable";
    match ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput) {
        SourceResolution::Source { source, .. } => return Some(source.to_string()),
        SourceResolution::Refused(refusal) => {
            if let Some(detail) = source_refusal_detail(builder, refusal, unavailable) {
                mongo_opaque(builder, model_node, &detail);
            }
        }
        SourceResolution::UnsupportedEncoding => mongo_opaque(
            builder,
            model_node,
            "mongo shell script file is not valid UTF-8",
        ),
        SourceResolution::AlreadySelected => {}
        SourceResolution::Unavailable => mongo_opaque(builder, model_node, unavailable),
    }
    None
}

fn mongo_opaque(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    for domain in ["database", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNRECOVERABLE_SOURCE,
        BoundaryClass::Unresolved,
        &["database", "network"],
        detail,
    );
}

/// The server and database the shell's `db` is bound to. `known` turns
/// false once a statement the recognizer cannot read may have rebound it.
#[derive(Default)]
struct MongoTarget {
    server: Option<String>,
    database: Option<String>,
    known: bool,
}
