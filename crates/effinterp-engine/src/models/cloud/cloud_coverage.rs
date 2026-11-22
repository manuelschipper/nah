use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
    ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::{FlagSpec, scan};
use crate::word::Word;

use super::aws_s3::AWS_S3API_SPEC;
use super::cloud_args::{
    AZ_GLOBAL_VALUE_FLAGS, CLOUD_SCOPE_FLAGS, GSUTIL_GLOBAL_FLAGS, az_reads_argument_file,
};
use super::object_store_target::object_store_target;

/// Process launches are known; individual branches establish network interactions.
/// A reviewed storage, credential or resource-delete grammar closes cloud coverage
/// for this invocation; unrelated subcommands do not make an otherwise complete
/// request partial.
pub(super) fn declare_cloud_common(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    covered: bool,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    if covered || storage_command_covered(ctx) {
        builder.declare_coverage(Domain::new("cloud"), CoverageLevel::Full);
        return;
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::PARTIAL_ANALYSIS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("cloud")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("cloud model covers selected operations".to_string()),
    });
}

// Closure is limited to literal storage requests whose complete argument grammar
// and target selection the CLI models preserve. Filters, stdin lists, indirect
// IDs and unknown options still need the partial claim; scope resolution can also
// add its own boundary after this check.
fn storage_command_covered(ctx: &InvocationCtx) -> bool {
    let argv = ctx.argv;
    if argv.iter().any(|word| word.as_literal().is_none()) {
        return false;
    }
    let tool = crate::models::args::basename(argv[0].as_literal().unwrap());
    if tool == "az" && az_reads_argument_file(argv) {
        return false;
    }
    let command = match tool {
        "aws" | "gcloud" => crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS),
        "gsutil" => crate::models::scope::command_position(argv, GSUTIL_GLOBAL_FLAGS),
        "az" => crate::models::scope::command_position(argv, AZ_GLOBAL_VALUE_FLAGS),
        _ => 1,
    };
    let at = |offset| argv.get(command + offset).and_then(Word::as_literal);
    // The container emitter also reads a joined `--name=` and an attached `-n`.
    let joined_values = (tool, at(1)) == ("az", Some("container"));
    if matches!(
        (tool, at(0), at(1)),
        ("aws", Some("s3api"), Some("put-bucket-versioning"))
    ) {
        let scanned = scan(argv, &AWS_S3API_SPEC);
        return scanned.unknown_flags.is_empty()
            && scanned.operands.len() == 2
            && scanned.has(&["--bucket"])
            && !scanned.has(&["--versioning-configuration"]);
    }
    let (prefix, values, flags, target_flag, scheme, many) = match (tool, at(0), at(1), at(2)) {
        ("aws", Some("s3"), Some("rm"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url"][..],
            &["--recursive", "--quiet", "--only-show-errors"][..],
            &[][..],
            Some("s3://"),
            false,
        ),
        ("aws", Some("s3"), Some("sync"), _) => (
            2,
            &[
                "--profile",
                "--region",
                "--endpoint-url",
                "--exclude",
                "--include",
            ][..],
            &["--delete", "--quiet", "--only-show-errors", "--no-progress"][..],
            &[][..],
            Some("s3://"),
            false,
        ),
        ("aws", Some("s3api"), Some("delete-bucket"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url", "--bucket"][..],
            &[][..],
            &["--bucket"][..],
            None,
            false,
        ),
        ("aws", Some("s3api"), Some("delete-objects"), _) => (
            2,
            &[
                "--profile",
                "--region",
                "--endpoint-url",
                "--bucket",
                "--delete",
            ][..],
            &[][..],
            &["--bucket"][..],
            None,
            false,
        ),
        ("aws", Some("s3"), Some("rb"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url"][..],
            &["--force"][..],
            &[][..],
            Some("s3://"),
            false,
        ),
        ("aws", Some("ec2"), Some("delete-snapshot"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url", "--snapshot-id"][..],
            &[][..],
            &["--snapshot-id"][..],
            None,
            false,
        ),
        ("aws", Some("ec2"), Some("delete-volume"), _) => (
            2,
            &["--profile", "--region", "--endpoint-url", "--volume-id"][..],
            &[][..],
            &["--volume-id"][..],
            None,
            false,
        ),
        ("gcloud", Some("storage"), Some("rm"), _) => (
            2,
            &["--project"][..],
            &["--recursive", "-r", "-R", "--quiet", "-q"][..],
            &[][..],
            Some("gs://"),
            true,
        ),
        ("gcloud", Some("storage"), Some("rsync"), _) => (
            2,
            &["--project"][..],
            &["--delete-unmatched-destination-objects", "--quiet", "-q"][..],
            &[][..],
            Some("gs://"),
            false,
        ),
        ("gcloud", Some("storage"), Some("buckets"), Some("delete")) => (
            3,
            &["--project"][..],
            &["--quiet", "-q"][..],
            &[][..],
            Some("gs://"),
            true,
        ),
        ("gcloud", Some("compute"), Some("snapshots" | "disks"), Some("delete")) => (
            3,
            if at(1) == Some("disks") {
                &["--project", "--zone", "--region"][..]
            } else {
                &["--project", "--region"][..]
            },
            &["--quiet", "-q"][..],
            &[][..],
            None,
            false,
        ),
        ("gsutil", Some("rm"), _, _) => (
            1,
            &[][..],
            &["-m", "-q", "-r", "-R"][..],
            &[][..],
            Some("gs://"),
            true,
        ),
        ("gsutil", Some("rsync"), _, _) => (
            1,
            &[][..],
            &["-m", "-q", "-r", "-d"][..],
            &[][..],
            Some("gs://"),
            false,
        ),
        ("gsutil", Some("rb"), _, _) => {
            (1, &[][..], &["-m", "-q"][..], &[][..], Some("gs://"), true)
        }
        ("azcopy", Some("rm" | "remove"), _, _) => (
            1,
            &[][..],
            &["--recursive"][..],
            &[][..],
            Some("https://"),
            false,
        ),
        ("azcopy", Some("sync"), _, _) => (
            1,
            &[][..],
            &["--delete-destination"][..],
            &[][..],
            Some("https://"),
            false,
        ),
        ("az", Some("storage"), Some("container" | "account"), Some("delete")) => (
            3,
            if at(1) == Some("container") {
                &[
                    "--name",
                    "-n",
                    "--account-name",
                    "--subscription",
                    "--auth-mode",
                    "--output",
                    "-o",
                    "--query",
                    "--change-reference",
                ][..]
            } else {
                &["--name", "-n", "--resource-group", "-g", "--subscription"][..]
            },
            if at(1) == Some("account") {
                &["--yes", "-y"][..]
            } else {
                // --bypass-immutability-policy deletes a container even under
                // an immutability policy; the rest are Azure CLI globals.
                &[
                    "--bypass-immutability-policy",
                    "--acquire-policy-token",
                    "--debug",
                    "--verbose",
                    "--only-show-errors",
                ][..]
            },
            &["--name", "-n"][..],
            None,
            false,
        ),
        ("az", Some("storage"), Some("blob"), Some("delete-batch")) => (
            3,
            &["--source", "--account-name", "--subscription"][..],
            &[][..],
            &["--source"][..],
            None,
            false,
        ),
        ("az", Some("snapshot" | "disk"), Some("delete"), _) => (
            2,
            &["--name", "-n", "--resource-group", "-g", "--subscription"][..],
            if at(0) == Some("disk") {
                &["--yes", "-y"][..]
            } else {
                &[][..]
            },
            &["--name", "-n"][..],
            None,
            false,
        ),
        _ => return false,
    };
    let scanned = crate::models::args::scan(
        argv,
        &FlagSpec {
            allow_abbreviation: false,
            value_flags: values,
            known_flags: flags,
        },
    );
    if scanned.dashdash.is_some() || !scanned.unknown_flags.is_empty() {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    for flag in &scanned.flags {
        let raw = argv[flag.index as usize].as_literal().unwrap();
        if !seen.insert(flag.name)
            || ((flag.index as usize) < command
                && !CLOUD_SCOPE_FLAGS.contains(&flag.name)
                && !matches!(
                    (tool, flag.name),
                    ("gsutil", "-m" | "-q")
                        | ("gcloud", "--quiet" | "-q")
                        | (
                            "az",
                            "--output"
                                | "-o"
                                | "--query"
                                | "--debug"
                                | "--verbose"
                                | "--only-show-errors"
                        )
                ))
            || (flag.name == "--delete-destination" && !raw.contains('='))
        {
            return false;
        }
        if values.contains(&flag.name) {
            // The effect emitters use detached name/ID flags. Scope flags can
            // also be assigned, but accepting them here must not widen that parser.
            if raw != flag.name && !joined_values {
                return false;
            }
            if !flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .is_some_and(|value| {
                    !value.is_empty()
                        && !value.starts_with('-')
                        && (matches!(flag.name, "--endpoint-url" | "--delete")
                            || !value.contains("://"))
                })
            {
                return false;
            }
        } else if raw.contains('=')
            && !(tool == "azcopy"
                && matches!(
                    raw.split_once('=').map(|(_, value)| value),
                    Some("true" | "false")
                ))
        {
            return false;
        }
    }
    let operands: Vec<_> = scanned
        .operands
        .iter()
        .map(|(_, word)| word.as_literal().unwrap())
        .collect();
    if operands.len() < prefix || (0..prefix).any(|offset| Some(operands[offset]) != at(offset)) {
        return false;
    }
    let targets = if target_flag.is_empty() {
        operands[prefix..].to_vec()
    } else {
        if operands.len() != prefix {
            return false;
        }
        scanned
            .flags
            .iter()
            .filter(|flag| target_flag.contains(&flag.name))
            .filter_map(|flag| flag.value.as_ref().and_then(Word::as_literal))
            .collect()
    };
    let sync = matches!(
        (tool, at(0), at(1)),
        ("gcloud", Some("storage"), Some("rsync"))
            | ("azcopy", Some("sync"), _)
            | ("aws", Some("s3"), Some("sync"))
            | ("gsutil", Some("rsync"), _)
    );
    // The source read and destination write/delete preserve this local-to-object
    // transfer. Other directions remain partial.
    let targets = if sync {
        if targets.len() != 2
            || targets[0].is_empty()
            || targets[0].contains([':', '*', '?', '[', ']', '#'])
        {
            return false;
        }
        &targets[1..]
    } else {
        &targets[..]
    };
    !targets.is_empty()
        && (many || targets.len() == 1)
        && targets.iter().all(|target| {
            !target.is_empty()
                && !target.contains(['*', '?', '[', ']', '#'])
                && match scheme {
                    Some(scheme) => target.starts_with(scheme)
                        && matches!(object_store_target(&Word::literal(*target)), Some(ResourceExpr::Concrete { identity: ResourceIdentity::ObjectStore { bucket, .. } }) if !bucket.is_empty()),
                    None => !target.contains(['/', ':']),
                }
        })
}
