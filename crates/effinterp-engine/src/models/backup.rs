//! Backup selection is distinct from deletion of an entire repository.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryRef, BoundaryScope, CoverageLevel,
    Domain, ExecutionAssurance, ExecutionEdgeKind, ExecutionRealm, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{Flag, FlagSpec, Scanned, scan};
use crate::models::common::{
    Attrs, arg_effect, environment_input, fs_arg_effect, program_input_attrs, reviewed_source_node,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{Transition, word_resource};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

const DOMAINS: &[&str] = &["environment", "filesystem", "cloud", "network", "process"];
const RESTIC_SOURCE: &str = "https://raw.githubusercontent.com/restic/restic/ba802d42b7294c98b62c16d1157ea3e80820c019/cmd/restic/cmd_forget.go";
const VELERO_SOURCE: &str = "https://raw.githubusercontent.com/vmware-tanzu/velero/60163e0827e72658bb6546165a727300170e628b/pkg/cmd/cli/backup/delete.go";
const BORG_SOURCE: &str =
    "https://raw.githubusercontent.com/borgbackup/borg/1.4.1/src/borg/archiver.py";
const BORG2_SOURCE: &str =
    "https://raw.githubusercontent.com/borgbackup/borg/2.0.0b19/src/borg/manifest.py";
const KOPIA_SOURCE: &str = "https://kopia.io/docs/reference/command-line/common/snapshot-delete/";
const PGBACKREST_SOURCE: &str = "https://pgbackrest.org/command.html";

pub(super) fn backup_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Borg),
        Box::new(Restic),
        Box::new(Velero),
        Box::new(Duplicity),
        Box::new(Kopia),
        Box::new(PgBackRest),
    ]
}

fn backup_boundary(builder: &mut PlanBuilder, node: ProvenanceRef, detail: &str) -> BoundaryRef {
    let reference = builder.boundary(Boundary {
        reason: BoundaryReason::MODEL_COVERAGE,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        affected_resource: None,
        callee: None,
        provenance: vec![node],
        limit: None,
        detail: Some(detail.into()),
    });
    for domain in DOMAINS {
        builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
    }
    reference
}

fn unresolved_boundary(
    builder: &mut PlanBuilder,
    node: ProvenanceRef,
    reason: BoundaryReason,
    scope: BoundaryScope,
    domains: &[&str],
    affected_resource: Option<ResourceExpr>,
    detail: &str,
) -> BoundaryRef {
    builder.boundary_with_coverage(
        Boundary {
            reason,
            class: BoundaryClass::Unresolved,
            scope,
            domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
            affected_resource,
            callee: None,
            provenance: vec![node],
            limit: None,
            detail: Some(detail.into()),
        },
        CoverageLevel::Partial,
    )
}

fn reviewed_boundary(builder: &mut PlanBuilder, node: ProvenanceRef, detail: &str) -> BoundaryRef {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::REVIEWED_COMMAND_SURFACE,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
            affected_resource: None,
            callee: None,
            provenance: vec![node],
            limit: None,
            detail: Some(detail.into()),
        },
        CoverageLevel::Partial,
    )
}

// pflag boolean options accept attached values; occurrence alone is not truth.
fn boolean(ctx: &InvocationCtx, scanned: &Scanned, names: &[&str]) -> Option<bool> {
    let mut value = false;
    for flag in scanned.flags.iter().filter(|f| names.contains(&f.name)) {
        let raw = ctx.argv[flag.index as usize].as_literal()?;
        value = match raw.split_once('=').map(|(_, value)| value) {
            None | Some("1" | "t" | "T" | "TRUE" | "true" | "True") => true,
            Some("0" | "f" | "F" | "FALSE" | "false" | "False") => false,
            _ => return None,
        };
    }
    Some(value)
}

fn valid_options(ctx: &InvocationCtx, scanned: &Scanned, spec: &FlagSpec, bools: &[&str]) -> bool {
    scanned.unknown_flags.is_empty()
        && scanned
            .operands
            .iter()
            .all(|(_, word)| word.as_literal().is_some())
        && scanned.flags.iter().all(|flag| {
            if spec.value_flags.contains(&flag.name) {
                flag.value.as_ref().and_then(Word::as_literal).is_some()
            } else if bools.contains(&flag.name) {
                boolean(ctx, scanned, &[flag.name]).is_some()
            } else {
                ctx.argv[flag.index as usize]
                    .as_literal()
                    .is_some_and(|s| !s.contains('='))
            }
        })
}

fn scanned_option_value<'a>(scanned: &'a Scanned, names: &[&str]) -> Option<&'a str> {
    scanned.value_of(names).and_then(Word::as_literal)
}

fn repository(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    scanned: &Scanned,
    names: &[&str],
    env: &str,
) -> Option<String> {
    if let Some(word) = scanned.value_of(names) {
        return word.as_literal().map(str::to_owned);
    }
    environment_input(builder, ctx, node, env);
    match ctx.environment_value(env) {
        Some(ResourceExpr::Literal { value }) => Some(value),
        _ => None,
    }
}

fn string(attrs: &mut Attrs, key: &str, value: &str) {
    attrs.insert(key.into(), AttrValue::String(value.into()));
}

/// Each selecting flag and its literal value, in invocation order, as the
/// `{prefix}_options` and `{prefix}_values` lists. Nothing when no flag
/// selects.
fn option_attrs<'a>(attrs: &mut Attrs, prefix: &str, flags: impl Iterator<Item = &'a Flag<'a>>) {
    let (options, values): (Vec<_>, Vec<_>) = flags
        .map(|flag| {
            (
                flag.name,
                flag.value.as_ref().unwrap().as_literal().unwrap(),
            )
        })
        .unzip();
    if options.is_empty() {
        return;
    }
    for (key, list) in [("options", options), ("values", values)] {
        attrs.insert(
            format!("{prefix}_{key}"),
            AttrValue::List(
                list.into_iter()
                    .map(|v| AttrValue::String(v.into()))
                    .collect(),
            ),
        );
    }
}

fn selection(kind: &str, whole: bool, all: bool) -> Attrs {
    let mut attrs = Attrs::new();
    string(&mut attrs, "selection", kind);
    attrs.insert("whole_repository".into(), AttrValue::Bool(whole));
    attrs.insert("all_requested".into(), AttrValue::Bool(all));
    attrs.insert("unsafe_allow_remove_all".into(), AttrValue::Bool(false));
    attrs
}

fn logical_backup_resource(attrs: &mut Attrs, physical_family: &str) -> ResourceExpr {
    let kind = match (attrs.get("backup_action"), attrs.get("selection")) {
        (Some(AttrValue::String(action)), _) if action == "delete_repository" => {
            "backup_repository"
        }
        (Some(AttrValue::String(action)), Some(AttrValue::String(selection)))
            if action == "delete_archive" && selection == "archive" =>
        {
            "backup_archive"
        }
        (Some(AttrValue::String(action)), Some(AttrValue::String(selection)))
            if matches!(action.as_str(), "delete_snapshot" | "delete_backup")
                && matches!(selection.as_str(), "snapshot" | "backup") =>
        {
            "backup_snapshot"
        }
        _ => "backup_selection",
    };
    string(attrs, "logical_resource_kind", kind);
    unresolved_resource(physical_family)
}

fn restic_repository_file(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    scanned: &Scanned,
) -> bool {
    environment_input(builder, ctx, node, "RESTIC_REPOSITORY_FILE");
    let source = scanned
        .flags
        .iter()
        .rev()
        .find(|flag| flag.name == "--repository-file");
    let resource = if let Some(source) = source {
        let word = source.value.as_ref().unwrap();
        let resource = ctx.resolve_fs_word(word);
        fs_arg_effect(
            builder,
            ctx,
            node,
            source.value_index.unwrap_or(source.index),
            word,
            "filesystem.read",
            resource.clone(),
            program_input_attrs(),
        );
        Some(resource)
    } else {
        ctx.environment_value("RESTIC_REPOSITORY_FILE")
            .inspect(|resource| {
                arg_effect(
                    builder,
                    ctx,
                    node,
                    0,
                    "filesystem.read",
                    resource.clone(),
                    program_input_attrs(),
                );
            })
    };
    if let Some(resource) = resource {
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::UNRESOLVED_SOURCE,
            BoundaryScope::Invocation,
            &["filesystem"],
            Some(resource),
            "restic repository-file contents are not supplied",
        );
        true
    } else {
        false
    }
}

// Snapshot names and selectors are not physical filenames or object keys.
// Keep the repository locator as evidence, without inventing those identities.
fn repository_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    repo: Option<&str>,
    restic: bool,
    mut attrs: Attrs,
) {
    let logical_resource = logical_backup_resource(&mut attrs, "filesystem");
    // The command grammar already established that backups are removed; only
    // where the repository lives, and with it its backend, stays unobserved.
    let Some(repo) = repo else {
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            BoundaryScope::Invocation,
            &["environment", "filesystem", "cloud", "network"],
            None,
            "backup repository location and backend are not observed",
        );
        arg_effect(
            builder,
            ctx,
            node,
            0,
            "filesystem.delete",
            logical_resource.clone(),
            attrs,
        );
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::LIVE_INVENTORY,
            BoundaryScope::Environment,
            &["filesystem", "cloud", "network"],
            None,
            "selected backups and physical repository objects require live inventory",
        );
        return;
    };
    if repo.is_empty() || repo.contains(['{', '}']) {
        backup_boundary(
            builder,
            node,
            "backup repository location is empty or requires runtime expansion",
        );
        return;
    }
    let location = if restic {
        repo.strip_prefix("local:").unwrap_or(repo)
    } else {
        repo
    };
    if location.is_empty() {
        backup_boundary(builder, node, "backup repository path is empty");
        return;
    }
    let mut remote = None;
    let mut object = false;
    if restic
        && ["s3:", "gs:", "azure:", "b2:", "swift:"]
            .iter()
            .any(|p| repo.starts_with(p))
    {
        // Backend identity is known, but repository contents and removed keys are not.
        let (backend, rest) = repo.split_once(':').unwrap();
        let valid = if backend == "s3" {
            let rest = rest
                .strip_prefix("https://")
                .or_else(|| rest.strip_prefix("http://"))
                .unwrap_or(rest);
            rest.split_once('/').is_some_and(|(host, path)| {
                !host.is_empty() && !path.split('/').next().unwrap_or("").is_empty()
            })
        } else {
            rest.split_once(':')
                .is_some_and(|(bucket, _)| !bucket.is_empty())
        };
        if !valid {
            backup_boundary(
                builder,
                node,
                "backup object repository syntax is not established",
            );
            return;
        }
        object = true;
    } else if let Some(ssh) = location
        .strip_prefix("ssh://")
        .filter(|_| !restic)
        .or_else(|| location.strip_prefix("sftp://").filter(|_| restic))
    {
        let Some((endpoint, path)) = ssh.split_once('/') else {
            backup_boundary(builder, node, "remote backup repository has no path");
            return;
        };
        if endpoint.is_empty() || path.is_empty() {
            backup_boundary(
                builder,
                node,
                "remote backup repository has an empty endpoint or path",
            );
            return;
        }
        remote = Some(endpoint.to_owned());
    } else if let Some(sftp) = location.strip_prefix("sftp:").filter(|_| restic) {
        let Some((endpoint, path)) = sftp.rsplit_once(':') else {
            backup_boundary(builder, node, "unresolved SFTP backup repository");
            return;
        };
        if endpoint.is_empty() || path.is_empty() {
            backup_boundary(builder, node, "empty SFTP backup endpoint or path");
            return;
        }
        remote = Some(endpoint.to_owned());
    } else if !location.starts_with('/') && !location.starts_with("./") && location.contains(':') {
        if !restic && !location.contains("://") {
            let (endpoint, path) = location.split_once(':').unwrap();
            if endpoint.is_empty() || path.is_empty() {
                backup_boundary(builder, node, "empty SSH backup endpoint or path");
                return;
            }
            remote = Some(endpoint.to_owned());
        } else {
            backup_boundary(builder, node, "backup repository backend is not modeled");
            return;
        }
    }
    string(&mut attrs, "repository", repo);
    let whole = attrs.get("whole_repository") == Some(&AttrValue::Bool(true));
    let resource = if whole && remote.is_none() && !object {
        ctx.resolve_fs_word(&Word::literal(location))
    } else if object {
        logical_backup_resource(&mut attrs, "object")
    } else {
        logical_resource
    };
    let op = if object {
        "cloud.object.delete"
    } else {
        "filesystem.delete"
    };
    if let Some(endpoint) = remote {
        // The client establishes the remote operation, not the server argv.
        // Keep that execution widened instead of inventing a remote command.
        let server = Word::new(vec![WordPart::Unknown]);
        let Some(frame) = ctx.nest.begin(
            builder,
            Transition::exec(vec![word_resource(&server)], vec![server])
                .kind(ExecutionEdgeKind::ToolModel)
                .realm(ExecutionRealm::Remote { endpoint })
                .mounts(Vec::new())
                .streams(Default::default())
                .assurance(ExecutionAssurance::Widened),
            &[node],
            ctx.depth,
        ) else {
            return;
        };
        let uncertainty = unresolved_boundary(
            builder,
            frame.scope,
            BoundaryReason::LIVE_INVENTORY,
            BoundaryScope::Environment,
            &["filesystem", "network", "process"],
            None,
            "backup server execution and physical repository entries are not observed",
        );
        builder.attach_boundary_to_uncertain_execution(uncertainty);
        arg_effect(builder, ctx, frame.scope, 0, op, resource.clone(), attrs);
        frame.end(builder);
    } else {
        arg_effect(builder, ctx, node, 0, op, resource.clone(), attrs);
    }
    unresolved_boundary(
        builder,
        node,
        BoundaryReason::LIVE_INVENTORY,
        BoundaryScope::Environment,
        &["environment", "filesystem", "cloud", "network", "process"],
        None,
        "backup repository contents, affected cardinality, cache, locks and transport effects are not enumerated",
    );
}

const BORG_GLOBAL: &[&str] = &[
    "-r",
    "--repo",
    "-h",
    "--help",
    "--version",
    "-v",
    "--verbose",
    "--debug",
    "--progress",
    "--log-json",
    "--show-rc",
];
const BORG_COUNTS: &[&str] = &[
    "--keep-last",
    "--keep-secondly",
    "--keep-minutely",
    "-H",
    "--keep-hourly",
    "-d",
    "--keep-daily",
    "-w",
    "--keep-weekly",
    "-m",
    "--keep-monthly",
    "-y",
    "--keep-yearly",
];
const BORG_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "-r",
        "--repo",
        "-a",
        "--glob-archives",
        "--match-archives",
        "-P",
        "--prefix",
        "--first",
        "--last",
        "--threshold",
        "--keep-last",
        "--keep-secondly",
        "--keep-minutely",
        "-H",
        "--keep-hourly",
        "-d",
        "--keep-daily",
        "-w",
        "--keep-weekly",
        "-m",
        "--keep-monthly",
        "-y",
        "--keep-yearly",
    ],
    known_flags: &[
        "-h",
        "--help",
        "--version",
        "-v",
        "--verbose",
        "--debug",
        "--progress",
        "--log-json",
        "--show-rc",
        "-n",
        "--dry-run",
        "--list",
        "-s",
        "--stats",
        "--quick-stats",
        "--force",
        "--cache-only",
        "--keep-security-info",
        "--save-space",
        "--cleanup-commits",
        "--yes",
    ],
};

struct Borg;
impl CommandModel for Borg {
    fn id(&self) -> &'static str {
        "borg/backup@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["borg"]
    }
    fn domains(&self) -> &'static [&'static str] {
        DOMAINS
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let scanned = scan(ctx.argv, &BORG_SPEC);
        let v2 = scanned.has(&["-r", "--repo"])
            || scanned
                .operands
                .first()
                .is_some_and(|(_, w)| w.as_literal() == Some("repo-delete"));
        let node = reviewed_source_node(
            builder,
            ctx,
            node,
            if v2 { BORG2_SOURCE } else { BORG_SOURCE },
        );
        if !valid_options(ctx, &scanned, &BORG_SPEC, &[]) {
            backup_boundary(
                builder,
                node,
                "borg options or operands are unknown, invalid or incomplete",
            );
            return;
        }
        if scanned.has(&["-h", "--help", "--version"]) {
            backup_boundary(
                builder,
                node,
                "borg informational invocation; output effects are not enumerated",
            );
            return;
        }
        let Some((command_index, command)) = scanned.operands.first() else {
            backup_boundary(builder, node, "borg subcommand is absent");
            return;
        };
        let command = command.as_literal().unwrap();
        if scanned.has(&["--yes"]) {
            reviewed_boundary(
                builder,
                node,
                "borg does not define --yes; repository deletion confirmation is interactive or environment-driven",
            );
            return;
        }
        if !matches!(command, "delete" | "repo-delete" | "prune" | "compact") {
            backup_boundary(
                builder,
                node,
                "borg subcommand is outside repository/archive destruction coverage",
            );
            return;
        }
        if v2 && command == "prune" {
            backup_boundary(
                builder,
                node,
                "borg 2 retention policy is outside modeled archive selection coverage",
            );
            return;
        }
        let counts = scanned
            .flags
            .iter()
            .filter(|f| BORG_COUNTS.contains(&f.name))
            .collect::<Vec<_>>();
        if counts.iter().any(|f| {
            counts
                .iter()
                .filter(|other| borg_count_name(other.name) == borg_count_name(f.name))
                .count()
                > 1
        }) {
            backup_boundary(
                builder,
                node,
                "repeated borg retention options are not modeled",
            );
            return;
        }
        let filters = [
            "-a",
            "--glob-archives",
            "--match-archives",
            "-P",
            "--prefix",
            "--first",
            "--last",
        ];
        let filtered = scanned.has(&filters);
        if v2
            && scanned
                .values_of(&["-a", "--match-archives"])
                .iter()
                .any(|(_, word)| {
                    let pattern = word.as_literal().unwrap();
                    pattern.contains(':') && !pattern.starts_with("sh:")
                })
        {
            backup_boundary(
                builder,
                node,
                "borg typed archive pattern requires unmodeled validation",
            );
            return;
        }
        if scanned
            .flags
            .iter()
            .any(|f| f.index < *command_index && !BORG_GLOBAL.contains(&f.name))
            || (command != "prune" && !counts.is_empty())
            || (command == "repo-delete"
                && (filtered || scanned.has(&["-s", "--stats", "--quick-stats", "--save-space"])))
            || (command == "prune"
                && scanned.has(&["--cache-only", "--keep-security-info", "--first", "--last"]))
            || (v2 && scanned.has(&["--glob-archives", "-P", "--prefix", "--save-space"]))
            || (!v2 && scanned.has(&["--match-archives"]))
            || (v2
                && command == "delete"
                && scanned.has(&[
                    "--stats",
                    "-s",
                    "--quick-stats",
                    "--force",
                    "--cache-only",
                    "--keep-security-info",
                ]))
            || (scanned.has(&["--stats", "-s"]) && scanned.has(&["--quick-stats"]))
            || (scanned.has(&["--stats", "-s", "--quick-stats"])
                && scanned.has(&["-n", "--dry-run"]))
        {
            backup_boundary(
                builder,
                node,
                "borg options conflict with the selected command grammar",
            );
            return;
        }
        if scanned.has(&["-n", "--dry-run"]) {
            reviewed_boundary(
                builder,
                node,
                "borg dry-run does not delete repository backups; ancillary effects are not enumerated",
            );
            return;
        }
        for flag in &scanned.flags {
            if ["--first", "--last"].contains(&flag.name)
                && flag
                    .value
                    .as_ref()
                    .and_then(Word::as_literal)
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_none_or(|n| n == 0)
            {
                backup_boundary(
                    builder,
                    node,
                    "borg archive count selector is zero, invalid or unknown",
                );
                return;
            }
        }
        if command == "prune"
            && (counts.is_empty()
                || counts.iter().any(|f| {
                    f.value
                        .as_ref()
                        .and_then(Word::as_literal)
                        .and_then(|s| s.parse::<i64>().ok())
                        .is_none()
                })
                || !counts.iter().any(|f| {
                    f.value
                        .as_ref()
                        .and_then(Word::as_literal)
                        .and_then(|s| s.parse::<i64>().ok())
                        .is_some_and(|n| n != 0)
                }))
        {
            backup_boundary(
                builder,
                node,
                "borg prune requires a valid nonzero retention policy",
            );
            return;
        }
        let mut operands = scanned
            .operands
            .iter()
            .skip(1)
            .map(|(_, w)| w.as_literal().unwrap())
            .collect::<Vec<_>>();
        let repo = if v2 {
            repository(builder, ctx, node, &scanned, &["-r", "--repo"], "BORG_REPO")
        } else if !operands.is_empty() {
            Some(operands.remove(0).to_owned())
        } else {
            // Without version evidence, BORG_REPO plus bare delete is ambiguous
            // between Borg 1 repository deletion and Borg 2 archive selection.
            backup_boundary(
                builder,
                node,
                "borg repository selection or command version is not observed",
            );
            return;
        };
        let (repo, archive) = match repo.as_deref() {
            Some(repo) if !v2 => repo
                .split_once("::")
                .map_or((Some(repo), None), |(r, a)| (Some(r), Some(a))),
            repo => (repo, None),
        };
        if let Some(archive) = archive {
            operands.insert(0, archive);
        }
        if (v2
            && ((command == "repo-delete" || command == "prune") && !operands.is_empty()
                || operands.len() > 1))
            || (command == "prune" && !operands.is_empty())
            || (filtered && !operands.is_empty())
            || operands.iter().any(|s| !archive_name(s, v2))
        {
            backup_boundary(
                builder,
                node,
                "borg archive operands conflict with selection controls",
            );
            return;
        }
        let whole = command == "repo-delete"
            || (!v2 && command == "delete" && !filtered && operands.is_empty());
        if v2 && command == "delete" && !filtered && operands.is_empty() {
            backup_boundary(
                builder,
                node,
                "borg archive deletion requires an explicit selection",
            );
            return;
        }
        if whole && scanned.has(&["--cache-only"]) {
            reviewed_boundary(
                builder,
                node,
                "borg cache-only affects its cache, not repository backups; cache identity is not observed",
            );
            return;
        }
        let mut attrs = selection(
            if whole {
                "repository"
            } else if command == "compact" {
                "unreferenced_data"
            } else if command == "prune" {
                "retention"
            } else {
                "archive"
            },
            whole,
            whole,
        );
        if command == "compact" {
            string(&mut attrs, "storage_action", "compact_repository");
        } else {
            string(
                &mut attrs,
                "backup_action",
                if whole {
                    "delete_repository"
                } else {
                    "delete_archive"
                },
            );
        }
        option_attrs(
            &mut attrs,
            "selection",
            scanned
                .flags
                .iter()
                .filter(|f| filters.contains(&f.name) || BORG_COUNTS.contains(&f.name)),
        );
        // Selecting archives removes those backups from the repository. Borg 2
        // keeps them recoverable until `borg compact`, which `soft_delete`
        // records; neither variant leaves the named backup available.
        attrs.insert(
            "soft_delete".into(),
            AttrValue::Bool(!whole && command != "compact"),
        );
        if operands.is_empty() {
            repository_effect(builder, ctx, node, repo, false, attrs);
        } else {
            for archive in operands {
                let mut attrs = attrs.clone();
                string(&mut attrs, "archive", archive);
                repository_effect(builder, ctx, node, repo, false, attrs);
            }
        }
    }
}

const RESTIC_COUNTS: &[&[&str]] = &[
    &["-l", "--keep-last"],
    &["-H", "--keep-hourly"],
    &["-d", "--keep-daily"],
    &["-w", "--keep-weekly"],
    &["-m", "--keep-monthly"],
    &["-y", "--keep-yearly"],
];
const RESTIC_WITHIN: &[&str] = &[
    "--keep-within",
    "--keep-within-hourly",
    "--keep-within-daily",
    "--keep-within-weekly",
    "--keep-within-monthly",
    "--keep-within-yearly",
];
const RESTIC_BOOLS: &[&str] = &[
    "-h",
    "--help",
    "-n",
    "--dry-run",
    "--unsafe-allow-remove-all",
    "--prune",
    "--no-lock",
    "--json",
    "-q",
    "--quiet",
    "-c",
    "--compact",
];
const RESTIC_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "-r",
        "--repo",
        "--repository-file",
        "--password-file",
        "-p",
        "--tag",
        "--host",
        "--hostname",
        "--path",
        "-g",
        "--group-by",
        "-l",
        "--keep-last",
        "-H",
        "--keep-hourly",
        "-d",
        "--keep-daily",
        "-w",
        "--keep-weekly",
        "-m",
        "--keep-monthly",
        "-y",
        "--keep-yearly",
        "--keep-within",
        "--keep-within-hourly",
        "--keep-within-daily",
        "--keep-within-weekly",
        "--keep-within-monthly",
        "--keep-within-yearly",
    ],
    known_flags: &[
        "-h",
        "--help",
        "-n",
        "--dry-run",
        "--unsafe-allow-remove-all",
        "--prune",
        "--no-lock",
        "--json",
        "-q",
        "--quiet",
        "-c",
        "--compact",
        "-v",
        "--verbose",
    ],
};

/// Whether a restic `--keep-within*` duration such as `1y5m7d2h` is all zero,
/// or `None` when restic rejects it; negative numbers are rejected.
fn restic_duration_is_zero(value: &str) -> Option<bool> {
    let mut rest = value.trim();
    let mut zero = true;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let number = rest[..digits].parse::<i32>().ok()?;
        rest = rest[digits..].strip_prefix(['y', 'm', 'd', 'h'])?;
        zero &= number == 0;
    }
    Some(zero)
}

struct Restic;
impl CommandModel for Restic {
    fn id(&self) -> &'static str {
        "restic/backup@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["restic"]
    }
    fn domains(&self) -> &'static [&'static str] {
        DOMAINS
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let node = reviewed_source_node(builder, ctx, node, RESTIC_SOURCE);
        let scanned = scan(ctx.argv, &RESTIC_SPEC);
        if !valid_options(ctx, &scanned, &RESTIC_SPEC, RESTIC_BOOLS) {
            backup_boundary(
                builder,
                node,
                "restic options or operands are unknown, invalid or incomplete",
            );
            return;
        }
        if boolean(ctx, &scanned, &["-h", "--help"]) == Some(true) {
            backup_boundary(
                builder,
                node,
                "restic help does not remove backups; output effects are not enumerated",
            );
            return;
        }
        let command = scanned
            .operands
            .first()
            .and_then(|(_, word)| word.as_literal());
        if !matches!(command, Some("forget" | "prune")) {
            backup_boundary(
                builder,
                node,
                "restic command is outside snapshot forgetting and repository pruning coverage",
            );
            return;
        }
        if command == Some("prune") {
            let prune_flags = [
                "-r",
                "--repo",
                "--repository-file",
                "--password-file",
                "-p",
                "-n",
                "--dry-run",
                "--no-lock",
                "--json",
                "-q",
                "--quiet",
                "-c",
                "--compact",
                "-v",
                "--verbose",
            ];
            if scanned.operands.len() != 1
                || scanned
                    .flags
                    .iter()
                    .any(|flag| !prune_flags.contains(&flag.name))
            {
                backup_boundary(
                    builder,
                    node,
                    "restic prune arguments are outside reviewed coverage",
                );
                return;
            }
            if boolean(ctx, &scanned, &["-n", "--dry-run"]) == Some(true) {
                reviewed_boundary(
                    builder,
                    node,
                    "restic prune dry-run does not remove unreferenced repository data",
                );
                return;
            }
            let from_file = restic_repository_file(builder, ctx, node, &scanned);
            let repo = if from_file {
                None
            } else {
                repository(
                    builder,
                    ctx,
                    node,
                    &scanned,
                    &["-r", "--repo"],
                    "RESTIC_REPOSITORY",
                )
            };
            let mut attrs = selection("unreferenced_data", false, false);
            string(&mut attrs, "storage_action", "prune_repository");
            repository_effect(builder, ctx, node, repo.as_deref(), true, attrs);
            return;
        }
        if boolean(ctx, &scanned, &["-n", "--dry-run"]) == Some(true)
            || boolean(ctx, &scanned, &["--no-lock"]) == Some(true)
        {
            reviewed_boundary(
                builder,
                node,
                "restic forget dry-run does not remove snapshots; --no-lock without dry-run is invalid",
            );
            return;
        }
        if scanned_option_value(&scanned, &["-g", "--group-by"]).is_some_and(|s| {
            !s.is_empty()
                && s.split(',')
                    .any(|part| !["host", "paths", "tags"].contains(&part))
        }) {
            backup_boundary(builder, node, "restic snapshot grouping is invalid");
            return;
        }
        let mut policy = false;
        for names in RESTIC_COUNTS {
            for (_, word) in scanned.values_of(names) {
                let s = word.as_literal().unwrap();
                if s != "unlimited" && s.parse::<i64>().map_or(true, |n| n < 0) {
                    backup_boundary(builder, node, "restic retention count is invalid");
                    return;
                }
            }
            policy |= scanned_option_value(&scanned, names)
                .is_some_and(|s| s == "unlimited" || s.parse::<i64>().is_ok_and(|n| n > 0));
        }
        for name in RESTIC_WITHIN {
            for (_, word) in scanned.values_of(&[name]) {
                if restic_duration_is_zero(word.as_literal().unwrap()).is_none() {
                    backup_boundary(builder, node, "restic retention duration is invalid");
                    return;
                }
            }
            // An all-zero duration sets no policy.
            policy |= scanned_option_value(&scanned, &[name]).and_then(restic_duration_is_zero)
                == Some(false);
        }
        let ids = &scanned.operands[1..];
        if ids.iter().any(|(_, w)| {
            w.as_literal().is_none_or(|s| {
                s != "latest"
                    && (s.is_empty() || s.len() > 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()))
            })
        }) {
            backup_boundary(
                builder,
                node,
                "restic snapshot ID is not a literal hexadecimal prefix or latest",
            );
            return;
        }
        let allow = boolean(ctx, &scanned, &["--unsafe-allow-remove-all"]).unwrap();
        let filters = ["--tag", "--host", "--hostname", "--path"];
        let filtered = scanned.has(&filters);
        // SnapshotFilter.FindAll rejects unused filters when every operand is
        // an explicit ID. `latest` is different: it resolves through the
        // filter and therefore consumes it.
        if !ids.is_empty()
            && filtered
            && !ids
                .iter()
                .any(|(_, word)| word.as_literal() == Some("latest"))
        {
            backup_boundary(
                builder,
                node,
                "restic explicit snapshot IDs leave filter options unused",
            );
            return;
        }
        if ids.is_empty()
            && (!(policy || (allow && filtered))
                || scanned_option_value(&scanned, &["-l", "--keep-last"]) == Some("unlimited"))
        {
            backup_boundary(
                builder,
                node,
                "restic forget has no removal policy, lacks the required allow-all filter, or keeps every snapshot",
            );
            return;
        }
        let from_file = restic_repository_file(builder, ctx, node, &scanned);
        // A repository file names a location this analysis has not read, the
        // same unobserved location an unset RESTIC_REPOSITORY leaves behind.
        let repo = if from_file {
            None
        } else {
            repository(
                builder,
                ctx,
                node,
                &scanned,
                &["-r", "--repo"],
                "RESTIC_REPOSITORY",
            )
        };
        let mut attrs = selection(
            if !ids.is_empty() {
                "snapshot"
            } else if policy {
                "retention"
            } else {
                "filter"
            },
            false,
            ids.is_empty() && !policy && allow,
        );
        attrs.insert("unsafe_allow_remove_all".into(), AttrValue::Bool(allow));
        attrs.insert(
            "prune_requested".into(),
            AttrValue::Bool(boolean(ctx, &scanned, &["--prune"]).unwrap()),
        );
        string(&mut attrs, "backup_action", "delete_snapshot");
        // Repeated filters are conjunctive/disjunctive according to restic;
        // retain them as evidence without pretending the last is the set.
        option_attrs(
            &mut attrs,
            "filter",
            scanned.flags.iter().filter(|f| filters.contains(&f.name)),
        );
        for names in RESTIC_COUNTS {
            if let Some(count) = scanned_option_value(&scanned, names) {
                string(&mut attrs, names[1].trim_start_matches("--"), count);
            }
        }
        for name in RESTIC_WITHIN {
            if let Some(duration) = scanned_option_value(&scanned, &[name]) {
                string(&mut attrs, name.trim_start_matches("--"), duration);
            }
        }
        if ids.is_empty() {
            repository_effect(builder, ctx, node, repo.as_deref(), true, attrs);
        } else {
            for (_, id) in ids {
                let mut attrs = attrs.clone();
                string(&mut attrs, "snapshot", id.as_literal().unwrap());
                repository_effect(builder, ctx, node, repo.as_deref(), true, attrs);
            }
        }
    }
}

const VELERO_BOOLS: &[&str] = &["--all", "--confirm", "-h", "--help"];
const VELERO_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "-l",
        "--selector",
        "-n",
        "--namespace",
        "--kubeconfig",
        "--kubecontext",
    ],
    known_flags: VELERO_BOOLS,
};

struct Velero;
impl CommandModel for Velero {
    fn id(&self) -> &'static str {
        "velero/backup@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["velero"]
    }
    fn domains(&self) -> &'static [&'static str] {
        DOMAINS
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let node = reviewed_source_node(builder, ctx, node, VELERO_SOURCE);
        let scanned = scan(ctx.argv, &VELERO_SPEC);
        if !valid_options(ctx, &scanned, &VELERO_SPEC, VELERO_BOOLS) {
            backup_boundary(
                builder,
                node,
                "velero selection or boolean options are unknown, invalid or incomplete",
            );
            return;
        }
        if boolean(ctx, &scanned, &["-h", "--help"]) == Some(true) {
            backup_boundary(
                builder,
                node,
                "velero help does not delete backups; output effects are not enumerated",
            );
            return;
        }
        let operands = scanned
            .operands
            .iter()
            .map(|(_, w)| w.as_literal().unwrap())
            .collect::<Vec<_>>();
        if operands.len() < 2 || operands[..2] != ["backup", "delete"] {
            backup_boundary(
                builder,
                node,
                "velero subcommand is outside backup deletion coverage",
            );
            return;
        }
        let names = &operands[2..];
        let all = boolean(ctx, &scanned, &["--all"]).unwrap();
        let selector = scanned_option_value(&scanned, &["-l", "--selector"]);
        if usize::from(!names.is_empty()) + usize::from(all) + usize::from(selector.is_some()) != 1
        {
            backup_boundary(
                builder,
                node,
                "velero backup delete requires exactly one of names, --all=true, or selector",
            );
            return;
        }
        // Support literal equality selectors here; other Kubernetes selector
        // syntax needs a parser before it can provide positive evidence.
        if scanned
            .values_of(&["-l", "--selector"])
            .iter()
            .any(|(_, word)| !equality_selector(word.as_literal().unwrap()))
            || names.iter().any(|s| !dns_name(s))
        {
            backup_boundary(
                builder,
                node,
                "velero backup name or selector syntax is outside modeled validation",
            );
            return;
        }
        let mut attrs = selection(
            if all {
                "all_backups"
            } else if selector.is_some() {
                "selector"
            } else {
                "backup"
            },
            false,
            all,
        );
        attrs.insert(
            "confirm_requested".into(),
            AttrValue::Bool(boolean(ctx, &scanned, &["--confirm"]).unwrap()),
        );
        attrs.insert("asynchronous".into(), AttrValue::Bool(true));
        string(&mut attrs, "backup_action", "delete_backup");
        if let Some(selector) = selector {
            string(&mut attrs, "selector", selector);
        }
        if let Some(namespace) = scanned_option_value(&scanned, &["-n", "--namespace"]) {
            string(&mut attrs, "namespace", namespace);
        }
        let resource = logical_backup_resource(&mut attrs, "object");
        let selections = if names.is_empty() {
            vec![None]
        } else {
            names.iter().map(|s| Some(*s)).collect()
        };
        for name in selections {
            let mut attrs = attrs.clone();
            if let Some(name) = name {
                string(&mut attrs, "backup", name);
            }
            arg_effect(
                builder,
                ctx,
                node,
                0,
                "cloud.object.delete",
                resource.clone(),
                attrs,
            );
        }
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::LIVE_INVENTORY,
            BoundaryScope::Environment,
            &["environment", "filesystem", "cloud", "network", "process"],
            None,
            "velero submits asynchronous deletion requests; storage locations, selected backups, removed counts and controller effects are not observed",
        );
    }
}

// `--delete` confirms the deletion: without it Kopia only lists what it would
// remove. `--unsafe-ignore-source` lets a manifest ID from any source match.
const KOPIA_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[],
    known_flags: &["--delete", "--unsafe-ignore-source"],
};

struct Kopia;
impl CommandModel for Kopia {
    fn id(&self) -> &'static str {
        "kopia/snapshot-delete@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["kopia"]
    }
    fn domains(&self) -> &'static [&'static str] {
        DOMAINS
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let node = reviewed_source_node(builder, ctx, node, KOPIA_SOURCE);
        let scanned = scan(ctx.argv, &KOPIA_SPEC);
        let operands = scanned
            .operands
            .iter()
            .map(|(_, word)| word.as_literal())
            .collect::<Option<Vec<_>>>();
        let Some(operands) = operands else {
            backup_boundary(builder, node, "kopia snapshot selection is not literal");
            return;
        };
        if !scanned.unknown_flags.is_empty()
            || operands.len() < 3
            || operands[..2] != ["snapshot", "delete"]
            || operands[2..].iter().any(|id| id.is_empty())
        {
            backup_boundary(
                builder,
                node,
                "kopia arguments are outside snapshot deletion coverage",
            );
            return;
        }
        let mut resource_attrs = selection("snapshot", false, false);
        string(&mut resource_attrs, "backup_action", "delete_snapshot");
        let affected = logical_backup_resource(&mut resource_attrs, "filesystem");
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            BoundaryScope::Invocation,
            &["environment", "filesystem", "cloud", "network"],
            None,
            "kopia repository backend requires runtime configuration",
        );
        for snapshot in &operands[2..] {
            let mut attrs = resource_attrs.clone();
            string(&mut attrs, "snapshot", snapshot);
            arg_effect(
                builder,
                ctx,
                node,
                0,
                "filesystem.delete",
                affected.clone(),
                attrs,
            );
        }
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::LIVE_INVENTORY,
            BoundaryScope::Environment,
            &["filesystem", "cloud", "network"],
            None,
            "kopia snapshot contents and removed physical objects require live repository inventory",
        );
    }
}

// The value options of `expire` that select the stanza, the repository, the
// backup set and the configuration and log locations. `--dry-run` stays
// outside coverage, since it expires nothing.
const PGBACKREST_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--repo",
        "--stanza",
        "--set",
        "--config",
        "--config-path",
        "--config-include-path",
        "--log-level-console",
        "--log-level-file",
        "--log-level-stderr",
        "--log-path",
        "--lock-path",
    ],
    known_flags: &[],
};

struct PgBackRest;
impl CommandModel for PgBackRest {
    fn id(&self) -> &'static str {
        "pgbackrest/expire@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["pgbackrest"]
    }
    fn domains(&self) -> &'static [&'static str] {
        DOMAINS
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let node = reviewed_source_node(builder, ctx, node, PGBACKREST_SOURCE);
        let scanned = scan(ctx.argv, &PGBACKREST_SPEC);
        let command = scanned
            .operands
            .first()
            .and_then(|(_, word)| word.as_literal());
        let repo = scanned_option_value(&scanned, &["--repo"]);
        if !valid_options(ctx, &scanned, &PGBACKREST_SPEC, &[])
            || scanned.operands.len() != 1
            || command != Some("expire")
            || repo.is_some_and(|value| {
                value
                    .parse::<u16>()
                    .map_or(true, |number| number == 0 || number > 256)
            })
        {
            backup_boundary(
                builder,
                node,
                "pgBackRest arguments are outside repository expiration coverage",
            );
            return;
        }
        let mut resource_attrs = selection("retention", false, false);
        string(&mut resource_attrs, "backup_action", "delete_backup");
        let affected = logical_backup_resource(&mut resource_attrs, "filesystem");
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::ENVIRONMENT_CONFIGURATION,
            BoundaryScope::Invocation,
            &["environment", "filesystem", "cloud", "network"],
            None,
            "pgBackRest repository path and retention policy require runtime configuration",
        );
        // Without `--repo`, expire runs against every configured repository.
        let mut attrs = resource_attrs;
        if let Some(repo) = repo {
            string(&mut attrs, "repository_index", repo);
        }
        arg_effect(
            builder,
            ctx,
            node,
            0,
            "filesystem.delete",
            affected.clone(),
            attrs,
        );
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::LIVE_INVENTORY,
            BoundaryScope::Environment,
            &["filesystem", "cloud", "network"],
            None,
            "pgBackRest expired backups and physical repository objects require live inventory",
        );
    }
}

const DUPLICITY_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--archive-dir",
        "--name",
        "--time-separator",
        "--num-retries",
        "--verbosity",
        "-v",
    ],
    known_flags: &["--force", "--dry-run", "-h", "--help", "--version"],
};

/// duplicity `remove-older-than TIME URL` and `remove-all[-inc-of]-but-n-full
/// COUNT URL` delete whole backup sets from the target backend.
struct Duplicity;
impl CommandModel for Duplicity {
    fn id(&self) -> &'static str {
        "duplicity/backup@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["duplicity"]
    }
    fn domains(&self) -> &'static [&'static str] {
        DOMAINS
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let scanned = scan(ctx.argv, &DUPLICITY_SPEC);
        if !valid_options(ctx, &scanned, &DUPLICITY_SPEC, &[]) {
            backup_boundary(
                builder,
                node,
                "duplicity options or operands are unknown, invalid or incomplete",
            );
            return;
        }
        if scanned.has(&["-h", "--help", "--version"]) {
            backup_boundary(
                builder,
                node,
                "duplicity informational invocation; output effects are not enumerated",
            );
            return;
        }
        let operands = scanned
            .operands
            .iter()
            .map(|(_, word)| word.as_literal().unwrap())
            .collect::<Vec<_>>();
        let [command, retention, target] = operands.as_slice() else {
            backup_boundary(
                builder,
                node,
                "duplicity command is outside backup-set removal coverage",
            );
            return;
        };
        let retained = match *command {
            "remove-older-than" => duplicity_interval(retention),
            "remove-all-but-n-full" | "remove-all-inc-of-but-n-full" => {
                retention.parse::<u64>().is_ok_and(|count| count > 0)
            }
            _ => {
                backup_boundary(
                    builder,
                    node,
                    "duplicity command is outside backup-set removal coverage",
                );
                return;
            }
        };
        if !retained {
            backup_boundary(
                builder,
                node,
                "duplicity retention selector is not an established interval or count",
            );
            return;
        }
        // Removal reports the backup sets it would delete until --force.
        if !scanned.has(&["--force"]) || scanned.has(&["--dry-run"]) {
            reviewed_boundary(
                builder,
                node,
                "duplicity removal without --force only reports the backup sets it would delete",
            );
            return;
        }
        let Some((provider, rest)) = target.split_once("://").and_then(|(scheme, rest)| {
            match scheme {
                "s3" => Some("aws"),
                "gs" => Some("gcp"),
                _ => None,
            }
            .map(|provider| (provider, rest))
        }) else {
            backup_boundary(
                builder,
                node,
                "duplicity backup target backend is not modeled",
            );
            return;
        };
        let (bucket, key) = match rest.split_once('/') {
            Some((bucket, key)) if !key.is_empty() => (bucket, Some(key.to_string())),
            _ => (rest.trim_end_matches('/'), None),
        };
        if bucket.is_empty() {
            backup_boundary(builder, node, "duplicity backup target has no bucket");
            return;
        }
        let mut attrs = selection("retention", false, false);
        string(&mut attrs, "backup_action", "delete_backup_set");
        string(&mut attrs, "repository", target);
        string(&mut attrs, "retention", retention);
        string(&mut attrs, "provider", provider);
        string(&mut attrs, "bucket", bucket);
        if let Some(key) = key.as_deref() {
            string(&mut attrs, "key_prefix", key);
        }
        string(&mut attrs, "logical_resource_kind", "backup_selection");
        arg_effect(
            builder,
            ctx,
            node,
            0,
            "cloud.object.delete",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::ObjectStore {
                    scope: Box::new(effinterp_proto::object_scope(Some(provider))),
                    provider: Some(provider.into()),
                    bucket: bucket.into(),
                    key,
                },
            },
            attrs,
        );
        unresolved_boundary(
            builder,
            node,
            BoundaryReason::LIVE_INVENTORY,
            BoundaryScope::Environment,
            &["filesystem", "cloud", "network"],
            None,
            "duplicity removes whole backup sets; the volumes they hold are not enumerated",
        );
    }
}

/// duplicity intervals are runs of `<count><unit>` over s, m, h, D, W, M and Y.
fn duplicity_interval(value: &str) -> bool {
    if value == "now" {
        return true;
    }
    let mut rest = value;
    let mut units = 0;
    while !rest.is_empty() {
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits == 0 {
            return false;
        }
        rest = &rest[digits..];
        let Some(unit) = rest.chars().next().filter(|unit| "smhDWMY".contains(*unit)) else {
            return false;
        };
        rest = &rest[unit.len_utf8()..];
        units += 1;
    }
    units > 0
}

fn dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c))
}

fn equality_selector(s: &str) -> bool {
    s.is_empty()
        || s.split(',').all(|part| {
            part.split_once('=').is_some_and(|(key, value)| {
                let valid_key = key.split_once('/').map_or_else(
                    || label(key),
                    |(prefix, name)| dns_name(prefix) && label(name),
                );
                valid_key && (value.is_empty() || label(value))
            })
        })
}

fn borg_count_name(name: &str) -> &str {
    match name {
        "--keep-secondly" => "--keep-last",
        "-H" => "--keep-hourly",
        "-d" => "--keep-daily",
        "-w" => "--keep-weekly",
        "-m" => "--keep-monthly",
        "-y" => "--keep-yearly",
        _ => name,
    }
}

fn archive_name(s: &str, v2: bool) -> bool {
    !s.is_empty()
        && !s.contains(['/', '{', '}', '\0'])
        && !s.contains("::")
        && (!v2
            || (s.chars().count() <= 200
                && !s.starts_with(' ')
                && !s.ends_with(' ')
                && !s.chars().any(|c| c < ' ' || "\\\"<|>?*".contains(c))))
}
