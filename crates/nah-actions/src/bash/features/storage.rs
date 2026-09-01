//! Classifies reviewed remote-storage and backup deletion commands.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::shell_word::static_word;

pub(crate) struct Classification {
    pub(crate) complete: bool,
    pub(crate) system_state: Option<SemanticCode>,
}

impl Classification {
    const fn operation(system_state: SemanticCode) -> Self {
        Self {
            complete: true,
            system_state: Some(system_state),
        }
    }

    const fn control() -> Self {
        Self {
            complete: true,
            system_state: None,
        }
    }

    const fn incomplete() -> Self {
        Self {
            complete: false,
            system_state: None,
        }
    }
}

pub(crate) fn classify(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Word)],
    path_overridden: bool,
    qualified_program: bool,
) -> Option<Classification> {
    if !storage_program(program) {
        return None;
    }
    if !qualified_program && (path_overridden || assignments.iter().any(|(name, _)| name == "PATH"))
    {
        return Some(Classification::incomplete());
    }
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete());
    };
    Some(match program {
        "aws" => aws(&arguments),
        "gcloud" => gcloud(&arguments),
        "gsutil" => gsutil(&arguments),
        "az" => az(&arguments),
        "azcopy" => azcopy(&arguments),
        "rclone" => rclone(&arguments),
        "rsync" => rsync(&arguments),
        "zfs" => zfs(&arguments),
        "btrfs" => btrfs(&arguments),
        "restic" => restic(&arguments),
        "borg" => borg(&arguments),
        "duplicity" => duplicity(&arguments),
        "velero" => velero(&arguments),
        _ => unreachable!("storage programs are matched above"),
    })
}

fn storage_program(program: &str) -> bool {
    matches!(
        program,
        "aws"
            | "gcloud"
            | "gsutil"
            | "az"
            | "azcopy"
            | "rclone"
            | "rsync"
            | "zfs"
            | "btrfs"
            | "restic"
            | "borg"
            | "duplicity"
            | "velero"
    )
}

fn aws(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &[
            "--debug",
            "--delete",
            "--dry-run",
            "--dryrun",
            "--exact-timestamps",
            "--force",
            "--follow-symlinks",
            "--help",
            "--no-cli-pager",
            "--no-follow-symlinks",
            "--no-progress",
            "--no-sign-request",
            "--only-show-errors",
            "--quiet",
            "--recursive",
            "--size-only",
            "--version",
        ],
        &[
            "--bucket",
            "--ca-bundle",
            "--cli-binary-format",
            "--cli-connect-timeout",
            "--cli-read-timeout",
            "--endpoint-url",
            "--exclude",
            "--include",
            "--output",
            "--page-size",
            "--profile",
            "--query",
            "--region",
            "--snapshot-id",
            "--volume-id",
        ],
        "",
        "",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    let positions = parsed.positionals();
    match positions {
        [service, command, target]
            if service == "s3" && command == "rb" && target.starts_with("s3://") =>
        {
            if parsed.flag("--force") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [service, command, target]
            if service == "s3" && command == "rm" && target.starts_with("s3://") =>
        {
            if parsed.safe_selection() {
                Classification::control()
            } else if parsed.flag("--recursive") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [service, command, _, _] if service == "s3" && command == "sync" => {
            if parsed.safe_selection() {
                Classification::control()
            } else if parsed.flag("--delete") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [service, command]
            if service == "ec2"
                && command == "delete-snapshot"
                && parsed.value("--snapshot-id").is_some() =>
        {
            if parsed.flag("--dry-run") {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            }
        }
        [service, command]
            if service == "ec2"
                && command == "delete-volume"
                && parsed.value("--volume-id").is_some() =>
        {
            if parsed.flag("--dry-run") {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            }
        }
        [service, command, ..]
            if (service == "s3api"
                && matches!(
                    command.as_str(),
                    "delete-bucket" | "delete-objects" | "put-bucket-replication"
                ))
                || (service == "ec2" && command == "deregister-image") =>
        {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

fn gcloud(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &[
            "--delete-unmatched-destination-objects",
            "--dry-run",
            "--help",
            "--quiet",
            "--recursive",
            "--version",
        ],
        &[
            "--account",
            "--configuration",
            "--exclude",
            "--filter",
            "--format",
            "--include",
            "--project",
            "--region",
            "--zone",
        ],
        "qrR",
        "",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    let positions = parsed.positionals();
    match positions {
        [storage, command, target]
            if storage == "storage" && command == "rm" && target.starts_with("gs://") =>
        {
            if parsed.safe_selection() {
                Classification::control()
            } else if parsed.any_flag(&["--recursive", "-r", "-R"]) {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [storage, command, _, _] if storage == "storage" && command == "rsync" => {
            if parsed.safe_selection() {
                Classification::control()
            } else if parsed.flag("--delete-unmatched-destination-objects") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [storage, buckets, delete, ..]
            if storage == "storage" && buckets == "buckets" && delete == "delete" =>
        {
            Classification::control()
        }
        [compute, resource, delete, names @ ..]
            if compute == "compute"
                && matches!(resource.as_str(), "snapshots" | "disks")
                && delete == "delete"
                && !names.is_empty() =>
        {
            if parsed.flag("--dry-run") || parsed.has_value(&["--filter"]) {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            }
        }
        _ => Classification::incomplete(),
    }
}

fn gsutil(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(arguments, &["--help", "--version"], &[], "mqrRdn", "ouix")
    else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    let positions = parsed.positionals();
    match positions {
        [command, target] if command == "rm" && target.starts_with("gs://") => {
            if parsed.any_flag(&["-n"]) || parsed.value("-x").is_some() {
                Classification::control()
            } else if parsed.any_flag(&["-r", "-R"]) {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [command, _, _] if command == "rsync" => {
            if parsed.any_flag(&["-n"]) || parsed.value("-x").is_some() {
                Classification::control()
            } else if parsed.flag("-d") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [command, ..] if command == "rb" => Classification::control(),
        _ => Classification::incomplete(),
    }
}

fn az(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &["--help", "--yes", "--version"],
        &[
            "--account-key",
            "--account-name",
            "--connection-string",
            "--container-name",
            "--name",
            "--output",
            "--pattern",
            "--resource-group",
            "--sas-token",
            "--source",
            "--subscription",
        ],
        "hy",
        "gno",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    let positions = parsed.positionals();
    match positions {
        [storage, container, delete]
            if storage == "storage"
                && container == "container"
                && delete == "delete"
                && parsed.has_value(&["--name", "--container-name", "-n"]) =>
        {
            Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
        }
        [storage, account, delete]
            if storage == "storage"
                && account == "account"
                && delete == "delete"
                && parsed.has_value(&["--name", "-n"]) =>
        {
            Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
        }
        [storage, blob, delete]
            if storage == "storage"
                && blob == "blob"
                && delete == "delete-batch"
                && parsed.has_value(&["--source", "--container-name"]) =>
        {
            if parsed.value("--pattern").is_some() {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            }
        }
        [resource, delete]
            if matches!(resource.as_str(), "snapshot" | "disk")
                && delete == "delete"
                && parsed.has_value(&["--name", "-n"]) =>
        {
            Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
        }
        _ => Classification::incomplete(),
    }
}

fn azcopy(arguments: &[String]) -> Classification {
    let arguments = arguments
        .iter()
        .map(|argument| {
            if argument == "--recursive" {
                "--recursive=true".to_owned()
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>();
    let Ok(parsed) = parse_options(
        &arguments,
        &["--dry-run", "--help", "--version"],
        &[
            "--delete-destination",
            "--exclude-path",
            "--exclude-pattern",
            "--include-path",
            "--include-pattern",
            "--list-of-files",
            "--log-level",
            "--recursive",
        ],
        "h",
        "",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    let narrowed = parsed.has_value(&[
        "--exclude-path",
        "--exclude-pattern",
        "--include-path",
        "--include-pattern",
        "--list-of-files",
    ]);
    match parsed.positionals() {
        [command, _, _] if command == "sync" => {
            if parsed.flag("--dry-run") || narrowed {
                Classification::control()
            } else if parsed.value("--delete-destination") == Some("true") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        [command, _] if command == "rm" => {
            if parsed.flag("--dry-run") || narrowed {
                Classification::control()
            } else if parsed.value("--recursive") == Some("true") {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            } else {
                Classification::control()
            }
        }
        _ => Classification::incomplete(),
    }
}

fn rclone(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &[
            "--backup",
            "--checksum",
            "--dry-run",
            "--dryrun",
            "--fast-list",
            "--help",
            "--ignore-existing",
            "--immutable",
            "--interactive",
            "--progress",
            "--quiet",
            "--verbose",
            "--version",
        ],
        &[
            "--backup-dir",
            "--checkers",
            "--config",
            "--exclude",
            "--exclude-from",
            "--files-from",
            "--filter",
            "--filter-from",
            "--include",
            "--include-from",
            "--log-file",
            "--log-level",
            "--max-age",
            "--max-size",
            "--min-age",
            "--min-size",
            "--transfers",
        ],
        "hinPqv",
        "",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    let safe = parsed.any_flag(&[
        "--backup",
        "--dry-run",
        "--dryrun",
        "--interactive",
        "-i",
        "-n",
    ]) || parsed.has_value(&[
        "--backup-dir",
        "--exclude",
        "--exclude-from",
        "--files-from",
        "--filter",
        "--filter-from",
        "--include",
        "--include-from",
        "--max-age",
        "--max-size",
        "--min-age",
        "--min-size",
    ]);
    match parsed.positionals() {
        [command, _] if matches!(command.as_str(), "purge" | "delete") => {
            if safe {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            }
        }
        [command, _, _] if command == "sync" => {
            if safe {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
            }
        }
        [command, ..]
            if matches!(
                command.as_str(),
                "copy" | "move" | "copyto" | "deletefile" | "rmdir" | "rmdirs"
            ) =>
        {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

fn rsync(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &[
            "--archive",
            "--backup",
            "--checksum",
            "--compress",
            "--del",
            "--delete",
            "--delete-after",
            "--delete-before",
            "--delete-delay",
            "--delete-during",
            "--delete-excluded",
            "--dry-run",
            "--help",
            "--ignore-existing",
            "--itemize-changes",
            "--links",
            "--partial",
            "--progress",
            "--quiet",
            "--recursive",
            "--remove-source-files",
            "--stats",
            "--verbose",
            "--version",
        ],
        &[
            "--backup-dir",
            "--bwlimit",
            "--exclude",
            "--exclude-from",
            "--filter",
            "--include",
            "--include-from",
            "--info",
            "--max-delete",
            "--password-file",
            "--port",
            "--rsh",
            "--timeout",
        ],
        "abchlnopqrtuvxzDH",
        "e",
    ) else {
        return Classification::incomplete();
    };
    if parsed.any_flag(&["--help", "--version"]) {
        return Classification::control();
    }
    if parsed.positionals().len() < 2 {
        return Classification::incomplete();
    }
    let safe = parsed.any_flag(&["--backup", "--dry-run", "-b", "-n"])
        || parsed.has_value(&[
            "--backup-dir",
            "--exclude",
            "--exclude-from",
            "--filter",
            "--include",
            "--include-from",
        ]);
    if safe {
        return Classification::control();
    }
    if parsed.any_flag(&[
        "--del",
        "--delete",
        "--delete-after",
        "--delete-before",
        "--delete-delay",
        "--delete-during",
        "--delete-excluded",
    ]) {
        Classification::operation(SemanticCode::STORAGE_RECURSIVE_DELETE)
    } else {
        Classification::control()
    }
}

fn zfs(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_zfs(arguments) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals() {
        [command, target] if command == "destroy" && target.contains('@') && !parsed.flag("-n") => {
            Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
        }
        [command, target]
            if command == "rollback" && target.contains('@') && parsed.any_flag(&["-r", "-R"]) =>
        {
            Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
        }
        [command, ..]
            if matches!(
                command.as_str(),
                "destroy" | "rollback" | "snapshot" | "send" | "receive"
            ) =>
        {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

pub(crate) fn zfs_live_dataset_destroy(arguments: &[Word]) -> bool {
    let Some(arguments) = static_arguments(arguments) else {
        return false;
    };
    let Ok(parsed) = parse_zfs(&arguments) else {
        return false;
    };
    matches!(parsed.positionals(), [command, target]
        if command == "destroy"
            && !target.contains(['@', '#'])
            && !parsed.any_flag(&["-n", "--help", "--version"]))
}

fn parse_zfs(arguments: &[String]) -> Result<ParsedOptions, ()> {
    parse_options(arguments, &["--help", "--version"], &[], "dfnpRrv", "")
}

fn btrfs(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(arguments, &["--help", "--version"], &[], "cCqv", "") else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals() {
        [group, command, targets @ ..]
            if group == "subvolume" && command == "delete" && !targets.is_empty() =>
        {
            Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
        }
        [group, command, ..]
            if (group == "subvolume" && command == "snapshot") || group == "send" =>
        {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

fn restic(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options_with_boolean_flags(
        arguments,
        &[],
        &[
            "--dry-run",
            "--help",
            "--json",
            "--no-lock",
            "--prune",
            "--unsafe-allow-remove-all",
            "--verbose",
            "--version",
        ],
        &[
            "--cache-dir",
            "--group-by",
            "--host",
            "--keep-daily",
            "--keep-hourly",
            "--keep-last",
            "--keep-monthly",
            "--keep-tag",
            "--keep-weekly",
            "--keep-within",
            "--keep-within-daily",
            "--keep-within-hourly",
            "--keep-within-monthly",
            "--keep-within-weekly",
            "--keep-within-yearly",
            "--keep-yearly",
            "--option",
            "--password-file",
            "--repo",
            "--repository-file",
            "--tag",
        ],
        "hqv",
        "opr",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals() {
        [command, snapshots @ ..] if command == "forget" => {
            if parsed.flag("--dry-run") {
                Classification::control()
            } else if parsed.flag("--unsafe-allow-remove-all") {
                Classification::operation(SemanticCode::STORAGE_DESTROY)
            } else if !snapshots.is_empty() || parsed.has_prefix_value("--keep-") {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            } else {
                Classification::incomplete()
            }
        }
        [command, ..] if matches!(command.as_str(), "backup" | "prune") => {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

fn borg(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &[
            "--cache-only",
            "--confirm",
            "--dry-run",
            "--force",
            "--help",
            "--list",
            "--log-json",
            "--progress",
            "--show-rc",
            "--show-version",
            "--stats",
            "--verbose",
            "--version",
            "--yes",
        ],
        &[
            "--glob-archives",
            "--keep-daily",
            "--keep-hourly",
            "--keep-last",
            "--keep-monthly",
            "--keep-weekly",
            "--keep-within",
            "--keep-yearly",
            "--lock-wait",
            "--match-archives",
            "--remote-path",
            "--repo",
            "--rsh",
            "--umask",
        ],
        "fhlnvy",
        "ar",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals() {
        [command, operands @ ..] if command == "repo-delete" => {
            if operands.is_empty() {
                Classification::operation(SemanticCode::STORAGE_DESTROY)
            } else {
                Classification::incomplete()
            }
        }
        [command, operands @ ..] if command == "delete" => {
            if parsed.any_flag(&["--cache-only", "--dry-run"]) {
                Classification::control()
            } else if parsed.has_value(&["--glob-archives", "--match-archives", "-a"])
                || operands.iter().any(|operand| operand.contains("::"))
                || parsed.has_value(&["--repo", "-r"])
                    && matches!(operands, [archive] if !archive.is_empty())
            {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            } else if matches!(operands, [repository] if !repository.is_empty()) {
                Classification::operation(SemanticCode::STORAGE_DESTROY)
            } else {
                Classification::incomplete()
            }
        }
        [command, ..] if command == "prune" => {
            if parsed.any_flag(&["--dry-run", "--list", "-n", "-l"]) {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            }
        }
        [command, ..] if matches!(command.as_str(), "compact" | "create") => {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

fn duplicity(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options(
        arguments,
        &["--dry-run", "--force", "--help", "--version"],
        &[
            "--archive-dir",
            "--backend-retry-delay",
            "--file-prefix",
            "--name",
            "--num-retries",
            "--time-separator",
        ],
        "h",
        "",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals() {
        [command, operands @ ..]
            if matches!(
                command.as_str(),
                "remove-older-than" | "remove-all-but-n-full" | "remove-all-inc-of-but-n-full"
            ) && operands.len() >= 2 =>
        {
            if parsed.flag("--dry-run") || !parsed.flag("--force") {
                Classification::control()
            } else {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            }
        }
        _ => Classification::incomplete(),
    }
}

fn velero(arguments: &[String]) -> Classification {
    let Ok(parsed) = parse_options_with_boolean_flags(
        arguments,
        &[],
        &["--all", "--confirm", "--help", "--version", "--yes"],
        &[
            "--context",
            "--kubeconfig",
            "--kubecontext",
            "--namespace",
            "--selector",
        ],
        "hy",
        "n",
    ) else {
        return Classification::incomplete();
    };
    if parsed.non_executing() {
        return Classification::control();
    }
    match parsed.positionals() {
        [backup, delete, names @ ..] if backup == "backup" && delete == "delete" => {
            if parsed.flag("--all") {
                Classification::operation(SemanticCode::STORAGE_DESTROY)
            } else if !names.is_empty() || parsed.value("--selector").is_some() {
                Classification::operation(SemanticCode::STORAGE_SNAPSHOT_DELETE)
            } else {
                Classification::incomplete()
            }
        }
        [resource, delete, ..]
            if delete == "delete" && matches!(resource.as_str(), "backup-location" | "restore") =>
        {
            Classification::control()
        }
        _ => Classification::incomplete(),
    }
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}

#[derive(Default)]
struct ParsedOptions {
    positionals: Vec<String>,
    flags: Vec<String>,
    values: Vec<(String, String)>,
}

impl ParsedOptions {
    fn positionals(&self) -> &[String] {
        &self.positionals
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|candidate| candidate == name)
    }

    fn any_flag(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.flag(name))
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    fn has_value(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.value(name).is_some())
    }

    fn has_prefix_value(&self, prefix: &str) -> bool {
        self.values.iter().any(|(name, _)| name.starts_with(prefix))
    }

    fn non_executing(&self) -> bool {
        self.any_flag(&["--help", "--version", "-h"])
    }

    fn safe_selection(&self) -> bool {
        self.any_flag(&["--dry-run", "--dryrun"])
            || self.has_value(&["--exclude", "--filter", "--include"])
    }
}

fn parse_options(
    arguments: &[String],
    long_flags: &[&str],
    long_values: &[&str],
    short_flags: &str,
    short_values: &str,
) -> Result<ParsedOptions, ()> {
    parse_options_with_boolean_flags(
        arguments,
        long_flags,
        &[],
        long_values,
        short_flags,
        short_values,
    )
}

fn parse_options_with_boolean_flags(
    arguments: &[String],
    long_flags: &[&str],
    long_boolean_flags: &[&str],
    long_values: &[&str],
    short_flags: &str,
    short_values: &str,
) -> Result<ParsedOptions, ()> {
    let mut parsed = ParsedOptions::default();
    let mut index = 0;
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument.starts_with("--") {
            let (name, attached) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(name, value)| {
                    (name, Some(value))
                });
            if long_boolean_flags.contains(&name) {
                let enabled = attached.map_or(Some(true), parse_go_bool).ok_or(())?;
                if enabled {
                    parsed.flags.push(name.to_owned());
                }
                index += 1;
                continue;
            }
            if long_flags.contains(&name) {
                if attached.is_some() {
                    return Err(());
                }
                parsed.flags.push(name.to_owned());
                index += 1;
                continue;
            }
            if long_values.contains(&name) {
                let value = if let Some(value) = attached {
                    value
                } else {
                    index += 1;
                    arguments.get(index).map(String::as_str).ok_or(())?
                };
                if value.is_empty() {
                    return Err(());
                }
                parsed.values.push((name.to_owned(), value.to_owned()));
                index += 1;
                continue;
            }
            return Err(());
        }
        if options && argument.starts_with('-') && argument != "-" {
            let cluster = argument.strip_prefix('-').ok_or(())?;
            if cluster.is_empty() {
                parsed.positionals.push(argument.clone());
                index += 1;
                continue;
            }
            let mut characters = cluster.char_indices().peekable();
            while let Some((_, flag)) = characters.next() {
                if short_flags.contains(flag) {
                    parsed.flags.push(format!("-{flag}"));
                    continue;
                }
                if short_values.contains(flag) {
                    let value_start = characters
                        .peek()
                        .map_or(cluster.len(), |(offset, _)| *offset);
                    let attached = cluster[value_start..]
                        .strip_prefix('=')
                        .unwrap_or(&cluster[value_start..]);
                    let value = if attached.is_empty() {
                        index += 1;
                        arguments.get(index).map(String::as_str).ok_or(())?
                    } else {
                        attached
                    };
                    if value.is_empty() {
                        return Err(());
                    }
                    parsed.values.push((format!("-{flag}"), value.to_owned()));
                    break;
                }
                return Err(());
            }
            index += 1;
            continue;
        }
        if argument.is_empty() {
            return Err(());
        }
        parsed.positionals.push(argument.clone());
        index += 1;
    }
    Ok(parsed)
}

fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}
