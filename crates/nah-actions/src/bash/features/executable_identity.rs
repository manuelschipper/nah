//! Tracks visible nah executable identity across exact same-call file aliases.

use std::collections::{BTreeMap, BTreeSet};

use nah_proto::action::{FilesystemOperation, SemanticCode};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::{
    Observation, ObservationFailure, ObservationValue, Observed, PathKind, PathObservation,
};

use crate::bash_model::{FilesystemDraft, InvocationDraft, ProgramDraft, StageDraft};
use crate::bash_self_protection::{
    operation_for_values, potential_operation_for_words, protected_path,
};
use crate::paths::{contains, join, resolve_from_cwd};

pub(crate) fn reclassify(
    stages: &mut [StageDraft],
    observation: &Observation,
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let mut aliases = BTreeSet::new();
    let mut tool_aliases = BTreeMap::<String, String>::new();
    let mut invalidations = Vec::new();
    let mut deterministic = true;

    for stage in stages {
        if let Some(tool) = direct_alias_tool(stage, &tool_aliases, home, platform)
            && tool == "rm"
            && alias_rm_mutates_protected(stage, home, critical_paths, platform)
        {
            reclassify_alias_tool(stage, &tool);
        }
        let direct_program = direct_program(&stage.invocation, platform).map(str::to_owned);
        let direct_is_nah = direct_program.is_some()
            && direct_file_is_nah(stage, observation, home, platform, &aliases, &invalidations);
        if direct_is_nah && let Some(operation) = mutation_operation(&stage.invocation) {
            let (words, argv) = invocation_input(&stage.invocation);
            let argv = argv.map(|argv| {
                let mut argv = argv.to_vec();
                if let Some(program) = argv.first_mut() {
                    *program = "nah".to_owned();
                }
                argv
            });
            stage.invocation = InvocationDraft::Known {
                program: "nah".to_owned(),
                operation: SemanticCode::new(operation)
                    .expect("self-protection operations are validated constants"),
                words: words.to_vec(),
                argv,
            };
        }

        let transfer = exact_transfer(stage, observation, platform);
        let source_is_nah = transfer.as_ref().is_some_and(|transfer| {
            let source = transfer.source;
            aliases.contains(&identity_key(&source.requested, platform))
                || observed_nah_file(source, observation, platform)
        });
        let source_tool = transfer.as_ref().and_then(|transfer| {
            tool_aliases
                .get(&identity_key(&transfer.source.requested, platform))
                .cloned()
                .or_else(|| observed_standard_tool(transfer.source, observation, platform))
        });

        for filesystem in &stage.filesystems {
            if stage.conditional_depth > 0 {
                continue;
            }
            if transfer.as_ref().is_some_and(|transfer| {
                std::ptr::eq(filesystem, transfer.source)
                    || std::ptr::eq(filesystem, transfer.target)
            }) {
                continue;
            }
            if !matches!(
                filesystem.operation,
                FilesystemOperation::Write | FilesystemOperation::Delete
            ) {
                continue;
            }
            record_mutation(
                &mut aliases,
                &mut tool_aliases,
                &mut invalidations,
                filesystem,
                observation,
                platform,
            );
        }

        if let Some(transfer) = transfer {
            match transfer.disposition {
                TransferDisposition::Replace if stage.conditional_depth > 0 => {
                    if source_is_nah {
                        aliases.insert(identity_key(&transfer.target.requested, platform));
                    }
                    if let Some(tool) = &source_tool {
                        tool_aliases.insert(
                            identity_key(&transfer.target.requested, platform),
                            tool.clone(),
                        );
                    }
                }
                TransferDisposition::Replace => {
                    if transfer.follows_target_symlink {
                        record_mutation(
                            &mut aliases,
                            &mut tool_aliases,
                            &mut invalidations,
                            transfer.target,
                            observation,
                            platform,
                        );
                    } else {
                        record_requested_mutation(
                            &mut aliases,
                            &mut tool_aliases,
                            &mut invalidations,
                            transfer.target,
                            platform,
                        );
                    }
                    if transfer.moved {
                        record_mutation(
                            &mut aliases,
                            &mut tool_aliases,
                            &mut invalidations,
                            transfer.source,
                            observation,
                            platform,
                        );
                    }
                    if source_is_nah {
                        aliases.insert(identity_key(&transfer.target.requested, platform));
                    }
                    if let Some(tool) = &source_tool {
                        tool_aliases.insert(
                            identity_key(&transfer.target.requested, platform),
                            tool.clone(),
                        );
                    }
                }
                TransferDisposition::MaybeReplace => {
                    deterministic = false;
                    if source_is_nah {
                        aliases.insert(identity_key(&transfer.target.requested, platform));
                    }
                    if let Some(tool) = &source_tool {
                        tool_aliases.insert(
                            identity_key(&transfer.target.requested, platform),
                            tool.clone(),
                        );
                    }
                }
                TransferDisposition::Preserve => {}
                TransferDisposition::Nested if stage.conditional_depth == 0 => {
                    if transfer.moved {
                        record_mutation(
                            &mut aliases,
                            &mut tool_aliases,
                            &mut invalidations,
                            transfer.source,
                            observation,
                            platform,
                        );
                    }
                }
                TransferDisposition::Nested => {}
            }
        }
    }
    deterministic
}

fn record_mutation(
    aliases: &mut BTreeSet<String>,
    tool_aliases: &mut BTreeMap<String, String>,
    invalidations: &mut Vec<(String, bool)>,
    filesystem: &FilesystemDraft,
    observation: &Observation,
    platform: Platform,
) {
    clear_path(
        aliases,
        &filesystem.requested,
        filesystem.recursive,
        platform,
    );
    clear_tool_path(
        tool_aliases,
        &filesystem.requested,
        filesystem.recursive,
        platform,
    );
    invalidations.push((
        identity_key(&filesystem.requested, platform),
        filesystem.recursive,
    ));
    if let Some(path) = observed_path(filesystem, observation).and_then(Result::ok) {
        let target = observed_target(filesystem, path);
        clear_path(aliases, target.as_str(), filesystem.recursive, platform);
        clear_tool_path(
            tool_aliases,
            target.as_str(),
            filesystem.recursive,
            platform,
        );
        invalidations.push((
            identity_key(target.as_str(), platform),
            filesystem.recursive,
        ));
    }
}

fn record_requested_mutation(
    aliases: &mut BTreeSet<String>,
    tool_aliases: &mut BTreeMap<String, String>,
    invalidations: &mut Vec<(String, bool)>,
    filesystem: &FilesystemDraft,
    platform: Platform,
) {
    clear_path(
        aliases,
        &filesystem.requested,
        filesystem.recursive,
        platform,
    );
    clear_tool_path(
        tool_aliases,
        &filesystem.requested,
        filesystem.recursive,
        platform,
    );
    invalidations.push((
        identity_key(&filesystem.requested, platform),
        filesystem.recursive,
    ));
}

fn direct_file_is_nah(
    stage: &StageDraft,
    observation: &Observation,
    home: &AbsolutePath,
    platform: Platform,
    aliases: &BTreeSet<String>,
    invalidations: &[(String, bool)],
) -> bool {
    let Some(program) = direct_program(&stage.invocation, platform) else {
        return false;
    };
    let Some(requested) =
        requested_program_path(program, stage.invocation_cwd.as_deref(), home, platform)
    else {
        return false;
    };
    let Some(executable) = stage.filesystems.iter().find(|filesystem| {
        filesystem.operation == FilesystemOperation::Read
            && !filesystem.pattern
            && same_path(&filesystem.requested, &requested, platform)
    }) else {
        return false;
    };
    if aliases.contains(&identity_key(&executable.requested, platform)) {
        return true;
    }
    let Some(Ok(path)) = observed_path(executable, observation) else {
        return false;
    };
    let target = observed_target(executable, path);
    !invalidated(
        invalidations,
        &executable.requested,
        target.as_str(),
        platform,
    ) && observed_path_is_nah_file(path, platform)
}

fn direct_program(invocation: &InvocationDraft, platform: Platform) -> Option<&str> {
    match invocation {
        InvocationDraft::CodeExecution {
            program, source, ..
        } if source == &SemanticCode::DIRECT_FILE => Some(program),
        InvocationDraft::Known {
            program, operation, ..
        } if (operation == &SemanticCode::CRITICAL_MUTATION
            || operation == &SemanticCode::PERMANENT_MUTATION)
            && program.contains(['/', '\\'])
            && nah_executable_name(program, platform) =>
        {
            Some(program)
        }
        _ => None,
    }
}

fn mutation_operation(invocation: &InvocationDraft) -> Option<&'static str> {
    let (words, argv) = invocation_input(invocation);
    argv.and_then(|argv| operation_for_values("nah", argv.get(1..).unwrap_or_default()))
        .or_else(|| potential_operation_for_words("nah", words.get(1..).unwrap_or_default()))
}

fn invocation_input(invocation: &InvocationDraft) -> (&[String], Option<&[String]>) {
    match invocation {
        InvocationDraft::Opaque { words, argv, .. }
        | InvocationDraft::Known { words, argv, .. }
        | InvocationDraft::CodeExecution { words, argv, .. } => (words, argv.as_deref()),
        InvocationDraft::Native { .. } => (&[], None),
    }
}

fn direct_alias_tool(
    stage: &StageDraft,
    aliases: &BTreeMap<String, String>,
    home: &AbsolutePath,
    platform: Platform,
) -> Option<String> {
    let program = direct_program(&stage.invocation, platform)?;
    let requested =
        requested_program_path(program, stage.invocation_cwd.as_deref(), home, platform)?;
    aliases.get(&identity_key(&requested, platform)).cloned()
}

fn alias_rm_mutates_protected(
    stage: &StageDraft,
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
) -> bool {
    let (_, argv) = invocation_input(&stage.invocation);
    let Some(argv) = argv else {
        return false;
    };
    let Some(cwd) = stage.invocation_cwd.as_deref() else {
        return false;
    };
    let mut after_options = false;
    for argument in argv.iter().skip(1) {
        if !after_options && argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options && matches!(argument.as_str(), "--help" | "--version") {
            return false;
        }
        if !after_options && argument.starts_with('-') && argument != "-" {
            continue;
        }
        let Some(target) = resolve_from_cwd(
            Some(cwd),
            Some(cwd),
            argument,
            home.as_str(),
            platform,
            true,
        ) else {
            continue;
        };
        if protected_path(&target, home.as_str(), critical_paths, platform) {
            return true;
        }
    }
    false
}

fn reclassify_alias_tool(stage: &mut StageDraft, tool: &str) {
    let (words, argv) = invocation_input(&stage.invocation);
    let words = words.to_vec();
    let argv = argv.map(|argv| {
        let mut argv = argv.to_vec();
        if let Some(program) = argv.first_mut() {
            *program = tool.to_owned();
        }
        argv
    });
    stage.invocation = InvocationDraft::Known {
        program: tool.to_owned(),
        operation: SemanticCode::new("critical-mutation")
            .expect("self-protection operations are validated constants"),
        words,
        argv,
    };
}

fn observed_standard_tool(
    filesystem: &FilesystemDraft,
    observation: &Observation,
    platform: Platform,
) -> Option<String> {
    let path = observed_path(filesystem, observation).and_then(Result::ok)?;
    let file = path.kind() == PathKind::File
        || path.kind() == PathKind::Symlink && path.target_kind() == Some(PathKind::File);
    if !file {
        return None;
    }
    let target = identity_key(observed_target_path(path).as_str(), platform);
    matches!(target.as_str(), "/bin/rm" | "/usr/bin/rm").then(|| "rm".to_owned())
}

struct Transfer<'a> {
    source: &'a FilesystemDraft,
    target: &'a FilesystemDraft,
    moved: bool,
    follows_target_symlink: bool,
    disposition: TransferDisposition,
}

#[derive(Clone, Copy)]
enum TransferDisposition {
    Replace,
    MaybeReplace,
    Preserve,
    Nested,
}

fn exact_transfer<'a>(
    stage: &'a StageDraft,
    observation: &Observation,
    platform: Platform,
) -> Option<Transfer<'a>> {
    let program = invocation_program(&stage.invocation)?;
    let source_operation = match program {
        "cp" | "ln" | "link" => FilesystemOperation::Read,
        "mv" => FilesystemOperation::Delete,
        _ => return None,
    };
    let sources = stage
        .filesystems
        .iter()
        .filter(|filesystem| filesystem.operation == source_operation)
        .collect::<Vec<_>>();
    let targets = stage
        .filesystems
        .iter()
        .filter(|filesystem| filesystem.operation == FilesystemOperation::Write)
        .collect::<Vec<_>>();
    let ([source], [target]) = (sources.as_slice(), targets.as_slice()) else {
        return None;
    };
    if source.pattern
        || target.pattern
        || target.recursive
        || target.requested.ends_with(['/', '\\'])
        || program == "cp" && !source.content_access
    {
        return None;
    }
    if symbolic_link_creation(stage, program)
        && !symbolic_source_matches(stage, program, source, target, platform)
    {
        return None;
    }
    if program == "cp"
        && copy_preserves_symlink(stage)
        && !matches!(
            observed_path(source, observation).and_then(Result::ok),
            Some(path) if path.kind() == PathKind::File
        )
    {
        return None;
    }
    let target_path = observed_path(target, observation).and_then(Result::ok)?;
    let disposition = transfer_disposition(stage, program, target_path);
    Some(Transfer {
        source,
        target,
        moved: program == "mv",
        follows_target_symlink: program == "cp",
        disposition,
    })
}

fn symbolic_source_matches(
    stage: &StageDraft,
    program: &str,
    source: &FilesystemDraft,
    target: &FilesystemDraft,
    platform: Platform,
) -> bool {
    let Some(operand) = source_operand(stage, program) else {
        return false;
    };
    if let Ok(operand) = AbsolutePath::new(platform, operand) {
        return same_path(operand.as_str(), &source.requested, platform);
    }
    if program == "ln"
        && invocation_argv(stage)
            .is_some_and(|argv| has_short_flag(argv, 'r') || has_long_option(argv, "--relative"))
    {
        return true;
    }
    let Some(cwd) = stage.invocation_cwd.as_deref() else {
        return false;
    };
    path_parent(&target.requested, platform).is_some_and(|parent| same_path(parent, cwd, platform))
}

fn path_parent(path: &str, platform: Platform) -> Option<&str> {
    let separator = if platform == Platform::Windows {
        path.rfind(['/', '\\'])
    } else {
        path.rfind('/')
    }?;
    Some(if separator == 0 {
        &path[..1]
    } else {
        &path[..separator]
    })
}

fn symbolic_link_creation(stage: &StageDraft, program: &str) -> bool {
    match program {
        "cp" => invocation_argv(stage).is_some_and(|argv| {
            has_short_flag(argv, 's') || has_long_option(argv, "--symbolic-link")
        }),
        "ln" => invocation_argv(stage)
            .is_some_and(|argv| has_short_flag(argv, 's') || has_long_option(argv, "--symbolic")),
        _ => false,
    }
}

fn copy_preserves_symlink(stage: &StageDraft) -> bool {
    invocation_argv(stage).is_some_and(|argv| {
        ['a', 'd', 'P', 'r', 'R']
            .into_iter()
            .any(|option| has_short_flag(argv, option))
            || ["--archive", "--no-dereference"]
                .into_iter()
                .any(|option| has_long_option(argv, option))
    })
}

fn source_operand<'a>(stage: &'a StageDraft, program: &str) -> Option<&'a str> {
    let argv = invocation_argv(stage)?;
    let mut operands = Vec::new();
    let mut skip_next = false;
    let mut after_options = false;
    for argument in argv.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if !after_options && argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options && matches!(argument.as_str(), "-S" | "-t") {
            skip_next = true;
            continue;
        }
        if !after_options && matches!(argument.as_str(), "--suffix" | "--target-directory") {
            skip_next = true;
            continue;
        }
        if !after_options && argument.starts_with('-') && argument != "-" {
            continue;
        }
        operands.push(argument.as_str());
    }
    match program {
        "cp" | "ln" | "link" | "mv" => operands.first().copied(),
        _ => None,
    }
}

fn transfer_disposition(
    stage: &StageDraft,
    program: &str,
    target: &PathObservation,
) -> TransferDisposition {
    if target_directory_form(stage)
        || target.kind() == PathKind::Directory
        || target.kind() == PathKind::Symlink && target.target_kind() == Some(PathKind::Directory)
    {
        return TransferDisposition::Nested;
    }
    if target.kind() == PathKind::Missing {
        return TransferDisposition::Replace;
    }
    if !matches!(target.kind(), PathKind::File | PathKind::Symlink) {
        return TransferDisposition::Preserve;
    }
    match program {
        "cp" | "mv" if non_replacing_option(stage) => TransferDisposition::Preserve,
        "cp" | "mv" if optional_replacement(stage) => TransferDisposition::MaybeReplace,
        "ln" if interactive_option(stage) => TransferDisposition::MaybeReplace,
        "ln" if backup_option(stage) => TransferDisposition::Replace,
        "ln" if force_option(stage) => TransferDisposition::Replace,
        "ln" | "link" => TransferDisposition::Preserve,
        "cp" | "mv" => TransferDisposition::Replace,
        _ => TransferDisposition::Preserve,
    }
}

fn target_directory_form(stage: &StageDraft) -> bool {
    invocation_argv(stage).is_some_and(|argv| {
        argv.iter()
            .skip(1)
            .take_while(|argument| *argument != "--")
            .any(|argument| {
                matches!(argument.as_str(), "-t" | "--target-directory")
                    || argument.starts_with("--target-directory=")
                    || argument
                        .strip_prefix("-t")
                        .is_some_and(|value| !value.is_empty())
            })
    })
}

fn non_replacing_option(stage: &StageDraft) -> bool {
    invocation_argv(stage).is_some_and(|argv| {
        has_short_flag(argv, 'n')
            || has_long_option(argv, "--no-clobber")
            || argv
                .iter()
                .any(|argument| matches!(argument.as_str(), "--update=none" | "--update=none-fail"))
    })
}

fn optional_replacement(stage: &StageDraft) -> bool {
    invocation_argv(stage).is_some_and(|argv| {
        interactive_option(stage)
            || has_short_flag(argv, 'u')
            || has_long_option(argv, "--update")
            || argv
                .iter()
                .any(|argument| argument.starts_with("--update="))
    })
}

fn interactive_option(stage: &StageDraft) -> bool {
    invocation_argv(stage)
        .is_some_and(|argv| has_short_flag(argv, 'i') || has_long_option(argv, "--interactive"))
}

fn backup_option(stage: &StageDraft) -> bool {
    invocation_argv(stage)
        .is_some_and(|argv| has_short_flag(argv, 'b') || has_long_option(argv, "--backup"))
}

fn force_option(stage: &StageDraft) -> bool {
    invocation_argv(stage)
        .is_some_and(|argv| has_short_flag(argv, 'f') || has_long_option(argv, "--force"))
}

fn invocation_argv(stage: &StageDraft) -> Option<&[String]> {
    match &stage.invocation {
        InvocationDraft::Known { argv, .. }
        | InvocationDraft::CodeExecution { argv, .. }
        | InvocationDraft::Opaque { argv, .. } => argv.as_deref(),
        InvocationDraft::Native { .. } => None,
    }
}

fn has_long_option(argv: &[String], option: &str) -> bool {
    argv.iter()
        .skip(1)
        .take_while(|argument| *argument != "--")
        .any(|argument| argument == option)
}

fn has_short_flag(argv: &[String], option: char) -> bool {
    argv.iter()
        .skip(1)
        .take_while(|argument| *argument != "--")
        .filter_map(|argument| {
            argument
                .strip_prefix('-')
                .filter(|flags| !flags.starts_with('-'))
        })
        .any(|flags| {
            flags
                .chars()
                .take_while(|flag| !matches!(flag, 'S' | 't'))
                .any(|flag| flag == option)
        })
}

fn invocation_program(invocation: &InvocationDraft) -> Option<&str> {
    match invocation {
        InvocationDraft::Known { program, .. }
        | InvocationDraft::CodeExecution { program, .. }
        | InvocationDraft::Opaque {
            program: ProgramDraft::Static(program),
            ..
        } => Some(program),
        InvocationDraft::Opaque {
            program: ProgramDraft::Env { .. } | ProgramDraft::Unresolved,
            ..
        }
        | InvocationDraft::Native { .. } => None,
    }
}

fn observed_nah_file(
    filesystem: &FilesystemDraft,
    observation: &Observation,
    platform: Platform,
) -> bool {
    observed_path(filesystem, observation)
        .and_then(Result::ok)
        .is_some_and(|path| observed_path_is_nah_file(path, platform))
}

fn observed_path_is_nah_file(path: &PathObservation, platform: Platform) -> bool {
    let file = path.kind() == PathKind::File
        || path.kind() == PathKind::Symlink && path.target_kind() == Some(PathKind::File);
    file && nah_executable_name(observed_target_path(path).as_str(), platform)
}

fn observed_path<'a>(
    filesystem: &FilesystemDraft,
    observation: &'a Observation,
) -> Option<Result<&'a PathObservation, ObservationFailure>> {
    let key = filesystem.key.as_deref()?;
    observation.facts().iter().find_map(|fact| {
        if fact.query().key() != key {
            return None;
        }
        match fact.value() {
            ObservationValue::Path {
                observed: Observed::Ok { value },
            } => Some(Ok(value)),
            ObservationValue::Path {
                observed: Observed::Error { error },
            } => Some(Err(*error)),
            _ => None,
        }
    })
}

fn observed_target<'a>(
    filesystem: &FilesystemDraft,
    path: &'a PathObservation,
) -> &'a AbsolutePath {
    if path.kind() == PathKind::Symlink
        && (!filesystem.follows_final_symlink
            || filesystem.operation == FilesystemOperation::Delete)
    {
        path.resolved()
    } else {
        observed_target_path(path)
    }
}

fn observed_target_path(path: &PathObservation) -> &AbsolutePath {
    path.realpath().unwrap_or_else(|| path.resolved())
}

fn requested_program_path(
    program: &str,
    cwd: Option<&str>,
    home: &AbsolutePath,
    platform: Platform,
) -> Option<String> {
    if program == "~" {
        return Some(home.as_str().to_owned());
    }
    if let Some(relative) = program
        .strip_prefix("~/")
        .or_else(|| program.strip_prefix("~\\"))
    {
        return Some(join(home.as_str(), relative, platform));
    }
    if AbsolutePath::new(platform, program).is_ok() {
        return Some(program.to_owned());
    }
    let cwd = cwd?;
    let relative = program
        .strip_prefix("./")
        .or_else(|| program.strip_prefix(".\\"))
        .unwrap_or(program);
    Some(join(cwd, relative, platform))
}

fn invalidated(
    invalidations: &[(String, bool)],
    requested: &str,
    target: &str,
    platform: Platform,
) -> bool {
    invalidations.iter().any(|(path, recursive)| {
        invalidates(path, *recursive, requested, platform)
            || invalidates(path, *recursive, target, platform)
    })
}

fn invalidates(path: &str, recursive: bool, target: &str, platform: Platform) -> bool {
    same_path(path, target, platform) || recursive && contains(path, target, platform)
}

fn clear_path(aliases: &mut BTreeSet<String>, path: &str, recursive: bool, platform: Platform) {
    let path = identity_key(path, platform);
    aliases.retain(|alias| !invalidates(&path, recursive, alias, platform));
}

fn clear_tool_path(
    aliases: &mut BTreeMap<String, String>,
    path: &str,
    recursive: bool,
    platform: Platform,
) {
    let path = identity_key(path, platform);
    aliases.retain(|alias, _| !invalidates(&path, recursive, alias, platform));
}

fn nah_executable_name(path: &str, platform: Platform) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if platform == Platform::Windows {
        name.eq_ignore_ascii_case("nah") || name.eq_ignore_ascii_case("nah.exe")
    } else {
        name == "nah"
    }
}

fn identity_key(path: &str, platform: Platform) -> String {
    let path = path.trim_end_matches(['/', '\\']).replace('\\', "/");
    if platform == Platform::Windows {
        path.to_ascii_lowercase()
    } else {
        path
    }
}

fn same_path(left: &str, right: &str, platform: Platform) -> bool {
    let left = identity_key(left, platform);
    let right = identity_key(right, platform);
    left == right
}
