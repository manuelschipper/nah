//! Owns TAR_OPTIONS state and tar parsing for filesystem, transport, and
//! nested-executor lowering.

use crate::shell_word::{static_filesystem_word, static_word};
use nah_parse::Word;
use nah_proto::action::FilesystemOperation;
use nah_proto::observation::SymlinkTraversal;

use crate::bash_descriptor_paths::preserved_descriptor_symlink_carrier;
use crate::bash_model::FilesystemSpec;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TarOptionsValue {
    Unset,
    Static(String),
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TarOptionsVariant {
    pub(crate) exported: bool,
    pub(crate) value: TarOptionsValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TarOptionsState {
    pub(crate) variants: Vec<TarOptionsVariant>,
}

impl Default for TarOptionsState {
    fn default() -> Self {
        Self {
            variants: vec![TarOptionsVariant {
                exported: false,
                value: TarOptionsValue::Unset,
            }],
        }
    }
}

impl TarOptionsState {
    pub(crate) fn merge(states: impl IntoIterator<Item = Self>) -> Self {
        let mut variants = states
            .into_iter()
            .flat_map(|state| state.variants)
            .collect::<Vec<_>>();
        variants.sort();
        variants.dedup();
        Self { variants }
    }

    pub(crate) fn assign(&mut self, value: Option<String>) {
        let value = value
            .map(TarOptionsValue::Static)
            .unwrap_or(TarOptionsValue::Unknown);
        for variant in &mut self.variants {
            variant.value.clone_from(&value);
        }
        self.canonicalize();
    }

    pub(crate) fn export(&mut self) {
        for variant in &mut self.variants {
            variant.exported = true;
        }
        self.canonicalize();
    }

    pub(crate) fn unexport(&mut self) {
        for variant in &mut self.variants {
            variant.exported = false;
        }
        self.canonicalize();
    }

    pub(crate) fn unset(&mut self) {
        self.variants = Self::default().variants;
    }

    fn canonicalize(&mut self) {
        self.variants.sort();
        self.variants.dedup();
    }
}

pub(crate) struct Analysis {
    pub(crate) filesystems: Vec<FilesystemSpec>,
    pub(crate) unresolved_members: bool,
    pub(crate) remote_archive: bool,
    pub(crate) remote_archive_inbound: bool,
    pub(crate) symlink_traversal: SymlinkTraversal,
    pub(crate) executor_payloads: Vec<String>,
    pub(crate) archive_target: Option<ArchiveTarget>,
    pub(crate) descriptor_symlink_carrier: bool,
}

pub(crate) struct ArchiveTarget {
    pub(crate) raw: String,
    pub(crate) static_path: Option<String>,
}

pub(crate) fn options_arguments(value: &Word) -> Option<Vec<Word>> {
    let value = static_word(value.raw(), value.substitutions().is_empty())?;
    options_value_arguments(&value)
}

pub(crate) fn options_value_arguments(value: &str) -> Option<Vec<Word>> {
    split_options(value).map(|values| {
        values
            .into_iter()
            .map(|value| Word::from_literal(&value))
            .collect()
    })
}

pub(crate) fn tape_archive_argument(value: &Word, arguments: &[Word]) -> Option<Word> {
    let value = static_word(value.raw(), value.substitutions().is_empty())?;
    analyze("tar", arguments)?
        .archive_target
        .is_none()
        .then(|| Word::from_literal(&format!("--file={value}")))
}

enum ExecutorKind {
    Compressor,
    Checkpoint,
    RemoteShell,
    ToCommand,
    VolumeScript,
}

/// Keeps every visible static fact even when another argument is dynamic.
pub(crate) fn analyze(program: &str, arguments: &[Word]) -> Option<Analysis> {
    debug_assert!(matches!(program, "tar" | "bsdtar"));

    let bsd = program == "bsdtar";
    let mut archive_operation = false;
    let mut archives_members = false;
    let mut archive_write = false;
    let mut archive_read = false;
    let mut extract = false;
    let mut list = false;
    let mut recursive = true;
    let mut archive: Option<ArchiveTarget> = None;
    let mut directory: Option<String> = None;
    let mut members = Vec::new();
    let mut descriptor_carrier_member = false;
    let mut auxiliary_files = Vec::new();
    let mut unresolved_members = false;
    let mut force_local = false;
    let mut saw_remote_archive = false;
    let mut symlink_traversal = SymlinkTraversal::None;
    let mut executor_candidates = Vec::new();
    let mut after_options = false;
    let mut index = 0;

    while index < arguments.len() {
        let argument_index = index;
        let argument = &arguments[index];
        index += 1;
        let option =
            static_word(argument.raw(), argument.substitutions().is_empty()).or_else(|| {
                dynamic_archive_option(argument.raw(), argument_index, bsd)
                    .then(|| argument.raw().to_owned())
            });
        let path = static_filesystem_word(argument.raw(), argument.substitutions().is_empty());

        if after_options {
            if let Some(path) = path {
                push_member(
                    &mut members,
                    &mut descriptor_carrier_member,
                    &directory,
                    &path,
                    recursive,
                );
            } else {
                unresolved_members = true;
            }
            continue;
        }

        let Some(option) = option else {
            if let Some(path) = path {
                push_member(
                    &mut members,
                    &mut descriptor_carrier_member,
                    &directory,
                    &path,
                    recursive,
                );
            } else {
                unresolved_members = true;
                // Before `--`, a dynamic word could enable dereferencing or
                // recursion. Inspect the conservative superset.
                symlink_traversal = SymlinkTraversal::All;
                recursive = true;
            }
            continue;
        };

        if option == "--" {
            after_options = true;
            continue;
        }

        if let Some(long) = option.strip_prefix("--") {
            let (name, attached) = split_long(long);
            let name = gnu_option_name(name, bsd);
            let path_attached = path
                .as_deref()
                .and_then(|path| path.strip_prefix("--"))
                .and_then(|path| split_long(path).1);
            match name {
                "create" | "append" | "update" => {
                    archive_operation = true;
                    archives_members = true;
                    archive_write = true;
                }
                "concatenate" | "catenate" => {
                    archive_operation = true;
                    archive_write = true;
                }
                "extract" | "get" => {
                    archive_operation = true;
                    archive_read = true;
                    extract = true;
                }
                "list" => {
                    archive_operation = true;
                    archive_read = true;
                    list = true;
                }
                "compare" | "diff" | "test-label" => {
                    archive_operation = true;
                    archive_read = true;
                }
                "delete" => archive_operation = true,
                "help" | "version" | "usage" => return None,
                "recursion" => recursive = true,
                "no-recursion" => recursive = false,
                "dereference" => symlink_traversal = SymlinkTraversal::All,
                "force-local" => force_local = true,
                "file" => {
                    archive = take_archive(path_attached, attached, arguments, &mut index);
                    saw_remote_archive |= archive
                        .as_ref()
                        .and_then(|archive| archive.static_path.as_deref())
                        .is_some_and(tar_remote_path);
                    unresolved_members |= archive
                        .as_ref()
                        .is_none_or(|archive| archive.static_path.is_none());
                }
                "directory" => {
                    if let Some(value) = take_path(path_attached, arguments, &mut index) {
                        directory = Some(tar_directory(directory.as_deref(), &value));
                    } else {
                        unresolved_members = true;
                    }
                }
                "files-from" => {
                    if let Some(value) = take_path(path_attached, arguments, &mut index)
                        && value != "-"
                    {
                        auxiliary_files.push(value);
                    }
                    unresolved_members = true;
                }
                "exclude-from" => {
                    if let Some(value) = take_path(path_attached, arguments, &mut index) {
                        if value != "-" {
                            auxiliary_files.push(value);
                        }
                    } else {
                        unresolved_members = true;
                    }
                }
                "add-file" => {
                    if let Some(value) = take_path(path_attached, arguments, &mut index) {
                        push_member(
                            &mut members,
                            &mut descriptor_carrier_member,
                            &directory,
                            &value,
                            recursive,
                        );
                    } else {
                        unresolved_members = true;
                    }
                }
                "checkpoint-action" => match take_option(attached, arguments, &mut index) {
                    Some(value) if !bsd => {
                        if let Some(payload) = value.strip_prefix("exec=")
                            && !payload.is_empty()
                        {
                            executor_candidates
                                .push((ExecutorKind::Checkpoint, payload.to_owned()));
                        }
                    }
                    Some(_) => unresolved_members = true,
                    None => unresolved_members = true,
                },
                "use-compress-program" => match take_option(attached, arguments, &mut index) {
                    Some(value) if !value.is_empty() => {
                        executor_candidates.push((ExecutorKind::Compressor, value));
                    }
                    Some(_) => {}
                    None => unresolved_members = true,
                },
                "to-command" => match take_option(attached, arguments, &mut index) {
                    Some(value) if !bsd && !value.is_empty() => {
                        executor_candidates.push((ExecutorKind::ToCommand, value));
                    }
                    Some(_) => unresolved_members = true,
                    None => unresolved_members = true,
                },
                "info-script" | "new-volume-script" => {
                    match take_option(attached, arguments, &mut index) {
                        Some(value) if !bsd && !value.is_empty() => {
                            executor_candidates.push((ExecutorKind::VolumeScript, value));
                        }
                        Some(_) if bsd => unresolved_members = true,
                        Some(_) => {}
                        None => unresolved_members = true,
                    }
                }
                "rmt-command" | "rsh-command" => {
                    match take_option(attached, arguments, &mut index) {
                        Some(value) if !bsd && !value.is_empty() => {
                            executor_candidates.push((ExecutorKind::RemoteShell, value));
                        }
                        Some(_) if bsd => unresolved_members = true,
                        Some(_) => {}
                        None => unresolved_members = true,
                    }
                }
                _ if long_option_takes_value(name) => {
                    if take_option(attached, arguments, &mut index).is_none() {
                        unresolved_members = true;
                    }
                }
                _ => unresolved_members = true,
            }
            continue;
        }

        let old_style = argument_index == 0 && !option.starts_with('-');
        if option.starts_with('-') || old_style {
            let flags = option.strip_prefix('-').unwrap_or(&option);
            if flags.is_empty() {
                if option == "-" {
                    push_member(
                        &mut members,
                        &mut descriptor_carrier_member,
                        &directory,
                        "-",
                        recursive,
                    );
                }
                continue;
            }
            let path_flags = path
                .as_deref()
                .map(|path| path.strip_prefix('-').unwrap_or(path));
            for (position, flag) in flags.char_indices() {
                match flag {
                    'c' | 'r' | 'u' => {
                        archive_operation = true;
                        archives_members = true;
                        archive_write = true;
                    }
                    'A' => {
                        archive_operation = true;
                        archive_write = true;
                    }
                    'x' => {
                        archive_operation = true;
                        archive_read = true;
                        extract = true;
                    }
                    't' => {
                        archive_operation = true;
                        archive_read = true;
                        list = true;
                    }
                    'd' => {
                        archive_operation = true;
                        archive_read = true;
                    }
                    'h' => symlink_traversal = SymlinkTraversal::All,
                    'H' if bsd => symlink_traversal = SymlinkTraversal::Root,
                    'L' if bsd => symlink_traversal = SymlinkTraversal::All,
                    flag if short_option_takes_value(flag, bsd) => {
                        let offset = position + flag.len_utf8();
                        let option_remainder = &flags[offset..];
                        let option_attached = (!old_style && !option_remainder.is_empty())
                            .then_some(option_remainder);
                        let path_attached = path_flags
                            .and_then(|flags| flags.get(offset..))
                            .filter(|remainder| !old_style && !remainder.is_empty());
                        match flag {
                            'f' => {
                                archive = take_archive(
                                    path_attached,
                                    option_attached,
                                    arguments,
                                    &mut index,
                                );
                                saw_remote_archive |= archive
                                    .as_ref()
                                    .and_then(|archive| archive.static_path.as_deref())
                                    .is_some_and(tar_remote_path);
                                unresolved_members |= archive
                                    .as_ref()
                                    .is_none_or(|archive| archive.static_path.is_none());
                            }
                            'C' => {
                                if let Some(value) = take_path(path_attached, arguments, &mut index)
                                {
                                    directory = Some(tar_directory(directory.as_deref(), &value));
                                } else {
                                    unresolved_members = true;
                                }
                            }
                            'T' => {
                                if let Some(value) = take_path(path_attached, arguments, &mut index)
                                    && value != "-"
                                {
                                    auxiliary_files.push(value);
                                }
                                unresolved_members = true;
                            }
                            'X' => {
                                if let Some(value) = take_path(path_attached, arguments, &mut index)
                                {
                                    if value != "-" {
                                        auxiliary_files.push(value);
                                    }
                                } else {
                                    unresolved_members = true;
                                }
                            }
                            'I' => {
                                if bsd {
                                    match take_path(path_attached, arguments, &mut index) {
                                        Some(value) if value != "-" => {
                                            auxiliary_files.push(value);
                                        }
                                        Some(_) => {}
                                        None => {}
                                    }
                                    unresolved_members = true;
                                } else {
                                    match take_option(option_attached, arguments, &mut index) {
                                        Some(value) if !value.is_empty() => {
                                            executor_candidates
                                                .push((ExecutorKind::Compressor, value));
                                        }
                                        Some(_) => {}
                                        None => unresolved_members = true,
                                    }
                                }
                            }
                            'W' if bsd => {
                                match take_option(option_attached, arguments, &mut index) {
                                    Some(value) => {
                                        if let Some(payload) =
                                            value.strip_prefix("use-compress-program=")
                                            && !payload.is_empty()
                                        {
                                            executor_candidates.push((
                                                ExecutorKind::Compressor,
                                                payload.to_owned(),
                                            ));
                                        } else {
                                            unresolved_members = true;
                                        }
                                    }
                                    None => unresolved_members = true,
                                }
                            }
                            'F' if !bsd => {
                                match take_option(option_attached, arguments, &mut index) {
                                    Some(value) if !value.is_empty() => {
                                        executor_candidates
                                            .push((ExecutorKind::VolumeScript, value));
                                    }
                                    Some(_) => {}
                                    None => unresolved_members = true,
                                }
                            }
                            _ => {
                                if take_option(option_attached, arguments, &mut index).is_none() {
                                    unresolved_members = true;
                                }
                            }
                        }
                        if option_attached.is_some() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }

        if let Some(path) = path {
            push_member(
                &mut members,
                &mut descriptor_carrier_member,
                &directory,
                &path,
                recursive,
            );
        } else {
            unresolved_members = true;
        }
    }

    let mut filesystems = auxiliary_files
        .into_iter()
        .map(|path| (path, FilesystemOperation::Read, false))
        .collect::<Vec<_>>();
    let remote_target = !bsd && !force_local && saw_remote_archive;
    let remote_archive = archive_write && remote_target;
    let remote_archive_inbound = archive_read && remote_target;
    let current_archive_remote = !bsd
        && !force_local
        && archive
            .as_ref()
            .and_then(|archive| archive.static_path.as_deref())
            .is_some_and(tar_remote_path);
    let descriptor_symlink_carrier = archives_members
        && symlink_traversal == SymlinkTraversal::None
        && descriptor_carrier_member;
    if archive_write {
        filesystems.extend(
            members
                .into_iter()
                .map(|(member, recursive)| (member, FilesystemOperation::Read, recursive)),
        );
        if let Some(archive) = archive
            .as_ref()
            .and_then(|archive| archive.static_path.as_ref())
            .filter(|archive| !tar_stdout(archive) && !current_archive_remote)
        {
            filesystems.push((archive.clone(), FilesystemOperation::Write, false));
        }
    }
    if archive_read
        && let Some(archive) = archive
            .as_ref()
            .and_then(|archive| archive.static_path.as_ref())
            .filter(|archive| !tar_stdout(archive) && !current_archive_remote)
    {
        filesystems.push((archive.clone(), FilesystemOperation::Read, false));
    }
    if extract && !remote_archive_inbound {
        filesystems.push((
            directory.unwrap_or_else(|| ".".to_owned()),
            FilesystemOperation::Write,
            true,
        ));
    }
    let executor_payloads = executor_candidates
        .into_iter()
        .filter_map(|(kind, payload)| match kind {
            ExecutorKind::Compressor if archive_write || extract || list => Some(payload),
            ExecutorKind::Checkpoint if archive_write || extract || list => Some(payload),
            ExecutorKind::RemoteShell if archive_operation && remote_target => {
                Some(shell_literal(&payload))
            }
            ExecutorKind::ToCommand if extract => Some(payload),
            ExecutorKind::VolumeScript if archive_operation => Some(payload),
            _ => None,
        })
        .collect();

    Some(Analysis {
        filesystems,
        unresolved_members,
        remote_archive,
        remote_archive_inbound,
        symlink_traversal,
        executor_payloads,
        archive_target: archive,
        descriptor_symlink_carrier,
    })
}

fn split_long(option: &str) -> (&str, Option<&str>) {
    option
        .split_once('=')
        .map_or((option, None), |(name, value)| (name, Some(value)))
}

fn gnu_option_name(option: &str, bsd: bool) -> &str {
    if bsd {
        return option;
    }
    for (minimum, canonical) in [
        (2, "create"),
        (2, "append"),
        (2, "update"),
        (4, "concatenate"),
        (2, "catenate"),
        (3, "extract"),
        (2, "get"),
        (4, "list"),
        (5, "compare"),
        (3, "diff"),
        (4, "delete"),
        (2, "test-label"),
        (3, "directory"),
        (5, "files-from"),
        (9, "exclude-from"),
        (2, "add-file"),
        (3, "dereference"),
        (4, "force-local"),
        (4, "no-recursion"),
        (8, "recursion"),
        (4, "file"),
        (11, "checkpoint-action"),
        (3, "use-compress-program"),
        (4, "to-command"),
        (3, "info-script"),
        (4, "new-volume-script"),
        (2, "rmt-command"),
        (2, "rsh-command"),
        (2, "help"),
        (4, "version"),
        (3, "usage"),
    ] {
        if option.len() >= minimum && canonical.starts_with(option) {
            return canonical;
        }
    }
    option
}

fn split_options(value: &str) -> Option<Vec<String>> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, character) if character.is_whitespace() => {
                if started {
                    values.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, '\'' | '"') => {
                quote = Some(character);
                started = true;
            }
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), character) => {
                current.push(character);
                started = true;
            }
            (None | Some('"'), '\\') => {
                current.push(chars.next()?);
                started = true;
            }
            (_, character) => {
                current.push(character);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        values.push(current);
    }
    Some(values)
}

fn dynamic_archive_option(raw: &str, index: usize, bsd: bool) -> bool {
    if raw.starts_with("--file=") {
        return true;
    }
    let old_style = index == 0 && !raw.starts_with('-');
    let Some(flags) = raw
        .strip_prefix('-')
        .or_else(|| old_style.then_some(raw))
        .filter(|flags| !flags.starts_with('-'))
    else {
        return false;
    };
    for flag in flags.chars() {
        match flag {
            'f' => return true,
            'C' | 'T' | 'X' | 'b' | 'I' | 'N' | 'V' => return false,
            'H' | 'L' if !bsd => return false,
            '$' | '`' => return false,
            _ => {}
        }
    }
    false
}

fn long_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "listed-incremental"
            | "hole-detection"
            | "level"
            | "sparse-version"
            | "exclude"
            | "exclude-ignore"
            | "exclude-ignore-recursive"
            | "exclude-tag"
            | "exclude-tag-all"
            | "exclude-tag-under"
            | "transform"
            | "format"
            | "index-file"
            | "label"
            | "mtime"
            | "newer-mtime"
            | "owner"
            | "owner-map"
            | "group"
            | "group-map"
            | "mode"
            | "sort"
            | "xattrs-exclude"
            | "xattrs-include"
            | "tape-length"
            | "rmt-command"
            | "volno-file"
            | "blocking-factor"
            | "record-size"
            | "pax-option"
            | "starting-file"
            | "newer"
            | "after-date"
            | "suffix"
            | "strip-components"
            | "no-quote-chars"
            | "quote-chars"
            | "quoting-style"
            | "warning"
    )
}

fn shell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn short_option_takes_value(flag: char, bsd: bool) -> bool {
    matches!(flag, 'f' | 'C' | 'T' | 'X' | 'b' | 'I' | 'N' | 'V')
        || !bsd && matches!(flag, 'F' | 'g' | 'H' | 'K' | 'L')
        || bsd && matches!(flag, 's' | 'W')
}

fn take_option(attached: Option<&str>, arguments: &[Word], index: &mut usize) -> Option<String> {
    if let Some(value) = attached {
        return Some(value.to_owned());
    }
    let argument = arguments.get(*index)?;
    *index += 1;
    static_word(argument.raw(), argument.substitutions().is_empty())
}

fn take_path(attached: Option<&str>, arguments: &[Word], index: &mut usize) -> Option<String> {
    if let Some(value) = attached {
        return Some(value.to_owned());
    }
    let argument = arguments.get(*index)?;
    *index += 1;
    static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
}

fn take_archive(
    static_attached: Option<&str>,
    raw_attached: Option<&str>,
    arguments: &[Word],
    index: &mut usize,
) -> Option<ArchiveTarget> {
    if let Some(value) = static_attached {
        return Some(ArchiveTarget {
            raw: value.to_owned(),
            static_path: Some(value.to_owned()),
        });
    }
    if let Some(value) = raw_attached {
        return Some(ArchiveTarget {
            raw: value.to_owned(),
            static_path: None,
        });
    }
    let argument = arguments.get(*index)?;
    *index += 1;
    Some(ArchiveTarget {
        raw: argument.raw().to_owned(),
        static_path: static_filesystem_word(argument.raw(), argument.substitutions().is_empty()),
    })
}

fn tar_directory(current: Option<&str>, value: &str) -> String {
    if value == "." {
        return current.unwrap_or(".").to_owned();
    }
    if value.starts_with('/') || value.as_bytes().get(1) == Some(&b':') {
        value.to_owned()
    } else {
        current.map_or_else(|| value.to_owned(), |current| format!("{current}/{value}"))
    }
}

fn tar_member(directory: &Option<String>, member: &str) -> String {
    if member == "." {
        return directory.clone().unwrap_or_else(|| ".".into());
    }
    if member.starts_with('/') || member.as_bytes().get(1) == Some(&b':') {
        member.to_owned()
    } else {
        directory.as_deref().map_or_else(
            || member.to_owned(),
            |directory| format!("{directory}/{member}"),
        )
    }
}

fn push_member(
    members: &mut Vec<(String, bool)>,
    descriptor_carrier_member: &mut bool,
    directory: &Option<String>,
    member: &str,
    recursive: bool,
) {
    let resolved = tar_member(directory, member);
    *descriptor_carrier_member |=
        !names_current_directory(member) && preserved_descriptor_symlink_carrier(&resolved);
    members.push((resolved, recursive));
}

fn names_current_directory(member: &str) -> bool {
    member
        .split(['/', '\\'])
        .all(|component| component.is_empty() || component == ".")
}

fn tar_stdout(path: &str) -> bool {
    matches!(path, "-" | "/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1")
}

fn tar_remote_path(path: &str) -> bool {
    let Some(colon) = path.find(':') else {
        return false;
    };
    colon > 0
        && !path[..colon].contains(['/', '\\'])
        && !(colon == 1
            && path.as_bytes()[0].is_ascii_alphabetic()
            && path
                .as_bytes()
                .get(2)
                .is_some_and(|separator| matches!(*separator, b'/' | b'\\')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nah_parse::{Statement, normalize};

    fn arguments(source: &str) -> Vec<Word> {
        let syntax = normalize(source).unwrap();
        let Statement::Command { arguments, .. } = &syntax.statements()[0] else {
            panic!("expected command");
        };
        arguments.clone()
    }

    #[test]
    fn dynamic_archive_targets_retain_their_raw_descriptor_alias() {
        for (source, raw) in [
            ("tar -cf /dev/fd/$sock src", "/dev/fd/$sock"),
            ("tar -cf/dev/fd/$sock src", "/dev/fd/$sock"),
            (
                "tar --create --file=/proc/self/fd/${sock} src",
                "/proc/self/fd/${sock}",
            ),
        ] {
            let analysis = analyze("tar", &arguments(source)).unwrap();
            let archive = analysis.archive_target.unwrap();
            assert_eq!(archive.raw, raw, "{source}");
            assert_eq!(archive.static_path, None, "{source}");
        }
    }

    #[test]
    fn exact_descriptor_carrier_members_require_preserved_symlinks() {
        for (program, source) in [
            ("tar", "tar -cf carrier.tar --no-recursion /dev/fd"),
            ("tar", "tar --append --file=carrier.tar -C / dev/fd"),
            ("tar", "tar --update --file carrier.tar -C /dev fd"),
            ("tar", "tar -rf carrier.tar --add-file=/dev/stdin"),
            ("bsdtar", "bsdtar -cf carrier.tar /dev/fd"),
        ] {
            let analysis = analyze(program, &arguments(source)).unwrap();
            assert!(analysis.descriptor_symlink_carrier, "{source}");
        }

        for (program, source) in [
            ("tar", "tar -chf carrier.tar --no-recursion /dev/fd"),
            (
                "tar",
                "tar --create --dereference --file=carrier.tar /dev/fd",
            ),
            ("bsdtar", "bsdtar -cHf carrier.tar /dev/fd"),
            ("tar", "tar -Af carrier.tar /dev/fd"),
            ("tar", "tar -cf carrier.tar /dev/fd/3"),
            ("tar", "tar -cf carrier.tar /proc/self/fd"),
            ("tar", "tar -cf carrier.tar -C /dev/fd ."),
            ("tar", "tar -xf carrier.tar /dev/fd"),
        ] {
            let analysis = analyze(program, &arguments(source)).unwrap();
            assert!(!analysis.descriptor_symlink_carrier, "{source}");
        }
    }
}
