//! Lowers reviewed filesystem commands into effects; it does not decide their safety.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::Platform;

use crate::bash_descriptor_paths::descriptor_reference_path;
use crate::bash_model::FilesystemSpec;
use crate::bash_rsync_options::{rsync_argument_has_short_flag, rsync_option_takes_value};
use crate::shell_word::{static_filesystem_word, static_word};
use crate::{bash_tar, bash_transforms};

/// Where macOS keeps the user's keychains. `security` names no path operand, so
/// its keychain subcommands lower to a read of this directory.
const KEYCHAIN_DIRECTORY: &str = "~/Library/Keychains";

pub(crate) fn command_filesystems(
    program: &str,
    arguments: &[Word],
) -> Option<Vec<FilesystemSpec>> {
    if matches!(program, "tar" | "bsdtar") {
        return bash_tar::analyze(program, arguments).map(|analysis| analysis.filesystems);
    }
    if let Some(analysis) = bash_transforms::analyze(program, arguments) {
        return Some(analysis.filesystems);
    }
    if program == "git" {
        return crate::bash_git_operations::worktree_mutations(program, arguments);
    }
    let arguments = arguments
        .iter()
        .map(|argument| {
            static_filesystem_word(argument.raw(), argument.substitutions().is_empty())
                .or_else(|| descriptor_reference_path(argument.raw()))
        })
        .collect::<Vec<_>>();
    let values = arguments
        .iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if is_filesystem_program(program) && filesystem_terminal(program, &arguments) {
        return Some(Vec::new());
    }

    if matches!(program, "rm" | "rmdir" | "unlink") {
        let recursive = has_flag(&values, "--recursive", 'r') || has_short_flag(&values, 'R');
        return Some(
            positional_arguments(&values)
                .into_iter()
                .map(|target| (target.to_owned(), FilesystemOperation::Delete, recursive))
                .collect(),
        );
    }
    if matches!(program, "chmod" | "chown" | "chgrp" | "setfacl" | "chattr") {
        let recursive = has_flag(&values, "--recursive", 'R');
        return Some(
            permission_targets(program, &arguments)
                .into_iter()
                .map(|target| (target.to_owned(), FilesystemOperation::Write, recursive))
                .collect(),
        );
    }
    if program == "find" && values.contains(&"-delete") {
        return Some(
            find_paths(&values)
                .into_iter()
                .map(|target| (target.to_owned(), FilesystemOperation::Delete, true))
                .collect(),
        );
    }
    let read = |target: &str| (target.to_owned(), FilesystemOperation::Read, false);
    let write = |target: &str| (target.to_owned(), FilesystemOperation::Write, false);
    let positional = || positional_arguments(&values);
    match program {
        "dd" => Some(dd_filesystems(&values)),
        "touch" | "mkfifo" | "shred" | "truncate" | "blkdiscard" => {
            Some(positional().into_iter().map(write).collect())
        }
        "mknod" => Some(mknod_fifo(&values).into_iter().map(write).collect()),
        "pvremove" if !lvm_test_mode(&values) => {
            Some(positional().into_iter().map(write).collect())
        }
        "cp" => {
            let targets = positional_slots(&arguments);
            let Some((destination, sources)) = targets.split_last() else {
                return Some(Vec::new());
            };
            if sources.is_empty() {
                return Some(Vec::new());
            }
            let mut effects = sources
                .iter()
                .filter_map(|target| target.map(read))
                .collect::<Vec<_>>();
            if let Some(destination) = destination {
                effects.push(write(destination));
            }
            Some(effects)
        }
        "awk" | "gawk" => Some(awk_filesystems(&arguments)),
        "sed" => Some(sed_filesystems(&arguments)),
        "perl" => Some(perl_filesystems(&arguments)),
        "patch" => Some(patch_filesystems(&arguments)),
        "ed" | "ex" | "vim" | "nvim" => Some(editor_filesystems(program, &arguments)),
        "unzip" => Some(unzip_filesystems(&arguments)),
        "7z" | "7za" | "7zr" => Some(seven_zip_filesystems(&arguments)),
        "xxd" => Some(xxd_filesystems(&arguments)),
        "strings" => Some(strings_filesystems(&arguments)),
        "less" | "more" => Some(pager_filesystems(program, &arguments)),
        "ln" => Some(copy_like_filesystems(
            &arguments,
            &["-t", "--target-directory", "-S", "--suffix"],
            false,
        )),
        "link" => Some(copy_like_filesystems(&arguments, &[], false)),
        "install" => Some(copy_like_filesystems(
            &arguments,
            &[
                "-g",
                "--group",
                "-m",
                "--mode",
                "-o",
                "--owner",
                "-S",
                "--suffix",
                "-t",
                "--target-directory",
                "--strip-program",
            ],
            values.iter().any(|argument| {
                *argument == "--directory"
                    || argument
                        .strip_prefix('-')
                        .is_some_and(|flags| !flags.starts_with('-') && flags.contains('d'))
            }),
        )),
        "objcopy" => Some(objcopy_filesystems(&arguments)),
        "strip" => Some(strip_filesystems(&arguments)),
        "rsync" => rsync_filesystems(&arguments),
        "base64" => Some(
            base64_read_targets(&arguments)?
                .into_iter()
                .map(read)
                .collect(),
        ),
        "security" if keychain_secret_access(&values) => Some(vec![read(KEYCHAIN_DIRECTORY)]),
        command
            if command.starts_with("mkfs")
                || command.starts_with("newfs")
                || matches!(command, "mke2fs" | "mkswap") =>
        {
            Some(
                (!mkfs_no_act(command, &values))
                    .then(positional)
                    .into_iter()
                    .flatten()
                    .map(write)
                    .collect(),
            )
        }
        "wipefs"
            if !values.contains(&"--no-act")
                && !has_short_flag(&values, 'n')
                && (values.contains(&"--all") || has_short_flag(&values, 'a')) =>
        {
            Some(positional().into_iter().map(write).collect())
        }
        "cryptsetup" if values.contains(&"luksFormat") => Some(
            positional()
                .into_iter()
                .filter(|argument| *argument != "luksFormat")
                .map(write)
                .collect(),
        ),
        "sgdisk"
            if values.iter().any(|argument| {
                matches!(
                    *argument,
                    "-o" | "-z" | "-Z" | "--clear" | "--zap" | "--zap-all"
                )
            }) =>
        {
            Some(positional().into_iter().map(write).collect())
        }
        "sfdisk"
            if values.contains(&"--delete")
                && !values.contains(&"--no-act")
                && !has_short_flag_before_double_dash(&values, 'n') =>
        {
            Some(positional().into_iter().map(write).collect())
        }
        "parted"
            if values
                .iter()
                .any(|argument| matches!(*argument, "mklabel" | "mktable" | "rm")) =>
        {
            positional().first().map(|target| vec![write(target)])
        }
        "mdadm" if values.contains(&"--zero-superblock") => {
            Some(positional().into_iter().map(write).collect())
        }
        "nvme"
            if values
                .iter()
                .any(|argument| matches!(*argument, "format" | "sanitize")) =>
        {
            Some(
                positional()
                    .into_iter()
                    .filter(|argument| !matches!(*argument, "format" | "sanitize"))
                    .map(write)
                    .collect(),
            )
        }
        "hdparm"
            if values
                .iter()
                .any(|argument| argument.contains("security-erase")) =>
        {
            Some(positional().into_iter().map(write).collect())
        }
        "diskutil"
            if values
                .iter()
                .any(|argument| matches!(*argument, "eraseDisk" | "secureErase" | "zeroDisk")) =>
        {
            Some(
                positional()
                    .into_iter()
                    .filter(|argument| {
                        !matches!(*argument, "eraseDisk" | "secureErase" | "zeroDisk")
                    })
                    .map(write)
                    .collect(),
            )
        }
        "badblocks" if has_short_flag(&values, 'w') => {
            Some(positional().into_iter().map(write).collect())
        }
        _ => None,
    }
}

pub(crate) fn terminal_program_help(program: &str, arguments: &[Word], platform: Platform) -> bool {
    platform == Platform::Linux
        && program == "rm"
        && arguments
            .iter()
            .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
            .take_while(|argument| argument.as_deref() != Some("--"))
            .flatten()
            .any(|argument| argument == "--help")
}

fn is_filesystem_program(program: &str) -> bool {
    matches!(
        program,
        "rm" | "rmdir"
            | "unlink"
            | "chmod"
            | "chown"
            | "chgrp"
            | "setfacl"
            | "chattr"
            | "find"
            | "dd"
            | "touch"
            | "mkfifo"
            | "mknod"
            | "cp"
            | "awk"
            | "gawk"
            | "sed"
            | "perl"
            | "patch"
            | "ed"
            | "ex"
            | "vim"
            | "nvim"
            | "unzip"
            | "7z"
            | "7za"
            | "7zr"
            | "ln"
            | "link"
            | "install"
            | "objcopy"
            | "strip"
            | "rsync"
            | "shred"
            | "truncate"
            | "blkdiscard"
            | "pvremove"
            | "mke2fs"
            | "mkswap"
            | "wipefs"
            | "cryptsetup"
            | "sgdisk"
            | "sfdisk"
            | "parted"
            | "mdadm"
            | "nvme"
            | "hdparm"
            | "diskutil"
            | "badblocks"
    ) || program.starts_with("mkfs")
        || program.starts_with("newfs")
}

fn objcopy_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut start = 0;
    while let Some(Some(argument)) = arguments.get(start) {
        if matches!(
            argument.as_str(),
            "-p" | "--preserve-dates"
                | "-D"
                | "--enable-deterministic-archives"
                | "-U"
                | "--disable-deterministic-archives"
                | "-S"
                | "--strip-all"
                | "-g"
                | "--strip-debug"
                | "--strip-dwo"
                | "--strip-unneeded"
                | "--only-keep-debug"
        ) {
            start += 1;
        } else {
            break;
        }
    }
    let (source, destination) = match &arguments[start..] {
        [Some(source)] if !source.starts_with('-') => (source, source),
        [Some(source), Some(destination)]
            if !source.starts_with('-') && !destination.starts_with('-') =>
        {
            (source, destination)
        }
        _ => return Vec::new(),
    };
    vec![
        (source.clone(), FilesystemOperation::Read, false),
        (destination.clone(), FilesystemOperation::Write, false),
    ]
}

fn strip_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut output: Option<&str> = None;
    let mut sources = Vec::new();
    let mut index = 0;
    while let Some(Some(argument)) = arguments.get(index) {
        if matches!(
            argument.as_str(),
            "-p" | "--preserve-dates"
                | "-D"
                | "--enable-deterministic-archives"
                | "-U"
                | "--disable-deterministic-archives"
                | "-s"
                | "--strip-all"
                | "-g"
                | "-S"
                | "-d"
                | "--strip-debug"
                | "--strip-dwo"
                | "--strip-unneeded"
                | "--only-keep-debug"
        ) {
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "-o" | "--output-file") {
            output = arguments
                .get(index + 1)
                .and_then(Option::as_ref)
                .map(String::as_str);
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--output-file=") {
            output = Some(value);
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return Vec::new();
        }
        sources.push(argument);
        index += 1;
    }
    if index != arguments.len() || sources.is_empty() {
        return Vec::new();
    }
    if let Some(output) = output {
        if output.is_empty() || output.starts_with('-') || sources.len() != 1 {
            return Vec::new();
        }
        return vec![
            (sources[0].clone(), FilesystemOperation::Read, false),
            (output.to_owned(), FilesystemOperation::Write, false),
        ];
    }
    sources
        .into_iter()
        .flat_map(|source| {
            [
                (source.clone(), FilesystemOperation::Read, false),
                (source.clone(), FilesystemOperation::Write, false),
            ]
        })
        .collect()
}

fn filesystem_terminal(program: &str, arguments: &[Option<String>]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if argument == "--" {
            return false;
        }
        if program == "find" && matches!(argument, "-exec" | "-execdir" | "-ok" | "-okdir") {
            index += 1;
            while index < arguments.len()
                && !arguments[index]
                    .as_deref()
                    .is_some_and(|argument| matches!(argument, ";" | "+"))
            {
                index += 1;
            }
            index += 1;
            continue;
        }
        if filesystem_option_takes_value(program, argument) {
            index += 2;
            continue;
        }
        if matches!(argument, "--help" | "--version")
            || argument == "-h"
                && !matches!(program, "chmod" | "chown" | "chgrp" | "setfacl" | "rsync")
        {
            return true;
        }
        index += 1;
    }
    false
}

fn filesystem_option_takes_value(program: &str, argument: &str) -> bool {
    match program {
        "chmod" | "chown" | "chgrp" => {
            argument == "--reference" || program == "chown" && argument == "--from"
        }
        "setfacl" => matches!(
            argument,
            "-m" | "--modify"
                | "-M"
                | "--modify-file"
                | "-x"
                | "--remove"
                | "-X"
                | "--remove-file"
                | "--set"
                | "--set-file"
                | "--restore"
        ),
        "cp" | "ln" => matches!(argument, "-t" | "--target-directory" | "-S" | "--suffix"),
        "install" => matches!(
            argument,
            "-g" | "--group"
                | "-m"
                | "--mode"
                | "-o"
                | "--owner"
                | "-S"
                | "--suffix"
                | "-t"
                | "--target-directory"
                | "--strip-program"
        ),
        "sed" => matches!(argument, "-e" | "--expression" | "-f" | "--file"),
        "touch" => matches!(argument, "-d" | "--date" | "-r" | "--reference" | "-t"),
        "truncate" => matches!(
            argument,
            "-o" | "--io-blocks" | "-r" | "--reference" | "-s" | "--size"
        ),
        "shred" => matches!(argument, "-n" | "--iterations" | "-s" | "--size"),
        "rsync" => rsync_option_takes_value(argument),
        "find" => matches!(
            argument,
            "-D" | "-name"
                | "-iname"
                | "-path"
                | "-ipath"
                | "-regex"
                | "-iregex"
                | "-lname"
                | "-ilname"
                | "-wholename"
                | "-iwholename"
                | "-user"
                | "-group"
                | "-uid"
                | "-gid"
                | "-size"
                | "-type"
                | "-xtype"
                | "-perm"
                | "-links"
                | "-inum"
                | "-samefile"
                | "-newer"
                | "-anewer"
                | "-cnewer"
                | "-maxdepth"
                | "-mindepth"
                | "-fprint"
                | "-fprint0"
                | "-fprintf"
                | "-fls"
                | "-printf"
        ),
        _ => false,
    }
}

fn awk_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut filesystems = Vec::new();
    let mut inputs = Vec::new();
    let mut in_place = false;
    let mut program_supplied = false;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            if !program_supplied {
                program_supplied = true;
            }
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "--help" | "--version" | "-h") {
            return Vec::new();
        } else if !after_options && matches!(argument, "-f" | "--file") {
            let Some(target) = arguments.get(index + 1).and_then(Option::as_deref) else {
                return filesystems;
            };
            filesystems.push((target.to_owned(), FilesystemOperation::Read, false));
            program_supplied = true;
            index += 1;
        } else if !after_options && matches!(argument, "-e" | "--source") {
            if arguments
                .get(index + 1)
                .and_then(Option::as_deref)
                .is_none()
            {
                return filesystems;
            }
            program_supplied = true;
            index += 1;
        } else if !after_options && matches!(argument, "-i" | "--include") {
            let Some(extension) = arguments.get(index + 1).and_then(Option::as_deref) else {
                return filesystems;
            };
            in_place |= extension == "inplace";
            index += 1;
        } else if !after_options
            && matches!(
                argument
                    .strip_prefix("--include=")
                    .or_else(|| argument.strip_prefix("-i")),
                Some("inplace")
            )
        {
            in_place = true;
        } else if !after_options
            && matches!(
                argument,
                "-F" | "--field-separator" | "-v" | "--assign" | "-W"
            )
        {
            if arguments
                .get(index + 1)
                .and_then(Option::as_deref)
                .is_none()
            {
                return filesystems;
            }
            index += 1;
        } else if !after_options
            && let Some(target) = argument.strip_prefix("--file=").or_else(|| {
                argument
                    .strip_prefix("-f")
                    .filter(|value| !value.is_empty())
            })
        {
            filesystems.push((target.to_owned(), FilesystemOperation::Read, false));
            program_supplied = true;
        } else if !after_options
            && (argument.starts_with("--source=")
                || argument.starts_with("--assign=")
                || argument.starts_with("--field-separator=")
                || argument.starts_with("-e") && argument.len() > 2
                || argument.starts_with("-v") && argument.len() > 2
                || argument.starts_with("-F") && argument.len() > 2)
        {
            program_supplied |= argument.starts_with("--source=") || argument.starts_with("-e");
        } else if !after_options
            && matches!(
                argument,
                "--characters-as-bytes"
                    | "--csv"
                    | "--debug"
                    | "--lint"
                    | "--posix"
                    | "--sandbox"
                    | "--traditional"
            )
        {
        } else if !after_options && argument.starts_with('-') {
            return filesystems;
        } else if !program_supplied {
            program_supplied = true;
        } else if argument != "-" {
            inputs.push(argument.to_owned());
        }
        index += 1;
    }
    for input in inputs {
        filesystems.push((input.clone(), FilesystemOperation::Read, false));
        if in_place {
            filesystems.push((input, FilesystemOperation::Write, false));
        }
    }
    filesystems
}

fn sed_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut in_place = false;
    let mut explicit_script = false;
    let mut skip_next = false;
    let mut after_options = false;
    let mut inputs = Vec::new();
    let mut script_files = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let Some(argument) = argument.as_deref() else {
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "--help" | "--version") {
            return Vec::new();
        } else if !after_options
            && (matches!(argument, "-i" | "--in-place")
                || argument.starts_with("-i") && argument.len() > 2
                || argument.starts_with("--in-place="))
        {
            in_place = true;
            if argument == "-i"
                && arguments
                    .get(index + 1)
                    .and_then(Option::as_deref)
                    .is_some_and(str::is_empty)
            {
                skip_next = true;
            }
        } else if !after_options && matches!(argument, "-e" | "--expression") {
            explicit_script = true;
            skip_next = true;
        } else if !after_options && matches!(argument, "-f" | "--file") {
            explicit_script = true;
            if let Some(target) = arguments.get(index + 1).and_then(Option::as_deref) {
                script_files.push(target);
            }
            skip_next = true;
        } else if !after_options
            && (argument.starts_with("-e") && argument.len() > 2
                || argument.starts_with("--expression="))
        {
            explicit_script = true;
        } else if !after_options
            && let Some(target) = argument.strip_prefix("--file=").or_else(|| {
                argument
                    .strip_prefix("-f")
                    .filter(|value| !value.is_empty())
            })
        {
            explicit_script = true;
            script_files.push(target);
        } else if !after_options && argument.starts_with('-') {
        } else {
            inputs.push(argument);
        }
    }
    if !explicit_script && !inputs.is_empty() {
        inputs.remove(0);
    }
    let mut filesystems = script_files
        .into_iter()
        .map(|target| (target.to_owned(), FilesystemOperation::Read, false))
        .collect::<Vec<_>>();
    for target in inputs.into_iter().filter(|target| *target != "-") {
        filesystems.push((target.to_owned(), FilesystemOperation::Read, false));
        if in_place {
            filesystems.push((target.to_owned(), FilesystemOperation::Write, false));
        }
    }
    filesystems
}

fn perl_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut in_place = false;
    let mut explicit_script = false;
    let mut operands = Vec::new();
    let mut options = true;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            operands.push(None);
            options = false;
            index += 1;
            continue;
        };
        if options && argument == "--" {
            options = false;
        } else if options && matches!(argument, "-h" | "--help" | "-v" | "--version") {
            return Vec::new();
        } else if options && matches!(argument, "-e" | "-E") {
            explicit_script = true;
            index += 1;
        } else if options
            && matches!(argument, "-I" | "-M" | "-m")
            && arguments.get(index + 1).is_some()
        {
            index += 1;
        } else if options && argument.starts_with('-') {
            if !argument.starts_with("--") {
                let (short_in_place, short_script) = perl_short_modes(argument);
                in_place |= short_in_place;
                explicit_script |= short_script;
            }
        } else {
            operands.push(Some(argument));
            options = false;
        }
        index += 1;
    }
    if !explicit_script && !operands.is_empty() {
        operands.remove(0);
    }
    operands
        .into_iter()
        .flatten()
        .filter(|target| *target != "-")
        .flat_map(|target| {
            let mut effects = vec![(target.to_owned(), FilesystemOperation::Read, false)];
            if in_place {
                effects.push((target.to_owned(), FilesystemOperation::Write, false));
            }
            effects
        })
        .collect()
}

fn perl_short_modes(argument: &str) -> (bool, bool) {
    let mut in_place = false;
    let mut explicit_script = false;
    let Some(flags) = argument.strip_prefix('-') else {
        return (in_place, explicit_script);
    };
    for flag in flags.chars() {
        match flag {
            'i' => {
                in_place = true;
                break;
            }
            'e' | 'E' => {
                explicit_script = true;
                break;
            }
            // These switches consume the rest of the word as a value. Its
            // letters are not additional switches (`-Mstrict` is not `-i`).
            '0' | 'C' | 'D' | 'F' | 'I' | 'M' | 'V' | 'd' | 'm' | 'x' => break,
            _ => {}
        }
    }
    (in_place, explicit_script)
}

fn patch_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut operands = Vec::new();
    let mut patch_input = None;
    let mut output = None;
    let mut reject = None;
    let mut directory = None;
    let mut dry_run = false;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "--help" | "--version") {
            return Vec::new();
        } else if !after_options && matches!(argument, "--dry-run") {
            dry_run = true;
        } else if !after_options
            && matches!(
                argument,
                "-i" | "--input"
                    | "-o"
                    | "--output"
                    | "-r"
                    | "--reject-file"
                    | "-d"
                    | "--directory"
                    | "-p"
                    | "--strip"
            )
        {
            let value = arguments.get(index + 1).and_then(Option::as_deref);
            match argument {
                "-i" | "--input" => patch_input = value,
                "-o" | "--output" => output = value,
                "-r" | "--reject-file" => reject = value,
                "-d" | "--directory" => directory = value,
                _ => {}
            }
            index += 1;
        } else if !after_options
            && let Some((name, value)) = argument.split_once('=')
            && matches!(
                name,
                "--input" | "--output" | "--reject-file" | "--directory" | "--strip"
            )
        {
            match name {
                "--input" => patch_input = Some(value),
                "--output" => output = Some(value),
                "--reject-file" => reject = Some(value),
                "--directory" => directory = Some(value),
                _ => {}
            }
        } else if !after_options && argument.starts_with('-') {
        } else {
            operands.push(argument);
        }
        index += 1;
    }

    let qualify = |path: &str| match directory {
        Some(directory) if !path.starts_with(['/', '~']) => {
            format!("{}/{path}", directory.trim_end_matches(['/', '\\']))
        }
        _ => path.to_owned(),
    };
    let mut filesystems = Vec::new();
    if let Some(input) = patch_input.or_else(|| operands.get(1).copied()) {
        filesystems.push((qualify(input), FilesystemOperation::Read, false));
    }
    let original = operands.first().copied();
    if let Some(original) = original {
        filesystems.push((qualify(original), FilesystemOperation::Read, false));
    }
    if !dry_run {
        if let Some(target) = output.or(original) {
            filesystems.push((qualify(target), FilesystemOperation::Write, false));
        }
        if let Some(target) = reject {
            filesystems.push((qualify(target), FilesystemOperation::Write, false));
        }
    }
    filesystems
}

fn editor_filesystems(program: &str, arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut operands = Vec::new();
    let mut writes = program == "ed";
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "-h" | "--help" | "--version") {
            return Vec::new();
        } else if !after_options
            && (matches!(argument, "-c" | "--cmd")
                || argument.strip_prefix('-').is_some_and(|flags| {
                    flags.ends_with('c')
                        && flags[..flags.len() - 1]
                            .bytes()
                            .all(|flag| matches!(flag, b'e' | b'E' | b's'))
                }))
        {
            writes |= arguments
                .get(index + 1)
                .and_then(Option::as_deref)
                .is_some_and(editor_command_writes);
            index += 1;
        } else if !after_options
            && let Some(command) = argument
                .strip_prefix("-c")
                .filter(|command| !command.is_empty())
                .or_else(|| argument.strip_prefix('+'))
        {
            writes |= editor_command_writes(command);
        } else if !after_options && let Some(command) = argument.strip_prefix("--cmd=") {
            writes |= editor_command_writes(command);
        } else if !after_options
            && matches!(
                argument,
                "-S" | "-u" | "-U" | "-i" | "-T" | "-w" | "-W" | "--servername"
            )
        {
            index += 1;
        } else if !after_options && argument.starts_with('-') {
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    operands
        .into_iter()
        .filter(|target| *target != "-")
        .flat_map(|target| {
            let mut effects = vec![(target.to_owned(), FilesystemOperation::Read, false)];
            if writes {
                effects.push((target.to_owned(), FilesystemOperation::Write, false));
            }
            effects
        })
        .collect()
}

fn editor_command_writes(command: &str) -> bool {
    command.split('|').any(|command| {
        let command = command.trim().trim_start_matches(':').trim();
        let command = command
            .strip_prefix("silent! ")
            .or_else(|| command.strip_prefix("silent "))
            .unwrap_or(command)
            .trim();
        let operation = command
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .trim_end_matches('!');
        matches!(
            operation,
            "w" | "write" | "update" | "up" | "x" | "xit" | "wq" | "wqa" | "wa" | "wall" | "xall"
        )
    })
}

fn unzip_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut archive = None;
    let mut destination = None;
    let mut extracts = true;
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "-h" | "--help" | "-v") {
            return Vec::new();
        } else if !after_options && matches!(argument, "-l" | "-t" | "-z" | "-p" | "-c" | "-Z") {
            extracts = false;
        } else if !after_options && argument == "-d" {
            destination = arguments.get(index + 1).and_then(Option::as_deref);
            index += 1;
        } else if !after_options
            && let Some(target) = argument.strip_prefix("-d")
            && !target.is_empty()
        {
            destination = Some(target);
        } else if !after_options && argument.starts_with('-') {
        } else if archive.is_none() {
            archive = Some(argument);
        }
        index += 1;
    }
    let Some(archive) = archive else {
        return Vec::new();
    };
    let mut filesystems = vec![(archive.to_owned(), FilesystemOperation::Read, false)];
    if extracts {
        filesystems.push((
            destination.unwrap_or(".").to_owned(),
            FilesystemOperation::Write,
            true,
        ));
    }
    filesystems
}

fn seven_zip_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let command = arguments.first().and_then(Option::as_deref);
    if !matches!(command, Some("e" | "x")) {
        return Vec::new();
    }
    let mut archive = None;
    let mut destination = ".";
    let mut index = 1;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if argument == "-o" {
            if let Some(target) = arguments.get(index + 1).and_then(Option::as_deref) {
                destination = target;
            }
            index += 1;
        } else if let Some(target) = argument.strip_prefix("-o") {
            if !target.is_empty() {
                destination = target;
            }
        } else if !argument.starts_with('-') && archive.is_none() {
            archive = Some(argument);
        }
        index += 1;
    }
    let Some(archive) = archive else {
        return Vec::new();
    };
    vec![
        (archive.to_owned(), FilesystemOperation::Read, false),
        (destination.to_owned(), FilesystemOperation::Write, true),
    ]
}

fn xxd_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "-h" | "--help" | "-v" | "--version") {
            return Vec::new();
        } else if !after_options && matches!(argument, "-c" | "-g" | "-l" | "-n" | "-o" | "-s") {
            index += 1;
        } else if !after_options
            && (["-c", "-g", "-l", "-n", "-o", "-s"]
                .iter()
                .any(|prefix| argument.starts_with(prefix) && argument.len() > prefix.len())
                || matches!(
                    argument,
                    "-a" | "-b" | "-E" | "-e" | "-i" | "-p" | "-ps" | "-r" | "-u"
                ))
        {
        } else if !after_options && argument.starts_with('-') {
            return Vec::new();
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    let mut filesystems = Vec::new();
    if let Some(input) = operands.first().filter(|target| **target != "-") {
        filesystems.push(((*input).to_owned(), FilesystemOperation::Read, false));
    }
    if let Some(output) = operands.get(1).filter(|target| **target != "-") {
        filesystems.push(((*output).to_owned(), FilesystemOperation::Write, false));
    }
    filesystems
}

fn strings_filesystems(arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut filesystems = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "-h" | "--help" | "-v" | "--version") {
            return Vec::new();
        } else if !after_options
            && matches!(
                argument,
                "-n" | "--bytes"
                    | "-t"
                    | "--radix"
                    | "-e"
                    | "--encoding"
                    | "-T"
                    | "--target"
                    | "-s"
                    | "--output-separator"
            )
        {
            index += 1;
        } else if !after_options
            && ([
                "--bytes=",
                "--radix=",
                "--encoding=",
                "--target=",
                "--output-separator=",
            ]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
                || argument
                    .strip_prefix('-')
                    .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
                || ["-n", "-t", "-e", "-T", "-s"]
                    .iter()
                    .any(|prefix| argument.starts_with(prefix) && argument.len() > prefix.len())
                || matches!(
                    argument,
                    "-a" | "--all"
                        | "-d"
                        | "--data"
                        | "-f"
                        | "--print-file-name"
                        | "-w"
                        | "--include-all-whitespace"
                ))
        {
        } else if !after_options && argument.starts_with('-') {
            return filesystems;
        } else if argument != "-" {
            filesystems.push((argument.to_owned(), FilesystemOperation::Read, false));
        }
        index += 1;
    }
    filesystems
}

fn pager_filesystems(program: &str, arguments: &[Option<String>]) -> Vec<FilesystemSpec> {
    let mut filesystems = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].as_deref() else {
            index += 1;
            continue;
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options
            && (matches!(argument, "-?" | "--help" | "-V" | "--version")
                || program == "more" && argument == "-h")
        {
            return Vec::new();
        } else if !after_options && program == "more" && matches!(argument, "-n" | "--lines") {
            index += 1;
        } else if !after_options
            && program == "more"
            && (argument.starts_with("--lines=")
                || argument
                    .strip_prefix("-n")
                    .is_some_and(|value| !value.is_empty())
                || argument.strip_prefix('-').is_some_and(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                || argument.starts_with('+')
                || matches!(
                    argument,
                    "-d" | "--silent"
                        | "-f"
                        | "--logical"
                        | "-l"
                        | "--no-pause"
                        | "-c"
                        | "--print-over"
                        | "-p"
                        | "--clean-print"
                        | "-e"
                        | "--exit-on-eof"
                        | "-s"
                        | "--squeeze"
                        | "-u"
                        | "--plain"
                ))
        {
        } else if !after_options && program == "more" && argument.starts_with('-') {
            return filesystems;
        } else if !after_options
            && program == "less"
            && matches!(argument, "-k" | "--lesskey-file" | "-T" | "--tag-file")
        {
            let Some(target) = arguments.get(index + 1).and_then(Option::as_deref) else {
                return filesystems;
            };
            filesystems.push((target.to_owned(), FilesystemOperation::Read, false));
            index += 1;
        } else if !after_options
            && program == "less"
            && matches!(argument, "-o" | "--log-file" | "-O" | "--LOG-FILE")
        {
            let Some(target) = arguments.get(index + 1).and_then(Option::as_deref) else {
                return filesystems;
            };
            filesystems.push((target.to_owned(), FilesystemOperation::Write, false));
            index += 1;
        } else if !after_options
            && program == "less"
            && let Some(target) = argument
                .strip_prefix("--lesskey-file=")
                .or_else(|| argument.strip_prefix("--tag-file="))
                .or_else(|| {
                    ["-k", "-T"].iter().find_map(|prefix| {
                        argument
                            .strip_prefix(prefix)
                            .filter(|value| !value.is_empty())
                    })
                })
        {
            filesystems.push((target.to_owned(), FilesystemOperation::Read, false));
        } else if !after_options
            && program == "less"
            && let Some(target) = argument
                .strip_prefix("--log-file=")
                .or_else(|| argument.strip_prefix("--LOG-FILE="))
                .or_else(|| {
                    ["-o", "-O"].iter().find_map(|prefix| {
                        argument
                            .strip_prefix(prefix)
                            .filter(|value| !value.is_empty())
                    })
                })
        {
            filesystems.push((target.to_owned(), FilesystemOperation::Write, false));
        } else if !after_options
            && program == "less"
            && matches!(
                argument,
                "-b" | "--buffers"
                    | "-h"
                    | "--max-back-scroll"
                    | "-j"
                    | "--jump-target"
                    | "-D"
                    | "--color"
                    | "-p"
                    | "--pattern"
                    | "-P"
                    | "--prompt"
                    | "-t"
                    | "--tag"
                    | "-x"
                    | "--tabs"
                    | "-y"
                    | "--max-forw-scroll"
                    | "-z"
                    | "--window"
            )
        {
            index += 1;
        } else if !after_options
            && program == "less"
            && ([
                "--buffers=",
                "--max-back-scroll=",
                "--jump-target=",
                "--color=",
                "--pattern=",
                "--lesskey-file=",
                "--prompt=",
                "--tag=",
                "--tabs=",
                "--max-forw-scroll=",
                "--window=",
            ]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
                || [
                    "-b", "-h", "-j", "-D", "-p", "-P", "-t", "-x", "-y", "-z", "-#",
                ]
                .iter()
                .any(|prefix| argument.starts_with(prefix) && argument.len() > prefix.len())
                || argument.strip_prefix('-').is_some_and(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                || argument.starts_with('+')
                || argument.starts_with('-')
                    && argument[1..].chars().all(|flag| {
                        matches!(
                            flag,
                            'a' | 'A'
                                | 'c'
                                | 'd'
                                | 'D'
                                | 'e'
                                | 'E'
                                | 'f'
                                | 'F'
                                | 'g'
                                | 'G'
                                | 'i'
                                | 'I'
                                | 'J'
                                | 'K'
                                | 'L'
                                | 'm'
                                | 'M'
                                | 'n'
                                | 'N'
                                | 'o'
                                | 'O'
                                | 'p'
                                | 'q'
                                | 'Q'
                                | 'r'
                                | 'R'
                                | 's'
                                | 'S'
                                | 'u'
                                | 'w'
                                | 'X'
                        )
                    }))
        {
        } else if !after_options && argument.starts_with('-') {
            return filesystems;
        } else if argument != "-" {
            filesystems.push((argument.to_owned(), FilesystemOperation::Read, false));
        }
        index += 1;
    }
    filesystems
}

fn copy_like_filesystems(
    arguments: &[Option<String>],
    value_options: &[&str],
    directory_mode: bool,
) -> Vec<FilesystemSpec> {
    let mut operands = Vec::new();
    let mut target_directory = None;
    let mut skip_next = false;
    let mut after_options = false;
    for (index, argument) in arguments.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let Some(argument) = argument.as_deref() else {
            return Vec::new();
        };
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && value_options.contains(&argument) {
            let Some(value) = arguments.get(index + 1).and_then(Option::as_deref) else {
                return Vec::new();
            };
            if matches!(argument, "-t" | "--target-directory") {
                target_directory = Some(value);
            }
            skip_next = true;
        } else if !after_options
            && [
                "--target-directory=",
                "--group=",
                "--mode=",
                "--owner=",
                "--suffix=",
            ]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
        {
            if let Some(value) = argument.strip_prefix("--target-directory=") {
                target_directory = Some(value);
            }
        } else if !after_options && argument.starts_with('-') {
        } else {
            operands.push(argument);
        }
    }
    if directory_mode {
        return operands
            .into_iter()
            .map(|target| (target.to_owned(), FilesystemOperation::Write, false))
            .collect();
    }
    let (destination, sources) = if let Some(destination) = target_directory {
        (destination, operands.as_slice())
    } else {
        let Some((destination, sources)) = operands.split_last() else {
            return Vec::new();
        };
        (*destination, sources)
    };
    if sources.is_empty() {
        return Vec::new();
    }
    sources
        .iter()
        .map(|source| ((*source).to_owned(), FilesystemOperation::Read, false))
        .chain(std::iter::once((
            destination.to_owned(),
            FilesystemOperation::Write,
            false,
        )))
        .collect()
}

fn dd_filesystems(arguments: &[&str]) -> Vec<FilesystemSpec> {
    let input = arguments
        .iter()
        .filter_map(|argument| argument.strip_prefix("if="))
        .next_back();
    let output = arguments
        .iter()
        .filter_map(|argument| argument.strip_prefix("of="))
        .next_back();
    input
        .map(|target| (target.to_owned(), FilesystemOperation::Read, false))
        .into_iter()
        .chain(output.map(|target| (target.to_owned(), FilesystemOperation::Write, false)))
        .collect()
}

fn rsync_filesystems(arguments: &[Option<String>]) -> Option<Vec<FilesystemSpec>> {
    let mut operands = Vec::new();
    let mut remove_sources = false;
    let mut delete_destination = false;
    let mut dry_run = false;
    let mut after_options = false;
    let mut recursive = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_deref()?;
        if !after_options {
            if matches!(argument, "--no-r" | "--no-recursive") {
                recursive = false;
            } else if matches!(argument, "-r" | "--recursive" | "-a" | "--archive")
                || rsync_argument_has_short_flag(argument, 'r')
                || rsync_argument_has_short_flag(argument, 'a')
            {
                recursive = true;
            }
        }
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && rsync_option_takes_value(argument) {
            index += 2;
            if index > arguments.len() {
                return None;
            }
            continue;
        } else if !after_options && argument == "--remove-source-files" {
            remove_sources = true;
        } else if !after_options
            && matches!(
                argument,
                "--delete"
                    | "--delete-before"
                    | "--delete-during"
                    | "--delete-delay"
                    | "--delete-after"
                    | "--delete-excluded"
                    | "--delete-missing-args"
            )
        {
            delete_destination = true;
        } else if !after_options
            && (matches!(argument, "--dry-run" | "--list-only")
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| !flags.starts_with('-') && flags.contains('n')))
        {
            dry_run = true;
        } else if !after_options && argument.starts_with('-') {
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    let (destination, sources) = operands.split_last()?;
    if sources.is_empty() || destination.contains(':') || destination.starts_with("rsync://") {
        return Some(Vec::new());
    }
    if dry_run {
        return Some(Vec::new());
    }
    let mut effects = sources
        .iter()
        .filter(|source| !source.contains(':') && !source.starts_with("rsync://"))
        .map(|source| {
            let normalized = source.trim_end_matches(['/', '\\']);
            (
                if normalized.is_empty() {
                    (*source).to_owned()
                } else {
                    normalized.to_owned()
                },
                FilesystemOperation::Read,
                recursive,
            )
        })
        .collect::<Vec<_>>();
    effects.push(((*destination).to_owned(), FilesystemOperation::Write, false));
    if delete_destination {
        effects.push(((*destination).to_owned(), FilesystemOperation::Delete, true));
    }
    if remove_sources {
        effects.extend(
            sources
                .iter()
                .filter(|source| !source.contains(':'))
                .map(|source| ((*source).to_owned(), FilesystemOperation::Delete, false)),
        );
    }
    Some(effects)
}

/// `base64` reads file content the same way `cat` does; without a read effect
/// an exfiltration pipe that starts with it has nothing to connect.
fn base64_read_targets(arguments: &[Option<String>]) -> Option<Vec<&str>> {
    let mut targets = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_deref()?;
        index += 1;
        if after_options {
            targets.push(argument);
        } else if argument == "--" {
            after_options = true;
        } else if matches!(argument, "--help" | "--version") {
            return None;
        } else if matches!(argument, "-w" | "--wrap") {
            index += 1;
        } else if !argument.starts_with('-') {
            targets.push(argument);
        }
    }
    Some(targets)
}

/// macOS `security` subcommands that extract stored secrets rather than
/// inspect keychain metadata.
fn keychain_secret_access(arguments: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        matches!(
            *argument,
            "dump-keychain"
                | "export"
                | "find-generic-password"
                | "find-internet-password"
                | "find-key"
        )
    })
}

fn positional_arguments<'a>(arguments: &'a [&'a str]) -> Vec<&'a str> {
    let mut after_options = false;
    arguments
        .iter()
        .filter_map(|argument| {
            if !after_options && *argument == "--" {
                after_options = true;
                return None;
            }
            (after_options || !argument.starts_with('-')).then_some(*argument)
        })
        .collect()
}

fn mknod_fifo<'a>(arguments: &'a [&'a str]) -> Option<&'a str> {
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        index += 1;
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && matches!(argument, "-m" | "--mode") {
            index += 1;
        } else if after_options || !argument.starts_with('-') {
            operands.push(argument);
        }
    }
    matches!(operands.as_slice(), [_, "p", ..]).then_some(operands[0])
}

fn permission_targets<'a>(program: &str, arguments: &'a [Option<String>]) -> Vec<&'a str> {
    let mut uses_reference = false;
    let mut skip_next = false;
    let mut positional = Vec::new();
    let mut after_options = false;
    for argument in arguments {
        if skip_next {
            skip_next = false;
            continue;
        }
        match argument.as_deref() {
            Some("--") if !after_options => after_options = true,
            Some("--reference") if !after_options => {
                uses_reference = true;
                skip_next = true;
            }
            Some(argument) if !after_options && argument.starts_with("--reference=") => {
                uses_reference = true;
            }
            Some(argument)
                if !after_options && filesystem_option_takes_value(program, argument) =>
            {
                skip_next = true;
            }
            Some(argument) if after_options || !argument.starts_with('-') => {
                positional.push(Some(argument));
            }
            None => positional.push(None),
            Some(_) => {}
        }
    }
    if program != "setfacl" && !uses_reference && !positional.is_empty() {
        positional.remove(0);
    }
    positional.into_iter().flatten().collect()
}

fn positional_slots(arguments: &[Option<String>]) -> Vec<Option<&str>> {
    let mut after_options = false;
    arguments
        .iter()
        .filter_map(|argument| match argument.as_deref() {
            Some("--") if !after_options => {
                after_options = true;
                None
            }
            Some(argument) if after_options || !argument.starts_with('-') => Some(Some(argument)),
            None => Some(None),
            Some(_) => None,
        })
        .collect()
}

fn find_paths<'a>(arguments: &'a [&'a str]) -> Vec<&'a str> {
    let mut paths = Vec::new();
    for argument in arguments {
        if argument == &"--" {
            continue;
        }
        if argument.starts_with('-') {
            if !paths.is_empty() {
                break;
            }
            continue;
        }
        paths.push(*argument);
    }
    paths
}

fn has_flag(arguments: &[&str], long: &str, short: char) -> bool {
    arguments.contains(&long) || has_short_flag(arguments, short)
}

fn lvm_test_mode(arguments: &[&str]) -> bool {
    arguments
        .iter()
        .take_while(|argument| **argument != "--")
        .any(|argument| {
            matches!(*argument, "--test" | "--dry-run")
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| !flags.starts_with('-') && flags.contains('t'))
        })
}

fn mkfs_no_act(program: &str, arguments: &[&str]) -> bool {
    let ext_builder = matches!(program, "mke2fs" | "mkfs.ext2" | "mkfs.ext3" | "mkfs.ext4")
        || program == "mkfs" && mkfs_type(arguments).is_none_or(|kind| kind.starts_with("ext"));
    ext_builder && has_short_flag_before_double_dash(arguments, 'n')
}

fn mkfs_type<'a>(arguments: &'a [&'a str]) -> Option<&'a str> {
    arguments
        .windows(2)
        .find_map(|pair| {
            matches!(pair[0], "-t" | "--type")
                .then_some(pair[1])
                .filter(|_| pair[0] != "--")
        })
        .or_else(|| {
            arguments
                .iter()
                .find_map(|argument| argument.strip_prefix("--type="))
        })
}

fn has_short_flag_before_double_dash(arguments: &[&str], flag: char) -> bool {
    arguments
        .iter()
        .take_while(|argument| **argument != "--")
        .any(|argument| {
            argument.starts_with('-') && !argument.starts_with("--") && argument[1..].contains(flag)
        })
}

fn has_short_flag(arguments: &[&str], flag: char) -> bool {
    arguments.iter().any(|argument| {
        argument.starts_with('-') && !argument.starts_with("--") && argument[1..].contains(flag)
    })
}
