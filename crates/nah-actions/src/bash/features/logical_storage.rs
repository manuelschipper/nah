//! Recognizes destructive logical-storage command forms.

use nah_parse::Word;

use crate::shell_word::static_word;

pub(crate) fn logical_storage_destroy(program: &str, arguments: &[Word]) -> bool {
    if program == "zfs" {
        return crate::bash_storage::zfs_live_dataset_destroy(arguments);
    }
    let Some(arguments) = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    match program {
        "lvremove" | "vgremove" => lvm_remove_has_target(&arguments),
        "lvm" => lvm_wrapped_remove(&arguments),
        "zpool" => {
            arguments
                .first()
                .is_some_and(|argument| argument == "destroy")
                && !arguments[1..].iter().any(|argument| {
                    matches!(
                        argument.as_str(),
                        "--help" | "--version" | "--dry-run" | "-n"
                    )
                })
                && arguments[1..]
                    .iter()
                    .any(|argument| !argument.starts_with('-'))
        }
        _ => false,
    }
}

pub(crate) fn models_logical_storage_command(program: &str) -> bool {
    matches!(program, "lvremove" | "vgremove" | "lvm" | "zpool" | "zfs")
}

fn lvm_wrapped_remove(arguments: &[String]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if matches!(
            argument,
            "--help" | "--longhelp" | "--version" | "--test" | "--dry-run" | "-h" | "-t" | "-n"
        ) {
            return false;
        }
        if matches!(
            argument,
            "--commandprofile"
                | "--config"
                | "--configreport"
                | "--devices"
                | "--devicesfile"
                | "--driverloaded"
                | "--journal"
                | "--lockopt"
                | "--profile"
        ) {
            index += 2;
            if index > arguments.len() {
                return false;
            }
            continue;
        }
        if matches!(
            argument,
            "--debug"
                | "--nohints"
                | "--nolocking"
                | "--quiet"
                | "--readonly"
                | "--verbose"
                | "--yes"
                | "-d"
                | "-q"
                | "-v"
                | "-y"
        ) {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return false;
        }
        return matches!(argument, "lvremove" | "vgremove")
            && lvm_remove_has_target(&arguments[index + 1..]);
    }
    false
}

fn lvm_remove_has_target(arguments: &[String]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "--" {
            return arguments[index + 1..]
                .iter()
                .any(|argument| !argument.is_empty());
        }
        if matches!(
            argument,
            "--help" | "--longhelp" | "--version" | "--test" | "--dry-run" | "-h" | "-t" | "-n"
        ) {
            return false;
        }
        if matches!(
            argument,
            "-A" | "-S"
                | "--addtag"
                | "--alloc"
                | "--autobackup"
                | "--commandprofile"
                | "--config"
                | "--devices"
                | "--devicesfile"
                | "--driverloaded"
                | "--journal"
                | "--lockopt"
                | "--metadataprofile"
                | "--profile"
                | "--reportformat"
                | "--select"
                | "--units"
        ) {
            index += 2;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        if !argument.is_empty() {
            return true;
        }
        index += 1;
    }
    false
}
