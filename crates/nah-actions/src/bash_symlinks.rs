//! Owns Bash symlink creation, traversal, and dynamic-target analysis.

use nah_parse::Word;
use nah_proto::observation::SymlinkTraversal;

use crate::bash_descriptor_paths::{
    descriptor_reference_path, descriptor_symlink_carrier, preserved_descriptor_symlink_carrier,
};
use crate::bash_model::{ResolvedWord, UnresolvedCause};
use crate::bash_rsync_options::{
    rsync_argument_has_short_flag, rsync_local_source_uses_trailing_slash, rsync_option_takes_value,
};
use crate::shell_word::{contains_unquoted_pattern, static_filesystem_word, static_word};
use crate::{bash_tar, bash_transforms};

pub(crate) fn creates_descriptor_symlink(program: &str, arguments: &[Word]) -> bool {
    if matches!(program, "tar" | "bsdtar") {
        return bash_tar::analyze(program, arguments)
            .is_some_and(|analysis| analysis.descriptor_symlink_carrier);
    }
    if program == "zip" {
        return bash_transforms::analyze(program, arguments)
            .is_some_and(|analysis| analysis.descriptor_symlink_carrier);
    }
    let Some(sources) = exact_copy_sources(program, arguments) else {
        return false;
    };
    sources.iter().any(|source| match program {
        "ln" if ln_symbolic_mode(arguments) => descriptor_symlink_carrier(source),
        "cp" if cp_symbolic_mode(arguments) => descriptor_symlink_carrier(source),
        "cp" if cp_preserves_symlink(arguments) => preserved_descriptor_symlink_carrier(source),
        "rsync" if rsync_preserves_symlink(arguments, source) => {
            preserved_descriptor_symlink_carrier(source)
        }
        _ => false,
    })
}

pub(crate) fn transformed_descriptor_symlink_source(
    program: &str,
    arguments: &[Word],
    resolutions: &[ResolvedWord],
) -> bool {
    let resolution_offset = arguments.len().saturating_sub(resolutions.len());
    resolutions.iter().enumerate().any(|(index, resolution)| {
        let ResolvedWord::Unresolved {
            literal_prefix,
            cause: UnresolvedCause::ShellTransformation,
            ..
        } = resolution
        else {
            return false;
        };
        let Some(probe) = descriptor_carrier_probe(literal_prefix) else {
            return false;
        };
        let argument_index = resolution_offset + index;
        if argument_index >= arguments.len() {
            return false;
        }
        let mut arguments = arguments.to_vec();
        arguments[argument_index] = Word::from_literal(&probe);
        creates_descriptor_symlink(program, &arguments)
    })
}

fn descriptor_carrier_probe(literal_prefix: &str) -> Option<String> {
    const CARRIER: &str = "/dev/fd";
    if CARRIER.starts_with(literal_prefix) {
        return Some(CARRIER.to_owned());
    }
    if literal_prefix.starts_with('-') && literal_prefix.ends_with('=') {
        return Some(format!("{literal_prefix}{CARRIER}"));
    }
    if matches!(literal_prefix, "-f" | "-C") {
        return Some(format!("{literal_prefix}{CARRIER}"));
    }
    None
}

fn exact_copy_sources(program: &str, arguments: &[Word]) -> Option<Vec<String>> {
    copy_source_operands(program, arguments)
        .map(|operands| operands.into_iter().flatten().collect())
}

fn copy_source_operands(program: &str, arguments: &[Word]) -> Option<Vec<Option<String>>> {
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut skip_next = false;
    let mut target_directory = false;
    for word in arguments {
        if skip_next {
            skip_next = false;
            continue;
        }
        let argument = static_filesystem_word(word.raw(), word.substitutions().is_empty())
            .or_else(|| descriptor_reference_path(word.raw()));
        if !after_options && argument.as_deref() == Some("--") {
            after_options = true;
        } else if !after_options
            && program == "rsync"
            && argument.as_deref().is_some_and(rsync_option_takes_value)
        {
            skip_next = true;
        } else if !after_options
            && matches!(program, "ln" | "cp")
            && matches!(argument.as_deref(), Some("-t" | "--target-directory"))
        {
            target_directory = true;
            skip_next = true;
        } else if !after_options
            && matches!(program, "ln" | "cp")
            && matches!(argument.as_deref(), Some("-S" | "--suffix"))
        {
            skip_next = true;
        } else if !after_options
            && matches!(program, "ln" | "cp")
            && argument
                .as_deref()
                .is_some_and(|argument| argument.starts_with("--target-directory="))
        {
            target_directory = true;
        } else if !after_options
            && matches!(program, "ln" | "cp")
            && argument
                .as_deref()
                .and_then(|argument| short_value_option(argument, 't'))
                .is_some()
        {
            target_directory = true;
            skip_next = argument
                .as_deref()
                .and_then(|argument| short_value_option(argument, 't'))
                == Some(false);
        } else if !after_options
            && matches!(program, "ln" | "cp")
            && argument
                .as_deref()
                .and_then(|argument| short_value_option(argument, 'S'))
                == Some(false)
        {
            skip_next = true;
        } else if !after_options
            && argument
                .as_deref()
                .is_some_and(|argument| argument.starts_with('-'))
        {
        } else {
            operands.push(argument);
        }
    }
    if !matches!(program, "ln" | "cp" | "rsync") {
        return None;
    }
    match (target_directory, operands.as_slice()) {
        (true, [_, ..]) => Some(operands),
        (false, [_, _, ..]) => {
            operands.pop();
            Some(operands)
        }
        _ => None,
    }
}

pub(crate) fn ln_symbolic_mode(arguments: &[Word]) -> bool {
    arguments
        .iter()
        .filter_map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument != "--")
        .any(|argument| {
            argument == "--symbolic" || short_option_before_value(&argument, 's', &['S', 't'])
        })
}

fn cp_symbolic_mode(arguments: &[Word]) -> bool {
    arguments
        .iter()
        .filter_map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument != "--")
        .any(|argument| {
            argument == "--symbolic-link" || short_option_before_value(&argument, 's', &['S', 't'])
        })
}

fn cp_preserves_symlink(arguments: &[Word]) -> bool {
    let mut recursive = false;
    let mut preserves = None;
    for argument in arguments
        .iter()
        .filter_map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument != "--")
    {
        match argument.as_str() {
            "--archive" => {
                recursive = true;
                preserves = Some(true);
            }
            "--recursive" => recursive = true,
            "--no-dereference" => preserves = Some(true),
            "--dereference" => preserves = Some(false),
            _ => {
                let Some(flags) = argument
                    .strip_prefix('-')
                    .filter(|flags| !flags.starts_with('-'))
                else {
                    continue;
                };
                for flag in flags.chars() {
                    match flag {
                        'a' => {
                            recursive = true;
                            preserves = Some(true);
                        }
                        'r' | 'R' => recursive = true,
                        'd' | 'P' => preserves = Some(true),
                        'H' | 'L' => preserves = Some(false),
                        'S' | 't' => break,
                        _ => {}
                    }
                }
            }
        }
    }
    preserves.unwrap_or(recursive)
}

fn rsync_preserves_symlink(arguments: &[Word], source: &str) -> bool {
    let directory_carrier =
        preserved_descriptor_symlink_carrier(source) && descriptor_reference_path(source).is_none();
    let mut preserves = false;
    let mut munges = false;
    for argument in arguments
        .iter()
        .filter_map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .take_while(|argument| argument != "--")
    {
        match argument.as_str() {
            "--archive" | "--links" => preserves = true,
            "--munge-links" => munges = true,
            "--no-munge-links" => munges = false,
            "--no-archive"
            | "--no-links"
            | "--no-l"
            | "--copy-links"
            | "--copy-unsafe-links"
            | "--safe-links" => preserves = false,
            "--copy-dirlinks" if directory_carrier => preserves = false,
            _ => {
                let Some(flags) = argument
                    .strip_prefix('-')
                    .filter(|flags| !flags.starts_with('-'))
                else {
                    continue;
                };
                for flag in flags.chars() {
                    match flag {
                        'a' | 'l' => preserves = true,
                        'L' => preserves = false,
                        'k' if directory_carrier => preserves = false,
                        flag if "BefMT@".contains(flag) => break,
                        _ => {}
                    }
                }
            }
        }
    }
    preserves && !munges
}

fn short_option_before_value(argument: &str, needle: char, value_options: &[char]) -> bool {
    let Some(flags) = argument
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))
    else {
        return false;
    };
    for flag in flags.chars() {
        if flag == needle {
            return true;
        }
        if value_options.contains(&flag) {
            return false;
        }
    }
    false
}

fn short_value_option(argument: &str, needle: char) -> Option<bool> {
    let flags = argument
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))?;
    for (index, flag) in flags.char_indices() {
        if flag == needle {
            return Some(index + flag.len_utf8() < flags.len());
        }
        if matches!(flag, 'S' | 't') {
            return None;
        }
    }
    None
}

pub(crate) fn has_unresolved_selection(program: &str, arguments: &[Word]) -> bool {
    if matches!(program, "tar" | "bsdtar") {
        return bash_tar::analyze(program, arguments)
            .is_none_or(|analysis| analysis.unresolved_members);
    }
    let arguments = arguments
        .iter()
        .map(|argument| static_filesystem_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Vec<_>>();
    match program {
        "rsync" => arguments
            .iter()
            .flatten()
            .any(|argument| argument == "--files-from" || argument.starts_with("--files-from=")),
        _ => false,
    }
}

pub(crate) fn recursive_symlink_traversal(program: &str, arguments: &[Word]) -> SymlinkTraversal {
    if matches!(program, "tar" | "bsdtar") {
        return bash_tar::analyze(program, arguments).map_or(SymlinkTraversal::None, |analysis| {
            analysis.symlink_traversal
        });
    }
    let Some(values) = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()
    else {
        return SymlinkTraversal::None;
    };
    match program {
        "cp" => copy_symlink_traversal(&values),
        "scp" => SymlinkTraversal::All,
        "rsync" => {
            if values
                .iter()
                .take_while(|argument| *argument != "--")
                .any(|argument| {
                    matches!(
                        argument.as_str(),
                        "--copy-links" | "--copy-unsafe-links" | "--copy-dirlinks"
                    ) || rsync_argument_has_short_flag(argument, 'L')
                        || rsync_argument_has_short_flag(argument, 'k')
                })
            {
                SymlinkTraversal::All
            } else if rsync_local_source_uses_trailing_slash(&values) {
                SymlinkTraversal::Root
            } else {
                SymlinkTraversal::None
            }
        }
        _ => SymlinkTraversal::None,
    }
}

pub(crate) fn pattern_symlink_traversal(program: &str, arguments: &[Word]) -> SymlinkTraversal {
    match program {
        "ln" | "link" => SymlinkTraversal::None,
        "tar" | "bsdtar" | "rsync" => {
            if recursive_symlink_traversal(program, arguments) != SymlinkTraversal::None {
                SymlinkTraversal::All
            } else {
                SymlinkTraversal::None
            }
        }
        "cp" if arguments.iter().any(|argument| {
            static_word(argument.raw(), argument.substitutions().is_empty()).is_some_and(
                |argument| {
                    argument == "--no-dereference"
                        || argument
                            .strip_prefix('-')
                            .is_some_and(|flags| !flags.starts_with('-') && flags.contains('P'))
                },
            )
        }) =>
        {
            SymlinkTraversal::None
        }
        _ => SymlinkTraversal::All,
    }
}

fn copy_symlink_traversal(arguments: &[String]) -> SymlinkTraversal {
    let mut traversal = SymlinkTraversal::None;
    for argument in arguments.iter().take_while(|argument| *argument != "--") {
        match argument.as_str() {
            "--dereference" => traversal = SymlinkTraversal::All,
            "--no-dereference" => traversal = SymlinkTraversal::None,
            _ => {
                let Some(flags) = argument
                    .strip_prefix('-')
                    .filter(|flags| !flags.starts_with('-'))
                else {
                    continue;
                };
                for flag in flags.chars() {
                    match flag {
                        'H' => traversal = SymlinkTraversal::Root,
                        'L' => traversal = SymlinkTraversal::All,
                        'P' => traversal = SymlinkTraversal::None,
                        _ => {}
                    }
                }
            }
        }
    }
    traversal
}

/// Targets the shell expands before the command sees them. The specs above keep
/// the pattern text, so callers match on the resolved value to tell an expanded
/// target apart from a quoted file that happens to contain the same characters.
pub(crate) fn pattern_targets(arguments: &[Word]) -> Vec<String> {
    arguments
        .iter()
        .filter(|argument| {
            argument.substitutions().is_empty() && contains_unquoted_pattern(argument.raw())
        })
        .filter_map(|argument| static_filesystem_word(argument.raw(), true))
        .flat_map(|value| {
            // `dd` and its relatives carry the path in an `operand=path` word.
            let operand = value.split_once('=').map(|(_, path)| path.to_owned());
            std::iter::once(value).chain(operand)
        })
        .collect()
}

pub(crate) fn has_dynamic_target(arguments: &[Word]) -> bool {
    arguments.iter().any(|argument| {
        !argument.substitutions().is_empty() || static_word(argument.raw(), true).is_none()
    })
}

pub(crate) fn has_dynamic_content_selection(program: &str, arguments: &[Word]) -> bool {
    if let Some(analysis) = bash_transforms::analyze(program, arguments) {
        return analysis.unresolved_read;
    }
    has_dynamic_target(arguments)
        && matches!(
            program,
            "awk"
                | "base64"
                | "bsdtar"
                | "cat"
                | "cp"
                | "dd"
                | "head"
                | "install"
                | "less"
                | "link"
                | "ln"
                | "more"
                | "mv"
                | "rsync"
                | "scp"
                | "sed"
                | "sort"
                | "strings"
                | "tac"
                | "tail"
                | "tar"
                | "uniq"
                | "wc"
                | "xxd"
        )
}

#[cfg(test)]
mod tests {
    use super::{creates_descriptor_symlink, transformed_descriptor_symlink_source};
    use crate::bash_model::{ResolvedWord, UnresolvedCause};
    use nah_parse::Word;

    fn words(arguments: &[&str]) -> Vec<Word> {
        arguments
            .iter()
            .map(|argument| Word::from_literal(argument))
            .collect()
    }

    fn resolutions(
        len: usize,
        transformed_index: usize,
        cause: UnresolvedCause,
        literal_prefix: &str,
    ) -> Vec<ResolvedWord> {
        (0..len)
            .map(|index| {
                if index == transformed_index {
                    ResolvedWord::Unresolved {
                        literal_prefix: literal_prefix.to_owned(),
                        may_be_absolute: true,
                        cause,
                    }
                } else {
                    ResolvedWord::Static {
                        value: String::new(),
                        changed: false,
                    }
                }
            })
            .collect()
    }

    #[test]
    fn exact_descriptor_symlink_carriers_are_refused_at_creation() {
        for (program, arguments) in [
            ("ln", vec!["-s", "/dev/fd/3", "carrier"]),
            ("ln", vec!["--symbolic", "/proc/self/fd/$fd", "carrier"]),
            ("ln", vec!["-s", "/dev/fd", "carrier"]),
            ("ln", vec!["-st", ".", "/dev/fd/3"]),
            ("cp", vec!["-s", "/dev/fd/3", "carrier"]),
            ("cp", vec!["--symbolic-link", "/proc/$$/fd/3", "carrier"]),
            ("cp", vec!["-P", "/dev/fd", "carrier"]),
            ("cp", vec!["--no-dereference", "/dev/stdin", "carrier"]),
            ("cp", vec!["-a", "/dev/fd", "carrier"]),
            ("cp", vec!["-R", "/dev/fd", "carrier"]),
            ("cp", vec!["--recursive", "/dev/fd", "carrier"]),
            ("rsync", vec!["-l", "/dev/fd", "carrier"]),
            ("rsync", vec!["--archive", "/dev/stdin", "carrier"]),
            (
                "rsync",
                vec![
                    "--archive",
                    "--munge-links",
                    "--no-munge-links",
                    "/dev/fd",
                    "carrier",
                ],
            ),
            ("ln", vec!["-s", "ordinary", "/dev/fd", "carrier-dir"]),
            ("ln", vec!["-s", "--", "ordinary", "/dev/fd", "carrier-dir"]),
            ("cp", vec!["-a", "ordinary", "/dev/fd", "carrier-dir"]),
            ("cp", vec!["-at", "carrier-dir", "ordinary", "/dev/fd"]),
            ("rsync", vec!["-a", "ordinary", "/dev/fd", "carrier-dir"]),
            (
                "tar",
                vec!["-cf", "carrier.tar", "--no-recursion", "-C", "/", "dev/fd"],
            ),
            ("bsdtar", vec!["-cf", "carrier.tar", "/dev/fd"]),
            ("zip", vec!["-y", "carrier.zip", "/dev/fd"]),
            ("zip", vec!["--symlinks", "carrier.zip", "/dev/stdin"]),
            ("zip", vec!["-qy", "carrier.zip", "/dev/fd"]),
        ] {
            assert!(
                creates_descriptor_symlink(program, &words(&arguments)),
                "{program} {arguments:?}"
            );
        }
    }

    #[test]
    fn non_carriers_and_dereferenced_sources_are_not_refused() {
        for (program, arguments) in [
            ("ln", vec!["-s", "ordinary", "link"]),
            ("ln", vec!["/dev/fd/3", "hard-link"]),
            ("ln", vec!["-Ssuffix", "ordinary", "link"]),
            ("ln", vec!["-s", "/proc/1/fd/$fd", "link"]),
            ("ln", vec!["-s", "ordinary", "another", "link-dir"]),
            ("ln", vec!["-st", "link-dir", "ordinary", "another"]),
            ("cp", vec!["-P", "/dev/fd/3", "copy"]),
            ("cp", vec!["ordinary", "copy"]),
            ("cp", vec!["-a", "ordinary", "another", "copy-dir"]),
            ("cp", vec!["-P", "-L", "/dev/fd", "copy"]),
            ("cp", vec!["-RL", "/dev/fd", "copy"]),
            ("cp", vec!["-RH", "/dev/fd", "copy"]),
            ("rsync", vec!["ordinary", "copy"]),
            ("rsync", vec!["-a", "ordinary", "another", "copy-dir"]),
            ("rsync", vec!["-lL", "/dev/fd", "copy"]),
            ("rsync", vec!["-a", "--copy-links", "/dev/stdin", "copy"]),
            ("rsync", vec!["-a", "--munge-links", "/dev/fd", "copy"]),
            ("rsync", vec!["-l", "/proc/1/fd/$fd", "copy"]),
            (
                "tar",
                vec!["-chf", "carrier.tar", "--no-recursion", "/dev/fd"],
            ),
            ("tar", vec!["-cf", "carrier.tar", "/dev/fd/3"]),
            ("zip", vec!["carrier.zip", "/dev/fd"]),
            ("zip", vec!["-y", "carrier.zip", "/dev/fd/3"]),
            ("zip", vec!["-Pmy", "carrier.zip", "/dev/fd"]),
            ("zip", vec!["-lfmy.log", "carrier.zip", "/dev/fd"]),
        ] {
            assert!(
                !creates_descriptor_symlink(program, &words(&arguments)),
                "{program} {arguments:?}"
            );
        }
    }

    #[test]
    fn transformed_carrier_sources_refuse_without_claiming_destinations() {
        for (program, arguments, transformed_index) in [
            ("ln", vec!["-s", "${SRC%x}", "carrier"], 1),
            ("cp", vec!["-a", "${SRC%x}", "carrier"], 1),
            (
                "tar",
                vec!["-cf", "carrier.tar", "--no-recursion", "${SRC%x}"],
                3,
            ),
            ("zip", vec!["-y", "carrier.zip", "${SRC%x}"], 2),
        ] {
            let arguments = words(&arguments);
            let resolutions = resolutions(
                arguments.len(),
                transformed_index,
                UnresolvedCause::ShellTransformation,
                "",
            );
            assert!(
                transformed_descriptor_symlink_source(program, &arguments, &resolutions),
                "{program}: {arguments:?}"
            );
        }

        let direct = words(&["-f", "carrier.tar", "${SRC%x}"]);
        let tar_resolutions =
            resolutions(direct.len(), 2, UnresolvedCause::ShellTransformation, "");
        assert!(transformed_descriptor_symlink_source(
            "tar",
            &words(&["--create", "-f", "carrier.tar", "${SRC%x}"]),
            &tar_resolutions,
        ));
        assert!(!transformed_descriptor_symlink_source(
            "tar",
            &words(&["--create", "--dereference", "-f", "carrier.tar", "${SRC%x}",]),
            &tar_resolutions,
        ));

        for (program, arguments, transformed_index, cause, literal_prefix) in [
            (
                "ln",
                vec!["-s", "ordinary", "${DEST%x}"],
                2,
                UnresolvedCause::ShellTransformation,
                "",
            ),
            (
                "tar",
                vec!["-cf", "${ARCHIVE%x}", "ordinary"],
                1,
                UnresolvedCause::ShellTransformation,
                "",
            ),
            (
                "cp",
                vec!["-a", "${SRC}", "carrier"],
                1,
                UnresolvedCause::UnknownValue,
                "",
            ),
            (
                "cp",
                vec!["-a", "ordinary/${SRC%x}", "carrier"],
                1,
                UnresolvedCause::ShellTransformation,
                "ordinary/",
            ),
            (
                "tar",
                vec!["-chf", "carrier.tar", "${SRC%x}"],
                2,
                UnresolvedCause::ShellTransformation,
                "",
            ),
            (
                "zip",
                vec!["carrier.zip", "${SRC%x}"],
                1,
                UnresolvedCause::ShellTransformation,
                "",
            ),
        ] {
            let arguments = words(&arguments);
            let resolutions =
                resolutions(arguments.len(), transformed_index, cause, literal_prefix);
            assert!(
                !transformed_descriptor_symlink_source(program, &arguments, &resolutions),
                "{program}: {arguments:?}"
            );
        }
    }
}
