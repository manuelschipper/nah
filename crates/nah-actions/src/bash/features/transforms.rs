//! Lowers compression, ZIP, and OpenSSL file transforms into filesystem effects.

use crate::shell_word::{static_filesystem_word, static_word};
use nah_parse::Word;
use nah_proto::action::FilesystemOperation;

use crate::bash_descriptor_paths::preserved_descriptor_symlink_carrier;
use crate::bash_model::FilesystemSpec;

#[derive(Default)]
pub(crate) struct TransformAnalysis {
    pub(crate) filesystems: Vec<FilesystemSpec>,
    pub(crate) unresolved_read: bool,
    pub(crate) descriptor_symlink_carrier: bool,
}

pub(crate) fn analyze(program: &str, arguments: &[Word]) -> Option<TransformAnalysis> {
    match program {
        "gzip" | "bzip2" | "xz" => Some(compression_analysis(program, arguments)),
        "zip" => Some(zip_analysis(arguments)),
        "openssl" => Some(openssl_analysis(arguments)),
        _ => None,
    }
}

fn compression_analysis(program: &str, arguments: &[Word]) -> TransformAnalysis {
    let mut analysis = TransformAnalysis::default();
    let mut inputs = Vec::new();
    let mut after_options = false;
    let mut decompress = false;
    let mut to_stdout = false;
    let mut no_output = false;
    let mut suffix_override: Option<Option<String>> = None;
    let mut xz_format: Option<Option<String>> = None;
    let mut output_mode_known = true;
    let mut index = 0;
    while index < arguments.len() {
        let word = &arguments[index];
        let argument = static_filesystem_word(word.raw(), word.substitutions().is_empty());
        index += 1;

        if after_options {
            match argument.as_deref() {
                Some("-") => {}
                Some(argument) => inputs.push(argument.to_owned()),
                None => analysis.unresolved_read = true,
            }
            continue;
        }

        let Some(argument) = argument.as_deref() else {
            if compression_dynamic_suffix(word.raw()) {
                suffix_override = Some(None);
            } else if program == "xz" && compression_dynamic_format(word.raw()) {
                xz_format = Some(None);
            } else if raw_dynamic_option(word.raw()).starts_with('-') {
                output_mode_known = false;
            } else {
                analysis.unresolved_read = true;
            }
            continue;
        };
        if argument == "--" {
            after_options = true;
        } else if matches!(argument, "-h" | "--help" | "--version")
            || matches!(argument, "-L" | "-V") && matches!(program, "gzip" | "bzip2" | "xz")
            || program == "xz" && argument == "-H"
        {
            return TransformAnalysis::default();
        } else if matches!(argument, "-c" | "--stdout" | "--to-stdout") {
            to_stdout = true;
        } else if matches!(argument, "-d" | "--decompress" | "--uncompress") {
            decompress = true;
        } else if matches!(argument, "-z" | "--compress") {
            decompress = false;
        } else if matches!(argument, "-t" | "--test")
            || matches!(program, "gzip" | "xz") && matches!(argument, "-l" | "--list")
        {
            no_output = true;
        } else if matches!(argument, "-S" | "--suffix") {
            suffix_override = Some(arguments.get(index).and_then(|word| {
                static_filesystem_word(word.raw(), word.substitutions().is_empty())
            }));
            index += 1;
        } else if let Some(suffix) = argument.strip_prefix("--suffix=") {
            suffix_override = Some(Some(suffix.to_owned()));
        } else if argument.starts_with("-S") && argument.len() > 2 {
            suffix_override = Some(Some(argument[2..].to_owned()));
        } else if program == "xz" && matches!(argument, "-F" | "--format") {
            xz_format = Some(
                arguments
                    .get(index)
                    .and_then(|word| static_word(word.raw(), word.substitutions().is_empty())),
            );
            index += 1;
        } else if program == "xz" && argument.starts_with("-F") && argument.len() > 2 {
            xz_format = Some(Some(argument[2..].to_owned()));
        } else if program == "xz"
            && let Some(format) = argument.strip_prefix("--format=")
        {
            xz_format = Some(Some(format.to_owned()));
        } else if compression_option_takes_value(program, argument) {
            index += 1;
        } else if compression_has_attached_option_value(program, argument) {
        } else if let Some(flags) = argument
            .strip_prefix('-')
            .filter(|flags| !flags.is_empty() && !flags.starts_with('-'))
        {
            for (flag_index, flag) in flags.char_indices() {
                if flag == 'S' && matches!(program, "gzip" | "xz") {
                    suffix_override = Some(if flag_index + 1 < flags.len() {
                        Some(flags[flag_index + 1..].to_owned())
                    } else {
                        let suffix = arguments.get(index).and_then(|word| {
                            static_filesystem_word(word.raw(), word.substitutions().is_empty())
                        });
                        index += 1;
                        suffix
                    });
                    break;
                }
                match flag {
                    'c' => to_stdout = true,
                    'd' => decompress = true,
                    'z' => decompress = false,
                    't' => no_output = true,
                    'l' if matches!(program, "gzip" | "xz") => no_output = true,
                    _ => {}
                }
            }
        } else if argument != "-" {
            inputs.push(argument.to_owned());
        }
    }

    for input in inputs {
        analysis
            .filesystems
            .push((input.clone(), FilesystemOperation::Read, false));
        if to_stdout || no_output || !output_mode_known {
            continue;
        }
        let output = if decompress {
            decompressed_target(
                program,
                &input,
                suffix_override.as_ref(),
                xz_format.as_ref(),
            )
        } else {
            compressed_target(
                program,
                &input,
                suffix_override.as_ref(),
                xz_format.as_ref(),
            )
        };
        if let Some(output) = output {
            analysis
                .filesystems
                .push((output, FilesystemOperation::Write, false));
        }
    }
    analysis
}

fn compression_option_takes_value(program: &str, argument: &str) -> bool {
    match program {
        "gzip" => matches!(argument, "-b" | "--bits"),
        "xz" => matches!(
            argument,
            "-C" | "--check"
                | "-M"
                | "--memlimit"
                | "--memlimit-compress"
                | "--memlimit-decompress"
                | "-S"
                | "--suffix"
                | "-T"
                | "--threads"
        ),
        _ => false,
    }
}

fn compression_has_attached_option_value(program: &str, argument: &str) -> bool {
    let options: &[&str] = match program {
        "gzip" => &["-b"],
        "xz" => &["-C", "-M", "-T"],
        _ => &[],
    };
    options
        .iter()
        .any(|option| argument.starts_with(option) && argument.len() > option.len())
}

fn compression_dynamic_suffix(raw: &str) -> bool {
    let raw = raw_dynamic_option(raw);
    raw.starts_with("--suffix=") || raw.starts_with("-S") && raw.len() > 2
}

fn compression_dynamic_format(raw: &str) -> bool {
    let raw = raw_dynamic_option(raw);
    raw.starts_with("--format=") || raw.starts_with("-F") && raw.len() > 2
}

fn raw_dynamic_option(raw: &str) -> &str {
    raw.strip_prefix('"').unwrap_or(raw)
}

fn compressed_target(
    program: &str,
    input: &str,
    suffix_override: Option<&Option<String>>,
    xz_format: Option<&Option<String>>,
) -> Option<String> {
    let suffix = match suffix_override {
        Some(Some(suffix)) if !suffix.is_empty() => suffix.as_str(),
        Some(_) => return None,
        None => match (program, xz_format) {
            ("gzip", _) => ".gz",
            ("bzip2", _) => ".bz2",
            ("xz", Some(Some(format))) if format == "lzma" => ".lzma",
            ("xz", Some(Some(format))) if format == "raw" => return None,
            ("xz", Some(Some(format))) if matches!(format.as_str(), "auto" | "xz") => ".xz",
            ("xz", Some(Some(_))) => return None,
            ("xz", Some(None)) => return None,
            ("xz", _) => ".xz",
            _ => return None,
        },
    };
    (!input.ends_with(suffix)).then(|| format!("{input}{suffix}"))
}

fn decompressed_target(
    program: &str,
    input: &str,
    suffix_override: Option<&Option<String>>,
    xz_format: Option<&Option<String>>,
) -> Option<String> {
    if let Some(suffix) = suffix_override {
        return suffix
            .as_deref()
            .filter(|suffix| !suffix.is_empty())
            .and_then(|suffix| input.strip_suffix(suffix))
            .map(str::to_owned);
    }
    let suffixes: &[(&str, &str)] = match (program, xz_format) {
        ("gzip", _) => &[(".tgz", ".tar"), (".taz", ".tar"), (".gz", "")],
        ("bzip2", _) => &[
            (".tbz2", ".tar"),
            (".tbz", ".tar"),
            (".bz2", ""),
            (".bz", ""),
        ],
        ("xz", Some(Some(format))) if format == "raw" => return None,
        ("xz", Some(Some(format))) if format == "lzma" => &[(".lzma", "")],
        ("xz", Some(Some(format))) if matches!(format.as_str(), "auto" | "xz") => {
            &[(".txz", ".tar"), (".xz", "")]
        }
        ("xz", Some(Some(_))) => return None,
        ("xz", Some(None)) => return None,
        ("xz", _) => &[(".txz", ".tar"), (".xz", ""), (".lzma", "")],
        _ => return None,
    };
    suffixes.iter().find_map(|(suffix, replacement)| {
        input
            .strip_suffix(suffix)
            .map(|stem| format!("{stem}{replacement}"))
    })
}

fn zip_analysis(arguments: &[Word]) -> TransformAnalysis {
    let mut analysis = TransformAnalysis::default();
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut recursive = false;
    let mut preserves_symlinks = false;
    let mut index = 0;
    while index < arguments.len() {
        let word = &arguments[index];
        let argument = static_filesystem_word(word.raw(), word.substitutions().is_empty());
        index += 1;
        match argument.as_deref() {
            Some("--") if !after_options => after_options = true,
            Some("-r" | "--recurse-paths") if !after_options => recursive = true,
            Some(argument) if !after_options && zip_option_preserves_symlinks(argument) => {
                preserves_symlinks = true;
            }
            Some("-@") if !after_options => analysis.unresolved_read = true,
            Some(argument) if !after_options && zip_option_takes_value(argument) => index += 1,
            Some("-h" | "-?" | "--help" | "--version") if !after_options => {
                return TransformAnalysis::default();
            }
            Some(argument) if !after_options && argument.starts_with('-') => {}
            Some(argument) => operands.push(Some(argument.to_owned())),
            None if !after_options && zip_dynamic_option(word.raw()) => {}
            None => operands.push(None),
        }
    }
    let mut operands = operands.into_iter();
    let archive = operands.next().flatten();
    analysis.filesystems = archive
        .as_deref()
        .filter(|target| *target != "-")
        .map(|target| (target.to_owned(), FilesystemOperation::Write, false))
        .into_iter()
        .collect::<Vec<_>>();
    for member in operands {
        match member.as_deref() {
            Some("-") => {}
            Some(member) => {
                analysis.descriptor_symlink_carrier |=
                    preserves_symlinks && preserved_descriptor_symlink_carrier(member);
                analysis
                    .filesystems
                    .push((member.to_owned(), FilesystemOperation::Read, recursive))
            }
            None => analysis.unresolved_read = true,
        }
    }
    analysis
}

fn zip_option_preserves_symlinks(argument: &str) -> bool {
    if argument == "--symlinks" {
        return true;
    }
    let Some(flags) = argument
        .strip_prefix('-')
        .filter(|flags| !flags.is_empty() && !flags.starts_with('-'))
    else {
        return false;
    };
    let mut offset = 0;
    while offset < flags.len() {
        let remaining = &flags[offset..];
        if ["ds", "lf", "TT", "UN"]
            .iter()
            .any(|option| remaining.starts_with(option))
        {
            return false;
        }
        if let Some(option) = [
            "db", "dc", "dd", "dg", "du", "dv", "DF", "FF", "FI", "FS", "fd", "fz", "la", "li",
            "ll", "MM", "nw", "RE", "sp", "sv", "sb", "sc", "sd", "sf", "so", "su", "sU", "ws",
        ]
        .into_iter()
        .find(|option| remaining.starts_with(option))
        {
            offset += option.len();
            continue;
        }
        let flag = remaining
            .chars()
            .next()
            .expect("non-empty option remainder");
        if flag == 'y' {
            return true;
        }
        if matches!(flag, 'b' | 'i' | 'n' | 'O' | 'P' | 's' | 't' | 'x' | 'Z') {
            return false;
        }
        offset += flag.len_utf8();
    }
    false
}

fn zip_dynamic_option(raw: &str) -> bool {
    let raw = raw_dynamic_option(raw);
    raw.starts_with('-')
}

fn zip_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "-b" | "--temp-path"
            | "-n"
            | "--suffixes"
            | "-P"
            | "--password"
            | "-s"
            | "--split-size"
            | "-t"
            | "--from-date"
            | "-tt"
            | "--before-date"
    )
}

fn openssl_analysis(arguments: &[Word]) -> TransformAnalysis {
    let mut analysis = TransformAnalysis::default();
    let mut index = 0;
    while index < arguments.len() {
        let word = &arguments[index];
        let argument = static_filesystem_word(word.raw(), word.substitutions().is_empty());
        index += 1;
        let Some(argument) = argument.as_deref() else {
            if raw_dynamic_option(word.raw()).starts_with("-in=") {
                analysis.unresolved_read = true;
            }
            continue;
        };
        if matches!(argument, "help" | "-help" | "--help") {
            return TransformAnalysis::default();
        }
        let (operation, attached) = if argument == "-in" {
            (Some(FilesystemOperation::Read), None)
        } else if argument == "-out" {
            (Some(FilesystemOperation::Write), None)
        } else if let Some(target) = argument.strip_prefix("-in=") {
            (Some(FilesystemOperation::Read), Some(target))
        } else if let Some(target) = argument.strip_prefix("-out=") {
            (Some(FilesystemOperation::Write), Some(target))
        } else {
            (None, None)
        };
        let Some(operation) = operation else {
            continue;
        };
        let target = if let Some(target) = attached {
            Some(target.to_owned())
        } else {
            let target = arguments.get(index).and_then(|word| {
                static_filesystem_word(word.raw(), word.substitutions().is_empty())
            });
            if operation == FilesystemOperation::Read && target.is_none() {
                analysis.unresolved_read = true;
            }
            index += 1;
            target
        };
        if let Some(target) = target.filter(|target| target != "-") {
            analysis.filesystems.push((target, operation, false));
        }
    }
    analysis
}
