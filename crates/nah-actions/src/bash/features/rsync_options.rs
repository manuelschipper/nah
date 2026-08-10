//! Owns rsync option spelling and operand-boundary rules.

pub(crate) fn rsync_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "-B" | "-e"
            | "-f"
            | "-M"
            | "-T"
            | "-@"
            | "--address"
            | "--backup-dir"
            | "--block-size"
            | "--bwlimit"
            | "--checksum-choice"
            | "--checksum-seed"
            | "--chmod"
            | "--chown"
            | "--compare-dest"
            | "--compress-choice"
            | "--compress-level"
            | "--contimeout"
            | "--copy-as"
            | "--copy-dest"
            | "--debug"
            | "--early-input"
            | "--exclude"
            | "--exclude-from"
            | "--files-from"
            | "--filter"
            | "--groupmap"
            | "--iconv"
            | "--include"
            | "--include-from"
            | "--info"
            | "--link-dest"
            | "--log-file"
            | "--log-file-format"
            | "--max-alloc"
            | "--max-delete"
            | "--max-size"
            | "--min-size"
            | "--modify-window"
            | "--only-write-batch"
            | "--out-format"
            | "--outbuf"
            | "--partial-dir"
            | "--password-file"
            | "--port"
            | "--protocol"
            | "--read-batch"
            | "--remote-option"
            | "--rsh"
            | "--rsync-path"
            | "--skip-compress"
            | "--sockopts"
            | "--stderr"
            | "--stop-after"
            | "--stop-at"
            | "--suffix"
            | "--temp-dir"
            | "--timeout"
            | "--usermap"
            | "--write-batch"
    )
}

pub(crate) fn rsync_argument_has_short_flag(argument: &str, expected: char) -> bool {
    let Some(flags) = argument
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))
    else {
        return false;
    };
    for flag in flags.chars() {
        if flag == expected {
            return true;
        }
        if "BefMT@".contains(flag) {
            break;
        }
    }
    false
}

pub(crate) fn rsync_local_source_uses_trailing_slash(arguments: &[String]) -> bool {
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if !after_options && argument == "--" {
            after_options = true;
        } else if !after_options && rsync_option_takes_value(argument) {
            index += 2;
            continue;
        } else if !after_options && argument.starts_with('-') {
        } else {
            operands.push(argument);
        }
        index += 1;
    }
    operands.split_last().is_some_and(|(_, sources)| {
        sources
            .iter()
            .any(|source| source.ends_with(['/', '\\']) && !source.contains(':'))
    })
}
