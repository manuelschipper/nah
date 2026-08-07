use crate::syntax::contains_call;

fn contains_command_alias(source: &str, aliases: &[&str]) -> bool {
    source
        .split(['|', '&', '{', '}'])
        .map(str::trim_start)
        .any(|command| {
            aliases.iter().any(|alias| {
                command
                    .strip_prefix(alias)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
            })
        })
}

fn contains_word(source: &str, word: &str) -> bool {
    source.match_indices(word).any(|(index, _)| {
        let identifier = |character: char| character.is_ascii_alphanumeric() || character == '_';
        !source[..index].chars().next_back().is_some_and(identifier)
            && !source[index + word.len()..]
                .chars()
                .next()
                .is_some_and(identifier)
    })
}

pub(super) fn write_mode(strings: &[String]) -> bool {
    strings.iter().any(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "w" | "wb"
                | "w+"
                | "wb+"
                | "w+b"
                | "a"
                | "ab"
                | "a+"
                | "ab+"
                | "a+b"
                | "x"
                | "xb"
                | "x+"
                | "xb+"
                | "x+b"
                | "c"
                | "c+"
                | ">"
                | ">>"
                | "+>"
        ) || value.starts_with(">:")
    })
}

pub(super) fn mutation_action(
    program: &str,
    outside: &str,
    strings: &[String],
    backtick_exec: bool,
) -> bool {
    let contains_any = |needles: &[&str]| needles.iter().any(|needle| outside.contains(needle));
    let contains_calls =
        |names: &[&str]| names.iter().any(|name| contains_call(outside, name, false));
    let contains_bare_calls =
        |names: &[&str]| names.iter().any(|name| contains_call(outside, name, true));
    let language_action = match program {
        "perl" => {
            contains_any(&[
                "unlink ",
                "link ",
                "symlink ",
                "rename ",
                "rmdir ",
                "mkdir ",
                "chmod ",
                "chown ",
                "truncate ",
                "system ",
                "exec ",
            ]) || contains_bare_calls(&[
                "unlink",
                "link",
                "symlink",
                "rename",
                "rmdir",
                "mkdir",
                "chmod",
                "chown",
                "truncate",
                "move",
                "remove_tree",
                "rmtree",
                "make_path",
                "system",
                "exec",
            ]) || (contains_bare_calls(&["sysopen"])
                && contains_any(&["o_wronly", "o_rdwr", "o_append", "o_creat", "o_trunc"]))
        }
        "node" | "nodejs" => {
            contains_calls(&[
                ".remove",
                ".unlink",
                ".unlinksync",
                ".rename",
                ".renamesync",
                ".rm",
                ".rmsync",
                ".writefile",
                ".writefilesync",
                ".appendfile",
                ".appendfilesync",
                ".createwritestream",
                ".link",
                ".linksync",
                ".symlink",
                ".symlinksync",
                ".truncate",
                ".truncatesync",
                ".chmod",
                ".chmodsync",
                ".chown",
                ".chownsync",
                ".mkdir",
                ".mkdirsync",
                "child_process.exec",
                "child_process.spawn",
            ]) || contains_bare_calls(&[
                "remove",
                "unlink",
                "unlinksync",
                "rename",
                "renamesync",
                "rm",
                "rmsync",
                "writefile",
                "writefilesync",
                "appendfile",
                "appendfilesync",
                "createwritestream",
                "link",
                "linksync",
                "symlink",
                "symlinksync",
                "truncate",
                "truncatesync",
                "chmod",
                "chmodsync",
                "chown",
                "chownsync",
                "mkdir",
                "mkdirsync",
            ]) || ((contains_calls(&[".open", ".opensync"])
                || contains_bare_calls(&["open", "opensync"]))
                && write_mode(strings))
                || strings
                    .iter()
                    .any(|value| matches!(value.as_str(), "child_process" | "node:child_process"))
                    && contains_calls(&[".exec", ".execfile", ".fork", ".spawn"])
        }
        "ruby" => {
            contains_calls(&[
                "file.delete",
                "file.unlink",
                "file.rename",
                "file.link",
                "file.symlink",
                "file.truncate",
                "file.write",
                "io.write",
                "fileutils.rm",
                "fileutils.rm_rf",
                "fileutils.mv",
                "dir.mkdir",
                "spawn",
            ]) || contains_any(&["system ", "exec "])
                || contains_bare_calls(&["system", "exec"])
        }
        "php" => contains_bare_calls(&[
            "unlink",
            "rename",
            "rmdir",
            "mkdir",
            "chmod",
            "chown",
            "touch",
            "link",
            "symlink",
            "file_put_contents",
            "exec",
            "system",
        ]),
        "lua" => {
            contains_calls(&["os.remove", "os.rename", "os.execute"])
                || contains_calls(&["io.open"]) && write_mode(strings)
        }
        "r" | "rscript" => contains_calls(&[
            "file.remove",
            "unlink",
            "file.rename",
            "file.create",
            "dir.create",
            "writelines",
            "system",
            "system2",
        ]),
        "julia" => {
            contains_bare_calls(&["rm", "mv", "touch", "mkdir", "mkpath", "chmod", "run"])
                || contains_bare_calls(&["open"]) && write_mode(strings)
        }
        "swift" => contains_calls(&[
            ".removeitem",
            ".moveitem",
            ".createfile",
            ".createdirectory",
            ".setattributes",
        ]),
        "powershell" | "pwsh" => {
            contains_any(&[
                "remove-item",
                "move-item",
                "rename-item",
                "set-content",
                "clear-content",
                "out-file",
                "start-process",
            ]) || contains_command_alias(
                outside,
                &[
                    "rm", "del", "erase", "rd", "rmdir", "ri", "mv", "move", "mi", "ren", "rni",
                ],
            ) || outside.contains("new-item") && outside.contains("hardlink")
        }
        "cmd" => {
            contains_any(&[
                "del ",
                "erase ",
                "move ",
                "rename ",
                "copy ",
                "xcopy ",
                "robocopy ",
            ]) || outside.contains("mklink") && outside.contains("/h")
        }
        _ => false,
    };
    let destructive_open = match program {
        "perl" => {
            (contains_bare_calls(&["open"]) || contains_word(outside, "open"))
                && write_mode(strings)
        }
        "ruby" => {
            (contains_bare_calls(&["open"]) || contains_calls(&["file.open", "io.open"]))
                && write_mode(strings)
        }
        "php" => contains_bare_calls(&["fopen"]) && write_mode(strings),
        _ => false,
    };
    language_action
        || destructive_open
        || backtick_exec
            && strings.iter().any(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("rm ") || value.contains("unlink ") || value.contains("nah hook ")
            })
}
