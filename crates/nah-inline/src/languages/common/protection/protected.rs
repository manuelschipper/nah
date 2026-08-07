use nah_proto::ctx::{AbsolutePath, Platform};

use crate::{EnvironmentValue, normalized_program};

use super::support::{
    EnvironmentVariables, environment_operation, protected_path, runtime_launch_bypass,
    runtime_launch_program, runtime_name,
};

pub(super) fn protected_target(
    outside: &str,
    strings: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    inline_runtime: bool,
    baseline_variables: &[(String, EnvironmentValue)],
) -> bool {
    let joined = strings.join(" ");
    let concatenated = strings.concat();
    let mut path_candidates = strings
        .iter()
        .map(String::as_str)
        .chain([joined.as_str(), concatenated.as_str()])
        .collect::<Vec<_>>();
    path_candidates.extend(outside.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(
                character,
                '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '=' | '"' | '\''
            )
    }));
    if path_candidates
        .iter()
        .any(|path| protected_path(path, home, critical_paths, platform))
    {
        return true;
    }
    let mut visible = format!("{outside} {joined} {concatenated}").replace('\\', "/");
    if platform == Platform::Windows {
        visible.make_ascii_lowercase();
    }
    let mut targets = critical_paths
        .iter()
        .map(|path| path.as_str().replace('\\', "/"))
        .collect::<Vec<_>>();
    targets.extend([
        format!("{home}/.nah"),
        format!("{home}/.local/bin/nah"),
        format!("{home}/.cargo/bin/nah"),
        "/usr/local/bin/nah".into(),
        "/usr/bin/nah".into(),
    ]);
    for target in &mut targets {
        *target = target.replace('\\', "/");
    }
    if platform == Platform::Windows {
        for target in &mut targets {
            target.make_ascii_lowercase();
        }
    }
    if targets.iter().any(|target| visible.contains(target)) {
        return true;
    }

    let normalized_home = home.replace('\\', "/");
    let home_reference = [
        "path.home",
        "expanduser",
        "homedir",
        "process.env.home",
        "env[",
        "$env{home}",
        "$env:home",
        "$home",
        "${home}",
    ]
    .iter()
    .any(|marker| visible.to_ascii_lowercase().contains(marker))
        || strings
            .iter()
            .any(|value| value.eq_ignore_ascii_case("home"))
            && ["getenv", "environ.get", "env.fetch", "sys.getenv", "$env{"]
                .iter()
                .any(|marker| outside.contains(marker));
    if home_reference
        && path_candidates.iter().any(|path| {
            let lowercase = path.to_ascii_lowercase();
            let relative = [
                "~",
                "$home",
                "$env:home",
                "$env{home}",
                "process.env.home",
                "path.home()",
                "${home}",
            ]
            .iter()
            .find_map(|prefix| lowercase.starts_with(prefix).then(|| &path[prefix.len()..]))
            .unwrap_or(path)
            .trim_start_matches(['/', '\\']);
            protected_path(
                &format!("{home}/{relative}"),
                home,
                critical_paths,
                platform,
            )
        })
    {
        return true;
    }
    if home_reference
        && targets.iter().any(|target| {
            target
                .strip_prefix(&normalized_home)
                .map(|relative| relative.trim_start_matches('/'))
                .is_some_and(|relative| !relative.is_empty() && visible.contains(relative))
        })
    {
        return true;
    }

    let words = visible
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let lifecycle = words.windows(4).any(|parts| {
        parts[0] == "nah"
            && parts[1] == "hook"
            && runtime_name(&parts[2])
            && matches!(parts[3].as_str(), "install" | "uninstall")
    });
    let which_nah = (outside.contains("which(")
        || outside.contains("shutil.which")
        || outside.contains("where("))
        && strings.iter().any(|value| value == "nah");
    lifecycle
        || which_nah
        || inline_runtime
            && inline_runtime_bypass(strings, home, critical_paths, platform, baseline_variables)
}

pub(super) fn inline_runtime_bypass(
    strings: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> bool {
    let ignored_prefix = |value: &str| {
        matches!(
            value,
            "fs" | "node:fs" | "child_process" | "node:child_process"
        )
    };
    let start = strings
        .iter()
        .position(|value| !ignored_prefix(value))
        .unwrap_or(strings.len());
    let words = strings[start..]
        .iter()
        .flat_map(|value| value.split_ascii_whitespace())
        .map(|value| {
            value.trim_matches(|character: char| {
                matches!(character, '[' | ']' | '(' | ')' | ',' | ';')
            })
        })
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    inline_runtime_words(&words, home, critical_paths, platform, baseline_variables)
}

fn inline_runtime_words(
    words: &[String],
    home: &str,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    baseline_variables: &[(String, EnvironmentValue)],
) -> bool {
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    let program = normalized_program(program);
    if matches!(program.as_str(), "bash" | "sh")
        && arguments.first().is_some_and(|word| word == "-c")
    {
        return inline_runtime_words(
            &arguments[1..],
            home,
            critical_paths,
            platform,
            baseline_variables,
        );
    }
    if runtime_launch_bypass(&program, arguments, Some(home), Some(platform)) {
        return true;
    }
    let mut assignments = Vec::new();
    let mut index = usize::from(program == "env");
    if program == "env" {
        while let Some(word) = words.get(index) {
            if matches!(word.as_str(), "-i" | "--ignore-environment" | "--") {
                index += 1;
            } else if matches!(word.as_str(), "-u" | "--unset") {
                index += 2;
            } else if word.starts_with("--unset=") {
                index += 1;
            } else {
                break;
            }
        }
    }
    while let Some(word) = words.get(index) {
        let Some((name, value)) = word.split_once('=') else {
            break;
        };
        assignments.push((name.to_owned(), Some(value.to_owned())));
        index += 1;
    }
    words.get(index).is_some_and(|program| {
        environment_operation(
            program,
            &words[index + 1..],
            &assignments,
            EnvironmentVariables {
                visible: &[],
                runtime: baseline_variables,
            },
            home,
            critical_paths,
            platform,
        )
        .is_some()
    })
}

pub(super) fn inline_direct_runtime_bypass(
    outside: &str,
    strings: &[String],
    string_offsets: &[usize],
    program: &str,
    home: &str,
    platform: Platform,
) -> bool {
    if !matches!(program, "powershell" | "pwsh" | "cmd") {
        return false;
    }
    let words = outside
        .split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(character, '[' | ']' | '(' | ')' | ',' | ';')
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    if words.first().copied() == Some("start-process")
        && let Some(file_path) = words.iter().position(|word| *word == "-filepath")
    {
        let runtime = match words.get(file_path + 1).copied() {
            Some(runtime) if runtime_launch_program(runtime) => runtime,
            Some(option) if !option.starts_with('-') => return false,
            _ => {
                let offset = outside
                    .find("-filepath")
                    .expect("the exact word was found above");
                let Some(runtime) = strings
                    .iter()
                    .zip(string_offsets)
                    .find(|(_, string_offset)| **string_offset > offset)
                    .map(|(runtime, _)| runtime)
                else {
                    return false;
                };
                if !runtime_launch_program(runtime) {
                    return false;
                }
                runtime
            }
        };
        let arguments = words[1..]
            .iter()
            .map(|word| (*word).to_owned())
            .chain(strings.iter().cloned())
            .collect::<Vec<_>>();
        return runtime_launch_bypass(runtime, &arguments, Some(home), Some(platform));
    }
    let start = match words.first().copied() {
        Some("&" | "." | "start-process") => 1,
        Some(_) => 0,
        None => return false,
    };
    let (runtime, argument_start, first_string_argument) =
        if words.get(start).copied() == Some("-filepath") {
            match words.get(start + 1).copied() {
                Some(runtime) if runtime_launch_program(runtime) => (runtime, start + 2, 0),
                Some(option) if option.starts_with('-') => {
                    let Some(runtime) = strings.first() else {
                        return false;
                    };
                    (runtime.as_str(), start + 1, 1)
                }
                None => {
                    let Some(runtime) = strings.first() else {
                        return false;
                    };
                    (runtime.as_str(), start + 1, 1)
                }
                Some(_) => return false,
            }
        } else if let Some(runtime) = words
            .get(start)
            .filter(|runtime| runtime_launch_program(runtime))
        {
            (*runtime, start + 1, 0)
        } else if start > 0 && words.get(start).is_none_or(|word| word.starts_with('-')) {
            let Some(runtime) = strings.first() else {
                return false;
            };
            (runtime.as_str(), start, 1)
        } else {
            return false;
        };
    let arguments = words[argument_start..]
        .iter()
        .map(|word| (*word).to_owned())
        .chain(strings[first_string_argument..].iter().cloned())
        .collect::<Vec<_>>();
    runtime_launch_bypass(runtime, &arguments, Some(home), Some(platform))
}
