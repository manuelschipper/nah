//! The `git config` command: the setting a write leaves for later
//! invocations, and the configuration values a read prints. `git remote`
//! prints remote URLs through the same read.

use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::fs_arg_effect;
use crate::paths::resolve_fs_word_with_cwd;
use crate::word::Word;

use super::git_options::{git_options, git_options_known};
use super::git_repository::{git_dir_resource, selects_by_discovery, worktree_resource};
use super::{SubCtx, string_list};

/// Record the setting a `git config` write leaves for later invocations in
/// the subject to read. The legacy grammar sets with `<name> <value>
/// [<value-pattern>]` (also under `--add` and `--replace-all`) and removes
/// with `--unset` or `--unset-all`; git 2.46 adds the `set` and `unset`
/// actions. A single name alone reads. A form the model does not read here
/// (a dynamic key or action, an unrecognized option, a section rename or
/// removal, an editor) is recorded under an unknown key: it may set
/// anything. A literal key keeps its name when only its value, or the file
/// `--file` names, is not known.
pub(super) fn record_config_write(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--type", "--comment", "--value", "-f", "--file"],
            known_flags: &[
                "--local",
                "--global",
                "--system",
                "--worktree",
                "--add",
                "--replace-all",
                "--unset",
                "--unset-all",
                "--all",
                "--fixed-value",
                "--bool",
                "--int",
                "--bool-or-int",
                "--path",
                "--expiry-date",
                "--no-type",
            ],
            allow_abbreviation: true,
        },
    );
    use crate::builder::GitConfigScope;

    // git refuses more than one of these; the last spelled is the file
    // the model takes.
    let location = parsed.flags.iter().rev().find_map(|flag| match flag.name {
        "--system" => Some(GitConfigScope::System),
        "--global" => Some(GitConfigScope::Global),
        "--local" => Some(GitConfigScope::Local),
        "--worktree" => Some(GitConfigScope::Worktree),
        _ => None,
    });
    let scope = location.unwrap_or(GitConfigScope::Local);
    // The write is tied to the repository its cwd discovers only when no
    // selector redirects it (see `selects_by_discovery`) and no option the
    // model does not know, which may be `--file`, names another file. A
    // redirected write may land in any file some reader selects or includes,
    // such as the common dir GIT_COMMON_DIR names or the file GIT_CONFIG
    // names, so it is not tied to one repository.
    let redirected = !selects_by_discovery(builder, s.ctx, s.globals)
        || !parsed.unknown_flags.is_empty()
        || parsed.has(&["-f", "--file"]);
    let repository = (matches!(scope, GitConfigScope::Local | GitConfigScope::Worktree)
        && !redirected)
        .then(|| s.repo.clone());
    let operands: Vec<Option<&str>> = parsed
        .operands
        .iter()
        .map(|(_, word)| word.as_literal())
        .collect();
    let (unset, operands) = match operands.split_first() {
        Some((Some("set"), rest)) => (false, rest),
        Some((Some("unset"), rest)) => (true, rest),
        _ => (parsed.has(&["--unset", "--unset-all"]), operands.as_slice()),
    };
    let (key, value) = if !git_options_known(&parsed) {
        (None, None)
    } else {
        match operands {
            [key, ..] if unset => (key.map(str::to_string), None),
            [key, value, ..] => (key.map(str::to_string), value.map(str::to_string)),
            // `<name>` alone reads its value.
            [Some(_)] => return,
            [None] | [] => (None, None),
        }
    };
    builder.record_git_config_write(scope, repository, key, value);
}

/// `git config` options that take the next word as their value.
const CONFIG_VALUE_FLAGS: &[&str] = &[
    "--type",
    "--default",
    "--comment",
    "--value",
    "--url",
    "-f",
    "--file",
    "--blob",
];

/// `git config` options that write, so a single name beside one is not read.
const CONFIG_WRITE_FLAGS: &[&str] = &[
    "--add",
    "--replace-all",
    "--unset",
    "--unset-all",
    "--rename-section",
    "--remove-section",
    "-e",
    "--edit",
];

/// The `git config` options that choose what the call does or which file it
/// acts on: the writes, the reads and the scopes without a value.
const CONFIG_ACTION_FLAGS: &[&str] = &[
    "--add",
    "--replace-all",
    "--unset",
    "--unset-all",
    "--rename-section",
    "--remove-section",
    "-e",
    "--edit",
    "--list",
    "-l",
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "--regexp",
    "--global",
    "--system",
];

/// Whether the variable a configuration key ends in is one whose value is a
/// URL or a request header, where a repository keeps a credential: a
/// remote's `url` and `pushurl`, a `proxy`, an `extraheader`. A key that is
/// not literal may name any of them.
fn key_may_hold_credential(key: &Word) -> bool {
    key.as_literal().is_none_or(|key| {
        let variable = key.rsplit('.').next().unwrap_or(key);
        ["url", "pushurl", "proxy", "extraheader"]
            .iter()
            .any(|name| variable.eq_ignore_ascii_case(name))
    })
}

/// State the read of the configuration file whose values the call prints:
/// `git config --list`, `--get`, `--get-all`, `--get-regexp`, `--get-urlmatch`,
/// the `list` and `get` actions and a single name; `git remote -v`, `get-url`
/// and `show`. The read is of the file `--file` names, or else of the
/// repository's own `config` under the git dir the call names or the `.git`
/// of its start directory. `repository_configuration` marks that second
/// read: git finds the repository upward from the start directory and
/// through a linked worktree's `.git` file, so a file missing at that path
/// means the values come from one this model does not name.
///
/// `printed_configuration` says which of the file's values reach the output,
/// with the keys or the pattern in `configuration_keys`: `all` of them;
/// `remotes`, every remote's URLs; `remote_urls`, the URLs under the keys
/// named, as git rewrites them; `keys`, the values of the keys named;
/// `matching`, the keys a plain-word pattern is found in. A read of one
/// literal key that holds no URL or header states nothing, and neither does
/// one of the global, system or blob scope.
pub(super) fn printed_configuration(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    let mut attributes = crate::models::common::program_input_attrs();
    let mut print = |kind: &str, keys: &[String]| {
        attributes.insert(
            "printed_configuration".into(),
            AttrValue::String(kind.into()),
        );
        if !keys.is_empty() {
            attributes.insert("configuration_keys".into(), string_list(keys));
        }
    };
    let mut named_file = None;
    if sub == "remote" {
        let operands = s.operands(false);
        let action = operands.first().and_then(|(_, word)| word.as_literal());
        match (
            action,
            operands.get(1).and_then(|(_, word)| word.as_literal()),
        ) {
            (Some("get-url"), Some(name)) => {
                let mut keys = vec![format!("remote.{name}.url")];
                if s.scanned(&["--push", "--all"]).has(&["--push", "--all"]) {
                    keys.push(format!("remote.{name}.pushurl"));
                }
                print("remote_urls", &keys);
            }
            (Some("get-url" | "show"), _) => print("remotes", &[]),
            _ if s.scanned(&["-v", "--verbose"]).has(&["-v", "--verbose"]) => print("remotes", &[]),
            _ => return,
        }
    } else {
        let parsed = git_options(
            s,
            &FlagSpec {
                value_flags: CONFIG_VALUE_FLAGS,
                known_flags: CONFIG_ACTION_FLAGS,
                allow_abbreviation: true,
            },
        );
        if parsed.has(&["--global", "--system", "--blob"]) || parsed.has(CONFIG_WRITE_FLAGS) {
            return;
        }
        let operands = parsed.operands.as_slice();
        let action = operands.first().and_then(|(_, word)| word.as_literal());
        let named = if action == Some("get") {
            operands.get(1)
        } else if operands.len() == 1
            || parsed.has(&["--get", "--get-all", "--get-regexp"]) && !operands.is_empty()
        {
            operands.first()
        } else {
            None
        };
        if parsed.has(&["--list", "-l", "--get-urlmatch"]) || action == Some("list") {
            print("all", &[]);
        } else if parsed.has(&["--get-regexp", "--regexp"]) {
            // Only a pattern of plain word characters is decided here: it
            // matches the keys it is found in. Any other may match any key.
            match named.and_then(|(_, pattern)| pattern.as_literal()) {
                Some(pattern)
                    if !pattern.is_empty()
                        && pattern.chars().all(|c| c.is_ascii_alphanumeric()) =>
                {
                    print("matching", &[pattern.to_owned()])
                }
                _ => print("all", &[]),
            }
        } else {
            match named {
                Some((_, key)) if !key_may_hold_credential(key) => return,
                Some((_, key)) => match key.as_literal() {
                    Some(key) => print("keys", &[key.to_owned()]),
                    None => print("all", &[]),
                },
                None => return,
            }
        }
        named_file = parsed
            .values_of(&["-f", "--file"])
            .into_iter()
            .last()
            .map(|(index, file)| (s.rest_offset - 1 + index, file.clone()));
    }
    if let Some((index, file)) = named_file {
        s.filesystem_path_effect(builder, index, &file, "filesystem.read", attributes);
        return;
    }
    let resource = match git_dir_resource(&s.repo) {
        Some(git_dir) => resolve_fs_word_with_cwd(&Word::literal("config"), Some(git_dir.clone())),
        None => match worktree_resource(&s.repo) {
            Some(worktree) => {
                resolve_fs_word_with_cwd(&Word::literal(".git/config"), Some(worktree.clone()))
            }
            None => return,
        },
    };
    if !matches!(
        resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { .. }
        }
    ) {
        return;
    }
    attributes.insert("repository_configuration".into(), AttrValue::Bool(true));
    fs_arg_effect(
        builder,
        s.ctx,
        s.model_node,
        s.sub_index,
        &s.ctx.argv[s.sub_index as usize],
        "filesystem.read",
        resource,
        attributes,
    );
}
