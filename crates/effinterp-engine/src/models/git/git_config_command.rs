//! The `git config` command: the setting a write leaves for later
//! invocations, and the configuration values a read prints. `git remote`
//! prints remote URLs through the same read.

use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned};
use crate::models::common::{Attrs, fs_arg_effect};
use crate::paths::resolve_fs_word_with_cwd;
use crate::word::Word;

use super::git_options::{
    git_operands_known, git_option_values_known, git_options, git_options_known,
};
use super::git_repository::{git_dir_resource, selects_by_discovery, worktree_resource};
use super::{SubCtx, string_list};

/// `git config` options that take a value: the type, the comment and value
/// pattern of the 2.46 actions, the file, and the blob and default a lookup
/// reads.
const CONFIG_OPTION_VALUE_FLAGS: &[&str] = &[
    "-t",
    "--type",
    "--comment",
    "--value",
    "-f",
    "--file",
    "--blob",
    "--default",
];

/// `git config` options that take no value: the scopes, the actions, and
/// the type and output options, with the `--no-` form git accepts of each
/// that is negatable.
const CONFIG_OPTION_FLAGS: &[&str] = &[
    "--local",
    "--no-local",
    "--global",
    "--no-global",
    "--system",
    "--no-system",
    "--worktree",
    "--no-worktree",
    "--no-file",
    "--no-blob",
    "--add",
    "--no-add",
    "--replace-all",
    "--no-replace-all",
    "--append",
    "--unset",
    "--no-unset",
    "--unset-all",
    "--no-unset-all",
    "--all",
    "--fixed-value",
    "--no-fixed-value",
    "--bool",
    "--int",
    "--bool-or-int",
    "--bool-or-str",
    "--path",
    "--expiry-date",
    "--no-type",
    "-z",
    "--null",
    "--no-null",
    "--name-only",
    "--no-name-only",
    "--includes",
    "--no-includes",
    "--show-scope",
    "--no-show-scope",
    "--show-origin",
    "--no-show-origin",
    "--no-default",
    "-e",
    "--edit",
    "--no-edit",
    "--rename-section",
    "--no-rename-section",
    "--remove-section",
    "--no-remove-section",
    "-l",
    "--list",
    "--no-list",
    "--get",
    "--no-get",
    "--get-all",
    "--no-get-all",
    "--get-regexp",
    "--no-get-regexp",
    "--get-urlmatch",
    "--no-get-urlmatch",
    "--get-color",
    "--no-get-color",
    "--get-colorbool",
    "--no-get-colorbool",
];

/// The options and operands of a `git config` call as git reads them, each
/// value consumed with its option, so a value spelled like an option
/// (`--file --get`) is not read as one. The legacy grammar stops reading
/// options at the first operand, so every later word is an operand, even
/// one spelled like an option (`git config core.hooksPath --get` sets the
/// value `--get`). The 2.46 actions (`set`, `get`, `unset` and the rest)
/// read their options anywhere after the action.
fn config_options<'a>(s: &'a SubCtx) -> Scanned<'a> {
    let mut parsed = git_options(
        s,
        &FlagSpec {
            value_flags: CONFIG_OPTION_VALUE_FLAGS,
            known_flags: CONFIG_OPTION_FLAGS,
            allow_abbreviation: true,
        },
    );
    let Some(&(first, word)) = parsed.operands.first() else {
        return parsed;
    };
    if matches!(
        word.as_literal(),
        Some("set" | "get" | "unset" | "list" | "edit" | "rename-section" | "remove-section")
    ) {
        return parsed;
    }
    let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
    parsed.flags.retain(|flag| flag.index < first);
    parsed.unknown_flags.retain(|(index, _)| *index <= first);
    parsed.operands = (first..argv.len() as u32)
        .map(|index| (index, &argv[index as usize]))
        .collect();
    parsed
}

/// Record the setting a `git config` write leaves for later invocations in
/// the subject to read. The legacy grammar sets with `<name> <value>
/// [<value-pattern>]` (also under `--add` and `--replace-all`) and removes
/// with `--unset` or `--unset-all`; git 2.46 adds the `set` and `unset`
/// actions. A single name with no option that writes reads
/// (`config_reads`) and never comes here. A form the model does not read here
/// (a dynamic key or action, an unrecognized option, a section rename or
/// removal, an editor) is recorded under an unknown key: it may set
/// anything. A literal key keeps its name when only its value, or the file
/// `--file` names, is not known.
///
/// Returns the attributes of the write's `git.config_write` effect: the key
/// it sets or unsets, as `written_key` states it, or that the key is not
/// known.
pub(super) fn record_config_write(builder: &mut PlanBuilder, s: &SubCtx) -> Attrs {
    let parsed = config_options(s);
    use crate::builder::GitConfigScope;

    // git refuses more than one of these that is on; the last spelled is
    // the file the model takes.
    let location = parsed.flags.iter().rev().find_map(|flag| {
        let scope = match flag.name {
            "--system" => GitConfigScope::System,
            "--global" => GitConfigScope::Global,
            "--local" => GitConfigScope::Local,
            "--worktree" => GitConfigScope::Worktree,
            _ => return None,
        };
        config_option_on(&parsed, &[flag.name]).then_some(scope)
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
        || config_option_on(&parsed, &["-f", "--file"]);
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
        _ => (
            config_option_on(&parsed, &["--unset"]) || config_option_on(&parsed, &["--unset-all"]),
            operands.as_slice(),
        ),
    };
    // An editor or a section rename or removal, also as the 2.46 `edit`,
    // `rename-section` and `remove-section` actions, changes keys the
    // operands do not name. A lookup the model did not take for a read (see
    // `config_reads`), or an option git refuses beside a write
    // (`--show-origin`, `--default`, `--blob`), still on leaves the call
    // unaccounted for too.
    let opaque = matches!(
        operands.first(),
        Some(Some("edit" | "rename-section" | "remove-section"))
    ) || [
        &["-e", "--edit"][..],
        &["--show-origin"],
        &["--default"],
        &["--blob"],
        &["--rename-section"],
        &["--remove-section"],
        &["-l", "--list"],
        &["--get"],
        &["--get-all"],
        &["--get-regexp"],
        &["--get-urlmatch"],
        &["--get-color"],
        &["--get-colorbool"],
    ]
    .into_iter()
    .any(|names| config_option_on(&parsed, names));
    // Only a call whose every option, option value and key the model reads
    // names its key; any other may set anything.
    let accounted = git_options_known(&parsed) && git_option_values_known(&parsed) && !opaque;
    let (key, value, value_known) = if !accounted {
        (None, None, false)
    } else {
        match operands {
            [key, ..] if unset => (key.map(str::to_string), None, false),
            [key, value, ..] => (
                key.map(str::to_string),
                value.map(str::to_string),
                value.is_some(),
            ),
            // `<name>` alone beside an option that writes, which git
            // refuses; a lone name is a read (`config_reads`).
            [key] => (key.map(str::to_string), None, false),
            [] => (None, None, false),
        }
    };
    let attributes = written_key(key.as_deref(), value.as_deref(), unset, value_known);
    builder.record_git_config_write(scope, repository, key, value);
    attributes
}

/// The key a `git config` write sets or unsets, as git compares it: the
/// section (`config_section`) and the variable name (`config_variable`)
/// without regard to case, so both lowercased, with whether the write unsets
/// it, the literal value it sets (`config_value`) and, for a set, whether
/// that value is known (`config_value_known`). The subsection between them,
/// which git compares exactly, is not stated. `config_key_known` is false
/// for a key the model does not know, and for one without a section, which
/// git refuses.
fn written_key(key: Option<&str>, value: Option<&str>, unset: bool, value_known: bool) -> Attrs {
    let mut attributes = Attrs::new();
    let Some(((section, _), (_, variable))) =
        key.and_then(|key| Some((key.split_once('.')?, key.rsplit_once('.')?)))
    else {
        attributes.insert("config_key_known".into(), AttrValue::Bool(false));
        return attributes;
    };
    attributes.insert("config_key_known".into(), AttrValue::Bool(true));
    attributes.insert(
        "config_section".into(),
        AttrValue::String(section.to_ascii_lowercase()),
    );
    attributes.insert(
        "config_variable".into(),
        AttrValue::String(variable.to_ascii_lowercase()),
    );
    attributes.insert("unset".into(), AttrValue::Bool(unset));
    if !unset {
        attributes.insert("config_value_known".into(), AttrValue::Bool(value_known));
    }
    if let Some(value) = value {
        attributes.insert("config_value".into(), AttrValue::String(value.into()));
    }
    attributes
}

/// Whether the option `names` spell is on once git has read every option:
/// git takes the last of an option and its `--no-` form, so
/// `git config --unset --no-unset core.editor vim` sets the key.
fn config_option_on(parsed: &Scanned<'_>, names: &[&str]) -> bool {
    parsed
        .flags
        .iter()
        .rev()
        .find_map(|flag| {
            if names.contains(&flag.name) {
                return Some(true);
            }
            let negates = names.iter().any(|name| {
                name.strip_prefix("--")
                    .is_some_and(|long| flag.name.strip_prefix("--no-") == Some(long))
            });
            negates.then_some(false)
        })
        .unwrap_or(false)
}

/// Whether a `git config` call only reads. It does only where the model
/// accounts for every option, option value and operand, no action that
/// writes is on, and a lookup is on after every `--no-` form (`--get`,
/// `--get-all`, `--get-regexp`, `--get-urlmatch`, `--get-color`,
/// `--get-colorbool`, `--list`), the first operand is git 2.46's `get` or
/// `list` action, or the legacy grammar's single name stands alone. Any
/// other call is taken for a write.
pub(super) fn config_reads(s: &SubCtx) -> bool {
    let parsed = config_options(s);
    let on = |groups: &[&[&str]]| groups.iter().any(|names| config_option_on(&parsed, names));
    let first = parsed
        .operands
        .first()
        .and_then(|(_, word)| word.as_literal());
    // A lone word that names a 2.46 action runs that action instead.
    let single_name = parsed.operands.len() == 1
        && !matches!(
            first,
            Some("set" | "unset" | "edit" | "rename-section" | "remove-section")
        );
    let lookup = on(&[
        &["--get"],
        &["--get-all"],
        &["--get-regexp"],
        &["--get-urlmatch"],
        &["--get-color"],
        &["--get-colorbool"],
        &["-l", "--list"],
    ]) || matches!(first, Some("get" | "list"))
        || single_name;
    let writes = on(&[
        &["-e", "--edit"],
        &["--add"],
        &["--replace-all"],
        &["--unset"],
        &["--unset-all"],
        &["--rename-section"],
        &["--remove-section"],
    ]);
    lookup
        && !writes
        && git_options_known(&parsed)
        && git_option_values_known(&parsed)
        && git_operands_known(&parsed)
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
            // `show` prints the fetch and push URL of each remote it names.
            (Some("show"), Some(_))
                if operands[1..]
                    .iter()
                    .all(|(_, word)| word.as_literal().is_some()) =>
            {
                let keys = operands[1..]
                    .iter()
                    .filter_map(|(_, word)| word.as_literal())
                    .flat_map(|name| {
                        [
                            format!("remote.{name}.url"),
                            format!("remote.{name}.pushurl"),
                        ]
                    })
                    .collect::<Vec<_>>();
                print("remote_urls", &keys);
            }
            // A name the shell still has to supply may be any remote. With
            // no name `get-url` fails and `show` lists names alone.
            (Some("get-url" | "show"), _) if operands.len() > 1 => print("remotes", &[]),
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
