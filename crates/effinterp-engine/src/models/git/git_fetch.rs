//! git transfers from a remote into the repository: `git fetch`,
//! `git pull` and the directory a `git clone` writes.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::common::{Attrs, attrs};
use crate::models::net::parse_endpoint;
use crate::resource_transfer::TransferBinding;
use crate::word::Word;

use super::git_config::{ConfigEntry, git_bool};
use super::{SubCtx, git_argument_boundary, request_attrs};

/// Fetching moves objects from the remote into the repository: the
/// remote read pairs with the most atomic local destination the modeled
/// operation has — a pull's worktree write, otherwise the repository
/// sync itself.
pub(super) fn fetch_or_pull(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    let synced = s.repo_effect_slot(builder, "git.remote_sync", attrs(&[("fetch", true)]));
    let mut destination = synced;
    if sub == "pull" {
        destination = s.repo_effect_slot(builder, "git.worktree_write", Attrs::new());
        let (rebases, certain) = pull_rebases(s);
        if !certain {
            git_argument_boundary(
                builder,
                s,
                "whether git pull rebases is not statically known",
            );
        }
        if rebases && certain {
            s.repo_effect(builder, "git.history_rewrite", attrs(&[("force", false)]));
            let mut request = request_attrs(&[("force", false), ("target_complete", true)]);
            request.insert("rewrite".into(), AttrValue::String("rebase".into()));
            request.insert(
                "history_operation".into(),
                AttrValue::String("rebase".into()),
            );
            request.insert("scope".into(), AttrValue::String("targeted".into()));
            request.insert("broad".into(), AttrValue::Bool(false));
            s.request_effect(builder, "git.history_rewrite_request", request);
        }
        s.hooks_boundary(builder);
    }
    let source = s.remote_network(builder, "network.download");
    if let (Some(source), Some(destination)) = (source, destination) {
        builder.transfer_binding(TransferBinding::new(source, destination));
    }
}

/// git-pull(1) options, with the fetch and merge options it passes on, that
/// take the next word as their value when none is attached.
const PULL_VALUE_OPTIONS: &[&str] = &[
    "--cleanup",
    "--strategy",
    "--strategy-option",
    "--upload-pack",
    "--jobs",
    "--depth",
    "--shallow-since",
    "--shallow-exclude",
    "--deepen",
    "--refmap",
    "--server-option",
    "--negotiation-tip",
];

/// git-pull(1) options that take no value, or only an attached one.
const PULL_FLAG_OPTIONS: &[&str] = &[
    "--verbose",
    "--quiet",
    "--progress",
    "--recurse-submodules",
    "--stat",
    "--summary",
    "--compact-summary",
    "--log",
    "--signoff",
    "--squash",
    "--commit",
    "--edit",
    "--ff",
    "--ff-only",
    "--verify",
    "--verify-signatures",
    "--autostash",
    "--gpg-sign",
    "--allow-unrelated-histories",
    "--all",
    "--append",
    "--force",
    "--tags",
    "--prune",
    "--keep",
    "--unshallow",
    "--update-shallow",
    "--ipv4",
    "--ipv6",
    "--show-forced-updates",
    "--set-upstream",
];

/// Whether `git pull` rebases the current branch onto what it fetched, and
/// whether that is certain. Only the command line decides certainly: the
/// last `-r[<mode>]`, `--rebase[=<mode>]` or `--no-rebase` (or their unique
/// abbreviations `--reb…`, `--no-reb…`), with `--dry-run` stopping after the
/// fetch. Options that take a value consume it first, so an option-shaped
/// value (`-o --no-rebase`) decides nothing. Without a command-line control,
/// an inline `pull.rebase` or `branch.<name>.rebase` may select a rebase,
/// which the model does not resolve; nor does it resolve a dynamic word, an
/// option it does not know (it may be an abbreviation that takes a value),
/// a short option letter it does not know, or a mode it cannot classify.
/// Repository configuration is not read.
fn pull_rebases(s: &SubCtx) -> (bool, bool) {
    let mut certain = true;
    let mut rebase = None;
    // git reads the mode as a boolean, then as merges or interactive.
    let mode = |value: &str, rebase: &mut Option<bool>, certain: &mut bool| match git_bool(value) {
        Some(value) => *rebase = Some(value),
        None if matches!(value, "merges" | "m" | "interactive" | "i") => *rebase = Some(true),
        None => {
            *rebase = None;
            *certain = false;
        }
    };
    let mut dry_run = false;
    let mut words = s.rest.iter();
    while let Some(word) = words.next() {
        let Some(text) = word.as_literal() else {
            certain = false;
            continue;
        };
        if text == "--" {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (format!("--{name}"), Some(value)),
                None => (text.to_string(), None),
            };
            match name.as_str() {
                name if name.len() >= 5 && "--rebase".starts_with(name) => {
                    mode(value.unwrap_or("true"), &mut rebase, &mut certain)
                }
                name if name.len() >= 8 && "--no-rebase".starts_with(name) && value.is_none() => {
                    rebase = Some(false)
                }
                "--dry-run" if value.is_none() => dry_run = true,
                name if PULL_VALUE_OPTIONS.contains(&name) => {
                    if value.is_none() && words.next().is_none() {
                        certain = false;
                    }
                }
                name if PULL_FLAG_OPTIONS.contains(&name)
                    || name.strip_prefix("--no-").is_some_and(|flag| {
                        PULL_FLAG_OPTIONS.contains(&format!("--{flag}").as_str())
                    }) => {}
                _ => certain = false,
            }
            continue;
        }
        let Some(cluster) = text.strip_prefix('-').filter(|cluster| !cluster.is_empty()) else {
            continue;
        };
        for (index, c) in cluster.char_indices() {
            let attached = &cluster[index + c.len_utf8()..];
            match c {
                'v' | 'q' | 'n' | 'a' | 'f' | 't' | 'p' | 'k' | '4' | '6' => continue,
                'r' => mode(
                    if attached.is_empty() {
                        "true"
                    } else {
                        attached
                    },
                    &mut rebase,
                    &mut certain,
                ),
                'S' => {}
                's' | 'X' | 'j' | 'o' => {
                    if attached.is_empty() && words.next().is_none() {
                        certain = false;
                    }
                }
                _ => certain = false,
            }
            break;
        }
    }
    if rebase.is_none()
        && s.globals.configs.iter().any(|ConfigEntry { key, .. }| {
            key.is_empty()
                || key.split_once('.').is_some_and(|(section, rest)| {
                    section.eq_ignore_ascii_case("pull") && rest.eq_ignore_ascii_case("rebase")
                        || section.eq_ignore_ascii_case("branch")
                            && rest.rsplit_once('.').is_some_and(|(_, variable)| {
                                variable.eq_ignore_ascii_case("rebase")
                            })
                })
        })
    {
        certain = false;
    }
    (rebase == Some(true) && !dry_run, certain)
}

/// The directory a clone of `operands` (`<url> [<dir>]`) writes, paired with
/// the download it receives.
pub(super) fn clone_destination(
    builder: &mut PlanBuilder,
    s: &SubCtx,
    operands: &[(u32, &Word)],
    source: Option<u32>,
) {
    let dest = match operands {
        // `clone <url> <dir>` — unless the last operand is itself a
        // URL (a value-consuming flag like -b shifted the operands).
        [_, .., (index, dest)] if dest.as_literal().and_then(parse_endpoint).is_none() => {
            Some((*index, (*dest).clone()))
        }
        [.., (index, url)] => url
            .as_literal()
            .and_then(|u| {
                u.trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .map(|b| b.trim_end_matches(".git").to_string())
            })
            .map(|b| (*index, Word::literal(b))),
        _ => None,
    };
    if let Some((index, dest)) = dest {
        let destination =
            s.filesystem_path_effect(builder, index, &dest, "filesystem.write", Attrs::new());
        if let (Some(source), Some(destination)) = (source, destination) {
            builder.transfer_binding(TransferBinding::new(source, destination));
        }
    }
}
