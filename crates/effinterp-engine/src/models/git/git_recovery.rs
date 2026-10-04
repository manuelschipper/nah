//! git commands that destroy recovery data: the unreachable objects
//! `git gc`, `git prune`, `git repack` and `git maintenance` collect, the
//! reflog entries `git reflog` expires, and the stashes `git stash` drops.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::{FlagSpec, Scanned};
use crate::models::common::{Attrs, arg_node, attrs};
use crate::word::Word;

use super::git_config::{config_value, config_values, git_bool};
use super::git_options::{
    git_controls_known, git_help_requested, git_options, parsed_effective_flag,
};
use super::git_repository::empty_repository_global;
use super::{
    SubCtx, dispatch, git_argument_boundary, request_attrs, unmodeled_subcommand_boundary,
};

/// Expiry selectors that expire everything at once, whatever its age. Git
/// hands a value other than its exact keywords to approxidate, which reads
/// `now` in any case.
fn immediate_expiry(value: &str) -> bool {
    matches!(value, "all" | "0") || value.eq_ignore_ascii_case("now")
}

/// Every option value prune and reflog expire take is an expiry date, and
/// git refuses an empty one, wherever it appears, before it expires
/// anything. gc reads only its last date, so it does not use this.
fn empty_option_value(parsed: &Scanned<'_>) -> bool {
    parsed
        .flags
        .iter()
        .any(|flag| flag.value.as_ref().and_then(Word::as_literal) == Some(""))
}

/// `git gc` expires reflog entries and collects unreachable objects.
/// The prune expiry, from the last `--prune` or `--no-prune` or else
/// `gc.pruneExpire`, decides whether the collection is immediate.
pub(super) fn gc(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--prune"],
            // Reporting does not select what is pruned, so it leaves
            // the recovery request exact.
            known_flags: &[
                "--no-prune",
                "--aggressive",
                "--no-aggressive",
                "--auto",
                "--force",
                "--quiet",
            ],
            allow_abbreviation: true,
        },
    );
    // git-gc(1) keeps only the last `--prune[=<date>]` or
    // `--no-prune` and refuses an empty final date before collecting
    // anything; an empty date a later option overrides is never read.
    let empty_expiry = parsed
        .flags
        .iter()
        .rev()
        .find(|flag| matches!(flag.name, "--prune" | "--no-prune"))
        .is_some_and(|flag| {
            flag.value_index == Some(flag.index)
                && flag.value.as_ref().and_then(Word::as_literal) == Some("")
        });
    // git-gc(1): `--prune=<date>` expires unreachable objects older
    // than the date, so the selector is what the collection destroys.
    // git reads the configured expiry before any option and refuses
    // an empty one, even when `--prune` or `--no-prune` overrides it.
    let configured = config_values(s.globals, "gc.pruneExpire");
    if git_help_requested(&parsed)
        || empty_expiry
        || empty_repository_global(s)
        || configured.certain() == Some(Some(""))
    {
        return;
    }
    // When executions may leave different expiries, one some path
    // leaves immediate is the collection planned, with a boundary.
    let possible_immediate = configured
        .certain()
        .is_none()
        .then(|| {
            configured
                .values
                .iter()
                .flatten()
                .copied()
                .find(|value| immediate_expiry(value))
        })
        .flatten();
    let configured_expiry = match possible_immediate {
        Some(value) => Some(Some(value)),
        None if configured.values.is_empty() => None,
        None => Some(configured.certain().flatten()),
    };
    // `--no-prune` keeps every unreachable object, overriding the
    // configured expiry and any earlier `--prune`.
    let no_prune = parsed
        .flags
        .iter()
        .rev()
        .find(|flag| matches!(flag.name, "--prune" | "--no-prune"))
        .is_some_and(|flag| flag.name == "--no-prune");
    let explicit_prune = s.flag_with_prefix("--prune=");
    if possible_immediate.is_some() && explicit_prune.is_none() && !no_prune {
        git_argument_boundary(
            builder,
            s,
            "git gc expiry configuration differs between the paths that reach it",
        );
    }
    let prune = explicit_prune
        .or_else(|| configured_expiry.flatten().map(str::to_string))
        .filter(|_| !no_prune);
    // A configured expiry the model cannot read decides what the
    // collection destroys just as `--prune=<date>` does.
    let expiry_known = no_prune || prune.is_some() || !matches!(configured_expiry, Some(None));
    if !expiry_known {
        git_argument_boundary(
            builder,
            s,
            "git gc expiry configuration is not statically resolvable",
        );
    }
    let prune_now = prune.as_deref().is_some_and(immediate_expiry);
    // `--aggressive` repacks more aggressively, rewriting the object
    // store rather than only collecting it.
    let aggressive = parsed_effective_flag(&parsed, &["--aggressive"], &["--no-aggressive"]);
    let valid_operands = s.operands(false).is_empty();
    // Without pruning, gc still expires reflog entries past
    // gc.reflogExpire and repacks, so it still destroys recovery data.
    s.repo_effect(
        builder,
        "git.recovery_destroy",
        attrs(&[("immediate", prune_now)]),
    );
    if git_controls_known(&parsed) && valid_operands && expiry_known {
        let mut request = request_attrs(&[
            ("immediate", prune_now),
            ("recovery", true),
            ("aggressive", aggressive),
        ]);
        request.insert(
            "scope".into(),
            AttrValue::String(if prune_now { "whole" } else { "named" }.into()),
        );
        request.insert("broad".into(), AttrValue::Bool(prune_now));
        if let Some(prune) = prune {
            request.insert("prune".into(), AttrValue::String(prune));
        }
        s.request_effect(builder, "git.recovery_destroy_request", request);
    }
}

/// `git reflog expire`, `delete` and `drop` remove reflog entries; the
/// reflog expiry and `--all` decide whether every reflog goes at once.
pub(super) fn reflog(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--expire", "--expire-unreachable"],
            // `--single-worktree` (expire and drop only) skips only
            // the other worktrees' own HEAD logs: the current
            // worktree's ref store also yields every shared branch
            // log, so `--all` stays whole.
            known_flags: if matches!(
                s.rest.first().and_then(Word::as_literal),
                Some("expire" | "drop")
            ) {
                &[
                    "delete",
                    "expire",
                    "--all",
                    "--single-worktree",
                    "-n",
                    "--dry-run",
                ]
            } else {
                &["delete", "expire", "--all", "-n", "--dry-run"]
            },
            allow_abbreviation: true,
        },
    );
    // git reports an empty ref as pointing nowhere and goes on to the
    // next one, so only a list of nothing but empty refs, without
    // `--all`, leaves every reflog alone.
    let refs = s.operands(false);
    let only_empty_refs = refs.len() > 1
        && refs
            .iter()
            .skip(1)
            .all(|(_, word)| word.as_literal() == Some(""));
    if empty_option_value(&parsed)
        || empty_repository_global(s)
        || only_empty_refs && !s.scanned(&["--all"]).has(&["--all"])
    {
        return;
    }
    // is_read_form filtered `reflog [show|list]`; the actions that
    // change reflogs land here. `drop` (git 2.50) deletes whole
    // reflogs, every entry whatever its age, as an immediate expiry
    // does.
    let drop = s.rest.first().and_then(Word::as_literal) == Some("drop");
    let immediate = drop
        || s.flag_with_prefix("--expire=")
            .or_else(|| s.flag_with_prefix("--expire-unreachable="))
            .map(|v| immediate_expiry(&v))
            .unwrap_or(false);
    let dry_run = parsed.has(&["-n", "--dry-run"]);
    let mut attributes = attrs(&[("immediate", immediate), ("reflog", true)]);
    if let Some(action @ ("expire" | "delete")) = s.rest.first().and_then(Word::as_literal) {
        attributes.insert("action".into(), AttrValue::String(action.into()));
    }
    if parsed.unknown_flags.is_empty() && git_controls_known(&parsed) {
        // Scope names the reflogs selected, independently of entry age.
        attributes.insert(
            "scope".into(),
            AttrValue::String(
                if parsed.has(&["--all"]) {
                    "whole"
                } else {
                    "named"
                }
                .into(),
            ),
        );
        attributes.insert("dry_run".into(), AttrValue::Bool(dry_run));
    }
    let action = attributes.get("action").cloned();
    s.repo_effect(builder, "git.recovery_destroy", attributes);
    if !dry_run && git_controls_known(&parsed) {
        let operands = s.operands(false);
        // expire, delete and drop take any number of refs or
        // entries; `exists` takes one ref and `write` one entry.
        let valid_operands = operands.len() <= 2
            || matches!(
                s.rest.first().and_then(Word::as_literal),
                Some("expire" | "delete" | "drop")
            );
        let all_refs = s.scanned(&["--all"]).has(&["--all"]);
        let target_complete = operands
            .iter()
            .skip(1)
            .all(|(_, word)| word.as_literal().is_some());
        let mut request = request_attrs(&[("immediate", immediate), ("reflog", true)]);
        if let Some(action) = action.clone() {
            request.insert("action".into(), action);
        }
        request.insert("target_complete".into(), AttrValue::Bool(target_complete));
        // `--all` expires every reflog before git looks up any named
        // ref, so a named ref beside it narrows nothing.
        request.insert(
            "scope".into(),
            AttrValue::String(
                if immediate && all_refs {
                    "whole"
                } else if target_complete && operands.len() > 1 {
                    "selected"
                } else {
                    "named"
                }
                .into(),
            ),
        );
        request.insert("broad".into(), AttrValue::Bool(immediate && all_refs));
        if target_complete
            && let [_, (_, target)] = operands.as_slice()
            && let Some(target) = target.as_literal()
        {
            request.insert("target".into(), AttrValue::String(target.into()));
        }
        // `--expire=never` and `--expire-unreachable=never` (or
        // `false`) together keep every entry, so expiring one named
        // ref's reflog then prunes nothing.
        let keeps_every_entry = action == Some(AttrValue::String("expire".into()))
            && ["--expire", "--expire-unreachable"].iter().all(|name| {
                parsed
                    .values_of(&[name])
                    .last()
                    .and_then(|(_, value)| value.as_literal())
                    .is_some_and(|value| matches!(value, "never" | "false"))
            });
        let selected = request.get("scope") == Some(&AttrValue::String("selected".into()));
        // `drop` refuses refs named beside `--all` ("references
        // specified along with --all").
        let drop_usage = drop && all_refs && operands.len() > 1;
        if valid_operands && !(keeps_every_entry && selected) && !drop_usage {
            s.request_effect(builder, "git.recovery_destroy_request", request);
        }
    }
}

/// `git stash drop` and `git stash clear` destroy stash entries; every
/// other stash action writes the working tree.
pub(super) fn stash(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[],
            known_flags: &["-q", "--quiet"],
            allow_abbreviation: true,
        },
    );
    let action = s
        .operands(false)
        .first()
        .and_then(|(_, w)| w.as_literal())
        .unwrap_or("push");
    match action {
        // git refuses an empty stash entry ("is not a valid
        // reference") before dropping anything.
        "drop" | "clear"
            if empty_repository_global(s)
                || action == "drop"
                    && s.operands(false).get(1).and_then(|(_, w)| w.as_literal()) == Some("") => {}
        "drop" | "clear" => {
            s.repo_effect(builder, "git.recovery_destroy", attrs(&[("stash", true)]));
            if git_controls_known(&parsed) {
                let operands = s.operands(false);
                let valid_operands = match action {
                    "clear" => operands.len() == 1,
                    "drop" => operands.len() <= 2,
                    _ => false,
                };
                let target_complete = operands
                    .iter()
                    .skip(1)
                    .all(|(_, word)| word.as_literal().is_some());
                let mut request = request_attrs(&[("stash", true)]);
                request.insert("target_complete".into(), AttrValue::Bool(target_complete));
                request.insert(
                    "scope".into(),
                    AttrValue::String(
                        if action == "clear" {
                            "whole"
                        } else {
                            "selected"
                        }
                        .into(),
                    ),
                );
                request.insert("broad".into(), AttrValue::Bool(action == "clear"));
                if target_complete
                    && let Some((_, target)) = operands.get(1)
                    && let Some(target) = target.as_literal()
                {
                    request.insert("target".into(), AttrValue::String(target.into()));
                }
                if valid_operands {
                    s.request_effect(builder, "git.recovery_destroy_request", request.clone());
                    request.insert("delete".into(), AttrValue::Bool(true));
                    request.insert("ref".into(), AttrValue::String("refs/stash".into()));
                    request.insert(
                        "selection_complete".into(),
                        AttrValue::Bool(target_complete),
                    );
                    if target_complete {
                        s.request_effect(builder, "git.ref_delete_request", request);
                    } else {
                        git_argument_boundary(
                            builder,
                            s,
                            "git stash entry is dynamic and may change option parsing",
                        );
                    }
                }
            }
        }
        _ => s.repo_effect(builder, "git.worktree_write", attrs(&[("stash", true)])),
    }
}

/// `git prune` removes unreachable objects: every one unless a prune
/// expiry (`--expire`) keeps the recent ones.
pub(super) fn prune(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--expire"],
            known_flags: &["-n", "--dry-run"],
            allow_abbreviation: true,
        },
    );
    if empty_option_value(&parsed) || empty_repository_global(s) {
        return;
    }
    // A bare `git prune` has no grace period and removes every
    // unreachable object. `--expire` restricts that set by age.
    if s.scanned(&["-n", "--dry-run"]).has(&["-n", "--dry-run"]) {
        s.repo_effect(builder, "git.read", Attrs::new());
    } else {
        let valid_operands = parsed.operands.is_empty();
        let immediate = parsed
            .value_of(&["--expire"])
            .and_then(Word::as_literal)
            .map(immediate_expiry)
            .unwrap_or(!parsed.has(&["--expire"]));
        s.repo_effect(
            builder,
            "git.recovery_destroy",
            attrs(&[("immediate", immediate)]),
        );
        if git_controls_known(&parsed) && valid_operands {
            let mut request = request_attrs(&[("immediate", immediate)]);
            request.insert(
                "scope".into(),
                AttrValue::String(if immediate { "whole" } else { "named" }.into()),
            );
            request.insert("broad".into(), AttrValue::Bool(immediate));
            s.request_effect(builder, "git.recovery_destroy_request", request);
        }
    }
}

/// `git maintenance run --task=<task>...` runs the named tasks in order, and
/// without `--task` the tasks its configuration and strategy select. The gc task runs
/// `git gc` as a child that inherits this invocation's `-c` settings, passing
/// on `--auto` and `--quiet`; the `--no-detach` and `--no-quiet` it may add
/// select nothing gc destroys. Returns false for the forms left to the
/// unmodeled-subcommand boundary: other actions, `--schedule`, and dynamic
/// task names.
pub(super) fn maintenance(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["--task", "--schedule"],
            known_flags: &["--auto", "--quiet", "--no-quiet"],
            allow_abbreviation: true,
        },
    );
    let tasks = parsed.values_of(&["--task"]);
    // The action is the word right after `maintenance`.
    if s.rest.first().and_then(Word::as_literal) != Some("run")
        || !matches!(parsed.operands.as_slice(), [(_, action)] if action.as_literal() == Some("run"))
        || !git_controls_known(&parsed)
        || parsed.has(&["--schedule"])
    {
        return false;
    }
    // git matches task names case-insensitively and refuses the whole list,
    // before running any task, when one names no task or one is named twice.
    let mut names = tasks
        .iter()
        .map(|(_, task)| task.as_literal().unwrap().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if names.is_empty() {
        // Without `--task`, the tasks come from `maintenance.<task>.enabled`
        // over a default strategy that changed between releases: gc in
        // 2.39, geometric (no gc) in 2.55. Only a setting that git reads as
        // true certainly selects gc; repository configuration, which can
        // select other tasks or the strategy, is not observed.
        if config_value(s.globals, "maintenance.gc.enabled")
            .flatten()
            .and_then(git_bool)
            == Some(true)
        {
            names.push("gc".into());
        }
        unmodeled_subcommand_boundary(
            builder,
            s,
            "git maintenance tasks selected by configuration or the default strategy are not observed",
        );
    }
    if names
        .iter()
        .enumerate()
        .any(|(index, name)| names[..index].contains(name))
    {
        return true;
    }
    // Every task some git release defines; a name outside them may still
    // be one a later release adds.
    if let Some(name) = names.iter().find(|name| {
        !matches!(
            name.as_str(),
            "gc" | "commit-graph"
                | "prefetch"
                | "loose-objects"
                | "incremental-repack"
                | "pack-refs"
                | "reflog-expire"
                | "worktree-prune"
                | "rerere-gc"
        )
    }) {
        unmodeled_subcommand_boundary(builder, s, &format!("git maintenance task {name:?}"));
        return true;
    }
    for name in names {
        if name != "gc" {
            unmodeled_subcommand_boundary(builder, s, &format!("git maintenance task {name:?}"));
            continue;
        }
        // With `--auto` the task runs only when `git gc --auto` would
        // collect, which a nonpositive `gc.auto` turns off (`need_to_gc`).
        // A value that is not a plain integer, or that the model cannot
        // read, leaves open whether the task runs.
        if parsed.has(&["--auto"])
            && let Some(value) = config_value(s.globals, "gc.auto")
            && let limit = value.and_then(|value| value.parse::<i64>().ok())
            && limit.is_none_or(|limit| limit <= 0)
        {
            if limit.is_none() {
                git_argument_boundary(
                    builder,
                    s,
                    "git gc.auto configuration is not a statically known integer",
                );
            }
            continue;
        }
        let offset = s.rest_offset as usize;
        let mut argv = s.ctx.argv[..offset - 1].to_vec();
        argv.push(Word::literal("gc"));
        for flag in ["--auto", "--quiet"] {
            if parsed.has(&[flag]) {
                argv.push(Word::literal(flag));
            }
        }
        let provenance = (0..argv.len())
            .map(|index| {
                vec![arg_node(
                    builder,
                    s.ctx,
                    if index < offset - 1 {
                        index as u32
                    } else {
                        s.sub_index
                    },
                )]
            })
            .collect::<Vec<_>>();
        let ctx = InvocationCtx {
            argv: &argv,
            stdin: s.ctx.stdin,
            argv_provenance: Some(&provenance),
            cwd: s.ctx.cwd,
            cwd_resource: s.ctx.cwd_resource.clone(),
            runtime_cwd: s.ctx.runtime_cwd,
            scope: s.ctx.scope,
            cwd_node: s.ctx.cwd_node,
            nest: s.ctx.nest,
            depth: s.ctx.depth,
            model_stack: s.ctx.model_stack.clone(),
        };
        let gc = SubCtx {
            globals: s.globals,
            ctx: &ctx,
            model_node: s.model_node,
            repo: s.repo.clone(),
            cwd: s.cwd.clone(),
            rest: &argv[offset..],
            rest_offset: s.rest_offset,
            sub_index: s.sub_index,
        };
        dispatch(builder, "gc", &gc);
    }
    true
}

/// git-repack(1): with `-d`, packing everything into one pack (`-a`, `-A`
/// or `--cruft`) deletes the old packs, and with them each unreachable
/// object the new pack left out. `-a` leaves out every one of them, so they
/// are gone at once, as `git gc --prune=now` removes them; objects a reflog
/// reaches are packed and survive. `-A`, or `--unpack-unreachable` beside
/// any of them, turns them loose instead, except those older than its date;
/// `--cruft` packs them apart, except those older than `--cruft-expiration`;
/// `-k` keeps them in the new pack. Returns false, leaving the invocation to
/// the unmodeled-subcommand boundary, for every form that does not certainly
/// destroy them, including the combinations git refuses.
pub(super) fn repack(builder: &mut PlanBuilder, s: &SubCtx) -> bool {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &[
                "--cruft-expiration",
                "--unpack-unreachable",
                "--expire-to",
                "--window",
                "--window-memory",
                "--depth",
                "--threads",
                "--max-pack-size",
                "--keep-pack",
                "-g",
                "--geometric",
            ],
            known_flags: &[
                "-a",
                "-A",
                "--cruft",
                "--no-cruft",
                "-d",
                "-k",
                "--keep-unreachable",
                "--no-keep-unreachable",
                "-f",
                "-F",
                "-n",
                "-q",
                "--quiet",
                "-l",
                "--local",
                "-b",
                "--write-bitmap-index",
                "-i",
                "--delta-islands",
                "--pack-kept-objects",
                "-m",
                "--write-midx",
            ],
            allow_abbreviation: true,
        },
    );
    if git_help_requested(&parsed) || empty_repository_global(s) {
        return true;
    }
    if !git_controls_known(&parsed) || !parsed.operands.is_empty() || !parsed.has(&["-d"]) {
        return false;
    }
    let cruft = parsed_effective_flag(&parsed, &["--cruft"], &["--no-cruft"]);
    let keep = parsed_effective_flag(
        &parsed,
        &["-k", "--keep-unreachable"],
        &["--no-keep-unreachable"],
    );
    let last_immediate = |name: &str| {
        parsed
            .value_of(&[name])
            .and_then(Word::as_literal)
            .is_some_and(immediate_expiry)
    };
    let loosen = parsed.has(&["-A", "--unpack-unreachable"]);
    // git refuses these combinations before it packs anything.
    if keep && loosen || cruft && (loosen || keep) {
        return false;
    }
    let destroys = if cruft {
        last_immediate("--cruft-expiration") && !parsed.has(&["--expire-to"])
    } else if loosen {
        parsed.has(&["-a", "-A"]) && last_immediate("--unpack-unreachable")
    } else {
        parsed.has(&["-a"]) && !keep
    };
    if !destroys {
        return false;
    }
    s.repo_effect(
        builder,
        "git.recovery_destroy",
        attrs(&[("immediate", true)]),
    );
    let mut request = request_attrs(&[("immediate", true), ("recovery", true)]);
    request.insert("scope".into(), AttrValue::String("whole".into()));
    request.insert("broad".into(), AttrValue::Bool(true));
    s.request_effect(builder, "git.recovery_destroy_request", request);
    true
}

/// git-stash(1) keeps the newest stash in `refs/stash` and the older ones
/// in that ref's reflog.
pub(super) const STASH_REF: &str = "refs/stash";

/// Deleting `refs/stash` deletes its reflog with it, which is every stash:
/// `git stash clear` is implemented as exactly that deletion.
pub(super) fn stash_destroyed(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.recovery_destroy", attrs(&[("stash", true)]));
    let mut request = request_attrs(&[("stash", true), ("target_complete", true)]);
    request.insert("scope".into(), AttrValue::String("whole".into()));
    request.insert("broad".into(), AttrValue::Bool(true));
    s.request_effect(builder, "git.recovery_destroy_request", request);
}
