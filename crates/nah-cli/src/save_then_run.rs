//! Save-then-run, `work`'s core behaviour in every runtime whose adapter
//! delivers a post-call event, on a Unix host (`available`). A git command
//! that discards uncommitted work (`git reset --hard`, `--merge` or
//! `--keep`, a checkout or restore over edited files, `git checkout -f`,
//! `git clean -f`), drops stash entries (`git stash drop`, `git stash
//! clear`), deletes local refs (`git branch -d`, `git tag -d`, `git
//! update-ref -d`, `git remote remove`), recursively deletes project files
//! (`rm -rf src`), or rewrites history no reflog or backup keeps (a rebase,
//! an amend, a reset to another commit, `git filter-branch`, `git
//! filter-repo`) does not block while `work/changes-discard`,
//! `work/untracked-clean`, `work/stash-drop`, `work/branch-delete`,
//! `work/files-delete` or `work/history-rewrite`, the rule it falls under,
//! runs at core: Nah saves a snapshot of what it would discard, for a
//! stash, a ref or a rewrite the commits only the dropped entries, deleted
//! refs or moved refs reach, and delegates, telling the agent how to undo;
//! whatever it cannot save, it blocks. At strict the rules decide whole:
//! their parts, and every discard of named paths or pathspecs a snapshot
//! would answer (`with_unmatched`). Where nothing can save, at core only
//! the parts whose 1.x guards shipped on block (`unsaveable`), so `work` is
//! never stricter there than 1.x. A discard Git finds nothing to lose in is
//! none, in every runtime. Every other rule is unchanged.

#[cfg(unix)]
mod post_call;
#[cfg(unix)]
mod pre_call;
#[cfg(unix)]
pub(crate) mod unfinished;

#[cfg(unix)]
pub(crate) use post_call::{
    refresh, retain, retain_in_background, run_detached_post_call, start_detached_post_call,
};
#[cfg(unix)]
pub(crate) use pre_call::{run_save_child, save_discards, save_preflight};

use std::path::{Path, PathBuf};

use nah_proto::ctx::GuardLevel;
use nah_proto::effinterp_proto::{
    AttrValue, Boundary, BoundaryReason, Effect, ExecutionNodeRef, Plan, ResourceExpr,
    ResourceIdentity, ResourcePattern,
};
use nah_proto::guard_host::{MatchedPart, ProjectDelete, ShippedGuardMatches};
use nah_proto::observation::RefDeletion;
use serde::{Deserialize, Serialize};

use crate::runtime::Runtime;

/// Whether save-then-run answers the discards of calls from `runtime`: its
/// adapter must refresh the rolling copy after every call, its payload must
/// state where a command runs, and nah-snapshot needs a Unix host.
/// Elsewhere the rules' parts decide as 1.x's guards did (`unsaveable`).
pub(crate) fn available(runtime: Option<Runtime>) -> bool {
    cfg!(unix)
        && runtime.is_some_and(|runtime| {
            runtime.follows_this_call() && runtime.states_where_commands_run()
        })
}

/// How save-then-run meets one decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SaveMode {
    /// The hook saves the call's discards before it runs.
    Saves,
    /// The runtime saves, but nothing saves before this decision's call
    /// runs, such as a later run of content written now: the work rules at
    /// core decide whole, so no discard runs unsaved.
    Withheld,
    /// Nothing can save, on this host or in this runtime: the parts whose
    /// 1.x guards shipped on decide (`unsaveable`).
    Unavailable,
}

impl SaveMode {
    /// The mode of the hook of `runtime`.
    pub(crate) fn of(runtime: Option<Runtime>) -> Self {
        if available(runtime) {
            Self::Saves
        } else {
            Self::Unavailable
        }
    }

    /// The mode of a decision in `runtime` whose call nothing saves first.
    pub(crate) fn withheld(runtime: Option<Runtime>) -> Self {
        match Self::of(runtime) {
            Self::Saves => Self::Withheld,
            mode => mode,
        }
    }
}

/// The rules whose discards a snapshot answers at core.
pub const RULES: [&str; 6] = [
    "work/changes-discard",
    "work/untracked-clean",
    "work/files-delete",
    "work/stash-drop",
    "work/branch-delete",
    "work/history-rewrite",
];

/// The rules of `RULES` that decide whole at core where nothing saves the
/// call, so none of their discards runs unsaved: a snapshot answers some of
/// their strict parts too. `work/branch-delete`'s strict parts, worktree
/// and submodule removals, are no discard a snapshot answers, and stay
/// strict. `work/history-rewrite` blocks a rewrite that may lose commits at
/// core by its own parts, and its strict-only parts, a rebase or filter
/// that loses nothing, are no loss a snapshot answers.
pub const WHOLE_UNSAVED: [&str; 4] = [
    "work/changes-discard",
    "work/untracked-clean",
    "work/files-delete",
    "work/stash-drop",
];

/// The rule whose rewrites a snapshot of commits answers.
const HISTORY_REWRITE: &str = "work/history-rewrite";

/// Effects of another step that may move the revision a discard lands on
/// before it runs, as `git fetch` moves `origin/main`.
const REF_MOVES: [&str; 2] = ["git.remote_sync", "git.ref_update"];

/// Effects that change the work tree, its index or git's configuration. One
/// outside the discard's own git process makes the call something a snapshot
/// taken before it cannot cover.
const TREE_CHANGES: [&str; 13] = [
    "filesystem.write",
    "filesystem.create",
    "filesystem.delete",
    "filesystem.move",
    "filesystem.metadata",
    "filesystem.mount",
    "filesystem.unmount",
    "git.worktree_discard",
    "git.worktree_write",
    "git.index_write",
    "git.history_rewrite",
    "git.recovery_destroy",
    "git.config_write",
];

/// The effects of `TREE_CHANGES` that may put under a recursive delete what
/// a snapshot taken before the call does not hold: work moved there from
/// elsewhere, a mount, a file another step deletes as it moves it, or what
/// git writes from its own state. A write, a new file or folder and a
/// permission change bring nothing there but the call's own output, which
/// is no earlier work. A new link, which may redirect the delete, is a
/// create `discards` checks apart.
const INTO_DELETES: [&str; 10] = [
    "filesystem.delete",
    "filesystem.move",
    "filesystem.mount",
    "filesystem.unmount",
    "git.worktree_discard",
    "git.worktree_write",
    "git.index_write",
    "git.history_rewrite",
    "git.recovery_destroy",
    "git.config_write",
];

/// One snapshot that holds what a call's discards would destroy, made or
/// found current before the call ran. The decision's audit record keeps it
/// as data, so nothing reads a save back from `note`.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Saved {
    /// The rules whose discards it holds.
    pub(crate) rules: Vec<String>,
    pub(crate) snapshot: String,
    /// The repository, or the folder, it belongs to: where `nah undo` runs.
    pub(crate) root: String,
    /// What it holds, such as `8 files, 51 lines`.
    pub(crate) holds: String,
    /// Undo cannot restore it in place, because Nah could not tell which
    /// tree a path copy writes from: `nah undo ID --into DIR` recovers it
    /// into a new folder.
    pub(crate) apart: bool,
    /// What the agent is told about it.
    pub(crate) note: String,
}

/// The discards of one call that a snapshot taken before it covers, and the
/// rules that own them: those that matched, and for each discard the one it
/// falls under, which may not match it (a `git clean` of only build output,
/// a `git reset --merge`).
#[derive(Clone, Debug)]
pub(crate) struct Discards {
    pub(crate) rules: Vec<&'static str>,
    pub(crate) discards: Vec<Discard>,
    /// Each rule's own reason, by `rules`, which a block keeps when the save
    /// fails.
    pub(crate) reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Discard {
    /// The folder git runs in; the snapshot is of its work tree.
    pub(crate) directory: PathBuf,
    pub(crate) kind: DiscardKind,
    pub(crate) selection: Selection,
    /// For tracked changes, the content it writes in their place.
    pub(crate) writes: Writes,
    /// Whether it copies without moving HEAD, as a pathspec checkout or
    /// restore does.
    pub(crate) keeps_head: bool,
    pub(crate) from_index: bool,
    pub(crate) writes_index: bool,
    pub(crate) source_no_overlay: bool,
    /// The pathspec mode options its git reads from its environment and
    /// command line, such as `--icase-pathspecs`; `None` when Nah cannot
    /// tell them.
    pub(crate) pathspec_options: Option<Vec<String>>,
    /// The folder the shell expands a glob among its pathspecs in, such as
    /// an unquoted `*`, when the glob may match a name that starts with `:`:
    /// git reads such a name as pathspec magic, so the save reads the
    /// folder's names.
    pub(crate) globbed_in: Option<PathBuf>,
}

/// What a discard is limited to.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum Selection {
    /// The whole work tree.
    All,
    /// These absolute paths and what lies under them.
    Paths(Vec<PathBuf>),
    /// The files these pathspecs match when git runs in the discard's
    /// folder, which the save lists before the command runs.
    Pathspecs(Vec<String>),
    /// What this shell glob selects, which Nah cannot tell: the save blocks.
    Unknown(String),
    /// The refs these deletes take, which the save lists.
    Refs(Vec<RefDeletion>),
}

/// What a discard of tracked changes writes. Content from the index or from
/// HEAD lands only on tracked paths; another tree can also write over an
/// untracked or ignored file in its way, which the rolling copy may not hold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Writes {
    /// The index or HEAD.
    Current,
    /// The tree this revision names when the command runs.
    Tree(String),
    /// A tree Nah cannot name before the command runs.
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum DiscardKind {
    /// Tracked changes: `reset --hard`, checkout, restore, switch.
    Changes,
    /// Untracked files, and with `ignored` the ignored ones; with
    /// `ignored_only` only those (`git clean -X`).
    Clean { ignored: bool, ignored_only: bool },
    /// Everything under the selected paths, as a recursive delete takes it:
    /// in a Git work tree what Git cannot check out again, its tracked
    /// changes and untracked and ignored files; in any other folder (`git`
    /// false) every file. A forced `git rm` (`tracked_only`) takes only the
    /// tracked files there, with their changes.
    Delete { git: bool, tracked_only: bool },
    /// The stash entry `stash@{entry}`, or with `None` every entry: its
    /// save copies commits, not files.
    StashDrop { entry: Option<usize> },
    /// The local refs of its `Selection::Refs`, whose save copies commits.
    RefDelete,
    /// A rewrite of history that moves what `moves` names: its save copies
    /// the commits only those reach.
    HistoryRewrite { moves: Moves },
}

/// What a history rewrite may move from the commits it names now.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Moves {
    /// `HEAD` and the local branches: a rebase, an amend or a reset.
    Branches,
    /// The backups under `refs/original/`: a forced `git filter-branch`.
    Backups,
    /// Any ref, and every commit a reflog records: `git filter-repo`.
    History,
}

impl DiscardKind {
    /// The rule a discard falls under.
    pub(crate) fn rule(self) -> &'static str {
        match self {
            DiscardKind::Changes => "work/changes-discard",
            DiscardKind::Clean { .. } => "work/untracked-clean",
            DiscardKind::Delete { .. } => "work/files-delete",
            DiscardKind::StashDrop { .. } => "work/stash-drop",
            DiscardKind::RefDelete => "work/branch-delete",
            DiscardKind::HistoryRewrite { .. } => HISTORY_REWRITE,
        }
    }
}

/// What save-then-run does with a call's discards.
#[derive(Debug)]
pub(crate) enum Saving {
    /// The call holds no discard of a work rule at core.
    Nothing,
    /// A snapshot answers these discards.
    Saves(Discards),
    /// The discards of `rules`, which run at core, cannot be saved in this
    /// call, for `why`: each blocks under its rule, and the agent is told
    /// `how` to go on.
    Blocks {
        rules: Vec<&'static str>,
        why: String,
        how: &'static str,
    },
}

/// What save-then-run does with the discards in `plan` of the rules that run
/// at core by `level`. A snapshot answers them when nothing else in the call
/// changes the tree, no step escapes the analysis, no rule of theirs runs
/// whole and every one is a kind a snapshot covers; where they are all
/// recursive deletes, when nothing else may bring earlier work under them
/// and none takes the folder the call runs in. Otherwise each blocks.
/// They are read from the plan, not from the rules' matches, which leave out
/// what a 1.x exemption spares (`git clean` of logs), what 1.x never covered
/// (`git reset --merge`) and the path discards that block only at strict.
/// A discard whose rule is off is left to run, and so is one the
/// observation shows has nothing to lose (`lossless`, by effect): it is no
/// discard. A recursive delete inside the project (`deletes`, by effect) is
/// one: the matches of `work/files-delete` count only through it, so a
/// recursive permission change or overwrite of the project, which no
/// snapshot answers, blocks under the rule's own part. A history rewrite is
/// taken only where a part of `work/history-rewrite` that a snapshot
/// answers matched, which it does only where the rewrite may lose commits.
pub(crate) fn discards(
    plan: &Plan,
    matches: &ShippedGuardMatches,
    level: &dyn Fn(&str) -> GuardLevel,
    lossless: &[bool],
    deletes: &[Option<ProjectDelete>],
) -> Saving {
    let pathspecs = pathspec_discards(plan);
    let (mut discards, executions, mut uncovered) =
        found(plan, matches, &pathspecs, lossless, deletes);
    let rewrites_lose_nothing = !matched_saved(matches, HISTORY_REWRITE);
    // A fetch in the call may move the refs a save counts on to keep what
    // it leaves out, as a pull moves the upstream a rebase then replays
    // onto, so beside one the save holds every commit history reaches.
    let fetches = plan
        .effects
        .iter()
        .any(|effect| effect.operation.as_str() == "git.remote_sync");
    let mut rewrites = Vec::new();
    for effect in &plan.effects {
        match rewrite(effect) {
            _ if rewrites_lose_nothing => {}
            Some(Some(mut discard)) => {
                if fetches {
                    discard.kind = DiscardKind::HistoryRewrite {
                        moves: Moves::History,
                    };
                }
                rewrites.push((discard, effect));
            }
            Some(None) => {}
            None => uncovered = true,
        }
    }
    let rewritten = rewrites
        .iter()
        .map(|(_, effect)| effect.execution)
        .collect::<Vec<_>>();
    let only_rewrites = discards.is_empty() && !rewrites.is_empty();
    discards.extend(rewrites.iter().map(|(discard, _)| discard.clone()));
    let mut rules = RULES
        .into_iter()
        .filter(|rule| *rule != "work/files-delete" && matched_saved(matches, rule))
        .chain(discards.iter().map(|discard| discard.kind.rule()))
        .chain(lossy(plan, &pathspecs, lossless).map(|discard| discard.rule))
        .collect::<Vec<_>>();
    rules.sort();
    rules.dedup();
    let whole = rules.iter().any(|rule| level(rule) == GuardLevel::Strict);
    rules.retain(|rule| level(rule) == GuardLevel::Core);
    discards.retain(|discard| rules.contains(&discard.kind.rule()));
    if rules.is_empty() {
        return Saving::Nothing;
    }
    // A recursive delete of everything under its paths loses only what is
    // there when it runs, and a snapshot taken before the call holds what
    // is there before every step of it: what another step puts there first
    // is that step's own output, not earlier work. So where the call's
    // discards are all such deletes, a step that writes files, or one Nah
    // cannot follow, leaves the snapshot sound, unless it is a delete's own
    // command or launches it (`sudo rm -rf src`); only a step that may bring
    // earlier work under a delete, or redirect it, does not
    // (`INTO_DELETES`). A step Nah cannot follow could lose work by itself,
    // with or without the delete beside it, which no rule judges either.
    // That holds only for a delete the call waits for: one in a background
    // or batch job may run after the call returns, over work written since,
    // so it is judged as every other discard is.
    let delete_effects = plan
        .effects
        .iter()
        .zip(deletes)
        .filter(|(_, delete)| delete.is_some())
        .map(|(effect, _)| effect)
        .collect::<Vec<_>>();
    let only_deletes = rules == ["work/files-delete"]
        && discards.iter().all(|discard| {
            matches!(
                discard.kind,
                DiscardKind::Delete {
                    tracked_only: false,
                    ..
                }
            )
        })
        && !delete_effects
            .iter()
            .any(|effect| nah_effinterp::detached_launch(plan, effect));
    // A step Nah could not follow may change the tree before the discard.
    // An unmodeled environment read cannot, nor can a sudo whose own target
    // is no discard (`sudo true; git clean -fd`): Nah could not tell which
    // of the programs it states runs, but none of them discards. A
    // recursive delete is one, so `sudo rm -rf src` stays opaque.
    let discarding = plan
        .effects
        .iter()
        .zip(deletes)
        .filter(|(_, delete)| delete.is_some())
        .map(|(effect, _)| effect.execution)
        .chain(executions.iter().copied())
        .chain(rewritten.iter().copied())
        .collect::<Vec<_>>();
    // Nor can what a rewrite's own command runs, its hooks and filter code,
    // change the commits it saves.
    let opaque = plan.boundaries.iter().enumerate().any(|(index, boundary)| {
        let rewrites_own = rewrites.iter().any(|(_, effect)| {
            nah_effinterp::git_hook_boundary(plan, index, effect)
                || !boundary.provenance.is_empty()
                    && boundary
                        .provenance
                        .iter()
                        .all(|node| effect.provenance.contains(node))
        });
        !rewrites_own
            && !pathspecs.iter().any(|(_, effects)| {
                effects
                    .iter()
                    .any(|effect| nah_effinterp::names_pathspec(boundary, effect))
            })
            && (boundary.domains.is_empty()
                || boundary
                    .domains
                    .iter()
                    .any(|domain| domain.0 != "environment"))
            && !launches_no_discard(plan, boundary, &discarding)
            && (!only_deletes || reaches_delete(plan, boundary, &delete_effects))
    });
    // A recursive delete's own process may move or write into what it
    // deletes before it deletes, which a snapshot taken before the call
    // would miss, so only the delete itself is spared, not its execution;
    // `git rm`'s index write beside its delete changes no file, nor does a
    // redirection of the call's output to /dev/null.
    let deleting = delete_effects
        .iter()
        .map(|effect| effect.execution)
        .collect::<Vec<_>>();
    let elsewhere = |operations: &[&str]| {
        plan.effects
            .iter()
            .zip(deletes)
            .filter(|(effect, _)| !nah_effinterp::redirects_to_null_device(plan, effect))
            .any(|(effect, delete)| {
                !executions.contains(&effect.execution)
                    && delete.is_none()
                    && !(effect.operation.as_str() == "git.index_write"
                        && deleting.contains(&effect.execution))
                    && operations.contains(&effect.operation.as_str())
            })
    };
    let blocks = |why: &str, how| Saving::Blocks {
        rules: rules.clone(),
        why: why.to_owned(),
        how,
    };
    const FIRST: &str = "Commit or stash that work first, or ask the operator";
    const ALONE: &str = "Run the discard as a command of its own, then the rest";
    // A delete of the folder the call runs in, or of one above it, takes
    // more than the project's files below it.
    let holding_cwd = deletes
        .iter()
        .zip(lossless)
        .filter(|(_, lossless)| !**lossless)
        .find_map(|(delete, _)| {
            let delete = delete.as_ref()?;
            Some((delete, delete.holds_cwd.as_ref()?))
        });
    if let Some((delete, path)) = holding_cwd.filter(|_| rules.contains(&"work/files-delete")) {
        let why = if *path == delete.project {
            format!(
                "it deletes the project folder {path} itself{}",
                if delete.git {
                    ", with the repository's history in .git"
                } else {
                    ""
                }
            )
        } else {
            format!("it deletes {path}, the folder the call runs in or one above it")
        };
        return blocks(
            &why,
            "Delete only folders inside the one the call runs in, or ask the operator",
        );
    }
    // A scheduler may start the job that discards long after the call, so a
    // snapshot taken now may not hold what it then deletes. A delete in a
    // job the call waits for, an `srun` step, runs on what it holds.
    if !only_deletes
        && plan.effects.iter().any(|effect| {
            discarding.contains(&effect.execution) && nah_effinterp::deferred_launch(plan, effect)
        })
    {
        return blocks(
            "the discard runs in a job a scheduler such as Slurm may start later, after any snapshot nah could take now",
            FIRST,
        );
    }
    if uncovered {
        return blocks(
            "nah does not save a `git show` written over a path, a worktree or submodule removal, a ref delete whose refs it cannot read, a forced `git filter-branch` over backups outside refs/original/, or a discard in a repository it cannot resolve",
            FIRST,
        );
    }
    if whole {
        return blocks(
            "another work rule in the call runs whole, which blocks discards instead of saving them",
            FIRST,
        );
    }
    if opaque {
        return blocks(
            "the call also runs a step nah cannot fully follow, such as `sudo`, `eval` or a build or test tool, which could change the files first",
            ALONE,
        );
    }
    // Another step that writes or creates anything but a folder at a deleted
    // path, or at a folder above one, may leave a link there, as `cp -RP`
    // copies one, through which the delete reaches files the snapshot does
    // not hold; so may one whose path Nah cannot tell. A delete's own
    // process, such as `rsync --delete` writing the folder it prunes, runs
    // its write and delete on the same folder.
    let deleted_paths = delete_effects
        .iter()
        .filter_map(|effect| fs_path(&effect.resource))
        .chain(
            deletes
                .iter()
                .flatten()
                .flat_map(|delete| &delete.paths)
                .map(Path::new),
        )
        .collect::<Vec<_>>();
    let on_delete_path = |effect: &Effect| {
        matches!(
            effect.operation.as_str(),
            "filesystem.write" | "filesystem.create"
        ) && effect.attributes.get("directory") != Some(&AttrValue::Bool(true))
            && !deleting.contains(&effect.execution)
            && !nah_effinterp::redirects_to_null_device(plan, effect)
            && fs_path(&effect.resource).is_none_or(|path| {
                deleted_paths
                    .iter()
                    .any(|deleted| deleted.starts_with(path))
            })
    };
    if only_deletes
        && (elsewhere(&INTO_DELETES)
            || plan.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.create"
                    && effect.attributes.get("symlink") == Some(&AttrValue::Bool(true))
                    || on_delete_path(effect)
            }))
    {
        return blocks(
            "the call also moves files, makes a link, writes over a folder it deletes or runs git in another step, which may put work under the delete that a snapshot taken before the call does not hold",
            ALONE,
        );
    }
    // A snapshot of commits holds no file, so only one of files minds
    // another step's changes to them.
    if !only_deletes && !only_rewrites && elsewhere(&TREE_CHANGES) {
        return blocks(
            "the call also changes files in another step, such as a build, a test or a write, so nah cannot save the discard and run it as one step",
            ALONE,
        );
    }
    // A save of commits keeps out what other refs reach when it runs, and
    // copies the tips the moved refs name then: another step that moves a
    // ref may change both before the rewrite runs.
    if !rewrites.is_empty()
        && plan.effects.iter().any(|effect| {
            !rewritten.contains(&effect.execution)
                && effect.operation.as_str().starts_with("git.")
                && !matches!(
                    effect.operation.as_str(),
                    "git.read" | "git.index_write" | "git.worktree_write" | "git.remote_sync"
                )
        })
    {
        return blocks(
            "the call also runs another git command that may move a branch or the commits a rewrite replaces, so nah cannot save the rewrite and run it as one step",
            ALONE,
        );
    }
    // The save runs before the call, so it holds no commit an earlier
    // rewrite in it makes and a later one may leave unreached.
    if rewritten.iter().any(|execution| *execution != rewritten[0]) {
        return blocks(
            "the call runs more than one history rewrite, and a later one may leave commits an earlier one made, which nah cannot save before the call runs",
            ALONE,
        );
    }
    // A ref keeps the commits of a stash entry or deleted ref it reaches,
    // which the save then leaves out: another step may move or delete that
    // ref. Stash drops and ref deletes are saved apart, so each is such a
    // step for the other.
    let others_move_refs = |kind: fn(&Effect, &Plan) -> bool| {
        let executions = plan
            .effects
            .iter()
            .filter(|effect| kind(effect, plan))
            .map(|effect| effect.execution)
            .collect::<Vec<_>>();
        !executions.is_empty()
            && plan.effects.iter().any(|effect| {
                !executions.contains(&effect.execution)
                    && effect.operation.as_str().starts_with("git.")
                    && effect.operation.as_str() != "git.read"
            })
    };
    if others_move_refs(covered_stash_drop) || others_move_refs(covered_ref_delete) {
        return blocks(
            "the call also runs another git command that may move or delete what keeps a stash entry or a deleted ref's commits, so nah cannot save the drop or delete and run it as one step",
            ALONE,
        );
    }
    if discards.is_empty() {
        return Saving::Nothing;
    }
    // A moved ref may be the one it lands on, HEAD's own branch among
    // them, so the tree a tracked-changes discard writes is unknown: a
    // mixed reset also rewrites the index a pathspec copy takes.
    if elsewhere(&REF_MOVES) {
        for discard in &mut discards {
            if discard.kind == DiscardKind::Changes {
                discard.writes = Writes::Unknown;
            }
        }
    }
    let reasons = rules
        .iter()
        .map(|rule| {
            matches
                .matched
                .iter()
                .find(|part| part.rule == *rule)
                .map(|part| {
                    part.reason.clone().unwrap_or_else(|| {
                        crate::catalog::shipped_guards().definitions()[part.part]
                            .reason
                            .to_owned()
                    })
                })
                .unwrap_or_else(|| {
                    unmatched_reason(
                        rule,
                        discards.iter().any(|discard| {
                            discard.kind.rule() == *rule
                                && matches!(discard.selection, Selection::All)
                        }),
                    )
                    .to_owned()
                })
        })
        .collect();
    Saving::Saves(Discards {
        rules,
        discards,
        reasons,
    })
}

/// The reason of the work rule `rule` for a discard no part of it matched,
/// of the whole tree or of what it names; for a rule whose discards no part
/// leaves unmatched, its first part's.
fn unmatched_reason(rule: &str, whole: bool) -> &'static str {
    match (rule, whole) {
        ("work/changes-discard", true) => {
            "this would discard the project's uncommitted changes. Git cannot bring back changes that were never staged"
        }
        ("work/changes-discard", false) => {
            "this would discard uncommitted changes to the files it names. Git cannot bring back changes that were never staged"
        }
        ("work/untracked-clean", true) => {
            "this would delete untracked files across the project. Git cannot bring them back; `git clean -n` shows what it would remove"
        }
        ("work/untracked-clean", false) => {
            "this would delete the untracked files it names. Git cannot bring them back; `git clean -n` shows what it would remove"
        }
        ("work/stash-drop", _) => {
            "this would drop stash entries. Git cannot bring back an entry no other ref keeps"
        }
        ("work/branch-delete", _) => "this would delete refs whose commits no other ref keeps",
        _ => crate::catalog::shipped_guards()
            .definitions()
            .iter()
            .find(|definition| definition.rule == rule)
            .map_or("", |definition| definition.reason),
    }
}

/// The discards in `plan` a snapshot covers, among them those of
/// `pathspecs`, with the executions they run in, and whether the plan also
/// holds one the work rules match that a snapshot does not cover. A discard
/// the observation shows has nothing to lose (`lossless`, by effect) is
/// none. Stash drops and ref deletes are judged together by `matches`
/// instead: each drop moves the entries after it up, so one that loses
/// nothing alone may not beside another.
fn found(
    plan: &Plan,
    matches: &ShippedGuardMatches,
    pathspecs: &[(Discard, Vec<&Effect>)],
    lossless: &[bool],
    deletes: &[Option<ProjectDelete>],
) -> (Vec<Discard>, Vec<ExecutionNodeRef>, bool) {
    let lossless = |effect: &Effect| {
        plan.effects
            .iter()
            .zip(lossless)
            .any(|(other, lossless)| *lossless && std::ptr::eq(other, effect))
    };
    let mut discards = Vec::new();
    let mut executions = Vec::new();
    let mut uncovered = false;
    // A drop whose entries Nah tells matches a part of `work/stash-drop`
    // exactly when it may lose something: each part blocks only where the
    // observation leaves a dropped entry that no other ref reaches. So with
    // the ref-delete part of `work/branch-delete` and a deleted ref.
    let stash_loses_nothing =
        !matches.matched("work/stash-drop") && !plan.effects.iter().any(unresolved_stash_drop);
    let refs_lose_nothing = !matched_saved(matches, "work/branch-delete");
    for effect in &plan.effects {
        match covered(effect, plan) {
            Some(Some(Discard {
                kind: DiscardKind::StashDrop { .. },
                ..
            })) if stash_loses_nothing => executions.push(effect.execution),
            Some(Some(Discard {
                kind: DiscardKind::RefDelete,
                ..
            })) if refs_lose_nothing => executions.push(effect.execution),
            Some(Some(discard))
                if matches!(
                    discard.kind,
                    DiscardKind::StashDrop { .. } | DiscardKind::RefDelete
                ) || !lossless(effect) =>
            {
                discards.push(discard);
                executions.push(effect.execution);
            }
            None if !lossless(effect) => uncovered = true,
            Some(_) | None => {}
        }
    }
    for (discard, effects) in pathspecs {
        if !lossless(effects[0]) {
            discards.push(discard.clone());
            executions.push(effects[0].execution);
        }
    }
    for (effect, delete) in plan.effects.iter().zip(deletes) {
        let Some(delete) = delete.as_ref().filter(|_| !lossless(effect)) else {
            continue;
        };
        discards.push(Discard {
            directory: PathBuf::from(&delete.project),
            kind: DiscardKind::Delete {
                git: delete.git,
                tracked_only: matches!(
                    effect.attributes.get("tracked_only"),
                    Some(AttrValue::Bool(true))
                ),
            },
            selection: Selection::Paths(delete.paths.iter().map(PathBuf::from).collect()),
            writes: Writes::Current,
            keeps_head: false,
            from_index: false,
            writes_index: false,
            source_no_overlay: false,
            pathspec_options: Some(Vec::new()),
            globbed_in: None,
        });
    }
    (discards, executions, uncovered)
}

/// The absolute path `resource` names, if it names one outright.
fn fs_path(resource: &ResourceExpr) -> Option<&Path> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path.starts_with('/') => Some(Path::new(path)),
        _ => None,
    }
}

/// Whether `boundary` is a sudo's own, which leaves only which of the
/// programs it states runs unknown, and none of them, nor what they launch,
/// runs in `executions`.
fn launches_no_discard(plan: &Plan, boundary: &Boundary, executions: &[ExecutionNodeRef]) -> bool {
    let launched = launched_by(plan, boundary);
    boundary.reason == BoundaryReason::UNREAD_CONFIG
        && matches!(&boundary.domains[..], [domain] if domain.0 == "process")
        && !launched.is_empty()
        && !launched.iter().any(|node| executions.contains(node))
}

/// Whether `boundary` leaves unknown what one of `deletes` does: it is a
/// delete's own, or of a command that launches one, as a sudo's is. One with
/// no provenance, such as a program whose source Nah cannot read, names no
/// command that states a delete.
fn reaches_delete(plan: &Plan, boundary: &Boundary, deletes: &[&Effect]) -> bool {
    !boundary.provenance.is_empty()
        && deletes.iter().any(|delete| {
            boundary
                .provenance
                .iter()
                .all(|node| delete.provenance.contains(node))
        })
        || launched_by(plan, boundary)
            .iter()
            .any(|node| deletes.iter().any(|delete| delete.execution == *node))
}

/// The executions the command of `boundary` launches, and what they launch.
fn launched_by(plan: &Plan, boundary: &Boundary) -> Vec<ExecutionNodeRef> {
    let edges = &plan.execution_graph.edges;
    let mut launched = edges
        .iter()
        .filter(|edge| {
            boundary
                .provenance
                .iter()
                .any(|node| edge.evidence.contains(node))
        })
        .map(|edge| edge.to)
        .collect::<Vec<_>>();
    let mut next = 0;
    while let Some(&from) = launched.get(next) {
        for edge in edges.iter().filter(|edge| edge.from == from) {
            if !launched.contains(&edge.to) {
                launched.push(edge.to);
            }
        }
        next += 1;
    }
    launched
}

/// A discard the observation does not show has nothing to lose, by the rule
/// it falls under: whether it takes the whole tree, and whether it is a
/// reset.
struct Lossy {
    rule: &'static str,
    whole: bool,
    reset: bool,
}

/// The discards in `plan`, with those of `pathspecs`, that may lose work
/// (`lossless`, by effect, says which cannot): the ones a snapshot covers,
/// and requests whose repository Nah could not resolve, such as one with
/// its own `--git-dir`.
fn lossy<'a>(
    plan: &'a Plan,
    pathspecs: &'a [(Discard, Vec<&Effect>)],
    lossless: &'a [bool],
) -> impl Iterator<Item = Lossy> + 'a {
    let requested = plan
        .effects
        .iter()
        .zip(lossless)
        .filter(|(_, lossless)| !**lossless)
        .filter_map(|(effect, _)| {
            let attribute = |name: &str| effect.attributes.get(name);
            let reset = effect.operation.as_str() == "git.reset_request";
            match covered(effect, plan) {
                // Stash drops and ref deletes are judged by their parts'
                // matches, as in `found`: only a drop whose entry Nah cannot
                // tell may lose work no part matched.
                Some(Some(Discard {
                    kind: DiscardKind::StashDrop { .. },
                    ..
                })) if !unresolved_stash_drop(effect) => None,
                Some(Some(Discard {
                    kind: DiscardKind::RefDelete,
                    ..
                })) => None,
                // A selection of a work tree set outright, as under
                // `GIT_WORK_TREE`, rather than one Git discovers from the
                // folder, such as `git -C pkg`, takes that whole tree.
                Some(Some(discard)) => Some(Lossy {
                    rule: discard.kind.rule(),
                    whole: match &discard.selection {
                        Selection::All => true,
                        Selection::Paths(paths) => {
                            !reset
                                && attribute("discovers_from_worktree")
                                    == Some(&AttrValue::Bool(false))
                                && paths.iter().all(|path| *path == discard.directory)
                        }
                        _ => false,
                    },
                    reset,
                }),
                Some(None) => None,
                None => {
                    let rule = match (effect.operation.as_str(), attribute("discard_mode")) {
                        ("git.clean_request", _) => DiscardKind::Clean {
                            ignored: false,
                            ignored_only: false,
                        },
                        ("git.reset_request", _) => DiscardKind::Changes,
                        ("git.worktree_discard_request", Some(AttrValue::String(mode)))
                            if matches!(mode.as_str(), "checkout" | "restore" | "switch") =>
                        {
                            DiscardKind::Changes
                        }
                        _ => return None,
                    }
                    .rule();
                    let flag = |name| matches!(attribute(name), Some(AttrValue::Bool(true)));
                    Some(Lossy {
                        rule,
                        whole: flag("selects_top")
                            || attribute("scope") != Some(&AttrValue::String("selected".into())),
                        reset,
                    })
                }
            }
        });
    let named = pathspecs
        .iter()
        .filter(move |(_, effects)| {
            !plan
                .effects
                .iter()
                .zip(lossless)
                .any(|(other, lossless)| *lossless && std::ptr::eq(other, effects[0]))
        })
        .map(|(discard, _)| Lossy {
            rule: discard.kind.rule(),
            whole: false,
            reset: false,
        });
    requested.chain(named)
}

/// `matches` with a part of each rule in `whole` that a lossy discard in
/// `plan` falls under while no part of it matched: a discard of named paths
/// or pathspecs, such as a clean of named paths or one whose pathspecs Nah
/// cannot read as plain paths, or one of the whole tree a part does not
/// spell, such as `git -C src clean -fd ':/'`. A rule that decides whole,
/// at strict or where nothing saves the call, blocks every such discard a
/// snapshot would answer at core, or could not, so neither is laxer than
/// saving. Whole-tree resets are left to the parts: `--merge` and `--keep`
/// keep what they would overwrite. A rule in `unsaved`, whose discards
/// this call cannot save first, blocks every lossy discard of its own. A
/// rule in `whole_tree`, at core where nothing can save, blocks only such a
/// discard of the whole tree, as 1.x's forced-clean and worktree-discard
/// guards did, and leaves named paths and stash drops to run as 1.x did.
pub(crate) fn with_unmatched(
    matches: &ShippedGuardMatches,
    plan: &Plan,
    lossless: &[bool],
    whole: &[&str],
    whole_tree: &[&str],
    unsaved: &[&str],
) -> ShippedGuardMatches {
    let pathspecs = pathspec_discards(plan);
    let mut kept = matches.clone();
    for discard in lossy(plan, &pathspecs, lossless) {
        let rule = discard.rule;
        let tree = discard.whole && !discard.reset;
        if kept.matched(rule)
            || !(unsaved.contains(&rule)
                || whole.contains(&rule) && !(discard.whole && discard.reset)
                || whole_tree.contains(&rule) && tree && rule != "work/stash-drop")
        {
            continue;
        }
        let part = crate::catalog::shipped_guards()
            .definitions()
            .iter()
            .position(|definition| definition.rule == rule)
            .expect("a work rule has a part");
        kept.matched.push(MatchedPart {
            rule,
            part,
            reason: Some(unmatched_reason(rule, discard.whole).to_owned()),
        });
    }
    kept
}

/// `matches` without the parts that block at core only because a snapshot
/// answers them where the runtime saves: a part of a rule of `RULES` at core
/// whose 1.x guard shipped off (`git-ref-delete`, `git-history-rewrite`).
/// Where nothing can save, on Windows or in a runtime with no post-call
/// event, `work` at core is then never stricter than 1.x; at strict every
/// part still blocks.
pub(crate) fn unsaveable(
    matches: &ShippedGuardMatches,
    level: &dyn Fn(&str) -> GuardLevel,
) -> ShippedGuardMatches {
    let definitions = crate::catalog::shipped_guards().definitions();
    let mut kept = matches.clone();
    kept.matched.retain(|part| {
        !(RULES.contains(&part.rule)
            && level(part.rule) == GuardLevel::Core
            && definitions[part.part].replaces.is_some_and(|legacy| {
                nah_policy::LEGACY_GUARDS
                    .iter()
                    .any(|(name, on)| *name == legacy && !on)
            }))
    });
    kept
}

/// `matches` with each part of the rules `unsaved` telling, after its own
/// reason, why Nah could not save the discard first and `how` to go on. A
/// block message leads with one rule's reason and names the others, so
/// where both work rules matched, each one's reason also tells the other's.
pub(crate) fn unsaved(
    matches: &ShippedGuardMatches,
    unsaved: &[&str],
    why: &str,
    how: &str,
) -> ShippedGuardMatches {
    let reason = |part: &MatchedPart| {
        part.reason.clone().unwrap_or_else(|| {
            crate::catalog::shipped_guards().definitions()[part.part]
                .reason
                .to_owned()
        })
    };
    let mut kept = matches.clone();
    for part in kept
        .matched
        .iter_mut()
        .filter(|part| unsaved.contains(&part.rule))
    {
        part.reason = Some(format!(
            "{}; nah could not save it first: {why}. {how}",
            reason(part)
        ));
    }
    let reasons = RULES
        .into_iter()
        .filter_map(|rule| {
            let part = kept.matched.iter().find(|part| part.rule == rule)?;
            Some((rule, reason(part)))
        })
        .collect::<Vec<_>>();
    if reasons.len() > 1 {
        for part in kept
            .matched
            .iter_mut()
            .filter(|part| RULES.contains(&part.rule))
        {
            let mut told = reason(part);
            for (rule, other) in reasons.iter().filter(|(rule, _)| *rule != part.rule) {
                told = format!("{}. {rule}: {other}", told.trim_end_matches('.'));
            }
            part.reason = Some(told);
        }
    }
    kept
}

/// The discard `effect` requests, `Some(None)` for an effect that is none,
/// and `None` for one the work rules match that a snapshot does not cover:
/// removing a worktree or a submodule's, a `git show` written over a path,
/// or a discard whose repository Nah could not resolve.
fn covered(effect: &Effect, plan: &Plan) -> Option<Option<Discard>> {
    let attribute = |name: &str| effect.attributes.get(name);
    let flag = |name: &str| matches!(attribute(name), Some(AttrValue::Bool(true)));
    let text = |name: &str| match attribute(name) {
        Some(AttrValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    // A revision a command lands on: none, or HEAD, keeps the current one.
    let landing = |revision: Option<&str>| match revision {
        _ if !flag("target_complete") => Writes::Unknown,
        None | Some("HEAD") => Writes::Current,
        Some(revision) => Writes::Tree(revision.to_owned()),
    };
    // `keeps_head` for a pathspec checkout or restore.
    let (kind, writes, keeps_head) = match effect.operation.as_str() {
        // `--merge` and `--keep` also drop staged work, and `--merge` a
        // newly added file with it.
        "git.reset_request"
            if matches!(text("reset_mode"), Some("hard" | "merge" | "keep"))
                && text("scope") != Some("selected") =>
        {
            (DiscardKind::Changes, landing(text("target")), false)
        }
        "git.worktree_discard_request" => match text("discard_mode") {
            // A forced switch names the revision it lands on; a pathspec
            // form (`scope` whole or selected) says whether it copies from
            // a tree.
            Some("checkout" | "restore" | "switch") if attribute("target_complete").is_some() => (
                DiscardKind::Changes,
                landing(text("start_point").or(text("target"))),
                false,
            ),
            Some("checkout" | "restore" | "switch") => {
                let writes = match text("source") {
                    _ if !flag("from_tree") => Writes::Current,
                    Some("HEAD") => Writes::Current,
                    Some(source) => Writes::Tree(source.to_owned()),
                    None => Writes::Unknown,
                };
                (DiscardKind::Changes, writes, true)
            }
            Some(_) => return None,
            None => return Some(None),
        },
        // An exclude pattern, or configuration the command sets such as
        // `core.excludesFile`, makes `-X` take untracked files the save's own
        // listing does not call ignored, so it saves, or refuses over a
        // secret, as for `-x`.
        "git.clean_request" => (
            DiscardKind::Clean {
                ignored: flag("ignored"),
                ignored_only: flag("ignored_only") && !flag("excluded") && !flag("config_set"),
            },
            Writes::Current,
            false,
        ),
        // A drop also states a ref delete request beside this one.
        "git.recovery_destroy_request" if flag("stash") => (
            DiscardKind::StashDrop {
                entry: nah_effinterp::dropped_stash_entry(effect),
            },
            Writes::Current,
            false,
        ),
        // A remote ref a push prunes is no local loss.
        "git.ref_delete_request" if !flag("stash") && !flag("prune") => {
            match nah_effinterp::ref_deletion(effect) {
                // The stash drop stated beside it is the discard.
                Some(deleted) if nah_effinterp::deletes_stash(&deleted) => return Some(None),
                Some(_) => (DiscardKind::RefDelete, Writes::Current, false),
                None => return None,
            }
        }
        "git.read" if flag("historical") && text("disclosure") == Some("contents") => {
            return None;
        }
        _ => return Some(None),
    };
    if flag("dry_run") || !flag("active") {
        return Some(None);
    }
    let (directory, None) = repository_worktree(&effect.resource)? else {
        return None;
    };
    let selection = match attribute("selections") {
        // Which entries a drop takes is the kind's.
        _ if matches!(kind, DiscardKind::StashDrop { .. }) => Selection::All,
        _ if kind == DiscardKind::RefDelete => {
            Selection::Refs(nah_effinterp::ref_deletion(effect).into_iter().collect())
        }
        // A pathspec such as `:/` from a subfolder selects the whole tree,
        // whatever folder the engine states beside it.
        _ if flag("selects_top") => Selection::All,
        Some(AttrValue::List(paths)) => Selection::Paths(
            paths
                .iter()
                .map(|path| match path {
                    AttrValue::String(path) => Some(PathBuf::from(path)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?,
        ),
        Some(_) => return None,
        None if text("scope") == Some("selected") => return None,
        None => Selection::All,
    };
    let restores_index = keeps_head
        && text("discard_mode") == Some("restore")
        && plan.effects.iter().any(|other| {
            other.execution == effect.execution && other.operation.as_str() == "git.index_write"
        });
    Some(Some(Discard {
        directory,
        kind,
        selection,
        writes,
        keeps_head,
        from_index: keeps_head && !flag("from_tree") && !restores_index,
        writes_index: (keeps_head && text("discard_mode") == Some("checkout")) || restores_index,
        source_no_overlay: flag("source_no_overlay"),
        pathspec_options: pathspec_options(effect)?,
        globbed_in: None,
    }))
}

/// The history rewrite `effect` requests, `Some(None)` for an effect that is
/// none, and `None` for one whose repository Nah could not resolve, or a
/// forced `git filter-branch` over backups outside `refs/original/`, the
/// only ones the save reads: a rebase, an amend, `git filter-branch` or
/// `git filter-repo`, and a reset that moves `HEAD`, whatever it discards
/// besides.
fn rewrite(effect: &Effect) -> Option<Option<Discard>> {
    let moves = match effect.operation.as_str() {
        "git.history_rewrite_request" => match effect.attributes.get("history_operation") {
            Some(AttrValue::String(operation)) if operation == "filter-repo" => Moves::History,
            Some(AttrValue::String(operation)) if operation == "filter-branch" => {
                if effect.attributes.get("force") == Some(&AttrValue::Bool(true))
                    && !nah_effinterp::filter_branch_backups_default(effect)
                {
                    return None;
                }
                Moves::Backups
            }
            _ => Moves::Branches,
        },
        "git.reset_request" if nah_effinterp::reset_moves_head(effect) => Moves::Branches,
        _ => return Some(None),
    };
    let flag = |name: &str| matches!(effect.attributes.get(name), Some(AttrValue::Bool(true)));
    if flag("dry_run") || !flag("active") {
        return Some(None);
    }
    let (directory, None) = repository_worktree(&effect.resource)? else {
        return None;
    };
    Some(Some(Discard {
        directory,
        kind: DiscardKind::HistoryRewrite { moves },
        selection: Selection::All,
        writes: Writes::Current,
        keeps_head: false,
        from_index: false,
        writes_index: false,
        source_no_overlay: false,
        pathspec_options: Some(Vec::new()),
        globbed_in: None,
    }))
}

/// Whether `effect` requests a stash drop whose entry Nah cannot tell, which
/// no part of `work/stash-drop` matches.
fn unresolved_stash_drop(effect: &Effect) -> bool {
    effect.operation.as_str() == "git.recovery_destroy_request"
        && effect.attributes.get("stash") == Some(&AttrValue::Bool(true))
        && effect.attributes.get("target_complete") != Some(&AttrValue::Bool(true))
}

/// Whether `effect` is a stash drop a snapshot covers.
fn covered_stash_drop(effect: &Effect, plan: &Plan) -> bool {
    matches!(
        covered(effect, plan),
        Some(Some(Discard {
            kind: DiscardKind::StashDrop { .. },
            ..
        }))
    )
}

/// Whether `effect` is a ref delete a snapshot covers.
fn covered_ref_delete(effect: &Effect, plan: &Plan) -> bool {
    matches!(
        covered(effect, plan),
        Some(Some(Discard {
            kind: DiscardKind::RefDelete,
            ..
        }))
    )
}

/// Whether a part of `rule` that a snapshot answers at core matched.
fn matched_saved(matches: &ShippedGuardMatches, rule: &str) -> bool {
    matches
        .matched
        .iter()
        .any(|part| part.rule == rule && answered(part))
}

/// Whether a snapshot answers the matched `part` at core: any part of a
/// rule of `WHOLE_UNSAVED`; of `work/history-rewrite` those that match only
/// a rewrite that may lose commits, not reflog expiry or pruning; and of
/// any other rule those at core.
fn answered(part: &MatchedPart) -> bool {
    let definition = &crate::catalog::shipped_guards().definitions()[part.part];
    match part.rule {
        rule if WHOLE_UNSAVED.contains(&rule) => true,
        HISTORY_REWRITE => definition.rewrites_history(),
        _ => definition.applies_at == GuardLevel::Core,
    }
}

/// The pathspec mode options `effect` states, `Some(None)` when it states
/// them unknown, and `None` when its attribute is malformed.
fn pathspec_options(effect: &Effect) -> Option<Option<Vec<String>>> {
    if matches!(
        effect.attributes.get("pathspec_options_unknown"),
        Some(AttrValue::Bool(true))
    ) {
        return Some(None);
    }
    match effect.attributes.get("pathspec_options") {
        None => Some(Some(Vec::new())),
        Some(AttrValue::List(options)) => options
            .iter()
            .map(|option| match option {
                AttrValue::String(option) => Some(option.clone()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(Some),
        Some(_) => None,
    }
}

/// The discards of the git commands whose pathspecs Nah cannot read as plain
/// paths, such as `git checkout -- '*.rs'` or `git restore ':(glob)src/**'`,
/// each with the effects that state it. Such a command
/// states no request, only one discard per pathspec beside a boundary that
/// names the selection unknown; nor the tree a checkout or restore copies
/// from, so the save takes it to be any. Git matches the pathspecs when the
/// save lists them, which settles the boundary.
fn pathspec_discards(plan: &Plan) -> Vec<(Discard, Vec<&Effect>)> {
    let requested = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str().ends_with("_request"))
        .map(|effect| effect.execution)
        .collect::<Vec<_>>();
    let mut found: Vec<(Discard, Vec<&Effect>)> = Vec::new();
    for effect in &plan.effects {
        if effect.operation.as_str() != "git.worktree_discard"
            || requested.contains(&effect.execution)
            || !plan
                .boundaries
                .iter()
                .any(|boundary| nah_effinterp::names_pathspec(boundary, effect))
        {
            continue;
        }
        let flag = |name: &str| matches!(effect.attributes.get(name), Some(AttrValue::Bool(true)));
        // `keeps_head` for a checkout or restore.
        let (kind, writes, keeps_head) = match effect.attributes.get("discard_mode") {
            Some(AttrValue::String(mode)) if mode == "checkout" || mode == "restore" => {
                (DiscardKind::Changes, Writes::Unknown, true)
            }
            Some(AttrValue::String(mode)) if mode == "clean" && !flag("dry_run") => (
                DiscardKind::Clean {
                    ignored: flag("ignored"),
                    ignored_only: false,
                },
                Writes::Current,
                false,
            ),
            // A forced `git rm` of what these pathspecs match.
            Some(AttrValue::String(mode)) if mode == "rm" => (
                DiscardKind::Delete {
                    git: true,
                    tracked_only: true,
                },
                Writes::Current,
                false,
            ),
            _ => continue,
        };
        let Some((directory, Some(_))) = repository_worktree(&effect.resource) else {
            continue;
        };
        let Some(pathspec_options) = pathspec_options(effect) else {
            continue;
        };
        match found
            .iter_mut()
            .find(|(_, effects)| effects[0].execution == effect.execution)
        {
            Some((_, effects)) => effects.push(effect),
            None => found.push((
                Discard {
                    directory,
                    kind,
                    selection: Selection::Pathspecs(Vec::new()),
                    writes,
                    keeps_head,
                    from_index: false,
                    writes_index: false,
                    source_no_overlay: false,
                    pathspec_options,
                    globbed_in: None,
                },
                vec![effect],
            )),
        }
    }
    // Every pathspec of the command selects, the plain ones too.
    for (discard, effects) in &mut found {
        discard.selection = effects
            .iter()
            .filter_map(|effect| repository_worktree(&effect.resource)?.1)
            .collect::<Result<Vec<_>, _>>()
            .map_or_else(Selection::Unknown, Selection::Pathspecs);
        // Pathspecs that only exclude take everything else: from the whole
        // tree for a checkout, restore or forced `git rm`, which the save's
        // listing in the folder must be told, but from the folder for a
        // clean. The listing reads the command's pathspec modes in their
        // order, so where git reads them literally, `:/` names no file and
        // widens nothing.
        if let Selection::Pathspecs(pathspecs) = &mut discard.selection
            && matches!(
                discard.kind,
                DiscardKind::Changes | DiscardKind::Delete { .. }
            )
            && !pathspecs.is_empty()
            && pathspecs.iter().all(|pathspec| excludes(pathspec))
        {
            pathspecs.push(":/".to_owned());
        }
        let Some(glob) = effects
            .iter()
            .filter_map(|effect| shell_glob(&effect.resource))
            .find(|glob| glob.starts_with(['*', '?', '[']))
        else {
            continue;
        };
        match plan
            .execution_graph
            .nodes
            .get(effects[0].execution.0 as usize)
            .and_then(|node| node.cwd.as_ref())
        {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) if path.starts_with('/') => discard.globbed_in = Some(PathBuf::from(path)),
            _ => discard.selection = Selection::Unknown(glob.to_owned()),
        }
    }
    found
}

/// Whether git reads `pathspec` as an exclusion: `:!x`, `:^x` or
/// `:(exclude)x`.
fn excludes(pathspec: &str) -> bool {
    let Some(magic) = pathspec.strip_prefix(':') else {
        return false;
    };
    match magic.strip_prefix('(') {
        Some(long) => long.split_once(')').is_some_and(|(words, _)| {
            words
                .split(',')
                .any(|word| word.trim_start().starts_with("exclude"))
        }),
        None => magic
            .chars()
            .take_while(|sign| matches!(sign, '/' | '!' | '^'))
            .any(|sign| sign != '/'),
    }
}

/// The shell glob a repository resource's pathspec is, such as an unquoted
/// `*.rs`, which the shell expands in its folder.
fn shell_glob(resource: &ResourceExpr) -> Option<&str> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                pathspec: Some(pathspec),
                ..
            },
    } = resource
    else {
        return None;
    };
    let ResourceExpr::Join { parts } = pathspec.as_ref() else {
        return None;
    };
    match &parts[..] {
        [
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            },
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            },
        ] if path == "." => Some(glob),
        _ => None,
    }
}

/// The folder of a repository resource that names its work tree by a
/// concrete path and no other git directory, and the pathspec it names, if
/// any, as git would take one reaching at least as far, or the shell glob
/// for which Nah cannot tell one.
fn repository_worktree(
    resource: &ResourceExpr,
) -> Option<(PathBuf, Option<Result<String, String>>)> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                git_dir: None,
                pathspec,
            },
    } = resource
    else {
        return None;
    };
    let pathspec = pathspec.as_deref().map(|pathspec| match pathspec {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Ok(path.clone()),
        // A shell glob the command's folder expands, such as an unquoted
        // `*.rs`: git's own `*` also crosses folders, so taken as a pathspec
        // it matches every name the shell could pass, and more.
        ResourceExpr::Join { .. } => match shell_glob(resource) {
            // Git reads each name such a glob expands to that starts with
            // `:` as pathspec magic, which `:(top)` widens to the whole
            // tree. One that starts with `:` itself expands to nothing else,
            // and the save reads the folder's names for one that may.
            Some(glob) if glob.starts_with(':') => Err(glob.to_owned()),
            Some(glob) => Ok(glob.to_owned()),
            None => Ok(":/".to_owned()),
        },
        // No pathspec reaches outside the work tree, so the whole tree holds
        // what one Nah cannot read reaches.
        _ => Ok(":/".to_owned()),
    });
    match worktree.as_ref() {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path.starts_with('/') => Some((PathBuf::from(path), pathspec)),
        _ => None,
    }
}

/// `matches` without the parts of the rules `held` that a snapshot answers
/// instead.
pub(crate) fn without(matches: &ShippedGuardMatches, held: &[&str]) -> ShippedGuardMatches {
    let mut kept = matches.clone();
    kept.matched
        .retain(|part| !held.contains(&part.rule) || !answered(part));
    kept
}
