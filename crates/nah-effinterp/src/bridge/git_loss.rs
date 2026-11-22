//! Whether a Git discard or history rewrite can lose anything, judged by the
//! repository's observed Git state: the state each one is judged by
//! (`git_state_queries`, read by `crates/nah-observe/src/git_state.rs`), and
//! the one answer the `GitLossPossible` qualifier and save-then-run read
//! (`git_discard_loses_nothing`, `git_rewrite_loses_nothing`).
//!
//! A recursive delete in a project no Git repository holds is judged in
//! `guard_host_facts.rs` (`folder_delete_loses_nothing`,
//! `lies_in_non_git_project`) with two checks this module owns for Git
//! deletes too: whether anything else the invocation does adds work where it
//! deletes (`rest_adds_nothing`), and whether a repository lies below a
//! deleted folder (`observed_nested_repository`). Dependencies run one way:
//! the host facts read this module, never the reverse.

use nah_proto::labels::{join_lexical_path, lexically_contains};
use nah_proto::observation::{
    GitCleanIgnored, GitRestoreSource, NestedRepositoryObservation, Observation, ObservationQuery,
    ObservationValue, Observed, PathKind, RefDeletion,
};
use std::collections::BTreeSet;

/// One Git state a discard is judged by: the repository Git finds from
/// `directory`, limited to what `pathspecs` match when Git runs there with
/// the pathspec mode options `pathspec_options` (no pathspec: the whole
/// tree), and what the discard takes there: the tracked files a copy from
/// `restores` writes, the untracked entries of kind `untracked` a clean
/// removes, or, with neither, the stash or the refs a delete names.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscardState<'a> {
    directory: std::borrow::Cow<'a, str>,
    pathspecs: Vec<String>,
    pathspec_options: Vec<String>,
    restores: Option<GitRestoreSource>,
    untracked: Option<GitCleanIgnored>,
}

impl<'a> DiscardState<'a> {
    fn whole(directory: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        Self {
            directory: directory.into(),
            pathspecs: Vec::new(),
            pathspec_options: Vec::new(),
            restores: None,
            untracked: None,
        }
    }
}

/// What decides whether a Git discard loses anything: the states of the
/// repositories it discards from. A discard limited to named paths or
/// pathspecs is judged by what Git matches of them, never by their
/// spelling. `None` for any other effect, and for a discard Nah cannot
/// judge: its repository is not the one Git finds from a named host
/// directory, Nah cannot hand Git its reach (a selection it did not
/// complete, pathspec modes it cannot tell, configuration the command sets,
/// which the observation's Git would not read, a shell glob), or it copies
/// from a tree Nah cannot name: one the command does not spell, or one
/// another step may move a ref under.
///
/// A git command whose pathspecs Nah cannot read as plain paths, such as
/// `git clean -fd -- '*.log'`, states no request, only one discard per
/// pathspec beside the boundary that names it unknown (`names_pathspec`):
/// each of them is judged by all of them. Without a request, a checkout or
/// restore is judged only when the engine marks it a copy from the index.
fn discard_states<'a>(
    plan: &'a effinterp_proto::Plan,
    effect: &'a effinterp_proto::Effect,
) -> Option<Vec<DiscardState<'a>>> {
    use effinterp_proto::AttrValue;
    if effect.operation.as_str() == "filesystem.delete" {
        return deleted_state(plan, effect).map(|state| vec![state]);
    }
    let worktree = host_worktree(effect)?;
    let flag = |name| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    // A request with an option the model does not know is never proven to
    // lose nothing: the option may change what it selects or loses.
    if flag("config_set") || flag("options_unknown") {
        return None;
    }
    let text = |name| match effect.attributes.get(name) {
        Some(AttrValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    // A ref another step moves may be the one the discard copies from.
    let moves_refs = plan.effects.iter().any(|other| {
        other.execution != effect.execution
            && matches!(
                other.operation.as_str(),
                "git.remote_sync" | "git.ref_update" | "git.ref_delete_request"
            )
    });
    let tree = |revision: Option<&str>| {
        Some(GitRestoreSource::Tree(
            revision.filter(|_| !moves_refs)?.to_owned(),
        ))
    };
    // A landing on the commit the command names, or on `HEAD`.
    let lands = |revision: Option<&str>| {
        if !flag("target_complete") {
            return None;
        }
        Some(vec![DiscardState {
            restores: Some(tree(Some(revision.unwrap_or("HEAD")))?),
            ..DiscardState::whole(worktree)
        }])
    };
    let selections = || match effect.attributes.get("selections") {
        Some(AttrValue::List(selections)) => selections
            .iter()
            .map(|selection| match selection {
                AttrValue::String(path) => Some(path.as_str()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>(),
        _ => None,
    };
    // An `-e` pattern adds to the ignore rules of `-X`, so the clean may then
    // remove any untracked entry; for the other modes it only keeps some.
    let untracked = || {
        Some(match (flag("ignored"), flag("ignored_only")) {
            (_, true) if flag("excluded") => GitCleanIgnored::Also,
            (_, true) => GitCleanIgnored::Only,
            (true, false) => GitCleanIgnored::Also,
            (false, false) => GitCleanIgnored::No,
        })
    };
    // `:/` from a subfolder selects the whole tree, whatever else it names.
    let selected = |restores: Option<GitRestoreSource>| {
        let restores = Some(restores?);
        if text("scope") != Some("selected") || flag("selects_top") {
            return Some(vec![DiscardState {
                restores,
                ..DiscardState::whole(worktree)
            }]);
        }
        let pathspecs = selections()?;
        if !flag("selection_complete") || pathspecs.is_empty() {
            return None;
        }
        Some(vec![DiscardState {
            directory: worktree.into(),
            pathspecs: pathspecs.into_iter().map(str::to_owned).collect(),
            pathspec_options: pathspec_options(effect)?,
            restores,
            untracked: None,
        }])
    };
    match effect.operation.as_str() {
        // `--merge` and `--keep` also drop staged work.
        "git.reset_request"
            if matches!(text("reset_mode"), Some("hard" | "merge" | "keep"))
                && text("scope") != Some("selected") =>
        {
            lands(text("target"))
        }
        // A stash drop states both.
        "git.recovery_destroy_request" | "git.ref_delete_request" if flag("stash") => {
            Some(vec![DiscardState::whole(worktree)])
        }
        // A remote ref a push prunes is no local loss.
        "git.ref_delete_request" if !flag("prune") => Some(vec![DiscardState::whole(worktree)]),
        "git.clean_request" => {
            let pathspec_options = pathspec_options(effect)?;
            // Without a pathspec the clean runs in the folder it was started
            // in, which is its one selection.
            let state = match (flag("pathspecs_given"), selections()) {
                _ if !flag("selection_complete") => return None,
                (true, _) if flag("selects_top") || text("scope") != Some("selected") => {
                    DiscardState {
                        pathspecs: vec![":/".into()],
                        ..DiscardState::whole(worktree)
                    }
                }
                (true, Some(selections)) if !selections.is_empty() => DiscardState {
                    pathspecs: selections.into_iter().map(str::to_owned).collect(),
                    ..DiscardState::whole(worktree)
                },
                (false, Some(selections)) => match selections[..] {
                    [directory] => DiscardState {
                        pathspecs: vec![directory.to_owned()],
                        ..DiscardState::whole(directory)
                    },
                    _ => return None,
                },
                (false, None) if text("scope") != Some("selected") => DiscardState::whole(worktree),
                _ => return None,
            };
            Some(vec![DiscardState {
                pathspec_options,
                untracked: untracked(),
                ..state
            }])
        }
        "git.worktree_discard_request" => match text("discard_mode")? {
            // A forced branch change lands on the revision it names.
            "checkout" | "switch" if text("scope") == Some("whole") => {
                lands(text("start_point").or(text("target")))
            }
            "checkout" | "restore" | "switch" if !flag("from_tree") => {
                selected(Some(GitRestoreSource::Index))
            }
            "checkout" | "restore" | "switch" => selected(tree(text("source"))),
            // The worktrees the request removes, with everything in them,
            // not the one it runs in.
            "worktree_remove" if flag("selection_complete") => {
                let removed = selections()?
                    .into_iter()
                    .map(|path| DiscardState {
                        restores: Some(GitRestoreSource::Tree("HEAD".into())),
                        untracked: Some(GitCleanIgnored::Also),
                        ..DiscardState::whole(path)
                    })
                    .collect::<Vec<_>>();
                (!removed.is_empty()).then_some(removed)
            }
            _ => None,
        },
        "git.worktree_discard"
            if (text("discard_mode") == Some("clean") || flag("from_index"))
                && !flag("dry_run")
                && !plan.effects.iter().any(|other| {
                    other.execution == effect.execution
                        && other.operation.as_str().ends_with("_request")
                }) =>
        {
            let pathspecs = plan
                .effects
                .iter()
                .filter(|other| {
                    other.execution == effect.execution
                        && other.operation.as_str() == "git.worktree_discard"
                })
                .map(|other| {
                    plan.boundaries
                        .iter()
                        .any(|boundary| names_pathspec(boundary, other))
                        .then(|| discarded_pathspec(other))
                        .flatten()
                })
                .collect::<Option<Vec<_>>>()?;
            let clean = text("discard_mode") == Some("clean");
            Some(vec![DiscardState {
                directory: worktree.into(),
                pathspecs,
                pathspec_options: pathspec_options(effect)?,
                restores: (!clean).then_some(GitRestoreSource::Index),
                untracked: if clean { untracked() } else { None },
            }])
        }
        _ => None,
    }
}

/// The pathspec magic a deleted path is handed to Git with.
const DELETED_PATH_MAGIC: &str = ":(literal,icase)";

/// The deleted path a delete's pathspec names.
fn deleted_path(pathspec: &str) -> &str {
    pathspec
        .strip_prefix(DELETED_PATH_MAGIC)
        .unwrap_or(pathspec)
}

/// The paths the Git state of a recursive host selection is judged by as a
/// delete, each the selected path taken literally (`deleted_state`). Like
/// `deleted_state`, it reads the selection and not the operation, so a
/// recursive host effect that deletes nothing, such as a `chmod -R`, yields
/// its paths too, and `repository_queries` asks the search below them.
/// Empty for a selection that is not recursive, not on this host, or that
/// no Git state judges.
pub(super) fn judged_deleted_paths(
    plan: &effinterp_proto::Plan,
    effect: &effinterp_proto::Effect,
) -> Vec<String> {
    deleted_state(plan, effect).map_or_else(Vec::new, |state| {
        state
            .pathspecs
            .iter()
            .map(|pathspec| deleted_path(pathspec).to_owned())
            .collect()
    })
}

/// Whether `effect` is the delete of a `git rm` without `--force`. Git
/// checks each file when it runs and removes only one that `HEAD` and the
/// index hold as it is, never an untracked or ignored one, so the delete
/// loses nothing whatever the repository holds and the call did before.
fn unforced_git_rm(effect: &effinterp_proto::Effect) -> bool {
    let flag = |name| effect.attributes.get(name) == Some(&effinterp_proto::AttrValue::Bool(true));
    effect.operation.as_str() == "filesystem.delete" && flag("tracked_only") && !flag("force")
}

/// The Git state a recursive delete on this host is judged by: what Git
/// finds of the deleted path taken literally, whether `HEAD` holds every
/// tracked file there as it is, and whether it holds an untracked or
/// ignored entry. A forced `git rm` deletes only tracked files, so it is
/// judged by the first alone; an unforced one needs no state
/// (`unforced_git_rm`), and one whose pathspecs Git reads as patterns or
/// with magic is judged by them, not by its paths (`git.worktree_discard`
/// of mode `rm`). A pattern is judged by the folder its literal start
/// names, which holds all it can select. Git refuses a path outside its
/// work tree or beyond a link, which leaves the delete unjudged. It reads
/// the effect's selection, not its operation: `discard_states` asks it only
/// for a `filesystem.delete`.
fn deleted_state<'a>(
    plan: &'a effinterp_proto::Plan,
    effect: &'a effinterp_proto::Effect,
) -> Option<DiscardState<'a>> {
    use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity, ResourcePattern};
    let flag = |name| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    let tracked_only = flag("tracked_only");
    if unforced_git_rm(effect)
        || tracked_only
            && plan.effects.iter().any(|other| {
                other.execution == effect.execution
                    && other.operation.as_str() == "git.worktree_discard"
                    && other.attributes.get("discard_mode") == Some(&AttrValue::String("rm".into()))
            })
    {
        return None;
    }
    if !effect.realm.is_host()
        || effect.attributes.get("recursive") != Some(&AttrValue::Bool(true))
            && !crate::observation_request::subtree_reached_whole(plan, effect)
    {
        return None;
    }
    // A Unix path, or a Windows one with its drive.
    let absolute = |path: &str| path.starts_with('/') || path.get(1..3) == Some(":\\");
    let directory = match plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)?
        .cwd
        .as_ref()?
    {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if absolute(path) => path.as_str(),
        _ => return None,
    };
    let path = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => path.clone(),
        ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob, .. },
        } => {
            let bound = nah_proto::action::pattern_bound(glob);
            bound[..bound.rfind(['/', '\\'])?].to_owned()
        }
        _ => return None,
    };
    let (path, platform) = match directory.starts_with('/') {
        _ if absolute(&path) && path.starts_with('/') => (path, nah_proto::ctx::Platform::Linux),
        _ if absolute(&path) => (path, nah_proto::ctx::Platform::Windows),
        true => (
            format!("{directory}/{path}"),
            nah_proto::ctx::Platform::Linux,
        ),
        false => (
            format!("{directory}\\{path}"),
            nah_proto::ctx::Platform::Windows,
        ),
    };
    let path = nah_proto::labels::lexical_path::lexically_normalized(&path, platform);
    // Git finds the repository from the folder that holds the path, which
    // the delete's working directory, such as a scheduled job's `/`, need
    // not lie in; the observation climbs from a folder that does not exist.
    let parent = match path.rfind(['/', '\\'])? {
        0 => "/".to_owned(),
        slash => path[..slash].to_owned(),
    };
    // Git matches pathspecs by case, while a case-insensitive filesystem
    // deletes `src` through `SRC` as well, so the path is matched both ways.
    Some(DiscardState {
        directory: parent.into(),
        pathspecs: vec![format!("{DELETED_PATH_MAGIC}{path}")],
        pathspec_options: Vec::new(),
        restores: Some(GitRestoreSource::Tree("HEAD".into())),
        untracked: (!tracked_only).then_some(GitCleanIgnored::Also),
    })
}

/// The pathspec a Git discard names as Git reads it, when the shell passes
/// it as one word: not a glob the shell expands.
fn discarded_pathspec(effect: &effinterp_proto::Effect) -> Option<String> {
    use effinterp_proto::{ResourceExpr, ResourceIdentity};
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                pathspec: Some(pathspec),
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    match pathspec.as_ref() {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

/// The pathspec mode options a Git effect states, such as
/// `--icase-pathspecs`; `None` when it states them unknown or malformed.
fn pathspec_options(effect: &effinterp_proto::Effect) -> Option<Vec<String>> {
    use effinterp_proto::AttrValue;
    if effect.attributes.get("pathspec_options_unknown") == Some(&AttrValue::Bool(true)) {
        return None;
    }
    match effect.attributes.get("pathspec_options") {
        None => Some(Vec::new()),
        Some(AttrValue::List(options)) => options
            .iter()
            .map(|option| match option {
                AttrValue::String(option) => Some(option.clone()),
                _ => None,
            })
            .collect(),
        Some(_) => None,
    }
}

/// Whether `boundary` is the one a git command whose pathspec Nah cannot
/// read as a plain path states beside `effect`, the discard of that
/// pathspec: its arguments are unrecognized, it concerns Git alone, the
/// effect's repository and the words it was found in. Git itself matches
/// such a pathspec when Nah observes or saves what it reaches, which
/// settles the boundary.
pub fn names_pathspec(
    boundary: &effinterp_proto::Boundary,
    effect: &effinterp_proto::Effect,
) -> bool {
    use effinterp_proto::{BoundaryReason, ResourceExpr, ResourceIdentity};
    let repository = |resource: &ResourceExpr| match resource {
        ResourceExpr::Concrete {
            identity:
                ResourceIdentity::GitRepository {
                    worktree, git_dir, ..
                },
        } => Some((worktree.clone(), git_dir.clone())),
        _ => None,
    };
    boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS
        && matches!(&boundary.domains[..], [domain] if domain.0 == "git")
        && !boundary.provenance.is_empty()
        && boundary
            .provenance
            .iter()
            .all(|node| effect.provenance.contains(node))
        && boundary.affected_resource.as_ref().and_then(repository) == repository(&effect.resource)
}

/// The Git state each discard and history rewrite of `plan` is judged by:
/// one query per distinct state, naming the refs the requests judged by it
/// delete and, for the whole tree a rewrite acts on, reading its history
/// and the revisions its resets move `HEAD` to.
pub(super) fn git_state_queries(
    plan: &effinterp_proto::Plan,
) -> Vec<nah_proto::observation::ObservationQuery> {
    #[derive(Default)]
    struct Read {
        deleted: BTreeSet<RefDeletion>,
        history: bool,
        head_targets: Vec<String>,
    }
    fn state_of<'s, 'a>(
        states: &'s mut Vec<(DiscardState<'a>, Read)>,
        state: DiscardState<'a>,
    ) -> &'s mut Read {
        let index = match states.iter().position(|(seen, _)| *seen == state) {
            Some(index) => index,
            None => {
                states.push((state, Read::default()));
                states.len() - 1
            }
        };
        &mut states[index].1
    }
    let mut states = Vec::new();
    for effect in &plan.effects {
        if let Some(found) = discard_states(plan, effect) {
            let deleted = ref_deletion(effect).filter(|deleted| !deletes_stash(deleted));
            for state in found {
                state_of(&mut states, state).deleted.extend(deleted.clone());
            }
        }
        if let Some(path) = rewrite_state_path(effect) {
            let read = state_of(&mut states, DiscardState::whole(path));
            read.history = true;
            if let Some(target) = reset_target(effect)
                && !read.head_targets.iter().any(|known| known == target)
            {
                read.head_targets.push(target.to_owned());
            }
        }
    }
    states
        .into_iter()
        .enumerate()
        .map(
            |(index, (state, read))| nah_proto::observation::ObservationQuery::GitState {
                key: format!("effinterp-git-state-{index:04}"),
                requested: state.directory.into_owned(),
                cwd_key: crate::observation_request::CWD_KEY.into(),
                pathspecs: state.pathspecs,
                pathspec_options: state.pathspec_options,
                restores: state.restores,
                untracked: state.untracked,
                inspect_history: read.history,
                head_targets: read.head_targets,
                deleted_refs: read.deleted.into_iter().collect(),
            },
        )
        .collect()
}

/// The refs a local `git.ref_delete_request` deletes, as its request names
/// them: a branch or tag in the namespace git finds it in, which git deletes
/// itself even when symbolic, a ref by its own name (`git update-ref -d`,
/// which follows a symbolic one unless `--no-deref`), or a remote's
/// remote-tracking refs. `None`
/// for any other effect, a stash drop, and a request whose name Nah cannot
/// read.
pub fn ref_deletion(effect: &effinterp_proto::Effect) -> Option<RefDeletion> {
    use effinterp_proto::AttrValue;
    let text = |name| match effect.attributes.get(name) {
        Some(AttrValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let flag = |name| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    if effect.operation.as_str() != "git.ref_delete_request" || flag("stash") || flag("prune") {
        return None;
    }
    match (text("ref"), text("remote")) {
        (Some(name), None) if !name.is_empty() => Some(match text("namespace") {
            Some(namespace) => RefDeletion::Itself(format!("{namespace}{name}")),
            None if flag("no_deref") => RefDeletion::Itself(name.to_owned()),
            None => RefDeletion::Ref(name.to_owned()),
        }),
        (None, Some(remote)) if !remote.is_empty() => Some(RefDeletion::Remote(remote.to_owned())),
        _ => None,
    }
}

/// Whether a `git filter-branch` request keeps its backups under
/// `refs/original/`, the namespace a forced run deletes first; `--original`
/// moves it.
pub fn filter_branch_backups_default(effect: &effinterp_proto::Effect) -> bool {
    use effinterp_proto::AttrValue;
    effect.attributes.get("backups_unknown") != Some(&AttrValue::Bool(true))
        && effect
            .attributes
            .get("backups")
            .is_none_or(|namespace| namespace == &AttrValue::String("refs/original/".into()))
}

/// Whether `deleted` is `refs/stash`, followed or not, which a stash drop
/// beside it states.
pub fn deletes_stash(deleted: &RefDeletion) -> bool {
    matches!(deleted, RefDeletion::Ref(name) | RefDeletion::Itself(name) if name == "refs/stash")
}

/// The work tree, named by a concrete host path, of the repository a Git
/// effect acts on, when Git finds that repository from it.
fn host_worktree(effect: &effinterp_proto::Effect) -> Option<&str> {
    use effinterp_proto::{ResourceExpr, ResourceIdentity};
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                git_dir: None,
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: worktree },
    } = worktree.as_ref()
    else {
        return None;
    };
    effect.realm.is_host().then_some(worktree.as_str())
}

/// The directory whose repository's history a request rewrites: a rebase,
/// an amend, `git filter-branch` or `git filter-repo`, or a reset that moves
/// its branch. `None` for any other effect, and for a request whose
/// repository is not the one Git finds from a named host directory.
fn rewrite_state_path(effect: &effinterp_proto::Effect) -> Option<&str> {
    match effect.operation.as_str() {
        "git.history_rewrite_request" => host_worktree(effect),
        "git.reset_request" if reset_moves_head(effect) => host_worktree(effect),
        _ => None,
    }
}

/// The effects of the Git commands that run the hook the plan's boundary
/// `index` stands for, in plan order; `None` for a boundary that is no
/// hook.
fn hook_runners(plan: &effinterp_proto::Plan, index: usize) -> Option<Vec<usize>> {
    let boundary = &plan.boundaries[index];
    if boundary.reason == effinterp_proto::BoundaryReason::UNMODELED_HOOKS {
        return Some(
            plan.effects
                .iter()
                .enumerate()
                .filter(|(_, effect)| {
                    !boundary.provenance.is_empty()
                        && boundary
                            .provenance
                            .iter()
                            .all(|node| effect.provenance.contains(node))
                })
                .map(|(effect_index, _)| effect_index)
                .collect(),
        );
    }
    let (node_index, _) =
        plan.execution_graph
            .nodes
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.boundary
                    .is_some_and(|boundary| boundary.0 as usize == index)
                    && node.input.as_ref().is_some_and(|input| {
                        input.phase == effinterp_proto::ExecutionPhase::VcsHook
                    })
            })?;
    Some(
        plan.effects
            .iter()
            .enumerate()
            .filter(|(_, effect)| {
                plan.execution_graph
                    .edges
                    .iter()
                    .any(|edge| edge.from == effect.execution && edge.to.0 as usize == node_index)
            })
            .map(|(effect_index, _)| effect_index)
            .collect(),
    )
}

/// Whether the plan's boundary `index` is a hook that the Git command
/// requesting `effect` runs: one Nah does not model, or a hook file whose
/// source it could not read. A hook another command in the call runs is
/// not.
pub fn git_hook_boundary(
    plan: &effinterp_proto::Plan,
    index: usize,
    effect: &effinterp_proto::Effect,
) -> bool {
    let boundary = &plan.boundaries[index];
    if boundary.reason == effinterp_proto::BoundaryReason::UNMODELED_HOOKS {
        return !boundary.provenance.is_empty()
            && boundary
                .provenance
                .iter()
                .all(|node| effect.provenance.contains(node));
    }
    plan.execution_graph
        .nodes
        .iter()
        .enumerate()
        .any(|(node_index, node)| {
            node.boundary
                .is_some_and(|boundary| boundary.0 as usize == index)
                && node
                    .input
                    .as_ref()
                    .is_some_and(|input| input.phase == effinterp_proto::ExecutionPhase::VcsHook)
                && plan
                    .execution_graph
                    .edges
                    .iter()
                    .any(|edge| edge.from == effect.execution && edge.to.0 as usize == node_index)
        })
}

/// Whether a `git reset` request moves `HEAD`, and the branch it is on, to
/// another commit: it names a revision other than `HEAD`, or one Nah cannot
/// read. A reset of paths moves nothing.
pub fn reset_moves_head(effect: &effinterp_proto::Effect) -> bool {
    use effinterp_proto::AttrValue;
    let attribute = |name| effect.attributes.get(name);
    effect.operation.as_str() == "git.reset_request"
        && attribute("scope") == Some(&AttrValue::String("targeted".into()))
        && (attribute("target_complete") != Some(&AttrValue::Bool(true))
            || match attribute("target") {
                None => false,
                Some(AttrValue::String(target)) => !matches!(target.as_str(), "HEAD" | "@"),
                Some(_) => true,
            })
}

/// The revision a `git reset` that moves `HEAD` names, as written.
fn reset_target(effect: &effinterp_proto::Effect) -> Option<&str> {
    use effinterp_proto::AttrValue;
    if !reset_moves_head(effect)
        || effect.attributes.get("target_complete") != Some(&AttrValue::Bool(true))
    {
        return None;
    }
    match effect.attributes.get("target") {
        Some(AttrValue::String(target)) => Some(target),
        _ => None,
    }
}

/// Whether the observation establishes that the Git history rewrite the
/// effect requests leaves every commit it replaces in reach: a rebase, an
/// amend and a reset where Git records the move in a reflog, a reset to a
/// revision that already reaches `HEAD`'s commit, and a
/// `git filter-branch` that writes its backup under `refs/original/` over
/// none; without `--force` it refuses to write over one, so it needs no
/// observation. `git filter-repo` expires the reflogs, removes the backups
/// and prunes, so it may always lose some.
///
/// The observation is of the repository's settings, which a `-c` option, a
/// `GIT_CONFIG*` variable or one that points Git at another repository
/// overrides where the command sets it, and of the state before the
/// invocation runs: nothing else in it may change the settings or remove
/// reflog entries, and no step Nah cannot follow may touch files, Git or
/// processes, but the rewrite's own filter code and the hooks Git runs. A
/// hook is followed only where it cannot undo what keeps the commits: a
/// filter-branch writes its own backup, and Git logs a rebase, an amend or
/// a reset whatever a hook does only where it creates the reflogs it
/// writes, a setting it read when it started.
pub(super) fn git_rewrite_loses_nothing(
    view: &crate::plan_view::PlanView<'_>,
    observation: &Observation,
    effect_index: usize,
) -> bool {
    use effinterp_proto::{AttrValue, ResourceExpr};
    use nah_proto::observation::ObservationQuery;
    let plan = view.plan();
    let effect = &plan.effects[effect_index];
    // An option the model does not know may change what the rewrite moves.
    // No option of a reset changes whether Git logs the move of `HEAD`, but
    // one may take the word read as its target, so a reset with one that
    // moves `HEAD` is kept only by a reflog; taking a word never makes one
    // that names no other revision move.
    let options_unknown = effect.attributes.get("options_unknown") == Some(&AttrValue::Bool(true));
    let reset = effect.operation.as_str() == "git.reset_request";
    if options_unknown && !reset {
        return false;
    }
    if reset && !reset_moves_head(effect) {
        return true;
    }
    let Some(path) = rewrite_state_path(effect) else {
        return false;
    };
    let history = || {
        observation
            .facts()
            .iter()
            .find_map(|fact| match (fact.query(), fact.value()) {
                (
                    ObservationQuery::GitState { requested, .. },
                    ObservationValue::GitState {
                        observed: Observed::Ok { value },
                    },
                ) if requested == path => value.history(),
                _ => None,
            })
    };
    let attribute = |name| effect.attributes.get(name);
    let logged = || history().is_some_and(|history| history.moves_logged);
    // A reset to a revision that reaches `HEAD`'s commit moves the branch
    // forward, where no earlier git step in the call may move either first.
    let forward = || {
        reset_target(effect).is_some_and(|target| {
            history().is_some_and(|history| {
                history
                    .targets_holding_head
                    .iter()
                    .any(|held| held == target)
            })
        }) && plan.effects.iter().all(|other| {
            other.execution == effect.execution
                || !other.operation.as_str().starts_with("git.")
                || other.operation.as_str() == "git.read"
        })
    };
    let kept = match effect.operation.as_str() {
        "git.history_rewrite_request" => match attribute("history_operation") {
            Some(AttrValue::String(operation)) => match operation.as_str() {
                "rebase" | "amend" => logged(),
                // The observation reads only `refs/original/`, so a forced
                // run over another backup namespace may always lose some.
                "filter-branch" => {
                    attribute("force") != Some(&AttrValue::Bool(true))
                        || filter_branch_backups_default(effect)
                            && history().is_some_and(|history| !history.backups)
                }
                _ => false,
            },
            _ => false,
        },
        _ => logged() || !options_unknown && forward(),
    };
    let follows_hooks = attribute("history_operation")
        == Some(&AttrValue::String("filter-branch".into()))
        || history().is_some_and(|history| history.creates_reflogs);
    let overridden = plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)
        .is_none_or(|node| {
            node.environment.iter().any(|(name, value)| {
                value.is_some()
                    && (name.starts_with("GIT_CONFIG")
                        || matches!(
                            name.as_str(),
                            "GIT_DIR" | "GIT_WORK_TREE" | "GIT_COMMON_DIR"
                        ))
            }) || node.argv.iter().any(|word| {
                matches!(word, ResourceExpr::Literal { value }
                        if value == "-c" || value.starts_with("--config-env"))
            })
        });
    let flag = |effect: &effinterp_proto::Effect, name| {
        effect.attributes.get(name) == Some(&AttrValue::Bool(true))
    };
    kept && !overridden
        && plan.boundaries.iter().enumerate().all(|(index, boundary)| {
            // A hook the rewrite's command or a later one runs acts after
            // Git read its settings; one an earlier command runs may
            // remove the reflogs first. A hook whose command Nah cannot
            // place counts as earlier.
            if let Some(runners) = hook_runners(plan, index) {
                let earlier = !git_hook_boundary(plan, index, effect)
                    && runners.first().is_none_or(|first| *first < effect_index);
                return follows_hooks && !earlier;
            }
            !boundary.provenance.is_empty()
                && boundary
                    .provenance
                    .iter()
                    .all(|node| effect.provenance.contains(node))
                || !boundary.domains.is_empty()
                    && !boundary
                        .domains
                        .iter()
                        .any(|domain| matches!(domain.0.as_str(), "filesystem" | "git" | "process"))
        })
        && plan
            .effects
            .iter()
            .all(|other| match other.operation.as_str() {
                "git.config_write" => false,
                // A stash entry's reflog holds no commit a rewrite replaces.
                "git.recovery_destroy" | "git.recovery_destroy_request" => {
                    flag(other, "stash") || !flag(other, "reflog") && !flag(other, "immediate")
                }
                _ => true,
            })
}

/// Whether the observation establishes that the Git discard the effect
/// requests, or a pathspec of one with no request states, has nothing to
/// lose: Git found that every tracked file it reaches already holds what it
/// would write, and that it reaches no untracked or ignored entry
/// (`discard_states`); a stash drop or ref delete, that another ref
/// reaches what it drops. Any doubt answers that it may lose, and the
/// discard is saved or blocked as any other. Every runtime and level reads
/// this one answer. An unforced `git rm` needs no observation: Git's own
/// check when it runs keeps it from losing anything (`unforced_git_rm`).
///
/// The observation is the state before the invocation runs, so it answers
/// only when nothing else the invocation does can put work where the discard
/// takes it: every other effect leaves the discarded repositories as they
/// were observed, and no boundary leaves filesystem or Git effects unknown
/// but the one naming a pathspec Git matched.
/// Order is not read, so a write after the discard refuses the answer too.
pub(super) fn git_discard_loses_nothing(
    view: &crate::plan_view::PlanView<'_>,
    observation: &Observation,
    effect_index: usize,
) -> bool {
    use effinterp_proto::AttrValue;
    use nah_proto::observation::ObservationQuery;
    let plan = view.plan();
    let effect = &plan.effects[effect_index];
    if unforced_git_rm(effect) {
        return true;
    }
    let Some(judged) = discard_states(plan, effect) else {
        return false;
    };
    let platform = view.authority().platform();
    let flag = |name| effect.attributes.get(name) == Some(&AttrValue::Bool(true));
    let keeps_by_refs = flag("stash") || effect.operation.as_str() == "git.ref_delete_request";
    let states = judged
        .iter()
        .map(|judged| {
            observation
                .facts()
                .iter()
                .find_map(|fact| match (fact.query(), fact.value()) {
                    (
                        ObservationQuery::GitState {
                            requested,
                            pathspecs,
                            pathspec_options,
                            restores,
                            untracked,
                            ..
                        },
                        ObservationValue::GitState {
                            observed: Observed::Ok { value },
                        },
                    ) if (
                        requested.as_str(),
                        pathspecs,
                        pathspec_options,
                        restores,
                        untracked,
                    ) == (
                        judged.directory.as_ref(),
                        &judged.pathspecs,
                        &judged.pathspec_options,
                        &judged.restores,
                        &judged.untracked,
                    ) =>
                    {
                        Some((judged, value))
                    }
                    _ => None,
                })
        })
        .collect::<Option<Vec<_>>>();
    let Some(states) = states else {
        return false;
    };
    // An unforced `git rm` adds no work for another discard to take either:
    // it removes only files `HEAD` holds as they are, from the tree and the
    // index, so its command is spared like a discard's own.
    let discards = plan
        .effects
        .iter()
        .filter(|other| discard_states(plan, other).is_some() || unforced_git_rm(other))
        .map(|other| other.execution)
        .collect::<BTreeSet<_>>();
    let unforced_rms = plan
        .effects
        .iter()
        .filter(|other| unforced_git_rm(other))
        .map(|other| other.execution)
        .collect::<BTreeSet<_>>();
    // A discard acts on the whole tree its repository's top level starts,
    // wherever inside it Git was pointed; a delete only on what it deletes.
    let top_levels = if effect.operation.as_str() == "filesystem.delete" {
        judged
            .iter()
            .flat_map(|judged| {
                judged
                    .pathspecs
                    .iter()
                    .map(|pathspec| deleted_path(pathspec))
            })
            .collect::<Vec<_>>()
    } else {
        states
            .iter()
            .map(|(_, state)| state.top_level().as_str())
            .collect::<Vec<_>>()
    };
    let nothing_observed = states.iter().all(|(judged, state)| {
        // `git update-ref -d refs/stash` drops every entry, as a stash
        // drop would.
        let stash_deleted = ref_deletion(effect).is_some_and(|deleted| deletes_stash(&deleted));
        match effect.operation.as_str() {
            "git.ref_delete_request" if !flag("stash") && !stash_deleted => {
                return ref_deletion(effect).is_some()
                    && state.deleted_refs_reached() == Some(true);
            }
            "git.recovery_destroy_request" | "git.ref_delete_request" => {
                return !state.stash_entries()
                    || state.stash_reached().is_some_and(|reached| {
                        match dropped_stash_entry(effect) {
                            // Git drops nothing past the last entry.
                            Some(entry) => reached.get(entry).is_none_or(|reached| *reached),
                            None => reached.iter().all(|reached| *reached),
                        }
                    });
            }
            // A recursive delete loses what `HEAD` does not hold as it is
            // and every untracked or ignored entry, unless it deletes only
            // folders tools rebuild, below which a finished search found no
            // repository. It also takes the repository itself where it
            // reaches the top level or the `.git` folder in it.
            // A forced `git rm` takes no untracked entry, nor the repository.
            "filesystem.delete" if flag("tracked_only") => {
                return state.restores_nothing() == Some(true);
            }
            "filesystem.delete" => {
                let top_level = state.top_level().as_str();
                let git_dir = join_lexical_path(top_level, ".git", platform);
                let deleted = judged
                    .pathspecs
                    .iter()
                    .map(|pathspec| deleted_path(pathspec));
                let rebuilt_only = deleted.clone().all(|deleted| {
                    nah_proto::labels::snapshot_skipped_directory(deleted)
                        && observed_nested_repository(observation, deleted)
                            == Some(NestedRepositoryObservation::Absent)
                });
                return deleted.clone().all(|deleted| {
                    !lexically_contains(deleted, top_level, platform)
                        && !lexically_contains(&git_dir, deleted, platform)
                }) && state.restores_nothing() == Some(true)
                    && (rebuilt_only || state.untracked() == Some(false));
            }
            _ => {}
        }
        // A forced removal deletes the whole worktree. The state answers for
        // it only when the named path is that worktree's top level, not a
        // directory inside another tree.
        let names_top_level = effect.attributes.get("discard_mode")
            != Some(&AttrValue::String("worktree_remove".into()))
            || nah_proto::labels::lexical_path::same_path(
                judged.directory.as_ref(),
                state.top_level().as_str(),
                platform,
            )
            || view
                .observed_path(judged.directory.as_ref())
                .and_then(|observed| observed.realpath())
                .is_some_and(|real| real.as_str() == state.top_level().as_str());
        names_top_level
            && (judged.restores.is_none() || state.restores_nothing() == Some(true))
            && (judged.untracked.is_none() || state.untracked() == Some(false))
    });
    // A delete's own process may move or write work into what it deletes
    // before it deletes, so only what runs from the delete on is spared,
    // with an unforced `git rm` anywhere in the call; a discard's own
    // command states more than its request (the files a restore rewrites),
    // none of which adds work.
    // What lands in a folder tools rebuild is as expendable as what it
    // holds, and the snapshot never copies one either, so a delete of only
    // such folders needs no more. `git rm` also drops the deleted files'
    // index entries, which Git finds no tracked change in, so HEAD holds
    // them.
    let rebuilt_only = effect.operation.as_str() == "filesystem.delete"
        && judged.iter().all(|judged| {
            judged
                .pathspecs
                .iter()
                .all(|path| nah_proto::labels::snapshot_skipped_directory(deleted_path(path)))
        });
    nothing_observed
        && if rebuilt_only {
            true
        } else if keeps_by_refs {
            // Another stash drop adds a loss: each drop moves the entries
            // after it up, so the observed entry it names is not the one it
            // drops. What keeps a stash entry or a deleted ref's commits is
            // another ref, which any step that is not a read may move or
            // delete.
            rest_adds_nothing(
                view,
                &|_, other| other.execution == effect.execution,
                None,
                &top_levels,
            ) && plan
                .effects
                .iter()
                .filter(|other| other.execution != effect.execution)
                .all(reads_only)
        } else if effect.operation.as_str() == "filesystem.delete" {
            rest_adds_nothing(
                view,
                &|index, other| {
                    index >= effect_index
                        || other.execution == effect.execution
                            && other.operation.as_str() == "git.index_write"
                        || unforced_rms.contains(&other.execution)
                },
                Some(effect_index),
                &top_levels,
            )
        } else {
            rest_adds_nothing(
                view,
                &|_, other| discards.contains(&other.execution),
                None,
                &top_levels,
            )
        }
}

/// Whether nothing the invocation does besides the effects it `spared` (by
/// index) can put work where a discard takes it, in the trees that start at
/// `top_levels` (for a delete, the paths it deletes): no boundary leaves
/// filesystem, Git or process effects unknown but one naming a pathspec Git
/// matched or, for the delete at index `after`, one of a program that runs
/// after it (`runs_after`), and every other effect leaves those trees as
/// they were observed.
pub(super) fn rest_adds_nothing(
    view: &crate::plan_view::PlanView<'_>,
    spared: &dyn Fn(usize, &effinterp_proto::Effect) -> bool,
    after: Option<usize>,
    top_levels: &[&str],
) -> bool {
    let plan = view.plan();
    plan.boundaries.iter().all(|boundary| {
        !boundary
            .domains
            .iter()
            .any(|domain| matches!(domain.0.as_str(), "filesystem" | "git" | "process"))
            || after.is_some_and(|delete| runs_after(plan, boundary, delete))
            || plan
                .effects
                .iter()
                .enumerate()
                .any(|(index, other)| spared(index, other) && names_pathspec(boundary, other))
    }) && plan
        .effects
        .iter()
        .enumerate()
        .filter(|(index, other)| !spared(*index, other))
        .all(|(_, other)| leaves_repositories_unchanged(view, other, top_levels))
}

/// Whether `boundary` is one of a program that starts only after the
/// command of the effect at index `delete` has finished, such as the hooks
/// of the `git commit` in `rm -rf docs && git commit`: what it does cannot
/// put work where the delete has already taken it. The boundary is tied to
/// the effects whose provenance holds all of its own. Each of them, and the
/// delete, must be of a separate command the request's own shell script
/// launches, and each must run only on the success of a `&&` list whose
/// left side holds the delete's command. The plan marks neither a loop
/// that repeats without a test (`while true`) nor a background job, which
/// would let the hook run before a later pass of the delete or beside it,
/// so a script that may hold either is never read by order
/// (`script_runs_in_order`).
fn runs_after(
    plan: &effinterp_proto::Plan,
    boundary: &effinterp_proto::Boundary,
    delete: usize,
) -> bool {
    use effinterp_proto::{Condition, ConditionKind, ExecutionEdgeKind};
    let graph = &plan.execution_graph;
    let launched_by_script = |execution: effinterp_proto::ExecutionNodeRef| {
        graph.edges.iter().any(|edge| {
            edge.from == graph.entry
                && edge.to == execution
                && edge.kind == ExecutionEdgeKind::Launch
                && !edge.cycle
        })
    };
    let effinterp_proto::Subject::Shell { source, .. } = &plan.subject else {
        return false;
    };
    let deleted = &plan.effects[delete];
    let Some(span) = graph
        .nodes
        .get(deleted.execution.0 as usize)
        .and_then(|node| node.source_span)
    else {
        return false;
    };
    // A condition holds only after the delete's command when one of the
    // atoms it requires is the success of a list around that command.
    fn after(condition: &Condition, span: effinterp_proto::ByteSpan) -> bool {
        match condition {
            Condition::Atom { atom } => {
                atom.origin.kind == ConditionKind::ShortCircuit
                    && atom.polarity == Some(true)
                    && atom.origin.call_instance.is_none()
                    && atom.origin.span.start <= span.start
                    && span.end <= atom.origin.span.end
            }
            Condition::All { conditions } => conditions.iter().any(|each| after(each, span)),
            Condition::Any { .. } | Condition::Widened => false,
        }
    }
    let tied = plan
        .effects
        .iter()
        .enumerate()
        .filter(|(_, effect)| {
            boundary
                .provenance
                .iter()
                .all(|node| effect.provenance.contains(node))
        })
        .collect::<Vec<_>>();
    !boundary.provenance.is_empty()
        && !tied.is_empty()
        && launched_by_script(deleted.execution)
        && script_runs_in_order(source)
        && tied.iter().all(|(index, effect)| {
            *index > delete
                && effect.execution != deleted.execution
                && launched_by_script(effect.execution)
                && effect
                    .condition
                    .as_ref()
                    .is_some_and(|condition| after(condition, span))
        })
}

/// Whether the effect `later` starts only after the command of `earlier`
/// has finished, so nothing it does changes what `earlier` found. Both are
/// of separate commands the request's own shell script launches, and
/// `later`'s command is spelled after `earlier`'s in a script that runs its
/// commands one at a time in the order it spells them: one with none of the
/// constructs `script_runs_in_order` rejects, no pipeline, whose commands
/// run side by side, and no function or sourced script, whose commands run
/// where they are called rather than where they are spelled.
pub(super) fn runs_after_command(
    plan: &effinterp_proto::Plan,
    earlier: &effinterp_proto::Effect,
    later: &effinterp_proto::Effect,
) -> bool {
    use effinterp_proto::ExecutionEdgeKind;
    let graph = &plan.execution_graph;
    let effinterp_proto::Subject::Shell { source, .. } = &plan.subject else {
        return false;
    };
    let launched = |execution: effinterp_proto::ExecutionNodeRef| {
        graph.edges.iter().any(|edge| {
            edge.from == graph.entry
                && edge.to == execution
                && edge.kind == ExecutionEdgeKind::Launch
                && !edge.cycle
        })
    };
    let span = |execution: effinterp_proto::ExecutionNodeRef| {
        graph
            .nodes
            .get(execution.0 as usize)
            .and_then(|node| node.source_span)
    };
    let bytes = source.as_bytes();
    let pipe = bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'|'
            && bytes.get(index + 1) != Some(&b'|')
            && (index == 0 || bytes[index - 1] != b'|')
    });
    let (Some(first), Some(second)) = (span(earlier.execution), span(later.execution)) else {
        return false;
    };
    earlier.execution != later.execution
        && launched(earlier.execution)
        && launched(later.execution)
        && script_runs_in_order(source)
        && !pipe
        && !runs_elsewhere(source)
        && first.end <= second.start
}

/// Whether the shell script `source` may define a function or source a
/// script, whose commands run where they are called rather than where they
/// are spelled. `function` counts wherever it is spelled; `source` and `.`
/// where they may start a command, the first word after an operator or a
/// reserved word, so `tar -czf out.tgz .` sources nothing.
fn runs_elsewhere(source: &str) -> bool {
    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let mut words = source
        .split(|character: char| character.is_whitespace() || "<>`'\"$".contains(character))
        .flat_map(|word| {
            word.split_inclusive(|character: char| ";&|(){}".contains(character))
                .flat_map(|part| {
                    let (word, operator) = part.split_at(
                        part.len()
                            - part.ends_with(|character: char| ";&|(){}".contains(character))
                                as usize,
                    );
                    [word, operator]
                })
        })
        .filter(|word| !word.is_empty());
    let mut command_position = true;
    compact.contains("()")
        || words.any(|word| {
            let starts = command_position && matches!(word, "source" | ".");
            command_position = word.len() == 1 && ";&|(){}".contains(word)
                || matches!(
                    word,
                    "then"
                        | "else"
                        | "elif"
                        | "do"
                        | "if"
                        | "while"
                        | "until"
                        | "!"
                        | "time"
                        | "command"
                        | "builtin"
                );
            starts || word == "function"
        })
}

/// Whether the effect `earlier` has finished before the effect `later`
/// starts, as the innermost shell script that spells both orders them
/// (`common_shell`): the request's own, or one a command it launches runs,
/// such as a script file or `bash -c` text. In that script the command
/// that makes `earlier` ends before the one that makes `later` begins, no
/// pipe between them runs the two side by side, and neither it nor any
/// script that runs it holds the constructs `script_runs_in_order` rejects
/// or any `runs_elsewhere` reads. A command the script launches is placed
/// by its own span, and anything it runs in turn by that span too, unless
/// that is itself a shell script spelling both; an effect of the script
/// itself, such as a redirection's write, is placed by the source spans of
/// its provenance.
pub(super) fn spelled_in_order(
    plan: &effinterp_proto::Plan,
    earlier: &effinterp_proto::Effect,
    later: &effinterp_proto::Effect,
) -> bool {
    let Some(shell) = common_shell(plan, earlier, later) else {
        return false;
    };
    let (Some(source), Some(first), Some(second)) = (
        shell_source(plan, shell),
        script_span(plan, earlier, shell),
        script_span(plan, later, shell),
    ) else {
        return false;
    };
    let between = source
        .as_bytes()
        .get(first.1 as usize..second.0 as usize)
        .unwrap_or_default();
    let pipe = between.iter().enumerate().any(|(index, byte)| {
        *byte == b'|'
            && between.get(index + 1) != Some(&b'|')
            && (index == 0 || between[index - 1] != b'|')
    });
    // A script that runs again, or whose commands run elsewhere, can run
    // `later` before a second `earlier`. One that runs `shell` beside other
    // commands still runs its steps in their order.
    let runs_once = std::iter::successors(Some(shell), |node| {
        plan.execution_graph
            .edges
            .iter()
            .find(|edge| edge.to == *node && !edge.cycle)
            .map(|edge| edge.from)
    })
    .skip(1)
    .filter_map(|node| shell_source(plan, node))
    .all(|source| runs_each_command_once(source) && !runs_elsewhere(source));
    first.1 <= second.0
        && !pipe
        && script_runs_in_order(source)
        && !runs_elsewhere(source)
        && runs_once
}

/// The innermost execution that runs a shell script (`shell_source`) and
/// is, or runs, both the calls that make `first` and `second`.
pub(super) fn common_shell(
    plan: &effinterp_proto::Plan,
    first: &effinterp_proto::Effect,
    second: &effinterp_proto::Effect,
) -> Option<effinterp_proto::ExecutionNodeRef> {
    let lineage = |node| {
        std::iter::successors(Some(node), |node| {
            plan.execution_graph
                .edges
                .iter()
                .find(|edge| edge.to == *node && !edge.cycle)
                .map(|edge| edge.from)
        })
        .collect::<Vec<_>>()
    };
    let first = lineage(first.execution);
    lineage(second.execution)
        .into_iter()
        .find(|node| first.contains(node) && shell_source(plan, *node).is_some())
}

/// The text of the shell script the execution `node` runs: the request's
/// own for the entry, or the script file or `-c` text a launched shell
/// runs.
pub(super) fn shell_source(
    plan: &effinterp_proto::Plan,
    node: effinterp_proto::ExecutionNodeRef,
) -> Option<&str> {
    let subject = if node == plan.execution_graph.entry {
        &plan.subject
    } else {
        &plan.execution_graph.nodes.get(node.0 as usize)?.subject
    };
    match subject {
        effinterp_proto::Subject::Shell { source, .. } => Some(source.as_str()),
        _ => None,
    }
}

/// Where in the script the execution `shell` runs the command that makes
/// `effect` is spelled, as `spelled_in_order` places it.
pub(super) fn script_span(
    plan: &effinterp_proto::Plan,
    effect: &effinterp_proto::Effect,
    shell: effinterp_proto::ExecutionNodeRef,
) -> Option<(u32, u32)> {
    use effinterp_proto::{ExecutionEdgeKind, ProvenanceKind};
    let graph = &plan.execution_graph;
    if effect.execution == shell {
        // A launched script's own spans are those its execution anchors;
        // others its provenance reaches lie in the scripts around it.
        let anchored = |antecedents: &[effinterp_proto::ProvenanceRef]| {
            shell == graph.entry
                || antecedents.iter().any(|antecedent| {
                    plan.provenance
                        .get(antecedent.0 as usize)
                        .is_some_and(|node| {
                            node.kind == ProvenanceKind::Execution { node: shell.0 }
                        })
                })
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut queue = effect.provenance.clone();
        let mut span: Option<(u32, u32)> = None;
        while let Some(reference) = queue.pop() {
            if !seen.insert(reference.0) {
                continue;
            }
            let node = plan.provenance.get(reference.0 as usize)?;
            if let ProvenanceKind::SourceSpan { start, end } = node.kind
                && anchored(&node.antecedents)
            {
                span = Some(span.map_or((start, end), |(first, last)| {
                    (first.min(start), last.max(end))
                }));
            }
            queue.extend(node.antecedents.iter().copied());
        }
        return span;
    }
    let mut node = effect.execution;
    loop {
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.to == node && !edge.cycle)?;
        if edge.from == shell {
            if edge.kind != ExecutionEdgeKind::Launch {
                return None;
            }
            let span = graph.nodes.get(node.0 as usize)?.source_span?;
            return Some((span.start, span.end));
        }
        node = edge.from;
    }
}

/// Whether the shell script `source` holds none of the constructs that run
/// a command again or beside the next one: a loop (`while`, `until`, `for`,
/// `select`), a background job or coprocess (`&`, `coproc`), a trap, or
/// code it builds and runs (`eval`). Any word or character that may spell
/// one counts, quoted or not, so a quoted `&` in a commit message counts
/// too.
fn script_runs_in_order(source: &str) -> bool {
    let bytes = source.as_bytes();
    let lone_ampersand = bytes.iter().enumerate().any(|(index, byte)| {
        let at = |offset: isize| {
            index
                .checked_add_signed(offset)
                .and_then(|position| bytes.get(position))
        };
        *byte == b'&'
            && at(-1) != Some(&b'&')
            && at(1) != Some(&b'&')
            && at(-1) != Some(&b'>')
            && at(-1) != Some(&b'<')
            && at(1) != Some(&b'>')
    });
    !lone_ampersand && runs_each_command_once(source)
}

/// Whether the shell script `source` holds no construct that runs one of
/// its commands again or later than it is spelled: a loop (`while`,
/// `until`, `for`, `select`), a coprocess, a trap, or code it builds and
/// runs (`eval`). Any word that may spell one counts, quoted or not.
fn runs_each_command_once(source: &str) -> bool {
    !source
        .split(|character: char| character.is_whitespace() || ";&|()<>`'\"{}$".contains(character))
        .any(|word| {
            matches!(
                word,
                "while" | "until" | "for" | "select" | "coproc" | "trap" | "eval"
            )
        })
}

/// The stash entry, `n` of `stash@{n}`, a `git stash drop` request drops;
/// `None` for one that drops every entry (`git stash clear`), and for one
/// whose entry Nah cannot tell, which may be any.
pub fn dropped_stash_entry(effect: &effinterp_proto::Effect) -> Option<usize> {
    use effinterp_proto::AttrValue;
    let attribute = |name| effect.attributes.get(name);
    if attribute("scope") != Some(&AttrValue::String("selected".into()))
        || attribute("target_complete") != Some(&AttrValue::Bool(true))
    {
        return None;
    }
    let target = match attribute("target") {
        None => return Some(0),
        Some(AttrValue::String(target)) => target.as_str(),
        Some(_) => return None,
    };
    // Git reads a number as an entry of `refs/stash`; a date, or any other
    // revision, may name another entry or none.
    let entry = ["refs/stash@{", "stash@{"]
        .iter()
        .find_map(|prefix| target.strip_prefix(prefix)?.strip_suffix('}'))
        .unwrap_or(target);
    (!entry.is_empty() && entry.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| entry.parse().ok())
        .flatten()
}

/// Whether `effect` only reads, runs a program whose own effects are stated
/// beside it, or reaches the network.
fn reads_only(effect: &effinterp_proto::Effect) -> bool {
    matches!(
        effect.operation.as_str(),
        "process.exec"
            | "process.code_execution"
            | "environment.read"
            | "filesystem.read"
            | "git.read"
    ) || effect.operation.as_str().starts_with("network.")
}

/// Whether `effect` cannot add uncommitted work or a stash entry to the
/// working trees that start at `top_levels`: it reads, runs a program (whose
/// own effects are stated beside it or left behind a boundary), fetches,
/// removes, or changes a path the host observed to lie outside every one of
/// them. A path's spelling does not say where it lies (a link, a `..`), and
/// one that does not exist yet has no observed place, so only an existing
/// path's real location counts as outside.
fn leaves_repositories_unchanged(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
    top_levels: &[&str],
) -> bool {
    let platform = view.authority().platform();
    use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};
    match effect.operation.as_str() {
        // A removal adds nothing a discard could take: a tracked file it
        // deletes is one the discard puts back.
        "process.exec"
        | "process.code_execution"
        | "environment.read"
        | "filesystem.read"
        | "filesystem.delete"
        | "git.read" => true,
        "git.remote_sync" => effect.attributes.get("fetch") == Some(&AttrValue::Bool(true)),
        // A shell variable changes no file, unless it is one Git reads to
        // choose the repository, index or work tree.
        "environment.write" => matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } if !name.starts_with("GIT_")
        ),
        // Moving or deleting a ref touches no working tree; the stash ref is
        // the one that holds work.
        "git.ref_update" | "git.ref_delete_request" => {
            effect.attributes.get("stash") != Some(&AttrValue::Bool(true))
                && effect.attributes.get("ref") != Some(&AttrValue::String("refs/stash".into()))
        }
        operation if operation.starts_with("network.") => true,
        operation if operation.starts_with("filesystem.") => match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => view
                .observed_path(path)
                .and_then(|observed| observed.realpath())
                .is_some_and(|real| {
                    // A macOS volume ignores case by default, so `.ENV`
                    // there is `.env`; folding only adds overlaps.
                    let key = |path: &str| match platform {
                        nah_proto::ctx::Platform::Macos => path.to_lowercase(),
                        _ => path.to_owned(),
                    };
                    let real = key(real.as_str());
                    top_levels.iter().all(|top_level| {
                        let top_level = key(top_level);
                        !nah_proto::labels::lexically_contains(&top_level, &real, platform)
                            && !nah_proto::labels::lexically_contains(&real, &top_level, platform)
                    })
                }),
            _ => false,
        },
        _ => false,
    }
}

/// What the observation found below the directory `target`, under any key
/// and whichever spelling the search was asked by: `target` itself, or a
/// path the observation resolved to it, since the guard reads a target by
/// its canonical path and the search was asked by the plan's. None where no
/// search was asked or it could not finish.
pub(super) fn observed_nested_repository(
    observation: &Observation,
    target: &str,
) -> Option<NestedRepositoryObservation> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::NestedRepository { requested, .. },
                ObservationValue::NestedRepository {
                    observed: Observed::Ok { value },
                },
            ) if requested == target
                || resolved_directory(observation, requested) == Some(target) =>
            {
                Some(*value)
            }
            _ => None,
        })
}

/// The canonical path of the directory the observation names `requested`,
/// under any key: None for a link, which a delete takes as the link and
/// whose target it names no folder by, and for a path the host did not
/// resolve to a directory.
fn resolved_directory<'o>(observation: &'o Observation, requested: &str) -> Option<&'o str> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::Path {
                    requested: asked, ..
                },
                ObservationValue::Path {
                    observed: Observed::Ok { value },
                },
            ) if asked == requested && value.kind() == PathKind::Directory => {
                value.realpath().map(|path| path.as_str())
            }
            _ => None,
        })
}
