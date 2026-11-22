//! Bind the Git model's content selections to filename-only host evidence,
//! and decide when an earlier change in the call leaves a `git add` selection
//! as observed (`change_leaves_add_candidates`). A staging selection is asked
//! of the observer with the writes and deletes earlier calls make first
//! (`staging_changes`), so it names what Git takes from the disk they leave.

use effinterp_proto::{AttrValue, Condition, ConditionAtom, Effect, Plan, ResourceExpr};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{
    GitReadKind, GitReadSelection, Observation, ObservationQuery, ObservationValue, Observed,
    StagingChange, StagingOperation,
};

fn selection(effect: &Effect) -> Option<(String, GitReadSelection)> {
    if !effect.realm.is_host() {
        return None;
    }
    let text = |key| match effect.attributes.get(key) {
        Some(AttrValue::String(text)) => Some(text.clone()),
        _ => None,
    };
    let strings = |key| match effect.attributes.get(key) {
        Some(AttrValue::List(values)) => values
            .iter()
            .map(|value| match value {
                AttrValue::String(text) => Some(text.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    };
    let kind = match text("content_selection")?.as_str() {
        "tracked" => GitReadKind::Tracked,
        "cached" => GitReadKind::Cached,
        "untracked" => GitReadKind::Untracked,
        "untracked-all" => GitReadKind::UntrackedAll,
        "directory" => GitReadKind::Directory,
        "directory-excluded" => GitReadKind::DirectoryExcluded,
        "diff" => GitReadKind::Diff,
        "staged-diff" => GitReadKind::StagedDiff,
        "head-diff" => GitReadKind::HeadDiff,
        "commit" => GitReadKind::Commit,
        "history" => GitReadKind::History,
        "revision-grep" => GitReadKind::RevisionGrep,
        "stash" => GitReadKind::Stash,
        "stash-untracked" => GitReadKind::StashUntracked,
        "stash-only-untracked" => GitReadKind::StashOnlyUntracked,
        "addable" => GitReadKind::Addable,
        "addable-all" => GitReadKind::AddableAll,
        "addable-tracked" => GitReadKind::AddableTracked,
        "addable-head" => GitReadKind::AddableHead,
        "renormalized" => GitReadKind::Renormalized,
        _ => return None,
    };
    Some((
        text("content_directory")?,
        GitReadSelection {
            kind,
            revisions: strings("content_revisions")?,
            revision_options: strings("content_revision_options")?,
            pathspecs: strings("content_pathspecs")?,
            pathspec_options: strings("content_pathspec_options")?,
            changes: Vec::new(),
            user_configuration_changed: effect.attributes.get("content_user_configuration_changed")
                == Some(&AttrValue::Bool(true)),
        },
    ))
}

/// The selection `effect` makes, as the observer is asked for it: with the
/// changes earlier calls make first, for a staging selection.
fn selection_in(plan: &Plan, effect: &Effect) -> Option<(String, GitReadSelection)> {
    let (directory, mut selection) = selection(effect)?;
    if stages_git_add_selection(effect) {
        selection.changes = staging_changes(plan, effect)
            .0
            .into_iter()
            .map(|(_, change)| change)
            .collect();
    }
    Some((directory, selection))
}

pub(super) fn queries(plan: &Plan) -> Vec<ObservationQuery> {
    plan.effects
        .iter()
        .filter_map(|effect| selection_in(plan, effect))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(
            |(index, (requested, selection))| ObservationQuery::GitRead {
                key: format!("effinterp-git-read-{index:04}"),
                requested,
                selection,
                cwd_key: crate::observation_request::CWD_KEY.into(),
            },
        )
        .collect()
}

pub(super) fn observed_paths<'a>(
    plan: &Plan,
    observation: &'a Observation,
    effect: &Effect,
) -> Option<&'a [AbsolutePath]> {
    let (directory, selection) = selection_in(plan, effect)?;
    observation
        .facts()
        .iter()
        .find_map(|fact| match (fact.query(), fact.value()) {
            (
                ObservationQuery::GitRead {
                    requested,
                    selection: observed_selection,
                    ..
                },
                ObservationValue::GitRead {
                    observed: Observed::Ok { value },
                },
            ) if *requested == directory && *observed_selection == selection => {
                Some(value.as_slice())
            }
            _ => None,
        })
}

/// Whether `read` is a `git add` or commit selection: a content selection
/// whose bytes the call stages into the index.
pub(super) fn stages_git_add_selection(read: &Effect) -> bool {
    let (key, purpose) = nah_proto::observation::GIT_STAGING_PURPOSE;
    read.operation.as_str() == "git.read"
        && read.attributes.contains_key("content_selection")
        && read.attributes.get(key) == Some(&AttrValue::String(purpose.into()))
}

/// Whether a change at `path` may alter what an add stages from its observed
/// `candidates`: a change at a candidate, at a directory above one, or at a
/// source of ignore rules or configuration. Paths are compared by component
/// name, so a candidate under a differently spelled root still counts.
/// Unobserved candidates may be reached by any path.
fn change_may_reach_add_candidates(path: &str, candidates: Option<&[AbsolutePath]>) -> bool {
    let name = path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("");
    matches!(name, "" | "." | "..")
        || name.contains("ignore")
        || name.contains("exclude")
        || name.ends_with("config")
        || path.split(['/', '\\']).any(|part| part == ".git")
        || candidates.is_none_or(|candidates| {
            candidates.iter().any(|candidate| {
                candidate
                    .as_str()
                    .split(['/', '\\'])
                    .any(|part| part == name)
            })
        })
}

/// An index write limited to paths that reach none of an add's `candidates`.
fn index_write_limited_away(write: &Effect, candidates: Option<&[AbsolutePath]>) -> bool {
    write.operation.as_str() == "git.index_write"
        && matches!(
            write.attributes.get("index_paths"),
            Some(AttrValue::List(paths)) if paths.iter().all(|path| {
                matches!(
                    path,
                    AttrValue::String(path) if !change_may_reach_add_candidates(path, candidates)
                )
            })
        )
}

/// Whether an earlier `change` in `plan` leaves an add's observed
/// `candidates` as observed: an index write limited away from them, the
/// reset request beside one, or a file written or deleted at a path that
/// reaches none.
pub(super) fn change_leaves_add_candidates(
    plan: &Plan,
    change: &Effect,
    candidates: Option<&[AbsolutePath]>,
) -> bool {
    candidates.is_some()
        && match change.operation.as_str() {
            "git.index_write" => index_write_limited_away(change, candidates),
            "git.reset_request" => plan.effects.iter().any(|write| {
                write.execution == change.execution && index_write_limited_away(write, candidates)
            }),
            "filesystem.write" | "filesystem.delete" => matches!(
                &change.resource,
                effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } if !change_may_reach_add_candidates(path, candidates)
            ),
            _ => false,
        }
}

pub(super) fn add_unavailable_gaps(
    plan: &Plan,
    observation: &Observation,
    graph: &mut nah_proto::effects::EffectGraph,
) {
    use nah_proto::effects::{CallId, Domain, GapPhase};
    let calls = plan
        .effects
        .iter()
        .filter(|effect| {
            selection(effect).is_some() && observed_paths(plan, observation, effect).is_none()
        })
        .map(|effect| effect.execution.0)
        .collect::<std::collections::BTreeSet<_>>();
    for call in calls {
        super::add_gap(
            graph,
            CallId(call),
            Some(Domain::Git),
            GapPhase::Observation,
            "git-content-selection-unavailable",
        );
    }
}

/// Whether the call `execution` may change the disk before the read `read`
/// makes its selection: the engine numbers calls in the order it reaches
/// them, and a call `read`'s own call launches runs while it does. A call
/// that stages its selection does so before anything else it does: a commit
/// takes its work tree files before it runs its hooks and records the
/// commit (builtin/commit.c `prepare_index` before `prepare_to_commit`), so
/// neither its own steps nor what its hooks do can change what it staged.
pub(super) fn may_precede(plan: &Plan, read: &Effect, execution: Option<u32>) -> bool {
    let parent = |node: u32| {
        plan.execution_graph
            .edges
            .iter()
            .find(|edge| edge.to.0 == node && !edge.cycle)
    };
    // Whether `execution` runs in a hook of the call `command`.
    let in_hook = |execution: u32, command: u32| {
        let mut node = execution;
        while let Some(edge) = parent(node) {
            if edge.from.0 == command {
                return plan.execution_graph.nodes[node as usize]
                    .input
                    .as_ref()
                    .is_some_and(|input| input.phase == effinterp_proto::ExecutionPhase::VcsHook);
            }
            node = edge.from.0;
        }
        false
    };
    let starts_after = |later: u32, earlier: u32| {
        if later <= earlier {
            return false;
        }
        let mut node = later;
        while let Some(edge) = parent(node) {
            if edge.from.0 == earlier {
                return false;
            }
            node = edge.from.0;
        }
        true
    };
    let staging = stages_git_add_selection(read);
    execution.is_none_or(|execution| {
        !(staging && (execution == read.execution.0 || in_hook(execution, read.execution.0))
            || starts_after(execution, read.execution.0)
                && !runs_beside(plan, read.execution.0, execution))
    })
}

/// Whether the call `later` may run while the call `earlier` still runs,
/// though the engine numbers it after: a peer of a pipeline `earlier` is
/// in, with either call inside a command its pipeline stage launches, or any
/// call after a job the script sends to the background with `&`. Two calls
/// inside one launched command are ordered by that command, not here.
fn runs_beside(plan: &Plan, earlier: u32, later: u32) -> bool {
    use effinterp_proto::{ExecutionEdgeKind, ExecutionStream};
    let graph = &plan.execution_graph;
    let effinterp_proto::Subject::Shell { source, .. } = &plan.subject else {
        return false;
    };
    let parent = |node: u32| {
        graph
            .edges
            .iter()
            .find(|edge| edge.to.0 == node && !edge.cycle)
    };
    // The call and the commands that launch it, up to the script's own.
    let lineage = |node: u32| {
        let mut nodes = vec![node];
        let mut current = node;
        while let Some(edge) = parent(current)
            && edge.from != graph.entry
        {
            current = edge.from.0;
            nodes.push(current);
        }
        nodes
    };
    let (first, second) = (lineage(earlier), lineage(later));
    let own = |nodes: &[u32], other: &[u32]| {
        nodes
            .iter()
            .copied()
            .filter(|node| !other.contains(node))
            .collect::<Vec<_>>()
    };
    let (first, second) = (own(&first, &second), own(&second, &first));
    // One call's output is the other's input: they are stages of a pipe.
    // A stream a launched command inherits names its launcher's same stream.
    let piped = |from: u32, to: u32| {
        graph.nodes.get(from as usize).is_some_and(|node| {
            [
                (&node.streams.stdout, ExecutionStream::Stdin),
                (&node.streams.stderr, ExecutionStream::Stdin),
                (&node.streams.stdin, ExecutionStream::Stdout),
            ]
            .into_iter()
            .any(|(stream, other)| {
                stream
                    .as_ref()
                    .is_some_and(|stream| stream.node.0 == to && stream.stream == other)
            })
        })
    };
    let mut pipeline = first.clone();
    let mut index = 0;
    while let Some(&node) = pipeline.get(index) {
        index += 1;
        for peer in 0..graph.nodes.len() as u32 {
            if !pipeline.contains(&peer) && (piped(node, peer) || piped(peer, node)) {
                pipeline.push(peer);
            }
        }
    }
    if second.iter().any(|node| pipeline.contains(node)) {
        return true;
    }
    // The commands the script itself spells, which a compound stage's
    // streams do not join: `(git add -A) | rm f` is still a pipeline, and
    // `{ git add -A; } & rm f` still a background job.
    let spelled = |nodes: &[u32]| {
        let top = *nodes.last()?;
        let edge = parent(top)?;
        (edge.from == graph.entry && edge.kind == ExecutionEdgeKind::Launch)
            .then(|| graph.nodes.get(top as usize)?.source_span)
            .flatten()
    };
    let (Some(first_span), Some(second_span)) = (spelled(&first), spelled(&second)) else {
        return false;
    };
    let end = pipeline
        .iter()
        .filter_map(|node| graph.nodes.get(*node as usize)?.source_span)
        .map(|span| span.end)
        .chain([first_span.end])
        .max()
        .unwrap_or(first_span.end) as usize;
    let closed = |text: &'_ str| -> String {
        text.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, ';' | ')' | '}')
        })
        .to_owned()
    };
    let rest = closed(source.get(end..).unwrap_or_default());
    if rest.starts_with('&') && !rest.starts_with("&&") && !rest.starts_with("&>") {
        return true;
    }
    let between = source
        .get(first_span.end as usize..second_span.start as usize)
        .map(closed)
        .unwrap_or_default();
    let piped_to = between.strip_prefix("|&").or_else(|| {
        between
            .strip_prefix('|')
            .filter(|rest| !rest.starts_with('|'))
    });
    piped_to.is_some_and(|rest| {
        rest.chars()
            .all(|character| character.is_whitespace() || matches!(character, '(' | '{'))
    })
}

/// The changes to files, the index or other Git state that calls which may
/// run before `read` make, in plan order.
pub(super) fn earlier_changes<'a>(plan: &'a Plan, read: &Effect) -> Vec<&'a Effect> {
    plan.effects
        .iter()
        .filter(|candidate| {
            may_precede(plan, read, Some(candidate.execution.0))
                // A step of a script spelled after `read`'s command, such as
                // the redirection of a later command, runs once it is done.
                && !super::git_loss::spelled_in_order(plan, read, candidate)
                && (matches!(
                    candidate.operation.as_str(),
                    "filesystem.write" | "filesystem.move" | "filesystem.delete"
                ) || candidate.operation.as_str().starts_with("git.")
                    && candidate.operation.as_str() != "git.read"
                    // `git add` writes the index it stages its selection into
                    // after reading it, so its own write selects nothing. An
                    // earlier `git add` only stages files, which takes from a
                    // later add's selection just what it staged itself, and
                    // that staging is judged on its own.
                    && !(candidate.operation.as_str() == "git.index_write"
                        && (candidate.execution == read.execution
                            || stages_git_add_selection(read)
                                && plan.effects.iter().any(|other| {
                                    other.execution == candidate.execution
                                        && stages_git_add_selection(other)
                                }))))
        })
        .collect()
}

/// The earlier changes of `earlier_changes` that the observer applies
/// before answering for the staging `read`: each host file written or
/// deleted at a path the plan names, with whether it surely has finished
/// first (`finishes_before`). A move is stated again as the delete of what
/// it moves and the write of its destination. The rest are returned apart,
/// for `change_leaves_add_candidates` to judge against the answer.
pub(super) fn staging_changes<'a>(
    plan: &'a Plan,
    read: &Effect,
) -> (Vec<(&'a Effect, StagingChange)>, Vec<&'a Effect>) {
    let (mut described, mut others) = (Vec::new(), Vec::new());
    for change in earlier_changes(plan, read) {
        let flag = |name| change.attributes.get(name) == Some(&AttrValue::Bool(true));
        let operation = match (change.operation.as_str(), &change.resource) {
            (
                "filesystem.write",
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                },
            ) if change.realm.is_host() => (
                path,
                StagingOperation::Write {
                    // An ignore file's text decides what Git leaves out;
                    // any other file's text stays with the plan.
                    content: match change.attributes.get("written_content") {
                        Some(AttrValue::String(text)) if may_hold_ignore_rules(path) => {
                            Some(text.clone())
                        }
                        _ => None,
                    },
                    append: flag("append"),
                },
            ),
            (
                "filesystem.delete",
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                },
            ) if change.realm.is_host() => (
                path,
                StagingOperation::Delete {
                    recursive: flag("recursive"),
                },
            ),
            ("filesystem.move", _)
                if plan.effects.iter().any(|delete| {
                    delete.execution == change.execution
                        && delete.operation.as_str() == "filesystem.delete"
                        && delete.resource == change.resource
                }) =>
            {
                continue;
            }
            _ => {
                others.push(change);
                continue;
            }
        };
        described.push((
            change,
            StagingChange {
                path: operation.0.clone(),
                operation: operation.1,
                certain: finishes_before(plan, change, read),
            },
        ));
    }
    (described, others)
}

/// Whether a file at `path` may hold what decides which files Git ignores:
/// a `.gitignore`, a repository's `info/exclude`, or a user's excludes file,
/// which may be named anything like those.
fn may_hold_ignore_rules(path: &str) -> bool {
    let name = path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("");
    name.contains("ignore") || name.contains("exclude")
}

/// Whether `change` has surely run to its end before `read` starts: it runs
/// whenever `read` does, and the innermost shell script that spells both
/// spells it, alone, before `read` (`git_loss::spelled_in_order`). In the
/// request's own script it runs whenever `read` does when it holds no
/// condition, or when `read` runs only once a list of commands joined by
/// `&&` alone that holds `change` has succeeded, as in
/// `printf x > f && rm g && git add -A`. In a script a command of the call
/// launches, only that `&&` list counts: a step joined by `;` or a line
/// break runs there whether or not `change` succeeded. A change in a
/// pipeline or background job beside `read`, or one that may not run, may
/// still be running or never happen. A delete that asks first (`rm -i`) may
/// be declined, and `rm` still succeeds when it is.
pub(super) fn finishes_before(plan: &Plan, change: &Effect, read: &Effect) -> bool {
    let Some(shell) = super::git_loss::common_shell(plan, change, read) else {
        return false;
    };
    let Some(source) = super::git_loss::shell_source(plan, shell) else {
        return false;
    };
    if change.attributes.get("interactive") == Some(&AttrValue::Bool(true)) {
        return false;
    }
    let own_script = shell == plan.execution_graph.entry;
    // Conditions name their script by a digest of its text.
    let digest =
        effinterp_proto::stable_hash(effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN, &source);
    // The atoms a condition requires, where it requires only atoms.
    fn required(condition: &Condition) -> Option<Vec<&ConditionAtom>> {
        match condition {
            Condition::Atom { atom } => Some(vec![atom]),
            Condition::All { conditions } => {
                conditions.iter().try_fold(Vec::new(), |mut atoms, each| {
                    atoms.extend(required(each)?);
                    Some(atoms)
                })
            }
            Condition::Any { .. } | Condition::Widened => None,
        }
    }
    // A list whose success needs every command in it to have run: commands
    // joined by `&&`, with no other operator, separator or compound command.
    let and_list = |text: &str| {
        let bytes = text.as_bytes();
        !text.contains("||")
            && !bytes.iter().enumerate().any(|(index, byte)| {
                matches!(byte, b';' | b'\n')
                    || matches!(byte, b'|' | b'&')
                        && bytes.get(index + 1) != Some(byte)
                        && (index == 0 || bytes[index - 1] != *byte)
                        && !(*byte == b'&' && (index > 0 && bytes[index - 1] == b'>'))
            })
            && !text
                .split(|character: char| {
                    character.is_whitespace() || ";&|()<>`'\"{}$".contains(character)
                })
                .any(|word| {
                    matches!(
                        word,
                        "if" | "then"
                            | "else"
                            | "elif"
                            | "fi"
                            | "case"
                            | "esac"
                            | "while"
                            | "until"
                            | "for"
                            | "select"
                            | "do"
                            | "done"
                    )
                })
    };
    let ran = own_script && change.condition.is_none()
        || super::git_loss::script_span(plan, change, shell).is_some_and(|(start, end)| {
            read.condition
                .as_ref()
                .and_then(required)
                .is_some_and(|atoms| {
                    atoms.iter().any(|atom| {
                        let span = atom.origin.span;
                        atom.origin.kind == effinterp_proto::ConditionKind::ShortCircuit
                            && atom.polarity == Some(true)
                            && atom.origin.call_instance.is_none()
                            && atom.origin.source_digest == digest
                            && span.start <= start
                            && end <= span.end
                            && source
                                .get(span.start as usize..span.end as usize)
                                .is_some_and(and_list)
                    })
                })
        });
    ran && super::git_loss::spelled_in_order(plan, change, read)
}
