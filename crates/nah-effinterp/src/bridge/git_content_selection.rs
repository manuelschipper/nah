//! Bind the Git model's content selections to filename-only host evidence.

use effinterp_proto::{AttrValue, Effect, Plan};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{
    GitReadKind, GitReadSelection, Observation, ObservationQuery, ObservationValue, Observed,
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
        },
    ))
}

pub(super) fn queries(plan: &Plan) -> Vec<ObservationQuery> {
    plan.effects
        .iter()
        .filter_map(selection)
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
    observation: &'a Observation,
    effect: &Effect,
) -> Option<&'a [AbsolutePath]> {
    let (directory, selection) = selection(effect)?;
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
            selection(effect).is_some() && observed_paths(observation, effect).is_none()
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
