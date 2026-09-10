//! Evaluates destructive Git guards; it does not interpret command-line syntax.

use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};
use nah_proto::effects::Knowledge::{Known, Unknown};
use nah_proto::effects::*;
use nah_proto::labels::PathScope;

pub(crate) fn add(
    evidence: &GuardEvidence,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut blocked = false;
    for (name, reason) in [
        (
            "git-clean-force",
            "git-clean-force blocked a forced clean selecting the project root; preview with git clean -n, name the intended target, or ask the operator to perform the project-wide clean",
        ),
        (
            "git-metadata",
            "git-metadata blocked a destructive change to Git metadata; use Git commands instead of editing or deleting .git data directly",
        ),
        (
            "git-path-discard",
            "git-path-discard blocked a named-path working-tree discard; inspect git diff and stash wanted work before replacing the path",
        ),
        (
            "git-protected-push",
            "git-protected-push blocked a push whose explicit refspec targets main or master; push a feature branch and use a pull request instead",
        ),
        (
            "git-force-push",
            "git-force-push blocked a force push without lease protection or to an explicit main/master destination; push a feature branch without force, or ask the operator to perform the intended history rewrite",
        ),
        (
            "git-hard-reset",
            "git-hard-reset blocked git reset --hard; inspect the diff and preserve wanted work; use a targeted restore or ask the operator to perform the full reset",
        ),
        (
            "git-history-rewrite",
            "git-history-rewrite blocked a Git history rewrite; inspect the affected refs, use an abort or dry-run mode when available, or ask the operator to verify the rewrite",
        ),
        (
            "git-rewrite-force",
            "git-rewrite-force blocked a forced history rewrite; remove the force bypass and preview the rewrite; ask the operator to verify the affected history",
        ),
        (
            "git-recovery-destroy",
            "git-recovery-destroy blocked deletion of Git recovery history; keep stashes, reflogs, and recovery refs; ask the operator to verify they are no longer needed",
        ),
        (
            "git-ref-delete",
            "git-ref-delete blocked deletion of a Git ref, stash entry, or worktree; preserve the selected state or ask the operator to verify its deletion",
        ),
        (
            "git-remote-repo-delete",
            "git-remote-repo-delete blocked deletion of an entire hosted repository; preserve the hosted project and ask the operator to verify any whole-repository deletion",
        ),
        (
            "git-remote-resource-delete",
            "git-remote-resource-delete blocked deleting a hosted Git resource; keep it and ask the operator to perform the reviewed removal",
        ),
        (
            "git-worktree-discard",
            "git-worktree-discard blocked a broad working-tree discard or forced worktree/submodule removal; inspect git diff and preserve wanted work in each affected tree, or ask the operator to perform the broad discard",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !matches_guard(name, evidence)
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name)?;
        contributions.push(GuardContribution::new(guard, reason)?);
        blocked = true;
    }
    Ok(blocked)
}

fn matches_guard(name: &str, evidence: &GuardEvidence) -> bool {
    evidence.graph().facts.iter().any(|fact| {
        // A possible or conditional operation is not an established destructive act.
        if fact.certainty != Certainty::Exact
            || fact.modality != Modality::MustOnSuccess
            || fact.condition.is_some()
        {
            return false;
        }
        match &fact.payload {
            FactPayload::GitPush { .. } => matches_push(name, &fact.payload),
            FactPayload::GitDiscard { target, mode, reset, selection, untracked, force, dry_run }
                if *dry_run == Known(false) => {
                let whole = matches!(selection, Selection::Whole);
                let named = matches!(selection, Selection::Exact | Selection::NamedSet { .. });
                let root = whole || evidence.graph().resources.iter().any(|r| r.id == *target
                    && matches!(&r.identity.details, Known(ResourceDetails::Git { worktree: Known(_), .. }))
                    && matches!(selection, Selection::Subtree { root: Known(path) }
                        if matches!(&r.identity.details, Known(ResourceDetails::Git { worktree: Known(worktree), .. }) if worktree == path)));
                match name {
                    "git-clean-force" => *mode == GitDiscardMode::Clean && *force == Known(true) && *untracked == Known(true) && root,
                    "git-hard-reset" => *mode == GitDiscardMode::Reset && *reset == Known(ResetMode::Hard),
                    "git-worktree-discard" => match mode {
                        GitDiscardMode::Checkout | GitDiscardMode::Restore => root,
                        GitDiscardMode::WorktreeRemove | GitDiscardMode::SubmoduleDeinit => *force == Known(true),
                        _ => false,
                    },
                    "git-path-discard" => matches!(mode, GitDiscardMode::Checkout | GitDiscardMode::Restore) && named && !root,
                    "git-ref-delete" => matches!(mode, GitDiscardMode::WorktreeRemove | GitDiscardMode::SubmoduleDeinit),
                    _ => false,
                }
            }
            FactPayload::GitHistory { operation, active: Known(true), abort: Known(false), dry_run: Known(false), force, .. } => match name {
                "git-rewrite-force" => *operation == GitHistoryOperation::Filter && *force == Known(true),
                "git-history-rewrite" => *operation != GitHistoryOperation::Amend && !(*operation == GitHistoryOperation::Filter && *force == Known(true)),
                _ => false,
            },
            FactPayload::GitRecovery { operation, selection, active: Known(true), abort: Known(false), dry_run: Known(false), .. } => {
                name == "git-recovery-destroy" && *operation == GitRecoveryOperation::Remove && matches!(selection, Selection::Whole)
            }
            FactPayload::GitRefChange { operation: GitRefOperation::Delete, active: Known(true), abort: Known(false), dry_run: Known(false), .. } => name == "git-ref-delete" && !evidence.graph().facts.iter().any(|push| {
                push.call == fact.call && push.certainty == Certainty::Exact && push.modality == Modality::MustOnSuccess
                    && push.condition == fact.condition && ["git-force-push", "git-protected-push", "git-history-rewrite"].iter().any(|name| matches_push(name, &push.payload))
            }),
            FactPayload::HostedDeletion { kind, delete: Known(true), .. } => matches!((name, kind),
                ("git-remote-repo-delete", HostedTarget::Repository) | ("git-remote-resource-delete", HostedTarget::Resource)),
            FactPayload::FilesystemAccess { operation, target, destination, recursive, .. }
                if fact.realm == Realm::Host && *operation != FilesystemOperation::Read => {
                name == "git-metadata" && [Some(*target), *destination].into_iter().flatten().any(|id| {
                    evidence.graph().resources.iter().any(|r| r.id == id && r.labels.as_ref().is_some_and(|labels| {
                        [&labels.lexical, &labels.canonical].into_iter().any(|path| matches!(path, Known(path) if metadata_path(path.as_str(), *operation, *recursive == Known(true)) || metadata_repository_path(evidence, path.as_str())))
                    }))
                })
            }
            _ => false,
        }
    }) || name == "git-path-discard" && matches_show_path_discard(evidence)
}

fn normalize_ref(reference: &str) -> &str {
    reference.strip_prefix("refs/heads/").unwrap_or(reference)
}

fn metadata_path(path: &str, operation: FilesystemOperation, recursive: bool) -> bool {
    let windows = path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(1) == Some(&b':')
        || path.starts_with("//")
        || path.starts_with(r"\\");
    let folded;
    let path = if windows {
        folded = path.replace('\\', "/").to_ascii_lowercase();
        &folded
    } else {
        path
    };
    let mut components = path.split('/');
    let Some(component) = components.find(|part| *part == ".git" || part.ends_with(".git")) else {
        return false;
    };
    match components.next() {
        None => component == ".git" || operation == FilesystemOperation::Delete && recursive,
        Some("logs" | "objects" | "packed-refs" | "refs" | "worktrees" | "*" | "**" | "{*,.*}") => {
            true
        }
        Some(first) => first
            .strip_prefix('{')
            .and_then(|v| v.strip_suffix('}'))
            .is_some_and(|choices| {
                choices.split(',').any(|choice| {
                    matches!(
                        choice,
                        "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
                    )
                })
            }),
    }
}

fn matches_show_path_discard(evidence: &GuardEvidence) -> bool {
    let established = |fact: &&EffectFact| {
        fact.certainty == Certainty::Exact
            && fact.modality == Modality::MustOnSuccess
            && fact.condition.is_none()
            && fact.realm == Realm::Host
    };
    evidence.graph().facts.iter().filter(established).any(|show| {
        matches!(&show.payload, FactPayload::Other { operation, .. } if operation == "git.show")
            && evidence.graph().facts.iter().filter(established).any(|read| {
                let FactPayload::FilesystemAccess { operation: FilesystemOperation::Read, target, .. } = &read.payload else { return false; };
                if read.call != show.call { return false; }
                let Some(resource) = evidence.graph().resources.iter().find(|r| r.id == *target) else { return false; };
                resource.selection == Selection::Exact
                    && resource.labels.as_ref().is_some_and(|l| matches!(&l.scope, Known(PathScope::Project { .. })) && l.selects_project == Reach::No)
                    && evidence.graph().facts.iter().filter(established).any(|write| {
                        write.call == show.call && matches!(&write.payload, FactPayload::FilesystemAccess { operation: FilesystemOperation::Write, target, .. }
                            if evidence.graph().resources.iter().any(|r| r.id == *target && r.selection == Selection::Exact && r.identity == resource.identity))
                    })
            })
    })
}

fn matches_push(name: &str, payload: &FactPayload) -> bool {
    match payload {
        FactPayload::GitPush {
            destinations,
            destinations_complete,
            explicit_force,
            lease_requested,
            all_refs_lease,
            leased_refs,
            delete,
            all,
            branches,
            mirror,
            prune,
            selection,
            dry_run,
            ..
        } if *dry_run == Known(false) => {
            let protected_destination = |d: &PushDestination| {
                matches!(&d.source, Known(source) if !source.is_empty())
                    && matches!(&d.destination, Known(destination) if matches!(normalize_ref(destination), "main" | "master"))
            };
            let protected = *destinations_complete == Known(true)
                && *delete == Known(false)
                && *all == Known(false)
                && *branches == Known(false)
                && destinations.iter().any(protected_destination);
            let lease_applies = |d: &PushDestination| {
                if *all_refs_lease == Known(true) {
                    return Known(true);
                }
                if *all_refs_lease == Known(false)
                    && matches!(leased_refs, Known(refs) if refs.is_empty())
                {
                    return Known(false);
                }
                match (&d.destination, leased_refs, all_refs_lease) {
                    (Known(destination), Known(refs), Known(false)) => Known(
                        refs.iter()
                            .any(|r| normalize_ref(r) == normalize_ref(destination)),
                    ),
                    _ => Unknown,
                }
            };
            let force = *explicit_force == Known(true)
                || *mirror == Known(true)
                || destinations
                    .iter()
                    .any(|d| d.forced == Known(true) && lease_applies(d) == Known(false))
                || protected
                    && destinations
                        .iter()
                        .any(|d| protected_destination(d) && lease_applies(d) == Known(true));
            let history = *lease_requested == Known(true);
            match name {
                "git-protected-push" => protected,
                "git-force-push" => force,
                "git-history-rewrite" => history,
                "git-ref-delete" => {
                    !force && !protected && !history
                        && *destinations_complete == Known(true)
                        && *explicit_force == Known(false) && *mirror == Known(false) && *lease_requested == Known(false)
                        && *all == Known(false) && *branches == Known(false) && *prune == Known(false)
                        && !matches!(selection, Selection::Whole)
                        && destinations.iter().any(|destination| {
                            matches!(&destination.destination, Known(name) if !name.is_empty())
                                && (*delete == Known(true) && !destinations.iter().any(|d| matches!(&d.source, Known(source) if source.is_empty())) || *delete == Known(false) && matches!(&destination.source, Known(source) if source.is_empty()))
                        })
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn metadata_repository_path(evidence: &GuardEvidence, path: &str) -> bool {
    evidence.graph().resources.iter().any(|resource| {
        if resource.realm != Realm::Host {
            return false;
        }
        let Known(ResourceDetails::Git {
            git_dir: Known(git_dir),
            ..
        }) = &resource.identity.details
        else {
            return false;
        };
        let windows = git_dir.as_str().as_bytes().get(1) == Some(&b':')
            || git_dir.as_str().starts_with(r"\\");
        let separator = |character| character == '/' || windows && character == '\\';
        path == git_dir.as_str()
            || path
                .strip_prefix(git_dir.as_str())
                .and_then(|tail| tail.strip_prefix(separator))
                .is_some_and(|tail| {
                    tail.split(separator).next().is_some_and(|component| {
                        matches!(
                            component,
                            "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
                        )
                    })
                })
    })
}
