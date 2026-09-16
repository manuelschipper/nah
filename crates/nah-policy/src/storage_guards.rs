//! Evaluates remote-storage and backup guards from typed system-state effects.

use Knowledge::Known;
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};
use nah_proto::effects::*;

pub(crate) fn add(
    evidence: &GuardEvidence,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut added = false;
    for (name, message) in [
        (
            "storage-backup-destroy",
            "storage-backup-destroy blocked deletion of a complete backup repository or every selected backup; keep the recovery set intact and ask the operator to perform any deliberate repository removal",
        ),
        (
            "storage-recursive-delete",
            "storage-recursive-delete blocked broad remote deletion or destination-deleting synchronization; narrow the selection or ask the operator to perform the reviewed cleanup",
        ),
        (
            "storage-snapshot-delete",
            "storage-snapshot-delete blocked snapshot, archive, volume, or retention deletion; keep the recovery point intact and ask the operator to perform the reviewed removal",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !matches(name, evidence)
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name)?;
        contributions.push(GuardContribution::new(guard, message)?);
        added = true;
    }
    Ok(added)
}

fn matches(name: &str, evidence: &GuardEvidence) -> bool {
    evidence.graph().facts.iter().any(|fact| {
        if fact.certainty != Certainty::Exact || fact.condition.is_some() { return false; }
        let FactPayload::StorageChange { target, operation, kind, selection, recursive, destination_deletion,
            allow_remove_all, all_selection_requested, .. } = &fact.payload else { return false; };
        let deleting = matches!(operation, StorageOperation::Delete | StorageOperation::Destroy);
        let backup_mode = *allow_remove_all == Known(true) || *all_selection_requested == Known(true);
        match name {
            "storage-backup-destroy" => deleting && (*kind == StorageTarget::BackupRepository
                || matches!(kind, StorageTarget::Archive | StorageTarget::Snapshot) && backup_mode),
            "storage-recursive-delete" => *kind == StorageTarget::ObjectTree
                && !matches!(selection, Selection::NamedSet { .. } | Selection::Pattern { .. })
                && (deleting && *recursive == Known(true)
                    || *operation == StorageOperation::Sync && *destination_deletion == Known(true)),
            "storage-snapshot-delete" => {
                let ordinary_mode = *allow_remove_all == Known(false) && *all_selection_requested == Known(false);
                let cloud_volume = *kind == StorageTarget::LiveVolume && deleting
                    && evidence.graph().resources.iter().any(|resource| resource.id == *target
                        && matches!(&resource.identity.provider, Known(provider) if matches!(provider.as_str(), "aws" | "gcloud" | "az")));
                (deleting && (matches!(kind, StorageTarget::Snapshot | StorageTarget::Archive) && ordinary_mode
                    || *kind == StorageTarget::Subvolume || cloud_volume))
                    || *kind == StorageTarget::Snapshot && *operation == StorageOperation::Rollback && *recursive == Known(true)
            }
            _ => false,
        }
    })
}
