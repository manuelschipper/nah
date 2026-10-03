//! Explicit source-to-destination pairing for modeled transfers.
//!
//! A transfer (copy, rename, move, upload, download, sync, archive
//! create/extract) produces one source-side interaction and one
//! destination-side interaction. Which pair belongs together is known only
//! while the model or language API is being lowered, so every emitter records
//! it here instead of leaving a consumer to guess from adjacent effects,
//! matching path strings, or a shared source span.
//!
//! [`crate::flow::build_causality`] turns the recorded pairs into
//! `CausalReason::ResourceTransfer` edges once effect identity is final.
//!
//! Unsupported: inferring a transfer pairing after the fact. An operation that
//! records no binding contributes no transfer edge, and no heuristic recovers
//! one.

use serde::{Deserialize, Serialize};

use effinterp_proto::{
    AttrValue, CausalAssurance, Condition, Effect, ExecutionNode, ExecutionNodeRef, Fact, PathKind,
    ProvenanceKind, ProvenanceNode, ProvenanceRef, ResourceExpr, Subject,
};

/// One directed transfer pairing between two effect slots of the same effect
/// list: `source` is the source-side interaction's slot and `destination` the
/// destination-side interaction's slot.
///
/// Slots index the effect list that owns the binding — a
/// [`crate::PlanBuilder`]'s effects while analyzing, a [`crate::Summary`]'s
/// `effects` while a callable is summarized, or a
/// [`crate::ModuleSummary`]'s `module_effects` — so a binding survives
/// argument substitution and replay without re-deriving the pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferBinding {
    pub source: u32,
    pub destination: u32,
    pub assurance: CausalAssurance,
}

impl Default for TransferBinding {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl TransferBinding {
    pub fn new(source: u32, destination: u32) -> Self {
        Self {
            source,
            destination,
            assurance: CausalAssurance::Conservative,
        }
    }

    pub fn exact(source: u32, destination: u32) -> Self {
        Self {
            source,
            destination,
            assurance: CausalAssurance::Exact,
        }
    }

    /// Shift both slots by a base offset, for a binding whose effects were
    /// appended to a longer list.
    pub fn shifted(self, base: u32) -> Self {
        Self {
            source: self.source + base,
            destination: self.destination + base,
            assurance: self.assurance,
        }
    }
}

/// Pair every recorded source slot with every recorded destination slot of one
/// operation. Emitters that resolve a side to several endpoint effects (a
/// bounded scope written as alternatives, an archive's selected inputs) use
/// this so multiple operands keep their own pairing instead of one collapsed
/// edge; operands that pair one-to-one call [`TransferBinding::new`] directly
/// rather than forming a Cartesian product across unrelated operands.
pub(crate) fn pair_slots(
    sources: &[Option<u32>],
    destinations: &[Option<u32>],
) -> Vec<TransferBinding> {
    let mut bindings = Vec::new();
    for source in sources.iter().flatten() {
        for destination in destinations.iter().flatten() {
            bindings.push(TransferBinding::new(*source, *destination));
        }
    }
    bindings
}

/// What a name created earlier in this execution refers to.
///
/// A symbolic link records the target's spelling, resolved in the directory
/// that owns the link. The `ln` model supplies its literal operand directly;
/// another hard-link model can bind the same inode with an exact
/// source-to-create transfer, without depending on its execution subject.
/// Either way a content access through the new name reaches the file the
/// invocation's own evidence names — the host's initial snapshot predates the
/// link and cannot.
///
/// Only the latest filesystem effect on the name decides: a later delete,
/// rename or non-link creation replaces whatever the link established, and
/// nothing about the earlier name survives it.
pub(crate) fn created_alias_identity(
    effects: &[Effect],
    executions: &[ExecutionNode],
    transfer_bindings: &[TransferBinding],
    link: &ResourceExpr,
) -> Option<(ResourceExpr, Vec<ProvenanceRef>)> {
    for (effect_index, effect) in effects
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, effect)| &effect.resource == link)
    {
        if !matches!(
            effect.operation.as_str(),
            "filesystem.create" | "filesystem.delete" | "filesystem.move"
        ) {
            continue;
        }
        if effect.operation.as_str() != "filesystem.create" {
            return None;
        }
        let symbolic = effect.attributes.get("symlink") == Some(&AttrValue::Bool(true));
        let ln_target = executions
            .get(effect.execution.0 as usize)
            .and_then(|execution| match &execution.subject {
                Subject::Exec { argv, .. } => {
                    literal_ln_target(argv, execution.cwd.as_ref(), link, symbolic)
                }
                _ => None,
            });
        let target = if symbolic {
            ln_target?
        } else if let Some(target) = ln_target {
            target
        } else {
            let bindings = transfer_bindings
                .iter()
                .filter(|binding| binding.destination as usize == effect_index)
                .collect::<Vec<_>>();
            let [binding] = bindings.as_slice() else {
                return None;
            };
            if binding.assurance != CausalAssurance::Exact {
                return None;
            }
            let source = effects.get(binding.source as usize)?;
            if source.operation.as_str() != "filesystem.read"
                || source.attributes.get("metadata") != Some(&AttrValue::Bool(true))
                || source.execution != effect.execution
                || source.realm != effect.realm
                || source.condition != effect.condition
                || !matches!(
                    source.resource,
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { .. }
                    }
                )
            {
                return None;
            }
            source.resource.clone()
        };
        return Some((target, effect.provenance.clone()));
    }
    None
}

/// The pre-move identity carried to a destination by one exact rename.
///
/// A destination write is enough to establish new stored bytes, but not their
/// prior identity. That identity is available only when the same modeled move
/// observed its source before deleting it, paired only that deletion to this
/// write, and the later use runs only after the move succeeded. The retained
/// observation is initial-state evidence for the source; asking the host about
/// either name after the rename would instead describe the wrong filesystem
/// state.
pub(crate) fn moved_content_identity(
    effects: &[Effect],
    executions: &[ExecutionNode],
    transfer_bindings: &[TransferBinding],
    provenance: &[ProvenanceNode],
    destination: &ResourceExpr,
    current_execution: ExecutionNodeRef,
    current_condition: Option<&Condition>,
) -> Option<(ResourceExpr, Vec<ProvenanceRef>)> {
    let (destination_index, destination_effect) =
        effects.iter().enumerate().rev().find(|(_, effect)| {
            &effect.resource == destination && changes_stored_identity(effect)
        })?;
    if destination_effect.operation.as_str() != "filesystem.write" {
        return None;
    }
    let bindings = transfer_bindings
        .iter()
        .filter(|binding| binding.destination as usize == destination_index)
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return None;
    };
    let source_index = binding.source as usize;
    let source = effects.get(source_index)?;
    if source.operation.as_str() != "filesystem.delete"
        || source.request_assurance != effinterp_proto::RequestAssurance::Exact
        || source.execution != destination_effect.execution
        || source.realm != destination_effect.realm
        || source.condition != destination_effect.condition
    {
        return None;
    }
    let move_effect = effects[..=source_index].iter().rev().find(|effect| {
        effect.operation.as_str() == "filesystem.move"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            && effect.resource == source.resource
            && effect.execution == source.execution
            && effect.realm == source.realm
            && effect.condition == source.condition
            && effect.provenance == source.provenance
    })?;
    let same_execution = current_execution == source.execution;
    let follows_success = executions
        .get(source.execution.0 as usize)
        .and_then(|execution| execution.source_span)
        .is_some_and(|span| condition_requires_short_circuit_success(current_condition, span));
    if !same_execution && !follows_success {
        return None;
    }

    let source_read = effects[..source_index].iter().rev().find(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && effect.resource == source.resource
            && effect.attributes.get("access_purpose")
                == Some(&AttrValue::String("program_input".into()))
            && effect.execution == source.execution
            && effect.realm == source.realm
            && effect.condition == source.condition
            && source
                .provenance
                .iter()
                .all(|reference| effect.provenance.contains(reference))
    })?;
    let observation = source_read.provenance.iter().rev().find(|reference| {
        matches!(
            provenance.get(reference.0 as usize).map(|node| &node.kind),
            Some(ProvenanceKind::HostObservation { .. })
        )
    })?;
    let ProvenanceKind::HostObservation {
        outcome: effinterp_proto::ObservationOutcome::Path(fact),
        ..
    } = &provenance.get(observation.0 as usize)?.kind
    else {
        return None;
    };
    if fact.kind == PathKind::Fifo
        || matches!(&fact.followed, Fact::Known(target) if target.kind == Fact::Known(PathKind::Fifo))
    {
        return None;
    }
    let identity = match &fact.followed {
        Fact::Known(target) => target.path.as_str(),
        Fact::Unavailable(_) if fact.kind != PathKind::Symlink => fact.entry.as_str(),
        Fact::Unavailable(_) => return None,
    };
    let ResourceExpr::Concrete {
        identity: effinterp_proto::ResourceIdentity::FsPath { path },
    } = &source_read.resource
    else {
        return None;
    };
    if path != identity {
        return None;
    }

    let mut evidence = source_read.provenance.clone();
    evidence.extend(move_effect.provenance.iter().copied());
    evidence.extend(source.provenance.iter().copied());
    evidence.extend(destination_effect.provenance.iter().copied());
    evidence.sort();
    evidence.dedup();
    Some((source_read.resource.clone(), evidence))
}

fn changes_stored_identity(effect: &Effect) -> bool {
    matches!(
        effect.operation.as_str(),
        "filesystem.create" | "filesystem.delete" | "filesystem.move"
    ) || effect.operation.as_str() == "filesystem.write"
        && effect.attributes.get("metadata") != Some(&AttrValue::Bool(true))
}

pub(crate) fn condition_requires_short_circuit_success(
    condition: Option<&Condition>,
    span: effinterp_proto::ByteSpan,
) -> bool {
    match condition {
        Some(Condition::Atom { atom }) => {
            atom.origin.kind == effinterp_proto::ConditionKind::ShortCircuit
                && atom.origin.span == span
                && atom.polarity == Some(true)
        }
        Some(Condition::All { conditions }) => conditions
            .iter()
            .any(|condition| condition_requires_short_circuit_success(Some(condition), span)),
        Some(Condition::Any { conditions }) => {
            !conditions.is_empty()
                && conditions.iter().all(|condition| {
                    condition_requires_short_circuit_success(Some(condition), span)
                })
        }
        Some(Condition::Widened) | None => false,
    }
}

/// The source link and trailing path selected by an exact Info-ZIP
/// create/extract pair. `zip -y` stores a symbolic link instead of following
/// it; the caller still has to establish that the selected source is a link.
pub(crate) fn archived_symlink_source(
    effects: &[Effect],
    executions: &[ExecutionNode],
    extracted: &ResourceExpr,
) -> Option<(ResourceExpr, String, Vec<ProvenanceRef>)> {
    let ResourceExpr::Concrete {
        identity: effinterp_proto::ResourceIdentity::FsPath { path: extracted },
    } = extracted
    else {
        return None;
    };
    for (unzip_index, unzip_effect) in effects.iter().enumerate().rev() {
        if unzip_effect.operation.as_str() != "process.exec" {
            continue;
        }
        let unzip = executions.get(unzip_effect.execution.0 as usize)?;
        let Subject::Exec { argv, .. } = &unzip.subject else {
            continue;
        };
        let [program, archive, option, destination] = argv.as_slice() else {
            continue;
        };
        if program.rsplit('/').next() != Some("unzip") || option != "-d" {
            continue;
        }
        let archive = crate::paths::resolve_fs_path_with_cwd(archive, unzip.cwd.clone());
        let ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path: destination },
        } = crate::paths::resolve_fs_path_with_cwd(destination, unzip.cwd.clone())
        else {
            continue;
        };
        let Some(member) = extracted
            .strip_prefix(&destination)
            .and_then(|suffix| suffix.strip_prefix('/'))
        else {
            continue;
        };
        for zip_effect in effects[..unzip_index].iter().rev() {
            if zip_effect.operation.as_str() != "process.exec" {
                continue;
            }
            let zip = executions.get(zip_effect.execution.0 as usize)?;
            let Subject::Exec { argv, .. } = &zip.subject else {
                continue;
            };
            let [program, option, zip_archive, source] = argv.as_slice() else {
                continue;
            };
            if program.rsplit('/').next() != Some("zip")
                || !matches!(option.as_str(), "-y" | "--symlinks")
                || crate::paths::resolve_fs_path_with_cwd(zip_archive, zip.cwd.clone()) != archive
            {
                continue;
            }
            let source = crate::paths::resolve_fs_path_with_cwd(source, zip.cwd.clone());
            let ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path: source_path },
            } = &source
            else {
                continue;
            };
            let stored = source_path.trim_start_matches('/');
            let Some(suffix) = member
                .strip_prefix(stored)
                .and_then(|suffix| suffix.strip_prefix('/'))
            else {
                continue;
            };
            let mut provenance = zip_effect.provenance.clone();
            provenance.extend(unzip_effect.provenance.iter().copied());
            return Some((source, suffix.to_string(), provenance));
        }
    }
    None
}

fn literal_ln_target(
    argv: &[String],
    cwd: Option<&ResourceExpr>,
    link: &ResourceExpr,
    symlink_effect: bool,
) -> Option<ResourceExpr> {
    let executable = argv.first()?.rsplit('/').next()?;
    if executable != "ln" {
        return None;
    }
    let mut symbolic = false;
    let mut operands = Vec::new();
    let mut flags = true;
    let mut i = 1;
    while i < argv.len() {
        let argument = &argv[i];
        if flags && argument == "--" {
            flags = false;
        } else if flags && argument == "--symbolic" {
            symbolic = true;
        } else if flags && matches!(argument.as_str(), "-S" | "--suffix") {
            i += 1;
            argv.get(i)?;
        } else if flags && matches!(argument.as_str(), "-t" | "--target-directory") {
            return None;
        } else if flags && argument.starts_with('-') && argument.len() > 1 {
            for flag in argument[1..].chars() {
                match flag {
                    's' => symbolic = true,
                    'f' | 'n' | 'T' | 'v' | 'b' | 'L' | 'P' | 'r' => {}
                    _ => return None,
                }
            }
        } else {
            operands.push(argument.as_str());
        }
        i += 1;
    }
    let [target, destination] = operands.as_slice() else {
        return None;
    };
    // The recovered grammar and the emitted effect must agree on which kind
    // of link this is; a disagreement means one of them is describing
    // something this parse does not cover.
    if symbolic != symlink_effect
        || crate::paths::resolve_fs_path_with_cwd(destination, cwd.cloned()) != *link
    {
        return None;
    }
    if symbolic {
        // A symbolic link stores the target's spelling, which the kernel
        // resolves in the directory holding the link, not in the cwd that
        // created it.
        return crate::paths::resolve_symlink_target(target, link);
    }
    // A hard link names the operand's inode. That file keeps its own name,
    // which the creating command resolved against its cwd.
    Some(crate::paths::resolve_fs_path_with_cwd(target, cwd.cloned()))
}
