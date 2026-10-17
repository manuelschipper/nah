//! Which file a launched path names when the plan itself changed that path
//! before the launch: the executed identity self-protection reads.

use effinterp_proto::{AttrValue, Effect, ResourceExpr, ResourceIdentity};
use nah_proto::labels::tier;

use super::process_protection::{literal_argv, literal_words};
use crate::plan_view::PlanView;

/// The file an executed path names, from Nah's host observation of it. That
/// observation describes the host before the plan runs, so it identifies the
/// launch only when no effect this plan orders before the launch writes,
/// creates, moves, deletes or mounts the path, a directory above it, or a
/// selection whose bounds are unknown. The engine has already replaced a path
/// this plan linked with the link's target. A path this plan last changed by
/// copying or hard-linking an installed nah binary onto it
/// (`cp nah alias; ./alias`, `cat nah > alias; ./alias`) names that binary,
/// identified as of the copy.
pub(super) fn executed_identity<'a>(
    view: &PlanView<'a>,
    effect: &Effect,
    path: &str,
) -> Option<&'a str> {
    let platform = view.authority().platform();
    let change = view
        .plan()
        .effects
        .iter()
        .take_while(|earlier| !std::ptr::eq(*earlier, effect))
        .filter(|earlier| {
            earlier.realm.is_host()
                && earlier.operation.domain() == "filesystem"
                && !matches!(
                    earlier.operation.as_str(),
                    "filesystem.read" | "filesystem.metadata"
                )
        })
        .filter(|earlier| {
            crate::observation_request::observation_bound(&earlier.resource).is_none_or(
                |(bound, _)| {
                    nah_proto::labels::lexically_contains(&bound, path, platform)
                        || nah_proto::labels::lexically_contains(
                            observed_entry_path(view, &bound),
                            observed_entry_path(view, path),
                            platform,
                        )
                },
            )
        })
        .last();
    let Some(change) = change else {
        let observed = view.observed_path(path)?;
        return Some(observed.realpath().unwrap_or(observed.resolved()).as_str());
    };
    let installed = |path: &str| {
        tier::is_installed_nah(
            path,
            view.authority().installed_executables(),
            view.authority().home(),
            platform,
        )
    };
    // A copy establishes only that the path is Nah. Several files copied
    // onto one path leave any of them there, and a source that is not Nah
    // leaves the launch as unidentified as any other rewritten path, so a
    // program spelled `nah` still fails closed.
    transferred_sources(view, change, path)
        .into_iter()
        .filter_map(|source| {
            if installed(source) {
                Some(source)
            } else {
                executed_identity(view, change, source)
            }
        })
        .find(|identity| installed(identity))
}

/// The files whose content `change`, a write or creation of exactly `path`,
/// puts there: the sources of the copy or hard link the engine modeled as a
/// resource transfer into it, or the one file a verbatim stream copy writes
/// there (`stream_copy_source`). Empty when `change` is any other kind of
/// change or covers more than that one path.
fn transferred_sources<'a>(view: &PlanView<'a>, change: &'a Effect, path: &str) -> Vec<&'a str> {
    let platform = view.authority().platform();
    let names_path = matches!(
        &change.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: written },
        } if nah_proto::labels::lexical_path::same_path(written, path, platform)
            || nah_proto::labels::lexical_path::same_path(
                observed_entry_path(view, written),
                observed_entry_path(view, path),
                platform,
            )
    );
    if !names_path
        || !matches!(
            change.operation.as_str(),
            "filesystem.write" | "filesystem.create"
        )
    {
        return Vec::new();
    }
    if !transfer_lands(view, change, path) {
        return Vec::new();
    }
    let written: Vec<_> = view
        .occurrences_for_execution(change.execution)
        .filter(|node| {
            node.realm == change.realm
                && node.condition == change.condition
                && node.provenance == change.provenance
                && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    ..
                } if operation == &change.operation && resource == &change.resource)
        })
        .collect();
    let transferred: Vec<&str> = written
        .iter()
        .flat_map(|node| view.incoming_edges(&node.id))
        .filter(|edge| edge.reason == effinterp_proto::CausalReason::ResourceTransfer)
        .filter_map(|edge| view.causal_node(&edge.from))
        .filter_map(|source| match &source.occurrence {
            effinterp_proto::OccurrenceKind::ResourceInteraction {
                operation,
                resource:
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    },
                ..
            } if source.realm.is_host() && operation.as_str() == "filesystem.read" => {
                Some(path.as_str())
            }
            _ => None,
        })
        .collect();
    if !transferred.is_empty() {
        return transferred;
    }
    match written.as_slice() {
        [written] => stream_copy_source(view, change, written)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// The one file whose bytes `change` writes unchanged through standard
/// streams: `cat nah > alias`, `cat nah | tee alias`, `tee alias < nah`.
/// Such a write leaves the file's content at the written path as a copy
/// does, although the engine models it as a flow, not a transfer.
///
/// An exact causal edge states that the output depends on the input, not
/// that it equals it (`base64 nah > alias` has one too), so every process
/// whose standard output the bytes pass through must be one that copies
/// its input verbatim (`copies_verbatim`). Every dependency on the way must
/// be exact, the write must replace the file rather than append to it, and
/// exactly one file may feed it: two files, or standard input the call
/// inherits, leave content no single file names.
fn stream_copy_source<'a>(
    view: &PlanView<'a>,
    change: &Effect,
    written: &'a effinterp_proto::OccurrenceNode,
) -> Option<&'a str> {
    use effinterp_proto::{CausalAssurance, CausalReason, OccurrenceKind, Port};
    if change.operation.as_str() != "filesystem.write"
        || change.attributes.get("append") == Some(&AttrValue::Bool(true))
    {
        return None;
    }
    let inputs = |node: &'a effinterp_proto::OccurrenceNode| {
        view.incoming_edges(&node.id)
            .filter(|edge| edge.reason == CausalReason::ValueDependency)
            .filter_map(|edge| Some((edge, view.causal_node(&edge.from)?)))
    };
    let mut sources = std::collections::BTreeSet::new();
    let mut reached = std::collections::BTreeSet::new();
    let mut conservative = Vec::new();
    let mut pending = vec![written];
    while let Some(node) = pending.pop() {
        if !reached.insert(&node.id) {
            continue;
        }
        match &node.occurrence {
            _ if std::ptr::eq(node, written) => {}
            OccurrenceKind::ResourceInteraction {
                operation,
                resource:
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    },
                ..
            } if node.realm.is_host() && operation.as_str() == "filesystem.read" => {
                sources.insert(path.as_str());
                continue;
            }
            OccurrenceKind::Port { port: Port::Stdout } => {
                if !copies_verbatim(view, node.execution?) {
                    return None;
                }
            }
            OccurrenceKind::Port { port: Port::Stdin } => {}
            _ => return None,
        }
        let mut exact = Vec::new();
        for (edge, from) in inputs(node) {
            // What a process adds to its own output; a verbatim copier adds
            // nothing.
            if from.execution == node.execution
                && matches!(&from.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.as_str() == "process.exec")
            {
                continue;
            }
            if edge.assurance == CausalAssurance::Exact {
                exact.push(from);
            } else {
                conservative.push(&from.id);
            }
        }
        // A redirection replaces the standard input its command would
        // otherwise inherit from the call, so that inherited input is left
        // out only where it meets a redirection at a standard input. Reached
        // anywhere else (`cat nah - > alias`) it is input no file names.
        if exact.len() > 1 && matches!(&node.occurrence, OccurrenceKind::Port { port: Port::Stdin })
        {
            exact.retain(|from| {
                !matches!(&from.occurrence, OccurrenceKind::Port { port: Port::Stdin })
                    || inputs(from).next().is_some()
            });
        }
        if exact.is_empty() {
            return None;
        }
        pending.extend(exact);
    }
    // A conservative dependency on something the exact flow does not pass
    // through may add or change bytes.
    if conservative.iter().any(|id| !reached.contains(id)) {
        return None;
    }
    let mut sources = sources.into_iter();
    sources.next().filter(|_| sources.next().is_none())
}

/// Whether the process writes exactly its input to its standard output:
/// `tee`, or `cat` without an option that numbers, squeezes or marks what it
/// prints.
fn copies_verbatim(view: &PlanView<'_>, execution: effinterp_proto::ExecutionNodeRef) -> bool {
    let Some(words) = literal_argv(&view.execution(execution).argv) else {
        return false;
    };
    let mut words = words.iter();
    match words.next().and_then(|program| program.rsplit('/').next()) {
        Some("tee") => true,
        Some("cat") => words
            .take_while(|word| *word != "--")
            .all(|word| !word.starts_with('-') || matches!(word.as_str(), "-" | "-u")),
        _ => false,
    }
}

/// `path` as its host observation resolved it, with the directory links
/// above it followed, so `/tmp/x` and `/private/tmp/x` compare equal.
fn observed_entry_path<'a>(view: &PlanView<'a>, path: &'a str) -> &'a str {
    view.observed_entry(path)
        .map_or(path, |observed| observed.resolved().as_str())
}

/// Whether the copy or link that `change` records can have put its source at
/// `path`. The engine names the destination operand as written and marks no
/// refusal, so the bridge rules out what it can see: a destination that is a
/// directory (the copy lands under it), a parent that is not the copy's
/// working directory, not observed and not created earlier in the plan (the
/// copy fails), and a `cp` or `mv` that
/// keeps an existing destination (`-n`) or replaces only an older one (`-u`),
/// which lands for certain only on a path that did not exist. BSD `cp` and
/// `mv` reject `-u`.
fn transfer_lands(view: &PlanView<'_>, change: &Effect, path: &str) -> bool {
    use nah_proto::observation::PathKind;
    let platform = view.authority().platform();
    let observed = view.observed_entry(path).map(|observed| observed.kind());
    if observed == Some(PathKind::Directory) {
        return false;
    }
    let Some(parent) = crate::observation_request::parent_directory(path) else {
        return false;
    };
    // The copying process runs in its working directory, so that exists.
    let runs_in_parent = matches!(
        view.execution(change.execution).cwd,
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: cwd },
        }) if nah_proto::labels::lexical_path::same_path(cwd, parent, platform)
    );
    let parent_exists = runs_in_parent
        || view.observed_directory(parent)
        || view
            .plan()
            .effects
            .iter()
            .take_while(|earlier| !std::ptr::eq(*earlier, change))
            .any(|earlier| {
                earlier.operation.as_str() == "filesystem.create"
                    && matches!(
                        &earlier.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: created },
                        } if nah_proto::labels::lexical_path::same_path(created, parent, platform)
                    )
            });
    if !parent_exists {
        return false;
    }
    let words = literal_words(&view.execution(change.execution).argv);
    let mut words = words.iter().flatten();
    let copies = words
        .next()
        .is_some_and(|program| matches!(program.rsplit('/').next(), Some("cp" | "mv")));
    let (mut keeps, mut updates) = (false, false);
    for word in words.take_while(|word| *word != "--") {
        match word.strip_prefix("--") {
            Some(long) => {
                keeps |= long == "no-clobber";
                updates |= long == "update" || long.starts_with("update=");
            }
            // A cluster of single-letter flags; `-t` and `-S` take the rest
            // of their word as a value.
            None if word.starts_with('-') => {
                let flags = word[1..].split(['t', 'S']).next().unwrap_or_default();
                keeps |= flags.contains('n');
                updates |= flags.contains('u');
            }
            None => {}
        }
    }
    if !copies || !(keeps || updates) {
        return true;
    }
    observed == Some(PathKind::Missing) && !(updates && platform == nah_proto::ctx::Platform::Macos)
}
