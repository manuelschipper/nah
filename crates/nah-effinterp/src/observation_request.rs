// Derives observation queries for effect plans.

use std::borrow::Cow;
use std::collections::BTreeMap;

use effinterp_proto::{AttrValue, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{ObservationQuery, ObservationRequest, SymlinkTraversal};
use nah_proto::tool::CallSite;

pub(crate) const CWD_KEY: &str = "effinterp-cwd";
const ROOTS_KEY: &str = "effinterp-roots";
const GUARDS_KEY: &str = "effinterp-project-guards";
const SEARCH_PATH_KEY: &str = "effinterp-search-path";

/// Request the stable host facts needed to annotate every effect in a plan.
pub fn plan_observation_request(plan: &Plan, call_site: &CallSite) -> ObservationRequest {
    // Each path's answer: whether it lists descendants, whether an effect
    // reads through the links below the path, and whether a move names it.
    let mut paths = BTreeMap::<String, (bool, bool, bool)>::new();
    for effect in &plan.effects {
        if !effect.realm.is_host() || effect.operation.domain() != "filesystem" {
            continue;
        }
        let resources = finite_members(&effect.resource)
            .unwrap_or_else(|| std::slice::from_ref(&effect.resource));
        for resource in resources {
            let Some((path, _)) = observation_bound(resource) else {
                continue;
            };
            let path = path.as_ref();
            // Numeric descriptor names refer to this process's transient table,
            // not host paths whose initial state can be observed safely.
            if process_descriptor_path(path) {
                continue;
            }
            let recursive = effect.attributes.get("recursive") == Some(&AttrValue::Bool(true))
                || subtree_root(resource).is_some();
            // A glob selects entries of the directory that bounds it, and a
            // move takes everything under what it names, so the entries are
            // what those selections are made of. Without them the observed
            // directory answers only for itself.
            let inspect_descendants = recursive
                || matches!(resource, ResourceExpr::Pattern { .. })
                || effect.operation.as_str() == "filesystem.move";
            // A followed target is already known from the entry's answer; do not
            // synthesize or independently observe a canonical-target row.
            if !recursive
                && effect_path_observation(plan, effect)
                    .is_some_and(|(original, _)| original != path)
            {
                continue;
            }
            let entry = paths.entry(path.to_owned()).or_default();
            entry.0 |= inspect_descendants;
            entry.1 |= reads_through_links(effect);
            entry.2 |= effect.operation.as_str() == "filesystem.move";
        }
    }
    // An executed path whose arguments would change nah's own state is
    // identified through its host observation (`annotate::executed_identity`).
    // One the engine found no path for is identified by its PATH search, which
    // needs the PATH the call inherits. That search reads a POSIX PATH, so a
    // Windows call (its cwd is drive-anchored) is not asked. A command
    // delivered to another terminal runs on that session's PATH, which this
    // call's does not describe; the engine reads the session's then-unknown
    // PATH as an unresolvable search that would hide what the delivered
    // command runs.
    let delivers_to_terminal = plan.effects.iter().any(|effect| {
        effect.attributes.get("delivery") == Some(&AttrValue::String("terminal".into()))
    });
    let mut search_path = false;
    let mut identifies_path = false;
    for effect in &plan.effects {
        match nah_control_executable(plan, effect) {
            Some(Some(path)) => {
                paths.entry(path.to_owned()).or_default();
                identifies_path = true;
            }
            Some(None) => search_path = true,
            None => {}
        }
    }
    // A copy puts Nah on such a path only when it lands, which takes an
    // existing directory to land in (`annotate::transfer_lands`).
    if identifies_path {
        for effect in &plan.effects {
            if effect.realm.is_host()
                && matches!(
                    effect.operation.as_str(),
                    "filesystem.write" | "filesystem.create"
                )
                && let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } = &effect.resource
                && let Some(separator) = path.rfind(['/', '\\'])
            {
                paths
                    .entry(path[..separator.max(1)].to_owned())
                    .or_default();
            }
        }
    }
    let mut queries = vec![
        ObservationQuery::Cwd {
            key: CWD_KEY.into(),
            requested: call_site.requested_cwd().clone(),
        },
        ObservationQuery::Roots {
            key: ROOTS_KEY.into(),
            cwd_key: CWD_KEY.into(),
        },
        ObservationQuery::ProjectGuards {
            key: GUARDS_KEY.into(),
            roots_key: ROOTS_KEY.into(),
        },
    ];
    if search_path && !delivers_to_terminal && call_site.requested_cwd().as_str().starts_with('/') {
        queries.push(ObservationQuery::Env {
            key: SEARCH_PATH_KEY.into(),
            name: "PATH".into(),
        });
    }
    queries.extend(paths.into_iter().enumerate().map(
        |(index, (requested, (inspect_descendants, follow_links, moved)))| ObservationQuery::Path {
            key: format!("effinterp-path-{index:04}"),
            requested,
            cwd_key: CWD_KEY.into(),
            inspect_descendants,
            // A read through links takes what they name, so the listing
            // below its root follows them too. A move takes a link as a
            // link, and the one listing answers it as well: a path any move
            // names is listed without following links, so a reader beside
            // the move cannot change what the move is shown to take.
            symlink_traversal: if inspect_descendants && follow_links && !moved {
                SymlinkTraversal::All
            } else {
                SymlinkTraversal::None
            },
        },
    ));
    ObservationRequest::new(SchemaVersion::V1, "effinterp-v1", queries)
        .expect("effinterp observation query graph is valid")
}

/// Whether an effect opens what the links it meets lead to: its model says it
/// follows links, or, when the model says nothing, it is a content read that
/// does not recurse, which opens each entry it names. Keep this identical to
/// `reads_through_links` in effinterp-matcher's `evaluate.rs`.
pub(crate) fn reads_through_links(effect: &effinterp_proto::Effect) -> bool {
    match effect.attributes.get("follow_links") {
        Some(AttrValue::Bool(follows)) => *follows,
        _ => {
            effect.operation.as_str() == "filesystem.read"
                && effect.attributes.get("access_purpose")
                    == Some(&AttrValue::String("program_input".into()))
                && effect.attributes.get("recursive") != Some(&AttrValue::Bool(true))
        }
    }
}

/// The executed path of a host launch whose literal arguments are a nah
/// control command (`annotate::nah_control`), `Some(None)` when the engine
/// names no path for it.
fn nah_control_executable<'a>(
    plan: &Plan,
    effect: &'a effinterp_proto::Effect,
) -> Option<Option<&'a str>> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::Process { path, argv, .. },
    } = &effect.resource
    else {
        return None;
    };
    let argv = if argv.is_empty() {
        plan.execution_graph
            .nodes
            .get(effect.execution.0 as usize)
            .map(|node| node.argv.as_slice())
            .unwrap_or_default()
    } else {
        argv
    };
    (effect.realm.is_host()
        && effect.operation.as_str() == "process.exec"
        && argv
            .iter()
            .all(|argument| matches!(argument, ResourceExpr::Literal { .. }))
        && crate::annotate::nah_control(plan, effect, argv).is_some())
    .then_some(path.as_deref())
}

fn process_descriptor_path(path: &str) -> bool {
    path.strip_prefix("/dev/fd/")
        .or_else(|| path.strip_prefix("/proc/self/fd/"))
        .is_some_and(|descriptor| {
            !descriptor.is_empty() && descriptor.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// The observed path that bounds a resource's selection, and the glob text
/// that follows it. A pattern's bound is its literal prefix with the escapes of
/// the filesystem glob grammar decoded, so `/w/proj\[1]/**/*` is bounded by
/// `/w/proj[1]` and followed by `/**/*`.
pub(crate) fn observation_bound(resource: &ResourceExpr) -> Option<(Cow<'_, str>, &str)> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some((Cow::Borrowed(path), "")),
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } => pattern_observation_bound(glob),
        _ => subtree_root(resource).map(|root| (Cow::Borrowed(root), "")),
    }
}

fn pattern_observation_bound(glob: &str) -> Option<(Cow<'_, str>, &str)> {
    // Each literal character before the first unescaped wildcard, where
    // `nah_proto::action::pattern_bound` stops, with its end in `glob`.
    let bytes = glob.as_bytes();
    let mut literal = Vec::<(char, usize)>::new();
    let mut chars = glob.char_indices();
    while let Some((index, character)) = chars.next() {
        if matches!(character, '*' | '?' | '[' | '{')
            || matches!(character, '@' | '+' | '!') && bytes.get(index + 1) == Some(&b'(')
        {
            break;
        }
        if character == '\\' {
            let Some((escaped, next)) = chars.next() else {
                break;
            };
            literal.push((next, escaped + next.len_utf8()));
            continue;
        }
        literal.push((character, index + character.len_utf8()));
    }
    let spelled = |literal: &[(char, usize)]| literal.iter().map(|(c, _)| *c).collect::<String>();
    let mut kept = literal.len();
    // The dot in .* belongs to the selection, not to the observed directory
    // identity. Keep it in the pattern suffix.
    if spelled(&literal[..kept]).ends_with("/.") {
        kept = (kept - 2).max(1);
    }
    // Observe the directory that bounds the selection, not a trailing
    // separator introduced by the pattern (for example, HOME/*). A root, `/`
    // or a drive's `C:/`, keeps its separator.
    let bound = spelled(&literal[..kept]);
    let drive_root =
        bound.len() == 3 && bound.as_bytes()[0].is_ascii_alphabetic() && &bound[1..] == ":/";
    if bound != "/" && !drive_root {
        while kept > 0 && literal[kept - 1].0 == '/' {
            kept -= 1;
        }
    }
    let end = literal[..kept].last()?.1;
    let bound = spelled(&literal[..kept]);
    let bound = if glob[..end] == bound {
        Cow::Borrowed(&glob[..end])
    } else {
        Cow::Owned(bound)
    };
    Some((bound, &glob[end..]))
}

/// A finite path union retains each member without choosing an alternative.
pub(crate) fn finite_members(resource: &ResourceExpr) -> Option<&[ResourceExpr]> {
    let ResourceExpr::Union { alternatives } = resource else {
        return None;
    };
    (!alternatives.is_empty()
        && alternatives.iter().all(|member| {
            matches!(
                member,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { .. }
                }
            )
        }))
    .then_some(alternatives)
}

/// Preserve the exact set of a root and any descendant without treating an
/// arbitrary union as one path. The root remains a selection bound.
pub(crate) fn subtree_root(resource: &ResourceExpr) -> Option<&str> {
    let ResourceExpr::Union { alternatives } = resource else {
        return None;
    };
    let [first, second] = alternatives.as_slice() else {
        return None;
    };
    let (path, glob) = match (first, second) {
        (
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            },
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            },
        )
        | (
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            },
        ) => (path, glob),
        _ => return None,
    };
    if !path.starts_with('/') {
        return None;
    }
    let mut expected = String::new();
    for character in path.trim_end_matches('/').chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            expected.push('\\');
        }
        expected.push(character);
    }
    expected.push_str("/**");
    (glob == &expected).then_some(path)
}

/// The original spelling stays attached to the effect even after the engine
/// has replaced its resource with a followed identity.
pub(crate) fn effect_path_observation<'a>(
    plan: &'a Plan,
    effect: &effinterp_proto::Effect,
) -> Option<(&'a str, &'a effinterp_proto::ObservationOutcome)> {
    effect.provenance.iter().rev().find_map(|reference| {
        match &plan.provenance.get(reference.0 as usize)?.kind {
            effinterp_proto::ProvenanceKind::HostObservation {
                query: effinterp_proto::ObservationQuery::Path { path },
                outcome,
            } => Some((path.as_str(), outcome)),
            _ => None,
        }
    })
}

pub(crate) fn recorded_path(
    fact: &effinterp_proto::PathFact,
    platform: nah_proto::ctx::Platform,
) -> Option<nah_proto::observation::PathObservation> {
    use nah_proto::ctx::AbsolutePath;
    use nah_proto::observation::{PathKind, PathObservation};
    let kind = |kind| match kind {
        effinterp_proto::PathKind::Missing => PathKind::Missing,
        effinterp_proto::PathKind::File => PathKind::File,
        effinterp_proto::PathKind::Directory => PathKind::Directory,
        effinterp_proto::PathKind::Symlink => PathKind::Symlink,
        effinterp_proto::PathKind::Fifo => PathKind::Fifo,
        effinterp_proto::PathKind::Other => PathKind::Other,
    };
    let target = fact.followed.known();
    let mut value = PathObservation::new(
        AbsolutePath::new(platform, &fact.entry).ok()?,
        target
            .map(|target| AbsolutePath::new(platform, &target.path))
            .transpose()
            .ok()?,
        kind(fact.kind),
    );
    if let Some(target_kind) = target.and_then(|target| target.kind.known())
        && fact.kind == effinterp_proto::PathKind::Symlink
    {
        value = value.with_target_kind(kind(*target_kind));
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_complete_root_and_descendant_unions_share_an_observation() {
        let root = ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/tmp/build[1]".into(),
            },
        };
        for (glob, expected) in [
            (r"/tmp/build\[1\]/**", Some("/tmp/build[1]")),
            ("/tmp/build[1]/**", None),
            (r"/tmp/build\[1\]/*", None),
            ("/other/**", None),
        ] {
            let pattern = ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob: glob.into() },
            };
            for alternatives in [
                vec![root.clone(), pattern.clone()],
                vec![pattern, root.clone()],
            ] {
                assert_eq!(
                    subtree_root(&ResourceExpr::Union { alternatives }),
                    expected
                );
            }
        }
        assert_eq!(
            subtree_root(&ResourceExpr::Union {
                alternatives: vec![root.clone(), root]
            }),
            None
        );
    }
}
