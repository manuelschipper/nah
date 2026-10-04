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
/// Ends the key of the link-following listing asked beside a path's
/// no-follow one.
pub(crate) const FOLLOWED_KEY_SUFFIX: &str = "-followed";

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
            entry.1 |= opens_through_links(plan, effect, resource);
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
                && let Some(parent) = parent_directory(path)
            {
                paths.entry(parent.to_owned()).or_default();
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
    for (index, (requested, (inspect_descendants, follow_links, moved))) in
        paths.into_iter().enumerate()
    {
        let follows = inspect_descendants && follow_links;
        let key = format!("effinterp-path-{index:04}");
        // A move takes a link as a link, so a path any move names is listed
        // without following links, and a reader beside the move cannot
        // change what the move is shown to take. The effects that open what
        // the links lead to read a second listing of that path, which
        // follows them (`PlanView::observed_path_for`).
        if follows && moved {
            queries.push(ObservationQuery::Path {
                key: format!("{key}{FOLLOWED_KEY_SUFFIX}"),
                requested: requested.clone(),
                cwd_key: CWD_KEY.into(),
                inspect_descendants,
                symlink_traversal: SymlinkTraversal::All,
            });
        }
        queries.push(ObservationQuery::Path {
            key,
            requested,
            cwd_key: CWD_KEY.into(),
            inspect_descendants,
            // A read through links takes what they name, so the listing
            // below its root follows them too.
            symlink_traversal: if follows && !moved {
                SymlinkTraversal::All
            } else {
                SymlinkTraversal::None
            },
        });
    }
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

/// Whether an effect opens what the links below `resource` lead to, so it
/// reads the listing that follows them. The read a move states for what it
/// moves takes a link as the move does.
pub(crate) fn opens_through_links(
    plan: &Plan,
    effect: &effinterp_proto::Effect,
    resource: &ResourceExpr,
) -> bool {
    reads_through_links(effect) && !stated_by_move(plan, effect)
        || writes_through_links(effect, resource)
}

/// Whether a move states `effect` for what it moves: the same execution
/// states a `filesystem.move` of the same resource. A move's read is its copy
/// half and its delete the removal of what it moved away, so either takes a
/// link, and a directory's contents, as the move does.
pub(crate) fn stated_by_move(plan: &Plan, effect: &effinterp_proto::Effect) -> bool {
    plan.effects.iter().any(|moved| {
        moved.operation.as_str() == "filesystem.move"
            && moved.execution == effect.execution
            && moved.resource == effect.resource
    })
}

/// The parent directory a path's spelling names, under either separator;
/// the root for an entry directly below it. `None` for a path with no
/// separator. Nothing is resolved.
pub(crate) fn parent_directory(path: &str) -> Option<&str> {
    path.rfind(['/', '\\'])
        .map(|separator| &path[..separator.max(1)])
}

/// Whether an effect changes what the links its glob matches lead to. A
/// write opens the file each matched name points at, and a stated permission
/// or ownership change (`chmod 000 keys*`) is applied to it, as either is
/// for the named link, unless its model says it leaves links unfollowed.
pub(crate) fn writes_through_links(
    effect: &effinterp_proto::Effect,
    resource: &ResourceExpr,
) -> bool {
    (effect.operation.as_str() == "filesystem.write"
        || crate::annotate::access_control_change(effect))
        && matches!(resource, ResourceExpr::Pattern { .. })
        && effect.attributes.get("follow_links") != Some(&AttrValue::Bool(false))
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
/// that follows it. A pattern's bound is the directory holding its first
/// wildcard component, with the escapes of the filesystem glob grammar
/// decoded, so `/w/proj\[1]/**/*` is bounded by `/w/proj[1]` and followed by
/// `/**/*`, and `/w/source/serv*` by `/w/source`, followed by `/serv*`.
pub(crate) fn observation_bound(resource: &ResourceExpr) -> Option<(Cow<'_, str>, &str)> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some((Cow::Borrowed(path), "")),
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
        } => pattern_observation_bound(glob),
        _ => subtree_root(resource).map(|root| (Cow::Borrowed(root), "")),
    }
}

fn pattern_observation_bound(glob: &str) -> Option<(Cow<'_, str>, &str)> {
    // Each literal character before the first unescaped wildcard, where
    // `nah_proto::action::pattern_bound` stops, with its end in `glob`.
    let bytes = glob.as_bytes();
    let mut literal = Vec::<(char, usize)>::new();
    let mut wildcard = false;
    let mut chars = glob.char_indices();
    while let Some((index, character)) = chars.next() {
        if matches!(character, '*' | '?' | '[' | '{')
            || matches!(character, '@' | '+' | '!') && bytes.get(index + 1) == Some(&b'(')
        {
            wildcard = true;
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
    // A wildcard that starts inside a component (`source/serv*`, `HOME/.*`)
    // selects among the entries of the directory holding that component. The
    // literal start of the name belongs to the selection, not to the observed
    // directory identity: keep it in the pattern suffix.
    if wildcard
        && let Some(separator) = literal.iter().rposition(|(character, _)| *character == '/')
    {
        kept = (separator + 1).max(1);
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

/// What a filesystem selection's producer says it leaves out: the narrowing of
/// a pattern, or of the descendants of a root-wide selection.
pub(crate) fn selection_narrowing(
    resource: &ResourceExpr,
) -> Option<&effinterp_proto::FsNarrowing> {
    match resource {
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { narrowing, .. },
        } => Some(narrowing),
        ResourceExpr::Union { alternatives } if subtree_root(resource).is_some() => {
            alternatives.iter().find_map(selection_narrowing)
        }
        _ => None,
    }
}

/// The glob a subset chosen by the names it spells is read as, or `None` for
/// any other selection. Such a subset reaches what lies under those names
/// and is not every entry below its bound: read by its literal prefix,
/// `HOME/**/node_modules/**` would take the home and every protected path in
/// it. The names are read directly below the bound, `HOME/**/.ssh/**` as
/// `HOME/.ssh/**`, where the protected paths a path test spells from the
/// start path lie.
pub(crate) fn named_subset_reading(resource: &ResourceExpr, glob: &str) -> Option<String> {
    selection_narrowing(resource)
        .is_some_and(|narrowing| narrowing.subset == effinterp_proto::FsSubset::Named)
        .then(|| glob.replace("/**/", "/"))
}

/// Whether an effect removes only the entries it is passed: a removal that
/// does not recurse (`rm`, `unlink`, `rmdir`) cannot take a directory that
/// holds any entry, so a directory's contents stay where they are. The
/// removal a move states for what it moved away carries them with it.
pub(crate) fn removes_entries_only(plan: &Plan, effect: &effinterp_proto::Effect) -> bool {
    effect.operation.as_str() == "filesystem.delete"
        && effect.attributes.get("recursive") != Some(&AttrValue::Bool(true))
        && !stated_by_move(plan, effect)
}

/// Whether an effect on a root-wide selection takes the root's whole tree.
/// A removal of only the entries it is passed, or a write, which changes
/// only a regular file's contents, takes none of the tree's files when its
/// selection leaves regular files out (`find . -type d -exec rm -f {} +`,
/// `find . -type d -exec truncate -s 0 {} +`).
pub(crate) fn subtree_reached_whole(plan: &Plan, effect: &effinterp_proto::Effect) -> bool {
    subtree_root(&effect.resource).is_some()
        && !((removes_entries_only(plan, effect)
            || effect.operation.as_str() == "filesystem.write")
            && selection_narrowing(&effect.resource).is_some_and(|narrowing| {
                !narrowing.kinds.is_empty()
                    && !narrowing
                        .kinds
                        .contains(&effinterp_proto::FsEntryKind::File)
            }))
}

/// Preserve the exact set of a root and any descendant without treating an
/// arbitrary union as one path. The root remains a selection bound. A producer
/// may narrow the descendants (`find DIR -type d`): the selection still works
/// through the whole tree, so it stays a subtree, and `selection_narrowing`
/// says what it leaves out.
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
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
            },
        )
        | (
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
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
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: glob.into(),
                    narrowing: Default::default(),
                },
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
        // A producer that narrows the descendants still works through the tree.
        let narrowed = ResourceExpr::Union {
            alternatives: vec![
                root.clone(),
                ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath {
                        glob: r"/tmp/build\[1\]/**".into(),
                        narrowing: effinterp_proto::FsNarrowing {
                            kinds: vec![effinterp_proto::FsEntryKind::Directory],
                            ..Default::default()
                        },
                    },
                },
            ],
        };
        assert_eq!(subtree_root(&narrowed), Some("/tmp/build[1]"));
        assert_eq!(
            selection_narrowing(&narrowed).map(|narrowing| narrowing.kinds.as_slice()),
            Some([effinterp_proto::FsEntryKind::Directory].as_slice())
        );
        assert_eq!(
            subtree_root(&ResourceExpr::Union {
                alternatives: vec![root.clone(), root]
            }),
            None
        );
    }
}
