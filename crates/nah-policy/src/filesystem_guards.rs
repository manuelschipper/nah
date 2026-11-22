//! Declarative definitions for the filesystem guards and the host path catalogs
//! their clauses name.
//!
//! Each clause is a matcher query over the engine's own effect: operation,
//! typed resource, the attributes the guard decides on, realm, and the request
//! or execution assurance the guard has always required. Beside it, a
//! [`HostRule`] states what the engine cannot know: which host paths Nah
//! protects (home, project roots, system trees, identity and startup files,
//! raw storage), read from the path labels the bridge attaches to what the
//! effect reaches, and the filesystem family's eligibility. The catalogs stay
//! pure policy relations; they do no I/O and never dispatch on a guard name.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_matcher::{
    Assertion, AttributePredicate, OperationMatch, Query, RealmPredicate, ResourcePredicate,
    ResourceVariant, SelectionShape, Selector, TextPredicate,
};
use effinterp_proto::{AttrValue, ExecutionAssurance, RequestAssurance};
use nah_proto::action::pattern_bound;
use nah_proto::ctx::{Guard, GuardLevel};
use nah_proto::effects::{
    Domain, EffectResource, Knowledge, Reach, ResourceDetails, ResourceIdentity, ResourceKind,
    Selection,
};
use nah_proto::guard_host::{GuardHostFacts, LinkedReading};
use nah_proto::labels::raw_storage::{is_raw_storage_or_sysrq, pattern_selects_raw_storage};
use nah_proto::labels::system_tree::{pattern_selects_system_tree, selects_root_or_system_tree};
use nah_proto::labels::temporary_root::{
    lies_under_temporary_root, pattern_reaches_temporary_root,
};
use nah_proto::labels::{HostIntegrityClass, PathScope};

use crate::guard_evaluation::QueryQualifier;
use crate::registry::{GuardClause, GuardDefinition};
use crate::shared_queries::{
    bool_attr, present_attr, resource_family, resource_selection, resource_variant, string_attr,
    string_one_of,
};

/// Nah's half of a filesystem guard clause, checked after its query matches.
///
/// It always carries the filesystem family's eligibility for an effect in the
/// filesystem domain: the owning execution's filesystem model is trusted (a
/// named interim until the engine certifies model identity: a model selected
/// by basename is trusted only for an executable in a system bin directory).
/// A clause with a `reach` rule also requires the effect to name an
/// identified host target rather than an unresolved or unbound expression; a
/// clause without one is decided by its query whatever the target.
pub struct HostRule {
    /// The effect's condition must not be proven impossible within the
    /// invocation. The rule is broader than the success path: a fallback
    /// after `||`, a branch body, or a condition too large to decide still
    /// reaches the path.
    /// The physical reach Nah summarizes for a Git discard carries no
    /// condition, so its clauses leave this off.
    pub feasible_condition: bool,
    pub reach: Option<ReachRule>,
}

/// A catalog requirement on one path the matched effect reaches.
pub struct ReachRule {
    pub endpoint: ReachEndpoint,
    /// The effect must select its path recursively: a subtree selection or an
    /// explicit recursive request.
    pub recursive: bool,
    pub path: PathRule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReachEndpoint {
    /// What the effect selects, each member of a finite selection, or a path a
    /// Git discard selection physically replaces or removes.
    Selected,
    /// Where a move's content-preserving transfer lands, when the engine
    /// certifies exactly one destination.
    MoveDestination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathRule {
    /// The filesystem root or a Linux, macOS or Windows system tree, including
    /// a pattern whose literal bound still reaches one.
    SystemTree,
    /// The `/*` pattern: every entry of the root.
    EveryRootEntry,
    /// The home root, or a standard personal folder directly under it.
    Home,
    /// An observed project root, or a pattern that selects every entry of one.
    ProjectRoot,
    /// Home, system or outside any project, except below a temporary or cache
    /// root or, for a named path, inside the project of a call no Git
    /// repository contains. A pattern below a temporary root is exempt only
    /// when it cannot select a root or a folder above one, by its spelling
    /// or as the observed links on its way read it, and a pattern in a
    /// non-Git project may select a repository, so it stays outside.
    OutsideWorkspace,
    /// Named interim: raw storage and the kernel crash trigger recognized by
    /// device spelling. The engine types a whole-device destruction as a block
    /// device, but states no raw-storage fact for an ordinary write to a device
    /// path, so the path spelling still decides.
    RawStorageSpelling,
    /// A persistent systemd system or global user unit directory, by path
    /// spelling: a unit write there changes what starts at boot or login
    /// whether or not the path was observed.
    SystemdUnitDirectory,
    HostIntegrity(HostIntegrityClass),
}

/// One path an effect reaches, as the bridge labeled it.
pub struct ReachedPath<'a> {
    pub resource: &'a EffectResource,
    /// The effect removes or relocates the entry itself, so a symlink is
    /// selected as the link rather than its target.
    pub entry: bool,
    pub recursive: bool,
    /// The path of a typed block device, which carries no path labels.
    pub device: Option<&'a str>,
    /// A recursive delete's pattern as the observed links on its way read it
    /// (`ReachedHostPath::linked_readings`).
    pub linked_readings: Option<&'a [LinkedReading]>,
}

impl ReachRule {
    pub fn holds(&self, reached: &ReachedPath<'_>, host: &dyn GuardHostFacts) -> bool {
        (!self.recursive || reached.recursive) && self.path.holds(reached, host)
    }
}

impl PathRule {
    fn holds(self, reached: &ReachedPath<'_>, host: &dyn GuardHostFacts) -> bool {
        let labels = reached.resource.labels.as_ref();
        let target = reached.device.or_else(|| {
            let labels = labels?;
            let endpoint = if reached.entry && labels.is_symlink == Knowledge::Known(true) {
                &labels.lexical
            } else {
                &labels.canonical
            };
            match endpoint {
                Knowledge::Known(path) => Some(path.as_str()),
                Knowledge::Unknown => match &labels.lexical {
                    Knowledge::Known(path) => Some(path.as_str()),
                    Knowledge::Unknown => None,
                },
            }
        });
        let pattern = matches!(reached.resource.selection, Selection::Pattern { .. });
        let unresolved =
            matches!(reached.resource.selection, Selection::Unknown) && target.is_none();
        // An unobserved path carries no labels, but the effect's own spelling
        // still names it.
        let spelling = match &reached.resource.identity.details {
            Knowledge::Known(ResourceDetails::Path {
                lexical: Knowledge::Known(path),
            }) => Some(path.as_str()),
            _ => None,
        };
        match self {
            Self::SystemTree => {
                let pattern_spelling = match &reached.resource.selection {
                    Selection::Pattern { pattern, .. } => Some(pattern.as_str()),
                    _ => None,
                };
                unresolved
                    || labels.is_some_and(|labels| labels.selects_root == Reach::Yes)
                    || target.or(spelling).or(pattern_spelling).is_some_and(|target| {
                        selects_root_or_system_tree(target)
                            || pattern && pattern_selects_system_tree(target)
                    })
            }
            Self::EveryRootEntry => pattern && target == Some("/*"),
            Self::Home => {
                unresolved
                    || labels.is_some_and(|labels| {
                        labels.selects_home == Reach::Yes
                            || labels.selects_home_folder == Reach::Yes
                    })
            }
            Self::ProjectRoot => labels.is_some_and(|labels| {
                labels.selects_project == Reach::Yes
                    || match &labels.scope {
                        Knowledge::Known(PathScope::Project { root }) => {
                            pattern
                                && target.is_some_and(|target| {
                                    pattern_selects_project_root(target, root.as_str())
                                })
                        }
                        _ => false,
                    }
            }),
            Self::OutsideWorkspace => {
                labels.is_some_and(|labels| {
                    matches!(
                        labels.scope,
                        Knowledge::Known(
                            PathScope::Home | PathScope::System | PathScope::OutsideProject
                        )
                    )
                }) && target.is_some_and(|target| {
                    let (home, roots) = (host.home().as_str(), host.observed_temporary_roots());
                    let platform = host.platform();
                    // A pattern reaches through the links on its way what
                    // its spelling does not name: a temporary root itself,
                    // or a folder outside temporary space and the project.
                    // A link the walk never reached may lead to either.
                    let leaves_temporary_space = || match reached.linked_readings {
                        None => true,
                        Some(readings) => {
                            pattern_reaches_temporary_root(target, home, &roots, platform)
                                || readings.iter().any(|reading| {
                                    pattern_reaches_temporary_root(
                                        &reading.pattern,
                                        home,
                                        &roots,
                                        platform,
                                    ) || !matches!(reading.scope, PathScope::Project { .. })
                                        && !lies_under_temporary_root(
                                            &reading.pattern,
                                            home,
                                            &roots,
                                            platform,
                                        )
                                })
                        }
                    };
                    !(lies_under_temporary_root(target, home, &roots, platform)
                        && !(pattern && leaves_temporary_space()))
                        && (pattern || !host.lies_in_non_git_project(target))
                })
            }
            Self::RawStorageSpelling => {
                // A Windows device-namespace path is never admitted as a
                // policy path, so it has no labels and no lexical spelling;
                // the name the engine gave the host path still spells it.
                let name = match &reached.resource.identity {
                    ResourceIdentity {
                        kind: ResourceKind::HostPath,
                        name: Knowledge::Known(name),
                        ..
                    } => Some(name.as_str()),
                    _ => None,
                };
                target.or(name).is_some_and(|target| {
                    is_raw_storage_or_sysrq(target)
                        || pattern && pattern_selects_raw_storage(pattern_bound(target))
                })
            }
            Self::SystemdUnitDirectory => {
                target.or(spelling).is_some_and(|target| {
                    SYSTEMD_UNIT_DIRECTORIES.iter().any(|directory| {
                        target
                            .strip_prefix(directory)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                    })
                })
            }
            Self::HostIntegrity(class) => labels.is_some_and(|labels| {
                matches!(&labels.host_integrity, Knowledge::Known(classes) if classes.contains(&class))
            }),
        }
    }
}

/// The rules whose reason names every effect they matched in the call
/// ([`effects_reason`]), because one call can delete what it also only
/// changes the permissions of, and a reason built from one effect would hide
/// the other.
pub(crate) fn describes_every_effect(rule: &str) -> bool {
    matches!(
        rule,
        "work/files-delete"
            | "machine/system-files-modify"
            | "machine/outside-workspace-delete"
            | "machine/home-folder-modify"
    )
}

/// What a matched filesystem effect does to its target, most severe first:
/// deleted and overwritten files are gone, old permissions can be restored
/// entry by entry, and a move can be moved back.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Change {
    Delete,
    Overwrite,
    Permissions,
    Move,
}

/// The reason a rule [`describes_every_effect`] gives for the plan effects
/// at `effects`, every effect its parts matched in the call: each kind of
/// change, most severe first, with what it reaches, then how to recover from
/// the most severe. Only the fixed folder names are spelled: a reason is
/// logged, and the audit log never holds paths.
pub(crate) fn effects_reason(
    rule: &str,
    plan: &effinterp_proto::Plan,
    host: &dyn GuardHostFacts,
    effects: &[usize],
) -> String {
    let mut changes = effects
        .iter()
        .map(|&effect| {
            let change = match plan.effects[effect].operation.as_str() {
                "filesystem.delete" => Change::Delete,
                "filesystem.metadata" => Change::Permissions,
                "filesystem.move" => Change::Move,
                _ => Change::Overwrite,
            };
            let target = match (rule, change) {
                ("machine/outside-workspace-delete", _)
                    if unresolved_tree_delete(plan, host, effect) =>
                {
                    match unresolved_operand(plan, effect) {
                        Some(spelled) => format!("{UNRESOLVED_TARGET} ({spelled})"),
                        None => UNRESOLVED_TARGET.to_owned(),
                    }
                }
                ("work/files-delete", _) if selects_project(host, effect) => {
                    "the project folder".to_owned()
                }
                ("work/files-delete", _) => "files in the project".to_owned(),
                ("machine/system-files-modify", Change::Move) => {
                    "the entries of the filesystem root".to_owned()
                }
                ("machine/system-files-modify", _) => {
                    "the filesystem root or a system folder".to_owned()
                }
                _ => home_target(host, effect)
                    .unwrap_or_else(|| "a folder outside the project".to_owned()),
            };
            (change, target)
        })
        .collect::<Vec<_>>();
    changes.sort();
    changes.dedup();
    let clauses = changes
        .chunk_by(|a, b| a.0 == b.0)
        .map(|group| {
            let targets = group
                .iter()
                .map(|(_, target)| target.as_str())
                .collect::<Vec<_>>()
                .join(" and ");
            match group[0].0 {
                Change::Delete => format!("delete {targets}"),
                Change::Overwrite => format!("overwrite files in {targets}"),
                Change::Permissions => {
                    format!("change the permissions or owner of everything in {targets}")
                }
                Change::Move => format!("move away {targets}"),
            }
        })
        .collect::<Vec<_>>();
    let action = match clauses.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => unreachable!("a matched part names at least one effect"),
    };
    let system = rule == "machine/system-files-modify";
    let recovery = match changes[0].0 {
        Change::Delete | Change::Overwrite => match rule {
            "work/files-delete" if changes[0].1 == "files in the project" => {
                "Only what Git has committed can be brought back; uncommitted changes and other files there are lost"
            }
            "work/files-delete" => "Whatever is not pushed elsewhere cannot be recovered",
            _ if system => "It can break this computer and cannot be undone",
            _ if changes[0].1.starts_with(UNRESOLVED_TARGET) => {
                "Nah cannot tell what would be lost or save it first; naming the path in the command lets Nah judge the delete, and save what it would lose"
            }
            _ => "nah keeps no copy, so it cannot be undone",
        },
        Change::Permissions => match rule {
            "work/files-delete" => {
                "No file is deleted, but you and your tools may be locked out until the old settings are restored entry by entry"
            }
            _ if system => {
                "No file is deleted, but it can break this computer until the old settings are restored entry by entry"
            }
            _ => {
                "No file is deleted, but you may be locked out until the old settings are restored entry by entry"
            }
        },
        Change::Move if system => "Moving them back undoes it, but this computer breaks until then",
        Change::Move => "Moving it back undoes it, but programs that use it break until then",
    };
    format!("this would {action}. {recovery}")
}

/// What a delete whose target the engine could not resolve takes, in its
/// reason ([`effects_reason`]), and the part's own reason.
const UNRESOLVED_TARGET: &str = "a folder whose path Nah could not work out";
const UNRESOLVED_DELETE_REASON: &str = "this would delete a folder whose path Nah could not work out. Nah cannot tell what would be lost or save it first; naming the path in the command lets Nah judge the delete, and save what it would lose";

/// Whether the plan effect at `effect` deletes recursively, or removes a whole
/// tree, a target the engine left unresolved: a value the frontend could not
/// name, such as another program's output, a line read from input or an
/// argument the call does not supply, alone or joined with known parts. A
/// variable observed unset is no such value: it expands to nothing. A delete
/// of tracked files only (`git rm`) is left out: Git takes them from its own
/// work tree alone, which `work/files-delete` judges and saves whole.
pub(crate) fn unresolved_tree_delete(
    plan: &effinterp_proto::Plan,
    host: &dyn GuardHostFacts,
    effect: usize,
) -> bool {
    fn unresolved(expr: &effinterp_proto::ResourceExpr) -> bool {
        use effinterp_proto::ResourceExpr;
        match expr {
            ResourceExpr::Unresolved { .. } => true,
            ResourceExpr::Join { parts } => parts.iter().any(unresolved),
            ResourceExpr::Union { alternatives } => alternatives.iter().any(unresolved),
            ResourceExpr::Property { base, .. } => unresolved(base),
            _ => false,
        }
    }
    let effect_ref = &plan.effects[effect];
    effect_ref.operation.as_str() == "filesystem.delete"
        && effect_ref.attributes.get("tracked_only") != Some(&AttrValue::Bool(true))
        && unresolved(&effect_ref.resource)
        && host.selects_recursively(effect)
}

/// Whether the target of the delete at `effect` is the output of another
/// program the call launches: a value path in the causal graph leads back
/// from the delete to the stdout or return value of a launched execution, as
/// for `rm -rf "$(cat cfg)"` or `subprocess.check_output`, or the deleting
/// command is one `xargs`-style tool builds from the stdout of another
/// program it reads. A line read from the call's own input, or an argument
/// the program is never given, is no other program's output.
pub(crate) fn target_from_program_output(plan: &effinterp_proto::Plan, effect: usize) -> bool {
    use effinterp_proto::{CausalReason, ExecutionEdgeKind, ExecutionStream, OccurrenceKind, Port};
    let deleted = &plan.effects[effect];
    let graph = &plan.execution_graph;
    let launched = |execution: effinterp_proto::ExecutionNodeRef| {
        graph
            .edges
            .iter()
            .any(|edge| edge.to == execution && edge.kind == ExecutionEdgeKind::Launch)
    };
    let built_from_output = graph.edges.iter().any(|edge| {
        edge.to == deleted.execution
            && edge.kind == ExecutionEdgeKind::ToolModel
            && graph
                .nodes
                .get(edge.from.0 as usize)
                .and_then(|launcher| launcher.streams.stdin.as_ref())
                .is_some_and(|stdin| stdin.stream == ExecutionStream::Stdout)
    });
    if built_from_output {
        return true;
    }
    let Some(causality) = &plan.causality.graph else {
        return false;
    };
    let mut incoming = BTreeMap::<_, Vec<_>>::new();
    for edge in &causality.edges {
        if matches!(
            edge.reason,
            CausalReason::ValueDependency | CausalReason::Containment | CausalReason::Alias
        ) {
            incoming.entry(&edge.to).or_default().push(&edge.from);
        }
    }
    let nodes = causality
        .nodes
        .iter()
        .map(|node| (&node.id, node))
        .collect::<BTreeMap<_, _>>();
    // The executions that launched the delete, such as the `xargs` that
    // builds it: what they read and pass on is followed to its source, and
    // is not itself another program's output.
    let mut launchers = BTreeSet::from([deleted.execution]);
    let mut pending = vec![deleted.execution];
    while let Some(execution) = pending.pop() {
        for edge in graph.edges.iter().filter(|edge| edge.to == execution) {
            if launchers.insert(edge.from) {
                pending.push(edge.from);
            }
        }
    }
    // The walk starts at the delete and at the arguments of the deleting
    // command that name its target, which carry the value where a tool
    // builds the command (`xargs -a <(...) rm -rf`).
    let arguments = deleted
        .provenance
        .iter()
        .filter_map(|reference| {
            let node = plan.provenance.get(reference.0 as usize)?;
            let effinterp_proto::ProvenanceKind::Argument { index } = node.kind else {
                return None;
            };
            node.antecedents
                .iter()
                .any(|parent| {
                    plan.provenance.get(parent.0 as usize).is_some_and(|parent| {
                    matches!(parent.kind, effinterp_proto::ProvenanceKind::Execution { node }
                        if node == deleted.execution.0)
                })
                })
                .then_some(index)
        })
        .collect::<BTreeSet<_>>();
    let mut frontier = causality
        .nodes
        .iter()
        .filter(|node| {
            node.execution == Some(deleted.execution)
                && match &node.occurrence {
                    OccurrenceKind::ResourceInteraction {
                        operation,
                        resource,
                        ..
                    } => {
                        node.provenance == deleted.provenance
                            && operation == &deleted.operation
                            && resource == &deleted.resource
                    }
                    OccurrenceKind::Port {
                        port: Port::Arg(index),
                    } => arguments.contains(index),
                    _ => false,
                }
        })
        .map(|node| &node.id)
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    while let Some(id) = frontier.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(node) = nodes.get(id)
            && let OccurrenceKind::Port {
                port: Port::Stdout | Port::Value,
            } = node.occurrence
            && let Some(execution) = node.execution
            && !launchers.contains(&execution)
            && launched(execution)
        {
            return true;
        }
        frontier.extend(incoming.get(id).into_iter().flatten().copied());
    }
    false
}

/// What the shell spelled for an unresolved delete's target, as the reason
/// may show it: the parameters its operand word names, such as `$D` or
/// `${OUT}`, or a command substitution's place in it. Only names are shown,
/// never the rest of the word, which may hold a path, and a reason is logged.
/// A wrapper such as `sudo` or `env` passes its own argument on, so the
/// argument a wrapped command received leads back to the word spelled.
/// `None` when the delete is not an operand of a command a shell spelled,
/// such as a delete a Python program makes.
fn unresolved_operand(plan: &effinterp_proto::Plan, effect: usize) -> Option<String> {
    use effinterp_proto::{ProvenanceKind, Subject};
    let provenance = &plan.provenance;
    let mut pending: std::collections::VecDeque<_> =
        plan.effects[effect].provenance.iter().copied().collect();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(node) = pending.pop_front() {
        if !seen.insert(node.0) {
            continue;
        }
        let Some(argument) = provenance.get(node.0 as usize) else {
            continue;
        };
        let ProvenanceKind::Argument { index } = argument.kind else {
            continue;
        };
        for parent in &argument.antecedents {
            match provenance.get(parent.0 as usize).map(|parent| &parent.kind) {
                Some(ProvenanceKind::Argument { .. }) => pending.push_back(*parent),
                // A command's execution keeps its words as spelled.
                Some(ProvenanceKind::Execution { node }) => {
                    let Some(Subject::Exec { argv, .. }) = plan
                        .execution_graph
                        .nodes
                        .get(*node as usize)
                        .map(|node| &node.subject)
                    else {
                        continue;
                    };
                    let Some(word) = argv.get(index as usize) else {
                        continue;
                    };
                    let names = spelled_parameters(word);
                    if !names.is_empty() {
                        return Some(names.join(" and "));
                    }
                    if word.contains("$(") || word.contains('`') {
                        return Some("a command's output".to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// The parameters a word expands outside single quotes, spelled `$NAME`,
/// `$1` or `${NAME}`, without what a `${...}` modifier adds.
fn spelled_parameters(word: &str) -> Vec<String> {
    let bytes = word.as_bytes();
    let mut names = Vec::new();
    let (mut index, mut single, mut double) = (0, false, false);
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if !single => index += 1,
            b'"' if !single => double = !double,
            b'\'' if !double => single = !single,
            b'$' if !single => {
                let braced = bytes.get(index + 1) == Some(&b'{');
                let begin = index + 1 + usize::from(braced);
                let end = if bytes.get(begin).is_some_and(u8::is_ascii_digit) {
                    begin + 1
                } else {
                    begin
                        + bytes[begin..]
                            .iter()
                            .take_while(|&&c| c.is_ascii_alphanumeric() || c == b'_')
                            .count()
                };
                if end > begin {
                    let name = format!("`${}`", &word[begin..end]);
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
                index = end.max(index + 1);
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    names
}

/// Whether the effect at `effect` selects the project root itself or every
/// entry in it.
fn selects_project(host: &dyn GuardHostFacts, effect: usize) -> bool {
    host.selected_host_paths(effect).iter().any(|reached| {
        reached.resource.labels.as_ref().is_some_and(|labels| {
            ReachRule {
                endpoint: ReachEndpoint::Selected,
                recursive: false,
                path: PathRule::ProjectRoot,
            }
            .holds(
                &ReachedPath {
                    resource: reached.resource,
                    entry: true,
                    recursive: reached.recursive,
                    device: reached.device,
                    linked_readings: reached.linked_readings.as_deref(),
                },
                host,
            ) || labels.selects_project == Reach::Yes
        })
    })
}

/// The home folder itself or the standard personal folder in it that the
/// effect at `effect` reaches, or `None` when it reaches neither.
fn home_target(host: &dyn GuardHostFacts, effect: usize) -> Option<String> {
    let reached = host.selected_host_paths(effect);
    let labels = || {
        reached
            .iter()
            .filter_map(|reached| reached.resource.labels.as_ref())
    };
    let names_home = |labels: &nah_proto::effects::ResourceLabels| {
        [&labels.canonical, &labels.lexical]
            .into_iter()
            .any(|path| {
                matches!(path, Knowledge::Known(path)
                if nah_proto::labels::lexical_path::same_path(
                    path.as_str(),
                    host.home().as_str(),
                    host.platform(),
                ))
            })
    };
    Some(
        if labels().any(|labels| labels.selects_home == Reach::Yes && names_home(labels)) {
            "your home folder".to_owned()
        } else if labels().any(|labels| labels.selects_home == Reach::Yes) {
            "a folder that holds your home folder".to_owned()
        } else {
            let folder = labels().find(|labels| labels.selects_home_folder == Reach::Yes)?;
            match &folder.lexical {
                Knowledge::Known(path) => {
                    let name = path.as_str().rsplit(['/', '\\']).next().unwrap_or_default();
                    if [
                        "Desktop",
                        "Documents",
                        "Pictures",
                        "Movies",
                        "Videos",
                        "Music",
                    ]
                    .contains(&name)
                    {
                        format!("your {name} folder")
                    } else {
                        "a personal folder in your home folder".to_owned()
                    }
                }
                Knowledge::Unknown => "a personal folder in your home folder".to_owned(),
            }
        },
    )
}

const MUTATIONS: [&str; 5] = [
    "filesystem.write",
    "filesystem.create",
    "filesystem.delete",
    "filesystem.move",
    "filesystem.metadata",
];

/// Every discard mode for which the bridge summarizes physical reach, and the
/// subset that overwrites the selected paths rather than removing them.
const GIT_DISCARD_MODES: [&str; 8] = [
    "clean",
    "reset",
    "restore",
    "checkout",
    "switch",
    "worktree_remove",
    "worktree_prune",
    "submodule_deinit",
];
const GIT_OVERWRITE_MODES: [&str; 4] = ["reset", "restore", "checkout", "switch"];

/// In the reducer's attribution order.
pub(crate) fn filesystem_guard_definitions() -> Vec<GuardDefinition> {
    vec![
        host_integrity(
            "persistence/auth-files-modify",
            GuardLevel::Core,
            "fs-auth-identity",
            "this would change or delete the files that decide who can log in or become root, such as authorized_keys or sudoers. A deleted file cannot be brought back, and until a wrong change is reverted it can lock you out or let someone else in",
            HostIntegrityClass::AuthIdentity,
        ),
        GuardDefinition {
            rule: "machine/system-files-modify",
            guard: Guard::Machine,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-system-tree"),
            reason: "this would delete or overwrite the filesystem root or a system folder. It can break this computer and cannot be undone",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![
                filesystem_guard_clause(
                    destructive(),
                    ReachEndpoint::Selected,
                    true,
                    PathRule::SystemTree,
                ),
                filesystem_guard_clause(
                    filesystem("filesystem.move", vec![]),
                    ReachEndpoint::Selected,
                    false,
                    PathRule::EveryRootEntry,
                ),
            ],
        },
        // Separate from outside-project deletes: a 1.x `fs-home` choice must
        // not turn those off, and turning them off must not turn home off.
        GuardDefinition {
            rule: "machine/home-folder-modify",
            guard: Guard::Machine,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-home"),
            reason: "this would delete, overwrite or lock your home folder or a personal folder in it. It cannot be undone",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![filesystem_guard_clause(
                destructive(),
                ReachEndpoint::Selected,
                true,
                PathRule::Home,
            )],
        },
        GuardDefinition {
            rule: "machine/outside-workspace-delete",
            guard: Guard::Machine,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-outside-workspace-delete"),
            reason: "this would delete a folder outside the project. nah keeps no copy of it, so it cannot be undone",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![filesystem_guard_clause(
                filesystem("filesystem.delete", vec![]),
                ReachEndpoint::Selected,
                true,
                PathRule::OutsideWorkspace,
            )],
        },
        // A recursive delete whose target the engine left unresolved may take
        // any folder, inside the project or out, and save-then-run cannot
        // save what it cannot name; 1.x let it run. At core only a target
        // another program in the call prints, part of the rule's intended
        // default change from the 1.x guard that shipped off, whose choice
        // it follows; at strict any, since frontends also leave unresolved
        // what a script is given, such as a Python program's `sys.argv`.
        unresolved_delete(
            GuardLevel::Core,
            Some("fs-outside-workspace-delete"),
            vec![
                QueryQualifier::UnresolvedTreeDeleted,
                QueryQualifier::TargetFromProgramOutput,
            ],
        ),
        unresolved_delete(
            GuardLevel::Strict,
            None,
            vec![QueryQualifier::UnresolvedTreeDeleted],
        ),
        GuardDefinition {
            rule: "machine/permissions-weaken",
            guard: Guard::Machine,
            applies_at: GuardLevel::Strict,
            replaces: Some("fs-permission-weaken"),
            reason: "this would let any user change these files, or let a program run with its owner's rights. The old permissions can be restored, but what another user or program does with the access until then cannot be undone",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![GuardClause {
                query: Query::new(Assertion::Any {
                    assertions: ["world_write", "setuid", "setgid"]
                        .into_iter()
                        .flat_map(|grant| {
                            let attributes = vec![permission_change(), bool_attr(grant, true)];
                            [
                                filesystem("filesystem.metadata", attributes.clone()),
                                executed_chmod(attributes),
                            ]
                        })
                        .collect(),
                }),
                host: Some(HostRule {
                    feasible_condition: true,
                    reach: None,
                }),
                qualifiers: Vec::new(),
            }],
        },
        GuardDefinition {
            rule: "work/files-delete",
            guard: Guard::Work,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-project-root"),
            reason: "this would delete or overwrite the whole project folder. Whatever is not pushed elsewhere cannot be recovered",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![GuardClause {
                qualifiers: vec![QueryQualifier::OwnerAccessLost],
                ..filesystem_guard_clause(
                    destructive(),
                    ReachEndpoint::Selected,
                    true,
                    PathRule::ProjectRoot,
                )
            }],
        },
        // At core where the runtime saves, save-then-run saves what such a
        // delete loses and lets it run, and blocks what it cannot save; at
        // strict the rule decides whole and this part blocks. Where nothing
        // can save it does not apply at core, as 1.x blocked only a wipe of
        // the whole project. A delete Git or the folder's names show loses
        // nothing matches no part.
        GuardDefinition {
            rule: "work/files-delete",
            guard: Guard::Work,
            applies_at: GuardLevel::Strict,
            // 1.x blocked only a wipe of the whole project.
            replaces: None,
            reason: "this would delete files in the project. Only what Git has committed can be brought back; uncommitted changes and other files there are lost",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![GuardClause {
                query: Query::new(filesystem("filesystem.delete", vec![])),
                host: Some(HostRule {
                    feasible_condition: true,
                    reach: None,
                }),
                qualifiers: vec![
                    QueryQualifier::ProjectFilesDeleted,
                    QueryQualifier::GitLossPossible,
                ],
            }],
        },
        GuardDefinition {
            rule: "machine/disk-overwrite",
            guard: Guard::Machine,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-raw-device"),
            reason: "this would write straight to a disk or to the kernel crash trigger. It can destroy every file on the disk or crash this computer at once, and destroyed data cannot be brought back",
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![
                filesystem_guard_clause(
                    Assertion::Any {
                        assertions: [
                            "filesystem.write",
                            "filesystem.create",
                            "filesystem.metadata",
                        ]
                        .into_iter()
                        .map(|operation| filesystem(operation, vec![]))
                        .collect(),
                    },
                    ReachEndpoint::Selected,
                    false,
                    PathRule::RawStorageSpelling,
                ),
                filesystem_guard_clause(
                    filesystem("filesystem.move", vec![]),
                    ReachEndpoint::MoveDestination,
                    false,
                    PathRule::RawStorageSpelling,
                ),
                // A whole-device destruction names a typed block device; the
                // device path it reaches is its identity.
                filesystem_guard_clause(
                    Assertion::Any {
                        assertions: established(|request, execution| Assertion::All {
                            assertions: vec![
                                host_effect(
                                    "system.storage_destroy",
                                    resource_family("blk"),
                                    vec![bool_attr("whole_device", true)],
                                    request,
                                    execution,
                                ),
                                attribute_is_not(
                                    "system.storage_destroy",
                                    "dry_run",
                                    AttrValue::Bool(true),
                                ),
                            ],
                        }),
                    },
                    ReachEndpoint::Selected,
                    false,
                    PathRule::RawStorageSpelling,
                ),
                git_reach(&GIT_OVERWRITE_MODES, PathRule::RawStorageSpelling),
            ],
        },
        host_integrity(
            "persistence/shell-profile-write",
            GuardLevel::Strict,
            "fs-shell-profile",
            "this would change a shell profile such as .bashrc, which runs in every new shell. The change can be removed later, but what it runs until then cannot be undone",
            HostIntegrityClass::ShellProfile,
        ),
        GuardDefinition {
            rule: "persistence/startup-item-add",
            guard: Guard::Persistence,
            applies_at: GuardLevel::Strict,
            replaces: Some("fs-startup-management"),
            reason: "this would set a program to run at boot, at login or on a schedule, after this session ends. It can be removed later, but what it runs until then cannot be undone",
            domain: Domain::System,
            gap_code: None,
            clauses: vec![
                eligible(Assertion::Any {
                    assertions: [
                        "system.service_enable",
                        "system.service_disable",
                        "system.scheduled_job_write",
                        "system.scheduled_job_delete",
                    ]
                    .into_iter()
                    .map(|operation| Assertion::All {
                        // The engine emits these operations only for a startup
                        // change it is carrying out: help, version and dry-run
                        // forms return before any effect, and neither enabling
                        // a unit nor replacing or removing a crontab has a
                        // cancel form. That operation contract is the active,
                        // not-help and not-cancel controls. `--runtime` is the
                        // one modeled qualifier, and it is what keeps the
                        // change out of the boot path, so a change is
                        // persistent exactly when the engine states no
                        // `runtime`. A unit changed on a remote host or a
                        // local container the user administers is the same
                        // loss as on this host.
                        assertions: vec![
                            Assertion::Any {
                                assertions: [
                                    RealmPredicate::Host,
                                    RealmPredicate::Remote,
                                    RealmPredicate::Container,
                                ]
                                .into_iter()
                                .map(|realm| {
                                    effect_in(
                                        realm,
                                        operation,
                                        ResourcePredicate::AnyOf {
                                            predicates: vec![
                                                resource_family("svc"),
                                                resource_family("job"),
                                                ResourcePredicate::All {
                                                    predicates: vec![
                                                        resource_family("system"),
                                                        resource_selection(SelectionShape::Pattern),
                                                    ],
                                                },
                                            ],
                                        },
                                        vec![],
                                        None,
                                        Some(ExecutionAssurance::Exact),
                                    )
                                })
                                .collect(),
                            },
                            attribute_is_not(operation, "runtime", AttrValue::Bool(true)),
                        ],
                    })
                    .collect(),
                }),
                // `systemctl edit` writes a unit or its drop-in directly, on
                // this host or, with `-M`, in a local container the user
                // administers. The runtime unit directory under /run is left
                // out for the same reason `--runtime` is.
                filesystem_guard_clause(
                    Assertion::Any {
                        assertions: [RealmPredicate::Host, RealmPredicate::Container]
                            .into_iter()
                            .map(|realm| filesystem_in(realm, "filesystem.write", vec![]))
                            .collect(),
                    },
                    ReachEndpoint::Selected,
                    false,
                    PathRule::SystemdUnitDirectory,
                ),
            ],
        },
        {
            let mut guard = host_integrity(
                "persistence/startup-item-add",
                GuardLevel::Core,
                "fs-startup-persistence",
                "this would add or change a startup item, or plant downloaded code in a shell profile, to run after this session ends. It can be removed later, but what it runs until then cannot be undone",
                HostIntegrityClass::StartupPersistence,
            );
            let mut clause = filesystem_guard_clause(
                Assertion::Any {
                    assertions: ["filesystem.write", "filesystem.create"]
                        .into_iter()
                        .map(|operation| filesystem(operation, vec![]))
                        .collect(),
                },
                ReachEndpoint::Selected,
                false,
                PathRule::HostIntegrity(HostIntegrityClass::ShellProfile),
            );
            clause.qualifiers.push(QueryQualifier::RemoteWrittenContent);
            guard.clauses.push(clause);
            guard
        },
        GuardDefinition {
            rule: "machine/disk-overwrite",
            guard: Guard::Machine,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-volume-destroy"),
            reason: "this would destroy a storage volume, pool or live dataset. Every file on it would be lost for good",
            domain: Domain::System,
            gap_code: None,
            clauses: vec![eligible(Assertion::All {
                assertions: vec![
                    // A live logical volume or dataset: not a btrfs subvolume,
                    // a zfs snapshot or bookmark selector, or a cloud disk.
                    host_effect(
                        "system.storage_destroy",
                        ResourcePredicate::All {
                            predicates: vec![
                                resource_variant(ResourceVariant::StorageVolume),
                                ResourcePredicate::Not {
                                    predicate: Box::new(ResourcePredicate::AnyOf {
                                        predicates: ["btrfs", "aws", "gcloud", "az"]
                                            .into_iter()
                                            .map(|manager| ResourcePredicate::StorageVolume {
                                                manager: Some(TextPredicate::Equals(
                                                    manager.into(),
                                                )),
                                                name: None,
                                            })
                                            .chain(["@", "#"].into_iter().map(|selector| {
                                                ResourcePredicate::StorageVolume {
                                                    manager: None,
                                                    name: Some(TextPredicate::Contains(
                                                        selector.into(),
                                                    )),
                                                }
                                            }))
                                            .collect(),
                                    }),
                                },
                            ],
                        },
                        vec![],
                        None,
                        Some(ExecutionAssurance::Exact),
                    ),
                    attribute_is_not("system.storage_destroy", "dry_run", AttrValue::Bool(true)),
                    attribute_is_not(
                        "system.storage_destroy",
                        "mode",
                        AttrValue::String("rollback".into()),
                    ),
                ],
            })],
        },
        // Separate from shutdown: allowing a reboot must not allow a fork bomb.
        GuardDefinition {
            rule: "machine/fork-bomb",
            guard: Guard::Machine,
            applies_at: GuardLevel::Core,
            replaces: Some("fs-forkbomb"),
            reason: "this would start processes without limit until this computer stops responding. Unsaved work in open programs may be lost for good",
            domain: Domain::Process,
            gap_code: None,
            clauses: vec![eligible(Assertion::Any {
                // A loop, or a recursive function the engine certifies as
                // unbounded background recursion. The growth is abstract: no
                // job-table field or causal growth proof is consulted.
                assertions: [
                    vec![string_attr("source", "loop")],
                    vec![
                        string_attr("source", "function"),
                        string_attr("process_growth", "unbounded_background_recursion"),
                    ],
                ]
                .into_iter()
                .map(|attributes| {
                    host_effect(
                        "process.code_execution",
                        resource_family("proc"),
                        attributes,
                        None,
                        Some(ExecutionAssurance::Exact),
                    )
                })
                .collect(),
            })],
        },
    ]
}

/// A `machine/outside-workspace-delete` part for a recursive delete whose
/// target the engine left unresolved, with the qualifiers that narrow it.
fn unresolved_delete(
    applies_at: GuardLevel,
    replaces: Option<&'static str>,
    qualifiers: Vec<QueryQualifier>,
) -> GuardDefinition {
    GuardDefinition {
        rule: "machine/outside-workspace-delete",
        guard: Guard::Machine,
        applies_at,
        replaces,
        reason: UNRESOLVED_DELETE_REASON,
        domain: Domain::Filesystem,
        gap_code: None,
        clauses: vec![GuardClause {
            query: Query::new(Assertion::Any {
                assertions: established(|request, execution| {
                    host_effect(
                        "filesystem.delete",
                        ResourcePredicate::Any,
                        vec![],
                        request,
                        execution,
                    )
                }),
            }),
            host: Some(HostRule {
                feasible_condition: true,
                reach: None,
            }),
            qualifiers,
        }],
    }
}

fn host_integrity(
    rule: &'static str,
    applies_at: GuardLevel,
    replaces: &'static str,
    reason: &'static str,
    class: HostIntegrityClass,
) -> GuardDefinition {
    let path = PathRule::HostIntegrity(class);
    GuardDefinition {
        rule,
        guard: crate::registry::rule_guard(rule),
        applies_at,
        replaces: Some(replaces),
        reason,
        domain: Domain::Filesystem,
        gap_code: None,
        clauses: vec![
            filesystem_guard_clause(
                Assertion::Any {
                    assertions: MUTATIONS
                        .into_iter()
                        .map(|operation| filesystem(operation, vec![]))
                        .collect(),
                },
                ReachEndpoint::Selected,
                false,
                path,
            ),
            filesystem_guard_clause(
                filesystem("filesystem.move", vec![]),
                ReachEndpoint::MoveDestination,
                false,
                path,
            ),
            git_reach(&GIT_DISCARD_MODES, path),
        ],
    }
}

fn filesystem_guard_clause(
    assertion: Assertion,
    endpoint: ReachEndpoint,
    recursive: bool,
    path: PathRule,
) -> GuardClause {
    GuardClause {
        query: Query::new(assertion),
        host: Some(HostRule {
            feasible_condition: true,
            reach: Some(ReachRule {
                endpoint,
                recursive,
                path,
            }),
        }),
        qualifiers: Vec::new(),
    }
}

fn eligible(assertion: Assertion) -> GuardClause {
    GuardClause {
        query: Query::new(assertion),
        host: Some(HostRule {
            feasible_condition: true,
            reach: None,
        }),
        qualifiers: Vec::new(),
    }
}

/// What can destroy a tree: a recursive deletion or permission change, or a
/// write its model states discards what each file held (`truncate`, `shred`,
/// `dd of=`) applied to every file below a root, which loses the contents as
/// a deletion does. A write that states neither, such as an append or an edit
/// in place, is not read this way.
fn destructive() -> Assertion {
    Assertion::Any {
        assertions: vec![
            filesystem("filesystem.delete", vec![]),
            filesystem("filesystem.metadata", vec![permission_change()]),
            filesystem("filesystem.write", vec![bool_attr("truncate", true)]),
            filesystem("filesystem.write", vec![bool_attr("overwrite", true)]),
        ],
    }
}

fn permission_change() -> AttributePredicate {
    string_one_of("action", &["chmod", "chown", "chgrp", "setfacl"])
}

/// The paths an exact, active, non-rehearsal Git discard selects. Git performs
/// the replacement or removal, so this reach is protected wherever the request
/// appears, whatever its realm or condition.
fn git_reach(modes: &[&str], path: PathRule) -> GuardClause {
    GuardClause {
        query: Query::new(Assertion::Any {
            assertions: ["git.clean_request", "git.worktree_discard_request"]
                .into_iter()
                .map(|operation| Assertion::Effect {
                    selector: Selector {
                        operation: OperationMatch::Exact(operation.into()),
                        resource: ResourcePredicate::Any,
                        attributes: vec![
                            bool_attr("active", true),
                            bool_attr("dry_run", false),
                            string_one_of("discard_mode", modes),
                        ],
                        request_assurance: Some(RequestAssurance::Exact),
                        condition: None,
                        modality: None,
                        execution_assurance: None,
                        realm: None,
                    },
                    closure: None,
                })
                .collect(),
        }),
        host: Some(HostRule {
            feasible_condition: false,
            reach: Some(ReachRule {
                endpoint: ReachEndpoint::Selected,
                recursive: false,
                path,
            }),
        }),
        qualifiers: Vec::new(),
    }
}

/// A host filesystem request the guards may act on: an exact request, an exact
/// execution of a concrete path, or an exact execution of a pattern write the
/// engine states is a raw-device write. A pattern names no single member, but
/// a raw-device write reaches raw storage whichever device the selector
/// matches; an ordinary pattern write or deletion is not established that
/// way, because there the identity decides what is lost.
fn filesystem(operation: &str, attributes: Vec<AttributePredicate>) -> Assertion {
    filesystem_in(RealmPredicate::Host, operation, attributes)
}

/// An exactly executed chmod whichever host files it changes, including one
/// the engine could not name, such as Node's `fchmod` of an open descriptor.
/// A proven grant is the loss whichever file receives it, so only this guard
/// reads it; every other filesystem guard needs the path.
fn executed_chmod(attributes: Vec<AttributePredicate>) -> Assertion {
    host_effect(
        "filesystem.metadata",
        resource_family("filesystem"),
        attributes,
        None,
        Some(ExecutionAssurance::Exact),
    )
}

fn filesystem_in(
    realm: RealmPredicate,
    operation: &str,
    attributes: Vec<AttributePredicate>,
) -> Assertion {
    let mut assertions = established(|request, execution| {
        effect_in(
            realm,
            operation,
            if execution.is_some() {
                resource_variant(ResourceVariant::FsPath)
            } else {
                ResourcePredicate::Any
            },
            attributes.clone(),
            request,
            execution,
        )
    });
    if operation == "filesystem.write" {
        let mut raw = attributes;
        raw.push(bool_attr("raw_device", true));
        assertions.push(Assertion::All {
            assertions: vec![
                effect_in(
                    realm,
                    operation,
                    ResourcePredicate::All {
                        predicates: vec![
                            resource_family("filesystem"),
                            resource_selection(SelectionShape::Pattern),
                        ],
                    },
                    raw,
                    None,
                    Some(ExecutionAssurance::Exact),
                ),
                // A metadata write is a metadata mutation, not a device write.
                attribute_is_not(operation, "metadata", AttrValue::Bool(true)),
            ],
        });
    }
    Assertion::Any { assertions }
}

/// The two ways the engine establishes a request: exactly as asked, or by an
/// exact execution of it.
fn established(
    assertion: impl Fn(Option<RequestAssurance>, Option<ExecutionAssurance>) -> Assertion,
) -> Vec<Assertion> {
    vec![
        assertion(Some(RequestAssurance::Exact), None),
        assertion(None, Some(ExecutionAssurance::Exact)),
    ]
}

fn host_effect(
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
    request_assurance: Option<RequestAssurance>,
    execution_assurance: Option<ExecutionAssurance>,
) -> Assertion {
    effect_in(
        RealmPredicate::Host,
        operation,
        resource,
        attributes,
        request_assurance,
        execution_assurance,
    )
}

fn effect_in(
    realm: RealmPredicate,
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
    request_assurance: Option<RequestAssurance>,
    execution_assurance: Option<ExecutionAssurance>,
) -> Assertion {
    Assertion::Effect {
        selector: Selector {
            operation: OperationMatch::Exact(operation.into()),
            resource,
            attributes,
            request_assurance,
            condition: None,
            modality: None,
            execution_assurance,
            realm: Some(realm),
        },
        closure: None,
    }
}

/// The attribute is absent or holds anything but `value`. Typed equality alone
/// leaves an absent attribute unknown, so absence is tested separately.
fn attribute_is_not(operation: &str, name: &str, value: AttrValue) -> Assertion {
    let absent_or = |attribute| Assertion::Not {
        assertion: Box::new(Assertion::Effect {
            selector: Selector {
                operation: OperationMatch::Exact(operation.into()),
                resource: ResourcePredicate::Any,
                attributes: vec![attribute],
                request_assurance: None,
                condition: None,
                modality: None,
                execution_assurance: None,
                realm: None,
            },
            closure: None,
        }),
    };
    Assertion::Any {
        assertions: vec![
            absent_or(present_attr(name)),
            absent_or(AttributePredicate {
                name: name.into(),
                test: effinterp_matcher::AttributeTest::Equals(value),
            }),
        ],
    }
}

fn pattern_selects_project_root(target: &str, root: &str) -> bool {
    let Some(suffix) = target.strip_prefix(root) else {
        return false;
    };
    let suffix = if root.ends_with(['/', '\\']) {
        suffix
    } else if let Some(suffix) = suffix.strip_prefix('/') {
        suffix
    } else if let Some(suffix) = suffix.strip_prefix('\\') {
        suffix
    } else {
        return false;
    };
    matches!(suffix, "*" | ".*" | "{*,.*}")
}

const SYSTEMD_UNIT_DIRECTORIES: [&str; 8] = [
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/etc/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
];

#[cfg(test)]
mod tests {
    use super::spelled_parameters;

    /// A block reason is logged, so the operand it names keeps only the
    /// parameters, never the path text around them or inside a substitution.
    #[test]
    fn an_unresolved_operand_is_named_by_its_parameters_alone() {
        assert!(spelled_parameters(r#""$(cat /srv/secret/out.txt)""#).is_empty());
        assert_eq!(spelled_parameters(r#""${D:-/srv/a}/b c""#), ["`$D`"]);
        assert_eq!(spelled_parameters(r#""$OUT/$1"/x"#), ["`$OUT`", "`$1`"]);
        assert!(spelled_parameters("'$NOT_EXPANDED'").is_empty());
        assert_eq!(spelled_parameters(r#""it's $D""#), ["`$D`"]);
    }
}
