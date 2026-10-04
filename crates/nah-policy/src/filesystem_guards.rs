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

use effinterp_matcher::{
    Assertion, AttributePredicate, OperationMatch, Query, RealmPredicate, ResourcePredicate,
    ResourceVariant, SelectionShape, Selector, TextPredicate,
};
use effinterp_proto::{AttrValue, ExecutionAssurance, RequestAssurance};
use nah_proto::action::pattern_bound;
use nah_proto::effects::{
    Domain, EffectResource, Knowledge, Reach, ResourceDetails, ResourceIdentity, ResourceKind,
    Selection,
};
use nah_proto::labels::raw_storage::{is_raw_storage_or_sysrq, pattern_selects_raw_storage};
use nah_proto::labels::system_tree::{pattern_selects_system_tree, selects_root_or_system_tree};
use nah_proto::labels::temporary_root::is_reviewed_temporary_root;
use nah_proto::labels::{HostIntegrityClass, PathScope};

use crate::registry::{GuardClause, GuardDefinition, GuardFamily};
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
    /// The home root.
    Home,
    /// An observed project root, or a pattern that selects every entry of one.
    ProjectRoot,
    /// Home, system or outside any project, except reviewed temporary roots.
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
}

impl ReachRule {
    pub fn holds(&self, reached: &ReachedPath<'_>) -> bool {
        (!self.recursive || reached.recursive) && self.path.holds(reached)
    }
}

impl PathRule {
    fn holds(self, reached: &ReachedPath<'_>) -> bool {
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
                unresolved || labels.is_some_and(|labels| labels.selects_home == Reach::Yes)
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
                }) && target.is_some_and(|target| !is_reviewed_temporary_root(target))
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
            "fs-auth-identity",
            true,
            "fs-auth-identity blocked modification or deletion affecting host authentication, identity, or privilege-policy files; this includes recursive deletion of their parent directories; do not retry through another tool; ask the operator to perform any intended change",
            HostIntegrityClass::AuthIdentity,
        ),
        GuardDefinition {
            id: "fs-system-tree",
            reason: "fs-system-tree blocked a destructive operation on the filesystem root or a system tree; narrow the target to the intended project path; ask the operator to perform any system-wide change",
            family: GuardFamily::Filesystem,
            default_enabled: true,
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
        GuardDefinition {
            id: "fs-home",
            reason: "fs-home blocked a destructive operation on the home root; name the exact files; ask the operator to perform any home-wide change",
            family: GuardFamily::Filesystem,
            default_enabled: true,
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
            id: "fs-outside-workspace-delete",
            reason: "fs-outside-workspace-delete blocked recursive deletion outside the active project; narrow the target to the project or a reviewed temporary root; ask the operator to perform any broader cleanup",
            family: GuardFamily::Filesystem,
            default_enabled: false,
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![filesystem_guard_clause(
                filesystem("filesystem.delete", vec![]),
                ReachEndpoint::Selected,
                true,
                PathRule::OutsideWorkspace,
            )],
        },
        GuardDefinition {
            id: "fs-permission-weaken",
            reason: "fs-permission-weaken blocked a chmod mode that provably grants world-write or setuid/setgid permission; use a narrower mode or ask the operator to perform the permission change",
            family: GuardFamily::Filesystem,
            default_enabled: false,
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
            id: "fs-project-root",
            reason: "fs-project-root blocked a destructive operation on the project root; name the exact files or subtree; ask the operator to perform any project-wide change",
            family: GuardFamily::Filesystem,
            default_enabled: true,
            domain: Domain::Filesystem,
            gap_code: None,
            clauses: vec![filesystem_guard_clause(
                destructive(),
                ReachEndpoint::Selected,
                true,
                PathRule::ProjectRoot,
            )],
        },
        GuardDefinition {
            id: "fs-raw-device",
            reason: "fs-raw-device blocked a write to raw storage or the kernel crash trigger; do not retry; report the exact target and operation to the operator",
            family: GuardFamily::Filesystem,
            default_enabled: true,
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
            "fs-shell-profile",
            false,
            "fs-shell-profile blocked a change to a user shell profile; do not retry through another tool; if this shell configuration is intended, ask the operator to open `nah tui` in a separate terminal and disable `fs-shell-profile`, then re-enable it after the change",
            HostIntegrityClass::ShellProfile,
        ),
        GuardDefinition {
            id: "fs-startup-management",
            reason: "fs-startup-management blocked a definite persistent startup-management command; do not retry through another tool; if this host administration is intended, ask the operator to open `nah tui` in a separate terminal and disable `fs-startup-management`, then re-enable it after the change",
            family: GuardFamily::Filesystem,
            default_enabled: false,
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
        host_integrity(
            "fs-startup-persistence",
            true,
            "fs-startup-persistence blocked a change to a path that can automatically run or load code; do not retry through another tool; if this host administration is intended, ask the operator to open `nah tui` in a separate terminal and disable `fs-startup-persistence`, then re-enable it after the change",
            HostIntegrityClass::StartupPersistence,
        ),
        GuardDefinition {
            id: "fs-volume-destroy",
            reason: "fs-volume-destroy blocked storage destruction; do not retry; report the exact volume, pool, or live dataset and operation to the operator",
            family: GuardFamily::Filesystem,
            default_enabled: true,
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
        GuardDefinition {
            id: "fs-forkbomb",
            reason: "fs-forkbomb blocked unbounded process spawning; use a fixed worker limit or bounded queue",
            family: GuardFamily::Filesystem,
            default_enabled: true,
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

fn host_integrity(
    id: &'static str,
    default_enabled: bool,
    reason: &'static str,
    class: HostIntegrityClass,
) -> GuardDefinition {
    let path = PathRule::HostIntegrity(class);
    GuardDefinition {
        id,
        reason,
        family: GuardFamily::Filesystem,
        default_enabled,
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
