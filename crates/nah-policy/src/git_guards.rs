//! Declarative definitions for the destructive Git guards.

use effinterp_matcher::{
    Assertion, AttributePredicate, AttributeTest, ElementTest, LabelId, ObservationBinding,
    OperationMatch, Query, RealmPredicate, ResourcePredicate, Selector, TextPredicate,
};
use effinterp_proto::{AttrValue, Modality, RequestAssurance};
use nah_proto::effects::Domain;
use nah_proto::labels::{LABEL_OBSERVATION, NahLabel};

use crate::guard_evaluation::QueryQualifier;
use crate::registry::{GuardClause, GuardDefinition, GuardFamily};
use crate::shared_queries::{bool_attr, present_attr, string_attr, string_one_of};

/// Which side of the observed Git root a discard must select: the root
/// itself, or a named path other than it.
#[derive(Clone, Copy)]
enum GitSelection {
    Root,
    NamedNonRoot,
}

/// The Git push predicates: force without a lease, a protected `main` or
/// `master` destination, a leased history rewrite, and ref deletion.
#[derive(Clone, Copy)]
enum GitPushPredicate {
    Force,
    Protected,
    History,
    RefDelete,
}

/// The destructive Git guard definitions, in definition order.
pub(crate) fn git_guard_definitions() -> Vec<GuardDefinition> {
    vec![
        program(
            "git-clean-force",
            true,
            vec![clause(
                selection_request(
                    "git.clean_request",
                    vec![
                        string_attr("discard_mode", "clean"),
                        bool_attr("force", true),
                        bool_attr("untracked", true),
                        bool_attr("dry_run", false),
                    ],
                    GitSelection::Root,
                ),
                vec![],
            )],
        ),
        program(
            "git-force-push",
            true,
            vec![push_clause(GitPushPredicate::Force)],
        ),
        program(
            "git-hard-reset",
            true,
            vec![clause(
                request(
                    "git.reset_request",
                    vec![
                        string_attr("reset_mode", "hard"),
                        bool_attr("dry_run", false),
                    ],
                ),
                vec![],
            )],
        ),
        program(
            "git-history-rewrite",
            false,
            vec![
                clause(
                    Query::new(Assertion::All {
                        assertions: vec![
                            request_assertion("git.history_rewrite_request", history_controls()),
                            Assertion::Not {
                                assertion: Box::new(request_assertion(
                                    "git.history_rewrite_request",
                                    vec![string_attr("history_operation", "amend")],
                                )),
                            },
                            Assertion::Not {
                                assertion: Box::new(request_assertion(
                                    "git.history_rewrite_request",
                                    vec![
                                        string_one_of(
                                            "history_operation",
                                            &["filter-branch", "filter-repo"],
                                        ),
                                        bool_attr("force", true),
                                    ],
                                )),
                            },
                        ],
                    }),
                    vec![],
                ),
                clause(
                    request(
                        "git.recovery_destroy_request",
                        with(
                            history_controls(),
                            vec![
                                present_attr("reflog"),
                                bool_attr("reflog", true),
                                present_attr("scope"),
                                string_attr("scope", "named"),
                            ],
                        ),
                    ),
                    vec![],
                ),
                // Expiring one literal ref's reflog is the same loss; deleting
                // one selected entry (`reflog delete HEAD@{1}`) is not.
                clause(
                    request(
                        "git.recovery_destroy_request",
                        with(
                            history_controls(),
                            vec![
                                present_attr("reflog"),
                                bool_attr("reflog", true),
                                present_attr("scope"),
                                string_attr("scope", "selected"),
                                present_attr("action"),
                                string_attr("action", "expire"),
                            ],
                        ),
                    ),
                    vec![],
                ),
                clause(
                    request(
                        "git.recovery_destroy_request",
                        with(
                            history_controls(),
                            vec![present_attr("aggressive"), bool_attr("aggressive", true)],
                        ),
                    ),
                    vec![],
                ),
                clause(
                    request(
                        "git.recovery_destroy_request",
                        with(history_controls(), vec![present_attr("prune")]),
                    ),
                    vec![],
                ),
                push_clause(GitPushPredicate::History),
            ],
        ),
        program(
            "git-metadata",
            true,
            [
                "filesystem.move",
                "filesystem.write",
                "filesystem.create",
                "filesystem.delete",
                "filesystem.metadata",
            ]
            .into_iter()
            .map(|operation| {
                clause(
                    Query::new(effect_assertion(
                        OperationMatch::Exact(operation.into()),
                        vec![],
                        None,
                        None,
                        Some(RealmPredicate::Host),
                    )),
                    vec![QueryQualifier::GitMetadata],
                )
            })
            .collect(),
        ),
        program(
            "git-path-discard",
            false,
            vec![
                clause(
                    selection_request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["checkout", "restore", "switch"]),
                            bool_attr("dry_run", false),
                        ],
                        GitSelection::NamedNonRoot,
                    ),
                    vec![],
                ),
                clause(
                    Query::new(effect_assertion(
                        OperationMatch::Exact("git.read".into()),
                        vec![
                            present_attr("disclosure"),
                            string_attr("disclosure", "contents"),
                            present_attr("historical"),
                            bool_attr("historical", true),
                            present_attr("object"),
                            present_attr("revision"),
                            present_attr("path"),
                        ],
                        None,
                        None,
                        Some(RealmPredicate::Host),
                    )),
                    vec![QueryQualifier::DirectPathRestoration],
                ),
            ],
        ),
        program(
            "git-protected-push",
            false,
            vec![push_clause(GitPushPredicate::Protected)],
        ),
        program(
            "git-recovery-destroy",
            true,
            vec![clause(
                request(
                    "git.recovery_destroy_request",
                    with(
                        history_controls(),
                        vec![string_attr("scope", "whole"), bool_attr("broad", true)],
                    ),
                ),
                vec![],
            )],
        ),
        program(
            "git-ref-delete",
            false,
            vec![
                clause(
                    request(
                        "git.ref_delete_request",
                        vec![
                            bool_attr("active", true),
                            bool_attr("abort", false),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![],
                ),
                push_clause(GitPushPredicate::RefDelete),
                clause(
                    request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["worktree_remove", "worktree_prune"]),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![],
                ),
                clause(
                    request(
                        "git.worktree_discard_request",
                        vec![
                            string_attr("discard_mode", "submodule_deinit"),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![],
                ),
            ],
        ),
        program(
            "git-remote-repo-delete",
            true,
            vec![clause(
                Query::new(effect_assertion(
                    OperationMatch::Exact("network.delete_request".into()),
                    vec![
                        string_attr("method", "DELETE"),
                        bool_attr("delete", true),
                        string_attr("hosted_target_kind", "repository"),
                    ],
                    Some(RequestAssurance::Exact),
                    None,
                    None,
                )),
                vec![],
            )],
        ),
        program(
            "git-remote-resource-delete",
            false,
            vec![
                clause(
                    Query::new(effect_assertion(
                        OperationMatch::Exact("network.delete_request".into()),
                        vec![
                            string_attr("method", "DELETE"),
                            bool_attr("delete", true),
                            string_attr("hosted_target_kind", "resource"),
                        ],
                        Some(RequestAssurance::Exact),
                        Some(Modality::MustOnSuccess),
                        None,
                    )),
                    vec![],
                ),
                // A bulk delete that may find nothing to delete
                // (`gh cache delete --all --succeed-on-no-caches`) is only
                // `May`, but no prompt stands between the command and the
                // deletion of every resource it finds.
                clause(
                    Query::new(effect_assertion(
                        OperationMatch::Exact("network.delete_request".into()),
                        vec![
                            string_attr("method", "DELETE"),
                            bool_attr("delete", true),
                            string_attr("hosted_target_kind", "resource"),
                            bool_attr("all", true),
                        ],
                        Some(RequestAssurance::Exact),
                        Some(Modality::May),
                        None,
                    )),
                    vec![],
                ),
                clause(
                    Query::new(effect_assertion(
                        OperationMatch::Exact("artifact.delete".into()),
                        vec![],
                        None,
                        Some(Modality::MustOnSuccess),
                        None,
                    )),
                    vec![QueryQualifier::GithubRelease],
                ),
            ],
        ),
        program(
            "git-rewrite-force",
            true,
            vec![clause(
                request(
                    "git.history_rewrite_request",
                    with(
                        history_controls(),
                        vec![
                            string_one_of("history_operation", &["filter-branch", "filter-repo"]),
                            bool_attr("force", true),
                        ],
                    ),
                ),
                vec![],
            )],
        ),
        program(
            "git-worktree-discard",
            true,
            vec![
                clause(
                    selection_request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["checkout", "restore", "switch"]),
                            bool_attr("dry_run", false),
                        ],
                        GitSelection::Root,
                    ),
                    vec![],
                ),
                clause(
                    request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["worktree_remove", "worktree_prune"]),
                            bool_attr("force", true),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![],
                ),
                clause(
                    request(
                        "git.worktree_discard_request",
                        vec![
                            string_attr("discard_mode", "submodule_deinit"),
                            bool_attr("force", true),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![],
                ),
            ],
        ),
    ]
}

fn metadata(id: &str) -> (&'static str, Domain, &'static str) {
    match id {
        "git-clean-force" => (
            "git-clean-force blocked a forced clean selecting the project root; preview with git clean -n, name the intended target, or ask the operator to perform the project-wide clean",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
        ),
        "git-force-push" => (
            "git-force-push blocked a force push without lease protection or to an explicit main/master destination; push a feature branch without force, or ask the operator to perform the intended history rewrite",
            Domain::Git,
            "git-push-destination-and-lease-details-unavailable",
        ),
        "git-hard-reset" => (
            "git-hard-reset blocked git reset --hard; inspect the diff and preserve wanted work; use a targeted restore or ask the operator to perform the full reset",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
        ),
        "git-history-rewrite" => (
            "git-history-rewrite blocked a Git history rewrite; inspect the affected refs, use an abort or dry-run mode when available, or ask the operator to verify the rewrite",
            Domain::Git,
            "git-history-active-mode-unavailable",
        ),
        "git-metadata" => (
            "git-metadata blocked a destructive change to Git metadata; use Git commands instead of editing or deleting .git data directly",
            Domain::Filesystem,
            "resource-components-unavailable",
        ),
        "git-path-discard" => (
            "git-path-discard blocked a named-path working-tree discard; inspect git diff and stash wanted work before replacing the path",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
        ),
        "git-protected-push" => (
            "git-protected-push blocked a push whose explicit refspec targets main or master; push a feature branch and use a pull request instead",
            Domain::Git,
            "git-push-destination-and-lease-details-unavailable",
        ),
        "git-recovery-destroy" => (
            "git-recovery-destroy blocked deletion of Git recovery history; keep stashes, reflogs, and recovery refs; ask the operator to verify they are no longer needed",
            Domain::Git,
            "git-recovery-selection-unavailable",
        ),
        "git-ref-delete" => (
            "git-ref-delete blocked deletion of a Git ref, stash entry, or worktree; preserve the selected state or ask the operator to verify its deletion",
            Domain::Git,
            "git-ref-active-selection-unavailable",
        ),
        "git-remote-repo-delete" => (
            "git-remote-repo-delete blocked deletion of an entire hosted repository; preserve the hosted project and ask the operator to verify any whole-repository deletion",
            Domain::Network,
            "network-delete-resource-kind-unavailable",
        ),
        "git-remote-resource-delete" => (
            "git-remote-resource-delete blocked deleting a hosted Git resource; keep it and ask the operator to perform the reviewed removal",
            Domain::Network,
            "network-delete-resource-kind-unavailable",
        ),
        "git-rewrite-force" => (
            "git-rewrite-force blocked a forced history rewrite; remove the force bypass and preview the rewrite; ask the operator to verify the affected history",
            Domain::Git,
            "git-history-active-mode-unavailable",
        ),
        "git-worktree-discard" => (
            "git-worktree-discard blocked a broad working-tree discard or forced worktree/submodule removal; inspect git diff and preserve wanted work in each affected tree, or ask the operator to perform the broad discard",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
        ),
        _ => unreachable!("Git query metadata exists for every program"),
    }
}

fn program(id: &'static str, default_enabled: bool, clauses: Vec<GuardClause>) -> GuardDefinition {
    let (reason, domain, gap_code) = metadata(id);
    GuardDefinition {
        id,
        reason,
        family: GuardFamily::Git,
        default_enabled,
        domain,
        gap_code: Some(gap_code),
        clauses,
    }
}

/// Every Git clause counts an effect at any position the invocation can reach,
/// not only on its success path: `git push || git push --force` force-pushes
/// exactly when the first push fails.
fn clause(query: Query, mut qualifiers: Vec<QueryQualifier>) -> GuardClause {
    qualifiers.push(QueryQualifier::FeasibleCondition);
    GuardClause {
        query,
        host: None,
        qualifiers,
    }
}

/// A push request on which `predicate` holds.
fn push_clause(predicate: GitPushPredicate) -> GuardClause {
    let query = Assertion::Any {
        assertions: push_terms(predicate)
            .into_iter()
            .map(|term| {
                push_assertion(with(
                    vec![
                        bool_attr("controls_complete", true),
                        bool_attr("dry_run", false),
                    ],
                    term,
                ))
            })
            .collect(),
    };
    clause(Query::new(query), vec![])
}

/// Each push predicate as alternative conjunctions of tests over a push
/// request. The engine joins every destination to its own properties: the
/// `updated_`, `deleted_`, `leased_` and `unleased_forced_destinations` lists
/// are present only when they name every destination and the property is
/// known for each, so an absent list is unknown. The `known_` lists and
/// `possibly_unleased_forced` hold only what is certain, and keep a partly
/// known push matching where one destination is.
fn push_terms(predicate: GitPushPredicate) -> Vec<Vec<AttributePredicate>> {
    let any_destination = || ElementTest::Text(TextPredicate::Any);
    let protected_branch = || {
        ElementTest::OneOf(vec![
            AttrValue::String("main".into()),
            AttrValue::String("master".into()),
        ])
    };
    // A deleting or `--all` push names no protected update; any other push
    // whose destinations the lists cannot enumerate may still update one.
    let explicit_destinations = || vec![bool_attr("delete", false), bool_attr("all", false)];
    // A protected destination named by the complete list, or by the witness
    // where a complete set also holds a destination the model cannot name,
    // such as `HEAD`.
    let protected_in = |list: &str, witness: &str| {
        vec![
            with(
                explicit_destinations(),
                vec![any_element(list, protected_branch())],
            ),
            with(
                explicit_destinations(),
                vec![
                    bool_attr("destination_complete", true),
                    any_element(witness, protected_branch()),
                ],
            ),
        ]
    };
    match predicate {
        GitPushPredicate::Force => [
            vec![bool_attr("explicit_force", true)],
            vec![bool_attr("mirror", true)],
            vec![any_element(
                "known_unleased_forced_destinations",
                any_destination(),
            )],
            vec![any_element(
                "unleased_forced_destinations",
                any_destination(),
            )],
            vec![bool_attr("possibly_unleased_forced", true)],
        ]
        .into_iter()
        // A lease does not make a force-push to a protected branch safe.
        .chain(protected_in(
            "leased_destinations",
            "known_leased_destinations",
        ))
        .collect(),
        GitPushPredicate::Protected => {
            protected_in("updated_destinations", "known_updated_destinations")
        }
        GitPushPredicate::History => vec![vec![bool_attr("lease_requested", true)]],
        GitPushPredicate::RefDelete => ["known_deleted_destinations", "deleted_destinations"]
            .into_iter()
            .map(|list| {
                with(
                    history_controls(),
                    vec![any_element(list, any_destination())],
                )
            })
            .collect(),
    }
}

fn push_assertion(attributes: Vec<AttributePredicate>) -> Assertion {
    effect_assertion(
        OperationMatch::Exact("git.push_request".into()),
        attributes,
        None,
        None,
        None,
    )
}

fn any_element(name: &str, test: ElementTest) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::AnyElement(test),
    }
}

/// A Git discard request selecting `side` of the observed Git root. The
/// bridge labels the request's repository with the side each path of its
/// `selections`, and the top `:/` names, lies on; a whole-tree discard selects
/// the root whatever it names.
fn selection_request(
    operation: &str,
    attributes: Vec<AttributePredicate>,
    side: GitSelection,
) -> Query {
    let whole_tree = || {
        vec![
            present_attr("scope"),
            string_attr("scope", "whole"),
            present_attr("broad"),
            bool_attr("broad", true),
        ]
    };
    let labeled = |label: NahLabel| {
        let mut assertion = request_assertion(
            operation,
            with(
                attributes.clone(),
                vec![bool_attr("selection_complete", true)],
            ),
        );
        if let Assertion::Effect { selector, .. } = &mut assertion {
            selector.resource = ResourcePredicate::Label {
                label: LabelId(label.label_id()),
                observation: ObservationBinding(LABEL_OBSERVATION.into()),
            };
        }
        assertion
    };
    let attribute_only = |attributes| {
        effect_assertion(
            OperationMatch::Exact(operation.into()),
            attributes,
            None,
            None,
            None,
        )
    };
    Query::new(match side {
        GitSelection::Root => Assertion::Any {
            assertions: vec![
                request_assertion(operation, with(attributes.clone(), whole_tree())),
                labeled(NahLabel::GitSelectsRoot),
            ],
        },
        // `:/` names the top, never a path below it, whatever else the
        // selection names.
        GitSelection::NamedNonRoot => Assertion::All {
            assertions: vec![
                labeled(NahLabel::GitSelectsNamedPath),
                Assertion::Not {
                    assertion: Box::new(attribute_only(whole_tree())),
                },
                Assertion::Not {
                    assertion: Box::new(attribute_only(vec![
                        present_attr("selects_top"),
                        bool_attr("selects_top", true),
                    ])),
                },
            ],
        },
    })
}

fn request(operation: &str, attributes: Vec<AttributePredicate>) -> Query {
    Query::new(request_assertion(operation, attributes))
}

fn request_assertion(operation: &str, attributes: Vec<AttributePredicate>) -> Assertion {
    effect_assertion(
        OperationMatch::Exact(operation.into()),
        attributes,
        Some(RequestAssurance::Exact),
        Some(Modality::MustOnSuccess),
        None,
    )
}

fn effect_assertion(
    operation: OperationMatch,
    attributes: Vec<AttributePredicate>,
    request_assurance: Option<RequestAssurance>,
    modality: Option<Modality>,
    realm: Option<RealmPredicate>,
) -> Assertion {
    Assertion::Effect {
        selector: Selector {
            operation,
            resource: ResourcePredicate::Any,
            attributes,
            request_assurance,
            condition: None,
            modality,
            execution_assurance: None,
            realm,
        },
        closure: None,
    }
}

fn history_controls() -> Vec<AttributePredicate> {
    vec![
        bool_attr("active", true),
        bool_attr("abort", false),
        bool_attr("dry_run", false),
    ]
}

fn with(
    mut attributes: Vec<AttributePredicate>,
    additional: Vec<AttributePredicate>,
) -> Vec<AttributePredicate> {
    attributes.extend(additional);
    attributes
}
