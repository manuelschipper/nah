//! Declarative definitions for the destructive Git guards.

use effinterp_matcher::{
    Assertion, AttributePredicate, AttributeTest, ElementTest, LabelId, ObservationBinding,
    OperationMatch, Query, RealmPredicate, ResourcePredicate, Selector, TextPredicate,
};
use effinterp_proto::{AttrValue, Modality, RequestAssurance};
use nah_proto::ctx::GuardLevel;
use nah_proto::effects::Domain;
use nah_proto::labels::{LABEL_OBSERVATION, NahLabel};

use crate::guard_evaluation::QueryQualifier;
use crate::registry::{GuardClause, GuardDefinition};
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

/// The `work` parts 1.x ships off (path discards and every history rewrite)
/// apply only at `strict`, so `work` at `core` blocks exactly what 1.x
/// blocks by default. Path discards are nonetheless saved and run at `core`
/// where the runtime saves (`nah-cli`'s `save_then_run`), which reads them
/// from the plan rather than from these parts. Stash entry and local ref
/// deletes no longer wait for save-then-run, and a history rewrite that may
/// lose commits has a core part of its own.
const PENDING_SAVE_THEN_RUN: GuardLevel = GuardLevel::Strict;

/// The destructive Git rule parts, in definition order.
pub(crate) fn git_guard_definitions() -> Vec<GuardDefinition> {
    vec![
        program(
            "work/untracked-clean",
            GuardLevel::Core,
            "git-clean-force",
            "this would delete untracked files across the project. Git cannot bring them back; `git clean -n` shows what it would remove",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
            vec![git_guard_clause(
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
                vec![QueryQualifier::GitLossPossible],
            )],
        ),
        program(
            "remote-code/force-push",
            GuardLevel::Core,
            "git-force-push",
            "this would overwrite a branch's history on the remote, or delete its default branch. Other people's commits there may be lost",
            Domain::Git,
            "git-push-destination-and-lease-details-unavailable",
            vec![push_clause(GitPushPredicate::Force)],
        ),
        program(
            "work/changes-discard",
            GuardLevel::Core,
            "git-hard-reset",
            "this would discard the project's uncommitted changes. Git cannot bring back changes that were never staged",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
            vec![git_guard_clause(
                request(
                    "git.reset_request",
                    vec![
                        string_attr("reset_mode", "hard"),
                        bool_attr("dry_run", false),
                    ],
                ),
                vec![QueryQualifier::GitLossPossible],
            )],
        ),
        program(
            "work/history-rewrite",
            PENDING_SAVE_THEN_RUN,
            "git-history-rewrite",
            "this would rewrite the project's Git history. The commits it replaces may be hard to recover",
            Domain::Git,
            "git-history-active-mode-unavailable",
            vec![
                git_guard_clause(
                    Query::new(Assertion::All {
                        assertions: vec![
                            request_assertion("git.history_rewrite_request", history_controls()),
                            Assertion::Not {
                                assertion: Box::new(request_assertion(
                                    "git.history_rewrite_request",
                                    vec![string_attr("history_operation", "amend")],
                                )),
                            },
                        ],
                    }),
                    vec![],
                ),
                git_guard_clause(
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
                git_guard_clause(
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
                git_guard_clause(
                    request(
                        "git.recovery_destroy_request",
                        with(
                            history_controls(),
                            vec![present_attr("aggressive"), bool_attr("aggressive", true)],
                        ),
                    ),
                    vec![],
                ),
                git_guard_clause(
                    request(
                        "git.recovery_destroy_request",
                        with(history_controls(), vec![present_attr("prune")]),
                    ),
                    vec![],
                ),
            ],
        ),
        // A rewrite moves a ref from the commits it replaces. Where Git logs
        // that move, or `filter-branch` backs them up over no earlier backup,
        // they stay in reach and it loses nothing; where the runtime saves, a
        // snapshot answers one that may lose them (`save_then_run`). Every
        // reset that moves `HEAD` matches, and the qualifier passes one that
        // moves nothing.
        program(
            "work/history-rewrite",
            GuardLevel::Core,
            "git-history-rewrite",
            "this would rewrite the project's Git history where no reflog or backup keeps the commits it replaces. Once Git prunes them they cannot be brought back",
            Domain::Git,
            "git-history-active-mode-unavailable",
            vec![
                git_guard_clause(
                    Query::new(Assertion::All {
                        assertions: vec![
                            request_assertion("git.history_rewrite_request", history_controls()),
                            Assertion::Not {
                                assertion: Box::new(forced_filter()),
                            },
                        ],
                    }),
                    vec![QueryQualifier::GitHistoryLossPossible],
                ),
                git_guard_clause(
                    request(
                        "git.reset_request",
                        with(history_controls(), vec![string_attr("scope", "targeted")]),
                    ),
                    vec![QueryQualifier::GitHistoryLossPossible],
                ),
            ],
        ),
        program(
            "remote-code/force-push",
            GuardLevel::Strict,
            "git-history-rewrite",
            "this would overwrite a branch's history on the remote with a leased force push. Other people's commits there may be lost",
            Domain::Git,
            "git-history-active-mode-unavailable",
            vec![push_clause(GitPushPredicate::History)],
        ),
        program(
            "work/git-internals-modify",
            GuardLevel::Core,
            "git-metadata",
            "this would edit or delete Git's internal data in .git directly. It can corrupt the repository beyond repair; use Git commands instead",
            Domain::Filesystem,
            "resource-components-unavailable",
            [
                "filesystem.move",
                "filesystem.write",
                "filesystem.create",
                "filesystem.delete",
                "filesystem.metadata",
            ]
            .into_iter()
            .map(|operation| {
                git_guard_clause(
                    Query::new(effect_assertion(
                        OperationMatch::Exact(operation.into()),
                        vec![],
                        None,
                        None,
                        Some(RealmPredicate::Host),
                    )),
                    vec![QueryQualifier::GitMetadata, QueryQualifier::OwnerAccessLost],
                )
            })
            .collect(),
        ),
        git_hook_write(),
        program(
            "work/changes-discard",
            PENDING_SAVE_THEN_RUN,
            "git-path-discard",
            "this would discard uncommitted changes to the named files. Git cannot bring back changes that were never staged",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
            vec![
                git_guard_clause(
                    selection_request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["checkout", "restore", "switch"]),
                            bool_attr("dry_run", false),
                        ],
                        GitSelection::NamedNonRoot,
                    ),
                    vec![QueryQualifier::GitLossPossible],
                ),
                git_guard_clause(
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
            "remote-code/protected-branch-push",
            GuardLevel::Strict,
            "git-protected-push",
            "this would push straight to the `main` or `master` branch on the remote, skipping review. Pushed commits reach everyone at once and can be taken out only by new commits; push a feature branch instead",
            Domain::Git,
            "git-push-destination-and-lease-details-unavailable",
            vec![push_clause(GitPushPredicate::Protected)],
        ),
        // Clearing the whole stash is a stash loss; any other broad recovery
        // destruction (expiring every reflog, pruning) is a history loss.
        program(
            "work/stash-drop",
            GuardLevel::Core,
            "git-recovery-destroy",
            "this would delete every stash entry. They can be recovered only by finding their unreachable commits with `git fsck` before Git's garbage collection removes them",
            Domain::Git,
            "git-recovery-selection-unavailable",
            vec![git_guard_clause(
                split_on(
                    "git.recovery_destroy_request",
                    with(
                        history_controls(),
                        vec![string_attr("scope", "whole"), bool_attr("broad", true)],
                    ),
                    &[("stash", true)],
                ),
                vec![QueryQualifier::GitLossPossible],
            )],
        ),
        program(
            "work/history-rewrite",
            GuardLevel::Core,
            "git-recovery-destroy",
            "this would expire the reflog or prune unreachable commits, the history Git uses to recover lost work. Once removed it cannot be brought back",
            Domain::Git,
            "git-recovery-selection-unavailable",
            vec![git_guard_clause(
                split_on(
                    "git.recovery_destroy_request",
                    with(
                        history_controls(),
                        vec![string_attr("scope", "whole"), bool_attr("broad", true)],
                    ),
                    &[("stash", false)],
                ),
                vec![QueryQualifier::GitLossPossible],
            )],
        ),
        // A stash entry is a stash loss; a local branch, tag, ref, remote or
        // worktree is a branch loss; a destination a push deletes, or a remote
        // ref a mirror or `--prune` push removes, is a remote loss.
        // Where the runtime saves, a snapshot answers a drop at core
        // (`save_then_run`); an entry another ref reaches loses nothing.
        program(
            "work/stash-drop",
            GuardLevel::Core,
            "git-ref-delete",
            "this would drop a stash entry. It can be recovered only by finding its unreachable commit with `git fsck` before Git's garbage collection removes it",
            Domain::Git,
            "git-ref-active-selection-unavailable",
            vec![git_guard_clause(
                split_on(
                    "git.ref_delete_request",
                    history_controls(),
                    &[("stash", true)],
                ),
                vec![QueryQualifier::GitLossPossible],
            )],
        ),
        program(
            "remote-code/repo-delete",
            GuardLevel::Strict,
            "git-ref-delete",
            "this would delete a branch, tag or ref on the remote, for everyone who uses it. It can be restored only from a copy someone still has",
            Domain::Git,
            "git-ref-active-selection-unavailable",
            vec![
                git_guard_clause(
                    split_on(
                        "git.ref_delete_request",
                        history_controls(),
                        &[("stash", false), ("prune", true)],
                    ),
                    vec![],
                ),
                push_clause(GitPushPredicate::RefDelete),
            ],
        ),
        // Where the runtime saves, a snapshot answers a local ref delete at
        // core (`save_then_run`); one whose commits another ref reaches
        // loses nothing. Worktree and submodule removals are no ref delete
        // a snapshot answers, and stay strict.
        program(
            "work/branch-delete",
            GuardLevel::Core,
            "git-ref-delete",
            "this would delete a local branch, tag or ref. Commits only it reaches may be lost",
            Domain::Git,
            "git-ref-active-selection-unavailable",
            vec![git_guard_clause(
                split_on(
                    "git.ref_delete_request",
                    history_controls(),
                    &[("stash", false), ("prune", false)],
                ),
                vec![QueryQualifier::GitLossPossible],
            )],
        ),
        program(
            "work/branch-delete",
            GuardLevel::Strict,
            "git-ref-delete",
            "this would remove a linked worktree or a submodule's working tree. Their commits stay, but ignored files only it holds are lost",
            Domain::Git,
            "git-ref-active-selection-unavailable",
            vec![
                git_guard_clause(
                    request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["worktree_remove", "worktree_prune"]),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![],
                ),
                git_guard_clause(
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
            "remote-code/repo-delete",
            GuardLevel::Core,
            "git-remote-repo-delete",
            "this would delete a whole hosted repository with its history. It cannot be undone",
            Domain::Network,
            "network-delete-resource-kind-unavailable",
            vec![git_guard_clause(
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
        // Separate from deleting a repository or a remote ref: pruning a
        // release or a secret must not also allow deleting the repository.
        program(
            "remote-code/hosted-resource-delete",
            GuardLevel::Strict,
            "git-remote-resource-delete",
            "this would delete a hosted Git resource, such as a release, branch or cache. It may not be recoverable",
            Domain::Network,
            "network-delete-resource-kind-unavailable",
            vec![
                git_guard_clause(
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
                git_guard_clause(
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
                git_guard_clause(
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
            "work/history-rewrite",
            GuardLevel::Core,
            "git-rewrite-force",
            "this would force a history rewrite past Git's safety checks. Commits it drops may be lost",
            Domain::Git,
            "git-history-active-mode-unavailable",
            vec![git_guard_clause(
                Query::new(forced_filter()),
                vec![QueryQualifier::GitHistoryLossPossible],
            )],
        ),
        program(
            "work/changes-discard",
            GuardLevel::Core,
            "git-worktree-discard",
            "this would discard uncommitted changes across the project, or force-remove a worktree or submodule with its changes. Git cannot bring back changes that were never staged",
            Domain::Git,
            "git-discard-mode-and-selection-unavailable",
            vec![
                git_guard_clause(
                    selection_request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["checkout", "restore", "switch"]),
                            bool_attr("dry_run", false),
                        ],
                        GitSelection::Root,
                    ),
                    vec![QueryQualifier::GitLossPossible],
                ),
                git_guard_clause(
                    request(
                        "git.worktree_discard_request",
                        vec![
                            string_one_of("discard_mode", &["worktree_remove", "worktree_prune"]),
                            bool_attr("force", true),
                            bool_attr("dry_run", false),
                        ],
                    ),
                    vec![QueryQualifier::GitLossPossible],
                ),
                git_guard_clause(
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

/// Planting code for Git to run on a later command: a write, creation or move
/// into the repository's hook directory or over its `config` file, or a
/// `git config` write of a key whose value Git runs as a command. It is new
/// in 2.0, so it replaces no 1.x guard. `work/git-internals-modify` protects
/// history metadata, not these paths, and a change matching both reports
/// both.
fn git_hook_write() -> GuardDefinition {
    // A key the model reads names its section and variable. A write whose
    // key the model cannot account for (one the shell computes, an editor,
    // a section rename, an option it does not read) may set any of these,
    // so it matches too. A read, and `git remote`'s writes, state neither.
    let key = |section: &str, variables: &[&str]| {
        vec![
            present_attr("config_section"),
            string_attr("config_section", section),
            present_attr("config_variable"),
            string_one_of("config_variable", variables),
            bool_attr("unset", false),
        ]
    };
    let config_terms = vec![
        key(
            "core",
            &[
                "hookspath",
                "fsmonitor",
                "sshcommand",
                "pager",
                "editor",
                "askpass",
            ],
        ),
        key("sequence", &["editor"]),
        // `diff.external`, and `diff.<driver>.textconv` and `.command`.
        key("diff", &["external", "textconv", "command"]),
        key("filter", &["clean", "smudge", "process"]),
        key("merge", &["driver"]),
        // `credential.helper` and `gpg.program`, also scoped to a URL or
        // signature format (`credential.<url>.helper`, `gpg.ssh.program`).
        key("credential", &["helper"]),
        key("gpg", &["program"]),
        vec![
            present_attr("config_key_known"),
            bool_attr("config_key_known", false),
        ],
        // An alias whose value starts with `!` runs it in a shell, and one
        // whose value the shell computes may.
        vec![
            present_attr("config_section"),
            string_attr("config_section", "alias"),
            bool_attr("unset", false),
            present_attr("config_value_known"),
            bool_attr("config_value_known", false),
        ],
        vec![
            present_attr("config_section"),
            string_attr("config_section", "alias"),
            bool_attr("unset", false),
            present_attr("config_value"),
            AttributePredicate {
                name: "config_value".into(),
                test: AttributeTest::Text(TextPredicate::StartsWith("!".into())),
            },
        ],
    ];
    let config_clause = git_guard_clause(
        Query::new(Assertion::Any {
            assertions: config_terms
                .into_iter()
                .map(|attributes| {
                    effect_assertion(
                        OperationMatch::Exact("git.config_write".into()),
                        attributes,
                        None,
                        None,
                        None,
                    )
                })
                .collect(),
        }),
        vec![],
    );
    let mut clauses = ["filesystem.move", "filesystem.write", "filesystem.create"]
        .into_iter()
        .map(|operation| {
            git_guard_clause(
                Query::new(effect_assertion(
                    OperationMatch::Exact(operation.into()),
                    vec![],
                    None,
                    None,
                    Some(RealmPredicate::Host),
                )),
                vec![QueryQualifier::GitCodePath],
            )
        })
        .collect::<Vec<_>>();
    clauses.push(config_clause);
    GuardDefinition {
        rule: "persistence/git-hook-write",
        guard: crate::registry::rule_guard("persistence/git-hook-write"),
        applies_at: GuardLevel::Strict,
        replaces: None,
        reason: "this would install a Git hook or setting that runs a command on later Git calls, after this session ends. It can be removed later, but what it runs until then cannot be undone",
        domain: Domain::Filesystem,
        gap_code: Some("resource-components-unavailable"),
        clauses,
    }
}

fn program(
    rule: &'static str,
    applies_at: GuardLevel,
    replaces: &'static str,
    reason: &'static str,
    domain: Domain,
    gap_code: &'static str,
    clauses: Vec<GuardClause>,
) -> GuardDefinition {
    GuardDefinition {
        rule,
        guard: crate::registry::rule_guard(rule),
        applies_at,
        replaces: Some(replaces),
        reason,
        domain,
        gap_code: Some(gap_code),
        clauses,
    }
}

/// The request of `operation` with `attributes`, narrowed by whether each
/// listed boolean attribute is set: `("stash", true)` keeps only stash
/// requests, `("stash", false)` every other one. Splits that differ in one
/// selector together match exactly what the request alone matches.
fn split_on(
    operation: &str,
    attributes: Vec<AttributePredicate>,
    selectors: &[(&str, bool)],
) -> Query {
    let mut assertions = vec![request_assertion(operation, attributes)];
    for (attribute, set) in selectors {
        let selects = request_assertion(
            operation,
            vec![present_attr(attribute), bool_attr(attribute, true)],
        );
        assertions.push(if *set {
            selects
        } else {
            Assertion::Not {
                assertion: Box::new(selects),
            }
        });
    }
    Query::new(Assertion::All { assertions })
}

/// Every Git clause counts an effect at any position the invocation can reach,
/// not only on its success path: `git push || git push --force` force-pushes
/// exactly when the first push fails.
fn git_guard_clause(query: Query, mut qualifiers: Vec<QueryQualifier>) -> GuardClause {
    qualifiers.push(QueryQualifier::FeasibleCondition);
    GuardClause {
        query,
        host: None,
        qualifiers,
    }
}

/// The reason a push rule gives when the push request at `effect` names
/// `main` or `master` among the destinations the rule is about: forced
/// ones for `remote-code/force-push`, updated ones for
/// `remote-code/protected-branch-push`. `None` keeps the part's own reason.
/// Only those two names are spelled: a reason is logged, and other branch
/// names are the user's data.
pub(crate) fn push_reason(
    rule: &str,
    plan: &effinterp_proto::Plan,
    effect: usize,
) -> Option<String> {
    let push = &plan.effects[effect];
    if push.operation.as_str() != "git.push_request" {
        return None;
    }
    let protected = |lists: &[&str]| {
        lists
            .iter()
            .find_map(|list| match push.attributes.get(*list) {
                Some(AttrValue::List(items)) => items.iter().find_map(|item| match item {
                    AttrValue::String(name) if name == "main" || name == "master" => {
                        Some(name.clone())
                    }
                    _ => None,
                }),
                _ => None,
            })
    };
    match rule {
        "remote-code/force-push" => protected(&[
            "known_unleased_forced_destinations",
            "unleased_forced_destinations",
            "known_leased_destinations",
            "leased_destinations",
        ])
        .map(|branch| {
            format!(
                "this would overwrite the history of the `{branch}` branch on the remote. Other people's commits there may be lost"
            )
        }),
        "remote-code/protected-branch-push" => {
            protected(&["known_updated_destinations", "updated_destinations"]).map(|branch| {
                format!(
                    "this would push straight to the `{branch}` branch on the remote, skipping review. Pushed commits reach everyone at once and can be taken out only by new commits; push a feature branch instead"
                )
            })
        }
        _ => None,
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
    git_guard_clause(Query::new(query), vec![])
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
            vec![
                present_attr("default_branch_deleted"),
                bool_attr("default_branch_deleted", true),
            ],
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

/// A forced `git filter-branch` or `git filter-repo` request.
fn forced_filter() -> Assertion {
    request_assertion(
        "git.history_rewrite_request",
        with(
            history_controls(),
            vec![
                string_one_of("history_operation", &["filter-branch", "filter-repo"]),
                bool_attr("force", true),
            ],
        ),
    )
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
