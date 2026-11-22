//! The shipped guard registry (`shipped_guard_definitions`) and the rule
//! part and clause types it holds. Each 1.x guard family's parts live in
//! their own module.

use effinterp_matcher::{Absence, Query};
use nah_proto::ctx::{Guard, GuardLevel};
use nah_proto::effects::Domain;

/// One part of a shipped rule: the clauses of one 1.x guard that landed in
/// this rule. A rule is every part that names it, and a 1.x guard split
/// across rules became one part per destination, its clauses moved unchanged.
pub struct GuardDefinition {
    /// The rule this part belongs to, as its `guard/rule` ID.
    pub rule: &'static str,
    pub guard: Guard,
    /// The lowest rule level at which this part blocks: `core` or `strict`.
    pub applies_at: GuardLevel,
    /// The one 1.x guard whose clauses this part holds, or `None` for a part
    /// new in 2.0. Only the 1.x import and the CLI's error for a 1.x name
    /// read it.
    pub replaces: Option<&'static str>,
    pub reason: &'static str,
    pub domain: Domain,
    /// The coverage gap an indeterminate query names on its call. A part
    /// whose predicate never named one leaves an indeterminate query silent.
    pub gap_code: Option<&'static str>,
    /// The part matches when any clause does.
    pub clauses: Vec<GuardClause>,
}

impl GuardDefinition {
    /// Whether the part matches only Git history rewrites that may leave
    /// commits out of every ref's and reflog's reach: a snapshot of those
    /// commits answers it where the runtime saves.
    pub fn rewrites_history(&self) -> bool {
        self.clauses.iter().all(|clause| {
            clause.qualifiers.iter().any(|qualifier| {
                matches!(
                    qualifier,
                    crate::guard_evaluation::QueryQualifier::GitHistoryLossPossible
                )
            })
        })
    }
}

/// One clause of a shipped guard definition: an engine query and what Nah
/// still decides beside it.
pub struct GuardClause {
    pub query: Query,
    /// What Nah still decides beside the engine query: its host path catalogs
    /// and the filesystem family's eligibility. `None` when the query alone
    /// decides. A clause that binds effects never binds one this rejects.
    pub host: Option<crate::filesystem_guards::HostRule>,
    /// What Nah still decides about a matched effect that the query language
    /// cannot state; every qualifier must hold. Empty when the query decides.
    pub qualifiers: Vec<crate::guard_evaluation::QueryQualifier>,
}

/// The part of remote-script-run that reads Claude Code's session ledger.
pub const FETCHED_CODE_RUN: GuardDefinition = GuardDefinition {
    rule: "untrusted-code/remote-script-run",
    guard: Guard::UntrustedCode,
    applies_at: GuardLevel::Strict,
    replaces: None,
    reason: "this would let code fetched during this session run. Its effects may be hard to undo, and the request may come from a prompt injection",
    domain: Domain::Execution,
    gap_code: None,
    clauses: Vec::new(),
};

/// The shipped guard registry: every shipped rule part, in evaluation order,
/// each query validated for conclusive absence, the only way
/// `ShippedGuards::evaluate` answers it. It is the single source of shipped
/// rule IDs, their parts and reasons; `ShippedGuards` holds it built once.
pub(crate) fn shipped_guard_definitions() -> Vec<GuardDefinition> {
    let mut definitions = vec![
        crate::package_registry_guards::registry_publish(),
        crate::package_registry_guards::registry_unpublish(),
        crate::system_guards::sys_power(),
        crate::system_guards::sys_service_stop(),
        crate::infrastructure_guards::infra_container_reset(),
        crate::infrastructure_guards::infra_container_volume_delete(),
        crate::infrastructure_guards::infra_iac_destroy(),
        crate::infrastructure_guards::infra_k8s_delete(),
        crate::infrastructure_guards::storage_backup_destroy(),
        crate::infrastructure_guards::storage_recursive_delete(),
        crate::infrastructure_guards::storage_snapshot_delete(),
        crate::database_guards::db_destroy(),
        crate::secret_guards::store_read(),
        crate::secret_guards::store_delete(),
        crate::secret_guards::store_destroy(),
    ];
    definitions.extend([
        crate::flow_guards::exec_remote(),
        crate::flow_guards::exec_decoded(),
        crate::flow_guards::embedded_archive_write(),
        crate::execution_guards::exec_obfuscated(),
        crate::flow_guards::exec_network_shell(),
        crate::secret_guards::credentials(),
        crate::secret_guards::environment(),
        crate::flow_guards::secrets_exfil(),
        crate::flow_guards::linked_tree_export(),
        crate::network_guards::lookalike_host(),
        crate::dependency_guards::lookalike_package(GuardLevel::Core),
        crate::dependency_guards::lookalike_package(GuardLevel::Strict),
    ]);
    definitions.extend(crate::git_guards::git_guard_definitions());
    definitions.extend(crate::filesystem_guards::filesystem_guard_definitions());
    definitions.push(FETCHED_CODE_RUN);
    for definition in &definitions {
        assert!(
            Guard::of_rule(definition.rule) == Some(definition.guard)
                && definition.guard.configurable()
                && definition.applies_at != GuardLevel::Off,
            "{} is a part of a configurable guard that applies at core or strict",
            definition.rule
        );
    }
    for clause in definitions
        .iter()
        .flat_map(|definition| &definition.clauses)
    {
        clause
            .query
            .validate_for(Absence::Conclusive)
            .expect("built-in guard definition must be valid");
    }
    definitions
}

/// The guard `rule`'s ID names.
pub(crate) fn rule_guard(rule: &str) -> Guard {
    Guard::of_rule(rule).expect("a shipped rule ID names its guard")
}

pub(crate) fn engine_only(query: Query) -> Vec<GuardClause> {
    vec![GuardClause {
        query,
        host: None,
        qualifiers: Vec::new(),
    }]
}
