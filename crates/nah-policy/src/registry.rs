//! The shipped guard registry (`shipped_guard_definitions`) and the
//! definition, clause and family types it holds. Each guard family's
//! definitions live in their own module.

use effinterp_matcher::{Absence, Query};
use nah_proto::effects::Domain;

/// The guard family a shipped guard belongs to: the grouping the README
/// inventory and the guard catalog show. Storage guards belong to
/// infrastructure, and secret exfiltration to secrets.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GuardFamily {
    Execution,
    Filesystem,
    Git,
    Infrastructure,
    Registry,
    Secrets,
    System,
}

impl GuardFamily {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Execution => "EXECUTION",
            Self::Filesystem => "FILESYSTEM",
            Self::Git => "GIT",
            Self::Infrastructure => "INFRASTRUCTURE",
            Self::Registry => "REGISTRY",
            Self::Secrets => "SECRETS",
            Self::System => "SYSTEM",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Filesystem => "filesystem",
            Self::Git => "git",
            Self::Infrastructure => "infrastructure",
            Self::Registry => "registry",
            Self::Secrets => "secrets",
            Self::System => "system",
        }
    }

    pub const fn rank(self) -> usize {
        match self {
            Self::Execution => 0,
            Self::Filesystem => 1,
            Self::Git => 2,
            Self::Infrastructure => 3,
            Self::Registry => 4,
            Self::Secrets => 5,
            Self::System => 6,
        }
    }
}

/// One shipped guard definition in the registry `shipped_guard_definitions`
/// builds.
pub struct GuardDefinition {
    pub id: &'static str,
    pub reason: &'static str,
    pub family: GuardFamily,
    /// Whether the guard ships enabled. Saved settings override it.
    pub default_enabled: bool,
    pub domain: Domain,
    /// The coverage gap an indeterminate query names on its call. A guard
    /// whose predicate never named one leaves an indeterminate query silent.
    pub gap_code: Option<&'static str>,
    /// The guard matches when any clause does.
    pub clauses: Vec<GuardClause>,
}

/// One clause of a shipped guard definition: an engine query and what Nah
/// still decides beside it.
pub struct GuardClause {
    pub query: Query,
    /// What Nah still decides beside the engine query: its host path catalogs
    /// and the filesystem family's eligibility. `None` when the query alone
    /// decides. A clause that binds effects never binds one this rejects.
    pub host: Option<crate::filesystem_queries::HostRule>,
    /// What Nah still decides about a matched effect that the query language
    /// cannot state; every qualifier must hold. Empty when the query decides.
    pub qualifiers: Vec<crate::guard_evaluation::QueryQualifier>,
}

/// The shipped guard registry: every shipped guard definition, in evaluation
/// order, each query validated for conclusive absence, the only way
/// `ShippedGuards::evaluate` answers it. It is the single source of shipped
/// guard ids, reasons and families; `ShippedGuards` holds it built once.
pub(crate) fn shipped_guard_definitions() -> Vec<GuardDefinition> {
    let mut definitions = vec![
        crate::simple_guards::registry_publish(),
        crate::simple_guards::registry_unpublish(),
        crate::simple_guards::sys_power(),
        crate::simple_guards::sys_service_stop(),
        crate::simple_guards::infra_container_reset(),
        crate::simple_guards::infra_container_volume_delete(),
        crate::simple_guards::infra_iac_destroy(),
        crate::simple_guards::infra_k8s_delete(),
        crate::simple_guards::storage_backup_destroy(),
        crate::simple_guards::storage_recursive_delete(),
        crate::simple_guards::storage_snapshot_delete(),
        crate::database_guards::db_destroy(),
        crate::secret_guards::store_read(),
        crate::secret_guards::store_delete(),
        crate::secret_guards::store_destroy(),
    ];
    definitions.extend([
        crate::flow_queries::exec_remote(),
        crate::flow_queries::exec_decoded(),
        crate::execution_guards::exec_obfuscated(),
        crate::flow_queries::exec_network_shell(),
        crate::secret_guards::credentials(),
        crate::secret_guards::environment(),
        crate::flow_queries::secrets_exfil(),
    ]);
    definitions.extend(crate::git_queries::definitions());
    definitions.extend(crate::filesystem_queries::definitions());
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

pub(crate) fn engine_only(query: Query) -> Vec<GuardClause> {
    vec![GuardClause {
        query,
        host: None,
        qualifiers: Vec::new(),
    }]
}
