use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, CausalAssurance, Domain, Effect,
    ExecutionEdgeKind, ExecutionRealm, Operation, ProvenanceRef, ResourceExpr, ResourceFamily,
    ResourceIdentity, SourceDialect, Subject,
};

use super::args::{FlagSpec, basename, dirname, scan_with_named_values};
use super::lifecycle::{FrameworkLifecycle, LifecycleSig};
use super::{CommandModel, InvocationCtx, ModelBindingEnd, ModelCausalBinding};
use crate::Lang;
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::nest::{Transition, word_resource};
use crate::resource_transfer::TransferBinding;
use crate::word::{Word, WordPart};
use effinterp_model_schema::{
    ApiRouteConditionDeclaration, ApiRouteSegmentKind, ApiRouteShapeDeclaration,
    AssignmentValueKind, AttributeDeclaration, BehaviorDeclaration, BindingEndDeclaration,
    COMPILER_SCHEMA_V2, CallableTargetDeclaration, CommandDeclaration, Declaration,
    DeclarationDocument, EffectRuleDeclaration, EffectSourceDeclaration,
    EnvironmentGateDeclaration, LauncherAttachmentDeclaration, LauncherOptionClassDeclaration,
    LibraryApiDeclaration, LifecycleDeclaration, LifecycleLanguage, LiteralShapeDeclaration,
    MODEL_SCHEMA_V1, NestedSourceFrom, OperandKind, OperandSelection, PermissionGrant,
    RealmDeclaration, ResourceDeclaration, RuleConditionDeclaration, SubcommandDeclaration,
    UrlComponent, ValueDeclaration,
};

use effinterp_model_schema::{declaration_digest, document_content_identity};

include!(concat!(env!("OUT_DIR"), "/promoted_models.rs"));

mod compile;
mod invocation;
pub(crate) mod launcher;
mod literals;
mod mcp;
mod model;
mod routes;
mod validate;

pub(crate) use compile::CompiledRegistry;
#[cfg(test)]
pub(crate) use compile::builtin_registry;
pub(crate) use compile::{CompiledLibraryApi, builtin_lifecycles};
use compile::{ModelValue, leak_string, leak_strings};
pub(super) use compile::{
    builtin_command_models, builtin_document_identities, builtin_library_apis, builtin_mcp_tools,
};
pub use compile::{compile_registry, compile_registry_with_builtin};
use invocation::{
    ParsedInvocation, classify_path_or_url, nested_source_subject, resource_values,
    value_environment_provenance_names, value_flag_names,
};
use literals::{
    attached_boolean_value, audited_go_duration, audited_go_integer, audited_http_header_field,
    audited_repository_selector, audited_short_boolean_value, percent_decode,
    proven_go_template_subset, proven_permission_mode, safe_route_component, valid_go_identifier,
};
pub(crate) use mcp::CompiledMcpTool;
pub(super) use model::reviewed_read_operand;
use model::{CommandData, DeclarativeCommandModel};
use routes::api_route_matches;
pub(crate) use routes::forge_repository_delete_attributes;
use validate::{
    behavior_domains, callable_target, collect_command_flags, command_behaviors, command_domains,
    invalid, lifecycle_target, resource_family, resource_uses_ambient_cwd, validate_command,
    validate_document, validate_id, validate_library_api, validate_lifecycle, validate_mcp_tool,
};

/// Why model documents failed to compile into a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    Json(String),
    WrongSchema(String),
    IdentityMismatch {
        expected: String,
        actual: String,
    },
    DuplicateId(String),
    CommandOwnership {
        command: String,
        first: String,
        second: String,
    },
    InvalidDeclaration {
        id: String,
        detail: String,
    },
    LifecycleConflict {
        first: String,
        second: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid declaration JSON: {error}"),
            Self::WrongSchema(schema) => {
                write!(
                    f,
                    "declaration schema {schema:?} is not {MODEL_SCHEMA_V1:?}"
                )
            }
            Self::IdentityMismatch { expected, actual } => write!(
                f,
                "promoted identity {actual:?} does not match content identity {expected:?}"
            ),
            Self::DuplicateId(id) => write!(f, "duplicate declaration id {id:?}"),
            Self::CommandOwnership {
                command,
                first,
                second,
            } => write!(
                f,
                "command {command:?} is owned by both {first:?} and {second:?}"
            ),
            Self::InvalidDeclaration { id, detail } => {
                write!(f, "invalid declaration {id:?}: {detail}")
            }
            Self::LifecycleConflict { first, second } => write!(
                f,
                "lifecycle declarations {first:?} and {second:?} contain conflicting signatures"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}
