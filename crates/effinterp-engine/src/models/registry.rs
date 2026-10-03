// The generated `generated_registry` below is test-only and names `BTreeMap`.
#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use super::lifecycle::{FrameworkLifecycle, LifecycleSig};
use crate::Lang;
use effinterp_model_schema::{CommandDeclaration, LifecycleLanguage, MODEL_SCHEMA_V1};

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
use compile::ModelValue;
pub(crate) use compile::{CompiledLibraryApi, builtin_lifecycles};
pub(super) use compile::{
    builtin_command_models, builtin_document_identities, builtin_library_apis, builtin_mcp_tools,
};
pub use compile::{compile_registry, compile_registry_with_builtin};
pub(crate) use mcp::CompiledMcpTool;
pub(super) use model::reviewed_read_operand;
use model::{CommandData, DeclarativeCommandModel};
pub(crate) use routes::forge_repository_delete_attributes;

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
