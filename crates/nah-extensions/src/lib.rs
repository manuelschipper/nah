#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Custom-guard extension lifecycle and exec/v1 transport.

mod activation;
mod bundle;
mod cache;
mod execution;
mod selection;
mod template;
mod transport;
mod trust;

pub use activation::{
    ActivationDatabase, ActivationError, ActivationRecord, activation_database_path,
    record_activation, remove_activation_by_identity,
};
pub use bundle::{
    ActiveExtensionCatalog, BundleError, ExtensionBundle, discover_bundles, guard_directory_path,
    load_active_extensions,
};
pub use cache::{CACHE_SIZE_CAP, MemoCache, memo_cache_path};
pub use execution::{
    ConsultationDiagnostic, ConsultationFailure, ConsultationOutput, consult_extensions,
};
pub use selection::request as exec_request;
pub use template::{create_project_guard, create_user_guard};
pub use transport::{EXEC_TIMEOUT, OUTPUT_SIZE_CAP};
pub use trust::{
    TrustDatabase, TrustError, record_project_activation, record_trusted_root, revoke_trusted_root,
    trust_database_path,
};
