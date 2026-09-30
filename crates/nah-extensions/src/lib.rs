#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Custom-guard extension lifecycle and exec/v2 transport.

mod activation;
mod bundle;
mod cache;
mod execution;
mod memo;
mod selection;
mod template;
mod transport;
mod trust;
mod user_state;

pub use activation::{
    ActivationDatabase, ActivationError, ActivationRecord, activation_database_path,
    record_activation, remove_activation_by_identity,
};
pub use bundle::{
    ActiveExtensionCatalog, BundleError, ExtensionBundle, discover_bundles, load_active_extensions,
};
pub use cache::{CacheError, MemoCache, memo_cache_path};
pub use execution::{
    ConsultationDiagnostic, ConsultationFailure, ConsultationOutput, consult_extensions,
};
pub use memo::MemoContext;
pub use selection::exec_request;
pub use template::{TemplateError, create_project_guard, create_user_guard};
pub use transport::EXEC_TIMEOUT;
pub use trust::{
    TrustDatabase, TrustError, record_project_activation, record_trusted_root, revoke_trusted_root,
    trust_database_path,
};
