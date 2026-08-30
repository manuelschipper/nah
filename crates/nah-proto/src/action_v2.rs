//! Per-effect labels attached to effectinterp plans.

use crate::action::{HostIntegrityClass, NahProtectionTier, PathScope, Sensitivity};
use crate::ctx::AbsolutePath;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectAnnotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathLabel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_cli: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PathLabel {
    Resolved {
        path: AbsolutePath,
        scope: PathScope,
        sensitivity: Sensitivity,
        #[serde(skip_serializing_if = "Option::is_none")]
        protection: Option<NahProtectionTier>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host_integrity: Option<HostIntegrityClass>,
        selects_root: bool,
        selects_home: bool,
    },
    Unresolved,
}
