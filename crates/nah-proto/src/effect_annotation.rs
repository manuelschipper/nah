//! Per-effect labels attached to effinterp plans.

use crate::ctx::AbsolutePath;
use crate::labels::{HostIntegrityClass, NahProtectionTier, PathScope, SelfRule, Sensitivity};
use serde::{Deserialize, Serialize};

/// Nah-owned labels for the effect at the same index in the engine plan.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectAnnotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathLabel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_cli: Option<String>,
}

/// Nah's evaluation of a filesystem effect's resource expression: `Resolved`
/// once the expression names one lexically normalized absolute path,
/// `Unresolved` while it stays symbolic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PathLabel {
    Resolved {
        path: AbsolutePath,
        scope: PathScope,
        sensitivity: Sensitivity,
        #[serde(skip_serializing_if = "Option::is_none")]
        protection: Option<NahProtectionTier>,
        /// The `self` rule a blocking `protection` falls under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        self_rule: Option<SelfRule>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host_integrity: Option<HostIntegrityClass>,
        selects_root: bool,
        selects_home: bool,
        selects_home_folder: bool,
    },
    Unresolved,
}
