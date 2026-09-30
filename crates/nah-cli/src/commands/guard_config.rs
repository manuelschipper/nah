//! Typed guard configuration shared by text commands and the interactive UI.

use std::path::PathBuf;

use nah_proto::ctx::{GuardIdentity, GuardScope};

use crate::catalog::{GuardFamily, shipped_names};

use super::{
    custom_guard_entries, disable_custom_guard, disable_custom_guard_scoped,
    disable_guard_identity, enable_custom_guard, enable_custom_guard_scoped, enable_guard_identity,
    reset_shipped_guard, set_shipped_guard, shipped_guard_entries, validate_guard_identity,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuardSelector {
    Any,
    User,
    Project(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum GuardTarget {
    BuiltIn { name: String },
    Custom { identity: GuardIdentity },
}

impl GuardTarget {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::BuiltIn { name } => name,
            Self::Custom { identity } => identity.name(),
        }
    }

    pub(crate) const fn scope(&self) -> Option<GuardScope> {
        match self {
            Self::BuiltIn { .. } => None,
            Self::Custom { identity } => Some(identity.scope()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuardStatus {
    Enabled,
    Disabled,
    NeedsReapproval {
        approved_hash: String,
        current_hash: String,
    },
    Missing {
        approved_hash: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardEntry {
    pub(crate) target: GuardTarget,
    pub(crate) family: Option<GuardFamily>,
    pub(crate) default_enabled: Option<bool>,
    pub(crate) operator_override: Option<bool>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) status: GuardStatus,
    pub(crate) behavior: Option<String>,
    pub(crate) examples: Vec<String>,
    pub(crate) match_programs: Vec<String>,
    pub(crate) current_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuardChange {
    BuiltInEnable {
        name: String,
    },
    BuiltInDisable {
        name: String,
    },
    BuiltInReset {
        name: String,
    },
    CustomEnable {
        identity: GuardIdentity,
        expected_hash: String,
    },
    CustomDisable {
        identity: GuardIdentity,
    },
}

impl GuardChange {
    pub(crate) fn target(&self) -> GuardTarget {
        match self {
            Self::BuiltInEnable { name }
            | Self::BuiltInDisable { name }
            | Self::BuiltInReset { name } => GuardTarget::BuiltIn { name: name.clone() },
            Self::CustomEnable { identity, .. } | Self::CustomDisable { identity } => {
                GuardTarget::Custom {
                    identity: identity.clone(),
                }
            }
        }
    }
}

pub(crate) fn guard_entries() -> Result<(Vec<GuardEntry>, Vec<String>), String> {
    let (mut entries, diagnostics) = shipped_guard_entries()?;
    entries.extend(custom_guard_entries()?);
    Ok((entries, diagnostics))
}

pub(crate) fn set_guard_enabled(
    name: &str,
    enabled: bool,
    selector: &GuardSelector,
) -> Result<Vec<String>, String> {
    if shipped_names().contains(&name) {
        if selector != &GuardSelector::Any {
            Err(format!(
                "built-in guard `{name}` is global; omit `--user` and `--project`"
            ))
        } else {
            set_shipped_guard(name, enabled)
        }
    } else if enabled {
        match selector {
            GuardSelector::Any => enable_custom_guard(name),
            _ => enable_custom_guard_scoped(name, selector),
        }
        .map(|()| vec![])
    } else {
        match selector {
            GuardSelector::Any => disable_custom_guard(name),
            _ => disable_custom_guard_scoped(name, selector),
        }
        .map(|()| vec![])
    }
}

pub(crate) fn reset_guard(name: &str, selector: &GuardSelector) -> Result<Vec<String>, String> {
    if !shipped_names().contains(&name) {
        return Err(format!("guard `{name}` was not found"));
    }
    if selector != &GuardSelector::Any {
        return Err(format!(
            "built-in guard `{name}` is global; omit `--user` and `--project`"
        ));
    }
    reset_shipped_guard(name)
}

/// Guard change preflight, run over every staged change before any is applied.
/// Built-in changes only need a shipped guard name. A custom enable checks the
/// reviewed bundle hash against current discovery, and a custom disable checks
/// for an activation record; see `validate_guard_identity`.
///
/// Success is a point-in-time check, not a reservation or transaction: disk can
/// change before `apply_guard_change` writes, custom applies recheck live
/// state, and an earlier applied change stays written if a later one fails.
pub(crate) fn validate_guard_change(change: &GuardChange) -> Result<(), String> {
    match change {
        GuardChange::BuiltInEnable { name }
        | GuardChange::BuiltInDisable { name }
        | GuardChange::BuiltInReset { name } => {
            if shipped_names().contains(&name.as_str()) {
                Ok(())
            } else {
                Err(format!("guard `{name}` was not found"))
            }
        }
        GuardChange::CustomEnable {
            identity,
            expected_hash,
        } => validate_guard_identity(identity, Some(expected_hash)),
        GuardChange::CustomDisable { identity } => validate_guard_identity(identity, None),
    }
}

pub(crate) fn apply_guard_change(change: &GuardChange) -> Result<Vec<String>, String> {
    match change {
        GuardChange::BuiltInReset { name } => reset_shipped_guard(name),
        GuardChange::BuiltInEnable { name } => set_shipped_guard(name, true),
        GuardChange::BuiltInDisable { name } => set_shipped_guard(name, false),
        GuardChange::CustomEnable {
            identity,
            expected_hash,
        } => enable_guard_identity(identity, expected_hash).map(|()| vec![]),
        GuardChange::CustomDisable { identity } => {
            disable_guard_identity(identity).map(|()| vec![])
        }
    }
}

pub(crate) const fn scope_name(scope: GuardScope) -> &'static str {
    match scope {
        GuardScope::User => "user",
        GuardScope::Project => "project",
    }
}
