//! Typed guard configuration shared by text commands and the interactive UI.

use std::path::PathBuf;

use nah_proto::ctx::{GuardIdentity, GuardScope};

use crate::catalog::{GuardFamily, resolve_shipped_guard};

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
pub(crate) struct GuardChange {
    pub(crate) target: GuardTarget,
    pub(crate) enabled: bool,
    pub(crate) expected_hash: Option<String>,
    pub(crate) reset: bool,
}

/// Result of one explicit guard mutation, named by its current identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardMutation {
    pub(crate) canonical_name: String,
    pub(crate) warnings: Vec<String>,
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
) -> Result<GuardMutation, String> {
    if resolve_shipped_guard(name).is_some() {
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
        .map(|()| GuardMutation {
            canonical_name: name.to_owned(),
            warnings: vec![],
        })
    } else {
        match selector {
            GuardSelector::Any => disable_custom_guard(name),
            _ => disable_custom_guard_scoped(name, selector),
        }
        .map(|()| GuardMutation {
            canonical_name: name.to_owned(),
            warnings: vec![],
        })
    }
}

pub(crate) fn reset_guard(name: &str, selector: &GuardSelector) -> Result<GuardMutation, String> {
    if resolve_shipped_guard(name).is_none() {
        return Err(format!("guard `{name}` was not found"));
    }
    if selector != &GuardSelector::Any {
        return Err(format!(
            "built-in guard `{name}` is global; omit `--user` and `--project`"
        ));
    }
    reset_shipped_guard(name)
}

pub(crate) fn validate_guard_change(change: &GuardChange) -> Result<(), String> {
    match &change.target {
        GuardTarget::BuiltIn { name } => {
            if resolve_shipped_guard(name).is_some() {
                Ok(())
            } else {
                Err(format!("guard `{name}` was not found"))
            }
        }
        GuardTarget::Custom { identity } if change.enabled => {
            let expected_hash = change
                .expected_hash
                .as_deref()
                .ok_or_else(|| "reviewed guard files hash is unavailable".to_owned())?;
            validate_guard_identity(identity, Some(expected_hash))
        }
        GuardTarget::Custom { identity } => validate_guard_identity(identity, None),
    }
}

pub(crate) fn apply_guard_change(change: &GuardChange) -> Result<Vec<String>, String> {
    match &change.target {
        GuardTarget::BuiltIn { name } if change.reset => {
            reset_shipped_guard(name).map(|mutation| mutation.warnings)
        }
        GuardTarget::BuiltIn { name } => {
            set_shipped_guard(name, change.enabled).map(|mutation| mutation.warnings)
        }
        GuardTarget::Custom { identity } if change.enabled => enable_guard_identity(
            identity,
            change
                .expected_hash
                .as_deref()
                .ok_or_else(|| "reviewed guard files hash is unavailable".to_owned())?,
        )
        .map(|()| vec![]),
        GuardTarget::Custom { identity } => disable_guard_identity(identity).map(|()| vec![]),
    }
}

pub(crate) const fn scope_name(scope: GuardScope) -> &'static str {
    match scope {
        GuardScope::User => "user",
        GuardScope::Project => "project",
    }
}
