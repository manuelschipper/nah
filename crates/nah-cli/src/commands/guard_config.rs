//! Typed guard configuration shared by text commands and the interactive UI.

use std::path::PathBuf;

use nah_proto::ctx::{GuardIdentity, GuardScope};

use crate::catalog::shipped_guards;

use super::{
    custom_guard_entries, disable_custom_guard, disable_custom_guard_scoped,
    disable_guard_identity, enable_custom_guard, enable_custom_guard_scoped, enable_guard_identity,
    set_shipped_guard, shipped_guard_entries, validate_guard_identity,
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
}

pub(crate) fn guard_entries() -> Result<Vec<GuardEntry>, String> {
    let mut entries = shipped_guard_entries()?;
    entries.extend(custom_guard_entries()?);
    Ok(entries)
}

pub(crate) fn set_guard_enabled(
    name: &str,
    enabled: bool,
    selector: &GuardSelector,
) -> Result<(), String> {
    if shipped_guards().contains(&name) {
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
    } else {
        match selector {
            GuardSelector::Any => disable_custom_guard(name),
            _ => disable_custom_guard_scoped(name, selector),
        }
    }
}

pub(crate) fn validate_guard_change(change: &GuardChange) -> Result<(), String> {
    match &change.target {
        GuardTarget::BuiltIn { name } => {
            if shipped_guards().contains(&name.as_str()) {
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

pub(crate) fn apply_guard_change(change: &GuardChange) -> Result<(), String> {
    match &change.target {
        GuardTarget::BuiltIn { name } => set_shipped_guard(name, change.enabled),
        GuardTarget::Custom { identity } if change.enabled => enable_guard_identity(
            identity,
            change
                .expected_hash
                .as_deref()
                .ok_or_else(|| "reviewed guard files hash is unavailable".to_owned())?,
        ),
        GuardTarget::Custom { identity } => disable_guard_identity(identity),
    }
}

pub(crate) const fn scope_name(scope: GuardScope) -> &'static str {
    match scope {
        GuardScope::User => "user",
        GuardScope::Project => "project",
    }
}
