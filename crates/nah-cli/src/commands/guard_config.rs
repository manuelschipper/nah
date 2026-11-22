//! Typed guard configuration shared by text commands and the interactive UI.

use nah_proto::ctx::{Guard, GuardLevel, GuardSettings, RuleOverride};

use crate::catalog::{legacy_name_error, rule_ids, rule_span};

use super::{set_shipped_guard, set_shipped_rule, shipped_guard_entries};

/// What one guards-screen row or text command configures: one of the nine
/// guards or one shipped rule.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum GuardTarget {
    Guard { guard: Guard },
    Rule { rule: String },
}

impl GuardTarget {
    /// The name `nah guards` lists: the guard or the rule ID.
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Guard { guard } => guard.name().to_owned(),
            Self::Rule { rule } => rule.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardStatus {
    Enabled,
    Disabled,
}

/// How much of a rule runs at its level: every part, only the parts that
/// apply at core, or none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleState {
    On,
    CoreOnly,
    Off,
}

impl RuleState {
    pub(crate) fn of(rule: &str, level: GuardLevel) -> Self {
        let (lowest, highest) = rule_span(rule);
        if level >= highest {
            Self::On
        } else if level >= lowest {
            Self::CoreOnly
        } else {
            Self::Off
        }
    }

    pub(crate) const fn marker(self) -> &'static str {
        match self {
            Self::On => "[x]",
            Self::CoreOnly => "[~]",
            Self::Off => "[ ]",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardEntry {
    pub(crate) target: GuardTarget,
    /// A guard's stored setting; `core` for every other target.
    pub(crate) setting: GuardLevel,
    /// A rule's stored override.
    pub(crate) rule_override: Option<RuleOverride>,
    /// `Enabled` unless its stored settings leave it off; screens recompute
    /// it as changes stage.
    pub(crate) status: GuardStatus,
    pub(crate) behavior: Option<String>,
    pub(crate) examples: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuardChange {
    /// Sets a guard; `core` is its reset.
    GuardSet { guard: Guard, level: GuardLevel },
    /// Sets a rule's override; `None` is its reset.
    RuleSet {
        rule: String,
        value: Option<RuleOverride>,
    },
}

impl GuardChange {
    pub(crate) fn target(&self) -> GuardTarget {
        match self {
            Self::GuardSet { guard, .. } => GuardTarget::Guard { guard: *guard },
            Self::RuleSet { rule, .. } => GuardTarget::Rule { rule: rule.clone() },
        }
    }
}

/// The settings the guard and rule entries store.
pub(crate) fn entry_settings(entries: &[GuardEntry]) -> GuardSettings {
    let mut settings = GuardSettings::default();
    for entry in entries {
        match &entry.target {
            GuardTarget::Guard { guard } => settings.set_guard(*guard, entry.setting),
            GuardTarget::Rule { rule } => settings.set_rule(rule, entry.rule_override),
        }
    }
    settings
}

pub(crate) fn guard_entries() -> Result<(Vec<GuardEntry>, Vec<String>), String> {
    shipped_guard_entries()
}

/// Parses a configurable guard name, naming the rules a 1.x guard became.
pub(crate) fn configurable_guard(name: &str) -> Result<Guard, String> {
    match Guard::from_name(name) {
        Some(guard) if guard.configurable() => Ok(guard),
        Some(guard) => Err(format!(
            "guard `{}` is always on and has no setting",
            guard.name()
        )),
        None => Err(legacy_name_error(name).unwrap_or_else(|| {
            format!("guard `{name}` was not found; run `nah guards` to list guards")
        })),
    }
}

/// `nah guard set <guard> <setting>`.
pub(crate) fn set_guard_setting(guard: &str, setting: &str) -> Result<Vec<String>, String> {
    let guard = configurable_guard(guard)?;
    let level = GuardLevel::from_name(setting)
        .ok_or_else(|| format!("unknown setting `{setting}`; use off, core, or strict"))?;
    set_shipped_guard("nah guard set", guard, level)
}

/// `nah guard reset <guard>`: back to `core`.
pub(crate) fn reset_guard_setting(guard: &str) -> Result<Vec<String>, String> {
    set_shipped_guard(
        "nah guard reset",
        configurable_guard(guard)?,
        GuardLevel::Core,
    )
}

/// `nah rule enable|disable <guard/rule>`.
pub(crate) fn set_rule_enabled(name: &str, enabled: bool) -> Result<Vec<String>, String> {
    let rule = shipped_rule(name)?;
    set_shipped_rule(
        if enabled {
            "nah rule enable"
        } else {
            "nah rule disable"
        },
        rule,
        Some(if enabled {
            RuleOverride::Enabled
        } else {
            RuleOverride::Disabled
        }),
    )
}

/// `nah rule reset <guard/rule>`: the rule follows its guard's setting again.
pub(crate) fn reset_rule(name: &str) -> Result<Vec<String>, String> {
    set_shipped_rule("nah rule reset", shipped_rule(name)?, None)
}

fn shipped_rule<'a>(name: &str) -> Result<&'a str, String> {
    rule_ids()
        .iter()
        .copied()
        .find(|rule| *rule == name)
        .ok_or_else(|| {
            legacy_name_error(name).unwrap_or_else(|| {
                format!("rule `{name}` was not found; run `nah guards` to list rules")
            })
        })
}

/// Guard change preflight, run over every staged change before any is applied:
/// a configurable guard or a shipped rule.
///
/// Success is a point-in-time check, not a reservation or transaction: disk can
/// change before `apply_guard_change` writes, and an earlier applied change
/// stays written if a later one fails.
pub(crate) fn validate_guard_change(change: &GuardChange) -> Result<(), String> {
    match change {
        GuardChange::GuardSet { guard, .. } => configurable_guard(guard.name()).map(|_| ()),
        GuardChange::RuleSet { rule, .. } => shipped_rule(rule).map(|_| ()),
    }
}

pub(crate) fn apply_guard_change(change: &GuardChange) -> Result<Vec<String>, String> {
    match change {
        GuardChange::GuardSet { guard, level } => set_shipped_guard("nah tui", *guard, *level),
        GuardChange::RuleSet { rule, value } => {
            set_shipped_rule("nah tui", shipped_rule(rule)?, *value)
        }
    }
}
