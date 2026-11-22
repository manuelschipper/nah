//! Slow-changing context and guard settings contracts.

use serde::Deserialize;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    pub const V1: Self = Self(1);

    pub fn new(value: u32) -> Result<Self, CtxError> {
        nonzero_version(value).map(Self)
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AbsolutePath(String);

impl AbsolutePath {
    pub fn new(platform: Platform, value: impl Into<String>) -> Result<Self, CtxError> {
        let value = value.into();
        if is_absolute(platform, &value) {
            Ok(Self(value))
        } else {
            Err(CtxError::InvalidPath)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_absolute_on_any_platform(value: &str) -> bool {
        is_absolute(Platform::Linux, value) || is_absolute(Platform::Windows, value)
    }
}

impl<'de> Deserialize<'de> for AbsolutePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if Self::is_absolute_on_any_platform(&value) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom("invalid-path"))
        }
    }
}

fn is_absolute(platform: Platform, value: &str) -> bool {
    match platform {
        Platform::Linux | Platform::Macos => value.starts_with('/'),
        Platform::Windows => {
            if windows_device_namespace(value) {
                return false;
            }
            let bytes = value.as_bytes();
            value.strip_prefix("\\\\").is_some_and(|remainder| {
                let mut components = remainder.split(['\\', '/']);
                components.next().is_some_and(|part| !part.is_empty())
                    && components.next().is_some_and(|part| !part.is_empty())
            }) || (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'))
        }
    }
}

fn windows_device_namespace(value: &str) -> bool {
    value.starts_with(r"\\?\")
        || value.starts_with(r"\\.\")
        || value.starts_with("//?/")
        || value.starts_with("//./")
}

/// One of the nine guards of the taxonomy, named for what it protects. Every
/// shipped rule belongs to one; `self` is Nah's own self-protection, which has
/// no setting and cannot be turned off.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Guard {
    Work,
    Machine,
    RemoteCode,
    Infrastructure,
    Secrets,
    Exfiltration,
    UntrustedCode,
    Persistence,
    #[serde(rename = "self")]
    SelfProtection,
}

impl Guard {
    /// Every guard, in catalog order.
    pub const ALL: [Self; 9] = [
        Self::Work,
        Self::Machine,
        Self::RemoteCode,
        Self::Infrastructure,
        Self::Secrets,
        Self::Exfiltration,
        Self::UntrustedCode,
        Self::Persistence,
        Self::SelfProtection,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Machine => "machine",
            Self::RemoteCode => "remote-code",
            Self::Infrastructure => "infrastructure",
            Self::Secrets => "secrets",
            Self::Exfiltration => "exfiltration",
            Self::UntrustedCode => "untrusted-code",
            Self::Persistence => "persistence",
            Self::SelfProtection => "self",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|guard| guard.name() == name)
    }

    /// The guard a `guard/rule` ID names.
    pub fn of_rule(rule: &str) -> Option<Self> {
        Self::from_name(rule.split_once('/')?.0)
    }

    /// Whether the operator can change this guard's setting.
    pub const fn configurable(self) -> bool {
        !matches!(self, Self::SelfProtection)
    }
}

/// A guard's setting, ordered from least to most protective. A rule part
/// blocks when its rule's level is at or above the part's `applies_at`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardLevel {
    Off,
    Core,
    Strict,
}

impl GuardLevel {
    pub const ALL: [Self; 3] = [Self::Off, Self::Core, Self::Strict];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Core => "core",
            Self::Strict => "strict",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.name() == name)
    }
}

/// An operator's override of one rule: `enabled` runs every part of the rule
/// whatever its guard's setting, and `disabled` turns the rule off.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleOverride {
    Enabled,
    Disabled,
}

impl RuleOverride {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// The operator's guard settings: each guard's setting where it differs from
/// `core`, and each rule override. Rule IDs are not checked against the
/// shipped rules here; the caller that knows them does.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct GuardSettings {
    guards: BTreeMap<Guard, GuardLevel>,
    rules: BTreeMap<String, RuleOverride>,
    /// Rules an active nap pauses; never stored.
    #[serde(skip)]
    paused: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGuardSettings {
    guards: BTreeMap<Guard, GuardLevel>,
    rules: BTreeMap<String, RuleOverride>,
}

impl<'de> Deserialize<'de> for GuardSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawGuardSettings::deserialize(deserializer)?;
        Self::new(raw.guards, raw.rules).map_err(serde::de::Error::custom)
    }
}

impl GuardSettings {
    /// Rejects a setting for `self`, a stored `core` (the default is never
    /// stored), and an empty rule ID.
    pub fn new(
        guards: BTreeMap<Guard, GuardLevel>,
        rules: BTreeMap<String, RuleOverride>,
    ) -> Result<Self, CtxError> {
        if guards
            .iter()
            .any(|(guard, level)| !guard.configurable() || *level == GuardLevel::Core)
        {
            return Err(CtxError::InvalidGuardState);
        }
        if rules.keys().any(String::is_empty) {
            return Err(CtxError::EmptyIdentifier);
        }
        Ok(Self {
            guards,
            rules,
            paused: BTreeSet::new(),
        })
    }

    /// Every configurable guard at `level`, with no rule override.
    pub fn every_guard_at(level: GuardLevel) -> Self {
        let mut settings = Self::default();
        for guard in Guard::ALL {
            settings.set_guard(guard, level);
        }
        settings
    }

    pub fn guards(&self) -> &BTreeMap<Guard, GuardLevel> {
        &self.guards
    }

    pub fn rules(&self) -> &BTreeMap<String, RuleOverride> {
        &self.rules
    }

    /// The guard's setting; `core` unless the operator changed it.
    pub fn guard_level(&self, guard: Guard) -> GuardLevel {
        self.guards.get(&guard).copied().unwrap_or(GuardLevel::Core)
    }

    pub fn rule_override(&self, rule: &str) -> Option<RuleOverride> {
        self.rules.get(rule).copied()
    }

    /// Sets a configurable guard; `core` removes the stored setting.
    pub fn set_guard(&mut self, guard: Guard, level: GuardLevel) {
        if !guard.configurable() || level == GuardLevel::Core {
            self.guards.remove(&guard);
        } else {
            self.guards.insert(guard, level);
        }
    }

    /// Sets or, with `None`, removes the override of `rule`.
    pub fn set_rule(&mut self, rule: &str, value: Option<RuleOverride>) {
        match value {
            Some(value) => {
                self.rules.insert(rule.to_owned(), value);
            }
            None => {
                self.rules.remove(rule);
            }
        }
    }

    /// Pauses `rule` for an active nap: it runs at no level, whatever its
    /// override says.
    pub fn pause(&mut self, rule: &str) {
        self.paused.insert(rule.to_owned());
    }

    /// The level a rule runs at: this is the one place it is computed. A nap
    /// pauses it outright. Otherwise an override decides, and without one
    /// the guard's setting applies.
    pub fn rule_level(&self, rule: &str) -> GuardLevel {
        let guard = Guard::of_rule(rule).map_or(GuardLevel::Off, |guard| self.guard_level(guard));
        if self.paused.contains(rule) || Guard::of_rule(rule).is_none() {
            return GuardLevel::Off;
        }
        match self.rule_override(rule) {
            Some(RuleOverride::Enabled) => GuardLevel::Strict,
            Some(RuleOverride::Disabled) => GuardLevel::Off,
            None => guard,
        }
    }

    /// These settings with `rule` run whole, as an enabled rule runs; a nap
    /// still pauses it.
    pub fn with_rule_whole(&self, rule: &str) -> Self {
        let mut whole = self.clone();
        whole.set_rule(rule, Some(RuleOverride::Enabled));
        whole
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ctx {
    platform: Platform,
    home: AbsolutePath,
    guard_settings: GuardSettings,
}

impl Ctx {
    pub fn new(
        platform: Platform,
        home: AbsolutePath,
        guard_settings: GuardSettings,
    ) -> Result<Self, CtxError> {
        if !is_absolute(platform, home.as_str()) {
            return Err(CtxError::InvalidPath);
        }
        Ok(Self {
            platform,
            home,
            guard_settings,
        })
    }

    pub const fn platform(&self) -> Platform {
        self.platform
    }

    pub fn home(&self) -> &AbsolutePath {
        &self.home
    }

    pub fn guard_settings(&self) -> &GuardSettings {
        &self.guard_settings
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtxError {
    EmptyIdentifier,
    InvalidGuardState,
    InvalidPath,
    ZeroVersion,
}

impl CtxError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyIdentifier => "empty-identifier",
            Self::InvalidGuardState => "invalid-guard-state",
            Self::InvalidPath => "invalid-path",
            Self::ZeroVersion => "zero-version",
        }
    }
}

impl std::fmt::Display for CtxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

fn nonzero_version(value: u32) -> Result<u32, CtxError> {
    if value == 0 {
        Err(CtxError::ZeroVersion)
    } else {
        Ok(value)
    }
}
