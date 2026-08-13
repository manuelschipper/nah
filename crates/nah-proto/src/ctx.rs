//! Slow-changing context and guard identity contracts.

use crate::observation::Observation;
use crate::observation::ProjectGuardDeclaration;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_GUARD_NAME_BYTES: usize = 64;

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PolicyVersion(u32);

impl PolicyVersion {
    pub const V1: Self = Self(1);
    pub const V2: Self = Self(2);
    pub const V3: Self = Self(3);

    pub fn new(value: u32) -> Result<Self, CtxError> {
        nonzero_version(value).map(Self)
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for PolicyVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ExecProtocolVersion(u32);

impl ExecProtocolVersion {
    pub const V1: Self = Self(1);

    pub fn new(value: u32) -> Result<Self, CtxError> {
        nonzero_version(value).map(Self)
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ExecProtocolVersion {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardScope {
    User,
    Project,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TrustedRootId(String);

impl TrustedRootId {
    pub fn new(value: impl Into<String>) -> Result<Self, CtxError> {
        non_empty(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TrustedRootId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentHash(String);

impl ContentHash {
    pub fn new(value: impl Into<String>) -> Result<Self, CtxError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(CtxError::InvalidContentHash)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GuardIdentity {
    scope: GuardScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_root: Option<TrustedRootId>,
    name: String,
}

#[derive(Deserialize)]
struct RawGuardIdentity {
    scope: GuardScope,
    #[serde(default)]
    trusted_root: Option<TrustedRootId>,
    name: String,
}

impl<'de> Deserialize<'de> for GuardIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawGuardIdentity::deserialize(deserializer)?;
        match (raw.scope, raw.trusted_root) {
            (GuardScope::User, None) => Self::user(raw.name),
            (GuardScope::Project, Some(root)) => Self::project(root, raw.name),
            _ => Err(CtxError::InvalidIdentity),
        }
        .map_err(serde::de::Error::custom)
    }
}

impl GuardIdentity {
    pub fn user(name: impl Into<String>) -> Result<Self, CtxError> {
        Ok(Self {
            scope: GuardScope::User,
            trusted_root: None,
            name: guard_name(name)?,
        })
    }

    pub fn project(trusted_root: TrustedRootId, name: impl Into<String>) -> Result<Self, CtxError> {
        Ok(Self {
            scope: GuardScope::Project,
            trusted_root: Some(trusted_root),
            name: guard_name(name)?,
        })
    }

    pub const fn scope(&self) -> GuardScope {
        self.scope
    }

    pub fn trusted_root(&self) -> Option<&TrustedRootId> {
        self.trusted_root.as_ref()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ShippedGuardState {
    name: String,
    enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    explicitly_disabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShippedGuardState {
    name: String,
    enabled: bool,
    #[serde(default)]
    explicitly_disabled: bool,
}

impl<'de> Deserialize<'de> for ShippedGuardState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawShippedGuardState::deserialize(deserializer)?;
        Self::with_explicit_disable(raw.name, raw.enabled, raw.explicitly_disabled)
            .map_err(serde::de::Error::custom)
    }
}

impl ShippedGuardState {
    pub fn new(name: impl Into<String>, enabled: bool) -> Result<Self, CtxError> {
        Self::with_explicit_disable(name, enabled, false)
    }

    pub fn with_explicit_disable(
        name: impl Into<String>,
        enabled: bool,
        explicitly_disabled: bool,
    ) -> Result<Self, CtxError> {
        if enabled && explicitly_disabled {
            return Err(CtxError::InvalidGuardState);
        }
        Ok(Self {
            name: non_empty(name)?,
            enabled,
            explicitly_disabled,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn explicitly_disabled(&self) -> bool {
        self.explicitly_disabled
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct TrustedRoot {
    identity: TrustedRootId,
    path: AbsolutePath,
}

impl TrustedRoot {
    pub fn new(identity: TrustedRootId, path: AbsolutePath) -> Self {
        Self { identity, path }
    }

    pub fn identity(&self) -> &TrustedRootId {
        &self.identity
    }

    pub fn path(&self) -> &AbsolutePath {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustProjection {
    trusted_roots: Vec<TrustedRoot>,
}

#[derive(Deserialize)]
struct RawTrustProjection {
    trusted_roots: Vec<TrustedRoot>,
}

impl<'de> Deserialize<'de> for TrustProjection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawTrustProjection::deserialize(deserializer)?;
        Self::new(raw.trusted_roots).map_err(serde::de::Error::custom)
    }
}

impl TrustProjection {
    pub fn new(mut trusted_roots: Vec<TrustedRoot>) -> Result<Self, CtxError> {
        reject_duplicate_keys(trusted_roots.iter().map(|root| root.identity()))?;
        reject_duplicate_keys(trusted_roots.iter().map(|root| root.path()))?;
        trusted_roots.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(Self { trusted_roots })
    }

    pub fn trusted_roots(&self) -> &[TrustedRoot] {
        &self.trusted_roots
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ActivationProjection {
    identity: GuardIdentity,
    bundle_hash: ContentHash,
    protocol: ExecProtocolVersion,
    match_programs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawActivationProjection {
    identity: GuardIdentity,
    bundle_hash: ContentHash,
    protocol: ExecProtocolVersion,
    match_programs: Vec<String>,
}

impl<'de> Deserialize<'de> for ActivationProjection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawActivationProjection::deserialize(deserializer)?;
        Self::new(
            raw.identity,
            raw.bundle_hash,
            raw.protocol,
            raw.match_programs,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ActivationProjection {
    pub fn new(
        identity: GuardIdentity,
        bundle_hash: ContentHash,
        protocol: ExecProtocolVersion,
        match_programs: Vec<String>,
    ) -> Result<Self, CtxError> {
        let mut match_programs = match_programs
            .into_iter()
            .map(program_name)
            .collect::<Result<Vec<_>, _>>()?;
        reject_duplicate_keys(match_programs.iter())?;
        match_programs.sort();
        Ok(Self {
            identity,
            bundle_hash,
            protocol,
            match_programs,
        })
    }

    pub fn identity(&self) -> &GuardIdentity {
        &self.identity
    }

    pub const fn protocol(&self) -> ExecProtocolVersion {
        self.protocol
    }

    pub fn bundle_hash(&self) -> &ContentHash {
        &self.bundle_hash
    }

    pub fn match_programs(&self) -> &[String] {
        &self.match_programs
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Ctx {
    v: SchemaVersion,
    platform: Platform,
    home: AbsolutePath,
    #[serde(rename = "shipped_units")]
    shipped_guards: Vec<ShippedGuardState>,
    activations: Vec<ActivationProjection>,
    trust: TrustProjection,
    policy_version: PolicyVersion,
}

#[derive(Deserialize)]
struct RawCtx {
    v: SchemaVersion,
    platform: Platform,
    home: AbsolutePath,
    #[serde(rename = "shipped_units")]
    shipped_guards: Vec<ShippedGuardState>,
    activations: Vec<ActivationProjection>,
    trust: TrustProjection,
    policy_version: PolicyVersion,
}

impl<'de> Deserialize<'de> for Ctx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let version = value
            .get("v")
            .cloned()
            .ok_or_else(|| serde::de::Error::missing_field("v"))
            .and_then(|value| {
                serde_json::from_value::<SchemaVersion>(value).map_err(serde::de::Error::custom)
            })?;
        if version != SchemaVersion::V1 {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        let raw = serde_json::from_value::<RawCtx>(value).map_err(serde::de::Error::custom)?;
        Self::new(
            raw.v,
            raw.platform,
            raw.home,
            raw.shipped_guards,
            raw.activations,
            raw.trust,
            raw.policy_version,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        v: SchemaVersion,
        platform: Platform,
        home: AbsolutePath,
        mut shipped_guards: Vec<ShippedGuardState>,
        mut activations: Vec<ActivationProjection>,
        trust: TrustProjection,
        policy_version: PolicyVersion,
    ) -> Result<Self, CtxError> {
        if v != SchemaVersion::V1 {
            return Err(CtxError::UnsupportedVersion);
        }
        if !is_absolute(platform, home.as_str())
            || trust
                .trusted_roots()
                .iter()
                .any(|root| !is_absolute(platform, root.path().as_str()))
        {
            return Err(CtxError::InvalidPath);
        }
        reject_duplicate_keys(shipped_guards.iter().map(ShippedGuardState::name))?;
        reject_duplicate_keys(activations.iter().map(ActivationProjection::identity))?;
        let trusted_identities = trust
            .trusted_roots()
            .iter()
            .map(TrustedRoot::identity)
            .collect::<BTreeSet<_>>();
        if activations.iter().any(|activation| {
            activation.identity().scope() == GuardScope::Project
                && activation
                    .identity()
                    .trusted_root()
                    .is_none_or(|identity| !trusted_identities.contains(identity))
        }) {
            return Err(CtxError::UntrustedActivation);
        }
        shipped_guards.sort_by(|left, right| left.name.cmp(&right.name));
        activations.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(Self {
            v,
            platform,
            home,
            shipped_guards,
            activations,
            trust,
            policy_version,
        })
    }

    pub const fn platform(&self) -> Platform {
        self.platform
    }

    pub const fn version(&self) -> SchemaVersion {
        self.v
    }

    pub fn home(&self) -> &AbsolutePath {
        &self.home
    }

    pub fn activations(&self) -> &[ActivationProjection] {
        &self.activations
    }

    pub fn shipped_guards(&self) -> &[ShippedGuardState] {
        &self.shipped_guards
    }

    pub fn trust(&self) -> &TrustProjection {
        &self.trust
    }

    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCtx {
    policy_version: PolicyVersion,
    enabled_shipped_guards: Vec<String>,
}

impl PolicyCtx {
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    pub fn enabled_shipped_guards(&self) -> &[String] {
        &self.enabled_shipped_guards
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCtxDerivation {
    policy_ctx: PolicyCtx,
    unknown_declared_guards: Vec<String>,
}

impl PolicyCtxDerivation {
    pub fn policy_ctx(&self) -> &PolicyCtx {
        &self.policy_ctx
    }

    pub fn unknown_declared_guards(&self) -> &[String] {
        &self.unknown_declared_guards
    }
}

pub fn derive_policy_ctx(
    ctx: &Ctx,
    observation: &Observation,
) -> Result<PolicyCtxDerivation, CtxError> {
    let mut enabled = ctx
        .shipped_guards
        .iter()
        .filter(|guard| guard.enabled)
        .map(|guard| guard.name.clone())
        .collect::<BTreeSet<_>>();
    let guards = ctx
        .shipped_guards
        .iter()
        .map(|guard| guard.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut unknown = BTreeSet::new();
    let declaration = observation
        .project_guard_declaration()
        .map_err(|_| CtxError::InvalidObservation)?;
    // A declaration that cannot be read or parsed adds no project guards; the
    // globally enabled guards still run.
    if let ProjectGuardDeclaration::Present { names } = declaration {
        for name in names {
            if !guards.contains(name.as_str()) {
                unknown.insert(name.clone());
            } else if !ctx
                .shipped_guards
                .iter()
                .any(|guard| guard.name == *name && guard.explicitly_disabled)
            {
                enabled.insert(name.clone());
            }
        }
    }
    Ok(PolicyCtxDerivation {
        policy_ctx: PolicyCtx {
            policy_version: ctx.policy_version,
            enabled_shipped_guards: enabled.into_iter().collect(),
        },
        unknown_declared_guards: unknown.into_iter().collect(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtxError {
    EmptyIdentifier,
    Duplicate,
    InvalidContentHash,
    InvalidGuardState,
    InvalidIdentity,
    InvalidObservation,
    InvalidPath,
    InvalidProgramName,
    UntrustedActivation,
    UnsupportedVersion,
    ZeroVersion,
}

impl CtxError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyIdentifier => "empty-identifier",
            Self::Duplicate => "duplicate",
            Self::InvalidContentHash => "invalid-content-hash",
            Self::InvalidGuardState => "invalid-guard-state",
            Self::InvalidIdentity => "invalid-identity",
            Self::InvalidObservation => "invalid-observation",
            Self::InvalidPath => "invalid-path",
            Self::InvalidProgramName => "invalid-program-name",
            Self::UntrustedActivation => "untrusted-activation",
            Self::UnsupportedVersion => "unsupported-version",
            Self::ZeroVersion => "zero-version",
        }
    }
}

impl std::fmt::Display for CtxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

fn non_empty(value: impl Into<String>) -> Result<String, CtxError> {
    let value = value.into();
    if value.is_empty() {
        Err(CtxError::EmptyIdentifier)
    } else {
        Ok(value)
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
}

fn guard_name(value: impl Into<String>) -> Result<String, CtxError> {
    let value = value.into();
    let edge_is_alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let valid = !value.is_empty()
        && value.len() <= MAX_GUARD_NAME_BYTES
        && value.bytes().next().is_some_and(edge_is_alphanumeric)
        && value.bytes().last().is_some_and(edge_is_alphanumeric)
        && value
            .bytes()
            .all(|byte| edge_is_alphanumeric(byte) || matches!(byte, b'-' | b'_' | b'.'));
    valid.then_some(value).ok_or(CtxError::InvalidIdentity)
}

fn program_name(value: String) -> Result<String, CtxError> {
    let valid = !value.is_empty()
        && !value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        && !value.contains(['*', '?', '[', ']']);
    valid.then_some(value).ok_or(CtxError::InvalidProgramName)
}

fn nonzero_version(value: u32) -> Result<u32, CtxError> {
    if value == 0 {
        Err(CtxError::ZeroVersion)
    } else {
        Ok(value)
    }
}

fn reject_duplicate_keys<'a, T: Ord + ?Sized + 'a>(
    keys: impl IntoIterator<Item = &'a T>,
) -> Result<(), CtxError> {
    let mut seen = BTreeSet::new();
    for key in keys {
        if !seen.insert(key) {
            return Err(CtxError::Duplicate);
        }
    }
    Ok(())
}
