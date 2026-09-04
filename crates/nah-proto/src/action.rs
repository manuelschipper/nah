//! Versioned, canonical visible-effect contract.

use core::net::IpAddr;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ctx::AbsolutePath;
pub use crate::labels::{HostIntegrityClass, NahProtectionTier, PathScope, Sensitivity};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ActionStreamVersion(u32);

impl ActionStreamVersion {
    pub const V1: Self = Self(1);

    pub fn new(value: u32) -> Result<Self, ActionError> {
        (value != 0)
            .then_some(Self(value))
            .ok_or(ActionError::ZeroVersion)
    }
}

impl<'de> Deserialize<'de> for ActionStreamVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    Full,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EffectId(String);

impl EffectId {
    fn from_ordinal(ordinal: usize) -> Self {
        Self(format!("e{ordinal}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn ordinal(&self) -> Option<usize> {
        parse_ordinal('e', &self.0)
    }
}

impl<'de> Deserialize<'de> for EffectId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        parse_ordinal('e', &value)
            .map(|_| Self(value))
            .ok_or_else(|| serde::de::Error::custom("invalid-effect-id"))
    }
}

impl Ord for EffectId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.ordinal(), other.ordinal()) {
            (Some(left), Some(right)) => left.cmp(&right),
            _ => self.0.cmp(&other.0),
        }
    }
}

impl PartialOrd for EffectId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for EffectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StageId(String);

impl StageId {
    fn from_ordinal(ordinal: usize) -> Self {
        Self(format!("s{ordinal}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn ordinal(&self) -> Option<usize> {
        parse_ordinal('s', &self.0)
    }
}

impl<'de> Deserialize<'de> for StageId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        parse_ordinal('s', &value)
            .map(|_| Self(value))
            .ok_or_else(|| serde::de::Error::custom("invalid-stage-id"))
    }
}

impl Ord for StageId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.ordinal(), other.ordinal()) {
            (Some(left), Some(right)) => left.cmp(&right),
            _ => self.0.cmp(&other.0),
        }
    }
}

impl PartialOrd for StageId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InvocationInput {
    Shell {
        words: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        argv: Option<Vec<String>>,
    },
    Native {
        value: serde_json::Value,
        complete: bool,
    },
}

impl InvocationInput {
    pub fn shell(program: &str, words: Vec<String>, argv: Option<Vec<String>>) -> Self {
        let words = if words.is_empty() {
            vec![program.to_owned()]
        } else {
            words
        };
        Self::Shell { words, argv }
    }

    pub fn native(value: serde_json::Value, complete: bool) -> Self {
        Self::Native { value, complete }
    }

    pub const fn complete(&self) -> bool {
        match self {
            Self::Shell { argv, .. } => argv.is_some(),
            Self::Native { complete, .. } => *complete,
        }
    }
}

/// A validated semantic label carried between lowering and policy.
///
/// The wire remains open for versioned native inputs and extensions. Built-in
/// security semantics use the named constants so producers and consumers
/// cannot drift through separately spelled string literals.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SemanticCode(Cow<'static, str>);

impl SemanticCode {
    pub const ANALYSIS_REFUSED: Self = Self::borrowed("analysis-refused");
    pub const CLOCK_SET: Self = Self::borrowed("clock-set");
    pub const CLEAN_FORCE: Self = Self::borrowed("clean-force");
    pub const CREDENTIAL_DISCLOSURE: Self = Self::borrowed("credential-disclosure");
    pub const CREDENTIAL_SEARCH: Self = Self::borrowed("credential-search");
    pub const CRITICAL_MUTATION: Self = Self::borrowed("critical-mutation");
    pub const DECODE: Self = Self::borrowed("decode");
    pub const DECODED_EXECUTION: Self = Self::borrowed("decoded-execution");
    pub const DIRECT_FILE: Self = Self::borrowed("direct-file");
    pub const ENCODED_COMMAND: Self = Self::borrowed("encoded-command");
    pub const ENVIRONMENT_DISCLOSURE: Self = Self::borrowed("environment-disclosure");
    pub const EVALUATED_SHELL: Self = Self::borrowed("evaluated-shell");
    pub const FORK_BOMB: Self = Self::borrowed("fork-bomb");
    pub const FORCE_PUSH: Self = Self::borrowed("force-push");
    pub const GIT_REMOTE_REPO_DELETE: Self = Self::borrowed("git-remote-repo-delete");
    pub const HARD_RESET: Self = Self::borrowed("hard-reset");
    pub const HISTORY_REWRITE: Self = Self::borrowed("history-rewrite");
    pub const HOST_POWER: Self = Self::borrowed("host-power");
    pub const INFRA_CONTAINER_VOLUME_DELETE: Self = Self::borrowed("infra-container-volume-delete");
    pub const INFRA_CONTAINER_RESET: Self = Self::borrowed("infra-container-reset");
    pub const INFRA_IAC_DESTROY: Self = Self::borrowed("infra-iac-destroy");
    pub const INFRA_K8S_BULK_RESOURCE_DELETE: Self =
        Self::borrowed("infra-k8s-bulk-resource-delete");
    pub const INFRA_K8S_CLUSTER_RESOURCE_DELETE: Self =
        Self::borrowed("infra-k8s-cluster-resource-delete");
    pub const INFRA_K8S_NAMESPACE_DELETE: Self = Self::borrowed("infra-k8s-namespace-delete");
    pub const INTERPRETER_FILE: Self = Self::borrowed("interpreter-file");
    pub const INTERPRETER_INLINE: Self = Self::borrowed("interpreter-inline");
    pub const INTERPRETER_STDIN: Self = Self::borrowed("interpreter-stdin");
    pub const LOGICAL_STORAGE_DESTROY: Self = Self::borrowed("logical-storage-destroy");
    pub const LOCAL_UTILITY: Self = Self::borrowed("local-utility");
    pub const METADATA_MUTATION: Self = Self::borrowed("metadata-mutation");
    pub const MOVE: Self = Self::borrowed("move");
    pub const NETWORK_LISTENER: Self = Self::borrowed("network-listener");
    pub const NETWORK_SHELL: Self = Self::borrowed("network-shell");
    pub const NETWORK_TRANSFER: Self = Self::borrowed("network-transfer");
    pub const NULL_COMMAND: Self = Self::borrowed("null-command");
    pub const PATH_DISCARD: Self = Self::borrowed("path-discard");
    pub const PERMANENT_MUTATION: Self = Self::borrowed("permanent-mutation");
    pub const PERMISSION_CHANGE: Self = Self::borrowed("permission-change");
    pub const PERMISSION_WEAKEN: Self = Self::borrowed("permission-weaken");
    pub const RECOVERY_DESTROY: Self = Self::borrowed("recovery-destroy");
    pub const REF_DELETE: Self = Self::borrowed("ref-delete");
    pub const REGISTRY_PUBLISH: Self = Self::borrowed("registry-publish");
    pub const REGISTRY_UNPUBLISH: Self = Self::borrowed("registry-unpublish");
    pub const REMOVE: Self = Self::borrowed("remove");
    pub const REWRITE_FORCE: Self = Self::borrowed("rewrite-force");
    pub const SERVICE_STOP: Self = Self::borrowed("sys-service-stop");
    pub const SHELL_INLINE: Self = Self::borrowed("shell-inline");
    pub const SHELL_INTERACTIVE: Self = Self::borrowed("shell-interactive");
    pub const SHELL_FILE: Self = Self::borrowed("shell-file");
    pub const SHELL_PATTERN: Self = Self::borrowed("shell-pattern");
    pub const SHELL_STDIN: Self = Self::borrowed("shell-stdin");
    pub const STARTUP_MANAGEMENT: Self = Self::borrowed("fs-startup-management");
    pub const STORAGE_BACKUP_DESTROY: Self = Self::borrowed("storage-backup-destroy");
    pub const STORAGE_RECURSIVE_DELETE: Self = Self::borrowed("storage-recursive-delete");
    pub const STORAGE_SNAPSHOT_DELETE: Self = Self::borrowed("storage-snapshot-delete");
    pub const STORAGE_WRITE: Self = Self::borrowed("storage-write");
    pub const EVALUATED_SUBSTITUTION: Self = Self::borrowed("evaluated-substitution");
    pub const UNRESOLVED_COMMAND: Self = Self::borrowed("unresolved-command");
    pub const WORKTREE_DISCARD: Self = Self::borrowed("worktree-discard");

    const fn borrowed(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }

    pub fn new(value: impl Into<String>) -> Result<Self, ActionError> {
        semantic_code(&value.into()).map(|value| Self(Cow::Owned(value)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether the semantic operation is a permission change, including
    /// the narrower permission-weakening classification.
    pub fn is_permission_change(&self) -> bool {
        self == &Self::PERMISSION_CHANGE || self == &Self::PERMISSION_WEAKEN
    }
}

impl<'de> Deserialize<'de> for SemanticCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SemanticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InvocationEffect {
    Known {
        program: String,
        operation: SemanticCode,
        input: InvocationInput,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<AbsolutePath>,
    },
    Opaque {
        program: String,
        input: InvocationInput,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<AbsolutePath>,
    },
    CodeExecution {
        program: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        interpreter: Option<String>,
        source: SemanticCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        input: InvocationInput,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<AbsolutePath>,
    },
}

impl InvocationEffect {
    pub fn program(&self) -> &str {
        match self {
            Self::Known { program, .. }
            | Self::Opaque { program, .. }
            | Self::CodeExecution { program, .. } => program,
        }
    }

    pub const fn input(&self) -> &InvocationInput {
        match self {
            Self::Known { input, .. }
            | Self::Opaque { input, .. }
            | Self::CodeExecution { input, .. } => input,
        }
    }

    pub fn cwd(&self) -> Option<&AbsolutePath> {
        match self {
            Self::Known { cwd, .. }
            | Self::Opaque { cwd, .. }
            | Self::CodeExecution { cwd, .. } => cwd.as_ref(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemOperation {
    Read,
    Write,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemEffect {
    pub operation: FilesystemOperation,
    pub target: AbsolutePath,
    pub scope: PathScope,
    pub sensitivity: Sensitivity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection: Option<NahProtectionTier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_integrity: Option<HostIntegrityClass>,
    pub selects_root: bool,
    pub selects_home: bool,
    pub recursive: bool,
    // The shell expands this target, so it names an unknown set of paths
    // instead of one file. `pattern_bound` states what the set cannot escape.
    pub pattern: bool,
}

/// The literal prefix of a shell pattern. Expansion can only add text to it, so
/// every path the shell can select here starts with this string.
pub fn pattern_bound(target: &str) -> &str {
    let bytes = target.as_bytes();
    let index = bytes.iter().enumerate().find_map(|(index, byte)| {
        (matches!(byte, b'*' | b'?' | b'[' | b'{')
            || matches!(byte, b'@' | b'+' | b'!') && bytes.get(index + 1) == Some(&b'('))
        .then_some(index)
    });
    index.map_or(target, |index| &target[..index])
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EffectKind {
    Invocation {
        invocation: InvocationEffect,
    },
    Filesystem {
        #[serde(flatten)]
        effect: FilesystemEffect,
    },
    /// A filesystem operand whose expansion cannot be bounded to one
    /// filesystem root. The stage's invocation retains the visible input.
    FilesystemUnresolved {
        operation: FilesystemOperation,
        recursive: bool,
    },
    Git {
        operation: SemanticCode,
    },
    Network {
        direction: NetworkDirection,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    SystemState {
        operation: SemanticCode,
    },
}

impl EffectKind {
    pub fn known(program: &str, operation: &str) -> Result<Self, ActionError> {
        Self::known_with_input(
            program,
            operation,
            InvocationInput::shell(
                program,
                vec![program.to_owned()],
                Some(vec![program.to_owned()]),
            ),
        )
    }

    pub fn known_with_input(
        program: &str,
        operation: &str,
        input: InvocationInput,
    ) -> Result<Self, ActionError> {
        Ok(Self::Invocation {
            invocation: InvocationEffect::Known {
                program: program_token(program)?,
                operation: SemanticCode::new(operation)?,
                input,
                cwd: None,
            },
        })
    }

    pub fn opaque(tool: &str) -> Result<Self, ActionError> {
        Self::opaque_with_input(
            tool,
            InvocationInput::shell(tool, vec![tool.to_owned()], Some(vec![tool.to_owned()])),
        )
    }

    pub fn opaque_with_input(program: &str, input: InvocationInput) -> Result<Self, ActionError> {
        Ok(Self::Invocation {
            invocation: InvocationEffect::Opaque {
                program: program_token(program)?,
                input,
                cwd: None,
            },
        })
    }

    pub fn code_execution(interpreter: Option<&str>, source: &str) -> Result<Self, ActionError> {
        let program = interpreter.unwrap_or("unknown");
        Self::code_execution_with_input(
            program,
            interpreter,
            source,
            None,
            InvocationInput::shell(
                program,
                vec![program.to_owned()],
                Some(vec![program.to_owned()]),
            ),
        )
    }

    pub fn code_execution_with_input(
        program: &str,
        interpreter: Option<&str>,
        source: &str,
        code: Option<String>,
        input: InvocationInput,
    ) -> Result<Self, ActionError> {
        Ok(Self::Invocation {
            invocation: InvocationEffect::CodeExecution {
                program: program_token(program)?,
                interpreter: interpreter.map(program_token).transpose()?,
                source: SemanticCode::new(source)?,
                code,
                input,
                cwd: None,
            },
        })
    }

    /// Binds the visible requested working directory for this invocation.
    /// Partial coverage tells consumers when an earlier directory change may
    /// have failed. The original program and argv stay unchanged.
    pub fn with_invocation_cwd(mut self, cwd: AbsolutePath) -> Self {
        if let Self::Invocation { invocation } = &mut self {
            match invocation {
                InvocationEffect::Known {
                    cwd: invocation_cwd,
                    ..
                }
                | InvocationEffect::Opaque {
                    cwd: invocation_cwd,
                    ..
                }
                | InvocationEffect::CodeExecution {
                    cwd: invocation_cwd,
                    ..
                } => *invocation_cwd = Some(cwd),
            }
        }
        self
    }

    pub fn network(host: Option<&str>) -> Self {
        Self::network_with_direction(NetworkDirection::Outbound, host)
    }

    pub fn network_with_direction(direction: NetworkDirection, host: Option<&str>) -> Self {
        Self::Network {
            direction,
            host: host.and_then(normalize_host),
        }
    }

    pub fn network_host(&self) -> Option<&str> {
        match self {
            Self::Network { host, .. } => host.as_deref(),
            _ => None,
        }
    }

    fn is_invocation(&self) -> bool {
        matches!(self, Self::Invocation { .. })
    }

    fn validate(&self) -> Result<(), ActionError> {
        match self {
            Self::Invocation {
                invocation:
                    InvocationEffect::Known {
                        program,
                        operation,
                        input,
                        cwd,
                    },
            } => {
                program_token(program)?;
                semantic_code(operation.as_str())?;
                validate_invocation_input(program, input)?;
                validate_invocation_cwd(cwd.as_ref())?;
            }
            Self::Invocation {
                invocation:
                    InvocationEffect::Opaque {
                        program,
                        input,
                        cwd,
                    },
            } => {
                program_token(program)?;
                validate_invocation_input(program, input)?;
                validate_invocation_cwd(cwd.as_ref())?;
            }
            Self::Invocation {
                invocation:
                    InvocationEffect::CodeExecution {
                        program,
                        interpreter,
                        source,
                        code,
                        input,
                        cwd,
                    },
            } => {
                program_token(program)?;
                if let Some(interpreter) = interpreter {
                    program_token(interpreter)?;
                }
                semantic_code(source.as_str())?;
                validate_invocation_input(program, input)?;
                if code.as_ref().is_some_and(|code| code.contains('\0')) {
                    return Err(ActionError::InvalidEffect);
                }
                validate_invocation_cwd(cwd.as_ref())?;
            }
            Self::Filesystem { effect } => {
                let target = effect.target.as_str();
                if !is_lexically_normalized_path(target) {
                    return Err(ActionError::InvalidFilesystemScope);
                }
                match &effect.scope {
                    PathScope::Project { root } => {
                        let root = root.as_str();
                        if !is_lexically_normalized_path(root) {
                            return Err(ActionError::InvalidFilesystemScope);
                        }
                        let inside = target == root || is_path_descendant(target, root);
                        if !inside || effect.selects_root != (target == root) {
                            return Err(ActionError::InvalidFilesystemScope);
                        }
                    }
                    _ if effect.selects_root => {
                        return Err(ActionError::InvalidFilesystemScope);
                    }
                    _ => {}
                }
            }
            Self::FilesystemUnresolved { .. } => {}
            Self::Git { operation } | Self::SystemState { operation } => {
                semantic_code(operation.as_str())?;
            }
            Self::Network { host, .. } => {
                if host
                    .as_ref()
                    .is_some_and(|host| normalize_host(host).as_deref() != Some(host))
                {
                    return Err(ActionError::InvalidHost);
                }
            }
        }
        Ok(())
    }
}

fn program_token(value: &str) -> Result<String, ActionError> {
    let valid = !value.is_empty()
        && !value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        && !value.contains(['*', '?', '[', ']']);
    valid
        .then(|| value.to_owned())
        .ok_or(ActionError::InvalidProgramName)
}

fn validate_invocation_input(program: &str, input: &InvocationInput) -> Result<(), ActionError> {
    match input {
        InvocationInput::Shell { words, argv } => {
            if words.is_empty() || words.iter().any(|word| word.contains('\0')) {
                return Err(ActionError::InvalidEffect);
            }
            if let Some(argv) = argv
                && (argv.is_empty()
                    || argv[0] != program
                    || argv.iter().any(|argument| argument.contains('\0')))
            {
                return Err(ActionError::InvalidEffect);
            }
        }
        InvocationInput::Native { value, .. } => {
            if value.is_null() {
                return Err(ActionError::InvalidEffect);
            }
        }
    }
    Ok(())
}

fn validate_invocation_cwd(cwd: Option<&AbsolutePath>) -> Result<(), ActionError> {
    if cwd.is_some_and(|cwd| !is_lexically_normalized_path(cwd.as_str())) {
        return Err(ActionError::InvalidEffect);
    }
    Ok(())
}

pub(crate) fn is_path_descendant(target: &str, root: &str) -> bool {
    let windows = root.starts_with("\\\\") || root.as_bytes().get(1) == Some(&b':');
    let is_separator = |byte| byte == b'/' || (windows && byte == b'\\');
    let Some(suffix) = target.strip_prefix(root) else {
        return false;
    };
    !suffix.is_empty()
        && (root
            .as_bytes()
            .last()
            .is_some_and(|byte| is_separator(*byte))
            || suffix
                .as_bytes()
                .first()
                .is_some_and(|byte| is_separator(*byte)))
}

pub(crate) fn is_lexically_normalized_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    if let Some(device) = path.strip_prefix(r"\\.\") {
        return !device.is_empty() && !device.contains(['/', '\\']);
    }
    let windows = path.starts_with("\\\\") || path.as_bytes().get(1) == Some(&b':');
    let is_separator = |byte| byte == b'/' || (windows && byte == b'\\');
    let root_len = if path.starts_with("\\\\") {
        2
    } else if path.as_bytes().get(1) == Some(&b':') {
        3
    } else {
        1
    };
    if path.len() == root_len {
        return windows && !path.starts_with("\\\\");
    }
    let remainder = &path[root_len..];
    let mut component_count = 0;
    let components_valid = remainder
        .split(|character| character == '/' || (windows && character == '\\'))
        .all(|component| {
            component_count += 1;
            !component.is_empty() && !matches!(component, "." | "..")
        });
    !remainder.is_empty()
        && !remainder
            .as_bytes()
            .last()
            .is_some_and(|byte| is_separator(*byte))
        && components_valid
        && (!path.starts_with("\\\\") || component_count >= 2)
}

fn semantic_code(value: &str) -> Result<String, ActionError> {
    let valid = !value.is_empty()
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
    valid
        .then(|| value.to_owned())
        .ok_or(ActionError::InvalidSemanticCode)
}

fn normalize_host(input: &str) -> Option<String> {
    let unbracketed = input
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(input);
    if unbracketed.is_empty() || !unbracketed.is_ascii() || unbracketed.contains('%') {
        return None;
    }
    let lower = unbracketed.to_ascii_lowercase();
    if lower.contains(':') {
        return lower
            .parse::<IpAddr>()
            .ok()
            .map(|address| address.to_string());
    }
    if lower
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return lower
            .parse::<IpAddr>()
            .ok()
            .map(|address| address.to_string());
    }
    let dns = lower.strip_suffix('.').unwrap_or(&lower);
    if dns.is_empty() || dns.len() > 253 || dns.ends_with('.') {
        return None;
    }
    dns.split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
        .then(|| dns.to_owned())
}

fn parse_ordinal(prefix: char, value: &str) -> Option<usize> {
    let suffix = value.strip_prefix(prefix)?;
    if suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        || (suffix.len() > 1 && suffix.starts_with('0'))
    {
        return None;
    }
    suffix.parse().ok()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Effect {
    id: EffectId,
    stage: StageId,
    kind: EffectKind,
}

impl Effect {
    pub fn id(&self) -> &EffectId {
        &self.id
    }

    pub fn stage(&self) -> &StageId {
        &self.stage
    }

    pub fn kind(&self) -> &EffectKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FlowEdge {
    from_stage: StageId,
    to_stage: StageId,
}

impl FlowEdge {
    pub fn from_stage(&self) -> &StageId {
        &self.from_stage
    }

    pub fn to_stage(&self) -> &StageId {
        &self.to_stage
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowOrdinals {
    from: usize,
    to: usize,
}

impl FlowOrdinals {
    pub const fn new(from: usize, to: usize) -> Self {
        Self { from, to }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionStream {
    v: ActionStreamVersion,
    coverage: Coverage,
    effects: Vec<Effect>,
    flows: Vec<FlowEdge>,
}

impl ActionStream {
    pub fn new(
        coverage: Coverage,
        stages: Vec<Vec<EffectKind>>,
        flow_ordinals: Vec<FlowOrdinals>,
    ) -> Result<Self, ActionError> {
        if stages.is_empty() {
            return if coverage == Coverage::Partial && flow_ordinals.is_empty() {
                Ok(Self {
                    v: ActionStreamVersion::V1,
                    coverage,
                    effects: vec![],
                    flows: vec![],
                })
            } else {
                Err(ActionError::InvalidStage)
            };
        }
        if stages.iter().any(Vec::is_empty) {
            return Err(ActionError::InvalidStage);
        }
        let mut effects = Vec::new();
        for (stage_index, kinds) in stages.iter().enumerate() {
            for kind in kinds {
                effects.push(Effect {
                    id: EffectId::from_ordinal(effects.len()),
                    stage: StageId::from_ordinal(stage_index),
                    kind: kind.clone(),
                });
            }
        }
        let flows = flow_ordinals
            .into_iter()
            .map(|flow| FlowEdge {
                from_stage: StageId::from_ordinal(flow.from),
                to_stage: StageId::from_ordinal(flow.to),
            })
            .collect();
        Self {
            v: ActionStreamVersion::V1,
            coverage,
            effects,
            flows,
        }
        .validate_and_normalize()
    }

    fn validate_and_normalize(mut self) -> Result<Self, ActionError> {
        if self.v != ActionStreamVersion::V1 {
            return Err(ActionError::UnsupportedVersion);
        }
        if self.effects.is_empty() {
            return if self.coverage == Coverage::Partial && self.flows.is_empty() {
                Ok(self)
            } else {
                Err(ActionError::InvalidStage)
            };
        }
        let mut stage_index = 0;
        let mut invocation_count = 0;
        for (effect_index, effect) in self.effects.iter().enumerate() {
            if effect.id != EffectId::from_ordinal(effect_index) {
                return Err(ActionError::InvalidEffectId);
            }
            let effect_stage = effect.stage.ordinal().ok_or(ActionError::InvalidStage)?;
            if effect_stage == stage_index + 1 {
                if invocation_count != 1 {
                    return Err(ActionError::InvalidStage);
                }
                stage_index = effect_stage;
                invocation_count = 0;
            } else if effect_stage != stage_index {
                return Err(ActionError::InvalidStage);
            }
            effect.kind.validate()?;
            invocation_count += usize::from(effect.kind.is_invocation());
        }
        if invocation_count != 1 {
            return Err(ActionError::InvalidStage);
        }
        let stage_count = stage_index + 1;
        for flow in &self.flows {
            let from = flow.from_stage.ordinal().ok_or(ActionError::InvalidFlow)?;
            let to = flow.to_stage.ordinal().ok_or(ActionError::InvalidFlow)?;
            if from >= stage_count || to >= stage_count || from == to {
                return Err(ActionError::InvalidFlow);
            }
        }
        self.flows.sort();
        if self.flows.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ActionError::InvalidFlow);
        }
        Ok(self)
    }

    pub const fn version(&self) -> ActionStreamVersion {
        self.v
    }

    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    pub fn flows(&self) -> &[FlowEdge] {
        &self.flows
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl<'de> Deserialize<'de> for ActionStream {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let version = value
            .get("v")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| serde::de::Error::missing_field("v"))?;
        if version != 1 {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        #[derive(Deserialize)]
        struct Raw {
            v: ActionStreamVersion,
            coverage: Coverage,
            effects: Vec<Effect>,
            flows: Vec<FlowEdge>,
        }
        let raw: Raw = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Self {
            v: raw.v,
            coverage: raw.coverage,
            effects: raw.effects,
            flows: raw.flows,
        }
        .validate_and_normalize()
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionError {
    InvalidEffect,
    InvalidEffectId,
    InvalidFlow,
    InvalidFilesystemScope,
    InvalidHost,
    InvalidProgramName,
    InvalidSemanticCode,
    InvalidStage,
    UnsupportedVersion,
    ZeroVersion,
}

impl ActionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEffect => "invalid-effect",
            Self::InvalidEffectId => "invalid-effect-id",
            Self::InvalidFlow => "invalid-flow",
            Self::InvalidFilesystemScope => "invalid-filesystem-scope",
            Self::InvalidHost => "invalid-host",
            Self::InvalidProgramName => "invalid-program-name",
            Self::InvalidSemanticCode => "invalid-semantic-code",
            Self::InvalidStage => "invalid-stage",
            Self::UnsupportedVersion => "unsupported-version",
            Self::ZeroVersion => "zero-version",
        }
    }
}

impl fmt::Display for ActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ActionError {}
