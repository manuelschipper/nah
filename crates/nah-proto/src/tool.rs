//! Machine tool-call input and validated per-call location.

use crate::ctx::AbsolutePath;
use crate::ctx::CtxError;
use crate::ctx::Platform;
use crate::ctx::SchemaVersion;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::effinterp_proto::CommandShell;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolCallInput {
    v: SchemaVersion,
    tool: String,
    input: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_input: Option<Value>,
    #[serde(default = "true_value", skip_serializing_if = "is_true")]
    normalization_complete: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    match_original: bool,
    cwd: String,
    /// The project or workspace directories the runtime reports for the
    /// call, such as Claude Code's `CLAUDE_PROJECT_DIR`. Empty when it
    /// reports none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    project_dirs: Vec<String>,
    /// The shell the runtime runs a shell command in, as far as it says.
    #[serde(skip_serializing_if = "CommandShell::is_bash")]
    shell: CommandShell,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
}

impl ToolCallInput {
    pub fn new(
        v: SchemaVersion,
        tool: impl Into<String>,
        input: Value,
        cwd: impl Into<String>,
        session: Option<String>,
    ) -> Result<Self, ToolInputError> {
        if v != SchemaVersion::V1 {
            return Err(ToolInputError::UnsupportedVersion);
        }
        let tool = require_non_empty(tool)?;
        let cwd = require_non_empty(cwd)?;
        let session = session.map(require_non_empty).transpose()?;
        Ok(Self {
            v,
            tool,
            input,
            original_input: None,
            normalization_complete: true,
            match_original: false,
            cwd,
            project_dirs: Vec::new(),
            shell: CommandShell::Bash,
            session,
        })
    }

    pub fn with_original_input(
        mut self,
        original_input: Value,
        normalization_complete: bool,
    ) -> Self {
        self.original_input = Some(original_input);
        self.normalization_complete = normalization_complete;
        self
    }

    /// Adapter-owned batch semantics, separate from caller-controlled arguments.
    pub fn with_original_file_edits(mut self) -> Self {
        self.match_original = true;
        self
    }

    /// The runtime's reported project directories; see `project_dirs`.
    pub fn with_project_dirs(mut self, project_dirs: Vec<String>) -> Self {
        self.project_dirs = project_dirs;
        self
    }

    /// The runtime's session id, as a replayed session names it.
    pub fn with_session(mut self, session: Option<String>) -> Self {
        self.session = session;
        self
    }

    pub fn project_dirs(&self) -> &[String] {
        &self.project_dirs
    }

    /// The runtime's shell; see `shell`.
    pub fn with_shell(mut self, shell: CommandShell) -> Self {
        self.shell = shell;
        self
    }

    pub const fn shell(&self) -> CommandShell {
        self.shell
    }

    pub const fn edits_match_original(&self) -> bool {
        self.match_original
    }

    pub const fn version(&self) -> SchemaVersion {
        self.v
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn input(&self) -> &Value {
        &self.input
    }

    pub fn invocation_input(&self) -> &Value {
        self.original_input.as_ref().unwrap_or(&self.input)
    }

    pub const fn normalization_complete(&self) -> bool {
        self.normalization_complete
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    pub fn call_site(&self, platform: Platform) -> Result<CallSite, ToolInputError> {
        CallSite::new(platform, self.cwd.clone())
    }
}

#[derive(Deserialize)]
struct RawToolCallInput {
    v: SchemaVersion,
    tool: String,
    input: Value,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    original_input: PresentValue,
    #[serde(default = "true_value")]
    normalization_complete: bool,
    #[serde(default)]
    match_original: bool,
    cwd: String,
    #[serde(default)]
    project_dirs: Vec<String>,
    #[serde(default)]
    shell: CommandShell,
    #[serde(default)]
    session: Option<String>,
}

#[derive(Default)]
enum PresentValue {
    #[default]
    Missing,
    Present(Value),
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<PresentValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(PresentValue::Present)
}

impl<'de> Deserialize<'de> for ToolCallInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
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
        let raw =
            serde_json::from_value::<RawToolCallInput>(value).map_err(serde::de::Error::custom)?;
        if !raw.normalization_complete && matches!(raw.original_input, PresentValue::Missing) {
            return Err(serde::de::Error::custom(
                "incomplete-normalization-requires-original-input",
            ));
        }
        Self::new(raw.v, raw.tool, raw.input, raw.cwd, raw.session)
            .map(|input| {
                let input = match raw.original_input {
                    PresentValue::Present(original) => {
                        input.with_original_input(original, raw.normalization_complete)
                    }
                    PresentValue::Missing => input,
                };
                let input = input
                    .with_project_dirs(raw.project_dirs)
                    .with_shell(raw.shell);
                if raw.match_original {
                    input.with_original_file_edits()
                } else {
                    input
                }
            })
            .map_err(serde::de::Error::custom)
    }
}

const fn true_value() -> bool {
    true
}

const fn is_false(value: &bool) -> bool {
    !*value
}

const fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallSite {
    requested_cwd: AbsolutePath,
}

impl CallSite {
    pub fn new(
        platform: Platform,
        requested_cwd: impl Into<String>,
    ) -> Result<Self, ToolInputError> {
        let requested_cwd =
            AbsolutePath::new(platform, requested_cwd).map_err(|_| ToolInputError::InvalidPath)?;
        Ok(Self { requested_cwd })
    }

    pub fn requested_cwd(&self) -> &AbsolutePath {
        &self.requested_cwd
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolInputError {
    EmptyIdentifier,
    InvalidPath,
    UnsupportedVersion,
}

impl ToolInputError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyIdentifier => "empty-identifier",
            Self::InvalidPath => "invalid-path",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }
}

impl std::fmt::Display for ToolInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl From<CtxError> for ToolInputError {
    fn from(error: CtxError) -> Self {
        match error {
            CtxError::InvalidPath => Self::InvalidPath,
            _ => Self::EmptyIdentifier,
        }
    }
}

fn require_non_empty(value: impl Into<String>) -> Result<String, ToolInputError> {
    let value = value.into();
    if value.is_empty() {
        Err(ToolInputError::EmptyIdentifier)
    } else {
        Ok(value)
    }
}
