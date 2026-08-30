// UNDOCUMENTED-EFFINTERP: This prototype contract changes in place until the effinterp switch.

//! Validated effect-interpreter stream and its custom-guard request.

use std::error::Error;
use std::fmt;

pub use effinterp_proto;
use effinterp_proto::{CoverageLevel, Plan, validate};
use serde::{Deserialize, Serialize};

use crate::action::{
    ActionStreamVersion, Coverage, is_lexically_normalized_path, is_path_descendant,
};
use crate::ctx::{AbsolutePath, ExecProtocolVersion};
use crate::exec_v1::{ExecObservation, ExecRequestError};
use crate::labels::{HostIntegrityClass, NahProtectionTier, PathScope, Sensitivity};
use crate::observation::{Observed, Root};

/// A validated effinterp plan paired positionally with nah-owned effect labels.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionStream {
    v: ActionStreamVersion,
    plan: Plan,
    annotations: Vec<EffectAnnotation>,
}

impl ActionStream {
    pub fn new(plan: Plan, annotations: Vec<EffectAnnotation>) -> Result<Self, StreamError> {
        Self {
            v: ActionStreamVersion::V1,
            plan,
            annotations,
        }
        .validate_and_normalize()
    }

    fn validate_and_normalize(self) -> Result<Self, StreamError> {
        if self.v != ActionStreamVersion::V1 {
            return Err(StreamError::UnsupportedVersion);
        }
        if validate(&self.plan).is_err() {
            return Err(StreamError::InvalidPlan);
        }
        if self.annotations.len() != self.plan.effects.len() {
            return Err(StreamError::AnnotationCount);
        }
        for (effect, annotation) in self.plan.effects.iter().zip(&self.annotations) {
            let domain = effect.operation.domain();
            if annotation.path.is_some() && domain != "filesystem"
                || annotation.runtime_cli.is_some() && domain != "process"
            {
                return Err(StreamError::InvalidAnnotationDomain);
            }
            let Some(PathLabel::Resolved {
                path,
                scope,
                selects_root,
                ..
            }) = annotation.path.as_ref()
            else {
                continue;
            };
            if !is_lexically_normalized_path(path.as_str()) {
                return Err(StreamError::InvalidPathLabel);
            }
            if let PathScope::Project { root } = scope {
                if !is_lexically_normalized_path(root.as_str()) {
                    return Err(StreamError::InvalidPathLabel);
                }
                let inside = path == root || is_path_descendant(path.as_str(), root.as_str());
                if !inside || *selects_root != (path == root) {
                    return Err(StreamError::InvalidPathLabel);
                }
            }
        }
        Ok(self)
    }

    pub const fn version(&self) -> ActionStreamVersion {
        self.v
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn annotations(&self) -> &[EffectAnnotation] {
        &self.annotations
    }

    pub fn coverage(&self) -> Coverage {
        if self
            .plan
            .coverage
            .0
            .values()
            .all(|level| *level == CoverageLevel::Full)
        {
            Coverage::Full
        } else {
            Coverage::Partial
        }
    }

    pub fn canonical_json(&self) -> String {
        effinterp_proto::canonical_json(self)
    }
}

impl<'de> Deserialize<'de> for ActionStream {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
            plan: Plan,
            annotations: Vec<EffectAnnotation>,
        }
        let raw: Raw = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Self {
            v: raw.v,
            plan: raw.plan,
            annotations: raw.annotations,
        }
        .validate_and_normalize()
        .map_err(serde::de::Error::custom)
    }
}

/// Nah-owned labels for the effect at the same index in the embedded plan.
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
        #[serde(skip_serializing_if = "Option::is_none")]
        host_integrity: Option<HostIntegrityClass>,
        selects_root: bool,
        selects_home: bool,
    },
    Unresolved,
}

/// One stdin request to an `exec/v1` extension carrying the effinterp stream shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecRequest {
    v: ExecProtocolVersion,
    action_stream: ActionStream,
    observation: ExecObservation,
}

impl ExecRequest {
    pub fn new(
        action_stream: ActionStream,
        cwd: Observed<AbsolutePath>,
        roots: Observed<Vec<Root>>,
    ) -> Result<Self, ExecRequestError> {
        Ok(Self::from_observation(
            action_stream,
            ExecObservation::new(cwd, roots)?,
        ))
    }

    fn from_observation(action_stream: ActionStream, observation: ExecObservation) -> Self {
        Self {
            v: ExecProtocolVersion::V1,
            action_stream,
            observation,
        }
    }

    pub const fn version(&self) -> ExecProtocolVersion {
        self.v
    }

    pub fn action_stream(&self) -> &ActionStream {
        &self.action_stream
    }

    pub fn observation(&self) -> &ExecObservation {
        &self.observation
    }
}

impl<'de> Deserialize<'de> for ExecRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct VersionOnly {
            v: ExecProtocolVersion,
        }

        #[derive(Deserialize)]
        struct WireRequest {
            #[serde(rename = "v")]
            _v: ExecProtocolVersion,
            action_stream: ActionStream,
            observation: ExecObservation,
        }

        let value = serde_json::Value::deserialize(deserializer)?;
        let version = VersionOnly::deserialize(&value).map_err(serde::de::Error::custom)?;
        if version.v != ExecProtocolVersion::V1 {
            return Err(serde::de::Error::custom("unsupported-version"));
        }
        let wire = WireRequest::deserialize(value).map_err(serde::de::Error::custom)?;
        Ok(Self::from_observation(wire.action_stream, wire.observation))
    }
}

/// Why an action stream failed its invariants; `code` is the stable wire text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    AnnotationCount,
    InvalidAnnotationDomain,
    InvalidPathLabel,
    InvalidPlan,
    UnsupportedVersion,
}

impl StreamError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AnnotationCount => "annotation-count",
            Self::InvalidAnnotationDomain => "invalid-annotation-domain",
            Self::InvalidPathLabel => "invalid-path-label",
            Self::InvalidPlan => "invalid-plan",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for StreamError {}
