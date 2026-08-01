//! The one-shot custom-guard request used by nah.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

use crate::action::ActionStream;
use crate::ctx::{AbsolutePath, ExecProtocolVersion};
use crate::observation::{Observed, Root};

/// The deliberately narrow Observation projection exposed to extensions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecObservation {
    cwd: Observed<AbsolutePath>,
    roots: Observed<Vec<Root>>,
}

impl ExecObservation {
    pub fn new(
        cwd: Observed<AbsolutePath>,
        mut roots: Observed<Vec<Root>>,
    ) -> Result<Self, ExecRequestError> {
        if let Observed::Ok { value } = &mut roots {
            value.sort();
            if value.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(ExecRequestError::DuplicateRoot);
            }
        }
        Ok(Self { cwd, roots })
    }

    pub fn cwd(&self) -> &Observed<AbsolutePath> {
        &self.cwd
    }

    pub fn roots(&self) -> &Observed<Vec<Root>> {
        &self.roots
    }
}

impl<'de> Deserialize<'de> for ExecObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            cwd: Observed<AbsolutePath>,
            roots: Observed<Vec<Root>>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.cwd, wire.roots).map_err(serde::de::Error::custom)
    }
}

/// One stdin request to an `exec/v1` extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecV1Request {
    v: ExecProtocolVersion,
    action_stream: ActionStream,
    observation: ExecObservation,
}

impl<'de> Deserialize<'de> for ExecV1Request {
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

impl ExecV1Request {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecRequestError {
    DuplicateRoot,
}

impl fmt::Display for ExecRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate-root")
    }
}

impl Error for ExecRequestError {}
