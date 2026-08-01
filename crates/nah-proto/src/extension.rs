//! Raw extension responses and their single semantic validation boundary.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::action::{ActionStream, ActionStreamVersion};
use crate::ctx::{ActivationProjection, Ctx, ExecProtocolVersion};

/// The untrusted response decoded from an extension process or memo-cache entry.
///
/// Both outcome arms are optional on purpose. This preserves malformed-but-
/// decodable responses for deterministic semantic validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The structured result of consulting one selected extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionConsultation {
    pub activation: ActivationProjection,
    pub outcome: ConsultationOutcome,
}

/// Process and transport results are data rather than implicit absence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConsultationOutcome {
    Response { response: ExtensionResponse },
    Silence,
    Crash,
    Timeout,
    SpawnFailure,
    RejectedTransport { code: TransportRejectionCode },
}

/// Stable transport rejection codes. OS errors and process output never enter
/// these values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportRejectionCode {
    Oversize,
    InvalidUtf8,
    InvalidJson,
    MultipleValues,
    InvalidFraming,
    InvalidResponseFields,
}

/// A response which has crossed the only semantic validation boundary.
///
/// Its fields and inner outcome are private, and the type intentionally does
/// not implement serde or `Default`. Policy code can only inspect it through
/// read-only accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedExtensionResponse {
    activation: ActivationProjection,
    outcome: ValidatedOutcome,
    reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ValidatedOutcome {
    Block,
    Abstain,
}

impl ValidatedExtensionResponse {
    pub fn activation(&self) -> &ActivationProjection {
        &self.activation
    }

    pub fn is_block(&self) -> bool {
        matches!(self.outcome, ValidatedOutcome::Block)
    }

    pub fn is_abstain(&self) -> bool {
        matches!(self.outcome, ValidatedOutcome::Abstain)
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Stable, non-secret semantic validation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionValidationError {
    InactiveActivation,
    UnsupportedExecProtocol,
    UnsupportedActionStreamVersion,
    DuplicateActionStreamEffectId,
    AmbiguousResponse,
    MissingOutcome,
    BlockMustBeTrue,
    AbstainMustBeTrue,
    AbstainHasReason,
    MissingReason,
    ReasonTooLong,
    InvalidReasonControl,
}

impl ExtensionValidationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InactiveActivation => "inactive-activation",
            Self::UnsupportedExecProtocol => "unsupported-exec-protocol",
            Self::UnsupportedActionStreamVersion => "unsupported-action-stream-version",
            Self::DuplicateActionStreamEffectId => "duplicate-action-stream-effect-id",
            Self::AmbiguousResponse => "ambiguous-response",
            Self::MissingOutcome => "missing-outcome",
            Self::BlockMustBeTrue => "block-must-be-true",
            Self::AbstainMustBeTrue => "abstain-must-be-true",
            Self::AbstainHasReason => "abstain-has-reason",
            Self::MissingReason => "missing-reason",
            Self::ReasonTooLong => "reason-too-long",
            Self::InvalidReasonControl => "invalid-reason-control",
        }
    }
}

impl fmt::Display for ExtensionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ExtensionValidationError {}

/// Validates an untrusted response against the captured activation and current
/// action stream. No transport, filesystem, environment, or clock access is
/// performed here.
pub fn validate_response(
    ctx: &Ctx,
    activation: &ActivationProjection,
    action_stream: &ActionStream,
    response: ExtensionResponse,
) -> Result<ValidatedExtensionResponse, ExtensionValidationError> {
    if !ctx.activations().contains(activation) {
        return Err(ExtensionValidationError::InactiveActivation);
    }
    if activation.protocol() != ExecProtocolVersion::V1 {
        return Err(ExtensionValidationError::UnsupportedExecProtocol);
    }
    if action_stream.version() != ActionStreamVersion::V1 {
        return Err(ExtensionValidationError::UnsupportedActionStreamVersion);
    }

    let effect_ids = action_stream
        .effects()
        .iter()
        .map(|effect| effect.id().clone())
        .collect::<BTreeSet<_>>();
    if effect_ids.len() != action_stream.effects().len() {
        return Err(ExtensionValidationError::DuplicateActionStreamEffectId);
    }

    let ExtensionResponse {
        block,
        abstain,
        reason,
    } = response;

    let outcomes = usize::from(block.is_some()) + usize::from(abstain.is_some());
    if outcomes > 1 {
        return Err(ExtensionValidationError::AmbiguousResponse);
    }
    if outcomes == 0 {
        return Err(ExtensionValidationError::MissingOutcome);
    }
    if block == Some(false) {
        return Err(ExtensionValidationError::BlockMustBeTrue);
    }
    if abstain == Some(false) {
        return Err(ExtensionValidationError::AbstainMustBeTrue);
    }

    if abstain == Some(true) {
        if reason.is_some() {
            return Err(ExtensionValidationError::AbstainHasReason);
        }
        return Ok(ValidatedExtensionResponse {
            activation: activation.clone(),
            outcome: ValidatedOutcome::Abstain,
            reason: String::new(),
        });
    }

    let reason = reason.ok_or(ExtensionValidationError::MissingReason)?;
    validate_reason(&reason)?;

    // Only `block` remains: `abstain` returned above, and the outcome count
    // already rejected a response that carries neither or both.
    Ok(ValidatedExtensionResponse {
        activation: activation.clone(),
        outcome: ValidatedOutcome::Block,
        reason,
    })
}

fn validate_reason(reason: &str) -> Result<(), ExtensionValidationError> {
    if reason.is_empty() {
        return Err(ExtensionValidationError::MissingReason);
    }
    if reason.len() > 1024 {
        return Err(ExtensionValidationError::ReasonTooLong);
    }
    if reason.chars().any(|character| {
        matches!(character, '\u{0}'..='\u{8}' | '\u{b}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
    }) {
        return Err(ExtensionValidationError::InvalidReasonControl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ExtensionValidationError, validate_reason};

    #[test]
    fn reason_bound_is_measured_in_utf8_bytes() {
        assert_eq!(
            validate_reason(""),
            Err(ExtensionValidationError::MissingReason)
        );
        assert_eq!(validate_reason(&"a".repeat(1024)), Ok(()));
        assert_eq!(
            validate_reason(&"a".repeat(1025)),
            Err(ExtensionValidationError::ReasonTooLong)
        );
        assert_eq!(validate_reason(&"é".repeat(512)), Ok(()));
        assert_eq!(
            validate_reason(&"é".repeat(513)),
            Err(ExtensionValidationError::ReasonTooLong)
        );
    }

    #[test]
    fn reason_allows_tab_and_newline_but_rejects_other_control_characters() {
        assert_eq!(validate_reason("line one\n\tline two"), Ok(()));
        assert_eq!(
            validate_reason("terminal\u{1b}escape"),
            Err(ExtensionValidationError::InvalidReasonControl)
        );
        assert_eq!(
            validate_reason("c1\u{85}control"),
            Err(ExtensionValidationError::InvalidReasonControl)
        );
    }
}
