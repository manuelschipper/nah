//! Coordinates selected extension consultations and memoization; it does not decide policy.

use nah_proto::action::ActionStream;
use nah_proto::ctx::Ctx;
use nah_proto::extension::{
    ConsultationOutcome, ExtensionConsultation, ExtensionValidationError, TransportRejectionCode,
    ValidatedExtensionResponse, validate_response,
};
use nah_proto::observation::Observation;

use crate::bundle::{ActiveExtensionCatalog, ExtensionBundle};
use crate::cache::MemoCache;
use crate::selection::{memo_key, request, selected_extensions};
use crate::transport::{decode_cache_entry, encode_cache_entry, execute, outcome_code};

pub struct ConsultationOutput {
    pub consultations: Vec<ExtensionConsultation>,
    pub responses: Vec<ValidatedExtensionResponse>,
    pub warnings: Vec<String>,
    pub diagnostics: Vec<ConsultationDiagnostic>,
    pub failures: Vec<ConsultationFailure>,
}

/// A stable, non-secret reason why a selected guard produced no policy input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsultationFailure {
    activation: nah_proto::ctx::ActivationProjection,
    kind: ConsultationFailureKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsultationFailureKind {
    RequestConstruction,
    Silence,
    Crash,
    Timeout,
    SpawnFailure,
    RejectedTransport(TransportRejectionCode),
    RejectedResponse(ExtensionValidationError),
}

impl ConsultationFailure {
    pub fn activation(&self) -> &nah_proto::ctx::ActivationProjection {
        &self.activation
    }

    pub const fn code(&self) -> &'static str {
        match self.kind {
            ConsultationFailureKind::RequestConstruction => "request-construction",
            ConsultationFailureKind::Silence => "silence",
            ConsultationFailureKind::Crash => "crash",
            ConsultationFailureKind::Timeout => "timeout",
            ConsultationFailureKind::SpawnFailure => "spawn-failure",
            ConsultationFailureKind::RejectedTransport(code) => transport_rejection_code(code),
            ConsultationFailureKind::RejectedResponse(error) => error.code(),
        }
    }
}

/// Bounded extension stderr carried to the application redaction boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsultationDiagnostic {
    activation: nah_proto::ctx::ActivationProjection,
    stderr: String,
}

impl ConsultationDiagnostic {
    pub fn activation(&self) -> &nah_proto::ctx::ActivationProjection {
        &self.activation
    }

    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

pub fn consult_extensions(
    catalog: &ActiveExtensionCatalog,
    ctx: &Ctx,
    observation: &Observation,
    action_stream: &ActionStream,
    cache: &MemoCache,
) -> ConsultationOutput {
    let selected = selected_extensions(catalog, ctx, action_stream);
    let request = match request(action_stream, observation) {
        Ok(request) => request,
        Err(error) => {
            return ConsultationOutput {
                consultations: vec![],
                responses: vec![],
                warnings: vec![format!("extension request failed: {error}")],
                diagnostics: vec![],
                failures: selected
                    .into_iter()
                    .map(|extension| ConsultationFailure {
                        activation: extension.projection().clone(),
                        kind: ConsultationFailureKind::RequestConstruction,
                    })
                    .collect(),
            };
        }
    };
    let mut consultations = Vec::with_capacity(selected.len());
    let mut responses = Vec::new();
    let mut warnings = Vec::new();
    let mut diagnostics = Vec::new();
    let mut failures = Vec::new();

    for extension in selected {
        let key = memo_key(&request, ctx, extension);
        let mut should_cache = false;
        let (consultation, diagnostic) = match cache.get(&key) {
            Ok(Some(bytes)) => match decode_cache_entry(&bytes, &key, extension.projection()) {
                Ok(response)
                    if validate_response(
                        ctx,
                        extension.projection(),
                        action_stream,
                        response.clone(),
                    )
                    .is_ok() =>
                {
                    (
                        ExtensionConsultation {
                            activation: extension.projection().clone(),
                            outcome: ConsultationOutcome::Response { response },
                        },
                        None,
                    )
                }
                _ => {
                    let _ = cache.discard(&key);
                    should_cache = true;
                    execute_extension(extension, &request)
                }
            },
            Ok(None) => {
                should_cache = true;
                execute_extension(extension, &request)
            }
            Err(error) => {
                warnings.push(format!(
                    "extension `{}` cache failed: {error}",
                    extension.projection().identity().name()
                ));
                should_cache = true;
                execute_extension(extension, &request)
            }
        };
        if let ConsultationOutcome::Response { response } = &consultation.outcome {
            match validate_response(ctx, extension.projection(), action_stream, response.clone()) {
                Ok(response) => {
                    if should_cache
                        && let ConsultationOutcome::Response { response: raw } =
                            &consultation.outcome
                        && let Ok(bytes) = encode_cache_entry(&key, extension.projection(), raw)
                        && let Err(error) = cache.put(&key, &bytes)
                    {
                        warnings.push(format!(
                            "extension `{}` cache write failed: {error}",
                            extension.projection().identity().name()
                        ));
                    }
                    responses.push(response);
                }
                Err(error) => {
                    failures.push(ConsultationFailure {
                        activation: extension.projection().clone(),
                        kind: ConsultationFailureKind::RejectedResponse(error),
                    });
                    warnings.push(format!(
                        "extension `{}` response rejected: {error}",
                        extension.projection().identity().name()
                    ));
                }
            }
        } else {
            failures.push(ConsultationFailure {
                activation: extension.projection().clone(),
                kind: failure_kind(&consultation.outcome)
                    .expect("every non-response outcome is a failure"),
            });
            warnings.push(format!(
                "extension `{}` failed: {}",
                extension.projection().identity().name(),
                outcome_code(&consultation.outcome)
            ));
        }
        if let Some(diagnostic) = diagnostic {
            diagnostics.push(diagnostic);
        }
        consultations.push(consultation);
    }
    ConsultationOutput {
        consultations,
        responses,
        warnings,
        diagnostics,
        failures,
    }
}

const fn failure_kind(outcome: &ConsultationOutcome) -> Option<ConsultationFailureKind> {
    match outcome {
        ConsultationOutcome::Response { .. } => None,
        ConsultationOutcome::Silence => Some(ConsultationFailureKind::Silence),
        ConsultationOutcome::Crash => Some(ConsultationFailureKind::Crash),
        ConsultationOutcome::Timeout => Some(ConsultationFailureKind::Timeout),
        ConsultationOutcome::SpawnFailure => Some(ConsultationFailureKind::SpawnFailure),
        ConsultationOutcome::RejectedTransport { code } => {
            Some(ConsultationFailureKind::RejectedTransport(*code))
        }
    }
}

const fn transport_rejection_code(code: TransportRejectionCode) -> &'static str {
    match code {
        TransportRejectionCode::Oversize => "oversize",
        TransportRejectionCode::InvalidUtf8 => "invalid-utf8",
        TransportRejectionCode::InvalidJson => "invalid-json",
        TransportRejectionCode::MultipleValues => "multiple-values",
        TransportRejectionCode::InvalidFraming => "invalid-framing",
        TransportRejectionCode::InvalidResponseFields => "invalid-response-fields",
    }
}

fn execute_extension(
    extension: &ExtensionBundle,
    request: &nah_proto::exec_v1::ExecV1Request,
) -> (ExtensionConsultation, Option<ConsultationDiagnostic>) {
    let executed = execute(extension, request);
    let diagnostic = executed.stderr.map(|stderr| ConsultationDiagnostic {
        activation: extension.projection().clone(),
        stderr,
    });
    (executed.consultation, diagnostic)
}
