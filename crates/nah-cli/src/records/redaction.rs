//! Constructs audit DTOs through one deterministic redaction boundary.

use nah_extensions::ConsultationDiagnostic;
use nah_proto::action::{
    ActionStream, EffectKind, FilesystemOperation, InvocationEffect, Sensitivity,
};
use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::{DecisionCore, DecisionEnvelope, GuardAttribution, Verdict};
use nah_proto::extension::{ConsultationOutcome, ExtensionConsultation, TransportRejectionCode};
use nah_proto::tool::ToolCallInput;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::pipeline::EvaluationFailure;

const MASK: &str = "[redacted]";

/// Effects a listing row names before it collapses the rest into a count.
const LISTING_EFFECTS: usize = 2;

/// Column every detail value starts in: `command:`, `verdict:`, and `runtime:`
/// are the widest keys and every record prints them.
const VALUE_COLUMN: usize = 9;

/// Recorded when the caller declared no runtime: generic `nah decide` cannot
/// know which agent sent the call.
pub(super) const UNKNOWN_RUNTIME: &str = "unknown";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct RedactedText(String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct AuditRecordV1 {
    schema: &'static str,
    v: SchemaVersion,
    #[serde(flatten)]
    outcome: AuditOutcome,
    envelope: DecisionEnvelope,
    /// Coding-agent runtime whose adapter decided this call, or `unknown` for
    /// a generic `nah decide`. Required: a record that does not say who
    /// decided is not a record nah accepts. nah owns every value written here,
    /// so it is recorded unredacted.
    runtime: String,
    command: RedactedText,
    effects: Vec<AuditEffect>,
    diagnostics: Vec<RedactedText>,
    consultations: Vec<AuditConsultation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    failures: Vec<AuditFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum AuditOutcome {
    Decision { core: AuditCore },
    Unavailable { reason: RedactedText },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecordWire {
    schema: String,
    v: SchemaVersion,
    status: AuditStatus,
    core: Option<AuditCore>,
    reason: Option<RedactedText>,
    envelope: DecisionEnvelope,
    runtime: String,
    command: RedactedText,
    effects: Vec<AuditEffect>,
    diagnostics: Vec<RedactedText>,
    consultations: Vec<AuditConsultation>,
    #[serde(default)]
    failures: Vec<AuditFailure>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuditStatus {
    Decision,
    Unavailable,
}

impl<'de> Deserialize<'de> for AuditRecordV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuditRecordWire::deserialize(deserializer)?;
        if wire.schema != AuditRecordV1::SCHEMA || wire.v != SchemaVersion::V1 {
            return Err(D::Error::custom("unsupported-audit-schema"));
        }
        let outcome = match (wire.status, wire.core, wire.reason) {
            (AuditStatus::Decision, Some(core), None) => AuditOutcome::Decision { core },
            (AuditStatus::Unavailable, None, Some(reason)) => AuditOutcome::Unavailable { reason },
            _ => return Err(D::Error::custom("invalid audit outcome")),
        };
        Ok(Self {
            schema: Self::SCHEMA,
            v: wire.v,
            outcome,
            envelope: wire.envelope,
            runtime: wire.runtime,
            command: wire.command,
            effects: wire.effects,
            diagnostics: wire.diagnostics,
            consultations: wire.consultations,
            failures: wire.failures,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditCore {
    verdict: Verdict,
    reason: RedactedText,
    policy_attributions: Vec<GuardAttribution>,
    coverage: nah_proto::action::Coverage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEffect {
    id: String,
    description: RedactedText,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditConsultation {
    policy: GuardAttribution,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<RedactedText>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFailure {
    source: String,
    component: String,
    code: String,
}

pub(super) struct AuditDiagnostics<'a> {
    warnings: &'a [String],
    consultations: &'a [ExtensionConsultation],
    stderr: &'a [ConsultationDiagnostic],
    failures: &'a [EvaluationFailure],
}

impl<'a> AuditDiagnostics<'a> {
    pub(super) fn new(
        warnings: &'a [String],
        consultations: &'a [ExtensionConsultation],
        stderr: &'a [ConsultationDiagnostic],
    ) -> Self {
        Self {
            warnings,
            consultations,
            stderr,
            failures: &[],
        }
    }

    pub(super) fn with_failures(mut self, failures: &'a [EvaluationFailure]) -> Self {
        self.failures = failures;
        self
    }
}

impl AuditRecordV1 {
    const SCHEMA: &'static str = "nah/audit/v1";

    pub(super) fn redact(
        tool_call: &ToolCallInput,
        action_stream: &ActionStream,
        core: &DecisionCore,
        envelope: DecisionEnvelope,
        runtime: &str,
        diagnostics: AuditDiagnostics<'_>,
    ) -> Self {
        let effects = action_stream
            .effects()
            .iter()
            .map(|effect| AuditEffect {
                id: effect.id().as_str().to_owned(),
                description: redact_effect(effect.kind()),
            })
            .collect();
        let consultations = diagnostics
            .consultations
            .iter()
            .map(|consultation| AuditConsultation {
                policy: GuardAttribution::extension(consultation.activation.clone()),
                outcome: consultation_outcome(&consultation.outcome).to_owned(),
                stderr: diagnostics
                    .stderr
                    .iter()
                    .find(|diagnostic| diagnostic.activation() == &consultation.activation)
                    .map(|diagnostic| redact(diagnostic.stderr(), true)),
            })
            .collect();

        let outcome = AuditOutcome::Decision {
            core: redact_core(core),
        };
        Self {
            schema: Self::SCHEMA,
            v: SchemaVersion::V1,
            outcome,
            envelope,
            runtime: runtime.to_owned(),
            command: redact_tool_call(tool_call, true),
            effects,
            diagnostics: diagnostics
                .warnings
                .iter()
                .map(|warning| RedactedText(warning.clone()))
                .collect(),
            consultations,
            failures: redact_failures(diagnostics.failures),
        }
    }

    pub(super) fn failure(
        tool_call: &ToolCallInput,
        core: &DecisionCore,
        envelope: DecisionEnvelope,
        runtime: &str,
        warnings: &[String],
        failures: &[EvaluationFailure],
    ) -> Self {
        let outcome = AuditOutcome::Decision {
            core: redact_core(core),
        };
        Self {
            schema: Self::SCHEMA,
            v: SchemaVersion::V1,
            outcome,
            envelope,
            runtime: runtime.to_owned(),
            command: redact_tool_call(tool_call, true),
            effects: vec![],
            diagnostics: warnings
                .iter()
                .map(|warning| RedactedText(warning.clone()))
                .collect(),
            consultations: vec![],
            failures: redact_failures(failures),
        }
    }

    pub(super) fn id(&self) -> &str {
        self.envelope.id()
    }

    pub(super) fn timestamp_rfc3339(&self) -> &str {
        self.envelope.timestamp_rfc3339()
    }

    pub(super) const fn verdict(&self) -> Option<Verdict> {
        match &self.outcome {
            AuditOutcome::Decision { core } => Some(core.verdict),
            AuditOutcome::Unavailable { .. } => None,
        }
    }

    pub(super) fn runtime(&self) -> &str {
        &self.runtime
    }

    pub(super) fn evaluation_failed(&self) -> bool {
        matches!(self.outcome, AuditOutcome::Unavailable { .. }) || !self.failures.is_empty()
    }

    pub(super) fn failure_component(&self) -> String {
        match self.failures.as_slice() {
            [] => "unavailable".into(),
            [failure] => failure.component.clone(),
            _ => "multiple components".into(),
        }
    }

    /// One scannable line for the record. A masked command names the tool at
    /// best, so the row falls back to the effects, whose descriptions already
    /// crossed the same redaction boundary the command did. The tool's own
    /// invocation effect and the `invoke` prefix only restate that boundary,
    /// so the row drops them and reads `Tool: what it did`.
    pub(super) fn display(&self) -> String {
        let command = single_line(&self.command.0);
        let Some(tool) = command.strip_suffix(MASK) else {
            return command;
        };
        let tool = tool.trim_end();
        let self_invocation = format!("invoke {tool} ");
        let duplicated_verb = format!("{} ", tool.to_lowercase());
        let named = self
            .effects
            .iter()
            .filter(|effect| !effect.description.0.starts_with(&self_invocation))
            .map(|effect| {
                let description = effect.description.0.as_str();
                let description = description.strip_prefix("invoke ").unwrap_or(description);
                description
                    .strip_prefix(&duplicated_verb)
                    .unwrap_or(description)
            })
            .collect::<Vec<_>>();
        if named.is_empty() {
            // Nothing but its own invocation is still more readable than a
            // repeated mask; a record with no effects at all keeps the mask.
            return if self.effects.is_empty() {
                command
            } else {
                tool.to_owned()
            };
        }
        let shown = &named[..named.len().min(LISTING_EFFECTS)];
        let remaining = match named.len() - shown.len() {
            0 => String::new(),
            hidden => format!(" (+{hidden})"),
        };
        single_line(&format!("{tool}: {}{remaining}", shown.join(", ")))
    }

    pub(super) fn summary(&self) -> String {
        format!(
            "{}  {:<8}  {:<10}  {}  ({})",
            short_time(self.envelope.timestamp_rfc3339()),
            self.outcome_name(),
            self.runtime,
            self.display(),
            self.envelope.id()
        )
    }

    pub(super) fn explanation(&self) -> String {
        let (outcome, reason) = match &self.outcome {
            AuditOutcome::Decision { core } => {
                // A call can trip more than one guard, so the verdict line
                // names every guard that attributed it.
                let mut verdict = verdict_name(core.verdict).to_owned();
                for guard in &core.policy_attributions {
                    verdict.push_str(" · ");
                    verdict.push_str(guard.name());
                }
                (field("verdict:", &verdict), core.reason.0.as_str())
            }
            AuditOutcome::Unavailable { reason } => {
                (field("status:", "unavailable"), reason.0.as_str())
            }
        };
        let mut lines = vec![field("id:", self.envelope.id()), outcome];
        // Stored reasons join their clauses with `; `. The detail view gives
        // each following clause its own line; the stored string is untouched.
        let mut clauses = reason.split("; ");
        lines.push(field("reason:", clauses.next().unwrap_or_default()));
        for clause in clauses {
            lines.push(format!("{:VALUE_COLUMN$}→ {clause}", ""));
        }
        lines.push(String::new());
        lines.push(field("command:", &self.command.0));
        lines.push(field("runtime:", &self.runtime));
        lines.push(String::new());
        lines.push("effects:".into());
        let id_width = self
            .effects
            .iter()
            .map(|effect| effect.id.chars().count())
            .max()
            .unwrap_or_default();
        for effect in &self.effects {
            lines.push(format!(
                "  {:id_width$}  {}",
                effect.id, effect.description.0
            ));
        }
        for diagnostic in &self.diagnostics {
            lines.push(format!("diagnostic: {}", diagnostic.0));
        }
        for consultation in &self.consultations {
            let stderr = consultation
                .stderr
                .as_ref()
                .map(|stderr| format!("; stderr: {}", stderr.0))
                .unwrap_or_default();
            lines.push(format!(
                "policy {}: {}{}",
                consultation.policy.name(),
                consultation.outcome,
                stderr
            ));
        }
        for failure in &self.failures {
            lines.push(format!(
                "failure: {}/{}/{}",
                failure.source, failure.component, failure.code
            ));
        }
        lines.join("\n")
    }

    fn outcome_name(&self) -> &'static str {
        match self.verdict() {
            Some(verdict) => verdict_name(verdict),
            None => "unavailable",
        }
    }
}

fn redact_failures(failures: &[EvaluationFailure]) -> Vec<AuditFailure> {
    failures
        .iter()
        .map(|failure| AuditFailure {
            source: failure.source().to_owned(),
            component: failure.component().to_owned(),
            code: failure.code().to_owned(),
        })
        .collect()
}

fn redact_core(core: &DecisionCore) -> AuditCore {
    let masks_reason = core
        .policy_attributions()
        .iter()
        .any(|guard| matches!(guard, GuardAttribution::Extension { .. }));
    AuditCore {
        verdict: core.verdict(),
        reason: redact(core.reason(), masks_reason),
        policy_attributions: core.policy_attributions().to_vec(),
        coverage: core.coverage(),
    }
}

/// One detail line with its value in the shared column.
pub(crate) fn field(key: &str, value: &str) -> String {
    format!("{key:<VALUE_COLUMN$}{value}")
}

/// Collapses newlines and runs of spaces so a multi-line command stays on one listing row.
fn single_line(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shortens `2026-07-26T21:58:24Z` to `07-26 21:58:24` for narrow list rows.
pub(crate) fn short_time(timestamp: &str) -> String {
    match (timestamp.get(5..10), timestamp.get(11..19)) {
        (Some(date), Some(time)) => format!("{date} {time}"),
        _ => timestamp.to_owned(),
    }
}

pub(crate) const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Block => "block",
        Verdict::Delegate => "delegate",
    }
}

fn redact(value: &str, masked: bool) -> RedactedText {
    RedactedText(if masked { MASK.into() } else { value.into() })
}

fn redact_tool_call(tool_call: &ToolCallInput, masked: bool) -> RedactedText {
    if !masked
        && tool_call.tool() == "Bash"
        && let Some(command) = tool_call
            .input()
            .as_object()
            .and_then(|input| input.get("command"))
            .and_then(serde_json::Value::as_str)
    {
        return RedactedText(command.to_owned());
    }
    RedactedText(format!("{} {MASK}", tool_call.tool()))
}

fn consultation_outcome(outcome: &ConsultationOutcome) -> &'static str {
    match outcome {
        ConsultationOutcome::Response { .. } => "response",
        ConsultationOutcome::Silence => "silence",
        ConsultationOutcome::Crash => "crash",
        ConsultationOutcome::Timeout => "timeout",
        ConsultationOutcome::SpawnFailure => "spawn-failure",
        ConsultationOutcome::RejectedTransport { code } => match code {
            TransportRejectionCode::Oversize => "rejected-transport:oversize",
            TransportRejectionCode::InvalidUtf8 => "rejected-transport:invalid-utf8",
            TransportRejectionCode::InvalidJson => "rejected-transport:invalid-json",
            TransportRejectionCode::MultipleValues => "rejected-transport:multiple-values",
            TransportRejectionCode::InvalidFraming => "rejected-transport:invalid-framing",
            TransportRejectionCode::InvalidResponseFields => {
                "rejected-transport:invalid-response-fields"
            }
        },
    }
}

fn redact_effect(kind: &EffectKind) -> RedactedText {
    let description = match kind {
        EffectKind::Invocation { invocation } => match invocation {
            InvocationEffect::Known {
                program, operation, ..
            } => {
                format!("invoke {program} {operation}")
            }
            InvocationEffect::Opaque { program, .. } => format!("invoke {program} opaque"),
            InvocationEffect::CodeExecution {
                interpreter,
                source,
                ..
            } => format!(
                "execute {} {source}",
                interpreter.as_deref().unwrap_or("unknown")
            ),
        },
        EffectKind::Filesystem { effect } => {
            let operation = match effect.operation {
                FilesystemOperation::Read => "read",
                FilesystemOperation::Write => "write",
                FilesystemOperation::Delete => "delete",
            };
            let target = if effect.sensitivity == Sensitivity::None {
                effect.target.as_str()
            } else {
                MASK
            };
            format!("{operation} {target}")
        }
        EffectKind::FilesystemUnresolved { operation, .. } => {
            let operation = match operation {
                FilesystemOperation::Read => "read",
                FilesystemOperation::Write => "write",
                FilesystemOperation::Delete => "delete",
            };
            format!("{operation} unresolved filesystem target")
        }
        EffectKind::Git { operation } => format!("git {operation}"),
        EffectKind::Network { .. } => format!("network outbound {MASK}"),
        EffectKind::SystemState { operation } => format!("system {operation}"),
    };
    RedactedText(description)
}

#[cfg(test)]
mod tests;
