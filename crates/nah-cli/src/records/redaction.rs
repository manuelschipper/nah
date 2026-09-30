//! Constructs audit DTOs through one deterministic redaction boundary.

use nah_extensions::ConsultationDiagnostic;
use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::{DecisionCore, DecisionEnvelope, GuardAttribution, Verdict};
use nah_proto::extension::ExtensionConsultation;
use nah_proto::labels::Sensitivity;
use nah_proto::tool::ToolCallInput;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::pipeline::{AnalysisRefusal, EvaluationFailure};

const MASK: &str = "[redacted]";

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
    /// Producer whose analysis this decision was reduced from. Absent when the
    /// call was answered before any producer ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    producer: Option<String>,
    command: RedactedText,
    effects: Vec<AuditEffect>,
    diagnostics: Vec<RedactedText>,
    consultations: Vec<AuditConsultation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    failures: Vec<AuditFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effinterp: Option<AuditEffinterp>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum AuditOutcome {
    Decision { core: AuditCore },
    Refused { core: AuditCore },
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
    #[serde(default)]
    producer: Option<String>,
    command: RedactedText,
    effects: Vec<AuditEffect>,
    diagnostics: Vec<RedactedText>,
    consultations: Vec<AuditConsultation>,
    #[serde(default)]
    failures: Vec<AuditFailure>,
    #[serde(default)]
    effinterp: Option<AuditEffinterp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuditStatus {
    Decision,
    Refused,
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
            (AuditStatus::Refused, Some(core), None) => AuditOutcome::Refused { core },
            (AuditStatus::Unavailable, None, Some(reason)) => AuditOutcome::Unavailable { reason },
            _ => return Err(D::Error::custom("invalid audit outcome")),
        };
        Ok(Self {
            schema: Self::SCHEMA,
            v: wire.v,
            outcome,
            envelope: wire.envelope,
            runtime: wire.runtime,
            producer: wire.producer,
            command: wire.command,
            effects: wire.effects,
            diagnostics: wire.diagnostics,
            consultations: wire.consultations,
            failures: wire.failures,
            effinterp: wire.effinterp,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEffinterp {
    engine_time_us: u64,
    gap: bool,
    effects: Vec<AuditEffinterpEffect>,
    annotations: Vec<AuditEffinterpAnnotation>,
    boundary_count: usize,
    coverage: Vec<AuditEffinterpCoverage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEffinterpEffect {
    operation: String,
    resource: RedactedText,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEffinterpAnnotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_integrity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selects_root: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selects_home: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_cli: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEffinterpCoverage {
    domain: String,
    level: String,
}

pub(super) struct AuditDiagnostics<'a> {
    warnings: &'a [String],
    consultations: &'a [ExtensionConsultation],
    stderr: &'a [ConsultationDiagnostic],
    failures: &'a [EvaluationFailure],
    refusals: &'a [AnalysisRefusal],
    producer: Option<&'a str>,
    effinterp: Option<&'a crate::pipeline::EffinterpAnalysis>,
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
            refusals: &[],
            producer: None,
            effinterp: None,
        }
    }

    pub(super) fn with_failures(mut self, failures: &'a [EvaluationFailure]) -> Self {
        self.failures = failures;
        self
    }

    pub(super) fn with_refusals(mut self, refusals: &'a [AnalysisRefusal]) -> Self {
        self.refusals = refusals;
        self
    }

    pub(super) const fn with_producer(mut self, producer: Option<&'a str>) -> Self {
        self.producer = producer;
        self
    }

    pub(super) fn with_effinterp(
        mut self,
        effinterp: Option<&'a crate::pipeline::EffinterpAnalysis>,
    ) -> Self {
        self.effinterp = effinterp;
        self
    }
}

impl AuditRecordV1 {
    const SCHEMA: &'static str = "nah/audit/v1";

    pub(super) fn redact(
        tool_call: &ToolCallInput,
        core: &DecisionCore,
        envelope: DecisionEnvelope,
        runtime: &str,
        diagnostics: AuditDiagnostics<'_>,
    ) -> Self {
        // The listing row and the explanation read what the command did from
        // these; they are the engine's annotated plan effects, already redacted.
        let effects = diagnostics
            .effinterp
            .map(effinterp_effects)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, effect)| AuditEffect {
                id: format!("e{index}"),
                description: RedactedText(format!("{} {}", effect.operation, effect.resource.0)),
            })
            .collect();
        let consultations = diagnostics
            .consultations
            .iter()
            .map(|consultation| AuditConsultation {
                policy: GuardAttribution::extension(consultation.activation.clone()),
                outcome: consultation.outcome.code().to_owned(),
                stderr: diagnostics
                    .stderr
                    .iter()
                    .find(|diagnostic| diagnostic.activation() == &consultation.activation)
                    .map(|diagnostic| redact(diagnostic.stderr(), true)),
            })
            .collect();

        let core = redact_core(core);
        let outcome = if diagnostics
            .refusals
            .iter()
            .any(|refusal| refusal.code() == "deadline-exceeded")
        {
            AuditOutcome::Refused { core }
        } else {
            AuditOutcome::Decision { core }
        };
        let effinterp = diagnostics.effinterp.map(redact_effinterp);
        Self {
            schema: Self::SCHEMA,
            v: SchemaVersion::V1,
            outcome,
            envelope,
            runtime: runtime.to_owned(),
            producer: diagnostics.producer.map(str::to_owned),
            command: redact_tool_call(tool_call),
            effects,
            diagnostics: diagnostics
                .warnings
                .iter()
                .map(|warning| RedactedText(warning.clone()))
                .collect(),
            consultations,
            failures: redact_failures(diagnostics.failures, diagnostics.refusals),
            effinterp,
        }
    }

    pub(super) fn failure(
        tool_call: &ToolCallInput,
        core: &DecisionCore,
        envelope: DecisionEnvelope,
        runtime: &str,
        warnings: &[String],
        failures: &[EvaluationFailure],
        refusals: &[AnalysisRefusal],
    ) -> Self {
        let core = redact_core(core);
        let outcome = if refusals
            .iter()
            .any(|refusal| refusal.code() == "deadline-exceeded")
        {
            AuditOutcome::Refused { core }
        } else {
            AuditOutcome::Decision { core }
        };
        Self {
            schema: Self::SCHEMA,
            v: SchemaVersion::V1,
            outcome,
            envelope,
            runtime: runtime.to_owned(),
            producer: None,
            command: redact_tool_call(tool_call),
            effects: vec![],
            diagnostics: warnings
                .iter()
                .map(|warning| RedactedText(warning.clone()))
                .collect(),
            consultations: vec![],
            failures: redact_failures(failures, refusals),
            effinterp: None,
        }
    }

    pub(super) fn unavailable(
        envelope: DecisionEnvelope,
        runtime: &str,
        reason: &str,
        component: &str,
        code: &str,
    ) -> Self {
        Self {
            schema: Self::SCHEMA,
            v: SchemaVersion::V1,
            outcome: AuditOutcome::Unavailable {
                reason: RedactedText(reason.to_owned()),
            },
            envelope,
            runtime: runtime.to_owned(),
            producer: None,
            command: RedactedText("[unavailable]".into()),
            effects: vec![],
            diagnostics: vec![],
            consultations: vec![],
            failures: vec![AuditFailure {
                source: "integration".into(),
                component: component.to_owned(),
                code: code.to_owned(),
            }],
            effinterp: None,
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
            AuditOutcome::Decision { core } | AuditOutcome::Refused { core } => Some(core.verdict),
            AuditOutcome::Unavailable { .. } => None,
        }
    }

    pub(super) fn runtime(&self) -> &str {
        &self.runtime
    }

    pub(super) fn evaluation_failed(&self) -> bool {
        matches!(
            self.outcome,
            AuditOutcome::Refused { .. } | AuditOutcome::Unavailable { .. }
        ) || !self.failures.is_empty()
    }

    pub(super) fn effinterp_gap(&self) -> bool {
        self.effinterp.as_ref().is_some_and(|stream| stream.gap)
    }

    pub(super) fn failure_component(&self) -> String {
        match self.failures.as_slice() {
            [] => "unavailable".into(),
            [failure] => failure.component.clone(),
            _ => "multiple components".into(),
        }
    }
}

fn effinterp_effects(analysis: &crate::pipeline::EffinterpAnalysis) -> Vec<AuditEffinterpEffect> {
    use nah_proto::effect_annotation::PathLabel;

    analysis
        .plan()
        .effects
        .iter()
        .zip(analysis.annotations())
        .map(|(effect, annotation)| {
            let sensitive = matches!(
                &annotation.path,
                Some(PathLabel::Resolved { sensitivity, .. }) if sensitivity != &Sensitivity::None
            );
            let masks_resource = sensitive || effect.operation.domain() != "filesystem";
            // A process is named by its executable; its arguments are
            // operands the record never persists.
            let resource = match &effect.resource {
                nah_proto::effinterp_proto::ResourceExpr::Concrete {
                    identity:
                        nah_proto::effinterp_proto::ResourceIdentity::Process { executable, .. },
                } => RedactedText(executable.clone()),
                resource => redact(
                    &nah_proto::effinterp_proto::display_resource(resource),
                    masks_resource,
                ),
            };
            AuditEffinterpEffect {
                operation: effect.operation.as_str().to_owned(),
                resource,
            }
        })
        .collect()
}

/// Audit label name: a `nah_proto::labels` label spelled by its serde name, so
/// the audit record never spells a label itself. A tagged label such as
/// `PathScope` records its `kind` alone, which drops the project root.
fn audit_label_name(label: &impl Serialize) -> String {
    let value = serde_json::to_value(label).expect("labels serialize to JSON");
    value
        .get("kind")
        .unwrap_or(&value)
        .as_str()
        .expect("labels serialize to a name or a tagged kind")
        .to_owned()
}

fn redact_effinterp(analysis: &crate::pipeline::EffinterpAnalysis) -> AuditEffinterp {
    use nah_proto::effect_annotation::PathLabel;

    let effects = effinterp_effects(analysis);
    let annotations = analysis
        .annotations()
        .iter()
        .map(|annotation| match &annotation.path {
            Some(PathLabel::Resolved {
                scope,
                sensitivity,
                protection,
                host_integrity,
                selects_root,
                selects_home,
                ..
            }) => AuditEffinterpAnnotation {
                scope: Some(audit_label_name(scope)),
                sensitivity: Some(audit_label_name(sensitivity)),
                protection: protection.as_ref().map(audit_label_name),
                host_integrity: host_integrity.as_ref().map(audit_label_name),
                selects_root: Some(*selects_root),
                selects_home: Some(*selects_home),
                runtime_cli: annotation.runtime_cli.clone(),
            },
            Some(PathLabel::Unresolved) | None => AuditEffinterpAnnotation {
                scope: None,
                sensitivity: None,
                protection: None,
                host_integrity: None,
                selects_root: None,
                selects_home: None,
                runtime_cli: annotation.runtime_cli.clone(),
            },
        })
        .collect();
    let coverage = analysis
        .plan()
        .coverage
        .0
        .iter()
        .map(|(domain, level)| AuditEffinterpCoverage {
            domain: domain.0.clone(),
            level: match level.level {
                nah_proto::effinterp_proto::CoverageLevel::Full => "full",
                nah_proto::effinterp_proto::CoverageLevel::Partial => "partial",
                nah_proto::effinterp_proto::CoverageLevel::None => "none",
            }
            .into(),
        })
        .collect();
    AuditEffinterp {
        engine_time_us: analysis.engine_time_us(),
        gap: analysis.gap(),
        effects,
        annotations,
        boundary_count: analysis.plan().boundaries.len(),
        coverage,
    }
}

fn redact_failures(
    failures: &[EvaluationFailure],
    refusals: &[AnalysisRefusal],
) -> Vec<AuditFailure> {
    failures
        .iter()
        .map(|failure| AuditFailure {
            source: failure.source().to_owned(),
            component: failure.component().to_owned(),
            code: failure.code().to_owned(),
        })
        .chain(refusals.iter().map(|refusal| AuditFailure {
            source: refusal.source().to_owned(),
            component: refusal.component().to_owned(),
            code: refusal.code().to_owned(),
        }))
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

fn redact(value: &str, masked: bool) -> RedactedText {
    RedactedText(if masked { MASK.into() } else { value.into() })
}

fn redact_tool_call(tool_call: &ToolCallInput) -> RedactedText {
    RedactedText(format!("{} {MASK}", tool_call.tool()))
}

pub(super) mod presentation;

#[cfg(test)]
mod tests;
