//! Exact decision pipeline shared by live calls and frozen corpus execution.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use nah_proto::action::Coverage;
use nah_proto::ctx::Ctx;
use nah_proto::decision::{DecisionCore, Verdict};
use nah_proto::extension::{ExtensionConsultation, ValidatedExtensionResponse};
use nah_proto::observation::{Observation, ObservationRequest};
use nah_proto::runtime_protection::SelfProtectionProjection;
use nah_proto::tool::ToolCallInput;

use crate::code_input::CodeInput;
use crate::live_state::LiveState;
use crate::nap::NapMode;

/// Frozen replays get this much so a corpus decision never depends on the
/// interactive deadline.
const REPLAY_EVIDENCE_BUDGET: Duration = Duration::from_secs(60);
/// Interactive calls get this much total evidence time; expiry is a typed
/// refusal, never a verdict. An optimised release build finishes a `/`-walking
/// analysis well inside 100 ms. Unoptimised builds exist only for local tests,
/// where a wall-clock deadline would make end-to-end verdicts depend on host
/// load, so they take the replay budget; tests that need the fail-to-delegate
/// path expire the deadline explicitly.
const PRODUCTION_EVIDENCE_BUDGET: Duration = if cfg!(debug_assertions) {
    REPLAY_EVIDENCE_BUDGET
} else {
    Duration::from_millis(100)
};
const MAX_ENVIRONMENT_ROUNDS: usize = 64;

/// Analysis identity stays outside the predicate-visible graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceProvenance {
    pub producer: String,
    pub model: Option<String>,
    pub limits: BTreeMap<String, u64>,
    pub input_fingerprint: String,
    pub observation_fingerprint: String,
}

fn evidence_fingerprint(value: &impl serde::Serialize) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("analysis inputs serialize"))
    )
}

fn memo_context(
    provenance: &EvidenceProvenance,
    source_identity: impl Into<String>,
) -> nah_extensions::MemoContext {
    nah_extensions::MemoContext::new(
        provenance.producer.clone(),
        provenance.model.clone(),
        provenance.limits.clone(),
        provenance.input_fingerprint.clone(),
        source_identity,
    )
}

/// One pipeline decision with everything it was reduced from: guard evidence,
/// observation, custom-guard consultations, evaluation failures, and analysis
/// refusals.
pub struct DecisionResult {
    evidence_provenance: Option<EvidenceProvenance>,
    guard_evidence:
        Option<Result<nah_proto::effects::GuardEvidence, nah_proto::effects::EvidenceError>>,
    core: DecisionCore,
    observation: Option<Observation>,
    warnings: Vec<String>,
    consultations: Vec<ExtensionConsultation>,
    diagnostics: Vec<nah_extensions::ConsultationDiagnostic>,
    failures: Vec<EvaluationFailure>,
    refusals: Vec<AnalysisRefusal>,
    effinterp: Option<EffinterpAnalysis>,
}

pub(crate) struct EffinterpAnalysis {
    plan: nah_proto::effinterp_proto::Plan,
    annotations: Vec<nah_proto::effect_annotation::EffectAnnotation>,
    /// Whole decision pipeline time, not engine time alone; see the accessor.
    engine_time_us: u64,
    gap: bool,
}

/// A Nah component or custom guard that could not finish evaluating a call,
/// named by a stable failure code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationFailure {
    source: EvaluationFailureSource,
    component: String,
    code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvaluationFailureSource {
    Nah,
    CustomGuard,
}

/// Where the pipeline stopped analyzing a call, from an invalid call site to an
/// engine boundary, with the recovery advice shown to the agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisRefusal {
    component: &'static str,
    code: &'static str,
    recovery: RecoveryAdvice,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum RecoveryAdvice {
    RetryOnce,
    CorrectOrSimplify,
    OperatorRequired,
}

#[derive(Default)]
struct ConsultedExtensions {
    consultations: Vec<ExtensionConsultation>,
    responses: Vec<ValidatedExtensionResponse>,
    warnings: Vec<String>,
    diagnostics: Vec<nah_extensions::ConsultationDiagnostic>,
    failures: Vec<EvaluationFailure>,
}

impl EvaluationFailure {
    pub(crate) fn nah(component: &'static str, code: &'static str) -> Self {
        Self {
            source: EvaluationFailureSource::Nah,
            component: component.to_owned(),
            code: code.to_owned(),
        }
    }

    fn custom(failure: &nah_extensions::ConsultationFailure) -> Self {
        Self {
            source: EvaluationFailureSource::CustomGuard,
            component: failure.activation().identity().name().to_owned(),
            code: failure.code().to_owned(),
        }
    }

    pub const fn source(&self) -> &'static str {
        match self.source {
            EvaluationFailureSource::Nah => "nah",
            EvaluationFailureSource::CustomGuard => "custom-guard",
        }
    }

    pub fn component(&self) -> &str {
        &self.component
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl AnalysisRefusal {
    pub(crate) fn new(
        component: &'static str,
        code: &'static str,
        recovery: RecoveryAdvice,
    ) -> Self {
        Self {
            component,
            code,
            recovery,
        }
    }

    pub const fn source(&self) -> &'static str {
        "analysis"
    }

    pub const fn component(&self) -> &'static str {
        self.component
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl RecoveryAdvice {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::RetryOnce => {
                "nah could not complete required safety evaluation; retry once; if it is blocked again, ask the operator; do not bypass nah through another tool"
            }
            Self::CorrectOrSimplify => {
                "nah reached a safety analysis boundary; correct incomplete syntax or split the intended operation into smaller independently reviewable calls; do not encode, obfuscate, move it into an existing script, drop safety-relevant arguments, or change nah state"
            }
            Self::OperatorRequired => {
                "nah could not complete required safety evaluation; ask the operator to inspect nah; do not retry through another tool or change nah state"
            }
        }
    }
}

impl DecisionResult {
    pub fn evidence_provenance(&self) -> Option<&EvidenceProvenance> {
        self.evidence_provenance.as_ref()
    }
    /// Typed guard evidence the decision was reduced from. Consumers project
    /// display facts from it.
    pub fn guard_evidence(
        &self,
    ) -> Option<Result<&nah_proto::effects::GuardEvidence, &nah_proto::effects::EvidenceError>>
    {
        self.guard_evidence.as_ref().map(Result::as_ref)
    }
    pub fn core(&self) -> &DecisionCore {
        &self.core
    }

    pub fn observation(&self) -> Option<&Observation> {
        self.observation.as_ref()
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn consultations(&self) -> &[ExtensionConsultation] {
        &self.consultations
    }

    pub fn failures(&self) -> &[EvaluationFailure] {
        &self.failures
    }

    pub fn refusals(&self) -> &[AnalysisRefusal] {
        &self.refusals
    }

    pub(crate) fn effinterp(&self) -> Option<&EffinterpAnalysis> {
        self.effinterp.as_ref()
    }

    pub(crate) fn replace_core(&mut self, core: DecisionCore) {
        self.core = core;
    }

    pub(crate) fn recovery_advice(&self) -> RecoveryAdvice {
        self.failures
            .iter()
            .map(failure_recovery)
            .chain(self.refusals.iter().map(|refusal| refusal.recovery))
            .max()
            .unwrap_or(RecoveryAdvice::OperatorRequired)
    }

    pub(crate) fn diagnostics(&self) -> &[nah_extensions::ConsultationDiagnostic] {
        &self.diagnostics
    }

    pub(crate) fn prepend_warnings(&mut self, warnings: &[String]) {
        self.warnings.splice(0..0, warnings.iter().cloned());
    }

    pub(crate) fn push_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub(crate) fn push_failure(&mut self, failure: EvaluationFailure) {
        self.failures.push(failure);
    }
}

impl EffinterpAnalysis {
    pub(crate) fn plan(&self) -> &nah_proto::effinterp_proto::Plan {
        &self.plan
    }

    pub(crate) fn annotations(&self) -> &[nah_proto::effect_annotation::EffectAnnotation] {
        &self.annotations
    }

    /// Decision pipeline elapsed wall time in microseconds, despite the name:
    /// measured from the start of `decide_with_evidence_budget` until this
    /// analysis is built, so it covers observation, projection, guard
    /// evaluation, custom-guard consultation (child processes and memo cache)
    /// and verdict reduction. Live-state preparation before the pipeline and
    /// dispatch or audit work after it are excluded.
    pub(crate) const fn engine_time_us(&self) -> u64 {
        self.engine_time_us
    }

    pub(crate) const fn gap(&self) -> bool {
        self.gap
    }
}

fn failure_recovery(failure: &EvaluationFailure) -> RecoveryAdvice {
    if failure.source() == "custom-guard"
        && matches!(failure.code(), "timeout" | "crash" | "spawn-failure")
        || failure.source() == "nah" && failure.component() == "observation"
    {
        RecoveryAdvice::RetryOnce
    } else {
        RecoveryAdvice::OperatorRequired
    }
}

/// Run the application pipeline with a supplied observation source and no
/// live state: normal enforcement, an empty self-protection projection, and no
/// custom-guard consultation. Live hooks enter through
/// `decide_live_with_self_protection`, which adds the nap posture, runtime
/// self-protection and custom guards; frozen corpus replay enters through
/// `decide_replay` and `decide_replay_code`.
pub fn decide_with<F>(input: &ToolCallInput, ctx: &Ctx, observe: F) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_with_extensions_mode(
        input,
        None,
        ctx,
        &SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
        |_, _, _| ConsultedExtensions::default(),
    )
}

#[cfg(test)]
fn decide_with_code<F>(
    input: &ToolCallInput,
    code: &CodeInput,
    ctx: &Ctx,
    observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_with_extensions_mode(
        input,
        Some(code),
        ctx,
        &SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
        |_, _, _| ConsultedExtensions::default(),
    )
}

pub(crate) fn decide_live_with_self_protection(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    state: &LiveState,
    self_protection: &SelfProtectionProjection,
) -> DecisionResult {
    // A guard nap already removed its guards from the live state, so the
    // rest of enforcement runs normally.
    let mode = match state.nap.as_ref().map(|nap| nap.mode()) {
        None | Some(NapMode::Guards(_)) => nah_policy::EnforcementMode::Normal,
        Some(NapMode::SelfProtection) => nah_policy::EnforcementMode::SelfProtectionPaused,
        Some(NapMode::All) => nah_policy::EnforcementMode::AllPaused,
    };
    let self_protection = self_protection.clone().with_installed_executables(
        crate::live_state::nah_executable_paths(state.ctx.platform()),
    );
    let mut result = decide_with_extensions_mode(
        input,
        code,
        &state.ctx,
        &self_protection,
        mode,
        |request| {
            nah_observe::fulfill_observation_request(request).map_err(|error| error.to_string())
        },
        |observation, evidence, memo_context| {
            let output = nah_extensions::consult_extensions(
                &state.extensions,
                &state.ctx,
                observation,
                evidence,
                &state.cache,
                memo_context,
            );
            ConsultedExtensions {
                consultations: output.consultations,
                responses: output.responses,
                warnings: output.warnings,
                diagnostics: output.diagnostics,
                failures: output
                    .failures
                    .iter()
                    .map(EvaluationFailure::custom)
                    .collect(),
            }
        },
    );
    if state.extension_state_unavailable && mode != nah_policy::EnforcementMode::AllPaused {
        result.push_failure(EvaluationFailure::nah("custom-guard-state", "unavailable"));
    }
    result.prepend_warnings(state.extensions.warnings());
    let mut state_warnings = state.warnings.clone();
    if let Some(active) = &state.nap {
        state_warnings.push(format!(
            "{} nap active globally until unix timestamp {}",
            active.mode().scope(),
            active.expires_at()
        ));
    }
    result.prepend_warnings(&state_warnings);
    result
}

#[cfg(test)]
fn decide_with_extensions<F, U>(
    input: &ToolCallInput,
    ctx: &Ctx,
    observe: F,
    consult: U,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
    U: FnOnce(&Observation, &nah_proto::effects::GuardEvidence) -> ConsultedExtensions,
{
    decide_with_extensions_mode(
        input,
        None,
        ctx,
        &SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
        move |observation, evidence, _| consult(observation, evidence),
    )
}

/// Consumer validation, then one bounded engine analysis under the production
/// budget with host-served sources. Every live entry point composes here.
fn decide_with_extensions_mode<F, U>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    observe: F,
    consult: U,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
    U: FnOnce(
        &Observation,
        &nah_proto::effects::GuardEvidence,
        &nah_extensions::MemoContext,
    ) -> ConsultedExtensions,
{
    decide_bounded(
        input,
        code,
        ctx,
        self_protection,
        mode,
        PRODUCTION_EVIDENCE_BUDGET,
        None,
        None,
        observe,
        consult,
    )
}

fn push_refusal(refusals: &mut Vec<AnalysisRefusal>, refusal: AnalysisRefusal) {
    if !refusals.contains(&refusal) {
        refusals.push(refusal);
    }
}

fn delegated_with_refusals(warning: String, refusals: Vec<AnalysisRefusal>) -> DecisionResult {
    let core = DecisionCore::new_with_coverage(Coverage::Partial, Verdict::Delegate, vec![])
        .expect("an unanalyzed call delegates without attributions");
    DecisionResult {
        guard_evidence: None,
        evidence_provenance: None,
        core,
        observation: None,
        warnings: vec![warning],
        consultations: vec![],
        diagnostics: vec![],
        failures: vec![],
        refusals,
        effinterp: None,
    }
}

pub(crate) fn failed_delegate(
    component: &'static str,
    code: &'static str,
    warning: &'static str,
) -> DecisionResult {
    let mut result = delegated_with_refusals(warning.to_owned(), vec![]);
    result
        .failures
        .push(EvaluationFailure::nah(component, code));
    result
}

/// The decision path. Adapter normalization and the call site are consumer
/// contracts checked before analysis; everything about the command itself is
/// the engine's to analyze, so no other parser runs first.
#[allow(clippy::too_many_arguments)]
fn decide_bounded<F, U>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    analysis_budget: Duration,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    observations: Option<std::sync::Arc<dyn nah_effinterp::ObservationResolver>>,
    observe: F,
    consult: U,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
    U: FnOnce(
        &Observation,
        &nah_proto::effects::GuardEvidence,
        &nah_extensions::MemoContext,
    ) -> ConsultedExtensions,
{
    let mut budget = nah_effinterp::EvidenceBudget::after(analysis_budget);
    if let Some(observations) = observations {
        budget = budget.with_observations(observations);
    }
    decide_with_evidence_budget(
        input,
        code,
        ctx,
        self_protection,
        mode,
        budget,
        sources,
        observe,
        consult,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_with_evidence_budget<F, U>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    budget: nah_effinterp::EvidenceBudget,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    mut observe: F,
    consult: U,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
    U: FnOnce(
        &Observation,
        &nah_proto::effects::GuardEvidence,
        &nah_extensions::MemoContext,
    ) -> ConsultedExtensions,
{
    use nah_effinterp::{SelectedInput, SourceLanguage};
    let started = Instant::now();
    let mut refusals = Vec::new();
    if !input.normalization_complete() {
        push_refusal(
            &mut refusals,
            AnalysisRefusal::new(
                "adapter-normalization",
                "incomplete",
                RecoveryAdvice::OperatorRequired,
            ),
        );
    }
    if input.call_site(ctx.platform()).is_err() {
        push_refusal(
            &mut refusals,
            AnalysisRefusal::new("call-site", "invalid", RecoveryAdvice::OperatorRequired),
        );
        return delegated_with_refusals("tool call could not be analyzed".into(), refusals);
    }
    if input.tool() == "Bash"
        && !input
            .input()
            .as_object()
            .and_then(|object| object.get("command"))
            .is_some_and(serde_json::Value::is_string)
    {
        push_refusal(
            &mut refusals,
            AnalysisRefusal::new(
                "bash-input",
                "invalid-command",
                RecoveryAdvice::CorrectOrSimplify,
            ),
        );
        return delegated_with_refusals("Bash input could not be analyzed".into(), refusals);
    }
    let selected = match code {
        Some(code) => {
            let (source, language) = match code {
                CodeInput::Python { source } => (source, SourceLanguage::Python),
                CodeInput::Ipython { source } => (source, SourceLanguage::Ipython),
                CodeInput::PowerShell { source } => (source, SourceLanguage::PowerShell),
                CodeInput::OpenClawJavaScript { source, .. } => {
                    (source, SourceLanguage::JavaScript)
                }
                CodeInput::OpenClawTypeScript { source, .. } => {
                    (source, SourceLanguage::TypeScript)
                }
            };
            SelectedInput::Source {
                input,
                source,
                language,
            }
        }
        None if input.tool() == "Bash" => SelectedInput::Shell(input),
        None => SelectedInput::Native(input),
    };
    let analysis = match analyze_observed(
        selected,
        ctx,
        &budget,
        self_protection,
        sources,
        &mut observe,
    ) {
        Ok(analysis) => analysis,
        // An observation the host could not answer, or an analysis the engine
        // could not complete, is an evaluation failure: a fail-closed hook
        // blocks on it. An input or environment the engine declines is a
        // refusal the caller can correct.
        Err(refusal) => {
            use nah_effinterp::RefusalKind;
            let mut result = match refusal.kind {
                RefusalKind::InvalidObservation => {
                    failed_delegate("observation", "failed", "observation failed")
                }
                RefusalKind::AnalysisFailed | RefusalKind::InvalidGraph => {
                    failed_delegate("effinterp", refusal.code, "effinterp analysis failed")
                }
                RefusalKind::DeadlineExceeded => {
                    push_refusal(
                        &mut refusals,
                        AnalysisRefusal::new(
                            refusal.component,
                            refusal.code,
                            RecoveryAdvice::CorrectOrSimplify,
                        ),
                    );
                    delegated_with_refusals(
                        format!("effinterp analysis unavailable: {}", refusal.code),
                        std::mem::take(&mut refusals),
                    )
                }
                RefusalKind::UnsupportedInput
                | RefusalKind::UnsupportedContext
                | RefusalKind::InvalidInput
                | RefusalKind::EnvironmentLimit
                | RefusalKind::EnvironmentDrift => {
                    push_refusal(
                        &mut refusals,
                        AnalysisRefusal::new(
                            "effinterp",
                            refusal.code,
                            if refusal.kind == RefusalKind::EnvironmentDrift {
                                RecoveryAdvice::RetryOnce
                            } else {
                                RecoveryAdvice::CorrectOrSimplify
                            },
                        ),
                    );
                    delegated_with_refusals(
                        format!("effinterp analysis unavailable: {}", refusal.code),
                        std::mem::take(&mut refusals),
                    )
                }
            };
            result.refusals.splice(0..0, refusals);
            return result;
        }
    };
    if let Some(refusal) = &analysis.evaluation_refusal {
        push_refusal(
            &mut refusals,
            AnalysisRefusal::new(
                refusal.component,
                refusal.code,
                RecoveryAdvice::CorrectOrSimplify,
            ),
        );
    }
    let derivation = match nah_proto::ctx::derive_policy_ctx(ctx, &analysis.observation) {
        Ok(derivation) => derivation,
        Err(_) => return failed_delegate("policy-context", "failed", "policy context failed"),
    };
    let mut consulted = if mode == nah_policy::EnforcementMode::AllPaused {
        ConsultedExtensions::default()
    } else {
        let source_identity =
            evidence_fingerprint(&(&analysis.source_observations, &analysis.path_observations));
        let context = memo_context(&analysis.provenance, source_identity);
        consult(&analysis.observation, &analysis.evidence, &context)
    };
    let coverage = analysis.evidence.coverage();
    let core = match nah_policy::reduce_policy_decision(
        &analysis.evidence,
        crate::catalog::shipped_guards(),
        &analysis.guard_matches,
        coverage,
        derivation.policy_ctx(),
        &consulted.responses,
        mode,
    ) {
        Ok(core) => core,
        Err(_) => {
            consulted
                .failures
                .push(EvaluationFailure::nah("shipped-policy", "failed"));
            DecisionCore::new_with_coverage(coverage, Verdict::Delegate, vec![])
                .expect("failed policy delegates")
        }
    };
    let mut warnings = derivation
        .unknown_declared_guards()
        .iter()
        .map(|name| format!("unknown project guard `{name}`"))
        .collect::<Vec<_>>();
    warnings.extend(consulted.warnings);
    if let Some(refusal) = &analysis.evaluation_refusal {
        warnings.push(format!("effinterp evaluation stopped: {}", refusal.code));
    } else if coverage == Coverage::Partial {
        warnings.push(
            "effinterp analysis is incomplete; only established effects were evaluated".into(),
        );
    }
    let audit = EffinterpAnalysis {
        plan: analysis.plan,
        annotations: analysis.annotations,
        engine_time_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        gap: coverage == Coverage::Partial,
    };
    DecisionResult {
        evidence_provenance: Some(analysis.provenance),
        guard_evidence: Some(Ok(analysis.evidence)),
        core,
        observation: Some(analysis.observation),
        warnings,
        consultations: consulted.consultations,
        diagnostics: consulted.diagnostics,
        failures: consulted.failures,
        refusals,
        effinterp: Some(audit),
    }
}

#[cfg(test)]
pub(crate) fn decide_with_expired_budget(
    input: &ToolCallInput,
    ctx: &Ctx,
    mode: nah_policy::EnforcementMode,
) -> DecisionResult {
    let budget = nah_effinterp::EvidenceBudget::after(Duration::from_secs(30));
    budget.expire();
    decide_with_evidence_budget(
        input,
        None,
        ctx,
        &SelfProtectionProjection::default(),
        mode,
        budget,
        None,
        |_| panic!("an expired budget must not request observations"),
        |_, _, _| ConsultedExtensions::default(),
    )
}

/// Replay the production path from one frozen world: the caller answers the
/// engine's source and path requests as well as host observations, supplies
/// the enforcement posture a live nap would, and the replay budget replaces
/// the interactive deadline.
pub fn decide_replay<F>(
    input: &ToolCallInput,
    ctx: &Ctx,
    mode: nah_policy::EnforcementMode,
    sources: &dyn nah_effinterp::SourceProvider,
    observations: std::sync::Arc<dyn nah_effinterp::ObservationResolver>,
    observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_bounded(
        input,
        None,
        ctx,
        &SelfProtectionProjection::default(),
        mode,
        REPLAY_EVIDENCE_BUDGET,
        Some(sources),
        Some(observations),
        observe,
        |_, _, _| ConsultedExtensions::default(),
    )
}

/// Replay a runtime code tool call from one frozen world, as `decide_replay`
/// does: the source in `language` (`python`, `ipython`, `powershell`,
/// `javascript` or `typescript`) takes the code route its hook takes. Fails
/// only on an unknown language or an input that is not a tool call.
#[allow(clippy::too_many_arguments)]
pub fn decide_replay_code<F>(
    language: &str,
    source: &str,
    cwd: &str,
    ctx: &Ctx,
    mode: nah_policy::EnforcementMode,
    sources: &dyn nah_effinterp::SourceProvider,
    observations: std::sync::Arc<dyn nah_effinterp::ObservationResolver>,
    observe: F,
) -> Result<DecisionResult, String>
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    let (tool, code) = CodeInput::for_replay(language, source.to_owned())
        .ok_or_else(|| format!("unknown code language `{language}`"))?;
    let input = ToolCallInput::new(
        nah_proto::ctx::SchemaVersion::V1,
        tool,
        code.canonical_input(),
        cwd,
        None,
    )
    .map_err(|error| error.to_string())?;
    Ok(decide_bounded(
        &input,
        Some(&code),
        ctx,
        &SelfProtectionProjection::default(),
        mode,
        REPLAY_EVIDENCE_BUDGET,
        Some(sources),
        Some(observations),
        observe,
        |_, _, _| ConsultedExtensions::default(),
    ))
}

#[cfg(all(test, unix))]
mod availability_tests;
#[cfg(test)]
mod environment_tests;
#[cfg(all(test, unix))]
mod performance_tests;
#[cfg(all(test, unix))]
mod source_evidence_tests;

/// Non-enforcing evidence seam for the pipeline tests. It has no custom guard,
/// record append, resolver, daemon, or operator-switch side effects.
#[cfg(test)]
fn analyze_with<F>(
    input: nah_effinterp::SelectedInput<'_>,
    ctx: &Ctx,
    budget: &nah_effinterp::EvidenceBudget,
    mut observe: F,
) -> Result<EvidenceAnalysis, nah_effinterp::AdapterRefusal>
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    analyze_observed(
        input,
        ctx,
        budget,
        &SelfProtectionProjection::default(),
        None,
        &mut observe,
    )
}

fn analyze_observed<F>(
    input: nah_effinterp::SelectedInput<'_>,
    ctx: &Ctx,
    budget: &nah_effinterp::EvidenceBudget,
    self_protection: &SelfProtectionProjection,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    observe: &mut F,
) -> Result<EvidenceAnalysis, nah_effinterp::AdapterRefusal>
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    let observation_failed = |_| nah_effinterp::AdapterRefusal {
        kind: nah_effinterp::RefusalKind::InvalidObservation,
        root_tool: input.input().tool().to_owned(),
        component: "observation",
        code: "observation-failed",
    };
    let deadline = |component| {
        budget
            .deadline_exceeded()
            .then(|| nah_effinterp::AdapterRefusal {
                kind: nah_effinterp::RefusalKind::DeadlineExceeded,
                root_tool: input.input().tool().to_owned(),
                component,
                code: "deadline-exceeded",
            })
    };
    let mut host = nah_effinterp::ObservedHost::default();
    for round in 0..MAX_ENVIRONMENT_ROUNDS {
        let plan = if round == 0 {
            nah_effinterp::plan_evidence(input, ctx, host, &budget.first_round(), sources)?
        } else {
            nah_effinterp::plan_evidence(input, ctx, host, budget, sources)?
        };
        // A walk the deadline stopped still yields the effects it established.
        // Once the observed host binds the plan they are evaluated like any
        // other, and the expiry becomes the evaluation refusal.
        let walk_expired = plan
            .deadline_exceeded()
            .then(|| nah_effinterp::AdapterRefusal {
                kind: nah_effinterp::RefusalKind::DeadlineExceeded,
                root_tool: input.input().tool().to_owned(),
                component: "effinterp-engine",
                code: "deadline-exceeded",
            });
        // Bind the environment from its own queries first. A round whose host
        // still changes only re-plans, so it never pays for the full request's
        // path observations and descendant walks.
        let environment = match plan.environment_request() {
            Some(request) => {
                let observation = observe(&request).map_err(observation_failed)?;
                nah_effinterp::observed_environment(&plan, &observation)?
            }
            None => nah_effinterp::ObservedHost::default(),
        };
        // Once the observed host binds this plan, an expired deadline stops
        // re-planning but never evaluation: structural protection and the
        // shipped guards still read the effects the engine established, and
        // the expiry becomes an evaluation refusal on the evidence.
        let expired = deadline("observation");
        if &environment != plan.host() {
            if let Some(refusal) = expired.or_else(|| deadline("environment-binding")) {
                return Err(refusal);
            }
            host = environment;
            continue;
        }
        let observation = plan
            .observe_with(ctx.platform(), &mut *observe)
            .map_err(observation_failed)?;
        let expired = expired.or_else(|| deadline("observation"));
        // Derive the host again from the full observation, so a value that
        // changed since the environment observation re-plans as before.
        host = nah_effinterp::observed_host(&plan, &observation)?;
        if &host != plan.host() {
            if let Some(refusal) = expired.or_else(|| deadline("environment-binding")) {
                return Err(refusal);
            }
        } else {
            let expired = walk_expired.or(expired).or_else(|| deadline("annotation"));
            let (model, limits) = plan.analysis_identity();
            let provenance = EvidenceProvenance {
                producer: nah_effinterp::producer_identity().to_owned(),
                model: Some(model.to_owned()),
                limits: limits.clone(),
                input_fingerprint: plan.input_fingerprint(),
                observation_fingerprint: observation.fingerprint().to_owned(),
            };
            let source_observations = plan.source_observations().to_vec();
            let path_observations = plan.path_observations().to_vec();
            // Project the plan, evaluate the shipped guards over it, then
            // complete the evidence with the gaps those guards named.
            let projection = nah_effinterp::project_guard_evidence(
                &plan,
                &observation,
                ctx,
                self_protection,
                &nah_effinterp::ShippedGuardPolicy {
                    gap_owners: shipped_gap_owners(),
                },
            )?;
            let guard_matches = crate::catalog::shipped_guards()
                .evaluate_within(
                    projection.plan(),
                    &projection.labels(),
                    &projection.host_facts(),
                    budget.guard_work(),
                )
                .map_err(|_| nah_effinterp::AdapterRefusal {
                    kind: nah_effinterp::RefusalKind::InvalidGraph,
                    root_tool: input.input().tool().to_owned(),
                    component: "effinterp",
                    code: "evidence-graph",
                })?;
            let plan_snapshot = projection.plan().clone();
            let (mut evidence, annotations) = projection.complete(&guard_matches)?;
            // A guard that ran out of matcher work is no evidence of absence:
            // like an expired deadline, it leaves the guards that did match in
            // force and becomes the evaluation refusal.
            let evaluation_refusal = expired
                .or_else(|| deadline("evidence-finalization"))
                .or_else(|| {
                    (!guard_matches.exceeded.is_empty()).then(|| nah_effinterp::AdapterRefusal {
                        kind: nah_effinterp::RefusalKind::AnalysisFailed,
                        root_tool: input.input().tool().to_owned(),
                        component: "shipped-guards",
                        code: "guard-work-limit",
                    })
                });
            if let Some(refusal) = &evaluation_refusal {
                evidence.refuse_evaluation(refusal.component, refusal.code);
            }
            return Ok(EvidenceAnalysis {
                evidence,
                guard_matches,
                observation,
                provenance,
                source_observations,
                path_observations,
                plan: plan_snapshot,
                annotations,
                evaluation_refusal,
            });
        }
    }
    Err(nah_effinterp::AdapterRefusal {
        kind: nah_effinterp::RefusalKind::EnvironmentDrift,
        root_tool: input.input().tool().to_owned(),
        component: "environment-binding",
        code: "environment-rounds",
    })
}

/// The shipped guards' gap owners, the policy data the bridge's projection
/// reads.
fn shipped_gap_owners() -> &'static [nah_effinterp::GapOwner] {
    crate::catalog::shipped_guards().gap_owners()
}

/// Evidence output, never a policy verdict.
#[derive(Debug)]
struct EvidenceAnalysis {
    pub evidence: nah_proto::effects::GuardEvidence,
    /// The shipped guard matches evaluated over `evidence`'s plan; the reducer
    /// reads them beside the evidence.
    pub guard_matches: nah_proto::guard_host::ShippedGuardMatches,
    pub observation: Observation,
    pub provenance: EvidenceProvenance,
    /// Every script and import the engine demanded, with the identity of exactly
    /// the bytes it was given. Raw source is never retained here.
    pub source_observations: Vec<nah_effinterp::SourceObservation>,
    pub path_observations: Vec<nah_proto::effinterp_proto::ProvenanceKind>,
    evaluation_refusal: Option<nah_effinterp::AdapterRefusal>,
    plan: nah_proto::effinterp_proto::Plan,
    annotations: Vec<nah_proto::effect_annotation::EffectAnnotation>,
}
