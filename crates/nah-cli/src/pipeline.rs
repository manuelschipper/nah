//! Exact decision pipeline shared by live calls and frozen corpus execution.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use nah_proto::action::Coverage;
use nah_proto::ctx::{Ctx, GuardSettings};
use nah_proto::decision::{DecisionCore, Verdict};
use nah_proto::observation::{Observation, ObservationRequest};
use nah_proto::runtime_protection::SelfProtectionProjection;
use nah_proto::tool::ToolCallInput;

use crate::code_input::CodeInput;
use crate::live_state::LiveState;
use crate::nap::NapMode;

mod failure_suspicion;

/// Frozen replays, and every decision of an unoptimised build, get this much
/// wall time, so neither the interactive deadline nor host load changes their
/// verdict. A debug decision on a 1 MiB command takes about 10 s of CPU, and on
/// a host loaded several times over its cores its wall time passed 60 s.
const REPLAY_EVIDENCE_BUDGET: Duration = Duration::from_secs(600);
/// Interactive calls get this much process CPU time where available; expiry is a typed
/// refusal, never a verdict. An optimised release build finishes a `/`-walking
/// analysis well inside 100 ms of CPU time. Waiting for scheduling or Git does
/// not spend it, but the whole hook's deadline still caps the wall time.
/// Unoptimised builds take the replay wall budget so end-to-end verdicts do not
/// depend on host speed; deadline tests expire the budget explicitly.
const PRODUCTION_EVIDENCE_BUDGET: Duration = Duration::from_millis(100);
// Caps the wall time analysis may spend waiting off CPU, inside the hook's
// decision budget.
const PRODUCTION_WALL_CEILING: Duration = Duration::from_secs(2);
// Reserve one second of the hosts' five-second hook limit for synchronous
// audit, reply serialization and process exit, including startup in the budget.
const HOOK_DECISION_BUDGET: Duration = Duration::from_secs(4);
const MAX_ENVIRONMENT_ROUNDS: usize = 64;

fn production_evidence_budget(wall_ceiling: Instant) -> nah_effinterp::EvidenceBudget {
    if cfg!(debug_assertions) {
        nah_effinterp::EvidenceBudget::after(REPLAY_EVIDENCE_BUDGET)
    } else {
        nah_effinterp::EvidenceBudget::with_deadline(nah_effinterp::InvocationDeadline::after_cpu(
            PRODUCTION_EVIDENCE_BUDGET,
            wall_ceiling,
            crate::cpu_clock::process_cpu_time,
        ))
    }
}

fn production_evidence_deadline(
    started: Instant,
    hook_deadline: Instant,
    cpu_clock_available: bool,
) -> Instant {
    let wall_budget = if cpu_clock_available {
        PRODUCTION_WALL_CEILING
    } else {
        PRODUCTION_EVIDENCE_BUDGET
    };
    (started + wall_budget).min(hook_deadline)
}

/// Analysis identity stays outside the predicate-visible graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceProvenance {
    pub producer: String,
    pub model: Option<String>,
    pub limits: BTreeMap<String, u64>,
    pub input_fingerprint: String,
}

/// One pipeline decision with everything it was reduced from: guard evidence,
/// observation, evaluation failures, and analysis refusals.
pub struct DecisionResult {
    evidence_provenance: Option<EvidenceProvenance>,
    guard_evidence:
        Option<Result<nah_proto::effects::GuardEvidence, nah_proto::effects::EvidenceError>>,
    core: DecisionCore,
    observation: Option<Observation>,
    settings: Option<GuardSettings>,
    /// The project file a live decision found in the call's project, which
    /// Nah does not read; the adapter's reply says so once.
    ignored_project_file: Option<std::path::PathBuf>,
    warnings: Vec<String>,
    failures: Vec<EvaluationFailure>,
    refusals: Vec<AnalysisRefusal>,
    blocking_refusal: Option<nah_proto::effinterp_proto::AnalysisRefusalKind>,
    effinterp: Option<EffinterpAnalysis>,
    matched_parts: Vec<usize>,
    /// Under save-then-run, the discards a snapshot must hold before this
    /// delegated call may run.
    save_request: Option<crate::save_then_run::Discards>,
    /// The snapshots save-then-run made of what this call would destroy. A
    /// later block keeps them: they were made either way.
    saved: Vec<crate::save_then_run::Saved>,
}

pub(crate) struct EffinterpAnalysis {
    plan: nah_proto::effinterp_proto::Plan,
    /// For each effect of `plan`, whether it is a Git discard or recursive
    /// project delete the observation shows has nothing to lose
    /// (`GuardHostFacts::git_discard_loses_nothing`).
    lossless: Vec<bool>,
    /// For each effect of `plan`, the project files it deletes recursively.
    deletes: Vec<Option<nah_proto::guard_host::ProjectDelete>>,
    annotations: Vec<nah_proto::effect_annotation::EffectAnnotation>,
    /// Whole decision pipeline time, not engine time alone; see the accessor.
    engine_time_us: u64,
    gap: bool,
}

/// A Nah component that could not finish evaluating a call, named by a
/// stable failure code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationFailure {
    component: String,
    code: String,
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

impl EvaluationFailure {
    pub(crate) fn nah(component: &'static str, code: &'static str) -> Self {
        Self {
            component: component.to_owned(),
            code: code.to_owned(),
        }
    }

    pub const fn source(&self) -> &'static str {
        "nah"
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
                "could not finish checking this call. Retry it once, and if it is blocked again, do not bypass nah through another tool"
            }
            Self::CorrectOrSimplify => {
                "reached the limit of what it can check in one call. Correct incomplete syntax or split the intended operation into smaller independently reviewable calls; do not encode, obfuscate, move it into an existing script, drop safety-relevant arguments, or change nah state"
            }
            Self::OperatorRequired => {
                "could not finish checking this call. Do not retry through another tool or change nah state"
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

    /// The shipped rule parts that matched the call, by position among
    /// `ShippedGuards::definitions`, whichever of them the settings ran;
    /// empty when the call was not analysed.
    pub fn matched_parts(&self) -> &[usize] {
        &self.matched_parts
    }

    pub fn observation(&self) -> Option<&Observation> {
        self.observation.as_ref()
    }

    pub(crate) fn settings(&self) -> Option<&GuardSettings> {
        self.settings.as_ref()
    }

    pub(crate) fn ignored_project_file(&self) -> Option<&std::path::Path> {
        self.ignored_project_file.as_deref()
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn failures(&self) -> &[EvaluationFailure] {
        &self.failures
    }

    pub fn refusals(&self) -> &[AnalysisRefusal] {
        &self.refusals
    }

    /// The refusal that changed a delegated decision into a structural block.
    pub fn blocking_refusal(&self) -> Option<nah_proto::effinterp_proto::AnalysisRefusalKind> {
        self.blocking_refusal
    }

    pub(crate) fn evaluation_failed(&self) -> bool {
        !self.failures.is_empty()
            || self
                .refusals
                .iter()
                .any(|refusal| matches!(refusal.code(), "deadline-exceeded" | "guard-work-limit"))
    }

    pub(crate) fn effinterp(&self) -> Option<&EffinterpAnalysis> {
        self.effinterp.as_ref()
    }

    /// The rules a save before this call would answer, if it saves.
    pub(crate) fn save_rules(&self) -> Option<&[&'static str]> {
        self.save_request
            .as_ref()
            .map(|discards| discards.rules.as_slice())
    }

    pub(crate) fn take_save_request(&mut self) -> Option<crate::save_then_run::Discards> {
        self.save_request.take()
    }

    #[cfg(unix)]
    pub(crate) fn record_saved(&mut self, saved: Vec<crate::save_then_run::Saved>) {
        self.saved = saved;
    }

    pub(crate) fn saved(&self) -> &[crate::save_then_run::Saved] {
        &self.saved
    }

    pub(crate) fn replace_core(&mut self, core: DecisionCore) {
        self.core = core;
        self.blocking_refusal = None;
        // Every replacement blocks, and a blocked call runs nothing to save
        // before.
        self.save_request = None;
    }

    pub(crate) fn recovery_advice(&self) -> RecoveryAdvice {
        self.failures
            .iter()
            .map(failure_recovery)
            .chain(self.refusals.iter().map(|refusal| refusal.recovery))
            .max()
            .unwrap_or(RecoveryAdvice::OperatorRequired)
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

    pub(crate) fn lossless(&self) -> &[bool] {
        &self.lossless
    }

    pub(crate) fn deletes(&self) -> &[Option<nah_proto::guard_host::ProjectDelete>] {
        &self.deletes
    }

    pub(crate) fn annotations(&self) -> &[nah_proto::effect_annotation::EffectAnnotation] {
        &self.annotations
    }

    /// Decision pipeline elapsed wall time in microseconds, despite the name:
    /// measured from the start of `decide_with_evidence_budget` until this
    /// analysis is built, so it covers observation, projection, guard
    /// evaluation and verdict reduction. Live-state preparation before the pipeline and
    /// dispatch or audit work after it are excluded.
    pub(crate) const fn engine_time_us(&self) -> u64 {
        self.engine_time_us
    }

    pub(crate) const fn gap(&self) -> bool {
        self.gap
    }
}

fn failure_recovery(failure: &EvaluationFailure) -> RecoveryAdvice {
    if failure.component() == "observation" {
        RecoveryAdvice::RetryOnce
    } else {
        RecoveryAdvice::OperatorRequired
    }
}

/// Run the application pipeline with a supplied observation source and no
/// live state: normal enforcement and an empty self-protection projection.
/// Live hooks enter through `decide_live_with_self_protection`, which adds
/// the nap posture and runtime self-protection; frozen corpus replay enters
/// through `decide_replay` and `decide_replay_code`.
pub fn decide_with<F>(input: &ToolCallInput, ctx: &Ctx, observe: F) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_in_mode(
        input,
        None,
        ctx,
        &SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
    )
}

#[cfg(all(test, unix))]
fn decide_with_code<F>(
    input: &ToolCallInput,
    code: &CodeInput,
    ctx: &Ctx,
    observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_in_mode(
        input,
        Some(code),
        ctx,
        &SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
    )
}

pub(crate) fn decide_live_with_self_protection(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    state: &LiveState,
    self_protection: &SelfProtectionProjection,
    saves: crate::save_then_run::SaveMode,
) -> DecisionResult {
    // A guard nap already paused its rules in the live state, so the rest of
    // enforcement runs normally.
    let mode = match state.nap.as_ref().map(|nap| nap.mode()) {
        None | Some(NapMode::Guards(_)) => nah_policy::EnforcementMode::Normal,
        Some(NapMode::SelfProtection) => nah_policy::EnforcementMode::SelfProtectionPaused,
        Some(NapMode::All) => nah_policy::EnforcementMode::AllPaused,
    };
    let rules_paused = state
        .nap
        .as_ref()
        .is_some_and(|active| matches!(active.mode(), NapMode::Guards(_)));
    let self_protection = self_protection.clone().with_installed_executables(
        crate::live_state::nah_executable_paths(state.ctx.platform()),
    );
    // Unit tests use a fresh replay budget; deadline tests expire it explicitly.
    let deadline = if cfg!(test) {
        Instant::now() + REPLAY_EVIDENCE_BUDGET
    } else {
        *crate::dispatch::HOOK_STARTED + HOOK_DECISION_BUDGET
    };
    let evidence_deadline = if cfg!(debug_assertions) {
        Instant::now() + REPLAY_EVIDENCE_BUDGET
    } else {
        production_evidence_deadline(
            Instant::now(),
            deadline,
            crate::cpu_clock::process_cpu_time().is_some(),
        )
    };
    let mut observation = nah_observe::DecisionObservation::until(evidence_deadline);
    let mut result = decide_with_evidence_budget(
        input,
        code,
        &state.ctx,
        &self_protection,
        mode,
        rules_paused,
        production_evidence_budget(evidence_deadline),
        None,
        saves,
        |request| {
            observation
                .fulfill(request)
                .map_err(|error| error.to_string())
        },
    );
    if let Some(error) = state.shipped_state_error {
        result.push_failure(EvaluationFailure::nah("built-ins.json", error.code()));
    }
    let mut state_warnings = state.warnings.clone();
    if let Some(active) = &state.nap {
        state_warnings.push(format!(
            "{} nap active globally until unix timestamp {}",
            active.mode().scope(),
            active.expires_at()
        ));
    }
    result.prepend_warnings(&state_warnings);
    result.ignored_project_file = result
        .observation
        .as_ref()
        .and_then(|observation| crate::ignored_project_file::find(observation, deadline));
    result
}

/// Consumer validation, then one bounded engine analysis under the production
/// budget with host-served sources. Every live entry point composes here.
fn decide_in_mode<F>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    let started = Instant::now();
    decide_bounded(
        input,
        code,
        ctx,
        self_protection,
        mode,
        production_evidence_budget(production_evidence_deadline(
            started,
            started + HOOK_DECISION_BUDGET,
            crate::cpu_clock::process_cpu_time().is_some(),
        )),
        None,
        None,
        observe,
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
        settings: None,
        ignored_project_file: None,
        warnings: vec![warning],
        failures: vec![],
        refusals,
        blocking_refusal: None,
        effinterp: None,
        matched_parts: vec![],
        save_request: None,
        saved: vec![],
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
fn decide_bounded<F>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    mut budget: nah_effinterp::EvidenceBudget,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    observations: Option<std::sync::Arc<dyn nah_effinterp::ObservationResolver>>,
    observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    if let Some(observations) = observations {
        budget = budget.with_observations(observations);
    }
    decide_with_evidence_budget(
        input,
        code,
        ctx,
        self_protection,
        mode,
        false,
        budget,
        sources,
        crate::save_then_run::SaveMode::Unavailable,
        observe,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_with_evidence_budget<F>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    rules_paused: bool,
    budget: nah_effinterp::EvidenceBudget,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    saves: crate::save_then_run::SaveMode,
    mut observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
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
    let (mut result, written_startup) = decide_selected(
        selected,
        input,
        ctx,
        self_protection,
        mode,
        rules_paused,
        &budget,
        sources,
        saves,
        &mut observe,
        refusals,
        started,
    );
    // Code written into a startup file runs at a later program start that
    // Nah does not see, so it is judged now, as a call of its own from an
    // unknown directory, by the shipped guards.
    // Its block, a limit it reaches and what it could not evaluate carry
    // over as they would for a direct call, and under an all-paused nap its
    // permanent self-protection still blocks.
    // Startup code that writes further startup code is judged in turn, until
    // a level past the execution depth blocks.
    let mut pending = std::collections::VecDeque::from(written_startup);
    while let Some(code) = pending.pop_front() {
        if result.core().verdict() == Verdict::Block {
            break;
        }
        let (startup, nested) = decide_selected(
            SelectedInput::Startup { input, code: &code },
            input,
            ctx,
            self_protection,
            mode,
            rules_paused,
            &budget,
            sources,
            // Startup code runs later, where no snapshot taken now covers it.
            match saves {
                crate::save_then_run::SaveMode::Unavailable => saves,
                _ => crate::save_then_run::SaveMode::Withheld,
            },
            &mut observe,
            Vec::new(),
            Instant::now(),
        );
        fold_startup_decision(&mut result, startup);
        pending.extend(nested);
    }
    result
}

/// Carries the decision on written startup code into the writing call's: a
/// block and its refusal, or else the code's refusals, failures and partial
/// coverage, so a fail-closed hook treats them as it would a direct call's.
fn fold_startup_decision(result: &mut DecisionResult, startup: DecisionResult) {
    for refusal in startup.refusals {
        push_refusal(&mut result.refusals, refusal);
    }
    result.failures.extend(startup.failures);
    if startup.core.verdict() == Verdict::Block {
        result.replace_core(startup.core);
        result.blocking_refusal = startup.blocking_refusal;
        result.push_warning(
            "blocked for the code this call writes into a startup file, which a later shell or Python start runs".into(),
        );
    } else if startup.core.coverage() == Coverage::Partial
        && result.core().coverage() == Coverage::Full
    {
        result.replace_core(
            DecisionCore::new_with_coverage(Coverage::Partial, Verdict::Delegate, vec![])
                .expect("a partial delegate has no attributions"),
        );
        result.push_warning(
            "the code this call writes into a startup file was only partly evaluated".into(),
        );
    }
}

/// One selected input's decision: engine analysis, shipped guards, then
/// failure and limit handling. Also returns
/// the code the input writes into startup files, which this does not judge.
#[allow(clippy::too_many_arguments)]
fn decide_selected<F>(
    selected: nah_effinterp::SelectedInput<'_>,
    input: &ToolCallInput,
    ctx: &Ctx,
    self_protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    rules_paused: bool,
    budget: &nah_effinterp::EvidenceBudget,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    saves: crate::save_then_run::SaveMode,
    observe: &mut F,
    mut refusals: Vec<AnalysisRefusal>,
    started: Instant,
) -> (DecisionResult, Vec<nah_effinterp::StartupCode>)
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    let mut failed_plan = None;
    let analysis = match analyze_observed(
        selected,
        ctx,
        budget,
        self_protection,
        sources,
        observe,
        &mut failed_plan,
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
            result.effinterp = failed_plan.map(|plan| EffinterpAnalysis {
                lossless: vec![false; plan.effects.len()],
                deletes: vec![None; plan.effects.len()],
                annotations: vec![Default::default(); plan.effects.len()],
                plan,
                engine_time_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                gap: true,
            });
            failure_suspicion::block_suspicious_failure(&mut result, input, ctx, mode, None);
            // A call past the input byte limit that nah cannot judge on a
            // target alone was never analyzed: padding must not buy a delegate.
            if refusal.code == "input-byte-limit"
                && mode != nah_policy::EnforcementMode::AllPaused
                && result.core().verdict() == Verdict::Delegate
            {
                result.replace_core(
                    DecisionCore::structural_block_with_coverage(
                        result.core().coverage(),
                        None,
                        result.recovery_advice().message(),
                    )
                    .expect("fixed input-byte-limit reason is valid"),
                );
            }
            return (result, Vec::new());
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
    let settings = ctx.guard_settings();
    let coverage = analysis.evidence.coverage();
    // An adapter that could not fully normalize its call, for example one that
    // had to guess the directory, leaves the engine analysing something it
    // cannot confirm will run, so the decision never claims full coverage.
    let decision_coverage = if input.normalization_complete() {
        coverage
    } else {
        Coverage::Partial
    };
    // Where the runtime saves, the discards of the work rules at core are
    // answered by a snapshot instead, unless another rule blocks the call
    // anyway: it then decides as in 1.x.
    let saving = match saves {
        // A nap of everything lets the call through unsaved, as in 1.x.
        _ if mode == nah_policy::EnforcementMode::AllPaused => {
            crate::save_then_run::Saving::Nothing
        }
        crate::save_then_run::SaveMode::Withheld | crate::save_then_run::SaveMode::Unavailable => {
            crate::save_then_run::Saving::Nothing
        }
        crate::save_then_run::SaveMode::Saves => crate::save_then_run::discards(
            &analysis.plan,
            &analysis.guard_matches,
            &|rule| settings.rule_level(rule),
            &analysis.lossless,
            &analysis.deletes,
        ),
    };
    let (discards, unsaved) = match saving {
        crate::save_then_run::Saving::Saves(discards) => (Some(discards), None),
        crate::save_then_run::Saving::Blocks { rules, why, how } => (None, Some((rules, why, how))),
        crate::save_then_run::Saving::Nothing => (None, None),
    };
    // Where the runtime saves, a discard at core is saved and runs, or
    // blocks: where nothing saves this call, the work rules at core decide
    // whole, as at strict, so none runs unsaved. Where the runtime cannot
    // save, they decide by the parts 1.x shipped on (`unsaveable`).
    let whole_settings;
    let policy_settings = match &discards {
        None if saves != crate::save_then_run::SaveMode::Unavailable
            && mode != nah_policy::EnforcementMode::AllPaused =>
        {
            whole_settings = crate::save_then_run::WHOLE_UNSAVED
                .into_iter()
                .filter(|rule| settings.rule_level(rule) == nah_proto::ctx::GuardLevel::Core)
                .fold(settings.clone(), |settings, rule| {
                    settings.with_rule_whole(rule)
                });
            &whole_settings
        }
        _ => settings,
    };
    // A work rule deciding whole blocks every discard of its kind that a
    // snapshot would answer, whether or not one of its parts matched it;
    // one Nah cannot save at core also tells why after each rule's reason.
    let whole = crate::save_then_run::RULES
        .into_iter()
        .filter(|rule| match settings.rule_level(rule) {
            nah_proto::ctx::GuardLevel::Strict => true,
            nah_proto::ctx::GuardLevel::Core => {
                saves != crate::save_then_run::SaveMode::Unavailable && discards.is_none()
            }
            _ => false,
        })
        .collect::<Vec<_>>();
    let whole_tree = crate::save_then_run::RULES
        .into_iter()
        .filter(|rule| {
            saves == crate::save_then_run::SaveMode::Unavailable
                && settings.rule_level(rule) == nah_proto::ctx::GuardLevel::Core
        })
        .collect::<Vec<_>>();
    let mut guard_matches = crate::save_then_run::with_unmatched(
        &analysis.guard_matches,
        &analysis.plan,
        &analysis.lossless,
        &whole,
        &whole_tree,
        unsaved.as_ref().map_or(&[][..], |(rules, ..)| rules),
    );
    if saves == crate::save_then_run::SaveMode::Unavailable {
        guard_matches =
            crate::save_then_run::unsaveable(&guard_matches, &|rule| settings.rule_level(rule));
    }
    if let Some((rules, why, how)) = &unsaved {
        guard_matches = crate::save_then_run::unsaved(&guard_matches, rules, why, how);
    }
    let reduce = |matches: &nah_proto::guard_host::ShippedGuardMatches| {
        nah_policy::reduce_policy_decision(
            &analysis.evidence,
            crate::catalog::shipped_guards(),
            matches,
            decision_coverage,
            policy_settings,
            mode,
            rules_paused,
        )
    };
    let held = discards
        .as_ref()
        .map(|discards| crate::save_then_run::without(&guard_matches, &discards.rules))
        .filter(|held| reduce(held).is_ok_and(|core| core.verdict() == Verdict::Delegate));
    let mut failures = Vec::new();
    let core = match reduce(held.as_ref().unwrap_or(&guard_matches)) {
        Ok(core) => core,
        Err(_) => {
            failures.push(EvaluationFailure::nah("shipped-policy", "failed"));
            DecisionCore::new_with_coverage(decision_coverage, Verdict::Delegate, vec![])
                .expect("failed policy delegates")
        }
    };
    let mut warnings = Vec::new();
    if let Some(refusal) = &analysis.evaluation_refusal {
        warnings.push(format!("effinterp evaluation stopped: {}", refusal.code));
    } else if coverage == Coverage::Partial {
        warnings.push(
            "effinterp analysis is incomplete; only established effects were evaluated".into(),
        );
    }
    let matched_parts = analysis
        .guard_matches
        .matched
        .iter()
        .map(|matched| matched.part)
        .collect();
    let exceeded = analysis.guard_matches.exceeded;
    let written_startup = analysis.written_startup;
    let audit = EffinterpAnalysis {
        plan: analysis.plan,
        lossless: analysis.lossless,
        deletes: analysis.deletes,
        annotations: analysis.annotations,
        engine_time_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        gap: coverage == Coverage::Partial,
    };
    let save_request = discards.filter(|_| core.verdict() == Verdict::Delegate && held.is_some());
    let mut result = DecisionResult {
        evidence_provenance: Some(analysis.provenance),
        guard_evidence: Some(Ok(analysis.evidence)),
        core,
        observation: Some(analysis.observation),
        settings: Some(policy_settings.clone()),
        ignored_project_file: None,
        warnings,
        failures,
        refusals,
        blocking_refusal: None,
        effinterp: Some(audit),
        matched_parts,
        save_request,
        saved: vec![],
    };
    let unfinished = if result
        .failures()
        .iter()
        .any(|failure| failure.component() == "shipped-policy")
    {
        None
    } else {
        Some(exceeded.as_slice())
    };
    failure_suspicion::block_suspicious_failure(&mut result, input, ctx, mode, unfinished);
    let blocking = result
        .refusals()
        .iter()
        .find_map(|refusal| match refusal.code() {
            "nesting-limit" => Some(nah_proto::effinterp_proto::AnalysisRefusalKind::NestingLimit),
            "executed-input-limit" | "startup-target-observation-limit" => {
                Some(nah_proto::effinterp_proto::AnalysisRefusalKind::ExecutedInputLimit)
            }
            "unpinned-source" => {
                Some(nah_proto::effinterp_proto::AnalysisRefusalKind::UnpinnedSource)
            }
            _ => None,
        });
    if let Some(blocking) = blocking
        && mode != nah_policy::EnforcementMode::AllPaused
        && result.core().verdict() == Verdict::Delegate
    {
        // Startup code may run anything at a later start, and a write an
        // observation limit could not locate may land in a startup file.
        let reason = if result
            .refusals()
            .iter()
            .any(|refusal| refusal.code() == "startup-target-observation-limit")
        {
            "reached its observation limit before establishing whether this call writes startup code, such as a shell profile or a Python startup file. Split the intended operation into smaller independently reviewable calls; do not encode, obfuscate, move it into an existing script, or change nah state"
        } else {
            result.recovery_advice().message()
        };
        result.replace_core(
            DecisionCore::structural_block_with_coverage(result.core().coverage(), None, reason)
                .expect("fixed refusal reason is valid"),
        );
        result.blocking_refusal = Some(blocking);
    }
    (result, written_startup)
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
        false,
        budget,
        None,
        crate::save_then_run::SaveMode::Unavailable,
        |_| panic!("an expired budget must not request observations"),
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
    decide_replay_with_protection(
        input,
        ctx,
        &SelfProtectionProjection::default(),
        mode,
        sources,
        observations,
        observe,
    )
}

/// `decide_replay` with the protected paths a fixture says are installed.
/// An empty projection is the uninstalled case: hook files then stay ordinary
/// paths, which is how `self-protection.critical.cursor-hook-write` delegates.
pub fn decide_replay_with_protection<F>(
    input: &ToolCallInput,
    ctx: &Ctx,
    protection: &SelfProtectionProjection,
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
        protection,
        mode,
        nah_effinterp::EvidenceBudget::after(REPLAY_EVIDENCE_BUDGET),
        Some(sources),
        Some(observations),
        observe,
    )
}

/// `decide_replay_with_protection` for a call of a replayed session, which
/// takes the save-then-run posture of the runtime it came through as the
/// live hook does. A code tool call carries its `code`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_supplied<F>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    protection: &SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    saves: crate::save_then_run::SaveMode,
    sources: &dyn nah_effinterp::SourceProvider,
    observations: std::sync::Arc<dyn nah_effinterp::ObservationResolver>,
    observe: F,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_with_evidence_budget(
        input,
        code,
        ctx,
        protection,
        mode,
        false,
        nah_effinterp::EvidenceBudget::after(REPLAY_EVIDENCE_BUDGET)
            .with_observations(observations),
        Some(sources),
        saves,
        observe,
    )
}

/// Replay a runtime code tool call from one frozen world, as `decide_replay`
/// does: the source in `language` (`python`, `powershell`,
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
        nah_effinterp::EvidenceBudget::after(REPLAY_EVIDENCE_BUDGET),
        Some(sources),
        Some(observations),
        observe,
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

/// Non-enforcing evidence seam for the pipeline tests. It has no
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
        &mut None,
    )
}

fn analyze_observed<F>(
    input: nah_effinterp::SelectedInput<'_>,
    ctx: &Ctx,
    budget: &nah_effinterp::EvidenceBudget,
    self_protection: &SelfProtectionProjection,
    sources: Option<&dyn nah_effinterp::SourceProvider>,
    observe: &mut F,
    failed_plan: &mut Option<nah_proto::effinterp_proto::Plan>,
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
        let mut plan = if round == 0 {
            nah_effinterp::plan_evidence(input, ctx, host, &budget.first_round(), sources)?
        } else {
            nah_effinterp::plan_evidence(input, ctx, host, budget, sources)?
        };
        // Bind the environment from its own queries first. A round whose host
        // still changes only re-plans, so it never pays for the full request's
        // path observations and descendant walks. What it read of the
        // temporary directory adds that directory's path to the full request,
        // and roots that hold the cwd in no Git project add a delete's
        // repository markers.
        let environment_observation = match plan.environment_request() {
            Some(request) => match observe(&request) {
                Ok(observation) => {
                    plan.observe_temporary_directory_path(&observation, ctx.platform());
                    plan.observe_repository_markers(&observation, ctx.platform());
                    Some(observation)
                }
                Err(error) => {
                    *failed_plan = Some(plan.plan().clone());
                    return Err(observation_failed(error));
                }
            },
            None => None,
        };
        let mut retain = |refusal| {
            *failed_plan = Some(plan.plan().clone());
            refusal
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
        // Evaluate established effects, then block an unread nest even under
        // the default failure policy.
        let nesting_limited = plan
            .nesting_limited()
            .then(|| nah_effinterp::AdapterRefusal {
                kind: nah_effinterp::RefusalKind::UnsupportedInput,
                root_tool: input.input().tool().to_owned(),
                component: "effinterp-engine",
                code: "nesting-limit",
            });
        let step_limited = plan.step_limited().then(|| nah_effinterp::AdapterRefusal {
            kind: nah_effinterp::RefusalKind::UnsupportedInput,
            root_tool: input.input().tool().to_owned(),
            component: "effinterp-engine",
            code: "analysis-step-limit",
        });
        // An execution left unread past the depth bound, or a launched script
        // past the size bound, may run anything: evaluate the established
        // effects, then block it like an unread nest.
        let executed_input_limited =
            plan.executed_input_limited()
                .then(|| nah_effinterp::AdapterRefusal {
                    kind: nah_effinterp::RefusalKind::UnsupportedInput,
                    root_tool: input.input().tool().to_owned(),
                    component: "effinterp-engine",
                    code: "executed-input-limit",
                });
        // A write whose landing an observation limit left unknown may write
        // any startup file: evaluate the established effects, then block it.
        let startup_target_unlocated =
            plan.startup_target_unlocated()
                .then(|| nah_effinterp::AdapterRefusal {
                    kind: nah_effinterp::RefusalKind::UnsupportedInput,
                    root_tool: input.input().tool().to_owned(),
                    component: "effinterp",
                    code: "startup-target-observation-limit",
                });
        // Code read from a file a write of the same command reaches at a point
        // the walk cannot order may be either version, or neither: block it
        // like an unread launch.
        let source_unpinned = plan
            .source_unpinned()
            .then(|| nah_effinterp::AdapterRefusal {
                kind: nah_effinterp::RefusalKind::UnsupportedInput,
                root_tool: input.input().tool().to_owned(),
                component: "effinterp-engine",
                code: "unpinned-source",
            });
        // A write judged without its oversize content stays a refused,
        // partial evaluation, which a fail-closed hook still blocks.
        let content_withheld = plan
            .content_withheld()
            .then(|| nah_effinterp::AdapterRefusal {
                kind: nah_effinterp::RefusalKind::UnsupportedInput,
                root_tool: input.input().tool().to_owned(),
                component: "effinterp",
                code: "written-content-withheld",
            });
        let environment = match environment_observation {
            Some(observation) => {
                nah_effinterp::observed_environment(&plan, &observation).map_err(&mut retain)?
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
                return Err(retain(refusal));
            }
            host = environment;
            continue;
        }
        let observation = plan
            .observe_with(ctx.platform(), &mut *observe)
            .map_err(observation_failed)
            .map_err(&mut retain)?;
        let expired = expired.or_else(|| deadline("observation"));
        // Derive the host again from the full observation, so a value that
        // changed since the environment observation re-plans as before.
        host = nah_effinterp::observed_host(&plan, &observation).map_err(&mut retain)?;
        if &host != plan.host() {
            if let Some(refusal) = expired.or_else(|| deadline("environment-binding")) {
                return Err(retain(refusal));
            }
        } else {
            let expired = walk_expired
                .or(nesting_limited)
                .or(executed_input_limited)
                .or(startup_target_unlocated)
                .or(source_unpinned)
                .or(step_limited)
                .or(content_withheld)
                .or(expired)
                .or_else(|| deadline("annotation"));
            let (model, limits) = plan.analysis_identity();
            let provenance = EvidenceProvenance {
                producer: nah_effinterp::producer_identity().to_owned(),
                model: Some(model.to_owned()),
                limits: limits.clone(),
                input_fingerprint: plan.input_fingerprint(),
            };
            #[cfg(test)]
            let source_observations = plan.source_observations().to_vec();
            #[cfg(test)]
            let path_observations = plan.path_observations().to_vec();
            let written_startup = plan.written_startup().to_vec();
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
            )
            .map_err(&mut retain)?;
            let expired = expired.or_else(|| {
                projection
                    .startup_target_unjudged()
                    .then(|| nah_effinterp::AdapterRefusal {
                        kind: nah_effinterp::RefusalKind::UnsupportedInput,
                        root_tool: input.input().tool().to_owned(),
                        component: "effinterp-engine",
                        code: "executed-input-limit",
                    })
            });
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
                })
                .map_err(&mut retain)?;
            let plan_snapshot = projection.plan().clone();
            let (lossless, deletes) = {
                use nah_proto::guard_host::GuardHostFacts;
                let facts = projection.host_facts();
                (0..plan_snapshot.effects.len())
                    .map(|effect| {
                        (
                            facts.git_discard_loses_nothing(effect),
                            facts.project_delete(effect),
                        )
                    })
                    .unzip()
            };
            let (mut evidence, annotations) =
                projection.complete(&guard_matches).map_err(&mut retain)?;
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
                #[cfg(test)]
                source_observations,
                #[cfg(test)]
                path_observations,
                plan: plan_snapshot,
                lossless,
                deletes,
                annotations,
                evaluation_refusal,
                written_startup,
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
    /// the bytes it was given. Raw source is never retained here. Only the
    /// tests read it.
    #[cfg(test)]
    pub source_observations: Vec<nah_effinterp::SourceObservation>,
    #[cfg(test)]
    pub path_observations: Vec<nah_proto::effinterp_proto::ProvenanceKind>,
    evaluation_refusal: Option<nah_effinterp::AdapterRefusal>,
    plan: nah_proto::effinterp_proto::Plan,
    /// For each effect of `plan`, whether it is a Git discard or recursive
    /// project delete the observation shows has nothing to lose
    /// (`GuardHostFacts::git_discard_loses_nothing`).
    lossless: Vec<bool>,
    /// For each effect of `plan`, the project files it deletes recursively.
    deletes: Vec<Option<nah_proto::guard_host::ProjectDelete>>,
    annotations: Vec<nah_proto::effect_annotation::EffectAnnotation>,
    /// The code the call's writes hand a later program start.
    written_startup: Vec<nah_effinterp::StartupCode>,
}
