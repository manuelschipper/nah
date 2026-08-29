//! Exact decision pipeline shared by live calls and frozen corpus execution.

use std::collections::{BTreeMap, BTreeSet};

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::ctx::Ctx;
use nah_proto::decision::{DecisionCore, Verdict};
use nah_proto::extension::{ExtensionConsultation, ValidatedExtensionResponse};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFailure, ObservationQuery, ObservationRequest,
    ObservationValue, Observed,
};
use nah_proto::tool::ToolCallInput;

use crate::code_input::CodeInput;
use crate::live_state::LiveState;
use crate::nap::NapMode;

const MAX_ENVIRONMENT_ROUNDS: usize = 64;
const MAX_ENVIRONMENT_NAMES: usize = 256;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
const ENVIRONMENT_LIMIT_REASON: &str = "environment preflight exceeds nah's analysis limits";
const ENVIRONMENT_OSCILLATION_REASON: &str = "environment changed repeatedly during nah analysis";

pub struct DecisionResult {
    core: DecisionCore,
    action_stream: ActionStream,
    observation: Option<Observation>,
    warnings: Vec<String>,
    consultations: Vec<ExtensionConsultation>,
    diagnostics: Vec<nah_extensions::ConsultationDiagnostic>,
    failures: Vec<EvaluationFailure>,
    refusals: Vec<AnalysisRefusal>,
}

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
    fn new(component: &'static str, code: &'static str, recovery: RecoveryAdvice) -> Self {
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
    pub fn core(&self) -> &DecisionCore {
        &self.core
    }

    pub fn action_stream(&self) -> &ActionStream {
        &self.action_stream
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

/// Run the exact application pipeline with a supplied observation source.
/// Live CLI calls and frozen corpus execution both enter through this function.
pub fn decide_with<F>(input: &ToolCallInput, ctx: &Ctx, observe: F) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    decide_with_extensions_mode(
        input,
        None,
        ctx,
        &nah_actions::SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
        |_, _| ConsultedExtensions::default(),
        false,
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
        &nah_actions::SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
        |_, _| ConsultedExtensions::default(),
        false,
    )
}

pub(crate) fn decide_live(input: &ToolCallInput, state: &LiveState) -> DecisionResult {
    decide_live_with_self_protection(
        input,
        None,
        state,
        &nah_actions::SelfProtectionProjection::default(),
    )
}

pub(crate) fn decide_live_with_self_protection(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    state: &LiveState,
    self_protection: &nah_actions::SelfProtectionProjection,
) -> DecisionResult {
    let mode = match state.nap.map(|nap| nap.mode()) {
        None => nah_policy::EnforcementMode::Normal,
        Some(NapMode::SelfProtection) => nah_policy::EnforcementMode::SelfProtectionPaused,
        Some(NapMode::All) => nah_policy::EnforcementMode::AllPaused,
    };
    let mut result = decide_with_extensions_mode(
        input,
        code,
        &state.ctx,
        self_protection,
        mode,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |observation, action_stream| {
            let output = nah_extensions::consult_extensions(
                &state.extensions,
                &state.ctx,
                observation,
                action_stream,
                &state.cache,
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
        false,
    );
    if state.extension_state_unavailable && mode != nah_policy::EnforcementMode::AllPaused {
        result.push_failure(EvaluationFailure::nah("custom-guard-state", "unavailable"));
    }
    result.prepend_warnings(state.extensions.warnings());
    let mut state_warnings = state.warnings.clone();
    if let Some(active) = state.nap {
        let scope = match active.mode() {
            NapMode::SelfProtection => "self-protection",
            NapMode::All => "all enforcement",
        };
        state_warnings.push(format!(
            "{scope} nap active globally until unix timestamp {}",
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
    U: FnOnce(&Observation, &ActionStream) -> ConsultedExtensions,
{
    decide_with_extensions_mode(
        input,
        None,
        ctx,
        &nah_actions::SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        observe,
        consult,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_with_extensions_mode<F, U>(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    ctx: &Ctx,
    self_protection: &nah_actions::SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    mut observe: F,
    consult: U,
    simulate_inline_failure: bool,
) -> DecisionResult
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
    U: FnOnce(&Observation, &ActionStream) -> ConsultedExtensions,
{
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
    let call_site = match input.call_site(ctx.platform()) {
        Ok(call_site) => call_site,
        Err(_) => {
            push_refusal(
                &mut refusals,
                AnalysisRefusal::new("call-site", "invalid", RecoveryAdvice::OperatorRequired),
            );
            return delegated_with_refusals("tool call could not be analyzed".into(), refusals);
        }
    };
    let syntax = if input.tool() == "Bash" {
        let Some(command) = input
            .input()
            .as_object()
            .and_then(|object| object.get("command"))
            .and_then(serde_json::Value::as_str)
        else {
            push_refusal(
                &mut refusals,
                AnalysisRefusal::new(
                    "bash-input",
                    "invalid-command",
                    RecoveryAdvice::CorrectOrSimplify,
                ),
            );
            return delegated_with_refusals("Bash input could not be analyzed".into(), refusals);
        };
        match nah_parse::normalize(command) {
            Ok(syntax) => {
                if !syntax.complete() {
                    push_refusal(
                        &mut refusals,
                        AnalysisRefusal::new(
                            "bash-syntax",
                            "incomplete",
                            RecoveryAdvice::CorrectOrSimplify,
                        ),
                    );
                }
                Some(syntax)
            }
            Err(nah_parse::ParseError::ExceedsLimit(limit)) => {
                push_refusal(
                    &mut refusals,
                    AnalysisRefusal::new(
                        "bash-parser",
                        limit.code(),
                        RecoveryAdvice::CorrectOrSimplify,
                    ),
                );
                return delegated_with_refusals(limit.to_string(), refusals);
            }
            Err(_) => {
                return failed_delegate_with_refusals(
                    "bash-parser",
                    "failed",
                    "Bash parser failed",
                    refusals,
                );
            }
        }
    } else {
        None
    };
    let analysis_input = match (&syntax, code) {
        (Some(syntax), _) => nah_actions::AnalysisInput::Bash(syntax, input),
        (None, Some(CodeInput::Python { source })) if input.tool() == "execute_code" => {
            nah_actions::AnalysisInput::VisibleCode(
                nah_actions::VisibleCode::Python { source },
                input,
            )
        }
        (None, Some(CodeInput::PowerShell { source })) => nah_actions::AnalysisInput::VisibleCode(
            nah_actions::VisibleCode::PowerShell { source },
            input,
        ),
        (None, Some(CodeInput::Pwsh { source })) => nah_actions::AnalysisInput::VisibleCode(
            nah_actions::VisibleCode::Pwsh { source },
            input,
        ),
        (None, Some(CodeInput::Cmd { source })) => {
            nah_actions::AnalysisInput::VisibleCode(nah_actions::VisibleCode::Cmd { source }, input)
        }
        (None, Some(CodeInput::OpenClawJavaScript { source, .. }))
            if input.tool() == "OpenClawCodeModeExec" =>
        {
            nah_actions::AnalysisInput::VisibleCode(
                nah_actions::VisibleCode::OpenClawJavaScript { source },
                input,
            )
        }
        (None, Some(CodeInput::OpenClawTypeScript { source, .. }))
            if input.tool() == "OpenClawCodeModeExec" =>
        {
            nah_actions::AnalysisInput::VisibleCode(
                nah_actions::VisibleCode::OpenClawTypeScript { source },
                input,
            )
        }
        (None, Some(CodeInput::Ipython { source })) if input.tool() == "ipython" => {
            nah_actions::AnalysisInput::VisibleCode(
                nah_actions::VisibleCode::Ipython { source },
                input,
            )
        }
        (None, _) => nah_actions::AnalysisInput::Native(input),
    };
    let plan =
        nah_actions::plan_with_self_protection(analysis_input, ctx, &call_site, self_protection);
    let (plan, observation) = match observe_stable_environment(
        analysis_input,
        ctx,
        &call_site,
        self_protection,
        plan,
        &mut observe,
    ) {
        Ok(stable) => stable,
        Err(EnvironmentFailure::Unavailable) => {
            return failed_delegate_with_refusals(
                "observation",
                "failed",
                "observation failed",
                refusals,
            );
        }
        Err(EnvironmentFailure::Refuse(refusal)) => {
            push_refusal(
                &mut refusals,
                AnalysisRefusal::new("environment", refusal.code(), refusal.recovery()),
            );
            return delegated_with_refusals(refusal.reason().to_owned(), refusals);
        }
    };
    refusals.extend(
        plan.inline_report()
            .refusals()
            .iter()
            .copied()
            .map(inline_refusal),
    );
    let derivation = match nah_proto::ctx::derive_policy_ctx(ctx, &observation) {
        Ok(derivation) => derivation,
        Err(_) => {
            return failed_delegate_with_refusals(
                "policy-context",
                "failed",
                "policy context failed",
                refusals,
            );
        }
    };
    let warnings = derivation
        .unknown_declared_guards()
        .iter()
        .map(|name| format!("unknown project guard `{name}`"))
        .collect::<Vec<_>>();
    let mut inline_report = plan.inline_report().clone();
    let mut inline_failed = plan.inline_failed();
    if simulate_inline_failure {
        inline_report = nah_inline::InlineReport::default();
        inline_failed = true;
    }
    let (action_stream, language_safety_stream) =
        nah_actions::finalize_with_language_safety_stream(plan, observation.clone());
    if action_stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation } if operation == &SemanticCode::ANALYSIS_REFUSED
        )
    }) {
        push_refusal(
            &mut refusals,
            AnalysisRefusal::new(
                "bash-lowering",
                "refused",
                RecoveryAdvice::CorrectOrSimplify,
            ),
        );
    }
    if mode == nah_policy::EnforcementMode::AllPaused {
        let mut failures = Vec::new();
        if inline_failed {
            failures.push(EvaluationFailure::nah("inline-analysis", "failed"));
        }
        return match decide_policy(
            &action_stream,
            &language_safety_stream,
            &inline_report,
            derivation.policy_ctx(),
            &[],
            mode,
        ) {
            Ok(core) => DecisionResult {
                core,
                action_stream,
                observation: Some(observation),
                warnings,
                consultations: vec![],
                diagnostics: vec![],
                failures,
                refusals,
            },
            Err(()) => {
                failures.push(EvaluationFailure::nah("shipped-policy", "failed"));
                failed_with_stream(
                    action_stream,
                    observation,
                    warnings,
                    vec![],
                    vec![],
                    failures,
                    refusals,
                )
            }
        };
    }
    let ConsultedExtensions {
        consultations,
        responses,
        warnings: extension_warnings,
        diagnostics,
        mut failures,
    } = consult(&observation, &action_stream);
    let mut warnings = warnings;
    warnings.extend(extension_warnings);
    if inline_failed {
        failures.push(EvaluationFailure::nah("inline-analysis", "failed"));
    }
    match decide_policy(
        &action_stream,
        &language_safety_stream,
        &inline_report,
        derivation.policy_ctx(),
        &responses,
        mode,
    ) {
        Ok(core) => DecisionResult {
            core,
            action_stream,
            observation: Some(observation),
            warnings,
            consultations,
            diagnostics,
            failures,
            refusals,
        },
        Err(()) => {
            failures.push(EvaluationFailure::nah("shipped-policy", "failed"));
            failed_with_stream(
                action_stream,
                observation,
                warnings,
                consultations,
                diagnostics,
                failures,
                refusals,
            )
        }
    }
}

fn decide_policy(
    action_stream: &ActionStream,
    language_safety_stream: &ActionStream,
    inline_report: &nah_inline::InlineReport,
    policy_ctx: &nah_proto::ctx::PolicyCtx,
    responses: &[ValidatedExtensionResponse],
    mode: nah_policy::EnforcementMode,
) -> Result<DecisionCore, ()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        nah_policy::decide_with_mode_and_inline_language_safety_stream(
            action_stream,
            language_safety_stream,
            inline_report,
            policy_ctx,
            responses,
            mode,
        )
    }))
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn observe_stable_environment<F>(
    input: nah_actions::AnalysisInput<'_>,
    ctx: &Ctx,
    call_site: &nah_proto::tool::CallSite,
    self_protection: &nah_actions::SelfProtectionProjection,
    mut plan: nah_actions::AnalysisPlan,
    observe: &mut F,
) -> Result<(nah_actions::AnalysisPlan, Observation), EnvironmentFailure>
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    let mut budget = EnvironmentBudget::default();
    let mut known = None::<EnvironmentSnapshot>;

    loop {
        let names = environment_names(plan.observation_request());
        budget.register_names(&names)?;

        if !names.is_empty() && known.as_ref().is_none_or(|known| !known.covers(&names)) {
            let request = environment_request(plan.observation_request())
                .expect("a nonempty environment name set has an environment request");
            let observation = observe_checked(&request, observe, &mut budget)?;
            let snapshot = EnvironmentSnapshot::from_observation(&observation)?;
            budget.register_snapshot(&snapshot)?;
            plan = nah_actions::replan_with_environment_and_self_protection(
                input,
                ctx,
                call_site,
                &observation,
                self_protection,
            );
            known = Some(snapshot);
            continue;
        }

        let observation = observe_checked(plan.observation_request(), observe, &mut budget)?;
        let observed = EnvironmentSnapshot::from_observation(&observation)?;
        budget.register_values(&observed)?;
        if names.is_empty()
            || known
                .as_ref()
                .is_some_and(|known| known.agrees_with(&observed, &names))
        {
            return Ok((plan, observation));
        }

        budget.register_state(&observed)?;
        plan = nah_actions::replan_with_environment_and_self_protection(
            input,
            ctx,
            call_site,
            &observation,
            self_protection,
        );
        known = Some(observed);
    }
}

fn environment_request(request: &ObservationRequest) -> Option<ObservationRequest> {
    let queries = request
        .queries()
        .iter()
        .filter(|query| matches!(query, ObservationQuery::Env { .. }))
        .cloned()
        .collect::<Vec<_>>();
    (!queries.is_empty()).then(|| {
        ObservationRequest::new(request.version(), request.request_id(), queries)
            .expect("a plan's environment queries remain a valid environment-only request")
    })
}

fn environment_names(request: &ObservationRequest) -> BTreeSet<String> {
    request
        .queries()
        .iter()
        .filter_map(|query| match query {
            ObservationQuery::Env { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn observe_checked<F>(
    request: &ObservationRequest,
    observe: &mut F,
    budget: &mut EnvironmentBudget,
) -> Result<Observation, EnvironmentFailure>
where
    F: FnMut(&ObservationRequest) -> Result<Observation, String>,
{
    budget.register_round()?;
    let observation = observe(request).map_err(|_| EnvironmentFailure::Unavailable)?;
    observation
        .bind(request)
        .map_err(|_| EnvironmentFailure::Unavailable)?;
    Ok(observation)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EnvironmentDatum {
    Value(String),
    Unset,
    Error(ObservationFailure),
}

impl EnvironmentDatum {
    fn value_bytes(&self) -> usize {
        match self {
            Self::Value(value) => value.len(),
            Self::Unset | Self::Error(_) => 0,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EnvironmentSnapshot {
    values: BTreeMap<String, EnvironmentDatum>,
}

impl EnvironmentSnapshot {
    fn from_observation(observation: &Observation) -> Result<Self, EnvironmentFailure> {
        let mut values = BTreeMap::new();
        for fact in observation.facts() {
            let ObservationQuery::Env { name, .. } = fact.query() else {
                continue;
            };
            let datum = match fact.value() {
                ObservationValue::Env {
                    observed:
                        Observed::Ok {
                            value: EnvObservation::Value { text },
                        },
                } => EnvironmentDatum::Value(text.clone()),
                ObservationValue::Env {
                    observed:
                        Observed::Ok {
                            value: EnvObservation::Unset,
                        },
                } => EnvironmentDatum::Unset,
                ObservationValue::Env {
                    observed: Observed::Error { error },
                } => EnvironmentDatum::Error(*error),
                _ => {
                    return Err(EnvironmentFailure::Unavailable);
                }
            };
            if values
                .insert(name.clone(), datum.clone())
                .is_some_and(|previous| previous != datum)
            {
                return Err(EnvironmentFailure::Unavailable);
            }
        }
        Ok(Self { values })
    }

    fn covers(&self, names: &BTreeSet<String>) -> bool {
        names.iter().all(|name| self.values.contains_key(name))
    }

    fn agrees_with(&self, observed: &Self, names: &BTreeSet<String>) -> bool {
        names
            .iter()
            .all(|name| self.values.get(name) == observed.values.get(name))
    }
}

#[derive(Default)]
struct EnvironmentBudget {
    rounds: usize,
    names: BTreeSet<String>,
    values: BTreeSet<(String, EnvironmentDatum)>,
    value_bytes: usize,
    states: BTreeSet<EnvironmentSnapshot>,
}

impl EnvironmentBudget {
    fn register_round(&mut self) -> Result<(), EnvironmentFailure> {
        if self.rounds == MAX_ENVIRONMENT_ROUNDS {
            return Err(EnvironmentFailure::Refuse(EnvironmentRefusal::RoundLimit));
        }
        self.rounds += 1;
        Ok(())
    }

    fn register_names(&mut self, names: &BTreeSet<String>) -> Result<(), EnvironmentFailure> {
        self.names.extend(names.iter().cloned());
        if self.names.len() > MAX_ENVIRONMENT_NAMES {
            Err(EnvironmentFailure::Refuse(EnvironmentRefusal::NameLimit))
        } else {
            Ok(())
        }
    }

    fn register_values(
        &mut self,
        snapshot: &EnvironmentSnapshot,
    ) -> Result<(), EnvironmentFailure> {
        let additional = snapshot
            .values
            .iter()
            .filter(|(name, value)| !self.values.contains(&(name.to_string(), (*value).clone())))
            .map(|(_, value)| value.value_bytes())
            .sum::<usize>();
        if self.value_bytes.saturating_add(additional) > MAX_ENVIRONMENT_VALUE_BYTES {
            return Err(EnvironmentFailure::Refuse(EnvironmentRefusal::ValueLimit));
        }
        self.value_bytes += additional;
        self.values.extend(
            snapshot
                .values
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        Ok(())
    }

    fn register_state(&mut self, snapshot: &EnvironmentSnapshot) -> Result<(), EnvironmentFailure> {
        if self.states.insert(snapshot.clone()) {
            Ok(())
        } else {
            Err(EnvironmentFailure::Refuse(EnvironmentRefusal::Oscillation))
        }
    }

    fn register_snapshot(
        &mut self,
        snapshot: &EnvironmentSnapshot,
    ) -> Result<(), EnvironmentFailure> {
        self.register_values(snapshot)?;
        self.register_state(snapshot)
    }
}

enum EnvironmentFailure {
    Unavailable,
    Refuse(EnvironmentRefusal),
}

#[derive(Clone, Copy)]
enum EnvironmentRefusal {
    RoundLimit,
    NameLimit,
    ValueLimit,
    Oscillation,
}

impl EnvironmentRefusal {
    const fn code(self) -> &'static str {
        match self {
            Self::RoundLimit => "round-limit",
            Self::NameLimit => "name-limit",
            Self::ValueLimit => "value-limit",
            Self::Oscillation => "oscillation",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::RoundLimit | Self::NameLimit | Self::ValueLimit => ENVIRONMENT_LIMIT_REASON,
            Self::Oscillation => ENVIRONMENT_OSCILLATION_REASON,
        }
    }

    const fn recovery(self) -> RecoveryAdvice {
        match self {
            Self::Oscillation => RecoveryAdvice::RetryOnce,
            Self::RoundLimit | Self::NameLimit | Self::ValueLimit => {
                RecoveryAdvice::CorrectOrSimplify
            }
        }
    }
}

fn inline_refusal(refusal: nah_inline::InlineRefusal) -> AnalysisRefusal {
    AnalysisRefusal::new(
        "inline-analysis",
        refusal.code(),
        RecoveryAdvice::CorrectOrSimplify,
    )
}

fn push_refusal(refusals: &mut Vec<AnalysisRefusal>, refusal: AnalysisRefusal) {
    if !refusals.contains(&refusal) {
        refusals.push(refusal);
    }
}

fn delegated_with_refusals(warning: String, refusals: Vec<AnalysisRefusal>) -> DecisionResult {
    let stream = ActionStream::new(Coverage::Partial, vec![], vec![])
        .expect("empty partial stream is the pre-analysis delegate contract");
    let core = DecisionCore::new(&stream, Verdict::Delegate, vec![])
        .expect("empty partial stream delegates");
    DecisionResult {
        core,
        action_stream: stream,
        observation: None,
        warnings: vec![warning],
        consultations: vec![],
        diagnostics: vec![],
        failures: vec![],
        refusals,
    }
}

pub(crate) fn failed_delegate(
    component: &'static str,
    code: &'static str,
    warning: &'static str,
) -> DecisionResult {
    failed_delegate_with_refusals(component, code, warning, vec![])
}

fn failed_delegate_with_refusals(
    component: &'static str,
    code: &'static str,
    warning: &'static str,
    refusals: Vec<AnalysisRefusal>,
) -> DecisionResult {
    let mut result = delegated_with_refusals(warning.to_owned(), refusals);
    result
        .failures
        .push(EvaluationFailure::nah(component, code));
    result
}

fn failed_with_stream(
    action_stream: ActionStream,
    observation: Observation,
    mut warnings: Vec<String>,
    consultations: Vec<ExtensionConsultation>,
    diagnostics: Vec<nah_extensions::ConsultationDiagnostic>,
    failures: Vec<EvaluationFailure>,
    refusals: Vec<AnalysisRefusal>,
) -> DecisionResult {
    warnings.push("policy evaluation failed".into());
    let core = DecisionCore::new(&action_stream, Verdict::Delegate, vec![])
        .expect("a policy failure delegates without attributions");
    DecisionResult {
        core,
        action_stream,
        observation: Some(observation),
        warnings,
        consultations,
        diagnostics,
        failures,
        refusals,
    }
}

#[cfg(all(test, unix))]
mod availability_tests;
#[cfg(test)]
mod environment_tests;
#[cfg(all(test, unix))]
mod performance_tests;
