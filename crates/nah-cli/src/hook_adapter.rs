//! Shared runtime-hook input normalization over the `nah decide` seam, and
//! the post-call handlers adapters hand a finished call to: [`post_call`]
//! (Claude Code, Codex), [`lowered_post_call`] (Cursor) and
//! [`post_call_detached`] (Antigravity, Hermes, OpenClaw, OpenCode, Pi).

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::{DecisionOutput, ExitCode, GuardAttribution, Verdict};
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::dispatch::{current_timestamp_rfc3339, decision_id, run_decide_for_runtime};
use crate::runtime::{FailurePolicy, Runtime};
use crate::{
    adapter_fields::runtime_field_names_covered, code_input::CodeInput, guard_knowledge,
    live_state, records,
};

pub(crate) const DELEGATED_FAILURE_MESSAGE: &str = "nah · could not finish safety evaluation; this call was delegated to the runtime; inspect `nah log`, then `nah why <ID>` for details";
pub(crate) const BLOCK_FAILURE_MESSAGE: &str =
    "nah · evaluation was incomplete; this call was blocked";

#[derive(Clone, Copy)]
pub(crate) enum IntegrationUnavailable {
    MalformedInput,
    Evaluation,
    InternalEvaluation,
}

impl IntegrationUnavailable {
    const fn component(self) -> &'static str {
        match self {
            Self::MalformedInput => "hook-input",
            Self::Evaluation | Self::InternalEvaluation => "decision",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed",
            Self::Evaluation => "unavailable",
            Self::InternalEvaluation => "internal",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::MalformedInput => {
                "could not validate the runtime hook input; ask the operator to inspect the nah integration; do not retry through another tool or change nah state"
            }
            Self::Evaluation => {
                "could not complete required safety evaluation; retry once; if it is blocked again, ask the operator; do not bypass nah through another tool"
            }
            Self::InternalEvaluation => {
                "could not complete required safety evaluation; ask the operator to inspect the nah integration; do not retry through another tool or change nah state"
            }
        }
    }
}

#[derive(Deserialize)]
struct HookInput {
    #[serde(rename = "hook_event_name")]
    _hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    cwd: String,
    #[serde(default)]
    session_id: Option<String>,
}

pub(crate) enum HookOutcome {
    Decision(HookDecision),
    IrrelevantEvent,
    MalformedInput,
    EvaluationUnavailable(IntegrationUnavailable),
}

pub(crate) struct HookDecision {
    output: DecisionOutput,
    evaluation_failed: bool,
    fail_closed_block: bool,
    agent_note: Option<String>,
    /// The project file of the call's project, which Nah does not read; see
    /// [`once_report`].
    ignored_project_file: Option<std::path::PathBuf>,
    /// Held until the reply is written; see `save_then_run::unfinished::UnfinishedMarker`.
    #[cfg(unix)]
    _marker: Option<crate::save_then_run::unfinished::UnfinishedMarker>,
}

impl HookDecision {
    pub(crate) const fn verdict(&self) -> Verdict {
        self.output.verdict()
    }

    pub(crate) const fn evaluation_failed(&self) -> bool {
        self.evaluation_failed
    }

    pub(crate) const fn guard_block_incomplete(&self) -> bool {
        self.evaluation_failed && !self.fail_closed_block
    }

    /// What save-then-run tells the agent about the snapshot it saved.
    pub(crate) fn agent_note(&self) -> Option<&str> {
        self.agent_note.as_deref()
    }

    pub(crate) fn delegated_failure_message(&self) -> String {
        format!(
            "nah · could not finish safety evaluation; this call was delegated to the runtime; run `nah why {}` for details",
            self.output.id()
        )
    }

    pub(crate) fn plugin_reply(&self) -> Value {
        let blocked = self.verdict() == Verdict::Block;
        let mut output = json!({"block":blocked,"evaluation_failed":self.evaluation_failed});
        if blocked {
            output["reason"] = json!(feedback(self));
        } else if self.evaluation_failed {
            output["reason"] = json!(self.delegated_failure_message());
        }
        output
    }

    /// [`Self::plugin_reply`] for the runtimes whose plugin passes Nah's
    /// notes on to the agent (OpenClaw, OpenCode and Pi): a block's reason
    /// also says what earlier hooks left unfinished, and a delegate carries
    /// the save note and that report as `note`.
    pub(crate) fn noting_plugin_reply(&self) -> Value {
        let mut output = self.plugin_reply();
        let unfinished = once_report(self);
        if self.verdict() == Verdict::Block {
            if unfinished.is_some() {
                output["reason"] = json!(block_reason(self, unfinished.as_deref()));
            }
        } else if let Some(note) = delegate_note(self, unfinished.as_deref()) {
            output["note"] = json!(note);
        }
        output
    }
}

/// Each adapter names itself, so the decision it produces is recorded against
/// the runtime that sent it. Parse, validation and decision-decoding errors are
/// dropped on purpose: their text can echo raw hook input, so a failure reaches
/// the runtime only as its fixed `HookOutcome` classification. `project_dir`
/// is the project directory the runtime reports outside its payload.
pub(crate) fn decide<R: Read, E: Write>(
    stdin: &mut R,
    stderr: &mut E,
    runtime: Runtime,
    project_dir: Option<&str>,
    failure_policy: FailurePolicy,
) -> HookOutcome {
    let input = match read_event::<_, HookInput>(stdin, "hook_event_name", "PreToolUse") {
        Ok(Some(input)) => input,
        Ok(None) => return HookOutcome::IrrelevantEvent,
        Err(_) => return HookOutcome::MalformedInput,
    };
    let request = match normalize_call(
        runtime,
        input.tool_name,
        input.tool_input,
        input.cwd,
        input.session_id,
    ) {
        Ok(request) => {
            request.with_project_dirs(project_dir.map(str::to_owned).into_iter().collect())
        }
        Err(_) => return HookOutcome::MalformedInput,
    };
    let code = powershell_code(runtime, &request);
    decide_input((request, code.as_ref()), stderr, runtime, failure_policy)
}

/// The source of a Claude Code `PowerShell` tool call. It is PowerShell, not
/// a native tool the engine models, so it takes the code route.
pub(crate) fn powershell_code(runtime: Runtime, request: &ToolCallInput) -> Option<CodeInput> {
    if runtime != Runtime::Claude || request.tool() != "PowerShell" {
        return None;
    }
    let source = request.input().get("command")?.as_str()?;
    Some(CodeInput::PowerShell {
        source: source.into(),
    })
}

/// The tool call of a runtime whose hook sends canonical tool names, such as
/// Claude Code and Codex, which `decide` hands to the pipeline unchanged.
pub(crate) fn normalize_call(
    runtime: Runtime,
    tool_name: String,
    mut tool_input: Value,
    cwd: String,
    session_id: Option<String>,
) -> Result<ToolCallInput, String> {
    let normalization_complete =
        runtime_field_names_covered(runtime.cli_name(), &tool_name, &tool_input);
    let original_input = tool_input.clone();
    // Claude Code runs its search as ripgrep without `--no-ignore`, so it
    // opens nothing an ignore file names. The call itself cannot say so.
    if let (Runtime::Claude, "Grep", Some(object)) =
        (runtime, tool_name.as_str(), tool_input.as_object_mut())
    {
        object.insert("ignore_files".into(), Value::Bool(true));
    }
    match ToolCallInput::new(SchemaVersion::V1, tool_name, tool_input, cwd, session_id) {
        Ok(request) if normalization_complete && *request.input() == original_input => Ok(request),
        Ok(request) => Ok(request.with_original_input(original_input, normalization_complete)),
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) fn read_event<R: Read, T: DeserializeOwned>(
    stdin: &mut R,
    field: &str,
    expected: &str,
) -> Result<Option<T>, serde_json::Error> {
    // `None` means only that the runtime named a different lifecycle event.
    let value = serde_json::from_reader::<_, Value>(stdin)?;
    if irrelevant_event(&value, field, expected) {
        return Ok(None);
    }
    serde_json::from_value(value).map(Some)
}

pub(crate) fn irrelevant_event(value: &Value, field: &str, expected: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|actual| actual != expected)
}

pub(crate) fn decide_input<'a, E: Write>(
    request: impl Into<crate::code_input::HookDecisionInput<'a>>,
    stderr: &mut E,
    runtime: Runtime,
    failure_policy: FailurePolicy,
) -> HookOutcome {
    let (request, code) = request.into().into_parts();
    let request = serde_json::to_vec(&request).expect("validated tool input serializes");
    let mut decision_bytes = Vec::new();
    let outcome = run_decide_for_runtime(
        &mut request.as_slice(),
        &mut decision_bytes,
        stderr,
        Some(runtime),
        failure_policy,
        code,
    );
    if outcome.code == ExitCode::UNAVAILABLE.value() {
        // `nah decide` reports no decision body when it cannot decide at all.
        return HookOutcome::EvaluationUnavailable(if outcome.operator_required_unavailable {
            IntegrationUnavailable::InternalEvaluation
        } else {
            IntegrationUnavailable::Evaluation
        });
    }
    match serde_json::from_slice::<DecisionOutput>(&decision_bytes) {
        Ok(decision) if outcome.code == ExitCode::from(decision.verdict()).value() => {
            HookOutcome::Decision(HookDecision {
                output: decision,
                evaluation_failed: outcome.evaluation_failed,
                fail_closed_block: outcome.fail_closed_block,
                agent_note: outcome.agent_note,
                ignored_project_file: outcome.ignored_project_file,
                #[cfg(unix)]
                _marker: outcome.marker,
            })
        }
        // A decision whose verdict disagrees with the exit status, or that does
        // not decode, is as unusable as no decision.
        Ok(_) | Err(_) => HookOutcome::EvaluationUnavailable(IntegrationUnavailable::Evaluation),
    }
}

/// The post-call handler of Claude Code and Codex, whose post-call event is
/// already in Claude Code's shape; the other runtimes reach
/// [`lowered_post_call`] or [`post_call_detached`].
/// After a call that succeeded it refreshes save-then-run's rolling copy,
/// unless `settle_hook` names the synchronous handler beside a background
/// one, then it settles session memory's account of how the call ended. It
/// never answers the runtime.
pub(crate) fn post_call(event: &Value, runtime: Runtime, settle_hook: bool) {
    #[cfg(unix)]
    if !settle_hook && event["hook_event_name"] == "PostToolUse" {
        crate::save_then_run::refresh(event);
    }
    let _ = settle_hook;
    crate::session_memory::post_call::settle(event, runtime);
}

/// The post-call event, in Claude Code's shape, that an adapter hands
/// [`post_call_detached`] or `session_memory::post_call::settle`, for a
/// runtime that reports a finished call in its own words: `request` is the
/// call as its pre-call hook normalized it, and `failed` whether the
/// runtime says it failed.
/// `call` is the id session memory settles the call by; a runtime whose
/// outcome for this call says nothing passes `None`, so its proposals keep
/// counting as run. Only what the refresh and the settle read is kept: a
/// written file's absolute path, not its content.
pub(crate) fn finished_call(request: &ToolCallInput, failed: bool, call: Option<&str>) -> Value {
    let file = ["file_path", "notebook_path"].into_iter().find_map(|key| {
        let path = request.input().get(key)?.as_str()?;
        Some((
            key,
            std::path::Path::new(request.cwd())
                .join(path)
                .to_string_lossy()
                .into_owned(),
        ))
    });
    let mut event = json!({
        "hook_event_name": if failed { "PostToolUseFailure" } else { "PostToolUse" },
        "tool_name": request.tool(),
        "tool_input": file.map_or_else(|| json!({}), |(key, path)| json!({ key: path })),
        "cwd": request.cwd(),
    });
    if let Some(session) = request.session() {
        event["session_id"] = json!(session);
    }
    if let Some(call) = call {
        event["tool_use_id"] = json!(call);
    }
    event
}

/// What a Nah plugin sends `nah hook <runtime> run` (OpenClaw, OpenCode,
/// Pi): the call in the runtime's words, its id, and for a finished call
/// `hook_event_name`, `PostToolUse` or, when the runtime marks the call
/// failed, `PostToolUseFailure`. A plugin sends no id for a finished call
/// whose outcome says nothing about what ran.
#[derive(Deserialize)]
pub(crate) struct PluginEvent<T> {
    #[serde(default)]
    hook_event_name: Option<String>,
    #[serde(default)]
    tool_use_id: Option<String>,
    #[serde(flatten)]
    call: T,
}

impl<T> PluginEvent<T> {
    /// The call to decide, with its id recorded for session memory; or,
    /// for a finished call, `None` once `normalize`, the pre-call hook's
    /// normalization, has given [`post_call_detached`] the call it decided.
    /// This is the plugin runtimes' post-call handler as well as their
    /// pre-call one.
    pub(crate) fn call_to_decide(
        self,
        runtime: Runtime,
        normalize: impl FnOnce(T) -> Option<ToolCallInput>,
    ) -> Option<T> {
        let Some(event) = self.hook_event_name else {
            if let Some(call) = &self.tool_use_id {
                crate::session_memory::set_call(call, None);
            }
            return Some(self.call);
        };
        if let Some(request) = normalize(self.call) {
            let failed = event == "PostToolUseFailure";
            let finished = finished_call(&request, failed, self.tool_use_id.as_deref());
            post_call_detached(&finished, runtime);
        }
        None
    }
}

/// The post-call handler of a runtime that waits for its post-call hook,
/// for an event of [`finished_call`]: [`lowered_post_call_event`] in a
/// process of its own, since the refresh may take much longer than the
/// runtime should wait. Hermes and the OpenClaw, OpenCode and Pi plugins
/// (through [`PluginEvent::call_to_decide`]) call it alone, so their call
/// settles only in that process; Antigravity settles session memory
/// first, so the next call is decided against the settled ledger. A call
/// that is not settled yet when the next one is decided counts as run.
pub(crate) fn post_call_detached(event: &Value, runtime: Runtime) {
    #[cfg(unix)]
    crate::save_then_run::start_detached_post_call(event, runtime);
    #[cfg(not(unix))]
    lowered_post_call_event(event, runtime);
}
/// The post-call handler of Cursor, whose own
/// event is not in Claude Code's shape: it builds that shape and hands it
/// to [`lowered_post_call_event`] in this process, which refreshes after a
/// failure too, unlike [`post_call`]. `request` is the call as
/// the adapter lowers it for the pre-call hook, so the refresh and session
/// memory read the tool, input, folder and session the decision read.
/// `call` is the runtime's id for the call, which the pre-call hook gave
/// `session_memory::set_call`; `succeeded` is false for a failure event.
pub(crate) fn lowered_post_call(
    request: &ToolCallInput,
    runtime: Runtime,
    call: Option<&str>,
    succeeded: bool,
) {
    let event = json!({
        "hook_event_name": if succeeded { "PostToolUse" } else { "PostToolUseFailure" },
        "tool_name": request.tool(),
        "tool_input": request.input(),
        "cwd": request.cwd(),
        "session_id": request.session(),
        "tool_use_id": call,
    });
    lowered_post_call_event(&event, runtime);
}

/// The post-call handler for an event in Claude Code's shape that a
/// runtime's adapter built: refresh, then settle. Unlike [`post_call`], it
/// refreshes the rolling copy after a failure too: a call that errors may
/// have changed files first.
pub(crate) fn lowered_post_call_event(event: &Value, runtime: Runtime) {
    #[cfg(unix)]
    crate::save_then_run::refresh(event);
    crate::session_memory::post_call::settle(event, runtime);
}

/// A blocked call's reason as the agent reads it, followed by `unfinished`,
/// what earlier hooks left unfinished ([`unfinished_report`]).
pub(crate) fn block_reason(decision: &HookDecision, unfinished: Option<&str>) -> String {
    let reason = feedback(decision);
    match unfinished {
        Some(unfinished) => format!("{reason}\n{unfinished}"),
        None => reason,
    }
}

/// What a reply to a delegated call tells the agent: save-then-run's note
/// about the snapshot it saved, then `unfinished`; `None` when neither is.
pub(crate) fn delegate_note(decision: &HookDecision, unfinished: Option<&str>) -> Option<String> {
    let note = [decision.agent_note(), unfinished]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
    (!note.is_empty()).then_some(note)
}

/// The reply to `decision` of a runtime whose pre-call hook speaks Claude
/// Code's `PreToolUse` protocol, as Codex's does: a deny with the block's
/// reason, or for a delegate the notes for the agent in
/// `additionalContext`, which these runtimes add to the model's context;
/// `None` when there is nothing to say. What earlier hooks left unfinished
/// goes to both the agent and the user.
pub(crate) fn pre_tool_use_reply(decision: &HookDecision) -> Option<Value> {
    let unfinished = once_report(decision);
    if decision.verdict() == Verdict::Block {
        let reason = block_reason(decision, unfinished.as_deref());
        let mut reply = pre_tool_use_deny(&reason, decision.guard_block_incomplete());
        if let Some(unfinished) = unfinished {
            reply["systemMessage"] = json!(unfinished);
        }
        return Some(reply);
    }
    let mut reply = json!({});
    if let Some(context) = delegate_note(decision, unfinished.as_deref()) {
        reply["hookSpecificOutput"] = json!({
            "hookEventName": "PreToolUse",
            "additionalContext": context,
        });
    }
    if decision.evaluation_failed() {
        reply["systemMessage"] = json!(decision.delegated_failure_message());
    } else if let Some(unfinished) = unfinished {
        reply["systemMessage"] = json!(unfinished);
    }
    (reply != json!({})).then_some(reply)
}

/// The `PreToolUse` deny of [`pre_tool_use_reply`]'s runtimes.
pub(crate) fn pre_tool_use_deny(reason: &str, incomplete: bool) -> Value {
    let mut output = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    });
    if incomplete {
        output["systemMessage"] = json!(BLOCK_FAILURE_MESSAGE);
    }
    output
}

/// What this reply tells once, where the runtime shows what earlier hooks
/// left unfinished: that report, then, the first time a reply meets the
/// call's project file, that Nah does not read it
/// (`ignored_project_file::claim_notice`). A decision no reply delivers,
/// such as `nah test`'s, claims nothing.
pub(crate) fn once_report(decision: &HookDecision) -> Option<String> {
    let notes = [
        unfinished_report(),
        decision
            .ignored_project_file
            .as_deref()
            .and_then(crate::ignored_project_file::claim_notice),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!notes.is_empty()).then(|| notes.join("\n"))
}

/// The report of save-then-run decisions earlier hooks left unfinished,
/// which it gives once: each reply reads it at most once.
fn unfinished_report() -> Option<String> {
    #[cfg(unix)]
    return crate::save_then_run::unfinished::unfinished_report();
    #[cfg(not(unix))]
    None
}

/// The prefix of every message Nah gives a runtime.
pub(crate) const PREFIX: &str = "nah · ";

/// The message for a blocked call, as the agent, `nah test` and `nah why`
/// show it: `nah · <rule-id>: <risk>. <recovery>. <next step>.` The decision
/// reason holds everything before the next step (see
/// `nah_proto::decision`); `attributions` decide the next step.
///
/// When the nap file holds another Nah version's nap, which pauses nothing
/// here, the message ends by saying so: a block is where the operator looks
/// when a nap seems to have no effect.
pub(crate) fn block_message(reason: &str, attributions: &[GuardAttribution]) -> String {
    let nap = current_nap();
    let mode = nap.as_ref().ok().and_then(Option::as_ref);
    let mut message = format!("{PREFIX}{reason} {}", next_step(reason, attributions, mode));
    if nap == Err(crate::nap::NapError::UnsupportedVersion) {
        message.push(' ');
        message.push_str(crate::nap::OTHER_VERSION_NOTICE);
    }
    message
}

/// The nap running now, as far as it can be read. A unit test that has not
/// moved into a temporary home reads none: it must not touch the developer's
/// nap, and a suggestion with no nap is the one those tests already pin down.
fn current_nap() -> Result<Option<crate::nap::NapMode>, crate::nap::NapError> {
    #[cfg(test)]
    if std::env::var_os("NAH_UNIT_TEST_TEMPORARY_HOME").is_none() {
        return Ok(None);
    }
    let platform = live_state::host_platform();
    let Ok(home) = live_state::home(platform) else {
        return Ok(None);
    };
    crate::nap::load(&home, platform).map(|nap| nap.map(|nap| nap.mode().clone()))
}

pub(crate) fn feedback(decision: &HookDecision) -> String {
    let message = block_message(
        decision.output.reason(),
        decision.output.policy_attributions(),
    );
    if decision.evaluation_failed {
        format!(
            "{message} Run `nah why {}` for details.",
            decision.output.id()
        )
    } else {
        message
    }
}

/// What to do about a block. Nothing releases a single call yet, so it is
/// always to ask the operator. For shipped rules it says how the operator
/// can allow it. A new nap replaces the current one, so during a nap suggest
/// an extension that keeps the existing pause, or tell the operator how to
/// end it. Permanent disables are only offered while awake and only if they
/// can clear every blocking rule.
/// Self-protection and evaluation failures say in their reason how the
/// operator allows them, even when a self rule leads shipped rules that are
/// named after it.
fn next_step(
    reason: &str,
    attributions: &[GuardAttribution],
    nap: Option<&crate::nap::NapMode>,
) -> String {
    use crate::nap::NapMode;
    let ask = if nap.is_some() {
        "Ask the operator, who can end the current nap with `nah wake`."
    } else {
        "Ask the operator."
    };
    if attributions.is_empty()
        || matches!(nap, Some(NapMode::All))
        || nah_proto::decision::led_by_self_rule(reason)
    {
        return ask.into();
    }
    if matches!(nap, Some(NapMode::SelfProtection)) {
        // Only an all nap can keep both self-protection and guards paused.
        return extend_nap("all");
    }
    let mut guards = Vec::new();
    for attribution in attributions {
        if !guards.contains(&attribution.name()) {
            guards.push(attribution.name());
        }
    }
    if let Some(NapMode::Guards(paused)) = nap {
        guards.extend(paused.iter().map(String::as_str));
        guards.sort_unstable();
        guards.dedup();
        return extend_nap(&guards.join(" "));
    }
    let command = format!("`nah nap {}` (10 min, in every session)", guards.join(" "));
    nap_or_disable(&guards, &command)
}

fn extend_nap(guards: &str) -> String {
    format!(
        "Ask the operator, who can run `nah nap {guards}` (10 min, in every session) if it is intended, or end the current nap with `nah wake`."
    )
}

fn nap_or_disable(guards: &[&str], command: &str) -> String {
    let nap_only = guards.iter().any(|guard| {
        guard_knowledge::guard_knowledge()
            .iter()
            .any(|knowledge| knowledge.name == *guard && knowledge.nap_only)
    });
    if nap_only {
        return format!("Ask the operator, who can run {command} if it is intended.");
    }
    let disable = guards
        .iter()
        .map(|guard| format!("`nah rule disable {guard}`"))
        .collect::<Vec<_>>();
    format!(
        "Ask the operator, who can run {command} or {} (off until re-enabled) if it is intended.",
        disable.join(" and ")
    )
}

/// Delegate policy returns `None` without recording. Fail-closed feedback
/// generates a decision ID, resolves home state, and attempts to append an
/// unavailable audit record before returning the message.
pub(crate) fn unavailable_feedback(
    failure_policy: FailurePolicy,
    runtime: Runtime,
    unavailable: IntegrationUnavailable,
) -> Option<String> {
    if failure_policy == FailurePolicy::Delegate {
        return None;
    }
    Some(record_unavailable(runtime, unavailable))
}

/// Records a call Nah could not decide as an `unavailable` audit row and
/// returns the message to show.
pub(crate) fn record_unavailable(runtime: Runtime, unavailable: IntegrationUnavailable) -> String {
    let id = decision_id();
    let envelope = nah_proto::decision::DecisionEnvelope::new(&id, &current_timestamp_rfc3339(), 0)
        .expect("generated decision envelope is valid");
    let platform = live_state::host_platform();
    if let Ok(home) = live_state::home(platform) {
        let _ = records::append_unavailable(
            &home,
            platform,
            envelope,
            runtime,
            unavailable.component(),
            unavailable.code(),
            unavailable.reason(),
        );
    }
    format!(
        "{PREFIX}{}; run `nah why {id}` for details",
        unavailable.reason()
    )
}

/// Writes one hook reply as a single JSON line on stdout; a failed write is ignored because the
/// runtime has no other channel to hear about it.
pub(crate) fn write_hook_reply_line<W: Write>(stdout: &mut W, value: Value) {
    let _ = serde_json::to_writer(&mut *stdout, &value);
    let _ = writeln!(stdout);
}

/// The blocking reply for the runtimes whose plugin reads a
/// `{"block":..,"evaluation_failed":..}` object (OpenClaw, OpenCode and Pi)
/// when Nah could not decide; `None` when the failure policy
/// delegates. See [`unavailable_feedback`] for the reason text and recording.
pub(crate) fn unavailable_plugin_reply(
    failure_policy: FailurePolicy,
    runtime: Runtime,
    unavailable: IntegrationUnavailable,
) -> Option<Value> {
    unavailable_feedback(failure_policy, runtime, unavailable)
        .map(|reason| json!({"block":true,"reason":reason,"evaluation_failed":true}))
}

/// The reply that hands a call back to its runtime, for the same plugin
/// runtimes as [`unavailable_plugin_reply`].
pub(crate) fn delegated_plugin_reply(evaluation_failed: bool) -> Value {
    let mut output = json!({"block": false, "evaluation_failed": evaluation_failed});
    if evaluation_failed {
        output["reason"] = json!(DELEGATED_FAILURE_MESSAGE);
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{IntegrationUnavailable, next_step, normalize_call, powershell_code};
    use crate::code_input::CodeInput;
    use crate::nap::NapMode;
    use crate::runtime::Runtime;
    use nah_proto::decision::GuardAttribution;

    fn shipped(name: &str) -> GuardAttribution {
        GuardAttribution::shipped(name).unwrap()
    }

    #[test]
    fn a_suggested_nap_keeps_the_pause_already_running() {
        let blocking = [shipped("remote-code/force-push")];
        let reason = "remote-code/force-push: this would rewrite the remote branch";
        let guards = NapMode::Guards(vec![
            "work".into(),
            "work/files-delete".into(),
            "secrets".into(),
        ]);
        for (nap, expected) in [
            (
                None,
                vec![
                    "nah nap remote-code/force-push",
                    "nah rule disable remote-code/force-push",
                ],
            ),
            (
                Some(&NapMode::SelfProtection),
                vec!["nah nap all", "nah wake"],
            ),
            (
                Some(&guards),
                vec![
                    "nah nap remote-code/force-push secrets work work/files-delete",
                    "nah wake",
                ],
            ),
            (Some(&NapMode::All), vec!["nah wake"]),
        ] {
            let message = next_step(reason, &blocking, nap);
            let commands = message.split('`').skip(1).step_by(2).collect::<Vec<_>>();
            for command in &commands {
                assert!(
                    crate::args::parse_from(command.split_whitespace()).is_ok(),
                    "{command}"
                );
            }
            assert_eq!(commands, expected, "{message}");
        }
    }

    #[test]
    fn claude_powershell_tool_takes_the_code_route() {
        let call = |runtime, tool: &str| {
            let input = json!({"command":"Remove-Item C:\\tmp\\x"});
            normalize_call(runtime, tool.into(), input, "/repo".into(), None).unwrap()
        };
        let request = call(Runtime::Claude, "PowerShell");
        assert!(request.normalization_complete());
        assert!(matches!(
            powershell_code(Runtime::Claude, &request),
            Some(CodeInput::PowerShell { .. })
        ));
        assert!(powershell_code(Runtime::Claude, &call(Runtime::Claude, "Bash")).is_none());
        assert!(powershell_code(Runtime::Codex, &call(Runtime::Codex, "PowerShell")).is_none());
    }

    #[test]
    fn internal_and_adapter_unavailability_have_distinct_recovery() {
        let retryable = IntegrationUnavailable::Evaluation.reason();
        assert!(retryable.contains("retry once"));
        let internal = IntegrationUnavailable::InternalEvaluation.reason();
        assert!(internal.contains("ask the operator"));
        assert!(!internal.contains("retry once"));
    }
}
