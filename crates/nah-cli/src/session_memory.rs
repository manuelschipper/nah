//! Session memory, in every runtime, since each adapter delivers a
//! post-call event. `dispatch.rs` skips it, and the ledger records nothing,
//! only for a call the adapter marked unfollowed
//! (`runtime::mark_call_unfollowed`, which `Runtime::follows_this_call`
//! reads; Antigravity's adapter marks a call with no id). A call whose
//! pre-call payload names no tool use id is still decided with memory, but
//! no `set_call` ran, so its proposals count as run at once and nothing
//! settles them. A named call whose post-call event never comes counts as
//! run until a later event settles it (a batch), or until, as the oldest
//! past `ledger::MAX_IN_FLIGHT`, it is applied as run.
//!
//! Session memory adds no guards of its own: it gives the existing guards
//! the history of the session through five rules, each reported and
//! switched with the guard that owns the loss.
//!
//! Each rule's id, in `rules.rs`, is what its block's reason and the `nah
//! session` ledger name it by.
//!
//! 1. `flagged-content-run`: content judged unsafe when written is blocked
//!    when it later reaches an interpreter by any route (the guards that
//!    flagged it).
//! 2. `pending-launch`: a launch waiting to run a path blocks flagged
//!    content written there and content no one has read, such as a
//!    download (any unstated content, for a crontab or launch agent entry),
//!    and flagged content placed where something runs it later outside the
//!    session (the flagging guard; `persistence/startup-item-add` for
//!    crontab and launch agent entries). A background launch waits only
//!    while a running process names its file.
//! 3. `secret-label`: a file secret bytes flowed into carries a session
//!    label, propagated to files derived from it: uploading it or staging
//!    it is blocked under `exfiltration/secret-upload`, reading it back
//!    under `secrets/env-files-read`, and snapshots leave it out.
//! 4. `fetched-code-run`: at strict, code fetched this session (a
//!    download, a clone, an extracted fetched archive, or a copy of one) is
//!    blocked when run (`untrusted-code/remote-script-run`).
//! 5. The rolling copy keeps the last copy of deleted unsaved files; that
//!    rule lives in the snapshot engine (`nah-snapshot`). Save-then-run's
//!    `refresh` updates it on Unix, from the post-call handler: after a
//!    `PostToolUse` in `hook_adapter::post_call` (not when `settle_hook`),
//!    after a failure too in `hook_adapter::lowered_post_call_event`, and
//!    only where `refresh` itself admits the call (its settings, tool and
//!    folder).
//!
//! Unsupported: session memory across `--fork-session`. A forked Claude Code
//! session (`--fork-session`, `/branch`, `/fork`) has a session id of its
//! own, so `ledger::session_key` gives it a new, empty ledger: the parent's
//! pending launches, flagged content, fetched code and secret labels stop
//! counting there. Only the shared label index outlives the session, so
//! snapshots still leave out what the parent labelled. Claude Code's hook
//! input does not name the parent: SessionStart marks a fork with `source:
//! "fork"`, but none of its documented fields gives the parent's session id
//! or transcript path, and every tool event names the fork's own (hooks
//! reference, as of 2.1.329). The fork's transcript copies the parent's
//! conversation, but its line format is undocumented, so a tool use id read
//! from it would be a guess. A tool use id can also sit in several ledgers
//! of a fork chain, so it names no one parent.
//!
//! A ledger that cannot be read blocks a delegated call that needs it
//! (`CallFacts::needs_ledger`), and one that cannot be written blocks a
//! delegated call that proposed changes. Both are structural blocks under
//! the rule id `ledger-unavailable`, which only the code names: their reason
//! does not carry it, and the ledger that failed cannot record the block.
//!
//! The pre-call hook decides and proposes what the call leaves behind; the
//! post-call hook keeps what the disk confirms, so a call the user denies, or
//! that fails, stops counting as run, and a download is hashed in its own
//! call. Until it reports, a call's proposals count, since it may be running.
//!
//! Production enters here four ways: each adapter's pre-call handler names
//! the call when its payload carries an id (`set_call`); `dispatch.rs` applies the rules to the decision
//! (`apply`) and records a block reached after them (`record_final_block`);
//! and the post-call handler (`hook_adapter::post_call`, or an adapter's
//! own) settles how the call ended (`post_call::settle`). `nah session`
//! prints a ledger (`print_session`), and snapshots leave out
//! `labelled_paths`.

mod facts;
mod flow;
mod judge;
mod ledger;
pub(crate) mod post_call;
mod rules;
pub(crate) mod seen;
pub(crate) mod world;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use nah_proto::ctx::{AbsolutePath, Ctx, Platform};
use nah_proto::decision::{DecisionCore, GuardAttribution, GuardContribution, Verdict};
use nah_proto::effinterp_proto::content_digest;
use nah_proto::tool::ToolCallInput;

use crate::live_state::LiveState;
use crate::pipeline::DecisionResult;
use crate::runtime::Runtime;
pub(crate) use facts::CallFacts;
use judge::Judged;
use ledger::{Change, ContentVerdict, Intent, Outcome, Row};
pub(crate) use ledger::{Record, SessionState};
pub(crate) use rules::Basis;
use world::World;

/// The tool use id of the call this hook process decides, and the subagent
/// that made it (`None` for the main agent).
static CALL: OnceLock<(String, Option<String>)> = OnceLock::new();

/// Records the runtime's ids for the call this process decides, which the
/// post-call hooks name when they report how the call ended.
pub(crate) fn set_call(id: &str, agent: Option<&str>) {
    let _ = CALL.set((id.to_owned(), agent.map(str::to_owned)));
}

/// What session memory decides one call against: the decision context,
/// where the session ledgers are kept, the world it reads, and how a run of
/// written content is decided in that world.
pub(crate) struct Host<'a> {
    pub(crate) ctx: &'a Ctx,
    /// The home whose `.nah/sessions` holds the ledgers: the user's live, a
    /// scratch folder in a replay.
    pub(crate) ledgers: &'a AbsolutePath,
    pub(crate) ledgers_platform: Platform,
    pub(crate) world: &'a dyn World,
    /// Decides one shell call as Claude Code's hook would where nothing
    /// saves before it.
    pub(crate) decide_shell: &'a dyn Fn(&ToolCallInput) -> DecisionResult,
    /// The runtime's ids for the call: its tool use id and the subagent that
    /// made it.
    pub(crate) call: Option<(&'a str, Option<&'a str>)>,
}

impl<'a> Host<'a> {
    /// The live host for a call this hook process decides.
    pub(crate) fn live(
        state: &'a LiveState,
        decide_shell: &'a dyn Fn(&ToolCallInput) -> DecisionResult,
    ) -> Self {
        Host {
            ctx: &state.ctx,
            ledgers: state.ctx.home(),
            ledgers_platform: state.ctx.platform(),
            world: &world::Live,
            decide_shell,
            call: CALL
                .get()
                .map(|(call, agent)| (call.as_str(), agent.as_deref())),
        }
    }
}

/// Decides a run of written content live, as `Host::decide_shell`.
pub(crate) fn decide_shell_live(input: &ToolCallInput, state: &LiveState) -> DecisionResult {
    // Nothing saves before a later run of judged content, so the work
    // guards judge it as they do where a runtime saves but this call is not
    // saved.
    crate::dispatch::decide_live_for_runtime(
        input,
        None,
        state,
        Some(Runtime::Claude),
        crate::save_then_run::SaveMode::withheld(Some(Runtime::Claude)),
    )
}

/// What session memory did with one call: the labels `apply` returns, and
/// for a replay's facts, what the call's plan says, the ledger entries the
/// rules used, the rule that blocked and the records the ledger took.
pub(crate) struct Applied {
    pub(crate) labels: Result<Vec<PathBuf>, String>,
    pub(crate) facts: Option<CallFacts>,
    /// `None` where the ledger could not be read.
    pub(crate) consulted: Option<rules::Consulted>,
    pub(crate) rule: Option<&'static str>,
    /// What the rule's block rested on beside the ledger, the settings and
    /// the plan's effects; `None` where it cannot say.
    pub(crate) rested_on: Option<Vec<Basis>>,
    pub(crate) recorded: Vec<Record>,
}

impl Applied {
    /// The call's facts for a replay's export: what its plan says
    /// (`call_facts`), and the ledger entries the rules used and the records
    /// the call left (`ledger`).
    pub(crate) fn export(&self) -> (serde_json::Value, serde_json::Value) {
        let facts = serde_json::to_value(&self.facts).expect("call facts serialize");
        let ledger = serde_json::json!({ "held": self.consulted, "recorded": self.recorded });
        (facts, ledger)
    }
}

/// One written state and how it judges.
pub(crate) struct JudgedWrite {
    path: String,
    digest: String,
    judged: Judged,
    verdict: ContentVerdict,
}

/// Applies the session rules to one call's decision from `runtime` and
/// records the call. Returns the files the session labels as secret, which a
/// snapshot taken before the call leaves out, or why its ledger could not be
/// read. While every guard is paused the session records nothing.
pub(crate) fn apply(
    input: &ToolCallInput,
    runtime: Runtime,
    host: &Host<'_>,
    result: &mut DecisionResult,
    all_paused: bool,
) -> Applied {
    let mut applied = Applied {
        labels: Ok(Vec::new()),
        facts: None,
        consulted: None,
        rule: None,
        rested_on: None,
        recorded: Vec::new(),
    };
    if all_paused {
        return applied;
    }
    let Some(policy) = result.settings() else {
        return applied;
    };
    let world = host.world;
    let platform = host.ledgers_platform;
    let key = ledger::session_key(runtime.cli_name(), input.session(), input.cwd());
    let path = ledger::log_path(host.ledgers, platform, &key);
    let facts = CallFacts::of(
        input.tool(),
        input.input(),
        result
            .effinterp()
            .map(|analysis| (analysis.plan(), analysis.annotations())),
        world,
    );
    let delegated = result.core().verdict() == Verdict::Delegate;
    // The files the call writes, the only ones the rules ask a launch
    // waits for.
    let written: Vec<&str> = facts
        .writes
        .iter()
        .map(|write| write.path.as_str())
        .chain(facts.opaque.iter().map(|opaque| opaque.path.as_str()))
        .collect();
    // Judging runs a whole decision per written state, so it happens before
    // the ledger is locked, against the state as it stood; a launch recorded
    // in between is met under the lock with the content left unjudged.
    let consulted = std::cell::RefCell::new(rules::Consulted::default());
    let judged = if delegated && !written.is_empty() {
        let before = ledger::read_state(&path)
            .map(|state| {
                state
                    .without_ended_launches(&written, world)
                    .counting_in_flight(world)
            })
            .unwrap_or_default();
        judge_writes(&facts, &before, input.cwd(), host, &consulted)
    } else {
        Vec::new()
    };
    let mut ledger = ledger::Locked::open(&path);
    let at = crate::dispatch::current_timestamp_rfc3339();
    let mut rows = Vec::new();
    let mut blocked = None;
    let labels;
    let mut changes = Vec::new();
    match &mut ledger {
        Ok(ledger) => {
            if ledger.state.session.is_none() {
                let session = ledger::Session {
                    runtime: runtime.cli_name().into(),
                    session_id: input.session().map(str::to_owned),
                    workspace: input.cwd().to_owned(),
                };
                ledger.state.session = Some(session.clone());
                rows.push(Record::Session(session));
            }
            consulted.borrow_mut().in_flight = ledger
                .state
                .in_flight
                .iter()
                .map(|intent| intent.call.clone())
                .collect();
            let memory = ledger
                .state
                .clone()
                .without_ended_launches(&written, world)
                .counting_in_flight(world);
            let call = rules::Call {
                memory: &memory,
                facts: &facts,
                judged: &judged,
                policy,
                home: host.ctx.home().as_str(),
                world,
                consulted: &consulted,
            };
            let labelling = call.label_flow();
            if delegated {
                blocked = call.check(&labelling);
            }
            labels = Ok(ledger::readable_labelled_paths(host.ledgers, platform)
                .into_iter()
                .chain(memory.labels.keys().cloned())
                .chain(labelling.labelled.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(PathBuf::from)
                .collect());
            if delegated && blocked.is_none() {
                for write in &judged {
                    if write.judged == Judged::Flagged {
                        ledger
                            .state
                            .flagged
                            .insert(write.digest.clone(), write.verdict.clone());
                        rows.push(Record::Flagged {
                            path: write.path.clone(),
                            digest: write.digest.clone(),
                            verdict: write.verdict.clone(),
                        });
                    }
                }
                changes = call.changes(&labelling);
            }
        }
        Err(error) if delegated && facts.needs_ledger() => {
            labels = Err(format!("this session's ledger is {}", error.code()));
            blocked = Some(
                rules::Block::structural(
                    "ledger-unavailable",
                    format!(
                        "nah session memory could not read this session's ledger ({}); this call needed it and was blocked; retry once, then ask the operator",
                        error.code()
                    ),
                )
                .resting_on(Vec::new()),
            );
        }
        Err(error) => labels = Err(format!("this session's ledger is {}", error.code())),
    }
    if let Some(block) = &blocked {
        replace_with_block(result, block);
    }
    if result.core().verdict() == Verdict::Block {
        rows.push(Record::Blocked {
            rule: blocked.as_ref().map(|block| block.rule.to_owned()),
            guards: blocking_guards(result.core()),
            resources: facts.resources.clone(),
        });
    } else if !changes.is_empty() {
        rows.push(Record::Proposed {
            call: host.call.map(|(call, _)| call.to_owned()),
            changes: changes.clone(),
        });
    }
    let consequential = !changes.is_empty();
    applied.rule = blocked.as_ref().map(|block| block.rule);
    applied.rested_on = blocked.as_ref().and_then(|block| block.rested_on.clone());
    let rows: Vec<Row> = rows
        .into_iter()
        .map(|record| Row {
            at: at.clone(),
            record,
        })
        .collect();
    let recorded = match &mut ledger {
        Ok(ledger) => {
            match host.call {
                // The post-call hook confirms what the call left.
                Some((call, agent)) if consequential => ledger.state.in_flight.push(Intent {
                    call: call.to_owned(),
                    agent: agent.map(str::to_owned),
                    background: facts.background,
                    // A patch writes its files one at a time, so one that
                    // fails may leave earlier files written, as a shell
                    // command may: the disk says which.
                    file_tool: facts.tool != "Bash" && facts.tool != "apply_patch",
                    changes,
                }),
                // No hook will report: the call counts as having run.
                _ => {
                    for change in &changes {
                        ledger.state.apply(change, world);
                    }
                }
            }
            // A call that leaves nothing keeps the state file as it is.
            if rows.is_empty() && !consequential {
                Ok(())
            } else {
                ledger.record(&rows, world)
            }
        }
        Err(error) => Err(*error),
    };
    if let Err(error) = recorded {
        result.push_warning(format!("session ledger write failed: {}", error.code()));
        if consequential && result.core().verdict() == Verdict::Delegate {
            replace_with_block(
                result,
                &rules::Block::structural(
                    "ledger-unavailable",
                    format!(
                        "nah session memory could not record this call in the session's ledger ({}); this call was blocked; retry once, then ask the operator",
                        error.code()
                    ),
                ),
            );
        }
    }
    applied.recorded = rows.into_iter().map(|row| row.record).collect();
    applied.consulted = ledger.is_ok().then(|| consulted.into_inner());
    applied.labels = labels;
    applied.facts = Some(facts);
    applied
}

/// Records a block the decision reached after the rules ran, such as a
/// save before a run that could not keep what the call would destroy. The
/// call never runs, so what it proposed is dropped with it.
pub(crate) fn record_final_block(
    ctx: &nah_proto::ctx::Ctx,
    input: &ToolCallInput,
    runtime: Runtime,
    result: &DecisionResult,
    all_paused: bool,
) {
    if result.settings().is_none() || all_paused || result.core().verdict() != Verdict::Block {
        return;
    }
    let key = ledger::session_key(runtime.cli_name(), input.session(), input.cwd());
    let Ok(mut ledger) = ledger::Locked::open(&ledger::log_path(ctx.home(), ctx.platform(), &key))
    else {
        return;
    };
    let facts = CallFacts::of(
        input.tool(),
        input.input(),
        result
            .effinterp()
            .map(|analysis| (analysis.plan(), analysis.annotations())),
        &world::Live,
    );
    let at = crate::dispatch::current_timestamp_rfc3339();
    let mut rows = vec![Row {
        at: at.clone(),
        record: Record::Blocked {
            rule: None,
            guards: blocking_guards(result.core()),
            resources: facts.resources,
        },
    }];
    if let Some((call, _)) = CALL.get()
        && let Some(position) = ledger
            .state
            .in_flight
            .iter()
            .position(|intent| intent.call == *call)
    {
        ledger.state.in_flight.remove(position);
        rows.push(Row {
            at,
            record: Record::Settled {
                call: call.clone(),
                outcome: Outcome::NotRun,
                kept: Vec::new(),
            },
        });
    }
    let _ = ledger.record(&rows, &world::Live);
}

/// The files any session labels as secret, settled or proposed, which a
/// snapshot leaves out: sessions of one project share its snapshots, or why
/// they cannot all be read. They are read whether or not memory is on here,
/// so `nah undo` in a terminal leaves them out too.
#[cfg(unix)]
pub(crate) fn labelled_paths() -> Result<Vec<PathBuf>, String> {
    let platform = crate::live_state::host_platform();
    let home = crate::live_state::home(platform)?;
    let labels = ledger::labelled_paths(&home, platform)
        .map_err(|error| format!("the session ledgers are {}", error.code()))?;
    Ok(labels.into_iter().map(PathBuf::from).collect())
}

/// One judgment per state the call's writes leave a file in, in order, so a
/// launch that runs the file between two writes meets every state. A file a
/// pending launch waits for is judged as the launching program runs it, and
/// a copy onto one, or into a place something runs later, is judged by the
/// bytes of its source.
fn judge_writes(
    facts: &CallFacts,
    before: &SessionState,
    cwd: &str,
    host: &Host<'_>,
    consulted: &std::cell::RefCell<rules::Consulted>,
) -> Vec<JudgedWrite> {
    let world = host.world;
    let home = host.ctx.home().as_str();
    let sourced = profile_sources(home, world);
    let launcher = |path: &str| {
        before
            .pending
            .get(path)
            .inspect(|pending| {
                consulted
                    .borrow_mut()
                    .pending
                    .insert(path.to_owned(), (*pending).clone());
            })
            .map(|pending| pending.via.as_str())
            .or_else(|| {
                facts
                    .launches
                    .iter()
                    .find(|(launched, _, _)| launched == path)
                    .map(|(_, via, _)| via.as_str())
            })
            .or_else(|| sourced.contains(path).then_some("source"))
    };
    let copies = facts.opaque.iter().filter_map(|opaque| {
        if launcher(&opaque.path).is_none() && !runs_later(&opaque.path, home, world) {
            return None;
        }
        let source = opaque.source.as_deref()?;
        let content = world.text(source).ok()?;
        Some((opaque.path.as_str(), content, Some(source)))
    });
    let mut judged: Vec<JudgedWrite> = Vec::new();
    for (path, content, source) in facts
        .writes
        .iter()
        .map(|write| (write.path.as_str(), write.content.clone(), None))
        .chain(copies)
    {
        let digest = content_digest(content.as_bytes());
        if judged
            .iter()
            .rev()
            .find(|known| known.path == path)
            .is_some_and(|known| known.digest == digest)
        {
            continue;
        }
        let mut judgment = judge::judge_written_content(path, &content, launcher(path), cwd, host);
        // A copy keeps what its bytes were judged to be, though its
        // destination's name says nothing, or something else, about how it
        // runs.
        if let Some(source) = source
            && judgment.judged != Judged::Flagged
        {
            let known = match before.flagged.get(&digest) {
                Some(verdict) => {
                    consulted
                        .borrow_mut()
                        .flagged
                        .insert(digest.clone(), verdict.clone());
                    judge::Judgment {
                        judged: Judged::Flagged,
                        verdict: verdict.clone(),
                    }
                }
                None => judge::judge_written_content(source, &content, None, cwd, host),
            };
            if known.judged != Judged::Unjudged {
                judgment = known;
            }
        }
        judged.push(JudgedWrite {
            path: path.to_owned(),
            digest,
            judged: judgment.judged,
            verdict: judgment.verdict,
        });
    }
    judged
}

/// The guards a blocked decision reports, leading one first: the `self`
/// rule its reason leads with, which self-protection names before any
/// shipped rule that matched too, then its shipped rules; `structural` when
/// it names neither.
fn blocking_guards(core: &DecisionCore) -> Vec<String> {
    let reason = core.reason();
    let lead = nah_proto::decision::led_by_self_rule(reason)
        .then(|| reason.split_once(':').map(|(rule, _)| rule.to_owned()))
        .flatten();
    let guards: Vec<String> = lead
        .into_iter()
        .chain(
            core.policy_attributions()
                .iter()
                .map(|attribution| attribution.name().to_owned()),
        )
        .collect();
    if guards.is_empty() {
        return vec!["structural".to_owned()];
    }
    guards
}

fn replace_with_block(result: &mut DecisionResult, block: &rules::Block) {
    let coverage = result.core().coverage();
    let core = match &block.guard {
        Some(guard) => GuardAttribution::shipped(guard)
            .and_then(|guard| GuardContribution::new(guard, &block.reason))
            .and_then(|contribution| {
                DecisionCore::new_with_coverage(coverage, Verdict::Block, vec![contribution])
            }),
        None => DecisionCore::structural_block_with_coverage(coverage, None, &block.reason),
    }
    .expect("a session memory reason is valid decision text");
    result.replace_core(core);
}

/// The last component of `path`, split at either separator. Every session
/// memory module uses this one.
fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Whether `path` is `folder` or lies under it.
fn within(path: &str, folder: &str) -> bool {
    path.strip_prefix(folder)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// `nah session`: prints one session's ledger, by default the one written
/// most recently.
pub(crate) fn print_session(session_id: Option<&str>) -> Result<String, String> {
    use clap::ValueEnum;
    let platform = crate::live_state::host_platform();
    let home = crate::live_state::home(platform)?;
    let path = match session_id {
        // The runtime whose session has this ID, or the first one's.
        Some(id) => {
            let paths = Runtime::value_variants()
                .iter()
                .map(|runtime| {
                    ledger::log_path(
                        &home,
                        platform,
                        &ledger::session_key(runtime.cli_name(), Some(id), ""),
                    )
                })
                .collect::<Vec<_>>();
            paths
                .iter()
                .find(|path| path.exists())
                .unwrap_or(&paths[0])
                .clone()
        }
        None => std::fs::read_dir(ledger::sessions_directory(&home, platform))
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
            .max_by_key(|entry| entry.metadata().and_then(|meta| meta.modified()).ok())
            .map(|entry| entry.path())
            .ok_or("no session ledger is recorded")?,
    };
    let rows = ledger::read_log(&path)
        .map_err(|error| format!("session ledger unavailable: {}", error.code()))?;
    if rows.is_empty() {
        return Err("no session ledger is recorded for that session".into());
    }
    let short = |digest: &str| digest[..digest.len().min(19)].to_owned();
    let change = |change: &Change| match change {
        Change::Wrote { path, digest } => format!("wrote {path} {}", short(digest)),
        Change::Launch {
            path,
            via,
            scheduled,
        } => format!(
            "launch {path} via {via}{}",
            if *scheduled { " (scheduled)" } else { "" }
        ),
        Change::Label { path, .. } => format!("label {path}"),
        Change::Unlabel { path, .. } => format!("unlabel {path}"),
        Change::Fetched {
            path, source, tree, ..
        } => format!(
            "fetched {path} by {source}{}",
            if *tree { " (folder)" } else { "" }
        ),
    };
    let mut out = format!("ledger: {}\n", path.display());
    for row in rows {
        let lines: Vec<String> = match row.record {
            Record::Session(session) => vec![format!(
                "session {} {} in {}",
                session.runtime,
                session.session_id.as_deref().unwrap_or("(no session id)"),
                session.workspace
            )],
            Record::Flagged {
                path,
                digest,
                verdict,
            } => vec![format!(
                "flagged {path} {} ({})",
                short(&digest),
                verdict.guards.join(", ")
            )],
            Record::Proposed { call, changes } => changes
                .iter()
                .map(|proposed| {
                    format!(
                        "proposed {}{}",
                        change(proposed),
                        call.as_deref()
                            .map(|call| format!(" [{call}]"))
                            .unwrap_or_default()
                    )
                })
                .collect(),
            Record::Settled {
                call,
                outcome,
                kept,
            } => std::iter::once(format!(
                "settled [{call}] {}",
                match outcome {
                    Outcome::Succeeded => "succeeded",
                    Outcome::Failed => "failed",
                    Outcome::NotRun => "not run",
                    Outcome::Ended => "ended",
                }
            ))
            .chain(kept.iter().map(|kept| format!("  kept {}", change(kept))))
            .collect(),
            Record::Blocked {
                rule,
                guards,
                resources,
            } => vec![format!(
                "blocked{} by {}{}",
                rule.map(|rule| format!(" ({rule})")).unwrap_or_default(),
                guards.join(", "),
                if resources.is_empty() {
                    String::new()
                } else {
                    format!(" on {}", resources.join(" "))
                }
            )],
        };
        for line in lines {
            out.push_str(&format!("{}  {line}\n", row.at));
        }
    }
    Ok(out)
}

/// The run-later places a flagged write is blocked from: folders on the
/// hook's `PATH`, git hook folders, and files a shell profile sources.
fn runs_later(path: &str, home: &str, world: &dyn World) -> bool {
    if path.contains("/.git/hooks/") {
        return true;
    }
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    if world.env("PATH").is_some_and(|paths| {
        paths
            .split(':')
            .filter(|folder| folder.starts_with('/'))
            .any(|folder| world.canonical(folder) == parent)
    }) {
        return true;
    }
    profile_sources(home, world).contains(path)
}

/// The files the user's shell profiles source by an absolute or `~` path.
fn profile_sources(home: &str, world: &dyn World) -> BTreeSet<String> {
    const PROFILES: [&str; 7] = [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
    ];
    PROFILES
        .iter()
        .filter_map(|profile| world.text(&format!("{home}/{profile}")).ok())
        .flat_map(|text| {
            text.lines()
                .filter_map(|line| {
                    let line = line.trim();
                    let rest = line
                        .strip_prefix("source ")
                        .or_else(|| line.strip_prefix(". "))?;
                    let word = rest.split_whitespace().next()?.trim_matches(['"', '\'']);
                    let word = word
                        .strip_prefix("~/")
                        .or_else(|| word.strip_prefix("$HOME/"))
                        .map(|rest| format!("{home}/{rest}"))
                        .unwrap_or_else(|| word.to_owned());
                    word.starts_with('/').then(|| world.canonical(&word))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}
