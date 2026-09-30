//! Testable command dispatch and machine-facing `nah decide` I/O.

use std::collections::BTreeSet;
use std::io::{IsTerminal, Read, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use nah_proto::decision::{DecisionEnvelope, DecisionOutput, ExitCode};
use nah_proto::tool::ToolCallInput;

use crate::amp_adapter;
use crate::antigravity_adapter;
use crate::args::{Cli, Command, GuardAction, GuardTargetArgs, HookAction, parse_from};
use crate::catalog::{NAP_ALL, shipped_names};
use crate::claude_adapter;
use crate::cline_adapter;
use crate::code_input::CodeInput;
use crate::codex_adapter;
use crate::commands::{
    GuardSelector, RuntimeHookStatus, TestError, custom_guard_entries, list_custom_guards,
    list_shipped_guards, new_guard, reset_guard, runtime_entry, runtime_self_protection,
    set_guard_enabled, set_runtime_configured, test_command, trust_root, untrust_root,
};
use crate::copilot_adapter;
use crate::cursor_adapter;
use crate::devin_adapter;
use crate::docs;
use crate::droid_adapter;
use crate::hermes_adapter;
use crate::kiro_adapter;
use crate::live_state;
use crate::nap::{self, NapMode};
use crate::openclaw_adapter;
use crate::opencode_adapter;
use crate::pi_adapter;
use crate::pipeline::{
    DecisionResult, EvaluationFailure, decide_live_with_self_protection, failed_delegate,
};
use crate::prime_agent_adapter;
use crate::records;
use crate::runtime::{FailurePolicy, Runtime};

/// Testable stdin/stdout seam for the thin binary.
fn run_with<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    if let [command, runtime] = args
        && command == "hook"
        && Runtime::value_variants()
            .iter()
            .any(|candidate| candidate.cli_name() == runtime)
    {
        let _ = writeln!(
            stderr,
            "error: `nah hook {runtime}` requires an action\n\nUsage: nah hook {runtime} <install|uninstall|status>\n\nFor more information, try `nah hook --help`."
        );
        return ExitCode::USAGE.value();
    }
    let cli = match parse_from(std::iter::once("nah".to_owned()).chain(args.iter().cloned())) {
        Ok(cli) => cli,
        Err(error) => return emit_clap_error(error, stdout, stderr),
    };
    match cli.command {
        Command::Tui => {
            let _ = writeln!(stderr, "nah: `nah tui` requires an interactive terminal.");
            ExitCode::USAGE.value()
        }
        Command::Decide(_) => run_decide(stdin, stdout, stderr),
        Command::Nap(_) => {
            let _ = writeln!(
                stderr,
                "nah: `nah nap` must be run by the operator in an interactive terminal."
            );
            ExitCode::USAGE.value()
        }
        Command::Wake => wake(stdout, stderr),
        Command::Test(args) => emit_test(test_command(&args), stdout, stderr),
        Command::Trust(args) => persist_trust(&args.root, stdout, stderr),
        Command::Untrust(args) => revoke_trust(&args.root, stdout, stderr),
        Command::Guards => emit_catalog(false, stdout, stderr),
        Command::Guard { action } => configure_guard(action, stdout, stderr),
        Command::Hook(args) => match args.action {
            HookAction::Install(install) => configure_runtime_hook(
                args.runtime,
                true,
                if install.fail_closed {
                    Some(FailurePolicy::Block)
                } else if install.fail_open {
                    Some(FailurePolicy::Delegate)
                } else {
                    None
                },
                stdout,
                stderr,
            ),
            HookAction::Uninstall => {
                configure_runtime_hook(args.runtime, false, None, stdout, stderr)
            }
            HookAction::Status => inspect_runtime_hook(args.runtime, stdout, stderr),
            HookAction::Run(run) => {
                let policy = if run.fail_closed {
                    FailurePolicy::Block
                } else {
                    FailurePolicy::Delegate
                };
                run_runtime_hook(args.runtime, policy, stdin, stdout, stderr)
            }
        },
        Command::Why(args) => explain(&args.id, stdout, stderr),
        Command::Log(args) => {
            let gap = args.effinterp_gap;
            list_log(args.count, args.json, args.blocked, gap, stdout, stderr)
        }
        Command::Docs(args) => {
            emit_docs(args.topic.as_deref(), args.guard.as_deref(), stdout, stderr)
        }
    }
}

fn emit_clap_error<W: Write, E: Write>(error: clap::Error, stdout: &mut W, stderr: &mut E) -> u8 {
    use clap::error::ErrorKind;

    let informational = matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    );
    let rendered = error.to_string();
    if informational {
        let _ = write!(stdout, "{rendered}");
        0
    } else {
        let _ = write!(stderr, "{rendered}");
        ExitCode::USAGE.value()
    }
}

fn configure_guard<W: Write, E: Write>(action: GuardAction, stdout: &mut W, stderr: &mut E) -> u8 {
    if let GuardAction::New(args) = action {
        let selector = guard_selector(&args);
        return match new_guard(&args.name, &selector) {
            Ok(path) => {
                let next = match selector {
                    GuardSelector::Project(_) => {
                        format!(
                            "after trust, nah guard enable {} --project <root>",
                            args.name
                        )
                    }
                    GuardSelector::Any | GuardSelector::User => {
                        format!("nah guard enable {}", args.name)
                    }
                };
                let _ = writeln!(
                    stdout,
                    "created {path:?}\nproposal only: review the generated bytes\nnext: {next}\ncontract: nah docs extending"
                );
                0
            }
            Err(error) => {
                let _ = writeln!(stderr, "nah: {error}");
                ExitCode::COMMAND_FAILURE.value()
            }
        };
    }
    let (action_name, args, enabled) = match action {
        GuardAction::Enable(args) => ("enabled", args, Some(true)),
        GuardAction::Disable(args) => ("disabled", args, Some(false)),
        GuardAction::Reset(args) => ("reset", args, None),
        GuardAction::New(_) => unreachable!(),
    };
    let selector = guard_selector(&args);
    let result = enabled.map_or_else(
        || reset_guard(&args.name, &selector),
        |enabled| set_guard_enabled(&args.name, enabled, &selector),
    );
    match result {
        Ok(warnings) => {
            let _ = writeln!(stdout, "{action_name} guard {}", args.name);
            for warning in warnings {
                let _ = writeln!(stderr, "nah: {warning}");
            }
            0
        }
        Err(error) => {
            let suffix = if error.starts_with("guard `") && error.ends_with("was not found") {
                "; run `nah guards` to list available guards"
            } else {
                ""
            };
            let _ = writeln!(stderr, "nah: {error}{suffix}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn guard_selector(args: &GuardTargetArgs) -> GuardSelector {
    match &args.project {
        Some(root) => GuardSelector::Project(root.clone()),
        None if args.user => GuardSelector::User,
        None => GuardSelector::Any,
    }
}

fn configure_runtime_hook<W: Write, E: Write>(
    runtime: Runtime,
    install: bool,
    failure_policy: Option<FailurePolicy>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    match set_runtime_configured(runtime, install, failure_policy) {
        Ok(mutation) => {
            for line in mutation.lines() {
                let _ = writeln!(stdout, "{line}");
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn inspect_runtime_hook<W: Write, E: Write>(
    runtime: Runtime,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let entry = runtime_entry(runtime);
    match entry.status {
        Ok(status) => {
            let runtime_name = runtime.cli_name();
            let docs_topic = entry.docs_topic;
            match status {
                RuntimeHookStatus::WiringCurrent => {
                    let _ = writeln!(stdout, "{}: wiring current", entry.name);
                    let _ = writeln!(
                        stdout,
                        "failure policy: {}",
                        FailurePolicy::Delegate.cli_name()
                    );
                    let _ = writeln!(
                        stdout,
                        "guarantee: runtime approval remains authoritative when nah cannot decide"
                    );
                    let _ = writeln!(stdout, "verify: nah docs {docs_topic}");
                }
                RuntimeHookStatus::WiringCurrentFailClosed => {
                    let _ = writeln!(stdout, "{}: wiring current", entry.name);
                    let _ = writeln!(
                        stdout,
                        "failure policy: {}",
                        FailurePolicy::Block.cli_name()
                    );
                    let _ = writeln!(
                        stdout,
                        "guarantee: intercepted calls are denied when nah cannot complete required safety evaluation"
                    );
                    let _ = writeln!(stdout, "verify: nah docs {docs_topic}");
                }
                RuntimeHookStatus::NotConfigured => {
                    let _ = writeln!(stdout, "{}: not configured", entry.name);
                    let _ = writeln!(stdout, "next: nah hook {runtime_name} install");
                    let _ = writeln!(stdout, "docs: nah docs {docs_topic}");
                }
                RuntimeHookStatus::NeedsReinstall => {
                    let _ = writeln!(stdout, "{}: reinstall required", entry.name);
                    let _ = writeln!(stdout, "detected failure policy: fail-open");
                    let _ = writeln!(
                        stdout,
                        "guarantee: runtime approval remains authoritative when nah cannot decide"
                    );
                    let _ = writeln!(stdout, "next: nah hook {runtime_name} install");
                    let _ = writeln!(stdout, "docs: nah docs {docs_topic}");
                }
                RuntimeHookStatus::NeedsReinstallFailClosed => {
                    let _ = writeln!(stdout, "{}: reinstall required", entry.name);
                    let _ = writeln!(stdout, "detected failure policy: fail-closed");
                    let _ = writeln!(
                        stdout,
                        "guarantee: intercepted calls are denied when nah cannot complete required safety evaluation"
                    );
                    let _ = writeln!(stdout, "next: nah hook {runtime_name} install");
                    let _ = writeln!(stdout, "docs: nah docs {docs_topic}");
                }
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn run_runtime_hook<R: Read, W: Write, E: Write>(
    runtime: Runtime,
    failure_policy: FailurePolicy,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    match runtime {
        Runtime::Amp => amp_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Antigravity => antigravity_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Claude => claude_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Cline => cline_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Codex => codex_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Copilot => copilot_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Cursor => cursor_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Devin => {
            let project_dir = std::env::var("DEVIN_PROJECT_DIR").ok();
            devin_adapter::run(
                stdin,
                stdout,
                stderr,
                project_dir.as_deref(),
                failure_policy,
            )
        }
        Runtime::Droid => droid_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Hermes => hermes_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Kiro => kiro_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::OpenClaw => openclaw_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::OpenCode => opencode_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::Pi => pi_adapter::run(stdin, stdout, stderr, failure_policy),
        Runtime::PrimeAgent => prime_agent_adapter::run(stdin, stdout, stderr, failure_policy),
    }
}

fn emit_test<W: Write, E: Write>(
    result: Result<(String, Vec<String>), TestError>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    match result {
        Ok((output, warnings)) => {
            let _ = write!(stdout, "{output}");
            for warning in warnings {
                let _ = writeln!(stderr, "nah: {warning}");
            }
            0
        }
        Err(TestError::Usage(error)) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::USAGE.value()
        }
        Err(TestError::Failed(error)) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn emit_docs<W: Write, E: Write>(
    topic: Option<&str>,
    guard: Option<&str>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let rendered = match (topic, guard) {
        (Some(docs::GUARDS_TOPIC), None) => return emit_catalog(true, stdout, stderr),
        (Some(docs::GUARDS_TOPIC), Some(guard)) => docs::render_guard(guard),
        (_, Some(_)) => Err("only the `guards` topic takes a guard name".to_owned()),
        (topic, None) => docs::render(topic),
    };
    match rendered {
        Ok(contents) => {
            let _ = write!(stdout, "{contents}");
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

pub(crate) fn run_decide<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    run_decide_for_runtime(stdin, stdout, stderr, None, FailurePolicy::Delegate, None).code
}

pub(crate) struct DecideOutcome {
    pub(crate) code: u8,
    pub(crate) audit_recorded: bool,
    pub(crate) evaluation_failed: bool,
    pub(crate) fail_closed_block: bool,
    pub(crate) operator_required_unavailable: bool,
}

/// `runtime` is the adapter that produced this call, and is recorded with the
/// decision. Only the `nah hook <runtime> run` adapters can name one.
pub(crate) fn run_decide_for_runtime<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    runtime: Option<Runtime>,
    failure_policy: FailurePolicy,
    code: Option<&CodeInput>,
) -> DecideOutcome {
    let code = if matches!(
        runtime,
        Some(Runtime::Copilot | Runtime::Hermes | Runtime::OpenClaw | Runtime::PrimeAgent)
    ) {
        code
    } else {
        None
    };
    // A panic would end the process with a signal and no decision body, which
    // every adapter reads as "nah did not block". Report no decision instead,
    // so each adapter answers through its own unavailable branch. This is the
    // backstop for a defect nobody has found yet; it cannot catch a stack
    // overflow, which is why the parser bounds its own recursion.
    let decided = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decide_and_emit(stdin, stdout, stderr, runtime, failure_policy, code)
    }));
    decided.unwrap_or_else(|_| {
        let _ = writeln!(stderr, "nah: internal failure; no decision was produced");
        DecideOutcome {
            code: ExitCode::UNAVAILABLE.value(),
            audit_recorded: false,
            evaluation_failed: true,
            fail_closed_block: false,
            operator_required_unavailable: true,
        }
    })
}

fn decide_and_emit<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    runtime: Option<Runtime>,
    failure_policy: FailurePolicy,
    code: Option<&CodeInput>,
) -> DecideOutcome {
    let started = Instant::now();
    let mut payload = String::new();
    let mut audit = None;
    let mut failure_audit = None;
    if stdin.read_to_string(&mut payload).is_err() {
        let _ = writeln!(stderr, "nah: input failed; no decision was produced");
        return DecideOutcome {
            code: ExitCode::UNAVAILABLE.value(),
            audit_recorded: false,
            evaluation_failed: true,
            fail_closed_block: false,
            operator_required_unavailable: true,
        };
    }
    let input = match serde_json::from_str::<ToolCallInput>(&payload) {
        Ok(input) => input,
        Err(_) => {
            let _ = writeln!(stderr, "nah: invalid input; no decision was produced");
            return DecideOutcome {
                code: ExitCode::UNAVAILABLE.value(),
                audit_recorded: false,
                evaluation_failed: true,
                fail_closed_block: false,
                operator_required_unavailable: true,
            };
        }
    };
    let mut all_paused = false;
    let mut result = match live_state::load() {
        Ok(state) => {
            all_paused = state
                .nap
                .as_ref()
                .is_some_and(|active| active.mode() == &NapMode::All);
            let result = decide_live_for_runtime(&input, code, &state, runtime);
            audit = Some((state.ctx.clone(), input.clone()));
            result
        }
        Err(_) => {
            let platform = live_state::host_platform();
            if let Ok(home) = live_state::home(platform) {
                failure_audit = Some((home, platform, input.clone()));
            }
            failed_delegate("pipeline", "context", "context failed")
        }
    };
    let fail_closed_block = apply_failure_policy(&mut result, failure_policy, all_paused);
    let duration_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let id = decision_id();
    let envelope = DecisionEnvelope::new(&id, &current_timestamp_rfc3339(), duration_us)
        .expect("generated decision envelope is valid");
    let include_refusals = failure_policy == FailurePolicy::Block
        || result
            .refusals()
            .iter()
            .any(|refusal| refusal.code() == "deadline-exceeded");
    let mut audit_recorded = false;
    if let Some((ctx, input)) = audit {
        match records::append_decision(
            &ctx,
            &input,
            &result,
            envelope.clone(),
            runtime,
            include_refusals,
        ) {
            Ok(()) => audit_recorded = true,
            Err(error) => {
                result.push_warning(format!("audit failed: {error}"));
                match records::append_failure(
                    ctx.home(),
                    ctx.platform(),
                    &input,
                    &result,
                    envelope,
                    runtime,
                    include_refusals,
                ) {
                    Ok(()) => audit_recorded = true,
                    Err(fallback_error) => {
                        result.push_warning(format!("audit fallback failed: {fallback_error}"));
                    }
                }
            }
        }
    } else if let Some((home, platform, input)) = failure_audit {
        match records::append_failure(
            &home,
            platform,
            &input,
            &result,
            envelope,
            runtime,
            include_refusals,
        ) {
            Ok(()) => audit_recorded = true,
            Err(error) => result.push_warning(format!("audit failed: {error}")),
        }
    }
    if runtime.is_none() {
        for warning in result.warnings() {
            let _ = writeln!(stderr, "nah: {warning}");
        }
    }
    let output = DecisionOutput::new(result.core(), &id, duration_us)
        .expect("generated decision output is valid");
    let evaluation_failed = !result.failures().is_empty();
    DecideOutcome {
        code: emit_decision_output(stdout, &output),
        audit_recorded,
        evaluation_failed,
        fail_closed_block,
        operator_required_unavailable: false,
    }
}

/// Decides under the self-protection projection of `runtime`, the adapter the
/// call came through. A projection that cannot be built is an evaluation
/// failure, never silently no protection.
pub(crate) fn decide_live_for_runtime(
    input: &ToolCallInput,
    code: Option<&CodeInput>,
    state: &live_state::LiveState,
    runtime: Option<Runtime>,
) -> DecisionResult {
    let self_protection = runtime
        .map(runtime_self_protection)
        .transpose()
        .map(|self_protection| self_protection.unwrap_or_default());
    let (self_protection, self_protection_error) = match self_protection {
        Ok(self_protection) => (self_protection, None),
        Err(error) => (
            nah_proto::runtime_protection::SelfProtectionProjection::default(),
            Some(error),
        ),
    };
    let mut result = decide_live_with_self_protection(input, code, state, &self_protection);
    if let Some(error) = self_protection_error {
        result.push_warning(format!("runtime self-protection failed: {error}"));
        result.push_failure(EvaluationFailure::nah("runtime-self-protection", "failed"));
    }
    result
}

fn apply_failure_policy(
    result: &mut DecisionResult,
    failure_policy: FailurePolicy,
    all_paused: bool,
) -> bool {
    if failure_policy == FailurePolicy::Block
        && !all_paused
        && result.core().verdict() == nah_proto::decision::Verdict::Delegate
        && (!result.failures().is_empty() || !result.refusals().is_empty())
    {
        let core = nah_proto::decision::DecisionCore::structural_block_with_coverage(
            result.core().coverage(),
            result.recovery_advice().message(),
        )
        .expect("fixed fail-closed reason is valid");
        result.replace_core(core);
        true
    } else {
        false
    }
}

fn emit_decision_output<W: Write>(stdout: &mut W, output: &DecisionOutput) -> u8 {
    if serde_json::to_writer(&mut *stdout, output).is_err() || writeln!(stdout).is_err() {
        ExitCode::UNAVAILABLE.value()
    } else {
        ExitCode::from(output.verdict()).value()
    }
}

fn persist_trust<W: Write, E: Write>(root: &str, stdout: &mut W, stderr: &mut E) -> u8 {
    match trust_root(root) {
        Ok(path) => {
            let _ = writeln!(stdout, "trusted {path}");
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn revoke_trust<W: Write, E: Write>(root: &str, stdout: &mut W, stderr: &mut E) -> u8 {
    match untrust_root(root) {
        Ok((path, removed)) => {
            let noun = if removed == 1 { "guard" } else { "guards" };
            let _ = writeln!(
                stdout,
                "untrusted {path}\nrevoked {removed} enabled project {noun}"
            );
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn wake<W: Write, E: Write>(stdout: &mut W, stderr: &mut E) -> u8 {
    let platform = live_state::host_platform();
    let result = live_state::home(platform)
        .and_then(|home| nap::wake(&home, platform).map_err(|error| error.to_string()));
    match result {
        Ok(()) => {
            let _ = writeln!(stdout, "nah is awake");
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn emit_catalog<W: Write, E: Write>(docs: bool, stdout: &mut W, stderr: &mut E) -> u8 {
    match (list_shipped_guards(docs), list_custom_guards()) {
        (Ok((shipped, warnings)), Ok(custom)) => {
            let _ = write!(stdout, "{shipped}{custom}");
            for warning in warnings {
                let _ = writeln!(stderr, "nah: {warning}");
            }
            0
        }
        (Err(error), _) | (_, Err(error)) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn explain<W: Write, E: Write>(id: &str, stdout: &mut W, stderr: &mut E) -> u8 {
    let platform = live_state::host_platform();
    let result = live_state::home(platform).and_then(|home| {
        records::explain_decision(&home, platform, id).map_err(|error| error.to_string())
    });
    match result {
        Ok(Some(explanation)) => {
            let _ = writeln!(stdout, "{explanation}");
            0
        }
        Ok(None) => {
            let _ = writeln!(
                stderr,
                "nah: decision `{id}` was not found; run `nah log` to list recent decision IDs"
            );
            ExitCode::COMMAND_FAILURE.value()
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn list_log<W: Write, E: Write>(
    limit: usize,
    json: bool,
    blocked: bool,
    effinterp_gap: bool,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let platform = live_state::host_platform();
    let result = live_state::home(platform).and_then(|home| {
        records::list_decisions(&home, platform, limit, json, blocked, effinterp_gap)
            .map_err(|error| error.to_string())
    });
    match result {
        Ok(view) => {
            if let Some(path) = &view.recovered_from {
                let _ = writeln!(
                    stderr,
                    "nah: decision log recovered; original archived to {}",
                    path.display()
                );
            }
            if view.lines.is_empty() && !json {
                let message = if limit == 0 {
                    "No decisions requested."
                } else if effinterp_gap {
                    "No effinterp gaps recorded."
                } else if blocked {
                    "No blocked decisions recorded."
                } else {
                    "No decisions recorded."
                };
                let _ = writeln!(stdout, "{message}");
            }
            if !json
                && limit > 0
                && let Some(summary) = view.failures
            {
                let _ = writeln!(stdout, "{}", summary.display());
            }
            for line in view.lines {
                let _ = writeln!(stdout, "{line}");
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

pub(crate) fn decision_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("decision-{}-{nanos}", std::process::id())
}

/// The current UTC time as an RFC 3339 timestamp with whole seconds, such as
/// `2026-07-23T12:00:00Z`.
pub(crate) fn current_timestamp_rfc3339() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The `nah` binary entry point.
pub fn run() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Some(requested) = interactive_nap_request(&args) {
        if !stdin.is_terminal() || !stdout.is_terminal() {
            eprintln!("nah: `nah nap` must be run by the operator in an interactive terminal.");
            return std::process::ExitCode::from(ExitCode::USAGE.value());
        }
        let mode = match nap_mode(requested, &shipped_names(), live_custom_guard_names) {
            Ok(mode) => mode,
            Err(error) => {
                eprintln!("nah: {error}");
                return std::process::ExitCode::from(ExitCode::USAGE.value());
            }
        };
        let mut stdin = stdin.lock();
        return std::process::ExitCode::from(run_interactive_nap(
            mode,
            &mut stdin,
            &mut stdout.lock(),
            &mut std::io::stderr().lock(),
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    if matches!(args.as_slice(), [command] if command == "tui") {
        if !stdin.is_terminal() || !stdout.is_terminal() {
            eprintln!("nah: `nah tui` requires an interactive terminal.");
            return std::process::ExitCode::from(ExitCode::USAGE.value());
        }
        return match crate::tui::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("nah: {error}");
                std::process::ExitCode::from(ExitCode::COMMAND_FAILURE.value())
            }
        };
    }
    if is_interactive_decide(&args, stdin.is_terminal()) {
        eprintln!(
            "nah: `nah decide` reads a JSON tool call from stdin; use `nah test <command>` for an interactive dry run."
        );
        return std::process::ExitCode::from(ExitCode::USAGE.value());
    }
    let code = run_with(
        &args,
        &mut stdin.lock(),
        &mut stdout.lock(),
        &mut std::io::stderr().lock(),
    );
    std::process::ExitCode::from(code)
}

/// Every argument list the grammar accepts as `nah nap` takes the interactive
/// path, returning its requested guard names. Help and usage errors fall
/// through to the ordinary dispatcher, which prints them without starting a
/// nap.
fn interactive_nap_request(args: &[String]) -> Option<Vec<String>> {
    match parse_from(std::iter::once("nah".to_owned()).chain(args.iter().cloned())) {
        Ok(Cli {
            command: Command::Nap(nap),
        }) => Some(nap.guards),
        _ => None,
    }
}

/// Resolves `nah nap` arguments against the guards `nah guards` lists.
/// `custom` yields one name per listed custom guard, so a name listed in
/// several scopes is ambiguous, as it is for `nah guard disable`; it is read
/// only when guard names were given.
fn nap_mode(
    requested: Vec<String>,
    shipped: &[&str],
    custom: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<NapMode, String> {
    let requested = requested.into_iter().collect::<BTreeSet<_>>();
    if requested.is_empty() {
        return Ok(NapMode::SelfProtection);
    }
    if requested.contains(NAP_ALL) {
        return if requested.len() == 1 {
            Ok(NapMode::All)
        } else {
            Err(format!("`{NAP_ALL}` cannot be combined with guard names"))
        };
    }
    let custom = custom()?;
    for name in &requested {
        match custom.iter().filter(|custom| *custom == name).count() {
            0 if shipped.contains(&name.as_str()) => {}
            0 => {
                let valid = shipped
                    .iter()
                    .map(|name| (*name).to_owned())
                    .chain(custom)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                return Err(format!(
                    "unknown guard `{name}`; valid guards: {}",
                    valid.join(", ")
                ));
            }
            1 => {}
            _ => return Err(format!("guard name `{name}` is ambiguous across scopes")),
        }
    }
    Ok(NapMode::Guards(requested.into_iter().collect()))
}

fn live_custom_guard_names() -> Result<Vec<String>, String> {
    Ok(custom_guard_entries()?
        .into_iter()
        .map(|entry| entry.target.name().to_owned())
        .collect())
}

fn run_interactive_nap<R: std::io::BufRead, W: Write, E: Write>(
    mode: NapMode,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let scope = nap_prompt(&mode);
    let _ = writeln!(
        stdout,
        "Pause nah globally for 10 minutes?\n{scope}\nThis affects every session using this nah installation.\nPersistent changes remain after the nap expires.\nIf nah or its hook is removed, expiration cannot restore it.\n\nType nap to continue:"
    );
    let _ = stdout.flush();
    let mut input = String::new();
    if stdin.read_line(&mut input).is_err() {
        let _ = writeln!(stderr, "nah: nap confirmation failed");
        return ExitCode::COMMAND_FAILURE.value();
    }
    if !nap_confirmation(&input) {
        let _ = writeln!(stderr, "nah: nap cancelled");
        return ExitCode::COMMAND_FAILURE.value();
    }
    let platform = live_state::host_platform();
    let result = live_state::home(platform)
        .and_then(|home| nap::start(&home, platform, mode).map_err(|error| error.to_string()));
    match result {
        Ok(active) => {
            let _ = writeln!(
                stdout,
                "nah {} is napping for 10 minutes\nrun `nah wake` to resume sooner",
                active.mode().scope()
            );
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn nap_confirmation(input: &str) -> bool {
    input
        .trim_end_matches(['\r', '\n'])
        .eq_ignore_ascii_case("nap")
}

fn nap_prompt(mode: &NapMode) -> String {
    match mode {
        NapMode::SelfProtection => "Self-protection will pause; guards remain active.".to_owned(),
        NapMode::All => {
            "All non-permanent enforcement will pause; other calls will delegate to their runtime."
                .to_owned()
        }
        NapMode::Guards(_) => format!(
            "Only {} will pause; self-protection and every other guard remain active.",
            mode.scope()
        ),
    }
}

fn is_interactive_decide(args: &[String], stdin_is_terminal: bool) -> bool {
    stdin_is_terminal && matches!(args, [command] if command == "decide")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_analysis_obeys_fail_open_fail_closed_and_all_paused() {
        use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};

        let ctx = Ctx::new(
            Platform::Linux,
            AbsolutePath::new(Platform::Linux, "/home/test").unwrap(),
            vec![],
            vec![],
            TrustProjection::new(vec![]).unwrap(),
        )
        .unwrap();
        let input = ToolCallInput::new(
            SchemaVersion::V1,
            "Bash",
            serde_json::json!({"command":"echo ok"}),
            "/repo",
            None,
        )
        .unwrap();
        let expired = |mode| crate::pipeline::decide_with_expired_budget(&input, &ctx, mode);

        let mut fail_open = expired(nah_policy::EnforcementMode::Normal);
        assert!(!apply_failure_policy(
            &mut fail_open,
            FailurePolicy::Delegate,
            false
        ));
        assert_eq!(
            fail_open.core().verdict(),
            nah_proto::decision::Verdict::Delegate
        );
        assert!(matches!(
            fail_open.refusals(),
            [refusal]
                if refusal.code() == "deadline-exceeded"
                    && refusal.component() == "effinterp-engine"
        ));
        assert_eq!(
            fail_open.recovery_advice(),
            crate::pipeline::RecoveryAdvice::CorrectOrSimplify
        );

        let mut fail_closed = expired(nah_policy::EnforcementMode::Normal);
        assert!(apply_failure_policy(
            &mut fail_closed,
            FailurePolicy::Block,
            false
        ));
        assert_eq!(
            fail_closed.core().verdict(),
            nah_proto::decision::Verdict::Block
        );
        assert!(!apply_failure_policy(
            &mut fail_closed,
            FailurePolicy::Delegate,
            false
        ));
        assert_eq!(
            fail_closed.core().verdict(),
            nah_proto::decision::Verdict::Block
        );

        let mut all_paused = expired(nah_policy::EnforcementMode::AllPaused);
        assert!(!apply_failure_policy(
            &mut all_paused,
            FailurePolicy::Block,
            true
        ));
        assert_eq!(
            all_paused.core().verdict(),
            nah_proto::decision::Verdict::Delegate
        );
    }

    #[test]
    fn trust_command_rejects_extra_root_arguments() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            &["trust".into(), "/one".into(), "/two".into()],
            &mut std::io::empty(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, ExitCode::USAGE.value());
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("unexpected argument '/two'"));
        assert!(stderr.contains("Usage: nah trust [ROOT]"));
    }

    #[test]
    fn timestamps_are_valid_rfc3339() {
        assert!(DecisionEnvelope::new("decision", &current_timestamp_rfc3339(), 0).is_ok());
    }

    #[test]
    fn a_panic_on_the_decision_path_reports_no_decision() {
        struct PanickingStdin;

        impl Read for PanickingStdin {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("decision path panicked");
            }
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = run_decide_for_runtime(
            &mut PanickingStdin,
            &mut stdout,
            &mut stderr,
            Some(Runtime::Claude),
            FailurePolicy::Block,
            None,
        );
        assert_eq!(outcome.code, ExitCode::UNAVAILABLE.value());
        assert!(outcome.operator_required_unavailable);
        assert!(stdout.is_empty());
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("no decision was produced"), "{stderr}");
    }

    #[test]
    fn malformed_and_unreadable_input_report_no_decision() {
        struct FailingStdin;

        impl Read for FailingStdin {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("offline"))
            }
        }

        for mut stdin in [
            Box::new("not-json".as_bytes()) as Box<dyn Read>,
            Box::new(FailingStdin) as Box<dyn Read>,
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run_decide(&mut stdin, &mut stdout, &mut stderr);
            assert_eq!(code, ExitCode::UNAVAILABLE.value());
            assert!(stdout.is_empty());
            assert!(!stderr.is_empty());
        }
    }

    #[test]
    fn decision_output_write_failure_reports_no_decision() {
        struct FailingStdout;

        impl Write for FailingStdout {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let core = nah_proto::decision::DecisionCore::new_with_coverage(
            nah_proto::action::Coverage::Full,
            nah_proto::decision::Verdict::Delegate,
            vec![],
        )
        .unwrap();
        let output = DecisionOutput::new(&core, "decision", 1).unwrap();

        assert_eq!(
            emit_decision_output(&mut FailingStdout, &output),
            ExitCode::UNAVAILABLE.value()
        );
    }

    #[test]
    fn only_bare_interactive_decide_is_refused() {
        assert!(is_interactive_decide(&["decide".into()], true));
        assert!(!is_interactive_decide(&["decide".into()], false));
        assert!(!is_interactive_decide(
            &["decide".into(), "--help".into()],
            true
        ));
        assert!(!is_interactive_decide(&["test".into()], true));
    }

    #[test]
    fn only_exact_nap_shapes_enter_the_interactive_path() {
        let request = |args: &[&str]| {
            interactive_nap_request(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(request(&["nap"]), Some(vec![]));
        assert_eq!(request(&["nap", "all"]), Some(vec!["all".into()]));
        assert_eq!(
            request(&["nap", "fs-home", "no-such-guard"]),
            Some(vec!["fs-home".into(), "no-such-guard".into()])
        );
        for help_or_usage_error in [
            &["nap", "--help"][..],
            &["nap", "-h"],
            &["nap", "fs-home", "--help"],
            &["nap", "--all"],
            &["nap", "--bogus"],
            &["wake"],
        ] {
            assert_eq!(
                request(help_or_usage_error),
                None,
                "{help_or_usage_error:?}"
            );
        }

        let shipped = ["fs-home", "git-history"];
        let custom = || Ok(vec!["corp".to_owned(), "shared".into(), "shared".into()]);
        let unread = || -> Result<Vec<String>, String> { panic!("custom guards were read") };
        let names = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(
            nap_mode(vec![], &shipped, unread),
            Ok(NapMode::SelfProtection)
        );
        assert_eq!(
            nap_mode(names(&["all", "all"]), &shipped, unread),
            Ok(NapMode::All)
        );
        assert_eq!(
            nap_mode(
                names(&["git-history", "corp", "git-history"]),
                &shipped,
                custom
            ),
            Ok(NapMode::Guards(names(&["corp", "git-history"])))
        );
        assert!(nap_mode(names(&["all", "fs-home"]), &shipped, custom).is_err());
        let unknown = nap_mode(names(&["fs-home", "nope"]), &shipped, custom).unwrap_err();
        assert!(unknown.contains("nope"), "{unknown}");
        for valid in ["corp", "fs-home", "git-history", "shared"] {
            assert!(unknown.contains(valid), "{unknown}");
        }
        let ambiguous = nap_mode(names(&["shared"]), &shipped, custom).unwrap_err();
        assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
    }

    #[test]
    fn confirmation_copy_distinguishes_self_and_all() {
        let guards = NapMode::Guards(vec!["corp".into(), "fs-home".into()]);
        let scopes = [
            nap_prompt(&NapMode::SelfProtection),
            nap_prompt(&NapMode::All),
            nap_prompt(&guards),
        ];
        for (index, scope) in scopes.iter().enumerate() {
            assert!(!scope.trim().is_empty());
            assert!(!scopes[..index].contains(scope));
        }
        assert!(scopes[2].contains("corp") && scopes[2].contains("fs-home"));
    }

    #[test]
    fn nap_confirmation_is_case_insensitive() {
        for input in ["NAP\n", "nap\r\n", "Nap\n", "nAP"] {
            assert!(nap_confirmation(input), "{input:?}");
        }
        for input in ["NAP ALL\n", "nap all", "", "naps\n"] {
            assert!(!nap_confirmation(input), "{input:?}");
        }
    }
}
