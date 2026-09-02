//! Testable command dispatch and machine-facing `nah decide` I/O.

use std::io::{IsTerminal, Read, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use nah_proto::decision::{DecisionEnvelope, DecisionOutput, ExitCode};
use nah_proto::tool::ToolCallInput;

use crate::amp_adapter;
use crate::antigravity_adapter;
#[cfg(feature = "effinterp")]
use crate::args::DaemonAction;
#[cfg(feature = "effinterp")]
use crate::args::EffinterpAction;
use crate::args::{Command, GuardAction, GuardTargetArgs, HookAction, parse_from};
use crate::claude_adapter;
use crate::cline_adapter;
use crate::code_input::CodeInput;
use crate::codex_adapter;
use crate::commands::{
    GuardSelector, RuntimeHookStatus, list_custom_guards, list_shipped_guards, new_guard,
    reset_guard, runtime_entry, runtime_self_protection, set_guard_enabled, set_runtime_configured,
    test_command, trust_root, untrust_root,
};
#[cfg(feature = "effinterp")]
use crate::commands::{configure_effinterp, effinterp_status};
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
use crate::pipeline::{EvaluationFailure, decide_live_with_self_protection, failed_delegate};
use crate::prime_agent_adapter;
use crate::records;
use crate::runtime::{FailurePolicy, Runtime};
use crate::xi_adapter;

const CLI_USAGE_ERROR: u8 = 4;

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
        return CLI_USAGE_ERROR;
    }
    let cli = match parse_from(std::iter::once("nah".to_owned()).chain(args.iter().cloned())) {
        Ok(cli) => cli,
        Err(error) => return emit_clap_error(error, stdout, stderr),
    };
    match cli.command {
        Command::Tui => {
            let _ = writeln!(stderr, "nah: `nah tui` requires an interactive terminal.");
            2
        }
        Command::Decide(args) => {
            #[cfg(feature = "effinterp")]
            {
                crate::effinterp_state::with_forced(args.effinterp, || {
                    run_decide(stdin, stdout, stderr)
                })
            }
            #[cfg(not(feature = "effinterp"))]
            {
                let _ = args;
                run_decide(stdin, stdout, stderr)
            }
        }
        Command::Nap(_) => {
            let _ = writeln!(
                stderr,
                "nah: `nah nap` must be run by the operator in an interactive terminal."
            );
            2
        }
        Command::Wake => wake(stdout, stderr),
        Command::Test(args) => {
            // UNDOCUMENTED-EFFINTERP: forward the hidden opt-in only in feature builds.
            #[cfg(feature = "effinterp")]
            let result = test_command(&args.command, args.json, args.effinterp);
            #[cfg(not(feature = "effinterp"))]
            let result = test_command(&args.command, args.json);
            emit_test(result, stdout, stderr)
        }
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
                #[cfg(feature = "effinterp")]
                {
                    crate::effinterp_state::with_forced(run.effinterp, || {
                        run_runtime_hook(args.runtime, policy, stdin, stdout, stderr)
                    })
                }
                #[cfg(not(feature = "effinterp"))]
                {
                    run_runtime_hook(args.runtime, policy, stdin, stdout, stderr)
                }
            }
        },
        Command::Why(args) => explain(&args.id, stdout, stderr),
        Command::Log(args) => {
            #[cfg(feature = "effinterp")]
            let gap = args.effinterp_gap;
            #[cfg(not(feature = "effinterp"))]
            let gap = false;
            list_log(args.count, args.json, args.blocked, gap, stdout, stderr)
        }
        #[cfg(feature = "effinterp")]
        Command::Effinterp(args) => configure_effinterp_command(args.action, stdout, stderr),
        Command::Docs(args) => emit_docs(args.topic.as_deref(), stdout, stderr),
        // UNDOCUMENTED-EFFINTERP: dispatch the hidden daemon only in feature builds.
        #[cfg(feature = "effinterp")]
        Command::Daemon(args) => match args.action {
            DaemonAction::Run(args) => nah_effinterp::run_daemon(
                nah_effinterp::DaemonRunOptions {
                    once: args.once,
                    poll_seconds: args.poll,
                    max_memory_mib: args.max_memory,
                    max_files: args.max_files,
                },
                stderr,
            ),
            DaemonAction::Status => nah_effinterp::daemon_status(stdout, stderr),
            DaemonAction::Stop => nah_effinterp::stop_daemon(stderr),
            DaemonAction::Build(args) => {
                nah_effinterp::build_daemon_snapshot(&args.id, args.max_memory, stderr)
            }
        },
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
        CLI_USAGE_ERROR
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
                2
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
        Ok(mutation) => {
            let _ = writeln!(stdout, "{action_name} guard {}", mutation.canonical_name);
            for warning in mutation.warnings {
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
            2
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
            2
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
            2
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
        Runtime::Xi => xi_adapter::run(stdin, stdout, stderr, failure_policy),
    }
}

fn emit_test<W: Write, E: Write>(
    result: Result<(String, Vec<String>), String>,
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
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            2
        }
    }
}

fn emit_docs<W: Write, E: Write>(topic: Option<&str>, stdout: &mut W, stderr: &mut E) -> u8 {
    if topic == Some(docs::GUARDS_TOPIC) {
        return emit_catalog(true, stdout, stderr);
    }
    match docs::render(topic) {
        Ok(contents) => {
            let _ = write!(stdout, "{contents}");
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            2
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
                .is_some_and(|active| active.mode() == NapMode::All);
            let self_protection = runtime
                .map(runtime_self_protection)
                .transpose()
                .map(|self_protection| self_protection.unwrap_or_default());
            let (self_protection, self_protection_error) = match self_protection {
                Ok(self_protection) => (self_protection, None),
                Err(error) => (
                    nah_actions::SelfProtectionProjection::default(),
                    Some(error),
                ),
            };
            let mut result =
                decide_live_with_self_protection(&input, code, &state, &self_protection);
            if let Some(error) = self_protection_error {
                result.push_warning(format!("runtime self-protection failed: {error}"));
                result.push_failure(EvaluationFailure::nah("runtime-self-protection", "failed"));
            }
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
    let mut fail_closed_block = false;
    if failure_policy == FailurePolicy::Block
        && !all_paused
        && result.core().verdict() == nah_proto::decision::Verdict::Delegate
        && (!result.failures().is_empty() || !result.refusals().is_empty())
    {
        let core = nah_proto::decision::DecisionCore::structural_block(
            result.action_stream(),
            result.recovery_advice().message(),
        )
        .expect("fixed fail-closed reason is valid");
        result.replace_core(core);
        fail_closed_block = true;
    }
    let duration_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let id = decision_id();
    let envelope = DecisionEnvelope::new(&id, &timestamp_rfc3339(), duration_us)
        .expect("generated decision envelope is valid");
    let mut audit_recorded = false;
    if let Some((ctx, input)) = audit {
        match records::append_decision(
            &ctx,
            &input,
            &result,
            envelope.clone(),
            runtime,
            failure_policy == FailurePolicy::Block,
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
                    failure_policy == FailurePolicy::Block,
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
            failure_policy == FailurePolicy::Block,
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
            2
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
            2
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
            2
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
            2
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
            2
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            2
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
            2
        }
    }
}

#[cfg(feature = "effinterp")]
fn configure_effinterp_command<W: Write, E: Write>(
    action: EffinterpAction,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let result = match action {
        EffinterpAction::On => configure_effinterp(true),
        EffinterpAction::Off => configure_effinterp(false),
        EffinterpAction::Status => effinterp_status(),
    };
    match result {
        Ok(status) => {
            let _ = writeln!(stdout, "{status}");
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            2
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

pub(crate) fn timestamp_rfc3339() -> String {
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

pub fn run() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Some(mode) = interactive_nap_mode(&args) {
        if !stdin.is_terminal() || !stdout.is_terminal() {
            eprintln!("nah: `nah nap` must be run by the operator in an interactive terminal.");
            return std::process::ExitCode::from(2);
        }
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
            return std::process::ExitCode::from(2);
        }
        return match crate::tui::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("nah: {error}");
                std::process::ExitCode::from(2)
            }
        };
    }
    if is_interactive_decide(&args, stdin.is_terminal()) {
        eprintln!(
            "nah: `nah decide` reads a JSON tool call from stdin; use `nah test <command>` for an interactive dry run."
        );
        return std::process::ExitCode::from(2);
    }
    let code = run_with(
        &args,
        &mut stdin.lock(),
        &mut stdout.lock(),
        &mut std::io::stderr().lock(),
    );
    std::process::ExitCode::from(code)
}

fn interactive_nap_mode(args: &[String]) -> Option<NapMode> {
    match args {
        [command] if command == "nap" => Some(NapMode::SelfProtection),
        [command, flag] if command == "nap" && flag == "--all" => Some(NapMode::All),
        _ => None,
    }
}

fn run_interactive_nap<R: std::io::BufRead, W: Write, E: Write>(
    mode: NapMode,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let (scope, confirmation) = nap_prompt(mode);
    let _ = writeln!(
        stdout,
        "Pause nah globally for 10 minutes?\n{scope}\nThis affects every session using this nah installation.\nPersistent changes remain after the nap expires.\nIf nah or its hook is removed, expiration cannot restore it.\n\nType {confirmation} to continue:"
    );
    let _ = stdout.flush();
    let mut input = String::new();
    if stdin.read_line(&mut input).is_err() {
        let _ = writeln!(stderr, "nah: nap confirmation failed");
        return 2;
    }
    if !nap_confirmation(&input, confirmation) {
        let _ = writeln!(stderr, "nah: nap cancelled");
        return 2;
    }
    let platform = live_state::host_platform();
    let result = live_state::home(platform)
        .and_then(|home| nap::start(&home, platform, mode).map_err(|error| error.to_string()));
    match result {
        Ok(active) => {
            let kind = match active.mode() {
                NapMode::SelfProtection => "self-protection",
                NapMode::All => "all enforcement",
            };
            let _ = writeln!(
                stdout,
                "nah {kind} is napping for 10 minutes\nrun `nah wake` to resume sooner"
            );
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            2
        }
    }
}

fn nap_confirmation(input: &str, confirmation: &str) -> bool {
    input
        .trim_end_matches(['\r', '\n'])
        .eq_ignore_ascii_case(confirmation)
}

fn nap_prompt(mode: NapMode) -> (&'static str, &'static str) {
    match mode {
        NapMode::SelfProtection => ("Self-protection will pause; guards remain active.", "NAP"),
        NapMode::All => (
            "All non-permanent enforcement will pause; other calls will delegate to their runtime.",
            "NAP ALL",
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
    fn trust_command_rejects_extra_root_arguments() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(
            &["trust".into(), "/one".into(), "/two".into()],
            &mut std::io::empty(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, CLI_USAGE_ERROR);
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("unexpected argument '/two'"));
        assert!(stderr.contains("Usage: nah trust [ROOT]"));
    }

    #[test]
    fn timestamps_are_valid_rfc3339() {
        assert!(DecisionEnvelope::new("decision", &timestamp_rfc3339(), 0).is_ok());
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

        let stream = nah_proto::action::ActionStream::new(
            nah_proto::action::Coverage::Full,
            vec![vec![
                nah_proto::action::EffectKind::known("echo", "print").unwrap(),
            ]],
            vec![],
        )
        .unwrap();
        let core = nah_proto::decision::DecisionCore::new(
            &stream,
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
        assert_eq!(
            interactive_nap_mode(&["nap".into()]),
            Some(NapMode::SelfProtection)
        );
        assert_eq!(
            interactive_nap_mode(&["nap".into(), "--all".into()]),
            Some(NapMode::All)
        );
        assert_eq!(interactive_nap_mode(&["nap".into(), "--help".into()]), None);
    }

    #[test]
    fn confirmation_copy_distinguishes_self_and_all() {
        assert_eq!(
            nap_prompt(NapMode::SelfProtection),
            ("Self-protection will pause; guards remain active.", "NAP")
        );
        assert_eq!(
            nap_prompt(NapMode::All),
            (
                "All non-permanent enforcement will pause; other calls will delegate to their runtime.",
                "NAP ALL"
            )
        );
    }

    #[test]
    fn nap_confirmation_is_case_insensitive() {
        assert!(nap_confirmation("NAP\n", "NAP"));
        assert!(nap_confirmation("nap\r\n", "NAP"));
        assert!(nap_confirmation("NAP ALL\n", "NAP ALL"));
        assert!(nap_confirmation("nap all\r\n", "NAP ALL"));
        assert!(!nap_confirmation("nap", "NAP ALL"));
    }
}
