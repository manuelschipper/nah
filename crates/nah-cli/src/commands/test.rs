//! Renders a human dry run through the live decision pipeline without auditing it.

use std::fmt::Write;

use nah_proto::action::Coverage;
use nah_proto::ctx::{AbsolutePath, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde_json::Value;

use super::engine_plan_rendering::render_engine_plan;
use crate::args::{TestArgs, TestSourceLanguage};
use crate::code_input::{self, CodeInput, CodeIntake};
use crate::dispatch::decide_live_for_runtime;
use crate::nap::NapMode;
use crate::records::verdict_name;
use crate::runtime::Runtime;
use crate::session_memory::{self, Host};
use crate::{
    antigravity_adapter, codex_adapter, cursor_adapter, hermes_adapter, hook_adapter, live_state,
    openclaw_adapter, opencode_adapter, pi_adapter,
};

/// Why `nah test` produced no decision: an input it cannot express (a usage
/// error), or a failure reading or preparing a valid one.
pub(crate) enum TestError {
    Usage(String),
    Failed(String),
}

impl From<String> for TestError {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

pub(crate) fn test_command(args: &TestArgs) -> Result<(String, Vec<String>), TestError> {
    if let Some(path) = &args.session {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("session file {} is unreadable: {error}", path.display()))?;
        return Ok((crate::session_replay::replay(&text)?, Vec::new()));
    }
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .ok_or_else(|| "current directory is unavailable".to_owned())?;
    let (runtime, inputs, code) = test_tool_call(args, cwd)?;
    let state = live_state::load().map_err(|error| format!("context failed: {error}"))?;
    // A runtime's batch lowers to one call per operation and its hook blocks
    // on the first that blocks, so that call's decision is the one shown.
    // Where the hook saves before a discard, the dry run shows the save it
    // would make, without making it.
    let saves = crate::save_then_run::SaveMode::of(Some(runtime));
    // The hook applies session memory to every call it follows, the first of
    // a session too, so the dry run decides the call as that first call,
    // against a ledger of its own that it drops.
    let scratch = tempfile::tempdir().map_err(|error| format!("no scratch folder: {error}"))?;
    let platform = live_state::host_platform();
    let ledgers = AbsolutePath::new(platform, scratch.path().to_string_lossy())
        .map_err(|error| error.to_string())?;
    let decide_shell = |input: &ToolCallInput| session_memory::decide_shell_live(input, &state);
    let host = Host {
        ctx: &state.ctx,
        ledgers: &ledgers,
        ledgers_platform: platform,
        world: &session_memory::world::Live,
        decide_shell: &decide_shell,
        call: None,
    };
    let all_paused = state
        .nap
        .as_ref()
        .is_some_and(|active| active.mode() == &NapMode::All);
    let mut result = None;
    let mut session_rule = None;
    for input in &inputs {
        let mut decided =
            decide_live_for_runtime(input, code.as_ref(), &state, Some(runtime), saves);
        if runtime.follows_this_call() {
            session_rule =
                session_memory::apply(input, runtime, &host, &mut decided, all_paused).rule;
        }
        let blocked = decided.core().verdict() == Verdict::Block;
        result = Some((input, decided));
        if blocked {
            break;
        }
    }
    let (input, mut result) = result.expect("a tool call lowers to at least one call");
    let saved = result.take_save_request();
    // A save the hook would refuse before reading anything, it blocks.
    #[cfg(unix)]
    let saved = saved.filter(|discards| {
        match crate::save_then_run::save_preflight(discards, crate::dispatch::call_command(input)) {
            Ok(()) => true,
            Err(reason) => {
                crate::dispatch::block_discards(&mut result, discards, &reason);
                false
            }
        }
    });
    #[cfg(not(unix))]
    let _ = input;
    let saved = saved.map(|discards| discards.rules.join(", "));
    let plan = result.effinterp().map(|analysis| analysis.plan());
    // `nah test` prints the import but does not audit it. The pending file
    // stays for the next decision, which is the one record of the notice.
    let mut warnings = result.warnings().to_vec();
    for report in &state.import_reports {
        if !warnings.contains(report) {
            warnings.push(report.clone());
        }
    }
    if args.json {
        let value = serde_json::json!({
            "schema": "nah/test/v3",
            "v": 3,
            "producer": result.evidence_provenance().map(|provenance| provenance.producer.as_str()),
            "decision": result.core(),
            "saves": saved,
            "session_rule": session_rule,
            "failures": result.failures().iter().map(|failure| serde_json::json!({
                "source": failure.source(),
                "component": failure.component(),
                "code": failure.code(),
            })).collect::<Vec<_>>(),
            "plan": plan,
        });
        let output = serde_json::to_string_pretty(&value)
            .map_err(|error| format!("test output failed: {error}"))?;
        return Ok((format!("{output}\n"), warnings));
    }
    let attributions = if result.core().policy_attributions().is_empty() {
        "none".into()
    } else {
        result
            .core()
            .policy_attributions()
            .iter()
            .map(nah_proto::decision::GuardAttribution::name)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let producer = result
        .evidence_provenance()
        .map_or("none", |provenance| provenance.producer.as_str());
    // A block shows the message the agent would be given.
    let reason = match result.core().verdict() {
        nah_proto::decision::Verdict::Block => crate::hook_adapter::block_message(
            result.core().reason(),
            result.core().policy_attributions(),
        ),
        nah_proto::decision::Verdict::Delegate => result.core().reason().to_owned(),
    };
    let mut output = String::new();
    writeln!(
        output,
        "verdict: {}\ncoverage: {}\nreason: {reason}\npolicy: {attributions}\nproducer: {producer}",
        verdict_name(result.core().verdict()),
        coverage_name(result.core().coverage()),
    )
    .expect("writing to a string succeeds");
    if let Some(rule) = session_rule {
        writeln!(
            output,
            "session: {rule}: session memory decided this call, as the first call of a session"
        )
        .expect("writing to a string succeeds");
    }
    if let Some(rules) = saved {
        writeln!(
            output,
            "saves: {rules}: the hook saves a snapshot of what the call would discard, then runs it, or blocks if the save fails"
        )
        .expect("writing to a string succeeds");
    }
    if !result.failures().is_empty() {
        writeln!(output, "failures:").expect("writing to a string succeeds");
        for failure in result.failures() {
            writeln!(
                output,
                "- {}/{}/{}",
                failure.source(),
                failure.component(),
                failure.code()
            )
            .expect("writing to a string succeeds");
        }
    }
    if let Some(plan) = plan {
        writeln!(output, "engine:").expect("writing to a string succeeds");
        for line in render_engine_plan(plan).lines() {
            writeln!(output, "  {line}").expect("writing to a string succeeds");
        }
    }
    Ok((output, warnings))
}

/// The runtime whose hook this input stands for, and the tool calls that hook
/// would hand the pipeline: the shell command as `Bash`, the agent's tool call
/// through the runtime adapter's own normalization, or code under the tool
/// name of the runtime whose hook analyzes that language.
fn test_tool_call(
    args: &TestArgs,
    cwd: String,
) -> Result<(Runtime, Vec<ToolCallInput>, Option<CodeInput>), TestError> {
    let runtime = args.runtime.unwrap_or(Runtime::Claude);
    if let Some(command) = &args.command {
        let input = ToolCallInput::new(
            SchemaVersion::V1,
            "Bash",
            serde_json::json!({"command": command}),
            cwd,
            None,
        )
        .map_err(|error| format!("invalid test input: {error}"))?;
        return Ok((runtime, vec![input], None));
    }
    if let Some(tool) = &args.tool {
        let arguments = match (&args.args_json, &args.args_file) {
            (Some(arguments), _) => arguments.clone(),
            (None, Some(path)) => std::fs::read_to_string(path).map_err(|error| {
                format!("tool input file {} is unreadable: {error}", path.display())
            })?,
            (None, None) => unreachable!("clap requires tool input with --tool"),
        };
        let arguments = serde_json::from_str::<Value>(&arguments)
            .map_err(|error| format!("invalid tool input JSON: {error}"))?;
        if let Some(language) = code_tool_language(runtime, tool, &arguments) {
            return Err(TestError::Usage(format!(
                "{} sends {tool} code with provenance outside the tool input, which --tool cannot carry; dry-run the code with --source {language}",
                runtime.cli_name()
            )));
        }
        let (input, code) = runtime_tool_call(runtime, tool, arguments, &cwd)
            .map_err(|error| format!("{} rejects this tool call: {error}", runtime.cli_name()))?;
        return Ok((runtime, input, code));
    }
    let language = args.source.expect("clap requires exactly one test input");
    let source = match (&args.code, &args.file) {
        (Some(code), _) => code.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|error| format!("source file {} is unreadable: {error}", path.display()))?,
        (None, None) => unreachable!("clap requires code with --source"),
    };
    let (runtime, tool, code) = match language {
        TestSourceLanguage::Python => (
            Runtime::Hermes,
            "execute_code",
            CodeInput::Python { source },
        ),
        TestSourceLanguage::Js => (
            Runtime::OpenClaw,
            "OpenClawCodeModeExec",
            CodeInput::OpenClawJavaScript {
                source,
                restart_safe: None,
            },
        ),
        TestSourceLanguage::Ts => (
            Runtime::OpenClaw,
            "OpenClawCodeModeExec",
            CodeInput::OpenClawTypeScript {
                source,
                restart_safe: None,
            },
        ),
    };
    let input = ToolCallInput::new(SchemaVersion::V1, tool, code.canonical_input(), cwd, None)
        .map_err(|error| format!("invalid test input: {error}"))?;
    Ok((runtime, vec![input], Some(code)))
}

/// The `--source` language for a code tool whose hook payload identifies it
/// outside the tool input: OpenClaw code mode by its tool kinds. `--tool`
/// cannot supply them, and without them the hook would not analyze the code.
fn code_tool_language(runtime: Runtime, tool: &str, arguments: &Value) -> Option<&'static str> {
    match runtime {
        // Without tool kinds, only a code-mode shaped input is not `NotCode`.
        Runtime::OpenClaw
            if code_input::openclaw(tool, None, None, arguments) != CodeIntake::NotCode =>
        {
            Some("js|ts")
        }
        _ => None,
    }
}

/// Normalizes a tool call exactly as `runtime`'s hook adapter does.
pub(crate) fn runtime_tool_call(
    runtime: Runtime,
    tool: &str,
    arguments: Value,
    cwd: &str,
) -> Result<(Vec<ToolCallInput>, Option<CodeInput>), String> {
    let without_code = |input: ToolCallInput| (vec![input], None);
    let with_code = |(input, code): (ToolCallInput, Option<CodeInput>)| (vec![input], code);
    match runtime {
        Runtime::Antigravity => {
            antigravity_adapter::normalize_call(tool, arguments, cwd).map(without_code)
        }
        Runtime::Claude => {
            hook_adapter::normalize_call(runtime, tool.into(), arguments, cwd.into(), None).map(
                |input| {
                    let code = hook_adapter::powershell_code(runtime, &input);
                    (vec![input], code)
                },
            )
        }
        Runtime::Codex => codex_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Cursor => cursor_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Hermes => hermes_adapter::normalize_call(tool, arguments, cwd).map(with_code),
        Runtime::OpenClaw => openclaw_adapter::normalize_call(tool, arguments, cwd).map(with_code),
        Runtime::OpenCode => {
            opencode_adapter::normalize_call(tool, arguments, cwd).map(without_code)
        }
        Runtime::Pi => pi_adapter::normalize_call(tool, arguments, cwd).map(without_code),
    }
}

const fn coverage_name(coverage: Coverage) -> &'static str {
    match coverage {
        Coverage::Full => "full",
        Coverage::Partial => "partial",
    }
}
