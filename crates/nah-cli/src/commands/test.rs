//! Renders a human dry run through the live decision pipeline without auditing it.

use std::fmt::Write;

use nah_proto::action::Coverage;
use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde_json::Value;

use super::engine_plan_rendering::render_engine_plan;
use crate::args::{TestArgs, TestSourceLanguage};
use crate::code_input::{self, CodeInput, CodeIntake};
use crate::dispatch::decide_live_for_runtime;
use crate::runtime::Runtime;
use crate::{
    amp_adapter, antigravity_adapter, cline_adapter, codex_adapter, copilot_adapter,
    cursor_adapter, devin_adapter, droid_adapter, hermes_adapter, hook_adapter, kiro_adapter,
    live_state, openclaw_adapter, opencode_adapter, pi_adapter, prime_agent_adapter,
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
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .ok_or_else(|| "current directory is unavailable".to_owned())?;
    let (runtime, input, code) = test_tool_call(args, cwd)?;
    let state = live_state::load().map_err(|error| format!("context failed: {error}"))?;
    let result = decide_live_for_runtime(&input, code.as_ref(), &state, Some(runtime));
    let plan = result.effinterp().map(|analysis| analysis.plan());
    if args.json {
        let exec_request = match (result.observation(), result.guard_evidence()) {
            (Some(observation), Some(Ok(evidence))) => {
                Some(nah_extensions::exec_request(evidence, observation)?)
            }
            _ => None,
        };
        let value = serde_json::json!({
            "schema": "nah/test/v2",
            "v": 2,
            "exec_request": exec_request,
            "producer": result.evidence_provenance().map(|provenance| provenance.producer.as_str()),
            "decision": result.core(),
            "consultations": result.consultations(),
            "failures": result.failures().iter().map(|failure| serde_json::json!({
                "source": failure.source(),
                "component": failure.component(),
                "code": failure.code(),
            })).collect::<Vec<_>>(),
            "plan": plan,
        });
        let output = serde_json::to_string_pretty(&value)
            .map_err(|error| format!("test output failed: {error}"))?;
        return Ok((format!("{output}\n"), result.warnings().to_vec()));
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
    let mut output = String::new();
    writeln!(
        output,
        "verdict: {}\ncoverage: {}\nreason: {}\npolicy: {attributions}\nproducer: {producer}",
        verdict_name(result.core().verdict()),
        coverage_name(result.core().coverage()),
        result.core().reason()
    )
    .expect("writing to a string succeeds");
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
    Ok((output, result.warnings().to_vec()))
}

/// The runtime whose hook this input stands for, and the tool call that hook
/// would hand the pipeline: the shell command as `Bash`, the agent's tool call
/// through the runtime adapter's own normalization, or code under the tool
/// name of the runtime whose hook analyzes that language.
fn test_tool_call(
    args: &TestArgs,
    cwd: String,
) -> Result<(Runtime, ToolCallInput, Option<CodeInput>), TestError> {
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
        return Ok((runtime, input, None));
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
        TestSourceLanguage::Ipython => (
            Runtime::PrimeAgent,
            "ipython",
            CodeInput::Ipython { source },
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
    Ok((runtime, input, Some(code)))
}

/// The `--source` language for a code tool whose hook payload identifies it
/// outside the tool input: Prime Agent's builtin ipython by its tool
/// provenance, OpenClaw code mode by its tool kinds. `--tool` cannot supply
/// either, and without them the hook would not analyze the code.
fn code_tool_language(runtime: Runtime, tool: &str, arguments: &Value) -> Option<&'static str> {
    match runtime {
        Runtime::PrimeAgent if tool == "ipython" => Some("ipython"),
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
fn runtime_tool_call(
    runtime: Runtime,
    tool: &str,
    arguments: Value,
    cwd: &str,
) -> Result<(ToolCallInput, Option<CodeInput>), String> {
    let without_code = |input: ToolCallInput| (input, None);
    match runtime {
        Runtime::Amp => amp_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Antigravity => {
            antigravity_adapter::normalize_call(tool, arguments, cwd).map(without_code)
        }
        Runtime::Claude => {
            hook_adapter::normalize_call(runtime, tool.into(), arguments, cwd.into(), None)
                .map(without_code)
        }
        Runtime::Cline => cline_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Codex => codex_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Copilot => copilot_adapter::normalize_call(tool, arguments, cwd),
        Runtime::Cursor => cursor_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Devin => devin_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Droid => droid_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::Hermes => hermes_adapter::normalize_call(tool, arguments, cwd),
        Runtime::Kiro => kiro_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::OpenClaw => openclaw_adapter::normalize_call(tool, arguments, cwd),
        Runtime::OpenCode => {
            opencode_adapter::normalize_call(tool, arguments, cwd).map(without_code)
        }
        Runtime::Pi => pi_adapter::normalize_call(tool, arguments, cwd).map(without_code),
        Runtime::PrimeAgent => prime_agent_adapter::normalize_call(tool, arguments, cwd),
    }
}

const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Block => "block",
        Verdict::Delegate => "delegate",
    }
}

const fn coverage_name(coverage: Coverage) -> &'static str {
    match coverage {
        Coverage::Full => "full",
        Coverage::Partial => "partial",
    }
}
