//! Renders a human dry run through the live decision pipeline without auditing it.

use std::fmt::Write;

use nah_proto::action::Coverage;
use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;

use crate::live_state;
use crate::pipeline::decide_live;

pub(crate) fn test_command(command: &str, json: bool) -> Result<(String, Vec<String>), String> {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .ok_or_else(|| "current directory is unavailable".to_owned())?;
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": command}),
        cwd,
        None,
    )
    .map_err(|error| format!("invalid test command: {error}"))?;
    let state = live_state::load().map_err(|error| format!("context failed: {error}"))?;
    let result = decide_live(&input, &state);
    if json {
        let exec_request = result
            .observation()
            .map(|observation| nah_extensions::exec_request(result.action_stream(), observation))
            .transpose()
            .map_err(|error| format!("extension request failed: {error}"))?;
        let value = serde_json::json!({
            "schema": "nah/test/v1",
            "v": 1,
            "exec_request": exec_request,
            "decision": result.core(),
            "consultations": result.consultations(),
            "failures": result.failures().iter().map(|failure| serde_json::json!({
                "source": failure.source(),
                "component": failure.component(),
                "code": failure.code(),
            })).collect::<Vec<_>>(),
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
    let mut output = String::new();
    writeln!(
        output,
        "verdict: {}\ncoverage: {}\nreason: {}\npolicy: {attributions}\neffects:",
        verdict_name(result.core().verdict()),
        coverage_name(result.core().coverage()),
        result.core().reason()
    )
    .expect("writing to a string succeeds");
    for effect in result.action_stream().effects() {
        let kind = serde_json::to_string(effect.kind()).expect("effect contracts serialize");
        writeln!(output, "- {} {kind}", effect.id().as_str())
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
    Ok((output, result.warnings().to_vec()))
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
