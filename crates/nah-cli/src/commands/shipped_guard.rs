//! Shipped-guard enablement mutations invoked only by explicit human CLI commands.

use std::fmt::Write;

use crate::catalog::{shipped_defaults, shipped_guard_docs, shipped_guards};
use crate::live_state::{home, host_platform};
use crate::shipped_state::{ShippedState, reset, set_enabled, state_path};

use super::{GuardEntry, GuardStatus, GuardTarget};

pub(crate) fn set_shipped_guard(name: &str, enabled: bool) -> Result<(), String> {
    if !shipped_guards().contains(&name) {
        return Err(format!("guard `{name}` was not found"));
    }
    let platform = host_platform();
    let home = home(platform)?;
    set_enabled(
        &state_path(&home, platform),
        &shipped_defaults(),
        name,
        enabled,
    )
    .map_err(|error| error.to_string())
}

pub(crate) fn reset_shipped_guard(name: &str) -> Result<(), String> {
    if !shipped_guards().contains(&name) {
        return Err(format!("guard `{name}` was not found"));
    }
    let platform = host_platform();
    let home = home(platform)?;
    reset(&state_path(&home, platform), &shipped_defaults(), name)
        .map_err(|error| error.to_string())
}

pub(crate) fn list_shipped_guards(docs: bool) -> Result<String, String> {
    let entries = shipped_guard_entries()?;
    let mut output = if docs {
        "Built-in:\n\nExamples are non-exhaustive. Inspect them with `nah test <command>`; do not execute them directly.\n\n".to_owned()
    } else {
        "Built-in:\n".to_owned()
    };
    for guard in entries {
        let enabled = guard.status == GuardStatus::Enabled;
        if docs {
            let examples = guard
                .examples
                .iter()
                .map(|example| format!("- `{example}`"))
                .collect::<Vec<_>>()
                .join("\n");
            writeln!(
                output,
                "# {}\n\nStatus: {}\n\nDefault: {}\n\nFamily: {}\n\n{}\n\nExamples nah blocks:\n\n{}\n\nIf disabled, matching calls are no longer blocked by this guard and fall through to other guards or delegation.\n\nDisable: `nah guard disable {}`\nEnable: `nah guard enable {}`\n",
                guard.target.name(),
                if enabled { "enabled" } else { "disabled" },
                if guard.default_enabled == Some(true) {
                    "enabled"
                } else {
                    "disabled"
                },
                guard.family.map_or("custom", |family| family.filter_name()),
                guard.behavior.as_deref().unwrap_or_default(),
                examples,
                guard.target.name(),
                guard.target.name(),
            )
            .expect("writing to a string succeeds");
        } else {
            writeln!(
                output,
                "- [{}] {} (default {})",
                if enabled { "x" } else { " " },
                guard.target.name(),
                if guard.default_enabled == Some(true) {
                    "on"
                } else {
                    "off"
                }
            )
            .expect("writing to a string succeeds");
        }
    }
    Ok(output)
}

pub(crate) fn shipped_guard_entries() -> Result<Vec<GuardEntry>, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let state = ShippedState::load(&state_path(&home, platform), &shipped_defaults())
        .map_err(|error| error.to_string())?;
    Ok(shipped_guard_docs()
        .into_iter()
        .map(|guard| GuardEntry {
            target: GuardTarget::BuiltIn {
                name: guard.name.to_owned(),
            },
            family: Some(guard.family),
            default_enabled: Some(guard.default_enabled),
            operator_override: state.operator_override(guard.name),
            path: None,
            status: if state.is_enabled(guard.name, guard.default_enabled) {
                GuardStatus::Enabled
            } else {
                GuardStatus::Disabled
            },
            behavior: Some(guard.behavior.to_owned()),
            examples: guard
                .examples
                .iter()
                .map(|example| (*example).into())
                .collect(),
            match_programs: vec![],
            current_hash: None,
        })
        .collect())
}
