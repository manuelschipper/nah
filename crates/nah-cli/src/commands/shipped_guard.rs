//! Shipped-guard enablement mutations invoked only by explicit human CLI commands.

use std::fmt::Write;

use crate::catalog::{
    ResolvedShippedGuard, resolve_shipped_guard, shipped_defaults, shipped_guard_aliases,
    shipped_guard_docs,
};
use crate::live_state::{home, host_platform};
use crate::shipped_state::{ShippedState, reset, set_enabled, state_path};

use super::{GuardEntry, GuardMutation, GuardStatus, GuardTarget};

pub(crate) fn set_shipped_guard(name: &str, enabled: bool) -> Result<GuardMutation, String> {
    let resolved =
        resolve_shipped_guard(name).ok_or_else(|| format!("guard `{name}` was not found"))?;
    let platform = host_platform();
    let home = home(platform)?;
    set_shipped_guard_at(
        &state_path(&home, platform),
        &shipped_defaults(),
        shipped_guard_aliases(),
        name,
        resolved,
        enabled,
    )
}

pub(crate) fn reset_shipped_guard(name: &str) -> Result<GuardMutation, String> {
    let resolved =
        resolve_shipped_guard(name).ok_or_else(|| format!("guard `{name}` was not found"))?;
    let platform = host_platform();
    let home = home(platform)?;
    reset_shipped_guard_at(
        &state_path(&home, platform),
        &shipped_defaults(),
        shipped_guard_aliases(),
        name,
        resolved,
    )
}

fn set_shipped_guard_at(
    path: &std::path::Path,
    defaults: &[(&str, bool)],
    aliases: &[(&str, &str)],
    requested_name: &str,
    resolved: ResolvedShippedGuard<'_>,
    enabled: bool,
) -> Result<GuardMutation, String> {
    let warnings = set_enabled(path, defaults, aliases, resolved.canonical_name, enabled)
        .map_err(|error| error.to_string())?;
    Ok(shipped_guard_mutation(requested_name, resolved, warnings))
}

fn reset_shipped_guard_at(
    path: &std::path::Path,
    defaults: &[(&str, bool)],
    aliases: &[(&str, &str)],
    requested_name: &str,
    resolved: ResolvedShippedGuard<'_>,
) -> Result<GuardMutation, String> {
    let warnings = reset(path, defaults, aliases, resolved.canonical_name)
        .map_err(|error| error.to_string())?;
    Ok(shipped_guard_mutation(requested_name, resolved, warnings))
}

fn shipped_guard_mutation(
    requested_name: &str,
    resolved: ResolvedShippedGuard<'_>,
    mut warnings: Vec<String>,
) -> GuardMutation {
    if resolved.renamed {
        warnings.push(format!(
            "built-in guard `{requested_name}` was renamed to `{}`",
            resolved.canonical_name
        ));
    }
    warnings.sort();
    warnings.dedup();
    GuardMutation {
        canonical_name: resolved.canonical_name.to_owned(),
        warnings,
    }
}

pub(crate) fn list_shipped_guards(docs: bool) -> Result<(String, Vec<String>), String> {
    let (entries, diagnostics) = shipped_guard_entries()?;
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
                guard.family.map_or("custom", |family| family.name()),
                guard.behavior.as_deref().unwrap_or_default(),
                examples,
                guard.target.name(),
                guard.target.name(),
            )
            .expect("writing to a string succeeds");
        } else {
            writeln!(
                output,
                "- [{}] {}",
                if enabled { "x" } else { " " },
                guard.target.name()
            )
            .expect("writing to a string succeeds");
        }
    }
    Ok((output, diagnostics))
}

pub(crate) fn shipped_guard_entries() -> Result<(Vec<GuardEntry>, Vec<String>), String> {
    let platform = host_platform();
    let home = home(platform)?;
    let (state, diagnostics) = ShippedState::load(
        &state_path(&home, platform),
        &shipped_defaults(),
        shipped_guard_aliases(),
    )
    .map_err(|error| error.to_string())?;
    let entries = shipped_guard_docs()
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
        .collect();
    Ok((entries, diagnostics))
}

#[cfg(test)]
mod tests {
    use crate::catalog::resolve_shipped_guard_from;

    use super::*;

    #[test]
    fn synthetic_alias_mutations_report_and_save_the_canonical_name() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [("current", true)];
        let aliases = [("old-current", "current")];
        let canonical_names = ["current"];
        let resolved = resolve_shipped_guard_from(&canonical_names, &aliases, "old-current")
            .expect("synthetic alias resolves");

        let mutation =
            set_shipped_guard_at(&path, &defaults, &aliases, "old-current", resolved, false)
                .unwrap();
        assert_eq!(mutation.canonical_name, "current");
        assert_eq!(mutation.warnings.len(), 1);
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["overrides"], serde_json::json!({"current": false}));

        let reset =
            reset_shipped_guard_at(&path, &defaults, &aliases, "old-current", resolved).unwrap();
        assert_eq!(reset.canonical_name, "current");
        assert_eq!(reset.warnings.len(), 1);
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["overrides"], serde_json::json!({}));
    }
}
