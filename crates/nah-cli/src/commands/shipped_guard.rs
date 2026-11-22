//! Shipped guard settings and rule overrides, mutated only by explicit human
//! CLI commands.

use std::fmt::Write;

use nah_proto::ctx::{Guard, GuardLevel, RuleOverride};

use crate::catalog::{rule_ids, rule_span, rules_of};
use crate::guard_knowledge::{guard_record, knowledge_for_rule, tui_examples};
use crate::legacy_import::import_once;
use crate::live_state::{self, host_platform};
use crate::shipped_state::{
    ShippedState, ShippedStateError, import_notices, set_guard_level, set_rule_override, state_path,
};

use super::{GuardEntry, GuardStatus, GuardTarget, RuleState};

/// Sets one guard. `command` names the change for the operator-terminal
/// error a change that lowers protection gets outside one.
pub(crate) fn set_shipped_guard(
    command: &str,
    guard: Guard,
    level: GuardLevel,
) -> Result<Vec<String>, String> {
    let platform = host_platform();
    let home = live_state::home(platform)?;
    let mut warnings = import_once(&home, platform).map_err(|error| error.to_string())?;
    let operator = crate::dispatch::require_operator_terminal(command);
    warnings.extend(
        set_guard_level(
            &state_path(&home, platform),
            rule_ids(),
            operator.is_ok(),
            guard,
            level,
        )
        .map_err(|error| operator_error(error, operator))?,
    );
    Ok(warnings)
}

/// Sets or removes one rule override, as [`set_shipped_guard`] sets a guard.
pub(crate) fn set_shipped_rule(
    command: &str,
    rule: &str,
    value: Option<RuleOverride>,
) -> Result<Vec<String>, String> {
    let platform = host_platform();
    let home = live_state::home(platform)?;
    let mut warnings = import_once(&home, platform).map_err(|error| error.to_string())?;
    let operator = crate::dispatch::require_operator_terminal(command);
    warnings.extend(
        set_rule_override(
            &state_path(&home, platform),
            rule_ids(),
            operator.is_ok(),
            rule,
            value,
        )
        .map_err(|error| operator_error(error, operator))?,
    );
    Ok(warnings)
}

fn operator_error(error: ShippedStateError, operator: Result<(), String>) -> String {
    match (error, operator) {
        (ShippedStateError::OperatorRequired, Err(terminal)) => terminal,
        (error, _) => error.to_string(),
    }
}

/// When a rule's parts apply, in the words `nah guards` and the guard
/// reference use.
pub(crate) fn applies_at(rule: &str) -> &'static str {
    match rule_span(rule) {
        (GuardLevel::Strict, _) => "strict",
        (_, GuardLevel::Strict) => "core; strict adds more",
        _ => "core",
    }
}

pub(crate) fn list_shipped_guards(docs: bool) -> Result<(String, Vec<String>), String> {
    let (entries, diagnostics) = shipped_guard_entries()?;
    let mut output = String::new();
    if !docs {
        let platform = host_platform();
        let notices = import_notices(&state_path(&live_state::home(platform)?, platform))
            .map_err(|error| error.to_string())?;
        if let Some(notices) = notices {
            output.push_str("The nah 1.x import could not carry these choices exactly:\n");
            for notice in notices.lines() {
                writeln!(output, "- {notice}").expect("writing to a string succeeds");
            }
            output.push('\n');
        }
    }
    output.push_str(if docs {
        "Built-in:\n\nExamples are non-exhaustive. Inspect them with `nah test <command>`; do not execute them directly.\n\n"
    } else {
        "Built-in:\n"
    });
    let settings = super::entry_settings(&entries);
    for entry in &entries {
        match &entry.target {
            GuardTarget::Guard { guard } if docs => writeln!(
                output,
                "# {}: {}\n\n{}\n",
                guard.name(),
                setting_name(*guard, entry.setting),
                guard_record(*guard).protects.trim(),
            ),
            GuardTarget::Guard { guard } => {
                writeln!(output, "{}: {}", guard.name(), setting_name(*guard, entry.setting))
            }
            GuardTarget::Rule { rule } => {
                let state = RuleState::of(rule, settings.rule_level(rule));
                let override_note = entry
                    .rule_override
                    .map(|value| format!(" ({})", value.name()))
                    .unwrap_or_default();
                if docs {
                    let examples = tui_examples(knowledge_for_rule(rule), host_platform())
                        .into_iter()
                        .map(|(command, strict)| {
                            format!("- `{command}`{}", if strict { " (at strict)" } else { "" })
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    let strict_adds = knowledge_for_rule(rule)
                        .strict_adds
                        .as_deref()
                        .map(|text| format!(" {}", text.trim()))
                        .unwrap_or_default();
                    writeln!(
                        output,
                        "## {rule}\n\nStatus: {}{override_note}\n\nApplies at: {}\n\n{}{strict_adds}\n\nExamples nah blocks:\n\n{examples}\n\nIf disabled, matching calls are no longer blocked by this rule and fall through to other rules or delegation.\n\nDisable: `nah rule disable {rule}`\nEnable: `nah rule enable {rule}`\nFollow the guard again: `nah rule reset {rule}`\n",
                        state_name(state),
                        applies_at(rule),
                        entry.behavior.as_deref().unwrap_or_default(),
                    )
                } else {
                    writeln!(output, "- {} {rule}{override_note}", state.marker())
                }
            }
        }
        .expect("writing to a string succeeds");
    }
    // The catalog ends with the nah 1.x custom guards that no longer run.
    if !docs {
        let platform = host_platform();
        if let Some(stopped) = crate::legacy_custom_guards::StoppedCustomGuards::find(
            &live_state::home(platform)?,
            platform,
        ) {
            output.push('\n');
            output.push_str(&stopped.notice());
        }
    }
    Ok((output, diagnostics))
}

fn setting_name(guard: Guard, setting: GuardLevel) -> &'static str {
    if guard.configurable() {
        setting.name()
    } else {
        "always on"
    }
}

const fn state_name(state: RuleState) -> &'static str {
    match state {
        RuleState::On => "on",
        RuleState::CoreOnly => "on at core; its strict parts are off",
        RuleState::Off => "off",
    }
}

/// Every guard, in catalog order, each followed by its rules.
pub(crate) fn shipped_guard_entries() -> Result<(Vec<GuardEntry>, Vec<String>), String> {
    let platform = host_platform();
    let home = live_state::home(platform)?;
    let mut diagnostics = import_once(&home, platform).map_err(|error| error.to_string())?;
    let (state, loaded) = ShippedState::load(&state_path(&home, platform), rule_ids())
        .map_err(|error| error.to_string())?;
    diagnostics.extend(loaded);
    let settings = state.settings();
    let entry = |target, setting, rule_override, enabled: bool| GuardEntry {
        target,
        setting,
        rule_override,
        status: if enabled {
            GuardStatus::Enabled
        } else {
            GuardStatus::Disabled
        },
        behavior: None,
        examples: vec![],
    };
    let mut entries = Vec::new();
    for guard in Guard::ALL {
        let setting = settings.guard_level(guard);
        entries.push(entry(
            GuardTarget::Guard { guard },
            setting,
            None,
            setting != GuardLevel::Off,
        ));
        for rule in rules_of(guard) {
            let knowledge = knowledge_for_rule(rule);
            entries.push(GuardEntry {
                behavior: Some(knowledge.summary.clone()),
                examples: tui_examples(knowledge, platform)
                    .into_iter()
                    .map(|(command, strict)| {
                        if strict {
                            format!("{command}  (at strict)")
                        } else {
                            command.to_owned()
                        }
                    })
                    .collect(),
                ..entry(
                    GuardTarget::Rule {
                        rule: rule.to_owned(),
                    },
                    GuardLevel::Core,
                    settings.rule_override(rule),
                    RuleState::of(rule, settings.rule_level(rule)) != RuleState::Off,
                )
            });
        }
    }
    Ok((entries, diagnostics))
}
