//! The one-time import of a nah 1.x configuration into 2.0 settings: the
//! global guard choices of `~/.nah/built-ins.json` and an active nap. Its
//! one table is the shipped parts' `replaces` with the frozen 1.x factory
//! defaults (`nah_policy::LEGACY_GUARDS`).
//!
//! For each rule, the import computes what 1.x decided for each of its parts
//! and picks the rule state that reproduces it. Where two 1.x guards in one
//! rule were set differently, no 2.0 state can, and the rule takes the least
//! protective state that still blocks everything 1.x blocked; each such
//! choice becomes a notice naming the 1.x choice, the rule and the command
//! that changes it.
//!
//! At core, `work/changes-discard`, `work/untracked-clean` and
//! `work/stash-drop` save a copy of what their discards destroy and let them
//! run where the runtime can (`save_then_run`), which is 2.0's intended
//! default change; elsewhere their core parts block as before. A 1.x choice
//! that blocked more of these discards than the defaults (`git-path-discard`
//! or `git-ref-delete` on) imports as the rule enabled whole, which blocks
//! them in every runtime, and a notice says so.

use std::collections::{BTreeMap, BTreeSet};

use nah_proto::ctx::{AbsolutePath, Guard, GuardLevel, GuardSettings, Platform, RuleOverride};

use crate::catalog::{rule_ids, rules_of, shipped_guards};
use crate::shipped_state::{self, ShippedStateError, state_path};

/// What nah 1.x did with one rule part's clauses without a project file,
/// which 2.0 never reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Wanted {
    /// Blocked.
    On,
    /// Not blocked: an explicit disable, or a guard that ships off and was
    /// left alone.
    Off,
}

/// The three behaviours a 2.0 rule can have, from least to most protective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleState {
    /// Disabled, or its guard off.
    Off,
    /// Follows its guard at `core`: the core parts block.
    Core,
    /// Enabled, or its guard strict: every part blocks.
    Whole,
}

impl RuleState {
    const ALL: [Self; 3] = [Self::Off, Self::Core, Self::Whole];

    fn blocks(self, applies_at: GuardLevel) -> bool {
        match self {
            Self::Off => false,
            Self::Core => applies_at == GuardLevel::Core,
            Self::Whole => true,
        }
    }
}

/// One rule part as the import sees it.
struct Part {
    legacy: Option<&'static str>,
    applies_at: GuardLevel,
    wanted: Wanted,
    /// The 1.x operator's own choice for the part's guard, if any.
    chosen: Option<bool>,
}

/// A 1.x choice the import could not carry exactly, on the rule it lands in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportNotice {
    pub rule: &'static str,
    /// The 1.x guards whose parts of this rule the import's choice of rule
    /// state turns on where 1.x left them off; empty for a notice about what
    /// a rule matches.
    pub legacy: Vec<&'static str>,
    pub text: String,
}

/// The 2.0 settings a 1.x global configuration became.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedSettings {
    pub settings: GuardSettings,
    pub notices: Vec<ImportNotice>,
}

/// What a 1.x nap of named guards became: the 2.0 names to pause, empty when
/// nothing can be paused exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedNap {
    pub names: Vec<String>,
    pub notices: Vec<ImportNotice>,
}

/// Converts a nah 1.x `~/.nah/built-ins.json` and an active 1.x nap in
/// place, the first time any 2.0 process loads them, and returns what the
/// conversion reports: the backup and the notices. The notices are also
/// kept for `nah guards`, and the reports wait in the pending file for
/// exactly one decision to record them. The returned lines are for the
/// converting command to print; a decision does not copy them onto its
/// result, or two concurrent first decisions would each record the notice.
/// Without 1.x
/// state it reads two small files and returns nothing. A failure to convert
/// the state file leaves it untouched and is returned; a 1.x nap that cannot
/// be converted stays unconverted, which reads as awake, with a warning.
/// Another Nah process holding the state or the nap past a hook's brief wait
/// leaves the import, or the nap's part of it, for a later call: the state
/// file's as `Contended`, the nap's without a warning.
pub(crate) fn import_once(
    home: &AbsolutePath,
    platform: Platform,
) -> Result<Vec<String>, ShippedStateError> {
    let path = state_path(home, platform);
    let nap_path = crate::nap::nap_path(home, platform);
    if !shipped_state::is_legacy(&path) && !crate::nap::is_legacy(&nap_path) {
        return Ok(vec![]);
    }
    let (overrides, mut warnings) = shipped_state::import_legacy(&path)?;
    let mut notices = Vec::new();
    let mut recorded = Ok(());
    // The notices are recorded before the nap is rewritten, so an import cut
    // short runs again and loses none.
    let converted = crate::nap::import_legacy(&nap_path, |names| {
        let imported = import_nap(&overrides, names);
        let texts = imported
            .notices
            .into_iter()
            .map(|notice| notice.text)
            .collect::<Vec<_>>();
        match shipped_state::record_import_notices(&path, &texts) {
            // Another process holds the state: the nap converts, and records
            // its notices, on a later call.
            Err(ShippedStateError::Contended) => return None,
            result => recorded = result,
        }
        notices = texts;
        Some(imported.names)
    });
    // These never went into the pending file with the conversion itself.
    // Append only them: rewriting the lines already stored would hand the
    // same notice to a second decision after the first had claimed the file.
    let mut extra = Vec::new();
    match converted {
        // A nap another process holds converts on a later call; until then
        // the 1.x nap reads as awake.
        Ok(()) | Err(crate::nap::NapError::Contended) => {}
        Err(error) => extra.push(format!(
            "~/.nah/nap.json: {error}; the nah 1.x nap was not converted and nah remains awake"
        )),
    }
    if let Err(error) = recorded {
        extra.push(format!(
            "{error}; the nah 1.x nap's notices below are not kept for `nah guards`"
        ));
    }
    if !extra.is_empty() {
        let _ = shipped_state::append_pending_reports(&path, &extra);
    }
    warnings.extend(extra);
    warnings.extend(notices);
    Ok(warnings)
}

/// Whether `name` is one of the 48 nah 1.x shipped guards.
pub(crate) fn is_legacy_guard(name: &str) -> bool {
    nah_policy::LEGACY_GUARDS
        .iter()
        .any(|(legacy, _)| *legacy == name)
}

/// Converts 1.x global overrides (1.x guard name to enabled) into 2.0 guard
/// settings and rule overrides. Every name must be a 1.x shipped guard.
pub fn import_settings(overrides: &BTreeMap<String, bool>) -> ImportedSettings {
    let mut settings = GuardSettings::default();
    let mut notices = Vec::new();
    for guard in Guard::ALL.into_iter().filter(|guard| guard.configurable()) {
        let states = rules_of(guard)
            .map(|rule| {
                let parts = parts(rule, overrides);
                let mut state = choose(&parts);
                // At core a snapshot answers these discards where the
                // runtime saves; a part 1.x shipped off and the operator
                // turned on blocked them by choice, which only the rule
                // whole keeps doing.
                if state == RuleState::Core
                    && crate::save_then_run::RULES.contains(&rule)
                    && parts.iter().any(|part| {
                        part.applies_at == GuardLevel::Core
                            && part.chosen == Some(true)
                            && nah_policy::LEGACY_GUARDS
                                .iter()
                                .any(|(legacy, default)| part.legacy == Some(legacy) && !default)
                    })
                {
                    state = RuleState::Whole;
                }
                notices.extend(state_notice(rule, &parts, state, overrides));
                (rule, state)
            })
            .collect::<Vec<_>>();
        // A guard whose every rule takes one state is set as a whole, as a
        // 1.x user who turned all of its guards off or on meant it.
        match states.first().map(|(_, state)| *state) {
            Some(RuleState::Off) if states.iter().all(|(_, s)| *s == RuleState::Off) => {
                settings.set_guard(guard, GuardLevel::Off);
            }
            Some(RuleState::Whole) if states.iter().all(|(_, s)| *s == RuleState::Whole) => {
                settings.set_guard(guard, GuardLevel::Strict);
            }
            _ => {
                for (rule, state) in states {
                    let value = match state {
                        RuleState::Off => Some(RuleOverride::Disabled),
                        RuleState::Core => None,
                        RuleState::Whole => Some(RuleOverride::Enabled),
                    };
                    settings.set_rule(rule, value);
                }
            }
        }
    }
    notices.extend(kept_blocking(&settings));
    if overrides.get(OUTSIDE_WORKSPACE_DELETE) == Some(&true) {
        notices.push(ImportNotice {
            rule: "machine/outside-workspace-delete",
            legacy: vec![],
            text: format!(
                "nah 1.x's `{OUTSIDE_WORKSPACE_DELETE}` on is now the default of `machine/outside-workspace-delete`, with one change: a recursive delete inside a working directory that no Git repository holds no longer blocks, because that directory is now the project"
            ),
        });
    }
    ImportedSettings { settings, notices }
}

/// A notice for each work rule that save-then-run answers at core and that
/// the import runs whole: it blocks the discards that `work` at core would
/// save and run, because a 1.x choice blocked them.
fn kept_blocking(settings: &GuardSettings) -> Vec<ImportNotice> {
    crate::save_then_run::RULES
        .into_iter()
        .filter(|rule| settings.rule_level(rule) == GuardLevel::Strict)
        .map(|rule| {
            let restore = if settings.guard_level(Guard::Work) == GuardLevel::Strict {
                "nah guard set work core".to_owned()
            } else {
                format!("nah rule reset {rule}")
            };
            ImportNotice {
                rule,
                legacy: vec![],
                text: format!(
                    "`{rule}` runs whole, as your nah 1.x choices asked, so it blocks its discards instead of saving a copy and letting them run as `work` at core does in Claude Code. To have them saved: {restore}"
                ),
            }
        })
        .collect()
}

/// The 1.x guard whose rule changed what it matches by design: a working
/// directory outside every Git repository is now the project (epic nah-55,
/// 18 Nov), so a recursive delete inside it is no longer outside.
const OUTSIDE_WORKSPACE_DELETE: &str = "fs-outside-workspace-delete";

/// Converts a 1.x nap of `napped` guards, taken on top of the 1.x
/// `overrides`, into the 2.0 names to pause. A rule is paused only when 1.x
/// would have run none of its parts under any 1.x project file: each part's
/// guard is napped or explicitly off, or the part is new in 2.0 and applies
/// only at strict. A rule that also holds a guard 1.x kept running, or one a
/// 1.x project file could have enabled, stays awake, with a notice where it
/// still blocks for a napped guard. Any other name was a custom guard, which
/// 2.0 does not run, so it pauses nothing.
pub fn import_nap(overrides: &BTreeMap<String, bool>, napped: &[String]) -> ImportedNap {
    let shipped = napped
        .iter()
        .map(String::as_str)
        .filter(|name| is_legacy_guard(name))
        .collect::<BTreeSet<_>>();
    let mut names = BTreeSet::new();
    let mut notices = Vec::new();
    for rule in rule_ids().iter().copied() {
        let napped_here = shipped_guards()
            .parts(rule)
            .filter_map(|part| part.replaces)
            .any(|legacy| shipped.contains(legacy));
        if !napped_here {
            continue;
        }
        let running = shipped_guards()
            .parts(rule)
            .filter(|part| match part.replaces {
                Some(legacy) => !shipped.contains(legacy) && overrides.get(legacy) != Some(&false),
                None => part.applies_at == GuardLevel::Core,
            })
            .map(|part| part.replaces.unwrap_or(part.rule))
            .collect::<BTreeSet<_>>();
        if running.is_empty() {
            names.insert(rule.to_owned());
            continue;
        }
        let awake = choose(&parts(rule, overrides));
        let kept = shipped_guards()
            .parts(rule)
            .filter(|part| awake.blocks(part.applies_at))
            .filter_map(|part| part.replaces)
            .filter(|legacy| shipped.contains(legacy))
            .collect::<BTreeSet<_>>();
        if kept.is_empty() {
            continue;
        }
        notices.push(ImportNotice {
            rule,
            legacy: kept.iter().copied().collect(),
            text: format!(
                "the nah 1.x nap of {} cannot pause `{rule}` alone: it also holds {}, which the nap did not pause; `{rule}` stays awake. To pause the whole rule: nah nap {rule}",
                code_list(&kept),
                code_list(&running)
            ),
        });
    }
    ImportedNap {
        names: names.into_iter().collect(),
        notices,
    }
}

/// The parts of `rule` with what 1.x did with each under `overrides`. A
/// part with no 1.x guard, or whose guard was left alone, gets its 2.0
/// factory default, which is the 1.x default except for the intended
/// default changes.
fn parts(rule: &str, overrides: &BTreeMap<String, bool>) -> Vec<Part> {
    shipped_guards()
        .parts(rule)
        .map(|part| {
            let chosen = part
                .replaces
                .and_then(|legacy| overrides.get(legacy))
                .copied();
            let wanted = match chosen {
                Some(true) => Wanted::On,
                Some(false) => Wanted::Off,
                None if part.applies_at == GuardLevel::Core => Wanted::On,
                None => Wanted::Off,
            };
            Part {
                legacy: part.replaces,
                applies_at: part.applies_at,
                wanted,
                chosen,
            }
        })
        .collect()
}

/// The rule state for `parts`: one that reproduces 1.x, or failing that,
/// the least protective one that blocks everything 1.x blocked; `Whole`
/// always does. A rule whose parts all apply at strict reproduces 1.x both
/// off and following its guard; it follows its guard unless the 1.x operator
/// turned every one of its guards off, so a later `strict` setting reaches
/// it as it reaches the rest of the guard.
fn choose(parts: &[Part]) -> RuleState {
    let exact = |state: RuleState| {
        parts
            .iter()
            .all(|part| state.blocks(part.applies_at) == (part.wanted == Wanted::On))
    };
    let covers = |state: RuleState| {
        parts
            .iter()
            .all(|part| part.wanted == Wanted::Off || state.blocks(part.applies_at))
    };
    let preferred = if parts.iter().all(|part| part.chosen == Some(false)) {
        [RuleState::Off, RuleState::Core, RuleState::Whole]
    } else {
        [RuleState::Core, RuleState::Off, RuleState::Whole]
    };
    preferred
        .into_iter()
        .find(|state| exact(*state))
        .or_else(|| RuleState::ALL.into_iter().find(|state| covers(*state)))
        .expect("a rule that runs whole blocks everything")
}

/// The notice for a rule state that blocks for parts 1.x did not block, or
/// none when it reproduces 1.x.
fn state_notice(
    rule: &'static str,
    parts: &[Part],
    state: RuleState,
    overrides: &BTreeMap<String, bool>,
) -> Option<ImportNotice> {
    let widened = parts
        .iter()
        .filter(|part| state.blocks(part.applies_at) && part.wanted == Wanted::Off)
        .filter_map(|part| part.legacy)
        .collect::<BTreeSet<_>>();
    if widened.is_empty() {
        return None;
    }
    let choices = parts
        .iter()
        .filter_map(|part| part.legacy)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|legacy| {
            let choice = match overrides.get(legacy) {
                Some(true) => "on",
                Some(false) => "off",
                None => "at its default",
            };
            format!("`{legacy}` {choice}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(ImportNotice {
        rule,
        legacy: widened.iter().copied().collect(),
        text: format!(
            "`{rule}` holds nah 1.x guards set differently ({choices}), so it cannot carry them exactly and now also blocks for {}. To turn the rule off: nah rule disable {rule}",
            code_list(&widened)
        ),
    })
}

fn code_list(names: &BTreeSet<&str>) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored form the operator reads back: a guard whose every 1.x
    /// guard was turned off is set off as a whole, a single rule carries its
    /// choice as an override, and a rule that cannot carry one keeps
    /// following its guard and names the choice. Decisions under these
    /// settings are proven against 1.x by the corpus (`nah-corpus`,
    /// `legacy_import`).
    #[test]
    fn settings_set_whole_guards_and_rule_overrides() {
        assert_eq!(
            import_settings(&BTreeMap::new()),
            ImportedSettings {
                settings: GuardSettings::default(),
                notices: vec![],
            }
        );

        let secrets = rules_of(Guard::Secrets)
            .flat_map(|rule| shipped_guards().parts(rule))
            .filter_map(|part| part.replaces)
            .map(|legacy| (legacy.to_owned(), false))
            .collect::<BTreeMap<_, _>>();
        let imported = import_settings(&secrets);
        assert_eq!(
            imported.settings.guard_level(Guard::Secrets),
            GuardLevel::Off
        );
        assert!(
            imported
                .settings
                .rules()
                .keys()
                .all(|rule| !rule.starts_with("secrets/"))
        );

        let overrides = BTreeMap::from([
            ("db-destroy".to_owned(), true),
            ("git-hard-reset".to_owned(), false),
        ]);
        let imported = import_settings(&overrides);
        assert_eq!(
            imported.settings.rules(),
            &BTreeMap::from([(
                "infrastructure/database-drop".to_owned(),
                RuleOverride::Enabled
            )])
        );
        assert_eq!(
            imported
                .notices
                .iter()
                .map(|notice| (notice.rule, notice.legacy.as_slice()))
                .collect::<Vec<_>>(),
            [("work/changes-discard", ["git-hard-reset"].as_slice())]
        );

        // A 1.x choice to block path discards too keeps the rule blocking
        // where `work` at core would save and run them, and says so.
        let imported = import_settings(&BTreeMap::from([("git-path-discard".to_owned(), true)]));
        assert_eq!(
            imported.settings.rule_override("work/changes-discard"),
            Some(RuleOverride::Enabled)
        );
        assert_eq!(
            imported
                .notices
                .iter()
                .map(|notice| notice.rule)
                .collect::<Vec<_>>(),
            ["work/changes-discard"]
        );
    }

    /// A 1.x choice of one guard that used to share a rule sets only that
    /// rule. The sibling keeps the protection 1.x left it with.
    #[test]
    fn a_split_1x_choice_does_not_widen_onto_its_sibling() {
        let level = |settings: &GuardSettings, rule: &str| settings.rule_level(rule);
        let off = |legacy: &str| import_settings(&BTreeMap::from([(legacy.to_owned(), false)]));
        let on = |legacy: &str| import_settings(&BTreeMap::from([(legacy.to_owned(), true)]));

        let forkbomb = off("fs-forkbomb");
        assert!(forkbomb.notices.is_empty());
        assert_eq!(
            level(&forkbomb.settings, "machine/fork-bomb"),
            GuardLevel::Off
        );
        assert_eq!(
            level(&forkbomb.settings, "machine/system-halt"),
            GuardLevel::Core
        );

        let home = off("fs-home");
        assert!(home.notices.is_empty());
        assert_eq!(
            level(&home.settings, "machine/home-folder-modify"),
            GuardLevel::Off
        );
        assert_eq!(
            level(&home.settings, "machine/outside-workspace-delete"),
            GuardLevel::Core
        );

        let outside = off("fs-outside-workspace-delete");
        assert!(outside.notices.is_empty());
        assert_eq!(
            level(&outside.settings, "machine/outside-workspace-delete"),
            GuardLevel::Off
        );
        assert_eq!(
            level(&outside.settings, "machine/home-folder-modify"),
            GuardLevel::Core
        );

        let snapshot = on("storage-snapshot-delete");
        assert!(snapshot.notices.is_empty());
        assert_eq!(
            level(&snapshot.settings, "infrastructure/snapshot-delete"),
            GuardLevel::Strict
        );
        assert_eq!(
            level(&snapshot.settings, "infrastructure/cloud-storage-delete"),
            GuardLevel::Core
        );

        let resource = on("git-remote-resource-delete");
        assert!(resource.notices.is_empty());
        assert_eq!(
            level(&resource.settings, "remote-code/hosted-resource-delete"),
            GuardLevel::Strict
        );
        assert_eq!(
            level(&resource.settings, "remote-code/repo-delete"),
            GuardLevel::Core
        );

        let nap = import_nap(&BTreeMap::new(), &["fs-forkbomb".into()]);
        assert_eq!(nap.names, ["machine/fork-bomb"]);
        assert!(nap.notices.is_empty());
    }
}
