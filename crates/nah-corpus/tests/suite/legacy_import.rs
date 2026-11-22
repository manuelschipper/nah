//! Proves the nah 1.x import keeps every 1.x decision: every corpus row is
//! decided under each 1.x configuration below and under the 2.0 state the
//! import makes of it, and only the intended default changes and the choices
//! the import names in a notice may differ.
//!
//! The 1.x side is a simulation over the same table the import reads: a row
//! blocks under 1.x when it blocks with every rule off (self-protection and
//! the like), or when a rule part it matched replaces a 1.x guard that this
//! configuration runs. The registry subtask proved each part holds exactly
//! its 1.x guard's clauses (`legacy_guards.rs`), so this is the base commit's
//! behaviour over today's matching. Each row runs once with every rule
//! enabled to learn which parts it matches. The fixtures' own guard settings
//! are replaced by each configuration's.
//!
//! Each row is also decided as a runtime that saves decides it (Claude Code):
//! there a part of a rule in `SAVED_RULES` at core saves a copy and lets the
//! call run instead of blocking. That may only drop a block 1.x made with its
//! factory default, never one a 1.x choice asked for. The simulation takes
//! every such part to save, though a forced worktree removal or submodule
//! deinit still blocks: it over-counts the intended change, never a choice.

use std::collections::{BTreeMap, BTreeSet};

use nah_cli::{ImportNotice, SAVED_RULES, import_nap, import_settings};
use nah_corpus::{RowMatches, corpus_dir, load_cases, load_fixtures, row_matches};
use nah_proto::ctx::{GuardLevel, GuardSettings};

/// The 2.0 rules whose part replacing a 1.x guard 1.x shipped off blocks at
/// core by design: outside-workspace deletes (design doc nah-56, "What
/// changes by default"), and stash drops, local ref deletes and history
/// rewrites no reflog or backup keeps, which a snapshot answers where the
/// runtime saves and which block elsewhere (nah-95).
const INTENDED: [(&str, &str); 4] = [
    (
        "machine/outside-workspace-delete",
        "fs-outside-workspace-delete",
    ),
    ("work/stash-drop", "git-ref-delete"),
    ("work/branch-delete", "git-ref-delete"),
    ("work/history-rewrite", "git-history-rewrite"),
];

/// The 2.0 rules with no 1.x guard behind them that block at core by design:
/// a dependency one typing slip from an installed package at its version.
/// 1.x had nothing to carry, so every row they block is a new
/// block under every configuration that leaves their guard on.
const NEW_AT_CORE: [&str; 1] = ["untrusted-code/lookalike-package"];

/// Rows nah-78 moved from block to delegate: a recursive delete inside a
/// working directory no Git repository holds. Both sides of this proof use
/// today's matching, which no longer treats that directory as outside the
/// project, so the comparison cannot see that 1.x blocked them. They are
/// named here, from nah-78's build log, and listed under the notice a user
/// who turned `fs-outside-workspace-delete` on already gets. Later
/// `fs-home.script-*-benign-delegates` rows are not part of this set.
const NON_GIT_PROJECT_DELETES: &[&str] = &[
    "fs-home.script-background-benign-delegates",
    "fs-home.script-stdin-file-benign-delegates",
    "fs-home.script-reader-pipe-benign-delegates",
    "fs-home.script-captured-eval-benign-delegates",
    "fs-home.script-python-stdin-file-benign-delegates",
    "fs-home.script-copied-file-benign-delegates",
    "fs-home.script-background-brace-outer-wait-delegates",
    "fs-home.script-background-brace-unrelated-write-delegates",
    "fs-home.script-background-function-outer-wait-delegates",
    "fs-home.script-background-function-unrelated-write-delegates",
    "fs-home.script-background-if-outer-wait-delegates",
    "fs-home.script-background-if-unrelated-write-delegates",
    "fs-home.script-background-inner-wait-delegates",
    "fs-home.script-foreground-outer-write-delegates",
    "fs-home.script-copied-file-force-benign-delegates",
    "fs-home.script-copied-file-option-end-benign-delegates",
    "fs-home.script-copied-file-preserve-benign-delegates",
];

/// One 1.x configuration: global overrides and a nap.
struct Configuration {
    name: String,
    overrides: BTreeMap<String, bool>,
    napped: Vec<String>,
}

impl Configuration {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            overrides: BTreeMap::new(),
            napped: Vec::new(),
        }
    }

    /// Whether 1.x ran `legacy` under this configuration: a nap or an
    /// explicit off stops it, and otherwise it runs at its factory default.
    fn runs(&self, legacy: &str, default: bool) -> bool {
        if self.napped.iter().any(|name| name == legacy) {
            return false;
        }
        match self.overrides.get(legacy) {
            Some(enabled) => *enabled,
            None => default,
        }
    }

    /// Whether 1.x had `legacy` at its factory default here, so a 2.0 part
    /// of it that blocks at core is the intended default change.
    fn left_alone(&self, legacy: &str) -> bool {
        !self.overrides.contains_key(legacy) && !self.napped.iter().any(|name| name == legacy)
    }
}

/// The 2.0 state the import makes of a configuration, applied as the hook
/// applies it: settings with napped rules paused.
struct Imported {
    settings: GuardSettings,
    notices: Vec<ImportNotice>,
}

fn import(configuration: &Configuration) -> Imported {
    let mut imported = import_settings(&configuration.overrides);
    let nap = import_nap(&configuration.overrides, &configuration.napped);
    for name in &nap.names {
        imported.settings.pause(name);
    }
    let mut notices = imported.notices;
    notices.extend(nap.notices);
    Imported {
        settings: imported.settings,
        notices,
    }
}

fn configurations() -> Vec<Configuration> {
    let mut configurations = vec![Configuration::new("1.x factory defaults")];
    for (legacy, default) in nah_policy::LEGACY_GUARDS {
        let mut on = Configuration::new(format!("{legacy} on"));
        // 1.x stored no enable of a guard that ships on.
        if !default {
            on.overrides.insert(legacy.to_owned(), true);
        }
        let mut off = Configuration::new(format!("{legacy} off"));
        off.overrides.insert(legacy.to_owned(), false);
        let mut napped = Configuration::new(format!("{legacy} napped"));
        napped.napped.push(legacy.to_owned());
        configurations.extend([on, off, napped]);
    }
    configurations
}

#[test]
#[allow(clippy::disallowed_macros)] // Print the full list of changed rows.
fn importing_each_1x_configuration_changes_only_intended_and_named_decisions() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).unwrap_or_else(|errors| panic!("{}", errors.join("\n")));
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let (rows, errors) = row_matches(&cases, &fixtures);
    assert!(
        errors.is_empty(),
        "rows that failed to replay:\n{}",
        errors.join("\n")
    );
    let shipped = nah_policy::ShippedGuards::new();
    let parts = shipped.definitions();
    let default_of = |legacy: &str| {
        nah_policy::LEGACY_GUARDS
            .iter()
            .find(|(name, _)| *name == legacy)
            .map(|(_, default)| *default)
            .expect("a part replaces a 1.x guard")
    };

    let mut changed = BTreeMap::<(String, String), Vec<&str>>::new();
    let mut unexplained = Vec::new();
    for configuration in configurations() {
        let imported = import(&configuration);
        let legacy_blocks = |part: usize| {
            parts[part]
                .replaces
                .is_some_and(|legacy| configuration.runs(legacy, default_of(legacy)))
        };
        let current_blocks = |part: usize| {
            let rule = parts[part].rule;
            imported.settings.rule_level(rule) >= parts[part].applies_at
        };
        for RowMatches {
            id,
            parts: matched,
            blocks_without_rules,
        } in &rows
        {
            if *blocks_without_rules {
                continue;
            }
            let legacy = matched.iter().any(|part| legacy_blocks(*part));
            let current = matched.iter().any(|part| current_blocks(*part));
            let saved = |part: usize| {
                let rule = parts[part].rule;
                SAVED_RULES.contains(&rule)
                    && imported.settings.rule_level(rule) == GuardLevel::Core
            };
            let saving = matched
                .iter()
                .any(|part| current_blocks(*part) && !saved(*part));
            if legacy && current && !saving {
                let chosen = matched.iter().copied().find(|part| {
                    legacy_blocks(*part)
                        && !(saved(*part)
                            && parts[*part]
                                .replaces
                                .is_some_and(|legacy| configuration.left_alone(legacy)))
                });
                match chosen {
                    Some(part) => unexplained.push(format!(
                        "{}: {id} no longer blocks where the runtime saves, though 1.x blocked it for {} by choice",
                        configuration.name,
                        parts[part].replaces.unwrap_or(parts[part].rule)
                    )),
                    None => changed
                        .entry((
                            configuration.name.clone(),
                            "intended: work saves a copy at core where the runtime saves"
                                .to_owned(),
                        ))
                        .or_default()
                        .push(id),
                }
            }
            if legacy == current {
                continue;
            }
            if legacy {
                unexplained.push(format!("{}: {id} no longer blocks", configuration.name));
                continue;
            }
            // Every part that newly blocks must be explained.
            let mut causes = BTreeSet::new();
            for part in matched.iter().copied().filter(|part| current_blocks(*part)) {
                let definition = &parts[part];
                let cause = match definition.replaces {
                    Some(legacy)
                        if INTENDED.contains(&(definition.rule, legacy))
                            && configuration.left_alone(legacy) =>
                    {
                        format!("intended: {} blocks at core", definition.rule)
                    }
                    Some(legacy) => match imported.notices.iter().find(|notice| {
                        notice.rule == definition.rule && notice.legacy.contains(&legacy)
                    }) {
                        Some(notice) => format!("not carried exactly: {}", notice.text),
                        None => {
                            unexplained.push(format!(
                                "{}: {id} now blocks on {} ({legacy}) with no notice",
                                configuration.name, definition.rule
                            ));
                            continue;
                        }
                    },
                    None if NEW_AT_CORE.contains(&definition.rule) => {
                        format!("intended: {} is new in 2.0", definition.rule)
                    }
                    None => {
                        unexplained.push(format!(
                            "{}: {id} now blocks on {}, which is new in 2.0",
                            configuration.name, definition.rule
                        ));
                        continue;
                    }
                };
                causes.insert(cause);
            }
            for cause in causes {
                changed
                    .entry((configuration.name.clone(), cause))
                    .or_default()
                    .push(id);
            }
        }
        // The notice for an explicit `fs-outside-workspace-delete` on. Its
        // legacy list is empty: it describes a matching change, not a choice
        // the rule level failed to carry.
        if let Some(notice) = imported.notices.iter().find(|notice| {
            notice.rule == "machine/outside-workspace-delete" && notice.legacy.is_empty()
        }) {
            let mut lost = Vec::new();
            for id in NON_GIT_PROJECT_DELETES {
                let Some(row) = rows.iter().find(|row| row.id == *id) else {
                    unexplained.push(format!(
                        "{}: {id} is a nah-78 project delete missing from the corpus",
                        configuration.name
                    ));
                    continue;
                };
                let still_blocks =
                    row.blocks_without_rules || row.parts.iter().copied().any(&current_blocks);
                if still_blocks {
                    eprintln!(
                        "{} | still blocks, so not a lost project delete | {id}",
                        configuration.name
                    );
                    continue;
                }
                lost.push(*id);
            }
            if !lost.is_empty() {
                changed
                    .entry((configuration.name.clone(), notice.text.clone()))
                    .or_default()
                    .extend(lost);
            }
        }
    }
    for id in NON_GIT_PROJECT_DELETES {
        assert!(
            rows.iter().any(|row| row.id == *id),
            "{id} disappeared from the corpus"
        );
    }
    let project_deletes = changed.iter().find_map(|((name, cause), ids)| {
        (name == "fs-outside-workspace-delete on" && cause.contains("no Git repository holds"))
            .then_some(ids.as_slice())
    });
    assert!(
        project_deletes.is_some_and(|ids| !ids.is_empty()),
        "the outside-workspace notice listed no nah-78 project deletes"
    );
    assert!(
        unexplained.is_empty(),
        "decisions the import changed without a notice:\n{}",
        unexplained.join("\n")
    );
    // The intended changes recur under most configurations; list each in
    // full once, under the factory defaults, and elsewhere only where it
    // differs.
    let defaults =
        |cause: &str| changed.get(&("1.x factory defaults".to_owned(), cause.to_owned()));
    for ((configuration, cause), ids) in &changed {
        if configuration != "1.x factory defaults"
            && cause.starts_with("intended")
            && Some(ids) == defaults(cause)
        {
            eprintln!(
                "{configuration} | {cause} | the factory defaults' {} rows",
                ids.len()
            );
            continue;
        }
        eprintln!(
            "{configuration} | {cause} | {} rows: {}",
            ids.len(),
            ids.join(", ")
        );
    }
}

/// 2.0 runs no custom guards, so a 1.x nap of one pauses nothing, and the
/// shipped settings stay the factory defaults.
#[test]
fn a_custom_guard_nap_pauses_nothing() {
    let nap = import_nap(&BTreeMap::new(), &["deploy-check".to_owned()]);
    assert!(nap.names.is_empty());
    assert!(nap.notices.is_empty());
    let imported = import_settings(&BTreeMap::new());
    assert_eq!(imported.settings, GuardSettings::default());
    assert!(imported.notices.is_empty());
}
