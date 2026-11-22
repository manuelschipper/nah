//! Built-in guard knowledge: one reviewed record per guard in
//! `crates/nah-cli/guards/<guard>.toml` and one per shipped rule in
//! `crates/nah-cli/guards/<guard>/<rule>.toml`. The records are the single
//! source of each guard's and rule's text and examples in `nah tui` and
//! `nah docs guards`, and of their sections of `docs/guard-reference.md`.
//!
//! An example names a `corpus/*.jsonl` row by id instead of copying its
//! command, with a reviewed reason. `blocks` rows block with the rule, and
//! `strict` marks those only a strict part blocks; `passes` rows delegate,
//! with every part running unless their cause is `strict-only`. The
//! `nah-corpus` suite holds every example to its row and to that level. The commands of the referenced rows are generated into
//! `guards/corpus-rows.json`, and the reference page is generated from the
//! records; the tests below fail when either file is stale and name the command
//! that regenerates both.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use nah_proto::ctx::{Guard, GuardLevel, Platform};
use serde::{Deserialize, Deserializer};

/// One guard's reviewed record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardRecord {
    /// One line naming what the guard keeps the agent from doing.
    pub protects: String,
    /// What the guard covers and where it meets its neighbors, in Markdown.
    pub description: String,
    /// What Nah does when one of the guard's rules matches.
    pub response: String,
    /// What each setting does; absent for `self`, which has none.
    pub settings: Option<GuardSettingsText>,
}

/// What each of a guard's settings runs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSettingsText {
    pub off: String,
    pub core: String,
    pub strict: String,
}

impl GuardSettingsText {
    /// The text of `level`, in `off`, `core`, `strict` order.
    pub fn of(&self, level: GuardLevel) -> &str {
        match level {
            GuardLevel::Off => &self.off,
            GuardLevel::Core => &self.core,
            GuardLevel::Strict => &self.strict,
        }
    }
}

/// One shipped rule's reviewed knowledge record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardKnowledge {
    /// The rule ID, `guard/rule`, taken from the record's path.
    #[serde(skip)]
    pub name: &'static str,
    /// One line shown beside the rule in `nah tui` and `nah docs guards`.
    pub summary: String,
    /// What the rule stops and why, in Markdown.
    pub description: String,
    /// What Nah cannot establish for this rule, in Markdown.
    pub limits: String,
    /// Why the rule applies where it does, and how it meets neighboring
    /// rules.
    pub applies_at: String,
    /// What strict adds, for a rule with parts at core and at strict; absent
    /// for every other rule.
    pub strict_adds: Option<String>,
    /// The nah 1.x guards whose clauses the rule's parts hold, as the
    /// catalog's `replaces` names them; empty for a rule new in 2.0.
    pub replaces: Vec<String>,
    /// Block feedback offers only `nah nap <rule>`, never
    /// `nah rule disable <rule>`: the rule has no routine legitimate use,
    /// so turning it off is never the fix for one blocked call.
    #[serde(default)]
    pub nap_only: bool,
    pub blocks: Vec<BlockExample>,
    pub passes: Vec<PassExample>,
}

/// A corpus row this rule blocks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockExample {
    pub row: String,
    /// The detail of the command that makes the rule match.
    pub why: String,
    /// The hosts whose `nah tui` and `nah docs guards` list this example:
    /// `tui = true` for every host, or a list such as `tui = ["linux"]`.
    #[serde(default, deserialize_with = "tui_hosts")]
    pub tui: Vec<Platform>,
    /// Only a part that applies at strict matches, so the row blocks at strict
    /// or with the rule enabled but not at core. Set only in a rule that also
    /// has core parts.
    #[serde(default)]
    pub strict: bool,
}

/// A corpus row that delegates with this rule at the level its cause names:
/// at core for `strict-only`, and with every part running otherwise.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassExample {
    pub row: String,
    /// The detail of the command that keeps the rule from matching.
    pub why: String,
    pub cause: PassCause,
}

/// Why a pass example does not match its rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PassCause {
    /// The call is clearly outside the rule's scope.
    OutOfScope,
    /// Nah cannot establish what the call does, and its decision reports
    /// partial coverage.
    Unresolved,
    /// The rule's core parts leave the call alone, and a part that applies
    /// only at strict blocks it: it delegates at core and blocks at strict or
    /// with the rule enabled.
    StrictOnly,
}

fn tui_hosts<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Platform>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Tui {
        All(bool),
        Hosts(Vec<Platform>),
    }
    match Tui::deserialize(deserializer)? {
        Tui::All(true) => Ok(vec![Platform::Linux, Platform::Macos, Platform::Windows]),
        Tui::Hosts(hosts) if !hosts.is_empty() => Ok(hosts),
        _ => Err(serde::de::Error::custom(
            "`tui` is `true` or a nonempty host list; omit it to keep the example out of the TUI",
        )),
    }
}

macro_rules! records {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../guards/", $name, ".toml")))),*]
    };
}

const RECORDS: &[(&str, &str)] = records![
    "exfiltration/linked-tree-export",
    "exfiltration/lookalike-host-request",
    "exfiltration/secret-upload",
    "infrastructure/cloud-resources-destroy",
    "infrastructure/cloud-storage-delete",
    "infrastructure/cluster-delete",
    "infrastructure/container-prune",
    "infrastructure/database-drop",
    "infrastructure/snapshot-delete",
    "infrastructure/vault-secret-delete",
    "machine/disk-overwrite",
    "machine/fork-bomb",
    "machine/home-folder-modify",
    "machine/outside-workspace-delete",
    "machine/permissions-weaken",
    "machine/system-files-modify",
    "machine/system-halt",
    "persistence/auth-files-modify",
    "persistence/git-hook-write",
    "persistence/shell-profile-write",
    "persistence/startup-item-add",
    "remote-code/force-push",
    "remote-code/hosted-resource-delete",
    "remote-code/package-unpublish",
    "remote-code/protected-branch-push",
    "remote-code/repo-delete",
    "secrets/env-files-read",
    "secrets/key-files-access",
    "secrets/vault-secrets-read",
    "untrusted-code/hidden-payload-run",
    "untrusted-code/lookalike-package",
    "untrusted-code/remote-script-run",
    "untrusted-code/reverse-shell-open",
    "work/branch-delete",
    "work/changes-discard",
    "work/files-delete",
    "work/git-internals-modify",
    "work/history-rewrite",
    "work/stash-drop",
    "work/untracked-clean",
];

const GUARD_RECORDS: [&str; 9] = [
    include_str!("../guards/work.toml"),
    include_str!("../guards/machine.toml"),
    include_str!("../guards/remote-code.toml"),
    include_str!("../guards/infrastructure.toml"),
    include_str!("../guards/secrets.toml"),
    include_str!("../guards/exfiltration.toml"),
    include_str!("../guards/untrusted-code.toml"),
    include_str!("../guards/persistence.toml"),
    include_str!("../guards/self.toml"),
];

/// `guard`'s reviewed record.
pub(crate) fn guard_record(guard: Guard) -> &'static GuardRecord {
    static RECORDS: OnceLock<Vec<GuardRecord>> = OnceLock::new();
    let records = RECORDS.get_or_init(|| {
        Guard::ALL
            .iter()
            .zip(GUARD_RECORDS)
            .map(|(guard, text)| {
                toml::from_str(text).unwrap_or_else(|error| {
                    panic!("guards/{}.toml is invalid: {error}", guard.name())
                })
            })
            .collect()
    });
    let index = Guard::ALL
        .iter()
        .position(|candidate| *candidate == guard)
        .expect("Guard::ALL lists every guard");
    &records[index]
}

/// Generated: the command of every corpus row a record references, by row id.
const CORPUS_ROWS: &str = include_str!("../guards/corpus-rows.json");

/// Every shipped rule's knowledge record, in catalog order.
pub fn guard_knowledge() -> &'static [GuardKnowledge] {
    static KNOWLEDGE: OnceLock<Vec<GuardKnowledge>> = OnceLock::new();
    KNOWLEDGE.get_or_init(|| {
        crate::catalog::rule_ids()
            .iter()
            .copied()
            .map(|name| {
                let (_, text) = RECORDS
                    .iter()
                    .find(|(record, _)| *record == name)
                    .expect("every shipped rule has a knowledge record");
                let mut record = toml::from_str::<GuardKnowledge>(text)
                    .unwrap_or_else(|error| panic!("guards/{name}.toml is invalid: {error}"));
                record.name = name;
                record
            })
            .collect()
    })
}

pub(crate) fn knowledge_for_rule(name: &str) -> &'static GuardKnowledge {
    guard_knowledge()
        .iter()
        .find(|guard| guard.name == name)
        .expect("every shipped rule has a knowledge record")
}

fn row_commands() -> &'static BTreeMap<String, String> {
    static COMMANDS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    COMMANDS.get_or_init(|| {
        serde_json::from_str(CORPUS_ROWS).expect("guards/corpus-rows.json is a row command table")
    })
}

/// The commands of `guard`'s examples that `host` lists in the TUI, each
/// with whether it blocks only at strict.
pub(crate) fn tui_examples(guard: &GuardKnowledge, host: Platform) -> Vec<(&'static str, bool)> {
    guard
        .blocks
        .iter()
        .filter(|block| block.tui.contains(&host))
        .map(|block| (row_command(&block.row), block.strict))
        .collect()
}

fn row_command(row: &str) -> &'static str {
    row_commands().get(row).map_or_else(
        || panic!("guards/corpus-rows.json lacks `{row}`; regenerate it"),
        String::as_str,
    )
}

/// `name`'s section of the guard reference, starting with its name.
pub(crate) fn reference_section(name: &str) -> String {
    render_section(knowledge_for_rule(name), row_commands())
}

/// `guard`'s section of the guard reference, without its rules and starting
/// with its name.
pub(crate) fn guard_section(guard: Guard) -> String {
    let record = guard_record(guard);
    let mut section = format!(
        "{}\n\n{}\n\n{}\n\nResponse: {}\n",
        guard.name(),
        record.protects.trim(),
        record.description.trim(),
        record.response.trim(),
    );
    if let Some(settings) = &record.settings {
        section.push_str("\nSettings:\n\n");
        for level in GuardLevel::ALL {
            let default = if level == GuardLevel::Core {
                " (the default)"
            } else {
                ""
            };
            section.push_str(&format!(
                "- `{}`{default}: {}\n",
                level.name(),
                settings.of(level).trim()
            ));
        }
    }
    section
}

/// "Replaces nah 1.x `a` and `b`.", or "New in 2.0." for a rule with no 1.x
/// source.
fn replaces_line(guard: &GuardKnowledge) -> String {
    let names = guard
        .replaces
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>();
    match names.split_last() {
        None => "New in 2.0.".to_owned(),
        Some((last, [])) => format!("Replaces nah 1.x {last}."),
        Some((last, rest)) => format!("Replaces nah 1.x {} and {last}.", rest.join(", ")),
    }
}

fn render_section(guard: &GuardKnowledge, commands: &BTreeMap<String, String>) -> String {
    let strict_only = crate::catalog::rule_span(guard.name).0 == GuardLevel::Strict;
    let command = |row: &str| code_span(&commands[row]);
    let passes = |cause: PassCause| {
        guard
            .passes
            .iter()
            .filter(|pass| pass.cause == cause)
            .map(|pass| format!("- {}: {}\n", command(&pass.row), pass.why))
            .collect::<String>()
    };

    let mut section = format!(
        "{}\n\nApplies at {}. {}\n\n{}",
        guard.name,
        crate::commands::applies_at(guard.name),
        replaces_line(guard),
        guard.summary.trim(),
    );
    if let Some(strict_adds) = &guard.strict_adds {
        section.push_str(&format!(" {}", strict_adds.trim()));
    }
    section.push_str(&format!("\n\n{}\n\n", guard.description.trim()));
    section.push_str(&format!(
        "Blocked examples{}:\n\n",
        if strict_only { " when enabled" } else { "" }
    ));
    let blocks = |strict: bool| {
        guard
            .blocks
            .iter()
            .filter(|block| block.strict == strict)
            .map(|block| format!("- {}\n", command(&block.row)))
            .collect::<String>()
    };
    section.push_str(&blocks(false));
    let strict_blocks = blocks(true);
    if !strict_blocks.is_empty() {
        section.push_str(&format!("\nBlocked only at strict:\n\n{strict_blocks}"));
    }
    let outside = passes(PassCause::OutOfScope);
    if !outside.is_empty() {
        section.push_str(&format!("\nOutside the rule:\n\n{outside}"));
    }
    let at_strict = passes(PassCause::StrictOnly);
    if !at_strict.is_empty() {
        section.push_str(&format!(
            "\nDelegated at core, blocked at strict:\n\n{at_strict}"
        ));
    }
    section.push_str(&format!("\n{}\n", guard.limits.trim()));
    let unresolved = passes(PassCause::Unresolved);
    if !unresolved.is_empty() {
        section.push_str(&format!("\nUnresolved, so delegated:\n\n{unresolved}"));
    }
    section.push_str(&format!("\n{}\n", guard.applies_at.trim()));
    section
}

/// `text` as one Markdown code span, fenced past any backticks it contains.
fn code_span(text: &str) -> String {
    let longest = text
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    if longest == 0 {
        format!("{fence}{text}{fence}")
    } else {
        format!("{fence} {text} {fence}")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use nah_corpus_schema::{CaseInput, read_corpus_rows};

    use super::*;

    const REGENERATE: &str =
        "NAH_REGENERATE_GUARD_DOCS=1 cargo test -p nah-cli --locked --lib guard_knowledge";

    /// `docs/guard-reference.md`: the reviewed intro, then each guard's
    /// section followed by its rules' sections, in catalog order.
    fn render_reference(commands: &BTreeMap<String, String>) -> String {
        let mut reference = include_str!("../guards/intro.md").to_owned();
        for guard in Guard::ALL {
            reference.push_str("\n## ");
            reference.push_str(&guard_section(guard));
            for rule in crate::catalog::rules_of(guard) {
                reference.push_str("\n### ");
                reference.push_str(&render_section(knowledge_for_rule(rule), commands));
            }
        }
        reference
    }

    #[test]
    fn every_guard_has_one_complete_record() {
        for guard in Guard::ALL {
            let record = guard_record(guard);
            let name = guard.name();
            for text in [&record.protects, &record.description, &record.response] {
                assert!(!text.trim().is_empty(), "{name} has an empty field");
            }
            assert_eq!(
                record.settings.is_some(),
                guard.configurable(),
                "{name} describes its settings exactly when it has them"
            );
        }
    }

    #[test]
    fn every_shipped_rule_has_one_complete_record() {
        let records = RECORDS.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        let mut shipped = crate::catalog::rule_ids().to_vec();
        shipped.sort_unstable();
        assert_eq!(
            records, shipped,
            "guards/<guard>/<rule>.toml must name the shipped rules"
        );
        for guard in guard_knowledge() {
            let name = guard.name;
            for text in [
                &guard.summary,
                &guard.description,
                &guard.limits,
                &guard.applies_at,
            ] {
                assert!(!text.trim().is_empty(), "{name} has an empty field");
            }
            let (lowest, highest) = crate::catalog::rule_span(name);
            assert_eq!(
                guard.strict_adds.is_some(),
                lowest == GuardLevel::Core && highest == GuardLevel::Strict,
                "{name} states what strict adds exactly when it has core and strict parts"
            );
            let mut replaces = crate::catalog::shipped_guards()
                .parts(name)
                .filter_map(|part| part.replaces)
                .collect::<Vec<_>>();
            replaces.sort_unstable();
            replaces.dedup();
            assert_eq!(
                guard.replaces, replaces,
                "{name} lists the 1.x guards its parts replace, sorted"
            );
            assert!(!guard.blocks.is_empty(), "{name} has no block example");
            let rows = guard
                .blocks
                .iter()
                .map(|block| (&block.row, &block.why))
                .chain(guard.passes.iter().map(|pass| (&pass.row, &pass.why)))
                .collect::<Vec<_>>();
            assert!(
                rows.iter().all(|(_, why)| !why.trim().is_empty()),
                "{name} has an example without a reason"
            );
            assert_eq!(
                rows.iter()
                    .map(|(row, _)| row)
                    .collect::<BTreeSet<_>>()
                    .len(),
                rows.len(),
                "{name} names a row twice"
            );
            for host in [Platform::Linux, Platform::Macos, Platform::Windows] {
                assert!(
                    !tui_examples(guard, host).is_empty(),
                    "{name} lists no TUI example on {host:?}"
                );
            }
        }
    }

    /// Regenerates `guards/corpus-rows.json` from the corpus and
    /// `docs/guard-reference.md` from the records when
    /// `NAH_REGENERATE_GUARD_DOCS` is set; otherwise fails when either
    /// committed file differs from what they generate.
    #[test]
    fn generated_guard_files_are_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let referenced = guard_knowledge()
            .iter()
            .flat_map(|guard| {
                guard
                    .blocks
                    .iter()
                    .map(|block| block.row.as_str())
                    .chain(guard.passes.iter().map(|pass| pass.row.as_str()))
            })
            .collect::<BTreeSet<_>>();
        let mut commands = BTreeMap::new();
        for row in read_corpus_rows(&root.join("../../corpus")).unwrap() {
            let case = row.case.unwrap();
            if !referenced.contains(case.id.as_str()) {
                continue;
            }
            let CaseInput::Command(command) = case.input else {
                panic!("guard example `{}` must be a command row", case.id);
            };
            commands.insert(case.id, command);
        }
        let missing = referenced
            .iter()
            .filter(|row| !commands.contains_key(**row))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "guard examples name missing corpus rows: {missing:?}"
        );

        let files = [
            (
                root.join("guards/corpus-rows.json"),
                serde_json::to_string_pretty(&commands).unwrap() + "\n",
            ),
            (
                root.join("../../docs/guard-reference.md"),
                render_reference(&commands),
            ),
        ];
        if std::env::var_os("NAH_REGENERATE_GUARD_DOCS").is_some() {
            for (path, contents) in &files {
                std::fs::write(path, contents).unwrap();
            }
            return;
        }
        for (path, contents) in &files {
            assert!(
                std::fs::read_to_string(path).unwrap() == *contents,
                "{} is stale; regenerate it with `{REGENERATE}`",
                path.display()
            );
        }
    }
}
