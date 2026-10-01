//! Built-in guard knowledge: one reviewed record per shipped guard in
//! `crates/nah-cli/guards/<guard>.toml`. The records are the single source of
//! each guard's summary and examples in `nah tui` and `nah docs guards`, and of
//! its section of `docs/guard-reference.md`.
//!
//! An example names a `corpus/*.jsonl` row by id instead of copying its
//! command, with a reviewed reason. `blocks` rows block with the guard and
//! `passes` rows delegate with it enabled; the `nah-corpus` suite holds every
//! example to its row. The commands of the referenced rows are generated into
//! `guards/corpus-rows.json`, and the reference page is generated from the
//! records; the tests below fail when either file is stale and name the command
//! that regenerates both.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use nah_proto::ctx::Platform;
use serde::{Deserialize, Deserializer};

/// One shipped guard's reviewed knowledge record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardKnowledge {
    /// The guard name, taken from the record's file name.
    #[serde(skip)]
    pub name: &'static str,
    /// One line shown beside the guard in `nah tui` and `nah docs guards`.
    pub summary: String,
    /// What the guard stops and why, in Markdown.
    pub description: String,
    /// What Nah cannot establish for this guard, in Markdown.
    pub limits: String,
    /// Why the guard ships on or off, and how it meets neighboring guards.
    pub default_reason: String,
    pub blocks: Vec<BlockExample>,
    pub passes: Vec<PassExample>,
}

/// A corpus row this guard blocks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockExample {
    pub row: String,
    /// The detail of the command that makes the guard match.
    pub why: String,
    /// The hosts whose `nah tui` and `nah docs guards` list this example:
    /// `tui = true` for every host, or a list such as `tui = ["linux"]`.
    #[serde(default, deserialize_with = "tui_hosts")]
    pub tui: Vec<Platform>,
}

/// A corpus row that delegates with this guard enabled.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassExample {
    pub row: String,
    /// The detail of the command that keeps the guard from matching.
    pub why: String,
    pub cause: PassCause,
}

/// Why a pass example does not match its guard.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PassCause {
    /// The call is clearly outside the guard's scope.
    OutOfScope,
    /// Nah cannot establish what the call does, and its decision reports
    /// partial coverage.
    Unresolved,
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
    "db-destroy",
    "exec-decoded",
    "exec-network-shell",
    "exec-obfuscated",
    "exec-remote",
    "fs-auth-identity",
    "fs-forkbomb",
    "fs-home",
    "fs-outside-workspace-delete",
    "fs-permission-weaken",
    "fs-project-root",
    "fs-raw-device",
    "fs-shell-profile",
    "fs-startup-management",
    "fs-startup-persistence",
    "fs-system-tree",
    "fs-volume-destroy",
    "git-clean-force",
    "git-force-push",
    "git-hard-reset",
    "git-history-rewrite",
    "git-metadata",
    "git-path-discard",
    "git-protected-push",
    "git-recovery-destroy",
    "git-ref-delete",
    "git-remote-repo-delete",
    "git-remote-resource-delete",
    "git-rewrite-force",
    "git-worktree-discard",
    "infra-container-reset",
    "infra-container-volume-delete",
    "infra-iac-destroy",
    "infra-k8s-delete",
    "registry-publish",
    "registry-unpublish",
    "secrets-credentials",
    "secrets-env",
    "secrets-exfil",
    "secrets-store-delete",
    "secrets-store-destroy",
    "secrets-store-read",
    "storage-backup-destroy",
    "storage-recursive-delete",
    "storage-snapshot-delete",
    "sys-power",
    "sys-service-stop",
];

/// Generated: the command of every corpus row a record references, by row id.
const CORPUS_ROWS: &str = include_str!("../guards/corpus-rows.json");

/// Every shipped guard's knowledge record, in catalog order.
pub fn guard_knowledge() -> &'static [GuardKnowledge] {
    static KNOWLEDGE: OnceLock<Vec<GuardKnowledge>> = OnceLock::new();
    KNOWLEDGE.get_or_init(|| {
        crate::catalog::shipped_names()
            .into_iter()
            .map(|name| {
                let (_, text) = RECORDS
                    .iter()
                    .find(|(record, _)| *record == name)
                    .expect("every shipped guard has a knowledge record");
                let mut record = toml::from_str::<GuardKnowledge>(text)
                    .unwrap_or_else(|error| panic!("guards/{name}.toml is invalid: {error}"));
                record.name = name;
                record
            })
            .collect()
    })
}

pub(crate) fn knowledge(name: &str) -> &'static GuardKnowledge {
    guard_knowledge()
        .iter()
        .find(|guard| guard.name == name)
        .expect("every shipped guard has a knowledge record")
}

fn row_commands() -> &'static BTreeMap<String, String> {
    static COMMANDS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    COMMANDS.get_or_init(|| {
        serde_json::from_str(CORPUS_ROWS).expect("guards/corpus-rows.json is a row command table")
    })
}

/// The commands of `guard`'s examples that `host` lists in the TUI.
pub(crate) fn tui_examples(guard: &GuardKnowledge, host: Platform) -> Vec<&'static str> {
    guard
        .blocks
        .iter()
        .filter(|block| block.tui.contains(&host))
        .map(|block| row_command(&block.row))
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
    render_section(knowledge(name), row_commands())
}

fn render_section(guard: &GuardKnowledge, commands: &BTreeMap<String, String>) -> String {
    let default_enabled = crate::catalog::shipped_guards()
        .definition(guard.name)
        .expect("a knowledge record names a shipped guard")
        .default_enabled;
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
        "{}\n\n{} by default.\n\n{}\n\nBlocked examples{}:\n\n",
        guard.name,
        if default_enabled { "On" } else { "Off" },
        guard.description.trim(),
        if default_enabled { "" } else { " when enabled" },
    );
    for block in &guard.blocks {
        section.push_str(&format!("- {}\n", command(&block.row)));
    }
    let outside = passes(PassCause::OutOfScope);
    if !outside.is_empty() {
        section.push_str(&format!("\nOutside the guard:\n\n{outside}"));
    }
    section.push_str(&format!("\n{}\n", guard.limits.trim()));
    let unresolved = passes(PassCause::Unresolved);
    if !unresolved.is_empty() {
        section.push_str(&format!("\nUnresolved, so delegated:\n\n{unresolved}"));
    }
    section.push_str(&format!("\n{}\n", guard.default_reason.trim()));
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

    /// `docs/guard-reference.md`: the reviewed intro, then every guard's
    /// section in catalog order.
    fn render_reference(commands: &BTreeMap<String, String>) -> String {
        let mut reference = include_str!("../guards/intro.md").to_owned();
        for guard in guard_knowledge() {
            reference.push_str("\n## ");
            reference.push_str(&render_section(guard, commands));
        }
        reference
    }

    #[test]
    fn every_shipped_guard_has_one_complete_record() {
        let records = RECORDS.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        let mut shipped = crate::catalog::shipped_names();
        shipped.sort_unstable();
        assert_eq!(
            records, shipped,
            "guards/*.toml must name the shipped guards"
        );
        for guard in guard_knowledge() {
            let name = guard.name;
            for text in [
                &guard.summary,
                &guard.description,
                &guard.limits,
                &guard.default_reason,
            ] {
                assert!(!text.trim().is_empty(), "{name} has an empty field");
            }
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
