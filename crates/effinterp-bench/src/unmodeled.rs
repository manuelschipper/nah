use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{Plan, ProvenanceKind, ResourceExpr};
use serde::{Deserialize, Serialize};

use crate::nah::report::Ceilings;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmodeledCommand {
    pub command: String,
    pub occurrences: usize,
    pub fixtures: BTreeSet<String>,
    pub entrypoints: BTreeSet<String>,
    pub sample_argv: Vec<ResourceExpr>,
    pub artefact: bool,
}

/// Counts boundary occurrences, not distinct spellings or normalized display rows.
#[derive(Debug, Default)]
pub struct UnmodeledCommands(BTreeMap<String, UnmodeledCommand>);

impl UnmodeledCommands {
    /// Observe each validated fixture entrypoint once; its first occurrence supplies the sample argv.
    pub fn observe(&mut self, plan: &Plan, fixture: &str, entrypoint: &str) {
        for boundary in &plan.boundaries {
            if boundary.reason != "unmodeled_command" {
                continue;
            }
            // Exact executions do not carry node.boundary. The boundary's argument
            // provenance names its execution; root-exec arguments have no such ancestor.
            let mut pending = boundary.provenance.clone();
            let mut seen = BTreeSet::new();
            let mut execution = plan.execution_graph.entry.0;
            while let Some(reference) = pending.pop() {
                if !seen.insert(reference) {
                    continue;
                }
                let node = &plan.provenance[reference.0 as usize];
                if let ProvenanceKind::Execution { node } = node.kind {
                    execution = execution.max(node);
                } else {
                    pending.extend(&node.antecedents);
                }
            }
            let argv = plan.execution_graph.nodes[execution as usize].argv.clone();
            let detail = boundary
                .detail
                .as_deref()
                .expect("unmodeled command has a detail");
            let command = if detail == "directly executed source is not valid UTF-8" {
                // This refusal names the source condition; the literal invoked path
                // still identifies the command whose source could not be decoded.
                let ResourceExpr::Literal { value } = &argv[0] else {
                    unreachable!("direct source execution has a literal path")
                };
                value.rsplit('/').next().unwrap().to_string()
            } else {
                unmodeled_command_name(detail)
            };
            let row = self
                .0
                .entry(command.clone())
                .or_insert_with(|| UnmodeledCommand {
                    command: command.clone(),
                    occurrences: 0,
                    fixtures: BTreeSet::new(),
                    entrypoints: BTreeSet::new(),
                    sample_argv: argv,
                    artefact: command.is_empty()
                        || !command
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._/+-".contains(&b)),
                });
            row.occurrences += 1;
            row.fixtures.insert(fixture.into());
            row.entrypoints.insert(format!("{fixture}:{entrypoint}"));
        }
    }

    /// Keep this table's first sample when a command was seen by both observers.
    pub fn merge(&mut self, other: Self) {
        for (command, row) in other.0 {
            if let Some(existing) = self.0.get_mut(&command) {
                existing.occurrences += row.occurrences;
                existing.fixtures.extend(row.fixtures);
                existing.entrypoints.extend(row.entrypoints);
            } else {
                self.0.insert(command, row);
            }
        }
    }

    /// Cross-fixture rows first, then occurrence count descending and command name.
    pub fn rows(&self) -> Vec<UnmodeledCommand> {
        let mut rows: Vec<_> = self.0.values().cloned().collect();
        rows.sort_by(|a, b| {
            b.fixtures
                .len()
                .cmp(&a.fixtures.len())
                .then(b.occurrences.cmp(&a.occurrences))
                .then(a.command.cmp(&b.command))
        });
        rows
    }

    /// The head-10 is ranked by occurrence count among real commands only.
    pub fn ceiling_counts(&self) -> Ceilings {
        let mut real: Vec<_> = self
            .0
            .values()
            .filter(|row| !row.artefact)
            .map(|row| row.occurrences)
            .collect();
        real.sort_unstable_by(|a, b| b.cmp(a));
        Ceilings {
            total: BTreeMap::from([
                ("unmodeled_commands.total".into(), real.iter().sum()),
                ("unmodeled_commands.tail".into(), real.iter().skip(10).sum()),
                (
                    "unmodeled_commands.artefact".into(),
                    self.0
                        .values()
                        .filter(|row| row.artefact)
                        .map(|row| row.occurrences)
                        .sum(),
                ),
            ]),
            per_guard: BTreeMap::new(),
        }
    }
}

// exec.rs quotes command names with Rust's Debug syntax. Decode that syntax,
// including invisible Unicode characters, before applying the artefact rule.
fn unmodeled_command_name(detail: &str) -> String {
    let mut chars = detail
        .strip_prefix("no model for command ")
        .expect("unmodeled command detail names the command")
        .chars();
    assert_eq!(chars.next(), Some('"'));
    let mut name = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return name,
            '\\' => name.push(match chars.next().expect("escaped command character") {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '0' => '\0',
                'u' => {
                    assert_eq!(chars.next(), Some('{'));
                    let hex: String = chars.by_ref().take_while(|ch| *ch != '}').collect();
                    char::from_u32(u32::from_str_radix(&hex, 16).expect("Unicode escape"))
                        .expect("Unicode scalar")
                }
                _ => unreachable!("Rust Debug string escape"),
            }),
            ch => name.push(ch),
        }
    }
    unreachable!("quoted command name is terminated")
}
