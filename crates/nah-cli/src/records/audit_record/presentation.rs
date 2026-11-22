//! Renders already-redacted audit records as `nah log` entries, `nah why`
//! explanations and the TUI log screen's rows and details; it never sees raw
//! values, so it cannot unmask them.

use nah_proto::decision::Verdict;

use super::{AuditAttribution, AuditOutcome, AuditRecordV1, MASK, saved_rules};

/// Effects a listing row names before it collapses the rest into a count.
const LISTING_EFFECTS: usize = 2;

/// Column every detail value starts in: `producer:` is the widest key, and
/// `command:`, `verdict:`, and `runtime:` print on every record.
const VALUE_COLUMN: usize = 10;

impl AuditRecordV1 {
    /// One scannable line for the record. A masked command names the tool at
    /// best, so the row falls back to the effects, whose descriptions already
    /// crossed the same redaction boundary the command did. The tool's own
    /// invocation effect and the `invoke` prefix only restate that boundary,
    /// so the row drops them and reads `Tool: what it did`.
    pub(in crate::records) fn row_text(&self) -> String {
        let command = single_line(&self.command.0);
        let Some(tool) = command.strip_suffix(MASK) else {
            return command;
        };
        let tool = tool.trim_end();
        let self_invocation = format!("invoke {tool} ");
        let duplicated_verb = format!("{} ", tool.to_lowercase());
        let named = self
            .effects
            .iter()
            .filter(|effect| !effect.description.0.starts_with(&self_invocation))
            .map(|effect| {
                let description = effect.description.0.as_str();
                let description = description.strip_prefix("invoke ").unwrap_or(description);
                description
                    .strip_prefix(&duplicated_verb)
                    .unwrap_or(description)
            })
            .collect::<Vec<_>>();
        if named.is_empty() {
            // Nothing but its own invocation is still more readable than a
            // repeated mask; a record with no effects at all keeps the mask.
            return if self.effects.is_empty() {
                command
            } else {
                tool.to_owned()
            };
        }
        let shown = &named[..named.len().min(LISTING_EFFECTS)];
        let remaining = match named.len() - shown.len() {
            0 => String::new(),
            hidden => format!(" (+{hidden})"),
        };
        single_line(&format!("{tool}: {}{remaining}", shown.join(", ")))
    }

    /// The `nah log` summary line: time, outcome, runtime, row text and id.
    pub(in crate::records) fn summary(&self) -> String {
        format!(
            "{}  {:<8}  {:<10}  {}  ({})",
            short_time(self.envelope.timestamp_rfc3339()),
            self.outcome_name(),
            self.runtime,
            self.row_text(),
            self.envelope.id()
        )
    }

    /// The `nah log` entry: the summary line and, for a block, the message
    /// the agent was given on the line below it, then each snapshot the call
    /// saved with its undo command.
    pub(in crate::records) fn listing(&self) -> String {
        let mut lines = vec![self.summary()];
        lines.extend(self.block_message());
        lines.extend(self.save_details());
        lines.join("\n  ")
    }

    /// The decision saved what the call would destroy and let it run.
    fn saved_then_delegated(&self) -> bool {
        matches!(&self.outcome, AuditOutcome::Decision { core } if core.verdict == Verdict::Delegate)
            && !self.saved.is_empty()
    }

    /// Each snapshot's rules, what it holds, its root and the command that
    /// restores it, one field a line.
    fn save_details(&self) -> Vec<String> {
        self.saved
            .iter()
            .flat_map(|saved| {
                [
                    detail_field(
                        "saved:",
                        &format!(
                            "snapshot {} by {}: {}",
                            saved.snapshot,
                            saved.rules.join(", "),
                            saved.holds
                        ),
                    ),
                    detail_field("in:", &saved.root),
                    detail_field("undo:", &saved.undo()),
                ]
            })
            .collect()
    }

    /// The message a blocked call gave the agent, as `nah test` shows it.
    fn block_message(&self) -> Option<String> {
        let (AuditOutcome::Decision { core } | AuditOutcome::Refused { core }) = &self.outcome
        else {
            return None;
        };
        // The next step names only shipped rules: a 1.x custom guard that
        // decided the call no longer exists to pause or disable.
        let shipped = core
            .policy_attributions
            .iter()
            .filter_map(|guard| match guard {
                AuditAttribution::Shipped(guard) => Some(guard.clone()),
                AuditAttribution::Custom(_) => None,
            })
            .collect::<Vec<_>>();
        (core.verdict == Verdict::Block)
            .then(|| crate::hook_adapter::block_message(&core.reason.0, &shipped))
    }

    /// The `nah why` explanation, which the TUI's log screen also shows as
    /// the selected decision's details and searches.
    pub(in crate::records) fn explanation(&self) -> String {
        let message = self.block_message();
        let (outcome, reason) = match &self.outcome {
            AuditOutcome::Decision { core } => {
                // A call can trip more than one guard, so the verdict line
                // names every guard that attributed it. The TUI's
                // `deciding_rules` reads the rules back from this line, so
                // its `verdict:` key and ` · ` separator are its contract.
                let mut verdict = verdict_name(core.verdict).to_owned();
                for guard in &core.policy_attributions {
                    verdict.push_str(" · ");
                    verdict.push_str(&guard.name());
                }
                (detail_field("verdict:", &verdict), core.reason.0.as_str())
            }
            AuditOutcome::Refused { core } => {
                (detail_field("status:", "refused"), core.reason.0.as_str())
            }
            AuditOutcome::Unavailable { reason } => {
                (detail_field("status:", "unavailable"), reason.0.as_str())
            }
        };
        // A block shows the message the agent was given, and a saved call
        // what saved it in place of the reason no guard blocked it.
        let mut lines = vec![detail_field("id:", self.envelope.id()), outcome];
        if let Some(message) = message {
            lines.push(detail_field("reason:", &message));
        } else if self.saved_then_delegated() {
            let snapshots = self
                .saved
                .iter()
                .map(|saved| saved.snapshot.as_str())
                .collect::<Vec<_>>();
            lines.push(detail_field(
                "reason:",
                &format!(
                    "{} saved {} {}, then let the call run",
                    saved_rules(&self.saved).join(", "),
                    if snapshots.len() == 1 {
                        "snapshot"
                    } else {
                        "snapshots"
                    },
                    snapshots.join(", ")
                ),
            ));
        } else {
            // Other stored reasons join their clauses with `; `. The detail
            // view gives each following clause its own line; the stored
            // string is untouched.
            let mut clauses = reason.split("; ");
            lines.push(detail_field("reason:", clauses.next().unwrap_or_default()));
            for clause in clauses {
                lines.push(format!("{:VALUE_COLUMN$}→ {clause}", ""));
            }
        }
        lines.extend(self.save_details());
        lines.push(String::new());
        lines.push(detail_field("command:", &self.command.0));
        lines.push(detail_field("runtime:", &self.runtime));
        if let Some(producer) = &self.producer {
            lines.push(detail_field("producer:", producer));
        }
        lines.push(String::new());
        lines.push("effects:".into());
        let id_width = self
            .effects
            .iter()
            .map(|effect| effect.id.chars().count())
            .max()
            .unwrap_or_default();
        for effect in &self.effects {
            lines.push(format!(
                "  {:id_width$}  {}",
                effect.id, effect.description.0
            ));
        }
        if let Some(effinterp) = &self.effinterp {
            lines.push(String::new());
            lines.push(format!(
                "effinterp: {}us{}",
                effinterp.engine_time_us,
                if effinterp.gap { " · gap" } else { "" }
            ));
            lines.push("effinterp effects:".into());
            for effect in &effinterp.effects {
                lines.push(format!("  {} {}", effect.operation, effect.resource.0));
            }
            if effinterp.boundary_count > 0 {
                lines.push(format!(
                    "effinterp boundaries: {}",
                    effinterp.boundary_count
                ));
            }
            if !effinterp.coverage.is_empty() {
                lines.push(format!(
                    "effinterp coverage: {}",
                    effinterp
                        .coverage
                        .iter()
                        .map(|coverage| format!("{}={}", coverage.domain, coverage.level))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
        }
        for diagnostic in &self.diagnostics {
            lines.push(format!("diagnostic: {}", diagnostic.0));
        }
        for failure in &self.failures {
            lines.push(format!(
                "failure: {}/{}/{}",
                failure.source, failure.component, failure.code
            ));
        }
        lines.join("\n")
    }

    fn outcome_name(&self) -> &'static str {
        match &self.outcome {
            _ if self.saved_then_delegated() => "saved",
            AuditOutcome::Decision { core } => verdict_name(core.verdict),
            AuditOutcome::Refused { .. } => "refused",
            AuditOutcome::Unavailable { .. } => "unavailable",
        }
    }
}

/// One detail line with its value in the shared column.
pub(crate) fn detail_field(key: &str, value: &str) -> String {
    format!("{key:<VALUE_COLUMN$}{value}")
}

/// Collapses newlines and runs of spaces so a multi-line command stays on one listing row.
fn single_line(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shortens `2026-07-26T21:58:24Z` to `07-26 21:58:24` for narrow list rows.
pub(crate) fn short_time(timestamp: &str) -> String {
    match (timestamp.get(5..10), timestamp.get(11..19)) {
        (Some(date), Some(time)) => format!("{date} {time}"),
        _ => timestamp.to_owned(),
    }
}

pub(crate) const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Block => "block",
        Verdict::Delegate => "delegate",
    }
}
