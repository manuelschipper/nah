//! Renders already-redacted audit records as decision log rows and detail
//! views; it never sees raw values, so it cannot unmask them.

use nah_proto::decision::Verdict;

use super::{AuditOutcome, AuditRecordV1, MASK};

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
    pub(in crate::records) fn display(&self) -> String {
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

    pub(in crate::records) fn summary(&self) -> String {
        format!(
            "{}  {:<8}  {:<10}  {}  ({})",
            short_time(self.envelope.timestamp_rfc3339()),
            self.outcome_name(),
            self.runtime,
            self.display(),
            self.envelope.id()
        )
    }

    pub(in crate::records) fn explanation(&self) -> String {
        let (outcome, reason) = match &self.outcome {
            AuditOutcome::Decision { core } => {
                // A call can trip more than one guard, so the verdict line
                // names every guard that attributed it.
                let mut verdict = verdict_name(core.verdict).to_owned();
                for guard in &core.policy_attributions {
                    verdict.push_str(" · ");
                    verdict.push_str(guard.name());
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
        let mut lines = vec![detail_field("id:", self.envelope.id()), outcome];
        // Stored reasons join their clauses with `; `. The detail view gives
        // each following clause its own line; the stored string is untouched.
        let mut clauses = reason.split("; ");
        lines.push(detail_field("reason:", clauses.next().unwrap_or_default()));
        for clause in clauses {
            lines.push(format!("{:VALUE_COLUMN$}→ {clause}", ""));
        }
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
        for consultation in &self.consultations {
            let stderr = consultation
                .stderr
                .as_ref()
                .map(|stderr| format!("; stderr: {}", stderr.0))
                .unwrap_or_default();
            lines.push(format!(
                "policy {}: {}{}",
                consultation.policy.name(),
                consultation.outcome,
                stderr
            ));
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
