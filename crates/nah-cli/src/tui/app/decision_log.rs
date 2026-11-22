//! Decision-log screen state: tailing reloads that badge new blocks and
//! retain the selected decision, the outcome, runtime, and search filters,
//! and what a stored decision says beyond its verdict: the rules that
//! decided it and the save that came before it ran. The live decision log
//! reads belong to `host_state`.

use nah_proto::decision::Verdict;

use super::{App, Screen, bounded};
use crate::records::{DecisionLogView, DecisionRecord, saved_rules};

/// What happened to a call, as a TUI log row names it. Unlike `nah log`'s
/// outcome column, it has no `refused`: a refused decision shows as its
/// verdict, or as `Saved` when it delegated after a save.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Block,
    /// Nah snapshotted what a discard would destroy, then let the call
    /// through. A call nah saved and then blocked is a `Block`.
    Saved,
    Delegate,
    /// No valid decision was produced.
    Unavailable,
}

impl Outcome {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Saved => "saved",
            Self::Delegate => "delegate",
            Self::Unavailable => "unavailable",
        }
    }

    pub(crate) fn of(record: &DecisionRecord) -> Self {
        match record.verdict {
            Some(Verdict::Block) => Self::Block,
            Some(Verdict::Delegate) if !record.saved.is_empty() => Self::Saved,
            Some(Verdict::Delegate) => Self::Delegate,
            None => Self::Unavailable,
        }
    }
}

/// The guards and rules that decided `record`, from the verdict line of its
/// explanation (`verdict:  block \u{b7} work/files-delete`). A discard that
/// was saved and let through has none there, and names its rules in the
/// snapshots it saved. It parses the explanation rather than reading the
/// record's attributions, which would show some accepted records' rows
/// differently: a 1.x custom guard name holding ` \u{b7} `, or a refused
/// record with a verdict-shaped line in a multiline field.
pub(crate) fn deciding_rules(record: &DecisionRecord) -> String {
    let blocking = record
        .explanation
        .lines()
        .find_map(|line| line.strip_prefix("verdict:"))
        .map(|verdict| {
            verdict
                .split(" \u{b7} ")
                .skip(1)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if blocking.is_empty() {
        saved_rules(&record.saved).join(", ")
    } else {
        blocking
    }
}

impl App {
    /// Badges the log tab with blocks that arrived while another screen was
    /// open. Records ahead of the last seen block are the new ones, so a
    /// window that slid past its old contents is still counted once.
    fn note_new_blocks(&mut self, blocked_log: &[DecisionRecord]) {
        let new = self
            .seen_block_id
            .as_ref()
            .map_or(blocked_log.len(), |seen| {
                blocked_log
                    .iter()
                    .position(|record| &record.id == seen)
                    .unwrap_or(blocked_log.len())
            });
        if self.screen != Screen::Log {
            self.new_blocks += new;
        }
        self.seen_block_id = blocked_log.first().map(|record| record.id.clone());
    }

    /// Keeps the newest record selected while following, otherwise keeps the
    /// selected decision under the cursor as new records push the list down.
    #[cfg(test)]
    pub(crate) fn apply_reloaded_log(&mut self, log: Vec<DecisionRecord>) {
        let blocked_log = log
            .iter()
            .filter(|record| record.verdict == Some(Verdict::Block))
            .cloned()
            .collect();
        self.apply_reloaded_logs(log, blocked_log);
    }

    fn apply_reloaded_logs(&mut self, log: Vec<DecisionRecord>, blocked_log: Vec<DecisionRecord>) {
        self.note_new_blocks(&blocked_log);
        let follow = self.log_index == 0;
        let selected = self.selected_log().map(|record| record.id.clone());
        self.log = log;
        self.blocked_log = blocked_log;
        let index = match (follow, &selected) {
            (true, _) | (false, None) => 0,
            (false, Some(id)) => self
                .filtered_log()
                .iter()
                .position(|record| &record.id == id)
                .unwrap_or_else(|| bounded(self.log_index, self.filtered_log().len())),
        };
        self.log_index = index;
        // The offset belongs to the screen that is open: a decision that
        // arrives while another screen is read must not scroll that screen.
        if self.screen == Screen::Log
            && self.selected_log().map(|record| record.id.clone()) != selected
        {
            self.detail_scroll = 0;
        }
    }

    pub(super) fn apply_reloaded_view(&mut self, view: DecisionLogView) {
        let recovered_from = view.recovered_from;
        // A read that works again takes back the error the failed one left,
        // and only that: warnings the load joined to it stay.
        if let Some(unreadable) = self.log_unreadable.take()
            && let Some(rest) = self
                .message
                .as_ref()
                .and_then(|message| message.text.strip_prefix(&unreadable))
        {
            let rest = rest.trim_start_matches("; ").to_owned();
            self.message = (!rest.is_empty()).then_some(super::Message {
                kind: super::MessageKind::Warning,
                text: rest,
            });
        }
        self.log_summary = view.summary;
        self.failure_summary = view.failures;
        self.apply_reloaded_logs(view.records, view.blocked_records);
        if self.message.is_none()
            && let Some(path) = recovered_from
        {
            self.warning(recovered_log_message(&path));
        }
    }

    /// How many decisions of each outcome the active recent or blocked
    /// history window holds.
    pub(crate) fn outcome_counts(&self) -> [(Outcome, usize); 4] {
        [
            Outcome::Block,
            Outcome::Saved,
            Outcome::Delegate,
            Outcome::Unavailable,
        ]
        .map(|outcome| {
            (
                outcome,
                self.log_window()
                    .iter()
                    .filter(|record| Outcome::of(record) == outcome)
                    .count(),
            )
        })
    }

    pub(crate) fn log_window(&self) -> &[DecisionRecord] {
        if self.log_filter == Some(Outcome::Block) {
            &self.blocked_log
        } else {
            &self.log
        }
    }

    /// Rows the log screen browses: the outcome filter, the runtime filter, and
    /// the query all apply, so live tail, pinning, and counts see the same
    /// list. The explanation carries the decision id, command, and effects, so
    /// one substring covers everything worth searching for.
    pub(crate) fn filtered_log(&self) -> Vec<&DecisionRecord> {
        let query = self.log_search.to_lowercase();
        self.log_window()
            .iter()
            .filter(|record| {
                self.log_filter
                    .is_none_or(|outcome| Outcome::of(record) == outcome)
                    && self
                        .log_runtime_filter
                        .as_ref()
                        .is_none_or(|runtime| &record.runtime == runtime)
                    && (query.is_empty() || record.explanation.to_lowercase().contains(&query))
            })
            .collect()
    }

    pub(crate) fn cycle_log_filter(&mut self) {
        self.log_filter = match self.log_filter {
            None => Some(Outcome::Block),
            Some(Outcome::Block) => Some(Outcome::Saved),
            Some(Outcome::Saved) => Some(Outcome::Delegate),
            Some(Outcome::Delegate | Outcome::Unavailable) => None,
        };
        self.log_index = 0;
        self.detail_scroll = 0;
        self.message = None;
    }

    /// Runtimes present in the loaded window, sorted, which are the only ones
    /// worth cycling through.
    pub(crate) fn log_runtimes(&self) -> Vec<&str> {
        let mut runtimes = self
            .log_window()
            .iter()
            .map(|record| record.runtime.as_str())
            .collect::<Vec<_>>();
        runtimes.sort_unstable();
        runtimes.dedup();
        runtimes
    }

    /// Steps through the runtimes actually recorded in the window and back to
    /// all, so the filter can never select rows that do not exist.
    pub(crate) fn cycle_log_runtime_filter(&mut self) {
        let runtimes = self.log_runtimes();
        let next = match &self.log_runtime_filter {
            None => runtimes.first(),
            Some(current) => runtimes
                .iter()
                .position(|runtime| runtime == current)
                .and_then(|index| runtimes.get(index + 1)),
        };
        self.log_runtime_filter = next.map(|runtime| (*runtime).to_owned());
        self.restart_log_selection();
        self.message = None;
    }

    /// Opens the query for editing, keeping an active search as the starting
    /// text so a near miss can be corrected instead of retyped.
    pub(crate) fn begin_log_search(&mut self) {
        self.log_search_editing = true;
        self.message = None;
    }

    pub(crate) fn push_log_search(&mut self, character: char) {
        self.log_search.push(character);
        self.restart_log_selection();
    }

    pub(crate) fn pop_log_search(&mut self) {
        self.log_search.pop();
        self.restart_log_selection();
    }

    /// Leaves the typed query as the active search. An empty one filters
    /// nothing, so confirming it is how a search is cleared while typing.
    pub(crate) const fn confirm_log_search(&mut self) {
        self.log_search_editing = false;
    }

    /// Abandons the search entirely, so Esc always returns the whole window.
    pub(crate) fn cancel_log_search(&mut self) {
        self.log_search_editing = false;
        self.log_search.clear();
        self.restart_log_selection();
    }

    /// A changed query renumbers the rows, so the cursor returns to the newest
    /// match rather than to whatever now sits at its old index.
    fn restart_log_selection(&mut self) {
        self.log_index = 0;
        self.detail_scroll = 0;
    }

    pub(crate) fn selected_log(&self) -> Option<&DecisionRecord> {
        self.filtered_log().get(self.log_index).copied()
    }
}

pub(super) fn recovered_log_message(path: &std::path::Path) -> String {
    format!(
        "decision log recovered; original archived to {}; showing latest readable decisions",
        path.display()
    )
}
