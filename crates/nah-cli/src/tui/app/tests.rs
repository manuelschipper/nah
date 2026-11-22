use super::*;
use crate::commands::GuardStatus;
use crate::records::DecisionLogView;

#[test]
fn shipped_state_diagnostics_use_the_footer_warning_surface() {
    let message = append_footer_warnings(None, vec!["renamed guard".into()]).unwrap();

    assert_eq!(message.kind, MessageKind::Warning);
    assert!(!message.text.is_empty());
}

#[test]
fn runtime_status_names_show_the_preserved_failure_policy() {
    assert_eq!(status_name(RuntimeHookStatus::WiringCurrent), "fail-open");
    assert_eq!(
        status_name(RuntimeHookStatus::WiringCurrentFailClosed),
        "fail-closed"
    );
}

#[test]
fn runtime_failure_policy_toggle_targets_the_opposite_mode() {
    let mut app = App::fixture();
    app.request_runtime_failure_policy();
    assert!(matches!(
        app.confirmation,
        Some(Confirmation::ConfigureRuntime {
            install: true,
            failure_policy: Some(FailurePolicy::Block),
            configured: true,
            ..
        })
    ));

    app.runtimes[0].status = Ok(RuntimeHookStatus::WiringCurrentFailClosed);
    app.request_runtime_failure_policy();
    assert!(matches!(
        app.confirmation,
        Some(Confirmation::ConfigureRuntime {
            failure_policy: Some(FailurePolicy::Delegate),
            ..
        })
    ));
}

#[test]
fn runtime_failure_policy_toggle_installs_unconfigured_runtime_fail_closed() {
    let mut app = App::fixture();
    app.runtimes[0].status = Ok(RuntimeHookStatus::NotConfigured);
    app.request_runtime_failure_policy();
    assert!(matches!(
        app.confirmation,
        Some(Confirmation::ConfigureRuntime {
            install: true,
            failure_policy: Some(FailurePolicy::Block),
            configured: false,
            ..
        })
    ));
}

#[test]
fn runtime_failure_policy_toggle_refuses_uninspectable_wiring() {
    let mut app = App::fixture();
    app.runtimes[0].status = Err("runtime-hook-read-failed".into());
    app.request_runtime_failure_policy();
    assert!(app.confirmation.is_none());
    assert_eq!(
        app.message.as_ref().map(|message| message.text.as_str()),
        Some("cannot change mode while runtime wiring cannot be inspected")
    );
}

#[test]
fn guard_and_rule_changes_stage_without_writing() {
    let mut app = App::fixture();
    // A guard cycles core, strict, off and back to its stored setting.
    for level in [GuardLevel::Strict, GuardLevel::Off] {
        app.toggle_guard();
        assert_eq!(app.guard_setting(Guard::UntrustedCode), level);
        assert_eq!(app.pending_count(), 1);
    }
    app.toggle_guard();
    assert_eq!(app.pending_count(), 0);
    assert!(app.confirmation.is_none());

    // A level key sets the level outright, and the stored level unstages.
    app.set_guard_level(GuardLevel::Off);
    assert_eq!(app.guard_setting(Guard::UntrustedCode), GuardLevel::Off);
    assert_eq!(app.pending_count(), 1);
    app.set_guard_level(GuardLevel::Core);
    assert_eq!(app.pending_count(), 0);

    // A rule has no level: a level key on its row stages nothing.
    app.guard_index = 1;
    app.set_guard_level(GuardLevel::Strict);
    assert_eq!(app.pending_count(), 0);

    // A rule overrides to the opposite of its state; resetting it to what is
    // stored unstages it.
    let rule = "untrusted-code/remote-script-run";
    app.toggle_guard();
    assert_eq!(app.rule_override(rule), Some(RuleOverride::Disabled));
    assert_eq!(app.rule_state(rule), RuleState::Off);
    app.toggle_guard();
    assert_eq!(app.rule_override(rule), Some(RuleOverride::Enabled));
    assert_eq!(app.pending_count(), 1);
    app.reset_guard();
    assert_eq!(app.pending_count(), 0);

    // `self` has no setting to change.
    app.guards.push(guard_entry(
        GuardTarget::Guard {
            guard: Guard::SelfProtection,
        },
        GuardStatus::Enabled,
    ));
    app.guard_index = app.guards.len() - 1;
    app.toggle_guard();
    app.reset_guard();
    assert_eq!(app.pending_count(), 0);
}

#[test]
fn quitting_with_pending_changes_requires_confirmation() {
    let mut app = App::fixture();
    app.toggle_guard();
    assert!(!app.request_quit());
    assert!(matches!(
        app.confirmation,
        Some(Confirmation::DiscardChanges { count: 1 })
    ));
}

#[test]
fn failed_preflight_preserves_the_complete_batch() {
    if crate::live_state::reran_in_temporary_home() {
        return;
    }
    let mut app = App::fixture();
    // A rule this build no longer ships fails the preflight.
    app.pending.push(GuardChange::RuleSet {
        rule: "machine/retired-rule".into(),
        value: Some(RuleOverride::Disabled),
    });
    app.guard_index = 1;
    app.toggle_guard();

    assert_eq!(app.pending_count(), 2);

    app.apply_guards();

    assert_eq!(app.pending_count(), 2);
    assert!(matches!(app.pending[0], GuardChange::RuleSet { .. }));
    assert!(matches!(app.pending[1], GuardChange::RuleSet { .. }));
    assert!(matches!(
        app.message,
        Some(Message {
            kind: MessageKind::Error,
            ..
        })
    ));
}

/// Entries beyond the fixture's, so a reset has every status to diff.
fn guard_entry(target: GuardTarget, status: GuardStatus) -> GuardEntry {
    GuardEntry {
        target,
        setting: GuardLevel::Core,
        rule_override: None,
        status,
        behavior: None,
        examples: vec![],
    }
}

fn staged(app: &App) -> Vec<String> {
    app.pending
        .iter()
        .map(|change| change.target().name())
        .collect()
}

#[test]
fn resetting_stages_the_diff_from_the_shipped_defaults() {
    let mut app = App::fixture();
    app.guards.extend([
        GuardEntry {
            setting: GuardLevel::Strict,
            ..guard_entry(
                GuardTarget::Guard {
                    guard: Guard::Machine,
                },
                GuardStatus::Enabled,
            )
        },
        GuardEntry {
            rule_override: Some(RuleOverride::Enabled),
            ..guard_entry(
                GuardTarget::Rule {
                    rule: "machine/system-halt".into(),
                },
                GuardStatus::Enabled,
            )
        },
        guard_entry(
            GuardTarget::Rule {
                rule: "machine/disk-overwrite".into(),
            },
            GuardStatus::Enabled,
        ),
    ]);

    app.reset_to_defaults();

    // Guards already at core and rules without an override are the shipped
    // posture, so they are not staged.
    assert_eq!(
        staged(&app),
        ["secrets/env-files-read", "machine", "machine/system-halt",]
    );
    assert!(app.confirmation.is_none());
    assert_eq!(
        app.message,
        Some(Message {
            kind: MessageKind::Info,
            text: "restore shipped settings staged: 3 change(s); Enter to apply".into(),
        })
    );

    // Resetting replaces whatever was staged by hand.
    app.guard_index = 0;
    app.toggle_guard();
    app.reset_to_defaults();
    assert_eq!(app.pending_count(), 3);
    assert!(!staged(&app).contains(&"untrusted-code".to_owned()));
}

#[test]
fn resetting_at_the_defaults_clears_the_batch() {
    let mut app = App::fixture();
    app.guards.truncate(2);
    app.toggle_guard();
    assert_eq!(app.pending_count(), 1);

    app.reset_to_defaults();

    assert_eq!(app.pending_count(), 0);
    assert_eq!(
        app.message,
        Some(Message {
            kind: MessageKind::Info,
            text: "shipped settings are already restored".into(),
        })
    );
}

#[test]
fn screen_navigation_wraps() {
    let mut app = App::fixture();
    app.previous_screen();
    assert_eq!(app.screen, Screen::Log);
    app.next_screen();
    assert_eq!(app.screen, Screen::Guards);
    app.next_screen();
    assert_eq!(app.screen, Screen::Runtimes);
}

#[test]
fn the_guard_screen_keeps_its_selection_across_screens() {
    let mut app = App::fixture();
    app.move_selection(true);
    app.move_selection(true);
    assert_eq!(app.guard_index, 2);
    assert_eq!(app.selected_guard().unwrap().target.name(), "secrets");

    app.select_screen(Screen::Runtimes);
    assert!(app.selected_guard().is_none());
    app.move_selection(true);
    assert_eq!(app.guard_index, 2);

    app.select_screen(Screen::Guards);
    assert_eq!(app.selected_guard().unwrap().target.name(), "secrets");
}

fn shown(app: &App) -> Vec<String> {
    app.guard_rows()
        .into_iter()
        .map(|row| row.target.name())
        .collect()
}

#[test]
fn folding_hides_rows_and_keeps_the_selection_on_a_shown_one() {
    let mut app = App::fixture();
    assert_eq!(
        shown(&app),
        [
            "untrusted-code",
            "untrusted-code/remote-script-run",
            "secrets",
            "secrets/env-files-read",
        ]
    );

    // Closing from a rule selects its guard, so no hidden row stays selected.
    app.guard_index = 3;
    app.close_selected();
    assert_eq!(app.selected_guard().unwrap().target.name(), "secrets");
    assert!(!shown(&app).contains(&"secrets/env-files-read".to_owned()));

    // Opening a heading shows its rows again and leaves the selection alone.
    app.open_selected();
    assert_eq!(shown(&app).last().unwrap(), "secrets/env-files-read");
    assert_eq!(shown(&app)[app.guard_index], "secrets");

    // A guard without rules has nothing to fold.
    app.guards.insert(
        0,
        guard_entry(
            GuardTarget::Guard {
                guard: Guard::SelfProtection,
            },
            GuardStatus::Enabled,
        ),
    );
    app.guard_index = 0;
    let rows = shown(&app);
    app.open_selected();
    app.close_selected();
    assert_eq!(shown(&app), rows);
}

#[test]
fn reloading_follows_the_newest_record_from_the_top() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    assert_eq!(app.selected_log().unwrap().id, "decision-2");

    let mut log = vec![App::record_fixture("decision-3", Verdict::Delegate)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);

    assert_eq!(app.log_index, 0);
    assert_eq!(app.selected_log().unwrap().id, "decision-3");
}

#[test]
fn reloading_pins_a_scrolled_selection_to_its_record() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.move_selection(true);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    let mut log = vec![
        App::record_fixture("decision-4", Verdict::Delegate),
        App::record_fixture("decision-3", Verdict::Block),
    ];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);

    assert_eq!(app.log_index, 3);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    // A filtered view pins to the record's position after filtering.
    app.log_filter = Some(Outcome::Delegate);
    app.log_index = 1;
    assert_eq!(app.selected_log().unwrap().id, "decision-1");
    let mut log = vec![App::record_fixture("decision-5", Verdict::Delegate)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.log_index, 2);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");
}

#[test]
fn reloading_clamps_when_the_pinned_record_is_gone() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.move_selection(true);

    app.apply_reloaded_log(vec![App::record_fixture("decision-9", Verdict::Block)]);

    assert_eq!(app.log_index, 0);
    assert_eq!(app.selected_log().unwrap().id, "decision-9");
}

#[test]
fn recovered_logs_raise_a_warning_after_the_readable_view_loads() {
    let mut app = App::fixture();
    let records = vec![App::record_fixture("decision-recovered", Verdict::Delegate)];
    app.apply_reloaded_view(DecisionLogView {
        records: records.clone(),
        blocked_records: vec![],
        summary: Default::default(),
        failures: None,
        recovered_from: Some("/home/test/.nah/old_logs/audit.jsonl".into()),
    });

    assert_eq!(app.log, records);
    assert!(matches!(
        app.message,
        Some(Message {
            kind: MessageKind::Warning,
            ..
        })
    ));
}

#[test]
fn a_log_read_that_works_again_takes_back_the_unreadable_error() {
    let mut app = App::fixture();
    let unreadable = "decision log is unreadable: audit-io".to_owned();
    app.log_unreadable = Some(unreadable.clone());
    app.message = Some(Message {
        kind: MessageKind::Error,
        text: unreadable,
    });
    let records = vec![App::record_fixture("decision-read", Verdict::Delegate)];
    app.apply_reloaded_view(DecisionLogView {
        records,
        blocked_records: vec![],
        summary: crate::records::LogSummary {
            calls: 1,
            ran: 1,
            ..Default::default()
        },
        failures: None,
        recovered_from: None,
    });

    assert!(app.log_unreadable.is_none());
    assert!(app.message.is_none());
    assert_eq!(app.log_summary.calls, 1);

    // A warning the load joined to the error outlives it.
    let unreadable = "decision log is unreadable: audit-io".to_owned();
    app.log_unreadable = Some(unreadable.clone());
    app.message = Some(Message {
        kind: MessageKind::Error,
        text: format!("{unreadable}; ignored retired/rule"),
    });
    app.apply_reloaded_view(DecisionLogView {
        records: vec![],
        blocked_records: vec![],
        summary: Default::default(),
        failures: None,
        recovered_from: None,
    });
    assert_eq!(
        app.message,
        Some(Message {
            kind: MessageKind::Warning,
            text: "ignored retired/rule".into(),
        })
    );
}

#[test]
fn a_recovery_warning_does_not_replace_an_active_error() {
    let mut app = App::fixture();
    app.message = Some(Message {
        kind: MessageKind::Error,
        text: "active error".into(),
    });
    app.apply_reloaded_view(DecisionLogView {
        records: vec![],
        blocked_records: vec![],
        summary: Default::default(),
        failures: None,
        recovered_from: Some("/home/test/.nah/old_logs/audit.jsonl".into()),
    });

    assert!(matches!(
        app.message,
        Some(Message {
            kind: MessageKind::Error,
            ..
        })
    ));
}

#[test]
fn blocks_arriving_off_the_log_screen_badge_its_tab() {
    let mut app = App::fixture();
    assert_eq!(app.screen, Screen::Guards);

    let mut log = vec![App::record_fixture("decision-3", Verdict::Block)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.new_blocks, 1);

    // Delegated decisions are not worth interrupting for.
    let mut log = vec![App::record_fixture("decision-4", Verdict::Delegate)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.new_blocks, 1);

    // A reload without new records recounts nothing.
    let log = app.log.clone();
    app.apply_reloaded_log(log);
    assert_eq!(app.new_blocks, 1);

    app.select_screen(Screen::Log);
    assert_eq!(app.new_blocks, 0);
}

#[test]
fn blocks_read_on_the_log_screen_never_badge() {
    let mut app = App::fixture();
    app.select_screen(Screen::Log);

    let mut log = vec![App::record_fixture("decision-3", Verdict::Block)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.new_blocks, 0);

    // Only what arrives after leaving the screen badges the tab.
    app.select_screen(Screen::Guards);
    let mut log = vec![App::record_fixture("decision-4", Verdict::Block)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.new_blocks, 1);
}

#[test]
fn the_badge_counts_records_the_window_pushed_out() {
    let mut app = App::fixture();

    // The window keeps its length while the oldest record drops off.
    let log = vec![
        App::record_fixture("decision-3", Verdict::Block),
        app.log[0].clone(),
    ];
    app.apply_reloaded_log(log);
    assert_eq!(app.log.len(), 2);
    assert_eq!(app.new_blocks, 1);

    // A window that slid past every seen record counts all of it.
    app.apply_reloaded_log(vec![
        App::record_fixture("decision-9", Verdict::Block),
        App::record_fixture("decision-8", Verdict::Block),
    ]);
    assert_eq!(app.new_blocks, 3);
}

#[test]
fn detail_scroll_resets_with_the_selection_and_the_filter() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.scroll_detail(true);
    assert!(app.detail_scroll > 0);

    app.move_selection(true);
    assert_eq!(app.detail_scroll, 0);

    app.scroll_detail(true);
    app.cycle_log_filter();
    assert_eq!(app.detail_scroll, 0);

    // A reload that keeps the same record under the cursor keeps the offset.
    app.log_filter = None;
    app.log_index = 1;
    app.scroll_detail(true);
    let scrolled = app.detail_scroll;
    assert!(scrolled > 0);
    let mut log = vec![App::record_fixture("decision-3", Verdict::Delegate)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");
    assert_eq!(app.detail_scroll, scrolled);

    // A decision that arrives while another screen is open moves the log's
    // selection, and leaves that screen's details where they were read.
    app.select_screen(Screen::Guards);
    app.log_index = 0;
    app.scroll_detail(true);
    let scrolled = app.detail_scroll;
    assert!(scrolled > 0);
    let mut log = vec![App::record_fixture("decision-4", Verdict::Delegate)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.selected_log().unwrap().id, "decision-4");
    assert_eq!(app.detail_scroll, scrolled);
}

fn counted(app: &App, outcome: Outcome) -> usize {
    app.outcome_counts()
        .into_iter()
        .find(|(counted, _)| *counted == outcome)
        .map_or(0, |(_, count)| count)
}

#[test]
fn outcome_counts_cover_the_loaded_window() {
    let mut app = App::fixture();
    app.log_filter = Some(Outcome::Delegate);

    assert_eq!(counted(&app, Outcome::Delegate), 1);
    assert_eq!(counted(&app, Outcome::Block), 1);
}

#[test]
fn a_saved_discard_is_read_from_its_audit_record() {
    let saved = App::saved_record_fixture("decision-7");
    assert_eq!(Outcome::of(&saved), Outcome::Saved);
    assert_eq!(deciding_rules(&saved), "work/changes-discard");

    // A call that saved two repositories is decided by the rules of both.
    let mut two = saved.clone();
    two.saved.push(crate::records::SavedSnapshot {
        rules: vec!["work/untracked-clean".into(), "work/changes-discard".into()],
        snapshot: "1abc2345".into(),
        root: "/repo/vendor".into(),
        holds: "2 files".into(),
        apart: true,
    });
    assert_eq!(
        deciding_rules(&two),
        "work/changes-discard, work/untracked-clean"
    );

    // A delegate without a save stays a delegate, and a block names the
    // rules on its verdict line.
    let app = App::fixture();
    assert_eq!(Outcome::of(&app.log[1]), Outcome::Delegate);
    assert_eq!(deciding_rules(&app.log[1]), "");
    let mut block = App::record_fixture("decision-8", Verdict::Block);
    block.explanation =
        "id: decision-8\nverdict:  block \u{b7} work/files-delete \u{b7} custom/corp\nreason: gone"
            .into();
    assert_eq!(Outcome::of(&block), Outcome::Block);
    assert_eq!(deciding_rules(&block), "work/files-delete, custom/corp");

    // A call nah saved and then blocked is a block, decided by what blocked
    // it; its snapshot is still there to read.
    let mut denied = saved.clone();
    denied.verdict = Some(Verdict::Block);
    denied.explanation = denied
        .explanation
        .replace("verdict:  delegate", "verdict:  block \u{b7} custom/corp");
    assert_eq!(Outcome::of(&denied), Outcome::Block);
    assert_eq!(deciding_rules(&denied), "custom/corp");
    assert_eq!(denied.saved[0].snapshot, "0dec7505");
}

#[test]
fn block_filter_uses_its_independent_history() {
    let mut app = App::fixture();
    app.log = vec![App::record_fixture("decision-recent", Verdict::Delegate)];
    app.blocked_log = vec![App::record_fixture("decision-old-block", Verdict::Block)];

    app.log_filter = Some(Outcome::Block);

    assert_eq!(app.filtered_log().len(), 1);
    assert_eq!(app.selected_log().unwrap().id, "decision-old-block");
}

/// Types a query from scratch the way the key handler does.
fn type_search(app: &mut App, query: &str) {
    app.cancel_log_search();
    app.begin_log_search();
    for character in query.chars() {
        app.push_log_search(character);
    }
}

fn matched_ids(app: &App) -> Vec<&str> {
    app.filtered_log()
        .iter()
        .map(|record| record.id.as_str())
        .collect()
}

/// Explanations carrying the command and the effects the decision covered,
/// which is what a search is expected to reach.
fn explained(app: &mut App) {
    app.log[0].explanation =
        "id: decision-2\nverdict: block\ncommand: curl https://install.sh | bash\neffect: network egress to install.sh".into();
    app.blocked_log[0].explanation = app.log[0].explanation.clone();
    app.log[1].explanation =
        "id: decision-1\nverdict: delegate\ncommand: git status\neffect: reads the worktree".into();
}

#[test]
fn searching_matches_the_explanation_case_insensitively() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    explained(&mut app);

    // Command text, in either case.
    type_search(&mut app, "CURL");
    assert_eq!(matched_ids(&app), vec!["decision-2"]);
    type_search(&mut app, "git status");
    assert_eq!(matched_ids(&app), vec!["decision-1"]);

    // Effect text, and the decision id a user can paste in.
    type_search(&mut app, "Egress");
    assert_eq!(matched_ids(&app), vec!["decision-2"]);
    type_search(&mut app, "decision-1");
    assert_eq!(matched_ids(&app), vec!["decision-1"]);

    type_search(&mut app, "verdict");
    assert_eq!(matched_ids(&app), vec!["decision-2", "decision-1"]);
    type_search(&mut app, "nothing here");
    assert!(matched_ids(&app).is_empty());
    assert!(app.selected_log().is_none());
}

/// A masked row shows the effects instead of the command, and the same
/// effect text is already in the explanation the search reads.
#[test]
fn searching_reaches_the_effects_a_masked_row_shows() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log[0].row_text = "Bash: curl request, network outbound [redacted] (+2)".into();
    app.log[0].explanation = "id: decision-2\nverdict: block\ncommand: Bash [redacted]\neffects:\n- effect-0: invoke curl request\n- effect-1: network outbound [redacted]".into();
    app.log[1].explanation =
        "id: decision-1\nverdict: delegate\ncommand: Bash [redacted]\neffects:\n- effect-0: git status".into();

    type_search(&mut app, "curl");
    assert_eq!(matched_ids(&app), vec!["decision-2"]);
    type_search(&mut app, "network outbound");
    assert_eq!(matched_ids(&app), vec!["decision-2"]);
    type_search(&mut app, "git status");
    assert_eq!(matched_ids(&app), vec!["decision-1"]);
}

#[test]
fn searching_composes_with_the_verdict_filter() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    explained(&mut app);

    type_search(&mut app, "command");
    assert_eq!(matched_ids(&app), vec!["decision-2", "decision-1"]);

    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Outcome::Block));
    assert_eq!(matched_ids(&app), vec!["decision-2"]);

    // The block filter reads the independent block history.
    assert_eq!(counted(&app, Outcome::Delegate), 0);
    assert_eq!(counted(&app, Outcome::Block), 1);
}

#[test]
fn the_runtime_filter_cycles_the_window_and_composes_with_the_others() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    explained(&mut app);
    assert_eq!(app.log_runtimes(), vec!["claude", "codex"]);

    app.cycle_log_runtime_filter();
    assert_eq!(app.log_runtime_filter.as_deref(), Some("claude"));
    assert_eq!(matched_ids(&app), vec!["decision-1"]);

    app.cycle_log_runtime_filter();
    assert_eq!(app.log_runtime_filter.as_deref(), Some("codex"));
    assert_eq!(matched_ids(&app), vec!["decision-2"]);

    // Past the last recorded runtime the filter is off again.
    app.cycle_log_runtime_filter();
    assert_eq!(app.log_runtime_filter, None);
    assert_eq!(matched_ids(&app), vec!["decision-2", "decision-1"]);

    // Claude delegated; the block came from codex.
    app.cycle_log_runtime_filter();
    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Outcome::Block));
    assert!(matched_ids(&app).is_empty());
    app.log_filter = Some(Outcome::Delegate);
    assert_eq!(matched_ids(&app), vec!["decision-1"]);

    // The query narrows what the runtime filter left.
    app.cycle_log_filter();
    assert_eq!(app.log_filter, None);
    type_search(&mut app, "command");
    assert_eq!(matched_ids(&app), vec!["decision-1"]);
    type_search(&mut app, "curl");
    assert!(matched_ids(&app).is_empty());
}

#[test]
fn editing_the_query_restarts_the_selection() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    explained(&mut app);
    app.move_selection(true);
    app.scroll_detail(true);
    assert_eq!(app.log_index, 1);

    app.begin_log_search();
    // Opening the query alone changes nothing about the list.
    assert_eq!(app.log_index, 1);

    app.push_log_search('c');
    assert_eq!(app.log_index, 0);
    assert_eq!(app.detail_scroll, 0);

    app.push_log_search('u');
    app.push_log_search('r');
    assert_eq!(matched_ids(&app), vec!["decision-2"]);
    app.move_selection(true);
    app.pop_log_search();
    assert_eq!(app.log_index, 0);
    assert_eq!(app.log_search, "cu");
}

#[test]
fn confirming_keeps_the_query_and_escape_drops_it() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    explained(&mut app);

    type_search(&mut app, "curl");
    app.confirm_log_search();
    assert!(!app.log_search_editing);
    assert_eq!(app.log_search, "curl");
    assert_eq!(matched_ids(&app), vec!["decision-2"]);

    // Reopening resumes the active query rather than starting empty.
    app.begin_log_search();
    assert_eq!(app.log_search, "curl");

    // Emptying the query and confirming is how a search is cleared.
    for _ in 0..4 {
        app.pop_log_search();
    }
    app.confirm_log_search();
    assert!(app.log_search.is_empty());
    assert_eq!(app.filtered_log().len(), 2);

    // Esc abandons a query mid-edit and any search behind it.
    type_search(&mut app, "curl");
    app.confirm_log_search();
    app.begin_log_search();
    app.push_log_search('x');
    app.cancel_log_search();
    assert!(!app.log_search_editing);
    assert!(app.log_search.is_empty());
    assert_eq!(app.filtered_log().len(), 2);
}

#[test]
fn reloading_during_a_search_pins_to_the_filtered_view() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    explained(&mut app);
    type_search(&mut app, "command");
    app.confirm_log_search();

    app.move_selection(true);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    // A matching arrival pushes the pinned record down by one; a record
    // the query excludes never enters the list at all.
    let mut log = vec![
        App::record_fixture("decision-4", Verdict::Delegate),
        App::record_fixture("decision-3", Verdict::Block),
    ];
    log[0].explanation = "id: decision-4\ncommand: git log".into();
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);

    assert_eq!(
        matched_ids(&app),
        vec!["decision-4", "decision-2", "decision-1"]
    );
    assert_eq!(app.log_index, 2);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    // Following from the top still lands on the newest match.
    app.log_index = 0;
    let mut log = vec![App::record_fixture("decision-5", Verdict::Delegate)];
    log[0].explanation = "id: decision-5\ncommand: git diff".into();
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.selected_log().unwrap().id, "decision-5");
    // Records the query excludes still load into the window behind it.
    assert_eq!(app.log.len(), 5);
}

#[test]
fn the_nap_banner_leads_with_a_countdown_to_the_second() {
    let banner = |mode: NapMode, remaining| NapStatus { mode, remaining }.banner(80);
    for (remaining, countdown) in [
        (600, "10m 00s"),
        (372, "6m 12s"),
        (60, "1m 00s"),
        // Under a minute the minutes are dropped rather than shown as zero.
        (59, " 59s"),
        (0, " 0s"),
    ] {
        let text = banner(NapMode::All, remaining);
        assert!(text.contains(&format!("{countdown} left")), "{text}");
        assert!(text.contains(&NapMode::All.scope()), "{text}");
    }
    assert!(banner(NapMode::SelfProtection, 600).contains(&NapMode::SelfProtection.scope()));
}

#[test]
fn a_rule_carries_the_reason_that_decides_its_state() {
    let mut app = App::fixture();
    let follows = "untrusted-code/remote-script-run";
    let set_off = "secrets/env-files-read";
    let strict_only = "machine/permissions-weaken";
    assert_eq!(app.rule_reason(follows), None);
    assert_eq!(app.rule_reason(set_off), Some(RuleReason::SetOff));

    // A staged override counts as it will once applied.
    app.pending.push(GuardChange::RuleSet {
        rule: follows.into(),
        value: Some(RuleOverride::Enabled),
    });
    assert_eq!(app.rule_reason(follows), Some(RuleReason::SetOn));

    // Under a guard at core, a rule with only strict parts is waiting, not
    // switched off; under a guard that is off it simply follows.
    assert_eq!(app.rule_state(strict_only), RuleState::Off);
    assert_eq!(
        app.rule_reason(strict_only),
        Some(RuleReason::WaitsForStrict)
    );
    app.pending.push(GuardChange::GuardSet {
        guard: Guard::Machine,
        level: GuardLevel::Off,
    });
    assert_eq!(app.rule_reason(strict_only), None);

    // A nap outranks an override, and a napped guard naps each of its rules.
    app.nap = Some(NapStatus {
        mode: NapMode::Guards(vec!["secrets".into(), follows.into()]),
        remaining: 60,
    });
    assert_eq!(app.rule_reason(set_off), Some(RuleReason::Napping));
    assert_eq!(app.rule_reason(follows), Some(RuleReason::Napping));
    assert_eq!(app.rule_reason(strict_only), None);
    app.nap = Some(NapStatus {
        mode: NapMode::All,
        remaining: 60,
    });
    assert_eq!(app.rule_reason(strict_only), Some(RuleReason::Napping));
}

#[test]
fn the_wake_key_needs_a_nap_to_end() {
    let mut app = App::fixture();
    app.request_wake();
    assert!(app.confirmation.is_none());

    app.nap = Some(NapStatus {
        mode: NapMode::SelfProtection,
        remaining: 30,
    });
    app.request_wake();
    assert_eq!(
        app.confirmation,
        Some(Confirmation::EndNap {
            mode: NapMode::SelfProtection
        })
    );
}

#[test]
fn log_filter_cycles_and_keeps_selection_in_bounds() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log.push(App::saved_record_fixture("decision-0"));
    app.move_selection(true);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Outcome::Block));
    assert_eq!(app.filtered_log().len(), 1);
    assert_eq!(app.selected_log().unwrap().id, "decision-2");
    app.move_selection(true);
    assert_eq!(app.selected_log().unwrap().id, "decision-2");

    // A saved discard is stored as a delegate, and is listed as saved only.
    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Outcome::Saved));
    assert_eq!(matched_ids(&app), vec!["decision-0"]);

    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Outcome::Delegate));
    assert_eq!(matched_ids(&app), vec!["decision-1"]);

    app.cycle_log_filter();
    assert_eq!(app.log_filter, None);
    assert_eq!(app.filtered_log().len(), 3);
}
