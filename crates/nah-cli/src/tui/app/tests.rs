use super::*;

#[test]
fn built_in_changes_stage_without_writing() {
    let mut app = App::fixture();
    app.toggle_guard();
    assert_eq!(app.pending_count(), 1);
    assert_eq!(app.pending_value(&app.guards[0]), Some(false));
    assert!(app.confirmation.is_none());
    app.toggle_guard();
    assert_eq!(app.pending_count(), 0);
}

#[test]
fn changed_custom_guard_stages_the_reviewed_hash() {
    let mut app = App::fixture();
    app.guard_index = 1;
    app.toggle_guard();
    assert!(matches!(
        app.confirmation,
        Some(Confirmation::ApproveGuard {
            reapproval: true,
            ..
        })
    ));
    assert_eq!(app.pending_count(), 0);
    app.confirm();
    assert_eq!(app.pending_value(&app.guards[1]), Some(true));
    assert_eq!(app.pending[0].expected_hash.as_deref(), Some("new"));
    app.toggle_guard();
    assert_eq!(app.pending_count(), 0);
}

#[test]
fn same_named_scoped_guards_do_not_share_pending_state() {
    let mut app = App::fixture();
    let mut user = app.guards[1].clone();
    user.target = GuardTarget::Custom {
        identity: nah_proto::ctx::GuardIdentity::user("corp-api").unwrap(),
    };
    app.guards.push(user);

    app.guard_index = 1;
    app.toggle_guard();
    app.confirm();

    assert_eq!(app.pending_value(&app.guards[1]), Some(true));
    assert_eq!(app.pending_value(&app.guards[3]), None);
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
fn trust_confirmation_inventories_the_project_proposals() {
    let temp = tempfile::tempdir().unwrap();
    let extensions = temp.path().join(".nah");
    std::fs::create_dir_all(extensions.join("guards").join("corp-api")).unwrap();
    let root = temp.path().to_str().unwrap().to_owned();

    let mut app = App::fixture();
    app.current_project = Some(root.clone());
    app.request_trust_current();

    assert_eq!(
        app.confirmation,
        Some(Confirmation::TrustCurrent {
            path: root,
            proposals: GuardProposals { guards: 1 },
        })
    );
}

#[test]
fn current_untrusted_project_participates_in_project_selection() {
    let mut app = App::fixture();
    app.screen = Screen::Projects;
    app.current_project = Some("/other".into());

    assert_eq!(app.project_count(), 2);
    assert_eq!(app.selected_project().unwrap().path, "/other");
    assert!(app.selected_project().unwrap().trusted.is_none());

    app.request_untrust_selected();
    assert!(app.confirmation.is_none());
    assert_eq!(
        app.message.as_ref().map(|message| message.text.as_str()),
        Some("the selected project is not trusted")
    );

    app.move_selection(true);
    assert_eq!(app.selected_project().unwrap().path, "/repo");
    assert!(app.selected_project().unwrap().trusted.is_some());
}

#[test]
fn failed_preflight_preserves_the_complete_batch() {
    let mut app = App::fixture();
    app.guard_index = 1;
    app.toggle_guard();
    app.confirm();
    app.guard_index = 2;
    app.toggle_guard();

    assert_eq!(app.pending_count(), 2);

    app.apply_guards();

    assert_eq!(app.pending_count(), 2);
    assert!(app.pending[0].enabled);
    assert!(app.pending[1].enabled);
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
        path: None,
        status,
        behavior: None,
        examples: vec![],
        match_programs: vec![],
        current_hash: None,
    }
}

fn built_in(name: &str) -> GuardTarget {
    GuardTarget::BuiltIn { name: name.into() }
}

fn custom(name: &str) -> GuardTarget {
    GuardTarget::Custom {
        identity: nah_proto::ctx::GuardIdentity::user(name).unwrap(),
    }
}

fn staged(app: &App) -> Vec<(&str, bool)> {
    app.pending
        .iter()
        .map(|change| (change.target.name(), change.enabled))
        .collect()
}

#[test]
fn resetting_stages_the_diff_from_the_shipped_defaults() {
    let mut app = App::fixture();
    app.guards.extend([
        guard_entry(built_in("fs-root"), GuardStatus::Disabled),
        guard_entry(custom("vendor-sync"), GuardStatus::Enabled),
        guard_entry(
            custom("vanished"),
            GuardStatus::Missing {
                approved_hash: "old".into(),
            },
        ),
    ]);

    app.reset_to_defaults();

    // The enabled built-in guard already ships that way, so it is not
    // staged; the disabled one is drift and is.
    assert_eq!(
        staged(&app),
        vec![
            ("corp-api", false),
            ("secrets-env", true),
            ("fs-root", true),
            ("vendor-sync", false),
            ("vanished", false),
        ]
    );
    // Nothing here enables a custom guard, so no review is asked for.
    assert!(app.confirmation.is_none());
    assert!(
        app.pending
            .iter()
            .all(|change| change.expected_hash.is_none())
    );
    assert_eq!(
        app.message,
        Some(Message {
            kind: MessageKind::Info,
            text: "reset to shipped defaults staged: 5 change(s); Enter to apply".into(),
        })
    );
}

#[test]
fn resetting_replaces_the_staged_batch() {
    let mut app = App::fixture();
    app.guards
        .push(guard_entry(built_in("fs-root"), GuardStatus::Disabled));
    app.toggle_guard();
    app.guard_index = 2;
    app.toggle_guard();
    assert_eq!(app.pending_count(), 2);

    app.reset_to_defaults();

    // Both hand-staged toggles moved an entry away from its default, so
    // the reset drops them and stages only the real drift.
    assert_eq!(
        staged(&app),
        vec![
            ("corp-api", false),
            ("secrets-env", true),
            ("fs-root", true)
        ]
    );
}

#[test]
fn resetting_at_the_defaults_clears_the_batch() {
    let mut app = App::fixture();
    // The fixture's enabled built-in alone is the shipped posture.
    app.guards
        .retain(|entry| entry.target.name() == "exec-remote");
    app.toggle_guard();
    assert_eq!(app.pending_count(), 1);

    app.reset_to_defaults();

    assert_eq!(app.pending_count(), 0);
    assert_eq!(
        app.message,
        Some(Message {
            kind: MessageKind::Info,
            text: "already at shipped defaults".into(),
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
    assert_eq!(app.screen, Screen::Projects);
}

#[test]
fn the_guard_screen_keeps_its_selection_across_screens() {
    let mut app = App::fixture();
    app.move_selection(true);
    assert_eq!(app.guard_index, 1);
    assert_eq!(app.selected_guard().unwrap().target.name(), "corp-api");

    app.select_screen(Screen::Projects);
    assert!(app.selected_guard().is_none());
    app.move_selection(true);
    assert_eq!(app.guard_index, 1);

    app.select_screen(Screen::Guards);
    assert_eq!(app.selected_guard().unwrap().target.name(), "corp-api");
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
    app.log_filter = Some(Verdict::Delegate);
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
    app.scroll_log_detail(true);
    assert!(app.log_detail_scroll > 0);

    app.move_selection(true);
    assert_eq!(app.log_detail_scroll, 0);

    app.scroll_log_detail(true);
    app.cycle_log_filter();
    assert_eq!(app.log_detail_scroll, 0);

    // A reload that keeps the same record under the cursor keeps the offset.
    app.log_filter = None;
    app.log_index = 1;
    app.scroll_log_detail(true);
    let scrolled = app.log_detail_scroll;
    assert!(scrolled > 0);
    let mut log = vec![App::record_fixture("decision-3", Verdict::Delegate)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");
    assert_eq!(app.log_detail_scroll, scrolled);
}

#[test]
fn verdict_counts_cover_the_loaded_window() {
    let mut app = App::fixture();
    app.log_filter = Some(Verdict::Delegate);

    assert_eq!(
        app.verdict_counts(),
        [(Verdict::Delegate, 1), (Verdict::Block, 1)]
    );
}

#[test]
fn block_filter_uses_its_independent_history() {
    let mut app = App::fixture();
    app.log = vec![App::record_fixture("decision-recent", Verdict::Delegate)];
    app.blocked_log = vec![App::record_fixture("decision-old-block", Verdict::Block)];

    app.log_filter = Some(Verdict::Block);

    assert_eq!(app.filtered_log().len(), 1);
    assert_eq!(app.selected_log().unwrap().id, "decision-old-block");
}

#[test]
fn approval_scroll_is_bounded_and_clears_with_the_modal() {
    let mut app = App::fixture();
    app.guard_index = 1;
    app.confirmation = Some(Confirmation::ApproveGuard {
        target: app.guards[1].target.clone(),
        name: "corp-api".into(),
        path: "/repo/.nah/guards/corp-api".into(),
        hash: "new".into(),
        reapproval: true,
        source: Ok(source_fixture(12)),
    });

    app.scroll_confirmation(true, PAGE);
    assert_eq!(app.confirmation_scroll, PAGE);
    for _ in 0..5 {
        app.scroll_confirmation(true, PAGE);
    }
    // One header line plus twelve content lines.
    assert_eq!(app.confirmation_scroll, 13);
    app.scroll_confirmation(false, PAGE);
    assert_eq!(app.confirmation_scroll, 3);

    app.cancel_confirmation();
    assert_eq!(app.confirmation_scroll, 0);
}

#[cfg(test)]
pub(super) fn source_fixture(lines: usize) -> GuardSource {
    GuardSource {
        files: vec![crate::commands::GuardSourceFile {
            name: "run".into(),
            text: Ok((0..lines)
                .map(|line| format!("print({line})\n"))
                .collect::<String>()),
        }],
        truncated: None,
    }
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
    app.log[0].display = "Bash: curl request, network outbound [redacted] (+2)".into();
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
    assert_eq!(app.log_filter, Some(Verdict::Block));
    assert_eq!(matched_ids(&app), vec!["decision-2"]);

    // The block filter reads the independent block history.
    assert_eq!(
        app.verdict_counts(),
        [(Verdict::Delegate, 0), (Verdict::Block, 1)]
    );
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
    assert_eq!(app.log_filter, Some(Verdict::Block));
    assert!(matched_ids(&app).is_empty());
    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Verdict::Delegate));
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
    app.scroll_log_detail(true);
    assert_eq!(app.log_index, 1);

    app.begin_log_search();
    // Opening the query alone changes nothing about the list.
    assert_eq!(app.log_index, 1);

    app.push_log_search('c');
    assert_eq!(app.log_index, 0);
    assert_eq!(app.log_detail_scroll, 0);

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
fn the_nap_banner_names_its_kind_and_counts_down_to_the_second() {
    let banner = |mode, remaining| NapStatus { mode, remaining }.banner();

    assert_eq!(
        banner(NapMode::SelfProtection, 600),
        "NAP: self-protection paused \u{2014} 10m 00s left (w wake)"
    );
    assert_eq!(
        banner(NapMode::All, 372),
        "NAP: all enforcement paused \u{2014} 6m 12s left (w wake)"
    );
    // Under a minute the minutes are dropped rather than shown as zero.
    assert_eq!(
        banner(NapMode::All, 60),
        "NAP: all enforcement paused \u{2014} 1m 00s left (w wake)"
    );
    assert_eq!(
        banner(NapMode::All, 59),
        "NAP: all enforcement paused \u{2014} 59s left (w wake)"
    );
    assert_eq!(
        banner(NapMode::All, 0),
        "NAP: all enforcement paused \u{2014} 0s left (w wake)"
    );
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
    app.move_selection(true);
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Verdict::Block));
    assert_eq!(app.filtered_log().len(), 1);
    assert_eq!(app.selected_log().unwrap().id, "decision-2");
    app.move_selection(true);
    assert_eq!(app.selected_log().unwrap().id, "decision-2");

    app.cycle_log_filter();
    assert_eq!(app.log_filter, Some(Verdict::Delegate));
    assert_eq!(app.selected_log().unwrap().id, "decision-1");

    app.cycle_log_filter();
    assert_eq!(app.log_filter, None);
    assert_eq!(app.filtered_log().len(), 2);
}
