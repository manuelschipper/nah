//! Full-screen human configuration for guards, trust, and runtime wiring.

mod app;
mod view;

use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use app::{App, PAGE, Screen};

/// How often an idle session re-checks the audit log for new decisions.
const TICK: Duration = Duration::from_millis(500);

pub(crate) fn run() -> Result<(), String> {
    let mut app = App::load()?;
    ratatui::run(|terminal| session(terminal, &mut app))
        .map_err(|error| format!("terminal interaction failed: {error}"))
}

fn session(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    loop {
        terminal.draw(|frame| view::render(frame, app))?;
        if !event::poll(TICK)? {
            app.poll_log();
            app.poll_nap();
            continue;
        }
        let event = event::read()?;
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind == KeyEventKind::Press {
            match handle_key(app, key) {
                Some(SessionAction::Quit) => return Ok(()),
                Some(SessionAction::ConfigureRuntime) => app.confirm(),
                None => {}
            }
        }
    }
}

/// Actions that need coordination with the full-screen session.
enum SessionAction {
    Quit,
    ConfigureRuntime,
}

fn handle_key(app: &mut App, key: KeyEvent) -> Option<SessionAction> {
    if app.confirmation.is_some() {
        if matches!(
            app.confirmation.as_ref(),
            Some(app::Confirmation::ViewGuard { .. })
        ) {
            match key.code {
                KeyCode::Char('v') | KeyCode::Char('q') | KeyCode::Char('n') | KeyCode::Esc => {
                    app.cancel_confirmation();
                }
                KeyCode::Up => app.scroll_confirmation(false, 1),
                KeyCode::Down => app.scroll_confirmation(true, 1),
                KeyCode::PageUp => app.scroll_confirmation(false, PAGE),
                KeyCode::PageDown => app.scroll_confirmation(true, PAGE),
                _ => {}
            }
            return None;
        }
        match key.code {
            KeyCode::Char('y')
                if matches!(
                    app.confirmation.as_ref(),
                    Some(app::Confirmation::DiscardChanges { .. })
                ) =>
            {
                return Some(SessionAction::Quit);
            }
            KeyCode::Char('y')
                if matches!(
                    app.confirmation.as_ref(),
                    Some(app::Confirmation::ConfigureRuntime { .. })
                ) =>
            {
                return Some(SessionAction::ConfigureRuntime);
            }
            KeyCode::Char('y') => app.confirm(),
            KeyCode::Char('n') | KeyCode::Esc => app.cancel_confirmation(),
            KeyCode::Up => app.scroll_confirmation(false, 1),
            KeyCode::Down => app.scroll_confirmation(true, 1),
            KeyCode::PageUp => app.scroll_confirmation(false, PAGE),
            KeyCode::PageDown => app.scroll_confirmation(true, PAGE),
            _ => {}
        }
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return app.request_quit().then_some(SessionAction::Quit);
    }
    // Typing a search query takes every printable key, so the single-key
    // bindings below stay dormant until Enter confirms or Esc abandons it.
    if app.log_search_editing {
        match key.code {
            KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.push_log_search(character);
            }
            KeyCode::Backspace => app.pop_log_search(),
            KeyCode::Enter => app.confirm_log_search(),
            KeyCode::Esc => app.cancel_log_search(),
            _ => {}
        }
        return None;
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            return app.request_quit().then_some(SessionAction::Quit);
        }
        KeyCode::Char('1') => app.select_screen(Screen::Guards),
        KeyCode::Char('2') => app.select_screen(Screen::Projects),
        KeyCode::Char('3') => app.select_screen(Screen::Runtimes),
        KeyCode::Char('4') => app.select_screen(Screen::Log),
        KeyCode::Tab => app.next_screen(),
        KeyCode::BackTab => app.previous_screen(),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(false),
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(true),
        KeyCode::Char('R') => app.refresh(),
        // The banner is on every screen, so its wake key is too.
        KeyCode::Char('w') => app.request_wake(),
        KeyCode::Char(' ') if is_guard_screen(app.screen) => app.toggle_guard(),
        KeyCode::Char('v') if is_guard_screen(app.screen) => app.view_guard(),
        KeyCode::Char('r') if is_guard_screen(app.screen) => app.reapprove_guard(),
        KeyCode::Char('D') if is_guard_screen(app.screen) => app.reset_to_defaults(),
        KeyCode::Enter if is_guard_screen(app.screen) => app.apply_guards(),
        KeyCode::Char('t') if app.screen == Screen::Projects => app.request_trust_current(),
        KeyCode::Char('u') if app.screen == Screen::Projects => app.request_untrust_selected(),
        KeyCode::Char('i') if app.screen == Screen::Runtimes => app.request_runtime(true),
        KeyCode::Char('u') if app.screen == Screen::Runtimes => app.request_runtime(false),
        KeyCode::Char('v') if app.screen == Screen::Log => app.cycle_log_filter(),
        KeyCode::Char('r') if app.screen == Screen::Log => app.cycle_log_runtime_filter(),
        KeyCode::Char('/') if app.screen == Screen::Log => app.begin_log_search(),
        KeyCode::PageUp if app.screen == Screen::Log => app.scroll_log_detail(false),
        KeyCode::PageDown if app.screen == Screen::Log => app.scroll_log_detail(true),
        _ => {}
    }
    None
}

/// Only the guard screen stages guard changes into the pending batch.
const fn is_guard_screen(screen: Screen) -> bool {
    matches!(screen, Screen::Guards)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nap::NapMode;

    use app::{Confirmation, Message, MessageKind, NapStatus};

    fn press(app: &mut App, code: KeyCode) -> Option<SessionAction> {
        handle_key(app, KeyEvent::new(code, KeyModifiers::NONE))
    }

    #[test]
    fn applying_guards_stays_inside_the_session() {
        let mut app = App::fixture();

        assert!(press(&mut app, KeyCode::Enter).is_none());

        // The apply already ran; only its message is left to render.
        assert_eq!(
            app.message,
            Some(Message {
                kind: MessageKind::Info,
                text: "no guard changes to apply".into(),
            })
        );
    }

    #[test]
    fn viewing_custom_guard_files_is_read_only() {
        let mut app = App::fixture();
        app.guard_index = 1;

        press(&mut app, KeyCode::Char('v'));

        assert!(matches!(
            app.confirmation,
            Some(Confirmation::ViewGuard { .. })
        ));
        assert_eq!(app.pending_count(), 0);

        press(&mut app, KeyCode::Esc);
        assert!(app.confirmation.is_none());
        assert_eq!(app.pending_count(), 0);
    }

    #[test]
    fn wiring_a_runtime_stays_inside_the_session() {
        let mut app = App::fixture();
        app.select_screen(Screen::Runtimes);
        press(&mut app, KeyCode::Char('i'));

        let outcome = press(&mut app, KeyCode::Char('y'));

        assert!(matches!(outcome, Some(SessionAction::ConfigureRuntime)));
        // The session applies this action without leaving the alternate screen.
        assert!(matches!(
            app.confirmation,
            Some(Confirmation::ConfigureRuntime { install: true, .. })
        ));
    }

    #[test]
    fn discarding_pending_changes_quits() {
        let mut app = App::fixture();
        press(&mut app, KeyCode::Char(' '));
        assert!(press(&mut app, KeyCode::Char('q')).is_none());
        assert!(matches!(
            app.confirmation,
            Some(Confirmation::DiscardChanges { count: 1 })
        ));

        assert!(matches!(
            press(&mut app, KeyCode::Char('y')),
            Some(SessionAction::Quit)
        ));
    }

    fn press_with(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> Option<SessionAction> {
        handle_key(app, KeyEvent::new(code, modifiers))
    }

    /// Opens the search on the log screen the way a user does.
    fn searching_app() -> App {
        let mut app = App::fixture();
        app.select_screen(Screen::Log);
        press(&mut app, KeyCode::Char('/'));
        assert!(app.log_search_editing);
        app
    }

    #[test]
    fn typing_a_search_takes_the_keys_its_bindings_own() {
        let mut app = searching_app();

        // Every one of these runs a binding outside input mode.
        for code in [
            KeyCode::Char('q'),
            KeyCode::Char('v'),
            KeyCode::Char('j'),
            KeyCode::Char('k'),
            KeyCode::Char('5'),
            KeyCode::Tab,
        ] {
            assert!(press(&mut app, code).is_none(), "{code:?}");
        }

        assert_eq!(app.log_search, "qvjk5");
        assert_eq!(app.screen, Screen::Log);
        assert_eq!(app.log_filter, None);
        assert!(app.log_search_editing);

        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.log_search, "qvjk");

        press(&mut app, KeyCode::Enter);
        assert!(!app.log_search_editing);
        assert_eq!(app.log_search, "qvjk");
    }

    #[test]
    fn escape_leaves_search_input_with_the_query_cleared() {
        let mut app = searching_app();
        press(&mut app, KeyCode::Char('g'));

        assert!(press(&mut app, KeyCode::Esc).is_none());

        assert!(!app.log_search_editing);
        assert!(app.log_search.is_empty());
        // The next Esc is the quit key again.
        assert!(matches!(
            press(&mut app, KeyCode::Esc),
            Some(SessionAction::Quit)
        ));
    }

    #[test]
    fn control_c_quits_out_of_search_input() {
        let mut app = searching_app();
        press(&mut app, KeyCode::Char('g'));

        // Other control chords are not text and do nothing.
        assert!(press_with(&mut app, KeyCode::Char('v'), KeyModifiers::CONTROL).is_none());
        assert_eq!(app.log_search, "g");

        assert!(matches!(
            press_with(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(SessionAction::Quit)
        ));
    }

    #[test]
    fn r_filters_runtimes_on_the_log_and_re_approves_elsewhere() {
        let mut app = App::fixture();
        app.select_screen(Screen::Log);

        press(&mut app, KeyCode::Char('r'));
        assert_eq!(app.log_runtime_filter.as_deref(), Some("claude"));

        // The same key still belongs to the guard screen.
        app.select_screen(Screen::Guards);
        press(&mut app, KeyCode::Char('r'));
        assert_eq!(app.log_runtime_filter.as_deref(), Some("claude"));
    }

    /// The wake itself writes to the real nap state, so these drive the key up
    /// to the confirmation and cancel it, never past it.
    #[test]
    fn w_offers_to_end_a_nap_only_while_one_is_active() {
        let mut app = App::fixture();

        assert!(press(&mut app, KeyCode::Char('w')).is_none());
        assert!(app.confirmation.is_none());

        app.nap = Some(NapStatus {
            mode: NapMode::All,
            remaining: 120,
        });
        // Every screen answers the key, the log one included.
        for screen in [Screen::Guards, Screen::Log] {
            app.select_screen(screen);
            assert!(press(&mut app, KeyCode::Char('w')).is_none(), "{screen:?}");
            assert!(
                matches!(
                    app.confirmation,
                    Some(Confirmation::EndNap { mode: NapMode::All })
                ),
                "{screen:?}"
            );
            app.cancel_confirmation();
        }
    }

    #[test]
    fn backing_out_of_the_wake_confirmation_leaves_the_nap_alone() {
        for code in [KeyCode::Char('n'), KeyCode::Esc] {
            let mut app = App::fixture();
            let nap = Some(NapStatus {
                mode: NapMode::SelfProtection,
                remaining: 90,
            });
            app.nap = nap;
            press(&mut app, KeyCode::Char('w'));
            assert!(app.confirmation.is_some(), "{code:?}");

            assert!(press(&mut app, code).is_none(), "{code:?}");

            assert!(app.confirmation.is_none(), "{code:?}");
            assert_eq!(app.nap, nap, "{code:?}");
        }
    }

    #[test]
    fn cancelling_a_confirmation_keeps_the_batch() {
        for code in [KeyCode::Char('n'), KeyCode::Esc] {
            let mut app = App::fixture();
            press(&mut app, KeyCode::Char(' '));
            press(&mut app, KeyCode::Char('q'));

            assert!(press(&mut app, code).is_none(), "{code:?}");

            assert!(app.confirmation.is_none(), "{code:?}");
            assert_eq!(app.pending_count(), 1, "{code:?}");
        }
    }
}
