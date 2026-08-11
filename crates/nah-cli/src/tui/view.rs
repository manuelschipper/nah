//! Rendering for the four-screen configuration and log UI.

use nah_proto::decision::Verdict;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};

use crate::commands::{
    GuardProposals, GuardSource, GuardSourceFile, GuardStatus, GuardTarget, RuntimeHookStatus,
    scope_name,
};
use crate::nap::NapMode;
use crate::records::{detail_field, short_time, verdict_name};
use crate::runtime::FailurePolicy;

use super::app::{App, Confirmation, MessageKind, NapStatus, Screen, status_name};

const SELECTED: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

/// Columns a log row spends on the deciding runtime: the longest name an
/// adapter stamps (`antigravity`) plus a separating space.
const RUNTIME_WIDTH: usize = 12;

pub(crate) fn render(frame: &mut Frame<'_>, app: &App) {
    if frame.area().width < 50 || frame.area().height < 14 {
        render_too_small(frame, app);
        return;
    }
    let footer_height = if frame.area().width < 90 { 4 } else { 3 };
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(footer_height),
        ])
        .split(frame.area());
    render_tabs(frame, app, areas[0]);
    // A banner exists only while a nap does, and takes its row from the body,
    // so the tab bar and footer keep their sizes at the minimum height.
    let body_area = match app.nap {
        Some(nap) => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(1)])
                .split(areas[1]);
            render_nap(frame, nap, rows[0]);
            rows[1]
        }
        None => areas[1],
    };
    let stacked = frame.area().width < 90 || frame.area().height < 22;
    let body = Layout::default()
        .direction(if stacked {
            Direction::Vertical
        } else {
            Direction::Horizontal
        })
        .constraints(if stacked {
            [Constraint::Percentage(48), Constraint::Percentage(52)]
        } else if app.screen == Screen::Log {
            // Log rows carry time, verdict, and full runtime name before the
            // command; the wider list keeps the command legible at 100 columns.
            [Constraint::Percentage(60), Constraint::Percentage(40)]
        } else {
            [Constraint::Percentage(43), Constraint::Percentage(57)]
        })
        .split(body_area);
    match app.screen {
        Screen::Guards => render_guards(frame, app, body[0], body[1]),
        Screen::Projects => render_projects(frame, app, body[0], body[1]),
        Screen::Runtimes => render_runtimes(frame, app, body[0], body[1]),
        Screen::Log => render_log(frame, app, body[0], body[1]),
    }
    render_footer(frame, app, areas[2]);
    if let Some(confirmation) = &app.confirmation {
        render_confirmation(frame, confirmation, app.confirmation_scroll);
    }
    if app.help_open {
        render_help(frame, app);
    }
}

fn render_too_small(frame: &mut Frame<'_>, app: &App) {
    let pending = app.pending_count();
    let text = if app.help_open {
        format!(
            "nah help \u{2014} {}\n\nResize to at least 50x14 for contextual help.\n\n? or Esc close",
            help_title(app.screen)
        )
    } else if let Some(confirmation) = &app.confirmation {
        let action = match confirmation {
            Confirmation::DiscardChanges { .. } => "y discard and quit  n cancel",
            Confirmation::ApproveGuard { .. } => "y stage enable  n cancel",
            Confirmation::ViewGuard { .. } => "Esc close",
            Confirmation::TrustCurrent { .. } => "y trust  n cancel",
            Confirmation::UntrustProject { .. } => "y untrust  n cancel",
            Confirmation::ConfigureRuntime {
                failure_policy: Some(_),
                configured: true,
                ..
            } => "y switch  n cancel",
            Confirmation::ConfigureRuntime {
                failure_policy: Some(_),
                configured: false,
                ..
            } => "y install  n cancel",
            Confirmation::ConfigureRuntime { install, .. } if *install => "y install  n cancel",
            Confirmation::ConfigureRuntime { .. } => "y uninstall  n cancel",
            Confirmation::EndNap { .. } => "y wake  n cancel",
        };
        format!("nah\n\n{action}\n\nResize to at least 50x14 for details.")
    } else {
        format!(
            "nah\n\nTerminal too small. Resize to at least 50x14.\n\n{pending} pending change(s)  ? help  q quit"
        )
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        frame.area(),
    );
}

/// A paused installation is the one thing worth interrupting every screen for,
/// so the banner takes a full inverted row. The colour separates the two kinds
/// as plainly as the text does, since `--all` pauses far more.
fn render_nap(frame: &mut Frame<'_>, nap: NapStatus, area: Rect) {
    let style = Style::new()
        .fg(Color::Black)
        .bg(match nap.mode {
            NapMode::SelfProtection => Color::Yellow,
            NapMode::All => Color::Red,
        })
        .add_modifier(Modifier::BOLD);
    frame.render_widget(
        Paragraph::new(nap.banner())
            .style(style)
            .alignment(Alignment::Center),
        area,
    );
}

fn render_tabs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let selected = match app.screen {
        Screen::Guards => 0,
        Screen::Projects => 1,
        Screen::Runtimes => 2,
        Screen::Log => 3,
    };
    frame.render_widget(
        Tabs::new([
            tab_label("1 Guards", app.pending_count(), '*'),
            "2 Projects".into(),
            "3 Runtimes".into(),
            tab_label("4 Log", app.new_blocks, '!'),
        ])
        .select(selected)
        .block(Block::default().title(" nah ").borders(Borders::ALL))
        .highlight_style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .divider(" | "),
        area,
    );
}

/// `marker` separates staged changes (`*`) from unread block decisions (`!`).
fn tab_label(name: &str, count: usize, marker: char) -> String {
    if count == 0 {
        name.to_owned()
    } else {
        format!("{name} ({count}{marker})")
    }
}

fn render_guards(frame: &mut Frame<'_>, app: &App, list_area: Rect, detail_area: Rect) {
    let items = app
        .guards
        .iter()
        .map(|entry| {
            let pending = app.pending_value(entry);
            let (marker, status_style) = if let Some(enabled) = pending {
                (
                    if enabled { "[x]*" } else { "[ ]*" },
                    Style::new().fg(Color::Yellow),
                )
            } else {
                match entry.status {
                    GuardStatus::Enabled => ("[x] ", Style::default()),
                    GuardStatus::Disabled => ("[ ] ", Style::default()),
                    GuardStatus::NeedsReapproval { .. } => ("[!] ", Style::new().fg(Color::Yellow)),
                    GuardStatus::Missing { .. } => ("[?] ", Style::new().fg(Color::Red)),
                }
            };
            ListItem::new(Line::from(vec![
                ratatui::text::Span::styled(marker, status_style),
                ratatui::text::Span::raw(entry.target.name()),
                ratatui::text::Span::raw(format!("  {}", guard_scope_name(&entry.target))),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(app.guard_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(" Guards ").borders(Borders::ALL))
            .highlight_style(SELECTED)
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );

    let text = app
        .selected_guard()
        .map(guard_details)
        .unwrap_or_else(|| Text::from("No guards discovered."));
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Details ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn guard_details(entry: &crate::commands::GuardEntry) -> Text<'static> {
    let mut lines = vec![Line::styled(
        entry.target.name().to_owned(),
        Style::new().add_modifier(Modifier::BOLD),
    )];
    match &entry.target {
        GuardTarget::BuiltIn { .. } => {
            lines.push(Line::from("Source: built-in"));
            lines.push(Line::from("Applies: everywhere nah is active"));
        }
        GuardTarget::Custom { identity, .. } => {
            lines.push(Line::from(format!(
                "Source: {} guard",
                scope_name(identity.scope())
            )));
            lines.push(Line::from(match identity.scope() {
                nah_proto::ctx::GuardScope::User => "Applies: all projects for this user",
                nah_proto::ctx::GuardScope::Project => {
                    "Applies: its trusted project and descendants"
                }
            }));
            lines.push(Line::from(format!(
                "Path: {}",
                entry
                    .path
                    .as_ref()
                    .map_or_else(|| "missing".into(), |path| path.display().to_string())
            )));
        }
    }
    match &entry.status {
        GuardStatus::Enabled => lines.push(Line::from("Status: enabled")),
        GuardStatus::Disabled => lines.push(Line::from("Status: disabled")),
        GuardStatus::NeedsReapproval {
            approved_hash,
            current_hash,
        } => {
            lines.push(Line::styled(
                "Status: needs re-approval",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::from(format!("Approved: {approved_hash}")));
            lines.push(Line::from(format!("Current:  {current_hash}")));
            lines.push(Line::from(""));
            lines.push(Line::from("Press r to review and stage re-approval."));
        }
        GuardStatus::Missing { approved_hash } => {
            lines.push(Line::styled(
                "Status: approved files are missing",
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::from(format!("Approved: {approved_hash}")));
            lines.push(Line::from(""));
            lines.push(Line::from("Space stages removal of the stale approval."));
        }
    }
    if let Some(behavior) = &entry.behavior {
        lines.push(Line::from(""));
        lines.push(Line::from(behavior.clone()));
    }
    if !entry.examples.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Examples nah blocks:"));
        lines.extend(
            entry
                .examples
                .iter()
                .map(|example| Line::from(format!("- {example}"))),
        );
    }
    if !entry.match_programs.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "Matches: {}",
            entry.match_programs.join(", ")
        )));
    }
    if matches!(entry.target, GuardTarget::Custom { .. }) {
        lines.push(Line::from(""));
        lines.push(Line::from("Press v to view guard files."));
    }
    Text::from(lines)
}

fn guard_scope_name(target: &GuardTarget) -> &'static str {
    target.scope().map_or("built-in", scope_name)
}

fn render_projects(frame: &mut Frame<'_>, app: &App, list_area: Rect, detail_area: Rect) {
    let items = (0..app.project_count())
        .filter_map(|index| app.project_at(index))
        .map(|project| {
            let marker = if project.current { "* " } else { "  " };
            let status = if project.trusted.is_some() {
                "trusted"
            } else {
                "not trusted"
            };
            ListItem::new(format!("{marker}[{status}] {}", project.path))
        })
        .collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(app.project_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Projects (* current) ")
                    .borders(Borders::ALL),
            )
            .highlight_style(SELECTED)
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );
    let text = match app.selected_project() {
        Some(project) => project_details(project),
        None => Text::from(vec![
            Line::from("No projects available."),
            Line::from(""),
            Line::from("Open nah from a project directory to trust it."),
        ]),
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Details ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn project_details(project: crate::tui::app::ProjectSelection<'_>) -> Text<'static> {
    let mut lines = vec![
        Line::styled(
            project.path.to_owned(),
            Style::new().add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(
            "Current project: {}",
            if project.current { "yes" } else { "no" }
        )),
        Line::from(format!(
            "Status: {}",
            if project.trusted.is_some() {
                "trusted"
            } else {
                "not trusted"
            }
        )),
        Line::from(""),
        Line::from("Trust allows this project to offer custom guards."),
        Line::from("Each guard must still be reviewed and enabled separately."),
        Line::from(""),
    ];
    if let Some(trusted) = project.trusted {
        lines.extend([
            Line::from("Project guards"),
            Line::from(format!("  Enabled: {}", trusted.enabled_guards)),
            Line::from(format!("  Need review: {}", trusted.needs_reapproval)),
            Line::from(format!("  Unavailable: {}", trusted.missing_guards)),
            Line::from(""),
            Line::from("Press 1 to review project guards."),
            Line::from("Press u to untrust this project."),
            Line::from("Untrusting also disables its project guards."),
        ]);
    } else {
        lines.extend([
            Line::from("Project guards are ignored until this project is trusted."),
            Line::from("Trusting does not enable guards automatically."),
            Line::from(""),
            Line::from("Press t to trust this project."),
        ]);
    }
    Text::from(lines)
}

fn render_runtimes(frame: &mut Frame<'_>, app: &App, list_area: Rect, detail_area: Rect) {
    let items = app
        .runtimes
        .iter()
        .map(|runtime| {
            let (status, style) = match &runtime.status {
                Ok(status) => (
                    status_name(*status),
                    match status {
                        RuntimeHookStatus::WiringCurrent
                        | RuntimeHookStatus::WiringCurrentFailClosed => {
                            Style::new().fg(Color::Green)
                        }
                        RuntimeHookStatus::NotConfigured => Style::default(),
                        RuntimeHookStatus::NeedsReinstall
                        | RuntimeHookStatus::NeedsReinstallFailClosed => {
                            Style::new().fg(Color::Yellow)
                        }
                    },
                ),
                Err(_) => ("cannot inspect", Style::new().fg(Color::Red)),
            };
            ListItem::new(Line::from(vec![
                ratatui::text::Span::raw(format!("{:<15}", runtime.name)),
                ratatui::text::Span::styled(status, style),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(app.runtime_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Runtime integrations ")
                    .borders(Borders::ALL),
            )
            .highlight_style(SELECTED)
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );
    let text = match app.selected_runtime() {
        Some(runtime) => {
            let mut lines = vec![
                Line::styled(runtime.name, Style::new().add_modifier(Modifier::BOLD)),
                Line::from(""),
            ];
            match &runtime.status {
                Ok(status) => {
                    let wiring = match status {
                        RuntimeHookStatus::WiringCurrent
                        | RuntimeHookStatus::WiringCurrentFailClosed => "wiring current",
                        RuntimeHookStatus::NotConfigured => "not configured",
                        RuntimeHookStatus::NeedsReinstall
                        | RuntimeHookStatus::NeedsReinstallFailClosed => "reinstall required",
                    };
                    let current = status.failure_policy();
                    let target = match current {
                        FailurePolicy::Delegate => FailurePolicy::Block,
                        FailurePolicy::Block => FailurePolicy::Delegate,
                    };
                    lines.push(Line::from(format!("Status: {wiring}")));
                    lines.push(Line::from(format!(
                        "Failure mode: {}{}",
                        current.cli_name(),
                        if matches!(status, RuntimeHookStatus::NotConfigured) {
                            " on install"
                        } else {
                            ""
                        }
                    )));
                    lines.push(Line::from(""));
                    lines.push(Line::from(format!(
                        "[f] {} {}",
                        if matches!(status, RuntimeHookStatus::NotConfigured) {
                            "Install with"
                        } else {
                            "Switch to"
                        },
                        target.cli_name()
                    )));
                    lines.push(Line::from(
                        if matches!(status, RuntimeHookStatus::NotConfigured) {
                            "[i] Install with fail-open"
                        } else {
                            "[i] Reinstall wiring"
                        },
                    ));
                    lines.push(Line::from("[u] Uninstall wiring"));
                }
                Err(error) => {
                    lines.push(Line::from(format!("Status: cannot inspect ({error})")));
                    lines.push(Line::from(""));
                    lines.push(Line::from("[i] Install or repair wiring"));
                    lines.push(Line::from("[u] Uninstall wiring"));
                }
            }
            lines.extend([
                Line::from(""),
                Line::from("Restart or reload the runtime after wiring changes."),
                Line::from(""),
                Line::from(format!("Docs: nah docs {}", runtime.docs_topic)),
            ]);
            Text::from(lines)
        }
        None => Text::from("No supported runtimes."),
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Details ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn render_log(frame: &mut Frame<'_>, app: &App, list_area: Rect, detail_area: Rect) {
    let records = app.filtered_log();
    let items = records
        .iter()
        .map(|record| {
            let (outcome, style) = match record.verdict {
                Some(Verdict::Block) => ("block", Style::new().fg(Color::Red)),
                Some(Verdict::Delegate) => ("delegate", Style::new().fg(Color::Yellow)),
                None => ("unavailable", Style::new().fg(Color::Magenta)),
            };
            ListItem::new(Line::from(vec![
                ratatui::text::Span::raw(format!("{} ", short_time(&record.timestamp))),
                ratatui::text::Span::styled(format!("{outcome:<9}"), style),
                // A name longer than any adapter stamps today simply pushes the
                // command right and clips at the pane edge.
                ratatui::text::Span::styled(
                    format!("{:<RUNTIME_WIDTH$}", record.runtime),
                    Style::new().add_modifier(Modifier::DIM),
                ),
                ratatui::text::Span::raw(record.display.clone()),
            ]))
        })
        .collect::<Vec<_>>();
    let title = format!(
        " Decisions ({}: {} of {}) ",
        log_scope(app),
        records.len(),
        app.log_window().len()
    );
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(app.log_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(SELECTED)
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );

    let mut text = app.selected_log().map_or_else(
        || {
            Text::from(if app.log_window().is_empty() {
                "No decisions recorded."
            } else {
                "No decisions match the filter."
            })
        },
        |record| {
            let mut lines = record
                .explanation
                .lines()
                .map(|line| Line::from(line.to_owned()))
                .collect::<Vec<_>>();
            lines.insert(
                1.min(lines.len()),
                Line::from(detail_field("time:", &record.timestamp)),
            );
            Text::from(lines)
        },
    );
    if let Some(summary) = &app.failure_summary {
        text.lines.insert(0, Line::from(""));
        text.lines.insert(0, Line::from(summary.display()));
    }
    let scroll = clamped_scroll(&text, detail_area, app.log_detail_scroll);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Details ").borders(Borders::ALL))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        detail_area,
    );
}

/// Bounds a stored scroll offset by what the bordered `area` can still show.
fn clamped_scroll(text: &Text<'_>, area: Rect, scroll: u16) -> u16 {
    let height = wrapped_height(&text.lines, area.width.saturating_sub(2));
    let visible = usize::from(area.height.saturating_sub(2));
    scroll.min(u16::try_from(height.saturating_sub(visible)).unwrap_or(u16::MAX))
}

/// Lines `content` occupies once wrapped into `width` columns.
fn wrapped_height(content: &[Line<'_>], width: u16) -> usize {
    let width = usize::from(width).max(1);
    content
        .iter()
        .map(|line| line.width().max(1).div_ceil(width))
        .sum()
}

/// Verdict totals for the loaded window, zero counts omitted.
fn verdict_counts(app: &App) -> String {
    let mut counts = app
        .verdict_counts()
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(verdict, count)| format!("{count} {}", verdict_name(*verdict)))
        .collect::<Vec<_>>();
    let unavailable = app
        .log_window()
        .iter()
        .filter(|record| record.verdict.is_none())
        .count();
    if unavailable > 0 {
        counts.push(format!("{unavailable} unavailable"));
    }
    if counts.is_empty() {
        "no decisions".to_owned()
    } else {
        counts.join(", ")
    }
}

const fn filter_name(filter: Option<Verdict>) -> &'static str {
    match filter {
        None => "all",
        Some(verdict) => verdict_name(verdict),
    }
}

fn runtime_filter_name(app: &App) -> &str {
    app.log_runtime_filter.as_deref().unwrap_or("all")
}

/// What narrowed the list, so the counts beside it can be read against it.
fn log_scope(app: &App) -> String {
    let mut scope = filter_name(app.log_filter).to_owned();
    if let Some(runtime) = &app.log_runtime_filter {
        scope.push_str(&format!(", {runtime}"));
    }
    if !app.log_search.is_empty() {
        scope.push_str(&format!(", /{}", app.log_search));
    }
    scope
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let keys = match app.screen {
        Screen::Guards => format!(
            "Space toggle  v files  r review  Enter apply  ? help  {} pending",
            app.pending_count()
        ),
        Screen::Projects => "t trust current  u untrust selected  ? help".into(),
        Screen::Runtimes => "f mode  i install/reinstall  u uninstall  ? help".into(),
        // Typing replaces the keymap, so the query stays visible even where the
        // list title is too narrow to show all of it.
        Screen::Log if app.log_search_editing => format!("/{}\u{2588}", app.log_search),
        Screen::Log => format!(
            "/ search  v filter: {} ({})  r runtime: {}  PgUp/PgDn detail  ? help",
            filter_name(app.log_filter),
            verdict_counts(app),
            runtime_filter_name(app)
        ),
    };
    // While typing, q is a letter rather than the quit key.
    let idle = if app.log_search_editing {
        "Enter search  Esc cancel"
    } else {
        "Tab screen  R refresh  q quit"
    };
    let (message, style) = app
        .message
        .as_ref()
        .map_or((idle, Style::default()), |message| {
            let color = match message.kind {
                MessageKind::Info => Color::White,
                MessageKind::Success => Color::Green,
                MessageKind::Error => Color::Red,
            };
            (message.text.as_str(), Style::new().fg(color))
        });
    frame.render_widget(
        Paragraph::new(vec![Line::from(keys), Line::styled(message, style)])
            .block(Block::default().borders(Borders::TOP))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, app: &App) {
    let text = help_lines(app);
    let width = frame.area().width.saturating_sub(2).clamp(48, 84);
    let content_height = wrapped_height(&text, width.saturating_sub(2));
    let height = u16::try_from(content_height.saturating_add(2))
        .unwrap_or(u16::MAX)
        .min(frame.area().height);
    let area = centered_rect(width, height, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(format!(" Help \u{2014} {} ", help_title(app.screen)))
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn help_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![help_heading("ABOUT")];
    lines.extend(match app.screen {
        Screen::Guards => vec![
            Line::from("Guards block understood danger; they never approve a call."),
            Line::from("Built-ins ship with nah. User guards are eligible everywhere."),
            Line::from("Project guards are eligible only in a trusted root and its descendants."),
            Line::from("Changed custom guard files require review before re-enabling."),
            Line::from("Changes stay pending until Enter applies them."),
            Line::from(""),
            help_heading("KEYS"),
            Line::from("Space toggle  v view files  r review changes"),
            Line::from("D reset defaults  Enter apply"),
        ],
        Screen::Projects => vec![
            Line::from("Trust lets a project offer custom guards from its .nah/ directory."),
            Line::from("Those guards are eligible only in the project root and its descendants."),
            Line::from("Trust does not enable guards; each still needs review and enablement."),
            Line::from("Untrusting also disables its project guards."),
            Line::from(""),
            help_heading("KEYS"),
            Line::from("t trust current  u untrust selected"),
            Line::from("1 open Guards to review project guards"),
        ],
        Screen::Runtimes => vec![
            Line::from("Runtime wiring lets nah inspect supported tool calls before execution."),
            Line::from("Fail-open (default): explicit evaluation failures and refusals delegate."),
            Line::from("Fail-closed: those failures and refusals block."),
            Line::from("Ordinary unknown or uncertain calls delegate in either mode."),
            Line::from("nah never approves a call; delegation returns control to the runtime."),
            Line::from(""),
            help_heading("KEYS"),
            Line::from("f change failure mode"),
            Line::from("i install/reinstall  u uninstall"),
        ],
        Screen::Log => vec![
            Line::from("Block means a guard or self-protection found definite danger."),
            Line::from("Delegate means nah did not block; the runtime keeps control."),
            Line::from("Delegate is not approval."),
            Line::from("Unavailable means no valid decision was produced."),
            Line::from("The log stores redacted decision details."),
            Line::from(""),
            help_heading("KEYS"),
            Line::from("/ search  v verdict filter  r runtime filter"),
            Line::from("PgUp/PgDn scroll details"),
        ],
    });
    if let Some(confirmation) = &app.confirmation {
        lines.extend([
            Line::from(""),
            help_heading("OPEN PROMPT"),
            Line::from(match confirmation {
                Confirmation::ViewGuard { .. } => {
                    "Close help, then v, q, n, or Esc closes the file view."
                }
                _ => "Close help, then y confirms; n or Esc cancels.",
            }),
            Line::from("Up/Down or PgUp/PgDn scrolls long prompt details."),
        ]);
    }
    lines.extend([
        Line::from(""),
        help_heading("GLOBAL"),
        Line::from("1-4 open tab  Tab/Shift-Tab cycle tabs"),
        Line::from("Up/Down or j/k move  R refresh  q quit"),
    ]);
    if app.nap.is_some() {
        lines.push(Line::from("w end the active nap"));
    }
    lines.push(Line::from("? or Esc close help"));
    lines
}

fn help_heading(text: &'static str) -> Line<'static> {
    Line::styled(
        text,
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )
}

const fn help_title(screen: Screen) -> &'static str {
    match screen {
        Screen::Guards => "Guards",
        Screen::Projects => "Projects",
        Screen::Runtimes => "Runtime integrations",
        Screen::Log => "Decision log",
    }
}

fn render_confirmation(frame: &mut Frame<'_>, confirmation: &Confirmation, scroll: u16) {
    let text = confirmation_lines(confirmation);
    let width = frame.area().width.saturating_sub(2).clamp(40, 84);
    match confirmation {
        Confirmation::ApproveGuard { source, .. } => {
            render_guard_files(frame, text, source, width, scroll, true);
            return;
        }
        Confirmation::ViewGuard { source, .. } => {
            render_guard_files(frame, text, source, width, scroll, false);
            return;
        }
        _ => {}
    }
    let content_height = wrapped_height(&text, width.saturating_sub(2));
    let height = u16::try_from(content_height.saturating_add(2))
        .unwrap_or(u16::MAX)
        .min(frame.area().height);
    let area = centered_rect(width, height, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Confirm ")
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Approval shows the bytes the hash covers, so it takes the tall overlay:
/// a fixed header with the pinned identity and a scrollable source pane.
fn render_guard_files(
    frame: &mut Frame<'_>,
    header: Vec<Line<'static>>,
    source: &Result<GuardSource, String>,
    width: u16,
    scroll: u16,
    approval: bool,
) {
    let text = Text::from(source_lines(source));
    let inner_width = width.saturating_sub(2);
    let header_height = u16::try_from(wrapped_height(&header, inner_width)).unwrap_or(u16::MAX);
    let height = u16::try_from(wrapped_height(&text.lines, inner_width))
        .unwrap_or(u16::MAX)
        .saturating_add(header_height)
        // The block borders and the source pane's own top rule.
        .saturating_add(3)
        .min(frame.area().height.saturating_sub(2));
    let area = centered_rect(width, height, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(if approval {
            " Enable guard "
        } else {
            " Guard files "
        })
        .borders(Borders::ALL)
        .border_style(Style::new().fg(if approval { Color::Yellow } else { Color::Cyan }));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(header_height), Constraint::Min(1)])
        .split(inner);
    frame.render_widget(Paragraph::new(header).wrap(Wrap { trim: false }), panes[0]);
    let height = wrapped_height(&text.lines, panes[1].width);
    let visible = usize::from(panes[1].height.saturating_sub(1));
    let scroll = scroll.min(u16::try_from(height.saturating_sub(visible)).unwrap_or(u16::MAX));
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Covered files ")
                    .borders(Borders::TOP),
            )
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        panes[1],
    );
}

fn file_lines(file: &GuardSourceFile) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        format!("--- {} ---", file.name),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )];
    match &file.text {
        Ok(text) => lines.extend(text.lines().map(|line| Line::from(line.to_owned()))),
        Err(notice) => lines.push(Line::styled(
            format!("{} {notice}", file.name),
            Style::new().fg(Color::Red),
        )),
    }
    lines
}

/// Renders the covered bundle bytes; unreadable files keep their name visible
/// so the reviewer sees what the hash still covers.
fn source_lines(source: &Result<GuardSource, String>) -> Vec<Line<'static>> {
    let source = match source {
        Ok(source) => source,
        Err(error) => {
            return vec![Line::styled(
                format!("Guard files cannot be read: {error}"),
                Style::new().fg(Color::Red),
            )];
        }
    };
    let mut lines = source.files.iter().flat_map(file_lines).collect::<Vec<_>>();
    if let Some(total) = source.truncated {
        lines.push(Line::styled(
            format!("... truncated ({total} bytes total)"),
            Style::new().fg(Color::Yellow),
        ));
    }
    lines
}

fn confirmation_lines(confirmation: &Confirmation) -> Vec<Line<'static>> {
    match confirmation {
        Confirmation::ApproveGuard {
            target,
            name,
            path,
            hash,
            reapproval,
            ..
        } => vec![
            Line::styled(
                if *reapproval {
                    "Review changed guard before re-enabling?"
                } else {
                    "Review custom guard before enabling?"
                },
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("y stage enable  n cancel  PgUp/PgDn scroll"),
            Line::from(""),
            Line::from(format!("Guard: {name}")),
            Line::from(format!(
                "Scope: {}",
                target.scope().map(scope_name).unwrap_or("built-in")
            )),
            Line::from(format!("Path: {path}")),
            Line::from(format!("Files hash: {hash}")),
        ],
        Confirmation::ViewGuard {
            target,
            name,
            path,
            hash,
            ..
        } => vec![
            Line::styled(
                format!("{name} guard files"),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("Read-only  Esc close  PgUp/PgDn scroll"),
            Line::from(""),
            Line::from(format!(
                "Scope: {}",
                target.scope().map(scope_name).unwrap_or("built-in")
            )),
            Line::from(format!("Path: {path}")),
            Line::from(format!(
                "Files hash: {}",
                hash.as_deref().unwrap_or("unavailable")
            )),
        ],
        Confirmation::TrustCurrent { path, proposals } => vec![
            Line::styled(
                "Trust this project?",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("y trust  n cancel"),
            Line::from(""),
            Line::from(path.clone()),
            Line::from(proposal_summary(*proposals)),
            Line::from("Project guards remain disabled until reviewed and enabled."),
        ],
        Confirmation::UntrustProject { path, approvals } => vec![
            Line::styled(
                "Untrust this project?",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("y untrust  n cancel"),
            Line::from(""),
            Line::from(path.clone()),
            Line::from(format!("This also disables {approvals} project guard(s).")),
        ],
        Confirmation::ConfigureRuntime {
            name,
            install,
            failure_policy,
            configured,
            ..
        } => {
            if let Some(policy) = failure_policy {
                vec![
                    Line::styled(
                        format!(
                            "{} {name} {} {}?",
                            if *configured { "Switch" } else { "Install" },
                            if *configured { "to" } else { "with" },
                            policy.cli_name()
                        ),
                        Style::new().add_modifier(Modifier::BOLD),
                    ),
                    Line::from(if *configured {
                        "y switch  n cancel"
                    } else {
                        "y install  n cancel"
                    }),
                    Line::from(""),
                    Line::from(match policy {
                        FailurePolicy::Delegate => {
                            "Explicit evaluation failures and refusals will return to the runtime."
                        }
                        FailurePolicy::Block => {
                            "Explicit evaluation failures and refusals will block."
                        }
                    }),
                    Line::from("Valid unknown calls still delegate in either mode."),
                    Line::from(""),
                    Line::from("Restart or reload the runtime after wiring changes."),
                ]
            } else {
                vec![
                    Line::styled(
                        if *install {
                            "Install or refresh runtime wiring?"
                        } else {
                            "Uninstall nah-owned runtime wiring?"
                        },
                        Style::new().add_modifier(Modifier::BOLD),
                    ),
                    Line::from(if *install {
                        "y install  n cancel"
                    } else {
                        "y uninstall  n cancel"
                    }),
                    Line::from(""),
                    Line::from(*name),
                    Line::from(if *install {
                        "This changes only nah-owned integration entries."
                    } else {
                        "Unrelated runtime configuration is preserved."
                    }),
                ]
            }
        }
        Confirmation::EndNap { mode } => vec![
            Line::styled(
                "End the nap and restore enforcement?",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("y wake  n cancel"),
            Line::from(""),
            Line::from(format!(
                "{} resumes immediately, for every session.",
                match mode {
                    NapMode::SelfProtection => "Self-protection",
                    NapMode::All => "All paused enforcement",
                }
            )),
        ],
        Confirmation::DiscardChanges { count } => vec![
            Line::styled(
                "Discard staged guard changes?",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("y discard and quit  n keep editing"),
            Line::from(""),
            Line::from(format!("{count} unapplied change(s) will be lost.")),
        ],
    }
}

/// What trust would expose for review, so the inventory is visible before the
/// decision rather than after it.
fn proposal_summary(proposals: GuardProposals) -> String {
    if proposals.guards == 0 {
        "No project guards found in .nah/.".to_owned()
    } else {
        format!("Found {} project guard(s) in .nah/.", proposals.guards)
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

#[cfg(test)]
mod tests;
