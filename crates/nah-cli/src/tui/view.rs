//! Rendering for the three-screen configuration and log UI.

use nah_proto::ctx::{Guard, GuardLevel};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};

use crate::commands::{GuardEntry, GuardTarget, RuleState, RuntimeHookStatus, applies_at};
use crate::guard_knowledge::{guard_record, knowledge_for_rule};
use crate::nap::{NapMode, OTHER_VERSION_NOTICE};
use crate::records::{age, detail_field, short_time, timestamp_seconds};
use crate::runtime::FailurePolicy;

use super::app::{
    App, Confirmation, MessageKind, NapStatus, Outcome, RuleReason, Screen, SummaryRow, UndoPoints,
    deciding_rules, status_name,
};

const SELECTED: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

/// Columns a log row spends on the deciding runtime: the longest name an
/// adapter stamps (`antigravity`) plus a separating space.
const RUNTIME_WIDTH: usize = 12;

/// Columns a log row spends on what happened to the call. `unavailable` is
/// longer and rare, and pushes the rest of its row right.
const OUTCOME_WIDTH: usize = 8;

/// Columns a log row keeps for the rule that decided the call, so what
/// follows lines up under most rule names; a longer name pushes it right.
const RULE_WIDTH: usize = 26;

/// Narrowest terminal that shows a list beside its details; below it the
/// two stack.
const SIDE_BY_SIDE_WIDTH: u16 = 80;

/// Smallest terminal that gets the full screens; below it only the
/// too-small notice renders.
const MIN_WIDTH: u16 = 50;
const MIN_HEIGHT: u16 = 14;

/// Rows the body keeps however much else a screen shows.
const MIN_BODY_HEIGHT: u16 = 7;

/// Blank columns kept left and right of every screen and dialog, and the
/// wider margin a terminal at least `ROOMY_WIDTH` columns wide gets.
const MARGIN_COLUMNS: u16 = 2;
const ROOMY_MARGIN_COLUMNS: u16 = 4;
const ROOMY_WIDTH: u16 = 120;

/// Blank rows kept above and below every screen, and the deeper margin a
/// terminal at least `ROOMY_HEIGHT` rows tall gets.
const MARGIN_ROWS: u16 = 1;
const ROOMY_MARGIN_ROWS: u16 = 2;
const ROOMY_HEIGHT: u16 = 40;

/// The room the screens keep around and inside their parts, decided once per
/// frame. Each kind of room is taken only from what the layout without it
/// leaves over, so a terminal too small to afford it shows that layout:
/// nothing it shows in full is cut, wrapped further or shortened.
#[derive(Clone, Copy)]
struct Spacing {
    /// The terminal less its outer margins, where screens and dialogs lay
    /// out.
    content: Rect,
    /// A blank row between the tab bar (with its notices) and the panels,
    /// and another between the panels and the key hints, or neither.
    gap: u16,
    /// Blank columns inside a panel's border, between it and the text.
    padding: u16,
}

impl Spacing {
    fn new(app: &App, terminal: Rect) -> Self {
        let wanted_columns = if terminal.width >= ROOMY_WIDTH {
            ROOMY_MARGIN_COLUMNS
        } else {
            MARGIN_COLUMNS
        };
        let forms = width_forms(app);
        let full = forms(terminal.width);
        let columns = (0..=wanted_columns)
            .rev()
            .find(|columns| {
                terminal
                    .width
                    .checked_sub(2 * columns)
                    .is_some_and(|width| width >= MIN_WIDTH && full.kept_by(&forms(width)))
            })
            .unwrap_or(0);
        let width = terminal.width - 2 * columns;
        let needed = (chrome_height(app, width) + MIN_BODY_HEIGHT).max(MIN_HEIGHT);
        let spare = terminal.height.saturating_sub(needed);
        let wanted_rows = if terminal.height >= ROOMY_HEIGHT {
            ROOMY_MARGIN_ROWS
        } else {
            MARGIN_ROWS
        };
        let rows = wanted_rows.min(spare / 2);
        Self {
            content: Rect {
                x: terminal.x + columns,
                y: terminal.y + rows,
                width,
                height: terminal.height - 2 * rows,
            },
            gap: u16::from(spare - 2 * rows >= 2),
            padding: u16::from(columns > 0),
        }
    }
}

/// What a row `width` columns wide shows of each one-row text that a
/// narrower screen shortens or drops, and the rows the key hints wrap to.
struct WidthForms {
    tabs: (bool, bool),
    notice_fits: Option<bool>,
    nap_banner: Option<String>,
    log_counts_fit: Option<bool>,
    footer_rows: usize,
}

impl WidthForms {
    /// Whether `inset` shows everything `self`, the full width's forms,
    /// does: the key hints may wrap further only within the rows they may
    /// take.
    fn kept_by(&self, inset: &Self) -> bool {
        inset.tabs == self.tabs
            && inset.notice_fits == self.notice_fits
            && inset.nap_banner == self.nap_banner
            && inset.log_counts_fit == self.log_counts_fit
            && inset.footer_rows <= self.footer_rows.max(4)
    }
}

/// The forms of `app`'s current screen, for any width.
fn width_forms(app: &App) -> impl Fn(u16) -> WidthForms {
    let labels = tab_labels(app);
    let footer = footer_lines(app);
    let notice = unhooked_notice(app);
    let nap = app.nap.clone();
    // The decision list spans the content width.
    let log_title = (app.screen == Screen::Log).then(|| {
        let (title, counts) = log_titles(app, app.filtered_log().len());
        title.chars().count() + counts.chars().count() + 4
    });
    move |width| WidthForms {
        tabs: tab_form(&labels, usize::from(width)),
        notice_fits: notice
            .as_ref()
            .map(|notice| notice.chars().count() <= usize::from(width)),
        nap_banner: nap.as_ref().map(|nap| nap.banner(nap_banner_room(width))),
        log_counts_fit: log_title.map(|needed| needed <= usize::from(width)),
        footer_rows: wrapped_height(&footer, width.saturating_sub(2)),
    }
}

/// Rows a screen `width` columns wide spends outside its body: the tab bar,
/// its notices in full, and the key hints.
fn chrome_height(app: &App, width: u16) -> u16 {
    1 + status_height(app)
        + other_version_notice(app).map_or(0, |notice| {
            u16::try_from(notice.line_count(width.saturating_sub(2))).unwrap_or(u16::MAX)
        })
        + stopped_notice(app).map_or(0, |notice| {
            u16::try_from(notice.line_count(width)).unwrap_or(u16::MAX)
        })
        + footer_height(app, width)
}

/// A key line or message too long for the terminal wraps instead of being
/// cut, and takes its extra rows from the body.
fn footer_height(app: &App, width: u16) -> u16 {
    u16::try_from(wrapped_height(&footer_lines(app), width.saturating_sub(2)))
        .unwrap_or(u16::MAX)
        .clamp(2, 4)
}

/// A status row exists only while nothing is hooked or a nap runs, and
/// takes its row from the body.
fn status_height(app: &App) -> u16 {
    u16::from(app.nothing_hooked() || app.nap.is_some())
}

fn unhooked_notice(app: &App) -> Option<String> {
    app.nothing_hooked().then(|| {
        let mut notice = " No runtime is hooked: nah is checking nothing.".to_owned();
        if app.screen != Screen::Runtimes {
            notice.push_str(" Press 3.");
        }
        notice
    })
}

/// A nap another Nah version wrote pauses nothing here, hooked or not. Its
/// notice sits below the status row, wrapped whole within its padding, and
/// leaves the body its minimum height.
fn other_version_notice(app: &App) -> Option<Paragraph<'static>> {
    (app.nap.is_none() && app.other_version_nap).then(|| {
        Paragraph::new(OTHER_VERSION_NOTICE)
            .style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .wrap(Wrap { trim: true })
            .block(Block::default().padding(Padding::horizontal(1)))
    })
}

/// The Guards tab also names the nah 1.x custom guards that no longer run,
/// wrapped to the width and beside either notice, so it is never cut or
/// hidden; it leaves the body its minimum height.
fn stopped_notice(app: &App) -> Option<Paragraph<'static>> {
    app.stopped_custom_guards
        .as_deref()
        .filter(|_| app.screen == Screen::Guards)
        .map(|text| {
            Paragraph::new(text.to_owned())
                .style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .wrap(Wrap { trim: true })
                .block(Block::default().padding(Padding::horizontal(1)))
        })
}

pub(crate) fn render(frame: &mut Frame<'_>, app: &App) {
    if frame.area().width < MIN_WIDTH || frame.area().height < MIN_HEIGHT {
        render_too_small(frame, app);
        return;
    }
    let spacing = Spacing::new(app, frame.area());
    let area = spacing.content;
    let footer_height = footer_height(app, area.width);
    // With nothing hooked a nap pauses nothing, so that notice comes first.
    let status_height = status_height(app);
    let other_version = other_version_notice(app);
    let other_version_height = other_version.as_ref().map_or(0, |notice| {
        u16::try_from(notice.line_count(area.width.saturating_sub(2)))
            .unwrap_or(u16::MAX)
            .min(
                area.height
                    .saturating_sub(1 + status_height + MIN_BODY_HEIGHT + footer_height)
                    .max(1),
            )
    });
    let notice_height = status_height + other_version_height;
    let stopped = stopped_notice(app);
    let stopped_height = stopped.as_ref().map_or(0, |notice| {
        u16::try_from(notice.line_count(area.width))
            .unwrap_or(u16::MAX)
            .min(
                area.height
                    .saturating_sub(1 + notice_height + MIN_BODY_HEIGHT + footer_height)
                    .max(1),
            )
    });
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(notice_height),
            Constraint::Length(stopped_height),
            Constraint::Length(spacing.gap),
            Constraint::Min(MIN_BODY_HEIGHT),
            Constraint::Length(spacing.gap),
            Constraint::Length(footer_height),
        ])
        .split(area);
    render_tabs(frame, app, areas[0]);
    let [status_area, other_version_area] = Layout::vertical([
        Constraint::Length(status_height),
        Constraint::Length(other_version_height),
    ])
    .areas(areas[1]);
    if let Some(notice) = unhooked_notice(app) {
        frame.render_widget(
            Paragraph::new(notice)
                .style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            status_area,
        );
    } else if let Some(nap) = &app.nap {
        render_nap(frame, nap, status_area);
    }
    if let Some(notice) = other_version {
        frame.render_widget(notice, other_version_area);
    }
    if let Some(stopped) = stopped {
        frame.render_widget(stopped, areas[2]);
    }
    let body_area = areas[4];
    let body = if app.screen == Screen::Log {
        // A decision row carries more than a narrow list can show, so the log
        // keeps the full width and puts the selected decision underneath.
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),
                Constraint::Length((body_area.height * 2 / 5).clamp(5, 14)),
            ])
            .split(body_area)
    } else if frame.area().width < SIDE_BY_SIDE_WIDTH {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(body_area)
    } else {
        // Wide enough for the longest rule name with its marker, and no wider
        // than that needs: the rest goes to the details. Padding widens the
        // pane rather than narrowing its rows.
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length((area.width * 43 / 100).clamp(42, 50) + spacing.padding),
                Constraint::Min(1),
            ])
            .split(body_area)
    };
    let padding = spacing.padding;
    match app.screen {
        Screen::Guards => render_guards(frame, app, body[0], body[1], padding),
        Screen::Runtimes => render_runtimes(frame, app, body[0], body[1], padding),
        Screen::Log => render_log(frame, app, body[0], body[1], padding),
    }
    frame.render_widget(
        Paragraph::new(footer_lines(app))
            .block(Block::default().padding(Padding::horizontal(1)))
            .wrap(Wrap { trim: true }),
        areas[6],
    );
    if let Some(confirmation) = &app.confirmation {
        render_confirmation(frame, confirmation, spacing);
    }
    if app.summary_open {
        render_summary(frame, app, spacing);
    }
    if app.help_open {
        render_help(frame, app, spacing);
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
/// so the banner takes a full inverted row: the countdown and what is paused
/// on the left, the wake key on the right. The colour separates the kinds as
/// plainly as the text does, since `all` pauses far more.
const NAP_WAKE: &str = "w wake";

fn render_nap(frame: &mut Frame<'_>, nap: &NapStatus, area: Rect) {
    let style = Style::new()
        .fg(Color::Black)
        .bg(match nap.mode {
            NapMode::SelfProtection | NapMode::Guards(_) => Color::Yellow,
            NapMode::All => Color::Red,
        })
        .add_modifier(Modifier::BOLD);
    let room = nap_banner_room(area.width);
    let text = nap.banner(room);
    let gap = room.saturating_sub(text.chars().count()) + 2;
    frame.render_widget(
        Paragraph::new(format!(" {text}{}{NAP_WAKE}", " ".repeat(gap))).style(style),
        area,
    );
}

/// Columns the nap banner's text may fill in a row `width` columns wide.
fn nap_banner_room(width: u16) -> usize {
    usize::from(width).saturating_sub(NAP_WAKE.len() + 4)
}

/// One row: the product name, the three tabs with the open one bracketed, and
/// the help key. A terminal too narrow for all of it drops the name and the
/// gaps, then the help key.
fn render_tabs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let labels = tab_labels(app);
    let width = usize::from(area.width);
    let (roomy, help) = tab_form(&labels, width);
    let mut spans = Vec::new();
    if roomy {
        spans.push(Span::styled(
            " nah  ",
            Style::new().add_modifier(Modifier::BOLD),
        ));
    }
    for (screen, label) in labels {
        spans.push(if screen == app.screen {
            Span::styled(
                format!("[{label}]"),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw(format!(" {label} "))
        });
        if roomy {
            spans.push(Span::raw(" "));
        }
    }
    if help {
        let used = spans.iter().map(Span::width).sum::<usize>();
        spans.push(Span::raw(" ".repeat(width - used - TAB_HELP.len() - 1)));
        spans.push(Span::styled(
            TAB_HELP,
            Style::new().add_modifier(Modifier::DIM),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

const TAB_HELP: &str = "? help";

fn tab_labels(app: &App) -> [(Screen, String); 3] {
    [
        (
            Screen::Guards,
            tab_label("1 Guards", app.pending_count(), '*'),
        ),
        (Screen::Runtimes, "2 Runtimes".to_owned()),
        (Screen::Log, tab_label("3 Log", app.new_blocks, '!')),
    ]
}

/// Which parts of the tab bar a row `width` columns wide shows besides the
/// tabs: the product name with the gaps, and the help key.
fn tab_form(labels: &[(Screen, String)], width: usize) -> (bool, bool) {
    let tabs_width = labels
        .iter()
        .map(|(_, label)| label.chars().count() + 2)
        .sum::<usize>();
    let roomy = " nah  ".len() + tabs_width + labels.len() + TAB_HELP.len() + 2 <= width;
    let used = if roomy {
        " nah  ".len() + tabs_width + labels.len()
    } else {
        tabs_width
    };
    (roomy, used + TAB_HELP.len() < width)
}

/// `marker` separates staged changes (`*`) from unread block decisions (`!`).
fn tab_label(name: &str, count: usize, marker: char) -> String {
    if count == 0 {
        name.to_owned()
    } else {
        format!("{name} ({count}{marker})")
    }
}

fn render_guards(
    frame: &mut Frame<'_>,
    app: &App,
    list_area: Rect,
    detail_area: Rect,
    padding: u16,
) {
    let rows = app.guard_rows();
    // The row a list item may fill: the pane less its borders, the
    // selection marker and its padding.
    let width = usize::from(list_area.width.saturating_sub(4 + padding));
    let items = rows
        .iter()
        .map(|row| guard_item(app, row, width))
        .collect::<Vec<_>>();
    let visible = usize::from(list_area.height.saturating_sub(2));
    let mut state = ListState::default()
        .with_selected(Some(app.guard_index))
        .with_offset(list_offset(app, &rows, visible));
    frame.render_stateful_widget(
        List::new(items)
            .block(list_block(" Guards ", padding))
            .highlight_style(SELECTED)
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );

    let (title, text) = match rows.get(app.guard_index) {
        Some(entry) => guard_details(app, entry),
        None => (" Details ".to_owned(), Text::from("No guards discovered.")),
    };
    render_details(frame, app, title, text, detail_area, padding);
}

/// The first row to show. The selected row stays in view; when it heads an
/// open guard, so do as many of that guard's rows as fit, so a guard is read
/// together with its rules.
fn list_offset(app: &App, rows: &[&GuardEntry], visible: usize) -> usize {
    let selected = app.guard_index;
    let children = match rows.get(selected) {
        Some(row) if app.heading_open(row) == Some(true) => rows[selected + 1..]
            .iter()
            .take_while(|row| app.heading_open(row).is_none() && !is_guard(row))
            .count(),
        _ => 0,
    };
    (selected + children + 1)
        .saturating_sub(visible)
        .min(selected)
}

fn is_guard(row: &GuardEntry) -> bool {
    matches!(row.target, GuardTarget::Guard { .. })
}

/// A guard heads its rules with its setting; a rule shows how much of it
/// runs. `+` and `-` mark a heading whose rows are hidden or shown, `*`
/// marks a staged change, and the right edge says why a rule is not simply
/// following its guard.
fn guard_item(app: &App, entry: &GuardEntry, width: usize) -> ListItem<'static> {
    let heading = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let pending = Style::new().fg(Color::Yellow);
    let dim = Style::new().add_modifier(Modifier::DIM);
    let fold = Span::styled(
        match app.heading_open(entry) {
            Some(true) => "- ",
            Some(false) => "+ ",
            None => "  ",
        },
        dim,
    );
    let staged = if app.is_pending(entry) { "*" } else { " " };
    let napping = app.napping(&entry.target);
    let line = match &entry.target {
        GuardTarget::Guard { guard } => {
            let setting = if guard.configurable() {
                app.guard_setting(*guard).name()
            } else {
                "always on"
            };
            let mut spans = vec![
                fold,
                Span::styled(
                    format!("{:<16}", guard.name().to_ascii_uppercase()),
                    heading,
                ),
                Span::styled(
                    format!("{:<8}", format!("{setting}{staged}")),
                    if app.is_pending(entry) {
                        pending
                    } else {
                        Style::default()
                    },
                ),
            ];
            // An open guard's rows say this themselves.
            if app.heading_open(entry) != Some(true) {
                spans.extend(guard_summary(app, *guard));
            }
            Line::from(spans)
        }
        GuardTarget::Rule { rule } => {
            let name = rule.split_once('/').map_or(rule.as_str(), |(_, name)| name);
            let marker = if napping {
                Span::styled(format!("{NAPPING}{staged}"), pending)
            } else {
                Span::styled(
                    format!("{}{staged}", app.rule_state(rule).marker()),
                    if app.is_pending(entry) {
                        pending
                    } else {
                        Style::default()
                    },
                )
            };
            let tag = app.rule_reason(rule).map(|reason| match reason {
                RuleReason::Napping => Span::styled(nap_tag(app), pending),
                RuleReason::SetOn => Span::raw("set on"),
                RuleReason::SetOff => Span::raw("set off"),
                RuleReason::WaitsForStrict => Span::styled("strict", dim),
            });
            tagged(
                vec![Span::raw("  "), marker, Span::raw(name.to_owned())],
                tag,
                width,
            )
        }
    };
    ListItem::new(line)
}

/// The marker of a rule that a nap pauses.
const NAPPING: &str = "[z]";

/// `left`, then `tag` at the right edge of a row `width` columns wide.
fn tagged(mut left: Vec<Span<'static>>, tag: Option<Span<'static>>, width: usize) -> Line<'static> {
    if let Some(tag) = tag {
        let used = left.iter().map(Span::width).sum::<usize>() + tag.width();
        left.push(Span::raw(" ".repeat(width.saturating_sub(used).max(1))));
        left.push(tag);
    }
    Line::from(left)
}

fn nap_tag(app: &App) -> String {
    app.nap
        .as_ref()
        .map_or_else(String::new, |nap| format!("nap {}", nap.countdown_short()))
}

/// How many of `guard`'s rules each reason holds, in the order shown.
/// A rule that waits for strict is following its guard, so it is not counted.
fn reason_counts(app: &App, guard: Guard) -> Vec<(RuleReason, usize)> {
    [RuleReason::SetOn, RuleReason::SetOff, RuleReason::Napping]
        .into_iter()
        .map(|reason| {
            let count = app
                .rules_of(guard)
                .filter(|rule| app.rule_reason(rule) == Some(reason))
                .count();
            (reason, count)
        })
        .filter(|(_, count)| *count > 0)
        .collect()
}

/// What a folded guard says about the rules that do not follow it, so an
/// override or a nap is never out of sight.
fn guard_summary(app: &App, guard: Guard) -> Option<Span<'static>> {
    let nap = Style::new().fg(Color::Yellow);
    let rules = app.rules_of(guard).count();
    let counts = reason_counts(app, guard);
    let napping = app.napping(&GuardTarget::Guard { guard })
        || (rules > 0 && counts == [(RuleReason::Napping, rules)]);
    if napping {
        return Some(Span::styled(nap_tag(app), nap));
    }
    let text = match counts.as_slice() {
        [] => return None,
        [(reason, count)] => format!(
            "{count} {}",
            match reason {
                RuleReason::SetOn => "set on",
                RuleReason::SetOff => "set off",
                RuleReason::Napping | RuleReason::WaitsForStrict => "napping",
            }
        ),
        several => several
            .iter()
            .map(|(reason, count)| {
                format!(
                    "{count} {}",
                    match reason {
                        RuleReason::SetOn => "on",
                        RuleReason::SetOff => "off",
                        RuleReason::Napping | RuleReason::WaitsForStrict => "nap",
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", "),
    };
    let has_nap = counts
        .iter()
        .any(|(reason, _)| *reason == RuleReason::Napping);
    Some(Span::styled(
        text,
        if has_nap {
            nap
        } else {
            Style::new().add_modifier(Modifier::DIM)
        },
    ))
}

/// A reason in words, for the details pane and the message row.
fn reason_words(app: &App, reason: RuleReason) -> String {
    match reason {
        RuleReason::Napping => format!(
            "napping for {}",
            app.nap
                .as_ref()
                .map_or_else(String::new, NapStatus::countdown)
        ),
        RuleReason::SetOn => "set on by you".to_owned(),
        RuleReason::SetOff => "set off by you".to_owned(),
        RuleReason::WaitsForStrict => "waits for strict".to_owned(),
    }
}

/// The marker and the words for how much of `rule` runs and why.
fn rule_status(app: &App, rule: &str) -> (&'static str, String) {
    let reason = app.rule_reason(rule);
    let marker = if reason == Some(RuleReason::Napping) {
        NAPPING
    } else {
        app.rule_state(rule).marker()
    };
    let words = reason.map_or_else(
        || {
            match app.rule_state(rule) {
                RuleState::On => "on",
                RuleState::CoreOnly => "on at core; strict parts off",
                RuleState::Off => "off",
            }
            .to_owned()
        },
        |reason| reason_words(app, reason),
    );
    (marker, words)
}

/// Points at the fuller text a details pane has no room for.
fn more(command: &str) -> Line<'static> {
    Line::styled(
        format!("More: {command}"),
        Style::new().add_modifier(Modifier::DIM),
    )
}

/// The details pane's title and text for one guard or rule.
fn guard_details(app: &App, entry: &GuardEntry) -> (String, Text<'static>) {
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let mut title = format!(" {} ", entry.target.name());
    let mut lines = Vec::new();
    match &entry.target {
        GuardTarget::Guard { guard } => {
            let record = guard_record(*guard);
            lines.push(Line::from(record.protects.trim().to_owned()));
            match &record.settings {
                Some(settings) => {
                    // The setting that runs now comes first, so it is read
                    // without scrolling; the others follow in their order.
                    let now = app.guard_setting(*guard);
                    title = format!(" {}: {} ", guard.name(), now.name());
                    let others = [GuardLevel::Core, GuardLevel::Strict, GuardLevel::Off]
                        .into_iter()
                        .filter(|level| *level != now);
                    for level in std::iter::once(now).chain(others) {
                        lines.push(Line::from(""));
                        lines.push(Line::styled(
                            format!(
                                "{}{}",
                                level.name().to_ascii_uppercase(),
                                if level == now { " (now)" } else { "" }
                            ),
                            bold,
                        ));
                        lines.push(Line::from(settings.of(level).trim().to_owned()));
                    }
                }
                None => title = format!(" {}: always on ", guard.name()),
            }
            let rules = app.rules_of(*guard).collect::<Vec<_>>();
            if !rules.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::styled("RULES", bold));
                let name = |rule: &str| {
                    rule.split_once('/')
                        .map_or(rule, |(_, name)| name)
                        .to_owned()
                };
                let width = rules
                    .iter()
                    .map(|rule| name(rule).len())
                    .max()
                    .unwrap_or_default();
                for rule in rules {
                    let (marker, words) = rule_status(app, rule);
                    lines.push(Line::from(format!(
                        "{marker} {:<width$}  {words}",
                        name(rule)
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(more(&format!("nah docs guards {}", guard.name())));
        }
        GuardTarget::Rule { rule } => {
            let (marker, words) = rule_status(app, rule);
            lines.push(Line::styled(format!("{marker} {words}"), bold));
            let guard = Guard::of_rule(rule);
            let guard_name = guard.map_or("its guard", Guard::name);
            let setting = guard.map_or("off", |guard| app.guard_setting(guard).name());
            lines.push(Line::from(match app.rule_reason(rule) {
                Some(RuleReason::Napping) => {
                    "A nap pauses it at every setting; w ends the nap.".to_owned()
                }
                Some(RuleReason::SetOn) => {
                    format!("Every part runs, whatever {guard_name} is set to.")
                }
                Some(RuleReason::SetOff) => {
                    format!("No part runs, whatever {guard_name} is set to.")
                }
                Some(RuleReason::WaitsForStrict) => {
                    format!("Its parts apply at strict, and {guard_name} is at {setting}.")
                }
                None => format!("Follows {guard_name} ({setting})."),
            }));
            lines.push(Line::from(format!("Applies at: {}", applies_at(rule))));
        }
    }
    if let Some(behavior) = &entry.behavior {
        lines.push(Line::from(""));
        lines.push(Line::from(behavior.clone()));
    }
    if let GuardTarget::Rule { rule } = &entry.target
        && let Some(strict_adds) = &knowledge_for_rule(rule).strict_adds
    {
        lines.push(Line::from(""));
        lines.push(Line::from(strict_adds.trim().to_owned()));
    }
    if !entry.examples.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Examples:"));
        lines.extend(
            entry
                .examples
                .iter()
                .map(|example| Line::from(format!("- {example}"))),
        );
    }
    if let GuardTarget::Rule { rule } = &entry.target {
        lines.push(Line::from(""));
        lines.push(more(&format!("nah docs guards {rule}")));
    }
    (title, Text::from(lines))
}

/// A list pane: its rows start after the selection marker's column, so only
/// their right end needs padding off the border.
fn list_block<'a>(title: impl Into<Line<'a>>, padding: u16) -> Block<'a> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .padding(Padding::right(padding))
}

/// A screen's details: wrapped, scrolled by PgUp and PgDn, with the border
/// saying when there is more above or below.
fn render_details(
    frame: &mut Frame<'_>,
    app: &App,
    title: String,
    text: Text<'static>,
    area: Rect,
    padding: u16,
) {
    let paragraph = Paragraph::new(text).wrap(Wrap { trim: false });
    let lines = paragraph.line_count(area.width.saturating_sub(2 + 2 * padding));
    let visible = usize::from(area.height.saturating_sub(2));
    let limit = u16::try_from(lines.saturating_sub(visible)).unwrap_or(u16::MAX);
    app.detail_scroll_limit.set(limit);
    app.detail_page
        .set(u16::try_from(visible.saturating_sub(1).max(1)).unwrap_or(u16::MAX));
    let scroll = app.detail_scroll.min(limit);
    let dim = Style::new().add_modifier(Modifier::DIM);
    let mut block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .padding(Padding::horizontal(padding));
    if scroll > 0 {
        block = block.title_bottom(Line::styled(" PgUp ", dim));
    }
    if scroll < limit {
        block = block.title_bottom(Line::styled(" PgDn more ", dim).right_aligned());
    }
    frame.render_widget(paragraph.block(block).scroll((scroll, 0)), area);
}

fn render_runtimes(
    frame: &mut Frame<'_>,
    app: &App,
    list_area: Rect,
    detail_area: Rect,
    padding: u16,
) {
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
            .block(list_block(" Runtime integrations ", padding))
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
            if let Some(notice) = runtime.coverage_notice {
                lines.push(Line::from(""));
                lines.push(Line::from(notice));
            }
            // Session memory keeps its ledger in every runtime, and
            // save-then-run saves there too, on Unix, where its payload says
            // where a command runs.
            lines.push(Line::from(""));
            lines.push(Line::from(
                if crate::save_then_run::available(Some(runtime.runtime)) {
                    "Here nah saves a discard before it runs, and remembers the session."
                } else if !runtime.runtime.states_where_commands_run() {
                    "Here nah remembers the session. It blocks the discards 1.x blocked: this runtime's hook does not say where a command runs, so nah cannot save what it would lose."
                } else {
                    "Here nah remembers the session. It blocks the discards 1.x blocked: saving them needs macOS or Linux."
                },
            ));
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
    render_details(
        frame,
        app,
        " Details ".to_owned(),
        text,
        detail_area,
        padding,
    );
}

fn render_log(frame: &mut Frame<'_>, app: &App, list_area: Rect, detail_area: Rect, padding: u16) {
    let records = app.filtered_log();
    let dim = Style::new().add_modifier(Modifier::DIM);
    // The date is the same on every row of most windows, so it is shown only
    // when the window spans more than one day.
    let window = app.log_window();
    let one_day = window.first().map(|record| record.timestamp.get(..10))
        == window.last().map(|record| record.timestamp.get(..10));
    let items = records
        .iter()
        .map(|record| {
            let (outcome, style) = match Outcome::of(record) {
                Outcome::Block => (
                    "BLOCK",
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Outcome::Saved => ("saved", Style::new().fg(Color::Green)),
                Outcome::Delegate => ("delegate", Style::new().fg(Color::Yellow)),
                Outcome::Unavailable => ("unavailable", Style::new().fg(Color::Magenta)),
            };
            let time = short_time(&record.timestamp);
            let time = if one_day {
                time.rsplit(' ').next().unwrap_or_default().to_owned()
            } else {
                time
            };
            let mut spans = vec![
                Span::raw(format!("{time}  ")),
                Span::styled(format!("{outcome:<OUTCOME_WIDTH$} "), style),
                // A name longer than any adapter stamps today simply pushes the
                // rest right and clips at the pane edge.
                Span::styled(format!("{:<RUNTIME_WIDTH$}", record.runtime), dim),
            ];
            // A row leads with what decided the call; the command or effects
            // follow. A saved discard names its snapshot instead.
            let rules = deciding_rules(record);
            if rules.is_empty() {
                spans.push(Span::raw(record.row_text.clone()));
            } else {
                spans.push(Span::raw(format!("{rules:<RULE_WIDTH$}  ")));
                let snapshots = record
                    .saved
                    .iter()
                    .map(|saved| saved.snapshot.as_str())
                    .collect::<Vec<_>>();
                spans.push(Span::styled(
                    if snapshots.is_empty() {
                        record.row_text.clone()
                    } else {
                        format!("snapshot {}  {}", snapshots.join(", "), record.row_text)
                    },
                    dim,
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect::<Vec<_>>();
    let (title, counts) = log_titles(app, records.len());
    let counts_fit =
        title.chars().count() + counts.chars().count() + 4 <= usize::from(list_area.width);
    let mut block = list_block(title, padding);
    if counts_fit {
        block = block.title(Line::from(counts).right_aligned());
    }
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(app.log_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(SELECTED)
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );

    let Some(record) = app.selected_log() else {
        let text = Text::from(if app.log_window().is_empty() {
            "No decisions recorded."
        } else {
            "No decisions match the filter."
        });
        render_details(
            frame,
            app,
            " Details ".to_owned(),
            text,
            detail_area,
            padding,
        );
        return;
    };
    let mut lines = record
        .explanation
        .lines()
        .map(|line| Line::from(line.to_owned()))
        .collect::<Vec<_>>();
    lines.insert(
        1.min(lines.len()),
        Line::from(detail_field("time:", &record.timestamp)),
    );
    let mut title = " Details ";
    // What was saved and how to get it back come first, each snapshot with
    // its own undo. The save is made before the call, and the record holds
    // nah's verdict, not whether the command then completed.
    if !record.saved.is_empty() {
        let blocked = Outcome::of(record) == Outcome::Block;
        title = if blocked {
            " saved, then blocked "
        } else {
            " saved, then let through "
        };
        let saves = record.saved.iter().flat_map(|saved| {
            [
                Line::from(vec![
                    Span::styled(
                        format!("Snapshot {}", saved.snapshot),
                        Style::new().fg(Color::Green),
                    ),
                    Span::raw(format!(
                        " holds {}. Nah saved it, then {}.",
                        saved.holds,
                        if blocked {
                            "blocked the call"
                        } else {
                            "let the call through"
                        }
                    )),
                ]),
                Line::from(vec![
                    Span::raw("Undo: "),
                    Span::styled(saved.undo(), Style::new().add_modifier(Modifier::BOLD)),
                ]),
                Line::styled(format!("  in: {}", app.short_path(&saved.root)), dim),
                Line::from(""),
            ]
        });
        lines.splice(0..0, saves.collect::<Vec<_>>());
    }
    render_details(
        frame,
        app,
        title.to_owned(),
        Text::from(lines),
        detail_area,
        padding,
    );
}

/// Lines `content` occupies once wrapped into `width` columns.
fn wrapped_height(content: &[Line<'_>], width: u16) -> usize {
    Paragraph::new(content.to_vec())
        .wrap(Wrap { trim: false })
        .line_count(width.max(1))
}

/// The decision list's title, and the outcome counts its border also shows
/// where both fit.
fn log_titles(app: &App, shown: usize) -> (String, String) {
    let title = format!(
        " Decisions ({}: {} of {}) ",
        log_scope(app),
        shown,
        app.log_window().len()
    );
    (title, format!(" {} ", outcome_counts(app)))
}

/// Outcome totals for the loaded window, zero counts omitted.
fn outcome_counts(app: &App) -> String {
    let counts = app
        .outcome_counts()
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(outcome, count)| format!("{count} {}", outcome.name()))
        .collect::<Vec<_>>();
    if counts.is_empty() {
        "no decisions".to_owned()
    } else {
        counts.join(", ")
    }
}

fn filter_name(filter: Option<Outcome>) -> &'static str {
    filter.map_or("all", Outcome::name)
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

/// The key line of the active screen, then the latest message. Without one
/// the guards screen says what the selected row is doing and what Space
/// would do to it, and the other screens name the keys they all share.
fn footer_lines(app: &App) -> Vec<Line<'static>> {
    let keys = match app.screen {
        Screen::Guards => format!("{}  Enter apply ({})", guard_keys(app), app.pending_count()),
        Screen::Runtimes => "f mode  i install/reinstall  u uninstall".into(),
        // Typing replaces the keymap, so the query stays visible even where the
        // list title is too narrow to show all of it.
        Screen::Log if app.log_search_editing => format!("/{}\u{2588}", app.log_search),
        Screen::Log => format!(
            "/ search  v outcome: {}  r runtime: {}  s summary",
            filter_name(app.log_filter),
            runtime_filter_name(app)
        ),
    };
    // While typing, q is a letter rather than the quit key.
    let idle = if app.log_search_editing {
        "Enter search  Esc cancel".to_owned()
    } else if app.screen == Screen::Guards {
        guard_hint(app)
    } else {
        "Tab screen  PgUp/PgDn details  R refresh  q quit".to_owned()
    };
    // Failed evaluations concern the whole log, not the selected decision,
    // so they stay in view below it; a message joins them rather than
    // replacing them.
    let failures = match (app.screen, &app.failure_summary) {
        (Screen::Log, Some(failures)) => Some(Line::styled(
            failures.display().trim_start_matches("nah: ").to_owned(),
            Style::new().fg(Color::Yellow),
        )),
        _ => None,
    };
    let message = app.message.as_ref().map(|message| {
        Line::styled(
            message.text.clone(),
            Style::new().fg(match message.kind {
                MessageKind::Info => Color::White,
                MessageKind::Warning => Color::Yellow,
                MessageKind::Success => Color::Green,
                MessageKind::Error => Color::Red,
            }),
        )
    });
    let mut lines = vec![Line::from(keys)];
    match (message, failures) {
        (None, None) => lines.push(Line::from(idle)),
        (message, failures) => lines.extend(message.into_iter().chain(failures)),
    }
    lines
}

/// The keys that act on the selected guards row.
fn guard_keys(app: &App) -> &'static str {
    match app.selected_guard().map(|entry| &entry.target) {
        Some(GuardTarget::Guard { guard }) if guard.configurable() => {
            "Space level  o/c/s set level  \u{2190}/\u{2192} fold  d core"
        }
        Some(GuardTarget::Rule { .. }) => "Space set off/on  d follow guard  \u{2190} fold",
        Some(GuardTarget::Guard { .. }) | None => "\u{2190}/\u{2192} fold  D shipped",
    }
}

/// What the selected guards row is doing, and what Space would do to it.
fn guard_hint(app: &App) -> String {
    let Some(entry) = app.selected_guard() else {
        return String::new();
    };
    match &entry.target {
        GuardTarget::Guard { guard } => {
            let rules = app.rules_of(*guard).collect::<Vec<_>>();
            if rules.is_empty() {
                return "Always on: it protects nah's own files, hooks and settings".to_owned();
            }
            let on = rules
                .iter()
                .filter(|rule| {
                    app.rule_state(rule) != RuleState::Off
                        && app.rule_reason(rule) != Some(RuleReason::Napping)
                })
                .count();
            let mut hint = format!("{on} of {} rules on", rules.len());
            let reasons = reason_counts(app, *guard)
                .into_iter()
                .map(|(reason, count)| format!("{count} {}", reason_words(app, reason)))
                .collect::<Vec<_>>();
            if !reasons.is_empty() {
                hint.push_str(&format!(": {}", reasons.join(", ")));
            }
            hint
        }
        GuardTarget::Rule { rule } => {
            let guard = Guard::of_rule(rule).map_or("its guard", Guard::name);
            let nap_only = if knowledge_for_rule(rule).nap_only {
                "  Nah itself offers only a nap for this rule."
            } else {
                ""
            };
            let sets_on = app.space_sets_on(rule);
            let space = if sets_on {
                "Space: set on, every part, strict ones too."
            } else {
                "Space: set off."
            };
            match app.rule_reason(rule) {
                Some(RuleReason::Napping) => {
                    "Napping: it blocks nothing until the nap ends. w ends it now".to_owned()
                }
                Some(RuleReason::SetOn) => {
                    format!("Set on: every part runs.  {space}  d: follow {guard}{nap_only}")
                }
                Some(RuleReason::SetOff) => format!("Set off.  {space}  d: follow {guard}"),
                Some(RuleReason::WaitsForStrict) => {
                    format!("Runs when {guard} is strict.  {space}  d: follow {guard}")
                }
                // It follows a guard that is off.
                None if sets_on => format!("Off with {guard}.  {space}"),
                None => {
                    format!("{space}  Again: set on, every part, strict ones too.{nap_only}")
                }
            }
        }
    }
}

/// How many guards the blocked row of the log summary names at most.
const SUMMARY_GUARDS: usize = 3;

/// What the log summary gives beside its counts.
#[derive(Clone, Copy)]
struct SummaryForm {
    /// How many of the guards that blocked most it names.
    guards: usize,
    /// Whether they get a line of their own under the blocked row, where
    /// they fit even after a wide count and label.
    guards_below: bool,
    /// Whether the saved and not-fully-checked rows say what their calls
    /// came to.
    details: bool,
}

/// The log summary over the log screen: every call the retained log
/// holds, in disjoint rows that add up to the total. Where the blocked
/// row's guards do not fit beside it, they move to a line of their own; a
/// terminal too narrow even for that drops them one at a time from the
/// last, then the other rows' details.
fn render_summary(frame: &mut Frame<'_>, app: &App, spacing: Spacing) {
    // The widest text `dialog_area` gives a dialog, reaching into the
    // margins without padding when it must.
    let room = usize::from(frame.area().width.saturating_sub(2).clamp(40, 84) - 2);
    let beside = SummaryForm {
        guards: SUMMARY_GUARDS,
        guards_below: false,
        details: true,
    };
    let below = (0..=SUMMARY_GUARDS).rev().map(|guards| SummaryForm {
        guards,
        guards_below: true,
        details: true,
    });
    let bare = SummaryForm {
        guards: 0,
        guards_below: false,
        details: false,
    };
    let text = std::iter::once(beside)
        .chain(below)
        .chain([bare])
        .map(|form| summary_lines(app, form))
        .find(|lines| lines.iter().all(|line| line.width() <= room))
        .unwrap_or_else(|| summary_lines(app, bare));
    let (area, padding) = dialog_area(&text, 40, spacing, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Summary ")
                    .title_bottom(
                        Line::styled(" s or Esc close ", Style::new().add_modifier(Modifier::DIM))
                            .right_aligned(),
                    )
                    .borders(Borders::ALL)
                    .padding(Padding::horizontal(padding))
                    .border_style(Style::new().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// The summary's lines in `form`.
fn summary_lines(app: &App, form: SummaryForm) -> Vec<Line<'static>> {
    let summary = &app.log_summary;
    if app.log_unreadable.is_some() {
        // The footer says why.
        return vec![Line::from("Nah could not read its decision log.")];
    }
    if summary.calls == 0 {
        return vec![Line::from("Nah has not judged a call yet.")];
    }
    let dim = Style::new().add_modifier(Modifier::DIM);
    let mut lines = vec![Line::styled(
        format!(
            "Nah judged {} {}",
            summary.calls,
            if summary.calls == 1 { "call" } else { "calls" }
        ),
        Style::new().add_modifier(Modifier::BOLD),
    )];
    let rows = app.summary_rows();
    let count_width = rows
        .iter()
        .map(|(_, count)| count.to_string().len())
        .max()
        .unwrap_or_default();
    let label_width = rows
        .iter()
        .map(|(row, _)| row.label().len())
        .max()
        .unwrap_or_default();
    for (row, count) in rows {
        let guards = (row == SummaryRow::Blocked && form.guards > 0)
            .then(|| blocking_guards(app, form.guards))
            .filter(|guards| !guards.is_empty());
        let detail = match row {
            SummaryRow::Ran => None,
            SummaryRow::Blocked => guards.clone().filter(|_| !form.guards_below),
            SummaryRow::SavedFirst => app
                .undo_points
                .as_ref()
                .filter(|_| form.details)
                .map(undo_points_words),
            SummaryRow::NotFullyChecked => unchecked_outcomes(app).filter(|_| form.details),
        };
        let mut spans = vec![Span::raw(format!(
            "  {count:>count_width$}  {:<label_width$}",
            row.label()
        ))];
        if let Some(detail) = detail.filter(|detail| !detail.is_empty()) {
            spans.push(Span::styled(format!("  {detail}"), dim));
        }
        lines.push(Line::from(spans));
        if let Some(guards) = guards.filter(|_| form.guards_below) {
            lines.push(Line::styled(
                format!("  {:count_width$}  {guards}", ""),
                dim,
            ));
        }
    }
    lines
}

/// The `limit` guards that blocked most, busiest first.
fn blocking_guards(app: &App, limit: usize) -> String {
    let mut guards = app.log_summary.blocking_guards.iter().collect::<Vec<_>>();
    guards.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
    guards
        .iter()
        .take(limit)
        .map(|(guard, count)| format!("{guard} {count}"))
        .collect::<Vec<_>>()
        .join(" \u{b7} ")
}

fn undo_points_words(points: &UndoPoints) -> String {
    let newest = points
        .newest
        .as_deref()
        .and_then(|timestamp| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            now.checked_sub(timestamp_seconds(timestamp)?)
        })
        .map_or_else(String::new, |seconds| format!("; newest {}", age(seconds)));
    match points.kept {
        0 => "none kept now".to_owned(),
        1 => format!("1 undo point kept{newest}"),
        kept => format!("{kept} undo points kept{newest}"),
    }
}

/// What the log says became of the calls Nah could not fully check. A call
/// no decision was produced for has no outcome there, so it is only counted.
fn unchecked_outcomes(app: &App) -> Option<String> {
    let failures = app.failure_summary.as_ref()?;
    Some(
        [(failures.let_run, "let run"), (failures.blocked, "blocked")]
            .iter()
            .filter(|(count, _)| *count > 0)
            .map(|(count, outcome)| format!("{count} {outcome}"))
            .collect::<Vec<_>>()
            .join(" \u{b7} "),
    )
}

fn render_help(frame: &mut Frame<'_>, app: &App, spacing: Spacing) {
    let text = help_lines(app);
    let (area, padding) = dialog_area(&text, 48, spacing, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(format!(" Help \u{2014} {} ", help_title(app.screen)))
                    .borders(Borders::ALL)
                    .padding(Padding::horizontal(padding))
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
            Line::from("Rules block understood danger; they never approve a call."),
            Line::from("Each guard is off, core, or strict; its rules follow it."),
            Line::from("A rule override runs or stops one rule whatever its guard says."),
            Line::from("[x] on  [~] core parts only  [ ] off  [z] napping"),
            Line::from("Pause one for 10 minutes: run `nah nap NAME` in another terminal."),
            Line::from("Changes stay pending until Enter applies them."),
            Line::from(""),
            help_heading("KEYS"),
            Line::from("Space cycle a guard or override a rule"),
            Line::from(
                "o/c/s set a guard off, core, strict  \u{2190}/\u{2192} or h/l fold its rules",
            ),
            Line::from("d reset the selected guard or rule"),
            Line::from("D restore shipped settings  Enter apply"),
        ],
        Screen::Runtimes => vec![
            Line::from("Runtime wiring lets nah inspect supported tool calls before execution."),
            Line::from("Fail-open (default): failures delegate unless guarded evidence remains."),
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
            Line::from("Saved means nah snapshotted what a discard would destroy, then let"),
            Line::from("the call through; its details give the `nah undo` command."),
            Line::from("Delegate means nah did not block; the runtime keeps control."),
            Line::from("Delegate is not approval."),
            Line::from("Unavailable means no valid decision was produced."),
            Line::from("The log stores redacted decision details."),
            Line::from(""),
            help_heading("KEYS"),
            Line::from("/ search  v outcome filter  r runtime filter"),
            Line::from("s summary of every call the log holds"),
        ],
    });
    if app.confirmation.is_some() {
        lines.extend([
            Line::from(""),
            help_heading("OPEN PROMPT"),
            Line::from("Close help, then y confirms; n or Esc cancels."),
        ]);
    }
    lines.extend([
        Line::from(""),
        help_heading("GLOBAL"),
        Line::from("1-3 open tab  Tab/Shift-Tab cycle tabs"),
        Line::from("Up/Down or j/k move  PgUp/PgDn scroll details"),
        Line::from("R refresh  q quit"),
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
        Screen::Runtimes => "Runtime integrations",
        Screen::Log => "Decision log",
    }
}

fn render_confirmation(frame: &mut Frame<'_>, confirmation: &Confirmation, spacing: Spacing) {
    let text = confirmation_lines(confirmation);
    let (area, padding) = dialog_area(&text, 40, spacing, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Confirm ")
                    .borders(Borders::ALL)
                    .padding(Padding::horizontal(padding))
                    .border_style(Style::new().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn confirmation_lines(confirmation: &Confirmation) -> Vec<Line<'static>> {
    match confirmation {
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
                            "Failures return to the runtime unless guarded evidence remains."
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
            Line::from(match mode {
                NapMode::SelfProtection => {
                    "Self-protection resumes immediately, for every session.".to_owned()
                }
                NapMode::All => {
                    "All paused enforcement resumes immediately, for every session.".to_owned()
                }
                NapMode::Guards(_) => format!(
                    "Enforcement of the napped {} resumes immediately, for every session.",
                    mode.scope()
                ),
            }),
        ],
        Confirmation::DiscardChanges { count } => vec![
            Line::styled(
                "Discard staged changes?",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::from("y discard and quit  n keep editing"),
            Line::from(""),
            Line::from(format!("{count} unapplied change(s) will be lost.")),
        ],
    }
}

/// Where a dialog of `text` goes, and its padding. Without margins its box
/// is two columns narrower than the terminal, at least `min_width` and at
/// most 84 wide; it keeps inside the margins, padded, at a width that wraps
/// its text to no more rows than that, and otherwise reaches into them.
/// Centred on the terminal, it is as tall as its text up to the terminal's
/// height, so it sits inside the margins whenever it fits there.
fn dialog_area(text: &[Line<'_>], min_width: u16, spacing: Spacing, terminal: Rect) -> (Rect, u16) {
    let unspaced = terminal.width.saturating_sub(2).clamp(min_width, 84) - 2;
    let rows = wrapped_height(text, unspaced);
    let (text_width, padding) = [spacing.padding, 0]
        .into_iter()
        .map(|padding| {
            let room = spacing.content.width.saturating_sub(2 + 2 * padding);
            (unspaced.min(room), padding)
        })
        .find(|(width, _)| wrapped_height(text, *width) == rows)
        .unwrap_or((unspaced, 0));
    let height = u16::try_from(rows + 2)
        .unwrap_or(u16::MAX)
        .min(terminal.height);
    (
        centered_rect(text_width + 2 + 2 * padding, height, terminal),
        padding,
    )
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
