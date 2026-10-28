//! Interactive `ratatui` + `crossterm` Live TUI Dashboard (`agy-top`).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Local;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

use crate::collector::{compute_recommendations, QuotaCollector};
use crate::models::{
    format_epoch_hms, now_epoch_secs, safe_fraction, AccountSnapshot, BucketQuota, ProfileSpec,
};
use crate::profiles::{save_user_preferences, AppConfig, ALLOWED_THEMES};

pub const POLL_INTERVAL_CHOICES: [u64; 3] = [120, 300, 900];

#[derive(Debug, Clone, Copy)]
pub struct ThemePalette {
    pub bg: Color,
    pub panel_bg: Color,
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    pub purple: Color,
    pub cyan: Color,
    pub ok: Color,
    pub best: Color,
    pub warn: Color,
    pub crit: Color,
    pub bar_empty: Color,
}

pub fn palette_for_theme(name: &str) -> ThemePalette {
    match name {
        "catppuccin-mocha" => ThemePalette {
            bg: Color::Rgb(30, 30, 46),
            panel_bg: Color::Rgb(24, 24, 37),
            fg: Color::Rgb(205, 214, 244),
            muted: Color::Rgb(108, 112, 134),
            accent: Color::Rgb(137, 180, 250),
            purple: Color::Rgb(203, 166, 247),
            cyan: Color::Rgb(137, 220, 235),
            ok: Color::Rgb(148, 226, 213),
            best: Color::Rgb(166, 227, 161),
            warn: Color::Rgb(249, 226, 175),
            crit: Color::Rgb(243, 139, 168),
            bar_empty: Color::Rgb(69, 71, 90),
        },
        "dracula" => ThemePalette {
            bg: Color::Rgb(40, 42, 54),
            panel_bg: Color::Rgb(33, 34, 44),
            fg: Color::Rgb(248, 248, 242),
            muted: Color::Rgb(98, 114, 164),
            accent: Color::Rgb(189, 147, 249),
            purple: Color::Rgb(255, 121, 198),
            cyan: Color::Rgb(139, 233, 253),
            ok: Color::Rgb(80, 250, 123),
            best: Color::Rgb(80, 250, 123),
            warn: Color::Rgb(241, 250, 140),
            crit: Color::Rgb(255, 85, 85),
            bar_empty: Color::Rgb(68, 71, 90),
        },
        "nord" => ThemePalette {
            bg: Color::Rgb(46, 52, 64),
            panel_bg: Color::Rgb(59, 66, 82),
            fg: Color::Rgb(236, 239, 244),
            muted: Color::Rgb(143, 188, 187),
            accent: Color::Rgb(136, 192, 208),
            purple: Color::Rgb(180, 142, 173),
            cyan: Color::Rgb(129, 161, 193),
            ok: Color::Rgb(163, 190, 140),
            best: Color::Rgb(163, 190, 140),
            warn: Color::Rgb(235, 203, 139),
            crit: Color::Rgb(191, 97, 106),
            bar_empty: Color::Rgb(76, 86, 106),
        },
        "gruvbox" => ThemePalette {
            bg: Color::Rgb(40, 40, 40),
            panel_bg: Color::Rgb(29, 32, 33),
            fg: Color::Rgb(235, 219, 178),
            muted: Color::Rgb(146, 131, 116),
            accent: Color::Rgb(131, 165, 152),
            purple: Color::Rgb(211, 134, 155),
            cyan: Color::Rgb(142, 192, 124),
            ok: Color::Rgb(184, 187, 38),
            best: Color::Rgb(184, 187, 38),
            warn: Color::Rgb(250, 189, 47),
            crit: Color::Rgb(251, 73, 52),
            bar_empty: Color::Rgb(80, 73, 69),
        },
        _ => ThemePalette {
            // tokyo-night (default)
            bg: Color::Rgb(26, 27, 38),
            panel_bg: Color::Rgb(22, 22, 30),
            fg: Color::Rgb(192, 202, 245),
            muted: Color::Rgb(120, 124, 153),
            accent: Color::Rgb(122, 162, 247),
            purple: Color::Rgb(187, 154, 247),
            cyan: Color::Rgb(125, 207, 255),
            ok: Color::Rgb(115, 218, 202),
            best: Color::Rgb(158, 206, 106),
            warn: Color::Rgb(224, 175, 104),
            crit: Color::Rgb(247, 118, 142),
            bar_empty: Color::Rgb(65, 72, 104),
        },
    }
}

pub struct DashboardState {
    pub profiles: Vec<ProfileSpec>,
    pub config: AppConfig,
    pub snapshots: BTreeMap<String, AccountSnapshot>,
    pub is_syncing: bool,
    pub last_sync_epoch: f64,
    pub next_poll_epoch: f64,
    pub toast: Option<(String, Instant)>,
    pub expired_triggered: BTreeSet<(String, String, i64)>,
}

impl DashboardState {
    pub fn new(profiles: Vec<ProfileSpec>, config: AppConfig, cached: Vec<AccountSnapshot>) -> Self {
        let now = now_epoch_secs();
        let mut snapshots = BTreeMap::new();
        let mut last_sync: f64 = 0.0;
        for snap in cached {
            if snap.fetched_at_epoch > last_sync {
                last_sync = snap.fetched_at_epoch;
            }
            snapshots.insert(snap.profile_id.clone(), snap);
        }
        Self {
            profiles,
            next_poll_epoch: now + config.poll_interval as f64,
            config,
            snapshots,
            is_syncing: false,
            last_sync_epoch: last_sync,
            toast: None,
            expired_triggered: BTreeSet::new(),
        }
    }

    pub fn ordered_snapshots(&self) -> Vec<AccountSnapshot> {
        self.profiles
            .iter()
            .filter_map(|p| self.snapshots.get(&p.id).cloned())
            .collect()
    }

    pub fn toggle_filter(&mut self) {
        self.config.filter_mode = if self.config.filter_mode == "all" {
            "5h".to_string()
        } else {
            "all".to_string()
        };
        let label = if self.config.filter_mode == "5h" {
            "5-Hour Limits Only"
        } else {
            "All Limits (5h + Weekly)"
        };
        self.toast = Some((label.to_string(), Instant::now()));
    }

    pub fn cycle_interval(&mut self) {
        let cur = self.config.poll_interval;
        let idx = POLL_INTERVAL_CHOICES
            .iter()
            .position(|&x| x == cur)
            .unwrap_or(1);
        let next = POLL_INTERVAL_CHOICES[(idx + 1) % POLL_INTERVAL_CHOICES.len()];
        self.config.poll_interval = next;
        self.next_poll_epoch = now_epoch_secs() + next as f64;
        self.toast = Some((
            format!("Auto-refresh interval: {}m", next / 60),
            Instant::now(),
        ));
    }

    pub fn cycle_theme(&mut self) {
        let cur = self.config.theme.as_str();
        let idx = ALLOWED_THEMES.iter().position(|&t| t == cur).unwrap_or(0);
        let next = ALLOWED_THEMES[(idx + 1) % ALLOWED_THEMES.len()];
        self.config.theme = next.to_string();
        self.toast = Some((format!("Theme: {next}"), Instant::now()));
    }
}

fn color_for_frac(frac: f64, pal: &ThemePalette) -> Color {
    let clamped = safe_fraction(frac);
    if clamped < 0.25 {
        pal.crit
    } else if clamped < 0.60 {
        pal.warn
    } else {
        pal.ok
    }
}

fn build_bar_spans(frac: f64, width: usize, pal: &ThemePalette) -> Vec<Span<'static>> {
    let clamped = safe_fraction(frac);
    let filled = ((clamped * width as f64).round() as usize).min(width);
    let empty = width.saturating_sub(filled);
    let col = color_for_frac(clamped, pal);
    vec![
        Span::styled(
            "█".repeat(filled),
            Style::default().fg(col).add_modifier(Modifier::BOLD),
        ),
        Span::styled("░".repeat(empty), Style::default().fg(pal.bar_empty)),
    ]
}

fn build_reset_line(bucket: &BucketQuota, now_epoch: f64, pal: &ThemePalette) -> Line<'static> {
    if bucket.window == "5h" && bucket.is_full() {
        return Line::from(vec![
            Span::raw("    "),
            Span::styled("Ready (5h)", Style::default().fg(pal.best)),
        ]);
    }
    let cd = bucket.format_countdown(now_epoch, true);
    let local = bucket.format_local_reset();
    let mut spans = vec![
        Span::raw("    "),
        Span::styled(format!("Reset: {cd}"), Style::default().fg(pal.cyan)),
    ];
    if !local.is_empty() {
        spans.push(Span::styled(
            format!(" ({local})"),
            Style::default().fg(pal.muted),
        ));
    }
    Line::from(spans)
}

fn pad_group_name(name: &str, target_width: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() >= target_width {
        chars.into_iter().take(target_width).collect()
    } else {
        let mut s: String = chars.into_iter().collect();
        s.push_str(&" ".repeat(target_width - name.chars().count()));
        s
    }
}

fn render_account_card(
    frame: &mut Frame,
    area: Rect,
    idx: usize,
    prof: &ProfileSpec,
    snap_opt: Option<&AccountSnapshot>,
    now_epoch: f64,
    only_5h: bool,
    is_best: bool,
    is_syncing: bool,
    pal: &ThemePalette,
) {
    let sync_mark = if is_syncing { " [SYNC]" } else { "" };

    let Some(snap) = snap_opt else {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(pal.muted))
            .style(Style::default().bg(pal.panel_bg).fg(pal.fg))
            .title(Span::styled(
                format!(" [{idx}] {} · Loading... ", prof.label),
                Style::default().fg(pal.fg).add_modifier(Modifier::BOLD),
            ));
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Querying quota data...",
                Style::default().fg(pal.muted),
            )),
        ])
        .block(block);
        frame.render_widget(p, area);
        return;
    };

    let state = snap.health_state();
    let (badge, border_color) = if !snap.ok {
        ("ERR", pal.crit)
    } else if is_best && state == "ok" {
        ("BEST", pal.best)
    } else if state == "crit" {
        ("LOW", pal.crit)
    } else if state == "warn" {
        ("WARN", pal.warn)
    } else {
        ("OK", pal.accent)
    };

    let title_line = Line::from(vec![
        Span::styled(
            format!(" [{idx}] {} · ", snap.label),
            Style::default().fg(pal.fg).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{badge}{sync_mark} "),
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(pal.panel_bg).fg(pal.fg))
        .title(title_line)
        .title_bottom(
            Line::from(Span::styled(
                format!(" cmd: {} ", snap.command_hint),
                Style::default().fg(pal.muted),
            ))
            .alignment(Alignment::Right),
        );

    if !snap.ok {
        let err_msg = if snap.error.is_empty() {
            "Not logged in or connection error."
        } else {
            &snap.error
        };
        let lines = vec![
            Line::from(Span::styled(
                " [ERROR] Failed to fetch quota data:",
                Style::default().fg(pal.crit).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!(" {err_msg}"),
                Style::default().fg(pal.fg),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!(" Run `{}` in terminal to diagnose.", snap.command_hint),
                Style::default().fg(pal.muted),
            )),
        ];
        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
        frame.render_widget(p, area);
        return;
    }

    let name_width = if area.width >= 42 { 16 } else { 13 };
    let bar_width = if area.width >= 44 { 10 } else { 8 };
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(16);

    let buckets_5h = snap.all_buckets(true);
    if !buckets_5h.is_empty() {
        lines.push(Line::from(Span::styled(
            " 5-HOUR LIMIT",
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        )));
        for (g_short, b) in &buckets_5h {
            let mut row_spans = vec![Span::styled(
                format!("  {} ", pad_group_name(g_short, name_width)),
                Style::default().fg(pal.fg).add_modifier(Modifier::BOLD),
            )];
            row_spans.extend(build_bar_spans(b.remaining_fraction, bar_width, pal));
            let pct_col = color_for_frac(b.remaining_fraction, pal);
            row_spans.push(Span::styled(
                format!(" {:3}%", b.remaining_pct()),
                Style::default().fg(pct_col).add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::from(row_spans));
            lines.push(build_reset_line(b, now_epoch, pal));
        }
    }

    if !only_5h {
        let buckets_wk: Vec<(String, &BucketQuota)> = snap
            .all_buckets(false)
            .into_iter()
            .filter(|(_, b)| b.window != "5h")
            .collect();
        if !buckets_wk.is_empty() {
            if !buckets_5h.is_empty() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                " WEEKLY LIMIT",
                Style::default().fg(pal.purple).add_modifier(Modifier::BOLD),
            )));
            for (g_short, b) in &buckets_wk {
                let mut row_spans = vec![Span::styled(
                    format!("  {} ", pad_group_name(g_short, name_width)),
                    Style::default().fg(pal.fg).add_modifier(Modifier::BOLD),
                )];
                row_spans.extend(build_bar_spans(b.remaining_fraction, bar_width, pal));
                let pct_col = color_for_frac(b.remaining_fraction, pal);
                row_spans.push(Span::styled(
                    format!(" {:3}%", b.remaining_pct()),
                    Style::default().fg(pct_col).add_modifier(Modifier::BOLD),
                ));
                lines.push(Line::from(row_spans));
                lines.push(build_reset_line(b, now_epoch, pal));
            }
        }
    }

    let p = Paragraph::new(lines).block(block);
    frame.render_widget(p, area);
}

pub fn render_dashboard(frame: &mut Frame, state: &DashboardState) {
    let pal = palette_for_theme(&state.config.theme);
    let now_epoch = now_epoch_secs();
    let area = frame.area();

    frame.render_widget(
        Block::default().style(Style::default().bg(pal.bg).fg(pal.fg)),
        area,
    );

    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(area);

    // 1. Top Header Bar
    let clock_str = Local::now().format("%H:%M:%S").to_string();
    let header_line = Line::from(vec![
        Span::styled(
            " AGY Quota Monitor ",
            Style::default()
                .fg(pal.bg)
                .bg(pal.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  Theme: {}  │  {clock_str}", state.config.theme),
            Style::default().fg(pal.muted),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(header_line).style(Style::default().bg(pal.panel_bg)),
        root_chunks[0],
    );

    // 2. Best Account Recommendation Banner
    let ordered = state.ordered_snapshots();
    let recs = compute_recommendations(&ordered);
    let top_ids: BTreeSet<String> = recs.iter().map(|r| r.profile_id.clone()).collect();

    let interval_min = state.config.poll_interval / 60;
    let rem_poll = (state.next_poll_epoch - now_epoch).max(0.0) as u64;
    let pm = rem_poll / 60;
    let ps = rem_poll % 60;
    let filter_label = if state.config.filter_mode == "5h" {
        "5h Only"
    } else {
        "All (5h + Weekly)"
    };
    let updated_str = format_epoch_hms(state.last_sync_epoch);
    let sync_status = if state.is_syncing {
        format!(
            "Syncing {} accounts...",
            state.profiles.len()
        )
    } else {
        format!(
            "Interval: {interval_min}m ({pm:02}:{ps:02}) · Filter: {filter_label} · Updated: {updated_str}"
        )
    };

    let banner_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(pal.accent))
        .style(Style::default().bg(pal.panel_bg).fg(pal.fg))
        .title(Span::styled(
            format!(" AGY MULTI-ACCOUNT QUOTA  │  {sync_status} "),
            Style::default().fg(pal.accent).add_modifier(Modifier::BOLD),
        ));

    let mut rec_spans = vec![Span::styled(
        " BEST ACCOUNT  >  ",
        Style::default().fg(pal.warn).add_modifier(Modifier::BOLD),
    )];
    if recs.is_empty() {
        rec_spans.push(Span::styled(
            "Analyzing quota data...",
            Style::default().fg(pal.muted),
        ));
    } else {
        for (idx, rec) in recs.iter().enumerate() {
            if idx > 0 {
                rec_spans.push(Span::styled("   │   ", Style::default().fg(pal.muted)));
            }
            rec_spans.push(Span::styled(
                format!("{}: ", rec.family),
                Style::default().fg(pal.fg),
            ));
            rec_spans.push(Span::styled(
                rec.command_hint.clone(),
                Style::default().fg(pal.ok).add_modifier(Modifier::BOLD),
            ));
            rec_spans.push(Span::styled(
                format!(" ({})", rec.reason),
                Style::default().fg(pal.muted),
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(Line::from(rec_spans)).block(banner_block),
        root_chunks[1],
    );

    // 3. Responsive Accounts Grid (3-col >= 122, 2-col >= 82, 1-col < 82)
    let cards_area = root_chunks[2];
    let num_profiles = state.profiles.len().max(1);
    let cols = if cards_area.width >= 122 && num_profiles >= 3 {
        3
    } else if cards_area.width >= 82 && num_profiles >= 2 {
        2
    } else {
        1
    };

    let rows = num_profiles.div_ceil(cols);
    let row_constraints: Vec<Constraint> = (0..rows)
        .map(|_| Constraint::Ratio(1, rows as u32))
        .collect();
    let row_rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(cards_area);

    let only_5h = state.config.filter_mode == "5h";
    for r in 0..rows {
        let start_idx = r * cols;
        let end_idx = (start_idx + cols).min(state.profiles.len());
        let slice = &state.profiles[start_idx..end_idx];
        let col_constraints: Vec<Constraint> = (0..cols)
            .map(|_| Constraint::Ratio(1, cols as u32))
            .collect();
        let col_rects = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints)
            .split(row_rects[r]);

        for (c_idx, prof) in slice.iter().enumerate() {
            let snap_opt = state.snapshots.get(&prof.id);
            let is_best = top_ids.contains(&prof.id);
            render_account_card(
                frame,
                col_rects[c_idx],
                start_idx + c_idx + 1,
                prof,
                snap_opt,
                now_epoch,
                only_5h,
                is_best,
                state.is_syncing,
                &pal,
            );
        }
    }

    // 4. Bottom Keybindings & Toast Footer
    let mut footer_spans = vec![
        Span::styled(
            " r ",
            Style::default()
                .fg(pal.bg)
                .bg(pal.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Refresh  ", Style::default().fg(pal.fg)),
        Span::styled(
            " f ",
            Style::default()
                .fg(pal.bg)
                .bg(pal.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Filter 5h/All  ", Style::default().fg(pal.fg)),
        Span::styled(
            " i ",
            Style::default()
                .fg(pal.bg)
                .bg(pal.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Interval  ", Style::default().fg(pal.fg)),
        Span::styled(
            " t ",
            Style::default()
                .fg(pal.bg)
                .bg(pal.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Theme  ", Style::default().fg(pal.fg)),
        Span::styled(
            " q ",
            Style::default()
                .fg(pal.bg)
                .bg(pal.crit)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Quit ", Style::default().fg(pal.fg)),
    ];

    if let Some((msg, ts)) = &state.toast {
        if ts.elapsed() < Duration::from_secs(3) {
            footer_spans.push(Span::styled("  │  ", Style::default().fg(pal.muted)));
            footer_spans.push(Span::styled(
                msg.clone(),
                Style::default().fg(pal.best).add_modifier(Modifier::BOLD),
            ));
        }
    }

    frame.render_widget(
        Paragraph::new(Line::from(footer_spans)).style(Style::default().bg(pal.panel_bg)),
        root_chunks[3],
    );
}

struct TerminalCleanupGuard;

impl Drop for TerminalCleanupGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

fn spawn_sync_worker(
    collector: &Arc<QuotaCollector>,
    sync_flag: &Arc<AtomicBool>,
    tx: &mpsc::Sender<Vec<AccountSnapshot>>,
    force: bool,
) -> bool {
    if sync_flag
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return false;
    }
    let col = Arc::clone(collector);
    let flag = Arc::clone(sync_flag);
    let sender = tx.clone();
    thread::spawn(move || {
        let results = col.collect_all(force);
        flag.store(false, Ordering::SeqCst);
        let _ = sender.send(results);
    });
    true
}

pub fn run_live_tui(collector: Arc<QuotaCollector>, config: AppConfig) -> io::Result<()> {
    let cached = collector.load_cached();
    let profiles = collector.profiles().to_vec();
    let mut state = DashboardState::new(profiles, config, cached);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalCleanupGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let (tx, rx) = mpsc::channel::<Vec<AccountSnapshot>>();
    let sync_flag = Arc::new(AtomicBool::new(false));

    // Trigger initial background refresh
    if spawn_sync_worker(&collector, &sync_flag, &tx, true) {
        state.is_syncing = true;
    }

    loop {
        while let Ok(results) = rx.try_recv() {
            for snap in results {
                state.snapshots.insert(snap.profile_id.clone(), snap);
            }
            state.last_sync_epoch = now_epoch_secs();
            state.next_poll_epoch = state.last_sync_epoch + state.config.poll_interval as f64;
            state.is_syncing = sync_flag.load(Ordering::SeqCst);
        }

        let now = now_epoch_secs();
        let mut should_poll = now >= state.next_poll_epoch;

        for snap in state.snapshots.values() {
            if !snap.ok {
                continue;
            }
            for (_, bucket) in snap.all_buckets(false) {
                if let Some(rep) = bucket.reset_epoch {
                    if !bucket.is_full() {
                        let key = (
                            snap.profile_id.clone(),
                            bucket.id.clone(),
                            rep.trunc() as i64,
                        );
                        if now >= rep && !state.expired_triggered.contains(&key) {
                            if state.expired_triggered.len() >= 256 {
                                state.expired_triggered.clear();
                            }
                            state.expired_triggered.insert(key);
                            should_poll = true;
                        }
                    }
                }
            }
        }

        if should_poll && !state.is_syncing {
            state.next_poll_epoch = now + state.config.poll_interval as f64;
            if spawn_sync_worker(&collector, &sync_flag, &tx, true) {
                state.is_syncing = true;
            }
        }

        terminal.draw(|frame| render_dashboard(frame, &state))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        if state.is_syncing {
                            state.toast = Some((
                                "Syncing data, please wait...".to_string(),
                                Instant::now(),
                            ));
                        } else if spawn_sync_worker(&collector, &sync_flag, &tx, false) {
                            state.is_syncing = true;
                        }
                    }
                    KeyCode::Char('f') | KeyCode::Char('F') => {
                        state.toggle_filter();
                        save_user_preferences(
                            state.config.poll_interval,
                            &state.config.filter_mode,
                            &state.config.theme,
                            None,
                        );
                    }
                    KeyCode::Char('i') | KeyCode::Char('I') => {
                        state.cycle_interval();
                        save_user_preferences(
                            state.config.poll_interval,
                            &state.config.filter_mode,
                            &state.config.theme,
                            None,
                        );
                    }
                    KeyCode::Char('t') | KeyCode::Char('T') => {
                        state.cycle_theme();
                        save_user_preferences(
                            state.config.poll_interval,
                            &state.config.filter_mode,
                            &state.config.theme,
                            None,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
