//! 24-bit TrueColor terminal snapshot renderer (`agy-top -s` & `agy-top --list-profiles`).

use std::collections::BTreeSet;

use chrono::Local;

use crate::collector::compute_recommendations;
use crate::models::{now_epoch_secs, safe_fraction, AccountSnapshot, BucketQuota, ProfileSpec};
use crate::profiles::AppConfig;
use crate::security::anonymize_home_path;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn ansi_color(c: ratatui::style::Color) -> String {
    match c {
        ratatui::style::Color::Rgb(r, g, b) => format!("\x1b[38;2;{r};{g};{b}m"),
        _ => "\x1b[39m".to_string(),
    }
}

pub struct AnsiPalette {
    pub blue: String,
    pub cyan: String,
    pub green: String,
    pub lime: String,
    pub amber: String,
    pub red: String,
    pub purple: String,
    pub text: String,
    pub muted: String,
    pub bar_bg: String,
}

impl AnsiPalette {
    pub fn for_theme(name: &str) -> Self {
        let pal = crate::tui::palette_for_theme(name);
        Self {
            blue: ansi_color(pal.accent),
            cyan: ansi_color(pal.cyan),
            green: ansi_color(pal.ok),
            lime: ansi_color(pal.best),
            amber: ansi_color(pal.warn),
            red: ansi_color(pal.crit),
            purple: ansi_color(pal.purple),
            text: ansi_color(pal.fg),
            muted: ansi_color(pal.muted),
            bar_bg: ansi_color(pal.bar_empty),
        }
    }
}

fn color_for_fraction<'a>(frac: f64, pal: &'a AnsiPalette) -> &'a str {
    let clamped = safe_fraction(frac);
    if clamped < 0.25 {
        &pal.red
    } else if clamped < 0.60 {
        &pal.amber
    } else {
        &pal.green
    }
}

fn render_bar(frac: f64, width: usize, pal: &AnsiPalette) -> String {
    let clamped = safe_fraction(frac);
    let filled = ((clamped * width as f64).round() as usize).min(width);
    let empty = width.saturating_sub(filled);
    let color = color_for_fraction(clamped, pal);
    let bar_bg = &pal.bar_bg;
    format!(
        "{BOLD}{color}{}{RESET}{DIM}{bar_bg}{}{RESET}",
        "━".repeat(filled),
        "╌".repeat(empty)
    )
}

fn format_bucket_reset_ansi(bucket: &BucketQuota, now_epoch: f64, pal: &AnsiPalette) -> String {
    let lime = &pal.lime;
    let cyan = &pal.cyan;
    let muted = &pal.muted;
    if bucket.window == "5h" && bucket.is_full() {
        return format!("{DIM}{lime}Ready (5h){RESET}");
    }
    let cd = bucket.format_countdown(now_epoch, false);
    let local = bucket.format_local_reset();
    if local.is_empty() {
        format!("{cyan}Reset: {cd}{RESET}")
    } else {
        format!("{cyan}Reset: {cd}{RESET} {DIM}{muted}({local}){RESET}")
    }
}

fn pad_right(s: &str, width: usize) -> String {
    let count = s.chars().count();
    if count >= width {
        s.chars().take(width).collect()
    } else {
        format!("{s}{}", " ".repeat(width - count))
    }
}

pub fn render_snapshot_to_stdout(snapshots: &[AccountSnapshot], only_5h: bool, theme: &str) {
    let pal = AnsiPalette::for_theme(theme);
    let now_epoch = now_epoch_secs();
    let now_str = Local::now().format("%H:%M:%S").to_string();
    let recs = compute_recommendations(snapshots);
    let top_ids: BTreeSet<&str> = recs.iter().map(|r| r.profile_id.as_str()).collect();

    let blue = &pal.blue;
    let amber = &pal.amber;
    let muted = &pal.muted;
    let text = &pal.text;
    let green = &pal.green;
    let red = &pal.red;
    let lime = &pal.lime;
    let purple = &pal.purple;

    println!(
        "{BOLD}{blue}╭─  AGY MULTI-ACCOUNT QUOTA MONITOR · {now_str}  ────────────────────────────────────────────╮{RESET}"
    );
    print!("{BOLD}{blue}│{RESET} {BOLD}{amber}BEST ACCOUNT  >  {RESET}");
    if recs.is_empty() {
        print!("{DIM}{muted}No account data available{RESET}");
    } else {
        for (idx, rec) in recs.iter().enumerate() {
            if idx > 0 {
                print!("   {DIM}{muted}│{RESET}   ");
            }
            print!(
                "{text}{}: {RESET}{BOLD}{green}{}{RESET} {muted}({}){RESET}",
                rec.family, rec.command_hint, rec.reason
            );
        }
    }
    println!();
    println!(
        "{BOLD}{blue}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
    );

    for (i, snap) in snapshots.iter().enumerate() {
        let idx = i + 1;
        let is_top = top_ids.contains(snap.profile_id.as_str());
        let (badge, border_col) = if !snap.ok {
            (format!("{BOLD}{red}[ERR]{RESET}"), red)
        } else if is_top && snap.health_state() == "ok" {
            (format!("{BOLD}{lime}[BEST]{RESET}"), green)
        } else if snap.health_state() == "crit" {
            (format!("{BOLD}{red}[LOW]{RESET}"), red)
        } else if snap.health_state() == "warn" {
            (format!("{BOLD}{amber}[WARN]{RESET}"), amber)
        } else {
            (format!("{BOLD}{green}[OK]{RESET}"), blue)
        };

        println!(
            "{border_col}╭─{RESET} {BOLD}{text}[{idx}] {}{RESET} {badge} {DIM}{muted}(cmd: {}){RESET}",
            snap.label, snap.command_hint
        );

        if !snap.ok {
            let err_msg = if snap.error.is_empty() {
                "Not logged in or connection error."
            } else {
                &snap.error
            };
            println!(
                "{border_col}│{RESET}   {BOLD}{red}[ERROR] Failed to fetch quota:{RESET} {text}{err_msg}{RESET}"
            );
            println!(
                "{border_col}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
            );
            continue;
        }

        let buckets_5h = snap.all_buckets(true);
        if !buckets_5h.is_empty() {
            println!("{border_col}│{RESET} {BOLD}{blue}5-HOUR LIMIT{RESET}");
            for (g_short, b) in &buckets_5h {
                let label_col = pad_right(g_short, 22);
                let bar = render_bar(b.remaining_fraction, 10, &pal);
                let pct_col = color_for_fraction(b.remaining_fraction, &pal);
                let pct = b.remaining_pct();
                let rst = format_bucket_reset_ansi(b, now_epoch, &pal);
                println!(
                    "{border_col}│{RESET}   {text}{label_col}{RESET} {bar} {BOLD}{pct_col}{pct:3}%{RESET}  {rst}"
                );
            }
        }

        if !only_5h {
            let buckets_wk: Vec<(String, &BucketQuota)> = snap
                .all_buckets(false)
                .into_iter()
                .filter(|(_, b)| b.window != "5h")
                .collect();
            if !buckets_wk.is_empty() {
                println!(
                    "{border_col}│{RESET} {BOLD}{purple}WEEKLY LIMIT{RESET}"
                );
                for (g_short, b) in &buckets_wk {
                    let label_col = pad_right(g_short, 22);
                    let bar = render_bar(b.remaining_fraction, 10, &pal);
                    let pct_col = color_for_fraction(b.remaining_fraction, &pal);
                    let pct = b.remaining_pct();
                    let rst = format_bucket_reset_ansi(b, now_epoch, &pal);
                    println!(
                        "{border_col}│{RESET}   {text}{label_col}{RESET} {bar} {BOLD}{pct_col}{pct:3}%{RESET}  {rst}"
                    );
                }
            }
        }

        println!(
            "{border_col}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
        );
    }
}

pub fn print_profiles_table(config: &AppConfig, profiles: &[ProfileSpec]) {
    let pal = AnsiPalette::for_theme(&config.theme);
    let blue = &pal.blue;
    let cyan = &pal.cyan;
    let green = &pal.green;
    let text = &pal.text;
    let purple = &pal.purple;
    let amber = &pal.amber;
    let muted = &pal.muted;

    println!(
        "{BOLD}{blue}╭─ Discovered / Configured Antigravity Profiles ────────────────────────────────────────────╮{RESET}"
    );
    println!(
        "{BOLD}{blue}│{RESET} {BOLD}{cyan}#   ID       Label                  Mode            Container      Isolated Home{RESET}"
    );
    println!(
        "{BOLD}{blue}├─── ──────── ────────────────────── ─────────────── ────────────── ────────────────────────┤{RESET}"
    );
    for (idx, p) in profiles.iter().enumerate() {
        let num = pad_right(&format!("{}", idx + 1), 3);
        let id = pad_right(&p.id, 8);
        let label = pad_right(&p.label, 22);
        let mode = pad_right(&p.mode, 15);
        let container = pad_right(p.container.as_deref().unwrap_or("—"), 14);
        let display_home = anonymize_home_path(&p.home_dir);
        println!(
            "{BOLD}{blue}│{RESET} {cyan}{num}{RESET} {BOLD}{green}{id}{RESET} {text}{label}{RESET} {purple}{mode}{RESET} {amber}{container}{RESET} {text}{display_home}{RESET}",
        );
    }
    println!(
        "{BOLD}{blue}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
    );
    println!(
        "{DIM}{muted}Poll interval: {}s | Filter: {} | Theme: {}{RESET}",
        config.poll_interval, config.filter_mode, config.theme
    );
}
