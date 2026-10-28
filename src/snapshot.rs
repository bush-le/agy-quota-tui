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
const FG_BLUE: &str = "\x1b[38;2;122;162;247m";
const FG_CYAN: &str = "\x1b[38;2;125;207;255m";
const FG_GREEN: &str = "\x1b[38;2;115;218;202m";
const FG_LIME: &str = "\x1b[38;2;158;206;106m";
const FG_AMBER: &str = "\x1b[38;2;224;175;104m";
const FG_RED: &str = "\x1b[38;2;247;118;142m";
const FG_PURPLE: &str = "\x1b[38;2;187;154;247m";
const FG_TEXT: &str = "\x1b[38;2;192;202;245m";
const FG_MUTED: &str = "\x1b[38;2;120;124;153m";
const FG_BAR_BG: &str = "\x1b[38;2;65;72;104m";

fn color_for_fraction(frac: f64) -> &'static str {
    let clamped = safe_fraction(frac);
    if clamped < 0.25 {
        FG_RED
    } else if clamped < 0.60 {
        FG_AMBER
    } else {
        FG_GREEN
    }
}

fn render_bar(frac: f64, width: usize) -> String {
    let clamped = safe_fraction(frac);
    let filled = ((clamped * width as f64).round() as usize).min(width);
    let empty = width.saturating_sub(filled);
    let color = color_for_fraction(clamped);
    format!(
        "{BOLD}{color}{}{RESET}{DIM}{FG_BAR_BG}{}{RESET}",
        "━".repeat(filled),
        "╌".repeat(empty)
    )
}

fn format_bucket_reset_ansi(bucket: &BucketQuota, now_epoch: f64) -> String {
    if bucket.window == "5h" && bucket.is_full() {
        return format!("{DIM}{FG_LIME}Ready (5h){RESET}");
    }
    let cd = bucket.format_countdown(now_epoch, true);
    let local = bucket.format_local_reset();
    if local.is_empty() {
        format!("{FG_CYAN}Reset: {cd}{RESET}")
    } else {
        format!("{FG_CYAN}Reset: {cd}{RESET} {DIM}{FG_MUTED}({local}){RESET}")
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

pub fn render_snapshot_to_stdout(snapshots: &[AccountSnapshot], only_5h: bool) {
    let now_epoch = now_epoch_secs();
    let now_str = Local::now().format("%H:%M:%S").to_string();
    let recs = compute_recommendations(snapshots);
    let top_ids: BTreeSet<&str> = recs.iter().map(|r| r.profile_id.as_str()).collect();

    println!(
        "{BOLD}{FG_BLUE}╭─  AGY MULTI-ACCOUNT QUOTA MONITOR · {now_str}  ────────────────────────────────────────────╮{RESET}"
    );
    print!("{BOLD}{FG_BLUE}│{RESET} {BOLD}{FG_AMBER}BEST ACCOUNT  >  {RESET}");
    if recs.is_empty() {
        print!("{DIM}{FG_MUTED}No account data available{RESET}");
    } else {
        for (idx, rec) in recs.iter().enumerate() {
            if idx > 0 {
                print!("   {DIM}{FG_MUTED}│{RESET}   ");
            }
            print!(
                "{FG_TEXT}{}: {RESET}{BOLD}{FG_GREEN}{}{RESET} {FG_MUTED}({}){RESET}",
                rec.family, rec.command_hint, rec.reason
            );
        }
    }
    println!();
    println!(
        "{BOLD}{FG_BLUE}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
    );

    for (i, snap) in snapshots.iter().enumerate() {
        let idx = i + 1;
        let is_top = top_ids.contains(snap.profile_id.as_str());
        let (badge, border_col) = if !snap.ok {
            (format!("{BOLD}{FG_RED}[ERR]{RESET}"), FG_RED)
        } else if is_top && snap.health_state() == "ok" {
            (format!("{BOLD}{FG_LIME}[BEST]{RESET}"), FG_GREEN)
        } else if snap.health_state() == "crit" {
            (format!("{BOLD}{FG_RED}[LOW]{RESET}"), FG_RED)
        } else if snap.health_state() == "warn" {
            (format!("{BOLD}{FG_AMBER}[WARN]{RESET}"), FG_AMBER)
        } else {
            (format!("{BOLD}{FG_GREEN}[OK]{RESET}"), FG_BLUE)
        };

        println!(
            "{border_col}╭─{RESET} {BOLD}{FG_TEXT}[{idx}] {}{RESET} {badge} {DIM}{FG_MUTED}(cmd: {}){RESET}",
            snap.label, snap.command_hint
        );

        if !snap.ok {
            let err_msg = if snap.error.is_empty() {
                "Not logged in or connection error."
            } else {
                &snap.error
            };
            println!(
                "{border_col}│{RESET}   {BOLD}{FG_RED}[ERROR] Failed to fetch quota:{RESET} {FG_TEXT}{err_msg}{RESET}"
            );
            println!(
                "{border_col}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
            );
            continue;
        }

        let buckets_5h = snap.all_buckets(true);
        if !buckets_5h.is_empty() {
            println!("{border_col}│{RESET} {BOLD}{FG_BLUE}5-HOUR LIMIT{RESET}");
            for (g_short, b) in &buckets_5h {
                let label_col = pad_right(g_short, 22);
                let bar = render_bar(b.remaining_fraction, 10);
                let pct_col = color_for_fraction(b.remaining_fraction);
                let pct = b.remaining_pct();
                let rst = format_bucket_reset_ansi(b, now_epoch);
                println!(
                    "{border_col}│{RESET}   {FG_TEXT}{label_col}{RESET} {bar} {BOLD}{pct_col}{pct:3}%{RESET}  {rst}"
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
                    "{border_col}│{RESET} {BOLD}{FG_PURPLE}WEEKLY LIMIT{RESET}"
                );
                for (g_short, b) in &buckets_wk {
                    let label_col = pad_right(g_short, 22);
                    let bar = render_bar(b.remaining_fraction, 10);
                    let pct_col = color_for_fraction(b.remaining_fraction);
                    let pct = b.remaining_pct();
                    let rst = format_bucket_reset_ansi(b, now_epoch);
                    println!(
                        "{border_col}│{RESET}   {FG_TEXT}{label_col}{RESET} {bar} {BOLD}{pct_col}{pct:3}%{RESET}  {rst}"
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
    println!(
        "{BOLD}{FG_BLUE}╭─ Discovered / Configured Antigravity Profiles ────────────────────────────────────────────╮{RESET}"
    );
    println!(
        "{BOLD}{FG_BLUE}│{RESET} {BOLD}{FG_CYAN}#   ID       Label                  Mode            Container      Isolated Home{RESET}"
    );
    println!(
        "{BOLD}{FG_BLUE}├─── ──────── ────────────────────── ─────────────── ────────────── ────────────────────────┤{RESET}"
    );
    for (idx, p) in profiles.iter().enumerate() {
        let num = pad_right(&format!("{}", idx + 1), 3);
        let id = pad_right(&p.id, 8);
        let label = pad_right(&p.label, 22);
        let mode = pad_right(&p.mode, 15);
        let container = pad_right(p.container.as_deref().unwrap_or("—"), 14);
        let display_home = anonymize_home_path(&p.home_dir);
        println!(
            "{BOLD}{FG_BLUE}│{RESET} {FG_CYAN}{num}{RESET} {BOLD}{FG_GREEN}{id}{RESET} {FG_TEXT}{label}{RESET} {FG_PURPLE}{mode}{RESET} {FG_AMBER}{container}{RESET} {FG_TEXT}{display_home}{RESET}",
        );
    }
    println!(
        "{BOLD}{FG_BLUE}╰───────────────────────────────────────────────────────────────────────────────────────────╯{RESET}"
    );
    println!(
        "{DIM}{FG_MUTED}Poll interval: {}s | Filter: {} | Theme: {}{RESET}",
        config.poll_interval, config.filter_mode, config.theme
    );
}
