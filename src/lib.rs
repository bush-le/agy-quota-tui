//! `agy-top` (`agy-quota`) — Security-hardened Multi-Account Quota & Refresh Timer TUI/CLI.

#![forbid(unsafe_code)]

pub mod collector;
pub mod models;
pub mod profiles;
pub mod security;
pub mod snapshot;
pub mod tui;

use std::env;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::collector::{compute_recommendations, QuotaCollector};
use crate::profiles::get_active_profiles;
use crate::security::{ensure_non_root, redact_sensitive_text, SecurityError};
use crate::snapshot::{print_profiles_table, render_snapshot_to_stdout};
use crate::tui::run_live_tui;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CliArgs {
    pub status: bool,
    pub only_5h: bool,
    pub cached: bool,
    pub json: bool,
    pub list_profiles: bool,
    pub help: bool,
    pub version: bool,
}

pub fn parse_cli_args<I, S>(args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = CliArgs::default();
    for raw in args {
        let arg = raw.as_ref();
        match arg {
            "-s" | "--status" => out.status = true,
            "-5" | "--only-5h" => out.only_5h = true,
            "-c" | "--cached" => out.cached = true,
            "-sc" | "-cs" => {
                out.status = true;
                out.cached = true;
            }
            "-s5" | "-5s" => {
                out.status = true;
                out.only_5h = true;
            }
            "--json" => out.json = true,
            "--list-profiles" => out.list_profiles = true,
            "-h" | "--help" => out.help = true,
            "-v" | "-V" | "--version" => out.version = true,
            unknown => {
                return Err(format!(
                    "Unknown argument: {unknown}\nRun 'agy-top --help' for usage."
                ))
            }
        }
    }
    Ok(out)
}

pub fn print_help() {
    println!(
        "agy-top {VERSION} — Security-hardened Multi-Account Quota & Refresh Timer TUI for Antigravity CLI

USAGE:
    agy-top [OPTIONS]

OPTIONS:
    -s, --status          Print a 24-bit colorized quota snapshot table to stdout and exit
    -5, --only-5h         Show only 5-hour rolling quota limits
    -c, --cached          Use the most recent cached snapshot if available (<5ms)
        --json            Output sanitized quota snapshots and recommendations as JSON
        --list-profiles   List auto-discovered or configured Antigravity profiles
    -v, --version         Print version information and exit
    -h, --help            Print this help message and exit"
    );
}

pub fn run_cli() -> i32 {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let args = match parse_cli_args(&raw_args) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{}", redact_sensitive_text(&msg, 240));
            return 2;
        }
    };

    if args.help {
        print_help();
        return 0;
    }
    if args.version {
        println!("agy-top {VERSION}");
        return 0;
    }

    let result = (|| -> Result<i32, SecurityError> {
        ensure_non_root()?;
        let (mut config, profiles) = get_active_profiles(None)?;
        if args.list_profiles {
            print_profiles_table(&config, &profiles);
            return Ok(0);
        }

        if args.only_5h {
            config.filter_mode = "5h".to_string();
        }

        let collector = Arc::new(QuotaCollector::new(profiles, Duration::from_secs(3)));

        if args.status || args.json {
            let mut snapshots = if args.cached {
                collector.load_cached()
            } else {
                Vec::new()
            };
            if snapshots.is_empty() {
                snapshots = collector.collect_all(true);
            }

            if args.json {
                let recs = compute_recommendations(&snapshots);
                let payload = json!({
                    "accounts": snapshots,
                    "recommendations": recs,
                });
                if let Ok(pretty) = serde_json::to_string_pretty(&payload) {
                    println!("{pretty}");
                }
                return Ok(0);
            }

            render_snapshot_to_stdout(&snapshots, config.filter_mode == "5h");
            return Ok(0);
        }

        if let Err(e) = run_live_tui(collector, config) {
            eprintln!("TUI error: {}", redact_sensitive_text(&e.to_string(), 240));
            return Ok(1);
        }
        Ok(0)
    })();

    match result {
        Ok(code) => code,
        Err(sec_err) => {
            eprintln!(
                "[SecurityError] {}",
                redact_sensitive_text(&sec_err.to_string(), 240)
            );
            2
        }
    }
}
