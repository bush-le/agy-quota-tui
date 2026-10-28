//! Parallel quota collector, bounded subprocess runner, and Best Account recommendation engine.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use chrono::DateTime;
use serde_json::{json, Value};

use crate::models::{
    now_epoch_secs, safe_epoch, safe_fraction, AccountSnapshot, BestAccountRecommendation,
    BucketQuota, GroupQuota, ProfileSpec,
};
use crate::profiles::locate_agy_binary;
use crate::security::{
    atomic_write_json, build_isolated_command, get_safe_cache_dir, get_safe_empty_workspace,
    kill_process_group, redact_sensitive_text, safe_read_json, sanitize_terminal_text,
};

pub const MAX_SUBPROCESS_OUTPUT_BYTES: u64 = 262_144; // 256 KB hard cap
pub const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
pub const CACHE_FILENAME: &str = "quota-cache.json";

pub fn parse_iso_timestamp(iso_str: &str) -> Option<f64> {
    let trimmed = iso_str.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        let ep = dt.timestamp_millis() as f64 / 1000.0;
        return safe_epoch(Some(ep));
    }
    None
}

/// Validate and transform `agy -p /usage --output-format json` stdout into `AccountSnapshot`.
pub fn parse_usage_json(
    raw_stdout: &str,
    profile: &ProfileSpec,
    fetched_at: Option<f64>,
) -> AccountSnapshot {
    let now = fetched_at.unwrap_or_else(now_epoch_secs);

    let Some(start_idx) = raw_stdout.find('{') else {
        let err = redact_sensitive_text(
            if raw_stdout.trim().is_empty() {
                "Empty response from agy CLI"
            } else {
                raw_stdout
            },
            240,
        );
        return AccountSnapshot {
            profile_id: profile.id.clone(),
            label: profile.label.clone(),
            command_hint: profile.command_hint.clone(),
            mode: profile.mode.clone(),
            ok: false,
            fetched_at_epoch: now,
            groups: Vec::new(),
            error: if err.is_empty() {
                "Invalid output format".to_string()
            } else {
                err
            },
        };
    };

    let Some(end_idx) = raw_stdout.rfind('}') else {
        return AccountSnapshot {
            profile_id: profile.id.clone(),
            label: profile.label.clone(),
            command_hint: profile.command_hint.clone(),
            mode: profile.mode.clone(),
            ok: false,
            fetched_at_epoch: now,
            groups: Vec::new(),
            error: "Incomplete JSON output from agy CLI".to_string(),
        };
    };

    if end_idx < start_idx {
        return AccountSnapshot {
            profile_id: profile.id.clone(),
            label: profile.label.clone(),
            command_hint: profile.command_hint.clone(),
            mode: profile.mode.clone(),
            ok: false,
            fetched_at_epoch: now,
            groups: Vec::new(),
            error: "Malformed JSON slice from agy CLI".to_string(),
        };
    }

    let json_slice = &raw_stdout[start_idx..=end_idx];
    let payload: Value = match serde_json::from_str(json_slice) {
        Ok(v) => v,
        Err(e) => {
            return AccountSnapshot {
                profile_id: profile.id.clone(),
                label: profile.label.clone(),
                command_hint: profile.command_hint.clone(),
                mode: profile.mode.clone(),
                ok: false,
                fetched_at_epoch: now,
                groups: Vec::new(),
                error: format!("JSON parse error: {}", sanitize_terminal_text(&e.to_string(), 160)),
            };
        }
    };

    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("ERROR");
    if status != "SUCCESS" {
        let raw_err = payload
            .get("error")
            .and_then(Value::as_str)
            .or_else(|| payload.get("response").and_then(Value::as_str))
            .unwrap_or("Query failed");
        return AccountSnapshot {
            profile_id: profile.id.clone(),
            label: profile.label.clone(),
            command_hint: profile.command_hint.clone(),
            mode: profile.mode.clone(),
            ok: false,
            fetched_at_epoch: now,
            groups: Vec::new(),
            error: redact_sensitive_text(raw_err, 240),
        };
    }

    let Some(groups_raw) = payload
        .get("command")
        .and_then(|c| c.get("data"))
        .and_then(|d| d.get("groups"))
        .and_then(Value::as_array)
    else {
        return AccountSnapshot {
            profile_id: profile.id.clone(),
            label: profile.label.clone(),
            command_hint: profile.command_hint.clone(),
            mode: profile.mode.clone(),
            ok: false,
            fetched_at_epoch: now,
            groups: Vec::new(),
            error: "No quota groups returned by CLI".to_string(),
        };
    };

    let mut groups = Vec::new();
    for g_val in groups_raw.iter().take(10) {
        let Some(g_obj) = g_val.as_object() else {
            continue;
        };
        let g_name = sanitize_terminal_text(
            g_obj.get("name").and_then(Value::as_str).unwrap_or("Models"),
            60,
        );
        let Some(b_arr) = g_obj.get("buckets").and_then(Value::as_array) else {
            continue;
        };

        let mut buckets = Vec::new();
        for b_val in b_arr.iter().take(10) {
            let Some(b_obj) = b_val.as_object() else {
                continue;
            };
            let b_id = sanitize_terminal_text(
                b_obj.get("id").and_then(Value::as_str).unwrap_or("bucket"),
                48,
            );
            let b_name = sanitize_terminal_text(
                b_obj.get("name").and_then(Value::as_str).unwrap_or("Limit"),
                60,
            );
            let b_window = sanitize_terminal_text(
                b_obj.get("window").and_then(Value::as_str).unwrap_or(""),
                16,
            );
            let frac = safe_fraction(
                b_obj
                    .get("remaining_fraction")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
            );
            let reset_iso = sanitize_terminal_text(
                b_obj.get("reset_time").and_then(Value::as_str).unwrap_or(""),
                40,
            );
            let reset_ep = parse_iso_timestamp(&reset_iso);

            buckets.push(BucketQuota {
                id: b_id,
                name: b_name,
                window: b_window,
                remaining_fraction: frac,
                reset_time_iso: reset_iso,
                reset_epoch: reset_ep,
            });
        }

        if !buckets.is_empty() {
            groups.push(GroupQuota {
                name: g_name,
                buckets,
            });
        }
    }

    let ok = !groups.is_empty();
    AccountSnapshot {
        profile_id: profile.id.clone(),
        label: profile.label.clone(),
        command_hint: profile.command_hint.clone(),
        mode: profile.mode.clone(),
        ok,
        fetched_at_epoch: now,
        groups,
        error: if ok {
            String::new()
        } else {
            "Empty quota buckets".to_string()
        },
    }
}

/// Execute a single isolated `agy -p /usage` query with bounded output reading and timeout reaping.
pub fn fetch_single_profile(
    profile: &ProfileSpec,
    agy_bin: &Path,
    empty_cwd: &Path,
    real_home: Option<&Path>,
) -> AccountSnapshot {
    let now = now_epoch_secs();
    let (argv, clean_env) = match build_isolated_command(
        &profile.mode,
        agy_bin,
        Path::new(&profile.home_dir),
        profile.container.as_deref(),
        real_home,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            return AccountSnapshot {
                profile_id: profile.id.clone(),
                label: profile.label.clone(),
                command_hint: profile.command_hint.clone(),
                mode: profile.mode.clone(),
                ok: false,
                fetched_at_epoch: now,
                groups: Vec::new(),
                error: redact_sensitive_text(&e.to_string(), 240),
            };
        }
    };

    let mut child = match Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(empty_cwd)
        .env_clear()
        .envs(&clean_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return AccountSnapshot {
                profile_id: profile.id.clone(),
                label: profile.label.clone(),
                command_hint: profile.command_hint.clone(),
                mode: profile.mode.clone(),
                ok: false,
                fetched_at_epoch: now_epoch_secs(),
                groups: Vec::new(),
                error: redact_sensitive_text(&format!("Spawn error: {e}"), 240),
            };
        }
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout_pipe {
            let _ = pipe.take(MAX_SUBPROCESS_OUTPUT_BYTES).read_to_end(&mut buf);
        }
        buf
    });

    let err_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(pipe) = stderr_pipe {
            let _ = pipe.take(MAX_SUBPROCESS_OUTPUT_BYTES).read_to_end(&mut buf);
        }
        buf
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Ok(st),
            Ok(None) => {
                if start.elapsed() >= SUBPROCESS_TIMEOUT {
                    kill_process_group(&mut child);
                    break Err("Timeout querying CLI (>30s)".to_string());
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                kill_process_group(&mut child);
                break Err(format!("Wait error: {e}"));
            }
        }
    };

    let stdout_bytes = out_handle.join().unwrap_or_default();
    let stderr_bytes = err_handle.join().unwrap_or_default();

    let exit_status = match status {
        Ok(st) => st,
        Err(err_msg) => {
            return AccountSnapshot {
                profile_id: profile.id.clone(),
                label: profile.label.clone(),
                command_hint: profile.command_hint.clone(),
                mode: profile.mode.clone(),
                ok: false,
                fetched_at_epoch: now_epoch_secs(),
                groups: Vec::new(),
                error: redact_sensitive_text(&err_msg, 240),
            };
        }
    };

    let stdout_str = String::from_utf8_lossy(&stdout_bytes);
    let stderr_str = String::from_utf8_lossy(&stderr_bytes);

    if !exit_status.success() && !stdout_str.contains('{') {
        let combined = if !stderr_str.trim().is_empty() {
            stderr_str.trim().to_string()
        } else if !stdout_str.trim().is_empty() {
            stdout_str.trim().to_string()
        } else {
            format!("Exit status: {exit_status}")
        };
        return AccountSnapshot {
            profile_id: profile.id.clone(),
            label: profile.label.clone(),
            command_hint: profile.command_hint.clone(),
            mode: profile.mode.clone(),
            ok: false,
            fetched_at_epoch: now_epoch_secs(),
            groups: Vec::new(),
            error: redact_sensitive_text(&combined, 240),
        };
    }

    parse_usage_json(&stdout_str, profile, Some(now_epoch_secs()))
}

/// Compute the optimal account to use right now for Gemini and Claude/GPT.
pub fn compute_recommendations(snapshots: &[AccountSnapshot]) -> Vec<BestAccountRecommendation> {
    let healthy: Vec<&AccountSnapshot> = snapshots.iter().filter(|s| s.ok).collect();
    if healthy.is_empty() {
        return Vec::new();
    }

    let families = [("Gemini", "gemini"), ("Claude / GPT", "claude")];
    let mut recs = Vec::with_capacity(2);

    for (display_family, keyword) in families {
        let mut best: Option<((i64, i64, f64), &AccountSnapshot, f64, f64)> = None;
        for snap in &healthy {
            let (eff_frac, wk_frac, reset_5h) = snap.effective_group_remaining(keyword);
            let eff_bucket = (eff_frac * 100.0).round() as i64;
            let wk_bucket = (wk_frac * 1000.0).round() as i64;
            let sooner_score = reset_5h.map(|r| -r).unwrap_or(f64::NEG_INFINITY);
            let key = (eff_bucket, wk_bucket, sooner_score);

            let replace = match &best {
                None => true,
                Some((best_key, _, _, _)) => {
                    key.0 > best_key.0
                        || (key.0 == best_key.0 && key.1 > best_key.1)
                        || (key.0 == best_key.0 && key.1 == best_key.1 && key.2 > best_key.2)
                }
            };
            if replace {
                best = Some((key, snap, eff_frac, wk_frac));
            }
        }

        if let Some((_, best_snap, best_eff, best_wk)) = best {
            let eff_pct = (best_eff.clamp(0.0, 1.0) * 100.0).round() as u8;
            let wk_pct = (best_wk.clamp(0.0, 1.0) * 100.0).round() as u8;
            let reason = format!("5h: {eff_pct}% · Wk: {wk_pct}%");
            recs.push(BestAccountRecommendation {
                family: display_family.to_string(),
                profile_id: best_snap.profile_id.clone(),
                command_hint: best_snap.command_hint.clone(),
                effective_pct: eff_pct,
                weekly_pct: wk_pct,
                reason,
            });
        }
    }

    recs
}

struct CollectorInner {
    last_fetch: Option<Instant>,
    latest_snapshots: Vec<AccountSnapshot>,
}

/// Thread-safe, debounced parallel collector with atomic `0600` caching.
pub struct QuotaCollector {
    profiles: Vec<ProfileSpec>,
    min_refresh_gap: Duration,
    inner: Mutex<CollectorInner>,
}

impl QuotaCollector {
    pub fn new(profiles: Vec<ProfileSpec>, min_refresh_gap: Duration) -> Self {
        Self {
            profiles,
            min_refresh_gap,
            inner: Mutex::new(CollectorInner {
                last_fetch: None,
                latest_snapshots: Vec::new(),
            }),
        }
    }

    pub fn profiles(&self) -> &[ProfileSpec] {
        &self.profiles
    }

    pub fn load_cached(&self) -> Vec<AccountSnapshot> {
        let Ok(cache_dir) = get_safe_cache_dir(None) else {
            return Vec::new();
        };
        let Ok(Some(val)) = safe_read_json(&cache_dir, CACHE_FILENAME, 65_536) else {
            return Vec::new();
        };
        let Some(arr) = val.get("accounts").and_then(Value::as_array) else {
            return Vec::new();
        };
        let snapshots: Vec<AccountSnapshot> = arr
            .iter()
            .take(12)
            .filter_map(AccountSnapshot::from_json_value)
            .collect();
        if !snapshots.is_empty() {
            if let Ok(mut guard) = self.inner.lock() {
                guard.latest_snapshots = snapshots.clone();
            }
        }
        snapshots
    }

    pub fn save_cache(&self, snapshots: &[AccountSnapshot]) {
        let Ok(cache_dir) = get_safe_cache_dir(None) else {
            return;
        };
        let payload = json!({
            "updated_at_epoch": (now_epoch_secs() * 1000.0).round() / 1000.0,
            "accounts": snapshots,
        });
        if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
            let _ = atomic_write_json(&cache_dir, CACHE_FILENAME, &bytes);
        }
    }

    pub fn collect_all(&self, force: bool) -> Vec<AccountSnapshot> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !force && !guard.latest_snapshots.is_empty() {
            if let Some(last) = guard.last_fetch {
                if last.elapsed() < self.min_refresh_gap {
                    return guard.latest_snapshots.clone();
                }
            }
        }

        let agy_bin = match locate_agy_binary(None) {
            Ok(b) => b,
            Err(e) => {
                let now = now_epoch_secs();
                return self
                    .profiles
                    .iter()
                    .map(|p| AccountSnapshot {
                        profile_id: p.id.clone(),
                        label: p.label.clone(),
                        command_hint: p.command_hint.clone(),
                        mode: p.mode.clone(),
                        ok: false,
                        fetched_at_epoch: now,
                        groups: Vec::new(),
                        error: redact_sensitive_text(&e.to_string(), 240),
                    })
                    .collect();
            }
        };

        let empty_cwd = match get_safe_empty_workspace(None) {
            Ok(c) => c,
            Err(e) => {
                let now = now_epoch_secs();
                return self
                    .profiles
                    .iter()
                    .map(|p| AccountSnapshot {
                        profile_id: p.id.clone(),
                        label: p.label.clone(),
                        command_hint: p.command_hint.clone(),
                        mode: p.mode.clone(),
                        ok: false,
                        fetched_at_epoch: now,
                        groups: Vec::new(),
                        error: redact_sensitive_text(&e.to_string(), 240),
                    })
                    .collect();
            }
        };

        let results: Vec<AccountSnapshot> = thread::scope(|s| {
            let handles: Vec<_> = self
                .profiles
                .iter()
                .map(|prof| s.spawn(|| fetch_single_profile(prof, &agy_bin, &empty_cwd, None)))
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| AccountSnapshot {
                        profile_id: "unknown".to_string(),
                        label: "Unknown".to_string(),
                        command_hint: "agy".to_string(),
                        mode: "host".to_string(),
                        ok: false,
                        fetched_at_epoch: now_epoch_secs(),
                        groups: Vec::new(),
                        error: "Worker thread panicked".to_string(),
                    })
                })
                .collect()
        });

        guard.latest_snapshots = results.clone();
        guard.last_fetch = Some(Instant::now());
        self.save_cache(&results);
        results
    }
}
