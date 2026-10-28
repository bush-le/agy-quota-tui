//! Immutable data models for Antigravity quota snapshots and account recommendations.

use chrono::{DateTime, Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::security::{redact_sensitive_text, sanitize_terminal_text};

pub const MAX_VALID_EPOCH: f64 = 4_102_444_800.0; // 2100-01-01T00:00:00Z

pub fn safe_fraction(val: f64) -> f64 {
    if !val.is_finite() {
        return 0.0;
    }
    val.clamp(0.0, 1.0)
}

pub fn safe_epoch(val: Option<f64>) -> Option<f64> {
    match val {
        Some(v) if v.is_finite() && (0.0..=MAX_VALID_EPOCH).contains(&v) => Some(v),
        _ => None,
    }
}

pub fn now_epoch_secs() -> f64 {
    Utc::now().timestamp_millis() as f64 / 1000.0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub id: String,
    pub label: String,
    pub command_hint: String,
    pub mode: String, // "host" | "toolbox" | "distrobox" | "isolated_home"
    pub home_dir: String,
    pub container: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BucketQuota {
    pub id: String,
    pub name: String,
    pub window: String, // "5h" | "weekly" | other
    pub remaining_fraction: f64,
    pub reset_time_iso: String,
    pub reset_epoch: Option<f64>,
}

impl BucketQuota {
    pub fn remaining_pct(&self) -> u8 {
        let clamped = safe_fraction(self.remaining_fraction);
        (clamped * 100.0).round() as u8
    }

    pub fn is_full(&self) -> bool {
        safe_fraction(self.remaining_fraction) >= 0.995
    }

    pub fn seconds_until_reset(&self, now_epoch: f64) -> Option<f64> {
        let ep = safe_epoch(self.reset_epoch)?;
        Some((ep - now_epoch).max(0.0))
    }

    pub fn format_countdown(&self, now_epoch: f64, include_seconds: bool) -> String {
        let Some(secs) = self.seconds_until_reset(now_epoch) else {
            return "—".to_string();
        };
        let total = secs as i64;
        if total <= 0 {
            return "Resetting...".to_string();
        }

        let days = total / 86_400;
        let rem1 = total % 86_400;
        let hours = rem1 / 3_600;
        let rem2 = rem1 % 3_600;
        let minutes = rem2 / 60;
        let seconds = rem2 % 60;

        if days > 0 {
            format!("{days}d {hours:02}h {minutes:02}m")
        } else if hours > 0 {
            if include_seconds {
                format!("{hours}h {minutes:02}m {seconds:02}s")
            } else {
                format!("{hours}h {minutes:02}m")
            }
        } else if include_seconds {
            format!("{minutes:02}m {seconds:02}s")
        } else {
            format!("{minutes}m")
        }
    }

    pub fn format_local_reset(&self) -> String {
        let Some(ep) = safe_epoch(self.reset_epoch) else {
            return String::new();
        };
        let secs = ep.trunc() as i64;
        let Some(dt_utc) = DateTime::<Utc>::from_timestamp(secs, 0) else {
            return String::new();
        };
        let dt_local = dt_utc.with_timezone(&Local);
        let now_local = Local::now();
        if dt_local.date_naive() == now_local.date_naive() {
            dt_local.format("%H:%M").to_string()
        } else {
            dt_local.format("%d/%m %H:%M").to_string()
        }
    }

    pub fn from_json_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let id = sanitize_terminal_text(obj.get("id").and_then(Value::as_str).unwrap_or(""), 64);
        let name =
            sanitize_terminal_text(obj.get("name").and_then(Value::as_str).unwrap_or(""), 80);
        let window =
            sanitize_terminal_text(obj.get("window").and_then(Value::as_str).unwrap_or(""), 32);
        let remaining_fraction = safe_fraction(
            obj.get("remaining_fraction")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
        );
        let reset_time_iso = sanitize_terminal_text(
            obj.get("reset_time_iso")
                .or_else(|| obj.get("reset_time"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            64,
        );
        let reset_epoch = safe_epoch(obj.get("reset_epoch").and_then(Value::as_f64));
        Some(Self {
            id,
            name,
            window,
            remaining_fraction,
            reset_time_iso,
            reset_epoch,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupQuota {
    pub name: String,
    pub buckets: Vec<BucketQuota>,
}

impl GroupQuota {
    pub fn short_name(&self) -> String {
        let lower = self.name.to_ascii_lowercase();
        if lower.contains("argon") {
            "Gemini 4 Argon".to_string()
        } else if lower.contains("gemini") {
            "Gemini Models".to_string()
        } else if lower.contains("claude") || lower.contains("gpt") {
            "Claude & GPT".to_string()
        } else {
            self.name.clone()
        }
    }

    pub fn get_bucket_by_window(&self, window: &str) -> Option<&BucketQuota> {
        self.buckets.iter().find(|b| b.window == window)
    }

    pub fn from_json_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let name =
            sanitize_terminal_text(obj.get("name").and_then(Value::as_str).unwrap_or(""), 80);
        let buckets = obj
            .get("buckets")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .take(10)
                    .filter_map(BucketQuota::from_json_value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Some(Self { name, buckets })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub profile_id: String,
    pub label: String,
    pub command_hint: String,
    pub mode: String,
    pub ok: bool,
    pub fetched_at_epoch: f64,
    pub groups: Vec<GroupQuota>,
    pub error: String,
}

impl AccountSnapshot {
    pub fn all_buckets(&self, only_5h: bool) -> Vec<(String, &BucketQuota)> {
        let mut items = Vec::new();
        for g in &self.groups {
            let sname = g.short_name();
            for b in &g.buckets {
                if only_5h && b.window != "5h" {
                    continue;
                }
                items.push((sname.clone(), b));
            }
        }
        items
    }

    pub fn lowest_overall_bucket(&self) -> Option<&BucketQuota> {
        self.groups.iter().flat_map(|g| g.buckets.iter()).min_by(|a, b| {
            safe_fraction(a.remaining_fraction)
                .partial_cmp(&safe_fraction(b.remaining_fraction))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    pub fn effective_group_remaining(&self, group_keyword: &str) -> (f64, f64, Option<f64>) {
        let kw = group_keyword.to_ascii_lowercase();
        for g in &self.groups {
            if g.name.to_ascii_lowercase().contains(&kw) {
                let b5 = g.get_bucket_by_window("5h");
                let bw = g.get_bucket_by_window("weekly");
                let f5 = b5.map(|b| safe_fraction(b.remaining_fraction)).unwrap_or(1.0);
                let fw = bw.map(|b| safe_fraction(b.remaining_fraction)).unwrap_or(1.0);
                let r5 = b5.and_then(|b| if b.is_full() { None } else { safe_epoch(b.reset_epoch) });
                return (f5.min(fw), fw, r5);
            }
        }
        (0.0, 0.0, None)
    }

    pub fn health_state(&self) -> &'static str {
        if !self.ok {
            return "err";
        }
        let Some(lowest) = self.lowest_overall_bucket() else {
            return "ok";
        };
        let frac = safe_fraction(lowest.remaining_fraction);
        if frac < 0.25 {
            "crit"
        } else if frac < 0.60 {
            "warn"
        } else {
            "ok"
        }
    }

    pub fn from_json_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let profile_id = sanitize_terminal_text(
            obj.get("profile_id").and_then(Value::as_str).unwrap_or(""),
            64,
        );
        let label =
            sanitize_terminal_text(obj.get("label").and_then(Value::as_str).unwrap_or(""), 64);
        let command_hint = sanitize_terminal_text(
            obj.get("command_hint").and_then(Value::as_str).unwrap_or(""),
            64,
        );
        let mode = sanitize_terminal_text(
            obj.get("mode").and_then(Value::as_str).unwrap_or("host"),
            32,
        );
        let ok = obj.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let fetched_at_epoch =
            safe_epoch(obj.get("fetched_at_epoch").and_then(Value::as_f64)).unwrap_or(0.0);
        let groups = obj
            .get("groups")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .take(10)
                    .filter_map(GroupQuota::from_json_value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let error =
            redact_sensitive_text(obj.get("error").and_then(Value::as_str).unwrap_or(""), 240);

        Some(Self {
            profile_id,
            label,
            command_hint,
            mode,
            ok,
            fetched_at_epoch,
            groups,
            error,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BestAccountRecommendation {
    pub family: String,
    pub profile_id: String,
    pub command_hint: String,
    pub effective_pct: u8,
    pub weekly_pct: u8,
    pub reason: String,
}

/// Format an epoch timestamp as `HH:MM:SS` in local time.
pub fn format_epoch_hms(epoch: f64) -> String {
    let Some(ep) = safe_epoch(Some(epoch)) else {
        return "—".to_string();
    };
    if ep <= 0.0 {
        return "—".to_string();
    }
    let Some(dt_utc) = DateTime::<Utc>::from_timestamp(ep.trunc() as i64, 0) else {
        return "—".to_string();
    };
    let dt_local = Local.from_utc_datetime(&dt_utc.naive_utc());
    dt_local.format("%H:%M:%S").to_string()
}
