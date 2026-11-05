//! Parallel quota collector, bounded subprocess runner, and Best Account recommendation engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
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
    BucketQuota, GroupQuota, ProfileSpec, SessionSummary,
};
use crate::profiles::locate_agy_binary;
use crate::security::{
    atomic_write_json, build_isolated_command, build_isolated_prime_command, current_uid,
    get_safe_cache_dir, get_safe_empty_workspace, kill_process_group, open_verified_sqlite_file,
    purge_priming_conversation, redact_sensitive_text, safe_read_json, sanitize_terminal_text,
    validate_uuid, verify_safe_home_dir, verify_safe_workspace_dir, MAX_SQLITE_DB_BYTES,
    MAX_SQLITE_WAL_BYTES,
};

pub const MAX_SUBPROCESS_OUTPUT_BYTES: u64 = 262_144; // 256 KB hard cap
pub const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
pub const CACHE_FILENAME: &str = "quota-cache.json";

pub fn parse_iso_timestamp(iso_str: &str) -> Option<f64> {
    let trimmed = iso_str.trim();
    if trimmed.is_empty() {
        return None;
    }
    let dt = DateTime::parse_from_rfc3339(trimmed)
        .or_else(|_| {
            if trimmed.len() > 10 && trimmed.as_bytes()[10] == b' ' {
                let normalized = format!("{}T{}", &trimmed[..10], &trimmed[11..]);
                DateTime::parse_from_rfc3339(&normalized)
            } else {
                DateTime::parse_from_rfc3339(trimmed)
            }
        })
        .ok()?;

    let ep = dt.timestamp_millis() as f64 / 1000.0;
    if ep < 946_684_800.0 {
        return None;
    }
    safe_epoch(Some(ep))
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
            recent_sessions: Vec::new(),
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
            recent_sessions: Vec::new(),
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
            recent_sessions: Vec::new(),
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
                recent_sessions: Vec::new(),
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
            recent_sessions: Vec::new(),
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
            recent_sessions: Vec::new(),
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
        recent_sessions: Vec::new(),
    }
}

fn run_bounded_subprocess(
    argv: &[String],
    clean_env: &std::collections::BTreeMap<String, String>,
    empty_cwd: &Path,
) -> Result<(std::process::ExitStatus, String, String), String> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(empty_cwd)
        .env_clear()
        .envs(clean_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("Spawn error: {e}"))?;

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

    let exit_status = status?;
    let stdout_str = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr_str = String::from_utf8_lossy(&stderr_bytes).into_owned();
    Ok((exit_status, stdout_str, stderr_str))
}

fn query_usage_once(
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
                recent_sessions: Vec::new(),
            };
        }
    };

    let (exit_status, stdout_str, stderr_str) =
        match run_bounded_subprocess(&argv, &clean_env, empty_cwd) {
            Ok(res) => res,
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
                    recent_sessions: Vec::new(),
                };
            }
        };

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
            recent_sessions: Vec::new(),
        };
    }

    parse_usage_json(&stdout_str, profile, Some(now_epoch_secs()))
}

fn extract_conversation_id_from_stdout(raw_stdout: &str) -> Option<String> {
    let start_idx = raw_stdout.find('{')?;
    let end_idx = raw_stdout.rfind('}')?;
    if end_idx < start_idx {
        return None;
    }
    let val: Value = serde_json::from_str(&raw_stdout[start_idx..=end_idx]).ok()?;
    val.get("conversation_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn prime_single_group(
    profile: &ProfileSpec,
    agy_bin: &Path,
    empty_cwd: &Path,
    model_name: &str,
    real_home: Option<&Path>,
) -> bool {
    let home_path = Path::new(&profile.home_dir);
    let Ok((argv, clean_env)) = build_isolated_prime_command(
        &profile.mode,
        agy_bin,
        home_path,
        profile.container.as_deref(),
        model_name,
        real_home,
    ) else {
        return false;
    };

    match run_bounded_subprocess(&argv, &clean_env, empty_cwd) {
        Ok((status, stdout_str, _)) => {
            if let Some(cid) = extract_conversation_id_from_stdout(&stdout_str) {
                let _ = purge_priming_conversation(home_path, &cid, real_home);
            }
            status.success() || stdout_str.contains("\"SUCCESS\"")
        }
        Err(_) => false,
    }
}

fn read_be_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let b0 = *buf.get(offset)?;
    let b1 = *buf.get(offset.checked_add(1)?)?;
    Some(u16::from_be_bytes([b0, b1]))
}

fn read_be_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let b0 = *buf.get(offset)?;
    let b1 = *buf.get(offset.checked_add(1)?)?;
    let b2 = *buf.get(offset.checked_add(2)?)?;
    let b3 = *buf.get(offset.checked_add(3)?)?;
    Some(u32::from_be_bytes([b0, b1, b2, b3]))
}

fn read_sqlite_varint(buf: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    for i in 0..8 {
        let b = *buf.get(offset.checked_add(i)?)?;
        val = (val << 7) | u64::from(b & 0x7f);
        if (b & 0x80) == 0 {
            return Some((val, i + 1));
        }
    }
    let b9 = *buf.get(offset.checked_add(8)?)?;
    val = (val << 8) | u64::from(b9);
    Some((val, 9))
}

#[derive(Debug, Clone)]
enum SqliteValue {
    Null,
    Int(i64),
    Float,
    Text(String),
    Blob,
}

impl SqliteValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }
}

fn decode_record_columns(payload: &[u8], max_cols: usize) -> Option<Vec<SqliteValue>> {
    let (hdr_size_u64, varint_len) = read_sqlite_varint(payload, 0)?;
    let hdr_size = usize::try_from(hdr_size_u64).ok()?;
    if hdr_size < varint_len || hdr_size > payload.len() {
        return None;
    }

    let mut serial_types = Vec::with_capacity(max_cols.min(32));
    let mut hdr_pos = varint_len;
    while hdr_pos < hdr_size && serial_types.len() < max_cols {
        let (stype, slen) = read_sqlite_varint(payload, hdr_pos)?;
        hdr_pos = hdr_pos.checked_add(slen)?;
        if hdr_pos > hdr_size {
            return None;
        }
        serial_types.push(stype);
    }

    let mut body_pos = hdr_size;
    let mut out = Vec::with_capacity(serial_types.len());
    for stype in serial_types {
        let val = match stype {
            0 => SqliteValue::Null,
            1 => {
                let b0 = *payload.get(body_pos)?;
                body_pos = body_pos.checked_add(1)?;
                SqliteValue::Int(i64::from(b0 as i8))
            }
            2 => {
                let b0 = *payload.get(body_pos)?;
                let b1 = *payload.get(body_pos.checked_add(1)?)?;
                body_pos = body_pos.checked_add(2)?;
                SqliteValue::Int(i64::from(i16::from_be_bytes([b0, b1])))
            }
            3 => {
                let b0 = i32::from(*payload.get(body_pos)?);
                let b1 = i32::from(*payload.get(body_pos.checked_add(1)?)?);
                let b2 = i32::from(*payload.get(body_pos.checked_add(2)?)?);
                body_pos = body_pos.checked_add(3)?;
                let raw = (b0 << 24) | (b1 << 16) | (b2 << 8);
                SqliteValue::Int(i64::from(raw >> 8))
            }
            4 => {
                let b0 = *payload.get(body_pos)?;
                let b1 = *payload.get(body_pos.checked_add(1)?)?;
                let b2 = *payload.get(body_pos.checked_add(2)?)?;
                let b3 = *payload.get(body_pos.checked_add(3)?)?;
                body_pos = body_pos.checked_add(4)?;
                SqliteValue::Int(i64::from(i32::from_be_bytes([b0, b1, b2, b3])))
            }
            5 => {
                let b0 = i64::from(*payload.get(body_pos)?);
                let b1 = i64::from(*payload.get(body_pos.checked_add(1)?)?);
                let b2 = i64::from(*payload.get(body_pos.checked_add(2)?)?);
                let b3 = i64::from(*payload.get(body_pos.checked_add(3)?)?);
                let b4 = i64::from(*payload.get(body_pos.checked_add(4)?)?);
                let b5 = i64::from(*payload.get(body_pos.checked_add(5)?)?);
                body_pos = body_pos.checked_add(6)?;
                let raw = (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) | (b4 << 24) | (b5 << 16);
                SqliteValue::Int(raw >> 16)
            }
            6 => {
                let slice = payload.get(body_pos..body_pos.checked_add(8)?)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(slice);
                body_pos = body_pos.checked_add(8)?;
                SqliteValue::Int(i64::from_be_bytes(arr))
            }
            7 => {
                let _slice = payload.get(body_pos..body_pos.checked_add(8)?)?;
                body_pos = body_pos.checked_add(8)?;
                SqliteValue::Float
            }
            8 => SqliteValue::Int(0),
            9 => SqliteValue::Int(1),
            10 | 11 => return None,
            n if n >= 12 && n % 2 == 0 => {
                let len = usize::try_from((n - 12) / 2).ok()?;
                let end = body_pos.checked_add(len)?;
                let _slice = payload.get(body_pos..end)?;
                body_pos = end;
                SqliteValue::Blob
            }
            n => {
                let len = usize::try_from((n.checked_sub(13)?) / 2).ok()?;
                let end = body_pos.checked_add(len)?;
                let slice = payload.get(body_pos..end)?;
                body_pos = end;
                SqliteValue::Text(String::from_utf8_lossy(slice).into_owned())
            }
        };
        out.push(val);
    }

    Some(out)
}

fn extract_leaf_cell_payload(
    page: &[u8],
    cell_offset: usize,
    usable_size: usize,
    read_page: &dyn Fn(u32) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if usable_size < 480 || usable_size > page.len() {
        return None;
    }
    let (payload_len_u64, vlen1) = read_sqlite_varint(page, cell_offset)?;
    let pos_after_p = cell_offset.checked_add(vlen1)?;
    let (_rowid, vlen2) = read_sqlite_varint(page, pos_after_p)?;
    let data_start = pos_after_p.checked_add(vlen2)?;
    let p = usize::try_from(payload_len_u64).ok()?;
    if p == 0 || p > 262_144 {
        return None;
    }

    let x = usable_size.checked_sub(35)?;
    let m = (usable_size.checked_sub(12)? * 32 / 255).checked_sub(23)?;

    if p <= x {
        let data_end = data_start.checked_add(p)?;
        if data_end > usable_size {
            return None;
        }
        return Some(page.get(data_start..data_end)?.to_vec());
    }

    let u_minus_4 = usable_size.checked_sub(4)?;
    if u_minus_4 == 0 {
        return None;
    }
    let k = m.checked_add(p.checked_sub(m)? % u_minus_4)?;
    let local_len = if k <= x { k } else { m };
    let local_end = data_start.checked_add(local_len)?;
    if local_end.checked_add(4)? > usable_size {
        return None;
    }

    let cap = p.min(16_384);
    let mut out = Vec::with_capacity(cap);
    let take_local = local_len.min(cap);
    out.extend_from_slice(page.get(data_start..data_start.checked_add(take_local)?)?);

    let mut next_pgno = read_be_u32(page, local_end)?;
    let mut ovf_steps = 0usize;
    while next_pgno != 0 && out.len() < cap && ovf_steps < 4 {
        ovf_steps += 1;
        let ovf_page = read_page(next_pgno)?;
        next_pgno = read_be_u32(&ovf_page, 0)?;
        let avail = ovf_page.get(4..usable_size)?;
        let need = cap - out.len();
        let take_n = avail.len().min(need);
        out.extend_from_slice(avail.get(..take_n)?);
    }

    Some(out)
}

fn traverse_table_btree(
    pgno: u32,
    depth: u8,
    usable_size: usize,
    visited: &mut BTreeSet<u32>,
    read_page: &dyn Fn(u32) -> Option<Vec<u8>>,
    on_leaf_record: &mut dyn FnMut(&[u8]),
) {
    if pgno == 0 || depth > 8 || visited.len() >= 512 || !visited.insert(pgno) {
        return;
    }
    let Some(page) = read_page(pgno) else {
        return;
    };
    let bhdr = if pgno == 1 { 100usize } else { 0usize };
    let Some(&page_type) = page.get(bhdr) else {
        return;
    };
    let Some(cell_count_u16) = read_be_u16(&page, bhdr + 3) else {
        return;
    };
    let cell_count = (cell_count_u16 as usize).min(1024);

    match page_type {
        0x0d => {
            let ptr_base = bhdr + 8;
            for i in 0..cell_count {
                let Some(cell_off_u16) = read_be_u16(&page, ptr_base + i * 2) else {
                    break;
                };
                if let Some(payload) =
                    extract_leaf_cell_payload(&page, cell_off_u16 as usize, usable_size, read_page)
                {
                    on_leaf_record(&payload);
                }
            }
        }
        0x05 => {
            let Some(right_child) = read_be_u32(&page, bhdr + 8) else {
                return;
            };
            let ptr_base = bhdr + 12;
            let mut child_pages = Vec::with_capacity(cell_count + 1);
            for i in 0..cell_count {
                let Some(cell_off_u16) = read_be_u16(&page, ptr_base + i * 2) else {
                    break;
                };
                if let Some(left_child) = read_be_u32(&page, cell_off_u16 as usize) {
                    child_pages.push(left_child);
                }
            }
            child_pages.push(right_child);
            for child_pgno in child_pages {
                traverse_table_btree(
                    child_pgno,
                    depth + 1,
                    usable_size,
                    visited,
                    read_page,
                    on_leaf_record,
                );
            }
        }
        _ => {}
    }
}

/// Read the top `max_items` recent root conversations for `profile_home` directly from
/// `conversation_summaries.db` (and its `.db-wal` Write-Ahead Log overlay) in 100% safe Rust.
pub fn load_profile_recent_sessions(
    profile_home: &Path,
    real_home: Option<&Path>,
    max_items: usize,
) -> Vec<SessionSummary> {
    if max_items == 0 {
        return Vec::new();
    }
    let Ok(verified_profile_home) = verify_safe_home_dir(profile_home, real_home) else {
        return Vec::new();
    };
    let Ok(uid) = current_uid() else {
        return Vec::new();
    };
    let Ok(Some((db_file, db_len))) = open_verified_sqlite_file(
        &verified_profile_home,
        "conversation_summaries.db",
        MAX_SQLITE_DB_BYTES,
        real_home,
    ) else {
        return Vec::new();
    };
    if db_len < 100 {
        return Vec::new();
    }

    let mut hdr = [0u8; 100];
    if db_file.read_exact_at(&mut hdr, 0).is_err() {
        return Vec::new();
    }
    if hdr.get(0..16) != Some(b"SQLite format 3\0".as_slice()) {
        return Vec::new();
    }

    let Some(raw_psize) = read_be_u16(&hdr, 16) else {
        return Vec::new();
    };
    let page_size: usize = if raw_psize == 1 {
        65_536
    } else {
        raw_psize as usize
    };
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Vec::new();
    }

    let reserved_space = hdr.get(20).copied().unwrap_or(0) as usize;
    let usable_size = page_size.saturating_sub(reserved_space);
    if usable_size < 480 {
        return Vec::new();
    }

    let mut committed_wal_pages: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    if let Ok(Some((wal_file, wal_len))) = open_verified_sqlite_file(
        &verified_profile_home,
        "conversation_summaries.db-wal",
        MAX_SQLITE_WAL_BYTES,
        real_home,
    ) {
        if wal_len >= 32 {
            let mut whdr = [0u8; 32];
            if wal_file.read_exact_at(&mut whdr, 0).is_ok() {
                let magic = read_be_u32(&whdr, 0).unwrap_or(0);
                let wal_psize_raw = read_be_u32(&whdr, 8).unwrap_or(0);
                let wal_psize = if wal_psize_raw == 1 {
                    65_536usize
                } else {
                    wal_psize_raw as usize
                };
                let salt1 = read_be_u32(&whdr, 16).unwrap_or(0);
                let salt2 = read_be_u32(&whdr, 20).unwrap_or(0);

                if (magic == 0x377f_0682 || magic == 0x377f_0683) && wal_psize == page_size {
                    let frame_size = 24usize.saturating_add(page_size) as u64;
                    let mut offset = 32u64;
                    let mut frames_read = 0usize;
                    let mut pending_pages: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

                    while frames_read < 4096
                        && offset.checked_add(frame_size).is_some_and(|end| end <= wal_len)
                    {
                        frames_read += 1;
                        let mut fhdr = [0u8; 24];
                        if wal_file.read_exact_at(&mut fhdr, offset).is_err() {
                            break;
                        }
                        let pgno = read_be_u32(&fhdr, 0).unwrap_or(0);
                        let commit_db_size = read_be_u32(&fhdr, 4).unwrap_or(0);
                        let fsalt1 = read_be_u32(&fhdr, 8).unwrap_or(0);
                        let fsalt2 = read_be_u32(&fhdr, 12).unwrap_or(0);

                        if fsalt1 != salt1 || fsalt2 != salt2 || pgno == 0 {
                            break;
                        }

                        let mut page_buf = vec![0u8; page_size];
                        if wal_file.read_exact_at(&mut page_buf, offset + 24).is_err() {
                            break;
                        }
                        pending_pages.insert(pgno, page_buf);

                        if commit_db_size > 0 {
                            for (k, v) in std::mem::take(&mut pending_pages) {
                                committed_wal_pages.insert(k, v);
                            }
                        }

                        offset += frame_size;
                    }
                }
            }
        }
    }

    let read_page = |pgno: u32| -> Option<Vec<u8>> {
        if pgno == 0 {
            return None;
        }
        if let Some(p) = committed_wal_pages.get(&pgno) {
            return Some(p.clone());
        }
        let byte_off = u64::from(pgno - 1).checked_mul(page_size as u64)?;
        let end_off = byte_off.checked_add(page_size as u64)?;
        if end_off > db_len {
            return None;
        }
        let mut buf = vec![0u8; page_size];
        db_file.read_exact_at(&mut buf, byte_off).ok()?;
        Some(buf)
    };

    // 1. Traverse sqlite_master (rooted at Page 1) to find rootpage of `conversation_summaries`
    let mut target_rootpage: Option<u32> = None;
    let mut master_visited = BTreeSet::new();
    traverse_table_btree(
        1,
        0,
        usable_size,
        &mut master_visited,
        &read_page,
        &mut |payload| {
            if target_rootpage.is_some() {
                return;
            }
            let Some(cols) = decode_record_columns(payload, 5) else {
                return;
            };
            let is_table = cols.first().and_then(SqliteValue::as_str) == Some("table");
            let is_target =
                cols.get(1).and_then(SqliteValue::as_str) == Some("conversation_summaries");
            if is_table && is_target {
                if let Some(rp) = cols.get(3).and_then(SqliteValue::as_i64) {
                    if let Ok(rp_u32) = u32::try_from(rp) {
                        if rp_u32 >= 2 {
                            target_rootpage = Some(rp_u32);
                        }
                    }
                }
            }
        },
    );

    let Some(rootpage) = target_rootpage else {
        return Vec::new();
    };

    let conv_dir = verified_profile_home
        .join(".gemini")
        .join("antigravity-cli")
        .join("conversations");

    // 2. Traverse `conversation_summaries` B-Tree
    let mut sessions = Vec::new();
    let mut table_visited = BTreeSet::new();
    traverse_table_btree(
        rootpage,
        0,
        usable_size,
        &mut table_visited,
        &read_page,
        &mut |payload| {
            let Some(cols) = decode_record_columns(payload, 12) else {
                return;
            };
            let Some(raw_cid) = cols.first().and_then(SqliteValue::as_str) else {
                return;
            };
            let Ok(cid) = validate_uuid(raw_cid.trim()) else {
                return;
            };
            let raw_title = cols.get(1).and_then(SqliteValue::as_str).unwrap_or("");
            let raw_preview = cols.get(2).and_then(SqliteValue::as_str).unwrap_or("");
            let step_count_i64 = cols.get(3).and_then(SqliteValue::as_i64).unwrap_or(0);
            let raw_mod_time = cols.get(4).and_then(SqliteValue::as_str).unwrap_or("");
            let raw_ws_uris = cols.get(5).and_then(SqliteValue::as_str).unwrap_or("");
            let parent_cid = cols.get(10).and_then(SqliteValue::as_str).unwrap_or("");
            let nesting_depth = cols.get(11).and_then(SqliteValue::as_i64).unwrap_or(0);

            if !parent_cid.trim().is_empty() || nesting_depth > 0 {
                return;
            }
            if step_count_i64 <= 0 {
                return;
            }
            if raw_ws_uris.contains("/usr/share/empty")
                || raw_ws_uris.contains("/var/empty")
                || raw_ws_uris.contains("empty-workspace")
            {
                return;
            }

            let conv_db_path = conv_dir.join(format!("{cid}.db"));
            let Ok(conv_meta) = fs::symlink_metadata(&conv_db_path) else {
                return;
            };
            if conv_meta.file_type().is_symlink()
                || !conv_meta.file_type().is_file()
                || conv_meta.uid() != uid
            {
                return;
            }

            let Some(mod_ep) = parse_iso_timestamp(raw_mod_time) else {
                return;
            };

            let chosen_title_raw = if !raw_title.trim().is_empty() {
                raw_title.trim()
            } else {
                raw_preview
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("")
            };
            let clean_title = redact_sensitive_text(chosen_title_raw, 80);
            let final_title = if clean_title.is_empty() {
                "Untitled Session".to_string()
            } else {
                clean_title
            };

            let ws_path = verify_safe_workspace_dir(raw_ws_uris, real_home);
            let step_count = u32::try_from(step_count_i64).unwrap_or(0).min(1_000_000);

            sessions.push(SessionSummary {
                conversation_id: cid.to_string(),
                title: final_title,
                step_count,
                last_modified_epoch: mod_ep,
                workspace_dir: ws_path.to_string_lossy().into_owned(),
            });
        },
    );

    sessions.sort_by(|a, b| {
        b.last_modified_epoch
            .partial_cmp(&a.last_modified_epoch)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sessions.truncate(max_items);
    sessions
}

/// Execute a single isolated `agy -p /usage` query with bounded output reading, auto-priming any
/// 100% (`1.0`) unprimed quota groups and re-querying immediately so the reset countdown runs.
pub fn fetch_single_profile(
    profile: &ProfileSpec,
    agy_bin: &Path,
    empty_cwd: &Path,
    real_home: Option<&Path>,
) -> AccountSnapshot {
    let profile_home = Path::new(&profile.home_dir);
    let mut initial = query_usage_once(profile, agy_bin, empty_cwd, real_home);
    if !initial.ok {
        initial.recent_sessions = load_profile_recent_sessions(profile_home, real_home, 10);
        return initial;
    }

    let models_to_prime: Vec<&'static str> = initial
        .groups
        .iter()
        .filter(|g| g.needs_priming())
        .filter_map(|g| g.priming_model())
        .collect();

    if models_to_prime.is_empty() {
        initial.recent_sessions = load_profile_recent_sessions(profile_home, real_home, 10);
        return initial;
    }

    let mut any_primed = false;
    for model_name in models_to_prime {
        let mut primed = prime_single_group(profile, agy_bin, empty_cwd, model_name, real_home);
        if !primed && model_name == "GPT-OSS 120B (Medium)" {
            primed = prime_single_group(
                profile,
                agy_bin,
                empty_cwd,
                "Claude Sonnet 5.5 (Low)",
                real_home,
            );
        }
        if primed {
            any_primed = true;
        }
    }

    if any_primed {
        let mut refreshed = query_usage_once(profile, agy_bin, empty_cwd, real_home);
        if refreshed.ok {
            refreshed.recent_sessions = load_profile_recent_sessions(profile_home, real_home, 10);
            return refreshed;
        }
    }

    initial.recent_sessions = load_profile_recent_sessions(profile_home, real_home, 10);
    initial
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
        let mut snapshots: Vec<AccountSnapshot> = arr
            .iter()
            .take(12)
            .filter_map(AccountSnapshot::from_json_value)
            .collect();
        for snap in &mut snapshots {
            if let Some(prof) = self.profiles.iter().find(|p| p.id == snap.profile_id) {
                let live_sessions =
                    load_profile_recent_sessions(Path::new(&prof.home_dir), None, 10);
                if !live_sessions.is_empty() || snap.recent_sessions.is_empty() {
                    snap.recent_sessions = live_sessions;
                }
            }
        }
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
                        recent_sessions: Vec::new(),
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
                        recent_sessions: Vec::new(),
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
                        recent_sessions: Vec::new(),
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
