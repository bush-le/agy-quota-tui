//! Defense-in-Depth security primitives for `agy-top`.
//!
//! Architectural guarantees:
//! - `#![forbid(unsafe_code)]` memory safety across the entire crate.
//! - Zero networking crates in dependency tree.
//! - Zero credential/keyring file access.
//! - Zero shell execution (`Command::env_clear()` + explicit argv).
//! - Symlink-safe & hardlink-safe atomic JSON I/O (`O_NOFOLLOW`, `create_new`, mode `0600`/`0700`).
//! - Deterministic state-machine stripping of ANSI CSI / OSC-52 clipboard escapes & secret redaction.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

pub const MIN_POLL_INTERVAL_SECONDS: u64 = 120;
pub const MAX_POLL_INTERVAL_SECONDS: u64 = 3600;
pub const DEFAULT_POLL_INTERVAL_SECONDS: u64 = 300;

#[cfg(target_os = "linux")]
const O_NOFOLLOW_FLAG: i32 = 0o400000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_FLAG: i32 = 0x0100;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const O_NOFOLLOW_FLAG: i32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityError(pub String);

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SecurityError {}

/// Obtain the current effective UID in 100% safe Rust via `/proc/self` (or `/dev/fd/0` lstat fallback).
pub fn current_uid() -> Result<u32, SecurityError> {
    if let Ok(meta) = fs::metadata("/proc/self") {
        return Ok(meta.uid());
    }
    if let Ok(meta) = fs::symlink_metadata("/dev/fd/0") {
        return Ok(meta.uid());
    }
    Err(SecurityError(
        "Unable to determine current process UID safely".to_string(),
    ))
}

/// Refuse to run as `root` (`UID 0`) unless explicitly overridden for isolated container testing.
pub fn ensure_non_root() -> Result<u32, SecurityError> {
    let uid = current_uid()?;
    if uid == 0 && env::var("AGY_TOP_ALLOW_ROOT").as_deref() != Ok("1") {
        return Err(SecurityError(
            "Refusing to run agy-top as root (UID 0). Run as your normal unprivileged user."
                .to_string(),
        ));
    }
    Ok(uid)
}

/// Resolve the canonical OS username for the current UID from `/etc/passwd` in 100% safe Rust.
pub fn get_current_username() -> String {
    if let Ok(uid) = current_uid() {
        let uid_str = uid.to_string();
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 && parts[2] == uid_str {
                    let candidate = parts[0].trim();
                    if validate_identifier(candidate, "username").is_ok() {
                        return candidate.to_string();
                    }
                }
            }
        }
    }
    "user".to_string()
}

/// Return the user's real home directory from `/etc/passwd` (preferred) or `$HOME`.
pub fn get_real_home_dir() -> Result<PathBuf, SecurityError> {
    let uid = current_uid()?;
    let uid_str = uid.to_string();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && parts[2] == uid_str {
                let candidate = PathBuf::from(parts[5].trim());
                if candidate.is_absolute() && candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }
    if let Some(h) = env::var_os("HOME") {
        let p = PathBuf::from(h);
        if p.is_absolute() {
            return Ok(p);
        }
    }
    Err(SecurityError(
        "Cannot resolve canonical user home directory".to_string(),
    ))
}

/// Validate that an identifier matches `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$` (blocks `--flag` injection).
pub fn validate_identifier<'a>(value: &'a str, field_name: &str) -> Result<&'a str, SecurityError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(SecurityError(format!(
            "Invalid {field_name}: length must be 1..=63 characters"
        )));
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(SecurityError(format!(
            "Invalid {field_name}: must start with an ASCII alphanumeric character (cannot start with '-')"
        )));
    }
    for &b in &bytes[1..] {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') {
            return Err(SecurityError(format!(
                "Invalid {field_name}: contains forbidden character"
            )));
        }
    }
    Ok(value)
}

/// Validate a safe JSON filename `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}\.json$`.
pub fn validate_json_filename(filename: &str) -> Result<&str, SecurityError> {
    if !filename.ends_with(".json") {
        return Err(SecurityError(format!(
            "Unsafe JSON filename (must end with .json): {filename}"
        )));
    }
    let stem = &filename[..filename.len() - 5];
    validate_identifier(stem, "filename")?;
    Ok(filename)
}

/// Strip all ANSI CSI, OSC (including OSC-52 clipboard), DCS/PM/APC escape sequences and C0/C1 control chars.
pub fn sanitize_terminal_text(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut chars = raw.chars().peekable();
    let mut last_was_space = false;

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some(']') => {
                    // OSC sequence: consume until BEL (\x07) or ST (\x1b\\)
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some('P') | Some('^') | Some('_') => {
                    // DCS / PM / APC sequence: consume until ST (\x1b\\) or BEL
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some('[') => {
                    // CSI sequence: consume parameter/intermediate bytes until final byte 0x40..=0x7E
                    chars.next();
                    while let Some(c) = chars.next() {
                        let code = c as u32;
                        if (0x40..=0x7E).contains(&code) {
                            break;
                        }
                    }
                }
                Some(c) if (0x40..=0x5F).contains(&(c as u32)) => {
                    chars.next();
                }
                _ => {}
            }
            continue;
        }

        if ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ' {
            if !last_was_space && !out.is_empty() {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }

        let code = ch as u32;
        if code < 0x20
            || (0x7F..=0x9F).contains(&code)
            || (0x200B..=0x200F).contains(&code)
            || (0x202A..=0x202E).contains(&code)
            || (0x2066..=0x2069).contains(&code)
            || code == 0x061C
            || code == 0xFEFF
        {
            continue;
        }

        out.push(ch);
        last_was_space = false;
    }

    let trimmed = out.trim();
    let char_count = trimmed.chars().count();
    if char_count > max_chars && max_chars > 1 {
        let mut truncated: String = trimmed.chars().take(max_chars - 1).collect();
        truncated.push('…');
        truncated
    } else {
        trimmed.to_string()
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '~' | '+' | '/' | '=')
}

fn redact_prefix_token(input: &str, prefix: &str, min_tail: usize, replacement: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find(prefix) {
        result.push_str(&rest[..idx]);
        let after_prefix = &rest[idx + prefix.len()..];
        let tail_len: usize = after_prefix
            .chars()
            .take_while(|&c| is_token_char(c))
            .map(char::len_utf8)
            .sum();
        if tail_len >= min_tail {
            result.push_str(replacement);
            rest = &after_prefix[tail_len..];
        } else {
            result.push_str(prefix);
            rest = after_prefix;
        }
    }
    result.push_str(rest);
    result
}

fn redact_query_params(input: &str) -> String {
    let keys = [
        "code=",
        "state=",
        "access_token=",
        "refresh_token=",
        "id_token=",
        "client_secret=",
    ];
    let mut current = input.to_string();
    for key in keys {
        let mut out = String::with_capacity(current.len());
        let mut rest = current.as_str();
        while let Some(idx) = rest.find(key) {
            out.push_str(&rest[..idx]);
            out.push_str(key);
            out.push_str("[REDACTED]");
            let after_key = &rest[idx + key.len()..];
            let val_len: usize = after_key
                .chars()
                .take_while(|&c| !c.is_whitespace() && c != '&' && c != '"' && c != '\'')
                .map(char::len_utf8)
                .sum();
            rest = &after_key[val_len..];
        }
        out.push_str(rest);
        current = out;
    }
    current
}

fn redact_bearer(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.to_ascii_lowercase().find("bearer ") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 7..];
        let trimmed = after.trim_start();
        let tok_len: usize = trimmed
            .chars()
            .take_while(|&c| is_token_char(c))
            .map(char::len_utf8)
            .sum();
        if tok_len >= 6 {
            out.push_str("Bearer [REDACTED]");
            rest = &trimmed[tok_len..];
        } else {
            out.push_str(&rest[idx..idx + 7]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn is_email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

fn is_email_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
}

fn redact_emails(input: &str) -> String {
    if !input.contains('@') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(at_idx) = rest.find('@') {
        let before = &rest[..at_idx];
        let after = &rest[at_idx + 1..];

        let local_bytes: usize = before
            .chars()
            .rev()
            .take_while(|&c| is_email_local_char(c))
            .map(char::len_utf8)
            .sum();
        let domain_bytes: usize = after
            .chars()
            .take_while(|&c| is_email_domain_char(c))
            .map(char::len_utf8)
            .sum();

        let local_part = &before[before.len() - local_bytes..];
        let domain_part = &after[..domain_bytes].trim_end_matches('.');
        let valid_email = !local_part.is_empty()
            && !local_part.starts_with('.')
            && !local_part.ends_with('.')
            && domain_part.contains('.')
            && domain_part
                .rsplit('.')
                .next()
                .map(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
                .unwrap_or(false);

        if valid_email {
            out.push_str(&before[..before.len() - local_bytes]);
            out.push_str("[REDACTED_EMAIL]");
            rest = &after[domain_part.len()..];
        } else {
            out.push_str(before);
            out.push('@');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Replace occurrences of the current user's real `$HOME` path with `~` to prevent username/path leaks in UI or logs.
pub fn anonymize_home_path(input: &str) -> String {
    if let Ok(home) = get_real_home_dir() {
        let home_str = home.to_string_lossy();
        if home_str.len() > 1 && home_str != "/" && input.contains(home_str.as_ref()) {
            return input.replace(home_str.as_ref(), "~");
        }
    }
    input.to_string()
}

/// Sanitize terminal escapes and redact OAuth tokens, refresh tokens, API keys, OAuth URLs, emails, and local HOME paths.
pub fn redact_sensitive_text(raw: &str, max_chars: usize) -> String {
    let mut s = sanitize_terminal_text(raw, max_chars.saturating_mul(2));
    s = redact_prefix_token(
        &s,
        "https://accounts.google.com/o/oauth2/",
        1,
        "[REDACTED_OAUTH_URL]",
    );
    s = redact_prefix_token(&s, "ya29.", 8, "[REDACTED_TOKEN]");
    s = redact_prefix_token(&s, "1//", 8, "[REDACTED_REFRESH_TOKEN]");
    s = redact_prefix_token(&s, "AIza", 16, "[REDACTED_API_KEY]");
    s = redact_prefix_token(&s, "GOCSPX-", 8, "[REDACTED_CLIENT_SECRET]");
    s = redact_bearer(&s);
    s = redact_query_params(&s);
    s = redact_emails(&s);
    s = anonymize_home_path(&s);

    let count = s.chars().count();
    if count > max_chars && max_chars > 1 {
        let mut truncated: String = s.chars().take(max_chars - 1).collect();
        truncated.push('…');
        truncated
    } else {
        s
    }
}

/// Verify an executable and its ancestor directory chain are owned by `root` (0) or current UID
/// and are not group-writable or world-writable.
pub fn verify_safe_executable(path: &Path) -> Result<PathBuf, SecurityError> {
    let resolved = fs::canonicalize(path)
        .map_err(|e| SecurityError(format!("Executable does not exist ({}): {e}", path.display())))?;
    let meta = fs::symlink_metadata(&resolved)
        .map_err(|e| SecurityError(format!("Cannot stat executable {}: {e}", resolved.display())))?;

    let uid = current_uid()?;
    if !meta.file_type().is_file() {
        return Err(SecurityError(format!(
            "Executable is not a regular file: {}",
            resolved.display()
        )));
    }
    if meta.uid() != 0 && meta.uid() != uid {
        return Err(SecurityError(format!(
            "Executable {} owned by untrusted UID {}",
            resolved.display(),
            meta.uid()
        )));
    }
    let mode = meta.mode();
    if (mode & 0o022) != 0 {
        return Err(SecurityError(format!(
            "Executable {} is group/world-writable (mode {:o})",
            resolved.display(),
            mode & 0o777
        )));
    }
    if (mode & 0o111) == 0 {
        return Err(SecurityError(format!(
            "File is not executable: {}",
            resolved.display()
        )));
    }

    let immediate_parent = resolved.parent().ok_or_else(|| {
        SecurityError(format!(
            "Executable has no parent directory: {}",
            resolved.display()
        ))
    })?;

    let mut cur_dir = immediate_parent;
    loop {
        let pmeta = fs::symlink_metadata(cur_dir).map_err(|e| {
            SecurityError(format!(
                "Cannot lstat ancestor directory {}: {e}",
                cur_dir.display()
            ))
        })?;
        if pmeta.uid() != 0 && pmeta.uid() != uid {
            return Err(SecurityError(format!(
                "Parent directory {} owned by untrusted UID {}",
                cur_dir.display(),
                pmeta.uid()
            )));
        }
        let pmode = pmeta.mode();
        if (pmode & 0o022) != 0 {
            let is_root_sticky_ancestor =
                cur_dir != immediate_parent && pmeta.uid() == 0 && (pmode & 0o1000) != 0;
            if !is_root_sticky_ancestor {
                return Err(SecurityError(format!(
                    "Parent directory {} is group/world-writable (mode {:o})",
                    cur_dir.display(),
                    pmode & 0o777
                )));
            }
        }
        match cur_dir.parent() {
            Some(parent) if parent != cur_dir => cur_dir = parent,
            _ => break,
        }
    }

    Ok(resolved)
}

/// Expand leading `~` or `~/` using `base_home`.
pub fn expand_tilde(raw: &str, base_home: &Path) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed == "~" || trimmed == "~/." {
        return base_home.to_path_buf();
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return base_home.join(rest);
    }
    PathBuf::from(trimmed)
}

/// Verify a profile HOME directory is not a symlink, is owned by the current UID,
/// is not group/world-writable, and resides inside `real_home` with no symlinked intermediate dirs.
pub fn verify_safe_home_dir(path: &Path, real_home: Option<&Path>) -> Result<PathBuf, SecurityError> {
    let default_home;
    let base_unres = match real_home {
        Some(h) => h,
        None => {
            default_home = get_real_home_dir()?;
            &default_home
        }
    };
    let base_home = fs::canonicalize(base_unres).map_err(|e| {
        SecurityError(format!(
            "Cannot canonicalize base home {}: {e}",
            base_unres.display()
        ))
    })?;

    let path_str = path.to_string_lossy();
    let candidate = expand_tilde(&path_str, &base_home);

    let lst = fs::symlink_metadata(&candidate).map_err(|e| {
        SecurityError(format!(
            "Profile home directory not found ({}): {e}",
            candidate.display()
        ))
    })?;

    let uid = current_uid()?;
    if lst.file_type().is_symlink() {
        return Err(SecurityError(format!(
            "Profile home directory must not be a symlink: {}",
            candidate.display()
        )));
    }
    if !lst.file_type().is_dir() {
        return Err(SecurityError(format!(
            "Profile home path is not a directory: {}",
            candidate.display()
        )));
    }
    if lst.uid() != uid {
        return Err(SecurityError(format!(
            "Profile home {} owned by UID {}, expected {}",
            candidate.display(),
            lst.uid(),
            uid
        )));
    }
    if (lst.mode() & 0o022) != 0 {
        return Err(SecurityError(format!(
            "Profile home {} is group/world-writable (mode {:o})",
            candidate.display(),
            lst.mode() & 0o777
        )));
    }

    let resolved = fs::canonicalize(&candidate).map_err(|e| {
        SecurityError(format!(
            "Cannot resolve profile home {}: {e}",
            candidate.display()
        ))
    })?;

    if !resolved.starts_with(&base_home) {
        return Err(SecurityError(format!(
            "Profile home {} must reside within user home {}",
            resolved.display(),
            base_home.display()
        )));
    }

    let mut cur: &Path = &resolved;
    loop {
        let cur_meta = fs::symlink_metadata(cur).map_err(|e| {
            SecurityError(format!("Cannot lstat directory {}: {e}", cur.display()))
        })?;
        if cur_meta.file_type().is_symlink() {
            return Err(SecurityError(format!(
                "Symlink component detected in path: {}",
                cur.display()
            )));
        }
        if cur_meta.uid() != uid {
            return Err(SecurityError(format!(
                "Directory {} owned by untrusted UID {}",
                cur.display(),
                cur_meta.uid()
            )));
        }
        if (cur_meta.mode() & 0o022) != 0 {
            return Err(SecurityError(format!(
                "Directory {} is group/world-writable",
                cur.display()
            )));
        }
        if cur == base_home {
            break;
        }
        match cur.parent() {
            Some(p) if p != cur => cur = p,
            _ => break,
        }
    }

    Ok(resolved)
}

/// Create or verify a private directory (no symlinks, owned by current UID, mode `0700`).
pub fn ensure_private_dir(path: &Path, mode: u32) -> Result<PathBuf, SecurityError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| {
                    SecurityError(format!(
                        "Failed to create parent directory {}: {e}",
                        parent.display()
                    ))
                })?;
        }
    }

    if !path.exists() {
        if let Err(e) = DirBuilder::new().mode(mode).create(path) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(SecurityError(format!(
                    "Failed to create directory {}: {e}",
                    path.display()
                )));
            }
        }
    }

    let lst = fs::symlink_metadata(path)
        .map_err(|e| SecurityError(format!("Cannot lstat directory {}: {e}", path.display())))?;

    if lst.file_type().is_symlink() {
        return Err(SecurityError(format!(
            "Refusing to use symlinked directory: {}",
            path.display()
        )));
    }
    if !lst.file_type().is_dir() {
        return Err(SecurityError(format!(
            "Path is not a directory: {}",
            path.display()
        )));
    }
    let uid = current_uid()?;
    if lst.uid() != uid {
        return Err(SecurityError(format!(
            "Directory {} owned by UID {}, expected {}",
            path.display(),
            lst.uid(),
            uid
        )));
    }

    if (lst.mode() & 0o077) != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
            SecurityError(format!(
                "Failed to tighten permissions on {}: {e}",
                path.display()
            ))
        })?;
    }

    Ok(path.to_path_buf())
}

/// Return a validated `0700` cache directory (`$XDG_RUNTIME_DIR/agy-tui` or `~/.cache/agy-tui`).
/// Never falls back to `/tmp`.
pub fn get_safe_cache_dir(real_home: Option<&Path>) -> Result<PathBuf, SecurityError> {
    let uid = current_uid()?;
    if let Ok(xdg) = env::var("XDG_RUNTIME_DIR") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            let rt_path = PathBuf::from(trimmed);
            if let Ok(lst) = fs::symlink_metadata(&rt_path) {
                if !lst.file_type().is_symlink()
                    && lst.file_type().is_dir()
                    && lst.uid() == uid
                    && (lst.mode() & 0o077) == 0
                {
                    return ensure_private_dir(&rt_path.join("agy-tui"), 0o700);
                }
            }
        }
    }

    let raw_home = match real_home {
        Some(h) => h.to_path_buf(),
        None => get_real_home_dir()?,
    };
    let home = verify_safe_home_dir(&raw_home, real_home)?;
    let cache_root = ensure_private_dir(&home.join(".cache"), 0o700)?;
    ensure_private_dir(&cache_root.join("agy-tui"), 0o700)
}

/// Return a validated `0700` configuration directory (`~/.config/agy-tui`).
pub fn get_safe_config_dir(real_home: Option<&Path>) -> Result<PathBuf, SecurityError> {
    let raw_home = match real_home {
        Some(h) => h.to_path_buf(),
        None => get_real_home_dir()?,
    };
    let home = verify_safe_home_dir(&raw_home, real_home)?;
    let cfg_root = ensure_private_dir(&home.join(".config"), 0o700)?;
    ensure_private_dir(&cfg_root.join("agy-tui"), 0o700)
}

/// Return an immutable empty workspace directory for executing `agy -p /usage`.
/// Prevents `agy` from loading untrusted `.gemini/settings.json` hooks or `.mcp.json` servers.
pub fn get_safe_empty_workspace(real_home: Option<&Path>) -> Result<PathBuf, SecurityError> {
    for sys_candidate in ["/usr/share/empty", "/var/empty"] {
        let p = Path::new(sys_candidate);
        if let Ok(lst) = fs::symlink_metadata(p) {
            if !lst.file_type().is_symlink()
                && lst.file_type().is_dir()
                && lst.uid() == 0
                && (lst.mode() & 0o022) == 0
            {
                if let Ok(mut rd) = fs::read_dir(p) {
                    if rd.next().is_none() {
                        return Ok(p.to_path_buf());
                    }
                }
            }
        }
    }

    let raw_home = match real_home {
        Some(h) => h.to_path_buf(),
        None => get_real_home_dir()?,
    };
    let home = verify_safe_home_dir(&raw_home, real_home)?;
    let local_dir = ensure_private_dir(&home.join(".local"), 0o700)?;
    let share_dir = ensure_private_dir(&local_dir.join("share"), 0o700)?;
    let base_dir = ensure_private_dir(&share_dir.join("agy-tui"), 0o700)?;
    let empty_dir = base_dir.join("empty-workspace");

    if !empty_dir.exists() {
        DirBuilder::new()
            .mode(0o500)
            .create(&empty_dir)
            .map_err(|e| {
                SecurityError(format!(
                    "Failed to create empty workspace {}: {e}",
                    empty_dir.display()
                ))
            })?;
    }

    let lst = fs::symlink_metadata(&empty_dir).map_err(|e| {
        SecurityError(format!(
            "Cannot lstat empty workspace {}: {e}",
            empty_dir.display()
        ))
    })?;
    let uid = current_uid()?;
    if lst.file_type().is_symlink() || !lst.file_type().is_dir() || lst.uid() != uid {
        return Err(SecurityError(format!(
            "Invalid empty workspace directory: {}",
            empty_dir.display()
        )));
    }
    let mut rd = fs::read_dir(&empty_dir).map_err(|e| {
        SecurityError(format!(
            "Cannot read empty workspace {}: {e}",
            empty_dir.display()
        ))
    })?;
    if rd.next().is_some() {
        return Err(SecurityError(format!(
            "Empty workspace {} is not empty! Refusing to run.",
            empty_dir.display()
        )));
    }
    if (lst.mode() & 0o777) != 0o500 {
        fs::set_permissions(&empty_dir, fs::Permissions::from_mode(0o500)).map_err(|e| {
            SecurityError(format!(
                "Failed to set 0500 mode on {}: {e}",
                empty_dir.display()
            ))
        })?;
    }

    Ok(empty_dir)
}

/// Build a strict allowlist environment for the host `agy` process.
pub fn build_host_env(real_home: Option<&Path>) -> Result<BTreeMap<String, String>, SecurityError> {
    let default_home;
    let target_home = match real_home {
        Some(h) => h,
        None => {
            default_home = get_real_home_dir()?;
            &default_home
        }
    };
    let home = verify_safe_home_dir(target_home, real_home)?;
    let uid = current_uid()?;
    let username = get_current_username();

    let mut env_map = BTreeMap::new();
    env_map.insert("HOME".to_string(), home.to_string_lossy().into_owned());
    env_map.insert("USER".to_string(), username.clone());
    env_map.insert("LOGNAME".to_string(), username);
    env_map.insert(
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin".to_string(),
    );
    env_map.insert("LANG".to_string(), "C.UTF-8".to_string());
    env_map.insert("TERM".to_string(), "dumb".to_string());

    let runtime_dir = format!("/run/user/{uid}");
    let rt_path = Path::new(&runtime_dir);
    if let Ok(st) = fs::symlink_metadata(rt_path) {
        if !st.file_type().is_symlink()
            && st.file_type().is_dir()
            && st.uid() == uid
            && (st.mode() & 0o077) == 0
        {
            env_map.insert("XDG_RUNTIME_DIR".to_string(), runtime_dir.clone());
            let bus_socket = rt_path.join("bus");
            if let Ok(bst) = fs::symlink_metadata(&bus_socket) {
                if !bst.file_type().is_symlink()
                    && bst.file_type().is_socket()
                    && bst.uid() == uid
                {
                    env_map.insert(
                        "DBUS_SESSION_BUS_ADDRESS".to_string(),
                        format!("unix:path={}", bus_socket.display()),
                    );
                }
            }
        }
    }

    Ok(env_map)
}

/// Construct verified `(argv, clean_env)` for executing `agy -p /usage` safely.
pub fn build_isolated_command(
    mode: &str,
    agy_bin: &Path,
    home_dir: &Path,
    container_name: Option<&str>,
    real_home: Option<&Path>,
) -> Result<(Vec<String>, BTreeMap<String, String>), SecurityError> {
    let verified_agy = verify_safe_executable(agy_bin)?;
    let verified_home = verify_safe_home_dir(home_dir, real_home)?;
    let username = get_current_username();

    let agy_args = vec![
        verified_agy.to_string_lossy().into_owned(),
        "--log-file".to_string(),
        "/dev/null".to_string(),
        "--print-timeout".to_string(),
        "25s".to_string(),
        "-p".to_string(),
        "/usage".to_string(),
        "--output-format".to_string(),
        "json".to_string(),
    ];

    match mode {
        "host" => {
            let host_env = build_host_env(Some(&verified_home))?;
            Ok((agy_args, host_env))
        }
        "isolated_home" => {
            let mut iso_env = BTreeMap::new();
            iso_env.insert(
                "HOME".to_string(),
                verified_home.to_string_lossy().into_owned(),
            );
            iso_env.insert("USER".to_string(), username.clone());
            iso_env.insert("LOGNAME".to_string(), username);
            iso_env.insert(
                "PATH".to_string(),
                "/usr/local/bin:/usr/bin:/bin".to_string(),
            );
            iso_env.insert("LANG".to_string(), "C.UTF-8".to_string());
            iso_env.insert("TERM".to_string(), "dumb".to_string());
            iso_env.insert("DBUS_SESSION_BUS_ADDRESS".to_string(), String::new());
            iso_env.insert("SSH_CONNECTION".to_string(), "127.0.0.1 1234".to_string());
            Ok((agy_args, iso_env))
        }
        "toolbox" | "distrobox" => {
            let cname = container_name.ok_or_else(|| {
                SecurityError(format!("Mode '{mode}' requires a valid container name"))
            })?;
            let safe_container = validate_identifier(cname, "container_name")?;
            let runner_bin = verify_safe_executable(Path::new(&format!("/usr/bin/{mode}")))?;
            let env_bin = verify_safe_executable(Path::new("/usr/bin/env"))?;

            let mut outer_env = build_host_env(real_home)?;
            outer_env.remove("DBUS_SESSION_BUS_ADDRESS");

            let mut cmd = Vec::with_capacity(24);
            cmd.push(runner_bin.to_string_lossy().into_owned());
            if mode == "toolbox" {
                cmd.push("run".to_string());
                cmd.push("-c".to_string());
                cmd.push(safe_container.to_string());
            } else {
                cmd.push("enter".to_string());
                cmd.push(safe_container.to_string());
                cmd.push("--".to_string());
            }
            cmd.push(env_bin.to_string_lossy().into_owned());
            cmd.push("-i".to_string());
            cmd.push(format!("HOME={}", verified_home.display()));
            cmd.push(format!("USER={username}"));
            cmd.push(format!("LOGNAME={username}"));
            cmd.push("PATH=/usr/local/bin:/usr/bin:/bin".to_string());
            cmd.push("LANG=C.UTF-8".to_string());
            cmd.push("TERM=dumb".to_string());
            cmd.push("DBUS_SESSION_BUS_ADDRESS=".to_string());
            cmd.push("SSH_CONNECTION=127.0.0.1 1234".to_string());
            cmd.extend(agy_args);

            Ok((cmd, outer_env))
        }
        other => Err(SecurityError(format!(
            "Unsupported profile execution mode: {other}"
        ))),
    }
}

/// Atomically write JSON bytes into a validated `0700` directory using `O_EXCL | O_NOFOLLOW` (`0600`).
pub fn atomic_write_json(dir_path: &Path, filename: &str, json_bytes: &[u8]) -> Result<PathBuf, SecurityError> {
    validate_json_filename(filename)?;
    let safe_dir = ensure_private_dir(dir_path, 0o700)?;
    let target = safe_dir.join(filename);
    let uid = current_uid()?;

    if let Ok(target_lst) = fs::symlink_metadata(&target) {
        if target_lst.file_type().is_symlink() {
            return Err(SecurityError(format!(
                "Refusing to overwrite symlink: {}",
                target.display()
            )));
        }
        if target_lst.uid() != uid {
            return Err(SecurityError(format!(
                "Target file owned by another UID: {}",
                target.display()
            )));
        }
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{filename}.{pid}.{nanos}.{seq}.tmp");
    let tmp_path = safe_dir.join(tmp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW_FLAG)
        .open(&tmp_path)
        .map_err(|e| {
            SecurityError(format!(
                "Failed to open temporary file {}: {e}",
                tmp_path.display()
            ))
        })?;

    let write_res = (|| -> std::io::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(json_bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(SecurityError(format!(
            "Failed writing temporary JSON {}: {e}",
            tmp_path.display()
        )));
    }
    drop(file);

    if let Err(e) = fs::rename(&tmp_path, &target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(SecurityError(format!(
            "Failed atomic rename to {}: {e}",
            target.display()
        )));
    }

    Ok(target)
}

/// Safely read a JSON file with `O_NOFOLLOW`, ownership verification, hardlink rejection (`nlink == 1`), and size cap.
pub fn safe_read_json(
    dir_path: &Path,
    filename: &str,
    max_bytes: u64,
) -> Result<Option<serde_json::Value>, SecurityError> {
    validate_json_filename(filename)?;
    let safe_dir = ensure_private_dir(dir_path, 0o700)?;
    let target = safe_dir.join(filename);
    let uid = current_uid()?;

    let lst = match fs::symlink_metadata(&target) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SecurityError(format!(
                "Cannot lstat {}: {e}",
                target.display()
            )))
        }
    };

    if lst.file_type().is_symlink() {
        return Err(SecurityError(format!(
            "Refusing to read symlinked file: {}",
            target.display()
        )));
    }
    if !lst.file_type().is_file() {
        return Err(SecurityError(format!(
            "Refusing to read non-regular file: {}",
            target.display()
        )));
    }
    if lst.uid() != uid {
        return Err(SecurityError(format!(
            "File {} owned by untrusted UID {}",
            target.display(),
            lst.uid()
        )));
    }
    if (lst.mode() & 0o022) != 0 {
        return Err(SecurityError(format!(
            "File {} is group/world-writable",
            target.display()
        )));
    }

    let file: File = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW_FLAG)
        .open(&target)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SecurityError(format!(
                "Cannot open {} (symlink or permission error): {e}",
                target.display()
            )))
        }
    };

    let fst = file
        .metadata()
        .map_err(|e| SecurityError(format!("fstat failed on {}: {e}", target.display())))?;
    if !fst.file_type().is_file() || fst.uid() != uid {
        return Err(SecurityError(format!(
            "File descriptor validation failed for {}",
            target.display()
        )));
    }
    if fst.nlink() > 1 {
        return Err(SecurityError(format!(
            "Refusing to read hardlinked file (nlink={}): {}",
            fst.nlink(),
            target.display()
        )));
    }
    if (fst.mode() & 0o022) != 0 {
        return Err(SecurityError(format!(
            "File descriptor for {} is group/world-writable",
            target.display()
        )));
    }
    if fst.len() > max_bytes {
        return Err(SecurityError(format!(
            "File {} exceeds maximum allowed size ({} > {max_bytes})",
            target.display(),
            fst.len()
        )));
    }

    let mut buf = Vec::with_capacity((fst.len() as usize).min(max_bytes as usize));
    file.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| SecurityError(format!("Error reading {}: {e}", target.display())))?;
    if buf.len() as u64 > max_bytes {
        return Err(SecurityError(format!(
            "File {} read exceeded {max_bytes} bytes",
            target.display()
        )));
    }

    let val: serde_json::Value = serde_json::from_slice(&buf)
        .map_err(|e| SecurityError(format!("Corrupted JSON in {}: {e}", target.display())))?;
    if !val.is_object() {
        return Err(SecurityError(format!(
            "Expected JSON object in {}",
            target.display()
        )));
    }

    Ok(Some(val))
}

/// Terminate an entire subprocess group (`-PGID`) in 100% safe Rust using a verified system `kill` binary.
pub fn kill_process_group(child: &mut Child) {
    let pid = child.id();
    if pid > 1 {
        let neg_pgid = format!("-{pid}");
        for kill_path in ["/usr/bin/kill", "/bin/kill"] {
            let p = Path::new(kill_path);
            if let Ok(verified_kill) = verify_safe_executable(p) {
                let _ = Command::new(verified_kill)
                    .args(["-KILL", "--", &neg_pgid])
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
