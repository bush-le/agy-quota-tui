//! Zero-config profile auto-discovery and declarative configuration validator.
//!
//! Strictly forbids arbitrary shell commands (`cmd`, `shell`, etc.) in `config.json`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::models::ProfileSpec;
use crate::security::{
    atomic_write_json, build_host_env, get_real_home_dir, get_safe_config_dir,
    get_safe_empty_workspace, kill_process_group, safe_read_json, sanitize_terminal_text,
    validate_identifier, verify_safe_executable, verify_safe_home_dir, SecurityError,
    DEFAULT_POLL_INTERVAL_SECONDS, MAX_POLL_INTERVAL_SECONDS, MIN_POLL_INTERVAL_SECONDS,
};

pub const ALLOWED_MODES: [&str; 4] = ["host", "toolbox", "distrobox", "isolated_home"];
pub const ALLOWED_THEMES: [&str; 5] = [
    "tokyo-night",
    "catppuccin-mocha",
    "dracula",
    "nord",
    "gruvbox",
];
pub const ALLOWED_FILTER_MODES: [&str; 2] = ["all", "5h"];

const ALLOWED_CONFIG_KEYS: [&str; 4] = ["poll_interval", "filter_mode", "theme", "profiles"];
const ALLOWED_PROFILE_KEYS: [&str; 6] = [
    "id",
    "label",
    "command_hint",
    "mode",
    "home_dir",
    "container",
];

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub poll_interval: u64,
    pub filter_mode: String,
    pub theme: String,
    pub profiles: Option<Vec<ProfileSpec>>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL_SECONDS,
            filter_mode: "all".to_string(),
            theme: "tokyo-night".to_string(),
            profiles: None,
        }
    }
}

/// Locate and verify the official `agy` binary from trusted canonical locations only.
/// Never searches untrusted `PATH` directories to prevent PATH shadowing attacks.
pub fn locate_agy_binary(real_home: Option<&Path>) -> Result<PathBuf, SecurityError> {
    let default_home;
    let base_ref = match real_home {
        Some(h) => h,
        None => {
            default_home = get_real_home_dir()?;
            &default_home
        }
    };
    let home = verify_safe_home_dir(base_ref, real_home)?;
    let candidates = [
        home.join(".local").join("bin").join("agy"),
        PathBuf::from("/usr/local/bin/agy"),
        PathBuf::from("/usr/bin/agy"),
    ];

    for candidate in &candidates {
        if !candidate.exists() {
            continue;
        }
        if let Ok(verified) = verify_safe_executable(candidate) {
            return Ok(verified);
        }
    }

    Err(SecurityError(
        "Could not find a safe, user/root-owned `agy` binary in ~/.local/bin or /usr/bin."
            .to_string(),
    ))
}

fn list_containers(tool_name: &str, real_home: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let tool_path = PathBuf::from(format!("/usr/bin/{tool_name}"));
    if !tool_path.exists() {
        return names;
    }

    let Ok(verified_tool) = verify_safe_executable(&tool_path) else {
        return names;
    };
    let Ok(clean_env) = build_host_env(Some(real_home)) else {
        return names;
    };
    let Ok(empty_cwd) = get_safe_empty_workspace(Some(real_home)) else {
        return names;
    };

    let Ok(mut child) = Command::new(verified_tool)
        .args(["list", "--containers"])
        .current_dir(empty_cwd)
        .env_clear()
        .envs(&clean_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    else {
        return names;
    };

    let stdout_pipe = child.stdout.take();
    let out_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout_pipe {
            let _ = pipe.take(65_536).read_to_end(&mut buf);
        }
        buf
    });

    let start = Instant::now();
    let finished_ok = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    kill_process_group(&mut child);
                    break false;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                kill_process_group(&mut child);
                break false;
            }
        }
    };

    let stdout_bytes = out_handle.join().unwrap_or_default();
    if finished_ok {
        let stdout_str = String::from_utf8_lossy(&stdout_bytes);
        for line in stdout_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] != "CONTAINER" {
                let candidate = parts[1].trim();
                if validate_identifier(candidate, "container").is_ok() {
                    names.insert(candidate.to_string());
                }
            }
        }
    }
    names
}

fn parse_profile_dir_suffix(dir_name: &str) -> Option<&str> {
    let suffix = dir_name
        .strip_prefix(".gemini-pro")
        .or_else(|| dir_name.strip_prefix(".agy-profile"))?;
    if suffix.is_empty() || suffix.len() > 32 {
        return None;
    }
    if suffix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Some(suffix)
    } else {
        None
    }
}

fn natural_sort_key(name: &str) -> (u64, String) {
    let digits_rev: String = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if !digits_rev.is_empty() {
        let digits: String = digits_rev.chars().rev().collect();
        if let Ok(num) = digits.parse::<u64>() {
            return (num, name.to_string());
        }
    }
    (9999, name.to_string())
}

/// Auto-discover host and isolated Antigravity profiles without hardcoded usernames or paths.
pub fn discover_profiles(real_home: Option<&Path>) -> Result<Vec<ProfileSpec>, SecurityError> {
    let default_home;
    let base_ref = match real_home {
        Some(h) => h,
        None => {
            default_home = get_real_home_dir()?;
            &default_home
        }
    };
    let home = verify_safe_home_dir(base_ref, real_home)?;
    let mut profiles = vec![ProfileSpec {
        id: "agy".to_string(),
        label: "agy (Host)".to_string(),
        command_hint: "agy".to_string(),
        mode: "host".to_string(),
        home_dir: home.to_string_lossy().into_owned(),
        container: None,
    }];

    let toolbox_containers = list_containers("toolbox", &home);
    let distrobox_containers = list_containers("distrobox", &home);

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(rd) = fs::read_dir(&home) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            entries.push((name, entry.path()));
        }
    }
    entries.sort_by_key(|(name, _)| natural_sort_key(name));

    for (name, path) in entries {
        let Some(suffix) = parse_profile_dir_suffix(&name) else {
            continue;
        };
        let Ok(verified_dir) = verify_safe_home_dir(&path, Some(&home)) else {
            continue;
        };

        let profile_id = format!("agy{suffix}");
        if validate_identifier(&profile_id, "profile_id").is_err() {
            continue;
        }

        let candidates = [
            format!("agy-pro{suffix}"),
            format!("agy-{suffix}"),
            format!("agy{suffix}"),
        ];
        let mut selected_mode = "isolated_home".to_string();
        let mut selected_container: Option<String> = None;

        for cname in &candidates {
            if toolbox_containers.contains(cname) {
                selected_mode = "toolbox".to_string();
                selected_container = Some(cname.clone());
                break;
            }
            if distrobox_containers.contains(cname) {
                selected_mode = "distrobox".to_string();
                selected_container = Some(cname.clone());
                break;
            }
        }

        let badge = selected_container.as_deref().unwrap_or(&name);
        profiles.push(ProfileSpec {
            id: profile_id.clone(),
            label: format!("{profile_id} ({badge})"),
            command_hint: profile_id,
            mode: selected_mode,
            home_dir: verified_dir.to_string_lossy().into_owned(),
            container: selected_container,
        });
    }

    Ok(profiles)
}

/// Strictly validate a declarative profile object from `config.json`.
pub fn validate_profile_value(
    raw: &Value,
    real_home: Option<&Path>,
) -> Result<ProfileSpec, SecurityError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| SecurityError("Each profile entry must be a JSON object".to_string()))?;

    for key in obj.keys() {
        if !ALLOWED_PROFILE_KEYS.contains(&key.as_str()) {
            return Err(SecurityError(format!(
                "Forbidden or unknown key in profile config: {key}"
            )));
        }
    }

    let id_raw = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| SecurityError("Profile missing string 'id'".to_string()))?;
    let id = validate_identifier(id_raw, "profile.id")?.to_string();

    let mode_raw = obj
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("isolated_home")
        .trim();
    if !ALLOWED_MODES.contains(&mode_raw) {
        return Err(SecurityError(format!("Invalid profile mode: {mode_raw}")));
    }

    let home_raw = obj
        .get("home_dir")
        .and_then(Value::as_str)
        .ok_or_else(|| SecurityError(format!("Profile '{id}' missing valid 'home_dir'")))?;
    if home_raw.trim().is_empty() {
        return Err(SecurityError(format!(
            "Profile '{id}' has empty 'home_dir'"
        )));
    }
    let verified_home = verify_safe_home_dir(Path::new(home_raw.trim()), real_home)?;

    let container = match (mode_raw, obj.get("container")) {
        ("toolbox" | "distrobox", Some(Value::String(s))) if !s.trim().is_empty() => {
            Some(validate_identifier(s.trim(), "profile.container")?.to_string())
        }
        ("toolbox" | "distrobox", _) => {
            return Err(SecurityError(format!(
                "Profile '{id}' with mode '{mode_raw}' requires 'container'"
            )))
        }
        (_, None | Some(Value::Null)) => None,
        _ => {
            return Err(SecurityError(format!(
                "Profile '{id}' with mode '{mode_raw}' must not specify 'container'"
            )))
        }
    };

    let label_raw = obj.get("label").and_then(Value::as_str).unwrap_or(&id);
    let label = sanitize_terminal_text(label_raw, 40);

    let hint_raw = obj
        .get("command_hint")
        .and_then(Value::as_str)
        .unwrap_or(&id);
    let command_hint = validate_identifier(hint_raw, "profile.command_hint")?.to_string();

    Ok(ProfileSpec {
        id,
        label,
        command_hint,
        mode: mode_raw.to_string(),
        home_dir: verified_home.to_string_lossy().into_owned(),
        container,
    })
}

/// Load and validate `~/.config/agy-tui/config.json` if present, else return defaults.
pub fn load_app_config(real_home: Option<&Path>) -> Result<AppConfig, SecurityError> {
    let cfg_dir = get_safe_config_dir(real_home)?;
    let Some(val) = safe_read_json(&cfg_dir, "config.json", 65_536)? else {
        return Ok(AppConfig::default());
    };
    let obj = val
        .as_object()
        .ok_or_else(|| SecurityError("config.json must be a JSON object".to_string()))?;

    for key in obj.keys() {
        if !ALLOWED_CONFIG_KEYS.contains(&key.as_str()) {
            return Err(SecurityError(format!(
                "Unknown key in config.json: {key}"
            )));
        }
    }

    let interval = match obj.get("poll_interval") {
        None => DEFAULT_POLL_INTERVAL_SECONDS,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                SecurityError("poll_interval must be a positive integer".to_string())
            })?;
            n.clamp(MIN_POLL_INTERVAL_SECONDS, MAX_POLL_INTERVAL_SECONDS)
        }
    };

    let filter_raw = obj
        .get("filter_mode")
        .and_then(Value::as_str)
        .unwrap_or("all");
    let filter_mode = if ALLOWED_FILTER_MODES.contains(&filter_raw) {
        filter_raw.to_string()
    } else {
        "all".to_string()
    };

    let theme_raw = obj
        .get("theme")
        .and_then(Value::as_str)
        .unwrap_or("tokyo-night");
    let theme = if ALLOWED_THEMES.contains(&theme_raw) {
        theme_raw.to_string()
    } else {
        "tokyo-night".to_string()
    };

    let mut profiles: Option<Vec<ProfileSpec>> = None;
    if let Some(p_val) = obj.get("profiles") {
        if !p_val.is_null() {
            let arr = p_val.as_array().ok_or_else(|| {
                SecurityError("profiles must be a list of profile objects".to_string())
            })?;
            if arr.is_empty() || arr.len() > 12 {
                return Err(SecurityError(
                    "profiles must contain between 1 and 12 profile objects".to_string(),
                ));
            }
            let mut parsed = Vec::with_capacity(arr.len());
            let mut seen_ids = BTreeSet::new();
            for item in arr {
                let spec = validate_profile_value(item, real_home)?;
                if !seen_ids.insert(spec.id.clone()) {
                    return Err(SecurityError(format!(
                        "Duplicate profile id in config.json: {}",
                        spec.id
                    )));
                }
                parsed.push(spec);
            }
            profiles = Some(parsed);
        }
    }

    Ok(AppConfig {
        poll_interval: interval,
        filter_mode,
        theme,
        profiles,
    })
}

/// Persist UI preferences safely without overwriting custom declarative profiles.
pub fn save_user_preferences(
    poll_interval: u64,
    filter_mode: &str,
    theme: &str,
    real_home: Option<&Path>,
) {
    let Ok(cfg_dir) = get_safe_config_dir(real_home) else {
        return;
    };
    let existing = safe_read_json(&cfg_dir, "config.json", 65_536)
        .ok()
        .flatten();

    let safe_interval = poll_interval.clamp(MIN_POLL_INTERVAL_SECONDS, MAX_POLL_INTERVAL_SECONDS);
    let safe_filter = if ALLOWED_FILTER_MODES.contains(&filter_mode) {
        filter_mode
    } else {
        "all"
    };
    let safe_theme = if ALLOWED_THEMES.contains(&theme) {
        theme
    } else {
        "tokyo-night"
    };

    let mut payload = json!({
        "poll_interval": safe_interval,
        "filter_mode": safe_filter,
        "theme": safe_theme,
    });

    if let Some(Value::Object(old_map)) = existing {
        if let Some(Value::Array(arr)) = old_map.get("profiles") {
            if !arr.is_empty() && arr.len() <= 12 {
                let mut valid_profs = Vec::with_capacity(arr.len());
                let mut seen_ids = BTreeSet::new();
                let mut all_valid = true;
                for item in arr {
                    match validate_profile_value(item, real_home) {
                        Ok(spec) if seen_ids.insert(spec.id.clone()) => valid_profs.push(spec),
                        _ => {
                            all_valid = false;
                            break;
                        }
                    }
                }
                if all_valid {
                    if let (Some(map), Ok(profs_val)) =
                        (payload.as_object_mut(), serde_json::to_value(valid_profs))
                    {
                        map.insert("profiles".to_string(), profs_val);
                    }
                }
            }
        }
    }

    if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
        let _ = atomic_write_json(&cfg_dir, "config.json", &bytes);
    }
}

/// Return validated `AppConfig` and the list of active profiles (configured or auto-discovered).
pub fn get_active_profiles(
    real_home: Option<&Path>,
) -> Result<(AppConfig, Vec<ProfileSpec>), SecurityError> {
    let config = load_app_config(real_home)?;
    let profiles = match &config.profiles {
        Some(p) => p.clone(),
        None => discover_profiles(real_home)?,
    };
    Ok((config, profiles))
}
