# `agy-top` (`agy-quota`)

**Blazing-fast, 100% memory-safe native Rust Terminal UI (TUI) & CLI quota monitor for managing multiple isolated Google Antigravity CLI (`agy`) accounts.**

![Language: Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)
![Memory Safety: forbid(unsafe_code)](https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg)
![Network: Zero Sockets](https://img.shields.io/badge/network-zero%20crates-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-informational.svg)

---

## Table of Contents

- [Why `agy-top`?](#why-agy-top)
- [Visual Previews](#visual-previews)
- [Key Features](#key-features)
- [Installation](#installation)
- [CLI Usage & Keyboard Shortcuts](#cli-usage--keyboard-shortcuts)
- [Multi-Account Isolation Guide (`agy`, `agy2`, `agy3`)](#multi-account-isolation-guide-agy-agy2-agy3)
- [Configuration (`config.json`)](#configuration-configjson)
- [Security Architecture](#security-architecture)
- [Repository Structure](#repository-structure)
- [License](#license)

---

## Why `agy-top`?

Developers running multiple **Google Antigravity CLI (`agy`)** subscriptions—such as a primary Host account alongside isolated **Fedora Toolbox**, **Distrobox**, or custom `$HOME` profiles (`agy2`, `agy3`, ...)—need an instant, zero-overhead way to see:

1. **Remaining Quota (%)** across all accounts for **Gemini Models**, **Claude & GPT**, and **Gemini 4 Argon**.
2. **Live Reset Countdowns** (`04h 55m 13s` ticking down every second for active 5-hour rolling windows, plus exact local reset timestamps `HH:MM` / `DD/MM HH:MM`).
3. **Smart "Best Account" Recommendations**: Automatically ranks accounts by effective 5-hour remaining quota, weekly remaining quota, and earliest reset time so you always know which account (`agy`, `agy2`, or `agy3`) to invoke next.

---

## Visual Previews

### 1. Interactive Live TUI Dashboard (`agy-top`)

```text
 AGY Quota Monitor   Theme: tokyo-night  │  01:30:35
╭─ AGY MULTI-ACCOUNT QUOTA  │  Interval: 5m (04:58) · Filter: All (5h + Weekly) · Updated: 01:30:35 ────╮
│ BEST ACCOUNT  >  Gemini: agy3 (5h: 100% · Wk: 100%)   │   Claude / GPT: agy3 (5h: 100% · Wk: 100%)    │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ [1] agy (Host) · WARN ────────╮╭─ [2] agy2 (agy-pro2) · WARN ───╮╭─ [3] agy3 (agy-pro3) · BEST ───╮
│ 5-HOUR LIMIT                   ││ 5-HOUR LIMIT                   ││ 5-HOUR LIMIT                   │
│  Gemini Models    ██████████ 97%││  Gemini Models    ██████████100%││  Gemini Models    ██████████100%│
│    Reset: 4h 55m 13s (06:25)   ││    Ready (5h)                  ││    Ready (5h)                  │
│  Claude & GPT     ██████████100%││  Claude & GPT     ██████████100%││  Claude & GPT     ██████████100%│
│    Ready (5h)                  ││    Ready (5h)                  ││    Ready (5h)                  │
│                                ││                                ││                                │
│ WEEKLY LIMIT                   ││ WEEKLY LIMIT                   ││ WEEKLY LIMIT                   │
│  Gemini Models    ████████░░ 83%││  Gemini Models    ██████████ 99%││  Gemini Models    ██████████100%│
│    Reset: 2d 13h 13m (31/10)   ││    Reset: 3d 16h 16m (01/11)   ││    Reset: 6d 21h 55m (04/11)   │
│  Claude & GPT     █████░░░░░ 49%││  Claude & GPT     █████░░░░░ 53%││  Claude & GPT     ██████████100%│
│    Reset: 6d 09h 31m (04/11)   ││    Reset: 3d 02h 54m (01/11)   ││    Reset: 6d 23h 59m (05/11)   │
╰────────────────────── cmd: agy ╯╰───────────────────── cmd: agy2 ╯╰───────────────────── cmd: agy3 ╯
 r  Refresh   f  Filter 5h/All   i  Interval   t  Theme   q  Quit
```

### 2. Instant CLI Snapshot (`agy-top -s`)

```text
╭─  AGY MULTI-ACCOUNT QUOTA MONITOR · 01:30:35  ────────────────────────────────────────────╮
│ BEST ACCOUNT  >  Gemini: agy3 (5h: 100% · Wk: 100%)   │   Claude / GPT: agy3 (5h: 100% · Wk: 100%)
╰───────────────────────────────────────────────────────────────────────────────────────────╯
╭─ [1] agy (Host) [WARN] (cmd: agy)
│ 5-HOUR LIMIT
│   Gemini Models          ━━━━━━━━━━  97%  Reset: 4h 55m 13s (06:25)
│   Claude & GPT           ━━━━━━━━━━ 100%  Ready (5h)
│ WEEKLY LIMIT
│   Gemini Models          ━━━━━━━━╌╌  83%  Reset: 2d 13h 13m (31/10 14:43)
│   Claude & GPT           ━━━━━╌╌╌╌╌  49%  Reset: 6d 09h 31m (04/11 11:01)
│   Gemini 4 Argon         ━━━━━╌╌╌╌╌  48%  Reset: 6d 09h 34m (04/11 11:04)
╰───────────────────────────────────────────────────────────────────────────────────────────╯
```

---

## Key Features

- **100% Safe Native Rust (`#![forbid(unsafe_code)]`)**:
  - Compiles to a single standalone ~1 MB native binary (`ratatui` + `crossterm`) with `< 2ms` startup time and zero Python/Node runtime dependencies.
- **Icon-Free Terminal Rendering**:
  - Uses pure fixed-width ASCII and standard box-drawing characters with zero ambiguous-width emojis, guaranteeing crisp alignment across every terminal emulator and monospace font.
- **Dual Execution Modes**:
  - **Interactive Live TUI (`agy-top`)**: Full-screen dashboard with 1-second live countdown ticks, non-blocking parallel background sync, and 5 built-in 24-bit color themes (`tokyo-night`, `catppuccin-mocha`, `dracula`, `nord`, `gruvbox`).
  - **Instant CLI Snapshot (`agy-top -s`)**: Prints a 24-bit TrueColor summary directly to stdout and exits (`agy-top -sc` renders from cache in `< 5ms`).
- **Auto-Responsive Terminal Grid**:
  - Automatically adapts between **3 columns** on wide monitors (`>= 122` cols), **2 columns** on medium windows (`82..121` cols), and a **1-column vertical stack** inside narrow **VS Code Split Terminals** (`< 82` cols).
- **Zero Token Cost & Zero Log Clutter**:
  - Queries `agy --log-file /dev/null --print-timeout 25s -p "/usage" --output-format json` concurrently across all accounts (`0` LLM tokens consumed, `0` conversation DB files created, `0` log files written).
- **Smart Auto-Refresh on Window Reset**:
  - Automatically triggers a fresh background sync when any active 5-hour or weekly quota bucket reaches `00m 00s`, plus configurable periodic polling (`2m` / `5m` / `15m`).

---

## Installation

### Prerequisites
- **OS**: Linux or macOS
- **Rust Toolchain**: `cargo` and `rustc` (`>= 1.75`, install via [rustup.rs](https://rustup.rs))
- **Antigravity CLI**: Official `agy` binary installed in `~/.local/bin/agy`, `/usr/local/bin/agy`, or `/usr/bin/agy`

### Build & Install (`~/.local/bin`)

```bash
git clone https://github.com/<your-username>/agy-tui.git
cd agy-tui
./install.sh
```

`./install.sh` compiles the release binary with `--locked` (verifying all SHA-256 crate checksums in `Cargo.lock`), strips symbols with LTO enabled, and installs:
- `~/.local/bin/agy-top`
- `~/.local/bin/agy-quota` (symlink alias)

Make sure `~/.local/bin` is in your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Uninstall

```bash
rm -f "$HOME/.local/bin/agy-top" "$HOME/.local/bin/agy-quota"
rm -rf "$HOME/.config/agy-tui" "$HOME/.cache/agy-tui" "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agy-tui"
```

---

## CLI Usage & Keyboard Shortcuts

| Command | Description |
| :--- | :--- |
| `agy-top` (or `agy-quota`) | Launch the interactive **Live TUI Dashboard** (default) |
| `agy-top -s` / `--status` | Print an instant 24-bit color snapshot to terminal and exit |
| `agy-top -s5` / `-s -5` / `--only-5h` | Print snapshot showing **only 5-hour rolling limits** |
| `agy-top -sc` / `-s -c` / `--cached` | Print the most recent cached snapshot immediately (`< 5ms`) |
| `agy-top --list-profiles` | List all auto-discovered or configured account profiles |
| `agy-top --json` | Output sanitized quota snapshots and recommendations as JSON |
| `agy-top -v` / `--version` | Display version information |
| `agy-top -h` / `--help` | Display help message |

### Interactive TUI Keybindings

| Key | Action |
| :---: | :--- |
| `r` | Trigger an immediate parallel refresh across all accounts (debounced single-flight) |
| `f` | Toggle bucket filter: **All Limits (5h + Weekly)** <-> **5-Hour Limits Only** |
| `i` | Cycle auto-refresh polling interval: **2m** -> **5m** (default) -> **15m** |
| `t` | Cycle color theme: `tokyo-night` -> `catppuccin-mocha` -> `dracula` -> `nord` -> `gruvbox` |
| `q` / `Esc` / `Ctrl+C` | Quit cleanly and restore terminal screen |

*(Filter mode, polling interval, and theme selections are automatically persisted to `~/.config/agy-tui/config.json`).*

---

## Multi-Account Isolation Guide (`agy`, `agy2`, `agy3`)

By default, `agy` on Linux stores OAuth credentials in the host **GNOME Keyring** (via `DBUS_SESSION_BUS_ADDRESS`) and writes state to `$HOME/.gemini`. Running a second account on the same host without isolating both `HOME` and `DBUS_SESSION_BUS_ADDRESS` will overwrite your primary account's keyring token.

Setting `DBUS_SESSION_BUS_ADDRESS=""` and `SSH_CONNECTION="127.0.0.1 1234"` forces `agy` to store each extra account's OAuth token in its own isolated `$HOME/.gemini/antigravity-oauth-token` (`0600`) without touching the host GNOME Keyring.

### Option A: Fedora Toolbox / Distrobox + Isolated `$HOME` (Recommended on Linux)

1. **Create an isolated container and home directory for each extra account**:

```bash
# Account 2 (agy2)
toolbox create -y agy-pro2
mkdir -p -m 700 "$HOME/.gemini-pro2"

# Account 3 (agy3)
toolbox create -y agy-pro3
mkdir -p -m 700 "$HOME/.gemini-pro3"
```

2. **Add isolated aliases to `~/.bashrc` (or `~/.zshrc`)**:

```bash
alias agy2='toolbox run -c agy-pro2 env DBUS_SESSION_BUS_ADDRESS="" SSH_CONNECTION="127.0.0.1 1234" HOME="$HOME/.gemini-pro2" "$HOME/.local/bin/agy"'
alias agy3='toolbox run -c agy-pro3 env DBUS_SESSION_BUS_ADDRESS="" SSH_CONNECTION="127.0.0.1 1234" HOME="$HOME/.gemini-pro3" "$HOME/.local/bin/agy"'
```

3. **Authenticate each account once**:

```bash
agy2 auth login
agy3 auth login
```

### Option B: Lightweight Host-Only Isolated `$HOME` (No Containers Needed)

If you do not use Toolbox or Distrobox, you can isolate accounts directly on the host:

```bash
mkdir -p -m 700 "$HOME/.gemini-pro2" "$HOME/.gemini-pro3"

alias agy2='env DBUS_SESSION_BUS_ADDRESS="" SSH_CONNECTION="127.0.0.1 1234" HOME="$HOME/.gemini-pro2" "$HOME/.local/bin/agy"'
alias agy3='env DBUS_SESSION_BUS_ADDRESS="" SSH_CONNECTION="127.0.0.1 1234" HOME="$HOME/.gemini-pro3" "$HOME/.local/bin/agy"'
```

---

## Configuration (`config.json`)

### Zero-Config Auto-Discovery

Out of the box, `agy-top` requires **zero configuration**. It automatically discovers:
1. `agy` (Host account in `$HOME`)
2. Any `~/.gemini-pro<N>` or `~/.agy-profile<N>` directory owned by your UID (`0700`), automatically pairing it with a matching `toolbox` or `distrobox` container (`agy-pro2`, `agy-pro3`, ...) or falling back to `isolated_home` mode.

### Optional Custom Configuration (`~/.config/agy-tui/config.json`)

To customize account labels or define profiles explicitly, create `~/.config/agy-tui/config.json` (arbitrary shell commands are strictly forbidden):

```json
{
  "poll_interval": 300,
  "filter_mode": "all",
  "theme": "tokyo-night",
  "profiles": [
    {
      "id": "agy",
      "label": "agy (Host)",
      "command_hint": "agy",
      "mode": "host",
      "home_dir": "~"
    },
    {
      "id": "agy2",
      "label": "agy2 (agy-pro2)",
      "command_hint": "agy2",
      "mode": "toolbox",
      "container": "agy-pro2",
      "home_dir": "~/.gemini-pro2"
    },
    {
      "id": "agy3",
      "label": "agy3 (agy-pro3)",
      "command_hint": "agy3",
      "mode": "toolbox",
      "container": "agy-pro3",
      "home_dir": "~/.gemini-pro3"
    }
  ]
}
```

| Mode | Execution Mechanism |
| :--- | :--- |
| `"host"` | Runs `agy` on the host with `Command::env_clear()`, sanitized allowlist env, and host keyring socket |
| `"toolbox"` | Runs `toolbox run -c <container> /usr/bin/env -i ...` with isolated `HOME` and empty D-Bus |
| `"distrobox"` | Runs `distrobox enter <container> -- /usr/bin/env -i ...` with isolated `HOME` and empty D-Bus |
| `"isolated_home"` | Runs `agy` directly on the host with `Command::env_clear()`, isolated `HOME`, and file-based token |

---

## Security Architecture

- **Memory Safety (`#![forbid(unsafe_code)]`)**: 100% safe Rust across all modules with zero `unsafe` blocks.
- **Zero Network Footprint**: Contains zero networking crates (`std::net`, `reqwest`, `hyper`, and `tokio` are completely absent) and never opens sockets.
- **Zero Direct Credential Access**: Never reads or parses `antigravity-oauth-token` files or system keyrings; only invokes the official `agy` binary's read-only `/usage` command.
- **PATH Shadowing & Binary Ownership Verification**: Resolves `agy` exclusively from canonical paths (`~/.local/bin/agy`, `/usr/local/bin/agy`, `/usr/bin/agy`) and verifies that the binary and its entire parent directory chain are owned by `root` or the current effective UID and are not group/world-writable.
- **Clean-Room Subprocess Isolation**: Spawns subprocesses with `Command::env_clear()`, an empty read-only working directory (`/usr/share/empty`), bounded stdout/stderr pipes (`256 KB`), and process-group timeout reaping (`-PGID`) so untrusted workspace hooks (`.gemini/settings.json`, `.mcp.json`) can never execute.
- **Symlink & Hardlink-Safe Atomic I/O**: Reads and writes cache/config files using `O_NOFOLLOW`, `create_new(true)` (`O_EXCL`), `nlink == 1` verification, and strict `0600`/`0700` permissions.
- **Terminal Escape & Secret Redaction**: Strips ANSI CSI, OSC-52 clipboard hijacking sequences, Unicode BiDi overrides, and C0/C1 control characters while automatically redacting OAuth tokens (`ya29.*`, `1//*`, `Bearer *`), email addresses, and local `$HOME` paths from any error messages.
- **Terms of Service Compliance**: Read-only visibility utility designed for legitimate multi-account workflows with a mandatory minimum polling interval floor (`>= 120s`).

---

## Repository Structure

```text
agy-tui/
├── .gitignore          # Strict secret, build artifact & local audit exclusion rules
├── Cargo.toml          # Crate metadata & minimal dependency list
├── Cargo.lock          # SHA-256 pinned crate checksums
├── install.sh          # Locked release builder (cargo build --release --locked)
├── LICENSE             # MIT License
├── README.md           # Project documentation
└── src/
    ├── main.rs         # Binary entrypoint (#![forbid(unsafe_code)])
    ├── lib.rs          # CLI parser & command dispatch
    ├── security.rs     # Process isolation, env_clear, O_NOFOLLOW I/O & redaction
    ├── profiles.rs     # Zero-config profile discovery & declarative config validator
    ├── models.rs       # Quota & recommendation data structures
    ├── collector.rs    # Parallel thread-scoped collector & single-flight cache
    ├── snapshot.rs     # Instant 24-bit TrueColor CLI snapshot renderer
    └── tui.rs          # Interactive ratatui + crossterm dashboard
```

---

## License

Released under the [MIT License](LICENSE).
