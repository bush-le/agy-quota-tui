#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "Error: Refusing to run install.sh as root (UID 0). Run as your normal user." >&2
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"

if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: 'cargo' (Rust toolchain) not found. Install via https://rustup.rs" >&2
    exit 1
fi

if [[ ! -f "${PROJECT_DIR}/Cargo.lock" ]]; then
    echo "Error: Cargo.lock is missing. Refusing to build without locked SHA-256 dependency checksums." >&2
    exit 1
fi

echo "==> [1/2] Building native release binary with locked dependencies (cargo build --release --locked)..."
cargo build --release --locked --manifest-path "${PROJECT_DIR}/Cargo.toml"

echo "==> [2/2] Installing native binary into ${BIN_DIR}..."
if [[ -L "${BIN_DIR}" ]]; then
    echo "Error: ${BIN_DIR} is a symbolic link. Refusing to install." >&2
    exit 1
fi
mkdir -p "${BIN_DIR}"
chmod 700 "${BIN_DIR}" 2>/dev/null || true

rm -f "${BIN_DIR}/agy-top" "${BIN_DIR}/agy-quota"
install -m 700 "${PROJECT_DIR}/target/release/agy-top" "${BIN_DIR}/agy-top"
ln -sf "${BIN_DIR}/agy-top" "${BIN_DIR}/agy-quota"

echo "[OK] Installed native Rust binary successfully!"
echo "   - Run 'agy-top' for the interactive Live TUI Dashboard"
echo "   - Run 'agy-top -s' for an instant 24-bit color terminal snapshot"
