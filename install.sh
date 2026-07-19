#!/usr/bin/env bash
set -euo pipefail

# Quick installer for nikau
# Usage: ./install.sh

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust via https://rustup.rs/" >&2
    exit 1
fi

if [ ! -e /dev/uinput ]; then
    echo "warning: /dev/uinput not found. nikau requires uinput and evdev kernel modules." >&2
fi

if [ ! -d /dev/input ]; then
    echo "warning: /dev/input not found. nikau requires uinput and evdev kernel modules." >&2
fi

echo "Installing nikau..."
cargo install --path . --force

echo "Installed nikau to $(which nikau)"
echo
echo "Run server: sudo nikau server"
echo "Run client: sudo nikau client [host]"
