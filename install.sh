#!/usr/bin/env bash
set -euo pipefail

# Quick installer for monux
# Usage: ./install.sh

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust via https://rustup.rs/" >&2
    exit 1
fi

if [ ! -e /dev/uinput ]; then
    echo "warning: /dev/uinput not found. monux requires uinput and evdev kernel modules." >&2
fi

if [ ! -d /dev/input ]; then
    echo "warning: /dev/input not found. monux requires uinput and evdev kernel modules." >&2
fi

# monux runs as a regular user; it needs read/write access to the input devices.
if [ -e /dev/uinput ] && [ ! -r /dev/uinput -o ! -w /dev/uinput ]; then
    cat >&2 <<'EOF'
warning: /dev/uinput is not accessible by your user. Fix it with:
    sudo usermod -aG input $USER
then log out and back in. If /dev/uinput is not group-writable on your
distribution, also add a udev rule, e.g.:
    echo 'SUBSYSTEM=="misc", KERNEL=="uinput", GROUP="input", MODE="0660"' | sudo tee /etc/udev/rules.d/99-monux-uinput.rules
    sudo udevadm control --reload && sudo udevadm trigger
EOF
elif ! id -nG "$USER" | grep -qw input; then
    cat >&2 <<'EOF'
note: your user is not in the 'input' group. If monux fails to open input
devices, run: sudo usermod -aG input $USER  (then log out and back in)
EOF
fi

# Install into ~/.local/bin: present in PATH by default on systemd-based
# distros and in most shell profiles, unlike ~/.cargo/bin.
# Install to a staging dir on the same filesystem first, then move into
# place atomically: a kill mid-'cargo install' would otherwise leave a
# truncated binary in ~/.local/bin.
echo "Installing monux..."
rm -rf "$HOME"/.local/.monux-install-staging.* 2>/dev/null || true
staging=$(mktemp -d "$HOME/.local/.monux-install-staging.XXXXXX")
trap 'rm -rf "$staging"' EXIT
cargo install --locked --path . --root "$staging" --force
mkdir -p "$HOME/.local/bin"
mv -f "$staging/bin/monux" "$HOME/.local/bin/monux"
rm -rf "$staging"
trap - EXIT

# Remove stale copies from previous install locations/names, so they can't
# shadow the new one depending on PATH order.
for stale in "$HOME/.cargo/bin/nikau" "$HOME/.cargo/bin/monux" "$HOME/.local/bin/nikau"; do
    if [ -f "$stale" ]; then
        echo "Removing previous install at $stale"
        rm -f "$stale"
    fi
done

echo "Installed monux to $(which monux 2>/dev/null || echo "$HOME/.local/bin/monux")"

# 'mx' shorthand: a symlink next to the binary (relative target, so the
# atomic binary replacement during updates keeps it valid). Works in every
# shell and in scripts, unlike a shell rc alias. Never overwrite an 'mx'
# that isn't ours.
mx="$HOME/.local/bin/mx"
if [ -L "$mx" ]; then
    target=$(readlink "$mx")
    case "$target" in
        monux|*/monux) ln -sf monux "$mx" ;;
        *) echo "note: $mx points at $target; leaving it alone — the 'mx' alias is unavailable" ;;
    esac
elif [ -e "$mx" ]; then
    echo "note: $mx exists and is not our symlink; leaving it alone — the 'mx' alias is unavailable"
else
    ln -s monux "$mx"
    echo "Alias: mx -> monux"
fi

# Desktop shortcut: 'monux tray' in the app menu runs 'monux gui tray show'
# (with no daemon running it starts a standalone tray). $XDG_DATA_HOME
# honored (absolute paths only, per the base-directory spec), default
# ~/.local/share.
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
case "$data_home" in
    /*) ;;
    *) data_home="$HOME/.local/share" ;;
esac
mkdir -p "$data_home/applications"
cat > "$data_home/applications/monux-tray.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=monux tray
Comment=Show the monux tray indicator (starts it when no daemon is running)
Exec=monux gui tray show
Terminal=false
Categories=Utility;
Icon=input-keyboard
EOF
echo "Desktop shortcut: $data_home/applications/monux-tray.desktop"

# 'sudo monux ...' (e.g. 'sudo monux setup') fails with "command not found"
# because sudo resets PATH to secure_path, which excludes ~/.local/bin.
# /usr/local/bin is in secure_path, so link the binary there too (needs sudo).
if [ ! -e /usr/local/bin/monux ]; then
    if sudo -n true 2>/dev/null || sudo -v; then
        sudo ln -sf "$HOME/.local/bin/monux" /usr/local/bin/monux
        echo "Linked /usr/local/bin/monux -> $HOME/.local/bin/monux (so 'sudo monux' works)"
    else
        echo "note: skipped linking /usr/local/bin/monux; use 'sudo ~/.local/bin/monux <cmd>' with sudo"
    fi
fi
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *)
        cat >&2 <<'EOF'
warning: ~/.local/bin is not in your PATH. Add it with:
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc   # or ~/.bashrc
then restart your shell.
EOF
        ;;
esac

echo
echo "Run server: monux server   (as your user; needs 'input' group + /dev/uinput access)"
echo "Run client: monux client [host]"
echo "Update later with: monux update"
echo
echo "If device permissions aren't set up, run 'monux setup' (elevates via sudo),"
echo "or fall back to: sudo -E monux server"
