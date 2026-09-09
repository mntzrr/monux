#!/usr/bin/env bash
set -euo pipefail

# Quick installer for monux
# Usage: ./install.sh
#
# Linux: sets up the client+server machine (checks uinput access, installs
#        the binary, tray shortcut, sudo-PATH link).
# macOS: sets up a client machine (installs the binary, creates a stable
#        code-signing identity so rebuilds keep the Accessibility grant,
#        and bootstraps the TCC permission prompt + verification).

os=$(uname -s)

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust via https://rustup.rs/" >&2
    exit 1
fi

# The dependency tree has an MSRV, and the resolver's failure ("rustc X is
# not supported by the following packages: ...") gives no hint that the fix
# is a toolchain upgrade. Check up front; keep the floor in sync with the
# crates pinned in Cargo.lock.
min_rustc_major=1
min_rustc_minor=88
if rustc_ver=$(rustc --version 2>/dev/null); then
    rustc_ver=${rustc_ver#rustc }          # "1.86.0 (Homebrew)"
    rustc_ver=${rustc_ver%% *}             # "1.86.0"
    rustc_major=${rustc_ver%%.*}           # "1"
    rustc_minor=${rustc_ver#*.}            # "86.0"
    rustc_minor=${rustc_minor%%.*}         # "86"
    if [ "$rustc_major" -lt "$min_rustc_major" ] || \
       { [ "$rustc_major" -eq "$min_rustc_major" ] && [ "$rustc_minor" -lt "$min_rustc_minor" ]; }; then
        cat >&2 <<EOF
error: rustc $rustc_ver is too old; building monux needs >= $min_rustc_major.$min_rustc_minor.
    Upgrade with rustup (https://rustup.rs/), or with Homebrew: brew upgrade rust
EOF
        exit 1
    fi
fi

if [ "$os" = "Darwin" ]; then
    # The Xcode command line tools provide the C toolchain that ring/zstd
    # (TLS, compression) build with.
    if ! xcode-select -p >/dev/null 2>&1; then
        cat >&2 <<'EOF'
error: Xcode command line tools are not installed. Run:
    xcode-select --install
and wait for the installer to finish (GUI dialog), then rerun ./install.sh
EOF
        exit 1
    fi
else
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

if [ "$os" = "Darwin" ]; then
    # ------------------------------------------------------------------
    # macOS: stable code-signing identity.
    #
    # The Accessibility (TCC) grant keys on the binary's code signature.
    # Cargo ad-hoc-signs every build with a fresh hash, so without a stable
    # identity each rebuild would silently lose the grant and input
    # injection would just stop. A self-signed identity re-applied after
    # each build keeps the grant valid. (-T pre-authorizes codesign to use
    # the key, so no keychain prompt on every build.)
    # ------------------------------------------------------------------
    sign_identity="monux-code-signing"
    if ! security find-identity -v -p codesigning 2>/dev/null | grep -q "$sign_identity"; then
        echo "Creating a self-signed code-signing identity ($sign_identity)..."
        tmp=$(mktemp -d)
        trap 'rm -rf "$tmp"' EXIT
        cat > "$tmp/monux.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=monux-code-signing
[v3]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
EOF
        # The config-file route (not -addext): macOS ships LibreSSL, whose
        # openssl does not support -addext.
        # PKCS#12: OpenSSL 3.x defaults (AES + PBKDF2 MAC) are rejected by
        # 'security import' with "MAC verification failed" — and Homebrew's
        # OpenSSL is first in PATH on many dev machines. -legacy switches to
        # the old algorithms; LibreSSL predates the flag and already exports
        # legacy-compatible formats, so only flag OpenSSL 3+.
        pkcs12_legacy=""
        case "$(openssl version 2>/dev/null)" in
            "OpenSSL 3"*) pkcs12_legacy="-legacy" ;;
        esac
        if openssl req -x509 -newkey rsa:2048 -keyout "$tmp/key.pem" -out "$tmp/cert.pem" \
                -days 3650 -nodes -config "$tmp/monux.cnf" >/dev/null 2>&1 \
            && openssl pkcs12 -export $pkcs12_legacy -out "$tmp/monux.p12" -inkey "$tmp/key.pem" \
                -in "$tmp/cert.pem" -passout pass:monux-install >/dev/null 2>&1 \
            && security import "$tmp/monux.p12" \
                -k "$HOME/Library/Keychains/login.keychain-db" \
                -P monux-install -T /usr/bin/codesign >/dev/null 2>&1; then
            echo "Identity created in the login keychain."
            # Trust the self-signed cert, or the identity fails
            # 'security find-identity -v' validation (the rerun check above)
            # and gets re-created on every rerun. macOS asks for
            # authorization with a dialog; declining only costs the rerun
            # check — the identity still signs.
            if ! security add-trusted-cert -r trustRoot \
                    -k "$HOME/Library/Keychains/login.keychain-db" \
                    "$tmp/cert.pem" >/dev/null 2>&1; then
                echo "note: could not mark the certificate trusted; the identity still signs," >&2
                echo "      but 'security find-identity -v' won't list it." >&2
            fi
        else
            echo "warning: could not create the signing identity; using ad-hoc signing instead." >&2
            echo "         Every rebuild will need the Accessibility grant re-done (remove and" >&2
            echo "         re-add monux under Privacy & Security -> Accessibility)." >&2
            sign_identity="-"
        fi
        rm -rf "$tmp"
        trap - EXIT
    fi
    if [ "$sign_identity" != "-" ]; then
        if codesign --force -s "$sign_identity" "$HOME/.local/bin/monux" >/dev/null 2>&1; then
            echo "Binary signed with $sign_identity (grant survives rebuilds)"
        else
            echo "warning: codesign failed; the binary is ad-hoc signed, and every rebuild" >&2
            echo "         will need the Accessibility grant re-done." >&2
            sign_identity="-"
        fi
    fi

    # ------------------------------------------------------------------
    # macOS: the Accessibility (TCC) grant.
    #
    # The toggle itself cannot be scripted — that is the point of TCC — but
    # everything around it can: a probe client run pops the system dialog
    # and registers monux in the Accessibility list, the right settings
    # pane opens for the one manual toggle, and a second probe verifies it.
    # ------------------------------------------------------------------
    monux_bin="$HOME/.local/bin/monux"
    tcc_probe() {
        # Until granted, a client run exits immediately with the grant
        # instructions (the TCC check runs before any networking). Once
        # granted it reaches the connection loop — still alive after the
        # wait means the grant is in effect. The unreachable 127.0.0.1:1
        # target keeps that loop from ever connecting to anything real.
        local out
        out=$(mktemp)
        "$monux_bin" client 127.0.0.1:1 >"$out" 2>&1 &
        local pid=$!
        sleep 3
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            rm -f "$out"
            return 0
        fi
        wait "$pid" 2>/dev/null || true
        # Exited: not granted. The bail message mentions Accessibility; a
        # different exit is unexpected and worth showing the user.
        if ! grep -qi "accessibility" "$out"; then
            echo "note: the client exited unexpectedly:" >&2
            sed 's/^/    /' "$out" >&2
        fi
        rm -f "$out"
        return 1
    }

    if pgrep -f '(monux|mx) client' >/dev/null 2>&1; then
        # A running daemon both proves the grant and owns the single-instance
        # lock the probe would take over (killing it) — so don't probe.
        echo "note: a monux client daemon is running; skipping the Accessibility check"
    elif tcc_probe; then
        echo "Accessibility permission: already granted."
    else
        echo
        echo "monux needs the Accessibility permission to inject keyboard and mouse"
        echo "input; the system dialog should have appeared (or will on the next run)."
        open "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility" 2>/dev/null || true
        echo "Enable monux under Privacy & Security -> Accessibility."
        printf "Press Enter once it is toggled on..."
        read -r _
        if tcc_probe; then
            echo "Accessibility permission: verified."
        else
            echo "warning: the permission still does not apply — input injection will not" >&2
            echo "         work. Check the list entry matches $monux_bin, re-toggle it, and" >&2
            echo "         verify later with: monux client <server>" >&2
        fi
    fi

    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *)
            cat >&2 <<'EOF'
warning: ~/.local/bin is not in your PATH. Add it with:
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
then restart your shell.
EOF
            ;;
    esac

    echo
    echo "Run client: monux client [host]   (this Mac is a client; the server runs on Linux)"
    if [ "$sign_identity" != "-" ]; then
        echo
        echo "note: after rebuilding or 'monux update', re-sign the binary or the"
        echo "      Accessibility grant stops applying:"
        echo "          codesign --force -s $sign_identity ~/.local/bin/monux"
    fi
    exit 0
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
