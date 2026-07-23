#!/usr/bin/env bash
#
# =============================================================================
# ReconWorm Installer
#   Original tool by coffeeaddict (tom).
#   Hardening pass by Kairos Lab / Valisthea.
#
# Installs exactly the tools reconworm.sh actually calls (no more, no less).
# Supports apt (Debian/Ubuntu/Kali) and brew (macOS).
# =============================================================================

set -uo pipefail

echo "[*] ReconWorm dependency installation..."

OS="$(uname -s)"
have() { command -v "$1" >/dev/null 2>&1; }

# --- pick a system package manager -------------------------------------------
if [[ "$OS" == "Darwin" ]]; then
    PKG="brew install"
    if ! have brew; then echo "[x] Homebrew required on macOS: https://brew.sh"; exit 1; fi
elif have apt; then
    PKG="sudo apt install -y"
    echo "[*] apt update..."; sudo apt update -y
else
    echo "[!] No apt/brew found. Install system packages manually, Go tools still work."
    PKG=""
fi

pkg_install() { # pkg_install <cmd> <package>
    if have "$1"; then echo "[+] $1 already installed";
    elif [[ -n "$PKG" ]]; then echo "[*] installing $2..."; $PKG "$2" || echo "[!] failed: $2";
    else echo "[!] $1 missing and no package manager"; fi
}

# --- base system deps --------------------------------------------------------
pkg_install git  git
pkg_install curl curl
pkg_install jq   jq

# dig (DNS lookups used by origin discovery)
if ! have dig; then
    if [[ "$OS" == "Darwin" ]]; then brew install bind || true
    else $PKG dnsutils || $PKG bind-tools || true; fi
fi

# coreutils on macOS gives gtimeout + md5sum (the script falls back gracefully,
# but installing it removes the fallbacks).
if [[ "$OS" == "Darwin" ]]; then pkg_install gtimeout coreutils; fi

# --- Go ----------------------------------------------------------------------
if ! have go; then
    echo "[*] installing Go..."
    if [[ "$OS" == "Darwin" ]]; then brew install go; else $PKG golang-go || $PKG golang; fi
fi
if have go; then export PATH="$PATH:$(go env GOPATH)/bin"; fi

install_go_tool() { # install_go_tool <bin> <module>
    if have "$1"; then echo "[+] $1 already installed";
    else echo "[*] installing $1..."; go install -v "$2@latest" || echo "[!] failed: $1"; fi
}

# --- Go recon tools (every one is actually used by reconworm.sh) -------------
install_go_tool subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_go_tool httpx        github.com/projectdiscovery/httpx/cmd/httpx
install_go_tool dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx
install_go_tool naabu        github.com/projectdiscovery/naabu/v2/cmd/naabu
install_go_tool nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_go_tool assetfinder  github.com/tomnomnom/assetfinder
install_go_tool waybackurls  github.com/tomnomnom/waybackurls
install_go_tool gau          github.com/lc/gau/v2/cmd/gau
install_go_tool subjack      github.com/haccer/subjack
install_go_tool gospider     github.com/jaeles-project/gospider

# --- trufflehog (JS/sourcemap secret scanning) -------------------------------
if have trufflehog; then
    echo "[+] trufflehog already installed"
else
    echo "[*] installing trufflehog..."
    # Prefer the reproducible Go build over an unpinned 'curl | sh' of a live branch.
    go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null \
        || echo "[!] install trufflehog manually: https://github.com/trufflesecurity/trufflehog/releases"
fi

# --- s3scanner (S3 bucket recon) ---------------------------------------------
if have s3scanner; then
    echo "[+] s3scanner already installed"
else
    echo "[*] installing s3scanner..."
    go install github.com/sa7mon/s3scanner@latest 2>/dev/null \
        || pipx install s3scanner 2>/dev/null \
        || pip install s3scanner 2>/dev/null \
        || echo "[!] install s3scanner manually: https://github.com/sa7mon/S3Scanner"
fi

# --- nuclei templates --------------------------------------------------------
if have nuclei; then echo "[*] updating nuclei templates..."; nuclei -update-templates -silent 2>/dev/null || true; fi

echo ""
echo "[+] Installation complete."
echo "[+] Make sure the Go bin dir is on your PATH:"
echo "      export PATH=\$PATH:\$(go env GOPATH)/bin"
echo ""
echo "[+] Run:  ./reconworm.sh -d example.com -m full"
