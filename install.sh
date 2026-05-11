#!/bin/bash

# =========================
# ReconWorm Installer
# =========================

echo "[*] Starting ReconWorm dependency installation..."

# Detect OS
OS="$(uname -s)"

# =========================
# Helper function
# =========================
install_if_missing() {
    if ! command -v $1 &> /dev/null; then
        echo "[*] Installing $1..."
        $2
    else
        echo "[+] $1 already installed"
    fi
}

# =========================
# Update system (Linux only)
# =========================
if [[ "$OS" == "Linux" ]]; then
    echo "[*] Updating system packages..."
    sudo apt update -y
fi

# =========================
# Core dependencies
# =========================

install_if_missing "git" "sudo apt install git -y"
install_if_missing "curl" "sudo apt install curl -y"
install_if_missing "wget" "sudo apt install wget -y"

# =========================
# Go installation check (required for most tools)
# =========================
if ! command -v go &> /dev/null; then
    echo "[*] Installing Go..."
    sudo apt install golang -y
else
    echo "[+] Go already installed"
fi

export PATH=$PATH:$(go env GOPATH)/bin

# =========================
# Install recon tools (ProjectDiscovery suite)
# =========================

install_go_tool() {
    TOOL=$1
    REPO=$2

    if ! command -v $TOOL &> /dev/null; then
        echo "[*] Installing $TOOL..."
        go install -v $REPO@latest
    else
        echo "[+] $TOOL already installed"
    fi
}

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"

# =========================
# Additional recon tools
# =========================

install_if_missing "assetfinder" "go install github.com/tomnomnom/assetfinder@latest"
install_if_missing "amass" "sudo apt install amass -y"
install_if_missing "subjack" "go install github.com/haccer/subjack@latest"
install_if_missing "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"
install_if_missing "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"
install_if_missing "anew" "go install github.com/tomnomnom/anew@latest"

# =========================
# Optional tools
# =========================

install_if_missing "jq" "sudo apt install jq -y"
install_if_missing "gitgraber" "pip install gitgraber"

# =========================
# Final message
# =========================

echo ""
echo "[+] Installation complete!"
echo "[+] Make sure Go bin is in PATH:"
echo "    export PATH=\$PATH:\$(go env GOPATH)/bin"
echo ""
echo "[+] You can now run ReconWorm:"
echo "    ./reconworm.sh -d example.com -m full"
