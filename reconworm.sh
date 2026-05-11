#!/bin/bash

# =========================
# ReconWorm CLI Tool
# =========================

VERSION="1.0"

DOMAIN=""
OUTPUT_DIR="output"
MODE="full"

# =========================
# Help Menu
# =========================
usage() {
cat << EOF
ReconWorm v$VERSION - Automated Recon CLI Tool

USAGE:
  reconworm -d example.com -o output_dir -m mode

OPTIONS:
  -d  Target domain (required)
  -o  Output directory (default: output)
  -m  Mode: passive | active | full (default: full)
  -h  Show help

MODES:
  passive -> subdomain enumeration only
  active  -> enum + http probing + ports
  full    -> full recon + vuln scanning

EXAMPLE:
  reconworm -d target.com -o results -m full
EOF
exit 1
}

# =========================
# Parse CLI Args
# =========================
while getopts "d:o:m:h" opt; do
  case $opt in
    d) DOMAIN=$OPTARG ;;
    o) OUTPUT_DIR=$OPTARG ;;
    m) MODE=$OPTARG ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "[!] Domain is required"
    usage
fi

# =========================
# Setup Paths
# =========================
BASE_DIR="$OUTPUT_DIR/$DOMAIN"
mkdir -p "$BASE_DIR"

echo "[*] Output directory: $BASE_DIR"
echo "[*] Mode: $MODE"
echo "[*] Target: $DOMAIN"

# =========================
# Banner
# =========================
banner() {
    cat << "EOF"
                                                   /~~\
     ____                                         /'o  |
   .~  | `\             ,-~~~\~-_               ,'  _/'|
   `\_/   /'\         /'`\    \  ~,             |     .'
       `,/'  |      ,'_   |   |   |`\          ,'~~\  |
       |   /`:     |  `\ /~~~~\ /   |        ,'    `.'
        | /'  |     |   ,'      `\  /`|      /'\    /  1.2
        `|   / \_ _/ `\ |         |'   `----\   |  /'
         `./'  | ~ |   ,'         |    |     |  |/'
          `\   |   /  ,'           `\ /      |/~'
            `\/_ /~ _/               `~------'
               ~~~~
 ____                   __        __                     _   ____
|  _ \ ___  ___ ___  _ _\ \      / /__  _ __ _ __ ___   / | |___ \
| |_) / _ \/ __/ _ \| '_ \ \ /\ / / _ \| '__| '_ ` _ \  | |   __) |
|  _ <  __/ (_| (_) | | | \ V  V / (_) | |  | | | | | | | |_ / __/
|_| \_\___|\___\___/|_| |_|\_/\_/ \___/|_|  |_| |_| |_| |_(_)_____|
--------------------------------------------------------------------
      It's a little itty bitty worm that does recon for you :)
               Made with <3 by coffeeaddict (tom)
              ------------------------------
EOF
}


# =========================
# Subdomain Enumeration
# =========================
sub_enum() {
    echo "[*] Running subdomain enumeration..."

    subfinder -d "$DOMAIN" -o "$BASE_DIR/subfinder.txt"
    assetfinder --subs-only "$DOMAIN" >> "$BASE_DIR/assetfinder.txt"

    cat "$BASE_DIR/subfinder.txt" "$BASE_DIR/assetfinder.txt" | sort -u > "$BASE_DIR/subdomains.txt"

    echo "[+] Subdomain enumeration done"
}

# =========================
# HTTP Probing
# =========================
http_probe() {
    echo "[*] Running httpx probes..."

    cat "$BASE_DIR/subdomains.txt" | httpx -silent -o "$BASE_DIR/live_hosts.txt"

    cat "$BASE_DIR/subdomains.txt" | httpx -title -status-code -tech-detect -follow-redirects -silent \
    -o "$BASE_DIR/http_details.txt"

    echo "[+] HTTP probing done"
}

# =========================
# Port Scanning
# =========================
port_scan() {
    echo "[*] Running naabu port scan..."

    cat "$BASE_DIR/subdomains.txt" | naabu -silent -o "$BASE_DIR/ports.txt"

    echo "[+] Port scan complete"
}

# =========================
# Vulnerability Scanning
# =========================
vuln_scan() {
    echo "[*] Running nuclei scan..."

    cat "$BASE_DIR/live_hosts.txt" | nuclei -silent -o "$BASE_DIR/nuclei_results.txt"

    echo "[+] Vulnerability scan complete"
}

# =========================
# Subdomain Takeover Check
# =========================
takeover_check() {
    echo "[*] Checking for subdomain takeover..."

    subjack -w "$BASE_DIR/subdomains.txt" -v 2>> "$BASE_DIR/takeovers.txt"

    echo "[+] Takeover scan complete"
}

# =========================
# JS / Recon Expansion
# =========================
js_recon() {
    echo "[*] Running JS + endpoint discovery..."

    waybackurls "$DOMAIN" | sort -u > "$BASE_DIR/wayback.txt"

    cat "$BASE_DIR/wayback.txt" | grep "\.js$" > "$BASE_DIR/js_urls.txt"

    echo "[+] JS recon complete"
}

# =========================
# Pipeline Controller
# =========================
run_passive() {
    sub_enum
    js_recon
}

run_active() {
    sub_enum
    http_probe
    port_scan
    js_recon
}

run_full() {
    sub_enum
    http_probe
    port_scan
    vuln_scan
    takeover_check
    js_recon
}

# =========================
# Main Execution
# =========================
main() {
    banner

    case "$MODE" in
        passive)
            run_passive
            ;;
        active)
            run_active
            ;;
        full)
            run_full
            ;;
        *)
            echo "[!] Invalid mode: $MODE"
            usage
            ;;
    esac

    echo "[+] Recon complete. Output: $BASE_DIR"
}

main
generate_summary() {
    echo "[*] Generating summary report..."

    SUMMARY_FILE="$BASE_DIR/summary.txt"

    echo "====== Recon Summary ======" > "$SUMMARY_FILE"
    echo "Target: $DOMAIN" >> "$SUMMARY_FILE"
    echo "Mode: $MODE" >> "$SUMMARY_FILE"
    echo "Date: $(date)" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"

    echo "Subdomains: $(wc -l < "$BASE_DIR/subdomains.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
    echo "Live hosts: $(wc -l < "$BASE_DIR/live_hosts.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
    echo "Ports found: $(wc -l < "$BASE_DIR/ports.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
    echo "Vulnerabilities: $(wc -l < "$BASE_DIR/nuclei_results.txt" 2>/dev/null)" >> "$SUMMARY_FILE"

    echo "[+] Summary saved to $SUMMARY_FILE"
}
