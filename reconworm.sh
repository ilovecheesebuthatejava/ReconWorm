#!/bin/bash

# =========================
# ReconWorm CLI Tool
# =========================

VERSION="1.0"

DOMAIN=""
OUTPUT_DIR="output"
MODE="full"

# =========================
# Timeout compatibility (macOS + Linux)
# =========================
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    echo "[!] timeout not found. Install coreutils (brew install coreutils)"
    exit 1
fi

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

    $TIMEOUT_CMD 300 subfinder -d "$DOMAIN" -o "$BASE_DIR/subfinder.txt"
    $TIMEOUT_CMD 300 assetfinder --subs-only "$DOMAIN" >> "$BASE_DIR/assetfinder.txt"

    cat "$BASE_DIR/subfinder.txt" "$BASE_DIR/assetfinder.txt" | sort -u > "$BASE_DIR/subdomains.txt"

    echo "[+] Subdomain enumeration done"
}

# =========================
# HTTP Probing
# =========================
http_probe() {
    echo "[*] Running httpx probes..."

    $TIMEOUT_CMD 300 httpx -l "$BASE_DIR/subdomains.txt" -silent -o "$BASE_DIR/live_hosts.txt"

    $TIMEOUT_CMD 300 httpx -l "$BASE_DIR/subdomains.txt" -title -status-code -tech-detect -follow-redirects -silent \
    -o "$BASE_DIR/http_details.txt"

    httpx -l "$BASE_DIR/live_hosts.txt" -silent -sr | \
    grep -E "s3\.amazonaws\.com|\.s3\." | \
    sort -u > "$BASE_DIR/s3_urls.txt"

    while read -r url; do
        $TIMEOUT_CMD 120 gospider -s "$url" -d 2 -c 10 --js \
        >> "$BASE_DIR/gospider_results.txt"
    done < "$BASE_DIR/live_hosts.txt"

    grep -E "s3\.amazonaws\.com|\.s3\." "$BASE_DIR/gospider_results.txt" | \
    sort -u >> "$BASE_DIR/s3_urls.txt"

    sort -u "$BASE_DIR/s3_urls.txt" -o "$BASE_DIR/s3_urls.txt"

    echo "[+] HTTP probing done"
}

# =========================
# Port Scanning
# =========================
port_scan() {
    echo "[*] Running port scan..."

    PORT_FILE="$BASE_DIR/ports.txt"

    # Ensure live_hosts exists
    if [[ ! -s "$BASE_DIR/live_hosts.txt" ]]; then
        echo "[!] No live hosts found. Skipping port scan."
        return 0
    fi

    # Clean URLs → hostnames for naabu
    cat "$BASE_DIR/live_hosts.txt" | sed 's#https\?://##' > "$BASE_DIR/naabu_targets.txt"

    # Run naabu safely
    cat "$BASE_DIR/live_hosts.txt" | sed -E 's#https?://##' | cut -d/ -f1 | sort -u > "$BASE_DIR/naabu_targets.txt"

$TIMEOUT_CMD 300 naabu -list "$BASE_DIR/naabu_targets.txt" -silent -o "$BASE_DIR/ports.txt"

    echo "[*] Splitting ports..."

    if [[ -f "$PORT_FILE" ]]; then
        grep ":21$" "$PORT_FILE" > "$BASE_DIR/ftp.txt"
        grep ":22$" "$PORT_FILE" > "$BASE_DIR/ssh.txt"
        grep -vE ":(21|22|80|443)$" "$PORT_FILE" > "$BASE_DIR/other_ports.txt"

    else
        echo "[!] No ports found."
    fi

    echo "[+] Port scan complete"
}
# =========================
# Vulnerability Scanning
# =========================
vuln_scan() {
    echo "[*] Running nuclei scan..."

    $TIMEOUT_CMD 600 nuclei -l "$BASE_DIR/live_hosts.txt" -silent -o "$BASE_DIR/nuclei_results.txt"

    echo "[+] Vulnerability scan complete"
}

# =========================
# Subdomain Takeover Check
# =========================
takeover_check() {
    echo "[*] Checking for subdomain takeover..."

    $TIMEOUT_CMD 300 subjack -w "$BASE_DIR/subdomains.txt" -v 2>> "$BASE_DIR/takeovers.txt"
    $TIMEOUT_CMD 300 cat "$BASE_DIR/subfinder.txt" | dnsx -silent -cname | httpx -silent -status-code -title -cname | nuclei -t http/takeovers/ -severity high,critical
    echo "[+] Takeover scan complete"
}

# =========================
# S3 Recon
# =========================
s3_recon() {
    echo "[*] Running S3 recon..."

    BUCKET_FILE="$BASE_DIR/buckets.txt"
    URL_FILE="$BASE_DIR/s3_urls.txt"
    OUTPUT_FILE="$BASE_DIR/s3_results.txt"

    echo "$DOMAIN" > "$BUCKET_FILE"
    echo "dev-$DOMAIN" >> "$BUCKET_FILE"
    echo "prod-$DOMAIN" >> "$BUCKET_FILE"

    if [[ -f "$URL_FILE" ]]; then
        cat "$URL_FILE" | \
        sed -E 's#https?://([^./]+)\.s3\.amazonaws\.com.*#\1#' | \
        sed -E 's#https?://s3\.amazonaws\.com/([^/]+).*#\1#' \
        >> "$BUCKET_FILE"
    fi

    sort -u "$BUCKET_FILE" -o "$BUCKET_FILE"

    $TIMEOUT_CMD 300 s3scanner -bucket-file "$BUCKET_FILE" > "$OUTPUT_FILE"

    echo "[+] S3 scan complete"
}

# =========================
# JS Recon
# =========================
js_recon() {
    echo "[*] Running JS discovery..."

    JS_DIR="$BASE_DIR/js"
    mkdir -p "$JS_DIR"

    WAYBACK_FILE="$JS_DIR/wayback.txt"
    GOSPIDER_FILE="$JS_DIR/gospider.txt"
    JS_URLS_FILE="$JS_DIR/js_urls.txt"

    # -------------------------
    # 1. Passive sources (Wayback + GAU)
    # -------------------------
    echo "[*] Collecting JS from wayback/gau..."

    waybackurls "$DOMAIN" > "$WAYBACK_FILE"
    gau "$DOMAIN" >> "$WAYBACK_FILE"

    grep -E "\.js(\?|$)" "$WAYBACK_FILE" > "$JS_DIR/js_wayback.txt"

    # -------------------------
    # 2. Active crawling (GoSpider)
    # -------------------------
    echo "[*] Crawling live hosts for JS..."

    if [[ -s "$BASE_DIR/live_hosts.txt" ]]; then
        while read -r url; do
            gospider -s "$url" -d 2 -c 10 --js \
            >> "$GOSPIDER_FILE"
        done < "$BASE_DIR/live_hosts.txt"
    else
        echo "[!] No live hosts found, skipping GoSpider"
    fi

    # Extract JS URLs cleanly from GoSpider output
    grep -Eo 'https?://[^ ]+\.js(\?[^ ]*)?' "$GOSPIDER_FILE" \
    > "$JS_DIR/js_gospider.txt"

    # -------------------------
    # 3. Merge + Deduplicate
    # -------------------------
    cat "$JS_DIR/js_wayback.txt" "$JS_DIR/js_gospider.txt" | \
    sort -u > "$JS_URLS_FILE"

    echo "[+] JS URLs collected: $(wc -l < "$JS_URLS_FILE")"

    # -------------------------
    # 4. Fetch JS files (for TruffleHog)
    # -------------------------
    echo "[*] Downloading JS files..."

    mkdir -p "$JS_DIR/files"

    while read -r url; do
        fname=$(echo "$url" | md5)
        curl -s "$url" > "$JS_DIR/files/$fname.js"
    done < "$JS_URLS_FILE"

    echo "[+] JS files downloaded"

    # -------------------------
    # 5. Secret scanning (TruffleHog)
    # -------------------------
    echo "[*] Running TruffleHog..."

    trufflehog filesystem "$JS_DIR/files" > "$JS_DIR/secrets.txt"

    echo "[+] JS recon complete"
}
#############################################
# TRUFFLEHOG JS SECRET SCAN MODULE
#############################################

trufflehog_scan() {

    TOOL_DIR="$BASE_DIR/trufflehog"
    JS_DIR="$TOOL_DIR/js_files"
    RESULTS_FILE="$TOOL_DIR/trufflehog_results.json"
    JS_CLEAN="$TOOL_DIR/js_urls_clean.txt"

    mkdir -p "$TOOL_DIR"
    mkdir -p "$JS_DIR"

    echo "[+] Running TruffleHog on JS assets..."

    # Ensure JS input exists
    if [[ ! -s "$BASE_DIR/js_urls.txt" ]]; then
        echo "[!] No JS URLs found. Skipping TruffleHog."
        return 0
    fi

    # Step 1: dedupe (FULL PATH FIXED)
    sort -u "$BASE_DIR/js_urls.txt" > "$JS_CLEAN"

    # Step 2: download JS files (macOS-safe hashing)
    echo "[+] Downloading JS files..."

    while read -r url; do
        [ -z "$url" ] && continue

        filename=$(echo -n "$url" | shasum | awk '{print $1}')

        curl -sL "$url" -o "$JS_DIR/$filename.js"

    done < "$JS_CLEAN"

    # Step 3: run trufflehog
    echo "[+] Scanning with TruffleHog..."

trufflehog filesystem "$JS_DIR" \
    --json \
    > "$RESULTS_FILE" 2> "$TOOL_DIR/trufflehog_error.log"c
    echo "[+] TruffleHog complete"
    echo "[+] Output: $RESULTS_FILE"


#
# extracting intresing stuff 
#

high_value_analysis() {
    echo "[*] Extracting high-value findings..."

    HV_DIR="$BASE_DIR/high_value"
    mkdir -p "$HV_DIR"

    # -------------------------
    # 1. Non-CDN / Origin IPs
    # -------------------------
    if [[ -f "$BASE_DIR/host_ip.txt" ]]; then
        grep -vE "cloudflare|akamai|fastly" "$BASE_DIR/host_ip.txt" \
        > "$HV_DIR/origin_ips.txt"
    fi

    # -------------------------
    # 2. Sensitive Ports
    # -------------------------
    if [[ -f "$BASE_DIR/ports.txt" ]]; then
        grep -E ":(21|22|3306|5432|6379|27017)$" "$BASE_DIR/ports.txt" \
        > "$HV_DIR/sensitive_ports.txt"
    fi

    # -------------------------
    # 3. Internal IP leaks (from JS)
    # -------------------------
    if [[ -d "$BASE_DIR/js/files" ]]; then
        grep -rE "10\.|172\.16|192\.168" "$BASE_DIR/js/files/" \
        > "$HV_DIR/internal_ips.txt"
    fi

    # -------------------------
    # 4. Interesting subdomains (dev/stage/admin)
    # -------------------------
    if [[ -f "$BASE_DIR/subdomains.txt" ]]; then
        grep -Ei "dev|test|stage|admin|internal|beta" "$BASE_DIR/subdomains.txt" \
        > "$HV_DIR/interesting_subdomains.txt"
    fi

    # -------------------------
    # 5. S3 buckets that actually exist
    # -------------------------
    if [[ -f "$BASE_DIR/s3_results.txt" ]]; then
        grep "exists" "$BASE_DIR/s3_results.txt" \
        > "$HV_DIR/valid_buckets.txt"
    fi

    # -------------------------
    # 6. Potential takeover signals
    # -------------------------
    if [[ -f "$BASE_DIR/takeovers.txt" ]]; then
        grep -Ei "vulnerable|possible|error" "$BASE_DIR/takeovers.txt" \
        > "$HV_DIR/takeover_hits.txt"
    fi

    # -------------------------
    # 7. Secrets (from JS recon)
    # -------------------------
    if [[ -f "$BASE_DIR/js/secrets.txt" ]]; then
        grep -Ei "AKIA|AIza|sk_live|token|secret|password" \
        "$BASE_DIR/js/secrets.txt" \
        > "$HV_DIR/high_value_secrets.txt"
    fi

    # -------------------------
    # 8. Build clean report
    # -------------------------
    REPORT="$HV_DIR/high_value_summary.txt"

    echo "====== High Value Findings ======" > "$REPORT"
    echo "Target: $DOMAIN" >> "$REPORT"
    echo "Date: $(date)" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Origin IPs]" >> "$REPORT"
    [[ -f "$HV_DIR/origin_ips.txt" ]] && head -n 10 "$HV_DIR/origin_ips.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Sensitive Ports]" >> "$REPORT"
    [[ -f "$HV_DIR/sensitive_ports.txt" ]] && head -n 10 "$HV_DIR/sensitive_ports.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Internal IP Leaks]" >> "$REPORT"
    [[ -f "$HV_DIR/internal_ips.txt" ]] && head -n 10 "$HV_DIR/internal_ips.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Interesting Subdomains]" >> "$REPORT"
    [[ -f "$HV_DIR/interesting_subdomains.txt" ]] && head -n 10 "$HV_DIR/interesting_subdomains.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[S3 Buckets]" >> "$REPORT"
    [[ -f "$HV_DIR/valid_buckets.txt" ]] && head -n 10 "$HV_DIR/valid_buckets.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Takeover Signals]" >> "$REPORT"
    [[ -f "$HV_DIR/takeover_hits.txt" ]] && head -n 10 "$HV_DIR/takeover_hits.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Secrets]" >> "$REPORT"
    [[ -f "$HV_DIR/high_value_secrets.txt" ]] && head -n 10 "$HV_DIR/high_value_secrets.txt" >> "$REPORT"

    echo "[+] High-value report saved to $REPORT"
}

# =========================
# Pipeline Controller
# =========================

run_passive() {
    sub_enum
    js_recon
    trufflehog_scan
}

run_active() {
    sub_enum
    http_probe
    port_scan
    js_recon
    trufflehog_scan
}

run_full() {
    sub_enum
    http_probe
    port_scan
    vuln_scan
    takeover_check
    s3_recon
    js_recon
    high_value_analysis  
}
# =========================
# Summary
# =========================
generate_summary() {
    SUMMARY_FILE="$BASE_DIR/summary.txt"

    echo "====== Recon Summary ======" > "$SUMMARY_FILE"
    echo "Target: $DOMAIN" >> "$SUMMARY_FILE"
    echo "Mode: $MODE" >> "$SUMMARY_FILE"
    echo "Date: $(date)" >> "$SUMMARY_FILE"

    echo "Subdomains: $(wc -l < "$BASE_DIR/subdomains.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
    echo "Live hosts: $(wc -l < "$BASE_DIR/live_hosts.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
    echo "Ports: $(wc -l < "$BASE_DIR/ports.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
    echo "Vulns: $(wc -l < "$BASE_DIR/nuclei_results.txt" 2>/dev/null)" >> "$SUMMARY_FILE"
}

# =========================
# Main Execution
# =========================
main() {
    banner

    case "$MODE" in
        passive) run_passive ;;
        active) run_active ;;
        full) run_full ;;
        *) echo "[!] Invalid mode"; usage ;;
    esac

    generate_summary

    echo "[+] Recon complete. Output: $BASE_DIR"
}

main






