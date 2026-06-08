#!/bin/bash

# =========================
# ReconWorm CLI Tool
# =========================

VERSION="1.0"

DOMAIN=""
OUTPUT_DIR="output"
MODE="full"
JS_TIMEOUT=500

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
# Cloud Origin Discovery
# =========================
origin_discovery() {
    echo "[*] Running cloud origin discovery..."

    ORIGIN_DIR="$BASE_DIR/origin_discovery"
    HOSTS_FILE="$ORIGIN_DIR/hosts.txt"
    CDN_PATTERN="cloudflare|akamai|fastly|cloudfront|edgesuite|edgekey|cdn77|incapsula|imperva|azureedge|trafficmanager|sucuri|stackpath|bunnycdn"

    mkdir -p "$ORIGIN_DIR"

    if [[ ! -s "$BASE_DIR/live_hosts.txt" ]]; then
        echo "[!] No live hosts found. Skipping origin discovery."
        return 0
    fi

    sed -E 's#https?://##' "$BASE_DIR/live_hosts.txt" | \
    cut -d/ -f1 | sort -u > "$HOSTS_FILE"

    : > "$ORIGIN_DIR/host_ips.txt"
    : > "$ORIGIN_DIR/cnames.txt"
    : > "$ORIGIN_DIR/http_headers.txt"
    : > "$ORIGIN_DIR/cdn_hosts.txt"

    while read -r host; do
        [ -z "$host" ] && continue

        dig +short A "$host" 2>/dev/null | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        while read -r ip; do
            echo "$host $ip"
        done >> "$ORIGIN_DIR/host_ips.txt"

        cname=$(dig +short CNAME "$host" 2>/dev/null)
        if [[ -n "$cname" ]]; then
            echo "$host $cname" >> "$ORIGIN_DIR/cnames.txt"
            echo "$cname" | grep -Eiq "$CDN_PATTERN" && echo "$host" >> "$ORIGIN_DIR/cdn_hosts.txt"
        fi

        headers=$($TIMEOUT_CMD 20 curl -skI --max-time 15 "https://$host" 2>/dev/null)
        if [[ -z "$headers" ]]; then
            headers=$($TIMEOUT_CMD 20 curl -skI --max-time 15 "http://$host" 2>/dev/null)
        fi

        if [[ -n "$headers" ]]; then
            {
                echo "### $host"
                echo "$headers"
                echo ""
            } >> "$ORIGIN_DIR/http_headers.txt"

            echo "$headers" | grep -Eiq "$CDN_PATTERN|cdn|waf|x-cache|cf-ray|x-served-by" && \
            echo "$host" >> "$ORIGIN_DIR/cdn_hosts.txt"
        fi
    done < "$HOSTS_FILE"

    sort -u "$ORIGIN_DIR/cdn_hosts.txt" -o "$ORIGIN_DIR/cdn_hosts.txt"
    comm -23 "$HOSTS_FILE" "$ORIGIN_DIR/cdn_hosts.txt" > "$ORIGIN_DIR/non_cdn_hosts.txt"

    : > "$ORIGIN_DIR/non_cdn_host_ips.txt"
    while read -r host; do
        [ -z "$host" ] && continue
        awk -v host="$host" '$1 == host {print}' "$ORIGIN_DIR/host_ips.txt" >> "$ORIGIN_DIR/non_cdn_host_ips.txt"
    done < "$ORIGIN_DIR/non_cdn_hosts.txt"

    grep -Ei 'origin|direct|staging|stage|dev|test|admin|internal|backend|api' \
    "$ORIGIN_DIR/non_cdn_host_ips.txt" > "$ORIGIN_DIR/possible_origins.txt" 2>/dev/null

    echo "[+] Origin discovery complete"
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

    $TIMEOUT_CMD "$JS_TIMEOUT" waybackurls "$DOMAIN" > "$WAYBACK_FILE"
    $TIMEOUT_CMD "$JS_TIMEOUT" gau "$DOMAIN" >> "$WAYBACK_FILE"

    grep -E "\.js(\?|$)" "$WAYBACK_FILE" > "$JS_DIR/js_wayback.txt"

    # -------------------------
    # 2. Active crawling (GoSpider)
    # -------------------------
    echo "[*] Crawling live hosts for JS..."

    if [[ -s "$BASE_DIR/live_hosts.txt" ]]; then
        while read -r url; do
            $TIMEOUT_CMD "$JS_TIMEOUT" gospider -s "$url" -d 2 -c 10 --js \
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

    $TIMEOUT_CMD "$JS_TIMEOUT" bash -c '
        js_urls_file=$1
        js_files_dir=$2

        while read -r url; do
            fname=$(echo "$url" | md5)
            curl -s "$url" > "$js_files_dir/$fname.js"
        done < "$js_urls_file"
    ' _ "$JS_URLS_FILE" "$JS_DIR/files"

    echo "[+] JS files downloaded"

    # -------------------------
    # 5. Secret scanning (TruffleHog)
    # -------------------------
    echo "[*] Running TruffleHog..."

    $TIMEOUT_CMD "$JS_TIMEOUT" trufflehog filesystem "$JS_DIR/files" > "$JS_DIR/secrets.txt"

    echo "[+] JS recon complete"
}

# =========================
# Open Redirect Candidate Finder
# =========================
open_redirect_finder() {
    echo "[*] Finding GET-based open redirect candidates..."

    REDIRECT_DIR="$BASE_DIR/open_redirects"
    URL_SOURCE_FILE="$REDIRECT_DIR/all_urls.txt"
    CANDIDATES_FILE="$REDIRECT_DIR/open_redirect_candidates.txt"
    PARAM_NAMES_FILE="$REDIRECT_DIR/redirect_param_names.txt"

    mkdir -p "$REDIRECT_DIR"
    : > "$URL_SOURCE_FILE"
    : > "$CANDIDATES_FILE"
    : > "$PARAM_NAMES_FILE"

    [[ -f "$BASE_DIR/js/wayback.txt" ]] && cat "$BASE_DIR/js/wayback.txt" >> "$URL_SOURCE_FILE"
    [[ -f "$BASE_DIR/js/js_urls.txt" ]] && cat "$BASE_DIR/js/js_urls.txt" >> "$URL_SOURCE_FILE"
    [[ -f "$BASE_DIR/gospider_results.txt" ]] && grep -Eo 'https?://[^ ]+' "$BASE_DIR/gospider_results.txt" >> "$URL_SOURCE_FILE"
    [[ -f "$BASE_DIR/http_details.txt" ]] && grep -Eo 'https?://[^ ]+' "$BASE_DIR/http_details.txt" >> "$URL_SOURCE_FILE"

    if [[ ! -s "$URL_SOURCE_FILE" ]]; then
        echo "[!] No URL sources found. Skipping open redirect finder."
        return 0
    fi

    sort -u "$URL_SOURCE_FILE" -o "$URL_SOURCE_FILE"

    grep -Ei '(\?|&)(next|url|target|redirect|redirect_uri|redirect_url|return|returnurl|return_url|continue|continueurl|continue_url|callback|callback_url|dest|destination|to|r|u|uri|path|goto|go|out|view|link)=' \
    "$URL_SOURCE_FILE" | sort -u > "$CANDIDATES_FILE"

    grep -Eio '(\?|&)(next|url|target|redirect|redirect_uri|redirect_url|return|returnurl|return_url|continue|continueurl|continue_url|callback|callback_url|dest|destination|to|r|u|uri|path|goto|go|out|view|link)=' \
    "$CANDIDATES_FILE" | sed -E 's/^[?&]//; s/=$//' | sort -u > "$PARAM_NAMES_FILE"

    echo "[+] Open redirect candidates saved to $CANDIDATES_FILE"
}

# =========================
# Open Redirect Validation
# =========================
open_redirect_scan() {
    echo "[*] Validating open redirect candidates with nuclei..."

    REDIRECT_DIR="$BASE_DIR/open_redirects"
    CANDIDATES_FILE="$REDIRECT_DIR/open_redirect_candidates.txt"
    RESULTS_FILE="$REDIRECT_DIR/nuclei_open_redirect_results.txt"

    if [[ ! -s "$CANDIDATES_FILE" ]]; then
        echo "[!] No open redirect candidates found. Skipping validation."
        return 0
    fi

    $TIMEOUT_CMD 300 nuclei -l "$CANDIDATES_FILE" -tags redirect -silent -o "$RESULTS_FILE"

    echo "[+] Open redirect validation saved to $RESULTS_FILE"
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
    if [[ ! -s "$BASE_DIR/js/js_urls.txt" ]]; then
        echo "[!] No JS URLs found. Skipping TruffleHog."
        return 0
    fi

    # Step 1: dedupe (FULL PATH FIXED)
    sort -u "$BASE_DIR/js/js_urls.txt" > "$JS_CLEAN"

    # Step 2: download JS files (macOS-safe hashing)
    echo "[+] Downloading JS files..."

    $TIMEOUT_CMD "$JS_TIMEOUT" bash -c '
        js_clean=$1
        js_files_dir=$2

        while read -r url; do
            [ -z "$url" ] && continue

            filename=$(echo -n "$url" | shasum | cut -d " " -f 1)

            curl -sL "$url" -o "$js_files_dir/$filename.js"

        done < "$js_clean"
    ' _ "$JS_CLEAN" "$JS_DIR"

    # Step 3: run trufflehog
    echo "[+] Scanning with TruffleHog..."

    $TIMEOUT_CMD "$JS_TIMEOUT" trufflehog filesystem "$JS_DIR" \
    --json \
    > "$RESULTS_FILE" 2> "$TOOL_DIR/trufflehog_error.log"
    echo "[+] TruffleHog complete"
    echo "[+] Output: $RESULTS_FILE"
}

# =========================
# Sourcemap Recon
# =========================
sourcemap_recon() {
    echo "[*] Running sourcemap recon..."

    SM_DIR="$BASE_DIR/sourcemaps"
    MAP_FILES_DIR="$SM_DIR/files"
    JS_URLS_FILE="$BASE_DIR/js/js_urls.txt"
    MAP_URLS_FILE="$SM_DIR/sourcemap_urls.txt"
    MAP_CONTENT_FILE="$SM_DIR/sourcemap_content.txt"

    mkdir -p "$MAP_FILES_DIR"

    if [[ ! -s "$JS_URLS_FILE" ]]; then
        echo "[!] No JS URLs found. Skipping sourcemap recon."
        return 0
    fi

    # Start with the most common sourcemap location: app.js -> app.js.map
    sed 's/$/.map/' "$JS_URLS_FILE" > "$MAP_URLS_FILE"

    # Add sourcemap URLs explicitly referenced inside downloaded JS files.
    if [[ -d "$BASE_DIR/js/files" ]]; then
        grep -rhoE 'sourceMappingURL=[^[:space:]]+' "$BASE_DIR/js/files" 2>/dev/null | \
        sed 's/sourceMappingURL=//' | \
        grep -E '^https?://' >> "$MAP_URLS_FILE"
    fi

    sort -u "$MAP_URLS_FILE" -o "$MAP_URLS_FILE"

    echo "[*] Downloading sourcemaps..."

    $TIMEOUT_CMD "$JS_TIMEOUT" bash -c '
        map_urls_file=$1
        map_files_dir=$2

        while read -r url; do
            [ -z "$url" ] && continue
            filename=$(echo -n "$url" | shasum | cut -d " " -f 1)
            curl -sLf "$url" -o "$map_files_dir/$filename.map"
        done < "$map_urls_file"
    ' _ "$MAP_URLS_FILE" "$MAP_FILES_DIR"

    echo "[*] Extracting sourcemap findings..."

    if command -v jq >/dev/null 2>&1; then
        find "$MAP_FILES_DIR" -type f -name '*.map' -exec jq -r '.sources[]?, .sourcesContent[]?' {} + \
        > "$MAP_CONTENT_FILE" 2>/dev/null
    else
        cat "$MAP_FILES_DIR"/*.map > "$MAP_CONTENT_FILE" 2>/dev/null
    fi

    grep -rhoE 'https?://[^"'\'' )]+' "$MAP_FILES_DIR" "$MAP_CONTENT_FILE" \
    > "$SM_DIR/urls.txt" 2>/dev/null

    grep -rhoE '(/[A-Za-z0-9._-]+)+/?' "$MAP_CONTENT_FILE" | \
    grep -Ei 'api|admin|auth|oauth|graphql|upload|debug|internal|token|callback' \
    > "$SM_DIR/api_routes.txt" 2>/dev/null

    grep -rhoE '([A-Za-z0-9_-]+\.)+(internal|local|corp|lan|dev|stage|staging|test)' \
    "$MAP_FILES_DIR" "$MAP_CONTENT_FILE" > "$SM_DIR/internal_hosts.txt" 2>/dev/null

    grep -rhoEi 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]+|token|secret|password|api[_-]?key' \
    "$MAP_FILES_DIR" "$MAP_CONTENT_FILE" > "$SM_DIR/secret_signals.txt" 2>/dev/null

    grep -rhoE '"sources"[[:space:]]*:[^]]+' "$MAP_FILES_DIR" \
    > "$SM_DIR/source_paths_raw.txt" 2>/dev/null

    $TIMEOUT_CMD "$JS_TIMEOUT" trufflehog filesystem "$MAP_FILES_DIR" \
    > "$SM_DIR/trufflehog_secrets.txt" 2>/dev/null

    sort -u "$SM_DIR/urls.txt" -o "$SM_DIR/urls.txt" 2>/dev/null
    sort -u "$SM_DIR/api_routes.txt" -o "$SM_DIR/api_routes.txt" 2>/dev/null
    sort -u "$SM_DIR/internal_hosts.txt" -o "$SM_DIR/internal_hosts.txt" 2>/dev/null
    sort -u "$SM_DIR/secret_signals.txt" -o "$SM_DIR/secret_signals.txt" 2>/dev/null
    sort -u "$SM_DIR/source_paths_raw.txt" -o "$SM_DIR/source_paths_raw.txt" 2>/dev/null

    echo "[+] Sourcemap recon complete"
}


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
    # 8. Sourcemap findings
    # -------------------------
    if [[ -d "$BASE_DIR/sourcemaps" ]]; then
        [[ -f "$BASE_DIR/sourcemaps/api_routes.txt" ]] && cp "$BASE_DIR/sourcemaps/api_routes.txt" "$HV_DIR/sourcemap_api_routes.txt"
        [[ -f "$BASE_DIR/sourcemaps/internal_hosts.txt" ]] && cp "$BASE_DIR/sourcemaps/internal_hosts.txt" "$HV_DIR/sourcemap_internal_hosts.txt"
        [[ -f "$BASE_DIR/sourcemaps/secret_signals.txt" ]] && cp "$BASE_DIR/sourcemaps/secret_signals.txt" "$HV_DIR/sourcemap_secret_signals.txt"
        [[ -f "$BASE_DIR/sourcemaps/trufflehog_secrets.txt" ]] && cp "$BASE_DIR/sourcemaps/trufflehog_secrets.txt" "$HV_DIR/sourcemap_trufflehog_secrets.txt"
    fi

    # -------------------------
    # 9. Cloud origin findings
    # -------------------------
    if [[ -d "$BASE_DIR/origin_discovery" ]]; then
        [[ -f "$BASE_DIR/origin_discovery/possible_origins.txt" ]] && cp "$BASE_DIR/origin_discovery/possible_origins.txt" "$HV_DIR/possible_origins.txt"
        [[ -f "$BASE_DIR/origin_discovery/non_cdn_host_ips.txt" ]] && cp "$BASE_DIR/origin_discovery/non_cdn_host_ips.txt" "$HV_DIR/non_cdn_host_ips.txt"
    fi

    # -------------------------
    # 10. Open redirect candidates
    # -------------------------
    if [[ -d "$BASE_DIR/open_redirects" ]]; then
        [[ -f "$BASE_DIR/open_redirects/open_redirect_candidates.txt" ]] && cp "$BASE_DIR/open_redirects/open_redirect_candidates.txt" "$HV_DIR/open_redirect_candidates.txt"
        [[ -f "$BASE_DIR/open_redirects/redirect_param_names.txt" ]] && cp "$BASE_DIR/open_redirects/redirect_param_names.txt" "$HV_DIR/redirect_param_names.txt"
        [[ -f "$BASE_DIR/open_redirects/nuclei_open_redirect_results.txt" ]] && cp "$BASE_DIR/open_redirects/nuclei_open_redirect_results.txt" "$HV_DIR/open_redirect_nuclei_results.txt"
    fi

    # -------------------------
    # 11. Build clean report
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
    echo "" >> "$REPORT"

    echo "[Sourcemap API Routes]" >> "$REPORT"
    [[ -f "$HV_DIR/sourcemap_api_routes.txt" ]] && head -n 10 "$HV_DIR/sourcemap_api_routes.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Sourcemap Internal Hosts]" >> "$REPORT"
    [[ -f "$HV_DIR/sourcemap_internal_hosts.txt" ]] && head -n 10 "$HV_DIR/sourcemap_internal_hosts.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Sourcemap Secret Signals]" >> "$REPORT"
    [[ -f "$HV_DIR/sourcemap_secret_signals.txt" ]] && head -n 10 "$HV_DIR/sourcemap_secret_signals.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Sourcemap TruffleHog Secrets]" >> "$REPORT"
    [[ -f "$HV_DIR/sourcemap_trufflehog_secrets.txt" ]] && head -n 10 "$HV_DIR/sourcemap_trufflehog_secrets.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Possible Origin Hosts]" >> "$REPORT"
    [[ -f "$HV_DIR/possible_origins.txt" ]] && head -n 10 "$HV_DIR/possible_origins.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Non-CDN Host IPs]" >> "$REPORT"
    [[ -f "$HV_DIR/non_cdn_host_ips.txt" ]] && head -n 10 "$HV_DIR/non_cdn_host_ips.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Open Redirect Candidates]" >> "$REPORT"
    [[ -f "$HV_DIR/open_redirect_candidates.txt" ]] && head -n 10 "$HV_DIR/open_redirect_candidates.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Redirect Parameter Names]" >> "$REPORT"
    [[ -f "$HV_DIR/redirect_param_names.txt" ]] && head -n 20 "$HV_DIR/redirect_param_names.txt" >> "$REPORT"
    echo "" >> "$REPORT"

    echo "[Open Redirect Nuclei Results]" >> "$REPORT"
    [[ -f "$HV_DIR/open_redirect_nuclei_results.txt" ]] && head -n 10 "$HV_DIR/open_redirect_nuclei_results.txt" >> "$REPORT"

    echo "[+] High-value report saved to $REPORT"
}

# =========================
# Pipeline Controller
# =========================

run_passive() {
    sub_enum
    js_recon
    open_redirect_finder
    sourcemap_recon
    trufflehog_scan
}

run_active() {
    sub_enum
    http_probe
    origin_discovery
    port_scan
    js_recon
    open_redirect_finder
    open_redirect_scan
    sourcemap_recon
    trufflehog_scan
}

run_full() {
    sub_enum
    http_probe
    origin_discovery
    port_scan
    vuln_scan
    takeover_check
    s3_recon
    js_recon
    open_redirect_finder
    open_redirect_scan
    sourcemap_recon
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






