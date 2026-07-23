#!/usr/bin/env bash
#
# =============================================================================
# ReconWorm - Automated Recon CLI Tool
#
# Original tool by coffeeaddict (tom)  -  github.com/ilovecheesebuthatejava
# Hardening pass (v2.0) by Kairos Lab / Valisthea  -  github.com/Valisthea
#
# Only run this against targets you are authorised to test (bug bounty scope or
# a signed pentest RoE). Active/full modes are LOUD. Respect the program rules.
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

VERSION="2.0"

# ---- Defaults ---------------------------------------------------------------
DOMAIN=""
OUTPUT_DIR="output"
MODE="full"
THREADS=20
JS_TIMEOUT=500
SCOPE_REGEX=""            # in-scope host regex; default derived from DOMAIN
EXCLUDE_REGEX=""          # out-of-scope host regex (kills matches)
RESUME="false"           # skip a module if its main output already exists
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_RL="${NUCLEI_RL:-150}"

trap 'log warn "interrupted"; exit 130' INT

# =============================================================================
# Helpers
# =============================================================================
log() {
    # log <level> <message>   level: info|ok|warn|skip|err
    local level="$1"; shift
    case "$level" in
        info) printf '[*] %s\n' "$*" ;;
        ok)   printf '[+] %s\n' "$*" ;;
        warn) printf '[!] %s\n' "$*" >&2 ;;
        skip) printf '[~] %s\n' "$*" ;;
        err)  printf '[x] %s\n' "$*" >&2 ;;
        *)    printf '%s\n' "$*" ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# Line count that is safe on a missing file (a bare `wc -l < missing` leaks a
# shell redirection error before 2>/dev/null can apply).
count() {
    if [[ -f "$1" ]]; then wc -l < "$1" 2>/dev/null | tr -d ' '; else echo 0; fi
}

# Portable content hash for filenames (Linux md5sum / macOS shasum / fallback).
hash_url() {
    if command -v md5sum >/dev/null 2>&1; then
        printf '%s' "$1" | md5sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum | awk '{print $1}'
    else
        printf '%s' "$1" | sha1sum | awk '{print $1}'
    fi
}
export -f hash_url

# timeout | gtimeout (coreutils on macOS), or a transparent no-op wrapper.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    log warn "timeout/gtimeout not found (install coreutils). Running without per-tool timeouts."
    TIMEOUT_CMD=""
fi
tmo() { # tmo <seconds> <cmd...>
    local secs="$1"; shift
    if [[ -n "$TIMEOUT_CMD" ]]; then "$TIMEOUT_CMD" "$secs" "$@"; else "$@"; fi
}

# Keep only in-scope hosts, then drop out-of-scope ones. Reads stdin, writes stdout.
scope_filter() {
    if [[ -n "$EXCLUDE_REGEX" ]]; then
        grep -Ei "$SCOPE_REGEX" | grep -Eiv "$EXCLUDE_REGEX"
    else
        grep -Ei "$SCOPE_REGEX"
    fi
}

# URL-aware scope: extract the host from each URL and keep the URL only if that
# host passes scope_filter. Untrusted URLs (crawl/wayback/sourceMappingURL) MUST
# go through this, never the bare-host scope_filter (a URL never ends in the host).
url_scope_filter() {
    local u host
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        host="${u#*://}"; host="${host%%/*}"; host="${host##*@}"; host="${host%%:*}"; host="${host%%\?*}"
        if printf '%s
' "$host" | scope_filter >/dev/null 2>&1; then
            printf '%s
' "$u"
        fi
    done
}

# Defence-in-depth: drop URLs pointing at loopback / RFC1918 / link-local / cloud
# metadata, so a broad -s can never be turned into an SSRF via crafted content.
drop_ssrf_hosts() {
    grep -Eiv '://(\[?::1\]?|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|localhost([:/]|$)|metadata[.:/])' || true
}

# Resume gate: return 0 (skip) if RESUME and the output already has content.
resume_skip() {
    if [[ "$RESUME" == "true" && -s "$1" ]]; then
        log skip "resume: keeping existing $(basename "$1")"
        return 0
    fi
    return 1
}

REQUIRED_TOOLS=(subfinder assetfinder dnsx httpx naabu nuclei gospider \
                waybackurls gau trufflehog s3scanner subjack dig curl jq)

preflight() {
    local miss=() t
    for t in "${REQUIRED_TOOLS[@]}"; do have "$t" || miss+=("$t"); done
    if ((${#miss[@]})); then
        ( IFS=' '; log warn "missing tools (modules needing them are skipped, not fatal): ${miss[*]}" )
        log warn "run ./install.sh to get them"
    fi
}

# =============================================================================
# Usage
# =============================================================================
usage() {
cat << EOF
ReconWorm v$VERSION - Automated Recon CLI Tool
  original: coffeeaddict (tom)  |  hardening: Kairos Lab / Valisthea

USAGE:
  reconworm.sh -d example.com [-o output] [-m mode] [-t threads] [-s scope] [-x exclude] [-r]

OPTIONS:
  -d  Target domain (required)
  -o  Output directory              (default: output)
  -m  Mode: passive | active | full (default: full)
  -t  Parallel threads              (default: 20)
  -s  In-scope host regex           (default: subdomains of the target)
  -x  Out-of-scope host regex       (default: none)
  -r  Resume: skip a stage whose output already exists
  -h  Show help

MODES:
  passive -> subdomain enum + passive URL/JS collection + param/secret mining (no requests to target beyond DNS)
  active  -> passive + httpx probing + crawl + ports + open-redirect validation + sourcemap/JS secrets
  full    -> active + nuclei vuln scan + subdomain takeover + S3 recon + high-value report

SCOPE SAFETY:
  Every discovered host is filtered against the in-scope regex before any active
  step. Set -x to hard-exclude hosts you must not touch. Recon still respects the
  program RoE - this is a guardrail, not a licence.

EXAMPLE:
  reconworm.sh -d target.com -o results -m full -t 30 -x 'internal\.target\.com'
EOF
exit "${1:-1}"
}

# =============================================================================
# CLI parsing
# =============================================================================
while getopts "d:o:m:t:s:x:rh" opt; do
  case "$opt" in
    d) DOMAIN="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    s) SCOPE_REGEX="$OPTARG" ;;
    x) EXCLUDE_REGEX="$OPTARG" ;;
    r) RESUME="true" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done

[[ -z "$DOMAIN" ]] && { log err "domain is required"; usage 1; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { log err "invalid domain (allowed: letters, digits, dot, dash)"; exit 1; }
[[ "$THREADS" =~ ^[0-9]+$ ]] || { log err "-t must be an integer"; exit 1; }

# Default in-scope = the target and its subdomains (dot-escaped).
if [[ -z "$SCOPE_REGEX" ]]; then
    esc="${DOMAIN//./\\.}"
    SCOPE_REGEX="(^|\.)${esc}\$"
fi

BASE_DIR="$OUTPUT_DIR/$DOMAIN"
mkdir -p "$BASE_DIR"

# =============================================================================
# Banner
# =============================================================================
banner() {
cat << "EOF"
                                                   /~~\
     ____                                         /'o  |
   .~  | `\             ,-~~~\~-_               ,'  _/'|
   `\_/   /'\         /'`\    \  ~,             |     .'
       `,/'  |      ,'_   |   |   |`\          ,'~~\  |
       |   /`:     |  `\ /~~~~\ /   |        ,'    `.'
        | /'  |     |   ,'      `\  /`|      /'\    /  2.0
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
          Hardened (v2.0) by Kairos Lab / Valisthea
              ------------------------------
EOF
}

# =============================================================================
# Subdomain Enumeration (scope-filtered + resolved)
# =============================================================================
sub_enum() {
    log info "subdomain enumeration..."
    local raw="$BASE_DIR/subdomains_raw.txt"
    : > "$raw"

    if have subfinder; then
        tmo 300 subfinder -d "$DOMAIN" -silent >> "$raw" 2>/dev/null || true
    else
        log skip "subfinder missing"
    fi
    if have assetfinder; then
        tmo 300 assetfinder --subs-only "$DOMAIN" >> "$raw" 2>/dev/null || true
    else
        log skip "assetfinder missing"
    fi

    # Scope filter BEFORE anything else touches these hosts.
    sort -u "$raw" | scope_filter > "$BASE_DIR/subdomains.txt" || true

    # Resolve so downstream stages skip dead names (cheaper httpx/naabu).
    if have dnsx; then
        tmo 300 dnsx -l "$BASE_DIR/subdomains.txt" -silent \
            -o "$BASE_DIR/resolved.txt" 2>/dev/null || true
    else
        cp "$BASE_DIR/subdomains.txt" "$BASE_DIR/resolved.txt" 2>/dev/null || true
    fi

    log ok "subdomains: $(count "$BASE_DIR/subdomains.txt") in scope"
}

# =============================================================================
# HTTP Probing
# =============================================================================
http_probe() {
    have httpx || { log skip "httpx missing, skipping probe"; return 0; }
    local input="$BASE_DIR/resolved.txt"
    [[ -s "$input" ]] || input="$BASE_DIR/subdomains.txt"
    [[ -s "$input" ]] || { log skip "no subdomains to probe"; return 0; }

    log info "httpx probing..."
    tmo 300 httpx -l "$input" -silent -o "$BASE_DIR/live_hosts.txt" 2>/dev/null || true

    tmo 300 httpx -l "$input" -title -status-code -tech-detect -follow-redirects -silent \
        -o "$BASE_DIR/http_details.txt" 2>/dev/null || true

    # S3 references surfaced directly from response bodies.
    if [[ -s "$BASE_DIR/live_hosts.txt" ]]; then
        tmo 300 httpx -l "$BASE_DIR/live_hosts.txt" -silent -sr -srd "$BASE_DIR/httpx_bodies" 2>/dev/null || true
        grep -rhoE 's3\.amazonaws\.com[^ "]*|[a-z0-9.-]+\.s3\.[a-z0-9.-]*amazonaws\.com' \
            "$BASE_DIR/httpx_bodies" 2>/dev/null | sort -u > "$BASE_DIR/s3_urls.txt" || true
    fi

    log ok "live hosts: $(count "$BASE_DIR/live_hosts.txt")"
}

# =============================================================================
# Crawl (single pass, shared by JS + open-redirect). Parallel across hosts.
# =============================================================================
crawl_hosts() {
    have gospider || { log skip "gospider missing, skipping crawl"; return 0; }
    [[ -s "$BASE_DIR/live_hosts.txt" ]] || { log skip "no live hosts to crawl"; return 0; }
    resume_skip "$BASE_DIR/crawl.txt" && return 0

    log info "crawling live hosts (parallel x$THREADS)..."
    : > "$BASE_DIR/crawl.txt"
    local wl="${DOMAIN//./\\.}"
    # Each child appends (O_APPEND is atomic for small lines, no interleave) and
    # gospider stays on the target via --whitelist; url_scope_filter is still the
    # hard scope guard applied to crawl.txt downstream.
    xargs -P "$THREADS" -I{} sh -c \
        'gospider -s "$1" -d 2 -c 10 -t 5 --js -q --whitelist "$2" >> "$3" 2>/dev/null' \
        _ {} "$wl" "$BASE_DIR/crawl.txt" \
        < "$BASE_DIR/live_hosts.txt" 2>/dev/null || true

    # Fold any S3 refs found while crawling into the S3 list.
    grep -Eo 's3\.amazonaws\.com[^ "]*|[a-z0-9.-]+\.s3\.[a-z0-9.-]*amazonaws\.com' \
        "$BASE_DIR/crawl.txt" 2>/dev/null >> "$BASE_DIR/s3_urls.txt" || true
    [[ -f "$BASE_DIR/s3_urls.txt" ]] && sort -u "$BASE_DIR/s3_urls.txt" -o "$BASE_DIR/s3_urls.txt"

    log ok "crawl done: $(count "$BASE_DIR/crawl.txt") lines"
}

# =============================================================================
# Cloud Origin Discovery (find origins hiding behind a CDN)
# =============================================================================
origin_discovery() {
    log info "cloud origin discovery..."
    local ORIGIN_DIR="$BASE_DIR/origin_discovery"
    local HOSTS_FILE="$ORIGIN_DIR/hosts.txt"
    local CDN_PATTERN="cloudflare|akamai|fastly|cloudfront|edgesuite|edgekey|cdn77|incapsula|imperva|azureedge|trafficmanager|sucuri|stackpath|bunnycdn"
    mkdir -p "$ORIGIN_DIR"

    [[ -s "$BASE_DIR/live_hosts.txt" ]] || { log skip "no live hosts, skipping origin discovery"; return 0; }

    sed -E 's#https?://##' "$BASE_DIR/live_hosts.txt" | cut -d/ -f1 | sort -u > "$HOSTS_FILE"

    : > "$ORIGIN_DIR/host_ips.txt"
    : > "$ORIGIN_DIR/cnames.txt"
    : > "$ORIGIN_DIR/http_headers.txt"
    : > "$ORIGIN_DIR/cdn_hosts.txt"

    while read -r host; do
        [[ -z "$host" ]] && continue

        if have dig; then
            dig +short A "$host" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
                | while read -r ip; do echo "$host $ip"; done >> "$ORIGIN_DIR/host_ips.txt"

            local cname
            cname="$(dig +short CNAME "$host" 2>/dev/null)"
            if [[ -n "$cname" ]]; then
                echo "$host $cname" >> "$ORIGIN_DIR/cnames.txt"
                echo "$cname" | grep -Eiq "$CDN_PATTERN" && echo "$host" >> "$ORIGIN_DIR/cdn_hosts.txt"
            fi
        fi

        local headers
        headers="$(tmo 20 curl -skI --max-time 15 --proto '=http,https' -- "https://$host" 2>/dev/null)"
        [[ -z "$headers" ]] && headers="$(tmo 20 curl -skI --max-time 15 --proto '=http,https' -- "http://$host" 2>/dev/null)"
        if [[ -n "$headers" ]]; then
            { echo "### $host"; echo "$headers"; echo ""; } >> "$ORIGIN_DIR/http_headers.txt"
            echo "$headers" | grep -Eiq "$CDN_PATTERN|cf-ray|x-cache|x-served-by|x-akamai" \
                && echo "$host" >> "$ORIGIN_DIR/cdn_hosts.txt"
        fi
    done < "$HOSTS_FILE"

    sort -u "$ORIGIN_DIR/cdn_hosts.txt" -o "$ORIGIN_DIR/cdn_hosts.txt"
    comm -23 "$HOSTS_FILE" "$ORIGIN_DIR/cdn_hosts.txt" > "$ORIGIN_DIR/non_cdn_hosts.txt" 2>/dev/null || true

    : > "$ORIGIN_DIR/non_cdn_host_ips.txt"
    while read -r host; do
        [[ -z "$host" ]] && continue
        awk -v h="$host" '$1 == h {print}' "$ORIGIN_DIR/host_ips.txt" >> "$ORIGIN_DIR/non_cdn_host_ips.txt"
    done < "$ORIGIN_DIR/non_cdn_hosts.txt"

    grep -Ei 'origin|direct|staging|stage|dev|test|admin|internal|backend|api' \
        "$ORIGIN_DIR/non_cdn_host_ips.txt" > "$ORIGIN_DIR/possible_origins.txt" 2>/dev/null || true

    log ok "origin discovery complete"
}

# =============================================================================
# Port Scanning
# =============================================================================
port_scan() {
    have naabu || { log skip "naabu missing, skipping port scan"; return 0; }
    [[ -s "$BASE_DIR/live_hosts.txt" ]] || { log skip "no live hosts, skipping port scan"; return 0; }
    resume_skip "$BASE_DIR/ports.txt" && return 0

    log info "port scan..."
    sed -E 's#https?://##' "$BASE_DIR/live_hosts.txt" | cut -d/ -f1 | sort -u > "$BASE_DIR/naabu_targets.txt"
    tmo 300 naabu -list "$BASE_DIR/naabu_targets.txt" -silent -o "$BASE_DIR/ports.txt" 2>/dev/null || true

    if [[ -s "$BASE_DIR/ports.txt" ]]; then
        grep ":21$"  "$BASE_DIR/ports.txt" > "$BASE_DIR/ftp.txt"          2>/dev/null || true
        grep ":22$"  "$BASE_DIR/ports.txt" > "$BASE_DIR/ssh.txt"          2>/dev/null || true
        grep -vE ":(21|22|80|443)$" "$BASE_DIR/ports.txt" > "$BASE_DIR/other_ports.txt" 2>/dev/null || true
    fi
    log ok "port scan complete"
}

# =============================================================================
# Vulnerability Scanning (severity-filtered, rate-limited)
# =============================================================================
vuln_scan() {
    have nuclei || { log skip "nuclei missing, skipping vuln scan"; return 0; }
    [[ -s "$BASE_DIR/live_hosts.txt" ]] || { log skip "no live hosts, skipping vuln scan"; return 0; }
    resume_skip "$BASE_DIR/nuclei_results.txt" && return 0

    log info "nuclei scan (severity: $NUCLEI_SEVERITY, rate: $NUCLEI_RL)..."
    tmo 900 nuclei -l "$BASE_DIR/live_hosts.txt" -severity "$NUCLEI_SEVERITY" \
        -rl "$NUCLEI_RL" -silent -o "$BASE_DIR/nuclei_results.txt" 2>/dev/null || true
    log ok "vuln scan complete"
}

# =============================================================================
# Subdomain Takeover Check
# =============================================================================
takeover_check() {
    log info "subdomain takeover check..."
    if have subjack; then
        tmo 300 subjack -w "$BASE_DIR/subdomains.txt" -v -o "$BASE_DIR/subjack.txt" 2>/dev/null || true
    else
        log skip "subjack missing"
    fi

    if have dnsx && have httpx && have nuclei; then
        # Dangling CNAME -> live probe -> nuclei takeover templates, captured to file.
        dnsx -l "$BASE_DIR/subdomains.txt" -silent -cname 2>/dev/null \
            | httpx -silent -status-code -title -cname 2>/dev/null \
            | nuclei -t http/takeovers/ -severity high,critical -silent \
                -o "$BASE_DIR/takeovers.txt" 2>/dev/null || true
    else
        log skip "dnsx/httpx/nuclei missing, skipping nuclei takeover pass"
    fi
    log ok "takeover check complete"
}

# =============================================================================
# S3 Recon
# =============================================================================
s3_recon() {
    have s3scanner || { log skip "s3scanner missing, skipping S3 recon"; return 0; }
    log info "S3 recon..."
    local BUCKET_FILE="$BASE_DIR/buckets.txt"
    local URL_FILE="$BASE_DIR/s3_urls.txt"
    local OUTPUT_FILE="$BASE_DIR/s3_results.txt"

    local short="${DOMAIN%%.*}"
    { echo "$DOMAIN"; echo "$short"; echo "dev-$short"; echo "prod-$short"; \
      echo "$short-dev"; echo "$short-prod"; echo "$short-backup"; echo "$short-assets"; } > "$BUCKET_FILE"

    if [[ -f "$URL_FILE" ]]; then
        sed -E 's#https?://([^./]+)\.s3\.[^/]*amazonaws\.com.*#\1#; t; s#https?://s3\.[^/]*amazonaws\.com/([^/]+).*#\1#' \
            "$URL_FILE" >> "$BUCKET_FILE" 2>/dev/null || true
    fi
    sort -u "$BUCKET_FILE" -o "$BUCKET_FILE"

    tmo 300 s3scanner -bucket-file "$BUCKET_FILE" > "$OUTPUT_FILE" 2>/dev/null || true
    log ok "S3 scan complete"
}

# =============================================================================
# JS Recon (passive collect + optional active fetch + secrets)
#   fetch=false in passive mode (no requests to the target beyond collection).
# =============================================================================
js_recon() {
    local fetch="${1:-true}"
    log info "JS discovery (fetch=$fetch)..."
    local JS_DIR="$BASE_DIR/js"
    mkdir -p "$JS_DIR/files"
    local WAYBACK_FILE="$JS_DIR/wayback.txt"
    local JS_URLS_FILE="$JS_DIR/js_urls.txt"

    : > "$WAYBACK_FILE"
    if have waybackurls; then tmo "$JS_TIMEOUT" waybackurls "$DOMAIN" >> "$WAYBACK_FILE" 2>/dev/null || true; fi
    if have gau;         then tmo "$JS_TIMEOUT" gau "$DOMAIN"         >> "$WAYBACK_FILE" 2>/dev/null || true; fi
    sort -u "$WAYBACK_FILE" -o "$WAYBACK_FILE" 2>/dev/null || true

    # .js URLs from passive history + the shared crawl.
    { grep -E '\.js(\?|$)' "$WAYBACK_FILE" 2>/dev/null
      grep -Eo 'https?://[^ ]+\.js(\?[^ ]*)?' "$BASE_DIR/crawl.txt" 2>/dev/null
    } | url_scope_filter | sort -u > "$JS_URLS_FILE" || true
    log ok "JS URLs: $(count "$JS_URLS_FILE")"

    if [[ "$fetch" != "true" ]]; then
        log skip "passive mode: not downloading JS (collection only)"
        return 0
    fi
    [[ -s "$JS_URLS_FILE" ]] || { log skip "no JS URLs to fetch"; return 0; }

    log info "downloading JS (parallel x$THREADS)..."
    export JS_FILES_DIR="$JS_DIR/files"
    _dl_js() {
        local url="$1" fn
        [[ -z "$url" ]] && return 0
        fn="$(hash_url "$url")"
        curl -sLf --max-time 20 --proto '=http,https' --proto-redir '=http,https' -- "$url" -o "$JS_FILES_DIR/$fn.js" 2>/dev/null || true
    }
    export -f _dl_js
    xargs -P "$THREADS" -I{} bash -c '_dl_js "$@"' _ {} < "$JS_URLS_FILE" 2>/dev/null || true

    if have trufflehog; then
        log info "trufflehog on downloaded JS..."
        tmo "$JS_TIMEOUT" trufflehog filesystem "$JS_DIR/files" --no-update \
            > "$JS_DIR/secrets.txt" 2>/dev/null || true
    else
        log skip "trufflehog missing, skipping JS secret scan"
    fi
    log ok "JS recon complete"
}

# =============================================================================
# Open Redirect candidate finder (param mining from collected URLs)
# =============================================================================
open_redirect_finder() {
    log info "open redirect candidate mining..."
    local REDIRECT_DIR="$BASE_DIR/open_redirects"
    local URL_SOURCE_FILE="$REDIRECT_DIR/all_urls.txt"
    local CANDIDATES_FILE="$REDIRECT_DIR/open_redirect_candidates.txt"
    local PARAM_NAMES_FILE="$REDIRECT_DIR/redirect_param_names.txt"
    local params='(next|url|target|redirect|redirect_uri|redirect_url|return|returnurl|return_url|continue|continueurl|continue_url|callback|callback_url|dest|destination|to|r|u|uri|path|goto|go|out|view|link)'
    mkdir -p "$REDIRECT_DIR"
    : > "$URL_SOURCE_FILE"

    [[ -f "$BASE_DIR/js/wayback.txt" ]]   && cat "$BASE_DIR/js/wayback.txt"    >> "$URL_SOURCE_FILE"
    [[ -f "$BASE_DIR/js/js_urls.txt" ]]   && cat "$BASE_DIR/js/js_urls.txt"    >> "$URL_SOURCE_FILE"
    [[ -f "$BASE_DIR/crawl.txt" ]]        && grep -Eo 'https?://[^ ]+' "$BASE_DIR/crawl.txt"       >> "$URL_SOURCE_FILE" 2>/dev/null
    [[ -f "$BASE_DIR/http_details.txt" ]] && grep -Eo 'https?://[^ ]+' "$BASE_DIR/http_details.txt" >> "$URL_SOURCE_FILE" 2>/dev/null

    [[ -s "$URL_SOURCE_FILE" ]] || { log skip "no URL sources, skipping open-redirect mining"; return 0; }
    # Crawl/wayback URLs contain third-party links. Scope-filter by host BEFORE any
    # candidate can reach the active validator (nuclei), or recon hits out-of-scope hosts.
    url_scope_filter < "$URL_SOURCE_FILE" | sort -u > "$URL_SOURCE_FILE.scoped" || true
    mv "$URL_SOURCE_FILE.scoped" "$URL_SOURCE_FILE"

    grep -Ei "(\?|&)$params=" "$URL_SOURCE_FILE" | sort -u > "$CANDIDATES_FILE" || true
    grep -Eio "(\?|&)$params=" "$CANDIDATES_FILE" | sed -E 's/^[?&]//; s/=$//' | sort -u > "$PARAM_NAMES_FILE" || true

    log ok "open redirect candidates: $(count "$CANDIDATES_FILE")"
}

# =============================================================================
# Open Redirect validation (nuclei) - active only
# =============================================================================
open_redirect_scan() {
    have nuclei || { log skip "nuclei missing, skipping open-redirect validation"; return 0; }
    local CANDIDATES_FILE="$BASE_DIR/open_redirects/open_redirect_candidates.txt"
    local RESULTS_FILE="$BASE_DIR/open_redirects/nuclei_open_redirect_results.txt"
    [[ -s "$CANDIDATES_FILE" ]] || { log skip "no open-redirect candidates to validate"; return 0; }

    log info "validating open redirects with nuclei..."
    tmo 300 nuclei -l "$CANDIDATES_FILE" -tags redirect -rl "$NUCLEI_RL" -silent \
        -o "$RESULTS_FILE" 2>/dev/null || true
    log ok "open redirect validation done"
}

# =============================================================================
# Sourcemap Recon (reconstruct source + mine routes/secrets) - active only
# =============================================================================
sourcemap_recon() {
    log info "sourcemap recon..."
    local SM_DIR="$BASE_DIR/sourcemaps"
    local MAP_FILES_DIR="$SM_DIR/files"
    local JS_URLS_FILE="$BASE_DIR/js/js_urls.txt"
    local MAP_URLS_FILE="$SM_DIR/sourcemap_urls.txt"
    local MAP_CONTENT_FILE="$SM_DIR/sourcemap_content.txt"
    mkdir -p "$MAP_FILES_DIR"

    [[ -s "$JS_URLS_FILE" ]] || { log skip "no JS URLs, skipping sourcemap recon"; return 0; }

    sed 's/$/.map/' "$JS_URLS_FILE" > "$MAP_URLS_FILE"
    if [[ -d "$BASE_DIR/js/files" ]]; then
        grep -rhoE 'sourceMappingURL=[^[:space:]]+' "$BASE_DIR/js/files" 2>/dev/null \
            | sed 's/sourceMappingURL=//' | grep -E '^https?://'             | url_scope_filter | drop_ssrf_hosts >> "$MAP_URLS_FILE" || true
    fi
    sort -u "$MAP_URLS_FILE" -o "$MAP_URLS_FILE"

    log info "downloading sourcemaps (parallel x$THREADS)..."
    export MAP_FILES_DIR
    _dl_map() {
        local url="$1" fn
        [[ -z "$url" ]] && return 0
        fn="$(hash_url "$url")"
        curl -sLf --max-time 20 --proto '=http,https' --proto-redir '=http,https' -- "$url" -o "$MAP_FILES_DIR/$fn.map" 2>/dev/null || true
    }
    export -f _dl_map
    xargs -P "$THREADS" -I{} bash -c '_dl_map "$@"' _ {} < "$MAP_URLS_FILE" 2>/dev/null || true

    if have jq; then
        find "$MAP_FILES_DIR" -type f -name '*.map' -exec jq -r '.sources[]?, .sourcesContent[]?' {} + \
            > "$MAP_CONTENT_FILE" 2>/dev/null || true
    else
        cat "$MAP_FILES_DIR"/*.map > "$MAP_CONTENT_FILE" 2>/dev/null || true
    fi

    grep -rhoE 'https?://[^"'\'' )]+' "$MAP_FILES_DIR" "$MAP_CONTENT_FILE" 2>/dev/null \
        | sort -u > "$SM_DIR/urls.txt" || true
    grep -rhoE '(/[A-Za-z0-9._-]+)+/?' "$MAP_CONTENT_FILE" 2>/dev/null \
        | grep -Ei 'api|admin|auth|oauth|graphql|upload|debug|internal|token|callback' \
        | sort -u > "$SM_DIR/api_routes.txt" || true
    grep -rhoE '([A-Za-z0-9_-]+\.)+(internal|local|corp|lan|dev|stage|staging|test)' \
        "$MAP_FILES_DIR" "$MAP_CONTENT_FILE" 2>/dev/null | sort -u > "$SM_DIR/internal_hosts.txt" || true
    # High-signal secret shapes only (avoid the token|secret|password false-positive flood).
    grep -rhoE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]+|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+' \
        "$MAP_FILES_DIR" "$MAP_CONTENT_FILE" 2>/dev/null | sort -u > "$SM_DIR/secret_signals.txt" || true
    grep -rhoE '"sources"[[:space:]]*:[^]]+' "$MAP_FILES_DIR" 2>/dev/null \
        | sort -u > "$SM_DIR/source_paths_raw.txt" || true

    if have trufflehog; then
        tmo "$JS_TIMEOUT" trufflehog filesystem "$MAP_FILES_DIR" --no-update \
            > "$SM_DIR/trufflehog_secrets.txt" 2>/dev/null || true
    fi
    log ok "sourcemap recon complete"
}

# =============================================================================
# High-value aggregation + summary report
# =============================================================================
high_value_analysis() {
    log info "extracting high-value findings..."
    local HV_DIR="$BASE_DIR/high_value"
    mkdir -p "$HV_DIR"
    local OD="$BASE_DIR/origin_discovery"

    # Origin IPs (non-CDN) - FIX: read host_ips.txt (was host_ip.txt) from origin_discovery.
    [[ -f "$OD/non_cdn_host_ips.txt" ]] && cp "$OD/non_cdn_host_ips.txt" "$HV_DIR/origin_ips.txt"
    [[ -f "$OD/possible_origins.txt" ]]  && cp "$OD/possible_origins.txt"  "$HV_DIR/possible_origins.txt"

    [[ -f "$BASE_DIR/ports.txt" ]] && grep -E ":(21|22|23|3306|5432|6379|9200|27017|11211|5900|3389)$" \
        "$BASE_DIR/ports.txt" > "$HV_DIR/sensitive_ports.txt" 2>/dev/null

    [[ -d "$BASE_DIR/js/files" ]] && grep -rhoE '(^|[^0-9])(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)' \
        "$BASE_DIR/js/files/" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$HV_DIR/internal_ips.txt"

    [[ -f "$BASE_DIR/subdomains.txt" ]] && grep -Ei 'dev|test|stage|staging|admin|internal|beta|uat|preprod|jenkins|gitlab|vpn' \
        "$BASE_DIR/subdomains.txt" | sort -u > "$HV_DIR/interesting_subdomains.txt" 2>/dev/null

    [[ -f "$BASE_DIR/s3_results.txt" ]] && grep -Ei 'exists|open|public|AuthenticatedRead' \
        "$BASE_DIR/s3_results.txt" > "$HV_DIR/valid_buckets.txt" 2>/dev/null

    [[ -f "$BASE_DIR/takeovers.txt" ]] && cp "$BASE_DIR/takeovers.txt" "$HV_DIR/takeover_hits.txt"
    [[ -f "$BASE_DIR/js/secrets.txt" ]] && cp "$BASE_DIR/js/secrets.txt" "$HV_DIR/high_value_secrets.txt"

    if [[ -d "$BASE_DIR/sourcemaps" ]]; then
        for f in api_routes internal_hosts secret_signals trufflehog_secrets; do
            [[ -f "$BASE_DIR/sourcemaps/$f.txt" ]] && cp "$BASE_DIR/sourcemaps/$f.txt" "$HV_DIR/sourcemap_$f.txt"
        done
    fi
    if [[ -d "$BASE_DIR/open_redirects" ]]; then
        [[ -f "$BASE_DIR/open_redirects/open_redirect_candidates.txt" ]] && cp "$BASE_DIR/open_redirects/open_redirect_candidates.txt" "$HV_DIR/open_redirect_candidates.txt"
        [[ -f "$BASE_DIR/open_redirects/nuclei_open_redirect_results.txt" ]] && cp "$BASE_DIR/open_redirects/nuclei_open_redirect_results.txt" "$HV_DIR/open_redirect_nuclei_results.txt"
        [[ -f "$BASE_DIR/open_redirects/redirect_param_names.txt" ]] && cp "$BASE_DIR/open_redirects/redirect_param_names.txt" "$HV_DIR/redirect_param_names.txt"
    fi

    # Build the report.
    local REPORT="$HV_DIR/high_value_summary.txt"
    {
        echo "====== High Value Findings ======"
        echo "Target: $DOMAIN"
        echo "Date:   $(date)"
        echo ""
        _section() { # _section <title> <file> <n>
            echo "[$1]"
            [[ -f "$2" ]] && head -n "${3:-10}" "$2"
            echo ""
        }
        _section "Origin IPs (non-CDN)"      "$HV_DIR/origin_ips.txt"
        _section "Possible Origin Hosts"     "$HV_DIR/possible_origins.txt"
        _section "Sensitive Ports"           "$HV_DIR/sensitive_ports.txt"
        _section "Internal IP Leaks (JS)"    "$HV_DIR/internal_ips.txt"
        _section "Interesting Subdomains"    "$HV_DIR/interesting_subdomains.txt"
        _section "S3 Buckets"                "$HV_DIR/valid_buckets.txt"
        _section "Takeover Signals"          "$HV_DIR/takeover_hits.txt"
        _section "Secrets (JS)"              "$HV_DIR/high_value_secrets.txt"
        _section "Sourcemap API Routes"      "$HV_DIR/sourcemap_api_routes.txt"
        _section "Sourcemap Internal Hosts"  "$HV_DIR/sourcemap_internal_hosts.txt"
        _section "Sourcemap Secret Signals"  "$HV_DIR/sourcemap_secret_signals.txt"
        _section "Open Redirect Candidates"  "$HV_DIR/open_redirect_candidates.txt"
        _section "Redirect Parameter Names"  "$HV_DIR/redirect_param_names.txt" 20
        _section "Open Redirect Nuclei Hits" "$HV_DIR/open_redirect_nuclei_results.txt"
        _section "Sourcemap TruffleHog Secrets" "$HV_DIR/sourcemap_trufflehog_secrets.txt"
    } > "$REPORT"

    log ok "high-value report: $REPORT"
}

# =============================================================================
# Summary
# =============================================================================
generate_summary() {
    local SUMMARY_FILE="$BASE_DIR/summary.txt"
    {
        echo "====== Recon Summary ======"
        echo "Target: $DOMAIN"
        echo "Mode:   $MODE"
        echo "Date:   $(date)"
        echo "Subdomains: $(count "$BASE_DIR/subdomains.txt")"
        echo "Live hosts: $(count "$BASE_DIR/live_hosts.txt")"
        echo "Ports:      $(count "$BASE_DIR/ports.txt")"
        echo "Vulns:      $(count "$BASE_DIR/nuclei_results.txt")"
        echo "JS URLs:    $(count "$BASE_DIR/js/js_urls.txt")"
    } > "$SUMMARY_FILE"
    cat "$SUMMARY_FILE"
}

# =============================================================================
# Pipelines
# =============================================================================
run_passive() {
    sub_enum
    js_recon false            # collect only, no requests to target
    open_redirect_finder
}

run_active() {
    sub_enum
    http_probe
    crawl_hosts
    origin_discovery
    port_scan
    js_recon true
    open_redirect_finder
    open_redirect_scan
    sourcemap_recon
    high_value_analysis
}

run_full() {
    sub_enum
    http_probe
    crawl_hosts
    origin_discovery
    port_scan
    vuln_scan
    takeover_check
    s3_recon
    js_recon true
    open_redirect_finder
    open_redirect_scan
    sourcemap_recon
    high_value_analysis
}

# =============================================================================
# Main
# =============================================================================
main() {
    banner
    log info "target:  $DOMAIN"
    log info "mode:    $MODE   threads: $THREADS   resume: $RESUME"
    log info "output:  $BASE_DIR"
    log info "scope:   $SCOPE_REGEX${EXCLUDE_REGEX:+   exclude: $EXCLUDE_REGEX}"
    preflight

    case "$MODE" in
        passive) run_passive ;;
        active)  run_active ;;
        full)    run_full ;;
        *) log err "invalid mode: $MODE"; usage 1 ;;
    esac

    generate_summary
    log ok "recon complete. output: $BASE_DIR"
}

main
