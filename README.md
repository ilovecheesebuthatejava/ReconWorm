# ReconWorm

A small, hackable recon CLI with a built-in pipeline you can extend. It does not
just enumerate: it chases high-value signal (origin IPs hiding behind a CDN,
sourcemap-reconstructed routes and secrets, JS secrets, open-redirect params, S3)
and folds it all into one high-value report.

> Original tool by **coffeeaddict (tom)** ([ilovecheesebuthatejava](https://github.com/ilovecheesebuthatejava/ReconWorm)).
> Hardening pass (v2.0) by **Kairos Lab / Valisthea**.

**Only run this against targets you are authorised to test** (a bug bounty scope
or a signed pentest RoE). `active` and `full` modes are loud: read the program
rules of engagement first.

---

## What's new in v2.0 (hardening pass)

- **Scope guard.** Every discovered host is filtered against an in-scope regex
  (defaults to the target and its subdomains) before any active step, with `-x`
  to hard-exclude hosts. Recon can no longer wander off-scope by accident.
- **Parallelism.** Crawling and file downloads run across `-t` threads
  (`xargs -P`), instead of one host at a time.
- **Fail-soft.** `set -uo pipefail`, a per-tool preflight, and every module
  skips gracefully when its tool is missing (no more silent half-runs).
- **Real fixes.** Portable hashing (Linux/macOS), the origin-IP report path
  (`host_ips.txt`), a single crawl shared across modules (gospider no longer
  runs twice), captured takeover output, severity-filtered + rate-limited nuclei,
  and a passive mode that actually stays passive.
- **Resume.** `-r` skips a stage whose output already exists.
- **Installer parity.** `install.sh` now installs exactly the tools the script
  calls (gospider, s3scanner, trufflehog were missing before).

---

## Install

```bash
git clone https://github.com/ilovecheesebuthatejava/ReconWorm
cd ReconWorm
chmod +x reconworm.sh install.sh
./install.sh
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Usage

```bash
./reconworm.sh -d example.com -o output -m full
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-d` | Target domain (required) | |
| `-o` | Output directory | `output` |
| `-m` | Mode: `passive` \| `active` \| `full` | `full` |
| `-t` | Parallel threads | `20` |
| `-s` | In-scope host regex | subdomains of `-d` |
| `-x` | Out-of-scope host regex (hard exclude) | none |
| `-r` | Resume (skip stages with existing output) | off |
| `-h` | Help | |

### Modes

- **passive** — subdomain enum + passive URL/JS collection (wayback/gau) + param
  and secret mining. No requests to the target beyond DNS.
- **active** — passive + httpx probing + a single crawl + ports + open-redirect
  validation + sourcemap/JS secret scanning.
- **full** — active + nuclei vuln scan + subdomain takeover + S3 recon + the
  high-value report.

### Example

```bash
# 30 threads, exclude an internal host, resume if re-run
./reconworm.sh -d target.com -m full -t 30 -x 'internal\.target\.com' -r
```

Output lands under `output/<domain>/`, with the aggregated findings in
`high_value/high_value_summary.txt`.

---

## Tuning

Nuclei severity and rate limit are environment-overridable:

```bash
NUCLEI_SEVERITY=medium,high,critical NUCLEI_RL=100 ./reconworm.sh -d target.com -m full
```

## Extending

Each stage is a shell function (`sub_enum`, `http_probe`, `crawl_hosts`,
`origin_discovery`, `sourcemap_recon`, ...). Add your own and wire it into
`run_passive` / `run_active` / `run_full`. Guard external tools with `have <tool>`
and honour the scope filter for anything that sends requests.
