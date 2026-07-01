# JS Analysis Workflow

End-to-end pipeline for JavaScript security analysis on Termux. Combines custom tools (`omega-unified.js`, `js-decoder-omega.js`) with external tools (`gau`, `katana`, `subjs`) and the BB Omega Suite (`termscan.py`, `jsreaper.py`).

---

## Pipeline Overview

```
PHASE 1: HARVEST     → Collect JS files from target
PHASE 2: DECODE      → Deobfuscate, beautify, unpack webpack, auto-follow sourcemaps
PHASE 3: DEEP SCAN   → 50+ security scanners + AST taint tracking + service worker + chunk graph
PHASE 4: CROSS-FILE  → Correlate credentials across files (batch mode)
PHASE 5: WEB3 SCAN   → Blockchain/Web3-specific patterns
PHASE 6: REPORT      → SARIF, HTML, JSON, Markdown, GitHub annotations
PHASE 7: VALIDATE    → Manual verification in browser/Burp; --verify for live endpoint checks
```

---

## Phase 1: Harvest

### Passive (zero-noise, run first)

```bash
TARGET="example.com"
mkdir -p ~/recon/$TARGET/js

# From multiple sources simultaneously
echo "$TARGET" | gau --threads 20 | grep -iE "\.(js|mjs)$" | sort -u > ~/recon/$TARGET/js/passive.txt &
echo "$TARGET" | waybackurls | grep -iE "\.(js|mjs)$" | sort -u >> ~/recon/$TARGET/js/passive.txt &
subjs -i <(subfinder -d "$TARGET" -silent) | sort -u >> ~/recon/$TARGET/js/passive.txt &
wait

# Dedup
sort -u ~/recon/$TARGET/js/passive.txt -o ~/recon/$TARGET/js/passive.txt
echo "[+] Passive: $(wc -l < ~/recon/$TARGET/js/passive.txt) JS URLs"
```

### Active crawl

```bash
katana -u "https://$TARGET" -jc -d 3 -silent |
  grep -iE "\.(js|mjs)$" | sort -u > ~/recon/$TARGET/js/active.txt

# Sourcemap discovery
katana -u "https://$TARGET" -affect-sourcemap | grep "\.map$" > ~/recon/$TARGET/js/sourcemaps.txt

echo "[+] Active: $(wc -l < ~/recon/$TARGET/js/active.txt) JS URLs"
echo "[+] Sourcemaps: $(wc -l < ~/recon/$TARGET/js/sourcemaps.txt)"
```

### Download

```bash
cd ~/recon/$TARGET/js
cat passive.txt active.txt | sort -u | while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sL --max-time 15 -o "$filename" "$url" 2>/dev/null &&
    echo "$url -> $filename" >> manifest.txt
done
echo "[+] Downloaded: $(wc -l < manifest.txt) files"
```

### Alternative: jsreaper (BB Omega Suite)

```bash
python3 ~/unified_bb_suite/attack_surface/jsreaper.py \
  --domain "$TARGET" \
  --output ~/recon/$TARGET/js/harvested/
```

---

## Phase 2: Decode

### Quick triage (omega_lite)

```bash
for f in ~/recon/$TARGET/js/*.js; do
  python3 ~/omega-pipeline/omega_lite.py "$f" 2>&1 | head -5
done
```

### Full decode pipeline (omega-unified)

```bash
# Individual file
node ~/tools/omega-unified.js ~/recon/$TARGET/js/bundle.js

# With decoded output
node ~/tools/omega-unified.js ~/recon/$TARGET/js/bundle.js -f json -o ~/recon/$TARGET/results.json
```

### Deep deobfuscation (v4 reference for complex obfuscation)

```bash
NODE_OPTIONS="--max-old-space-size=128" node ~/tools/js-decoder-omega.js \
  ~/recon/$TARGET/js/obfuscated.js \
  --all --report --out ~/recon/$TARGET/decode_out/
```

---

## Phase 3: Deep Scan

### Primary: omega-unified (50+ scanners, AST taint)

```bash
# Single file
node ~/tools/omega-unified.js ~/recon/$TARGET/js/bundle.js

# HTML report
node ~/tools/omega-unified.js -f html -o ~/recon/$TARGET/report.html ~/recon/$TARGET/js/bundle.js

# Fast scan (skip extended scanners)
node ~/tools/omega-unified.js --fast ~/recon/$TARGET/js/bundle.js

# SARIF for CI
node ~/tools/omega-unified.js -f sarif -o ~/recon/$TARGET/results.sarif ~/recon/$TARGET/js/bundle.js
```

### Secondary: termscan (rule-based, 293 patterns)

```bash
# Universal ruleset (all categories)
python3 ~/bb-framework/tools/termscan.py scan \
  --rules ~/bb-framework/rules/bugbounty_rules.yaml \
  --output ~/recon/$TARGET/termscan_results.json \
  ~/recon/$TARGET/js/bundle.js

# Targeted by category
python3 ~/bb-framework/tools/termscan.py scan \
  --rules ~/bb-framework/rules/bb-crypto-web3.yaml \
  --output ~/recon/$TARGET/crypto_results.json \
  ~/recon/$TARGET/js/bundle.js
```

### Tertiary: termux-js-secret-scanner (entropy + cross-file)

```bash
python3 ~/termux_js_scanner.py \
  -d ~/recon/$TARGET/js/ \
  -r --format json --cache
```

---

## Phase 4: Cross-File Correlation

```bash
# Collect all findings from all tools
mkdir -p ~/recon/$TARGET/correlated

# Find shared credentials across files
rg -o 'ghp_[0-9A-Za-z]{36}' ~/recon/$TARGET/js/*.js | sort > ~/recon/$TARGET/correlated/gh_tokens.txt
rg -o 'AKIA[0-9A-Z]{16}' ~/recon/$TARGET/js/*.js | sort > ~/recon/$TARGET/correlated/aws_keys.txt
rg -o 'sk_live_[0-9a-zA-Z]{24,}' ~/recon/$TARGET/js/*.js | sort > ~/recon/$TARGET/correlated/stripe_keys.txt

# Find API endpoints appearing in multiple files
rg -oh 'https?://[a-zA-Z0-9./_-]+' ~/recon/$TARGET/js/*.js | sort -u > ~/recon/$TARGET/correlated/endpoints.txt

# OAuth client IDs used across chunks
rg -oh 'AIza[0-9A-Za-z_-]{35}' ~/recon/$TARGET/js/*.js | sort -u > ~/recon/$TARGET/correlated/google_oauth.txt
```

---

## Phase 5: Web3 / Blockchain Scan

```bash
# omega-unified has built-in Phase 12n scanner
node ~/tools/omega-unified.js ~/recon/$TARGET/js/web3-bundle.js

# termscan crypto/web3 ruleset
python3 ~/bb-framework/tools/termscan.py scan \
  --rules ~/bb-framework/rules/bb-crypto-web3.yaml \
  --output ~/recon/$TARGET/web3_results.json \
  ~/recon/$TARGET/js/web3-bundle.js

# Individual pattern grep
rg -n '0x[a-fA-F0-9]{40}' ~/recon/$TARGET/js/*.js  # ETH addresses
rg -n 'ethers|web3|ethereum\.' ~/recon/$TARGET/js/*.js  # Web3 lib usage
rg -n 'solana|@solana' ~/recon/$TARGET/js/*.js  # Solana
rg -n 'metamask|walletConnect|walletlink' ~/recon/$TARGET/js/*.js  # Wallet connectors
```

---

## Phase 6: Report

```bash
# omega-unified reports
node ~/tools/omega-unified.js -f html -o ~/recon/$TARGET/report.html ~/recon/$TARGET/js/bundle.js
node ~/tools/omega-unified.js -f json -o ~/recon/$TARGET/report.json ~/recon/$TARGET/js/bundle.js

# Consolidate all findings
cat ~/recon/$TARGET/report.json \
  ~/recon/$TARGET/termscan_results.json \
  | jq -s '.[0].findings + .[1].results' > ~/recon/$TARGET/all_findings.json

# Summary
jq 'group_by(.severity) | map({severity: .[0].severity, count: length})' \
  ~/recon/$TARGET/all_findings.json
```

---

## Phase 7: Validate

For each finding:

```bash
# 1. Is it a real secret or test data?
# Check: does the value appear in test fixtures, example code, or docs?

# 2. Can you access the service with it?
# e.g., for Google API keys:
curl -s "https://maps.googleapis.com/maps/api/staticmap?center=NYC&size=400x400&key=AIza..."

# 3. Is it behind a login that matters?
# Follow up with authenticated scanning:
node ~/tools/omega-unified.js ~/recon/$TARGET/js/bundle.js 2>&1 \
  | grep -E "CRITICAL|HIGH" | head -20
```

---

## Gaps & Implemented Improvements

### Gap 1: Directory/batch mode (IMPLEMENTED)

**Status:** `--dir <path>` scans all `.js` files in a directory, producing a consolidated report with cross-file aggregation.

```bash
node ~/tools/omega-unified.js --dir ~/recon/$TARGET/js/ -o consolidated-report.json
node ~/tools/omega-unified.js --dir ./js/ --cache --format html -o batch.html
```
- Aggregate findings across files
- Cross-file credential correlation
- Summary metrics (X files scanned, Y findings, cached count)
- `--cache` flag prevents re-scanning unchanged files

### Gap 2: URL crawling (IMPLEMENTED)

**Status:** `--url <url>` downloads and scans a remote JS file in one command.

```bash
node ~/tools/omega-unified.js --url https://target.com/static/js/main.js
node ~/tools/omega-unified.js --url https://target.com/bundle.js --verify -f github-annotation
```
- Auto-follows redirects (max 1 hop)
- 30s timeout per request
- Sourcemap auto-follow works for inline base64 sourcemaps

### Gap 3: Service worker analysis (IMPLEMENTED)

**Status:** Phase 12o added to main pipeline. Scans for SW registration, fetch intercept, message listeners (with/without origin validation), Cache API usage, `skipWaiting()`, and `clients.claim()`.

```bash
# Runs automatically in non--fast mode
node ~/tools/omega-unified.js --verbose bundle.js
  # service-worker           5ms
```
- `sw-register-relative` (MEDIUM): relative SW URL → scope hijacking risk
- `sw-fetch-intercept` (MEDIUM): SW intercepts all fetch requests
- `sw-message-no-origin` (HIGH): postMessage listener without origin validation
- `sw-cache-api` (INFO): Cache API usage
- `sw-skip-waiting` / `sw-clients-claim` (INFO): immediate takeover

### Gap 4: Sourcemap auto-follow (IMPLEMENTED)

**Status:** `decodePipeline()` auto-detects inline base64 `sourceMappingURL` comments and reverse-applies mappings via `lib/sourcemap.js`. Adjacent `.map` files are resolved when a file path is available.

```bash
# Inline sourcemaps auto-decoded — no extra flag needed
# Adjacent .map files: place bundle.js.map next to bundle.js
node ~/tools/omega-unified.js bundle.js
```
- Recovers original variable/function names from minified code
- Supports inline base64 and adjacent-file sourcemaps
- Name replacement is applied to decoded code (structural analysis unaffected)

### Gap 5: File-hash cache (IMPLEMENTED)

**Status:** `--cache` flag enables MD5-based JSON file cache at `~/.cache/omega-unified/`.

```bash
# First run — normal scan
node ~/tools/omega-unified.js --cache bundle.js

# Second run — "Cache hit — skipping" if file unchanged
node ~/tools/omega-unified.js --cache bundle.js

# Batch mode with cache
node ~/tools/omega-unified.js --dir ./js/ --cache -f html -o batch.html
```
- Zero external dependencies (core `crypto` + `fs` only)
- Per-file cache keyed by absolute path (sanitized for filesystem)
- Silent failure if cache dir unwritable — scanning continues
- Cache miss triggers re-scan and automatic cache update

### Gap 6: Chunk dependency graph (IMPLEMENTED)

**Status:** `analyseChunkGraph()` (Phase 12p) wraps `lib/webpack-resolver.js`. Runs automatically in non-`--fast` mode.

```bash
# Runs automatically — chunk info in verbose phase output
node ~/tools/omega-unified.js --verbose bundle.js
  # chunk-graph             42ms

# Findings generated for:
#   chunk-hub (LOW): modules with >20 outgoing deps
#   chunk-admin-module (MEDIUM): admin logic in webpack chunks
#   chunk-hot-module (INFO): most-referenced modules
#   chunk-format (INFO): detected webpack version + module count
```
- Parses WP5 (`self["webpackChunk"].push`) and WP4 (`[[id],{...}]`) formats
- Module name heuristics: source-level hints (`require`), legacy ID map, source patterns
- No `--chunk-graph` flag needed — always-on in full scan

### Gap 7: GitHub Annotation format (IMPLEMENTED)

**Status:** `--format github-annotation` emits GitHub-native `::error`/`::warning`/`::notice` annotations.

```bash
node ~/tools/omega-unified.js --format github-annotation bundle.js
```
- Severity map: CRITICAL/HIGH → `error`, MEDIUM/LOW → `warning`, INFO → `notice`
- File paths localized per-finding (batch mode)
- Direct CI integration — no SARIF parser needed

### Gap 8: Live URL verification (IMPLEMENTED)

**Status:** `--verify` flag performs HTTP(S) requests on discovered endpoints after scanning.

```bash
node ~/tools/omega-unified.js --verify bundle.js
```
- Concurrent verification (batch size 5, 5s timeout)
- Skips non-HTTP URLs (ws://, wss://, etc.)
- Reports reachable status codes
- Works with `--cache`: cached results also get verified
