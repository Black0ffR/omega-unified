# JS Analysis Workflow

End-to-end pipeline for JavaScript security analysis on Termux. Combines custom tools (`omega-unified.js`, `js-decoder-omega.js`) with external tools (`gau`, `katana`, `subjs`) and the BB Omega Suite (`termscan.py`, `jsreaper.py`).

---

## Pipeline Overview

```
PHASE 1: HARVEST     → Collect JS files from target
PHASE 2: DECODE      → Deobfuscate, beautify, unpack webpack
PHASE 3: DEEP SCAN   → 50+ security scanners + AST taint tracking
PHASE 4: CROSS-FILE  → Correlate credentials across files
PHASE 5: WEB3 SCAN   → Blockchain/Web3-specific patterns
PHASE 6: REPORT      → SARIF, HTML, JSON, Markdown
PHASE 7: VALIDATE    → Manual verification in browser/Burp
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

## Gaps & Suggested Improvements

### Gap 1: No directory/batch mode in omega-unified

**Current:** Scans one file at a time. Running 50 JS files means running the command 50 times.

**Suggested:**
```bash
# --dir mode: process all .js files in a directory, produce one consolidated report
node ~/tools/omega-unified.js --dir ~/recon/$TARGET/js/ -o consolidated-report.json
```
- Aggregate findings across files (count how many files have `innerHTML` sinks)
- Cross-file credential correlation (same key appears in 3 chunks)
- Summary metrics (X files scanned, Y findings, top categories)
- Chunk overlap detection (same route/endpoint in multiple chunks)

### Gap 2: No URL crawling in omega-unified

**Current:** Requires already-downloaded files. No `omega-unified --url https://target.com/bundle.js`.

**Suggested:**
```bash
# --url mode: download + scan in one command
node ~/tools/omega-unified.js --url https://target.com/static/js/main.js
```
- `curl` + pipe to scanners
- Follow sourcemap links automatically
- Optional: `--crawl` to find additional JS from `<script src>` tags

### Gap 3: No service worker analysis

**Current:** Neither omega-unified nor termscan have dedicated SW scanners.

**Suggested:** Add scanner for:
```javascript
// In omega-unified Phase 12b-n or new phase:
// navigator.serviceWorker.register(url) — is the SW from a controllable path?
// self.addEventListener('fetch', ...) — does SW intercept and modify requests?
// self.addEventListener('message', ...) — does SW trust origin?
// caches.open(...) — cache poisoning potential
// skipWaiting / clients.claim — immediate takeover
```
See `[OK] service-worker-attacks` skill for full methodology.

### Gap 4: No sourcemap auto-follow

**Current:** Sourcemaps must be manually discovered and fetched.

**Suggested:**
```bash
# In decode pipeline (Phase 0):
# If //# sourceMappingURL= found, auto-fetch and decode
curl -s "https://target.com/bundle.js.map" | node ~/tools/omega-unified.js --sourcemap -
```
- Recover original source from .map files
- Compare minified vs original findings delta

### Gap 5: No batch resume/cache

**Current:** Re-running omega-unified on a large bundle re-does all work.

**Suggested:** Add SQLite cache (similar to termux-js-secret-scanner):
```bash
node ~/tools/omega-unified.js --cache ~/omega-cache.db bundle.js
```
- File hash → cached results
- Only re-scan on hash change
- Mandatory for directory batch mode

### Gap 6: No chunk dependency graph

**Current:** `lib/webpack-resolver.js` exists but is not wired into the main pipeline.

**Suggested:** In Phase 12, add:
```bash
node ~/tools/omega-unified.js --chunk-graph ~/recon/$TARGET/js/ --entry main.js
```
- Parse Webpack runtime to find chunk IDs
- Build import graph: `main.js` → `vendors~main.chunk.js` → `admin.chunk.js`
- Flag "admin-only code in public chunk" issues
- Cross-chunk taint tracking (if tainted data flows from main to a lazy chunk)

### Gap 7: No CI/CD formatting flag

**Current:** SARIF output exists but no GitHub-native annotations.

**Suggested:**
```bash
--format github-annotation
```
- Output `::warning file=bundle.js,line=42::XSS sink detected`
- Direct CI integration without SARIF parser

### Gap 8: No live URL verification

**Current:** Scans static files. No way to verify findings against live endpoints.

**Suggested:** Optional follow-up to Phase 7:
```bash
# --verify: for each API endpoint found, try a test request
node ~/tools/omega-unified.js --verify --auth "Bearer $TOKEN" bundle.js
```
- Check if discovered endpoints are actually accessible
- Check if discovered API keys are still valid
- Rate-limit awareness (--delay 1000ms)
