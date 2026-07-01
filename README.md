# Omega Unified Scanner

Merged v4+v5 JavaScript security scanner — decodes and analyzes JS bundles for credentials, XSS, network surfaces, crypto misuse, IDOR, AST-based taint flow analysis, Web3 vulnerabilities, and more. Zero external dependencies. Achieves **273 findings** on OWASP Juice Shop 20.1.1 in 10.7s.

## Quick Start (Termux)

```bash
# 1. Prerequisites — Node.js is required
node --version          # should be v18+

# 2. Create package.json (needed for lib/ module resolution)
cd ~/tools
cat > package.json << 'EOF'
{ "name": "omega-unified", "version": "5.0.0", "private": true, "main": "omega-unified.js" }
EOF

# 3. Run a scan
node omega-unified.js test-target.js

# Full scan with report
node omega-unified.js -f html -o scan-report.html js-decoder-omega.js
```

## CLI Usage

```
node omega-unified.js [options] <file.js>

Options:
  -f, --format <type>    Report format: text|json|html|md|sarif  (default: text)
  -o, --output <file>    Write report to file
  -q, --quiet            Suppress progress output
  -v, --verbose          Show phase timings and details
  --fast                 Skip extended scanners (reduces runtime ~2x)
  --no-color             Disable ANSI colors
  --config <file>        Load config for suppression comments
  -h, --help             Show help
  --version              Show version
```

### Examples

```bash
# Quick scan, default text output
node omega-unified.js bundle.js

# Full scan with JSON report
node omega-unified.js -f json -o report.json bundle.js

# Scan without extended scanners (faster)
node omega-unified.js --fast bundle.js

# SARIF output for CI integration
node omega-unified.js -f sarif -o results.sarif bundle.js

# HTML report with verbose phase info
node omega-unified.js -f html -o scan.html --verbose bundle.js
```

## Output Formats

| Format    | Extension  | Use Case              |
|-----------|------------|-----------------------|
| `text`    | stdout     | Terminal review       |
| `json`    | `.json`    | Programmatic parsing  |
| `html`    | `.html`    | Visual report         |
| `md`      | `.md`      | GitHub/GitLab notes   |
| `sarif`   | `.sarif`   | CI/CD pipeline ingest |

## How It Works

1. **Decode pipeline** (Phases 0-7): resolves module aliases, unescapes strings, decodes charCode/base64/hex obfuscation, normalizes booleans, strips Webpack wrappers, annotates Angular Ivy / Vue3 / React / Svelte / Lodash / RxJS symbols, beautifies output
2. **Code analysis** (Phase 8): counts functions/classes/components/services, measures cyclomatic complexity, identifies route guards, socket events
3. **Storage audit** (Phase 8b): catalogs localStorage/sessionStorage/cookie keys, flags sensitive names
4. **Auth surface mapping** (Phase 8c): finds protected vs unprotected endpoints
5. **Framework detection** (Phase 9): identifies Angular/Vue/React/Svelte/Next.js/Webpack/Vite
6. **Route extraction** (Phase 10): parses Angular/Vue/React route definitions
7. **Credential scanner** (Phase 11): 32 patterns — API keys, JWTs, AWS, Google OAuth, Stripe, tokens
8. **Security analysis** (Phase 12): XSS sinks, eval/Function(), Angular `bypassSecurityTrust*`, command injection, broken crypto, JWT secrets, window.open
9. **Extended scanners** (Phase 12b-n, skip with `--fast`): dynamic code exec, business logic flaws, WebSocket XSS, crypto context, info leakage, IDOR, vulnerable dependencies, race conditions, **AST-based taint flow** (propagation through 5+ variable hops), Web3/blockchain, config-driven behaviour, lazy loading
10. **Attack surface scoring**: weighted score + risk level (CRITICAL/HIGH/MEDIUM/LOW)

## Suppression Comments

Suppress false positives by adding comments to the scanned file:

```js
// omega-ignore: xss-eval this is analyzed server-side
// omega-ignore: all suppress everything on this line
/* omega-ignore: leak-debug intentional for debugging */
// omega-ignore-next-line: crypto-broken-entropy
```

## Upload to GitHub

```bash
cd ~/tools

# Create package.json (if you haven't already)
cat > package.json << 'EOF'
{ "name": "omega-unified", "version": "5.0.0", "private": true, "main": "omega-unified.js" }
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
node_modules/
report.*.json
omega_output/
*.log
EOF

git init
git add -A
git commit -m "Initial: omega-unified v5 — merged JS security scanner"

# Create repo and push (requires GitHub CLI)
gh repo create omega-unified --public --push --source=.
```

To push to an existing repo instead:

```bash
git remote add origin https://github.com/YOUR_USER/omega-unified.git
git branch -M main
git push -u origin main
```

## File Structure

```
tools/
├── omega-unified.js        # Main merged script (1,880 lines)
├── js-decoder-omega.js      # v4 original (reference)
├── js-decoder-omega-v5.js   # v5 entry point (reference)
├── test-target.js           # Small test input
├── package.json             # Module metadata
├── README.md                # This file
└── lib/
    ├── ast-parser.js
    ├── call-chain.js
    ├── config.js             # Suppression comment parser
    ├── crypto-patterns.js
    ├── esm-detector.js
    ├── framework-inference.js
    ├── import-graph.js
    ├── network-surface.js
    ├── obfuscation.js
    ├── sarif.js
    ├── sourcemap.js
    ├── taint-ast.js           # AST-based taint flow analyzer (541 lines)
    ├── taint-tracker.js
    ├── wasm-extractor.js
    ├── webpack-resolver.js
    └── worker-pool.js
```

## Real-World Benchmarks

| Target | Size | Findings | Attack Surface | Time |
|--------|------|----------|---------------|------|
| OWASP Juice Shop 20.1.1 `main.js` | 766 KB | **273** (11 Critical) | 677 [CRITICAL] | 10.7s |
| OWASP Juice Shop 20.1.1 (all chunks) | 4.7 MB | ~290 total | — | ~30s |
| `test-target.js` (synthetic) | 1.4 KB | 8 | 27 [MEDIUM] | 0.5s |

Notable findings on Juice Shop:
- Hardcoded credentials (`IamUsedForTesting`)
- Google OAuth client ID
- 5 coupon codes (`WMNSDY2019`-`2023`)
- `bypassSecurityTrustHtml` (Angular XSS bypass)
- Prototype pollution sinks
- 12 unguarded admin routes
- 43 taint flows (AST-detected, 160 tainted variables tracked)

## Requirements

- Node.js v18+ (v20+ recommended)
- Termux on Android or any Linux/macOS/Windows environment
- No npm dependencies — zero external packages
