# Ω Omega Unified Scanner

**Zero-dependency JavaScript security scanner** — decodes obfuscated JS bundles and detects XSS, prototype pollution, hardcoded credentials, crypto misuse, AST-based taint flow, eval/Funcion() sinks, and 50+ vulnerability classes. Achieves **273 findings** on OWASP Juice Shop 20.1.1 in 10.7s.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Output Formats](#output-formats)
- [How It Works](#how-it-works)
- [Suppression Comments](#suppression-comments)
- [Benchmarks](#benchmarks)
- [File Structure](#file-structure)
- [Requirements](#requirements)

---

## Features

- **Zero npm dependencies** — runs on Node.js core only
- **AST-based taint tracking** — traces untrusted data through 5+ variable hops
- **Decode pipeline** — resolves Webpack wrappers, charCode/base64/hex obfuscation, Angular Ivy/Vue3/React/Svelte symbols, beautifies output
- **50+ detection scanners** — XSS, prototype pollution, eval, crypto misuse, hardcoded secrets, WebSocket hijacking, command injection, IDOR, race conditions, Web3/blockchain
- **Multiple output formats** — text, JSON, HTML, Markdown, SARIF
- **Suppression comments** — `// omega-ignore: rule-id` for false positives
- **Attack surface scoring** — weighted CRITICAL/HIGH/MEDIUM/LOW risk levels

## Quick Start

```bash
# Ensure Node.js v18+
node --version

# Create minimal package.json for module resolution
cat > package.json << 'EOF'
{ "name": "omega-unified", "version": "5.0.0", "private": true, "main": "omega-unified.js" }
EOF

# Scan a file
node omega-unified.js bundle.js

# Generate HTML report
node omega-unified.js -f html -o report.html bundle.js
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
# Quick scan
node omega-unified.js bundle.js

# JSON report for programmatic parsing
node omega-unified.js -f json -o report.json bundle.js

# Fast scan (skip extended scanners)
node omega-unified.js --fast bundle.js

# CI/CD integration with SARIF
node omega-unified.js -f sarif -o results.sarif bundle.js

# Verbose HTML report with phase timings
node omega-unified.js -f html -o scan.html --verbose bundle.js
```

## Output Formats

| Format  | Extension | Use Case              |
|---------|-----------|-----------------------|
| `text`  | stdout    | Terminal review       |
| `json`  | `.json`   | Programmatic parsing  |
| `html`  | `.html`   | Visual report         |
| `md`    | `.md`     | GitHub/GitLab notes   |
| `sarif` | `.sarif`  | CI/CD pipeline ingest |

## How It Works

The scanner processes JS files through 15 phases:

1. **Decode pipeline (Phases 0–7):** Resolves module aliases, unescapes strings, decodes charCode/base64/hex obfuscation, normalizes booleans, strips Webpack wrappers, annotates Angular Ivy / Vue3 / React / Svelte / Lodash / RxJS symbols, beautifies output
2. **Code analysis (Phase 8):** Counts functions/classes/components/services, measures cyclomatic complexity, identifies route guards, socket events
3. **Storage audit (Phase 8b):** Catalogs localStorage/sessionStorage/cookie keys, flags sensitive names
4. **Auth surface mapping (Phase 8c):** Finds protected vs unprotected endpoints
5. **Framework detection (Phase 9):** Identifies Angular/Vue/React/Svelte/Next.js/Webpack/Vite
6. **Route extraction (Phase 10):** Parses Angular/Vue/React route definitions
7. **Credential scanner (Phase 11):** 32 patterns — API keys, JWTs, AWS, Google OAuth, Stripe, tokens
8. **Security analysis (Phase 12):** XSS sinks, eval/Funcion(), Angular `bypassSecurityTrust*`, command injection, broken crypto, JWT secrets, window.open
9. **Extended scanners (Phases 12b–n, skip with `--fast`):** Dynamic code exec, business logic flaws, WebSocket XSS, crypto context, info leakage, IDOR, vulnerable dependencies, race conditions, **AST-based taint flow** (propagation through 5+ variable hops), Web3/blockchain, config-driven behavior, lazy loading
10. **Attack surface scoring:** Weighted score + risk level

## Suppression Comments

Suppress false positives by annotating the scanned file:

```js
// omega-ignore: xss-eval this is analyzed server-side
// omega-ignore: all suppress everything on this line
/* omega-ignore: leak-debug intentional for debugging */
// omega-ignore-next-line: crypto-broken-entropy
```

## Benchmarks

| Target | Size | Findings | Attack Surface | Time |
|--------|------|----------|---------------|------|
| Juice Shop 20.1.1 `main.js` | 766 KB | **273** (11 Critical) | 677 [CRITICAL] | 10.7s |
| Juice Shop 20.1.1 (all chunks) | 4.7 MB | ~290 total | — | ~30s |
| `test-target.js` (synthetic) | 1.4 KB | 10 | 47 [HIGH] | 0.7s |

Notable findings on Juice Shop:

| Class | Example |
|-------|---------|
| Hardcoded credentials | `IamUsedForTesting` |
| OAuth key exposure | Google OAuth client ID |
| Coupon codes | `WMNSDY2019`–`WMNSDY2023` |
| Angular XSS bypass | `bypassSecurityTrustHtml` |
| Prototype pollution | Multiple sinks detected |
| Unguarded admin routes | 12 unprotected endpoints |
| Taint flows (AST) | 43 flows, 160 variables tracked |

## File Structure

```
tools/
├── omega-unified.js          # Main scanner (1,907 lines)
├── js-decoder-omega.js       # v4 original (reference)
├── js-decoder-omega-v5.js    # v5 entry point (reference)
├── test-target.js            # Synthetic test input
├── package.json              # Module metadata
├── README.md
└── lib/
    ├── ast-parser.js         # Component-counting AST parser
    ├── call-chain.js         # Call chain analyser
    ├── config.js             # Suppression comment parser
    ├── crypto-patterns.js    # Crypto misuse detectors
    ├── esm-detector.js       # ESM module analyser
    ├── framework-inference.js# Framework detection
    ├── import-graph.js       # Import dependency graph
    ├── network-surface.js    # Network endpoint extraction
    ├── obfuscation.js        # Obfuscation decoder
    ├── sarif.js              # SARIF report generator
    ├── sourcemap.js          # Source map parser
    ├── taint-ast.js          # AST taint flow analyser (625 lines)
    ├── taint-tracker.js      # Regex taint tracker (legacy)
    ├── wasm-extractor.js     # WebAssembly binary extractor
    ├── webpack-resolver.js   # Webpack chunk resolver
    └── worker-pool.js        # Parallel worker pool
```

## Requirements

- **Node.js** v18+ (v20+ recommended)
- **Platforms:** Termux (Android), Linux, macOS, Windows
- **Dependencies:** Zero — no npm packages required
