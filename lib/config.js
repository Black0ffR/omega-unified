'use strict';

/**
 * OMEGA v5 — Configurable Rule Packs + Suppression
 * Item 13: .omegalintrc JSON config file for rule enable/disable, severity
 * overrides, and suppression comments.
 *
 * Suppression comment formats:
 *   // omega-ignore: rule-id                    — suppress on THIS line
 *   // omega-ignore: rule-id reason text        — with reason
 *   /* omega-ignore: rule-id *​/                 — block form
 *   // omega-ignore: rule-id, rule-id2          — multiple rules
 *   // omega-ignore: all                        — suppress all rules on this line
 *
 * Config format (.omegalintrc):
 *   {
 *     "rules": { "xss-innerhtml": "off" },
 *     "severityOverrides": { "bl-balance": "critical" },
 *     "suppressions": [{ "rule": "leak-debug", "file": "*", "reason": "dev-only" }],
 *     "output": { "sarif": true, "html": true, "json": true, "md": true }
 *   }
 */

const fs = require('fs');
const path = require('path');

const CONFIG_FILE_NAMES = ['.omegalintrc', '.omegalintrc.json', 'omegalint.json', 'omega.config.json'];

const DEFAULT_RULE_SEVERITY = {
  // Phase 11 — Credential scanner
  'Hardcoded Password': 'error',
  'Hardcoded Credential': 'error',
  'Hardcoded API Key': 'error',
  'JWT Secret': 'error',
  'Private Key': 'error',
  'AWS Access Key': 'error',
  'AWS Secret Key': 'error',
  'Stripe Key': 'error',
  'GitHub Token': 'error',
  'MongoDB URI': 'error',
  'Slack Token': 'error',

  // Phase 12 — Security patterns
  'xss-write': 'error',
  'xss-innerhtml': 'warn',
  'xss-eval': 'error',
  'xss-new-func': 'error',
  'xss-outerhtml': 'error',
  'xss-insertadj': 'error',
  'xss-srcdoc': 'error',
  'xss-jquery-html': 'warn',
  'xss-set-attr-on': 'error',
  'xss-location-href': 'warn',
  'xss-loc-replace': 'warn',

  'sqli-concat': 'error',
  'cmd-injection': 'error',

  'proto-assign': 'error',
  'proto-merge': 'warn',

  'postmsg-wildcard': 'warn',

  'crypto-ecb': 'error',
  'crypto-static-iv': 'warn',
  'crypto-privkey': 'error',
  'crypto-det-seed': 'warn',

  'dyncode-Function-constructor': 'error',
  'dyncode-indirect-eval': 'error',
  'dyncode-setTimeout/Interval-string': 'warn',

  'bl-ratelimit': 'warn',
  'bl-balance': 'warn',
  'bl-coupon': 'warn',
  'bl-hardcoded-coupon': 'error',
  'bl-access-control': 'info',

  'ws-dom-sink': 'error',
  'ws-code-exec': 'error',
  'ws-sensitive-emit': 'warn',

  'idor-url-id': 'warn',
  'idor-qp': 'warn',
  'idor-ls-id': 'warn',

  'race-ls-rw': 'warn',
  'race-promise-ls': 'warn',
  'race-counter': 'warn',

  'taint-flow': 'warn',

  'web3-privkey': 'error',
  'web3-sendtx': 'warn',
  'web3-sig-replay': 'warn',

  'cfg-sec-disable': 'error',
  'cfg-cors-wildcard': 'warn',
  'cfg-hardcoded-url': 'info',

  'lazy-unguarded': 'warn',
  'lazy-dyn-import': 'warn',

  'leak-path': 'info',
  'sourcemap-ref': 'info',
  'network-socket': 'info',
  'network-http-open': 'info',
  'storage-local': 'info',
  'storage-session': 'info',
  'angular-guard': 'info',
  'worker-new': 'info',
};

// ── Load config ────────────────────────────────────────────────────────────
function loadConfig(cliOpts) {
  const config = {
    rules: { ...DEFAULT_RULE_SEVERITY },
    severityOverrides: {},
    suppressions: [],
    output: { sarif: false, html: true, json: true, md: true },
  };

  if (cliOpts.config) {
    if (fs.existsSync(cliOpts.config)) {
      mergeConfig(config, loadConfigFile(cliOpts.config));
    }
  } else {
    const cwd = process.cwd();
    let dir = cwd;
    while (true) {
      for (const name of CONFIG_FILE_NAMES) {
        const p = path.join(dir, name);
        if (fs.existsSync(p)) {
          mergeConfig(config, loadConfigFile(p));
          return config;
        }
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }

  return config;
}

function loadConfigFile(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error(`Warning: Could not load config ${filePath}: ${e.message}`);
    return {};
  }
}

function mergeConfig(base, override) {
  if (override.rules) {
    for (const [key, value] of Object.entries(override.rules)) {
      if (value === 'off') {
        delete base.rules[key];
      } else {
        base.rules[key] = value;
      }
    }
  }
  if (override.severityOverrides) {
    for (const [key, value] of Object.entries(override.severityOverrides)) {
      base.severityOverrides[key] = value;
    }
  }
  if (override.suppressions) {
    base.suppressions = base.suppressions.concat(override.suppressions);
  }
  if (override.output) {
    Object.assign(base.output, override.output);
  }
  if (override.extend) {
    const extPath = path.resolve(path.dirname(base._configPath || process.cwd()), override.extend);
    if (fs.existsSync(extPath)) {
      mergeConfig(base, loadConfigFile(extPath));
    }
  }
}

// ── Apply config to a finding ──────────────────────────────────────────────
function applyConfigToFinding(finding, config) {
  const ruleId = finding.id || finding.name;

  if (config.rules[ruleId] === 'off') return null;

  let effectiveSev = finding.severity || finding.sev || 'info';
  if (config.severityOverrides[ruleId]) {
    effectiveSev = config.severityOverrides[ruleId];
  }

  const ruleLevel = config.rules[ruleId];
  if (ruleLevel === 'error') {
    if (effectiveSev !== 'critical') effectiveSev = 'high';
  } else if (ruleLevel === 'warn') {
    if (effectiveSev === 'critical' || effectiveSev === 'high') effectiveSev = 'medium';
  } else if (ruleLevel === 'info') {
    effectiveSev = 'info';
  }

  for (const sup of config.suppressions) {
    if (sup.rule === ruleId || sup.rule === '*') {
      return null;
    }
  }

  return { ...finding, severity: effectiveSev };
}

// ── Suppression comment parsing ────────────────────────────────────────────

/**
 * Parse inline suppression comments from source code.
 * Returns a Map of lineNumber → { rules: Set, reasons: Map<rule, string> }
 */
function parseSuppressionComments(src) {
  const lines = src.split('\n');
  const suppressions = new Map();

  // Single-line: // omega-ignore: rule-id [reason]
  // Also // omega-ignore: rule1, rule2
  const singleRe = /\/\/\s*omega-ignore:\s*(.+)/i;
  // Block: /* omega-ignore: rule-id [reason] */
  const blockRe = /\/\*\s*omega-ignore:\s*(.+?)\s*\*\//gi;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(singleRe);
    if (m) {
      const rest = m[1].trim();
      const rules = rest.split(',').map(s => s.trim());
      // Determine which line is suppressed
      const targetLine = rest.toLowerCase().includes('next-line') ? i + 2 : i + 1;

      for (const entry of rules) {
        const parts = entry.split(/\s+/);
        const rule = parts[0].toLowerCase();
        const reason = parts.slice(1).join(' ') || '';
        if (rule === 'next-line') continue;

        if (!suppressions.has(targetLine)) {
          suppressions.set(targetLine, { rules: new Set(), reasons: new Map() });
        }
        const sup = suppressions.get(targetLine);
        sup.rules.add(rule);
        if (reason) sup.reasons.set(rule, reason);
      }
    }

    // Block comments — check for /* omega-ignore: ... */
    blockRe.lastIndex = 0;
    let bm;
    while ((bm = blockRe.exec(line)) !== null) {
      const rest = bm[1].trim();
      const rules = rest.split(',').map(s => s.trim());
      const targetLine = i + 1;

      for (const entry of rules) {
        const parts = entry.split(/\s+/);
        const rule = parts[0].toLowerCase();
        const reason = parts.slice(1).join(' ') || '';

        if (!suppressions.has(targetLine)) {
          suppressions.set(targetLine, { rules: new Set(), reasons: new Map() });
        }
        const sup = suppressions.get(targetLine);
        sup.rules.add(rule);
        if (reason) sup.reasons.set(rule, reason);
      }
    }
  }

  return suppressions;
}

/**
 * Check if a finding at a given line should be suppressed.
 * @param {Map} suppressionMap — from parseSuppressionComments
 * @param {Object} finding — { id, name } (uses id or name as rule ID)
 * @param {number} lineNumber — 1-indexed line number
 * @returns {string|false} — reason string if suppressed, false otherwise
 */
function isFindingSuppressed(suppressionMap, finding, lineNumber) {
  if (!suppressionMap || suppressionMap.size === 0) return false;

  const ruleId = (finding.id || finding.name || '').toLowerCase();
  const sup = suppressionMap.get(lineNumber);
  if (!sup) return false;

  if (sup.rules.has('all')) {
    const reason = sup.reasons.get('all') || '';
    return reason || 'suppressed by omega-ignore: all';
  }

  if (sup.rules.has(ruleId)) {
    const reason = sup.reasons.get(ruleId) || '';
    return reason || 'suppressed by omega-ignore comment';
  }

  return false;
}

/**
 * Apply suppression comments to a list of findings.
 * Returns { findings, suppressedCount, suppressionReasons }
 */
function applySuppressions(findings, suppressionMap) {
  const filtered = [];
  let suppressedCount = 0;
  const suppressionReasons = [];

  for (const f of findings) {
    const line = f.line || f.lineNumber || 0;
    const reason = isFindingSuppressed(suppressionMap, f, line);
    if (reason) {
      suppressedCount++;
      suppressionReasons.push({
        rule: f.id || f.name || 'unknown',
        line,
        reason,
        value: (f.value || '').slice(0, 60),
      });
    } else {
      filtered.push(f);
    }
  }

  return { findings: filtered, suppressedCount, suppressionReasons };
}

/**
 * Strip suppression comment markers from source (for cleaner output).
 */
function stripSuppressionComments(src) {
  return src
    .replace(/\/\/\s*omega-ignore:\s*[\w\-, ]+(\s+next-line)?.*\n?/gi, '')
    .replace(/\/\*\s*omega-ignore:\s*[\w\-, ]+\s*\*\//gi, '');
}

function isOutputEnabled(config, format) {
  return config.output[format] !== false;
}

module.exports = {
  loadConfig,
  loadConfigFile,
  mergeConfig,
  applyConfigToFinding,
  parseSuppressionComments,
  isFindingSuppressed,
  applySuppressions,
  stripSuppressionComments,
  isOutputEnabled,
  DEFAULT_RULE_SEVERITY,
};
