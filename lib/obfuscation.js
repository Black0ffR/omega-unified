'use strict';

/**
 * OMEGA v5 — Generic Obfuscation Detector
 * Item 14: Replace Phase 2b's hardcoded CharCode decoder with a generic
 * String.fromCharCode(arithmetic) reconstruction engine.
 *
 * Finds every fromCharCode(...) call site, constant-folds the arithmetic
 * expressions in the args, and emits decoded strings.
 *
 * Detects:
 *  - fromCharCode(x - y - offset - i)  (Juice Shop style)
 *  - fromCharCode(x * y + z)           (general arithmetic)
 *  - fromCharCode(x ^ y)               (xor-based)
 *  - fromCharCode(a, b, c)             (direct)
 *  - Nested fromCharCode in map/reduce
 *  - fromCharCode in reverse().map() chains
 */

const C = { reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m', green:'\x1c[32m', cyan:'\x1c[36m', yellow:'\x1c[33m' };

// ── Constant-folding expression evaluator ──────────────────────────────────
function evalExpression(expr, knownVars) {
  expr = expr.trim();

  // Literal number
  if (/^-?\d+$/.test(expr)) return parseInt(expr, 10);
  if (/^-?0x[0-9a-fA-F]+$/.test(expr)) return parseInt(expr, 16);

  // Variable lookup
  if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(expr) && knownVars.has(expr)) {
    return knownVars.get(expr);
  }

  // Addition: a + b
  const addParts = splitOnTopLevel(expr, '+');
  if (addParts.length > 1) {
    const results = addParts.map(p => evalExpression(p.trim(), knownVars));
    if (results.every(r => r !== null)) {
      return results.reduce((a, b) => a + b, 0);
    }
  }

  // Subtraction: a - b
  const subParts = splitOnTopLevel(expr, '-');
  if (subParts.length > 1) {
    const results = subParts.map(p => evalExpression(p.trim(), knownVars));
    if (results.every(r => r !== null)) {
      return results.reduce((a, b) => a - b);
    }
  }

  // Multiplication: a * b
  const mulParts = splitOnTopLevel(expr, '*');
  if (mulParts.length > 1) {
    const results = mulParts.map(p => evalExpression(p.trim(), knownVars));
    if (results.every(r => r !== null)) {
      return results.reduce((a, b) => a * b, 1);
    }
  }

  // Bitwise XOR: a ^ b
  const xorParts = splitOnTopLevel(expr, '^');
  if (xorParts.length > 1) {
    const results = xorParts.map(p => evalExpression(p.trim(), knownVars));
    if (results.every(r => r !== null)) {
      return results.reduce((a, b) => a ^ b);
    }
  }

  // Bitwise AND: a & b
  const andParts = splitOnTopLevel(expr, '&');
  if (andParts.length > 1) {
    const results = andParts.map(p => evalExpression(p.trim(), knownVars));
    if (results.every(r => r !== null)) {
      return results.reduce((a, b) => a & b);
    }
  }

  // Parenthesized: (expr)
  if (expr.startsWith('(') && expr.endsWith(')')) {
    return evalExpression(expr.slice(1, -1), knownVars);
  }

  return null;
}

// Split on operator at top level (not inside parentheses)
function splitOnTopLevel(str, op) {
  const parts = [];
  let depth = 0;
  let current = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (depth === 0 && ch === op) {
      // Verify it's the operator, not part of a larger token
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current) parts.push(current);
  return parts;
}

// ── Extract variable values from IIFE context ──────────────────────────────
function extractIIFEVars(src, matchPos) {
  const knownVars = new Map();

  // Look backward from the match position for variable declarations
  const before = src.slice(Math.max(0, matchPos - 2000), matchPos);

  // Extract var/const/let assignments near the match
  const varRe = /(?:var|const|let)\s+(\w+)\s*=\s*(\d+|0x[0-9a-fA-F]+)/g;
  let m;
  while ((m = varRe.exec(before)) !== null) {
    const val = parseInt(m[2], 10);
    if (!isNaN(val)) knownVars.set(m[1], val);
  }

  // Extract seed argument: function(seed, ...) { ... }(SEED, ...)
  const iifeRe = /\}\s*\(\s*(\d+)/g;
  while ((m = iifeRe.exec(before)) !== null) {
    knownVars.set('seed', parseInt(m[1], 10));
  }

  return knownVars;
}

// ── Find and decode fromCharCode patterns ──────────────────────────────────
function findFromCharCodePatterns(src) {
  const findings = [];
  const seen = new Set();

  // Pattern 1: String.fromCharCode(a, b, c, ...) — direct
  const directRe = /String\.fromCharCode\s*\(\s*(\d+(?:\s*,\s*\d+)*)\s*\)/g;
  let m;
  while ((m = directRe.exec(src)) !== null) {
    const codes = m[1].split(',').map(x => parseInt(x.trim(), 10)).filter(n => !isNaN(n));
    if (codes.length < 2) continue;
    const decoded = codes.map(c => String.fromCharCode(c)).join('');
    if (!/^[\x20-\x7e]+$/.test(decoded) || decoded.length < 2) continue;
    if (seen.has(decoded)) continue;
    seen.add(decoded);
    findings.push({
      decoded,
      type: 'direct',
      args: codes,
      context: src.slice(Math.max(0, m.index - 30), m.index + 50).replace(/\n/g, ' '),
    });
  }

  // Pattern 2: fromCharCode with arithmetic expressions
  const arithRe = /String\.fromCharCode\s*\(([^)]+)\)/g;
  arithRe.lastIndex = 0;
  while ((m = arithRe.exec(src)) !== null) {
    // Skip if already matched as direct
    if (/^\d+(?:\s*,\s*\d+)*$/.test(m[1])) continue;

    const knownVars = extractIIFEVars(src, m.index);
    const args = m[1].split(',').map(a => a.trim());
    const codes = args.map(a => {
      const val = evalExpression(a, knownVars);
      return val !== null ? val : NaN;
    }).filter(n => !isNaN(n));

    if (codes.length < 2) continue;
    const decoded = codes.map(c => String.fromCharCode(c)).join('');
    if (!/^[\x20-\x7e]+$/.test(decoded) || decoded.length < 2) continue;
    if (seen.has(decoded)) continue;
    seen.add(decoded);
    findings.push({
      decoded,
      type: 'arithmetic',
      args: codes,
      expr: m[1].slice(0, 80),
      context: src.slice(Math.max(0, m.index - 30), m.index + 50).replace(/\n/g, ' '),
    });
  }

  // Pattern 3: fromCharCode inside reverse().map() chains (obfuscation)
  const mapRe = /reverse\s*\(\s*\)\s*\.\s*map\s*\(\s*(?:function\s*\([^)]*\)|[^)=>\s]+\s*=>)\s*\{[^}]*String\.fromCharCode\s*\(([^)]+)\)[^}]*\}\s*\)\s*\.\s*join\s*\(\s*["']["']\s*\)/g;
  while ((m = mapRe.exec(src)) !== null) {
    const knownVars = extractIIFEVars(src, m.index);
    const args = m[1].split(',').map(a => a.trim());

    // Try to find seed: look for the IIFE call
    const callMatch = src.slice(m.index, m.index + 100).match(/\(\s*(\d+)\s*,/);
    const seed = callMatch ? parseInt(callMatch[1], 10) : 0;

    // Extract offset from expression pattern: o - e - OFFSET - a
    const offsetMatch = m[1].match(/-?\s*(\d+)/g);
    let totalOffset = 0;
    if (offsetMatch) {
      totalOffset = offsetMatch.map(x => parseInt(x, 10)).filter(n => !isNaN(n)).reduce((a, b) => a + b, 0);
    }

    // Try to decode: reverse, then map with (value - seed - offset - index)
    const bytes = args.map(a => {
      const val = evalExpression(a, knownVars);
      return val !== null ? val : NaN;
    }).filter(n => !isNaN(n));

    // Different offset variants
    for (const offset of [totalOffset, totalOffset + 24, totalOffset + 42, totalOffset - 24, totalOffset - 42]) {
      const decoded = bytes.slice().reverse().map((o, a) => String.fromCharCode(o - seed - offset - a)).join('');
      if (/^[\x20-\x7e]{2,}$/.test(decoded) && !seen.has(decoded)) {
        seen.add(decoded);
        findings.push({
          decoded,
          type: 'reverse-map',
          seed,
          offset,
          bytes: bytes.length,
          context: src.slice(Math.max(0, m.index - 40), m.index + 60).replace(/\n/g, ' '),
        });
        break;
      }
    }
  }

  // Pattern 4: Charcode via charCodeAt or charAt
  // (often used in string-based obfuscation)

  // Sort by longest decoded string first (most interesting)
  findings.sort((a, b) => b.decoded.length - a.decoded.length);

  return findings;
}

// ── Inject decoded strings as comments ─────────────────────────────────────
function injectDecodedComments(src, findings) {
  let result = src;
  for (const f of findings) {
    result = result.replace(
      /String\.fromCharCode\s*\(/,
      `/* OMEGA-decoded: "${f.decoded}" */\nString.fromCharCode(`
    );
  }
  return result;
}

// ── Main entry point ───────────────────────────────────────────────────────
function decodeObfuscation(src, opts) {
  const t0 = Date.now();

  const findings = findFromCharCodePatterns(src);

  if (findings.length && opts.verbose) {
    console.log(`  Generic obfuscation decoded: ${findings.length} string(s)`);
    for (const f of findings.slice(0, 5)) {
      console.log(`    → "${f.decoded}" (${f.type})`);
    }
  }

  let srcOut = src;
  if (findings.length) {
    srcOut = injectDecodedComments(src, findings);
  }

  return {
    findings,
    src: srcOut,
    count: findings.length,
    elapsed: Date.now() - t0,
  };
}

module.exports = {
  evalExpression,
  findFromCharCodePatterns,
  injectDecodedComments,
  decodeObfuscation,
};
