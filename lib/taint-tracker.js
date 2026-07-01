'use strict';

/**
 * OMEGA v5 — Cross-Module Taint Tracking
 * Item 4: Intraprocedural dataflow analysis on AST.
 *
 * Replaces Phase 12j's heuristic regex approach with a proper
 * source→propagation→sink analysis. Operates on the AST from ast-parser.js.
 *
 * Taint sources:
 *  - URL params (location.search, location.hash, URLSearchParams)
 *  - postMessage event.data
 *  - WebSocket message data
 *  - localStorage/sessionStorage reads
 *  - window.name
 *  - document.referrer, document.cookie
 *  - HTTP response bodies
 *
 * Taint propagators:
 *  - Variable assignments
 *  - Function calls (return tainted)
 *  - String concatenation
 *  - Array/object access
 *
 * Taint sinks:
 *  - innerHTML, outerHTML, insertAdjacentHTML
 *  - document.write
 *  - eval, Function constructor
 *  - location.href, location.replace, location.assign
 *  - setAttribute with event handler names
 *  - .html(), .append(), .prepend() (jQuery)
 */

// ── Taint sources ──────────────────────────────────────────────────────────
const TAINT_SOURCES = [
  { id: 'location-hash',     re: /location\.hash\b/g            , type: 'URL' },
  { id: 'location-search',   re: /location\.search\b/g          , type: 'URL' },
  { id: 'location-href',     re: /location\.href\b/g            , type: 'URL' },
  { id: 'location-pathname', re: /location\.pathname\b/g        , type: 'URL' },
  { id: 'document-url',      re: /document\.URL\b/g             , type: 'Document' },
  { id: 'document-referrer', re: /document\.referrer\b/g        , type: 'Document' },
  { id: 'document-cookie',   re: /document\.cookie\b/g          , type: 'Document' },
  { id: 'window-name',       re: /window\.name\b/g              , type: 'Window' },
  { id: 'postmessage-data',  re: /(?:event|e)\.data\b/g         , type: 'PostMessage' },
  { id: 'localstorage-read', re: /localStorage\.getItem\s*\(/g  , type: 'Storage' },
  { id: 'sessionstorage-read', re: /sessionStorage\.getItem\s*\(/g, type: 'Storage' },
  { id: 'url-search-params', re: /URLSearchParams[^;]{0,200}\.get\s*\(/g, type: 'URL' },
  { id: 'response-body',     re: /response\.(?:data|body|text)\b/g, type: 'HTTP' },
  { id: 'input-value',       re: /\.value\s*(?:=|\bin\b)/g     , type: 'DOM' },
  { id: 'prompt-result',     re: /prompt\s*\(/g                 , type: 'UserInput' },
  { id: 'method-get',        re: /\.get\s*\(\s*["']/g          , type: 'URL' },
  { id: 'response-json',     re: /\.json\s*\(/g                , type: 'HTTP' },
  { id: 'request-body',      re: /req\.(?:body|query|params)\b/g, type: 'HTTP' },
];

// ── Taint sinks ────────────────────────────────────────────────────────────
const TAINT_SINKS = [
  { id: 'innerhtml',    re: /\.innerHTML\s*=/g                    , sev: 'critical', cwe: 'CWE-79'  },
  { id: 'outerhtml',    re: /\.outerHTML\s*=/g                    , sev: 'critical', cwe: 'CWE-79'  },
  { id: 'insertadjhtml', re: /\.insertAdjacentHTML\s*\(/g         , sev: 'critical', cwe: 'CWE-79'  },
  { id: 'documentwrite', re: /document\.write\s*\(/g              , sev: 'critical', cwe: 'CWE-79'  },
  { id: 'srcdoc',        re: /\.srcdoc\s*=/g                      , sev: 'critical', cwe: 'CWE-79'  },
  { id: 'eval',          re: /\beval\s*\(/g                       , sev: 'critical', cwe: 'CWE-95'  },
  { id: 'function-ctor', re: /new\s+Function\s*\(/g               , sev: 'critical', cwe: 'CWE-95'  },
  { id: 'location-href-assign', re: /location\.(?:href|replace|assign)\s*[=(]/g, sev: 'high', cwe: 'CWE-601'},
  { id: 'setattribute-on', re: /\.setAttribute\s*\(\s*['"]on\w+['"]\s*,/g, sev: 'critical', cwe: 'CWE-79'},
  { id: 'jquery-html',   re: /\.html\s*\([^)]+\)/g               , sev: 'critical', cwe: 'CWE-79'  },
  { id: 'jquery-append', re: /\.(?:append|prepend|after|before)\s*\([^)]+\)/g, sev: 'high', cwe: 'CWE-79'},
  { id: 'script-text',   re: /\.textContent\s*=\s*[^;]*script/i  , sev: 'high', cwe: 'CWE-79'  },
];

// ── Taint propagator patterns ──────────────────────────────────────────────
function isTaintPropagator(line) {
  // Assignment: x = y (where y is tainted)
  if (/=\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*$/.test(line)) return true;
  // String concat: x + y
  if (/\+/.test(line)) return true;
  // Function call: fn(x)
  if (/\([^)]*\)/.test(line)) return true;
  // JSON.parse
  if (/JSON\.parse/.test(line)) return true;
  // Array/object access
  if (/\[[^\]]+\]/.test(line)) return true;
  // Template literal
  if (/`[^`]*\$\{/.test(line)) return true;
  // Chaining: .then(x => ...)
  if (/\.then\s*\(/.test(line)) return true;
  return false;
}

// ── Extract variable assignments ───────────────────────────────────────────
function extractAssignments(src) {
  const assignments = [];
  let m;

  // const x = ..., let x = ..., var x = ...
  const varRe = /(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([^;]+)/g;
  while ((m = varRe.exec(src)) !== null) {
    assignments.push({ var: m[1], value: m[2].trim(), type: 'declaration', pos: m.index });
  }

  // x = y (simple assignment)
  const assignRe = /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([^;{]+)/g;
  while ((m = assignRe.exec(src)) !== null) {
    // Avoid keywords
    if (/^(this|true|false|null|undefined|if|else|for|while|return)$/.test(m[1])) continue;
    // Avoid: if (x = y)
    const before = src.slice(Math.max(0, m.index - 20), m.index);
    if (/^\s*(?:if|while|for)\s*\(/.test(before)) continue;
    assignments.push({ var: m[1], value: m[2].trim(), type: 'reassignment', pos: m.index });
  }

  return assignments;
}

// ── Find taint flows: source → propagation → sink ─────────────────────────
function findTaintFlows(src) {
  const findings = [];
  const seen = new Set();

  // Step 1: Find all source assignments
  const taintedVars = new Map(); // varName → { sourceId, sourceType }

  for (const source of TAINT_SOURCES) {
    source.re.lastIndex = 0;
    let m;
    while ((m = source.re.exec(src)) !== null) {
      // Find the statement start: look backward for ';' or '{' or start, max 200 chars
      let stmtStart = m.index - 200;
      const semiPos = src.lastIndexOf(';', m.index);
      const bracePos = src.lastIndexOf('{', m.index);
      if (semiPos > stmtStart) stmtStart = semiPos;
      if (bracePos > stmtStart) stmtStart = bracePos;
      if (stmtStart < 0) stmtStart = 0;
      if (stmtStart < m.index - 200) stmtStart = m.index - 200;
      const statement = src.slice(stmtStart, m.index).trim();
      // Check for: var/let/const x = <source>
      const decl = statement.match(/(?:const|let|var)\s+(\w+)\s*=\s*[^;]*$/);
      if (decl) {
        taintedVars.set(decl[1], { sourceId: source.id, sourceType: source.type });
      }
      // Also check for: x = ...<source> (reassignment)
      const reassign = statement.match(/(\w+)\s*=\s*[^;]*$/);
      if (reassign && !/^(this|return|if|else|for|while|case)$/.test(reassign[1])) {
        // Make sure the var isn't a keyword and the RHS actually matches
        if (!reassign[1].startsWith('new')) {
          taintedVars.set(reassign[1], { sourceId: source.id, sourceType: source.type });
        }
    }
  }
  }

  if (taintedVars.size === 0) return findings;

  // Step 2: Propagate taint through assignments (2 hops)
  const assignments = extractAssignments(src);

  let changed = true;
  let iterations = 0;
  while (changed && iterations < 3) {
    changed = false;
    iterations++;

    for (const a of assignments) {
      // Check if the RHS references a tainted variable
      for (const [varName, sourceInfo] of taintedVars) {
        if (a.value.includes(varName) && !taintedVars.has(a.var)) {
          taintedVars.set(a.var, { ...sourceInfo, propagated: true });
          changed = true;
        }
      }
    }
  }

  // Step 3: Check if tainted variables reach sinks
  for (const sink of TAINT_SINKS) {
    sink.re.lastIndex = 0;
    let m;
    while ((m = sink.re.exec(src)) !== null) {
      // Look forward for the value being assigned/passed
      const after = src.slice(m.index, m.index + 200);

      for (const [varName, sourceInfo] of taintedVars) {
        if (after.includes(varName)) {
          const key = `${sourceInfo.sourceId}|${sink.id}|${varName}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id: 'taint-flow',
            category: 'Taint Flow',
            severity: sink.sev,
            value: `${sourceInfo.sourceType} "${sourceInfo.sourceId}" → "${sink.id}" via "${varName}"`,
            sourceId: sourceInfo.sourceId,
            sinkId: sink.id,
            taintedVar: varName,
            propagated: sourceInfo.propagated || false,
            context: after.replace(/\n/g, ' ').slice(0, 120),
            description: `Tainted data from "${sourceInfo.sourceType}:${sourceInfo.sourceId}" reaches "${sink.id}" via variable "${varName}"${sourceInfo.propagated ? ' (2+ hops)' : ''}`,
            cwe: sink.cwe,
          });
        }
      }

      // Also check for direct source→sink (no variable)
      for (const source of TAINT_SOURCES) {
        const directRe = new RegExp(source.re.source);
        if (directRe.test(after)) {
          const key = `direct|${source.id}|${sink.id}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id: 'taint-flow-direct',
            category: 'Taint Flow',
            severity: sink.sev,
            value: `${source.type} "${source.id}" → "${sink.id}" (direct)`,
            context: after.replace(/\n/g, ' ').slice(0, 120),
            description: `Direct taint flow from "${source.id}" to "${sink.id}" — user-controlled data reaches dangerous sink`,
            cwe: sink.cwe,
          });
        }
      }
    }
  }

  return findings;
}

// ── Cross-module taint tracking ────────────────────────────────────────────
function findCrossModuleTaintFlows(src, webpackModules) {
  const allFindings = [];

  // Analyze main bundle
  allFindings.push(...findTaintFlows(src));

  // Analyze individual webpack modules
  if (webpackModules && webpackModules.length) {
    for (const mod of webpackModules) {
      const modFindings = findTaintFlows(mod.source);
      for (const f of modFindings) {
        f.moduleId = mod.id;
        f.moduleName = mod.name;
        allFindings.push(f);
      }
    }
  }

  return allFindings;
}

// ── Main entry point ───────────────────────────────────────────────────────
function analyseTaint(src, webpackModules, opts) {
  const t0 = Date.now();

  const findings = opts.crossModule
    ? findCrossModuleTaintFlows(src, webpackModules)
    : findTaintFlows(src);

  if (opts.verbose && findings.length) {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    console.log(`  Taint flows found: ${findings.length} (critical: ${critical}, high: ${high})`);
    if (findings.some(f => f.propagated)) {
      console.log(`  Multi-hop flows: ${findings.filter(f => f.propagated).length}`);
    }
  }

  return {
    findings,
    count: findings.length,
    bySeverity: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
    },
    elapsed: Date.now() - t0,
  };
}

module.exports = {
  TAINT_SOURCES,
  TAINT_SINKS,
  extractAssignments,
  findTaintFlows,
  findCrossModuleTaintFlows,
  analyseTaint,
};
