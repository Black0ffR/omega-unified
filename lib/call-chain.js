'use strict';

/**
 * OMEGA v5 — Real Call-Chain Reporting
 * Item 8: Walk AST → sinks/entries → render as collapsible tree.
 *
 * Given a finding (sink), walks backward through the AST to build
 * the call chain: entry point → calls → ... → sink. Renders as
 * a collapsible tree in the HTML report.
 */

// ── Find entry points (event handlers, HTTP handlers) ─────────────────────
function findEntryPoints(src) {
  const entries = [];
  let m;

  // Angular component initialization
  const ngInitRe = /\bngOnInit\s*\(\s*\)\s*\{/g;
  while ((m = ngInitRe.exec(src)) !== null) {
    entries.push({ type: 'Angular:ngOnInit', pos: m.index });
  }

  // Event listeners
  const listenerRe = /\.addEventListener\s*\(\s*["']([^"']+)["']\s*,/g;
  while ((m = listenerRe.exec(src)) !== null) {
    entries.push({ type: `EventListener:${m[1]}`, pos: m.index });
  }

  // React useEffect
  const effectRe = /useEffect\s*\(\s*\(/g;
  while ((m = effectRe.exec(src)) !== null) {
    entries.push({ type: 'React:useEffect', pos: m.index });
  }

  // HTTP handlers
  const httpRe = /app\.(?:get|post|put|delete)\s*\(\s*["']\//g;
  while ((m = httpRe.exec(src)) !== null) {
    entries.push({ type: 'Express:handler', pos: m.index });
  }

  // Socket.io handlers
  const socketRe = /\.on\s*\(\s*["']([^"']+)["']\s*,/g;
  while ((m = socketRe.exec(src)) !== null) {
    entries.push({ type: `Socket:${m[1]}`, pos: m.index });
  }

  // Constructor functions
  const ctorRe = /\bconstructor\s*\(/g;
  while ((m = ctorRe.exec(src)) !== null) {
    entries.push({ type: 'Class:constructor', pos: m.index });
  }

  return entries;
}

// ── Build call chain backward from a position ──────────────────────────────
function buildCallChainBackward(src, sinkPos, maxHops = 5) {
  const chain = [];
  let currentPos = sinkPos;

  for (let hop = 0; hop < maxHops; hop++) {
    // Look backward for the nearest function boundary
    const before = src.slice(Math.max(0, currentPos - 1000), currentPos);

    // Find the closest function keyword before current position
    const fnMatches = [...before.matchAll(/\b(?:async\s+)?function\s*\*?\s*(\w*)\s*\(/g)];
    const arrowMatches = [...before.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*(?:\([^)]*\)|[^=>\s]+)\s*=>\s*(?:\{|\b)/g)];
    const methodMatches = [...before.matchAll(/(\w+)\s*\([^)]*\)\s*\{/g)];

    // Find the closest one
    let closest = null;
    let closestPos = -1;

    for (const m of fnMatches) {
      if (m.index > closestPos) { closestPos = m.index; closest = { name: m[1] || 'anonymous', type: 'function', pos: m.index }; }
    }
    for (const m of arrowMatches) {
      if (m.index > closestPos) { closestPos = m.index; closest = { name: m[1], type: 'arrow', pos: m.index }; }
    }
    for (const m of methodMatches) {
      if (m.index > closestPos) { closestPos = m.index; closest = { name: m[1], type: 'method', pos: m.index }; }
    }

    if (!closest) break;

    // Get the context (what calls this function?)
    const callBefore = src.slice(Math.max(0, closestPos - 300), closestPos);

    // Extract the caller line
    const callerMatch = callBefore.match(/([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\(\s*$/m);
    const callerName = callerMatch ? callerMatch[1] : null;

    chain.push({
      hop,
      type: closest.type,
      name: closest.name || 'anonymous',
      caller: callerName,
      line: getLineNumber(src, closest.pos),
    });

    // Move backward past the function declaration
    currentPos = Math.max(0, closestPos - 50);
  }

  return chain.reverse(); // oldest first
}

function getLineNumber(src, pos) {
  let line = 1;
  for (let i = 0; i < pos && i < src.length; i++) {
    if (src[i] === '\n') line++;
  }
  return line;
}

// ── Generate HTML for call chain ──────────────────────────────────────────
function renderCallChainHTML(chain) {
  if (!chain || chain.length === 0) return '';

  let html = '<div class="call-chain">';
  for (let i = 0; i < chain.length; i++) {
    const link = chain[i];
    html += `<div class="call-chain-item" style="margin-left:${i*20}px">`;
    html += `<span class="call-chain-indicator">${i > 0 ? '└─→' : '○'}</span>`;
    html += `<span class="call-chain-name">${link.name}</span>`;
    html += `<span class="call-chain-type">(${link.type})</span>`;
    if (link.caller) {
      html += `<span class="call-chain-caller">called by: ${link.caller}</span>`;
    }
    html += `<span class="call-chain-line">line ${link.line}</span>`;
    html += '</div>';
  }
  html += '</div>';
  return html;
}

// ── Main entry point ──────────────────────────────────────────────────────
function analyseCallChains(src, findings) {
  const entries = findEntryPoints(src);
  const chained = [];

  for (const f of findings) {
    // Try to find the position of this finding's value in the source
    const pos = src.indexOf(f.value || '');
    if (pos === -1) continue;

    const chain = buildCallChainBackward(src, pos);
    chained.push({
      finding: f,
      chain,
      entryPoint: entries.find(e => Math.abs(e.pos - pos) < 500) || null,
    });
  }

  return {
    chained,
    entryPoints: entries,
    count: chained.length,
  };
}

module.exports = {
  findEntryPoints,
  buildCallChainBackward,
  renderCallChainHTML,
  analyseCallChains,
};
