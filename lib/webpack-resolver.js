'use strict';

/**
 * OMEGA v5 — Dynamic Webpack Module Alias Resolver
 * Item 2: Replace hardcoded module map with dynamic resolution.
 *
 * Parses webpackChunk arrays to extract moduleId → source mappings.
 * Follows d(N) calls inside each module body to build a real call graph.
 * Outputs weighted-edge dependency graph as JSON.
 *
 * Supports both webpack 4 ([[id],{...}]) and webpack 5 (self.webpackChunk.push)
 * formats.
 */

const C = { reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m', green:'\x1b[32m', cyan:'\x1b[36m', yellow:'\x1b[33m' };

// ── Module ID extraction patterns ──────────────────────────────────────────

// Webpack 5 style: self["webpackChunk"].push([[id],{moduleId:fn,...}])
const WP5_CHUNK_RE = /self\[\s*["']webpackChunk["']\s*\]\.push\s*\(\s*\[\[\s*(\d+)\s*\]\s*,\s*\{/g;

// Webpack 4 style: [[id],{moduleId:fn,...}]
const WP4_CHUNK_RE = /\[\[\s*(\d+)\]\s*,\s*\{/g;

// Module function pattern: moduleId: function(Q,H,d){...} or moduleId:(Q,H,d)=>{...}
const MODULE_FN_RE = /(\d+)\s*:\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g;

// d(N) call pattern
const D_CALL_RE = /\bd\s*\(\s*(\d+)\s*\)/g;

// require(N) call pattern (webpack 4 style)
const REQUIRE_CALL_RE = /\brequire\s*\(\s*(\d+)\s*\)/g;

// Module ID key in webpack module registry
const MODULE_REGISTRY_RE = /(\d+):\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g;

// ── Known npm package name heuristics ──────────────────────────────────────

const PKG_NAME_HINTS = [
  [/@angular\/core/, '@angular/core'],
  [/@angular\/common/, '@angular/common'],
  [/@angular\/router/, '@angular/router'],
  [/@angular\/forms/, '@angular/forms'],
  [/@angular\/material/, '@angular/material'],
  [/@angular\/cdk/, '@angular/cdk'],
  [/@angular\/platform-browser/, '@angular/platform-browser'],
  [/rxjs[\/\\]/, 'rxjs'],
  [/socket\.io/, 'socket.io'],
  [/jwt-decode/, 'jwt-decode'],
  [/ngx-translate|@ngx-translate/, '@ngx-translate/core'],
  [/ng2-file-upload/, 'ng2-file-upload'],
  [/ngx-highlightjs/, 'ngx-highlightjs'],
  [/ngx-gallery/, 'ngx-gallery'],
  [/file-saver/, 'file-saver'],
  [/qrcode/, 'qrcode'],
  [/ngx-text-diff/, 'ngx-text-diff'],
  [/environment/, 'environment'],
  [/@ngrx/, '@ngrx/store'],
  [/lodash/, 'lodash'],
  [/moment/, 'moment'],
  [/axios/, 'axios'],
  [/jquery/, 'jquery'],
  [/d3\./, 'd3'],
  [/marked/, 'marked'],
  [/node-fetch/, 'node-fetch'],
  [/minimatch/, 'minimatch'],
  [/express/, 'express'],
  [/zone\.js/, 'zone.js'],
  [/tslib/, 'tslib'],
  [/core-js/, 'core-js'],
  [/webpack/, 'webpack'],
  [/zone\.js/, 'zone.js'],
];

function guessPackageName(moduleSource, moduleId) {
  // Check source body for import/require hints
  for (const [re, name] of PKG_NAME_HINTS) {
    if (re.test(moduleSource)) return name;
  }
  // Check for known module IDs from the old hardcoded map
  const legacyMap = {
    2615:'@angular/core', 9330:'@angular/common/http', 3664:'@angular/core/rendering',
    5312:'environment', 7916:'configuration-service', 9437:'rxjs/operators/catchError',
    6354:'rxjs/operators/map', 9711:'rxjs/operators', 7810:'rxjs/operators2',
    6556:'rxjs/operators3', 1943:'@angular/router', 5416:'@angular/material/snack-bar',
    1585:'@angular/material/dialog', 4382:'socket.io-client', 9946:'jwt-decode',
    5635:'@ngx-translate/core', 3955:'@ngx-translate/core2', 2629:'@angular/material/button',
    455:'@angular/router-link', 8834:'@angular/material/icon', 9417:'@angular/forms',
    1228:'@angular/common', 3746:'@angular/forms2', 9588:'@angular/forms3',
    6192:'@angular/material/table', 882:'@angular/material/sidenav',
    6471:'@angular/material/card', 3902:'@angular/material/list',
    3029:'ngx-highlightjs', 7468:'rxjs/forkJoin', 3869:'@angular/cdk/collections',
    6369:'ngx-highlightjs2', 4843:'rxjs/firstValueFrom', 9183:'@angular/cdk/drag-drop',
    2578:'file-saver', 6648:'rxjs/from', 4257:'@angular/platform-browser-dynamic',
    8132:'@angular/common/http2', 5951:'@angular/cdk/portal',
    2496:'@angular/material/autocomplete', 7200:'ng2-file-upload',
    8288:'qrcode', 4370:'ngx-text-diff', 107:'ngx-gallery', 767:'@angular/common/location',
  };
  if (legacyMap[moduleId]) return legacyMap[moduleId];

  // Try to infer from the first few chars of the source
  const firstLine = moduleSource.split('\n')[0].trim().slice(0, 60);
  // Check for import statements
  const importMatch = firstLine.match(/require\(["']([^"']+)["']\)/);
  if (importMatch) return importMatch[1];

  return `module-${moduleId}`;
}

// ── Extract modules from webpack bundle ────────────────────────────────────
function extractWebpackModules(src) {
  const modules = new Map();
  let format = null;

  // Try webpack 5 format first
  let m;
  const wp5Chunks = [];
  WP5_CHUNK_RE.lastIndex = 0;
  while ((m = WP5_CHUNK_RE.exec(src)) !== null) {
    const chunkId = m[1];
    // Find the corresponding module block
    const blockStart = m.index + m[0].length - 1; // after the {
    let depth = 1;
    let pos = blockStart;
    while (depth > 0 && pos < src.length) {
      if (src[pos] === '{') depth++;
      else if (src[pos] === '}') depth--;
      pos++;
    }
    const blockSrc = src.slice(blockStart, pos - 1);
    // Extract individual module functions from this chunk
    MODULE_FN_RE.lastIndex = 0;
    let mm;
    while ((mm = MODULE_FN_RE.exec(blockSrc)) !== null) {
      const modId = mm[1];
      const fnStart = mm.index + mm[0].length - 1; // after {
      let depth2 = 1;
      let pos2 = fnStart;
      while (depth2 > 0 && pos2 < blockSrc.length) {
        if (blockSrc[pos2] === '{') depth2++;
        else if (blockSrc[pos2] === '}') depth2--;
        pos2++;
      }
      const modBody = blockSrc.slice(fnStart, pos2 - 1);
      modules.set(modId, {
        id: modId,
        chunk: chunkId,
        source: modBody,
        name: guessPackageName(modBody, modId),
      });
    }
    format = 'webpack5';
  }

  // Try webpack 4 format
  if (modules.size === 0) {
    WP4_CHUNK_RE.lastIndex = 0;
    while ((m = WP4_CHUNK_RE.exec(src)) !== null) {
      const blockStart = m.index + m[0].length;
      let depth = 1;
      let pos = blockStart;
      while (depth > 0 && pos < src.length) {
        if (src[pos] === '{') depth++;
        else if (src[pos] === '}') depth--;
        pos++;
      }
      const blockSrc = src.slice(blockStart, pos - 1);
      MODULE_FN_RE.lastIndex = 0;
      let mm;
      while ((mm = MODULE_FN_RE.exec(blockSrc)) !== null) {
        const modId = mm[1];
        const fnStart = mm.index + mm[0].length - 1;
        let depth2 = 1;
        let pos2 = fnStart;
        while (depth2 > 0 && pos2 < blockSrc.length) {
          if (blockSrc[pos2] === '{') depth2++;
          else if (blockSrc[pos2] === '}') depth2--;
          pos2++;
        }
        const modBody = blockSrc.slice(fnStart, pos2 - 1);
        modules.set(modId, {
          id: modId,
          chunk: 'main',
          source: modBody,
          name: guessPackageName(modBody, modId),
        });
      }
      format = 'webpack4';
    }
  }

  // Try module registry format (IIFE)
  if (modules.size === 0) {
    MODULE_REGISTRY_RE.lastIndex = 0;
    while ((m = MODULE_REGISTRY_RE.exec(src)) !== null) {
      const modId = m[1];
      const fnStart = m.index + m[0].length - 1;
      let depth = 1;
      let pos = fnStart;
      while (depth > 0 && pos < src.length) {
        if (src[pos] === '{') depth++;
        else if (src[pos] === '}') depth--;
        pos++;
      }
      const modBody = src.slice(fnStart, pos - 1);
      modules.set(modId, {
        id: modId,
        chunk: 'main',
        source: modBody,
        name: guessPackageName(modBody, modId),
      });
    }
    if (modules.size) format = 'webpack-iife';
  }

  return { modules, format, count: modules.size };
}

// ── Build dependency graph ─────────────────────────────────────────────────
function buildDependencyGraph(src, modules) {
  const graph = [];

  for (const [modId, mod] of modules) {
    const uses = new Map();

    // Count d(N) calls
    D_CALL_RE.lastIndex = 0;
    let m;
    while ((m = D_CALL_RE.exec(mod.source)) !== null) {
      const targetId = m[1];
      uses.set(targetId, (uses.get(targetId) || 0) + 1);
    }

    // Count require(N) calls
    REQUIRE_CALL_RE.lastIndex = 0;
    while ((m = REQUIRE_CALL_RE.exec(mod.source)) !== null) {
      const targetId = m[1];
      uses.set(targetId, (uses.get(targetId) || 0) + 1);
    }

    graph.push({
      id: modId,
      name: mod.name,
      chunk: mod.chunk,
      totalCalls: uses.size,
      calls: Array.from(uses.entries()).map(([targetId, count]) => ({
        target: targetId,
        targetName: modules.has(targetId) ? modules.get(targetId).name : `module-${targetId}`,
        count,
      })),
    });
  }

  // Sort by number of outgoing calls descending
  graph.sort((a, b) => b.totalCalls - a.totalCalls);

  return graph;
}

// ── Find most-used modules ─────────────────────────────────────────────────
function findHotModules(graph, topN = 20) {
  // Count incoming references
  const incomingCount = {};
  for (const mod of graph) {
    for (const call of mod.calls) {
      incomingCount[call.target] = (incomingCount[call.target] || 0) + call.count;
    }
  }

  return Object.entries(incomingCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([id, count]) => ({
      id,
      name: graph.find(g => g.id === id)?.name || `module-${id}`,
      incomingReferences: count,
    }));
}

// ── Generate DOT graph for Graphviz ────────────────────────────────────────
function toDOT(graph, maxEdges = 200) {
  const lines = ['digraph webpack_modules {'];
  lines.push('  rankdir=LR;');
  lines.push('  node [shape=box, style=filled, fillcolor="#1a1a2e", fontcolor=white, fontsize=10];');
  lines.push('  edge [color="#4488ff", penwidth=1.2];');

  for (const mod of graph) {
    const label = mod.name.replace(/[^a-zA-Z0-9_\-@./]/g, '_');
    lines.push(`  "${mod.id}" [label="${mod.id}: ${label}"];`);
  }

  let edgeCount = 0;
  for (const mod of graph) {
    for (const call of mod.calls) {
      if (edgeCount++ >= maxEdges) break;
      lines.push(`  "${mod.id}" -> "${call.target}" [label="${call.count}"];`);
    }
    if (edgeCount >= maxEdges) break;
  }

  lines.push('}');
  return lines.join('\n');
}

// ── Main entry point ───────────────────────────────────────────────────────
function analyseWebpack(src, opts) {
  const t0 = Date.now();

  // Phase 1: Extract modules
  const { modules, format, count } = extractWebpackModules(src);

  if (count === 0) {
    return {
      modules: [],
      graph: [],
      format: null,
      count: 0,
      hotModules: [],
      elapsed: Date.now() - t0,
    };
  }

  // Phase 2: Build graph
  const graph = buildDependencyGraph(src, modules);
  const hotModules = findHotModules(graph, 20);

  if (opts.verbose) {
    console.log(`  Webpack modules extracted: ${count} (format: ${format})`);
    console.log(`  Dependency graph: ${graph.length} nodes`);
    console.log(`  Hot modules: ${hotModules.slice(0,5).map(m => `${m.name} (${m.incomingReferences} refs)`).join(', ')}`);
  }

  return {
    modules: Array.from(modules.values()),
    graph,
    format,
    count,
    hotModules,
    elapsed: Date.now() - t0,
  };
}

module.exports = {
  extractWebpackModules,
  buildDependencyGraph,
  findHotModules,
  toDOT,
  analyseWebpack,
};
