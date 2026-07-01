'use strict';

/**
 * OMEGA v5 — Real Import Graph & Call Graph Analysis
 * Item 3: Connect moduleId → imports/exports/calls to build a real graph.
 *
 * Given webpack modules (from webpack-resolver.js), builds:
 *  - Import graph: which modules import from which packages
 *  - Call graph: which functions call which functions across modules
 *  - Route→Guard→Module correlation
 *
 * Works with the AST from ast-parser.js for intra-module analysis,
 * and with webpack-resolver.js for inter-module analysis.
 */

// ── Extract imports from a module body ─────────────────────────────────────
function extractImports(moduleSource) {
  const imports = [];
  let m;

  // ES import: require("x") or require(x)
  const reqRe = /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g;
  while ((m = reqRe.exec(moduleSource)) !== null) {
    imports.push({ type: 'require', source: m[1] });
  }

  // ES import: import x from "y"
  const importRe = /\bimport\s+(?:\*\s+as\s+\w+\s+from\s+)?["']([^"']+)["']\s*;?/g;
  while ((m = importRe.exec(moduleSource)) !== null) {
    imports.push({ type: 'import', source: m[1] });
  }

  // Dynamic import: import("x")
  const dynImportRe = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  while ((m = dynImportRe.exec(moduleSource)) !== null) {
    imports.push({ type: 'dynamic-import', source: m[1] });
  }

  return imports;
}

// ── Extract exports from a module body ─────────────────────────────────────
function extractExports(moduleSource) {
  const exports = [];
  let m;

  // module.exports = X
  const meRe = /module\.exports\s*=\s*(\w+)/g;
  while ((m = meRe.exec(moduleSource)) !== null) {
    exports.push({ type: 'module-exports', value: m[1] });
  }

  // exports.X = Y
  const exRe = /exports\.(\w+)\s*=/g;
  while ((m = exRe.exec(moduleSource)) !== null) {
    exports.push({ type: 'named-export', name: m[1] });
  }

  // export default X
  const edRe = /\bexport\s+default\s+(\w+)/g;
  while ((m = edRe.exec(moduleSource)) !== null) {
    exports.push({ type: 'export-default', value: m[1] });
  }

  // export { X, Y }
  const enRe = /\bexport\s+\{[^}]+\}/g;
  while ((m = enRe.exec(moduleSource)) !== null) {
    exports.push({ type: 'export-named', specifiers: m[0] });
  }

  return exports;
}

// ── Extract function calls from a module body ──────────────────────────────
function extractCalls(moduleSource) {
  const calls = [];
  let m;

  // this.http.get/post/put...
  const httpRe = /this\.(\w+)\.(get|post|put|delete|patch|request)\s*\(/g;
  while ((m = httpRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'http-call', service: m[1], method: m[2] });
  }

  // socket.emit("event", ...)
  const emitRe = /\.emit\s*\(\s*["']([^"']+)["']/g;
  while ((m = emitRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'socket-emit', event: m[1] });
  }

  // socket.on("event", ...)
  const onRe = /\.on\s*\(\s*["']([^"']+)["']/g;
  while ((m = onRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'socket-on', event: m[1] });
  }

  // router.navigate([...])
  const navRe = /router\.navigate\s*\(/g;
  while ((m = navRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'router-navigate' });
  }

  // d(N) calls to other modules
  const dCallRe = /\bd\s*\(\s*(\d+)\s*\)/g;
  while ((m = dCallRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'module-dep', target: m[1] });
  }

  // fetch(...), axios.get(...), http.get(...)
  const fetchRe = /\b(fetch|axios\.\w+|http\.\w+)\s*\(/g;
  while ((m = fetchRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'http-fetch', name: m[1] });
  }

  // RouterLink references
  const routerLinkRe = /["']routerLink["'].*?["']([^"']+)["']/g;
  while ((m = routerLinkRe.exec(moduleSource)) !== null) {
    calls.push({ type: 'router-link', path: m[1] });
  }

  return calls;
}

// ── Build full graph ───────────────────────────────────────────────────────
function buildFullGraph(webpackModules) {
  const nodes = [];
  const edges = [];

  for (const mod of webpackModules) {
    const imports = extractImports(mod.source);
    const exports = extractExports(mod.source);
    const calls = extractCalls(mod.source);

    nodes.push({
      id: mod.id,
      name: mod.name,
      chunk: mod.chunk,
      imports,
      exports,
      calls,
    });

    // Create edges for module dependencies
    for (const call of calls) {
      if (call.type === 'module-dep') {
        edges.push({
          from: mod.id,
          to: call.target,
          type: 'dep',
          count: 1,
        });
      }
    }

    // Create edges for HTTP calls (show which module makes which API call)
    for (const call of calls) {
      if (call.type === 'http-call' || call.type === 'http-fetch') {
        edges.push({
          from: mod.id,
          to: `http:${call.method || call.name}`,
          type: 'http',
          count: 1,
        });
      }
    }

    // Create edges for socket events
    for (const call of calls) {
      if (call.type === 'socket-emit') {
        edges.push({
          from: mod.id,
          to: `socket:emit:${call.event}`,
          type: 'socket-emit',
          count: 1,
        });
      }
      if (call.type === 'socket-on') {
        edges.push({
          from: mod.id,
          to: `socket:on:${call.event}`,
          type: 'socket-on',
          count: 1,
        });
      }
    }
  }

  // Merge duplicate edges
  const edgeMap = new Map();
  for (const edge of edges) {
    const key = `${edge.from}|${edge.to}|${edge.type}`;
    if (edgeMap.has(key)) {
      edgeMap.get(key).count++;
    } else {
      edgeMap.set(key, { ...edge });
    }
  }

  return {
    nodes,
    edges: Array.from(edgeMap.values()),
  };
}

// ── Find routes guarded by which modules ───────────────────────────────────
function correlateRouteGuards(webpackModules, routes) {
  const guardMap = new Map();

  for (const mod of webpackModules) {
    const calls = extractCalls(mod.source);

    // Find Angular route definitions in this module
    const pathDefs = [];
    let m;
    const pathRe = /path\s*:\s*["']([^"']+)["']/g;
    while ((m = pathRe.exec(mod.source)) !== null) {
      pathDefs.push(m[1]);
    }

    // Find canActivate references
    const guardCalls = calls.filter(c => c.type === 'router-navigate');
    const hasGuard = /canActivate|AuthGuard/.test(mod.source);

    for (const path of pathDefs) {
      guardMap.set(path, {
        moduleName: mod.name,
        moduleId: mod.id,
        hasGuard,
        guardDetails: hasGuard ? extractGuardDetails(mod.source) : [],
      });
    }
  }

  // Correlate with extracted routes
  return routes.map(route => ({
    ...route,
    moduleInfo: guardMap.get(route.path.replace(/^\//, '')) || null,
  }));
}

function extractGuardDetails(src) {
  const guards = [];
  let m;
  const guardRe = /canActivate\s*:\s*\[([^\]]+)\]/g;
  while ((m = guardRe.exec(src)) !== null) {
    guards.push(m[1].trim());
  }
  return guards;
}

// ── Generate DOT output for vis/render ─────────────────────────────────────
function toDOT(graph, title = 'Module Dependency Graph') {
  const lines = [`digraph "${title}" {`];
  lines.push('  rankdir=LR;');
  lines.push('  node [shape=box, style="rounded,filled", fillcolor="#1a1a2e", fontcolor=white, fontsize=10];');

  for (const node of graph.nodes) {
    const label = node.name.replace(/[^a-zA-Z0-9_\-@./]/g, '_');
    lines.push(`  "${node.id}" [label="${node.id}: ${label}"];`);
  }

  for (const edge of graph.edges) {
    const color = edge.type === 'http' ? '#44cc88' :
                  edge.type === 'socket-emit' ? '#ff8844' :
                  edge.type === 'socket-on' ? '#ff44cc' :
                  '#4488ff';
    lines.push(`  "${edge.from}" -> "${edge.to}" [color="${color}", label="${edge.count}", fontsize=8];`);
  }

  lines.push('}');
  return lines.join('\n');
}

// ── Main entry point ───────────────────────────────────────────────────────
function analyseImports(webpackData, routes, opts) {
  if (!webpackData || !webpackData.modules || webpackData.modules.length === 0) {
    return { nodes: [], edges: [], guardCorrelation: [] };
  }

  const graph = buildFullGraph(webpackData.modules);
  const guardCorrelation = correlateRouteGuards(webpackData.modules, routes || []);

  if (opts.verbose) {
    const httpEdges = graph.edges.filter(e => e.type === 'http');
    const socketEdges = graph.edges.filter(e => e.type.startsWith('socket'));
    console.log(`  Import graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges`);
    console.log(`  HTTP edges: ${httpEdges.length}, Socket edges: ${socketEdges.length}`);
  }

  return { ...graph, guardCorrelation };
}

module.exports = {
  extractImports,
  extractExports,
  extractCalls,
  buildFullGraph,
  correlateRouteGuards,
  toDOT,
  analyseImports,
};
