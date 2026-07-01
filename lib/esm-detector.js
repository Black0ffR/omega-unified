'use strict';

/**
 * OMEGA v5 — ESM Bundler Support (Vite/Rollup/ESM)
 * Item 5: Detect bundler type and adapt module splitting accordingly.
 *
 * Three detection modes:
 *  1. Vite output: import {a as f} from "./chunk-X.js", __vitePreload
 *  2. Rollup IIFE: var __defProp = ..., __export = ...
 *  3. ESM native: import/export statements, no bundler wrapper
 */

const C = { reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m', green:'\x1c[32m', cyan:'\x1c[36m' };

const BUNDLER_PATTERNS = [
  {
    name: 'Vite',
    re: /__vitePreload|import\.meta\.hot|__vite__mapDeps|@vite\/client/,
    markers: [
      /__vitePreload/g,
      /import\.meta\.hot/g,
      /__vite__mapDeps/g,
    ],
    // Vite modules are in separate files, not in a bundle — we detect the
    // entry point and extracted dynamic imports
  },
  {
    name: 'Rollup',
    re: /var\s+__defProp\s*=|var\s+__export\s*=|var\s+__esm\s*=|var\s+__commonJS\s*=|var\s+__toESM\s*=|var\s+__async\s*=/,
    markers: [
      /__defProp/g,
      /__export/g,
      /__esm/g,
      /__commonJS/g,
    ],
    // Rollup IIFE modules are in a single file with helper prefix
  },
  {
    name: 'ESM',
    re: /\bimport\s+(?:\*\s+as\s+|\{[^}]*\}\s+)?[a-zA-Z_$][a-zA-Z0-9_$]*\s+from\s+["']|\bimport\s+\{[^}]*\}\s+from\s+["']/,
    markers: [
      /\bimport\s+[a-zA-Z_$]/g,
      /\bimport\s*\{/g,
      /\bexport\s+(?:default|const|function|class|interface|type|\{)/g,
    ],
  },
  {
    name: 'Parcel',
    re: /parcelRequire|define\(\s*\d+\s*,\s*function/,
    markers: [
      /parcelRequire/g,
      /\bdefine\(\d+/g,
    ],
  },
  {
    name: 'esbuild',
    re: /var\s+__require\s*=|var\s+__commonJS\s*=|init_/,
    markers: [
      /__require/g,
      /init_/g,
    ],
  },
];

const MODULE_SPLIT_PATTERNS = {
  // Rollup: var __defProp = ...; function __export(...) { ... }
  // Modules are separated by: // <filename>
  rollup: /\/\/\s+([a-zA-Z0-9_\-./]+\.(?:js|ts|jsx|tsx|vue|svelte))\s*\n(?:var|const|let|function|class)/g,

  // Parcel: define(moduleId, function(require, module, exports) { ... })
  parcel: /\bdefine\(\s*(\d+)\s*,\s*function\s*\(/g,

  // esbuild: // <filename> \n function init_X() { ... }
  esbuild: /\/\/\s+([a-zA-Z0-9_\-./]+)\s*\n(?:function\s+\w+\s*\(|\/\*\s*)/g,

  // Vite: static imports in the entry module
  vite: /import\s+\{[^}]*\}\s+from\s+["']\.\/([^"']+)["']/g,
};

function detectBundler(src) {
  for (const bundler of BUNDLER_PATTERNS) {
    if (bundler.re.test(src)) {
      return {
        name: bundler.name,
        confidence: bundler.markers.reduce((sum, m) => {
          m.lastIndex = 0;
          const count = (src.match(m) || []).length;
          return sum + Math.min(count, 5);
        }, 1),
      };
    }
  }
  return { name: 'Unknown', confidence: 0 };
}

function splitModulesByBundler(src, bundlerName) {
  switch (bundlerName) {
    case 'Rollup': {
      const modules = [];
      const re = MODULE_SPLIT_PATTERNS.rollup;
      let lastIndex = 0;
      let lastFile = 'preamble';
      let m;

      const boundaries = [];
      re.lastIndex = 0;
      while ((m = re.exec(src)) !== null) {
        boundaries.push({ file: m[1], index: m.index });
      }

      for (let i = 0; i < boundaries.length; i++) {
        const start = boundaries[i].index;
        const end = boundaries[i + 1] ? boundaries[i + 1].index : src.length;
        modules.push({
          id: boundaries[i].file,
          source: src.slice(start, end),
        });
      }

      return modules;
    }

    case 'Parcel': {
      const modules = [];
      const re = MODULE_SPLIT_PATTERNS.parcel;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(src)) !== null) {
        const modId = m[1];
        const fnStart = m.index + m[0].length;
        let depth = 1;
        let pos = fnStart;
        while (depth > 0 && pos < src.length) {
          if (src[pos] === '{') depth++;
          else if (src[pos] === '}') depth--;
          pos++;
        }
        modules.push({
          id: modId,
          source: src.slice(fnStart, pos - 1),
        });
      }
      return modules;
    }

    case 'esbuild': {
      const modules = [];
      const re = MODULE_SPLIT_PATTERNS.esbuild;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(src)) !== null) {
        const file = m[1];
        const fnStart = m.index;
        // Find the matching closing brace
        const bodyStart = src.indexOf('{', fnStart);
        if (bodyStart === -1) continue;
        let depth = 1;
        let pos = bodyStart + 1;
        while (depth > 0 && pos < src.length) {
          if (src[pos] === '{') depth++;
          else if (src[pos] === '}') depth--;
          pos++;
        }
        modules.push({
          id: file,
          source: src.slice(fnStart, pos),
        });
      }
      return modules;
    }

    case 'ESM':
    case 'Vite': {
      // Extract import statements as module boundaries
      const modules = [];
      const importRe = /import\s+(?:\{[^}]*\}\s+from\s+["']([^"']+)["']|(?:\*\s+as\s+)?(\w+)\s+from\s+["']([^"']+)["']|["']([^"']+)["'])/g;
      importRe.lastIndex = 0;
      let m;
      while ((m = importRe.exec(src)) !== null) {
        const source = m[1] || m[2] || m[3] || m[4] || 'unknown';
        modules.push({
          id: `import:${source}`,
          source: m[0],
          name: source,
        });
      }
      // Also split by export statements
      const exportRe = /\bexport\s+(default\s+)?(const|function|class)\s+(\w+)/g;
      exportRe.lastIndex = 0;
      while ((m = exportRe.exec(src)) !== null) {
        const name = m[3] || `export-${m.index}`;
        modules.push({
          id: `export:${name}`,
          source: m[0],
          name,
        });
      }
      return modules;
    }
    default:
      return [];
  }
}

function analyseForBundler(src, opts) {
  const bundler = detectBundler(src);
  const modules = splitModulesByBundler(src, bundler.name);

  return {
    bundler,
    modules,
    moduleCount: modules.length,
  };
}

module.exports = {
  BUNDLER_PATTERNS,
  MODULE_SPLIT_PATTERNS,
  detectBundler,
  splitModulesByBundler,
  analyseForBundler,
};
