'use strict';

/**
 * OMEGA v5 — Import-Graph Framework Inference
 * Item 9: Per-module framework confidence scoring using import analysis.
 *
 * Instead of scanning for keywords in the full bundle, this module
 * analyzes individual webpack modules: if a module imports from @angular/*,
 * it's Angular with high confidence. Mixed modules report mixed.
 */

const FRAMEWORK_SIGNATURES = [
  {
    name: 'Angular',
    imports: ['@angular/core', '@angular/common', '@angular/router', '@angular/forms',
              '@angular/material', '@angular/cdk', '@angular/platform-browser',
              '@angular/animations', '@angular/http', '@angular/elements'],
    markers: ['ɵɵ', 'ɵcmp', 'ɵfac', 'ɵprov', 'ɵpipe', 'ɵdir', 'ɵmod', 'ɵinj',
              'Component({', 'NgModule({', 'Injectable({'],
    weight: 10,
  },
  {
    name: 'React',
    imports: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime',
              'react-native', 'next/link', 'next/router', 'next/head'],
    markers: ['React.createElement', 'createElement', 'jsx(', 'jsxs(', 'jsxDEV(',
              'useState(', 'useEffect(', 'useCallback(', 'useMemo('],
    weight: 8,
  },
  {
    name: 'Vue',
    imports: ['vue', 'vue-router', 'vuex', 'pinia', 'nuxt'],
    markers: ['createElementVNode', 'openBlock', 'createApp(', 'defineComponent({',
              '__vccOpts', 'createVNode'],
    weight: 8,
  },
  {
    name: 'Svelte',
    imports: ['svelte', 'svelte/internal', 'svelte/store', 'svelte/transition',
              'svelte/animate', 'svelte/easing'],
    markers: ['SvelteComponent', 'create_fragment', 'mount_component',
              'svelte\\/internal'],
    weight: 7,
  },
  {
    name: 'Next.js',
    imports: ['next', 'next/dist', 'next/link', 'next/router', 'next/head',
              'next/image', 'next/script'],
    markers: ['__NEXT_DATA__', 'usePathname', 'useSearchParams', '_next/static',
              '__N_SSP', '__N_SSG'],
    weight: 6,
  },
  {
    name: 'Express',
    imports: ['express', 'body-parser', 'cors', 'morgan', 'helmet'],
    markers: ['app.get(', 'app.post(', 'app.use(', 'express()', 'Router()'],
    weight: 5,
  },
  {
    name: 'Lodash',
    imports: ['lodash', 'lodash-es'],
    markers: ['_.map(', '_.filter(', '_.find(', '_.forEach(', 'lodash'],
    weight: 3,
  },
  {
    name: 'RxJS',
    imports: ['rxjs', 'rxjs/operators'],
    markers: ['BehaviorSubject', 'Observable', 'pipe(', 'subscribe('],
    weight: 4,
  },
  {
    name: 'Socket.io',
    imports: ['socket.io', 'socket.io-client'],
    markers: ['io(', 'io.connect', 'socket.on(', 'socket.emit('],
    weight: 5,
  },
  {
    name: 'jQuery',
    imports: ['jquery', 'jquery-ui'],
    markers: ['$(', 'jQuery(', '$.ajax', '$.get', '$.post'],
    weight: 3,
  },
];

function scoreModule(moduleSource, moduleImports) {
  const scores = {};

  // Score by imports
  for (const imp of moduleImports) {
    for (const fw of FRAMEWORK_SIGNATURES) {
      for (const fwImport of fw.imports) {
        if (imp.source.includes(fwImport)) {
          scores[fw.name] = (scores[fw.name] || 0) + fw.weight * 2;
        }
      }
    }
  }

  // Score by markers
  for (const fw of FRAMEWORK_SIGNATURES) {
    for (const marker of fw.markers) {
      const re = new RegExp(marker, 'g');
      const count = (moduleSource.match(re) || []).length;
      if (count > 0) {
        scores[fw.name] = (scores[fw.name] || 0) + fw.weight * count;
      }
    }
  }

  return scores;
}

function inferFrameworks(webpackModules, src) {
  const moduleScores = {};

  // Import the import-graph module for extraction
  const importGraph = require('./import-graph.js');

  for (const mod of webpackModules || []) {
    const imports = importGraph.extractImports(mod.source);
    const scores = scoreModule(mod.source, imports);

    if (Object.keys(scores).length > 0) {
      moduleScores[mod.id] = {
        name: mod.name,
        scores,
        top: Object.entries(scores).sort((a, b) => b[1] - a[1])[0],
      };
    }
  }

  // Aggregate: count modules per framework, average confidence
  const frameworkCounts = {};
  const frameworkModules = {};

  for (const [, info] of Object.entries(moduleScores)) {
    const topFramework = info.top[0];
    const topScore = info.top[1];

    frameworkCounts[topFramework] = (frameworkCounts[topFramework] || 0) + 1;
    if (!frameworkModules[topFramework]) frameworkModules[topFramework] = [];
    frameworkModules[topFramework].push(info.name);
  }

  // Also scan the full bundle for framework markers (fallback)
  for (const fw of FRAMEWORK_SIGNATURES) {
    for (const marker of fw.markers) {
      const re = new RegExp(marker.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
      const count = (src.match(re) || []).length;
      if (count > 0 && !frameworkCounts[fw.name]) {
        frameworkCounts[fw.name] = 1;
      }
    }
  }

  return {
    moduleScores,
    frameworkCounts,
    frameworkModules,
    topFrameworks: Object.entries(frameworkCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({ name, moduleCount: count })),
  };
}

module.exports = {
  FRAMEWORK_SIGNATURES,
  scoreModule,
  inferFrameworks,
};
