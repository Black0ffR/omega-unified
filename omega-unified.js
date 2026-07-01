#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║     JS DECODER OMEGA  v4+v5  UNIFIED  —  Full Superset Security Engine      ║
 * ║                                                                              ║
 * ║  Merges v4 (js-decoder-omega.js) + v5 (js-decoder-omega-v5.js + 15 lib      ║
 *  ║  modules) into a single CLI with ALL flags from both versions.              ║
 * ║                                                                              ║
 * ║  PHASES:                                                                     ║
 * ║    0   Module alias resolver (d(N) → npm package name)                       ║
 * ║    1   Escape decode  (Unicode / ES6 / Hex / Octal / HTML-entity)            ║
 * ║    2   String decode  (fromCharCode / atob / base64 / hex-array / concat)    ║
 * ║   2b   CharCode obfuscation decoder (v4) + generic obfuscation (v5)          ║
 * ║    3   Boolean/undefined normalise                                            ║
 * ║    4   Webpack 5 cleanup                                                      ║
 * ║    5   Angular Ivy annotation                                                 ║
 * ║   5b   Multi-framework symbol annotation (Vue3/React/Svelte/Next.js/)         ║
 * ║    6   RxJS operator annotation                                               ║
 * ║    7   Token-based beautifier                                                 ║
 * ║    8   Code analysis (cyclomatic complexity, metrics)                         ║
 * ║   8b   Storage key audit  (localStorage/sessionStorage/cookieService)         ║
 * ║   8c   Auth surface mapper  (guard→route, A2 correlation)                     ║
 * ║    9   Framework detection  (confidence-scored)                               ║
 * ║   9b   AST-based framework analysis (v5)                                     ║
 * ║   9c   ESM/Bundler detection (v5)                                            ║
 * ║   10   Route extraction  (REST/HTTP/Angular/WebSocket/GraphQL/hidden)         ║
 * ║   11   Credential scanner  (32 patterns v4 + v5 subset)                      ║
 * ║   12   Security analysis  (XSS/injection/proto/postmsg/bypass)                ║
 * ║  12b   Dynamic code execution  (setTimeout/Function/Wasm)                    ║
 * ║  12c   Business logic  (rate-limit/balance/coupon/role)                      ║
 * ║  12d   WebSocket & Socket.io content analyzer                                ║
 * ║  12e   Cryptographic context  (privkey/static-IV/ECB/subtle)                 ║
 * ║  12f   Information leakage / enumeration                                     ║
 * ║  12g   IDOR pattern detection                                                ║
 * ║  12h   Dependency vulnerability correlation                                  ║
 * ║  12i   Race condition in async storage                                       ║
 * ║  12j   Heuristic taint-flow analysis (source→sink)                           ║
 * ║  12k   Web3/blockchain security                                              ║
 * ║  12l   Configuration-driven behaviour analysis                               ║
 * ║  12m   Lazy-loading route security                                           ║
 * ║  12n   Attack surface prioritisation scoring                                 ║
 * ║  12o   Modern crypto patterns (v5)                                          ║
 * ║  12p   Cross-module taint tracking (v5)                                     ║
 * ║  12q   Network surface extraction (v5)                                      ║
 * ║  12r   WASM binary detection (v5)                                           ║
 * ║  12s   Call-chain analysis (v5)                                             ║
 * ║  12t   Import-graph analysis (v5)                                           ║
 * ║  13    Webpack module splitter                                               ║
 * ║  13b   Suppression comment filtering (omega-ignore)                          ║
 * ║  14    Dependency graph (d(N) call-graph)                                    ║
 * ║  15    Reports  (HTML dark-mode / JSON / Markdown / SARIF)                    ║
 * ║                                                                              ║
 * ║  Zero external dependencies — Node.js core only.                             ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════════════════
//  LIB MODULES (v5 upgrades)
// ═══════════════════════════════════════════════════════════════════════════
const astParser        = require('./lib/ast-parser.js');
const taintAST         = require('./lib/taint-ast.js');
const webpackResolver  = require('./lib/webpack-resolver.js');
const importGraph      = require('./lib/import-graph.js');
const taintTracker     = require('./lib/taint-tracker.js');
const esmDetector      = require('./lib/esm-detector.js');
const cryptoPatterns   = require('./lib/crypto-patterns.js');
const sourcemap        = require('./lib/sourcemap.js');
const callChain        = require('./lib/call-chain.js');
const frameworkInfer   = require('./lib/framework-inference.js');
const networkSurface   = require('./lib/network-surface.js');
const sarifOutput      = require('./lib/sarif.js');
const omegaConfig      = require('./lib/config.js');
const obfuscation      = require('./lib/obfuscation.js');
const wasmExtractor    = require('./lib/wasm-extractor.js');
const workerPool       = require('./lib/worker-pool.js');

// ═══════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════
const VERSION     = 'OMEGA-UNIFIED-5.0';
const MAX_FILE_MB = 200;
const INDENT      = '  ';

let useColor = process.stdout.isTTY;
const C = new Proxy({
  reset:s=>s, bold:s=>`\x1b[1m${s}\x1b[22m`, dim:s=>`\x1b[2m${s}\x1b[22m`,
  red:s=>`\x1b[31m${s}\x1b[39m`, green:s=>`\x1b[32m${s}\x1b[39m`, yellow:s=>`\x1b[33m${s}\x1b[39m`,
  blue:s=>`\x1b[34m${s}\x1b[39m`, magenta:s=>`\x1b[35m${s}\x1b[39m`, cyan:s=>`\x1b[36m${s}\x1b[39m`,
  white:s=>`\x1b[37m${s}\x1b[39m`, gray:s=>`\x1b[90m${s}\x1b[39m`,
  bgRed:s=>`\x1b[41m${s}\x1b[49m`, bgGreen:s=>`\x1b[42m${s}\x1b[49m`, bgBlue:s=>`\x1b[44m${s}\x1b[49m`,
}, { get(t,k) { return useColor ? (t[k]||(s=>s)) : (s=>s); } });
const ok   = s => `${C.green('✔')} ${s}${C.reset('')}`;
const info = s => `${C.cyan('ℹ')} ${s}${C.reset('')}`;
const warn = s => `${C.yellow('⚠')} ${s}${C.reset('')}`;
const fail = s => `${C.red('✘')} ${s}${C.reset('')}`;
const head = s => `\n${C.bold('')}${C.blue(`══ ${s} ══`)}${C.reset('')}`;

// ═══════════════════════════════════════════════════════════════════════════
//  ANGULAR IVY MAP — 110+ entries
// ═══════════════════════════════════════════════════════════════════════════
const ANGULAR_IVY_MAP = {
  j41:'ɵɵelementStart',   k0s:'ɵɵelementEnd',     nrm:'ɵɵelement',
  Hgh:'ɵɵelementContainer', Hqn:'ɵɵelementContainerEnd',
  ncO:'ɵɵprojectionDef',  aNF:'ɵɵprojection',     SdG:'ɵɵprojectionImpl',
  NAR:'ɵɵdeclareProjDef', rj2:'ɵɵelementStartNS', eux:'ɵɵnamespacedElementEnd',
  qSk:'ɵɵnamespaceSVG',   joV:'ɵɵnamespaceHTML',
  bIt:'ɵɵlistener',       mxI:'ɵɵtwoWayListener',
  tSv:'ɵɵsyntheticHostListener', Z7z:'ɵɵrepeaterTrackBy',
  EFF:'ɵɵtext',           JRh:'ɵɵtextInterpolate1',
  SpI:'ɵɵtextInterpolate2', Lme:'ɵɵtextInterpolate4',
  LHq:'ɵɵtextInterpolate8', ai1:'ɵɵtextInterpolateV', DH7:'ɵɵtextInterpolateV',
  Y8G:'ɵɵproperty',       R50:'ɵɵtwoWayProperty',
  BMQ:'ɵɵattribute',      MHs:'ɵɵattribute',
  MHn:'ɵɵattributeInterpolate', THe:'ɵɵpropertyInterpolate',
  jOp:'ɵɵhostProperty',   xc7:'ɵɵstylePropInterpolate1',
  AVh:'ɵɵclassProp',      HbH:'ɵɵclassMap',        KoU:'ɵɵclassMap',
  sMw:'ɵɵclassMapInterpolate1', sbH:'ɵɵstyleProp',
  d8G:'ɵɵstyleMap',        VkB:'ɵɵstyleMapInterpolate1', Udp:'ɵɵupdateBinding',
  nVh:'ɵɵtemplate',       vxM:'ɵɵconditional',     vZN:'ɵɵconditionalWithMemo',
  Dyx:'ɵɵrepeaterApply',  BUC:'ɵɵrepeaterCreate',
  qex:'ɵɵdeferredBlockStart', bVm:'ɵɵdeferredBlockEnd', DNE:'ɵɵdeferredBlockSlot',
  'R7$':'ɵɵadvance',
  RV6:'ɵɵgetCurrentView', XpG:'ɵɵnextContext', eBV:'ɵɵrestoreView',
  Njj:'ɵɵresetView', sdS:'ɵɵgetDirectives', fX1:'ɵɵtemplateRefExtractor',
  wD4:'ɵɵtemplateContext',
  nI1:'ɵɵpipe',           bMT:'ɵɵpipeBind2',       Xts:'ɵɵpipeBind',
  x7i:'ɵɵpipeBindV',      mI1:'ɵɵpipeBindV',       i5U:'ɵɵpipeBind4',
  l_i:'ɵɵpipeBind3',       lJ4:'ɵɵpipeBindV',       eq3:'ɵɵi18nExp',
  GBs:'ɵɵviewQuery',      lsd:'ɵɵloadQueryList',   mGM:'ɵɵqueryRefresh',
  npT:'ɵɵsanitizeHtml',   mNQ:'ɵɵsanitizeHtml2',
  P7a:'ɵɵsanitizeUrl',    scb:'ɵɵsanitizeResourceUrl',
  yYe:'ɵɵsanitizeScript', nln:'ɵɵsanitizeStyle',
  B4B:'ɵɵtrustHtml',      GfV:'ɵɵtrustResourceUrl',
  ZxD:'ɵɵtrustScript',    KVd:'ɵɵtrustUrl',
  lnJ:'ɵɵi18n',           f6r:'ɵɵi18nApply',       mI1x:'ɵɵi18nAttributes',
  VBU:'ɵɵdefineComponent', 'VB$':'ɵɵdefineComponent2',
  jDH:'ɵɵdefineInjectable', tiK:'ɵɵdefineNgModule',
  hqG:'ɵɵsetNgModuleScope', bmF:'ɵɵdefineDirective',
  jtY:'ɵɵdefinePipe',      EJ8:'ɵɵdefinePipe',
  WQX:'ɵɵinject',          Mgp:'ɵɵinjectAttribute',
  lFW:'ɵɵinjectImplementation', wRn:'ɵɵrunInInjectionContext',
  rCR:'ɵɵresetCompiledComponents', xGo:'ɵɵgetFactory',
  oKB:'ɵɵimportProvidersFrom', 'Jv_':'ɵɵproviders',
  Rfq:'ɵɵforwardRef',      SKi:'NgZone',
  OA$:'ɵɵNgOnChangesFeature', Vt3:'ɵɵInheritDefinitionFeature',
  'kB':'ɵɵCopyDefinitionFeature',
};

const ANGULAR_UNICODE_PROPS = {
  '\\u0275fac':'ɵfac', '\\u0275cmp':'ɵcmp', '\\u0275dir':'ɵdir',
  '\\u0275pipe':'ɵpipe', '\\u0275prov':'ɵprov',
  '\\u0275mod':'ɵmod',  '\\u0275inj':'ɵinj',
};

const ANGULAR_STATIC_MAP = {
  'static ɵfac':  '/* Angular Factory   */ static ɵfac',
  'static ɵcmp':  '/* Angular Component */ static ɵcmp',
  'static ɵprov': '/* Angular Provider  */ static ɵprov',
  'static ɵmod':  '/* Angular NgModule  */ static ɵmod',
  'static ɵinj':  '/* Angular Injector  */ static ɵinj',
  'static ɵdir':  '/* Angular Directive */ static ɵdir',
};

// ── RxJS operator annotation ──────────────────────────────────────────────
const RXJS_OPERATORS = {
  'b.T':'/*rxjs:map*/',      'b.t':'/*rxjs:mapTo*/',
  'g.W':'/*rxjs:catchError*/','g.w':'/*rxjs:catchError*/',
  'g.M':'/*rxjs:mergeMap*/', 'g.S':'/*rxjs:switchMap*/',
  'g.E':'/*rxjs:exhaustMap*/','g.F':'/*rxjs:flatMap*/',
  'g.c':'/*rxjs:concatMap*/','g.f':'/*rxjs:filter*/',
  'g.d':'/*rxjs:debounceTime*/','g.t':'/*rxjs:tap*/',
  'g.D':'/*rxjs:distinctUntilChanged*/','g.T':'/*rxjs:take*/',
  'xt.p':'/*rxjs:combineLatest*/','xt.A':'/*rxjs:forkJoin*/',
  'rd.z':'/*rxjs:zip*/','yt.of':'/*rxjs:of*/',
  'gm.H':'/*rxjs:from*/','Vc.c':'/*rxjs:Observable*/',
  'St.w':'/*rxjs:EMPTY*/','Zt.B':'/*rxjs:BehaviorSubject*/',
};

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 5b MAPS — Multi-framework symbol deobfuscation
// ═══════════════════════════════════════════════════════════════════════════

const VUE3_VNODE_MAP = {
  cEV:'createElementVNode', cTV:'createTextVNode', cCV:'createCommentVNode',
  cSV:'createStaticVNode',  cVN:'createVNode',     clV:'cloneVNode',
  cEB:'createElementBlock', oB:'openBlock',         cB:'createBlock',
  kS:'KeepAlive',           sS:'Suspense',          tP:'Teleport',
  rL:'renderList',          rS:'renderSlot',        wC:'withCtx',
  wD:'withDirectives',      rD:'resolveDirective',  rC:'resolveComponent',
  rDC:'resolveDynamicComponent', mP:'mergeProps',   nC:'normalizeClass',
  nSt:'normalizeStyle',     nP:'normalizeProps',    tDS:'toDisplayString',
  gSS:'guardReactiveProps', cSS:'createSlots',      wSK:'withScopeId',
  pSV:'pushScopeId',        pSP:'popScopeId',
  sR:'shallowRef',          tR:'triggerRef',        cR:'customRef',
  rct:'reactive',           sRc:'shallowReactive',  ro:'readonly',
  sRo:'shallowReadonly',    wE:'watchEffect',       wPS:'watchPostEffect',
  wSE:'watchSyncEffect',    eR:'effectScope',       gCS:'getCurrentScope',
  oCS:'onScopeDispose',     iR:'isRef',             uR:'unref',
  tRw:'toRef',              tRws:'toRefs',          iRP:'isReactive',
  iRO:'isReadonly',         iP:'isProxy',           iSR:'isShallow',
  tRW:'toRaw',              mkR:'markRaw',          prx:'proxyRefs',
  oMt:'onMounted',          oUM:'onUnmounted',      oBM:'onBeforeMount',
  oBU:'onBeforeUnmount',    oU:'onUpdated',         oBUp:'onBeforeUpdate',
  oAc:'onActivated',        oDa:'onDeactivated',    oEH:'onErrorCaptured',
  oRt:'onRenderTracked',    oRT:'onRenderTriggered',oSC:'onServerPrefetch',
  dC:'defineComponent',     dAs:'defineAsyncComponent',
  dPr:'defineProps',        dEm:'defineEmits',      dEx:'defineExpose',
  dOp:'defineOptions',      dSl:'defineSlots',      dMd:'defineModel',
  wMd:'withDefaults',       sSU:'setupStatefulComponent',
  gCI:'getCurrentInstance', gPB:'getPublicInstance',
  prv:'provide',            inj:'inject',           hIj:'hasInjectionContext',
  uAt:'useAttrs',           uSl:'useSlots',         uTR:'useTemplateRef',
  uID:'useId',              nxt:'nextTick',         mXP:'mergeDefaults',
  tSS:'toHandlers',         vSh:'vShow',            vMd:'vModelText',
  vMC:'vModelCheckbox',     vMR:'vModelRadio',      vMS:'vModelSelect',
  vMDy:'vModelDynamic',     usA:'useSSRContext',
};

const VUE3_INTERNAL_PROPS = {
  '__vccOpts':'/* Vue: component options */__vccOpts',
  '__hmrId':'/* Vue: HMR ID */__hmrId',
  '__file':'/* Vue: source file */__file',
  '__scopeId':'/* Vue: scoped CSS ID */__scopeId',
  '__cssModules':'/* Vue: CSS modules */__cssModules',
  '_component':'/* Vue: component ref */_component',
  '_ctx':'/* Vue: component ctx */_ctx',
  '_cache':'/* Vue: template cache */_cache',
};

const VUE_ROUTER_MAP = {
  cRt:'createRouter', cWH:'createWebHistory', cWHH:'createWebHashHistory',
  cMH:'createMemoryHistory', uRt:'useRouter', uRte:'useRoute',
  rVw:'RouterView', rLk:'RouterLink', nVI:'NavigationFailureType',
  iNF:'isNavigationFailure', oBC:'onBeforeRouteLeave',
  oBRC:'onBeforeRouteUpdate', stRt:'START_LOCATION',
};

const REACT_HOOKS_MAP = {
  uSt:'useState', uEf:'useEffect', uLEf:'useLayoutEffect', uIEf:'useInsertionEffect',
  uCb:'useCallback', uMm:'useMemo', uRf:'useRef', uCx:'useContext',
  uRd:'useReducer', uId:'useId', uDV:'useDeferredValue', uTr:'useTransition',
  uSI:'useSyncExternalStore', uIS:'useImperativeHandle', uDL:'useDebugValue',
  uAt:'useActionState', uOm:'useOptimistic',
  cEL:'createElementWithValidation', jsx:'jsx', jsxs:'jsxs', jsxD:'jsxDEV',
  clE:'cloneElement', isVE:'isValidElement', cRef:'createRef', fwd:'forwardRef',
  memo:'memo', lazy:'lazy', frag:'Fragment', stn:'StrictMode', pro:'Profiler',
  sus:'Suspense', cCx:'createContext', chM:'Children.map', chFe:'Children.forEach',
  chC:'Children.count', chO:'Children.only', chTa:'Children.toArray',
  stTr:'startTransition', act:'act', cch:'cache',
};

const REACT_DOM_MAP = {
  cRt:'createRoot', hSR:'hydrateRoot', rnd:'render', umt:'unmountComponentAtNode',
  cPt:'createPortal', flS:'flushSync', rTS:'renderToString',
  rTSt:'renderToStaticMarkup', rNS:'renderToNodeStream', rSS:'renderToStaticNodeStream',
  rTP:'renderToPipeableStream', rTRS:'renderToReadableStream',
};

const REACT_FIBER_PROPS = {
  '__reactFiber\\$':'/* React: fiber node */__reactFiber',
  '__reactProps\\$':'/* React: props cache */__reactProps',
  '__reactEvents\\$':'/* React: delegated events */__reactEvents',
  '__reactListeners\\$':'/* React: listeners */__reactListeners',
  '__reactContext':'/* React: context value */__reactContext',
  '_reactRootContainer':'/* React: root container */_reactRootContainer',
  '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED':'/* React: internal dispatcher */__REACT_INTERNALS',
};

const REACT_EVENTS_MAP = {
  oCp:'onClickCapture', oCh:'onChange', oI:'onInput', oSb:'onSubmit',
  oKD:'onKeyDown', oKU:'onKeyUp', oKP:'onKeyPress', oFc:'onFocus',
  oBl:'onBlur', oME:'onMouseEnter', oML:'onMouseLeave', oMM:'onMouseMove',
  oMD:'onMouseDown', oMU:'onMouseUp', oMO:'onMouseOver',
  oTO:'onTouchStart', oTE:'onTouchEnd', oTM:'onTouchMove',
  oDR:'onDragOver', oDp:'onDrop', oSl:'onScroll', oWhl:'onWheel',
  oCx:'onContextMenu', oAP:'onAnimationStart', oAE:'onAnimationEnd',
  oTP:'onTransitionEnd', oPS:'onPointerDown',
};

const SVELTE_RUNTIME_MAP = {
  apH:'append_hydration', ins:'insert', insH:'insert_hydration',
  nod:'noop', elIs:'element_is', svgE:'svg_element',
  clT:'claim_text', clSp:'claim_space', atNS:'attr_dev',
  sAt:'set_attributes', xLk:'xlink_attr', sSD:'set_svg_attributes',
  sIC:'set_input_value', sDat:'set_data', sDtD:'set_data_dev',
  sSt:'set_style', tgl:'toggle_class', rmAt:'remove_attribute',
  lnrD:'listen_dev', prD:'prevent_default', stP:'stop_propagation',
  stIP:'stop_immediate_propagation', slf:'self', trsted:'trusted',
  sfd:'safe_not_equal', nEql:'not_equal',
  vrEl:'validate_each_argument', vrCm:'validate_component',
  vrSt:'validate_store', sbc:'subscribe', cmPN:'component_subscribe',
  cr8:'create_component', mntC:'mount_component', dstC:'destroy_component',
  trIn:'transition_in', trOt:'transition_out', gSpC:'get_spread_object',
  gSpU:'get_spread_update', upF:'update_keyed_each',
  oWk:'outro_and_destroy_block', cEch:'create_each_block',
  cIfB:'create_if_block', cElB:'create_else_block',
  cSlB:'create_slot', gSlC:'get_slot_context',
  gSlS:'get_slot_spread_changes', uSlC:'update_slot_base',
  cMtB:'create_mount_block', bfUd:'before_update', afUd:'after_update',
  wrt:'writable', rdd:'readable', drv:'derived', rdbl:'readable',
  slid:'slide', scl:'scale', drw:'draw', crst:'crossfade',
  twn:'tweened', spr:'spring',
};

const NEXTJS_RUNTIME_MAP = {
  uPN:'usePathname', uSP:'useSearchParams', uPrm:'useParams',
  uSI:'useSelectedLayoutSegment', uSIS:'useSelectedLayoutSegments',
  rdr:'redirect', prRdr:'permanentRedirect', nNA:'notFound',
  usEF:'useFormStatus', usEA:'useFormState', wRtr:'withRouter',
  cSA:'createServerAction$', rSC:'registerServerReference',
  cSR:'createServerReference', encA:'encodeReply',
  decRp:'decodeReply', decAc:'decodeAction', decFm:'decodeFormState',
  cRq:'createRequest', rPth:'revalidatePath', rTag:'revalidateTag',
  uns:'unstable_cache', unNo:'unstable_noStore',
  hds:'headers', cks:'cookies', nImg:'Image', gImP:'getImageProps',
  gStP:'generateStaticParams', gMtd:'generateMetadata',
  gVP:'generateViewport', nLnk:'Link', ntFt:'localFont',
};

const NEXTJS_LITERAL_MAP = {
  '__N_SSP':'/* Next.js: SSP marker */__N_SSP',
  '__N_SSG':'/* Next.js: SSG marker */__N_SSG',
  '__NEXT_DATA__':'/* Next.js: page data */__NEXT_DATA__',
  '__nextRouterBasePath':'/* Next.js: base path */__nextRouterBasePath',
};

const WEBPACK_RUNTIME_COMMENTS = {
  '__webpack_require__':'/* webpack: require */__webpack_require__',
  '__webpack_module__':'/* webpack: module */__webpack_module__',
  '__webpack_exports__':'/* webpack: exports */__webpack_exports__',
  '__webpack_modules__':'/* webpack: module registry */__webpack_modules__',
  '__webpack_chunk_load__':'/* webpack: chunk loader */__webpack_chunk_load__',
  '__webpack_base_uri__':'/* webpack: public path */__webpack_base_uri__',
  '__webpack_nonce__':'/* webpack: CSP nonce */__webpack_nonce__',
  '__webpack_share_scopes__':'/* webpack: federation shares */__webpack_share_scopes__',
  '__webpack_init_sharing__':'/* webpack: federation init */__webpack_init_sharing__',
  'webpackJsonp':'/* webpack: jsonp (legacy) */webpackJsonp',
};

const VITE_RUNTIME_COMMENTS = {
  '__vite__mapDeps':'/* Vite: dep map for preload */__vite__mapDeps',
  '__vitePreload':'/* Vite: asset preload */__vitePreload',
  '__vite_ssr_import__':'/* Vite SSR: import */__vite_ssr_import__',
  '__vite_ssr_exports__':'/* Vite SSR: exports */__vite_ssr_exports__',
  '__vite_ssr_exportAll__':'/* Vite SSR: exportAll */__vite_ssr_exportAll__',
};

const LODASH_ES_MAP = {
  fnd:'_.find', fI:'_.findIndex', evr:'_.every', grB:'_.groupBy', kBy:'_.keyBy',
  cntB:'_.countBy', srtB:'_.sortBy', orB:'_.orderBy', fltD:'_.flattenDeep',
  fltM:'_.flatMap', pkB:'_.pickBy', omB:'_.omitBy', asn:'_.assign', dfD:'_.defaults',
  dfDp:'_.defaultsDeep', kys:'_.keys', vls:'_.values', ens:'_.entries',
  clnD:'_.cloneDeep', chk:'_.chunk', dff:'_.difference', drp:'_.drop',
  drpR:'_.dropRight', tke:'_.take', tkeR:'_.takeRight', nth:'_.nth',
  inp:'_.intersection', unqB:'_.uniqBy', zpO:'_.zipObject',
  cml:'_.camelCase', kbb:'_.kebabCase', snk:'_.snakeCase', stC:'_.startCase',
  trnc:'_.truncate', tpl:'_.template', dbc:'_.debounce', thrt:'_.throttle',
  miz:'_.memoize', crO:'_.curry', prt:'_.partial', nce:'_.once', flp:'_.flip',
  neg:'_.negate', isA:'_.isArray', isO:'_.isObject', isS:'_.isString',
  isN:'_.isNumber', isB:'_.isBoolean', isFn:'_.isFunction', isNl:'_.isNull',
  isUd:'_.isUndefined', isNE:'_.isNil', isEq:'_.isEqual', isEm:'_.isEmpty',
  isIn:'_.isInteger', isNaN:'_.isNaN', nop:'_.noop', idn:'_.identity',
  cnst:'_.constant', tms:'_.times', uid:'_.uniqueId',
};

const DATE_FNS_MAP = {
  prsI:'parseISO', fmtI:'formatISO', fmtRl:'formatRelative',
  fmtDst:'formatDistance', fmtDstTNow:'formatDistanceToNow',
  isVld:'isValid', isBf:'isBefore', isAf:'isAfter',
  addD:'addDays', addH:'addHours', addM:'addMinutes',
  addMo:'addMonths', addYr:'addYears', addWk:'addWeeks',
  subD:'subDays', subMo:'subMonths', subYr:'subYears', subWk:'subWeeks',
  dffD:'differenceInDays', dffH:'differenceInHours', dffMn:'differenceInMinutes',
  dffMo:'differenceInMonths', dffYr:'differenceInYears', dffCd:'differenceInCalendarDays',
  strtD:'startOfDay', endD:'endOfDay', strtMo:'startOfMonth', endMo:'endOfMonth',
  strtWk:'startOfWeek', endWk:'endOfWeek', strtYr:'startOfYear', endYr:'endOfYear',
  gtDy:'getDay', gtDt:'getDate', gtMo:'getMonth', gtYr:'getYear',
  gtHr:'getHours', gtMin:'getMinutes', gtSec:'getSeconds', gtMs:'getMilliseconds',
  setDy:'setDay', setDt:'setDate', setMo:'setMonth', setYr:'setYear',
  toD:'toDate', frUnx:'fromUnixTime', gtUnx:'getUnixTime',
};

const ZOD_MAP = {
  zO:'z.object', zS:'z.string', zN:'z.number', zB:'z.boolean',
  zA:'z.array', zU:'z.union', zI:'z.intersection', zE:'z.enum',
  zNE:'z.nativeEnum', zL:'z.literal', zTp:'z.tuple', zRc:'z.record',
  zMp:'z.map', zSt:'z.set', zFn:'z.function', zLz:'z.lazy',
  zPm:'z.promise', zVd:'z.void', zAn:'z.any', zUk:'z.unknown',
  zNv:'z.never', zNl:'z.null', zUd:'z.undefined',
  zDc:'z.discriminatedUnion', prsA:'schema.parseAsync', sprA:'schema.safeParseAsync',
};

const ZUSTAND_MAP = {
  crtSt:'createStore', uSt:'useStore', sbscr:'subscribeWithSelector',
  imr:'immer', prst:'persist', dvtl:'devtools', cmbn:'combine',
  cmpS:'computed', stlS:'shallow',
};

const IMMER_MAP = {
  prdWR:'produceWithPatches', cDft:'createDraft', fnDft:'finishDraft',
  apPt:'applyPatches', gnPt:'generatePatches',
  enAS:'enableAllPlugins', enMP:'enableMapSet', enPS:'enablePatches',
  isDft:'isDraft', isDtb:'isDraftable', crnt:'current',
  orgnl:'original', cstm:'setAutoFreeze',
};

const COREJS_SHIMS_COMMENTS = {
  '__core-js_shared__':'/* core-js: shared state */',
  'IS_PURE':'/* core-js: pure mode flag */',
  'NATIVE_WEAK_MAP':'/* core-js: WeakMap native check */',
  'nativeBind':'/* core-js: Function.bind shim */',
  'nativeCreate':'/* core-js: Object.create shim */',
  'nativeGetPrototype':'/* core-js: getPrototypeOf shim */',
  'nativeObjectCreate':'/* core-js: Object.create */',
  'nativeFreeze':'/* core-js: Object.freeze */',
  'nativeKeys':'/* core-js: Object.keys */',
  '$export':'/* core-js: export helper */',
  '$iterCreate':'/* core-js: iterator factory */',
  '$iterDefine':'/* core-js: iterator define */',
  'DESCRIPTORS':'/* core-js: descriptor support flag */',
  'arraySpeciesCreate':'/* core-js: array species */',
  'arrayFromIterable':'/* core-js: from iterable */',
};

// ═══════════════════════════════════════════════════════════════════════════
//  CREDENTIAL PATTERNS (v4 full set — superset of v5)
// ═══════════════════════════════════════════════════════════════════════════
const CREDENTIAL_PATTERNS = [
  { name:'Hardcoded Password', severity:'critical', re:/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,64})["']/gi, fpGuard: v => /^(?:password|placeholder|\*+|your.password)$/i.test(v) },
  { name:'Hardcoded Credential', severity:'critical', re:/(?:testingUsername|testingPassword|TESTING_CRED)\s*=\s*["']([^"']+)["']/gi, fpGuard: null },
  { name:'Hardcoded API Key', severity:'critical', re:/(?:api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,64})["']/gi, fpGuard: null },
  { name:'JWT Secret', severity:'critical', re:/(?:jwt[_-]?secret|jwtSecret)\s*[:=]\s*["']([^"']{8,})["']/gi, fpGuard: null },
  { name:'Google OAuth Client ID', severity:'high', re:/\d{12,}-[a-z0-9]{32}\.apps\.googleusercontent\.com/g, fpGuard: null },
  { name:'OAuth Client ID', severity:'high', re:/client[_-]?id\s*[:=]\s*["']([^"']{8,128})["']/gi, fpGuard: v => /placeholder|example|test/i.test(v) },
  { name:'localStorage token', severity:'high', re:/localStorage\.(?:getItem|setItem)\s*\(\s*["']token["']/g, fpGuard: null },
  { name:'Cookie token', severity:'medium', re:/cookieService\.(?:put|get)\s*\(\s*["']token["']/g, fpGuard: null },
  { name:'Broken Crypto — btoa(reverse)', severity:'critical', re:/btoa\s*\(\s*\w+\.split\s*\(\s*["']["']\s*\)\.reverse\s*\(\s*\)\.join\s*\(\s*["']["']\s*\)\s*\)/g, fpGuard: null },
  { name:'Broken Crypto — btoa(field.split.reverse)', severity:'critical', re:/btoa\s*\(\s*[\w.]+(?:email|password|user)\s*(?:\?\.|\.)\s*split\s*\(["']["']\s*\)\s*\.reverse/gi, fpGuard: null },
  { name:'Cookie token storage', severity:'medium', re:/cookieService\.put\s*\(\s*["']token["']/g, fpGuard: null },
  { name:'Weak Entropy — Math.random password', severity:'high', re:/Math\.random\s*\(\s*\).*?password/gi, fpGuard: null },
  { name:'Private Key', severity:'critical', re:/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, fpGuard: null },
  { name:'Bearer Token', severity:'high', re:/Bearer\s+[A-Za-z0-9\-_\.]{20,}/g, fpGuard: null },
  { name:'AWS Access Key', severity:'critical', re:/AKIA[0-9A-Z]{16}/g, fpGuard: null },
  { name:'AWS Secret Key', severity:'critical', re:/aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*["']([^"']{40})["']/gi, fpGuard: null },
  { name:'Stripe Key', severity:'critical', re:/sk_(?:live|test)_[0-9a-zA-Z]{24}/g, fpGuard: null },
  { name:'SendGrid API Key', severity:'critical', re:/SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, fpGuard: null },
  { name:'GitHub Token', severity:'critical', re:/gh[pousr]_[A-Za-z0-9]{36}/g, fpGuard: null },
  { name:'Hardcoded Email', severity:'medium', re:/["'][a-zA-Z0-9._%+\-]+@(?!example\.com|test\.com)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}["']/g, fpGuard: v => v.length > 80 },
  { name:'Internal IP', severity:'low', re:/["'](?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+["']/g, fpGuard: null },
  { name:'US SSN', severity:'critical', re:/\b\d{3}-\d{2}-\d{4}\b/g, fpGuard: v => /entry\.\d+/.test(v) },
  { name:'Hardcoded Coupon Code', severity:'high', re:/\b([A-Z]{4,10}\d{4})\s*:/g, fpGuard: v => v.length > 20 },
  { name:'Time-Gated Discount', severity:'medium', re:/validOn\s*:\s*(\d{10,13})/g, fpGuard: null },
  { name:'MongoDB URI', severity:'critical', re:/mongodb(?:\+srv)?:\/\/[^"'\s]+/gi, fpGuard: null },
  { name:'Database password', severity:'critical', re:/db[_-]?pass(?:word)?\s*[:=]\s*["']([^"']+)["']/gi, fpGuard: null },
  { name:'SMTP credentials', severity:'high', re:/smtp[_-]?(?:pass|password|user|username)\s*[:=]\s*["']([^"']+)["']/gi, fpGuard: null },
  { name:'Slack Token', severity:'critical', re:/xox[baprs]-[0-9a-zA-Z]{10,48}/g, fpGuard: null },
  { name:'Base64 secret candidate', severity:'low', re:/["'][A-Za-z0-9+/]{40,}={0,2}["']/g, fpGuard: v => v.length > 200 },
  { name:'Hex secret candidate', severity:'low', re:/["'][0-9a-fA-F]{40,}["']/g, fpGuard: v => v.length > 80 },
];

// ═══════════════════════════════════════════════════════════════════════════
//  SECURITY PATTERNS (v4 superset)
// ═══════════════════════════════════════════════════════════════════════════
const SECURITY_PATTERNS = [
  { id:'xss-write', cat:'XSS', sev:'critical', re:/document\.write\s*\(/g, ctx: m => !m.includes('// test') },
  { id:'xss-innerhtml', cat:'XSS', sev:'high', re:/\.innerHTML\s*=/g, ctx: m => !/sanitize|DomSanitizer|bypassSecurityTrust/.test(m.slice(-200)) },
  { id:'xss-eval', cat:'XSS', sev:'critical', re:/\beval\s*\(/g, ctx: null },
  { id:'xss-new-func', cat:'XSS', sev:'critical', re:/new\s+Function\s*\(/g, ctx: null },
  { id:'sqli-concat', cat:'Injection', sev:'high', re:/(?:query|sql|exec)\s*=\s*["'][^"']*["']\s*\+/gi, ctx: m => !/placeholder|label|aria/.test(m) },
  { id:'cmd-injection', cat:'Injection', sev:'critical', re:/child_process|exec\s*\(\s*[^)]*\+/g, ctx: null },
  { id:'crypto-broken-entropy', cat:'Broken Crypto', sev:'critical', re:/btoa\s*\([^)]*\.split\s*\(\s*["']["']\s*\)\.reverse/g, ctx: null },
  { id:'crypto-weak-hash', cat:'Broken Crypto', sev:'high', re:/(?:MD5|sha1|SHA1)\s*\(/gi, ctx: m => !/comment|hmac/.test(m.toLowerCase()) },
  { id:'crypto-math-random', cat:'Broken Crypto', sev:'medium', re:/Math\.random\s*\(\s*\)/g, ctx: m => /password|secret|token|key|nonce/i.test(m.slice(-100,100)) },
  { id:'network-socket', cat:'Network', sev:'info', re:/socket\.io|\.on\s*\(\s*["'](?:connect|message|data)/g, ctx: null },
  { id:'network-socket-emit', cat:'Network Surface', sev:'medium', re:/\.emit\s*\(\s*["']([^"']+)["']/g, ctx: null },
  { id:'network-http-open', cat:'Network', sev:'info', re:/https?:\/\/[^\s"']+/g, ctx: m => !/accounts\.google|cdnjs\.cloudflare|openstreetmap/.test(m) },
  { id:'storage-local', cat:'Storage', sev:'medium', re:/localStorage\./g, ctx: null },
  { id:'storage-session', cat:'Storage', sev:'medium', re:/sessionStorage\./g, ctx: null },
  { id:'storage-cookie', cat:'Storage', sev:'low', re:/document\.cookie/g, ctx: null },
  { id:'pii-email-field', cat:'PII', sev:'low', re:/\.email\s*=|email\s*:/g, ctx: m => !/placeholder|label|aria/.test(m) },
  { id:'angular-guard', cat:'Auth Surface', sev:'info', re:/canActivate\s*:\s*\[([^\]]+)\]/g, ctx: null },
  { id:'angular-bypass', cat:'Angular Security', sev:'high', re:/bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)/g, ctx: null },
  // B2: DOM XSS Sinks
  { id:'xss-outerhtml', cat:'XSS', sev:'critical', re:/\.outerHTML\s*=/g, ctx: null },
  { id:'xss-insertadj', cat:'XSS', sev:'critical', re:/\.insertAdjacentHTML\s*\(/g, ctx: null },
  { id:'xss-srcdoc', cat:'XSS', sev:'critical', re:/\.srcdoc\s*=/g, ctx: null },
  { id:'xss-createfrag', cat:'XSS', sev:'high', re:/createContextualFragment\s*\(/g, ctx: null },
  { id:'xss-jquery-html', cat:'XSS', sev:'critical', re:/(?:jQuery|\$)\s*\([^)]*\)\.html\s*\([^)]+\)/g, ctx: null },
  { id:'xss-jquery-dom', cat:'XSS', sev:'high', re:/(?:jQuery|\$)\([^)]*\)\.(?:append|prepend|after|before|wrap)\s*\([^)]+\)/g, ctx: null },
  { id:'xss-set-attr-on', cat:'XSS', sev:'critical', re:/\.setAttribute\s*\(\s*['"]on\w+['"]\s*,/g, ctx: null },
  { id:'xss-location-href', cat:'XSS', sev:'high', re:/(?:location|window\.location)\.href\s*=/g, ctx: m => !/https?:\/\//.test(m) },
  { id:'xss-loc-replace', cat:'XSS', sev:'high', re:/location\.(?:replace|assign)\s*\(/g, ctx: null },
  { id:'xss-window-open', cat:'XSS', sev:'medium', re:/window\.open\s*\(/g, ctx: null },
  // B3: Angular Template Injection
  { id:'ng-tmpl-inject', cat:'Angular Security', sev:'high', re:/DomSanitizer.*bypassSecurityTrustHtml\s*\(\s*[`'"]/g, ctx: null },
  { id:'ng-compile', cat:'Angular Security', sev:'critical', re:/\$compile\s*\(\s*(?!['"])/g, ctx: null },
  // B4: Prototype Pollution
  { id:'proto-assign', cat:'Prototype Pollution', sev:'critical', re:/(?:__proto__|prototype)\s*(?:\[|\.)/g, ctx: null },
  { id:'proto-merge', cat:'Prototype Pollution', sev:'high', re:/Object\.assign\s*\(\s*(?:target|obj|config|opts|options|settings)/gi, ctx: m => /user|request|input|body|data|param/i.test(m) },
  { id:'proto-setproto', cat:'Prototype Pollution', sev:'high', re:/Object\.setPrototypeOf\s*\(/g, ctx: null },
  { id:'proto-jsonparse', cat:'Prototype Pollution', sev:'medium', re:/JSON\.parse\s*\([^)]+\)/g, ctx: m => /user|request|input|body|data|param|__proto__|constructor/i.test(m) },
  // B5: PostMessage
  { id:'postmsg-wildcard', cat:'PostMessage', sev:'high', re:/\.postMessage\s*\([^)]+,\s*['"][*]['"]/g, ctx: null },
  { id:'postmsg-nocheck', cat:'PostMessage', sev:'medium', re:/addEventListener\s*\(\s*['"]message['"]/g, ctx: m => !/event\.origin|e\.origin/.test(m.slice(0,400)) },
  // B6: Insufficient Randomness
  { id:'rand-date-token', cat:'Broken Crypto', sev:'high', re:/(?:Date\.now\(\)|new\s+Date\(\)\.getTime\(\))/g, ctx: m => /token|nonce|csrf|session|secret|key|id|ref/i.test(m) },
  // B7: bypassSecurityTrust* family
  { id:'bypass-style', cat:'Angular Security', sev:'high', re:/bypassSecurityTrustStyle\s*\(/g, ctx: null },
  { id:'bypass-url', cat:'Angular Security', sev:'critical', re:/bypassSecurityTrustUrl\s*\(/g, ctx: null },
  { id:'bypass-resurl', cat:'Angular Security', sev:'critical', re:/bypassSecurityTrustResourceUrl\s*\(/g, ctx: null },
  { id:'bypass-script', cat:'Angular Security', sev:'critical', re:/bypassSecurityTrustScript\s*\(/g, ctx: null },
  // B8: Error Handling Leakage
  { id:'err-console', cat:'Info Leakage', sev:'medium', re:/console\.(log|error|warn|info)\s*\(\s*(?:error|err|e|ex)\b/g, ctx: null },
  { id:'err-alert', cat:'Info Leakage', sev:'medium', re:/alert\s*\(\s*(?:error|err|e|ex)(?:\.message|\.stack)?\s*\)/g, ctx: null },
  { id:'err-tostring', cat:'Info Leakage', sev:'low', re:/\.toString\s*\(\s*\).*(?:innerHTML|textContent|innerText)\s*=/g, ctx: null },
  { id:'err-stacktrace', cat:'Info Leakage', sev:'high', re:/(?:error|err|e)\.stack\b/g, ctx: null },
  // B9: Source Map Artifacts
  { id:'sourcemap-ref', cat:'Info Leakage', sev:'low', re:/\/\/[#@]\s*sourceMappingURL\s*=/g, ctx: null },
  { id:'sourcemap-file', cat:'Info Leakage', sev:'low', re:/\.map["']\s*\)|\bsource-maps?\b/gi, ctx: null },
  // B10: Web Workers
  { id:'worker-new', cat:'Web Worker', sev:'info', re:/new\s+Worker\s*\(\s*(?:new\s+URL|['"`])/g, ctx: null },
  { id:'worker-blob', cat:'Web Worker', sev:'medium', re:/new\s+Worker\s*\(\s*URL\.createObjectURL/g, ctx: null },
  { id:'worker-importscripts', cat:'Web Worker', sev:'high', re:/importScripts\s*\(/g, ctx: null },
  // B11: File Upload Validation
  { id:'upload-type-client', cat:'File Upload', sev:'medium', re:/\.type\.(?:includes?|startsWith|indexOf|match)\s*\(\s*['"](?:image|video|text|application)/gi, ctx: null },
  { id:'upload-ext-client', cat:'File Upload', sev:'medium', re:/\.name\.(?:endsWith|split|match)\s*\([^)]*(?:jpg|png|pdf|zip|exe|svg)/gi, ctx: null },
  { id:'upload-size-client', cat:'File Upload', sev:'low', re:/\.size\s*(?:>|<|>=|<=|===)\s*\d+(?:\s*\*\s*1024)?/g, ctx: m => /file|upload|attach/i.test(m) },
];

// ═══════════════════════════════════════════════════════════════════════════
//  FRAMEWORK FINGERPRINTS
// ═══════════════════════════════════════════════════════════════════════════
const FRAMEWORKS = [
  { name:'Angular', re:/ɵɵdefineComponent|angular\.json|NgModule|@angular\//,
    score: s => (s.match(/ɵɵdefineComponent|ɵɵdefineInjectable|ɵɵelement/g)||[]).length,
    uniqueMarkers: [/@Component\s*\(/, /@NgModule\s*\(/, /@Injectable\s*\(/, /from\s*['"]@angular\/core['"]/, /ɵɵdefineComponent/] },
  { name:'Webpack 5', re:/webpackChunk[a-zA-Z]|__webpack_require__|self\.webpackChunk/ },
  { name:'Socket.io', re:/socket\.io|io\.connect|io\(\)|\.emit\(|\.on\("connect"\)/ },
  { name:'RxJS', re:/BehaviorSubject|switchMap|catchError|combineLatest|pipe\(/ },
  { name:'Svelte', re:/SvelteComponent|mount_component|create_fragment|svelte\/internal/,
    guard: s => !/angular|react/.test(s.toLowerCase().slice(0,2000)) },
  { name:'Next.js', re:/__NEXT_DATA__|next\/dist|_next\/static|usePathname|__N_SSP/ },
  { name:'Vite', re:/__vitePreload|import\.meta\.hot|__vite__mapDeps|@vite\/client/ },
  { name:'Vue', re:/from\s*['"]vue['"]|createApp\s*\(|defineComponent\s*\(\s*\{|__vccOpts|createElementVNode|Vue\.extend\s*\(|new\s+Vue\s*\(/,
    guard: s => !/@angular\/|ɵɵ|NgModule/.test(s.slice(0,5000)),
    uniqueMarkers: [/from\s*['"]vue['"]/, /createApp\s*\(/, /defineComponent\s*\(\s*\{/, /new\s+Vue\s*\(/] },
  { name:'React', re:/React\.createElement|ReactDOM\.render|useState\s*\(|jsx-runtime/ },
  { name:'Express', re:/app\.(?:get|post|put|delete|use)\s*\(\s*["']\//,
    guard: s => !/angular|router\.navigate/.test(s.slice(0,3000)) },
  { name:'jQuery', re:/\$\s*\(\s*document\s*\)|jQuery\s*\(/ },
  { name:'Lodash', re:/import\s+_\s+from\s+['"]lodash["']|_\.map\(|_\.filter\(/ },
  { name:'D3', re:/d3\.select|d3\.scale|d3\.arc/ },
];

// ═══════════════════════════════════════════════════════════════════════════
//  WEBPACK MODULE MAP
// ═══════════════════════════════════════════════════════════════════════════
const WEBPACK_MODULE_MAP = {
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

// ═══════════════════════════════════════════════════════════════════════════
//  CLI PARSING
// ═══════════════════════════════════════════════════════════════════════════
function parseArgs() {
  const args = process.argv.slice(2);
  if (!args.length || args[0] === '--help' || args[0] === '-h') { printHelp(); process.exit(0); }
  const o = {
    input: args[0], out: './omega_output',
    splitModules: false, beautify: true,
    secrets: false, routes: false, security: false,
    graph: false, report: false, verbose: false,
    // v5 upgrades
    ast: false, sourcemap: false, taint: false,
    webpack: false, esm: false, network: false,
    wasm: false, obfuscation: false, parallel: false,
    sarif: false, config: null,
    // v4 extended scanners
    dyncode: false, bizlogic: false, websocket: false,
    infoleak: false, idor: false, race: false,
    web3: false, lazy: false,
  };
  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case '--out':           o.out          = args[++i]; break;
      case '--split-modules': o.splitModules = true;      break;
      case '--no-beautify':   o.beautify     = false;     break;
      case '--secrets':       o.secrets      = true;      break;
      case '--routes':        o.routes       = true;      break;
      case '--security':      o.security     = true;      break;
      case '--graph':         o.graph        = true;      break;
      case '--report':        o.report       = true;      break;
      case '--verbose':       o.verbose      = true;      break;
      case '--no-color':      useColor       = false;     break;
      case '--ast':           o.ast          = true;      break;
      case '--sourcemap':     o.sourcemap    = true;      break;
      case '--taint':         o.taint        = true;      break;
      case '--webpack':       o.webpack      = true;      break;
      case '--esm':           o.esm          = true;      break;
      case '--network':       o.network      = true;      break;
      case '--wasm':          o.wasm         = true;      break;
      case '--obfuscation':   o.obfuscation  = true;      break;
      case '--parallel':      o.parallel     = true;      break;
      case '--sarif':         o.sarif        = true;      break;
      case '--config':        o.config       = args[++i]; break;
      case '--dyncode':       o.dyncode      = true;      break;
      case '--bizlogic':      o.bizlogic     = true;      break;
      case '--websocket':     o.websocket    = true;      break;
      case '--infoleak':      o.infoleak     = true;      break;
      case '--idor':          o.idor         = true;      break;
      case '--race':          o.race         = true;      break;
      case '--web3':          o.web3         = true;      break;
      case '--lazy':          o.lazy         = true;      break;
      case '--v5':
        o.ast = o.sourcemap = o.taint = o.webpack = o.esm =
        o.network = o.wasm = o.obfuscation = o.parallel = o.sarif = true;
        break;
      case '--all':
        o.splitModules = o.secrets = o.routes = o.security =
        o.graph = o.report = true;
        o.ast = o.sourcemap = o.taint = o.webpack = o.esm =
        o.network = o.wasm = o.obfuscation = o.parallel = o.sarif = true;
        o.dyncode = o.bizlogic = o.websocket = o.infoleak =
        o.idor = o.race = o.web3 = o.lazy = true;
        break;
    }
  }
  return o;
}

function printHelp() {
  console.log(`\n${C.bold('')}${C.cyan('JS Decoder OMEGA Unified')}${C.reset('')} ${VERSION}\n`);
  console.log('Usage:  node omega-unified.js <file.js> [options]\n');
  console.log('Shared options:');
  console.log('  --out <dir>        Output directory');
  console.log('  --split-modules    Write each webpack module to its own file');
  console.log('  --no-beautify      Skip formatting pass');
  console.log('  --secrets          Credential & secret key scanner');
  console.log('  --routes           API route / endpoint extractor');
  console.log('  --security         Full security scan');
  console.log('  --graph            Module dependency graph');
  console.log('  --report           Generate HTML + JSON + Markdown reports');
  console.log('  --all              Enable everything (v4 + v5)');
  console.log('  --verbose          Verbose progress output');
  console.log('  --no-color         Plain output\n');
  console.log('v5 upgrades (or --v5 for all):');
  console.log('  --ast              AST-based framework analysis');
  console.log('  --sourcemap        Sourcemap-aware decoder mode');
  console.log('  --taint            Cross-module taint tracking');
  console.log('  --webpack          Dynamic webpack module resolver');
  console.log('  --esm              ESM/Vite/Rollup/Parcel/esbuild support');
  console.log('  --network          Network surface extraction');
  console.log('  --wasm             WebAssembly binary analysis');
  console.log('  --obfuscation      Generic obfuscation decoder');
  console.log('  --parallel         Parallel scanning phases');
  console.log('  --sarif            SARIF 2.1.0 output');
  console.log('  --config <path>    Path to .omegalintrc config file\n');
  console.log('v4 extended scanners:');
  console.log('  --dyncode          Dynamic code execution analysis');
  console.log('  --bizlogic         Business logic analysis');
  console.log('  --websocket        WebSocket/Socket.io content analysis');
  console.log('  --infoleak         Info leakage/enumeration detection');
  console.log('  --idor             IDOR pattern detection');
  console.log('  --race             Race condition detection');
  console.log('  --web3             Web3/blockchain security');
  console.log('  --lazy             Lazy-loading route security\n');
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 0 — MODULE ALIAS RESOLVER
// ═══════════════════════════════════════════════════════════════════════════
function resolveModuleAliases(src, opts) {
  let resolved = 0;
  const aliases = {};
  const aliasRe = /(?:var|const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*d\((\d+)\)/g;
  let m;
  while ((m = aliasRe.exec(src)) !== null) {
    const [, varName, modId] = m;
    const pkgName = WEBPACK_MODULE_MAP[modId];
    if (pkgName) { aliases[varName] = pkgName; resolved++; }
  }
  if (opts.verbose && resolved) console.log(info(`  Resolved ${resolved} module aliases`));
  return { src, aliases, count: resolved };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 1 — ESCAPE DECODE
// ═══════════════════════════════════════════════════════════════════════════
function decodeEscapes(src) {
  const stats = { unicode:0, hex:0, octal:0, htmlEnt:0 };
  src = src.replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_,h) => { stats.unicode++; return String.fromCodePoint(parseInt(h,16)); });
  src = src.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => { stats.unicode++; return String.fromCharCode(parseInt(h,16)); });
  src = src.replace(/\\x([0-9a-fA-F]{2})/g, (_,h) => { stats.hex++; return String.fromCharCode(parseInt(h,16)); });
  const htmlEnts = {'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&apos;':"'",'&nbsp;':'\u00a0'};
  src = src.replace(/&(?:amp|lt|gt|quot|apos|nbsp);/g, e => { stats.htmlEnt++; return htmlEnts[e]||e; });
  return { src, stats };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 2 — STRING DECODE (10-pass iterative)
// ═══════════════════════════════════════════════════════════════════════════
function decodeStrings(src) {
  const totals = { charCode:0, base64:0, hexArr:0, concat:0 };
  for (let pass = 0; pass < 10; pass++) {
    let changed = false;
    src = src.replace(/String\.fromCharCode\s*\(([^)]+)\)/g, (_, args) => {
      try { const codes = args.split(',').map(x=>parseInt(x.trim(),10)).filter(n=>!isNaN(n)); if (!codes.length) return _; totals.charCode++; changed=true; return JSON.stringify(codes.map(c=>String.fromCharCode(c)).join('')); } catch { return _; }
    });
    src = src.replace(/atob\s*\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)/g, (_,b) => {
      try { totals.base64++; changed=true; return JSON.stringify(Buffer.from(b,'base64').toString('utf8')); } catch { return _; }
    });
    src = src.replace(/\[\s*((?:0x[0-9a-fA-F]{1,4}\s*,?\s*)+)\]/g, (_, inner) => {
      try { const nums = inner.split(',').map(x=>parseInt(x.trim(),16)).filter(n=>!isNaN(n)); if (nums.length<2) return _; const s=nums.map(c=>String.fromCharCode(c)).join(''); if (!/^[\x20-\x7e\t\n\r]+$/.test(s)) return _; totals.hexArr++; changed=true; return JSON.stringify(s); } catch { return _; }
    });
    src = src.replace(/["']([^"']*)["']\s*\+\s*["']([^"']*)["']/g, (_,a,b) => { totals.concat++; changed=true; return JSON.stringify(a+b); });
    for (let j = 0; j < 4; j++) src = src.replace(/["']([^"']*)["']\s*\+\s*["']([^"']*)["']/g, (_,a,b) => { totals.concat++; return JSON.stringify(a+b); });
    // Array join: ["a","b"].join("") — common in obfuscated bundles
    src = src.replace(/\[\s*((?:["'][^"']*["']\s*,?\s*)+)\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g, (_,items) => {
      try { const parts=[...items.matchAll(/["']([^"']*)["']/g)].map(m=>m[1]); if(parts.length<2)return _; totals.concat++; changed=true; return JSON.stringify(parts.join('')); }catch{return _;}
    });
    if (!changed) break;
  }
  return { src, stats: totals };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 2b — CHARCODE OBFUSCATION DECODER (v4)
// ═══════════════════════════════════════════════════════════════════════════
function decodeCharCodeObfuscation(src) {
  const findings = [];
  const ctxRe = /reverse\(\s*\)\.map\s*\(\s*function\s*\([^)]*\)\s*\{\s*return\s+String\.fromCharCode\s*\(([^)]+)\)\s*\}\s*\)\.join\s*\(\s*["']["']\s*\)\s*\}\s*\(([^)]+)\)/g;
  let m;
  const rawMatches = [];
  while ((m = ctxRe.exec(src)) !== null) {
    const offsetExpr = m[1].trim();
    const argStr = m[2].trim();
    const args = argStr.split(',').map(x=>parseInt(x.trim(),10)).filter(n=>!isNaN(n));
    if (args.length < 3 || args.length > 32) continue;
    const fixedOffset = [...offsetExpr.matchAll(/\d+/g)].map(x=>parseInt(x[0])).reduce((a,b)=>a+b,0);
    const seed = args[0];
    const bytes = args.slice(1);
    const decoded = [...bytes].reverse().map((o,a)=>String.fromCharCode(o-seed-fixedOffset-a)).join('');
    if (!/^[\x20-\x7e]{2,}$/.test(decoded)) continue;
    rawMatches.push({ index:m.index, end:m.index+m[0].length, match:m[0], decoded, seed, bytes:args, offsetExpr, context:src.slice(Math.max(0,m.index-60),m.index+80).replace(/\n/g,' ') });
  }
  const assembledSeen = new Set();
  for (let i = 0; i < rawMatches.length; i++) {
    const gap = src.slice(rawMatches[i].end, rawMatches[i].end + 600);
    const adj = /^((?:\s*\+\s*["'][a-zA-Z0-9\-_/]*["'](?:\.toLowerCase\(\))?\s*)*)\s*\+\s*function/.exec(gap);
    if (!adj) continue;
    const nextMatch = rawMatches[i + 1];
    if (!nextMatch || nextMatch.index > rawMatches[i].end + 600) continue;
    const betweenText = src.slice(rawMatches[i].end, nextMatch.end);
    const midLiterals = [...betweenText.matchAll(/["']([a-zA-Z0-9\-_/]{0,20})["']\.toLowerCase\(\)/g)].map(x=>x[1]);
    const afterText = src.slice(nextMatch.end, nextMatch.end + 200);
    const trailLiterals = [...afterText.matchAll(/\+\s*["']([a-zA-Z0-9\-_/]{0,20})["']\.toLowerCase\(\)/g)].map(x=>x[1]);
    const assembled = rawMatches[i].decoded + midLiterals.join('') + nextMatch.decoded + trailLiterals.join('');
    if (assembled.length < 4 || assembledSeen.has(assembled) || !/^[\x20-\x7e]+$/.test(assembled)) continue;
    assembledSeen.add(assembled);
    findings.push({ decoded:assembled, seed:rawMatches[i].seed, bytes:[], offsetExpr:'multi-segment-concat', isAssembled:true, segments:[rawMatches[i].decoded,nextMatch.decoded], literals:[...midLiterals,...trailLiterals], context:betweenText.slice(0,120).replace(/\n/g,' ') });
  }
  const indivSeen = new Set();
  for (const rm of rawMatches) {
    if (!indivSeen.has(rm.decoded)) { indivSeen.add(rm.decoded); findings.unshift({ decoded:rm.decoded, seed:rm.seed, bytes:rm.bytes, offsetExpr:rm.offsetExpr, context:rm.context }); }
  }
  let mutatedSrc = src;
  for (const rm of [...rawMatches].reverse()) {
    mutatedSrc = mutatedSrc.slice(0, rm.index) + `/* OMEGA-decoded: "${rm.decoded}" */` + mutatedSrc.slice(rm.index);
  }
  return { src: mutatedSrc, findings };
}

function normaliseBooleans(src) {
  return src.replace(/\b!0\b/g,'true').replace(/\b!1\b/g,'false').replace(/\bvoid\s+0\b/g,'undefined').replace(/\bvoid\(0\)/g,'undefined').replace(/\b!!\[\]/g,'true').replace(/\b!\[\]/g,'false').replace(/\+\[\]/g,'0');
}

function cleanupWebpack(src) {
  return src.replace(/\(0\s*,\s*([A-Za-z_$][A-Za-z0-9_$.]*)\)\s*\(/g,'$1(').replace(/__webpack_require__/g,'require').replace(/Object\.defineProperty\s*\(\s*\w+\s*,\s*["']__esModule["']\s*,\s*\{[^}]*\}\s*\)\s*;?/g,'/* ESModule */').replace(/\/\*\*\*\/\s*\(function\s*\(/g,'/* webpack-module */ (function(').replace(/\/\*\s*!eval\s*\*\//g,'/* eval */');
}

function annotateAngularIvy(src) {
  for (const [pat,repl] of Object.entries(ANGULAR_UNICODE_PROPS)) src = src.replace(new RegExp(pat,'g'), repl);
  for (const [short,full] of Object.entries(ANGULAR_IVY_MAP)) {
    const escaped = short.replace(/[$]/g,'\\$');
    src = src.replace(new RegExp(`(\\w+)\\.${escaped}(\\s*\\()`, 'g'), `$1.${full}$2`);
    src = src.replace(new RegExp(`(?<![.\\w])${escaped}(\\s*\\()`, 'g'), `${full}$1`);
  }
  for (const [pat,repl] of Object.entries(ANGULAR_STATIC_MAP)) src = src.split(pat).join(repl);
  return src;
}

function detectFrameworkHits(src) {
  return {
    angular:/ɵɵ|ɵcmp|ɵfac|ɵprov|ivy/.test(src), vue:/__vccOpts|createElementVNode|openBlock|__vueParentComponent/.test(src),
    react:/React\.createElement|__reactFiber|jsx-runtime|react-dom/.test(src), svelte:/SvelteComponent|mount_component|create_fragment|svelte\/internal/.test(src),
    nextjs:/__NEXT_DATA__|next\/dist|_next\/static|usePathname/.test(src), webpack:/__webpack_require__|webpackChunk|webpackJsonp/.test(src),
    vite:/__vitePreload|import\.meta\.hot|__vite__mapDeps/.test(src), lodash:/import\s+_\s+from|lodash-es|_\.map\(|_\.filter\(/.test(src),
    dateFns:/date-fns|parseISO|formatISO|differenceInDays/.test(src), zod:/z\.object|z\.string|\.safeParse|zod/.test(src),
    zustand:/create.*store|useStore|devtools.*zustand|zustand/.test(src), immer:/produce|createDraft|finishDraft|immer/.test(src),
    corejs:/__core-js_shared__|IS_PURE|NATIVE_WEAK_MAP|core-js/.test(src),
  };
}

function applySymbolMap(src, map, minTopLevel) {
  if (minTopLevel === undefined) minTopLevel = 3;
  let count = 0;
  for (const [short, full] of Object.entries(map)) {
    if (short.length < 2) continue;
    const esc = short.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const prev = src;
    src = src.replace(new RegExp('(\\w+)\\.'+esc+'(\\s*\\()','g'), '$1.'+full+'$2');
    if (short.length >= minTopLevel) src = src.replace(new RegExp('(?<![.\\w])'+esc+'(\\s*\\()','g'), full+'$1');
    if (src !== prev) count++;
  }
  return { src, count };
}

function applyLiteralMap(src, map) {
  let count = 0;
  for (const [key, replacement] of Object.entries(map)) {
    if (src.includes(key)) { src = src.split(key).join(replacement); count++; }
  }
  return { src, count };
}

function annotateFrameworkSymbols(src, opts) {
  const hits = detectFrameworkHits(src);
  const stats = { frameworks: [], symbolsAnnotated: 0 };
  const apply = (map, label, minTopLevel) => {
    const r = applySymbolMap(src, map, minTopLevel !== undefined ? minTopLevel : 2);
    src = r.src;
    if (r.count > 0) { stats.symbolsAnnotated += r.count; if (!stats.frameworks.includes(label)) stats.frameworks.push(label); }
  };
  const literal = (map, label) => {
    const r = applyLiteralMap(src, map);
    src = r.src;
    if (r.count > 0) { stats.symbolsAnnotated += r.count; if (!stats.frameworks.includes(label)) stats.frameworks.push(label); }
  };
  if (hits.vue)     { apply(VUE3_VNODE_MAP,'Vue3'); apply(VUE_ROUTER_MAP,'Vue3-Router'); literal(VUE3_INTERNAL_PROPS,'Vue3-Internals'); }
  if (hits.react)   { apply(REACT_HOOKS_MAP,'React-Hooks'); apply(REACT_DOM_MAP,'React-DOM'); apply(REACT_EVENTS_MAP,'React-Events'); for (const [rk,rpl] of Object.entries(REACT_FIBER_PROPS)) { try { src=src.replace(new RegExp(rk,'g'),rpl); stats.symbolsAnnotated++; } catch{} } if (!stats.frameworks.includes('React')) stats.frameworks.push('React'); }
  if (hits.svelte)  { apply(SVELTE_RUNTIME_MAP,'Svelte'); }
  if (hits.nextjs)  { apply(NEXTJS_RUNTIME_MAP,'Next.js'); literal(NEXTJS_LITERAL_MAP,'Next.js-Internals'); }
  if (hits.webpack) { literal(WEBPACK_RUNTIME_COMMENTS,'Webpack-Runtime'); }
  if (hits.vite)    { literal(VITE_RUNTIME_COMMENTS,'Vite-Runtime'); }
  if (hits.lodash)  { apply(LODASH_ES_MAP,'Lodash-ES'); }
  if (hits.dateFns) { apply(DATE_FNS_MAP,'date-fns'); }
  if (hits.zod)     { apply(ZOD_MAP,'Zod'); }
  if (hits.zustand) { apply(ZUSTAND_MAP,'Zustand'); }
  if (hits.immer)   { apply(IMMER_MAP,'Immer'); }
  if (hits.corejs)  { literal(COREJS_SHIMS_COMMENTS,'core-js'); }
  return { src, hits, stats };
}

function annotateRxJS(src) {
  for (const [pattern, comment] of Object.entries(RXJS_OPERATORS)) {
    const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    src = src.replace(new RegExp(`(?<![\\w])${escaped}(?![\\w])`,'g'), `${comment}${pattern}`);
  }
  return src;
}

function beautify(src) {
  const out = []; let depth = 0, tmpl = 0, i = 0; const n = src.length;
  let inStr = false, strChar = '', inLineComment = false, inBlockComment = false, inTmplExpr = false;
  let lastNonWs = '', hadSpace = false;
  const indent = () => INDENT.repeat(Math.max(0,depth));
  const compoundOpRe = /^(==|===|!=|!==|>=|<=|\|\||&&|\+\+|--|<<|>>|>>>|\*\*|=>|\?\?|\?\.|<<=|>>=|>>>=|\*\=|\+=|-=|\/=|%=|&=|\|=|\^=)$/;
  const idRe = /[a-zA-Z0-9_$]/;
  while (i < n) {
    const ch = src[i]; const ch2 = src[i+1]||'';
    if (tmpl > 0 && !inTmplExpr) {
      if (ch === '`') { tmpl--; out.push(ch); i++; continue; }
      if (ch === '$' && ch2 === '{') { inTmplExpr = true; out.push(ch); out.push(ch2); i += 2; continue; }
      out.push(ch); i++; continue;
    }
    if (inTmplExpr) {
      if (ch === '{') { depth++; out.push(ch); i++; continue; }
      if (ch === '}') { depth--; out.push(ch); if (depth === 0) inTmplExpr = false; i++; continue; }
      out.push(ch); i++; continue;
    }
    if (!inStr&&!inBlockComment&&ch==='/'&&ch2==='/') inLineComment=true;
    if (inLineComment) { out.push(ch); if (ch==='\n') { inLineComment=false; hadSpace=true; out.push(indent()); } i++; continue; }
    if (!inStr&&!inLineComment&&ch==='/'&&ch2==='*') inBlockComment=true;
    if (inBlockComment) { out.push(ch); if (ch==='*'&&ch2==='/') { inBlockComment=false; out.push('/'); i+=2; continue; } i++; continue; }
    if (!inStr&&(ch==='"'||ch==="'"||(ch==='`'&&!tmpl))) { inStr=true; strChar=ch; out.push(ch); i++; continue; }
    if (inStr) { if (ch==='\\') { out.push(ch); out.push(ch2); i+=2; continue; } out.push(ch); if (ch===strChar) inStr=false; i++; continue; }
    if (ch==='`') { tmpl++; out.push(ch); i++; continue; }
    if (ch===' '||ch==='\t'||ch==='\r') { hadSpace = true; i++; continue; }
    if (ch==='\n') { hadSpace = true; i++; continue; }
    if (ch==='{') { out.push(' {\n'); depth++; out.push(indent()); lastNonWs='{'; hadSpace=false; i++; continue; }
    if (ch==='}') { depth=Math.max(0,depth-1); out.push('\n'); out.push(indent()); out.push('}'); const rr=src.slice(i+1).replace(/\s/g,''); if (rr&&idRe.test(rr[0])) out.push(' '); lastNonWs='}'; hadSpace=false; i++; continue; }
    if (ch===';') {
      const after = src.slice(i+1).replace(/\s/g,'');
      if (after[0]===';'||after[0]===')') { out.push('; '); } else { out.push(';\n'); out.push(indent()); }
      lastNonWs=';'; hadSpace=false; i++; continue;
    }
    if (ch===',') { out.push(', '); lastNonWs=','; hadSpace=false; i++; continue; }
    // don't let tokens merge after whitespace (e.g. `returna`, `functionfoo`, `}else`)
    if (hadSpace && (idRe.test(lastNonWs) || lastNonWs === '}') && (idRe.test(ch) || ch === '{')) out.push(' ');
    hadSpace = false;
    // operator spacing — don't split compound operators
    if ('=><+-*%&|^!~'.includes(ch)) {
      const two = ch + ch2;
      const prev = lastNonWs + ch;
      if (!compoundOpRe.test(two) && !compoundOpRe.test(prev)) {
        if (!' \n'.includes(lastNonWs)) out.push(' ');
      }
    }
    out.push(ch); lastNonWs=ch; i++;
  }
  return out.join('').replace(/\n{3,}/g,'\n\n').trim();
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 8 — CODE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════
function analyseCode(src) {
  const fnRe = /(?:function\s*\*?\s*\w*\s*\(|=>\s*\{|\b(?:async\s+)?function\s*\()/g;
  const functions = (src.match(fnRe)||[]).length;
  const classes = (src.match(/\bclass\s+\w+/g)||[]).length;
  const components = (src.match(/ɵɵdefineComponent/g)||[]).length;
  const services = (src.match(/ɵɵdefineInjectable/g)||[]).length;
  const pipes = (src.match(/ɵɵdefinePipe/g)||[]).length;
  const directives = (src.match(/ɵɵdefineDirective/g)||[]).length;
  const httpCalls = (src.match(/this\.\w+\.(?:get|post|put|delete|patch)\s*\(/g)||[]).length;
  const evalCalls = (src.match(/\beval\s*\(/g)||[]).length;
  const decisions = (src.match(/\bif\b|\belse\b|\bfor\b|\bwhile\b|\bcase\b|\bcatch\b|\?\s*[^:]/g)||[]).length;
  const cyclomatic = decisions + 1;
  let maxDepth = 0, currDepth = 0, inStr2 = false, strCh2 = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (!inStr2&&(c==='"'||c==="'"||c==='`')) { inStr2=true; strCh2=c; continue; }
    if (inStr2) { if (src[i-1]!=='\\'&&c===strCh2) inStr2=false; continue; }
    if (c==='{') { currDepth++; maxDepth=Math.max(maxDepth,currDepth); }
    if (c==='}') currDepth=Math.max(0,currDepth-1);
  }
  const guardMatches = [...src.matchAll(/canActivate\s*:\s*\[([^\]]+)\]/g)];
  const routeGuards = guardMatches.map(m=>m[1].trim());
  const socketEmits = [...(src.matchAll(/\.emit\s*\(\s*["']([^"']+)["']/g))].map(m=>m[1]);
  const socketOns = [...(src.matchAll(/\.on\s*\(\s*["']([^"']+)["']/g))].map(m=>m[1]);
  const reactComponents = (src.match(/(?:function|const)\s+[A-Z][A-Za-z0-9]+\s*(?:=\s*(?:\([^)]*\)|[A-Za-z_$])\s*=>|\([^)]*\)\s*\{)[^}]*(?:return\s*(?:<|jsx|createElement))/g)||[]).length;
  const vueComponents = (src.match(/createElementVNode|defineComponent|__vccOpts/g)||[]).length;
  const svelteComponents = (src.match(/SvelteComponent|create_fragment/g)||[]).length;
  return { functions, classes, components, services, pipes, directives, reactComponents, vueComponents, svelteComponents, httpCalls, evalCalls, cyclomatic, maxNesting: maxDepth, routeGuards: [...new Set(routeGuards)], socketEmits: [...new Set(socketEmits)], socketOns: [...new Set(socketOns)] };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 8b — STORAGE KEY AUDIT
// ═══════════════════════════════════════════════════════════════════════════
function auditStorageKeys(src) {
  const lsMap = {}, ckMap = {};
  let m;
  const storeRe = /(localStorage|sessionStorage)\.(getItem|setItem|removeItem|clear)\s*\(\s*["']([^"']+)["']/g;
  while ((m = storeRe.exec(src)) !== null) {
    const store = m[1] === 'localStorage' ? 'local' : 'session';
    const op = m[2]; const key = m[3];
    if (!lsMap[key]) lsMap[key] = { store, ops: new Set() };
    lsMap[key].ops.add(op.replace('Item','').replace('clear','clear'));
  }
  const ckRe = /cookieService\.(get|put|remove)\s*\(\s*["']([^"']+)["']/g;
  while ((m = ckRe.exec(src)) !== null) {
    const key = m[2]; if (!ckMap[key]) ckMap[key] = { ops: new Set() };
    ckMap[key].ops.add(m[1]);
  }
  const sensitiveRe = /token|password|secret|auth|credential|session|jwt|totp|key|email/i;
  const flag = arr => arr.map(e => ({ ...e, sensitive: sensitiveRe.test(e.key) }));
  const localStorage = flag(Object.entries(lsMap).filter(([,v])=>v.store==='local').map(([k,v])=>({key:k,ops:[...v.ops].sort()})).sort((a,b)=>a.key.localeCompare(b.key)));
  const sessionStorage = flag(Object.entries(lsMap).filter(([,v])=>v.store==='session').map(([k,v])=>({key:k,ops:[...v.ops].sort()})).sort((a,b)=>a.key.localeCompare(b.key)));
  const cookies = flag(Object.entries(ckMap).map(([k,v])=>({key:k,ops:[...v.ops].sort()})).sort((a,b)=>a.key.localeCompare(b.key)));
  return { localStorage, sessionStorage, cookies, totalKeys: localStorage.length + sessionStorage.length + cookies.length, sensitiveCount: [...localStorage,...sessionStorage,...cookies].filter(e=>e.sensitive).length };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 8c — AUTH SURFACE MAPPER
// ═══════════════════════════════════════════════════════════════════════════
function mapAuthSurface(src) {
  const guardedRoutes = [], unguardedRoutes = [];
  const highValueRe = /admin|account|wallet|score|payment|order|data.?export|2fa|two.?factor|deluxe|membership|recycl|address|profile|change.?pass|reset.?pass/i;
  let m;
  const guardRe = /path\s*:\s*["']([^"']{0,120})["']([^{};]{0,400}?)canActivate\s*:\s*\[([^\]]+)\]/g;
  while ((m = guardRe.exec(src)) !== null) guardedRoutes.push({ path:'/'+m[1], guards:m[3].trim().split(',').map(s=>s.trim()) });
  const allRoutesRe = /path\s*:\s*["']([^"']{1,120})["'][^{};]{0,400}?(?:component|loadChildren)\s*:/g;
  const allPaths = new Set();
  while ((m = allRoutesRe.exec(src)) !== null) allPaths.add(m[1]);
  const guardedPaths = new Set(guardedRoutes.map(r=>r.path.replace(/^\//,'')));
  for (const p of allPaths) { if (!guardedPaths.has(p) && highValueRe.test(p)) unguardedRoutes.push({ path:'/'+p, risk:'HIGH — sensitive route with no canActivate guard detected' }); }
  const btoaRe = /btoa\s*\(([^)]{0,120}(?:split|reverse)[^)]{0,120})\)/g;
  const btoaMisuse = []; const btoaSeen = new Set();
  while ((m = btoaRe.exec(src)) !== null) { const expr=m[1].trim().slice(0,100); if (!btoaSeen.has(expr)) { btoaSeen.add(expr); btoaMisuse.push({ expr, context:src.slice(Math.max(0,m.index-40),m.index+100).replace(/\n/g,' ').trim(), severity:'critical', note:'btoa(x.split("").reverse().join("")) — trivially reversible' }); } }
  const endpointMap = [];
  const httpRe = /this\.\w+\.(?:get|post|put|delete|patch)\s*<[^>]*>\s*\(\s*["'`]([^"'`]+)["'`]/g;
  while ((m = httpRe.exec(src)) !== null) { const ep=m[1]; const surrounding=src.slice(Math.max(0,m.index-300),m.index+50); const hasAuthHeader=/Authorization|Bearer|x-auth-token|token|jwt/i.test(surrounding); const hasGuardContext=/canActivate|AuthGuard|auth\.isLoggedIn/i.test(surrounding); endpointMap.push({ endpoint:ep, hasAuthHeader, hasGuardContext, risk:(!hasAuthHeader&&!hasGuardContext)?'potential-unprotected':'appears-protected' }); }
  const unprotectedEndpoints = endpointMap.filter(e=>e.risk==='potential-unprotected');
  return { guardedRoutes, unguardedRoutes, btoaMisuse, endpointMap, unprotectedEndpoints };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 9 — FRAMEWORK DETECTION
// ═══════════════════════════════════════════════════════════════════════════
function detectFrameworks(src) {
  const found = []; const sample = src.slice(0,10000);
  for (const fw of FRAMEWORKS) {
    if (fw.guard && !fw.guard(sample)) continue;
    if (!fw.re.test(src)) continue;
    let confidence = 0.6;
    if (fw.uniqueMarkers) {
      const matchedUnique = fw.uniqueMarkers.filter(m=>m.test(src)).length;
      if (matchedUnique === 0) continue;
      confidence = Math.min(0.5 + matchedUnique * 0.15, 1.0);
    }
    const entry = { name:fw.name, confidence:parseFloat(confidence.toFixed(2)) };
    if (fw.score) entry.score = fw.score(src);
    found.push(entry);
  }
  const hasAngular = found.some(f=>f.name==='Angular');
  const filtered = hasAngular ? found.filter(f=>f.name!=='Vue') : found;
  const names = filtered.map(f=>f.name);
  names._details = filtered;
  return names;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 10 — ROUTE EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════
function extractRoutes(src, charCodeFindings, rawSrc) {
  const routes = new Map();
  const addRoute = (rawPath, type, meta) => { if (!rawPath) return; let p=rawPath.replace(/\s+/g,'').replace(/\\n/g,''); if (!p||p.length<1) return; if (!routes.has(p)) routes.set(p,{path:p,type,...(meta||{})}); else if(meta&&meta.guarded) routes.get(p).guarded=true; };
  let m;
  const restRe = /["'](\/(?:api|rest|graphql|v\d+)\/[^"'\s<>{}|\\^`[\]]{1,120})["']/g;
  while ((m = restRe.exec(src)) !== null) addRoute(m[1],'REST');
  const fetchRe = /(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:get|post|put|delete))\s*\(\s*["']([^"']+)["']/g;
  while ((m = fetchRe.exec(src)) !== null) addRoute(m[1],'HTTP');
  const ngRoutRe = /path\s*:\s*["']([^"']{0,120})["'][^{};]{0,400}?(?:component|loadChildren)\s*:/g;
  while ((m = ngRoutRe.exec(src)) !== null) { const raw=m[1]; if (raw==='') continue; const ahead=src.slice(m.index,m.index+300); addRoute('/'+raw,'Angular',ahead.includes('canActivate')?{guarded:true}:{}); }
  if (/path\s*:\s*["']\*\*["']/.test(src)) addRoute('/**','Angular');
  const parentChildRe = /path\s*:\s*["']([^"']{1,80})["'][^;]{0,100}children\s*:\s*\[([^\]]{0,2000})\]/g;
  while ((m = parentChildRe.exec(src)) !== null) { const parent=m[1]; const childBlock=m[2]; addRoute('/'+parent,'Angular-Parent'); const childPathRe=/path\s*:\s*["']([^"']{1,80})["']/g; let cm; while((cm=childPathRe.exec(childBlock))!==null) { if(cm[1].length>0) addRoute('/'+parent+'/'+cm[1],'Angular-Child'); } }
  const childArrRe = /(?:=\s*)?\(\s*\)\s*(?:=\s*>|=>)\s*\[\s*["']([a-zA-Z0-9_\-/]{3,80})["']\s*\]/g;
  while ((m = childArrRe.exec(src)) !== null) { if(m[1].includes('/')) addRoute('/'+m[1],'Angular-Child'); }
  const ivySrc = rawSrc || src;
  const ivyRouteLinkRe = /["']routerLink["']\s*,\s*["']([^"']{1,120})["']/g;
  while ((m = ivyRouteLinkRe.exec(ivySrc)) !== null) { const p=m[1]; if(/^\/[a-zA-Z]/.test(p)) addRoute(p,'Angular-RouterLink'); else if(/^[a-zA-Z][a-zA-Z0-9\-_]+\//.test(p)) addRoute('/'+p,'Angular-RouterLink'); }
  const navRe = /router\.navigate\s*\(\s*\[\s*["']([a-zA-Z0-9_\-/]{2,80})["']/g;
  while ((m = navRe.exec(src)) !== null) { const p=m[1].replace(/^\/+/,''); if(p.length>1) addRoute('/'+p,'Angular-Nav'); }
  const wsRe = /wss?:\/\/[^\s"'<>]{4,80}/g;
  while ((m = wsRe.exec(src)) !== null) addRoute(m[0],'WebSocket');
  const gqlRe = /(?:query|mutation|subscription)\s+\w+/g;
  while ((m = gqlRe.exec(src)) !== null) addRoute(m[0],'GraphQL');
  const nextRouteRe = /["'](\/(?:app|pages)\/[^"'\s]{1,80})["']/g;
  while ((m = nextRouteRe.exec(src)) !== null) addRoute(m[1],'Next.js');
  if (charCodeFindings && charCodeFindings.length) {
    for (const f of charCodeFindings) {
      const decoded = f.decoded||'';
      if (/^[a-z0-9][a-z0-9\-_/]{2,}$/.test(decoded)) {
        const label = f.isAssembled ? 'Hidden-Assembled' : 'Hidden-Decoded';
        addRoute('/'+decoded, label, { note:f.isAssembled?`segments: [${(f.segments||[]).map(s=>`"${s}"`).join(',')}] + literals: [${(f.literals||[]).map(l=>`"${l}"`).join(',')}]`:`seed=${f.seed}, expr=${f.offsetExpr}` });
      }
    }
  }
  return [...routes.values()].sort((a,b)=>a.path.localeCompare(b.path));
}

function lineFromPos(src, pos) {
  let line = 1;
  for (let i = 0; i < pos && i < src.length; i++) { if (src[i] === '\n') line++; }
  return line;
}

function buildLineIndex(src) {
  const lineStarts = [0];
  for (let i = 0; i < src.length; i++) { if (src[i] === '\n') lineStarts.push(i + 1); }
  lineStarts.push(src.length + 1);
  return function posToLine(pos) {
    if (pos < 0 || pos >= src.length) return 1;
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= pos) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 11 — CREDENTIAL SCANNER
// ═══════════════════════════════════════════════════════════════════════════
function scanCredentials(src) {
  const findings = []; const seen = new Set();
  for (const pat of CREDENTIAL_PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      const value = (m[1]||m[0]).trim();
      if (!value||value.length<3) continue;
      if (pat.fpGuard && pat.fpGuard(value)) continue;
      const key = `${pat.name}::${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ id:m[0].length>30?pat.name:pat.name+'-', name:pat.name, severity:pat.severity, value:value.slice(0,120), context:src.slice(Math.max(0,m.index-40),m.index+80).replace(/\n/g,' '), pos:m.index, line:lineFromPos(src,m.index) });
    }
  }
  const order = {critical:0,high:1,medium:2,low:3,info:4};
  return findings.sort((a,b)=>(order[a.severity]||4)-(order[b.severity]||4));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12 — SECURITY ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════
function analyseSecurity(src) {
  const findings = []; const seen = new Set();
  for (const pat of SECURITY_PATTERNS) {
    const re = new RegExp(pat.re.source, 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      const snippet = src.slice(Math.max(0,m.index-100), m.index+120);
      if (pat.ctx && !pat.ctx(snippet)) continue;
      const value = (m[1]||m[0]).slice(0,100);
      const key = `${pat.id}::${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ id:pat.id, category:pat.cat, severity:pat.sev, value, context:snippet.replace(/\n/g,' ').trim(), pos:m.index, line:lineFromPos(src,m.index) });
    }
  }
  const order = {critical:0,high:1,medium:2,low:3,info:4};
  return findings.sort((a,b)=>(order[a.severity]||4)-(order[b.severity]||4));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12b — DYNAMIC CODE EXECUTION DETECTOR (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanDynamicCodeExecution(src) {
  const findings = []; const seen = new Set();
  const ctx = (i,r=150) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  const patterns = [
    { re:/(?:setTimeout|setInterval)\s*\(\s*(["'`][^"'`]{0,200}["'`]|[A-Za-z_$][A-Za-z0-9_$.]*(?!\s*=>|\s*function|\s*\())\s*,/g, type:'setTimeout/Interval-string', sev:'critical', desc:'String argument evaluated as code' },
    { re:/new\s+Function\s*\(/g, type:'Function-constructor', sev:'critical', desc:'Function constructor evaluates string as code' },
    { re:/\(\s*0\s*,\s*eval\s*\)\s*\(/g, type:'indirect-eval', sev:'critical', desc:'Indirect eval bypasses strict-mode' },
    { re:/execScript\s*\(/g, type:'execScript', sev:'high', desc:'Legacy IE code execution' },
    { re:/WebAssembly\.(?:instantiate|compile|instantiateStreaming)\s*\(/g, type:'WebAssembly', sev:'medium', desc:'WebAssembly binary can execute native code' },
    { re:/importScripts\s*\(\s*([^)]+)\)/g, type:'importScripts', sev:'high', desc:'importScripts loads external code into Worker' },
  ];
  for (const pat of patterns) {
    const re = new RegExp(pat.re.source, 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      if (pat.type==='setTimeout/Interval-string') { const arg=m[1]||''; if (/^\s*(?:function|\(|[A-Za-z_$][A-Za-z0-9_$.]*\s*=>)/.test(arg)) continue; }
      const key = `${pat.type}::${m.index}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ id:`dyncode-${pat.type}`, category:'Dynamic Code Execution', severity:pat.sev, value:m[0].slice(0,100), context:ctx(m.index), description:pat.desc });
    }
  }
  return findings.sort((a,b)=>({critical:0,high:1,medium:2,low:3}[a.severity]||3)-({critical:0,high:1,medium:2,low:3}[b.severity]||3));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12c — BUSINESS LOGIC DETECTOR (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanBusinessLogic(src) {
  const findings = []; const ctx = (i,r=200) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const rateLimitRe = /localStorage\.(?:getItem|setItem)\s*\(\s*["'](?:last|prev|time|rate|limit)[^"']*["']/gi;
  while ((m = rateLimitRe.exec(src)) !== null) findings.push({ id:'bl-ratelimit', category:'Business Logic', severity:'medium', value:m[0].slice(0,100), context:ctx(m.index), description:'Client-side rate limiting via localStorage — bypass by clearing storage' });
  const balanceRe = /(?:balance|wallet|credit|amount)\s*(?:<|>|<=|>=|===|!==)\s*(?:total|price|amount|cost|\d)/gi;
  while ((m = balanceRe.exec(src)) !== null) findings.push({ id:'bl-balance', category:'Business Logic', severity:'high', value:m[0].slice(0,100), context:ctx(m.index), description:'Client-side balance check — bypass by modifying JS variables' });
  const couponRe = /(?:coupon|promo|discount|voucher)\s*(?:===|==|includes?|match)/gi;
  while ((m = couponRe.exec(src)) !== null) findings.push({ id:'bl-coupon', category:'Business Logic', severity:'high', value:m[0].slice(0,100), context:ctx(m.index), description:'Client-side coupon validation — valid codes visible in bundle' });
  const hcCouponRe = /["'][A-Z0-9]{4,}['"]\s*(?:===|==)\s*(?:coupon|promo|code)/gi;
  while ((m = hcCouponRe.exec(src)) !== null) findings.push({ id:'bl-hardcoded-coupon', category:'Business Logic', severity:'critical', value:m[0].slice(0,100), context:ctx(m.index), description:'Hardcoded coupon code comparison in client bundle' });
  const roleRe = /(?:role|admin|premium|deluxe|vip)\s*(?:===|==|!==|!=)\s*["']\w+["']/gi;
  while ((m = roleRe.exec(src)) !== null) findings.push({ id:'bl-access-control', category:'Business Logic', severity:'medium', value:m[0].slice(0,100), context:ctx(m.index), description:'Client-side role check — bypass by modifying role variable' });
  const featureRe = /(?:featureFlag|config|settings)\.\w+\s*(?:\?|&&)/gi;
  while ((m = featureRe.exec(src)) !== null) { const c=ctx(m.index); if (/admin|premium|beta|internal|hidden/i.test(c)) findings.push({ id:'bl-feature-flag', category:'Business Logic', severity:'low', value:m[0].slice(0,100), context:c, description:'Feature flag gating sensitive functionality on client' }); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12d — WEBSOCKET & SOCKET.IO CONTENT ANALYZER (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanWebSocketContent(src) {
  const findings = []; const ctx = (i,r=250) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  const socketOnRe = /\.on\s*\(\s*["']([^"']+)["']\s*,\s*(?:function\s*\([^)]*\)|[^)=\s>]+\s*=>)\s*\{([^}]{0,400})\}/gs;
  let m;
  while ((m = socketOnRe.exec(src)) !== null) {
    const event=m[1]; const body=m[2];
    if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.html\(/.test(body)) findings.push({ id:'ws-dom-sink', category:'WebSocket XSS', severity:'critical', value:`socket.on("${event}") → DOM sink`, context:ctx(m.index), description:`Socket.io event "${event}" handler writes data directly to DOM` });
    if (/eval\s*\(|new\s+Function/.test(body)) findings.push({ id:'ws-code-exec', category:'WebSocket Code Exec', severity:'critical', value:`socket.on("${event}") → eval/Function`, context:ctx(m.index), description:`Socket.io event "${event}" handler evaluates received data as code` });
  }
  const wsOnMsgRe = /\.onmessage\s*=\s*(?:function\s*\([^)]*\)|[^=>\s]+\s*=>)\s*\{([^}]{0,400})\}/gs;
  while ((m = wsOnMsgRe.exec(src)) !== null) {
    const body=m[1];
    if (/innerHTML|outerHTML|document\.write/.test(body)) findings.push({ id:'ws-raw-dom', category:'WebSocket XSS', severity:'critical', value:'ws.onmessage → DOM sink', context:ctx(m.index), description:'Raw WebSocket onmessage writes event.data directly to DOM' });
    if (/JSON\.parse/.test(body)&&!/origin|source/.test(body)) findings.push({ id:'ws-json-nocheck', category:'WebSocket Security', severity:'medium', value:'ws.onmessage → JSON.parse (no origin check)', context:ctx(m.index), description:'WebSocket message parsed without origin/source validation' });
  }
  const socketEmitBodyRe = /\.emit\s*\(\s*["']([^"']+)["']\s*(?:,([^)]{0,200}))?\)/g;
  while ((m = socketEmitBodyRe.exec(src)) !== null) { const event=m[1]; const payload=m[2]||''; if (/password|token|secret|auth|key|credential/i.test(payload)) findings.push({ id:'ws-sensitive-emit', category:'Socket.io Security', severity:'high', value:`socket.emit("${event}", ${payload.slice(0,60)})`, context:ctx(m.index), description:`Potentially sensitive data emitted over socket event "${event}"` }); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12e — CRYPTOGRAPHIC CONTEXT ANALYZER (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanCryptoContext(src) {
  const findings = []; const ctx = (i,r=200) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const privKeyRe = /(?:privateKey|private_key|privKey|secretKey)\s*[=:]/gi;
  while ((m = privKeyRe.exec(src)) !== null) findings.push({ id:'crypto-privkey', category:'Cryptographic Risk', severity:'critical', value:m[0].slice(0,80), context:ctx(m.index), description:'Private/secret key handled in client-side code' });
  const ivRe = /(?:iv|nonce|salt)\s*[:=]\s*["'][0-9a-fA-F]{16,}["']/gi;
  while ((m = ivRe.exec(src)) !== null) findings.push({ id:'crypto-static-iv', category:'Cryptographic Risk', severity:'high', value:m[0].slice(0,80), context:ctx(m.index), description:'Static/hardcoded IV or nonce' });
  const ecbRe = /(?:AES-ECB|mode:\s*CryptoJS\.mode\.ECB)/gi;
  while ((m = ecbRe.exec(src)) !== null) findings.push({ id:'crypto-ecb', category:'Cryptographic Risk', severity:'critical', value:m[0].slice(0,80), context:ctx(m.index), description:'ECB mode leaks plaintext patterns' });
  const detSeedRe = /(?:seed|key|secret)\s*[:=]\s*(?:username|email|userId|Date\.now)/gi;
  while ((m = detSeedRe.exec(src)) !== null) findings.push({ id:'crypto-det-seed', category:'Cryptographic Risk', severity:'high', value:m[0].slice(0,80), context:ctx(m.index), description:'Cryptographic seed derived from predictable user data' });
  const subtleRe = /crypto\.subtle\.(?:encrypt|decrypt|sign|verify|importKey)\s*\(/g;
  while ((m = subtleRe.exec(src)) !== null) { const ahead=src.slice(m.index,m.index+300); if (!/.catch\s*\(|try\s*\{/.test(ahead)) findings.push({ id:'crypto-subtle-noerr', category:'Cryptographic Risk', severity:'medium', value:m[0].slice(0,80), context:ctx(m.index), description:'crypto.subtle operation with no .catch()' }); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12f — INFORMATION LEAKAGE DETECTOR (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanInfoLeakage(src) {
  const findings = []; const ctx = (i,r=200) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const stackRe = /(?:error|err|e)\.stack\b/g;
  while ((m = stackRe.exec(src)) !== null) { const c=ctx(m.index); if (/innerHTML|textContent|innerText|response|send|json/i.test(c)) findings.push({ id:'leak-stack', category:'Info Leakage', severity:'high', value:m[0], context:c, description:'Stack trace exposed to user' }); }
  const enumRe = /["'`]\/(?:api|rest|v\d+)\/[^"'`]*\${[^}]*(?:id|Id|ID|num|index)}/g;
  while ((m = enumRe.exec(src)) !== null) findings.push({ id:'leak-enum', category:'Info Leakage / IDOR', severity:'medium', value:m[0].slice(0,100), context:ctx(m.index), description:'Template URL with sequential ID parameter' });
  const debugRe = /console\.(log|debug|dir|table)\s*\(/g;
  const debugFindings = [];
  while ((m = debugRe.exec(src)) !== null) { const c=ctx(m.index); if (/token|password|secret|key|auth|session|user|email/i.test(c)) debugFindings.push({ id:'leak-debug', category:'Info Leakage', severity:'medium', value:m[0].slice(0,80), context:c, description:'Sensitive data logged to console' }); }
  const seenDebug = new Set();
  for (const f of debugFindings) { if (!seenDebug.has(f.context.slice(0,60))) { seenDebug.add(f.context.slice(0,60)); findings.push(f); } }
  const pathRe = /["'][^"']*\/(?:src|app|lib|server|backend|node_modules)\/[^"']{5,}["']/g;
  while ((m = pathRe.exec(src)) !== null) findings.push({ id:'leak-path', category:'Info Leakage', severity:'low', value:m[0].slice(0,100), context:ctx(m.index), description:'Internal filesystem path exposed in client bundle' });
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12g — IDOR DETECTOR (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanIDOR(src) {
  const findings = []; const ctx = (i,r=250) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const idUrlRe = /["'`][^"'`]*\/\$\{(?:[^}]*\.)?(?:userId|user_id|id|uid|accountId|customerId)[^}]*\}[^"'`]*["'`]/g;
  while ((m = idUrlRe.exec(src)) !== null) { const surrounding=ctx(m.index); const hasOwnerCheck=/userId\s*===\s*|currentUser|isOwner|checkOwner|verifyOwner/i.test(surrounding); findings.push({ id:'idor-url-id', category:'IDOR', severity:hasOwnerCheck?'low':'high', value:m[0].slice(0,120), context:surrounding, description:hasOwnerCheck?'User ID in URL — ownership check detected':'User ID in URL — no ownership verification' }); }
  const qpIdRe = /[?&](?:id|user_id|userId|account_id|order_id)=\$\{/g;
  while ((m = qpIdRe.exec(src)) !== null) findings.push({ id:'idor-qp', category:'IDOR', severity:'medium', value:m[0].slice(0,80), context:ctx(m.index), description:'Resource ID passed as query parameter' });
  const lsIdRe = /localStorage\.getItem\s*\(\s*["'](?:userId|user_id|uid)["']\s*\)/g;
  while ((m = lsIdRe.exec(src)) !== null) { const ahead=src.slice(m.index,m.index+400); if (/fetch|http\.|axios\.|get\s*\(|post\s*\(/.test(ahead)) findings.push({ id:'idor-ls-id', category:'IDOR', severity:'high', value:m[0].slice(0,80), context:ctx(m.index), description:'User ID from localStorage used in API call — client-controlled ID' }); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12h — DEPENDENCY VULNERABILITY CORRELATOR (v4)
// ═══════════════════════════════════════════════════════════════════════════
const KNOWN_VULN_DEPS = [
  { pkg:'lodash', verRe:/["']lodash["'].*?["']([0-9.]+)["']|lodash@([0-9.]+)/, vuln:'<4.17.21', cve:'CVE-2021-23337', sev:'high', desc:'Command injection via template' },
  { pkg:'axios', verRe:/["']axios["'].*?["']([0-9.]+)["']|axios@([0-9.]+)/, vuln:'<0.21.1', cve:'CVE-2020-28168', sev:'medium', desc:'SSRF in redirects' },
  { pkg:'jquery', verRe:/jquery@([0-9.]+)|["']jquery["'].*?["']([0-9.]+)["']/i, vuln:'<3.5.0', cve:'CVE-2020-11022', sev:'high', desc:'XSS via html()' },
  { pkg:'angular/core', verRe:/@angular\/core@([0-9.]+)/, vuln:'<12.0.0', cve:'CVE-2021-4231', sev:'high', desc:'XSS via bypassSecurityTrust*' },
  { pkg:'socket.io', verRe:/socket\.io@([0-9.]+)/, vuln:'<4.0.0', cve:'CVE-2020-28467', sev:'high', desc:'ReDoS in parser' },
  { pkg:'moment', verRe:/moment@([0-9.]+)/, vuln:'<2.29.2', cve:'CVE-2022-24785', sev:'medium', desc:'Path traversal in locale loading' },
  { pkg:'d3', verRe:/["']d3["'].*?["']([0-9.]+)["']|d3@([0-9.]+)/, vuln:'<7.0.0', cve:'CVE-2019-1000016', sev:'medium', desc:'XSS via selection.html()' },
  { pkg:'marked', verRe:/marked@([0-9.]+)/, vuln:'<4.0.10', cve:'CVE-2022-21681', sev:'high', desc:'ReDoS in markdown parser' },
  { pkg:'node-fetch', verRe:/node-fetch@([0-9.]+)/, vuln:'<2.6.7', cve:'CVE-2022-0235', sev:'high', desc:'Exposure via redirect' },
  { pkg:'minimatch', verRe:/minimatch@([0-9.]+)/, vuln:'<3.0.5', cve:'CVE-2022-3517', sev:'high', desc:'ReDoS' },
];
function scanDependencies(src) {
  const findings = []; const pkgRefRe = /["']([a-z@][a-z0-9_\-./]*)["']\s*[:=,]\s*["']([0-9^~><= .]{1,20})["']/gi;
  const pkgVersions = {}; let m;
  while ((m = pkgRefRe.exec(src)) !== null) pkgVersions[m[1].toLowerCase()] = m[2].replace(/[\^~>=< ]/g,'');
  for (const dep of KNOWN_VULN_DEPS) {
    const vm = dep.verRe.exec(src); const ver = vm ? (vm[1]||vm[2]) : (pkgVersions[dep.pkg]||null);
    if (!ver) continue;
    const parts = ver.split('.').map(Number); const vulnParts = dep.vuln.replace(/[<>=]/g,'').split('.').map(Number);
    const isVuln = parts[0] < vulnParts[0] || (parts[0]===vulnParts[0]&&(parts[1]||0)<(vulnParts[1]||0)) || (parts[0]===vulnParts[0]&&(parts[1]||0)===(vulnParts[1]||0)&&(parts[2]||0)<(vulnParts[2]||0));
    if (isVuln) findings.push({ id:`dep-${dep.pkg}`, category:'Vulnerable Dependency', severity:dep.sev, value:`${dep.pkg}@${ver}`, context:`Detected: ${ver} — vulnerable ${dep.vuln}`, description:`${dep.cve}: ${dep.desc}` });
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12i — RACE CONDITION DETECTOR (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanRaceConditions(src) {
  const findings = []; const ctx = (i,r=250) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const asyncStorageRe = /(?:async\s+function|async\s*\([^)]*\)\s*=>|async\s+\w+\s*\()[^}]{0,500}localStorage\.(getItem|setItem)/gs;
  while ((m = asyncStorageRe.exec(src)) !== null) { const block=m[0]; if (/localStorage\.getItem/.test(block)&&/localStorage\.setItem/.test(block)) findings.push({ id:'race-ls-rw', category:'Race Condition', severity:'medium', value:'async read-modify-write on localStorage', context:ctx(m.index), description:'localStorage read then write in async function' }); }
  const promiseStorageRe = /localStorage\.getItem[^;]{0,200}\.then\s*\([^)]{0,200}localStorage\.setItem/gs;
  while ((m = promiseStorageRe.exec(src)) !== null) findings.push({ id:'race-promise-ls', category:'Race Condition', severity:'medium', value:'localStorage read→Promise→write', context:ctx(m.index), description:'Storage write inside Promise .then() following a read' });
  const counterRe = /(\w+)\s*=\s*(?:parseInt\s*\()?\s*localStorage\.getItem[^;]{0,100};\s*(?:[^;]{0,100};\s*){0,3}\1\s*(?:\+\+|\+=\s*1|\+\s*1)/gs;
  while ((m = counterRe.exec(src)) !== null) findings.push({ id:'race-counter', category:'Race Condition', severity:'high', value:`Non-atomic counter: ${m[1]}`, context:ctx(m.index), description:'Non-atomic counter pattern' });
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12j — TAINT-FLOW ANALYZER (AST-based via taint-ast.js)
// ═══════════════════════════════════════════════════════════════════════════
function scanTaintFlow(src) {
  const findings = [];
  try {
    const result = taintAST.analyseTaintFlows(src);
    if (result && result.success && result.findings.length > 0) {
      const ctx = (i,r=300) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
      for (const f of result.findings) {
        findings.push({
          id: 'taint-flow',
          category: 'Taint Flow',
          severity: f.severity,
          value: f.value,
          context: f.position ? ctx(f.position) : '',
          description: f.description,
          cwe: f.cwe || 'CWE-79',
          propagated: f.propagated,
          hopCount: f.hopCount,
        });
      }
    }
  } catch (e) {
    // fall through to regex-based scanner
  }

  // if AST found nothing, fall back to regex-based heuristic scanner
  if (findings.length === 0) {
    const ctx = (i,r=300) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
    const SOURCE_NAMES = [
      { re:/location\.(?:hash|search|href|pathname)/g, name:'URL parameter' },
      { re:/document\.(?:URL|referrer|cookie)/g, name:'Document property' },
      { re:/(?:event|e)\.data\b/g, name:'Event data (postMessage/WebSocket)' },
      { re:/localStorage\.getItem\s*\([^)]+\)/g, name:'localStorage' },
      { re:/sessionStorage\.getItem\s*\([^)]+\)/g, name:'sessionStorage' },
      { re:/window\.name\b/g, name:'window.name' },
      { re:/URLSearchParams[^;]{0,100}\.get\s*\(/g, name:'URLSearchParams' },
      { re:/activatedRoute\.(?:queryParams|params|snapshot\.params)\b/g, name:'Angular route params' },
      { re:/this\.route\.snapshot\.(?:paramMap|queryParamMap)\.get/g, name:'Angular route paramMap' },
      { re:/FormGroup\.value\b/g, name:'form control value' },
      { re:/\.value\s*(?:!==|===|==)\s*["']/g, name:'input value' },
      { re:/postMessage\s*\(/g, name:'postMessage' },
      { re:/new\s+MessageEvent/g, name:'MessageEvent' },
      { re:/responseText|response\.data\b/g, name:'HTTP response data' },
    ];
    const SINKS = [
      { re:/\.innerHTML\s*=/g, name:'innerHTML', sev:'critical', cwe:'CWE-79' },
      { re:/\.outerHTML\s*=/g, name:'outerHTML', sev:'critical', cwe:'CWE-79' },
      { re:/\.insertAdjacentHTML\s*\(/g, name:'insertAdjacentHTML', sev:'critical', cwe:'CWE-79' },
      { re:/document\.write\s*\(/g, name:'document.write', sev:'critical', cwe:'CWE-79' },
      { re:/\beval\s*\(/g, name:'eval()', sev:'critical', cwe:'CWE-95' },
      { re:/new\s+Function\s*\(/g, name:'Function()', sev:'critical', cwe:'CWE-95' },
      { re:/location\.(?:href|replace|assign)\s*=/g, name:'location navigation', sev:'high', cwe:'CWE-601' },
      { re:/\.setAttribute\s*\(\s*['"]on\w+['"]/g, name:'setAttribute(on*)', sev:'critical', cwe:'CWE-79' },
      { re:/\[innerHTML\]/g, name:'Angular [innerHTML]', sev:'critical', cwe:'CWE-79' },
      { re:/dangerouslySetInnerHTML/g, name:'React dangerouslySetInnerHTML', sev:'critical', cwe:'CWE-79' },
      { re:/v-html\s*=/g, name:'Vue v-html', sev:'critical', cwe:'CWE-79' },
      { re:/srcdoc\s*=/g, name:'iframe srcdoc', sev:'critical', cwe:'CWE-79' },
      { re:/(?:\.html\(|\.append\(|\.prepend\(|\.after\(|\.before\(|\.replaceWith\()/g, name:'jQuery DOM manip', sev:'high', cwe:'CWE-79' },
      { re:/\$\s*\([^)]*\)\s*\.html\s*\(/g, name:'jQuery .html()', sev:'critical', cwe:'CWE-79' },
      { re:/createContextualFragment/g, name:'Range.createContextualFragment', sev:'critical', cwe:'CWE-79' },
      { re:/DOMParser\(\)\.parseFromString/g, name:'DOMParser', sev:'medium', cwe:'CWE-79' },
    ];
    const seen = new Set();
    const taintedVars = new Set();
    for (const src_pat of SOURCE_NAMES) {
      const re = new RegExp(src_pat.re.source, 'g');
      let m;
      while ((m = re.exec(src)) !== null) {
        const before = src.slice(Math.max(0, m.index - 120), m.index);
        const varMatch = /(?:const|let|var|private|public|readonly)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[A-Za-z_$][A-Za-z0-9_$]*)?\s*=\s*$/.exec(before);
        if (varMatch) { taintedVars.add(varMatch[1]); continue; }
        const thisMatch = /this\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*$/.exec(before);
        if (thisMatch) { taintedVars.add(thisMatch[1]); taintedVars.add('this.'+thisMatch[1]); continue; }
        const paramMatch = /function\s*(?:<[^>]*>)?\s*\([^)]*\b([A-Za-z_$][A-Za-z0-9_$]*)\b[^)]*\)\s*\{[^}]{0,80}$/.exec(before+src[m.index]);
        if (paramMatch) { taintedVars.add(paramMatch[1]); }
      }
    }
    for (const sink of SINKS) {
      const re = new RegExp(sink.re.source, 'g');
      let m;
      while ((m = re.exec(src)) !== null) {
        const w = src.slice(Math.max(0, m.index - 200), m.index + 200);
        let taintSource = null;
        for (const v of taintedVars) { if (w.includes(v)) { taintSource=v; break; } }
        if (!taintSource) { for (const src_pat of SOURCE_NAMES) { if (new RegExp(src_pat.re.source).test(w)) { taintSource=src_pat.name; break; } } }
        if (!taintSource) {
          const paramInFn = /(?:function|=>)\s*\([^)]*\)/.exec(w);
          if (paramInFn && /\.(?:data|body|message|value|text|response|result|input|param|query)\b/.test(w)) taintSource = 'function parameter property';
        }
        if (taintSource) {
          const key = `${taintSource}→${sink.name}::${m.index}`;
          if (!seen.has(key)) { seen.add(key);
            findings.push({ id:'taint-flow', category:'Taint Flow', severity:sink.sev, value:`${sink.name} (src: ${taintSource})`, context:ctx(m.index), description:`Tainted "${taintSource}" → "${sink.name}" — ${sink.cwe}`, cwe:sink.cwe });
          }
        }
      }
    }
  }

  return findings.sort((a,b)=>(({critical:0,high:1,medium:2,low:3}[a.severity])||3)-(({critical:0,high:1,medium:2,low:3}[b.severity])||3));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12k — WEB3/BLOCKCHAIN SECURITY (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanWeb3(src) {
  const findings = []; const ctx = (i,r=200) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const pkRe = /(?:0x[0-9a-fA-F]{64}|privateKey\s*[:=]\s*["'][^"']{20,}["'])/g;
  while ((m = pkRe.exec(src)) !== null) findings.push({ id:'web3-privkey', category:'Web3 Security', severity:'critical', value:m[0].slice(0,80), context:ctx(m.index), description:'Ethereum private key or 32-byte hex secret in client bundle' });
  const sendTxRe = /eth_sendTransaction|\.sendTransaction\s*\(/g;
  while ((m = sendTxRe.exec(src)) !== null) findings.push({ id:'web3-sendtx', category:'Web3 Security', severity:'high', value:m[0].slice(0,80), context:ctx(m.index), description:'sendTransaction call — verify user confirmation UI exists' });
  const reentrancyRe = /\.call\s*\([^)]*\)\s*\.\s*then\s*\([^)]*\s*=>\s*\{[^}]{0,200}balance/g;
  while ((m = reentrancyRe.exec(src)) !== null) findings.push({ id:'web3-reentrancy', category:'Web3 Security', severity:'high', value:m[0].slice(0,100), context:ctx(m.index), description:'Potential reentrancy pattern' });
  const addrRe = /["']0x[0-9a-fA-F]{40}["']/g; const addrSeen = new Set();
  while ((m = addrRe.exec(src)) !== null) { if (!addrSeen.has(m[0])) { addrSeen.add(m[0]); findings.push({ id:'web3-address', category:'Web3 Security', severity:'info', value:m[0], context:ctx(m.index), description:'Hardcoded Ethereum address' }); } }
  const sigRe = /(?:ethers|web3)\.utils\.(?:solidityKeccak256|keccak256)\s*\(/g;
  while ((m = sigRe.exec(src)) !== null) { const c=ctx(m.index); if (!/nonce|chainId|deadline/i.test(c)) findings.push({ id:'web3-sig-replay', category:'Web3 Security', severity:'high', value:m[0].slice(0,80), context:c, description:'Hash/signature without nonce/chainId — potential replay' }); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12l — CONFIG-DRIVEN BEHAVIOUR ANALYZER (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanConfigDrivenBehaviour(src) {
  const findings = []; const ctx = (i,r=200) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const envProdRe = /environment\.production\s*(?:===|==|!==|!=)\s*(?:false|true)/g;
  while ((m = envProdRe.exec(src)) !== null) { const c=ctx(m.index); if (/debug|log|verbose|trace/i.test(c)) findings.push({ id:'cfg-debug-env', category:'Config Behaviour', severity:'low', value:m[0], context:c, description:'Debug/logging gated on environment.production' }); }
  const secDisableRe = /(?:disableAuth|skipAuth|noAuth|bypassAuth|ignoreSSL|rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false)/gi;
  while ((m = secDisableRe.exec(src)) !== null) findings.push({ id:'cfg-sec-disable', category:'Config Behaviour', severity:'high', value:m[0].slice(0,80), context:ctx(m.index), description:'Security feature disabled via config flag' });
  const apiUrlRe = /(?:apiUrl|baseUrl|API_URL|BASE_URL)\s*[:=]\s*["'](https?:\/\/[^"']+)["']/gi;
  while ((m = apiUrlRe.exec(src)) !== null) findings.push({ id:'cfg-hardcoded-url', category:'Config Behaviour', severity:'info', value:m[0].slice(0,100), context:ctx(m.index), description:'Hardcoded API base URL in client bundle' });
  const corsRe = /(?:allowedOrigins|cors)\s*[:=]\s*["'][*]["']/gi;
  while ((m = corsRe.exec(src)) !== null) findings.push({ id:'cfg-cors-wildcard', category:'Config Behaviour', severity:'high', value:m[0].slice(0,80), context:ctx(m.index), description:'CORS wildcard origin configured' });
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12m — LAZY-LOADING ROUTE SECURITY (v4)
// ═══════════════════════════════════════════════════════════════════════════
function scanLazyLoading(src) {
  const findings = []; const ctx = (i,r=250) => src.slice(Math.max(0,i-r/2),i+r/2).replace(/\n/g,' ');
  let m;
  const lazyRe = /path\s*:\s*["']([^"']{1,80})["'][^{};]{0,400}?loadChildren\s*:/g;
  while ((m = lazyRe.exec(src)) !== null) { const routePath=m[1]; const window=src.slice(m.index,m.index+400); const hasGuard=/canActivate\s*:\s*\[/.test(window); if (!hasGuard&&/admin|account|payment|order|wallet|secret|internal/i.test(routePath)) findings.push({ id:'lazy-unguarded', category:'Lazy Loading Security', severity:'high', value:'/'+routePath, context:ctx(m.index), description:`Lazy-loaded route "/${routePath}" has no canActivate guard` }); const chunkNameM=/\/\*\s*webpackChunkName\s*:\s*["']([^"']+)["']\s*\*\//.exec(window); if (chunkNameM) findings.push({ id:'lazy-chunk-name', category:'Lazy Loading Security', severity:'info', value:chunkNameM[1], context:ctx(m.index), description:`Lazy chunk "${chunkNameM[1]}" has predictable filename` }); }
  const dynImportRe = /import\s*\(\s*(?!['"`])[A-Za-z_$][A-Za-z0-9_$.]*\s*\)/g;
  while ((m = dynImportRe.exec(src)) !== null) { const c=ctx(m.index); if (/user|input|param|query|data|route/i.test(c)) findings.push({ id:'lazy-dyn-import', category:'Lazy Loading Security', severity:'high', value:m[0].slice(0,80), context:c, description:'Dynamic import() with potentially user-controlled path' }); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12n — ATTACK SURFACE SCORE
// ═══════════════════════════════════════════════════════════════════════════
function scoreAttackSurface(allFindings, authSurface, routes) {
  const weights = { critical:10, high:5, medium:2, low:1, info:0 };
  let score = 0; const breakdown = {};
  for (const f of allFindings) { const sev=f.severity||f.sev||'info'; const cat=f.category||f.name||'Unknown'; const w=weights[sev]||0; score+=w; breakdown[cat]=(breakdown[cat]||0)+w; }
  if (authSurface) {
    score += (authSurface.unguardedRoutes||[]).length * 8;
    if ((authSurface.unguardedRoutes||[]).length) breakdown['Unguarded Routes'] = authSurface.unguardedRoutes.length * 8;
    score += (authSurface.unprotectedEndpoints||[]).length * 6;
    if ((authSurface.unprotectedEndpoints||[]).length) breakdown['Unprotected Endpoints'] = authSurface.unprotectedEndpoints.length * 6;
  }
  if (routes) {
    const hiddenRoutes = routes.filter(r=>r.type&&r.type.startsWith('Hidden'));
    score += hiddenRoutes.length * 4;
    if (hiddenRoutes.length) breakdown['Hidden Routes'] = hiddenRoutes.length * 4;
  }
  const risk = score>=80?'CRITICAL':score>=40?'HIGH':score>=15?'MEDIUM':'LOW';
  const topCategories = Object.entries(breakdown).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([cat,pts])=>`${cat} (${pts}pts)`);
  return { score, risk, breakdown, topCategories };
}

function splitWebpackModules(src) {
  const modules = [];
  const chunkRe = /\[\[(\d+)\]\s*,\s*\{/g;
  let m; const boundaries = [];
  while ((m = chunkRe.exec(src)) !== null) boundaries.push({ id:m[1], pos:m.index });
  if (!boundaries.length) {
    const modRe = /^(\d+):\s*\((?:Q|module),\s*(?:H|exports),\s*(?:d|require)\)/mg;
    while ((m = modRe.exec(src)) !== null) boundaries.push({ id:m[1], pos:m.index });
  }
  for (let i = 0; i < boundaries.length; i++) {
    const start = boundaries[i].pos;
    const end = boundaries[i+1] ? boundaries[i+1].pos : src.length;
    modules.push({ id:boundaries[i].id, src:src.slice(start,end) });
  }
  if (!modules.length) modules.push({ id:'main', src });
  return modules;
}

function buildDependencyGraph(src) {
  const graph = {};
  const callRe = /d\((\d+)\)/g;
  let m;
  while ((m = callRe.exec(src)) !== null) {
    const id = m[1];
    const name = WEBPACK_MODULE_MAP[id] || `module-${id}`;
    if (!graph[id]) graph[id] = { id, name, uses:0 };
    graph[id].uses++;
  }
  return Object.values(graph).sort((a,b)=>b.uses-a.uses);
}

// ═══════════════════════════════════════════════════════════════════════════
//  REPORT GENERATORS (v4+v5 merged)
// ═══════════════════════════════════════════════════════════════════════════

function generateJSONReport(findings, metadata) {
  return JSON.stringify({ metadata, findings, total:findings.length, generatedAt:new Date().toISOString() }, null, 2);
}

function generateHTMLReport(findings, metadata) {
  const grouped = {};
  for (const f of findings) {
    const g = f.category || f.type || 'Unknown';
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(f);
  }
  const categories = Object.keys(grouped).sort();
  let body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Omega Scan Report</title><style>
    *{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#f5f5f5;color:#333;padding:20px}
    h1{font-size:24px;margin-bottom:5px}h2{font-size:18px;margin:20px 0 10px;padding-bottom:5px;border-bottom:2px solid #ddd}
    .meta{background:#fff;padding:15px;border-radius:6px;margin-bottom:20px;font-size:14px;line-height:1.6;box-shadow:0 1px 3px rgba(0,0,0,.08)}
    .summary{background:#fff;padding:15px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
    .summary table{width:100%;border-collapse:collapse} .summary td,.summary th{padding:8px 12px;text-align:center}
    .sev-critical{color:#b71c1c;font-weight:700}.sev-high{color:#e65100;font-weight:700}.sev-medium{color:#f57f17}.sev-low{color:#33691e}.sev-info{color:#555}
    .finding{background:#fff;padding:12px 15px;margin:6px 0;border-radius:6px;border-left:4px solid #999;font-size:13px;line-height:1.5;box-shadow:0 1px 2px rgba(0,0,0,.06)}
    .finding.critical{border-left-color:#b71c1c}.finding.high{border-left-color:#e65100}.finding.medium{border-left-color:#f57f17}.finding.low{border-left-color:#33691e}
    .finding .val{font-family:'Consolas','Courier New',monospace;background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;word-break:break-all}
    .finding .ctx{display:block;font-family:'Consolas','Courier New',monospace;background:#fafafa;padding:4px 6px;margin-top:4px;border-radius:3px;font-size:11px;color:#555;max-height:60px;overflow:hidden}
    .finding .desc{margin-top:4px;font-size:12px;color:#555}
    .count-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-left:6px}
    .count-badge.critical{background:#ffcdd2;color:#b71c1c}.count-badge.high{background:#ffe0b2;color:#e65100}.count-badge.medium{background:#fff9c4;color:#f57f17}.count-badge.low{background:#dcedc8;color:#33691e}
    @media(max-width:600px){body{padding:10px}}
  </style></head><body>`;
  body += `<h1>🔍 Omega JS Scanner Report</h1><div class="meta">`;
  body += `<b>File:</b> ${metadata.filename||'N/A'}<br>`;
  body += `<b>Size:</b> ${metadata.size||'N/A'} bytes<br>`;
  body += `<b>Attack Surface:</b> ${metadata.attackSurface?.score||'N/A'} [${metadata.attackSurface?.risk||'N/A'}]<br>`;
  body += `<b>Total Findings:</b> ${findings.length}<br>`;
  body += `<b>Generated:</b> ${new Date().toISOString()}</div>`;
  const counts = {critical:0,high:0,medium:0,low:0,info:0};
  for (const f of findings) { const s=f.severity||f.sev||'info'; counts[s]=(counts[s]||0)+1; }
  body += `<div class="summary"><table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>`;
  body += `<tr><td class="sev-critical">${counts.critical}</td><td class="sev-high">${counts.high}</td><td class="sev-medium">${counts.medium}</td><td class="sev-low">${counts.low}</td><td>${counts.info}</td></tr></table></div>`;
  for (const cat of categories) {
    const items = grouped[cat];
    let catCounts={critical:0,high:0,medium:0,low:0,info:0};
    for (const f of items) { const s=f.severity||f.sev||'info'; catCounts[s]++; }
    const badges=Object.entries(catCounts).filter(([k,v])=>v>0).map(([k,v])=>`<span class="count-badge ${k}">${k} ${v}</span>`).join(' ');
    body += `<h2>${cat} (${items.length}) ${badges}</h2>`;
    for (const f of items) {
      const sev=f.severity||f.sev||'info';
      body += `<div class="finding ${sev}">`;
      body += `<b>${f.id||f.type||'Finding'}</b> <span class="sev-${sev}">${sev.toUpperCase()}</span><br>`;
      if (f.value) body += `<span class="val">${escHtml(f.value)}</span><br>`;
      if (f.description) body += `<div class="desc">${escHtml(f.description)}</div>`;
      if (f.context) body += `<span class="ctx">${escHtml(f.context)}</span>`;
      body += `</div>\n`;
    }
  }
  body += `</body></html>`;
  return body;
}

function escHtml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function generateMarkdownReport(findings, metadata) {
  let md = `# Omega JS Scanner Report\n\n`;
  md += `**File:** ${metadata.filename||'N/A'}  \n**Size:** ${metadata.size||'N/A'} bytes  \n**Attack Surface:** ${metadata.attackSurface?.score||'N/A'} [${metadata.attackSurface?.risk||'N/A'}]  \n**Total:** ${findings.length}  \n**Generated:** ${new Date().toISOString()}\n\n`;
  const counts = {critical:0,high:0,medium:0,low:0,info:0};
  for (const f of findings) { const s=f.severity||f.sev||'info'; counts[s]=(counts[s]||0)+1; }
  md += `| Critical | High | Medium | Low | Info |\n|---------|------|--------|-----|------|\n| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |\n\n`;
  md += `## Top Attack Surface Categories\n${(metadata.attackSurface?.topCategories||['N/A']).map(c=>`- ${c}`).join('\n')}\n\n`;
  for (const f of findings) {
    const sev = f.severity||f.sev||'info';
    md += `### ${f.id||f.type||'Finding'} [${sev.toUpperCase()}]\n`;
    if (f.category||f.type) md += `**Category:** ${f.category||f.type}  \n`;
    if (f.value) md += `**Value:** \`${f.value}\`  \n`;
    if (f.description) md += `**Description:** ${f.description}  \n`;
    if (f.context) md += `<details><summary>Context</summary>\n\`\`\`\n${f.context}\n\`\`\`\n</details>\n`;
    md += `\n`;
  }
  return md;
}

function generateSARIFReport(findings, metadata) {
  const sarif = {
    version:'2.1.0', $schema:'https://json.schemastore.org/sarif-2.1.0.json',
    runs:[{
      tool:{ driver:{ name:'omega-unified', version:'4.0+v5.0', informationUri:'https://github.com/omega-scanner' } },
      artifacts:[{ location:{ uri:metadata.filename||'input.js' }, sourceLanguage:'javascript' }],
      results:[],
      invocations:[{ startTimeUtc:metadata.startTime, endTimeUtc:new Date().toISOString(), executionSuccessful:true }]
    }]
  };
  for (const f of findings) {
    const sev = f.severity||f.sev||'info';
    const levelMap = { critical:'error', high:'error', medium:'warning', low:'note', info:'note' };
    const ruleId = f.id||f.type||'omega-finding';
    sarif.runs[0].results.push({
      ruleId,
      level: levelMap[sev]||'note',
      message:{ text: (f.description||'')+ (f.value?` — ${f.value}`:'') },
      locations:[{
        physicalLocation:{
          artifactLocation:{ uri:metadata.filename||'input.js' },
          region:{ snippet:{ text: (f.context||'').slice(0,200) } }
        }
      }]
    });
  }
  return JSON.stringify(sarif, null, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
//  TEXT REPORT FORMATTER (default CLI output)
// ═══════════════════════════════════════════════════════════════════════════
function formatTextReport(findings, metadata, clr) {
  const c = clr || C;
  let out = '';
  out += `${c.bold('Ω Omega Scanner Report')}\n`;
  out += `${c.dim('═'.repeat(50))}\n`;
  out += `File: ${c.cyan(metadata.filename||'N/A')}\n`;
  out += `Size: ${metadata.size||0} bytes\n`;
  out += `Runtime: ${(metadata.totalMs||0).toFixed(0)}ms\n`;
  out += `Attack Surface: ${c.bold(String(metadata.attackSurface?.score||'?'))} [${c.bold(metadata.attackSurface?.risk||'?')}]\n`;
  out += `\n`;
  const counts = {critical:0,high:0,medium:0,low:0,info:0};
  for (const f of findings) { const s=f.severity||f.sev||'info'; counts[s]=(counts[s]||0)+1; }
  out += `${c.bold('Summary:')}  ${c.red(`Critical:${counts.critical}`)}  ${c.yellow(`High:${counts.high}`)}  ${c.magenta(`Medium:${counts.medium}`)}  ${c.green(`Low:${counts.low}`)}  Info:${counts.info}  ${c.dim(`Total:${findings.length}`)}\n`;
  if (metadata.suppressedCount) out += `${c.yellow(`Suppressed: ${metadata.suppressedCount} finding(s)`)}\n`;
  out += `\n`;
  if (metadata.attackSurface?.topCategories?.length) {
    out += `${c.bold('Top Attack Categories:')}\n`;
    for (const cat of metadata.attackSurface.topCategories.slice(0,5)) out += `  ${c.dim('•')} ${cat}\n`;
    out += `\n`;
  }
  for (const f of findings) {
    const sev = f.severity||f.sev||'info';
    const colorFn = ({critical:c.red,high:c.yellow,medium:c.magenta,low:c.green,info:c.dim})[sev]||c.dim;
    const label = sev.toUpperCase().padEnd(8);
    out += `${colorFn(label)} ${c.bold(f.id||f.type||'Finding')}`;
    if (f.category||f.type) out += ` ${c.dim(`[${f.category||f.type}]`)}`;
    out += `\n`;
    if (f.value) out += `       ${c.dim('Value:')} ${c.cyan(String(f.value).slice(0,200))}\n`;
    if (f.description) out += `       ${c.dim('Desc:')}  ${f.description}\n`;
    if (f.context && findings.length <= 50) {
      const ctx = String(f.context).replace(/\n/g,' ').slice(0,200);
      out += `       ${c.dim('Ctx:')}  ${c.dim(ctx)}\n`;
    }
    out += `\n`;
  }
  out += `${c.dim('═'.repeat(50))}\n`;
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN PIPELINE ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
//  DECODE PIPELINE (wraps P0-P7)
// ═══════════════════════════════════════════════════════════════════════════
function decodePipeline(src) {
  let code = resolveModuleAliases(src, {}).src;
  code = decodeEscapes(code).src;
  code = decodeStrings(code).src;
  code = decodeCharCodeObfuscation(code).src;
  // v5 generic obfuscation decoder — handles arrow functions, XOR, arithmetic folding, var lookups
  try { const r = obfuscation.decodeObfuscation(code, {}); if (r && r.src) code = r.src; } catch(e) {}
  code = normaliseBooleans(code);
  code = cleanupWebpack(code);
  code = annotateAngularIvy(code);
  code = annotateFrameworkSymbols(code, {}).src;
  code = annotateRxJS(code);
  code = beautify(code);
  return code;
}

function scanCodePatterns(src) { return analyseCode(src); }
function scanStorageKeys(src) { return auditStorageKeys(src); }
function detectFramework(src) { return detectFrameworks(src); }

// ═══════════════════════════════════════════════════════════════════════════
//  URL FETCHER (--url mode)
// ═══════════════════════════════════════════════════════════════════════════

function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? require('https') : require('http');
    mod.get(url, { timeout: 30000, headers: { 'User-Agent': 'Omega-Unified/5.0' } }, (res) => {
      if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      if (res.statusCode >= 300 && res.headers.location) return fetchURL(res.headers.location);
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    }).on('error', reject).on('timeout', function() { this.destroy(); reject(new Error('Timeout')); });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  DIRECTORY SCANNER (--dir mode)
// ═══════════════════════════════════════════════════════════════════════════

function scanDirectory(dirPath, options) {
  const entries = fs.readdirSync(dirPath).filter(f => f.endsWith('.js')).sort();
  if (!entries.length) throw new Error(`No .js files found in ${dirPath}`);
  const allFindings = []; const phaseTimes = []; let totalMs = 0; let suppressedCount = 0;
  for (const file of entries) {
    const fp = path.join(dirPath, file);
    const src = fs.readFileSync(fp, 'utf8');
    const opts = { ...options, filename: file, quiet: true };
    const result = runPipeline(src, opts);
    for (const f of result.findings) {
      if (f && typeof f === 'object') { f.file = file; allFindings.push(f); }
    }
    phaseTimes.push(...result.metadata.phaseTimes.map(p => ({ ...p, file })));
    totalMs += result.metadata.totalMs;
    suppressedCount += result.suppressedCount || 0;
  }
  const attackSurface = scoreAttackSurface(allFindings, null, null);
  return {
    findings: allFindings, phaseTimes, totalMs, suppressedCount,
    metadata: { filename: dirPath, size: 0, attackSurface, framework: null, totalMs, suppressedCount, filesScanned: entries.length },
    batch: { files: entries.length, filesScanned: entries.length },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  SERVICE WORKER SCANNER (Phase 12o)
// ═══════════════════════════════════════════════════════════════════════════

function scanServiceWorker(src) {
  const findings = [];
  if (!/serviceWorker|self\.addEventListener|caches\.open|skipWaiting|clients\.claim/.test(src)) return findings;

  const swReg = src.match(/navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*["']([^"']+)["']/g);
  if (swReg) {
    for (const m of swReg) {
      const url = m.match(/["']([^"']+)["']/)[1];
      if (!url.startsWith('/') && !url.startsWith('./') && !url.startsWith(self?.location?.origin)) {
        findings.push({ type:'sw-register-relative', severity:'MEDIUM', value:`SW register: ${url}`, ctx:m.substring(0,120), desc:'Service worker with relative URL — scope hijacking risk' });
      }
    }
  }

  if (/addEventListener\s*\(\s*["']fetch["']/.test(src)) {
    const ms = src.match(/addEventListener\s*\(\s*["']fetch["'][^)]*\)/g);
    if (ms) for (const m of ms) {
      findings.push({ type:'sw-fetch-intercept', severity:'MEDIUM', value:'SW fetch listener', ctx:m.substring(0,120), desc:'SW intercepts all fetch requests — can modify responses, inject content, exfiltrate data' });
    }
  }

  if (/addEventListener\s*\(\s*["']message["']/.test(src)) {
    const ms = src.match(/addEventListener\s*\(\s*["']message["'][^)]*\)/g);
    if (ms) for (const m of ms) {
      const hasOriginCheck = /(origin|source)\s*===?\s*/.test(m);
      findings.push({ type: hasOriginCheck ? 'sw-message' : 'sw-message-no-origin', severity: hasOriginCheck ? 'INFO' : 'HIGH',
        value: hasOriginCheck ? 'SW message (origin-checked)' : 'SW message (NO origin check)',
        ctx: m.substring(0,120),
        desc: hasOriginCheck ? 'SW postMessage communication' : 'SW message listener without origin validation' });
    }
  }

  const cacheOpen = src.match(/caches\s*\.\s*open\s*\(/g);
  if (cacheOpen) findings.push({ type:'sw-cache-api', severity:'INFO', value:`Cache API: ${cacheOpen.length} call(s)`, ctx:`caches.open() used ${cacheOpen.length} times`, desc:'SW uses Cache API — verify cache keys are not attacker-controllable' });

  if (/skipWaiting\s*\(/.test(src)) findings.push({ type:'sw-skip-waiting', severity:'INFO', value:'skipWaiting()', desc:'SW calls skipWaiting() — immediate activation, version rollback risk' });
  if (/clients\s*\.\s*claim\s*\(/.test(src)) findings.push({ type:'sw-clients-claim', severity:'INFO', value:'clients.claim()', desc:'SW calls clients.claim() — takes control of all clients immediately' });

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  GITHUB ANNOTATIONS FORMATTER
// ═══════════════════════════════════════════════════════════════════════════

function formatGitHubAnnotations(findings, metadata) {
  const emap = { CRITICAL:'error', HIGH:'error', MEDIUM:'warning', LOW:'warning', INFO:'notice' };
  return findings.map(f => {
    const sev = emap[f.severity] || 'warning';
    const file = f.file || metadata.filename || 'input.js';
    const title = (f.type || 'finding').replace(/"/g, '\\"');
    const msg = (f.value || f.desc || 'no details').replace(/"/g, '\\"').replace(/\n/g, ' ');
    return `::${sev} file=${file},title=${title}::${msg}`;
  }).join('\n') + '\n';
}

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN PIPELINE ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════
function runPipeline(src, options = {}) {
  const startTime = new Date().toISOString();
  const phaseTimes = [];
  const phase = (name, fn) => { const s=Date.now(); const r=fn(); phaseTimes.push({name,ms:Date.now()-s}); return r; };
  const results = {};

  // Phase 0-7: Decoding pipeline + bracket normalization
  let decoded = phase('decode', () => decodePipeline(src));
  // Convert obj["prop"] to obj.prop so all dot-notation regexes match minified code
  decoded = decoded.replace(/\[\s*["'](\w+)["']\s*\]/g, '.$1');
  results.decoded = decoded;

  // Phase 8: Code analysis
  const codeAnalysis = phase('code-analysis', () => scanCodePatterns(decoded));
  results.codeAnalysis = codeAnalysis;

  // Phase 8b: Storage key audit
  const storageKeys = phase('storage-keys', () => scanStorageKeys(decoded));
  results.storageKeys = storageKeys;

  // Phase 8c: Auth surface mapper
  const authSurface = phase('auth-mapper', () => mapAuthSurface(decoded));
  results.authSurface = authSurface;

  // Phase 9: Framework detection
  const framework = phase('framework-detect', () => detectFramework(decoded));
  results.framework = framework;

  // Phase 10: Route extraction
  const routes = phase('route-extract', () => extractRoutes(decoded));
  results.routes = routes;

  // Phase 11: Credential scanning
  const credentials = phase('credentials', () => scanCredentials(decoded));
  results.credentials = credentials;

  // Phase 12: Security analysis
  const security = phase('security', () => analyseSecurity(decoded));
  results.security = security;

  // Phase 12b-n: Extended scanners
  if (!options.fast) {
    results.dynamicCode = phase('dyncode', () => scanDynamicCodeExecution(decoded));
    results.businessLogic = phase('business-logic', () => scanBusinessLogic(decoded));
    results.webSocket = phase('websocket', () => scanWebSocketContent(decoded));
    results.cryptoContext = phase('crypto-context', () => scanCryptoContext(decoded));
    results.infoLeakage = phase('info-leak', () => scanInfoLeakage(decoded));
    results.idor = phase('idor', () => scanIDOR(decoded));
    results.dependencies = phase('dependencies', () => scanDependencies(decoded));
    results.raceConditions = phase('race-conditions', () => scanRaceConditions(decoded));
    results.taintFlow = phase('taint-flow', () => scanTaintFlow(decoded));
    results.web3 = phase('web3', () => scanWeb3(decoded));
    results.configBehaviour = phase('config-behaviour', () => scanConfigDrivenBehaviour(decoded));
  results.lazyLoading = phase('lazy-loading', () => scanLazyLoading(decoded));
  }

  // Phase 12o: Service worker analysis
  if (!options.fast) {
    results.serviceWorker = phase('service-worker', () => scanServiceWorker(decoded));
  }

  // Aggregate all findings
  const allFindings = [];
  for (const key of Object.keys(results)) {
    const v = results[key];
    if (Array.isArray(v)) {
      for (const item of v) { if (item && typeof item === 'object') allFindings.push(item); }
    } else if (v && v.findings && Array.isArray(v.findings)) {
      for (const item of v.findings) { if (item && typeof item === 'object') allFindings.push(item); }
    }
  }

  // Attack surface scoring
  const attackSurface = scoreAttackSurface(allFindings, authSurface, routes);

  // Apply suppressions if config provided
  let suppressedCount = 0;
  let suppressionReasons = [];
  if (options.config && typeof options.config.parseSuppressionComments === 'function') {
    let findings = allFindings;
    const config = options.config;
    const suppressionMap = config.parseSuppressionComments(src);
    const applied = config.applySuppressions(findings, suppressionMap);
    suppressedCount = applied.suppressedCount;
    suppressionReasons = applied.suppressionReasons;
    allFindings.splice(0, allFindings.length, ...applied.findings);
  }

  const totalMs = phaseTimes.reduce((a,b)=>a+b.ms, 0);
  const metadata = {
    filename: options.filename || 'input.js',
    size: Buffer.byteLength(src, 'utf8'),
    attackSurface,
    framework: framework?.name || null,
    phaseTimes,
    totalMs,
    startTime,
    suppressedCount,
  };

  return { findings: allFindings, metadata, results, phaseTimes, suppressedCount, suppressionReasons };
}

// ═══════════════════════════════════════════════════════════════════════════
//  CLI MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════

function parseCLI(argv) {
  const opts = { _:[], format:'text', quiet:false, verbose:false, fast:false, dir:false, url:false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { opts.help = true; continue; }
    if (a === '--version') { opts.version = true; continue; }
    if (a === '-q' || a === '--quiet') { opts.quiet = true; continue; }
    if (a === '-v' || a === '--verbose') { opts.verbose = true; continue; }
    if (a === '--fast') { opts.fast = true; continue; }
    if (a === '--no-color') { opts['no-color'] = true; continue; }
    if (a === '--no-frames') { opts['no-frames'] = true; continue; }
    if (a === '--no-routes') { opts['no-routes'] = true; continue; }
    if (a === '--dir') { opts.dir = true; opts.dirPath = argv[++i] || null; continue; }
    if (a === '--url') { opts.url = true; continue; }
    if (a === '-f' || a === '--format') { opts.format = argv[++i] || 'text'; continue; }
    if (a === '-o' || a === '--output') { opts.output = argv[++i] || null; continue; }
    if (a === '--config') { opts.config = argv[++i] || null; continue; }
    if (!a.startsWith('-')) { opts._.push(a); continue; }
  }
  return opts;
}

if (require.main === module) {
  const args = parseCLI(process.argv.slice(2));
  if (args.help || args.h) {
    const pkg = require('./package.json');
    console.log(`Omega Unified Scanner v${pkg.version||'4.0+v5.0'}

Usage: node omega-unified.js [options] <file.js | --dir <path> | --url <url>]

Options:
  -f, --format <type>    Report format: text|json|html|md|sarif|github-annotation (default: text)
  -o, --output <file>    Write output to file (optional)
  -q, --quiet            Suppress progress output
  -v, --verbose          Show detailed scan progress
  --fast                 Skip extended scanners (12b-n)
  --dir <path>           Scan all .js files in directory (batch mode)
  --url <url>            Download and scan a JS file from URL
  --no-color             Disable ANSI colors
  --no-frames            Disable framework detection
  --no-routes            Disable route extraction
  --config <file>        Load config file for suppression rules
  -h, --help             Show this help
  --version              Show version

Examples:
  node omega-unified.js bundle.js
  node omega-unified.js -f json -o report.json bundle.js
  node omega-unified.js --fast --verbose bundle.js
  node omega-unified.js --dir ./js-files/ -f html -o batch-report.html
  node omega-unified.js --url https://example.com/bundle.js -f github-annotation`);
    process.exit(0);
  }
  if (args.version) {
    try { const p=require('./package.json'); console.log(p.version); }
    catch(e) { console.log('4.0+v5.0'); }
    process.exit(0);
  }

  async function main() {
    let src, filename;

    if (args.dir && args.dirPath) {
      // ── Directory batch mode ──
      if (!args.quiet) console.log(`${C.cyan('Ω Omega Unified Scanner')} — batch scanning ${args.dirPath}`);
      let config = null;
      if (args.config) { try { config = require('./lib/config'); } catch(e) { console.error(`Warning: ${e.message}`); } }
      const startTime = Date.now();
      const result = scanDirectory(args.dirPath, { fast: !!args.fast, verbose: !!args.verbose, config });
      const elapsed = Date.now() - startTime;
      if (!args.quiet) {
        const {score,risk}=result.metadata.attackSurface;
        console.log(`Files: ${result.batch.files} | Findings: ${result.findings.length} | Attack Surface: ${score} [${risk}] ${C.dim(`in ${(elapsed/1000).toFixed(2)}s`)}`);
      }
      const format = args.format;
      let output;
      switch (format) {
        case 'json': output = JSON.stringify({ findings: result.findings, metadata: result.metadata, batch: result.batch }, null, 2); break;
        case 'github-annotation': output = formatGitHubAnnotations(result.findings, result.metadata); break;
        default: output = formatTextReport(result.findings, result.metadata, args['no-color'] ? null : C);
      }
      if (args.output) { fs.writeFileSync(args.output, output, 'utf8'); if (!args.quiet) console.log(`${C.green('Report written:')} ${args.output}`); }
      else process.stdout.write(output);
      return;
    }

    if (args.url) {
      // ── URL fetch mode ──
      const url = args._[0] || null;
      if (!url) { console.error('Error: --url requires a URL as argument. Use -h for help.'); process.exit(1); }
      if (!args.quiet) console.log(`${C.cyan('Ω Omega Unified Scanner')} — fetching ${C.dim(url)}`);
      try {
        src = await fetchURL(url);
        filename = url.split('/').pop() || 'remote.js';
      } catch(e) { console.error(`Error fetching ${url}: ${e.message}`); process.exit(1); }
    } else {
      // ── File mode ──
      if (!args._ || args._.length < 1) { console.error('Error: No input file specified. Use -h for help.'); process.exit(1); }
      const filepath = args._[0];
      try { src = fs.readFileSync(filepath, 'utf8'); filename = path.basename(filepath); } catch(e) { console.error(`Error reading ${filepath}: ${e.message}`); process.exit(1); }
    }

    if (!args.quiet) { const sizeK=(src.length/1024).toFixed(1); console.log(`${C.cyan('Ω Omega Unified Scanner')} — ${C.dim(`${src.length} bytes (${sizeK}KB)`)}`); }
    const startTime = Date.now();
    let config = null;
    if (args.config) { try { config = require('./lib/config'); } catch(e) { console.error(`Warning: Could not load config module: ${e.message}`); } }
    const pipelineOpts = { fast: !!args.fast, verbose: !!args.verbose, filename: filename || 'input.js', config };
    const result = runPipeline(src, pipelineOpts);
    const elapsed = Date.now() - startTime;
    if (!args.quiet) {
      const {score,risk}=result.metadata.attackSurface;
      const riskColor = risk==='CRITICAL'?C.red:risk==='HIGH'?C.yellow:risk==='MEDIUM'?C.magenta:C.green;
      console.log(`${C.bold('Findings:')} ${result.findings.length} | ${C.bold('Attack Surface:')} ${riskColor(`${score} [${risk}]`)} ${C.dim(`in ${(elapsed/1000).toFixed(2)}s`)}`);
    }
    if (result.suppressedCount > 0 && !args.quiet) {
      console.log(`${C.yellow('Suppressed:')} ${result.suppressedCount} finding(s) via suppression comments`);
    }
    if (args.verbose && !args.quiet) {
      console.log(`\n${C.dim('Phase Times:')}`);
      for (const pt of result.metadata.phaseTimes) console.log(`  ${C.dim(pt.name.padEnd(20)+String(pt.ms).padStart(6)+'ms')}`);
      if (result.suppressionReasons && result.suppressionReasons.length) {
        console.log(`\n${C.dim('Suppression Reasons:')}`);
        for (const r of result.suppressionReasons) console.log(`  ${C.dim(r)}`);
      }
    }
    const format = args.format || 'text';
    let output;
    switch (format) {
      case 'json': output = generateJSONReport(result.findings, result.metadata); break;
      case 'html': output = generateHTMLReport(result.findings, result.metadata); break;
      case 'md': case 'markdown': output = generateMarkdownReport(result.findings, result.metadata); break;
      case 'sarif': output = generateSARIFReport(result.findings, result.metadata); break;
      case 'github-annotation': output = formatGitHubAnnotations(result.findings, result.metadata); break;
      default: output = formatTextReport(result.findings, result.metadata, args['no-color'] ? null : C);
    }
    if (args.output) {
      fs.writeFileSync(args.output, output, 'utf8');
      if (!args.quiet) console.log(`${C.green('Report written:')} ${args.output}`);
    } else {
      process.stdout.write(output);
    }
  }

  main().catch(e => { console.error(`Error: ${e.message}`); process.exit(1); });
}

// ═══════════════════════════════════════════════════════════════════════════
//  EXPORTS
// ═══════════════════════════════════════════════════════════════════════════
module.exports = {
  decodePipeline,
  scanCredentials, analyseSecurity,
  scanDynamicCodeExecution, scanBusinessLogic, scanWebSocketContent,
  scanCryptoContext, scanInfoLeakage, scanIDOR, scanDependencies,
  scanRaceConditions, scanTaintFlow, scanWeb3, scanConfigDrivenBehaviour, scanLazyLoading,
  scanServiceWorker, scanDirectory, fetchURL, formatGitHubAnnotations,
  detectFramework, extractRoutes, mapAuthSurface, scanStorageKeys, scanCodePatterns,
  scoreAttackSurface, splitWebpackModules, buildDependencyGraph,
  generateJSONReport, generateHTMLReport, generateMarkdownReport, generateSARIFReport,
  runPipeline,
};;
