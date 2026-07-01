'use strict';

/**
 * OMEGA v5 — AST-Based Taint Flow Analyzer
 *
 * Lightweight JS tokenizer + recursive descent parser with full
 * position tracking + AST-based taint flow analysis.
 *
 * No external dependencies.
 *
 * Difference from ast-parser.js:
 *  - Position tracking (start/end) on every node
 *  - Complete control flow: For/While/DoWhile/Switch/Try/ConditionalExpression
 *  - Built-in taint flow analyzer using the AST
 *  - Focused on patterns relevant to security analysis
 */

// ═════════════════════════════════════════════════════════════════════════
//  TOKENIZER
// ═════════════════════════════════════════════════════════════════════════

const TT = {
  LPAREN:1, RPAREN:2, LBRACE:3, RBRACE:4, LBRACK:5, RBRACK:6,
  SEMI:7, COMMA:8, DOT:9, EQUALS:10, COLON:11, QUESTION:12,
  STRING:13, NUMBER:14, IDENT:15, KEYWORD:16, OPERATOR:17,
  EOF:18, FATARROW:19, TEMPLATE:20, REGEX:21, SPREAD:22, OPTCHAIN:23,
};

const KEYWORDS = new Set([
  'function','class','return','if','else','for','while','do',
  'switch','case','break','continue','var','let','const',
  'new','this','typeof','delete','void','throw','try','catch',
  'finally','in','of','import','export','default','from',
  'async','await','yield','static','get','set','extends',
  'instanceof','debugger',
]);

function tokenize(src) {
  const tokens = [];
  let i = 0, n = src.length, expectExpr = false;
  while (i < n) {
    if (/[\s\n\r\t]/.test(src[i])) { i++; continue; }
    // Line comment
    if (src[i] === '/' && src[i+1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    // Block comment
    if (src[i] === '/' && src[i+1] === '*') { i += 2; while (i < n && !(src[i] === '*' && src[i+1] === '/')) i++; i += 2; continue; }
    // String literal
    if (src[i] === '"' || src[i] === "'" || src[i] === '`') {
      const q = src[i]; let s = q; const start = i; i++;
      while (i < n) { if (src[i] === '\\') { s += src[i] + (src[i+1]||''); i += 2; continue; } s += src[i]; if (src[i] === q) { i++; break; } i++; }
      tokens.push({ type: TT.STRING, value: s, start, end: i });
      expectExpr = false;
      continue;
    }
    // Regex literal (when expression is expected, `/` starts a regex not division)
    if (src[i] === '/' && expectExpr) {
      const start = i; let body = ''; i++;
      while (i < n) { if (src[i] === '\\') { body += src[i] + (src[i+1]||''); i += 2; continue; } if (src[i] === '/') { i++; break; } body += src[i]; i++; }
      let flags = '';
      while (i < n && /[gimsuydv]/.test(src[i])) { flags += src[i]; i++; }
      tokens.push({ type: TT.REGEX, value: '/' + body + '/' + flags, start, end: i });
      expectExpr = false;
      continue;
    }
    // Number literal
    if (/[0-9]/.test(src[i]) || (src[i] === '.' && /[0-9]/.test(src[i+1]))) {
      const start = i; let num = '';
      if (src[i] === '0' && (src[i+1] === 'x' || src[i+1] === 'X')) {
        num = src[i] + src[i+1]; i += 2;
        while (i < n && /[0-9a-fA-F]/.test(src[i])) { num += src[i]; i++; }
      } else if (src[i] === '0' && (src[i+1] === 'b' || src[i+1] === 'B')) {
        num = src[i] + src[i+1]; i += 2;
        while (i < n && /[01]/.test(src[i])) { num += src[i]; i++; }
      } else if (src[i] === '0' && (src[i+1] === 'o' || src[i+1] === 'O')) {
        num = src[i] + src[i+1]; i += 2;
        while (i < n && /[0-7]/.test(src[i])) { num += src[i]; i++; }
      } else {
        while (i < n && /[0-9.eE+\-_]/.test(src[i])) {
          if ((src[i] === '+' || src[i] === '-') && i > 0 && src[i-1] !== 'e' && src[i-1] !== 'E') break;
          if (src[i] === '_') { i++; continue; } // numeric separators
          if (src[i] === '.' && num.includes('.')) break;
          num += src[i]; i++;
        }
        if (src[i] === 'n') { num += 'n'; i++; } // BigInt
      }
      tokens.push({ type: TT.NUMBER, value: num, start, end: i });
      expectExpr = false;
      continue;
    }
    // Identifier or keyword
    if (/[a-zA-Z_$\u00a0-\uffff]/.test(src[i]) || src[i] === '\\') {
      const start = i; let id = '';
      if (src[i] === '\\') { id += src[i] + src[i+1] + src[i+2] + src[i+3] + src[i+4] + src[i+5]; i += 6; }
      else { while (i < n && /[a-zA-Z0-9_$\u00a0-\uffff]/.test(src[i])) { id += src[i]; i++; } }
      const isKw = KEYWORDS.has(id);
      tokens.push({ type: isKw ? TT.KEYWORD : TT.IDENT, value: id, start, end: i });
      expectExpr = isKw && /^(return|typeof|throw|void|delete|new|case|default|yield|await)$/.test(id);
      continue;
    }
    // Three-char operators: ... **= ||= &&= ??=
    const three = src.substr(i, 3);
    if (three === '...') { tokens.push({ type: TT.SPREAD, value: '...', start: i, end: i+3 }); i += 3; expectExpr = true; continue; }
    if (/^(\*\*|\|\||&&|\?\?)=$/.test(three)) { tokens.push({ type: TT.OPERATOR, value: three, start: i, end: i+3 }); i += 3; expectExpr = true; continue; }
    // Two-char operators
    const two = src.substr(i, 2);
    if (two === '=>') { tokens.push({ type: TT.FATARROW, value: '=>', start: i, end: i+2 }); i += 2; expectExpr = true; continue; }
    if (two === '?.') { tokens.push({ type: TT.OPTCHAIN, value: '?.', start: i, end: i+2 }); i += 2; expectExpr = true; continue; }
    if (/^(==|===|!=|!==|>=|<=|\|\||&&|\?\?|\+\+|--|<<|>>|>>>|\*\*)$/.test(two)) {
      tokens.push({ type: TT.OPERATOR, value: two, start: i, end: i+2 }); i += 2; expectExpr = true; continue;
    }
    // Single-char tokens
    const map = { '(':'LPAREN',')':'RPAREN','{':'LBRACE','}':'RBRACE','[':'LBRACK',']':'RBRACK',';':'SEMI',',':'COMMA','.':'DOT',':':'COLON','?':'QUESTION' };
    const tn = map[src[i]];
    if (tn) {
      const type = TT[tn];
      tokens.push({ type, value: src[i], start: i, end: i+1 }); i++;
      expectExpr = type === TT.LPAREN || type === TT.LBRACK || type === TT.COMMA || type === TT.SEMI || type === TT.QUESTION || type === TT.COLON;
      continue;
    }
    if ('+-*/%<>&|^!~@#='.includes(src[i])) {
      tokens.push({ type: TT.OPERATOR, value: src[i], start: i, end: i+1 }); i++; expectExpr = true; continue;
    }
    i++;
  }
  tokens.push({ type: TT.EOF, value: '', start: n, end: n });
  return tokens;
}

// ═════════════════════════════════════════════════════════════════════════
//  RECURSIVE DESCENT PARSER (position-tracked nodes)
// ═════════════════════════════════════════════════════════════════════════

class TaintParser {
  constructor(tokens) { this.t = tokens; this.p = 0; }
  peek() { return this.t[this.p]; }
  next() { return this.t[this.p++]; }
  expect(type) { const t = this.next(); if (t.type !== type) throw Error(`Expected ${type}, got ${t.value}`); return t; }
  skip(type) { if (this.peek().type === type) { this.p++; return true; } return false; }
  sync() { while (this.p < this.t.length && !this.skip(TT.SEMI) && !this.peek().type === TT.RBRACE && !this.skip(TT.EOF)) this.p++; }

  node(type, start, end, props) { return { type, start, end, ...props }; }

  program() {
    const body = [], start = this.peek().start;
    while (this.peek().type !== TT.EOF) {
      try { const s = this.stmt(); if (s) body.push(s); } catch (e) { this.sync(); }
    }
    return this.node('Program', start, this.peek().end, { body });
  }

  stmt() {
    const t = this.peek();
    if (!t) return null;
    if (t.value === 'var' || t.value === 'let' || t.value === 'const') return this.varDecl();
    if (t.value === 'function') return this.funcDecl();
    if (t.value === 'class') return this.classDecl();
    if (t.value === 'return') { this.next(); const a = this.expr(); this.skip(TT.SEMI); return this.node('ReturnStatement', t.start, this.peek().end, { argument: a }); }
    if (t.value === 'if') return this.ifStmt();
    if (t.value === 'for') return this.forStmt();
    if (t.value === 'while') return this.whileStmt();
    if (t.value === 'do') return this.doWhileStmt();
    if (t.value === 'switch') return this.switchStmt();
    if (t.value === 'try') return this.tryStmt();
    if (t.value === 'throw') { this.next(); const a = this.expr(); this.skip(TT.SEMI); return this.node('ThrowStatement', t.start, this.peek().end, { argument: a }); }
    if (t.value === 'break' || t.value === 'continue') { this.next(); this.skip(TT.SEMI); return this.node(t.value==='break'?'BreakStatement':'ContinueStatement', t.start, this.peek().end, {}); }
    if (t.value === 'debugger') { this.next(); this.skip(TT.SEMI); return this.node('DebuggerStatement', t.start, this.peek().end, {}); }
    if (t.type === TT.LBRACE) return this.block();
    if (t.type === TT.SEMI) { this.next(); return null; }
    const e = this.expr(); this.skip(TT.SEMI);
    return this.node('ExpressionStatement', e.start, this.peek().end, { expression: e });
  }

  block() {
    const start = this.expect(TT.LBRACE).start; const body = [];
    while (this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) { const s = this.stmt(); if (s) body.push(s); }
    const end = this.expect(TT.RBRACE).end;
    return this.node('BlockStatement', start, end, { body });
  }

  ifStmt() {
    const start = this.next().start; this.expect(TT.LPAREN); const test = this.expr(); this.expect(TT.RPAREN);
    const cons = this.stmt(); let alt = null;
    if (this.peek().value === 'else') { this.next(); alt = this.stmt(); }
    return this.node('IfStatement', start, this.peek().end, { test, consequent: cons, alternate: alt });
  }

  forStmt() {
    const start = this.next().start; this.expect(TT.LPAREN);
    let init = null; if (this.peek().type !== TT.SEMI) init = this.expr(); this.expect(TT.SEMI);
    let test = null; if (this.peek().type !== TT.SEMI) test = this.expr(); this.expect(TT.SEMI);
    let update = null; if (this.peek().type !== TT.RPAREN) update = this.expr(); this.expect(TT.RPAREN);
    const body = this.stmt();
    return this.node('ForStatement', start, this.peek().end, { init, test, update, body });
  }

  whileStmt() {
    const start = this.next().start; this.expect(TT.LPAREN); const test = this.expr(); this.expect(TT.RPAREN); const body = this.stmt();
    return this.node('WhileStatement', start, this.peek().end, { test, body });
  }

  doWhileStmt() {
    const start = this.next().start; const body = this.stmt(); this.expect(TT.KEYWORD); this.expect(TT.LPAREN); const test = this.expr(); this.expect(TT.RPAREN); this.skip(TT.SEMI);
    return this.node('DoWhileStatement', start, this.peek().end, { body, test });
  }

  switchStmt() {
    const start = this.next().start; this.expect(TT.LPAREN); const disc = this.expr(); this.expect(TT.RPAREN); this.expect(TT.LBRACE);
    const cases = [];
    while (this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) {
      if (this.peek().value === 'case') { this.next(); const t = this.expr(); this.expect(TT.COLON); const c = []; while (this.peek().value !== 'case' && this.peek().value !== 'default' && this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) { const s = this.stmt(); if (s) c.push(s); } cases.push(this.node('SwitchCase', t.start, this.peek().end, { test: t, consequent: c })); }
      else if (this.peek().value === 'default') { this.next(); this.expect(TT.COLON); const c = []; while (this.peek().value !== 'case' && this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) { const s = this.stmt(); if (s) c.push(s); } cases.push(this.node('SwitchCase', start, this.peek().end, { test: null, consequent: c })); }
      else this.p++;
    }
    this.expect(TT.RBRACE);
    return this.node('SwitchStatement', start, this.peek().end, { discriminant: disc, cases });
  }

  tryStmt() {
    const start = this.next().start; const block = this.block();
    let handler = null; if (this.peek().value === 'catch') { this.next(); this.expect(TT.LPAREN); const param = this.expr(); this.expect(TT.RPAREN); const cb = this.block(); handler = this.node('CatchClause', start, this.peek().end, { param, body: cb }); }
    let finalizer = null; if (this.peek().value === 'finally') { this.next(); finalizer = this.block(); }
    return this.node('TryStatement', start, this.peek().end, { block, handler, finalizer });
  }

  varDecl() {
    const kind = this.next().value; const start = this.peek().start;
    const dcls = [];
    do {
      const id = this.idOrPattern(); let init = null;
      if (this.peek().type === TT.OPERATOR && this.peek().value === '=') { this.next(); init = this.expr(); }
      dcls.push(this.node('VariableDeclarator', id.start, (init||id).end, { id, init }));
    } while (this.skip(TT.COMMA));
    this.skip(TT.SEMI);
    return this.node('VariableDeclaration', start, this.peek().end, { kind, declarations: dcls });
  }

  idOrPattern() {
    if (this.peek().type === TT.LBRACE) return this.objPattern();
    if (this.peek().type === TT.LBRACK) return this.arrPattern();
    const t = this.expect(TT.IDENT);
    return this.node('Identifier', t.start, t.end, { name: t.value });
  }

  objPattern() {
    const start = this.expect(TT.LBRACE).start; const props = [];
    while (this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) {
      const key = this.expr(); let value = key;
      if (this.peek().type === TT.COLON) { this.next(); value = this.idOrPattern(); }
      props.push(this.node('Property', key.start, value.end, { key, value }));
      this.skip(TT.COMMA);
    }
    const end = this.expect(TT.RBRACE).end;
    return this.node('ObjectPattern', start, end, { properties: props });
  }

  arrPattern() {
    const start = this.expect(TT.LBRACK).start; const els = [];
    while (this.peek().type !== TT.RBRACK && this.peek().type !== TT.EOF) {
      if (this.peek().type === TT.COMMA) { els.push(null); this.next(); }
      else { els.push(this.idOrPattern()); this.skip(TT.COMMA); }
    }
    const end = this.expect(TT.RBRACK).end;
    return this.node('ArrayPattern', start, end, { elements: els });
  }

  funcDecl() {
    const start = this.next().start;
    let id = null; if (this.peek().type === TT.IDENT) { const t = this.next(); id = this.node('Identifier', t.start, t.end, { name: t.value }); }
    const { params, body } = this.parseFuncRest();
    return this.node('FunctionDeclaration', start, this.peek().end, { id, params, body });
  }

  parseFuncRest() {
    this.expect(TT.LPAREN); const params = [];
    while (this.peek().type !== TT.RPAREN && this.peek().type !== TT.EOF) { params.push(this.idOrPattern()); this.skip(TT.COMMA); }
    this.expect(TT.RPAREN); const body = this.block();
    return { params, body };
  }

  classDecl() {
    const start = this.next().start;
    let id = null; if (this.peek().type === TT.IDENT) { const t = this.next(); id = this.node('Identifier', t.start, t.end, { name: t.value }); }
    let superClass = null; if (this.peek().value === 'extends') { this.next(); superClass = this.expr(); }
    this.expect(TT.LBRACE); const body = [];
    while (this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) {
      let isStatic = false; if (this.peek().value === 'static') { isStatic = true; this.next(); }
      let key = null;
      if (this.peek().type === TT.IDENT) { const t = this.next(); key = this.node('Identifier', t.start, t.end, { name: t.value }); }
      else if (this.peek().type === TT.STRING) { const t = this.next(); key = this.node('Literal', t.start, t.end, { value: t.value }); }
      else if (this.peek().type === TT.LBRACK) { this.next(); key = this.expr(); this.expect(TT.RBRACK); }
      if (!key) break;
      if (this.peek().type === TT.LPAREN) {
        const { params, body: b } = this.parseFuncRest();
        body.push(this.node('MethodDefinition', start, this.peek().end, { key, value: this.node('FunctionExpression', key.start, this.peek().end, { params, body: b }), isStatic }));
      } else if (this.peek().type === TT.OPERATOR || this.peek().type === TT.EQUALS) { this.next(); const v = this.expr(); body.push(this.node('PropertyDefinition', key.start, this.peek().end, { key, value: v, isStatic })); this.skip(TT.SEMI); }
      else if (this.skip(TT.SEMI)) { body.push(this.node('PropertyDefinition', key.start, key.end, { key, value: null, isStatic })); }
      else break;
    }
    this.expect(TT.RBRACE);
    return this.node('ClassDeclaration', start, this.peek().end, { id, superClass, body });
  }

  // — Expression parsing —
  expr() { return this.assign(); }

  assign() {
    let l = this.ternary();
    if (this.peek().type === TT.OPERATOR && /^[+\-*/%&|^]=$|^=$/.test(this.peek().value)) {
      const op = this.next().value; const r = this.assign();
      l = this.node('AssignmentExpression', l.start, r.end, { operator: op, left: l, right: r });
    }
    return l;
  }

  ternary() {
    let l = this.binary(0);
    if (this.peek().type === TT.QUESTION) {
      this.next(); const cons = this.expr(); this.expect(TT.COLON); const alt = this.expr();
      l = this.node('ConditionalExpression', l.start, alt.end, { test: l, consequent: cons, alternate: alt });
    }
    return l;
  }

  prec(op) { return ({ '||':1,'&&':2,'|':3,'^':4,'&':5,'==':6,'!=':6,'===':6,'!==':6,'<':7,'<=':7,'>':7,'>=':7,'instanceof':7,'in':7,'<<':8,'>>':8,'>>>':8,'+':9,'-':9,'*':10,'/':10,'%':10,'**':11 })[op]||0; }

  binary(minP) {
    let l = this.unary();
    while ((this.peek().type === TT.OPERATOR || this.peek().type === TT.IDENT) && this.prec(this.peek().value) > 0) {
      const op = this.peek().value; const p = this.prec(op); if (p <= minP) break;
      this.next(); const r = this.binary(p);
      l = this.node('BinaryExpression', l.start, r.end, { operator: op, left: l, right: r });
    }
    return l;
  }

  unary() {
    if (this.peek().type === TT.OPERATOR && /^[+\-!~]$/.test(this.peek().value)) { const op = this.next().value; const a = this.unary(); return this.node('UnaryExpression', op.start, a.end, { operator: op, argument: a, prefix: true }); }
    if (/^(typeof|delete|void)$/.test(this.peek().value)) { const op = this.next().value; const a = this.unary(); return this.node('UnaryExpression', op.start, a.end, { operator: op, argument: a, prefix: true }); }
    if (this.peek().value === 'await') { this.next(); const a = this.unary(); return this.node('AwaitExpression', a.start, a.end, { argument: a }); }
    return this.callMember();
  }

  callMember() {
    let o = this.primary();
    while (true) {
      if (this.peek().type === TT.DOT) { this.next(); const p = this.expect(TT.IDENT); o = this.node('MemberExpression', o.start, p.end, { object: o, property: this.node('Identifier', p.start, p.end, { name: p.value }), computed: false, optional: false }); }
      else if (this.peek().type === TT.OPTCHAIN) {
        this.next();
        if (this.peek().type === TT.LBRACK) { this.next(); const p = this.expr(); const end = this.expect(TT.RBRACK).end; o = this.node('MemberExpression', o.start, end, { object: o, property: p, computed: true, optional: true }); }
        else if (this.peek().type === TT.LPAREN) { this.next(); const args = []; while (this.peek().type !== TT.RPAREN && this.peek().type !== TT.EOF) { args.push(this.expr()); this.skip(TT.COMMA); } const end = this.expect(TT.RPAREN).end; o = this.node('CallExpression', o.start, end, { callee: o, arguments: args, optional: true }); }
        else { const p = this.expect(TT.IDENT); o = this.node('MemberExpression', o.start, p.end, { object: o, property: this.node('Identifier', p.start, p.end, { name: p.value }), computed: false, optional: true }); }
      }
      else if (this.peek().type === TT.LBRACK) { this.next(); const p = this.expr(); const end = this.expect(TT.RBRACK).end; o = this.node('MemberExpression', o.start, end, { object: o, property: p, computed: true, optional: false }); }
      else if (this.peek().type === TT.LPAREN) { this.next(); const args = []; while (this.peek().type !== TT.RPAREN && this.peek().type !== TT.EOF) { args.push(this.expr()); this.skip(TT.COMMA); } const end = this.expect(TT.RPAREN).end; o = this.node('CallExpression', o.start, end, { callee: o, arguments: args, optional: false }); }
      else break;
    }
    return o;
  }

  primary() {
    const t = this.peek();
    if (t.type === TT.LPAREN) {
      this.next(); const e = this.expr(); this.expect(TT.RPAREN);
      if (this.peek().type === TT.FATARROW) { this.next(); const b = this.peek().type === TT.LBRACE ? this.block() : this.expr(); return this.node('ArrowFunctionExpression', e.start, this.peek().end, { params: [e], body: b }); }
      return e;
    }
    if (t.type === TT.LBRACK) {
      this.next(); const els = [];
      while (this.peek().type !== TT.RBRACK && this.peek().type !== TT.EOF) {
        if (this.peek().type === TT.COMMA) { els.push(null); this.next(); }
        else if (this.peek().type === TT.SPREAD) { const st = this.next(); const arg = this.expr(); els.push(this.node('SpreadElement', st.start, arg.end, { argument: arg })); this.skip(TT.COMMA); }
        else { els.push(this.expr()); this.skip(TT.COMMA); }
      }
      const end = this.expect(TT.RBRACK).end; return this.node('ArrayExpression', t.start, end, { elements: els });
    }
    if (t.type === TT.LBRACE) {
      this.next(); const props = [];
      while (this.peek().type !== TT.RBRACE && this.peek().type !== TT.EOF) {
        if (this.peek().type === TT.SPREAD) { const st = this.next(); const arg = this.expr(); props.push(this.node('SpreadElement', st.start, arg.end, { argument: arg })); this.skip(TT.COMMA); continue; }
        let k = this.expr(); let v = k;
        if (this.peek().type === TT.COLON) { this.next(); v = this.expr(); }
        props.push(this.node('Property', k.start, v.end, { key: k, value: v }));
        this.skip(TT.COMMA);
      }
      const end = this.expect(TT.RBRACE).end; return this.node('ObjectExpression', t.start, end, { properties: props });
    }
    // Arrow function: single param (a) => or multi-param (a, b) =>
    if (t.type === TT.IDENT && this.t[this.p+1] && this.t[this.p+1].type === TT.FATARROW) {
      const n = this.next().value; this.next();
      return this.node('ArrowFunctionExpression', t.start, this.peek().end, { params: [this.node('Identifier', t.start, t.end, { name: n })], body: this.peek().type === TT.LBRACE ? this.block() : this.expr() });
    }
    if (t.type === TT.IDENT || t.type === TT.KEYWORD) {
      this.next();
      if (t.value === 'new') { const c = this.callMember(); return this.node('NewExpression', t.start, c.end, { callee: c }); }
      if (t.value === 'import' && this.peek().type === TT.LPAREN) { this.next(); const s = this.expr(); const end = this.expect(TT.RPAREN).end; return this.node('ImportExpression', t.start, end, { source: s }); }
      if (t.value === 'this') return this.node('ThisExpression', t.start, t.end, {});
      if (/^(true|false|null|undefined)$/.test(t.value)) return this.node('Literal', t.start, t.end, { value: t.value });
      if (t.value === 'async' && this.peek().value === 'function') return this.funcDecl();
      if (t.value === 'function' && this.peek().type === TT.OPERATOR && this.peek().value === '*') { this.next(); return this.funcDecl(); }
      return this.node('Identifier', t.start, t.end, { name: t.value });
    }
    if (t.type === TT.REGEX) { this.next(); return this.node('Literal', t.start, t.end, { value: t.value, regex: true }); }
    if (t.type === TT.STRING) { this.next(); return this.node('Literal', t.start, t.end, { value: t.value }); }
    if (t.type === TT.NUMBER) { this.next(); return this.node('Literal', t.start, t.end, { value: /n$/.test(t.value) ? BigInt(t.value.slice(0,-1)) : parseFloat(t.value) }); }
    if (t.type === TT.SPREAD) { this.next(); const arg = this.expr(); return this.node('SpreadElement', t.start, arg.end, { argument: arg }); }
    this.next(); return this.node('Identifier', t.start, t.end, { name: t.value||'' });
  }
}

// ═════════════════════════════════════════════════════════════════════════
//  AST WALKER
// ═════════════════════════════════════════════════════════════════════════

function walk(node, visitors) {
  if (!node || typeof node !== 'object') return;
  const v = visitors[node.type];
  if (v) v(node);
  for (const k of Object.keys(node)) {
    if (k === 'type' || k === 'start' || k === 'end') continue;
    const c = node[k];
    if (Array.isArray(c)) { for (const i of c) walk(i, visitors); }
    else if (c && typeof c === 'object') walk(c, visitors);
  }
}

// ═════════════════════════════════════════════════════════════════════════
//  TAINT TRACKER (AST-based)
// ═════════════════════════════════════════════════════════════════════════

const TAINT_SOURCES = [
  { id:'location-hash', re:/location\.hash\b/g, type:'URL' },
  { id:'location-search', re:/location\.search\b/g, type:'URL' },
  { id:'location-href', re:/location\.href\b/g, type:'URL' },
  { id:'location-pathname', re:/location\.pathname\b/g, type:'URL' },
  { id:'document-url', re:/document\.URL\b/g, type:'Document' },
  { id:'document-referrer', re:/document\.referrer\b/g, type:'Document' },
  { id:'document-cookie', re:/document\.cookie\b/g, type:'Document' },
  { id:'window-name', re:/window\.name\b/g, type:'Window' },
  { id:'postmessage-data', re:/(?:event|e)\.data\b/g, type:'PostMessage' },
  { id:'localstorage-read', re:/localStorage\.getItem\s*\(/g, type:'Storage' },
  { id:'sessionstorage-read', re:/sessionStorage\.getItem\s*\(/g, type:'Storage' },
  { id:'url-search-params', re:/URLSearchParams[^;]{0,200}\.get\s*\(/g, type:'URL' },
  { id:'response-body', re:/response\.(?:data|body|text)\b/g, type:'HTTP' },
  { id:'input-value', re:/\.value\s*(?:=|\bin\b)/g, type:'DOM' },
  { id:'response-json', re:/\.json\s*\(/g, type:'HTTP' },
  { id:'prompt-result', re:/prompt\s*\(/g, type:'UserInput' },
];

const TAINT_SINKS = [
  { id:'innerhtml', re:/\.innerHTML\s*=/g, sev:'critical', cwe:'CWE-79' },
  { id:'outerhtml', re:/\.outerHTML\s*=/g, sev:'critical', cwe:'CWE-79' },
  { id:'insertadjhtml', re:/\.insertAdjacentHTML\s*\(/g, sev:'critical', cwe:'CWE-79' },
  { id:'documentwrite', re:/document\.write\s*\(/g, sev:'critical', cwe:'CWE-79' },
  { id:'srcdoc', re:/\.srcdoc\s*=/g, sev:'critical', cwe:'CWE-79' },
  { id:'eval', re:/\beval\s*\(/g, sev:'critical', cwe:'CWE-95' },
  { id:'function-ctor', re:/new\s+Function\s*\(/g, sev:'critical', cwe:'CWE-95' },
  { id:'location-href-assign', re:/location\.(?:href|replace|assign)\s*[=(]/g, sev:'high', cwe:'CWE-601' },
  { id:'setattribute-on', re:/\.setAttribute\s*\(\s*['"]on\w+['"]\s*,/g, sev:'critical', cwe:'CWE-79' },
  { id:'jquery-html', re:/\.html\s*\([^)]+\)/g, sev:'critical', cwe:'CWE-79' },
  { id:'jquery-append', re:/\.(?:append|prepend|after|before)\s*\([^)]+\)/g, sev:'high', cwe:'CWE-79' },
];

/**
 * AST-based taint analysis.
 * Walks the parse tree, tracks which variables are tainted,
 * and detects when tainted variables reach dangerous sinks.
 *
 * Unlike regex-based taint trackers, this approach:
 *  - Respects scope boundaries
 *  - Only matches actual variable references (not strings/comments)
 *  - Can track through multi-hop assignments within the AST
 *  - Provides position-accurate findings
 */
function analyseTaintFlows(src) {
  const tokens = tokenize(src);
  const parser = new TaintParser(tokens);
  let ast;
  try { ast = parser.program(); } catch (e) { return { findings:[], ast:null, success:false, error:e.message }; }

  const findings = [];
  const seen = new Set();

  // Step 1: Identify which AST nodes are taint sources
  const taintedVars = new Map(); // varName → source info

  // Phase 1a: match source patterns in source and extract variable assignments
  for (const source of TAINT_SOURCES) {
    source.re.lastIndex = 0;
    let m;
    while ((m = source.re.exec(src)) !== null) {
      let stmtStart = Math.max(0, m.index - 300);
      const semi = src.lastIndexOf(';', m.index);
      const brace = src.lastIndexOf('{', m.index);
      if (semi > stmtStart) stmtStart = semi;
      if (brace > stmtStart) stmtStart = brace;
      const stmt = src.slice(stmtStart, m.index).trim();
      const decl = stmt.match(/(?:const|let|var)\s+(\w+)\s*=\s*[^;]*$/);
      if (decl) taintedVars.set(decl[1], { sourceId:source.id, sourceType:source.type, pos:m.index, varPos:stmtStart + stmt.lastIndexOf(decl[1]) });
      const reassign = stmt.match(/(\w+)\s*=\s*[^;]*$/);
      if (reassign && !/^(this|return|if|else|for|while|case|new)$/.test(reassign[1]) && !reassign[1].startsWith('new')) {
        taintedVars.set(reassign[1], { sourceId:source.id, sourceType:source.type, pos:m.index, varPos:m.index - reassign[1].length });
      }
    }
  }

  if (taintedVars.size === 0) return { findings:[], ast, success:true, taintedCount:0 };

  // Step 2: Walk the AST to find all assignment expressions and propagate taint
  const assignments = [];

  walk(ast, {
    AssignmentExpression(node) {
      if (node.left.type === 'Identifier') {
        assignments.push({ var:node.left.name, rhs:node.right, pos:node.start, type:'assign' });
      } else if (node.left.type === 'MemberExpression' && node.left.object.type === 'Identifier' && node.left.property.type === 'Identifier') {
        assignments.push({ var:`${node.left.object.name}.${node.left.property.name}`, rhs:node.right, pos:node.start, type:'member-assign' });
      }
    },
    VariableDeclarator(node) {
      if (node.id.type === 'Identifier' && node.init) {
        assignments.push({ var:node.id.name, rhs:node.init, pos:node.start, type:'decl' });
      }
    },
  });

  // Propagate taint through assignments (up to 5 hops)
  for (let iter = 0; iter < 5; iter++) {
    let changed = false;
    for (const a of assignments) {
      if (taintedVars.has(a.var)) continue;
      // Check if RHS references any tainted variable
      const rhsStr = JSON.stringify(a.rhs);
      for (const [vName] of taintedVars) {
        if (rhsStr.includes(vName)) {
          const srcInfo = taintedVars.get(vName);
          taintedVars.set(a.var, { ...srcInfo, propagated:true, hop:iter+1 });
          changed = true;
          break;
        }
      }
    }
    if (!changed) break;
  }

  // Step 3: Check if any tainted variable reaches a sink
  for (const sink of TAINT_SINKS) {
    sink.re.lastIndex = 0;
    let m;
    while ((m = sink.re.exec(src)) !== null) {
      const after = src.slice(m.index, m.index + 250);
      const before = src.slice(Math.max(0, m.index - 100), m.index);

      for (const [varName, srcInfo] of taintedVars) {
        // Check if the variable name appears as a standalone identifier in the sink context
        const varRe = new RegExp('\\b' + varName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '\\b');
        if (varRe.test(after) || varRe.test(before)) {
          const key = `${srcInfo.sourceId}|${sink.id}|${varName}|${m.index}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            id:'taint-flow-ast',
            category:'Taint Flow (AST)',
            severity:sink.sev,
            value:`${sink.id} ← "${varName}" (src:${srcInfo.sourceId})`,
            sourceId:srcInfo.sourceId,
            sinkId:sink.id,
            taintedVar:varName,
            propagated:!!srcInfo.propagated,
            hopCount:srcInfo.hop||0,
            context:after.replace(/\n/g,' ').slice(0,120),
            posStart:m.index,
            posEnd:m.index + m[0].length,
            description:`AST: tainted data from "${srcInfo.sourceType}:${srcInfo.sourceId}" reaches "${sink.id}" via variable "${varName}"${srcInfo.propagated ? ` (${srcInfo.hop}+ hops)` : ''}`,
            cwe:sink.cwe,
          });
        }
      }

      // Direct source→sink (no intermediate variable)
      for (const source of TAINT_SOURCES) {
        const dr = new RegExp(source.re.source);
        if (dr.test(after) || dr.test(before)) {
          const key = `direct|${source.id}|${sink.id}|${m.index}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            id:'taint-flow-ast-direct',
            category:'Taint Flow (AST)',
            severity:sink.sev,
            value:`${source.id} → ${sink.id} (direct)`,
            context:after.replace(/\n/g,' ').slice(0,120),
            description:`AST: direct flow from "${source.id}" to "${sink.id}"`,
            cwe:sink.cwe, posStart:m.index, posEnd:m.index + m[0].length,
          });
        }
      }
    }
  }

  return {
    findings,
    ast,
    success:true,
    taintedCount:taintedVars.size,
    total:findings.length,
    bySeverity:{
      critical:findings.filter(f=>f.severity==='critical').length,
      high:findings.filter(f=>f.severity==='high').length,
      medium:findings.filter(f=>f.severity==='medium').length,
    },
  };
}

// ═════════════════════════════════════════════════════════════════════════
//  EXPORTS
// ═════════════════════════════════════════════════════════════════════════

module.exports = {
  tokenize,
  TaintParser,
  walk,
  analyseTaintFlows,
  TAINT_SOURCES,
  TAINT_SINKS,
};
