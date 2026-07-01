'use strict';

/**
 * OMEGA v5 — AST Parser Module
 * Item 1: Replace regex framework detection with real AST analysis.
 *
 * Uses a hand-rolled tokenizer + recursive descent parser for minified JS.
 * No external dependencies — works on webpack/Vite/Rollup output.
 *
 * Walks top-level statements to count:
 *  - Angular components (class { static ɵfac/ɵcmp/ɵprov/ɵpipe })
 *  - Vue components (createElementVNode, defineComponent calls)
 *  - React components (createElement, jsx calls)
 *  - Svelte components (SvelteComponent, create_fragment)
 *  - Class declarations, function declarations, arrow functions
 */

const C = { reset:'\x1b[0m', bold:'\x1b[1m', red:'\x1b[31m', green:'\x1b[32m', yellow:'\x1b[33m', cyan:'\x1b[36m', dim:'\x1b[2m' };

// ── Tokenizer ──────────────────────────────────────────────────────────────
const TokenType = {
  LPAREN: 1, RPAREN: 2, LBRACE: 3, RBRACE: 4, LBRACK: 5, RBRACK: 6,
  SEMI: 7, COMMA: 8, DOT: 9, EQUALS: 10, COLON: 11, ARROW: 12,
  STRING: 13, NUMBER: 14, IDENT: 15, KEYWORD: 16, OPERATOR: 17,
  EOF: 18, TEMPLATE: 19, COLONCOLON: 20, FATARROW: 21,
};

const KEYWORDS = new Set([
  'function', 'class', 'return', 'if', 'else', 'for', 'while', 'do',
  'switch', 'case', 'break', 'continue', 'var', 'let', 'const',
  'new', 'this', 'typeof', 'delete', 'void', 'throw', 'try', 'catch',
  'finally', 'in', 'of', 'import', 'export', 'default', 'from',
  'async', 'await', 'yield', 'static', 'get', 'set', 'extends',
  'instanceof',
]);

function tokenize(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    // Whitespace
    if (/[\s\n\r\t]/.test(src[i])) { i++; continue; }
    // Comments
    if (src[i] === '/' && src[i+1] === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (src[i] === '/' && src[i+1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i+1] === '/')) i++;
      i += 2;
      continue;
    }
    // Strings
    if (src[i] === '"' || src[i] === "'" || src[i] === '`') {
      const quote = src[i];
      let s = quote;
      i++;
      while (i < n) {
        if (src[i] === '\\') { s += src[i] + (src[i+1]||''); i += 2; continue; }
        s += src[i];
        if (src[i] === quote) { i++; break; }
        i++;
      }
      tokens.push({ type: TokenType.STRING, value: s, pos: i });
      continue;
    }
    // Template literals (handle backtick strings we already got above)
    // Numbers
    if (/[0-9]/.test(src[i]) || (src[i] === '.' && /[0-9]/.test(src[i+1]))) {
      let num = '';
      if (src[i] === '0' && (src[i+1] === 'x' || src[i+1] === 'X')) {
        num = src[i] + src[i+1]; i += 2;
        while (i < n && /[0-9a-fA-F]/.test(src[i])) { num += src[i]; i++; }
      } else {
        while (i < n && /[0-9.eE+\-]/.test(src[i])) {
          if ((src[i] === '+' || src[i] === '-') && i > 0 && src[i-1] !== 'e' && src[i-1] !== 'E') break;
          if (src[i] === '.' && num.includes('.')) break;
          num += src[i]; i++;
        }
      }
      tokens.push({ type: TokenType.NUMBER, value: num, pos: i });
      continue;
    }
    // Identifiers & keywords
    if (/[a-zA-Z_$\u00a0-\uffff]/.test(src[i]) || src[i] === '\\') {
      let id = '';
      if (src[i] === '\\') {
        id += src[i] + src[i+1] + src[i+2] + src[i+3] + src[i+4] + src[i+5];
        i += 6;
      } else {
        while (i < n && /[a-zA-Z0-9_$\u00a0-\uffff]/.test(src[i])) {
          id += src[i]; i++;
        }
      }
      tokens.push({
        type: KEYWORDS.has(id) ? TokenType.KEYWORD : TokenType.IDENT,
        value: id, pos: i,
      });
      continue;
    }
    // Multi-char operators
    const twoChar = src.substr(i, 2);
    if (twoChar === '=>') { tokens.push({ type: TokenType.FATARROW, value: '=>', pos: i }); i += 2; continue; }
    if (twoChar === '::') { tokens.push({ type: TokenType.COLONCOLON, value: '::', pos: i }); i += 2; continue; }
    if (twoChar === '==') { tokens.push({ type: TokenType.OPERATOR, value: '==', pos: i }); i += 2; continue; }
    if (twoChar === '===') { tokens.push({ type: TokenType.OPERATOR, value: '===', pos: i }); i += 3; continue; }
    if (twoChar === '!=') { tokens.push({ type: TokenType.OPERATOR, value: '!=', pos: i }); i += 2; continue; }
    if (twoChar === '!==') { tokens.push({ type: TokenType.OPERATOR, value: '!==', pos: i }); i += 3; continue; }
    if (twoChar === '>=') { tokens.push({ type: TokenType.OPERATOR, value: '>=', pos: i }); i += 2; continue; }
    if (twoChar === '<=') { tokens.push({ type: TokenType.OPERATOR, value: '<=', pos: i }); i += 2; continue; }
    if (twoChar === '||') { tokens.push({ type: TokenType.OPERATOR, value: '||', pos: i }); i += 2; continue; }
    if (twoChar === '&&') { tokens.push({ type: TokenType.OPERATOR, value: '&&', pos: i }); i += 2; continue; }
    if (twoChar === '??') { tokens.push({ type: TokenType.OPERATOR, value: '??', pos: i }); i += 2; continue; }

    // Single-char
    const map = {
      '(':'LPAREN', ')':'RPAREN', '{':'LBRACE', '}':'RBRACE',
      '[':'LBRACK', ']':'RBRACK', ';':'SEMI', ',':'COMMA',
      '.':'DOT', '=':'EQUALS', ':':'COLON',
    };
    const typeName = map[src[i]];
    if (typeName) {
      tokens.push({ type: TokenType[typeName], value: src[i], pos: i });
      i++;
      continue;
    }
    // Operators
    if ('+-*/%<>&|^!~?@#'.includes(src[i])) {
      tokens.push({ type: TokenType.OPERATOR, value: src[i], pos: i });
      i++;
      continue;
    }
    // Skip anything else
    i++;
  }

  tokens.push({ type: TokenType.EOF, value: '', pos: n });
  return tokens;
}

// ── Recursive Descent Parser ───────────────────────────────────────────────
class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek() { return this.tokens[this.pos]; }
  next() { return this.tokens[this.pos++]; }
  expect(type) {
    const t = this.next();
    if (t.type !== type) throw new Error(`Expected ${type}, got ${t.value} at ${t.pos}`);
    return t;
  }
  skip(type) {
    if (this.peek().type === type) { this.pos++; return true; }
    return false;
  }

  // Skip to next semicolon or RBRACE (for error recovery)
  sync() {
    while (this.pos < this.tokens.length && !this.skip(TokenType.SEMI) && !this.skip(TokenType.RBRACE) && !this.skip(TokenType.EOF)) {
      this.pos++;
    }
  }

  parseProgram() {
    const nodes = [];
    while (this.peek().type !== TokenType.EOF) {
      try {
        const stmt = this.parseStatement();
        if (stmt) nodes.push(stmt);
      } catch (e) {
        this.sync();
      }
    }
    return { type: 'Program', body: nodes };
  }

  parseStatement() {
    const tok = this.peek();
    if (!tok) return null;

    // Variable declaration
    if (tok.value === 'var' || tok.value === 'let' || tok.value === 'const') {
      return this.parseVarDecl();
    }
    // Function declaration
    if (tok.value === 'function') {
      return this.parseFunction();
    }
    // Class declaration
    if (tok.value === 'class') {
      return this.parseClass();
    }
    // Return
    if (tok.value === 'return') {
      this.next();
      const expr = this.parseExpression();
      this.skip(TokenType.SEMI);
      return { type: 'ReturnStatement', argument: expr };
    }
    // If
    if (tok.value === 'if') { return this.parseIf(); }
    // Expression statement (assignment, call, etc.)
    if (tok.type === TokenType.IDENT || tok.type === TokenType.STRING || tok.type === TokenType.NUMBER ||
        tok.type === TokenType.LPAREN || tok.type === TokenType.LBRACK || tok.type === TokenType.OPERATOR) {
      const expr = this.parseExpression();
      this.skip(TokenType.SEMI);
      return { type: 'ExpressionStatement', expression: expr };
    }
    // Skip semicolons
    if (tok.type === TokenType.SEMI) { this.next(); return null; }
    // Block
    if (tok.type === TokenType.LBRACE) { return this.parseBlock(); }
    // Unknown — skip
    this.next();
    return null;
  }

  parseBlock() {
    this.expect(TokenType.LBRACE);
    const body = [];
    while (this.peek().type !== TokenType.RBRACE && this.peek().type !== TokenType.EOF) {
      const stmt = this.parseStatement();
      if (stmt) body.push(stmt);
    }
    this.expect(TokenType.RBRACE);
    return { type: 'Block', body };
  }

  parseIf() {
    this.next();
    this.expect(TokenType.LPAREN);
    const test = this.parseExpression();
    this.expect(TokenType.RPAREN);
    const consequent = this.parseStatement();
    let alternate = null;
    if (this.peek().value === 'else') {
      this.next();
      alternate = this.parseStatement();
    }
    return { type: 'IfStatement', test, consequent, alternate };
  }

  parseVarDecl() {
    const kind = this.next().value;
    const declarations = [];
    do {
      const id = this.parseExpression(); // simplified — just get the identifier
      let init = null;
      if (this.peek().type === TokenType.OPERATOR && this.peek().value === '=') {
        this.next();
        init = this.parseExpression();
      }
      declarations.push({ type: 'VariableDeclarator', id, init });
    } while (this.skip(TokenType.COMMA));
    this.skip(TokenType.SEMI);
    return { type: 'VariableDeclaration', kind, declarations };
  }

  parseFunction() {
    this.next(); // 'function'
    let id = null;
    if (this.peek().type === TokenType.IDENT) {
      id = this.next().value;
    }
    this.expect(TokenType.LPAREN);
    const params = [];
    while (this.peek().type !== TokenType.RPAREN && this.peek().type !== TokenType.EOF) {
      params.push(this.parseExpression());
      this.skip(TokenType.COMMA);
    }
    this.expect(TokenType.RPAREN);
    const body = this.parseBlock();
    return { type: 'FunctionDeclaration', id, params, body };
  }

  parseClass() {
    this.next();
    let id = null;
    if (this.peek().type === TokenType.IDENT) {
      id = this.next().value;
    }
    let superClass = null;
    if (this.peek().value === 'extends') {
      this.next();
      superClass = this.parseExpression();
    }
    this.expect(TokenType.LBRACE);
    const body = [];
    while (this.peek().type !== TokenType.RBRACE && this.peek().type !== TokenType.EOF) {
      // Static keyword?
      let isStatic = false;
      if (this.peek().value === 'static') {
        isStatic = true;
        this.next();
      }
      // Property name — identifier or computed
      let key = null;
      if (this.peek().type === TokenType.IDENT) {
        key = this.next().value;
      } else if (this.peek().type === TokenType.STRING) {
        key = this.next().value;
      } else if (this.peek().type === TokenType.LBRACK) {
        this.next();
        key = this.parseExpression();
        this.expect(TokenType.RBRACK);
      }
      // Function-like or expression
      if (this.peek().type === TokenType.LPAREN) {
        this.expect(TokenType.LPAREN);
        const params = [];
        while (this.peek().type !== TokenType.RPAREN && this.peek().type !== TokenType.EOF) {
          params.push(this.parseExpression());
          this.skip(TokenType.COMMA);
        }
        this.expect(TokenType.RPAREN);
        const bodyNode = this.parseBlock();
        body.push({ type: 'MethodDefinition', key, value: { type: 'FunctionExpression', params, body: bodyNode }, isStatic });
      } else if (this.peek().type === TokenType.EQUALS || (this.peek().type === TokenType.OPERATOR && this.peek().value === '=')) {
        this.next();
        const value = this.parseExpression();
        body.push({ type: 'PropertyDefinition', key, value, isStatic });
        this.skip(TokenType.SEMI);
      } else if (this.peek().type === TokenType.SEMI) {
        // Empty property
        this.next();
        body.push({ type: 'PropertyDefinition', key, value: null, isStatic });
      } else {
        break;
      }
    }
    this.expect(TokenType.RBRACE);
    return { type: 'ClassDeclaration', id, superClass, body };
  }

  // Expression parsing (simplified Pratt parser)
  parseExpression() {
    return this.parseAssignment();
  }

  parseAssignment() {
    let left = this.parseBinary(0);
    if (this.peek().type === TokenType.OPERATOR && /^[+\-*/%&|^]=$|^=$/.test(this.peek().value)) {
      const op = this.next().value;
      const right = this.parseAssignment();
      left = { type: 'AssignmentExpression', operator: op, left, right };
    }
    return left;
  }

  // Operator precedence table
  getPrecedence(op) {
    const prec = {
      '||':1, '&&':2, '|':3, '^':4, '&':5, '==':6, '!=':6, '===':6, '!==':6,
      '<':7, '<=':7, '>':7, '>=':7, 'instanceof':7, 'in':7,
      '<<':8, '>>':8, '>>>':8,
      '+':9, '-':9, '*':10, '/':10, '%':10,
      '**':11,
    };
    return prec[op] || 0;
  }

  parseBinary(minPrec) {
    let left = this.parseUnary();
    while (this.peek().type === TokenType.OPERATOR || this.peek().type === TokenType.IDENT) {
      const op = this.peek().value;
      const prec = this.getPrecedence(op);
      if (prec === 0 || prec <= minPrec) break;
      this.next();
      const right = this.parseBinary(prec);
      left = { type: 'BinaryExpression', operator: op, left, right };
    }
    return left;
  }

  parseUnary() {
    if (this.peek().type === TokenType.OPERATOR && /^[+\-!~]$/.test(this.peek().value)) {
      const op = this.next().value;
      const arg = this.parseUnary();
      return { type: 'UnaryExpression', operator: op, argument: arg };
    }
    if (this.peek().value === 'typeof' || this.peek().value === 'delete' || this.peek().value === 'void') {
      const op = this.next().value;
      const arg = this.parseUnary();
      return { type: 'UnaryExpression', operator: op, argument: arg };
    }
    if (this.peek().value === 'await') {
      this.next();
      const arg = this.parseUnary();
      return { type: 'AwaitExpression', argument: arg };
    }
    return this.parseCallMember();
  }

  parseCallMember() {
    let obj = this.parsePrimary();

    while (true) {
      // Member access .x or [x]
      if (this.peek().type === TokenType.DOT) {
        this.next();
        const prop = this.next().value;
        obj = { type: 'MemberExpression', object: obj, property: { type: 'Identifier', name: prop }, computed: false };
      } else if (this.peek().type === TokenType.LBRACK) {
        this.next();
        const prop = this.parseExpression();
        this.expect(TokenType.RBRACK);
        obj = { type: 'MemberExpression', object: obj, property: prop, computed: true };
      }
      // Call ()
      else if (this.peek().type === TokenType.LPAREN) {
        this.next();
        const args = [];
        while (this.peek().type !== TokenType.RPAREN && this.peek().type !== TokenType.EOF) {
          args.push(this.parseExpression());
          this.skip(TokenType.COMMA);
        }
        this.expect(TokenType.RPAREN);
        obj = { type: 'CallExpression', callee: obj, arguments: args };
      }
      // Template literal
      else if (this.peek().type === TokenType.TEMPLATE) {
        const quasi = this.next().value;
        obj = { type: 'TaggedTemplateExpression', tag: obj, quasi };
      }
      else { break; }
    }
    return obj;
  }

  parsePrimary() {
    const tok = this.peek();

    // Parenthesized expression
    if (tok.type === TokenType.LPAREN) {
      this.next();
      // Arrow function? params) => body
      const expr = this.parseExpression();
      this.expect(TokenType.RPAREN);
      if (this.peek().type === TokenType.FATARROW) {
        this.next();
        const body = this.peek().type === TokenType.LBRACE ? this.parseBlock() : this.parseExpression();
        return { type: 'ArrowFunctionExpression', params: [expr], body };
      }
      if (this.peek().type === TokenType.COLON) {
        this.next();
        // This might be a sequence expression or comma
        return { type: 'SequenceExpression', expressions: [expr, this.parseExpression()] };
      }
      return expr;
    }

    // Array literal
    if (tok.type === TokenType.LBRACK) {
      this.next();
      const elements = [];
      while (this.peek().type !== TokenType.RBRACK && this.peek().type !== TokenType.EOF) {
        if (this.peek().type === TokenType.COMMA) {
          elements.push(null);
          this.next();
        } else {
          elements.push(this.parseExpression());
          this.skip(TokenType.COMMA);
        }
      }
      this.expect(TokenType.RBRACK);
      return { type: 'ArrayExpression', elements };
    }

    // Object literal
    if (tok.type === TokenType.LBRACE) {
      this.next();
      const properties = [];
      while (this.peek().type !== TokenType.RBRACE && this.peek().type !== TokenType.EOF) {
        let key = this.parseExpression();
        let value = null;
        if (this.peek().type === TokenType.COLON) {
          this.next();
          value = this.parseExpression();
        } else {
          value = key;
        }
        properties.push({ type: 'Property', key, value });
        this.skip(TokenType.COMMA);
      }
      this.expect(TokenType.RBRACE);
      return { type: 'ObjectExpression', properties };
    }

    // Arrow function: params => body
    if (tok.type === TokenType.IDENT && this.tokens[this.pos + 1] && this.tokens[this.pos + 1].type === TokenType.FATARROW) {
      const id = this.next().value;
      this.next();
      const body = this.peek().type === TokenType.LBRACE ? this.parseBlock() : this.parseExpression();
      return { type: 'ArrowFunctionExpression', params: [{ type: 'Identifier', name: id }], body };
    }

    // Identifiers and keywords
    if (tok.type === TokenType.IDENT) {
      this.next();
      // new X()
      if (tok.value === 'new' && this.peek().type === TokenType.IDENT) {
        const callee = this.parseCallMember();
        return { type: 'NewExpression', callee };
      }
      // import()
      if (tok.value === 'import' && this.peek().type === TokenType.LPAREN) {
        this.next();
        const source = this.parseExpression();
        this.expect(TokenType.RPAREN);
        return { type: 'ImportExpression', source };
      }
      return { type: 'Identifier', name: tok.value };
    }

    if (tok.type === TokenType.KEYWORD && tok.value === 'new') {
      this.next();
      const callee = this.parseCallMember();
      return { type: 'NewExpression', callee };
    }

    // Strings and numbers
    if (tok.type === TokenType.STRING) {
      this.next();
      return { type: 'Literal', value: tok.value };
    }
    if (tok.type === TokenType.NUMBER) {
      this.next();
      return { type: 'Literal', value: parseFloat(tok.value) };
    }

    // Arrow function: () => body or async () => body
    if (tok.type === TokenType.LPAREN || tok.value === 'async') {
      if (tok.value === 'async') {
        this.next();
        this.expect(TokenType.LPAREN);
        const params = [this.parseExpression()];
        this.expect(TokenType.RPAREN);
        if (this.peek().type === TokenType.FATARROW) {
          this.next();
          const body = this.peek().type === TokenType.LBRACE ? this.parseBlock() : this.parseExpression();
          return { type: 'ArrowFunctionExpression', params, async: true, body };
        }
        return null;
      }
    }

    // this, super, true, false, null, undefined
    if (tok.value === 'this' || tok.value === 'super' || tok.value === 'true' || tok.value === 'false' || tok.value === 'null' || tok.value === 'undefined') {
      this.next();
      return { type: tok.value === 'this' ? 'ThisExpression' : 'Literal', value: tok.value };
    }

    // Skip unknown
    this.next();
    return { type: 'Identifier', name: tok.value };
  }
}

// ── AST Walker ──────────────────────────────────────────────────────────────
function walkAST(node, visitors) {
  if (!node || typeof node !== 'object') return;

  const visitor = visitors[node.type];
  if (visitor) visitor(node);

  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'loc') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) walkAST(item, visitors);
    } else if (child && typeof child === 'object') {
      walkAST(child, visitors);
    }
  }
}

// ── Component/Service/Class Counter ─────────────────────────────────────────
function countAngularComponents(ast) {
  let components = 0, services = 0, pipes = 0, directives = 0;

  walkAST(ast, {
    PropertyDefinition(node) {
      const key = node.key;
      if (!key) return;
      const name = typeof key === 'string' ? key : (key.name || key.value || '');
      if (name === 'ɵfac' || name === '\\u0275fac') { /* factory — not counted */ }
      if (name === 'ɵcmp' || name === '\\u0275cmp') components++;
      if (name === 'ɵprov' || name === '\\u0275prov') services++;
      if (name === 'ɵpipe' || name === '\\u0275pipe') pipes++;
      if (name === 'ɵdir' || name === '\\u0275dir') directives++;
    },
    // Also count via defineComponent/defineInjectable calls
    CallExpression(node) {
      const callee = node.callee;
      if (!callee) return;
      const name = callee.type === 'MemberExpression'
        ? (callee.property && callee.property.name)
        : (callee.name || '');
      if (name === 'ɵɵdefineComponent' || name === 'ɵɵdefineComponent2') components++;
      if (name === 'ɵɵdefineInjectable') services++;
      if (name === 'ɵɵdefinePipe') pipes++;
      if (name === 'ɵɵdefineDirective') directives++;
    },
  });

  return { components, services, pipes, directives };
}

function countVueComponents(ast) {
  let vueComponents = 0, vueAppCalls = 0;

  walkAST(ast, {
    CallExpression(node) {
      const callee = node.callee;
      if (!callee) return;
      const name = callee.type === 'MemberExpression'
        ? (callee.property && callee.property.name)
        : (callee.name || '');
      if (name === 'createElementVNode' || name === 'openBlock') vueComponents++;
      if (name === 'createApp' || name === 'defineComponent') vueAppCalls++;
    },
    PropertyDefinition(node) {
      const key = node.key;
      if (!key) return;
      const name = typeof key === 'string' ? key : (key.name || key.value || '');
      if (name === '__vccOpts') vueComponents++;
    },
  });

  return { components: Math.max(vueComponents, vueAppCalls), appCalls: vueAppCalls };
}

function countReactComponents(ast) {
  let components = 0;

  walkAST(ast, {
    CallExpression(node) {
      const callee = node.callee;
      if (!callee) return;
      const name = callee.type === 'MemberExpression'
        ? (callee.property && callee.property.name)
        : (callee.name || '');
      if (name === 'createElement' || name === 'createElementWithValidation') components++;
      if (name === 'jsx' || name === 'jsxs' || name === 'jsxDEV') components++;
    },
  });

  return { components };
}

function countSvelteComponents(ast) {
  let components = 0;

  walkAST(ast, {
    CallExpression(node) {
      const callee = node.callee;
      if (!callee) return;
      const name = callee.type === 'MemberExpression'
        ? (callee.property && callee.property.name)
        : (callee.name || '');
      if (name === 'create_fragment') components++;
    },
  });

  // Also count SvelteComponent class references
  return { components };
}

// ── Count generic code metrics ──────────────────────────────────────────────
function countCodeMetrics(ast, src) {
  let functions = 0, classes = 0, arrowFunctions = 0;

  walkAST(ast, {
    FunctionDeclaration() { functions++; },
    ArrowFunctionExpression() { arrowFunctions++; },
    ClassDeclaration() { classes++; },
  });

  // Cyclomatic complexity
  let decisions = 0;
  walkAST(ast, {
    IfStatement() { decisions++; },
    ConditionalExpression() { decisions++; },
    LogicalExpression() { decisions++; },
    ForStatement() { decisions++; },
    WhileStatement() { decisions++; },
    SwitchCase() { decisions++; },
    CatchClause() { decisions++; },
  });

  return {
    functions: functions + arrowFunctions,
    classes,
    arrowFunctions,
    cyclomatic: decisions + 1,
  };
}

// ── Main analysis entry point ──────────────────────────────────────────────
function analyseWithAST(src) {
  const tokens = tokenize(src);
  const parser = new Parser(tokens);
  let ast;
  try {
    ast = parser.parseProgram();
  } catch (e) {
    // Fallback to regex-based analysis if AST parsing fails
    return null;
  }

  const angular = countAngularComponents(ast);
  const vue = countVueComponents(ast);
  const react = countReactComponents(ast);
  const svelte = countSvelteComponents(ast);
  const metrics = countCodeMetrics(ast, src);

  return {
    angular,
    vue,
    react,
    svelte,
    metrics,
    ast, // pass through for downstream modules
    success: true,
  };
}

module.exports = {
  tokenize,
  Parser,
  walkAST,
  analyseWithAST,
  countAngularComponents,
  countVueComponents,
  countReactComponents,
  countSvelteComponents,
  countCodeMetrics,
};
