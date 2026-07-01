'use strict';

/**
 * OMEGA v5 — WASM Module Detection + Strings Extraction
 * Item 15: Detect inline WebAssembly binaries, decode base64, extract data sections as strings.
 */

const C = { reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m', green:'\x1c[32m', cyan:'\x1c[36m' };

// Pattern: Uint8Array.from(atob("...")) or Uint8Array([...]) near WebAssembly.compile
const WASM_BASE64_RE = /WebAssembly\.(?:instantiate|compile|instantiateStreaming)\s*\([^)]*Uint8Array\.from\s*\(\s*(?:atob|Buffer\.from)\s*\(\s*["']([A-Za-z0-9+/=]{100,})["']/g;

// Pattern: WebAssembly.compile(new Uint8Array([...byte array...]))
const WASM_BYTE_RE = /WebAssembly\.compile\s*\(\s*new\s+Uint8Array\s*\(\s*\[([\d,\s,a-fA-Fx]+)\]\)/g;

// Pattern: WebAssembly instantiateStreaming(fetch("..."))
const WASM_FETCH_RE = /WebAssembly\.instantiateStreaming\s*\(\s*fetch\s*\(\s*["']([^"']+)["']/g;

// WASM magic bytes
const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d]; // \0asm

// Known WASM section IDs
const WASM_SECTIONS = {
  0: 'custom',
  1: 'type',
  2: 'import',
  3: 'function',
  4: 'table',
  5: 'memory',
  6: 'global',
  7: 'export',
  8: 'start',
  9: 'element',
  10: 'code',
  11: 'data',
  12: 'data count',
};

class WASMNameSectionReader {
  constructor(buffer) {
    this.buffer = buffer;
    this.pos = 8; // skip magic + version
    this.names = {};
  }

  readULEB128() {
    let result = 0;
    let shift = 0;
    while (this.pos < this.buffer.length) {
      const byte = this.buffer[this.pos++];
      result |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }
    return result;
  }

  readByte() { return this.buffer[this.pos++]; }

  readString() {
    const len = this.readULEB128();
    const str = Buffer.from(this.buffer.slice(this.pos, this.pos + len)).toString('utf8');
    this.pos += len;
    return str;
  }

  parse() {
    while (this.pos < this.buffer.length) {
      const sectionId = this.readByte();
      const sectionSize = this.readULEB128();
      const sectionEnd = this.pos + sectionSize;

      if (sectionId === 0) {
        // Custom section — may contain name section
        const name = this.readString();
        if (name === 'name') {
          // Parse name section subsections
          while (this.pos < sectionEnd) {
            const subsectionId = this.readByte();
            const subsectionSize = this.readULEB128();
            const subEnd = this.pos + subsectionSize;
            if (subsectionId === 0) {
              // Module name
              this.names.module = this.readString();
            } else if (subsectionId === 1) {
              // Function names
              const count = this.readULEB128();
              for (let i = 0; i < count && this.pos < subEnd; i++) {
                const idx = this.readULEB128();
                this.names[`func_${idx}`] = this.readString();
              }
            } else if (subsectionId === 2) {
              // Local names
              this.pos = subEnd;
            }
          }
        }
      }
      this.pos = sectionEnd;
    }
    return this.names;
  }
}

function extractWASMStrings(wasmBuffer) {
  const strings = [];
  const textDecoder = new (require('util').TextDecoder)('utf8');
  const view = Buffer.from(wasmBuffer);

  // Check magic bytes
  if (view.length < 4 || view[0] !== 0x00 || view[1] !== 0x61 || view[2] !== 0x73 || view[3] !== 0x6d) {
    return strings;
  }

  // Extract strings from data sections by scanning for printable strings
  let current = '';
  for (let i = 0; i < view.length; i++) {
    const byte = view[i];
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 4) strings.push(current);
      current = '';
    }
  }
  if (current.length >= 4) strings.push(current);

  // Try to read name section for function/export names
  try {
    const reader = new WASMNameSectionReader(view);
    const names = reader.parse();
    for (const [key, val] of Object.entries(names)) {
      if (typeof val === 'string' && val.length > 2) {
        strings.push(`[name:${key}] ${val}`);
      }
    }
  } catch (e) {
    // Name section parsing failed — not critical
  }

  // Deduplicate
  return [...new Set(strings)];
}

function detectWASM(src, opts) {
  const findings = [];

  // Pattern 1: base64-encoded WASM binary
  let m;
  WASM_BASE64_RE.lastIndex = 0;
  while ((m = WASM_BASE64_RE.exec(src)) !== null) {
    try {
      const binary = Buffer.from(m[1], 'base64');
      if (binary.length > 4 && binary[0] === 0x00 && binary[1] === 0x61 && binary[2] === 0x73 && binary[3] === 0x6d) {
        const wasmStrings = extractWASMStrings(binary);
        findings.push({
          id: 'wasm-base64',
          category: 'WebAssembly',
          severity: 'medium',
          value: `WASM binary (${binary.length} bytes) via base64`,
          stringsFound: wasmStrings,
          stringCount: wasmStrings.length,
          context: src.slice(Math.max(0, m.index - 60), m.index + 80).replace(/\n/g, ' ').trim(),
          description: `Inline WebAssembly module — ${wasmStrings.length} string(s) extracted`,
        });
      }
    } catch (e) { /* skip malformed */ }
  }

  // Pattern 2: WASM via byte array
  WASM_BYTE_RE.lastIndex = 0;
  while ((m = WASM_BYTE_RE.exec(src)) !== null) {
    try {
      const bytes = m[1].split(',').map(x => { const t = x.trim(); return t.startsWith('0x') || t.startsWith('0X') ? parseInt(t, 16) : parseInt(t, 10); }).filter(n => !isNaN(n) && n >= 0 && n <= 255);
      if (bytes.length >= 4 && bytes[0] === 0x00 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) {
        const binary = Buffer.from(bytes);
        const wasmStrings = extractWASMStrings(binary);
        findings.push({
          id: 'wasm-bytearray',
          category: 'WebAssembly',
          severity: 'medium',
          value: `WASM binary (${binary.length} bytes) via Uint8Array`,
          stringsFound: wasmStrings,
          stringCount: wasmStrings.length,
          context: src.slice(Math.max(0, m.index - 60), m.index + 80).replace(/\n/g, ' ').trim(),
          description: `Inline WebAssembly byte array — ${wasmStrings.length} string(s) extracted`,
        });
      }
    } catch (e) { /* skip */ }
  }

  // Pattern 3: WASM fetched from URL
  WASM_FETCH_RE.lastIndex = 0;
  while ((m = WASM_FETCH_RE.exec(src)) !== null) {
    findings.push({
      id: 'wasm-fetch',
      category: 'WebAssembly',
      severity: 'info',
      value: `WASM fetched from: ${m[1]}`,
      context: src.slice(Math.max(0, m.index - 60), m.index + 80).replace(/\n/g, ' ').trim(),
      description: 'WebAssembly loaded from external URL — binary not analyzed',
    });
  }

  // Run credential scanner on extracted WASM strings
  for (const f of findings) {
    if (f.stringsFound && f.stringsFound.length) {
      const allStrings = f.stringsFound.join('\n');
      // Check for URLs
      const urlRe = /https?:\/\/[^\s]+/g;
      let urlM;
      while ((urlM = urlRe.exec(allStrings)) !== null) {
        findings.push({
          id: 'wasm-url',
          category: 'WebAssembly',
          severity: 'high',
          value: `URL in WASM: ${urlM[0]}`,
          context: f.context,
          description: 'URL found within WASM binary data section',
        });
      }
      // Check for API keys / tokens
      const keyRe = /[A-Za-z0-9_\-]{20,}/g;
      while ((urlM = keyRe.exec(allStrings)) !== null) {
        if (/^[A-Za-z0-9_\-]{20,}$/.test(urlM[0]) && !urlM[0].startsWith('http')) {
          findings.push({
            id: 'wasm-secret',
            category: 'WebAssembly',
            severity: 'medium',
            value: `Potential secret in WASM: ${urlM[0].slice(0, 30)}...`,
            context: f.context,
            description: 'Potential API key or secret found in WASM binary',
          });
        }
      }
    }
  }

  return findings;
}

module.exports = {
  extractWASMStrings,
  detectWASM,
};
