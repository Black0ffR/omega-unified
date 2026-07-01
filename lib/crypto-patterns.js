'use strict';

/**
 * OMEGA v5 — Modernized Crypto Patterns
 * Item 6: Replace 2018-era btoa-reverse patterns with modern crypto detection.
 *
 * New patterns:
 *  - JWT eyJ... strings in source (decoded payload = instant finding)
 *  - WebCrypto subtle.importKey with 'raw' or 'jwk' and exported key material
 *  - Hardcoded bearer tokens in fetch headers
 *  - crypto.createHash('md5'|'sha1') in Node-flavored code
 *  - bcrypt.compare with hardcoded hash literals
 *  - Hardcoded AES keys / IVs
 *  - JWT verification with 'none' algorithm
 *  - Weak PRNG in token generation (Math.random for security tokens)
 */

const MODERN_CRYPTO_PATTERNS = [
  // ── JWT tokens in source ────────────────────────────────────────────────
  {
    id: 'crypto-jwt-in-source',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /["'](eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/g,
    ctx: null,
    desc: 'JWT token hardcoded in source — extract and decode payload',
  },
  {
    id: 'crypto-jwt-partial',
    cat: 'Broken Crypto',
    sev: 'high',
    re: /["'](eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})["']/g,
    ctx: null,
    desc: 'Partial JWT-like token in source',
  },

  // ── WebCrypto subtle operations ──────────────────────────────────────────
  {
    id: 'crypto-subtle-import-raw',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /crypto\.subtle\.importKey\s*\(\s*["']raw["']/g,
    ctx: m => !/test|spec|example/i.test(m),
    desc: 'WebCrypto importKey with raw format — key material may be exposed',
  },
  {
    id: 'crypto-subtle-export',
    cat: 'Broken Crypto',
    sev: 'high',
    re: /crypto\.subtle\.(exportKey|wrapKey)\s*\(/g,
    ctx: null,
    desc: 'WebCrypto key export — key material may be exfiltrated',
  },
  {
    id: 'crypto-subtle-no-catch',
    cat: 'Broken Crypto',
    sev: 'medium',
    re: /crypto\.subtle\.(encrypt|decrypt|sign|verify|digest)\s*\(/g,
    ctx: m => !/\.catch\s*\(|try\s*\{/.test(m.slice(0, 300)),
    desc: 'WebCrypto operation without error handling — failures silently ignored',
  },

  // ── Hardcoded bearer tokens in HTTP headers ─────────────────────────────
  {
    id: 'crypto-bearer-token',
    cat: 'Hardcoded Credential',
    sev: 'critical',
    re: /["']Bearer\s+([A-Za-z0-9\-_.]{20,})["']/g,
    ctx: m => !/example|test|placeholder/i.test(m),
    desc: 'Hardcoded Bearer token in source — immediate credential exposure',
  },
  {
    id: 'crypto-auth-header',
    cat: 'Hardcoded Credential',
    sev: 'high',
    re: /Authorization\s*:\s*["'](?:Bearer|Basic|Token)\s+([^"']+)["']/gi,
    ctx: null,
    desc: 'Hardcoded Authorization header with credential',
  },

  // ── Node.js crypto misuse ───────────────────────────────────────────────
  {
    id: 'crypto-node-md5',
    cat: 'Broken Crypto',
    sev: 'high',
    re: /crypto\.create(?:Hash|Hmac)\s*\(\s*["'](?:md5|MD5|sha1|SHA1)["']/g,
    ctx: null,
    desc: 'Weak hash algorithm (MD5/SHA1) — use SHA-256 or higher',
  },
  {
    id: 'crypto-node-createcipher',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /crypto\.createCipher\s*\(/g,
    ctx: null,
    desc: 'crypto.createCipher is deprecated — use createCipheriv with random IV',
  },

  // ── bcrypt misuse ────────────────────────────────────────────────────────
  {
    id: 'crypto-bcrypt-hash',
    cat: 'Broken Crypto',
    sev: 'medium',
    re: /bcrypt\.compare\s*\([^,]+,\s*["']\$2[ab]?\$\d{2}\$[^"']+["']/g,
    ctx: null,
    desc: 'Hardcoded bcrypt hash in source — could be test credential',
  },

  // ── JWT verification bypass ──────────────────────────────────────────────
  {
    id: 'crypto-jwt-none',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /(?:jwt\.verify|jsonwebtoken\.verify)\s*\([^,]+,\s*["']none["']/gi,
    ctx: null,
    desc: 'JWT verification with "none" algorithm — signature bypass',
  },
  {
    id: 'crypto-jwt-no-secret',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /jwt\.(?:sign|verify)\s*\([^,]+,\s*["']\s*["']/g,
    ctx: null,
    desc: 'JWT operation with empty secret — trivially forgeable',
  },

  // ── Weak PRNG for security tokens ───────────────────────────────────────
  {
    id: 'crypto-math-random-token',
    cat: 'Broken Crypto',
    sev: 'high',
    re: /(?:Math\.random|Math\.floor\s*\(\s*Math\.random\s*\*)\s*[^;]{0,100}(?:token|secret|key|nonce|csrf|session|password)/gi,
    ctx: null,
    desc: 'Weak Math.random used for security-sensitive value — use crypto.getRandomValues',
  },
  {
    id: 'crypto-date-token',
    cat: 'Broken Crypto',
    sev: 'high',
    re: /(?:Date\.now|new\s+Date\s*\([^)]*\)\.getTime)\s*[^;]{0,100}(?:token|secret|key|nonce|csrf|session|password)/gi,
    ctx: null,
    desc: 'Predictable Date-based value used for security token',
  },

  // ── Hardcoded AES keys / IVs ────────────────────────────────────────────
  {
    id: 'crypto-hardcoded-key',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /(?:aesKey|aes_key|AES_KEY|encryptionKey)\s*[:=]\s*["'][0-9a-fA-F]{32,}["']/g,
    ctx: null,
    desc: 'Hardcoded AES key in source — should be derived or stored securely',
  },
  {
    id: 'crypto-hardcoded-iv',
    cat: 'Broken Crypto',
    sev: 'high',
    re: /(?:iv|initializationVector|nonce)\s*[:=]\s*["'][0-9a-fA-F]{16,}["']/gi,
    ctx: m => !/example|placeholder/i.test(m),
    desc: 'Hardcoded initialization vector — defeats CBC/GCM security',
  },

  // ── ECB mode ─────────────────────────────────────────────────────────────
  {
    id: 'crypto-ecb-mode',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /(?:AES-ECB|CryptoJS\.mode\.ECB|aes-128-ecb|aes-256-ecb)/gi,
    ctx: null,
    desc: 'ECB encryption mode — identical plaintext blocks produce identical ciphertext',
  },

  // ── Insecure random values ──────────────────────────────────────────────
  {
    id: 'crypto-insecure-random',
    cat: 'Broken Crypto',
    sev: 'medium',
    re: /\b(Math\.random\s*\(\s*\)|[^c]random\s*\(\s*\))\s*[*x×]\s*\d+/g,
    ctx: m => /token|code|otp|pin|key|secret|nonce/i.test(m),
    desc: 'Insecure random number generation for security-sensitive value',
  },

  // ── Hardcoded 32-byte hex (likely private key) ──────────────────────────
  {
    id: 'crypto-hex-secret-key',
    cat: 'Broken Crypto',
    sev: 'critical',
    re: /["']([0-9a-fA-F]{64})["']\s*(?:,|;|\s*\))/g,
    ctx: m => /secret|key|private|mnemonic|seed|passphrase/i.test(m),
    desc: '64-char hex string — likely a private key or seed phrase',
  },

  // ── Generic token/secret patterns ────────────────────────────────────────
  {
    id: 'crypto-token-in-source',
    cat: 'Credential Leakage',
    sev: 'high',
    re: /(?:api_token|api_key|secret_key|app_secret|access_token)\s*=\s*["'][A-Za-z0-9_\-]{16,}["']/gi,
    ctx: m => !/example|test|changeme|your_|placeholder/i.test(m),
    desc: 'Likely API token or secret key hardcoded in source',
  },
];

function scanModernCrypto(src) {
  const findings = [];

  for (const pat of MODERN_CRYPTO_PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(src)) !== null) {
      // Skip if context check fails
      if (pat.ctx) {
        const snippet = src.slice(Math.max(0, m.index - 100), m.index + 120);
        if (!pat.ctx(snippet)) continue;
      }
      findings.push({
        id: pat.id,
        category: pat.cat,
        severity: pat.sev,
        value: (m[1] || m[0]).slice(0, 80),
        context: src.slice(Math.max(0, m.index - 80), m.index + 100).replace(/\n/g, ' ').trim(),
        description: pat.desc,
        pos: m.index,
      });
    }
  }

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));

  return findings;
}

module.exports = {
  MODERN_CRYPTO_PATTERNS,
  scanModernCrypto,
};
