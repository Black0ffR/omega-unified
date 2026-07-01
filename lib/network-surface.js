'use strict';

/**
 * OMEGA v5 — Network Surface Extraction
 * Item 10: Extract every URL literal, host, port, protocol, and cluster by domain.
 *
 * Outputs:
 *  - All HTTP/HTTPS URLs with paths
 *  - WebSocket endpoints (ws://, wss://)
 *  - Hostnames and IPs
 *  - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
 *  - Internal/private IPs (RFC1918)
 *  - GraphQL endpoints
 *  - API base URLs
 */

const C = { reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m' };

// Pattern collection for URL extraction
const NETWORK_PATTERNS = {
  // Full HTTP/HTTPS URLs
  httpUrl: /https?:\/\/[a-zA-Z0-9._\-:~]+(?::\d{2,5})?(?:\/[^\s"'<>{}|\\^`[\]]*)?/g,

  // WebSocket URLs
  wsUrl: /wss?:\/\/[a-zA-Z0-9._\-~]+(?::\d{2,5})?(?:\/[^\s"'<>{}|\\^`[\]]*)?/g,

  // GraphQL endpoints
  graphql: /\/graphql|\/api\/graphql|\/gql|\/query/g,

  // API path patterns (REST)
  apiPath: /["'`](\/(?:api|rest|v\d+|service|backend)\/[a-zA-Z0-9_\-/.{}[\]$]+(?:\.(?:json|xml|html))?)["'`]/g,

  // Hostnames from string literals (likely API hosts)
  hostname: /["'`]([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)(?::\d{2,5})?["'`]/g,

  // IP addresses
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,

  // Cloud metadata endpoints
  cloudMetadata: /(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.amazonaws\.com|169\.254\.170\.\d+)/g,

  // Internal hostnames (common patterns)
  internalHost: /(?:localhost|local|dev|staging|internal|intranet|corp|private)(?:\.[a-zA-Z.]+)?\b/gi,
};

const PRIVATE_RANGES = [
  { prefix: '10.', label: 'Class A private' },
  { prefix: '172.16.', label: 'Class B private' },
  { prefix: '172.17.', label: 'Class B private' },
  { prefix: '172.18.', label: 'Class B private' },
  { prefix: '172.19.', label: 'Class B private' },
  { prefix: '172.20.', label: 'Class B private' },
  { prefix: '172.21.', label: 'Class B private' },
  { prefix: '172.22.', label: 'Class B private' },
  { prefix: '172.23.', label: 'Class B private' },
  { prefix: '172.24.', label: 'Class B private' },
  { prefix: '172.25.', label: 'Class B private' },
  { prefix: '172.26.', label: 'Class B private' },
  { prefix: '172.27.', label: 'Class B private' },
  { prefix: '172.28.', label: 'Class B private' },
  { prefix: '172.29.', label: 'Class B private' },
  { prefix: '172.30.', label: 'Class B private' },
  { prefix: '172.31.', label: 'Class B private' },
  { prefix: '192.168.', label: 'Class C private' },
  { prefix: '127.', label: 'Loopback' },
  { prefix: '0.', label: 'Current network' },
];

function isPrivateIP(ip) {
  for (const range of PRIVATE_RANGES) {
    if (ip.startsWith(range.prefix)) return range.label;
  }
  return null;
}

function extractNetworkSurface(src, opts) {
  const findings = [];

  // Collect unique entries with context
  const seen = new Set();
  function addFinding(id, cat, sev, value, ctxWindow) {
    const key = `${id}::${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    const ctx = src.slice(Math.max(0, ctxWindow - 80), ctxWindow + 100).replace(/\n/g, ' ').trim();
    findings.push({ id, category: cat, severity: sev, value: value.slice(0, 120), context: ctx });
  }

  // HTTP URLs
  let m;
  NETWORK_PATTERNS.httpUrl.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.httpUrl.exec(src)) !== null) {
    const url = m[0];
    try {
      const u = new URL(url);
      const host = u.hostname;
      const path = u.pathname;

      // Skip common CDN / library URLs
      if (/cdn\.jsdelivr|cdnjs\.cloudflare|unpkg|googleapis|gstatic|facebook|twitter/.test(host)) {
        addFinding('net-cdn-url', 'Network Surface', 'info', url, m.index);
        continue;
      }

      // Check for internal/private hosts
      if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0') {
        addFinding('net-internal-url', 'Network Surface', 'high', url, m.index);
      } else {
        addFinding('net-http-url', 'Network Surface', 'info', url, m.index);
      }

      // Cloud metadata check
      if (NETWORK_PATTERNS.cloudMetadata.test(host + path)) {
        addFinding('net-cloud-meta', 'Network Surface', 'critical', url, m.index);
      }
    } catch (e) {
      addFinding('net-malformed-url', 'Network Surface', 'low', url, m.index);
    }
  }

  // WebSocket URLs
  NETWORK_PATTERNS.wsUrl.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.wsUrl.exec(src)) !== null) {
    addFinding('net-ws-url', 'Network Surface', 'medium', m[0], m.index);
  }

  // GraphQL endpoints
  NETWORK_PATTERNS.graphql.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.graphql.exec(src)) !== null) {
    addFinding('net-graphql', 'Network Surface', 'medium', m[0], m.index);
  }

  // API paths
  NETWORK_PATTERNS.apiPath.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.apiPath.exec(src)) !== null) {
    addFinding('net-api-path', 'Network Surface', 'info', m[1], m.index);
  }

  // Hostnames
  NETWORK_PATTERNS.hostname.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.hostname.exec(src)) !== null) {
    const host = m[1].toLowerCase();
    // Skip common domains
    if (/^(example|test|localhost|\.local|\.test)$/.test(host) ||
        /accounts\.google|cdnjs\.cloudflare|openstreetmap/.test(host)) continue;
    addFinding('net-hostname', 'Network Surface', 'low', host, m.index);
  }

  // IP addresses — check for private/internal
  NETWORK_PATTERNS.ipv4.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.ipv4.exec(src)) !== null) {
    const ip = m[0];
    const privateLabel = isPrivateIP(ip);
    if (privateLabel) {
      addFinding('net-internal-ip', 'Network Surface', 'high', `${ip} (${privateLabel})`, m.index);
    } else {
      addFinding('net-external-ip', 'Network Surface', 'low', ip, m.index);
    }
  }

  // Cloud metadata endpoints specifically
  NETWORK_PATTERNS.cloudMetadata.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.cloudMetadata.exec(src)) !== null) {
    addFinding('net-cloud-meta-ip', 'Network Surface', 'critical', m[0], m.index);
  }

  // Internal hostnames
  NETWORK_PATTERNS.internalHost.lastIndex = 0;
  while ((m = NETWORK_PATTERNS.internalHost.exec(src)) !== null) {
    const host = m[0].toLowerCase();
    if (host === 'localhost') continue; // already handled
    addFinding('net-internal-host', 'Network Surface', 'medium', host, m.index);
  }

  return {
    findings,
    count: findings.length,
    bySeverity: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
    },
  };
}

module.exports = {
  NETWORK_PATTERNS,
  extractNetworkSurface,
};
