'use strict';

/**
 * OMEGA v5 — SARIF 2.1.0 Output
 * Item 12: Emit SARIF 2.1.0 for CI/IDE integration (GitHub Code Scanning, GitLab).
 */

const path = require('path');

function findingsToSARIF(allFindings, meta, rules) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/opencsam/develop/sarif-ifr/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'JS Decoder OMEGA',
          version: meta.version || 'OMEGA-5.0',
          informationUri: 'https://github.com/your-repo/js-decoder-omega',
          rules: [],
        },
      },
      results: [],
      invocations: [{
        startTimeUtc: meta.date || new Date().toISOString(),
        endTimeUtc: new Date().toISOString(),
      }],
      artifacts: [{
        location: { uri: meta.file || 'input.js' },
        contents: { sourceLanguage: 'javascript' },
      }],
    }],
  };

  const ruleIds = new Set();
  const ruleMap = {};

  for (const f of allFindings) {
    const ruleId = f.id || f.name || 'unknown';
    if (!ruleIds.has(ruleId)) {
      ruleIds.add(ruleId);
      const rule = {
        id: ruleId,
        name: f.name || f.category || ruleId,
        fullDescription: { text: f.description || 'No description' },
        defaultConfiguration: { level: severityToSARIFLevel(f.severity || f.sev || 'info') },
        properties: { category: f.category || 'Security' },
      };
      if (f.cwe) {
        rule.relationships = [{
          target: { id: f.cwe, guid: `https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html` },
          kinds: ['relevant'],
        }];
      }
      sarif.runs[0].tool.driver.rules.push(rule);
      ruleMap[ruleId] = rule;
    }

    const result = {
      ruleId,
      ruleIndex: sarif.runs[0].tool.driver.rules.length - 1,
      message: { text: `${f.name || f.category || ''}: ${(f.value || '').slice(0, 200)}` },
      level: severityToSARIFLevel(f.severity || f.sev || 'info'),
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: meta.file || 'input.js' },
          region: f.line ? {
            startLine: f.line,
            snippet: { text: (f.context || '').slice(0, 100) },
          } : undefined,
        },
      }],
    };

    if (f.cwe) {
      result.relatedLocations = [{
        id: 0,
        message: { text: `CWE: ${f.cwe}` },
      }];
    }

    sarif.runs[0].results.push(result);
  }

  return JSON.stringify(sarif, null, 2);
}

function severityToSARIFLevel(severity) {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    case 'info': return 'note';
    default: return 'warning';
  }
}

function writeSARIF(allFindings, meta, outDir) {
  const sarifContent = findingsToSARIF(allFindings, meta);
  const fs = require('fs');
  const sarifPath = path.join(outDir, 'report.sarif');
  fs.writeFileSync(sarifPath, sarifContent);
  return sarifPath;
}

module.exports = {
  findingsToSARIF,
  writeSARIF,
};
