'use strict';

/**
 * OMEGA v5 — Sourcemap-Aware Decoder
 * Item 7: Parse .map files, reverse-apply mappings to variable names.
 *
 * When a sourcemap is found adjacent to the bundle, load it and apply
 * the reverse mappings to recover original names, positions, and structure.
 *
 * Three strategies:
 *  1. Adjacent .map file (same basename + .map)
 *  2. Inline sourceMappingURL comment
 *  3. X-SourceMap HTTP header (not applicable for file-based analysis)
 */

const fs = require('fs');
const path = require('path');

// ── Find and load sourcemap ────────────────────────────────────────────────
function findSourcemap(inputPath, src) {
  // Strategy 1: Adjacent .map file
  const mapPath = inputPath + '.map';
  if (fs.existsSync(mapPath)) {
    try {
      const map = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
      return { map, source: 'adjacent-file' };
    } catch (e) {
      // Fall through
    }
  }

  // Strategy 2: sourceMappingURL comment (last line)
  const lines = src.split('\n');
  const lastLine = lines[lines.length - 1].trim();
  const smMatch = lastLine.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(.+)$/);
  if (smMatch) {
    const url = smMatch[1].trim();
    // Check if it's a data URI
    if (url.startsWith('data:application/json;base64,')) {
      const base64 = url.split(',')[1];
      try {
        const map = JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
        return { map, source: 'inline-base64' };
      } catch (e) {}
    }
    // Check if it's a relative path
    const dir = path.dirname(inputPath);
    const relativeMapPath = path.resolve(dir, url);
    if (fs.existsSync(relativeMapPath)) {
      try {
        const map = JSON.parse(fs.readFileSync(relativeMapPath, 'utf8'));
        return { map, source: 'relative-file' };
      } catch (e) {}
    }
  }

  return null;
}

// ── VLQ decoder ────────────────────────────────────────────────────────────
// Decode a single VLQ segment
const VLQ_BASE = 32;
const VLQ_BASE_SHIFT = 5;
const VLQ_BASE_MASK = 31;
const VLQ_CONTINUATION_BIT = 32;

function decodeVLQ(encoded) {
  const values = [];
  let i = 0;

  while (i < encoded.length) {
    let result = 0;
    let shift = 0;
    let continuation;

    do {
      const char = encoded.charCodeAt(i);
      if (char >= 127) break; // Skip non-ASCII
      const digit = char - 33; // VLQ uses '!' + base64
      if (digit < 0 || digit > 127) break;
      continuation = digit & VLQ_CONTINUATION_BIT;
      result += (digit & VLQ_BASE_MASK) << shift;
      shift += VLQ_BASE_SHIFT;
      i++;
    } while (continuation);

    // Sign handling
    if (result & 1) {
      result = -(result >> 1);
    } else {
      result = result >> 1;
    }
    values.push(result);
  }

  return values;
}

// ── Apply sourcemap to minified source ─────────────────────────────────────
function applySourcemap(src, map) {
  if (!map || !map.mappings) {
    return { success: false, reason: 'No valid mappings in sourcemap' };
  }

  const { sources = [], sourcesContent = [], names = [], mappings } = map;

  // Build a map of generated line → original mappings
  const mappingLines = [];
  const encodedLines = mappings.split(';');

  let sourceIndex = 0;
  let originalLine = 0;
  let originalCol = 0;
  let nameIndex = 0;

  for (let genLine = 0; genLine < encodedLines.length; genLine++) {
    const segments = encodedLines[genLine];
    if (!segments) {
      mappingLines[genLine] = [];
      continue;
    }

    const decodedSegs = decodeVLQ(segments);
    const decoded = [];
    for (let i = 0; i < decodedSegs.length; i += 5) {
      if (i + 4 < decodedSegs.length) {
        const generatedColumn = decodedSegs[i];
        const srcIdx = decodedSegs[i + 1];
        const origLine = decodedSegs[i + 2];
        const origColumn = decodedSegs[i + 3];
        const nameIdx = decodedSegs[i + 4];
        decoded.push({
          generatedColumn,
          sourceIndex: srcIdx,
          originalLine: origLine,
          originalColumn: origColumn,
          nameIndex: nameIdx,
        });
      }
    }
    mappingLines[genLine] = decoded;
  }

  // Apply name mappings: wherever a mapping has a nameIndex, replace
  // the generated token with the original name.
  const srcLines = src.split('\n');
  const resultLines = srcLines.slice();

  // Process in reverse to avoid position shifts
  const replacements = [];

  for (let genLine = 0; genLine < mappingLines.length && genLine < srcLines.length; genLine++) {
    const segments = mappingLines[genLine];
    const line = srcLines[genLine];

    for (const seg of segments) {
      if (seg.nameIndex >= 0 && seg.nameIndex < names.length) {
        const originalName = names[seg.nameIndex];
        const genCol = seg.generatedColumn;

        // Extract the token at this position
        let tokenStart = genCol;
        while (tokenStart > 0 && /[a-zA-Z0-9_$]/.test(line[tokenStart - 1])) tokenStart--;
        let tokenEnd = genCol;
        while (tokenEnd < line.length && /[a-zA-Z0-9_$]/.test(line[tokenEnd])) tokenEnd++;

        const token = line.slice(tokenStart, tokenEnd);
        if (token && token !== originalName && token.length > 1) {
          replacements.push({
            line: genLine,
            from: tokenStart,
            to: tokenEnd,
            originalName,
            generatedName: token,
          });
        }
      }
    }
  }

  // Apply replacements (reverse order)
  replacements.sort((a, b) => b.line - a.line || b.from - a.from);
  for (const r of replacements) {
    const line = resultLines[r.line];
    resultLines[r.line] = line.slice(0, r.from) + r.originalName + line.slice(r.to);
  }

  return {
    success: true,
    source: resultLines.join('\n'),
    replacements,
    count: replacements.length,
    sources,
    sourcesContent,
  };
}

// ── Recover original sources from sourcemap ────────────────────────────────
function recoverSources(map) {
  if (!map || !map.sources) return [];

  const { sources = [], sourcesContent = [] } = map;
  const result = [];

  for (let i = 0; i < sources.length; i++) {
    if (sourcesContent[i] !== undefined) {
      result.push({
        filename: sources[i],
        content: sourcesContent[i],
      });
    }
  }

  return result;
}

// ── Main entry point ───────────────────────────────────────────────────────
function decodeWithSourcemap(inputPath, src, opts) {
  const t0 = Date.now();

  const found = findSourcemap(inputPath, src);
  if (!found) {
    return { found: false, elapsed: Date.now() - t0 };
  }

  const { map, source } = found;
  const applied = applySourcemap(src, map);
  const recovered = recoverSources(map);

  if (opts.verbose) {
    console.log(`  Sourcemap found via ${source}`);
    console.log(`  Name replacements: ${applied.count}`);
    console.log(`  Original sources recovered: ${recovered.length}`);
  }

  return {
    found: true,
    source: source,
    ...applied,
    recovered,
    map,
    elapsed: Date.now() - t0,
  };
}

module.exports = {
  findSourcemap,
  decodeVLQ,
  applySourcemap,
  recoverSources,
  decodeWithSourcemap,
};
