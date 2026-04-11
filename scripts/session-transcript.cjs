#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const PROJECT_DIR = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const SESSIONS_DIR = path.join(PROJECT_DIR, '.nomark', 'sessions');
const BACKFILL_DIR = path.join(SESSIONS_DIR, 'backfill');
const INDEX_PATH = path.join(SESSIONS_DIR, 'INDEX.md');
const SCHEMA_PATH = path.join(PROJECT_DIR, '.nomark', 'schemas', 'session-transcript.schema.json');

const LINE_TYPES = ['session-meta', 'exchange', 'tool-result', 'session-summary'];
const SCOPES = ['brainstorm', 'architecture', 'debugging', 'design', 'review', 'general'];
const ROLES = ['user', 'agent', 'tool'];

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadSchema() {
  return JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
}

function validateLine(line) {
  const errors = [];
  if (!line || typeof line !== 'object') return ['line must be an object'];

  if (line.type === 'session-meta') {
    if (!line.id) errors.push('session-meta: missing id');
    if (!line.date) errors.push('session-meta: missing date');
    if (line.scope && !SCOPES.includes(line.scope)) errors.push(`session-meta: invalid scope "${line.scope}"`);
  } else if (line.type === 'session-summary') {
    if (line.decisions && !Array.isArray(line.decisions)) errors.push('session-summary: decisions must be array');
    if (line.rejected && !Array.isArray(line.rejected)) errors.push('session-summary: rejected must be array');
  } else if (line.role === 'tool') {
    if (!line.ts) errors.push('tool-result: missing ts');
    if (!line.tool) errors.push('tool-result: missing tool');
    if (!line.summary) errors.push('tool-result: missing summary');
  } else {
    if (!line.ts) errors.push('exchange: missing ts');
    if (!line.role || !['user', 'agent'].includes(line.role)) errors.push(`exchange: invalid role "${line.role}"`);
    if (!line.content) errors.push('exchange: missing content');
  }

  return errors;
}

function transcriptPath(date, sessionId) {
  return path.join(SESSIONS_DIR, `${date}-${sessionId}.jsonl`);
}

function appendLine(filePath, lineObj) {
  ensureDir(path.dirname(filePath));
  const errors = validateLine(lineObj);
  if (errors.length > 0) {
    process.stderr.write(`transcript validation: ${errors.join(', ')}\n`);
    return false;
  }
  fs.appendFileSync(filePath, JSON.stringify(lineObj) + '\n');
  return true;
}

function prependMeta(filePath, metaObj) {
  if (!fs.existsSync(filePath)) return false;
  const existing = fs.readFileSync(filePath, 'utf8');
  const metaLine = JSON.stringify({ type: 'session-meta', ...metaObj }) + '\n';
  fs.writeFileSync(filePath, metaLine + existing);
  return true;
}

function readTranscript(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n');
  return lines.map((line, i) => {
    try {
      return JSON.parse(line);
    } catch {
      process.stderr.write(`transcript parse error line ${i + 1}: ${line.slice(0, 80)}\n`);
      return null;
    }
  }).filter(Boolean);
}

function getMeta(filePath) {
  const lines = readTranscript(filePath);
  if (!lines || lines.length === 0) return null;
  return lines.find(l => l.type === 'session-meta') || null;
}

function getSummary(filePath) {
  const lines = readTranscript(filePath);
  if (!lines || lines.length === 0) return null;
  return lines.find(l => l.type === 'session-summary') || null;
}

function listTranscripts() {
  ensureDir(SESSIONS_DIR);
  return fs.readdirSync(SESSIONS_DIR)
    .filter(f => f.endsWith('.jsonl'))
    .sort()
    .reverse();
}

function searchTranscripts(query, filters = {}) {
  const files = listTranscripts();
  const results = [];
  const q = query.toLowerCase();

  for (const file of files) {
    const filePath = path.join(SESSIONS_DIR, file);
    const meta = getMeta(filePath);
    const summary = getSummary(filePath);

    if (filters.feature && meta && meta.features && !meta.features.some(f => f.toLowerCase().includes(filters.feature.toLowerCase()))) continue;
    if (filters.date && !file.startsWith(filters.date)) continue;

    let matched = false;
    if (meta) {
      if (meta.topics && meta.topics.some(t => t.toLowerCase().includes(q))) matched = true;
      if (meta.features && meta.features.some(f => f.toLowerCase().includes(q))) matched = true;
      if (meta.scope && meta.scope.toLowerCase().includes(q)) matched = true;
    }
    if (summary) {
      if (summary.decisions && summary.decisions.some(d => d.toLowerCase().includes(q))) matched = true;
      if (summary.rejected && summary.rejected.some(r => r.toLowerCase().includes(q))) matched = true;
      if (summary.artifacts_produced && summary.artifacts_produced.some(a => a.toLowerCase().includes(q))) matched = true;
    }

    if (!matched && query) {
      const content = fs.readFileSync(filePath, 'utf8');
      if (content.toLowerCase().includes(q)) matched = true;
    }

    if (matched || !query) {
      results.push({ file, meta, summary });
    }
  }

  return results;
}

function searchBackfills(query) {
  if (!fs.existsSync(BACKFILL_DIR)) return [];
  const files = fs.readdirSync(BACKFILL_DIR).filter(f => f.endsWith('.summary.json'));
  const q = query.toLowerCase();
  const results = [];

  for (const file of files) {
    const filePath = path.join(BACKFILL_DIR, file);
    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      let matched = false;
      if (data.topics && data.topics.some(t => t.toLowerCase().includes(q))) matched = true;
      if (data.features && data.features.some(f => f.toLowerCase().includes(q))) matched = true;
      if (data.decisions && data.decisions.some(d => d.toLowerCase().includes(q))) matched = true;
      if (matched || !query) results.push({ file, ...data, backfill: true });
    } catch { /* skip malformed */ }
  }

  return results;
}

function updateIndex() {
  ensureDir(SESSIONS_DIR);
  const transcripts = listTranscripts();
  const lines = ['# Session Transcript Index', ''];

  for (const file of transcripts) {
    const filePath = path.join(SESSIONS_DIR, file);
    const meta = getMeta(filePath);
    const id = meta ? meta.id : file.replace('.jsonl', '');
    const features = meta && meta.features ? meta.features.join(', ') : '';
    const scope = meta && meta.scope ? meta.scope : '';
    const topics = meta && meta.topics ? meta.topics.join(', ') : '';
    lines.push(`- [${id}](${file}) — ${features} ${scope}: ${topics}`);
  }

  if (fs.existsSync(BACKFILL_DIR)) {
    const backfills = fs.readdirSync(BACKFILL_DIR).filter(f => f.endsWith('.summary.json')).sort().reverse();
    for (const file of backfills) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(BACKFILL_DIR, file), 'utf8'));
        const id = data.id || file.replace('.summary.json', '');
        const features = data.features ? data.features.join(', ') : '';
        const scope = data.scope || '';
        const topics = data.topics ? data.topics.join(', ') : '';
        lines.push(`- [${id}](backfill/${file}) — [backfill] ${features} ${scope}: ${topics}`);
      } catch { /* skip */ }
    }
  }

  lines.push('');
  fs.writeFileSync(INDEX_PATH, lines.join('\n'));
  return INDEX_PATH;
}

module.exports = {
  PROJECT_DIR,
  SESSIONS_DIR,
  BACKFILL_DIR,
  INDEX_PATH,
  LINE_TYPES,
  SCOPES,
  ROLES,
  ensureDir,
  loadSchema,
  validateLine,
  transcriptPath,
  appendLine,
  prependMeta,
  readTranscript,
  getMeta,
  getSummary,
  listTranscripts,
  searchTranscripts,
  searchBackfills,
  updateIndex,
};

// CLI mode
if (require.main === module) {
  const cmd = process.argv[2];

  if (cmd === 'search') {
    const query = process.argv[3] || '';
    const results = [...searchTranscripts(query), ...searchBackfills(query)];
    console.log(JSON.stringify(results, null, 2));
  } else if (cmd === 'index') {
    const p = updateIndex();
    console.log(`Updated: ${p}`);
  } else if (cmd === 'list') {
    const files = listTranscripts();
    files.forEach(f => console.log(f));
  } else if (cmd === 'read') {
    const file = process.argv[3];
    if (!file) { console.error('Usage: session-transcript.cjs read <file>'); process.exit(1); }
    const filePath = path.join(SESSIONS_DIR, file);
    const lines = readTranscript(filePath);
    if (!lines) { console.error(`Not found: ${filePath}`); process.exit(1); }
    console.log(JSON.stringify(lines, null, 2));
  } else {
    console.log('Usage: session-transcript.cjs <search|index|list|read> [args]');
    console.log('  search <query>  — search transcripts by topic/feature/content');
    console.log('  index           — rebuild INDEX.md from transcript files');
    console.log('  list            — list all transcript files');
    console.log('  read <file>     — read and parse a transcript file');
  }
}
