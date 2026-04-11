#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();
const TRUST_DIR = path.join(ROOT, '.nomark', 'metrics', 'trust');
const EVENTS_DIR = path.join(TRUST_DIR, 'events');
const PREFS_DIR = path.join(TRUST_DIR, 'preferences');
const PREFS_PATH = path.join(PREFS_DIR, 'preferences.json');
const LEDGER_PATH = path.join(TRUST_DIR, 'ledger.jsonl');
const SCHEMA_PATH = path.join(ROOT, '.nomark', 'schemas', 'mee-event.schema.json');

const ENTRY_CAPS = { meta: 1, pref: 20, map: 10, asn: 5, rub: 4 };
const TOTAL_CAP = 40;

// --- Schema validation (lightweight, no external deps) ---

function loadSchema() {
  return JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
}

function validateEvent(event, schema) {
  const def = schema.definitions.archive_event;
  const errors = [];
  for (const field of def.required || []) {
    if (event[field] === undefined || event[field] === null) {
      errors.push(`missing required field: ${field}`);
    }
  }
  if (event.id && !/^sig-/.test(event.id)) {
    errors.push('id must start with "sig-"');
  }
  if (event.context && !['chat', 'cowork', 'code'].includes(event.context)) {
    errors.push(`invalid context: ${event.context}`);
  }
  if (event.outcome && !['accepted', 'edited', 'corrected', 'rejected', 'abandoned', 'unknown'].includes(event.outcome)) {
    errors.push(`invalid outcome: ${event.outcome}`);
  }
  if (event.input_tier !== undefined && (event.input_tier < 0 || event.input_tier > 2)) {
    errors.push(`input_tier must be 0-2, got: ${event.input_tier}`);
  }
  if (event.intent_confidence !== undefined && (event.intent_confidence < 0 || event.intent_confidence > 1)) {
    errors.push('intent_confidence must be 0-1');
  }
  return errors;
}

function validateLedgerEntry(type, data, schema) {
  const defName = `sig_${type}`;
  const def = schema.definitions[defName];
  if (!def) return [`unknown ledger entry type: ${type}`];
  const errors = [];
  for (const field of def.required || []) {
    if (data[field] === undefined || data[field] === null) {
      errors.push(`[sig:${type}] missing required field: ${field}`);
    }
  }
  return errors;
}

// --- Decay computation (Section 8) ---

function computeDecay(lastDate, contradictions, recentContradictions, recentReinforcement) {
  const now = new Date();
  const last = new Date(lastDate);
  const daysSinceLast = Math.max(0, (now - last) / (1000 * 60 * 60 * 24));

  let decay = Math.max(0.1, Math.pow(0.98, daysSinceLast / 30));

  if (recentContradictions >= 2) {
    decay = Math.max(0.1, decay * 0.85);
  }

  if (recentReinforcement) {
    decay = Math.min(1.0, decay * 1.1);
  }

  return Math.round(decay * 1000) / 1000;
}

function effectiveWeight(w, decay) {
  return Math.round(w * decay * 1000) / 1000;
}

// --- Utility score (Section 7.3) ---

function utilityScore(entry) {
  const now = new Date();
  const last = new Date(entry.last);
  const daysSinceLast = Math.max(0, (now - last) / (1000 * 60 * 60 * 24));

  const frequency = Math.min(1.0, (entry._uses_30d || 0) / 10);
  const impact = entry._impact || 0.5;
  const recency = Math.max(0, 1.0 - daysSinceLast / 180);
  const n = entry.n || entry.total || 0;
  const ctd = entry.ctd || 0;

  let portability = 0;
  if (entry.src) {
    portability = Object.keys(entry.src).filter(k => entry.src[k] > 0).length / 3;
  }

  const stability = n > 0 ? 1.0 - (ctd / n) : 0.5;

  return (frequency * 0.25) + (impact * 0.25) + (recency * 0.20) + (portability * 0.15) + (stability * 0.15);
}

// --- Cold-start (Section 15.1) ---

function coldStartMeta() {
  const today = new Date().toISOString().slice(0, 10);
  return {
    profile: {},
    signals: 0,
    by_ctx: { chat: 0, code: 0, cowork: 0 },
    by_out: { accepted: 0, edited: 0, corrected: 0, rejected: 0, abandoned: 0 },
    avg_conf: 0.5,
    avg_q: 1.5,
    updated: today
  };
}

// --- Ledger I/O ---

function parseLedgerLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;
  const match = trimmed.match(/^\[sig:(\w+)\]\s+(.+)$/);
  if (!match) return null;
  try {
    return { type: match[1], data: JSON.parse(match[2]), raw: trimmed };
  } catch {
    return null;
  }
}

function formatLedgerLine(type, data) {
  return `[sig:${type}] ${JSON.stringify(data)}`;
}

function readLedger() {
  if (!fs.existsSync(LEDGER_PATH)) return [];
  const lines = fs.readFileSync(LEDGER_PATH, 'utf8').split('\n');
  return lines.map(parseLedgerLine).filter(Boolean);
}

function writeLedger(entries) {
  const lines = entries.map(e => formatLedgerLine(e.type, e.data));
  fs.writeFileSync(LEDGER_PATH, lines.join('\n') + '\n');
}

// --- Events I/O ---

function eventFilePath(timestamp) {
  const date = timestamp.slice(0, 10);
  return path.join(EVENTS_DIR, `${date}.jsonl`);
}

function readAllEvents() {
  const events = [];
  if (!fs.existsSync(EVENTS_DIR)) return events;
  const files = fs.readdirSync(EVENTS_DIR).filter(f => f.endsWith('.jsonl')).sort();
  for (const file of files) {
    const lines = fs.readFileSync(path.join(EVENTS_DIR, file), 'utf8').split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        events.push(JSON.parse(line));
      } catch { /* skip malformed */ }
    }
  }
  return events;
}

// --- Subcommand: write ---

function cmdWrite(args) {
  const jsonStr = args.join(' ');
  if (!jsonStr) {
    console.error('Usage: mee-event.cjs write <json>');
    process.exit(1);
  }

  let event;
  try {
    event = JSON.parse(jsonStr);
  } catch (e) {
    console.error(`Invalid JSON: ${e.message}`);
    process.exit(1);
  }

  const schema = loadSchema();
  const errors = validateEvent(event, schema);
  if (errors.length > 0) {
    console.error(`Validation failed:\n  ${errors.join('\n  ')}`);
    process.exit(1);
  }

  const filePath = eventFilePath(event.timestamp);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, JSON.stringify(event) + '\n');
  console.log(JSON.stringify({ status: 'ok', file: path.basename(filePath), id: event.id }));
}

// --- Subcommand: cold-start ---

function cmdColdStart() {
  if (fs.existsSync(LEDGER_PATH)) {
    const content = fs.readFileSync(LEDGER_PATH, 'utf8').trim();
    if (content.length > 0) {
      console.log(JSON.stringify({ status: 'exists', message: 'Ledger already exists, skipping cold-start' }));
      return;
    }
  }

  const meta = coldStartMeta();
  const schema = loadSchema();
  const errors = validateLedgerEntry('meta', meta, schema);
  if (errors.length > 0) {
    console.error(`Cold-start meta validation failed:\n  ${errors.join('\n  ')}`);
    process.exit(1);
  }

  fs.mkdirSync(path.dirname(LEDGER_PATH), { recursive: true });
  fs.writeFileSync(LEDGER_PATH, formatLedgerLine('meta', meta) + '\n');
  console.log(JSON.stringify({ status: 'ok', message: 'Cold-start ledger created' }));
}

// --- Subcommand: aggregate ---

function cmdAggregate() {
  const events = readAllEvents();
  if (events.length === 0) {
    console.log(JSON.stringify({ status: 'ok', message: 'No events to aggregate', prefs: 0, asns: 0 }));
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  const now = new Date();
  const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);

  // Aggregate corrections into preference dimensions (global + scoped)
  const prefMap = new Map();
  const asnMap = new Map();
  // Track scoped corrections for auto-discovery
  const scopeTracker = new Map(); // "dim::context:xxx" or "dim::topic:xxx" → count

  function upsertPref(key, dim, target, scope) {
    if (!prefMap.has(key)) {
      prefMap.set(key, {
        dim, target, w: 0.5, n: 0,
        src: { chat: 0, code: 0, cowork: 0 },
        ctd: 0, scope, last: today,
        _recent_ctd: 0, _recent_reinforced: false
      });
    }
    return prefMap.get(key);
  }

  for (const event of events) {
    // Track preference updates from corrections
    if (event.preference_updates) {
      for (const update of event.preference_updates) {
        // Global entry
        const globalKey = `${update.dim}::*`;
        const pref = upsertPref(globalKey, update.dim, update.reason || update.dim, '*');
        pref.n++;
        if (event.context && pref.src[event.context] !== undefined) {
          pref.src[event.context]++;
        }
        if (update.delta < 0) {
          pref.ctd++;
          if (new Date(event.timestamp) >= thirtyDaysAgo) pref._recent_ctd++;
        }
        if (new Date(event.timestamp) >= new Date(now - 7 * 24 * 60 * 60 * 1000)) {
          pref._recent_reinforced = true;
        }
        pref.last = event.timestamp.slice(0, 10);
        pref.w = Math.min(1.0, 0.5 + (pref.n * 0.03));

        // Track scoped corrections for auto-discovery
        if (event.context) {
          const ctxKey = `${update.dim}::context:${event.context}`;
          scopeTracker.set(ctxKey, (scopeTracker.get(ctxKey) || 0) + 1);
        }
        if (event.request_type) {
          const typeKey = `${update.dim}::type:${event.request_type}`;
          scopeTracker.set(typeKey, (scopeTracker.get(typeKey) || 0) + 1);
        }
        // Compound: context + request_type
        if (event.context && event.request_type) {
          const compKey = `${update.dim}::context:${event.context}+type:${event.request_type}`;
          scopeTracker.set(compKey, (scopeTracker.get(compKey) || 0) + 1);
        }
      }
    }

    // Track assumption accuracy
    if (event.assumptions) {
      for (const asn of event.assumptions) {
        const key = `${asn.field}::${asn.value}`;
        if (!asnMap.has(key)) {
          asnMap.set(key, {
            field: asn.field,
            default: asn.value,
            total: 0,
            correct: 0,
            last: event.timestamp.slice(0, 10)
          });
        }
        const entry = asnMap.get(key);
        entry.total++;
        if (asn.correct) entry.correct++;
        entry.last = event.timestamp.slice(0, 10);
      }
    }
  }

  // Auto-discover scoped entries (3+ corrections in same scope)
  for (const [scopeKey, count] of scopeTracker) {
    if (count < 3) continue;
    const [dim, scope] = scopeKey.split('::');
    const globalKey = `${dim}::*`;
    const globalPref = prefMap.get(globalKey);
    if (!globalPref) continue;

    // Create scoped entry derived from global
    if (!prefMap.has(scopeKey)) {
      prefMap.set(scopeKey, {
        dim: globalPref.dim,
        target: globalPref.target,
        w: Math.min(1.0, globalPref.w + 0.05),
        n: count,
        src: { ...globalPref.src },
        ctd: 0,
        scope,
        last: globalPref.last,
        _recent_ctd: 0,
        _recent_reinforced: globalPref._recent_reinforced
      });
    }
  }

  // Apply value test + decay
  const prefs = [];
  for (const [, pref] of prefMap) {
    const crossContext = Object.values(pref.src).filter(v => v > 0).length >= 2;
    const stable = pref.n > 0 && (pref.ctd / pref.n) < 0.15;
    const repeated = pref.n >= 3;

    if (!repeated && !crossContext && !stable) continue;

    pref.decay = computeDecay(pref.last, pref.ctd, pref._recent_ctd, pref._recent_reinforced);
    delete pref._recent_ctd;
    delete pref._recent_reinforced;
    prefs.push(pref);
  }

  const asns = [];
  for (const [, asn] of asnMap) {
    if (asn.total < 3) continue;
    asn.accuracy = Math.round((asn.correct / asn.total) * 1000) / 1000;
    asns.push(asn);
  }

  // Write aggregate state
  const aggregate = { prefs, asns, event_count: events.length, aggregated_at: today };
  fs.mkdirSync(PREFS_DIR, { recursive: true });
  fs.writeFileSync(PREFS_PATH, JSON.stringify(aggregate, null, 2));

  console.log(JSON.stringify({
    status: 'ok',
    event_count: events.length,
    prefs: prefs.length,
    asns: asns.length
  }));
}

// --- Subcommand: project ---

function cmdProject() {
  if (!fs.existsSync(PREFS_PATH)) {
    console.error('No aggregate state found. Run `aggregate` first.');
    process.exit(1);
  }

  const aggregate = JSON.parse(fs.readFileSync(PREFS_PATH, 'utf8'));
  const schema = loadSchema();
  const today = new Date().toISOString().slice(0, 10);

  // Build entries from aggregate
  const entries = [];

  // Always include meta
  const existingLedger = readLedger();
  const existingMeta = existingLedger.find(e => e.type === 'meta');
  const meta = existingMeta ? { ...existingMeta.data } : coldStartMeta();

  meta.signals = aggregate.event_count || 0;
  meta.updated = today;

  // Update profile from top preferences
  const topPrefs = [...aggregate.prefs]
    .sort((a, b) => effectiveWeight(b.w, b.decay) - effectiveWeight(a.w, a.decay))
    .slice(0, 5);
  for (const pref of topPrefs) {
    meta.profile[pref.dim] = pref.target;
  }

  entries.push({ type: 'meta', data: meta });

  // Add prefs (up to cap)
  const sortedPrefs = [...aggregate.prefs]
    .map(p => ({ ...p, _utility: utilityScore(p) }))
    .sort((a, b) => b._utility - a._utility)
    .slice(0, ENTRY_CAPS.pref);

  for (const pref of sortedPrefs) {
    const { _utility, _uses_30d, _impact, ...clean } = pref;
    entries.push({ type: 'pref', data: clean });
  }

  // Add existing maps (carry forward from ledger)
  const existingMaps = existingLedger.filter(e => e.type === 'map').slice(0, ENTRY_CAPS.map);
  entries.push(...existingMaps);

  // Add asns (up to cap)
  const sortedAsns = [...(aggregate.asns || [])]
    .sort((a, b) => b.total - a.total)
    .slice(0, ENTRY_CAPS.asn);
  for (const asn of sortedAsns) {
    entries.push({ type: 'asn', data: asn });
  }

  // Carry forward existing proven/trusted rubrics
  const existingRubs = existingLedger
    .filter(e => e.type === 'rub' && (e.data.stage === 'proven' || e.data.stage === 'trusted'))
    .slice(0, ENTRY_CAPS.rub);
  entries.push(...existingRubs);

  // Enforce total cap with utility-ranked pruning
  if (entries.length > TOTAL_CAP) {
    const protectedIndices = new Set();
    entries.forEach((e, i) => {
      if (e.type === 'meta') { protectedIndices.add(i); return; }
      if (e.type === 'rub' && (e.data.stage === 'proven' || e.data.stage === 'trusted')) { protectedIndices.add(i); return; }
      if (e.type === 'pref' && e.data.n >= 15 && e.data.ctd === 0) { protectedIndices.add(i); return; }
    });

    while (entries.length > TOTAL_CAP) {
      let lowestIdx = -1;
      let lowestUtility = Infinity;
      for (let i = 0; i < entries.length; i++) {
        if (protectedIndices.has(i)) continue;
        const u = utilityScore(entries[i].data || {});
        if (u < lowestUtility) {
          lowestUtility = u;
          lowestIdx = i;
        }
      }
      if (lowestIdx === -1) break;
      entries.splice(lowestIdx, 1);
      // Rebuild protected indices after splice
      protectedIndices.clear();
      entries.forEach((e, i) => {
        if (e.type === 'meta') protectedIndices.add(i);
        if (e.type === 'rub' && (e.data.stage === 'proven' || e.data.stage === 'trusted')) protectedIndices.add(i);
        if (e.type === 'pref' && e.data.n >= 15 && e.data.ctd === 0) protectedIndices.add(i);
      });
    }
  }

  // Validate all entries
  for (const entry of entries) {
    const errors = validateLedgerEntry(entry.type, entry.data, schema);
    if (errors.length > 0) {
      console.error(`Validation warning for [sig:${entry.type}]: ${errors.join(', ')}`);
    }
  }

  writeLedger(entries);

  // Estimate token count (~75 per entry)
  const estimatedTokens = entries.length * 75;

  console.log(JSON.stringify({
    status: 'ok',
    entries: entries.length,
    by_type: {
      meta: entries.filter(e => e.type === 'meta').length,
      pref: entries.filter(e => e.type === 'pref').length,
      map: entries.filter(e => e.type === 'map').length,
      asn: entries.filter(e => e.type === 'asn').length,
      rub: entries.filter(e => e.type === 'rub').length
    },
    estimated_tokens: estimatedTokens,
    cap: TOTAL_CAP
  }));
}

// --- Subcommand: adapt-code ---

function cmdAdaptCode() {
  const scorePath = path.join(TRUST_DIR, 'score.json');
  if (!fs.existsSync(scorePath)) {
    console.error('No trust score found at .nomark/metrics/trust/score.json');
    process.exit(1);
  }

  const score = JSON.parse(fs.readFileSync(scorePath, 'utf8'));
  const today = new Date().toISOString().slice(0, 10);
  const now = new Date().toISOString();
  const sessionId = `code-${today}-${Date.now().toString(36)}`;
  const events = [];

  // Map story completions
  if (score.lifetime && score.lifetime.stories_verified > 0) {
    events.push({
      id: `sig-${today}-adapt-completions`,
      timestamp: now,
      context: 'code',
      session_id: sessionId,
      input_tier: 1,
      outcome: 'accepted',
      outcome_confidence: 1.0,
      input_summary: `${score.lifetime.stories_verified} stories verified lifetime`,
      preference_updates: [{ dim: 'verification_discipline', delta: 0.0, reason: 'confirmed' }]
    });
  }

  // Map breaches
  const breaches = score.lifetime?.breaches || {};
  const totalBreaches = Object.values(breaches).reduce((a, b) => a + b, 0);
  if (totalBreaches > 0) {
    events.push({
      id: `sig-${today}-adapt-breaches`,
      timestamp: now,
      context: 'code',
      session_id: sessionId,
      input_tier: 1,
      outcome: 'corrected',
      outcome_confidence: 1.0,
      input_summary: `${totalBreaches} breaches lifetime (S0:${breaches.S0||0} S1:${breaches.S1||0} S2:${breaches.S2||0} S3:${breaches.S3||0} S4:${breaches.S4||0})`,
      preference_updates: [{ dim: 'factual_verification', delta: -0.1, reason: 'breach_correction' }]
    });
  }

  // Map commends
  if (score.lifetime?.commends > 0) {
    events.push({
      id: `sig-${today}-adapt-commends`,
      timestamp: now,
      context: 'code',
      session_id: sessionId,
      input_tier: 1,
      outcome: 'accepted',
      outcome_confidence: 1.0,
      input_summary: `${score.lifetime.commends} commends lifetime`,
      preference_updates: [{ dim: 'trust_reinforcement', delta: 0.1, reason: 'commended' }]
    });
  }

  // Write events
  const schema = loadSchema();
  let written = 0;
  for (const event of events) {
    const errors = validateEvent(event, schema);
    if (errors.length > 0) {
      console.error(`Skipping invalid event ${event.id}: ${errors.join(', ')}`);
      continue;
    }
    const filePath = eventFilePath(event.timestamp);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, JSON.stringify(event) + '\n');
    written++;
  }

  console.log(JSON.stringify({ status: 'ok', events_written: written, total_generated: events.length }));
}

// --- Subcommand: intake ---

function cmdIntake() {
  const ledger = readLedger();
  const staged = ledger.filter(e => e.data.staged === true);

  if (staged.length === 0) {
    console.log(JSON.stringify({ status: 'ok', message: 'No staged entries', processed: 0 }));
    return;
  }

  // Load existing aggregate for conflict check
  let aggregate = { prefs: [], asns: [] };
  if (fs.existsSync(PREFS_PATH)) {
    aggregate = JSON.parse(fs.readFileSync(PREFS_PATH, 'utf8'));
  }

  const archivePrefs = new Map();
  for (const pref of aggregate.prefs) {
    archivePrefs.set(`${pref.dim}::${pref.scope}`, pref);
  }

  let merged = 0;
  let rejected = 0;
  let corrected = 0;

  const keptEntries = [];
  for (const entry of ledger) {
    if (!entry.data.staged) {
      keptEntries.push(entry);
      continue;
    }

    if (entry.type === 'pref') {
      const key = `${entry.data.dim}::${entry.data.scope}`;
      const archivePref = archivePrefs.get(key);

      if (archivePref) {
        // Archive wins — correct staged to match
        entry.data = { ...archivePref };
        delete entry.data.staged;
        keptEntries.push(entry);
        corrected++;
      } else {
        // Value test: 3+ occurrences or cross-context
        const crossCtx = entry.data.src ? Object.values(entry.data.src).filter(v => v > 0).length >= 2 : false;
        if (entry.data.n >= 3 || crossCtx) {
          delete entry.data.staged;
          keptEntries.push(entry);
          merged++;
        } else {
          rejected++;
        }
      }
    } else {
      // Non-pref staged entries: keep if reasonable
      delete entry.data.staged;
      keptEntries.push(entry);
      merged++;
    }
  }

  writeLedger(keptEntries);
  console.log(JSON.stringify({ status: 'ok', processed: staged.length, merged, corrected, rejected }));
}

// --- Subcommand: sync ---

function cmdSync() {
  // Step 1: Intake staged
  const ledgerBefore = readLedger();
  const hadStaged = ledgerBefore.some(e => e.data.staged);
  if (hadStaged) {
    cmdIntake();
  }

  // Step 2: Aggregate
  cmdAggregate();

  // Step 3: Project
  if (fs.existsSync(PREFS_PATH)) {
    cmdProject();
  }

  console.log(JSON.stringify({ status: 'ok', message: 'Sync complete (intake → aggregate → project)' }));
}

// --- Subcommand: adapt-cowork ---

function cmdAdaptCowork(args) {
  const jsonStr = args.join(' ');
  if (!jsonStr) {
    console.error('Usage: mee-event.cjs adapt-cowork <json>');
    console.error('Expected: {"file":"name","action":"kept|edited|deleted|undone"}');
    process.exit(1);
  }

  let input;
  try {
    input = JSON.parse(jsonStr);
  } catch (e) {
    console.error(`Invalid JSON: ${e.message}`);
    process.exit(1);
  }

  const outcomeMap = {
    kept: { outcome: 'accepted', confidence: 0.9 },
    edited: { outcome: 'edited', confidence: 0.9 },
    deleted: { outcome: 'rejected', confidence: 0.85 },
    undone: { outcome: 'rejected', confidence: 0.9 }
  };

  const mapping = outcomeMap[input.action];
  if (!mapping) {
    console.error(`Unknown action: ${input.action}. Must be: kept, edited, deleted, undone`);
    process.exit(1);
  }

  const now = new Date().toISOString();
  const today = now.slice(0, 10);
  const event = {
    id: `sig-${today}-cowork-${Date.now().toString(36)}`,
    timestamp: now,
    context: 'cowork',
    session_id: input.session_id || `cowork-${today}`,
    input_tier: 1,
    outcome: mapping.outcome,
    outcome_confidence: mapping.confidence,
    input_summary: `File "${input.file}" ${input.action}`,
    correction: input.correction || null
  };

  const schema = loadSchema();
  const errors = validateEvent(event, schema);
  if (errors.length > 0) {
    console.error(`Validation failed:\n  ${errors.join('\n  ')}`);
    process.exit(1);
  }

  const filePath = eventFilePath(event.timestamp);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, JSON.stringify(event) + '\n');
  console.log(JSON.stringify({ status: 'ok', id: event.id, outcome: mapping.outcome, confidence: mapping.confidence }));
}

// --- Resolver scoring (Section 10.2) ---

function scopeSpecificity(scope) {
  if (scope === '*') return 0.3;
  if (scope.includes('+')) return 1.0; // compound
  return 0.7; // single scope
}

function resolverScore(pref) {
  const now = new Date();
  const last = new Date(pref.last);
  const daysSinceLast = Math.max(0, (now - last) / (1000 * 60 * 60 * 24));
  const n = pref.n || 0;
  const ctd = pref.ctd || 0;

  const specificity = scopeSpecificity(pref.scope || '*');
  const evidence = Math.min(1.0, n / 20);
  const recency = Math.max(0, 1.0 - daysSinceLast / 180);
  const stability = n > 0 ? 1.0 - (ctd / n) : 0.5;
  let portability = 0;
  if (pref.src) {
    portability = Object.keys(pref.src).filter(k => pref.src[k] > 0).length / 3;
  }
  const contradictionPenalty = ctd * 0.15;

  return (specificity * 0.30) + (evidence * 0.25) + (recency * 0.20) +
         (stability * 0.15) + (portability * 0.10) - contradictionPenalty;
}

// --- Subcommand: resolve ---

function cmdResolve(args) {
  const dim = args[0];
  if (!dim) {
    console.error('Usage: mee-event.cjs resolve <dimension> [context] [topic]');
    process.exit(1);
  }

  const context = args[1] || null;
  const topic = args[2] || null;

  const ledger = readLedger();
  const candidates = ledger
    .filter(e => e.type === 'pref' && e.data.dim === dim)
    .map(e => ({
      ...e.data,
      _score: resolverScore(e.data),
      _effective_w: effectiveWeight(e.data.w, e.data.decay)
    }))
    .sort((a, b) => b._score - a._score);

  if (candidates.length === 0) {
    console.log(JSON.stringify({ status: 'ok', dim, resolved: null, reason: 'no_candidates' }));
    return;
  }

  const winner = candidates[0];
  const runnerUp = candidates.length > 1 ? candidates[1] : null;
  const unstable = winner._score < 0.4;

  console.log(JSON.stringify({
    status: 'ok',
    dim,
    winner: { target: winner.target, scope: winner.scope, score: Math.round(winner._score * 1000) / 1000, effective_w: winner._effective_w },
    runner_up: runnerUp ? { target: runnerUp.target, scope: runnerUp.scope, score: Math.round(runnerUp._score * 1000) / 1000 } : null,
    unstable,
    action: unstable ? 'ask' : 'use_winner',
    candidates: candidates.length
  }));
}

// --- Dispatcher ---

const [,, command, ...args] = process.argv;

const commands = {
  write: cmdWrite,
  'cold-start': cmdColdStart,
  aggregate: cmdAggregate,
  project: cmdProject,
  'adapt-code': cmdAdaptCode,
  intake: cmdIntake,
  sync: cmdSync,
  'adapt-cowork': cmdAdaptCowork,
  resolve: cmdResolve
};

if (!command || !commands[command]) {
  console.error(`Usage: mee-event.cjs <command> [args]`);
  console.error(`Commands: ${Object.keys(commands).join(', ')}`);
  process.exit(1);
}

commands[command](args);
