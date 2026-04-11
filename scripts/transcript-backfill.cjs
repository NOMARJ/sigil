#!/usr/bin/env node
'use strict';

/**
 * transcript-backfill.cjs
 *
 * Reconstructs session summaries from git history + observations + PRDs.
 * Produces summary JSON files in .nomark/sessions/backfill/ (no fabricated transcripts).
 * Idempotent — running twice doesn't duplicate entries.
 *
 * Sources:
 * 1. .nomark/observations/*.md — session entries with dates, features, story counts
 * 2. git log — memory commits with timestamps
 * 3. tasks/prd-*.md — Resolved Decisions sections linked to features
 * 4. SOLUTION.md — feature registry with brainstorm evidence
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PROJECT_DIR = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const OBS_DIR = path.join(PROJECT_DIR, '.nomark', 'observations');
const BACKFILL_DIR = path.join(PROJECT_DIR, '.nomark', 'sessions', 'backfill');
const SOLUTION_PATH = path.join(PROJECT_DIR, 'SOLUTION.md');
const transcript = require(path.join(PROJECT_DIR, 'scripts', 'session-transcript.cjs'));

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function parseObservations() {
  const sessions = [];
  if (!fs.existsSync(OBS_DIR)) return sessions;

  const files = fs.readdirSync(OBS_DIR).filter(f => f.endsWith('.md'));
  for (const file of files) {
    const content = fs.readFileSync(path.join(OBS_DIR, file), 'utf8');
    const blocks = content.split(/^### Session /m).filter(Boolean);

    for (const block of blocks) {
      const lines = block.split('\n');
      const headerLine = lines[0] || '';
      const dateMatch = headerLine.match(/(\d{4}-\d{2}-\d{2})/);
      if (!dateMatch) continue;

      const date = dateMatch[1];
      const idMatch = block.match(/session[_-]id[:\s]*["']?([^"'\n,]+)/i);
      const blockHash = require('crypto').createHash('md5').update(block.slice(0, 500)).digest('hex').slice(0, 8);
      const id = idMatch ? idMatch[1] : `obs-${date}-${blockHash}`;

      const scopeMatch = block.match(/\*\*Task scope:\*\*\s*(.+)/);
      const outcomeMatch = block.match(/\*\*Outcome:\*\*\s*(\w+)/);
      const storiesMatch = block.match(/\*\*Stories:\*\*\s*(\d+)/);
      const notesMatch = block.match(/\*\*Notes:\*\*\n([\s\S]*?)(?=\n###|\n---|\n$)/);

      const features = [];
      const featureMatches = block.match(/(?:EP|F)-\d+/g);
      if (featureMatches) {
        for (const f of new Set(featureMatches)) features.push(f);
      }

      const topics = [];
      if (scopeMatch) {
        const scopeText = scopeMatch[1];
        const words = scopeText.split(/[\s—–()]+/).filter(w => w.length > 3 && !['stories', 'trivial', 'moderate', 'complex'].includes(w.toLowerCase()));
        topics.push(...words.slice(0, 5));
      }

      let scope = 'general';
      const textLower = block.toLowerCase();
      if (textLower.includes('brainstorm')) scope = 'brainstorm';
      else if (textLower.includes('debug')) scope = 'debugging';
      else if (textLower.includes('architect')) scope = 'architecture';
      else if (textLower.includes('design') || textLower.includes('prd')) scope = 'design';

      const decisions = [];
      if (notesMatch) {
        const noteLines = notesMatch[1].split('\n').filter(l => l.trim().startsWith('-'));
        for (const nl of noteLines) {
          decisions.push(nl.replace(/^-\s*/, '').trim().slice(0, 120));
        }
      }

      sessions.push({
        id,
        date,
        features,
        topics,
        scope,
        story_count: storiesMatch ? parseInt(storiesMatch[1]) : 0,
        outcome: outcomeMatch ? outcomeMatch[1] : 'unknown',
        decisions: decisions.slice(0, 10),
        source: 'observation',
        source_file: file,
      });
    }
  }

  return sessions;
}

function parsePRDDecisions() {
  const prds = [];
  const prdDir = path.join(PROJECT_DIR, 'tasks');
  if (!fs.existsSync(prdDir)) return prds;

  const files = fs.readdirSync(prdDir).filter(f => f.startsWith('prd-') && f.endsWith('.md'));
  for (const file of files) {
    const content = fs.readFileSync(path.join(prdDir, file), 'utf8');
    const resolvedMatch = content.match(/## Resolved Decisions\n\n([\s\S]*?)(?=\n## |\n---|\n$)/);
    if (!resolvedMatch) continue;

    const featureMatch = content.match(/\*\*Feature:\*\*\s*([\w-]+)/);
    const createdMatch = content.match(/\*\*Created:\*\*\s*(\d{4}-\d{2}-\d{2})/);

    const decisions = [];
    const decisionBlocks = resolvedMatch[1].split(/\n\d+\.\s+/).filter(Boolean);
    for (const db of decisionBlocks) {
      const firstLine = db.split('\n')[0].trim();
      if (firstLine) decisions.push(firstLine.slice(0, 120));
    }

    if (decisions.length > 0) {
      prds.push({
        file,
        feature: featureMatch ? featureMatch[1] : file.replace('prd-', '').replace('.md', ''),
        date: createdMatch ? createdMatch[1] : null,
        decisions,
      });
    }
  }

  return prds;
}

function parseGitMemoryCommits() {
  const commits = [];
  try {
    const log = execSync('git log --all --oneline --grep="memory:" --format="%H %ai %s"', {
      cwd: PROJECT_DIR,
      encoding: 'utf8',
      timeout: 10000,
    });

    for (const line of log.trim().split('\n').filter(Boolean)) {
      const match = line.match(/^(\w+)\s+(\d{4}-\d{2}-\d{2})\s+[\d:]+\s+[+-]\d+\s+(.+)/);
      if (match) {
        commits.push({
          sha: match[1],
          date: match[2],
          message: match[3],
        });
      }
    }
  } catch { /* git not available or no matches */ }

  return commits;
}

function main() {
  ensureDir(BACKFILL_DIR);

  const existing = new Set(
    fs.readdirSync(BACKFILL_DIR)
      .filter(f => f.endsWith('.summary.json'))
      .map(f => f.replace('.summary.json', ''))
  );

  const observations = parseObservations();
  const prdDecisions = parsePRDDecisions();
  let created = 0;

  for (const obs of observations) {
    const key = `${obs.date}-${obs.id.replace(/[^a-zA-Z0-9-]/g, '')}`.slice(0, 60);
    if (existing.has(key)) continue;

    const prd = prdDecisions.find(p =>
      obs.features.some(f => p.feature.includes(f.replace('F-', '').replace('EP-', '')))
    );

    const summary = {
      id: obs.id,
      date: obs.date,
      features: obs.features,
      topics: obs.topics,
      scope: obs.scope,
      story_count: obs.story_count,
      outcome: obs.outcome,
      decisions: [...obs.decisions, ...(prd ? prd.decisions : [])].slice(0, 10),
      source: 'backfill',
      sources_used: ['observation'],
    };

    if (prd) summary.sources_used.push(`prd:${prd.file}`);

    const outPath = path.join(BACKFILL_DIR, `${key}.summary.json`);
    fs.writeFileSync(outPath, JSON.stringify(summary, null, 2));
    existing.add(key);
    created++;
  }

  transcript.updateIndex();

  console.log(`Backfill complete: ${created} new summaries from ${observations.length} observations`);
  console.log(`Total backfill entries: ${existing.size}`);
  if (created > 0) {
    console.log(`INDEX.md updated: ${transcript.INDEX_PATH}`);
  }
}

main();
