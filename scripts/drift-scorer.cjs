#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = process.cwd();
const METRICS_DIR = path.join(ROOT, '.nomark', 'metrics');
const DRIFT_PATH = path.join(METRICS_DIR, 'drift.json');
const BRACKETS_PATH = path.join(ROOT, '.nomark', 'config', 'context-brackets.json');
const INSTINCTS_INDEX = path.join(ROOT, 'tasks', 'instincts', 'index.json');
const BRIEFS_DIR = path.join(ROOT, '.nomark', 'briefs');
const RESOURCES_PATH = path.join(ROOT, '.nomark', 'resources.json');
const PROGRESS_PATH = path.join(ROOT, 'progress.md');
const MEMORY_DIR = path.join(ROOT, '.nomark', 'memory');

function cap(value, max) {
  return Math.min(Math.max(value, 0), max);
}

function scoreStaleInstincts() {
  const result = { count: 0, score: 0, details: [] };
  try {
    const index = JSON.parse(fs.readFileSync(INSTINCTS_INDEX, 'utf8'));
    for (const [id, inst] of Object.entries(index.instincts || {})) {
      if (inst.confidence < 0.2 || inst.status === 'expired') {
        result.count++;
        result.details.push(id);
      }
    }
  } catch {
    return result;
  }
  result.score = cap(result.count / 3, 2);
  return result;
}

function scoreOrphanedBriefs() {
  const result = { count: 0, score: 0, details: [] };
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  const cutoff = Date.now() - sevenDaysMs;
  try {
    const files = fs.readdirSync(BRIEFS_DIR);
    for (const file of files) {
      const stat = fs.statSync(path.join(BRIEFS_DIR, file));
      if (stat.mtimeMs < cutoff) {
        result.count++;
        result.details.push(file);
      }
    }
  } catch {
    return result;
  }
  result.score = cap(result.count, 2);
  return result;
}

function scoreUnverifiedResources() {
  const result = { count: 0, score: 0, details: [] };
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
  const cutoff = Date.now() - thirtyDaysMs;
  try {
    const resources = JSON.parse(fs.readFileSync(RESOURCES_PATH, 'utf8'));
    for (const [id, node] of Object.entries(resources.nodes || {})) {
      if (node.verified === false) {
        result.count++;
        result.details.push(id);
      } else if (node.last_verified) {
        const verifiedAt = new Date(node.last_verified).getTime();
        if (verifiedAt < cutoff) {
          result.count++;
          result.details.push(id);
        }
      }
    }
  } catch {
    return result;
  }
  result.score = cap(result.count / 2, 2);
  return result;
}

function scoreZombieStories() {
  const result = { count: 0, score: 0, details: [] };
  try {
    const content = fs.readFileSync(PROGRESS_PATH, 'utf8');
    const storyRegex = /^### (US-\d+):.*$/gm;
    const statusRegex = /^\s*-\s*\*\*Status:\*\*\s*(.+)$/;
    const lines = content.split('\n');
    let currentStory = null;

    for (let i = 0; i < lines.length; i++) {
      const storyMatch = lines[i].match(/^### (US-\d+):/);
      if (storyMatch) {
        currentStory = storyMatch[1];
        continue;
      }
      if (currentStory) {
        const statusMatch = lines[i].match(statusRegex);
        if (statusMatch) {
          const status = statusMatch[1].trim();
          if (status === 'IN PROGRESS') {
            result.count++;
            result.details.push(currentStory);
          }
          currentStory = null;
        }
      }
    }
  } catch {
    return result;
  }
  result.score = cap(result.count, 2);
  return result;
}

function scoreMemoryBloat() {
  const result = { count: 0, score: 0, details: [] };
  const threshold = 30;
  try {
    const files = fs.readdirSync(MEMORY_DIR).filter(f => f.endsWith('.md') && f !== 'MEMORY.md');
    result.count = files.length;
  } catch {
    return result;
  }
  result.score = result.count > threshold ? cap((result.count - threshold) / 10, 2) : 0;
  return result;
}

function loadBrackets() {
  try {
    return JSON.parse(fs.readFileSync(BRACKETS_PATH, 'utf8'));
  } catch {
    return {
      brackets: [
        { name: 'FRESH', min_exchange: 0, max_exchange: 15 },
        { name: 'MODERATE', min_exchange: 16, max_exchange: 25 },
        { name: 'DEPLETED', min_exchange: 26, max_exchange: 35 },
        { name: 'CRITICAL', min_exchange: 36, max_exchange: 999 }
      ],
      drift_multiplier: { enabled: true, threshold: 7, shift: -5 }
    };
  }
}

function determineBracket(exchangeCount, driftScore, bracketsConfig) {
  const config = bracketsConfig || loadBrackets();
  const shift = config.drift_multiplier.enabled && driftScore >= config.drift_multiplier.threshold
    ? config.drift_multiplier.shift
    : 0;

  const adjusted = config.brackets.map(b => ({
    name: b.name,
    min_exchange: Math.max(0, b.min_exchange + shift),
    max_exchange: b.max_exchange === 999 ? 999 : Math.max(0, b.max_exchange + shift)
  }));

  for (let i = adjusted.length - 1; i >= 0; i--) {
    if (exchangeCount >= adjusted[i].min_exchange) {
      return {
        bracket: adjusted[i].name,
        thresholds: Object.fromEntries(adjusted.map(b => [b.name, b.min_exchange]))
      };
    }
  }

  return { bracket: 'FRESH', thresholds: Object.fromEntries(adjusted.map(b => [b.name, b.min_exchange])) };
}

function buildSuggestions(score, indicators) {
  const suggestions = [];
  if (indicators.stale_instincts.count > 0) suggestions.push('/prune');
  if (indicators.orphaned_briefs.count > 0) suggestions.push('archive old briefs');
  if (indicators.unverified_resources.count > 0) suggestions.push('/resources verify');
  if (indicators.zombie_stories.count > 0) suggestions.push('review zombie stories in progress.md');
  if (indicators.memory_bloat.score > 0) suggestions.push('prune old memory files');
  return suggestions;
}

function run() {
  const exchangeCount = parseInt(process.argv[2] || '0', 10);

  const indicators = {
    stale_instincts: scoreStaleInstincts(),
    orphaned_briefs: scoreOrphanedBriefs(),
    unverified_resources: scoreUnverifiedResources(),
    zombie_stories: scoreZombieStories(),
    memory_bloat: scoreMemoryBloat()
  };

  const score = Object.values(indicators).reduce((sum, i) => sum + i.score, 0);

  const bracketsConfig = loadBrackets();
  const { bracket, thresholds } = determineBracket(exchangeCount, score, bracketsConfig);

  let threshold = 'healthy';
  if (score >= 7) threshold = 'auto_groom';
  else if (score >= 4) threshold = 'groom_available';

  const suggestions = score >= 4 ? buildSuggestions(score, indicators) : [];

  const output = {
    score: Math.round(score * 100) / 100,
    bracket,
    exchange_count: exchangeCount,
    adjusted_thresholds: thresholds,
    indicators: Object.fromEntries(
      Object.entries(indicators).map(([k, v]) => [k, { count: v.count, score: Math.round(v.score * 100) / 100 }])
    ),
    threshold,
    suggestions,
    computed_at: new Date().toISOString()
  };

  if (!fs.existsSync(METRICS_DIR)) {
    fs.mkdirSync(METRICS_DIR, { recursive: true });
  }
  fs.writeFileSync(DRIFT_PATH, JSON.stringify(output, null, 2) + '\n');

  process.stdout.write(JSON.stringify(output, null, 2) + '\n');
}

run();
