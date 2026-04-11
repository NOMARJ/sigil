#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const LIFECYCLES_DIR = path.join(process.cwd(), '.nomark', 'lifecycles');
const TRUST_SCORE_PATH = path.join(process.cwd(), '.nomark', 'metrics', 'trust', 'score.json');

function loadYaml(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const result = { stages: [] };
  let currentStage = null;
  let currentList = null;
  let currentArtifact = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (line.match(/^name:/)) result.name = trimmed.split(':').slice(1).join(':').trim().replace(/^["']|["']$/g, '');
    else if (line.match(/^version:/)) result.version = trimmed.split(':').slice(1).join(':').trim().replace(/^["']|["']$/g, '');
    else if (line.match(/^description:/)) result.description = trimmed.split(':').slice(1).join(':').trim().replace(/^["']|["']$/g, '');
    else if (trimmed.startsWith('- id:')) {
      currentStage = {
        id: trimmed.replace('- id:', '').trim(),
        entry_criteria: [],
        exit_criteria: [],
        artifacts: [],
        skills: []
      };
      result.stages.push(currentStage);
      currentList = null;
      currentArtifact = null;
    } else if (currentStage) {
      if (trimmed === 'entry_criteria:') { currentList = 'entry_criteria'; currentArtifact = null; }
      else if (trimmed === 'exit_criteria:') { currentList = 'exit_criteria'; currentArtifact = null; }
      else if (trimmed === 'artifacts:') { currentList = 'artifacts'; currentArtifact = null; }
      else if (trimmed === 'skills:') { currentList = 'skills'; currentArtifact = null; }
      else if (trimmed.match(/^trust_gate:/)) {
        currentStage.trust_gate = parseFloat(trimmed.split(':')[1].trim());
        currentList = null;
      }
      else if (trimmed.match(/^handoff_to:/)) {
        currentStage.handoff_to = trimmed.split(':').slice(1).join(':').trim().replace(/^["']|["']$/g, '');
        currentList = null;
      }
      else if (trimmed.match(/^persona:/)) {
        currentStage.persona = trimmed.split(':').slice(1).join(':').trim().replace(/^["']|["']$/g, '');
        currentList = null;
      }
      else if (trimmed.startsWith('- ') && currentList) {
        if (currentList === 'artifacts') {
          if (trimmed.startsWith('- name:')) {
            currentArtifact = { name: trimmed.replace('- name:', '').trim().replace(/^["']|["']$/g, '') };
            currentStage.artifacts.push(currentArtifact);
          } else {
            const val = trimmed.replace(/^- /, '').replace(/^["']|["']$/g, '');
            if (currentList === 'entry_criteria') currentStage.entry_criteria.push(val);
            else if (currentList === 'exit_criteria') currentStage.exit_criteria.push(val);
            else if (currentList === 'skills') currentStage.skills.push(val);
          }
        } else {
          const val = trimmed.replace(/^- /, '').replace(/^["']|["']$/g, '');
          if (currentList === 'entry_criteria') currentStage.entry_criteria.push(val);
          else if (currentList === 'exit_criteria') currentStage.exit_criteria.push(val);
          else if (currentList === 'skills') currentStage.skills.push(val);
        }
      } else if (trimmed.startsWith('type:') && currentArtifact) {
        currentArtifact.type = trimmed.split(':')[1].trim().replace(/^["']|["']$/g, '');
      }
    }
  }
  return result;
}

function getManifestPath(name) {
  return path.join(LIFECYCLES_DIR, 'manifests', `${name}.yaml`);
}

function getInstanceDir(name, instance) {
  return path.join(LIFECYCLES_DIR, name, 'instances', instance);
}

function getStatePath(name, instance) {
  return path.join(getInstanceDir(name, instance), 'state.json');
}

function readState(name, instance) {
  const p = getStatePath(name, instance);
  if (!fs.existsSync(p)) throw new Error(`Instance '${instance}' of lifecycle '${name}' does not exist`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function writeState(name, instance, state) {
  const p = getStatePath(name, instance);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n');
  fs.renameSync(tmp, p);
}

const TRUST_GRAPH_PATH = path.join(process.cwd(), '.nomark', 'metrics', 'trust', 'graph.json');

function logBreach(severity, penalty, lifecycle, stage, instance, description) {
  const scoreData = JSON.parse(fs.readFileSync(TRUST_SCORE_PATH, 'utf8'));
  const oldScore = scoreData.current;
  scoreData.current = Math.max(0, oldScore + penalty);
  scoreData.lifetime.breaches[severity] = (scoreData.lifetime.breaches[severity] || 0) + 1;
  scoreData.last_updated = now();
  fs.writeFileSync(TRUST_SCORE_PATH, JSON.stringify(scoreData, null, 2) + '\n');

  try {
    const graph = JSON.parse(fs.readFileSync(TRUST_GRAPH_PATH, 'utf8'));
    if (graph.sessions && graph.sessions.length > 0) {
      const session = graph.sessions[graph.sessions.length - 1];
      session.events.push({
        type: 'breach',
        severity,
        penalty,
        lifecycle,
        stage,
        instance,
        description,
        timestamp: now(),
        score_before: oldScore,
        score_after: scoreData.current
      });
      session.end_score = scoreData.current;
      fs.writeFileSync(TRUST_GRAPH_PATH, JSON.stringify(graph, null, 2) + '\n');
    }
  } catch {}

  console.error(`BREACH ${severity} (${penalty}): ${description}`);
  console.error(`  Trust: ${oldScore} → ${scoreData.current}`);
}

function readTrustScore() {
  try {
    const data = JSON.parse(fs.readFileSync(TRUST_SCORE_PATH, 'utf8'));
    if (typeof data.current === 'number') return data.current;
    if (typeof data.score === 'number') return data.score;
    return null;
  } catch {
    return null;
  }
}

function handleHandoff(sourceManifest, sourceStage, sourceState, sourceInstanceDir) {
  if (!sourceStage.handoff_to) return;

  const [targetLifecycle, targetStageId] = sourceStage.handoff_to.split('.');
  const targetManifestPath = getManifestPath(targetLifecycle);

  if (!fs.existsSync(targetManifestPath)) {
    console.log(`  Handoff target manifest '${targetLifecycle}' not found — skipping handoff`);
    return;
  }

  const targetManifest = loadYaml(targetManifestPath);
  const targetStageIdx = findStageIndex(targetManifest, targetStageId);
  if (targetStageIdx < 0) {
    console.log(`  Handoff target stage '${targetStageId}' not found in '${targetLifecycle}' — skipping handoff`);
    return;
  }

  const targetInstance = sourceState._handoff_instance || `${sourceState.instance}-handoff-${Date.now()}`;
  const targetInstanceDir = getInstanceDir(targetLifecycle, targetInstance);
  const targetStatePath = getStatePath(targetLifecycle, targetInstance);

  const artifactsToCopy = (sourceStage.artifacts || []).map(a => a.name);
  const artifactsTransferred = [];

  if (!fs.existsSync(targetStatePath)) {
    fs.mkdirSync(path.join(targetInstanceDir, 'artifacts'), { recursive: true });

    const stages = [];
    for (let i = 0; i <= targetStageIdx; i++) {
      const stage = targetManifest.stages[i];
      if (i < targetStageIdx) {
        stages.push({
          id: stage.id,
          entered_at: now(),
          completed_at: now(),
          advanced_by: 'handoff',
          handoff_skipped: true
        });
      } else {
        stages.push({
          id: stage.id,
          entered_at: now(),
          completed_at: null,
          advanced_by: 'handoff'
        });
      }
    }

    const targetState = {
      lifecycle: targetLifecycle,
      instance: targetInstance,
      current_stage: targetStageId,
      created_at: now(),
      stages,
      gate_decisions: [],
      artifacts: {},
      handoff_from: {
        lifecycle: sourceState.lifecycle,
        stage: sourceStage.id,
        instance: sourceState.instance,
        timestamp: now(),
        artifacts_transferred: []
      }
    };

    for (const name of artifactsToCopy) {
      const src = path.join(sourceInstanceDir, 'artifacts', name);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, path.join(targetInstanceDir, 'artifacts', name));
        artifactsTransferred.push(name);
      }
    }
    targetState.handoff_from.artifacts_transferred = artifactsTransferred;

    writeState(targetLifecycle, targetInstance, targetState);
    console.log(`  Handoff: created '${targetLifecycle}/${targetInstance}' at stage '${targetStageId}'`);
    if (artifactsTransferred.length > 0) {
      console.log(`  Artifacts transferred: ${artifactsTransferred.join(', ')}`);
    }
  } else {
    console.log(`  Handoff: target instance '${targetInstance}' already exists — skipping creation`);
  }

  sourceState.handoff_to = {
    lifecycle: targetLifecycle,
    stage: targetStageId,
    instance: targetInstance,
    timestamp: now(),
    artifacts_transferred: artifactsTransferred
  };
}

function evaluateCriterion(criterion, instanceDir, state) {
  if (criterion.startsWith('artifact:')) {
    const artifactName = criterion.slice('artifact:'.length);
    const artifactPath = path.join(instanceDir, 'artifacts', artifactName);
    if (fs.existsSync(artifactPath)) return { passed: true, criterion };
    const allArtifacts = Object.values(state.artifacts || {}).flat();
    if (allArtifacts.includes(artifactName)) return { passed: true, criterion };
    return { passed: false, criterion, reason: `artifact '${artifactName}' not found` };
  }
  if (criterion.startsWith('trust >= ') || criterion.startsWith('trust>=')) {
    const threshold = parseFloat(criterion.replace(/trust\s*>=\s*/, ''));
    const score = readTrustScore();
    if (score === null) return { passed: false, criterion, reason: 'trust score unavailable (fail closed)' };
    if (score >= threshold) return { passed: true, criterion };
    return { passed: false, criterion, reason: `trust ${score} < ${threshold}` };
  }
  return { passed: true, criterion };
}

function evaluateCriteria(criteria, instanceDir, state) {
  return criteria.map(c => evaluateCriterion(c, instanceDir, state));
}

function findStageIndex(manifest, stageId) {
  return manifest.stages.findIndex(s => s.id === stageId);
}

function now() {
  return new Date().toISOString();
}

function cmdStart(name, instance) {
  const manifestPath = getManifestPath(name);
  if (!fs.existsSync(manifestPath)) {
    console.error(`Manifest not found: ${manifestPath}`);
    process.exit(1);
  }

  const result = execSync(`ajv validate -s ${path.join(LIFECYCLES_DIR, 'schema.json')} -d ${manifestPath} --spec=draft2020 2>&1`, { encoding: 'utf8' });
  if (!result.includes('valid')) {
    console.error(`Manifest validation failed:\n${result}`);
    process.exit(1);
  }

  const instanceDir = getInstanceDir(name, instance);
  const statePath = getStatePath(name, instance);
  if (fs.existsSync(statePath)) {
    console.error(`Instance '${instance}' already exists for lifecycle '${name}'`);
    process.exit(1);
  }

  const manifest = loadYaml(manifestPath);
  const firstStage = manifest.stages[0].id;

  fs.mkdirSync(path.join(instanceDir, 'artifacts'), { recursive: true });

  const state = {
    lifecycle: name,
    instance,
    current_stage: firstStage,
    created_at: now(),
    stages: [{
      id: firstStage,
      entered_at: now(),
      completed_at: null,
      advanced_by: 'manual'
    }],
    gate_decisions: [],
    artifacts: {}
  };

  writeState(name, instance, state);
  console.log(`Lifecycle '${name}' instance '${instance}' started at stage '${firstStage}'`);
}

function cmdComplete(name, instance) {
  const manifest = loadYaml(getManifestPath(name));
  const state = readState(name, instance);
  const instanceDir = getInstanceDir(name, instance);
  const currentIdx = findStageIndex(manifest, state.current_stage);
  const currentStage = manifest.stages[currentIdx];

  const results = evaluateCriteria(currentStage.exit_criteria, instanceDir, state);
  const failures = results.filter(r => !r.passed);

  if (failures.length > 0) {
    console.log(`Exit criteria NOT met for stage '${state.current_stage}':`);
    failures.forEach(f => console.log(`  FAIL: ${f.criterion} — ${f.reason}`));
    process.exit(1);
  }

  const declaredArtifacts = currentStage.artifacts || [];
  const missingArtifacts = declaredArtifacts.filter(a =>
    !fs.existsSync(path.join(instanceDir, 'artifacts', a.name))
  );
  if (missingArtifacts.length > 0) {
    console.log(`Declared artifacts missing for stage '${state.current_stage}':`);
    missingArtifacts.forEach(a => console.log(`  MISSING: ${a.name}`));
    process.exit(1);
  }

  const stageEntry = state.stages.find(s => s.id === state.current_stage && !s.completed_at);
  if (stageEntry) stageEntry.completed_at = now();

  state.artifacts[state.current_stage] = declaredArtifacts.map(a => a.name);

  handleHandoff(manifest, currentStage, state, instanceDir);
  writeState(name, instance, state);

  const nextIdx = currentIdx + 1;
  if (nextIdx < manifest.stages.length) {
    const nextStage = manifest.stages[nextIdx];
    const entryResults = evaluateCriteria(nextStage.entry_criteria, instanceDir, state);
    const entryFailures = entryResults.filter(r => !r.passed);
    if (entryFailures.length === 0) {
      console.log(`Stage '${state.current_stage}' completed. Next stage '${nextStage.id}' is ready.`);
    } else {
      console.log(`Stage '${state.current_stage}' completed. Next stage '${nextStage.id}' entry criteria not yet met.`);
    }
  } else {
    console.log(`Stage '${state.current_stage}' completed. Lifecycle complete.`);
  }
}

function cmdAdvance(name, instance, advancedBy = 'manual') {
  const manifest = loadYaml(getManifestPath(name));
  const state = readState(name, instance);
  const instanceDir = getInstanceDir(name, instance);
  const currentIdx = findStageIndex(manifest, state.current_stage);
  const currentStage = manifest.stages[currentIdx];

  const exitResults = evaluateCriteria(currentStage.exit_criteria, instanceDir, state);
  const exitFailures = exitResults.filter(r => !r.passed);
  if (exitFailures.length > 0) {
    console.log(`Exit criteria NOT met for stage '${state.current_stage}':`);
    exitFailures.forEach(f => console.log(`  FAIL: ${f.criterion} — ${f.reason}`));
    process.exit(1);
  }

  const nextIdx = currentIdx + 1;
  if (nextIdx >= manifest.stages.length) {
    const stageEntry = state.stages.find(s => s.id === state.current_stage && !s.completed_at);
    if (stageEntry) stageEntry.completed_at = now();
    state.artifacts[state.current_stage] = (currentStage.artifacts || []).map(a => a.name);
    handleHandoff(manifest, currentStage, state, instanceDir);
    writeState(name, instance, state);
    console.log(`Stage '${state.current_stage}' completed. Lifecycle '${name}' is complete.`);
    return;
  }

  const nextStage = manifest.stages[nextIdx];

  const entryResults = evaluateCriteria(nextStage.entry_criteria, instanceDir, state);
  const entryFailures = entryResults.filter(r => !r.passed);
  if (entryFailures.length > 0) {
    console.log(`Entry criteria NOT met for stage '${nextStage.id}':`);
    entryFailures.forEach(f => console.log(`  FAIL: ${f.criterion} — ${f.reason}`));
    process.exit(1);
  }

  if (typeof nextStage.trust_gate === 'number') {
    const trustScore = readTrustScore();
    if (trustScore === null) {
      console.log(`Owner approval required: trust score unavailable (fail closed) for gate ${nextStage.trust_gate}`);
      state._pending_gate = { stage: nextStage.id, threshold: nextStage.trust_gate };
      writeState(name, instance, state);
      process.exit(1);
    }
    if (trustScore < nextStage.trust_gate) {
      console.log(`Owner approval required: trust ${trustScore} < gate ${nextStage.trust_gate}`);
      state._pending_gate = { stage: nextStage.id, threshold: nextStage.trust_gate };
      writeState(name, instance, state);
      process.exit(1);
    }
    state.gate_decisions.push({
      stage: nextStage.id,
      type: 'auto_approved',
      trust_at_decision: trustScore,
      gate_threshold: nextStage.trust_gate,
      timestamp: now(),
      source: 'cli'
    });
  }

  const stageEntry = state.stages.find(s => s.id === state.current_stage && !s.completed_at);
  if (stageEntry) stageEntry.completed_at = now();
  state.artifacts[state.current_stage] = (currentStage.artifacts || []).map(a => a.name);

  handleHandoff(manifest, currentStage, state, instanceDir);

  state.stages.push({
    id: nextStage.id,
    entered_at: now(),
    completed_at: null,
    advanced_by: advancedBy
  });
  state.current_stage = nextStage.id;
  delete state._pending_gate;

  writeState(name, instance, state);
  console.log(`Advanced to stage '${nextStage.id}'`);
  if (typeof nextStage.trust_gate === 'number') {
    console.log(`  Trust gate: ${nextStage.trust_gate} (auto-approved at ${readTrustScore()})`);
  }
}

function cmdApprove(name, instance) {
  const state = readState(name, instance);
  const manifest = loadYaml(getManifestPath(name));
  const currentIdx = findStageIndex(manifest, state.current_stage);

  if (!state._pending_gate) {
    const nextIdx = currentIdx + 1;
    if (nextIdx >= manifest.stages.length) {
      console.log('No pending trust gate to approve');
      process.exit(1);
    }
    const nextStage = manifest.stages[nextIdx];
    if (typeof nextStage.trust_gate !== 'number') {
      console.log('No pending trust gate to approve');
      process.exit(1);
    }
  }

  const pending = state._pending_gate;
  const trustScore = readTrustScore();

  state.gate_decisions.push({
    stage: pending ? pending.stage : manifest.stages[currentIdx + 1].id,
    type: 'owner_approval',
    trust_at_decision: trustScore,
    gate_threshold: pending ? pending.threshold : manifest.stages[currentIdx + 1].trust_gate,
    timestamp: now(),
    source: 'cli'
  });

  const nextStage = manifest.stages[currentIdx + 1];
  const currentStage = manifest.stages[currentIdx];

  const stageEntry = state.stages.find(s => s.id === state.current_stage && !s.completed_at);
  if (stageEntry) stageEntry.completed_at = now();
  state.artifacts[state.current_stage] = (currentStage.artifacts || []).map(a => a.name);

  state.stages.push({
    id: nextStage.id,
    entered_at: now(),
    completed_at: null,
    advanced_by: 'owner_approval'
  });
  state.current_stage = nextStage.id;
  delete state._pending_gate;

  writeState(name, instance, state);
  console.log(`Owner approved. Advanced to stage '${nextStage.id}'`);
}

function cmdStatus(filterName) {
  const manifestsDir = path.join(LIFECYCLES_DIR, 'manifests');
  if (!fs.existsSync(manifestsDir)) {
    console.log('No lifecycles configured');
    return;
  }

  const rows = [];
  const entries = fs.readdirSync(LIFECYCLES_DIR).filter(d => {
    const p = path.join(LIFECYCLES_DIR, d, 'instances');
    return fs.existsSync(p) && fs.statSync(p).isDirectory();
  });

  for (const lcName of entries) {
    if (filterName && lcName !== filterName) continue;
    const instancesDir = path.join(LIFECYCLES_DIR, lcName, 'instances');
    if (!fs.existsSync(instancesDir)) continue;
    for (const inst of fs.readdirSync(instancesDir)) {
      try {
        const state = readState(lcName, inst);
        const currentStageEntry = state.stages.find(s => s.id === state.current_stage && !s.completed_at);
        let timeInStage = 'N/A';
        if (currentStageEntry) {
          const entered = new Date(currentStageEntry.entered_at);
          const diff = Date.now() - entered.getTime();
          const mins = Math.floor(diff / 60000);
          const hrs = Math.floor(mins / 60);
          timeInStage = hrs > 0 ? `${hrs}h ${mins % 60}m` : `${mins}m`;
        }

        const manifest = loadYaml(getManifestPath(lcName));
        const idx = findStageIndex(manifest, state.current_stage);
        const stage = manifest.stages[idx];
        let gateStatus = 'none';
        if (stage && typeof stage.trust_gate === 'number') {
          if (state._pending_gate) gateStatus = 'pending';
          else {
            const gd = state.gate_decisions.find(g => g.stage === state.current_stage);
            gateStatus = gd ? `${gd.type} (${gd.trust_at_decision})` : 'none';
          }
        }

        const allCompleted = state.stages.every(s => s.completed_at !== null);
        const isLast = idx === manifest.stages.length - 1;
        const displayStage = allCompleted && isLast ? 'COMPLETE' : state.current_stage;

        rows.push({ lifecycle: lcName, instance: inst, stage: displayStage, timeInStage, gateStatus });
      } catch {}
    }
  }

  if (rows.length === 0) {
    console.log(filterName ? `No instances for lifecycle '${filterName}'` : 'No active lifecycle instances');
    return;
  }

  console.log('| Lifecycle | Instance | Stage | Time in Stage | Gate Status |');
  console.log('|-----------|----------|-------|---------------|-------------|');
  for (const r of rows) {
    console.log(`| ${r.lifecycle} | ${r.instance} | ${r.stage} | ${r.timeInStage} | ${r.gateStatus} |`);
  }
}

function cmdSkipTo(name, instance, targetStageId) {
  const manifest = loadYaml(getManifestPath(name));
  const state = readState(name, instance);
  const currentIdx = findStageIndex(manifest, state.current_stage);
  const targetIdx = findStageIndex(manifest, targetStageId);

  if (targetIdx < 0) {
    console.error(`Stage '${targetStageId}' not found in manifest`);
    process.exit(1);
  }

  if (targetIdx <= currentIdx) {
    console.error(`Cannot skip backwards (current: ${state.current_stage}, target: ${targetStageId})`);
    process.exit(1);
  }

  if (targetIdx === currentIdx + 1) {
    console.log('Target is the next stage — use advance instead');
    process.exit(1);
  }

  const skippedStages = manifest.stages.slice(currentIdx + 1, targetIdx).map(s => s.id);
  logBreach('S2', -0.4, name, state.current_stage, instance,
    `Stage skip attempted: tried to jump from '${state.current_stage}' to '${targetStageId}', skipping: ${skippedStages.join(', ')}`);

  console.log(`BLOCKED: Stage skip detected. Cannot jump from '${state.current_stage}' to '${targetStageId}'`);
  console.log(`  Skipped stages: ${skippedStages.join(', ')}`);
  console.log(`  Breach: S2 (-0.4) logged to trust graph`);
  process.exit(1);
}

function cmdForceComplete(name, instance) {
  const manifest = loadYaml(getManifestPath(name));
  const state = readState(name, instance);
  const instanceDir = getInstanceDir(name, instance);
  const currentIdx = findStageIndex(manifest, state.current_stage);
  const currentStage = manifest.stages[currentIdx];

  const results = evaluateCriteria(currentStage.exit_criteria, instanceDir, state);
  const failures = results.filter(r => !r.passed);

  if (failures.length > 0) {
    logBreach('S3', -0.5, name, state.current_stage, instance,
      `False exit criteria: stage '${state.current_stage}' force-completed with unmet criteria: ${failures.map(f => f.criterion).join(', ')}`);

    console.log(`BREACH: Force-completing stage '${state.current_stage}' with unmet exit criteria`);
    console.log(`  Unmet: ${failures.map(f => f.criterion).join(', ')}`);
    console.log(`  Breach: S3 (-0.5) logged to trust graph`);
  }

  const stageEntry = state.stages.find(s => s.id === state.current_stage && !s.completed_at);
  if (stageEntry) stageEntry.completed_at = now();
  state.artifacts[state.current_stage] = (currentStage.artifacts || []).map(a => a.name);
  writeState(name, instance, state);
  console.log(`Stage '${state.current_stage}' force-completed (breach logged if criteria unmet)`);
}

function cmdArtifacts(name, instance) {
  const state = readState(name, instance);
  const instanceDir = getInstanceDir(name, instance);

  console.log(`Artifacts for ${name}/${instance}:`);
  for (const [stageId, artifacts] of Object.entries(state.artifacts || {})) {
    const stageEntry = state.stages.find(s => s.id === stageId);
    const ts = stageEntry ? stageEntry.completed_at : 'unknown';
    for (const a of artifacts) {
      const exists = fs.existsSync(path.join(instanceDir, 'artifacts', a));
      console.log(`  ${a} — stage: ${stageId}, exists: ${exists ? 'yes' : 'no'}, completed: ${ts}`);
    }
  }
}

const [,, command, ...args] = process.argv;

switch (command) {
  case 'start':
    if (args.length < 2) { console.log('Usage: lifecycle-engine.cjs start {name} {instance}'); process.exit(1); }
    cmdStart(args[0], args[1]);
    break;
  case 'complete':
    if (args.length < 2) { console.log('Usage: lifecycle-engine.cjs complete {name} {instance}'); process.exit(1); }
    cmdComplete(args[0], args[1]);
    break;
  case 'advance':
    if (args.length < 2) { console.log('Usage: lifecycle-engine.cjs advance {name} {instance}'); process.exit(1); }
    cmdAdvance(args[0], args[1], args[2] || 'manual');
    break;
  case 'approve':
    if (args.length < 2) { console.log('Usage: lifecycle-engine.cjs approve {name} {instance}'); process.exit(1); }
    cmdApprove(args[0], args[1]);
    break;
  case 'status':
    cmdStatus(args[0]);
    break;
  case 'artifacts':
    if (args.length < 2) { console.log('Usage: lifecycle-engine.cjs artifacts {name} {instance}'); process.exit(1); }
    cmdArtifacts(args[0], args[1]);
    break;
  case 'skip-to':
    if (args.length < 3) { console.log('Usage: lifecycle-engine.cjs skip-to {name} {instance} {target-stage}'); process.exit(1); }
    cmdSkipTo(args[0], args[1], args[2]);
    break;
  case 'force-complete':
    if (args.length < 2) { console.log('Usage: lifecycle-engine.cjs force-complete {name} {instance}'); process.exit(1); }
    cmdForceComplete(args[0], args[1]);
    break;
  default:
    console.log('Usage: lifecycle-engine.cjs {start|complete|advance|approve|status|artifacts|skip-to|force-complete} [args...]');
    process.exit(1);
}
