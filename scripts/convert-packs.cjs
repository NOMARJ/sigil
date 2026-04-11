#!/usr/bin/env node
/**
 * convert-packs.cjs — Converts packs/ into .claude/agents/ + .claude/skills/
 *
 * Usage:
 *   node scripts/convert-packs.cjs              # dry run (default)
 *   node scripts/convert-packs.cjs --execute    # actually write files
 *   node scripts/convert-packs.cjs --registry   # only generate skill-registry.json
 */

const fs = require('fs')
const path = require('path')

const ROOT = path.resolve(__dirname, '..')
const PACKS_DIR = path.join(ROOT, 'packs')
const AGENTS_DIR = path.join(ROOT, '.claude', 'agents')
const SKILLS_DIR = path.join(ROOT, '.claude', 'skills')
const REGISTRY_PATH = path.join(ROOT, '.claude', 'skill-registry.json')

const args = process.argv.slice(2)
const EXECUTE = args.includes('--execute')
const REGISTRY_ONLY = args.includes('--registry')

// NOMARK Agent Discipline — replaces generic guardrails
const NOMARK_DISCIPLINE = `## NOMARK Agent Discipline

You operate under the NOMARK method. These principles are absolute:

1. **No false completion** — never claim done without running and reading verification output in the same response
2. **No confabulation** — never quote files from memory; read them first. Never assume edits persisted
3. **No fake data** — never fabricate metrics, scores, or results without [MOCK] labels
4. **Escalate at 2 failures** — same approach failed twice = stop, report BLOCKED, don't loop
5. **Scope integrity** — stay within the task you were given. No auth, schema, or CI/CD changes without explicit approval
6. **Verify before asserting** — run it, read the output, then claim it. "Should work" is not evidence
7. **Simple wins** — the best code is code you don't write. No unnecessary abstractions
8. **Check resources** — before writing any URL, connection string, or resource name, verify it exists in \`.nomark/resources.json\`

When judgment is required and rules don't cover it: state the trade-off clearly and defer to the caller.`

// ── Helpers ──

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/)
  if (!match) return { meta: {}, body: content }

  const rawMeta = match[1]
  const body = match[2]
  const meta = {}

  // Simple YAML parser for flat key-value pairs
  for (const line of rawMeta.split('\n')) {
    const kv = line.match(/^(\w[\w-]*):\s*(.+)$/)
    if (kv) {
      let val = kv[2].trim()
      if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1)
      if (val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1)
      meta[kv[1]] = val
    }
  }

  return { meta, body }
}

function buildFrontmatter(meta) {
  const lines = ['---']
  for (const [k, v] of Object.entries(meta)) {
    if (v === undefined || v === null) continue
    if (typeof v === 'boolean') {
      lines.push(`${k}: ${v}`)
    } else if (typeof v === 'string' && (v.includes(':') || v.includes('#') || v.includes('"'))) {
      lines.push(`${k}: "${v.replace(/"/g, '\\"')}"`)
    } else {
      lines.push(`${k}: ${v}`)
    }
  }
  lines.push('---')
  return lines.join('\n')
}

function stripGuardrails(body) {
  // Remove everything from ## Guardrails to the next ## heading or end of string
  const idx = body.indexOf('\n## Guardrails')
  if (idx === -1) return body

  const afterGuardrails = body.slice(idx + 1)
  // Find the next ## heading that isn't a sub-section of guardrails
  const nextSection = afterGuardrails.search(/\n## (?!Guardrails)/)
  if (nextSection !== -1) {
    return body.slice(0, idx) + afterGuardrails.slice(nextSection)
  }
  // Guardrails is the last section — remove it entirely
  return body.slice(0, idx)
}

function stripProjectSpecifics(content) {
  return content
    .replace(/for the Operable AI Enclave(?: platform)?/gi, 'for this project')
    .replace(/Operable AI Enclave/gi, 'the project')
    .replace(/Enclave AI platform/gi, 'the project')
    .replace(/Enclave AI/gi, 'the project')
    .replace(/the Enclave/gi, 'the project')
    .replace(/Enclave subsystem/gi, 'platform subsystem')
    .replace(/Enclave/g, 'platform')
    .replace(/Enclave-Specific Patterns/g, 'Platform-Specific Patterns')
    .replace(/for Operable/gi, 'for this project')
    .replace(/Operable/g, 'the project')
}

function slugify(str) {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function ensureDir(dir) {
  if (EXECUTE && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
}

// ── Registry ──

const registry = {
  version: '1.0.0',
  generated: new Date().toISOString().split('T')[0],
  categories: {},
  agents: [],
  skills: []
}

function addToRegistry(type, entry) {
  if (type === 'agent') registry.agents.push(entry)
  else registry.skills.push(entry)

  const cat = entry.category
  if (!registry.categories[cat]) {
    registry.categories[cat] = { agents: 0, skills: 0, description: '' }
  }
  registry.categories[cat][type === 'agent' ? 'agents' : 'skills']++
}

// ── Processors ──

function processAgent(packName, agentFile) {
  const filePath = path.join(PACKS_DIR, packName, 'agents', agentFile)
  const content = fs.readFileSync(filePath, 'utf8')
  const { meta, body } = parseFrontmatter(content)

  const name = meta.name || path.basename(agentFile, '.md')
  const destPath = path.join(AGENTS_DIR, agentFile)

  // Add category to frontmatter
  meta.category = packName

  // Clean project-specific references from description
  if (meta.description) meta.description = stripProjectSpecifics(meta.description)

  // Strip old guardrails and project-specifics, add NOMARK discipline
  let newBody = stripGuardrails(body)
  newBody = stripProjectSpecifics(newBody)

  // Append NOMARK discipline at the end
  newBody = newBody.trimEnd() + '\n\n' + NOMARK_DISCIPLINE + '\n'

  const newContent = buildFrontmatter(meta) + '\n' + newBody

  addToRegistry('agent', {
    name,
    file: `.claude/agents/${agentFile}`,
    category: packName,
    description: meta.description || '',
    model: meta.model || 'sonnet'
  })

  if (EXECUTE && !REGISTRY_ONLY) {
    ensureDir(AGENTS_DIR)
    fs.writeFileSync(destPath, newContent)
  }

  return { name, dest: destPath, action: 'agent' }
}

function processCommand(packName, commandFile) {
  const filePath = path.join(PACKS_DIR, packName, 'commands', commandFile)
  const content = fs.readFileSync(filePath, 'utf8')
  const { meta, body } = parseFrontmatter(content)

  // Derive skill name from path: commands/growth/gtm.md → growth-gtm
  const parts = commandFile.replace('.md', '').split('/')
  const skillName = parts.length > 1 ? `${parts[0]}-${parts[parts.length - 1]}` : parts[0]

  const destDir = path.join(SKILLS_DIR, skillName)
  const destPath = path.join(destDir, 'SKILL.md')

  // Check for collision with core skill (skip files created by previous conversion runs)
  if (fs.existsSync(destDir) && fs.existsSync(destPath)) {
    const existing = fs.readFileSync(destPath, 'utf8')
    const { meta: existingMeta } = parseFrontmatter(existing)
    if (existingMeta.category === 'core' || (!existingMeta.category && existingMeta.name)) {
      const altName = `${packName}-${skillName}`
      const altDir = path.join(SKILLS_DIR, altName)
      const altPath = path.join(altDir, 'SKILL.md')
      return processCommandWrite(packName, altName, altDir, altPath, meta, body, content)
    }
  }

  return processCommandWrite(packName, skillName, destDir, destPath, meta, body, content)
}

function processCommandWrite(packName, skillName, destDir, destPath, meta, body, rawContent) {
  // Build skill frontmatter
  const skillMeta = {
    name: skillName,
    description: meta.description || extractFirstLine(body),
    'user-invocable': true,
    category: packName
  }

  let newBody = stripProjectSpecifics(body)

  const newContent = buildFrontmatter(skillMeta) + '\n' + newBody

  addToRegistry('skill', {
    name: skillName,
    dir: `.claude/skills/${skillName}/`,
    category: packName,
    source: 'command',
    description: skillMeta.description
  })

  if (EXECUTE && !REGISTRY_ONLY) {
    ensureDir(destDir)
    fs.writeFileSync(destPath, newContent)
  }

  return { name: skillName, dest: destPath, action: 'command→skill' }
}

function processPackSkill(packName, skillPath) {
  const filePath = path.join(PACKS_DIR, packName, 'skills', skillPath, 'SKILL.md')
  if (!fs.existsSync(filePath)) return null

  const content = fs.readFileSync(filePath, 'utf8')
  const { meta, body } = parseFrontmatter(content)

  // Derive name from path: e.g., cicd/github-actions-templates → cicd-github-actions-templates
  const parts = skillPath.split('/').filter(Boolean)
  const skillName = parts.join('-')

  const destDir = path.join(SKILLS_DIR, skillName)
  const destPath = path.join(destDir, 'SKILL.md')

  // Check for collision with core skill only
  if (fs.existsSync(destDir) && fs.existsSync(destPath)) {
    const existing = fs.readFileSync(destPath, 'utf8')
    const { meta: existingMeta } = parseFrontmatter(existing)
    if (existingMeta.category === 'core' || (!existingMeta.category && existingMeta.name)) {
      const altName = `${packName}-${skillName}`
      const altDir = path.join(SKILLS_DIR, altName)
      const altPath = path.join(altDir, 'SKILL.md')
      return writePackSkill(packName, altName, altDir, altPath, meta, body)
    }
  }

  return writePackSkill(packName, skillName, destDir, destPath, meta, body)
}

function writePackSkill(packName, skillName, destDir, destPath, meta, body) {
  // Ensure category is set
  if (!meta.category) meta.category = packName

  let newBody = stripProjectSpecifics(body)
  const newContent = buildFrontmatter(meta) + '\n' + newBody

  addToRegistry('skill', {
    name: meta.name || skillName,
    dir: `.claude/skills/${skillName}/`,
    category: packName,
    source: 'pack-skill',
    description: meta.description || ''
  })

  if (EXECUTE && !REGISTRY_ONLY) {
    ensureDir(destDir)
    fs.writeFileSync(destPath, newContent)
  }

  return { name: skillName, dest: destPath, action: 'pack-skill→skill' }
}

function extractFirstLine(body) {
  const lines = body.trim().split('\n')
  for (const line of lines) {
    // Skip headings, empty lines, code blocks, lists starting with -
    if (/^#+\s/.test(line) || line.trim() === '' || line.startsWith('```')) continue
    const clean = line.replace(/\*+/g, '').trim()
    if (clean.length > 10 && clean.length < 200 && !clean.startsWith('/') && !clean.startsWith('[')) return clean
  }
  return ''
}

// ── Main ──

function main() {
  console.log(`\n  convert-packs.cjs — ${EXECUTE ? 'EXECUTE MODE' : 'DRY RUN'}\n`)

  const packDirs = fs.readdirSync(PACKS_DIR).filter(d => {
    const p = path.join(PACKS_DIR, d)
    return fs.statSync(p).isDirectory() && fs.existsSync(path.join(p, 'plugin.json'))
  })

  const results = { agents: [], skills: [], errors: [] }

  for (const pack of packDirs) {
    const manifestPath = path.join(PACKS_DIR, pack, 'plugin.json')
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))

    // Set category description
    registry.categories[pack] = registry.categories[pack] || { agents: 0, skills: 0, description: manifest.description || '' }
    registry.categories[pack].description = manifest.description || ''

    console.log(`  Pack: ${pack}`)

    // Process agents
    const agentsDir = path.join(PACKS_DIR, pack, 'agents')
    if (fs.existsSync(agentsDir)) {
      const agents = fs.readdirSync(agentsDir).filter(f => f.endsWith('.md'))
      for (const agent of agents) {
        try {
          const r = processAgent(pack, agent)
          results.agents.push(r)
        } catch (e) {
          results.errors.push({ file: `${pack}/agents/${agent}`, error: e.message })
        }
      }
      console.log(`    agents:   ${agents.length}`)
    }

    // Process commands
    const commandsDir = path.join(PACKS_DIR, pack, 'commands')
    if (fs.existsSync(commandsDir)) {
      const commandFiles = []
      function walkCommands(dir, prefix = '') {
        for (const entry of fs.readdirSync(dir)) {
          const full = path.join(dir, entry)
          if (fs.statSync(full).isDirectory()) {
            walkCommands(full, prefix ? `${prefix}/${entry}` : entry)
          } else if (entry.endsWith('.md')) {
            commandFiles.push(prefix ? `${prefix}/${entry}` : entry)
          }
        }
      }
      walkCommands(commandsDir)

      for (const cmd of commandFiles) {
        try {
          const r = processCommand(pack, cmd)
          results.skills.push(r)
        } catch (e) {
          results.errors.push({ file: `${pack}/commands/${cmd}`, error: e.message })
        }
      }
      console.log(`    commands: ${commandFiles.length} → skills`)
    }

    // Process pack skills
    const skillsDir = path.join(PACKS_DIR, pack, 'skills')
    if (fs.existsSync(skillsDir)) {
      const skillPaths = []
      function walkSkills(dir, prefix = '') {
        for (const entry of fs.readdirSync(dir)) {
          const full = path.join(dir, entry)
          if (fs.statSync(full).isDirectory()) {
            // If this dir has SKILL.md, it's a skill
            if (fs.existsSync(path.join(full, 'SKILL.md'))) {
              skillPaths.push(prefix ? `${prefix}/${entry}` : entry)
            }
            // Also recurse for nested skills
            walkSkills(full, prefix ? `${prefix}/${entry}` : entry)
          }
        }
      }
      walkSkills(skillsDir)

      for (const sp of skillPaths) {
        try {
          const r = processPackSkill(pack, sp)
          if (r) results.skills.push(r)
        } catch (e) {
          results.errors.push({ file: `${pack}/skills/${sp}`, error: e.message })
        }
      }
      console.log(`    skills:   ${skillPaths.length} → relocated`)
    }

    console.log()
  }

  // Add existing core skills to registry
  if (fs.existsSync(SKILLS_DIR)) {
    const existingSkills = fs.readdirSync(SKILLS_DIR).filter(d => {
      const skillFile = path.join(SKILLS_DIR, d, 'SKILL.md')
      return fs.statSync(path.join(SKILLS_DIR, d)).isDirectory() && fs.existsSync(skillFile)
    })

    for (const skillDir of existingSkills) {
      // Skip if already in registry (from pack conversion)
      if (registry.skills.some(s => s.name === skillDir)) continue

      const skillFile = path.join(SKILLS_DIR, skillDir, 'SKILL.md')
      const content = fs.readFileSync(skillFile, 'utf8')
      const { meta } = parseFrontmatter(content)

      registry.skills.push({
        name: meta.name || skillDir,
        dir: `.claude/skills/${skillDir}/`,
        category: 'core',
        source: 'core',
        description: meta.description || ''
      })
    }
  }

  // Write registry
  if (EXECUTE || REGISTRY_ONLY) {
    fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2) + '\n')
    console.log(`  Registry written: ${REGISTRY_PATH}`)
  }

  // Summary
  console.log(`\n  ── Summary ──`)
  console.log(`  Agents:  ${results.agents.length} processed`)
  console.log(`  Skills:  ${results.skills.length} processed`)
  console.log(`  Errors:  ${results.errors.length}`)

  if (results.errors.length > 0) {
    console.log(`\n  ── Errors ──`)
    for (const e of results.errors) {
      console.log(`  ${e.file}: ${e.error}`)
    }
  }

  const catSummary = Object.entries(registry.categories)
    .map(([k, v]) => `    ${k}: ${v.agents}a ${v.skills}s`)
    .join('\n')
  console.log(`\n  ── Categories ──\n${catSummary}`)

  console.log(`\n  Registry: ${registry.agents.length} agents + ${registry.skills.length} skills`)

  if (!EXECUTE && !REGISTRY_ONLY) {
    console.log(`\n  This was a dry run. Use --execute to write files.\n`)
  }
}

main()
