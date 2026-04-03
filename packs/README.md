# NOMARK Plugin Packs

Optional capability extensions for NOMARK v2. Core provides governance and discipline. Packs add domain-specific agents, commands, and skills.

## Available Packs

| Pack | Contents | Use Case |
|------|----------|----------|
| `security` | OWASP agents, security skills, scan commands | Security audits, vulnerability detection |
| `business` | McKinsey suite + SEO agents, growth skills, startup commands | Business strategy, GTM, financial modeling, SEO |
| `languages` | Language-specific agents (python-pro, typescript-pro, etc.) | Per-language expertise |
| `infra` | Terraform, K8s, cloud, deployment agents + ops commands | Infrastructure, DevOps, operations |
| `discovery` | Empathy engine, persona panels, silence audit, HMW | Human-centered design, user research |
| `quality` | Code review, debugging, design systems, C4 architecture | Code quality, review, documentation |
| `team` | Multi-agent orchestration, conductor track management | Parallel story execution, team workflows |
| `feature` | Full-stack, API scaffold, data-driven, multi-platform | Feature development workflows |
| `data` | Data engineering, ML/AI, vector databases, LLM integration | Data pipelines, ML ops, AI features |

## Install a Pack

```bash
/install security     # Install the security pack
/install business     # Install the business pack
/install --list       # Show available packs
```

Or manually:
```bash
# Copy pack contents into your .claude/ directory
cp -r nomark_v2/packs/security/agents/* .claude/agents/
cp -r nomark_v2/packs/security/skills/* .claude/skills/
cp -r nomark_v2/packs/security/commands/* .claude/commands/
```

## Pack Manifest Format

Each pack has a `plugin.json`:

```json
{
  "name": "pack-name",
  "version": "1.0.0",
  "description": "What this pack provides",
  "agents": [
    { "file": "agents/agent-name.md", "description": "What it does" }
  ],
  "commands": [
    { "file": "commands/namespace/command.md", "description": "What it does" }
  ],
  "skills": [
    { "dir": "skills/skill-name/", "description": "What it does" }
  ],
  "token_impact": "~X agent defs + Y commands + Z skills loaded into context"
}
```

## Creating a Pack

1. Create a directory under `packs/` with your pack name
2. Add `plugin.json` with the format above
3. Add your agents, commands, and skills files
4. Estimate token impact (count of definitions that load into context)
5. Test: install into a project and verify `/verify` passes

## Token Impact

Every pack increases context token consumption. The core loads ~10 agents + ~35 commands + 13 skills. Each pack adds to this. Plan accordingly — stay under 80 total tools.

| Pack | Agents | Commands | Skills | Estimated Impact |
|------|--------|----------|--------|-----------------|
| security | 6 | 6 | 7 | Medium |
| business | 26 | 8 | 14 | High (install selectively) |
| languages | 26 | 0 | 0 | High (install selectively) |
| infra | 14 | 18 | 21 | High |
| discovery | 2 | 4 | 4 | Low |
| quality | ~20 | ~23 | 0 | High |
| team | 0 | 13 | ~3 | Medium |
| feature | 0 | 9 | 0 | Low |
| data | ~11 | 4 | ~20 | High |

## Recommended Install Order

1. **Always:** Core (included by default)
2. **Most projects:** `security` (medium impact, high value)
3. **Your language:** `languages` (install only the ones you use)
4. **If building features:** `quality` + `feature`
5. **If team/parallel work:** `team`
6. **If deploying:** `infra`
7. **If data/ML work:** `data`
8. **If business strategy:** `business`
9. **If user research:** `discovery`
