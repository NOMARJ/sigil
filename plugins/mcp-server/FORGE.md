# Sigil Forge MCP Server

Discovery and security tools for AI agent skills and MCP servers.

## Overview

The Sigil Forge MCP Server extends the core Sigil security scanning capabilities with discovery tools that help AI agents find, evaluate, and compose their own toolchains. It provides semantic search, compatibility matching, and curated stack recommendations — all with trust scores from Sigil's security scans.

## Installation

```bash
npm install -g @nomark/sigil-mcp-server
```

## Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "sigil-mcp-server"
    }
  }
}
```

## Forge Discovery Tools

### forge_search
Search for AI agent skills and MCP servers by capability or keyword.

**Input:**
- `query` (string): Search query (e.g., "postgres database", "web scraping")
- `type` (string, optional): Filter by "skill", "mcp", or "both" (default: "both")

**Output:**
Ranked list of matching tools with:
- Trust scores (0-100)
- Security verdicts (LOW_RISK, MEDIUM_RISK, HIGH_RISK, CRITICAL_RISK)
- Categories and capabilities
- Installation commands

**Example:**
```
Agent: forge_search("postgres database", "mcp")

Response:
Found 3 tool(s) matching "postgres database":

[LOW_RISK] mcp/mcp-postgres — Database Connectors
  Trust Score: 92/100
  MCP server for PostgreSQL database queries
  Capabilities: database, authentication, network
  Install: Add to claude_desktop_config.json

[MEDIUM_RISK] mcp/postgres-admin — Database Connectors
  Trust Score: 75/100
  PostgreSQL administration tools
  Capabilities: database, system_calls, file_system
```

### forge_stack
Get a curated stack of compatible tools for your use case.

**Input:**
- `use_case` (string): Description of what you want your agent to do

**Output:**
A "Forge Stack" containing:
- Matched skill + MCP combinations
- Installation instructions
- Compatibility analysis
- Trust summary with risk assessment

**Example:**
```
Agent: forge_stack("I want to query a Postgres database and generate reports")

Response:
## Database Agent Stack

Recommended Tools (3):

**mcp/mcp-postgres**
  Category: Database Connectors
  Trust Score: 92/100 (LOW_RISK)
  PostgreSQL database connector
  Capabilities: database, authentication, network

**skill/db-query-builder**
  Category: Database Connectors
  Trust Score: 88/100 (LOW_RISK)
  SQL query builder and executor
  Capabilities: database, code

**skill/report-generator**
  Category: Data Pipeline Tools
  Trust Score: 85/100 (LOW_RISK)
  Generate reports from data
  Capabilities: data_pipeline, file_system

### Installation:
```bash
# Add to claude_desktop_config.json:
"mcp-postgres": { "command": "npx", "args": ["github.com/user/mcp-postgres"] }

npx skills add db-query-builder
npx skills add report-generator
```

### Trust Summary:
  Overall Risk: LOW_RISK
  Average Trust Score: 88/100
  Highest Risk Tool: report-generator
  Lowest Risk Tool: mcp-postgres
```

### forge_check
Get detailed information about a specific tool.

**Input:**
- `name` (string): Name of the skill or MCP server
- `ecosystem` (string): "skill" or "mcp"

**Output:**
Comprehensive tool analysis including:
- Category and capabilities
- Trust score and security verdict
- Required permissions (env vars, network, files)
- Security findings summary
- Alternative tools
- Installation instructions

**Example:**
```
Agent: forge_check("mcp-postgres", "mcp")

Response:
## mcp/mcp-postgres

**Category:** Database Connectors
**Trust Score:** 92/100 (LOW_RISK)
**Description:** PostgreSQL database connector for AI agents

### Capabilities:
- database
- authentication
- network
- query execution

### Permissions Required:
**Environment Variables:** DATABASE_URL, PGPASSWORD, PGHOST
**Network Access:** localhost:5432, api.postgres.com
**System Calls:** None detected

### Security Findings:
- Critical: 0
- High: 0
- Medium: 1
- Low: 3

Last Scanned: 2024-03-01T10:30:00Z

### Alternative Tools:
- mcp/postgres-simple (Trust: 90/100)
- mcp/pg-connector (Trust: 87/100)
- skill/postgres-skill (Trust: 85/100)

### Installation:
Add to claude_desktop_config.json:
```json
"mcp-postgres": {
  "command": "npx",
  "args": ["github.com/user/mcp-postgres"]
}
```

### Recommendations:
✅ This tool has a high trust score and appears safe to use.
Always run 'sigil scan' for detailed security analysis before installation.
```

## Core Security Tools

The Forge MCP server includes all standard Sigil security tools:

- `sigil_scan` - Scan files/directories for security issues
- `sigil_scan_package` - Scan npm/pip packages before installation  
- `sigil_clone` - Clone and scan git repositories
- `sigil_check_package` - Look up package risk in database
- `sigil_quarantine` - List quarantined items
- `sigil_approve` - Approve quarantined items
- `sigil_reject` - Reject quarantined items
- `sigil_search_database` - Search the scan database
- `sigil_report_threat` - Report suspicious packages

## Tool Categories

Forge classifies tools into these categories:

- **Database Connectors**: Postgres, MySQL, MongoDB, Redis
- **API Integrations**: REST, GraphQL, webhooks
- **Code Tools**: Linting, formatting, testing
- **File/System Tools**: File operations, search
- **AI/LLM Tools**: Prompts, RAG, embeddings
- **Security Tools**: Scanning, auditing
- **DevOps Tools**: Docker, K8s, CI/CD
- **Search Tools**: Elasticsearch, semantic search
- **Communication Tools**: Slack, Discord, email
- **Data Pipeline Tools**: ETL, streaming
- **Testing Tools**: Unit, integration, E2E
- **Monitoring Tools**: Logs, metrics, traces

## Trust Scoring

Every tool receives a trust score (0-100) based on Sigil's 8-phase security scan:

| Score | Verdict | Recommendation |
|-------|---------|----------------|
| 90-100 | LOW_RISK | Safe for production |
| 70-89 | MEDIUM_RISK | Review findings first |
| 50-69 | HIGH_RISK | Significant concerns |
| 0-49 | CRITICAL_RISK | Do not use |

## Compatibility Matching

Forge identifies compatible tools by analyzing:

- **Shared environment variables** (e.g., DATABASE_URL)
- **Common protocols** (HTTP, WebSocket, gRPC)
- **Data formats** (JSON, Protocol Buffers)
- **Complementary capabilities** (e.g., database + query builder)
- **Dependency overlap** (shared libraries)

## Agent Integration

AI agents can use Forge to autonomously:

1. **Discover capabilities**: Search for tools by function
2. **Evaluate safety**: Check trust scores before installation
3. **Build toolchains**: Get compatible tool combinations
4. **Monitor changes**: Track security updates

Example agent workflow:
```python
# Agent needs database capability
tools = forge_search("database postgres")

# Check the top result
details = forge_check(tools[0].name, tools[0].ecosystem)

# If trust score is acceptable
if details.trust_score >= 80:
    # Get a full stack
    stack = forge_stack("postgres database with migrations")
    
    # Install the recommended tools
    for tool in stack.tools:
        if tool.trust_score >= 80:
            install(tool)
```

## API Backend

The Forge MCP server connects to the Sigil API at `https://api.sigilsec.ai/forge` for:

- Real-time classification data
- Updated trust scores
- Stack recommendations
- Compatibility analysis

Set custom API endpoint:
```bash
export FORGE_API_URL=https://your-api.com/forge
```

## Caching

Forge caches classification data for 1 hour to improve performance. The cache automatically refreshes when:

- TTL expires (3600 seconds)
- New classifications are available
- Force refresh is requested

## Development

### Building
```bash
npm install
npm run build
```

### Testing
```bash
npm test
```

### Running locally
```bash
npm run dev
```

## Security Considerations

- **Trust scores are automated assessments**, not security certifications
- **Always run sigil_scan** before deploying to production
- **Review all HIGH/CRITICAL findings** before use
- **Monitor tools for security updates** via Forge Weekly digest

## Support

- Documentation: https://sigilsec.ai/docs/forge
- API Status: https://status.sigilsec.ai
- Security Reports: security@sigilsec.ai
- General Support: support@sigilsec.ai

## License

MIT License - See LICENSE file for details

---

**Sigil Forge** by NOMARK | Where agent tools are tested.