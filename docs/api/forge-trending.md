# Forge Trending API Documentation

This document describes the Forge API endpoints for trending tools and enhanced search functionality.

## Table of Contents

- [Trending Tools Endpoint](#trending-tools-endpoint)
- [Enhanced Search with Sorting](#enhanced-search-with-sorting)
- [Response Models](#response-models)
- [Error Handling](#error-handling)
- [Integration Guide](#integration-guide)

## Trending Tools Endpoint

### GET `/forge/trending`

Get trending tools based on downloads, stars, and growth metrics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeframe` | string | `"7d"` | Time period for trending calculation (`24h`, `7d`, `30d`) |
| `ecosystem` | string | `"all"` | Filter by tool ecosystem (`all`, `npm`, `pypi`, `github`, `skills`, `mcps`) |
| `category` | string | `"all"` | Filter by tool category (`all`, `ai_llm_tools`, `api_integrations`, etc.) |
| `limit` | integer | `20` | Maximum results to return (1-100) |

**Response Format:**

```json
{
  "tools": [
    {
      "tool_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "rank": 1,
      "rank_change": 2,
      "direction": "up",
      "growth_percentage": 45.2,
      "downloads": 15420,
      "stars": 342,
      "trust_score": 87.5,
      "downloads_growth": 45.2,
      "stars_growth": 12.3,
      "composite_score": 89.7,
      "timeframe": "7d",
      "ecosystem": "npm",
      "category": "ai_llm_tools"
    }
  ],
  "total": 25,
  "timeframe": "7d",
  "ecosystem": "npm", 
  "category": "all",
  "limit": 20,
  "generated_at": "2026-03-08T18:45:00.123Z",
  "response_time_ms": 145.2
}
```

**Trending Score Algorithm:**

The composite trending score is calculated using:
- 40% downloads weight
- 30% growth rate weight  
- 20% stars weight
- 10% trust score weight

**Performance:**
- Response time target: <200ms with caching
- Cache TTL: 1 hour

### Example Requests

**Get trending tools for the last 7 days:**
```bash
curl 'http://localhost:8000/forge/trending?timeframe=7d&limit=10'
```

**Get trending npm packages:**
```bash
curl 'http://localhost:8000/forge/trending?timeframe=30d&ecosystem=npm&limit=20'
```

**Get trending AI/LLM tools:**
```bash
curl 'http://localhost:8000/forge/trending?timeframe=24h&category=ai_llm_tools&limit=15'
```

## Enhanced Search with Sorting

### GET `/forge/search`

Search tools with enhanced sorting capabilities.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `q` | string | `""` | Search query |
| `ecosystem` | string | `null` | Filter by ecosystem |
| `type` | string | `null` | Compatibility filter (`skill`, `mcp`) |
| `category` | string | `null` | Filter by category |
| `min_trust` | number | `null` | Minimum trust score |
| `sort` | string | `"trending"` | Sort by (`trending`, `downloads`, `stars`, `newest`) |
| `order` | string | `"desc"` | Order (`asc`, `desc`) |
| `limit` | integer | `20` | Maximum results |

**Response Format:**

```json
{
  "query": "database",
  "tools": [
    {
      "id": "db123-456-789",
      "slug": "postgres-connector",
      "name": "@mcp/postgres",
      "ecosystem": "mcps",
      "category": "database_connectors",
      "capabilities": ["database", "network"],
      "trust_score": 92,
      "verdict": "LOW_RISK",
      "compatibility_signals": ["env_vars:DATABASE_URL", "database:postgres_compatible"],
      "github_url": "https://github.com/mcp/postgres",
      "install_command": "npm install @mcp/postgres",
      "description": "PostgreSQL database connector for MCP",
      "downloads": 8421,
      "stars": 156,
      "author": "MCP Team",
      "version": "1.2.0",
      "last_updated": "2026-03-07T14:30:00Z"
    }
  ],
  "total": 147,
  "sort_metadata": {
    "sort": "trending",
    "order": "desc",
    "supported_sorts": ["trending", "downloads", "stars", "newest"]
  }
}
```

### Sorting Options

**`trending` (default):**
- Composite score based on downloads (40%), stars (30%), trust score (30%)
- Best for discovering popular and reliable tools

**`downloads`:**
- Sort by download count
- Best for finding widely-used tools

**`stars`:**
- Sort by GitHub stars count
- Best for community-endorsed tools

**`newest`:**
- Sort by last updated timestamp
- Best for finding recently updated tools

### Example Search Requests

**Search with trending sort (default):**
```bash
curl 'http://localhost:8000/forge/search?q=database&sort=trending&order=desc'
```

**Search by downloads descending:**
```bash
curl 'http://localhost:8000/forge/search?q=api&sort=downloads&order=desc&limit=10'
```

**Search newest tools first:**
```bash
curl 'http://localhost:8000/forge/search?ecosystem=npm&sort=newest&order=desc'
```

**Search with multiple filters:**
```bash
curl 'http://localhost:8000/forge/search?q=postgres&category=database_connectors&sort=stars&min_trust=80'
```

## Response Models

### TrendingToolResponse

```typescript
interface TrendingToolResponse {
  tool_id: string;           // Unique tool identifier
  rank: number;              // Current ranking position  
  rank_change: number;       // Change in rank (+/-)
  direction: "up" | "down" | "stable" | "new";
  growth_percentage: number;  // Overall growth percentage
  downloads: number;         // Current downloads
  stars: number;            // Current stars 
  trust_score: number;      // Trust score (0-100)
  downloads_growth: number; // Downloads growth %
  stars_growth: number;     // Stars growth %
  composite_score: number;  // Calculated trending score
  timeframe: "24h" | "7d" | "30d";
  ecosystem: string;
  category: string;
}
```

### SearchResponse

```typescript
interface SearchResponse {
  query: string;
  tools: ToolDetails[];
  total: number;
  sort_metadata: {
    sort: string;
    order: string;
    supported_sorts: string[];
  };
}
```

## Error Handling

### HTTP Status Codes

- `200 OK` - Success
- `400 Bad Request` - Invalid parameters
- `404 Not Found` - No results found
- `500 Internal Server Error` - Server error

### Error Response Format

```json
{
  "detail": "Invalid timeframe 'invalid'. Must be one of: 24h, 7d, 30d"
}
```

### Common Errors

**Invalid Timeframe:**
```bash
# Returns 400 Bad Request
curl 'http://localhost:8000/forge/trending?timeframe=invalid'
```

**Invalid Sort Parameter:**
- Invalid sort values default to 'trending'
- No error thrown, but warning logged

**Rate Limiting:**
- API includes caching to prevent excessive requests
- Cache TTL: 1 hour for trending, no-cache for search

## Integration Guide

### Frontend Integration

**1. Load trending tools:**
```javascript
const response = await fetch('/forge/trending?timeframe=7d&limit=10');
const data = await response.json();
console.log(`Found ${data.total} trending tools`);
```

**2. Search with sorting:**
```javascript
const searchParams = new URLSearchParams({
  q: 'database',
  sort: 'downloads',
  order: 'desc',
  limit: '20'
});

const response = await fetch(`/forge/search?${searchParams}`);
const data = await response.json();
console.log(`Sort: ${data.sort_metadata.sort} ${data.sort_metadata.order}`);
```

### Agent Integration

**MCP-compatible endpoints available:**
- `/forge/mcp/search` - Simplified search for agents
- `/forge/mcp/stack` - Stack generation for agents
- `/forge/mcp/check` - Tool verification for agents

**Example agent usage:**
```bash
curl 'http://localhost:8000/forge/mcp/search?query=postgres&type=mcp&limit=5'
```

### Caching Strategy

**Trending Endpoint:**
- Server-side cache: 1 hour TTL
- Client-side cache: `Cache-Control: public, max-age=3600`

**Search Endpoint:**
- Server-side cache: None (real-time)
- Client-side cache: `Cache-Control: no-cache, no-store`

### Performance Monitoring

**Response Time Headers:**
```
X-Response-Time: 145.2ms
```

**Performance Targets:**
- Trending API: <200ms
- Search API: <100ms
- Warning logged if targets exceeded

### Timeframe Options

| Timeframe | Description | Cache TTL |
|-----------|-------------|-----------|
| `24h` | Last 24 hours | 30 min |
| `7d` | Last 7 days | 1 hour |
| `30d` | Last 30 days | 2 hours |

### Ecosystem Filters

- `all` - All ecosystems
- `npm` - NPM packages
- `pypi` - Python packages
- `github` - GitHub repositories
- `skills` - AI agent skills
- `mcps` - MCP servers

### Category Filters

- `ai_llm_tools` - AI/LLM related tools
- `api_integrations` - API integration tools
- `database_connectors` - Database connectors
- `code_tools` - Development tools
- `security_tools` - Security tools
- `file_system_tools` - File system tools
- `devops_tools` - DevOps tools
- And more...

---

**API Version:** 1.0  
**Last Updated:** March 8, 2026  
**Base URL:** `http://localhost:8000/forge`