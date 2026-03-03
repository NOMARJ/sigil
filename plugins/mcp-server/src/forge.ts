/**
 * Sigil Forge MCP Tools
 * Discovery and curation tools for AI agent skills and MCP servers
 */

import { z } from "zod";
import { request as httpsRequest } from "https";
import { request as httpRequest } from "http";

const FORGE_API_URL = process.env.FORGE_API_URL ?? "https://api.sigilsec.ai/forge";
const SIGIL_API_URL = process.env.SIGIL_API_URL ?? "https://api.sigilsec.ai";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ToolMatch {
  name: string;
  ecosystem: "skill" | "mcp";
  category: string;
  description: string;
  capabilities: string[];
  trust_score: number;
  verdict: string;
  install_command?: string;
  github_url?: string;
  compatibility_signals?: string[];
}

export interface ForgeStack {
  name: string;
  use_case: string;
  description: string;
  tools: ToolMatch[];
  install_instructions: string[];
  trust_summary: {
    overall_risk: string;
    highest_risk_tool?: string;
    lowest_risk_tool?: string;
    average_trust_score: number;
  };
}

export interface ToolCheckResult {
  name: string;
  ecosystem: "skill" | "mcp";
  category: string;
  capabilities: string[];
  trust_score: number;
  verdict: string;
  permissions: {
    env_vars?: string[];
    file_access?: string[];
    network?: string[];
    system_calls?: string[];
  };
  alternatives?: ToolMatch[];
  last_scanned?: string;
  findings_summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function fetchForgeAPI<T = unknown>(path: string, options?: {
  method?: string;
  body?: unknown;
}): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, FORGE_API_URL);
    const doRequest = url.protocol === "http:" ? httpRequest : httpsRequest;
    
    const requestOptions: any = {
      method: options?.method ?? "GET",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Sigil-Forge-MCP/1.0",
      },
    };

    const req = doRequest(url, requestOptions, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString();
        const statusCode = res.statusCode ?? 0;
        if (statusCode < 200 || statusCode >= 300) {
          reject(new Error(`HTTP ${statusCode}: ${body.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(body) as T);
        } catch {
          resolve(body as T);
        }
      });
    });
    
    req.on("error", reject);
    req.setTimeout(30_000, () => {
      req.destroy(new Error("Request timed out"));
    });
    
    if (options?.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

// In-memory cache for classification data (refreshed periodically)
let classificationCache: Map<string, ToolMatch> = new Map();
let cacheLastRefresh = 0;
const CACHE_TTL = 3600000; // 1 hour

async function refreshClassificationCache(): Promise<void> {
  if (Date.now() - cacheLastRefresh < CACHE_TTL) {
    return;
  }
  
  try {
    // Fetch classified tools from Forge API
    const skills = await fetchForgeAPI<ToolMatch[]>("/classifications/skills");
    const mcps = await fetchForgeAPI<ToolMatch[]>("/classifications/mcps");
    
    classificationCache.clear();
    
    for (const skill of skills) {
      classificationCache.set(`skill:${skill.name}`, skill);
    }
    
    for (const mcp of mcps) {
      classificationCache.set(`mcp:${mcp.name}`, mcp);
    }
    
    cacheLastRefresh = Date.now();
  } catch (error) {
    // Fallback to basic search if classification service is unavailable
    console.error("Failed to refresh classification cache:", error);
  }
}

// Semantic search implementation
function semanticSearch(query: string, type: "skill" | "mcp" | "both"): ToolMatch[] {
  const results: ToolMatch[] = [];
  const queryLower = query.toLowerCase();
  const queryTerms = queryLower.split(/\s+/);
  
  for (const [key, tool] of classificationCache.entries()) {
    if (type !== "both" && !key.startsWith(type + ":")) {
      continue;
    }
    
    // Score based on multiple factors
    let score = 0;
    
    // Name matching
    if (tool.name.toLowerCase().includes(queryLower)) {
      score += 10;
    }
    
    // Description matching
    const descLower = tool.description.toLowerCase();
    for (const term of queryTerms) {
      if (descLower.includes(term)) {
        score += 5;
      }
    }
    
    // Category matching
    if (tool.category.toLowerCase().includes(queryLower)) {
      score += 8;
    }
    
    // Capability matching
    for (const cap of tool.capabilities) {
      for (const term of queryTerms) {
        if (cap.toLowerCase().includes(term)) {
          score += 3;
        }
      }
    }
    
    // Apply trust score as a weight
    score *= (tool.trust_score / 100);
    
    if (score > 0) {
      results.push({ ...tool, score } as any);
    }
  }
  
  // Sort by score and return top results
  results.sort((a: any, b: any) => b.score - a.score);
  return results.slice(0, 20);
}

// Stack recommendation logic
async function recommendStack(useCase: string): Promise<ForgeStack> {
  await refreshClassificationCache();
  
  const useCaseLower = useCase.toLowerCase();
  const tools: ToolMatch[] = [];
  
  // Analyze use case to determine needed capabilities
  const neededCapabilities: Set<string> = new Set();
  
  // Database-related keywords
  if (/database|postgres|mysql|mongodb|redis|sql/i.test(useCase)) {
    neededCapabilities.add("database");
    neededCapabilities.add("query");
  }
  
  // API/Web-related keywords
  if (/api|web|http|rest|graphql|webhook/i.test(useCase)) {
    neededCapabilities.add("api");
    neededCapabilities.add("http");
    neededCapabilities.add("web");
  }
  
  // File system keywords
  if (/file|directory|folder|read|write|search/i.test(useCase)) {
    neededCapabilities.add("filesystem");
    neededCapabilities.add("file_access");
  }
  
  // AI/LLM keywords
  if (/ai|llm|prompt|rag|embedding|vector|chat/i.test(useCase)) {
    neededCapabilities.add("ai");
    neededCapabilities.add("llm");
    neededCapabilities.add("prompt");
  }
  
  // Code/Development keywords
  if (/code|lint|test|format|build|compile|git/i.test(useCase)) {
    neededCapabilities.add("code");
    neededCapabilities.add("development");
    neededCapabilities.add("git");
  }
  
  // Security keywords
  if (/security|scan|audit|vulnerability|secret/i.test(useCase)) {
    neededCapabilities.add("security");
    neededCapabilities.add("scanning");
  }
  
  // Find matching tools
  const mcpTools: ToolMatch[] = [];
  const skillTools: ToolMatch[] = [];
  
  for (const [key, tool] of classificationCache.entries()) {
    let matchScore = 0;
    
    for (const cap of tool.capabilities) {
      if (neededCapabilities.has(cap.toLowerCase())) {
        matchScore += 10;
      }
    }
    
    // Also check description
    for (const needed of neededCapabilities) {
      if (tool.description.toLowerCase().includes(needed)) {
        matchScore += 5;
      }
    }
    
    if (matchScore > 0) {
      if (key.startsWith("mcp:")) {
        mcpTools.push({ ...tool, matchScore } as any);
      } else if (key.startsWith("skill:")) {
        skillTools.push({ ...tool, matchScore } as any);
      }
    }
  }
  
  // Sort by match score and trust
  mcpTools.sort((a: any, b: any) => (b.matchScore * b.trust_score) - (a.matchScore * a.trust_score));
  skillTools.sort((a: any, b: any) => (b.matchScore * b.trust_score) - (a.matchScore * a.trust_score));
  
  // Build the stack (top MCP + top 2 skills)
  if (mcpTools.length > 0) {
    tools.push(mcpTools[0]);
  }
  if (skillTools.length > 0) {
    tools.push(...skillTools.slice(0, 2));
  }
  
  // Generate install instructions
  const installInstructions: string[] = [];
  
  for (const tool of tools) {
    if (tool.install_command) {
      installInstructions.push(tool.install_command);
    } else if (tool.ecosystem === "mcp" && tool.github_url) {
      installInstructions.push(`# Add to claude_desktop_config.json:\n# "${tool.name}": { "command": "npx", "args": ["${tool.github_url}"] }`);
    } else if (tool.ecosystem === "skill") {
      installInstructions.push(`npx skills add ${tool.name}`);
    }
  }
  
  // Calculate trust summary
  const trustScores = tools.map(t => t.trust_score);
  const avgTrust = trustScores.length > 0 
    ? trustScores.reduce((a, b) => a + b, 0) / trustScores.length 
    : 0;
  
  const highestRisk = tools.reduce((prev, curr) => 
    curr.trust_score < prev.trust_score ? curr : prev, tools[0]);
  
  const lowestRisk = tools.reduce((prev, curr) => 
    curr.trust_score > prev.trust_score ? curr : prev, tools[0]);
  
  // Determine stack name based on primary capability
  let stackName = "Custom Stack";
  if (neededCapabilities.has("database")) {
    stackName = "Database Agent Stack";
  } else if (neededCapabilities.has("api")) {
    stackName = "API Integration Stack";
  } else if (neededCapabilities.has("ai")) {
    stackName = "AI/LLM Stack";
  } else if (neededCapabilities.has("code")) {
    stackName = "Code Development Stack";
  } else if (neededCapabilities.has("security")) {
    stackName = "Security Audit Stack";
  }
  
  return {
    name: stackName,
    use_case: useCase,
    description: `Recommended tools for: ${useCase}`,
    tools,
    install_instructions: installInstructions,
    trust_summary: {
      overall_risk: avgTrust > 90 ? "LOW_RISK" : avgTrust > 70 ? "MEDIUM_RISK" : "HIGH_RISK",
      highest_risk_tool: highestRisk?.name,
      lowest_risk_tool: lowestRisk?.name,
      average_trust_score: Math.round(avgTrust),
    },
  };
}

// ── Tool: forge_search ─────────────────────────────────────────────────────

export const forgeSearchSchema = {
  query: z.string().describe("Search query for tools (e.g., 'postgres database', 'web scraping')"),
  type: z.enum(["skill", "mcp", "both"]).optional().default("both").describe("Filter by tool type"),
};

export async function forgeSearch({ query, type = "both" }: { query: string; type?: "skill" | "mcp" | "both" }) {
  await refreshClassificationCache();
  
  // Perform semantic search
  const results = semanticSearch(query, type);
  
  if (results.length === 0) {
    // Fallback to API search if no cache hits
    try {
      const apiResults = await fetchForgeAPI<{ items: ToolMatch[] }>(
        `/search?q=${encodeURIComponent(query)}&type=${type}`
      );
      results.push(...(apiResults.items || []));
    } catch (error) {
      console.error("Forge API search failed:", error);
    }
  }
  
  // Format response
  let response = `Found ${results.length} tool(s) matching "${query}":\n`;
  
  for (const tool of results.slice(0, 10)) {
    response += `\n[${tool.verdict}] ${tool.ecosystem}/${tool.name} — ${tool.category}\n`;
    response += `  Trust Score: ${tool.trust_score}/100\n`;
    response += `  ${tool.description}\n`;
    response += `  Capabilities: ${tool.capabilities.slice(0, 3).join(", ")}\n`;
    if (tool.install_command) {
      response += `  Install: ${tool.install_command}\n`;
    }
  }
  
  if (results.length > 10) {
    response += `\n... and ${results.length - 10} more results`;
  }
  
  response += "\n\nUse forge_check to get detailed information about a specific tool.";
  
  return {
    content: [{ type: "text" as const, text: response }],
  };
}

// ── Tool: forge_stack ──────────────────────────────────────────────────────

export const forgeStackSchema = {
  use_case: z.string().describe("Description of what you want your agent to do (e.g., 'query a Postgres database and generate reports')"),
};

export async function forgeStack({ use_case }: { use_case: string }) {
  const stack = await recommendStack(use_case);
  
  let response = `## ${stack.name}\n\n`;
  response += `Use Case: ${stack.use_case}\n\n`;
  response += `### Recommended Tools (${stack.tools.length}):\n`;
  
  for (const tool of stack.tools) {
    response += `\n**${tool.ecosystem}/${tool.name}**\n`;
    response += `  Category: ${tool.category}\n`;
    response += `  Trust Score: ${tool.trust_score}/100 (${tool.verdict})\n`;
    response += `  ${tool.description}\n`;
    response += `  Capabilities: ${tool.capabilities.join(", ")}\n`;
  }
  
  response += `\n### Installation:\n\`\`\`bash\n${stack.install_instructions.join("\n")}\n\`\`\`\n`;
  
  response += `\n### Trust Summary:\n`;
  response += `  Overall Risk: ${stack.trust_summary.overall_risk}\n`;
  response += `  Average Trust Score: ${stack.trust_summary.average_trust_score}/100\n`;
  if (stack.trust_summary.highest_risk_tool) {
    response += `  Highest Risk Tool: ${stack.trust_summary.highest_risk_tool}\n`;
  }
  if (stack.trust_summary.lowest_risk_tool) {
    response += `  Lowest Risk Tool: ${stack.trust_summary.lowest_risk_tool}\n`;
  }
  
  response += `\n### Compatibility Notes:\n`;
  response += `These tools were selected based on complementary capabilities and shared requirements.\n`;
  response += `Run 'sigil scan' on each tool before installation for detailed security analysis.`;
  
  return {
    content: [{ type: "text" as const, text: response }],
  };
}

// ── Tool: forge_check ──────────────────────────────────────────────────────

export const forgeCheckSchema = {
  name: z.string().describe("Name of the skill or MCP server to check"),
  ecosystem: z.enum(["skill", "mcp"]).describe("Tool ecosystem"),
};

export async function forgeCheck({ name, ecosystem }: { name: string; ecosystem: "skill" | "mcp" }) {
  await refreshClassificationCache();
  
  // Check cache first
  const cacheKey = `${ecosystem}:${name}`;
  let toolInfo = classificationCache.get(cacheKey);
  
  if (!toolInfo) {
    // Fetch from API if not in cache
    try {
      toolInfo = await fetchForgeAPI<ToolMatch>(`/tools/${ecosystem}/${encodeURIComponent(name)}`);
    } catch (error) {
      return {
        content: [{
          type: "text" as const,
          text: `Tool not found: ${ecosystem}/${name}. It may not have been classified yet.`,
        }],
      };
    }
  }
  
  // Fetch detailed scan results from Sigil API
  let scanDetails: any = null;
  try {
    const sigilEcosystem = ecosystem === "skill" ? "clawhub" : "github";
    scanDetails = await fetchForgeAPI(`${SIGIL_API_URL}/registry/${sigilEcosystem}/${encodeURIComponent(name)}`);
  } catch (error) {
    // Scan details are optional
  }
  
  let response = `## ${ecosystem}/${name}\n\n`;
  response += `**Category:** ${toolInfo.category}\n`;
  response += `**Trust Score:** ${toolInfo.trust_score}/100 (${toolInfo.verdict})\n`;
  response += `**Description:** ${toolInfo.description}\n\n`;
  
  response += `### Capabilities:\n`;
  for (const cap of toolInfo.capabilities) {
    response += `- ${cap}\n`;
  }
  
  // Extract permissions from scan details if available
  if (scanDetails?.findings) {
    const permissions: any = {
      env_vars: new Set<string>(),
      file_access: new Set<string>(),
      network: new Set<string>(),
      system_calls: new Set<string>(),
    };
    
    for (const finding of scanDetails.findings) {
      if (finding.phase === "credentials" && finding.snippet) {
        // Extract env var names
        const envMatch = finding.snippet.match(/process\.env\.(\w+)|ENV\[['"](\w+)['"]\]/);
        if (envMatch) {
          permissions.env_vars.add(envMatch[1] || envMatch[2]);
        }
      }
      if (finding.phase === "network_exfil" && finding.snippet) {
        // Extract network endpoints
        const urlMatch = finding.snippet.match(/https?:\/\/[^\s'"]+/);
        if (urlMatch) {
          permissions.network.add(urlMatch[0]);
        }
      }
      if (finding.phase === "code_patterns" && finding.rule?.includes("exec")) {
        permissions.system_calls.add(finding.rule);
      }
    }
    
    response += `\n### Permissions Required:\n`;
    if (permissions.env_vars.size > 0) {
      response += `**Environment Variables:** ${Array.from(permissions.env_vars).join(", ")}\n`;
    }
    if (permissions.network.size > 0) {
      response += `**Network Access:** ${Array.from(permissions.network).slice(0, 3).join(", ")}\n`;
    }
    if (permissions.system_calls.size > 0) {
      response += `**System Calls:** ${Array.from(permissions.system_calls).join(", ")}\n`;
    }
    
    // Add findings summary
    const findingsBySeverity: any = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of scanDetails.findings) {
      const severity = finding.severity?.toLowerCase() || "low";
      findingsBySeverity[severity] = (findingsBySeverity[severity] || 0) + 1;
    }
    
    response += `\n### Security Findings:\n`;
    response += `- Critical: ${findingsBySeverity.critical}\n`;
    response += `- High: ${findingsBySeverity.high}\n`;
    response += `- Medium: ${findingsBySeverity.medium}\n`;
    response += `- Low: ${findingsBySeverity.low}\n`;
    
    if (scanDetails.scanned_at) {
      response += `\nLast Scanned: ${new Date(scanDetails.scanned_at).toISOString()}\n`;
    }
  }
  
  // Find alternatives
  const alternatives = semanticSearch(toolInfo.category, ecosystem as any)
    .filter(t => t.name !== name)
    .slice(0, 3);
  
  if (alternatives.length > 0) {
    response += `\n### Alternative Tools:\n`;
    for (const alt of alternatives) {
      response += `- ${alt.ecosystem}/${alt.name} (Trust: ${alt.trust_score}/100)\n`;
    }
  }
  
  // Installation instructions
  response += `\n### Installation:\n`;
  if (toolInfo.install_command) {
    response += `\`\`\`bash\n${toolInfo.install_command}\n\`\`\`\n`;
  } else if (ecosystem === "mcp" && toolInfo.github_url) {
    response += `Add to claude_desktop_config.json:\n`;
    response += `\`\`\`json\n"${name}": {\n  "command": "npx",\n  "args": ["${toolInfo.github_url}"]\n}\n\`\`\`\n`;
  } else if (ecosystem === "skill") {
    response += `\`\`\`bash\nnpx skills add ${name}\n\`\`\`\n`;
  }
  
  response += `\n### Recommendations:\n`;
  if (toolInfo.trust_score >= 90) {
    response += `✅ This tool has a high trust score and appears safe to use.\n`;
  } else if (toolInfo.trust_score >= 70) {
    response += `⚠️ This tool has a moderate trust score. Review the findings before use.\n`;
  } else {
    response += `❌ This tool has a low trust score. Consider alternatives or thorough review.\n`;
  }
  response += `Always run 'sigil scan' for detailed security analysis before installation.`;
  
  return {
    content: [{ type: "text" as const, text: response }],
  };
}