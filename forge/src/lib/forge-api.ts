/**
 * Forge Backend API — Server-side proxy helper
 *
 * Used by Next.js API route handlers to proxy requests to the Forge backend
 * (api.sigilsec.ai/forge). Handles authentication, Content-Type validation,
 * and graceful fallbacks when the backend returns non-JSON (e.g. 401 HTML).
 */

const FORGE_BACKEND_URL =
  process.env.FORGE_BACKEND_URL || "https://api.sigilsec.ai/forge";
const FORGE_API_KEY = process.env.FORGE_API_KEY || "";

export interface ForgeProxyOptions {
  /** Path relative to the forge backend base URL (e.g. "/stats") */
  path: string;
  /** Query string to forward (already URL-encoded) */
  queryString?: string;
  /** HTTP method (defaults to GET) */
  method?: string;
}

/**
 * Fetch from the Forge backend with proper auth headers and Content-Type
 * validation. Returns the parsed JSON body on success, or throws with a
 * descriptive message on failure.
 */
export async function forgeBackendFetch<T>(
  options: ForgeProxyOptions
): Promise<T> {
  const { path, queryString, method = "GET" } = options;
  const qs = queryString ? `?${queryString}` : "";
  const url = `${FORGE_BACKEND_URL}${path}${qs}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "Sigil-Frontend/1.0",
    Accept: "application/json",
  };

  if (FORGE_API_KEY) {
    headers["Authorization"] = `Bearer ${FORGE_API_KEY}`;
  }

  const response = await fetch(url, { method, headers });

  // Validate that we got JSON back before trying to parse
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    throw new Error(
      `Expected JSON response but got ${contentType || "unknown"} (HTTP ${response.status})`
    );
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(
      (body as Record<string, string>).detail ||
        `Backend returned HTTP ${response.status}`
    );
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Fallback data — used when the backend is unreachable or returns errors
// ---------------------------------------------------------------------------

export const FALLBACK_STATS = {
  total_tools: 0,
  total_categories: 0,
  total_matches: 0,
  mcp_servers: 0,
  skills_count: 0,
  npm_packages: 0,
  pypi_packages: 0,
  ecosystems: {},
  categories: {},
  trust_score_distribution: { low: 0, medium: 0, high: 0, critical: 0 },
  recent_scans: [],
  top_categories: [],
  last_updated: new Date().toISOString(),
};

export const FALLBACK_CATEGORIES: never[] = [];

export const FALLBACK_SEARCH = {
  query: "",
  items: [],
  total: 0,
};
