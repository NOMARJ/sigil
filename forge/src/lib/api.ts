// Forge API Client
import {
  Tool,
  Stack,
  Category,
  SearchResult,
  SearchFilters,
  StackRecommendation,
  APIResponse,
  PaginatedResponse,
  TrustScoreBreakdown,
  PublisherBadge,
  ForgeError
} from '@/types';

class ForgeAPIError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string
  ) {
    super(message);
    this.name = 'ForgeAPIError';
  }
}

class ForgeAPI {
  private backendUrl: string;
  private defaultHeaders: HeadersInit;

  constructor() {
    this.backendUrl = process.env.NEXT_PUBLIC_FORGE_API_URL || 'http://localhost:8000';
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
  }

  /**
   * Make a request to the backend API. Validates Content-Type before parsing
   * JSON so that HTML error pages (e.g. 401 from a reverse proxy) don't crash
   * the process.
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.backendUrl}${endpoint}`;
    const config: RequestInit = {
      headers: this.defaultHeaders,
      ...options,
    };

    try {
      const response = await fetch(url, config);

      // Check Content-Type BEFORE attempting to parse as JSON
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new ForgeAPIError(
          `Expected JSON response but got ${contentType || 'unknown'} (HTTP ${response.status})`,
          response.status
        );
      }

      const data = await response.json();

      if (!response.ok) {
        throw new ForgeAPIError(
          data.message || data.detail || 'API request failed',
          response.status,
          data.code
        );
      }

      return data;
    } catch (error) {
      if (error instanceof ForgeAPIError) {
        throw error;
      }
      throw new ForgeAPIError(
        'Network error or server unavailable',
        0
      );
    }
  }

  /**
   * Make a request through the local Next.js API proxy routes. These routes
   * handle auth headers server-side and return JSON with proper fallbacks.
   */
  private async proxyRequest<T>(
    path: string,
    fallback: T
  ): Promise<T> {
    try {
      const response = await fetch(`/api/forge${path}`);

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        console.error(`[ForgeAPI] Non-JSON response from proxy: ${contentType}`);
        return fallback;
      }

      return await response.json() as T;
    } catch (error) {
      console.error(`[ForgeAPI] Proxy request failed for ${path}:`, error);
      return fallback;
    }
  }

  // Tools API — routed through server-side proxy
  async searchTools(
    query?: string,
    filters?: SearchFilters,
    page = 1,
    limit = 20
  ): Promise<SearchResult> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });

    if (query) params.append('q', query);
    if (filters?.categories?.length) {
      filters.categories.forEach(cat => params.append('category', cat));
    }
    if (filters?.ecosystems?.length) {
      filters.ecosystems.forEach(eco => params.append('ecosystem', eco));
    }
    if (filters?.trust_score_min) {
      params.append('trust_score_min', filters.trust_score_min.toString());
    }
    if (filters?.trust_score_max) {
      params.append('trust_score_max', filters.trust_score_max.toString());
    }
    if (filters?.tags?.length) {
      filters.tags.forEach(tag => params.append('tag', tag));
    }
    if (filters?.sort_by) {
      params.append('sort_by', filters.sort_by);
    }
    if (filters?.sort_order) {
      params.append('sort_order', filters.sort_order);
    }

    return this.proxyRequest<SearchResult>(
      `/search?${params}`,
      { tools: [], total: 0, page, limit, filters: {} as SearchFilters }
    );
  }

  async getToolByEcosystem(ecosystem: string, name: string): Promise<Tool | null> {
    try {
      return await this.proxyRequest<Tool | null>(
        `/tools/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}`,
        null
      );
    } catch {
      return null;
    }
  }

  async getToolMatches(ecosystem: string, name: string): Promise<unknown[]> {
    return this.proxyRequest<unknown[]>(
      `/tools/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/matches`,
      []
    );
  }

  async getTool(id: string): Promise<Tool> {
    const response = await this.request<APIResponse<Tool>>(
      `/api/v1/tools/${id}`
    );
    return response.data;
  }

  async getToolTrustScore(id: string): Promise<TrustScoreBreakdown> {
    const response = await this.request<APIResponse<TrustScoreBreakdown>>(
      `/api/v1/tools/${id}/trust-score`
    );
    return response.data;
  }

  async getPopularTools(limit = 10): Promise<Tool[]> {
    const response = await this.request<APIResponse<Tool[]>>(
      `/api/v1/tools/popular?limit=${limit}`
    );
    return response.data;
  }

  async getFeaturedTools(limit = 6): Promise<Tool[]> {
    const response = await this.request<APIResponse<Tool[]>>(
      `/api/v1/tools/featured?limit=${limit}`
    );
    return response.data;
  }

  // Categories API — routed through server-side proxy
  async getCategories(): Promise<Category[]> {
    return this.proxyRequest<Category[]>('/categories', []);
  }

  async getCategoryTools(
    categoryId: string,
    page = 1,
    limit = 20
  ): Promise<PaginatedResponse<Tool>> {
    const response = await this.request<APIResponse<PaginatedResponse<Tool>>>(
      `/api/v1/categories/${categoryId}/tools?page=${page}&limit=${limit}`
    );
    return response.data;
  }

  // Stats API — routed through server-side proxy
  async getStats(): Promise<Record<string, unknown>> {
    return this.proxyRequest<Record<string, unknown>>('/stats', {
      total_tools: 0,
      total_categories: 0,
      total_matches: 0,
      ecosystems: {},
      categories: {},
    });
  }

  // Stacks API
  async searchStacks(
    query?: string,
    page = 1,
    limit = 20
  ): Promise<PaginatedResponse<Stack>> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });

    if (query) params.append('q', query);

    const response = await this.request<APIResponse<PaginatedResponse<Stack>>>(
      `/api/v1/stacks/search?${params}`
    );
    return response.data;
  }

  async getStack(id: string): Promise<Stack> {
    const response = await this.request<APIResponse<Stack>>(
      `/api/v1/stacks/${id}`
    );
    return response.data;
  }

  async getFeaturedStacks(limit = 6): Promise<Stack[]> {
    const response = await this.request<APIResponse<Stack[]>>(
      `/api/v1/stacks/featured?limit=${limit}`
    );
    return response.data;
  }

  async generateStack(
    useCase: string,
    requirements: string[],
    preferences?: {
      ecosystems?: string[];
      trust_threshold?: number;
      include_experimental?: boolean;
    }
  ): Promise<StackRecommendation> {
    const response = await this.request<APIResponse<StackRecommendation>>(
      '/api/v1/stacks/generate',
      {
        method: 'POST',
        body: JSON.stringify({
          use_case: useCase,
          requirements,
          preferences: preferences || {},
        }),
      }
    );
    return response.data;
  }

  // Publisher API
  async generateBadge(toolId: string): Promise<PublisherBadge> {
    const response = await this.request<APIResponse<PublisherBadge>>(
      `/api/v1/publisher/badge/${toolId}`
    );
    return response.data;
  }

  async getToolStats(toolId: string): Promise<{
    downloads: number;
    stars: number;
    trust_score: number;
    last_scan: string;
  }> {
    const response = await this.request<APIResponse<any>>(
      `/api/v1/tools/${toolId}/stats`
    );
    return response.data;
  }

  // Analytics API
  async trackToolView(toolId: string): Promise<void> {
    await this.request<APIResponse<void>>(
      '/api/v1/analytics/tool-view',
      {
        method: 'POST',
        body: JSON.stringify({ tool_id: toolId }),
      }
    );
  }

  // Newsletter API
  async subscribeToNewsletter(data: {
    email: string;
    preferences?: {
      security_alerts?: boolean;
      tool_discoveries?: boolean;
      weekly_digest?: boolean;
      product_updates?: boolean;
    };
    source?: string;
  }): Promise<{
    success: boolean;
    message: string;
    email: string;
    preferences: Record<string, boolean>;
    unsubscribe_token: string;
  }> {
    const response = await this.request<{
      success: boolean;
      message: string;
      email: string;
      preferences: Record<string, boolean>;
      unsubscribe_token: string;
    }>('/email/subscribe', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return response;
  }

  async trackSearch(query: string, filters?: SearchFilters): Promise<void> {
    await this.request<APIResponse<void>>(
      '/api/v1/analytics/search',
      {
        method: 'POST',
        body: JSON.stringify({ query, filters }),
      }
    );
  }

  // Suggestions API
  async getSearchSuggestions(query: string): Promise<string[]> {
    const response = await this.request<APIResponse<string[]>>(
      `/api/v1/suggestions/search?q=${encodeURIComponent(query)}`
    );
    return response.data;
  }

  async getRelatedTools(toolId: string, limit = 5): Promise<Tool[]> {
    const response = await this.request<APIResponse<Tool[]>>(
      `/api/v1/tools/${toolId}/related?limit=${limit}`
    );
    return response.data;
  }
}

// Create singleton instance
export const forgeApi = new ForgeAPI();

// Error handling utility
export function isForgeAPIError(error: unknown): error is ForgeAPIError {
  return error instanceof ForgeAPIError;
}

// Cache utilities for React Query
export const queryKeys = {
  tools: {
    search: (query?: string, filters?: SearchFilters) =>
      ['tools', 'search', query, filters] as const,
    detail: (id: string) => ['tools', 'detail', id] as const,
    trustScore: (id: string) => ['tools', 'trust-score', id] as const,
    popular: (limit?: number) => ['tools', 'popular', limit] as const,
    featured: (limit?: number) => ['tools', 'featured', limit] as const,
    related: (id: string, limit?: number) => ['tools', 'related', id, limit] as const,
  },
  stacks: {
    search: (query?: string) => ['stacks', 'search', query] as const,
    detail: (id: string) => ['stacks', 'detail', id] as const,
    featured: (limit?: number) => ['stacks', 'featured', limit] as const,
  },
  categories: {
    all: () => ['categories'] as const,
    tools: (id: string, page?: number) => ['categories', 'tools', id, page] as const,
  },
  suggestions: {
    search: (query: string) => ['suggestions', 'search', query] as const,
  },
} as const;
