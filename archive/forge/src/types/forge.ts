// Core Forge Types
export interface Tool {
  id: string;
  name: string;
  description: string;
  category: string;
  ecosystem: 'mcp' | 'skill' | 'plugin' | 'extension';
  version: string;
  author: string;
  repository_url?: string;
  documentation_url?: string;
  trust_score: number;
  vulnerability_count: number;
  download_count: number;
  star_count: number;
  last_updated: string;
  created_at: string;
  tags: string[];
  manifest: ToolManifest;
  trust_factors: TrustFactor[];
  vulnerabilities: Vulnerability[];
}

export interface ToolManifest {
  name: string;
  version: string;
  description: string;
  author: string;
  license?: string;
  keywords?: string[];
  dependencies?: Record<string, string>;
  capabilities: string[];
  permissions?: string[];
  config_schema?: Record<string, any>;
  entry_point?: string;
  supported_platforms?: string[];
}

export interface TrustFactor {
  id: string;
  tool_id: string;
  factor_type: string;
  score: number;
  weight: number;
  evidence: Record<string, any>;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  tool_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  affected_versions: string;
  fixed_version?: string;
  published_at: string;
  source: string;
}

export interface Category {
  id: string;
  name: string;
  description: string;
  icon: string;
  tool_count: number;
  popular_tools: Tool[];
}

export interface Stack {
  id: string;
  name: string;
  description: string;
  use_case: string;
  tools: Tool[];
  trust_score: number;
  compatibility_score: number;
  installation_guide: string;
  created_by: string;
  featured: boolean;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface SearchFilters {
  categories?: string[];
  ecosystems?: string[];
  trust_score_min?: number;
  trust_score_max?: number;
  tags?: string[];
  has_vulnerabilities?: boolean;
  min_downloads?: number;
  sort_by?: 'relevance' | 'trust_score' | 'popularity' | 'updated' | 'created';
  sort_order?: 'asc' | 'desc';
}

export interface SearchResult {
  tools: Tool[];
  total: number;
  page: number;
  limit: number;
  filters: SearchFilters;
}

export interface StackRecommendation {
  use_case: string;
  suggested_stacks: Stack[];
  custom_tools: Tool[];
  reasoning: string;
  compatibility_notes: string[];
  installation_script: string;
}

// API Response Types
export interface APIResponse<T> {
  success: boolean;
  data: T;
  message?: string;
  error?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  has_next: boolean;
  has_prev: boolean;
}

// Trust Score Visualization Types
export interface TrustScoreBreakdown {
  overall_score: number;
  factors: {
    code_quality: number;
    security_scan: number;
    community_trust: number;
    maintenance: number;
    documentation: number;
  };
  recent_changes: {
    score_change: number;
    factors_changed: string[];
    last_updated: string;
  };
}

// Publisher Badge System
export interface PublisherBadge {
  tool_id: string;
  badge_type: 'verified' | 'featured' | 'secure' | 'popular';
  badge_url: string;
  embed_code: string;
  stats: {
    trust_score: number;
    downloads: number;
    last_scan: string;
  };
}

// WebSocket Message Types
export interface WSMessage {
  type: 'tool_update' | 'trust_score_change' | 'new_vulnerability' | 'stack_recommendation';
  payload: any;
  timestamp: string;
}

// Error Types
export interface ForgeError {
  code: string;
  message: string;
  details?: Record<string, any>;
}

// Form Types for React Hook Form
export interface SearchFormData {
  query: string;
  categories: string[];
  ecosystems: string[];
  trust_score_range: [number, number];
  tags: string;
  sort_by: string;
}

export interface StackGenerationFormData {
  use_case: string;
  requirements: string[];
  preferred_ecosystems: string[];
  trust_score_threshold: number;
  include_experimental: boolean;
}