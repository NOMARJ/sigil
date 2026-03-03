export type * from './forge';

// UI Component Props Types
export interface BaseComponentProps {
  className?: string;
  children?: React.ReactNode;
}

export interface ButtonProps extends BaseComponentProps {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
  href?: string;
  type?: 'button' | 'submit' | 'reset';
}

export interface BadgeProps extends BaseComponentProps {
  variant?: 'default' | 'success' | 'warning' | 'error' | 'info';
  size?: 'sm' | 'md' | 'lg';
}

export interface CardProps extends BaseComponentProps {
  header?: React.ReactNode;
  footer?: React.ReactNode;
  padding?: 'none' | 'sm' | 'md' | 'lg';
}

// Layout Types
export interface NavigationItem {
  name: string;
  href: string;
  icon?: React.ComponentType<{ className?: string }>;
  current?: boolean;
  children?: NavigationItem[];
}

export interface BreadcrumbItem {
  name: string;
  href?: string;
  current?: boolean;
}

// State Management Types
export interface AppState {
  user: {
    preferences: {
      theme: 'light' | 'dark';
      language: string;
      notifications: boolean;
    };
  };
  forge: {
    searchFilters: SearchFilters;
    recentSearches: string[];
    bookmarkedTools: string[];
    viewedTools: string[];
  };
  ui: {
    sidebar: {
      open: boolean;
    };
    modals: {
      [key: string]: boolean;
    };
    loading: {
      [key: string]: boolean;
    };
  };
}

// Hook Return Types
export interface UseSearchReturn {
  query: string;
  setQuery: (query: string) => void;
  filters: SearchFilters;
  setFilters: (filters: Partial<SearchFilters>) => void;
  results: SearchResult | null;
  isLoading: boolean;
  error: ForgeError | null;
  search: () => void;
  clearSearch: () => void;
}

export interface UseTrustScoreReturn {
  score: number;
  breakdown: TrustScoreBreakdown | null;
  isLoading: boolean;
  error: ForgeError | null;
  refresh: () => void;
}

// Event Handler Types
export type SearchEventHandler = (query: string, filters?: SearchFilters) => void;
export type ToolSelectHandler = (tool: Tool) => void;
export type CategorySelectHandler = (category: Category) => void;
export type StackSelectHandler = (stack: Stack) => void;