import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Utility for merging Tailwind classes
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Trust score utilities
export function getTrustScoreColor(score: number): string {
  if (score >= 90) return 'text-green-600';
  if (score >= 70) return 'text-blue-600';
  if (score >= 50) return 'text-yellow-600';
  return 'text-red-600';
}

export function getTrustScoreBackgroundColor(score: number): string {
  if (score >= 90) return 'bg-green-100';
  if (score >= 70) return 'bg-blue-100';
  if (score >= 50) return 'bg-yellow-100';
  return 'bg-red-100';
}

export function getTrustScoreLabel(score: number): string {
  if (score >= 90) return 'Excellent';
  if (score >= 70) return 'Good';
  if (score >= 50) return 'Fair';
  return 'Poor';
}

// Formatting utilities
export function formatNumber(num: number): string {
  if (num >= 1000000) {
    return `${(num / 1000000).toFixed(1)}M`;
  }
  if (num >= 1000) {
    return `${(num / 1000).toFixed(1)}K`;
  }
  return num.toString();
}

export function formatDate(date: string): string {
  const now = new Date();
  const target = new Date(date);
  const diff = now.getTime() - target.getTime();
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const months = Math.floor(days / 30);
  const years = Math.floor(days / 365);

  if (years > 0) return `${years} year${years > 1 ? 's' : ''} ago`;
  if (months > 0) return `${months} month${months > 1 ? 's' : ''} ago`;
  if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
  if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  return 'Just now';
}

export function formatDateLong(date: string): string {
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

// String utilities
export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength).trim() + '...';
}

export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w ]+/g, '')
    .replace(/ +/g, '-');
}

export function capitalizeFirst(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// URL utilities
export function buildSearchUrl(query?: string, filters?: Record<string, any>): string {
  const params = new URLSearchParams();
  
  if (query) {
    params.set('q', query);
  }
  
  if (filters) {
    Object.entries(filters).forEach(([key, value]) => {
      if (Array.isArray(value)) {
        value.forEach(v => params.append(key, v));
      } else if (value !== undefined && value !== null && value !== '') {
        params.set(key, value.toString());
      }
    });
  }
  
  const queryString = params.toString();
  return queryString ? `/discover?${queryString}` : '/discover';
}

// Validation utilities
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export function isValidGithubUrl(url: string): boolean {
  const githubRegex = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+$/;
  return githubRegex.test(url);
}

// Category icon mapping
export function getCategoryIcon(category: string): string {
  const iconMap: Record<string, string> = {
    'ai-agents': '🤖',
    'automation': '⚙️',
    'data-analysis': '📊',
    'web-scraping': '🕷️',
    'api-tools': '🔌',
    'security': '🛡️',
    'development': '💻',
    'productivity': '📈',
    'communication': '💬',
    'content': '📝',
    'testing': '🧪',
    'monitoring': '👁️',
    'deployment': '🚀',
    'database': '🗄️',
    'machine-learning': '🧠',
  };
  
  return iconMap[category] || '📦';
}

// Ecosystem configuration
export function getEcosystemConfig(ecosystem: string): {
  label: string;
  color: string;
  description: string;
} {
  const configs = {
    mcp: {
      label: 'MCP Server',
      color: 'blue',
      description: 'Model Context Protocol server for AI agents',
    },
    skill: {
      label: 'Claude Skill',
      color: 'green',
      description: 'Skill package for Claude Code',
    },
    plugin: {
      label: 'Plugin',
      color: 'purple',
      description: 'Plugin for various development tools',
    },
    extension: {
      label: 'Extension',
      color: 'orange',
      description: 'Browser or editor extension',
    },
  };
  
  return configs[ecosystem as keyof typeof configs] || {
    label: ecosystem,
    color: 'gray',
    description: 'Tool or package',
  };
}

// Error handling
export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  
  if (typeof error === 'string') {
    return error;
  }
  
  return 'An unexpected error occurred';
}

// Local storage utilities
export function getLocalStorageItem<T>(key: string, defaultValue: T): T {
  if (typeof window === 'undefined') {
    return defaultValue;
  }
  
  try {
    const item = window.localStorage.getItem(key);
    return item ? JSON.parse(item) : defaultValue;
  } catch {
    return defaultValue;
  }
}

export function setLocalStorageItem<T>(key: string, value: T): void {
  if (typeof window === 'undefined') {
    return;
  }
  
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Silently fail if localStorage is not available
  }
}

export function removeLocalStorageItem(key: string): void {
  if (typeof window === 'undefined') {
    return;
  }
  
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Silently fail if localStorage is not available
  }
}

// Performance utilities
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

export function throttle<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let lastExecution = 0;
  
  return (...args: Parameters<T>) => {
    const now = Date.now();
    
    if (now - lastExecution >= delay) {
      func(...args);
      lastExecution = now;
    }
  };
}

// SEO utilities
export function generateMetaTags(options: {
  title: string;
  description: string;
  keywords?: string[];
  image?: string;
  url?: string;
}) {
  return {
    title: options.title,
    description: options.description,
    keywords: options.keywords?.join(', '),
    openGraph: {
      title: options.title,
      description: options.description,
      images: options.image ? [{ url: options.image }] : undefined,
      url: options.url,
    },
    twitter: {
      card: 'summary_large_image',
      title: options.title,
      description: options.description,
      images: options.image ? [options.image] : undefined,
    },
  };
}