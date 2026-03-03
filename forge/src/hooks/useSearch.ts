'use client';

import { useState, useEffect, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useDebounce } from 'use-debounce';
import { forgeApi, queryKeys } from '@/lib/api';
import { SearchFilters, SearchResult, UseSearchReturn } from '@/types';
import { getLocalStorageItem, setLocalStorageItem } from '@/lib/utils';

export function useSearch(): UseSearchReturn {
  const [query, setQuery] = useState('');
  const [filters, setFiltersState] = useState<SearchFilters>(() => 
    getLocalStorageItem<SearchFilters>('forge_search_filters', {})
  );
  
  const [debouncedQuery] = useDebounce(query, 300);
  const [debouncedFilters] = useDebounce(filters, 300);

  // Save filters to localStorage when they change
  useEffect(() => {
    setLocalStorageItem('forge_search_filters', filters);
  }, [filters]);

  const setFilters = (newFilters: Partial<SearchFilters>) => {
    setFiltersState(prev => ({ ...prev, ...newFilters }));
  };

  const { 
    data: results, 
    isLoading, 
    error,
    refetch
  } = useQuery({
    queryKey: queryKeys.tools.search(debouncedQuery, debouncedFilters),
    queryFn: () => forgeApi.searchTools(debouncedQuery, debouncedFilters),
    enabled: debouncedQuery.length > 0 || Object.keys(debouncedFilters).length > 0,
    staleTime: 1000 * 60 * 5, // 5 minutes
  });

  const search = () => {
    refetch();
    
    // Track search analytics
    if (query || Object.keys(filters).length > 0) {
      forgeApi.trackSearch(query, filters).catch(() => {
        // Ignore analytics errors
      });
    }
  };

  const clearSearch = () => {
    setQuery('');
    setFiltersState({});
  };

  return {
    query,
    setQuery,
    filters,
    setFilters,
    results: results || null,
    isLoading,
    error: error as any,
    search,
    clearSearch,
  };
}

// Hook for search suggestions
export function useSearchSuggestions(query: string) {
  const [debouncedQuery] = useDebounce(query, 200);

  return useQuery({
    queryKey: queryKeys.suggestions.search(debouncedQuery),
    queryFn: () => forgeApi.getSearchSuggestions(debouncedQuery),
    enabled: debouncedQuery.length > 2,
    staleTime: 1000 * 60 * 10, // 10 minutes
  });
}

// Hook for recent searches
export function useRecentSearches() {
  const [recentSearches, setRecentSearches] = useState<string[]>(() =>
    getLocalStorageItem<string[]>('forge_recent_searches', [])
  );

  const addRecentSearch = (searchQuery: string) => {
    if (!searchQuery.trim()) return;

    setRecentSearches(prev => {
      const filtered = prev.filter(q => q !== searchQuery);
      const updated = [searchQuery, ...filtered].slice(0, 10); // Keep last 10
      setLocalStorageItem('forge_recent_searches', updated);
      return updated;
    });
  };

  const clearRecentSearches = () => {
    setRecentSearches([]);
    setLocalStorageItem('forge_recent_searches', []);
  };

  return {
    recentSearches,
    addRecentSearch,
    clearRecentSearches,
  };
}

// Hook for saved filters
export function useSavedFilters() {
  const [savedFilters, setSavedFilters] = useState<Array<{
    name: string;
    filters: SearchFilters;
  }>>(() =>
    getLocalStorageItem('forge_saved_filters', [])
  );

  const saveFilter = (name: string, filterSet: SearchFilters) => {
    setSavedFilters(prev => {
      const filtered = prev.filter(f => f.name !== name);
      const updated = [...filtered, { name, filters: filterSet }];
      setLocalStorageItem('forge_saved_filters', updated);
      return updated;
    });
  };

  const removeFilter = (name: string) => {
    setSavedFilters(prev => {
      const updated = prev.filter(f => f.name !== name);
      setLocalStorageItem('forge_saved_filters', updated);
      return updated;
    });
  };

  return {
    savedFilters,
    saveFilter,
    removeFilter,
  };
}