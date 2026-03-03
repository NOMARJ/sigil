'use client';

import { useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useSearch, useSearchSuggestions } from '@/hooks/useSearch';
import { SearchInput, FilterDropdown } from '@/components/ui/Search';
import { Button } from '@/components/ui/Button';
import { SearchResults } from './SearchResults';
import { SearchFilters } from './SearchFilters';
import { SavedSearches } from './SavedSearches';
import { 
  AdjustmentsHorizontalIcon,
  FunnelIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import { buildSearchUrl } from '@/lib/utils';

const sortOptions = [
  { label: 'Relevance', value: 'relevance' },
  { label: 'Trust Score', value: 'trust_score' },
  { label: 'Popularity', value: 'popularity' },
  { label: 'Recently Updated', value: 'updated' },
  { label: 'Recently Added', value: 'created' },
];

export function SearchInterface() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showFilters, setShowFilters] = useState(false);
  const [showSavedSearches, setShowSavedSearches] = useState(false);
  
  const {
    query,
    setQuery,
    filters,
    setFilters,
    results,
    isLoading,
    error,
    search,
    clearSearch
  } = useSearch();

  const { data: suggestions = [] } = useSearchSuggestions(query);

  // Initialize from URL parameters
  useEffect(() => {
    const q = searchParams.get('q');
    const categories = searchParams.getAll('category');
    const ecosystems = searchParams.getAll('ecosystem');
    const sortBy = searchParams.get('sort_by');
    
    if (q) setQuery(q);
    
    if (categories.length || ecosystems.length || sortBy) {
      setFilters({
        categories: categories.length ? categories : undefined,
        ecosystems: ecosystems.length ? ecosystems : undefined,
        sort_by: sortBy || undefined,
      });
    }
  }, [searchParams, setQuery, setFilters]);

  // Update URL when search changes
  useEffect(() => {
    const url = buildSearchUrl(query, filters);
    router.replace(url, { scroll: false });
  }, [query, filters, router]);

  const handleSearch = (searchQuery: string) => {
    setQuery(searchQuery);
    search();
  };

  const handleFilterChange = (newFilters: any) => {
    setFilters(newFilters);
  };

  const activeFiltersCount = Object.values(filters).filter(Boolean).length;
  const hasResults = results && results.tools.length > 0;
  const hasSearched = query || activeFiltersCount > 0;

  return (
    <div className="space-y-6">
      {/* Search Bar */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="space-y-4">
          <SearchInput
            placeholder="Search tools, MCP servers, skills..."
            value={query}
            onChange={setQuery}
            onSubmit={handleSearch}
            suggestions={suggestions}
            autoComplete={true}
            loading={isLoading}
          />

          {/* Quick Actions */}
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowFilters(!showFilters)}
                className={showFilters ? 'bg-sigil-50 border-sigil-300 text-sigil-700' : ''}
              >
                <AdjustmentsHorizontalIcon className="h-4 w-4 mr-2" />
                Filters
                {activeFiltersCount > 0 && (
                  <span className="ml-2 bg-sigil-600 text-white text-xs rounded-full px-2 py-0.5">
                    {activeFiltersCount}
                  </span>
                )}
              </Button>

              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowSavedSearches(!showSavedSearches)}
              >
                Saved Searches
              </Button>

              {hasSearched && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearSearch}
                  className="text-gray-500"
                >
                  <XMarkIcon className="h-4 w-4 mr-1" />
                  Clear
                </Button>
              )}
            </div>

            <div className="flex items-center space-x-4">
              <FilterDropdown
                label="Sort by"
                options={sortOptions}
                selectedValues={filters.sort_by ? [filters.sort_by] : []}
                onChange={(values) => handleFilterChange({ sort_by: values[0] })}
                multiple={false}
              />

              {hasResults && (
                <span className="text-sm text-gray-500">
                  {results.total.toLocaleString()} results
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <SearchFilters
          filters={filters}
          onFiltersChange={handleFilterChange}
          onClose={() => setShowFilters(false)}
        />
      )}

      {/* Saved Searches */}
      {showSavedSearches && (
        <SavedSearches
          onSearchSelect={(savedQuery, savedFilters) => {
            setQuery(savedQuery);
            setFilters(savedFilters);
            setShowSavedSearches(false);
            search();
          }}
          onClose={() => setShowSavedSearches(false)}
        />
      )}

      {/* Search Results */}
      <SearchResults
        query={query}
        filters={filters}
        results={results}
        isLoading={isLoading}
        error={error}
        onLoadMore={() => {
          // Implement pagination
        }}
      />
    </div>
  );
}