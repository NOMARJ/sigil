'use client';

import { SearchResult, SearchFilters, ForgeError } from '@/types';
import { ToolCard } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { SearchResultsLoading } from '@/components/ui/Loading';
import { useRouter } from 'next/navigation';
import { forgeApi } from '@/lib/api';
import { 
  ExclamationTriangleIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';

interface SearchResultsProps {
  query: string;
  filters: SearchFilters;
  results: SearchResult | null;
  isLoading: boolean;
  error: ForgeError | null;
  onLoadMore: () => void;
}

export function SearchResults({
  query,
  filters,
  results,
  isLoading,
  error,
  onLoadMore
}: SearchResultsProps) {
  const router = useRouter();
  const hasSearched = query || Object.keys(filters).length > 0;

  // Loading state
  if (isLoading && !results) {
    return <SearchResultsLoading />;
  }

  // Error state
  if (error) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
        <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          Search Error
        </h3>
        <p className="text-gray-600 mb-4">
          {error.message || 'Something went wrong while searching.'}
        </p>
        <Button
          variant="outline"
          onClick={() => window.location.reload()}
        >
          Try Again
        </Button>
      </div>
    );
  }

  // Empty state - no search performed
  if (!hasSearched) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
        <MagnifyingGlassIcon className="h-16 w-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          Start Your Search
        </h3>
        <p className="text-gray-600 mb-6">
          Enter a search term or use filters to discover AI agent tools, 
          MCP servers, and extensions.
        </p>
        
        <div className="flex flex-wrap justify-center gap-2">
          <span className="text-sm text-gray-500">Try searching for:</span>
          {['web scraping', 'data analysis', 'automation', 'API tools', 'security'].map((term) => (
            <button
              key={term}
              onClick={() => router.push(`/discover?q=${encodeURIComponent(term)}`)}
              className="text-sm text-sigil-600 hover:text-sigil-800 font-medium transition-colors"
            >
              {term}
            </button>
          ))}
        </div>
      </div>
    );
  }

  // No results found
  if (results && results.tools.length === 0) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
        <MagnifyingGlassIcon className="h-16 w-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          No Tools Found
        </h3>
        <p className="text-gray-600 mb-6">
          No tools match your current search criteria. Try adjusting your 
          search terms or filters.
        </p>
        
        <div className="space-y-4">
          <div className="text-sm text-gray-500">
            Suggestions:
          </div>
          <ul className="text-sm text-gray-600 space-y-1">
            <li>• Check for typos in your search terms</li>
            <li>• Try broader or different keywords</li>
            <li>• Remove some filters to expand results</li>
            <li>• Browse categories instead</li>
          </ul>
          
          <div className="pt-4">
            <Button variant="outline" href="/categories">
              Browse Categories
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Results found
  if (results) {
    return (
      <div className="space-y-6">
        {/* Results header */}
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-medium text-gray-900">
                Search Results
              </h2>
              <p className="text-sm text-gray-600">
                {results.total.toLocaleString()} tools found
                {query && ` for "${query}"`}
              </p>
            </div>
            
            <div className="text-sm text-gray-500">
              Showing {((results.page - 1) * results.limit + 1).toLocaleString()}-
              {Math.min(results.page * results.limit, results.total).toLocaleString()}
            </div>
          </div>
        </div>

        {/* Tool grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {results.tools.map((tool) => (
            <ToolCard
              key={tool.id}
              tool={tool}
              onClick={() => {
                // Track tool view
                forgeApi.trackToolView(tool.id).catch(() => {});
                router.push(`/tools/${tool.id}`);
              }}
              className="card-hover"
            />
          ))}
        </div>

        {/* Load more */}
        {results.page * results.limit < results.total && (
          <div className="text-center py-8">
            <Button
              variant="outline"
              onClick={onLoadMore}
              loading={isLoading}
            >
              Load More Tools
            </Button>
          </div>
        )}
      </div>
    );
  }

  return null;
}