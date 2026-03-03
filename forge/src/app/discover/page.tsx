import { Suspense } from 'react';
import { Metadata } from 'next';
import { SearchInterface } from '@/components/discover/SearchInterface';
import { SearchResultsLoading } from '@/components/ui/Loading';

export const metadata: Metadata = {
  title: 'Discover AI Agent Tools - Sigil Forge',
  description: 'Search and discover AI agent tools, MCP servers, Claude skills, and extensions. Filter by trust score, category, and ecosystem.',
  openGraph: {
    title: 'Discover AI Agent Tools - Sigil Forge',
    description: 'Search and discover AI agent tools with trust scores and security scanning.',
  },
};

export default function DiscoverPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Discover AI Agent Tools
          </h1>
          <p className="text-lg text-gray-600">
            Search through thousands of verified tools, MCP servers, and extensions 
            with detailed trust scores and security analysis.
          </p>
        </div>

        <Suspense fallback={<SearchResultsLoading />}>
          <SearchInterface />
        </Suspense>
      </div>
    </div>
  );
}