import { Suspense } from 'react';
import { Metadata } from 'next';
import { HeroSection } from '@/components/home/HeroSection';
import { FeaturedStacks } from '@/components/home/FeaturedStacks';
import { PopularTools } from '@/components/home/PopularTools';
import { CategoryGrid } from '@/components/home/CategoryGrid';
import { TrustSection } from '@/components/home/TrustSection';
import { StatsSection } from '@/components/home/StatsSection';
import { CTASection } from '@/components/home/CTASection';
import { LoadingSkeleton } from '@/components/ui/Loading';

export const metadata: Metadata = {
  title: 'Sigil Forge - Discover AI Agent Tools with Trust Scores',
  description: 'Find, evaluate, and deploy AI agent tools including MCP servers, Claude skills, and extensions. Every tool scanned for security with detailed trust scores.',
  openGraph: {
    title: 'Sigil Forge - Discover AI Agent Tools with Trust Scores',
    description: 'Find, evaluate, and deploy AI agent tools including MCP servers, Claude skills, and extensions.',
  },
};

export default function HomePage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <HeroSection />

      {/* Trust & Security Section */}
      <TrustSection />

      {/* Stats Section */}
      <Suspense fallback={<LoadingSkeleton />}>
        <StatsSection />
      </Suspense>

      {/* Featured Stacks */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
              Featured Tool Stacks
            </h2>
            <p className="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">
              Curated collections of compatible tools for common AI agent use cases
            </p>
          </div>
          
          <Suspense fallback={
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[...Array(6)].map((_, i) => (
                <LoadingSkeleton key={i} variant="rect" height="300px" />
              ))}
            </div>
          }>
            <FeaturedStacks />
          </Suspense>
        </div>
      </section>

      {/* Popular Tools */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
              Popular Tools
            </h2>
            <p className="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">
              Most downloaded and trusted tools in the community
            </p>
          </div>
          
          <Suspense fallback={
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {[...Array(8)].map((_, i) => (
                <LoadingSkeleton key={i} variant="rect" height="250px" />
              ))}
            </div>
          }>
            <PopularTools />
          </Suspense>
        </div>
      </section>

      {/* Categories */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
              Browse by Category
            </h2>
            <p className="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">
              Explore tools organized by functionality and use case
            </p>
          </div>
          
          <Suspense fallback={
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
              {[...Array(12)].map((_, i) => (
                <LoadingSkeleton key={i} variant="rect" height="120px" />
              ))}
            </div>
          }>
            <CategoryGrid />
          </Suspense>
        </div>
      </section>

      {/* CTA Section */}
      <CTASection />
    </div>
  );
}