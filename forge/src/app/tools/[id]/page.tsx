import { Suspense } from 'react';
import { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { ToolDetail } from '@/components/tools/ToolDetail';
import { RelatedTools } from '@/components/tools/RelatedTools';
import { TrustScoreBreakdown } from '@/components/tools/TrustScoreBreakdown';
import { PageLoading } from '@/components/ui/Loading';

// This would be populated from API in a real implementation
async function getToolData(id: string) {
  try {
    // In a real app, this would fetch from your API
    return {
      id,
      name: 'Sample Tool',
      description: 'A sample tool for demonstration',
      category: 'automation',
      ecosystem: 'mcp',
      version: '1.0.0',
      author: 'Sample Author',
      trust_score: 85,
    };
  } catch {
    return null;
  }
}

export async function generateMetadata({ params }: { params: { id: string } }): Promise<Metadata> {
  const tool = await getToolData(params.id);
  
  if (!tool) {
    return {
      title: 'Tool Not Found - Sigil Forge'
    };
  }

  return {
    title: `${tool.name} - Sigil Forge`,
    description: tool.description,
    openGraph: {
      title: `${tool.name} - AI Agent Tool`,
      description: tool.description,
    },
  };
}

export default async function ToolPage({ params }: { params: { id: string } }) {
  const tool = await getToolData(params.id);

  if (!tool) {
    notFound();
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            <Suspense fallback={<PageLoading />}>
              <ToolDetail toolId={params.id} />
            </Suspense>
          </div>
          
          {/* Sidebar */}
          <div className="space-y-6">
            <Suspense fallback={<PageLoading />}>
              <TrustScoreBreakdown toolId={params.id} />
            </Suspense>
            
            <Suspense fallback={<PageLoading />}>
              <RelatedTools toolId={params.id} />
            </Suspense>
          </div>
        </div>
      </div>
    </div>
  );
}