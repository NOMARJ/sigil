'use client';

import { useQuery } from '@tanstack/react-query';
import { forgeApi, queryKeys } from '@/lib/api';
import { ToolCard } from '@/components/ui/Card';
import { LoadingSkeleton } from '@/components/ui/Loading';
import { Button } from '@/components/ui/Button';
import { useRouter } from 'next/navigation';

export function PopularTools() {
  const router = useRouter();
  
  const { data: tools, isLoading } = useQuery({
    queryKey: queryKeys.tools.popular(8),
    queryFn: () => forgeApi.getPopularTools(8),
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <LoadingSkeleton key={i} variant="rect" height="250px" />
        ))}
      </div>
    );
  }

  if (!tools || tools.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">No popular tools available yet.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {tools.map((tool) => (
          <ToolCard
            key={tool.id}
            tool={tool}
            onClick={() => {
              forgeApi.trackToolView(tool.id).catch(() => {});
              router.push(`/tools/${tool.id}`);
            }}
            className="card-hover"
          />
        ))}
      </div>
      
      <div className="text-center">
        <Button variant="outline" href="/discover" size="lg">
          Discover More Tools
        </Button>
      </div>
    </div>
  );
}