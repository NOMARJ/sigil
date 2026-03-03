'use client';

import { useQuery } from '@tanstack/react-query';
import { forgeApi, queryKeys } from '@/lib/api';
import { StackCard } from '@/components/ui/Card';
import { LoadingSkeleton } from '@/components/ui/Loading';
import { Button } from '@/components/ui/Button';
import { useRouter } from 'next/navigation';

export function FeaturedStacks() {
  const router = useRouter();
  
  const { data: stacks, isLoading } = useQuery({
    queryKey: queryKeys.stacks.featured(6),
    queryFn: () => forgeApi.getFeaturedStacks(6),
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {[...Array(6)].map((_, i) => (
          <LoadingSkeleton key={i} variant="rect" height="300px" />
        ))}
      </div>
    );
  }

  if (!stacks || stacks.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">No featured stacks available yet.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {stacks.map((stack) => (
          <StackCard
            key={stack.id}
            stack={stack}
            onClick={() => router.push(`/stacks/${stack.id}`)}
            className="card-hover"
          />
        ))}
      </div>
      
      <div className="text-center">
        <Button variant="outline" href="/stacks" size="lg">
          Browse All Stacks
        </Button>
      </div>
    </div>
  );
}