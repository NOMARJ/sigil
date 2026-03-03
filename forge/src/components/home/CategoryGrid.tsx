'use client';

import { useQuery } from '@tanstack/react-query';
import { forgeApi, queryKeys } from '@/lib/api';
import { LoadingSkeleton } from '@/components/ui/Loading';
import { getCategoryIcon } from '@/lib/utils';
import { useRouter } from 'next/navigation';
import { ArrowRightIcon } from '@heroicons/react/24/outline';

export function CategoryGrid() {
  const router = useRouter();
  
  const { data: categories, isLoading } = useQuery({
    queryKey: queryKeys.categories.all(),
    queryFn: () => forgeApi.getCategories(),
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
        {[...Array(12)].map((_, i) => (
          <LoadingSkeleton key={i} variant="rect" height="120px" />
        ))}
      </div>
    );
  }

  if (!categories || categories.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">No categories available yet.</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
      {categories.map((category) => (
        <div
          key={category.id}
          className="group cursor-pointer bg-white rounded-lg border border-gray-200 p-6 hover:shadow-md hover:border-sigil-300 transition-all duration-200"
          onClick={() => router.push(`/discover?category=${encodeURIComponent(category.name)}`)}
        >
          <div className="flex flex-col items-center text-center space-y-4">
            <div className="text-4xl mb-2">
              {getCategoryIcon(category.id)}
            </div>
            
            <div className="flex-1">
              <h3 className="font-semibold text-gray-900 group-hover:text-sigil-600 transition-colors">
                {category.name}
              </h3>
              <p className="text-sm text-gray-500 mt-1">
                {category.tool_count} tools
              </p>
            </div>
            
            <ArrowRightIcon className="h-4 w-4 text-gray-400 group-hover:text-sigil-500 group-hover:translate-x-1 transition-all" />
          </div>
        </div>
      ))}
    </div>
  );
}