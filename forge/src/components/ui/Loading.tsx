'use client';

import { clsx } from 'clsx';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function LoadingSpinner({ size = 'md', className }: LoadingSpinnerProps) {
  const sizes = {
    sm: 'h-4 w-4',
    md: 'h-6 w-6',
    lg: 'h-8 w-8'
  };

  return (
    <svg
      className={clsx(
        'animate-spin text-sigil-600',
        sizes[size],
        className
      )}
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

interface LoadingSkeletonProps {
  variant?: 'text' | 'rect' | 'circle';
  width?: string;
  height?: string;
  className?: string;
}

export function LoadingSkeleton({ 
  variant = 'text', 
  width, 
  height, 
  className 
}: LoadingSkeletonProps) {
  const baseClasses = 'animate-pulse bg-gray-200';
  
  const variants = {
    text: 'h-4 rounded',
    rect: 'rounded-lg',
    circle: 'rounded-full'
  };

  const style = {
    width: width || (variant === 'text' ? '100%' : '40px'),
    height: height || (variant === 'circle' ? width || '40px' : '20px')
  };

  return (
    <div 
      className={clsx(baseClasses, variants[variant], className)}
      style={style}
    />
  );
}

// Tool Card Skeleton
export function ToolCardSkeleton() {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="space-y-4">
        <div className="flex items-start justify-between">
          <div className="flex-1 space-y-2">
            <LoadingSkeleton variant="text" width="60%" height="20px" />
            <LoadingSkeleton variant="text" width="40%" height="16px" />
          </div>
          <div className="flex space-x-2">
            <LoadingSkeleton variant="rect" width="80px" height="24px" />
            <LoadingSkeleton variant="rect" width="60px" height="24px" />
          </div>
        </div>
        
        <div className="space-y-2">
          <LoadingSkeleton variant="text" width="100%" />
          <LoadingSkeleton variant="text" width="80%" />
        </div>
        
        <div className="flex items-center justify-between">
          <LoadingSkeleton variant="text" width="80px" />
          <LoadingSkeleton variant="text" width="50px" />
          <LoadingSkeleton variant="text" width="40px" />
        </div>
        
        <div className="flex space-x-1">
          {[...Array(3)].map((_, i) => (
            <LoadingSkeleton key={i} variant="rect" width="50px" height="20px" />
          ))}
        </div>
      </div>
    </div>
  );
}

// Search Results Loading
export function SearchResultsLoading() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <LoadingSkeleton variant="text" width="200px" height="24px" />
        <LoadingSkeleton variant="rect" width="120px" height="32px" />
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {[...Array(9)].map((_, i) => (
          <ToolCardSkeleton key={i} />
        ))}
      </div>
    </div>
  );
}

// Page Loading Component
export function PageLoading() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center space-y-4">
        <LoadingSpinner size="lg" />
        <p className="text-gray-500">Loading...</p>
      </div>
    </div>
  );
}