'use client';

import { clsx } from 'clsx';
import { CardProps } from '@/types';

export function Card({ 
  className, 
  children, 
  header, 
  footer, 
  padding = 'md' 
}: CardProps) {
  const paddingClasses = {
    none: '',
    sm: 'p-4',
    md: 'p-6',
    lg: 'p-8'
  };

  return (
    <div className={clsx(
      'bg-white rounded-lg border border-gray-200 shadow-sm',
      'hover:shadow-md transition-shadow duration-200',
      className
    )}>
      {header && (
        <div className="px-6 py-4 border-b border-gray-200">
          {header}
        </div>
      )}
      
      <div className={paddingClasses[padding]}>
        {children}
      </div>
      
      {footer && (
        <div className="px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-lg">
          {footer}
        </div>
      )}
    </div>
  );
}

// Tool Card Component
export function ToolCard({ 
  tool, 
  onClick, 
  className 
}: { 
  tool: any; 
  onClick?: () => void; 
  className?: string;
}) {
  return (
    <Card 
      className={clsx(
        'cursor-pointer hover:ring-2 hover:ring-sigil-500',
        'transition-all duration-200',
        className
      )}
      onClick={onClick}
    >
      <div className="space-y-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900">{tool.name}</h3>
            <p className="text-sm text-gray-600">{tool.author}</p>
          </div>
          <div className="flex items-center space-x-2">
            <TrustScoreBadge score={tool.trust_score} />
            <EcosystemBadge ecosystem={tool.ecosystem} />
          </div>
        </div>
        
        <p className="text-gray-700 text-sm line-clamp-2">
          {tool.description}
        </p>
        
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>{tool.download_count.toLocaleString()} downloads</span>
          <span>{tool.star_count} stars</span>
          <span>v{tool.version}</span>
        </div>
        
        {tool.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {tool.tags.slice(0, 3).map((tag: string) => (
              <Badge key={tag} size="sm" variant="default">
                {tag}
              </Badge>
            ))}
            {tool.tags.length > 3 && (
              <Badge size="sm" variant="default">
                +{tool.tags.length - 3}
              </Badge>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

// Stack Card Component
export function StackCard({ 
  stack, 
  onClick, 
  className 
}: { 
  stack: any; 
  onClick?: () => void; 
  className?: string;
}) {
  return (
    <Card 
      className={clsx(
        'cursor-pointer hover:ring-2 hover:ring-sigil-500',
        'transition-all duration-200',
        stack.featured && 'ring-2 ring-sigil-300',
        className
      )}
      onClick={onClick}
    >
      <div className="space-y-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900">{stack.name}</h3>
            <p className="text-sm text-gray-600">{stack.use_case}</p>
          </div>
          {stack.featured && (
            <Badge variant="info" size="sm">Featured</Badge>
          )}
        </div>
        
        <p className="text-gray-700 text-sm line-clamp-2">
          {stack.description}
        </p>
        
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-500">{stack.tools.length} tools</span>
            <TrustScoreBadge score={stack.trust_score} />
          </div>
          
          <div className="flex -space-x-1 overflow-hidden">
            {stack.tools.slice(0, 4).map((tool: any, index: number) => (
              <div
                key={tool.id}
                className="inline-block h-6 w-6 rounded-full ring-2 ring-white bg-gray-300"
                title={tool.name}
              />
            ))}
            {stack.tools.length > 4 && (
              <div className="inline-block h-6 w-6 rounded-full ring-2 ring-white bg-gray-400 text-xs text-white flex items-center justify-center">
                +{stack.tools.length - 4}
              </div>
            )}
          </div>
        </div>
      </div>
    </Card>
  );
}

import { Badge, TrustScoreBadge, EcosystemBadge } from './Badge';