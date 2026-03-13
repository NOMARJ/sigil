'use client';

import { clsx } from 'clsx';
import { BadgeProps } from '@/types';

export function Badge({ 
  className, 
  children, 
  variant = 'default', 
  size = 'md' 
}: BadgeProps) {
  const baseClasses = [
    'inline-flex items-center font-medium rounded-full',
    'border transition-all duration-200'
  ];

  const variants = {
    default: 'bg-gray-100 text-gray-800 border-gray-200',
    success: 'bg-green-100 text-green-800 border-green-200',
    warning: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    error: 'bg-red-100 text-red-800 border-red-200',
    info: 'bg-blue-100 text-blue-800 border-blue-200'
  };

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
    lg: 'px-3 py-1.5 text-base'
  };

  return (
    <span className={clsx(baseClasses, variants[variant], sizes[size], className)}>
      {children}
    </span>
  );
}

// Trust Score Badge Component
export function TrustScoreBadge({ score, className }: { score: number; className?: string }) {
  const getVariant = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 70) return 'info';
    if (score >= 50) return 'warning';
    return 'error';
  };

  const getLabel = (score: number) => {
    if (score >= 90) return 'Excellent';
    if (score >= 70) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
  };

  return (
    <Badge variant={getVariant(score)} className={className}>
      {score}/100 {getLabel(score)}
    </Badge>
  );
}

// Ecosystem Badge Component
export function EcosystemBadge({ 
  ecosystem, 
  className 
}: { 
  ecosystem: string; 
  className?: string;
}) {
  const ecosystemConfig = {
    mcp: { label: 'MCP', variant: 'info' as const },
    skill: { label: 'Skill', variant: 'success' as const },
    plugin: { label: 'Plugin', variant: 'warning' as const },
    extension: { label: 'Extension', variant: 'default' as const }
  };

  const config = ecosystemConfig[ecosystem as keyof typeof ecosystemConfig] || 
    { label: ecosystem, variant: 'default' as const };

  return (
    <Badge variant={config.variant} size="sm" className={className}>
      {config.label}
    </Badge>
  );
}