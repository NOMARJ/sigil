import React from 'react';

interface EnhancedStatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  icon?: React.ReactNode;
  status?: 'default' | 'success' | 'warning' | 'danger' | 'info';
}

export function EnhancedStatsCard({
  title,
  value,
  subtitle,
  trend,
  icon,
  status = 'default'
}: EnhancedStatsCardProps) {
  const statusColors = {
    default: 'border-dark-500/30 bg-dark-800/50',
    success: 'border-success-500/30 bg-success-500/10 glow-green',
    warning: 'border-warning-500/30 bg-warning-500/10 glow-warning',
    danger: 'border-danger-500/30 bg-danger-500/10 glow-red',
    info: 'border-info-500/30 bg-info-500/10'
  };

  const statusIconColors = {
    default: 'text-dark-300',
    success: 'text-success-400',
    warning: 'text-warning-400',
    danger: 'text-danger-400',
    info: 'text-info-400'
  };

  const trendColors = {
    positive: 'text-success-400 bg-success-500/10',
    negative: 'text-danger-400 bg-danger-500/10'
  };

  return (
    <div className={`
      relative overflow-hidden rounded-xl border transition-all duration-300
      hover:scale-[1.02] hover:shadow-2xl
      ${statusColors[status]}
    `}>
      {/* Background gradient effect - subtle green security theme */}
      <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-brand-500/5" />
      
      <div className="relative p-6">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              {icon && (
                <div className={`${statusIconColors[status]}`}>
                  {icon}
                </div>
              )}
              <p className="stat-label">{title}</p>
            </div>
            
            <p className="stat-value mt-2">{value}</p>
            
            {subtitle && (
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
                {subtitle}
              </p>
            )}
          </div>
          
          {trend && (
            <div className={`
              inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium
              ${trend.isPositive ? trendColors.positive : trendColors.negative}
            `}>
              <svg 
                className={`w-3 h-3 ${trend.isPositive ? '' : 'rotate-180'}`}
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
              </svg>
              <span>{Math.abs(trend.value)}%</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}