'use client';

import React, { useState } from 'react';

type RiskLevel = 'all' | 'critical' | 'high' | 'medium' | 'low';

interface RiskFilterBarProps {
  onFilterChange?: (filter: RiskLevel) => void;
  counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export function RiskFilterBar({ onFilterChange, counts = { critical: 0, high: 0, medium: 0, low: 0 } }: RiskFilterBarProps) {
  const [activeFilter, setActiveFilter] = useState<RiskLevel>('all');

  const handleFilterClick = (filter: RiskLevel) => {
    setActiveFilter(filter);
    onFilterChange?.(filter);
  };

  const totalCount = counts.critical + counts.high + counts.medium + counts.low;

  return (
    <div className="flex items-center gap-2 p-1 rounded-lg" style={{ background: 'var(--color-bg-secondary)' }}>
      {/* ALL filter */}
      <button
        onClick={() => handleFilterClick('all')}
        className={`
          risk-badge
          ${activeFilter === 'all' 
            ? 'bg-dark-700 border-dark-500 text-white' 
            : 'bg-dark-800 border-dark-600 text-dark-300 hover:text-white hover:bg-dark-700'
          }
        `}
      >
        ALL
        {totalCount > 0 && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-dark-600">
            {totalCount}
          </span>
        )}
      </button>

      {/* CRITICAL filter */}
      <button
        onClick={() => handleFilterClick('critical')}
        className={`risk-badge risk-critical ${activeFilter === 'critical' ? 'active' : ''}`}
      >
        CRITICAL_RISK
        {counts.critical > 0 && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-black/30">
            {counts.critical}
          </span>
        )}
      </button>

      {/* HIGH filter */}
      <button
        onClick={() => handleFilterClick('high')}
        className={`risk-badge risk-high ${activeFilter === 'high' ? 'active' : ''}`}
      >
        HIGH_RISK
        {counts.high > 0 && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-black/30">
            {counts.high}
          </span>
        )}
      </button>

      {/* MEDIUM filter */}
      <button
        onClick={() => handleFilterClick('medium')}
        className={`risk-badge risk-medium ${activeFilter === 'medium' ? 'active' : ''}`}
      >
        MEDIUM_RISK
        {counts.medium > 0 && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-black/30">
            {counts.medium}
          </span>
        )}
      </button>

      {/* LOW filter */}
      <button
        onClick={() => handleFilterClick('low')}
        className={`risk-badge risk-low ${activeFilter === 'low' ? 'active' : ''}`}
      >
        LOW_RISK
        {counts.low > 0 && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-black/30">
            {counts.low}
          </span>
        )}
      </button>
    </div>
  );
}

// Risk level indicator component for use in tables/lists
export function RiskIndicator({ level }: { level: 'critical' | 'high' | 'medium' | 'low' }) {
  const styles = {
    critical: 'bg-critical text-critical',
    high: 'bg-high text-high',
    medium: 'bg-medium text-medium',
    low: 'bg-low text-low'
  };

  const labels = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW'
  };

  return (
    <span className={`risk-badge ${styles[level]}`}>
      {labels[level]}
    </span>
  );
}