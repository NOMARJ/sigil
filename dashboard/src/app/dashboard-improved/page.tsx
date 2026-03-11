'use client';

import { EnhancedStatsCard } from '@/components/ui/EnhancedStatsCard';
import { RiskFilterBar, RiskIndicator } from '@/components/ui/RiskFilterBar';
import { UserPlanHeader, PlanBadge } from '@/components/ui/PlanBadge';

export default function ImprovedDashboard() {
  return (
    <div className="min-h-screen p-6">
      {/* Header with Pro Plan Badge */}
      <div className="mb-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-3xl font-bold" style={{ color: 'var(--color-text-primary)' }}>
                Pro Dashboard
              </h1>
              <PlanBadge plan="pro" />
            </div>
            <p style={{ color: 'var(--color-text-secondary)' }}>
              Enhanced threat detection with AI-powered insights
            </p>
          </div>
          <UserPlanHeader userName="Reece Frazier" plan="pro" />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <EnhancedStatsCard
          title="TOTAL SCANS"
          value="0"
          subtitle="all time"
          status="default"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        />
        
        <EnhancedStatsCard
          title="CRITICAL THREATS"
          value="2"
          subtitle="this month"
          trend={{ value: 15, isPositive: false }}
          status="danger"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          }
        />
        
        <EnhancedStatsCard
          title="HIGH RISK"
          value="5"
          subtitle="pending review"
          status="warning"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        />
        
        <EnhancedStatsCard
          title="PACKAGES APPROVED"
          value="127"
          subtitle="all time"
          status="success"
          icon={
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        />
      </div>

      {/* Recent Scans Section with Risk Filter */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h2 className="section-header">Recent Scans</h2>
              <RiskFilterBar 
                counts={{ critical: 2, high: 5, medium: 12, low: 8 }}
                onFilterChange={(filter) => console.log('Filter:', filter)}
              />
            </div>
            <button className="btn-ghost text-sm">
              View all →
            </button>
          </div>
        </div>
        <div className="card-body">
          <div className="flex flex-col items-center justify-center py-16">
            <svg className="w-16 h-16 mb-4" style={{ color: 'var(--color-text-muted)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            <p style={{ color: 'var(--color-text-secondary)' }} className="text-lg font-medium mb-1">
              No scans match the current filter
            </p>
            <p style={{ color: 'var(--color-text-muted)' }} className="text-sm">
              Latest package and repository scans will appear here
            </p>
            <div className="flex gap-2 mt-6">
              <RiskIndicator level="critical" />
              <RiskIndicator level="high" />
              <RiskIndicator level="medium" />
              <RiskIndicator level="low" />
            </div>
          </div>
        </div>
      </div>

      {/* Action Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mt-6">
        <div className="card hover:border-success-500/30">
          <div className="card-body">
            <h3 className="font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
              Quick Actions
            </h3>
            <div className="space-y-2">
              <button className="w-full btn-secondary justify-start">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                Scan Repository
              </button>
              <button className="w-full btn-secondary justify-start">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                </svg>
                Check Package
              </button>
            </div>
          </div>
        </div>

        <div className="card hover:border-info-500/30">
          <div className="card-body">
            <h3 className="font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
              Security Score
            </h3>
            <div className="flex items-baseline gap-2 mb-3">
              <span className="text-3xl font-bold" style={{ color: 'var(--color-info)' }}>A+</span>
              <span style={{ color: 'var(--color-text-secondary)' }}>Excellent</span>
            </div>
            <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
              No vulnerabilities detected in your supply chain
            </p>
          </div>
        </div>

        <div className="card hover:border-warning-500/30">
          <div className="card-body">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                Latest Threat Intel
              </h3>
              <PlanBadge plan="pro" showIcon={false} className="text-xs" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-warning-400"></div>
                <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                  New npm supply chain attack detected
                </p>
              </div>
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                Updated 2 hours ago
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}