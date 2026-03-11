'use client';

import { PlanBadge } from '@/components/ui/PlanBadge';

export default function PlanBadgesDemo() {
  return (
    <div className="min-h-screen p-8">
      <h1 className="text-2xl font-bold mb-8" style={{ color: 'var(--color-text-primary)' }}>
        Plan Badges - Professional Security Style
      </h1>

      {/* Plan Tiers Section */}
      <div className="card mb-8">
        <div className="card-header">
          <h2 className="section-header">Subscription Tiers</h2>
        </div>
        <div className="card-body">
          <div className="flex items-center gap-4">
            <PlanBadge plan="free" />
            <PlanBadge plan="trial" />
            <PlanBadge plan="pro" />
            <PlanBadge plan="enterprise" />
          </div>
          
          <div className="mt-6 grid grid-cols-4 gap-4">
            <div className="p-4 rounded-lg border" style={{ borderColor: 'var(--color-border-subtle)' }}>
              <PlanBadge plan="free" className="mb-2" />
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                Basic scanning features
              </p>
            </div>
            
            <div className="p-4 rounded-lg border" style={{ borderColor: 'var(--color-warning)/30' }}>
              <PlanBadge plan="trial" className="mb-2" />
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                14 days remaining
              </p>
            </div>
            
            <div className="p-4 rounded-lg border" style={{ borderColor: 'var(--color-accent)/30' }}>
              <PlanBadge plan="pro" className="mb-2" />
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                AI-powered detection
              </p>
            </div>
            
            <div className="p-4 rounded-lg border" style={{ borderColor: 'var(--color-info)/30' }}>
              <PlanBadge plan="enterprise" className="mb-2" />
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                Custom deployment
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Status Badges Section */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Status & Feature Badges</h2>
        </div>
        <div className="card-body">
          <div className="flex items-center gap-3">
            <span className="badge badge-success">Active</span>
            <span className="badge badge-warning">Pending</span>
            <span className="badge badge-danger">Expired</span>
            <span className="badge badge-info">Beta</span>
          </div>
          
          <div className="mt-6">
            <p className="text-sm mb-3" style={{ color: 'var(--color-text-secondary)' }}>
              No more purple AI gradients! Professional security-focused design with:
            </p>
            <ul className="space-y-2 text-sm" style={{ color: 'var(--color-text-muted)' }}>
              <li className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-accent)' }}></div>
                Green for Pro (security/trust)
              </li>
              <li className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ background: '#0ea5e9' }}></div>
                Blue for Enterprise (professional/corporate)
              </li>
              <li className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-warning)' }}></div>
                Amber for Trial (time-limited)
              </li>
              <li className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-text-muted)' }}></div>
                Muted for Free (basic tier)
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}