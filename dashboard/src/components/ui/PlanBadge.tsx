import React from 'react';

type PlanType = 'free' | 'pro' | 'enterprise' | 'trial';

interface PlanBadgeProps {
  plan: PlanType;
  showIcon?: boolean;
  className?: string;
}

export function PlanBadge({ plan, showIcon = true, className = '' }: PlanBadgeProps) {
  const planConfig = {
    free: {
      label: 'Free',
      className: 'badge-free',
      icon: null
    },
    pro: {
      label: 'Pro Plan',
      className: 'badge-pro',
      icon: (
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
        </svg>
      )
    },
    enterprise: {
      label: 'Enterprise',
      className: 'badge-enterprise',
      icon: (
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
      )
    },
    trial: {
      label: 'Trial',
      className: 'badge-trial',
      icon: (
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    }
  };

  const config = planConfig[plan];

  return (
    <span className={`badge-plan ${config.className} ${className}`}>
      {showIcon && config.icon}
      {config.label}
    </span>
  );
}

// Header component with user info and plan badge
interface UserPlanHeaderProps {
  userName?: string;
  plan?: PlanType;
  avatarUrl?: string;
}

export function UserPlanHeader({ 
  userName = "User", 
  plan = "pro",
  avatarUrl
}: UserPlanHeaderProps) {
  return (
    <div className="flex items-center gap-3 p-4 rounded-lg" style={{ background: 'var(--color-bg-secondary)' }}>
      {/* Avatar */}
      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-brand-600 to-brand-400 flex items-center justify-center text-white font-semibold">
        {avatarUrl ? (
          <img src={avatarUrl} alt={userName} className="w-full h-full rounded-full" />
        ) : (
          userName.charAt(0).toUpperCase()
        )}
      </div>
      
      {/* User Info */}
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="font-medium" style={{ color: 'var(--color-text-primary)' }}>
            {userName}
          </span>
          <PlanBadge plan={plan} />
        </div>
        <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
          AI-Powered Detection
        </p>
      </div>
      
      {/* Stats */}
      <div className="flex items-center gap-4 text-xs">
        <div>
          <p style={{ color: 'var(--color-text-muted)' }}>Threats</p>
          <p className="font-semibold" style={{ color: 'var(--color-text-primary)' }}>3</p>
        </div>
        <div>
          <p style={{ color: 'var(--color-text-muted)' }}>Chains</p>
          <p className="font-semibold" style={{ color: 'var(--color-text-primary)' }}>1</p>
        </div>
      </div>
    </div>
  );
}