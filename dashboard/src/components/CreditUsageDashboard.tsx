"use client";

import { useEffect, useState } from "react";

interface CreditTransaction {
  id: string;
  amount: number;
  feature: string;
  timestamp: string;
  description: string;
}

interface CreditUsage {
  current_balance: number;
  monthly_allocation: number;
  used_this_month: number;
  days_until_reset: number;
  transactions: CreditTransaction[];
}

interface CreditUsageDashboardProps {
  subscription?: {
    plan: string;
    current_period_end?: string;
  };
}

export function CreditUsageDashboard({ subscription }: CreditUsageDashboardProps): JSX.Element {
  const [usage, setUsage] = useState<CreditUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCreditUsage();
  }, []);

  const fetchCreditUsage = async (): Promise<void> => {
    try {
      const response = await fetch('/api/v1/billing/credits/usage');
      if (!response.ok) {
        throw new Error('Failed to fetch credit usage');
      }
      const data = await response.json();
      setUsage(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-6 bg-gray-800 rounded w-1/3 animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="card">
              <div className="card-body">
                <div className="h-4 bg-gray-800 rounded mb-2 animate-pulse" />
                <div className="h-6 bg-gray-800 rounded animate-pulse" />
              </div>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-body">
            <div className="h-6 bg-gray-800 rounded w-1/4 mb-4 animate-pulse" />
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-4 bg-gray-800 rounded animate-pulse" />
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card border-red-500/30">
        <div className="card-body text-center py-8">
          <div className="text-red-400 text-4xl mb-4">⚠️</div>
          <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
            Unable to load credit usage
          </h3>
          <p className="text-sm mb-4" style={{ color: 'var(--color-text-secondary)' }}>
            {error}
          </p>
          <button 
            onClick={fetchCreditUsage}
            className="btn-secondary text-sm"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!usage) {
    return (
      <div className="card">
        <div className="card-body text-center py-8">
          <p style={{ color: 'var(--color-text-secondary)' }}>No credit usage data available</p>
        </div>
      </div>
    );
  }

  const usagePercentage = (usage.used_this_month / usage.monthly_allocation) * 100;
  const plan = subscription?.plan ?? "pro";
  
  // Calculate features usage breakdown
  const featureUsage = usage.transactions.reduce((acc, transaction) => {
    if (transaction.amount < 0) {
      const feature = transaction.feature || 'Other';
      acc[feature] = (acc[feature] || 0) + Math.abs(transaction.amount);
    }
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
          AI Credit Usage
        </h2>
        <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Track your monthly AI credit consumption and history
        </p>
      </div>

      {/* Credit Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="card-body">
            <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>
              CURRENT BALANCE
            </p>
            <p className="text-2xl font-bold" style={{ color: 'var(--color-accent)' }}>
              {usage.current_balance.toLocaleString()}
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
              credits available
            </p>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>
              MONTHLY ALLOCATION
            </p>
            <p className="text-2xl font-bold" style={{ color: 'var(--color-text-primary)' }}>
              {usage.monthly_allocation.toLocaleString()}
            </p>
            <p className="text-xs mt-1 capitalize" style={{ color: 'var(--color-text-muted)' }}>
              {plan} plan limit
            </p>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>
              USED THIS MONTH
            </p>
            <p className="text-2xl font-bold" style={{ 
              color: usagePercentage > 80 ? '#f59e0b' : usagePercentage > 60 ? '#eab308' : 'var(--color-text-primary)' 
            }}>
              {usage.used_this_month.toLocaleString()}
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
              {usagePercentage.toFixed(1)}% of allocation
            </p>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>
              RESETS IN
            </p>
            <p className="text-2xl font-bold" style={{ color: 'var(--color-text-primary)' }}>
              {usage.days_until_reset}
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
              {usage.days_until_reset === 1 ? 'day' : 'days'}
            </p>
          </div>
        </div>
      </div>

      {/* Usage Progress Bar */}
      <div className="card">
        <div className="card-body">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              Monthly Progress
            </h3>
            <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
              {usage.used_this_month.toLocaleString()} / {usage.monthly_allocation.toLocaleString()}
            </span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2 mb-4">
            <div 
              className="h-2 rounded-full transition-all duration-500"
              style={{
                width: `${Math.min(usagePercentage, 100)}%`,
                backgroundColor: usagePercentage > 80 ? '#f59e0b' : usagePercentage > 60 ? '#eab308' : 'var(--color-accent)',
              }}
            />
          </div>
          {usagePercentage > 80 && (
            <div className="flex items-center gap-2 text-xs p-2 bg-yellow-500/10 border border-yellow-500/20 rounded">
              <span className="text-yellow-400">⚠️</span>
              <span style={{ color: 'var(--color-text-secondary)' }}>
                You&apos;ve used {usagePercentage.toFixed(1)}% of your monthly credits
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Feature Breakdown */}
      {Object.keys(featureUsage).length > 0 && (
        <div className="card">
          <div className="card-body">
            <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
              Usage by Feature
            </h3>
            <div className="space-y-3">
              {Object.entries(featureUsage)
                .sort((a, b) => b[1] - a[1])
                .map(([feature, credits]) => {
                  const percentage = (credits / usage.used_this_month) * 100;
                  return (
                    <div key={feature} className="flex items-center justify-between">
                      <div className="flex items-center gap-3 flex-1">
                        <span className="text-sm" style={{ color: 'var(--color-text-primary)' }}>
                          {feature}
                        </span>
                        <div className="flex-1 bg-gray-800 rounded-full h-1.5 max-w-32">
                          <div 
                            className="h-1.5 rounded-full"
                            style={{
                              width: `${percentage}%`,
                              backgroundColor: 'var(--color-accent-dim)',
                            }}
                          />
                        </div>
                      </div>
                      <span className="text-xs tabular-nums" style={{ color: 'var(--color-text-muted)' }}>
                        {credits.toLocaleString()} credits
                      </span>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}

      {/* Recent Transactions */}
      <div className="card">
        <div className="card-body">
          <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
            Recent Activity
          </h3>
          {usage.transactions.length === 0 ? (
            <p className="text-sm py-4 text-center" style={{ color: 'var(--color-text-muted)' }}>
              No credit transactions yet
            </p>
          ) : (
            <div className="space-y-3 max-h-80 overflow-y-auto">
              {usage.transactions.slice(0, 20).map((transaction) => (
                <div key={transaction.id} className="flex items-start justify-between py-2 border-b border-gray-800/50 last:border-b-0">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text-primary)' }}>
                      {transaction.description}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs px-2 py-0.5 rounded" style={{ 
                        backgroundColor: 'var(--color-accent-dim)', 
                        color: 'var(--color-accent-bright)' 
                      }}>
                        {transaction.feature}
                      </span>
                      <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                        {new Date(transaction.timestamp).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                    </div>
                  </div>
                  <div className="text-right ml-4">
                    <span 
                      className={`text-sm font-mono font-medium ${
                        transaction.amount > 0 ? 'text-green-400' : 'text-red-400'
                      }`}
                    >
                      {transaction.amount > 0 ? '+' : ''}{transaction.amount.toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}