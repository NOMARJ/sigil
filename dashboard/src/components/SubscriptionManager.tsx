"use client";

import { useState, useEffect } from "react";

interface SubscriptionDetails {
  plan: string;
  status: string;
  billing_interval: "monthly" | "annual";
  current_period_start?: string | null;
  current_period_end?: string | null;
  cancel_at_period_end?: boolean;
  price_amount?: number;
  stripe_subscription_id?: string;
  checkout_url?: string;
}

interface InvoiceHistory {
  id: string;
  date: string;
  amount: number;
  status: string;
  invoice_url?: string;
}

interface SubscriptionManagerProps {
  subscription: SubscriptionDetails | null;
  onSubscriptionUpdate?: (subscription: SubscriptionDetails) => void;
}

export function SubscriptionManager({ 
  subscription, 
  onSubscriptionUpdate 
}: SubscriptionManagerProps): JSX.Element {
  const [invoices, setInvoices] = useState<InvoiceHistory[]>([]);
  const [loading, setLoading] = useState(false);
  const [portalLoading, setPortalLoading] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (subscription?.plan && subscription.plan !== 'free') {
      fetchInvoiceHistory();
    }
  }, [subscription]);

  const fetchInvoiceHistory = async (): Promise<void> => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/billing/invoices');
      if (!response.ok) {
        throw new Error('Failed to fetch invoice history');
      }
      const data = await response.json();
      setInvoices(data.invoices || []);
    } catch (err) {
      console.error('Failed to fetch invoices:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleManageBilling = async (): Promise<void> => {
    setPortalLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/billing/portal', {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Failed to create portal session');
      }
      const data = await response.json();
      window.location.href = data.url;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to open billing portal');
    } finally {
      setPortalLoading(false);
    }
  };

  const handleCancelSubscription = async (): Promise<void> => {
    if (!confirm('Are you sure you want to cancel your subscription? You&apos;ll lose access to Pro features at the end of your billing period.')) {
      return;
    }

    setCancelLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/billing/cancel', {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Failed to cancel subscription');
      }
      const updatedSubscription = await response.json();
      onSubscriptionUpdate?.(updatedSubscription);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to cancel subscription');
    } finally {
      setCancelLoading(false);
    }
  };

  const handleReactivateSubscription = async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/billing/reactivate', {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Failed to reactivate subscription');
      }
      const updatedSubscription = await response.json();
      onSubscriptionUpdate?.(updatedSubscription);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reactivate subscription');
    } finally {
      setLoading(false);
    }
  };

  if (!subscription || subscription.plan === 'free') {
    return (
      <div className="card border-blue-500/30">
        <div className="card-body text-center py-8">
          <div className="text-4xl mb-4">💎</div>
          <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
            No active subscription
          </h3>
          <p className="text-sm mb-6" style={{ color: 'var(--color-text-secondary)' }}>
            You&apos;re currently on the free plan. Upgrade to Pro for AI investigation features and 5,000 monthly credits.
          </p>
          <a href="/pricing" className="btn-primary">
            View Plans
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
          Subscription Management
        </h2>
        <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Manage your billing, view invoices, and update subscription settings
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Subscription Status */}
      <div className="card">
        <div className="card-body">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3 className="text-lg font-semibold capitalize mb-1" style={{ color: 'var(--color-text-primary)' }}>
                {subscription.plan} Plan
              </h3>
              <div className="flex items-center gap-3 text-sm">
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  subscription.status === 'active' 
                    ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                    : subscription.status === 'trialing'
                      ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                }`}>
                  {subscription.status.charAt(0).toUpperCase() + subscription.status.slice(1)}
                </span>
                <span style={{ color: 'var(--color-text-muted)' }} className="capitalize">
                  {subscription.billing_interval} billing
                </span>
                {subscription.price_amount && (
                  <span style={{ color: 'var(--color-text-muted)' }}>
                    ${subscription.price_amount}/{subscription.billing_interval === 'annual' ? 'year' : 'month'}
                  </span>
                )}
              </div>
              {subscription.cancel_at_period_end && (
                <p className="text-sm mt-2 text-yellow-400">
                  ⚠️ Subscription will cancel on {subscription.current_period_end ? new Date(subscription.current_period_end).toLocaleDateString() : 'the next billing date'}
                </p>
              )}
            </div>
            <button
              onClick={handleManageBilling}
              disabled={portalLoading}
              className="btn-secondary"
            >
              {portalLoading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Opening...
                </span>
              ) : (
                'Manage in Stripe'
              )}
            </button>
          </div>

          {subscription.current_period_start && subscription.current_period_end && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-gray-800/30 rounded-lg">
              <div>
                <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>
                  CURRENT PERIOD START
                </p>
                <p className="text-sm" style={{ color: 'var(--color-text-primary)' }}>
                  {new Date(subscription.current_period_start).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>
                  NEXT BILLING DATE
                </p>
                <p className="text-sm" style={{ color: 'var(--color-text-primary)' }}>
                  {new Date(subscription.current_period_end).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card">
        <div className="card-body">
          <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
            Quick Actions
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <button 
              onClick={handleManageBilling}
              disabled={portalLoading}
              className="btn-outline text-sm p-3 flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
              </svg>
              Update Payment Method
            </button>
            
            <button 
              onClick={handleManageBilling}
              disabled={portalLoading}
              className="btn-outline text-sm p-3 flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
              </svg>
              {subscription.plan === 'pro' ? 'Upgrade to Team' : 'Change Plan'}
            </button>

            {subscription.cancel_at_period_end ? (
              <button 
                onClick={handleReactivateSubscription}
                disabled={loading}
                className="btn-primary text-sm p-3 flex items-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Reactivate Subscription
              </button>
            ) : (
              <button 
                onClick={handleCancelSubscription}
                disabled={cancelLoading}
                className="btn-outline text-sm p-3 flex items-center gap-2 text-red-400 border-red-500/30 hover:bg-red-500/10"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                {cancelLoading ? 'Cancelling...' : 'Cancel Subscription'}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Invoice History */}
      <div className="card">
        <div className="card-body">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              Billing History
            </h3>
            <button 
              onClick={fetchInvoiceHistory}
              disabled={loading}
              className="btn-outline text-xs"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Refreshing...
                </span>
              ) : (
                'Refresh'
              )}
            </button>
          </div>

          {loading && invoices.length === 0 ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-gray-800/30 rounded border border-gray-800 animate-pulse">
                  <div className="flex items-center gap-3">
                    <div className="h-4 w-20 bg-gray-800 rounded" />
                    <div className="h-3 w-16 bg-gray-800 rounded" />
                  </div>
                  <div className="h-4 w-12 bg-gray-800 rounded" />
                </div>
              ))}
            </div>
          ) : invoices.length === 0 ? (
            <p className="text-sm py-4 text-center" style={{ color: 'var(--color-text-muted)' }}>
              No billing history available
            </p>
          ) : (
            <div className="space-y-2">
              {invoices.map((invoice) => (
                <div key={invoice.id} className="flex items-center justify-between p-3 bg-gray-800/30 rounded border border-gray-800 hover:border-gray-700 transition-colors">
                  <div className="flex items-center gap-3">
                    <div>
                      <p className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>
                        {new Date(invoice.date).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'short',
                          day: 'numeric'
                        })}
                      </p>
                      <p className={`text-xs font-medium ${
                        invoice.status === 'paid' ? 'text-green-400' : 
                        invoice.status === 'pending' ? 'text-yellow-400' : 
                        'text-red-400'
                      }`}>
                        {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm font-mono" style={{ color: 'var(--color-text-primary)' }}>
                        ${invoice.amount.toFixed(2)}
                      </p>
                    </div>
                  </div>
                  {invoice.invoice_url && (
                    <a 
                      href={invoice.invoice_url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="btn-outline text-xs px-3 py-1"
                    >
                      Download PDF
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}