"use client";

import { useState } from "react";

interface CreditPackage {
  id: string;
  credits: number;
  price: number;
  bonus?: number;
  popular?: boolean;
}

interface CreditPurchaseProps {
  currentBalance: number;
  isOpen: boolean;
  onClose: () => void;
  onPurchaseComplete?: (credits: number) => void;
}

const CREDIT_PACKAGES: CreditPackage[] = [
  {
    id: "credits_1000",
    credits: 1000,
    price: 10,
  },
  {
    id: "credits_5000",
    credits: 5000,
    price: 40,
    bonus: 500,
    popular: true,
  },
  {
    id: "credits_10000",
    credits: 10000,
    price: 75,
    bonus: 1500,
  },
  {
    id: "credits_25000",
    credits: 25000,
    price: 150,
    bonus: 5000,
  },
];

export function CreditPurchase({ 
  currentBalance, 
  isOpen, 
  onClose, 
  onPurchaseComplete 
}: CreditPurchaseProps): JSX.Element {
  const [selectedPackage, setSelectedPackage] = useState<CreditPackage | null>(null);
  const [purchasing, setPurchasing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return <></>;

  const handlePurchase = async (pkg: CreditPackage): Promise<void> => {
    setPurchasing(true);
    setError(null);
    setSelectedPackage(pkg);

    try {
      const response = await fetch('/api/v1/billing/credits/purchase', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          package_id: pkg.id,
          credits: pkg.credits,
          amount: pkg.price,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create purchase session');
      }

      const data = await response.json();
      
      // Redirect to Stripe checkout
      if (data.checkout_url) {
        window.location.href = data.checkout_url;
      } else {
        // For test mode or immediate purchase
        onPurchaseComplete?.(pkg.credits + (pkg.bonus || 0));
        onClose();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to purchase credits');
    } finally {
      setPurchasing(false);
      setSelectedPackage(null);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="card max-w-2xl w-full max-h-[80vh] overflow-y-auto">
        <div className="card-body">
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                Purchase Additional Credits
              </h2>
              <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
                Add more AI credits to your account for continued analysis
              </p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
                Current balance: <span className="font-mono">{currentBalance.toLocaleString()}</span> credits
              </p>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-300 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 mb-4">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {CREDIT_PACKAGES.map((pkg) => {
              const totalCredits = pkg.credits + (pkg.bonus || 0);
              const pricePerCredit = pkg.price / totalCredits;
              const isPurchasing = purchasing && selectedPackage?.id === pkg.id;

              return (
                <div
                  key={pkg.id}
                  className={`relative p-4 rounded-lg border transition-all ${
                    pkg.popular
                      ? 'border-blue-500/50 bg-blue-500/5'
                      : 'border-gray-800 hover:border-gray-700'
                  }`}
                >
                  {pkg.popular && (
                    <div className="absolute -top-2 left-1/2 transform -translate-x-1/2">
                      <span className="px-2 py-1 bg-blue-500 text-white text-xs font-medium rounded">
                        Best Value
                      </span>
                    </div>
                  )}

                  <div className="text-center">
                    <div className="text-2xl font-bold mb-1" style={{ color: 'var(--color-text-primary)' }}>
                      {pkg.credits.toLocaleString()}
                    </div>
                    {pkg.bonus && (
                      <div className="text-sm text-green-400 mb-2">
                        + {pkg.bonus.toLocaleString()} bonus credits
                      </div>
                    )}
                    <div className="text-sm mb-2" style={{ color: 'var(--color-text-muted)' }}>
                      Total: {totalCredits.toLocaleString()} credits
                    </div>
                    <div className="text-xl font-bold mb-2" style={{ color: 'var(--color-accent)' }}>
                      ${pkg.price}
                    </div>
                    <div className="text-xs mb-4" style={{ color: 'var(--color-text-muted)' }}>
                      ${pricePerCredit.toFixed(3)} per credit
                    </div>

                    <button
                      onClick={() => handlePurchase(pkg)}
                      disabled={purchasing}
                      className={`w-full text-sm ${
                        pkg.popular ? 'btn-primary' : 'btn-outline'
                      }`}
                    >
                      {isPurchasing ? (
                        <span className="flex items-center justify-center gap-2">
                          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                          </svg>
                          Processing...
                        </span>
                      ) : (
                        'Purchase'
                      )}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="border-t border-gray-800 pt-4">
            <div className="text-xs space-y-2" style={{ color: 'var(--color-text-muted)' }}>
              <div className="flex items-start gap-2">
                <svg className="w-3 h-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>Credits are added to your account immediately after purchase</span>
              </div>
              <div className="flex items-start gap-2">
                <svg className="w-3 h-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>Purchased credits expire at the end of your current billing cycle</span>
              </div>
              <div className="flex items-start gap-2">
                <svg className="w-3 h-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                </svg>
                <span>Secure payment processing through Stripe</span>
              </div>
            </div>
          </div>

          <div className="flex justify-between items-center mt-6 pt-4 border-t border-gray-800">
            <div className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
              Need more credits regularly?{' '}
              <a href="/pricing" className="text-blue-400 hover:text-blue-300">
                Upgrade to Team
              </a>
            </div>
            <button
              onClick={onClose}
              className="btn-outline text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}