"use client";

import React from 'react';

interface PricingTier {
  id: string;
  name: string;
  subtitle: string;
  price: {
    monthly: number | null;
    yearly: number | null;
  };
  priceDisplay: {
    monthly: string;
    yearly: string;
  };
  billingCycle: string;
  popular: boolean;
  features: string[];
  limitations: string[];
  ctaText: string;
  ctaVariant: 'primary' | 'secondary';
  annualDiscount?: {
    amount: number;
    percentage: number;
  };
  highlights?: Array<{
    icon: string;
    title: string;
    description: string;
  }>;
}

interface PricingCardProps {
  tier: PricingTier;
  isYearly: boolean;
  onSelectPlan: (tierId: string, billingCycle: 'monthly' | 'yearly') => void;
  isLoading?: boolean;
}

export default function PricingCard({ tier, isYearly, onSelectPlan, isLoading }: PricingCardProps): JSX.Element {
  const handleSelectPlan = (): void => {
    onSelectPlan(tier.id, isYearly ? 'yearly' : 'monthly');
  };

  const getCtaClasses = (): string => {
    if (tier.ctaVariant === 'primary') {
      return "w-full btn-primary";
    }
    return "w-full btn-secondary";
  };

  const renderPrice = (): JSX.Element => {
    if (tier.price.monthly === null) {
      return (
        <div className="flex items-baseline">
          <span className="text-3xl font-bold text-gray-100">Custom</span>
          <span className="text-gray-500 ml-2">pricing</span>
        </div>
      );
    }

    if (tier.price.monthly === 0) {
      return (
        <div className="flex items-baseline">
          <span className="text-3xl font-bold text-gray-100">Free</span>
          <span className="text-gray-500 ml-2">forever</span>
        </div>
      );
    }

    const currentPrice = isYearly ? tier.priceDisplay.yearly : tier.priceDisplay.monthly;
    const monthlyPrice = isYearly && tier.price.yearly 
      ? Math.round(tier.price.yearly / 12) 
      : tier.price.monthly;

    return (
      <div className="flex items-baseline">
        <span className="text-3xl font-bold text-gray-100">{currentPrice}</span>
        <span className="text-gray-500 ml-2">
          /{isYearly ? 'year' : 'month'}
        </span>
        {isYearly && tier.annualDiscount && (
          <div className="ml-3">
            <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
              Save ${tier.annualDiscount.amount}
            </span>
          </div>
        )}
      </div>
    );
  };

  const renderFeature = (feature: string, index: number): JSX.Element => {
    const isHighlight = feature.includes('🤖') || feature.includes('🔍') || feature.includes('🎭') || feature.includes('💡') || feature.includes('🔗');
    
    return (
      <li key={index} className="flex items-start gap-3">
        <svg 
          className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" 
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
        <span className={`text-sm ${isHighlight ? 'text-gray-100 font-medium' : 'text-gray-300'}`}>
          {feature}
        </span>
      </li>
    );
  };

  const renderLimitation = (limitation: string, index: number): JSX.Element => (
    <li key={index} className="flex items-start gap-3 opacity-60">
      <svg 
        className="w-4 h-4 text-gray-500 mt-0.5 flex-shrink-0" 
        fill="none" 
        stroke="currentColor" 
        viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
      </svg>
      <span className="text-sm text-gray-500 line-through">
        {limitation}
      </span>
    </li>
  );

  return (
    <div className={`relative bg-gray-900 rounded-xl border transition-all duration-200 ${
      tier.popular 
        ? 'border-brand-500/50 ring-1 ring-brand-500/20 scale-105' 
        : 'border-gray-800 hover:border-gray-700'
    }`}>
      {/* Popular badge */}
      {tier.popular && (
        <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
          <div className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-brand-600 text-white">
            Most Popular
          </div>
        </div>
      )}

      <div className="p-6">
        {/* Header */}
        <div className="text-center mb-6">
          <h3 className="text-xl font-bold text-gray-100 mb-1">{tier.name}</h3>
          <p className="text-sm text-gray-500 mb-4">{tier.subtitle}</p>
          {renderPrice()}
        </div>

        {/* Pro highlights */}
        {tier.highlights && (
          <div className="mb-6 p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
            <h4 className="text-sm font-semibold text-gray-100 mb-3">AI-Powered Security</h4>
            <div className="space-y-3">
              {tier.highlights.map((highlight, index) => (
                <div key={index} className="flex items-start gap-3">
                  <span className="text-lg">{highlight.icon}</span>
                  <div>
                    <div className="text-sm font-medium text-gray-200">{highlight.title}</div>
                    <div className="text-xs text-gray-500 mt-1">{highlight.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CTA Button */}
        <button 
          onClick={handleSelectPlan}
          disabled={isLoading}
          className={`${getCtaClasses()} mb-6 ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          {isLoading ? (
            <div className="flex items-center justify-center gap-2">
              <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-current" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Processing...
            </div>
          ) : (
            tier.ctaText
          )}
        </button>

        {/* Features */}
        <div className="space-y-3 mb-4">
          <h4 className="text-sm font-semibold text-gray-100">Features included:</h4>
          <ul className="space-y-2">
            {tier.features.map((feature, index) => renderFeature(feature, index))}
          </ul>
        </div>

        {/* Limitations */}
        {tier.limitations.length > 0 && (
          <div className="space-y-3 pt-4 border-t border-gray-800">
            <h4 className="text-sm font-semibold text-gray-400">Not included:</h4>
            <ul className="space-y-2">
              {tier.limitations.map((limitation, index) => renderLimitation(limitation, index))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}