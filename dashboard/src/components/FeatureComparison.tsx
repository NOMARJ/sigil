"use client";

import React from 'react';

interface ComparisonFeature {
  name: string;
  free: boolean | string;
  pro: boolean | string;
  enterprise: boolean | string;
}

interface FeatureCategory {
  category: string;
  features: ComparisonFeature[];
}

interface FeatureComparisonProps {
  categories: FeatureCategory[];
}

export default function FeatureComparison({ categories }: FeatureComparisonProps): JSX.Element {
  const renderFeatureValue = (value: boolean | string, tierName: string): JSX.Element => {
    if (typeof value === 'boolean') {
      return value ? (
        <div className="flex justify-center">
          <svg className="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
      ) : (
        <div className="flex justify-center">
          <svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </div>
      );
    }

    return (
      <div className="text-center">
        <span className={`text-sm font-medium ${
          tierName === 'pro' ? 'text-gray-100' : 'text-gray-300'
        }`}>
          {value}
        </span>
      </div>
    );
  };

  const getTierHeaderClasses = (tier: string): string => {
    switch (tier) {
      case 'pro':
        return 'bg-brand-600/10 border-brand-500/30';
      case 'enterprise':
        return 'bg-gray-800 border-gray-700';
      default:
        return 'bg-gray-900 border-gray-800';
    }
  };

  const getTierNameClasses = (tier: string): string => {
    switch (tier) {
      case 'pro':
        return 'text-brand-400 font-semibold';
      case 'enterprise':
        return 'text-gray-100 font-semibold';
      default:
        return 'text-gray-200 font-medium';
    }
  };

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      {/* Mobile-only tier selector */}
      <div className="md:hidden">
        <div className="p-4 border-b border-gray-800">
          <h3 className="text-lg font-semibold text-gray-100 mb-4">Compare Plans</h3>
          <p className="text-sm text-gray-400">
            Tap a plan below to see features. Full comparison available on desktop.
          </p>
        </div>
        {/* Mobile tier cards */}
        <div className="space-y-4 p-4">
          {['free', 'pro', 'enterprise'].map((tier) => (
            <div key={tier} className={`p-4 rounded-lg border ${getTierHeaderClasses(tier)}`}>
              <div className="text-center">
                <div className={getTierNameClasses(tier)}>
                  {tier === 'free' ? 'Free' : tier === 'pro' ? 'Pro' : 'Enterprise'}
                </div>
                <div className="text-sm text-gray-500 mt-1">
                  {tier === 'free' ? '$0/month' : tier === 'pro' ? '$29/month' : 'Custom'}
                </div>
              </div>
              <div className="mt-4 space-y-3">
                {categories.slice(0, 1).map((category) => 
                  category.features.slice(0, 3).map((feature) => (
                    <div key={feature.name} className="flex justify-between items-center">
                      <span className="text-sm text-gray-300">{feature.name}</span>
                      <div className="ml-2">
                        {renderFeatureValue(
                          tier === 'free' ? feature.free : tier === 'pro' ? feature.pro : feature.enterprise,
                          tier
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Desktop table */}
      <div className="hidden md:block">
        {/* Header */}
        <div className="grid grid-cols-4 gap-0">
        <div className="p-4 bg-gray-950 border-b border-gray-800">
          <h3 className="text-lg font-semibold text-gray-100">Features</h3>
        </div>
        <div className={`p-4 border-b border-l border-gray-800 ${getTierHeaderClasses('free')}`}>
          <div className="text-center">
            <div className={getTierNameClasses('free')}>Free</div>
            <div className="text-sm text-gray-500 mt-1">$0/month</div>
          </div>
        </div>
        <div className={`p-4 border-b border-l border-gray-800 relative ${getTierHeaderClasses('pro')}`}>
          <div className="absolute -top-2 left-1/2 transform -translate-x-1/2">
            <div className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-brand-600 text-white">
              Popular
            </div>
          </div>
          <div className="text-center">
            <div className={getTierNameClasses('pro')}>Pro</div>
            <div className="text-sm text-gray-500 mt-1">$29/month</div>
          </div>
        </div>
        <div className={`p-4 border-b border-l border-gray-800 ${getTierHeaderClasses('enterprise')}`}>
          <div className="text-center">
            <div className={getTierNameClasses('enterprise')}>Enterprise</div>
            <div className="text-sm text-gray-500 mt-1">Custom</div>
          </div>
        </div>
      </div>

      {/* Feature categories */}
      {categories.map((category, categoryIndex) => (
        <div key={categoryIndex}>
          {/* Category header */}
          <div className="grid grid-cols-4 gap-0 bg-gray-800/50">
            <div className="col-span-4 p-3 border-b border-gray-800">
              <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
                {category.category}
              </h4>
            </div>
          </div>

          {/* Category features */}
          {category.features.map((feature, featureIndex) => (
            <div 
              key={featureIndex} 
              className={`grid grid-cols-4 gap-0 ${
                featureIndex !== category.features.length - 1 ? 'border-b border-gray-800/50' : ''
              }`}
            >
              <div className="p-4 border-r border-gray-800">
                <span className="text-sm text-gray-300">{feature.name}</span>
              </div>
              <div className="p-4 border-r border-gray-800 bg-gray-900/50">
                {renderFeatureValue(feature.free, 'free')}
              </div>
              <div className="p-4 border-r border-gray-800 bg-brand-600/5">
                {renderFeatureValue(feature.pro, 'pro')}
              </div>
              <div className="p-4 bg-gray-900/50">
                {renderFeatureValue(feature.enterprise, 'enterprise')}
              </div>
            </div>
          ))}
        </div>
      ))}

        {/* CTA Footer */}
        <div className="grid grid-cols-4 gap-4 p-4 bg-gray-950 border-t border-gray-800">
          <div></div>
          <div>
            <button className="w-full btn-secondary text-sm">
              Get Started
            </button>
          </div>
          <div>
            <button className="w-full btn-primary text-sm">
              Start Pro Trial
            </button>
          </div>
          <div>
            <button className="w-full btn-secondary text-sm">
              Contact Sales
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}