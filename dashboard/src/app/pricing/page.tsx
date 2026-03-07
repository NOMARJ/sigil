"use client";

import React, { useState, useEffect } from 'react';
import { Metadata } from 'next';
import PricingCard from '@/components/PricingCard';
import FeatureComparison from '@/components/FeatureComparison';

interface PricingData {
  tiers: Array<{
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
  }>;
  comparisonFeatures: Array<{
    category: string;
    features: Array<{
      name: string;
      free: boolean | string;
      pro: boolean | string;
      enterprise: boolean | string;
    }>;
  }>;
  testimonials: Array<{
    quote: string;
    author: string;
    title: string;
    company: string;
    avatar: string;
  }>;
  faqs: Array<{
    question: string;
    answer: string;
  }>;
}

export default function PricingPage(): JSX.Element {
  const [pricingData, setPricingData] = useState<PricingData | null>(null);
  const [isYearly, setIsYearly] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [expandedFaq, setExpandedFaq] = useState<number | null>(null);

  useEffect(() => {
    // Load pricing data
    fetch('/pricing-data.json')
      .then(response => response.json())
      .then(data => setPricingData(data))
      .catch(error => console.error('Failed to load pricing data:', error));
  }, []);

  const handleSelectPlan = async (tierId: string, billingCycle: 'monthly' | 'yearly'): Promise<void> => {
    if (tierId === 'free') {
      // Redirect to signup for free plan
      window.location.href = '/auth/signup';
      return;
    }

    if (tierId === 'enterprise') {
      // Open contact form or redirect to sales
      window.open('mailto:sales@sigilsec.ai?subject=Enterprise%20Plan%20Inquiry', '_blank');
      return;
    }

    if (tierId === 'pro') {
      setIsLoading(true);
      
      try {
        // Create Stripe checkout session
        const response = await fetch('/api/billing/create-checkout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            tier: 'pro',
            billing_cycle: billingCycle,
            success_url: `${window.location.origin}/pro?checkout=success`,
            cancel_url: `${window.location.origin}/pricing?checkout=cancelled`,
          }),
        });

        if (response.ok) {
          const { checkout_url } = await response.json();
          window.location.href = checkout_url;
        } else {
          throw new Error('Failed to create checkout session');
        }
      } catch (error) {
        console.error('Checkout error:', error);
        alert('Unable to process payment. Please try again or contact support.');
      } finally {
        setIsLoading(false);
      }
    }
  };

  const toggleFaq = (index: number): void => {
    setExpandedFaq(expandedFaq === index ? null : index);
  };

  if (!pricingData) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand-500 mx-auto"></div>
          <p className="text-gray-500 mt-4">Loading pricing...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Hero Section */}
      <div className="relative">
        <div className="absolute inset-0 bg-gradient-to-br from-brand-900/20 to-transparent"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-16 pb-24">
          <div className="text-center">
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-gray-100 mb-6">
              Protect Your Code with{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand-400 to-brand-600">
                AI-Powered
              </span>{' '}
              Security
            </h1>
            <p className="text-xl text-gray-400 mb-8 max-w-3xl mx-auto">
              Advanced threat detection that goes beyond static analysis. Catch zero-day attacks, 
              sophisticated obfuscation, and supply chain threats with LLM-powered insights.
            </p>

            {/* Billing Toggle */}
            <div className="flex items-center justify-center gap-4 mb-12">
              <span className={`text-sm font-medium ${!isYearly ? 'text-gray-100' : 'text-gray-500'}`}>
                Monthly
              </span>
              <button
                onClick={() => setIsYearly(!isYearly)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  isYearly ? 'bg-brand-600' : 'bg-gray-700'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    isYearly ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
              <span className={`text-sm font-medium ${isYearly ? 'text-gray-100' : 'text-gray-500'}`}>
                Yearly
              </span>
              {isYearly && (
                <span className="ml-2 inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
                  Save 33%
                </span>
              )}
            </div>
          </div>

          {/* Pricing Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8 max-w-6xl mx-auto mb-20">
            {pricingData.tiers.map((tier) => (
              <PricingCard
                key={tier.id}
                tier={tier}
                isYearly={isYearly}
                onSelectPlan={handleSelectPlan}
                isLoading={isLoading}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Feature Comparison */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="text-center mb-8 lg:mb-12">
          <h2 className="text-2xl lg:text-3xl font-bold text-gray-100 mb-4">
            Compare Plans
          </h2>
          <p className="text-base lg:text-lg text-gray-400 max-w-2xl mx-auto">
            Choose the perfect plan for your security needs. Upgrade anytime as your requirements grow.
          </p>
        </div>
        
        <FeatureComparison categories={pricingData.comparisonFeatures} />
      </div>

      {/* Pro Tier Benefits */}
      <div className="bg-gray-900/50 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-100 mb-4">
              Why Choose Pro?
            </h2>
            <p className="text-lg text-gray-400 max-w-2xl mx-auto">
              Go beyond traditional static analysis with AI-powered threat detection
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
              <div className="text-4xl mb-4">🤖</div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">AI-Powered Analysis</h3>
              <p className="text-gray-400 text-sm">
                Claude AI analyzes code context and relationships to detect sophisticated threats 
                that traditional pattern matching misses.
              </p>
            </div>

            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
              <div className="text-4xl mb-4">🔍</div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">Zero-Day Detection</h3>
              <p className="text-gray-400 text-sm">
                Identify novel attack patterns and previously unknown threats before they become 
                widespread security issues.
              </p>
            </div>

            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
              <div className="text-4xl mb-4">🎭</div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">Advanced Obfuscation</h3>
              <p className="text-gray-400 text-sm">
                Detect sophisticated hiding techniques including steganography, 
                multi-layer encoding, and polymorphic code.
              </p>
            </div>

            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
              <div className="text-4xl mb-4">💡</div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">Smart Insights</h3>
              <p className="text-gray-400 text-sm">
                Get natural language explanations of threats, impact assessment, 
                and actionable remediation steps.
              </p>
            </div>

            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
              <div className="text-4xl mb-4">🔗</div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">Attack Chain Analysis</h3>
              <p className="text-gray-400 text-sm">
                Understand multi-file attack coordination and cross-dependency exploitation 
                patterns in complex codebases.
              </p>
            </div>

            <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
              <div className="text-4xl mb-4">📊</div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">Confidence Scoring</h3>
              <p className="text-gray-400 text-sm">
                Reduce false positives with intelligent confidence levels and 
                contextual threat prioritization.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Testimonials */}
      <div className="py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-100 mb-4">
              Trusted by Security Teams
            </h2>
            <p className="text-lg text-gray-400">
              See how teams are using Sigil to catch threats others miss
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {pricingData.testimonials.map((testimonial, index) => (
              <div key={index} className="bg-gray-900 p-6 rounded-xl border border-gray-800">
                <blockquote className="text-gray-300 mb-4">
                  &ldquo;{testimonial.quote}&rdquo;
                </blockquote>
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 flex items-center justify-center text-sm font-medium text-gray-300">
                    {testimonial.author.split(' ').map(n => n[0]).join('')}
                  </div>
                  <div>
                    <div className="font-medium text-gray-200">{testimonial.author}</div>
                    <div className="text-sm text-gray-500">{testimonial.title}, {testimonial.company}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* FAQ */}
      <div className="bg-gray-900/50 py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-100 mb-4">
              Frequently Asked Questions
            </h2>
          </div>

          <div className="space-y-4">
            {pricingData.faqs.map((faq, index) => (
              <div key={index} className="bg-gray-900 rounded-lg border border-gray-800">
                <button
                  onClick={() => toggleFaq(index)}
                  className="w-full p-6 text-left flex justify-between items-center hover:bg-gray-800/50 transition-colors"
                >
                  <h3 className="text-lg font-medium text-gray-100">{faq.question}</h3>
                  <svg
                    className={`w-5 h-5 text-gray-400 transition-transform ${
                      expandedFaq === index ? 'transform rotate-180' : ''
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {expandedFaq === index && (
                  <div className="px-6 pb-6">
                    <p className="text-gray-400">{faq.answer}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Final CTA */}
      <div className="py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold text-gray-100 mb-4">
            Ready to Secure Your Code?
          </h2>
          <p className="text-lg text-gray-400 mb-8">
            Join thousands of developers protecting their applications with AI-powered security.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button 
              onClick={() => handleSelectPlan('free', 'monthly')}
              className="btn-secondary"
            >
              Start Free
            </button>
            <button 
              onClick={() => handleSelectPlan('pro', isYearly ? 'yearly' : 'monthly')}
              className="btn-primary"
              disabled={isLoading}
            >
              Try Pro Free for 14 Days
            </button>
          </div>
          <p className="text-sm text-gray-500 mt-4">
            No credit card required for free trial
          </p>
        </div>
      </div>
    </div>
  );
}