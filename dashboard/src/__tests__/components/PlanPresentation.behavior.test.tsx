import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import PricingCard from '@/components/PricingCard';
import FeatureComparison from '@/components/FeatureComparison';
import ProFeatures from '@/components/ProFeatures';
import UpgradeCTA, { FeatureLockedCTA } from '@/components/UpgradeCTA';
import ProBadge from '@/components/ProBadge';
import { PlanBadge, UserPlanHeader } from '@/components/ui/PlanBadge';
import StatsCard from '@/components/StatsCard';
import { EnhancedStatsCard } from '@/components/ui/EnhancedStatsCard';
import type { LLMAnalysisResponse } from '@/lib/types';

const tier = { id: '[MOCK] pro', name: '[MOCK] Pro', subtitle: '[MOCK] Security', price: { monthly: 29, yearly: 290 }, priceDisplay: { monthly: '$29', yearly: '$290' }, billingCycle: 'monthly', popular: true, features: ['🤖 [MOCK] AI investigation', '[MOCK] Scans'], limitations: ['[MOCK] SSO'], ctaText: '[MOCK] Select plan', ctaVariant: 'primary' as const, annualDiscount: { amount: 58, percentage: 17 }, highlights: [{ icon: '🔍', title: '[MOCK] Analysis', description: '[MOCK] Context' }] };

it.each([false, true])('shows pricing and sends plan selection with yearly=%s', yearly => {
  const select = jest.fn();
  render(<PricingCard tier={tier} isYearly={yearly} onSelectPlan={select} />);
  expect(screen.getByText(yearly ? '$290' : '$29')).toBeInTheDocument();
  expect(screen.getByText('Most Popular')).toBeInTheDocument();
  expect(screen.getByText('[MOCK] Analysis')).toBeInTheDocument();
  expect(screen.getByText('[MOCK] SSO')).toBeInTheDocument();
  if (yearly) expect(screen.getByText('Save $58')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: tier.ctaText }));
  expect(select).toHaveBeenCalledWith(tier.id, yearly ? 'yearly' : 'monthly');
});
it.each([0, null])('renders free/custom price %s', monthly => {
  render(<PricingCard tier={{ ...tier, popular: false, price: { monthly, yearly: null }, ctaVariant: 'secondary', highlights: undefined, limitations: [] }} isYearly onSelectPlan={jest.fn()} />);
  expect(screen.getByText(monthly === 0 ? 'Free' : 'Custom')).toBeInTheDocument();
  expect(screen.queryByText('Not included:')).not.toBeInTheDocument();
});
it('disables selection while processing', () => {
  const select = jest.fn();
  render(<PricingCard tier={tier} isYearly={false} isLoading onSelectPlan={select} />);
  fireEvent.click(screen.getByRole('button', { name: 'Processing...' }));
  expect(select).not.toHaveBeenCalled();
  expect(screen.getByRole('button')).toBeDisabled();
});
it('compares string limits and boolean availability', () => {
  const { container } = render(<FeatureComparison categories={[{ category: '[MOCK] Security', features: [{ name: '[MOCK] Credits', free: '0 credits', pro: '5,000 credits', enterprise: 'Custom allocation' }, { name: '[MOCK] Investigation', free: false, pro: true, enterprise: true }] }]} />);
  expect(screen.getAllByText('5,000 credits')).toHaveLength(2);
  expect(screen.getAllByText('0 credits')).toHaveLength(2);
  expect(container.querySelectorAll('svg.text-green-400')).toHaveLength(4);
  expect(container.querySelectorAll('svg.text-gray-600')).toHaveLength(2);
});
it('renders empty comparison', () => {
  render(<FeatureComparison categories={[]} />);
  expect(screen.getByText('Compare Plans')).toBeInTheDocument();
});
it.each(['banner', 'card', 'inline', 'modal'] as const)('links %s upgrades and dismisses', variant => {
  const close = jest.fn();
  const { container } = render(<UpgradeCTA variant={variant} creditsNeeded={12} currentBalance={3} onClose={close} />);
  expect(screen.getByRole('link')).toHaveAttribute('href', '/pricing');
  if (variant === 'modal') expect(screen.getByText(/You need 12 credits, but only have 3/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: variant === 'modal' ? 'Maybe Later' : 'Dismiss upgrade prompt' }));
  expect(close).toHaveBeenCalledTimes(1);
  expect(container).toBeEmptyDOMElement();
});
it('explains locked features', () => {
  render(<FeatureLockedCTA featureName="[MOCK] Investigation" description="[MOCK] Upgrade required" />);
  expect(screen.getByText('[MOCK] Upgrade required')).toBeInTheDocument();
  expect(screen.getByRole('link')).toHaveAttribute('href', '/pricing');
});
it.each(['sm', 'md', 'lg'] as const)('renders compact Pro %s', size => {
  render(<ProBadge size={size} variant="compact" />);
  expect(screen.getByText('PRO')).toBeInTheDocument();
});
it('renders default Pro badge', () => {
  render(<ProBadge />);
  expect(screen.getByText('Pro Plan')).toBeInTheDocument();
});
it.each([['free', 'Free'], ['pro', 'Pro Plan'], ['enterprise', 'Enterprise'], ['trial', 'Trial']] as const)('renders %s label and optional icon', (plan, label) => {
  const { container, rerender } = render(<PlanBadge plan={plan} className="mock-class" />);
  expect(screen.getByText(label)).toHaveClass('badge-plan', 'mock-class');
  expect(container.querySelector('svg') !== null).toBe(plan !== 'free');
  rerender(<PlanBadge plan={plan} showIcon={false} />);
  expect(container.querySelector('svg')).not.toBeInTheDocument();
});
it('shows default initial and supplied avatar', () => {
  const { rerender } = render(<UserPlanHeader />);
  expect(screen.getByText('User')).toBeInTheDocument();
  expect(screen.getByText('U')).toBeInTheDocument();
  rerender(<UserPlanHeader userName="[MOCK] User" plan="trial" avatarUrl="https://avatar.invalid/mock.png" />);
  expect(screen.getByRole('img', { name: '[MOCK] User' })).toHaveAttribute('src', 'https://avatar.invalid/mock.png');
});
it.each([-12, 0, 8])('shows trend %s direction', trend => {
  render(<StatsCard title="[MOCK] Credits" value={123} subtitle="[MOCK] Remaining" trend={trend} icon={<span>[MOCK] Icon</span>} accentColor="blue" />);
  expect(screen.getByText('123')).toBeInTheDocument();
  expect(screen.getByText(`${Math.abs(trend)}%`)).toHaveClass(trend >= 0 ? 'text-green-400' : 'text-red-400');
});
it('omits optional stat fields', () => {
  render(<StatsCard title="[MOCK] Credits" value="Unlimited" icon={null} />);
  expect(screen.getByText('Unlimited')).toBeInTheDocument();
  expect(screen.queryByText(/%/)).not.toBeInTheDocument();
});
it.each(['default', 'success', 'warning', 'danger', 'info'] as const)('renders enhanced %s state', status => {
  render(<EnhancedStatsCard title="[MOCK] Balance" value={40} status={status} subtitle="[MOCK] available" icon={<span>[MOCK] Icon</span>} trend={{ value: -5, isPositive: status === 'success' }} />);
  expect(screen.getByText('40')).toBeInTheDocument();
  expect(screen.getByText('5%').parentElement).toHaveClass(status === 'success' ? 'text-success-400' : 'text-danger-400');
});
it('renders enhanced stats without optional fields', () => {
  render(<EnhancedStatsCard title="[MOCK] Usage" value={0} />);
  expect(screen.getByText('0')).toBeInTheDocument();
});
const analysis = { insights: [{ analysis_type: 'zero_day_detection', confidence: 0.8, severity_adjustment: 3 }], context_analysis: { attack_chain_detected: true, overall_intent: '[MOCK] exfiltration', sophistication_level: 'high', coordinated_threat: true }, tokens_used: 1200, model_used: '[MOCK] offline-model', processing_time_ms: 1500, confidence_summary: { high_confidence: 1 }, threat_summary: { data_theft: 1 } } as unknown as LLMAnalysisResponse;
it('computes threat metrics and toggles resource details', () => {
  render(<ProFeatures analysisResponse={analysis} />);
  expect(screen.getByText('80% avg confidence')).toBeInTheDocument();
  expect(screen.getByText('🚨 Novel threats detected')).toBeInTheDocument();
  expect(screen.getByText('Multi-step attack detected')).toBeInTheDocument();
  expect(screen.getByText('1.5s')).toBeInTheDocument();
  expect(screen.getByText('1,200')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Show Details' }));
  expect(screen.getByText('high confidence')).toBeInTheDocument();
  expect(screen.getByText('data theft')).toBeInTheDocument();
  expect(screen.getByText('Coordinated threat')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Hide Details' }));
  expect(screen.queryByText('Context Analysis')).not.toBeInTheDocument();
});
it('handles empty insight/context results', () => {
  render(<ProFeatures analysisResponse={{ ...analysis, insights: [], context_analysis: null, confidence_summary: {}, threat_summary: {} }} />);
  expect(screen.getByText('0% avg confidence')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Show Details' }));
  expect(screen.queryByText('Context Analysis')).not.toBeInTheDocument();
});
