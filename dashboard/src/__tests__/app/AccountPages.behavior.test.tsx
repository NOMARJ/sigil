import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Pricing from '@/app/pricing/page';
import Pro from '@/app/pro/page';
import Onboarding from '@/app/onboarding/pro/page';
import * as api from '@/lib/api';
import { useUser } from '@auth0/nextjs-auth0/client';

// [MOCK] External billing/auth services never connect; fixture identity is unusable.
jest.mock('@/lib/api');
jest.mock('@auth0/nextjs-auth0/client', () => ({ useUser: jest.fn() }));
const push = jest.fn();
jest.mock('next/navigation', () => ({ useRouter: () => ({ push }), useSearchParams: () => new URLSearchParams() }));
jest.mock('@/components/CreditUsageDashboard', () => ({ CreditUsageDashboard: () => <div>Mock credit usage</div> }));
jest.mock('@/components/ProOnboardingFlow', () => ({ ProOnboardingFlow: () => <div>Mock onboarding flow</div> }));
const mocked = jest.mocked(api);
beforeEach(() => { jest.clearAllMocks(); mocked.getSubscription.mockResolvedValue({ plan: 'free', status: 'active' } as never); jest.mocked(useUser).mockReturnValue({ user: { sub: 'mock-unusable-identity' }, isLoading: false } as never); });
it('upgrades directly with the Pro monthly API contract and shows the resulting subscription', async () => {
  mocked.subscribe.mockResolvedValue({ plan: 'pro', status: 'active', current_period_end: '2026-11-01T00:00:00Z', billing_interval: 'annual' } as never);
  render(<Pricing />);
  fireEvent.click(await screen.findByRole('button', { name: /Start 14-day/ }));
  expect(await screen.findByText('Manage your plan and billing')).toBeInTheDocument();
  expect(mocked.subscribe).toHaveBeenCalledWith('pro', 'monthly');
  expect(screen.getByText(/annual billing/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Upgrade to Team' })).toBeInTheDocument();
});
it.each([new Error('Mock checkout unavailable'), 'mock rejection'])('shows checkout errors and allows retry (%s)', async (error) => {
  mocked.getSubscription.mockRejectedValue(new Error('Mock unauthenticated'));
  mocked.subscribe.mockRejectedValue(error);
  render(<Pricing />);
  fireEvent.click(await screen.findByRole('button', { name: /Start 14-day/ }));
  expect(await screen.findByText(error instanceof Error ? error.message : 'Unable to start checkout. Please try again.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /Start 14-day/ })).toBeEnabled();
});
it.each(['enterprise'])('shows %s features and portal failure feedback', async (plan) => {
  mocked.getSubscription.mockResolvedValue({ plan, status: 'trialing' } as never);
  mocked.createPortalSession.mockRejectedValue(new Error('Mock portal unavailable'));
  const alert = jest.spyOn(window, 'alert').mockImplementation(() => {});
  render(<Pricing />);
  fireEvent.click(await screen.findByRole('button', { name: 'Manage Billing' }));
  await waitFor(() => expect(alert).toHaveBeenCalledWith('Unable to open billing portal. Please try again.'));
  expect(screen.getByText(plan === 'team' ? '50,000 monthly AI credits' : 'Unlimited AI credits')).toBeInTheDocument();
  alert.mockRestore();
});
it('treats an inactive paid subscription as an upgrade opportunity', async () => {
  mocked.getSubscription.mockResolvedValue({ plan: 'pro', status: 'canceled' } as never);
  render(<Pricing />);
  expect(await screen.findByRole('heading', { name: 'Upgrade to Pro' })).toBeInTheDocument();
});
it.each(['pro', 'enterprise'])('shows Pro tools and usage for %s', async (plan) => {
  mocked.getSubscription.mockResolvedValue({ plan, status: 'active', current_period_end: '2026-11-01T00:00:00Z', billing_interval: 'annual' } as never);
  render(<Pro />);
  expect(await screen.findByText('Mock credit usage')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'View Scans' })).toHaveAttribute('href', '/scans');
  expect(screen.getByText('annual billing')).toBeInTheDocument();
});
it('keeps Pro features locked when subscription lookup fails', async () => {
  mocked.getSubscription.mockRejectedValue(new Error('Mock subscription unavailable'));
  render(<Pro />);
  expect(await screen.findByText('Pro features require a Pro plan')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Upgrade to Pro' })).toHaveAttribute('href', '/pricing');
});
it.each(['active', 'trialing'])('opens onboarding for an authenticated %s paid user', async (status) => {
  mocked.getSubscription.mockResolvedValue({ plan: 'pro', status } as never);
  render(<Onboarding />);
  expect(await screen.findByText('Mock onboarding flow')).toBeInTheDocument();
  expect(push).not.toHaveBeenCalled();
});
it.each([{ plan: 'free', status: 'active' }, { plan: 'pro', status: 'past_due' }])('redirects ineligible onboarding subscriptions (%s)', async (subscription) => {
  mocked.getSubscription.mockResolvedValue(subscription as never);
  render(<Onboarding />);
  await waitFor(() => expect(push).toHaveBeenCalledWith('/pricing'));
  fireEvent.click(screen.getByRole('button', { name: 'Upgrade to Pro' }));
  expect(push).toHaveBeenCalledWith('/pro');
});
it('redirects subscription failures to pricing', async () => {
  mocked.getSubscription.mockRejectedValue(new Error('Mock lookup failed'));
  render(<Onboarding />);
  await waitFor(() => expect(push).toHaveBeenCalledWith('/pricing'));
});
it('waits for auth and redirects signed-out visitors to the return path', () => {
  jest.mocked(useUser).mockReturnValue({ user: null, isLoading: true } as never);
  const { rerender } = render(<Onboarding />);
  expect(mocked.getSubscription).not.toHaveBeenCalled();
  expect(push).not.toHaveBeenCalled();
  jest.mocked(useUser).mockReturnValue({ user: null, isLoading: false } as never);
  rerender(<Onboarding />);
  expect(push).toHaveBeenCalledWith('/login?returnTo=/onboarding/pro');
});
