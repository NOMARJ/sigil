import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useRouter } from 'next/navigation';
import * as api from '@/lib/api';
import { CreditUsageDashboard } from '@/components/CreditUsageDashboard';
import { CreditPurchase } from '@/components/CreditPurchase';
import { SubscriptionManager } from '@/components/SubscriptionManager';
import { ProOnboardingFlow } from '@/components/ProOnboardingFlow';

jest.mock('@/lib/api', () => ({ getCreditUsage: jest.fn(), purchaseCredits: jest.fn(), createPortalSession: jest.fn() }));
const usage = { current_balance: 150, monthly_allocation: 1000, used_this_month: 850, days_until_reset: 1, transactions: [
  { id: '[MOCK] debit', amount: -800, feature: '[MOCK] Investigation', timestamp: '2026-10-01T12:00:00Z', description: '[MOCK] analysis debit' },
  { id: '[MOCK] other', amount: -50, feature: '', timestamp: '2026-10-01T12:00:00Z', description: '[MOCK] other debit' },
  { id: '[MOCK] credit', amount: 100, feature: '[MOCK] Purchase', timestamp: '2026-10-01T12:00:00Z', description: '[MOCK] credit topup' },
] };
beforeEach(() => jest.clearAllMocks());

describe('credit usage', () => {
  it('loads the API balance, remaining allowance, debit breakdown and signed history', async () => {
    let resolve!: (value: typeof usage) => void;
    jest.mocked(api.getCreditUsage).mockImplementationOnce(() => new Promise(r => { resolve = r; }));
    const { container } = render(<CreditUsageDashboard subscription={{ plan: 'enterprise' }} />);
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
    await act(async () => resolve(usage));
    expect(api.getCreditUsage).toHaveBeenCalledWith();
    expect(screen.getByText('150')).toBeInTheDocument();
    expect(screen.getByText('enterprise plan limit')).toBeInTheDocument();
    expect(screen.getByText('85.0% of allocation')).toBeInTheDocument();
    expect(screen.getByText(/You've used 85.0%/)).toBeInTheDocument();
    expect(screen.getByText('day')).toBeInTheDocument();
    expect(screen.getByText('800 credits')).toBeInTheDocument();
    expect(screen.getByText('Other')).toBeInTheDocument();
    expect(screen.getByText('+100')).toBeInTheDocument();
    expect(screen.getByText('-800')).toBeInTheDocument();
  });
  it.each([0, 65, 120])('renders %s percent consumption with empty history and capped progress', async percent => {
    jest.mocked(api.getCreditUsage).mockResolvedValueOnce({ ...usage, used_this_month: percent * 10, days_until_reset: 3, transactions: [] });
    const { container } = render(<CreditUsageDashboard />);
    await screen.findByText('No credit transactions yet');
    expect(screen.getByText(`${percent.toFixed(1)}% of allocation`)).toBeInTheDocument();
    expect(screen.getByText('pro plan limit')).toBeInTheDocument();
    expect(screen.getByText('days')).toBeInTheDocument();
    expect(container.querySelector('.transition-all')).toHaveStyle({ width: `${Math.min(percent, 100)}%` });
    expect(screen.queryByText('Usage by Feature')).not.toBeInTheDocument();
  });
  it.each([new Error('[MOCK] unavailable'), '[MOCK] failure'])('shows an API failure and retries the shared client', async failure => {
    jest.mocked(api.getCreditUsage).mockRejectedValueOnce(failure).mockRejectedValueOnce(failure);
    render(<CreditUsageDashboard />);
    await screen.findByText('Unable to load credit usage');
    expect(screen.getByText(failure instanceof Error ? failure.message : 'Unknown error')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(api.getCreditUsage).toHaveBeenCalledTimes(2));
  });
  it('handles absent usage', async () => {
    jest.mocked(api.getCreditUsage).mockResolvedValueOnce(null as unknown as Awaited<ReturnType<typeof api.getCreditUsage>>);
    render(<CreditUsageDashboard />);
    await screen.findByText('No credit usage data available');
  });
});

describe('credit purchase', () => {
  it('stays hidden when closed', () => {
    const { container } = render(<CreditPurchase currentBalance={0} isOpen={false} onClose={jest.fn()} />);
    expect(container).toBeEmptyDOMElement();
    expect(api.purchaseCredits).not.toHaveBeenCalled();
  });
  it.each([[0, 1, 1100], [1, 2, 3500], [2, 3, 6000], [3, 4, 12500]])('purchases package %s and delivers bonus credits', async (index, id, credits) => {
    jest.mocked(api.purchaseCredits).mockResolvedValueOnce({} as Awaited<ReturnType<typeof api.purchaseCredits>>);
    const close = jest.fn(), complete = jest.fn();
    render(<CreditPurchase currentBalance={1234} isOpen onClose={close} onPurchaseComplete={complete} />);
    expect(screen.getByText('1,234')).toBeInTheDocument();
    expect(screen.getByText('$9.99')).toBeInTheDocument();
    expect(screen.getByText('Best Value')).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: 'Purchase' })[index]);
    expect(api.purchaseCredits).toHaveBeenCalledWith(id);
    await waitFor(() => expect(complete).toHaveBeenCalledWith(credits));
    expect(close).toHaveBeenCalledTimes(1);
  });
  it.each([new Error('[MOCK] declined'), '[MOCK] failure'])('locks purchases while pending and allows retry after failure', async failure => {
    let reject!: (reason: unknown) => void;
    jest.mocked(api.purchaseCredits).mockImplementationOnce(() => new Promise((_resolve, r) => { reject = r; }));
    const close = jest.fn();
    render(<CreditPurchase currentBalance={0} isOpen onClose={close} />);
    fireEvent.click(screen.getAllByRole('button', { name: 'Purchase' })[0]);
    expect(screen.getByRole('button', { name: 'Processing...' })).toBeDisabled();
    screen.getAllByRole('button', { name: 'Purchase' }).forEach(button => expect(button).toBeDisabled());
    await act(async () => reject(failure));
    expect(screen.getByText(failure instanceof Error ? failure.message : 'Failed to purchase credits')).toBeInTheDocument();
    expect(close).not.toHaveBeenCalled();
    expect(screen.getAllByRole('button', { name: 'Purchase' })[0]).toBeEnabled();
    fireEvent.click(screen.getAllByRole('button')[0]);
    expect(close).toHaveBeenCalledTimes(1);
  });
});

describe('subscription manager', () => {
  it.each([null, { plan: 'free', status: 'active', billing_interval: 'monthly' as const }])('routes unsubscribed users to plans', subscription => {
    render(<SubscriptionManager subscription={subscription} />);
    expect(screen.getByText('No active subscription')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View Plans' })).toHaveAttribute('href', '/pricing');
  });
  it.each(['active', 'trialing', 'past_due'])('renders %s annual subscriptions and cancellation dates', status => {
    render(<SubscriptionManager subscription={{ plan: 'pro', status, billing_interval: 'annual', price_amount: 290, cancel_at_period_end: true, current_period_start: '2026-10-01T12:00:00Z', current_period_end: '2027-10-01T12:00:00Z' }} />);
    expect(screen.getByText('$290/year')).toBeInTheDocument();
    expect(screen.getByText('annual billing')).toBeInTheDocument();
    expect(screen.getByText('October 1, 2027')).toBeInTheDocument();
    expect(screen.getByText(/Subscription will cancel on/)).toBeInTheDocument();
  });
  it.each([new Error('[MOCK] portal unavailable'), '[MOCK] failure'])('uses portal API, blocks duplicate requests and recovers after error', async failure => {
    let reject!: (reason: unknown) => void;
    jest.mocked(api.createPortalSession).mockImplementationOnce(() => new Promise((_resolve, r) => { reject = r; }));
    render(<SubscriptionManager subscription={{ plan: 'pro', status: 'active', billing_interval: 'monthly', price_amount: 29, cancel_at_period_end: true }} />);
    expect(screen.getByText('$29/month')).toBeInTheDocument();
    expect(screen.getByText(/the next billing date/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Open Stripe Portal' }));
    expect(api.createPortalSession).toHaveBeenCalledWith();
    screen.getAllByRole('button', { name: 'Opening...' }).forEach(button => expect(button).toBeDisabled());
    await act(async () => reject(failure));
    expect(screen.getByText(failure instanceof Error ? failure.message : 'Failed to open billing portal')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Manage in Stripe' })).toBeEnabled();
  });
});

describe('pro onboarding', () => {
  it('walks forward and backward, loads allocation and offers scan and skip destinations', async () => {
    const push = jest.fn();
    jest.mocked(useRouter).mockReturnValue({ push } as unknown as ReturnType<typeof useRouter>);
    jest.mocked(api.getCreditUsage).mockResolvedValueOnce(usage);
    render(<ProOnboardingFlow />);
    expect(screen.getByRole('button', { name: 'Back' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('credits available of 1,000 monthly');
    expect(screen.getByText('150')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByRole('heading', { name: 'Welcome to Sigil Pro!' })).toBeInTheDocument();
    for (let step = 0; step < 3; step++) fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('100% complete')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Start First Scan' })).toHaveAttribute('href', '/scans?new=true');
    fireEvent.click(screen.getByRole('button', { name: 'Skip for Now' }));
    expect(push).toHaveBeenCalledWith('/pro?onboarded=true');
  });
  it('uses fallback allocation after API failure', async () => {
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    jest.mocked(api.getCreditUsage).mockRejectedValueOnce(new Error('[MOCK] balance unavailable'));
    render(<ProOnboardingFlow />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('5,000');
    expect(error).toHaveBeenCalledWith('Failed to fetch credit balance:', expect.any(Error));
    error.mockRestore();
  });
});

// Hash destinations exercise the redirect boundary without leaving jsdom or using a live Stripe URL.
it('redirects credit purchases to the checkout URL returned by the API', async () => {
  jest.mocked(api.purchaseCredits).mockResolvedValueOnce({ checkout_url: '#MOCK-offline-checkout' } as Awaited<ReturnType<typeof api.purchaseCredits>>);
  const close = jest.fn(), complete = jest.fn();
  render(<CreditPurchase currentBalance={0} isOpen onClose={close} onPurchaseComplete={complete} />);
  fireEvent.click(screen.getAllByRole('button', { name: 'Purchase' })[0]);
  await waitFor(() => expect(window.location.hash).toBe('#MOCK-offline-checkout'));
  expect(close).not.toHaveBeenCalled();
  expect(complete).not.toHaveBeenCalled();
  window.history.replaceState(null, '', '/');
});
it('redirects subscribers to the portal URL returned by the API', async () => {
  jest.mocked(api.createPortalSession).mockResolvedValueOnce({ url: '#MOCK-offline-portal' } as Awaited<ReturnType<typeof api.createPortalSession>>);
  render(<SubscriptionManager subscription={{ plan: 'pro', status: 'active', billing_interval: 'monthly' }} />);
  fireEvent.click(screen.getByRole('button', { name: 'Manage in Stripe' }));
  await waitFor(() => expect(window.location.hash).toBe('#MOCK-offline-portal'));
  window.history.replaceState(null, '', '/');
});
it('limits recent credit history to twenty transactions', async () => {
  jest.mocked(api.getCreditUsage).mockResolvedValueOnce({ ...usage, transactions: Array.from({ length: 21 }, (_, index) => ({ ...usage.transactions[0], id: `[MOCK] ${index}`, description: `[MOCK] activity ${index}` })) });
  render(<CreditUsageDashboard />);
  await screen.findByText('[MOCK] activity 19');
  expect(screen.queryByText('[MOCK] activity 20')).not.toBeInTheDocument();
});
