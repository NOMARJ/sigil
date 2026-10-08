import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Analytics from '@/app/analytics/page';
import Layout, { metadata } from '@/app/analytics/layout';
import * as api from '@/lib/api';
// [MOCK] Analytics fixtures are synthetic test data; all API calls are isolated.
jest.mock('@/lib/api');
const mocked = jest.mocked(api);
const usage = { scans_this_period: 90, tokens_used: 1234, cost_this_period: 9, threats_discovered: 2, zero_days_found: 1, plan_limits: { max_scans_per_month: 100, max_cost_per_month: 10 }, usage_by_day: [{ date: '2026-10-01', scans: 2, threats: 1, tokens: 100 }], top_threat_categories: [{ threat_type: 'credential_theft', count: 2, avg_confidence: .9 }, { threat_type: 'injection', count: 1, avg_confidence: .5 }] };
beforeEach(() => { jest.clearAllMocks(); mocked.getUserUsageStats.mockResolvedValue(usage); mocked.getUserChurnRisk.mockResolvedValue({ risk_category: 'HEALTHY', monthly_scans: 5, threat_hit_rate: .1, feature_adoption_score: .5 }); });
it('renders measured usage, threats and recommendations and refreshes the API', async () => {
  render(<Analytics />);
  expect(screen.getByText('Loading analytics...')).toBeInTheDocument();
  expect(await screen.findByText('Usage Analytics')).toBeInTheDocument();
  expect(screen.getByText('$9.00')).toBeInTheDocument();
  expect(screen.getAllByText('credential theft')).toHaveLength(2);
  expect(screen.getAllByText('90% confidence')).toHaveLength(2);
  expect(screen.getByText('Zero-Day Discoveries')).toBeInTheDocument();
  expect(screen.getByText(/Try scanning more diverse/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await waitFor(() => expect(mocked.getUserUsageStats).toHaveBeenCalledTimes(2));
  expect(mocked.getUserUsageStats).toHaveBeenLastCalledWith('30');
  await screen.findByText('Usage Analytics');
});
it.each(['LOW_ENGAGEMENT', 'ENGAGEMENT_METRICS', 'UNKNOWN'])('renders empty charts and %s engagement without low-usage tips', async (risk_category) => {
  mocked.getUserUsageStats.mockResolvedValue({ ...usage, scans_this_period: 0, cost_this_period: 0, threats_discovered: 0, zero_days_found: 0, plan_limits: { max_scans_per_month: 0, max_cost_per_month: 0 }, usage_by_day: [], top_threat_categories: [] });
  mocked.getUserChurnRisk.mockResolvedValue({ risk_category, monthly_scans: 20, threat_hit_rate: .8, feature_adoption_score: 1 });
  render(<Analytics />);
  expect(await screen.findByText('No usage data available')).toBeInTheDocument();
  expect(screen.getAllByText('No threats discovered yet')).toHaveLength(2);
  expect(screen.getByText(risk_category === 'ENGAGEMENT_METRICS' ? 'Active' : risk_category.toLowerCase())).toBeInTheDocument();
  expect(screen.queryByText(/Try scanning more diverse/)).not.toBeInTheDocument();
  expect(screen.queryByText('Zero-Day Discoveries')).not.toBeInTheDocument();
});
it.each([new Error('Mock analytics unavailable'), 'mock rejection'])('shows failure and retries successfully (%s)', async (error) => {
  const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
  mocked.getUserUsageStats.mockRejectedValueOnce(error);
  render(<Analytics />);
  expect(await screen.findByText(error instanceof Error ? error.message : 'Failed to load analytics')).toBeInTheDocument();
  expect(mocked.getUserChurnRisk).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Try Again' }));
  expect(await screen.findByText('Usage Analytics')).toBeInTheDocument();
  consoleError.mockRestore();
});
it('preserves page children and descriptive metadata', () => {
  render(<Layout><p>Analytics child</p></Layout>);
  expect(screen.getByText('Analytics child')).toBeInTheDocument();
  expect(metadata.title).toBe('Analytics | Sigil Pro');
});
