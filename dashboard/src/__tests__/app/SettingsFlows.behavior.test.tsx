import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Settings from '@/app/settings/page';
import * as api from '@/lib/api';
import { useAuth } from '@/lib/auth';
// [MOCK] External services and auth use isolated, unusable fixtures.
jest.mock('@/lib/api');
jest.mock('@/lib/auth', () => ({ useAuth: jest.fn() }));
jest.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams() }));
jest.mock('@/components/SubscriptionManager', () => ({ SubscriptionManager: ({ subscription }: { subscription: { plan: string } | null }) => <div>Mock subscription: {subscription?.plan ?? 'none'}</div> }));
const mocked = jest.mocked(api);
beforeEach(() => {
 jest.clearAllMocks(); jest.mocked(useAuth).mockReturnValue({ user: { plan: 'pro', id: 'mock-unusable' }, loading: false } as never);
 mocked.listPolicies.mockResolvedValue({ auto_approve_threshold: 'LOW_RISK', allowlisted_packages: ['mock-package'], blocklisted_packages: [], require_approval_for: ['CRITICAL_RISK'] } as never); mocked.listAlerts.mockResolvedValue([]); mocked.getSubscription.mockResolvedValue({ plan: 'free', status: 'active' } as never);
 mocked.getPlans.mockResolvedValue([{ tier: 'pro', name: 'Pro', price_monthly: 10, price_yearly: 96, features: ['Mock feature'] }, { tier: 'team', name: 'Team', price_monthly: 20, price_yearly: 192, features: ['Mock team feature'] }] as never);
});
it('saves trimmed lists, selected threshold and manual approval choices', async () => {
 mocked.updatePolicy.mockResolvedValue({} as never); render(<Settings />);
 fireEvent.change(await screen.findByLabelText('Allowlisted Packages'), { target: { value: ' alpha \n\n beta ' } }); fireEvent.change(screen.getByLabelText('Blocklisted Packages'), { target: { value: ' bad@1 \n ' } });
 fireEvent.click(screen.getAllByRole('button', { name: 'MEDIUM_RISK' })[0]); fireEvent.click(screen.getAllByRole('button', { name: 'CRITICAL_RISK' })[1]); fireEvent.click(screen.getAllByRole('button', { name: 'HIGH_RISK' })[1]); fireEvent.click(screen.getByRole('button', { name: 'Save Policies' }));
 expect(await screen.findByText('Policy settings saved successfully.')).toBeInTheDocument(); expect(mocked.updatePolicy).toHaveBeenCalledWith({ auto_approve_threshold: 'MEDIUM_RISK', allowlisted_packages: ['alpha', 'beta'], blocklisted_packages: ['bad@1'], require_approval_for: ['HIGH_RISK'] });
});
it('locks policy editing for free users', async () => {
 jest.mocked(useAuth).mockReturnValue({ user: null, loading: false } as never); mocked.listPolicies.mockResolvedValue({} as never); render(<Settings />);
 expect(await screen.findByLabelText('Allowlisted Packages')).toBeDisabled(); expect(screen.getByRole('button', { name: 'Save Policies' })).toBeDisabled(); expect(screen.getByRole('link', { name: 'Upgrade' })).toHaveAttribute('href', '/pricing');
});
it.each(['email', 'slack', 'webhook'])('creates %s alert configuration and clears its target', async (type) => {
 const target = type === 'email' ? ' one@example.invalid, , two@example.invalid ' : ' https://mock.example.invalid/alert ';
 const config = type === 'email' ? { recipients: ['one@example.invalid', 'two@example.invalid'], min_severity: 'CRITICAL_RISK' } : { webhook_url: target.trim(), min_severity: 'CRITICAL_RISK' };
 mocked.createAlert.mockResolvedValue({ id: 'mock-alert', channel_type: type, channel_config: config, enabled: true } as never); render(<Settings />); await screen.findByText('No alert channels configured yet.');
 fireEvent.change(screen.getByLabelText('Type'), { target: { value: type } }); fireEvent.change(screen.getByLabelText('Target'), { target: { value: target } }); fireEvent.change(screen.getByLabelText('Min Severity'), { target: { value: 'CRITICAL_RISK' } }); fireEvent.click(screen.getByRole('button', { name: 'Add' }));
 await waitFor(() => expect(screen.getByLabelText('Target')).toHaveValue('')); expect(mocked.createAlert).toHaveBeenCalledWith({ channel_type: type, channel_config: config, enabled: true }); expect(screen.getByText('Min severity: CRITICAL_RISK')).toBeInTheDocument();
});
it('rejects whitespace targets and reports creation failures', async () => {
 mocked.createAlert.mockRejectedValue('mock rejection'); render(<Settings />); await screen.findByText('No alert channels configured yet.'); fireEvent.change(screen.getByLabelText('Target'), { target: { value: '   ' } }); fireEvent.click(screen.getByRole('button', { name: 'Add' })); expect(mocked.createAlert).not.toHaveBeenCalled(); fireEvent.change(screen.getByLabelText('Target'), { target: { value: 'https://mock.example.invalid' } }); fireEvent.click(screen.getByRole('button', { name: 'Add' })); expect(await screen.findByText('Failed to add alert channel.')).toBeInTheDocument();
});
it('displays annual savings and subscribes with the selected interval', async () => {
 mocked.subscribe.mockResolvedValue({ plan: 'pro', status: 'active' } as never); render(<Settings />); await screen.findByText('Available Plans'); expect(screen.getByText('Save 20%')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: /Annual/ })); expect(screen.getByText('$96/yr — billed annually')).toBeInTheDocument(); fireEvent.click(screen.getAllByRole('button', { name: 'Subscribe' })[0]); expect(await screen.findByText('Mock subscription: pro')).toBeInTheDocument(); expect(mocked.subscribe).toHaveBeenCalledWith('pro', 'annual');
});
it.each([new Error('Mock unavailable'), 'mock rejection'])('reports policy load/save errors (%s)', async (error) => {
 const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {}); mocked.listPolicies.mockRejectedValue(error); mocked.listAlerts.mockRejectedValue(error); mocked.updatePolicy.mockRejectedValue(error); render(<Settings />); await screen.findByLabelText('Allowlisted Packages'); expect(screen.getByRole('alert')).toHaveTextContent(error instanceof Error ? error.message : 'Failed to load policy settings.'); fireEvent.click(screen.getByRole('button', { name: 'Save Policies' })); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(error instanceof Error ? error.message : 'Failed to save policy settings.')); consoleError.mockRestore();
});
it('toggles an existing alert and removes it only after API success', async () => {
 mocked.listAlerts.mockResolvedValue([{ id: 'mock-alert', channel_type: 'email', channel_config: { recipients: ['alert@example.invalid'] }, enabled: true }] as never);
 mocked.updateAlert.mockResolvedValue({ enabled: false } as never); mocked.deleteAlert.mockResolvedValue(undefined); render(<Settings />);
 const row = (await screen.findByText('alert@example.invalid')).closest('.justify-between') as HTMLElement;
 const buttons = row.querySelectorAll('button'); fireEvent.click(buttons[0]); await waitFor(() => expect(mocked.updateAlert).toHaveBeenCalledWith('mock-alert', { enabled: false }));
 await waitFor(() => expect(buttons[0]).toHaveClass('bg-gray-700')); fireEvent.click(buttons[1]); expect(await screen.findByText('No alert channels configured yet.')).toBeInTheDocument(); expect(mocked.deleteAlert).toHaveBeenCalledWith('mock-alert');
});
it.each([new Error('Mock action failed'), 'mock rejection'])('keeps channels on failed toggles/deletes and reports subscription failures (%s)', async (error) => {
 mocked.listAlerts.mockResolvedValue([{ id: 'mock-alert', channel_type: 'webhook', channel_config: { webhook_url: 'https://mock.example.invalid' }, enabled: false }] as never); mocked.updateAlert.mockRejectedValue(error); mocked.deleteAlert.mockRejectedValue(error); mocked.subscribe.mockRejectedValue(error); render(<Settings />);
 const row = (await screen.findByText('https://mock.example.invalid')).closest('.justify-between') as HTMLElement; const buttons = row.querySelectorAll('button'); fireEvent.click(buttons[0]); await screen.findByText(error instanceof Error ? error.message : 'Failed to toggle alert channel.'); fireEvent.click(buttons[1]); await screen.findByText(error instanceof Error ? error.message : 'Failed to remove alert channel.'); expect(screen.getByText('https://mock.example.invalid')).toBeInTheDocument(); fireEvent.click(screen.getAllByRole('button', { name: 'Subscribe' })[1]); await waitFor(() => expect(mocked.subscribe).toHaveBeenCalledWith('team', 'monthly'));
});
it('renders billing safely when both independent reads reject', async () => {
 const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {}); mocked.getPlans.mockRejectedValue(new Error('Mock plans unavailable')); mocked.getSubscription.mockRejectedValue(new Error('Mock subscription unavailable')); render(<Settings />); expect(await screen.findByText('Mock subscription: none')).toBeInTheDocument(); expect(screen.queryByText('Available Plans')).not.toBeInTheDocument(); consoleError.mockRestore();
});
