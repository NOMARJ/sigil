import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import Team from '@/app/team/page';
import * as api from '@/lib/api';
// [MOCK] Synthetic identities and API mocks prevent real invitations or connections.
jest.mock('@/lib/api');
const mocked = jest.mocked(api);
const members = [{ id: 'mock-owner', name: 'Mock Owner', email: 'owner@example.invalid', role: 'owner', created_at: '2026-10-01', last_login: '2026-10-02' }, { id: 'mock-member', name: 'Mock Member', email: 'member@example.invalid', role: 'member', created_at: '2026-10-01' }];
beforeEach(() => { jest.clearAllMocks(); mocked.getTeam.mockResolvedValue({ members } as never); });
it('displays owner roles and updates editable member roles', async () => {
 mocked.updateMemberRole.mockResolvedValue({ role: 'reviewer' } as never); render(<Team />);
 const owner = (await screen.findByText('Mock Owner')).closest('.px-5') as HTMLElement;
 expect(within(owner).getByText('Owner')).toBeInTheDocument(); expect(within(owner).queryByRole('combobox')).not.toBeInTheDocument(); expect(within(owner).getByText(/Last active/)).toBeInTheDocument();
 const row = screen.getByText('Mock Member').closest('.px-5') as HTMLElement;
 fireEvent.change(within(row).getByRole('combobox'), { target: { value: 'reviewer' } });
 await waitFor(() => expect(within(row).getByRole('combobox')).toHaveValue('reviewer')); expect(mocked.updateMemberRole).toHaveBeenCalledWith('mock-member', 'reviewer');
});
it('validates required email then invites the selected role and clears the form', async () => {
 mocked.inviteMember.mockResolvedValue({} as never); render(<Team />); await screen.findByText('Mock Member');
 fireEvent.click(screen.getByRole('button', { name: 'Send Invite' })); expect(mocked.inviteMember).not.toHaveBeenCalled();
 fireEvent.change(screen.getByLabelText('Email address'), { target: { value: 'invite@example.invalid' } }); fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'admin' } }); fireEvent.click(screen.getByRole('button', { name: 'Send Invite' }));
 expect(await screen.findByText('Invitation sent to invite@example.invalid.')).toBeInTheDocument(); expect(mocked.inviteMember).toHaveBeenCalledWith('invite@example.invalid', 'admin'); expect(screen.getByLabelText('Email address')).toHaveValue('');
});
it('cancels removal and then removes only the confirmed member', async () => {
 const confirm = jest.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true); mocked.removeMember.mockResolvedValue(undefined); render(<Team />);
 const row = (await screen.findByText('Mock Member')).closest('.px-5') as HTMLElement;
 fireEvent.click(within(row).getByRole('button')); expect(mocked.removeMember).not.toHaveBeenCalled(); fireEvent.click(within(row).getByRole('button'));
 await waitFor(() => expect(screen.queryByText('Mock Member')).not.toBeInTheDocument()); expect(screen.getByText('Mock Owner')).toBeInTheDocument(); expect(mocked.removeMember).toHaveBeenCalledWith('mock-member'); confirm.mockRestore();
});
it.each([new Error('Mock unavailable'), 'mock rejection'])('retries load errors into an empty state (%s)', async (error) => {
 mocked.getTeam.mockRejectedValueOnce(error).mockResolvedValue({ members: [] } as never); render(<Team />);
 await screen.findByText(error instanceof Error ? error.message : 'Failed to load team data.'); fireEvent.click(screen.getByRole('button', { name: 'Retry' })); expect(await screen.findByText('No team members found.')).toBeInTheDocument();
});
it.each([new Error('Mock action unavailable'), 'mock rejection'])('reports invite and role failures and preserves members (%s)', async (error) => {
 mocked.inviteMember.mockRejectedValue(error); mocked.updateMemberRole.mockRejectedValue(error); render(<Team />); const row = (await screen.findByText('Mock Member')).closest('.px-5') as HTMLElement;
 fireEvent.change(screen.getByLabelText('Email address'), { target: { value: 'invite@example.invalid' } }); fireEvent.click(screen.getByRole('button', { name: 'Send Invite' })); await screen.findByText(error instanceof Error ? error.message : 'Failed to send invitation.');
 fireEvent.change(within(row).getByRole('combobox'), { target: { value: 'admin' } }); await waitFor(() => expect(mocked.updateMemberRole).toHaveBeenCalled()); await waitFor(() => expect(within(row).getByRole('combobox')).toBeEnabled()); expect(within(row).getByRole('combobox')).toHaveValue('member');
});
it.each([new Error('Mock remove unavailable'), 'mock rejection'])('preserves the member and reports failed removal (%s)', async (error) => {
 const confirm = jest.spyOn(window, 'confirm').mockReturnValue(true); mocked.removeMember.mockRejectedValue(error); render(<Team />); const row = (await screen.findByText('Mock Member')).closest('.px-5') as HTMLElement; fireEvent.click(within(row).getByRole('button')); expect(await screen.findByText(error instanceof Error ? error.message : 'Failed to remove member.')).toBeInTheDocument(); expect(screen.getByText('Mock Member')).toBeInTheDocument(); confirm.mockRestore();
});
