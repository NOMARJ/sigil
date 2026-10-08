import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import ScansPage from '@/app/scans/page';
import ScanDetailPage from '@/app/scans/[id]/page';
import ThreatsPage from '@/app/threats/page';
import * as api from '@/lib/api';
import { useAuth } from '@/lib/auth';
import type { Scan, Finding, ScanPhase } from '@/lib/types';

// [MOCK] External API/auth/router boundaries only. Fixtures are synthetic, unusable security data.
jest.mock('@/lib/api', () => ({ listScans: jest.fn(), getScan: jest.fn(), getScanFindings: jest.fn(), approveScan: jest.fn(), rejectScan: jest.fn(), rescanScan: jest.fn(), searchThreats: jest.fn(), listThreatReports: jest.fn(), getSignatures: jest.fn(), submitReport: jest.fn(), updateThreatReportStatus: jest.fn() }));
jest.mock('@/lib/auth', () => ({ useAuth: jest.fn() }));
jest.mock('next/navigation', () => ({ useParams: () => ({ id: 'mock-unusable-scan' }) }));
const mocked = api as jest.Mocked<typeof api>;
const mockScan = (extra: Partial<Scan> = {}) => ({ id: 'mock-unusable-scan', target: 'mock-unusable-package', target_type: 'npm', verdict: 'HIGH_RISK', risk_score: 30, findings_count: 0, threat_hits: 0, created_at: '2026-10-05T00:00:00Z', scanner_version: '2.0.0', ...extra } as Scan);
const phases: ScanPhase[] = ['install_hooks', 'code_patterns', 'network_exfil', 'credentials', 'obfuscation', 'provenance', 'prompt_injection', 'skill_security', 'inference_security', 'llm_analysis'];
const labels = ['Install Hooks', 'Code Patterns', 'Network / Exfiltration', 'Credentials', 'Obfuscation', 'Provenance', 'Prompt Injection', 'Skill Security', 'Inference Security', 'LLM Analysis'];
const empty = { items: [], total: 0, has_more: false };
beforeEach(() => {
  jest.resetAllMocks();
  (useAuth as jest.Mock).mockReturnValue({ user: { role: 'reviewer' } });
  mocked.listScans.mockResolvedValue(empty as never);
  mocked.getScan.mockResolvedValue(mockScan());
  mocked.getScanFindings.mockResolvedValue([]);
  mocked.searchThreats.mockResolvedValue(empty as never);
  mocked.listThreatReports.mockResolvedValue(empty as never);
  mocked.getSignatures.mockResolvedValue([]);
});

describe('scan history page', () => {
  it('shows loading, empty and failure states and retries with an abortable request', async () => {
    let resolve!: (value: unknown) => void;
    mocked.listScans.mockImplementationOnce(() => new Promise(r => { resolve = r; }) as never);
    render(<ScansPage />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(mocked.listScans).toHaveBeenCalledWith({ page: 1, per_page: 20, scope: 'all' }, { signal: expect.any(AbortSignal) });
    await act(async () => resolve(empty));
    expect(screen.getAllByText('No scans found')).toHaveLength(2);
    mocked.listScans.mockRejectedValueOnce(new Error('Mock unavailable'));
    fireEvent.click(screen.getByRole('button', { name: 'Public' }));
    expect(await screen.findByText('Mock unavailable')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(screen.queryByText('Mock unavailable')).not.toBeInTheDocument());
  });
  it('paginates and resets page for risk, scope and source filters', async () => {
    mocked.listScans.mockResolvedValue({ items: [mockScan()], total: 41 } as never);
    render(<ScansPage />);
    expect(await screen.findByRole('link', { name: 'mock-unusable-package' })).toHaveAttribute('href', '/scans/mock-unusable-scan');
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Showing 21–40 of 41 scans');
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    await screen.findByText('Showing 1–20 of 41 scans');
    for (const label of ['CRITICAL_RISK', 'HIGH_RISK', 'MEDIUM_RISK', 'LOW_RISK', 'ALL']) {
      fireEvent.click(screen.getByRole('button', { name: label }));
      await waitFor(() => expect(mocked.listScans).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, ...(label === 'ALL' ? {} : { verdict: label }) }), expect.any(Object)));
    }
    for (const [label, scope] of [['My Scans', 'own'], ['Public', 'public'], ['Community', 'community'], ['All', 'all']]) {
      fireEvent.click(screen.getByRole('button', { name: label }));
      await waitFor(() => expect(mocked.listScans).toHaveBeenLastCalledWith({ page: 1, per_page: 20, scope }, expect.any(Object)));
    }
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'skills' } });
    await waitFor(() => expect(mocked.listScans).toHaveBeenLastCalledWith({ page: 1, per_page: 20, scope: 'all', source: 'skills' }, expect.any(Object)));
  });
  it('aborts a hung request and displays a retryable timeout', async () => {
    jest.useFakeTimers();
    try {
      mocked.listScans.mockImplementation((_params, options) => new Promise((_resolve, reject) => options?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))));
      render(<ScansPage />);
      await act(async () => { jest.advanceTimersByTime(15000); });
      expect(screen.getByText(/Loading scan history timed out/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Retry' })).toBeEnabled();
    } finally { jest.useRealTimers(); }
  });
});

describe('scan detail page', () => {
  it('loads both resources, recovers from failure and shows a scan with no findings', async () => {
    mocked.getScan.mockRejectedValueOnce(new Error('Mock detail unavailable'));
    const { container } = render(<ScanDetailPage />);
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
    expect(await screen.findByText('Mock detail unavailable')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No findings detected')).toBeInTheDocument();
    expect(mocked.getScan).toHaveBeenCalledWith('mock-unusable-scan');
    expect(mocked.getScanFindings).toHaveBeenCalledWith('mock-unusable-scan');
    expect(screen.queryByText('Risk Breakdown')).not.toBeInTheDocument();
    expect(screen.getByText(/badge\/scan\/mock-unusable-scan/)).toBeInTheDocument();
  });
  it('renders every phase, aggregates weights, and presents threat hits and rescanned score', async () => {
    mocked.getScan.mockResolvedValue(mockScan({ threat_hits: 2, original_score: 60, rescanned_at: '2026-10-06T00:00:00Z' }));
    mocked.getScanFindings.mockResolvedValue([...phases.map((phase, i) => ({ id: `mock-${i}`, phase, severity: 'HIGH_RISK', title: `Mock unusable finding ${i}`, description: 'Synthetic only', file_path: 'mock.invalid', line_number: 1, weight: i + 1 } as Finding)), { id: 'mock-extra', phase: 'code_patterns', severity: 'CRITICAL_RISK', title: 'Mock extra', description: 'Synthetic only', weight: 20 } as Finding]);
    render(<ScanDetailPage />);
    await screen.findByText('Risk Breakdown');
    labels.forEach(label => expect(screen.getByRole('heading', { name: label })).toBeInTheDocument());
    const breakdown = screen.getByText('Risk Breakdown').closest('.card')!;
    expect(within(breakdown as HTMLElement).getByText('22')).toBeInTheDocument();
    expect(within(breakdown as HTMLElement).getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('2 known threats detected')).toBeInTheDocument();
    expect(screen.getByText('60')).toHaveClass('line-through');
    expect(screen.queryByRole('button', { name: 'Refresh' })).not.toBeInTheDocument();
  });
  it('approves with disabled pending actions and hides review buttons after approval', async () => {
    let resolve!: (scan: Scan) => void;
    mocked.approveScan.mockImplementation(() => new Promise(r => { resolve = r; }));
    render(<ScanDetailPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled();
    expect(mocked.approveScan).toHaveBeenCalledWith('mock-unusable-scan');
    await act(async () => resolve(mockScan({ metadata: { approved: true } })));
    expect(screen.getByText('Approved')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });
  it('shows rejection failures then applies a successful rejection', async () => {
    mocked.rejectScan.mockRejectedValueOnce(new Error('Mock rejection failure')).mockResolvedValueOnce(mockScan({ verdict: 'CRITICAL_RISK' }));
    render(<ScanDetailPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    expect(await screen.findByText('Mock rejection failure')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    expect(await screen.findByText('CRITICAL')).toBeInTheDocument();
    expect(mocked.rejectScan).toHaveBeenCalledWith('mock-unusable-scan');
  });
  it.each(['rescanned', 'already_v2'])('refreshes legacy scans after %s', async status => {
    mocked.getScan.mockResolvedValueOnce(mockScan({ scanner_version: '1.0.0' }));
    mocked.rescanScan.mockResolvedValue({ status } as never);
    render(<ScanDetailPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(mocked.getScan).toHaveBeenCalledTimes(2));
    expect(mocked.rescanScan).toHaveBeenCalledWith('mock-unusable-scan');
  });
  it('hides reviewer actions from members and displays rescan failures without refetching', async () => {
    (useAuth as jest.Mock).mockReturnValue({ user: { role: 'member' } });
    mocked.getScan.mockResolvedValue(mockScan({ scanner_version: '1.0.0' }));
    mocked.rescanScan.mockRejectedValue(new Error('Mock rescan failed'));
    render(<ScanDetailPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText('Mock rescan failed')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(mocked.getScan).toHaveBeenCalledTimes(1);
  });
});

describe('threat intelligence page', () => {
  it('retries threats, paginates and sends severity and trimmed search filters', async () => {
    mocked.searchThreats.mockRejectedValueOnce(new Error('Mock threats unavailable')).mockResolvedValue({ items: [{ id: 'mock-threat', package_name: 'mock-unusable-threat', source: 'npm', severity: 'HIGH_RISK', threat_type: 'Other', description: 'Synthetic only', indicators: ['mock-indicator'], reporter: 'mock-reviewer', reported_at: '2026-10-05' }], total: 30, has_more: true } as never);
    const { container } = render(<ThreatsPage />);
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
    await screen.findByText('Mock threats unavailable');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await screen.findByText('mock-unusable-threat');
    expect(screen.getByText('mock-indicator')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(mocked.searchThreats).toHaveBeenLastCalledWith({ page: 2, per_page: 20 }));
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    await waitFor(() => expect(mocked.searchThreats).toHaveBeenLastCalledWith({ page: 1, per_page: 20 }));
    fireEvent.click(screen.getByRole('button', { name: 'HIGH_RISK' }));
    fireEvent.change(screen.getByPlaceholderText(/Search threats/), { target: { value: ' mock-invalid ' } });
    await waitFor(() => expect(mocked.searchThreats).toHaveBeenLastCalledWith({ page: 1, per_page: 20, severity: 'HIGH_RISK', search: 'mock-invalid' }));
  });
  it('loads report pagination and reviewer transitions', async () => {
    const report = { id: 'mock-report', package_name: 'mock-unusable-report', package_version: '0.0.0-invalid', ecosystem: 'npm', reason: 'Synthetic only', evidence: 'mock evidence', review_notes: 'mock notes', status: 'received', created_at: '2026-10-05' };
    mocked.listThreatReports.mockResolvedValue({ items: [report], total: 30, has_more: true } as never);
    mocked.updateThreatReportStatus.mockResolvedValue(undefined as never);
    render(<ThreatsPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Reports' }));
    await screen.findByText(/mock-unusable-report/);
    fireEvent.click(screen.getByRole('button', { name: 'Review' }));
    await waitFor(() => expect(mocked.updateThreatReportStatus).toHaveBeenCalledWith('mock-report', 'under_review'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(mocked.listThreatReports).toHaveBeenLastCalledWith({ status: undefined, page: 2, per_page: 20 }));
    mocked.listThreatReports.mockResolvedValue({ items: [{ ...report, status: 'under_review' }], total: 1 } as never);
    fireEvent.click(screen.getByRole('button', { name: 'under review' }));
    await screen.findByRole('button', { name: 'Confirm' });
    expect(mocked.listThreatReports).toHaveBeenLastCalledWith({ status: 'under_review', page: 1, per_page: 20 });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(mocked.updateThreatReportStatus).toHaveBeenCalledWith('mock-report', 'confirmed'));
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(mocked.updateThreatReportStatus).toHaveBeenCalledWith('mock-report', 'rejected'));
  });
  it('renders empty threats and reports for members, then every signature phase', async () => {
    (useAuth as jest.Mock).mockReturnValue({ user: { role: 'member' } });
    mocked.getSignatures.mockResolvedValue(phases.map((phase, i) => ({ id: `mock-signature-${i}`, phase, severity: 'HIGH_RISK', description: 'Synthetic only', pattern: 'mock-unusable-pattern' })) as never);
    render(<ThreatsPage />);
    await screen.findByText('No threats match your filters.');
    fireEvent.click(screen.getByRole('button', { name: 'Reports' }));
    await screen.findByText('No reports match your filter.');
    expect(screen.queryByRole('button', { name: 'Review' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Signatures' }));
    await screen.findByRole('table');
    phases.forEach(phase => expect(screen.getByText(phase)).toBeInTheDocument());
  });
  it('renders empty signatures', async () => {
    render(<ThreatsPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Signatures' }));
    await screen.findByText('No signatures loaded.');
  });
  it('validates required fields, edits evidence lists and retries a valid report submission', async () => {
    mocked.submitReport.mockRejectedValueOnce(new Error('Mock submission failed')).mockResolvedValueOnce(undefined as never);
    const { container } = render(<ThreatsPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Report Threat' }));
    const form = container.querySelector('form')!;
    expect(form.checkValidity()).toBe(false);
    expect(mocked.submitReport).not.toHaveBeenCalled();
    fireEvent.change(screen.getByPlaceholderText('package-name'), { target: { value: 'mock-unusable-report' } });
    fireEvent.change(screen.getByPlaceholderText(/Describe the threat/), { target: { value: 'Synthetic threat description' } });
    const selects = within(form).getAllByRole('combobox');
    fireEvent.change(selects[0], { target: { value: 'pip' } });
    fireEvent.change(selects[1], { target: { value: 'Other' } });
    fireEvent.change(selects[2], { target: { value: 'LOW_RISK' } });
    const indicator = screen.getByPlaceholderText('e.g., eval() with network fetch');
    fireEvent.change(indicator, { target: { value: ' mock indicator ' } });
    fireEvent.keyDown(indicator, { key: 'Enter' });
    fireEvent.change(screen.getByPlaceholderText('https://...'), { target: { value: 'https://mock.invalid/evidence' } });
    fireEvent.click(within(form).getAllByRole('button', { name: 'Add' })[1]);
    fireEvent.click(within(form).getAllByRole('button', { name: 'x' })[0]);
    fireEvent.click(within(form).getByRole('button', { name: 'x' }));
    expect(screen.queryByText('mock indicator')).not.toBeInTheDocument();
    expect(screen.queryByText('https://mock.invalid/evidence')).not.toBeInTheDocument();
    expect(form.checkValidity()).toBe(true);
    fireEvent.submit(form);
    await screen.findByText('Mock submission failed');
    expect(mocked.submitReport).toHaveBeenCalledWith({ package_name: 'mock-unusable-report', source: 'pip', threat_type: 'Other', description: 'Synthetic threat description', severity: 'LOW_RISK', indicators: [], references: [] });
    fireEvent.submit(form);
    await screen.findByText('Threat reported successfully.');
    expect(screen.getByPlaceholderText('package-name')).toHaveValue('');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('Report a Threat')).not.toBeInTheDocument();
  });
});

it('auto-closes a successful report after two seconds and retains trimmed submitted evidence', async () => {
  jest.useFakeTimers();
  try {
    mocked.submitReport.mockResolvedValue(undefined as never);
    const { container } = render(<ThreatsPage />);
    await act(async () => { jest.advanceTimersByTime(0); });
    fireEvent.click(screen.getByRole('button', { name: 'Report Threat' }));
    fireEvent.change(screen.getByPlaceholderText('package-name'), { target: { value: 'mock-unusable-package' } });
    fireEvent.change(screen.getByPlaceholderText(/Describe the threat/), { target: { value: 'Synthetic only' } });
    const indicator = screen.getByPlaceholderText('e.g., eval() with network fetch');
    fireEvent.change(indicator, { target: { value: ' mock evidence ' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Add' })[0]);
    const reference = screen.getByPlaceholderText('https://...');
    fireEvent.change(reference, { target: { value: 'https://mock.invalid/reference' } });
    fireEvent.keyDown(reference, { key: 'Enter' });
    await act(async () => { fireEvent.submit(container.querySelector('form')!); });
    expect(mocked.submitReport).toHaveBeenCalledWith(expect.objectContaining({ indicators: ['mock evidence'], references: ['https://mock.invalid/reference'] }));
    expect(screen.getByText('Threat reported successfully.')).toBeInTheDocument();
    await act(async () => { jest.advanceTimersByTime(2000); });
    expect(screen.queryByText('Report a Threat')).not.toBeInTheDocument();
  } finally { jest.useRealTimers(); }
});

it('shows approval errors and restores enabled actions', async () => {
  mocked.approveScan.mockRejectedValue(new Error('Mock approval failed'));
  render(<ScanDetailPage />);
  fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
  await screen.findByText('Mock approval failed');
  expect(screen.getByRole('button', { name: 'Approve' })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Reject' })).toBeEnabled();
});
