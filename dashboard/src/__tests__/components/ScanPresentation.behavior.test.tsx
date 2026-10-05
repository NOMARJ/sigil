import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import ScanTable from '@/components/ScanTable';
import FindingsList from '@/components/FindingsList';
import VerdictBadge from '@/components/VerdictBadge';
import ScanBadge from '@/components/ScanBadge';
import ConfidenceBadge from '@/components/ConfidenceBadge';
import ConfidenceScore, { ConfidenceDistribution } from '@/components/ConfidenceScore';
import ScoreComparison from '@/components/ScoreComparison';
import { RiskFilterBar, RiskIndicator } from '@/components/ui/RiskFilterBar';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import type { Finding, Scan } from '@/lib/types';

// [MOCK] Explicit presentation fixtures; no measured scan/security results.
const scan = (overrides: Partial<Scan> = {}): Scan => ({
  id: 'mock-scan', target: 'mock-package', target_type: 'npm', verdict: 'HIGH_RISK',
  risk_score: 30, findings_count: 2, created_at: '2026-10-05T00:00:00Z',
  ...overrides,
} as Scan);
const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: 'mock-finding', phase: 'code_patterns', severity: 'HIGH_RISK',
  title: 'Mock dangerous pattern', description: 'Mock finding description',
  file_path: 'mock-source.ts', line_number: 12, pattern_matched: 'mock-pattern',
  confidence: 'HIGH', weight: 5, ...overrides,
} as Finding);

describe('scan table', () => {
  it('renders an empty state without a misleading table', () => {
    render(<ScanTable scans={[]} />);
    expect(screen.getByText('No scans found')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
  it.each([['pip', 'PyPI'], ['npm', 'npm'], ['git', 'Git'], ['directory', 'Local'], ['mock-custom', 'mock-custom']])('labels target type %s as %s and links to its scan', (type, label) => {
    render(<ScanTable scans={[scan({ target_type: type as Scan['target_type'] })]} />);
    expect(screen.getByRole('link', { name: 'mock-package' })).toHaveAttribute('href', '/scans/mock-scan');
    const row = screen.getAllByRole('row')[1];
    expect(within(row).getByText(label)).toBeInTheDocument();
    expect(within(row).getByText('HIGH')).toBeInTheDocument();
    expect(within(row).getByText('2')).toBeInTheDocument();
    expect(within(row).getByText(/Oct 5, 2026/)).toBeInTheDocument();
  });
  it('shows original and rescanned scores only when they differ', () => {
    const { rerender } = render(<ScanTable scans={[scan({ original_score: 60, scanner_version: '2.0.0', rescanned_at: '2026-10-05' })]} />);
    expect(screen.getByText('60')).toHaveClass('line-through');
    expect(screen.getByText('30')).toBeInTheDocument();
    expect(screen.getByText('Recently Updated')).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    rerender(<ScanTable scans={[scan({ original_score: 30 })]} />);
    expect(screen.getAllByText('30')).toHaveLength(1);
    expect(screen.getByText('30')).not.toHaveClass('line-through');
  });
});

describe('finding groups', () => {
  it('shows the no-findings message', () => {
    render(<FindingsList findings={[]} />);
    expect(screen.getByText('No findings detected')).toBeInTheDocument();
  });
  it('orders phases and groups multiple findings while showing location and evidence', () => {
    render(<FindingsList findings={[
      finding(),
      finding({ id: 'mock-install', phase: 'install_hooks', title: 'Mock install hook' }),
      finding({ id: 'mock-second', title: 'Mock second pattern', file_path: '', line_number: null, pattern_matched: '' }),
    ]} />);
    expect(screen.getAllByRole('heading').map(h => h.textContent)).toEqual(['Install Hooks', 'Code Patterns']);
    expect(screen.getByText('2 findings')).toBeInTheDocument();
    expect(screen.getByText('1 finding')).toBeInTheDocument();
    expect(screen.getAllByText('mock-source.ts:12')).toHaveLength(2);
    expect(screen.getAllByText('mock-pattern')).toHaveLength(2);
    expect(screen.getByText('Mock second pattern')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Credentials' })).not.toBeInTheDocument();
  });
  it('shows a file without inventing a line number or matched pattern', () => {
    render(<FindingsList findings={[finding({ line_number: null, pattern_matched: '' })]} />);
    expect(screen.getByText('mock-source.ts')).toBeInTheDocument();
    expect(screen.queryByText('mock-pattern')).not.toBeInTheDocument();
    expect(screen.queryByText('mock-source.ts:null')).not.toBeInTheDocument();
  });
});

describe('scanner and verdict badges', () => {
  it.each([
    [undefined, undefined, 'Legacy Scan'], ['1.0.0', undefined, 'Legacy Scan'],
    ['2.0.0', undefined, 'Enhanced Scanner'], ['3.1.0', undefined, 'v3.1.0'],
    ['1.0.0', '2026-10-05', 'Recently Updated'],
  ])('presents scanner %s rescan %s as %s', (version, rescannedAt, label) => {
    render(<ScanBadge scannerVersion={version} rescannedAt={rescannedAt} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
  it.each(['CLEAN', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_RISK', 'mock_unknown'])('shows verdict %s without altering an unknown verdict', verdict => {
    render(<VerdictBadge verdict={verdict} />);
    expect(screen.getByText(verdict.replace(/_RISK$/, ''))).toBeInTheDocument();
  });
  it.each([undefined, 'HIGH', 'MEDIUM', 'LOW'] as const)('shows confidence %s without claiming missing confidence', confidence => {
    render(<ConfidenceBadge confidence={confidence} />);
    expect(screen.getByText(confidence ?? '—')).toBeInTheDocument();
  });
});

describe('confidence presentation', () => {
  it.each(['low', 'medium', 'high', 'very_high'] as const)('rounds the percentage and labels %s', level => {
    const { container } = render(<ConfidenceScore confidence={0.856} confidenceLevel={level} />);
    expect(screen.getByText('86%')).toBeInTheDocument();
    expect(screen.getByText(level.replace('_', ' ').toUpperCase())).toBeInTheDocument();
    expect(container.querySelector('[style]')).toHaveStyle({ width: '86%' });
  });
  it('honors hidden labels and percentages', () => {
    render(<ConfidenceScore confidence={0.85} confidenceLevel="high" size="lg" showLabel={false} showPercentage={false} />);
    expect(screen.queryByText('85%')).not.toBeInTheDocument();
    expect(screen.queryByText('HIGH')).not.toBeInTheDocument();
  });
  it('renders only nonzero distribution segments and their counts', () => {
    render(<ConfidenceDistribution summary={{ very_high: 1, high: 3, medium: 0 }} total={4} />);
    expect(screen.getByTitle('very_high: 1 insights')).toHaveStyle({ width: '25%' });
    expect(screen.getByTitle('high: 3 insights')).toHaveStyle({ width: '75%' });
    expect(screen.getByText('very high: 1')).toBeInTheDocument();
    expect(screen.queryByTitle(/medium/)).not.toBeInTheDocument();
    expect(screen.queryByText(/low:/)).not.toBeInTheDocument();
  });
  it('renders no distribution segments for a zero total', () => {
    const { container } = render(<ConfidenceDistribution summary={{}} total={0} />);
    expect(container.querySelector('[title]')).toBeNull();
    expect(screen.getByText('Confidence Distribution')).toBeInTheDocument();
  });
});

describe('risk score comparison', () => {
  it.each([
    [100, 50, '(-50%)', 'text-green-400'],
    [50, 100, '(+100%)', 'text-red-400'],
    [0, 10, '(+0%)', 'text-red-400'],
  ])('compares %s to %s', (original, next, percentage, color) => {
    render(<ScoreComparison originalScore={original} newScore={next} />);
    expect(screen.getByText(String(original))).toHaveClass('line-through');
    expect(screen.getByText(String(next))).toHaveClass(color);
    expect(screen.getByText(percentage)).toHaveClass(color);
  });
  it('omits percentage for an unchanged score or when disabled', () => {
    const { rerender } = render(<ScoreComparison originalScore={10} newScore={10} />);
    expect(screen.getAllByText('10')).toHaveLength(2);
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    rerender(<ScoreComparison originalScore={10} newScore={5} showPercentage={false} size="sm" />);
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });
});

describe('risk filters', () => {
  it('shows counts and selects each filter through its callback', () => {
    const change = jest.fn();
    render(<RiskFilterBar counts={{ critical: 1, high: 2, medium: 3, low: 4 }} onFilterChange={change} />);
    expect(screen.getByRole('button', { name: 'ALL 10' })).toHaveClass('text-white');
    const labels = ['CRITICAL_RISK 1', 'HIGH_RISK 2', 'MEDIUM_RISK 3', 'LOW_RISK 4'];
    labels.forEach(label => {
      fireEvent.click(screen.getByRole('button', { name: label }));
      expect(screen.getByRole('button', { name: label })).toHaveClass('active');
    });
    fireEvent.click(screen.getByRole('button', { name: 'ALL 10' }));
    expect(change.mock.calls.map(([value]) => value)).toEqual(['critical', 'high', 'medium', 'low', 'all']);
  });
  it('works without counts or a callback', () => {
    render(<RiskFilterBar />);
    expect(screen.queryByText('0')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'HIGH_RISK' }));
    expect(screen.getByRole('button', { name: 'HIGH_RISK' })).toHaveClass('active');
    expect(screen.getByRole('button', { name: 'ALL' })).not.toHaveClass('text-white');
  });
  it.each(['critical', 'high', 'medium', 'low'] as const)('labels %s consistently', level => {
    render(<RiskIndicator level={level} />);
    expect(screen.getByText(level.toUpperCase())).toBeInTheDocument();
  });
});

describe('error recovery', () => {
  it('renders healthy children', () => {
    render(<ErrorBoundary><p>Healthy content</p></ErrorBoundary>);
    expect(screen.getByText('Healthy content')).toBeInTheDocument();
  });
  it('reports an error and can retry the recovered child', () => {
    const errorLog = jest.spyOn(console, 'error').mockImplementation(() => {});
    let broken = true;
    function Child() { if (broken) throw new Error('Mock render failure'); return <p>Recovered</p>; }
    try {
      render(<ErrorBoundary><Child /></ErrorBoundary>);
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Mock render failure')).toBeInTheDocument();
      expect(errorLog).toHaveBeenCalledWith('ErrorBoundary caught:', expect.any(Error), expect.any(Object));
      broken = false;
      fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
      expect(screen.getByText('Recovered')).toBeInTheDocument();
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
    } finally { errorLog.mockRestore(); }
  });
  it('uses a supplied fallback on render failure', () => {
    const errorLog = jest.spyOn(console, 'error').mockImplementation(() => {});
    function Broken(): React.ReactNode { throw new Error('Mock failure'); }
    try {
      render(<ErrorBoundary fallback={<p>Custom recovery</p>}><Broken /></ErrorBoundary>);
      expect(screen.getByText('Custom recovery')).toBeInTheDocument();
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
    } finally { errorLog.mockRestore(); }
  });
});
