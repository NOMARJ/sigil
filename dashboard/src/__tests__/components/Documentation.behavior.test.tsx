import { act, fireEvent, render, screen } from '@testing-library/react';
import { usePathname } from 'next/navigation';
import ApiEndpoint from '@/components/docs/ApiEndpoint';
import CodeBlock from '@/components/docs/CodeBlock';
import TerminalDemo from '@/components/docs/TerminalDemo';
import DocsSidebar from '@/components/docs/DocsSidebar';
import ScanPhaseCard from '@/components/docs/ScanPhaseCard';
import CalloutBox from '@/components/docs/CalloutBox';
import ComparisonTable from '@/components/docs/ComparisonTable';

// [MOCK] Documentation examples and clipboard boundary; no network or credentials.
describe('interactive documentation', () => {
  const writeText = jest.fn().mockResolvedValue(undefined);
  beforeEach(() => {
    jest.useFakeTimers();
    writeText.mockClear();
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  });
  afterEach(() => { jest.clearAllTimers(); jest.useRealTimers(); });

  it('expands an endpoint, copies the displayed authenticated request, then collapses it', async () => {
    render(<ApiEndpoint method="POST" path="/v1/mock" description="[MOCK] Submit example" requestBody={'{"example":"MOCK"}'} responseBody={'{"status":"MOCK"}'}><p>Example details</p></ApiEndpoint>);
    expect(screen.queryByText('Example details')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /POST/ }));
    expect(screen.getByText('Request Body')).toBeInTheDocument();
    expect(screen.getByText('Response')).toBeInTheDocument();
    expect(screen.getByText('Example details')).toBeInTheDocument();
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Copy' })));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('https://api.sigilsec.ai/v1/mock'));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('-d \'{"example":"MOCK"}\''));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('Authorization: Bearer $TOKEN'));
    expect(screen.getByRole('button', { name: 'Copied!' })).toBeInTheDocument();
    act(() => jest.advanceTimersByTime(2000));
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /POST/ }));
    expect(screen.queryByText('Example details')).not.toBeInTheDocument();
  });

  it.each(['GET', 'PUT', 'PATCH', 'DELETE'] as const)('shows a %s endpoint without optional bodies or auth badge', (method) => {
    render(<ApiEndpoint method={method} path="/mock" description="[MOCK] Public example" authRequired={false} />);
    fireEvent.click(screen.getByRole('button', { name: `${method} /mock` }));
    expect(screen.getByText('[MOCK] Public example')).toBeInTheDocument();
    expect(screen.queryByText('Auth')).not.toBeInTheDocument();
    expect(screen.queryByText('Request Body')).not.toBeInTheDocument();
    expect(screen.queryByText('Response')).not.toBeInTheDocument();
  });

  it('shows numbered changes and copies the original code without line numbers', async () => {
    const code = '+added MOCK\n-removed MOCK\n unchanged MOCK';
    render(<CodeBlock code={code} filename="mock.diff" showLineNumbers diff />);
    expect(screen.getByText('mock.diff')).toBeInTheDocument();
    expect(screen.getByText('+added MOCK').parentElement).toHaveClass('bg-green-500/10');
    expect(screen.getByText('-removed MOCK').parentElement).toHaveClass('bg-red-500/10');
    expect(screen.getByText('3')).toBeInTheDocument();
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Copy' })));
    expect(writeText).toHaveBeenCalledWith(code);
    expect(screen.getByText('Copied!')).toBeInTheDocument();
    act(() => jest.advanceTimersByTime(2000));
    expect(screen.getByText('Copy')).toBeInTheDocument();
  });

  it('copies a headerless block and renders the default language header', async () => {
    const { rerender } = render(<CodeBlock code="MOCK" language="" />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Copy' })));
    expect(writeText).toHaveBeenCalledWith('MOCK');
    rerender(<CodeBlock code="plain MOCK" />);
    expect(screen.getByText('bash')).toBeInTheDocument();
    expect(screen.getByText('plain MOCK').parentElement).not.toHaveClass('bg-green-500/10');
  });

  it('plays timed lines, pauses, resumes and restarts the terminal example', () => {
    render(<TerminalDemo lines={[{ text: 'first MOCK', delay: 100 }, { text: 'second MOCK', color: 'green' }]} />);
    expect(screen.queryByText('first MOCK')).not.toBeInTheDocument();
    act(() => jest.advanceTimersByTime(100));
    expect(screen.getByText('first MOCK')).toBeInTheDocument();
    fireEvent.click(screen.getByTitle('Pause'));
    act(() => jest.advanceTimersByTime(1000));
    expect(screen.queryByText('second MOCK')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTitle('Play'));
    act(() => jest.advanceTimersByTime(50));
    expect(screen.getByText('second MOCK')).toHaveClass('text-green-400');
    fireEvent.click(screen.getByTitle('Play'));
    expect(screen.queryByText('first MOCK')).not.toBeInTheDocument();
    act(() => jest.advanceTimersByTime(100));
    fireEvent.click(screen.getByTitle('Restart'));
    expect(screen.queryByText('first MOCK')).not.toBeInTheDocument();
  });

  it('shows a static terminal example immediately and permits replay', () => {
    render(<TerminalDemo autoplay={false} title="[MOCK] Demo" speed={10} lines={[{ text: 'static MOCK', color: 'bold' }]} />);
    expect(screen.getByText('[MOCK] Demo')).toBeInTheDocument();
    expect(screen.getByText('static MOCK')).toHaveClass('font-bold');
    fireEvent.click(screen.getByTitle('Play'));
    expect(screen.queryByText('static MOCK')).not.toBeInTheDocument();
    act(() => jest.advanceTimersByTime(10));
    expect(screen.getByText('static MOCK')).toBeInTheDocument();
  });

  it('collapses navigation sections, highlights the current route and closes mobile navigation', () => {
    jest.mocked(usePathname).mockReturnValue('/docs/getting-started');
    const onClose = jest.fn();
    const { container, rerender } = render(<DocsSidebar isOpen onClose={onClose} />);
    expect(screen.getByRole('link', { name: 'Quick Start' })).toHaveClass('font-medium');
    fireEvent.click(screen.getByRole('button', { name: 'Getting Started' }));
    expect(screen.queryByRole('link', { name: 'Quick Start' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Getting Started' }));
    fireEvent.click(screen.getByRole('link', { name: 'Quick Start' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(container.querySelector('.fixed.inset-0')!);
    expect(onClose).toHaveBeenCalledTimes(2);
    jest.mocked(usePathname).mockReturnValue('/docs');
    rerender(<DocsSidebar />);
    expect(screen.getByRole('link', { name: 'Introduction' })).toHaveClass('font-medium');
    expect(screen.getByRole('link', { name: 'Quick Start' })).not.toHaveClass('font-medium');
  });

  it.each(['critical', 'high', 'medium', 'low'] as const)('expands and collapses %s phase detection rules', (severity) => {
    render(<ScanPhaseCard phase={1} name="[MOCK] Phase" weight="5x" severity={severity} description="[MOCK] Description" rules={[{ id: 'MOCK', pattern: 'MOCK_PATTERN', description: '[MOCK] Detect example' }]} />);
    expect(screen.queryByText('MOCK_PATTERN')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button'));
    expect(screen.getByText('Detection Rules (1)')).toBeInTheDocument();
    expect(screen.getByText('MOCK_PATTERN')).toBeInTheDocument();
    expect(screen.getByText('[MOCK] Detect example')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button'));
    expect(screen.queryByText('MOCK_PATTERN')).not.toBeInTheDocument();
  });

  it.each([['info', 'Note'], ['warning', 'Warning'], ['tip', 'Tip'], ['danger', 'Danger']] as const)('shows %s callout defaults and supplied titles', (variant, title) => {
    const { rerender } = render(<CalloutBox variant={variant}>[MOCK] Advice</CalloutBox>);
    expect(screen.getByText(title)).toBeInTheDocument();
    expect(screen.getByText('[MOCK] Advice')).toBeInTheDocument();
    rerender(<CalloutBox variant={variant} title="[MOCK] Custom">Other advice</CalloutBox>);
    expect(screen.getByText('[MOCK] Custom')).toBeInTheDocument();
    expect(screen.queryByText(title)).not.toBeInTheDocument();
  });

  it('compares supported, absent, partial and text capabilities with the highlighted tool', () => {
    const { container } = render(<ComparisonTable tools={['MOCK A', 'MOCK B']} highlightTool="MOCK A" features={[
      { name: '[MOCK] One', values: { 'MOCK A': 'yes', 'MOCK B': 'no' } },
      { name: '[MOCK] Two', values: { 'MOCK A': 'partial', 'MOCK B': 'Limited' } },
      { name: '[MOCK] Three', values: {} },
    ]} />);
    expect(screen.getByRole('columnheader', { name: 'MOCK A' })).toHaveClass('text-brand-400');
    expect(screen.getByText('Limited')).toBeInTheDocument();
    expect(container.querySelectorAll('tbody tr')).toHaveLength(3);
    expect(container.querySelectorAll('.bg-red-500\\/10')).toHaveLength(3);
    expect(container.querySelectorAll('.bg-green-500\\/10')).toHaveLength(1);
    expect(container.querySelectorAll('.bg-yellow-500\\/10')).toHaveLength(1);
  });
});
