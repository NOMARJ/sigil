import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import LLMInsights from '@/components/LLMInsights';
import ThreatExplanation from '@/components/ThreatExplanation';
import FirstInvestigationGuide from '@/components/FirstInvestigationGuide';
import ToolTrackingCard from '@/components/ToolTrackingCard';
import type { LLMInsight, Finding, CreditInfo, ForgeTool } from '@/lib/types';
// [MOCK] Security analysis and tool metadata are local synthetic fixtures.
const insight: LLMInsight = { analysis_type: 'zero_day_detection', threat_category: 'code_injection', confidence: .95, confidence_level: 'very_high', title: 'Eval chain', description: 'Remote request execution', reasoning: 'Input reaches eval', evidence_snippets: ['eval(input)'], affected_files: ['index.js'], severity_adjustment: 2, false_positive_likelihood: .1, remediation_suggestions: ['Use a parser'], mitigation_steps: ['Disable endpoint'] };
const finding: Finding = { id: 'f', scan_id: 's', phase: 'code_patterns', severity: 'HIGH_RISK', title: 'Eval chain', description: 'execution', file_path: 'index.js', line_number: 1, pattern_matched: 'eval', weight: 3 };
const credit: CreditInfo = { balance: 10, monthly_limit: 10, used_this_month: 0, costs: { quick_investigation: 4, thorough_investigation: 8, exhaustive_investigation: 16, false_positive_check: 4, remediation: 8, chat_message: 2 } };
const tool: ForgeTool = { id: 't', name: 'Parser', description: 'Parses input', category: 'security', repository_url: 'https://example.test/repo', documentation_url: 'https://example.test/docs', version: '1.0', risk_score: 1, last_scan_id: 's', tracked_at: '2026-01-01', created_by: 'fixture' };
beforeEach(() => localStorage.clear());
it.each([2, -2, 0])('expands and collapses actual evidence, remediation and details for severity %s', adjustment => {
 render(<ThreatExplanation insight={{ ...insight, severity_adjustment: adjustment, affected_files: adjustment === 0 ? [] : insight.affected_files }} isZeroDay={adjustment > 0} />);
 expect(screen.queryByText('eval(input)')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Evidence (1)' })); expect(screen.getByText('eval(input)')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button', { name: 'Remediation (1)' })); expect(screen.getByText('Use a parser')).toBeInTheDocument(); expect(screen.getByText('Disable endpoint')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button', { name: 'Details' })); expect(screen.getByText('False Positive Likelihood:')).toBeInTheDocument();
 for (const name of ['Evidence (1)', 'Remediation (1)', 'Details']) fireEvent.click(screen.getByRole('button', { name })); expect(screen.queryByText('eval(input)')).not.toBeInTheDocument(); expect(screen.queryByText('Use a parser')).not.toBeInTheDocument();
});
it('filters titles and descriptions, categories and confidence, switches table/cards and shows coordinated context', () => {
 const other: LLMInsight = { ...insight, title: 'Token theft', description: 'Leaked secret', threat_category: 'credential_theft', analysis_type: 'contextual_correlation', confidence_level: 'low', severity_adjustment: -1 };
 render(<LLMInsights insights={[insight, other, { ...other, title: 'Neutral', severity_adjustment: 0 }]} contextAnalysis={{ attack_chain_detected: true, coordinated_threat: true, attack_chain_steps: ['Collect input', 'Execute'], correlation_insights: [], overall_intent: 'Compromise service', sophistication_level: 'advanced' }} />);
 expect(screen.getByText('Multi-file coordination')).toBeInTheDocument(); expect(screen.getByText('Collect input')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Table' })); expect(screen.getByRole('table')).toBeInTheDocument(); expect(screen.getByText('3 insights')).toBeInTheDocument();
 fireEvent.change(screen.getByPlaceholderText('Search insights...'), { target: { value: 'LEAKED' } }); expect(screen.queryByText('Eval chain')).not.toBeInTheDocument(); expect(screen.getByText('Token theft')).toBeInTheDocument();
 fireEvent.change(screen.getByPlaceholderText('Search insights...'), { target: { value: '' } }); fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: 'code_injection' } }); expect(screen.getByText('1 insights')).toBeInTheDocument();
 fireEvent.change(screen.getAllByRole('combobox')[1], { target: { value: 'low' } }); expect(screen.getByText('No insights match your filters.')).toBeInTheDocument();
 fireEvent.change(screen.getAllByRole('combobox')[1], { target: { value: 'all' } }); fireEvent.click(screen.getByRole('button', { name: 'Cards' })); expect(screen.getByText('Eval chain')).toBeInTheDocument();
 fireEvent.change(screen.getByPlaceholderText('Search insights...'), { target: { value: 'eval' } }); expect(screen.getByText('1 insights')).toBeInTheDocument();
});
it('renders empty insights without context or zero-day alerts', () => { render(<LLMInsights insights={[]} contextAnalysis={null} />); expect(screen.getByText('No insights match your filters.')).toBeInTheDocument(); expect(screen.queryByText(/zero-day$/)).not.toBeInTheDocument(); });
it('completes the guide, persists completion and hides it on future mounts', () => {
 const start = jest.fn(); const dismiss = jest.fn(); const props = { finding, creditInfo: credit, onStartInvestigation: start, onDismiss: dismiss }; const { unmount } = render(<FirstInvestigationGuide {...props} />);
 fireEvent.click(screen.getByRole('button', { name: 'Get Started' })); expect(screen.getByText('Investigate Security Findings')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Next' })); expect(screen.getByText('Verify False Positives Fast')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Next' })); expect(screen.getByText(/This will cost 4 credits/)).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Start Investigation' })); expect(start).toHaveBeenCalledTimes(1); expect(dismiss).not.toHaveBeenCalled(); expect(localStorage.getItem('sigil-first-investigation-guide')).toBe('true'); unmount(); const { container } = render(<FirstInvestigationGuide {...props} />); expect(container).toBeEmptyDOMElement();
});
it('skips early and blocks unaffordable start while allowing final skip', () => {
 const dismiss = jest.fn(); const start = jest.fn(); const props = { finding, creditInfo: { ...credit, balance: 0 }, onStartInvestigation: start, onDismiss: dismiss }; const { unmount } = render(<FirstInvestigationGuide {...props} />); fireEvent.click(screen.getByRole('button', { name: 'Skip' })); expect(dismiss).toHaveBeenCalledTimes(1); unmount(); localStorage.clear(); render(<FirstInvestigationGuide {...props} />); fireEvent.click(screen.getByRole('button', { name: 'Get Started' })); fireEvent.click(screen.getByRole('button', { name: 'Next' })); fireEvent.click(screen.getByRole('button', { name: 'Next' })); expect(screen.getByRole('button', { name: 'Start Investigation' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Skip Tutorial' })); expect(dismiss).toHaveBeenCalledTimes(2); expect(start).not.toHaveBeenCalled();
});
it.each([[undefined, 'Unknown'], [1, 'Low Risk'], [3, 'Medium Risk'], [5, 'High Risk']])('shows tool risk %s and tracks/untracks compact and full cards', (score, label) => {
 const track = jest.fn(); const untrack = jest.fn(); const fixture = { ...tool, risk_score: score }; const { rerender } = render(<ToolTrackingCard tool={fixture} tracked={false} onTrack={track} />);
 expect(screen.getByText(label)).toBeInTheDocument(); expect(screen.getByRole('link', { name: 'Repository →' })).toHaveAttribute('href', tool.repository_url); expect(screen.getByRole('link', { name: 'Docs →' })).toHaveAttribute('rel', 'noopener noreferrer'); fireEvent.click(screen.getByRole('button', { name: 'Track' })); expect(track).toHaveBeenCalledWith(fixture);
 rerender(<ToolTrackingCard tool={fixture} onUntrack={untrack} />); fireEvent.click(screen.getByTitle('Untrack tool')); expect(untrack).toHaveBeenCalledWith('t');
 rerender(<ToolTrackingCard tool={{ ...fixture, documentation_url: undefined, last_scan_id: undefined }} compact tracked={false} onTrack={track} />); fireEvent.click(screen.getByRole('button', { name: 'Track' })); rerender(<ToolTrackingCard tool={fixture} compact onUntrack={untrack} />); fireEvent.click(screen.getByRole('button', { name: 'Untrack' })); expect(untrack).toHaveBeenCalledTimes(2);
 rerender(<ToolTrackingCard tool={fixture} compact />); fireEvent.click(screen.getByRole('button', { name: 'Untrack' })); rerender(<ToolTrackingCard tool={fixture} tracked={false} />); fireEvent.click(screen.getByRole('button', { name: 'Track' }));
});
