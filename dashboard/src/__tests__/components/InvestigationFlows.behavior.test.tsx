import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import FindingInvestigator from '@/components/FindingInvestigator';
import FalsePositiveVerifier from '@/components/FalsePositiveVerifier';
import RemediationViewer from '@/components/RemediationViewer';
import InteractiveChat from '@/components/InteractiveChat';
import InteractiveFindingsPanel from '@/components/InteractiveFindingsPanel';
import { launchConfig, ProFeature } from '@/lib/launch-config';
import * as api from '@/lib/api';
import type { Finding, Scan, CreditInfo, InvestigationResult, FalsePositiveAnalysis, RemediationResult, ChatSession } from '@/lib/types';
jest.mock('@/lib/api');
const mocked = jest.mocked(api);
// [MOCK] Local findings, balances, and AI responses; no authentication or network.
const finding: Finding = { id: 'f1', scan_id: 's1', phase: 'code_patterns', severity: 'HIGH_RISK', title: 'Unsafe eval', description: 'input execution', file_path: 'index.js', line_number: 8, pattern_matched: 'eval', weight: 3 };
const scan: Scan = { id: 's1', target: 'fixture', target_type: 'directory', files_scanned: 1, findings_count: 1, risk_score: 4, verdict: 'HIGH_RISK', threat_hits: 1, metadata: {}, created_at: '2026-01-01' };
const credit: CreditInfo = { balance: 100, monthly_limit: 100, used_this_month: 0, costs: { quick_investigation: 4, thorough_investigation: 8, exhaustive_investigation: 16, false_positive_check: 4, remediation: 8, chat_message: 2 } };
const investigation: InvestigationResult = { finding_id: 'f1', depth: 'quick', confidence_score: 95, threat_assessment: 'Input reaches eval', evidence: ['Untrusted request'], code_flow_analysis: 'request -> eval', false_positive_likelihood: 10, credits_used: 4, model_used: 'fixture', created_at: '2026-01-01' };
const analysis: FalsePositiveAnalysis = { finding_id: 'f1', is_safe: true, confidence_percentage: 95, explanation: 'Validated input', context_analysis: 'Allowlist in use', defense_suggestions: ['Retain validation'], credits_used: 4, created_at: '2026-01-01' };
const remediation: RemediationResult = { finding_id: 'f1', fixes: [{ id: 'fix1', title: 'Parse safely', description: 'Use JSON', code: 'JSON.parse(input)', language: 'javascript', explanation: 'No execution' }, { id: 'fix2', title: 'Allowlist', description: 'Known values', code: 'allowlist[input]', language: 'unknown', explanation: 'Restricts input' }], unit_test: 'expect(parse()).toBeSafe()', credits_used: 8, created_at: '2026-01-01' };
const session: ChatSession = { id: 'chat1', scan_id: 's1', messages: [], created_at: '2026-01-01', updated_at: '2026-01-01' };
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (error: Error) => void; const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; }); return { promise, resolve, reject }; }
beforeEach(() => { jest.resetAllMocks(); jest.spyOn(console, 'error').mockImplementation(() => {}); HTMLElement.prototype.scrollIntoView = jest.fn(); });
afterEach(() => { jest.restoreAllMocks(); });
it.each([[95, 'Very High Threat', 10], [75, 'High Threat', 50], [55, 'Moderate Threat', 80], [25, 'Low Threat', 0]])('investigates and renders %s confidence', async (confidence, label, fp) => {
 const response = { ...investigation, confidence_score: confidence, false_positive_likelihood: fp, evidence: confidence === 25 ? [] : investigation.evidence };
 mocked.investigateFinding.mockResolvedValue(response); const done = jest.fn();
 render(<FindingInvestigator finding={finding} creditInfo={credit} onInvestigationComplete={done} />);
 fireEvent.click(screen.getByRole('radio', { name: /Thorough Investigation/ }));
 fireEvent.click(screen.getByRole('button', { name: /Start Investigation/ }));
 expect(await screen.findByText(label)).toBeInTheDocument(); expect(done).toHaveBeenCalledWith(response);
 expect(mocked.investigateFinding).toHaveBeenCalledWith({ scanId: 's1', findingId: 'f1', depth: 'thorough' });
 expect(screen.getByText(response.code_flow_analysis)).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button', { name: 'New Investigation' })); expect(screen.getByRole('radio', { name: /Thorough/ })).toBeChecked();
});
it('disables unaffordable investigations and recovers from a rejected request', async () => {
 const pending = deferred<InvestigationResult>(); mocked.investigateFinding.mockReturnValue(pending.promise);
 const props = { finding, creditInfo: credit, onInvestigationComplete: jest.fn() }; const { rerender } = render(<FindingInvestigator {...props} />);
 fireEvent.click(screen.getByRole('radio', { name: /Exhaustive/ })); fireEvent.click(screen.getByRole('button', { name: /Start Investigation/ }));
 expect(screen.getByRole('button', { name: 'Analyzing...' })).toBeDisabled(); await act(async () => pending.reject(new Error('offline')));
 expect(props.onInvestigationComplete).not.toHaveBeenCalled(); expect(screen.getByRole('button', { name: /Start Investigation/ })).toBeEnabled();
 rerender(<FindingInvestigator {...props} creditInfo={{ ...credit, balance: 0 }} />); expect(screen.getByRole('button', { name: /Start Investigation/ })).toBeDisabled(); expect(screen.getByRole('link', { name: 'Upgrade to Pro' })).toHaveAttribute('href', '/pricing');
});
it.each([[true, 95], [false, 75], [false, 55], [true, 25]])('verifies safe=%s at %s confidence', async (safe, confidence) => {
 const response = { ...analysis, is_safe: safe, confidence_percentage: confidence, defense_suggestions: safe ? analysis.defense_suggestions : [] };
 mocked.analyzeFalsePositive.mockResolvedValue(response); const done = jest.fn(); render(<FalsePositiveVerifier finding={finding} creditInfo={credit} onAnalysisComplete={done} />);
 fireEvent.click(screen.getByRole('button', { name: /Verify False Positive/ })); expect(await screen.findByText(safe ? 'Potentially Safe (May be False Positive)' : 'Genuine Security Risk')).toBeInTheDocument();
 expect(mocked.analyzeFalsePositive).toHaveBeenCalledWith({ scanId: 's1', findingId: 'f1' }); expect(done).toHaveBeenCalledWith(response);
 expect(screen.getByText('Allowlist in use')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'New Analysis' })); expect(screen.getByRole('button', { name: /Verify False Positive/ })).toBeEnabled();
});
it('shows verification loading, recovers on error, and blocks insufficient credit', async () => {
 const pending = deferred<FalsePositiveAnalysis>(); mocked.analyzeFalsePositive.mockReturnValue(pending.promise); const done = jest.fn(); const { rerender } = render(<FalsePositiveVerifier finding={finding} creditInfo={credit} onAnalysisComplete={done} />);
 fireEvent.click(screen.getByRole('button', { name: /Verify False/ })); expect(screen.getByRole('button', { name: /Analyzing Context/ })).toBeDisabled(); await act(async () => pending.reject(new Error('offline')));
 expect(done).not.toHaveBeenCalled(); expect(screen.getByRole('button', { name: /Verify False/ })).toBeEnabled(); rerender(<FalsePositiveVerifier finding={finding} creditInfo={{ ...credit, balance: 0 }} onAnalysisComplete={done} />); expect(screen.getByRole('button', { name: /Verify False/ })).toBeDisabled();
});
it('generates fixes, switches options, copies code and tests, and resets', async () => {
 const pending = deferred<RemediationResult>(); mocked.generateRemediation.mockReturnValue(pending.promise); const copy = jest.fn().mockResolvedValue(undefined); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: copy } }); const done = jest.fn();
 render(<RemediationViewer finding={finding} creditInfo={credit} onRemediationComplete={done} />); fireEvent.click(screen.getByRole('button', { name: /Generate Fix/ })); expect(screen.getByRole('button', { name: /Generating Fix/ })).toBeDisabled(); await act(async () => pending.resolve(remediation));
 expect(mocked.generateRemediation).toHaveBeenCalledWith({ scanId: 's1', findingId: 'f1' }); expect(done).toHaveBeenCalledWith(remediation);
 fireEvent.click(screen.getAllByRole('button', { name: 'Copy' })[0]); expect(await screen.findByText('Copied')).toBeInTheDocument(); expect(copy).toHaveBeenCalledWith('JSON.parse(input)');
 fireEvent.click(screen.getByRole('button', { name: 'Allowlist' })); expect(screen.getByText('allowlist[input]')).toBeInTheDocument();
 fireEvent.click(screen.getAllByRole('button', { name: 'Copy' })[1]); await waitFor(() => expect(copy).toHaveBeenCalledWith(remediation.unit_test));
 fireEvent.click(screen.getByRole('button', { name: 'Generate New Fix' })); expect(screen.getByRole('button', { name: /Generate Fix/ })).toBeEnabled();
});
it('handles generation and clipboard errors, single and empty fixes, and low balance', async () => {
 mocked.generateRemediation.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ ...remediation, fixes: [remediation.fixes[0]], unit_test: undefined }).mockResolvedValueOnce({ ...remediation, fixes: [], unit_test: undefined });
 Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: jest.fn().mockRejectedValue(new Error('denied')) } }); const done = jest.fn(); const { rerender } = render(<RemediationViewer finding={finding} creditInfo={credit} onRemediationComplete={done} />);
 fireEvent.click(screen.getByRole('button', { name: /Generate Fix/ })); await waitFor(() => expect(console.error).toHaveBeenCalledWith('Remediation generation error:', expect.any(Error)));
 fireEvent.click(screen.getByRole('button', { name: /Generate Fix/ })); await screen.findByText('1 Fix Generated'); fireEvent.click(screen.getByRole('button', { name: 'Copy' })); await waitFor(() => expect(console.error).toHaveBeenCalledWith('Copy failed:', expect.any(Error))); expect(screen.queryByText('Copied')).not.toBeInTheDocument();
 fireEvent.click(screen.getByRole('button', { name: 'Generate New Fix' })); fireEvent.click(screen.getByRole('button', { name: /Generate Fix/ })); await screen.findByText('0 Fixes Generated'); fireEvent.click(screen.getByRole('button', { name: 'Generate New Fix' })); rerender(<RemediationViewer finding={finding} creditInfo={{ ...credit, balance: 0 }} onRemediationComplete={done} />); expect(screen.getByRole('button', { name: /Generate Fix/ })).toBeDisabled();
});
it('opens chat, previews and cancels suggested cost, sends optimistically, formats responses', async () => {
 mocked.createInteractiveSession.mockResolvedValue(session); const pending = deferred<ChatSession>(); mocked.continueInteractiveSession.mockReturnValue(pending.promise); const done = jest.fn(); const toggle = jest.fn(); const props = { scan, creditInfo: credit, onChatSessionUpdate: done, onToggle: toggle }; const { rerender } = render(<InteractiveChat {...props} isOpen={false} />);
 fireEvent.click(screen.getByRole('button', { name: 'Ask AI about scan' })); expect(toggle).toHaveBeenCalled(); rerender(<InteractiveChat {...props} isOpen />); await waitFor(() => expect(done).toHaveBeenCalledWith(session)); expect(mocked.createInteractiveSession).toHaveBeenCalledWith('s1');
 fireEvent.click(screen.getByRole('button', { name: 'How serious is this security issue?' })); expect(screen.getByText('This will cost 2 credits')).toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Cancel' })); expect(screen.queryByText('This will cost 2 credits')).not.toBeInTheDocument();
 fireEvent.change(screen.getByRole('textbox'), { target: { value: ' Explain eval ' } }); fireEvent.keyPress(screen.getByRole('textbox'), { key: 'Enter', charCode: 13, shiftKey: true }); expect(mocked.continueInteractiveSession).not.toHaveBeenCalled(); fireEvent.keyPress(screen.getByRole('textbox'), { key: 'Enter', charCode: 13 }); expect(screen.getByText('Explain eval')).toBeInTheDocument(); expect(screen.getByText('Thinking...')).toBeInTheDocument();
 // Existing API accepts only session id; missing question transmission is reported separately.
 await act(async () => pending.resolve({ ...session, messages: [{ id: 'a', role: 'assistant', content: 'Before `eval` after\n```js\nsafe()\n```\nTail `input`', timestamp: '2026-01-01', credits_used: 2 }] })); expect(screen.getByText('safe()')).toBeInTheDocument(); expect(screen.getByText('input')).toBeInTheDocument(); expect(screen.queryByText('Thinking...')).not.toBeInTheDocument();
});
it('recovers chat sends and blocks empty or unaffordable input', async () => {
 mocked.createInteractiveSession.mockResolvedValue(session); mocked.continueInteractiveSession.mockRejectedValue(new Error('offline')); const props = { scan, creditInfo: credit, onChatSessionUpdate: jest.fn(), onToggle: jest.fn(), isOpen: true }; const { rerender } = render(<InteractiveChat {...props} />); await waitFor(() => expect(props.onChatSessionUpdate).toHaveBeenCalled());
 expect(screen.getAllByRole('button').at(-1)!).toBeDisabled(); fireEvent.change(screen.getByRole('textbox'), { target: { value: 'question' } }); fireEvent.click(screen.getAllByRole('button').at(-1)!); await waitFor(() => expect(screen.queryByText('Thinking...')).not.toBeInTheDocument()); expect(screen.queryByText('question')).not.toBeInTheDocument();
 rerender(<InteractiveChat {...props} creditInfo={{ ...credit, balance: 0 }} />); expect(screen.getByPlaceholderText('Insufficient credits')).toBeDisabled();
});
it('loads panel credit, selects and clears findings, switches real tabs and refreshes credit', async () => {
 jest.spyOn(launchConfig, 'isFeatureVisible').mockReturnValue(true); mocked.getInteractiveCreditInfo.mockResolvedValue(credit); mocked.investigateFinding.mockResolvedValue(investigation); mocked.analyzeFalsePositive.mockResolvedValue(analysis); mocked.generateRemediation.mockResolvedValue(remediation); const select = jest.fn(); const props = { scan, findings: [finding], onFindingSelect: select }; const { rerender } = render(<InteractiveFindingsPanel {...props} selectedFinding={null} />);
 expect(screen.getByText('Loading interactive features...')).toBeInTheDocument(); fireEvent.click(await screen.findByRole('button', { name: /Unsafe eval/ })); expect(select).toHaveBeenCalledWith(finding); rerender(<InteractiveFindingsPanel {...props} selectedFinding={finding} />);
 fireEvent.click(screen.getByRole('button', { name: /Start Investigation/ })); await screen.findByText('Very High Threat'); expect(mocked.getInteractiveCreditInfo).toHaveBeenCalledTimes(2);
 fireEvent.click(screen.getByRole('button', { name: 'Check False Positive' })); fireEvent.click(screen.getByRole('button', { name: /Verify False/ })); await screen.findByText('Validated input');
 fireEvent.click(screen.getByRole('button', { name: 'Get Fix' })); fireEvent.click(screen.getByRole('button', { name: /Generate Fix/ })); await screen.findByText('2 Fixes Generated'); expect(mocked.getInteractiveCreditInfo).toHaveBeenCalledTimes(4); fireEvent.click(screen.getAllByRole('button')[0]); expect(select).toHaveBeenCalledWith(null);
});
it('retains loading on credit failure and starts in the visible verification tab', async () => {
 mocked.getInteractiveCreditInfo.mockRejectedValueOnce(new Error('offline')); const props = { scan, findings: [finding], onFindingSelect: jest.fn(), selectedFinding: finding }; const { unmount } = render(<InteractiveFindingsPanel {...props} />); await waitFor(() => expect(console.error).toHaveBeenCalled()); expect(screen.getByText('Loading interactive features...')).toBeInTheDocument(); unmount();
 jest.spyOn(launchConfig, 'isFeatureVisible').mockImplementation(feature => feature === ProFeature.FALSE_POSITIVE_VERIFICATION); mocked.getInteractiveCreditInfo.mockResolvedValue(credit); render(<InteractiveFindingsPanel {...props} />); expect(await screen.findByRole('button', { name: /Verify False/ })).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Investigate' })).not.toBeInTheDocument();
});

it('logs failed session creation without adding messages or notifying completion', async () => {
 mocked.createInteractiveSession.mockRejectedValue(new Error('offline')); const done = jest.fn(); render(<InteractiveChat scan={scan} creditInfo={credit} isOpen onToggle={jest.fn()} onChatSessionUpdate={done} />);
 await waitFor(() => expect(console.error).toHaveBeenCalledWith('Session initialization error:', expect.any(Error))); expect(done).not.toHaveBeenCalled(); expect(screen.getByText('Ask questions about your scan results')).toBeInTheDocument();
 fireEvent.change(screen.getByRole('textbox'), { target: { value: 'question' } }); fireEvent.click(screen.getAllByRole('button').at(-1)!); expect(mocked.continueInteractiveSession).not.toHaveBeenCalled();
});
it('renders available chat on a selected finding, refreshes session balance, and closes', async () => {
 jest.spyOn(launchConfig, 'canUseInteractiveChat', 'get').mockReturnValue(true); mocked.getInteractiveCreditInfo.mockResolvedValue(credit); mocked.createInteractiveSession.mockResolvedValue(session);
 render(<InteractiveFindingsPanel scan={scan} findings={[finding]} selectedFinding={finding} onFindingSelect={jest.fn()} />); fireEvent.click(await screen.findByRole('button', { name: 'Ask AI about scan' })); await screen.findByText('Security Assistant'); await waitFor(() => expect(mocked.getInteractiveCreditInfo).toHaveBeenCalledTimes(2));
 const chatHeader = screen.getByText('Security Assistant').parentElement!.parentElement!; fireEvent.click(chatHeader.querySelector('button')!); expect(screen.getByRole('button', { name: 'Ask AI about scan' })).toBeInTheDocument();
});
it('clears clipboard success feedback after two seconds', async () => {
 jest.useFakeTimers(); mocked.generateRemediation.mockResolvedValue({ ...remediation, fixes: [remediation.fixes[0]], unit_test: undefined }); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: jest.fn().mockResolvedValue(undefined) } });
 try { render(<RemediationViewer finding={finding} creditInfo={credit} onRemediationComplete={jest.fn()} />); fireEvent.click(screen.getByRole('button', { name: /Generate Fix/ })); await act(async () => {}); fireEvent.click(screen.getByRole('button', { name: 'Copy' })); await act(async () => {}); expect(screen.getByText('Copied')).toBeInTheDocument(); act(() => jest.advanceTimersByTime(2000)); expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument(); } finally { jest.useRealTimers(); }
});
