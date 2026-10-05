import type * as Api from '@/lib/api';

// [MOCK] Deterministic HTTP fixtures; no live credentials, billing or network calls.
const backend = 'https://api.example.invalid';
const fetchMock = jest.fn();
const originalFetch = global.fetch;
const originalUrl = process.env.NEXT_PUBLIC_API_URL;
let api: typeof Api;

function response(value: unknown, status = 200) {
  return { ok: status >= 200 && status < 300, status,
    json: jest.fn().mockResolvedValue(value),
    text: jest.fn().mockResolvedValue(typeof value === 'string' ? value : JSON.stringify(value)) };
}

beforeAll(() => {
  process.env.NEXT_PUBLIC_API_URL = backend;
  jest.isolateModules(() => { api = require('@/lib/api'); });
});
beforeEach(() => {
  global.fetch = fetchMock;
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (url: string) =>
    url === '/api/auth/token' ? response({ accessToken: 'mock-access-token' }) : response({ id: 'mock-result' }));
});
afterAll(() => {
  global.fetch = originalFetch;
  if (originalUrl === undefined) delete process.env.NEXT_PUBLIC_API_URL;
  else process.env.NEXT_PUBLIC_API_URL = originalUrl;
});

describe('HTTP authentication and failures', () => {
  it('uses the session token without caching it and returns backend JSON', async () => {
    await expect(api.getCurrentUser()).resolves.toEqual({ id: 'mock-result' });
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/auth/token', { credentials: 'include', cache: 'no-store' });
    expect(fetchMock).toHaveBeenNthCalledWith(2, `${backend}/auth/me`, {
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer mock-access-token' },
    });
  });
  it.each([
    [{ token: 'mock-legacy-token' }, 'Bearer mock-legacy-token'],
    [{ accessToken: 'mock-current', token: 'mock-legacy' }, 'Bearer mock-current'],
    [{}, undefined],
  ])('supports token response %j', async (tokens, authorization) => {
    fetchMock.mockResolvedValueOnce(response(tokens));
    await api.getCurrentUser();
    expect(fetchMock.mock.calls[1][1].headers.Authorization).toBe(authorization);
  });
  it.each(['denied', 'network', 'malformed'])('sends no bearer token when session lookup is %s', async (failure) => {
    if (failure === 'denied') fetchMock.mockResolvedValueOnce(response({}, 401));
    if (failure === 'network') fetchMock.mockRejectedValueOnce(new Error('offline'));
    if (failure === 'malformed') fetchMock.mockResolvedValueOnce({ ok: true, json: jest.fn().mockRejectedValue(new Error('invalid JSON')) });
    await api.getCurrentUser();
    expect(fetchMock.mock.calls[1][1].headers).not.toHaveProperty('Authorization');
  });
  it.each([
    [401, 'Authentication required. Please sign in again.'],
    [403, 'You do not have permission to perform this action.'],
    [404, 'The requested resource was not found.'],
    [422, 'Invalid request data. Please check your input.'],
    [429, 'Too many requests. Please wait a moment and try again.'],
    [500, 'An internal server error occurred. Please try again later.'],
    [503, 'Request failed (503): unavailable'],
  ])('reports an actionable fallback for HTTP %s', async (status, message) => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response('unavailable', status));
    await expect(api.getCurrentUser()).rejects.toThrow(message);
  });
  it.each([
    [{ detail: 'Insufficient credits' }, 'Insufficient credits'],
    [{ detail: [{ msg: 'Missing email' }, { msg: 'Invalid role' }] }, 'Missing email, Invalid role'],
    [{ detail: ['invalid'] }, 'invalid'],
    [{ detail: {} }, 'Invalid request data. Please check your input.'],
    [{}, 'Invalid request data. Please check your input.'],
  ])('interprets backend validation details %j', async (body, message) => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response(body, 422));
    await expect(api.inviteMember('mock@example.invalid', 'member')).rejects.toThrow(message);
  });
  it('does not parse a 204 body', async () => {
    const empty = response(undefined, 204);
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(empty);
    await expect(api.removeMember('mock-member')).resolves.toBeUndefined();
    expect(empty.json).not.toHaveBeenCalled();
  });
  it('propagates backend transport failure', async () => {
    fetchMock.mockResolvedValueOnce(response({})).mockRejectedValueOnce(new Error('connection refused'));
    await expect(api.getScan('mock-scan')).rejects.toThrow('connection refused');
  });
  it('allows logout to finish if the server rejects it', async () => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response('error', 500));
    await expect(api.logout()).resolves.toBeUndefined();
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/auth/logout`);
  });
  it('fails before a backend request when the API URL is missing', async () => {
    delete process.env.NEXT_PUBLIC_API_URL;
    let unconfigured: typeof Api;
    jest.isolateModules(() => { unconfigured = require('@/lib/api'); });
    process.env.NEXT_PUBLIC_API_URL = backend;
    await expect(unconfigured!.getCurrentUser()).rejects.toThrow('NEXT_PUBLIC_API_URL is not configured');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('backend route and payload contracts', () => {
  const cases: Array<[string, () => Promise<unknown>, string, string | undefined, unknown?]> = [
    ['statistics', () => api.getDashboardStats(), '/dashboard/stats', undefined],
    ['scan', () => api.getScan('mock-scan'), '/scans/mock-scan', undefined],
    ['findings', () => api.getScanFindings('mock-scan'), '/scans/mock-scan/findings', undefined],
    ['rescan', () => api.rescanScan('mock-scan'), '/api/rescan/mock-scan', 'POST'],
    ['submit scan', () => api.submitScan({ package_name: 'mock-package', source: 'npm' }), '/scans', 'POST', { package_name: 'mock-package', source: 'npm' }],
    ['approve', () => api.approveScan('mock-scan'), '/scans/mock-scan/approve', 'POST'],
    ['reject', () => api.rejectScan('mock-scan'), '/scans/mock-scan/reject', 'POST'],
    ['threat', () => api.getThreat('mock-threat'), '/threats/mock-threat', undefined],
    ['report', () => api.getThreatReport('mock-report'), '/threat-reports/mock-report', undefined],
    ['report status', () => api.updateThreatReportStatus('mock-report', 'reviewed', 'confirmed'), '/threat-reports/mock-report', 'PATCH', { status: 'reviewed', notes: 'confirmed' }],
    ['report default notes', () => api.updateThreatReportStatus('mock-report', 'reviewed'), '/threat-reports/mock-report', 'PATCH', { status: 'reviewed', notes: '' }],
    ['team', () => api.getTeam(), '/team', undefined],
    ['invite', () => api.inviteMember('mock@example.invalid', 'member'), '/team/invite', 'POST', { email: 'mock@example.invalid', role: 'member' }],
    ['remove', () => api.removeMember('mock-member'), '/team/members/mock-member', 'DELETE'],
    ['role', () => api.updateMemberRole('mock-member', 'reviewer'), '/team/members/mock-member/role', 'PATCH', { role: 'reviewer' }],
    ['delete policy', () => api.deletePolicy('mock-policy'), '/settings/policy/mock-policy', 'DELETE'],
    ['alerts', () => api.listAlerts(), '/settings/alerts', undefined],
    ['delete alert', () => api.deleteAlert('mock-alert'), '/settings/alerts/mock-alert', 'DELETE'],
    ['plans', () => api.getPlans(), '/billing/plans', undefined],
    ['monthly subscription', () => api.subscribe('pro'), '/billing/subscribe', 'POST', { plan: 'pro', interval: 'monthly' }],
    ['annual subscription', () => api.subscribe('team', 'annual'), '/billing/subscribe', 'POST', { plan: 'team', interval: 'annual' }],
    ['subscription', () => api.getSubscription(), '/billing/subscription', undefined],
    ['portal', () => api.createPortalSession(), '/billing/portal', 'POST'],
    ['investigate', () => api.investigateFinding({ scanId: 'mock-scan', findingId: 'mock-finding', depth: 'quick' }), '/v1/interactive/investigate', 'POST', { scan_id: 'mock-scan', finding_id: 'mock-finding', depth: 'quick' }],
    ['false positive', () => api.analyzeFalsePositive({ scanId: 'mock-scan', findingId: 'mock-finding' }), '/v1/interactive/false-positive', 'POST', { scan_id: 'mock-scan', finding_id: 'mock-finding' }],
    ['remediation', () => api.generateRemediation({ scanId: 'mock-scan', findingId: 'mock-finding' }), '/v1/interactive/remediate', 'POST', { scan_id: 'mock-scan', finding_id: 'mock-finding' }],
    ['shared session', () => api.getSharedInteractiveSession('mock-share'), '/v1/interactive/sessions/shared/mock-share', undefined],
    ['export session', () => api.exportInteractiveSession({ session_id: 'mock-session' }), '/v1/interactive/sessions/export', 'POST', { session_id: 'mock-session' }],
    ['usage', () => api.getUserUsageStats('30'), '/v1/analytics/my/usage?days=30', undefined],
    ['churn', () => api.getUserChurnRisk(), '/v1/analytics/my/churn-risk', undefined],
    ['purchase', () => api.purchaseCredits(2), '/v1/billing/purchase-credits', 'POST', { package_id: 2 }],
  ];
  it.each(cases.map(([name, invoke, path, method, body]) => ({ name, invoke, path, method, body })))('uses the backend contract for $name', async ({ invoke, path, method, body }) => {
    await invoke();
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}${path}`);
    expect(fetchMock.mock.calls[1][1].method).toBe(method);
    expect(fetchMock.mock.calls[1][1].body).toBe(body === undefined ? undefined : JSON.stringify(body));
  });
  it('encodes scan filters and preserves cancellation', async () => {
    const signal = new AbortController().signal;
    await api.listScans({ page: 2, per_page: 10, verdict: 'HIGH_RISK', source: 'npm', search: '@scope/a b', scope: 'own' }, { signal });
    const url = new URL(fetchMock.mock.calls[1][0]);
    expect(Object.fromEntries(url.searchParams)).toEqual({ page: '2', per_page: '10', verdict: 'HIGH_RISK', source: 'npm', search: '@scope/a b', scope: 'own' });
    expect(fetchMock.mock.calls[1][1].signal).toBe(signal);
  });
  it('propagates an aborted scan request', async () => {
    const controller = new AbortController();
    controller.abort();
    fetchMock.mockResolvedValueOnce(response({})).mockRejectedValueOnce(new DOMException('aborted', 'AbortError'));
    await expect(api.listScans(undefined, { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
  });
  it.each([undefined, {}])('omits an empty scan query %j', async (params) => {
    await api.listScans(params);
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/scans`);
  });
  it('encodes threat filters', async () => {
    await api.searchThreats({ page: 2, per_page: 5, severity: 'HIGH_RISK', search: 'a & b', source: 'npm' });
    expect(Object.fromEntries(new URL(fetchMock.mock.calls[1][0]).searchParams)).toEqual({ page: '2', per_page: '5', severity: 'HIGH_RISK', search: 'a & b', source: 'npm' });
  });
  it('omits an empty threat query', async () => {
    await api.searchThreats();
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/threats`);
  });
  it.each([undefined, { status: 'all' }])('omits non-filtering report status %j', async (params) => {
    await api.listThreatReports(params);
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/threat-reports`);
  });
  it('encodes report pagination and status', async () => {
    await api.listThreatReports({ status: 'pending', page: 3, per_page: 7 });
    expect(Object.fromEntries(new URL(fetchMock.mock.calls[1][0]).searchParams)).toEqual({ status: 'pending', page: '3', per_page: '7' });
  });
  it('encodes publisher and package identities', async () => {
    await api.getPublisher('@scope/a & b', 'npm');
    expect(Object.fromEntries(new URL(fetchMock.mock.calls[1][0]).searchParams)).toEqual({ name: '@scope/a & b', source: 'npm' });
    await api.verifyPackage('@scope/a & b', 'npm');
    expect(Object.fromEntries(new URL(fetchMock.mock.calls[3][0]).searchParams)).toEqual({ package_name: '@scope/a & b', source: 'npm' });
  });
  it('maps a threat report to backend evidence fields', async () => {
    await api.submitReport({ package_name: 'mock-package', source: 'npm', description: 'Observed behavior', threat_type: 'exfiltration', severity: 'HIGH_RISK', indicators: ['mock-indicator'], references: ['https://example.invalid/report'] } as Parameters<typeof api.submitReport>[0]);
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/report`);
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ package_name: 'mock-package', ecosystem: 'npm', reason: 'Observed behavior', evidence: 'Threat type: exfiltration\nSeverity: HIGH_RISK\nIndicator: mock-indicator\nReference: https://example.invalid/report' });
  });
});

describe('response normalization and multi-request operations', () => {
  it.each([[{ id: 'mock-signature' }], { signatures: [{ id: 'mock-signature' }] }, {}])('normalizes signature response %j', async (value) => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response(value));
    await expect(api.getSignatures()).resolves.toEqual('signatures' in value ? value.signatures : Array.isArray(value) ? value : []);
  });
  it('defaults absent policy types safely', async () => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response([]));
    await expect(api.listPolicies()).resolves.toEqual({ auto_approve_threshold: 'LOW_RISK', allowlisted_packages: [], blocklisted_packages: [], require_approval_for: [] });
  });
  const records = [
    { id: 'mock-threshold', type: 'auto_approve_threshold', config: { verdict: 'MEDIUM_RISK' } },
    { id: 'mock-allow', type: 'allowlist', config: { packages: ['allowed'] } },
    { id: 'mock-block', type: 'blocklist', config: { packages: ['blocked'] } },
    { id: 'mock-phases', type: 'required_phases', config: { verdicts: ['HIGH_RISK'] } },
  ];
  it('maps persisted policy records to dashboard fields', async () => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response(records));
    await expect(api.listPolicies()).resolves.toEqual({ auto_approve_threshold: 'MEDIUM_RISK', allowlisted_packages: ['allowed'], blocklisted_packages: ['blocked'], require_approval_for: ['HIGH_RISK'] });
  });
  it.each([false, true])('updates existing=%s policy records and reloads persisted values', async (existing) => {
    fetchMock.mockImplementation(async (url: string, options?: RequestInit) => {
      if (url === '/api/auth/token') return response({});
      if (options?.method) return response({});
      return response(existing ? records : []);
    });
    const desired = { auto_approve_threshold: 'MEDIUM_RISK' as const, allowlisted_packages: ['allowed'], blocklisted_packages: ['blocked'], require_approval_for: ['HIGH_RISK' as const] };
    await api.updatePolicy(desired);
    const writes = fetchMock.mock.calls.filter(([, options]) => options?.method);
    expect(writes).toHaveLength(4);
    expect(writes.map(([url]) => url)).toEqual(records.map(record => `${backend}/settings/policy${existing ? `/${record.id}` : ''}`));
    expect(writes.map(([, options]) => options.method)).toEqual(Array(4).fill(existing ? 'PATCH' : 'POST'));
    expect(writes.map(([, options]) => JSON.parse(options.body).config)).toEqual(records.map(record => record.config));
    expect(fetchMock.mock.calls.filter(([url, options]) => url === `${backend}/settings/policy` && !options.method)).toHaveLength(2);
  });
  it('creates missing policies with safe defaults', async () => {
    fetchMock.mockImplementation(async (url: string, options?: RequestInit) => response(url === '/api/auth/token' ? {} : options?.method ? {} : []));
    await api.createPolicy({});
    const writes = fetchMock.mock.calls.filter(([, options]) => options?.method);
    expect(writes.map(([, options]) => JSON.parse(options.body).config)).toEqual([{ verdict: 'LOW_RISK' }, { packages: [] }, { packages: [] }, { verdicts: [] }]);
    expect(writes.every(([, options]) => JSON.parse(options.body).enabled === true)).toBe(true);
  });
  it('stops policy reload when a write fails', async () => {
    fetchMock.mockImplementation(async (url: string, options?: RequestInit) => response(url === '/api/auth/token' ? {} : options?.method ? 'denied' : [], options?.method ? 403 : 200));
    await expect(api.updatePolicy({})).rejects.toThrow('permission');
    expect(fetchMock.mock.calls.filter(([url, options]) => url === `${backend}/settings/policy` && !options.method)).toHaveLength(1);
  });
  it('creates and updates alert configuration without dropping fields', async () => {
    const channel = { channel_type: 'email', channel_config: { email: 'mock@example.invalid' }, enabled: true } as Parameters<typeof api.createAlert>[0];
    await api.createAlert(channel);
    await api.updateAlert('mock-alert', { enabled: false });
    expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/settings/alerts`);
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual(channel);
    expect(fetchMock.mock.calls[3][0]).toBe(`${backend}/settings/alerts/mock-alert`);
    expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({ enabled: false });
  });
  it('tests the selected saved alert channel', async () => {
    const config = { email: 'mock@example.invalid' };
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response([{ id: 'other' }, { id: 'mock-alert', channel_type: 'email', channel_config: config }]));
    await api.testAlert('mock-alert');
    expect(fetchMock.mock.calls[3][0]).toBe(`${backend}/settings/alerts/test`);
    expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({ channel_type: 'email', channel_config: config });
  });
  it('refuses to test a missing channel', async () => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response([]));
    await expect(api.testAlert('missing')).rejects.toThrow('Alert channel not found');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
  it.each([null, undefined, 'invalid', '2020-01-01', '2026-10-07T12:00:00Z'])('computes credit reset days for %s', async (resetDate) => {
    const now = jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-05T00:00:00Z'));
    try {
      const usage = { current_balance: 42, monthly_allocation: 100, used_this_month: 58, reset_date: resetDate };
      fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response(usage));
      await expect(api.getCreditUsage()).resolves.toEqual({ ...usage, days_until_reset: resetDate === '2026-10-07T12:00:00Z' ? 3 : 0, transactions: [] });
    } finally { now.mockRestore(); }
  });
  it('maps credit totals and exposes the defined feature costs', async () => {
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response({ current_balance: 42, monthly_allocation: 100, used_this_month: 58 }));
    await expect(api.getInteractiveCreditInfo()).resolves.toEqual({ balance: 42, monthly_limit: 100, used_this_month: 58, costs: { quick_investigation: 4, thorough_investigation: 8, exhaustive_investigation: 16, false_positive_check: 4, remediation: 6, chat_message: 2 } });
  });
  it('maps created session timestamps and history', async () => {
    const session = { session_id: 'mock-session', scan_id: 'mock-scan', started_at: '2026-10-04T00:00:00Z', last_activity: '2026-10-05T00:00:00Z', conversation_history: [{ role: 'user', content: 'Explain' }] };
    fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response(session));
    await expect(api.createInteractiveSession('mock-scan')).resolves.toEqual({ id: 'mock-session', scan_id: 'mock-scan', created_at: session.started_at, updated_at: session.last_activity, messages: session.conversation_history });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ scan_id: 'mock-scan' });
  });
  it('supplies a deterministic creation time and empty history for sparse resumed sessions', async () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-10-05T00:00:00Z'));
    try {
      fetchMock.mockResolvedValueOnce(response({})).mockResolvedValueOnce(response({ session_id: 'mock-session', scan_id: 'mock-scan' }));
      await expect(api.continueInteractiveSession('mock-session')).resolves.toEqual({ id: 'mock-session', scan_id: 'mock-scan', created_at: '2026-10-05T00:00:00.000Z', updated_at: '2026-10-05T00:00:00.000Z', messages: [] });
      expect(fetchMock.mock.calls[1][0]).toBe(`${backend}/v1/interactive/sessions/mock-session/continue`);
    } finally { jest.useRealTimers(); }
  });
});
