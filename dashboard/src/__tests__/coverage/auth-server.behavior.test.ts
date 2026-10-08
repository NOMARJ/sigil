/** @jest-environment node */
// [MOCK] All identity and HTTP boundaries are inert; token is deliberately unusable.
import { auth0 } from '@/lib/auth0';
import { GET as me } from '@/app/api/auth/me/route';
import { GET as token } from '@/app/api/auth/token/route';
import { GET as legacy, dynamic } from '@/app/api/auth/[auth0]/route';
import { proxy, config } from '@/proxy';
import { NextRequest } from 'next/server';
jest.mock('@/lib/auth0', () => ({ auth0: { getSession: jest.fn(), getAccessToken: jest.fn(), middleware: jest.fn() } }));
const session = jest.mocked(auth0.getSession);
const access = jest.mocked(auth0.getAccessToken);
const http = jest.fn();
beforeEach(() => {
  jest.resetAllMocks();
  global.fetch = http;
  process.env.NEXT_PUBLIC_API_URL = 'https://api.invalid';
  session.mockResolvedValue({ user: { sub: 'MOCK-user', email: 'nobody@example.invalid', name: 'Mock User' } } as never);
  access.mockResolvedValue({ token: 'MOCK-UNUSABLE-NOT-A-TOKEN' } as never);
  http.mockImplementation((url: string) => Promise.resolve({ ok: true, json: async () => url.endsWith('/auth/me') ? { id: 'MOCK-backend', role: 'admin' } : { plan: 'team' } }));
});
it('maps backend identity and subscription using private uncached requests', async () => {
  const response = await me();
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(expect.objectContaining({ id: 'MOCK-backend', email: 'nobody@example.invalid', role: 'admin', plan: 'team', avatar_url: null, team_id: null }));
  expect(http).toHaveBeenCalledWith('https://api.invalid/auth/me', { headers: { Authorization: 'Bearer MOCK-UNUSABLE-NOT-A-TOKEN', Accept: 'application/json' }, cache: 'no-store' });
});
it('normalizes unsupported role and plan and uses session fallbacks', async () => {
  http.mockResolvedValue({ ok: true, json: async () => ({ role: 'root', plan: 'unlimited' }) });
  expect(await (await me()).json()).toEqual(expect.objectContaining({ id: 'MOCK-user', name: 'Mock User', role: 'member', plan: 'free' }));
});
it('tolerates subscription failure without losing the user', async () => {
  http.mockImplementation((url: string) => url.includes('billing') ? Promise.reject(new Error('MOCK timeout')) : Promise.resolve({ ok: true, json: async () => ({}) }));
  expect(await (await me()).json()).toEqual(expect.objectContaining({ id: 'MOCK-user', plan: 'free' }));
});
it.each([null, {}])('rejects missing session %p before fetching', async value => {
  session.mockResolvedValue(value as never);
  expect((await me()).status).toBe(401);
  expect(http).not.toHaveBeenCalled();
});
it('rejects empty access token and identity errors', async () => {
  access.mockResolvedValue({ token: '' } as never);
  expect((await me()).status).toBe(401);
  access.mockRejectedValue(new Error('MOCK unavailable'));
  expect((await token()).status).toBe(401);
});
it.each(['http', 'timeout', 'configuration'])('rejects backend %s failures', async failure => {
  if (failure === 'configuration') delete process.env.NEXT_PUBLIC_API_URL;
  else if (failure === 'timeout') http.mockRejectedValue(new Error('MOCK timeout'));
  else http.mockResolvedValue({ ok: false, status: 503 });
  expect((await me()).status).toBe(401);
});
it.each(['nobody@example.invalid', 42])('reports unverified email with sanitized email %p', async email => {
  session.mockResolvedValue({ user: { email_verified: false, email } } as never);
  http.mockResolvedValue({ ok: false, status: 403 });
  const response = await me();
  expect(response.status).toBe(403);
  expect(await response.json()).toEqual({ error: 'email_unverified', email: typeof email === 'string' ? email : null });
});
it('returns the SDK access token contract', async () => {
  expect(await (await token()).json()).toEqual({ accessToken: 'MOCK-UNUSABLE-NOT-A-TOKEN' });
});
it.each(['login', 'logout', 'callback', 'signup'])('redirects legacy %s preserving query on the same origin', async action => {
  const response = await legacy(new NextRequest(`https://dashboard.invalid/api/auth/${action}?returnTo=%2Fscans`), { params: Promise.resolve({ auth0: action }) });
  const location = new URL(response.headers.get('location')!);
  expect(location.origin).toBe('https://dashboard.invalid');
  expect(location.pathname).toBe(action === 'signup' ? '/auth/login' : `/auth/${action}`);
  expect(location.searchParams.get('returnTo')).toBe('/scans');
  expect(location.searchParams.get('screen_hint')).toBe(action === 'signup' ? 'signup' : null);
  expect(dynamic).toBe('force-dynamic');
});
it('rejects unknown legacy action', async () => {
  const response = await legacy(new NextRequest('https://dashboard.invalid/api/auth/unknown'), { params: Promise.resolve({ auth0: 'unknown' }) });
  expect(response.status).toBe(404);
  expect(await response.json()).toEqual({ error: 'Unknown auth route' });
});
it('delegates proxy requests and retains static asset exclusions', async () => {
  const request = new Request('https://dashboard.invalid/');
  const response = new Response('MOCK');
  jest.mocked(auth0.middleware).mockResolvedValue(response as never);
  expect(await proxy(request)).toBe(response);
  expect(auth0.middleware).toHaveBeenCalledWith(request);
  expect(config.matcher[0]).toContain('_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt');
});
