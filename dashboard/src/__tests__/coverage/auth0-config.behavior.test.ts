/** @jest-environment node */
// [MOCK] Constructor is inert; all domains are reserved .invalid sentinels.
jest.mock('@auth0/nextjs-auth0/server', () => ({ Auth0Client: jest.fn() }));
const saved = { ...process.env };
afterEach(() => { process.env = { ...saved }; });
it.each([
  ['https://identity.invalid/', undefined, 'identity.invalid'],
  ['<placeholder>', 'http://fallback.invalid/', 'fallback.invalid'],
  [undefined, undefined, undefined],
])('normalizes domain configuration %p', (domain, issuer, expected) => {
  jest.resetModules();
  delete process.env.AUTH0_DOMAIN;
  delete process.env.AUTH0_ISSUER_BASE_URL;
  if (domain) process.env.AUTH0_DOMAIN = domain;
  if (issuer) process.env.AUTH0_ISSUER_BASE_URL = issuer;
  process.env.APP_BASE_URL = '<placeholder>';
  process.env.AUTH0_BASE_URL = 'https://dashboard.invalid';
  process.env.AUTH0_AUDIENCE = 'MOCK-UNUSABLE-AUDIENCE';
  const { Auth0Client } = require('@auth0/nextjs-auth0/server');
  require('@/lib/auth0');
  expect(Auth0Client).toHaveBeenCalledWith({ domain: expected, appBaseUrl: 'https://dashboard.invalid', authorizationParameters: { audience: 'MOCK-UNUSABLE-AUDIENCE', scope: 'openid profile email' } });
});
