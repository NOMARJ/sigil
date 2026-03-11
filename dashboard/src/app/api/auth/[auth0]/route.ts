import { handleAuth, handleLogin, handleLogout } from '@auth0/nextjs-auth0';

export const dynamic = 'force-dynamic';

export const GET = handleAuth({
  login: handleLogin({
    authorizationParams: {
      audience: process.env.AUTH0_AUDIENCE,
      scope: 'openid profile email',
    },
  }),
  logout: handleLogout({
    returnTo: process.env.AUTH0_BASE_URL,
  }),
  onError(_req: Request, error: Error & { status?: number }) {
    // Return proper status code instead of always 500
    return new Response(JSON.stringify({ error: error.message }), {
      status: error.status ?? 401,
      headers: { 'Content-Type': 'application/json' },
    });
  },
});
