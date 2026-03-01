import { handleAuth, handleLogin, handleCallback, handleLogout } from '@auth0/nextjs-auth0';

export const dynamic = 'force-dynamic';

export const GET = handleAuth({
  login: handleLogin({
    authorizationParams: {
      audience: process.env.AUTH0_AUDIENCE,
      scope: 'openid profile email',
    },
  }),
  callback: handleCallback(),
  logout: handleLogout({
    returnTo: process.env.AUTH0_BASE_URL,
  }),
});
