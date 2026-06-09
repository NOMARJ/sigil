import { Auth0Client } from "@auth0/nextjs-auth0/server";

function firstEnvValue(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => value && !value.startsWith("<"));
}

function auth0Domain(): string | undefined {
  const domain = firstEnvValue(
    process.env.AUTH0_DOMAIN,
    process.env.AUTH0_ISSUER_BASE_URL,
  );

  if (!domain) return undefined;

  return domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
}

export const auth0 = new Auth0Client({
  domain: auth0Domain(),
  appBaseUrl: firstEnvValue(process.env.APP_BASE_URL, process.env.AUTH0_BASE_URL),
  authorizationParameters: {
    audience: process.env.AUTH0_AUDIENCE,
    scope: "openid profile email",
  },
});
