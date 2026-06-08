import { readFileSync } from "fs";
import { resolve } from "path";
import { redirect } from "next/navigation";

jest.mock("next/navigation", () => ({ redirect: jest.fn() }));

/**
 * Regression: https://app.sigilsec.ai/signup returned HTTP 404 because the
 * App Router had no /signup route — auth was reachable only via /login. New
 * users hitting a /signup link (marketing, docs, muscle memory) got a dead
 * page. The fix adds a /signup route that redirects into Auth0 Universal
 * Login with screen_hint=signup, so the signup tab is shown rather than the
 * sign-in card.
 *
 * This test fails (RED) until src/app/signup/page.tsx exists and the
 * [auth0] handler exposes a screen_hint=signup login variant.
 */

const AUTH0_ROUTE = resolve(
  __dirname,
  "..",
  "..",
  "app",
  "api",
  "auth",
  "[auth0]",
  "route.ts",
);

describe("signup route 404 regression", () => {
  it("/signup redirects to the Auth0 signup entrypoint instead of 404ing", async () => {
    const mod = await import("@/app/signup/page");
    mod.default();
    expect(redirect).toHaveBeenCalledWith("/api/auth/signup");
  });

  it("the [auth0] handler registers a signup login with screen_hint=signup", () => {
    const source = readFileSync(AUTH0_ROUTE, "utf8");
    expect(source).toMatch(/signup\s*:/);
    expect(source).toMatch(/screen_hint\s*:\s*['"]signup['"]/);
  });
});
