import { readFileSync } from "fs";
import { resolve } from "path";
import { redirect } from "next/navigation";

jest.mock("next/navigation", () => ({ redirect: jest.fn() }));

/**
 * Regression: https://app.sigilsec.ai/signup returned HTTP 404 because the
 * App Router had no /signup route — auth was reachable only via /login. New
 * users hitting a /signup link (marketing, docs, muscle memory) got a dead
 * page. The fix adds a /signup route that redirects into the Auth0 v4
 * Universal Login route with screen_hint=signup, so the signup tab is shown
 * rather than the sign-in card.
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
    expect(redirect).toHaveBeenCalledWith("/auth/login?screen_hint=signup");
  });

  it("the legacy /api/auth/signup shim redirects to the v4 signup entrypoint", () => {
    const source = readFileSync(AUTH0_ROUTE, "utf8");
    expect(source).toMatch(/action === ['"]signup['"]/);
    expect(source).toMatch(/pathname = ['"]\/auth\/login['"]/);
    expect(source).toMatch(/screen_hint['"], ['"]signup['"]/);
  });
});
