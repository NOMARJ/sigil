import { existsSync, readFileSync } from "fs";
import { resolve } from "path";

const SRC = resolve(__dirname, "..", "..");
const ROOT = resolve(SRC, "..");
const REPO = resolve(ROOT, "..");
const DOCKERFILE = resolve(REPO, "Dockerfile");
const NEXT_CONFIG = resolve(ROOT, "next.config.js");
const AUTH_PROVIDER = resolve(SRC, "lib", "auth.ts");
const AUTH_ME_ROUTE = resolve(SRC, "app", "api", "auth", "me", "route.ts");

// The free-tier OnboardingFlow (API-key setup and its 501-stub routes) was
// never reachable — only ProOnboardingFlow is routed — and once contained
// fabricated API-key generation. It was deleted rather than parked; these
// paths must stay gone until server-side key management actually exists.
const DELETED_ONBOARDING_PATHS = [
  resolve(SRC, "app", "api", "onboarding"),
  resolve(SRC, "components", "OnboardingFlow.tsx"),
  resolve(SRC, "components", "OnboardingStep.tsx"),
  resolve(SRC, "components", "ProgressIndicator.tsx"),
  resolve(SRC, "components", "onboarding"),
];

describe("auth and onboarding hardening", () => {
  it("fails production builds when the backend API URL is missing", () => {
    const configSource = readFileSync(NEXT_CONFIG, "utf8");
    const dockerfile = readFileSync(DOCKERFILE, "utf8");

    expect(configSource).toContain("NEXT_PUBLIC_API_URL is required");
    expect(configSource).not.toContain("http://localhost:8000");
    expect(dockerfile).toContain("NEXT_PUBLIC_API_URL build arg is required");
    expect(dockerfile).not.toContain("ARG NEXT_PUBLIC_API_URL=http://localhost");
    expect(dockerfile).not.toContain("substitute-env.sh");
    expect(dockerfile).toContain("/build/.next/standalone /app/dashboard");
    expect(dockerfile).toContain("/build/.next/static /app/dashboard/.next/static");
    expect(dockerfile).toContain("cd /app/dashboard && node server.js");
  });

  it("maps Auth0 users through backend-backed role and plan sources", () => {
    const providerSource = readFileSync(AUTH_PROVIDER, "utf8");
    const meRouteSource = readFileSync(AUTH_ME_ROUTE, "utf8");

    expect(providerSource).not.toContain('role: "owner"');
    expect(providerSource).not.toContain('plan: "pro"');
    expect(providerSource).toContain('fetch("/api/auth/me"');
    expect(providerSource).not.toContain('fetch("/auth/profile"');
    expect(providerSource).toContain("role: userData.role");
    expect(providerSource).toContain("plan: userData.plan");

    expect(meRouteSource).not.toContain('plan: "pro"');
    expect(meRouteSource).toContain('fetchJson<ApiUser>("/auth/me"');
    expect(meRouteSource).not.toContain('fetchJson<ApiUser>("/auth/me", token).catch');
    expect(meRouteSource).toContain('fetchJson<ApiSubscription>("/billing/subscription"');
    expect(meRouteSource).toContain("normalizeRole(apiUser.role)");
    expect(meRouteSource).toContain("normalizePlan(subscription.plan)");
  });

  it("keeps the dead API-key onboarding flow deleted instead of shipping fake credentials", () => {
    for (const path of DELETED_ONBOARDING_PATHS) {
      expect(existsSync(path)).toBe(false);
    }
  });
});
