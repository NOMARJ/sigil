import { readFileSync } from "fs";
import { resolve } from "path";

const SRC = resolve(__dirname, "..", "..");
const ROOT = resolve(SRC, "..");
const REPO = resolve(ROOT, "..");
const DOCKERFILE = resolve(REPO, "Dockerfile");
const NEXT_CONFIG = resolve(ROOT, "next.config.js");
const AUTH_PROVIDER = resolve(SRC, "lib", "auth.ts");
const AUTH_ME_ROUTE = resolve(SRC, "app", "api", "auth", "me", "route.ts");
const GENERATE_KEY_ROUTE = resolve(
  SRC,
  "app",
  "api",
  "onboarding",
  "generate-key",
  "route.ts",
);
const API_KEY_STEP = resolve(
  SRC,
  "components",
  "onboarding",
  "ApiKeySetupStep.tsx",
);
const COMPLETE_ROUTE = resolve(SRC, "app", "api", "onboarding", "complete", "route.ts");
const COMPLETE_STEP_ROUTE = resolve(
  SRC,
  "app",
  "api",
  "onboarding",
  "complete-step",
  "route.ts",
);
const ONBOARDING_FLOW = resolve(SRC, "components", "OnboardingFlow.tsx");

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
    expect(meRouteSource).toContain('fetchJson<ApiSubscription>("/billing/subscription"');
    expect(meRouteSource).toContain("normalizeRole(apiUser.role)");
    expect(meRouteSource).toContain("normalizePlan(subscription.plan)");
  });

  it("fails closed for dashboard API key issuance instead of returning fake credentials", () => {
    const routeSource = readFileSync(GENERATE_KEY_ROUTE, "utf8");
    const stepSource = readFileSync(API_KEY_STEP, "utf8");

    for (const source of [routeSource, stepSource]) {
      expect(source).not.toMatch(/Math\.random|mockApiKey|mockKey|Date\.now/);
    }

    expect(routeSource).toContain("{ status: 501 }");
    expect(routeSource).not.toContain("api_key:");
    expect(stepSource).toContain('fetch("/api/onboarding/generate-key"');
    expect(stepSource).toContain('authenticationMethod: apiKey ? "api_key" : "device_flow"');
    expect(stepSource).toContain("sigil login");
  });

  it("fails closed for onboarding persistence instead of reporting fake success", () => {
    const completeSource = readFileSync(COMPLETE_ROUTE, "utf8");
    const completeStepSource = readFileSync(COMPLETE_STEP_ROUTE, "utf8");
    const flowSource = readFileSync(ONBOARDING_FLOW, "utf8");

    expect(completeSource).toContain("{ status: 501 }");
    expect(completeStepSource).toContain("{ status: 501 }");
    expect(completeSource).not.toContain("success: true");
    expect(completeStepSource).not.toContain("success: true");
    expect(flowSource).toContain("if (!response.ok)");
    expect(flowSource).not.toContain("Still redirect on error");
  });
});
