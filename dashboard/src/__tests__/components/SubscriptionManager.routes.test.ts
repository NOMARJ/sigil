import { readFileSync } from "fs";
import { resolve } from "path";

/**
 * Regression: SubscriptionManager once called four /api/v1/billing/* paths
 * (portal, cancel, reactivate, invoices). Three of those endpoints don't
 * exist anywhere — not in api/routers/billing.py and not as Next.js API
 * routes — so they 404'd in production. The supported path is to delegate
 * to Stripe's hosted Customer Portal via the existing /v1/billing/portal
 * FastAPI route, called through lib/api.ts:createPortalSession.
 *
 * This test prevents the dead-route pattern from coming back.
 */

const SUBSCRIPTION_MANAGER = resolve(
  __dirname,
  "..",
  "..",
  "components",
  "SubscriptionManager.tsx",
);
const CREDIT_USAGE_DASHBOARD = resolve(
  __dirname,
  "..",
  "..",
  "components",
  "CreditUsageDashboard.tsx",
);
const PRO_ONBOARDING_FLOW = resolve(
  __dirname,
  "..",
  "..",
  "components",
  "ProOnboardingFlow.tsx",
);
const CREDIT_PURCHASE = resolve(
  __dirname,
  "..",
  "..",
  "components",
  "CreditPurchase.tsx",
);
const V2_NOTIFICATION_BANNER = resolve(
  __dirname,
  "..",
  "..",
  "components",
  "V2NotificationBanner.tsx",
);
const API_CLIENT = resolve(__dirname, "..", "..", "lib", "api.ts");
const APP_DIR = resolve(__dirname, "..", "..", "app");

describe("SubscriptionManager dead-route regression", () => {
  it("does not call any /api/v1/billing/* path (those routes 404 in production)", () => {
    const source = readFileSync(SUBSCRIPTION_MANAGER, "utf8");
    const matches = source.match(/\/api\/v1\/billing\/[a-z-]+/g) ?? [];
    expect(matches).toEqual([]);
  });

  it("uses lib/api.ts helpers instead of raw fetch for billing", () => {
    const source = readFileSync(SUBSCRIPTION_MANAGER, "utf8");
    const rawBillingFetches = source.match(
      /fetch\(\s*['"`]\/(?:api\/)?(?:v1\/)?billing\//g,
    ) ?? [];
    expect(rawBillingFetches).toEqual([]);
  });

  it("uses the checked-in Auth0 token route for API bearer tokens", () => {
    const source = readFileSync(API_CLIENT, "utf8");
    expect(source).toContain('fetch("/api/auth/token"');
    expect(source).not.toContain("/auth/access-token");
  });

  it("routes Pro credit widgets through the shared API client", () => {
    for (const path of [CREDIT_USAGE_DASHBOARD, PRO_ONBOARDING_FLOW, CREDIT_PURCHASE]) {
      const source = readFileSync(path, "utf8");
      expect(source).not.toMatch(/\/api\/v1\/billing\/credits\//);
    }
  });

  it("links scanner announcement docs to existing app routes", () => {
    const source = readFileSync(V2_NOTIFICATION_BANNER, "utf8");
    const docsLinks = Array.from(source.matchAll(/href="(\/docs\/[^"]+)"/g)).map(
      (match) => match[1],
    );

    expect(docsLinks).toEqual(["/docs/scanner-v2", "/docs/changelog"]);

    for (const href of docsLinks) {
      const route = href.replace(/^\//, "");
      expect(readFileSync(resolve(APP_DIR, route, "page.tsx"), "utf8")).toBeTruthy();
    }
  });
});
