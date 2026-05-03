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
});
