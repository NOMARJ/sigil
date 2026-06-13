import { readFileSync } from "fs";
import { resolve } from "path";

const SRC = resolve(__dirname, "..", "..");
const INTERACTIVE_COMPONENTS = [
  resolve(SRC, "components", "FindingInvestigator.tsx"),
  resolve(SRC, "components", "FalsePositiveVerifier.tsx"),
  resolve(SRC, "components", "RemediationViewer.tsx"),
  resolve(SRC, "components", "InteractiveFindingsPanel.tsx"),
  resolve(SRC, "components", "InteractiveChat.tsx"),
  resolve(SRC, "pages", "session", "[id].tsx"),
  resolve(SRC, "pages", "security-timeline.tsx"),
  resolve(SRC, "app", "analytics", "page.tsx"),
];
const API_CLIENT = resolve(SRC, "lib", "api.ts");
const LAUNCH_CONFIG = resolve(SRC, "lib", "launch-config.ts");
const SESSION_PAGE = resolve(SRC, "pages", "session", "[id].tsx");

describe("interactive dashboard API routing", () => {
  it("does not call local /api/v1/interactive routes from components", () => {
    for (const path of INTERACTIVE_COMPONENTS) {
      const source = readFileSync(path, "utf8");
      expect(source).not.toMatch(/fetch\(\s*['"`]\/api\/v1\/interactive/);
    }
  });

  it("does not bypass Auth0 API token handling with localStorage auth tokens", () => {
    const analyticsSource = readFileSync(
      resolve(SRC, "app", "analytics", "page.tsx"),
      "utf8",
    );

    expect(analyticsSource).not.toContain("localStorage.getItem('auth_token')");
    expect(analyticsSource).toContain("api.getUserUsageStats");
    expect(analyticsSource).toContain("api.getUserChurnRisk");
  });

  it("sends scan_id through the shared Pro action helpers", () => {
    const source = readFileSync(API_CLIENT, "utf8");

    expect(source).toContain("scan_id: payload.scanId");
    expect(source).toContain('"/v1/interactive/investigate"');
    expect(source).toContain('"/v1/interactive/false-positive"');
    expect(source).toContain('"/v1/interactive/remediate"');
  });

  it("keeps interactive chat hidden until a message endpoint exists", () => {
    const source = readFileSync(LAUNCH_CONFIG, "utf8");

    expect(source).toMatch(/ProFeature\.INTERACTIVE_CHAT,[\s\S]*enabled: false/);
    expect(source).toMatch(/ProFeature\.INTERACTIVE_CHAT,[\s\S]*userVisible: false/);
  });

  it("does not render assistant chat messages with dangerouslySetInnerHTML", () => {
    const source = readFileSync(resolve(SRC, "components", "InteractiveChat.tsx"), "utf8");

    expect(source).not.toContain("dangerouslySetInnerHTML");
  });

  it("submits threat reports to the public report contract", () => {
    const source = readFileSync(API_CLIENT, "utf8");

    expect(source).toContain('request<ReportThreatResponse>("/report"');
    expect(source).not.toContain('"/threats/report"');
    expect(source).toContain("ecosystem: payload.source");
    expect(source).toContain("reason: payload.description");
  });

  it("routes credit purchases to the real FastAPI billing endpoint", () => {
    const source = readFileSync(API_CLIENT, "utf8");

    expect(source).toContain('"/v1/billing/purchase-credits"');
    expect(source).not.toContain('"/billing/purchase-credits"');
  });

  it("does not silently fall back to localhost for backend API calls", () => {
    const source = readFileSync(API_CLIENT, "utf8");

    expect(source).toContain("NEXT_PUBLIC_API_URL is not configured");
    expect(source).not.toContain("http://localhost:8000");
  });

  it("continues shared sessions back to the existing scan detail route", () => {
    const source = readFileSync(SESSION_PAGE, "utf8");

    expect(source).toContain("`/scans/${session.scan_id}#interactive`");
    expect(source).not.toContain("`/scan/${session.scan_id}#interactive`");
  });
});
