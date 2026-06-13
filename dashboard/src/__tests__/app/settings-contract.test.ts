import { readFileSync } from "fs";
import { resolve } from "path";

const SRC = resolve(__dirname, "..", "..");
const API_CLIENT = resolve(SRC, "lib", "api.ts");
const SETTINGS_PAGE = resolve(SRC, "app", "settings", "page.tsx");

describe("settings API contracts", () => {
  it("saves aggregate scan-policy UI state through backend policy resources", () => {
    const source = readFileSync(API_CLIENT, "utf8");

    expect(source).toContain("request<PolicyRecord[]>(\"/settings/policy\")");
    expect(source).toContain("`/settings/policy/${current.id}`");
    expect(source).toContain('method: "PATCH"');
    expect(source).toContain('type: "allowlist"');
    expect(source).toContain('type: "blocklist"');
    expect(source).toContain('type: "auto_approve_threshold"');
    expect(source).toContain('type: "required_phases"');
    expect(source).not.toContain('request<Policy>("/settings/policy",');
  });

  it("creates and renders alert channels using backend channel_config fields", () => {
    const apiSource = readFileSync(API_CLIENT, "utf8");
    const pageSource = readFileSync(SETTINGS_PAGE, "utf8");

    expect(pageSource).toContain("channel_type: newChannelType");
    expect(pageSource).toContain("channel_config: buildChannelConfig");
    expect(pageSource).toContain("channel.channel_type");
    expect(pageSource).toContain("channel.channel_config");
    expect(pageSource).not.toMatch(/^\s*type:\s*newChannelType,/m);
    expect(pageSource).not.toMatch(/^\s*target:\s*newChannelTarget/m);
    expect(apiSource).toContain('"/settings/alerts/test"');
    expect(apiSource).not.toContain("`/settings/alerts/${id}/test`");
  });
});
