import { readFileSync } from "fs";
import { resolve } from "path";

const SRC = resolve(__dirname, "..", "..");
const UPGRADE_CTA = resolve(SRC, "components", "UpgradeCTA.tsx");
const INTERACTIVE_CHAT = resolve(SRC, "components", "InteractiveChat.tsx");

describe("upgrade and icon control hardening", () => {
  it("makes non-modal upgrade CTAs actionable", () => {
    const source = readFileSync(UPGRADE_CTA, "utf8");

    expect(source).toContain('href="/pricing"');
    expect(source).not.toContain('href="/upgrade"');
    expect(source).not.toContain('<button className="btn-primary">');
    expect(source).not.toContain('<button className="btn-primary text-sm">');
  });

  it("adds accessible names to icon-only controls", () => {
    const upgradeSource = readFileSync(UPGRADE_CTA, "utf8");
    const chatSource = readFileSync(INTERACTIVE_CHAT, "utf8");

    expect(upgradeSource).toContain('aria-label="Dismiss upgrade prompt"');
    expect(chatSource).toContain('aria-label="Send message"');
  });
});
