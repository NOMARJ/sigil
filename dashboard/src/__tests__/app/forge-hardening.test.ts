import { readFileSync } from "fs";
import { resolve } from "path";

const SRC = resolve(__dirname, "..", "..");
const FORGE_TOOLS_PAGE = resolve(SRC, "app", "forge", "tools", "page.tsx");
const FORGE_SETTINGS_PAGE = resolve(SRC, "app", "forge", "settings", "page.tsx");

describe("forge hardening", () => {
  it("does not ship local mock tracked tool state", () => {
    const source = readFileSync(FORGE_TOOLS_PAGE, "utf8");

    expect(source).not.toContain("mockTools");
    expect(source).not.toContain("setTimeout");
    expect(source).not.toContain("Date.now()");
    expect(source).not.toContain("LangChain");
    expect(source).toContain("Tracked tool management is unavailable");
  });

  it("does not simulate saving forge settings locally", () => {
    const source = readFileSync(FORGE_SETTINGS_PAGE, "utf8");

    expect(source).not.toContain("mockInitialSettings");
    expect(source).not.toContain("setTimeout");
    expect(source).not.toContain("Saved!");
    expect(source).toContain("Forge settings are unavailable");
  });
});
