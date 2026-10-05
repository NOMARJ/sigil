const path = require("node:path");
const { globSync: tinyGlobSync } = require("tinyglobby");

// Next ESLint calls this API with one rootDir pattern and onlyDirectories.
// Keep static directories unexpanded and preserve absolute rootDir paths.
function globSync(pattern, options = {}) {
  if (typeof pattern !== "string" || options.onlyDirectories !== true) {
    throw new TypeError("Sigil glob compatibility supports Next ESLint directory patterns only");
  }
  return tinyGlobSync(pattern, {
    ...options,
    expandDirectories: false,
    absolute: options.absolute ?? path.isAbsolute(pattern),
  }).map((entry) => entry.length > 1 ? entry.replace(/\/$/, "") : entry);
}

module.exports = { globSync };
