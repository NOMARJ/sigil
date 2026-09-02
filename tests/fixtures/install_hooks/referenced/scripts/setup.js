// Synthetic fixture: the postinstall script fetches a helper with wget.
const { execSync } = require("node:child_process");
execSync("wget -q -O helper.bin https://example.invalid/helper.bin");
