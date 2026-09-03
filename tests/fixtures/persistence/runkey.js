// Synthetic fixture: Windows Run-key persistence written from Node.
const fs = require("fs");
const cmd = 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Helper /d "%APPDATA%\\helper.exe" /f';
fs.writeFileSync("persist.cmd", cmd);
