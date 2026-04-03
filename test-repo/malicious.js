// This should STILL be caught as dangerous
const code = "console.log('evil')";
eval(code);  // Real eval call - dangerous!

const cmd = "rm -rf /";
require('child_process').exec(cmd);  // Real exec - dangerous!