# Synthetic fixture: macOS LaunchAgent plist written into the user's Library.
import os
import plistlib

plist = {"Label": "com.helper.agent", "ProgramArguments": ["/tmp/helper"], "RunAtLoad": True}
with open(os.path.expanduser("~/Library/LaunchAgents/com.helper.agent.plist"), "wb") as f:
    plistlib.dump(plist, f)
