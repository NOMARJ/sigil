---
name: scan-package
description: "Scan a pip or npm package before installation using Sigil. Use when installing dependencies, adding new packages, or when package behavior seems suspicious. Auto-invoke before pip install or npm install commands. Trigger phrases (English): 'is this safe to install', 'check this package before installing', 'scan this skill', 'vet this MCP server', 'is this npm package safe', 'is this pip package safe'. Trigger phrases (Chinese): '安全扫描', '这个插件安全吗', '这个技能安全吗', '扫描一下', '安装前检查'."
allowed-tools: Bash(sigil *)
---

# Package Security Scan

Scan a package before installation:

1. Identify package type (pip or npm)
2. Run appropriate Sigil scan:
   - `sigil pip <package>` for Python packages
   - `sigil npm <package>` for Node packages

   Name a registry package (`requests==2.32.3`, `left-pad@1.3.0`). Sigil
   refuses paths, URLs and git specs, and a PyPI package with no prebuilt
   wheel fails to download, because fetching those would run the package's
   own code before the scan. Report that to the user; never add
   `--allow-build-scripts` yourself (the hook asks the user before it runs).
3. Review quarantine findings
4. Recommend approve/reject based on risk score

**Critical patterns to flag:**
- Install hooks (setup.py cmdclass, npm postinstall)
- Eval/exec/pickle usage
- Network exfiltration (webhooks, DNS tunneling)
- Credential access (ENV vars, SSH keys)
- Code obfuscation (base64, charCode)

Present findings and guide the user through quarantine approval.
