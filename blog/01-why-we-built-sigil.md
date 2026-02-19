# Why We Built Sigil

*Published: 2026-02-19*
*Author: NOMARK*
*Tags: announcement, security, supply-chain*

---

Last year, one of our engineers installed an MCP server from a tutorial with 40 GitHub stars. It looked normal — a simple tool for querying databases. The `postinstall` script ran `node setup.js`, which read every environment variable on the machine and POST'd them to a Discord webhook. OpenAI keys, AWS credentials, database URLs — all gone in under a second.

The code wasn't obfuscated. It wasn't in a dependency six layers deep. It was right there in `setup.js`, 14 lines long. And no tool caught it, because no tool was looking.

## The gap no one is filling

The existing security tooling ecosystem is good at one thing: matching known CVEs against dependency trees. Snyk, Dependabot, and npm audit compare your `package-lock.json` against advisory databases. If a vulnerability has been reported and assigned a CVE number, they find it.

But the attacks hitting AI developers aren't CVEs. They are intentionally malicious packages — typosquats, hijacked maintainer accounts, and trojan tools published specifically to target developers who work with LLMs, agents, and MCP servers. These packages don't have CVEs because they were never legitimate. They were designed to steal your credentials from day one.

No existing tool answers the question: **"Is this code trying to hurt me?"**

## What Sigil does differently

We built Sigil around three principles:

**1. Quarantine first.** Nothing executes until it's been scanned and explicitly approved. When you run `sigil pip some-package`, the package is downloaded to an isolated directory, scanned, and held there. No `postinstall` hooks run. No `setup.py` cmdclass fires. You review the verdict, then approve or reject.

**2. Behavioral detection, not CVE matching.** Sigil's six scan phases look for the patterns that malicious code actually uses: install hooks that execute on install, `eval()` and `exec()` calls, outbound HTTP to webhook URLs, credential file access, obfuscated payloads, and provenance gaps. These are the building blocks of real attacks.

**3. Community threat intelligence.** When any user flags a malicious package, the detection signature propagates to every authenticated scanner within minutes. No source code is transmitted — only metadata about which patterns triggered.

## The AI agent problem

AI agents make this worse. An agent with `npm install` access will install whatever package it thinks is relevant. It cannot distinguish `langchain` from `langchian` (a typosquat). It cannot tell that an MCP server's `postinstall` script reads `~/.aws/credentials`. It trusts every package equally because it has no security tools.

Sigil gives agents security tools. Our MCP server exposes `sigil_scan`, `sigil_scan_package`, and `sigil_clone` as tools that agents can call before taking any action that introduces external code. The agent scans first, checks the verdict, and only proceeds if the code is clean.

This is why we built Sigil: because the tooling developers use every day — especially AI developers — has direct access to the most sensitive data on their machines, and nothing was checking whether that tooling was safe to run.

## Try it

```bash
curl -sSL https://sigilsec.ai/install.sh | sh
sigil scan .
```

The CLI is free and open source. All six scan phases run locally, offline, with no account required.

---

*Sigil is made by [NOMARK](https://nomark.ai). Star us on [GitHub](https://github.com/NOMARJ/sigil).*
