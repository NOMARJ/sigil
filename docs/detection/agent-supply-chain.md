# Agent supply chain rules (AGENTSC)

The `agent_supply_chain.json` pack (`cli/packs/core/v1/`, meta id
`sigil-core-agent-supply-chain`) covers the attack shapes of real malicious
AI-agent skills that Sigil's other packs did not block. Every rule was derived
by reading the samples Sigil missed, and every rule was checked against the
vendor skills it must leave alone before it was written into the pack.

```
Data Source: Real samples. Malicious: Datadog malicious-software-packages-dataset,
             ai-skills/malicious_intent bucket (204 samples).
             Clean: vendor skill catalogs from Anthropic (20), NVIDIA (382),
             OpenAI (44) and Vercel Labs (9) — 455 skill directories.
Sample Size: 204 malicious, 455 clean.
Limitations: Static analysis only. "Clean" means published by a reputable vendor,
             not audited. Several dataset entries are not malicious on inspection
             (listed below); they are counted as misses, not removed. The rules
             were written after reading the corpus they are measured on, so the
             recall figure is an in-sample number: it shows the shapes are
             covered, not how well the rules generalise to the next campaign.
```

## Result

Measured with `scripts/benchmark_skills.py --tools sigil` (blocked = verdict
HIGH or CRITICAL, warned = MEDIUM or above), same corpora, same commit apart
from this pack:

| | Malicious blocked | Malicious warned | Clean blocked | Clean warned |
|---|---:|---:|---:|---:|
| Before (dc82a94) | 142/204 (69.6%) | 149/204 (73.0%) | 108/455 (23.7%) | 226/455 (49.7%) |
| With AGENTSC | 184/204 (90.2%) | 188/204 (92.2%) | 108/455 (23.7%) | 226/455 (49.7%) |

42 malicious skills move to HIGH or CRITICAL. No clean skill changes verdict.
One clean skill gains a finding: NVIDIA `tao-setup` (already HIGH before this
pack) gets AGENTSC-030 at Medium for documenting a copy of its agent identity
into `~/.codex/AGENTS.md` — a true description of what that optional installer
does, see AGENTSC-030 below.

## Rules

Counts are samples (skill directories), from the benchmark run above.
"Newly blocked" = the sample was below HIGH before the pack and is HIGH or
CRITICAL with it; a sample can be counted under more than one rule.

| Rule | Sev. | Phase | Catches | Malicious hit | Newly blocked | Clean hit |
|---|---|---|---|---:|---:|---:|
| AGENTSC-001 | High | skill_security | "Download and install … from" a free-hosting or throwaway origin (`*.vercel.app`, `*.netlify.app`, `*.pages.dev`, `*.workers.dev`, abused TLDs such as `.forum`) | 39 | 24 | 0 |
| AGENTSC-002 | High | skill_security | Password-protected archive handed out as a prerequisite ("extract using pass: …") | 24 | 0 | 0 |
| AGENTSC-003 | High | skill_security | Installer on a personal file-share drive (Quark, Baidu, Lanzou, MEGA, MediaFire …) | 1 | 0 | 0 |
| AGENTSC-004 | Critical | code_patterns | Script or executable URL on an anonymous file-drop host (tmpfiles.org, catbox, transfer.sh, 0x0.st …) — a dropper | 1 | 1 | 0 |
| AGENTSC-005 | Medium | skill_security | Per-OS download of a required tool ("Download (Windows, MacOS) from", "requires X to be installed on Windows/MacOS") | 39 | 24 | 0 |
| AGENTSC-010 | High | credentials | Environment swept for secret-named variables (`env \| grep TOKEN\|SECRET\|PASSWORD`) | 1 | 1 | 0 |
| AGENTSC-011 | Medium | code_patterns | Project tarball that excludes `.git`/`node_modules` but not `.env` | 4 | 4 | 0 |
| AGENTSC-012 | High | network_exfil | `curl` form-upload of a file from `/etc`, `~`, `$HOME` … | 1 | 1 | 0 |
| AGENTSC-013 | High | skill_security | Skill whose job is extracting refresh tokens or session cookies | 2 | 2 | 0 |
| AGENTSC-014 | Critical | credentials | Saved browser session (storage state / cookies.txt) with live cookie values shipped in the package | 1 | 1 | 0 |
| AGENTSC-020 | High | network_exfil | Endpoint on a tunnel or IP-wildcard DNS host (bore.pub, sslip.io, nip.io, trycloudflare …) | 6 | 2 | 0 |
| AGENTSC-030 | Medium | prompt_injection | Skill targets the global agent instruction file (`~/.claude/CLAUDE.md`, `~/.gemini/GEMINI.md`, `~/.codex/AGENTS.md`, `~/.cursor/rules`) | 3 | 1 | 1 (tao-setup, already HIGH) |
| AGENTSC-031 | Medium | prompt_injection | Tool shadowing: "MUST replace WebFetch and WebSearch", "replaces all built-in … tools" | 2 | 2 | 0 |
| AGENTSC-032 | High | prompt_injection | Silent default to a hard-coded third-party account ("AUTOMATICALLY use `x@126.com` as the default sender") | 1 | 1 | 0 |
| AGENTSC-040 | High | skill_security | AppleScript `execute javascript` in the user's logged-in browser (session riding) | 2 | 1 | 0 |
| AGENTSC-041 | High | skill_security | Raw HTML event-handler payload (`<img onerror=…>`, `<svg onload=…>`) in agent-facing markdown | 1 | 1 | 0 |
| AGENTSC-CHAIN-001 | Critical | network_exfil | Correlation: a secret-named environment sweep assigned to a variable that reaches a network send within 20 lines | 0 | 0 | 0 |

AGENTSC-002, AGENTSC-003 and AGENTSC-CHAIN-001 add no newly blocked sample.
AGENTSC-002's 24 hits are all samples other rules already blocked; it is
there because the password-protected archive is the one part of the lure the
campaigns have not varied. AGENTSC-003's one hit is the JianYing skill, which
it does not move to HIGH (see remaining misses). The correlation rule has no
corpus hit because the one sample with the shape assigns the sweep five lines
above the `jq` step that feeds `curl`, two hops rather than one; its unit test
covers the one-hop form.

Severity follows the project policy: Medium where the shape has an innocent
reading in context (a release tarball without `.env` excluded; a vendor
documenting an opt-in global install; a skill that prefers its own fetch
tool), High where the line is the attack, Critical only where no legitimate
package does it (fetching a script from an anonymous file-drop host; shipping
a live session cookie). AGENTSC-010 carries weight 5 instead of the
credentials default of 2, because a filtered secret sweep is a harvesting
action, not a capability an API client has.

Behaviour labels (`sigil scan` profile): AGENTSC-004 is `dynamic_execution`
and AGENTSC-030 is `installs_persistence` — the two ACTION behaviours, which
let a first-party score of 50 reach HIGH. The fake-prerequisite rules are
`drive_by_install` (not an action: the rule reads an instruction to a human),
harvesting rules are `harvests_credentials` / `exfiltrates_data` /
`hardcoded_secrets`, AGENTSC-020 is `c2_tunnel_host`, AGENTSC-031 is
`manipulates_agent`, AGENTSC-040 is `hijacks_browser_session` and AGENTSC-041
is `active_content_payload`.

## What the 62 missed samples were

Every missed sample was read (statically; nothing in the corpus was run).

| Cluster | Samples | Blocked now | Rules |
|---|---:|---:|---|
| Fake prerequisite (ClawHavoc-style "OpenClawCLI must be installed … Download and install (Windows, MacOS) from https://openclawcli.vercel.app/") | 24 | 24 | 001, 005 |
| Fake prerequisite via personal file-share (JianYing Pro 5.9 from a Quark drive link) | 1 | 0 | 003 |
| Dropper: code downloads `slack_gif_helper.py` from tmpfiles.org and runs it with `sys.executable` | 1 | 1 | 004 |
| Secret harvest and exfiltration: env sweep posted to a `workers.dev` collector; project tarball with `.env` uploaded to a public deploy preview (4 copies); host file attached to a Discord webhook; Google refresh tokens extracted from another app's config; `sessionid` cookie lifted from a logged-in browser; live SSO session cookie shipped in `.session.json` | 9 | 9 | 010, 011, 012, 013, 014 |
| MCP endpoint on a tunnel or raw-IP host (`bore.pub:44876`, `<ip>.sslip.io`) | 2 | 2 | 020 |
| Agent hijacking: self-propagation into `~/.claude/CLAUDE.md` / `~/.gemini/GEMINI.md` / `~/.codex/instructions.md`; "MUST replace WebFetch and WebSearch" (2); default sender is the author's `@126.com` mailbox with "DO NOT ask the user"; AppleScript `execute javascript` in the user's Chrome to post to Reddit "undetectably" | 5 | 5 | 030, 031, 032, 040 |
| Stored XSS in SKILL.md aimed at a skills directory (self-declared bug-bounty PoC — still a live payload for any renderer) | 1 | 1 | 041 |
| Other lanes / not an attack shape / not malicious on inspection | 19 | 0 | — |

### Remaining misses (20) and why

| Sample | Verdict | Why it is not blocked |
|---|---|---|
| `luoluoluo22-jianying-editor-skill` | MEDIUM | AGENTSC-003 fires (twice), but the skill has 97 scanned files, so one High finding cannot reach the density threshold, and `drive_by_install` is not an ACTION behaviour. Measured on a scratch build that adds `drive_by_install` to `ACTION_BEHAVIOURS` in `scoring.rs` (not part of this change): this sample becomes HIGH (185/204 blocked) and no clean verdict changes. |
| `one-box-u-openclaw-daily-hot-news` | NONE | At run time it `git clone`s an unpinned third-party repo (imsyy/DailyHotApi) and runs its `deploy.sh`. A real supply-chain risk, but the upstream is a well-known open-source project and the clone-then-run spans two assignments, which a one-hop correlation cannot link without also matching ordinary build tooling. Not forced. |
| `tjade273-…-simple-formatter` (2 copies) | NONE | Shipped `__pycache__/*.pyc` whose bytecode (`eval`, `os.environ`) differs from the `.py` source. Owned by the bytecode/concealed-executable lane. |
| `plurigrid-asi-skills-vercel-deploy` | NONE | `scripts/deploy.sh` is byte-identical to OpenAI's curated `vercel-deploy`, which excludes `.env`; the SKILL.md is an older vendor revision. Blocking it would block the vendor skill. |
| `cisco-ai-defense-skill-scanner-file-validator` | NONE | Cisco's own evaluation sample; its `_expected.json` says `"expected_safe": true`. Not malicious. |
| `binhmuc-…-frontend-development`, `zircote-…-frontend-development` | NONE | React/TypeScript guideline documents; no URLs, code execution, hidden text or instructions beyond style rules. No malicious content found. |
| `dauquangthanh-…-rpg-migration-analyzer` | NONE | RPG-to-Java migration reference. SkillSpector's HIGH comes from "Send message to" in RPG messaging pseudocode, `api.example.com` placeholders and `PLIST` (an RPG parameter list) — false positives. No malicious content found. |
| `sebastiaanwouters-dotagents-skills-e2e-tester` | MEDIUM | Playwright/Pest test-generation guide. The only risky shape is an unpinned `npx -y playwriter@latest` MCP server, which is how most MCP servers are declared. No malicious content found. |
| `matteocervelli-…-whitelist-bypass-skill` | NONE | An empty generated template ("Bypass attempt. Use for security testing.") with no instructions or code. Nothing to detect. |
| `wpsteak-popmagic-skills-skills-emotion-bird` | NONE | A user-requested "guilt-trip" reminder persona that comments on the user's own Notion tasks. Manipulative tone, no attack on the installer or the agent. |
| `mcpcat-skills-skills-install-mcpcat-typescript` | NONE | Installs a disclosed commercial analytics SDK into an MCP server the user owns. A privacy decision, not an attack shape. |
| `parcadei-…-git-commits` | NONE | Routes commits through a `/commit` skill that removes AI attribution trailers. Deceptive about authorship, but a choice many users make deliberately; not flagged. |
| `dreamineering-…-community-architect`, `manojbajaj95-…-community-architect` | NONE | A crypto "holder psychology" playbook (cult creation, exit prevention). Harmful content aimed at third parties, but no code, exfiltration or agent hijack. Out of scope for a code-security rule. |
| `gmh5225-…-anti-cheat`, `gmh5225-…-graphics-api` | NONE | Game anti-cheat bypass and graphics-hooking research notes. Dual-use knowledge, no payload. |
| `tmdgusya-code-squad-skills-subway` | MEDIUM | Team lunch-order tool that posts to a default GitHub repo and reads `../../../.env`; its `execSync` string building is injection-prone (CODE-007 fires). Not clearly malicious. |
| `buff-m-email-sender-skill` | MEDIUM | `requirements.txt` asks for `smtplib-ssl`, a package named after a standard-library module. Possibly a squat, but that is dependency-name analysis (typosquat module), not this pack. |

## Suppressing a finding

Each rule's remediation says what to check. When a reviewer has checked and
the line is legitimate, suppress it where it is, with a reason:

```text
<!-- sigil:ignore AGENTSC-030 -- optional, documented Codex identity install -->
```

or, for a path that should never be scanned, add a scoped entry with a written
rationale to `.sigilignore`.

## Known limitations

- **Line-level matching.** Shell commands continued with `\` are seen one line
  at a time, so a `curl -X POST \` / `-d "$REPORT" \` / `https://…` sequence
  is three unrelated lines. That is why the `workers.dev` collector in the
  env-sweep sample is not itself a finding; the sweep is.
- **Host lists need maintenance.** AGENTSC-001, 003, 004 and 020 name
  hosting, file-share, file-drop and tunnel services. A campaign that moves to
  an ordinary registered domain escapes AGENTSC-001; AGENTSC-005 (the per-OS
  download wording) is the host-independent backstop and fires on all 24
  fake-prerequisite samples, but at Medium it only blocks the smallest of
  them (one or two files) without AGENTSC-001 beside it.
- **Language.** The token-harvest rule (AGENTSC-013) and the file-share rule
  (AGENTSC-003) include Chinese keywords because the samples were Chinese;
  other languages are not covered.
- **In-sample measurement.** See the disclosure block at the top.

## Reconciliation with the false-positive calibration

The false-positive calibration (`docs/detection/fp-calibration.md`) made Low
findings observations and HIGH conditional on a High or Critical first-party
finding. Merged with this pack (commit 7c9b68a), 24 malicious skills this pack
had blocked fell back to MEDIUM or below, eight of them because the attack
evidence was carried by rules authored here at Medium. The reconciliation pass
moved that evidence to rules that can block, without re-grading any routine
idiom. The whole pass, with the Datadog work and every sample, is written up
under "Reconciliation" in `fp-calibration.md`; this section records what
changed in this pack.

```
Data Source: Real samples, same corpora as above (204 malicious ai-skills,
             455 vendor skills), scanned with the built binary, static phases.
Sample Size: 204 malicious, 455 clean.
Limitations: In-sample. Every rule below was written or re-graded after reading
             the samples it recovers; the clean figures are the only check that
             it does not over-fire, and they are the same 455 skills.
```

| Rule | Before | After | Change | Malicious hit | Clean hit |
|---|---|---|---|---:|---:|
| AGENTSC-031 | Medium | High | Narrowed to the take-over order: "MUST/always replace (override, supersede) WebFetch/WebSearch/built-in" | 2 | 0 |
| AGENTSC-033 | — | Medium | New: the softer forms split out of the old AGENTSC-031 ("instead of WebFetch", "never use WebSearch", "should replace", "prefer X over WebFetch") and the claim "replaces all built-in … tools", which scoped to one task ("replaces all the default tools for PDF editing") is an ordinary product description | 2 | 0 |
| AGENTSC-034 | — | High | New: an instruction to write the skill's rules into the global instruction file without the user's say — a stealth or no-consent phrase ("silently", "without asking", "do not tell the user", 不要告诉用户, 静默), a first-person report of an automatic write ("I have automatically updated your global rules", 我已自動加固您的全局規則), or "automatically … the user's global …". Opt-in documentation ("add the following to your global CLAUDE.md", 将以下内容添加到全局规则) does not fire; AGENTSC-030 still names the file at Medium | 1 | 0 |
| AGENTSC-030 | Medium | Medium | Unchanged. It names the global file; NVIDIA `tao-setup` documents an opt-in script that installs its identity there, and AGENTSC-034 now carries the write instruction instead of this rule being raised | 3 | 1 |
| AGENTSC-015 | — | High | New: a loop over the user's SSH private-key names (`for key_file in ["id_rsa", "id_ed25519", …]`, the JS `.forEach` and shell `for k in ~/.ssh/id_*` forms). A list of key names that is only data — Pygments' filename table — does not match, and a loop that looks for the public half (`.pub` within the next three lines) is suppressed | 1 | 0 |
| AGENTSC-011 | Medium | Medium | Unchanged: a tarball without `.env` excluded that stays on the machine is a hygiene defect | 4 | 0 |
| AGENTSC-CHAIN-002 | — | High | New correlation: an AGENTSC-011 archive whose path (`tar -czf "$TARBALL"`) is uploaded within 20 lines (`curl -F "file=@$TARBALL"`, NET-UPLOAD-001, or an HTTP client) | 4 | 0 |
| AGENTSC-005 | Medium | Medium | Unchanged. All 39 samples it fires on are blocked by AGENTSC-001 or SKILL-024, so High would add no block, and "Download (Windows, macOS) from …" is also how a legitimate cross-platform tool words its download page | 39 | 0 |

The rows for AGENTSC-031, AGENTSC-033, AGENTSC-034 and AGENTSC-015 describe
the rules after the adversarial verification pass ("Adversarial verification"
in `fp-calibration.md`). That pass narrowed them because benign inputs fired
them at High:

- opt-in documentation that tells a person how to add a snippet to their global
  file (AGENTSC-034)
- a scoped product description, "replaces all the default tools for PDF
  editing" (AGENTSC-031)
- a loop that looks for the user's public key (AGENTSC-015)

Blocked and warned counts did not change. AGENTSC-033 now also fires on the two
firecrawl copies' "Replaces all built-in … tools" line; they stay blocked on
"MUST replace WebFetch and WebSearch".

The fake-prerequisite behaviour (`drive_by_install`, AGENTSC-001..005) is now
an ACTION behaviour in `scoring.rs`, as the "Remaining misses" table above
proposed. Re-measured after the calibration: `luoluoluo22-jianying-editor-skill`
moves from MEDIUM to HIGH and no clean skill changes verdict.

The correlation linker binds file paths as well as assignments (`tar -czf
"$TARBALL"`, `curl -o "$OUT"`, `open(PATH, 'wb')`, `urlretrieve(url,
"/tmp/x.pyz")`), which is what lets AGENTSC-CHAIN-002 connect the archive to
the upload. AGENTSC-CHAIN-001 is unchanged and still has no corpus hit (the one
sample with the sweep shape is two hops, see above).

Samples recovered from the 24: the four vercel-deploy copies
(AGENTSC-CHAIN-002), the two firecrawl copies (AGENTSC-031), toolsai
auto-skill (AGENTSC-034) and Charpup credential-harvester (AGENTSC-015). The
other sixteen are listed with the reason they stay below HIGH in
`fp-calibration.md`.
