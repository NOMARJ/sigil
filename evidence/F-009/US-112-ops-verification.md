# Evidence: US-112 — Ops verification (env, retention, live smoke)

**Date:** 2026-06-12 · **Feature:** F-009 · **Status:** PARTIAL — env/deploy verified; authenticated live call pending an owner-provided token

## Deploy summary

- F-009 merged to `sigil` main (`236884b`), images built in ACR: `sigil-api:latest` (run ca2j), `sigil-bot:latest` (run ca2k).
- `sigil-infra` PR #9 merged → deploy workflow run `27383369395` **success** (plan + apply + health-check all green).
- API revision `sigil-api--0000099` Running, 100% traffic (prior `--0000098` drained to 0%).
- 3 bot workers force-rolled (DEPLOY_TIMESTAMP bump) to the new `sigil-bot:latest`, all Healthy:
  `sigil-bot-watchers` rev 43, `sigil-bot-workers` rev 52, `sigil-bot-pr-worker` rev 41.

## Verified (deterministic)

| Check | Result |
|-------|--------|
| `ANTHROPIC_API_KEY` env on sigil-api (secretRef name only) | `ANTHROPIC_API_KEY → secretRef anthropic-api-key` ✅ |
| `anthropic-api-key` Container App secret present | present ✅ (sourced from Key Vault `claude-secret-key` via TF data source) |
| New revision healthy + serving | `sigil-api--0000099` Running, 100% traffic ✅ |
| API liveness | `GET https://api.sigilsec.ai/health` → 200 ✅ |
| Adjudicate gate intact | `POST /v1/scans/x/findings/0/adjudicate` (no auth) → 401 ✅ |
| CI deploy | run 27383369395 conclusion=success ✅ |

No secrets in this file — secretRef/Key-Vault names only.

## Pending — needs owner action

1. **Live authenticated Fable 5 call through prod** + **Free-402 / Pro-200 round-trip** + **usage row visible.**
   These require an authenticated token, which I cannot self-issue:
   - CLI `sigil login` (1.2.0) still uses the deprecated email/password path → **410 Gone**.
   - `POST /v1/auth/register` → **410** ("use Auth0").
   - `POST /v1/auth/device/code` → **500** "Failed to initiate device flow" (device-flow grant not fully wired — an auth-infra gap, **separate from F-009**, logged below).
   - No token in `~/.sigil/token`.

   **What I need:** a Personal Access Token (dashboard → Settings → API Tokens → Generate), or any valid bearer token. With it I'll run, against `https://api.sigilsec.ai`: submit a scan with a dual-use finding → `POST .../adjudicate` → expect 200 with a real `claude-fable-5` verdict (proves key wired + funded + deep-model path live + metering row), and verify the gate behavior for the caller's tier.

2. **Anthropic org 30-day data retention** — Fable 5 requires it; this is an Anthropic org console setting I can't read from here. Owner attests.

## Finding (out of F-009 scope, logged honestly)

The device-flow auth endpoints (`/v1/auth/device/code`) return 500/503 in production, and the CLI's `login` command still targets the removed custom-JWT endpoint (410). Programmatic/CLI authentication is currently broken against the Auth0-migrated API — dashboard PAT appears to be the only working token path. Filed as **NOMARJ/sigil#124**.
