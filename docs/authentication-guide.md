# Sigil Authentication Guide

Local scanning requires no account. Authentication connects the Rust CLI to the Sigil cloud; it does not automatically enable every cloud scan option.

## Sign in

```bash
sigil login
```

The CLI prints a verification URL and code. Open the URL, confirm the code, and finish signing in in your browser. The CLI waits for authorization and saves the returned access token to `~/.sigil/token`. It does not prompt for a password or accept `--email` or `--password`.

For non-interactive use, supply an existing API token:

```bash
sigil login --token "$SIGIL_API_TOKEN"
```

`SIGIL_API_TOKEN` here is a shell variable that you pass explicitly; the CLI does not read it automatically. The CLI validates the token with `GET /v1/auth/verify` before saving it. Keep the variable in your CI secret store and avoid logging the command with shell tracing enabled.

There is currently no way to generate an API token from the dashboard. The token you can supply is the access token a browser sign-in saved to `~/.sigil/token`. It expires and the CLI does not refresh it, so sign in again and replace the stored secret when it does.

## Token storage

The fixed token path is `~/.sigil/token`. Login creates the parent directory as needed and attempts to set owner-only permissions (`600`) on Unix. Check storage without displaying the token:

```bash
ls -l ~/.sigil/token
```

A stored file establishes that a token was saved, not that it is still valid. Expiration depends on the token issued by the server; the CLI does not refresh it automatically. Run `sigil login` again if it expires.

There is no `sigil logout` command. Remove the local token to stop subsequent CLI processes from using it:

```bash
rm ~/.sigil/token
```

Deleting the file does not revoke the token on the server. Do not commit or share it.

## Choose cloud operations explicitly

```bash
sigil scan ./my-project
sigil scan ./my-project --enrich
sigil scan ./my-project --submit
sigil scan ./my-project --enhanced
sigil fetch
```

- Plain scanning runs the local detection phases. Dependency advisory and registry lookups may still access the network; lack of authentication is not a network isolation setting.
- `--enrich` looks up a directory hash in the cloud threat database.
- `--submit` uploads the scan result, including findings, their metadata and each finding's flagged source line, which can contain a secret.
- `--enhanced` requires authentication and sends collected source file contents and the scan result for server-side LLM analysis. Review the files before selecting this option. The API does not yet return LLM findings for it: it stores the scan and answers with its static analysis, and the CLI says so (CLI 1.3.7 prints `Enhanced analysis failed`). The API keeps the uploaded files out of the stored scan; an API without the update stores them with the scan record (see [API update rollout](cli.md#api-update-rollout) and [Data Handling](data-handling.md#3-pro-enhanced-scan-and-ai-investigation)).
- `sigil fetch` downloads cloud signatures. Logging in alone does not fetch them.
- `sigil explain <scan.json>` requires authentication and uploads every finding in that saved scan report, flagged source lines included, so the server can have a model adjudicate one finding.

Cloud feature access depends on the server and account plan. Local scanning remains available when cloud enrichment cannot be reached; an explicitly requested enhanced scan without authentication returns an error.

The `sigil scan` cloud options run only on a fresh scan. When `sigil scan` reuses a cached result (it prints `sigil: using cached result`; the cache is keyed on relative paths and file contents, so an unchanged directory or a copy of content scanned before reuses it), `--enrich`, `--submit` and `--enhanced` are skipped with a warning on stderr (including an unauthenticated `--enhanced`, which then returns no error). Add `--no-cache` when you request them. Signatures from `sigil fetch` likewise reach content scanned before the fetch, in that directory or a copy of it, only after `sigil clear-cache` or with `--no-cache`. For a repository URL, `sigil scan` runs the `sigil clone` workflow, which ignores these options without a message, cache or not; clone first, then scan `~/.sigil/quarantine/<id>` (`sigil list` shows the id).

## API endpoint

The default endpoint is `https://api.sigilsec.ai`. Select another endpoint for login with:

```bash
sigil login --endpoint https://api.yourcompany.com
```

The endpoint applies to that login only and is not saved. `sigil fetch`, `sigil report`, and the cloud options of `sigil scan` (`--enrich`, `--submit`, `--enhanced`) use the default endpoint. `sigil explain` accepts its own `--endpoint`. The CLI does not read `SIGIL_API_URL` or automatically read `SIGIL_TOKEN`.

## Authentication flow

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/auth/device/code` | POST | Start browser device authorization |
| `/v1/auth/device/token` | POST | Poll for the authorized access token |
| `/v1/auth/verify` | GET | Validate an explicitly supplied token |

Authenticated API requests use an `Authorization: Bearer` header. Password authentication and database implementation details are not part of the CLI login flow.

## Troubleshooting

- **Sign-in code expired:** run `sigil login` again and complete authorization before the new code expires.
- **Sign-in denied:** retry only if you intended to authorize this CLI session.
- **Device flow unavailable (503):** the endpoint has not configured Auth0 device authorization. Contact its operator or use a valid existing token.
- **Invalid token:** obtain a valid token and rerun `sigil login --token` or use browser sign-in.
- **Network failure:** check connectivity and the endpoint. Local scanning remains available, but login and requested cloud operations need network access.

## CI example

```yaml
- name: Authenticate Sigil
  env:
    SIGIL_API_TOKEN: ${{ secrets.SIGIL_API_TOKEN }}
  run: sigil login --token "$SIGIL_API_TOKEN"

- name: Scan dependencies
  run: sigil scan ./ --fail-on high
```

Use the CI system's secret store for the token (the access token from `~/.sigil/token`, see [Sign in](#sign-in); replace it when it expires). A plain scan does not require this authentication step; authenticate when your workflow requests cloud operations that need it.

## Further reading

- [CLI guide](./cli.md)
- [Getting started](./getting-started.md)
- [Configuration](./configuration.md)
- [Report an issue](https://github.com/NOMARJ/sigil/issues)
