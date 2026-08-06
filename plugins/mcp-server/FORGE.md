# Sigil Forge (Sunset)

The Forge discovery feature has been removed from the Sigil MCP server.

## What was removed

The following tools no longer exist in `@nomark/sigil-mcp-server` (removed in the discovery-feature sunset; see the "Forge tools removed" comments in `src/index.ts`):

- `forge_search` — semantic search for AI agent skills and MCP servers
- `forge_stack` — curated stacks of compatible tools for a use case
- `forge_check` — detailed trust/compatibility report for a single tool

The associated trust-scoring, category-classification, compatibility-matching, and caching behavior documented in earlier revisions of this file was part of that feature and was removed with it. The `FORGE_API_URL` environment variable is no longer read.

## What remains

The MCP server continues to provide the core Sigil security tools (`sigil_scan`, `sigil_scan_package`, `sigil_clone`, `sigil_quarantine`, `sigil_approve`, `sigil_reject`, `sigil_check_package`, `sigil_search_database`, `sigil_report_threat`). See [README.md](README.md) for the current tool list, configuration, and environment variables.
