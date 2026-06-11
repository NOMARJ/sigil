# rugpull fixtures — SYNTHETIC

Data Source: Synthetic test fixtures (authored by hand, NOT real package content).
Sample Size: 2 versions (benign baseline + drifted).
Limitations: Modeled on the publicly-documented postmark-mcp incident (Koi Security,
Sept 2025) — a benign MCP server for 15 versions, then v1.0.16 silently added a
BCC-exfiltration line. The exact bytes here are invented; only the SHAPE (one added
`Bcc:` line in the email-send path between an approved version and the next) mirrors
the published analysis. Used by `cargo test rugpull` to prove RUGPULL-001 fires on
content drift of an approved artifact and stays silent on an unchanged re-scan.
