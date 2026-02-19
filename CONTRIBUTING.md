# Contributing to Sigil

Thanks for your interest in making AI agent code safer. Sigil is built by [NOMARK](https://nomark.ai) and contributions from the community are welcome.

## Ways to Contribute

**Report malicious packages.** Found a dodgy MCP server, agent skill, or package? Report it via `sigil report <package>` from the CLI, or open an issue with the `threat-report` label.

**Report bugs.** Something not scanning right? False positive driving you mad? Open an issue using the bug report template.

**Suggest features.** Got an idea? Open an issue using the feature request template. We read every one.

**Submit code.** Bug fixes, new scan rules, documentation improvements, and new features are all welcome via pull request.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Install Rust toolchain (if you don't have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Run tests
cargo test

# Run the CLI locally
cargo run -- scan ./test-fixtures/
```

## Pull Request Process

1. **Fork the repo** and create your branch from `main`.
2. **Write tests** for any new scan rules or functionality.
3. **Run the test suite** â€” all tests must pass before review.
4. **Keep PRs focused.** One feature or fix per PR. Small PRs get reviewed faster.
5. **Write a clear description** of what changed and why.
6. **Update docs** if your change affects CLI behaviour, scan output, or configuration.

## Writing Scan Rules

Scan rules live in the engine and follow this pattern:

- Each rule targets a specific attack vector (install hooks, credential access, obfuscation, etc.).
- Rules produce findings with a severity weight.
- Rules must include test fixtures: one benign file that should NOT trigger, and one malicious file that SHOULD trigger.
- False positive rate matters. If your rule fires on common legitimate patterns, it needs refinement.

## Code Style

- Rust code follows standard `rustfmt` formatting. Run `cargo fmt` before committing.
- Python code (API service) follows `black` formatting with `ruff` for linting.
- Commit messages: imperative mood, concise. `Add install hook detection for Poetry` not `Added some stuff`.

## Issue Labels

| Label | Meaning |
|-------|---------|
| `bug` | Something broken |
| `feature` | New capability |
| `scan-rule` | New or improved detection rule |
| `threat-report` | Malicious package report |
| `false-positive` | Rule triggering incorrectly |
| `docs` | Documentation improvement |
| `good-first-issue` | Suitable for new contributors |

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, be constructive, be helpful.

## Questions?

Open a discussion on the [Discussions](https://github.com/NOMARJ/sigil/discussions) tab or reach out at hello@nomark.ai.

---

**SIGIL** by NOMARK â€” *A protective mark for every line of code.*
