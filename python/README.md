# sigilsec (PyPI wrapper)

[Sigil](https://github.com/NOMARJ/sigil) is an automated security auditing
CLI for AI agent code: quarantine-first scanning for pip and npm packages,
git repositories, MCP servers and agent skills.

This package is a thin, dependency-free installer for the prebuilt Rust
binary. It is the Python counterpart of the npm package
[`@nomarj/sigil`](https://www.npmjs.com/package/@nomarj/sigil) and follows
the same mechanics.

```bash
pip install sigilsec
sigil scan .
```

The PyPI name is **`sigilsec`**: `sigil-cli` (the crates.io name) is already
taken on PyPI by an unrelated project, checked 2026-09-02. The import package
is `sigil_cli` and the installed command is `sigil`.

## What it does

1. On the first `sigil` invocation the wrapper picks the release asset for the
   host from `platform.system()` / `platform.machine()`:

   | Platform | Machine            | Asset                       |
   | -------- | ------------------ | --------------------------- |
   | macOS    | `x86_64`           | `sigil-macos-x64.tar.gz`    |
   | macOS    | `arm64`            | `sigil-macos-arm64.tar.gz`  |
   | Linux    | `x86_64`           | `sigil-linux-x64.tar.gz`    |
   | Linux    | `aarch64`/`arm64`  | `sigil-linux-arm64.tar.gz`  |
   | Windows  | `AMD64`            | `sigil-windows-x64.zip`     |

2. It downloads `https://github.com/NOMARJ/sigil/releases/download/v<version>/<asset>`
   together with `SHA256SUMS.txt` from the same release, where `<version>` is
   this package's version (it tracks `cli/Cargo.toml`).
3. It verifies the archive's SHA-256 against `SHA256SUMS.txt` with `hashlib`.
   A 404 or a checksum mismatch aborts with a clear message and nothing is
   written.
4. The single `sigil` (or `sigil.exe`) member is read out of the archive —
   nothing else in the archive is extracted — and written atomically to
   `~/.sigil/bin/sigil-<version>[.exe]` with mode `0755`.
5. Control is handed to the binary with your original arguments: `os.execv`
   on macOS/Linux (the wrapper process is replaced), `subprocess.call` on
   Windows (the exit code is forwarded).

Subsequent runs find the cached binary and skip straight to step 5. Progress
messages go to stderr, so `sigil scan -f json | jq` stays clean.

## Environment variables

| Variable        | Effect                                                                                         |
| --------------- | ---------------------------------------------------------------------------------------------- |
| `SIGIL_BINARY`  | Path to an existing `sigil` executable. Skips download and cache (local builds, air-gapped).   |
| `SIGIL_VERSION` | Release to fetch instead of the packaged version, e.g. `1.3.6` or `v1.3.6` (as in `install.sh`). |
| `SIGIL_HOME`    | Cache root, default `~/.sigil`.                                                                |

## Supported Python

Python 3.9 or newer. Standard library only — the wrapper deliberately adds no
third-party dependencies to your environment.

## Development

```bash
# Run the offline unit tests (no network access required)
python3 -m unittest discover -s python/tests

# Run the wrapper from source without installing
PYTHONPATH=python/src python3 -m sigil_cli --version

# Build sdist + wheel
python3 -m pip install build
python3 -m build python/
```

Keep `sigil_cli.__version__` equal to the `version` in `cli/Cargo.toml` — the
wrapper downloads exactly that release tag.

## Publishing

Each release is published from its `vX.Y.Z` tag by
`.github/workflows/publish-pypi.yml`, dispatched by hand once `release.yml` has
published that tag's GitHub release with all five binaries and
`SHA256SUMS.txt`. It uses PyPI trusted publishing, so no token is stored. Full
steps: [`docs/RELEASING.md`](https://github.com/NOMARJ/sigil/blob/main/docs/RELEASING.md).

## License

Apache-2.0, same as Sigil.
