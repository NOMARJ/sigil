"""PyPI wrapper for the Sigil CLI.

This package contains no scanner logic. It installs a ``sigil`` console
script that fetches the matching prebuilt release binary from GitHub
Releases on first run, verifies it against the release's ``SHA256SUMS.txt``,
caches it under ``~/.sigil/bin/``, and hands control over to it.

The version below MUST track ``cli/Cargo.toml`` — it selects which release
tag is downloaded.
"""

__version__ = "1.3.6"

__all__ = ["__version__"]
