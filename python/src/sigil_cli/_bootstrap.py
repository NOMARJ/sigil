"""First-run bootstrap: fetch, verify, cache and hand off to the Sigil binary.

Mirrors the npm wrapper (``scripts/install-binary.js``) and ``install.sh``:

* asset chosen from ``platform.system()`` / ``platform.machine()``
* downloaded from ``https://github.com/NOMARJ/sigil/releases/download/v<version>/<asset>``
* SHA-256 checked against the release's ``SHA256SUMS.txt`` (fail closed)
* cached as ``~/.sigil/bin/sigil-<version>`` (``.exe`` on Windows), mode 0755
* control handed to the binary with the original arguments

Environment overrides:

``SIGIL_BINARY``
    Absolute path to a ``sigil`` executable. Skips download and cache
    entirely — useful for local builds and air-gapped hosts.
``SIGIL_VERSION``
    Release to fetch instead of the packaged version. Accepts ``1.3.6`` or
    ``v1.3.6`` (same as ``install.sh``).
``SIGIL_HOME``
    Overrides ``~/.sigil`` as the cache root.

Standard library only — no third-party dependencies.
"""

import hashlib
import io
import os
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile

from sigil_cli import __version__

REPO = "NOMARJ/sigil"
RELEASE_BASE = "https://github.com/%s/releases/download" % REPO
CHECKSUMS_NAME = "SHA256SUMS.txt"

# (platform.system().lower(), normalised machine) -> release asset.
# Kept in sync with .github/workflows/release.yml and scripts/install-binary.js.
ASSETS = {
    ("darwin", "x64"): "sigil-macos-x64.tar.gz",
    ("darwin", "arm64"): "sigil-macos-arm64.tar.gz",
    ("linux", "x64"): "sigil-linux-x64.tar.gz",
    ("linux", "arm64"): "sigil-linux-arm64.tar.gz",
    ("windows", "x64"): "sigil-windows-x64.zip",
}

_MACHINE_ALIASES = {
    "x86_64": "x64",
    "amd64": "x64",
    "x64": "x64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


class BootstrapError(Exception):
    """Raised for any condition that must stop the wrapper from running sigil."""


# ── Platform / version resolution ────────────────────────────────────────────


def normalise_machine(machine):
    """Map ``platform.machine()`` spellings onto the release naming (x64/arm64)."""
    return _MACHINE_ALIASES.get((machine or "").lower())


def asset_name(system=None, machine=None):
    """Return the release asset for this platform, or raise ``BootstrapError``."""
    system = (system if system is not None else platform.system()).lower()
    raw_machine = machine if machine is not None else platform.machine()
    arch = normalise_machine(raw_machine)
    asset = ASSETS.get((system, arch)) if arch else None
    if not asset:
        raise BootstrapError(
            "unsupported platform %s/%s. Prebuilt binaries exist for macOS "
            "(x64, arm64), Linux (x64, arm64) and Windows (x64). Build from "
            "source with `cargo install sigil-cli` or set SIGIL_BINARY to an "
            "existing executable." % (system, raw_machine)
        )
    return asset


def is_windows(system=None):
    system = (system if system is not None else platform.system()).lower()
    return system == "windows"


def resolve_version(env=None):
    """Version to install: ``SIGIL_VERSION`` (with or without ``v``) or ours."""
    env = os.environ if env is None else env
    override = (env.get("SIGIL_VERSION") or "").strip()
    if override:
        return override[1:] if override[:1] in ("v", "V") else override
    return __version__


def sigil_home(env=None):
    env = os.environ if env is None else env
    return env.get("SIGIL_HOME") or os.path.join(os.path.expanduser("~"), ".sigil")


def cached_binary_path(version, env=None, system=None):
    """``~/.sigil/bin/sigil-<version>`` (``.exe`` on Windows)."""
    name = "sigil-%s" % version
    if is_windows(system):
        name += ".exe"
    return os.path.join(sigil_home(env), "bin", name)


# ── Download & verification ───────────────────────────────────────────────────


def _log(message):
    # Progress goes to stderr so `sigil scan -f json | jq` stays clean.
    sys.stderr.write("sigil: %s\n" % message)
    sys.stderr.flush()


def download(url, version=__version__):
    """Fetch ``url`` fully into memory. 404 and network errors fail closed."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "sigil-cli/%s" % version}
    )
    try:
        # sigil:ignore-next-line NET-002 -- release download from the pinned GitHub Releases URL; SHA-256 verified against SHA256SUMS.txt before anything is written
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise BootstrapError(
                "release asset not found (404): %s\n"
                "  Either v%s has no published release yet or this platform is "
                "not shipped for that version. Check "
                "https://github.com/%s/releases, or set SIGIL_VERSION to an "
                "existing release." % (url, version, REPO)
            )
        raise BootstrapError("could not download %s (HTTP %s)" % (url, exc.code))
    except urllib.error.URLError as exc:
        raise BootstrapError("could not download %s (%s)" % (url, exc.reason))


def expected_hash(checksums_text, name):
    """Pull the SHA-256 for ``name`` out of ``SHA256SUMS.txt`` content.

    Accepts the ``sha256sum`` formats ``<hash>  <name>`` and ``<hash> *<name>``.
    """
    for line in checksums_text.splitlines():
        entry = line.strip()
        if not entry:
            continue
        parts = entry.split()
        if len(parts) < 2:
            continue
        listed = parts[-1].lstrip("*")
        if listed == name:
            return parts[0].lower()
    raise BootstrapError("checksum missing for %s in %s" % (name, CHECKSUMS_NAME))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data, expected, name="native binary archive"):
    """Raise ``BootstrapError`` unless ``sha256(data)`` equals ``expected``."""
    actual = sha256_hex(data)
    if actual != (expected or "").lower():
        raise BootstrapError(
            "checksum mismatch for %s\n"
            "  expected %s\n"
            "  actual   %s\n"
            "  Refusing to install. The download may be corrupt or tampered "
            "with — retry, and report it if it persists." % (name, expected, actual)
        )
    return True


def verify_file(path, expected, name=None):
    """Convenience: checksum an on-disk file (used by tests and re-verification)."""
    with open(path, "rb") as handle:
        data = handle.read()
    return verify_checksum(data, expected, name or os.path.basename(path))


# ── Extraction & caching ──────────────────────────────────────────────────────


def _extract_member(archive, asset, binary_name):
    """Return the raw bytes of ``binary_name`` from a ``.tar.gz`` or ``.zip``.

    Only the single expected member is read; nothing is extracted to disk from
    the archive's own paths, so a crafted archive cannot write elsewhere.
    """
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            for info in bundle.infolist():
                if os.path.basename(info.filename) == binary_name and not info.is_dir():
                    return bundle.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            for member in bundle.getmembers():
                if member.isfile() and os.path.basename(member.name) == binary_name:
                    handle = bundle.extractfile(member)
                    if handle is not None:
                        return handle.read()
    raise BootstrapError("%s does not contain %s" % (asset, binary_name))


def install_from_archive(archive, asset, destination):
    """Write the binary from ``archive`` to ``destination`` atomically, mode 0755."""
    binary_name = "sigil.exe" if asset.endswith(".zip") else "sigil"
    payload = _extract_member(archive, asset, binary_name)

    target_dir = os.path.dirname(destination)
    os.makedirs(target_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".sigil-download-", dir=target_dir)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.chmod(
            temp_path,
            stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH,
        )  # 0o755
        os.replace(temp_path, destination)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
    return destination


def fetch_binary(version, destination, asset=None):
    """Download + verify + extract one release into ``destination``."""
    asset = asset or asset_name()
    base = "%s/v%s" % (RELEASE_BASE, version)
    _log("downloading Sigil v%s (%s) ..." % (version, asset))
    archive = download("%s/%s" % (base, asset), version)
    checksums = download("%s/%s" % (base, CHECKSUMS_NAME), version).decode(
        "utf-8", "replace"
    )
    verify_checksum(archive, expected_hash(checksums, asset), asset)
    install_from_archive(archive, asset, destination)
    _log("installed %s" % destination)
    return destination


def ensure_binary(env=None):
    """Return the path of an executable sigil, downloading it if necessary."""
    env = os.environ if env is None else env

    override = (env.get("SIGIL_BINARY") or "").strip()
    if override:
        if not os.path.isfile(override):
            raise BootstrapError("SIGIL_BINARY points to a missing file: %s" % override)
        return override

    version = resolve_version(env)
    path = cached_binary_path(version, env)
    if os.path.isfile(path):
        return path
    return fetch_binary(version, path)


# ── Hand-off ──────────────────────────────────────────────────────────────────


def run(argv, env=None):
    """Replace this process with sigil (POSIX) or run it and return its code (Windows)."""
    binary = ensure_binary(env)
    command = [binary] + list(argv)
    if is_windows():
        # execv on Windows spawns a detached child and returns immediately,
        # which loses the exit code — so wait on a subprocess instead.
        # sigil:ignore-next-line CODE-013 -- hand-off to the checksum-verified sigil binary with the user's own argv; argv list, no shell
        return subprocess.call(command)
    try:
        # sigil:ignore-next-line CODE-014 -- POSIX hand-off replaces this wrapper with the verified sigil binary; argv list, no shell
        os.execv(binary, command)
    except OSError as exc:
        raise BootstrapError("failed to execute %s: %s" % (binary, exc))
    return 0  # unreachable: execv does not return on success
