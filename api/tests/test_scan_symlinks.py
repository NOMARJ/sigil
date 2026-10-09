"""A package's symbolic links are never read by the scan.

`tar` and `unzip` refuse to write *through* a link but do create it, so an
unpacked package can hold ``config.js -> /home/user/.aws/credentials`` (or a
link to ``/``). A scan that follows it puts lines of the host file into the
stored findings' snippets. The scanners skip links, and the crawler removes
them after unpacking. The files here hold fake credentials in a temporary
directory; nothing outside it is read.
"""

from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path

import pytest

from api.services import crawler
from api.services.crawler import CrawlTarget
from api.services.scanner import count_scannable_files, scan_directory

SECRET = "AKIAIOSFODNN7EXAMPLE"
HOST_FILE = f'aws_access_key_id = "{SECRET}"\n'


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    """A host directory with a secret, and a package tree linking to it."""
    host = tmp_path / "host"
    host.mkdir()
    (host / "credentials.txt").write_text(HOST_FILE)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "real.py").write_text("print('hello')\n")
    for name in ("a.py", "a.sh", "a.txt", "a.json", "a.yml", "a.md"):
        (pkg / name).symlink_to(host / "credentials.txt")
    (pkg / "hostdir").symlink_to(host, target_is_directory=True)
    return host, pkg


def test_scanner_does_not_read_through_links(tmp_path: Path) -> None:
    _, pkg = _tree(tmp_path)

    findings = scan_directory(str(pkg))

    assert SECRET not in " ".join(f.snippet for f in findings)
    assert not any("credentials" in f.file or "hostdir" in f.file for f in findings)
    assert count_scannable_files(pkg) == 1


def test_other_walkers_skip_links_too(tmp_path: Path) -> None:
    # The scanner engine imports the LLM service, which needs these.
    pytest.importorskip("aiohttp")
    pytest.importorskip("tenacity")
    from api.scanner.scanner_engine import scanner_engine
    from api.services.scanner_v1 import count_scannable_files_v1, scan_directory_v1

    _, pkg = _tree(tmp_path)

    walked = [p.name for p in scanner_engine._walk_files(pkg)]
    assert walked == ["real.py"]
    assert count_scannable_files_v1(str(pkg)) == 1
    findings = scan_directory_v1(str(pkg))
    assert SECRET not in " ".join(f.snippet for f in findings)


def test_remove_links_deletes_links_and_nothing_else(tmp_path: Path) -> None:
    host, pkg = _tree(tmp_path)

    assert crawler._remove_links(str(pkg)) == 7

    assert [p.name for p in pkg.iterdir()] == ["real.py"]
    assert (host / "credentials.txt").read_text() == HOST_FILE


class _Proc:
    returncode = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"", b""


def _tgz_with_links(host_file: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        body = b"module.exports = 1\n"
        info = tarfile.TarInfo("package/index.js")
        info.size = len(body)
        t.addfile(info, io.BytesIO(body))
        link = tarfile.TarInfo("package/config.js")
        link.type = tarfile.SYMTYPE
        link.linkname = str(host_file)
        t.addfile(link)
    return buf.getvalue()


def test_crawler_unpacks_an_npm_tarball_without_its_links(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The real `tar` unpacks a tarball holding a link; none is left."""
    import base64
    import hashlib
    import json
    import shutil

    if shutil.which("tar") is None:
        pytest.skip("tar is not installed")
    host = tmp_path / "host"
    host.mkdir()
    secret_file = host / "credentials.txt"
    secret_file.write_text(HOST_FILE)
    data = _tgz_with_links(secret_file)
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    tarball_url = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    meta = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {"dist": {"tarball": tarball_url, "integrity": integrity}}
        },
    }
    responses = {
        f"{crawler.NPM_REGISTRY}/demo": json.dumps(meta).encode(),
        tarball_url: data,
    }

    async def fake_get(
        url: str, timeout: int = 120, headers: dict[str, str] | None = None
    ) -> bytes | None:
        return responses.get(url)

    monkeypatch.setattr(crawler, "_http_get_bytes", fake_get)
    dest = tmp_path / "dest"
    dest.mkdir()

    ok = asyncio.run(
        crawler._download_npm(
            CrawlTarget(ecosystem="npm", name="demo", version=""), str(dest)
        )
    )

    assert ok is True
    assert (dest / "package" / "index.js").is_file()
    assert not (dest / "package" / "config.js").exists()
    assert not (dest / "package" / "config.js").is_symlink()
    findings = scan_directory(str(dest))
    assert SECRET not in " ".join(f.snippet for f in findings)
