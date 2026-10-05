"""The package crawler fetches PyPI and npm packages without running their code.

`pip download` builds a source distribution (running its setup.py or build
backend) to read its metadata, and `npm pack` runs a directory's or git
checkout's prepare script. The crawler takes PyPI files from the JSON API
instead, and packs only registry npm names with --ignore-scripts. No network:
the HTTP fetch and subprocesses are replaced with recorders.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from api.services import crawler
from api.services.crawler import CrawlTarget

SDIST = b"sdist bytes"
WHEEL = b"wheel bytes"
FILES = "https://files.pythonhosted.org/packages/ab/cd"


def _file(kind: str, filename: str, body: bytes, **extra: Any) -> dict[str, Any]:
    return {
        "packagetype": kind,
        "filename": filename,
        "url": f"{FILES}/{filename}",
        "digests": {"sha256": hashlib.sha256(body).hexdigest()},
        "yanked": False,
        **extra,
    }


class _Proc:
    returncode = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"", b""


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Record subprocesses and HTTP fetches instead of running them."""
    calls: dict[str, list[Any]] = {"exec": [], "http": []}
    responses: dict[str, bytes] = {}

    async def fake_exec(*cmd: str, **kwargs: Any) -> _Proc:
        calls["exec"].append(list(cmd))
        return _Proc()

    async def fake_get(url: str, timeout: int = 120) -> bytes | None:
        calls["http"].append(url)
        return responses.get(url)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(crawler, "_http_get_bytes", fake_get)
    calls["responses"] = [responses]
    return calls


def _serve(recorder: dict[str, list[Any]], url: str, body: bytes) -> None:
    recorder["responses"][0][url] = body


def test_pip_target_is_fetched_as_a_file_never_built(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    meta = {
        "urls": [
            _file("bdist_wheel", "demo-1.0-py3-none-any.whl", WHEEL),
            _file("sdist", "demo-1.0.tar.gz", SDIST),
        ]
    }
    _serve(recorder, "https://pypi.org/pypi/demo/1.0/json", json.dumps(meta).encode())
    _serve(recorder, f"{FILES}/demo-1.0.tar.gz", SDIST)

    ok = asyncio.run(
        crawler._download_pip(
            CrawlTarget(ecosystem="pypi", name="Demo", version="1.0"), str(tmp_path)
        )
    )

    assert ok is True
    # The sdist (where setup.py lives) is preferred, and saved as fetched.
    assert (tmp_path / "demo-1.0.tar.gz").read_bytes() == SDIST
    assert not any(cmd[0].startswith("pip") for cmd in recorder["exec"])
    assert all(cmd[0] in ("tar", "unzip") for cmd in recorder["exec"])
    assert recorder["http"][0] == "https://pypi.org/pypi/demo/1.0/json"


def test_pip_target_without_sdist_gets_its_wheel(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    meta = {
        "urls": [
            _file("sdist", "demo-2.0.tar.gz", SDIST, yanked=True),
            _file("sdist", "demo-2.0.tar.bz2", SDIST),
            _file("bdist_wheel", "demo-2.0-py3-none-any.whl", WHEEL),
        ]
    }
    _serve(recorder, "https://pypi.org/pypi/demo/json", json.dumps(meta).encode())
    _serve(recorder, f"{FILES}/demo-2.0-py3-none-any.whl", WHEEL)

    ok = asyncio.run(
        crawler._download_pip(CrawlTarget(ecosystem="pypi", name="demo"), str(tmp_path))
    )

    assert ok is True
    assert (tmp_path / "demo-2.0-py3-none-any.whl").read_bytes() == WHEEL
    assert ["unzip", "-o", str(tmp_path / "demo-2.0-py3-none-any.whl")] == recorder[
        "exec"
    ][0][:3]


def test_pip_file_with_wrong_digest_is_not_kept(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    meta = {"urls": [_file("sdist", "demo-1.0.tar.gz", SDIST)]}
    _serve(recorder, "https://pypi.org/pypi/demo/json", json.dumps(meta).encode())
    _serve(recorder, f"{FILES}/demo-1.0.tar.gz", b"other bytes")

    ok = asyncio.run(
        crawler._download_pip(CrawlTarget(ecosystem="pypi", name="demo"), str(tmp_path))
    )

    assert ok is False
    assert not (tmp_path / "demo-1.0.tar.gz").exists()
    assert recorder["exec"] == []


def test_pip_file_off_pythonhosted_is_not_fetched(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    for url in (
        "https://example.invalid/demo-1.0.tar.gz",
        "http://files.pythonhosted.org/demo-1.0.tar.gz",
        "https://files.pythonhosted.org.example.invalid/demo-1.0.tar.gz",
    ):
        meta = {"urls": [dict(_file("sdist", "demo-1.0.tar.gz", SDIST), url=url)]}
        _serve(recorder, "https://pypi.org/pypi/demo/json", json.dumps(meta).encode())
        ok = asyncio.run(
            crawler._download_pip(
                CrawlTarget(ecosystem="pypi", name="demo"), str(tmp_path)
            )
        )
        assert ok is False, url
        assert url not in recorder["http"]
    assert recorder["exec"] == []


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("./demo", ""),
        ("git+https://example.invalid/o/r", ""),
        ("-r", ""),
        ("demo @ https://example.invalid/x.tar.gz", ""),
        ("demo/sub", ""),
        ("demo", "--pre"),
        ("demo", "1.0 extra"),
        ("demo", "1.0/../x"),
    ],
)
def test_pip_target_that_is_not_a_package_is_refused(
    recorder: dict[str, list[Any]], tmp_path: Path, name: str, version: str
) -> None:
    ok = asyncio.run(
        crawler._download_pip(
            CrawlTarget(ecosystem="pypi", name=name, version=version), str(tmp_path)
        )
    )
    assert ok is False
    assert recorder["http"] == []
    assert recorder["exec"] == []


def test_npm_target_is_packed_with_scripts_off(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    for name, version, spec in (
        ("left-pad", "1.3.0", "left-pad@1.3.0"),
        ("@types/node", "", "@types/node"),
        ("JSONStream", "latest", "JSONStream@latest"),
    ):
        recorder["exec"].clear()
        ok = asyncio.run(
            crawler._download_npm(
                CrawlTarget(ecosystem="npm", name=name, version=version), str(tmp_path)
            )
        )
        assert ok is True
        assert recorder["exec"][0] == [
            "npm",
            "pack",
            "--ignore-scripts",
            "--pack-destination",
            str(tmp_path),
            "--",
            spec,
        ]


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("github:owner/repo", ""),
        ("owner/repo", ""),
        ("./local-dir", ""),
        ("file:../pkg", ""),
        ("https://example.invalid/pkg-1.0.0.tgz", ""),
        ("git+https://example.invalid/o/r.git", ""),
        ("-g", ""),
        ("foo", "npm:bar"),
        ("foo", "github:owner/repo"),
        ("foo", "^1.0"),
        ("foo#main", ""),
    ],
)
def test_npm_target_that_is_not_a_registry_package_is_refused(
    recorder: dict[str, list[Any]], tmp_path: Path, name: str, version: str
) -> None:
    ok = asyncio.run(
        crawler._download_npm(
            CrawlTarget(ecosystem="npm", name=name, version=version), str(tmp_path)
        )
    )
    assert ok is False
    assert recorder["exec"] == []
