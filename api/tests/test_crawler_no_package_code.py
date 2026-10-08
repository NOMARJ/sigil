"""The package crawler fetches PyPI and npm packages without running their code.

`pip download` builds a source distribution (running its setup.py or build
backend) to read its metadata, and `npm pack` runs a directory's or git
checkout's prepare script, even with --ignore-scripts, and packing by name
follows whatever tarball the registry's metadata names (a `file:` path or git
URL included). The crawler takes PyPI files from the JSON API and npm
tarballs from the public registry's metadata instead, checks each against the
registry's digest, and only unpacks them: neither pip nor npm runs. No
network: the HTTP fetch and subprocesses are replaced with recorders.
"""

from __future__ import annotations

import asyncio
import base64
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

    async def fake_get(
        url: str, timeout: int = 120, headers: dict[str, str] | None = None
    ) -> bytes | None:
        calls["http"].append(url)
        calls.setdefault("headers", []).append(headers or {})
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


NPM = "https://registry.npmjs.org"
TARBALL = b"npm tarball bytes"


def _sri(body: bytes, algorithm: str = "sha512") -> str:
    digest = hashlib.new(algorithm, body).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode()}"


def _packument(
    name: str,
    version: str,
    tarball: str,
    tags: dict[str, str] | None = None,
    **dist: Any,
) -> bytes:
    """Abbreviated npm registry metadata for one release."""
    dist = {"tarball": tarball, **dist}
    return json.dumps(
        {
            "name": name,
            "dist-tags": tags or {"latest": version},
            "versions": {version: {"name": name, "version": version, "dist": dist}},
        }
    ).encode()


def test_npm_target_is_fetched_as_a_file_never_packed(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    for name, version, meta_url, release in (
        ("left-pad", "1.3.0", f"{NPM}/left-pad", "1.3.0"),
        ("@types/node", "", f"{NPM}/@types%2Fnode", "20.1.0"),
        ("JSONStream", "latest", f"{NPM}/JSONStream", "1.3.5"),
    ):
        recorder["exec"].clear()
        recorder["http"].clear()
        tarball = f"{NPM}/{name}/-/{name.split('/')[-1]}-{release}.tgz"
        _serve(
            recorder,
            meta_url,
            _packument(name, release, tarball, integrity=_sri(TARBALL)),
        )
        _serve(recorder, tarball, TARBALL)
        ok = asyncio.run(
            crawler._download_npm(
                CrawlTarget(ecosystem="npm", name=name, version=version), str(tmp_path)
            )
        )
        assert ok is True, name
        assert recorder["http"] == [meta_url, tarball]
        assert recorder["headers"][-2] == {"Accept": crawler.NPM_METADATA_ACCEPT}
        # The tarball is saved as fetched and only unpacked: npm never runs.
        saved = tmp_path / f"{name.lstrip('@').replace('/', '-')}-{release}.tgz"
        assert saved.read_bytes() == TARBALL
        assert [cmd[0] for cmd in recorder["exec"]] == ["tar"]
        assert recorder["exec"][0][:2] == ["tar", "xzf"]


def test_npm_tarball_must_match_the_registry_integrity(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    tarball = f"{NPM}/plainpkg/-/plainpkg-1.0.0.tgz"
    sha1_hex = hashlib.sha1(TARBALL).hexdigest()
    for dist, ok_expected in (
        ({"integrity": _sri(b"other bytes")}, False),
        # The strongest algorithm listed decides.
        ({"integrity": f"{_sri(TARBALL, 'sha1')} {_sri(b'other', 'sha512')}"}, False),
        ({"integrity": f"{_sri(b'other')} {_sri(TARBALL)}"}, True),
        ({"integrity": "md5-abc"}, False),
        ({}, False),
        ({"shasum": "0" * 40}, False),
        ({"shasum": sha1_hex}, True),
        ({"integrity": _sri(TARBALL, "sha1")}, True),
    ):
        recorder["exec"].clear()
        for f in tmp_path.iterdir():
            f.unlink()
        _serve(
            recorder,
            f"{NPM}/plainpkg",
            _packument("plainpkg", "1.0.0", tarball, **dist),
        )
        _serve(recorder, tarball, TARBALL)
        ok = asyncio.run(
            crawler._download_npm(
                CrawlTarget(ecosystem="npm", name="plainpkg"), str(tmp_path)
            )
        )
        assert ok is ok_expected, dist
        if not ok_expected:
            assert list(tmp_path.iterdir()) == [], dist
            assert recorder["exec"] == [], dist


def test_npm_tarball_off_the_registry_is_never_fetched(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    # A registry or mirror can name any tarball; `npm pack <name>` would
    # pack a `file:` directory or clone a git URL and run its prepare
    # script. The crawler takes the tarball only from the registry host.
    for tarball in (
        "file:/srv/dirpkg",
        "file:///srv/pkg.tgz",
        "git+file:///srv/gitrepo",
        "git+https://github.com/owner/repo.git",
        "https://github.com/owner/repo.tgz",
        "http://registry.npmjs.org/x/-/x-1.0.0.tgz",
        "https://registry.npmjs.org.example.invalid/x-1.0.0.tgz",
        "https://example.invalid/x-1.0.0.tgz",
    ):
        recorder["http"].clear()
        _serve(
            recorder,
            f"{NPM}/probe",
            _packument("probe", "1.0.0", tarball, integrity=_sri(TARBALL)),
        )
        ok = asyncio.run(
            crawler._download_npm(
                CrawlTarget(ecosystem="npm", name="probe"), str(tmp_path)
            )
        )
        assert ok is False, tarball
        assert recorder["http"] == [f"{NPM}/probe"], tarball
    assert recorder["exec"] == []


def test_npm_release_must_be_on_the_registry(
    recorder: dict[str, list[Any]], tmp_path: Path
) -> None:
    tarball = f"{NPM}/x/-/x-1.0.0.tgz"
    _serve(
        recorder, f"{NPM}/x", _packument("x", "1.0.0", tarball, integrity=_sri(TARBALL))
    )
    for version in ("2.0.0", "next", "1"):
        recorder["http"].clear()
        ok = asyncio.run(
            crawler._download_npm(
                CrawlTarget(ecosystem="npm", name="x", version=version), str(tmp_path)
            )
        )
        assert ok is False, version
        assert recorder["http"] == [f"{NPM}/x"], version
    assert recorder["exec"] == []


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
        # npm-package-arg reads these as tarball paths, not registry names.
        ("a.tgz", ""),
        ("pkg.tar", ""),
        ("x.tar-gz", ""),
        ("foo", "1.tgz"),
        ("foo", "1.tarxgz"),
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
    assert recorder["http"] == []
    assert recorder["exec"] == []
