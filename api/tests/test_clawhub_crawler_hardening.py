from __future__ import annotations

import asyncio
import io
import zipfile
from pathlib import Path

import pytest

from api.services import clawhub_crawler
from api.services.clawhub_crawler import ClawHubSkill


def test_http_get_rejects_non_clawhub_urls() -> None:
    assert (
        asyncio.run(clawhub_crawler._http_get("https://evil.example/api/v1/skills"))
        is None
    )
    assert (
        asyncio.run(clawhub_crawler._http_get("http://clawhub.ai/api/v1/skills"))
        is None
    )
    assert (
        asyncio.run(clawhub_crawler._http_get("https://clawhub.ai.evil/api/v1/skills"))
        is None
    )
    assert (
        asyncio.run(clawhub_crawler._http_get("https://clawhub.ai/not-api/skills"))
        is None
    )


def test_safe_temp_slug_strips_path_characters() -> None:
    assert clawhub_crawler._safe_temp_slug("../../bad/skill") == "bad-skill"
    assert clawhub_crawler._safe_temp_slug("valid.skill_1") == "valid.skill_1"


def test_download_skill_rejects_zip_path_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as zf:
        zf.writestr("../escape.txt", "bad")

    async def fake_http_get(*args: object, **kwargs: object) -> bytes:
        return payload.getvalue()

    monkeypatch.setattr(clawhub_crawler, "_http_get", fake_http_get)

    result = asyncio.run(
        clawhub_crawler.download_skill(ClawHubSkill(slug="bad-skill"), str(tmp_path))
    )

    assert result is False
    assert not (tmp_path.parent / "escape.txt").exists()
