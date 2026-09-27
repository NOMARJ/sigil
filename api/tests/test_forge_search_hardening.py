"""Regression tests for /forge/search resilience against null-laden rows.

Production incident 2026-08-29 (Sentry, sigil-api): crawler-written
public_scans rows carry JSON nulls ("description": null, findings with
"snippet": null). dict.get(key, "") passes those through as None, so
classify_tool called .lower() on None and the resulting 500 poisoned the
entire /forge/search page — one bad row took down the whole listing.
"""

from __future__ import annotations

import json

import pytest

from api.routers.forge import (
    _build_scan_data_from_row,
    _determine_capabilities,
    _parse_jsonish,
    classify_tool,
)


def _poisoned_scan_data() -> dict:
    """Scan data shaped like a crawler row full of JSON nulls."""
    return {
        "verdict": None,
        "risk_score": None,
        "findings": [
            {"snippet": None, "phase": None},
            "not-a-dict",
        ],
        "metadata": {
            "description": None,
            "category": None,
            "repository": None,
        },
        "package_version": None,
    }


@pytest.mark.asyncio
async def test_classify_tool_survives_json_null_fields():
    tool = await classify_tool("npm", "null-riddled-pkg", _poisoned_scan_data())

    assert tool.name == "null-riddled-pkg"
    assert tool.verdict == "UNKNOWN"
    assert tool.trust_score == 100  # null risk_score reads as 0 risk
    assert tool.github_url is None


@pytest.mark.asyncio
async def test_classify_tool_survives_fractional_risk_score():
    # Production incident 2026-08-30: public_scans rows store fractional risk
    # scores (e.g. 22.5); ClassifiedTool.trust_score declared int made every
    # /forge/search response 500 with an int_from_float validation error.
    scan_data = _poisoned_scan_data()
    scan_data["risk_score"] = 22.5

    tool = await classify_tool("npm", "fractional-score-pkg", scan_data)

    assert tool.trust_score == 77.5


@pytest.mark.asyncio
async def test_classify_tool_survives_metadata_that_parsed_to_none():
    scan_data = _poisoned_scan_data()
    scan_data["metadata"] = None
    scan_data["findings"] = None

    tool = await classify_tool("pypi", "no-metadata-pkg", scan_data)

    assert tool.capabilities == []
    assert tool.compatibility_signals == []


def test_determine_capabilities_ignores_null_and_non_dict_findings():
    capabilities = _determine_capabilities(
        [{"snippet": None, "phase": None}, "not-a-dict", {}],
        "",
    )
    assert capabilities == []


def test_build_scan_data_normalizes_null_json_blobs():
    scan_data = _build_scan_data_from_row(
        {
            "metadata_json": "null",
            "findings_json": "null",
        }
    )
    assert scan_data["metadata"] == {}
    assert scan_data["findings"] == []


def test_parse_jsonish_rejects_wrong_shapes():
    assert _parse_jsonish("null", {}) == {}
    assert _parse_jsonish("null", []) == []
    assert _parse_jsonish('"just a string"', {}) == {}
    assert _parse_jsonish("42", []) == []
    assert _parse_jsonish(json.dumps({"ok": True}), {}) == {"ok": True}
    assert _parse_jsonish(json.dumps([1, 2]), []) == [1, 2]
