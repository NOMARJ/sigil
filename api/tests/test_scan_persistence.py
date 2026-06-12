"""Scan persistence — store_scan drops non-schema columns; findings_count derived.

Regression for the prod incident where POST /v1/scan 503'd with
"Invalid column name 'findings_count'": the scan row builder carries
findings_count / threat_hits, which are not columns on the `scans` table.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from api.database import MssqlClient
from api.routers.scan import _findings_count, _row_to_list_item


class TestFindingsCountDerivation:
    def test_derives_from_findings_json_list(self):
        row = {"findings_json": [{"rule": "a"}, {"rule": "b"}], "findings_count": 0}
        assert _findings_count(row) == 2

    def test_derives_from_findings_json_string(self):
        row = {"findings_json": '[{"rule":"a"}]', "findings_count": 0}
        assert _findings_count(row) == 1

    def test_empty_findings(self):
        assert _findings_count({"findings_json": []}) == 0

    def test_list_item_uses_derived_count(self):
        row = {"id": "s1", "findings_json": [{"r": 1}, {"r": 2}, {"r": 3}]}
        item = _row_to_list_item(row)
        assert item.findings_count == 3


class TestStoreScanColumnFilter:
    def test_drops_columns_not_in_table(self):
        client = MssqlClient()
        captured: dict = {}

        async def fake_insert(table, data):
            captured["table"] = table
            captured["data"] = data
            return data

        real_cols = {
            "id", "target", "target_type", "files_scanned", "risk_score",
            "verdict", "findings_json", "metadata_json", "created_at",
        }
        with patch.object(client, "_table_columns", new=AsyncMock(return_value=real_cols)), \
                patch.object(client, "insert", new=fake_insert):
            asyncio.run(client.store_scan({
                "id": "s1",
                "target": "x",
                "findings_count": 5,   # phantom column
                "threat_hits": 2,      # phantom column
                "risk_score": 1.0,
                "findings_json": "[]",
            }))

        assert "findings_count" not in captured["data"]
        assert "threat_hits" not in captured["data"]
        assert captured["data"]["id"] == "s1"
        assert captured["data"]["risk_score"] == 1.0

    def test_no_filter_when_columns_unknown(self):
        """In-memory mode (_table_columns -> None) must not drop anything."""
        client = MssqlClient()
        captured: dict = {}

        async def fake_insert(table, data):
            captured["data"] = data
            return data

        with patch.object(client, "_table_columns", new=AsyncMock(return_value=None)), \
                patch.object(client, "insert", new=fake_insert):
            asyncio.run(client.store_scan({"id": "s1", "findings_count": 5}))

        assert captured["data"]["findings_count"] == 5
