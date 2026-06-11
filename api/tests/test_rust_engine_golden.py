"""
Sigil API — Rust Engine Golden Schema Test (F-008 US-G1)

Anti-regression guard for the Python-API-delegates-to-Rust feature flag
(``SIGIL_RUST_ENGINE``). Asserts that the scan RESPONSE SCHEMA — the set of
serialized field names and their value types for every ``Finding`` — is
identical whether the flag is OFF (legacy Python rules) or ON (Rust binary).

The contract under test is the schema, not the specific findings: the two
engines are allowed to disagree on *what* they detect, but the shape of each
``Finding`` the API serializes must be byte-for-byte compatible so downstream
consumers (and ``ScanResponse``) are unaffected by which engine ran.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

from api.services import scanner as scanner_module

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "golden_scan"


def _schema_of(findings) -> set[tuple[str, str]]:
    """Reduce a list of Findings to a set of (field_name, type_name) pairs.

    Serializes each Finding through the Pydantic model (the exact path the API
    response uses) and records the JSON field name and the runtime type of its
    value. Enum fields serialize to their string value, so the type is ``str``
    in both modes — proving the wire schema matches regardless of engine.
    """
    schema: set[tuple[str, str]] = set()
    for finding in findings:
        dumped = finding.model_dump(mode="json")
        for key, value in dumped.items():
            schema.add((key, type(value).__name__))
    return schema


def _scan_off(path: str):
    """Scan with the Rust engine flag OFF (legacy Python rules)."""
    os.environ.pop("SIGIL_RUST_ENGINE", None)
    importlib.reload(scanner_module)
    return scanner_module.scan_directory(path)


def _scan_on(path: str):
    """Scan with the Rust engine flag ON, or skip if no pinned binary is given.

    The ON-half requires an explicitly pinned ``SIGIL_BIN`` so the test runs
    against a binary known to honour the ADR-0010 exit contract (0 clean /
    1 finding / 2 error), rather than whatever ``sigil`` happens to be on PATH
    — older packaged builds may diverge (e.g. return exit 2 alongside valid
    findings) and would make this guard flaky for reasons unrelated to schema.
    """
    if not os.environ.get("SIGIL_BIN", "").strip():
        pytest.skip(
            "SIGIL_BIN not set; pin it to a release 'sigil' binary "
            "(cli/target/release/sigil) to run the flag-ON half of this test."
        )
    os.environ["SIGIL_RUST_ENGINE"] = "1"
    try:
        importlib.reload(scanner_module)
        if scanner_module._resolve_rust_binary() is None:
            pytest.skip("SIGIL_BIN does not point to an existing file.")
        return scanner_module.scan_directory(path)
    finally:
        os.environ.pop("SIGIL_RUST_ENGINE", None)
        importlib.reload(scanner_module)


def test_finding_schema_identical_across_engine_flag() -> None:
    """The serialized Finding schema must match whether the flag is on or off."""
    path = str(FIXTURE_DIR)

    off_findings = _scan_off(path)
    assert off_findings, "fixture should produce Python findings (sanity check)"
    off_schema = _schema_of(off_findings)

    on_findings = _scan_on(path)  # may pytest.skip if no binary
    assert on_findings, "fixture should produce Rust findings (sanity check)"
    on_schema = _schema_of(on_findings)

    assert on_schema == off_schema, (
        "Finding response schema diverged between engines.\n"
        f"  only in OFF (python): {sorted(off_schema - on_schema)}\n"
        f"  only in ON  (rust):   {sorted(on_schema - off_schema)}"
    )


def test_off_mode_uses_python_rules() -> None:
    """Flag OFF must yield Python rule identifiers (engine provenance check)."""
    off_findings = _scan_off(str(FIXTURE_DIR))
    rule_ids = {f.rule for f in off_findings}
    assert any(
        r.startswith(("code-", "obf-", "install-", "net-", "cred-", "prov-", "novel-"))
        for r in rule_ids
    ), f"expected Python rule ids, got {sorted(rule_ids)}"


def test_on_mode_uses_rust_rules() -> None:
    """Flag ON must yield Rust rule identifiers, not Python ones."""
    on_findings = _scan_on(str(FIXTURE_DIR))  # may pytest.skip if no binary
    rule_ids = {f.rule for f in on_findings}
    # Rust rule ids are upper-case dashed codes (e.g. CODE-001, OBFUSC-001).
    assert any(
        r.upper() == r and "-" in r and r[0].isupper() for r in rule_ids
    ), f"expected Rust rule ids, got {sorted(rule_ids)}"
    assert not any(
        r.startswith(("code-", "obf-", "install-")) for r in rule_ids
    ), f"unexpected Python rule ids in Rust mode: {sorted(rule_ids)}"
