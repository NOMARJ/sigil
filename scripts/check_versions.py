#!/usr/bin/env python3
"""Check that Sigil's version numbers agree across every ship channel.

Sigil ships the same scanner through a lot of front doors: a Rust crate, a
PyPI wrapper, an npm wrapper, an MCP server, IDE plugins and a skill listing.
Some of those versions MUST match (they select the release binary a user ends
up running); the rest are independent products that only need to be visible
when cutting a release.

Hard checks (a mismatch exits 1)
--------------------------------
* ``cli/Cargo.toml``                   ``[package] version``
* ``python/src/sigil_cli/__init__.py`` ``__version__``
* ``python/pyproject.toml``            ``[project] version``, or, when the
  project declares ``dynamic = ["version"]``, the
  ``[tool.setuptools.dynamic]`` attribute it resolves the version from — which
  must be ``sigil_cli.__version__``, otherwise the built wheel carries a
  version nothing here verified.
* the tag passed with ``--expect`` (a leading ``v`` is stripped), so the
  release workflows can gate a publish on it.

These three are one unit: the PyPI wrapper downloads the GitHub release named
by its own ``__version__``, and that release is built from ``cli/Cargo.toml``.
If they drift, ``pip install sigilsec==X`` installs a scanner that is not X.

Soft checks (reported, never fatal)
-----------------------------------
The MCP server, its ``server.json`` registry manifest, the npm wrapper, the
VS Code extension, the JetBrains plugin, the Claude Code plugin and the
skills.sh/ClawHub skill listing. These version independently. Two of them are
internally paired (``server.json`` with the MCP ``package.json``; the Claude
Code ``plugin.json`` with the root ``marketplace.json``) and a drift there is
reported as a warning, because the registries reject the mismatch at publish
time rather than at review time.

Usage
-----
    python3 scripts/check_versions.py                # report + hard check
    python3 scripts/check_versions.py --expect v1.3.6
    make check-versions
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Where the PyPI wrapper's dynamic version must come from.
EXPECTED_VERSION_ATTR = "sigil_cli.__version__"


class Missing(Exception):
    """A file or key this script needs could not be read."""


# ---------------------------------------------------------------------------
# Tiny readers. Deliberately dependency-free: this script runs in release
# workflows before anything is installed, and on Pythons older than tomllib.
# ---------------------------------------------------------------------------


def toml_sections(text: str) -> dict[str, str]:
    """Split TOML into {section name: body}. Good enough for the keys we read.

    The top-level (pre-header) body is keyed ``""``. Array-of-table headers
    (``[[bin]]``) start a section under their bracketed name so their keys
    never leak into the preceding table.
    """
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped.strip("[]").strip()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    return {name: "\n".join(body) for name, body in sections.items()}


def toml_string(body: str, key: str) -> str | None:
    """Read a bare ``key = "value"`` string out of one TOML section body."""
    match = re.search(r'^\s*%s\s*=\s*"([^"]*)"' % re.escape(key), body, re.MULTILINE)
    return match.group(1) if match else None


def dynamic_version_attr(body: str) -> str | None:
    """Read ``version = { attr = "pkg.__version__" }`` from a section body.

    setuptools' dynamic-version declaration is an inline table, so the key we
    want is not at the start of its line and ``toml_string`` cannot see it.
    """
    match = re.search(
        r'^\s*version\s*=\s*\{[^}]*\battr\s*=\s*"([^"]+)"', body, re.MULTILINE
    )
    return match.group(1) if match else None


def cargo_version(root: Path) -> str:
    path = root / "cli" / "Cargo.toml"
    if not path.is_file():
        raise Missing("%s not found" % path)
    package = toml_sections(path.read_text()).get("package")
    if package is None:
        raise Missing("%s has no [package] table" % path)
    version = toml_string(package, "version")
    if not version:
        raise Missing("%s [package] has no version" % path)
    return version


def dunder_version(root: Path) -> str:
    path = root / "python" / "src" / "sigil_cli" / "__init__.py"
    if not path.is_file():
        raise Missing("%s not found" % path)
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', path.read_text(), re.MULTILINE)
    if not match:
        raise Missing("%s has no __version__" % path)
    return match.group(1)


def pyproject_version(root: Path) -> tuple[str | None, str]:
    """Return (literal version or None, how it is declared).

    ``None`` means the version is dynamic; the caller then relies on the
    attribute check, which is done here and raises on a wrong attribute.
    """
    path = root / "python" / "pyproject.toml"
    if not path.is_file():
        raise Missing("%s not found" % path)
    sections = toml_sections(path.read_text())
    project = sections.get("project")
    if project is None:
        raise Missing("%s has no [project] table" % path)

    literal = toml_string(project, "version")
    if literal:
        return literal, "literal"

    dynamic = re.search(r"^\s*dynamic\s*=\s*\[([^\]]*)\]", project, re.MULTILINE)
    if not dynamic or "version" not in dynamic.group(1):
        raise Missing(
            '%s [project] declares neither a version nor dynamic = ["version"]' % path
        )

    body = sections.get("tool.setuptools.dynamic")
    attr = dynamic_version_attr(body) if body is not None else None
    if attr is None:
        raise Missing(
            "%s declares a dynamic version but [tool.setuptools.dynamic] has no "
            "version attr" % path
        )
    if attr != EXPECTED_VERSION_ATTR:
        raise Missing(
            "%s resolves its dynamic version from %r, expected %r — the built wheel "
            "would carry a version this check never saw"
            % (path, attr, EXPECTED_VERSION_ATTR)
        )
    return None, "dynamic -> %s" % attr


def pyproject_name(root: Path) -> str | None:
    path = root / "python" / "pyproject.toml"
    if not path.is_file():
        return None
    project = toml_sections(path.read_text()).get("project")
    return toml_string(project, "name") if project is not None else None


def json_key(root: Path, relative: str, *keys: str | int) -> str | None:
    """Read a nested key out of a JSON file; None if the file or key is absent."""
    path = root / relative
    if not path.is_file():
        return None
    try:
        node = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    for key in keys:
        if isinstance(node, list):
            if not isinstance(key, int) or key >= len(node):
                return None
            node = node[key]
        elif isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return node if isinstance(node, str) else None


def marketplace_plugin_version(root: Path, name: str) -> str | None:
    path = root / ".claude-plugin" / "marketplace.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    for plugin in data.get("plugins", []):
        if isinstance(plugin, dict) and plugin.get("name") == name:
            version = plugin.get("version")
            return version if isinstance(version, str) else None
    return None


def jetbrains_version(root: Path) -> tuple[str | None, str]:
    """JetBrains reads pluginVersion from gradle.properties, with a code default."""
    properties = root / "plugins" / "jetbrains" / "gradle.properties"
    if properties.is_file():
        match = re.search(
            r"^\s*pluginVersion\s*=\s*(\S+)", properties.read_text(), re.MULTILINE
        )
        if match:
            return match.group(1), "plugins/jetbrains/gradle.properties"
    build = root / "plugins" / "jetbrains" / "build.gradle.kts"
    if build.is_file():
        match = re.search(r'orElse\("([^"]+)"\)', build.read_text())
        if match:
            return match.group(1), "plugins/jetbrains/build.gradle.kts (fallback)"
    return None, "plugins/jetbrains"


def skill_frontmatter_version(root: Path) -> str | None:
    """`metadata.version` from the skill's YAML front matter.

    Read with a regex rather than a YAML parser: this script must stay
    dependency-free, and the front matter is a fixed two-level shape.
    """
    path = root / "sigil-skill" / "sigil-scan" / "SKILL.md"
    if not path.is_file():
        return None
    text = path.read_text()
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    front = text[:end] if end != -1 else text
    match = re.search(
        r'^metadata:\s*$.*?^\s+version:\s*"?([^"\s]+)"?\s*$',
        front,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else None


def server_json_versions(root: Path) -> tuple[str | None, str | None]:
    """server.json carries the version twice: top level and on the npm package."""
    return (
        json_key(root, "plugins/mcp-server/server.json", "version"),
        json_key(root, "plugins/mcp-server/server.json", "packages", 0, "version"),
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_table(rows: list[tuple[str, str, str, str]]) -> str:
    header = ("COMPONENT", "SOURCE", "VERSION", "STATUS")
    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(len(header))]
    lines = [
        "  ".join(header[i].ljust(widths[i]) for i in range(4)).rstrip(),
        "  ".join("-" * widths[i] for i in range(4)),
    ]
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(4)).rstrip())
    return "\n".join(lines)


def check(root: Path, expect: str | None) -> tuple[int, str]:
    """Return (exit code, printable report)."""
    problems: list[str] = []
    warnings: list[str] = []
    rows: list[tuple[str, str, str, str]] = []

    # ---- hard set -------------------------------------------------------
    hard: dict[str, str] = {}
    for label, source, reader in (
        ("Rust CLI", "cli/Cargo.toml", cargo_version),
        ("PyPI wrapper", "python/src/sigil_cli/__init__.py", dunder_version),
    ):
        try:
            version = reader(root)
        except Missing as exc:
            problems.append(str(exc))
            rows.append((label, source, "?", "UNREADABLE"))
        else:
            hard[label] = version
            rows.append((label, source, version, "must match"))

    try:
        literal, how = pyproject_version(root)
    except Missing as exc:
        problems.append(str(exc))
        rows.append(("PyPI metadata", "python/pyproject.toml", "?", "UNREADABLE"))
    else:
        if literal is None:
            rows.append(("PyPI metadata", "python/pyproject.toml", how, "must match"))
        else:
            hard["PyPI metadata"] = literal
            rows.append(
                ("PyPI metadata", "python/pyproject.toml", literal, "must match")
            )

    if expect is not None:
        hard["release tag"] = expect.lstrip("v")
        rows.append(("release tag", "--expect", hard["release tag"], "must match"))

    distinct = sorted(set(hard.values()))
    if len(distinct) > 1:
        problems.append(
            "version mismatch across the release-critical set: "
            + ", ".join("%s=%s" % (label, hard[label]) for label in sorted(hard))
        )

    # ---- soft set -------------------------------------------------------
    mcp_pkg = json_key(root, "plugins/mcp-server/package.json", "version")
    rows.append(
        (
            "MCP server",
            "plugins/mcp-server/package.json",
            mcp_pkg or "-",
            "independent",
        )
    )
    manifest_version, manifest_pkg_version = server_json_versions(root)
    rows.append(
        (
            "MCP registry manifest",
            "plugins/mcp-server/server.json",
            manifest_version or "-",
            "tracks MCP server",
        )
    )
    rows.append(
        (
            "MCP registry package",
            "plugins/mcp-server/server.json packages[0]",
            manifest_pkg_version or "-",
            "tracks MCP server",
        )
    )
    if mcp_pkg and {manifest_version, manifest_pkg_version} != {mcp_pkg}:
        warnings.append(
            "server.json (%s / %s) does not track plugins/mcp-server/package.json (%s) "
            "— the MCP registry rejects a package version that is not on npm"
            % (manifest_version or "-", manifest_pkg_version or "-", mcp_pkg)
        )

    rows.append(
        (
            "npm wrapper",
            "package.json",
            json_key(root, "package.json", "version") or "-",
            "set at publish time",
        )
    )
    rows.append(
        (
            "VS Code extension",
            "plugins/vscode/package.json",
            json_key(root, "plugins/vscode/package.json", "version") or "-",
            "independent",
        )
    )
    jb_version, jb_source = jetbrains_version(root)
    rows.append(("JetBrains plugin", jb_source, jb_version or "-", "independent"))

    plugin_version = json_key(
        root, "plugins/claude-code/.claude-plugin/plugin.json", "version"
    )
    marketplace_version = marketplace_plugin_version(root, "sigil-security")
    rows.append(
        (
            "Claude Code plugin",
            "plugins/claude-code/.claude-plugin/plugin.json",
            plugin_version or "-",
            "independent",
        )
    )
    rows.append(
        (
            "Plugin marketplace",
            ".claude-plugin/marketplace.json",
            marketplace_version or "-",
            "tracks Claude Code plugin",
        )
    )
    if plugin_version and marketplace_version and plugin_version != marketplace_version:
        warnings.append(
            "marketplace.json (%s) does not track the Claude Code plugin.json (%s)"
            % (marketplace_version, plugin_version)
        )

    skill_version = json_key(root, "sigil-skill/skill.json", "version")
    rows.append(
        (
            "Skill listing",
            "sigil-skill/skill.json",
            skill_version or "-",
            "independent",
        )
    )
    skill_front = skill_frontmatter_version(root)
    rows.append(
        (
            "Skill front matter",
            "sigil-skill/sigil-scan/SKILL.md",
            skill_front or "-",
            "tracks skill listing",
        )
    )
    if skill_version and skill_front and skill_version != skill_front:
        warnings.append(
            "SKILL.md front matter (%s) does not track sigil-skill/skill.json (%s) "
            "— the hub listing and the installed skill would report different versions"
            % (skill_front, skill_version)
        )

    out = [render_table(rows), ""]
    dist = pyproject_name(root)
    if dist:
        out.append("PyPI distribution name: %s" % dist)
        out.append("")
    for warning in warnings:
        out.append("warning: %s" % warning)
    if warnings:
        out.append("")

    if problems:
        for problem in problems:
            out.append("error: %s" % problem)
        out.append("")
        out.append(
            "FAIL: the release-critical versions must agree. Bump cli/Cargo.toml, "
            "python/src/sigil_cli/__init__.py and python/pyproject.toml together."
        )
        return 1, "\n".join(out)

    out.append(
        "OK: release-critical versions agree (%s)."
        % (distinct[0] if distinct else "none checked")
    )
    return 0, "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--expect",
        metavar="VERSION",
        help="also require this version (a release tag; a leading 'v' is stripped)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to inspect (default: this script's repo)",
    )
    args = parser.parse_args(argv)
    code, report = check(args.root, args.expect)
    print(report)
    return code


if __name__ == "__main__":
    sys.exit(main())
