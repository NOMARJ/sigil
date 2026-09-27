#!/usr/bin/env python3
"""Validate the Claude Code marketplace and plugin manifests in this repo.

Structural validation of .claude-plugin/marketplace.json, every plugin.json it
points at, and that plugin's skills, agents and hooks. Replaces the ad-hoc
existence checks in .github/workflows/publish-plugin.yml so a renamed plugin
directory, a version drift or a dangling hook script fails a pull request
instead of a release tag.

Usage:
    python3 scripts/validate_marketplace.py [--repo-root PATH] [--json] [--strict]

Exit codes:
    0 - no ERROR-severity problems (and, under --strict, no WARNs either)
    1 - at least one ERROR (or, under --strict, at least one WARN)
    2 - the validator could not run at all (unusable --repo-root)

Standard library only: this runs on a bare python in CI.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ERROR = "ERROR"
WARN = "WARN"

MARKETPLACE_RELPATH = ".claude-plugin/marketplace.json"
PLUGIN_MANIFEST_RELPATH = ".claude-plugin/plugin.json"

# Kebab-ish name accepted by the Claude Code loader: starts alphanumeric,
# then letters, digits, ".", "_", "-".
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Official semver.org 2.0.0 pattern.
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

PLUGIN_ROOT_VAR = "${CLAUDE_PLUGIN_ROOT}"

# Hook events the runtime recognises. An unrecognised event is loaded as
# nothing at all, so it is reported rather than ignored.
VALID_HOOK_EVENTS = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "Notification",
        "Stop",
        "SubagentStop",
        "SubagentStart",
        "PreCompact",
        "PostCompact",
        "SessionStart",
        "SessionEnd",
        "PermissionRequest",
        "Setup",
        "FileChanged",
        "TaskCompleted",
    }
)

VALID_HOOK_TYPES = frozenset({"command", "prompt", "agent"})

# The field each hook type cannot load without.
HOOK_TYPE_REQUIRED_FIELD = {"command": "command", "prompt": "prompt"}

# `claude plugin validate` treats a non-".md" entry in plugin.json `agents` as a
# hard error. It is reported here as a WARN so this gate stays additive to the
# checks in the fixed contract; flip this to ERROR once the manifest is fixed.
AGENTS_MUST_BE_MD_SEVERITY = WARN


@dataclass(frozen=True)
class Problem:
    """A single validation finding, anchored to a file and a JSON path."""

    severity: str
    file: str
    json_path: str
    message: str

    def render(self) -> str:
        """One human-readable line for CI logs."""
        return f"{self.severity} {self.file} [{self.json_path}]: {self.message}"

    def to_dict(self) -> dict[str, str]:
        """Plain dict for --json output."""
        return {
            "severity": self.severity,
            "file": self.file,
            "json_path": self.json_path,
            "message": self.message,
        }


@dataclass
class ValidationResult:
    """Every problem found by one validate() run, in discovery order."""

    problems: list[Problem] = field(default_factory=list)

    @property
    def errors(self) -> list[Problem]:
        return [p for p in self.problems if p.severity == ERROR]

    @property
    def warnings(self) -> list[Problem]:
        return [p for p in self.problems if p.severity == WARN]

    @property
    def ok(self) -> bool:
        """True when nothing ERROR-severity was found."""
        return not self.errors

    def ok_under(self, strict: bool) -> bool:
        """True when this run should exit 0 for the given strictness."""
        if strict:
            return not self.problems
        return self.ok

    def add(self, severity: str, file: str, json_path: str, message: str) -> None:
        self.problems.append(Problem(severity, file, json_path, message))


class _Context:
    """Path bookkeeping plus the problem list, threaded through the checks."""

    def __init__(self, repo_root: Path, result: ValidationResult) -> None:
        self.repo_root = repo_root
        self.result = result

    def rel(self, path: Path) -> str:
        """Repo-relative POSIX path, so CI output is copy-pasteable."""
        try:
            return path.resolve().relative_to(self.repo_root).as_posix()
        except ValueError:
            return path.as_posix()

    def error(self, path: Path, json_path: str, message: str) -> None:
        self.result.add(ERROR, self.rel(path), json_path, message)

    def warn(self, path: Path, json_path: str, message: str) -> None:
        self.result.add(WARN, self.rel(path), json_path, message)

    def report(self, severity: str, path: Path, json_path: str, message: str) -> None:
        self.result.add(severity, self.rel(path), json_path, message)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _load_json(ctx: _Context, path: Path, json_path: str) -> Any | None:
    """Read and parse a JSON file, reporting every failure mode as an ERROR."""
    if not path.exists():
        ctx.error(path, json_path, "file does not exist")
        return None
    if not path.is_file():
        ctx.error(path, json_path, "expected a file, found a directory")
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        ctx.error(path, json_path, f"cannot be read: {exc.strerror or exc}")
        return None
    except UnicodeDecodeError as exc:
        ctx.error(path, json_path, f"is not valid UTF-8: {exc}")
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        ctx.error(
            path,
            json_path,
            f"is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})",
        )
        return None


def _require_str(
    ctx: _Context, path: Path, obj: dict[str, Any], key: str, json_path: str
) -> str | None:
    """Require a present, non-empty string value at obj[key]."""
    if key not in obj:
        ctx.error(path, json_path, f"required key '{key}' is missing")
        return None
    value = obj[key]
    if not isinstance(value, str):
        ctx.error(
            path, json_path, f"'{key}' must be a string, found {_typename(value)}"
        )
        return None
    if not value.strip():
        ctx.error(path, json_path, f"'{key}' must not be empty")
        return None
    return value


def _is_contained(path: Path, root: Path) -> bool:
    """True when an already-resolved path lies inside root.

    Both arguments must already be ``.resolve()``d, so this also catches a
    symlink that points out of the tree, not just a literal '../' in the
    manifest.
    """
    return path == root or root in path.parents


def _typename(value: Any) -> str:
    """JSON-flavoured type name for messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _as_path_list(value: Any) -> list[str] | None:
    """plugin.json path keys accept a string or an array of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def read_frontmatter(path: Path) -> tuple[dict[str, str] | None, str | None]:
    """Parse the leading '---' YAML frontmatter of a Markdown file.

    Deliberately tiny and dependency-free: PyYAML is not guaranteed present in
    CI. Only top-level `key: value` scalars are read, which is all the plugin
    manifests use. Returns (mapping, error_message); exactly one is not None.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"cannot be read: {exc.strerror or exc}"
    except UnicodeDecodeError as exc:
        return None, f"is not valid UTF-8: {exc}"

    lines = text.splitlines()
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1
    if start >= len(lines) or lines[start].strip() != "---":
        return None, "has no YAML frontmatter block (expected '---' on the first line)"

    fields: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if line.strip() == "---":
            return fields, None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace():
            # Continuation / nested value: not needed by any manifest key.
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        fields[key.strip()] = _strip_quotes(value.strip())
    return None, "frontmatter block is not closed (missing the second '---')"


def _strip_quotes(value: str) -> str:
    """Remove one layer of matching quotes from a scalar."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _check_frontmatter_doc(
    ctx: _Context,
    path: Path,
    json_path: str,
    kind: str,
    expected_name: str | None,
    name_mismatch_severity: str,
) -> None:
    """Shared frontmatter checks for SKILL.md and agent .md files."""
    fields, err = read_frontmatter(path)
    if fields is None:
        ctx.error(path, json_path, f"{kind} {err}")
        return
    name = fields.get("name", "").strip()
    if not name:
        ctx.error(path, json_path, f"{kind} frontmatter is missing a 'name' field")
    elif expected_name is not None and name != expected_name:
        ctx.report(
            name_mismatch_severity,
            path,
            json_path,
            f"{kind} frontmatter name '{name}' does not match '{expected_name}'",
        )
    if not fields.get("description", "").strip():
        ctx.error(
            path, json_path, f"{kind} frontmatter is missing a 'description' field"
        )


# --------------------------------------------------------------------------
# marketplace.json
# --------------------------------------------------------------------------


def validate(repo_root: Path) -> ValidationResult:
    """Validate the marketplace and every plugin it declares.

    Collects all problems; never raises on malformed input and never stops at
    the first failure.
    """
    result = ValidationResult()
    repo_root = repo_root.resolve()
    ctx = _Context(repo_root, result)

    marketplace_path = repo_root / MARKETPLACE_RELPATH
    data = _load_json(ctx, marketplace_path, "$")
    if data is None:
        return result
    if not isinstance(data, dict):
        ctx.error(
            marketplace_path,
            "$",
            f"top level must be an object, found {_typename(data)}",
        )
        return result

    name = _require_str(ctx, marketplace_path, data, "name", "$.name")
    if name is not None:
        if any(ch.isspace() for ch in name):
            ctx.error(
                marketplace_path,
                "$.name",
                f"marketplace name '{name}' must not contain whitespace",
            )
        elif not NAME_RE.match(name):
            ctx.warn(
                marketplace_path,
                "$.name",
                f"marketplace name '{name}' is not kebab-case "
                "(lowercase alphanumeric start, then letters, digits, '.', '_', '-')",
            )

    owner = data.get("owner")
    if "owner" not in data:
        ctx.error(marketplace_path, "$.owner", "required key 'owner' is missing")
    elif not isinstance(owner, dict):
        ctx.error(
            marketplace_path,
            "$.owner",
            f"'owner' must be an object, found {_typename(owner)}",
        )
    else:
        _require_str(ctx, marketplace_path, owner, "name", "$.owner.name")

    if not isinstance(data.get("description"), str) or not data["description"].strip():
        ctx.warn(
            marketplace_path,
            "$.description",
            "no marketplace description provided; it is what users see when "
            "browsing the marketplace",
        )

    plugins = data.get("plugins")
    if "plugins" not in data:
        ctx.error(marketplace_path, "$.plugins", "required key 'plugins' is missing")
        return result
    if not isinstance(plugins, list):
        ctx.error(
            marketplace_path,
            "$.plugins",
            f"'plugins' must be an array, found {_typename(plugins)}",
        )
        return result
    if not plugins:
        ctx.error(marketplace_path, "$.plugins", "'plugins' must not be empty")
        return result

    seen: dict[str, int] = {}
    for index, entry in enumerate(plugins):
        _validate_entry(ctx, marketplace_path, entry, index, seen)

    return result


def _validate_entry(
    ctx: _Context,
    marketplace_path: Path,
    entry: Any,
    index: int,
    seen: dict[str, int],
) -> None:
    """Validate one marketplace plugin entry and the plugin it points at."""
    base = f"$.plugins[{index}]"
    if not isinstance(entry, dict):
        ctx.error(
            marketplace_path,
            base,
            f"plugin entry must be an object, found {_typename(entry)}",
        )
        return

    name = _require_str(ctx, marketplace_path, entry, "name", f"{base}.name")
    if name is not None:
        if any(ch.isspace() for ch in name):
            ctx.error(
                marketplace_path,
                f"{base}.name",
                f"plugin name '{name}' must not contain whitespace",
            )
        elif not NAME_RE.match(name):
            ctx.error(
                marketplace_path,
                f"{base}.name",
                f"plugin name '{name}' is not a valid plugin name "
                "(lowercase alphanumeric start, then letters, digits, '.', '_', '-')",
            )
        if name in seen:
            ctx.error(
                marketplace_path,
                f"{base}.name",
                f"duplicate plugin name '{name}' (already declared at "
                f"$.plugins[{seen[name]}])",
            )
        else:
            seen[name] = index

    _require_str(ctx, marketplace_path, entry, "description", f"{base}.description")

    version = entry.get("version")
    if "version" in entry:
        if not isinstance(version, str):
            ctx.error(
                marketplace_path,
                f"{base}.version",
                f"'version' must be a string, found {_typename(version)}",
            )
            version = None
        elif not SEMVER_RE.match(version):
            ctx.error(
                marketplace_path,
                f"{base}.version",
                f"version '{version}' is not valid semver (MAJOR.MINOR.PATCH)",
            )

    plugin_dir = _resolve_source(ctx, marketplace_path, entry, index)
    if plugin_dir is None:
        return

    _validate_plugin(
        ctx,
        plugin_dir,
        entry=entry,
        entry_name=name,
        entry_version=version if isinstance(version, str) else None,
        marketplace_path=marketplace_path,
        base=base,
    )


def _resolve_source(
    ctx: _Context, marketplace_path: Path, entry: dict[str, Any], index: int
) -> Path | None:
    """Resolve a plugin entry's `source` to a local directory, if it is local.

    Returns the plugin directory when the source is a relative path that
    resolves to a real plugin; None when it is remote or unusable.
    """
    json_path = f"$.plugins[{index}].source"
    if "source" not in entry:
        ctx.error(marketplace_path, json_path, "required key 'source' is missing")
        return None
    source = entry["source"]

    if isinstance(source, dict):
        kind = source.get("source")
        if kind == "github":
            if not isinstance(source.get("repo"), str) or not source["repo"].strip():
                ctx.error(
                    marketplace_path,
                    json_path,
                    "a github source requires a non-empty 'repo' string",
                )
        elif kind == "url":
            if not isinstance(source.get("url"), str) or not source["url"].strip():
                ctx.error(
                    marketplace_path,
                    json_path,
                    "a url source requires a non-empty 'url' string",
                )
        else:
            ctx.error(
                marketplace_path,
                json_path,
                'an object source must set \'source\' to "github" or "url", '
                f"found {kind!r}",
            )
        return None

    if not isinstance(source, str):
        ctx.error(
            marketplace_path,
            json_path,
            f"'source' must be a string or an object, found {_typename(source)}",
        )
        return None
    if not source.strip():
        ctx.error(marketplace_path, json_path, "'source' must not be empty")
        return None
    if not source.startswith("./"):
        ctx.error(
            marketplace_path,
            json_path,
            f"a string source must be a relative path starting with './', "
            f"found '{source}'",
        )
        return None

    plugin_dir = (ctx.repo_root / source).resolve()
    rel = source.rstrip("/")
    if not _is_contained(plugin_dir, ctx.repo_root):
        # './../secrets' or a symlink out of the tree. This validator runs in CI
        # on unreviewed pull-request content, so a source that walks out of the
        # checkout is refused rather than followed — otherwise the job reads and
        # reports on paths outside the repository.
        ctx.error(
            marketplace_path,
            json_path,
            f"source '{rel}' resolves outside the repository",
        )
        return None
    if not plugin_dir.exists():
        ctx.error(
            marketplace_path,
            json_path,
            f"source directory '{rel}' does not exist in the repository",
        )
        return None
    if not plugin_dir.is_dir():
        ctx.error(
            marketplace_path,
            json_path,
            f"source '{rel}' is not a directory",
        )
        return None
    if not (plugin_dir / PLUGIN_MANIFEST_RELPATH).is_file():
        ctx.error(
            marketplace_path,
            json_path,
            f"source directory '{rel}' has no {PLUGIN_MANIFEST_RELPATH}",
        )
        return None
    return plugin_dir


# --------------------------------------------------------------------------
# plugin.json
# --------------------------------------------------------------------------


def _validate_plugin(
    ctx: _Context,
    plugin_dir: Path,
    entry: dict[str, Any],
    entry_name: str | None,
    entry_version: str | None,
    marketplace_path: Path,
    base: str,
) -> None:
    """Validate one plugin.json and the assets it declares."""
    manifest_path = plugin_dir / PLUGIN_MANIFEST_RELPATH
    data = _load_json(ctx, manifest_path, "$")
    if data is None:
        return
    if not isinstance(data, dict):
        ctx.error(
            manifest_path, "$", f"top level must be an object, found {_typename(data)}"
        )
        return

    name = _require_str(ctx, manifest_path, data, "name", "$.name")
    if name is not None and entry_name is not None and name != entry_name:
        ctx.error(
            manifest_path,
            "$.name",
            f"plugin name '{name}' does not match the marketplace entry name "
            f"'{entry_name}' ({ctx.rel(marketplace_path)} {base}.name)",
        )

    version = _require_str(ctx, manifest_path, data, "version", "$.version")
    if version is not None:
        if not SEMVER_RE.match(version):
            ctx.error(
                manifest_path,
                "$.version",
                f"version '{version}' is not valid semver (MAJOR.MINOR.PATCH)",
            )
        elif entry_version is not None and version != entry_version:
            ctx.error(
                manifest_path,
                "$.version",
                f"version '{version}' does not match the marketplace entry version "
                f"'{entry_version}' ({ctx.rel(marketplace_path)} {base}.version); "
                "update both files together",
            )

    description = _require_str(ctx, manifest_path, data, "description", "$.description")
    entry_description = entry.get("description")
    if (
        description is not None
        and isinstance(entry_description, str)
        and description != entry_description
    ):
        ctx.warn(
            manifest_path,
            "$.description",
            "description differs from the marketplace entry description "
            f"({ctx.rel(marketplace_path)} {base}.description)",
        )

    if (
        "keywords" in data
        and "keywords" in entry
        and data["keywords"] != entry["keywords"]
    ):
        ctx.warn(
            manifest_path,
            "$.keywords",
            "keywords differ from the marketplace entry keywords "
            f"({ctx.rel(marketplace_path)} {base}.keywords)",
        )

    if "author" in data and "author" in entry and data["author"] != entry["author"]:
        ctx.warn(
            manifest_path,
            "$.author",
            "author differs from the marketplace entry author "
            f"({ctx.rel(marketplace_path)} {base}.author)",
        )

    if "author" in data and not isinstance(data["author"], dict):
        ctx.error(
            manifest_path,
            "$.author",
            f"'author' must be an object, found {_typename(data['author'])}",
        )

    skill_roots = _validate_path_key(ctx, manifest_path, plugin_dir, data, "skills")
    agent_targets = _validate_path_key(ctx, manifest_path, plugin_dir, data, "agents")
    _validate_path_key(ctx, manifest_path, plugin_dir, data, "hooks")
    _validate_path_key(ctx, manifest_path, plugin_dir, data, "commands")

    _validate_mcp_servers(ctx, manifest_path, data)

    _validate_skills(ctx, plugin_dir, skill_roots)
    _validate_agents(ctx, plugin_dir, agent_targets)
    _validate_hooks(ctx, plugin_dir, data.get("hooks"))


def _validate_path_key(
    ctx: _Context,
    manifest_path: Path,
    plugin_dir: Path,
    data: dict[str, Any],
    key: str,
) -> list[Path]:
    """Check that a plugin.json path key resolves; return the resolved paths."""
    if key not in data:
        return []
    value = data[key]
    if key == "hooks" and isinstance(value, dict):
        # An inline hooks object is legal in place of a path.
        return []
    if key == "mcpServers" and isinstance(value, dict):
        return []
    entries = _as_path_list(value)
    if entries is None:
        ctx.error(
            manifest_path,
            f"$.{key}",
            f"'{key}' must be a string or an array of strings, "
            f"found {_typename(value)}",
        )
        return []

    resolved: list[Path] = []
    for index, item in enumerate(entries):
        json_path = f"$.{key}" if isinstance(value, str) else f"$.{key}[{index}]"
        target = (plugin_dir / item).resolve()
        if not _is_contained(target, ctx.repo_root):
            ctx.error(
                manifest_path,
                json_path,
                f"'{item}' resolves outside the repository",
            )
            continue
        if not target.exists():
            ctx.error(
                manifest_path,
                json_path,
                f"'{item}' does not exist relative to the plugin root "
                f"({ctx.rel(plugin_dir)})",
            )
            continue
        if key == "agents" and target.is_dir():
            ctx.report(
                AGENTS_MUST_BE_MD_SEVERITY,
                manifest_path,
                json_path,
                f"'{item}' is a directory; `claude plugin validate` requires every "
                'agents entry to end in ".md" (list the agent files explicitly)',
            )
        resolved.append(target)
    return resolved


def _validate_mcp_servers(
    ctx: _Context, manifest_path: Path, data: dict[str, Any]
) -> None:
    """mcpServers must be {name: {command, args?, env?}} (or a path string)."""
    if "mcpServers" not in data:
        return
    value = data["mcpServers"]
    if isinstance(value, str):
        return
    if not isinstance(value, dict):
        ctx.error(
            manifest_path,
            "$.mcpServers",
            f"'mcpServers' must be an object or a path string, "
            f"found {_typename(value)}",
        )
        return
    for server_name, config in value.items():
        json_path = f"$.mcpServers.{server_name}"
        if not isinstance(config, dict):
            ctx.error(
                manifest_path,
                json_path,
                f"server config must be an object, found {_typename(config)}",
            )
            continue
        command = config.get("command")
        if not isinstance(command, str) or not command.strip():
            ctx.error(
                manifest_path,
                f"{json_path}.command",
                "server config requires a non-empty 'command' string",
            )
        if "args" in config and (
            not isinstance(config["args"], list)
            or not all(isinstance(a, str) for a in config["args"])
        ):
            ctx.error(
                manifest_path,
                f"{json_path}.args",
                "'args' must be an array of strings",
            )
        if "env" in config:
            env = config["env"]
            if not isinstance(env, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in env.items()
            ):
                ctx.error(
                    manifest_path,
                    f"{json_path}.env",
                    "'env' must be an object of string values",
                )


# --------------------------------------------------------------------------
# skills / agents
# --------------------------------------------------------------------------


def _default_dir(plugin_dir: Path, declared: Iterable[Path], name: str) -> list[Path]:
    """Fall back to the conventional <plugin>/<name>/ directory."""
    dirs = [p for p in declared if p.is_dir()]
    if dirs:
        return dirs
    candidate = plugin_dir / name
    return [candidate] if candidate.is_dir() else []


def _validate_skills(ctx: _Context, plugin_dir: Path, declared: list[Path]) -> None:
    """Every skill directory needs a SKILL.md whose frontmatter matches it."""
    for skills_dir in _default_dir(plugin_dir, declared, "skills"):
        subdirs = sorted(p for p in skills_dir.iterdir() if p.is_dir())
        if not subdirs:
            ctx.warn(
                skills_dir,
                "$",
                "skills directory contains no skill subdirectories",
            )
        for skill_dir in subdirs:
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                ctx.error(
                    skill_dir,
                    "$",
                    f"skill directory '{skill_dir.name}' has no SKILL.md",
                )
                continue
            _check_frontmatter_doc(
                ctx,
                skill_md,
                "$",
                kind="skill",
                expected_name=skill_dir.name,
                name_mismatch_severity=ERROR,
            )


def _validate_agents(ctx: _Context, plugin_dir: Path, declared: list[Path]) -> None:
    """The agents directory must hold at least one .md, each with frontmatter."""
    agent_files = sorted(p for p in declared if p.is_file() and p.suffix == ".md")
    for agents_dir in _default_dir(plugin_dir, declared, "agents"):
        found = sorted(agents_dir.glob("*.md"))
        if not found:
            ctx.error(agents_dir, "$", "agents directory contains no .md files")
        agent_files.extend(found)

    if not agent_files:
        ctx.error(plugin_dir / "agents", "$", "no agent .md files were found")
        return

    for agent_md in sorted(set(agent_files)):
        _check_frontmatter_doc(
            ctx,
            agent_md,
            "$",
            kind="agent",
            expected_name=agent_md.stem,
            name_mismatch_severity=WARN,
        )


# --------------------------------------------------------------------------
# hooks.json
# --------------------------------------------------------------------------


def _validate_hooks(ctx: _Context, plugin_dir: Path, hooks_value: Any) -> None:
    """Validate the hooks manifest shape and every command script it names."""
    if isinstance(hooks_value, dict):
        # Inline hooks object: validated in place, no file to read.
        _validate_hooks_mapping(
            ctx,
            plugin_dir / PLUGIN_MANIFEST_RELPATH,
            plugin_dir,
            hooks_value,
            "$.hooks",
        )
        return

    paths = _as_path_list(hooks_value) if hooks_value is not None else None
    if paths is None:
        candidate = plugin_dir / "hooks" / "hooks.json"
        paths = [os.path.relpath(candidate, plugin_dir)] if candidate.is_file() else []

    for item in paths:
        hooks_path = (plugin_dir / item).resolve()
        if not hooks_path.is_file():
            # Already reported by _validate_path_key.
            continue
        data = _load_json(ctx, hooks_path, "$")
        if data is None:
            continue
        if not isinstance(data, dict):
            ctx.error(
                hooks_path, "$", f"top level must be an object, found {_typename(data)}"
            )
            continue
        mapping = data.get("hooks")
        if "hooks" not in data:
            ctx.error(hooks_path, "$.hooks", "required key 'hooks' is missing")
            continue
        if not isinstance(mapping, dict):
            ctx.error(
                hooks_path,
                "$.hooks",
                f"'hooks' must be an object, found {_typename(mapping)}",
            )
            continue
        _validate_hooks_mapping(ctx, hooks_path, plugin_dir, mapping, "$.hooks")


def _validate_hooks_mapping(
    ctx: _Context,
    hooks_path: Path,
    plugin_dir: Path,
    mapping: dict[str, Any],
    base: str,
) -> None:
    """Validate {Event: [ {matcher?, hooks: [entry, ...]} ]}."""
    for event, groups in mapping.items():
        event_path = f"{base}.{event}"
        if event not in VALID_HOOK_EVENTS:
            ctx.warn(
                hooks_path,
                event_path,
                f"'{event}' is not a recognised hook event; it is ignored at runtime",
            )
        if not isinstance(groups, list):
            ctx.error(
                hooks_path,
                event_path,
                f"event must map to an array of matcher groups, "
                f"found {_typename(groups)}",
            )
            continue
        for g_index, group in enumerate(groups):
            group_path = f"{event_path}[{g_index}]"
            if not isinstance(group, dict):
                ctx.error(
                    hooks_path,
                    group_path,
                    f"matcher group must be an object, found {_typename(group)}",
                )
                continue
            if "matcher" in group:
                matcher = group["matcher"]
                if not isinstance(matcher, str):
                    ctx.error(
                        hooks_path,
                        f"{group_path}.matcher",
                        f"'matcher' must be a string, found {_typename(matcher)}",
                    )
                else:
                    try:
                        re.compile(matcher)
                    except re.error as exc:
                        ctx.warn(
                            hooks_path,
                            f"{group_path}.matcher",
                            f"'{matcher}' is not a valid regular expression: {exc}",
                        )
            entries = group.get("hooks")
            if "hooks" not in group:
                ctx.error(
                    hooks_path,
                    f"{group_path}.hooks",
                    "matcher group is missing its 'hooks' array",
                )
                continue
            if not isinstance(entries, list):
                ctx.error(
                    hooks_path,
                    f"{group_path}.hooks",
                    f"'hooks' must be an array of hook entries, "
                    f"found {_typename(entries)}",
                )
                continue
            if not entries:
                ctx.warn(
                    hooks_path, f"{group_path}.hooks", "matcher group has no hooks"
                )
            for h_index, entry in enumerate(entries):
                _validate_hook_entry(
                    ctx,
                    hooks_path,
                    plugin_dir,
                    entry,
                    f"{group_path}.hooks[{h_index}]",
                )


def _validate_hook_entry(
    ctx: _Context,
    hooks_path: Path,
    plugin_dir: Path,
    entry: Any,
    json_path: str,
) -> None:
    """Validate one hook entry and, for command hooks, the script it runs."""
    if not isinstance(entry, dict):
        ctx.error(
            hooks_path,
            json_path,
            f"hook entry must be an object, found {_typename(entry)}",
        )
        return
    hook_type = entry.get("type")
    if not isinstance(hook_type, str) or not hook_type:
        ctx.error(
            hooks_path, f"{json_path}.type", "hook entry is missing its 'type' string"
        )
        return
    if hook_type not in VALID_HOOK_TYPES:
        ctx.error(
            hooks_path,
            f"{json_path}.type",
            f"unknown hook type '{hook_type}' (expected one of "
            f"{', '.join(sorted(VALID_HOOK_TYPES))})",
        )
        return

    required = HOOK_TYPE_REQUIRED_FIELD.get(hook_type)
    if required is not None:
        value = entry.get(required)
        if not isinstance(value, str) or not value.strip():
            ctx.error(
                hooks_path,
                f"{json_path}.{required}",
                f"a '{hook_type}' hook requires a non-empty '{required}' string",
            )
            return
        if hook_type == "command":
            _validate_hook_command(
                ctx, hooks_path, plugin_dir, value, f"{json_path}.command"
            )


def _validate_hook_command(
    ctx: _Context,
    hooks_path: Path,
    plugin_dir: Path,
    command: str,
    json_path: str,
) -> None:
    """A ${CLAUDE_PLUGIN_ROOT}-rooted command must exist and be runnable."""
    if PLUGIN_ROOT_VAR not in command:
        return
    # The script is the first ${CLAUDE_PLUGIN_ROOT}-rooted token of the command.
    remainder = command.split(PLUGIN_ROOT_VAR, 1)[1]
    relative = remainder.split()[0].lstrip("/") if remainder.split() else ""
    if not relative:
        ctx.error(
            hooks_path,
            json_path,
            f"command references {PLUGIN_ROOT_VAR} without a script path",
        )
        return
    script = (plugin_dir / relative).resolve()
    if not script.is_file():
        ctx.error(
            hooks_path,
            json_path,
            f"hook command script '{relative}' does not exist in the plugin "
            f"({ctx.rel(plugin_dir)})",
        )
        return
    if script.suffix in (".sh", ".bash") and not os.access(script, os.X_OK):
        ctx.error(
            hooks_path,
            json_path,
            f"hook command script '{relative}' is not executable (chmod +x)",
        )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = argparse.ArgumentParser(
        description="Validate the Claude Code marketplace and plugin manifests."
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="repository root to validate (default: the repo containing this script)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit a single JSON object on stdout"
    )
    parser.add_argument(
        "--strict", action="store_true", help="treat warnings as failures"
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root)
    if not repo_root.is_dir():
        print(
            f"ERROR --repo-root '{args.repo_root}' is not a directory", file=sys.stderr
        )
        return 2

    result = validate(repo_root)
    ok = result.ok_under(args.strict)

    if args.json:
        payload = {
            "ok": ok,
            "errors": [p.to_dict() for p in result.errors],
            "warnings": [p.to_dict() for p in result.warnings],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if ok else 1

    for problem in result.problems:
        print(problem.render())
    print(
        f"validate_marketplace: {len(result.errors)} error(s), "
        f"{len(result.warnings)} warning(s) "
        f"— {'PASS' if ok else 'FAIL'}"
        f"{' (strict)' if args.strict else ''}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
