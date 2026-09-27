"""Tests for scripts/validate_marketplace.py.

Runs under a plain `pytest tests/marketplace` from the repo root: no api/
imports, no database, no network. Every tree built under tmp_path here is a
synthetic fixture invented for the assertion it appears in — none of it is
real scan data or a real plugin.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_marketplace.py"


def _load_validator():
    """Import the script by path; scripts/ is not an importable package."""
    spec = importlib.util.spec_from_file_location("validate_marketplace", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec: @dataclass resolves annotations via sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vm = _load_validator()


# ---------------------------------------------------------------------------
# synthetic fixture builders
# ---------------------------------------------------------------------------

# synthetic fixture: a minimal, deliberately valid marketplace + plugin tree.
MARKETPLACE = {
    "name": "demo-marketplace",
    "description": "A synthetic marketplace used only by these tests.",
    "owner": {"name": "Demo Owner", "url": "https://example.invalid"},
    "plugins": [
        {
            "name": "demo-plugin",
            "source": "./plugins/demo",
            "description": "A synthetic plugin used only by these tests.",
            "version": "1.2.3",
        }
    ],
}

# synthetic fixture: the plugin manifest the entry above points at.
PLUGIN = {
    "name": "demo-plugin",
    "version": "1.2.3",
    "description": "A synthetic plugin used only by these tests.",
    "author": {"name": "Demo Owner"},
    "skills": "./skills/",
    "agents": ["./agents/demo-agent.md"],
    "hooks": "./hooks/hooks.json",
    "mcpServers": {"demo": {"command": "npx", "args": ["-y", "demo"], "env": {}}},
}

# synthetic fixture: a hooks manifest whose command hook points at demo.sh.
HOOKS = {
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "${CLAUDE_PLUGIN_ROOT}/hooks/demo.sh",
                    }
                ],
            }
        ],
        "UserPromptSubmit": [
            {"hooks": [{"type": "prompt", "prompt": "synthetic prompt hook"}]}
        ],
    }
}

SKILL_MD = """---
name: demo-skill
description: A synthetic skill used only by these tests.
allowed-tools: Bash(demo *)
---

# Demo skill
"""

AGENT_MD = """---
name: demo-agent
description: A synthetic agent used only by these tests.
---

You are a synthetic agent.
"""


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_repo(
    tmp_path: Path,
    *,
    marketplace: dict | None = None,
    plugin: dict | None = None,
    hooks: dict | None = None,
    plugin_dir_name: str = "demo",
) -> Path:
    """Build a synthetic repo tree under tmp_path and return its root."""
    root = tmp_path / "repo"
    _write_json(
        root / ".claude-plugin" / "marketplace.json",
        MARKETPLACE if marketplace is None else marketplace,
    )
    plugin_root = root / "plugins" / plugin_dir_name
    _write_json(
        plugin_root / ".claude-plugin" / "plugin.json",
        PLUGIN if plugin is None else plugin,
    )
    _write_text(plugin_root / "skills" / "demo-skill" / "SKILL.md", SKILL_MD)
    _write_text(plugin_root / "agents" / "demo-agent.md", AGENT_MD)
    _write_json(plugin_root / "hooks" / "hooks.json", HOOKS if hooks is None else hooks)
    script = plugin_root / "hooks" / "demo.sh"
    _write_text(script, "#!/usr/bin/env bash\nexit 0\n")
    script.chmod(0o755)
    return root


def messages(problems) -> str:
    return "\n".join(p.render() for p in problems)


def error_paths(result) -> list[str]:
    return [p.json_path for p in result.errors]


# ---------------------------------------------------------------------------
# the regression gate: the real repository
# ---------------------------------------------------------------------------


def test_real_repo_reports_no_errors():
    """The live repo must stay free of ERROR-severity problems."""
    result = vm.validate(REPO_ROOT)
    assert result.errors == [], messages(result.errors)
    assert result.ok is True


def test_real_repo_agents_key_drift_is_reported_while_it_exists():
    """plugin.json `agents` is a directory today; that must be surfaced.

    Written to stay correct after the manifest is fixed: if `agents` no longer
    names a directory, the warning must be gone.
    """
    manifest = json.loads(
        (
            REPO_ROOT / "plugins" / "claude-code" / ".claude-plugin" / "plugin.json"
        ).read_text(encoding="utf-8")
    )
    agents = manifest.get("agents")
    warnings = [w for w in vm.validate(REPO_ROOT).warnings if w.json_path == "$.agents"]
    declares_directory = isinstance(agents, str) and not agents.endswith(".md")
    if declares_directory:
        assert warnings, "the agents-is-a-directory drift must be reported"
    else:
        assert not warnings, messages(warnings)


# ---------------------------------------------------------------------------
# the synthetic baseline
# ---------------------------------------------------------------------------


def test_synthetic_valid_tree_has_no_problems(tmp_path):
    result = vm.validate(build_repo(tmp_path))
    assert result.problems == [], messages(result.problems)


# ---------------------------------------------------------------------------
# marketplace.json
# ---------------------------------------------------------------------------


def test_missing_marketplace_file_is_an_error(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    result = vm.validate(root)
    assert not result.ok
    assert "file does not exist" in messages(result.errors)


def test_malformed_marketplace_json_is_an_error_not_a_traceback(tmp_path):
    root = build_repo(tmp_path)
    # synthetic fixture: truncated JSON.
    (root / ".claude-plugin" / "marketplace.json").write_text(
        '{"name": "demo-marketplace",', encoding="utf-8"
    )
    result = vm.validate(root)
    assert not result.ok
    assert "is not valid JSON" in messages(result.errors)


def test_malformed_plugin_json_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    (root / "plugins" / "demo" / ".claude-plugin" / "plugin.json").write_text(
        "not json at all", encoding="utf-8"
    )
    result = vm.validate(root)
    assert not result.ok
    assert "is not valid JSON" in messages(result.errors)


@pytest.mark.parametrize("missing", ["name", "owner", "plugins"])
def test_marketplace_required_keys(tmp_path, missing):
    market = json.loads(json.dumps(MARKETPLACE))  # synthetic fixture: deep copy
    del market[missing]
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert f"$.{missing}" in error_paths(result), messages(result.errors)


def test_marketplace_name_with_whitespace_is_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["name"] = "demo marketplace"  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.name" in error_paths(result)
    assert "whitespace" in messages(result.errors)


def test_owner_must_be_an_object_with_a_name(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["owner"] = {"url": "https://example.invalid"}  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.owner.name" in error_paths(result)


def test_empty_plugins_array_is_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"] = []
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.plugins" in error_paths(result)


def test_entry_missing_description_is_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    del market["plugins"][0]["description"]
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.plugins[0].description" in error_paths(result)


def test_duplicate_entry_names_are_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"].append(json.loads(json.dumps(market["plugins"][0])))
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "duplicate plugin name" in messages(result.errors)


def test_bad_entry_semver_is_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["version"] = "v1.2"  # synthetic fixture: not semver
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.plugins[0].version" in error_paths(result)
    assert "not valid semver" in messages(result.errors)


def test_bad_plugin_semver_is_an_error(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["version"] = "1.2"  # synthetic fixture: not semver
    market = json.loads(json.dumps(MARKETPLACE))
    del market["plugins"][0]["version"]
    result = vm.validate(build_repo(tmp_path, marketplace=market, plugin=plugin))
    assert "$.version" in error_paths(result)


# ---------------------------------------------------------------------------
# source resolution — the highest-value check
# ---------------------------------------------------------------------------


def test_source_pointing_at_a_missing_directory_is_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["source"] = "./plugins/renamed-away"  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.plugins[0].source" in error_paths(result)
    assert "does not exist in the repository" in messages(result.errors)


def test_source_traversing_out_of_the_repo_is_an_error(tmp_path):
    # This validator runs in CI over unreviewed pull-request content, so a
    # source that walks out of the checkout must be refused, not followed.
    outside = tmp_path / "outside"  # synthetic fixture
    _write_json(
        outside / ".claude-plugin" / "plugin.json",
        {"name": "demo", "version": "1.0.0", "description": "d"},
    )
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["source"] = "./../outside"  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.plugins[0].source" in error_paths(result)
    assert "resolves outside the repository" in messages(result.errors)


def test_source_symlinked_out_of_the_repo_is_an_error(tmp_path):
    # A literal '../' is the obvious case; a symlink is the one that slips past
    # a string-prefix check, which is why containment is tested post-resolve.
    outside = tmp_path / "elsewhere"  # synthetic fixture
    _write_json(
        outside / ".claude-plugin" / "plugin.json",
        {"name": "demo", "version": "1.0.0", "description": "d"},
    )
    root = build_repo(tmp_path)
    link = root / "plugins" / "linked"
    link.symlink_to(outside, target_is_directory=True)
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["source"] = "./plugins/linked"  # synthetic fixture
    _write_json(root / ".claude-plugin" / "marketplace.json", market)
    result = vm.validate(root)
    assert "resolves outside the repository" in messages(result.errors)


def test_source_directory_without_plugin_json_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    (root / "plugins" / "demo" / ".claude-plugin" / "plugin.json").unlink()
    result = vm.validate(root)
    assert "has no .claude-plugin/plugin.json" in messages(result.errors)


def test_string_source_must_be_relative(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["source"] = "https://example.invalid/x.git"  # synthetic
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "relative path starting with './'" in messages(result.errors)


def test_github_object_source_is_accepted(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["source"] = {"source": "github", "repo": "owner/name"}
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert result.errors == [], messages(result.errors)


def test_unknown_object_source_kind_is_an_error(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["source"] = {"source": "git", "url": "x"}  # synthetic
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert "$.plugins[0].source" in error_paths(result)


# ---------------------------------------------------------------------------
# cross-file drift
# ---------------------------------------------------------------------------


def test_version_drift_between_manifests_is_an_error(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["version"] = "9.9.9"  # synthetic fixture: drifted from the entry
    result = vm.validate(build_repo(tmp_path, plugin=plugin))
    assert "$.version" in error_paths(result)
    assert "does not match the marketplace entry version" in messages(result.errors)


def test_name_drift_between_manifests_is_an_error(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["name"] = "renamed-plugin"  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, plugin=plugin))
    assert "$.name" in error_paths(result)
    assert "does not match the marketplace entry name" in messages(result.errors)


def test_description_drift_is_only_a_warning(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["description"] = "A different synthetic description."
    result = vm.validate(build_repo(tmp_path, plugin=plugin))
    assert result.errors == [], messages(result.errors)
    assert [w.json_path for w in result.warnings] == ["$.description"]


def test_missing_marketplace_description_is_a_warning(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    del market["description"]
    result = vm.validate(build_repo(tmp_path, marketplace=market))
    assert result.errors == [], messages(result.errors)
    assert "$.description" in [w.json_path for w in result.warnings]


def test_keyword_and_author_drift_are_warnings(tmp_path):
    market = json.loads(json.dumps(MARKETPLACE))
    market["plugins"][0]["keywords"] = ["a"]  # synthetic fixture
    market["plugins"][0]["author"] = {"name": "Someone Else"}  # synthetic fixture
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["keywords"] = ["a", "b"]
    result = vm.validate(build_repo(tmp_path, marketplace=market, plugin=plugin))
    assert result.errors == [], messages(result.errors)
    assert {"$.keywords", "$.author"} <= {w.json_path for w in result.warnings}


def test_declared_path_that_does_not_resolve_is_an_error(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["skills"] = "./nope/"  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, plugin=plugin))
    assert "$.skills" in error_paths(result)
    assert "does not exist relative to the plugin root" in messages(result.errors)


def test_mcp_servers_must_be_objects_with_a_command(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["mcpServers"] = {"demo": {"args": ["-y"]}}  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, plugin=plugin))
    assert "$.mcpServers.demo.command" in error_paths(result)


# ---------------------------------------------------------------------------
# skills and agents
# ---------------------------------------------------------------------------


def test_skill_directory_without_skill_md_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    # synthetic fixture: a skill folder that forgot its SKILL.md.
    (root / "plugins" / "demo" / "skills" / "orphan-skill").mkdir()
    result = vm.validate(root)
    assert "has no SKILL.md" in messages(result.errors)


def test_skill_name_directory_mismatch_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    skill_md = root / "plugins" / "demo" / "skills" / "demo-skill" / "SKILL.md"
    # synthetic fixture: frontmatter name that no longer matches its folder.
    skill_md.write_text(
        SKILL_MD.replace("name: demo-skill", "name: renamed-skill"), encoding="utf-8"
    )
    result = vm.validate(root)
    assert "does not match 'demo-skill'" in messages(result.errors)


def test_skill_without_frontmatter_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    skill_md = root / "plugins" / "demo" / "skills" / "demo-skill" / "SKILL.md"
    skill_md.write_text("# just a heading\n", encoding="utf-8")  # synthetic fixture
    result = vm.validate(root)
    assert "no YAML frontmatter block" in messages(result.errors)


def test_skill_without_description_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    skill_md = root / "plugins" / "demo" / "skills" / "demo-skill" / "SKILL.md"
    skill_md.write_text(
        "---\nname: demo-skill\n---\n\n# Demo\n", encoding="utf-8"
    )  # synthetic fixture
    result = vm.validate(root)
    assert "missing a 'description' field" in messages(result.errors)


def test_agents_directory_with_no_markdown_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    plugin = json.loads(json.dumps(PLUGIN))
    del plugin["agents"]  # fall back to the conventional agents/ directory
    _write_json(root / "plugins" / "demo" / ".claude-plugin" / "plugin.json", plugin)
    (root / "plugins" / "demo" / "agents" / "demo-agent.md").unlink()
    result = vm.validate(root)
    assert "no .md files" in messages(result.errors)


def test_agent_without_frontmatter_description_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    agent = root / "plugins" / "demo" / "agents" / "demo-agent.md"
    agent.write_text(
        "---\nname: demo-agent\n---\n\nbody\n", encoding="utf-8"
    )  # synthetic fixture
    result = vm.validate(root)
    assert "missing a 'description' field" in messages(result.errors)


def test_agents_directory_entry_is_warned_about(tmp_path):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["agents"] = "./agents/"  # synthetic fixture: the live repo's shape
    result = vm.validate(build_repo(tmp_path, plugin=plugin))
    assert result.errors == [], messages(result.errors)
    assert "$.agents" in [w.json_path for w in result.warnings]


# ---------------------------------------------------------------------------
# hooks
# ---------------------------------------------------------------------------


def test_dangling_hook_command_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    (root / "plugins" / "demo" / "hooks" / "demo.sh").unlink()  # synthetic fixture
    result = vm.validate(root)
    assert "does not exist in the plugin" in messages(result.errors)


def test_non_executable_hook_script_is_an_error(tmp_path):
    root = build_repo(tmp_path)
    (root / "plugins" / "demo" / "hooks" / "demo.sh").chmod(0o644)
    result = vm.validate(root)
    if os.geteuid() == 0 and os.access(
        root / "plugins" / "demo" / "hooks" / "demo.sh", os.X_OK
    ):
        pytest.skip("running as root: os.access(X_OK) ignores the mode bits")
    assert "is not executable" in messages(result.errors)


def test_hook_group_without_hooks_array_is_an_error(tmp_path):
    hooks = {"hooks": {"PreToolUse": [{"matcher": "Bash"}]}}  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, hooks=hooks))
    assert "$.hooks.PreToolUse[0].hooks" in error_paths(result)


def test_unknown_hook_type_is_an_error(tmp_path):
    # synthetic fixture: a hook type the runtime cannot load.
    hooks = {"hooks": {"PreToolUse": [{"hooks": [{"type": "deny"}]}]}}
    result = vm.validate(build_repo(tmp_path, hooks=hooks))
    assert "unknown hook type 'deny'" in messages(result.errors)


def test_command_hook_without_command_is_an_error(tmp_path):
    hooks = {"hooks": {"Stop": [{"hooks": [{"type": "command"}]}]}}  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, hooks=hooks))
    assert "$.hooks.Stop[0].hooks[0].command" in error_paths(result)


def test_prompt_hook_without_prompt_is_an_error(tmp_path):
    hooks = {"hooks": {"Stop": [{"hooks": [{"type": "prompt"}]}]}}  # synthetic fixture
    result = vm.validate(build_repo(tmp_path, hooks=hooks))
    assert "$.hooks.Stop[0].hooks[0].prompt" in error_paths(result)


def test_unknown_hook_event_is_a_warning(tmp_path):
    # synthetic fixture: an event name the runtime does not recognise.
    hooks = {
        "hooks": {"BeforeSubmit": [{"hooks": [{"type": "prompt", "prompt": "x"}]}]}
    }
    result = vm.validate(build_repo(tmp_path, hooks=hooks))
    assert result.errors == [], messages(result.errors)
    assert "not a recognised hook event" in messages(result.warnings)


def test_missing_hooks_key_in_hooks_json_is_an_error(tmp_path):
    hooks = {"PreToolUse": []}  # synthetic fixture: events at the top level
    result = vm.validate(build_repo(tmp_path, hooks=hooks))
    assert "$.hooks" in error_paths(result)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_main_exit_codes_and_json_output(tmp_path, capsys):
    root = build_repo(tmp_path)
    assert vm.main(["--repo-root", str(root)]) == 0
    capsys.readouterr()

    assert vm.main(["--repo-root", str(root), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"ok": True, "errors": [], "warnings": []}

    (root / "plugins" / "demo" / "hooks" / "demo.sh").unlink()  # synthetic fixture
    assert vm.main(["--repo-root", str(root), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["warnings"] == []
    assert len(payload["errors"]) == 1
    problem = payload["errors"][0]
    assert set(problem) == {"severity", "file", "json_path", "message"}
    assert problem["severity"] == "ERROR"
    assert problem["file"] == "plugins/demo/hooks/hooks.json"


def test_strict_turns_warnings_into_failure(tmp_path, capsys):
    plugin = json.loads(json.dumps(PLUGIN))
    plugin["description"] = "A drifted synthetic description."
    root = build_repo(tmp_path, plugin=plugin)
    assert vm.main(["--repo-root", str(root)]) == 0
    assert vm.main(["--repo-root", str(root), "--strict"]) == 1
    out = capsys.readouterr().out
    assert "WARN plugins/demo/.claude-plugin/plugin.json [$.description]" in out


def test_bad_repo_root_exits_two(tmp_path, capsys):
    assert vm.main(["--repo-root", str(tmp_path / "nope")]) == 2
    assert "is not a directory" in capsys.readouterr().err
