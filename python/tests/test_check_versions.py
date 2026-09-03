"""Offline unit tests for scripts/check_versions.py.

Standard library only — the script is a release gate that runs before any
dependency is installed, so its test suite may not need one either.

Run with:  python3 -m pytest python/tests -q
       or  python3 -m unittest discover -s python/tests
"""

import importlib.util
import json
import os
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "check_versions.py")

# scripts/ is not a package, so load the module from its path.
_spec = importlib.util.spec_from_file_location("sigil_check_versions", SCRIPT)
check_versions = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_versions)


PYPROJECT_DYNAMIC = """\
[build-system]
requires = ["setuptools>=61"]

[project]
name = "sigilsec"
dynamic = ["version"]
description = "wrapper"

[tool.setuptools.dynamic]
version = { attr = "sigil_cli.__version__" }
"""

CARGO = """\
[package]
name = "sigil-cli"
version = "%s"
edition = "2021"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = "1"

[[bin]]
name = "sigil"
path = "src/main.rs"
"""


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)


def fake_repo(root, cargo="1.3.6", dunder="1.3.6", pyproject=PYPROJECT_DYNAMIC):
    """Minimal tree with only the release-critical files present."""
    write(os.path.join(root, "cli", "Cargo.toml"), CARGO % cargo)
    write(
        os.path.join(root, "python", "src", "sigil_cli", "__init__.py"),
        '"""doc."""\n\n__version__ = "%s"\n' % dunder,
    )
    write(os.path.join(root, "python", "pyproject.toml"), pyproject)
    return root


class ReaderTests(unittest.TestCase):
    def test_toml_sections_keeps_tables_apart(self):
        sections = check_versions.toml_sections(CARGO % "1.2.3")
        self.assertEqual(
            check_versions.toml_string(sections["package"], "version"), "1.2.3"
        )
        # The dependency table's `version = "1"` must not leak into [package].
        self.assertEqual(
            check_versions.toml_string(sections["dependencies"], "serde"), "1"
        )
        self.assertIn("bin", sections)

    def test_dynamic_version_attr_reads_inline_table(self):
        sections = check_versions.toml_sections(PYPROJECT_DYNAMIC)
        self.assertEqual(
            check_versions.dynamic_version_attr(sections["tool.setuptools.dynamic"]),
            "sigil_cli.__version__",
        )

    def test_dynamic_version_attr_missing(self):
        self.assertIsNone(check_versions.dynamic_version_attr('name = { attr = "x" }'))


class HardCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def run_check(self, expect=None):
        from pathlib import Path

        return check_versions.check(Path(self.root), expect)

    def test_aligned_tree_passes(self):
        fake_repo(self.root)
        code, report = self.run_check()
        self.assertEqual(code, 0, report)
        self.assertIn("OK: release-critical versions agree (1.3.6)", report)

    def test_cargo_and_wrapper_drift_fails(self):
        fake_repo(self.root, cargo="1.3.7", dunder="1.3.6")
        code, report = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("version mismatch", report)
        self.assertIn("1.3.7", report)

    def test_expect_matching_tag_passes_with_or_without_v(self):
        fake_repo(self.root)
        for tag in ("1.3.6", "v1.3.6"):
            with self.subTest(tag=tag):
                code, report = self.run_check(expect=tag)
                self.assertEqual(code, 0, report)

    def test_expect_wrong_tag_fails(self):
        fake_repo(self.root)
        code, report = self.run_check(expect="v9.9.9")
        self.assertEqual(code, 1)
        self.assertIn("release tag=9.9.9", report)

    def test_literal_pyproject_version_is_compared(self):
        pyproject = PYPROJECT_DYNAMIC.replace(
            'dynamic = ["version"]', 'version = "1.0.0"'
        )
        fake_repo(self.root, pyproject=pyproject)
        code, report = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("1.0.0", report)

    def test_dynamic_version_pointing_elsewhere_fails(self):
        pyproject = PYPROJECT_DYNAMIC.replace(
            'attr = "sigil_cli.__version__"', 'attr = "other_pkg.__version__"'
        )
        fake_repo(self.root, pyproject=pyproject)
        code, report = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("other_pkg.__version__", report)

    def test_missing_cargo_toml_fails_closed(self):
        fake_repo(self.root)
        os.remove(os.path.join(self.root, "cli", "Cargo.toml"))
        code, report = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("UNREADABLE", report)

    def test_soft_channels_never_fail_the_check(self):
        fake_repo(self.root)
        write(
            os.path.join(self.root, "plugins", "mcp-server", "package.json"),
            json.dumps({"version": "1.3.0"}),
        )
        write(
            os.path.join(self.root, "plugins", "vscode", "package.json"),
            json.dumps({"version": "0.0.1"}),
        )
        write(os.path.join(self.root, "package.json"), json.dumps({"version": "1.2.1"}))
        code, report = self.run_check()
        self.assertEqual(code, 0, report)
        self.assertIn("1.3.0", report)
        self.assertIn("0.0.1", report)

    def test_server_json_drift_warns_but_passes(self):
        fake_repo(self.root)
        write(
            os.path.join(self.root, "plugins", "mcp-server", "package.json"),
            json.dumps({"version": "1.3.0"}),
        )
        write(
            os.path.join(self.root, "plugins", "mcp-server", "server.json"),
            json.dumps({"version": "1.2.9", "packages": [{"version": "1.2.9"}]}),
        )
        code, report = self.run_check()
        self.assertEqual(code, 0, report)
        self.assertIn("warning:", report)
        self.assertIn("server.json", report)

    def test_skill_front_matter_drift_warns_but_passes(self):
        fake_repo(self.root)
        write(
            os.path.join(self.root, "sigil-skill", "skill.json"),
            json.dumps({"version": "1.1.0"}),
        )
        write(
            os.path.join(self.root, "sigil-skill", "sigil-scan", "SKILL.md"),
            "---\n"
            "name: sigil-scan\n"
            "license: Apache-2.0\n"
            "metadata:\n"
            "  author: nomarj\n"
            '  version: "1.0.9"\n'
            "---\n\n# Sigil\n",
        )
        code, report = self.run_check()
        self.assertEqual(code, 0, report)
        self.assertIn("1.0.9", report)
        self.assertIn("warning:", report)

    def test_skill_front_matter_version_is_read_from_metadata_block(self):
        from pathlib import Path

        write(
            os.path.join(self.root, "sigil-skill", "sigil-scan", "SKILL.md"),
            "---\n"
            "name: sigil-scan\n"
            'description: "mentions version: 9.9.9 in prose"\n'
            "metadata:\n"
            '  version: "2.0.1"\n'
            "---\n",
        )
        self.assertEqual(
            check_versions.skill_frontmatter_version(Path(self.root)), "2.0.1"
        )

    def test_skill_front_matter_absent(self):
        from pathlib import Path

        self.assertIsNone(check_versions.skill_frontmatter_version(Path(self.root)))

    def test_jetbrains_prefers_gradle_properties(self):
        fake_repo(self.root)
        write(
            os.path.join(self.root, "plugins", "jetbrains", "build.gradle.kts"),
            'val pluginVersion = providers.gradleProperty("pluginVersion").orElse("0.1.0").get()\n',
        )
        code, report = self.run_check()
        self.assertEqual(code, 0, report)
        self.assertIn("build.gradle.kts (fallback)", report)

        write(
            os.path.join(self.root, "plugins", "jetbrains", "gradle.properties"),
            "pluginVersion=2.4.0\n",
        )
        code, report = self.run_check()
        self.assertEqual(code, 0, report)
        self.assertIn("2.4.0", report)


class RealRepositoryTests(unittest.TestCase):
    """The tree this test runs in must itself be aligned."""

    def test_this_repository_passes(self):
        self.assertEqual(check_versions.main([]), 0)

    def test_expect_current_cli_version_passes(self):
        from pathlib import Path

        version = check_versions.cargo_version(Path(REPO_ROOT))
        self.assertEqual(check_versions.main(["--expect", "v" + version]), 0)


if __name__ == "__main__":
    unittest.main()
