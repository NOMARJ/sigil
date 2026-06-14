from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from api.utils.git_analyzer import GitAnalyzer


def _run_git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is unavailable")

    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(repo, "init")
    _run_git(repo, "config", "user.email", "sigil@example.com")
    _run_git(repo, "config", "user.name", "Sigil Tester")
    (repo / "README.md").write_text("first\nsecond\n")
    _run_git(repo, "add", "README.md")
    _run_git(repo, "commit", "-m", "initial commit")
    return repo


def test_git_analyzer_rejects_unsafe_file_paths(git_repo: Path) -> None:
    analyzer = GitAnalyzer()

    result = asyncio.run(
        analyzer.get_blame_for_line(str(git_repo), "../README.md", 1)
    )

    assert result is None


def test_git_analyzer_rejects_unsafe_refs(git_repo: Path) -> None:
    analyzer = GitAnalyzer()

    commits = asyncio.run(
        analyzer.get_recent_commits(str(git_repo), branch="main;touch x")
    )
    changed = asyncio.run(analyzer.get_changed_files(str(git_repo), "HEAD", "HEAD -- ."))
    stats = asyncio.run(analyzer.get_commit_stats(str(git_repo), "HEAD^{tree}"))

    assert commits == []
    assert changed == []
    assert stats == {}


def test_git_analyzer_disables_direct_checkout(git_repo: Path) -> None:
    analyzer = GitAnalyzer()

    result = asyncio.run(
        analyzer.checkout_ref(str(git_repo), "HEAD", create_worktree=False)
    )

    assert result is None


def test_git_analyzer_allows_safe_blame(git_repo: Path) -> None:
    analyzer = GitAnalyzer()

    result = asyncio.run(analyzer.get_blame_for_line(str(git_repo), "README.md", 1))

    assert result is not None
    assert result["author"] == "Sigil Tester"
