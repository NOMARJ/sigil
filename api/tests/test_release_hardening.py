from __future__ import annotations

import os
import shutil
import stat
import subprocess
import json
from pathlib import Path


def test_github_action_fails_closed_when_sigil_scan_produces_no_report(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    action = tmp_path / "action-entrypoint.sh"
    shutil.copy(repo_root / ".github" / "action-entrypoint.sh", action)
    action.chmod(action.stat().st_mode | stat.S_IXUSR)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_sigil = fake_bin / "sigil"
    fake_sigil.write_text(
        "#!/usr/bin/env bash\n"
        "echo 'Sigil detection engine (Rust binary) not found'\n"
        "exit 127\n"
    )
    fake_sigil.chmod(fake_sigil.stat().st_mode | stat.S_IXUSR)

    scan_target = tmp_path / "scan-target"
    scan_target.mkdir()
    output = tmp_path / "github-output"
    summary = tmp_path / "github-summary"

    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "INPUT_PATH": str(scan_target),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
    }

    result = subprocess.run(
        [str(action)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 127
    assert "verdict=error" in output.read_text()
    assert "verdict=clean" not in output.read_text()
    assert "did not produce a report" in result.stdout + result.stderr


def test_github_action_fails_closed_on_unparseable_success_without_report(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    action = tmp_path / "action-entrypoint.sh"
    shutil.copy(repo_root / ".github" / "action-entrypoint.sh", action)
    action.chmod(action.stat().st_mode | stat.S_IXUSR)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_sigil = fake_bin / "sigil"
    fake_sigil.write_text(
        "#!/usr/bin/env bash\necho '[LOW] suspicious file found'\nexit 0\n"
    )
    fake_sigil.chmod(fake_sigil.stat().st_mode | stat.S_IXUSR)

    scan_target = tmp_path / "scan-target"
    scan_target.mkdir()
    output = tmp_path / "github-output"
    summary = tmp_path / "github-summary"

    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "INPUT_PATH": str(scan_target),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
    }

    result = subprocess.run(
        [str(action)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "verdict=error" in output.read_text()
    assert "verdict=clean" not in output.read_text()


def test_github_action_parses_json_scan_output_without_report(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    action = tmp_path / "action-entrypoint.sh"
    shutil.copy(repo_root / ".github" / "action-entrypoint.sh", action)
    action.chmod(action.stat().st_mode | stat.S_IXUSR)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_sigil = fake_bin / "sigil"
    fake_sigil.write_text(
        "#!/usr/bin/env bash\n"
        "cat <<'JSON'\n"
        "{\n"
        '  "files_scanned": 1,\n'
        '  "findings_count": 1,\n'
        '  "score": 1,\n'
        '  "verdict": "LOW RISK",\n'
        '  "duration_ms": 1\n'
        "}\n"
        "JSON\n"
        "exit 0\n"
    )
    fake_sigil.chmod(fake_sigil.stat().st_mode | stat.S_IXUSR)

    scan_target = tmp_path / "scan-target"
    scan_target.mkdir()
    output = tmp_path / "github-output"
    summary = tmp_path / "github-summary"

    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "INPUT_PATH": str(scan_target),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
    }

    result = subprocess.run(
        [str(action)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    outputs = output.read_text()
    assert result.returncode == 0
    assert "verdict=low" in outputs
    assert "risk-score=1" in outputs
    assert "findings-count=1" in outputs


def test_github_action_uses_scan_subcommand_before_format_flag(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    action = tmp_path / "action-entrypoint.sh"
    shutil.copy(repo_root / ".github" / "action-entrypoint.sh", action)
    action.chmod(action.stat().st_mode | stat.S_IXUSR)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    args_file = tmp_path / "args.txt"
    fake_sigil = fake_bin / "sigil"
    fake_sigil.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$@" > "$SIGIL_ARGS_FILE"\n'
        "cat <<'JSON'\n"
        "{\n"
        '  "files_scanned": 1,\n'
        '  "findings_count": 0,\n'
        '  "score": 0,\n'
        '  "verdict": "LOW RISK",\n'
        '  "duration_ms": 1\n'
        "}\n"
        "JSON\n"
    )
    fake_sigil.chmod(fake_sigil.stat().st_mode | stat.S_IXUSR)

    scan_target = tmp_path / "scan-target"
    scan_target.mkdir()

    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "INPUT_PATH": str(scan_target),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "github-summary"),
        "SIGIL_ARGS_FILE": str(args_file),
    }

    result = subprocess.run(
        [str(action)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert args_file.read_text().splitlines() == [
        "scan",
        str(scan_target),
        "--format",
        "json",
    ]


def test_release_packaging_targets_native_assets():
    repo_root = Path(__file__).resolve().parents[2]
    package_json = json.loads((repo_root / "package.json").read_text())
    installer = (repo_root / "install.sh").read_text()
    postinstall = (repo_root / "scripts" / "install-binary.js").read_text()
    wrapper = (repo_root / "bin" / "sigil-wrapper.js").read_text()

    assert package_json["version"] == "1.2.1"
    assert package_json["os"] == ["darwin", "linux"]
    assert package_json["cpu"] == ["x64", "arm64"]
    assert "win32" not in package_json["os"]
    assert "macos-arm64.tar.gz" in installer
    assert "macos-x64.tar.gz" in installer
    assert "linux-x64.tar.gz" in installer
    assert "linux-arm64.tar.gz" in installer
    assert "sigil-linux-x64.tar.gz" in postinstall
    assert "sigil-linux-arm64.tar.gz" in postinstall
    assert "linux: {\n    x64: 'sigil-linux-x64.tar.gz'" in postinstall
    assert "linux-aarch64" not in postinstall
    assert "SHA256SUMS.txt" in postinstall
    assert "@nomarj/sigil" in wrapper
    assert "falling back to bash script" not in installer
    assert "cargo install sigil-cli" in installer
    assert 'cargo install sigil"' not in installer


def test_release_workflow_publishes_npm_after_public_release_assets_exist():
    repo_root = Path(__file__).resolve().parents[2]
    workflow = (repo_root / ".github" / "workflows" / "release.yml").read_text()

    assert "if-no-files-found: error" in workflow
    for asset in [
        "release-assets/sigil-macos-arm64.tar.gz",
        "release-assets/sigil-macos-x64.tar.gz",
        "release-assets/sigil-linux-x64.tar.gz",
        "release-assets/sigil-linux-arm64.tar.gz",
        "release-assets/sigil-windows-x64.zip",
    ]:
        assert f"test -f {asset}" in workflow

    assert "aarch64-unknown-linux-gnu" in workflow
    assert "cross build --release --target ${{ matrix.target }}" in workflow
    assert workflow.index("name: Publish to crates.io") < workflow.index(
        "name: Create GitHub Release"
    )
    assert workflow.index("name: Create GitHub Release") < workflow.index(
        "name: Publish to npm"
    )
    assert "draft: true" not in workflow
    assert "cargo install sigil-cli" in workflow
    assert 'gh release edit "${{ github.ref_name }}" --draft=false' not in workflow
    assert "npm (macOS/Linux)" in workflow
    assert "npm publish --access public ||" not in workflow


def test_full_docker_image_builds_with_dashboard_api_url_and_rust_engine():
    repo_root = Path(__file__).resolve().parents[2]
    workflow = (repo_root / ".github" / "workflows" / "docker.yml").read_text()
    dockerfile = (repo_root / "Dockerfile").read_text()

    assert "NEXT_PUBLIC_API_URL=https://api.sigilsec.ai" in workflow
    assert "COPY --from=cli-builder" in dockerfile
    assert "/usr/local/bin/sigil-engine" in dockerfile
    assert "ENV SIGIL_BIN=/usr/local/bin/sigil-engine" in dockerfile
    assert "--entrypoint /usr/local/bin/sigil" in workflow


def test_api_deploy_and_ci_use_locked_python_dependencies():
    repo_root = Path(__file__).resolve().parents[2]
    api_dockerfile = (repo_root / "api" / "Dockerfile").read_text()
    ci_workflow = (repo_root / ".github" / "workflows" / "ci.yml").read_text()
    pro_workflow = (
        repo_root / ".github" / "workflows" / "test-pro-tier.yml"
    ).read_text()

    assert "api/requirements.lock" in api_dockerfile
    assert "api/requirements.txt" not in api_dockerfile
    assert "pip install -r api/requirements.lock" in ci_workflow
    assert "cd api && pytest tests -v --tb=short" in ci_workflow
    assert "- '.github/workflows/test-pro-tier.yml'" in pro_workflow
    assert "coverage combine ../artifact/coverage-*.xml" not in pro_workflow


def test_base_schema_contains_billing_entitlement_column():
    repo_root = Path(__file__).resolve().parents[2]
    schema = (repo_root / "api" / "schema.sql").read_text()

    assert "name = 'subscription_tier'" in schema
    assert "ALTER TABLE users ADD subscription_tier" in schema
    assert "idx_users_subscription_tier" in schema


def test_production_migrations_verify_auth_billing_and_interactive_schema():
    repo_root = Path(__file__).resolve().parents[2]
    auth_migration = (
        repo_root / "api" / "migrations" / "add_auth0_subscription_columns_prod.sql"
    ).read_text()
    credits_migration = (
        repo_root / "api" / "migrations" / "add_credits_system_prod.sql"
    ).read_text()
    runner = (repo_root / "api" / "migrations" / "apply_prod_migration.py").read_text()

    assert "ALTER TABLE users ADD auth0_sub" in auth_migration
    assert "ALTER TABLE users ADD subscription_tier" in auth_migration
    assert "idx_users_auth0_sub" in auth_migration
    assert "idx_users_subscription_tier" in auth_migration
    assert "CREATE TABLE interactive_sessions" in credits_migration
    assert "IX_sessions_user_active" in credits_migration
    assert "IX_sessions_share_token" in credits_migration

    for required_object in [
        "users.auth0_sub",
        "users.subscription_tier",
        "idx_users_auth0_sub",
        "idx_users_subscription_tier",
        "user_credits",
        "credit_transactions",
        "interactive_sessions",
        "IX_sessions_user_active",
        "IX_sessions_scan",
        "IX_sessions_share_token",
        "IX_sessions_expiry",
        "sp_DeductCredits",
        "sp_AddCredits",
    ]:
        assert required_object in runner
    assert "async def main(paths: list[str]) -> int" in runner


def test_cli_auto_approval_uses_ledger_helper():
    repo_root = Path(__file__).resolve().parents[2]
    source = (repo_root / "cli" / "src" / "main.rs").read_text()
    production_source = source.split("#[cfg(test)]", 1)[0]

    assert production_source.count("approve_with_ledger(&entry.id") == 3
    assert "quarantine::approve(&entry.id" not in production_source
