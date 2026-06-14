from __future__ import annotations

import os
import shutil
import stat
import subprocess
import json
from pathlib import Path

import pytest


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


def test_infra_image_tag_variables_reject_mutable_defaults():
    repo_root = Path(__file__).resolve().parents[2]
    infra_root = repo_root.parent / "sigil-infra"
    variables = infra_root / "azure" / "variables.tf"
    if not variables.exists():
        pytest.skip("sigil-infra sibling checkout is not available")

    content = variables.read_text()

    assert 'default     = "latest"' not in content
    for variable_name in [
        "api_image_tag",
        "dashboard_image_tag",
        "bot_image_tag",
    ]:
        assert f'variable "{variable_name}"' in content
        assert f"{variable_name} must be an immutable image tag" in content
        assert f'trimspace(var.{variable_name}) != "latest"' in content


def test_infra_deploy_workflow_verifies_running_image_identity():
    repo_root = Path(__file__).resolve().parents[2]
    infra_root = repo_root.parent / "sigil-infra"
    workflow = infra_root / ".github" / "workflows" / "deploy.yml"
    if not workflow.exists():
        pytest.skip("sigil-infra sibling checkout is not available")

    content = workflow.read_text()

    assert "Check deployed image tags" in content
    assert "az containerapp show" in content
    assert "sigilacr46iy6y.azurecr.io" in content
    assert "sigil-api:$API_IMAGE_TAG" in content
    assert "sigil-dashboard:$DASHBOARD_IMAGE_TAG" in content
    assert "sigil-bot-watchers" in content
    assert "sigil-bot-workers" in content
    assert "sigil-bot-pr-worker" in content
    assert "needs.terraform-apply.result == 'skipped'" in content


def test_infra_ignores_local_nomark_chain_artifacts():
    repo_root = Path(__file__).resolve().parents[2]
    infra_root = repo_root.parent / "sigil-infra"
    gitignore = infra_root / ".gitignore"
    if not gitignore.exists():
        pytest.skip("sigil-infra sibling checkout is not available")

    assert "chains/" in gitignore.read_text()


def test_release_workflows_avoid_node20_only_action_paths():
    repo_root = Path(__file__).resolve().parents[2]
    workflow_text = "\n".join(
        path.read_text()
        for path in sorted((repo_root / ".github" / "workflows").glob("*.yml"))
    )
    infra_workflow = (
        repo_root.parent / "sigil-infra" / ".github" / "workflows" / "deploy.yml"
    )
    if infra_workflow.exists():
        workflow_text += "\n" + infra_workflow.read_text()

    for removed_action in [
        "docker/build-push-action@",
        "actions/download-artifact@",
        "peter-evans/repository-dispatch@",
        "softprops/action-gh-release@c062e08",
        "softprops/action-gh-release@3bb12739",
        "hashicorp/setup-terraform@v3",
        "azure/login@v2",
    ]:
        assert removed_action not in workflow_text

    for node24_action in [
        "actions/checkout@v5",
        "actions/cache@v5",
        "actions/setup-node@v5",
        "actions/upload-artifact@v6",
        "azure/login@v3",
        "hashicorp/setup-terraform@v4",
    ]:
        assert node24_action in workflow_text


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
    for watched_path in [
        ".github/workflows/test-pro-tier.yml",
        "api/gates.py",
        "api/permissions.py",
        "api/routers/scan.py",
        "api/routers/threat.py",
    ]:
        assert watched_path in pro_workflow
    assert "workflow_dispatch:" in pro_workflow
    assert "actions/setup-python@v6" in pro_workflow
    assert "codecov/codecov-action@v7" in pro_workflow
    assert "actions/github-script@v9" in pro_workflow
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
    assert "async def main(argv: list[str]) -> int" in runner
    assert "--verify-only" in runner
    assert "--apply" in runner
    assert "SIGIL_ALLOW_SCHEMA_WRITES" in runner
    assert "preview =" not in runner

    drift_workflow = (
        repo_root / ".github" / "workflows" / "prod-migration-drift.yml"
    ).read_text()
    assert (
        "python -m api.migrations.apply_prod_migration --verify-only" in drift_workflow
    )
    assert "az containerapp exec" in drift_workflow
    assert "script -q -e -c" in drift_workflow
    assert "sigil-rg" in drift_workflow
    assert "sigil-api" in drift_workflow
    assert "--apply" not in drift_workflow
    assert "*.sql" not in drift_workflow


def test_deploy_workflows_serialize_and_fail_closed_health_checks():
    repo_root = Path(__file__).resolve().parents[2]
    deploy_workflow = (
        repo_root / ".github" / "workflows" / "deploy-azure.yml"
    ).read_text()
    infra_workflow_path = (
        repo_root.parent / "sigil-infra" / ".github" / "workflows" / "deploy.yml"
    )

    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in deploy_workflow
    assert "concurrency:" in deploy_workflow
    assert "cancel-in-progress: true" in deploy_workflow

    if not infra_workflow_path.exists():
        return

    infra_workflow = infra_workflow_path.read_text()
    assert "concurrency:" in infra_workflow
    assert "cancel-in-progress: false" in infra_workflow
    assert "api_url: ${{ steps.outputs.outputs.api_url }}" in infra_workflow
    assert "dashboard_url: ${{ steps.outputs.outputs.dashboard_url }}" in infra_workflow
    assert 'API_URL="$(terraform output -raw api_url)"' in infra_workflow
    assert "Terraform output URLs are empty" in infra_workflow
    assert 'echo "api_url=$API_URL" >> "$GITHUB_OUTPUT"' in infra_workflow
    assert "-lock-timeout=10m" in infra_workflow
    assert "api_image_tag:" in infra_workflow
    assert "dashboard_image_tag:" in infra_workflow
    assert "bot_image_tag:" in infra_workflow
    assert "production deploys require immutable" in infra_workflow
    assert (
        "github.event_name != 'push' && needs.terraform-plan.outputs" in infra_workflow
    )
    assert (
        "github.event.inputs.api_image_tag || github.event.client_payload.api_image_tag || github.sha"
        in infra_workflow
    )
    assert (
        "TF_VAR_api_image_tag: ${{ github.event.client_payload.api_image_tag || 'latest' }}"
        not in infra_workflow
    )
    assert (
        "TF_VAR_dashboard_image_tag: ${{ github.event.client_payload.dashboard_image_tag || 'latest' }}"
        not in infra_workflow
    )
    assert (
        "TF_VAR_bot_image_tag: ${{ github.event.client_payload.bot_image_tag || 'latest' }}"
        not in infra_workflow
    )
    assert (
        'curl --fail --show-error --silent --retry 5 --retry-delay 10 "$API_URL/health"'
        in infra_workflow
    )
    assert (
        'curl --fail --show-error --silent --retry 5 --retry-delay 10 "https://api.sigilsec.ai/health"'
        in infra_workflow
    )
    assert "|| echo" not in infra_workflow


def test_release_support_workflows_have_valid_outputs_and_action_pins():
    repo_root = Path(__file__).resolve().parents[2]
    plugin_workflow = (
        repo_root / ".github" / "workflows" / "publish-plugin.yml"
    ).read_text()
    sbom_workflow = (repo_root / ".github" / "workflows" / "sbom.yml").read_text()

    assert "outputs:" in plugin_workflow
    assert "version: ${{ steps.version.outputs.version }}" in plugin_workflow
    assert "needs.publish-github-release.outputs.version" in plugin_workflow
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in plugin_workflow
    assert "gh release create" in plugin_workflow
    assert "softprops/action-gh-release" not in plugin_workflow

    assert "anchore/sbom-action/download-syft@v0.24.0" in sbom_workflow
    assert "f325610c9f50a54015d37feeff2e57e8981374a0" not in sbom_workflow
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true" in sbom_workflow


def test_cli_auto_approval_uses_ledger_helper():
    repo_root = Path(__file__).resolve().parents[2]
    source = (repo_root / "cli" / "src" / "main.rs").read_text()
    production_source = source.split("#[cfg(test)]", 1)[0]

    assert production_source.count("approve_with_ledger(&entry.id") == 3
    assert "quarantine::approve(&entry.id" not in production_source
