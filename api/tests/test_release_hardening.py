from __future__ import annotations

import os
import shutil
import stat
import subprocess
import json
import re
import textwrap
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
    assert "did not produce parseable JSON" in result.stdout + result.stderr


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
        '  "summary": {\n'
        '    "files_scanned": 1,\n'
        '    "findings_count": 1,\n'
        '    "score": 1,\n'
        '    "verdict": "LOW RISK",\n'
        '    "duration_ms": 1\n'
        "  },\n"
        '  "findings": []\n'
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
        '  "summary": {\n'
        '    "files_scanned": 1,\n'
        '    "findings_count": 0,\n'
        '    "score": 0,\n'
        '    "verdict": "LOW RISK",\n'
        '    "duration_ms": 1\n'
        "  },\n"
        '  "findings": []\n'
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
    ]:
        assert node24_action in workflow_text

    for gradle_workflow in [
        repo_root / ".github" / "workflows" / "ci.yml",
        repo_root / ".github" / "workflows" / "publish-jetbrains.yml",
    ]:
        gradle_text = gradle_workflow.read_text()
        assert "gradle/actions/setup-gradle@v6" in gradle_text
        assert "cache-provider: basic" in gradle_text
        assert "gradle/actions/setup-gradle@v5" not in gradle_text
        assert "gradle/actions/setup-gradle@v4" not in gradle_text

    assert (
        "gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a"
        not in workflow_text
    )

    if infra_workflow.exists():
        infra_text = infra_workflow.read_text()
        assert "azure/login@v3" in infra_text
        assert "hashicorp/setup-terraform@v4" in infra_text


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

    # linux-arm64 is built natively on GitHub's arm64 runner. cross cannot be
    # used for it: its container mounts only cli/, so the corpus include_str!
    # paths into the repo-root packs/ never resolve (release run 33239558719).
    assert re.search(
        r"target: aarch64-unknown-linux-gnu\s+os: ubuntu-22\.04-arm\s", workflow
    )
    assert "cargo build --release --target ${{ matrix.target }}" in workflow
    assert "cross build" not in workflow
    assert "use_cross" not in workflow

    # The repo uses immutable releases: assets can only be attached before
    # publication, so the workflow must create the release as a draft with
    # every asset already attached, flip it to published, and only then run
    # the registry publishes (a crates.io failure must never block assets —
    # runs 33244784841 and 33247510578 are the incidents behind this order).
    assert "draft: true" in workflow
    assert "-F draft=false" in workflow
    assert workflow.index(
        "name: Create draft GitHub Release with assets"
    ) < workflow.index("name: Publish GitHub Release")
    assert workflow.index("name: Publish GitHub Release") < workflow.index(
        "name: Publish to crates.io"
    )
    assert workflow.index("name: Publish to crates.io") < workflow.index(
        "name: Publish to npm"
    )
    # crates.io publish must stay idempotent so a re-run of the release job
    # (e.g. after an npm failure) does not die on "crate already exists".
    assert "already on crates.io" in workflow

    # A release created via the web UI is published (immutable, assetless)
    # before the workflow can act — the preflight guard must fail fast on
    # that, before the five platform builds run (v1.3.4, run 33269519976).
    assert "A published release already exists" in workflow
    assert workflow.index("preflight:") < workflow.index("build:")
    assert "needs: preflight" in workflow
    assert "cargo install sigil-cli" in workflow
    assert "npm (macOS/Linux)" in workflow
    assert "npm publish --access public ||" not in workflow


def test_full_docker_image_builds_with_dashboard_api_url_and_rust_engine():
    repo_root = Path(__file__).resolve().parents[2]
    workflow = (repo_root / ".github" / "workflows" / "docker.yml").read_text()
    dockerfile = (repo_root / "Dockerfile").read_text()

    assert "NEXT_PUBLIC_API_URL=https://api.sigilsec.ai" in workflow
    assert ":latest" not in workflow
    assert "type=raw,value=latest" not in workflow
    assert "image-tag" in workflow
    assert "Docker image tag must be immutable" in workflow
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
    requirements = (repo_root / "api" / "requirements.txt").read_text()
    lock = (repo_root / "api" / "requirements.lock").read_text()
    deploy_workflow = (
        repo_root / ".github" / "workflows" / "deploy-azure.yml"
    ).read_text()

    assert "api/requirements.lock" in api_dockerfile
    assert "api/requirements.txt" not in api_dockerfile
    assert "httpx2>=2.4.0" in requirements
    assert "httpx2==2.4.0" in lock
    assert "httpcore2==2.4.0" in lock
    assert "sigil-api:latest" not in deploy_workflow
    assert "sigil-bot:latest" not in deploy_workflow
    assert "sigil-dashboard:latest" not in deploy_workflow
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


def test_api_testclient_compatibility_uses_locked_httpx2_stack():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    with TestClient(app) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


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


def _workflow(name: str) -> str:
    repo_root = Path(__file__).resolve().parents[2]
    return (repo_root / ".github" / "workflows" / name).read_text()


def _step_blocks(workflow: str) -> list[tuple[str, str]]:
    """(name, text) of every step in the workflow's jobs, in order."""
    blocks, name, lines = [], None, []
    for line in workflow.splitlines():
        if re.match(r"^      - ", line):
            if name is not None:
                blocks.append((name, "\n".join(lines)))
            match = re.match(r"^      - name: (.+)$", line)
            name, lines = (match.group(1) if match else line.strip()), [line]
        elif name is not None:
            if re.match(r"^  \S", line):  # the next job
                blocks.append((name, "\n".join(lines)))
                name, lines = None, []
            else:
                lines.append(line)
    if name is not None:
        blocks.append((name, "\n".join(lines)))
    return blocks


def _step_script(workflow: str, step_name: str) -> str:
    """The `run: |` script of the named step, dedented, as bash will see it."""
    lines = workflow.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.strip() == f"- name: {step_name}"
    )
    step_indent = len(lines[start]) - len(lines[start].lstrip())
    run = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "run: |")
    assert not any(
        line.strip().startswith("- ") and len(line) - len(line.lstrip()) == step_indent
        for line in lines[start + 1 : run]
    ), f"no run block in step {step_name!r}"
    run_indent = len(lines[run]) - len(lines[run].lstrip())
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= run_indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


def _as_actions_would(script: str, expressions: dict) -> str:
    """Substitute `${{ expr }}` into the script text, as Actions does before bash
    parses it. A step that interpolates an input then runs the input's shell
    syntax, which is what the injection cases below detect."""
    for expression, value in expressions.items():
        script = script.replace("${{ " + expression + " }}", value)
    return script


def _run_step(
    script: str, tmp_path: Path, env: dict, cwd: Path | None = None
) -> tuple[subprocess.CompletedProcess, dict]:
    output = tmp_path / "github-output"
    output.write_text("")
    result = subprocess.run(
        # How Actions runs a `run:` step that sets no `shell:`: bash -e {0}.
        ["bash", "-e", "-c", script],
        cwd=cwd or tmp_path,
        env={**os.environ, "GITHUB_OUTPUT": str(output), **env},
        capture_output=True,
        text=True,
        check=False,
    )
    outputs = dict(
        line.split("=", 1) for line in output.read_text().splitlines() if "=" in line
    )
    return result, outputs


def _fake_bin(tmp_path: Path, name: str, body: str) -> Path:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    tool = fake_bin / name
    tool.write_text("#!/usr/bin/env bash\n" + body)
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    return fake_bin


_SBOM_SET = [
    f"sbom-{kind}.{fmt}.json{att}"
    for kind in ("source", "cli-container", "full-container")
    for fmt in ("cdx", "spdx")
    for att in ("", ".att")
] + ["SBOM-SHA256SUMS.txt"]


def _fake_gh(tmp_path: Path) -> Path:
    """A gh that answers only the exact calls the attach step should make.

    FAKE_STATE_FILE holds "true" (draft), "false" (published) or "absent";
    FAKE_ASSETS lists the assets already attached; FAKE_UPLOAD makes an
    upload succeed ("ok"), fail ("fail") or fail because the release was
    published meanwhile ("publish"). Any other call exits 2, as a changed
    flag or --jq filter would print something the step does not expect.
    """
    return _fake_bin(
        tmp_path,
        "gh",
        'echo "$*" >> "$FAKE_GH_LOG"\n'
        'state="$(cat "$FAKE_STATE_FILE")"\n'
        'view="release view v9.9.9 --repo NOMARJ/sigil"\n'
        'case "$*" in\n'
        '  "$view --json isDraft --jq .isDraft")\n'
        '    [ "$state" = "absent" ] && { echo "release not found" >&2; exit 1; }\n'
        '    echo "$state" ;;\n'
        '  "$view --json assets --jq .assets[].name")\n'
        '    [ "$state" = "absent" ] && { echo "release not found" >&2; exit 1; }\n'
        '    printf "%s\\n" $FAKE_ASSETS ;;\n'
        '  "release upload v9.9.9 --repo NOMARJ/sigil --clobber "*)\n'
        '    [ "$FAKE_UPLOAD" = "ok" ] && exit 0\n'
        '    [ "$FAKE_UPLOAD" = "publish" ] && echo false > "$FAKE_STATE_FILE"\n'
        '    echo "upload failed" >&2; exit 1 ;;\n'
        '  *) echo "unexpected gh call: $*" >&2; exit 2 ;;\n'
        "esac\n",
    )


@pytest.mark.parametrize(
    ("release", "assets", "upload", "code", "uploaded", "attached"),
    [
        # A draft with nothing attached gets the whole set.
        ("true", [], "ok", 0, True, "true"),
        # A complete set is never deleted and re-uploaded.
        ("true", _SBOM_SET, "ok", 0, False, "true"),
        # A partial set from a failed earlier upload is replaced whole.
        ("true", _SBOM_SET[:3], "ok", 0, True, "true"),
        # release.yml published the draft mid-upload: a warning, not a failure.
        ("true", [], "publish", 0, True, "false"),
        # The draft is still a draft and the upload failed: a real failure.
        ("true", [], "fail", 1, True, None),
        # Published or missing releases are never touched or created.
        ("false", [], "ok", 0, False, "false"),
        ("absent", [], "ok", 0, False, "false"),
    ],
)
def test_sbom_workflow_attaches_only_to_a_draft_release(
    tmp_path, release, assets, upload, code, uploaded, attached
):
    workflow = _workflow("sbom.yml")
    # softprops/action-gh-release creates (and so publishes) a release when the
    # tag has none, and replaces the notes of one that exists.
    assert "softprops/action-gh-release" not in workflow
    assert "gh release create" not in workflow
    assert "gh release edit" not in workflow

    fake_bin = _fake_gh(tmp_path)
    log = tmp_path / "gh.log"
    state = tmp_path / "release-state"
    state.write_text(release)
    result, outputs = _run_step(
        _step_script(workflow, "Attach SBOMs to the draft release"),
        tmp_path,
        {
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "FAKE_GH_LOG": str(log),
            "FAKE_STATE_FILE": str(state),
            "FAKE_ASSETS": " ".join(assets),
            "FAKE_UPLOAD": upload,
            "GITHUB_REF_NAME": "v9.9.9",
            "GITHUB_REPOSITORY": "NOMARJ/sigil",
        },
    )

    assert "unexpected gh call" not in result.stderr
    assert result.returncode == code, result.stderr
    calls = log.read_text().splitlines()
    assert (
        calls[0]
        == "release view v9.9.9 --repo NOMARJ/sigil --json isDraft --jq .isDraft"
    )
    uploads = [call for call in calls if call.startswith("release upload ")]
    assert bool(uploads) is uploaded
    for call in uploads:
        # Always the complete set from this run, never a subset, so a
        # partial set left by an earlier upload is replaced whole.
        assert call.split()[6:] == [f"sboms/{name}" for name in _SBOM_SET]
    assert outputs.get("attached") == attached


@pytest.mark.parametrize(
    ("env", "code", "outputs"),
    [
        (
            {"EVENT_NAME": "workflow_dispatch", "INPUT_TAG": "v1.3.7"},
            0,
            {"version": "1.3.7", "tag": "v1.3.7", "skip": "false"},
        ),
        (
            {"EVENT_NAME": "release", "RELEASE_TAG": "v1.3.7"},
            0,
            {"version": "1.3.7", "tag": "v1.3.7", "skip": "false"},
        ),
        # Other ship channels publish releases too; they are not formula updates.
        (
            {"EVENT_NAME": "release", "RELEASE_TAG": "vscode-v1.2.0"},
            0,
            {"skip": "true"},
        ),
        (
            {"EVENT_NAME": "workflow_dispatch", "INPUT_TAG": "v1.3.7$(touch pwned)"},
            1,
            {},
        ),
        (
            {"EVENT_NAME": "release", "RELEASE_TAG": "v1.3.7$(touch pwned)"},
            0,
            {"skip": "true"},
        ),
        ({"EVENT_NAME": "workflow_dispatch", "INPUT_TAG": "vscode-v1.2.0"}, 1, {}),
    ],
)
def test_homebrew_workflow_accepts_only_cli_release_tags(tmp_path, env, code, outputs):
    env = {"RELEASE_TAG": "", "INPUT_TAG": "", "GH_TOKEN": "unused", **env}
    script = _as_actions_would(
        _step_script(_workflow("update-homebrew.yml"), "Get release info"),
        {
            "github.event_name": env["EVENT_NAME"],
            "github.event.release.tag_name": env["RELEASE_TAG"],
            "inputs.tag": env["INPUT_TAG"],
        },
    )

    result, got = _run_step(script, tmp_path, env)

    assert not (tmp_path / "pwned").exists()
    assert result.returncode == code, result.stderr
    assert got == outputs


def test_homebrew_steps_after_release_info_all_honour_skip():
    blocks = _step_blocks(_workflow("update-homebrew.yml"))
    names = [name for name, _ in blocks]
    later = blocks[names.index("Get release info") + 1 :]

    assert [name for name, _ in later] == [
        "Download checksums",
        "Extract SHA256 hashes",
        "Update Formula",
        "Commit and push",
    ]
    for name, text in later:
        assert "if: steps.release.outputs.skip != 'true'" in text, name


def test_homebrew_workflow_refuses_a_missing_or_malformed_hash(tmp_path):
    workflow = _workflow("update-homebrew.yml")
    script = _step_script(workflow, "Extract SHA256 hashes")
    names = [
        "sigil-macos-arm64.tar.gz",
        "sigil-macos-x64.tar.gz",
        "sigil-linux-x64.tar.gz",
        "sigil-linux-arm64.tar.gz",
    ]
    sums = tmp_path / "SHA256SUMS.txt"

    sums.write_text("".join(f"{str(i) * 64}  {name}\n" for i, name in enumerate(names)))
    result, outputs = _run_step(script, tmp_path, {})
    assert result.returncode == 0, result.stderr
    assert outputs == {
        "macos_arm64_sha": "0" * 64,
        "macos_x64_sha": "1" * 64,
        "linux_x64_sha": "2" * 64,
        "linux_arm64_sha": "3" * 64,
    }

    # linux-arm64 missing: the step fails before writing any output.
    sums.write_text("".join(f"{'a' * 64}  {name}\n" for name in names[:3]))
    result, outputs = _run_step(script, tmp_path, {})
    assert result.returncode != 0
    assert outputs == {}

    sums.write_text("".join(f"{'z' * 64}  {name}\n" for name in names))
    result, outputs = _run_step(script, tmp_path, {})
    assert result.returncode != 0
    assert outputs == {}


def _render_formula(tmp_path: Path) -> str:
    script = _as_actions_would(
        _step_script(_workflow("update-homebrew.yml"), "Update Formula"),
        {
            "steps.release.outputs.version": "1.3.7",
            "steps.release.outputs.tag": "v1.3.7",
            "github.repository": "NOMARJ/sigil",
            "steps.hashes.outputs.macos_arm64_sha": "0" * 64,
            "steps.hashes.outputs.macos_x64_sha": "1" * 64,
            "steps.hashes.outputs.linux_x64_sha": "2" * 64,
            "steps.hashes.outputs.linux_arm64_sha": "3" * 64,
        },
    )
    assert "${{" not in script
    if shutil.which("ruby") is None:
        script = script.replace("ruby -c homebrew-tap/Formula/sigil.rb", "true")
    (tmp_path / "homebrew-tap" / "Formula").mkdir(parents=True)

    result, _ = _run_step(script, tmp_path, {})

    assert result.returncode == 0, result.stderr
    return (tmp_path / "homebrew-tap" / "Formula" / "sigil.rb").read_text()


def test_homebrew_formula_tests_the_version_and_has_no_post_install(tmp_path):
    formula = _render_formula(tmp_path)

    # `sigil --version` prints "sigil X.Y.Z"; the old "SIGIL" never matched.
    assert (
        'assert_match version.to_s, shell_output("#{bin}/sigil --version")' in formula
    )
    assert "SIGIL" not in formula
    # `sigil install` copied the binary onto the Homebrew symlink to itself.
    assert "post_install" not in formula
    assert '"install"' not in formula


def test_homebrew_formula_gives_each_platform_its_own_binary(tmp_path):
    formula = _render_formula(tmp_path)
    base = r'url "https://github\.com/NOMARJ/sigil/releases/download/v1\.3\.7/'

    for block, arm, intel in (
        ("on_macos", ("macos-arm64", "0"), ("macos-x64", "1")),
        ("on_linux", ("linux-arm64", "3"), ("linux-x64", "2")),
    ):
        assert re.search(
            rf"{block} do\s+if Hardware::CPU\.arm\?\s+"
            rf'{base}sigil-{arm[0]}\.tar\.gz"\s+sha256 "{arm[1] * 64}"\s+else\s+'
            rf'{base}sigil-{intel[0]}\.tar\.gz"\s+sha256 "{intel[1] * 64}"\s+end\s+end',
            formula,
        ), block


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def test_homebrew_commit_is_a_no_op_when_the_formula_is_unchanged(tmp_path):
    script = _step_script(_workflow("update-homebrew.yml"), "Commit and push")
    remote, tap = tmp_path / "tap.git", tmp_path / "homebrew-tap"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    _git(tmp_path, "clone", "-q", str(remote), str(tap))
    (tap / "Formula").mkdir()
    (tap / "Formula" / "sigil.rb").write_text("# 1.3.6\n")
    _git(tap, "add", ".")
    _git(tap, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    _git(tap, "push", "-q", "-u", "origin", "main")

    (tap / "Formula" / "sigil.rb").write_text("# 1.3.7\n")
    first, _ = _run_step(script, tmp_path, {"VERSION": "1.3.7"}, cwd=tap)
    second, _ = _run_step(script, tmp_path, {"VERSION": "1.3.7"}, cwd=tap)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "nothing to push" in second.stdout
    log = _git(remote, "log", "--format=%s", "main").splitlines()
    assert log == ["Update sigil to 1.3.7", "init"]


_TAG_EXPRESSION = re.compile(
    r"\$\{\{[^}]*\b(inputs\.tag|github\.event\.inputs\.tag|github\.event\.release\.tag_name)\b[^}]*\}\}"
)


def test_release_side_workflows_never_interpolate_a_tag_into_shell():
    for name in ("publish-npm.yml", "update-homebrew.yml"):
        for line in _workflow(name).splitlines():
            if _TAG_EXPRESSION.search(line):
                assert re.match(r"^\s*(TAG|INPUT_TAG|RELEASE_TAG|ref):", line), (
                    name,
                    line,
                )

    npm = _workflow("publish-npm.yml")
    assert "ref: refs/tags/${{ inputs.tag }}" in npm
    assert npm.index("Refuse anything but a vX.Y.Z tag") < npm.index(
        "actions/checkout@v5"
    )


@pytest.mark.parametrize(
    ("tag", "code"),
    [("v1.3.7", 0), ("v1.3.7$(touch pwned)", 1), ("1.3.7", 1), ("v1.3", 1)],
)
def test_npm_publish_refuses_a_tag_that_is_not_vxyz(tmp_path, tag, code):
    script = _as_actions_would(
        _step_script(_workflow("publish-npm.yml"), "Refuse anything but a vX.Y.Z tag"),
        {"inputs.tag": tag},
    )

    result, _ = _run_step(script, tmp_path, {"TAG": tag})

    assert not (tmp_path / "pwned").exists()
    assert result.returncode == code


def test_npm_publish_step_reads_the_tag_as_data(tmp_path):
    tag = "v1.3.7$(touch pwned)"
    fake_bin = _fake_bin(
        tmp_path,
        "npm",
        'echo "$*" >> "$FAKE_NPM_LOG"\n[ "$1" = "view" ] && exit 1\nexit 0\n',
    )
    script = _as_actions_would(
        _step_script(_workflow("publish-npm.yml"), "Publish to npm"),
        {"inputs.tag": tag},
    )

    result, _ = _run_step(
        script,
        tmp_path,
        {
            "TAG": tag,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "FAKE_NPM_LOG": str(tmp_path / "npm.log"),
        },
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "pwned").exists()
    calls = (tmp_path / "npm.log").read_text().splitlines()
    assert (
        calls[1]
        == "version 1.3.7$(touch pwned) --no-git-tag-version --allow-same-version"
    )


def test_crate_excludes_the_maintainers_nomark_graph():
    import tomllib

    repo_root = Path(__file__).resolve().parents[2]
    manifest = tomllib.loads((repo_root / "cli" / "Cargo.toml").read_text())

    assert ".nomark/" in manifest["package"]["exclude"]


@pytest.mark.parametrize(
    ("listing", "code"),
    [
        (["Cargo.toml", "src/main.rs", ".cargo_vcs_info.json"], 0),
        (["Cargo.toml", ".nomark/graph.json", ".cargo_vcs_info.json"], 1),
        (["Cargo.toml", "src/.secret", ".cargo_vcs_info.json"], 1),
    ],
)
def test_ci_fails_when_the_crate_would_ship_a_hidden_file(tmp_path, listing, code):
    fake_bin = _fake_bin(
        tmp_path,
        "cargo",
        '[ "$*" = "package --list --allow-dirty" ] || exit 2\n'
        'printf "%s\\n" $FAKE_LISTING\n',
    )
    script = _step_script(_workflow("ci.yml"), "Crate ships no hidden files")

    result, _ = _run_step(
        script,
        tmp_path,
        {"PATH": f"{fake_bin}:{os.environ['PATH']}", "FAKE_LISTING": " ".join(listing)},
    )

    assert result.returncode == code, result.stdout + result.stderr


def test_cli_auto_approval_uses_ledger_helper():
    repo_root = Path(__file__).resolve().parents[2]
    source = (repo_root / "cli" / "src" / "main.rs").read_text()
    production_source = source.split("#[cfg(test)]", 1)[0]

    assert production_source.count("approve_with_ledger(&entry.id") == 3
    assert "quarantine::approve(&entry.id" not in production_source
