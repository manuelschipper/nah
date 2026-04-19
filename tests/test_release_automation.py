import json
import subprocess
import sys
from pathlib import Path

from nah import __version__

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_claude_plugin.py"
CHECK_SCRIPT = ROOT / "scripts" / "check_release.py"
PUBLISH_SCRIPT = ROOT / "scripts" / "publish_claude_marketplace.py"


def _run(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    result = _run(["git", *args], cwd=cwd)
    assert result.returncode == 0, result.stderr
    return result


def _build_marketplace(out: Path) -> None:
    result = _run([sys.executable, str(BUILD_SCRIPT), "--marketplace-out", str(out)])
    assert result.returncode == 0, result.stderr


def _release_changelog(tmp_path: Path) -> Path:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(
        f"# Changelog\n\n## [{__version__}] - 2026-04-19\n\n### Added\n\n- Release note.\n",
        encoding="utf-8",
    )
    return path


def _run_check(marketplace: Path, changelog: Path, tag: str | None = None) -> subprocess.CompletedProcess:
    return _run([
        sys.executable,
        str(CHECK_SCRIPT),
        "--tag",
        tag or f"v{__version__}",
        "--marketplace-root",
        str(marketplace),
        "--changelog",
        str(changelog),
    ])


def _run_publish(marketplace: Path, remote: Path, tag: str | None = None) -> subprocess.CompletedProcess:
    return _run([
        sys.executable,
        str(PUBLISH_SCRIPT),
        "--marketplace-root",
        str(marketplace),
        "--remote",
        str(remote),
        "--source-tag",
        tag or f"v{__version__}",
    ])


def test_release_verifier_accepts_generated_marketplace(tmp_path):
    marketplace = tmp_path / "marketplace"
    _build_marketplace(marketplace)
    changelog = _release_changelog(tmp_path)

    result = _run_check(marketplace, changelog)

    assert result.returncode == 0, result.stderr
    assert f"nah {__version__}" in result.stdout


def test_release_verifier_rejects_mismatched_tag(tmp_path):
    marketplace = tmp_path / "marketplace"
    _build_marketplace(marketplace)
    changelog = _release_changelog(tmp_path)

    result = _run_check(marketplace, changelog, tag="v0.0.0")

    assert result.returncode == 1
    assert "does not match package version" in result.stderr


def test_release_verifier_rejects_missing_changelog_heading(tmp_path):
    marketplace = tmp_path / "marketplace"
    _build_marketplace(marketplace)
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## [Unreleased]\n", encoding="utf-8")

    result = _run_check(marketplace, changelog)

    assert result.returncode == 1
    assert "missing dated release heading" in result.stderr


def test_release_verifier_rejects_stale_marketplace_version(tmp_path):
    marketplace = tmp_path / "marketplace"
    _build_marketplace(marketplace)
    changelog = _release_changelog(tmp_path)
    marketplace_path = marketplace / ".claude-plugin" / "marketplace.json"
    data = json.loads(marketplace_path.read_text(encoding="utf-8"))
    data["metadata"]["version"] = "0.0.0"
    marketplace_path.write_text(json.dumps(data), encoding="utf-8")

    result = _run_check(marketplace, changelog)

    assert result.returncode == 1
    assert "metadata.version" in result.stderr


def test_release_verifier_rejects_incomplete_plugin_artifact(tmp_path):
    marketplace = tmp_path / "marketplace"
    _build_marketplace(marketplace)
    changelog = _release_changelog(tmp_path)
    (marketplace / "plugins" / "nah" / "lib" / "nah" / "hook.py").unlink()

    result = _run_check(marketplace, changelog)

    assert result.returncode == 1
    assert "incomplete" in result.stderr


def test_marketplace_publisher_updates_branch_and_immutable_tag(tmp_path):
    marketplace = tmp_path / "marketplace"
    remote = tmp_path / "remote.git"
    clone = tmp_path / "clone"
    _build_marketplace(marketplace)
    _git(["init", "--bare", str(remote)], cwd=tmp_path)

    first = _run_publish(marketplace, remote)
    second = _run_publish(marketplace, remote)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "identical content" in second.stdout

    _git(["clone", "--branch", "claude-marketplace", str(remote), str(clone)], cwd=tmp_path)
    assert (clone / ".claude-plugin" / "marketplace.json").exists()
    assert (clone / "plugins" / "nah" / "lib" / "nah" / "hook.py").exists()

    tag_ref = _git(["rev-parse", f"refs/tags/claude-plugin-v{__version__}"], cwd=remote)
    branch_ref = _git(["rev-parse", "refs/heads/claude-marketplace"], cwd=remote)
    assert tag_ref.stdout.strip()
    assert branch_ref.stdout.strip()


def test_marketplace_publisher_rejects_changed_content_for_existing_plugin_tag(tmp_path):
    marketplace = tmp_path / "marketplace"
    remote = tmp_path / "remote.git"
    _build_marketplace(marketplace)
    _git(["init", "--bare", str(remote)], cwd=tmp_path)
    first = _run_publish(marketplace, remote)
    assert first.returncode == 0, first.stderr

    marketplace_path = marketplace / ".claude-plugin" / "marketplace.json"
    data = json.loads(marketplace_path.read_text(encoding="utf-8"))
    data["metadata"]["description"] = "changed after tag"
    marketplace_path.write_text(json.dumps(data), encoding="utf-8")

    second = _run_publish(marketplace, remote)

    assert second.returncode == 1
    assert "already exists with different content" in second.stderr


def test_publish_workflow_orders_plugin_release_after_verification_and_before_release():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    ordered_steps = [
        "Verify tag release",
        "Build package",
        "Build Claude plugin marketplace",
        "Check Claude plugin marketplace freshness",
        "Verify release metadata",
        "Validate Claude plugin marketplace",
        "Publish to PyPI",
        "Publish Claude plugin marketplace",
        "Extract changelog for release",
        "Create GitHub Release",
    ]
    positions = [workflow.index(step) for step in ordered_steps]
    assert positions == sorted(positions)
    assert "claude-marketplace" in workflow
    assert "CLAUDE_MARKETPLACE_ROOT" in workflow
    assert "--marketplace-root \"$CLAUDE_MARKETPLACE_ROOT\"" in workflow
    assert "pypa/gh-action-pypi-publish@release/v1" in workflow
    assert "skip-existing: true" in workflow
