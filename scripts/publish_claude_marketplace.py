#!/usr/bin/env python3
"""Publish a generated Claude plugin marketplace tree to Git."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_BRANCH = "claude-marketplace"
DEFAULT_TAG_PREFIX = "claude-plugin-"


def _run(args: list[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if check and result.returncode != 0:
        cmd = " ".join(args[:2]) if args[:1] == ["git"] else args[0]
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"{cmd} failed with exit {result.returncode}: {detail}")
    return result


def _validate_release_ref(value: str, kind: str) -> None:
    if not value:
        raise RuntimeError(f"{kind} must not be empty")
    if value.startswith("-") or any(ch.isspace() for ch in value):
        raise RuntimeError(f"Invalid {kind}: {value!r}")
    if ".." in value or value.endswith("/") or value.endswith(".lock"):
        raise RuntimeError(f"Invalid {kind}: {value!r}")


def _copy_marketplace(src: Path, dst: Path) -> None:
    if not (src / ".claude-plugin" / "marketplace.json").exists():
        raise RuntimeError(f"Marketplace root is missing .claude-plugin/marketplace.json: {src}")
    shutil.copytree(
        src,
        dst,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )


def _ls_remote_ref(remote: str, ref: str, *, cwd: Path) -> str | None:
    result = _run(["git", "ls-remote", "--exit-code", remote, ref], cwd=cwd, check=False)
    if result.returncode == 2:
        return None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"git ls-remote failed for {ref}: {detail}")
    first_line = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
    sha = first_line.split()[0] if first_line.split() else ""
    return sha or None


def _ensure_existing_tag_matches(remote: str, tag: str, *, cwd: Path) -> bool:
    tag_ref = f"refs/tags/{tag}"
    existing = _ls_remote_ref(remote, tag_ref, cwd=cwd)
    if existing is None:
        return False

    _run(["git", "fetch", "--depth=1", "origin", f"{tag_ref}:{tag_ref}"], cwd=cwd)
    diff = _run(["git", "diff", "--quiet", tag_ref, "HEAD", "--"], cwd=cwd, check=False)
    if diff.returncode == 0:
        print(f"Plugin marketplace tag already exists with identical content: {tag}")
        return True
    if diff.returncode == 1:
        raise RuntimeError(
            f"Remote plugin marketplace tag {tag!r} already exists with different content"
        )
    detail = (diff.stderr or diff.stdout).strip()
    raise RuntimeError(f"git diff failed while checking existing tag {tag}: {detail}")


def publish_marketplace(
    *,
    marketplace_root: Path,
    remote: str,
    source_tag: str,
    branch: str = DEFAULT_BRANCH,
    tag_prefix: str = DEFAULT_TAG_PREFIX,
) -> str:
    _validate_release_ref(source_tag, "source tag")
    _validate_release_ref(branch, "branch")
    plugin_tag = f"{tag_prefix}{source_tag}"
    _validate_release_ref(plugin_tag, "plugin tag")

    with tempfile.TemporaryDirectory(prefix="nah-claude-marketplace-publish-") as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        _run(["git", "init"], cwd=repo)
        _run(["git", "checkout", "-B", branch], cwd=repo)
        _copy_marketplace(marketplace_root, repo)
        _run(["git", "config", "user.name", "github-actions[bot]"], cwd=repo)
        _run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=repo)
        _run(["git", "add", "-A"], cwd=repo)
        _run(["git", "commit", "-m", f"Publish Claude plugin marketplace {source_tag}"], cwd=repo)
        _run(["git", "remote", "add", "origin", remote], cwd=repo)

        tag_exists = _ensure_existing_tag_matches(remote, plugin_tag, cwd=repo)
        branch_ref = f"refs/heads/{branch}"
        expected_branch_sha = _ls_remote_ref(remote, branch_ref, cwd=repo) or ""
        lease = f"--force-with-lease={branch_ref}:{expected_branch_sha}"
        _run(["git", "push", lease, "origin", f"HEAD:{branch_ref}"], cwd=repo)

        if not tag_exists:
            _run(["git", "tag", plugin_tag], cwd=repo)
            _run(["git", "push", "origin", f"refs/tags/{plugin_tag}"], cwd=repo)

    return plugin_tag


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--marketplace-root",
        type=Path,
        required=True,
        help="Generated Claude plugin marketplace root to publish",
    )
    parser.add_argument("--remote", required=True, help="Git remote URL or local bare repository path")
    parser.add_argument("--source-tag", required=True, help="Source release tag, for example v0.6.5")
    parser.add_argument(
        "--branch",
        default=DEFAULT_BRANCH,
        help=f"Distribution branch to update (default: {DEFAULT_BRANCH})",
    )
    parser.add_argument(
        "--tag-prefix",
        default=DEFAULT_TAG_PREFIX,
        help=f"Prefix for immutable plugin distribution tags (default: {DEFAULT_TAG_PREFIX})",
    )
    args = parser.parse_args(argv)

    try:
        plugin_tag = publish_marketplace(
            marketplace_root=args.marketplace_root.resolve(),
            remote=args.remote,
            source_tag=args.source_tag,
            branch=args.branch,
            tag_prefix=args.tag_prefix,
        )
    except Exception as exc:
        print(f"publish_claude_marketplace.py: {exc}", file=sys.stderr)
        return 1

    print(f"Published Claude plugin marketplace branch {args.branch} and tag {plugin_tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
