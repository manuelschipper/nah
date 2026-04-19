#!/usr/bin/env python3
"""Build the local Claude Code plugin artifact for nah."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "plugins" / "claude-code" / "nah"
DEFAULT_OUT = ROOT / "dist" / "claude-plugin" / "nah"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_out(out: Path) -> None:
    dist_dir = (ROOT / "dist").resolve()
    if out == ROOT or (_is_relative_to(out, ROOT) and not _is_relative_to(out, dist_dir)):
        raise RuntimeError(
            f"Refusing to build plugin artifact into tracked repository path: {out}"
        )


def _read_regex(path: Path, pattern: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"Could not read version from {path}")
    return match.group(1)


def _package_version() -> str:
    pyproject_version = _read_regex(
        ROOT / "pyproject.toml",
        r'^version\s*=\s*"([^"]+)"',
    )
    init_version = _read_regex(
        ROOT / "src" / "nah" / "__init__.py",
        r'^__version__\s*=\s*"([^"]+)"',
    )
    if pyproject_version != init_version:
        raise RuntimeError(
            "Version mismatch: "
            f"pyproject.toml has {pyproject_version}, "
            f"src/nah/__init__.py has {init_version}"
        )
    return pyproject_version


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _hook_command(script_name: str) -> str:
    return f'sh "${{CLAUDE_PLUGIN_ROOT}}/bin/{script_name}"'


def _generated_hooks() -> dict:
    sys.path.insert(0, str(ROOT / "src"))
    from nah import agents

    pre_tool_use = []
    for matcher in agents.AGENT_TOOL_MATCHERS[agents.CLAUDE]:
        pre_tool_use.append({
            "matcher": matcher,
            "hooks": [{
                "type": "command",
                "command": _hook_command("nah-plugin-hook"),
                "timeout": 10,
            }],
        })

    return {
        "description": "Run nah before Claude Code tool use.",
        "hooks": {
            "PreToolUse": pre_tool_use,
            "SessionStart": [{
                "hooks": [{
                    "type": "command",
                    "command": _hook_command("nah-plugin-session-start"),
                    "timeout": 5,
                }],
            }],
        },
    }


def _copy_artifact_skeleton(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        TEMPLATE_DIR,
        out,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def _set_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build(out: Path) -> None:
    version = _package_version()
    _copy_artifact_skeleton(out)

    plugin_json = _load_json(out / ".claude-plugin" / "plugin.json")
    plugin_json["version"] = version
    _write_json(out / ".claude-plugin" / "plugin.json", plugin_json)
    _write_json(out / "hooks" / "hooks.json", _generated_hooks())

    lib_dir = out / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        ROOT / "src" / "nah",
        lib_dir / "nah",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    _set_executable(out / "bin" / "nah-plugin-hook")
    _set_executable(out / "bin" / "nah-plugin-session-start")


def _files(root: Path) -> dict[str, Path]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): path
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _is_executable(path: Path) -> bool:
    return bool(path.stat().st_mode & stat.S_IXUSR)


def compare_dirs(expected: Path, actual: Path) -> list[str]:
    expected_files = _files(expected)
    actual_files = _files(actual)
    diffs: list[str] = []

    for rel in sorted(set(expected_files) - set(actual_files)):
        diffs.append(f"missing: {rel}")
    for rel in sorted(set(actual_files) - set(expected_files)):
        diffs.append(f"extra: {rel}")

    for rel in sorted(set(expected_files) & set(actual_files)):
        expected_path = expected_files[rel]
        actual_path = actual_files[rel]
        if expected_path.read_bytes() != actual_path.read_bytes():
            diffs.append(f"changed: {rel}")
        elif _is_executable(expected_path) != _is_executable(actual_path):
            diffs.append(f"mode changed: {rel}")

    return diffs


def check(out: Path) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="nah-plugin-check-") as tmp:
        expected = Path(tmp) / "nah"
        build(expected)
        return compare_dirs(expected, out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output directory (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the output directory already matches the generated artifact",
    )
    args = parser.parse_args(argv)

    out = args.out.resolve()
    try:
        _validate_out(out)
        if args.check:
            diffs = check(out)
            if diffs:
                print(f"Claude plugin artifact is stale: {out}", file=sys.stderr)
                for diff in diffs[:50]:
                    print(f"  {diff}", file=sys.stderr)
                if len(diffs) > 50:
                    print(f"  ... {len(diffs) - 50} more", file=sys.stderr)
                return 1
            print(f"Claude plugin artifact is up to date: {out}")
            return 0

        build(out)
        print(f"Built Claude plugin artifact: {out}")
        return 0
    except Exception as exc:
        print(f"build_claude_plugin.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
