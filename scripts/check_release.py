#!/usr/bin/env python3
"""Validate source and Claude plugin release metadata before publication."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHANGELOG = ROOT / "CHANGELOG.md"


def _read_regex(path: Path, pattern: str, description: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"Could not read {description} from {path}")
    return match.group(1)


def _package_version() -> str:
    pyproject_version = _read_regex(
        ROOT / "pyproject.toml",
        r'^version\s*=\s*"([^"]+)"',
        "project version",
    )
    init_version = _read_regex(
        ROOT / "src" / "nah" / "__init__.py",
        r'^__version__\s*=\s*"([^"]+)"',
        "package version",
    )
    if pyproject_version != init_version:
        raise RuntimeError(
            "Version mismatch: "
            f"pyproject.toml has {pyproject_version}, "
            f"src/nah/__init__.py has {init_version}"
        )
    return pyproject_version


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"Missing required JSON file: {path}")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected JSON object in {path}")
    return data


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _check_tag(tag: str, version: str) -> None:
    expected = f"v{version}"
    _require(
        tag == expected,
        f"Release tag {tag!r} does not match package version; expected {expected!r}",
    )


def _check_changelog(changelog: Path, version: str) -> None:
    if not changelog.exists():
        raise RuntimeError(f"Missing changelog: {changelog}")
    text = changelog.read_text(encoding="utf-8")
    pattern = rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}\s*$"
    _require(
        re.search(pattern, text, re.MULTILINE) is not None,
        f"CHANGELOG.md is missing dated release heading for {version}",
    )


def _find_plugin_entry(marketplace: dict[str, Any]) -> dict[str, Any]:
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list):
        raise RuntimeError("marketplace.json field 'plugins' must be a list")
    for entry in plugins:
        if isinstance(entry, dict) and entry.get("name") == "nah":
            return entry
    raise RuntimeError("marketplace.json is missing plugin entry named 'nah'")


def _check_marketplace(marketplace_root: Path, version: str) -> None:
    _require(
        marketplace_root.is_dir(),
        f"Marketplace root does not exist or is not a directory: {marketplace_root}",
    )

    marketplace = _load_json(marketplace_root / ".claude-plugin" / "marketplace.json")
    _require(marketplace.get("name") == "nah", "marketplace.json name must be 'nah'")

    metadata = marketplace.get("metadata")
    _require(isinstance(metadata, dict), "marketplace.json metadata must be an object")
    _require(
        metadata.get("version") == version,
        f"marketplace metadata.version must be {version!r}",
    )

    plugin_entry = _find_plugin_entry(marketplace)
    _require(plugin_entry.get("version") == version, f"marketplace plugin version must be {version!r}")
    _require(
        plugin_entry.get("source") == "./plugins/nah",
        "marketplace plugin source must be './plugins/nah'",
    )

    plugin_root = marketplace_root / "plugins" / "nah"
    plugin_manifest = _load_json(plugin_root / ".claude-plugin" / "plugin.json")
    _require(plugin_manifest.get("name") == "nah", "plugin.json name must be 'nah'")
    _require(plugin_manifest.get("version") == version, f"plugin.json version must be {version!r}")

    bundled_init = plugin_root / "lib" / "nah" / "__init__.py"
    bundled_version = _read_regex(
        bundled_init,
        r'^__version__\s*=\s*"([^"]+)"',
        "bundled plugin runtime version",
    )
    _require(
        bundled_version == version,
        f"bundled plugin runtime version must be {version!r}",
    )

    required_paths = [
        plugin_root / "hooks" / "hooks.json",
        plugin_root / "bin" / "nah-plugin-hook",
        plugin_root / "bin" / "nah-plugin-session-start",
        plugin_root / "runtime" / "nah_plugin_runner.py",
        plugin_root / "lib" / "nah" / "hook.py",
    ]
    for path in required_paths:
        _require(path.exists(), f"Generated plugin artifact is incomplete; missing {path}")


def check_release(tag: str, marketplace_root: Path, changelog: Path) -> str:
    version = _package_version()
    _check_tag(tag, version)
    _check_changelog(changelog, version)
    _check_marketplace(marketplace_root, version)
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Release source tag, for example v0.6.5")
    parser.add_argument(
        "--marketplace-root",
        type=Path,
        required=True,
        help="Generated Claude plugin marketplace root to validate",
    )
    parser.add_argument(
        "--changelog",
        type=Path,
        default=DEFAULT_CHANGELOG,
        help=f"Changelog path (default: {DEFAULT_CHANGELOG})",
    )
    args = parser.parse_args(argv)

    try:
        version = check_release(
            tag=args.tag,
            marketplace_root=args.marketplace_root.resolve(),
            changelog=args.changelog.resolve(),
        )
    except Exception as exc:
        print(f"check_release.py: {exc}", file=sys.stderr)
        return 1

    print(f"Release metadata verified for nah {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
