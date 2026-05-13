"""Managed Codex exec-policy prompt rules for nah-owned authority routing."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


AUTHORITY_RULES_FILE = "nah-authority.rules"
AUTHORITY_RULES_MARKER = "# nah-managed codex authority rules"
AUTHORITY_RULES_VERSION = "1"
AUTHORITY_RULES_HASH_PREFIX = "# nah-managed-sha256: "
_AUTHORITY_RULES_TMP_PREFIX = ".nah-authority.rules.tmp"
_AUTHORITY_RULES_JUSTIFICATION = "Route Codex known-safe commands through nah."

AUTHORITY_RULE_PREFIXES: tuple[str, ...] = (
    "base64",
    "bash",
    "cat",
    "cd",
    "cut",
    "echo",
    "expr",
    "false",
    "find",
    "git",
    "grep",
    "head",
    "id",
    "ls",
    "nl",
    "numfmt",
    "paste",
    "powershell",
    "powershell.exe",
    "pwd",
    "pwsh",
    "pwsh.exe",
    "rev",
    "rg",
    "sed",
    "seq",
    "stat",
    "tac",
    "tail",
    "tr",
    "true",
    "uname",
    "uniq",
    "wc",
    "which",
    "whoami",
    "zsh",
)


class CodexAuthorityError(Exception):
    """Raised when nah cannot safely manage Codex authority rules."""


@dataclass(frozen=True)
class AuthorityRulesStatus:
    """Current state of nah's managed Codex authority rules file."""

    path: Path
    state: str
    current: bool
    managed: bool
    repairable: bool
    message: str


def codex_home(env: Mapping[str, str] | None = None) -> Path:
    """Return Codex's state directory for an optional environment mapping."""
    source = env if env is not None else os.environ
    raw = source.get("CODEX_HOME")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".codex"


def authority_rules_path(home: Path | None = None) -> Path:
    """Return the nah-managed Codex exec-policy rules path."""
    root = home or codex_home()
    return root / "rules" / AUTHORITY_RULES_FILE


def render_authority_rules() -> str:
    """Render deterministic prompt rules for Codex-known-safe command prefixes."""
    body = _render_rules_body()
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    header = "\n".join([
        AUTHORITY_RULES_MARKER,
        f"# version: {AUTHORITY_RULES_VERSION}",
        f"{AUTHORITY_RULES_HASH_PREFIX}{digest}",
        "# Regenerate with `nah codex repair`; do not edit manually.",
        "",
    ])
    return f"{header}{body}"


def expected_authority_hash() -> str:
    """Return the expected hash for the generated rules body."""
    return hashlib.sha256(_render_rules_body().encode("utf-8")).hexdigest()


def authority_rules_status(home: Path | None = None) -> AuthorityRulesStatus:
    """Inspect the managed Codex authority rules file."""
    path = authority_rules_path(home)
    expected = render_authority_rules()
    if not path.exists():
        return AuthorityRulesStatus(
            path=path,
            state="missing",
            current=False,
            managed=False,
            repairable=True,
            message="nah Codex authority rules are missing",
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return AuthorityRulesStatus(
            path=path,
            state="unreadable",
            current=False,
            managed=False,
            repairable=False,
            message=f"cannot read nah Codex authority rules: {exc}",
        )
    except UnicodeDecodeError as exc:
        return AuthorityRulesStatus(
            path=path,
            state="undecodable",
            current=False,
            managed=False,
            repairable=False,
            message=f"cannot decode nah Codex authority rules: {exc}",
        )
    if text == expected:
        return AuthorityRulesStatus(
            path=path,
            state="current",
            current=True,
            managed=True,
            repairable=False,
            message="nah Codex authority rules are current",
        )
    if is_managed_authority_rules(text):
        return AuthorityRulesStatus(
            path=path,
            state="stale",
            current=False,
            managed=True,
            repairable=True,
            message="nah Codex authority rules are stale",
        )
    return AuthorityRulesStatus(
        path=path,
        state="unmanaged",
        current=False,
        managed=False,
        repairable=False,
        message="nah Codex authority rules path contains unmanaged content",
    )


def ensure_authority_rules(home: Path | None = None) -> AuthorityRulesStatus:
    """Install or refresh nah's managed Codex authority rules."""
    status = authority_rules_status(home)
    if status.current:
        return status
    if status.state == "unmanaged":
        raise CodexAuthorityError(
            f"{status.path} exists but is not managed by nah; move it aside or "
            "delete it before running `nah codex repair`.",
        )
    if not status.repairable:
        raise CodexAuthorityError(status.message)

    path = status.path
    expected = render_authority_rules()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{_AUTHORITY_RULES_TMP_PREFIX}.{os.getpid()}")
        tmp.write_text(expected, encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            if "tmp" in locals() and tmp.exists():
                tmp.unlink()
        except OSError:
            # Best-effort cleanup for a temp file we just created. The launch
            # still fails below so the unsafe fallback is not hidden.
            pass
        raise CodexAuthorityError(f"failed to write {path}: {exc}") from exc
    return authority_rules_status(home)


def remove_authority_rules(home: Path | None = None) -> Path | None:
    """Remove nah's managed authority rules file, refusing unmanaged content."""
    status = authority_rules_status(home)
    if status.state == "missing":
        return None
    if not status.managed:
        raise CodexAuthorityError(
            f"{status.path} exists but is not managed by nah; refusing to remove it.",
        )
    try:
        status.path.unlink()
    except OSError as exc:
        raise CodexAuthorityError(f"failed to remove {status.path}: {exc}") from exc
    return status.path


def is_managed_authority_rules(text: str) -> bool:
    """Return whether rules text carries nah's managed marker."""
    first_lines = text.splitlines()[:4]
    return AUTHORITY_RULES_MARKER in first_lines


def _render_rules_body() -> str:
    lines = []
    for prefix in AUTHORITY_RULE_PREFIXES:
        lines.extend([
            "prefix_rule(",
            f"    pattern = [{json.dumps(prefix)}],",
            '    decision = "prompt",',
            f"    justification = {json.dumps(_AUTHORITY_RULES_JUSTIFICATION)},",
            ")",
            "",
        ])
    return "\n".join(lines)
