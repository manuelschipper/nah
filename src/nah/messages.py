"""Human-facing safety messages for nah decisions.

This module deliberately does not classify anything. It translates an existing
technical decision into short product copy for prompts and logs while leaving
the original reason/action metadata untouched.
"""

from __future__ import annotations

import re

from nah import taxonomy

_MAX_VALUE_CHARS = 72
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SPACE_RE = re.compile(r"\s+")
_BRACKETED_COMPOSITION_RE = re.compile(r"^\[([^\]]+)\]\s*")
_ACTION_ID_RE = re.compile(
    r"\b(?:"
    r"filesystem_(?:read|write|delete)|git_(?:safe|write|remote_write|discard|history_rewrite)|"
    r"network_(?:outbound|write|diagnostic)|package_(?:install|run|uninstall)|"
    r"lang_exec|process_signal|container_(?:read|write|exec|destructive)|"
    r"service_(?:read|write|destructive)|browser_(?:read|interact|state|navigate|exec|file)|"
    r"db_(?:read|write)|agent_(?:read|write|exec_read|exec_write|exec_remote|server|exec_bypass)|"
    r"obfuscated|unknown"
    r")\b"
)

_COMPOSITION_MESSAGES = {
    "network | exec": "this downloads code and runs it in bash",
    "sensitive_read | network": "this sends sensitive local data over the network",
    "decode | exec": "this decodes hidden content and runs it",
    "read | exec": "this runs code read from a local file or command output",
}

_ACTION_MESSAGES = {
    taxonomy.GIT_HISTORY_REWRITE: "this can rewrite Git history",
    taxonomy.GIT_DISCARD: "this can discard local Git changes",
    taxonomy.GIT_REMOTE_WRITE: "this writes to a remote Git repository",
    taxonomy.FILESYSTEM_WRITE: "this writes files",
    taxonomy.FILESYSTEM_DELETE: "this deletes files",
    taxonomy.NETWORK_OUTBOUND: "this contacts the network",
    taxonomy.NETWORK_WRITE: "this sends data over the network",
    taxonomy.LANG_EXEC: "this runs code",
    taxonomy.PACKAGE_UNINSTALL: "this uninstalls packages",
    taxonomy.PROCESS_SIGNAL: "this can stop or signal running processes",
    taxonomy.CONTAINER_EXEC: "this runs a command inside a container",
    taxonomy.CONTAINER_WRITE: "this changes container state",
    taxonomy.CONTAINER_DESTRUCTIVE: "this can remove or reset containers",
    taxonomy.SERVICE_WRITE: "this changes service state",
    taxonomy.SERVICE_DESTRUCTIVE: "this can stop or remove services",
    taxonomy.BROWSER_EXEC: "this runs code in a browser context",
    taxonomy.BROWSER_INTERACT: "this interacts with a browser",
    taxonomy.BROWSER_STATE: "this changes browser state",
    taxonomy.BROWSER_FILE: "this accesses browser-managed files",
    taxonomy.DB_WRITE: "this writes to a database",
    taxonomy.AGENT_WRITE: "this changes agent state",
    taxonomy.AGENT_EXEC_READ: "this runs an agent command that can read data",
    taxonomy.AGENT_EXEC_WRITE: "this runs an agent command that can change data",
    taxonomy.AGENT_EXEC_REMOTE: "this runs an agent command against a remote target",
    taxonomy.AGENT_SERVER: "this starts or changes an agent server",
    taxonomy.AGENT_EXEC_BYPASS: "this bypasses agent safety controls",
    taxonomy.OBFUSCATED: "this hides what will run",
    taxonomy.UNKNOWN: "this runs an unrecognized command",
}

_CONTENT_MESSAGES = {
    "secret": "this includes content that looks like a secret",
    "obfuscation": "this includes hidden or encoded code",
    "destructive": "this includes code that can delete or overwrite data",
    "exfiltration": "this includes code that can send local data over the network",
    "credential_access": "this includes code that can access credentials",
    "subprocess_execution": "this includes code that can run other commands",
}


def human_reason(
    reason: str = "",
    *,
    decision: str = "",
    action_type: str = "",
    tool: str = "",
    meta: dict | None = None,
) -> str:
    """Return a concise, sanitized sentence fragment for a decision."""
    meta = meta or {}
    clean_reason = _strip_wrappers(reason, tool)
    composition = _composition_from(meta, clean_reason)
    if composition in _COMPOSITION_MESSAGES:
        return _finalize(_COMPOSITION_MESSAGES[composition])
    if "remote code execution" in clean_reason.lower():
        return _finalize(_COMPOSITION_MESSAGES["network | exec"])

    pattern_message = _reason_pattern_message(clean_reason, tool)
    if pattern_message:
        return _finalize(pattern_message)

    chosen_action = action_type or _action_from_meta(meta, decision)
    if chosen_action in _ACTION_MESSAGES:
        return _finalize(_ACTION_MESSAGES[chosen_action])

    if decision == taxonomy.BLOCK:
        return "this was blocked before it could run"
    return "this needs confirmation before it can run"


def enrich_decision(decision: dict, *, tool: str = "") -> dict:
    """Attach one computed ``human_reason`` to a decision and its metadata."""
    d = decision.get("decision", "")
    if d not in (taxonomy.ASK, taxonomy.BLOCK):
        return decision
    meta = decision.setdefault("_meta", {})
    existing = decision.get("human_reason") or meta.get("human_reason")
    if existing:
        human = _finalize(str(existing))
    else:
        human = human_reason(
            decision.get("reason", ""),
            decision=d,
            tool=tool,
            meta=meta,
        )
    decision["human_reason"] = human
    meta["human_reason"] = human
    return decision


def brand(prefix: str, message: str) -> str:
    """Render a branded first line while preserving any following diagnostics."""
    first, sep, rest = str(message or "").partition("\n")
    first = _finalize(first) or "this needs confirmation before it can run"
    line = f"{prefix}: {first}{_terminal_punctuation(first)}"
    return f"{line}{sep}{rest}" if sep else line


def _terminal_punctuation(text: str) -> str:
    return "" if text.endswith((".", "!", "?")) else "."


def _finalize(text: str) -> str:
    text = _sanitize_text(text)
    text = re.sub(r"^(?:nah[\s:?.-]+)+", "", text, flags=re.IGNORECASE).strip()
    text = text.rstrip(" .")
    return text


def _sanitize_text(value: str) -> str:
    value = _CONTROL_RE.sub(" ", str(value or ""))
    value = _SPACE_RE.sub(" ", value)
    return value.strip()


def _sanitize_value(value: str, *, strip_host_punctuation: bool = False) -> str:
    value = _sanitize_text(value)
    if strip_host_punctuation:
        value = value.strip(" \t\r\n<>'\"`[]{}")
        value = value.rstrip(").,;:")
    else:
        value = value.strip()
    if len(value) > _MAX_VALUE_CHARS:
        value = value[: _MAX_VALUE_CHARS - 3].rstrip() + "..."
    return value


def _friendly_path(value: str) -> str:
    value = _sanitize_value(value).strip(" \t\r\n<>'\"`()[]{}").rstrip(".,;")
    if value.startswith("~") or value.startswith("."):
        return _sanitize_value(value)
    try:
        from nah.paths import friendly_path, resolve_path

        if value.startswith("/"):
            return _sanitize_value(friendly_path(resolve_path(value)))
    except Exception:
        pass
    return value


def _strip_wrappers(reason: str, tool: str = "") -> str:
    text = _sanitize_text(reason)
    if tool and text.startswith(f"{tool}:"):
        text = text[len(tool) + 1 :].strip()
    text = re.sub(r"^(?:Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep):\s*", "", text)
    text = re.sub(r"\s+\u2192\s+(?:ask|block|allow|context)\b", "", text)
    text = re.sub(r"\s+->\s+(?:ask|block|allow|context)\b", "", text)
    return text.strip()


def _composition_from(meta: dict, reason: str) -> str:
    comp = str(meta.get("composition_rule") or "").strip()
    if comp:
        return comp
    match = _BRACKETED_COMPOSITION_RE.match(reason)
    return match.group(1).strip() if match else ""


def _action_from_meta(meta: dict, decision: str) -> str:
    stages = meta.get("stages", [])
    if not isinstance(stages, list):
        return ""
    for stage in stages:
        if isinstance(stage, dict) and stage.get("decision") == decision:
            return str(stage.get("action_type") or "")
    for stage in stages:
        if isinstance(stage, dict) and stage.get("decision") != taxonomy.ALLOW:
            return str(stage.get("action_type") or "")
    for stage in stages:
        if isinstance(stage, dict):
            return str(stage.get("action_type") or "")
    return ""


def _reason_pattern_message(reason: str, tool: str) -> str:
    text = _strip_wrappers(reason, tool)
    lower = text.lower()

    content = re.search(r"content inspection \[([^\]]+)\]", text, flags=re.IGNORECASE)
    if content:
        categories = [part.strip() for part in content.group(1).split(",")]
        for category in ("secret", "obfuscation", "destructive", "exfiltration"):
            if category in categories:
                return _CONTENT_MESSAGES[category]
        for category in categories:
            if category in _CONTENT_MESSAGES:
                return _CONTENT_MESSAGES[category]
        return "this includes content that needs review"

    match = re.search(r"unknown host:\s*([^\s)]+)", text, flags=re.IGNORECASE)
    if match:
        return f"this contacts an untrusted host: {_sanitize_value(match.group(1), strip_host_punctuation=True)}"

    match = re.search(r"network_write to localhost:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return f"this sends data to a local service: {_sanitize_value(match.group(1), strip_host_punctuation=True)}"

    match = re.search(r"\bhost:\s*([^\s)]+)", text, flags=re.IGNORECASE)
    if "network_write" in lower and match:
        return f"this sends data over the network to: {_sanitize_value(match.group(1), strip_host_punctuation=True)}"

    match = re.search(r"targets sensitive path:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return f"this targets a protected file or folder: {_friendly_path(match.group(1))}"

    match = re.search(r"targets nah config:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return "this changes nah's own configuration"

    match = re.search(r"targets hook directory(?::\s*(.+))?", text, flags=re.IGNORECASE)
    if match:
        return "this tries to modify Claude Code hooks"

    match = re.search(r"\boutside project(?: \(no git root\))?:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return f"this writes outside the current project: {_friendly_path(match.group(1))}"
    if "outside project" in lower:
        return "this writes outside the current project"

    match = re.search(r"script not found:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return f"this tries to run a script that was not found: {_friendly_path(match.group(1))}"

    match = re.search(r"script not readable:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return f"this tries to run a script nah cannot read: {_friendly_path(match.group(1))}"

    if "terminal guard cannot safely run" in lower:
        return "this shell input is too complex to inspect safely"

    match = re.search(r"unrecognized tool:\s*(.+)$", text, flags=re.IGNORECASE)
    if match:
        return f"this uses an unrecognized tool: {_sanitize_value(match.group(1))}"

    if "credential search pattern" in lower:
        return "this searches for credential-looking content"

    if _ACTION_ID_RE.search(text):
        return ""
    return ""
