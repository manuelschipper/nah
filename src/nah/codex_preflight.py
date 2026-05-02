"""Codex preflight scanner for approval-memory and MCP bypass state."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


PROMPT = "prompt"
_MCP_POLICY_KINDS = {
    "mcp_default",
    "mcp_tool",
    "plugin_mcp_default",
    "plugin_mcp_tool",
}
_RULE_KINDS = {"exec_policy_allow", "exec_policy_unknown"}


class CodexPreflightError(Exception):
    """Raised when Codex state can bypass nah's hook path."""


@dataclass(frozen=True)
class Finding:
    """A Codex preflight finding."""

    kind: str
    message: str
    path: str = ""
    line: int = 0
    end_line: int = 0
    blocking: bool = True
    repairable: bool = True
    table_path: tuple[str, ...] = field(default_factory=tuple)
    key: str = ""
    plugin: str = ""
    server: str = ""
    tool: str = ""


@dataclass
class RepairResult:
    """Result of an explicit Codex preflight repair."""

    findings: list[Finding] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    backups: list[str] = field(default_factory=list)
    unrepaired: list[Finding] = field(default_factory=list)


@dataclass
class _Table:
    path: tuple[str, ...]
    line: int
    values: dict[str, tuple[str, int]] = field(default_factory=dict)


def codex_home() -> Path:
    """Return Codex's state directory."""
    raw = os.environ.get("CODEX_HOME")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".codex"


def scan_preflight(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
) -> list[Finding]:
    """Scan Codex state that can bypass nah's PermissionRequest hook."""
    root = home or codex_home()
    workdir = cwd or Path.cwd()
    findings: list[Finding] = []

    for rule_path in _rule_paths(root, workdir):
        findings.extend(_scan_rules_file(rule_path))

    config_paths = _config_paths(root, workdir)
    for config_path in config_paths:
        findings.extend(_scan_config_file(config_path, root))

    return findings


def blocking_findings(findings: list[Finding]) -> list[Finding]:
    """Return only findings that should block Codex startup."""
    return [finding for finding in findings if finding.blocking]


def ensure_preflight(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
) -> list[Finding]:
    """Raise when preflight finds Codex state that can skip nah."""
    findings = scan_preflight(home=home, cwd=cwd)
    blockers = blocking_findings(findings)
    if blockers:
        raise CodexPreflightError(format_block_message(blockers))
    return findings


def format_doctor_output(findings: list[Finding]) -> str:
    """Render findings for `nah codex doctor`."""
    if not findings:
        return "nah codex: no approval-memory or MCP preflight issues found."
    lines = ["nah codex: approval-memory/MCP preflight findings:"]
    lines.extend(_format_finding_lines(findings))
    if any(f.repairable for f in findings):
        lines.append("Run `nah codex repair` to back up and repair supported files.")
    return "\n".join(lines)


def format_block_message(findings: list[Finding]) -> str:
    """Render startup block text for `nah run codex`."""
    lines = ["nah run codex: Codex approval state can bypass nah."]
    lines.extend(_format_finding_lines(findings))
    if any(f.repairable for f in findings):
        lines.append("Run `nah codex repair`, then retry `nah run codex`.")
    return "\n".join(lines)


def repair_preflight(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
) -> RepairResult:
    """Repair supported Codex preflight findings after creating backups."""
    root = home or codex_home()
    workdir = cwd or Path.cwd()
    findings = scan_preflight(home=root, cwd=workdir)
    result = RepairResult(findings=findings)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    rule_ranges: dict[str, list[tuple[int, int]]] = {}
    for finding in findings:
        if finding.kind in _RULE_KINDS and finding.repairable and finding.path and finding.line:
            end_line = finding.end_line or finding.line
            rule_ranges.setdefault(finding.path, []).append((finding.line, end_line))

    for path, ranges in rule_ranges.items():
        changed, backup = _remove_rule_ranges(Path(path), ranges, timestamp)
        if changed:
            result.changed.append(path)
            if backup:
                result.backups.append(str(backup))

    config_findings = [
        finding
        for finding in findings
        if finding.kind in _MCP_POLICY_KINDS
        and finding.repairable
        and finding.path
        and finding.table_path
        and finding.key
    ]
    for path in sorted({finding.path for finding in config_findings}):
        edits = [
            (finding.table_path, finding.key, PROMPT)
            for finding in config_findings
            if finding.path == path
        ]
        changed, backup = _ensure_toml_values(Path(path), edits, timestamp)
        if changed:
            result.changed.append(path)
            if backup:
                result.backups.append(str(backup))

    repaired = set(result.changed)
    for finding in findings:
        if finding.blocking and (
            not finding.repairable
            or (finding.repairable and finding.path and finding.path not in repaired)
        ):
            result.unrepaired.append(finding)
    return result


def _format_finding_lines(findings: list[Finding]) -> list[str]:
    lines = []
    for finding in findings:
        location = finding.path or "Codex config"
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.append(f"- {location}: {finding.message}")
    return lines


def _rule_paths(root: Path, workdir: Path) -> list[Path]:
    paths: list[Path] = []
    user_rules = root / "rules"
    if user_rules.is_dir():
        paths.extend(sorted(user_rules.glob("*.rules")))
    for parent in _walk_project_ancestors(workdir):
        project_rules = parent / ".codex" / "rules"
        if project_rules.is_dir():
            paths.extend(sorted(project_rules.glob("*.rules")))
    return _dedupe_paths(paths)


def _config_paths(root: Path, workdir: Path) -> list[Path]:
    paths = []
    user_config = root / "config.toml"
    if user_config.exists():
        paths.append(user_config)
    for parent in _walk_project_ancestors(workdir):
        project_config = parent / ".codex" / "config.toml"
        if project_config.exists():
            paths.append(project_config)
    return _dedupe_paths(paths)


def _walk_ancestors(path: Path) -> list[Path]:
    try:
        start = path.resolve()
    except OSError:
        start = path.absolute()
    if start.is_file():
        start = start.parent
    return [start, *start.parents]


def _walk_project_ancestors(path: Path) -> list[Path]:
    """Return workspace ancestors, excluding the user's Codex home location."""
    try:
        user_home = Path.home().resolve()
    except OSError:
        user_home = Path.home()
    out = []
    for parent in _walk_ancestors(path):
        if parent == user_home:
            break
        out.append(parent)
    return out


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _scan_rules_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [Finding(
            kind="exec_policy_unknown",
            path=str(path),
            message=f"cannot read Codex exec-policy rules: {exc}",
            repairable=False,
        )]
    except UnicodeDecodeError as exc:
        return [Finding(
            kind="exec_policy_unknown",
            path=str(path),
            message=f"cannot decode Codex exec-policy rules: {exc}",
            repairable=False,
        )]

    findings: list[Finding] = []
    lines = text.splitlines()
    for kind, call, start, end in _iter_rule_calls(lines):
        decision = _extract_rule_decision(call)
        if decision is None:
            findings.append(Finding(
                kind="exec_policy_unknown",
                path=str(path),
                line=start,
                end_line=end,
                message=f"cannot determine Codex {kind} decision",
            ))
            continue
        if decision != "allow":
            continue
        detail = ""
        if kind == "prefix_rule":
            pattern = _extract_rule_pattern(call)
            if pattern:
                detail = f" for `{_shell_join(pattern)}`"
        findings.append(Finding(
            kind="exec_policy_allow",
            path=str(path),
            line=start,
            end_line=end,
            message=f"remembered Codex {kind} allow{detail} can skip nah",
        ))
    return findings


def _iter_rule_calls(lines: list[str]) -> list[tuple[str, str, int, int]]:
    calls: list[tuple[str, str, int, int]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        positions = [(name, line.find(name + "(")) for name in ("prefix_rule", "network_rule")]
        positions = [(name, pos) for name, pos in positions if pos >= 0]
        if not positions:
            i += 1
            continue
        name, pos = min(positions, key=lambda item: item[1])
        start = i + 1
        chunks = [line[pos:]]
        balance = _paren_balance(line[pos:])
        while balance > 0 and i + 1 < len(lines):
            i += 1
            chunks.append(lines[i])
            balance += _paren_balance(lines[i])
        end = i + 1
        calls.append((name, "\n".join(chunks), start, end))
        i += 1
    return calls


def _paren_balance(text: str) -> int:
    balance = 0
    quote = ""
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            balance += 1
        elif ch == ")":
            balance -= 1
    return balance


def _extract_rule_decision(call: str) -> str | None:
    match = re.search(
        r"decision\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z_][A-Za-z0-9_.]*))",
        call,
    )
    if not match:
        return None
    raw = next(group for group in match.groups() if group)
    return raw.rsplit(".", 1)[-1].lower()


def _extract_rule_pattern(call: str) -> list[str]:
    match = re.search(r"pattern\s*=\s*\[([^\]]*)\]", call, re.DOTALL)
    if not match:
        return []
    return re.findall(r"\"([^\"]+)\"|'([^']+)'", match.group(1))


def _shell_join(tokens: list[str] | list[tuple[str, str]]) -> str:
    parts = []
    for token in tokens:
        if isinstance(token, tuple):
            token = token[0] or token[1]
        if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", str(token)):
            parts.append(str(token))
        else:
            parts.append(json.dumps(str(token)))
    return " ".join(parts)


def _scan_config_file(path: Path, root: Path) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [Finding(
            kind="mcp_config_unknown",
            path=str(path),
            message=f"cannot read Codex config: {exc}",
            repairable=False,
        )]
    except UnicodeDecodeError as exc:
        return [Finding(
            kind="mcp_config_unknown",
            path=str(path),
            message=f"cannot decode Codex config: {exc}",
            repairable=False,
        )]

    tables = _parse_toml_tables(lines)
    findings: list[Finding] = _scan_config_shape_errors(path, lines)
    findings.extend(_scan_custom_mcp_tables(path, tables))
    findings.extend(_scan_plugin_overlays(path, tables))
    findings.extend(_scan_plugin_manifests(path, root, tables))
    return _dedupe_findings(findings)


def _scan_config_shape_errors(path: Path, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for idx, raw in enumerate(lines, 1):
        line = _strip_comment(raw).strip()
        if not line.startswith("["):
            if _is_inline_mcp_or_plugin_table(line):
                findings.append(Finding(
                    kind="mcp_config_unknown",
                    path=str(path),
                    line=idx,
                    message="cannot evaluate inline Codex MCP/plugin config",
                    repairable=False,
                ))
            continue
        if line.endswith("]"):
            continue
        if "mcp_servers" not in line and "plugins" not in line:
            continue
        findings.append(Finding(
            kind="mcp_config_unknown",
            path=str(path),
            line=idx,
            message="cannot parse Codex MCP/plugin config table",
            repairable=False,
        ))
    return findings


def _is_inline_mcp_or_plugin_table(line: str) -> bool:
    if "=" not in line or "{" not in line:
        return False
    key, value = line.split("=", 1)
    key = key.strip().strip("'\"")
    compact = value.strip().replace(" ", "")
    if compact in {"{}", "{},", ""}:
        return False
    return key in {"mcp_servers", "plugins"}


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for finding in findings:
        key = (
            finding.kind,
            finding.path,
            finding.table_path,
            finding.key,
            finding.line,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _parse_toml_tables(lines: list[str]) -> dict[tuple[str, ...], _Table]:
    tables: dict[tuple[str, ...], _Table] = {}
    current = _Table((), 1)
    tables[current.path] = current
    for idx, raw in enumerate(lines, 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            path = tuple(_split_table_path(line.strip("[]").strip()))
            current = tables.setdefault(path, _Table(path, idx))
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().strip("'\"")
        current.values[key] = (value.strip().rstrip(","), idx)
    return tables


def _strip_comment(line: str) -> str:
    quote = ""
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch == "#":
            return line[:idx]
    return line


def _split_table_path(raw: str) -> list[str]:
    parts: list[str] = []
    current = []
    quote = ""
    escaped = False
    for ch in raw:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            else:
                current.append(ch)
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch == ".":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def _scan_custom_mcp_tables(path: Path, tables: dict[tuple[str, ...], _Table]) -> list[Finding]:
    findings: list[Finding] = []
    server_paths = sorted(p for p in tables if len(p) == 2 and p[0] == "mcp_servers")
    for server_path in server_paths:
        server = server_path[1]
        table = tables[server_path]
        if not _enabled(table):
            continue
        mode = _string_value(table.values.get("default_tools_approval_mode", ("", 0))[0])
        if mode != PROMPT:
            findings.append(Finding(
                kind="mcp_default",
                path=str(path),
                line=table.line,
                message=_mode_message("MCP server", server, mode),
                table_path=server_path,
                key="default_tools_approval_mode",
                server=server,
            ))
        findings.extend(_scan_tool_tables(path, tables, ("mcp_servers", server), server=server))
    return findings


def _scan_plugin_overlays(path: Path, tables: dict[tuple[str, ...], _Table]) -> list[Finding]:
    findings: list[Finding] = []
    for table_path, table in sorted(tables.items()):
        if len(table_path) != 4 or table_path[0] != "plugins" or table_path[2] != "mcp_servers":
            continue
        plugin = table_path[1]
        server = table_path[3]
        if not _plugin_enabled(tables, plugin) or not _enabled(table):
            continue
        mode = _string_value(table.values.get("default_tools_approval_mode", ("", 0))[0])
        if mode != PROMPT:
            findings.append(Finding(
                kind="plugin_mcp_default",
                path=str(path),
                line=table.line,
                message=_mode_message(f"plugin `{plugin}` MCP server", server, mode),
                table_path=table_path,
                key="default_tools_approval_mode",
                plugin=plugin,
                server=server,
            ))
        findings.extend(_scan_tool_tables(
            path,
            tables,
            ("plugins", plugin, "mcp_servers", server),
            plugin=plugin,
            server=server,
        ))
    return findings


def _scan_tool_tables(
    path: Path,
    tables: dict[tuple[str, ...], _Table],
    base: tuple[str, ...],
    *,
    server: str,
    plugin: str = "",
) -> list[Finding]:
    findings = []
    for tool_path, table in sorted(tables.items()):
        if len(tool_path) != len(base) + 2:
            continue
        if tool_path[: len(base)] != base or tool_path[len(base)] != "tools":
            continue
        raw_mode = table.values.get("approval_mode")
        if raw_mode is None:
            continue
        mode = _string_value(raw_mode[0])
        if mode == PROMPT:
            continue
        tool = tool_path[-1]
        kind = "plugin_mcp_tool" if plugin else "mcp_tool"
        owner = f"plugin `{plugin}` MCP tool" if plugin else "MCP tool"
        findings.append(Finding(
            kind=kind,
            path=str(path),
            line=raw_mode[1],
            message=_mode_message(owner, f"{server}.{tool}", mode),
            table_path=tool_path,
            key="approval_mode",
            plugin=plugin,
            server=server,
            tool=tool,
        ))
    return findings


def _scan_plugin_manifests(
    path: Path,
    root: Path,
    tables: dict[tuple[str, ...], _Table],
) -> list[Finding]:
    if _feature_disabled(tables, "plugins"):
        return []
    findings: list[Finding] = []
    for plugin in _active_plugins(tables):
        roots = _plugin_roots(root, plugin)
        if not roots:
            plugin_table = tables.get(("plugins", plugin))
            findings.append(Finding(
                kind="plugin_mcp_default",
                path=str(path),
                line=plugin_table.line if plugin_table else 1,
                message=f"active plugin `{plugin}` cannot be evaluated before launch",
                table_path=("plugins", plugin),
                key="enabled",
                plugin=plugin,
                repairable=False,
            ))
            continue
        for plugin_root in roots:
            mcp_path = plugin_root / ".mcp.json"
            if not mcp_path.exists():
                continue
            findings.extend(_scan_plugin_mcp_manifest(path, mcp_path, plugin, tables))
    return findings


def _feature_disabled(tables: dict[tuple[str, ...], _Table], name: str) -> bool:
    features = tables.get(("features",))
    if not features:
        return False
    return _bool_value(features.values.get(name, ("", 0))[0]) is False


def _active_plugins(tables: dict[tuple[str, ...], _Table]) -> list[str]:
    plugins = []
    for path, table in tables.items():
        if len(path) == 2 and path[0] == "plugins" and _enabled(table):
            plugins.append(path[1])
    return sorted(plugins)


def _plugin_roots(root: Path, plugin: str) -> list[Path]:
    if "@" not in plugin:
        return []
    name, marketplace = plugin.rsplit("@", 1)
    cache_root = root / "plugins" / "cache" / marketplace / name
    if not cache_root.is_dir():
        return []
    return sorted(path for path in cache_root.iterdir() if path.is_dir())


def _scan_plugin_mcp_manifest(
    config_path: Path,
    manifest_path: Path,
    plugin: str,
    tables: dict[tuple[str, ...], _Table],
) -> list[Finding]:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [Finding(
            kind="plugin_mcp_default",
            path=str(config_path),
            message=f"plugin `{plugin}` MCP manifest is unreadable: {manifest_path}: {exc}",
            plugin=plugin,
            repairable=False,
        )]
    servers = data.get("mcpServers", {}) if isinstance(data, dict) else {}
    if not isinstance(servers, dict):
        return [Finding(
            kind="plugin_mcp_default",
            path=str(config_path),
            message=f"plugin `{plugin}` MCP manifest has invalid mcpServers: {manifest_path}",
            plugin=plugin,
            repairable=False,
        )]
    findings: list[Finding] = []
    for server in sorted(servers):
        table_path = ("plugins", plugin, "mcp_servers", str(server))
        table = tables.get(table_path)
        if table and not _enabled(table):
            continue
        mode = _string_value(table.values.get("default_tools_approval_mode", ("", 0))[0]) if table else ""
        if mode != PROMPT:
            line = table.line if table else tables.get(("plugins", plugin), _Table((), 1)).line
            findings.append(Finding(
                kind="plugin_mcp_default",
                path=str(config_path),
                line=line,
                message=_mode_message(f"plugin `{plugin}` MCP server", str(server), mode),
                table_path=table_path,
                key="default_tools_approval_mode",
                plugin=plugin,
                server=str(server),
            ))
    return findings


def _plugin_enabled(tables: dict[tuple[str, ...], _Table], plugin: str) -> bool:
    table = tables.get(("plugins", plugin))
    return True if table is None else _enabled(table)


def _enabled(table: _Table) -> bool:
    raw = table.values.get("enabled")
    if raw is None:
        return True
    parsed = _bool_value(raw[0])
    return True if parsed is None else parsed


def _bool_value(raw: str) -> bool | None:
    value = raw.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _string_value(raw: str) -> str:
    value = raw.strip().rstrip(",")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip().lower()
    return value.strip().lower()


def _mode_message(owner: str, name: str, mode: str) -> str:
    shown = mode or "missing"
    return f"{owner} `{name}` approval mode is `{shown}`; nah requires `prompt`"


def _remove_rule_ranges(
    path: Path,
    ranges: list[tuple[int, int]],
    timestamp: str,
) -> tuple[bool, Path | None]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        return False, None
    indexes: set[int] = set()
    for start, end in ranges:
        indexes.update(range(max(start, 1) - 1, min(end, len(lines))))
    if not indexes:
        return False, None
    new_lines = [line for idx, line in enumerate(lines) if idx not in indexes]
    backup = _backup(path, timestamp)
    path.write_text("".join(new_lines), encoding="utf-8")
    return True, backup


def _ensure_toml_values(
    path: Path,
    edits: list[tuple[tuple[str, ...], str, str]],
    timestamp: str,
) -> tuple[bool, Path | None]:
    original = path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []
    lines = list(original)
    changed = False
    for table_path, key, value in edits:
        rendered = _render_table_path(table_path)
        assignment = f'{key} = "{value}"\n'
        start, end = _find_table_range(lines, table_path)
        if start is None:
            if lines and lines[-1].strip():
                lines.append("\n")
            lines.extend([f"[{rendered}]\n", assignment])
            changed = True
            continue
        key_idx = _find_key_index(lines, start + 1, end, key)
        if key_idx is None:
            lines.insert(start + 1, assignment)
            changed = True
        elif lines[key_idx] != assignment:
            lines[key_idx] = assignment
            changed = True
    if not changed:
        return False, None
    backup = _backup(path, timestamp) if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(lines), encoding="utf-8")
    return True, backup


def _find_table_range(
    lines: list[str],
    table_path: tuple[str, ...],
) -> tuple[int | None, int]:
    start: int | None = None
    end = len(lines)
    for idx, line in enumerate(lines):
        stripped = _strip_comment(line).strip()
        if not stripped.startswith("[") or not stripped.endswith("]"):
            continue
        parsed = tuple(_split_table_path(stripped.strip("[]").strip()))
        if parsed == table_path:
            start = idx
            continue
        if start is not None:
            end = idx
            break
    return start, end


def _find_key_index(lines: list[str], start: int, end: int, key: str) -> int | None:
    for idx in range(start, end):
        line = _strip_comment(lines[idx]).strip()
        if "=" not in line:
            continue
        raw_key = line.split("=", 1)[0].strip().strip("'\"")
        if raw_key == key:
            return idx
    return None


def _render_table_path(path: tuple[str, ...]) -> str:
    return ".".join(_render_key(part) for part in path)


def _render_key(part: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", part):
        return part
    return json.dumps(part)


def _backup(path: Path, timestamp: str) -> Path:
    backup = path.with_name(f"{path.name}.nah-bak-{timestamp}")
    counter = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.nah-bak-{timestamp}.{counter}")
        counter += 1
    shutil.copy2(path, backup)
    return backup
