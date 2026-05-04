"""Codex apply_patch parsing and guarded decision helpers."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from nah import paths, taxonomy
from nah.content import format_content_message, scan_content


_SAFE_APPLY_PATCH_ENV = "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH"


@dataclass(frozen=True)
class PatchOperation:
    kind: str
    path: str
    dest_path: str = ""
    added_lines: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ParsedPatch:
    operations: tuple[PatchOperation, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        out: list[str] = []
        for op in self.operations:
            out.append(op.path)
            if op.dest_path:
                out.append(op.dest_path)
        return tuple(out)

    @property
    def added_content(self) -> str:
        lines: list[str] = []
        for op in self.operations:
            lines.extend(op.added_lines)
        return "\n".join(lines)

    @property
    def has_destructive_operation(self) -> bool:
        return any(op.kind in {"delete", "move"} for op in self.operations)

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for op in self.operations:
            counts[op.kind] = counts.get(op.kind, 0) + 1
        op_summary = ",".join(f"{kind}={counts[kind]}" for kind in sorted(counts))
        return f"{op_summary} paths={','.join(self.paths)}"


@dataclass(frozen=True)
class PatchText:
    text: str
    source: str


@dataclass(frozen=True)
class TranscriptPatchLookup:
    text: PatchText | None
    status: str


class PatchParseError(ValueError):
    """Raised when an apply_patch payload is not safe to classify."""


def classify_codex_apply_patch(tool_input: dict, payload: dict) -> tuple[dict, dict]:
    """Classify a Codex apply_patch request and return (decision, log input)."""
    patch_text = acquire_patch_text(tool_input, str(payload.get("transcript_path", "") or ""))
    if patch_text is None:
        return _ask("apply_patch: patch text unavailable"), _log_input([], "missing")

    try:
        parsed = parse_patch(patch_text.text)
    except PatchParseError as exc:
        return _ask(f"apply_patch: malformed patch: {exc}"), _log_input([], "malformed")

    cwd = str(payload.get("cwd", "") or "")
    resolved_paths = [_resolve_patch_path(p, cwd) for p in parsed.paths]
    log_input = _log_input(resolved_paths, parsed.summary())

    for raw_path in resolved_paths:
        path_decision = paths.check_path("Write", raw_path)
        if path_decision:
            return _with_stage(path_decision, _path_action(path_decision)), log_input
        boundary_decision = paths.check_project_boundary("apply_patch", raw_path)
        if boundary_decision:
            return _with_stage(boundary_decision, taxonomy.FILESYSTEM_WRITE), log_input

    content_decision = _scan_added_content(parsed.added_content)
    if content_decision.get("decision") == taxonomy.BLOCK:
        return content_decision, log_input

    if parsed.has_destructive_operation:
        return _ask("apply_patch: delete/move patch requires native approval"), log_input

    if content_decision.get("decision") == taxonomy.ALLOW:
        from nah import hook

        review_input = {
            "file_path": ", ".join(resolved_paths),
            "content": parsed.added_content,
        }
        content_decision = hook._llm_write_review_gate(
            "apply_patch",
            review_input,
            content_decision,
        )

    if content_decision.get("decision") != taxonomy.ALLOW:
        return _with_stage(content_decision, taxonomy.FILESYSTEM_WRITE), log_input

    if os.environ.get(_SAFE_APPLY_PATCH_ENV) == "1":
        meta = dict(content_decision.get("_meta", {}))
        meta["stages"] = [
            _stage(
                taxonomy.FILESYSTEM_WRITE,
                taxonomy.ALLOW,
                taxonomy.ALLOW,
                "safe apply_patch edit",
            )
        ]
        meta["source"] = patch_text.source
        return {
            "decision": taxonomy.ALLOW,
            "_meta": meta,
        }, log_input

    return _ask(
        "apply_patch: safe edit requires native approval in this mode",
        content_decision.get("_meta", {}),
    ), log_input


def acquire_patch_text(tool_input: dict, transcript_path: str = "") -> PatchText | None:
    """Return direct patch text or a strict unmatched transcript fallback."""
    direct = _direct_patch_text(tool_input)
    if direct is not None:
        lookup = _lookup_patch_text_from_transcript(transcript_path)
        if (
            lookup.status == "single"
            and lookup.text is not None
            and lookup.text.text != direct
        ):
            return None
        if lookup.status == "ambiguous":
            return None
        return PatchText(direct, "tool_input")
    return _patch_text_from_transcript(transcript_path)


def parse_patch(text: str) -> ParsedPatch:
    lines = text.splitlines()
    if not lines or lines[0] != "*** Begin Patch":
        raise PatchParseError("missing begin marker")
    end_index = _last_nonempty_index(lines)
    if end_index is None or lines[end_index] != "*** End Patch":
        raise PatchParseError("missing end marker")

    operations: list[PatchOperation] = []
    current_kind = ""
    current_path = ""
    current_dest = ""
    current_added: list[str] = []

    def finish_current() -> None:
        nonlocal current_kind, current_path, current_dest, current_added
        if not current_kind:
            return
        kind = "move" if current_dest else current_kind
        operations.append(PatchOperation(
            kind=kind,
            path=current_path,
            dest_path=current_dest,
            added_lines=tuple(current_added),
        ))
        current_kind = ""
        current_path = ""
        current_dest = ""
        current_added = []

    for line in lines[1:end_index]:
        if line.startswith("*** Add File: "):
            finish_current()
            current_kind = "add"
            current_path = _header_path(line, "*** Add File: ")
            continue
        if line.startswith("*** Update File: "):
            finish_current()
            current_kind = "update"
            current_path = _header_path(line, "*** Update File: ")
            continue
        if line.startswith("*** Delete File: "):
            finish_current()
            operations.append(PatchOperation("delete", _header_path(line, "*** Delete File: ")))
            continue
        if line.startswith("*** Move to: "):
            if current_kind != "update" or current_dest:
                raise PatchParseError("move header without update source")
            current_dest = _header_path(line, "*** Move to: ")
            continue
        if line.startswith("*** "):
            raise PatchParseError(f"unsupported header: {line[:60]}")
        if not current_kind:
            if line.strip():
                raise PatchParseError("content before file header")
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current_added.append(line[1:])

    finish_current()
    if not operations:
        raise PatchParseError("no file operations")
    return ParsedPatch(tuple(operations))


def _direct_patch_text(tool_input: dict) -> str | None:
    for key in ("input", "patch", "content", "command"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.startswith("*** Begin Patch"):
            return value
    return None


def _patch_text_from_transcript(transcript_path: str) -> PatchText | None:
    return _lookup_patch_text_from_transcript(transcript_path).text


def _lookup_patch_text_from_transcript(transcript_path: str) -> TranscriptPatchLookup:
    if not transcript_path:
        return TranscriptPatchLookup(None, "missing")
    pending: dict[str, str] = {}
    anonymous: list[str] = []
    try:
        with open(transcript_path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    # Codex transcripts are append-only JSONL. A torn line can
                    # happen while the TUI is writing; unrelated malformed lines
                    # are ignored, and missing/ambiguous patch state asks later.
                    continue
                payload = entry.get("payload")
                if (
                    not isinstance(payload, dict)
                    or entry.get("type") != "response_item"
                ):
                    continue
                item_type = payload.get("type")
                call_id = str(payload.get("call_id") or "")
                if item_type == "custom_tool_call_output" and call_id:
                    pending.pop(call_id, None)
                    continue
                if item_type != "custom_tool_call" or payload.get("name") != "apply_patch":
                    continue
                patch_input = payload.get("input")
                if (
                    not isinstance(patch_input, str)
                    or not patch_input.startswith("*** Begin Patch")
                ):
                    continue
                if call_id:
                    pending[call_id] = patch_input
                else:
                    anonymous.append(patch_input)
    except OSError:
        # Transcript fallback is best-effort. If Codex has not written or kept
        # a readable transcript, the safe behavior is no hook verdict so Codex
        # presents its native approval prompt.
        return TranscriptPatchLookup(None, "unreadable")

    candidates = list(pending.values()) + anonymous
    if len(candidates) != 1:
        return TranscriptPatchLookup(None, "missing" if not candidates else "ambiguous")
    return TranscriptPatchLookup(PatchText(candidates[0], "transcript"), "single")


def _scan_added_content(content: str) -> dict:
    matches = scan_content(content)
    if not matches:
        return {"decision": taxonomy.ALLOW}
    return {
        "decision": taxonomy.BLOCK,
        "reason": format_content_message("apply_patch", matches),
        "_meta": {
            "content_match": ", ".join(m.pattern_desc for m in matches),
            "stages": [
                _stage(
                    taxonomy.FILESYSTEM_WRITE,
                    taxonomy.BLOCK,
                    taxonomy.BLOCK,
                    "apply_patch added dangerous content",
                )
            ],
        },
        "_hint": "(content varies per call — cannot be remembered)",
    }


def _resolve_patch_path(path: str, cwd: str) -> str:
    expanded = os.path.expanduser(path)
    if os.path.isabs(expanded) or not cwd:
        return expanded
    return os.path.join(cwd, expanded)


def _header_path(line: str, prefix: str) -> str:
    path = line[len(prefix):].strip()
    if not path:
        raise PatchParseError("empty path")
    return path


def _last_nonempty_index(lines: list[str]) -> int | None:
    for idx in range(len(lines) - 1, -1, -1):
        if lines[idx].strip():
            return idx
    return None


def _with_stage(decision: dict, action_type: str) -> dict:
    decision = dict(decision)
    meta = dict(decision.get("_meta", {}))
    meta.setdefault("stages", [_stage(
        action_type,
        decision.get("decision", taxonomy.ASK),
        decision.get("decision", taxonomy.ASK),
        decision.get("reason", ""),
    )])
    decision["_meta"] = meta
    return decision


def _ask(reason: str, meta: dict | None = None) -> dict:
    merged_meta = dict(meta or {})
    merged_meta["stages"] = [
        _stage(taxonomy.FILESYSTEM_WRITE, taxonomy.ASK, taxonomy.ASK, reason)
    ]
    return {
        "decision": taxonomy.ASK,
        "reason": reason,
        "_meta": merged_meta,
    }


def _stage(action_type: str, decision: str, policy: str, reason: str) -> dict:
    return {
        "action_type": action_type,
        "decision": decision,
        "policy": policy,
        "reason": reason,
    }


def _path_action(decision: dict) -> str:
    reason = decision.get("reason", "")
    if "delete" in reason.lower():
        return taxonomy.FILESYSTEM_DELETE
    return taxonomy.FILESYSTEM_WRITE


def _log_input(paths_: list[str], summary: str) -> dict:
    return {
        "_nah_patch_paths": paths_,
        "_nah_patch_summary": summary,
    }
