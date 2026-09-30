"""Extract recorded tool invocations without interpreting transcript prose."""

import hashlib
import json
import sqlite3
from collections import Counter

from session_json import canonical_session_json


def digest(value):
    return hashlib.sha256(canonical_session_json(value).encode()).hexdigest()


def recorded_tool_calls(payload):
    """Yield (event ordinal, block index, call ID, tool name, arguments) per recorded tool call; transcript prose never becomes a call."""
    for ordinal, event in enumerate(payload["events"]):
        if not isinstance(event, dict):
            continue
        message = event.get("message", event)
        if not isinstance(message, dict):
            continue
        # Codex records function calls in response_item payloads.
        if event.get("type") == "response_item":
            message = event.get("payload", {})
        if not isinstance(message, dict):
            continue
        if message.get("type") in ("function_call", "custom_tool_call"):
            yield ordinal, 0, message.get("call_id"), message.get("name"), message.get("arguments", message.get("input"))
        if message.get("role") == "assistant":
            content = message.get("content", [])
            if isinstance(content, list):
                for index, block in enumerate(content):
                    if isinstance(block, dict) and block.get("type") in ("tool_use", "toolCall"):
                        yield ordinal, index, block.get("id"), block.get("name"), block.get("input", block.get("arguments"))
            for index, call in enumerate(message.get("tool_calls") or message.get("tool_uses") or []):
                if isinstance(call, dict):
                    function = call.get("function", call)
                    if isinstance(function, dict):
                        yield ordinal, index, call.get("id"), function.get("name", function.get("tool")), function.get("arguments", function.get("input"))
        # SWE-agent trajectory records contain the executed action separately from prose.
        if payload["format"] == "trajectory" and isinstance(event.get("action"), str):
            yield ordinal, 0, None, "bash", {"command": event["action"]}


def subject_from_tool_call(name, arguments):
    """Map one recorded tool call to a coverage subject and extraction issue; unknown or unparsed calls stay tool.unknown."""
    if not isinstance(name, str) or not name:
        return None, "missing_tool_name"
    tool = name.removeprefix("functions.")
    if tool == "apply_patch" and isinstance(arguments, str) and arguments.startswith("*** Begin Patch"):
        return {"kind": "tool_call", "tool": "file.patch", "args": {"format": "apply_patch", "text": arguments}}, None
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            return {"kind": "tool_call", "tool": "tool.unknown", "args": {"name": name, "args": arguments}}, "unparsed_tool_arguments"
    if not isinstance(arguments, dict):
        return {"kind": "tool_call", "tool": "tool.unknown", "args": {"name": name, "args": arguments}}, "unparsed_tool_arguments"
    if tool in ("bash", "Bash", "shell_command", "exec_command", "execute_bash", "run_terminal_cmd", "terminal"):
        command = arguments.get("command", arguments.get("cmd"))
        if isinstance(command, str) and command.strip():
            return {"kind": "shell", "source": command}, None
    if tool == "shell" and isinstance(arguments.get("command"), list):
        argv = arguments["command"]
        if argv and all(isinstance(arg, str) for arg in argv):
            return {"kind": "exec", "argv": argv}, None
    path = arguments.get("file_path", arguments.get("path"))
    if isinstance(path, str) and path:
        if tool in ("Read", "read", "read_file"):
            return {"kind": "tool_call", "tool": "file.read", "args": {"path": path}}, None
        if tool in ("Write", "write", "write_file") and isinstance(arguments.get("content"), str):
            return {"kind": "tool_call", "tool": "file.write", "args": {"path": path, "content": arguments["content"]}}, None
        if tool in ("Edit", "edit"):
            old, new = arguments.get("old_string", arguments.get("oldText")), arguments.get("new_string", arguments.get("newText"))
            if isinstance(old, str) and old and isinstance(new, str):
                return {"kind": "tool_call", "tool": "file.edit", "args": {"path": path, "old": old, "new": new}}, None
    return {"kind": "tool_call", "tool": "tool.unknown", "args": {"name": name, "args": arguments}}, "unmapped_tool"


class SessionCallExport:
    """Deduplicate recorded tool calls into coverage cases while keeping every origin and issue in SQLite."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        # Hash-key deduplication needs more than SQLite's default 2 MiB cache.
        self.db.execute("PRAGMA cache_size = -262144")
        self.db.executescript("""
            CREATE TABLE cases (id TEXT PRIMARY KEY, subject TEXT NOT NULL);
            CREATE TABLE calls (id TEXT PRIMARY KEY, case_id TEXT NOT NULL);
            CREATE TABLE records (source TEXT, file TEXT, record INTEGER, context TEXT,
                                  PRIMARY KEY(source, file, record));
            CREATE TABLE origins (call_id TEXT, source TEXT, file TEXT, record INTEGER,
                                  event INTEGER, context TEXT,
                                  PRIMARY KEY(call_id, source, file, record, event));
            CREATE TABLE issues (source TEXT, file TEXT, record INTEGER, event INTEGER, reason TEXT);
        """)
        self.counts = Counter()

    def add(self, source, file, record, payload):
        self.counts["session_records"] += 1
        recorded_calls = list(recorded_tool_calls(payload))
        if not recorded_calls:
            self.issue(source, file, record, 0, "session_without_tool_calls")
            return
        # Ignore wrapper metadata when identifying identical exported sessions.
        session_id = digest(payload["events"])
        metadata = payload.get("metadata", {})
        for fields in (metadata, metadata.get("metadata")):
            if isinstance(fields, dict):
                for key in ("session_id", "sessionId", "trajectory_id", "traj_id"):
                    if isinstance(fields.get(key), str) and fields[key]:
                        session_id = digest(["recorded_session", fields[key]])
                        break
        context = {"metadata": metadata, "recorded_context": []}
        for event in payload["events"]:
            if not isinstance(event, dict):
                continue
            if event.get("type") in ("session", "session_meta"):
                data = event.get("payload", event)
                if isinstance(data, dict):
                    context["recorded_context"].append(data)
                    if isinstance(data.get("id"), str):
                        session_id = digest(["recorded_session", data["id"]])
            elif isinstance(event.get("sessionId", event.get("session_id")), str):
                session_id = digest(["recorded_session", event.get("sessionId", event.get("session_id"))])
        self.db.execute("INSERT OR IGNORE INTO records VALUES (?, ?, ?, ?)",
                        (source, file, record, canonical_session_json(context)))
        for ordinal, index, call_id, name, arguments in recorded_calls:
            self.counts["tool_call_records"] += 1
            value, issue = subject_from_tool_call(name, arguments)
            if issue:
                self.issue(source, file, record, ordinal, issue)
            if value is None:
                continue
            case_id = digest(value)
            # A repeated call ID is one invocation, even across mirrored or wrapped exports.
            identity = digest([session_id, call_id if call_id else [ordinal, index], case_id])
            self.db.execute("INSERT OR IGNORE INTO cases VALUES (?, ?)", (case_id, canonical_session_json(value)))
            self.db.execute("INSERT OR IGNORE INTO calls VALUES (?, ?)", (identity, case_id))
            self.db.execute("INSERT OR IGNORE INTO origins VALUES (?, ?, ?, ?, ?, ?)",
                            (identity, source, file, record, ordinal, canonical_session_json(arguments)))

    def issue(self, source, file, record, event, reason):
        self.counts[reason] += 1
        self.db.execute("INSERT INTO issues VALUES (?, ?, ?, ?, ?)", (source, file, record, event, reason))

    def finish(self, output):
        self.db.commit()
        with output.open("w") as stream:
            for key, value, weight in self.db.execute("SELECT cases.id, subject, count(*) FROM cases JOIN calls ON cases.id=calls.case_id GROUP BY cases.id ORDER BY cases.id"):
                stream.write(canonical_session_json({"id": key, "source": "sessions", "weight": weight, "subject": json.loads(value)}) + "\n")
        for table in ("records", "cases", "calls", "origins", "issues"):
            self.counts[table] = self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        self.db.close()
        return dict(self.counts)
