import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("session_datasets", Path(__file__).with_name("session-datasets.py"))
datasets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(datasets)


def file_record(path, content):
    return {"path": path, "bytes": len(content), "hash": {"algorithm": "sha256", "value": hashlib.sha256(content).hexdigest()}}


class SessionDatasets(unittest.TestCase):
    # SWE-chat timestamp metadata must not abort extraction of otherwise valid calls.
    def test_parquet_nanosecond_timestamps_retain_precision(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sessions.parquet"
            table = pa.table({"timestamp": pa.array([1770798834310650256], type=pa.timestamp("ns")),
                              "messages": ['[{"role":"assistant","content":[]}]']})
            pq.write_table(table, path)
            row = next(datasets.records(path, []))[1]
            self.assertTrue(row["timestamp"].endswith(".310650256"))
            self.assertIsNotNone(datasets.session(row))

    # Mirrors and wrapper copies must not inflate occurrence weights, and prose/tool
    # results must not become commands. Unknown tools must remain scored boundaries.
    def test_export_scores_recorded_calls_and_preserves_duplicate_origins(self):
        from session_calls import SessionCallExport, recorded_tool_calls
        events = [
            {"type": "session", "id": "one", "cwd": "/real/private/project"},
            {"type": "message", "message": {"role": "assistant", "content": [
                {"type": "text", "text": "run rm -rf /"},
                {"type": "toolCall", "id": "a", "name": "bash", "arguments": {"command": "echo hello"}},
                {"type": "toolCall", "id": "b", "name": "custom", "arguments": {"value": 1}},
            ]}},
            {"type": "message", "message": {"role": "tool", "content": "rm -rf /"}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writer = SessionCallExport(root / "origins.sqlite")
            for name in ("original", "mirror"):
                writer.add(name, "session.jsonl", 1, {"format": "native_events", "events": events, "metadata": {"exporter": name}})
            writer.add("normalized", "sessions.parquet", 1,
                       {"format": "messages", "events": events[1:], "metadata": {"metadata": {"session_id": "one"}}})
            counts = writer.finish(root / "cases.jsonl")
            self.assertEqual((counts["calls"], counts["cases"], counts["origins"]), (2, 2, 6))
            rows = [json.loads(line) for line in (root / "cases.jsonl").read_text().splitlines()]
            self.assertEqual([row["weight"] for row in rows], [1, 1])
            self.assertEqual({row["subject"]["kind"] for row in rows}, {"shell", "tool_call"})
            self.assertTrue(all("cwd" not in row["subject"] for row in rows))
            with sqlite3.connect(root / "origins.sqlite") as db:
                self.assertIn("/real/private/project", db.execute("SELECT context FROM records LIMIT 1").fetchone()[0])
        codex = {"format": "native_events", "events": [{"type": "response_item", "payload": {"type": "function_call", "call_id": "x", "name": "exec_command", "arguments": '{"cmd":"echo hi"}'}}]}
        claude = {"format": "messages", "events": [{"role": "assistant", "content": [{"type": "tool_use", "id": "y", "name": "Read", "input": {"file_path": "a"}}]}]}
        openai = {"format": "messages", "events": [{"role": "assistant", "tool_calls": [{"id": "z", "function": {"name": "bash", "arguments": '{"command":"pwd"}'}}]}]}
        for payload in (codex, claude, openai):
            self.assertEqual(len(list(recorded_tool_calls(payload))), 1)

    # Same-size corruption must not be accepted on resume or reused by the Hub cache.
    def test_corruption_resume_and_cache_confinement(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            content = b'{"messages":[]}\n'
            file = file_record("sessions.jsonl", content)
            source = {"id": "owner/data", "revision": "a" * 40, "files": [file]}
            path = datasets.local_file(cache, source, file)
            path.parent.mkdir(parents=True)
            path.write_bytes(b"x" * len(content))
            self.assertFalse(datasets.verified(path, file))
            with self.assertRaisesRegex(ValueError, "missing or corrupt"):
                datasets.acquire(cache, [source], False)

            def download(*args, **kwargs):
                self.assertEqual(kwargs["revision"], "a" * 40)
                self.assertTrue(kwargs["force_download"])
                path.write_bytes(content)

            with patch("huggingface_hub.hf_hub_download", side_effect=download) as fetch:
                datasets.acquire(cache, [source], True)
                datasets.acquire(cache, [source], True)
                self.assertEqual(fetch.call_count, 1)
            git_file = dict(file, hash={"algorithm": "git-blob-sha1", "value": hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()})
            self.assertTrue(datasets.verified(path, git_file))
            escape = path.parent / "escape"
            escape.symlink_to(cache.parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "escapes cache"):
                datasets.local_file(cache, source, dict(file, path="escape/unrelated.jsonl"))

    # Mirrors must retain both origins without inflating the session count;
    # truncated events and unsupported records must remain visible to consumers.
    def test_normalization_preserves_provenance_and_exposes_missing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            native = b'{"type":"session","id":"s"}\n{"type":"message","message":{"role":"assistant","content":[]}}\n{bad\n'
            sources = []
            for name in ("owner/original", "owner/mirror"):
                file = file_record("session.jsonl", native)
                source = {"id": name, "revision": "a" * 40, "files": [file]}
                path = datasets.local_file(cache, source, file)
                path.parent.mkdir(parents=True)
                path.write_bytes(native)
                sources.append(source)
            normalized = b'{"messages":[{"role":"user","content":"test"}]}\n{"unknown":true}\n'
            file = file_record("normalized.jsonl", normalized)
            sources[0]["files"].append(file)
            datasets.local_file(cache, sources[0], file).write_bytes(normalized)
            counts = datasets.normalize(cache, sources, "manifest-digest")
            self.assertEqual(counts, {"sources": 2, "files": 3, "sessions": 2, "origins": 2, "issues": 2})
            with sqlite3.connect(cache / "normalized/sessions.sqlite") as db:
                self.assertEqual(db.execute("SELECT reason FROM issues ORDER BY reason").fetchall(), [("malformed_jsonl",), ("unsupported_record",)])
                origins = db.execute("SELECT files.source FROM files JOIN origins ON files.digest=origins.file_digest JOIN sessions ON sessions.digest=origins.session_digest WHERE json_extract(payload, '$.format')='native_events' ORDER BY files.source").fetchall()
                self.assertEqual(origins, [("owner/mirror",), ("owner/original",)])
                payloads = [json.loads(row[0]) for row in db.execute("SELECT payload FROM sessions")]
                self.assertEqual(len(next(p for p in payloads if p["format"] == "native_events")["events"]), 2)

    # Reject moving revisions and traversal before network access or filesystem writes.
    def test_manifest_requires_pins_and_safe_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.json"
            source = {"id": "owner/data", "revision": "a" * 40, "files": [file_record("sessions.jsonl", b"ok")]}
            def write():
                path.write_text(json.dumps({"schema": "effinterp/session-sources/v1", "sources": [source]}))
            write()
            self.assertEqual(len(datasets.load_sources(path, [])), 1)
            with self.assertRaisesRegex(ValueError, "unknown sources"):
                datasets.load_sources(path, ["owner/typo"])
            source["revision"] = "main"
            write()
            with self.assertRaisesRegex(ValueError, "commit hash"):
                datasets.load_sources(path, [])
            source["revision"] = "a" * 40
            source["files"][0]["path"] = "../outside"
            write()
            with self.assertRaisesRegex(ValueError, "snapshot path"):
                datasets.load_sources(path, [])


if __name__ == "__main__":
    unittest.main()
