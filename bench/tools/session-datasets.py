#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["huggingface-hub==0.34.3", "pyarrow==20.0.0"]
# ///
"""Acquire pinned session snapshots and normalize them in an external cache."""

import argparse
import contextlib
import fcntl
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

from session_json import canonical_session_json


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "bench/sessions/sources.json"


def load_sources(path, selected):
    manifest = json.loads(path.read_text())
    if manifest["schema"] != "effinterp/session-sources/v1":
        raise ValueError("unsupported source manifest schema")
    sources = manifest["sources"]
    names = [source["id"] for source in sources]
    if len(names) != len(set(names)):
        raise ValueError("duplicate source IDs")
    for source in sources:
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", source["id"]) or any(part in (".", "..") for part in source["id"].split("/")):
            raise ValueError("invalid source ID")
        if not re.fullmatch(r"[0-9a-f]{40}", source["revision"]):
            raise ValueError(f"{source['id']}: revision must be a commit hash")
        paths = set()
        for file in source["files"]:
            path = PurePosixPath(file["path"])
            if not path.parts or path.is_absolute() or ".." in path.parts or str(path) != file["path"] or "\\" in file["path"]:
                raise ValueError("invalid snapshot path")
            if file["path"] in paths:
                raise ValueError("duplicate snapshot path")
            paths.add(file["path"])
            algorithm = file["hash"]["algorithm"]
            length = {"sha256": 64, "git-blob-sha1": 40}.get(algorithm)
            if length is None or not re.fullmatch(rf"[0-9a-f]{{{length}}}", file["hash"]["value"]):
                raise ValueError("invalid snapshot checksum")
            if not isinstance(file["bytes"], int) or file["bytes"] < 0:
                raise ValueError("invalid snapshot size")
    unknown = set(selected) - set(names)
    if unknown:
        raise ValueError(f"unknown sources: {', '.join(sorted(unknown))}")
    return [source for source in sources if not selected or source["id"] in selected]


def external_cache(path):
    path = path.expanduser().resolve()
    ancestor = path
    while not ancestor.exists():
        ancestor = ancestor.parent
    result = subprocess.run(
        ["git", "-C", str(ancestor), "rev-parse", "--show-toplevel"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        raise ValueError("dataset cache must be outside Git checkouts")
    path.mkdir(parents=True, exist_ok=True)
    return path


def local_file(cache, source, file):
    path = cache / "raw" / source["id"] / file["path"]
    if not path.resolve().is_relative_to(cache.resolve()):
        raise ValueError(f"snapshot symlink escapes cache: {file['path']}")
    return path


def verified(path, file):
    if not path.is_file() or path.stat().st_size != file["bytes"]:
        return False
    algorithm = file["hash"]["algorithm"]
    digest = hashlib.sha256() if algorithm == "sha256" else hashlib.sha1()
    if algorithm == "git-blob-sha1":
        digest.update(f"blob {file['bytes']}\0".encode())
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest() == file["hash"]["value"]


def acquire(cache, sources, download):
    if download:
        from huggingface_hub import hf_hub_download
    for source in sources:
        for file in source["files"]:
            path = local_file(cache, source, file)
            if verified(path, file):
                continue
            if not download:
                raise ValueError(f"missing or corrupt file: {source['id']}/{file['path']}")
            # Failed verification must bypass the Hub's same-size local-file shortcut.
            time.sleep(0.15)
            hf_hub_download(
                source["id"], file["path"], repo_type="dataset",
                revision=source["revision"], local_dir=cache / "raw" / source["id"],
                force_download=path.exists(),
            )
            if not verified(path, file):
                raise ValueError(f"checksum mismatch: {source['id']}/{file['path']}")
        print(f"verified {source['id']}: {len(source['files'])} files", file=sys.stderr)


def session(row):
    if not isinstance(row, dict):
        return None
    if isinstance(row.get("raw_jsonl"), str):
        try:
            events = [json.loads(line) for line in row["raw_jsonl"].splitlines() if line.strip()]
        except json.JSONDecodeError:
            return None
        if events:
            return {"format": "native_events", "events": events, "metadata": {k: v for k, v in row.items() if k != "raw_jsonl"}}
    for key in ("messages", "trajectory", "conversations"):
        events = row.get(key)
        if isinstance(events, str):
            try:
                events = json.loads(events)
            except json.JSONDecodeError:
                continue
        if isinstance(events, list) and events:
            return {"format": key, "events": events, "metadata": {k: v for k, v in row.items() if k != key}}
    return None


def records(path, issues):
    if path.suffix == ".parquet":
        import pyarrow as pa
        import pyarrow.parquet as pq
        ordinal = 0
        for batch in pq.ParquetFile(path).iter_batches(batch_size=8):
            # Arrow's Python datetime conversion cannot retain nanoseconds.
            # Preserve timestamp metadata as exact strings before conversion.
            for index, field in enumerate(batch.schema):
                if pa.types.is_timestamp(field.type):
                    batch = batch.set_column(index, field.name, batch.column(index).cast(pa.string()))
            for row in batch.to_pylist():
                ordinal += 1
                yield ordinal, row
    elif path.suffix == ".json":
        try:
            yield 1, json.loads(path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            issues.append({"line": 1, "reason": "malformed_json"})
    else:
        with path.open() as stream:
            # Some exports use the jsonl extension for a pretty-printed document.
            if stream.readline().strip() == "{":
                stream.seek(0)
                try:
                    yield 1, json.load(stream)
                except json.JSONDecodeError:
                    issues.append({"line": 1, "reason": "malformed_json_document"})
                return
            stream.seek(0)
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    yield number, json.loads(line)
                except json.JSONDecodeError:
                    issues.append({"line": number, "reason": "malformed_jsonl"})


def sessions(path, issues):
    iterator = iter(records(path, issues))
    first = next(iterator, None)
    if first is None:
        return
    number, row = first
    # Native Pi, Codex and Claude exports are event streams, not one session per line.
    native = isinstance(row, dict) and (
        row.get("type") in ("session", "session_meta", "file-history-snapshot", "queue-operation")
        or (("sessionId" in row or "session_id" in row) and "type" in row)
    )
    if native:
        events = [row] + [event for _, event in iterator]
        yield number, {"format": "native_events", "events": events, "metadata": {}}
        return
    import itertools
    for number, row in itertools.chain([first], iterator):
        normalized = session(row)
        if normalized is None:
            issues.append({"line": number, "reason": "unsupported_record"})
        else:
            yield number, normalized


def normalize(cache, sources, manifest_hash):
    target = cache / "normalized"
    target.mkdir(exist_ok=True)
    # A fresh database is published only after every selected source was processed.
    with tempfile.TemporaryDirectory(prefix="sessions-", dir=target) as scratch:
        database = Path(scratch) / "sessions.sqlite"
        with contextlib.closing(sqlite3.connect(database)) as db:
            db.executescript("""
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE sources (id TEXT PRIMARY KEY, provenance TEXT NOT NULL);
                CREATE TABLE files (source TEXT, path TEXT, digest TEXT, PRIMARY KEY(source, path));
                CREATE TABLE sessions (digest TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE origins (file_digest TEXT, ordinal INTEGER, session_digest TEXT,
                                      PRIMARY KEY(file_digest, ordinal));
                CREATE TABLE issues (file_digest TEXT, ordinal INTEGER, reason TEXT);
            """)
            db.execute("INSERT INTO metadata VALUES (?, ?)", ("schema", "effinterp/session-cache/v1"))
            db.execute("INSERT INTO metadata VALUES (?, ?)", ("manifest_sha256", manifest_hash))
            seen = set()
            for source in sources:
                db.execute("INSERT INTO sources VALUES (?, ?)", (source["id"], canonical_session_json(source)))
                for file in source["files"]:
                    path = local_file(cache, source, file)
                    if path.name in ("manifest.jsonl", "manifest.json", "export_manifest.json", "dataset_stats.json", "tool_catalog.json", "reconstruction_manifest.json"):
                        continue
                    if path.suffix not in (".json", ".jsonl", ".parquet", ".gz", ".zip", ".zst"):
                        continue
                    # The suffix affects parsing, so identical bytes in differently named formats remain distinct inputs.
                    digest = f"{file['hash']['algorithm']}:{file['hash']['value']}:{path.suffix}"
                    db.execute("INSERT INTO files VALUES (?, ?, ?)", (source["id"], file["path"], digest))
                    if digest in seen:
                        continue
                    seen.add(digest)
                    issues = []
                    if path.suffix in (".gz", ".zip", ".zst"):
                        issues.append({"line": 0, "reason": "unsupported_archive"})
                    else:
                        for number, payload in sessions(path, issues):
                            encoded = canonical_session_json(payload)
                            key = hashlib.sha256(encoded.encode()).hexdigest()
                            db.execute("INSERT OR IGNORE INTO sessions VALUES (?, ?)", (key, encoded))
                            db.execute("INSERT INTO origins VALUES (?, ?, ?)", (digest, number, key))
                    db.executemany("INSERT INTO issues VALUES (?, ?, ?)", [(digest, i["line"], i["reason"]) for i in issues])
                db.commit()
            counts = {table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in ("sources", "files", "sessions", "origins", "issues")}
        database.replace(target / "sessions.sqlite")
    return counts


def file_sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def export(cache, sources, manifest_hash):
    from session_calls import SessionCallExport
    target = cache / "coverage"
    target.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="coverage-", dir=cache) as scratch:
        scratch = Path(scratch)
        writer = SessionCallExport(scratch / "origins.sqlite")
        for source in sources:
            for file in source["files"]:
                path = local_file(cache, source, file)
                if path.name in ("manifest.jsonl", "manifest.json", "export_manifest.json", "dataset_stats.json", "tool_catalog.json", "reconstruction_manifest.json"):
                    continue
                if path.suffix not in (".json", ".jsonl", ".parquet", ".gz", ".zip", ".zst"):
                    continue
                issues = []
                if path.suffix in (".gz", ".zip", ".zst"):
                    issues.append({"line": 0, "reason": "unsupported_archive"})
                else:
                    for number, payload in sessions(path, issues):
                        writer.add(source["id"], file["path"], number, payload)
                for issue in issues:
                    writer.issue(source["id"], file["path"], issue["line"], 0, issue["reason"])
                writer.db.commit()
            print(f"extracted {source['id']}", file=sys.stderr)
        counts = writer.finish(scratch / "cases.jsonl")
        manifest = {"schema": "effinterp/session-coverage/v1", "manifest_sha256": manifest_hash,
                    "sources": [{k: v for k, v in source.items() if k != "files"} for source in sources],
                    "counts": counts, "cases_sha256": file_sha256(scratch / "cases.jsonl")}
        (scratch / "MANIFEST.json").write_text(canonical_session_json(manifest) + "\n")
        for name in ("origins.sqlite", "cases.jsonl", "MANIFEST.json"):
            (scratch / name).replace(target / name)
    return counts


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Run with: uv run bench/tools/session-datasets.py COMMAND. HF_TOKEN or a Hugging Face login provides gated access. Export streams normalized sessions into coverage cases, deduplicates recorded calls, and preserves origins and extraction issues in SQLite. Recorded cwd/env remain provenance, not observations of the benchmark host. Score with effinterp-bench --session-corpus CACHE/coverage measure --group coverage. Selected sources replace the output. Exit 3 means reported input issues; exit 2 means an operational failure.",
    )
    parser.add_argument("command", choices=("list", "fetch", "verify", "normalize", "export"))
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/effinterp/sessions", help="external cache root; raw snapshots live under raw/OWNER/DATASET")
    parser.add_argument("--source", action="append", default=[], help="exact dataset ID, repeatable; omitted selects every pinned source")
    args = parser.parse_args()
    try:
        sources = load_sources(args.manifest, args.source)
        if args.command == "list":
            for source in sources:
                print(f"{source['id']}\t{source['revision']}\t{sum(f['bytes'] for f in source['files'])}\t{source['category']}")
            return 0
        cache = external_cache(args.cache)
        with (cache / "session-datasets.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquire(cache, sources, args.command == "fetch")
            if args.command == "export":
                counts = export(cache, sources, hashlib.sha256(args.manifest.read_bytes()).hexdigest())
                print(json.dumps(counts, sort_keys=True))
                return 3 if counts["issues"] else 0
            if args.command == "normalize":
                counts = normalize(cache, sources, hashlib.sha256(args.manifest.read_bytes()).hexdigest())
                print(json.dumps(counts, sort_keys=True))
                return 3 if counts["issues"] else 0
        return 0
    except (OSError, ValueError) as error:
        print(f"session-datasets: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
