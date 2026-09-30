#!/usr/bin/env python3
"""Run benchmark measurement or a publish dry run on Linux for an exact committed source tree."""

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


# Stdout is the result envelope; compiler/benchmark output goes to stderr.
# Each commit owns its checkout, target directory, run records, and exclusive lock.
REMOTE = r'''
import fcntl, json, pathlib, platform, subprocess, sys
commit, args = sys.argv[1], json.loads(sys.argv[2])
if platform.system() != "Linux":
    raise SystemExit("remote benchmark host must be Linux")
root = pathlib.Path.home() / ".cache/effectinterp/bench-remote" / commit
root.mkdir(parents=True, exist_ok=True)
with (root / "lock").open("w") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    bundle = root / "source.bundle"
    with bundle.open("wb") as output:
        while data := sys.stdin.buffer.read(1024 * 1024):
            output.write(data)
    tree = root / "tree"
    if not tree.exists():
        subprocess.run(["git", "clone", "--no-checkout", str(bundle), str(tree)], check=True, stdout=sys.stderr)
        subprocess.run(["git", "checkout", "--detach", commit], cwd=tree, check=True, stdout=sys.stderr)
    bundle.unlink()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tree, text=True).strip()
    if head != commit:
        raise SystemExit("remote checkout does not match the requested commit")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", ".", ":(exclude)bench/runs"], cwd=tree, check=True, stdout=sys.stderr)
    subprocess.run(["cargo", "build", "--locked", "-p", "effinterp-bench"], cwd=tree, check=True, stdout=sys.stderr)
    binary = tree / "target/debug/effinterp-bench"
    result = subprocess.run([str(binary), *args], cwd=tree, text=True, stdout=subprocess.PIPE)
    sys.stderr.write(result.stdout)
    run = args[2] if args[0] == "publish" else None
    if args[0] == "measure" and result.returncode in (0, 1, 3):
        recorded = [pathlib.Path(line.removeprefix("recorded ")).name for line in result.stdout.splitlines() if line.startswith("recorded ") and pathlib.Path(line.removeprefix("recorded ")).parent == pathlib.Path("bench/runs")]
        if len(recorded) != 1:
            raise SystemExit("measurement did not identify exactly one run")
        run = recorded[0]
    check_exit = None
    if run is not None:
        checked = subprocess.run([str(binary), "publish", "--dry-run", run], cwd=tree, stdout=sys.stderr)
        check_exit = checked.returncode
        if check_exit not in (0, 1, 3):
            raise SystemExit("remote run failed integrity validation")
        manifest = json.loads((tree / "bench/runs" / run / "manifest.json").read_text())["data"]
        if manifest["provenance"]["git_head"] != commit:
            raise SystemExit("run provenance does not match the requested commit")
    print(json.dumps({"commit": commit, "tree": str(tree), "run": run, "exit_code": result.returncode, "check_exit_code": check_exit}))
'''


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Example: %(prog)s --host repos --out /tmp/repo-evidence -- measure --group repositories --repo steveyegge/beads\n"
        "Requires SSH, Python 3, Git, and the pinned Rust toolchain on Linux. "
        "Commit source changes first. The host keeps an isolated checkout per commit. "
        "Results retain Linux build/machine identity and are never promoted automatically. "
        "A Mac can inspect this evidence, but cannot publish it as a Mac build. "
        "For invocation baseline updates on Mac, use native measure/publish.",
    )
    parser.add_argument("--host", required=True, help="SSH host alias for the Linux verifier")
    parser.add_argument("--out", required=True, type=Path, help="new directory for evidence and transport.json")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- measure OPTIONS, or -- publish --dry-run RUN")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or command[0] not in {"measure", "publish"}:
        parser.error("supply -- measure OPTIONS or -- publish --dry-run RUN")
    if command[0] == "publish" and (len(command) != 3 or command[1] != "--dry-run"):
        parser.error("publish requires --dry-run and exactly one run ID")
    if args.host.startswith("-") or not args.host:
        parser.error("host must be an SSH destination")
    root = Path(git(Path(__file__).resolve().parent, "rev-parse", "--show-toplevel"))
    scope = ["--", ".", ":(exclude)bench/runs"]
    if git(root, "status", "--porcelain", "--untracked-files=all", *scope):
        parser.error("commit source and baseline changes before Linux verification")
    commit = git(root, "rev-parse", "HEAD")
    args.out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="effinterp-bench-bundle-") as temporary:
        bundle = Path(temporary) / "source.bundle"
        subprocess.run(["git", "-C", str(root), "bundle", "create", str(bundle), "HEAD"], check=True)
        remote_command = shlex.join(["python3", "-c", REMOTE, commit, json.dumps(command)])
        with bundle.open("rb") as source:
            result = subprocess.run(["ssh", args.host, remote_command], stdin=source, stdout=subprocess.PIPE, text=True, check=True)
    evidence = json.loads(result.stdout)
    if evidence["commit"] != commit or git(root, "rev-parse", "HEAD") != commit:
        raise RuntimeError("source commit changed during verification")
    if git(root, "status", "--porcelain", "--untracked-files=all", *scope):
        raise RuntimeError("local source changed during verification")
    run = evidence["run"]
    if run is not None:
        # These files remain evidence from the Linux build; do not relabel or
        # copy them over the local scoreboard or runner-owned worktrees.
        remote_path = str(Path(evidence["tree"]) / "bench/runs" / run)
        subprocess.run(["scp", "-r", f"{args.host}:{remote_path}", str(args.out / "run")], check=True)
        manifest = json.loads((args.out / "run/manifest.json").read_text())["data"]
        if manifest["run_id"] != run or manifest["provenance"]["git_head"] != commit:
            raise RuntimeError("downloaded run does not match the verified source")
    (args.out / "transport.json").write_text(json.dumps({**evidence, "host": args.host, "command": command}, indent=2) + "\n")
    print(f"Linux verification evidence: {args.out}")
    return evidence["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(f"Linux verification command failed (exit {error.returncode}); see diagnostics above")
    except (OSError, RuntimeError) as error:
        sys.exit(f"Linux verification failed: {error}")
