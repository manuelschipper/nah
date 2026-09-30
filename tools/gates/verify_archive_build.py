#!/usr/bin/env python3
"""Build the committed tree from a fresh `git archive` with empty caches, then prove it decides.

The workspace test suites cover engine provenance. This gate covers what they
cannot see from inside a checkout: every file the build needs is committed, and
the build works without a `.git` directory.
"""

import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def run(argv, *, cwd, env, **kwargs):
    return subprocess.run(argv, cwd=cwd, env=env, check=True, **kwargs)


def main():
    root = Path(__file__).resolve().parents[2]
    rustc = subprocess.check_output(["rustup", "which", "rustc"], text=True).strip()
    cargo = subprocess.check_output(["rustup", "which", "cargo"], text=True).strip()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    archive = subprocess.check_output(["git", "archive", revision], cwd=root)

    with tempfile.TemporaryDirectory(prefix="nah-archive-build-") as temporary:
        scratch = Path(temporary)
        source = scratch / "source"
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as files:
            files.extractall(source, filter="data")
        home = scratch / "home"
        config = scratch / "config"
        cargo_home = scratch / "cargo"
        target = scratch / "target"
        for directory in [home, config, cargo_home, target]:
            directory.mkdir()
        # The child inherits no Cargo config, caches, or build output from this host.
        environment = {
            "PATH": os.pathsep.join([str(Path(rustc).parent), os.environ["PATH"]]),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(config),
            "CARGO_HOME": str(cargo_home),
            "CARGO_TARGET_DIR": str(target),
            "RUSTC": rustc,
        }

        print(f"Archive build at {revision}", flush=True)
        run([cargo, "check", "--workspace", "--all-targets", "--locked"], cwd=source, env=environment)
        run([cargo, "build", "-p", "nah-cli", "--locked"], cwd=source, env=environment)

        binary = target / "debug" / ("nah.exe" if os.name == "nt" else "nah")
        request = json.dumps({
            "v": 1, "tool": "Bash", "input": {"command": "rm -rf /etc"},
            "cwd": str(source),
        })
        decided = subprocess.run([str(binary), "decide"], cwd=source, env=environment, input=request, capture_output=True, text=True)
        decision = json.loads(decided.stdout)
        if decided.returncode != 1 or decision["verdict"] != "block":
            raise RuntimeError("the archive build lost the system-tree protection")
        print("Archive build passed: fresh resolution and build, engine-backed decision.")


if __name__ == "__main__":
    main()
