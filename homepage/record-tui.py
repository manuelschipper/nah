#!/usr/bin/env python3
"""Record `nah tui` into an asciinema v2 .cast by driving it through a PTY
with human-paced keystrokes. HOME is sandboxed so the demo shows factory
defaults and mutates nothing real. Rebuild afterwards: build.py splices
nah-tui.cast into the page."""
import fcntl
import json
import os
import pty
import select
import struct
import termios
import time

HERE = os.path.dirname(os.path.abspath(__file__))
COLS, ROWS = 80, 30
BIN = os.path.join(HERE, "..", "target", "release", "nah")
SANDBOX = os.path.join(HERE, ".tui-home")
OUT = os.path.join(HERE, "nah-tui.cast")

# (delay-before-send seconds, bytes). None = just wait.
SCRIPT = [
    (1.6, None),
    (0.8, b"j"), (0.4, b"j"), (0.4, b"j"),
    (1.0, b" "),
    (1.2, b"\r"),
    (1.5, b" "),
    (1.1, b"\r"),
    (2.2, b"q"),
    (0.9, None),
]

os.makedirs(SANDBOX, exist_ok=True)
env = dict(os.environ, HOME=SANDBOX, TERM="xterm-256color",
           COLUMNS=str(COLS), LINES=str(ROWS))

pid, fd = pty.fork()
if pid == 0:
    os.execve(BIN, [BIN, "tui"], env)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

events = []
start = time.monotonic()
deadline_idx = 0
next_at = start + SCRIPT[0][0]

while True:
    timeout = max(0, next_at - time.monotonic()) if deadline_idx < len(SCRIPT) else 0.5
    r, _, _ = select.select([fd], [], [], min(timeout, 0.05))
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        events.append([round(time.monotonic() - start, 4), "o",
                       data.decode("utf-8", "replace")])
    if deadline_idx < len(SCRIPT) and time.monotonic() >= next_at:
        _, keys = SCRIPT[deadline_idx]
        if keys:
            os.write(fd, keys)
        deadline_idx += 1
        if deadline_idx < len(SCRIPT):
            next_at = time.monotonic() + SCRIPT[deadline_idx][0]
    if deadline_idx >= len(SCRIPT) and not r:
        break

try:
    os.close(fd)
except OSError:
    pass
os.waitpid(pid, 0)

header = {"version": 2, "width": COLS, "height": ROWS,
          "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
with open(OUT, "w") as f:
    f.write(json.dumps(header) + "\n")
    for ev in events:
        f.write(json.dumps(ev) + "\n")
print(f"cast: {len(events)} events, {events[-1][0] if events else 0}s, "
      f"{os.path.getsize(OUT)} bytes")
