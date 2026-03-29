"""Interactive API key setup for nah LLM providers.

Stores API keys in the OS keyring (Windows Credential Manager /
macOS Keychain / Linux SecretService).

Usage:
  python -m nah.setup_keys           # Opens GUI window for secure key entry
  python -m nah.setup_keys --status  # Check configured keys (no secrets shown)

When called without --status, launches a tkinter GUI in a subprocess
and blocks until the user closes it. Prints a JSON summary to stdout
so the calling agent can confirm the result without seeing key values.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import keyring
except ImportError:
    print("Error: keyring not installed. Run: pip install keyring", file=sys.stderr)
    sys.exit(1)

_SERVICE = "nah"

# (env_var_name, display_name, docs_url)
_KEYS = [
    ("ANTHROPIC_API_KEY", "Anthropic",
     "https://console.anthropic.com/settings/keys"),
    ("OPENAI_API_KEY", "OpenAI",
     "https://platform.openai.com/api-keys"),
    ("OPENROUTER_API_KEY", "OpenRouter",
     "https://openrouter.ai/settings/keys"),
    ("SNOWFLAKE_PAT", "Snowflake Cortex (PAT)",
     "https://docs.snowflake.com/en/user-guide/programmatic-access-tokens"),
]


def get_status():
    """Return current key configuration status."""
    result = {}
    for key_env, description, url in _KEYS:
        result[key_env] = {
            "description": description,
            "configured": bool(keyring.get_password(_SERVICE, key_env)),
        }
    return result


def gui_setup(marker_path=None):
    """Open a tkinter GUI window for secure API key entry."""
    import tkinter as tk
    from tkinter import ttk
    import webbrowser

    root = tk.Tk()
    root.title("nah — LLM API Key Setup")
    root.resizable(False, False)

    root.update_idletasks()
    root.geometry("+200+100")

    style = ttk.Style()
    style.configure("Link.TLabel", foreground="#4a9eed")
    style.configure("Status.TLabel", foreground="#888888", font=("", 8))
    style.configure("Set.TLabel", foreground="#2ecc71", font=("", 8))

    frame = ttk.Frame(root, padding=20)
    frame.grid(sticky="nsew")

    ttk.Label(frame, text="nah LLM API Key Setup",
              font=("", 12, "bold")).grid(row=0, column=0, columnspan=3, pady=(0, 4))
    ttk.Label(frame, text=f"keyring service: {_SERVICE}",
              style="Status.TLabel").grid(row=1, column=0, columnspan=3, pady=(0, 4))
    ttk.Label(frame, text="Only configure the provider(s) you use.",
              style="Status.TLabel").grid(row=2, column=0, columnspan=3, pady=(0, 12))

    ttk.Separator(frame, orient="horizontal").grid(
        row=3, column=0, columnspan=3, sticky="ew", pady=(0, 8))

    entries = {}
    for i, (key_env, description, url) in enumerate(_KEYS):
        row = i * 2 + 4
        existing = keyring.get_password(_SERVICE, key_env)

        desc_frame = ttk.Frame(frame)
        desc_frame.grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 0))

        ttk.Label(desc_frame, text=description, font=("", 9, "bold")).pack(side="left")
        if existing:
            ttk.Label(desc_frame, text=" (configured)", style="Set.TLabel").pack(side="left")

        link = ttk.Label(desc_frame, text="  Get Key", style="Link.TLabel", cursor="hand2")
        link.pack(side="left", padx=(8, 0))
        link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

        entry_row = row + 1
        entry = ttk.Entry(frame, width=60)
        entry.grid(row=entry_row, column=0, columnspan=2, sticky="ew", padx=(0, 8))
        if existing:
            entry.insert(0, "(keep current)")

            def on_focus_in(e, ent=entry):
                if ent.get() == "(keep current)":
                    ent.delete(0, "end")

            def on_focus_out(e, ent=entry, ex=existing):
                if not ent.get():
                    ent.insert(0, "(keep current)")

            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)

        entries[key_env] = entry

    ttk.Separator(frame, orient="horizontal").grid(
        row=len(_KEYS) * 2 + 4, column=0, columnspan=3, sticky="ew", pady=(12, 8))

    status_var = tk.StringVar(value="Leave fields blank to keep current values.")
    status_label = ttk.Label(frame, textvariable=status_var, style="Status.TLabel")
    status_label.grid(row=len(_KEYS) * 2 + 5, column=0, columnspan=2, sticky="w")

    def on_save():
        changed = 0
        for key_env, entry in entries.items():
            value = entry.get().strip()
            if value and value != "(keep current)":
                keyring.set_password(_SERVICE, key_env, value)
                changed += 1
        if changed:
            status_var.set(f"{changed} key(s) saved to OS keyring.")
        else:
            status_var.set("No changes made.")
        save_btn.config(state="disabled")
        root.after(2000, root.destroy)

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=len(_KEYS) * 2 + 5, column=2, sticky="e")

    save_btn = ttk.Button(btn_frame, text="Save", command=on_save)
    save_btn.pack(side="right")

    ttk.Button(btn_frame, text="Cancel", command=root.destroy).pack(side="right", padx=(0, 4))

    root.mainloop()

    if marker_path:
        Path(marker_path).touch()


def detached_setup():
    """Launch GUI in a subprocess, block until done."""
    script = str(Path(__file__).resolve())
    fd, tmp = tempfile.mkstemp(suffix=".done", prefix="nah-keyring-")
    os.close(fd)
    marker = Path(tmp)
    marker.unlink()  # mkstemp creates the file; remove it so we can use existence as signal

    subprocess.Popen([sys.executable, script, "--_gui", str(marker)])

    while not marker.exists():
        time.sleep(0.5)
    marker.unlink()

    status = get_status()
    configured = [k for k, v in status.items() if v["configured"]]
    print(json.dumps({
        "configured": len(configured),
        "total": len(_KEYS),
        "keys": configured,
    }))


def main():
    if "--_gui" in sys.argv:
        idx = sys.argv.index("--_gui")
        marker = sys.argv[idx + 1] if len(sys.argv) > idx + 1 else None
        gui_setup(marker)
    elif "--status" in sys.argv:
        status = get_status()
        for key_env, info in status.items():
            mark = "+" if info["configured"] else "-"
            print(f"  [{mark}] {info['description']} ({key_env})")
    else:
        detached_setup()


if __name__ == "__main__":
    main()
