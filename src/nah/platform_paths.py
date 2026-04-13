"""Platform-specific filesystem locations."""

import os
import sys


def is_windows() -> bool:
    """Return True when running on Windows."""
    return sys.platform == "win32"


def windows_appdata_dir() -> str:
    """Return the Windows APPDATA directory, or empty when unavailable."""
    if not is_windows():
        return ""
    return os.environ.get("APPDATA", "")


def nah_config_dir() -> str:
    """Return nah's global config/log directory for the current platform."""
    appdata = windows_appdata_dir()
    if appdata:
        return os.path.join(appdata, "nah")
    return os.path.join(os.path.expanduser("~"), ".config", "nah")
