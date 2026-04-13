"""Helpers for loading the packaged nah demo battery."""

import json
from importlib import resources
from typing import Any


def load_test_battery() -> dict[str, list[dict[str, Any]]]:
    """Load the same packaged battery data used by the /nah-demo command."""
    data = resources.files("nah.data").joinpath("test_battery.json")
    return json.loads(data.read_text(encoding="utf-8"))
