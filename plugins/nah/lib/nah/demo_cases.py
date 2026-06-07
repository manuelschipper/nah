"""Helpers for loading the packaged nah demo cases."""

import json
from importlib import resources
from typing import Any


def load_nah_demo_cases() -> list[dict[str, Any]]:
    """Load the curated cases used by the /nah-demo command."""
    data = resources.files("nah.data").joinpath("nah_demo.json")
    return json.loads(data.read_text(encoding="utf-8"))
