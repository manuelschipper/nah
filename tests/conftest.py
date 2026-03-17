"""Shared fixtures for nah tests."""

import os

import pytest

from nah import content, hook, paths, taxonomy
from nah.config import reset_config
from nah.context import reset_known_hosts


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset project root, config cache, and sensitive paths between tests for isolation."""
    reset_config()
    paths.reset_sensitive_paths()
    paths._sensitive_paths_merged = True  # prevent real config from polluting tests
    taxonomy.reset_exec_sinks()
    taxonomy._exec_sinks_merged = True
    taxonomy.reset_decode_commands()
    taxonomy._decode_commands_merged = True
    reset_known_hosts()
    from nah.context import _known_hosts_merged
    import nah.context
    nah.context._known_hosts_merged = True
    content.reset_content_patterns()
    content._content_patterns_merged = True
    yield
    paths.reset_project_root()
    paths.reset_sensitive_paths()
    paths._sensitive_paths_merged = True
    taxonomy.reset_exec_sinks()
    taxonomy._exec_sinks_merged = True
    taxonomy.reset_decode_commands()
    taxonomy._decode_commands_merged = True
    reset_known_hosts()
    nah.context._known_hosts_merged = True
    content.reset_content_patterns()
    content._content_patterns_merged = True
    reset_config()
    hook._transcript_path = ""


@pytest.fixture
def project_root(tmp_path):
    """Set project root to a temp dir. Use for context-dependent tests."""
    root = str(tmp_path / "project")
    os.makedirs(root, exist_ok=True)
    paths.set_project_root(root)
    return root
