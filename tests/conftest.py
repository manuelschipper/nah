"""Shared fixtures for nah tests."""

import os

import pytest

from nah import paths


@pytest.fixture(autouse=True)
def _reset_paths():
    """Reset project root between tests for isolation."""
    yield
    paths.reset_project_root()


@pytest.fixture
def project_root(tmp_path):
    """Set project root to a temp dir. Use for context-dependent tests."""
    root = str(tmp_path / "project")
    os.makedirs(root, exist_ok=True)
    paths.set_project_root(root)
    return root
