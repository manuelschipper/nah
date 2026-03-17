"""FD-025 verification: config overrides are wired end-to-end."""

import os
from unittest.mock import patch

import pytest

from nah import paths
from nah.config import reset_config

HOME = os.path.expanduser("~")


def _check(tool, path):
    """Reset state, let real config load, return decision."""
    paths.reset_sensitive_paths()
    paths._sensitive_paths_merged = False
    reset_config()
    r = paths.check_path(tool, path)
    return r["decision"] if r else "allow"


class TestFD025LiveVerification:
    """Verify config overrides through the real config loading path."""

    def test_keys_file_ask_from_config(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("sensitive_paths:\n  ~/.keys: ask\n")
        with patch("nah.config._GLOBAL_CONFIG", str(cfg)):
            assert _check("Read", HOME + "/.keys") == "ask"

    def test_gnupg_hardcoded_block(self):
        assert _check("Read", HOME + "/.gnupg/key") == "block"

    def test_netrc_hardcoded_block(self):
        assert _check("Read", HOME + "/.netrc") == "block"

    def test_aws_hardcoded_ask(self):
        assert _check("Read", HOME + "/.aws/creds") == "ask"

    def test_hooks_immutable(self):
        assert _check("Edit", HOME + "/.claude/hooks/x.py") == "block"

    def test_clean_path_allow(self):
        assert _check("Read", "/tmp/safe.txt") == "allow"

    def test_no_config_defaults_apply(self):
        paths.reset_sensitive_paths()
        paths._sensitive_paths_merged = False
        reset_config()
        with patch("nah.config._GLOBAL_CONFIG", "/tmp/no_config.yaml"):
            r = paths.check_path("Read", HOME + "/.gnupg/key")
            assert r is not None
            assert r["decision"] == "block"
