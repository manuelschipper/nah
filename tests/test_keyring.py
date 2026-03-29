"""Tests for keyring integration in the LLM layer."""

import os
from unittest.mock import patch

import keyring as real_keyring
import pytest

from nah.llm import _resolve_key, _KEYRING_SERVICE


class TestResolveKey:
    """Tests for _resolve_key(): keyring → env var (auto-migrate) → empty."""

    def test_keyring_value_preferred(self, _mock_keyring):
        """When keyring has a value, use it regardless of env var."""
        _mock_keyring.get_password.return_value = "kr-secret"
        with patch.dict(os.environ, {"TEST_KEY": "env-secret"}):
            result = _resolve_key("TEST_KEY")
        assert result == "kr-secret"
        _mock_keyring.set_password.assert_not_called()

    def test_env_fallback_when_keyring_empty(self, _mock_keyring):
        """When keyring returns None, fall back to env var."""
        with patch.dict(os.environ, {"TEST_KEY": "env-secret"}):
            result = _resolve_key("TEST_KEY")
        assert result == "env-secret"

    def test_empty_when_neither(self, _mock_keyring):
        """When neither keyring nor env var has a value, return empty."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NONEXISTENT_KEY", None)
            result = _resolve_key("NONEXISTENT_KEY")
        assert result == ""
        _mock_keyring.set_password.assert_not_called()

    def test_keyring_returns_empty_string(self, _mock_keyring):
        """When keyring returns empty string, treat as absent and fallback."""
        _mock_keyring.get_password.return_value = ""
        with patch.dict(os.environ, {"TEST_KEY": "env-secret"}):
            result = _resolve_key("TEST_KEY")
        assert result == "env-secret"

    def test_env_var_empty_string_treated_as_absent(self, _mock_keyring):
        """When env var is explicitly set to empty string, treat as absent."""
        with patch.dict(os.environ, {"TEST_KEY": ""}):
            result = _resolve_key("TEST_KEY")
        assert result == ""
        _mock_keyring.set_password.assert_not_called()

    def test_keyring_read_error_falls_back_with_stderr(self, _mock_keyring, capsys):
        """When keyring.get_password raises, fall back to env var and warn."""
        _mock_keyring.get_password.side_effect = RuntimeError("backend error")
        with patch.dict(os.environ, {"TEST_KEY": "env-fallback"}):
            result = _resolve_key("TEST_KEY")
        assert result == "env-fallback"
        captured = capsys.readouterr()
        assert "nah: keyring: read failed" in captured.err
        assert "backend error" in captured.err

    def test_auto_migrate_env_to_keyring(self, _mock_keyring):
        """When key is in env but not keyring, auto-migrate to keyring."""
        with patch.dict(os.environ, {"MY_API_KEY": "secret-val"}):
            _resolve_key("MY_API_KEY")
        _mock_keyring.set_password.assert_called_once_with(
            _KEYRING_SERVICE, "MY_API_KEY", "secret-val",
        )

    def test_auto_migrate_message_on_stderr(self, _mock_keyring, capsys):
        """Auto-migration prints a message to stderr."""
        with patch.dict(os.environ, {"MY_API_KEY": "secret"}):
            _resolve_key("MY_API_KEY")
        captured = capsys.readouterr()
        assert "nah: keyring: migrated" in captured.err
        assert "remove the env var" in captured.err

    def test_auto_migrate_only_once(self, _mock_keyring):
        """Auto-migration happens only once per key_env per process."""
        with patch.dict(os.environ, {"MY_API_KEY": "secret"}):
            _resolve_key("MY_API_KEY")
            _resolve_key("MY_API_KEY")
        assert _mock_keyring.set_password.call_count == 1

    def test_auto_migrate_fallback_when_write_fails(self, _mock_keyring, capsys):
        """When keyring write fails, still return env value and show hint."""
        _mock_keyring.set_password.side_effect = RuntimeError("write failed")
        with patch.dict(os.environ, {"MY_API_KEY": "secret"}):
            result = _resolve_key("MY_API_KEY")
        assert result == "secret"
        captured = capsys.readouterr()
        assert "nah: keyring: write failed" in captured.err

    def test_no_migrate_when_keyring_has_value(self, _mock_keyring):
        """No migration when keyring already has the key."""
        _mock_keyring.get_password.return_value = "kr-secret"
        with patch.dict(os.environ, {"MY_API_KEY": "env-secret"}):
            _resolve_key("MY_API_KEY")
        _mock_keyring.set_password.assert_not_called()

    def test_no_migrate_when_env_empty(self, _mock_keyring):
        """No migration when env var is not set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MY_API_KEY", None)
            _resolve_key("MY_API_KEY")
        _mock_keyring.set_password.assert_not_called()


# -- Integration tests (real OS keyring) --
# Run with: pytest -m integration


_TEST_KEY = "NAH_TEST_INTEGRATION_KEY"
_TEST_MIGRATE_KEY = "NAH_TEST_MIGRATE_KEY"


def _cleanup(*keys: str) -> None:
    """Delete test keys from real keyring, ignoring errors."""
    for k in keys:
        try:
            real_keyring.delete_password(_KEYRING_SERVICE, k)
        except Exception:
            pass


@pytest.mark.integration
class TestKeyringIntegration:
    """Real OS keyring round-trip tests. Requires keyring backend."""

    def test_roundtrip(self):
        """set → _resolve_key → delete."""
        _cleanup(_TEST_KEY)
        try:
            real_keyring.set_password(_KEYRING_SERVICE, _TEST_KEY, "int-test-val")
            result = _resolve_key(_TEST_KEY)
            assert result == "int-test-val"
        finally:
            _cleanup(_TEST_KEY)

    def test_auto_migrate_real(self, capsys):
        """env var → auto-migrate → verify in real keyring."""
        _cleanup(_TEST_MIGRATE_KEY)
        try:
            with patch.dict(os.environ, {_TEST_MIGRATE_KEY: "env-migrate-val"}):
                result = _resolve_key(_TEST_MIGRATE_KEY)
            assert result == "env-migrate-val"

            # verify actually written to real keyring
            kr_val = real_keyring.get_password(_KEYRING_SERVICE, _TEST_MIGRATE_KEY)
            assert kr_val == "env-migrate-val"

            captured = capsys.readouterr()
            assert "migrated" in captured.err
        finally:
            _cleanup(_TEST_MIGRATE_KEY)

    def test_full_migration_lifecycle(self):
        """Full migration: env var → auto-migrate → remove env → keyring-only."""
        _cleanup(_TEST_MIGRATE_KEY)
        try:
            # 1. Start with env var only
            from nah.llm import _migrated
            _migrated.discard(_TEST_MIGRATE_KEY)

            with patch.dict(os.environ, {_TEST_MIGRATE_KEY: "migrate-me"}):
                result = _resolve_key(_TEST_MIGRATE_KEY)
            assert result == "migrate-me"

            # 2. Verify migrated to keyring
            kr_val = real_keyring.get_password(_KEYRING_SERVICE, _TEST_MIGRATE_KEY)
            assert kr_val == "migrate-me"

            # 3. Remove env var — next call should read from keyring only
            _migrated.discard(_TEST_MIGRATE_KEY)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop(_TEST_MIGRATE_KEY, None)
                result = _resolve_key(_TEST_MIGRATE_KEY)
            assert result == "migrate-me"
        finally:
            _cleanup(_TEST_MIGRATE_KEY)

    def test_keyring_preferred_over_env(self):
        """When both keyring and env have values, keyring wins."""
        _cleanup(_TEST_KEY)
        try:
            real_keyring.set_password(_KEYRING_SERVICE, _TEST_KEY, "from-keyring")
            with patch.dict(os.environ, {_TEST_KEY: "from-env"}):
                result = _resolve_key(_TEST_KEY)
            assert result == "from-keyring"
        finally:
            _cleanup(_TEST_KEY)
