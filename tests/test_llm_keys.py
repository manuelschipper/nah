"""Unit tests for keyring-backed LLM key helpers."""

import pytest

from nah import llm_keys


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


class FailingKeyring:
    def get_password(self, _service, _username):
        raise RuntimeError("backend down")

    def set_password(self, _service, _username, _password):
        raise RuntimeError("backend down")

    def delete_password(self, _service, _username):
        raise RuntimeError("backend down")


def test_builtin_key_slots_have_expected_defaults():
    assert llm_keys.builtin_key_slots() == [
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("openrouter", "OPENROUTER_API_KEY"),
        ("cortex", "SNOWFLAKE_PAT"),
        ("azure", "AZURE_OPENAI_API_KEY"),
    ]


def test_resolve_key_prefers_keyring_over_env(monkeypatch):
    fake = FakeKeyring()
    fake.set_password(llm_keys.KEYRING_SERVICE, "OPENAI_API_KEY", "stored-key")
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: fake)
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")

    assert llm_keys.resolve_key("OPENAI_API_KEY") == "stored-key"


def test_resolve_key_falls_back_to_env_when_keyring_not_installed(monkeypatch):
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: None)
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")

    assert llm_keys.resolve_key("OPENROUTER_API_KEY") == "env-key"


def test_resolve_key_warns_and_falls_back_on_backend_error(monkeypatch, capsys):
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: FailingKeyring())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")

    assert llm_keys.resolve_key("ANTHROPIC_API_KEY") == "env-key"
    err = capsys.readouterr().err
    assert "ANTHROPIC_API_KEY" in err
    assert "falling back to env" in err


def test_key_status_reports_env_with_backend_error(monkeypatch):
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: FailingKeyring())
    monkeypatch.setenv("SNOWFLAKE_PAT", "env-key")

    status = llm_keys.key_status("cortex", "SNOWFLAKE_PAT")

    assert status.source == "env"
    assert "keyring backend error" in status.note


def test_key_status_reports_keyring_error_without_env(monkeypatch):
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: FailingKeyring())
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)

    status = llm_keys.key_status("azure", "AZURE_OPENAI_API_KEY")

    assert status.source == "keyring-error"
    assert "keyring backend error" in status.note


def test_keyring_entry_exists_and_set_key_use_env_slot_name(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: fake)

    assert llm_keys.keyring_entry_exists("OPENAI_API_KEY") is False
    llm_keys.set_key("OPENAI_API_KEY", "secret-value")

    assert llm_keys.keyring_entry_exists("OPENAI_API_KEY") is True
    assert fake.store[(llm_keys.KEYRING_SERVICE, "OPENAI_API_KEY")] == "secret-value"


def test_set_key_requires_optional_support(monkeypatch):
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: None)

    with pytest.raises(llm_keys.KeyStoreUnavailable) as exc:
        llm_keys.set_key("OPENAI_API_KEY", "secret-value")

    assert llm_keys.INSTALL_HINT in str(exc.value)


def test_set_key_surfaces_backend_error_without_secret(monkeypatch):
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: FailingKeyring())

    with pytest.raises(llm_keys.KeyStoreBackendError) as exc:
        llm_keys.set_key("OPENAI_API_KEY", "super-secret")

    assert "super-secret" not in str(exc.value)


def test_remove_key_returns_false_when_slot_missing(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: fake)

    assert llm_keys.remove_key("OPENROUTER_API_KEY") is False


def test_remove_key_deletes_existing_slot(monkeypatch):
    fake = FakeKeyring()
    fake.set_password(llm_keys.KEYRING_SERVICE, "OPENROUTER_API_KEY", "stored")
    monkeypatch.setattr(llm_keys, "_load_keyring", lambda: fake)

    assert llm_keys.remove_key("OPENROUTER_API_KEY") is True
    assert fake.get_password(llm_keys.KEYRING_SERVICE, "OPENROUTER_API_KEY") is None


def test_read_env_key_requires_value(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(llm_keys.KeyStoreMissingEnv):
        llm_keys.read_env_key("OPENAI_API_KEY")


def test_read_env_key_returns_current_value(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "from-env")

    assert llm_keys.read_env_key("OPENAI_API_KEY") == "from-env"
