"""Optional OS keyring-backed storage for LLM provider credentials."""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass

KEYRING_SERVICE = "nah.llm"
INSTALL_HINT = "pip install 'nah[keys]'"
BUILTIN_PROVIDER_ENVS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "cortex": "SNOWFLAKE_PAT",
    "azure": "AZURE_OPENAI_API_KEY",
}


class KeyStoreError(RuntimeError):
    """Base error for nah key management."""


class KeyStoreUnavailable(KeyStoreError):
    """Optional keyring support is not installed."""


class KeyStoreBackendError(KeyStoreError):
    """Installed keyring backend failed."""


class KeyStoreMissingEnv(KeyStoreError):
    """Expected env var is not set for import."""


@dataclass(frozen=True)
class KeyStatus:
    provider: str
    key_env: str
    source: str
    note: str = ""


def _load_keyring():
    """Return the optional keyring module, or None when not installed."""
    try:
        return importlib.import_module("keyring")
    except ModuleNotFoundError as exc:
        if exc.name != "keyring":
            raise
        return None


def _error_label(exc: Exception) -> str:
    """Return a safe backend error label without leaking secret bytes."""
    return type(exc).__name__


def _provider_key_env(provider: str) -> str:
    key = (provider or "").strip().lower()
    if key not in BUILTIN_PROVIDER_ENVS:
        valid = ", ".join(BUILTIN_PROVIDER_ENVS)
        raise ValueError(f"unknown provider '{provider}' (expected one of: {valid})")
    return BUILTIN_PROVIDER_ENVS[key]


def _require_keyring():
    """Return the keyring module or raise a product-facing error."""
    try:
        keyring = _load_keyring()
    except Exception as exc:
        raise KeyStoreBackendError(
            f"keyring import failed ({_error_label(exc)})"
        ) from exc
    if keyring is None:
        raise KeyStoreUnavailable(
            f"OS key storage requires optional keyring support. Install with: {INSTALL_HINT}"
        )
    return keyring


def _get_keyring_value(keyring, key_env: str) -> str:
    """Read a keyring slot, surfacing backend failures explicitly."""
    try:
        return keyring.get_password(KEYRING_SERVICE, key_env) or ""
    except Exception as exc:
        # Keyring backends are pluggable and can raise backend-specific errors.
        # Surface a stable backend failure here instead of pretending the slot
        # is simply unset.
        raise KeyStoreBackendError(
            f"keyring backend error ({_error_label(exc)})"
        ) from exc


def builtin_key_slots() -> list[tuple[str, str]]:
    """Return (provider, key_env) tuples in CLI display order."""
    return [(provider, BUILTIN_PROVIDER_ENVS[provider]) for provider in BUILTIN_PROVIDER_ENVS]


def builtin_provider_key_env(provider: str) -> str:
    """Return the default env-var slot for a built-in provider alias."""
    return _provider_key_env(provider)


def resolve_key(key_env: str) -> str:
    """Resolve a secret by env-var slot, preferring the OS keyring."""
    slot = str(key_env or "").strip()
    if not slot:
        return ""

    env_value = os.environ.get(slot, "")
    try:
        keyring = _load_keyring()
    except Exception:
        if env_value:
            sys.stderr.write(
                f"nah: LLM: keyring unavailable for {slot}; falling back to env\n"
            )
        return env_value
    if keyring is None:
        return env_value

    try:
        keyring_value = _get_keyring_value(keyring, slot)
    except KeyStoreBackendError:
        if env_value:
            sys.stderr.write(
                f"nah: LLM: keyring unavailable for {slot}; falling back to env\n"
            )
        return env_value

    if keyring_value:
        return keyring_value
    return env_value


def key_status(provider: str, key_env: str) -> KeyStatus:
    """Describe the effective key source for a provider slot."""
    env_value = os.environ.get(key_env, "")
    try:
        keyring = _load_keyring()
    except Exception as exc:
        note = f"keyring error: {_error_label(exc)}"
        if env_value:
            return KeyStatus(provider, key_env, "env", note)
        return KeyStatus(provider, key_env, "keyring-error", note)
    if keyring is None:
        if env_value:
            return KeyStatus(provider, key_env, "env")
        return KeyStatus(provider, key_env, "missing")

    try:
        keyring_value = _get_keyring_value(keyring, key_env)
    except KeyStoreBackendError as exc:
        note = str(exc)
        if env_value:
            return KeyStatus(provider, key_env, "env", note)
        return KeyStatus(provider, key_env, "keyring-error", note)

    if keyring_value:
        return KeyStatus(provider, key_env, "keyring")
    if env_value:
        return KeyStatus(provider, key_env, "env")
    return KeyStatus(provider, key_env, "missing")


def list_builtin_key_statuses() -> list[KeyStatus]:
    """Return effective key status for each built-in provider."""
    return [
        key_status(provider, key_env)
        for provider, key_env in builtin_key_slots()
    ]


def keyring_entry_exists(key_env: str) -> bool:
    """Return whether the nah-owned keyring slot already has a value."""
    keyring = _require_keyring()
    return bool(_get_keyring_value(keyring, key_env))


def set_key(key_env: str, secret: str) -> None:
    """Store a secret in the nah-owned OS keyring slot."""
    if not secret or not secret.strip():
        raise ValueError("secret cannot be empty")
    keyring = _require_keyring()
    try:
        keyring.set_password(KEYRING_SERVICE, key_env, secret)
    except Exception as exc:
        # Some keyring backends raise implementation-specific exceptions here.
        # Convert them into a stable product-facing error without echoing the
        # secret or backend-provided message text.
        raise KeyStoreBackendError(
            f"keyring backend error ({_error_label(exc)})"
        ) from exc


def remove_key(key_env: str) -> bool:
    """Delete a nah-owned keyring slot, returning True when it existed."""
    keyring = _require_keyring()
    if not _get_keyring_value(keyring, key_env):
        return False
    try:
        keyring.delete_password(KEYRING_SERVICE, key_env)
    except Exception as exc:
        raise KeyStoreBackendError(
            f"keyring backend error ({_error_label(exc)})"
        ) from exc
    return True


def read_env_key(key_env: str) -> str:
    """Return an env-var value for explicit import, or raise if missing."""
    value = os.environ.get(key_env, "")
    if not value:
        raise KeyStoreMissingEnv(f"{key_env} is not set in the environment")
    return value
