"""Layer-1 target re-check (nah-982): floor matches LLM-surfaced targets."""

from dataclasses import dataclass, field

import pytest

from nah import config, taxonomy
from nah.classify_recheck import recheck
from nah.config import NahConfig


@dataclass
class _Cls:
    action_type: str
    targets: list = field(default_factory=list)
    evidence: str = "ev"


def _t(kind, value):
    return {"kind": kind, "value": value}


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset cached config after each test (nah-994 config-driven cases)."""
    yield
    config._cached_config = None


# --- target-keyed floor catches sensitive targets regardless of type ---


def test_sensitive_path_blocks_allow_type():
    # filesystem_read is allow-policy, but ~/.ssh/id_rsa trips the floor.
    out = recheck(_Cls("filesystem_read", [_t("path", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)
    assert out["targets"][0]["floor"] == out["decision"]
    assert out["targets"][0]["kind"] == "path"


def test_known_host_clears_context_type():
    out = recheck(_Cls("network_outbound", [_t("host", "github.com")]),
                  taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ALLOW
    assert out["targets"][0]["floor"] == taxonomy.ALLOW


def test_unknown_host_asks():
    out = recheck(_Cls("network_outbound", [_t("host", "evil.example")]),
                  taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK


def test_unknown_kind_sensitive_path_still_caught():
    # An unknown/unroutable kind is sniffed as both path and host (most
    # restrictive wins), so a sensitive path is caught regardless of label.
    out = recheck(_Cls("filesystem_read", [_t("unknown", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)


def test_sensitive_path_tagged_host_still_caught():
    # A sensitive path tagged `host` lands on ask via the host checker (unknown
    # host), so it is not auto-allowed.
    out = recheck(_Cls("filesystem_read", [_t("host", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)


# --- db / container kinds route through config-driven allowlists (nah-994) ---
#
# Pre-nah-994 these kinds had no floor and auto-allowed. Now they route through
# the SAME resolvers the deterministic floor uses (db_targets / trusted_containers),
# so a target with no matching allowlist entry -> ask, matching `psql -d PROD`.


def test_db_target_no_config_asks():
    config._cached_config = NahConfig(db_targets=[])
    out = recheck(_Cls("db_write", [_t("db", "anything")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK
    assert out["targets"][0]["floor"] == taxonomy.ASK


def test_db_target_matches_allowlist_allows():
    config._cached_config = NahConfig(db_targets=[{"database": "STAGING"}])
    # case-insensitive parity with resolve_database_context (.upper()).
    out = recheck(_Cls("db_write", [_t("db", "staging")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ALLOW


def test_db_target_not_in_allowlist_asks():
    config._cached_config = NahConfig(db_targets=[{"database": "STAGING"}])
    out = recheck(_Cls("db_write", [_t("db", "PROD")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK


def test_db_target_wildcard_allows():
    config._cached_config = NahConfig(db_targets=[{"database": "*"}])
    out = recheck(_Cls("db_read", [_t("db", "PROD")]), taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ALLOW


def test_container_target_no_config_asks():
    config._cached_config = NahConfig(trusted_containers=[])
    out = recheck(_Cls("container_read", [_t("container", "mydb")]), taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ASK


def test_container_trusted_container_prefix_allows():
    config._cached_config = NahConfig(trusted_containers=["container:api"])
    out = recheck(_Cls("container_write", [_t("container", "api")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ALLOW


def test_container_trusted_compose_prefix_allows():
    config._cached_config = NahConfig(trusted_containers=["compose:web"])
    out = recheck(_Cls("container_write", [_t("container", "web")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ALLOW


def test_container_untrusted_asks():
    config._cached_config = NahConfig(trusted_containers=["container:api"])
    out = recheck(_Cls("container_write", [_t("container", "db")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK


def test_sensitive_path_mislabeled_container_now_asks():
    # Residual tightened (nah-994): a sensitive path tagged `container` now hits
    # the trusted_containers check, is absent, and asks instead of auto-allowing.
    config._cached_config = NahConfig(trusted_containers=[])
    out = recheck(_Cls("filesystem_read", [_t("container", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ASK


# --- policy tiers ---


def test_block_policy_blocks():
    out = recheck(_Cls("obfuscated", []), taxonomy.BLOCK)
    assert out["decision"] == taxonomy.BLOCK


def test_ask_policy_asks():
    out = recheck(_Cls("container_exec", []), taxonomy.ASK)
    assert out["decision"] == taxonomy.ASK


# --- no-target fallback ---


def test_target_insensitive_allow_with_no_target_allows():
    out = recheck(_Cls("git_safe", []), taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ALLOW


def test_target_sensitive_allow_with_no_target_asks():
    # filesystem_read is allow but target-sensitive; no surfaced target -> ask.
    out = recheck(_Cls("filesystem_read", []), taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ASK


def test_context_with_no_target_asks():
    out = recheck(_Cls("filesystem_write", []), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK


# --- most-restrictive across multiple targets ---


def test_most_restrictive_target_wins():
    out = recheck(
        _Cls("network_outbound",
             [_t("host", "github.com"), _t("host", "evil.example")]),
        taxonomy.CONTEXT,
    )
    assert out["decision"] == taxonomy.ASK
    assert len(out["targets"]) == 2
