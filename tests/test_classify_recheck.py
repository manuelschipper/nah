"""Layer-1 target re-check (nah-982): floor matches LLM-surfaced targets."""

from dataclasses import dataclass, field

from nah import taxonomy
from nah.classify_recheck import recheck


@dataclass
class _Cls:
    action_type: str
    targets: list = field(default_factory=list)
    evidence: str = "ev"


def _t(kind, value):
    return {"kind": kind, "value": value}


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


def test_container_db_kind_is_an_accepted_residual():
    # ACCEPTED RESIDUAL (nah-982 QA): container/db kinds have no floor list and
    # are NOT re-sniffed as path/host, so a sensitive value mislabeled
    # container/db is auto-allowed. This is intentionally tolerated: Layer 1
    # auto-allow trusts an honest classifier (a misaligned/injected classifier
    # could equally omit the target entirely), and the real security boundary is
    # the deterministic floor on KNOWN commands, not Layer 1. Genuine
    # container/db targets are the common case and stay allow.
    genuine = recheck(_Cls("container_read", [_t("container", "mydb")]),
                      taxonomy.ALLOW)
    assert genuine["decision"] == taxonomy.ALLOW
    assert genuine["targets"][0]["floor"] == taxonomy.ALLOW
    # The residual: a sensitive path mislabeled container is not caught here.
    mislabeled = recheck(_Cls("filesystem_read", [_t("container", "~/.ssh/id_rsa")]),
                         taxonomy.ALLOW)
    assert mislabeled["decision"] == taxonomy.ALLOW  # documents the known gap


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
