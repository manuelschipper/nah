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


def test_mislabeled_sensitive_path_as_host_still_caught():
    # Kind says "host" but value is a sensitive path: unknown/sniff path... here
    # the value is tagged host; the sniff happens for kind="unknown". Tag it
    # unknown to exercise the both-checkers path.
    out = recheck(_Cls("filesystem_read", [_t("unknown", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)


def test_container_target_has_no_floor():
    out = recheck(_Cls("container_read", [_t("container", "mydb")]),
                  taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ALLOW
    assert out["targets"][0]["floor"] == taxonomy.ALLOW


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
