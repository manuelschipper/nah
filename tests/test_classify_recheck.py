"""Layer-1 target re-check (nah-982, nah-994): policy baseline + path/host tighten."""

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


def test_unknown_kind_bareword_is_not_a_host():
    # Regression: an unknown-kind bareword (e.g. a `for id in mold-7 ...` loop
    # value / mold id) is not host-shaped, so it must not be routed through the
    # host floor and mislabeled "unknown host". git_write is allow-policy with a
    # clean path target, so the command should clear, not ask as an untrusted host.
    out = recheck(
        _Cls("git_write", [_t("path", "."), _t("unknown", "mold-7"),
                           _t("unknown", "molds-7")]),
        taxonomy.ALLOW,
    )
    assert out["decision"] == taxonomy.ALLOW
    assert "unknown host" not in out["reason"]
    bareword = next(t for t in out["targets"] if t["value"] == "mold-7")
    assert bareword["floor"] == taxonomy.ALLOW
    assert "host" not in bareword["reason"]


def test_unknown_kind_dotted_value_still_host_checked():
    # A host-shaped unknown-kind value (dotted) is still sniffed as a host, so a
    # mislabeled untrusted host remains caught.
    out = recheck(_Cls("git_write", [_t("unknown", "evil.example")]),
                  taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ASK


def test_sensitive_path_tagged_host_still_caught():
    # A sensitive path tagged `host` lands on ask via the host checker (unknown
    # host), so it is not auto-allowed.
    out = recheck(_Cls("filesystem_read", [_t("host", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)


# --- db / container kinds are unverifiable; the policy decides (nah-994) ---
#
# Config-independent: db/container targets never consult db_targets /
# trusted_containers. allow-policy reads clear; context-policy lifecycle asks.


def test_db_safe_target_allows():
    # Parity guard: deterministic db_safe is unconditional allow, so Layer 1
    # must not be stricter — an unverifiable db target does not force ask.
    out = recheck(_Cls("db_safe", [_t("db", "prod")]), taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ALLOW
    assert out["targets"][0]["floor"] == "unverified"


def test_container_read_target_allows():
    # Parity guard: deterministic container_read is unconditional allow.
    out = recheck(_Cls("container_read", [_t("container", "api")]), taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ALLOW


def test_db_exec_target_asks():
    # context type + unverifiable db target -> cannot confirm -> ask.
    out = recheck(_Cls("db_exec", [_t("db", "prod")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK
    assert out["targets"][0]["floor"] == "unverified"


def test_container_lifecycle_target_asks():
    out = recheck(_Cls("container_lifecycle", [_t("container", "api")]), taxonomy.CONTEXT)
    assert out["decision"] == taxonomy.ASK


def test_sensitive_path_mislabeled_container_asks():
    # Residual tightened (nah-994): a sensitive path tagged `container` is
    # unverifiable, so a target-sensitive allow type falls back to ask instead
    # of the old blanket auto-allow.
    out = recheck(_Cls("filesystem_read", [_t("container", "~/.ssh/id_rsa")]),
                  taxonomy.ALLOW)
    assert out["decision"] == taxonomy.ASK


def test_context_mixed_cleared_host_and_db_target_asks():
    # Guards the load-bearing `unverifiable > 0` clause: a context type whose
    # host target clears but which ALSO carries an unverifiable db target cannot
    # be confirmed safe -> ask. Without that term this would wrongly allow.
    out = recheck(
        _Cls("network_outbound", [_t("host", "github.com"), _t("db", "prod")]),
        taxonomy.CONTEXT,
    )
    assert out["decision"] == taxonomy.ASK


def test_insensitive_read_still_tightens_on_sensitive_path_with_db_target():
    # An allow-policy read is target-insensitive, but a verifiable sensitive path
    # still tightens it even alongside an unverifiable db target — the path floor
    # (worst) wins before the insensitive clearance. (~/.ssh is ask or block
    # depending on config, so accept either non-allow tier, like the sibling.)
    out = recheck(
        _Cls("db_safe", [_t("db", "prod"), _t("path", "~/.ssh/id_rsa")]),
        taxonomy.ALLOW,
    )
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)


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
