"""Tests for deterministic human-facing decision messages."""

from nah import messages, taxonomy


def assert_clean(fragment: str) -> None:
    assert "\u2192" not in fragment
    assert "->" not in fragment
    assert "git_history_rewrite" not in fragment
    assert "network | exec" not in fragment
    assert not fragment.lower().startswith("nah")
    assert ".." not in fragment
    assert "\n" not in fragment


def test_composition_messages_take_priority():
    cases = [
        ("network | exec", "this downloads code and runs it in bash"),
        ("sensitive_read | network", "this sends sensitive local data over the network"),
        ("decode | exec", "this decodes hidden content and runs it"),
        ("read | exec", "this runs code read from a local file or command output"),
    ]
    for composition, expected in cases:
        fragment = messages.human_reason(
            "Bash: remote code execution: bash receives network input",
            decision=taxonomy.BLOCK,
            meta={"composition_rule": composition},
        )
        assert fragment == expected
        assert_clean(fragment)


def test_composition_reason_text_translates_without_metadata():
    cases = [
        ("unwrapped: data exfiltration: curl receives sensitive input", "this sends sensitive local data over the network"),
        ("unwrapped: obfuscated execution: bash receives decoded input", "this decodes hidden content and runs it"),
        ("unwrapped: local code execution: bash receives file input", "this runs code read from a local file or command output"),
        ("if body uses command substitution", "this shell body uses dynamic command output"),
        ("control-flow pipeline is not inspectable", "this shell loop pipes output in a way nah cannot inspect safely"),
        ("for-loop variable comes from a dynamic item list", "this shell loop uses a dynamic item list"),
        (
            "for-loop variable uses unsupported shell expansion",
            "this shell loop uses shell expansion nah cannot inspect safely",
        ),
        (
            "for-loop variable is hidden by shell syntax",
            "this shell loop hides a variable in shell syntax nah cannot inspect safely",
        ),
    ]
    for reason, expected in cases:
        fragment = messages.human_reason(reason, decision=taxonomy.BLOCK)
        assert fragment == expected
        assert_clean(fragment)


def test_reason_pattern_messages():
    cases = [
        ("network_outbound \u2192 ask (unknown host: schipper.ai)", "this contacts an untrusted host: schipper.ai"),
        ("network_write \u2192 ask (host: evil.example)", "this sends data over the network to: evil.example"),
        ("network_write to localhost: 127.0.0.1:3000", "this sends data to a local service: 127.0.0.1:3000"),
        ("targets sensitive path: ~/.bashrc", "this targets a protected file or folder: ~/.bashrc"),
        ("targets nah config: ~/.config/nah/config.yaml", "this changes nah's own configuration"),
        ("targets hook directory: ~/.claude/hooks/evil.py", "this tries to modify Claude Code hooks"),
        ("script outside project: /tmp/run-me.sh", "this runs a script outside the current project: /tmp/run-me.sh"),
        ("Write outside project: /tmp/out.txt", "this writes outside the current project: /tmp/out.txt"),
        ("script not found: ./missing.sh", "this script path does not exist: ./missing.sh"),
        ("terminal guard supports complete single-line commands only", "this shell input is too complex to inspect safely"),
        ("terminal guard cannot safely run here-doc input", "this shell input is too complex to inspect safely"),
        ("unrecognized tool: WeirdTool", "this uses an unrecognized tool: WeirdTool"),
    ]
    for reason, expected in cases:
        fragment = messages.human_reason(reason, decision=taxonomy.ASK)
        assert fragment == expected
        assert_clean(fragment)


def test_content_categories_translate_to_plain_copy():
    assert messages.human_reason("Write content inspection [secret]: private key", decision=taxonomy.ASK) == (
        "this includes content that looks like a secret"
    )
    assert messages.human_reason("Write content inspection [obfuscation]: base64", decision=taxonomy.ASK) == (
        "this includes hidden or encoded code"
    )
    assert messages.human_reason("Write content inspection [destructive]: rm -rf", decision=taxonomy.BLOCK) == (
        "this includes code that can delete or overwrite data"
    )
    assert messages.human_reason("Write content inspection [exfiltration]: curl -d", decision=taxonomy.ASK) == (
        "this includes code that can send local data over the network"
    )


def test_action_type_fallbacks_are_human_copy():
    cases = [
        (taxonomy.GIT_HISTORY_REWRITE, "this can rewrite Git history"),
        (taxonomy.GIT_DISCARD, "this can discard local Git changes"),
        (taxonomy.GIT_REMOTE_WRITE, "this writes to a remote Git repository"),
        (taxonomy.OBFUSCATED, "this hides what will run"),
        (taxonomy.UNKNOWN, "this runs an unrecognized command"),
    ]
    for action_type, expected in cases:
        fragment = messages.human_reason(
            f"{action_type} \u2192 ask",
            decision=taxonomy.ASK,
            action_type=action_type,
        )
        assert fragment == expected
        assert_clean(fragment)


def test_all_action_types_have_human_copy_even_when_policy_is_overridden():
    generic = {
        "this needs confirmation before it can run",
        "this was blocked before it could run",
    }
    for action_type, policy in taxonomy.POLICIES.items():
        for decision in (taxonomy.ASK, taxonomy.BLOCK):
            fragment = messages.human_reason(
                f"{action_type} \u2192 {policy}",
                decision=decision,
                action_type=action_type,
            )
            assert fragment not in generic, action_type
            assert_clean(fragment)

            reason_only = messages.human_reason(f"{action_type} \u2192 {policy}", decision=decision)
            assert reason_only == fragment

            top_level = messages.enrich_decision(
                {
                    "decision": decision,
                    "reason": f"{action_type} \u2192 {policy}",
                    "action_type": action_type,
                }
            )
            assert top_level["human_reason"] == fragment

            with_stage = messages.enrich_decision(
                {
                    "decision": decision,
                    "reason": f"{action_type} \u2192 {policy}",
                    "_meta": {
                        "stages": [
                            {
                                "action_type": action_type,
                                "decision": decision,
                                "policy": policy,
                                "reason": f"{action_type} \u2192 {policy}",
                            }
                        ]
                    },
                }
            )
            assert with_stage["human_reason"] == fragment

            invalid_meta = messages.enrich_decision(
                {
                    "decision": decision,
                    "reason": f"{action_type} \u2192 {policy}",
                    "_meta": None,
                }
            )
            assert invalid_meta["human_reason"] == fragment


def test_enrich_decision_tolerates_missing_or_invalid_meta():
    decision = messages.enrich_decision(
        {
            "decision": taxonomy.ASK,
            "reason": "package_install \u2192 ask",
            "action_type": taxonomy.PACKAGE_INSTALL,
            "_meta": None,
        }
    )

    assert decision["human_reason"] == "this installs packages"
    assert decision["_meta"]["human_reason"] == "this installs packages"


def test_enrich_decision_repairs_prefixed_or_technical_human_reason():
    prefixed = messages.enrich_decision(
        {
            "decision": taxonomy.ASK,
            "reason": "some fallback",
            "human_reason": "nah paused: this can rewrite Git history.",
        }
    )
    assert prefixed["human_reason"] == "this can rewrite Git history"

    technical = messages.enrich_decision(
        {
            "decision": taxonomy.ASK,
            "reason": "some fallback",
            "human_reason": "git_history_rewrite \u2192 ask",
        }
    )
    assert technical["human_reason"] == "this can rewrite Git history"


def test_raw_reason_fallback_survives_malformed_stage_action_type():
    decision = messages.enrich_decision(
        {
            "decision": taxonomy.BLOCK,
            "reason": "obfuscated \u2192 block",
            "_meta": {
                "stages": [
                    {
                        "action_type": 123,
                        "decision": taxonomy.BLOCK,
                        "policy": taxonomy.BLOCK,
                        "reason": "obfuscated \u2192 block",
                    }
                ]
            },
        }
    )

    assert decision["human_reason"] == "this hides what will run"


def test_raw_reason_action_detection_does_not_match_paths_or_hosts():
    assert messages.human_reason(
        "downloaded https://example.com/git_history_rewrite.tar.gz",
        decision=taxonomy.ASK,
    ) == "this needs confirmation before it can run"
    assert messages.human_reason(
        "looked at /tmp/git_history_rewrite",
        decision=taxonomy.BLOCK,
    ) == "this was blocked before it could run"


def test_enrich_decision_uses_top_level_action_type_without_stage_meta():
    decision = messages.enrich_decision(
        {
            "decision": taxonomy.ASK,
            "reason": "git_history_rewrite \u2192 ask",
            "action_type": taxonomy.GIT_HISTORY_REWRITE,
        }
    )

    assert decision["human_reason"] == "this can rewrite Git history"
    assert decision["_meta"]["human_reason"] == "this can rewrite Git history"


def test_value_sanitization_is_bounded_and_one_line():
    long_host = "evil.example" + "x" * 100 + ")."
    fragment = messages.human_reason(
        f"unknown host: {long_host}\nnext line",
        decision=taxonomy.ASK,
    )
    assert fragment.startswith("this contacts an untrusted host: evil.example")
    assert len(fragment) < 120
    assert "\n" not in fragment
    assert ")" not in fragment


def test_brand_punctuation_and_multiline_diagnostics():
    branded = messages.brand("nah paused", "this can rewrite Git history.\n     To always allow: nah allow git_history_rewrite")
    assert branded.startswith("nah paused: this can rewrite Git history.\n")
    assert "Git history.." not in branded
    assert "nah allow git_history_rewrite" in branded
