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


def test_reason_pattern_messages():
    cases = [
        ("network_outbound \u2192 ask (unknown host: schipper.ai)", "this contacts an untrusted host: schipper.ai"),
        ("network_write \u2192 ask (host: evil.example)", "this sends data over the network to: evil.example"),
        ("network_write to localhost: 127.0.0.1:3000", "this sends data to a local service: 127.0.0.1:3000"),
        ("targets sensitive path: ~/.bashrc", "this targets a protected file or folder: ~/.bashrc"),
        ("targets nah config: ~/.config/nah/config.yaml", "this changes nah's own configuration"),
        ("targets hook directory: ~/.claude/hooks/evil.py", "this tries to modify Claude Code hooks"),
        ("Write outside project: /tmp/out.txt", "this writes outside the current project: /tmp/out.txt"),
        ("script not found: ./missing.sh", "this tries to run a script that was not found: ./missing.sh"),
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
