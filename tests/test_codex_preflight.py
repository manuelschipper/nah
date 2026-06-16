"""Tests for Codex approval-memory and MCP preflight setup checks."""

from pathlib import Path

from nah.codex_authority import (
    AUTHORITY_RULES_MARKER,
    authority_rules_path,
    ensure_authority_rules,
)
from nah.codex_preflight import (
    blocking_findings,
    format_setup_blockers,
    scan_preflight,
    setup_preflight,
)


def _home(tmp_path, *, authority: bool = True) -> Path:
    home = tmp_path / "codex"
    home.mkdir()
    if authority:
        ensure_authority_rules(home=home)
    return home


def test_current_authority_rules_have_no_findings(tmp_path):
    findings = scan_preflight(home=_home(tmp_path), cwd=tmp_path)

    assert findings == []


def test_missing_authority_rules_blocks_startup(tmp_path):
    home = _home(tmp_path, authority=False)

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "codex_authority_missing"
    assert findings[0].repairable is True


def test_stale_authority_rules_blocks_and_is_repairable(tmp_path):
    home = _home(tmp_path, authority=False)
    path = authority_rules_path(home)
    path.parent.mkdir(parents=True)
    path.write_text(f"{AUTHORITY_RULES_MARKER}\nold\n", encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "codex_authority_stale"
    assert findings[0].repairable is True


def test_unmanaged_authority_rules_path_blocks_without_setup_fix(tmp_path):
    home = _home(tmp_path, authority=False)
    path = authority_rules_path(home)
    path.parent.mkdir(parents=True)
    path.write_text('prefix_rule(pattern=["cat"], decision="prompt")\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "codex_authority_conflict"
    assert findings[0].repairable is False


def test_prefix_allow_rule_blocks_startup(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rule = rules / "default.rules"
    rule.write_text('prefix_rule(pattern=["curl"], decision="allow")\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_allow"
    assert findings[0].path == str(rule)
    assert "curl" in findings[0].message


def test_network_allow_rule_blocks_startup(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rule = rules / "network.rules"
    rule.write_text('network_rule(host="example.com", decision="allow")\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_allow"
    assert "network_rule" in findings[0].message


def test_unknown_rule_decision_blocks_startup(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    (rules / "default.rules").write_text('prefix_rule(pattern=["curl"])\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_unknown"


def test_forbidden_rule_blocks_without_setup_fix(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rule = rules / "deny.rules"
    rule.write_text('prefix_rule(pattern=["cat"], decision="forbidden")\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_forbidden"
    assert findings[0].repairable is False


def test_host_executable_for_managed_prefix_blocks_without_setup_fix(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rule = rules / "host.rules"
    rule.write_text('host_executable(name="git", paths=["/usr/bin/git"])\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_host_executable"
    assert findings[0].repairable is False


def test_mcp_server_missing_auto_or_approve_blocks(tmp_path):
    home = _home(tmp_path)
    config = home / "config.toml"

    config.write_text('[mcp_servers.docs]\ncommand = "docs-server"\n', encoding="utf-8")
    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))
    assert any("missing" in finding.message for finding in findings)

    config.write_text(
        '[mcp_servers.docs]\ncommand = "docs-server"\ndefault_tools_approval_mode = "auto"\n',
        encoding="utf-8",
    )
    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))
    assert any("`auto`" in finding.message for finding in findings)

    config.write_text(
        '[mcp_servers.docs]\ncommand = "docs-server"\ndefault_tools_approval_mode = "approve"\n',
        encoding="utf-8",
    )
    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))
    assert any("`approve`" in finding.message for finding in findings)


def test_malformed_mcp_config_table_blocks(tmp_path):
    home = _home(tmp_path)
    (home / "config.toml").write_text("[mcp_servers.docs\ncommand = \"docs-server\"\n", encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "mcp_config_unknown"
    assert findings[0].repairable is False


def test_inline_mcp_config_blocks_when_not_evaluable(tmp_path):
    home = _home(tmp_path)
    (home / "config.toml").write_text(
        'mcp_servers = { docs = { default_tools_approval_mode = "approve" } }\n',
        encoding="utf-8",
    )

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "mcp_config_unknown"


def test_mcp_server_prompt_passes(tmp_path):
    home = _home(tmp_path)
    (home / "config.toml").write_text(
        '[mcp_servers.docs]\ncommand = "docs-server"\ndefault_tools_approval_mode = "prompt"\n',
        encoding="utf-8",
    )

    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_mcp_tool_approve_blocks_with_prompt_default(tmp_path):
    home = _home(tmp_path)
    (home / "config.toml").write_text(
        "\n".join([
            "[mcp_servers.docs]",
            'command = "docs-server"',
            'default_tools_approval_mode = "prompt"',
            "",
            "[mcp_servers.docs.tools.search]",
            'approval_mode = "approve"',
            "",
        ]),
        encoding="utf-8",
    )

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "mcp_tool"
    assert "docs.search" in findings[0].message


def test_disabled_mcp_server_is_ignored(tmp_path):
    home = _home(tmp_path)
    (home / "config.toml").write_text(
        '[mcp_servers.docs]\nenabled = false\ndefault_tools_approval_mode = "auto"\n',
        encoding="utf-8",
    )

    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_active_plugin_mcp_manifest_requires_prompt_overlay(tmp_path):
    home = _home(tmp_path)
    plugin_root = home / "plugins" / "cache" / "test" / "sample" / "local"
    plugin_root.mkdir(parents=True)
    (plugin_root / ".mcp.json").write_text(
        '{"mcpServers": {"sample": {"command": "sample-server"}}}',
        encoding="utf-8",
    )
    (home / "config.toml").write_text(
        '[plugins."sample@test"]\nenabled = true\n',
        encoding="utf-8",
    )

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "plugin_mcp_default"
    assert findings[0].plugin == "sample@test"
    assert findings[0].server == "sample"


def test_active_plugin_mcp_prompt_overlay_passes(tmp_path):
    home = _home(tmp_path)
    plugin_root = home / "plugins" / "cache" / "test" / "sample" / "local"
    plugin_root.mkdir(parents=True)
    (plugin_root / ".mcp.json").write_text(
        '{"mcpServers": {"sample": {"command": "sample-server"}}}',
        encoding="utf-8",
    )
    (home / "config.toml").write_text(
        "\n".join([
            '[plugins."sample@test"]',
            "enabled = true",
            "",
            '[plugins."sample@test".mcp_servers.sample]',
            'default_tools_approval_mode = "prompt"',
            "",
        ]),
        encoding="utf-8",
    )

    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_setup_removes_allows_and_sets_mcp_modes_to_prompt(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rule = rules / "default.rules"
    rule.write_text(
        "\n".join([
            'prefix_rule(pattern=["curl"], decision="allow")',
            'prefix_rule(pattern=["git", "status"], decision="prompt")',
            "",
        ]),
        encoding="utf-8",
    )
    config = home / "config.toml"
    config.write_text(
        "\n".join([
            "[mcp_servers.docs]",
            'command = "docs-server"',
            'default_tools_approval_mode = "auto"',
            "",
            "[mcp_servers.docs.tools.search]",
            'approval_mode = "approve"',
            "",
        ]),
        encoding="utf-8",
    )

    result = setup_preflight(home=home, cwd=tmp_path)

    assert str(rule) in result.changed
    assert str(config) in result.changed
    assert len(result.backups) == 2
    assert 'decision="allow"' not in rule.read_text(encoding="utf-8")
    assert 'decision="prompt"' in rule.read_text(encoding="utf-8")
    updated_config = config.read_text(encoding="utf-8")
    assert 'default_tools_approval_mode = "prompt"' in updated_config
    assert 'approval_mode = "prompt"' in updated_config
    assert scan_preflight(home=home, cwd=tmp_path) == []
    assert result.final_findings == []


def test_setup_installs_missing_authority_rules(tmp_path):
    home = _home(tmp_path, authority=False)

    result = setup_preflight(home=home, cwd=tmp_path)

    path = authority_rules_path(home)
    assert str(path) in result.changed
    assert path.exists()
    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_setup_refreshes_stale_authority_rules(tmp_path):
    home = _home(tmp_path, authority=False)
    path = authority_rules_path(home)
    path.parent.mkdir(parents=True)
    path.write_text(f"{AUTHORITY_RULES_MARKER}\nold\n", encoding="utf-8")

    result = setup_preflight(home=home, cwd=tmp_path)

    assert str(path) in result.changed
    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_setup_refreshes_stale_authority_rules_with_allow_without_corruption(tmp_path):
    home = _home(tmp_path, authority=False)
    path = authority_rules_path(home)
    path.parent.mkdir(parents=True)
    path.write_text(
        "\n".join([
            AUTHORITY_RULES_MARKER,
            'prefix_rule(pattern=["cat"], decision="allow")',
            "",
        ]),
        encoding="utf-8",
    )

    result = setup_preflight(home=home, cwd=tmp_path)

    updated = path.read_text(encoding="utf-8")
    assert str(path) in result.changed
    assert 'pattern = ["cat"]' in updated
    assert 'decision = "prompt"' in updated
    assert 'decision="allow"' not in updated
    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_setup_adds_plugin_mcp_prompt_overlay(tmp_path):
    home = _home(tmp_path)
    plugin_root = home / "plugins" / "cache" / "test" / "sample" / "local"
    plugin_root.mkdir(parents=True)
    (plugin_root / ".mcp.json").write_text(
        '{"mcpServers": {"sample": {"command": "sample-server"}}}',
        encoding="utf-8",
    )
    config = home / "config.toml"
    config.write_text('[plugins."sample@test"]\nenabled = true\n', encoding="utf-8")

    result = setup_preflight(home=home, cwd=tmp_path)

    assert str(config) in result.changed
    updated_config = config.read_text(encoding="utf-8")
    assert '[plugins."sample@test".mcp_servers.sample]' in updated_config
    assert 'default_tools_approval_mode = "prompt"' in updated_config
    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_setup_blockers_include_exact_rule_remediation(tmp_path):
    home = _home(tmp_path)
    rule = home / "rules" / "deny.rules"
    rule.write_text('prefix_rule(pattern=["cat"], decision="forbidden")\n', encoding="utf-8")

    output = format_setup_blockers(scan_preflight(home=home, cwd=tmp_path))

    assert "codex: still blocked:" in output
    assert str(rule) in output
    assert 'prefix_rule(pattern=["cat"], decision="forbidden")' in output
    assert "Remove this rule or change its decision to `prompt`." in output
