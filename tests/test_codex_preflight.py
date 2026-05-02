"""Tests for Codex approval-memory and MCP preflight scanning."""

from pathlib import Path

from nah.codex_preflight import blocking_findings, repair_preflight, scan_preflight


def _home(tmp_path) -> Path:
    home = tmp_path / "codex"
    home.mkdir()
    return home


def test_empty_codex_home_has_no_findings(tmp_path):
    findings = scan_preflight(home=_home(tmp_path), cwd=tmp_path)

    assert findings == []


def test_prefix_allow_rule_blocks_startup(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rules.mkdir()
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
    rules.mkdir()
    rule = rules / "network.rules"
    rule.write_text('network_rule(host="example.com", decision="allow")\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_allow"
    assert "network_rule" in findings[0].message


def test_unknown_rule_decision_blocks_startup(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rules.mkdir()
    (rules / "default.rules").write_text('prefix_rule(pattern=["curl"])\n', encoding="utf-8")

    findings = blocking_findings(scan_preflight(home=home, cwd=tmp_path))

    assert len(findings) == 1
    assert findings[0].kind == "exec_policy_unknown"


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


def test_repair_removes_allows_and_sets_mcp_modes_to_prompt(tmp_path):
    home = _home(tmp_path)
    rules = home / "rules"
    rules.mkdir()
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

    result = repair_preflight(home=home, cwd=tmp_path)

    assert str(rule) in result.changed
    assert str(config) in result.changed
    assert len(result.backups) == 2
    assert 'decision="allow"' not in rule.read_text(encoding="utf-8")
    assert 'decision="prompt"' in rule.read_text(encoding="utf-8")
    repaired_config = config.read_text(encoding="utf-8")
    assert 'default_tools_approval_mode = "prompt"' in repaired_config
    assert 'approval_mode = "prompt"' in repaired_config
    assert scan_preflight(home=home, cwd=tmp_path) == []


def test_repair_adds_plugin_mcp_prompt_overlay(tmp_path):
    home = _home(tmp_path)
    plugin_root = home / "plugins" / "cache" / "test" / "sample" / "local"
    plugin_root.mkdir(parents=True)
    (plugin_root / ".mcp.json").write_text(
        '{"mcpServers": {"sample": {"command": "sample-server"}}}',
        encoding="utf-8",
    )
    config = home / "config.toml"
    config.write_text('[plugins."sample@test"]\nenabled = true\n', encoding="utf-8")

    result = repair_preflight(home=home, cwd=tmp_path)

    assert str(config) in result.changed
    repaired_config = config.read_text(encoding="utf-8")
    assert '[plugins."sample@test".mcp_servers.sample]' in repaired_config
    assert 'default_tools_approval_mode = "prompt"' in repaired_config
    assert scan_preflight(home=home, cwd=tmp_path) == []
