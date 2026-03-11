"""Unit tests for _classify_unknown_tool — FD-037 + FD-024 + FD-045."""

from nah.hook import _classify_unknown_tool
from nah import config
from nah.config import NahConfig


class TestClassifyUnknownTool:
    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def test_no_config_returns_ask(self):
        d = _classify_unknown_tool("SomeTool")
        assert d["decision"] == "ask"
        assert "unrecognized tool" in d["reason"]

    def test_global_classify_allow(self):
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["MyTool"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("MyTool")
        assert d["decision"] == "allow"

    def test_global_classify_ask(self):
        config._cached_config = NahConfig(
            classify_global={"db_write": ["DbTool"]},
        )
        d = _classify_unknown_tool("DbTool")
        assert d["decision"] == "ask"

    def test_mcp_skips_project_classify(self):
        config._cached_config = NahConfig(
            classify_project={"mcp_trusted": ["mcp__evil__exfil"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("mcp__evil__exfil")
        assert d["decision"] == "ask"  # project ignored

    def test_non_mcp_uses_project_classify(self):
        config._cached_config = NahConfig(
            classify_project={"package_run": ["CustomRunner"]},
        )
        d = _classify_unknown_tool("CustomRunner")
        assert d["decision"] == "allow"  # package_run → allow

    # --- FD-024 adversarial tests ---

    def test_mcp_classify_prefix_collision(self):
        """mcp__postgres in config must NOT match mcp__postgres__query."""
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["mcp__postgres"]},
            actions={"mcp_trusted": "allow"},
        )
        # Exact match
        d = _classify_unknown_tool("mcp__postgres")
        assert d["decision"] == "allow"
        # Different tool — no match (single-token prefix, not substring)
        d = _classify_unknown_tool("mcp__postgres__query")
        assert d["decision"] == "ask"

    def test_mcp_classified_global_allow(self):
        """Global config can classify and allow MCP tools."""
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["mcp__memory__search"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("mcp__memory__search")
        assert d["decision"] == "allow"

    # --- FD-045 configurable unknown tool policy ---

    def test_unknown_default_ask(self):
        """No actions config → unknown defaults to ask."""
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "ask"
        assert "unrecognized tool" in d["reason"]

    def test_unknown_actions_block(self):
        """actions.unknown: block → block unknown tools."""
        config._cached_config = NahConfig(actions={"unknown": "block"})
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "block"
        assert "unrecognized tool" in d["reason"]

    def test_unknown_actions_allow(self):
        """actions.unknown: allow → allow unknown tools."""
        config._cached_config = NahConfig(actions={"unknown": "allow"})
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "allow"

    def test_unknown_context_falls_to_ask(self):
        """actions.unknown: context → ask (no context resolver for 'unknown' type)."""
        config._cached_config = NahConfig(actions={"unknown": "context"})
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "ask"
        assert "no context resolver" in d["reason"]


class TestClassifyUnknownToolContext:
    """FD-055: MCP tools with context policy resolve context via tool_input."""

    def setup_method(self):
        config._cached_config = NahConfig(
            classify_global={"db_write": ["mcp__snowflake__execute_sql"]},
            actions={"db_write": "context"},
            db_targets=[
                {"database": "SANDBOX"},
                {"database": "SALES", "schema": "DEV"},
            ],
        )

    def teardown_method(self):
        config._cached_config = None

    def test_mcp_db_write_matching_target_allow(self):
        """MCP tool_input with matching database → allow."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SANDBOX", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "allowed target" in d["reason"]

    def test_mcp_db_write_matching_db_schema_allow(self):
        """MCP tool_input with matching database+schema → allow."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SALES", "schema": "DEV", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "SALES.DEV" in d["reason"]

    def test_mcp_db_write_non_matching_target_ask(self):
        """MCP tool_input with non-matching database → ask."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "PRODUCTION", "query": "DROP TABLE users"},
        )
        assert d["decision"] == "ask"
        assert "unrecognized target" in d["reason"]

    def test_mcp_db_write_no_database_key_ask(self):
        """MCP tool_input without database key → ask."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"query": "SELECT 1"},
        )
        assert d["decision"] == "ask"
        assert "unknown database target" in d["reason"]

    def test_mcp_db_write_no_tool_input_ask(self):
        """MCP with no tool_input → ask."""
        d = _classify_unknown_tool("mcp__snowflake__execute_sql")
        assert d["decision"] == "ask"

    def test_mcp_db_write_no_db_targets_ask(self):
        """No db_targets configured → ask even with matching input."""
        config._cached_config = NahConfig(
            classify_global={"db_write": ["mcp__snowflake__execute_sql"]},
            actions={"db_write": "context"},
            db_targets=[],
        )
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SANDBOX", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "ask"
        assert "no db_targets configured" in d["reason"]

    def test_mcp_db_write_empty_tool_input_ask(self):
        """Empty dict {} (what main() actually passes) → ask."""
        d = _classify_unknown_tool("mcp__snowflake__execute_sql", {})
        assert d["decision"] == "ask"
        assert "unknown database target" in d["reason"]

    def test_mcp_db_write_case_insensitive(self):
        """Database name matching is case-insensitive."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "sandbox", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "SANDBOX" in d["reason"]

    def test_mcp_non_db_context_falls_to_ask(self):
        """MCP tool classified as network_outbound + context → ask (no tokens)."""
        config._cached_config = NahConfig(
            classify_global={"network_outbound": ["mcp__api__fetch"]},
            actions={"network_outbound": "context"},
        )
        d = _classify_unknown_tool(
            "mcp__api__fetch",
            {"url": "https://example.com"},
        )
        assert d["decision"] == "ask"
        assert "unknown host" in d["reason"]

    def test_mcp_db_write_default_policy_ask(self):
        """db_write with default policy (ask, not context) → no context resolution."""
        config._cached_config = NahConfig(
            classify_global={"db_write": ["mcp__snowflake__execute_sql"]},
            db_targets=[{"database": "SANDBOX"}],
        )
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SANDBOX", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "ask"
        assert "allowed target" not in d.get("reason", "")
