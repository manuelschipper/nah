"""Unit tests for nah.context — filesystem and network context resolution."""

import os
import subprocess

import pytest

from unittest.mock import patch

from nah import paths
from nah import config
from nah.config import NahConfig
from nah.context import (
    check_host,
    extract_host,
    resolve_context,
    resolve_container_lifecycle_context,
    resolve_filesystem_context,
    resolve_lang_exec_context,
    resolve_network_context,
    reset_known_hosts,
)
import nah.context


def _make_git_worktree(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / ".claude" / "skills").mkdir(parents=True)
    (repo / ".claude" / "skills" / "demo.md").write_text("skill\n", encoding="utf-8")
    (repo / "script.py").write_text("print('ok')\n", encoding="utf-8")
    (repo / "file.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True, text=True)
    worktree = repo / ".worktrees" / "feature"
    subprocess.run(
        ["git", "worktree", "add", "-b", "feature", str(worktree)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return repo, worktree


# --- resolve_filesystem_context ---


class TestResolveFilesystemContext:
    def test_inside_project(self, project_root):
        # Create a file inside the project root
        target = os.path.join(project_root, "src", "main.py")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        decision, reason = resolve_filesystem_context(target)
        assert decision == "allow"
        assert "inside project" in reason

    def test_outside_project(self, project_root):
        """Path outside project but not trusted → ask."""
        decision, reason = resolve_filesystem_context("/opt/somewhere/outside.txt")
        assert decision == "ask"
        assert "outside project" in reason

    def test_tmp_trusted_by_default(self, project_root):
        """/tmp is trusted by default in profile: full."""
        decision, reason = resolve_filesystem_context("/tmp/scratch.txt")
        assert decision == "allow"
        assert "trusted" in reason

    def test_no_project_root(self):
        """Non-trusted path with no project root → ask."""
        paths.set_project_root(None)
        assert paths.get_project_root() is None
        decision, reason = resolve_filesystem_context("/opt/random/file.txt")
        assert decision == "ask"
        assert "no project root" in reason

    def test_sensitive_path(self, project_root):
        decision, reason = resolve_filesystem_context("~/.ssh/id_rsa")
        assert decision == "block"
        assert "sensitive path" in reason

    def test_sensitive_path_home_env_var(self, project_root):
        decision, reason = resolve_filesystem_context("$HOME/.ssh/id_rsa")
        assert decision == "block"
        assert "sensitive path" in reason

    def test_sensitive_path_home_glob(self, project_root):
        decision, reason = resolve_filesystem_context("/home/*/.aws/credentials")
        assert decision == "ask"
        assert "sensitive path" in reason

    def test_hook_path_not_flagged_as_hook(self, project_root):
        """Hook path no longer flagged as hook directory — ask is for outside-project."""
        decision, reason = resolve_filesystem_context("~/.claude/hooks/guard.py")
        assert decision == "ask"
        assert "outside project" in reason  # not "hook directory"

    def test_empty_path(self, project_root):
        decision, _ = resolve_filesystem_context("")
        assert decision == "allow"

    def test_project_root_itself(self, project_root):
        decision, reason = resolve_filesystem_context(project_root)
        assert decision == "allow"
        assert "inside project" in reason

    def test_main_repo_file_inside_project_from_worktree(self, tmp_path, monkeypatch):
        repo, worktree = _make_git_worktree(tmp_path)
        monkeypatch.chdir(worktree)
        paths.reset_project_root()
        target = repo / ".claude" / "skills" / "demo.md"

        decision, reason = resolve_filesystem_context(str(target))

        assert decision == "allow"
        assert "inside project" in reason

    def test_lang_exec_main_repo_script_inside_project_from_worktree(self, tmp_path, monkeypatch):
        repo, worktree = _make_git_worktree(tmp_path)
        monkeypatch.chdir(worktree)
        paths.reset_project_root()
        target = repo / "script.py"

        decision, reason = resolve_lang_exec_context(str(target))

        assert decision == "allow"
        assert "script path allowed" in reason


# --- resolve_network_context ---


class TestResolveNetworkContext:
    def test_localhost(self):
        decision, reason = resolve_network_context(["curl", "http://localhost:3000"])
        assert decision == "allow"
        assert "localhost" in reason

    def test_127_0_0_1(self):
        decision, reason = resolve_network_context(["curl", "http://127.0.0.1:8080"])
        assert decision == "allow"
        assert "localhost" in reason

    def test_ipv6_localhost(self):
        decision, reason = resolve_network_context(["curl", "http://[::1]:8080"])
        # urlparse may or may not handle [::1] well, but we test the intent
        # The extract_host may return "::1" or None depending on parsing
        assert decision in ("allow", "ask")

    def test_known_host_github(self):
        decision, reason = resolve_network_context(["curl", "https://github.com/repo"])
        assert decision == "allow"
        assert "known host" in reason

    def test_known_host_pypi(self):
        decision, reason = resolve_network_context(["curl", "https://pypi.org/simple/"])
        assert decision == "allow"
        assert "known host" in reason

    def test_known_host_npmjs(self):
        decision, reason = resolve_network_context(["curl", "https://registry.npmjs.org/pkg"])
        assert decision == "allow"

    def test_unknown_host(self):
        decision, reason = resolve_network_context(["curl", "https://evil.com/data"])
        assert decision == "ask"
        assert "unknown host" in reason
        assert "evil.com" in reason

    def test_no_host_extracted(self):
        decision, reason = resolve_network_context(["curl"])
        assert decision == "ask"
        assert "unknown host" in reason

    def test_rsync_remote_host(self):
        decision, reason = resolve_network_context(
            ["rsync", "-avz", "./local/", "user@host.com:/remote/"]
        )
        assert decision == "ask"
        assert "host.com" in reason

    def test_ssh_copy_id_host(self):
        decision, reason = resolve_network_context(["ssh-copy-id", "user@myserver.com"])
        assert decision == "ask"
        assert "myserver.com" in reason


# --- check_host (bare-host entry, used by Layer-1 target re-check) ---


class TestCheckHost:
    def test_known_host_allows(self):
        decision, reason = check_host("github.com")
        assert decision == "allow"
        assert "known host" in reason

    def test_known_host_with_port(self):
        decision, reason = check_host("github.com:443")
        assert decision == "allow"

    def test_localhost_read_allows(self):
        decision, reason = check_host("localhost")
        assert decision == "allow"
        assert "localhost" in reason

    def test_localhost_write_asks(self):
        decision, reason = check_host("localhost", "network_write")
        assert decision == "ask"

    def test_unknown_host_asks(self):
        decision, reason = check_host("evil.example")
        assert decision == "ask"
        assert "evil.example" in reason

    def test_known_host_write_asks(self):
        # Known hosts are only trusted for reads; a write to one still asks.
        decision, reason = check_host("github.com", "network_write")
        assert decision == "ask"

    def test_empty_host_asks(self):
        decision, reason = check_host("")
        assert decision == "ask"
        assert "unknown host" in reason

    def test_parity_with_resolve_network_context(self):
        # check_host on the extracted host must match resolve_network_context.
        tokens = ["curl", "https://evil.com/data"]
        net = resolve_network_context(tokens)
        direct = check_host("evil.com")
        assert net == direct


# --- extract_host ---


class TestExtractHost:
    def test_curl_url(self):
        assert extract_host(["curl", "https://example.com/path"]) == "example.com"

    def test_curl_bare_host(self):
        assert extract_host(["curl", "example.com"]) == "example.com"

    def test_wget_url(self):
        assert extract_host(["wget", "http://files.example.org/file.tar.gz"]) == "files.example.org"

    def test_ssh_user_at_host(self):
        assert extract_host(["ssh", "user@myserver.com"]) == "myserver.com"

    def test_ssh_with_flags(self):
        assert extract_host(["ssh", "-i", "key.pem", "user@host.com"]) == "host.com"

    def test_scp_user_at_host_path(self):
        assert extract_host(["scp", "user@host.com:file.txt", "."]) == "host.com"

    def test_nc_host(self):
        assert extract_host(["nc", "example.com", "80"]) == "example.com"

    def test_telnet_host(self):
        assert extract_host(["telnet", "example.com"]) == "example.com"

    def test_nc_with_flags(self):
        assert extract_host(["nc", "-w", "5", "example.com", "80"]) == "example.com"

    def test_empty(self):
        assert extract_host([]) is None

    def test_curl_with_flags(self):
        assert extract_host(["curl", "-s", "-o", "/dev/null", "https://api.github.com"]) == "api.github.com"

    def test_curl_json_body_before_url(self):
        assert extract_host([
            "curl", "--json", '{"query":"query { viewer { login } }"}',
            "https://api.github.com/graphql",
        ]) == "api.github.com"

    def test_curl_data_body_before_url(self):
        assert extract_host([
            "curl", "-d", '{"jsonrpc":"2.0","method":"resources/read","id":1}',
            "https://mcp.example.com/rpc",
        ]) == "mcp.example.com"

    def test_curl_auth_header_cookie_and_proxy_values_are_not_hosts(self):
        assert extract_host(["curl", "-u", "user:pass", "https://api.example.com"]) == "api.example.com"
        assert extract_host([
            "curl", "-H", "Authorization: Bearer TOKEN", "https://api.example.com",
        ]) == "api.example.com"
        assert extract_host(["curl", "-b", "cookies.txt", "https://example.com"]) == "example.com"
        assert extract_host(["curl", "-c", "cookies.txt", "https://example.com"]) == "example.com"
        assert extract_host(["curl", "-x", "http://proxy:8080", "https://target.com"]) == "target.com"

    def test_curl_local_file_options_are_not_hosts(self):
        assert extract_host(["curl", "-K", "config.txt", "https://api.example.com"]) == "api.example.com"
        assert extract_host(["curl", "--config", "config.txt", "https://api.example.com"]) == "api.example.com"
        assert extract_host(["curl", "-E", "cert.pem", "https://api.example.com"]) == "api.example.com"
        assert extract_host(["curl", "-D", "headers.txt", "https://api.example.com"]) == "api.example.com"

    def test_wget_post_data_before_url(self):
        assert extract_host([
            "wget", "--post-data", '{"x":1}', "https://api.example.com/items",
        ]) == "api.example.com"

    def test_api_cli_form_field_is_not_host(self):
        assert extract_host(["glab", "api", "projects/1/wikis/attachments", "--form", "file=@image.png"]) is None

    def test_api_cli_hostname_flag(self):
        assert extract_host(["glab", "api", "projects/1", "--hostname", "gitlab.example.com"]) == "gitlab.example.com"
        assert extract_host(["gh", "api", "user", "--hostname=github.example.com"]) == "github.example.com"

    def test_api_cli_url_endpoint_host(self):
        assert extract_host(["glab", "api", "https://gitlab.example.com/api/v4/projects/1"]) == "gitlab.example.com"


# --- FD-086: SSH/SCP host extraction ---


class TestExtractHostSSH:
    """FD-086: SSH/SCP/SFTP host extraction — valued flags, IPv6, SCP paths."""

    # IPv6 bracketed addresses
    def test_ssh_ipv6_user_at(self):
        assert extract_host(["ssh", "user@[2001:db8::1]"]) == "2001:db8::1"

    def test_scp_ipv6_user_at_path(self):
        assert extract_host(["scp", "user@[2001:db8::1]:/remote/file", "."]) == "2001:db8::1"

    def test_scp_ipv6_no_user(self):
        assert extract_host(["scp", "[2001:db8::1]:/remote/file", "."]) == "2001:db8::1"

    # SCP local-path-first (should not extract the local path)
    def test_scp_local_path_first_user_at(self):
        assert extract_host(["scp", "/local/file.txt", "user@host.com:/remote/"]) == "host.com"

    def test_scp_local_path_first_colon(self):
        assert extract_host(["scp", "/local/file.txt", "host.com:/remote/"]) == "host.com"

    # Valued flags that were previously missing
    def test_ssh_S_flag(self):
        assert extract_host(["ssh", "-S", "/tmp/socket", "user@host.com"]) == "host.com"

    def test_ssh_D_flag(self):
        assert extract_host(["ssh", "-D", "9999", "user@host.com"]) == "host.com"

    # Bare host (regression guard)
    def test_ssh_bare_host(self):
        assert extract_host(["ssh", "host.com"]) == "host.com"

    # IPv6 localhost
    def test_ssh_ipv6_localhost(self):
        assert extract_host(["ssh", "user@[::1]"]) == "::1"

    # Multiple valued flags in sequence
    def test_ssh_multiple_valued_flags(self):
        assert extract_host(["ssh", "-L", "8080:localhost:80", "-i", "key.pem", "user@host.com"]) == "host.com"

    # ProxyJump (-J consumes jump host, extracts final)
    def test_ssh_proxy_jump(self):
        assert extract_host(["ssh", "-J", "jump.com", "user@final.com"]) == "final.com"

    # -l flag consumes username, bare host is positional
    def test_ssh_l_flag_bare_host(self):
        assert extract_host(["ssh", "-l", "user", "host.com"]) == "host.com"

    # SCP with -r boolean flag (not in valued flags)
    def test_scp_r_flag(self):
        assert extract_host(["scp", "-r", "/dir", "user@host.com:/dest/"]) == "host.com"

    # SCP with -o valued flag
    def test_scp_o_flag(self):
        assert extract_host(["scp", "-o", "StrictHostKeyChecking=no", "/local/file", "root@host.com:/remote/"]) == "host.com"

    # SFTP host extraction
    def test_sftp_user_at_host(self):
        assert extract_host(["sftp", "user@host.com"]) == "host.com"

    def test_sftp_host_colon_path(self):
        assert extract_host(["sftp", "host.com:/path"]) == "host.com"

    # rsync host extraction
    def test_rsync_remote_user_at(self):
        assert extract_host(["rsync", "-avz", "./local/", "user@host.com:/remote/"]) == "host.com"

    def test_rsync_remote_with_rsh_flag(self):
        assert extract_host(["rsync", "-e", "ssh", "file.txt", "user@host.com:/path"]) == "host.com"

    def test_rsync_remote_source(self):
        assert extract_host(["rsync", "user@host.com:/remote/", "./local/"]) == "host.com"

    def test_rsync_host_colon_path(self):
        assert extract_host(["rsync", "host.com:/remote/", "./local/"]) == "host.com"

    def test_rsync_daemon_module(self):
        assert extract_host(["rsync", "host.com::module/path", "./local/"]) == "host.com"

    # ssh-copy-id host extraction
    def test_ssh_copy_id_user_at_host(self):
        assert extract_host(["ssh-copy-id", "user@myserver.com"]) == "myserver.com"

    def test_ssh_copy_id_i_flag(self):
        assert extract_host(["ssh-copy-id", "-i", "~/.ssh/id_rsa.pub", "user@myserver.com"]) == "myserver.com"


# --- FD-022: Network write context ---


class TestNetworkWriteContext:
    """FD-022: network_write context resolution."""

    def test_localhost_ask(self):
        """network_write to localhost asks — exfiltration risk (FD-071)."""
        decision, _ = resolve_network_context(
            ["curl", "-d", "{}", "http://localhost:3000"], "network_write"
        )
        assert decision == "ask"

    def test_known_host_ask(self):
        decision, _ = resolve_network_context(
            ["curl", "-X", "POST", "https://github.com"], "network_write"
        )
        assert decision == "ask"

    def test_unknown_host_ask(self):
        decision, _ = resolve_network_context(
            ["curl", "-d", "x", "https://evil.com"], "network_write"
        )
        assert decision == "ask"

    def test_json_body_before_url_reports_url_host(self):
        decision, reason = resolve_network_context(
            [
                "curl", "--json", '{"query":"query { viewer { login } }"}',
                "https://api.github.com/graphql",
            ],
            "network_write",
        )
        assert decision == "ask"
        assert "api.github.com" in reason
        assert "query" not in reason

    def test_backward_compat_default_param(self):
        """Default action_type preserves old behavior: known hosts → allow."""
        decision, _ = resolve_network_context(["curl", "https://github.com"])
        assert decision == "allow"


class TestServiceReadContext:
    def test_service_read_without_remote_op_allows(self):
        # Defensive branch: local daemon inspection now classifies as
        # service_inspect (nah-1004), so service_read should only ever see
        # remote ops. If a token stream with no visible remote op still reaches
        # here, fall through to allow.
        decision, reason = resolve_context("service_read", tokens=["systemctl", "status", "nginx"])

        assert decision == "allow"
        assert "service_read" in reason

    def test_local_inspection_is_service_inspect_allow(self):
        # The real path for local daemon inspection: service_inspect is an
        # allow-policy type, resolved by policy lookup (not a context resolver).
        from nah import taxonomy

        assert taxonomy.classify_tokens(
            ["systemctl", "status", "nginx"], None, taxonomy.get_builtin_table(), None
        ) == "service_inspect"
        assert taxonomy.get_policy("service_inspect") == "allow"

    def test_remote_service_read_known_host_allows(self):
        decision, reason = resolve_context("service_read", tokens=["curl", "https://github.com/repos/openai/codex"])

        assert decision == "allow"
        assert "github.com" in reason

    def test_remote_service_read_unknown_host_asks(self):
        decision, reason = resolve_context("service_read", tokens=["curl", "https://api.example.com/v1/items"])

        assert decision == "ask"
        assert "api.example.com" in reason

    def test_grpc_service_read_known_host_allows(self):
        decision, reason = resolve_context(
            "service_read",
            tokens=["grpcurl", "github.com:443", "pkg.User/GetUser"],
        )

        assert decision == "allow"
        assert "github.com" in reason

    def test_grpc_service_read_unknown_host_asks(self):
        decision, reason = resolve_context(
            "service_read",
            tokens=["grpcurl", "api.example.com:443", "pkg.User/GetUser"],
        )

        assert decision == "ask"
        assert "api.example.com" in reason

    def test_websocket_connection_known_host_allows(self):
        decision, reason = resolve_context(
            "network_outbound",
            tokens=["wscat", "-c", "ws://github.com/socket"],
        )

        assert decision == "allow"
        assert "github.com" in reason

    def test_websocket_connection_unknown_host_asks(self):
        decision, reason = resolve_context(
            "network_outbound",
            tokens=["wscat", "-c", "ws://api.example.com/socket"],
        )

        assert decision == "ask"
        assert "api.example.com" in reason

    def test_websocket_service_read_known_host_allows(self):
        decision, reason = resolve_context(
            "service_read",
            tokens=["websocat", "ws://github.com/socket", '{"type":"getUser"}'],
        )

        assert decision == "allow"
        assert "github.com" in reason

    def test_websocket_service_read_unknown_host_asks(self):
        decision, reason = resolve_context(
            "service_read",
            tokens=["websocat", "ws://api.example.com/socket", '{"type":"getUser"}'],
        )

        assert decision == "ask"
        assert "api.example.com" in reason


# --- FD-022: httpie host extraction ---


class TestExtractHostHttpie:
    """FD-022: httpie host extraction."""

    def test_http_bare_host(self):
        assert extract_host(["http", "example.com"]) == "example.com"

    def test_http_method_host(self):
        assert extract_host(["http", "POST", "example.com"]) == "example.com"

    def test_xh_url(self):
        assert extract_host(["xh", "POST", "https://api.example.com/path"]) == "api.example.com"


# --- FD-055: shared context dispatcher ---


class TestResolveContext:
    """FD-055: resolve_context() dispatches by action type."""

    def teardown_method(self):
        config._cached_config = None

    def test_db_exec_with_tool_input(self):
        config._cached_config = NahConfig(db_targets=[{"database": "SANDBOX"}])
        decision, reason = resolve_context(
            "db_exec", tool_input={"database": "SANDBOX", "query": "INSERT ..."}
        )
        assert decision == "allow"
        assert "allowed target" in reason

    def test_db_exec_with_tokens(self):
        config._cached_config = NahConfig(db_targets=[{"database": "SANDBOX"}])
        decision, reason = resolve_context(
            "db_exec", tokens=["psql", "-d", "sandbox"]
        )
        assert decision == "allow"

    def test_db_exec_no_input_ask(self):
        config._cached_config = NahConfig(db_targets=[{"database": "SANDBOX"}])
        decision, reason = resolve_context("db_exec")
        assert decision == "ask"
        assert "unknown database target" in reason

    def test_network_outbound_with_tokens(self):
        decision, reason = resolve_context(
            "network_outbound", tokens=["curl", "https://github.com/repo"]
        )
        assert decision == "allow"

    def test_network_outbound_no_tokens_ask(self):
        decision, reason = resolve_context("network_outbound")
        assert decision == "ask"
        assert "unknown host" in reason

    def test_network_write_no_tokens_ask(self):
        decision, reason = resolve_context("network_write")
        assert decision == "ask"
        assert "unknown host" in reason

    def test_filesystem_write_with_target(self, project_root):
        target = os.path.join(project_root, "output.txt")
        decision, reason = resolve_context("filesystem_write", target_path=target)
        assert decision == "allow"

    def test_filesystem_write_no_target_ask(self):
        decision, reason = resolve_context("filesystem_write")
        assert decision == "ask"
        assert "no target path" in reason

    def test_filesystem_delete_no_target_ask(self):
        decision, reason = resolve_context("filesystem_delete")
        assert decision == "ask"
        assert "no target path" in reason

    def test_filesystem_read_no_target_allow(self):
        decision, reason = resolve_context("filesystem_read")
        assert decision == "allow"

    def test_container_lifecycle_trusted_container_allows(self):
        config._cached_config = NahConfig(trusted_containers=["container:my-trusted-api"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "my-trusted-api"],
        )
        assert decision == "allow"
        assert "trusted_containers" in reason

    def test_container_lifecycle_untrusted_container_asks(self):
        config._cached_config = NahConfig(trusted_containers=["container:my-trusted-api"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "some-prod-box"],
        )
        assert decision == "ask"
        assert "untrusted" in reason

    def test_container_lifecycle_multi_container_requires_all_trusted(self):
        config._cached_config = NahConfig(trusted_containers=["container:a"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "a", "b"],
        )
        assert decision == "ask"
        assert "untrusted" in reason

    def test_container_lifecycle_flag_safety_asks(self):
        config._cached_config = NahConfig(trusted_containers=["container:my-trusted-api"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "-t", "5", "my-trusted-api"],
        )
        assert decision == "ask"
        assert "options" in reason

    def test_container_lifecycle_flag_value_misparse_guard(self):
        config._cached_config = NahConfig(trusted_containers=["container:my-trusted-api"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "--time", "my-trusted-api", "real-untrusted"],
        )
        assert decision == "ask"
        assert "options" in reason

    def test_container_lifecycle_dynamic_identity_asks(self):
        config._cached_config = NahConfig(trusted_containers=["container:my-trusted-api"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "$CONTAINER"],
        )
        assert decision == "ask"
        assert "dynamic" in reason

    def test_container_lifecycle_empty_trusted_list_asks(self):
        config._cached_config = NahConfig(trusted_containers=[])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "stop", "my-trusted-api"],
        )
        assert decision == "ask"
        assert "untrusted" in reason

    def test_container_lifecycle_compose_asks(self):
        config._cached_config = NahConfig(trusted_containers=["compose:api"])
        decision, reason = resolve_context(
            "container_lifecycle",
            tokens=["docker", "compose", "up"],
        )
        assert decision == "ask"
        assert "compose" in reason

    def test_container_lifecycle_none_tokens_asks(self):
        config._cached_config = NahConfig(trusted_containers=["container:api"])
        decision, reason = resolve_container_lifecycle_context(None)
        assert decision == "ask"
        assert "no tokens" in reason

    def test_browser_navigate_stub_reason(self):
        decision, reason = resolve_context(
            "browser_navigate",
            tool_input={"url": "https://example.com"},
        )
        assert decision == "ask"
        assert reason == "browser_navigate: url extraction pending"

    def test_browser_exec_stub_reason(self):
        decision, reason = resolve_context(
            "browser_exec",
            tool_input={"expression": "document.cookie"},
        )
        assert decision == "ask"
        assert reason == "browser_exec: code extraction pending"

    def test_browser_file_stub_reason(self):
        decision, reason = resolve_context(
            "browser_file",
            tool_input={"path": "/tmp/state.json"},
        )
        assert decision == "ask"
        assert reason == "browser_file: path extraction pending"

    def test_unknown_action_type_ask(self):
        decision, reason = resolve_context("unknown")
        assert decision == "ask"
        assert "no context resolver" in reason

    def test_future_action_type_ask(self):
        decision, reason = resolve_context("some_future_type")
        assert decision == "ask"
        assert "no context resolver" in reason


# --- FD-051: Configurable known hosts ---


class TestKnownHostsConfigurable:
    """FD-051: known_registries add/remove/profile-none."""

    def _setup_merge(self, cfg):
        """Reset and allow merge to run with given config."""
        reset_known_hosts()
        nah.context._known_hosts_merged = False
        config._cached_config = cfg

    def teardown_method(self):
        config._cached_config = None
        reset_known_hosts()
        nah.context._known_hosts_merged = True

    def test_add_host_list_form(self):
        self._setup_merge(NahConfig(known_registries=["custom.corp.com"]))
        decision, reason = resolve_network_context(["curl", "https://custom.corp.com/pkg"])
        assert decision == "allow"
        assert "known host" in reason

    def test_add_host_dict_form(self):
        self._setup_merge(NahConfig(known_registries={"add": ["custom.corp.com"]}))
        decision, reason = resolve_network_context(["curl", "https://custom.corp.com/pkg"])
        assert decision == "allow"

    def test_remove_host(self):
        self._setup_merge(NahConfig(known_registries={"remove": ["github.com"]}))
        decision, reason = resolve_network_context(["curl", "https://github.com/repo"])
        assert decision == "ask"
        assert "unknown host" in reason

    def test_add_and_remove_same_host(self):
        """Remove wins over add."""
        self._setup_merge(NahConfig(known_registries={"add": ["x.com"], "remove": ["x.com"]}))
        decision, _ = resolve_network_context(["curl", "https://x.com"])
        assert decision == "ask"

    def test_legacy_profile_none_keeps_default_hosts(self):
        self._setup_merge(NahConfig(profile="none"))
        decision, _ = resolve_network_context(["curl", "https://github.com/repo"])
        assert decision == "allow"

    def test_legacy_profile_none_with_add_keeps_defaults(self):
        """Legacy profile values are ignored; defaults and user entries both apply."""
        self._setup_merge(NahConfig(profile="none", known_registries=["custom.io"]))
        decision, _ = resolve_network_context(["curl", "https://custom.io/pkg"])
        assert decision == "allow"
        decision2, _ = resolve_network_context(["curl", "https://pypi.org/simple/"])
        assert decision2 == "allow"

    def test_list_backward_compat(self):
        """Plain list form works same as before (add-only)."""
        self._setup_merge(NahConfig(known_registries=["internal.corp.com"]))
        # Default hosts still present
        decision, _ = resolve_network_context(["curl", "https://github.com/repo"])
        assert decision == "allow"
        # New host added
        decision2, _ = resolve_network_context(["curl", "https://internal.corp.com/pkg"])
        assert decision2 == "allow"


# --- FD-054: Trusted path in filesystem context ---


class TestTrustedPathContext:
    """FD-054: trusted_paths in resolve_filesystem_context."""

    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def test_trusted_path_allow(self, project_root):
        """Trusted path outside project → allow."""
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        decision, reason = resolve_filesystem_context("/tmp/file.txt")
        assert decision == "allow"
        assert "trusted path" in reason

    def test_untrusted_path_ask(self, project_root):
        """Non-trusted path outside project → ask."""
        decision, reason = resolve_filesystem_context("/tmp/file.txt")
        assert decision == "ask"
        assert "outside project" in reason

    def test_legacy_profile_none_does_not_disable_boundary(self, project_root):
        """Legacy profile values are ignored; project boundary checks still run."""
        config._cached_config = NahConfig(profile="none")
        decision, reason = resolve_filesystem_context("/opt/outside-project-file.txt")
        assert decision == "ask"
        assert "outside project" in reason

    def test_trusted_nested(self, project_root):
        """Nested path inside trusted directory → allow."""
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        decision, reason = resolve_filesystem_context("/tmp/deep/nested.txt")
        assert decision == "allow"
        assert "trusted path" in reason

    def test_trusted_exact_match(self, project_root):
        """Trusted directory itself → allow."""
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        decision, reason = resolve_filesystem_context("/tmp")
        assert decision == "allow"
        assert "trusted path" in reason

    def test_trusted_path_no_git_root(self):
        """Trusted path should allow even with no project root (FD-107)."""
        paths.set_project_root(None)
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        decision, reason = resolve_filesystem_context("/tmp/file.txt")
        assert decision == "allow"
        assert "trusted path" in reason
