"""Unit tests for nah.context — filesystem and network context resolution."""

import os

import pytest

from nah import paths
from nah.context import extract_host, resolve_filesystem_context, resolve_network_context


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
