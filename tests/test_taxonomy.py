"""Unit tests for nah.taxonomy — classification table, policies, helpers."""

import pytest

from nah.taxonomy import (
    classify_tokens,
    get_policy,
    is_decode_stage,
    is_exec_sink,
    is_shell_wrapper,
)


# --- classify_tokens ---


class TestClassifyTokens:
    """Action type classification via prefix matching."""

    # filesystem_read
    @pytest.mark.parametrize("cmd", ["cat", "head", "tail", "less", "more", "file",
                                      "wc", "stat", "du", "df", "ls", "tree", "bat",
                                      "echo", "printf", "diff", "grep", "rg", "awk", "sed"])
    def test_filesystem_read(self, cmd):
        assert classify_tokens([cmd, "file.txt"]) == "filesystem_read"

    # filesystem_write
    @pytest.mark.parametrize("cmd", ["tee", "cp", "mv", "mkdir", "touch", "chmod",
                                      "chown", "ln", "install"])
    def test_filesystem_write(self, cmd):
        assert classify_tokens([cmd, "target"]) == "filesystem_write"

    # filesystem_delete
    @pytest.mark.parametrize("cmd", ["rm", "rmdir", "unlink", "shred", "truncate"])
    def test_filesystem_delete(self, cmd):
        assert classify_tokens([cmd, "file"]) == "filesystem_delete"

    # git_safe
    @pytest.mark.parametrize("tokens", [
        ["git", "status"],
        ["git", "log", "--oneline"],
        ["git", "diff"],
        ["git", "show", "HEAD"],
        ["git", "branch"],
        ["git", "tag"],
        ["git", "remote", "-v"],
        ["git", "stash", "list"],
    ])
    def test_git_safe(self, tokens):
        assert classify_tokens(tokens) == "git_safe"

    # git_write
    @pytest.mark.parametrize("tokens", [
        ["git", "add", "."],
        ["git", "commit", "-m", "msg"],
        ["git", "push"],
        ["git", "pull"],
        ["git", "fetch"],
        ["git", "merge", "main"],
        ["git", "stash"],
        ["git", "checkout", "branch"],
        ["git", "switch", "branch"],
    ])
    def test_git_write(self, tokens):
        assert classify_tokens(tokens) == "git_write"

    # git_history_rewrite
    @pytest.mark.parametrize("tokens", [
        ["git", "reset", "--hard"],
        ["git", "push", "--force"],
        ["git", "push", "-f"],
        ["git", "rebase", "main"],
        ["git", "clean", "-fd"],
        ["git", "stash", "drop"],
        ["git", "stash", "clear"],
        ["git", "branch", "-D", "old"],
    ])
    def test_git_history_rewrite(self, tokens):
        assert classify_tokens(tokens) == "git_history_rewrite"

    # Prefix priority: longer prefix wins
    def test_git_push_force_beats_git_push(self):
        assert classify_tokens(["git", "push", "--force"]) == "git_history_rewrite"
        assert classify_tokens(["git", "push"]) == "git_write"

    def test_git_branch_D_beats_git_branch(self):
        assert classify_tokens(["git", "branch", "-D", "x"]) == "git_history_rewrite"
        assert classify_tokens(["git", "branch"]) == "git_safe"

    def test_git_stash_drop_beats_git_stash(self):
        assert classify_tokens(["git", "stash", "drop"]) == "git_history_rewrite"
        assert classify_tokens(["git", "stash"]) == "git_write"

    # network_outbound
    @pytest.mark.parametrize("cmd", ["curl", "wget", "ssh", "scp", "rsync",
                                      "nc", "ncat", "telnet", "ftp", "sftp"])
    def test_network_outbound(self, cmd):
        assert classify_tokens([cmd, "target"]) == "network_outbound"

    # package_install
    @pytest.mark.parametrize("tokens", [
        ["npm", "install"],
        ["pip", "install", "flask"],
        ["pip3", "install", "flask"],
        ["cargo", "build"],
        ["brew", "install", "jq"],
        ["apt", "install", "curl"],
        ["gem", "install", "rails"],
        ["go", "get", "pkg"],
        ["pnpm", "install"],
        ["yarn", "add", "react"],
        ["bun", "install"],
    ])
    def test_package_install(self, tokens):
        assert classify_tokens(tokens) == "package_install"

    # package_run
    @pytest.mark.parametrize("tokens", [
        ["npx", "create-react-app"],
        ["pytest", "-v"],
        ["make", "build"],
        ["npm", "test"],
        ["npm", "run", "dev"],
        ["cargo", "test"],
        ["cargo", "run"],
        ["go", "test", "./..."],
        ["go", "run", "main.go"],
        ["python", "-m", "pytest"],
        ["pnpm", "run", "dev"],
        ["yarn", "run", "build"],
        ["bun", "run", "dev"],
        ["just", "build"],
        ["task", "lint"],
    ])
    def test_package_run(self, tokens):
        assert classify_tokens(tokens) == "package_run"

    # lang_exec
    @pytest.mark.parametrize("tokens", [
        ["python", "-c", "print(1)"],
        ["python3", "-c", "print(1)"],
        ["node", "-e", "console.log(1)"],
        ["ruby", "-e", "puts 1"],
        ["perl", "-e", "print 1"],
        ["php", "-r", "echo 1;"],
    ])
    def test_lang_exec(self, tokens):
        assert classify_tokens(tokens) == "lang_exec"

    # find — special case
    def test_find_read(self):
        assert classify_tokens(["find", ".", "-name", "*.py"]) == "filesystem_read"

    def test_find_delete(self):
        assert classify_tokens(["find", ".", "-delete"]) == "filesystem_delete"

    def test_find_exec(self):
        assert classify_tokens(["find", ".", "-exec", "rm", "{}", ";"]) == "filesystem_delete"

    def test_find_execdir(self):
        assert classify_tokens(["find", ".", "-execdir", "cmd", "{}", ";"]) == "filesystem_delete"

    # git_discard
    @pytest.mark.parametrize("tokens", [
        ["git", "checkout", "."],
        ["git", "checkout", "--", "file.txt"],
        ["git", "checkout", "HEAD", "file.txt"],
        ["git", "checkout", "-f"],
        ["git", "checkout", "--force"],
        ["git", "checkout", "--ours", "file.txt"],
        ["git", "checkout", "--theirs", "file.txt"],
        ["git", "checkout", "-B", "branch"],
        ["git", "switch", "-f", "branch"],
        ["git", "switch", "--force", "branch"],
        ["git", "switch", "--discard-changes", "branch"],
        ["git", "restore", "file.txt"],
        ["git", "rm", "file.txt"],
    ])
    def test_git_discard(self, tokens):
        assert classify_tokens(tokens) == "git_discard"

    # git_discard vs git_write priority
    def test_git_checkout_dot_discard_not_write(self):
        assert classify_tokens(["git", "checkout", "."]) == "git_discard"
        assert classify_tokens(["git", "checkout", "branch"]) == "git_write"

    def test_git_switch_force_discard_not_write(self):
        assert classify_tokens(["git", "switch", "--force", "b"]) == "git_discard"
        assert classify_tokens(["git", "switch", "branch"]) == "git_write"

    # process_signal
    @pytest.mark.parametrize("tokens", [
        ["kill", "-9", "1234"],
        ["kill", "-KILL", "1234"],
        ["kill", "-SIGKILL", "1234"],
        ["pkill", "nginx"],
        ["killall", "node"],
    ])
    def test_process_signal(self, tokens):
        assert classify_tokens(tokens) == "process_signal"

    # container_destructive
    @pytest.mark.parametrize("tokens", [
        ["docker", "rm", "abc"],
        ["docker", "rmi", "img"],
        ["docker", "system", "prune"],
        ["docker", "volume", "rm", "vol"],
        ["docker", "container", "rm", "abc"],
        ["docker", "image", "rm", "img"],
        ["docker", "network", "rm", "net"],
    ])
    def test_container_destructive(self, tokens):
        assert classify_tokens(tokens) == "container_destructive"

    # package_uninstall
    @pytest.mark.parametrize("tokens", [
        ["pip", "uninstall", "flask"],
        ["pip3", "uninstall", "flask"],
        ["npm", "uninstall", "react"],
        ["brew", "uninstall", "jq"],
        ["brew", "remove", "jq"],
        ["cargo", "uninstall", "ripgrep"],
        ["gem", "uninstall", "rails"],
        ["pnpm", "remove", "react"],
        ["yarn", "remove", "react"],
        ["bun", "remove", "react"],
        ["apt", "remove", "curl"],
        ["apt", "purge", "curl"],
    ])
    def test_package_uninstall(self, tokens):
        assert classify_tokens(tokens) == "package_uninstall"

    # sql_write
    @pytest.mark.parametrize("tokens", [
        ["snow", "sql", "-q", "SELECT 1"],
        ["snowsql", "-q", "SELECT 1"],
        ["psql", "-c", "SELECT 1"],
        ["psql", "-f", "script.sql"],
        ["mysql", "-e", "SHOW TABLES"],
        ["sqlite3", "db.sqlite", "SELECT 1"],
        ["bq", "query", "--use_legacy_sql=false", "SELECT 1"],
    ])
    def test_sql_write(self, tokens):
        assert classify_tokens(tokens) == "sql_write"

    # git push origin --force → git_history_rewrite (not git_write)
    def test_git_push_origin_force(self):
        assert classify_tokens(["git", "push", "origin", "--force"]) == "git_history_rewrite"
        assert classify_tokens(["git", "push", "origin", "-f"]) == "git_history_rewrite"
        assert classify_tokens(["git", "push", "origin", "main", "--force"]) == "git_history_rewrite"
        assert classify_tokens(["git", "push", "origin", "main", "-f"]) == "git_history_rewrite"

    # git flag stripping
    def test_git_C_flag_stripped(self):
        assert classify_tokens(["git", "-C", "/dir", "rm", "file"]) == "git_discard"

    def test_git_no_pager_stripped(self):
        assert classify_tokens(["git", "--no-pager", "log"]) == "git_safe"

    def test_git_git_dir_stripped(self):
        assert classify_tokens(["git", "--git-dir", "/x", "push", "--force"]) == "git_history_rewrite"

    def test_git_multiple_flags_stripped(self):
        assert classify_tokens(["git", "-C", "/dir", "--no-pager", "status"]) == "git_safe"

    # Edge cases
    def test_empty_tokens(self):
        assert classify_tokens([]) == "unknown"

    def test_unknown_command(self):
        assert classify_tokens(["foobar", "--flag"]) == "unknown"


# --- get_policy ---


class TestGetPolicy:
    """Policy defaults per action type."""

    @pytest.mark.parametrize("action_type, expected", [
        ("filesystem_read", "allow"),
        ("filesystem_write", "context"),
        ("filesystem_delete", "context"),
        ("git_safe", "allow"),
        ("git_write", "allow"),
        ("git_discard", "ask"),
        ("git_history_rewrite", "ask"),
        ("network_outbound", "context"),
        ("package_install", "allow"),
        ("package_run", "allow"),
        ("package_uninstall", "ask"),
        ("lang_exec", "ask"),
        ("process_signal", "ask"),
        ("container_destructive", "ask"),
        ("sql_write", "ask"),
        ("obfuscated", "block"),
        ("unknown", "ask"),
    ])
    def test_all_defaults(self, action_type, expected):
        assert get_policy(action_type) == expected

    def test_unknown_type_falls_back_to_ask(self):
        assert get_policy("totally_made_up") == "ask"


# --- is_shell_wrapper ---


class TestIsShellWrapper:
    """Shell wrapper detection for unwrapping."""

    def test_bash_c(self):
        is_w, inner = is_shell_wrapper(["bash", "-c", "rm -rf /"])
        assert is_w is True
        assert inner == "rm -rf /"

    def test_sh_c(self):
        is_w, inner = is_shell_wrapper(["sh", "-c", "ls"])
        assert is_w is True
        assert inner == "ls"

    def test_dash_c(self):
        is_w, inner = is_shell_wrapper(["dash", "-c", "echo hi"])
        assert is_w is True

    def test_zsh_c(self):
        is_w, inner = is_shell_wrapper(["zsh", "-c", "echo hi"])
        assert is_w is True

    def test_eval(self):
        is_w, inner = is_shell_wrapper(["eval", "echo", "hello"])
        assert is_w is True
        assert inner == "echo hello"

    def test_source_not_wrapper(self):
        is_w, _ = is_shell_wrapper(["source", "script.sh"])
        assert is_w is False

    def test_dot_not_wrapper(self):
        is_w, _ = is_shell_wrapper([".", "script.sh"])
        assert is_w is False

    def test_bash_without_c_not_wrapper(self):
        is_w, _ = is_shell_wrapper(["bash", "script.sh"])
        assert is_w is False

    def test_empty(self):
        is_w, _ = is_shell_wrapper([])
        assert is_w is False

    def test_bash_c_missing_arg(self):
        is_w, _ = is_shell_wrapper(["bash", "-c"])
        assert is_w is False


# --- is_exec_sink ---


class TestIsExecSink:
    """Exec sink detection for pipe composition."""

    @pytest.mark.parametrize("token", ["bash", "sh", "dash", "zsh", "eval",
                                        "python", "python3", "node", "ruby", "perl", "php"])
    def test_sinks(self, token):
        assert is_exec_sink(token) is True

    @pytest.mark.parametrize("token", ["cat", "grep", "ls", "curl", "rm", ""])
    def test_non_sinks(self, token):
        assert is_exec_sink(token) is False


# --- is_decode_stage ---


class TestIsDecodeStage:
    """Decode command detection for pipe composition."""

    def test_base64_d(self):
        assert is_decode_stage(["base64", "-d"]) is True

    def test_base64_decode(self):
        assert is_decode_stage(["base64", "--decode"]) is True

    def test_xxd_r(self):
        assert is_decode_stage(["xxd", "-r"]) is True

    def test_base64_encode_not_decode(self):
        assert is_decode_stage(["base64"]) is False

    def test_non_decode(self):
        assert is_decode_stage(["cat", "file"]) is False

    def test_empty(self):
        assert is_decode_stage([]) is False
