"""Unit tests for nah.taxonomy — classification table, policies, helpers."""

import pytest

from nah.taxonomy import (
    build_user_table,
    classify_tokens,
    get_builtin_table,
    get_policy,
    is_decode_stage,
    is_exec_sink,
    is_shell_wrapper,
)

_FULL = get_builtin_table("full")


def _ct(tokens: list[str]) -> str:
    """Classify tokens against the full built-in table."""
    return classify_tokens(tokens, builtin_table=_FULL)


# --- classify_tokens ---


class TestClassifyTokens:
    """Action type classification via prefix matching."""

    # filesystem_read
    @pytest.mark.parametrize("cmd", ["cat", "head", "tail", "less", "more", "file",
                                      "wc", "stat", "du", "df", "ls", "tree", "bat",
                                      "echo", "printf", "diff", "grep", "rg", "awk", "sed"])
    def test_filesystem_read(self, cmd):
        assert _ct([cmd, "file.txt"]) == "filesystem_read"

    # filesystem_write
    @pytest.mark.parametrize("cmd", ["tee", "cp", "mv", "mkdir", "touch", "chmod",
                                      "chown", "ln", "install"])
    def test_filesystem_write(self, cmd):
        assert _ct([cmd, "target"]) == "filesystem_write"

    # filesystem_delete
    @pytest.mark.parametrize("cmd", ["rm", "rmdir", "unlink", "shred", "truncate"])
    def test_filesystem_delete(self, cmd):
        assert _ct([cmd, "file"]) == "filesystem_delete"

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
        assert _ct(tokens) == "git_safe"

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
        assert _ct(tokens) == "git_write"

    # git_history_rewrite
    @pytest.mark.parametrize("tokens", [
        ["git", "push", "--force"],
        ["git", "push", "-f"],
        ["git", "rebase", "main"],
        ["git", "clean", "-fd"],
        ["git", "stash", "drop"],
        ["git", "stash", "clear"],
        ["git", "branch", "-D", "old"],
    ])
    def test_git_history_rewrite(self, tokens):
        assert _ct(tokens) == "git_history_rewrite"

    # Prefix priority: longer prefix wins
    def test_git_push_force_beats_git_push(self):
        assert _ct(["git", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "push"]) == "git_write"

    def test_git_branch_D_beats_git_branch(self):
        assert _ct(["git", "branch", "-D", "x"]) == "git_history_rewrite"
        assert _ct(["git", "branch"]) == "git_safe"

    def test_git_stash_drop_beats_git_stash(self):
        assert _ct(["git", "stash", "drop"]) == "git_history_rewrite"
        assert _ct(["git", "stash"]) == "git_write"

    # network_outbound
    @pytest.mark.parametrize("cmd", ["curl", "wget", "ssh", "scp", "rsync",
                                      "nc", "ncat", "telnet", "ftp", "sftp"])
    def test_network_outbound(self, cmd):
        assert _ct([cmd, "target"]) == "network_outbound"

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
        assert _ct(tokens) == "package_install"

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
        assert _ct(tokens) == "package_run"

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
        assert _ct(tokens) == "lang_exec"

    # find — special case
    def test_find_read(self):
        assert _ct(["find", ".", "-name", "*.py"]) == "filesystem_read"

    def test_find_delete(self):
        assert _ct(["find", ".", "-delete"]) == "filesystem_delete"

    def test_find_exec(self):
        assert _ct(["find", ".", "-exec", "rm", "{}", ";"]) == "filesystem_delete"

    def test_find_execdir(self):
        assert _ct(["find", ".", "-execdir", "cmd", "{}", ";"]) == "filesystem_delete"

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
        assert _ct(tokens) == "git_discard"

    # git_discard vs git_write priority
    def test_git_checkout_dot_discard_not_write(self):
        assert _ct(["git", "checkout", "."]) == "git_discard"
        assert _ct(["git", "checkout", "branch"]) == "git_write"

    def test_git_switch_force_discard_not_write(self):
        assert _ct(["git", "switch", "--force", "b"]) == "git_discard"
        assert _ct(["git", "switch", "branch"]) == "git_write"

    # process_signal
    @pytest.mark.parametrize("tokens", [
        ["kill", "-9", "1234"],
        ["kill", "-KILL", "1234"],
        ["kill", "-SIGKILL", "1234"],
        ["pkill", "nginx"],
        ["killall", "node"],
    ])
    def test_process_signal(self, tokens):
        assert _ct(tokens) == "process_signal"

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
        assert _ct(tokens) == "container_destructive"

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
        assert _ct(tokens) == "package_uninstall"

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
        assert _ct(tokens) == "sql_write"

    # git push origin --force → git_history_rewrite (not git_write)
    def test_git_push_origin_force(self):
        assert _ct(["git", "push", "origin", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "push", "origin", "-f"]) == "git_history_rewrite"
        assert _ct(["git", "push", "origin", "main", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "push", "origin", "main", "-f"]) == "git_history_rewrite"

    # git flag stripping
    def test_git_C_flag_stripped(self):
        assert _ct(["git", "-C", "/dir", "rm", "file"]) == "git_discard"

    def test_git_no_pager_stripped(self):
        assert _ct(["git", "--no-pager", "log"]) == "git_safe"

    def test_git_git_dir_stripped(self):
        assert _ct(["git", "--git-dir", "/x", "push", "--force"]) == "git_history_rewrite"

    def test_git_multiple_flags_stripped(self):
        assert _ct(["git", "-C", "/dir", "--no-pager", "status"]) == "git_safe"

    # git reset --hard → git_discard (DD#3)
    def test_git_reset_hard_is_discard(self):
        assert _ct(["git", "reset", "--hard"]) == "git_discard"

    # Edge cases
    def test_empty_tokens(self):
        assert _ct([]) == "unknown"

    def test_unknown_command(self):
        assert _ct(["foobar", "--flag"]) == "unknown"


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


# --- _classify_git (FD-017) ---


class TestClassifyGit:
    """Flag-dependent git classification via _classify_git()."""

    # --- tag ---
    def test_tag_bare_safe(self):
        assert _ct(["git", "tag"]) == "git_safe"

    def test_tag_with_args_write(self):
        assert _ct(["git", "tag", "v1.0"]) == "git_write"

    def test_tag_annotated_write(self):
        assert _ct(["git", "tag", "-a", "v1.0", "-m", "release"]) == "git_write"

    # --- branch ---
    def test_branch_bare_safe(self):
        assert _ct(["git", "branch"]) == "git_safe"

    def test_branch_list_a_safe(self):
        assert _ct(["git", "branch", "-a"]) == "git_safe"

    def test_branch_list_r_safe(self):
        assert _ct(["git", "branch", "-r"]) == "git_safe"

    def test_branch_list_flag_safe(self):
        assert _ct(["git", "branch", "--list"]) == "git_safe"

    def test_branch_v_safe(self):
        assert _ct(["git", "branch", "-v"]) == "git_safe"

    def test_branch_vv_safe(self):
        assert _ct(["git", "branch", "-vv"]) == "git_safe"

    def test_branch_create_write(self):
        assert _ct(["git", "branch", "newfeature"]) == "git_write"

    def test_branch_d_discard(self):
        assert _ct(["git", "branch", "-d", "old"]) == "git_discard"

    def test_branch_D_history_rewrite(self):
        assert _ct(["git", "branch", "-D", "old"]) == "git_history_rewrite"

    # --- config ---
    def test_config_get_safe(self):
        assert _ct(["git", "config", "--get", "user.name"]) == "git_safe"

    def test_config_list_safe(self):
        assert _ct(["git", "config", "--list"]) == "git_safe"

    def test_config_get_all_safe(self):
        assert _ct(["git", "config", "--get-all", "remote.origin.url"]) == "git_safe"

    def test_config_get_regexp_safe(self):
        assert _ct(["git", "config", "--get-regexp", "user"]) == "git_safe"

    def test_config_read_key_safe(self):
        assert _ct(["git", "config", "user.name"]) == "git_safe"

    def test_config_set_write(self):
        assert _ct(["git", "config", "user.name", "Alice"]) == "git_write"

    def test_config_unset_write(self):
        assert _ct(["git", "config", "--unset", "user.name"]) == "git_write"

    def test_config_unset_all_write(self):
        assert _ct(["git", "config", "--unset-all", "user.name"]) == "git_write"

    def test_config_replace_all_write(self):
        assert _ct(["git", "config", "--replace-all", "k", "v"]) == "git_write"

    # --- reset ---
    def test_reset_hard_discard(self):
        assert _ct(["git", "reset", "--hard"]) == "git_discard"

    def test_reset_hard_head_discard(self):
        assert _ct(["git", "reset", "--hard", "HEAD~1"]) == "git_discard"

    def test_reset_soft_write(self):
        assert _ct(["git", "reset", "--soft", "HEAD~1"]) == "git_write"

    def test_reset_mixed_write(self):
        assert _ct(["git", "reset", "HEAD~1"]) == "git_write"

    def test_reset_bare_write(self):
        assert _ct(["git", "reset"]) == "git_write"

    # --- push ---
    def test_push_bare_write(self):
        assert _ct(["git", "push"]) == "git_write"

    def test_push_origin_main_write(self):
        assert _ct(["git", "push", "origin", "main"]) == "git_write"

    def test_push_force_history(self):
        assert _ct(["git", "push", "--force"]) == "git_history_rewrite"

    def test_push_f_history(self):
        assert _ct(["git", "push", "-f"]) == "git_history_rewrite"

    def test_push_force_with_lease_history(self):
        assert _ct(["git", "push", "--force-with-lease"]) == "git_history_rewrite"

    def test_push_force_if_includes_history(self):
        assert _ct(["git", "push", "--force-if-includes"]) == "git_history_rewrite"

    def test_push_plus_refspec_history(self):
        assert _ct(["git", "push", "origin", "+main"]) == "git_history_rewrite"

    def test_push_origin_force_history(self):
        assert _ct(["git", "push", "origin", "--force"]) == "git_history_rewrite"

    def test_push_origin_main_force_history(self):
        assert _ct(["git", "push", "origin", "main", "--force"]) == "git_history_rewrite"

    # --- add ---
    def test_add_write(self):
        assert _ct(["git", "add", "."]) == "git_write"

    def test_add_dry_run_safe(self):
        assert _ct(["git", "add", "--dry-run", "."]) == "git_safe"

    def test_add_n_safe(self):
        assert _ct(["git", "add", "-n", "."]) == "git_safe"

    # --- rm ---
    def test_rm_discard(self):
        assert _ct(["git", "rm", "file.txt"]) == "git_discard"

    def test_rm_cached_write(self):
        assert _ct(["git", "rm", "--cached", "file.txt"]) == "git_write"

    # --- clean ---
    def test_clean_fd_history(self):
        assert _ct(["git", "clean", "-fd"]) == "git_history_rewrite"

    def test_clean_dry_run_safe(self):
        assert _ct(["git", "clean", "--dry-run"]) == "git_safe"

    def test_clean_n_safe(self):
        assert _ct(["git", "clean", "-n"]) == "git_safe"

    # --- reflog ---
    def test_reflog_bare_safe(self):
        assert _ct(["git", "reflog"]) == "git_safe"

    def test_reflog_show_safe(self):
        assert _ct(["git", "reflog", "show"]) == "git_safe"

    def test_reflog_delete_discard(self):
        assert _ct(["git", "reflog", "delete"]) == "git_discard"

    def test_reflog_expire_discard(self):
        assert _ct(["git", "reflog", "expire"]) == "git_discard"

    # --- checkout ---
    def test_checkout_branch_write(self):
        assert _ct(["git", "checkout", "main"]) == "git_write"

    def test_checkout_dot_discard(self):
        assert _ct(["git", "checkout", "."]) == "git_discard"

    def test_checkout_dashdash_discard(self):
        assert _ct(["git", "checkout", "--", "file.txt"]) == "git_discard"

    def test_checkout_head_discard(self):
        assert _ct(["git", "checkout", "HEAD", "file.txt"]) == "git_discard"

    def test_checkout_force_discard(self):
        assert _ct(["git", "checkout", "--force"]) == "git_discard"

    def test_checkout_f_discard(self):
        assert _ct(["git", "checkout", "-f"]) == "git_discard"

    def test_checkout_ours_discard(self):
        assert _ct(["git", "checkout", "--ours", "file.txt"]) == "git_discard"

    def test_checkout_theirs_discard(self):
        assert _ct(["git", "checkout", "--theirs", "file.txt"]) == "git_discard"

    def test_checkout_B_discard(self):
        assert _ct(["git", "checkout", "-B", "branch"]) == "git_discard"

    # --- switch ---
    def test_switch_branch_write(self):
        assert _ct(["git", "switch", "main"]) == "git_write"

    def test_switch_force_discard(self):
        assert _ct(["git", "switch", "--force", "main"]) == "git_discard"

    def test_switch_f_discard(self):
        assert _ct(["git", "switch", "-f", "main"]) == "git_discard"

    def test_switch_discard_changes_discard(self):
        assert _ct(["git", "switch", "--discard-changes", "main"]) == "git_discard"

    # --- restore ---
    def test_restore_discard(self):
        assert _ct(["git", "restore", "file.txt"]) == "git_discard"

    def test_restore_staged_write(self):
        assert _ct(["git", "restore", "--staged", "file.txt"]) == "git_write"

    # --- fallthrough ---
    def test_unknown_subcommand_falls_through(self):
        """Subcommands not handled by _classify_git() fall to prefix matching."""
        assert _ct(["git", "commit", "-m", "msg"]) == "git_write"

    def test_git_alone_falls_through(self):
        assert _ct(["git"]) == "unknown"


class TestGitSubcommands:
    """FD-017 Commit 2: Expanded git subcommand coverage."""

    # git_safe — new entries
    @pytest.mark.parametrize("sub", [
        "archive", "blame", "format-patch", "gitk", "grep",
        "annotate", "bisect", "bugreport", "count-objects", "diagnose",
        "difftool", "fast-export", "fsck", "help", "merge-tree",
        "range-diff", "rerere", "show-branch", "verify-commit", "verify-tag",
        "version", "whatchanged",
        "cherry", "diff-files", "diff-index", "diff-tree", "for-each-repo",
        "get-tar-commit-id", "ls-remote", "merge-base", "pack-redundant",
        "show-index", "show-ref", "unpack-file", "var", "verify-pack",
        "check-attr", "check-ignore", "check-mailmap", "check-ref-format",
        "column", "fmt-merge-msg", "interpret-trailers", "mailinfo",
        "mailsplit", "patch-id", "sh-i18n", "sh-setup", "stripspace",
        "remote",
    ])
    def test_git_safe_subcommands(self, sub):
        assert _ct(["git", sub]) == "git_safe"

    # git_write — new entries
    @pytest.mark.parametrize("sub", [
        "am", "bundle", "cherry-pick", "citool", "clone", "gc", "gui",
        "init", "maintenance", "mv", "revert", "scalar", "sparse-checkout",
        "worktree", "fast-import", "mergetool", "notes", "pack-refs",
        "repack", "submodule", "apply", "checkout-index", "commit-graph",
        "commit-tree", "hash-object", "index-pack", "merge-file",
        "merge-index", "mktag", "mktree", "multi-pack-index",
        "pack-objects", "prune-packed", "read-tree", "symbolic-ref",
        "unpack-objects", "update-index", "update-ref", "write-tree",
        "fetch-pack", "send-pack", "update-server-info",
        "credential", "credential-cache", "credential-store", "hook",
        "merge-one-file",
    ])
    def test_git_write_subcommands(self, sub):
        assert _ct(["git", sub]) == "git_write"

    # git_discard — new entry
    def test_git_prune_discard(self):
        assert _ct(["git", "prune"]) == "git_discard"

    # git_history_rewrite — new entries
    @pytest.mark.parametrize("sub", ["filter-branch", "replace"])
    def test_git_history_rewrite_subcommands(self, sub):
        assert _ct(["git", sub]) == "git_history_rewrite"

    # network_outbound — new entries
    @pytest.mark.parametrize("sub", ["daemon", "http-backend"])
    def test_git_network_outbound(self, sub):
        assert _ct(["git", sub]) == "network_outbound"


class TestGhCommands:
    """FD-017 Commit 3: gh (GitHub CLI) classification."""

    # git_safe — read-only queries
    @pytest.mark.parametrize("tokens", [
        ["gh", "issue", "list"],
        ["gh", "issue", "view", "123"],
        ["gh", "issue", "status"],
        ["gh", "pr", "list"],
        ["gh", "pr", "view", "456"],
        ["gh", "pr", "status"],
        ["gh", "pr", "checks", "456"],
        ["gh", "pr", "diff", "456"],
        ["gh", "repo", "list"],
        ["gh", "repo", "view"],
        ["gh", "release", "list"],
        ["gh", "release", "view", "v1.0"],
        ["gh", "run", "list"],
        ["gh", "run", "view", "123"],
        ["gh", "workflow", "list"],
        ["gh", "workflow", "view", "ci.yml"],
        ["gh", "codespace", "list"],
        ["gh", "gist", "list"],
        ["gh", "gist", "view", "abc"],
        ["gh", "project", "list"],
        ["gh", "project", "view", "1"],
        ["gh", "search", "code", "foo"],
        ["gh", "search", "issues", "bar"],
        ["gh", "search", "prs", "baz"],
        ["gh", "search", "repos", "qux"],
        ["gh", "search", "commits", "fix"],
        ["gh", "gpg-key", "list"],
        ["gh", "ssh-key", "list"],
        ["gh", "secret", "list"],
        ["gh", "variable", "list"],
        ["gh", "variable", "get", "VAR"],
        ["gh", "label", "list"],
        ["gh", "ruleset", "list"],
        ["gh", "ruleset", "view", "1"],
        ["gh", "ruleset", "check"],
        ["gh", "extension", "browse"],
        ["gh", "extension", "search", "foo"],
        ["gh", "browse"],
        ["gh", "org", "list"],
        ["gh", "status"],
        ["gh", "cache", "list"],
        ["gh", "auth", "status"],
        ["gh", "auth", "token"],
    ])
    def test_gh_safe(self, tokens):
        assert _ct(tokens) == "git_safe"

    # git_write — workflow mutations
    @pytest.mark.parametrize("tokens", [
        ["gh", "issue", "create"],
        ["gh", "issue", "close", "123"],
        ["gh", "issue", "comment", "123"],
        ["gh", "issue", "edit", "123"],
        ["gh", "issue", "reopen", "123"],
        ["gh", "issue", "lock", "123"],
        ["gh", "issue", "unlock", "123"],
        ["gh", "issue", "pin", "123"],
        ["gh", "issue", "unpin", "123"],
        ["gh", "issue", "transfer", "123", "owner/repo"],
        ["gh", "issue", "develop", "123"],
        ["gh", "pr", "create"],
        ["gh", "pr", "close", "456"],
        ["gh", "pr", "comment", "456"],
        ["gh", "pr", "edit", "456"],
        ["gh", "pr", "merge", "456"],
        ["gh", "pr", "ready", "456"],
        ["gh", "pr", "reopen", "456"],
        ["gh", "pr", "review", "456"],
        ["gh", "pr", "lock", "456"],
        ["gh", "pr", "unlock", "456"],
        ["gh", "pr", "update-branch"],
        ["gh", "pr", "checkout", "456"],
        ["gh", "repo", "create", "my-repo"],
        ["gh", "repo", "edit"],
        ["gh", "repo", "fork"],
        ["gh", "repo", "clone", "owner/repo"],
        ["gh", "repo", "sync"],
        ["gh", "release", "create", "v1.0"],
        ["gh", "release", "edit", "v1.0"],
        ["gh", "release", "upload", "v1.0", "file.tar.gz"],
        ["gh", "run", "rerun", "123"],
        ["gh", "workflow", "run", "ci.yml"],
        ["gh", "codespace", "create"],
        ["gh", "codespace", "ssh"],
        ["gh", "codespace", "stop"],
        ["gh", "gist", "create", "file.py"],
        ["gh", "gist", "edit", "abc"],
        ["gh", "gist", "clone", "abc"],
        ["gh", "project", "create"],
        ["gh", "project", "edit", "1"],
        ["gh", "gpg-key", "add", "key.pub"],
        ["gh", "ssh-key", "add", "key.pub"],
        ["gh", "secret", "set", "TOKEN"],
        ["gh", "variable", "set", "VAR"],
        ["gh", "label", "create", "bug"],
        ["gh", "label", "edit", "bug"],
        ["gh", "label", "clone", "owner/repo"],
    ])
    def test_gh_write(self, tokens):
        assert _ct(tokens) == "git_write"

    # git_history_rewrite — destructive / hard to reverse
    @pytest.mark.parametrize("tokens", [
        ["gh", "repo", "delete", "owner/repo"],
        ["gh", "repo", "archive", "owner/repo"],
        ["gh", "repo", "unarchive", "owner/repo"],
        ["gh", "repo", "rename", "new-name"],
        ["gh", "issue", "delete", "123"],
        ["gh", "release", "delete", "v1.0"],
        ["gh", "release", "delete-asset", "v1.0"],
        ["gh", "run", "cancel", "123"],
        ["gh", "run", "delete", "123"],
        ["gh", "workflow", "disable", "ci.yml"],
        ["gh", "workflow", "enable", "ci.yml"],
        ["gh", "codespace", "delete"],
        ["gh", "codespace", "rebuild"],
        ["gh", "gist", "delete", "abc"],
        ["gh", "project", "delete", "1"],
        ["gh", "project", "field-delete", "1"],
        ["gh", "project", "item-delete", "1"],
        ["gh", "gpg-key", "delete", "123"],
        ["gh", "ssh-key", "delete", "123"],
        ["gh", "secret", "delete", "TOKEN"],
        ["gh", "variable", "delete", "VAR"],
        ["gh", "label", "delete", "bug"],
        ["gh", "cache", "delete", "abc"],
    ])
    def test_gh_history_rewrite(self, tokens):
        assert _ct(tokens) == "git_history_rewrite"

    # filesystem_read — local config reads
    @pytest.mark.parametrize("tokens", [
        ["gh", "config", "get", "editor"],
        ["gh", "config", "list"],
        ["gh", "alias", "list"],
        ["gh", "extension", "list"],
        ["gh", "completion"],
        ["gh", "attestation", "trusted-root"],
    ])
    def test_gh_filesystem_read(self, tokens):
        assert _ct(tokens) == "filesystem_read"

    # filesystem_write — local config/file writes
    @pytest.mark.parametrize("tokens", [
        ["gh", "config", "set", "editor", "vim"],
        ["gh", "config", "clear-cache"],
        ["gh", "alias", "set", "co", "pr checkout"],
        ["gh", "alias", "delete", "co"],
        ["gh", "alias", "import", "aliases.yml"],
        ["gh", "extension", "create", "my-ext"],
        ["gh", "extension", "install", "owner/ext"],
        ["gh", "extension", "remove", "owner/ext"],
        ["gh", "extension", "upgrade", "owner/ext"],
        ["gh", "release", "download", "v1.0"],
        ["gh", "run", "download", "123"],
        ["gh", "attestation", "download"],
        ["gh", "attestation", "verify"],
        ["gh", "repo", "set-default"],
        ["gh", "auth", "login"],
        ["gh", "auth", "logout"],
        ["gh", "auth", "refresh"],
        ["gh", "auth", "setup-git"],
        ["gh", "auth", "switch"],
    ])
    def test_gh_filesystem_write(self, tokens):
        assert _ct(tokens) == "filesystem_write"

    # lang_exec — runs arbitrary code
    @pytest.mark.parametrize("tokens", [
        ["gh", "api", "/repos/owner/repo"],
        ["gh", "extension", "exec", "my-ext"],
    ])
    def test_gh_lang_exec(self, tokens):
        assert _ct(tokens) == "lang_exec"


# --- Profiles (FD-032) ---


class TestProfiles:
    """Built-in classify table loading by profile."""

    def test_profile_full_loads_all(self):
        table = get_builtin_table("full")
        action_types = {at for _, at in table}
        # Full profile has tool-specific types absent from minimal
        assert "container_destructive" in action_types
        assert "lang_exec" in action_types
        assert "package_install" in action_types
        assert "sql_write" in action_types

    def test_profile_minimal_subset(self):
        table = get_builtin_table("minimal")
        action_types = {at for _, at in table}
        # Minimal has core types
        assert "filesystem_delete" in action_types
        assert "filesystem_read" in action_types
        assert "filesystem_write" in action_types
        assert "git_safe" in action_types
        assert "network_outbound" in action_types
        assert "process_signal" in action_types
        # Minimal does NOT have tool-specific types
        assert "container_destructive" not in action_types
        assert "lang_exec" not in action_types
        assert "package_install" not in action_types
        assert "package_run" not in action_types
        assert "sql_write" not in action_types

    def test_profile_none_empty(self):
        table = get_builtin_table("none")
        assert table == []

    def test_profile_minimal_smaller_than_full(self):
        full = get_builtin_table("full")
        minimal = get_builtin_table("minimal")
        assert len(minimal) < len(full)

    def test_profile_minimal_docker_unknown(self):
        """Docker commands are not classified in minimal profile."""
        table = get_builtin_table("minimal")
        assert classify_tokens(["docker", "rm", "x"], builtin_table=table) == "unknown"

    def test_profile_minimal_rm_still_classified(self):
        """Core commands are classified in minimal profile."""
        table = get_builtin_table("minimal")
        assert classify_tokens(["rm", "file"], builtin_table=table) == "filesystem_delete"

    def test_profile_minimal_curl_still_classified(self):
        table = get_builtin_table("minimal")
        assert classify_tokens(["curl", "example.com"], builtin_table=table) == "network_outbound"

    def test_profile_none_everything_unknown(self):
        """With none profile, all commands are unknown."""
        table = get_builtin_table("none")
        assert classify_tokens(["rm", "-rf", "/"], builtin_table=table) == "unknown"
        assert classify_tokens(["git", "status"], builtin_table=table) == "unknown"
        assert classify_tokens(["curl", "x"], builtin_table=table) == "unknown"

    def test_profile_none_find_still_works(self):
        """Special classifiers (find) work regardless of profile."""
        table = get_builtin_table("none")
        assert classify_tokens(["find", ".", "-name", "*.py"], builtin_table=table) == "filesystem_read"
        assert classify_tokens(["find", ".", "-delete"], builtin_table=table) == "filesystem_delete"

    def test_profile_none_git_special_still_works(self):
        """Flag-dependent git classifiers work regardless of profile."""
        table = get_builtin_table("none")
        assert classify_tokens(["git", "push", "--force"], builtin_table=table) == "git_history_rewrite"
        assert classify_tokens(["git", "reset", "--hard"], builtin_table=table) == "git_discard"


# --- Three-table lookup (FD-032) ---


class TestThreeTableLookup:
    """Three-table priority: global → built-in → project."""

    def test_global_wins_over_builtin(self):
        """Global user entry overrides built-in classification."""
        global_t = build_user_table({"package_run": ["docker rm"]})
        builtin_t = get_builtin_table("full")
        result = classify_tokens(["docker", "rm", "x"], global_t, builtin_t, None)
        assert result == "package_run"  # global wins over container_destructive

    def test_builtin_wins_over_project(self):
        """Built-in beats project even with longer prefix (supply-chain safety)."""
        builtin_t = get_builtin_table("full")
        project_t = build_user_table({"filesystem_read": ["rm -rf"]})
        result = classify_tokens(["rm", "-rf", "foo"], None, builtin_t, project_t)
        assert result == "filesystem_delete"  # built-in "rm" wins, project "rm -rf" ignored

    def test_project_fills_gaps(self):
        """Project entries work for commands with no built-in match."""
        builtin_t = get_builtin_table("full")
        project_t = build_user_table({"my_deploys": ["my-tool deploy"]})
        result = classify_tokens(["my-tool", "deploy", "prod"], None, builtin_t, project_t)
        assert result == "my_deploys"

    def test_global_fills_gaps(self):
        """Global entries also work for unclassified commands."""
        global_t = build_user_table({"my_safe": ["terraform plan"]})
        builtin_t = get_builtin_table("full")
        result = classify_tokens(["terraform", "plan"], global_t, builtin_t, None)
        assert result == "my_safe"

    def test_no_tables_returns_unknown(self):
        """No tables provided → returns unknown (no implicit fallback)."""
        assert classify_tokens(["rm", "file"]) == "unknown"
        assert classify_tokens(["docker", "rm", "x"]) == "unknown"

    def test_supply_chain_reclassify_blocked(self):
        """Project can't reclassify rm to bypass filesystem_delete policy."""
        builtin_t = get_builtin_table("full")
        # Malicious project tries to reclassify rm variants as safe
        project_t = build_user_table({
            "filesystem_read": ["rm -rf", "rm -f", "rmdir --ignore"],
        })
        # All still match built-in "rm" / "rmdir" first
        assert classify_tokens(["rm", "-rf", "/"], None, builtin_t, project_t) == "filesystem_delete"
        assert classify_tokens(["rm", "-f", "file"], None, builtin_t, project_t) == "filesystem_delete"
        assert classify_tokens(["rmdir", "--ignore", "dir"], None, builtin_t, project_t) == "filesystem_delete"

    def test_project_with_minimal_profile(self):
        """Project fills gaps in minimal profile."""
        builtin_t = get_builtin_table("minimal")
        project_t = build_user_table({"my_docker": ["docker rm"]})
        # docker rm is unknown in minimal, project fills the gap
        assert classify_tokens(["docker", "rm", "x"], None, builtin_t, project_t) == "my_docker"

    def test_global_override_with_minimal_profile(self):
        """Global can reclassify even in minimal profile."""
        global_t = build_user_table({"my_safe_rm": ["rm"]})
        builtin_t = get_builtin_table("minimal")
        # Global "rm" wins over minimal built-in "rm → filesystem_delete"
        assert classify_tokens(["rm", "file"], global_t, builtin_t, None) == "my_safe_rm"
