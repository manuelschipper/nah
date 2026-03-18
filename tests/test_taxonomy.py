"""Unit tests for nah.taxonomy — classification table, policies, helpers."""

import pytest

from nah import taxonomy
from nah.taxonomy import (
    build_user_table,
    classify_tokens,
    find_flag_classifier_shadows,
    find_table_shadows,
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
        ["git", "pull"],
        ["git", "fetch"],
        ["git", "merge", "main"],
        ["git", "stash"],
        ["git", "checkout", "branch"],
        ["git", "switch", "branch"],
    ])
    def test_git_write(self, tokens):
        assert _ct(tokens) == "git_write"

    # git_remote_write
    def test_git_push_remote_write(self):
        assert _ct(["git", "push"]) == "git_remote_write"

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
        assert _ct(["git", "push"]) == "git_remote_write"

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

    @pytest.mark.parametrize("tokens", [
        ["pip", "install", "--target=/tmp/lib", "flask"],
        ["pip", "install", "--root=/opt", "flask"],
        ["pip", "install", "-t", "/tmp/lib", "flask"],
        ["pip3", "install", "-t", "/tmp/lib", "flask"],
    ])
    def test_global_install_flag_variants_escalate_to_unknown(self, tokens):
        assert _ct(tokens) == "unknown"

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
        assert _ct(["find", ".", "-type", "f", "-exec", "grep", "-l", "needle", "{}", "+"]) == "filesystem_read"

    def test_find_exec_delete_command(self):
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
        ["docker", "container", "prune"],
        ["docker", "image", "prune"],
        ["docker", "volume", "prune"],
        ["docker", "network", "prune"],
        ["docker", "builder", "prune"],
        ["docker", "buildx", "prune"],
        ["docker", "compose", "down"],
        ["docker", "compose", "rm"],
        ["docker", "buildx", "rm", "builder0"],
        ["docker", "volume", "rm", "vol"],
        ["docker", "container", "rm", "abc"],
        ["docker", "image", "rm", "img"],
        ["docker", "network", "rm", "net"],
        ["podman", "rm", "abc"],
        ["podman", "rmi", "img"],
        ["podman", "system", "prune"],
        ["podman", "container", "prune"],
        ["podman", "image", "prune"],
        ["podman", "volume", "prune"],
        ["podman", "network", "prune"],
        ["podman", "pod", "prune"],
        ["podman", "compose", "down"],
        ["podman", "compose", "rm"],
        ["podman", "volume", "rm", "vol"],
        ["podman", "container", "rm", "abc"],
        ["podman", "image", "rm", "img"],
        ["podman", "network", "rm", "net"],
        ["podman", "pod", "rm", "dev"],
        ["podman", "machine", "rm", "devvm"],
        ["podman", "secret", "rm", "db-pass"],
    ])
    def test_container_destructive(self, tokens):
        assert _ct(tokens) == "container_destructive"


    # docker/podman read-only listing ops
    @pytest.mark.parametrize("tokens", [
        ["docker", "ps"],
        ["docker", "images"],
        ["docker", "image", "ls"],
        ["docker", "container", "ls"],
        ["docker", "compose", "ps"],
        ["docker", "compose", "ls"],
        ["docker", "volume", "ls"],
        ["docker", "network", "ls"],
        ["podman", "ps"],
        ["podman", "images"],
        ["podman", "image", "ls"],
        ["podman", "container", "ls"],
        ["podman", "compose", "ps"],
        ["podman", "pod", "ps"],
        ["podman", "volume", "ls"],
        ["podman", "network", "ls"],
    ])
    def test_container_listing_read_ops(self, tokens):
        assert _ct(tokens) == "filesystem_read"

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

    # db_write
    @pytest.mark.parametrize("tokens", [
        ["psql"],
        ["psql", "-c", "SELECT 1"],
        ["psql", "-f", "script.sql"],
        ["psql", "--command", "SELECT 1"],
        ["psql", "--file", "script.sql"],
        ["mysql"],
        ["mysql", "-e", "SHOW TABLES"],
        ["mysql", "--execute", "SHOW TABLES"],
        ["sqlite3", "db.sqlite", "SELECT 1"],
        ["snow", "sql", "-q", "SELECT 1"],
        ["snow", "sql", "-f", "file.sql"],
        ["snow", "sql", "--query", "SELECT 1"],
        ["snow", "sql", "--filename", "file.sql"],
        ["snowsql", "-q", "SELECT 1"],
        ["snowsql", "-f", "file.sql"],
        ["snowsql", "--query", "SELECT 1"],
        ["pg_restore", "dump.sql"],
    ])
    def test_db_write(self, tokens):
        assert _ct(tokens) == "db_write"

    # beads_safe
    @pytest.mark.parametrize("tokens", [
        ["bd", "list"],
        ["bd", "show", "nah-123"],
        ["bd", "ready"],
        ["bd", "doctor"],
        ["bd", "info"],
        ["bd", "status"],
        ["bd", "label", "list"],
        ["bd", "duplicates"],
    ])
    def test_beads_safe(self, tokens):
        assert _ct(tokens) == "beads_safe"

    # beads_write
    @pytest.mark.parametrize("tokens", [
        ["bd", "create", "foo"],
        ["bd", "update", "nah-123"],
        ["bd", "close", "nah-123"],
        ["bd", "label", "add", "nah-123", "design"],
        ["bd", "dolt", "push"],
        ["bd", "gate", "check"],
        ["bd", "doctor", "--fix"],
        ["bd", "duplicates", "--auto-merge"],
        ["bd", "backup"],
    ])
    def test_beads_write(self, tokens):
        assert _ct(tokens) == "beads_write"

    # beads_destructive
    @pytest.mark.parametrize("tokens", [
        ["bd", "delete", "nah-123"],
        ["bd", "sql", "SELECT 1"],
        ["bd", "init"],
        ["bd", "purge"],
        ["bd", "admin", "reset"],
        ["bd", "backup", "restore"],
    ])
    def test_beads_destructive(self, tokens):
        assert _ct(tokens) == "beads_destructive"

    def test_bd_dolt_start_stays_process_signal(self):
        assert _ct(["bd", "dolt", "start"]) == "process_signal"

    def test_bare_dolt_stays_db(self):
        assert _ct(["dolt", "sql"]) == "db_write"
        assert _ct(["dolt", "status"]) == "db_read"

    # db companion tools → filesystem_write
    @pytest.mark.parametrize("tokens", [
        ["pg_dump", "mydb"],
        ["pg_dumpall"],
        ["mysqldump", "mydb"],
    ])
    def test_db_companion_filesystem_write(self, tokens):
        assert _ct(tokens) == "filesystem_write"

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

    def test_git_equals_joined_global_value_flags_stripped(self):
        assert _ct(["git", "--git-dir=/x", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--work-tree=/x", "rm", "file"]) == "git_discard"
        assert _ct(["git", "--namespace=ns", "status"]) == "git_safe"

    def test_git_more_boolean_global_flags_stripped(self):
        assert _ct(["git", "-P", "status"]) == "git_safe"
        assert _ct(["git", "-p", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--paginate", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--no-advice", "status"]) == "git_safe"
        assert _ct(["git", "--no-lazy-fetch", "status"]) == "git_safe"
        assert _ct(["git", "--no-lazy-fetch", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--no-optional-locks", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--bare", "status"]) == "git_safe"
        assert _ct(["git", "--bare", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--icase-pathspecs", "status"]) == "git_safe"
        assert _ct(["git", "--icase-pathspecs", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--literal-pathspecs", "status"]) == "git_safe"
        assert _ct(["git", "--glob-pathspecs", "branch", "-D", "old"]) == "git_history_rewrite"
        assert _ct(["git", "--noglob-pathspecs", "rm", "file"]) == "git_discard"

    def test_git_config_env_variants_stripped(self):
        assert _ct(["git", "--config-env", "http.extraHeader=ENV", "push", "--force"]) == "git_history_rewrite"
        assert _ct(["git", "--config-env=http.extraHeader=ENV", "rm", "file"]) == "git_discard"

    def test_git_c_valid_values_stripped(self):
        assert _ct(["git", "-c", "core.editor=true", "status"]) == "git_safe"
        assert _ct(["git", "-c", "core.editor=true", "push", "--force"]) == "git_history_rewrite"

    def test_git_c_valid_values_work_with_global_overrides(self):
        tbl = build_user_table({"testing": ["git status"]})
        assert classify_tokens(
            ["git", "-c", "core.editor=true", "status"],
            global_table=tbl,
            builtin_table=_FULL,
        ) == "testing"

    def test_git_exec_path_equals_joined_flag_stripped(self):
        assert _ct(["git", "--exec-path=/tmp/git-core", "push", "--force"]) == "git_history_rewrite"

    def test_git_new_global_flags_work_with_global_overrides(self):
        tbl = build_user_table({"testing": ["git status"]})
        assert classify_tokens(
            ["git", "--config-env=http.extraHeader=ENV", "status"],
            global_table=tbl,
            builtin_table=_FULL,
        ) == "testing"
        assert classify_tokens(
            ["git", "--exec-path=/tmp/git-core", "status"],
            global_table=tbl,
            builtin_table=_FULL,
        ) == "testing"

    def test_git_config_env_invalid_values_fail_closed(self):
        assert _ct(["git", "--config-env", "push", "--force"]) == "unknown"
        assert _ct(["git", "--config-env", "push=ENV", "status"]) == "unknown"
        assert _ct(["git", "--config-env=http.extraHeader", "push", "--force"]) == "unknown"
        assert _ct(["git", "--config-env=push=ENV", "push", "--force"]) == "unknown"

    def test_git_c_invalid_values_fail_closed(self):
        assert _ct(["git", "-c", "push", "status"]) == "unknown"
        assert _ct(["git", "-c", "push", "push", "--force"]) == "unknown"

    def test_git_exec_path_bare_form_not_stripped(self):
        assert _ct(["git", "--exec-path", "push", "--force"]) == "unknown"

    # git reset --hard → git_discard (DD#3)
    def test_git_reset_hard_is_discard(self):
        assert _ct(["git", "reset", "--hard"]) == "git_discard"

    # Edge cases
    def test_empty_tokens(self):
        assert _ct([]) == "unknown"

    def test_unknown_command(self):
        assert _ct(["foobar", "--flag"]) == "unknown"

    # FD-065: basename normalization
    def test_basename_normalization(self):
        assert _ct(["/usr/bin/rm", "-rf", "/"]) == "filesystem_delete"

    def test_basename_curl(self):
        assert _ct(["/usr/local/bin/curl", "-X", "POST", "url"]) == "network_write"

    def test_basename_no_change(self):
        assert _ct(["rm", "-rf", "/"]) == "filesystem_delete"

    # FD-091: path-style classify entries with basename normalization
    def test_user_classify_path_prefix(self):
        """User entry 'vendor/bin/codecept run' matches after basename normalization."""
        tbl = build_user_table({"testing": ["vendor/bin/codecept run"]})
        assert classify_tokens(["vendor/bin/codecept", "run"], global_table=tbl) == "testing"

    def test_user_classify_dotslash(self):
        """User entry './my-tool test' matches after basename normalization."""
        tbl = build_user_table({"testing": ["./my-tool test"]})
        assert classify_tokens(["./my-tool", "test"], global_table=tbl) == "testing"

    def test_user_classify_absolute_path(self):
        """User entry '/usr/local/bin/foo' matches after basename normalization."""
        tbl = build_user_table({"testing": ["/usr/local/bin/foo"]})
        assert classify_tokens(["/usr/local/bin/foo"], global_table=tbl) == "testing"

    def test_builtin_gradlew_dotslash(self):
        """./gradlew tasks classifies via builtin gradlew entry after normalization."""
        assert _ct(["./gradlew", "tasks"]) == "filesystem_read"

    def test_user_classify_bare_still_works(self):
        """Bare command entries still match (no regression)."""
        tbl = build_user_table({"testing": ["codecept run"]})
        assert classify_tokens(["codecept", "run"], global_table=tbl) == "testing"

    def test_user_classify_path_via_project_table(self):
        """Path entry works via project_table (Phase 3), not just global_table."""
        tbl = build_user_table({"testing": ["vendor/bin/codecept run"]})
        assert classify_tokens(
            ["vendor/bin/codecept", "run"], project_table=tbl, profile="none",
        ) == "testing"

    def test_project_table_overrides_builtin_prefix(self):
        """Project classify entries beat builtins for the same command prefix."""
        tbl = build_user_table({"container_destructive": ["make docker-clean"]})
        builtin = get_builtin_table("full")
        assert classify_tokens(
            ["make", "docker-clean"],
            builtin_table=builtin,
            project_table=tbl,
            profile="none",
        ) == "container_destructive"

    def test_project_table_overrides_builtin_prefix_with_full_profile(self):
        """Override also works with profile='full' (flag classifiers enabled)."""
        tbl = build_user_table({"container_destructive": ["make docker-clean"]})
        builtin = get_builtin_table("full")
        assert classify_tokens(
            ["make", "docker-clean"],
            builtin_table=builtin,
            project_table=tbl,
            profile="full",
        ) == "container_destructive"

    def test_project_cannot_loosen_builtin_without_trust(self):
        """Without trust_project, project classify cannot weaken a builtin."""
        # docker rm is container_destructive (ask) in builtins;
        # project tries to reclassify as filesystem_read (allow) — should be denied.
        tbl = build_user_table({"filesystem_read": ["docker rm"]})
        builtin = get_builtin_table("full")
        assert classify_tokens(
            ["docker", "rm", "abc"],
            builtin_table=builtin,
            project_table=tbl,
            profile="none",
        ) == "container_destructive"

    def test_project_can_loosen_builtin_with_trust(self):
        """With trust_project=True, project classify can weaken a builtin."""
        tbl = build_user_table({"filesystem_read": ["docker rm"]})
        builtin = get_builtin_table("full")
        assert classify_tokens(
            ["docker", "rm", "abc"],
            builtin_table=builtin,
            project_table=tbl,
            profile="none",
            trust_project=True,
        ) == "filesystem_read"

    def test_user_classify_multi_token_path(self):
        """Path in non-first position: only first token gets basename'd."""
        tbl = build_user_table({"testing": ["php vendor/bin/codecept run"]})
        # 'php' has no path — stays 'php'. 'vendor/bin/codecept' is NOT first token
        # so it stays as-is in both the table and the input.
        assert classify_tokens(
            ["php", "vendor/bin/codecept", "run"], global_table=tbl,
        ) == "testing"

    def test_build_user_table_normalizes_path(self):
        """build_user_table normalizes path in first token."""
        tbl = build_user_table({"testing": ["vendor/bin/codecept run"]})
        assert tbl[0][0] == ("codecept", "run")

    def test_load_classify_table_no_dotslash_duplicates(self):
        """Built-in table has no duplicate prefixes after normalization."""
        table = get_builtin_table("full")
        seen: set[tuple[str, ...]] = set()
        dupes = []
        for prefix, action_type in table:
            if prefix in seen:
                dupes.append((prefix, action_type))
            seen.add(prefix)
        assert dupes == [], f"Duplicate prefixes in builtin table: {dupes}"

    def test_builtin_gradlew_build_dotslash(self):
        """./gradlew build classifies via builtin gradlew entry (package_install)."""
        assert _ct(["./gradlew", "build"]) == "package_install"

    def test_basename_empty_guard(self):
        """Entry with just '/' doesn't crash — basename returns empty string."""
        tbl = build_user_table({"testing": ["/"]})
        # '/' → basename '' → fallback keeps '/' → no crash
        assert len(tbl) == 1

    # FD-065: awk meta-execution
    def test_awk_safe(self):
        assert _ct(["awk", "{print $1}", "file"]) == "filesystem_read"

    def test_awk_system(self):
        assert _ct(["awk", 'BEGIN{system("whoami")}']) == "lang_exec"

    def test_awk_getline(self):
        assert _ct(["gawk", "{x | getline y}", "file"]) == "lang_exec"

    def test_awk_flag_skip(self):
        assert _ct(["awk", "-F:", "{print $1}", "/etc/passwd"]) == "filesystem_read"

    def test_mawk_nawk(self):
        assert _ct(["mawk", 'BEGIN{system("x")}']) == "lang_exec"


# --- get_policy ---


class TestGetPolicy:
    """Policy defaults per action type."""

    @pytest.mark.parametrize("action_type, expected", [
        ("filesystem_read", "allow"),
        ("filesystem_write", "context"),
        ("filesystem_delete", "context"),
        ("git_safe", "allow"),
        ("git_write", "allow"),
        ("git_remote_write", "ask"),
        ("git_discard", "ask"),
        ("git_history_rewrite", "ask"),
        ("network_outbound", "context"),
        ("package_install", "allow"),
        ("package_run", "allow"),
        ("package_uninstall", "ask"),
        ("lang_exec", "context"),
        ("process_signal", "ask"),
        ("container_destructive", "ask"),
        ("db_read", "allow"),
        ("db_write", "context"),
        ("beads_safe", "allow"),
        ("beads_write", "allow"),
        ("beads_destructive", "ask"),
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

    # FD-066: here-string detection
    def test_bash_here_string(self):
        is_w, inner = is_shell_wrapper(["bash", "<<<", "rm -rf /"])
        assert is_w is True
        assert inner == "rm -rf /"

    def test_sh_here_string(self):
        is_w, inner = is_shell_wrapper(["sh", "<<<", "ls"])
        assert is_w is True
        assert inner == "ls"

    def test_zsh_here_string(self):
        is_w, inner = is_shell_wrapper(["zsh", "<<<", "echo hi"])
        assert is_w is True
        assert inner == "echo hi"

    def test_non_wrapper_here_string(self):
        is_w, inner = is_shell_wrapper(["cat", "<<<", "text"])
        assert is_w is False
        assert inner is None

    def test_bash_here_string_missing_arg(self):
        is_w, _ = is_shell_wrapper(["bash", "<<<"])
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

    def test_branch_delete_discard(self):
        assert _ct(["git", "branch", "--delete", "old"]) == "git_discard"

    def test_branch_D_history_rewrite(self):
        assert _ct(["git", "branch", "-D", "old"]) == "git_history_rewrite"

    def test_branch_delete_force_history_rewrite(self):
        assert _ct(["git", "branch", "--delete", "--force", "old"]) == "git_history_rewrite"

    @pytest.mark.parametrize("tokens", [
        ["git", "branch", "-d", "-f", "old"],
        ["git", "branch", "-f", "-d", "old"],
        ["git", "branch", "-df", "old"],
        ["git", "branch", "-fd", "old"],
        ["git", "branch", "--force", "-d", "old"],
    ])
    def test_branch_force_delete_variants_history_rewrite(self, tokens):
        assert _ct(tokens) == "git_history_rewrite"

    def test_branch_delete_beats_safe_flag(self):
        assert _ct(["git", "branch", "-d", "-v", "old"]) == "git_discard"

    def test_branch_force_delete_beats_safe_flag(self):
        assert _ct(["git", "branch", "-D", "-v", "old"]) == "git_history_rewrite"

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
    def test_push_bare_remote_write(self):
        assert _ct(["git", "push"]) == "git_remote_write"

    def test_push_origin_main_remote_write(self):
        assert _ct(["git", "push", "origin", "main"]) == "git_remote_write"

    def test_push_force_history(self):
        assert _ct(["git", "push", "--force"]) == "git_history_rewrite"

    def test_push_f_history(self):
        assert _ct(["git", "push", "-f"]) == "git_history_rewrite"

    def test_push_force_with_lease_history(self):
        assert _ct(["git", "push", "--force-with-lease"]) == "git_history_rewrite"

    def test_push_force_with_lease_equals_history(self):
        assert _ct(["git", "push", "--force-with-lease=main"]) == "git_history_rewrite"
        assert _ct(["git", "push", "origin", "--force-with-lease=refs/heads/main"]) == "git_history_rewrite"

    def test_push_force_if_includes_history(self):
        assert _ct(["git", "push", "--force-if-includes"]) == "git_history_rewrite"

    def test_push_plus_refspec_history(self):
        assert _ct(["git", "push", "origin", "+main"]) == "git_history_rewrite"

    def test_push_origin_force_history(self):
        assert _ct(["git", "push", "origin", "--force"]) == "git_history_rewrite"

    def test_push_origin_main_force_history(self):
        assert _ct(["git", "push", "origin", "main", "--force"]) == "git_history_rewrite"

    @pytest.mark.parametrize("tokens", [
        ["git", "push", "origin", "--delete", "old"],
        ["git", "push", "--delete", "origin", "old"],
        ["git", "push", "-d", "origin", "old"],
        ["git", "push", "origin", ":old"],
    ])
    def test_push_delete_variants_history(self, tokens):
        assert _ct(tokens) == "git_history_rewrite"

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

    @pytest.mark.parametrize("tokens", [
        ["git", "clean", "-nfd"],
        ["git", "clean", "-fdn"],
        ["git", "clean", "-nd"],
    ])
    def test_clean_combined_dry_run_safe(self, tokens):
        assert _ct(tokens) == "git_safe"

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

    # git_write — local gh operations
    @pytest.mark.parametrize("tokens", [
        ["gh", "pr", "checkout", "456"],
        ["gh", "repo", "clone", "owner/repo"],
        ["gh", "gist", "clone", "abc"],
        ["gh", "codespace", "ssh"],
    ])
    def test_gh_write(self, tokens):
        assert _ct(tokens) == "git_write"

    # git_remote_write — remote state mutations
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
        ["gh", "repo", "create", "my-repo"],
        ["gh", "repo", "edit"],
        ["gh", "repo", "fork"],
        ["gh", "repo", "sync"],
        ["gh", "repo", "autolink", "create"],
        ["gh", "repo", "deploy-key", "add"],
        ["gh", "release", "create", "v1.0"],
        ["gh", "release", "edit", "v1.0"],
        ["gh", "release", "upload", "v1.0", "file.tar.gz"],
        ["gh", "run", "rerun", "123"],
        ["gh", "workflow", "run", "ci.yml"],
        ["gh", "codespace", "create"],
        ["gh", "codespace", "stop"],
        ["gh", "codespace", "edit"],
        ["gh", "gist", "create", "file.py"],
        ["gh", "gist", "edit", "abc"],
        ["gh", "gist", "rename", "abc", "newname"],
        ["gh", "project", "create"],
        ["gh", "project", "edit", "1"],
        ["gh", "project", "close", "1"],
        ["gh", "project", "copy", "1"],
        ["gh", "project", "field-create"],
        ["gh", "project", "item-add"],
        ["gh", "project", "item-archive"],
        ["gh", "project", "item-create"],
        ["gh", "project", "item-edit"],
        ["gh", "project", "link"],
        ["gh", "project", "mark-template"],
        ["gh", "project", "unlink"],
        ["gh", "gpg-key", "add", "key.pub"],
        ["gh", "ssh-key", "add", "key.pub"],
        ["gh", "secret", "set", "TOKEN"],
        ["gh", "variable", "set", "VAR"],
        ["gh", "label", "create", "bug"],
        ["gh", "label", "edit", "bug"],
        ["gh", "label", "clone", "owner/repo"],
    ])
    def test_gh_remote_write(self, tokens):
        assert _ct(tokens) == "git_remote_write"

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
        assert "db_write" in action_types
        assert "beads_safe" in action_types
        assert "beads_write" in action_types
        assert "beads_destructive" in action_types

    def test_profile_minimal_subset(self):
        table = get_builtin_table("minimal")
        action_types = {at for _, at in table}
        # Minimal has core types
        assert "filesystem_delete" in action_types
        assert "filesystem_read" in action_types
        assert "filesystem_write" in action_types
        assert "git_safe" in action_types
        assert "network_diagnostic" in action_types
        assert "process_signal" in action_types
        # Minimal does NOT have tool-specific types
        assert "container_destructive" not in action_types
        assert "lang_exec" not in action_types
        assert "package_install" not in action_types
        assert "package_run" not in action_types
        assert "db_write" not in action_types
        assert "beads_safe" not in action_types
        assert "beads_write" not in action_types
        assert "beads_destructive" not in action_types

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
        """With none profile, table-only commands are unknown."""
        table = get_builtin_table("none")
        assert classify_tokens(["rm", "-rf", "/"], builtin_table=table) == "unknown"
        assert classify_tokens(["git", "status"], builtin_table=table) == "unknown"

    def test_profile_none_curl_skipped(self):
        """Flag classifiers skipped under profile=none (FD-050)."""
        table = get_builtin_table("none")
        assert classify_tokens(["curl", "x"], builtin_table=table, profile="none") == "unknown"

    def test_profile_none_find_skipped(self):
        """Flag classifiers skipped under profile=none (FD-050)."""
        table = get_builtin_table("none")
        assert classify_tokens(["find", ".", "-name", "*.py"], builtin_table=table, profile="none") == "unknown"
        assert classify_tokens(["find", ".", "-delete"], builtin_table=table, profile="none") == "unknown"

    def test_profile_none_git_skipped(self):
        """Flag classifiers skipped under profile=none (FD-050)."""
        table = get_builtin_table("none")
        assert classify_tokens(["git", "push", "--force"], builtin_table=table, profile="none") == "unknown"
        assert classify_tokens(["git", "reset", "--hard"], builtin_table=table, profile="none") == "unknown"


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


# --- FD-050: Global config overrides flag classifiers ---


class TestGlobalOverridesFlagClassifiers:
    """FD-050: Global table checked before flag classifiers; profile:none skips them."""

    # --- V1: Default behavior (no regressions) ---

    def test_default_sed_i_unchanged(self):
        """No global table → sed -i still classified by flag classifier."""
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["sed", "-i", "s/a/b/", "file"], builtin_table=builtin_t) == "filesystem_write"

    def test_default_curl_d_unchanged(self):
        """No global table → curl -d still classified by flag classifier."""
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["curl", "-d", "data", "url"], builtin_table=builtin_t) == "network_write"

    def test_default_git_push_force_unchanged(self):
        """No global table → git push --force still classified by flag classifier."""
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "push", "--force"], builtin_table=builtin_t) == "git_history_rewrite"

    # --- V4–V10: Per-classifier override via global table ---

    def test_global_overrides_find(self):
        """Global classify entry overrides _classify_find."""
        global_t = build_user_table({"filesystem_read": ["find"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["find", ".", "-delete"], global_t, builtin_t) == "filesystem_read"

    def test_global_overrides_sed(self):
        """Global classify entry overrides _classify_sed."""
        global_t = build_user_table({"filesystem_read": ["sed"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["sed", "-i", "s/a/b/", "file"], global_t, builtin_t) == "filesystem_read"

    def test_global_overrides_tar(self):
        """Global classify entry overrides _classify_tar."""
        global_t = build_user_table({"filesystem_read": ["tar"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["tar", "czf", "a.tar.gz", "."], global_t, builtin_t) == "filesystem_read"

    def test_global_overrides_git(self):
        """Global classify entry overrides _classify_git."""
        global_t = build_user_table({"git_safe": ["git tag"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "tag", "-d", "v1"], global_t, builtin_t) == "git_safe"

    def test_global_overrides_curl(self):
        """Global classify entry overrides _classify_curl."""
        global_t = build_user_table({"network_outbound": ["curl"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["curl", "-d", "data", "url"], global_t, builtin_t) == "network_outbound"

    def test_global_overrides_wget(self):
        """Global classify entry overrides _classify_wget."""
        global_t = build_user_table({"network_outbound": ["wget"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["wget", "--post-data=x", "url"], global_t, builtin_t) == "network_outbound"

    def test_global_overrides_httpie(self):
        """Global classify entry overrides _classify_httpie."""
        global_t = build_user_table({"network_outbound": ["http"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["http", "POST", "example.com"], global_t, builtin_t) == "network_outbound"

    # --- V11–V13: Granularity (longest-prefix-first) ---

    def test_longest_prefix_wins(self):
        """More specific 'sed -i' wins over broader 'sed'."""
        global_t = build_user_table({
            "filesystem_write": ["sed -i"],
            "filesystem_read": ["sed"],
        })
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["sed", "-i", "s/a/b/", "file"], global_t, builtin_t) == "filesystem_write"
        assert classify_tokens(["sed", "s/a/b/", "file"], global_t, builtin_t) == "filesystem_read"

    def test_partial_override_leaves_other_commands(self):
        """Overriding git tag doesn't affect git push (flag classifier still runs)."""
        global_t = build_user_table({"git_safe": ["git tag"]})
        builtin_t = get_builtin_table("full")
        # git tag overridden
        assert classify_tokens(["git", "tag", "-d", "v1"], global_t, builtin_t) == "git_safe"
        # git push still uses flag classifier
        assert classify_tokens(["git", "push", "--force"], global_t, builtin_t) == "git_history_rewrite"

    def test_git_push_granularity(self):
        """More specific 'git push --force' wins over broader 'git push'."""
        global_t = build_user_table({
            "git_history_rewrite": ["git push --force"],
            "git_safe": ["git push"],
        })
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "push", "--force"], global_t, builtin_t) == "git_history_rewrite"
        assert classify_tokens(["git", "push", "origin", "main"], global_t, builtin_t) == "git_safe"

    # --- V14–V15: Git global flag stripping ---

    def test_git_C_stripped_for_global_lookup(self):
        """git -C /path push --force matches global 'git push --force'."""
        global_t = build_user_table({"git_safe": ["git push --force"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "-C", "/path", "push", "--force"], global_t, builtin_t) == "git_safe"

    def test_git_no_pager_stripped_for_global_lookup(self):
        """git --no-pager push matches global 'git push'."""
        global_t = build_user_table({"git_safe": ["git push"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "--no-pager", "push"], global_t, builtin_t) == "git_safe"

    def test_git_equals_joined_flag_stripped_for_global_lookup(self):
        """git --git-dir=/path push matches global 'git push'."""
        global_t = build_user_table({"git_safe": ["git push"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "--git-dir=/path", "push"], global_t, builtin_t) == "git_safe"

    def test_git_paginate_flag_stripped_for_global_lookup(self):
        """git -P push --force matches global 'git push --force'."""
        global_t = build_user_table({"git_safe": ["git push --force"]})
        builtin_t = get_builtin_table("full")
        assert classify_tokens(["git", "-P", "push", "--force"], global_t, builtin_t) == "git_safe"

    # --- V16–V21: Profile:none ---

    def test_profile_none_sed_unknown(self):
        """profile:none → sed -i → unknown (flag classifier skipped)."""
        assert classify_tokens(["sed", "-i", "s/a/b/", "file"], profile="none") == "unknown"

    def test_profile_none_curl_unknown(self):
        """profile:none → curl -d → unknown."""
        assert classify_tokens(["curl", "-d", "data", "url"], profile="none") == "unknown"

    def test_profile_none_find_unknown(self):
        """profile:none → find -delete → unknown."""
        assert classify_tokens(["find", ".", "-delete"], profile="none") == "unknown"

    def test_profile_none_git_unknown(self):
        """profile:none → git push --force → unknown."""
        assert classify_tokens(["git", "push", "--force"], profile="none") == "unknown"

    def test_profile_none_global_still_works(self):
        """profile:none + global table → global table still classifies."""
        global_t = build_user_table({"filesystem_read": ["sed"]})
        assert classify_tokens(["sed", "-i", "s/a/b/", "file"], global_t, profile="none") == "filesystem_read"

    def test_profile_none_ls_unknown(self):
        """profile:none → ls → unknown (builtin table empty, flag classifiers skipped)."""
        table = get_builtin_table("none")
        assert classify_tokens(["ls", "-la"], builtin_table=table, profile="none") == "unknown"

    # --- V25: Supply-chain safety ---

    def test_project_cannot_override_flag_classifiers(self):
        """Project table is Phase 3 — cannot override flag classifiers."""
        builtin_t = get_builtin_table("full")
        project_t = build_user_table({"filesystem_read": ["sed"]})
        # Project says sed → filesystem_read, but flag classifier runs first
        assert classify_tokens(["sed", "-i", "s/a/b/", "file"], None, builtin_t, project_t) == "filesystem_write"


# --- FD-018: sed classifier ---


class TestClassifySed:
    """Flag-dependent sed classification: -i/-I → write, else → read."""

    def test_bare_sed_is_read(self):
        assert _ct(["sed", "s/a/b/", "file"]) == "filesystem_read"

    def test_sed_e_is_read(self):
        assert _ct(["sed", "-e", "s/a/b/", "file"]) == "filesystem_read"

    def test_sed_n_is_read(self):
        assert _ct(["sed", "-n", "s/a/b/p", "file"]) == "filesystem_read"

    def test_sed_i_is_write(self):
        assert _ct(["sed", "-i", "s/a/b/", "file"]) == "filesystem_write"

    def test_sed_i_bak_is_write(self):
        assert _ct(["sed", "-i.bak", "s/a/b/", "file"]) == "filesystem_write"

    def test_sed_I_bsd_is_write(self):
        assert _ct(["sed", "-I", ".bak", "s/a/b/", "file"]) == "filesystem_write"

    def test_sed_ni_combined_is_write(self):
        assert _ct(["sed", "-ni", "s/a/b/p", "file"]) == "filesystem_write"

    def test_sed_nI_bsd_combined_is_write(self):
        assert _ct(["sed", "-nI", "s/a/b/", "file"]) == "filesystem_write"

    def test_sed_in_place_long_is_write(self):
        assert _ct(["sed", "--in-place", "s/a/b/", "file"]) == "filesystem_write"

    def test_sed_in_place_eq_bak_is_write(self):
        assert _ct(["sed", "--in-place=.bak", "s/a/b/", "file"]) == "filesystem_write"

    def test_sed_i_after_expr_is_write(self):
        assert _ct(["sed", "-e", "s/a/b/", "-i", "file"]) == "filesystem_write"

    def test_sed_ein_combined_is_write(self):
        assert _ct(["sed", "-ein", "s/a/b/", "file"]) == "filesystem_write"


# --- FD-018: tar classifier ---


class TestClassifyTar:
    """Flag-dependent tar classification: mode detection with write precedence."""

    def test_tar_tf_is_read(self):
        assert _ct(["tar", "tf", "a.tar"]) == "filesystem_read"

    def test_tar_list_long_is_read(self):
        assert _ct(["tar", "--list", "-f", "a.tar"]) == "filesystem_read"

    def test_tar_dash_tf_is_read(self):
        assert _ct(["tar", "-tf", "a.tar"]) == "filesystem_read"

    def test_tar_cf_is_write(self):
        assert _ct(["tar", "cf", "a.tar", "dir/"]) == "filesystem_write"

    def test_tar_xf_is_write(self):
        assert _ct(["tar", "xf", "a.tar"]) == "filesystem_write"

    def test_tar_czf_is_write(self):
        assert _ct(["tar", "czf", "a.tar.gz", "dir/"]) == "filesystem_write"

    def test_tar_dash_xzf_is_write(self):
        assert _ct(["tar", "-xzf", "a.tar.gz"]) == "filesystem_write"

    def test_tar_txf_write_wins(self):
        """Both t and x present: write takes precedence."""
        assert _ct(["tar", "-txf", "a.tar"]) == "filesystem_write"

    def test_tar_rf_append_is_write(self):
        assert _ct(["tar", "rf", "a.tar", "newfile"]) == "filesystem_write"

    def test_tar_delete_is_write(self):
        assert _ct(["tar", "--delete", "-f", "a.tar", "member"]) == "filesystem_write"

    def test_tar_extract_long_is_write(self):
        assert _ct(["tar", "--extract", "-f", "a.tar"]) == "filesystem_write"

    def test_tar_bare_conservative_default(self):
        """No mode recognized → conservative default (write)."""
        assert _ct(["tar"]) == "filesystem_write"

    def test_tar_uf_update_is_write(self):
        assert _ct(["tar", "uf", "a.tar", "dir/"]) == "filesystem_write"

    def test_tar_filename_not_misread(self):
        """Filename 'archive.tar' should not be parsed as mode string after a flag."""
        assert _ct(["tar", "-f", "archive.tar"]) == "filesystem_write"


# --- FD-018: bash builtins ---


class TestBashBuiltins:
    """Bash builtins classified as filesystem_read (allow)."""

    @pytest.mark.parametrize("cmd", [
        ["cd", "/tmp"],
        ["pwd"],
        ["type", "ls"],
        ["which", "python"],
        ["command", "-v", "git"],
        ["command", "-V", "git"],
        ["help", "cd"],
        ["alias"],
        ["test", "-f", "file"],
        ["true"],
        ["false"],
        ["dirs"],
        ["pushd", "/tmp"],
        ["popd"],
        ["compgen", "-c", "git"],
        ["[", "-f", "file", "]"],
    ])
    def test_builtin_is_read(self, cmd):
        assert _ct(cmd) == "filesystem_read"

    def test_bare_command_is_unknown(self):
        """Bare 'command' (no args) → unknown (not filesystem_read)."""
        assert _ct(["command"]) == "unknown"

    def test_command_psql_is_unknown(self):
        """'command psql' → unknown at taxonomy level (unwrap is bash.py's job)."""
        assert _ct(["command", "psql"]) == "unknown"


# --- FD-018: system info + compute ---


class TestSystemInfo:
    """System info, process info, and compute-only → filesystem_read."""

    @pytest.mark.parametrize("cmd", [
        ["uname", "-a"],
        ["hostname"],
        ["whoami"],
        ["uptime"],
        ["date"],
        ["cal"],
        ["nproc"],
        ["arch"],
        ["ps", "aux"],
        ["pgrep", "python"],
        ["free", "-h"],
        ["top", "-l", "1"],
        ["htop"],
        ["sleep", "5"],
        ["seq", "1", "10"],
        ["factor", "42"],
        ["expr", "1", "+", "1"],
        ["time", "ls"],
    ])
    def test_system_info_is_read(self, cmd):
        assert _ct(cmd) == "filesystem_read"


# --- FD-018: expanded coreutils ---


class TestCoreutilsExpanded:
    """Text processing, file info, binary inspection, compressed reading, wrappers."""

    @pytest.mark.parametrize("cmd", [
        # Text processing
        ["sort", "file.txt"],
        ["cut", "-d:", "-f1", "/etc/passwd"],
        ["uniq", "-c"],
        ["paste", "a.txt", "b.txt"],
        ["join", "a.txt", "b.txt"],
        ["comm", "a.txt", "b.txt"],
        ["tr", "a-z", "A-Z"],
        ["nl", "file.txt"],
        ["tac", "file.txt"],
        ["rev", "file.txt"],
        ["fold", "-w", "80"],
        ["fmt", "-w", "72", "file.txt"],
        ["column", "-t"],
        ["expand", "file.txt"],
        ["unexpand", "file.txt"],
        # File info & checksums
        ["basename", "/foo/bar.txt"],
        ["dirname", "/foo/bar.txt"],
        ["realpath", "file.txt"],
        ["readlink", "link"],
        ["md5sum", "file"],
        ["sha256sum", "file"],
        ["sha1sum", "file"],
        ["sha512sum", "file"],
        ["cksum", "file"],
        ["b2sum", "file"],
        ["cmp", "a", "b"],
        ["whereis", "python"],
        # Binary inspection
        ["od", "-x", "file"],
        ["hexdump", "-C", "file"],
        ["strings", "binary"],
        # Compressed reading
        ["zcat", "file.gz"],
        ["zgrep", "pattern", "file.gz"],
        ["zless", "file.gz"],
        ["zmore", "file.gz"],
        # Misc
        ["getconf", "PAGE_SIZE"],
        ["locale"],
        ["tty"],
        # nice/nohup/timeout/stdbuf removed — were classification bypasses (FD-105)
    ])
    def test_coreutils_is_read(self, cmd):
        assert _ct(cmd) == "filesystem_read"


# --- FD-022: Network classifiers ---


class TestFD022Classifiers:
    """FD-022: curl, wget, httpie flag-dependent classification."""

    # --- _classify_curl ---
    def test_curl_bare_outbound(self):
        assert _ct(["curl", "https://example.com"]) == "network_outbound"

    def test_curl_X_POST(self):
        assert _ct(["curl", "-X", "POST", "https://example.com"]) == "network_write"

    def test_curl_XPOST_no_space(self):
        assert _ct(["curl", "-XPOST", "https://example.com"]) == "network_write"

    def test_curl_request_eq_POST(self):
        assert _ct(["curl", "--request=POST", "https://example.com"]) == "network_write"

    def test_curl_request_eq_post_lowercase(self):
        assert _ct(["curl", "--request=post", "https://example.com"]) == "network_write"

    def test_curl_d_flag(self):
        assert _ct(["curl", "-d", "data", "https://example.com"]) == "network_write"

    def test_curl_data_eq(self):
        assert _ct(["curl", "--data=x", "https://example.com"]) == "network_write"

    def test_curl_F_form(self):
        assert _ct(["curl", "-F", "file=@f", "https://example.com"]) == "network_write"

    def test_curl_form_long(self):
        assert _ct(["curl", "--form", "file=@f", "https://example.com"]) == "network_write"

    def test_curl_T_upload(self):
        assert _ct(["curl", "-T", "file.txt", "https://example.com"]) == "network_write"

    def test_curl_upload_file(self):
        assert _ct(["curl", "--upload-file", "file.txt", "https://example.com"]) == "network_write"

    def test_curl_json_flag(self):
        assert _ct(["curl", "--json", '{"key":"val"}', "https://example.com"]) == "network_write"

    def test_curl_combined_sXPOST(self):
        assert _ct(["curl", "-sXPOST", "https://example.com"]) == "network_write"

    def test_curl_contradictory_X_GET_d(self):
        """Data flags take priority over method flags: -X GET -d data → write."""
        assert _ct(["curl", "-X", "GET", "-d", "data", "https://example.com"]) == "network_write"

    def test_curl_sXGET_outbound(self):
        assert _ct(["curl", "-sXGET", "https://example.com"]) == "network_outbound"

    # --- _classify_wget ---
    def test_wget_bare_outbound(self):
        assert _ct(["wget", "https://example.com"]) == "network_outbound"

    def test_wget_post_data(self):
        assert _ct(["wget", "--post-data", "x", "https://example.com"]) == "network_write"

    def test_wget_post_data_eq(self):
        assert _ct(["wget", "--post-data=x", "https://example.com"]) == "network_write"

    def test_wget_post_file(self):
        assert _ct(["wget", "--post-file", "data.txt", "https://example.com"]) == "network_write"

    def test_wget_method_POST(self):
        assert _ct(["wget", "--method", "POST", "https://example.com"]) == "network_write"

    def test_wget_method_eq_post(self):
        assert _ct(["wget", "--method=post", "https://example.com"]) == "network_write"

    def test_wget_method_GET_post_data_contradictory(self):
        """Data flags take priority: --method=GET --post-data=x → write."""
        assert _ct(["wget", "--method=GET", "--post-data=x", "https://example.com"]) == "network_write"

    # --- _classify_httpie ---
    def test_httpie_bare_outbound(self):
        assert _ct(["http", "example.com"]) == "network_outbound"

    def test_httpie_explicit_GET(self):
        assert _ct(["http", "GET", "example.com"]) == "network_outbound"

    def test_httpie_POST(self):
        assert _ct(["http", "POST", "example.com"]) == "network_write"

    def test_httpie_PUT(self):
        assert _ct(["http", "PUT", "example.com"]) == "network_write"

    def test_httpie_DELETE(self):
        assert _ct(["http", "DELETE", "example.com"]) == "network_write"

    def test_httpie_PATCH(self):
        assert _ct(["http", "PATCH", "example.com"]) == "network_write"

    def test_httpie_form_flag(self):
        assert _ct(["http", "--form", "example.com"]) == "network_write"

    def test_httpie_f_flag(self):
        assert _ct(["http", "-f", "example.com"]) == "network_write"

    def test_httpie_data_items(self):
        assert _ct(["http", "example.com", "key=value"]) == "network_write"

    def test_httpie_not_httpie_returns_none(self):
        """Non-httpie commands should not be caught."""
        assert _ct(["curl", "example.com"]) != "network_write"  # curl has its own classifier

    # --- Policy defaults ---
    def test_network_write_policy(self):
        assert get_policy("network_write") == "context"

    def test_network_diagnostic_policy(self):
        assert get_policy("network_diagnostic") == "allow"

    # --- Table entries ---
    def test_ping_diagnostic(self):
        assert _ct(["ping", "8.8.8.8"]) == "network_diagnostic"

    def test_netstat_filesystem_read(self):
        assert _ct(["netstat", "-an"]) == "filesystem_read"

    def test_netcat_outbound(self):
        assert _ct(["netcat", "example.com", "80"]) == "network_outbound"

    def test_ss_filesystem_read(self):
        assert _ct(["ss", "-tulpn"]) == "filesystem_read"

    def test_lsof_filesystem_read(self):
        assert _ct(["lsof", "-i"]) == "filesystem_read"

    def test_openssl_s_client_outbound(self):
        assert _ct(["openssl", "s_client"]) == "network_outbound"


# --- FD-051: Configurable exec sinks ---


class TestExecSinksConfigurable:
    """FD-051: exec_sinks add/remove/profile-none and new defaults."""

    def _setup_merge(self, cfg):
        from nah import config
        taxonomy.reset_exec_sinks()
        taxonomy._exec_sinks_merged = False
        config._cached_config = cfg

    def teardown_method(self):
        from nah import config
        config._cached_config = None
        taxonomy.reset_exec_sinks()
        taxonomy._exec_sinks_merged = True

    def test_new_defaults_bun(self):
        """bun is now a default exec sink."""
        assert "bun" in taxonomy._EXEC_SINKS_DEFAULTS
        assert is_exec_sink("bun")

    def test_new_defaults_deno(self):
        assert "deno" in taxonomy._EXEC_SINKS_DEFAULTS

    def test_new_defaults_fish(self):
        assert "fish" in taxonomy._EXEC_SINKS_DEFAULTS

    def test_new_defaults_pwsh(self):
        assert "pwsh" in taxonomy._EXEC_SINKS_DEFAULTS

    def test_add_via_list(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(exec_sinks=["custom_shell"]))
        assert is_exec_sink("custom_shell")
        # Default still present
        assert is_exec_sink("bash")

    def test_add_via_dict(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(exec_sinks={"add": ["custom_shell"]}))
        assert is_exec_sink("custom_shell")

    def test_remove_via_dict(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(exec_sinks={"remove": ["python3"]}))
        assert not is_exec_sink("python3")
        # Others still present
        assert is_exec_sink("bash")

    def test_profile_none_clears(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(profile="none"))
        assert not is_exec_sink("bash")
        assert not is_exec_sink("python3")

    def test_profile_none_with_add(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(profile="none", exec_sinks=["bash"]))
        assert is_exec_sink("bash")
        assert not is_exec_sink("python3")


# --- FD-051: Configurable decode commands ---


class TestDecodeCommandsConfigurable:
    """FD-051: decode_commands add/remove/profile-none and new defaults."""

    def _setup_merge(self, cfg):
        from nah import config
        taxonomy.reset_decode_commands()
        taxonomy._decode_commands_merged = False
        config._cached_config = cfg

    def teardown_method(self):
        from nah import config
        config._cached_config = None
        taxonomy.reset_decode_commands()
        taxonomy._decode_commands_merged = True

    def test_new_default_uudecode(self):
        """uudecode is now a default decode command."""
        assert ("uudecode", None) in taxonomy._DECODE_COMMANDS_DEFAULTS
        assert is_decode_stage(["uudecode", "file.uu"])

    def test_add_via_list(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(decode_commands=["openssl base64"]))
        assert is_decode_stage(["openssl", "base64", "-d", "payload"])
        # Default still present
        assert is_decode_stage(["base64", "-d"])

    def test_add_command_only(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(decode_commands=["mydecode"]))
        assert is_decode_stage(["mydecode", "whatever"])

    def test_remove_by_command_name(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(decode_commands={"remove": ["xxd"]}))
        assert not is_decode_stage(["xxd", "-r"])
        # Others still present
        assert is_decode_stage(["base64", "-d"])

    def test_profile_none_clears(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(profile="none"))
        assert not is_decode_stage(["base64", "-d"])
        assert not is_decode_stage(["xxd", "-r"])

    def test_profile_none_with_add(self):
        from nah.config import NahConfig
        self._setup_merge(NahConfig(profile="none", decode_commands=["uudecode"]))
        assert is_decode_stage(["uudecode", "file"])
        assert not is_decode_stage(["base64", "-d"])


# --- Shadow detection (FD-062) ---


class TestFindTableShadows:
    """Detect user classify entries that shadow finer-grained builtin entries."""

    def test_short_prefix_shadows_longer(self):
        user = [(("docker",), "container_destructive")]
        builtin = [
            (("docker", "rm"), "container_destructive"),
            (("docker", "rmi"), "container_destructive"),
            (("docker", "system", "prune"), "container_destructive"),
        ]
        result = find_table_shadows(user, builtin)
        assert ("docker",) in result
        assert len(result[("docker",)]) == 3

    def test_no_overlap_empty(self):
        user = [(("mycmd",), "lang_exec")]
        builtin = [(("docker", "rm"), "container_destructive")]
        assert find_table_shadows(user, builtin) == {}

    def test_exact_match_included(self):
        user = [(("docker", "rm"), "container_destructive")]
        builtin = [(("docker", "rm"), "container_destructive")]
        result = find_table_shadows(user, builtin)
        assert result[("docker", "rm")] == [("docker", "rm")]

    def test_user_longer_than_builtin_no_shadow(self):
        user = [(("docker", "rm", "-f"), "container_destructive")]
        builtin = [(("docker",), "container_destructive")]
        assert find_table_shadows(user, builtin) == {}

    def test_empty_tables(self):
        assert find_table_shadows([], []) == {}
        assert find_table_shadows([(("x",), "t")], []) == {}
        assert find_table_shadows([], [(("x",), "t")]) == {}

    def test_against_real_builtin_table(self):
        """User 'docker' should shadow multiple real builtin docker entries."""
        user = [(("docker",), "container_destructive")]
        builtin = get_builtin_table("full")
        result = find_table_shadows(user, builtin)
        assert ("docker",) in result
        assert len(result[("docker",)]) >= 2


class TestFindFlagClassifierShadows:
    """Detect user classify entries that shadow Phase 2 flag classifiers."""

    def test_curl_detected(self):
        user = [(("curl",), "network_outbound")]
        assert ("curl",) in find_flag_classifier_shadows(user)

    def test_git_detected(self):
        user = [(("git",), "git_safe")]
        assert ("git",) in find_flag_classifier_shadows(user)

    def test_find_detected(self):
        user = [(("find",), "filesystem_read")]
        assert ("find",) in find_flag_classifier_shadows(user)

    def test_non_flag_cmd_not_detected(self):
        user = [(("docker",), "container_destructive")]
        assert find_flag_classifier_shadows(user) == []

    def test_multi_token_not_detected(self):
        user = [(("curl", "-d"), "network_write")]
        assert find_flag_classifier_shadows(user) == []

    def test_all_flag_cmds(self):
        from nah.taxonomy import _FLAG_CLASSIFIER_CMDS
        user = [((cmd,), "unknown") for cmd in _FLAG_CLASSIFIER_CMDS]
        result = find_flag_classifier_shadows(user)
        assert len(result) == len(_FLAG_CLASSIFIER_CMDS)


# --- FD-019: Package Managers & Build Tools ---


class TestFD019PackageInstall:
    """FD-019: package_install classification for new entries."""

    @pytest.mark.parametrize("tokens", [
        ["npm", "ci"],
        ["npm", "update", "react"],
        ["npm", "audit", "fix"],
        ["npm", "dedupe"],
        ["npm", "rebuild"],
        ["npm", "link", "my-pkg"],
        ["npm", "init"],
        ["npm", "pack"],
        ["yarn", "install"],
        ["yarn", "upgrade", "react"],
        ["yarn", "up", "react"],
        ["yarn", "dedupe"],
        ["yarn", "patch", "react"],
        ["yarn", "plugin", "import", "@yarnpkg/plugin-typescript"],
        ["pnpm", "add", "react"],
        ["pnpm", "update", "react"],
        ["pnpm", "fetch"],
        ["pnpm", "patch", "react"],
        ["pnpm", "env", "use", "18"],
        ["bun", "add", "react"],
        ["bun", "build", "index.ts"],
        ["bun", "upgrade"],
        ["bun", "pm", "migrate"],
        ["python", "-m", "pip", "install", "flask"],
        ["python3", "-m", "pip", "install", "flask"],
        ["python", "-m", "build"],
        ["python", "-m", "venv", ".venv"],
        ["pip", "download", "flask"],
        ["pip", "wheel", "flask"],
        ["pip3", "download", "flask"],
        ["uv", "pip", "install", "flask"],
        ["uv", "pip", "sync"],
        ["uv", "pip", "compile", "requirements.in"],
        ["uv", "sync"],
        ["uv", "lock"],
        ["uv", "add", "flask"],
        ["uv", "venv"],
        ["uv", "build"],
        ["uv", "init"],
        ["uv", "self", "update"],
        ["uv", "tool", "install", "ruff"],
        ["uv", "python", "install", "3.12"],
        ["brew", "upgrade", "jq"],
        ["brew", "reinstall", "jq"],
        ["brew", "fetch", "jq"],
        ["apt", "update"],
        ["apt", "upgrade"],
        ["apt", "full-upgrade"],
        ["apt-get", "install", "curl"],
        ["apt-get", "dist-upgrade"],
        ["apt-get", "build-dep", "pkg"],
        ["dnf", "install", "vim"],
        ["dnf", "group", "install", "dev-tools"],
        ["dnf", "module", "install", "nodejs"],
        ["dnf", "makecache"],
        ["yum", "install", "gcc"],
        ["yum", "update"],
        ["gem", "update", "rails"],
        ["gem", "build", "my.gemspec"],
        ["gem", "pristine", "--all"],
        ["cargo", "add", "serde"],
        ["cargo", "check"],
        ["cargo", "doc"],
        ["cargo", "init", "my-project"],
        ["cargo", "new", "my-project"],
        ["cargo", "fetch"],
        ["cargo", "vendor"],
        ["go", "build", "./..."],
        ["go", "install", "./cmd/tool"],
        ["go", "mod", "tidy"],
        ["go", "mod", "vendor"],
        ["go", "mod", "init", "example.com/foo"],
        ["go", "work", "init"],
        ["go", "work", "sync"],
        ["gradle", "build"],
        ["gradle", "assemble"],
        ["gradle", "compileJava"],
        ["gradle", "jar"],
        ["gradle", "bootJar"],
        ["gradle", "init"],
        ["gradlew", "build"],
        ["gradlew", "assemble"],
        ["./gradlew", "build"],
        ["./gradlew", "jar"],
        ["mvn", "compile"],
        ["mvn", "package"],
        ["mvn", "install"],
        ["mvn", "archetype:generate"],
        ["mvn", "release:prepare"],
        ["cmake", "--build", "build/"],
        ["cpack"],
    ])
    def test_package_install(self, tokens):
        assert _ct(tokens) == "package_install"


class TestFD019PackageRun:
    """FD-019: package_run classification for new entries."""

    @pytest.mark.parametrize("tokens", [
        ["npm", "exec", "tsc"],
        ["npm", "start"],
        ["npm", "stop"],
        ["npm", "restart"],
        ["npm", "install-test"],
        ["yarn", "dlx", "create-react-app"],
        ["yarn", "exec", "tsc"],
        ["yarn", "start"],
        ["yarn", "test"],
        ["yarn", "create", "react-app"],
        ["yarn", "workspaces", "foreach", "run", "build"],
        ["pnpm", "exec", "tsc"],
        ["pnpm", "dlx", "create-react-app"],
        ["pnpm", "create", "react-app"],
        ["pnpm", "start"],
        ["pnpm", "test"],
        ["bun", "exec", "tsc"],
        ["bun", "x", "create-react-app"],
        ["bun", "test"],
        ["bun", "create", "react-app"],
        ["bun", "repl"],
        ["bunx", "create-react-app"],
        ["uv", "run", "python", "script.py"],
        ["uv", "tool", "run", "ruff"],
        ["uvx", "ruff"],
        ["cargo", "bench"],
        ["cargo", "fmt"],
        ["cargo", "fix"],
        ["go", "fmt", "./..."],
        ["go", "fix", "./..."],
        ["go", "tool", "cover"],
        ["gradle", "test"],
        ["gradle", "check"],
        ["gradle", "run"],
        ["gradle", "bootRun"],
        ["gradlew", "test"],
        ["gradlew", "run"],
        ["./gradlew", "test"],
        ["./gradlew", "bootRun"],
        ["mvn", "test"],
        ["mvn", "verify"],
        ["mvn", "exec:java"],
        ["mvn", "exec:exec"],
        ["ctest"],
        ["gmake"],
        ["gmake", "all"],
    ])
    def test_package_run(self, tokens):
        assert _ct(tokens) == "package_run"


class TestFD019PackageUninstall:
    """FD-019: package_uninstall classification for new entries."""

    @pytest.mark.parametrize("tokens", [
        ["npm", "prune"],
        ["npm", "unlink", "my-pkg"],
        ["npm", "cache", "clean", "--force"],
        ["yarn", "cache", "clean"],
        ["yarn", "autoclean"],
        ["yarn", "unlink", "my-pkg"],
        ["yarn", "plugin", "remove", "@yarnpkg/plugin-typescript"],
        ["pnpm", "prune"],
        ["pnpm", "unlink", "my-pkg"],
        ["pnpm", "store", "prune"],
        ["pnpm", "patch-remove", "react"],
        ["pnpm", "env", "remove", "18"],
        ["bun", "unlink", "my-pkg"],
        ["bun", "pm", "cache", "rm"],
        ["pip", "cache", "purge"],
        ["pip", "cache", "remove", "flask"],
        ["pip3", "cache", "purge"],
        ["uv", "pip", "uninstall", "flask"],
        ["uv", "remove", "flask"],
        ["uv", "tool", "uninstall", "ruff"],
        ["uv", "python", "uninstall", "3.12"],
        ["uv", "cache", "clean"],
        ["uv", "cache", "prune"],
        ["brew", "cleanup"],
        ["brew", "autoremove"],
        ["brew", "unlink", "jq"],
        ["brew", "untap", "homebrew/cask"],
        ["brew", "update-reset"],
        ["apt", "autoremove"],
        ["apt", "clean"],
        ["apt", "autoclean"],
        ["apt-get", "remove", "pkg"],
        ["apt-get", "purge", "pkg"],
        ["apt-get", "autoremove"],
        ["apt-get", "clean"],
        ["dnf", "remove", "vim"],
        ["dnf", "autoremove"],
        ["dnf", "clean", "all"],
        ["dnf", "clean", "packages"],
        ["dnf", "history", "undo", "5"],
        ["dnf", "group", "remove", "dev-tools"],
        ["dnf", "module", "remove", "nodejs"],
        ["yum", "remove", "gcc"],
        ["yum", "clean", "all"],
        ["yum", "autoremove"],
        ["gem", "cleanup"],
        ["cargo", "clean"],
        ["cargo", "remove", "serde"],
        ["go", "clean"],
        ["gradle", "clean"],
        ["gradlew", "clean"],
        ["./gradlew", "clean"],
        ["mvn", "clean"],
        ["mvn", "dependency:purge-local-repository"],
    ])
    def test_package_uninstall(self, tokens):
        assert _ct(tokens) == "package_uninstall"


class TestFD019FilesystemRead:
    """FD-019: filesystem_read classification for package manager query commands."""

    @pytest.mark.parametrize("tokens", [
        ["npm", "ls"],
        ["npm", "list"],
        ["npm", "outdated"],
        ["npm", "info", "react"],
        ["npm", "view", "react"],
        ["npm", "audit"],
        ["npm", "fund"],
        ["npm", "search", "react"],
        ["npm", "doctor"],
        ["npm", "whoami"],
        ["npm", "help"],
        ["npm", "config", "get", "registry"],
        ["npm", "cache", "ls"],
        ["yarn", "info", "react"],
        ["yarn", "list"],
        ["yarn", "why", "react"],
        ["yarn", "audit"],
        ["yarn", "config", "get", "registry"],
        ["yarn", "npm", "info", "react"],
        ["yarn", "npm", "whoami"],
        ["yarn", "workspaces", "list"],
        ["yarn", "help"],
        ["pnpm", "list"],
        ["pnpm", "outdated"],
        ["pnpm", "audit"],
        ["pnpm", "why", "react"],
        ["pnpm", "store", "status"],
        ["pnpm", "doctor"],
        ["bun", "pm", "ls"],
        ["bun", "pm", "bin"],
        ["bun", "outdated"],
        ["bun", "help"],
        ["pip", "list"],
        ["pip", "show", "flask"],
        ["pip", "freeze"],
        ["pip", "check"],
        ["pip", "cache", "list"],
        ["pip", "cache", "info"],
        ["pip", "hash", "flask.whl"],
        ["pip", "help"],
        ["pip3", "list"],
        ["pip3", "show", "flask"],
        ["pip3", "freeze"],
        ["pip3", "help"],
        ["uv", "pip", "list"],
        ["uv", "pip", "show", "flask"],
        ["uv", "pip", "freeze"],
        ["uv", "pip", "tree"],
        ["uv", "tree"],
        ["uv", "tool", "list"],
        ["uv", "python", "list"],
        ["uv", "python", "find"],
        ["uv", "cache", "dir"],
        ["uv", "version"],
        ["uv", "help"],
        ["brew", "list"],
        ["brew", "info", "jq"],
        ["brew", "search", "jq"],
        ["brew", "outdated"],
        ["brew", "deps", "jq"],
        ["brew", "leaves"],
        ["brew", "doctor"],
        ["brew", "--version"],
        ["brew", "--prefix"],
        ["brew", "services", "list"],
        ["brew", "services", "info", "redis"],
        ["brew", "help"],
        ["apt", "list"],
        ["apt", "search", "curl"],
        ["apt", "show", "curl"],
        ["apt", "policy", "curl"],
        ["apt-get", "check"],
        ["dnf", "list"],
        ["dnf", "search", "vim"],
        ["dnf", "info", "vim"],
        ["dnf", "repolist"],
        ["dnf", "check-update"],
        ["dnf", "history"],
        ["dnf", "history", "info", "5"],
        ["dnf", "group", "list"],
        ["dnf", "module", "list"],
        ["dnf", "help"],
        ["yum", "list"],
        ["yum", "search", "gcc"],
        ["yum", "info", "gcc"],
        ["yum", "check-update"],
        ["gem", "list"],
        ["gem", "search", "rails"],
        ["gem", "info", "rails"],
        ["gem", "contents", "rails"],
        ["gem", "environment"],
        ["gem", "outdated"],
        ["gem", "help"],
        ["cargo", "search", "serde"],
        ["cargo", "tree"],
        ["cargo", "metadata"],
        ["cargo", "clippy"],
        ["cargo", "fmt", "--check"],
        ["cargo", "version"],
        ["cargo", "help"],
        ["go", "doc", "fmt"],
        ["go", "list", "./..."],
        ["go", "vet", "./..."],
        ["go", "version"],
        ["go", "mod", "verify"],
        ["go", "mod", "graph"],
        ["go", "mod", "why", "example.com/foo"],
        ["go", "help"],
        ["gradle", "dependencies"],
        ["gradle", "dependencyInsight", "--dependency", "junit"],
        ["gradle", "projects"],
        ["gradle", "tasks"],
        ["gradle", "properties"],
        ["gradle", "--version"],
        ["gradle", "help"],
        ["gradlew", "dependencies"],
        ["gradlew", "tasks"],
        ["gradlew", "--version"],
        ["./gradlew", "dependencies"],
        ["./gradlew", "tasks"],
        ["./gradlew", "--version"],
        ["mvn", "validate"],
        ["mvn", "dependency:tree"],
        ["mvn", "dependency:analyze"],
        ["mvn", "help:effective-pom"],
        ["mvn", "-version"],
        ["mvn", "--help"],
        ["cmake", "--version"],
        ["cmake", "--help"],
        ["cmake", "--system-information"],
        ["ctest", "-N"],
        ["ctest", "--show-only"],
        ["make", "-n"],
        ["make", "--dry-run"],
        ["make", "-p"],
        ["make", "-q"],
        ["make", "--version"],
        ["make", "--help"],
        ["gmake", "-n"],
        ["gmake", "--dry-run"],
        ["gmake", "--version"],
    ])
    def test_filesystem_read(self, tokens):
        assert _ct(tokens) == "filesystem_read"


class TestFD019FilesystemWrite:
    """FD-019: filesystem_write for make/cmake install."""

    @pytest.mark.parametrize("tokens", [
        ["make", "install"],
        ["gmake", "install"],
        ["cmake", "--install", "build/"],
    ])
    def test_filesystem_write(self, tokens):
        assert _ct(tokens) == "filesystem_write"


class TestFD019NetworkWrite:
    """FD-019: network_write classification for publish/deploy commands."""

    @pytest.mark.parametrize("tokens", [
        ["npm", "publish"],
        ["npm", "unpublish", "my-pkg"],
        ["npm", "deprecate", "my-pkg@1.0", "use v2"],
        ["npm", "dist-tag", "add", "my-pkg@1.0", "latest"],
        ["npm", "access", "public", "my-pkg"],
        ["npm", "owner", "add", "user", "my-pkg"],
        ["yarn", "publish"],
        ["yarn", "npm", "publish"],
        ["yarn", "npm", "tag", "add", "my-pkg@1.0", "latest"],
        ["pnpm", "publish"],
        ["bun", "publish"],
        ["uv", "publish"],
        ["gem", "push", "my.gem"],
        ["gem", "yank", "my-gem", "-v", "1.0"],
        ["gem", "owner", "--add", "user", "my-gem"],
        ["cargo", "publish"],
        ["cargo", "owner", "--add", "user"],
        ["cargo", "yank", "--version", "1.0"],
        ["gradle", "publish"],
        ["gradle", "uploadArchives"],
        ["gradlew", "publish"],
        ["./gradlew", "publish"],
        ["./gradlew", "uploadArchives"],
        ["mvn", "deploy"],
        ["mvn", "site-deploy"],
        ["mvn", "release:perform"],
    ])
    def test_network_write(self, tokens):
        assert _ct(tokens) == "network_write"


class TestFD019PrefixPriority:
    """FD-019: Longest-prefix-first resolves ambiguous commands."""

    def test_npm_audit_vs_audit_fix(self):
        assert _ct(["npm", "audit"]) == "filesystem_read"
        assert _ct(["npm", "audit", "fix"]) == "package_install"

    def test_make_vs_make_install(self):
        assert _ct(["make"]) == "package_run"
        assert _ct(["make", "install"]) == "filesystem_write"

    def test_make_vs_make_dry_run(self):
        assert _ct(["make"]) == "package_run"
        assert _ct(["make", "-n"]) == "filesystem_read"

    def test_cargo_fmt_vs_fmt_check(self):
        assert _ct(["cargo", "fmt"]) == "package_run"
        assert _ct(["cargo", "fmt", "--check"]) == "filesystem_read"

    def test_cmake_build_vs_install(self):
        assert _ct(["cmake", "--build", "build/"]) == "package_install"
        assert _ct(["cmake", "--install", "build/"]) == "filesystem_write"

    def test_gmake_vs_gmake_install(self):
        assert _ct(["gmake"]) == "package_run"
        assert _ct(["gmake", "install"]) == "filesystem_write"

    def test_gmake_vs_gmake_dry_run(self):
        assert _ct(["gmake"]) == "package_run"
        assert _ct(["gmake", "-n"]) == "filesystem_read"

    def test_ctest_vs_ctest_N(self):
        assert _ct(["ctest"]) == "package_run"
        assert _ct(["ctest", "-N"]) == "filesystem_read"


class TestFD019GlobalInstall:
    """FD-019: Global-install flag classifier escalation."""

    @pytest.mark.parametrize("tokens", [
        ["npm", "install", "-g", "typescript"],
        ["npm", "install", "--global", "typescript"],
        ["pnpm", "add", "--global", "turbo"],
        ["bun", "add", "--global", "bun-types"],
        ["pip", "install", "--system", "flask"],
        ["pip", "install", "--target", "/tmp/lib", "flask"],
        ["pip", "install", "--root", "/opt", "flask"],
        ["pip3", "install", "--system", "flask"],
        ["cargo", "install", "--root", "/usr/local", "ripgrep"],
        ["gem", "install", "--system", "bundler"],
    ])
    def test_global_flag_escalates_to_unknown(self, tokens):
        assert _ct(tokens) == "unknown"

    def test_npm_install_without_global_still_install(self):
        assert _ct(["npm", "install", "react"]) == "package_install"

    def test_pip_install_without_system_still_install(self):
        assert _ct(["pip", "install", "flask"]) == "package_install"

    def test_cargo_build_without_root_still_install(self):
        assert _ct(["cargo", "build"]) == "package_install"

    def test_yarn_not_in_global_install_cmds(self):
        """yarn uses 'yarn global add' pattern, not a flag."""
        assert _ct(["yarn", "add", "something"]) == "package_install"

    def test_global_override_via_user_table(self):
        """Global config can override the global-install flag classifier."""
        global_t = build_user_table({"package_install": ["npm install"]})
        builtin_t = get_builtin_table("full")
        result = classify_tokens(
            ["npm", "install", "-g", "x"], global_t, builtin_t
        )
        assert result == "package_install"


class TestFD019Roundtrip:
    """Every JSON prefix entry classifies to its file's action type."""

    def test_all_classify_full_entries_roundtrip(self):
        import json
        from pathlib import Path
        data_dir = Path(__file__).parent.parent / "src" / "nah" / "data" / "classify_full"
        full_table = get_builtin_table("full")
        failures = []
        for json_file in sorted(data_dir.glob("*.json")):
            expected_type = json_file.stem
            with open(json_file) as f:
                prefixes = json.load(f)
            for prefix_str in prefixes:
                tokens = prefix_str.split()
                result = classify_tokens(tokens, builtin_table=full_table)
                if result != expected_type:
                    failures.append(
                        f"{prefix_str!r} → {result} (expected {expected_type})"
                    )
        assert failures == [], "Misclassified entries:\n" + "\n".join(failures)


class TestFD019NoDuplicates:
    """No prefix string appears in more than one JSON file."""

    def test_no_cross_file_duplicates(self):
        import json
        from pathlib import Path
        data_dir = Path(__file__).parent.parent / "src" / "nah" / "data" / "classify_full"
        seen: dict[str, str] = {}
        duplicates = []
        for json_file in sorted(data_dir.glob("*.json")):
            with open(json_file) as f:
                prefixes = json.load(f)
            for prefix_str in prefixes:
                if prefix_str in seen:
                    duplicates.append(
                        f"{prefix_str!r} in both {seen[prefix_str]} and {json_file.name}"
                    )
                else:
                    seen[prefix_str] = json_file.name
        assert duplicates == [], "Duplicate entries:\n" + "\n".join(duplicates)
