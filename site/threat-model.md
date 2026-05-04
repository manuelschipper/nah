# Threat Model

nah's threat model is action-level, not Claude Code-specific. It covers the
dangerous things coding agents and guarded terminals tend to do: run unknown
code, expose secrets, rewrite history, escape the project, hide behavior behind
shell tricks, escalate through package/container tooling, or tamper with the
guard itself.

Runtime coverage depends on the approval surface the runtime exposes. Claude
Code exposes the broadest tool surface today. Codex and Terminal Guard share the
same Bash classifier for command-level risk.

## Current audit

The pytest threat-model audit currently tracks **1,724 category coverage hits**
across **12 tested danger classes**.

| Danger class | Internal category | Hits | What it means |
| --- | --- | ---: | --- |
| Sensitive file access | `sensitive_path` | 254 | SSH keys, `.env`, cloud credentials, symlinks, protected paths |
| Wrapper evasion | `wrapper_evasion` | 236 | `env`, `command`, `xargs`, nested shells, passthrough wrappers |
| Unknown code execution | `rce` | 234 | `curl | bash`, downloaded scripts, command substitution, heredocs |
| Git history damage | `git_history` | 222 | force pushes, resets, branch/tag rewrites, destructive Git flows |
| Shell redirection abuse | `shell_redirect` | 213 | `>`, `>>`, `tee`, here-strings, redirected writes and secret flows |
| Package escalation | `package_escalation` | 153 | package installs, global installs, external-source package actions |
| Secret leaks | `secret_leak` | 92 | private keys, tokens, secret-looking writes, script/content leaks |
| Destructive container actions | `container_destructive` | 89 | `docker rm`, `docker system prune`, destructive container cleanup |
| Secret exfiltration | `credential_exfil` | 88 | sensitive reads flowing into network commands or credential searches |
| Guard tampering | `self_protection` | 67 | edits to nah hooks, config, runtime settings, robustness paths |
| Project boundary escapes | `project_boundary` | 46 | reads/writes outside the project root or trusted paths |
| Shell obfuscation | `shell_obfuscation` | 30 | process substitution, command substitution, hidden shell behavior |

Run it locally:

```bash
nah audit-threat-model --format summary
```

Current output:

```text
rce: 234
credential_exfil: 88
secret_leak: 92
git_history: 222
shell_redirect: 213
shell_obfuscation: 30
wrapper_evasion: 236
sensitive_path: 254
project_boundary: 46
package_escalation: 153
container_destructive: 89
self_protection: 67
```

These are pytest coverage hits. Some tests intentionally count toward more than
one danger class, so the number is not a unique test count and not a runtime
allow/ask/block promise.

The audit implementation lives in `src/nah/audit_threat_model.py`. It walks
`pytest --collect-only`, maps test node IDs into the categories above, and
renders summary, Markdown, or JSON output.

## Coverage by protection layer

| Layer | What is covered | Runtime notes |
| --- | --- | --- |
| Shell command safety | Unknown code execution, `curl | bash`, nested shells, command substitution, redirects, wrappers, `xargs`, Git rewrites, package installs, destructive container commands | Same Bash classifier for Claude Code Bash, Codex Bash permission requests, and Terminal Guard |
| File and path safety | Sensitive files, SSH keys, `.env`, cloud credentials, symlinks, writes outside the project | Full Claude Code file-tool coverage; partial Codex coverage through `apply_patch` |
| Content inspection | Private keys, tokens, destructive code patterns, credential-search patterns | Claude Code Write/Edit/MultiEdit/NotebookEdit/Grep; focused Codex `apply_patch` checks |
| Agent and MCP permissions | Third-party MCP tools, browser/database action types, unknown agent tools | Claude Code and Codex MCP permission surfaces |
| Guard self-protection | Attempts to edit nah hooks, config, runtime settings, and robustness paths | Runtime-specific install and preflight checks |

## Runtime matrix

| Protection | Claude Code | Codex | Terminal Guard |
| --- | --- | --- | --- |
| Bash classifier | Yes | Yes | Yes |
| File/path tools | Yes: Read, Write, Edit, MultiEdit, NotebookEdit, Glob | Partial: `apply_patch` | No |
| Content inspection | Yes: Write/Edit/MultiEdit/NotebookEdit/Grep | Partial: `apply_patch` path and added content | No |
| Search/Grep guard | Yes | No current equivalent | No |
| MCP classification | Yes | Yes | No |
| Guard self-protection | Yes | Partial: preflight and guarded patch paths | Shell install paths only |

Codex-specific hook behavior is tested separately in focused Codex tests. The
threat-model audit itself is strongest around the shared Bash classifier and the
Claude Code-style file/content/search handlers.

## Where the audit is strongest

The current audit hit distribution is Bash-heavy by design:

| Test area | Category hits | What it represents |
| --- | ---: | --- |
| `tests/test_bash.py` | 585 | Shell parsing, composition, redirects, wrappers, Git, packages, containers |
| `tests/test_taxonomy.py` | 499 | Action taxonomy, built-in classifiers, MCP/action-type mappings |
| `tests/test_fd079_script_exec.py` | 186 | Script execution, language runtimes, inspectable local code execution |
| `tests/test_paths.py` | 183 | Sensitive paths, symlinks, project boundaries, guard config paths |
| `tests/test_content.py` | 99 | Secret patterns, destructive content, credential-search detection |
| `tests/test_hint_battery.py` | 75 | Human-facing explanations for risky categories |
| `tests/test_fd080_write_llm.py` | 70 | Write/Edit/MultiEdit/NotebookEdit review flow |
| `tests/test_cli.py` | 21 | `nah test --tool ...`, CLI path/content/MCP probes |
| `tests/test_hook_robustness.py` | 6 | Guard robustness and failure handling |

That means the headline audit number should be read as: strong command-safety
coverage, plus meaningful file/path/content/search/guard coverage where the
runtime exposes those actions.
