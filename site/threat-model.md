# Threat model

nah guards agents you can't fully isolate — running on your laptop, or where
credentials are available in plaintext. Its threat model starts with what an
action can do: run unknown code, expose
secrets, rewrite history, escape the project, hide behavior behind shell tricks,
escalate through package/container tooling, or tamper with the guard itself.

Runtime coverage depends on the approval surface each runtime exposes. Claude
Code exposes the broadest tool surface today. Codex and Terminal Guard share the
same Bash classifier for command-level risk.

## Current audit

The pytest threat-model audit currently tracks **1,673 category coverage hits**
across **13 tested danger classes**.

| Danger class | Internal category | Hits | What it means |
| --- | --- | ---: | --- |
| Sensitive file access | `sensitive_path` | 261 | SSH keys, `.env`, cloud credentials, symlinks, protected paths |
| Wrapper evasion | `wrapper_evasion` | 236 | `env`, `command`, `xargs`, nested shells, passthrough wrappers |
| Unknown code execution | `rce` | 222 | <code>curl &#124; bash</code>, downloaded scripts, command substitution, heredocs |
| Git history damage | `git_history` | 216 | force pushes, resets, branch/tag rewrites, destructive Git flows |
| Shell redirection abuse | `shell_redirect` | 190 | `>`, `>>`, `tee`, here-strings, redirected writes and secret flows |
| Package escalation | `package_escalation` | 149 | package installs, global installs, external-source package actions |
| Secret exfiltration | `credential_exfil` | 90 | sensitive reads flowing into network commands or credential searches |
| Destructive container actions | `container_destructive` | 89 | `docker rm`, `docker system prune`, destructive container cleanup |
| MCP and agent tool permissions | `mcp_permissions` | 83 | third-party MCP tools, global-only classification, wildcard safety, browser/database MCP actions |
| Project boundary escapes | `project_boundary` | 38 | reads/writes outside the project root or trusted paths |
| Guard tampering | `self_protection` | 37 | edits to nah hooks, config, runtime settings, robustness paths |
| Credential exposure | `secret_leak` | 32 | sensitive-path flows, credential searches, secret-store and environment reads |
| Shell obfuscation | `shell_obfuscation` | 30 | process substitution, command substitution, hidden shell behavior |

Run it locally:

```bash
nah audit-threat-model --format summary
```

Current output:

```text
rce: 222
credential_exfil: 90
secret_leak: 32
git_history: 216
shell_redirect: 190
shell_obfuscation: 30
wrapper_evasion: 236
sensitive_path: 261
project_boundary: 38
package_escalation: 149
container_destructive: 89
mcp_permissions: 83
self_protection: 37
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
| Shell command safety | Unknown code execution, <code>curl &#124; bash</code>, nested shells, command substitution, redirects, wrappers, `xargs`, Git rewrites, package installs, destructive container commands | Same Bash classifier for Claude Code Bash, Codex Bash permission requests, and Terminal Guard |
| File and path safety | Sensitive files, SSH keys, `.env`, cloud credentials, symlinks, writes outside the project | Full Claude Code file-tool coverage; partial Codex coverage through `apply_patch` |
| Content inspection | Destructive, exfiltration, obfuscation, and subprocess-execution code patterns; credential-search patterns | Bash redirect-to-file literals and Claude Code Grep; write-like payloads use structural checks only (path + project-boundary floor) |
| Agent and MCP permissions | Third-party MCP tools, browser/database action types, unknown agent tools | Claude Code and Codex MCP permission surfaces |
| Guard self-protection | Attempts to edit nah hooks, config, runtime settings, and robustness paths | Runtime-specific install and preflight checks |

## Runtime matrix

| Protection | Claude Code | Codex | Terminal Guard |
| --- | --- | --- | --- |
| Bash classifier | Yes | Yes | Yes |
| File/path tools | Yes: Read, Write, Edit, MultiEdit, NotebookEdit, Glob | Partial: `apply_patch` | No |
| Content inspection | Yes: Bash redirect-to-file literals, Grep | Partial: `apply_patch` path + destructive checks | No |
| Search/Grep guard | Yes | No current equivalent | No |
| MCP classification | Yes | Yes | No |
| Guard self-protection | Yes | Partial: preflight and guarded patch paths | Shell install paths only |

MCP permission behavior is counted explicitly through Claude Code matcher tests,
Codex hook tests, Codex setup checks, and taxonomy tests
for built-in browser/database MCP tools. Terminal Guard does not expose MCP, so
those protections apply only where the guarded agent runtime exposes MCP
permission requests.

## Where the audit is strongest

The current audit hit distribution is Bash-heavy by design:

| Test area | Category hits | What it represents |
| --- | ---: | --- |
| `tests/test_bash.py` | 613 | Shell parsing, composition, redirects, wrappers, Git, packages, containers |
| `tests/test_taxonomy.py` | 544 | Action taxonomy, built-in classifiers, MCP/action-type mappings |
| `tests/test_paths.py` | 192 | Sensitive paths, symlinks, project boundaries, guard config paths |
| `tests/test_fd079_script_exec.py` | 154 | Script execution, language runtimes, inspectable local code execution |
| `tests/test_content.py` | 85 | Destructive/exfiltration/obfuscation content, credential-search detection |
| `tests/test_hook_classify.py` | 29 | MCP global-only config, wildcard safety, DB context, and Playwright MCP mapping |
| `tests/test_cli.py` | 26 | `nah test --tool ...`, CLI path/content/MCP probes |
| `tests/test_codex_preflight.py` | 10 | Codex approval-memory and MCP setup checks |
| `tests/test_hook_robustness.py` | 9 | Guard robustness and failure handling |
| `tests/test_codex_hooks.py` | 4 | Codex hook decisions for Bash/MCP surfaces |
| `tests/test_hook_integration.py` | 4 | Claude hook integration coverage for MCP edge cases |
| `tests/test_remember.py` | 2 | Config writer validation for unsafe MCP wildcard rules |
| `tests/test_agents.py` | 1 | Agent tool matcher registration for MCP hooks |

That means the headline audit number should be read as: strong command-safety
coverage, plus meaningful file/path/content/search/guard coverage where the
runtime exposes those actions.

## The LLM layer and its boundary

The optional LLM layer (off by default) never clears a known deterministic ask
or block. Its only job is classify-unknown: name a built-in action type for a
deterministically `unknown` Bash command and list touched targets. Those targets
are re-checked by the same deterministic floor before anything can run.

This is friction reduction under an honest-classifier assumption, not a boundary
against a hostile model. A misaligned or prompt-injected classifier could
under-report a target; the deterministic layer remains the thing that catches
danger when the command is already understood or when surfaced targets cross a
known boundary.
