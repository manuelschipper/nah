# Content Inspection

!!! note "Runtime scope"
    Deterministic content inspection applies to two surfaces: the literal text a
    Bash command redirects into a file (`echo '...' > file`, heredocs) and Claude
    Code `Grep` patterns (credential-search detection), plus the dry-run
    equivalents under `nah test`. Claude Code `Write`/`Edit`/`MultiEdit`/
    `NotebookEdit` are guarded by path and project-boundary checks plus optional
    LLM review — they do **not** use the deterministic content scanner. Codex and
    Terminal Guard do not use this scanner today.

nah scans the literal content a Bash command writes to disk for dangerous
patterns, and Grep queries for credential searches. This catches threats that
path-based checks alone can't detect.

## What gets scanned

| Surface | What is scanned |
|---------|-----------------|
| **Bash redirect-to-file** | the literal text being written (`echo '...' > f`, `cat <<EOF > f`) |
| **Grep** | `pattern` (the search query -- checked for credential searches) |

## Built-in content patterns

Patterns are organized by category. Each match triggers the category's policy (default: `ask`).

### destructive

| Pattern | Matches |
|---------|---------|
| `rm -rf` | `rm` with recursive + force flags |
| `shutil.rmtree` | Python recursive delete |
| `os.remove` | Python file delete |
| `os.unlink` | Python file unlink |

### exfiltration

| Pattern | Matches |
|---------|---------|
| `curl -X POST` | curl with POST method |
| `curl --data` | curl with data flag |
| `curl -d` | curl with short data flag |
| `requests.post` | Python requests POST |
| `urllib POST` | Python urllib with data= |

### obfuscation

| Pattern | Matches |
|---------|---------|
| `base64 -d \| bash` | Decode-pipe-execute |
| `eval(base64.b64decode` | Python base64 eval |
| `exec(compile` | Python dynamic compilation |

### subprocess_execution

| Pattern | Matches |
|---------|---------|
| `os.system(...)` | Python `os.system` invoking curl/wget/bash/sh/python/node/ruby/perl/php |
| `subprocess.run/call/Popen(...)` | Python `subprocess` running a dangerous command |
| `child_process .exec/.spawn(...)` | Node `child_process` running a dangerous command |
| `system/exec(...)` | Generic `system`/`exec` running a dangerous command |

!!! note "Secret detection moved to structural controls"
    nah no longer scans write/edit content for secret-looking literals (AWS
    keys, tokens, private keys) or credential paths. Deterministic secret
    pattern-matching was removed because it only catches known formats and gives
    false confidence. Secret protection is now structural: sensitive-path checks,
    taint/provenance, and Grep credential-search detection (below).

## Credential search patterns (Grep)

These patterns flag Grep queries that look like credential searches:

`password`, `secret`, `token`, `api_key`, `private_key`, `AWS_SECRET`, `BEGIN.*PRIVATE`

## Config options

### Suppress built-in patterns

Suppress by description string (the "Matches" column above):

```yaml
content_patterns:
  suppress:
    - "rm -rf"              # too many false positives in your workflow
    - "requests.post"       # you POST frequently in this project
```

Unmatched suppress entries print a stderr warning.

### Add custom patterns

```yaml
content_patterns:
  add:
    - category: destructive
      pattern: "\\bdd\\s+if=.*of=/dev/"
      description: "dd overwrite of a block device"
    - category: exfiltration
      pattern: "\\bwebhook\\.site\\b"
      description: "webhook.site exfil endpoint"
```

Each entry needs `category`, `pattern` (regex), and `description`. Invalid regexes
are rejected with a stderr warning. A `category` that isn't a built-in
(`destructive`, `exfiltration`, `obfuscation`, `subprocess_execution`) simply
creates a new custom category.

### Per-category policies

Override the default `ask` policy for specific categories:

```yaml
content_patterns:
  policies:
    destructive: block         # block destructive content patterns
    obfuscation: block         # block obfuscation patterns
```

Valid values: `ask`, `block`. Project config can only tighten by default.
Loosening requires `nah trust-project` for that exact project root.

### Suppress credential search patterns

```yaml
credential_patterns:
  suppress:
    - "\\btoken\\b"         # suppress the token pattern (by regex string)
  add:
    - "\\bINTERNAL_SECRET\\b"  # add a custom credential pattern
```

Use [presets](index.md#presets) when you want different content-inspection
settings for different workflows. Legacy `profile` keys are ignored and do not
disable built-in content or credential scanners.
