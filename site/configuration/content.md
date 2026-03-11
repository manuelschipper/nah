# Content Inspection

nah scans the content of Write, Edit, and Grep operations for dangerous patterns. This catches threats that path-based checks alone can't detect.

## What gets scanned

| Tool | Field scanned |
|------|---------------|
| **Write** | `content` (the full file content being written) |
| **Edit** | `new_string` (the replacement text) |
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

### credential_access

| Pattern | Matches |
|---------|---------|
| `~/.ssh/` access | References to SSH directory |
| `~/.aws/` access | References to AWS directory |
| `~/.gnupg/` access | References to GPG directory |

### obfuscation

| Pattern | Matches |
|---------|---------|
| `base64 -d \| bash` | Decode-pipe-execute |
| `eval(base64.b64decode` | Python base64 eval |
| `exec(compile` | Python dynamic compilation |

### secret

| Pattern | Matches |
|---------|---------|
| `-----BEGIN [RSA] PRIVATE KEY-----` | Private key literals |
| `AKIA...` | AWS access key IDs |
| `ghp_...` | GitHub personal access tokens |
| `sk-...` | Secret key tokens |
| `api_key / apikey / api_secret = '...'` | Hardcoded API keys |

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
    - category: secret
      pattern: "PRIVATE_TOKEN_[A-Z0-9]{32}"
      description: "internal service token"
    - category: exfiltration
      pattern: "\\bwebhook\\.site\\b"
      description: "webhook.site exfil endpoint"
```

Each entry needs `category`, `pattern` (regex), and `description`. Invalid regexes are rejected with a stderr warning.

### Per-category policies

Override the default `ask` policy for specific categories:

```yaml
content_patterns:
  policies:
    secret: block              # block all secret pattern matches
    obfuscation: block         # block obfuscation patterns
```

Valid values: `ask`, `block`. Project config can only tighten.

### Suppress credential search patterns

```yaml
credential_patterns:
  suppress:
    - "\\btoken\\b"         # suppress the token pattern (by regex string)
  add:
    - "\\bINTERNAL_SECRET\\b"  # add a custom credential pattern
```

## profile: none

Setting `profile: none` clears all built-in content patterns and credential search patterns. Add back only what you need.
