# Safety Lists

nah uses configurable safety lists and pattern sets that feed into
classification and composition rules. All have built-in defaults that you can
extend or trim.

## known_registries

Trusted hosts for network context resolution. Outbound requests to known registries are auto-allowed; unknown hosts trigger `ask`.

**Built-in defaults (20 hosts):**

| Registry | Hosts |
|----------|-------|
| npm | `npmjs.org`, `www.npmjs.org`, `registry.npmjs.org`, `registry.yarnpkg.com`, `registry.npmmirror.com` |
| PyPI | `pypi.org`, `files.pythonhosted.org` |
| GitHub | `github.com`, `api.github.com`, `raw.githubusercontent.com` |
| Crates | `crates.io` |
| RubyGems | `rubygems.org` |
| Packagist | `packagist.org` |
| Go | `pkg.go.dev`, `proxy.golang.org` |
| Maven | `repo.maven.apache.org` |
| Google | `dl.google.com` |
| Docker | `hub.docker.com`, `registry.hub.docker.com`, `ghcr.io` |

Localhost addresses (`localhost`, `127.0.0.1`, `0.0.0.0`, `::1`) are always allowed regardless of this list.

!!! note
    `network_write` requests (POST/PUT/DELETE/PATCH) always ask, even to known hosts. Known registries only auto-allow reads.

**Config:**

```yaml
# Add hosts (list form)
known_registries:
  - internal-mirror.corp.com
  - artifacts.mycompany.io

# Add and remove (dict form)
known_registries:
  add:
    - internal-mirror.corp.com
  remove:
    - registry.npmmirror.com
```

!!! warning "Global config only"
    `known_registries` is only accepted in `~/.config/nah/config.yaml`. Project `.nah.yaml` cannot modify it (supply-chain safety).

**CLI:** `nah trust api.example.com` / `nah forget api.example.com`

## exec_sinks

Executables that trigger pipe composition rules. When a network or decode command pipes into an exec sink, nah blocks it.

**Built-in defaults (24):**

`bash`, `sh`, `dash`, `zsh`, `eval`, `python`, `python3`, `node`, `ruby`, `perl`, `php`, `bun`, `deno`, `fish`, `pwsh`, `powershell`, `cmd`, `env`, `lua`, `R`, `Rscript`, `make`, `julia`, `swift`

**Config:**

```yaml
exec_sinks:
  add:
    - lua
    - elixir
  remove:
    - php
```

!!! warning
    Removing exec sinks weakens composition rules (nah prints a stderr warning). The `network | exec` and `decode | exec` rules won't fire for removed sinks.

## sensitive_basenames

Filenames that trigger sensitive path detection regardless of directory.

**Built-in defaults (8):**

| Basename | Default policy |
|----------|:--------------:|
| `.env` | ask |
| `.env.local` | ask |
| `.env.production` | ask |
| `.npmrc` | ask |
| `.pypirc` | ask |
| `.pgpass` | ask |
| `.boto` | ask |
| `terraform.tfvars` | ask |

**Config:**

```yaml
sensitive_basenames:
  .env.staging: ask         # add new
  .npmrc: block             # tighten existing
  .pypirc: allow            # remove from list
```

## decode_commands

Commands that trigger obfuscation detection in pipe composition. When a decode command pipes into an exec sink, nah blocks the chain.

**Built-in defaults (13):**

| Command | Flag | Detects |
|---------|------|---------|
| `base64` | `-d` | `base64 -d \| bash` |
| `base64` | `--decode` | `base64 --decode \| bash` |
| `xxd` | `-r` | `xxd -r \| bash` |
| `uudecode` | *(any)* | `uudecode \| bash` |
| `gzip` | `-d` | `gzip -d \| bash` |
| `gzip` | `-dc` | `gzip -dc \| bash` |
| `zcat` | *(any)* | `zcat \| bash` |
| `bzip2` | `-d` | `bzip2 -d \| bash` |
| `bzcat` | *(any)* | `bzcat \| bash` |
| `xz` | `-d` | `xz -d \| bash` |
| `xzcat` | *(any)* | `xzcat \| bash` |
| `openssl` | `enc` | `openssl enc ... \| bash` |
| `unzip` | `-p` | `unzip -p archive.zip script.sh \| bash` |

**Config:**

```yaml
decode_commands:
  add:
    - "openssl enc -d"    # "command flag" format
    - "gunzip"            # no flag needed
  remove:
    - uudecode
```

!!! warning
    Removing decode commands weakens composition rules (nah prints a stderr warning).

## content_patterns

nah scans literal text written through Bash redirects, such as
`echo '...' > file` and heredocs, for destructive, exfiltration, obfuscation,
and subprocess-execution patterns. This applies wherever nah uses its Bash
classifier: Claude Code, Codex, Terminal Guard, and `nah test`.

Write/Edit/MultiEdit/NotebookEdit and Codex `apply_patch` payloads are not
content-scanned. Those surfaces use path, project-boundary, and destructive
patch checks instead.

Built-in content categories default to `ask`. Configure all three operations in
the global config; project config can only tighten category policies until the
project is trusted.

```yaml
content_patterns:
  suppress:
    - "requests.post"
  add:
    - category: destructive
      pattern: "\\bdd\\s+if=.*of=/dev/"
      description: "dd overwrite of a block device"
  policies:
    destructive: block
    obfuscation: block
```

`suppress` matches the built-in description string. Each `add` entry needs a
category, regular expression, and description. Custom category names are
allowed. Policy values are `ask` or `block`; invalid patterns and unmatched
suppress entries produce a warning.

## credential_patterns

Claude Code Grep queries are checked for credential-search patterns such as
`password`, `secret`, `token`, `api_key`, `private_key`, `AWS_SECRET`, and
`BEGIN.*PRIVATE`. This protects the search query; nah does not scan arbitrary
write content for secret-looking values.

```yaml
credential_patterns:
  suppress:
    - "\\btoken\\b"
  add:
    - "\\bINTERNAL_SECRET\\b"
```

Credential-pattern configuration is global-only. Values are regular
expressions; `suppress` matches the built-in regex string.

Use [presets](index.md#presets) when you want different safety-list values for
different workflows. Preset list values replace the base list for that selected
session.
