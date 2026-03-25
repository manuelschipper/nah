"""Content inspection — regex-scan Write/Edit content for dangerous patterns."""

import re
import sys

from dataclasses import dataclass


@dataclass
class ContentMatch:
    category: str
    pattern_desc: str
    matched_text: str
    policy: str = "ask"


_MAX_SCAN_CHARS = 1_048_576  # 1M characters (~1MB for ASCII)
_truncation_logged = False


# Compiled regexes by category. Each entry: (compiled_regex, description).
_CONTENT_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "destructive": [
        (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"), "rm -rf"),
        (re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b"), "rm -rf"),
        (re.compile(r"\bshutil\.rmtree\b"), "shutil.rmtree"),
        (re.compile(r"\bos\.remove\b"), "os.remove"),
        (re.compile(r"\bos\.unlink\b"), "os.unlink"),
    ],
    "exfiltration": [
        (re.compile(r"\bcurl\s+.*-[a-zA-Z]*X\s+POST\b"), "curl -X POST"),
        (re.compile(r"\bcurl\s+.*--data\b"), "curl --data"),
        (re.compile(r"\bcurl\s+.*-d\s"), "curl -d"),
        (re.compile(r"\brequests\.post\b"), "requests.post"),
        (re.compile(r"\burllib\.request\.urlopen\b.*data\s*="), "urllib POST"),
    ],
    "credential_access": [
        (re.compile(r"~/\.ssh/"), "~/.ssh/ access"),
        (re.compile(r"~/\.aws/"), "~/.aws/ access"),
        (re.compile(r"~/\.gnupg/"), "~/.gnupg/ access"),
    ],
    "obfuscation": [
        (re.compile(r"\bbase64\s+.*-d\s*\|\s*bash\b"), "base64 -d | bash"),
        (re.compile(r"\beval\s*\(\s*base64\.b64decode\b"), "eval(base64.b64decode"),
        (re.compile(r"\bexec\s*\(\s*compile\b"), "exec(compile"),
    ],
    "secret": [
        (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"), "private key"),
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
        (re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"), "GitHub personal access token"),
        (re.compile(r"\bsk-[0-9a-zA-Z]{20,}\b"), "secret key token (sk-)"),
        (re.compile(r"""(?:api_key|apikey|api_secret)\s*[=:]\s*['"][^'"]{8,}['"]"""), "hardcoded API key"),
    ],
}

# Patterns for detecting credential-searching Grep queries.
_CREDENTIAL_SEARCH_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bpassword\b", re.IGNORECASE),
    re.compile(r"\bsecret\b", re.IGNORECASE),
    re.compile(r"\btoken\b", re.IGNORECASE),
    re.compile(r"\bapi_key\b", re.IGNORECASE),
    re.compile(r"\bprivate_key\b", re.IGNORECASE),
    re.compile(r"\bAWS_SECRET"),
    re.compile(r"BEGIN.*PRIVATE", re.IGNORECASE),
]

# Snapshot of hardcoded defaults for reset (testing).
_CONTENT_PATTERNS_DEFAULTS: dict[str, list[tuple[re.Pattern, str]]] = {
    cat: list(patterns) for cat, patterns in _CONTENT_PATTERNS.items()
}
_CREDENTIAL_SEARCH_DEFAULTS: list[re.Pattern] = list(_CREDENTIAL_SEARCH_PATTERNS)

# Merge state
_content_patterns_merged: bool = False
_content_policies: dict[str, str] = {}  # category → effective policy after merge


def _ensure_content_patterns_merged() -> None:
    """Lazy one-time merge of config into content patterns and policies."""
    global _content_patterns_merged
    if _content_patterns_merged:
        return
    _content_patterns_merged = True
    try:
        from nah.config import get_config
        cfg = get_config()

        # Profile: none clears all built-in patterns
        if cfg.profile == "none":
            _CONTENT_PATTERNS.clear()
            _CREDENTIAL_SEARCH_PATTERNS.clear()

        # --- Content pattern suppression (by description string) ---
        if cfg.content_patterns_suppress:
            suppress_set = {str(s) for s in cfg.content_patterns_suppress}
            matched = set()
            for cat in list(_CONTENT_PATTERNS):
                before = list(_CONTENT_PATTERNS[cat])
                _CONTENT_PATTERNS[cat] = [
                    (r, d) for r, d in before if d not in suppress_set
                ]
                matched.update(d for _, d in before if d in suppress_set)
            unmatched = suppress_set - matched
            for desc in sorted(unmatched):
                sys.stderr.write(
                    f"nah: unmatched content_patterns.suppress: '{desc}'\n"
                )

        # --- Add custom content patterns ---
        for entry in cfg.content_patterns_add:
            if not isinstance(entry, dict):
                continue
            category = str(entry.get("category", "")).strip()
            pattern = str(entry.get("pattern", "")).strip()
            description = str(entry.get("description", "")).strip()
            if not category or not pattern or not description:
                sys.stderr.write(
                    "nah: content_patterns.add: missing category/pattern/description, skipping\n"
                )
                continue
            try:
                compiled = re.compile(pattern)
            except re.error as e:
                sys.stderr.write(
                    f"nah: invalid regex in content_patterns.add: '{pattern}' — {e}\n"
                )
                continue
            if category not in _CONTENT_PATTERNS:
                _CONTENT_PATTERNS[category] = []
            _CONTENT_PATTERNS[category].append((compiled, description))

        # --- Build effective policies map ---
        _content_policies.clear()
        for cat in _CONTENT_PATTERNS:
            _content_policies[cat] = "ask"  # default for all categories
        for cat, policy in cfg.content_policies.items():
            if policy in ("ask", "block"):
                _content_policies[cat] = policy

        # --- Credential pattern suppression (by regex .pattern string) ---
        if cfg.credential_patterns_suppress:
            suppress_regexes = {str(s) for s in cfg.credential_patterns_suppress}
            matched_cred = set()
            original = list(_CREDENTIAL_SEARCH_PATTERNS)
            _CREDENTIAL_SEARCH_PATTERNS.clear()
            for rx in original:
                if rx.pattern in suppress_regexes:
                    matched_cred.add(rx.pattern)
                else:
                    _CREDENTIAL_SEARCH_PATTERNS.append(rx)
            unmatched_cred = suppress_regexes - matched_cred
            for pat in sorted(unmatched_cred):
                sys.stderr.write(
                    f"nah: unmatched credential_patterns.suppress: '{pat}'\n"
                )

        # --- Add custom credential patterns ---
        for entry in cfg.credential_patterns_add:
            pat = str(entry).strip()
            if not pat:
                continue
            try:
                compiled = re.compile(pat)
            except re.error as e:
                sys.stderr.write(
                    f"nah: invalid regex in credential_patterns.add: '{pat}' — {e}\n"
                )
                continue
            _CREDENTIAL_SEARCH_PATTERNS.append(compiled)

    except Exception as exc:
        sys.stderr.write(f"nah: config: content_patterns: {exc}\n")


def reset_content_patterns() -> None:
    """Restore defaults and clear merge flag (for testing)."""
    global _content_patterns_merged, _truncation_logged
    _content_patterns_merged = False
    _truncation_logged = False
    _CONTENT_PATTERNS.clear()
    for cat, patterns in _CONTENT_PATTERNS_DEFAULTS.items():
        _CONTENT_PATTERNS[cat] = list(patterns)
    _CREDENTIAL_SEARCH_PATTERNS.clear()
    _CREDENTIAL_SEARCH_PATTERNS.extend(_CREDENTIAL_SEARCH_DEFAULTS)
    _content_policies.clear()


def scan_content(content: str) -> list[ContentMatch]:
    """Scan content for dangerous patterns. Returns matches (empty = safe)."""
    global _truncation_logged
    _ensure_content_patterns_merged()
    if not content:
        return []

    if len(content) > _MAX_SCAN_CHARS:
        if not _truncation_logged:
            sys.stderr.write(
                f"nah: content truncated from {len(content)} to "
                f"{_MAX_SCAN_CHARS} characters for scanning\n"
            )
            _truncation_logged = True
        content = content[:_MAX_SCAN_CHARS]

    matches = []
    for category, patterns in _CONTENT_PATTERNS.items():
        policy = _content_policies.get(category, "ask")
        for regex, desc in patterns:
            m = regex.search(content)
            if m:
                matches.append(ContentMatch(
                    category=category,
                    pattern_desc=desc,
                    matched_text=m.group()[:80],
                    policy=policy,
                ))
    return matches


def format_content_message(tool_name: str, matches: list[ContentMatch]) -> str:
    """Format content matches into a human-readable ask message."""
    if not matches:
        return ""

    categories = sorted({m.category for m in matches})
    details = ", ".join(m.pattern_desc for m in matches)
    return f"{tool_name} content inspection [{', '.join(categories)}]: {details}"


def is_credential_search(pattern: str) -> bool:
    """Check if a Grep pattern looks like a credential search."""
    _ensure_content_patterns_merged()
    if not pattern:
        return False
    return any(regex.search(pattern) for regex in _CREDENTIAL_SEARCH_PATTERNS)


def get_secret_patterns() -> list[tuple[re.Pattern, str]]:
    """Return compiled secret-category patterns for external use (e.g., LLM redaction)."""
    _ensure_content_patterns_merged()
    return list(_CONTENT_PATTERNS.get("secret", []))
