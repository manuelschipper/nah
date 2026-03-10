"""Content inspection — regex-scan Write/Edit content for dangerous patterns."""

import re

from dataclasses import dataclass


@dataclass
class ContentMatch:
    category: str
    pattern_desc: str
    matched_text: str


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
    re.compile(r"\bAWS_SECRET\b"),
    re.compile(r"BEGIN.*PRIVATE", re.IGNORECASE),
]


def scan_content(content: str) -> list[ContentMatch]:
    """Scan content for dangerous patterns. Returns matches (empty = safe)."""
    if not content:
        return []

    matches = []
    for category, patterns in _CONTENT_PATTERNS.items():
        for regex, desc in patterns:
            m = regex.search(content)
            if m:
                matches.append(ContentMatch(
                    category=category,
                    pattern_desc=desc,
                    matched_text=m.group()[:80],
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
    if not pattern:
        return False
    return any(regex.search(pattern) for regex in _CREDENTIAL_SEARCH_PATTERNS)
