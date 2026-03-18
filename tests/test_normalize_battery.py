"""Test battery for _normalize_interpreter — tricky and complex scenarios.

Tests the prefix-list + suffix-match normalizer against edge cases
found during deep analysis (modeep, 2026-03-18).
"""

import pytest

from nah.taxonomy import _normalize_interpreter


# ── Battery 1: Core versioned interpreters ─────────────────────────────

class TestCoreVersioned:
    """The primary use case — versioned interpreters in the wild."""

    @pytest.mark.parametrize("inp, expected", [
        # Python — most common case
        ("python3.12", "python3"),
        ("python3.11", "python3"),
        ("python3.10", "python3"),
        ("python3.9", "python3"),
        ("python3.13", "python3"),
        ("python3.14", "python3"),
        # Python without dot
        ("python312", "python3"),
        ("python311", "python3"),
        # Python multi-level version
        ("python3.12.1", "python3"),
        ("python3.12.1.2", "python3"),
        # Python 2 legacy
        ("python2.7", "python"),
        ("python27", "python"),
        # Node
        ("node22", "node"),
        ("node20", "node"),
        ("node18", "node"),
        ("node16", "node"),
        ("node20.11", "node"),
        ("node20.11.1", "node"),
        # Ruby
        ("ruby3.2", "ruby"),
        ("ruby3.3", "ruby"),
        ("ruby32", "ruby"),
        # Perl
        ("perl5.38", "perl"),
        ("perl5.36", "perl"),
        ("perl536", "perl"),
        # PHP
        ("php8.1", "php"),
        ("php8.2", "php"),
        ("php8.3", "php"),
        ("php82", "php"),
        # Deno / Bun
        ("deno1.40", "deno"),
        ("deno2.0", "deno"),
        ("bun1.0", "bun"),
        ("bun1.1", "bun"),
        # Pip
        ("pip3.12", "pip3"),
        ("pip3.11", "pip3"),
        ("pip312", "pip3"),
        ("pip22.3", "pip"),
        # Shells
        ("bash5.2", "bash"),
        ("bash5.1", "bash"),
        ("zsh5.9", "zsh"),
        ("zsh5.8", "zsh"),
        ("dash0.5", "dash"),
        ("fish3.7", "fish"),
        ("pwsh7.4", "pwsh"),
        ("pwsh7", "pwsh"),
    ])
    def test_versioned_normalizes(self, inp, expected):
        assert _normalize_interpreter(inp) == expected


# ── Battery 2: Canonical names must NOT change ─────────────────────────

class TestCanonicalUnchanged:
    """Canonical names that should pass through untouched."""

    @pytest.mark.parametrize("name", [
        "python", "python3", "pip", "pip3",
        "node", "ruby", "perl", "php", "deno", "bun",
        "bash", "sh", "dash", "zsh", "fish", "pwsh",
        # These are in lookup tables and must stay as-is
        "eval", "env", "tsx",
    ])
    def test_canonical_unchanged(self, name):
        assert _normalize_interpreter(name) == name


# ── Battery 3: Variant builds — must fail-closed ──────────────────────

class TestVariantBuilds:
    """Debug, free-threading, and other variant builds must NOT normalize.
    They should fall through to unknown → ask."""

    @pytest.mark.parametrize("name", [
        # Free-threading (PEP 703)
        "python3.13t",
        "python3.14t",
        # Debug builds
        "python3.12d",
        "python3.12-dbg",
        "python3.11-dbg",
        # Combined
        "python3.13td",
        # Hypothetical future suffixes
        "python3.14rc1",
        "python3.14a1",
        "python3.14b2",
        "node22-nightly",
        "node22.0.0-rc.1",
    ])
    def test_variant_unchanged(self, name):
        assert _normalize_interpreter(name) == name


# ── Battery 4: Alternative implementations — excluded ─────────────────

class TestAltImplementations:
    """Alternative Python/JS/etc implementations should NOT normalize."""

    @pytest.mark.parametrize("name", [
        "pypy3.10",
        "pypy3",
        "pypy",
        "cpython3.12",
        "cpython",
        "micropython",
        "graalpy",
        "jython",
        "ironpython",
        # Platform-specific
        "platform-python",
        "python.exe",  # Windows, but basename would strip path
    ])
    def test_alt_impl_unchanged(self, name):
        assert _normalize_interpreter(name) == name


# ── Battery 5: Non-interpreters that could false-positive ─────────────

class TestFalsePositiveResistance:
    """Commands that end in digits or contain interpreter substrings
    but must NOT be normalized."""

    @pytest.mark.parametrize("name", [
        # Common tools ending in digits
        "gcc12", "g++12", "clang16",
        "sha256sum", "sha512sum", "md5sum",
        "base32", "base64",
        "x264", "x265",
        "lz4", "bzip2", "gzip",
        "p7zip", "7zip", "7z",
        "mp3gain", "mp3info",
        "sqlite3",
        "openssl3",
        # Tools containing interpreter names as substrings
        "nodemon", "nodeenv",
        "perlbrew",
        "phpunit", "phpstan",
        "rubocop",
        "bundler",  # starts with "bun" but has non-digit suffix
        "fisherman",
        "dashboard",  # contains "dash"
        # Single-char or empty
        "", "a", "1",
        # Docker/container commands
        "docker", "podman",
        # Build tools
        "make", "cmake", "gmake",
        "gradle", "maven",
    ])
    def test_not_normalized(self, name):
        assert _normalize_interpreter(name) == name


# ── Battery 6: The regex backtracking bug (regression) ────────────────

class TestNoBacktrackingBug:
    """Verify the old regex bug doesn't resurface.
    The broken regex: r'^(python3?|...)' caused python3.12 → python.
    These tests catch that specific failure mode."""

    def test_python3_12_not_python(self):
        """python3.12 must normalize to python3, NOT python."""
        result = _normalize_interpreter("python3.12")
        assert result == "python3"
        assert result != "python"  # the bug

    def test_python3_stays_python3(self):
        """python3 must stay python3, NOT normalize to python."""
        result = _normalize_interpreter("python3")
        assert result == "python3"
        assert result != "python"  # the bug

    def test_pip3_12_not_pip(self):
        """pip3.12 must normalize to pip3, NOT pip."""
        result = _normalize_interpreter("pip3.12")
        assert result == "pip3"
        assert result != "pip"  # the bug

    def test_pip3_stays_pip3(self):
        """pip3 must stay pip3, NOT normalize to pip."""
        result = _normalize_interpreter("pip3")
        assert result == "pip3"
        assert result != "pip"  # the bug


# ── Battery 7: Prefix ordering correctness ────────────────────────────

class TestPrefixOrdering:
    """Verify longer prefixes are checked before shorter ones."""

    def test_python3_before_python(self):
        # python3.12 should match python3 prefix, not fall to python
        assert _normalize_interpreter("python3.12") == "python3"

    def test_pip3_before_pip(self):
        assert _normalize_interpreter("pip3.12") == "pip3"

    def test_dash_before_sh(self):
        # dash0.5 should match dash, not sh (even though sh is a prefix of... wait, no)
        # dash starts with 'd', sh starts with 's' — no overlap
        # but test anyway for ordering confidence
        assert _normalize_interpreter("dash0.5") == "dash"

    def test_sh_only_matches_sh(self):
        # sh5 should match sh, not bash or dash
        assert _normalize_interpreter("sh5") == "sh"
        assert _normalize_interpreter("sh5.2") == "sh"


# ── Battery 8: Version suffix edge cases ──────────────────────────────

class TestVersionSuffixEdgeCases:
    """Boundary conditions for the version suffix pattern."""

    @pytest.mark.parametrize("inp, expected", [
        # Trailing dot — NOT a valid version
        ("python3.", "python3."),
        ("node.", "node."),
        # Leading dot versions (e.g. python3.12 → suffix is .12)
        ("python3.1", "python3"),
        ("python3.0", "python3"),
        # Single digit version
        ("node8", "node"),
        ("php5", "php"),
        ("perl5", "perl"),
        # Very long version
        ("python3.12.1.2.3.4.5", "python3"),
        # Zero version
        ("node0", "node"),
        ("python0", "python"),
        # Large version numbers
        ("node999", "node"),
        ("python3.999", "python3"),
    ])
    def test_suffix_edge_case(self, inp, expected):
        assert _normalize_interpreter(inp) == expected


# ── Battery 9: Idempotency (double normalization) ─────────────────────

class TestIdempotency:
    """Normalizing twice must produce the same result as once."""

    @pytest.mark.parametrize("inp", [
        "python3.12", "node22", "bash5.2", "pip3.12",
        "python3", "python", "node", "bash",
        "gcc12", "pypy3.10", "python3.13t",
    ])
    def test_double_normalize(self, inp):
        once = _normalize_interpreter(inp)
        twice = _normalize_interpreter(once)
        assert once == twice


# ── Battery 10: Composition with basename ─────────────────────────────

class TestWithBasename:
    """Simulate the real pipeline: basename then normalize."""

    import os

    @pytest.mark.parametrize("path, expected", [
        ("/usr/bin/python3.12", "python3"),
        ("/opt/miniconda3/envs/py312/bin/python3.12", "python3"),
        ("/usr/local/bin/node22", "node"),
        ("/home/user/.local/bin/pip3.12", "pip3"),
        ("/usr/bin/bash", "bash"),
        ("/usr/bin/python3", "python3"),
        # Basename of a plain name is the name itself
        ("python3.12", "python3"),
    ])
    def test_basename_then_normalize(self, path, expected):
        import os
        base = os.path.basename(path)
        assert _normalize_interpreter(base) == expected


# ── Battery 11: go1.22 — documented gap ──────────────────────────────

class TestDocumentedGaps:
    """These are known gaps documented in the design.
    They should NOT normalize (fail-closed to unknown → ask)."""

    @pytest.mark.parametrize("name", [
        "go1.22",
        "go1.21",
        "rustc1.75",
        "java17",
        "java21",
    ])
    def test_documented_gap_unchanged(self, name):
        assert _normalize_interpreter(name) == name
