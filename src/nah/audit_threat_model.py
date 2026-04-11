"""Audit threat-model coverage across the pytest suite.

Walks `pytest --collect-only` from the current working directory, applies a
categorization ruleset derived from the private threat-model document, and
emits a per-category report. Heuristic by design — the categorization is a
measurement, not a contract. The ground truth is the pytest suite itself.

Invoke via `nah audit-threat-model [--format markdown|json|summary]`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


CATEGORY_ORDER = (
    "rce",
    "credential_exfil",
    "secret_leak",
    "git_history",
    "shell_redirect",
    "shell_obfuscation",
    "wrapper_evasion",
    "sensitive_path",
    "project_boundary",
    "package_escalation",
    "container_destructive",
    "self_protection",
)


@dataclass(frozen=True)
class Rule:
    category: str
    rationale: str
    match_any: tuple[str, ...]

    def matching_patterns(self, node_id: str) -> list[str]:
        return [pattern for pattern in self.match_any if pattern in node_id]


RULES = (
    Rule(
        category="rce",
        rationale="Shell composition, wrapper unwrapping, substitution, heredoc, and script-exec coverage.",
        match_any=(
            "tests/test_bash.py::TestComposition::",
            "tests/test_bash.py::TestUnwrapping::",
            "tests/test_bash.py::TestProcessSubstitutionInspection::",
            "tests/test_bash.py::TestCommandSubstitutionInspection::",
            "tests/test_bash.py::TestHeredocInterpreter::",
            "tests/test_fd079_script_exec.py::",
        ),
    ),
    Rule(
        category="credential_exfil",
        rationale="Sensitive-read and credential-detection coverage across content and path guards.",
        match_any=(
            "tests/test_bash.py::TestComposition::",
            "tests/test_content.py::TestIsCredentialSearch::",
            "tests/test_paths.py::TestIsSensitive::",
            "tests/test_paths.py::TestCheckPath::",
        ),
    ),
    Rule(
        category="secret_leak",
        rationale="Secret-pattern inspection for writes, script execution, and write-LLM veto paths.",
        match_any=(
            "tests/test_content.py::TestScanContent::",
            "tests/test_fd079_script_exec.py::TestVetoGate::",
            "tests/test_fd079_script_exec.py::TestReadScriptForLlm::",
            "tests/test_fd080_write_llm.py::",
        ),
    ),
    Rule(
        category="git_history",
        rationale="Git rewrite and destructive-regression coverage in bash classification, taxonomy, and hints.",
        match_any=(
            "tests/test_bash.py::TestFD017Regressions::",
            "tests/test_bash.py::TestFD017MoreGitRegressions::",
            "tests/test_bash.py::TestFD017TagRegressions::",
            "tests/test_taxonomy.py::TestClassifyGit::",
            "tests/test_taxonomy.py::TestGitSubcommands::",
            "tests/test_hint_battery.py::TestGitMaintenanceHints::",
        ),
    ),
    Rule(
        category="shell_redirect",
        rationale="Redirect parsing, redirected content scanning, and redirect-specific hint coverage.",
        match_any=(
            "tests/test_bash.py::TestDecomposition::",
            "tests/test_bash.py::TestFD095RegexPipeParsing::",
            "tests/test_content.py::TestScanContent::",
            "tests/test_hint_battery.py::TestRedirectOutsideProject::",
            "tests/test_hint_battery.py::TestRedirectInsideProject::",
            "tests/test_hint_battery.py::TestMoreRedirectBroadHints::",
            "tests/test_hint_battery.py::TestTeeHints::",
            "tests/test_hint_battery.py::TestTeeLocalFile::",
            "tests/test_hint_battery.py::TestHereString::",
            "tests/test_taxonomy.py::TestFD019FilesystemWrite::",
        ),
    ),
    Rule(
        category="shell_obfuscation",
        rationale="Process substitution, command substitution, and content-layer obfuscation coverage.",
        match_any=(
            "tests/test_bash.py::TestProcessSubstitutionInspection::",
            "tests/test_bash.py::TestCommandSubstitutionInspection::",
            "tests/test_content.py::TestContentPatternSuppression::",
            "tests/test_content.py::TestContentPatternAdd::",
        ),
    ),
    Rule(
        category="wrapper_evasion",
        rationale="Passthrough wrappers and command/xargs unwrapping coverage.",
        match_any=(
            "tests/test_bash.py::TestPassthroughWrappers::",
            "tests/test_bash.py::TestUnwrapping::",
            "tests/test_bash.py::TestCommandUnwrap::",
            "tests/test_bash.py::TestXargsUnwrap::",
        ),
    ),
    Rule(
        category="sensitive_path",
        rationale="Sensitive path detection, symlink handling, CLI path checks, and read taxonomy coverage.",
        match_any=(
            "tests/test_paths.py::TestIsSensitive::",
            "tests/test_paths.py::TestCheckPath::",
            "tests/test_paths.py::TestSymlinkResolution::",
            "tests/test_paths.py::TestSensitivePathConfigOverride::",
            "tests/test_paths.py::TestSensitiveBasenamesConfigurable::",
            "tests/test_bash.py::TestPathExtraction::",
            "tests/test_cli.py::TestCmdTest::",
            "tests/test_taxonomy.py::TestFD019FilesystemRead::",
        ),
    ),
    Rule(
        category="project_boundary",
        rationale="Project-root resolution and inside/outside-project context coverage.",
        match_any=(
            "tests/test_paths.py::TestProjectRoot::",
            "tests/test_paths.py::TestTrustedPathNoGitRoot::",
            "tests/test_bash.py::TestContextResolverFallback::",
            "tests/test_fd079_script_exec.py::TestContextResolver::",
            "tests/test_hint_battery.py::TestOutsideProjectHints::",
            "tests/test_hint_battery.py::TestAbsolutePathCommands::",
        ),
    ),
    Rule(
        category="package_escalation",
        rationale="Package-manager install and external-source escalation coverage.",
        match_any=(
            "tests/test_bash.py::TestAcceptanceCriteria::test_package_manager_create_scaffolds_allow",
            "tests/test_hint_battery.py::TestPackageManagerHints::",
            "tests/test_taxonomy.py::TestFD019PackageInstall::",
            "tests/test_taxonomy.py::TestFD019GlobalInstall::",
            "tests/test_taxonomy.py::TestPackageEscalationCoverage::",
        ),
    ),
    Rule(
        category="container_destructive",
        rationale="Container destruction coverage from end-to-end bash tests and full taxonomy sweeps.",
        match_any=(
            "tests/test_bash.py::TestNewActionTypes::test_docker_system_prune_ask",
            "tests/test_bash.py::TestNewActionTypes::test_docker_rm_ask",
            "tests/test_bash.py::TestContainerDestructiveCoverage::",
            "tests/test_taxonomy.py::TestClassifyTokens::test_container_destructive",
        ),
    ),
    Rule(
        category="self_protection",
        rationale="nah self-protection around hooks, config, settings, and robustness paths.",
        match_any=(
            "tests/test_paths.py::TestIsHookPath::",
            "tests/test_paths.py::TestIsNahConfigPath::",
            "tests/test_paths.py::TestConfigSelfProtection::",
            "tests/test_paths.py::TestSettingsJsonProtection::",
            "tests/test_cli.py::TestWriteHookScriptOptimization::",
            "tests/test_fd080_write_llm.py::",
            "tests/test_hook_robustness.py::",
        ),
    ),
)


def _run_collect(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stderr.strip() or exc.stdout.strip()
        raise RuntimeError(f"pytest collection failed: {output}") from exc


def collect_node_ids() -> list[str]:
    command = ["pytest", "--collect-only", "-q", "--no-header"]
    try:
        proc = _run_collect(command)
    except FileNotFoundError:
        # Some runners expose pytest only as a module entry point. Falling back
        # keeps the audit usable without changing which test nodes are collected.
        proc = _run_collect([sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-header"])

    node_ids = [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    ]
    if not node_ids:
        raise RuntimeError("pytest collection returned no test node IDs")
    return node_ids


def audit_node_ids(node_ids: list[str]) -> dict[str, Any]:
    categories: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for rule in RULES:
        categories[rule.category] = {
            "count": 0,
            "rationale": rule.rationale,
            "patterns": list(rule.match_any),
            "tests": [],
        }

    overlaps: list[dict[str, Any]] = []
    unmatched: list[str] = []
    matched_total = 0

    for node_id in node_ids:
        matched_categories: list[str] = []
        matched_patterns: dict[str, list[str]] = {}
        for rule in RULES:
            patterns = rule.matching_patterns(node_id)
            if not patterns:
                continue
            categories[rule.category]["count"] += 1
            categories[rule.category]["tests"].append(
                {
                    "node_id": node_id,
                    "matched_patterns": patterns,
                }
            )
            matched_categories.append(rule.category)
            matched_patterns[rule.category] = patterns

        if matched_categories:
            matched_total += 1
            if len(matched_categories) > 1:
                overlaps.append(
                    {
                        "node_id": node_id,
                        "categories": matched_categories,
                        "matched_patterns": matched_patterns,
                    }
                )
            continue

        unmatched.append(node_id)

    return {
        "collected": len(node_ids),
        "matched": matched_total,
        "unmatched_count": len(unmatched),
        "categories": categories,
        "overlaps": overlaps,
        "unmatched": unmatched,
    }


def render_summary(report: dict[str, Any]) -> str:
    return "\n".join(
        f"{category}: {report['categories'][category]['count']}"
        for category in CATEGORY_ORDER
    )


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Threat model coverage audit",
        "",
        f"- Collected tests: {report['collected']}",
        f"- Matched tests: {report['matched']}",
        f"- Unmatched tests: {report['unmatched_count']}",
        f"- Multi-category overlaps: {len(report['overlaps'])}",
        "",
        "## Summary",
        "",
        "| Category | Count | Rule |",
        "| --- | ---: | --- |",
    ]

    for category in CATEGORY_ORDER:
        entry = report["categories"][category]
        lines.append(f"| `{category}` | {entry['count']} | {entry['rationale']} |")

    for category in CATEGORY_ORDER:
        entry = report["categories"][category]
        lines.extend(
            [
                "",
                f"## {category}",
                "",
                f"Count: {entry['count']}",
                "",
                f"Rule: {entry['rationale']}",
                "",
                "Patterns:",
            ]
        )
        for pattern in entry["patterns"]:
            lines.append(f"- `{pattern}`")

        lines.extend(
            [
                "",
                "<details>",
                f"<summary>Matched tests ({entry['count']})</summary>",
                "",
            ]
        )
        for match in entry["tests"]:
            via = ", ".join(f"`{pattern}`" for pattern in match["matched_patterns"])
            lines.append(f"- `{match['node_id']}` via {via}")
        lines.extend(["", "</details>"])

    lines.extend(
        [
            "",
            "## Overlaps",
            "",
            f"Count: {len(report['overlaps'])}",
            "",
            "<details>",
            f"<summary>Multi-category tests ({len(report['overlaps'])})</summary>",
            "",
        ]
    )
    for overlap in report["overlaps"]:
        cats = ", ".join(f"`{category}`" for category in overlap["categories"])
        lines.append(f"- `{overlap['node_id']}` -> {cats}")
    lines.extend(["", "</details>"])

    lines.extend(
        [
            "",
            "## No rule matched",
            "",
            f"Count: {report['unmatched_count']}",
            "",
            "<details>",
            f"<summary>Unmatched tests ({report['unmatched_count']})</summary>",
            "",
        ]
    )
    for node_id in report["unmatched"]:
        lines.append(f"- `{node_id}`")
    lines.extend(["", "</details>"])
    return "\n".join(lines)


def run(format_name: str) -> int:
    """Entry point called by `nah audit-threat-model`."""
    if tuple(rule.category for rule in RULES) != CATEGORY_ORDER:
        raise RuntimeError("RULES category order drifted from CATEGORY_ORDER")

    report = audit_node_ids(collect_node_ids())

    if format_name == "summary":
        print(render_summary(report))
    elif format_name == "json":
        print(render_json(report))
    else:
        print(render_markdown(report))
    return 0
