//! Embedded, bounded documentation for progressive CLI disclosure.

pub(crate) const GUARDS_TOPIC: &str = "guards";
const GUARDS_SUMMARY: &str = "Inspect built-in behavior, examples, and live guard status.";

// `nah docs guards <guard/rule>` prints one rule's section of the generated
// `docs/guard-reference.md`, and `nah docs guards <guard>` one guard's section
// with its rules' summaries, so the budget applies per section. A rule made
// of several parts carries each part's examples and limits.
const GUARD_SECTION_MAX_BYTES: usize = 6_144;

struct Topic {
    name: &'static str,
    summary: &'static str,
    contents: &'static str,
    // Byte ceilings are deterministic across models; exact token counts are not.
    max_bytes: usize,
}

macro_rules! topic {
    ($name:literal, $summary:literal, $path:literal, $max_bytes:literal) => {
        Topic {
            name: $name,
            summary: $summary,
            contents: include_str!($path),
            max_bytes: $max_bytes,
        }
    };
}

const TOPICS: &[Topic] = &[
    topic!(
        "start",
        "Install nah and guard the first coding agent.",
        "../../../docs/start.md",
        2_560
    ),
    topic!(
        "windows",
        "Install, upgrade, or remove nah on Windows.",
        "../../../docs/windows.md",
        3_072
    ),
    topic!(
        "concepts",
        "Understand verdicts and guards.",
        "../../../docs/concepts.md",
        7_168
    ),
    topic!(
        "cli",
        "See the human and machine command surfaces.",
        "../../../docs/cli.md",
        4_864
    ),
    topic!(
        "configuration",
        "Configure guards and rules.",
        "../../../docs/configuration.md",
        7_552
    ),
    topic!(
        "runtimes",
        "Choose and install a supported agent integration.",
        "../../../docs/runtimes.md",
        6_144
    ),
    topic!(
        "runtime-antigravity",
        "Install nah for Google Antigravity.",
        "../../../docs/runtimes/antigravity.md",
        5_120
    ),
    topic!(
        "runtime-claude",
        "Install nah for Claude Code.",
        "../../../docs/runtimes/claude.md",
        5_120
    ),
    topic!(
        "runtime-codex",
        "Install nah for Codex.",
        "../../../docs/runtimes/codex.md",
        5_120
    ),
    topic!(
        "runtime-cursor",
        "Install nah for Cursor.",
        "../../../docs/runtimes/cursor.md",
        4_096
    ),
    topic!(
        "runtime-hermes",
        "Install nah for Hermes.",
        "../../../docs/runtimes/hermes.md",
        6_144
    ),
    topic!(
        "runtime-openclaw",
        "Install nah for OpenClaw.",
        "../../../docs/runtimes/openclaw.md",
        5_120
    ),
    topic!(
        "runtime-opencode",
        "Install nah for OpenCode.",
        "../../../docs/runtimes/opencode.md",
        5_120
    ),
    topic!(
        "runtime-pi",
        "Install nah for Pi.",
        "../../../docs/runtimes/pi.md",
        4_096
    ),
    topic!(
        "security",
        "Review nah's enforcement and trust boundaries.",
        "../../../docs/security.md",
        8_384
    ),
    topic!(
        "threat-model",
        "Understand nah's adversary, assumptions, and companion controls.",
        "../../../docs/threat-model.md",
        6_144
    ),
    topic!(
        "architecture",
        "Navigate the codebase by responsibility.",
        "../../../docs/architecture.md",
        6_656
    ),
];

pub(crate) fn render(name: Option<&str>) -> Result<String, String> {
    let Some(name) = name else {
        let mut topics = TOPICS
            .iter()
            .filter(|topic| !topic.name.starts_with("runtime-"))
            .map(|topic| (topic.name, topic.summary))
            .collect::<Vec<_>>();
        let insert_at = topics
            .iter()
            .position(|(name, _)| *name == "runtimes")
            .unwrap_or(topics.len());
        topics.insert(insert_at, (GUARDS_TOPIC, GUARDS_SUMMARY));
        let width = topics.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
        return Ok(topics
            .into_iter()
            .map(|(name, summary)| format!("{name:<width$}  {summary}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n");
    };
    TOPICS
        .iter()
        .find(|topic| topic.name == name)
        .map(|topic| {
            debug_assert!(topic.contents.len() <= topic.max_bytes);
            topic.contents.to_owned()
        })
        .ok_or_else(|| format!("documentation topic not found: {name}; run `nah docs`"))
}

/// Renders one guard's reference section with its rules' summaries, or one
/// shipped rule's section.
pub(crate) fn render_guard(name: &str) -> Result<String, String> {
    if let Some(guard) = nah_proto::ctx::Guard::from_name(name) {
        let section = guard_overview(guard);
        debug_assert!(section.len() <= GUARD_SECTION_MAX_BYTES);
        return Ok(section);
    }
    if !crate::catalog::rule_ids().contains(&name) {
        return Err(crate::catalog::legacy_name_error(name).unwrap_or_else(|| {
            format!("built-in guard or rule not found: {name}; run `nah docs guards`")
        }));
    }
    let section = crate::guard_knowledge::reference_section(name);
    debug_assert!(section.len() <= GUARD_SECTION_MAX_BYTES);
    Ok(format!("# {}\n", section.trim_end()))
}

fn guard_overview(guard: nah_proto::ctx::Guard) -> String {
    let mut overview = format!("# {}", crate::guard_knowledge::guard_section(guard));
    let rules = crate::catalog::rules_of(guard)
        .map(|rule| {
            let knowledge = crate::guard_knowledge::knowledge_for_rule(rule);
            let strict_adds = knowledge
                .strict_adds
                .as_deref()
                .map(|text| format!(" {}", text.trim()))
                .unwrap_or_default();
            format!(
                "- `{rule}` (applies at {}): {}{strict_adds}\n",
                crate::commands::applies_at(rule),
                knowledge.summary.trim(),
            )
        })
        .collect::<String>();
    if !rules.is_empty() {
        overview.push_str(&format!(
            "\nRules:\n\n{rules}\nRun `nah docs guards <guard/rule>` for one rule's examples and limits.\n"
        ));
    }
    overview
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum;

    use super::*;
    use crate::runtime::Runtime;

    #[test]
    fn docs_registry_is_valid() {
        for topic in TOPICS {
            assert!(
                topic.contents.len() <= topic.max_bytes,
                "docs topic {:?} is {} bytes; budget is {}",
                topic.name,
                topic.contents.len(),
                topic.max_bytes
            );
        }
        let mut names = TOPICS.iter().map(|topic| topic.name).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TOPICS.len());
        for runtime in Runtime::value_variants() {
            let name = runtime.docs_topic();
            assert!(
                TOPICS.iter().any(|topic| topic.name == name),
                "missing docs for {}",
                runtime.cli_name()
            );
        }
        assert!(render(Some("missing-topic")).is_err());
        assert!(render(Some("../start")).is_err());

        for name in crate::catalog::rule_ids() {
            let section = crate::guard_knowledge::reference_section(name);
            assert!(
                section.len() <= GUARD_SECTION_MAX_BYTES,
                "rule reference for {name} is {} bytes; budget is {GUARD_SECTION_MAX_BYTES}",
                section.len()
            );
        }
        for guard in nah_proto::ctx::Guard::ALL {
            let section = guard_overview(guard);
            assert!(
                section.len() <= GUARD_SECTION_MAX_BYTES,
                "guard overview for {} is {} bytes; budget is {GUARD_SECTION_MAX_BYTES}",
                guard.name(),
                section.len()
            );
        }
        assert!(render_guard("missing-guard").is_err());
    }
}
