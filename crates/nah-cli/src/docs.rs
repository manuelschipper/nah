//! Embedded, bounded documentation for progressive CLI disclosure.

pub(crate) const GUARDS_TOPIC: &str = "guards";
const GUARDS_SUMMARY: &str = "Inspect built-in behavior, examples, and live guard status.";

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
        2_048
    ),
    topic!(
        "concepts",
        "Understand verdicts, guards, and trust.",
        "../../../docs/concepts.md",
        4_096
    ),
    topic!(
        "cli",
        "See the human and machine command surfaces.",
        "../../../docs/cli.md",
        4_096
    ),
    topic!(
        "configuration",
        "Configure guards and trusted projects.",
        "../../../docs/configuration.md",
        5_632
    ),
    topic!(
        "extending",
        "Build one-shot guard programs.",
        "../../../docs/extensions.md",
        12_288
    ),
    topic!(
        "runtimes",
        "Choose and install a supported agent integration.",
        "../../../docs/runtimes.md",
        3_072
    ),
    topic!(
        "runtime-amp",
        "Install nah for Amp.",
        "../../../docs/runtimes/amp.md",
        4_096
    ),
    topic!(
        "runtime-antigravity",
        "Install nah for Google Antigravity.",
        "../../../docs/runtimes/antigravity.md",
        4_096
    ),
    topic!(
        "runtime-claude",
        "Install nah for Claude Code.",
        "../../../docs/runtimes/claude.md",
        4_096
    ),
    topic!(
        "runtime-cline",
        "Install nah for Cline.",
        "../../../docs/runtimes/cline.md",
        4_096
    ),
    topic!(
        "runtime-codex",
        "Install nah for Codex.",
        "../../../docs/runtimes/codex.md",
        4_096
    ),
    topic!(
        "runtime-copilot",
        "Install nah for GitHub Copilot.",
        "../../../docs/runtimes/copilot.md",
        4_096
    ),
    topic!(
        "runtime-cursor",
        "Install nah for Cursor.",
        "../../../docs/runtimes/cursor.md",
        4_096
    ),
    topic!(
        "runtime-devin",
        "Install nah for Devin.",
        "../../../docs/runtimes/devin.md",
        4_096
    ),
    topic!(
        "runtime-droid",
        "Install nah for Factory Droid.",
        "../../../docs/runtimes/droid.md",
        4_096
    ),
    topic!(
        "runtime-hermes",
        "Install nah for Hermes.",
        "../../../docs/runtimes/hermes.md",
        4_096
    ),
    topic!(
        "runtime-kiro",
        "Install nah for Kiro CLI.",
        "../../../docs/runtimes/kiro.md",
        4_096
    ),
    topic!(
        "runtime-openclaw",
        "Install nah for OpenClaw.",
        "../../../docs/runtimes/openclaw.md",
        4_096
    ),
    topic!(
        "runtime-opencode",
        "Install nah for OpenCode.",
        "../../../docs/runtimes/opencode.md",
        4_096
    ),
    topic!(
        "runtime-pi",
        "Install nah for Pi.",
        "../../../docs/runtimes/pi.md",
        4_096
    ),
    topic!(
        "runtime-prime-agent",
        "Install nah for Prime Agent.",
        "../../../docs/runtimes/prime-agent.md",
        5_120
    ),
    topic!(
        "security",
        "Review nah's enforcement and trust boundaries.",
        "../../../docs/security.md",
        4_096
    ),
    topic!(
        "threat-model",
        "Understand nah's adversary, assumptions, and companion controls.",
        "../../../docs/threat-model.md",
        5_120
    ),
    topic!(
        "architecture",
        "Navigate the codebase by responsibility.",
        "../../../docs/architecture.md",
        6_144
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
    }
}
