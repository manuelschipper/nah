use std::path::Path;

use effinterp_proto::{SourceDialect, Subject};

use super::{Entrypoint, EntrypointCrawl, EntrypointEvidence, EntrypointKind};

pub(super) fn could_have_shebang(name: &str, path: &Path) -> bool {
    // Extensionless files or common script extensions may carry a shebang.
    let ext = path.extension().map(|e| e.to_string_lossy().to_string());
    matches!(
        ext.as_deref(),
        None | Some("py")
            | Some("js")
            | Some("mjs")
            | Some("cjs")
            | Some("ts")
            | Some("mts")
            | Some("cts")
            | Some("tsx")
    ) && !name.starts_with('.')
}

pub(super) fn push_shell_file(
    ctx: &mut EntrypointCrawl,
    relpath: &str,
    source: String,
    source_cwd: String,
    kind: EntrypointKind,
) {
    ctx.entrypoints.push(Entrypoint {
        id: relpath.to_string(),
        subject: Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        },
        source_file: relpath.to_string(),
        source_cwd: Some(source_cwd),
        evidence: EntrypointEvidence {
            kind,
            file: relpath.to_string(),
            line: None,
        },
        entry_function: None,
        registration: None,
        package_inits: Vec::new(),
        span_map: None,
    });
}

pub(super) fn shebang_file(
    ctx: &mut EntrypointCrawl,
    relpath: &str,
    content: &str,
    source_cwd: String,
) {
    let Some(first) = content.lines().next() else {
        return;
    };
    let Some(rest) = first.strip_prefix("#!") else {
        return;
    };
    let interp = interpreter(rest);
    let subject = match interp.as_deref() {
        Some("sh" | "bash" | "dash" | "zsh") => Subject::Shell {
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        },
        Some("python" | "python3" | "python2") => Subject::Source {
            dialect: None,
            language: "python".into(),
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        },
        Some("node" | "nodejs") => Subject::Source {
            language: "js".into(),
            source: content.to_string(),
            dialect: Some(
                match Path::new(relpath).extension().and_then(|ext| ext.to_str()) {
                    Some("ts" | "mts" | "cts" | "tsx") => SourceDialect::Ts,
                    _ => SourceDialect::Js,
                },
            ),
            cwd: None,
            context: Default::default(),
        },
        Some("tsx" | "ts-node" | "bun" | "deno") => Subject::Source {
            language: "js".into(),
            source: content.to_string(),
            dialect: Some(SourceDialect::Ts),
            cwd: None,
            context: Default::default(),
        },
        Some("ruby") => Subject::Source {
            dialect: None,
            language: "ruby".to_string(),
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        },
        Some("php") => Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        },
        _ => return,
    };
    ctx.entrypoints.push(Entrypoint {
        id: relpath.to_string(),
        subject,
        source_file: relpath.to_string(),
        source_cwd: Some(source_cwd),
        evidence: EntrypointEvidence {
            kind: EntrypointKind::ShebangFile,
            file: relpath.to_string(),
            line: Some(1),
        },
        entry_function: None,
        registration: None,
        package_inits: Vec::new(),
        span_map: None,
    });
}

/// The interpreter basename from a shebang line, resolving `/usr/bin/env foo`.
pub(super) fn interpreter(rest: &str) -> Option<String> {
    let mut parts = rest.split_whitespace();
    let first = parts.next()?;
    let base = first.rsplit('/').next().unwrap_or(first);
    if base == "env" {
        parts
            .next()
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
    } else {
        Some(base.to_string())
    }
}
