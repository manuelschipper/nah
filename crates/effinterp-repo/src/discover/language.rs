use super::*;

/// A Python/JS file that runs when executed (not a pure library), or None.
/// Python uses the precise `if __name__ == "__main__"` guard; JS treats a file
/// that runs at module scope (a top-level call) as a script. A parse failure
/// leaves root classification unknown and must be recorded by discovery.
pub(super) fn script_subject(
    ext: Option<&str>,
    content: &str,
    masked: &str,
    engine_limits: &effinterp_proto::Limits,
) -> Result<Option<Subject>, &'static str> {
    Ok(match ext {
        Some("py") if python_is_script(content, masked, engine_limits) => Some(Subject::Source {
            dialect: None,
            language: "python".into(),
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        }),
        Some("js" | "mjs" | "cjs")
            if js_is_script(content, engine_limits)
                .ok_or("parse_error: execution root classification failed")? =>
        {
            Some(Subject::Source {
                language: "js".into(),
                source: content.to_string(),
                dialect: Some(SourceDialect::Js),
                cwd: None,
                context: Default::default(),
            })
        }
        Some("rb") if ruby_is_script(content, masked) => Some(Subject::Source {
            dialect: None,
            language: "ruby".to_string(),
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        }),
        _ => None,
    })
}

/// A Ruby file runs when executed if it has top-level code beyond
/// definitions/requires — a runnable script, not a pure library. The precise
/// `__FILE__ == $0`/`$PROGRAM_NAME` guard also marks one.
fn ruby_is_script(content: &str, masked: &str) -> bool {
    if let Some(runs) = effinterp_engine::ruby_runs_top_level(content) {
        return runs;
    }
    let content = masked;
    if content.lines().any(|line| {
        let comparison = line.replace("==", " == ");
        let tokens: Vec<_> = comparison
            .split(|c: char| !c.is_alphanumeric() && !matches!(c, '_' | '$' | '='))
            .filter(|token| !token.is_empty())
            .collect();
        tokens.windows(3).any(|tokens| {
            matches!(
                tokens,
                ["__FILE__", "==", "$0" | "$PROGRAM_NAME"]
                    | ["$0" | "$PROGRAM_NAME", "==", "__FILE__"]
            )
        })
    }) {
        return true;
    }
    content.lines().any(|line| {
        if line.is_empty() || line.starts_with(char::is_whitespace) {
            return false;
        }
        // Top-level declarations and directives are not execution.
        const DECL: [&str; 11] = [
            "def ", "class ", "module ", "require", "attr_", "include ", "extend ", "#", "end",
            "private", "public",
        ];
        !DECL.iter().any(|k| line.starts_with(k)) && (line.contains('(') || line.contains('`'))
    })
}

/// A real `if __name__ == "__main__":` guard on a code line (or a shebang, which
/// is classified separately). The `"__main__"` literal is masked out, so the
/// comparison target is checked against the original line; the `if __name__ ==`
/// part must survive masking to prove it is code and not an f-string or a
/// `import __main__` mention.
fn python_is_script(content: &str, masked: &str, engine_limits: &effinterp_proto::Limits) -> bool {
    if content.lines().zip(masked.lines()).any(|(orig, mask)| {
        let m = mask.trim_start();
        m.starts_with("if") && m.contains("__name__") && orig.contains("__main__")
    }) {
        return true;
    }
    let signatures: Vec<_> = effinterp_engine::LIFECYCLE_CATALOG
        .iter()
        .filter(|model| model.lang == Some(effinterp_engine::Lang::Python))
        .flat_map(|model| model.sigs)
        .filter(|sig| sig.component.is_some())
        .collect();
    if !signatures.iter().any(|sig| {
        sig.import_path
            .is_some_and(|module| masked.contains(module))
    }) {
        return false;
    }
    let summary = effinterp_engine::module_summaries(
        content,
        effinterp_engine::Lang::Python,
        "",
        effinterp_engine::ScopeKey::Module { key: String::new() },
        &effinterp_engine::SummaryBudget::for_lang(engine_limits, effinterp_engine::Lang::Python),
    );
    summary.module_calls.iter().any(|call| {
        signatures.iter().any(|sig| {
            summary.imports.iter().any(|binding| {
                sig.import_path == Some(binding.module.as_str())
                    && sig
                        .method
                        .is_some_and(|method| match binding.imported.as_deref() {
                            Some(imported) => imported == method && call.callee == binding.local,
                            None => call.callee == format!("{}.{method}", binding.local),
                        })
            })
        })
    })
}

fn js_is_script(content: &str, engine_limits: &effinterp_proto::Limits) -> Option<bool> {
    // The frontend owns declaration and initializer scope, including exported
    // initializers and multiline calls. Exports do not veto module execution.
    let summary = effinterp_engine::module_summaries(
        content,
        effinterp_engine::Lang::Js(SourceDialect::Js),
        "",
        effinterp_engine::ScopeKey::Module { key: String::new() },
        &effinterp_engine::SummaryBudget::for_lang(
            engine_limits,
            effinterp_engine::Lang::Js(SourceDialect::Js),
        ),
    );
    if !summary.module_boundaries.is_empty()
        || !summary.module_calls.is_empty()
        || !summary.module_effects.is_empty()
    {
        return Some(true);
    }
    // Inert calls such as console.log are omitted from semantic summaries but
    // still mark scripts. The frontend classifies module-scope execution, so a
    // parsed uncalled body never becomes an execution root. Preserve unknown
    // classification separately from both executable and library modules.
    effinterp_engine::js_runs_module_scope_call(content)
}

/// The language of a source file that declares a program entry point, or None
/// (a library file with no entry — not an entrypoint).
pub(super) fn main_language(ext: Option<&str>, masked: &str) -> Option<&'static str> {
    match ext {
        // A real top-level main DECLARATION, not the substring "fn main"
        // appearing in a string literal or comment (which used to make e.g.
        // a frontend source file that mentions "fn main" a false entrypoint).
        // `masked` has strings/comments blanked, so a match must be real code.
        // A bounded declarative entry macro (`path::bin!(ident)`) writes
        // `fn main` only after expansion and is still a program entry.
        Some("rs")
            if declares_line(masked, |t| {
                t.starts_with("fn main") || rust_is_entry_macro_line(t)
            }) =>
        {
            Some("rust")
        }
        Some("go") if declares_line(masked, |t| t.starts_with("func main(")) => Some("go"),
        Some("java")
            if declares_line(masked, |t| {
                t.contains("static void main(")
                    && ["public", "protected", "private", "static", "final"]
                        .iter()
                        .any(|m| t.starts_with(m))
            }) =>
        {
            Some("java")
        }
        _ => None,
    }
}

/// Whether any line, once trimmed and stripped of leading Rust visibility/async
/// modifiers, satisfies `pred` — i.e. is a real declaration line rather than a
/// substring buried inside a string literal or an indented expression.
fn declares_line(content: &str, pred: impl Fn(&str) -> bool) -> bool {
    content.lines().any(|line| {
        let mut t = line.trim_start();
        for prefix in ["pub(crate) ", "pub ", "async "] {
            t = t.strip_prefix(prefix).unwrap_or(t);
        }
        pred(t)
    })
}

/// Read `bin` entries from the root `composer.json`, normalized to repo-relative
/// paths. Missing or malformed `composer.json` yields no bins.
pub(super) fn read_composer_bins(
    root: &Path,
    limits: &CrawlLimits,
    budget: &mut crate::index::IndexBudget,
) -> Vec<String> {
    let Ok(metadata) = std::fs::symlink_metadata(root.join("composer.json")) else {
        return Vec::new();
    };
    if !metadata.is_file()
        || metadata.len() > limits.max_file_bytes
        || budget.charge(1, metadata.len()).is_err()
    {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(root.join("composer.json")) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    let norm = |s: &str| s.trim_start_matches("./").to_string();
    match json.get("bin") {
        Some(serde_json::Value::Array(a)) => {
            a.iter().filter_map(|v| v.as_str()).map(norm).collect()
        }
        Some(serde_json::Value::String(s)) => vec![norm(s)],
        _ => Vec::new(),
    }
}

/// A `.php` file is an entrypoint only if it is a real program: a `php` shebang
/// script, a file under a `bin/` directory, or a declared composer bin. Ordinary
/// class files are not entrypoints (they remain queryable via the surface).
pub(super) fn php_entrypoint(ctx: &mut Ctx, relpath: &str, content: &str, source_cwd: String) {
    let shebang = has_php_shebang(content);
    let is_program = shebang
        || relpath.split('/').any(|seg| seg == "bin")
        || ctx.composer_bins.iter().any(|b| b == relpath);
    if !is_program {
        return;
    }
    ctx.entrypoints.push(Entrypoint {
        id: relpath.to_string(),
        subject: Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: content.to_string(),
            cwd: None,
            context: Default::default(),
        },
        source_file: relpath.to_string(),
        source_cwd: Some(source_cwd),
        evidence: EntrypointEvidence {
            kind: if shebang {
                EntrypointKind::ShebangFile
            } else {
                EntrypointKind::MainFile
            },
            file: relpath.to_string(),
            line: shebang.then_some(1),
        },
        entry_function: None,
        registration: None,
        package_inits: Vec::new(),
        span_map: None,
    });
}

fn has_php_shebang(content: &str) -> bool {
    content
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("#!"))
        .and_then(interpreter)
        .as_deref()
        == Some("php")
}

pub(super) fn registration_entrypoints(
    ctx: &mut Ctx,
    file: &str,
    source: &str,
    dir: &str,
    lang: effinterp_engine::Lang,
) {
    if source
        .lines()
        .take_while(|line| {
            line.trim().is_empty() || line.starts_with('#') || line.starts_with("//")
        })
        .any(|line| line.to_ascii_lowercase().contains("generated") && line.contains("DO NOT EDIT"))
    {
        return;
    }
    if let Err(limit) = ctx.budget.charge(source.len() as u64, 0) {
        ctx.skip_source(file.into(), SkipCategory::Limit, limit);
        return;
    }
    let registrations = match effinterp_engine::registrations(source, lang, file, ctx.engine_limits)
    {
        Ok(registrations) => registrations,
        Err(reason) => {
            ctx.skip_source(
                file.into(),
                if reason.starts_with("parse_error") {
                    SkipCategory::Failure
                } else {
                    SkipCategory::Limit
                },
                reason,
            );
            return;
        }
    };
    for registration in registrations {
        let id = registration.id();
        if let Some(existing) = ctx
            .entrypoints
            .iter_mut()
            .find(|entry| entry.id == id && entry.registration.is_some())
        {
            let retained = existing.registration.as_mut().unwrap();
            retained.spans.extend(registration.spans);
            retained.spans.sort();
            retained.spans.dedup();
            for handler in registration.selected_handlers {
                if !retained.selected_handlers.contains(&handler) {
                    retained.selected_handlers.push(handler);
                }
            }
            for unresolved in registration.unresolved {
                if !retained.unresolved.contains(&unresolved) {
                    retained.unresolved.push(unresolved);
                }
            }
            continue;
        }
        if let Err(limit) = ctx.budget.charge(
            0,
            source.len() as u64 + effinterp_proto::canonical_json(&registration).len() as u64,
        ) {
            ctx.skip_source(file.into(), SkipCategory::Limit, limit);
            return;
        }
        let kind = match registration.kind {
            effinterp_engine::RegistrationKind::Route { .. } => EntrypointKind::Route,
            effinterp_engine::RegistrationKind::Command { .. } => EntrypointKind::Command,
        };
        let line = registration.spans.first().map(|(start, _)| {
            source[..*start as usize]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count() as u32
                + 1
        });
        ctx.entrypoints.push(Entrypoint {
            id,
            subject: Subject::Source {
                dialect: None,
                language: match lang {
                    effinterp_engine::Lang::Python => "python",
                    _ => "go",
                }
                .into(),
                source: source.into(),
                cwd: None,
                context: Default::default(),
            },
            source_file: file.into(),
            source_cwd: Some(dir.into()),
            evidence: EntrypointEvidence {
                kind,
                file: file.into(),
                line,
            },
            entry_function: None,
            registration: Some(registration),
            package_inits: Vec::new(),
            span_map: None,
        });
    }
}
