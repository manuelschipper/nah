use super::*;

pub(super) fn package_scripts(ctx: &mut Ctx, relpath: &str, content: &str, cwd: Option<&str>) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        ctx.skip(
            relpath.to_string(),
            SkipCategory::Failure,
            "package.json is not valid JSON",
        );
        return;
    };
    let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) else {
        return;
    };
    // BTreeMap for deterministic ordering.
    let ordered: BTreeMap<&String, &serde_json::Value> = scripts.iter().collect();
    let value_offsets = script_value_offsets(content);
    for (name, value) in ordered {
        let Some(command) = value.as_str() else {
            continue;
        };
        let span_map = value_offsets
            .get(name.as_str())
            .map(|&off| json_string_segments(content.as_bytes(), off));
        ctx.entrypoints.push(Entrypoint {
            id: format!("{relpath}:scripts.{name}"),
            subject: Subject::Shell {
                source: command.to_string(),
                cwd: Some(cwd.unwrap_or("").to_string()),
                context: Default::default(),
            },
            source_file: relpath.to_string(),
            source_cwd: Some(cwd.unwrap_or("").to_string()),
            evidence: EntrypointEvidence {
                kind: EntrypointKind::PackageScript,
                file: relpath.to_string(),
                line: None,
            },
            entry_function: None,
            registration: None,
            package_inits: Vec::new(),
            span_map,
        });
    }
}

/// Byte offset of each script value's opening quote inside the top-level
/// `"scripts"` object, keyed by decoded script name. A minimal scan of JSON
/// serde already validated; anything unexpected simply yields no entry (and
/// that script keeps subject-relative spans).
fn script_value_offsets(content: &str) -> BTreeMap<String, usize> {
    let b = content.as_bytes();
    let mut out = BTreeMap::new();
    let mut depth = 0i32;
    let mut in_scripts = false;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let Some((decoded, end)) = scan_json_string(b, i) else {
                    return out;
                };
                i = end;
                let mut j = i;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                // A key: the next token is a colon; resume at its value.
                if j < b.len() && b[j] == b':' {
                    j += 1;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if depth == 1 && decoded == "scripts" && b.get(j) == Some(&b'{') {
                        in_scripts = true;
                    } else if in_scripts && depth == 2 && b.get(j) == Some(&b'"') {
                        out.insert(decoded, j);
                        match scan_json_string(b, j) {
                            Some((_, vend)) => {
                                i = vend;
                                continue;
                            }
                            None => return out,
                        }
                    }
                    i = j;
                }
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                if in_scripts && depth == 2 {
                    return out;
                }
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// Decode the JSON string whose opening quote is at `start`: the decoded text
/// and the offset just past the closing quote.
fn scan_json_string(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                let (ch, raw) = json_escape(b, i)?;
                out.push(ch);
                i += raw;
            }
            _ => {
                // Raw bytes (UTF-8 continuation bytes included) pass through.
                let end = i + utf8_len(b[i]);
                out.push_str(std::str::from_utf8(b.get(i..end)?).ok()?);
                i = end;
            }
        }
    }
    None
}

/// Decode the JSON escape whose backslash is at `i`: the decoded character and
/// the escape's raw byte length (2, 6, or 12 for a surrogate pair).
fn json_escape(b: &[u8], i: usize) -> Option<(char, usize)> {
    let hex4 = |at: usize| {
        std::str::from_utf8(b.get(at..at + 4)?)
            .ok()
            .and_then(|h| u32::from_str_radix(h, 16).ok())
    };
    Some(match *b.get(i + 1)? {
        b'b' => ('\u{8}', 2),
        b'f' => ('\u{c}', 2),
        b'n' => ('\n', 2),
        b'r' => ('\r', 2),
        b't' => ('\t', 2),
        b'u' => {
            let hi = hex4(i + 2)?;
            if (0xD800..0xDC00).contains(&hi) && b.get(i + 6..i + 8) == Some(b"\\u") {
                let lo = hex4(i + 8)?;
                let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                (char::from_u32(cp)?, 12)
            } else {
                (char::from_u32(hi)?, 6)
            }
        }
        c => (c as char, 2),
    })
}

fn utf8_len(byte: u8) -> usize {
    match byte {
        0xF0.. => 4,
        0xE0.. => 3,
        0xC0.. => 2,
        _ => 1,
    }
}

/// The span segments of the JSON string whose opening quote is at `start`:
/// verbatim runs map 1:1 into the host file; an escape maps its decoded bytes
/// to the backslash's offset.
fn json_string_segments(b: &[u8], start: usize) -> Vec<SpanSegment> {
    let mut segs: Vec<SpanSegment> = Vec::new();
    let mut src = 0u32;
    let mut i = start + 1;
    let mut run = SpanSegment {
        src: 0,
        host: (start + 1) as u32,
        len: 0,
    };
    while i < b.len() {
        match b[i] {
            b'"' => break,
            b'\\' => {
                let Some((ch, raw)) = json_escape(b, i) else {
                    break;
                };
                if run.len > 0 {
                    segs.push(run);
                }
                let decoded = ch.len_utf8() as u32;
                segs.push(SpanSegment {
                    src,
                    host: i as u32,
                    len: decoded,
                });
                src += decoded;
                i += raw;
                run = SpanSegment {
                    src,
                    host: i as u32,
                    len: 0,
                };
            }
            byte => {
                let raw = utf8_len(byte) as u32;
                run.len += raw;
                src += raw;
                i += raw as usize;
            }
        }
    }
    if run.len > 0 || segs.is_empty() {
        segs.push(run);
    }
    segs
}

/// Discover literal `target:` rules. The engine's Make command model owns
/// recipe selection and execution semantics for these entrypoints.
pub(super) fn makefile_targets(ctx: &mut Ctx, relpath: &str, content: &str, cwd: Option<&str>) {
    let mut seen = std::collections::BTreeSet::new();
    for (index, line) in content.lines().enumerate() {
        if let Some(target) = rule_target(line) {
            if !seen.insert(target.clone()) {
                continue;
            }
            ctx.entrypoints.push(Entrypoint {
                id: format!("{relpath}:{target}"),
                subject: Subject::Exec {
                    argv: vec!["make".to_string(), target],
                    cwd: Some(cwd.unwrap_or("").to_string()),
                    context: Default::default(),
                },
                source_file: relpath.to_string(),
                source_cwd: Some(cwd.unwrap_or("").to_string()),
                evidence: EntrypointEvidence {
                    kind: EntrypointKind::MakefileTarget,
                    file: relpath.to_string(),
                    line: Some((index + 1) as u32),
                },
                entry_function: None,
                registration: None,
                package_inits: Vec::new(),
                span_map: None,
            });
        }
    }
}

/// A Makefile rule target name, if this line declares one (`name: deps`).
/// Excludes variable assignments and directives.
fn rule_target(line: &str) -> Option<String> {
    if line.starts_with('\t') {
        return None;
    }
    let line = line.trim_start();
    if line.starts_with('#') || line.is_empty() {
        return None;
    }
    let colon = line.find(':')?;
    let name = line[..colon].trim();
    let prerequisites = line[colon + 1..].trim_start();
    // Reject assignments (`X := ...`, `X = ...`) and phony lists.
    if name.is_empty()
        || name.chars().any(char::is_whitespace)
        || name.contains(['=', '$', '%'])
        || name.starts_with('.')
        || prerequisites.trim_start_matches(':').starts_with('=')
    {
        return None;
    }
    Some(name.to_string())
}

/// tsconfig `compilerOptions.outDir`/`rootDir`, normalized repo-relative.
struct TsDirs {
    out_dir: Option<String>,
    root_dir: Option<String>,
}

fn read_tsconfig_dirs(root: &Path) -> TsDirs {
    let none = TsDirs {
        out_dir: None,
        root_dir: None,
    };
    let Ok(content) = std::fs::read_to_string(root.join("tsconfig.json")) else {
        return none;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return none;
    };
    let dir = |key: &str| {
        json.get("compilerOptions")
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches("./").trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
    };
    TsDirs {
        out_dir: dir("outDir"),
        root_dir: dir("rootDir"),
    }
}

/// Register source entrypoints for workspace package.json `bin` programs, and
/// return wrapper -> program launch edges. A bin target may name built output
/// absent from the source repo (zx: `"zx": "build/cli.js"` with only
/// `src/cli.ts` in tree), or exist as a thin wrapper importing built output
/// or a workspace package (changesets: `bin.js` `import('@pkg/cli')` whose
/// export is `dist/index.mjs`, built from `src/index.ts`). Both map back to
/// the source file that produces the artifact via [`built_to_source`].
pub(super) fn package_bin_entrypoints(ctx: &mut Ctx, root: &Path) -> Vec<LaunchEdge> {
    let packages = crate::module::js_packages::collect_js_packages(root, &mut |path| {
        crate::canonical_repo_path(root, path)
            .is_some_and(|path| ctx.manifest.iter().any(|input| input.path == path))
    });
    let mut edges = Vec::new();
    for pkg in &packages {
        let evidence_file = prefix_pkg(&pkg.dir, "package.json");
        let pkg_abs = if pkg.dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&pkg.dir)
        };
        let local_ts = read_tsconfig_dirs(&pkg_abs);
        let ts = if local_ts.out_dir.is_some() || local_ts.root_dir.is_some() {
            local_ts
        } else {
            read_tsconfig_dirs(root)
        };
        let mut targets = pkg.bins.clone();
        targets.sort();
        targets.dedup();
        for target in targets {
            let rel = if pkg.dir.is_empty() {
                target.clone()
            } else {
                format!("{}/{}", pkg.dir, target)
            };
            ctx.mark_skipped_root(&rel);
            if root.join(&rel).is_file() {
                // A committed built artifact (zx checks `build/` in): the source
                // that produces it is the real program — register it and union it
                // into the artifact's surface through a launch edge. Only a target
                // under a recognized build dir is treated as built output.
                if in_build_dir(&target, &ts)
                    && let Some(source) = built_to_source(&pkg_abs, &target, &ts)
                {
                    let source = prefix_pkg(&pkg.dir, &source);
                    ctx.mark_skipped_root(&source);
                    if add_js_source_entrypoint(ctx, root, &source, &evidence_file) {
                        edges.push(LaunchEdge {
                            wrapper: rel.clone(),
                            launch_entrypoint: source.clone(),
                            launched: source,
                            line: None,
                            process: None,
                            alternative: false,
                        });
                    }
                    continue;
                }
                // The bin file exists: it may be a wrapper importing built
                // output that is not in the source tree, or a workspace
                // package whose export maps to that source.
                let Ok(src) = std::fs::read_to_string(root.join(&rel)) else {
                    continue;
                };
                let dir = target.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                for (spec, line) in relative_import_specs(&src) {
                    let Some(resolved) = join_rel_path(dir, &spec) else {
                        continue;
                    };
                    if pkg_abs.join(&resolved).is_file() {
                        continue;
                    }
                    if let Some(source) = built_to_source(&pkg_abs, &resolved, &ts) {
                        let source = prefix_pkg(&pkg.dir, &source);
                        ctx.mark_skipped_root(&source);
                        if add_js_source_entrypoint(ctx, root, &source, &evidence_file) {
                            edges.push(LaunchEdge {
                                wrapper: rel.clone(),
                                launch_entrypoint: source.clone(),
                                launched: source,
                                line: Some(line),
                                process: None,
                                alternative: false,
                            });
                        }
                    }
                }
                for (spec, line) in package_import_specs(&src) {
                    let Some(owner) = packages.iter().find(|p| match &p.name {
                        Some(n) => spec == *n || spec.starts_with(&format!("{n}/")),
                        None => false,
                    }) else {
                        continue;
                    };
                    let sub = if owner.name.as_deref() == Some(spec.as_str()) {
                        ".".to_string()
                    } else if let Some(name) = &owner.name {
                        format!(".{}", &spec[name.len()..])
                    } else {
                        continue;
                    };
                    let Some(artifact) =
                        crate::module::js_packages::js_package_artifact(owner, &sub)
                    else {
                        continue;
                    };
                    let owner_abs = if owner.dir.is_empty() {
                        root.to_path_buf()
                    } else {
                        root.join(&owner.dir)
                    };
                    if owner_abs.join(&artifact).is_file() {
                        let launched = prefix_pkg(&owner.dir, &artifact);
                        ctx.mark_skipped_root(&launched);
                        if add_js_source_entrypoint(ctx, root, &launched, &evidence_file) {
                            edges.push(LaunchEdge {
                                wrapper: rel.clone(),
                                launch_entrypoint: launched.clone(),
                                launched,
                                line: Some(line),
                                process: None,
                                alternative: false,
                            });
                        }
                        continue;
                    }
                    let owner_ts = {
                        let local = read_tsconfig_dirs(&owner_abs);
                        if local.out_dir.is_some() || local.root_dir.is_some() {
                            local
                        } else {
                            read_tsconfig_dirs(root)
                        }
                    };
                    if let Some(source) = built_to_source(&owner_abs, &artifact, &owner_ts) {
                        let source = prefix_pkg(&owner.dir, &source);
                        ctx.mark_skipped_root(&source);
                        if add_js_source_entrypoint(ctx, root, &source, &evidence_file) {
                            edges.push(LaunchEdge {
                                wrapper: rel.clone(),
                                launch_entrypoint: source.clone(),
                                launched: source,
                                line: Some(line),
                                process: None,
                                alternative: false,
                            });
                        }
                    }
                }
            } else if let Some(source) = built_to_source(&pkg_abs, &target, &ts) {
                let source = prefix_pkg(&pkg.dir, &source);
                ctx.mark_skipped_root(&source);
                add_js_source_entrypoint(ctx, root, &source, &evidence_file);
            }
        }
    }
    edges
}

fn prefix_pkg(pkg_dir: &str, rel: &str) -> String {
    if pkg_dir.is_empty() {
        rel.to_string()
    } else {
        format!("{pkg_dir}/{rel}")
    }
}

/// Quoted package specifiers in `import(...)` / `from` / `require(...)`, with
/// their 1-based lines. Relative and `node:` builtins are excluded.
fn package_import_specs(src: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        for marker in ["import(", "from ", "require("] {
            if let Some(spec) = quoted_spec_after(line, marker)
                && is_package_spec(&spec)
            {
                out.push((spec, i as u32 + 1));
            }
        }
    }
    out
}

fn quoted_spec_after(line: &str, marker: &str) -> Option<String> {
    let rest = line.split(marker).nth(1)?.trim_start();
    let q = rest.chars().next()?;
    if q != '\'' && q != '"' {
        return None;
    }
    rest[1..].split(q).next().map(str::to_string)
}

fn is_package_spec(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('.') && !s.starts_with('/') && !s.starts_with("node:")
}

/// Quoted `./`/`../` specifiers in a JS file (import or require), with their
/// 1-based lines.
fn relative_import_specs(src: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut j = 0;
        while j < bytes.len() {
            let quote = bytes[j];
            if (quote == b'\'' || quote == b'"')
                && let Some(len) = line[j + 1..].find(quote as char)
            {
                let inner = &line[j + 1..j + 1 + len];
                if inner.starts_with("./") || inner.starts_with("../") {
                    out.push((inner.to_string(), i as u32 + 1));
                }
                j += len + 2;
                continue;
            }
            j += 1;
        }
    }
    out
}

/// Whether a path lies under the tsconfig `outDir` or a conventional build
/// directory.
fn in_build_dir(path: &str, ts: &TsDirs) -> bool {
    let head = path.split('/').next().unwrap_or("");
    ts.out_dir.as_deref() == Some(head) || BUILD_DIRS.contains(&head)
}

const BUILD_DIRS: [&str; 5] = ["build", "dist", "lib", "out", "output"];

/// Map a built JS artifact path (`build/cli.js`, `dist/ni.mjs`) back to the
/// source file that produces it. tsconfig `outDir`/`rootDir` drive the exact
/// mapping when declared; otherwise conventional build-dir names map to
/// conventional source roots, and as a last resort a bounded walk of the
/// source roots finds a uniquely-named source file with the same stem.
fn built_to_source(root: &Path, built: &str, ts: &TsDirs) -> Option<String> {
    let (dir, name) = built.rsplit_once('/').unwrap_or(("", built));
    let (stem, ext) = name.rsplit_once('.')?;
    let source_exts: &[&str] = match ext {
        "js" => &["ts", "tsx", "js", "jsx"],
        "mjs" => &["mts", "ts", "mjs"],
        "cjs" => &["cts", "ts", "cjs"],
        _ => return None,
    };
    // The artifact's subpath under its build directory.
    let rest_dir = match &ts.out_dir {
        Some(out) if dir == out => Some(""),
        Some(out) if dir.starts_with(&format!("{out}/")) => Some(&dir[out.len() + 1..]),
        _ => match dir.split_once('/') {
            Some((head, rest)) if BUILD_DIRS.contains(&head) => Some(rest),
            None if BUILD_DIRS.contains(&dir) => Some(""),
            _ => None,
        },
    };
    let mut roots: Vec<&str> = Vec::new();
    if let Some(r) = &ts.root_dir {
        roots.push(r);
    }
    roots.extend(["src", ""]);
    if let Some(rest) = rest_dir {
        for src_root in &roots {
            let base: String = [*src_root, rest, stem]
                .iter()
                .filter(|p| !p.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join("/");
            for e in source_exts {
                let cand = format!("{base}.{e}");
                if root.join(&cand).is_file() {
                    return Some(cand);
                }
            }
        }
    }
    // Unique-stem search: the artifact's source keeps its name even when the
    // build flattens directories (tsdown `src/commands/*.ts` -> `dist/*.mjs`).
    let mut found: Vec<String> = Vec::new();
    for src_root in &roots {
        if src_root.is_empty() {
            continue;
        }
        find_stem(
            &root.join(src_root),
            src_root,
            stem,
            source_exts,
            0,
            &mut found,
        );
    }
    found.sort();
    found.dedup();
    match found.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// Collect files named `<stem>.<ext>` under `dir` (bounded depth, skipping
/// vendored/build/test trees), pushing repo-relative paths.
fn find_stem(dir: &Path, rel: &str, stem: &str, exts: &[&str], depth: u32, out: &mut Vec<String>) {
    if depth > 8 || is_non_root_path(rel, "") {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let Ok(ft) = entry.file_type() else { continue };
        let Some(name) = entry
            .file_name()
            .to_str()
            .filter(|name| !name.contains('\\'))
            .map(str::to_string)
        else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if CRAWL_SKIP_DIRS.contains(&name.as_str()) || is_non_root_path(&name, &name) {
                continue;
            }
            find_stem(
                &entry.path(),
                &format!("{rel}/{name}"),
                stem,
                exts,
                depth + 1,
                out,
            );
        } else if ft.is_file()
            && !is_non_root_path(rel, &name)
            && let Some((s, e)) = name.rsplit_once('.')
            && s == stem
            && exts.contains(&e)
        {
            out.push(format!("{rel}/{name}"));
        }
    }
}

/// Register a JS/TS source file as a bin-program entrypoint (unless some other
/// mechanism already claimed its id).
fn add_js_source_entrypoint(
    ctx: &mut Ctx,
    root: &Path,
    relpath: &str,
    evidence_file: &str,
) -> bool {
    if !ctx.manifest.iter().any(|input| input.path == relpath) {
        return false;
    }
    if ctx.entrypoints.iter().any(|e| e.id == relpath) {
        return true;
    }
    let Ok(source) = std::fs::read_to_string(root.join(relpath)) else {
        return false;
    };
    let dialect = match relpath.rsplit_once('.').map(|(_, e)| e) {
        Some("ts" | "mts" | "cts" | "tsx") => SourceDialect::Ts,
        _ => SourceDialect::Js,
    };
    let source_cwd = relpath
        .rsplit_once('/')
        .map_or_else(String::new, |(dir, _)| dir.to_string());
    ctx.entrypoints.push(Entrypoint {
        id: relpath.to_string(),
        subject: Subject::Source {
            language: "js".into(),
            source,
            dialect: Some(dialect),
            cwd: None,
            context: Default::default(),
        },
        source_file: relpath.to_string(),
        source_cwd: Some(source_cwd),
        evidence: EntrypointEvidence {
            kind: EntrypointKind::PackageBin,
            file: evidence_file.to_string(),
            line: None,
        },
        entry_function: None,
        registration: None,
        package_inits: Vec::new(),
        span_map: None,
    });
    true
}

/// Register console-script entrypoints declared in Python packaging metadata:
/// pyproject `[project.scripts]` / `[project.gui-scripts]` (table or dotted
/// `scripts.name = "..."` keys under `[project]`), the console/gui groups of
/// `[project.entry-points]`, poetry `[tool.poetry.scripts]`, and setup.cfg
/// `[options.entry_points] console_scripts`. Each `pkg.mod:func` spec roots
/// at the module's file (src/ layout included) with `func` as the entry
/// function the script runner calls after import.
pub(super) fn python_entry_point_scripts(ctx: &mut Ctx, root: &Path) {
    let mut specs: Vec<(String, String, u32)> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(root.join("pyproject.toml")) {
        specs.extend(
            pyproject_script_specs(&text)
                .into_iter()
                .map(|(spec, line)| (spec, "pyproject.toml".to_string(), line)),
        );
    }
    if let Ok(text) = std::fs::read_to_string(root.join("setup.cfg")) {
        specs.extend(
            setup_cfg_script_specs(&text)
                .into_iter()
                .map(|(spec, line)| (spec, "setup.cfg".to_string(), line)),
        );
    }
    for (spec, evidence_file, line) in specs {
        let (module, func) = match spec.split_once(':') {
            Some((m, f)) => (m.trim(), Some(f)),
            None => (spec.trim(), None),
        };
        // `mod:func [extra]` — the callable name ends at whitespace/extras.
        let func = func
            .map(|f| f.trim().split([' ', '[']).next().unwrap_or("").to_string())
            .filter(|f| !f.is_empty() && f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        let Some(file) = python_module_file(root, module) else {
            ctx.skip(
                evidence_file,
                SkipCategory::Failure,
                format!("console script target {spec:?} is not a repository Python module"),
            );
            continue;
        };
        // A `__main__` guard may have already registered the same file. The
        // console-script still names the callable the wrapper invokes after
        // import (`pkg.mod:func`); attach it rather than dropping the spec.
        if let Some(existing) = ctx.entrypoints.iter_mut().find(|e| e.id == file) {
            if existing.entry_function.is_none() {
                existing.entry_function = func;
                existing.evidence = EntrypointEvidence {
                    kind: EntrypointKind::ConsoleScript,
                    file: evidence_file,
                    line: Some(line),
                };
            }
            continue;
        }
        let Ok(source) = std::fs::read_to_string(root.join(&file)) else {
            ctx.mark_skipped_root(&file);
            continue;
        };
        let source_cwd = file
            .rsplit_once('/')
            .map_or_else(String::new, |(dir, _)| dir.to_string());
        ctx.entrypoints.push(Entrypoint {
            id: file.clone(),
            subject: Subject::Source {
                dialect: None,
                language: "python".into(),
                source,
                cwd: None,
                context: Default::default(),
            },
            source_file: file.clone(),
            source_cwd: Some(source_cwd),
            evidence: EntrypointEvidence {
                kind: EntrypointKind::ConsoleScript,
                file: evidence_file,
                line: Some(line),
            },
            entry_function: func,
            registration: None,
            package_inits: Vec::new(),
            span_map: None,
        });
    }
}

/// `module:func` values of script-declaring keys in a pyproject.toml, via a
/// line-level TOML subset (table headers plus `key = "string"` pairs, dotted
/// keys included).
fn pyproject_script_specs(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut table: Vec<String> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let inner = line.trim_start_matches('[').trim_end_matches(']').trim();
            table = split_dotted(inner);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(spec) = toml_basic_string(value.trim()) else {
            continue;
        };
        let mut path = table.clone();
        path.extend(split_dotted(key.trim()));
        if is_script_key(&path) {
            out.push((spec, index as u32 + 1));
        }
    }
    out
}

/// Whether a full dotted key path declares an executable script.
fn is_script_key(path: &[String]) -> bool {
    let p: Vec<&str> = path.iter().map(String::as_str).collect();
    matches!(
        p.as_slice(),
        ["project", "scripts" | "gui-scripts", _]
            | [
                "project",
                "entry-points",
                "console_scripts" | "gui_scripts",
                _
            ]
            | ["tool", "poetry", "scripts", _]
    )
}

/// Split a (possibly dotted, possibly quoted-segment) TOML key into segments.
fn split_dotted(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in key.chars() {
        match c {
            '"' | '\'' if quote == Some(c) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(c),
            '.' if quote.is_none() => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// The inner text of a TOML basic string value, or None for any other shape.
fn toml_basic_string(value: &str) -> Option<String> {
    for q in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(q) && value[1..].find(q) == Some(value.len() - 2) {
            return Some(value[1..value.len() - 1].to_string());
        }
    }
    None
}

/// `module:func` values under setup.cfg `[options.entry_points]`
/// console_scripts / gui_scripts groups.
fn setup_cfg_script_specs(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut in_entry_points = false;
    let mut in_scripts_group = false;
    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') {
            in_entry_points = trimmed == "[options.entry_points]";
            in_scripts_group = false;
            continue;
        }
        if !in_entry_points || trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        if !raw.starts_with([' ', '\t']) {
            // `console_scripts =` opens a group of indented `name = spec` lines.
            let key = trimmed.split('=').next().unwrap_or("").trim();
            in_scripts_group = matches!(key, "console_scripts" | "gui_scripts");
            continue;
        }
        if in_scripts_group && let Some((_, spec)) = trimmed.split_once('=') {
            out.push((spec.trim().to_string(), index as u32 + 1));
        }
    }
    out
}

/// Search the conventional roots first, then root-manifest declarations in file order.
fn python_layout_roots(root: &Path) -> Vec<String> {
    let mut roots = vec![String::new(), "src".to_string()];
    let mut add = |value: &str| {
        if let Some(path) = join_rel_path("", value.trim())
            && !roots.contains(&path)
        {
            roots.push(path);
        }
    };
    if let Ok(text) = std::fs::read_to_string(root.join("pyproject.toml")) {
        let mut table = Vec::new();
        let mut statement = String::new();
        let mut depth = 0i32;
        let mut quote = None;
        for raw in text.lines() {
            let line = raw.trim();
            if statement.is_empty() && line.starts_with('[') {
                table = split_dotted(line.trim_start_matches('[').split(']').next().unwrap_or(""));
                continue;
            }
            for c in line.chars() {
                match c {
                    '#' if quote.is_none() => break,
                    '\'' | '"' if quote == Some(c) => quote = None,
                    '\'' | '"' if quote.is_none() => quote = Some(c),
                    '[' | '{' if quote.is_none() => depth += 1,
                    ']' | '}' if quote.is_none() => depth -= 1,
                    _ => {}
                }
                statement.push(c);
            }
            if depth > 0 || quote.is_some() {
                statement.push(' ');
                continue;
            }
            if let Some((key, value)) = statement.split_once('=') {
                let mut path = table.clone();
                path.extend(split_dotted(key.trim()));
                let path = path.iter().map(String::as_str).collect::<Vec<_>>();
                match path.as_slice() {
                    ["tool", "setuptools", "packages", "find", "where"] => {
                        for value in value
                            .trim()
                            .trim_start_matches('[')
                            .trim_end_matches(']')
                            .split(',')
                        {
                            if let Some(value) = toml_basic_string(value.trim()) {
                                add(&value);
                            }
                        }
                    }
                    ["tool", "setuptools", "package-dir", _] => {
                        if let Some(value) = toml_basic_string(value.trim()) {
                            add(&value);
                        }
                    }
                    ["tool", "setuptools", "package-dir"] | ["tool", "poetry", "packages"] => {
                        let poetry = path[1] == "poetry";
                        for field in value.split([',', '{', '}', '[', ']']) {
                            if let Some((key, value)) = field.split_once('=')
                                && (!poetry || key.trim() == "from")
                                && let Some(value) = toml_basic_string(value.trim())
                            {
                                add(&value);
                            }
                        }
                    }
                    _ => {}
                }
            }
            statement.clear();
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join("setup.cfg")) {
        let mut section = "";
        let mut option = "";
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if line.starts_with('[') {
                section = line;
                option = "";
                continue;
            }
            let value = if !raw.starts_with([' ', '\t']) {
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                option = key.trim();
                value.trim()
            } else {
                line
            };
            match (section, option) {
                ("[options.packages.find]", "where") if !value.is_empty() => add(value),
                ("[options]", "package_dir") => {
                    if let Some((_, value)) = value.split_once('=') {
                        add(value);
                    }
                }
                _ => {}
            }
        }
    }
    roots
}

/// The repo file a dotted Python module path names under the declared layout roots.
fn python_module_file(root: &Path, module: &str) -> Option<String> {
    if module.is_empty()
        || !module
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return None;
    }
    let rel = module.replace('.', "/");
    for src_root in python_layout_roots(root) {
        let base = if src_root.is_empty() {
            rel.clone()
        } else {
            format!("{src_root}/{rel}")
        };
        for cand in [format!("{base}.py"), format!("{base}/__init__.py")] {
            if root.join(&cand).is_file() {
                return Some(cand);
            }
        }
    }
    None
}

pub(super) fn python_module_program(
    ctx: &Ctx,
    root: &Path,
    cwd: &str,
    module: &str,
) -> Option<(String, Vec<String>)> {
    if module.is_empty()
        || !module
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return None;
    }
    let module = module.replace('.', "/");
    for layout_root in python_layout_roots(root) {
        let base = join_rel_path(cwd, &layout_root)?;
        let package = join_rel_path(&base, &module)?;
        let main = format!("{package}/__main__.py");
        if root.join(&main).is_file() && ctx.manifest.iter().any(|input| input.path == main) {
            let mut package_inits = Vec::new();
            let mut package = base.clone();
            for component in module.split('/') {
                package = join_rel_path(&package, component)?;
                let init = format!("{package}/__init__.py");
                if root.join(&init).is_file() && ctx.manifest.iter().any(|input| input.path == init)
                {
                    package_inits.push(init);
                }
            }
            return Some((main, package_inits));
        }
        let file = format!("{package}.py");
        if root.join(&file).is_file() && ctx.manifest.iter().any(|input| input.path == file) {
            let mut package_inits = Vec::new();
            let mut package = base.clone();
            if let Some((parents, _)) = module.rsplit_once('/') {
                for component in parents.split('/') {
                    package = join_rel_path(&package, component)?;
                    let init = format!("{package}/__init__.py");
                    if root.join(&init).is_file()
                        && ctx.manifest.iter().any(|input| input.path == init)
                    {
                        package_inits.push(init);
                    }
                }
            }
            return Some((file, package_inits));
        }
    }
    None
}
