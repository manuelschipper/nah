//! Launched local sources: repository source files that a shell or
//! package-script entrypoint starts as a process. Each becomes an entrypoint
//! of its own, joined to its wrapper by a launch edge.

use std::path::Path;

use effinterp_engine::Engine;
use effinterp_proto::{
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity, SourceDialect, Subject,
};

use super::package::python_module_program;
use super::shebang::interpreter;
use super::{
    Entrypoint, EntrypointCrawl, EntrypointEvidence, EntrypointKind, LaunchEdge,
    ProcessLaunchEvidence, join_rel_path, subject_cwd,
};

/// Register repository source files named by typed process effects in shell
/// and package-script entrypoints. The engine bounds argv alternatives before
/// this adapter sees them, so symbolic and over-wide commands stay unresolved.
pub(super) fn launch_local_sources(ctx: &mut EntrypointCrawl, root: &Path) -> Vec<LaunchEdge> {
    let wrappers: Vec<Entrypoint> = ctx
        .entrypoints
        .iter()
        .filter(|entry| matches!(entry.subject, Subject::Shell { .. }))
        .cloned()
        .collect();
    let engine = Engine::new();
    let mut edges = Vec::new();
    for wrapper in wrappers {
        let Ok(plan) = engine.analyze_with_cwds(
            &wrapper.subject,
            wrapper.source_cwd.as_deref(),
            subject_cwd(&wrapper.subject),
        ) else {
            continue;
        };
        let source = match &wrapper.subject {
            Subject::Shell { source, .. } => source.as_str(),
            _ => unreachable!(),
        };
        for effect in &plan.effects {
            let ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable,
                        path,
                        argv,
                        cwd,
                    },
            } = &effect.resource
            else {
                continue;
            };
            if !effect.realm.is_host() {
                continue;
            }
            let invocation_executable = invocation_executable(&plan, &effect.provenance);
            let cwd = repository_cwd(cwd.as_deref());
            let mut specs = Vec::new();
            for launched in
                launched_sources(executable, path.as_deref(), argv, invocation_executable)
            {
                match launched {
                    LaunchedSource::Resolved(spec) => {
                        specs.push((spec.to_string(), true, false, false, true, true, Vec::new()));
                    }
                    LaunchedSource::Literal(spec) => {
                        let direct = !engine_nests_source(executable);
                        specs.push((
                            spec.to_string(),
                            false,
                            false,
                            false,
                            direct,
                            direct,
                            Vec::new(),
                        ));
                    }
                    LaunchedSource::Dynamic { argument } => {
                        let recovered = static_source_specs(
                            &plan,
                            &effect.provenance,
                            source,
                            executable,
                            argument + 1,
                        );
                        let alternative = recovered.len() > 1;
                        specs.extend(recovered.into_iter().map(|spec| {
                            (
                                spec.path,
                                false,
                                alternative,
                                spec.wrapper_relative,
                                true,
                                false,
                                Vec::new(),
                            )
                        }));
                    }
                    LaunchedSource::PythonModule(module) => {
                        let Some(from_dir) = cwd.as_deref() else {
                            continue;
                        };
                        let Some((file, package_inits)) =
                            python_module_program(ctx, root, from_dir, module)
                        else {
                            continue;
                        };
                        specs.push((file, true, false, false, true, false, package_inits));
                    }
                }
            }
            let wrapper_dir = wrapper
                .evidence
                .file
                .rsplit_once('/')
                .map_or("", |(dir, _)| dir);
            for (
                spec,
                resolved,
                alternative,
                wrapper_relative,
                contextual,
                require_shebang,
                package_inits,
            ) in specs
            {
                let from_dir = if resolved {
                    Some("")
                } else if wrapper_relative {
                    Some(wrapper_dir)
                } else {
                    cwd.as_deref()
                };
                let Some(from_dir) = from_dir else {
                    continue;
                };
                let relpath = match resolve_repo_source(ctx, root, from_dir, &spec, require_shebang)
                {
                    Some(relpath) => relpath,
                    None => {
                        if let Some(path) = ctx.skipped_source_path(from_dir, &spec) {
                            ctx.depend_on_skipped_source(path, &wrapper.id);
                        }
                        continue;
                    }
                };
                let Some(launch_entrypoint) = add_local_source_program(
                    ctx,
                    root,
                    &relpath,
                    cwd.clone(),
                    contextual,
                    package_inits,
                ) else {
                    continue;
                };
                edges.push(LaunchEdge {
                    wrapper: wrapper.id.clone(),
                    launched: relpath,
                    launch_entrypoint,
                    line: source_line(&plan, &effect.provenance, source),
                    process: Some(ProcessLaunchEvidence {
                        resource: effect.resource.clone(),
                        realm: effect.realm.clone(),
                        provenance: effect.provenance.clone(),
                    }),
                    alternative,
                });
            }
        }
    }
    sort_launch_edges(&mut edges);
    edges.dedup();
    edges
}

pub(super) fn sort_launch_edges(edges: &mut [LaunchEdge]) {
    edges.sort_by_cached_key(|edge| {
        (
            edge.wrapper.clone(),
            edge.launched.clone(),
            edge.launch_entrypoint.clone(),
            edge.line,
            format!("{:?}", edge.process),
        )
    });
}

enum LaunchedSource<'a> {
    Resolved(&'a str),
    Literal(&'a str),
    Dynamic { argument: usize },
    PythonModule(&'a str),
}

fn launched_sources<'a>(
    executable: &str,
    path: Option<&'a str>,
    argv: &'a [ResourceExpr],
    invocation_executable: Option<&'a str>,
) -> Vec<LaunchedSource<'a>> {
    if let Some(path) = path {
        return vec![LaunchedSource::Resolved(path)];
    }
    if let Some(spec) = invocation_executable
        && spec.contains('/')
    {
        return vec![LaunchedSource::Literal(spec)];
    }
    if matches!(executable, "python" | "python2" | "python3")
        && let Some(module) = python_module_operand(argv)
    {
        return vec![LaunchedSource::PythonModule(module)];
    }
    let (operand, expected) = match executable {
        "python" | "python2" | "python3" => (
            program_operand(
                argv,
                &["-W", "-X", "--check-hash-based-pycs"],
                &["-c", "-m", "-"],
            ),
            &["py"][..],
        ),
        "node" | "nodejs" | "iojs" => (
            program_operand(
                argv,
                &[
                    "--require",
                    "-r",
                    "--import",
                    "--loader",
                    "--experimental-loader",
                    "--conditions",
                    "-C",
                ],
                &["-e", "--eval", "-p", "--print", "-"],
            ),
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..],
        ),
        "tsx" | "ts-node" | "bun" => (
            program_operand(argv, &[], &[]),
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..],
        ),
        "deno" if argv.first().and_then(literal) == Some("run") => (
            program_operand(
                &argv[1..],
                &[
                    "--cert",
                    "--config",
                    "-c",
                    "--env-file",
                    "--ext",
                    "--import-map",
                    "--location",
                    "--lock",
                    "--seed",
                    "--v8-flags",
                ],
                &[],
            )
            .map(|(index, value)| (index + 1, value)),
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..],
        ),
        "php" | "php7" | "php8" => {
            if argv.first().and_then(literal) == Some("-f") {
                (argv.get(1).map(|value| (1, literal(value))), &["php"][..])
            } else {
                (
                    program_operand(
                        argv,
                        &["-c", "-d", "-F", "-B", "-R", "-E", "-S", "-t", "-z"],
                        &["-r", "--run", "-"],
                    ),
                    &["php"][..],
                )
            }
        }
        "ruby" | "irb" => (
            program_operand(
                argv,
                &["-I", "-r", "-E", "--encoding"],
                &["-e", "--eval", "-C", "--directory", "-"],
            ),
            &["rb"][..],
        ),
        "go" if argv.first().and_then(literal) == Some("run") => {
            let Some((argument, value)) = program_operand(
                &argv[1..],
                &[
                    "-asmflags",
                    "-buildmode",
                    "-compiler",
                    "-covermode",
                    "-coverpkg",
                    "-exec",
                    "-gccgoflags",
                    "-gcflags",
                    "-installsuffix",
                    "-ldflags",
                    "-mod",
                    "-modfile",
                    "-overlay",
                    "-p",
                    "-pgo",
                    "-pkgdir",
                    "-tags",
                    "-toolexec",
                ],
                &["-C"],
            )
            .map(|(index, value)| (index + 1, value)) else {
                return Vec::new();
            };
            return match value {
                Some(value) if value.ends_with(".go") => argv[argument..]
                    .iter()
                    .map_while(literal)
                    .take_while(|value| value.ends_with(".go"))
                    .map(LaunchedSource::Literal)
                    .collect(),
                Some(_) => Vec::new(),
                None => vec![LaunchedSource::Dynamic { argument }],
            };
        }
        "java" => (
            program_operand(
                argv,
                &[
                    "--class-path",
                    "-classpath",
                    "-cp",
                    "--module-path",
                    "-p",
                    "--source",
                ],
                &[],
            ),
            &["java"][..],
        ),
        "rust-script" => (program_operand(argv, &[], &[]), &["rs"][..]),
        _ => return Vec::new(),
    };
    let Some((argument, value)) = operand else {
        return Vec::new();
    };
    match value {
        Some(value) => {
            let Some((_, ext)) = value.rsplit_once('.') else {
                return Vec::new();
            };
            if expected.contains(&ext) {
                vec![LaunchedSource::Literal(value)]
            } else {
                Vec::new()
            }
        }
        None => vec![LaunchedSource::Dynamic { argument }],
    }
}

fn python_module_operand(argv: &[ResourceExpr]) -> Option<&str> {
    let mut index = 0;
    while index < argv.len() {
        let argument = literal(&argv[index])?;
        if argument == "-m" {
            return argv.get(index + 1).and_then(literal);
        }
        if let Some(module) = argument
            .strip_prefix("-m")
            .filter(|module| !module.is_empty())
        {
            return Some(module);
        }
        if matches!(argument, "-W" | "-X" | "--check-hash-based-pycs") {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return None;
        }
    }
    None
}

fn engine_nests_source(executable: &str) -> bool {
    matches!(
        executable,
        "python"
            | "python2"
            | "python3"
            | "node"
            | "nodejs"
            | "iojs"
            | "tsx"
            | "ts-node"
            | "bun"
            | "deno"
            | "php"
            | "php7"
            | "php8"
            | "ruby"
            | "irb"
            | "go"
            | "java"
            | "rust-script"
    )
}

fn program_operand<'a>(
    argv: &'a [ResourceExpr],
    value_flags: &[&str],
    blocked: &[&str],
) -> Option<(usize, Option<&'a str>)> {
    let mut index = 0;
    while index < argv.len() {
        // Shell wrappers commonly splice an unset `*_ARGS` environment word
        // before the program. It contributes no source candidate of its own;
        // the next operand still has to carry bounded program evidence.
        if matches!(&argv[index], ResourceExpr::Environment { name } if name.ends_with("_ARGS")) {
            index += 1;
            continue;
        }
        match literal(&argv[index]) {
            Some("--") => return argv.get(index + 1).map(|value| (index + 1, literal(value))),
            Some(value) if blocked.contains(&value) => return None,
            Some(value) if blocked.iter().any(|flag| has_attached_value(value, flag)) => {
                return None;
            }
            Some(flag) if value_flags.contains(&flag) => index += 2,
            Some(flag) if flag.starts_with('-') => index += 1,
            Some(value) => return Some((index, Some(value))),
            None => return Some((index, None)),
        }
    }
    None
}

fn has_attached_value(argument: &str, flag: &str) -> bool {
    if flag == "-" {
        return false;
    }
    argument
        .strip_prefix(flag)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !flag.starts_with("--") || value.starts_with('='))
}

fn literal(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Literal { value } => Some(value),
        _ => None,
    }
}

fn invocation_executable<'a>(
    plan: &'a effinterp_proto::Plan,
    roots: &[ProvenanceRef],
) -> Option<&'a str> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let node = plan.provenance.get(reference.0 as usize)?;
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(execution) = plan.execution_graph.nodes.get(execution as usize)
            && let Subject::Exec { argv, .. } = &execution.subject
        {
            return argv.first().map(String::as_str);
        }
        pending.extend(node.antecedents.iter().copied());
    }
    None
}

/// Literal source paths retained in shell assignments before a bounded value
/// becomes symbolic (for example a path built from `dirname "$0"`). More than
/// four candidates is intentionally not a bounded alternative.
fn static_source_specs(
    plan: &effinterp_proto::Plan,
    roots: &[ProvenanceRef],
    source: &str,
    executable: &str,
    argument: usize,
) -> Vec<StaticSourceSpec> {
    let expected = match executable {
        "python" | "python2" | "python3" => &["py"][..],
        "node" | "nodejs" | "iojs" | "tsx" | "ts-node" | "bun" | "deno" => {
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..]
        }
        "php" | "php7" | "php8" => &["php"][..],
        "ruby" | "irb" => &["rb"][..],
        "go" => &["go"][..],
        "java" => &["java"][..],
        "rust-script" => &["rs"][..],
        _ => return Vec::new(),
    };
    let roots = program_assignment_roots(plan, roots, source, argument);
    if roots.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let spans = source_spans(plan, &roots, source.len());
    let wrapper_relative = source_spans_reference_wrapper(source, &spans);
    for extension in expected {
        let suffix = format!(".{extension}");
        for (span_start, span_end) in &spans {
            let Some(span) = source.get(*span_start..*span_end) else {
                continue;
            };
            let mut offset = 0;
            while let Some(found) = span[offset..].find(&suffix) {
                let end = offset + found + suffix.len();
                if inside_shell_substitution(span, offset + found) {
                    offset = end;
                    continue;
                }
                let mut start = end - suffix.len();
                while start > 0 {
                    let byte = span.as_bytes()[start - 1];
                    if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
                        start -= 1;
                    } else {
                        break;
                    }
                }
                if start < end - suffix.len() {
                    let raw = &span[start..end];
                    if source_token_is_substitution_suffix(span, start) {
                        offset = end;
                        continue;
                    }
                    let candidate = raw
                        .strip_prefix('/')
                        .filter(|rest| rest.starts_with("../"))
                        .unwrap_or(raw)
                        .to_string();
                    let candidate = StaticSourceSpec {
                        path: candidate,
                        wrapper_relative,
                    };
                    if !out.contains(&candidate) {
                        out.push(candidate);
                    }
                }
                if out.len() > 4 {
                    return Vec::new();
                }
                offset = end;
            }
        }
    }
    out.sort_by(|left, right| left.path.cmp(&right.path));
    out.dedup();
    out
}

#[derive(Clone, PartialEq, Eq)]
struct StaticSourceSpec {
    path: String,
    wrapper_relative: bool,
}

fn source_spans_reference_wrapper(source: &str, spans: &[(usize, usize)]) -> bool {
    for (start, end) in spans {
        let Some(span) = source.get(*start..*end) else {
            continue;
        };
        if !span.contains("dirname") {
            continue;
        }
        if span.contains("$0") || span.contains("${0}") {
            return true;
        }
        if shell_variables(span)
            .into_iter()
            .any(|name| shell_assignment_references_script(source, name))
        {
            return true;
        }
    }
    false
}

fn shell_variables(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(found) = source[index..].find('$') {
        let start = index + found + 1;
        let braced = bytes.get(start) == Some(&b'{');
        let name_start = start + usize::from(braced);
        let mut end = name_start;
        while bytes
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            end += 1;
        }
        if end > name_start && (!braced || bytes.get(end) == Some(&b'}')) {
            out.push(&source[name_start..end]);
        }
        index = end.max(start);
    }
    out
}

fn shell_assignment_references_script(source: &str, name: &str) -> bool {
    source.lines().any(|line| {
        line.trim_start()
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .is_some_and(|value| value.contains("$0") || value.contains("${0}"))
    })
}

fn source_token_is_substitution_suffix(source: &str, position: usize) -> bool {
    position > 0
        && matches!(source.as_bytes()[position - 1], b')' | b'`')
        && !source[position..].starts_with('/')
}

fn inside_shell_substitution(source: &str, position: usize) -> bool {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut depth = 0;
    let mut backtick = false;
    while index < position.min(bytes.len()) {
        if bytes[index] == b'`' && (index == 0 || bytes[index - 1] != b'\\') {
            backtick = !backtick;
        } else if !backtick && bytes[index..].starts_with(b"$(") {
            depth += 1;
            index += 1;
        } else if !backtick && depth > 0 && bytes[index] == b')' {
            depth -= 1;
        }
        index += 1;
    }
    backtick || depth > 0
}

fn program_assignment_roots(
    plan: &effinterp_proto::Plan,
    roots: &[ProvenanceRef],
    source: &str,
    argument: usize,
) -> Vec<ProvenanceRef> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(execution) = plan.execution_graph.nodes.get(execution as usize)
            && let Subject::Exec { argv, .. } = &execution.subject
            && let Some(name) = argv.get(argument).and_then(|raw| shell_parameter(raw))
        {
            return node
                .antecedents
                .iter()
                .copied()
                .filter(|reference| assignment_name(plan, *reference, source) == Some(name))
                .collect();
        }
        pending.extend(node.antecedents.iter().copied());
    }
    Vec::new()
}

fn shell_parameter(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix('"')
        .and_then(|raw| raw.strip_suffix('"'))
        .unwrap_or(raw);
    let name = raw
        .strip_prefix("${")
        .and_then(|raw| raw.strip_suffix('}'))
        .or_else(|| raw.strip_prefix('$'))?;
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()))
    .then_some(name)
}

fn assignment_name<'a>(
    plan: &effinterp_proto::Plan,
    reference: ProvenanceRef,
    source: &'a str,
) -> Option<&'a str> {
    let node = plan.provenance.get(reference.0 as usize)?;
    let ProvenanceKind::SourceSpan { start, end } = node.kind else {
        return None;
    };
    let span = source.get(start as usize..end as usize)?;
    let (name, _) = span.split_once('=')?;
    let name = name.trim();
    let name = name.strip_suffix('+').unwrap_or(name);
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()))
    .then_some(name)
}

fn source_spans(
    plan: &effinterp_proto::Plan,
    roots: &[ProvenanceRef],
    source_len: usize,
) -> Vec<(usize, usize)> {
    let mut invocation_spans = std::collections::HashSet::new();
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(execution) = plan.execution_graph.nodes.get(execution as usize)
        {
            invocation_spans.extend(execution.evidence.iter().copied());
        }
        pending.extend(node.antecedents.iter().copied());
    }
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    let mut spans = Vec::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if !invocation_spans.contains(&reference)
            && let ProvenanceKind::SourceSpan { start, end } = node.kind
        {
            spans.push((
                (start as usize).min(source_len),
                (end as usize).min(source_len),
            ));
        }
        pending.extend(node.antecedents.iter().copied());
    }
    spans.sort();
    spans.dedup();
    spans
}

fn repository_cwd(expr: Option<&ResourceExpr>) -> Option<String> {
    match expr {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) if !path.starts_with('/') => join_rel_path("", path),
        _ => None,
    }
}

fn resolve_repo_source(
    ctx: &EntrypointCrawl,
    root: &Path,
    from_dir: &str,
    spec: &str,
    require_shebang: bool,
) -> Option<String> {
    if from_dir.starts_with('/') || spec.starts_with('/') {
        return None;
    }
    let joined = join_rel_path(from_dir, spec)?;
    if !ctx.manifest.iter().any(|input| input.path == joined) {
        return None;
    }
    let source = std::fs::read_to_string(root.join(&joined)).ok()?;
    if require_shebang && !source.starts_with("#!") {
        return None;
    }
    source_language_evidence(&joined, &source).map(|_| joined)
}

pub(super) fn source_language(path: &str) -> Option<&'static str> {
    match path.rsplit_once('.')?.1 {
        "py" => Some("python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("js"),
        "ts" | "mts" | "cts" | "tsx" => Some("ts"),
        "php" => Some("php"),
        "rb" => Some("ruby"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "java" => Some("java"),
        "sh" => Some("shell"),
        _ => None,
    }
}

fn source_language_evidence(path: &str, source: &str) -> Option<&'static str> {
    source_language(path).or_else(|| {
        let shebang = source.lines().next()?.strip_prefix("#!")?;
        match interpreter(shebang)?.as_str() {
            "sh" | "bash" | "dash" | "zsh" => Some("shell"),
            "python" | "python2" | "python3" => Some("python"),
            "node" | "nodejs" => Some("js"),
            "tsx" | "ts-node" | "bun" | "deno" => Some("ts"),
            "php" => Some("php"),
            "ruby" => Some("ruby"),
            _ => None,
        }
    })
}

fn source_line(plan: &effinterp_proto::Plan, roots: &[ProvenanceRef], source: &str) -> Option<u32> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        let node = plan.provenance.get(reference.0 as usize)?;
        if !seen.insert(reference) {
            continue;
        }
        if let ProvenanceKind::SourceSpan { start, .. } = node.kind {
            let start = (start as usize).min(source.len());
            return Some(
                source.as_bytes()[..start]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count() as u32
                    + 1,
            );
        }
        pending.extend(node.antecedents.iter().copied());
    }
    None
}

fn add_local_source_program(
    ctx: &mut EntrypointCrawl,
    root: &Path,
    relpath: &str,
    runtime_cwd: Option<String>,
    contextual: bool,
    package_inits: Vec<String>,
) -> Option<String> {
    if !contextual
        && package_inits.is_empty()
        && let Some(entrypoint) = ctx.entrypoints.iter().find(|entry| {
            entry.source_file == relpath
                && entry.registration.is_none()
                && entry.package_inits.is_empty()
        })
    {
        return Some(entrypoint.id.clone());
    }
    if let Some(entrypoint) = ctx.entrypoints.iter().find(|entry| {
        entry.source_file == relpath
            && entry.registration.is_none()
            && entry.entry_function.is_none()
            && subject_cwd(&entry.subject) == runtime_cwd.as_deref()
            && entry.package_inits == package_inits
    }) {
        return Some(entrypoint.id.clone());
    }
    let Ok(source) = std::fs::read_to_string(root.join(relpath)) else {
        return None;
    };
    let source_cwd = relpath
        .rsplit_once('/')
        .map_or_else(String::new, |(dir, _)| dir.to_string());
    let language = source_language_evidence(relpath, &source)?;
    let subject = match language {
        "shell" => Subject::Shell {
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        "python" => Subject::Source {
            dialect: None,
            language: "python".into(),
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        "js" | "ts" => Subject::Source {
            language: "js".into(),
            source,
            dialect: Some(if language == "ts" {
                SourceDialect::Ts
            } else {
                SourceDialect::Js
            }),
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        "php" => Subject::Source {
            dialect: None,
            language: language.to_string(),
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        language => Subject::Source {
            dialect: None,
            language: language.to_string(),
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
    };
    let context = match runtime_cwd.as_deref() {
        Some("") => "root",
        Some(cwd) => cwd,
        None => "unknown",
    };
    let id = if !package_inits.is_empty() {
        format!("{relpath}:launch@{context}:python-m")
    } else {
        format!("{relpath}:launch@{context}")
    };
    ctx.entrypoints.push(Entrypoint {
        id: id.clone(),
        subject,
        source_file: relpath.to_string(),
        source_cwd: Some(source_cwd),
        evidence: EntrypointEvidence {
            kind: EntrypointKind::MainFile,
            file: relpath.to_string(),
            line: None,
        },
        entry_function: None,
        registration: None,
        package_inits,
        span_map: None,
    });
    Some(id)
}
