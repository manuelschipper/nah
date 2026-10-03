use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionEdgeKind, ExecutionInputReason, ExecutionInputRole, ExecutionNodeRef,
    ExecutionPhase, ExecutionRealm, ExecutionSelector, Modality, Operation, PathPlatform,
    ProvenanceKind, ProvenanceRef, ResourceExpr, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::{self, FlagSpec};
use crate::models::common::{
    RuntimeSourceLanguage, arg_effect, arg_node, program_input_attrs, program_output_attrs,
    runtime_searched_source, runtime_selected_source, runtime_unobserved_input,
};
use crate::models::{CommandModel, InvocationCtx, source_refusal_detail};
use crate::nest::{SourceResolution, Transition};
use crate::value::unresolved_resource;
use crate::word::Word;

pub(super) fn build_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Make),
        Box::new(Just),
        Box::new(Task),
        Box::new(Cargo),
        Box::new(Javac),
        Box::new(Maven),
        Box::new(Gradle),
    ]
}

struct BuildToolContext {
    runtime_cwd: Option<String>,
    cwd: Option<String>,
    cwd_resource: Option<ResourceExpr>,
}

impl BuildToolContext {
    fn new(ctx: &InvocationCtx<'_>) -> Self {
        Self {
            runtime_cwd: ctx.runtime_cwd.map(str::to_string),
            cwd: ctx.cwd.map(str::to_string),
            cwd_resource: ctx.cwd_resource(),
        }
    }

    fn descend(&mut self, directory: &str) -> bool {
        let Some(runtime_cwd) =
            crate::paths::join_relative_file(self.runtime_cwd.as_deref(), directory)
        else {
            return false;
        };
        self.runtime_cwd = Some(runtime_cwd);
        self.cwd = self
            .cwd
            .as_deref()
            .map(|cwd| crate::paths::join_cwd(cwd, directory));
        self.cwd_resource = Some(effinterp_proto::filesystem_path(
            directory,
            self.cwd_resource.take(),
            PathPlatform::Posix,
        ));
        true
    }
}

fn unresolved_build_target(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    detail: impl Into<String>,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRESOLVED_BUILD_TARGET,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("process"), Domain::new("filesystem")],
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.into()),
    });
}

fn resolve_from(
    ctx: &InvocationCtx<'_>,
    builder: &mut PlanBuilder,
    source_cwd: Option<&str>,
    path: &str,
) -> SourceResolution {
    let Some((_namespace, path)) = crate::paths::join_source_path(source_cwd, path) else {
        return SourceResolution::Unavailable;
    };
    ctx.resolve_source_file(builder, &path, SourcePurpose::InvocationInput)
}

fn resolve_first<'a>(
    ctx: &InvocationCtx<'_>,
    builder: &mut PlanBuilder,
    source_cwd: Option<&str>,
    paths: impl IntoIterator<Item = &'a str>,
) -> SourceResolution {
    let mut unavailable = SourceResolution::Unavailable;
    for path in paths {
        match resolve_from(ctx, builder, source_cwd, path) {
            source @ SourceResolution::Source { .. } => return source,
            refused @ SourceResolution::Refused(crate::SourceRefusal::Limit { .. }) => {
                return refused;
            }
            other => unavailable = other,
        }
    }
    unavailable
}

fn resolved_build_source(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    resolved: SourceResolution,
    detail: &str,
) -> Option<(String, String)> {
    match resolved {
        SourceResolution::Source { origin, source } => Some((origin, source)),
        SourceResolution::Refused(refusal) => {
            if let Some(detail) = source_refusal_detail(builder, refusal, detail) {
                unresolved_build_target(builder, model_node, detail);
            }
            None
        }
        SourceResolution::UnsupportedEncoding => {
            unresolved_build_target(
                builder,
                model_node,
                format!("{detail}: source is not valid UTF-8"),
            );
            None
        }
        SourceResolution::AlreadySelected => None,
        SourceResolution::Unavailable => {
            unresolved_build_target(builder, model_node, detail);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn nest_shell_lines(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    provenance: &[ProvenanceRef],
    origin: &str,
    build: &BuildToolContext,
    lines: Vec<ShellLine>,
    detail: &str,
) {
    let mut widened = false;
    for line in lines {
        let Some(source) = line.source else {
            if let Some(refusal) = line.refusal {
                unresolved_build_target(builder, model_node, refusal);
                continue;
            }
            widened = true;
            continue;
        };
        let mut provenance = provenance.to_vec();
        let source_span_offset = line.source_span.map_or(0, |(start, end)| {
            let source_node = builder.node(ProvenanceKind::SourceSpan { start, end }, &provenance);
            provenance.push(source_node);
            start
        });
        {
            let cwd_resource = build.cwd_resource.clone();
            let cwd_node = (cwd_resource.as_ref() == ctx.cwd_resource.as_ref())
                .then_some(ctx.cwd_node)
                .flatten();
            ctx.nest.nest(
                builder,
                Transition::file(Subject::Shell {
                    source,
                    cwd: build.cwd.clone(),
                    context: Default::default(),
                })
                .origin(origin.to_string())
                .kind(ExecutionEdgeKind::BuildTarget)
                .source_cwd(build.runtime_cwd.as_deref())
                .runtime_cwd(build.runtime_cwd.as_deref())
                .cwd(cwd_resource, cwd_node)
                .source_span_offset((source_span_offset) as usize),
                &provenance,
                ctx.depth,
            );
        };
    }
    if widened {
        unresolved_build_target(builder, model_node, detail);
    }
}

struct ShellLine {
    refusal: Option<String>,
    source: Option<String>,
    source_span: Option<(u32, u32)>,
}

fn unlocated_shell_lines(lines: Vec<Option<String>>) -> Vec<ShellLine> {
    lines
        .into_iter()
        .map(|source| ShellLine {
            refusal: None,
            source,
            source_span: None,
        })
        .collect()
}

fn nest_program(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    provenance: &[ProvenanceRef],
    origin: String,
    source: String,
    language: &str,
    build: &BuildToolContext,
) {
    {
        let cwd_resource = build.cwd_resource.clone();
        let cwd_node = (cwd_resource.as_ref() == ctx.cwd_resource.as_ref())
            .then_some(ctx.cwd_node)
            .flatten();
        ctx.nest.nest(
            builder,
            Transition::file(Subject::Source {
                dialect: None,
                language: language.to_string(),
                source,
                cwd: build.cwd.clone(),
                context: Default::default(),
            })
            .origin(origin)
            .kind(ExecutionEdgeKind::BuildTarget)
            .source_cwd(build.runtime_cwd.as_deref())
            .runtime_cwd(build.runtime_cwd.as_deref())
            .cwd(cwd_resource, cwd_node),
            provenance,
            ctx.depth,
        );
    };
}

struct Make;

impl CommandModel for Make {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/make@v8"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["make", "gmake"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let Ok(invocation) = make_invocation(ctx) else {
            unresolved_build_target(
                builder,
                model_node,
                "make options are not statically supported",
            );
            return;
        };
        let mut build = BuildToolContext::new(ctx);
        for directory in &invocation.directories {
            if !build.descend(directory) {
                unresolved_build_target(
                    builder,
                    model_node,
                    "make -C directory is not repository-relative",
                );
                return;
            }
        }
        let files = invocation
            .file
            .as_deref()
            .map(|file| vec![file])
            .unwrap_or_else(|| vec!["GNUmakefile", "makefile", "Makefile"]);
        let resolved = resolve_first(ctx, builder, build.runtime_cwd.as_deref(), files);
        let Some((origin, source)) =
            resolved_build_source(builder, model_node, resolved, "makefile is not recoverable")
        else {
            return;
        };
        let arg = arg_node(
            builder,
            ctx,
            invocation
                .targets
                .first()
                .map_or(0, |(index, _)| *index as u32),
        );
        let read = builder.node(
            ProvenanceKind::ToolArgument {
                name: origin.clone(),
            },
            &[model_node, arg],
        );
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("filesystem.read"),
            resource: effinterp_proto::filesystem_path(
                invocation
                    .file
                    .as_deref()
                    .unwrap_or_else(|| origin.rsplit('/').next().unwrap()),
                build.cwd_resource.clone(),
                PathPlatform::Posix,
            ),
            attributes: Default::default(),
            modality: Modality::May,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: vec![model_node, arg, read],
        });
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        if source.lines().any(|line| {
            if line.starts_with('\t') {
                return false;
            }
            let line = line
                .split_once('#')
                .map_or(line, |(before, _)| before)
                .trim();
            let Some((targets, prerequisites)) = line.split_once(':') else {
                return false;
            };
            !prerequisites.trim_start().starts_with('=')
                && targets
                    .split_whitespace()
                    .any(|target| target == ".ONESHELL")
        }) {
            unresolved_build_target(builder, model_node, "make .ONESHELL recipe is not modeled");
            return;
        }

        let targets = if invocation.targets.is_empty() {
            vec![(None, None)]
        } else {
            invocation
                .targets
                .iter()
                .map(|(index, target)| (Some(*index), Some(target.as_str())))
                .collect()
        };
        for (target_index, target) in targets {
            let Some((selected_target, lines)) = make_recipe(&source, target) else {
                unresolved_build_target(
                    builder,
                    model_node,
                    format!(
                        "make target {:?} is not recoverable",
                        target.unwrap_or("<default>")
                    ),
                );
                continue;
            };
            let identity = builder.node(
                ProvenanceKind::ToolArgument {
                    name: format!("{origin}:{selected_target}"),
                },
                &[read],
            );
            let mut provenance = vec![model_node, arg, read, identity];
            if let Some(index) = target_index {
                provenance.push(arg_node(builder, ctx, index as u32));
            }
            let previous = ctx.nest.source_resolution_disabled.replace(true);
            nest_shell_lines(
                builder,
                ctx,
                model_node,
                &provenance,
                &origin,
                &build,
                lines,
                &format!(
                    "make target {:?} contains make expansion or continuation",
                    target.unwrap_or("<default>")
                ),
            );
            ctx.nest.source_resolution_disabled.set(previous);
        }
    }
}

struct MakeInvocation {
    directories: Vec<String>,
    file: Option<String>,
    targets: Vec<(usize, String)>,
}

fn make_invocation(ctx: &InvocationCtx<'_>) -> Result<MakeInvocation, ()> {
    let mut out = MakeInvocation {
        directories: Vec::new(),
        file: None,
        targets: Vec::new(),
    };
    let mut index = 1;
    let mut options = true;
    while index < ctx.argv.len() {
        let value = ctx.argv[index].as_literal().ok_or(())?;
        if options && value == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options {
            if matches!(value, "-C" | "--directory" | "-f" | "--file" | "--makefile") {
                let operand = ctx
                    .argv
                    .get(index + 1)
                    .and_then(|word| word.as_literal())
                    .ok_or(())?;
                if matches!(value, "-C" | "--directory") {
                    out.directories.push(operand.to_string());
                } else {
                    out.file = Some(operand.to_string());
                }
                index += 2;
                continue;
            }
            if let Some(operand) = value.strip_prefix("--directory=") {
                out.directories.push(operand.to_string());
                index += 1;
                continue;
            }
            if let Some(operand) = value
                .strip_prefix("--file=")
                .or_else(|| value.strip_prefix("--makefile="))
            {
                out.file = Some(operand.to_string());
                index += 1;
                continue;
            }
            if let Some(operand) = value.strip_prefix("-C").filter(|value| !value.is_empty()) {
                out.directories.push(operand.to_string());
                index += 1;
                continue;
            }
            if let Some(operand) = value.strip_prefix("-f").filter(|value| !value.is_empty()) {
                out.file = Some(operand.to_string());
                index += 1;
                continue;
            }
            if matches!(
                value,
                "-I" | "--include-dir"
                    | "-o"
                    | "--old-file"
                    | "--assume-old"
                    | "-W"
                    | "--what-if"
                    | "--new-file"
                    | "--assume-new"
                    | "--jobserver-auth"
                    | "--jobserver-fds"
                    | "--output-sync"
            ) {
                ctx.argv
                    .get(index + 1)
                    .and_then(|word| word.as_literal())
                    .ok_or(())?;
                index += 2;
                continue;
            }
            if matches!(value, "-j" | "--jobs" | "-l" | "--load-average" | "-O") {
                index += 1;
                if ctx
                    .argv
                    .get(index)
                    .and_then(|word| word.as_literal())
                    .is_some_and(|operand| operand.parse::<f64>().is_ok())
                {
                    index += 1;
                }
                continue;
            }
            if value.starts_with("-j")
                || value.starts_with("-l")
                || value.starts_with("-O")
                || value.starts_with("-I")
                || value.starts_with("-o")
                || value.starts_with("-W")
                || value.starts_with("--jobs=")
                || value.starts_with("--load-average=")
                || value.starts_with("--output-sync=")
            {
                index += 1;
                continue;
            }
            if matches!(
                value,
                "-B" | "--always-make"
                    | "-d"
                    | "--debug"
                    | "-e"
                    | "--environment-overrides"
                    | "-i"
                    | "--ignore-errors"
                    | "-k"
                    | "--keep-going"
                    | "-r"
                    | "--no-builtin-rules"
                    | "-R"
                    | "--no-builtin-variables"
                    | "-s"
                    | "--silent"
                    | "--quiet"
                    | "-S"
                    | "--no-keep-going"
                    | "--trace"
                    | "-w"
                    | "--print-directory"
                    | "--no-print-directory"
                    | "--warn-undefined-variables"
            ) {
                index += 1;
                continue;
            }
            if matches!(
                value,
                "-n" | "--just-print"
                    | "--dry-run"
                    | "--recon"
                    | "-q"
                    | "--question"
                    | "-t"
                    | "--touch"
                    | "--eval"
            ) {
                return Err(());
            }
            if value.starts_with('-') {
                return Err(());
            }
        }
        if !value.contains('=') {
            out.targets.push((index, value.to_string()));
        }
        index += 1;
    }
    Ok(out)
}

fn make_recipe(source: &str, requested: Option<&str>) -> Option<(String, Vec<ShellLine>)> {
    let mut offset = 0u32;
    let lines: Vec<(u32, &str)> = source
        .split_inclusive('\n')
        .map(|raw| {
            let line = raw.trim_end_matches(['\n', '\r']);
            let line_offset = offset;
            offset += raw.len() as u32;
            (line_offset, line)
        })
        .collect();
    let line_text: Vec<&str> = lines.iter().map(|(_, line)| *line).collect();
    if line_text
        .iter()
        .any(|line| unsupported_make_directive(line))
    {
        return None;
    }
    let default_goal = if requested.is_none() {
        make_default_goal(&line_text)?
    } else {
        None
    };
    let mut selected_target = requested.or(default_goal.as_deref()).map(str::to_string);
    let mut selected_recipe = None;
    let mut index = 0;
    while index < lines.len() {
        let (_, line) = lines[index];
        let header = line
            .split_once('#')
            .map_or(line, |(header, _)| header)
            .trim();
        if !line.starts_with('\t')
            && let Some((targets, prerequisites)) = header.split_once(':')
            && !targets.contains('=')
            && !prerequisites.trim_start().starts_with('=')
        {
            let names: Vec<_> = targets.split_whitespace().collect();
            let selected = if let Some(requested) = selected_target.as_deref() {
                names.contains(&requested)
            } else {
                let selected = names
                    .iter()
                    .find(|target| !target.starts_with('.') && !target.contains('%'));
                if let Some(selected) = selected {
                    selected_target = Some((*selected).to_string());
                }
                selected.is_some()
            };
            if !selected {
                index += 1;
                continue;
            }
            if names.iter().any(|target| target.contains(['$', '%']))
                || targets.trim_end().ends_with('&')
                || prerequisites.starts_with(':')
                || !prerequisites.trim().is_empty()
                || line.ends_with('\\')
            {
                return None;
            }
            let mut recipe = Vec::new();
            let mut continuation = false;
            index += 1;
            while index < lines.len() {
                let (line_offset, line) = lines[index];
                if line.trim().is_empty()
                    || (!line.starts_with('\t') && line.trim_start().starts_with('#'))
                {
                    index += 1;
                    continue;
                }
                if !line.starts_with('\t') {
                    break;
                }
                let mut command = line.trim_start_matches('\t');
                loop {
                    command = command.trim_start();
                    let Some(rest) = command
                        .strip_prefix('@')
                        .or_else(|| command.strip_prefix('-'))
                        .or_else(|| command.strip_prefix('+'))
                    else {
                        break;
                    };
                    command = rest;
                }
                if !command.is_empty() {
                    if continuation {
                        continuation = command.ends_with('\\');
                    } else if command.ends_with('\\') {
                        recipe.push(ShellLine {
                            refusal: make_line_refusal(command),
                            source: None,
                            source_span: None,
                        });
                        continuation = true;
                    } else {
                        let start = line_offset + (line.len() - command.len()) as u32;
                        let refusal = make_line_refusal(command);
                        recipe.push(ShellLine {
                            source: if refusal.is_some() {
                                None
                            } else {
                                make_shell_line(command)
                            },
                            refusal,
                            source_span: Some((start, start + command.len() as u32)),
                        });
                    }
                }
                index += 1;
            }
            if !recipe.is_empty() || selected_recipe.is_none() {
                selected_recipe = Some(recipe);
            }
            continue;
        }
        index += 1;
    }
    Some((selected_target?, selected_recipe?))
}

fn unsupported_make_directive(line: &str) -> bool {
    if line.starts_with('\t') {
        return false;
    }
    let line = line
        .split_once('#')
        .map_or(line, |(before, _)| before)
        .trim();
    let directive = line.split_whitespace().next().unwrap_or_default();
    matches!(
        directive,
        "ifeq"
            | "ifneq"
            | "ifdef"
            | "ifndef"
            | "else"
            | "endif"
            | "include"
            | "-include"
            | "sinclude"
            | "define"
            | "endef"
            | "override"
            | "export"
            | "unexport"
            | "private"
            | "vpath"
    ) || line.starts_with(".RECIPEPREFIX")
        || make_shell_assignment(line)
}

fn make_shell_assignment(line: &str) -> bool {
    let line = line
        .strip_prefix("override ")
        .or_else(|| line.strip_prefix("export "))
        .unwrap_or(line)
        .trim_start();
    ["SHELL", ".SHELLFLAGS"].iter().any(|name| {
        line.strip_prefix(name).is_some_and(|rest| {
            let rest = rest.trim_start();
            ["::=", ":=", "?=", "+=", "!=", "="]
                .iter()
                .any(|operator| rest.starts_with(operator))
        })
    })
}

fn make_default_goal(lines: &[&str]) -> Option<Option<String>> {
    let mut default = None;
    for line in lines {
        if line.starts_with('\t') {
            continue;
        }
        let line = line
            .split_once('#')
            .map_or(*line, |(before, _)| before)
            .trim();
        let Some(rest) = line.strip_prefix(".DEFAULT_GOAL") else {
            continue;
        };
        let value = rest
            .trim_start()
            .strip_prefix(":=")
            .or_else(|| rest.trim_start().strip_prefix('='))?
            .trim();
        if value.is_empty() {
            default = None;
        } else if value.split_whitespace().count() == 1 && !value.contains(['$', '%']) {
            default = Some(value.to_string());
        } else {
            return None;
        }
    }
    Some(default)
}

fn make_line_refusal(line: &str) -> Option<String> {
    if matches!(
        line.split_whitespace().next(),
        Some("$(MAKE)" | "${MAKE}" | "make" | "gmake")
    ) {
        return Some("recursive make is not followed".to_string());
    }
    let mut chars = line.char_indices();
    while let Some((index, ch)) = chars.next() {
        if ch != '$' {
            continue;
        }
        match chars.next() {
            Some((_, '$')) => continue,
            Some((_, opener @ ('(' | '{'))) => {
                let closer = if opener == '(' { ')' } else { '}' };
                let end = line[index..]
                    .find(closer)
                    .map_or(line.len(), |end| index + end + 1);
                return Some(format!(
                    "make recipe contains expansion {}",
                    &line[index..end]
                ));
            }
            Some((next, ch)) => {
                return Some(format!(
                    "make recipe contains expansion {}",
                    &line[index..next + ch.len_utf8()]
                ));
            }
            None => return Some("make recipe contains expansion $".to_string()),
        }
    }
    line.ends_with('\\')
        .then(|| "make recipe contains continuation".to_string())
}

fn make_shell_line(line: &str) -> Option<String> {
    if line.ends_with('\\') {
        return None;
    }
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }
        if chars.next() == Some('$') {
            out.push('$');
        } else {
            return None;
        }
    }
    Some(out)
}

struct Just;

impl CommandModel for Just {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/just@v6"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["just"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let Ok((file, directories, target)) = just_invocation(ctx) else {
            unresolved_build_target(
                builder,
                model_node,
                "just options are not statically supported",
            );
            return;
        };
        let mut build = BuildToolContext::new(ctx);
        let files = file
            .as_deref()
            .map(|file| vec![file])
            .unwrap_or_else(|| vec!["justfile", "Justfile"]);
        let resolved = resolve_first(ctx, builder, build.runtime_cwd.as_deref(), files);
        let Some((origin, source)) =
            resolved_build_source(builder, model_node, resolved, "justfile is not recoverable")
        else {
            return;
        };
        let Some(recipe) = just_recipe(
            &source,
            target
                .as_ref()
                .map(|(_, value, arguments)| (value.as_str(), *arguments)),
        ) else {
            unresolved_build_target(builder, model_node, "just recipe is not recoverable");
            return;
        };
        if !recipe.no_cd {
            if directories.is_empty() {
                if let Some(directory) = file
                    .as_deref()
                    .and_then(|file| file.rsplit_once('/').map(|(directory, _)| directory))
                    .filter(|directory| !directory.is_empty())
                    && !build.descend(directory)
                {
                    unresolved_build_target(
                        builder,
                        model_node,
                        "justfile directory is not repository-relative",
                    );
                    return;
                }
            } else {
                for directory in directories {
                    if !build.descend(&directory) {
                        unresolved_build_target(
                            builder,
                            model_node,
                            "just working directory is not repository-relative",
                        );
                        return;
                    }
                }
            }
            for directory in &recipe.working_directories {
                if !build.descend(directory) {
                    unresolved_build_target(
                        builder,
                        model_node,
                        "just recipe working directory is not repository-relative",
                    );
                    return;
                }
            }
        }
        let mut provenance = vec![model_node];
        if let Some((index, _, _)) = target {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
        nest_shell_lines(
            builder,
            ctx,
            model_node,
            &provenance,
            &origin,
            &build,
            unlocated_shell_lines(recipe.commands),
            "just recipe contains unresolved interpolation",
        );
    }
}

/// Justfile path, `--directory` operands, and the target's index, name, and argv position.
type JustInvocation = (Option<String>, Vec<String>, Option<(usize, String, usize)>);

fn just_invocation(ctx: &InvocationCtx<'_>) -> Result<JustInvocation, ()> {
    let mut file = None;
    let mut directories = Vec::new();
    let mut target = None;
    let mut index = 1;
    while index < ctx.argv.len() {
        let value = ctx.argv[index].as_literal().ok_or(())?;
        if matches!(value, "-f" | "--justfile" | "-d" | "--working-directory") {
            let operand = ctx
                .argv
                .get(index + 1)
                .and_then(|word| word.as_literal())
                .ok_or(())?;
            if matches!(value, "-f" | "--justfile") {
                file = Some(operand.to_string());
            } else {
                directories.push(operand.to_string());
            }
            index += 2;
        } else if let Some(operand) = value.strip_prefix("--justfile=") {
            file = Some(operand.to_string());
            index += 1;
        } else if let Some(operand) = value.strip_prefix("--working-directory=") {
            directories.push(operand.to_string());
            index += 1;
        } else if value.starts_with('-') {
            return Err(());
        } else {
            target = Some((index, value.to_string(), ctx.argv.len() - index - 1));
            break;
        }
    }
    if !directories.is_empty() && file.is_none() {
        return Err(());
    }
    Ok((file, directories, target))
}

struct BuildRecipe {
    commands: Vec<Option<String>>,
    working_directories: Vec<String>,
    no_cd: bool,
}

fn just_recipe(source: &str, requested: Option<(&str, usize)>) -> Option<BuildRecipe> {
    let lines: Vec<&str> = source.lines().collect();
    let mut default_working_directory = None;
    for line in &lines {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed
            .strip_prefix("set shell")
            .is_some_and(|rest| rest.trim_start().starts_with(":="))
        {
            return None;
        }
        if let Some(directory) = just_setting_working_directory(trimmed) {
            if default_working_directory.is_some() {
                return None;
            }
            default_working_directory = Some(directory);
        }
    }
    let mut index = 0;
    let mut working_directory = None;
    let mut no_cd = false;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if !line.starts_with(char::is_whitespace) && trimmed.starts_with('[') {
            let attributes = just_attributes(trimmed)?;
            if let Some(directory) = attributes.working_directory {
                working_directory = Some(directory);
            }
            no_cd |= attributes.no_cd;
            index += 1;
            continue;
        }
        let header_line = line.strip_prefix('@').unwrap_or(line);
        if !line.starts_with(char::is_whitespace)
            && !header_line.starts_with('#')
            && let Some((header, dependencies)) = header_line.split_once(':')
            && !dependencies.trim_start().starts_with('=')
            && let Some(name) = header.split_whitespace().next()
            && requested.is_none_or(|(requested, _)| requested == name)
        {
            if !dependencies.trim().is_empty() {
                return None;
            }
            let arguments = requested.map_or(0, |(_, arguments)| arguments);
            if !just_arguments_match(header, arguments) {
                return None;
            }
            let mut working_directories = Vec::new();
            if !no_cd {
                for directory in [default_working_directory.clone(), working_directory.take()] {
                    match directory {
                        Some(Ok(directory)) => working_directories.push(directory),
                        Some(Err(())) => return None,
                        None => {}
                    }
                }
            }
            let mut recipe = Vec::new();
            index += 1;
            while index < lines.len()
                && (lines[index].starts_with(char::is_whitespace) || lines[index].trim().is_empty())
            {
                let mut command = lines[index].trim();
                if command.starts_with("#!") {
                    return None;
                }
                loop {
                    command = command.trim_start();
                    let Some(rest) = command
                        .strip_prefix('@')
                        .or_else(|| command.strip_prefix('-'))
                    else {
                        break;
                    };
                    command = rest;
                }
                if !command.is_empty() {
                    recipe.push((!command.contains("{{")).then(|| command.to_string()));
                }
                index += 1;
            }
            return Some(BuildRecipe {
                commands: recipe,
                working_directories,
                no_cd,
            });
        } else {
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                working_directory = None;
                no_cd = false;
            }
            index += 1;
        }
    }
    None
}

struct JustAttributes {
    working_directory: Option<Result<String, ()>>,
    no_cd: bool,
}

fn just_attributes(line: &str) -> Option<JustAttributes> {
    let line = line.strip_prefix('[')?;
    let (attributes, suffix) = line.rsplit_once(']')?;
    if !suffix.trim().is_empty() && !suffix.trim_start().starts_with('#') {
        return None;
    }
    let mut result = JustAttributes {
        working_directory: None,
        no_cd: false,
    };
    for attribute in attributes.split(',').map(str::trim) {
        if attribute == "no-cd" {
            result.no_cd = true;
        } else if attribute.starts_with("working-directory") {
            if result.working_directory.is_some() {
                return None;
            }
            result.working_directory = Some(just_working_directory(attribute));
        }
    }
    Some(result)
}

fn just_working_directory(attribute: &str) -> Result<String, ()> {
    let argument = attribute
        .strip_prefix("working-directory(")
        .and_then(|value| value.strip_suffix(')'))
        .map(str::trim)
        .ok_or(())?;
    unquote_exact(argument)
        .filter(|value| !value.contains(['\\', '\n', '\r']))
        .ok_or(())
}

fn just_setting_working_directory(line: &str) -> Option<Result<String, ()>> {
    let rest = line.strip_prefix("set working-directory")?;
    Some(
        rest.trim_start()
            .strip_prefix(":=")
            .map(str::trim)
            .ok_or(())
            .and_then(|value| {
                unquote_exact(value)
                    .filter(|value| !value.contains(['\\', '\n', '\r']))
                    .ok_or(())
            }),
    )
}

fn just_arguments_match(header: &str, arguments: usize) -> bool {
    let mut minimum = 0;
    let mut maximum = Some(0);
    for parameter in header.split_whitespace().skip(1) {
        if parameter.starts_with('*') {
            maximum = None;
        } else if parameter.starts_with('+') {
            minimum += 1;
            maximum = None;
        } else {
            if !parameter.contains('=') {
                minimum += 1;
            }
            if let Some(maximum) = &mut maximum {
                *maximum += 1;
            }
        }
    }
    arguments >= minimum && maximum.is_none_or(|maximum| arguments <= maximum)
}

struct Task;

impl CommandModel for Task {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/task@v6"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["task", "go-task"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let Ok((file, directory, target)) = task_invocation(ctx) else {
            unresolved_build_target(
                builder,
                model_node,
                "task options are not statically supported",
            );
            return;
        };
        let mut build = BuildToolContext::new(ctx);
        if file.is_none()
            && let Some(directory) = directory.as_deref()
            && !build.descend(directory)
        {
            unresolved_build_target(
                builder,
                model_node,
                "task working directory is not repository-relative",
            );
            return;
        }
        let files = file.as_deref().map(|file| vec![file]).unwrap_or_else(|| {
            vec![
                "Taskfile.yml",
                "Taskfile.yaml",
                "taskfile.yml",
                "taskfile.yaml",
            ]
        });
        let resolved = resolve_first(ctx, builder, build.runtime_cwd.as_deref(), files);
        let Some((origin, source)) =
            resolved_build_source(builder, model_node, resolved, "Taskfile is not recoverable")
        else {
            return;
        };
        if file.is_some() {
            let execution_directory = directory.as_deref().or_else(|| {
                file.as_deref()
                    .and_then(|file| file.rsplit_once('/').map(|(directory, _)| directory))
                    .filter(|directory| !directory.is_empty())
            });
            if let Some(directory) = execution_directory
                && !build.descend(directory)
            {
                unresolved_build_target(
                    builder,
                    model_node,
                    "task working directory is not repository-relative",
                );
                return;
            }
        }
        let name = target.as_ref().map_or("default", |(_, name)| name.as_str());
        let Some(recipe) = task_recipe(&source, name) else {
            unresolved_build_target(
                builder,
                model_node,
                format!("task target {name:?} is not recoverable"),
            );
            return;
        };
        for directory in &recipe.working_directories {
            if !build.descend(directory) {
                unresolved_build_target(
                    builder,
                    model_node,
                    "task working directory is not repository-relative",
                );
                return;
            }
        }
        let mut provenance = vec![model_node];
        if let Some((index, _)) = target {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
        nest_shell_lines(
            builder,
            ctx,
            model_node,
            &provenance,
            &origin,
            &build,
            unlocated_shell_lines(recipe.commands),
            "task command contains unresolved template expansion",
        );
    }
}

/// Taskfile path, `--dir` operand, and the target's index and name.
type TaskInvocation = (Option<String>, Option<String>, Option<(usize, String)>);

fn task_invocation(ctx: &InvocationCtx<'_>) -> Result<TaskInvocation, ()> {
    let mut file = None;
    let mut directory = None;
    let mut target = None;
    let mut index = 1;
    while index < ctx.argv.len() {
        let value = ctx.argv[index].as_literal().ok_or(())?;
        if matches!(value, "-t" | "--taskfile" | "-d" | "--dir") {
            let operand = ctx
                .argv
                .get(index + 1)
                .and_then(|word| word.as_literal())
                .ok_or(())?
                .to_string();
            if matches!(value, "-t" | "--taskfile") {
                file = Some(operand);
            } else {
                directory = Some(operand);
            }
            index += 2;
        } else if let Some(operand) = value.strip_prefix("--taskfile=") {
            file = Some(operand.to_string());
            index += 1;
        } else if let Some(operand) = value.strip_prefix("--dir=") {
            directory = Some(operand.to_string());
            index += 1;
        } else if value.starts_with('-') {
            return Err(());
        } else {
            if target.is_some() {
                return Err(());
            }
            target = Some((index, value.to_string()));
            index += 1;
        }
    }
    Ok((file, directory, target))
}

fn task_recipe(source: &str, requested: &str) -> Option<BuildRecipe> {
    let lines: Vec<&str> = source.lines().collect();
    let tasks = lines.iter().position(|line| line.trim() == "tasks:")?;
    let tasks_indent = indent(lines[tasks]);
    let target_indent = lines[tasks + 1..]
        .iter()
        .filter(|line| !line.trim().is_empty() && indent(line) > tasks_indent)
        .map(|line| indent(line))
        .min()?;
    let mut index = tasks + 1;
    while index < lines.len() {
        let line = lines[index];
        if !line.trim().is_empty() && indent(line) <= tasks_indent {
            break;
        }
        let trimmed = line.trim();
        if indent(line) == target_indent && trimmed.strip_suffix(':') == Some(requested) {
            let start = index + 1;
            let end = lines[start..]
                .iter()
                .position(|line| !line.trim().is_empty() && indent(line) <= target_indent)
                .map_or(lines.len(), |offset| start + offset);
            let field_indent = lines[start..end]
                .iter()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .map(|line| indent(line))
                .min()?;
            let mut commands = None;
            let mut working_directory = None;
            index = start;
            while index < end {
                let line = lines[index];
                let field = (indent(line) == field_indent)
                    .then(|| task_mapping_entry(line.trim()))
                    .flatten();
                if field
                    .as_ref()
                    .is_some_and(|(key, _)| matches!(key.as_str(), "deps" | "env" | "status"))
                {
                    return None;
                }
                if let Some((key, value)) = &field
                    && key == "dir"
                {
                    working_directory = Some(task_yaml_scalar(value)?);
                    index += 1;
                    continue;
                }
                if field
                    .as_ref()
                    .is_some_and(|(key, value)| key == "cmds" && value.is_empty())
                {
                    let cmds_indent = indent(line);
                    index += 1;
                    let mut recovered = Vec::new();
                    let mut command_indent = None;
                    while index < end {
                        let command_line = lines[index];
                        if !command_line.trim().is_empty() && indent(command_line) <= cmds_indent {
                            break;
                        }
                        let line_indent = indent(command_line);
                        let command = command_line
                            .trim()
                            .strip_prefix("- ")
                            .filter(|_| command_indent.is_none_or(|indent| indent == line_indent))
                            .map(|value| {
                                command_indent.get_or_insert(line_indent);
                                match value.split_once(':') {
                                    Some(("cmd", command)) => Some(command.trim()),
                                    Some((key, _))
                                        if !key.is_empty()
                                            && key.chars().all(|ch| {
                                                ch.is_ascii_alphanumeric() || ch == '_'
                                            }) =>
                                    {
                                        None
                                    }
                                    _ => Some(value),
                                }
                            });
                        if let Some(command) = command {
                            let command = command
                                .filter(|command| !command.is_empty())
                                .map(unquote_or_verbatim);
                            recovered.push(command.filter(|command| !command.contains("{{")));
                        }
                        index += 1;
                    }
                    commands = Some(recovered);
                    continue;
                }
                index += 1;
            }
            return commands
                .filter(|commands| !commands.is_empty())
                .map(|commands| BuildRecipe {
                    commands,
                    working_directories: working_directory.into_iter().collect(),
                    no_cd: false,
                });
        }
        index += 1;
    }
    None
}

fn task_mapping_entry(line: &str) -> Option<(String, &str)> {
    let (key, value) = line.split_once(':')?;
    let key = key.trim();
    let key = if key.starts_with(['"', '\'']) {
        unquote_exact(key)?
    } else {
        key.to_string()
    };
    Some((key, value.trim()))
}

fn task_yaml_scalar(value: &str) -> Option<String> {
    if let Some(value) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        return (!value.contains('\\') && !value.contains("{{")).then(|| value.to_string());
    }
    if let Some(value) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return (!value.contains('\'') && !value.contains("{{")).then(|| value.to_string());
    }
    if value.starts_with(['"', '\'', '|', '>', '&', '*', '!', '[', '{']) {
        return None;
    }
    let value = value
        .char_indices()
        .find(|(index, ch)| {
            *ch == '#'
                && value[..*index]
                    .chars()
                    .next_back()
                    .is_none_or(char::is_whitespace)
        })
        .map_or(value, |(index, _)| &value[..index])
        .trim_end();
    (!value.is_empty() && !value.contains(": ") && !value.contains("{{")).then(|| value.to_string())
}

struct Cargo;
struct Javac;

impl CommandModel for Cargo {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/cargo@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["cargo"]
    }

    /// An install or uninstall states the binaries it replaces or removes,
    /// which count wherever `cargo` is likely the program PATH selects.
    fn applies_under_unresolved_identity(&self, ctx: &InvocationCtx) -> bool {
        cargo_subcommand(ctx).is_some_and(|(command, _, _)| {
            matches!(
                ctx.argv.get(command).and_then(Word::as_literal),
                Some("install" | "uninstall")
            )
        })
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if super::artifact::literal_package_dispatch(builder, ctx, model_node)
            || cargo_release_dispatch(builder, ctx, model_node)
        {
            return;
        }
        let mut command = 1;
        if ctx
            .argv
            .get(command)
            .and_then(Word::as_literal)
            .is_some_and(|s| s.starts_with('+'))
        {
            command += 1;
        }
        while matches!(
            ctx.argv.get(command).and_then(Word::as_literal),
            Some("-q" | "--quiet" | "-v" | "-vv" | "--verbose")
        ) {
            command += 1;
        }
        if cargo_install_dispatch(builder, ctx, model_node)
            || cargo_metadata_dispatch(builder, ctx, model_node, command)
        {
            return;
        }
        if ctx.argv.get(1).and_then(|word| word.as_literal()) == Some("build") {
            cargo_build_inputs(builder, ctx, model_node);
            unresolved_build_target(
                builder,
                model_node,
                "cargo build executes unmodeled compiler, dependency build scripts, and proc macros",
            );
            return;
        }
        let Some(run_index) = ctx
            .argv
            .get(1)
            .and_then(|word| (word.as_literal() == Some("run")).then_some(1))
        else {
            unresolved_build_target(
                builder,
                model_node,
                "cargo command is not an executable entrypoint",
            );
            return;
        };
        let Ok((manifest_path, bin)) = cargo_run_args(ctx, run_index + 1) else {
            unresolved_build_target(
                builder,
                model_node,
                "cargo run options are not statically supported",
            );
            return;
        };
        let build = BuildToolContext::new(ctx);
        let manifest_path = manifest_path.as_deref().unwrap_or("Cargo.toml");
        let resolved = resolve_from(ctx, builder, build.runtime_cwd.as_deref(), manifest_path);
        let Some((manifest_origin, manifest)) = resolved_build_source(
            builder,
            model_node,
            resolved,
            "Cargo.toml is not recoverable",
        ) else {
            return;
        };
        let manifest_dir = crate::paths::parent_dir(&manifest_origin);
        let source_path = cargo_source_path(&manifest, bin.as_ref().map(|(_, name)| name.as_str()));
        let Some(source_path) = source_path
            .and_then(|path| crate::paths::join_relative_file(Some(&manifest_dir), &path))
        else {
            unresolved_build_target(builder, model_node, "cargo binary source is ambiguous");
            return;
        };
        let resolved =
            ctx.resolve_source_file(builder, &source_path, SourcePurpose::InvocationInput);
        let Some((origin, source)) = resolved_build_source(
            builder,
            model_node,
            resolved,
            "cargo binary source is not recoverable",
        ) else {
            return;
        };
        let mut provenance = vec![model_node, arg_node(builder, ctx, run_index as u32)];
        if let Some((index, _)) = bin {
            provenance.push(arg_node(builder, ctx, index as u32));
        }
        nest_program(builder, ctx, &provenance, origin, source, "rust", &build);
    }
}

fn cargo_metadata_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    command: usize,
) -> bool {
    let Some(verb @ ("fmt" | "package" | "yank")) =
        ctx.argv.get(command).and_then(Word::as_literal)
    else {
        return false;
    };
    let spec = FlagSpec {
        allow_abbreviation: false,
        value_flags: match verb {
            "fmt" => &["--manifest-path", "-p", "--package", "--message-format"],
            "package" => &[
                "--manifest-path",
                "-p",
                "--package",
                "--target-dir",
                "--target",
                "--registry",
                "--index",
            ],
            _ => &["--version", "--vers", "--registry", "--index", "--token"],
        },
        known_flags: match verb {
            "fmt" => &[
                "--check",
                "--all",
                "-q",
                "--quiet",
                "-v",
                "--verbose",
                "-h",
                "--help",
            ],
            "package" => &[
                "--list",
                "-l",
                "--no-verify",
                "--no-metadata",
                "--allow-dirty",
                "--locked",
                "--offline",
                "--frozen",
                "--workspace",
                "-q",
                "--quiet",
                "-v",
                "--verbose",
                "-h",
                "--help",
            ],
            _ => &["-q", "--quiet", "-v", "--verbose", "-h", "--help"],
        },
    };
    let scanned = args::scan_with_value_indices(&ctx.argv[command..], &spec, true);
    if !scanned.unknown_flags.is_empty()
        || ctx.argv[command + 1..].iter().any(|word| {
            word.as_literal().is_none_or(|value| {
                value
                    .split_once('=')
                    .is_some_and(|(key, _)| spec.known_flags.contains(&key))
            })
        })
        || scanned.flags.iter().any(|flag| {
            spec.value_flags.contains(&flag.name)
                && flag
                    .value
                    .as_ref()
                    .and_then(Word::as_literal)
                    .is_none_or(|value| value.is_empty() || value.starts_with('-'))
        })
        || scanned.operands.len() > usize::from(verb == "yank")
    {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![
                Domain::new("filesystem"),
                Domain::new("process"),
                Domain::new("artifact"),
                Domain::new("network"),
            ],
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!("cargo {verb} options are not statically supported")),
        });
        return true;
    }
    if scanned.has(&["-h", "--help"]) {
        return true;
    }
    let provenance: Vec<_> = (command..ctx.argv.len())
        .map(|index| arg_node(builder, ctx, index as u32))
        .chain([model_node])
        .collect();
    let node = builder.node(
        ProvenanceKind::ModelApplication {
            model: if verb == "fmt" {
                "cargo/fmt@1:https://github.com/rust-lang/rustfmt".into()
            } else {
                format!("cargo/{verb}@1:https://doc.rust-lang.org/cargo/commands/cargo-{verb}.html")
            },
        },
        &provenance,
    );
    if verb == "yank" {
        let operand = scanned
            .operands
            .first()
            .and_then(|(_, word)| word.as_literal());
        let (name, attached_version) = operand.map_or((None, None), |value| {
            value
                .split_once('@')
                .map_or((Some(value), None), |(name, version)| {
                    (Some(name), Some(version))
                })
        });
        let version = scanned
            .value_of(&["--version", "--vers"])
            .and_then(Word::as_literal)
            .or(attached_version);
        if version.is_none_or(str::is_empty)
            || name == Some("")
            || scanned.values_of(&["--version", "--vers"]).len()
                > usize::from(attached_version.is_none())
        {
            return true;
        }
        let mut attrs = std::collections::BTreeMap::from([
            ("package_manager".into(), AttrValue::String("cargo".into())),
            ("ecosystem".into(), AttrValue::String("crates.io".into())),
            ("action".into(), AttrValue::String("yank".into())),
        ]);
        for (key, value) in [
            ("package", name),
            ("version", version),
            (
                "registry_name",
                scanned.value_of(&["--registry"]).and_then(Word::as_literal),
            ),
            (
                "registry",
                scanned.value_of(&["--index"]).and_then(Word::as_literal),
            ),
        ] {
            if let Some(value) = value {
                attrs.insert(key.into(), AttrValue::String(value.into()));
            }
        }
        if name.is_none() {
            builder.boundary(Boundary {
                reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: Some(ctx.resolve_fs_word(&Word::literal("Cargo.toml"))),
                callee: None,
                domains: vec![Domain::new("artifact")],
                provenance: vec![node],
                limit: None,
                detail: Some(
                    "cargo yank requires the current package manifest for an omitted crate name"
                        .into(),
                ),
            });
            return true;
        }
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("artifact.yank_request"),
            resource: unresolved_resource("artifact"),
            attributes: attrs.clone(),
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            modality: Modality::MustOnSuccess,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: vec![node],
        });
        arg_effect(
            builder,
            ctx,
            node,
            command as u32,
            "network.request",
            unresolved_resource("network"),
            attrs,
        );
        builder.declare_coverage(Domain::new("artifact"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    } else {
        let manifest = scanned
            .value_of(&["--manifest-path"])
            .map(|word| ctx.resolve_fs_word(word))
            .unwrap_or(ResourceExpr::Parameter {
                name: "cargo_workspace_manifest".into(),
            });
        arg_effect(
            builder,
            ctx,
            node,
            command as u32,
            "filesystem.read",
            manifest,
            program_input_attrs(),
        );
        let sources = ResourceExpr::Parameter {
            name: "cargo_selected_package_sources".into(),
        };
        arg_effect(
            builder,
            ctx,
            node,
            command as u32,
            "filesystem.read",
            sources.clone(),
            program_input_attrs(),
        );
        if verb == "fmt" {
            if !scanned.has(&["--check"]) {
                arg_effect(
                    builder,
                    ctx,
                    node,
                    command as u32,
                    "filesystem.write",
                    sources,
                    program_output_attrs(),
                );
            }
        } else if !scanned.has(&["--list", "-l"]) {
            if !scanned.has(&["--offline", "--frozen"]) {
                arg_effect(
                    builder,
                    ctx,
                    node,
                    command as u32,
                    "network.request",
                    unresolved_resource("network"),
                    Default::default(),
                );
                builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
            }
            let target = scanned
                .value_of(&["--target-dir"])
                .map(|word| ctx.resolve_fs_word(word))
                .or_else(|| {
                    ctx.environment_value("CARGO_TARGET_DIR")
                        .map(|value| match value {
                            ResourceExpr::Literal { value } => {
                                ctx.resolve_fs_word(&Word::literal(value))
                            }
                            value => value,
                        })
                })
                .unwrap_or(ResourceExpr::Parameter {
                    name: "cargo_workspace_target_dir".into(),
                });
            arg_effect(
                builder,
                ctx,
                node,
                command as u32,
                "filesystem.write",
                effinterp_proto::filesystem_path("package", Some(target), PathPlatform::Posix),
                program_output_attrs(),
            );
            if !scanned.has(&["--no-verify"]) {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNMODELED_HOOKS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Environment,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("process"), Domain::new("filesystem"), Domain::new("network")],
                    provenance: vec![node],
                    limit: None,
                    detail: Some("cargo package verifies the archive by compiling it, including dependency build scripts and proc macros".into()),
                });
            }
        }
    }
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    true
}

/// The cargo-release and cargo-workspaces subcommands that publish crates:
/// `cargo release [LEVEL|VERSION]` and its `publish` step, which act only
/// under `-x`/`--execute`, and `cargo workspaces publish` (alias `ws`).
/// Their other steps and commands stay with the generic cargo reading.
fn cargo_release_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) -> bool {
    let Some((command, _, _)) = cargo_subcommand(ctx) else {
        return false;
    };
    let word = |index: usize| ctx.argv.get(index).and_then(Word::as_literal);
    let release = match word(command) {
        Some("release")
            if !matches!(
                word(command + 1),
                Some(
                    "changes"
                        | "version"
                        | "replace"
                        | "hook"
                        | "commit"
                        | "owner"
                        | "tag"
                        | "push"
                        | "config"
                        | "help"
                )
            ) =>
        {
            super::release::Release {
                tool: "cargo-release",
                ecosystem: Some("crates.io"),
                start: command + 1,
                uncertain: false,
                options: super::release::CARGO_RELEASE,
                style: super::release::CLAP,
                suppressed: super::release::cargo_release_suppressed,
                source: "https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md",
            }
        }
        Some("workspaces" | "ws") if word(command + 1) == Some("publish") => {
            super::release::Release {
                tool: "cargo-workspaces",
                ecosystem: Some("crates.io"),
                start: command + 2,
                uncertain: false,
                options: super::release::CARGO_WORKSPACES_PUBLISH,
                style: super::release::CLAP,
                suppressed: super::release::cargo_workspaces_suppressed,
                source: "https://github.com/pksunkara/cargo-workspaces#publish",
            }
        }
        _ => return false,
    };
    super::release::release_publication(builder, ctx, model_node, &release);
    true
}

/// The index of the subcommand after cargo's global options, whether a
/// `--config` among them may set `install.root`, and whether one of them is an
/// option the model does not read. A symbolic option word, or a value option
/// without its value, ends that reading of the options, as does an
/// informational mode (`--help`, `--version`, `--list`, `--explain`), which
/// runs no subcommand. Another reading may still reach one.
fn cargo_subcommand(ctx: &InvocationCtx<'_>) -> Option<(usize, bool, bool)> {
    let start = if ctx
        .argv
        .get(1)
        .and_then(Word::as_literal)
        .is_some_and(|s| s.starts_with('+'))
    {
        2
    } else {
        1
    };
    let mut configured = false;
    let mut unknown = false;
    // Each index a reading of the options so far has reached. An option this
    // scan does not know stands alone or takes the next word, so it forks the
    // reading; every fork is kept to the subcommand it reaches.
    let mut readings = vec![start];
    let mut visited = std::collections::BTreeSet::new();
    let mut reached = Vec::new();
    let mut informational = false;
    while let Some(command) = readings.pop() {
        if !visited.insert(command) {
            continue;
        }
        let Some(word) = ctx.argv.get(command).and_then(Word::as_literal) else {
            continue;
        };
        let value = || {
            ctx.argv
                .get(command + 1)
                .and_then(Word::as_literal)
                .is_some()
        };
        match word {
            "-h" | "--help" | "-V" | "--version" | "--list" | "--explain" => informational = true,
            _ if word.starts_with("--explain=") => informational = true,
            "-q" | "--quiet" | "-v" | "--verbose" | "--frozen" | "--locked" | "--offline" => {
                readings.push(command + 1);
            }
            // `-C` runs Cargo from another directory, which relative paths
            // then name.
            "--color" | "--config" | "-Z" | "-C" => {
                if value() {
                    configured |= word == "--config";
                    unknown |= word == "-C";
                    readings.push(command + 2);
                }
            }
            _ if word.starts_with("-vv") && word[1..].bytes().all(|byte| byte == b'v') => {
                readings.push(command + 1);
            }
            _ if word.starts_with("--color=") || word.starts_with("-Z") && word.len() > 2 => {
                readings.push(command + 1);
            }
            _ if word.starts_with("--config=") => {
                configured = true;
                readings.push(command + 1);
            }
            _ if word.starts_with('-') && word != "--" => {
                unknown = true;
                readings.push(command + 1);
                if !word.contains('=')
                    && ctx
                        .argv
                        .get(command + 1)
                        .and_then(Word::as_literal)
                        .is_some_and(|value| !value.starts_with('-'))
                {
                    readings.push(command + 2);
                }
            }
            _ => reached.push(command),
        }
    }
    // The reading that reaches `install` or `uninstall` is the one that can
    // change installed binaries; otherwise the earliest subcommand, unless a
    // reading ends in an informational mode.
    let command = reached
        .iter()
        .copied()
        .filter(|index| {
            matches!(
                ctx.argv.get(*index).and_then(Word::as_literal),
                Some("install" | "uninstall")
            )
        })
        .min()
        .or_else(|| {
            (!informational)
                .then(|| reached.iter().copied().min())
                .flatten()
        })?;
    Some((command, configured, unknown))
}

fn cargo_install_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) -> bool {
    let Some((command, configured, leading_unknown)) = cargo_subcommand(ctx) else {
        return false;
    };
    let Some(verb @ ("install" | "uninstall")) = ctx.argv.get(command).and_then(Word::as_literal)
    else {
        return false;
    };
    let install = verb == "install";
    let spec = FlagSpec {
        allow_abbreviation: false,
        // `cargo install --help` and `cargo uninstall --help` (Cargo 1.8x).
        value_flags: if install {
            &[
                "--root",
                "--path",
                "--bin",
                "--example",
                "--version",
                "--vers",
                "--git",
                "--branch",
                "--tag",
                "--rev",
                "--registry",
                "--index",
                "-F",
                "--features",
                "-j",
                "--jobs",
                "--target",
                "--target-dir",
                "--profile",
                "--message-format",
                "--color",
                "--config",
                "-Z",
            ]
        } else {
            &[
                "--root",
                "--bin",
                "--package",
                "-p",
                "--color",
                "--config",
                "-Z",
            ]
        },
        known_flags: if install {
            &[
                "-h",
                "--help",
                "--list",
                "-q",
                "--quiet",
                "-v",
                "--verbose",
                "--locked",
                "--frozen",
                "--offline",
                "-f",
                "--force",
                "--no-track",
                "-n",
                "--dry-run",
                "--bins",
                "--examples",
                "--all-features",
                "--no-default-features",
                "--debug",
                "--keep-going",
                "--ignore-rust-version",
                "--timings",
            ]
        } else {
            &[
                "-h",
                "--help",
                "-q",
                "--quiet",
                "-v",
                "--verbose",
                "--locked",
                "--frozen",
                "--offline",
            ]
        },
    };
    let scanned = args::scan_with_value_indices(&ctx.argv[command..], &spec, true);
    // An option the model does not read may change what the command does, but
    // not which package or binary it names: the selection stays stated.
    let unknown_options = leading_unknown || !scanned.unknown_flags.is_empty();
    if unknown_options {
        unresolved_build_target(
            builder,
            model_node,
            "cargo install/uninstall option is not modeled",
        );
    }
    if ctx.argv[command + 1..].iter().any(|word| {
        word.as_literal().is_none_or(|value| {
            value
                .split_once('=')
                .is_some_and(|(key, _)| spec.known_flags.contains(&key))
        })
    }) || scanned.flags.iter().any(|flag| {
        spec.value_flags.contains(&flag.name)
            && flag
                .value
                .as_ref()
                .and_then(Word::as_literal)
                .is_none_or(|value| value.is_empty() || value.starts_with('-'))
    }) || ["--root", "--path"]
        .iter()
        .any(|name| scanned.values_of(&[name]).len() > 1)
    {
        unresolved_build_target(
            builder,
            model_node,
            "cargo install/uninstall options or selectors are not statically supported",
        );
        return true;
    }
    if scanned.has(&["-h", "--help", "--list"]) {
        return true;
    }
    let dry_run = scanned.has(&["-n", "--dry-run"]);
    if install && scanned.operands.is_empty() && !scanned.has(&["--path", "--git"]) {
        unresolved_build_target(
            builder,
            model_node,
            "cargo install package or path source is not explicit",
        );
        return true;
    }
    // An example installs into the same directory under its own name.
    let bins = scanned.values_of(&["--bin", "--example"]);
    if bins.iter().any(|(_, word)| {
        word.as_literal().is_none_or(|name| {
            name == "." || name == ".." || name.contains(['/', '\\', '*', '?', '[', ']'])
        })
    }) {
        unresolved_build_target(
            builder,
            model_node,
            "cargo binary selector is not a literal executable name",
        );
        return true;
    }
    // Cargo finds its home under the user's home directory: `HOME`, or on
    // Windows `USERPROFILE`, which is where Windows keeps it.
    let mut root = if ctx.nest.path_platform == PathPlatform::Windows {
        match ctx.environment_value("USERPROFILE") {
            Some(ResourceExpr::Literal { value }) => {
                ctx.resolve_fs_word(&Word::literal(format!("{value}\\.cargo")))
            }
            home => ResourceExpr::Join {
                parts: vec![
                    home.unwrap_or(ResourceExpr::Environment {
                        name: "USERPROFILE".into(),
                    }),
                    ResourceExpr::Literal {
                        value: "\\.cargo".into(),
                    },
                ],
            },
        }
    } else {
        ResourceExpr::Join {
            parts: vec![
                ctx.environment_value("HOME")
                    .unwrap_or(ResourceExpr::Environment {
                        name: "HOME".into(),
                    }),
                ResourceExpr::Literal {
                    value: "/.cargo".into(),
                },
            ],
        }
    };
    // Whether a `--config` may still choose the root once `CARGO_INSTALL_ROOT`
    // and `--root`, which Cargo prefers to it, are applied.
    let mut config_root = configured || scanned.value_of(&["--config"]).is_some();
    for name in ["CARGO_HOME", "CARGO_INSTALL_ROOT"] {
        // A `--config` may set `install.root`, which Cargo prefers to
        // `CARGO_HOME` and yields to `CARGO_INSTALL_ROOT` and `--root`.
        if name == "CARGO_INSTALL_ROOT" && config_root {
            root = ResourceExpr::Union {
                alternatives: vec![unresolved_resource("filesystem"), root],
            };
        }
        root = match ctx.environment_value(name) {
            Some(ResourceExpr::Literal { value }) => ctx.resolve_fs_word(&Word::literal(value)),
            Some(value) => value,
            None if !ctx.tracks_host_context_environment()
                && !ctx.nest.environment_is_closed()
                && !ctx.nest.current_environment_unsets().contains(name) =>
            {
                ResourceExpr::Union {
                    alternatives: vec![ResourceExpr::Environment { name: name.into() }, root],
                }
            }
            None => root,
        };
        if name == "CARGO_INSTALL_ROOT" && ctx.environment_value(name).is_some() {
            config_root = false;
        }
    }
    if let Some(word) = scanned.value_of(&["--root"]) {
        root = ctx.resolve_fs_word(word);
        config_root = false;
    }
    let directory =
        effinterp_proto::filesystem_path("bin", Some(root.clone()), PathPlatform::Posix);
    let mut selectors = bins.clone();
    let selection = if !bins.is_empty() {
        "named"
    } else if scanned.has(&["--path"]) {
        selectors = scanned.values_of(&["--path"]);
        "manifest_binaries"
    } else {
        selectors = scanned.operands.clone();
        selectors.extend(scanned.values_of(&["--package", "-p"]));
        "package_binaries"
    };
    // An omitted package is selected from metadata, never from the directory name.
    if selectors.is_empty() {
        selectors.push((0, &ctx.argv[command]));
    }
    // Only a package selector can be looked up in the install root's registry;
    // a `--bin` name is already exact and a `--path` manifest is not named here.
    let registry_path = (!install && selection == "package_binaries")
        .then(|| {
            match effinterp_proto::filesystem_path(
                ".crates2.json",
                Some(root.clone()),
                PathPlatform::Posix,
            ) {
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } => Some(path),
                _ => None,
            }
        })
        .flatten();
    let registry = registry_path
        .as_deref()
        .and_then(|path| installed_registry(builder, ctx, path));
    let mut provenance = vec![model_node];
    for index in 1..ctx.argv.len() {
        provenance.push(arg_node(builder, ctx, index as u32));
    }
    if let Some((registry_node, _)) = &registry {
        provenance.push(*registry_node);
    }
    let node = builder.node(ProvenanceKind::ModelApplication {
        model: "cargo/install-uninstall@1:https://doc.rust-lang.org/cargo/commands/cargo-install.html;https://doc.rust-lang.org/cargo/commands/cargo-uninstall.html".into(),
    }, &provenance);
    let operation = if install {
        "filesystem.write"
    } else {
        "filesystem.delete"
    };
    if let Some((index, path)) = scanned.values_of(&["--path"]).first() {
        let manifest = effinterp_proto::filesystem_path(
            "Cargo.toml",
            Some(ctx.resolve_fs_word(path)),
            PathPlatform::Posix,
        );
        arg_effect(
            builder,
            ctx,
            node,
            command as u32 + index,
            "filesystem.read",
            manifest.clone(),
            program_input_attrs(),
        );
        if bins.is_empty() {
            let manifest_path = format!(
                "{}/Cargo.toml",
                path.as_literal().unwrap().trim_end_matches('/')
            );
            let observed = crate::paths::join_source_path(ctx.runtime_cwd, &manifest_path)
                .is_some_and(|path| {
                    match ctx.nest.observe_source_search(
                        builder,
                        &[path],
                        SourcePurpose::DependencySource,
                    ) {
                        crate::nest::SourceSearchObservation::Found { .. } => true,
                        crate::nest::SourceSearchObservation::Refused(
                            crate::SourceRefusal::Limit { limit },
                        ) => {
                            builder.note_saturated(limit);
                            false
                        }
                        _ => false,
                    }
                });
            builder.boundary(Boundary {
                reason: if observed { BoundaryReason::UNRESOLVED_BUILD_TARGET } else { BoundaryReason::OBSERVATION_UNAVAILABLE },
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: Some(manifest),
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![node],
                limit: None,
                detail: Some(if observed {
                    "cargo install manifest is observed, but manifest target and source-tree discovery is not modeled".into()
                } else {
                    "cargo install target discovery requires the selected Cargo.toml and its auto-discovered binary source paths; supply manifest and source-tree observations".into()
                }),
            });
        }
        arg_effect(
            builder,
            ctx,
            node,
            command as u32 + index,
            "filesystem.read",
            ctx.resolve_fs_word(path),
            {
                let mut attrs = program_input_attrs();
                attrs.insert(
                    "selection".into(),
                    AttrValue::String("package_sources".into()),
                );
                attrs
            },
        );
    }
    if install {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_HOOKS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("process"), Domain::new("filesystem"), Domain::new("network")],
            provenance: vec![node],
            limit: None,
            detail: Some("cargo install dependency resolution, compiler, build scripts and proc macros are not modeled; dry-run performs checks without installing binaries".into()),
        });
    }
    if dry_run {
        return true;
    }
    let mut unrecorded = false;
    let mut mutates = false;
    if config_root && !install {
        unresolved_build_target(
            builder,
            node,
            "cargo --config may set the install root the uninstall removes from",
        );
    }
    let mut requested = Vec::new();
    for (index, word) in selectors {
        // Under a root a `--config` may move, or behind an option the model
        // does not read, an uninstall names no binary it removes; it still
        // reads the registry for what it was asked.
        if (config_root || unknown_options) && !install {
            if index != 0 {
                requested.push((index, word));
            }
            continue;
        }
        // Outer None: no registry, or a selector it cannot be keyed on. Inner
        // None: the registry records no binaries for that package.
        let recorded = registry
            .as_ref()
            .zip(package_selector_name(index, word))
            .and_then(|((_, packages), name)| match packages.get(&name) {
                Some(Some(bins)) => Some(Some(bins)),
                Some(None) => None,
                None => Some(None),
            });
        if let Some(Some(recorded)) = recorded {
            for bin in recorded {
                mutates = true;
                arg_effect(
                    builder,
                    ctx,
                    node,
                    command as u32 + index,
                    operation,
                    effinterp_proto::filesystem_path(
                        bin,
                        Some(directory.clone()),
                        PathPlatform::Posix,
                    ),
                    std::collections::BTreeMap::from([
                        (
                            "selection".into(),
                            AttrValue::String("installed_binaries".into()),
                        ),
                        ("package_manager".into(), AttrValue::String("cargo".into())),
                        (
                            "package".into(),
                            AttrValue::String(word.as_literal().unwrap().into()),
                        ),
                    ]),
                );
            }
            continue;
        }
        // An uninstall of a package the registry does not record removes
        // nothing: Cargo refuses it. A fresh install still declares binaries.
        if matches!(recorded, Some(None)) && !install {
            requested.push((index, word));
            continue;
        }
        unrecorded = true;
        mutates = true;
        let mut attrs = std::collections::BTreeMap::from([
            ("selection".into(), AttrValue::String(selection.into())),
            ("package_manager".into(), AttrValue::String("cargo".into())),
        ]);
        if install {
            attrs.extend(program_output_attrs());
        }
        let resource = if !bins.is_empty() {
            // The name is stated apart from the path, which a computed root
            // leaves unresolved.
            attrs.insert(
                "binary".into(),
                AttrValue::String(word.as_literal().unwrap().into()),
            );
            effinterp_proto::filesystem_path(
                word.as_literal().unwrap(),
                Some(directory.clone()),
                PathPlatform::Posix,
            )
        } else {
            if index != 0 {
                attrs.insert(
                    if selection == "manifest_binaries" {
                        "source_path"
                    } else {
                        "package"
                    }
                    .into(),
                    AttrValue::String(word.as_literal().unwrap().into()),
                );
            }
            directory.clone()
        };
        arg_effect(
            builder,
            ctx,
            node,
            command as u32 + index,
            operation,
            resource,
            attrs,
        );
    }
    // The registry read states each package or binary the uninstall was asked
    // to remove where Cargo refuses it or the root is unknown.
    for (index, word) in requested {
        arg_effect(
            builder,
            ctx,
            node,
            command as u32 + index,
            "filesystem.read",
            effinterp_proto::filesystem_path(
                ".crates2.json",
                Some(root.clone()),
                PathPlatform::Posix,
            ),
            {
                let mut attrs = program_input_attrs();
                attrs.extend([
                    ("selection".into(), AttrValue::String("requested".into())),
                    ("package_manager".into(), AttrValue::String("cargo".into())),
                    (
                        if bins.is_empty() { "package" } else { "binary" }.into(),
                        AttrValue::String(word.as_literal().unwrap().into()),
                    ),
                ]);
                attrs
            },
        );
    }
    for file in [".crates.toml", ".crates2.json"] {
        let resource =
            effinterp_proto::filesystem_path(file, Some(root.clone()), PathPlatform::Posix);
        arg_effect(
            builder,
            ctx,
            node,
            command as u32,
            "filesystem.read",
            resource.clone(),
            program_input_attrs(),
        );
        if mutates {
            arg_effect(
                builder,
                ctx,
                node,
                command as u32,
                "filesystem.write",
                resource,
                program_output_attrs(),
            );
        }
    }
    if unrecorded && bins.is_empty() && selection == "package_binaries" {
        let resource = if install {
            None
        } else {
            Some(effinterp_proto::filesystem_path(
                ".crates2.json",
                Some(root),
                PathPlatform::Posix,
            ))
        };
        builder.boundary(Boundary {
            reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: resource,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![node],
            limit: None,
            detail: Some(if install {
                "cargo install requires the selected package's current manifest and binary source paths; prior installed binaries do not determine a new build".into()
            } else {
                format!("{} is not observed or does not uniquely resolve the package selector; supply the selected install root's package-to-binary metadata", registry_path.as_deref().unwrap_or(".crates2.json"))
            }),
        });
    }
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    true
}

/// Bare names and exact versions can be keyed on the installation metadata.
/// Partial versions and source-qualified selectors require Cargo's package-ID resolver.
fn package_selector_name(index: u32, word: &Word) -> Option<String> {
    if index == 0 {
        return None;
    }
    let value = word.as_literal()?;
    let name = value.split_once('@').map_or(value, |(name, _)| name);
    if let Some((_, version)) = value.split_once('@') {
        let core = version.split(['-', '+']).next()?;
        if core.split('.').count() != 3 || core.split('.').any(|part| part.parse::<u64>().is_err())
        {
            return None;
        }
    }
    (!name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then(|| value.to_string())
}

/// The binaries the install registry records for each package; none when it
/// records that package twice, or without a binary list.
type InstalledBins = std::collections::BTreeMap<String, Option<Vec<String>>>;

/// Cargo records every package it installed under an install root in that
/// root's `.crates2.json`, including the binaries it placed in `bin`.
/// `cargo uninstall` removes exactly those. Returns the observed registry's
/// provenance and, per package, its recorded binaries; a package recorded
/// twice, or without a binary list, has none that can be selected.
fn installed_registry(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    path: &str,
) -> Option<(ProvenanceRef, InstalledBins)> {
    use crate::nest::SourceSearchObservation;

    if !builder.is_host_realm() {
        return None;
    }
    let bytes = match ctx.nest.observe_source_search(
        builder,
        &[(crate::SourceNamespace::Host, path.to_string())],
        SourcePurpose::DependencySource,
    ) {
        SourceSearchObservation::Found { bytes, .. } => bytes,
        SourceSearchObservation::Refused(crate::SourceRefusal::Limit { limit }) => {
            builder.note_saturated(limit);
            return None;
        }
        _ => return None,
    };
    let source = std::str::from_utf8(&bytes).ok()?;
    if !builder.budget().try_charge_steps(source.len() as u64) {
        builder.note_saturated("max_analysis_steps");
        return None;
    }
    let document = serde_json::from_str::<serde_json::Value>(source).ok()?;
    let installs = document.get("installs")?.as_object()?;
    let mut packages = InstalledBins::new();
    for (key, entry) in installs {
        // An install key is "<name> <version> (<source>)".
        let name = key.split_once(' ').map_or(key.as_str(), |(name, _)| name);
        if name.is_empty() {
            continue;
        }
        let bins = entry
            .get("bins")
            .and_then(serde_json::Value::as_array)
            .and_then(|bins| {
                bins.iter()
                    .map(|bin| bin.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            });
        for selector in std::iter::once(name.to_string()).chain(
            key.split_whitespace()
                .nth(1)
                .map(|version| format!("{name}@{version}")),
        ) {
            packages
                .entry(selector)
                .and_modify(|recorded| *recorded = None)
                .or_insert_with(|| bins.clone());
        }
    }
    let node = builder.node(
        ProvenanceKind::SourceInput {
            path: path.to_string(),
            digest: effinterp_proto::content_digest(&bytes),
        },
        &[],
    );
    Some((node, packages))
}

fn cargo_build_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    for variable in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
        match ctx.environment_value(variable) {
            Some(ResourceExpr::Literal { value }) if !value.is_empty() => {
                runtime_selected_source(
                    builder,
                    ctx,
                    model_node,
                    &value,
                    ExecutionInputRole::UnexpectedSelected,
                    ExecutionPhase::BuildHook,
                    ExecutionSelector::Environment {
                        variable: variable.to_string(),
                    },
                    RuntimeSourceLanguage::Executable,
                );
            }
            Some(ResourceExpr::Literal { .. }) | None => {}
            Some(_) => runtime_unobserved_input(
                builder,
                ctx,
                &format!("${variable}"),
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::BuildHook,
                ExecutionSelector::Environment {
                    variable: variable.to_string(),
                },
                ExecutionInputReason::Ambiguous,
            ),
        }
    }
    let manifest_path = cargo_option(ctx, "--manifest-path").unwrap_or("Cargo.toml");
    let SourceResolution::Source {
        origin: manifest_origin,
        source: manifest,
    } = resolve_from(ctx, builder, ctx.runtime_cwd, manifest_path)
    else {
        unresolved_build_target(builder, model_node, "Cargo.toml is not recoverable");
        return;
    };
    let Some(package_name) = cargo_package_value(&manifest, "name") else {
        unresolved_build_target(
            builder,
            model_node,
            "Cargo workspace package selection is not explicit",
        );
        return;
    };
    if let Some(requested) = cargo_option(ctx, "--package").or_else(|| cargo_option(ctx, "-p"))
        && package_name != requested
    {
        return;
    }
    if cargo_package_value(&manifest, "build").as_deref() == Some("false") {
        return;
    }
    let build_script = cargo_package_value(&manifest, "build")
        .filter(|value| value != "true")
        .unwrap_or_else(|| "build.rs".to_string());
    let manifest_dir = crate::paths::parent_dir(&manifest_origin);
    let Some(path) = crate::paths::join_file(Some(&manifest_dir), &build_script) else {
        return;
    };
    runtime_searched_source(
        builder,
        ctx,
        model_node,
        &build_script,
        vec![path],
        ExecutionInputRole::UnexpectedSelected,
        ExecutionPhase::BuildHook,
        ExecutionSelector::Convention {
            name: "cargo-package-build-script@1".to_string(),
        },
        RuntimeSourceLanguage::Source("rust"),
        false,
    );
}

fn cargo_option<'a>(ctx: &'a InvocationCtx<'_>, name: &str) -> Option<&'a str> {
    let mut index = 2;
    while index < ctx.argv.len() {
        let argument = ctx.argv[index].as_literal()?;
        if argument == name {
            return ctx.argv.get(index + 1).and_then(|word| word.as_literal());
        }
        if let Some(value) = argument.strip_prefix(&format!("{name}=")) {
            return Some(value);
        }
        index += 1;
    }
    None
}

fn cargo_package_value(manifest: &str, key: &str) -> Option<String> {
    let mut package = false;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            package = line == "[package]";
            continue;
        }
        if package
            && let Some(value) = line.strip_prefix(key)
            && let Some(value) = value.trim_start().strip_prefix('=')
        {
            let value = value.trim();
            return Some(
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value)
                    .to_string(),
            );
        }
    }
    None
}

impl CommandModel for Javac {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/javac@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["javac"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx
            .argv
            .iter()
            .filter_map(|word| word.as_literal())
            .filter_map(|argument| argument.strip_prefix("-proc:"))
            .next_back()
            == Some("none")
        {
            unresolved_build_target(
                builder,
                model_node,
                "javac compilation is not modeled when annotation processing is disabled",
            );
            return;
        }
        let processor = build_option(ctx, &["-processor"]);
        let processor_path = build_option(
            ctx,
            &["-processorpath", "--processor-path", "-processor-path"],
        );
        let (Some(processor), Some(processor_path)) = (processor, processor_path) else {
            unresolved_build_target(
                builder,
                model_node,
                "javac annotation processor is not explicitly selected",
            );
            return;
        };
        let processor_class = format!("{}.class", processor.replace('.', "/"));
        let candidates = processor_path
            .split(':')
            .map(|entry| {
                if entry.ends_with(".jar") {
                    entry.to_string()
                } else {
                    format!("{entry}/{processor_class}")
                }
            })
            .collect::<Vec<_>>();
        let opaque = candidates
            .iter()
            .any(|candidate| candidate.ends_with(".jar"));
        runtime_searched_source(
            builder,
            ctx,
            model_node,
            processor,
            candidates,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::BuildHook,
            ExecutionSelector::RuntimeOption {
                option: "-processorpath".to_string(),
            },
            if opaque {
                RuntimeSourceLanguage::Opaque
            } else {
                RuntimeSourceLanguage::Source("java")
            },
            true,
        );
    }
}

fn build_option<'a>(ctx: &'a InvocationCtx<'_>, names: &[&str]) -> Option<&'a str> {
    let mut index = 1;
    while index < ctx.argv.len() {
        let argument = ctx.argv[index].as_literal()?;
        if names.contains(&argument) {
            return ctx.argv.get(index + 1).and_then(|word| word.as_literal());
        }
        for name in names {
            if let Some(value) = argument.strip_prefix(&format!("{name}=")) {
                return Some(value);
            }
        }
        index += 1;
    }
    None
}

/// Manifest path and the selected binary's index and name.
type CargoRunArgs = (Option<String>, Option<(usize, String)>);

fn cargo_run_args(ctx: &InvocationCtx<'_>, mut index: usize) -> Result<CargoRunArgs, ()> {
    let mut manifest = None;
    let mut bin = None;
    while index < ctx.argv.len() {
        let value = ctx.argv[index].as_literal().ok_or(())?;
        if value == "--" {
            break;
        }
        if matches!(value, "--manifest-path" | "--bin") {
            let operand_index = index + 1;
            let operand = ctx
                .argv
                .get(operand_index)
                .and_then(|word| word.as_literal())
                .ok_or(())?;
            if value == "--manifest-path" {
                manifest = Some(operand.to_string());
            } else {
                bin = Some((operand_index, operand.to_string()));
            }
            index += 2;
        } else if let Some(operand) = value.strip_prefix("--manifest-path=") {
            manifest = Some(operand.to_string());
            index += 1;
        } else if let Some(operand) = value.strip_prefix("--bin=") {
            bin = Some((index, operand.to_string()));
            index += 1;
        } else if matches!(
            value,
            "--release" | "--quiet" | "-q" | "--locked" | "--offline" | "--frozen"
        ) {
            index += 1;
        } else {
            return Err(());
        }
    }
    Ok((manifest, bin))
}

fn cargo_source_path(manifest: &str, requested: Option<&str>) -> Option<String> {
    let mut bins = Vec::new();
    let mut current_name = None;
    let mut current_path = None;
    let mut in_bin = false;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line == "[[bin]]" {
            if in_bin {
                bins.push((current_name.take(), current_path.take()));
            }
            in_bin = true;
            continue;
        }
        if line.starts_with('[') {
            if in_bin {
                bins.push((current_name.take(), current_path.take()));
            }
            in_bin = false;
            continue;
        }
        if in_bin {
            if let Some(value) = toml_string(line, "name") {
                current_name = Some(value);
            } else if let Some(value) = toml_string(line, "path") {
                current_path = Some(value);
            }
        }
    }
    if in_bin {
        bins.push((current_name, current_path));
    }
    if let Some(requested) = requested {
        if let Some((_, path)) = bins
            .iter()
            .find(|(name, _)| name.as_deref() == Some(requested))
        {
            return path
                .clone()
                .or_else(|| Some(format!("src/bin/{requested}.rs")));
        }
        return Some(format!("src/bin/{requested}.rs"));
    }
    if !bins.is_empty() {
        return None;
    }
    Some("src/main.rs".to_string())
}

fn toml_string(line: &str, key: &str) -> Option<String> {
    let value = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    unquote_exact(value)
}

struct Maven;

impl CommandModel for Maven {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/maven@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mvn", "mvnw"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx.argv.iter().any(|word| word.as_literal().is_none()) {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRESOLVED_BUILD_TARGET,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: crate::builder::KNOWN_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "symbolic Maven options may select another build file or main class".into(),
                ),
            });
        }
        if !ctx.argv.iter().any(|word| {
            word.as_literal().is_some_and(|arg| {
                arg == "exec:java" || (arg.contains("exec-maven-plugin") && arg.ends_with(":java"))
            })
        }) {
            unresolved_build_target(
                builder,
                model_node,
                "Maven goal is not an executable entrypoint",
            );
            return;
        }
        let build = BuildToolContext::new(ctx);
        let file = option_value(ctx, &["-f", "--file", "--pom-file"]).unwrap_or("pom.xml");
        let resolved = resolve_from(ctx, builder, build.runtime_cwd.as_deref(), file);
        let Some((manifest_origin, manifest)) =
            resolved_build_source(builder, model_node, resolved, "pom.xml is not recoverable")
        else {
            return;
        };
        let cli_main = ctx
            .argv
            .iter()
            .filter_map(|word| word.as_literal())
            .find_map(|arg| arg.strip_prefix("-Dexec.mainClass="))
            .map(str::to_string);
        let main = cli_main.or_else(|| maven_exec_main_class(&manifest));
        let Some(main) = main else {
            unresolved_build_target(builder, model_node, "Maven main class is not explicit");
            return;
        };
        let manifest_dir = crate::paths::parent_dir(&manifest_origin);
        let path = format!("src/main/java/{}.java", main.replace('.', "/"));
        let resolved = resolve_from(ctx, builder, Some(&manifest_dir), &path);
        let Some((origin, source)) = resolved_build_source(
            builder,
            model_node,
            resolved,
            "Maven main source is not recoverable",
        ) else {
            return;
        };
        nest_program(builder, ctx, &[model_node], origin, source, "java", &build);
    }
}

struct Gradle;

impl CommandModel for Gradle {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "build/gradle@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["gradle", "gradlew"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let run_index = match gradle_run_task(ctx) {
            Ok(Some(index)) => index,
            Ok(None) => {
                unresolved_build_target(
                    builder,
                    model_node,
                    "Gradle task is not an executable entrypoint",
                );
                return;
            }
            Err(()) => {
                unresolved_build_target(
                    builder,
                    model_node,
                    "Gradle options are not statically supported",
                );
                return;
            }
        };
        let mut build = BuildToolContext::new(ctx);
        if let Some(directory) = option_value(ctx, &["-p", "--project-dir"])
            && !build.descend(directory)
        {
            unresolved_build_target(
                builder,
                model_node,
                "Gradle project directory is not repository-relative",
            );
            return;
        }
        let files = option_value(ctx, &["-b", "--build-file"])
            .map(|file| vec![file])
            .unwrap_or_else(|| vec!["build.gradle", "build.gradle.kts"]);
        let resolved = resolve_first(ctx, builder, build.runtime_cwd.as_deref(), files);
        let Some((manifest_origin, manifest)) = resolved_build_source(
            builder,
            model_node,
            resolved,
            "Gradle build file is not recoverable",
        ) else {
            return;
        };
        if !gradle_application_plugin(&manifest) {
            unresolved_build_target(
                builder,
                model_node,
                "Gradle application plugin is not explicit",
            );
            return;
        }
        let Some(main) = gradle_main_class(&manifest) else {
            unresolved_build_target(builder, model_node, "Gradle main class is not explicit");
            return;
        };
        let manifest_dir = crate::paths::parent_dir(&manifest_origin);
        let path = format!("src/main/java/{}.java", main.replace('.', "/"));
        let resolved = resolve_from(ctx, builder, Some(&manifest_dir), &path);
        let Some((origin, source)) = resolved_build_source(
            builder,
            model_node,
            resolved,
            "Gradle main source is not recoverable",
        ) else {
            return;
        };
        let provenance = [model_node, arg_node(builder, ctx, run_index as u32)];
        nest_program(builder, ctx, &provenance, origin, source, "java", &build);
    }
}

fn gradle_run_task(ctx: &InvocationCtx<'_>) -> Result<Option<usize>, ()> {
    let mut run = None;
    let mut excluded = false;
    let mut index = 1;
    while index < ctx.argv.len() {
        let value = ctx.argv[index].as_literal().ok_or(())?;
        if matches!(
            value,
            "-p" | "--project-dir" | "-b" | "--build-file" | "-x" | "--exclude-task"
        ) {
            let operand = ctx
                .argv
                .get(index + 1)
                .and_then(|word| word.as_literal())
                .ok_or(())?;
            if matches!(value, "-x" | "--exclude-task") && operand == "run" {
                excluded = true;
            }
            index += 2;
            continue;
        }
        if let Some(task) = value.strip_prefix("--exclude-task=") {
            excluded |= task == "run";
            index += 1;
            continue;
        }
        if value.starts_with('-') {
            return Err(());
        }
        if value == "run" {
            run = Some(index);
        }
        index += 1;
    }
    Ok((!excluded).then_some(run).flatten())
}

fn option_value<'a>(ctx: &'a InvocationCtx<'_>, names: &[&str]) -> Option<&'a str> {
    ctx.argv.windows(2).find_map(|pair| {
        names
            .contains(&pair[0].as_literal()?)
            .then(|| pair[1].as_literal())
            .flatten()
    })
}

fn xml_text(source: &str, tag: &str) -> Option<String> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let value = source.split_once(&start)?.1.split_once(&end)?.0.trim();
    (!value.is_empty() && !value.contains('<') && !value.contains("${")).then(|| value.to_string())
}

fn maven_exec_main_class(source: &str) -> Option<String> {
    let mut rest = source;
    while let Some((_, after_start)) = rest.split_once("<plugin>") {
        let (plugin, after_end) = after_start.split_once("</plugin>")?;
        if xml_text(plugin, "artifactId").as_deref() == Some("exec-maven-plugin") {
            return xml_text(plugin, "mainClass");
        }
        rest = after_end;
    }
    None
}

fn gradle_main_class(source: &str) -> Option<String> {
    for raw in source.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        for key in ["mainClass", "mainClassName"] {
            if let Some(value) = line.strip_prefix(key).and_then(|rest| {
                let rest = rest.trim_start();
                if let Some(value) = rest.strip_prefix('=') {
                    unquote_exact(value.trim())
                } else if let Some(value) = rest.strip_prefix(".set(") {
                    unquote_exact(value.strip_suffix(')')?.trim())
                } else {
                    None
                }
            }) {
                return Some(value);
            }
        }
    }
    None
}

fn gradle_application_plugin(source: &str) -> bool {
    source.lines().any(|raw| {
        let line = raw.split("//").next().unwrap_or("").trim();
        line == "application {"
            || line.contains("id 'application'")
            || line.contains("id(\"application\")")
            || line.contains("plugin: 'application'")
            || line.contains("plugin: \"application\"")
    })
}

fn unquote_or_verbatim(value: &str) -> String {
    unquote_exact(value).unwrap_or_else(|| value.to_string())
}

fn unquote_exact(value: &str) -> Option<String> {
    (value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))))
    .then(|| value[1..value.len() - 1].to_string())
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}
