use effinterp_proto::{
    CoverageLevel, Domain, ExecutionInputRole, ExecutionPhase, ExecutionSelector, ProvenanceRef,
    RequestAssurance, ResourceExpr,
};

use super::{PerlFailure, PerlImports, analyze, perl_boundary};
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{
    RuntimeSourceLanguage, code_execution, operand_effect, program_input_attrs,
    runtime_searched_source,
};
use crate::models::{CommandModel, InvocationCtx};

/// `perlMAJOR.MINOR` or `perlMAJOR.MINOR.PATCH`, as installed beside `perl`.
pub(crate) fn versioned_interpreter(name: &str) -> bool {
    let Some(version) = name.strip_prefix("perl") else {
        return false;
    };
    let parts = version.split('.').collect::<Vec<_>>();
    matches!(parts.len(), 2 | 3)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
}

pub(crate) struct Perl;

impl CommandModel for Perl {
    fn id(&self) -> &'static str {
        "perl/perl@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["perl"]
    }

    fn domains(&self) -> &'static [&'static str] {
        &KNOWN_DOMAINS
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        if !crate::nest::charge_analysis_steps(
            builder,
            ctx.nest.budget,
            ctx.argv.len() as u64,
            None,
        ) {
            return;
        }
        let launch = match Launch::parse(ctx) {
            Ok(launch) => launch,
            Err(PerlFailure::SourceBytes) => {
                builder.note_saturated_at("max_source_bytes", None);
                return;
            }
            Err(PerlFailure::AnalysisBytes | PerlFailure::AnalysisSteps) => {
                unreachable!("the launcher charges no analysis budget")
            }
            Err(PerlFailure::Refused(detail)) => {
                crate::models::common::unrecognized_arguments_boundary(
                    builder,
                    node,
                    &KNOWN_DOMAINS,
                    &[(0, detail)],
                );
                return;
            }
        };
        load_modules(builder, ctx, node, &launch);
        // Startup options and library paths can replace builtin/import ownership.
        if let Some(name) = ["PERL5OPT", "PERL5LIB", "PERLLIB"].into_iter().find(|name| {
            ctx.environment_value(name).is_some_and(|value| {
                !matches!(value, effinterp_proto::ResourceExpr::Literal { value } if value.is_empty())
            })
        }) {
            perl_boundary(builder, node, &format!("Perl {name} startup selection is not modeled"));
            return;
        }
        if launch.sources.is_empty() {
            let script = ctx.argv.get(launch.operands);
            let file = script.is_some_and(|word| word.as_literal() != Some("-"));
            // Without a script operand, or with `-`, the program is stdin.
            if !file
                && launch.unsupported.is_none()
                && let Some(source) = ctx.stdin_literal()
            {
                code_execution(
                    RequestAssurance::Conservative,
                    builder,
                    ctx,
                    node,
                    script.map(|_| launch.operands as u32),
                    "stdin",
                    Default::default(),
                );
                let mut antecedents = vec![node];
                antecedents.extend(ctx.stdin.unwrap().provenance.iter().copied());
                let source_node = builder.node(
                    effinterp_proto::ProvenanceKind::ModelApplication {
                        model: "perl/literal-source@v1".into(),
                    },
                    &antecedents,
                );
                input_operands(
                    builder,
                    ctx,
                    node,
                    &launch,
                    launch.operands + usize::from(script.is_some()),
                );
                analyze(
                    builder,
                    ctx.nest,
                    source,
                    ctx.cwd,
                    Some(source_node),
                    &launch.imports,
                    ctx.depth,
                );
                for domain in ["filesystem", "process"] {
                    builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
                }
                return;
            }
            if file {
                operand_effect(
                    builder,
                    ctx,
                    node,
                    launch.operands as u32,
                    script.unwrap(),
                    "filesystem.read",
                    Default::default(),
                );
            }
            code_execution(
                RequestAssurance::Conservative,
                builder,
                ctx,
                node,
                script.map(|_| launch.operands as u32),
                if file { "file" } else { "stdin" },
                Default::default(),
            );
            if file {
                input_operands(builder, ctx, node, &launch, launch.operands + 1);
            }
            crate::models::common::dynamic_source(
                builder,
                node,
                launch
                    .unsupported
                    .as_deref()
                    .unwrap_or("Perl file or stdin source is not supplied as literal -e/-E source"),
            );
            return;
        }
        code_execution(
            if launch.sources.iter().all(|(_, source)| source.is_some()) {
                RequestAssurance::Exact
            } else {
                RequestAssurance::Conservative
            },
            builder,
            ctx,
            node,
            Some(launch.sources[0].0 as u32),
            "argument",
            Default::default(),
        );
        if let Some(detail) = launch.unsupported.as_deref() {
            input_operands(builder, ctx, node, &launch, launch.operands);
            perl_boundary(builder, node, detail);
            return;
        }
        if launch.sources.iter().any(|(_, source)| source.is_none()) {
            input_operands(builder, ctx, node, &launch, launch.operands);
            perl_boundary(builder, node, "Perl -e/-E source is runtime-selected");
            return;
        }
        let mut antecedents = vec![node];
        for (index, _) in &launch.sources {
            antecedents.push(crate::models::common::arg_node(builder, ctx, *index as u32));
        }
        let source_node = builder.node(
            effinterp_proto::ProvenanceKind::ModelApplication {
                model: "perl/literal-source@v1".into(),
            },
            &antecedents,
        );
        // Each -e contributes a line, not an implicit statement terminator.
        let source = launch
            .sources
            .iter()
            .filter_map(|(_, s)| *s)
            .collect::<Vec<_>>()
            .join("\n");
        input_operands(builder, ctx, node, &launch, launch.operands);
        analyze(
            builder,
            ctx.nest,
            &source,
            ctx.cwd,
            Some(source_node),
            &launch.imports,
            ctx.depth,
        );
        for domain in ["filesystem", "process"] {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

/// A `-M` module found under a `-Mlib=DIR`, `-I`, `PERL5LIB` or `PERLLIB`
/// directory is that file: those directories precede the installed ones in
/// `@INC`, `lib`'s first and the latest of them before the earlier. Its
/// source is not read as Perl, so it is recorded as code the launch runs. A
/// module found in none of them comes from the installed directories, which
/// this search does not cover.
fn load_modules(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    launch: &Launch<'_>,
) {
    // Perl reads PERLLIB only when PERL5LIB is not set.
    let library = ["PERL5LIB", "PERLLIB"]
        .into_iter()
        .find_map(|name| ctx.environment_value(name));
    let mut inherited = launch.include.clone();
    if let Some(ResourceExpr::Literal { value }) = &library {
        inherited.extend(value.split(':').filter(|directory| !directory.is_empty()));
    }
    for (module, libraries) in &launch.modules {
        let directories: Vec<_> = launch.libraries[..*libraries]
            .iter()
            .rev()
            .chain(&inherited)
            .collect();
        if directories.is_empty() {
            continue;
        }
        let file = format!("{}.pm", module.replace("::", "/"));
        runtime_searched_source(
            builder,
            ctx,
            node,
            module,
            directories
                .iter()
                .map(|directory| format!("{directory}/{file}"))
                .collect(),
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: "-M".into(),
            },
            RuntimeSourceLanguage::Opaque,
            false,
        );
    }
}

/// The files the implicit `-n`/`-p` input loop reads and `-i` rewrites in
/// place, from argument `first` on. The loop opens them whatever the program
/// is, so a script whose source is unknown still names them.
fn input_operands(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    launch: &Launch<'_>,
    first: usize,
) {
    if launch.in_place.is_some() || launch.loop_input {
        if first == ctx.argv.len() {
            perl_boundary(builder, node, "Perl implicit input loop selects stdin");
        }
        for (index, operand) in ctx.argv.iter().enumerate().skip(first) {
            let Some(path) = operand
                .as_literal()
                .filter(|path| *path != "-" && !path.is_empty())
            else {
                perl_boundary(
                    builder,
                    node,
                    "Perl input operand is dynamic or selects stdin",
                );
                continue;
            };
            if launch.in_place.is_none()
                && (path.starts_with('|')
                    || path.ends_with('|')
                    || path.trim() != path
                    || path.starts_with(['<', '>', '+', '&']))
            {
                perl_boundary(
                    builder,
                    node,
                    "Perl diamond input operand can select a pipe or trimmed filename",
                );
                continue;
            }
            // The loop hands every line to the program as `$_`, which `-p`
            // and a bare `print` write out, so the read is program input as
            // awk's and sed's operands are.
            if launch.loop_input {
                operand_effect(
                    builder,
                    ctx,
                    node,
                    index as u32,
                    operand,
                    "filesystem.read",
                    program_input_attrs(),
                );
            }
            if let Some(extension) = launch.in_place {
                operand_effect(
                    builder,
                    ctx,
                    node,
                    index as u32,
                    operand,
                    "filesystem.write",
                    Default::default(),
                );
                if !extension.is_empty() {
                    let backup = if extension.contains('*') {
                        extension.replace('*', path)
                    } else {
                        format!("{path}{extension}")
                    };
                    operand_effect(
                        builder,
                        ctx,
                        node,
                        index as u32,
                        &crate::word::Word::literal(backup),
                        "filesystem.write",
                        Default::default(),
                    );
                }
            }
        }
    }
}

#[derive(Default)]
struct Launch<'a> {
    sources: Vec<(usize, Option<&'a str>)>,
    unsupported: Option<String>,
    operands: usize,
    in_place: Option<&'a str>,
    loop_input: bool,
    imports: PerlImports,
    /// `-I` directories, in order.
    include: Vec<&'a str>,
    /// Directories `-Mlib=DIR` and `-M'lib DIR'` add, in order.
    libraries: Vec<&'a str>,
    /// Modules named by `-M` and `-m`, in order, each with how many of
    /// `libraries` were added before it.
    modules: Vec<(&'a str, usize)>,
}

impl<'a> Launch<'a> {
    fn parse(ctx: &'a InvocationCtx) -> Result<Self, PerlFailure> {
        let mut launch = Self::default();
        let mut i = 1;
        let mut bytes = 0;
        while i < ctx.argv.len() {
            if ctx.argv[i].as_literal().is_none()
                && crate::models::common::is_attached_inline_source(&ctx.argv[i], &["-e", "-E"])
            {
                launch.sources.push((i, None));
                i += 1;
                continue;
            }
            let Some(word) = ctx.argv[i].as_literal() else {
                // Before any -e source, a dynamic word is most likely the
                // script, whose source stays unknown either way; after one, it
                // could add source this launch never sees.
                if !launch.sources.is_empty() {
                    return Err("Perl launcher argument is dynamic".into());
                }
                launch.unsupported = Some("Perl launcher argument is dynamic".into());
                break;
            };
            if word == "--" {
                i += 1;
                break;
            }
            if !word.starts_with('-') || word == "-" {
                break;
            }
            // Digits a -0 or -l switch consumes; clustered switches may follow them.
            let mut value_end = 0;
            for (offset, flag) in word[1..].char_indices() {
                if offset < value_end {
                    continue;
                }
                match flag {
                    'w' => {}
                    'W' | 'T' | 't' | 'f' | 's' | 'U' | 'a' => {
                        launch.unsupported =
                            Some(format!("Perl -{flag} execution semantics are not modeled"));
                    }
                    'l' | '0' => {
                        launch.unsupported =
                            Some(format!("Perl -{flag} execution semantics are not modeled"));
                        value_end = offset
                            + 1
                            + word[offset + 2..]
                                .bytes()
                                .take_while(u8::is_ascii_digit)
                                .count();
                    }
                    'C' => {
                        launch.unsupported =
                            Some(format!("Perl -{flag} execution semantics are not modeled"));
                        if !word[offset + 2..].is_empty() {
                            if !word[offset + 2..].bytes().all(|c| c.is_ascii_digit()) {
                                return Err(
                                    format!("Perl -{flag} option suffix is not modeled").into()
                                );
                            }
                            break;
                        }
                    }
                    'I' => {
                        launch.unsupported =
                            Some("Perl -I module search path is not modeled".into());
                        let mut directory = Some(&word[offset + 2..]);
                        if word[offset + 2..].is_empty() {
                            i += 1;
                            if i == ctx.argv.len() {
                                return Err("Perl -I directory is missing".into());
                            }
                            directory = ctx.argv[i].as_literal();
                        }
                        launch.include.extend(directory);
                        break;
                    }
                    'p' | 'n' => launch.loop_input = true,
                    'i' => {
                        launch.in_place = Some(&word[offset + 2..]);
                        break;
                    }
                    'e' | 'E' | 'M' | 'm' => {
                        let mut value = &word[offset + 2..];
                        if value.is_empty() {
                            if matches!(flag, 'M' | 'm') {
                                return Err(format!(
                                    "Perl -{flag} requires an attached module name"
                                )
                                .into());
                            }
                            i += 1;
                            let source = ctx
                                .argv
                                .get(i)
                                .ok_or_else(|| format!("Perl -{flag} source is missing"))?;
                            let Some(literal) = source.as_literal() else {
                                launch.sources.push((i, None));
                                break;
                            };
                            value = literal;
                        }
                        if matches!(flag, 'e' | 'E') {
                            bytes += value.len() + 1;
                            if bytes as u64 > ctx.nest.limits.max_source_bytes {
                                return Err(PerlFailure::SourceBytes);
                            }
                            launch.sources.push((i, Some(value)));
                        } else {
                            // `-M-Module` unimports, and `-MModule=a,b` or
                            // `-M'Module qw(a b)'` names an import list.
                            let module = value.strip_prefix('-').unwrap_or(value);
                            let (name, list) =
                                module.split_once(['=', ' ']).unwrap_or((module, ""));
                            launch.modules.push((name, launch.libraries.len()));
                            // `use lib` takes effect before the next module
                            // loads; `-M-lib` removes directories instead.
                            // Only plain directory names are read. One
                            // list is stored last first, because the search
                            // reads `libraries` backwards.
                            if name == "lib" && !value.starts_with('-') {
                                launch.libraries.extend(
                                    list.split([',', ' '])
                                        .rev()
                                        .map(|directory| directory.trim_matches(['"', '\'']))
                                        .filter(|directory| {
                                            !directory.is_empty()
                                                && !directory.contains(['$', '@', '(', ')', '`'])
                                        }),
                                );
                            }
                            if let Err(detail) = launch.imports.add(value, flag == 'M') {
                                launch.unsupported = Some(detail);
                            }
                        }
                        break;
                    }
                    _ => {
                        return Err(format!(
                            "Perl launcher option -{flag} is outside the bounded grammar"
                        )
                        .into());
                    }
                }
            }
            i += 1;
        }
        launch.operands = i;
        Ok(launch)
    }
}
