//! Source-file launchers whose literal operands can be analyzed from a
//! caller-supplied repository source resolver.

use std::collections::BTreeMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionEdgeKind, ExecutionInputReason, ExecutionInputRole, ExecutionPhase, ExecutionSelector,
    ProvenanceRef, ResourceExpr, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::args::{self, FlagSpec};
use crate::models::common::{
    RuntimeSourceLanguage, arg_effect, arg_node, code_execution, operand_effect,
    runtime_selected_source, runtime_unobserved_input, runtime_unobserved_input_scoped,
};
use crate::models::{CommandModel, InvocationCtx, source_refusal_detail};
use crate::nest::{SourceResolution, Transition};
use crate::value::unresolved_resource;
use crate::word::Word;

pub(super) fn sourceexec_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(GoRun), Box::new(JavaSource), Box::new(RustScript)]
}

struct GoRun;
struct JavaSource;
struct RustScript;

const JAVA_VALUE_OPTIONS: &[&str] = &[
    "--class-path",
    "-classpath",
    "-cp",
    "--module-path",
    "-p",
    "--source",
    "--source-path",
    "--upgrade-module-path",
    "--add-modules",
    "--enable-native-access",
    "--limit-modules",
    "--add-reads",
    "--add-exports",
    "--add-opens",
    "--patch-module",
];

impl CommandModel for GoRun {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "go/verbs@v3"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["go"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx.argv.get(1).and_then(Word::as_literal) != Some("run") {
            go_verb(builder, ctx, model_node);
            return;
        }
        let Some((index, script)) = program_operand(
            &ctx.argv[2..],
            2,
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
        ) else {
            source_unavailable(
                builder,
                model_node,
                "go run source is not a bounded literal file or package",
            );
            return;
        };
        let Some(value) = script.as_literal() else {
            source_unavailable(builder, model_node, "go run source is symbolic");
            return;
        };
        if value.ends_with(".go") {
            for (offset, script) in
                ctx.argv[index..]
                    .iter()
                    .enumerate()
                    .take_while(|(_, script)| {
                        script
                            .as_literal()
                            .is_some_and(|value| value.ends_with(".go"))
                    })
            {
                nest_go(builder, ctx, model_node, index + offset, script, None);
            }
        } else if matches!(value, "." | "./") || value.starts_with("./") || value.starts_with("../")
        {
            let path = if matches!(value, "." | "./") {
                "main.go".to_string()
            } else {
                format!("{}/main.go", value.trim_end_matches('/'))
            };
            nest_go(builder, ctx, model_node, index, script, Some(&path));
        } else {
            source_unavailable(
                builder,
                model_node,
                "go run package is not an exact local path",
            );
        }
    }
}

impl CommandModel for JavaSource {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "java/source-file@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["java"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        java_agent_inputs(builder, ctx, model_node);
        let operand = program_operand(
            &ctx.argv[1..],
            1,
            JAVA_VALUE_OPTIONS,
            &["-jar", "-m", "--module"],
        );
        let Some((index, script)) = operand else {
            crate::exec::unmodeled(
                builder,
                model_node,
                "java invocation is outside the source-file launch model",
            );
            return;
        };
        match script.as_literal() {
            Some(value) if value.ends_with(".java") => {
                nest(builder, ctx, model_node, index, script, |source| {
                    Subject::Source {
                        dialect: None,
                        language: "java".to_string(),
                        source,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    }
                })
            }
            None => source_unavailable(
                builder,
                model_node,
                "java source is not a bounded literal file",
            ),
            Some(_) => crate::exec::unmodeled(
                builder,
                model_node,
                "java invocation is outside the source-file launch model",
            ),
        }
    }
}

const GO_FLAGS: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "-o",
        "-tags",
        "-ldflags",
        "-asmflags",
        "-buildmode",
        "-compiler",
        "-covermode",
        "-coverpkg",
        "-coverprofile",
        "-exec",
        "-gccgoflags",
        "-gcflags",
        "-installsuffix",
        "-mod",
        "-modfile",
        "-overlay",
        "-p",
        "-pgo",
        "-pkgdir",
        "-toolexec",
        "-run",
        "-bench",
        "-benchtime",
        "-count",
        "-cpu",
        "-parallel",
        "-timeout",
        "-vet",
        "-fuzz",
        "-fuzztime",
        "-fuzzminimizetime",
        "-blockprofile",
        "-cpuprofile",
        "-memprofile",
        "-mutexprofile",
        "-trace",
        "-outputdir",
    ],
    known_flags: &[
        "-a",
        "-n",
        "-race",
        "-msan",
        "-asan",
        "-v",
        "-work",
        "-x",
        "-trimpath",
        "-buildvcs",
        "-cover",
        "-short",
        "-failfast",
        "-json",
        "-c",
        "-i",
        "-w",
        "-u",
        "-e",
        "-m",
        "-d",
    ],
};

fn go_args(argv: &[Word]) -> args::Scanned<'_> {
    let mut scanned = args::scan(argv, &GO_FLAGS);
    // Go accepts -o=file; POSIX tools treat the equals sign as part of the value.
    for flag in &mut scanned.flags {
        if flag.name.len() == 2
            && argv[flag.index as usize].parts.first().is_some_and(|part| {
                matches!(part, crate::word::WordPart::Literal(head) if head.starts_with(&format!("{}=", flag.name)))
            })
        {
            flag.value = Some(args::strip_literal_prefix(&argv[flag.index as usize], 3));
        }
    }
    scanned
}

fn go_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    detail: &str,
    domains: &[&str],
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::DYNAMIC_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

fn go_env_path(
    ctx: &InvocationCtx<'_>,
    name: &str,
    base: ResourceExpr,
    suffix: &str,
) -> ResourceExpr {
    if let Some(value) = ctx.environment_value(name) {
        return match value {
            ResourceExpr::Literal { value } => ctx.resolve_fs_word(&Word::literal(value)),
            value => value,
        };
    }
    ResourceExpr::Join {
        parts: vec![
            base,
            ResourceExpr::Literal {
                value: format!("/{suffix}"),
            },
        ],
    }
}

fn go_verb(builder: &mut PlanBuilder, ctx: &InvocationCtx<'_>, model_node: ProvenanceRef) {
    let verb = ctx.argv.get(1).and_then(Word::as_literal).unwrap_or("");
    if !matches!(
        verb,
        "build"
            | "install"
            | "test"
            | "vet"
            | "version"
            | "fmt"
            | "env"
            | "mod"
            | "generate"
            | "tool"
    ) {
        crate::exec::unmodeled(builder, model_node, "unsupported go verb");
        return;
    }
    for domain in ["filesystem", "network", "process"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    let offset = if verb == "mod" { 2 } else { 1 };
    if verb == "mod"
        && !matches!(
            ctx.argv.get(2).and_then(Word::as_literal),
            Some("download" | "tidy" | "vendor")
        )
    {
        crate::exec::unmodeled(builder, model_node, "unsupported go mod verb");
        return;
    }
    let scanned = go_args(&ctx.argv[offset..]);
    if !scanned.unknown_flags.is_empty() {
        go_boundary(
            builder,
            model_node,
            "unrecognized go options",
            &["filesystem", "network", "process"],
        );
    }
    if verb == "install" && scanned.has(&["-o"]) {
        go_boundary(
            builder,
            model_node,
            "go install does not accept -o",
            &["filesystem"],
        );
        return;
    }
    let home = ctx
        .environment_value("HOME")
        .unwrap_or(ResourceExpr::Parameter {
            name: "HOME".to_string(),
        });
    let gopath = go_env_path(ctx, "GOPATH", home.clone(), "go");
    let cache = go_env_path(ctx, "GOCACHE", home.clone(), ".cache/go-build");
    let package_cache = ResourceExpr::Join {
        parts: vec![
            gopath.clone(),
            ResourceExpr::Literal {
                value: "/pkg".to_string(),
            },
        ],
    };
    let build = matches!(verb, "build" | "install" | "test");
    if build || matches!(verb, "vet" | "fmt" | "generate" | "version") {
        if scanned.operands.is_empty() && verb != "version" {
            operand_effect(
                builder,
                ctx,
                model_node,
                1,
                &Word::literal("."),
                "filesystem.read",
                BTreeMap::new(),
            );
        }
        if verb == "fmt" && scanned.operands.is_empty() {
            operand_effect(
                builder,
                ctx,
                model_node,
                1,
                &Word::literal("."),
                "filesystem.write",
                BTreeMap::new(),
            );
        }
        for (index, word) in &scanned.operands {
            if scanned
                .unknown_flags
                .iter()
                .any(|(unknown, _)| unknown < index)
            {
                continue;
            }
            if verb == "install" && word.as_literal().is_some_and(|value| value.contains('@')) {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    *index + offset as u32,
                    "network.download",
                    unresolved_resource("network"),
                    BTreeMap::new(),
                );
                continue;
            }
            // Import paths resolve through the module graph, not relative to cwd.
            if verb != "version"
                && word.as_literal().is_some_and(|value| {
                    !matches!(value, "." | "..")
                        && !value.starts_with("./")
                        && !value.starts_with("../")
                        && !value.starts_with('/')
                        && !value.ends_with(".go")
                })
            {
                go_boundary(
                    builder,
                    model_node,
                    "go package import path requires module resolution",
                    &["filesystem", "network"],
                );
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                *index + offset as u32,
                word,
                "filesystem.read",
                BTreeMap::new(),
            );
            if verb == "fmt" {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index + offset as u32,
                    word,
                    "filesystem.write",
                    BTreeMap::new(),
                );
            }
        }
    }
    if build {
        for resource in [cache, package_cache] {
            arg_effect(
                builder,
                ctx,
                model_node,
                1,
                "filesystem.write",
                resource,
                BTreeMap::new(),
            );
        }
        if verb == "install" {
            let bin = go_env_path(ctx, "GOBIN", gopath.clone(), "bin");
            // Package patterns and symbolic operands do not identify one executable.
            let packages: Vec<_> = if scanned.operands.is_empty() {
                vec![(1, Word::literal("."))]
            } else {
                scanned
                    .operands
                    .iter()
                    .map(|(index, word)| (*index + offset as u32, (*word).clone()))
                    .collect()
            };
            for (index, package) in packages {
                let name = package.as_literal().and_then(|value| {
                    let path = value
                        .split('@')
                        .next()
                        .unwrap_or(value)
                        .trim_end_matches('/');
                    if path == "." {
                        ctx.cwd
                            .and_then(|cwd| cwd.trim_end_matches('/').rsplit('/').next())
                    } else {
                        path.rsplit('/').next().filter(|name| !name.contains("..."))
                    }
                });
                let resource = match name {
                    Some(name) => ResourceExpr::Join {
                        parts: vec![
                            bin.clone(),
                            ResourceExpr::Literal {
                                value: format!("/{name}"),
                            },
                        ],
                    },
                    None => bin.clone(),
                };
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "filesystem.write",
                    resource,
                    BTreeMap::new(),
                );
            }
        } else if let Some((index, output)) = scanned.values_of(&["-o"]).last() {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index + offset as u32,
                output,
                "filesystem.write",
                BTreeMap::new(),
            );
        } else if verb != "test" && scanned.unknown_flags.is_empty() {
            let package = scanned.operands.last().map(|(_, word)| *word);
            let basename = package.and_then(Word::as_literal).map(|package| {
                package
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or(package)
            });
            let output = match basename {
                None | Some("." | "") if package.is_none() || basename.is_some() => ctx
                    .cwd
                    .and_then(|cwd| cwd.trim_end_matches('/').rsplit('/').next())
                    .map(Word::literal),
                Some(name) if !name.contains("...") => {
                    Some(Word::literal(name.trim_end_matches(".go")))
                }
                _ => None,
            };
            if let Some(output) = output {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    1,
                    &output,
                    "filesystem.write",
                    BTreeMap::new(),
                );
            }
        }
        let goflags = match ctx.environment_value("GOFLAGS") {
            Some(ResourceExpr::Literal { value }) => {
                let mut words = vec![Word::literal("go")];
                words.extend(value.split_ascii_whitespace().map(Word::literal));
                words
            }
            _ => Vec::new(),
        };
        let env_flags = go_args(&goflags);
        if scanned
            .value_of(&["-mod"])
            .or_else(|| env_flags.value_of(&["-mod"]))
            .and_then(Word::as_literal)
            == Some("mod")
        {
            arg_effect(
                builder,
                ctx,
                model_node,
                1,
                "network.download",
                unresolved_resource("network"),
                BTreeMap::new(),
            );
        }
        go_toolexec_input(builder, ctx, model_node);
    }
    match verb {
        "test" => {
            code_execution(
                effinterp_proto::RequestAssurance::Conservative,
                builder,
                ctx,
                model_node,
                Some(1),
                "go test binaries",
                BTreeMap::new(),
            );
            for (index, output) in scanned.values_of(&[
                "-coverprofile",
                "-blockprofile",
                "-cpuprofile",
                "-memprofile",
                "-mutexprofile",
                "-trace",
            ]) {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index + offset as u32,
                    output,
                    "filesystem.write",
                    BTreeMap::new(),
                );
            }
        }
        "version" => {
            let resource = ctx
                .environment_value("GOROOT")
                .unwrap_or(ResourceExpr::Parameter {
                    name: "GOROOT".to_string(),
                });
            arg_effect(
                builder,
                ctx,
                model_node,
                1,
                "filesystem.read",
                resource,
                BTreeMap::new(),
            );
        }
        "env" => {
            let resource = go_env_path(ctx, "GOENV", home, ".config/go/env");
            arg_effect(
                builder,
                ctx,
                model_node,
                1,
                if scanned.has(&["-w", "-u"]) {
                    "filesystem.write"
                } else {
                    "filesystem.read"
                },
                resource,
                BTreeMap::new(),
            );
        }
        "mod" => {
            arg_effect(
                builder,
                ctx,
                model_node,
                2,
                "network.download",
                unresolved_resource("network"),
                BTreeMap::new(),
            );
            let resource = go_env_path(ctx, "GOMODCACHE", gopath, "pkg/mod");
            arg_effect(
                builder,
                ctx,
                model_node,
                2,
                "filesystem.write",
                resource,
                BTreeMap::new(),
            );
            if ctx.argv[2].as_literal() == Some("tidy") {
                for path in ["go.mod", "go.sum"] {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        2,
                        &Word::literal(path),
                        "filesystem.write",
                        BTreeMap::new(),
                    );
                }
            }
            if ctx.argv[2].as_literal() == Some("vendor") {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    2,
                    &Word::literal("vendor"),
                    "filesystem.write",
                    BTreeMap::new(),
                );
            }
        }
        "generate" | "tool" => {
            arg_effect(
                builder,
                ctx,
                model_node,
                1,
                "process.exec",
                unresolved_resource("process"),
                BTreeMap::new(),
            );
            if verb == "generate" {
                go_boundary(
                    builder,
                    model_node,
                    "go generate directives select runtime commands",
                    &["process"],
                );
            }
        }
        _ => {}
    }
}

fn go_toolexec_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    let mut request: Option<Word> = None;
    let mut uncertain = false;
    let mut selector = ExecutionSelector::RuntimeOption {
        option: "-toolexec".to_string(),
    };
    if let Some(value) = ctx.environment_value("GOENV")
        && value
            != (ResourceExpr::Literal {
                value: "off".to_string(),
            })
    {
        uncertain = true;
        selector = ExecutionSelector::Environment {
            variable: "GOENV".to_string(),
        };
    }
    if let Some(value) = ctx.environment_value("GOFLAGS") {
        selector = ExecutionSelector::Environment {
            variable: "GOFLAGS".to_string(),
        };
        match value {
            ResourceExpr::Literal { value } if !value.contains('$') => {
                let mut words = vec![Word::literal("go")];
                words.extend(value.split_ascii_whitespace().map(Word::literal));
                let flags = go_args(&words);
                if let Some(flag) = flags
                    .flags
                    .iter()
                    .rev()
                    .find(|flag| flag.name == "-toolexec")
                {
                    request = flag.value.clone();
                    uncertain = request.is_none();
                }
            }
            _ => uncertain = true,
        }
    }
    // Build options stop at the first package operand, unlike test options.
    let flags = go_args(&ctx.argv[1..]);
    let end = flags
        .operands
        .first()
        .map(|(index, _)| *index)
        .unwrap_or(u32::MAX);
    if let Some(flag) = flags.flags.iter().rev().find(|flag| {
        flag.name == "-toolexec" && (flag.index < end || ctx.argv[1].as_literal() == Some("test"))
    }) {
        request = flag.value.clone();
        uncertain = request.is_none();
        selector = ExecutionSelector::RuntimeOption {
            option: "-toolexec".to_string(),
        };
    }
    let literal = request.as_ref().and_then(Word::as_literal);
    uncertain |= request.is_some() && literal.is_none();
    uncertain |= literal.is_some_and(|value| {
        !value.is_empty()
            && (!value.contains('/')
                || value
                    .chars()
                    .any(|ch| ch.is_whitespace() || matches!(ch, '\'' | '"' | '$')))
    });
    if uncertain {
        runtime_unobserved_input_scoped(
            builder,
            ctx,
            literal
                .filter(|value| !value.is_empty())
                .unwrap_or("-toolexec"),
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::BuildHook,
            selector,
            ExecutionInputReason::Ambiguous,
            Some(&["process"]),
        );
    } else if let Some(request) = literal.filter(|value| !value.is_empty()) {
        runtime_selected_source(
            builder,
            ctx,
            model_node,
            request,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::BuildHook,
            selector,
            RuntimeSourceLanguage::Executable,
        );
    }
}

fn java_agent_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    for variable in ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"] {
        let Some(value) = ctx.environment_value(variable) else {
            continue;
        };
        let ResourceExpr::Literal { value } = value else {
            runtime_unobserved_input(
                builder,
                ctx,
                &format!("${variable}"),
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Preload,
                ExecutionSelector::Environment {
                    variable: variable.to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            continue;
        };
        for option in value.split_ascii_whitespace() {
            if let Some(request) = java_agent_path(option) {
                runtime_selected_source(
                    builder,
                    ctx,
                    model_node,
                    request,
                    ExecutionInputRole::UnexpectedSelected,
                    ExecutionPhase::Preload,
                    ExecutionSelector::Environment {
                        variable: variable.to_string(),
                    },
                    RuntimeSourceLanguage::Opaque,
                );
            }
        }
    }
    let mut index = 1;
    while index < ctx.argv.len() {
        let Some(option) = ctx.argv[index].as_literal() else {
            break;
        };
        if !option.starts_with('-')
            || matches!(option, "--" | "-jar" | "-m" | "--module")
            || option.starts_with("--module=")
        {
            break;
        }
        if JAVA_VALUE_OPTIONS.contains(&option) {
            index += 2;
            continue;
        }
        if let Some(request) = java_agent_path(option) {
            runtime_selected_source(
                builder,
                ctx,
                model_node,
                request,
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Preload,
                ExecutionSelector::RuntimeOption {
                    option: option.split(':').next().unwrap_or(option).to_string(),
                },
                RuntimeSourceLanguage::Opaque,
            );
        }
        index += 1;
    }
}

fn java_agent_path(option: &str) -> Option<&str> {
    option
        .strip_prefix("-javaagent:")
        .map(|value| value.split('=').next().unwrap_or(value))
        .or_else(|| {
            option
                .strip_prefix("-agentpath:")
                .map(|value| value.split('=').next().unwrap_or(value))
        })
}

impl CommandModel for RustScript {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "rust/script-source@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["rust-script"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let Some((index, script)) =
            program_operand(&ctx.argv[1..], 1, &[], &[]).filter(|(_, script)| {
                script
                    .as_literal()
                    .is_some_and(|value| value.ends_with(".rs"))
            })
        else {
            source_unavailable(
                builder,
                model_node,
                "Rust source is not a bounded literal file",
            );
            return;
        };
        nest(builder, ctx, model_node, index, script, |source| {
            Subject::Source {
                dialect: None,
                language: "rust".to_string(),
                source,
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            }
        });
    }
}

fn program_operand<'a>(
    args: &'a [Word],
    offset: usize,
    value_flags: &[&str],
    blocked_flags: &[&str],
) -> Option<(usize, &'a Word)> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_literal() {
            Some("--") => return args.get(index + 1).map(|arg| (offset + index + 1, arg)),
            Some(flag)
                if blocked_flags.iter().any(|blocked| {
                    flag == *blocked
                        || flag
                            .strip_prefix(blocked)
                            .is_some_and(|value| value.starts_with('='))
                }) =>
            {
                return None;
            }
            Some(flag) if value_flags.contains(&flag) => index += 2,
            Some(flag) if flag.starts_with('-') => index += 1,
            Some(_) => return Some((offset + index, &args[index])),
            None => return None,
        }
    }
    None
}

pub(crate) fn nest(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    script: &Word,
    subject: impl FnOnce(String) -> Subject,
) {
    operand_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        script,
        "filesystem.read",
        BTreeMap::new(),
    );
    let resolved = script
        .as_literal()
        .map_or(SourceResolution::Unavailable, |path| {
            ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput)
        });
    match resolved {
        SourceResolution::Source {
            origin: path,
            source,
        } => {
            let arg = arg_node(builder, ctx, index as u32);
            ctx.nest_file_subject(builder, subject(source), &[model_node, arg], path);
        }
        SourceResolution::Refused(refusal) => {
            if let Some(detail) =
                source_refusal_detail(builder, refusal, "source file is unavailable")
            {
                source_unavailable(builder, model_node, &detail);
            }
        }
        SourceResolution::UnsupportedEncoding => {
            source_unavailable(builder, model_node, "source file is not valid UTF-8")
        }
        SourceResolution::AlreadySelected => (),
        SourceResolution::Unavailable => {
            source_unavailable(builder, model_node, "source file is unavailable")
        }
    }
}

fn nest_go(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    operand: &Word,
    source_path: Option<&str>,
) {
    operand_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        operand,
        "filesystem.read",
        BTreeMap::new(),
    );
    let resolved = source_path
        .or_else(|| operand.as_literal())
        .map_or(SourceResolution::Unavailable, |path| {
            ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput)
        });
    match resolved {
        SourceResolution::Source {
            origin: path,
            source,
        } => {
            if source_path.is_some() {
                let Some(siblings) = ctx.source_siblings(&path) else {
                    ctx.nest.record_unsupported_source(builder, &path);
                    source_unavailable(
                        builder,
                        model_node,
                        "go run package sibling source closure is unavailable",
                    );
                    return;
                };
                if siblings
                    .iter()
                    .any(|sibling| sibling.ends_with(".go") && !sibling.ends_with("_test.go"))
                {
                    ctx.nest.record_unsupported_source(builder, &path);
                    source_unavailable(
                        builder,
                        model_node,
                        "go run package contains unmodeled sibling Go sources",
                    );
                    return;
                }
            }
            let arg = arg_node(builder, ctx, index as u32);
            {
                let origin = path;
                let source_cwd = crate::models::source_parent(&origin).to_string();
                ctx.nest.nest(
                    builder,
                    Transition::file(Subject::Source {
                        dialect: None,
                        language: "go".to_string(),
                        source,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .origin(origin)
                    .kind(ExecutionEdgeKind::BuildTarget)
                    .source_cwd(Some(&source_cwd))
                    .runtime_cwd(ctx.runtime_cwd)
                    .cwd(ctx.cwd_resource.clone(), ctx.cwd_node),
                    &[model_node, arg],
                    ctx.depth,
                );
            };
        }
        SourceResolution::Refused(refusal) => {
            if let Some(detail) =
                source_refusal_detail(builder, refusal, "source file is unavailable")
            {
                source_unavailable(builder, model_node, &detail);
            }
        }
        SourceResolution::UnsupportedEncoding => {
            source_unavailable(builder, model_node, "source file is not valid UTF-8")
        }
        SourceResolution::AlreadySelected => (),
        SourceResolution::Unavailable => {
            source_unavailable(builder, model_node, "source file is unavailable")
        }
    }
}

fn source_unavailable(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];
    for domain in DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
}
