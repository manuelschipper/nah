use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
    ResourceExpr, Subject,
};

use crate::builder::PlanBuilder;
use crate::models::args::{Flag, FlagSpec, Scanned, basename, scan, scan_with_value_indices};
use crate::models::common::{
    arg_effect, arg_node, attrs, code_execution, filesystem_read_stdout_binding, fs_full_no_spawn,
    operand_effect, operands_read_stdin, program_input_attrs, program_output_attrs,
    stdin_stdout_binding, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx, ModelCausalBinding};
use crate::word::{Word, WordPart};

pub(crate) fn coreutils_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Sort),
        Box::new(Wc),
        Box::new(Grep),
        Box::new(Pager),
        Box::new(Base64),
        Box::new(Cut),
        Box::new(Awk),
        Box::new(Inert),
        Box::new(OpenSslEnc),
        Box::new(Ed),
        Box::new(Ex),
    ]
}

pub(crate) fn with_xxd_decode(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(XxdDecode { owner })
}

struct XxdDecode {
    owner: Box<dyn CommandModel>,
}

const XXD_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-c", "--cols", "-l", "--len", "-s", "--seek"],
    known_flags: &["-r", "--revert", "-p", "--plain", "-i", "--include"],
};

fn xxd_decode_stream(argv: &[Word]) -> Option<Scanned<'_>> {
    let scanned = scan(argv, &XXD_SPEC);
    (argv.iter().all(|word| word.as_literal().is_some())
        && scanned.unknown_flags.is_empty()
        && scanned.has(&["-r", "--revert"])
        && !scanned.has(&["-i", "--include"])
        && scanned.operands.len() <= 2
        && scanned.flags.iter().all(|flag| {
            !XXD_SPEC.value_flags.contains(&flag.name)
                || flag
                    .value
                    .as_ref()
                    .and_then(Word::as_literal)
                    .is_some_and(|value| !value.is_empty())
        }))
    .then_some(scanned)
}

impl CommandModel for XxdDecode {
    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn records_process(&self) -> bool {
        self.owner.records_process()
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.stdout_value_bindings(argv)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        use crate::models::ModelBindingEnd;
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::{CausalAssurance, Port};

        let Some(scanned) = xxd_decode_stream(argv) else {
            return self.owner.causal_bindings(argv);
        };
        let source = if scanned
            .operands
            .first()
            .is_some_and(|(_, input)| input.as_literal() != Some("-"))
        {
            ModelBindingEnd::Effect {
                operation: "filesystem.read".into(),
                selection: EffectSelection::All,
            }
        } else {
            ModelBindingEnd::Port(Port::Stdin)
        };
        let output = if scanned
            .operands
            .get(1)
            .is_some_and(|(_, output)| output.as_literal() != Some("-"))
        {
            ModelBindingEnd::Effect {
                operation: "filesystem.write".into(),
                selection: EffectSelection::All,
            }
        } else {
            ModelBindingEnd::Port(Port::Stdout)
        };
        let transform = ModelBindingEnd::Effect {
            operation: "process.stream_transform".into(),
            selection: EffectSelection::All,
        };
        vec![
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: source.clone(),
                to: output.clone(),
            },
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: source,
                to: transform.clone(),
            },
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: transform,
                to: output,
            },
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        self.owner.apply(builder, ctx, model_node);
        if xxd_decode_stream(ctx.argv).is_none() {
            return;
        }
        builder.effect(effinterp_proto::Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: effinterp_proto::Operation::new("process.stream_transform"),
            resource: crate::models::common::code_execution_resource(ctx),
            attributes: std::collections::BTreeMap::from([(
                "transform".into(),
                effinterp_proto::AttrValue::String("decode".into()),
            )]),
            modality: effinterp_proto::Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![model_node],
        });
    }
}

/// `sort [OPTION]... [FILE]...`: reads its file operands; `-o FILE` (not a
/// positional operand) writes the sorted result there instead of stdout.
struct Sort;

const SORT_VALUE_FLAGS: &[&str] = &[
    "--batch-size",
    "--compress-program",
    "--random-source",
    "--sort",
    "-o",
    "--output",
    "-k",
    "--key",
    "-t",
    "--field-separator",
    "-T",
    "--temporary-directory",
    "-S",
    "--buffer-size",
    "--parallel",
    "--files0-from",
];

const SORT_KNOWN_FLAGS: &[&str] = &[
    "-n",
    "--numeric-sort",
    "-r",
    "--reverse",
    "-u",
    "--unique",
    "-f",
    "--ignore-case",
    "-c",
    "--check",
    "-C",
    "-m",
    "--merge",
    "-b",
    "--ignore-leading-blanks",
    "-d",
    "--dictionary-order",
    "-g",
    "--general-numeric-sort",
    "-h",
    "--human-numeric-sort",
    "-i",
    "--ignore-nonprinting",
    "-M",
    "--month-sort",
    "-R",
    "--random-sort",
    "-s",
    "--stable",
    "-V",
    "--version-sort",
    "-z",
    "--zero-terminated",
    "--debug",
    "--help",
    "--version",
];

fn attached_value_for_no_value_flag(
    argv: &[Word],
    flags: &[&str],
    optional_value_flags: &[&str],
) -> Option<u32> {
    argv.iter()
        .enumerate()
        .skip(1)
        .take_while(|(_, word)| word.as_literal() != Some("--"))
        .find_map(|(index, word)| {
            let (name, _) = word.as_literal()?.split_once('=')?;
            (flags.contains(&name) && !optional_value_flags.contains(&name)).then_some(index as u32)
        })
}

fn sort_has_conflicting_ordering(scanned: &Scanned<'_>) -> bool {
    [
        scanned.has(&["-n", "--numeric-sort"]),
        scanned.has(&["-g", "--general-numeric-sort"]),
        scanned.has(&["-h", "--human-numeric-sort"]),
        scanned.has(&["-M", "--month-sort"]),
        scanned.has(&[
            "-d",
            "--dictionary-order",
            "-i",
            "--ignore-nonprinting",
            "-R",
            "--random-sort",
            "-V",
            "--version-sort",
        ]),
    ]
    .into_iter()
    .filter(|selected| *selected)
    .count()
        > 1
}

impl CommandModel for Sort {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/sort@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["sort"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let scanned = scan(
            argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: SORT_VALUE_FLAGS,
                known_flags: &[],
            },
        );
        if scanned.has(&["--files0-from"]) {
            return Vec::new();
        }
        let mut bindings = Vec::new();
        if operands_read_stdin(&scanned.operands) {
            bindings.push(stdin_stdout_binding());
        }
        if scanned
            .operands
            .iter()
            .any(|(_, operand)| operand.as_literal() != Some("-"))
        {
            bindings.push(filesystem_read_stdout_binding());
        }
        // `-o FILE` receives the sorted input in place of stdout.
        if scanned.has(&["-o", "--output"]) {
            for binding in &mut bindings {
                binding.to = crate::models::ModelBindingEnd::Effect {
                    operation: "filesystem.write".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                };
            }
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: SORT_VALUE_FLAGS,
            known_flags: SORT_KNOWN_FLAGS,
        };
        let scanned =
            scan_with_value_indices(ctx.argv, &SPEC, ctx.tracks_host_context_environment());
        // --help and --version print their text and exit before sort opens a file.
        if scanned.has(&["--help", "--version"]) {
            fs_full_no_spawn(builder);
            return;
        }
        let has_files0_from = scanned.has(&["--files0-from"]);
        let files0_from = scanned.values_of(&["--files0-from"]).into_iter().last();
        let invalid_attached_value =
            attached_value_for_no_value_flag(ctx.argv, SORT_KNOWN_FLAGS, &["--check"]).is_some();
        let invalid_files0_from = has_files0_from
            && (files0_from.is_none()
                || files0_from.is_some_and(|(_, file)| file.as_literal() == Some(""))
                || !scanned.operands.is_empty()
                || invalid_attached_value);
        if invalid_files0_from {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unsupported,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "sort --files0-from invocation has invalid flag/value or operand grammar"
                            .into(),
                    ),
                },
                CoverageLevel::Partial,
            );
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem"],
                &scanned.unknown_flags,
            );
            return;
        } else if let Some((index, file)) = files0_from {
            let conflicting_ordering = sort_has_conflicting_ordering(&scanned);
            let reviewed_files0_grammar = scanned.unknown_flags.is_empty()
                && !conflicting_ordering
                && scanned.flags.iter().all(|flag| {
                    flag.name == "--files0-from"
                        || !SORT_VALUE_FLAGS.contains(&flag.name)
                            && !matches!(
                                flag.name,
                                "-c" | "--check" | "-C" | "-m" | "--merge" | "--debug"
                            )
                });
            if file.as_literal() != Some("-") {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    file,
                    "filesystem.read",
                    if reviewed_files0_grammar {
                        program_input_attrs()
                    } else {
                        Default::default()
                    },
                );
            }
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: (file.as_literal() != Some("-"))
                        .then(|| ctx.resolve_fs_word(file)),
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "sort input paths selected by the NUL-delimited file list are not statically recoverable"
                            .into(),
                    ),
                },
                CoverageLevel::Partial,
            );
            if conflicting_ordering {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        class: BoundaryClass::Unsupported,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some("sort ordering modes are mutually exclusive".into()),
                    },
                    CoverageLevel::Partial,
                );
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                return;
            }
        }
        if let Some((index, out)) = scanned.values_of(&["-o", "--output"]).last() {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                out,
                "filesystem.write",
                program_output_attrs(),
            );
        }
        // sort opens its random source only when an effective ordering is
        // random. Without keys that is the global ordering (`-R`,
        // `--sort=random`). A key uses its own modifiers (`R` is random), and
        // inherits the global ordering only when it has none (GNU sort.c).
        let global_random = scanned.has(&["-R", "--random-sort"])
            || scanned
                .values_of(&["--sort"])
                .iter()
                .any(|(_, value)| value.as_literal() == Some("random"));
        let keys = scanned.values_of(&["-k", "--key"]);
        let random = if keys.is_empty() {
            global_random
        } else {
            keys.iter().any(|(_, key)| {
                let modifiers = key
                    .as_literal()
                    .unwrap_or_default()
                    .split(',')
                    .flat_map(|end| {
                        end.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
                            .chars()
                    })
                    .collect::<String>();
                modifiers.contains('R') || modifiers.is_empty() && global_random
            })
        };
        if random && let Some((index, source)) = scanned.values_of(&["--random-source"]).last() {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                source,
                "filesystem.read",
                program_input_attrs(),
            );
        }
        for (index, directory) in scanned.values_of(&["-T", "--temporary-directory"]) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                directory,
                "filesystem.write",
                attrs(&[("temporary_directory", true)]),
            );
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(ctx.resolve_fs_word(directory)),
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("sort temporary file names are not statically recoverable".into()),
                },
                CoverageLevel::Partial,
            );
        }
        if !has_files0_from {
            // With no operand, or `-`, standard input is what sort sorts, so
            // a file redirected onto it is program input as an operand is.
            if operands_read_stdin(&scanned.operands) && scanned.unknown_flags.is_empty() {
                builder.note_stdin_consumed();
            }
            for (index, operand) in &scanned.operands {
                if operand.as_literal() == Some("-") {
                    continue;
                }
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    operand,
                    "filesystem.read",
                    if scanned.unknown_flags.is_empty() {
                        program_input_attrs()
                    } else {
                        Default::default()
                    },
                );
            }
        }
        if scanned.has(&["-T", "--temporary-directory"]) {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        } else {
            fs_full_no_spawn(builder);
        }
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// `wc [OPTION]... [FILE]...`: reads its file operands.
struct Wc;

impl CommandModel for Wc {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/wc@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["wc"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: &["--files0-from"],
            known_flags: &[
                "-c",
                "--bytes",
                "-m",
                "--chars",
                "-l",
                "--lines",
                "-L",
                "--max-line-length",
                "-w",
                "--words",
                "--total",
            ],
        };
        let scanned =
            scan_with_value_indices(ctx.argv, &SPEC, ctx.tracks_host_context_environment());
        let files0_from = scanned.values_of(&["--files0-from"]);
        for (index, file) in &files0_from {
            // wc consumes the list itself and names each entry it cannot open
            // in its diagnostics, so the list's contents reach the output.
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                file,
                "filesystem.read",
                if scanned.unknown_flags.is_empty() {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
        }
        // Every wc option prints counts, never the bytes it counts, so the
        // operands it reads are not program input the output discloses.
        for (index, operand) in &scanned.operands {
            if operand.as_literal() == Some("-") {
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.read",
                Default::default(),
            );
        }
        fs_full_no_spawn(builder);
        if let Some((_, file)) = files0_from.last() {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: (file.as_literal() != Some("-"))
                        .then(|| ctx.resolve_fs_word(file)),
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "wc input paths selected by the NUL-delimited file list are not statically recoverable"
                            .into(),
                    ),
                },
                CoverageLevel::Partial,
            );
        }
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// `grep [OPTION]... PATTERN [FILE]...`: reads its file operands. Without
/// `-e`/`-f` the first operand is the pattern, not a file; `-f FILE` and
/// `--exclude-from FILE` read pattern/exclusion-list files of their own.
struct Grep;

const GREP_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--regexp",
    "-f",
    "--file",
    "-A",
    "--after-context",
    "-B",
    "--before-context",
    "-C",
    "--context",
    "-m",
    "--max-count",
    "-d",
    "--directories",
    "-D",
    "--devices",
    "--include",
    "--exclude",
    "--exclude-from",
    "--exclude-dir",
    "--color",
    "--colour",
    "--binary-files",
    "--label",
];

const GREP_NO_VALUE_FLAGS: &[&str] = &[
    "-i",
    "--ignore-case",
    "-v",
    "--invert-match",
    "-w",
    "--word-regexp",
    "-x",
    "--line-regexp",
    "-c",
    "--count",
    "-l",
    "--files-with-matches",
    "-L",
    "--files-without-match",
    "-n",
    "--line-number",
    "-H",
    "--with-filename",
    "-h",
    "--no-filename",
    "-o",
    "--only-matching",
    "-q",
    "--quiet",
    "--silent",
    "-r",
    "--recursive",
    "-R",
    "--dereference-recursive",
    "-s",
    "--no-messages",
    "-z",
    "--null-data",
    "-Z",
    "--null",
    "-E",
    "--extended-regexp",
    "-F",
    "--fixed-strings",
    "-G",
    "--basic-regexp",
    "-P",
    "--perl-regexp",
    "-a",
    "--text",
    "-I",
    "-u",
    "--unix-byte-offsets",
    "-b",
    "--byte-offset",
    "-T",
    "--initial-tab",
    "-U",
    "--binary",
    "-y",
];

fn grep_invalid_grammar(
    scanned: &Scanned<'_>,
    command: Option<&str>,
    invalid_attached_value: bool,
) -> bool {
    let missing_value = scanned
        .flags
        .iter()
        .any(|flag| GREP_VALUE_FLAGS.contains(&flag.name) && flag.value.is_none());
    let empty_control_file = scanned.flags.iter().any(|flag| {
        matches!(flag.name, "-f" | "--file" | "--exclude-from")
            && flag.value.as_ref().and_then(Word::as_literal) == Some("")
    });
    let command = command.and_then(|name| name.rsplit('/').next());
    let matcher_count = [
        scanned.has(&["-E", "--extended-regexp"]) || command == Some("egrep"),
        scanned.has(&["-F", "--fixed-strings"]) || command == Some("fgrep"),
        scanned.has(&["-G", "--basic-regexp"]),
        scanned.has(&["-P", "--perl-regexp"]),
    ]
    .into_iter()
    .filter(|selected| *selected)
    .count();
    let has_pattern_flag = scanned.has(&["-e", "--regexp", "-f", "--file"]);
    missing_value
        || empty_control_file
        || invalid_attached_value
        || matcher_count > 1
        || !has_pattern_flag && scanned.operands.is_empty()
}

/// GNU grep's `--color` takes only an attached optional value and changes
/// highlighting, never which lines print, so a literal `--color=WHEN` it
/// accepts keeps the reviewed output modes.
fn grep_color_when(flag: &Flag<'_>) -> bool {
    matches!(flag.name, "--color" | "--colour")
        && flag.value_index == Some(flag.index)
        && matches!(
            flag.value.as_ref().and_then(Word::as_literal),
            Some("always" | "yes" | "force" | "never" | "no" | "none" | "auto" | "tty" | "if-tty")
        )
}

fn grep_reviewed_input_grammar(
    scanned: &Scanned<'_>,
    command: Option<&str>,
    invalid_attached_value: bool,
) -> bool {
    scanned.unknown_flags.is_empty()
        && !grep_invalid_grammar(scanned, command, invalid_attached_value)
        && !scanned
            .flags
            .iter()
            .filter(|flag| !grep_color_when(flag))
            .any(|flag| {
                matches!(
                    flag.name,
                    "-A" | "--after-context"
                        | "-B"
                        | "--before-context"
                        | "-C"
                        | "--context"
                        | "-m"
                        | "--max-count"
                        | "-d"
                        | "--directories"
                        | "-D"
                        | "--devices"
                        | "--color"
                        | "--colour"
                        | "--binary-files"
                )
            })
}

impl CommandModel for Grep {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "gnu/grep@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["grep", "egrep", "fgrep"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: GREP_VALUE_FLAGS,
            known_flags: GREP_NO_VALUE_FLAGS,
        };
        let scanned =
            scan_with_value_indices(ctx.argv, &SPEC, ctx.tracks_host_context_environment());
        let recursive = scanned.has(&["-r", "--recursive", "-R", "--dereference-recursive"]);
        let command = ctx.argv.first().and_then(Word::as_literal);
        let invalid_attached_value =
            attached_value_for_no_value_flag(ctx.argv, GREP_NO_VALUE_FLAGS, &[]);
        let invalid_grammar =
            grep_invalid_grammar(&scanned, command, invalid_attached_value.is_some());
        let reviewed_input_grammar =
            grep_reviewed_input_grammar(&scanned, command, invalid_attached_value.is_some());
        let has_pattern_flag = scanned.has(&["-e", "--regexp", "-f", "--file"]);
        let inputs = if has_pattern_flag {
            scanned.operands.as_slice()
        } else {
            scanned.operands.get(1..).unwrap_or_default()
        };
        let output_mode = if scanned.has(&["-q", "--quiet", "--silent"]) {
            "quiet"
        } else if scanned.has(&["-l", "--files-with-matches", "-L", "--files-without-match"]) {
            "filenames"
        } else if scanned.has(&["-c", "--count"]) {
            "count"
        } else {
            "content"
        };
        let exact_arguments = reviewed_input_grammar
            && ctx.argv.iter().enumerate().all(|(index, word)| {
                word.as_literal().is_some()
                    || inputs.iter().any(|(input, _)| *input == index as u32)
                        && super::registry::reviewed_read_operand(
                            word,
                            index as u32,
                            scanned.dashdash,
                        )
            });
        let mut filter_attributes = attrs(&[("content_filter", true)]);
        let mut input_attributes = attrs(&[("recursive", recursive), ("content_filter", true)]);
        // GNU `-R` opens what every link below an operand leads to, where
        // `-r` follows only the links named on the command line. BSD grep's
        // `-R` follows none without `-S`; nothing here tells the two apart,
        // so `-R` is read as following on every host.
        if scanned.has(&["-R", "--dereference-recursive"]) {
            input_attributes.insert(
                "follow_links".into(),
                effinterp_proto::AttrValue::Bool(true),
            );
        }
        input_attributes.insert(
            "input_role".into(),
            effinterp_proto::AttrValue::String("content".into()),
        );
        input_attributes.insert(
            "output_mode".into(),
            effinterp_proto::AttrValue::String(output_mode.into()),
        );
        let patterns = scanned.values_of(&["-e", "--regexp"]);
        let query = if !patterns.is_empty() {
            Some(
                patterns
                    .iter()
                    .map(|(_, word)| word.render_raw())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        } else if !has_pattern_flag {
            scanned.operands.first().map(|(_, word)| word.render_raw())
        } else {
            None
        };
        if let Some(query) = query {
            input_attributes.insert("query".into(), effinterp_proto::AttrValue::String(query));
        }
        if reviewed_input_grammar {
            filter_attributes.extend(program_input_attrs());
            input_attributes.extend(program_input_attrs());
        }

        filter_attributes.insert(
            "input_role".into(),
            effinterp_proto::AttrValue::String("pattern".into()),
        );
        for (index, file) in scanned.values_of(&["-f", "--file"]) {
            if matches!(file.as_literal(), Some("" | "-"))
                || invalid_attached_value.is_some_and(|invalid| index >= invalid)
            {
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.read",
                filter_attributes.clone(),
            );
        }
        filter_attributes.insert(
            "input_role".into(),
            effinterp_proto::AttrValue::String("exclude".into()),
        );
        for (index, file) in scanned.values_of(&["--exclude-from"]) {
            if matches!(file.as_literal(), Some("" | "-"))
                || invalid_attached_value.is_some_and(|invalid| index >= invalid)
            {
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.read",
                filter_attributes.clone(),
            );
        }

        if invalid_grammar {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unsupported,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("grep pattern, flag-value, or matcher grammar is invalid".into()),
                },
                CoverageLevel::Partial,
            );
        } else if scanned.unknown_flags.is_empty() && !reviewed_input_grammar {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "grep value-option grammar is outside the reviewed input-purpose subset"
                            .into(),
                    ),
                },
                CoverageLevel::Partial,
            );
        }

        // A recursive search reads a file below an operand when the last
        // --include or --exclude glob matching its base name is an --include,
        // or when none matches and the first of them is not an --include.
        // Only hidden names are narrowed: `*` keeps every visible name. A
        // file no glob matches is read only when the first glob excludes, so
        // the hidden names read are those the literal hidden names and
        // `.name*` prefixes excluded leave, plus those an --include matches;
        // other exclude globs only exclude more, so leaving them out keeps the
        // selection complete. `-R` follows every link below the operand, and
        // a visible link can name an excluded file, so only `-r`, which
        // follows command-line links alone, narrows. An --exclude-from file's
        // globs join the same ordered list and are unknown here, so one
        // before the first --include may supply the first glob; the globs it
        // adds only exclude more, so literal excludes stay excluded.
        let excluded_name_globs = if recursive && !scanned.has(&["-R", "--dereference-recursive"]) {
            let includes_first = scanned
                .flags
                .iter()
                .find(|flag| matches!(flag.name, "--include" | "--exclude" | "--exclude-from"))
                .is_some_and(|flag| flag.name == "--include");
            let mut globs = if includes_first {
                vec!["*".to_owned()]
            } else {
                let mut names = std::collections::BTreeSet::new();
                let mut prefixes = std::collections::BTreeSet::new();
                for (_, word) in scanned.values_of(&["--exclude"]) {
                    let Some(glob) = word.as_literal().filter(|glob| glob.starts_with('.')) else {
                        continue;
                    };
                    let prefix = glob.strip_suffix('*').unwrap_or(glob);
                    if prefix.contains(['*', '?', '[', '\\', '/']) {
                        continue;
                    }
                    if prefix.len() < glob.len() {
                        prefixes.insert(prefix);
                    } else {
                        names.insert(prefix);
                    }
                }
                basename_complement(&names, &prefixes)
            };
            // An include this model cannot spell as base-name globs keeps the
            // whole tree.
            let included = scanned
                .values_of(&["--include"])
                .into_iter()
                .map(|(_, word)| super::find::find_name_globs(word.as_literal()?, false))
                .collect::<Option<Vec<_>>>();
            match included {
                Some(included) if !globs.is_empty() => {
                    for glob in included.into_iter().flatten() {
                        if glob.starts_with('.') && !globs.contains(&glob) {
                            globs.push(glob);
                        }
                    }
                    if globs.len() > MAX_BASENAME_COMPLEMENT_GLOBS {
                        globs.clear();
                    }
                    globs
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };

        use crate::flow::{BindEnd, FlowStage, PortBinding};
        use effinterp_proto::{CausalAssurance, Port};
        let mut content_reads = Vec::new();
        for (index, operand) in inputs {
            if operand.as_literal() == Some("-") || invalid_attached_value.is_some() {
                continue;
            }
            // Only a literal operand without `..` keeps its resolved spelling,
            // so its tree is the one the narrowed selection names.
            let subtree = operand
                .as_literal()
                .filter(|text| {
                    !excluded_name_globs.is_empty() && !text.split('/').any(|part| part == "..")
                })
                .and_then(|_| match ctx.resolve_fs_word(operand) {
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    } => Some(path),
                    _ => None,
                });
            let mut operand_attributes = input_attributes.clone();
            if subtree.is_some() {
                operand_attributes
                    .insert("recursive".into(), effinterp_proto::AttrValue::Bool(false));
            }
            let Some(read) = operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.read",
                operand_attributes,
            ) else {
                continue;
            };
            content_reads.push(read);
            let Some(root) = subtree else {
                continue;
            };
            let root = crate::paths::escape_fs_glob_path(root.trim_end_matches('/'));
            let provenance = builder
                .effect_provenance(read as usize)
                .unwrap_or_default()
                .to_vec();
            for name_glob in &excluded_name_globs {
                if let Some(descendants) = builder.effect(effinterp_proto::Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: effinterp_proto::Operation::new("filesystem.read"),
                    resource: ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::FsPath {
                            glob: format!("{root}/**/{name_glob}"),
                            narrowing: Default::default(),
                        },
                    },
                    attributes: input_attributes.clone(),
                    modality: effinterp_proto::Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: provenance.clone(),
                }) {
                    content_reads.push(descendants);
                }
            }
        }
        if output_mode == "content" && !invalid_grammar && scanned.unknown_flags.is_empty() {
            let assurance = if exact_arguments {
                CausalAssurance::Exact
            } else {
                CausalAssurance::Conservative
            };
            let mut bindings = content_reads
                .iter()
                .map(|read| PortBinding {
                    assurance,
                    from: BindEnd::Effect(*read),
                    to: BindEnd::Port(Port::Stdout),
                })
                .collect::<Vec<_>>();
            let control_stdin = scanned
                .values_of(&["-f", "--file", "--exclude-from"])
                .iter()
                .any(|(_, word)| word.as_literal() == Some("-"));
            if operands_read_stdin(inputs) && !control_stdin && (!recursive || !inputs.is_empty()) {
                bindings.push(PortBinding {
                    assurance,
                    from: BindEnd::Port(Port::Stdin),
                    to: BindEnd::Port(Port::Stdout),
                });
            }
            if !bindings.is_empty() {
                builder.flow_stage(FlowStage {
                    execution: Some(builder.current_execution()),
                    effects: content_reads,
                    bindings,
                    provenance: vec![model_node],
                });
            }
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// Past this many base-name globs a search keeps its whole tree rather than
/// spend the plan's effect budget on one selection.
const MAX_BASENAME_COMPLEMENT_GLOBS: usize = 32;

/// Base-name globs that together select every name except the hidden names in
/// `names` and the hidden names starting with one of `prefixes`, or none when
/// there is nothing to exclude or the selection would need too many.
///
/// A path glob's wildcards never match a leading dot, so `*` selects every
/// name that is not hidden, and hidden names are reached only through a
/// literal leading `.`. Walk the prefixes of the excluded names below that
/// dot. Each contributes the names that leave it at a character no excluded
/// name continues with, and itself when it is not excluded. Keeping `*` whole
/// keeps the selection spanning the tree, which the bridge credits as
/// selecting the tree's project, home or root.
fn basename_complement(
    names: &std::collections::BTreeSet<&str>,
    prefixes: &std::collections::BTreeSet<&str>,
) -> Vec<String> {
    // An excluded prefix already excludes every name that extends it.
    let covered = |name: &str| prefixes.iter().any(|prefix| name.starts_with(prefix));
    let names = names
        .iter()
        .copied()
        .filter(|name| !covered(name))
        .collect::<std::collections::BTreeSet<_>>();
    let prefixed = prefixes
        .iter()
        .copied()
        .filter(|prefix| {
            !prefixes
                .iter()
                .any(|other| other != prefix && prefix.starts_with(other))
        })
        .collect::<std::collections::BTreeSet<_>>();
    let excluded = names
        .union(&prefixed)
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if excluded.is_empty() {
        return Vec::new();
    }
    let prefixes = excluded
        .iter()
        .flat_map(|name| name.char_indices().map(|(end, _)| &name[..end]))
        .collect::<std::collections::BTreeSet<_>>();
    let mut globs = Vec::new();
    for prefix in &prefixes {
        let prefix = *prefix;
        if prefix.is_empty() {
            globs.push("*".to_owned());
            continue;
        }
        let continuations = excluded
            .iter()
            .filter_map(|name| name.strip_prefix(prefix)?.chars().next())
            .collect::<std::collections::BTreeSet<_>>();
        let escaped = crate::paths::escape_fs_glob_path(prefix);
        let class = continuations
            .iter()
            .map(|c| {
                if matches!(c, ']' | '\\' | '-' | '!' | '^') {
                    format!("\\{c}")
                } else {
                    c.to_string()
                }
            })
            .collect::<String>();
        globs.push(format!("{escaped}[!{class}]*"));
        if !matches!(prefix, "." | "..") && !excluded.contains(prefix) {
            globs.push(escaped);
        }
    }
    // A name no other excluded name extends still has its longer names; an
    // excluded prefix has none.
    for name in names.iter().filter(|name| !prefixes.contains(*name)) {
        globs.push(format!("{}?*", crate::paths::escape_fs_glob_path(name)));
    }
    if globs.len() > MAX_BASENAME_COMPLEMENT_GLOBS {
        return Vec::new();
    }
    globs
}

/// `less`/`more`: pagers that read their file operands. A leading `+` token
/// (`+10`, `+/pattern`) is a jump command, not a file.
struct Pager;

/// `less` options. Those taking a value are listed so the value is not read
/// as a file the pager shows.
const LESS_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--lesskey-file",
        "--lesskey-src",
        "-b",
        "-h",
        "-j",
        "-k",
        "-n",
        "-o",
        "-O",
        "-p",
        "-P",
        "-t",
        "-T",
        "-x",
        "-y",
        "-z",
    ],
    known_flags: &[
        "-a",
        "-A",
        "-c",
        "-C",
        "-d",
        "-e",
        "-E",
        "-f",
        "-F",
        "-g",
        "-G",
        "-i",
        "-I",
        "-J",
        "-K",
        "-l",
        "-L",
        "-m",
        "-M",
        "-N",
        "-q",
        "-Q",
        "-r",
        "-R",
        "-s",
        "-S",
        "-u",
        "-U",
        "-V",
        "--version",
        "-w",
        "-W",
        "-X",
    ],
};
/// `more` options, which differ from `less`'s and may be abbreviated.
const MORE_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: true,
    value_flags: &["-n", "--lines"],
    known_flags: &[
        "-d",
        "--silent",
        "-f",
        "--logical",
        "-l",
        "--no-pause",
        "-c",
        "--print-over",
        "-p",
        "--clean-print",
        "-e",
        "--exit-on-eof",
        "-s",
        "--squeeze",
        "-u",
        "--plain",
        "-V",
        "--version",
        "-h",
        "--help",
    ],
};

/// Whether the pager is invoked as `more`, by any path, and so reads its
/// options with `MORE_SPEC`.
fn pager_invoked_as_more(argv: &[Word]) -> bool {
    argv[0]
        .as_literal()
        .and_then(|name| name.rsplit('/').next())
        == Some("more")
}

/// The files a pager shows: every operand but `-` and a `+CMD` start command.
fn pager_files<'a>(scanned: &Scanned<'a>) -> Vec<(u32, &'a Word)> {
    scanned
        .operands
        .iter()
        .filter(|(_, operand)| {
            !matches!(operand.as_literal(), Some(text) if text == "-" || text.starts_with('+'))
        })
        .copied()
        .collect()
}

/// Whether the pager shows its standard input: no file operand, or `-`.
fn pager_reads_stdin(scanned: &Scanned<'_>) -> bool {
    pager_files(scanned).is_empty()
        || scanned
            .operands
            .iter()
            .any(|(_, operand)| operand.as_literal() == Some("-"))
}

impl CommandModel for Pager {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "util/pager@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["less", "more"]
    }

    /// A pager whose output is not a terminal writes its input through, as
    /// `cat` does, so what it shows reaches the call's standard output. The
    /// binding takes every file the call reads, a lesskey file among them.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let scanned = scan(
            argv,
            if pager_invoked_as_more(argv) {
                &MORE_SPEC
            } else {
                &LESS_SPEC
            },
        );
        let mut bindings = Vec::new();
        if pager_reads_stdin(&scanned) {
            bindings.push(stdin_stdout_binding());
        }
        if !pager_files(&scanned).is_empty() {
            bindings.push(filesystem_read_stdout_binding());
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let more = pager_invoked_as_more(ctx.argv);
        let mut scanned = scan_with_value_indices(
            ctx.argv,
            if more { &MORE_SPEC } else { &LESS_SPEC },
            ctx.tracks_host_context_environment(),
        );
        if more {
            // util-linux `more -NUM` is the screen size, like `-n NUM`.
            scanned
                .unknown_flags
                .retain(|(_, flag)| !flag[1..].bytes().all(|byte| byte.is_ascii_digit()));
        }
        if scanned.has(&["-V", "--version"]) || more && scanned.has(&["-h", "--help"]) {
            fs_full_no_spawn(builder);
            return;
        }
        for (index, file) in scanned.values_of(&["-k", "--lesskey-file", "--lesskey-src"]) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.read",
                program_input_attrs(),
            );
        }
        if !more {
            // `-o`/`-O` copy piped input into a log file; `-O` overwrites it
            // without asking.
            for (index, file) in scanned.values_of(&["-o", "-O"]) {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    file,
                    "filesystem.write",
                    Default::default(),
                );
            }
        }
        // With no file operand, or `-`, standard input is what the pager
        // shows, so a file redirected onto it is program input as an operand
        // is.
        if pager_reads_stdin(&scanned) && scanned.unknown_flags.is_empty() {
            builder.note_stdin_consumed();
        }
        for (index, operand) in pager_files(&scanned) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                operand,
                "filesystem.read",
                if scanned.unknown_flags.is_empty() {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// `base64` and `base32` are stdin/stdout byte transforms that read a FILE
/// operand when given, in both directions. `-D` decodes in BSD base64 and in
/// uutils coreutils, so it is read as a decode on every host.
struct Base64;

const BASE64_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-w", "--wrap"],
    known_flags: &[
        "-d",
        "-D",
        "--decode",
        "-i",
        "--ignore-garbage",
        "--help",
        "--version",
    ],
};

fn base64_decodes(scanned: &Scanned<'_>) -> bool {
    scanned.has(&["-d", "-D", "--decode"])
}

/// The invocation as a reviewed stream: every option literal and at most one
/// operand. The operand may be a pattern or a symbolic path where option
/// parsing cannot reinterpret it, or beside a literal decode option, where
/// no option it could spell instead makes the call do anything but decode,
/// print help or fail.
fn base64_stream(argv: &[Word]) -> Option<crate::models::args::Scanned<'_>> {
    let scanned = scan(argv, &BASE64_SPEC);
    (argv.iter().enumerate().all(|(index, word)| {
        word.as_literal().is_some()
            || scanned
                .operands
                .iter()
                .any(|(operand, _)| *operand == index as u32)
                && (base64_decodes(&scanned)
                    || super::registry::reviewed_read_operand(word, index as u32, scanned.dashdash))
    }) && scanned.unknown_flags.is_empty()
        && !scanned.has(&["--help", "--version"])
        && scanned.operands.len() <= 1
        && scanned.flags.iter().all(|flag| {
            if BASE64_SPEC.value_flags.contains(&flag.name) {
                flag.value
                    .as_ref()
                    .and_then(Word::as_literal)
                    .is_some_and(|value| {
                        !value.is_empty()
                            && value.bytes().all(|byte| byte.is_ascii_digit())
                            && value.parse::<u64>().is_ok()
                    })
            } else {
                !argv[flag.index as usize].literal_prefix().contains('=')
            }
        }))
    .then_some(scanned)
}

impl CommandModel for Base64 {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/base64@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["base64", "base32"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        use crate::models::ModelBindingEnd;
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::{CausalAssurance, Port};
        let Some(scanned) = base64_stream(argv) else {
            // Unresolved selectors retain possible byte dependencies without
            // certifying a transform or its accepted command grammar.
            let scanned = scan(argv, &BASE64_SPEC);
            let mut bindings = Vec::new();
            if operands_read_stdin(&scanned.operands) {
                bindings.push(stdin_stdout_binding());
            }
            if scanned
                .operands
                .iter()
                .any(|(_, word)| word.as_literal() != Some("-"))
            {
                bindings.push(filesystem_read_stdout_binding());
            }
            return bindings;
        };
        // An operand that is not literal may name a file or spell `-`.
        let symbolic = scanned
            .operands
            .iter()
            .any(|(_, operand)| operand.as_literal().is_none());
        let mut sources = Vec::new();
        if operands_read_stdin(&scanned.operands) || symbolic {
            sources.push(ModelBindingEnd::Port(Port::Stdin));
        }
        if !operands_read_stdin(&scanned.operands) {
            sources.push(ModelBindingEnd::Effect {
                operation: "filesystem.read".into(),
                selection: EffectSelection::All,
            });
        }
        let output = ModelBindingEnd::Port(Port::Stdout);
        let transform = ModelBindingEnd::Effect {
            operation: "process.stream_transform".into(),
            selection: EffectSelection::All,
        };
        let mut bindings = Vec::new();
        for source in sources {
            bindings.push(ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: source.clone(),
                to: output.clone(),
            });
            if base64_decodes(&scanned) {
                bindings.push(ModelCausalBinding {
                    assurance: CausalAssurance::Exact,
                    from: source,
                    to: transform.clone(),
                });
            }
        }
        if base64_decodes(&scanned) {
            bindings.push(ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: transform,
                to: output,
            });
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan(ctx.argv, &BASE64_SPEC);
        if scanned.has(&["--help", "--version"]) {
            return;
        }
        let audited = base64_stream(ctx.argv).is_some();
        // Decoding is a typed policy fact. Encoding still carries bytes through
        // the direct causal binding without adding an untranslatable effect.
        if audited && base64_decodes(&scanned) {
            builder.effect(effinterp_proto::Effect {
                request_assurance: effinterp_proto::RequestAssurance::Exact,
                id: Default::default(),
                operation: effinterp_proto::Operation::new("process.stream_transform"),
                resource: crate::models::common::code_execution_resource(ctx),
                attributes: std::collections::BTreeMap::from([(
                    "transform".into(),
                    effinterp_proto::AttrValue::String("decode".into()),
                )]),
                modality: effinterp_proto::Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![model_node],
            });
        } else if !audited {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem"), Domain::new("process")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "base encoding stream selection or option grammar is unresolved".into(),
                ),
            });
        }
        for (index, operand) in &scanned.operands {
            if operand.as_literal() == Some("-") {
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.read",
                if audited {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// `cut [OPTION]... [FILE]...`: reads its file operands. The field/byte
/// selectors and the delimiter take values that are not paths.
struct Cut;

const CUT_VALUE_FLAGS: &[&str] = &[
    "-b",
    "--bytes",
    "-c",
    "--characters",
    "-d",
    "--delimiter",
    "-f",
    "--fields",
    "--output-delimiter",
];

impl CommandModel for Cut {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "coreutils/cut@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["cut"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let scanned = scan(
            argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: CUT_VALUE_FLAGS,
                known_flags: &[],
            },
        );
        let mut bindings = Vec::new();
        if operands_read_stdin(&scanned.operands) {
            bindings.push(stdin_stdout_binding());
        }
        if scanned
            .operands
            .iter()
            .any(|(_, operand)| operand.as_literal() != Some("-"))
        {
            bindings.push(filesystem_read_stdout_binding());
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: CUT_VALUE_FLAGS,
            known_flags: &[
                "-n",
                "-s",
                "--only-delimited",
                "-z",
                "--zero-terminated",
                "--complement",
            ],
        };
        let scanned = scan(ctx.argv, &SPEC);
        // With no operand, or `-`, standard input is what cut selects from,
        // so a file redirected onto it is program input as an operand is.
        if operands_read_stdin(&scanned.operands) && scanned.unknown_flags.is_empty() {
            builder.note_stdin_consumed();
        }
        for (index, operand) in &scanned.operands {
            if operand.as_literal() == Some("-") {
                continue;
            }
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.read",
                if scanned.unknown_flags.is_empty() {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem"],
            &scanned.unknown_flags,
        );
    }
}

/// One awk invocation's program, program files and input operands.
struct AwkInvocation<'a> {
    program: Option<(u32, &'a Word)>,
    prog_files: Vec<(u32, Word)>,
    files: Vec<(u32, &'a Word)>,
    unknown: Vec<(u32, String)>,
    in_place: bool,
    /// A `-` operand names stdin as an input.
    reads_stdin: bool,
}

fn awk_invocation<'a>(argv: &'a [Word]) -> AwkInvocation<'a> {
    let mut program: Option<(u32, &'a Word)> = None;
    let mut prog_files: Vec<(u32, Word)> = Vec::new();
    let mut files: Vec<(u32, &'a Word)> = Vec::new();
    let mut unknown: Vec<(u32, String)> = Vec::new();
    let mut flags_done = false;
    let mut in_place = false;
    let mut reads_stdin = false;

    let mut i = 1;
    while i < argv.len() {
        let word = &argv[i];
        let index = i as u32;
        match word.as_literal() {
            Some("--") if !flags_done && program.is_none() => flags_done = true,
            Some(t) if !flags_done && program.is_none() && t.starts_with('-') && t.len() > 1 => {
                if t == "-f" || t == "--file" {
                    if i + 1 < argv.len() {
                        prog_files.push(((i + 1) as u32, argv[i + 1].clone()));
                    }
                    i += 1;
                } else if t == "-i" || t == "--include" {
                    if let Some(value) = argv.get(i + 1).and_then(Word::as_literal) {
                        in_place = value == "inplace";
                        if !in_place {
                            unknown.push((index, format!("{t} {value}")));
                        }
                    } else {
                        unknown.push((index, t.to_string()));
                    }
                    i += 1;
                } else if matches!(t, "-iinplace" | "--include=inplace") {
                    in_place = true;
                } else if t.starts_with("-i") || t.starts_with("--include=") {
                    unknown.push((index, t.to_string()));
                } else if let Some(rest) = t.strip_prefix("--file=") {
                    prog_files.push((index, Word::literal(rest)));
                } else if let Some(attached) = t.strip_prefix("-W") {
                    // mawk `-W name[=value]`; any unique prefix selects the
                    // option, and `-W exec file` reads the program like `-f`
                    // and ends option parsing.
                    let value = if attached.is_empty() {
                        i += 1;
                        argv.get(i).and_then(Word::as_literal)
                    } else {
                        Some(attached)
                    };
                    match value.map(|value| value.split_once('=').map_or(value, |(n, _)| n)) {
                        Some(name) if !name.is_empty() && "exec".starts_with(name) => {
                            if let Some(file) = argv.get(i + 1) {
                                prog_files.push(((i + 1) as u32, file.clone()));
                            }
                            i += 1;
                            flags_done = true;
                        }
                        Some(name)
                            if !name.is_empty()
                                && [
                                    "version",
                                    "dump",
                                    "interactive",
                                    "posix_space",
                                    "sprintf",
                                    "random",
                                    "usage",
                                ]
                                .iter()
                                .any(|option| option.starts_with(name)) => {}
                        _ => unknown.push((index, t.to_string())),
                    }
                } else if matches!(t, "-F" | "-v") {
                    i += 1; // value in the next token
                } else if t.starts_with("--") {
                    if !matches!(t, "--version" | "--help" | "--posix" | "--traditional") {
                        unknown.push((index, t.to_string()));
                    }
                } else if t.starts_with("-F") || t.starts_with("-v") {
                    // attached value (`-F:`, `-vx=y`)
                } else if let Some(rest) = t.strip_prefix("-f") {
                    prog_files.push((index, Word::literal(rest)));
                } else {
                    unknown.push((index, t.to_string()));
                }
            }
            _ => {
                if program.is_none() && prog_files.is_empty() {
                    program = Some((index, word));
                } else {
                    match word.as_literal() {
                        Some("-") => reads_stdin = true,
                        Some(t) if is_awk_assignment(t) => {}
                        _ => files.push((index, word)),
                    }
                }
            }
        }
        i += 1;
    }
    AwkInvocation {
        program,
        prog_files,
        files,
        unknown,
        in_place,
        reads_stdin,
    }
}

/// `awk [-F sep] [-v var=val] [-f progfile] ['program'] [file...]`: a stream
/// filter that reads its file operands; `name=value` operands are variable
/// assignments, not files. The program itself only touches the stream unless
/// it redirects `print`/`printf` output (`> file`, `>> file`, `| cmd`), reads
/// with `getline < file` or `cmd | getline`, or calls `system(cmd)`. A literal
/// program is scanned for those: a literal file becomes a read or write, a
/// literal command is analyzed as `sh -c` source, and any other target, or a
/// program we cannot inspect, keeps a boundary.
struct Awk;

impl CommandModel for Awk {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "posix/awk@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["awk", "gawk", "mawk", "nawk"]
    }

    /// Records the program prints reach stdout: stdin when no input file
    /// operand names the input or a `-` operand does, and the files it reads
    /// when any does. gawk's in-place mode writes them back to the files
    /// instead.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let awk = awk_invocation(argv);
        if awk.in_place {
            return Vec::new();
        }
        let mut bindings = Vec::new();
        if awk.files.is_empty() || awk.reads_stdin {
            bindings.push(stdin_stdout_binding());
        }
        if !awk.files.is_empty() {
            bindings.push(filesystem_read_stdout_binding());
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let AwkInvocation {
            program,
            prog_files,
            files,
            unknown,
            in_place,
            reads_stdin,
        } = awk_invocation(ctx.argv);
        // With no input file, or `-`, standard input holds the records, so
        // a file redirected onto it is program input as an operand is.
        if (files.is_empty() || reads_stdin) && unknown.is_empty() {
            builder.note_stdin_consumed();
        }

        // awk runs a program file's text as its program, as `sh FILE` runs a
        // script; the text itself stays uninspected below.
        for (index, prog_file) in &prog_files {
            code_execution(
                effinterp_proto::RequestAssurance::Conservative,
                builder,
                ctx,
                model_node,
                Some(*index),
                "file",
                Default::default(),
            );
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                prog_file,
                "filesystem.read",
                Default::default(),
            );
        }
        for (index, file) in &files {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                file,
                "filesystem.read",
                if unknown.is_empty() {
                    program_input_attrs()
                } else {
                    Default::default()
                },
            );
            if in_place {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.write",
                    Default::default(),
                );
            }
        }
        fs_full_no_spawn(builder);

        let danger: Option<(&[&str], &str)> = if !prog_files.is_empty() {
            Some((
                &["filesystem", "process"],
                "awk program file is not inspected",
            ))
        } else {
            match program.map(|(index, word)| (index, word.as_literal())) {
                Some((index, Some(text))) => match awk_io(text) {
                    Ok(io) => {
                        awk_program_io(builder, ctx, model_node, index, io);
                        None
                    }
                    Err(detail) => Some((&["filesystem", "process"], detail)),
                },
                None => None,
                Some((_, None)) => Some((
                    &["filesystem", "process"],
                    "awk program is not statically recoverable",
                )),
            }
        };
        if let Some((domains, detail)) = danger {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNPARSED_SCRIPT,
                class: BoundaryClass::Unsupported,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: domains.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(detail.to_string()),
            });
        }
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown);
    }
}

/// Where a literal awk program reads, writes and runs commands outside its
/// input and output streams.
#[derive(Default)]
struct AwkIo {
    /// `getline < "file"`.
    reads: Vec<String>,
    /// `print > "file"` and, when appending, `print >> "file"`. A target
    /// may also concatenate `ENVIRON["NAME"]` values, kept as `WordPart::Env`.
    writes: Vec<(Word, bool)>,
    /// `system("cmd")`, `"cmd" | getline` and `print | "cmd"`, each run by `sh -c`.
    commands: Vec<String>,
    /// Why a redirection or command target is not a literal, with its domains.
    unresolved: Vec<(&'static [&'static str], &'static str)>,
}

fn awk_program_io(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    io: AwkIo,
) {
    for path in &io.reads {
        operand_effect(
            builder,
            ctx,
            model_node,
            index,
            &Word::literal(path),
            "filesystem.read",
            program_input_attrs(),
        );
    }
    for (target, append) in &io.writes {
        let mut attributes = program_output_attrs();
        attributes.extend(attrs(&[("append", *append)]));
        // `ENVIRON` holds the environment awk itself was started with.
        let target = Word::new(
            target
                .parts
                .iter()
                .map(|part| match part {
                    WordPart::Env(name) => match ctx.environment_value(name) {
                        Some(ResourceExpr::Literal { value }) => WordPart::Literal(value),
                        Some(ResourceExpr::Environment { name }) => WordPart::Env(name),
                        Some(_) => WordPart::Unknown,
                        None if ctx.nest.current_environment_unsets().contains(name) => {
                            WordPart::Literal(String::new())
                        }
                        None => part.clone(),
                    },
                    part => part.clone(),
                })
                .collect(),
        );
        operand_effect(
            builder,
            ctx,
            model_node,
            index,
            &target,
            "filesystem.write",
            attributes,
        );
    }
    let arg = arg_node(builder, ctx, index);
    for command in io.commands {
        ctx.nest_subject(
            builder,
            Subject::Shell {
                source: command,
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &[model_node, arg],
        );
    }
    for (domains, detail) in io.unresolved {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNPARSED_SCRIPT,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![model_node, arg],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
}

#[derive(Clone, Debug, PartialEq)]
enum AwkToken {
    /// A string literal, or None when an escape leaves its value unknown.
    Text(Option<String>),
    Name(String),
    Number,
    Regex,
    Newline,
    Punct(&'static str),
}

/// Operators the scan distinguishes, longest first so `>>` is not read as `>`.
const AWK_PUNCT: [&str; 34] = [
    ">>", "|&", "||", "&&", ">=", "<=", "==", "!=", "++", "--", "+=", "-=", "*=", "/=", "%=", "^=",
    ">", "<", "|", "(", ")", "[", "]", "{", "}", ";", ",", "@", "$", "=", "!", "?", ":", "~",
];

/// Words after which a `/` starts a regex rather than dividing an operand.
const AWK_KEYWORDS: [&str; 6] = ["print", "printf", "return", "in", "case", "getline"];

fn awk_operand_end(token: Option<&AwkToken>) -> bool {
    match token {
        Some(AwkToken::Text(_) | AwkToken::Number | AwkToken::Regex) => true,
        Some(AwkToken::Name(name)) => !AWK_KEYWORDS.contains(&name.as_str()),
        Some(AwkToken::Punct(punct)) => matches!(*punct, ")" | "]" | "++" | "--"),
        _ => false,
    }
}

fn awk_tokens(text: &str) -> Result<Vec<AwkToken>, &'static str> {
    const UNTERMINATED: &str = "awk program has an unterminated string or regex";
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'\n') => {
                chars.next();
            }
            '\n' => tokens.push(AwkToken::Newline),
            c if c.is_whitespace() => {}
            '#' => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                }
            }
            '"' => {
                let mut value = Some(String::new());
                loop {
                    match chars.next().ok_or(UNTERMINATED)? {
                        '"' => break,
                        '\n' => return Err(UNTERMINATED),
                        '\\' => {
                            let decoded = match chars.next().ok_or(UNTERMINATED)? {
                                '"' => Some('"'),
                                '\\' => Some('\\'),
                                '/' => Some('/'),
                                'n' => Some('\n'),
                                't' => Some('\t'),
                                'r' => Some('\r'),
                                // Octal, other control and implementation-
                                // specific escapes leave the value unknown.
                                _ => None,
                            };
                            match (decoded, value.as_mut()) {
                                (Some(c), Some(value)) => value.push(c),
                                _ => value = None,
                            }
                        }
                        c => {
                            if let Some(value) = value.as_mut() {
                                value.push(c);
                            }
                        }
                    }
                }
                tokens.push(AwkToken::Text(value));
            }
            '/' if !awk_operand_end(tokens.last()) => {
                loop {
                    match chars.next().ok_or(UNTERMINATED)? {
                        '/' => break,
                        '\n' => return Err(UNTERMINATED),
                        '\\' => {
                            chars.next().ok_or(UNTERMINATED)?;
                        }
                        _ => {}
                    }
                }
                tokens.push(AwkToken::Regex);
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = c.to_string();
                while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                    name.push(c);
                }
                tokens.push(AwkToken::Name(name));
            }
            c if c.is_ascii_digit() || c == '.' => {
                while chars
                    .next_if(|c| c.is_ascii_alphanumeric() || *c == '.')
                    .is_some()
                {}
                tokens.push(AwkToken::Number);
            }
            c => {
                let next = chars.peek().copied();
                let punct = AWK_PUNCT.iter().find(|punct| {
                    let mut expected = punct.chars();
                    expected.next() == Some(c)
                        && match expected.next() {
                            Some(second) => next == Some(second),
                            None => true,
                        }
                });
                match punct {
                    Some(punct) => {
                        if punct.len() == 2 {
                            chars.next();
                        }
                        tokens.push(AwkToken::Punct(punct));
                    }
                    // Arithmetic and the like.
                    None => tokens.push(AwkToken::Punct("")),
                }
            }
        }
    }
    Ok(tokens)
}

/// The index just past the bracket that closes the one at `open`.
fn awk_close(tokens: &[AwkToken], open: usize) -> usize {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            AwkToken::Punct("(" | "[") => depth += 1,
            AwkToken::Punct(")" | "]") => {
                depth -= 1;
                if depth == 0 {
                    return index + 1;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

/// Whether the `ARGV` (subscripted when `subscript`) or `ARGC` name at `at`
/// is assigned, incremented or decremented. ARGV is also written without an
/// assignment operator: passed whole (to `split` or a function, whose array
/// parameter aliases it), as a getline target, or as a later call argument
/// (`sub`/`gsub` rewrite their third).
fn awk_assigned(tokens: &[AwkToken], at: usize, subscript: bool) -> bool {
    let before = at.checked_sub(1).map(|i| &tokens[i]);
    if subscript
        && (tokens.get(at + 1) != Some(&AwkToken::Punct("["))
            || matches!(before, Some(AwkToken::Punct(",")))
            || matches!(before, Some(AwkToken::Name(name)) if name == "getline"))
    {
        return true;
    }
    let after = if subscript && tokens.get(at + 1) == Some(&AwkToken::Punct("[")) {
        awk_close(tokens, at + 1)
    } else {
        at + 1
    };
    let assignment = |token: Option<&AwkToken>| {
        matches!(
            token,
            Some(AwkToken::Punct(
                "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "^=" | "++" | "--"
            ))
        )
    };
    assignment(tokens.get(after)) || matches!(before, Some(AwkToken::Punct("++" | "--")))
}

fn awk_literal(tokens: &[AwkToken]) -> Option<&str> {
    match tokens {
        [AwkToken::Text(Some(value))] => Some(value),
        _ => None,
    }
}

/// An output file concatenating string literals and at least one
/// `ENVIRON["NAME"]` value, optionally in one pair of parentheses.
fn awk_environ_path(tokens: &[AwkToken]) -> Option<Word> {
    let mut rest = match tokens {
        [AwkToken::Punct("("), inner @ .., AwkToken::Punct(")")] => inner,
        _ => tokens,
    };
    let mut parts = Vec::new();
    while !rest.is_empty() {
        rest = match rest {
            [AwkToken::Text(Some(value)), tail @ ..] => {
                parts.push(WordPart::Literal(value.clone()));
                tail
            }
            [
                AwkToken::Name(name),
                AwkToken::Punct("["),
                AwkToken::Text(Some(variable)),
                AwkToken::Punct("]"),
                tail @ ..,
            ] if name == "ENVIRON" => {
                parts.push(WordPart::Env(variable.clone()));
                tail
            }
            _ => return None,
        };
    }
    parts
        .iter()
        .any(|part| matches!(part, WordPart::Env(_)))
        .then(|| Word::new(parts))
}

/// Scan a literal awk program for the files and commands it reaches outside
/// its streams, or refuse one whose I/O this scan cannot place.
fn awk_io(text: &str) -> Result<AwkIo, &'static str> {
    const COMMAND: &[&str] = &["filesystem", "process"];
    const FILE: &[&str] = &["filesystem"];
    const ARGV: &str = "awk program assigns its input files through ARGV";
    // gawk opens `/inet/...`, `/inet4/...` and `/inet6/...` names as sockets.
    const NETWORK: &[&str] = &["network", "process"];
    let socket = |path: &str| {
        ["/inet/", "/inet4/", "/inet6/"]
            .iter()
            .any(|p| path.starts_with(p))
    };
    let tokens = awk_tokens(text)?;
    let mut io = AwkIo::default();
    for (i, token) in tokens.iter().enumerate() {
        match token {
            // `@include`, `@load` and indirect calls reach code this scan
            // never sees.
            AwkToken::Punct("@") => return Err("awk program uses a gawk @ directive"),
            // Assigning ARGV or ARGC changes which files the main input
            // loop reads.
            AwkToken::Name(name)
                if (name == "ARGV" || name == "ARGC")
                    && awk_assigned(&tokens, i, name == "ARGV")
                    && !io.unresolved.iter().any(|(_, detail)| *detail == ARGV) =>
            {
                io.unresolved.push((FILE, ARGV));
            }
            AwkToken::Punct("|&") => {
                io.unresolved
                    .push((COMMAND, "awk program runs a coprocess"));
            }
            AwkToken::Name(name) if name == "system" => {
                if tokens.get(i + 1) != Some(&AwkToken::Punct("(")) {
                    continue;
                }
                let end = awk_close(&tokens, i + 1);
                match awk_literal(tokens.get(i + 2..end - 1).unwrap_or_default()) {
                    Some(command) => io.commands.push(command.to_string()),
                    None => io
                        .unresolved
                        .push((COMMAND, "awk system() command is not a literal")),
                }
            }
            AwkToken::Name(name) if name == "getline" => {
                if i >= 1 && tokens[i - 1] == AwkToken::Punct("|") {
                    // Only a literal nothing binds more tightly than `|` is
                    // the command: concatenation and arithmetic both do.
                    let bounded = i >= 2
                        && matches!(
                            i.checked_sub(3).map(|j| &tokens[j]),
                            None | Some(
                                AwkToken::Newline
                                    | AwkToken::Punct(
                                        "(" | "{"
                                            | "}"
                                            | ";"
                                            | ","
                                            | "="
                                            | "!"
                                            | "?"
                                            | ":"
                                            | "&&"
                                            | "||"
                                    )
                            )
                        );
                    match bounded
                        .then(|| awk_literal(&tokens[i - 2..i - 1]))
                        .flatten()
                    {
                        Some(command) => io.commands.push(command.to_string()),
                        None => io
                            .unresolved
                            .push((COMMAND, "awk getline command is not a literal")),
                    }
                    continue;
                }
                // `getline [lvalue] [< file]`: the first unbracketed `<`
                // before the expression ends names the file. A shape the scan
                // does not recognize is a boundary rather than a silent miss.
                let mut depth = 0usize;
                let mut j = i + 1;
                while let Some(token) = tokens.get(j) {
                    match token {
                        AwkToken::Punct("(" | "[") => depth += 1,
                        AwkToken::Punct(")" | "]") if depth > 0 => depth -= 1,
                        _ if depth > 0 => {}
                        AwkToken::Punct("<") => {
                            let end = matches!(
                                tokens.get(j + 2),
                                None | Some(
                                    AwkToken::Newline
                                        | AwkToken::Punct(
                                            ";" | "}" | ")" | "]" | "," | "&&" | "||" | ">"
                                        )
                                )
                            );
                            match end.then(|| awk_literal(&tokens[j + 1..j + 2])).flatten() {
                                Some("-" | "/dev/stdin") => {}
                                Some(path) if socket(path) => io.unresolved.push((
                                    NETWORK,
                                    "awk getline reads a gawk network special file",
                                )),
                                Some(path) => io.reads.push(path.to_string()),
                                None => io
                                    .unresolved
                                    .push((FILE, "awk getline file is not a literal")),
                            }
                            break;
                        }
                        AwkToken::Name(_)
                        | AwkToken::Number
                        | AwkToken::Punct("$" | "++" | "--") => {}
                        AwkToken::Newline
                        | AwkToken::Punct(
                            ";" | "}" | ")" | "]" | "," | "&&" | "||" | ">" | ">=" | "<=" | "=="
                            | "!=" | "?" | ":" | "~" | "",
                        ) => break,
                        _ => {
                            io.unresolved
                                .push((FILE, "awk getline target is not modeled"));
                            break;
                        }
                    }
                    j += 1;
                }
            }
            AwkToken::Name(name) if name == "print" || name == "printf" => {
                // The statement's first unbracketed `>`, `>>` or `|` redirects
                // its output; the target runs to the end of the statement.
                let mut depth = 0usize;
                let mut j = i + 1;
                while let Some(token) = tokens.get(j) {
                    match token {
                        AwkToken::Punct("(" | "[") => depth += 1,
                        AwkToken::Punct(")" | "]") if depth > 0 => depth -= 1,
                        AwkToken::Punct(";" | "}" | ")" | "]") => break,
                        AwkToken::Newline
                            if !matches!(
                                tokens.get(j - 1),
                                Some(AwkToken::Punct("," | "&&" | "||"))
                            ) =>
                        {
                            break;
                        }
                        AwkToken::Punct(op @ (">" | ">>" | "|")) if depth == 0 => {
                            let start = j + 1;
                            let mut end = start;
                            while tokens.get(end).is_some_and(|token| {
                                !matches!(token, AwkToken::Newline | AwkToken::Punct(";" | "}"))
                            }) {
                                end += 1;
                            }
                            match (*op, awk_literal(&tokens[start..end])) {
                                ("|", Some(command)) => io.commands.push(command.to_string()),
                                ("|", None) => io
                                    .unresolved
                                    .push((COMMAND, "awk output pipe command is not a literal")),
                                (_, Some("/dev/stdout" | "/dev/stderr" | "-")) => {}
                                (_, Some(path)) if socket(path) => io.unresolved.push((
                                    NETWORK,
                                    "awk output goes to a gawk network special file",
                                )),
                                (op, Some(path)) => {
                                    io.writes.push((Word::literal(path), op == ">>"));
                                }
                                (op, None) => match awk_environ_path(&tokens[start..end]) {
                                    Some(target) => io.writes.push((target, op == ">>")),
                                    None => io
                                        .unresolved
                                        .push((FILE, "awk output file is not a literal")),
                                },
                            }
                            break;
                        }
                        _ => {}
                    }
                    j += 1;
                }
            }
            _ => {}
        }
    }
    Ok(io)
}

/// An awk file operand of the form `name=value` is a variable assignment.
fn is_awk_assignment(text: &str) -> bool {
    match text.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.chars().enumerate().all(|(i, c)| {
                    c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
        }
        None => false,
    }
}

const TR_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[],
    known_flags: &[
        "-c",
        "-C",
        "--complement",
        "-d",
        "--delete",
        "-s",
        "--squeeze-repeats",
        "-t",
        "--truncate-set1",
        "--help",
        "--version",
    ],
};

fn tr_stream(argv: &[Word]) -> bool {
    let scanned = scan(argv, &TR_SPEC);
    argv.iter().all(|word| word.as_literal().is_some())
        && scanned.unknown_flags.is_empty()
        && !scanned.has(&["--help", "--version"])
        && matches!(scanned.operands.len(), 1 | 2)
}

/// The model is chosen by basename, so `/usr/bin/rev` is rev too.
fn is_rev(argv: &[Word]) -> bool {
    argv.first().and_then(Word::as_literal).map(basename) == Some("rev")
}

fn rev_stream(argv: &[Word]) -> bool {
    argv.len() == 1 && is_rev(argv)
}

/// `rev FILE...` prints each file's lines reversed. Any option, or `-`, stays
/// unmodeled: util-linux and BSD rev differ on them.
fn rev_files(argv: &[Word]) -> bool {
    is_rev(argv)
        && argv.len() > 1
        && argv[1..].iter().all(|word| {
            !matches!(word.parts.first(), Some(crate::word::WordPart::Literal(text)) if text.starts_with('-'))
        })
}

/// Commands with no effect outside their own output: string transforms
/// (`tr`/`rev` rewrite stdin, `basename`/`dirname` manipulate argument text),
/// terminal/system probes (`tput`, `uname`), and no-ops.
/// Their operands are never files, except the files `rev` reads and prints.
struct Inert;

impl CommandModel for Inert {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "util/inert@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &[
            "tr", "rev", "tput", "uname", "sleep", "true", "false", "basename", "dirname",
        ]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        use crate::models::ModelBindingEnd;
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::{CausalAssurance, Port};

        let transform = ModelBindingEnd::Effect {
            operation: "process.stream_transform".into(),
            selection: EffectSelection::All,
        };
        if (argv.first().and_then(Word::as_literal) == Some("tr") && tr_stream(argv))
            || rev_stream(argv)
        {
            let mut bindings = vec![ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Port(Port::Stdout),
            }];
            if deciphers(argv) {
                bindings.extend([
                    ModelCausalBinding {
                        assurance: CausalAssurance::Exact,
                        from: ModelBindingEnd::Port(Port::Stdin),
                        to: transform.clone(),
                    },
                    ModelCausalBinding {
                        assurance: CausalAssurance::Exact,
                        from: transform,
                        to: ModelBindingEnd::Port(Port::Stdout),
                    },
                ]);
            }
            bindings
        } else if rev_files(argv) {
            vec![
                filesystem_read_stdout_binding(),
                ModelCausalBinding {
                    assurance: CausalAssurance::Conservative,
                    from: ModelBindingEnd::Effect {
                        operation: "filesystem.read".into(),
                        selection: EffectSelection::All,
                    },
                    to: transform.clone(),
                },
                ModelCausalBinding {
                    assurance: CausalAssurance::Conservative,
                    from: transform,
                    to: ModelBindingEnd::Port(Port::Stdout),
                },
            ]
        } else {
            Vec::new()
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx.argv.first().and_then(Word::as_literal) == Some("tr") && !tr_stream(ctx.argv) {
            let scanned = scan(ctx.argv, &TR_SPEC);
            let informational = scanned.has(&["--help", "--version"]);
            let mut unknown = scanned.unknown_flags;
            if unknown.is_empty() && !informational {
                unknown.push((0, "tr requires one or two literal sets".into()));
            }
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem", "process"],
                &unknown,
            );
        } else if rev_files(ctx.argv) {
            for (index, operand) in ctx.argv.iter().enumerate().skip(1) {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index as u32,
                    operand,
                    "filesystem.read",
                    program_input_attrs(),
                );
            }
        } else if is_rev(ctx.argv) && !rev_stream(ctx.argv) {
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem", "process"],
                &[(0, "rev file operands and options are not modeled".into())],
            );
        }
        // Reversed or letter-substituted text is an encoding of the output:
        // Nah types undoing it as decoding, as it does base64.
        if deciphers(ctx.argv) || rev_files(ctx.argv) {
            builder.effect(effinterp_proto::Effect {
                request_assurance: effinterp_proto::RequestAssurance::Exact,
                id: Default::default(),
                operation: effinterp_proto::Operation::new("process.stream_transform"),
                resource: crate::models::common::code_execution_resource(ctx),
                attributes: std::collections::BTreeMap::from([(
                    "transform".into(),
                    effinterp_proto::AttrValue::String("decode".into()),
                )]),
                modality: effinterp_proto::Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![model_node],
            });
        }
        fs_full_no_spawn(builder);
    }
}

/// `rev` over stdin, or `tr SET1 SET2` whose SET2 reorders SET1's own
/// characters, as ROT13 (`tr A-Za-z N-ZA-Mn-za-m`) does: each undoes a
/// reversible encoding of its input. Any option, a deleting or squeezing `tr`,
/// or sets that map onto other characters stay plain text transforms.
fn deciphers(argv: &[Word]) -> bool {
    if rev_stream(argv) {
        return true;
    }
    let [name, from, to] = argv else {
        return false;
    };
    if name.as_literal() != Some("tr") || !tr_stream(argv) {
        return false;
    }
    let (Some(from), Some(to)) = (
        from.as_literal().and_then(tr_alphabet),
        to.as_literal().and_then(tr_alphabet),
    ) else {
        return false;
    };
    let mut sorted_from = from.clone();
    sorted_from.sort_unstable();
    sorted_from.dedup();
    let mut sorted_to = to.clone();
    sorted_to.sort_unstable();
    sorted_from.len() == from.len() && sorted_from == sorted_to && from != to
}

/// A `tr` set of plain ASCII characters and ascending `a-z` ranges; escapes,
/// classes and anything GNU and BSD read differently are not expanded. GNU and
/// BSD both read `[` and `]` as literals unless the `[` opens `[:class:]`,
/// `[=c=]` or `[c*n]`, so the common `'[A-Za-z]'` spelling is plain text.
fn tr_alphabet(set: &str) -> Option<Vec<char>> {
    if set.is_empty() || set.starts_with('-') || !set.is_ascii() || set.contains('\\') {
        return None;
    }
    let chars = set.chars().collect::<Vec<_>>();
    if chars.iter().enumerate().any(|(index, c)| {
        *c == '['
            && (matches!(chars.get(index + 1), Some(':' | '='))
                || chars.get(index + 2) == Some(&'*'))
    }) {
        return None;
    }
    let mut expanded = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars.get(index + 1) == Some(&'-') && index + 2 < chars.len() {
            let (start, end) = (chars[index], chars[index + 2]);
            if start > end || [start, end].iter().any(|c| matches!(c, '[' | ']')) {
                return None;
            }
            expanded.extend(start..=end);
            index += 3;
        } else {
            expanded.push(chars[index]);
            index += 1;
        }
    }
    Some(expanded)
}

/// Recover text transforms without treating their operands as files read.
pub(crate) fn stdout_value(words: &[Word], cwd: Option<ResourceExpr>) -> Option<ResourceExpr> {
    let name = words.first()?.as_literal()?;
    let args = &words[1..];
    let cwd = || {
        cwd.clone()
            .unwrap_or(ResourceExpr::Parameter { name: "cwd".into() })
    };
    match name {
        "pwd"
            if args.is_empty()
                || matches!(args, [arg] if matches!(arg.as_literal(), Some("-L" | "-P"))) =>
        {
            Some(cwd())
        }
        "git" if matches!(args, [a, b] if a.as_literal() == Some("rev-parse") && b.as_literal() == Some("--show-toplevel")) => {
            Some(ResourceExpr::Property {
                base: Box::new(cwd()),
                name: "git_toplevel".into(),
            })
        }
        "command" if matches!(args, [a, b] if a.as_literal() == Some("-v") && b.as_literal().is_some_and(|s| !s.starts_with('-'))) => {
            Some(ResourceExpr::Property {
                base: Box::new(ResourceExpr::Parameter {
                    name: "PATH".into(),
                }),
                name: args[1].as_literal()?.into(),
            })
        }
        "echo" if args.iter().all(|arg| {
            let prefix = arg.literal_prefix();
            (arg.as_literal().is_some() || !prefix.is_empty())
                && !prefix.starts_with('-')
                && arg.parts.iter().all(|part| !matches!(part, crate::word::WordPart::Literal(text) if text.contains('\\')))
        }) => {
            let mut parts = Vec::new();
            for (index, arg) in args.iter().enumerate() {
                if index > 0 {
                    parts.push(crate::word::WordPart::Literal(" ".into()));
                }
                parts.extend(arg.parts.clone());
            }
            if let Some(crate::word::WordPart::Literal(tail)) = parts.last_mut() {
                tail.truncate(tail.trim_end_matches('\n').len());
            }
            Some(crate::nest::word_resource(&Word::new(parts)))
        }
        "dirname" | "basename" | "realpath" | "readlink" => {
            let args = if name == "readlink" {
                match args {
                    [flag, operand] if flag.as_literal() == Some("-f") => {
                        std::slice::from_ref(operand)
                    }
                    _ => return None,
                }
            } else if args.first().and_then(Word::as_literal) == Some("--") {
                &args[1..]
            } else {
                args
            };
            let [operand] = args else {
                return None;
            };
            if operand
                .as_literal()
                .is_some_and(|value| value.starts_with('-'))
            {
                return None;
            }
            if matches!(name, "dirname" | "basename")
                && let Some(value) = operand.as_literal() {
                    let path = value.trim_end_matches('/');
                    let value = if value.is_empty() {
                        if name == "basename" { "" } else { "." }
                    } else if path.is_empty() {
                        "/"
                    } else if name == "basename" {
                        path.rsplit('/').next().unwrap()
                    } else {
                        path.rsplit_once('/')
                            .map(|(parent, _)| parent.trim_end_matches('/'))
                            .map(|parent| if parent.is_empty() { "/" } else { parent })
                            .unwrap_or(".")
                    };
                    return Some(ResourceExpr::Literal {
                        value: value.into(),
                    });
                }
            let base = if matches!(name, "realpath" | "readlink") {
                crate::paths::resolve_fs_word_with_cwd(operand, Some(cwd()))
            } else {
                crate::nest::word_resource(operand)
            };
            // Canonical paths may traverse symlinks: retain the operation,
            // rather than claiming the operand itself is the resolved path.
            Some(ResourceExpr::Property {
                base: Box::new(base),
                name: if name == "readlink" { "realpath" } else { name }.into(),
            })
        }
        _ => None,
    }
}

/// `openssl enc` and its `base64` alias transform one input byte stream;
/// `openssl s_client` relays standard input to a TLS peer.
struct OpenSslEnc;

const OPENSSL_ENC_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-in", "-out"],
    known_flags: &[
        "-e", "-d", "-a", "-base64", "-A", "-none", "-help", "-list", "-ciphers",
    ],
};

fn openssl_base64_stream(argv: &[Word]) -> Option<Scanned<'_>> {
    let subcommand = argv.get(1).and_then(Word::as_literal)?;
    if !matches!(subcommand, "enc" | "base64") {
        return None;
    }
    let parsed = scan(&argv[1..], &OPENSSL_ENC_SPEC);
    (argv.iter().all(|word| word.as_literal().is_some())
        && parsed.unknown_flags.is_empty()
        && parsed.operands.is_empty()
        && parsed.flags.iter().all(|flag| {
            !OPENSSL_ENC_SPEC.value_flags.contains(&flag.name)
                || flag
                    .value
                    .as_ref()
                    .and_then(Word::as_literal)
                    .is_some_and(|value| !value.is_empty())
        })
        && !parsed.has(&["-help", "-list", "-ciphers"])
        && (subcommand == "base64" || parsed.has(&["-a", "-base64"])))
    .then_some(parsed)
}

/// The reviewed `openssl s_client` options: the peer and the session
/// options that leave its standard-input relay in place.
const OPENSSL_S_CLIENT_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-connect", "-servername"],
    known_flags: &[
        "-quiet",
        "-brief",
        "-ign_eof",
        "-no_ign_eof",
        "-nocommands",
        "-crlf",
        "-showcerts",
        "-tls1_2",
        "-tls1_3",
    ],
};

/// A literal `openssl s_client -connect HOST[:PORT]` over the reviewed
/// options: the index of the `-connect` value and the peer it names. Without
/// a port, s_client connects to 4433. After the handshake it sends every line
/// of standard input to the peer and prints what the peer sends.
fn openssl_s_client(argv: &[Word]) -> Option<(u32, String, u16)> {
    if argv.get(1).and_then(Word::as_literal) != Some("s_client")
        || argv.iter().any(|word| word.as_literal().is_none())
    {
        return None;
    }
    let parsed = scan_with_value_indices(&argv[1..], &OPENSSL_S_CLIENT_SPEC, true);
    if !parsed.unknown_flags.is_empty()
        || !parsed.operands.is_empty()
        || parsed.flags.iter().any(|flag| {
            OPENSSL_S_CLIENT_SPEC.value_flags.contains(&flag.name) && flag.value.is_none()
        })
    {
        return None;
    }
    let (index, target) = parsed.values_of(&["-connect"]).last().copied()?;
    let target = target.as_literal()?;
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') || host.starts_with('[') => (
            host.trim_start_matches('[').trim_end_matches(']'),
            port.parse().ok()?,
        ),
        Some(_) => return None,
        None => (target, 4433),
    };
    (!host.is_empty() && port != 0).then(|| (index + 1, host.to_owned(), port))
}

impl CommandModel for OpenSslEnc {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "openssl/enc@v2"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["openssl"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        use crate::models::ModelBindingEnd;
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::{CausalAssurance, Port};

        if openssl_s_client(argv).is_some() {
            return vec![
                ModelCausalBinding {
                    assurance: CausalAssurance::Exact,
                    from: ModelBindingEnd::Effect {
                        operation: "network.download".into(),
                        selection: EffectSelection::All,
                    },
                    to: ModelBindingEnd::Port(Port::Stdout),
                },
                ModelCausalBinding {
                    assurance: CausalAssurance::Exact,
                    from: ModelBindingEnd::Port(Port::Stdin),
                    to: ModelBindingEnd::Effect {
                        operation: "network.upload".into(),
                        selection: EffectSelection::All,
                    },
                },
            ];
        }
        let parsed = if let Some(parsed) = openssl_base64_stream(argv) {
            parsed
        } else {
            if argv.get(1).and_then(Word::as_literal) != Some("enc") {
                return Vec::new();
            }
            let parsed = scan(&argv[1..], &OPENSSL_ENC_SPEC);
            if !parsed.unknown_flags.is_empty()
                || !parsed.operands.is_empty()
                || parsed.flags.iter().any(|flag| {
                    OPENSSL_ENC_SPEC.value_flags.contains(&flag.name) && flag.value.is_none()
                })
                || parsed.has(&["-help", "-list", "-ciphers"])
            {
                return Vec::new();
            }
            return vec![ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: if parsed
                    .value_of(&["-in"])
                    .is_some_and(|file| file.as_literal() != Some("-"))
                {
                    ModelBindingEnd::Effect {
                        operation: "filesystem.read".into(),
                        selection: EffectSelection::All,
                    }
                } else {
                    ModelBindingEnd::Port(Port::Stdin)
                },
                to: if parsed
                    .value_of(&["-out"])
                    .is_some_and(|file| file.as_literal() != Some("-"))
                {
                    ModelBindingEnd::Effect {
                        operation: "filesystem.write".into(),
                        selection: EffectSelection::All,
                    }
                } else {
                    ModelBindingEnd::Port(Port::Stdout)
                },
            }];
        };
        let transform = ModelBindingEnd::Effect {
            operation: "process.stream_transform".into(),
            selection: EffectSelection::All,
        };
        vec![
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: if parsed
                    .value_of(&["-in"])
                    .is_some_and(|file| file.as_literal() != Some("-"))
                {
                    ModelBindingEnd::Effect {
                        operation: "filesystem.read".into(),
                        selection: EffectSelection::All,
                    }
                } else {
                    ModelBindingEnd::Port(Port::Stdin)
                },
                to: transform.clone(),
            },
            ModelCausalBinding {
                assurance: CausalAssurance::Exact,
                from: transform,
                to: if parsed
                    .value_of(&["-out"])
                    .is_some_and(|file| file.as_literal() != Some("-"))
                {
                    ModelBindingEnd::Effect {
                        operation: "filesystem.write".into(),
                        selection: EffectSelection::All,
                    }
                } else {
                    ModelBindingEnd::Port(Port::Stdout)
                },
            },
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if let Some((index, host, port)) = openssl_s_client(ctx.argv) {
            let peer = ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme: Some("tcp".into()),
                    port: Some(port),
                    path: None,
                },
            };
            let attributes = std::collections::BTreeMap::from([
                ("listen".into(), effinterp_proto::AttrValue::Bool(false)),
                (
                    "port".into(),
                    effinterp_proto::AttrValue::String(port.to_string()),
                ),
                (
                    "protocol".into(),
                    effinterp_proto::AttrValue::String("tcp".into()),
                ),
            ]);
            for operation in ["network.connect", "network.download", "network.upload"] {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    operation,
                    peer.clone(),
                    attributes.clone(),
                );
            }
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            return;
        }
        if !matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("enc" | "base64")
        ) {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNMODELED_SUBCOMMAND,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: self
                        .domains()
                        .iter()
                        .map(|name| Domain::new(*name))
                        .collect(),
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "only the openssl enc and base64 stream operations and a reviewed s_client session are modeled".into(),
                    ),
                },
                CoverageLevel::Partial,
            );
            return;
        }
        let parsed = scan_with_value_indices(&ctx.argv[1..], &OPENSSL_ENC_SPEC, true);
        let mut unknown = parsed.unknown_flags.clone();
        for flag in &parsed.flags {
            if OPENSSL_ENC_SPEC.value_flags.contains(&flag.name) && flag.value.is_none() {
                unknown.push((flag.index, format!("{} requires a value", flag.name)));
            }
        }
        unknown.extend(
            parsed
                .operands
                .iter()
                .map(|(index, word)| (*index, word.render_raw())),
        );
        if !unknown.is_empty() {
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem", "process"],
                &unknown,
            );
            return;
        }
        fs_full_no_spawn(builder);
        if parsed.has(&["-help", "-list", "-ciphers"]) {
            return;
        }
        if openssl_base64_stream(ctx.argv).is_some() {
            builder.effect(effinterp_proto::Effect {
                request_assurance: effinterp_proto::RequestAssurance::Exact,
                id: Default::default(),
                operation: effinterp_proto::Operation::new("process.stream_transform"),
                resource: crate::models::common::code_execution_resource(ctx),
                attributes: std::collections::BTreeMap::from([(
                    "transform".into(),
                    effinterp_proto::AttrValue::String(if parsed.has(&["-d"]) {
                        "decode".into()
                    } else {
                        "encode".into()
                    }),
                )]),
                modality: effinterp_proto::Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![model_node],
            });
        }
        for (flag, operation) in [("-in", "filesystem.read"), ("-out", "filesystem.write")] {
            if let Some((index, file)) = parsed.values_of(&[flag]).last() {
                if file.as_literal() == Some("-") {
                    continue;
                }
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index + 1,
                    file,
                    operation,
                    program_input_attrs(),
                );
            }
        }
    }
}

/// `ed [OPTION]... [FILE]`: loads FILE into a buffer and runs the editing
/// commands it reads from standard input. Any of them may write the buffer
/// back (`w`), touch another file, or run a shell command (`!`), so only a
/// literal script of reviewed buffer commands is interpreted.
struct Ed;

/// ed commands, after their line address, that name no other file and run
/// no shell command.
const ED_REVIEWED_COMMANDS: &[&str] = &["", "p", "n", "l", "q", "Q", "w", "wq", "W"];

impl CommandModel for Ed {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "editor/ed@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["ed"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: true,
            value_flags: &["-p", "--prompt"],
            known_flags: &[
                "-E",
                "--extended-regexp",
                "-G",
                "--traditional",
                "-l",
                "--loose-exit-status",
                "-q",
                "--quiet",
                "-s",
                "--silent",
                "-r",
                "--restricted",
                "-v",
                "--verbose",
                "-h",
                "--help",
                "-V",
                "--version",
            ],
        };
        let scanned =
            scan_with_value_indices(ctx.argv, &SPEC, ctx.tracks_host_context_environment());
        if scanned.has(&["-h", "--help", "-V", "--version"]) {
            fs_full_no_spawn(builder);
            return;
        }
        let commands = ctx.stdin_literal().map(|script| {
            script
                .lines()
                .map(|line| {
                    line.trim()
                        .trim_start_matches(|c: char| c.is_ascii_digit() || ",;.$+-".contains(c))
                })
                .collect::<Vec<_>>()
        });
        let reviewed = commands.as_ref().is_some_and(|commands| {
            commands
                .iter()
                .all(|command| ED_REVIEWED_COMMANDS.contains(command))
        });
        let writes = commands.as_ref().is_none_or(|commands| {
            commands
                .iter()
                .any(|command| command.starts_with(['w', 'W']))
        });
        let mut unknown = scanned.unknown_flags.clone();
        for (index, operand) in scanned.operands.iter().skip(1) {
            unknown.push((*index, operand.render_raw()));
        }
        if let Some((index, file)) = scanned.operands.first() {
            if file.literal_prefix().starts_with('!') {
                // `ed !command` edits the command's output, not a file.
                crate::models::common::boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBPROCESS,
                    BoundaryClass::Unmodeled,
                    &["process"],
                    "ed reads the output of a shell command",
                );
            } else {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.read",
                    program_input_attrs(),
                );
                if writes {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        file,
                        "filesystem.write",
                        Default::default(),
                    );
                }
            }
        }
        fs_full_no_spawn(builder);
        if !reviewed {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                &["filesystem", "process"],
                "ed commands from standard input are not statically recoverable",
            );
        }
        unrecognized_arguments_boundary(builder, model_node, &["filesystem", "process"], &unknown);
    }
}

/// `ex [OPTION]... [FILE]...`: Vim started in Ex mode. It reads its file
/// operands and runs the Ex commands given with `-c`/`+` and on standard
/// input; a write command saves the current file, or every file.
struct Ex;

impl CommandModel for Ex {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "editor/ex@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["ex"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut commands = Vec::new();
        let mut files = Vec::new();
        let mut unknown = Vec::new();
        let mut writes_disabled = false;
        let mut flags = true;
        let mut i = 1;
        while i < ctx.argv.len() {
            let word = &ctx.argv[i];
            let index = i as u32;
            let Some(text) = word.as_literal() else {
                unknown.push((index, word.render_raw()));
                i += 1;
                continue;
            };
            if flags && text == "--" {
                flags = false;
            } else if flags && text.starts_with('+') {
                if text.len() > 1 {
                    commands.push(&text[1..]);
                }
            } else if flags && text.starts_with("--") {
                if !matches!(
                    text,
                    "--clean" | "--noplugin" | "--not-a-term" | "--ttyfail"
                ) {
                    unknown.push((index, text.into()));
                }
            } else if flags && text.len() > 1 && text.starts_with('-') {
                // Vim reads a flag argument one letter at a time, so `-sc wq`
                // is `-s -c wq`; `-c` takes the rest of the word or the next.
                for (position, letter) in text.char_indices().skip(1) {
                    match letter {
                        's' | 'e' | 'E' | 'n' | 'b' | 'l' | 'C' | 'N' | 'D' | 'R' | 'Z' | 'v' => {}
                        'm' | 'M' => writes_disabled = true,
                        'c' => {
                            let rest = &text[position + 1..];
                            if !rest.is_empty() {
                                commands.push(rest);
                            } else if let Some(command) =
                                ctx.argv.get(i + 1).and_then(Word::as_literal)
                            {
                                commands.push(command);
                                i += 1;
                            } else {
                                unknown.push((index, text.into()));
                            }
                            break;
                        }
                        _ => {
                            unknown.push((index, text.into()));
                            break;
                        }
                    }
                }
            } else {
                files.push((index, word));
            }
            i += 1;
        }

        for (index, file) in &files {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                file,
                "filesystem.read",
                program_input_attrs(),
            );
        }
        let mut write_current = false;
        let mut write_all = false;
        let mut shell = false;
        for command in commands
            .into_iter()
            .chain(ctx.stdin_literal())
            .flat_map(|source| source.lines().flat_map(|line| line.split('|')))
        {
            let command = command.trim().trim_start_matches(':').trim();
            shell |= command.starts_with('!');
            let command = command.strip_suffix('!').unwrap_or(command);
            match command.to_ascii_lowercase().as_str() {
                "w" | "write" | "wq" | "x" | "xit" | "exit" | "update" => write_current = true,
                "wa" | "wall" | "wqa" | "wqall" | "xa" | "xall" => write_all = true,
                _ => {}
            }
        }
        if !writes_disabled {
            let selected = if write_all {
                files.as_slice()
            } else if write_current {
                &files[..files.len().min(1)]
            } else {
                &[]
            };
            for (index, file) in selected {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.write",
                    Default::default(),
                );
            }
        }
        fs_full_no_spawn(builder);
        if ctx.stdin.is_some() && ctx.stdin_literal().is_none() {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                &["filesystem", "process"],
                "Ex commands from standard input are not statically recoverable",
            );
        }
        if shell {
            crate::models::common::boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBPROCESS,
                BoundaryClass::Unmodeled,
                &["process"],
                "Ex shell commands are not modeled",
            );
        }
        unrecognized_arguments_boundary(builder, model_node, &["filesystem", "process"], &unknown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_complement_selects_exactly_the_names_left_unexcluded() {
        let excluded = [".env", ".env.local", ".a]-!^\\b"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let prefixes = [".env.l", ".cache"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let globs = basename_complement(&excluded, &prefixes);
        for name in [
            "x",
            "xy",
            "y",
            ".x",
            ".env",
            ".en",
            ".e",
            ".env.local",
            ".env.lo",
            ".env.",
            ".env.local.bak",
            ".envrc",
            ".git",
            "env",
            ".a]-!^\\b",
            ".a]-!^\\",
            ".a]-!^\\bc",
            ".cache",
            ".cached",
            ".cach",
        ] {
            let path = format!("/r/sub/{name}");
            let selected = globs.iter().any(|glob| {
                effinterp_proto::glob_match(&format!("/r/**/{glob}"), &path) == Ok(true)
            });
            let unexcluded =
                !excluded.contains(name) && !prefixes.iter().any(|prefix| name.starts_with(prefix));
            assert_eq!(selected, unexcluded, "{name} under {globs:?}");
        }
        let every_hidden = ["."].into_iter().collect();
        assert_eq!(
            basename_complement(&Default::default(), &every_hidden),
            ["*"]
        );
    }
}
