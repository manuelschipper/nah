//! Decompressors and archivers whose standard output is the decoded bytes of
//! their input. Nah types decompression as decoding: the invocation states a
//! `process.stream_transform` that its input feeds and its output carries, the
//! effect the decoded-payload rule follows into code execution. gzip, xz and
//! bzip2 state it in their own models; `STREAM_DECODERS` states it for the
//! other compressors' stdout spellings, whether a declarative model owns the
//! command (`with_stream_decode`) or not (`StreamDecoders`).

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance,
    CoverageLevel, Domain, Port, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, FlowStage, PortBinding};
use crate::models::args::{Flag, FlagSpec, Scanned, basename, scan_with_value_indices};
use crate::models::common::{
    arg_effect, code_execution_resource, fs_full_no_spawn, operand_effect, program_input_attrs,
    program_output_attrs,
};
use crate::models::{CommandModel, InvocationCtx, ModelCausalBinding};
use crate::value::unresolved_resource;
use crate::word::Word;

/// Where one command writes what it decodes, and when it decodes at all.
enum DecodeWhen {
    /// A `*cat` spelling always decodes, to stdout.
    Always,
    /// Decodes when the name implies it or a `decompress` flag is given, to
    /// stdout when a `stdout` flag is given or every input is stdin.
    Flags {
        decompress: Option<&'static [&'static str]>,
        stdout: &'static [&'static str],
    },
    /// Zstandard decodes under `-d` (or as `zstdcat`, which implies `-dc`);
    /// the last of `-o FILE` and `-c` names the output.
    Zstd { cat: bool },
    /// LZ4 decodes under `-d` (or as `lz4cat`, which implies `-dcm`); `-c`
    /// writes to stdout, and without `-m` a second operand names the output,
    /// `-` being stdout.
    Lz4 { cat: bool },
    /// `7z x` and `7z e` write the extracted members to stdout under `-so`.
    SevenZipStdout,
    /// `uudecode` writes to `-o FILE`, to stdout under `-p` or `-o
    /// /dev/stdout`, and otherwise to the file its encoded header names.
    Uudecode,
}

/// Whether a decode removes its input files afterwards. `--rm` and `-k` or
/// `--keep` set it, the last one winning.
#[derive(Clone, Copy, PartialEq)]
enum Removal {
    Never,
    /// LZ4 removes its inputs even after decoding to stdout.
    EvenToStdout,
    /// Zstandard ignores `--rm` when the output is stdout.
    UnlessStdout,
}

struct StreamDecoder {
    name: &'static str,
    when: DecodeWhen,
    spec: FlagSpec<'static>,
    /// Flags that print no decoded content at all (a test, a listing, help).
    elsewhere: &'static [&'static str],
    removal: Removal,
}

/// A flag list plus the compression levels `-0` to `-9`, which cluster.
macro_rules! with_levels {
    ($($flag:literal),* $(,)?) => {
        &[$($flag,)* "-0", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"]
    };
}

const ZSTD: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-o", "-D", "-T", "-M", "--memory", "--format"],
    known_flags: with_levels!(
        "-d",
        "--decompress",
        "--uncompress",
        "-c",
        "--stdout",
        "-f",
        "--force",
        "-k",
        "--keep",
        "--rm",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-z",
        "--compress",
        "-t",
        "--test",
        "-l",
        "--list",
        "--no-progress",
        "--sparse",
        "--no-sparse",
        "--ultra",
        "--fast",
        "--long",
        "-h",
        "-H",
        "--help",
        "-V",
        "--version",
    ),
};
const ZSTD_ELSEWHERE: &[&str] = &[
    "-t",
    "--test",
    "-l",
    "--list",
    "-h",
    "-H",
    "--help",
    "-V",
    "--version",
    "-z",
    "--compress",
];

const XZ: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: true,
    value_flags: &[
        "-F",
        "--format",
        "-C",
        "--check",
        "-T",
        "--threads",
        "-M",
        "--memlimit",
        "-S",
        "--suffix",
    ],
    known_flags: with_levels!(
        "-z",
        "--compress",
        "-d",
        "--decompress",
        "--uncompress",
        "-t",
        "--test",
        "-l",
        "--list",
        "-k",
        "--keep",
        "-f",
        "--force",
        "-c",
        "--stdout",
        "--to-stdout",
        "--single-stream",
        "--no-sparse",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-Q",
        "--no-warn",
        "-e",
        "--extreme",
        "-h",
        "-H",
        "--help",
        "-V",
        "--version",
    ),
};
const XZ_ELSEWHERE: &[&str] = &[
    "-t",
    "--test",
    "-l",
    "--list",
    "-h",
    "-H",
    "--help",
    "-V",
    "--version",
    "-z",
    "--compress",
];

const BZIP2: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: true,
    value_flags: &[],
    known_flags: with_levels!(
        "-d",
        "--decompress",
        "-z",
        "--compress",
        "-k",
        "--keep",
        "-f",
        "--force",
        "-t",
        "--test",
        "-c",
        "--stdout",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-s",
        "--small",
        "--fast",
        "--best",
        "-L",
        "--license",
        "-V",
        "--version",
        "-h",
        "--help",
    ),
};
const BZIP2_ELSEWHERE: &[&str] = &[
    "-t",
    "--test",
    "-L",
    "--license",
    "-V",
    "--version",
    "-h",
    "--help",
    "-z",
    "--compress",
];

const LZ4: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-B"],
    known_flags: with_levels!(
        "-d",
        "--decompress",
        "--uncompress",
        "-c",
        "--stdout",
        "--to-stdout",
        "-f",
        "--force",
        "-k",
        "--keep",
        "--rm",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-m",
        "--multiple",
        "-t",
        "--test",
        "-l",
        "--list",
        "-z",
        "--compress",
        "--fast",
        "--best",
        "--no-frame-crc",
        "--content-size",
        "--sparse",
        "--no-sparse",
        "-h",
        "-H",
        "--help",
        "-V",
        "--version",
    ),
};
const LZ4_ELSEWHERE: &[&str] = &[
    "-t",
    "--test",
    "--list",
    "-h",
    "-H",
    "--help",
    "-V",
    "--version",
    "-z",
    "--compress",
];

const PIGZ: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-b", "--blocksize", "-p", "--processes", "-S", "--suffix"],
    known_flags: with_levels!(
        "-d",
        "--decompress",
        "-c",
        "--stdout",
        "-f",
        "--force",
        "-k",
        "--keep",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-n",
        "--no-name",
        "-N",
        "--name",
        "-m",
        "--no-time",
        "-M",
        "--time",
        "-l",
        "--list",
        "-t",
        "--test",
        "-z",
        "--zlib",
        "-K",
        "--zip",
        "-i",
        "--independent",
        "-R",
        "--rsyncable",
        "--fast",
        "--best",
        "-h",
        "--help",
        "-V",
        "--version",
        "-L",
        "--license",
    ),
};
const PIGZ_ELSEWHERE: &[&str] = &[
    "-l",
    "--list",
    "-t",
    "--test",
    "-h",
    "--help",
    "-V",
    "--version",
    "-L",
    "--license",
];

const UUDECODE: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: true,
    value_flags: &["-o", "--output-file"],
    known_flags: &["-c", "-i", "-p", "-r", "-s", "--help", "--version"],
};

const SEVEN_ZIP: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[],
    known_flags: &[],
};

/// The decoders this module states. A name a declarative model owns is
/// wrapped by `with_stream_decode`; the rest belong to `StreamDecoders`.
const STREAM_DECODERS: &[StreamDecoder] = &[
    StreamDecoder {
        name: "zstd",
        when: DecodeWhen::Zstd { cat: false },
        spec: ZSTD,
        elsewhere: ZSTD_ELSEWHERE,
        removal: Removal::UnlessStdout,
    },
    StreamDecoder {
        name: "zstdcat",
        when: DecodeWhen::Zstd { cat: true },
        spec: ZSTD,
        elsewhere: ZSTD_ELSEWHERE,
        removal: Removal::UnlessStdout,
    },
    StreamDecoder {
        name: "unxz",
        when: DecodeWhen::Flags {
            decompress: None,
            stdout: &["-c", "--stdout", "--to-stdout"],
        },
        spec: XZ,
        elsewhere: XZ_ELSEWHERE,
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "xzcat",
        when: DecodeWhen::Always,
        spec: XZ,
        elsewhere: XZ_ELSEWHERE,
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "lzcat",
        when: DecodeWhen::Always,
        spec: XZ,
        elsewhere: XZ_ELSEWHERE,
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "bunzip2",
        when: DecodeWhen::Flags {
            decompress: None,
            stdout: &["-c", "--stdout"],
        },
        spec: BZIP2,
        elsewhere: BZIP2_ELSEWHERE,
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "bzcat",
        when: DecodeWhen::Always,
        spec: BZIP2,
        elsewhere: BZIP2_ELSEWHERE,
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "lz4",
        when: DecodeWhen::Lz4 { cat: false },
        spec: LZ4,
        elsewhere: LZ4_ELSEWHERE,
        removal: Removal::EvenToStdout,
    },
    StreamDecoder {
        name: "lz4cat",
        when: DecodeWhen::Lz4 { cat: true },
        spec: LZ4,
        elsewhere: LZ4_ELSEWHERE,
        removal: Removal::EvenToStdout,
    },
    StreamDecoder {
        name: "pigz",
        when: DecodeWhen::Flags {
            decompress: Some(&["-d", "--decompress"]),
            stdout: &["-c", "--stdout"],
        },
        spec: PIGZ,
        elsewhere: PIGZ_ELSEWHERE,
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "uudecode",
        when: DecodeWhen::Uudecode,
        spec: UUDECODE,
        elsewhere: &["--help", "--version"],
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "7z",
        when: DecodeWhen::SevenZipStdout,
        spec: SEVEN_ZIP,
        elsewhere: &[],
        removal: Removal::Never,
    },
    StreamDecoder {
        name: "7za",
        when: DecodeWhen::SevenZipStdout,
        spec: SEVEN_ZIP,
        elsewhere: &[],
        removal: Removal::Never,
    },
];

/// An invocation that writes decoded bytes: the input words it reads (stdin
/// when none), the other files the decode reads (a dictionary, a member
/// list), the transform it states, where the decoded bytes go and whether
/// it removes its inputs afterwards.
struct DecodedStream<'a> {
    inputs: Vec<(u32, &'a Word)>,
    other_reads: Vec<(u32, Word)>,
    transform: &'static [(&'static str, &'static str)],
    output: Output,
    removes_inputs: bool,
}

enum Output {
    Stdout,
    File(u32, Word),
    /// A file whose name only the decoded input states.
    Unnamed,
}

const DECODE: &[(&str, &str)] = &[("transform", "decode")];

/// The last of the given flags, in argument order.
fn last_flag<'s>(scanned: &'s Scanned<'_>, names: &[&str]) -> Option<&'s Flag<'s>> {
    scanned
        .flags
        .iter()
        .filter(|flag| names.contains(&flag.name))
        .max_by_key(|flag| flag.index)
}

fn output_word(index: u32, file: &Word) -> Output {
    if matches!(file.as_literal(), Some("-" | "/dev/stdout")) {
        Output::Stdout
    } else {
        Output::File(index, file.clone())
    }
}

/// The decode an invocation performs, or None when it decodes nothing, writes
/// to a name it derives from its input (which the owner model states), or
/// passes an option this grammar does not know.
fn decoded_stream(argv: &[Word]) -> Option<DecodedStream<'_>> {
    let name = basename(argv.first()?.as_literal()?);
    let decoder = STREAM_DECODERS
        .iter()
        .find(|decoder| decoder.name == name)?;
    if let DecodeWhen::SevenZipStdout = decoder.when {
        return seven_zip_stdout(argv);
    }
    let scanned: Scanned<'_> = scan_with_value_indices(argv, &decoder.spec, true);
    if !scanned.unknown_flags.is_empty() || scanned.has(decoder.elsewhere) {
        return None;
    }
    let mut inputs = scanned.operands.clone();
    let stdin_only = inputs
        .iter()
        .all(|(_, operand)| operand.as_literal() == Some("-"));
    let decompress = &["-d", "--decompress", "--uncompress"];
    let output = match decoder.when {
        DecodeWhen::Always => Output::Stdout,
        DecodeWhen::Flags { decompress, stdout } => {
            if !decompress.is_none_or(|flags| scanned.has(flags)) {
                return None;
            }
            if !scanned.has(stdout) && !stdin_only {
                return None;
            }
            Output::Stdout
        }
        DecodeWhen::Zstd { cat } => {
            if !cat && !scanned.has(decompress) {
                return None;
            }
            match last_flag(&scanned, &["-o", "-c", "--stdout"]) {
                Some(flag) if flag.name == "-o" => {
                    output_word(flag.value_index?, flag.value.as_ref()?)
                }
                Some(_) => Output::Stdout,
                None if cat || stdin_only => Output::Stdout,
                None => return None,
            }
        }
        DecodeWhen::Lz4 { cat } => {
            if !cat && !scanned.has(decompress) {
                return None;
            }
            let multiple = cat || scanned.has(&["-m", "--multiple"]);
            if cat || scanned.has(&["-c", "--stdout", "--to-stdout"]) {
                // A second operand beside `-c` is not modeled.
                if !multiple && inputs.len() > 1 {
                    return None;
                }
                Output::Stdout
            } else if multiple {
                return None;
            } else if inputs.len() == 2 {
                let (index, file) = inputs.pop()?;
                output_word(index, file)
            } else if stdin_only && inputs.len() <= 1 {
                Output::Stdout
            } else {
                return None;
            }
        }
        DecodeWhen::Uudecode => match scanned.values_of(&["-o", "--output-file"]).last() {
            Some((index, file)) => output_word(*index, file),
            None if scanned.has(&["-p"]) => Output::Stdout,
            None => Output::Unnamed,
        },
        DecodeWhen::SevenZipStdout => return None,
    };
    let removes =
        last_flag(&scanned, &["--rm", "-k", "--keep"]).is_some_and(|flag| flag.name == "--rm");
    let removes_inputs = match decoder.removal {
        Removal::Never => false,
        Removal::EvenToStdout => removes,
        Removal::UnlessStdout => removes && !matches!(output, Output::Stdout),
    };
    let other_reads = match decoder.when {
        DecodeWhen::Zstd { .. } => scanned
            .flags
            .iter()
            .filter(|flag| flag.name == "-D")
            .filter_map(|flag| Some((flag.value_index?, flag.value.clone()?)))
            .collect(),
        _ => Vec::new(),
    };
    Some(DecodedStream {
        inputs,
        other_reads,
        transform: DECODE,
        output,
        removes_inputs,
    })
}

/// 7-Zip switches that change nothing an extraction to stdout reads or
/// writes: a password, the archive type, overwrite and output-directory
/// modes stdout ignores, recursion, threads, console output and charsets.
const SEVEN_ZIP_SWITCHES: &[&str] = &[
    "-p", "-t", "-o", "-ao", "-r", "-y", "-bb", "-bd", "-bs", "-bt", "-mmt", "-scs", "-scc",
];

/// `7z x|e [SWITCH]... ARCHIVE [MEMBER|@LISTFILE]...` with `-so` among the
/// switches. Every 7-Zip switch attaches its value, so a dashed word never
/// consumes the next one; the first other word after the command is the
/// archive. A member list (`@FILE`, or `-i@FILE`, `-xr@FILE` and the like)
/// is a file the extraction reads; a switch outside the reviewed set leaves
/// the invocation to the owner model.
fn seven_zip_stdout(argv: &[Word]) -> Option<DecodedStream<'_>> {
    if !matches!(argv.get(1)?.as_literal()?, "x" | "e") {
        return None;
    }
    let list = |index: usize, text: &str| (index as u32, Word::literal(text));
    let mut switches = true;
    let mut stdout = false;
    let mut archive = None;
    let mut other_reads = Vec::new();
    for (index, word) in argv.iter().enumerate().skip(2) {
        let Some(text) = word.as_literal() else {
            if switches && word.literal_prefix().starts_with(['-', '@']) {
                return None;
            }
            if archive.is_none() {
                archive = Some((index as u32, word));
            }
            continue;
        };
        if !switches {
            if archive.is_none() {
                archive = Some((index as u32, word));
            }
            continue;
        }
        if text == "--" {
            switches = false;
        } else if text == "-so" {
            stdout = true;
        } else if let Some(rest) = text.strip_prefix("-i").or_else(|| text.strip_prefix("-x")) {
            // `-i` and `-x` take an optional recursion modifier, then a
            // wildcard (`!`) or a list file (`@`).
            let rest = rest
                .strip_prefix('r')
                .map(|rest| rest.trim_start_matches(['-', '0']))
                .unwrap_or(rest);
            if let Some(file) = rest.strip_prefix('@') {
                other_reads.push(list(index, file));
            } else if !rest.starts_with('!') {
                return None;
            }
        } else if text.starts_with('-') {
            if !SEVEN_ZIP_SWITCHES
                .iter()
                .any(|switch| text.starts_with(switch))
            {
                return None;
            }
        } else if let Some(file) = text.strip_prefix('@') {
            other_reads.push(list(index, file));
        } else if archive.is_none() {
            archive = Some((index as u32, word));
        }
    }
    if other_reads
        .iter()
        .any(|(_, file)| file.as_literal() == Some(""))
    {
        return None;
    }
    stdout.then(|| DecodedStream {
        inputs: archive.into_iter().collect(),
        other_reads,
        transform: &[
            ("transform", "extract"),
            ("format", "7z"),
            ("selection", "archive_member"),
        ],
        output: Output::Stdout,
        removes_inputs: false,
    })
}

/// The decode or archive-member extraction an invocation performs.
pub(crate) fn stream_transform(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    attributes: &[(&str, &str)],
) -> Option<u32> {
    builder.effect(effinterp_proto::Effect {
        request_assurance: effinterp_proto::RequestAssurance::Exact,
        id: Default::default(),
        operation: effinterp_proto::Operation::new("process.stream_transform"),
        resource: code_execution_resource(ctx),
        attributes: attributes
            .iter()
            .map(|(name, value)| ((*name).into(), AttrValue::String((*value).into())))
            .collect(),
        modality: effinterp_proto::Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: vec![model_node],
    })
}

fn apply_decoded_stream(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    stream: &DecodedStream<'_>,
) {
    fs_full_no_spawn(builder);
    let files: Vec<(u32, &Word)> = stream
        .inputs
        .iter()
        .filter(|(_, input)| input.as_literal() != Some("-"))
        .copied()
        .collect();
    let reads: Vec<u32> = files
        .iter()
        .copied()
        .chain(
            stream
                .other_reads
                .iter()
                .map(|(index, file)| (*index, file)),
        )
        .filter_map(|(index, file)| {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.read",
                program_input_attrs(),
            )
        })
        .collect();
    let Some(transform) = stream_transform(builder, ctx, model_node, stream.transform) else {
        return;
    };
    let assurance = if stream.inputs.len() <= 1
        && ctx.argv.iter().all(|word| word.as_literal().is_some())
        && builder.execution_is_exact(builder.current_execution())
    {
        CausalAssurance::Exact
    } else {
        CausalAssurance::Conservative
    };
    let output = match &stream.output {
        Output::Stdout => Some(BindEnd::Port(Port::Stdout)),
        Output::File(index, file) => operand_effect(
            builder,
            ctx,
            model_node,
            *index,
            file,
            "filesystem.write",
            program_output_attrs(),
        )
        .map(BindEnd::Effect),
        Output::Unnamed => {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("uudecode names its output file in the encoded input".into()),
                },
                CoverageLevel::Partial,
            );
            arg_effect(
                builder,
                ctx,
                model_node,
                0,
                "filesystem.write",
                unresolved_resource("filesystem"),
                program_output_attrs(),
            )
            .map(BindEnd::Effect)
        }
    };
    let binding = |from, to| PortBinding {
        assurance,
        from,
        to,
    };
    let mut bindings = Vec::new();
    let mut effects = reads.clone();
    effects.push(transform);
    if let Some(output) = output {
        if let BindEnd::Effect(write) = output {
            effects.push(write);
        }
        bindings.push(binding(BindEnd::Effect(transform), output));
    }
    for read in &reads {
        bindings.push(binding(BindEnd::Effect(*read), BindEnd::Effect(transform)));
    }
    if stream.inputs.is_empty()
        || stream
            .inputs
            .iter()
            .any(|(_, input)| input.as_literal() == Some("-"))
    {
        bindings.push(binding(
            BindEnd::Port(Port::Stdin),
            BindEnd::Effect(transform),
        ));
    }
    builder.flow_stage(FlowStage {
        execution: Some(builder.current_execution()),
        effects,
        bindings,
        provenance: vec![model_node],
    });
    if stream.removes_inputs {
        for (index, file) in files {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.delete",
                Default::default(),
            );
        }
    }
}

/// The `*cat` decoders and `uudecode`, which no other model owns.
pub(crate) struct StreamDecoders;

impl CommandModel for StreamDecoders {
    fn id(&self) -> &'static str {
        "decode/stream-decoders@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["zstdcat", "xzcat", "lzcat", "bzcat", "lz4cat", "uudecode"]
    }

    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        match decoded_stream(ctx.argv) {
            Some(stream) => apply_decoded_stream(builder, ctx, model_node, &stream),
            // A test, listing, help or version run, or an option this
            // grammar does not know, is outside the decode forms stated.
            None => {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::MODEL_COVERAGE,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem"), Domain::new("process")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some("only decoding to stdout or a named file is modeled".into()),
                    },
                    CoverageLevel::Partial,
                );
            }
        }
    }
}

/// A declarative compressor model whose decode `STREAM_DECODERS` states: a
/// decoding invocation is this module's; any other, including one with an
/// option the grammar does not know, is the owner's.
pub(crate) fn with_stream_decode(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(StreamDecode { owner })
}

struct StreamDecode {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for StreamDecode {
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
        if decoded_stream(argv).is_some() {
            return Vec::new();
        }
        self.owner.stdout_value_bindings(argv)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        if decoded_stream(argv).is_some() {
            return Vec::new();
        }
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        match decoded_stream(ctx.argv) {
            Some(stream) => apply_decoded_stream(builder, ctx, model_node, &stream),
            None => self.owner.apply(builder, ctx, model_node),
        }
    }
}
