//! tar: old-style mode clusters (`tar cf - src`), dashed clusters
//! (`tar -czf a.tgz src`), and long options, for GNU tar and libarchive's
//! bsdtar.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance, CoverageLevel, Domain,
    Port, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, FlowStage, PortBinding};
use crate::models::common::{
    arg_effect, code_execution, fs_arg_effect, fs_full_no_spawn, nest_remote_shell,
    opaque_source_with_provenance, operand_effect, program_input_attrs, program_output_attrs,
    unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::paths::resolve_fs_word_with_cwd;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

pub(super) fn archive_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Tar(TarDialect::Gnu)),
        Box::new(Tar(TarDialect::Bsd)),
    ]
}

/// `gtar` is GNU tar under the name it is installed by beside another tar.
/// Its model document reads a flag's value but not where the flag stands, so
/// it cannot apply each `-C` to the members after it; creating an archive
/// with a `-C` is read by the native GNU model, which does.
pub(super) fn with_gnu_create(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(Gtar { owner })
}

struct Gtar {
    owner: Box<dyn CommandModel>,
}

/// The command line may create an archive and change directory: `--create`
/// and `--directory`, or a `c` and a `C` in a short option cluster or in the
/// first word's old-style letters. A letter that is part of an attached
/// value only sends another command line to the native model too, which
/// reads it as GNU tar does.
fn gtar_creates_in_directory(argv: &[Word]) -> bool {
    let spells = |long: &str, letter: char| {
        argv.iter().enumerate().skip(1).any(|(index, word)| {
            let text = word.literal_prefix();
            match text.strip_prefix('-') {
                Some(rest) if rest.starts_with('-') => {
                    let name = text.split('=').next().unwrap_or(text);
                    name.len() > 3 && long.starts_with(name)
                }
                Some(cluster) => cluster.contains(letter),
                None => index == 1 && text.contains(letter),
            }
        })
    };
    spells("--create", 'c') && spells("--directory", 'C')
}

impl CommandModel for Gtar {
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

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        self.owner.stdout_value_bindings(argv)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        if gtar_creates_in_directory(argv) {
            Tar(TarDialect::Gnu).causal_bindings(argv)
        } else {
            self.owner.causal_bindings(argv)
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if gtar_creates_in_directory(ctx.argv) {
            Tar(TarDialect::Gnu).apply(builder, ctx, model_node);
        } else {
            self.owner.apply(builder, ctx, model_node);
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum TarMode {
    Create,
    Extract,
    List,
}

/// Everything extracted writes *somewhere under* the target directory;
/// members are unknown statically, so the resource is a pattern.
pub(super) fn extraction_target(dir: Option<&Word>, cwd: Option<ResourceExpr>) -> ResourceExpr {
    let dir_word = dir.cloned().unwrap_or_else(|| Word::literal("."));
    match resolve_fs_word_with_cwd(&dir_word, cwd) {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: format!(
                    "{}/**",
                    crate::paths::escape_fs_glob_path(path.trim_end_matches('/'))
                ),
                narrowing: Default::default(),
            },
        },
        other => ResourceExpr::Join {
            parts: vec![
                other,
                ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath {
                        glob: "**".to_string(),
                        narrowing: Default::default(),
                    },
                },
            ],
        },
    }
}

/// GNU tar and bsdtar share most of the command line. bsdtar ignores
/// TAR_OPTIONS, has no remote archives or command hooks beyond a compressor,
/// spells `-H` and `-L` as symlink-following flags, and reads `-I` as `-T`.
#[derive(Clone, Copy, PartialEq)]
enum TarDialect {
    Gnu,
    Bsd,
}

struct Tar(TarDialect);

#[derive(Clone, Copy)]
enum AuditedBinding {
    CreateStdout,
    /// Creation whose archive is an effect endpoint: a local file, a remote
    /// `host:path` upload, or a symbolic destination. Stdout has its own
    /// variant.
    CreateArchiveEndpoint,
    ExtractStdoutFile,
    ExtractStdoutStdin,
    ExtractStdoutUnknown,
}

/// An archive name tar opens as a file. `/dev/fd/N` and `/proc/self/fd/N`
/// are ordinary names for a descriptor the caller already opened, so tar
/// writes or reads the archive through them like any other path; where that
/// descriptor leads is the shell's to say, not tar's. `--force-local` drops
/// the colon rule, making a `host:path` name a plain local file.
fn local_archive(value: &str, force_local: bool) -> bool {
    !value.is_empty()
        && value != "-"
        && (force_local || !value.contains(':'))
        && !matches!(value, "/dev/stdin" | "/dev/stdout" | "/dev/stderr")
}

/// The long options this model understands. GNU tar accepts any unambiguous
/// prefix of an option name, so a prefix resolves to the single option it
/// selects here; anything ambiguous or unlisted stays unrecognized.
const LONG_OPTIONS: [&str; 40] = [
    "--absolute-names",
    "--add-file",
    "--append",
    "--bzip2",
    "--catenate",
    "--checkpoint",
    "--checkpoint-action",
    "--concatenate",
    "--create",
    "--dereference",
    "--directory",
    "--exclude",
    "--exclude-from",
    "--extract",
    "--file",
    "--files-from",
    "--force-local",
    "--get",
    "--gzip",
    "--info-script",
    "--keep-old-files",
    "--label",
    "--list",
    "--new-volume-script",
    "--no-recursion",
    "--no-same-owner",
    "--overwrite",
    "--preserve-permissions",
    "--recursion",
    "--remove-files",
    "--rmt-command",
    "--rsh-command",
    "--same-owner",
    "--strip-components",
    "--to-command",
    "--to-stdout",
    "--update",
    "--use-compress-program",
    "--xz",
    "--zstd",
];

fn tar_environment_read(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    name: &str,
) {
    arg_effect(
        builder,
        ctx,
        model_node,
        0,
        "environment.read",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
        },
        Default::default(),
    );
}

/// GNU tar splits TAR_OPTIONS into words the way a shell would without
/// expansions: whitespace separates words and single or double quotes group
/// them. GNU also runs each word through its own backslash-escape decoder
/// (`wordsplit_string_unquote_copy`), whose byte semantics — uppercase `\X`
/// hex, octal byte truncation, UTF-8 reassembly, decoded NUL — this model does
/// not replicate. A value containing any backslash is therefore left
/// unrecoverable, so no option or concrete path is ever derived from a wrong
/// interpretation; only a backslash-free value is parsed. An unterminated
/// quote also leaves the options unknown.
fn split_tar_options(value: &str) -> Option<Vec<Word>> {
    if value.contains('\\') {
        return None;
    }
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_ascii_whitespace() => words.extend(word.take().map(Word::literal)),
            '\'' => {
                let word = word.get_or_insert_default();
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => word.push(c),
                    }
                }
            }
            '"' => {
                let word = word.get_or_insert_default();
                loop {
                    match chars.next()? {
                        '"' => break,
                        c => word.push(c),
                    }
                }
            }
            c => word.get_or_insert_default().push(c),
        }
    }
    words.extend(word.map(Word::literal));
    Some(words)
}

fn tar_option_words(value: &ResourceExpr) -> Option<Vec<Word>> {
    match value {
        ResourceExpr::Literal { value } => split_tar_options(value),
        ResourceExpr::Union { alternatives } => {
            let mut words = Vec::new();
            for alternative in alternatives {
                words.extend(tar_option_words(alternative)?);
            }
            Some(words)
        }
        _ => None,
    }
}

fn tar_options_exact(value: Option<&ResourceExpr>) -> bool {
    match value {
        None => true,
        // A value `split_tar_options` fully parses is exact; a backslash
        // (unmodeled escape decoding) or an unterminated quote returns None.
        Some(ResourceExpr::Literal { value }) => split_tar_options(value).is_some(),
        Some(ResourceExpr::Union { alternatives }) => alternatives
            .iter()
            .all(|value| tar_options_exact(Some(value))),
        Some(_) => false,
    }
}

fn canonical_long_option(name: &str) -> Option<&'static str> {
    if let Some(exact) = LONG_OPTIONS.iter().copied().find(|option| *option == name) {
        return Some(exact);
    }
    let mut matching = LONG_OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(name));
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

/// GNU tar transfers an archive named `[user@]host:path` over a remote shell.
/// The colon must appear in the first path component, or the name is local.
fn remote_archive_host(value: &str) -> Option<&str> {
    let (host, _) = value.split('/').next()?.split_once(':')?;
    let host = host.rsplit('@').next()?;
    (!host.is_empty()).then_some(host)
}

/// The archive endpoint of a remote archive name. GNU tar reaches it through
/// `--rsh-command` or `rmt`, so no transport scheme is claimed.
fn remote_archive_endpoint(host: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host: host.to_string(),
            scheme: None,
            port: None,
            path: None,
        },
    }
}

fn audited_tar_binding(argv: &[Word], default_archive: Option<&str>) -> Option<AuditedBinding> {
    let mut mode = None;
    let mut archive = None;
    let mut to_stdout = false;
    let mut operands = 0;
    let mut compression = 0;
    let mut force_local = false;
    let mut end_of_options = false;
    let mut i = 1;
    while i < argv.len() {
        let word = &argv[i];
        if end_of_options {
            operands += 1;
            i += 1;
            continue;
        }
        let text = match word.as_literal() {
            Some(text) => text,
            // A fixed path prefix prevents expansion into a tar option. The
            // selected members remain symbolic; their content route is known.
            None if i > 1
                && matches!(word.parts.as_slice(), [crate::word::WordPart::Glob(pattern)]
                if pattern.starts_with('/') || pattern.starts_with("./")
                    || pattern.split(['*', '?', '[', '{', '@', '!', '+']).next()
                        .is_some_and(|prefix| !prefix.starts_with('-') && prefix.contains('/'))) =>
            {
                operands += 1;
                i += 1;
                continue;
            }
            None => return None,
        };
        if text == "--" {
            end_of_options = true;
        } else if text.starts_with("--") {
            let (name, attached) = text
                .split_once('=')
                .map_or((text, None), |(n, v)| (n, Some(v)));
            match canonical_long_option(name).unwrap_or(name) {
                "--create" | "--extract" | "--get" if attached.is_none() => {
                    if mode
                        .replace(
                            if matches!(canonical_long_option(name), Some("--get" | "--extract")) {
                                TarMode::Extract
                            } else {
                                TarMode::Create
                            },
                        )
                        .is_some()
                    {
                        return None;
                    }
                }
                "--to-stdout" if attached.is_none() => to_stdout = true,
                "--gzip" | "--bzip2" if attached.is_none() => compression += 1,
                "--verbose" if attached.is_none() => {}
                "--no-recursion" | "--recursion" if attached.is_none() && operands == 0 => {}
                "--force-local" if attached.is_none() => force_local = true,
                "--add-file" => {
                    if attached.is_none() {
                        i += 1;
                        argv.get(i)?.as_literal()?;
                    }
                    operands += 1;
                }
                "--file" | "--directory" | "--label" => {
                    let value = if let Some(value) = attached {
                        value
                    } else {
                        i += 1;
                        argv.get(i)?.as_literal()?
                    };
                    if value.is_empty() {
                        return None;
                    }
                    if canonical_long_option(name) == Some("--file")
                        && archive.replace(value).is_some()
                    {
                        return None;
                    }
                }
                _ => return None,
            }
        } else if text.starts_with('-') && text != "-" || i == 1 {
            let dashed = text.starts_with('-');
            let letters = text.strip_prefix('-').unwrap_or(text);
            for (offset, letter) in letters.char_indices() {
                match letter {
                    'c' | 'x' => {
                        if mode
                            .replace(if letter == 'c' {
                                TarMode::Create
                            } else {
                                TarMode::Extract
                            })
                            .is_some()
                        {
                            return None;
                        }
                    }
                    'O' => to_stdout = true,
                    'v' => {}
                    'z' | 'j' | 'J' | 'Z' => compression += 1,
                    'f' | 'C' => {
                        let suffix = &letters[offset + 1..];
                        let value = if dashed && !suffix.is_empty() {
                            suffix
                        } else {
                            i += 1;
                            argv.get(i)?.as_literal()?
                        };
                        if value.is_empty() || letter == 'f' && archive.replace(value).is_some() {
                            return None;
                        }
                        if dashed {
                            break;
                        }
                    }
                    _ => return None,
                }
            }
        } else {
            operands += 1;
        }
        i += 1;
    }
    if compression > 1 {
        return None;
    }
    match (mode, to_stdout, archive.or(default_archive), operands) {
        (Some(TarMode::Create), false, Some("-"), 1..) => Some(AuditedBinding::CreateStdout),
        (Some(TarMode::Create), false, Some(archive), 1..)
            if local_archive(archive, force_local)
                || (!force_local && remote_archive_host(archive).is_some()) =>
        {
            Some(AuditedBinding::CreateArchiveEndpoint)
        }
        (Some(TarMode::Extract), true, Some("-"), 1..) => Some(AuditedBinding::ExtractStdoutStdin),
        (Some(TarMode::Extract), true, Some(archive), 1..)
            if local_archive(archive, force_local) =>
        {
            Some(AuditedBinding::ExtractStdoutFile)
        }
        (Some(TarMode::Extract), true, None, 1..) => Some(AuditedBinding::ExtractStdoutUnknown),
        _ => None,
    }
}

fn tar_value_stage(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    audited: Option<AuditedBinding>,
    assurance: CausalAssurance,
    sources: &[u32],
    archive: Option<u32>,
) {
    let transform = matches!(
        audited,
        Some(
            AuditedBinding::ExtractStdoutFile
                | AuditedBinding::ExtractStdoutStdin
                | AuditedBinding::ExtractStdoutUnknown
        )
    )
    .then(|| {
        builder.effect(effinterp_proto::Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: effinterp_proto::Operation::new("process.stream_transform"),
            resource: crate::models::common::code_execution_resource(ctx),
            attributes: std::collections::BTreeMap::from([
                (
                    "transform".into(),
                    effinterp_proto::AttrValue::String("extract".into()),
                ),
                (
                    "format".into(),
                    effinterp_proto::AttrValue::String("tar".into()),
                ),
                (
                    "selection".into(),
                    effinterp_proto::AttrValue::String("archive_member".into()),
                ),
            ]),
            modality: effinterp_proto::Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: vec![model_node],
        })
    })
    .flatten();
    let bindings = match audited {
        Some(AuditedBinding::CreateStdout) => sources
            .iter()
            .map(|source| PortBinding {
                assurance,
                from: BindEnd::Effect(*source),
                to: BindEnd::Port(Port::Stdout),
            })
            .collect(),
        Some(AuditedBinding::CreateArchiveEndpoint) => archive
            .into_iter()
            .flat_map(|archive| {
                sources.iter().map(move |source| PortBinding {
                    assurance,
                    from: BindEnd::Effect(*source),
                    to: BindEnd::Effect(archive),
                })
            })
            .collect(),
        Some(AuditedBinding::ExtractStdoutFile) => archive
            .into_iter()
            .zip(transform)
            .flat_map(|(archive, transform)| {
                [
                    PortBinding {
                        assurance,
                        from: BindEnd::Effect(archive),
                        to: BindEnd::Effect(transform),
                    },
                    PortBinding {
                        assurance,
                        from: BindEnd::Effect(transform),
                        to: BindEnd::Port(Port::Stdout),
                    },
                ]
            })
            .collect(),
        Some(AuditedBinding::ExtractStdoutStdin) => transform
            .into_iter()
            .flat_map(|transform| {
                [
                    PortBinding {
                        assurance,
                        from: BindEnd::Port(Port::Stdin),
                        to: BindEnd::Effect(transform),
                    },
                    PortBinding {
                        assurance,
                        from: BindEnd::Effect(transform),
                        to: BindEnd::Port(Port::Stdout),
                    },
                ]
            })
            .collect(),
        Some(AuditedBinding::ExtractStdoutUnknown) => transform
            .into_iter()
            .map(|transform| PortBinding {
                assurance,
                from: BindEnd::Effect(transform),
                to: BindEnd::Port(Port::Stdout),
            })
            .collect(),
        None => Vec::new(),
    };
    if bindings.is_empty() {
        return;
    }
    let mut effects = sources.to_vec();
    effects.extend(archive);
    effects.extend(transform);
    builder.flow_stage(FlowStage {
        execution: Some(builder.current_execution()),
        effects,
        bindings,
        provenance: vec![model_node],
    });
}

impl CommandModel for Tar {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        match self.0 {
            TarDialect::Gnu => "gnu/tar@v1",
            TarDialect::Bsd => "libarchive/bsdtar@v1",
        }
    }

    fn command_names(&self) -> &'static [&'static str] {
        match self.0 {
            TarDialect::Gnu => &["tar"],
            TarDialect::Bsd => &["bsdtar"],
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut mode: Option<TarMode> = None;
        let mut to_stdout = false;
        let mut archive: Option<(u32, Word)> = None;
        let mut directory: Option<(u32, Word)> = None;
        let mut operands = Vec::new();
        let mut member_cwd = ctx.cwd_resource();
        let mut member_lists: Vec<(u32, Word)> = Vec::new();
        // Pattern files tar reads before it selects members.
        let mut exclude_lists: Vec<(u32, Word)> = Vec::new();
        // `--exclude` patterns, which drop matching members and their subtrees.
        let mut excludes: Vec<Word> = Vec::new();
        // Since GNU tar 1.29 exclusions are positional when creating: one
        // after a member name has no effect on it. Only those before every
        // member are known to apply to all of them.
        let mut leading_excludes: Vec<Word> = Vec::new();
        let bsd = self.0 == TarDialect::Bsd;
        let mut end_of_options = false;
        let mut force_local = bsd;
        let mut recursion = true;
        // GNU `--remove-files` deletes each member after archiving it.
        let mut remove_files = false;
        // Options that change where a named member lands on extraction.
        let mut renames_members = false;
        let mut absolute_names = false;
        let mut unknown: Vec<(u32, String)> = Vec::new();
        let mut spawns: Vec<String> = Vec::new();
        // Options whose value tar runs as a shell command line.
        let mut spawned_commands = std::collections::BTreeMap::new();
        // Every `--checkpoint-action=exec=` command runs, not only the last.
        let mut checkpoint_commands = Vec::new();
        let mut to_command = None;
        let mut rmt_command = None;
        let mut rsh_command = None;
        let mut source_effects = Vec::new();
        let mut archive_effect = None;
        // Whether an effect was stated for a member exclusions may still drop.
        let mut narrowed_effect = false;
        let mut binding_shape_known = true;
        // GNU `-h` and bsdtar `-L`/`-h` follow every link; bsdtar `-H` follows
        // only links named on the command line. Otherwise tar archives a link
        // as the link.
        let mut dereference = false;
        let mut follow_operands = false;
        // bsdtar uses BSD getopt: ordinary option parsing stops at the first
        // operand. After it, only positional directives (`-C dir`) are options.
        let mut seen_operand = false;

        let tar_options = if bsd {
            None
        } else {
            tar_environment_read(builder, ctx, model_node, "TAR_OPTIONS");
            ctx.environment_value("TAR_OPTIONS")
        };
        let prefixed = tar_options.as_ref().and_then(tar_option_words);
        let tar_options_empty = ctx
            .nest
            .current_environment_unsets()
            .contains("TAR_OPTIONS")
            || tar_options.is_none()
            || prefixed.as_ref().is_some_and(Vec::is_empty);
        // GNU tar parses the TAR_OPTIONS words ahead of the command line, so
        // argv wins a conflict.
        // A branch union contributes every possible literal option: omitting an
        // option in one arm does not erase the remote archive selected by another.
        if tar_options.is_some() && prefixed.is_none() {
            unknown.push((
                0,
                "TAR_OPTIONS is present or unresolved; effective tar options are unmodeled".into(),
            ));
        }
        let prefixed = prefixed.unwrap_or_default();
        // Words carry the argv position that provenance is attributed to;
        // TAR_OPTIONS words are attributed to the command itself.
        let mut args: Vec<(u32, Word)> = prefixed.into_iter().map(|word| (0, word)).collect();
        args.extend(
            ctx.argv
                .iter()
                .enumerate()
                .skip(1)
                .map(|(index, word)| (index as u32, word.clone())),
        );

        // bsdtar's `-s` and `-W` take values; `-H` and `-L` follow symlinks.
        let benign = if bsd {
            "vzjJZahpSkmoOwPUHL"
        } else {
            "vzjJZahpsSkmoOwWPU0123456789"
        };
        let mut i = 0;
        while i < args.len() {
            let (index, word) = args[i].clone();
            let word = &word;
            if end_of_options {
                operands.push((index, word.clone(), member_cwd.clone(), recursion));
                seen_operand = true;
                i += 1;
                continue;
            }
            // Past the first operand bsdtar reads a dashed word as a member,
            // e.g. a file literally named `-h` or `--directory=x`, keeping only
            // the positional `-C DIR` / `-CDIR` directive. GNU tar permutes
            // options and keeps parsing them, so this only applies to bsdtar.
            if bsd && seen_operand && word.as_literal().is_some() {
                let head = word.literal_prefix();
                let positional = head == "-C" || (head.starts_with("-C") && head.len() > 2);
                if head.starts_with('-') && head != "-" && !positional {
                    operands.push((index, word.clone(), member_cwd.clone(), recursion));
                    seen_operand = true;
                    i += 1;
                    continue;
                }
            }
            if let Some(prefix) = ["--file=", "--directory="]
                .into_iter()
                .find(|prefix| word.literal_prefix().starts_with(prefix))
            {
                let value = super::args::strip_literal_prefix(word, prefix.len());
                if prefix == "--file=" {
                    archive = Some((index, value));
                } else {
                    member_cwd = Some(resolve_fs_word_with_cwd(&value, member_cwd));
                    directory = Some((index, value));
                }
                i += 1;
                continue;
            }
            let text = word.as_literal().or_else(|| {
                let prefix = word.literal_prefix();
                (prefix.starts_with('-') && prefix.len() > 1).then_some(prefix)
            });
            if word.as_literal().is_none() {
                let argument = super::common::arg_node(builder, ctx, index);
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: crate::builder::KNOWN_DOMAINS
                        .iter()
                        .map(|d| Domain::new(*d))
                        .collect(),
                    provenance: vec![argument, model_node],
                    limit: None,
                    detail: Some(
                        "symbolic tar operand may select options or executable callbacks".into(),
                    ),
                });
            }
            let is_first = i == 0;
            match text {
                Some(t)
                    if (t.starts_with('-') && t.len() > 1 && !t.starts_with("--"))
                        || (is_first && !t.starts_with('-')) =>
                {
                    // Mode cluster, dashed or old-style.
                    let dashed = t.starts_with('-');
                    let letters = t.strip_prefix('-').unwrap_or(t);
                    let mut ok = true;
                    let mut values = Vec::new();
                    for (offset, c) in letters.char_indices() {
                        match c {
                            'c' => mode = Some(TarMode::Create),
                            'x' => mode = Some(TarMode::Extract),
                            't' => mode = Some(TarMode::List),
                            'O' => to_stdout = true,
                            'r' | 'u' | 'A' => mode = Some(TarMode::Create),
                            'F' if bsd => ok = false,
                            // bsdtar's link-following flags are last-wins: `-H`
                            // follows only command-line links, `-L`/`-h` follow
                            // every link, and whichever comes last decides.
                            'H' if bsd => {
                                follow_operands = true;
                                dereference = false;
                            }
                            'L' if bsd => {
                                dereference = true;
                                follow_operands = false;
                            }
                            'h' => {
                                dereference = true;
                                follow_operands = false;
                            }
                            'P' => absolute_names = true,
                            // `-H` names the archive format, `-T` a member list
                            // and `-X` an exclude-pattern file.
                            'f' | 'C' | 'I' | 'F' | 'H' | 'T' | 'X' => {
                                if matches!(c, 'I' | 'F') && !bsd {
                                    binding_shape_known = false;
                                }
                                let suffix = &letters[offset + c.len_utf8()..];
                                values.push((
                                    c,
                                    (dashed && (!suffix.is_empty() || word.as_literal().is_none()))
                                        .then(|| {
                                            super::args::strip_literal_prefix(
                                                word,
                                                1 + offset + c.len_utf8(),
                                            )
                                        }),
                                ));
                                if dashed {
                                    break;
                                }
                            }
                            'z' | 'j' | 'J' | 'Z' | 'a' => {}
                            c if benign.contains(c) => {}
                            _ => ok = false,
                        }
                    }
                    if !ok {
                        binding_shape_known = false;
                        unknown.push((index, t.to_string()));
                    } else {
                        for (option, attached) in values {
                            let (value_index, value) = if let Some(value) = attached {
                                (index, value)
                            } else if i + 1 < args.len() {
                                i += 1;
                                args[i].clone()
                            } else {
                                continue;
                            };
                            match option {
                                'f' => archive = Some((value_index, value)),
                                'C' => {
                                    member_cwd = Some(resolve_fs_word_with_cwd(&value, member_cwd));
                                    directory = Some((value_index, value));
                                }
                                'I' | 'F' if !bsd => {
                                    spawned_commands.insert(option, (value_index, value));
                                }
                                'T' | 'I' => member_lists.push((value_index, value)),
                                'X' => exclude_lists.push((value_index, value)),
                                'H' => {}
                                _ => unreachable!(),
                            }
                        }
                    }
                }
                Some(t) if t.starts_with("--") => {
                    let (name, attached) = t.split_once('=').map_or((t, None), |(name, _)| {
                        (
                            name,
                            Some(super::args::strip_literal_prefix(word, name.len() + 1)),
                        )
                    });
                    // Detached option values are taken from the next word.
                    let take_value = |i: &mut usize| match attached.clone() {
                        Some(value) => Some((index, value)),
                        None if *i + 1 < args.len() => {
                            *i += 1;
                            Some(args[*i].clone())
                        }
                        None => None,
                    };
                    let option = match canonical_long_option(name).unwrap_or(name) {
                        "--checkpoint"
                        | "--checkpoint-action"
                        | "--info-script"
                        | "--new-volume-script"
                        | "--rmt-command"
                        | "--rsh-command"
                        | "--to-command"
                        | "--force-local"
                        | "--add-file"
                        | "--remove-files"
                            if bsd =>
                        {
                            "unrecognized"
                        }
                        option => option,
                    };
                    match option {
                        "--" => end_of_options = true,
                        // Appending, updating and concatenating all encode the
                        // named inputs into the archive, as `-r`, `-u` and `-A` do.
                        "--create" | "--append" | "--update" | "--concatenate" | "--catenate" => {
                            mode = Some(TarMode::Create)
                        }
                        "--extract" | "--get" => mode = Some(TarMode::Extract),
                        "--list" => mode = Some(TarMode::List),
                        "--to-stdout" => to_stdout = true,
                        "--recursion" => recursion = true,
                        "--no-recursion" => recursion = false,
                        "--remove-files" => remove_files = true,
                        "--force-local" => force_local = true,
                        // `--add-file` names one member, even one spelled like
                        // an option.
                        "--add-file" => {
                            if let Some((index, member)) = take_value(&mut i) {
                                operands.push((index, member, member_cwd.clone(), recursion));
                            }
                        }
                        "--file" => archive = take_value(&mut i),
                        "--directory" => {
                            directory = take_value(&mut i);
                            if let Some((_, value)) = &directory {
                                member_cwd = Some(resolve_fs_word_with_cwd(value, member_cwd));
                            }
                        }
                        "--files-from" => {
                            if let Some(list) = take_value(&mut i) {
                                member_lists.push(list);
                            }
                        }
                        // The optional interval is attached only; without it
                        // tar still fires checkpoint actions every 10 records.
                        "--checkpoint" => {}
                        "--checkpoint-action" => {
                            binding_shape_known = false;
                            match take_value(&mut i) {
                                Some((index, action))
                                    if action.literal_prefix().starts_with("exec=") =>
                                {
                                    checkpoint_commands.push((
                                        index,
                                        super::args::strip_literal_prefix(&action, "exec=".len()),
                                    ));
                                }
                                // The other actions print, sleep or signal.
                                Some((_, action)) if action.as_literal().is_some() => {}
                                _ => spawns.push(name.to_string()),
                            }
                        }
                        "--use-compress-program" | "--info-script" | "--new-volume-script" => {
                            binding_shape_known = false;
                            if let Some(command) = take_value(&mut i) {
                                let key = if canonical_long_option(name).unwrap_or(name)
                                    == "--use-compress-program"
                                {
                                    'I'
                                } else {
                                    'F'
                                };
                                spawned_commands.insert(key, command);
                            }
                        }
                        "--to-command" => {
                            binding_shape_known = false;
                            to_command = take_value(&mut i);
                        }
                        "--rmt-command" => rmt_command = take_value(&mut i),
                        "--rsh-command" => rsh_command = take_value(&mut i),
                        "--gzip" | "--bzip2" | "--xz" | "--zstd" => {}
                        "--verbose"
                        | "--preserve-permissions"
                        | "--same-owner"
                        | "--no-same-owner"
                        | "--overwrite"
                        | "--keep-old-files" => {}
                        "--absolute-names" => absolute_names = true,
                        "--dereference" => {
                            dereference = true;
                            follow_operands = false;
                        }
                        "--exclude-from" => {
                            if let Some(list) = take_value(&mut i) {
                                exclude_lists.push(list);
                            }
                        }
                        "--strip-components" => {
                            renames_members = true;
                            take_value(&mut i);
                        }
                        "--exclude" => {
                            if let Some((_, pattern)) = take_value(&mut i) {
                                if operands.is_empty() {
                                    leading_excludes.push(pattern.clone());
                                }
                                excludes.push(pattern);
                            }
                        }
                        "--label" => {
                            take_value(&mut i);
                        }
                        _ => {
                            binding_shape_known = false;
                            unknown.push((index, t.to_string()));
                        }
                    }
                }
                _ => {
                    operands.push((index, word.clone(), member_cwd.clone(), recursion));
                    seen_operand = true;
                }
            }
            i += 1;
        }

        for (index, list) in &exclude_lists {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                list,
                "filesystem.read",
                program_input_attrs(),
            );
        }
        // Without `--file`, GNU tar takes the archive from TAPE before falling
        // back to a compiled-in default device.
        if archive.is_none() {
            tar_environment_read(builder, ctx, model_node, "TAPE");
            match ctx.environment_value("TAPE") {
                Some(ResourceExpr::Literal { value }) if !value.is_empty() => {
                    archive = Some((0, Word::literal(value)));
                }
                _ => unknown.push((
                    0,
                    "tar archive selected by TAPE or a compiled default is unmodeled".into(),
                )),
            }
        }
        let stdio_archive = archive
            .as_ref()
            .is_some_and(|(_, w)| w.as_literal() == Some("-"));
        // `--force-local` makes a colon-bearing archive name a local file.
        let remote_host = (!force_local)
            .then(|| {
                archive
                    .as_ref()
                    .and_then(|(_, archive)| archive.as_literal())
                    .and_then(remote_archive_host)
                    .map(str::to_string)
            })
            .flatten();
        let unsupported_archive = remote_host.is_none()
            && archive.as_ref().is_some_and(|(_, archive)| {
                archive
                    .as_literal()
                    .is_some_and(|archive| !local_archive(archive, force_local) && archive != "-")
            });
        if unsupported_archive {
            unknown.push((
                archive.as_ref().unwrap().0,
                "remote or empty archive is unmodeled".into(),
            ));
        }

        // Suppressing an observed symlink's content read is only sound when
        // every effective option is understood: an unrecoverable TAR_OPTIONS
        // value or a symbolic argv word could carry a dereference flag (`-h`,
        // `-L`, `--dereference`) we never saw, so keep the conservative read
        // and its flow in that case.
        let options_understood =
            unknown.is_empty() && args.iter().all(|(_, word)| word.as_literal().is_some());
        // A member glob cannot spell a dereference flag, so it leaves how
        // tar stores links known.
        let link_handling_understood = unknown.is_empty()
            && args
                .iter()
                .all(|(_, word)| word.as_literal().is_some() || member_glob(word));

        // GNU tar's default exclusion matching proves a member is dropped only
        // over a literal command line whose every option was read: an unread or
        // symbolic option, such as `--anchored`, `--no-wildcards` or
        // `--ignore-case`, may change how patterns match, and bsdtar's matching
        // is not modeled.
        let exclusion_proofs = !bsd && options_understood;
        let excluded = exclusion_proofs
            .then(|| excluded_names(leading_excludes.iter().filter_map(Word::as_literal)))
            .flatten();
        match mode {
            // Creating an archive reads the selected inputs and may write a
            // local archive. The encoded bytes are not a content-preserving copy.
            Some(TarMode::Create) => {
                if let Some((index, archive)) = &archive {
                    if let Some(host) = &remote_host {
                        archive_effect = arg_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            "network.upload",
                            remote_archive_endpoint(host),
                            Default::default(),
                        );
                    } else if !stdio_archive && !unsupported_archive {
                        archive_effect = operand_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            archive,
                            "filesystem.write",
                            program_output_attrs(),
                        );
                    }
                }
                // A member list names archive members this analysis cannot read,
                // so the archive gains one unresolved filesystem source.
                for (index, list) in &member_lists {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        list,
                        "filesystem.read",
                        program_input_attrs(),
                    );
                    if let Some(effect) = arg_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        "filesystem.read",
                        unresolved_resource("filesystem"),
                        {
                            let mut attributes = program_input_attrs();
                            attributes.insert(
                                "recursive".into(),
                                effinterp_proto::AttrValue::Bool(recursion),
                            );
                            attributes
                        },
                    ) {
                        source_effects.push(effect);
                    }
                    if remove_files {
                        arg_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            "filesystem.delete",
                            unresolved_resource("filesystem"),
                            removal_attrs(recursion),
                        );
                    }
                    if let Some(effect) = fs_arg_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        list,
                        "filesystem.read",
                        member_cwd
                            .clone()
                            .unwrap_or(ResourceExpr::Parameter { name: "cwd".into() }),
                        {
                            let mut attributes = program_input_attrs();
                            attributes.insert(
                                "recursive".into(),
                                effinterp_proto::AttrValue::Bool(recursion),
                            );
                            attributes
                        },
                    ) {
                        source_effects.push(effect);
                    }
                }
                for (index, operand, cwd, recursive) in &operands {
                    let resource = resolve_fs_word_with_cwd(operand, cwd.clone());
                    let name = operand.as_literal().or(match &resource {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } => Some(path.as_str()),
                        _ => None,
                    });
                    // The member itself goes, a link as the link: removal
                    // never follows it. An excluded member is never added, so
                    // never removed.
                    if remove_files
                        && !(exclusion_proofs
                            && tar_member_excluded(&leading_excludes, name) == Some(true))
                    {
                        narrowed_effect = true;
                        fs_arg_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            operand,
                            "filesystem.delete",
                            resource.clone(),
                            removal_attrs(*recursive),
                        );
                    }
                    // A link archived as the link stores only the name it
                    // points at; tar reads nothing through it. A trailing
                    // slash makes the lookup follow it.
                    if options_understood
                        && !dereference
                        && !follow_operands
                        && operand
                            .as_literal()
                            .is_some_and(|text| !text.ends_with('/'))
                        && let ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } = &resource
                        && super::find::find_observe(builder, path, model_node)
                            .is_some_and(|fact| fact.kind == effinterp_proto::PathKind::Symlink)
                    {
                        continue;
                    }
                    if let Some(effect) = fs_arg_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        operand,
                        "filesystem.read",
                        resource,
                        {
                            let mut attributes = program_input_attrs();
                            attributes.insert(
                                "recursive".into(),
                                effinterp_proto::AttrValue::Bool(*recursive),
                            );
                            if let Some(excluded) = excluded.clone().filter(|_| *recursive) {
                                attributes.extend(excluded);
                            }
                            // The traversal reads what the links below the
                            // member name, so the listing follows them too.
                            // Without a dereference flag tar stores each link
                            // as the link. bsdtar -H follows only the member's
                            // own link, and an unread option might follow
                            // them, so neither is stated.
                            if dereference {
                                attributes.insert(
                                    "follow_links".into(),
                                    effinterp_proto::AttrValue::Bool(true),
                                );
                            } else if link_handling_understood && !follow_operands {
                                attributes.insert(
                                    "follow_links".into(),
                                    effinterp_proto::AttrValue::Bool(false),
                                );
                            }
                            attributes
                        },
                    ) {
                        source_effects.push(effect);
                    }
                }
            }
            // Extraction reads the archive and writes the bounded destination
            // scope. Unknown members stay inside that scope; no concrete child
            // path is invented for them.
            Some(TarMode::Extract) => {
                if let Some((index, archive)) = &archive {
                    if let Some(host) = &remote_host {
                        archive_effect = arg_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            "network.download",
                            remote_archive_endpoint(host),
                            Default::default(),
                        );
                    } else if !stdio_archive && !unsupported_archive {
                        archive_effect = operand_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            archive,
                            "filesystem.read",
                            Default::default(),
                        );
                    }
                }
                if !to_stdout && to_command.is_none() {
                    let (target_index, target_word) =
                        directory.clone().unwrap_or_else(|| (0, Word::literal(".")));
                    let target = extraction_target(Some(&target_word), ctx.cwd_resource());
                    let mut writes = Vec::new();
                    if ctx.tracks_host_context_environment() {
                        writes.extend(fs_arg_effect(
                            builder,
                            ctx,
                            model_node,
                            target_index,
                            &target_word,
                            "filesystem.write",
                            target,
                            {
                                let mut attributes = program_output_attrs();
                                attributes.insert(
                                    "recursive".into(),
                                    effinterp_proto::AttrValue::Bool(true),
                                );
                                attributes
                            },
                        ));
                    } else {
                        writes.extend(arg_effect(
                            builder,
                            ctx,
                            model_node,
                            0,
                            "filesystem.write",
                            target,
                            {
                                let mut attributes = program_output_attrs();
                                attributes.insert(
                                    "recursive".into(),
                                    effinterp_proto::AttrValue::Bool(true),
                                );
                                attributes
                            },
                        ));
                    }
                    if unknown.is_empty() && !renames_members {
                        let members = named_member_writes(
                            builder,
                            ctx,
                            model_node,
                            &operands,
                            absolute_names,
                            if exclusion_proofs { &excludes } else { &[] },
                        );
                        narrowed_effect |= !members.is_empty();
                        writes.extend(members);
                    }
                    // The extracted files are decoded from the archive's
                    // bytes: a named local or remote archive, or standard
                    // input for `-f -`. Without `-f` the archive is TAPE or a
                    // compiled default, which is standard input in the usual
                    // builds, so it may be too; that choice keeps its boundary.
                    let archive_end = match (archive_effect, &archive) {
                        (Some(read), _) => Some(BindEnd::Effect(read)),
                        (None, None) => Some(BindEnd::Port(Port::Stdin)),
                        (None, Some(_)) => stdio_archive.then_some(BindEnd::Port(Port::Stdin)),
                    };
                    if let Some(from) = archive_end.filter(|_| !writes.is_empty()) {
                        builder.flow_stage(FlowStage {
                            execution: Some(builder.current_execution()),
                            effects: archive_effect
                                .into_iter()
                                .chain(writes.iter().copied())
                                .collect(),
                            bindings: writes
                                .iter()
                                .map(|write| PortBinding {
                                    assurance: CausalAssurance::Conservative,
                                    from: from.clone(),
                                    to: BindEnd::Effect(*write),
                                })
                                .collect(),
                            provenance: vec![model_node],
                        });
                    }
                }
            }
            Some(TarMode::List) => {
                if let Some((index, archive)) = &archive {
                    if let Some(host) = &remote_host {
                        arg_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            "network.download",
                            remote_archive_endpoint(host),
                            Default::default(),
                        );
                    } else if !stdio_archive && !unsupported_archive {
                        operand_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            archive,
                            "filesystem.read",
                            Default::default(),
                        );
                    }
                }
            }
            None => unknown.push((0, "<no mode>".to_string())),
        }

        let possible = binding_shape_known.then(|| match (mode, to_stdout, archive.as_ref()) {
            (Some(TarMode::Create), false, Some((_, archive)))
                if archive.as_literal() == Some("-") && !source_effects.is_empty() =>
            {
                Some(AuditedBinding::CreateStdout)
            }
            // Creating an archive encodes the selected members into whatever
            // `-f` names, whether or not the name resolves statically.
            (Some(TarMode::Create), false, Some(_))
                if !stdio_archive && !source_effects.is_empty() && archive_effect.is_some() =>
            {
                Some(AuditedBinding::CreateArchiveEndpoint)
            }
            (Some(TarMode::Extract), true, Some((_, archive)))
                if archive.as_literal() == Some("-") =>
            {
                Some(AuditedBinding::ExtractStdoutStdin)
            }
            (Some(TarMode::Extract), true, Some((_, archive)))
                if archive
                    .as_literal()
                    .is_some_and(|archive| local_archive(archive, force_local))
                    && archive_effect.is_some() =>
            {
                Some(AuditedBinding::ExtractStdoutFile)
            }
            (Some(TarMode::Extract), true, None) if !operands.is_empty() => {
                Some(AuditedBinding::ExtractStdoutUnknown)
            }
            _ => None,
        });
        let possible = possible.flatten();
        let audited = audited_tar_binding(
            &ctx.argv[..1]
                .iter()
                .cloned()
                .chain(args.iter().map(|(_, word)| word.clone()))
                .collect::<Vec<_>>(),
            archive.as_ref().and_then(|(_, word)| word.as_literal()),
        );
        tar_value_stage(
            builder,
            ctx,
            model_node,
            audited.or(possible),
            if (audited.is_some() || !member_lists.is_empty() && possible.is_some())
                && (tar_options_empty || tar_options_exact(tar_options.as_ref()))
                && unknown.is_empty()
                && builder.execution_is_exact(builder.current_execution())
            {
                CausalAssurance::Exact
            } else {
                CausalAssurance::Conservative
            },
            &source_effects,
            archive_effect,
        );

        fs_full_no_spawn(builder);
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
        if !member_lists.is_empty() {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(unresolved_resource("filesystem")),
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("tar member paths are selected by an unobserved file list".into()),
                },
                CoverageLevel::Partial,
            );
        }
        if mode == Some(TarMode::Extract) {
            if let Some(command) = to_command {
                spawned_commands.insert('T', command);
            }
        } else if to_command.is_some() {
            spawns.push("--to-command outside extraction".into());
        }
        for (index, command) in spawned_commands.into_values().chain(checkpoint_commands) {
            let argument = super::common::arg_node(builder, ctx, index);
            code_execution(
                effinterp_proto::RequestAssurance::Conservative,
                builder,
                ctx,
                model_node,
                Some(index),
                "argument",
                Default::default(),
            );
            let Some(source) = command.as_literal() else {
                opaque_source_with_provenance(
                    builder,
                    &[model_node, argument],
                    &["environment", "filesystem", "network", "process"],
                    "tar command option is not statically recoverable",
                );
                continue;
            };
            // tar hands the option value to the shell, arguments included.
            ctx.nest_subject(
                builder,
                effinterp_proto::Subject::Shell {
                    source: source.to_string(),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                &[model_node, argument],
            );
        }
        if let Some(host) = &remote_host {
            if let Some((index, command)) = rsh_command {
                let argument = super::common::arg_node(builder, ctx, index);
                let mut provenance = vec![model_node, argument];
                if let Some((index, _)) = &rmt_command {
                    provenance.push(super::common::arg_node(builder, ctx, *index));
                }
                // rsh-command is a program name; rmt-command is its remote command.
                let mut words = vec![command, Word::literal(host)];
                if let Some(user) = archive
                    .as_ref()
                    .and_then(|(_, value)| value.as_literal())
                    .and_then(|value| value.split_once(':'))
                    .and_then(|(host, _)| host.rsplit_once('@'))
                    .map(|(user, _)| user)
                {
                    words.extend([Word::literal("-l"), Word::literal(user)]);
                }
                words.push(rmt_command.map_or_else(
                    || Word::new(vec![crate::word::WordPart::Unknown]),
                    |(_, command)| command,
                ));
                ctx.nest_exec(builder, &words, ctx.cwd, None, &provenance);
            } else if let Some((index, command)) = rmt_command {
                let argument = super::common::arg_node(builder, ctx, index);
                if let Some(source) = command.as_literal() {
                    nest_remote_shell(
                        builder,
                        ctx,
                        &[model_node, argument],
                        source.to_string(),
                        host.clone(),
                    );
                } else {
                    opaque_source_with_provenance(
                        builder,
                        &[model_node, argument],
                        &["environment", "filesystem", "network", "process"],
                        "tar remote tape command is not statically recoverable",
                    );
                }
            }
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        }
        if !spawns.is_empty() {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNMODELED_SUBPROCESS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: crate::builder::KNOWN_DOMAINS
                    .iter()
                    .map(|d| Domain::new(*d))
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!("tar executes a command via {}", spawns.join(", "))),
            });
        }
        if narrowed_effect && (!excludes.is_empty() || !exclude_lists.is_empty()) {
            builder.boundary(Boundary {
                reason: BoundaryReason::MODEL_COVERAGE,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "tar exclusions may drop members below the ones it removes or extracts".into(),
                ),
            });
        }
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown);
    }
}

fn removal_attrs(recursive: bool) -> crate::models::common::Attrs {
    std::collections::BTreeMap::from([(
        "recursive".into(),
        effinterp_proto::AttrValue::Bool(recursive),
    )])
}

/// Extracting named members writes exactly those names under the extraction
/// directory, or their whole subtree when a member is a directory; tar fails on
/// a name the archive lacks. Tar strips a leading `/` unless `-P` keeps it. A
/// member that may be a pattern (bsdtar, GNU `--wildcards`) or climbs with
/// `..` keeps only the directory-wide write, as does a member an `--exclude`
/// pattern drops. Returns the member writes stated.
fn named_member_writes(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    operands: &[(u32, Word, Option<ResourceExpr>, bool)],
    absolute_names: bool,
    excludes: &[Word],
) -> Vec<u32> {
    let mut stated = Vec::new();
    for (index, member, cwd, _) in operands {
        let Some(text) = member.as_literal() else {
            continue;
        };
        if text.contains(['*', '?', '[', '\\'])
            || text.split('/').any(|part| part == "..")
            || tar_member_excluded(excludes, Some(text)) == Some(true)
        {
            continue;
        }
        let name = if absolute_names && text.starts_with('/') {
            text
        } else {
            text.trim_start_matches('/')
        };
        if name.is_empty() {
            continue;
        }
        stated.extend(fs_arg_effect(
            builder,
            ctx,
            model_node,
            *index,
            member,
            "filesystem.write",
            resolve_fs_word_with_cwd(&Word::literal(name), cwd.clone()),
            {
                let mut attributes = program_output_attrs();
                attributes.insert("recursive".into(), effinterp_proto::AttrValue::Bool(true));
                attributes
            },
        ));
    }
    stated
}

/// Whether GNU tar's default unanchored `--exclude` matching drops the member
/// `name` entirely: `Some(false)` when no pattern does, `None` when a pattern
/// or the name is not literal.
fn tar_member_excluded(excludes: &[Word], name: Option<&str>) -> Option<bool> {
    if excludes.is_empty() {
        return Some(false);
    }
    let name = name?;
    excludes.iter().try_fold(false, |dropped, pattern| {
        Some(dropped || super::find::unanchored_exclusion_drops(pattern.as_literal()?, name)?)
    })
}

/// The attributes of a recursive read that skips the entries literal
/// exclusion `patterns` name: whole names and `name*` prefixes, as the
/// sorted `excluded_names` list. Such a pattern, without `/` or another wildcard, drops every
/// entry below the read's root with a path component it matches, and that
/// entry's subtree, under GNU tar's default unanchored matching and rsync's
/// final-component matching alike. Every pattern passed must be an
/// exclusion that applies to the read, so leaving any other shape out only
/// keeps more entries read; the caller rules out includes, clears and
/// exclusions that apply to only some of the entries. `None` when no pattern
/// is read.
pub(super) fn excluded_names<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
) -> Option<crate::models::common::Attrs> {
    let names = patterns
        .into_iter()
        .filter(|pattern| {
            let name = pattern.strip_suffix('*').unwrap_or(pattern);
            !(name.is_empty() || name.contains(['*', '?', '[', '\\', '/']))
        })
        .collect::<std::collections::BTreeSet<_>>();
    (!names.is_empty()).then(|| {
        crate::models::common::Attrs::from([(
            "excluded_names".into(),
            effinterp_proto::AttrValue::List(
                names
                    .iter()
                    .map(|name| effinterp_proto::AttrValue::String((*name).into()))
                    .collect(),
            ),
        )])
    })
}

/// A glob whose every expansion begins with the same literal non-dash
/// character, so it names members and never an option.
fn member_glob(word: &Word) -> bool {
    word.parts
        .iter()
        .all(|part| matches!(part, WordPart::Literal(_) | WordPart::Glob(_)))
        && match word.parts.first() {
            Some(WordPart::Literal(text)) => !text.is_empty() && !text.starts_with('-'),
            Some(WordPart::Glob(text)) => text.chars().next().is_some_and(|first| {
                first.is_ascii_alphanumeric() || matches!(first, '.' | '/' | '_')
            }),
            _ => false,
        }
}
