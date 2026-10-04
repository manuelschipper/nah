//! Storage destruction uses system identities; device writers retain their filesystem effects.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ProvenanceRef, RequestAssurance, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, basename, scan, scan_operand_flags, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, filesystem_read_stdout_binding, fs_full_no_spawn, operand_effect,
    program_input_attrs, stdin_stdout_binding, system_full, unrecognized_arguments_boundary,
};
use crate::models::fsutils::requested_operand_effect;
use crate::models::{CommandModel, InvocationCtx, ModelCausalBinding};
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

pub(super) fn storage_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Dd),
        Box::new(Mkfs),
        Box::new(Wipefs),
        Box::new(Shred),
        Box::new(Blkdiscard),
        Box::new(Hdparm),
        Box::new(Diskutil),
        Box::new(Badblocks),
        Box::new(LvmRemove),
        Box::new(Lvm),
        Box::new(Zfs),
        Box::new(Btrfs),
        Box::new(PartitionTool),
    ]
}

fn is_device(word: &Word) -> bool {
    matches!(word.parts.first(), Some(WordPart::Literal(text) | WordPart::Glob(text)) if text.starts_with("/dev/"))
}

fn bool_attr(key: &str, on: bool) -> Attrs {
    let mut a = Attrs::new();
    if on {
        a.insert(key.to_string(), AttrValue::Bool(true));
    }
    a
}

/// dd: `if=SRC of=DEST bs=... count=...`. `of=` overwrites (write), `if=`
/// reads. A `/dev/*` target is flagged raw_device — `dd of=/dev/sda` is the
/// canonical disk-destroyer. Without `of=`, or with `of=/dev/stdout`, dd
/// writes what it copies to standard output; without `if=`, it copies
/// standard input.
struct Dd;

/// Whether argv names an `if=` operand, and whether dd's output is its own
/// standard output: no `of=`, or a last `of=` that names the stdout
/// descriptor (`/dev/stdout`, `/dev/fd/1`).
fn dd_operands(argv: &[Word]) -> (bool, bool) {
    let mut input = false;
    let mut to_stdout = true;
    for word in &argv[1..] {
        let Some(WordPart::Literal(text) | WordPart::Glob(text)) = word.parts.first() else {
            continue;
        };
        match text.split_once('=') {
            Some(("if", _)) => input = true,
            Some(("of", value)) => {
                to_stdout = word.parts.len() == 1 && matches!(value, "/dev/stdout" | "/dev/fd/1");
            }
            _ => {}
        }
    }
    (input, to_stdout)
}

impl CommandModel for Dd {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "coreutils/dd@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["dd"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        match dd_operands(argv) {
            (_, false) => Vec::new(),
            (true, true) => vec![filesystem_read_stdout_binding()],
            (false, true) => vec![stdin_stdout_binding()],
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // dd copies its input operand to its output operand; a repeated
        // operand keeps the last one, as dd itself does.
        let mut input = None;
        let mut output = None;
        for (index, word) in ctx.argv.iter().enumerate().skip(1) {
            let Some(first @ (WordPart::Literal(text) | WordPart::Glob(text))) = word.parts.first()
            else {
                continue;
            };
            let Some((key, value)) = text.split_once('=') else {
                continue;
            };
            let mut parts = Vec::new();
            if !value.is_empty() {
                parts.push(
                    if matches!(first, WordPart::Glob(_)) && value.contains(['*', '?', '[']) {
                        WordPart::Glob(value.to_string())
                    } else {
                        WordPart::Literal(value.to_string())
                    },
                );
            }
            parts.extend_from_slice(&word.parts[1..]);
            let target = Word::new(parts);
            match key {
                "of" => {
                    destroy_device(builder, ctx, model_node, index as u32, &target);
                    let mut attributes = bool_attr("raw_device", is_device(&target));
                    attributes.insert("truncate".to_string(), AttrValue::Bool(true));
                    output = operand_effect(
                        builder,
                        ctx,
                        model_node,
                        index as u32,
                        &target,
                        "filesystem.write",
                        attributes,
                    );
                }
                "if" => {
                    input = operand_effect(
                        builder,
                        ctx,
                        model_node,
                        index as u32,
                        &target,
                        "filesystem.read",
                        program_input_attrs(),
                    );
                }
                _ => {}
            }
        }
        if let (Some(input), Some(output)) = (input, output) {
            builder.transfer_binding(TransferBinding::new(input, output));
        }
        fs_full_no_spawn(builder);
    }
}

/// mkfs / mkfs.* / mke2fs / mkswap: reformats the target device, destroying
/// its contents. Each device operand is a write with a `format` attribute.
struct Mkfs;

impl CommandModel for Mkfs {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "util-linux/mkfs@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &[
            "mkfs",
            "mke2fs",
            "mkswap",
            "mkfs.ext2",
            "mkfs.ext3",
            "mkfs.ext4",
            "mkfs.xfs",
            "mkfs.btrfs",
            "mkfs.vfat",
            "mkfs.fat",
            "mkfs.msdos",
            "mkfs.ntfs",
            "mkfs.exfat",
            "mkfs.f2fs",
            "mkfs.reiserfs",
            "mkfs.minix",
            "mkfs.jfs",
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // Operands are the device (and optionally a block count); `-t TYPE`
        // takes a value. Treat every path-like operand as a format target.
        let args = scan_operand_flags(ctx.argv, &OPERAND_FLAGS);
        let program = ctx.argv.first().and_then(Word::as_literal).map(basename);
        // A help request prints the usage and exits: the formatters that
        // document `--help` never reach the device, and the ones that do not
        // reject the option before they do.
        if ctx.argv[1..]
            .iter()
            .any(|word| word.as_literal() == Some("--help"))
        {
            fs_full_no_spawn(builder);
            return;
        }
        // `mkfs` is a wrapper: it runs `mkfs.TYPE`, and without `-t` the type
        // is ext2, so the e2fsprogs option surface is the one it hands the
        // remaining arguments to.
        let filesystem_type = scan(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &["-t", "--type"],
                known_flags: &[],
            },
        )
        .value_of(&["-t", "--type"])
        .and_then(Word::as_literal)
        .map(str::to_string);
        let e2fsprogs = match program {
            Some("mke2fs" | "mkfs.ext2" | "mkfs.ext3" | "mkfs.ext4") => true,
            Some("mkfs") => matches!(
                filesystem_type.as_deref(),
                None | Some("ext2" | "ext3" | "ext4")
            ),
            _ => false,
        };
        // -n means no-write for e2fsprogs; other formatters assign it different
        // meanings (for example a filesystem label), so do not suppress them.
        if e2fsprogs
            && scan(
                ctx.argv,
                &FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &[
                        "-b", "-C", "-d", "-e", "-E", "-g", "-G", "-i", "-I", "-J", "-l", "-L",
                        "-m", "-M", "-N", "-o", "-O", "-r", "-t", "-T", "-U", "-z",
                    ],
                    known_flags: &["-c", "-D", "-F", "-j", "-n", "-q", "-S", "-v", "-V"],
                },
            )
            .has(&["-n"])
        {
            fs_full_no_spawn(builder);
            return;
        }

        for (index, operand) in &args.operands {
            if operand
                .as_literal()
                .is_some_and(|t| t.chars().all(|c| c.is_ascii_digit()))
            {
                continue; // trailing block-count, not a device
            }
            destroy_device(builder, ctx, model_node, *index, operand);
            let mut attributes = bool_attr("raw_device", is_device(operand));
            attributes.insert("format".to_string(), AttrValue::Bool(true));
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.write",
                attributes,
            );
        }
        fs_full_no_spawn(builder);
    }
}

/// wipefs: erases filesystem signatures from a device (write), destroying the
/// ability to mount it.
struct Wipefs;

impl CommandModel for Wipefs {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "util-linux/wipefs@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["wipefs"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let args = scan(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &["-o", "--offset", "-O", "--output", "-t", "--types"],
                known_flags: &[
                    "-a",
                    "--all",
                    "-n",
                    "--no-act",
                    "-b",
                    "--backup",
                    "-f",
                    "--force",
                    "-h",
                    "--help",
                    "-V",
                    "--version",
                    "-i",
                    "--noheadings",
                    "-J",
                    "--json",
                    "-p",
                    "--parsable",
                    "-q",
                    "--quiet",
                ],
            },
        );
        let mut invalid = args.unknown_flags.clone();
        for flag in &args.flags {
            let attached_boolean = flag.name.starts_with("--")
                && flag.name != "--backup"
                && flag.value_index.is_none()
                && ctx.argv[flag.index as usize]
                    .as_literal()
                    .is_some_and(|word| word.contains('='));
            let missing_value = ["-o", "--offset", "-O", "--output", "-t", "--types"]
                .contains(&flag.name)
                && flag.value.is_none();
            if attached_boolean || missing_value {
                invalid.push((flag.index, flag.name.to_owned()));
            }
        }
        if !invalid.is_empty() {
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem", "system"],
                &invalid,
            );
            return;
        }
        if args.has(&["-h", "--help", "-V", "--version"]) {
            fs_full_no_spawn(builder);
            return;
        }
        let all = args.has(&["-a", "--all"]);
        let writes = (all || args.has(&["-o", "--offset"])) && !args.has(&["-n", "--no-act"]);
        for (index, operand) in &args.operands {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                if writes {
                    "filesystem.write"
                } else {
                    "filesystem.read"
                },
                bool_attr("all", all),
            );
            if writes {
                destroy_device(builder, ctx, model_node, *index, operand);
            }
        }
        fs_full_no_spawn(builder);
    }
}

/// shred: overwrites files (write); `-u`/`--remove` also unlinks (delete).
struct Shred;

impl CommandModel for Shred {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "coreutils/shred@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["shred"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // GNU shred's option surface: the pass count, size and random source
        // take values, which are not files to overwrite.
        let args = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: true,
                value_flags: &["-n", "--iterations", "-s", "--size", "--random-source"],
                known_flags: &[
                    "-f",
                    "--force",
                    "-u",
                    "--remove",
                    "-v",
                    "--verbose",
                    "-x",
                    "--exact",
                    "-z",
                    "--zero",
                ],
            },
            true,
        );
        for (index, source) in args.values_of(&["--random-source"]) {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                source,
                "filesystem.read",
                crate::models::common::program_input_attrs(),
            );
        }
        let remove = args.has(&["-u", "--remove"]);
        // shred overwrites every file operand and `-u` removes each one; an
        // option the model does not read may change that.
        let request_assurance = if args.unknown_flags.is_empty() {
            RequestAssurance::Exact
        } else {
            RequestAssurance::Conservative
        };
        for (index, operand) in &args.operands {
            requested_operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.write",
                bool_attr("overwrite", true),
                request_assurance,
            );
            destroy_device(builder, ctx, model_node, *index, operand);
            if remove {
                requested_operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    operand,
                    "filesystem.delete",
                    Attrs::new(),
                    request_assurance,
                );
            }
        }
        fs_full_no_spawn(builder);
    }
}

/// blkdiscard: discards (zeroes) all blocks on a device — destructive write.
struct Blkdiscard;

impl CommandModel for Blkdiscard {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "util-linux/blkdiscard@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["blkdiscard"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let args = scan_operand_flags(ctx.argv, &OPERAND_FLAGS);
        for (index, operand) in &args.operands {
            destroy_device(builder, ctx, model_node, *index, operand);
            let mut attributes = bool_attr("raw_device", is_device(operand));
            attributes.insert("discard".to_string(), AttrValue::Bool(true));
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.write",
                attributes,
            );
        }
        fs_full_no_spawn(builder);
    }
}

/// hdparm: only the ATA Security Erase forms are modeled. The drive erases
/// every user sector of each named device, so each is a whole-device
/// destruction and a raw write.
struct Hdparm;

impl CommandModel for Hdparm {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "hdparm/hdparm@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["hdparm"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const ERASE: [&str; 2] = ["--security-erase", "--security-erase-enhanced"];
        let args = scan(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &[
                    "--security-erase",
                    "--security-erase-enhanced",
                    "--user-master",
                ],
                known_flags: &[],
            },
        );
        if !args.unknown_flags.is_empty() || !args.has(&ERASE) || args.operands.is_empty() {
            storage_unmodeled_subcommand(
                builder,
                model_node,
                "only hdparm security erase is modeled",
            );
            return;
        }
        for (index, operand) in &args.operands {
            destroy_device(builder, ctx, model_node, *index, operand);
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                operand,
                "filesystem.write",
                bool_attr("raw_device", is_device(operand)),
            );
        }
        fs_full_no_spawn(builder);
    }
}

/// diskutil (macOS): the whole-disk erase verbs rewrite the disk named by
/// their last operand; listing and inspection verbs change nothing. Other
/// verbs are an honest boundary.
struct Diskutil;

impl CommandModel for Diskutil {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "diskutil/diskutil@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["diskutil"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let verb = ctx.argv.get(1).and_then(Word::as_literal).unwrap_or("");
        let operands = ctx.argv.len().saturating_sub(2);
        // Operand counts include the device: eraseDisk FORMAT NAME [SCHEME]
        // DEVICE, zeroDisk/randomDisk [COUNT] DEVICE, secureErase [freespace]
        // LEVEL DEVICE.
        let erases = match verb.to_ascii_lowercase().as_str() {
            "list" | "info" | "listfilesystems" => {
                fs_full_no_spawn(builder);
                return;
            }
            "erasedisk" => matches!(operands, 3 | 4),
            "zerodisk" | "randomdisk" => matches!(operands, 1 | 2),
            "secureerase" => matches!(operands, 2 | 3),
            _ => false,
        };
        let index = ctx.argv.len() - 1;
        // diskutil names a disk by its node or its bare BSD name.
        let device = ctx.argv[index].as_literal().and_then(|name| {
            let name = name.strip_prefix("/dev/").unwrap_or(name);
            let number = name.strip_prefix("disk")?;
            (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| format!("/dev/{name}"))
        });
        let (true, Some(device)) = (erases, device) else {
            storage_unmodeled_subcommand(builder, model_node, "unmodeled diskutil verb or disk");
            return;
        };
        let device = Word::literal(&device);
        destroy_device(builder, ctx, model_node, index as u32, &device);
        arg_effect(
            builder,
            ctx,
            model_node,
            index as u32,
            "filesystem.write",
            ctx.resolve_fs_word(&device),
            bool_attr("raw_device", true),
        );
        fs_full_no_spawn(builder);
    }
}

/// badblocks: scans a device for bad blocks. The default test only reads;
/// `-w` writes test patterns over every block, destroying the device's data;
/// `-n` rewrites every block and restores it. Options follow getopt(3) and
/// may appear anywhere before `--`.
struct Badblocks;

impl CommandModel for Badblocks {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "e2fsprogs/badblocks@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["badblocks"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut operands = Vec::new();
        let mut files = Vec::new();
        let (mut write, mut non_destructive) = (false, false);
        let mut options_done = false;
        let mut i = 1;
        while i < ctx.argv.len() {
            let word = &ctx.argv[i];
            let Some(text) = word.as_literal() else {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &["filesystem", "process", "system"],
                    &[(i as u32, word.render_raw())],
                );
                return;
            };
            if options_done || !text.starts_with('-') || text == "-" {
                operands.push((i as u32, word));
            } else if text == "--" {
                options_done = true;
            } else {
                for (offset, option) in text.char_indices().skip(1) {
                    match option {
                        'w' => write = true,
                        'n' => non_destructive = true,
                        's' | 'v' | 'f' | 'B' | 'X' => {}
                        'b' | 'c' | 'd' | 'e' | 'h' | 'i' | 'o' | 'p' | 't' => {
                            let rest = &text[offset + 1..];
                            let value = if rest.is_empty() {
                                i += 1;
                                ctx.argv.get(i).map(|value| (i as u32, value.clone()))
                            } else {
                                Some((i as u32, Word::literal(rest)))
                            };
                            let Some(value) = value else {
                                return;
                            };
                            if matches!(option, 'i' | 'o') {
                                files.push((option, value));
                            }
                            break;
                        }
                        // getopt rejects the option and badblocks exits with usage.
                        _ => return,
                    }
                }
            }
            i += 1;
        }
        // The write modes are exclusive, and the device is required; last and
        // first block are the only other operands.
        let [(index, device), ..] = operands.as_slice() else {
            return;
        };
        if write && non_destructive || operands.len() > 3 {
            return;
        }
        for (option, (index, file)) in &files {
            if file.as_literal() != Some("-") {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    if *option == 'i' {
                        "filesystem.read"
                    } else {
                        "filesystem.write"
                    },
                    Attrs::new(),
                );
            }
        }
        if write {
            destroy_device(builder, ctx, model_node, *index, device);
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                device,
                "filesystem.write",
                bool_attr("raw_device", is_device(device)),
            );
        } else {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                device,
                "filesystem.read",
                Attrs::new(),
            );
        }
        fs_full_no_spawn(builder);
        if non_destructive {
            builder.boundary(Boundary {
                reason: BoundaryReason::PARTIAL_ANALYSIS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "badblocks -n rewrites every block with test patterns and restores the original data"
                        .into(),
                ),
            });
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Partial);
        }
    }
}

/// lvremove / vgremove / pvremove: destroy a logical volume, volume group, or
/// physical volume. Volume names remain verbatim system identities.
struct LvmRemove;

impl CommandModel for LvmRemove {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "lvm/remove@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["lvremove", "vgremove", "pvremove"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        lvm_remove(builder, ctx, model_node);
    }
}

/// The `lvm` dispatcher wrapper: `lvm lvremove vg/data`. Only its destructive
/// remove subcommands are modeled; anything else is an honest boundary.
struct Lvm;

impl CommandModel for Lvm {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "lvm/lvm@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["lvm"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        lvm_remove(builder, ctx, model_node);
    }
}

fn lvm_remove(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    // Scan the full invocation so wrapper flags and absolute argument positions survive dispatch.
    let args = scan(ctx.argv, &LVM_FLAGS);
    let invalid_value = args.flags.iter().any(|flag| {
        LVM_FLAGS.value_flags.contains(&flag.name) && flag.value.is_none()
            || flag.name.starts_with("--")
                && flag.value_index.is_none()
                && ctx.argv[flag.index as usize]
                    .as_literal()
                    .is_some_and(|word| word.contains('='))
    });
    if invalid_value || args.has(&["-h", "--help", "--longhelp", "--version"]) {
        fs_full_no_spawn(builder);
        system_full(builder);
        return;
    }
    let mut operands = args.operands.iter();
    let mut command = basename(ctx.argv[0].as_literal().unwrap_or(""));
    if command == "lvm" {
        match operands.next().and_then(|(_, word)| word.as_literal()) {
            Some(sub @ ("lvremove" | "vgremove" | "pvremove")) => command = sub,
            _ => {
                storage_unmodeled_subcommand(
                    builder,
                    model_node,
                    "lvm without a literal remove subcommand",
                );
                return;
            }
        }
    }
    if !args.unknown_flags.is_empty() {
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "system"],
            &args.unknown_flags,
        );
        return;
    }
    if args.has(&["-S", "--select"])
        || operands
            .clone()
            .any(|(_, word)| word.as_literal().is_some_and(|name| name.starts_with('@')))
    {
        storage_unmodeled_subcommand(
            builder,
            model_node,
            "lvm selection or tag requires host volume metadata",
        );
        return;
    }
    let attributes = bool_attr("dry_run", args.has(&["-t", "--test"]));
    for (index, operand) in operands {
        destroy_volume(
            builder,
            ctx,
            model_node,
            *index,
            operand,
            "lvm",
            command == "pvremove",
            attributes.clone(),
        );
    }
    fs_full_no_spawn(builder);
    system_full(builder);
}

// Value arity from lvremove(8), vgremove(8), pvremove(8), and their common LVM options.
const LVM_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: true,
    value_flags: &[
        "--reportformat",
        "--config",
        "--commandprofile",
        "--profile",
        "--select",
        "-S",
        "--devices",
        "--devicesfile",
        "-A",
        "--autobackup",
        "--driverloaded",
        "--journal",
        "--lockopt",
    ],
    known_flags: &[
        "-h",
        "--help",
        "--longhelp",
        "--version",
        "-t",
        "--test",
        "-f",
        "--force",
        "-d",
        "--debug",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-y",
        "--yes",
        "--nohistory",
        "--noudevsync",
        "--nohints",
        "--nolocking",
    ],
};

/// zpool / zfs: `destroy TARGET` removes a pool or dataset, and `zfs rollback
/// DATASET@SNAP` discards every change the dataset took after that snapshot.
/// Other subcommands stay opaque rather than silently effectless.
struct Zfs;

impl CommandModel for Zfs {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "openzfs/zfs@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["zpool", "zfs"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let tool = basename(ctx.argv[0].as_literal().unwrap_or(""));
        let sub = ctx.argv.get(1).and_then(Word::as_literal);
        let rollback = tool == "zfs" && sub == Some("rollback");
        if sub != Some("destroy") && !rollback {
            storage_unmodeled_subcommand(builder, model_node, "zfs/zpool subcommand");
            return;
        }
        let args = scan_operand_flags(&ctx.argv[1..], &OPERAND_FLAGS);
        if tool == "zpool" && args.has(&["-n"]) {
            storage_unmodeled_subcommand(builder, model_node, "zpool destroy does not support -n");
            return;
        }
        // OpenZFS accepts deferred destruction only for snapshots. A live
        // dataset operand makes the invocation invalid before destruction.
        if tool == "zfs"
            && !rollback
            && args.has(&["-d"])
            && !args.operands.is_empty()
            && args
                .operands
                .iter()
                .all(|(_, operand)| operand.as_literal().is_some())
            && args
                .operands
                .iter()
                .any(|(_, operand)| operand.as_literal().is_some_and(|name| !name.contains('@')))
        {
            system_full(builder);
            fs_full_no_spawn(builder);
            return;
        }
        let deep = args.has(&["-r", "-R"]);
        let mut attributes = Attrs::new();
        if rollback {
            // zfs(8): rollback rewinds the dataset to the snapshot and, with
            // -r/-R, destroys the snapshots newer than it. The dataset is not
            // destroyed, so this is not a recursive removal of its children.
            attributes.insert("mode".into(), AttrValue::String("rollback".into()));
            if deep {
                attributes.insert("newer_snapshots_destroyed".into(), AttrValue::Bool(true));
            }
        } else if deep {
            attributes.insert("recursive".into(), AttrValue::Bool(true));
        }
        if tool == "zfs" && !rollback && args.has(&["-n"]) {
            attributes.insert("dry_run".into(), AttrValue::Bool(true));
        }
        for (index, operand) in &args.operands {
            // Rollback names a snapshot but rewinds the dataset holding it;
            // without that `dataset@snapshot` shape there is nothing to name.
            let mut attributes = attributes.clone();
            let target = if rollback {
                let Some((name, dataset)) = operand.as_literal().and_then(|name| {
                    let (dataset, _) = name.split_once('@')?;
                    (!dataset.is_empty()).then_some((name, dataset))
                }) else {
                    storage_unmodeled_subcommand(
                        builder,
                        model_node,
                        "zfs rollback without a dataset@snapshot operand",
                    );
                    continue;
                };
                // The snapshot rolled back to bounds what the dataset keeps
                // and which newer snapshots -r removes, so it is named too.
                attributes.insert("snapshot".into(), AttrValue::String(name.into()));
                Word::literal(dataset)
            } else {
                (*operand).clone()
            };
            // index is relative to argv[1..]; add 1 for the absolute position.
            destroy_volume(
                builder,
                ctx,
                model_node,
                index + 1,
                &target,
                "zfs",
                false,
                attributes,
            );
        }
        system_full(builder);

        fs_full_no_spawn(builder);
    }
}

/// Partition editors (fdisk/gdisk/parted/sgdisk): sgdisk with operands is
/// scriptable and destructive to the device; the interactive editors don't
/// determine their effect from argv, so they widen to an opaque boundary.
struct PartitionTool;

impl CommandModel for PartitionTool {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "storage/partition@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["sgdisk", "fdisk", "gdisk", "parted", "cfdisk", "sfdisk"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let name = ctx.argv[0].as_literal().unwrap_or("");
        if partition_query(builder, ctx, model_node, basename(name)) {
            return;
        }
        if basename(name) == "sfdisk" {
            let args = scan(
                ctx.argv,
                &FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &[],
                    known_flags: &["--delete", "--no-act", "-n"],
                },
            );
            if args.has(&["--delete"])
                && args.unknown_flags.is_empty()
                && !args.operands.is_empty()
                && args.operands[0].1.as_literal() != Some("")
                && args.operands[1..].iter().all(|(_, word)| {
                    word.as_literal()
                        .and_then(|value| value.parse::<u32>().ok())
                        .is_some_and(|number| number > 0)
                })
                && args.flags.iter().all(|flag| {
                    ctx.argv[flag.index as usize]
                        .as_literal()
                        .is_some_and(|option| !option.contains('='))
                })
            {
                let (index, device) = args.operands[0];
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    device,
                    if args.has(&["--no-act", "-n"]) {
                        "filesystem.read"
                    } else {
                        "filesystem.write"
                    },
                    bool_attr("partition_table", true),
                );
                fs_full_no_spawn(builder);
                return;
            }
            if !args.has(&["--delete"]) {
                sfdisk_script(builder, ctx, model_node);
                return;
            }
            builder.boundary(Boundary {
                reason: BoundaryReason::UNPARSED_PARTITION_OPS,
                class: BoundaryClass::Unsupported,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some(
                    "sfdisk operation is not a literal --delete device [partition ...] invocation"
                        .into(),
                ),
            });
            return;
        }
        let args = scan_operand_flags(ctx.argv, &OPERAND_FLAGS);
        // parted takes its commands after the device. The ones that only report
        // the table or set parted's own display state change nothing on disk, so
        // a command line built from them alone is a query of the device.
        if basename(name) == "parted"
            && let [(device_index, device), commands @ ..] = args.operands.as_slice()
            && !commands.is_empty()
            && parted_reports_only(commands)
        {
            operand_effect(
                builder,
                ctx,
                model_node,
                *device_index,
                device,
                "filesystem.read",
                crate::models::common::program_input_attrs(),
            );
            fs_full_no_spawn(builder);
            return;
        }
        // The device is the operand; the specific partition change is opaque,
        // but writing the device is the modeled effect.
        for (index, operand) in &args.operands {
            if name == "sgdisk" && (args.has(&["-Z", "--zap-all"]) || args.has(&["-o"])) {
                destroy_device(builder, ctx, model_node, *index, operand);
            }
            if is_device(operand) || name == "sgdisk" {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    operand,
                    "filesystem.write",
                    bool_attr("partition_table", true),
                );
            }
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::UNPARSED_PARTITION_OPS,
            class: BoundaryClass::Unsupported,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!("{name} partition changes are not fully modeled")),
        });
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Partial);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    }
}

/// sfdisk without a report mode or `--delete` reads a partition script from
/// its input and writes the table it describes to the device, its first
/// operand. The script is not modeled, so the write keeps the operations
/// boundary; `--no-act` runs everything except the write.
fn sfdisk_script(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let args = scan(
        ctx.argv,
        &FlagSpec {
            allow_abbreviation: true,
            value_flags: &[
                "-N",
                "--partno",
                "-X",
                "--label",
                "-Y",
                "--label-nested",
                "-w",
                "--wipe",
                "-W",
                "--wipe-partitions",
                "-O",
                "--backup-file",
            ],
            known_flags: &[
                "-a",
                "--append",
                "-b",
                "--backup",
                "-f",
                "--force",
                "-q",
                "--quiet",
                "--no-reread",
                "--no-tell-kernel",
                "-n",
                "--no-act",
                "--color",
                "--lock",
            ],
        },
    );
    // Past an option this spec does not know, operand positions are not
    // reliable, so every device operand is taken as the target.
    let devices: Vec<_> = if args.unknown_flags.is_empty() {
        args.operands.first().into_iter().collect()
    } else {
        args.operands
            .iter()
            .filter(|(_, word)| is_device(word))
            .collect()
    };
    if args.has(&["-n", "--no-act"]) && args.unknown_flags.is_empty() {
        for (index, device) in devices {
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                device,
                "filesystem.read",
                crate::models::common::program_input_attrs(),
            );
        }
        fs_full_no_spawn(builder);
        return;
    }
    for (index, device) in devices {
        operand_effect(
            builder,
            ctx,
            model_node,
            *index,
            device,
            "filesystem.write",
            bool_attr("partition_table", true),
        );
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::UNPARSED_PARTITION_OPS,
        class: BoundaryClass::Unsupported,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("filesystem")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("sfdisk partition script is not modeled".into()),
    });
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Partial);
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
}

/// Whether parted's commands after the device only report the table or set
/// parted's own display state, each with the arguments it takes.
fn parted_reports_only(commands: &[(u32, &Word)]) -> bool {
    let mut words = commands
        .iter()
        .map(|(_, word)| word.as_literal())
        .peekable();
    while let Some(command) = words.next() {
        let arguments = match command {
            // `print` takes an optional listing selector or partition number.
            Some("print") => usize::from(words.peek().is_some_and(|argument| {
                argument.is_some_and(|argument| {
                    matches!(argument, "all" | "devices" | "free" | "list")
                        || argument.parse::<u32>().is_ok()
                })
            })),
            Some("unit" | "select") => 1,
            Some("align-check") => 2,
            Some("help" | "quit" | "version") => 0,
            _ => return false,
        };
        for _ in 0..arguments {
            if words.next().is_none() {
                return false;
            }
        }
    }
    true
}

/// The partition tools' report-only modes: listing, printing, verifying or
/// sizing the table reads the device, and `sgdisk --backup` copies the table
/// into a file. Any other option may change the table, so a command line
/// qualifies only when every option belongs to a report mode or a display
/// modifier and at least one mode is selected; everything else keeps the
/// conservative device write.
fn partition_query(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    program: &str,
) -> bool {
    // fdisk's -u, -c and -L take an optional argument attached to the same
    // word (-lu=sectors, -usectors): the rest of the cluster after one is its
    // argument, not more options. A letter that requires a value takes the
    // rest of the cluster itself, which the scan already reads.
    let argv: Vec<Word> = ctx
        .argv
        .iter()
        .map(|word| match word.as_literal() {
            Some(option)
                if program == "fdisk" && option.starts_with('-') && !option.starts_with("--") =>
            {
                let optional = option[1..]
                    .char_indices()
                    .take_while(|(_, letter)| !"bCHoStwW".contains(*letter))
                    .find(|(_, letter)| "ucL".contains(*letter));
                match optional {
                    Some((at, _)) => Word::literal(&option[..at + 2]),
                    None => word.clone(),
                }
            }
            _ => word.clone(),
        })
        .collect();
    // The display modifiers change only how a mode reports.
    let (modes, modifiers, value_flags): (&[&str], &[&str], &[&str]) = match program {
        "fdisk" => (
            &["-l", "--list", "-x", "--list-details", "-s", "--getsz"],
            // DOS compatibility and color only change how the table is shown.
            &[
                "-u",
                "--units",
                "--bytes",
                "-c",
                "--compatibility",
                "-L",
                "--color",
            ],
            // A list mode never writes, so its wipe policy never applies.
            &[
                "-o",
                "--output",
                "-b",
                "--sector-size",
                "-w",
                "--wipe",
                "-W",
                "--wipe-partitions",
            ],
        ),
        "sgdisk" => (
            &[
                "-p", "--print", "-v", "--verify", "-i", "--info", "-b", "--backup",
            ],
            &[],
            &["-i", "--info", "-b", "--backup"],
        ),
        "gdisk" => (&["-l"], &[], &[]),
        // parted lists every device and exits once -l is given, before it
        // reads a device or a command.
        "parted" => (
            &["-l", "--list"],
            &["-s", "--script", "-m", "--machine", "-j", "--json"],
            &[],
        ),
        "sfdisk" => (
            &[
                "-l",
                "--list",
                "-d",
                "--dump",
                "-F",
                "--list-free",
                "-s",
                "--show-size",
                "-V",
                "--verify",
                "-J",
                "--json",
                "-g",
                "--show-geometry",
                // With only the device and partition number (or, for
                // --disk-id, the device) these print the value they would
                // set; the setter form takes one more operand.
                "--part-type",
                "--part-label",
                "--part-uuid",
                "--part-attrs",
                "--disk-id",
            ],
            // A report has nothing to hold back from the device, so
            // --no-act changes nothing either. The rest are settings of the
            // scripting action (the partition to script, the label to create,
            // the wipe and backup policy), which a selected report action
            // never reaches.
            &[
                "-q",
                "--quiet",
                "--color",
                "--lock",
                "-n",
                "--no-act",
                "-a",
                "--append",
                "-b",
                "--backup",
                "-f",
                "--force",
                "--no-reread",
                "--no-tell-kernel",
            ],
            &[
                "-o",
                "--output",
                "-N",
                "--partno",
                "-X",
                "--label",
                "-Y",
                "--label-nested",
                "-w",
                "--wipe",
                "-W",
                "--wipe-partitions",
                "-O",
                "--backup-file",
            ],
        ),
        _ => return false,
    };
    let known_flags: Vec<&str> = modes
        .iter()
        .chain(modifiers)
        .copied()
        .filter(|flag| !value_flags.contains(flag))
        .collect();
    let args = scan_with_value_indices(
        &argv,
        &FlagSpec {
            allow_abbreviation: false,
            value_flags,
            known_flags: &known_flags,
        },
        true,
    );
    if !args.unknown_flags.is_empty()
        // A partly symbolic option word could expand to another option.
        || args.flags.iter().any(|flag| {
            flag.value_index != Some(flag.index)
                && ctx.argv[flag.index as usize].as_literal().is_none()
        })
        || !args.flags.iter().any(|flag| modes.contains(&flag.name))
        || args.flags.iter().any(|flag| {
            value_flags.contains(&flag.name) && flag.value.is_none()
        })
        // An operand that does not start with literal text, such as
        // "$(cat flags)", could expand to another option.
        || args.operands.iter().any(|(index, word)| {
            args.dashdash.is_none_or(|dashdash| *index < dashdash)
                && !matches!(
                    word.parts.first(),
                    Some(WordPart::Literal(text)) if !text.is_empty() && !text.starts_with('-')
                )
        })
    {
        return false;
    }
    let getter = args
        .flags
        .iter()
        .find(|flag| flag.name.starts_with("--part-") || flag.name == "--disk-id")
        .map(|flag| if flag.name == "--disk-id" { 1 } else { 2 });
    if getter.is_some_and(|arity| args.operands.len() != arity) {
        return false;
    }
    // parted -l ignores its operands, and a getter's operands after the
    // device name a partition.
    let operands = if program == "parted" {
        &[][..]
    } else if getter.is_some() {
        &args.operands[..1]
    } else {
        &args.operands[..]
    };
    for (index, operand) in operands {
        operand_effect(
            builder,
            ctx,
            model_node,
            *index,
            operand,
            "filesystem.read",
            crate::models::common::program_input_attrs(),
        );
    }
    // fdisk's -b is the sector size; sgdisk's writes the backup file.
    let backups = if program == "sgdisk" {
        args.values_of(&["-b", "--backup"])
    } else {
        Vec::new()
    };
    for (index, file) in backups {
        operand_effect(
            builder,
            ctx,
            model_node,
            index,
            file,
            "filesystem.write",
            Attrs::new(),
        );
    }
    fs_full_no_spawn(builder);
    true
}

fn storage_unmodeled_subcommand(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNMODELED_SUBCOMMAND,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![
            Domain::new("filesystem"),
            Domain::new("process"),
            Domain::new("system"),
        ],
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.into()),
    });
    for domain in ["filesystem", "process", "system"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
}

fn destroy_device(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    index: u32,
    word: &Word,
) {
    if let Some(device) = word.as_literal().filter(|s| s.starts_with("/dev/")) {
        arg_effect(
            builder,
            ctx,
            node,
            index,
            super::system::STORAGE_DESTROY,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::BlockDevice {
                    device: device.into(),
                },
            },
            bool_attr("whole_device", true),
        );
        system_full(builder);
    }
}

#[allow(clippy::too_many_arguments)]
fn destroy_volume(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    index: u32,
    word: &Word,
    manager: &str,
    physical: bool,
    mut attributes: Attrs,
) {
    if physical
        && !word
            .as_literal()
            .is_some_and(|name| name.starts_with("/dev/"))
    {
        storage_unmodeled_subcommand(
            builder,
            node,
            "physical-volume operand is not a literal /dev/ device path",
        );
        return;
    }
    let resource = match word.as_literal() {
        Some(device) if physical && device.starts_with("/dev/") => {
            attributes.insert(
                "whole_device".into(),
                effinterp_proto::AttrValue::Bool(true),
            );
            ResourceExpr::Concrete {
                identity: ResourceIdentity::BlockDevice {
                    device: device.into(),
                },
            }
        }
        Some(name) => ResourceExpr::Concrete {
            identity: ResourceIdentity::StorageVolume {
                manager: manager.into(),
                name: name.into(),
            },
        },
        None => unresolved_resource("system"),
    };
    arg_effect(
        builder,
        ctx,
        node,
        index,
        super::system::STORAGE_DESTROY,
        resource,
        attributes,
    );
}

struct Btrfs;
impl CommandModel for Btrfs {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "btrfs/subvolume@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["btrfs"]
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        if ctx.argv.get(1).and_then(Word::as_literal) != Some("subvolume")
            || ctx.argv.get(2).and_then(Word::as_literal) != Some("delete")
        {
            storage_unmodeled_subcommand(builder, node, "btrfs subcommand");
            return;
        }
        for (index, word) in scan_operand_flags(&ctx.argv[2..], &OPERAND_FLAGS).operands {
            destroy_volume(
                builder,
                ctx,
                node,
                index + 2,
                word,
                "btrfs",
                false,
                Attrs::new(),
            );
        }
        fs_full_no_spawn(builder);
        system_full(builder);
    }
}

const OPERAND_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[],
    known_flags: &[
        "-a",
        "--all",
        "-u",
        "--remove",
        "-r",
        "-R",
        "-Z",
        "--zap-all",
        "-o",
        "-b",
        "-c",
        "-d",
        "-e",
        "-f",
        "-g",
        "-h",
        "-i",
        "-j",
        "-k",
        "-l",
        "-m",
        "-n",
        "-p",
        "-q",
        "-s",
        "-t",
        "-v",
        "-w",
        "-x",
        "-y",
        "-z",
        "-A",
        "-B",
        "-C",
        "-D",
        "-E",
        "-F",
        "-G",
        "-H",
        "-I",
        "-J",
        "-K",
        "-L",
        "-M",
        "-N",
        "-O",
        "-P",
        "-Q",
        "-S",
        "-T",
        "-U",
        "-V",
        "-W",
        "-X",
        "-Y",
    ],
};
