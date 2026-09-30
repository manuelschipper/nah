//! The Windows command models. `cmd`'s `/c` and `/k` run the rest of the
//! command line, which is analyzed as a nested cmd subject; cmd takes that
//! string from the raw line, so the value may be attached to the switch itself
//! (`/Cdel x`). `certutil` models the URL cache verb, which fetches a URL and
//! writes what it fetched. `xcopy` and `robocopy` read their source and write
//! their destination.

use std::collections::BTreeMap;

use effinterp_proto::{
    BoundaryClass, BoundaryReason, CoverageLevel, Domain, PathPlatform, ProvenanceRef,
    ResourceExpr, Subject, filesystem_path,
};

use crate::TransferBinding;
use crate::builder::PlanBuilder;
use crate::models::common::{
    arg_effect, arg_node, boundary, code_execution, dynamic_source, fs_arg_effect,
    program_output_attrs, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

pub(super) fn cmdexec_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Cmd),
        Box::new(Certutil),
        Box::new(Copier::Xcopy),
        Box::new(Copier::Robocopy),
    ]
}

/// Switches accepted before the command string. `/e`, `/f` and `/v` carry an
/// `:on`/`:off` value; the rest are plain selectors.
const SWITCHES: [&str; 9] = ["a", "u", "q", "d", "s", "e", "f", "v", "t"];

struct Cmd;

impl CommandModel for Cmd {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cmd/cmd@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["cmd", "cmd.exe"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut index = 1;
        while index < ctx.argv.len() {
            let Some(argument) = ctx.argv[index].as_literal() else {
                dynamic_source(builder, model_node, "cmd switch is not a literal argument");
                return;
            };
            let Some(switch) = argument.strip_prefix('/') else {
                dynamic_source(
                    builder,
                    model_node,
                    "cmd operand does not select a command string",
                );
                return;
            };
            let name = switch
                .chars()
                .next()
                .map(|name| name.to_ascii_lowercase())
                .unwrap_or_default();
            if name == 'c' || name == 'k' {
                let attached = &switch[name.len_utf8()..];
                self.command(builder, ctx, model_node, index, attached);
                return;
            }
            let value = switch.split_once(':').map_or(switch, |(name, _)| name);
            if value.len() != 1 || !SWITCHES.contains(&value.to_ascii_lowercase().as_str()) {
                dynamic_source(builder, model_node, "cmd switch is not modeled");
                return;
            }
            index += 1;
        }
        dynamic_source(builder, model_node, "cmd interactive interpreter");
    }
}

impl Cmd {
    /// The command string is the text attached to `/c` plus every remaining
    /// argument; cmd reads it from the raw command line, not from argv.
    fn command(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        index: usize,
        attached: &str,
    ) {
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            Some(index as u32),
            "argument",
            BTreeMap::new(),
        );
        let words = ctx.argv[index + 1..]
            .iter()
            .map(|word| word.as_literal())
            .collect::<Option<Vec<_>>>();
        let Some(words) = words else {
            dynamic_source(
                builder,
                model_node,
                "cmd command string contains a dynamic argument",
            );
            return;
        };
        let source = std::iter::once(attached)
            .filter(|attached| !attached.is_empty())
            .chain(words)
            .collect::<Vec<_>>()
            .join(" ");
        if source.is_empty() {
            return;
        }
        let mut provenance = vec![model_node];
        provenance
            .extend((index..ctx.argv.len()).map(|index| arg_node(builder, ctx, index as u32)));
        ctx.nest_subject(
            builder,
            Subject::Source {
                dialect: None,
                language: "cmd".to_string(),
                source,
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &provenance,
        );
    }
}

/// certutil's URL cache verb. Microsoft documents it as
/// `certutil [options] -URLcache [URL | CRL | * [delete]]` accepting `[-f]
/// [-split]`, where `-f` "forces fetching a specific URL and updating the
/// cache" and `-split` "Split embedded ASN.1 elements, and save to files" —
/// the option that gives the fetched bytes a name on disk. Every other verb,
/// and every cache selector whose entries this invocation does not name,
/// stays unmodeled.
struct Certutil;

/// The options `-URLcache` documents. Any other dashed word may take a value,
/// so the operand roles past it are no longer reliable.
const URLCACHE_OPTIONS: [&str; 2] = ["-f", "-split"];

/// Domains the URL cache verb can reach.
const CERTUTIL_DOMAINS: [&str; 3] = ["filesystem", "network", "process"];

impl CommandModel for Certutil {
    fn domains(&self) -> &'static [&'static str] {
        &CERTUTIL_DOMAINS
    }

    fn id(&self) -> &'static str {
        "windows/certutil@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["certutil", "certutil.exe"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mut verb: Option<usize> = None;
        let mut split = false;
        let mut unknown: Vec<(u32, String)> = Vec::new();
        let mut operands: Vec<(u32, &Word)> = Vec::new();
        for (index, word) in ctx.argv.iter().enumerate().skip(1) {
            match word.as_literal() {
                Some(text) if text.starts_with('-') => {
                    if text.eq_ignore_ascii_case("-urlcache") {
                        verb = Some(index);
                    } else if URLCACHE_OPTIONS
                        .iter()
                        .any(|option| text.eq_ignore_ascii_case(option))
                    {
                        split |= text.eq_ignore_ascii_case("-split");
                    } else {
                        unknown.push((index as u32, text.to_string()));
                    }
                }
                _ => operands.push((index as u32, word)),
            }
        }
        let Some(verb) = verb else {
            boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &CERTUTIL_DOMAINS,
                "certutil verbs other than -URLcache are not modeled",
            );
            return;
        };
        if !unknown.is_empty() {
            unrecognized_arguments_boundary(builder, model_node, &CERTUTIL_DOMAINS, &unknown);
            return;
        }
        // `-URLcache URL FILE` with `-split`: the fetch reaches the URL and
        // the split output lands in the named file. `CRL`, `*`, `delete`, a
        // missing selector and the forms without `-split` all operate on cache
        // entries this invocation does not name.
        let named = operands
            .iter()
            .filter(|(index, _)| *index as usize > verb)
            .collect::<Vec<_>>();
        let [(url_index, url), (file_index, file)] = named.as_slice() else {
            self.unnamed_cache(builder, model_node);
            return;
        };
        let endpoint = url
            .as_literal()
            .filter(|text| !text.eq_ignore_ascii_case("crl") && *text != "*")
            .and_then(super::net::parse_endpoint);
        let deleting = file
            .as_literal()
            .is_some_and(|text| text.eq_ignore_ascii_case("delete"));
        let Some(identity) = endpoint.filter(|_| split && !deleting) else {
            self.unnamed_cache(builder, model_node);
            return;
        };
        let fetched = arg_effect(
            builder,
            ctx,
            model_node,
            *url_index,
            "network.download",
            ResourceExpr::Concrete { identity },
            Default::default(),
        );
        // certutil is a Windows program, so its output operand resolves in the
        // Windows dialect: a drive-rooted name is already absolute.
        let destination = match file.as_literal().filter(|path| !path.is_empty()) {
            Some(path) => filesystem_path(
                path,
                ctx.cwd
                    .map(|cwd| filesystem_path(cwd, None, PathPlatform::Windows)),
                PathPlatform::Windows,
            ),
            None => ctx.resolve_fs_word(file),
        };
        let written = fs_arg_effect(
            builder,
            ctx,
            model_node,
            *file_index,
            file,
            "filesystem.write",
            destination,
            program_output_attrs(),
        );
        if let (Some(fetched), Some(written)) = (fetched, written) {
            builder.transfer_binding(TransferBinding::exact(fetched, written));
        }
        for domain in CERTUTIL_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
    }
}

impl Certutil {
    /// The cache entries this invocation reaches are not named by its
    /// operands, so neither the fetch nor the files it leaves are attributable.
    fn unnamed_cache(&self, builder: &mut PlanBuilder, model_node: ProvenanceRef) {
        boundary(
            builder,
            model_node,
            BoundaryReason::MODEL_COVERAGE,
            BoundaryClass::Unmodeled,
            &CERTUTIL_DOMAINS,
            "certutil -URLcache operates on cache entries this invocation does not name",
        );
    }
}

/// `xcopy SOURCE DESTINATION [/switch...]` and `robocopy SOURCE DESTINATION
/// [FILE...] [/option...]`. Both read the source and write the destination,
/// but which entries land where is decided at run time: xcopy asks whether a
/// destination that does not exist names a file or a directory, and robocopy
/// copies the selected files into its destination directory. Coverage stays
/// Partial for that reason. A switch outside the reviewed set may list, delete,
/// move, log, or change source attributes, so it leaves its own boundary.
enum Copier {
    Xcopy,
    Robocopy,
}

/// Switches that only select or pace what is copied.
const XCOPY_SWITCHES: [&str; 19] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "n", "o", "q", "r", "s", "t", "v", "y",
];
const ROBOCOPY_OPTIONS: [&str; 19] = [
    "s", "e", "z", "b", "zb", "j", "r", "w", "np", "nfl", "ndl", "njh", "njs", "xo", "xn", "xc",
    "mt", "copy", "dcopy",
];

const COPIER_DOMAINS: [&str; 1] = ["filesystem"];

impl CommandModel for Copier {
    fn domains(&self) -> &'static [&'static str] {
        &COPIER_DOMAINS
    }

    fn id(&self) -> &'static str {
        match self {
            Self::Xcopy => "windows/xcopy@v0",
            Self::Robocopy => "windows/robocopy@v0",
        }
    }

    fn command_names(&self) -> &'static [&'static str] {
        match self {
            Self::Xcopy => &["xcopy", "xcopy.exe"],
            Self::Robocopy => &["robocopy", "robocopy.exe"],
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let accepted: &[&str] = match self {
            Self::Xcopy => &XCOPY_SWITCHES,
            Self::Robocopy => &ROBOCOPY_OPTIONS,
        };
        let mut unknown: Vec<(u32, String)> = Vec::new();
        let mut operands: Vec<(u32, &Word)> = Vec::new();
        for (index, word) in ctx.argv.iter().enumerate().skip(1) {
            match word.as_literal().and_then(|text| text.strip_prefix('/')) {
                Some(switch) => {
                    let name = switch.split_once(':').map_or(switch, |(name, _)| name);
                    if !accepted.contains(&name.to_ascii_lowercase().as_str()) {
                        unknown.push((index as u32, format!("/{switch}")));
                    }
                }
                None => operands.push((index as u32, word)),
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &COPIER_DOMAINS, &unknown);
        // robocopy's further operands only narrow which files are copied.
        let [(source_index, source), (target_index, target), ..] = operands.as_slice() else {
            boundary(
                builder,
                model_node,
                BoundaryReason::MISSING_REQUIRED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &COPIER_DOMAINS,
                "copy names no source and destination",
            );
            return;
        };
        let read = fs_arg_effect(
            builder,
            ctx,
            model_node,
            *source_index,
            source,
            "filesystem.read",
            windows_operand(ctx, source),
            Default::default(),
        );
        let written = fs_arg_effect(
            builder,
            ctx,
            model_node,
            *target_index,
            target,
            "filesystem.write",
            windows_operand(ctx, target),
            Default::default(),
        );
        if let (Some(read), Some(written)) = (read, written) {
            builder.transfer_binding(TransferBinding::exact(read, written));
        }
        boundary(
            builder,
            model_node,
            BoundaryReason::MODEL_COVERAGE,
            BoundaryClass::Unmodeled,
            &COPIER_DOMAINS,
            "the entries written under the destination are decided at run time",
        );
    }
}

/// A Windows program's operand resolves in the Windows dialect, so a
/// drive-rooted name is already absolute.
fn windows_operand(ctx: &InvocationCtx, word: &Word) -> ResourceExpr {
    match word.as_literal().filter(|path| !path.is_empty()) {
        Some(path) => filesystem_path(
            path,
            ctx.cwd
                .map(|cwd| filesystem_path(cwd, None, PathPlatform::Windows)),
            PathPlatform::Windows,
        ),
        None => ctx.resolve_fs_word(word),
    }
}
