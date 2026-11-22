//! `$(cat FILE)` captures. A word spelled as a lone quoted `"$(cat FILE)"`,
//! a here-string of one, or a `<(cat FILE)` operand holds FILE's bytes, which
//! the plan knows only as the file and the host writes recorded before the
//! capture. Naming the file reads nothing: a model that runs the capture as
//! code or opens it as a script demands the bytes through
//! `CapturedFile::text` for an argv word, or `CapturedFile::script_text` for
//! a capture the shell made while it opened the command's redirections. The
//! shell recognizes the spelling here (`captured_file_path`), stdin carries a
//! here-string's capture (`StdinValue::captured_file`, re-marked by
//! `stdin_after_assignments`), and the launching shell lends the captured
//! operands of the argv it runs to the model it applies, and to the models
//! its wrappers apply (`CapturedOperands`).
//!
//! Bash expands a command's words, then runs its prefix assignments, then
//! opens its redirections in order. The walk expands the words, then the
//! here-strings and here-documents, then runs the assignments and the
//! command, and expands the other redirection targets last. A capture whose
//! file a write reaches at a point the walk cannot order fails the call
//! closed (`PlanBuilder::note_unpinned_source`).

use std::collections::BTreeMap;

use effinterp_proto::{ProvenanceRef, ResourceExpr, ResourceIdentity};

use crate::builder::{PlanBuilder, SourceAuthorship};
use crate::models::StdinValue;
use crate::nest::{Nest, SourceResolution};
use crate::word::Word;

use super::eval::command_substitution::literal_command_words;
use super::lex::{self, Seg};
use super::parse::{self, ShellItem};
use super::shell_env::ShellEnv;

/// The file a capture holds, how many host writes the plan had recorded
/// when the capture ran, and whether those are the writes bash makes first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapturedFile {
    pub(crate) path: String,
    pub(crate) writes_at_capture: usize,
    pub(crate) order: CaptureOrder,
    /// For a here-string, the index of its redirection: bash expands it
    /// after the targets before it and before those after it. `None` for a
    /// process substitution, whose `cat` runs beside every redirection.
    pub(crate) redirection: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureOrder {
    /// Bash makes exactly the writes recorded before the capture before it.
    Recorded,
    /// As recorded, and a here-document or here-string the walk expanded
    /// earlier wrote the file. Bash runs the prefix assignments before it,
    /// so an assignment that also writes the file runs out of order.
    RedirectionWritten,
    /// A prefix assignment wrote the file just before the capture: bytes the
    /// walk cannot read there are unknown code, so the read fails closed.
    Rewritten,
    /// Writes the walk recorded reach the file in an order bash does not
    /// follow, so the read fails closed.
    Unordered,
}

impl CapturedFile {
    /// The text a command substitution of `cat PATH` yields, as the host and
    /// the writes recorded before the capture left PATH: the served bytes
    /// less their trailing newlines. A later write cannot change what the
    /// substitution already printed. A NUL byte, which the substitution would
    /// drop, leaves the text unknown.
    pub(crate) fn text(&self, nest: &Nest, builder: &mut PlanBuilder) -> Option<String> {
        self.text_with_origin(nest, builder).map(|(text, _)| text)
    }

    /// `text`, with who wrote the bytes it was read from.
    pub(crate) fn text_with_origin(
        &self,
        nest: &Nest,
        builder: &mut PlanBuilder,
    ) -> Option<(String, SourceAuthorship)> {
        builder.with_source_writes_before(self.writes_at_capture, |builder| {
            let SourceResolution::Source { source, origin } = nest.resolve_source_file(
                builder,
                &self.path,
                crate::SourcePurpose::InvocationInput,
                "shell",
            ) else {
                return None;
            };
            (!source.contains('\0')).then(|| {
                (
                    source.trim_end_matches('\n').to_string(),
                    nest.source_authorship(&origin),
                )
            })
        })
    }

    /// The text of a capture the shell made while it opened the command's
    /// redirections, run as code. Bash expands the command's other
    /// redirection targets before that, which the walk does after the
    /// command, so the read is recorded for the command to check against
    /// them (`PlanBuilder::note_script_reads_rewritten`). Bytes the walk
    /// cannot order, or cannot read after a prefix assignment rewrote them,
    /// fail the call closed.
    pub(crate) fn script_text(
        &self,
        nest: &Nest,
        builder: &mut PlanBuilder,
    ) -> Option<(String, SourceAuthorship)> {
        if self.order == CaptureOrder::Unordered {
            builder.note_unpinned_source();
            return None;
        }
        builder.note_script_read(&self.path, self.redirection);
        let text = self.text_with_origin(nest, builder);
        if text.is_none() && self.order == CaptureOrder::Rewritten {
            builder.note_unpinned_source();
        }
        text
    }

    /// Whether a write recorded at an index in `range` may reach PATH.
    pub(crate) fn written_in(
        &self,
        nest: &Nest,
        builder: &PlanBuilder,
        range: std::ops::Range<usize>,
    ) -> bool {
        builder.source_written_in(range, &self.path, |resource, path| {
            nest.source_mutation_may_alias(resource, path)
        })
    }
}

/// The argv the launching shell runs, and the operands in it spelled as a
/// lone quoted `"$(cat FILE)"`, keyed by argv index. Only a model applied to
/// that same argv, or to a tail of it, may take an operand's bytes.
#[derive(Default)]
pub(crate) struct CapturedOperands {
    pub(crate) argv: Vec<Word>,
    pub(crate) operands: BTreeMap<usize, CapturedFile>,
    /// Request computations consumed by a shell binding at the same argv position.
    pub(crate) request_computations: BTreeMap<usize, ProvenanceRef>,
    /// Words spelled `--NAME="$(cat FILE)"`, an option whose attached value
    /// holds FILE's bytes, with their `--NAME=` prefix.
    pub(crate) attached: BTreeMap<usize, (String, CapturedFile)>,
}

impl CapturedOperands {
    /// The file the operand at `index` of `argv` captures. A wrapper the
    /// shell launches (`env`, `timeout`, `nice`) applies the program it runs
    /// to a tail of the shell's argv, whose words keep their captures.
    pub(crate) fn operand(&self, argv: &[Word], index: usize) -> Option<&CapturedFile> {
        if argv.is_empty() || !self.argv.ends_with(argv) {
            return None;
        }
        self.operands.get(&(self.argv.len() - argv.len() + index))
    }

    /// The `--NAME=` prefix and captured file of the option word at `index`
    /// of `argv`, read as [`Self::operand`] reads an operand.
    pub(crate) fn attached(&self, argv: &[Word], index: usize) -> Option<&(String, CapturedFile)> {
        if argv.is_empty() || !self.argv.ends_with(argv) {
            return None;
        }
        self.attached.get(&(self.argv.len() - argv.len() + index))
    }

    pub(crate) fn request_computation(&self, argv: &[Word], index: usize) -> Option<ProvenanceRef> {
        (self.argv == argv)
            .then(|| self.request_computations.get(&index).copied())
            .flatten()
    }
}

/// The stdin a command opens once its prefix assignments, which the walk ran
/// from host write `assignments_from` on, have run, when that changes how a
/// here-string's capture reads. Bash expands a here-string after the prefix
/// assignments, which the walk runs after it, so a capture of a file an
/// assignment wrote sees that write. It sees no write of a here-document or
/// here-string after it, and an earlier one runs after the assignments, so
/// when one of those also writes the file the walk cannot order the bytes.
pub(in crate::shell) fn stdin_after_assignments(
    stdin: Option<&StdinValue>,
    assignments_from: usize,
    nest: &Nest,
    builder: &PlanBuilder,
) -> Option<StdinValue> {
    let stdin = stdin?;
    let captured = stdin.captured_file.as_deref()?;
    let assigned = builder.source_write_count();
    if !captured.written_in(nest, builder, assignments_from..assigned) {
        return None;
    }
    let order = if captured.order == CaptureOrder::RedirectionWritten
        || captured.written_in(nest, builder, captured.writes_at_capture..assignments_from)
    {
        CaptureOrder::Unordered
    } else {
        CaptureOrder::Rewritten
    };
    Some(StdinValue {
        captured_file: Some(Box::new(CapturedFile {
            path: captured.path.clone(),
            writes_at_capture: assigned,
            order,
            redirection: captured.redirection,
        })),
        ..stdin.clone()
    })
}

/// The capture a here-string spelled as a lone quoted `"$(cat FILE)"` holds
/// at the command's redirection `redirection`, given the host writes
/// recorded when the command's redirections began and when the here-string
/// finished expanding.
pub(in crate::shell) fn here_string_capture(
    env: &ShellEnv,
    segs: &[Seg],
    redirection: usize,
    redirections_from: usize,
    writes_at_capture: Option<usize>,
    nest: &Nest,
    builder: &PlanBuilder,
) -> Option<CapturedFile> {
    let mut captured = quoted_capture(env, segs, writes_at_capture)?;
    captured.redirection = Some(redirection);
    if captured.written_in(nest, builder, redirections_from..captured.writes_at_capture) {
        captured.order = CaptureOrder::RedirectionWritten;
    }
    Some(captured)
}

/// The capture a word spelled as a lone quoted `"$(cat FILE)"` holds, given
/// the host writes recorded when the word finished expanding.
pub(in crate::shell) fn quoted_capture(
    env: &ShellEnv,
    segs: &[Seg],
    writes_at_capture: Option<usize>,
) -> Option<CapturedFile> {
    let [
        Seg::CommandSub {
            source,
            quoted: true,
            ..
        },
    ] = segs
    else {
        return None;
    };
    substitution_capture(env, source, writes_at_capture?)
}

/// A word spelled `--NAME="$(cat FILE)"`: its `--NAME=` prefix and the
/// capture its attached value holds.
pub(in crate::shell) fn attached_capture(
    env: &ShellEnv,
    segs: &[Seg],
    writes_at_capture: Option<usize>,
) -> Option<(String, CapturedFile)> {
    let [Seg::Literal { text, .. }, value @ ..] = segs else {
        return None;
    };
    if !text.starts_with("--") || !text.ends_with('=') {
        return None;
    }
    Some((text.clone(), quoted_capture(env, value, writes_at_capture)?))
}

/// The capture a substitution's command `source` holds when it is `cat
/// FILE`, taken when the plan held `writes_at_capture` host writes. Its bytes
/// are demanded only where the capture is used as shell code.
pub(in crate::shell) fn substitution_capture(
    env: &ShellEnv,
    source: &str,
    writes_at_capture: usize,
) -> Option<CapturedFile> {
    Some(CapturedFile {
        path: captured_file_path(env, source)?,
        writes_at_capture,
        order: CaptureOrder::Recorded,
        redirection: None,
    })
}

/// The file a substitution's command `cat FILE` prints unchanged, when that
/// `cat` is the external program. Naming the file reads nothing: its bytes
/// are demanded only where the capture is used as code or as a script name.
pub(in crate::shell) fn captured_file_path(env: &ShellEnv, source: &str) -> Option<String> {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return None;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    let [
        ShellItem::Pipeline {
            cmds,
            conditional: false,
            short_circuit: None,
        },
    ] = items.as_slice()
    else {
        return None;
    };
    let [cmd] = cmds.as_slice() else {
        return None;
    };
    let words = literal_command_words(cmd)?;
    let [program, operand] = words.as_slice() else {
        return None;
    };
    if program.as_literal() != Some("cat")
        || operand.as_literal()?.starts_with('-')
        || !external_program(env, "cat")
    {
        return None;
    }
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = crate::paths::resolve_fs_word_with_cwd(operand, env.cwd_resource.clone())
    else {
        return None;
    };
    Some(path)
}

/// Whether `name` run as a command is the external program of that name: no
/// function, alias or disabled builtin the shell may hold takes its place.
pub(in crate::shell) fn external_program(env: &ShellEnv, name: &str) -> bool {
    !(env.functions.contains_key(name)
        || env.function_alternatives.contains_key(name)
        || env.aliases.contains_key(name)
        || env.alias_alternatives.contains_key(name)
        || env.unread_alias_names
        || env.unread_aliases.contains(name)
        || env.disabled_builtins.contains(name))
}

/// The bytes of the file at `path` as the host and the writes the plan
/// recorded so far leave it, less their trailing newlines, read as a
/// substitution reads it. A file that cannot be read leaves no evidence: the
/// substitution keeps its own unresolved value.
pub(in crate::shell) fn served_text(
    path: &str,
    nest: &Nest,
    builder: &mut PlanBuilder,
) -> Option<String> {
    if !nest.host_source_readable(builder, path, crate::SourcePurpose::InvocationInput) {
        return None;
    }
    CapturedFile {
        path: path.to_owned(),
        writes_at_capture: builder.source_write_count(),
        order: CaptureOrder::Recorded,
        redirection: None,
    }
    .text(nest, builder)
}
