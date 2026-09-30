//! Source-text helpers shared by the line-oriented Julia, Lua, Perl, R and
//! Swift frontends.

use effinterp_proto::{PathPlatform, ProvenanceRef, Subject};

use crate::builder::PlanBuilder;
use crate::nest::{Nest, Transition, word_resource};
use crate::word::Word;

/// A language call that hands one string to the system shell (`system "..."`,
/// `os.execute`, R's `system2`, which joins its command and arguments into one
/// shell line): analyze the string as `sh -c` source in the caller's cwd.
/// When the language `captured` the child's stdout into a value (a backtick,
/// `io.popen` for reading, R's `intern = TRUE`), the child does not inherit
/// the program's stdout, so its output reaches no pipe the program feeds.
pub(super) fn nest_shell(
    builder: &mut PlanBuilder,
    nest: &Nest,
    command: String,
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u64,
    captured: bool,
) {
    let subject = Subject::Shell {
        source: command,
        cwd: cwd.map(str::to_string),
        context: Default::default(),
    };
    let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
    let source_cwd = nest.current_source_cwd();
    let mut transition = Transition::file(subject)
        .source_cwd(source_cwd.as_deref())
        .runtime_cwd(runtime_cwd.as_deref());
    if captured {
        let mut streams = builder.inherited_execution_streams();
        streams.stdout = None;
        transition = transition.streams(streams);
    }
    nest.nest(builder, transition, &[node], depth);
}

/// A language call that executes an exact argument vector without a shell
/// (`system LIST`, Julia's `run` command literal).
pub(super) fn nest_argv(
    builder: &mut PlanBuilder,
    nest: &Nest,
    argv: &[String],
    cwd: Option<&str>,
    node: ProvenanceRef,
    depth: u64,
) {
    let words: Vec<Word> = argv
        .iter()
        .map(|word| Word::literal(word.as_str()))
        .collect();
    let runtime_cwd = nest.current_runtime_cwd();
    nest.nest(
        builder,
        Transition::exec(words.iter().map(word_resource).collect(), words)
            .exec_cwd(cwd)
            .cwd(
                builder.current_execution_cwd(),
                (runtime_cwd.as_deref() == cwd)
                    .then(|| nest.current_cwd_node())
                    .flatten(),
            )
            .runtime_cwd(runtime_cwd.as_deref()),
        &[node],
        depth,
    );
}

/// The path platform of a literal path: Windows when the path, or the cwd a
/// relative path resolves against, starts with a drive letter.
pub(super) fn drive_letter_platform(path: &str, cwd: Option<&str>) -> PathPlatform {
    let drive = |text: &str| {
        text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && (text.get(1..3) == Some(":\\") || text.get(1..3) == Some(":/"))
    };
    if drive(path) || (!path.starts_with('/') && cwd.is_some_and(drive)) {
        PathPlatform::Windows
    } else {
        PathPlatform::Posix
    }
}

/// Consume up to `limit` leading characters of `rest` that `accept` admits,
/// as an escape sequence's digits.
pub(super) fn take_accepted_chars(
    rest: &mut &str,
    limit: usize,
    accept: impl Fn(char) -> bool,
) -> String {
    let mut taken = String::new();
    while taken.len() < limit
        && let Some(character) = rest.chars().next()
        && accept(character)
    {
        taken.push(character);
        *rest = &rest[character.len_utf8()..];
    }
    taken
}

/// Trim source text to at most 40 characters for a boundary detail.
pub(super) fn elide_detail(text: &str) -> String {
    let text = text.trim();
    match text.char_indices().nth(40) {
        Some((index, _)) => format!("{}…", &text[..index]),
        None => text.to_string(),
    }
}
