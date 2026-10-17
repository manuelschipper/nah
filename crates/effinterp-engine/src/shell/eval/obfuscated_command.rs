//! Obfuscated command: a program name the shell computes at run time
//! instead of one the source spells (`$(echo cm0= | base64 -d) -rf /`). States
//! the hidden program effect that `exec-obfuscated` matches.

use effinterp_proto::{
    AttrValue, Effect, ExecutionNodeRef, Modality, Operation, ProvenanceKind, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::paths::process_identity_with_cwd;
use crate::shell::lex::{RedirKind, Seg, ShellSpan, WordTok};
use crate::shell::parse::{ShellItem, Simple};
use crate::shell::shell_env::ShellEnv;
use crate::shell::{Converted, Shell, lex, parse};
use crate::word::{Word, WordPart};

use super::command_substitution::heredoc_body_expands;
use super::simple_command::substituted_head;
use super::variable_binding::entry_definitely_transparent;
use super::word_expansion::{
    effective_ifs, ifs_joined_fields, split_ifs_fields, splits_substitution_output,
};

impl Shell<'_> {
    /// State the hidden program effect when the command head is computed rather
    /// than spelled: a transformed or word-split parameter, a glob, or a command
    /// substitution that hides the name it produces.
    pub(super) fn emit_obfuscated_command_effect(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        variants: &[Vec<Converted>],
    ) {
        let transformed_head = matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Param {
                transform: Some(_),
                ..
            }]
        );
        // A head split on a custom IFS, from a variable or from a
        // substitution's output (`IFS=:; $(printf 'git:reset')`).
        let custom_split_head = match cmd.words[0].segs.as_slice() {
            [
                Seg::Env {
                    name,
                    quoted: false,
                },
            ] => effective_ifs(env).is_some_and(|ifs| {
                ifs != " \t\n"
                    && env
                        .vars
                        .get(name)
                        .and_then(|entry| entry.value.as_deref())
                        .is_some_and(|value| split_ifs_fields(value, &ifs).len() > 1)
            }),
            _ => {
                splits_substitution_output(&cmd.words[0], env)
                    && effective_ifs(env).is_some_and(|ifs| ifs != " \t\n")
            }
        };
        let heads = || variants.iter().filter_map(|variant| variant.first());
        // Pathname expansion of an unquoted variable selects the program from
        // whichever files match, as `TOOL='r*'; $TOOL` does.
        let glob_head = matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Env { quoted: false, .. }]
        ) && heads()
            .any(|head| matches!(head.word.parts.as_slice(), [WordPart::Glob(_)]));
        // `rm${IFS}-rf${IFS}/` splits the program out of one word, under the
        // default or a custom IFS.
        let ifs_joined_head =
            effective_ifs(env).is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some());
        // A command substitution prints the program name, as `$(rev <<< mr)`
        // does, whether or not its output is recovered. A transparent producer
        // (`echo`, `printf`, `cat`) passes a source-visible literal through and
        // does not conceal the name. But an unquoted substitution at the head
        // also undergoes field splitting and pathname/brace expansion: even a
        // transparent producer whose output (`r*`, `a b`) does not survive as a
        // single proven literal hides the real program, so it stays marked.
        // A substitution that prints only part of the name (`g$(rev <<< ti)`,
        // `$prefix$(cat suffix)`) conceals it the same way. One before the
        // last `/`, which a literal or a definite variable spells, only picks
        // the directory (`"$(git rev-parse --show-toplevel)/scripts/test.sh"`)
        // when it stays one field: quoted, recovered, or a modeled path query.
        // Unquoted, other output may split into another program and its
        // arguments. A pattern in the head lets the files it matches choose
        // the program.
        let head_segs = cmd.words[0].segs.as_slice();
        let spliced_head = head_segs.iter().all(|seg| {
            matches!(
                seg,
                Seg::CommandSub { .. } | Seg::Literal { .. } | Seg::Env { .. }
            )
        });
        let definite_text = |seg: &Seg| match seg {
            Seg::Literal { text, .. } => Some(text.clone()),
            Seg::Env { name, .. } => env
                .reference_target(name)
                .and_then(|name| env.vars.get(&name))
                .and_then(|entry| entry.value.clone()),
            _ => None,
        };
        let name_start = head_segs
            .iter()
            .rposition(|seg| definite_text(seg).is_some_and(|text| text.contains('/')))
            .unwrap_or(0);
        let recovered_head = heads().all(|head| {
            !head
                .word
                .parts
                .iter()
                .any(|part| matches!(part, WordPart::Unknown))
        });
        let pattern_in_head = head_segs.iter().any(|seg| {
            matches!(seg, Seg::Literal { text, quoted: false } if text.contains(['*', '?', '[']))
        });
        let substituted_name = spliced_head
            && head_segs
                .iter()
                .any(|seg| matches!(seg, Seg::CommandSub { .. }))
            && (pattern_in_head
                || head_segs.iter().enumerate().any(|(index, seg)| match seg {
                    Seg::CommandSub { quoted: true, .. } if index < name_start => false,
                    Seg::CommandSub { source, .. } if index < name_start => {
                        !recovered_head && !prints_one_path(source)
                    }
                    Seg::CommandSub { source, quoted, .. } => {
                        substitution_hides_name(source, *quoted)
                            || (!quoted
                                && substituted_head(&cmd.words[0])
                                && heads().any(|head| head.word.as_literal().is_none()))
                    }
                    _ => false,
                }));
        // A lone variable holding a value captured from a name-hiding
        // substitution is the same concealment reached through an assignment
        // (`X=$(which rm); $X`), whether or not the value is recovered to a
        // literal head. A transparent capture (`X=$(echo rm)`) is not.
        let captured_value_head = match cmd.words[0].segs.as_slice() {
            [Seg::Env { name, .. }] => env
                .reference_target(name)
                .and_then(|name| env.vars.get(&name))
                .is_some_and(|entry| {
                    entry.captured_name_hidden && !entry_definitely_transparent(entry)
                }),
            _ => false,
        };
        // A literal pattern spelled as the command name also leaves the
        // program to whichever files match, as `r? -rf /` does. A lone `[`
        // is the test builtin, not a bracket expression.
        let literal_head = parse::literal_text(&cmd.words[0]).is_some_and(|name| {
            let bracket = name
                .find('[')
                .is_some_and(|open| name[open + 1..].find(']').is_some_and(|close| close > 0));
            name.contains(['*', '?']) || bracket
        });
        let has_literal_head = heads().any(|head| head.word.as_literal().is_some());
        let marked = glob_head
            || literal_head
            || substituted_name
            || captured_value_head
            || ((transformed_head || custom_split_head || ifs_joined_head) && has_literal_head);
        if !marked {
            return;
        }
        self.emit_hidden_program_effect(builder, env, cmd.words[0].span);
    }

    /// The exact code execution `exec-obfuscated` matches: a program the
    /// shell computes at run time rather than one the source spells.
    pub(super) fn emit_hidden_program_effect(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        span: ShellSpan,
    ) {
        let source = self.span_node(builder, span);
        let node = builder.node(
            ProvenanceKind::ModelApplication {
                model: "shell/obfuscated-command@v0".into(),
            },
            &[source],
        );
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new("process.code_execution"),
            resource: ResourceExpr::Concrete {
                identity: process_identity_with_cwd(
                    &[Word::literal("sh")],
                    env.cwd_resource.clone(),
                ),
            },
            attributes: [
                ("source".into(), AttrValue::String("argument".into())),
                (
                    "derivation".into(),
                    AttrValue::String("unresolved_command".into()),
                ),
            ]
            .into_iter()
            .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }
}

/// Whether a word is text already visible in the source: every segment is a
/// literal and no glob or brace metacharacter can expand it to something else.
/// A command substitution, parameter expansion, arithmetic, or process
/// substitution segment makes the word's value depend on runtime state. When
/// the substitution's output is consumed by a quoted head (`"$(printf '%s'
/// {l,s})"`), that head is one word no expansion can split or rewrite, so a
/// metacharacter there is delivered verbatim and stays source-visible.
fn word_is_source_literal(tok: &WordTok, head_quoted: bool) -> bool {
    tok.segs.iter().all(|seg| match seg {
        Seg::Literal { text, quoted } => {
            head_quoted || *quoted || !text.contains(['*', '?', '[', '{', '}'])
        }
        _ => false,
    })
}

/// Whether a command substitution used as a program name hides that name
/// behind a transformation. The only transparent producers pass a
/// source-visible literal through unchanged: `echo`/`printf` with literal
/// argument words, or `cat` of a here-string or heredoc literal. A file read
/// (`cat FILE`, `cat < FILE`), a nested substitution, a multi-stage pipeline,
/// `rev`, `tr`, `which`, `command -v`, or any other producer conceals the name.
/// An unparseable or unrecognized producer is treated as hiding. `head_quoted`
/// is the quoting of the substitution where it is consumed: under a quoted head
/// a producer metacharacter cannot expand, so it does not conceal the name.
/// Whether a substitution is a path query whose output is one directory the
/// environment supplies rather than text the source chooses: one the engine
/// models (`pwd`, `git rev-parse --show-toplevel`, `command -v NAME`) or one
/// of `TOOL_PATH_QUERIES`.
fn prints_one_path(source: &str) -> bool {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return false;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    let [
        ShellItem::Pipeline {
            cmds,
            short_circuit: None,
            ..
        },
    ] = items.as_slice()
    else {
        return false;
    };
    let [cmd] = cmds.as_slice() else {
        return false;
    };
    if !cmd.assignments.is_empty() || !cmd.redirs.is_empty() {
        return false;
    }
    if tool_path_query(&cmd.words) {
        return true;
    }
    let Some(words) = cmd
        .words
        .iter()
        .map(|word| parse::literal_text(word).map(Word::literal))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    // `dirname` of a literal is that literal text, which expansion already
    // recovered when it stays one field.
    crate::models::coreutils::stdout_value(&words, None).is_some_and(|value| {
        !matches!(value, ResourceExpr::Literal { .. }) && source_text_stays_one_field(&value)
    })
}

/// Everyday tool queries that print the one directory a tool is configured
/// with, so `$(npm bin)/eslint` names the program it runs. Each is listed
/// because agents run tools this way and the output is a single path:
/// - `dirname ARG`: the parent directory of its one operand, including
///   `"$0"` in `$(dirname "$0")/run.sh`.
/// - `npm bin`, `npm prefix [-g]`, `npm root [-g]`: the project's or the
///   global install's bin, prefix or `node_modules` directory.
/// - `go env GOPATH|GOROOT|GOBIN`: the one directory that variable names.
/// - `brew --prefix [FORMULA]`: Homebrew's prefix, or that formula's.
fn tool_path_query(words: &[WordTok]) -> bool {
    let Some((name, arguments)) = words.split_first() else {
        return false;
    };
    let Some(name) = parse::literal_text(name) else {
        return false;
    };
    if name == "dirname" {
        let operands = match arguments {
            [separator, operands @ ..]
                if parse::literal_text(separator).as_deref() == Some("--") =>
            {
                operands
            }
            operands => operands,
        };
        return matches!(operands, [operand]
            if !parse::literal_text(operand).is_some_and(|operand| operand.starts_with('-')));
    }
    let Some(arguments) = arguments
        .iter()
        .map(parse::literal_text)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    match (name.as_str(), arguments.as_slice()) {
        ("npm", ["bin"] | ["prefix" | "root"] | ["prefix" | "root", "-g" | "--global"]) => true,
        ("go", ["env", "GOPATH" | "GOROOT" | "GOBIN"]) => true,
        ("brew", ["--prefix"]) => true,
        ("brew", ["--prefix", formula]) => !formula.starts_with('-'),
        _ => false,
    }
}

/// Whether every piece of text the source supplied to a modeled path (the
/// operand of `realpath 'a b'`) is free of whitespace and pattern characters.
fn source_text_stays_one_field(value: &ResourceExpr) -> bool {
    let one_field = |text: &str| !text.contains([' ', '\t', '\n', '*', '?', '[']);
    match value {
        ResourceExpr::Literal { value } => one_field(value),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => one_field(path),
        ResourceExpr::Property { base, .. } => source_text_stays_one_field(base),
        ResourceExpr::Join { parts } => parts.iter().all(source_text_stays_one_field),
        ResourceExpr::Parameter { .. } => true,
        _ => false,
    }
}

pub(super) fn substitution_hides_name(source: &str, head_quoted: bool) -> bool {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return true;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    // A transparent producer is one single-stage pipeline, so a `|` between
    // stages or a `&&`/`||` between commands already conceals the name.
    let [
        ShellItem::Pipeline {
            cmds,
            short_circuit: None,
            ..
        },
    ] = items.as_slice()
    else {
        return true;
    };
    let [cmd] = cmds.as_slice() else {
        return true;
    };
    let Some(name) = cmd.words.first().and_then(parse::literal_text) else {
        return true;
    };
    let transparent = match name.as_str() {
        // Only literal argument words are visible; a nested `$(...)` or a
        // parameter expansion in an argument hides what is printed.
        "echo" | "printf" => cmd.words[1..]
            .iter()
            .all(|word| word_is_source_literal(word, head_quoted)),
        // A here-string or heredoc body is source text; a file operand or an
        // input redirection reads bytes the source never shows.
        "cat" => {
            cmd.words.len() == 1
                && !cmd.redirs.is_empty()
                && cmd.redirs.iter().all(|redir| match redir.kind {
                    RedirKind::HereString => redir
                        .target
                        .as_ref()
                        .is_some_and(|target| word_is_source_literal(target, head_quoted)),
                    // A heredoc body is source-visible only when it cannot
                    // expand: a quoted delimiter, or a body whose `$`/backtick
                    // are all backslash-escaped. `cat <<EOF\n$(which rm)\nEOF`
                    // conceals the name; an escaped `\$(which rm)` is literal.
                    RedirKind::HereDoc => redir
                        .heredoc
                        .as_ref()
                        .is_some_and(|heredoc| !heredoc_body_expands(heredoc)),
                    _ => false,
                })
        }
        _ => false,
    };
    !transparent
}
