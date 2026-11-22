use effinterp_proto::ProvenanceRef;

use crate::builder::PlanBuilder;
use crate::models::common::program_input_attrs;
use crate::models::{CommandModel, InvocationCtx};
use crate::resource_transfer::TransferBinding;
use crate::word::Word;

/// Add the file reads from HTTPie and xh request items to the registered HTTP model.
pub(in crate::models) fn with_httpie_request_item_files(
    owner: Box<dyn CommandModel>,
) -> Box<dyn CommandModel> {
    Box::new(HttpieRequestItemFiles { owner })
}

struct HttpieRequestItemFiles {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for HttpieRequestItemFiles {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let start = builder.effects_len();
        // The document's one positional is the URL, so it reads a METHOD word
        // as the URL; it is given the argv without that word. A symbolic word
        // before it might be the URL, so it is then left as it is.
        match httpie_operands(ctx.argv) {
            (operands, true)
                if ctx.argv[1..operands[0].0]
                    .iter()
                    .all(|word| word.as_literal().is_some()) =>
            {
                let method = operands[0].0;
                let argv = ctx
                    .argv
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != method)
                    .map(|(_, word)| word.clone())
                    .collect::<Vec<_>>();
                let provenance = (0..ctx.argv.len())
                    .filter(|index| *index != method)
                    .map(|index| ctx.argv_provenance_at(builder, index))
                    .collect::<Vec<_>>();
                let ctx = InvocationCtx {
                    argv: &argv,
                    stdin: ctx.stdin,
                    argv_provenance: Some(&provenance),
                    cwd: ctx.cwd,
                    cwd_resource: ctx.cwd_resource.clone(),
                    runtime_cwd: ctx.runtime_cwd,
                    scope: ctx.scope,
                    cwd_node: ctx.cwd_node,
                    nest: ctx.nest,
                    depth: ctx.depth,
                    model_stack: ctx.model_stack.clone(),
                };
                self.owner.apply(builder, &ctx, model_node);
            }
            _ => self.owner.apply(builder, ctx, model_node),
        }
        let uploads = (start..builder.effects_len())
            .filter(|&index| builder.effect_operation(index) == Some("network.upload"))
            .collect::<Vec<_>>();
        if uploads.is_empty() {
            return;
        }
        for (index, path) in httpie_request_item_files(ctx.argv) {
            let Some(read) = crate::models::common::content_read_effect(
                builder,
                ctx,
                model_node,
                index as u32,
                &Word::literal(path),
                program_input_attrs(),
            ) else {
                continue;
            };
            for &upload in &uploads {
                builder.transfer_binding(TransferBinding::new(read, upload as u32));
            }
        }
    }
}

/// httpie and xh options that take the next word as their value.
const HTTPIE_VALUE_FLAGS: &[&str] = &[
    "-a",
    "--auth",
    "-A",
    "--auth-type",
    "-o",
    "--output",
    "-p",
    "--print",
    "-P",
    "--history-print",
    "-s",
    "--style",
    "--session",
    "--session-read-only",
    "--verify",
    "--cert",
    "--cert-key",
    "--cert-key-pass",
    "--ssl",
    "--ciphers",
    "--proxy",
    "--timeout",
    "--max-redirects",
    "--max-headers",
    "--pretty",
    "--format-options",
    "--boundary",
    "--raw",
    "--response-charset",
    "--response-mime",
    "--default-scheme",
    "--unix-socket",
    "--http-version",
    "--resolve",
    "--interface",
    "--bearer",
];

/// The literal operands of an httpie/xh invocation, by argv index, and
/// whether the first is the METHOD. As httpie guesses: a word before the URL
/// is the METHOD, unless the word after it is a request item, which makes
/// that first word the URL. A word with a scheme (`https://…`) or httpie's
/// `:PORT` localhost shorthand is a URL, not a header item.
fn httpie_operands(argv: &[Word]) -> (Vec<(usize, &str)>, bool) {
    let mut operands = Vec::new();
    let mut index = 1;
    while index < argv.len() {
        let Some(word) = argv[index].as_literal() else {
            index += 1;
            continue;
        };
        if word.len() > 1 && word.starts_with('-') && !word.starts_with("-@") {
            index += if HTTPIE_VALUE_FLAGS.contains(&word) {
                2
            } else {
                1
            };
            continue;
        }
        operands.push((index, word));
        index += 1;
    }
    let method = operands.len() > 1
        && operands[0]
            .1
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        && (request_item_separator(operands[1].1).is_none()
            || operands[1].1.contains("://")
            || operands[1].1.starts_with(':'));
    (operands, method)
}

/// A request item's separator and its position: the first one in the item,
/// the longest at that position.
fn request_item_separator(item: &str) -> Option<(usize, &'static str)> {
    item.char_indices().find_map(|(at, _)| {
        [":=@", "=@", "==", ":=", "@", "=", ":"]
            .into_iter()
            .find(|separator| item[at..].starts_with(separator))
            .map(|separator| (at, separator))
    })
}

/// The files a literal httpie/xh invocation's request items send, by argv
/// index: `field=@file` and `field:=@file` embed a file's contents,
/// `field@file` uploads it as a form file, and a bare `@file` is the body.
/// Items follow the optional METHOD and the URL. Escaped separators are not
/// read.
fn httpie_request_item_files(argv: &[Word]) -> Vec<(usize, &str)> {
    let (operands, method) = httpie_operands(argv);
    operands
        .into_iter()
        .skip(if method { 2 } else { 1 })
        .filter(|(_, item)| !item.contains('\\'))
        .filter_map(|(index, item)| {
            let (at, separator) = request_item_separator(item)?;
            let path = &item[at + separator.len()..];
            let path = match separator {
                ":=@" | "=@" => path,
                // A form file may carry `;type=MIME` after its path.
                "@" => path.split(';').next().unwrap_or(path),
                _ => return None,
            };
            (!path.is_empty()).then_some((index, path))
        })
        .collect()
}
