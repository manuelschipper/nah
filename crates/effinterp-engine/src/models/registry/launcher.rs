//! Declarative argv parsing shared by language launchers. The parser assigns
//! syntax roles only; each named Rust frontend retains source and runtime
//! semantics.

use effinterp_model_schema::{
    LauncherAttachmentDeclaration, LauncherFrontendDeclaration, LauncherGrammarDeclaration,
    LauncherOperandRoleDeclaration, LauncherOptionClassDeclaration, LauncherOptionDeclaration,
};
use effinterp_proto::ProvenanceRef;

use crate::builder::PlanBuilder;
use crate::models::args::strip_literal_prefix;
use crate::word::Word;

use super::super::InvocationCtx;

#[derive(Clone)]
pub(crate) struct LauncherArgument {
    pub(crate) index: u32,
    pub(crate) word: Word,
}

#[derive(Clone)]
pub(crate) struct LauncherOption {
    pub(crate) index: u32,
    pub(crate) name: String,
    pub(crate) class: LauncherOptionClassDeclaration,
    pub(crate) value: Option<LauncherArgument>,
    pub(crate) raw: Word,
}

pub(crate) enum LauncherBoundary {
    UnreviewedOption(LauncherArgument),
    UnexpectedOperand(LauncherArgument),
}

pub(crate) struct LauncherInvocation {
    pub(crate) options: Vec<LauncherOption>,
    pub(crate) inline_source: Option<LauncherArgument>,
    pub(crate) module: Option<LauncherArgument>,
    pub(crate) preloads: Vec<LauncherArgument>,
    pub(crate) cwd: Option<LauncherArgument>,
    pub(crate) script: Option<LauncherArgument>,
    pub(crate) program_arguments: Vec<LauncherArgument>,
    pub(crate) boundaries: Vec<LauncherBoundary>,
}

impl LauncherInvocation {
    fn new() -> Self {
        Self {
            options: Vec::new(),
            inline_source: None,
            module: None,
            preloads: Vec::new(),
            cwd: None,
            script: None,
            program_arguments: Vec::new(),
            boundaries: Vec::new(),
        }
    }
}

pub(crate) fn parse(grammar: &LauncherGrammarDeclaration, argv: &[Word]) -> LauncherInvocation {
    let mut invocation = LauncherInvocation::new();
    let mut index = 1;
    let mut flags_done = false;
    let mut program_arguments = None;

    while index < argv.len() {
        if flags_done {
            if grammar.frontend == LauncherFrontendDeclaration::R {
                break;
            }
            assign_operand(grammar, argv, index, &mut invocation);
            break;
        }

        let matched = exact_option(grammar, &argv[index])
            .or_else(|| clustered_option(grammar, &argv[index]))
            .or_else(|| attached_option(grammar, &argv[index]));
        let Some((rule, name, attached)) = matched else {
            if grammar.frontend != LauncherFrontendDeclaration::R
                && (invocation.inline_source.is_some() || invocation.module.is_some())
            {
                break;
            }
            assign_operand(grammar, argv, index, &mut invocation);
            break;
        };

        let option_index = index;
        let value = if takes_value(rule.class) {
            match attached {
                Some(word) => Some(LauncherArgument {
                    index: option_index as u32,
                    word,
                }),
                None if accepts_separate(rule.attachment) => argv.get(index + 1).map(|word| {
                    index += 1;
                    LauncherArgument {
                        index: index as u32,
                        word: word.clone(),
                    }
                }),
                None => None,
            }
        } else {
            None
        };
        let option = LauncherOption {
            index: option_index as u32,
            name,
            class: rule.class,
            value: value.clone(),
            raw: argv[option_index].clone(),
        };

        match rule.class {
            LauncherOptionClassDeclaration::InlineSource => {
                if invocation.inline_source.is_none() {
                    invocation.inline_source = value.clone();
                    if grammar.frontend != LauncherFrontendDeclaration::R {
                        program_arguments = Some(index + 1);
                    }
                }
            }
            LauncherOptionClassDeclaration::ModuleSelector => {
                if invocation.module.is_none() {
                    invocation.module = value.clone();
                    program_arguments = Some(index + 1);
                }
            }
            LauncherOptionClassDeclaration::Preload => {
                if let Some(value) = value.clone() {
                    invocation.preloads.push(value);
                }
            }
            LauncherOptionClassDeclaration::Chdir => invocation.cwd = value.clone(),
            LauncherOptionClassDeclaration::EndOfOptions => {
                flags_done = true;
                if grammar.frontend == LauncherFrontendDeclaration::R {
                    program_arguments = Some(index + 1);
                }
            }
            LauncherOptionClassDeclaration::Unreviewed => {
                invocation
                    .boundaries
                    .push(LauncherBoundary::UnreviewedOption(LauncherArgument {
                        index: option_index as u32,
                        word: argv[option_index].clone(),
                    }));
            }
            LauncherOptionClassDeclaration::Value | LauncherOptionClassDeclaration::Inert => {}
        }
        invocation.options.push(option);
        index += 1;
    }

    if let Some(start) = program_arguments {
        invocation.program_arguments = launcher_arguments(argv, start);
    }
    invocation
}

pub(crate) fn apply(
    grammar: &LauncherGrammarDeclaration,
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) {
    let invocation = parse(grammar, ctx.argv);
    match grammar.frontend {
        LauncherFrontendDeclaration::Python => {
            super::super::pyexec::apply(builder, ctx, model_node, &invocation)
        }
        LauncherFrontendDeclaration::Node => {
            super::super::nodeexec::apply(builder, ctx, model_node, &invocation)
        }
        LauncherFrontendDeclaration::Ruby => {
            super::super::rubyexec::apply(builder, ctx, model_node, &invocation)
        }
        LauncherFrontendDeclaration::Php => {
            super::super::phpexec::apply(builder, ctx, model_node, &invocation)
        }
        LauncherFrontendDeclaration::R => {
            super::super::rexec::apply(builder, ctx, model_node, &invocation)
        }
    }
}

fn assign_operand(
    grammar: &LauncherGrammarDeclaration,
    argv: &[Word],
    index: usize,
    invocation: &mut LauncherInvocation,
) {
    if (argv[index].as_literal() == Some("-")
        && grammar
            .operands
            .contains(&LauncherOperandRoleDeclaration::StdinProgram))
        || grammar
            .operands
            .contains(&LauncherOperandRoleDeclaration::Script)
    {
        invocation.script = Some(LauncherArgument {
            index: index as u32,
            word: argv[index].clone(),
        });
        invocation.program_arguments = launcher_arguments(argv, index + 1);
    } else {
        invocation
            .boundaries
            .push(LauncherBoundary::UnexpectedOperand(LauncherArgument {
                index: index as u32,
                word: argv[index].clone(),
            }));
        if grammar
            .operands
            .contains(&LauncherOperandRoleDeclaration::ProgramArguments)
        {
            invocation.program_arguments = launcher_arguments(argv, index);
        }
    }
}

fn launcher_arguments(argv: &[Word], start: usize) -> Vec<LauncherArgument> {
    argv.iter()
        .enumerate()
        .skip(start)
        .map(|(index, word)| LauncherArgument {
            index: index as u32,
            word: word.clone(),
        })
        .collect()
}

fn exact_option<'a>(
    grammar: &'a LauncherGrammarDeclaration,
    word: &Word,
) -> Option<(&'a LauncherOptionDeclaration, String, Option<Word>)> {
    let literal = word.as_literal()?;
    grammar.options.iter().find_map(|rule| {
        rule.names
            .iter()
            .find(|name| name.as_str() == literal)
            .filter(|_| rule.attachment != LauncherAttachmentDeclaration::Attached)
            .map(|name| (rule, name.clone(), None))
    })
}

fn attached_option<'a>(
    grammar: &'a LauncherGrammarDeclaration,
    word: &Word,
) -> Option<(&'a LauncherOptionDeclaration, String, Option<Word>)> {
    grammar
        .options
        .iter()
        .filter(|rule| {
            matches!(
                rule.attachment,
                LauncherAttachmentDeclaration::Attached | LauncherAttachmentDeclaration::Either
            ) && (word.as_literal().is_some()
                || rule.class == LauncherOptionClassDeclaration::InlineSource)
        })
        .flat_map(|rule| rule.names.iter().map(move |name| (rule, name)))
        .filter_map(|(rule, name)| {
            let value = strip_attached_value(word, name)?;
            Some((rule, name, value))
        })
        .max_by_key(|(_, name, _)| name.len())
        .map(|(rule, name, value)| (rule, name.clone(), takes_value(rule.class).then_some(value)))
}

fn clustered_option<'a>(
    grammar: &'a LauncherGrammarDeclaration,
    word: &Word,
) -> Option<(&'a LauncherOptionDeclaration, String, Option<Word>)> {
    let prefix = word.literal_prefix().strip_prefix('-')?;
    if prefix.starts_with('-') {
        return None;
    }
    let mut offset = 1;
    for option in prefix.chars() {
        let name = format!("-{option}");
        let rule = grammar.options.iter().find(|rule| {
            rule.attachment == LauncherAttachmentDeclaration::ClusteredTail
                && rule.names.contains(&name)
        })?;
        offset += option.len_utf8();
        if takes_value(rule.class) {
            let value = strip_literal_prefix(word, offset);
            return Some((rule, name, (!value.parts.is_empty()).then_some(value)));
        }
        if rule.class != LauncherOptionClassDeclaration::Inert {
            return Some((rule, name, None));
        }
    }
    None
}

fn strip_attached_value(word: &Word, name: &str) -> Option<Word> {
    let prefix = word.literal_prefix();
    let consumed = if name.starts_with("--") {
        let expected = format!("{name}=");
        prefix.starts_with(&expected).then_some(expected.len())?
    } else {
        if !prefix.starts_with(name) {
            return None;
        }
        if prefix.len() == name.len() && word.parts.len() == 1 {
            return None;
        }
        name.len()
    };
    Some(strip_literal_prefix(word, consumed))
}

fn accepts_separate(attachment: LauncherAttachmentDeclaration) -> bool {
    matches!(
        attachment,
        LauncherAttachmentDeclaration::Separate
            | LauncherAttachmentDeclaration::ClusteredTail
            | LauncherAttachmentDeclaration::Either
    )
}

fn takes_value(class: LauncherOptionClassDeclaration) -> bool {
    matches!(
        class,
        LauncherOptionClassDeclaration::InlineSource
            | LauncherOptionClassDeclaration::Value
            | LauncherOptionClassDeclaration::ModuleSelector
            | LauncherOptionClassDeclaration::Preload
            | LauncherOptionClassDeclaration::Chdir
    )
}
