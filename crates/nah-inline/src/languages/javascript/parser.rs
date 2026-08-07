use tree_sitter::{Language, Node, ParseOptions, Parser};

use crate::InlineRefusal;

const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 512;
const MAX_PARSE_CALLBACKS: usize = 16 * 1024 * 1024;
const MAX_DIAGNOSTIC_SPANS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Span {
    start: usize,
    end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Admission {
    parser_error: bool,
    invalid_spans: Vec<Span>,
}

impl Admission {
    pub(super) fn executable(&self) -> bool {
        !self.parser_error && self.invalid_spans.is_empty()
    }
}

#[derive(Clone, Copy, Default)]
struct Context {
    in_function: bool,
    loops: usize,
    switches: usize,
}

pub(super) fn javascript(code: &str) -> Result<Admission, InlineRefusal> {
    parse(code, tree_sitter_javascript::LANGUAGE.into())
}

#[allow(dead_code)] // The TypeScript runtime routes in the next frontend tranche.
pub(super) fn typescript(code: &str) -> Result<Admission, InlineRefusal> {
    parse(code, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
}

#[allow(dead_code)] // The TSX file route lands with typed source routing.
pub(super) fn tsx(code: &str) -> Result<Admission, InlineRefusal> {
    parse(code, tree_sitter_typescript::LANGUAGE_TSX.into())
}

fn parse(code: &str, language: Language) -> Result<Admission, InlineRefusal> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .expect("the pinned JavaScript grammar matches tree-sitter");
    let mut callbacks = 0usize;
    let mut progress = |_: &tree_sitter::ParseState| {
        callbacks += 1;
        callbacks > MAX_PARSE_CALLBACKS
    };
    let mut read = |offset: usize, _| &code.as_bytes()[offset..];
    let tree = parser
        .parse_with_options(
            &mut read,
            None,
            Some(ParseOptions::new().progress_callback(&mut progress)),
        )
        .ok_or(InlineRefusal::WorkLimit)?;
    inspect(tree.root_node())
}

fn inspect(root: Node<'_>) -> Result<Admission, InlineRefusal> {
    let mut nodes = 0usize;
    let mut invalid_spans = Vec::new();
    let mut stack = vec![(root, 0usize, Context::default())];
    while let Some((node, depth, context)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(InlineRefusal::WorkLimit);
        }
        if (node.is_error() || node.is_missing() || early_error(node, context))
            && invalid_spans.len() < MAX_DIAGNOSTIC_SPANS
        {
            invalid_spans.push(Span {
                start: node.start_byte(),
                end: node.end_byte(),
            });
        }
        let child_context = context.for_children(node);
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, depth + 1, child_context));
            }
        }
    }
    Ok(Admission {
        parser_error: root.has_error(),
        invalid_spans,
    })
}

fn early_error(node: Node<'_>, context: Context) -> bool {
    match node.kind() {
        "return_statement" => !context.in_function,
        "break_statement" => {
            node.named_child_count() == 0 && context.loops == 0 && context.switches == 0
        }
        "continue_statement" => node.named_child_count() == 0 && context.loops == 0,
        _ => false,
    }
}

impl Context {
    fn for_children(self, node: Node<'_>) -> Self {
        match node.kind() {
            "function_declaration"
            | "function_expression"
            | "generator_function_declaration"
            | "generator_function"
            | "arrow_function"
            | "method_definition" => Self {
                in_function: true,
                ..Self::default()
            },
            "class_static_block" => Self::default(),
            "do_statement" | "for_in_statement" | "for_statement" | "while_statement" => Self {
                loops: self.loops + 1,
                ..self
            },
            "switch_statement" => Self {
                switches: self.switches + 1,
                ..self
            },
            _ => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Case {
        id: String,
        dialect: String,
        code: String,
        executable: bool,
    }

    #[test]
    fn frozen_parser_admission_cases_match() {
        for line in include_str!("../../../tests/fixtures/javascript_parser.jsonl").lines() {
            let case: Case = serde_json::from_str(line).unwrap();
            let admission = match case.dialect.as_str() {
                "javascript" => javascript(&case.code),
                "typescript" => typescript(&case.code),
                "tsx" => tsx(&case.code),
                dialect => panic!("{}: unknown dialect {dialect}", case.id),
            }
            .unwrap();
            assert_eq!(admission.executable(), case.executable, "{}", case.id);
        }
    }
}
