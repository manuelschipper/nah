use tree_sitter::{Language, Node, ParseOptions, Parser};

use crate::InlineRefusal;

const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 512;
const MAX_PARSE_CALLBACKS: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Span {
    start: usize,
    end: usize,
}

impl Span {
    pub(super) const fn start(self) -> usize {
        self.start
    }

    pub(super) const fn end(self) -> usize {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HirKind {
    Program,
    StatementBlock,
    ExpressionStatement,
    LexicalDeclaration,
    VariableDeclaration,
    VariableDeclarator,
    FunctionDeclaration,
    FunctionExpression,
    ArrowFunction,
    FormalParameters,
    Identifier,
    PropertyIdentifier,
    ShorthandPropertyIdentifier,
    ObjectPattern,
    ArrayPattern,
    AssignmentPattern,
    RestPattern,
    CallExpression,
    Arguments,
    MemberExpression,
    SubscriptExpression,
    String,
    TemplateString,
    StringFragment,
    EscapeSequence,
    TemplateSubstitution,
    Number,
    True,
    False,
    Null,
    Undefined,
    Array,
    Object,
    Pair,
    ComputedPropertyName,
    MethodDefinition,
    ParenthesizedExpression,
    SequenceExpression,
    BinaryExpression,
    UnaryExpression,
    TernaryExpression,
    AssignmentExpression,
    AugmentedAssignmentExpression,
    UpdateExpression,
    IfStatement,
    ElseClause,
    WhileStatement,
    ReturnStatement,
    ThrowStatement,
    TryStatement,
    CatchClause,
    FinallyClause,
    ImportStatement,
    ImportClause,
    NamespaceImport,
    NamedImports,
    ImportSpecifier,
    SpreadElement,
    Comment,
    Token,
    Unsupported,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HirField {
    Alias,
    Alternative,
    Arguments,
    Body,
    Condition,
    Consequence,
    Constructor,
    Finalizer,
    Function,
    Handler,
    Index,
    Key,
    Kind,
    Left,
    Name,
    Object,
    Operator,
    Parameter,
    Parameters,
    Property,
    Right,
    Source,
    Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HirNode {
    kind: HirKind,
    span: Span,
    field: Option<HirField>,
    children: Vec<HirNode>,
}

impl HirNode {
    pub(super) const fn kind(&self) -> HirKind {
        self.kind
    }

    pub(super) const fn span(&self) -> Span {
        self.span
    }

    pub(super) const fn field(&self) -> Option<HirField> {
        self.field
    }

    pub(super) fn children(&self) -> &[Self] {
        &self.children
    }

    pub(super) fn child(&self, field: HirField) -> Option<&Self> {
        self.children
            .iter()
            .find(|child| child.field == Some(field))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoverageKind {
    Unsupported,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoverageSpan {
    span: Span,
    kind: CoverageKind,
}

impl CoverageSpan {
    pub(super) const fn span(self) -> Span {
        self.span
    }

    pub(super) const fn kind(self) -> CoverageKind {
        self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HirModule {
    root: HirNode,
    coverage: Vec<CoverageSpan>,
    opaque: bool,
}

impl HirModule {
    pub(super) const fn root(&self) -> &HirNode {
        &self.root
    }

    pub(super) fn coverage(&self) -> &[CoverageSpan] {
        &self.coverage
    }

    pub(super) const fn executable(&self) -> bool {
        !self.opaque
    }
}

#[derive(Clone, Copy, Default)]
struct Context {
    in_function: bool,
    loops: usize,
    switches: usize,
}

pub(super) fn javascript(code: &str) -> Result<HirModule, InlineRefusal> {
    parse(code, tree_sitter_javascript::LANGUAGE.into())
}

#[allow(dead_code)] // The TypeScript runtime routes in the next frontend tranche.
pub(super) fn typescript(code: &str) -> Result<HirModule, InlineRefusal> {
    parse(code, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
}

#[allow(dead_code)] // The TSX file route lands with typed source routing.
pub(super) fn tsx(code: &str) -> Result<HirModule, InlineRefusal> {
    parse(code, tree_sitter_typescript::LANGUAGE_TSX.into())
}

fn parse(code: &str, language: Language) -> Result<HirModule, InlineRefusal> {
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
    let root = tree.root_node();
    let opaque = inspect(root)?;
    let mut nodes = 0usize;
    let root = lower_node(root, None, 0, &mut nodes)?;
    let mut coverage = Vec::new();
    collect_coverage(&root, &mut coverage);
    coverage.sort_unstable_by_key(|covered| (covered.span.start, covered.span.end));
    Ok(HirModule {
        root,
        coverage,
        opaque,
    })
}

fn inspect(root: Node<'_>) -> Result<bool, InlineRefusal> {
    let mut nodes = 0usize;
    let mut opaque = root.has_error();
    let mut stack = vec![(root, 0usize, Context::default())];
    while let Some((node, depth, context)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(InlineRefusal::WorkLimit);
        }
        opaque |= node.is_error() || node.is_missing() || early_error(node, context);
        let child_context = context.for_children(node);
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, depth + 1, child_context));
            }
        }
    }
    Ok(opaque)
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

fn lower_node(
    node: Node<'_>,
    field: Option<HirField>,
    depth: usize,
    nodes: &mut usize,
) -> Result<HirNode, InlineRefusal> {
    *nodes += 1;
    if *nodes > MAX_NODES || depth > MAX_DEPTH {
        return Err(InlineRefusal::WorkLimit);
    }
    let mut children = Vec::with_capacity(node.child_count());
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        let field = node.field_name_for_child(index as u32).and_then(hir_field);
        children.push(lower_node(child, field, depth + 1, nodes)?);
    }
    Ok(HirNode {
        kind: hir_kind(node),
        span: Span {
            start: node.start_byte(),
            end: node.end_byte(),
        },
        field,
        children,
    })
}

fn hir_kind(node: Node<'_>) -> HirKind {
    if node.is_error() || node.is_missing() {
        return HirKind::Error;
    }
    match node.kind() {
        "program" => HirKind::Program,
        "statement_block" => HirKind::StatementBlock,
        "expression_statement" => HirKind::ExpressionStatement,
        "lexical_declaration" => HirKind::LexicalDeclaration,
        "variable_declaration" => HirKind::VariableDeclaration,
        "variable_declarator" => HirKind::VariableDeclarator,
        "function_declaration" => HirKind::FunctionDeclaration,
        "function_expression" => HirKind::FunctionExpression,
        "arrow_function" => HirKind::ArrowFunction,
        "formal_parameters" => HirKind::FormalParameters,
        "identifier" => HirKind::Identifier,
        "property_identifier" => HirKind::PropertyIdentifier,
        "shorthand_property_identifier" => HirKind::ShorthandPropertyIdentifier,
        "object_pattern" => HirKind::ObjectPattern,
        "array_pattern" => HirKind::ArrayPattern,
        "assignment_pattern" => HirKind::AssignmentPattern,
        "rest_pattern" => HirKind::RestPattern,
        "call_expression" => HirKind::CallExpression,
        "arguments" => HirKind::Arguments,
        "member_expression" => HirKind::MemberExpression,
        "subscript_expression" => HirKind::SubscriptExpression,
        "string" => HirKind::String,
        "template_string" => HirKind::TemplateString,
        "string_fragment" => HirKind::StringFragment,
        "escape_sequence" => HirKind::EscapeSequence,
        "template_substitution" => HirKind::TemplateSubstitution,
        "number" => HirKind::Number,
        "true" => HirKind::True,
        "false" => HirKind::False,
        "null" => HirKind::Null,
        "undefined" => HirKind::Undefined,
        "array" => HirKind::Array,
        "object" => HirKind::Object,
        "pair" | "pair_pattern" => HirKind::Pair,
        "computed_property_name" => HirKind::ComputedPropertyName,
        "method_definition" => HirKind::MethodDefinition,
        "parenthesized_expression" => HirKind::ParenthesizedExpression,
        "sequence_expression" => HirKind::SequenceExpression,
        "binary_expression" => HirKind::BinaryExpression,
        "unary_expression" => HirKind::UnaryExpression,
        "ternary_expression" => HirKind::TernaryExpression,
        "assignment_expression" => HirKind::AssignmentExpression,
        "augmented_assignment_expression" => HirKind::AugmentedAssignmentExpression,
        "update_expression" => HirKind::UpdateExpression,
        "if_statement" => HirKind::IfStatement,
        "else_clause" => HirKind::ElseClause,
        "while_statement" => HirKind::WhileStatement,
        "return_statement" => HirKind::ReturnStatement,
        "throw_statement" => HirKind::ThrowStatement,
        "try_statement" => HirKind::TryStatement,
        "catch_clause" => HirKind::CatchClause,
        "finally_clause" => HirKind::FinallyClause,
        "import_statement" => HirKind::ImportStatement,
        "import_clause" => HirKind::ImportClause,
        "namespace_import" => HirKind::NamespaceImport,
        "named_imports" => HirKind::NamedImports,
        "import_specifier" => HirKind::ImportSpecifier,
        "spread_element" => HirKind::SpreadElement,
        "comment" => HirKind::Comment,
        kind if !node.is_named() && !kind.is_empty() => HirKind::Token,
        _ => HirKind::Unsupported,
    }
}

fn hir_field(field: &str) -> Option<HirField> {
    match field {
        "alias" => Some(HirField::Alias),
        "alternative" => Some(HirField::Alternative),
        "arguments" => Some(HirField::Arguments),
        "body" => Some(HirField::Body),
        "condition" => Some(HirField::Condition),
        "consequence" => Some(HirField::Consequence),
        "constructor" => Some(HirField::Constructor),
        "finalizer" => Some(HirField::Finalizer),
        "function" => Some(HirField::Function),
        "handler" => Some(HirField::Handler),
        "index" => Some(HirField::Index),
        "key" => Some(HirField::Key),
        "kind" => Some(HirField::Kind),
        "left" => Some(HirField::Left),
        "name" => Some(HirField::Name),
        "object" => Some(HirField::Object),
        "operator" => Some(HirField::Operator),
        "parameter" => Some(HirField::Parameter),
        "parameters" => Some(HirField::Parameters),
        "property" => Some(HirField::Property),
        "right" => Some(HirField::Right),
        "source" => Some(HirField::Source),
        "value" => Some(HirField::Value),
        _ => None,
    }
}

fn collect_coverage(node: &HirNode, coverage: &mut Vec<CoverageSpan>) {
    let kind = match node.kind {
        HirKind::Unsupported => Some(CoverageKind::Unsupported),
        HirKind::Error => Some(CoverageKind::Error),
        _ => None,
    };
    if let Some(kind) = kind {
        coverage.push(CoverageSpan {
            span: node.span,
            kind,
        });
    }
    for child in &node.children {
        collect_coverage(child, coverage);
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
            let module = match case.dialect.as_str() {
                "javascript" => javascript(&case.code),
                "typescript" => typescript(&case.code),
                "tsx" => tsx(&case.code),
                dialect => panic!("{}: unknown dialect {dialect}", case.id),
            }
            .unwrap();
            assert_eq!(module.executable(), case.executable, "{}", case.id);
        }
    }

    #[test]
    fn lowering_owns_spans_and_marks_unsupported_boundaries() {
        let code = "const fs = require('node:fs'); switch (value) { default: fs.rmSync('/') }";
        let module = javascript(code).unwrap();

        assert_eq!(module.root().kind(), HirKind::Program);
        assert_eq!(
            module.root().span(),
            Span {
                start: 0,
                end: code.len()
            }
        );
        assert!(module.coverage().iter().any(|covered| {
            covered.kind() == CoverageKind::Unsupported
                && &code[covered.span().start()..covered.span().end()]
                    == "switch (value) { default: fs.rmSync('/') }"
        }));
    }

    #[test]
    fn malformed_nodes_are_owned_error_boundaries() {
        let module = javascript("const value = ; execute()").unwrap();

        assert!(!module.executable());
        assert!(
            module
                .coverage()
                .iter()
                .any(|covered| covered.kind() == CoverageKind::Error)
        );
    }
}
