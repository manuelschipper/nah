use std::ops::Range;

use tree_sitter::{Node, ParseOptions, Parser};

use crate::InlineRefusal;

const MAX_DELIMITERS: usize = 4_096;
const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 512;
const MAX_PARSE_CALLBACKS: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dialect {
    Python2,
    Python3 { minor: Option<u16> },
    Common,
}

#[derive(Clone, Copy, Default)]
struct SyntaxContext {
    function_depth: usize,
    function_body: bool,
    async_body: bool,
    loops: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Span {
    start: usize,
    end: usize,
}

#[allow(dead_code)]
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
    Module,
    Block,
    Import,
    ImportFrom,
    AliasedImport,
    DottedName,
    ExpressionStatement,
    Assignment,
    AugmentedAssignment,
    Identifier,
    Call,
    ArgumentList,
    KeywordArgument,
    Attribute,
    String,
    StringStart,
    StringContent,
    StringEnd,
    ConcatenatedString,
    Integer,
    Float,
    True,
    False,
    None,
    List,
    Tuple,
    Set,
    Dictionary,
    Pair,
    ParenthesizedExpression,
    BinaryOperator,
    BooleanOperator,
    ComparisonOperator,
    NotOperator,
    UnaryOperator,
    ConditionalExpression,
    If,
    Elif,
    Else,
    For,
    While,
    Function,
    Parameters,
    DefaultParameter,
    TypedParameter,
    TypedDefaultParameter,
    Return,
    Raise,
    Pass,
    Break,
    Continue,
    DecoratedDefinition,
    Decorator,
    Class,
    With,
    WithClause,
    Try,
    Except,
    Finally,
    Lambda,
    Subscript,
    Slice,
    ListSplat,
    DictionarySplat,
    Interpolation,
    Generator,
    FormatSpecifier,
    TypeConversion,
    Exec,
    Print,
    Comment,
    Token,
    Unsupported,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HirField {
    Alias,
    Alternative,
    Argument,
    Arguments,
    Attribute,
    Body,
    Condition,
    Consequence,
    Definition,
    Expression,
    FormatSpecifier,
    Function,
    Key,
    Left,
    ModuleName,
    Name,
    Object,
    Operator,
    Operators,
    Parameters,
    ReturnType,
    Right,
    Type,
    TypeConversion,
    TypeParameters,
    Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HirNode {
    kind: HirKind,
    span: Span,
    field: Option<HirField>,
    children: Vec<HirNode>,
}

#[allow(dead_code)]
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
    Supported,
    Unsupported,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoverageSpan {
    span: Span,
    kind: CoverageKind,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
impl HirModule {
    pub(super) const fn root(&self) -> &HirNode {
        &self.root
    }

    pub(super) fn coverage(&self) -> &[CoverageSpan] {
        &self.coverage
    }

    pub(super) const fn opaque(&self) -> bool {
        self.opaque
    }
}

#[cfg(test)]
fn source_status(code: &str, program: &str) -> Result<bool, InlineRefusal> {
    lower(code, program).map(|module| !module.opaque())
}

pub(super) fn lower(code: &str, program: &str) -> Result<HirModule, InlineRefusal> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("the pinned Python grammar matches tree-sitter");
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
    let opaque = inspect(root, code, dialect(program))?;
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

fn inspect(root: Node<'_>, code: &str, dialect: Dialect) -> Result<bool, InlineRefusal> {
    let mut nodes = 0usize;
    let mut has_error = false;
    let mut incompatible_dialect = false;
    let mut structural = None;
    let mut masked_ranges = Vec::new();
    let mut stack = vec![(root, 0usize, SyntaxContext::default())];
    while let Some((node, depth, context)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(InlineRefusal::WorkLimit);
        }
        if matches!(
            node.kind(),
            "string" | "comment" | "string_start" | "string_content"
        ) {
            masked_ranges.push(node.byte_range());
        }
        incompatible_dialect |= incompatible_dialect_node(node, code, dialect);
        if node.is_error() || node.is_missing() {
            has_error = true;
            structural = structural.or_else(|| structural_error(node, code));
        }
        has_error |= early_error(node, context, code);
        if required_suite(node) == Some(false) {
            structural = Some(InlineRefusal::StructureMismatch);
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, depth + 1, context.for_child(node, index, code)));
            }
        }
    }
    delimiter_status(code, &mut masked_ranges)?;
    if let Some(refusal) = structural {
        return Err(refusal);
    }
    Ok(has_error || root.has_error() || incompatible_dialect)
}

fn early_error(node: Node<'_>, context: SyntaxContext, code: &str) -> bool {
    match node.kind() {
        "return_statement" | "yield" => !context.function_body,
        "break_statement" | "continue_statement" => context.loops == 0,
        "nonlocal_statement" => context.function_depth == 0,
        "await" => !context.async_body,
        "for_statement" | "with_statement" if direct_token(node, code, "async") => {
            !context.async_body
        }
        _ => false,
    }
}

impl SyntaxContext {
    fn for_child(self, parent: Node<'_>, index: usize, code: &str) -> Self {
        if parent.field_name_for_child(index as u32) != Some("body") {
            return self;
        }
        match parent.kind() {
            "function_definition" => Self {
                function_depth: self.function_depth + 1,
                function_body: true,
                async_body: direct_token(parent, code, "async"),
                loops: 0,
            },
            "class_definition" => Self {
                function_body: false,
                async_body: false,
                loops: 0,
                ..self
            },
            "for_statement" | "while_statement" => Self {
                loops: self.loops + 1,
                ..self
            },
            _ => self,
        }
    }
}

fn incompatible_dialect_node(node: Node<'_>, code: &str, dialect: Dialect) -> bool {
    if matches!(node.kind(), "print_statement" | "exec_statement") {
        return dialect != Dialect::Python2;
    }
    let Some(required_minor) = python3_minor(node, code) else {
        return false;
    };
    match dialect {
        Dialect::Python2 | Dialect::Common => true,
        Dialect::Python3 { minor: Some(minor) } => minor < required_minor,
        Dialect::Python3 { minor: None } => false,
    }
}

fn python3_minor(node: Node<'_>, code: &str) -> Option<u16> {
    let required = match node.kind() {
        "type_alias_statement" | "type_parameter" => 12,
        "match_statement" | "case_clause" | "case_pattern" => 10,
        "named_expression" | "positional_separator" => 8,
        "interpolation" | "format_specifier" | "type_conversion" => 6,
        "async" => 5,
        "await" => 5,
        "nonlocal_statement"
        | "keyword_separator"
        | "typed_default_parameter"
        | "typed_parameter" => 0,
        "list_splat" | "parenthesized_list_splat"
            if node
                .parent()
                .is_some_and(|parent| matches!(parent.kind(), "list" | "set" | "tuple")) =>
        {
            5
        }
        "dictionary_splat"
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "dictionary") =>
        {
            5
        }
        "string_start" if string_prefix(node, code).contains('f') => 6,
        "assignment" if node.child_by_field_name("type").is_some() => 6,
        "binary_operator" if direct_token(node, code, "@") => 5,
        "yield" if direct_token(node, code, "from") => 3,
        "raise_statement" if direct_token(node, code, "from") => 0,
        "except_clause" if direct_token(node, code, "*") => 11,
        "integer" | "float" if node_text(node, code).contains('_') => 6,
        _ => return None,
    };
    Some(required)
}

fn node_text<'a>(node: Node<'_>, code: &'a str) -> &'a str {
    code.get(node.byte_range()).unwrap_or_default()
}

fn string_prefix(node: Node<'_>, code: &str) -> String {
    node_text(node, code)
        .chars()
        .take_while(|character| !matches!(character, '\'' | '"'))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn direct_token(node: Node<'_>, code: &str, expected: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index).is_some_and(|child| {
            !child.is_named()
                && code
                    .get(child.byte_range())
                    .is_some_and(|text| text == expected)
        })
    })
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
        "module" => HirKind::Module,
        "block" => HirKind::Block,
        "import_statement" => HirKind::Import,
        "import_from_statement" | "future_import_statement" => HirKind::ImportFrom,
        "aliased_import" => HirKind::AliasedImport,
        "dotted_name" | "relative_import" => HirKind::DottedName,
        "expression_statement" => HirKind::ExpressionStatement,
        "assignment" | "named_expression" => HirKind::Assignment,
        "augmented_assignment" => HirKind::AugmentedAssignment,
        "identifier" => HirKind::Identifier,
        "call" => HirKind::Call,
        "argument_list" => HirKind::ArgumentList,
        "keyword_argument" => HirKind::KeywordArgument,
        "attribute" => HirKind::Attribute,
        "string" => HirKind::String,
        "string_start" => HirKind::StringStart,
        "string_content" => HirKind::StringContent,
        "string_end" => HirKind::StringEnd,
        "concatenated_string" => HirKind::ConcatenatedString,
        "integer" => HirKind::Integer,
        "float" => HirKind::Float,
        "true" => HirKind::True,
        "false" => HirKind::False,
        "none" => HirKind::None,
        "list" => HirKind::List,
        "tuple" | "expression_list" | "pattern_list" | "tuple_pattern" => HirKind::Tuple,
        "set" => HirKind::Set,
        "dictionary" => HirKind::Dictionary,
        "pair" => HirKind::Pair,
        "parenthesized_expression" => HirKind::ParenthesizedExpression,
        "binary_operator" => HirKind::BinaryOperator,
        "boolean_operator" => HirKind::BooleanOperator,
        "comparison_operator" => HirKind::ComparisonOperator,
        "not_operator" => HirKind::NotOperator,
        "unary_operator" => HirKind::UnaryOperator,
        "conditional_expression" => HirKind::ConditionalExpression,
        "if_statement" => HirKind::If,
        "elif_clause" => HirKind::Elif,
        "else_clause" => HirKind::Else,
        "for_statement" => HirKind::For,
        "while_statement" => HirKind::While,
        "function_definition" => HirKind::Function,
        "parameters" => HirKind::Parameters,
        "default_parameter" => HirKind::DefaultParameter,
        "typed_parameter" => HirKind::TypedParameter,
        "typed_default_parameter" => HirKind::TypedDefaultParameter,
        "return_statement" => HirKind::Return,
        "raise_statement" => HirKind::Raise,
        "pass_statement" => HirKind::Pass,
        "break_statement" => HirKind::Break,
        "continue_statement" => HirKind::Continue,
        "decorated_definition" => HirKind::DecoratedDefinition,
        "decorator" => HirKind::Decorator,
        "class_definition" => HirKind::Class,
        "with_statement" => HirKind::With,
        "with_clause" => HirKind::WithClause,
        "try_statement" => HirKind::Try,
        "except_clause" => HirKind::Except,
        "finally_clause" => HirKind::Finally,
        "lambda" => HirKind::Lambda,
        "subscript" => HirKind::Subscript,
        "slice" => HirKind::Slice,
        "list_splat" | "parenthesized_list_splat" => HirKind::ListSplat,
        "dictionary_splat" => HirKind::DictionarySplat,
        "interpolation" => HirKind::Interpolation,
        "generator_expression" => HirKind::Generator,
        "format_specifier" => HirKind::FormatSpecifier,
        "type_conversion" => HirKind::TypeConversion,
        "exec_statement" => HirKind::Exec,
        "print_statement" => HirKind::Print,
        "comment" => HirKind::Comment,
        kind if !node.is_named() && !kind.is_empty() => HirKind::Token,
        _ => HirKind::Unsupported,
    }
}

fn hir_field(field: &str) -> Option<HirField> {
    match field {
        "alias" => Some(HirField::Alias),
        "alternative" => Some(HirField::Alternative),
        "argument" => Some(HirField::Argument),
        "arguments" => Some(HirField::Arguments),
        "attribute" => Some(HirField::Attribute),
        "body" => Some(HirField::Body),
        "condition" => Some(HirField::Condition),
        "consequence" => Some(HirField::Consequence),
        "definition" => Some(HirField::Definition),
        "expression" => Some(HirField::Expression),
        "format_specifier" => Some(HirField::FormatSpecifier),
        "function" => Some(HirField::Function),
        "key" => Some(HirField::Key),
        "left" => Some(HirField::Left),
        "module_name" => Some(HirField::ModuleName),
        "name" => Some(HirField::Name),
        "object" => Some(HirField::Object),
        "operator" => Some(HirField::Operator),
        "operators" => Some(HirField::Operators),
        "parameters" => Some(HirField::Parameters),
        "return_type" => Some(HirField::ReturnType),
        "right" => Some(HirField::Right),
        "type" => Some(HirField::Type),
        "type_conversion" => Some(HirField::TypeConversion),
        "type_parameters" => Some(HirField::TypeParameters),
        "value" => Some(HirField::Value),
        _ => None,
    }
}

fn collect_coverage(node: &HirNode, coverage: &mut Vec<CoverageSpan>) {
    if node.kind == HirKind::Comment {
        return;
    }
    let kind = match node.kind {
        HirKind::Unsupported => Some(CoverageKind::Unsupported),
        HirKind::Error => Some(CoverageKind::Error),
        _ if node.children.is_empty() => Some(CoverageKind::Supported),
        _ => None,
    };
    if let Some(kind) = kind {
        if node.span.start < node.span.end {
            coverage.push(CoverageSpan {
                span: node.span,
                kind,
            });
        }
        return;
    }
    for child in &node.children {
        collect_coverage(child, coverage);
    }
}

fn delimiter_status(code: &str, masked_ranges: &mut [Range<usize>]) -> Result<(), InlineRefusal> {
    masked_ranges.sort_unstable_by_key(|range| (range.start, usize::MAX - range.end));
    let mut range = 0usize;
    let mut delimiters = 0usize;
    let mut stack = Vec::new();
    for (index, byte) in code.bytes().enumerate() {
        while masked_ranges
            .get(range)
            .is_some_and(|masked| index >= masked.end)
        {
            range += 1;
        }
        if masked_ranges
            .get(range)
            .is_some_and(|masked| masked.contains(&index))
        {
            continue;
        }
        match byte {
            b'(' | b'[' | b'{' => {
                delimiters += 1;
                if delimiters > MAX_DELIMITERS {
                    return Err(InlineRefusal::DelimiterLimit);
                }
                stack.push(byte);
            }
            b')' | b']' | b'}' => {
                let matches = matches!(
                    (stack.pop(), byte),
                    (Some(b'('), b')') | (Some(b'['), b']') | (Some(b'{'), b'}')
                );
                if !matches {
                    return Err(InlineRefusal::StructureMismatch);
                }
            }
            _ => {}
        }
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(InlineRefusal::StructureMismatch)
    }
}

fn structural_error(node: Node<'_>, code: &str) -> Option<InlineRefusal> {
    let end = code.trim_end().len();
    let text = code.get(node.byte_range()).unwrap_or_default().trim();
    if text.starts_with([')', ']', '}']) {
        return Some(InlineRefusal::StructureMismatch);
    }
    if node.is_missing() && node.start_byte() >= end {
        return Some(InlineRefusal::StructureIncomplete);
    }
    if text.starts_with(['\'', '"']) {
        return Some(InlineRefusal::StructureIncomplete);
    }
    if node.end_byte() >= end
        && (text.ends_with(['(', '[', '{'])
            || matches!(node.kind(), "string_start" | "string_content"))
    {
        return Some(InlineRefusal::StructureIncomplete);
    }
    None
}

fn required_suite(node: Node<'_>) -> Option<bool> {
    let field = match node.kind() {
        "if_statement" | "elif_clause" | "case_clause" => "consequence",
        "class_definition"
        | "function_definition"
        | "for_statement"
        | "while_statement"
        | "with_statement"
        | "try_statement"
        | "match_statement"
        | "else_clause" => "body",
        "except_clause" | "finally_clause" => {
            return node
                .named_children(&mut node.walk())
                .find(|child| child.kind() == "block")
                .map(|body| valid_suite(node, body))
                .or(Some(false));
        }
        _ => return None,
    };
    let Some(body) = node.child_by_field_name(field) else {
        return Some(false);
    };
    Some(valid_suite(node, body))
}

fn valid_suite(node: Node<'_>, body: Node<'_>) -> bool {
    if body.kind() != "block" {
        return body.start_position().row == node.start_position().row;
    }
    let mut cursor = body.walk();
    let Some(first) = body.named_children(&mut cursor).next() else {
        return false;
    };
    first.start_position().row == node.start_position().row
        || first.start_position().column > node.start_position().column
}

fn dialect(program: &str) -> Dialect {
    if matches!(program, "python2" | "pypy2")
        || program.starts_with("python2.")
        || program.starts_with("pypy2.")
    {
        Dialect::Python2
    } else if matches!(program, "python3" | "pypy3") {
        Dialect::Python3 { minor: None }
    } else if let Some(version) = program
        .strip_prefix("python3.")
        .or_else(|| program.strip_prefix("pypy3."))
    {
        Dialect::Python3 {
            minor: version.strip_suffix('t').unwrap_or(version).parse().ok(),
        }
    } else {
        Dialect::Common
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialects_admit_only_their_reviewed_syntax() {
        assert_eq!(source_status("print 'ok'", "python2"), Ok(true));
        assert_eq!(source_status("print 'ok'", "python3"), Ok(false));
        assert_eq!(source_status("print 'ok'", "python"), Ok(false));
        assert_eq!(
            source_status("match value:\n    case 1: pass", "python3"),
            Ok(true)
        );
        assert_eq!(
            source_status("match value:\n    case 1: pass", "python2"),
            Ok(false)
        );
        assert_eq!(
            source_status("import os; os.system(f'rm -rf /')", "python2"),
            Ok(false)
        );
        assert_eq!(
            source_status("import os; os.system(f'rm -rf /')", "python"),
            Ok(false)
        );
        assert_eq!(source_status("value = f'{name}'", "python3.5"), Ok(false));
        assert_eq!(source_status("value = f'{name}'", "python3.6"), Ok(true));
        assert_eq!(
            source_status("match value:\n    case 1: pass", "python3.9"),
            Ok(false)
        );
        assert_eq!(
            source_status("match value:\n    case 1: pass", "python3.10"),
            Ok(true)
        );
        assert_eq!(source_status("(value := 1)", "python3.7"), Ok(false));
        assert_eq!(source_status("(value := 1)", "python3.8"), Ok(true));
        assert_eq!(source_status("type Value = int", "python3.11"), Ok(false));
        assert_eq!(source_status("type Value = int", "python3.12"), Ok(true));
        assert_eq!(source_status("value = 1_000", "python3.5"), Ok(false));
        assert_eq!(source_status("value = 1_000", "python3.6"), Ok(true));
        assert_eq!(
            source_status("async def run():\n    pass", "python3.4"),
            Ok(false)
        );
        assert_eq!(
            source_status("async def run():\n    pass", "python3.5"),
            Ok(true)
        );
    }

    #[test]
    fn compile_time_control_flow_errors_make_the_unit_opaque() {
        for code in [
            "return\nimport shutil; shutil.rmtree('/')",
            "break\nimport shutil; shutil.rmtree('/')",
            "continue\nimport shutil; shutil.rmtree('/')",
            "yield 1\nimport shutil; shutil.rmtree('/')",
            "await task\nimport shutil; shutil.rmtree('/')",
            "nonlocal value\nimport shutil; shutil.rmtree('/')",
            "for value in []:\n    pass\nelse:\n    break",
            "async for value in values:\n    pass",
        ] {
            assert_eq!(source_status(code, "python3"), Ok(false), "{code}");
        }
        for code in [
            "def value():\n    return 1",
            "while True:\n    break",
            "async def value():\n    await task",
            "def outer():\n    class Value:\n        def method(self):\n            return 1",
        ] {
            assert_eq!(source_status(code, "python3"), Ok(true), "{code}");
        }
    }

    #[test]
    fn structural_failures_keep_existing_refusals() {
        assert_eq!(
            source_status("import shutil; shutil.rmtree('/')]", "python3"),
            Err(InlineRefusal::StructureMismatch)
        );
        assert_eq!(
            source_status("print('unterminated)", "python3"),
            Err(InlineRefusal::StructureIncomplete)
        );
        assert_eq!(
            source_status("if True:\nos.system('x')", "python3"),
            Err(InlineRefusal::StructureMismatch)
        );
    }

    #[test]
    fn future_or_unclassified_recovery_is_opaque() {
        assert_eq!(source_status("value = @", "python3"), Ok(false));
    }

    #[test]
    fn lowering_owns_nodes_and_accounts_for_non_trivia_bytes() {
        let code = "import os\n# data\ntarget = f'/tmp/{name}'\nos.remove(target)";
        let comment = code.find("# data").unwrap()..code.find("\ntarget").unwrap();
        let module = lower(code, "python3").unwrap();
        assert!(!module.opaque());
        assert_eq!(module.root().kind(), HirKind::Module);
        assert!(module.coverage().iter().all(|covered| {
            covered.span().start() < covered.span().end()
                && covered.kind() == CoverageKind::Supported
        }));
        for (index, byte) in code.bytes().enumerate() {
            if byte.is_ascii_whitespace() || comment.contains(&index) {
                continue;
            }
            assert!(
                module
                    .coverage()
                    .iter()
                    .any(|covered| covered.span().start() <= index && index < covered.span().end())
            );
        }
    }

    #[test]
    fn unsupported_nodes_are_explicit_boundaries() {
        let module = lower("value = [x for x in items]", "python3").unwrap();
        assert!(!module.opaque());
        assert!(
            module
                .coverage()
                .iter()
                .any(|covered| covered.kind() == CoverageKind::Unsupported)
        );
    }
}
