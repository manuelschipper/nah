use tree_sitter::{Node, ParseOptions, Parser};

use crate::InlineRefusal;

const MAX_DELIMITERS: usize = 4_096;
const MAX_NODES: usize = 1_048_576;
const MAX_DEPTH: usize = 512;
const MAX_PARSE_CALLBACKS: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Dialect {
    Python2,
    Python3,
    Common,
}

pub(super) fn source_status(code: &str, program: &str) -> Result<bool, InlineRefusal> {
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
    inspect(tree.root_node(), code, dialect(program))
}

fn inspect(root: Node<'_>, code: &str, dialect: Dialect) -> Result<bool, InlineRefusal> {
    let mut nodes = 0usize;
    let mut has_error = false;
    let mut incompatible_dialect = false;
    let mut structural = None;
    let mut masked_ranges = Vec::new();
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(InlineRefusal::WorkLimit);
        }
        if matches!(node.kind(), "string" | "comment") {
            masked_ranges.push(node.byte_range());
        }
        incompatible_dialect |= match dialect {
            Dialect::Python2 => matches!(node.kind(), "match_statement" | "type_alias_statement"),
            Dialect::Python3 | Dialect::Common => {
                matches!(node.kind(), "print_statement" | "exec_statement")
            }
        };
        if node.is_error() || node.is_missing() {
            has_error = true;
            structural = structural.or_else(|| structural_error(node, code));
        }
        if required_suite(node) == Some(false) {
            structural = Some(InlineRefusal::StructureMismatch);
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, depth + 1));
            }
        }
    }
    delimiter_status(code, &mut masked_ranges)?;
    if let Some(refusal) = structural {
        return Err(refusal);
    }
    if has_error || root.has_error() || incompatible_dialect {
        return Ok(false);
    }
    Ok(true)
}

fn delimiter_status(
    code: &str,
    masked_ranges: &mut [std::ops::Range<usize>],
) -> Result<(), InlineRefusal> {
    masked_ranges.sort_unstable_by_key(|range| range.start);
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
    if !matches!(
        node.kind(),
        "class_definition"
            | "function_definition"
            | "if_statement"
            | "for_statement"
            | "while_statement"
            | "with_statement"
            | "try_statement"
            | "match_statement"
    ) {
        return None;
    }
    let field = if node.kind() == "if_statement" {
        "consequence"
    } else {
        "body"
    };
    let Some(body) = node.child_by_field_name(field) else {
        return Some(false);
    };
    if body.kind() != "block" {
        return Some(body.start_position().row == node.start_position().row);
    }
    let mut cursor = body.walk();
    let Some(first) = body.named_children(&mut cursor).next() else {
        return Some(false);
    };
    Some(
        first.start_position().row == node.start_position().row
            || first.start_position().column > node.start_position().column,
    )
}

fn dialect(program: &str) -> Dialect {
    if matches!(program, "python2" | "pypy2")
        || program.starts_with("python2.")
        || program.starts_with("pypy2.")
    {
        Dialect::Python2
    } else if matches!(program, "python3" | "pypy3")
        || program.starts_with("python3.")
        || program.starts_with("pypy3.")
    {
        Dialect::Python3
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
}
