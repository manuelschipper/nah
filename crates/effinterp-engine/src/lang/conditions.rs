use effinterp_proto::{ByteSpan, Condition, ConditionKind};
use tree_sitter::Node;

/// Recover enclosing arms from syntax, independently of which calls the walker executes.
pub(super) fn tree_condition(source: &str, site: Node<'_>) -> Option<Condition> {
    let mut terms = Vec::new();
    let mut child = site;
    let mut ancestors = 0;
    while let Some(parent) = child.parent() {
        ancestors += 1;
        if ancestors > 256 {
            return Some(Condition::Widened);
        }
        let kind = parent.kind();
        if matches!(kind, "method_declaration" | "function_definition") {
            break;
        }
        let field_contains = |field| {
            parent.child_by_field_name(field).is_some_and(|node| {
                node.start_byte() <= site.start_byte() && node.end_byte() >= site.end_byte()
            })
        };
        if matches!(kind, "block" | "compound_statement" | "program") {
            let mut previous = child.prev_named_sibling();
            let mut scanned = 0;
            while let Some(prior) = previous {
                scanned += 1;
                if scanned > 64 {
                    return Some(Condition::Widened);
                }
                if prior.kind() == "if_statement" {
                    let yes = prior
                        .child_by_field_name("consequence")
                        .or_else(|| prior.child_by_field_name("body"))
                        .is_some_and(tree_stops);
                    let no = prior
                        .child_by_field_name("alternative")
                        .is_some_and(tree_stops);
                    if yes != no {
                        terms.push(Condition::from_source(
                            source,
                            ByteSpan {
                                start: prior.start_byte() as u32,
                                end: prior.end_byte() as u32,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                            true,
                        ));
                    }
                }
                previous = prior.prev_named_sibling();
            }
        }
        let selection = match kind {
            "anonymous_function"
            | "anonymous_function_creation_expression"
            | "lambda_expression"
            | "arrow_function" => Some((ConditionKind::Dispatch, 0, 2, false)),
            "if_statement" | "conditional_expression" | "ternary_expression" => {
                if field_contains("consequence") || field_contains("body") {
                    Some((ConditionKind::Branch, 0, 2, true))
                } else if field_contains("alternative")
                    || matches!(child.kind(), "else_clause" | "else_if_clause")
                {
                    Some((ConditionKind::Branch, 1, 2, true))
                } else {
                    None
                }
            }
            "while_statement"
            | "for_statement"
            | "enhanced_for_statement"
            | "foreach_statement" => {
                field_contains("body").then_some((ConditionKind::Loop, 0, 2, false))
            }
            "catch_clause" | "catch_block" => {
                Some((ConditionKind::UnresolvedExecution, 0, 2, false))
            }
            "binary_expression" => {
                let operator = parent
                    .child_by_field_name("operator")
                    .and_then(|n| source.get(n.byte_range()));
                match operator {
                    Some("&&" | "and") if field_contains("right") => {
                        Some((ConditionKind::ShortCircuit, 0, 2, true))
                    }
                    Some("||" | "or" | "??") if field_contains("right") => {
                        Some((ConditionKind::ShortCircuit, 1, 2, true))
                    }
                    _ => None,
                }
            }
            "switch_block" | "switch_body" => {
                let mut cursor = parent.walk();
                let arms: Vec<_> = parent.named_children(&mut cursor).take(65).collect();
                if arms.len() > 64 {
                    return Some(Condition::Widened);
                }
                if let Some(index) = arms.iter().position(|n| n.id() == child.id())
                    && index > 0
                    && arms[index - 1].kind() != "switch_rule"
                    && !arms[index - 1]
                        .named_child(arms[index - 1].named_child_count().saturating_sub(1))
                        .is_some_and(tree_stops)
                {
                    return Some(Condition::Widened);
                }
                arms.iter().position(|n| n.id() == child.id()).map(|index| {
                    (
                        ConditionKind::Branch,
                        index as u32,
                        arms.len() as u32
                            + u32::from(!arms.iter().any(|arm| {
                                source
                                    .get(arm.byte_range())
                                    .is_some_and(|text| text.trim_start().starts_with("default"))
                            })),
                        false,
                    )
                })
            }
            _ => None,
        };
        if let Some((kind, arm, arms, boolean)) = selection {
            terms.push(Condition::from_source(
                source,
                ByteSpan {
                    start: parent.start_byte() as u32,
                    end: parent.end_byte() as u32,
                },
                kind,
                arm,
                arms,
                true,
                boolean,
            ));
            if terms.len() >= effinterp_proto::MAX_CONDITION_DEPTH {
                return Some(Condition::Widened);
            }
        }
        child = parent;
    }
    Condition::compose(&terms)
}

fn tree_stops(mut node: Node<'_>) -> bool {
    for _ in 0..16 {
        match node.kind() {
            "return_statement" | "throw_statement" | "break_statement" | "continue_statement" => {
                return true;
            }
            "block" | "compound_statement" | "else_clause" => {
                let Some(child) = node.named_child(node.named_child_count().saturating_sub(1))
                else {
                    return false;
                };
                node = child;
            }
            _ => return false,
        }
    }
    false
}
