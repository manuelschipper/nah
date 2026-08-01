//! Detects structurally unbounded background process creation.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use tree_sitter::Node;

use super::{text, walk_nodes};

pub(super) fn detect(root: Node<'_>, source: &str) -> (bool, bool) {
    fn command_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
        (node.kind() == "command")
            .then(|| node.child_by_field_name("name"))
            .flatten()
            .map(|name| text(name, source))
    }

    fn pipeline_recurses(node: Node<'_>, source: &str, name: &str) -> bool {
        walk_nodes(node, true, |node| node.kind() == "function_definition").any(|node| {
            if node.kind() != "pipeline" {
                return false;
            }
            let mut cursor = node.walk();
            let names = node
                .named_children(&mut cursor)
                .filter_map(|child| command_name(child, source))
                .collect::<Vec<_>>();
            names.len() >= 2 && names.iter().all(|command| *command == name)
        })
    }

    fn recursive_invocations(node: Node<'_>, source: &str, name: &str) -> usize {
        walk_nodes(node, true, |node| node.kind() == "function_definition")
            .filter(|node| command_name(*node, source) == Some(name))
            .count()
    }

    fn contains_command(node: Node<'_>, source: &str, name: &str) -> bool {
        walk_nodes(node, true, |node| node.kind() == "function_definition")
            .any(|node| command_name(node, source) == Some(name))
    }

    fn command_count(node: Node<'_>, source: &str) -> usize {
        walk_nodes(node, true, |_| false)
            .filter(|node| command_name(*node, source).is_some())
            .count()
    }

    fn static_literal_truth(value: &str) -> Option<bool> {
        let value = value.trim();
        if value.len() >= 2
            && ((value.starts_with('\'') && value.ends_with('\''))
                || (value.starts_with('"') && value.ends_with('"')))
        {
            let inner = &value[1..value.len() - 1];
            if value.starts_with('"') && inner.contains(['$', '`', '\\']) {
                return None;
            }
            return Some(!inner.is_empty());
        }
        (!value.is_empty()
            && !value.contains([
                '$', '`', '\\', '*', '?', '[', ']', '(', ')', '<', '>', '&', '|', ';',
            ])
            && !value.starts_with('-'))
        .then_some(true)
    }

    fn static_arithmetic_truth(value: &str) -> Option<bool> {
        let value = value.trim();
        let value = value
            .strip_prefix("((")
            .and_then(|value| value.strip_suffix("))"))
            .unwrap_or(value)
            .trim();
        let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
        if digits.is_empty()
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || digits.len() > 1 && digits.starts_with('0')
        {
            return None;
        }
        value.parse::<i128>().ok().map(|value| value != 0)
    }

    fn static_condition_truth(node: Node<'_>, source: &str) -> Option<bool> {
        let condition = text(node, source);
        let words = condition.split_whitespace().collect::<Vec<_>>();
        if let ["[[", value, "]]"] | ["[", value, "]"] | ["test", value] = words.as_slice() {
            return static_literal_truth(value);
        }
        if condition.trim_start().starts_with("((") {
            return static_arithmetic_truth(condition);
        }
        if command_count(node, source) != 1 {
            return None;
        }
        if ["true", ":", "/bin/true", "/usr/bin/true"]
            .iter()
            .any(|name| contains_command(node, source, name))
        {
            Some(true)
        } else if ["false", "/bin/false", "/usr/bin/false"]
            .iter()
            .any(|name| contains_command(node, source, name))
        {
            Some(false)
        } else {
            None
        }
    }

    fn loop_truth(node: Node<'_>, source: &str) -> Option<bool> {
        match node.kind() {
            "while_statement" => {
                let until = node.child(0).is_some_and(|child| child.kind() == "until");
                node.child_by_field_name("condition")
                    .and_then(|condition| static_condition_truth(condition, source))
                    .map(|truth| if until { !truth } else { truth })
            }
            "c_style_for_statement" => {
                let mut cursor = node.walk();
                let mut conditions = node.children_by_field_name("condition", &mut cursor);
                let first = conditions.next();
                if conditions.next().is_some() {
                    None
                } else {
                    first
                        .map(|condition| static_arithmetic_truth(text(condition, source)))
                        .unwrap_or(Some(true))
                }
            }
            _ => None,
        }
    }

    fn last_background<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
        walk_nodes(node, false, |node| node.kind() == "function_definition")
            .filter(|node| !node.is_named() && text(*node, source) == "&")
            .max_by_key(Node::start_byte)
    }

    fn backgrounds_recursion(node: Node<'_>, source: &str, name: &str) -> bool {
        walk_nodes(node, true, |node| node.kind() == "function_definition").any(|node| {
            let mut previous_named = None;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if !child.is_named() && text(child, source) == "&" {
                    if previous_named
                        .is_some_and(|previous| recursive_invocations(previous, source, name) > 0)
                    {
                        return true;
                    }
                } else if child.is_named() {
                    previous_named = Some(child);
                }
            }
            false
        })
    }

    /// Answers for this node only. `find` already visits every descendant, so
    /// recursing here would re-walk the whole subtree once per ancestor.
    fn is_infinite_background_loop(node: Node<'_>, source: &str) -> bool {
        loop_truth(node, source) == Some(true)
            && node.child_by_field_name("body").is_some_and(|body| {
                last_background(body, source).is_some_and(|background| {
                    !contains_unconditional_loop_exit(body, source)
                        && !contains_bounding_wait(body, source, background)
                })
            })
    }

    fn contains_uncertain_background_loop(node: Node<'_>, source: &str) -> bool {
        walk_nodes(node, true, |_| false).any(|node| {
            matches!(node.kind(), "while_statement" | "c_style_for_statement")
                && loop_truth(node, source).is_none()
                && node
                    .child_by_field_name("body")
                    .is_some_and(|body| last_background(body, source).is_some())
        })
    }

    fn isolated_job_scope(kind: &str) -> bool {
        matches!(
            kind,
            "subshell" | "command_substitution" | "process_substitution"
        )
    }

    fn background_scope<'tree>(background: Node<'tree>, body: Node<'tree>) -> Node<'tree> {
        let mut current = background;
        while let Some(parent) = current.parent() {
            if parent == body {
                return body;
            }
            if isolated_job_scope(parent.kind()) {
                return parent;
            }
            current = parent;
        }
        body
    }

    fn background_count(node: Node<'_>, root: Node<'_>, source: &str) -> usize {
        walk_nodes(node, false, |node| {
            node != root && isolated_job_scope(node.kind())
        })
        .filter(|node| !node.is_named() && text(*node, source) == "&")
        .count()
    }

    fn unconditional_in_body(node: Node<'_>, body: Node<'_>) -> bool {
        let mut current = node;
        while let Some(parent) = current.parent() {
            if parent == body {
                return true;
            }
            if matches!(
                parent.kind(),
                "if_statement"
                    | "elif_clause"
                    | "else_clause"
                    | "case_statement"
                    | "case_item"
                    | "list"
                    | "pipeline"
                    | "subshell"
                    | "command_substitution"
                    | "process_substitution"
                    | "function_definition"
                    | "while_statement"
                    | "for_statement"
                    | "c_style_for_statement"
            ) {
                return false;
            }
            current = parent;
        }
        false
    }

    fn contains_unconditional_loop_exit(body: Node<'_>, source: &str) -> bool {
        walk_nodes(body, true, |_| false).any(|node| {
            node.kind() == "command"
                && unconditional_in_body(node, body)
                && matches!(
                    text(node, source)
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .as_slice(),
                    ["break"] | ["exit"]
                )
        })
    }

    fn contains_bounding_wait(body: Node<'_>, source: &str, background: Node<'_>) -> bool {
        fn find(
            root: Node<'_>,
            scope: Node<'_>,
            source: &str,
            background: usize,
            single_background: bool,
        ) -> bool {
            walk_nodes(root, true, |_| false).any(|node| {
                if node.kind() != "command" || !unconditional_in_body(node, scope) {
                    return false;
                }
                let words = text(node, source).split_whitespace().collect::<Vec<_>>();
                let after_background = node.start_byte() > background;
                let waits_after = after_background
                    && (words.as_slice() == ["wait"]
                        || (single_background
                            && matches!(
                                words.as_slice(),
                                ["wait", "-n"] | ["wait", "$!"] | ["wait", "\"$!\""]
                            )));
                let waits_for_previous_iteration =
                    !after_background && single_background && words.as_slice() == ["wait"];
                waits_after || waits_for_previous_iteration
            })
        }

        let scope = background_scope(background, body);
        if contains_command(scope, source, "disown") {
            return false;
        }
        find(
            scope,
            scope,
            source,
            background.start_byte(),
            background_count(scope, scope, source) == 1,
        )
    }

    fn invoked_after(node: Node<'_>, source: &str, name: &str, byte: usize) -> bool {
        walk_nodes(node, true, |node| node.kind() == "function_definition")
            .any(|node| node.start_byte() >= byte && command_name(node, source) == Some(name))
    }

    fn contains_background_recursive_cycle(root: Node<'_>, source: &str) -> bool {
        fn collect_definitions<'tree>(
            node: Node<'tree>,
            source: &str,
            definitions: &mut Vec<(String, Node<'tree>, usize)>,
        ) {
            for node in walk_nodes(node, true, |node| node.kind() == "function_definition") {
                if node.kind() != "function_definition" {
                    continue;
                }
                if let (Some(name), Some(body)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("body"),
                ) {
                    definitions.push((text(name, source).to_owned(), body, node.end_byte()));
                }
            }
        }

        fn collect_calls(
            node: Node<'_>,
            source: &str,
            functions: &HashMap<&str, usize>,
            calls: &mut HashSet<usize>,
        ) {
            for node in walk_nodes(node, true, |node| node.kind() == "function_definition") {
                if let Some(name) = command_name(node, source)
                    && let Some(index) = functions.get(name)
                {
                    calls.insert(*index);
                }
            }
        }

        fn collect_background_calls(
            node: Node<'_>,
            source: &str,
            functions: &HashMap<&str, usize>,
            calls: &mut HashSet<usize>,
        ) {
            for node in walk_nodes(node, true, |node| node.kind() == "function_definition") {
                let mut previous_named = None;
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if !child.is_named() && text(child, source) == "&" {
                        if let Some(previous) = previous_named {
                            collect_calls(previous, source, functions, calls);
                        }
                    } else if child.is_named() {
                        previous_named = Some(child);
                    }
                }
            }
        }

        fn collect_roots(
            node: Node<'_>,
            source: &str,
            functions: &HashMap<&str, usize>,
            roots: &mut Vec<(usize, usize)>,
        ) {
            for node in walk_nodes(node, true, |node| node.kind() == "function_definition") {
                if let Some(name) = command_name(node, source)
                    && let Some(index) = functions.get(name)
                {
                    roots.push((*index, node.start_byte()));
                }
            }
        }

        let mut definitions = Vec::new();
        collect_definitions(root, source, &mut definitions);
        if definitions.len() < 2 {
            return false;
        }

        let mut counts = HashMap::new();
        for (name, _, _) in &definitions {
            *counts.entry(name.as_str()).or_insert(0_usize) += 1;
        }
        let functions = definitions
            .iter()
            .enumerate()
            .filter(|(_, (name, _, _))| counts.get(name.as_str()) == Some(&1))
            .map(|(index, (name, _, _))| (name.as_str(), index))
            .collect::<HashMap<_, _>>();
        if functions.len() < 2 {
            return false;
        }

        let mut root_invocations = Vec::new();
        collect_roots(root, source, &functions, &mut root_invocations);
        if root_invocations.is_empty() {
            return false;
        }

        let active = functions.values().copied().collect::<HashSet<_>>();
        let mut graph = vec![Vec::new(); definitions.len()];
        let mut reverse = vec![Vec::new(); definitions.len()];
        for (index, (_, body, _)) in definitions.iter().enumerate() {
            if !active.contains(&index) {
                continue;
            }
            let mut calls = HashSet::new();
            let mut background_calls = HashSet::new();
            collect_calls(*body, source, &functions, &mut calls);
            collect_background_calls(*body, source, &functions, &mut background_calls);
            for target in calls {
                graph[index].push((target, background_calls.contains(&target)));
                reverse[target].push(index);
            }
        }

        let mut visited = vec![false; definitions.len()];
        let mut order = Vec::new();
        for start in 0..definitions.len() {
            if !active.contains(&start) || visited[start] {
                continue;
            }
            visited[start] = true;
            let mut stack = vec![(start, 0_usize)];
            while let Some((index, next)) = stack.last_mut() {
                if *next < graph[*index].len() {
                    let target = graph[*index][*next].0;
                    *next += 1;
                    if !visited[target] {
                        visited[target] = true;
                        stack.push((target, 0));
                    }
                } else {
                    order.push(*index);
                    stack.pop();
                }
            }
        }

        let mut component = vec![usize::MAX; definitions.len()];
        let mut component_index = 0;
        while let Some(start) = order.pop() {
            if component[start] != usize::MAX {
                continue;
            }
            component[start] = component_index;
            let mut stack = vec![start];
            while let Some(index) = stack.pop() {
                for target in &reverse[index] {
                    if component[*target] == usize::MAX {
                        component[*target] = component_index;
                        stack.push(*target);
                    }
                }
            }
            component_index += 1;
        }

        let mut component_end = vec![0_usize; component_index];
        for index in &active {
            component_end[component[*index]] =
                component_end[component[*index]].max(definitions[*index].2);
        }
        let mut dangerous = vec![false; component_index];
        for (index, edges) in graph.iter().enumerate() {
            if !active.contains(&index) {
                continue;
            }
            for (target, backgrounded) in edges {
                if *backgrounded && component[index] == component[*target] {
                    dangerous[component[index]] = true;
                }
            }
        }

        let mut required_byte = vec![usize::MAX; definitions.len()];
        let mut pending = BinaryHeap::new();
        for index in &active {
            if dangerous[component[*index]] {
                required_byte[*index] = component_end[component[*index]];
                pending.push(Reverse((required_byte[*index], *index)));
            }
        }
        while let Some(Reverse((required, index))) = pending.pop() {
            if required != required_byte[index] {
                continue;
            }
            for predecessor in &reverse[index] {
                let candidate = required.max(definitions[*predecessor].2);
                if candidate < required_byte[*predecessor] {
                    required_byte[*predecessor] = candidate;
                    pending.push(Reverse((candidate, *predecessor)));
                }
            }
        }

        root_invocations
            .iter()
            .any(|(index, byte)| *byte >= required_byte[*index])
    }

    fn contains_uncertain_background_function_graph(root: Node<'_>, source: &str) -> bool {
        fn collect(
            node: Node<'_>,
            source: &str,
            names: &mut Vec<String>,
            any_background: &mut bool,
            last_definition: &mut usize,
        ) {
            for node in walk_nodes(node, true, |node| node.kind() == "function_definition") {
                if node.kind() != "function_definition" {
                    continue;
                }
                if let Some(name) = node.child_by_field_name("name") {
                    names.push(text(name, source).to_owned());
                }
                if let Some(body) = node.child_by_field_name("body") {
                    *any_background |= last_background(body, source).is_some();
                }
                *last_definition = (*last_definition).max(node.end_byte());
            }
        }

        let mut names = Vec::new();
        let mut any_background = false;
        let mut last_definition = 0;
        collect(
            root,
            source,
            &mut names,
            &mut any_background,
            &mut last_definition,
        );
        names.sort();
        let has_duplicate = names.windows(2).any(|pair| pair[0] == pair[1]);
        has_duplicate
            && any_background
            && names
                .iter()
                .any(|name| invoked_after(root, source, name, last_definition))
    }

    fn find(node: Node<'_>, root: Node<'_>, source: &str) -> bool {
        walk_nodes(node, true, |_| false).any(|node| {
            if is_infinite_background_loop(node, source) {
                return true;
            }
            if node.kind() == "function_definition"
                && let (Some(name), Some(body)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("body"),
                )
            {
                let name = text(name, source);
                return text(body, source).contains('&')
                    && (pipeline_recurses(body, source, name)
                        || recursive_invocations(body, source, name) >= 2
                        || backgrounds_recursion(body, source, name))
                    && invoked_after(root, source, name, node.end_byte());
            }
            false
        })
    }

    let detected = contains_background_recursive_cycle(root, source) || find(root, root, source);
    let uncertain = !detected
        && (contains_uncertain_background_loop(root, source)
            || contains_uncertain_background_function_graph(root, source));
    (detected, uncertain)
}
