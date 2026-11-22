//! ProcessBuilder command and directory recovery within a Java method frame.

use super::super::call_resolution::jdk_receiver_type;
use super::super::local_bindings::is_guarded_java_assignment;
use super::super::resource_recovery::recover_typed_java_resource;
use super::super::syntax::{
    bare_java_type, first_argument, java_node_text, receiver_identifier, unquote_java_string,
};
use super::{JavaMethodFrame, JavaWalker};
use crate::value::fs_path_resource;
use effinterp_proto::ResourceExpr;
use tree_sitter::Node;

impl<'a> JavaWalker<'a> {
    /// A conditional ProcessBuilder mutation invalidates the recovered setting.
    pub(super) fn track_process_mutations(
        &self,
        n: Node<'a>,
        name: &str,
        recv: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
    ) {
        let Some(id) = receiver_identifier(recv, self.src) else {
            return;
        };
        if jdk_receiver_type(recv, self.src, self.file, &frame.class, &frame.types).as_deref()
            == Some("ProcessBuilder")
        {
            match name {
                "command" => {
                    // A branch-only command() write is not certain; drop recovered
                    // argv so start() stays unresolved instead of taking one arm as fact.
                    if is_guarded_java_assignment(n, self.src) {
                        frame.process_argv.remove(id);
                    } else {
                        let argv = self.argv_from_invocation(n, frame);
                        if !argv.is_empty() {
                            frame.process_argv.insert(id.to_string(), argv);
                        }
                    }
                }
                "directory" => {
                    if is_guarded_java_assignment(n, self.src) {
                        frame.process_cwd.remove(id);
                    } else if let Some(argument) = first_argument(n) {
                        frame.process_cwd.insert(
                            id.to_string(),
                            recover_typed_java_resource(
                                argument,
                                self.src,
                                &frame.env,
                                &self.file.constants,
                                &frame.types,
                            ),
                        );
                    }
                }
                _ => {}
            }
        }
        if name == "add"
            && let Some(argument) = first_argument(n)
        {
            let word = recover_typed_java_resource(
                argument,
                self.src,
                &frame.env,
                &self.file.constants,
                &frame.types,
            );
            if let Some(list) = frame.arrays.get_mut(id) {
                list.push(word);
            }
        }
    }

    /// Rebind recovered process argv after an unguarded assignment of `name`.
    pub(super) fn bind_assigned_argv(
        &self,
        name: &str,
        value: Node<'a>,
        frame: &mut JavaMethodFrame<'a>,
    ) {
        if value.kind() == "object_creation_expression" {
            let ty = bare_java_type(
                value
                    .child_by_field_name("type")
                    .map(|t| java_node_text(t, self.src))
                    .unwrap_or(""),
            );
            if ty == "ProcessBuilder" {
                let argv = self.argv_from_creation(value, frame);
                if !argv.is_empty() {
                    frame.process_argv.insert(name.to_string(), argv);
                }
            }
            if matches!(ty.as_str(), "ArrayList" | "LinkedList") {
                let argv = self.argv_from_expr(value, frame);
                if !argv.is_empty() {
                    frame.arrays.insert(name.to_string(), argv);
                }
            }
        }
        let argv = self.argv_from_expr(value, frame);
        if argv.is_empty() {
            return;
        }
        let ty = frame.types.get(name).map(String::as_str).unwrap_or("");
        if ty.contains("[]")
            || matches!(ty, "List" | "ArrayList" | "LinkedList" | "String[]" | "var")
            || matches!(
                value.kind(),
                "array_initializer" | "array_creation_expression"
            )
        {
            frame.arrays.insert(name.to_string(), argv);
        }
    }

    /// Recovers ProcessBuilder argv from the current frame, including chained calls.
    pub(super) fn process_builder_argv(
        &self,
        recv: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        match recv.kind() {
            "object_creation_expression"
                if recv.child_by_field_name("type").is_some_and(|t| {
                    bare_java_type(java_node_text(t, self.src)) == "ProcessBuilder"
                }) =>
            {
                self.argv_from_creation(recv, frame)
            }
            "identifier" => {
                let id = java_node_text(recv, self.src);
                if let Some(argv) = frame.process_argv.get(id) {
                    return argv.clone();
                }
                if let Some(argv) = frame.arrays.get(id) {
                    return argv.clone();
                }
                // Do not fall back to `news.first()`: reassignment can leave a
                // stale constructor while `process_argv` has already been dropped.
                Vec::new()
            }
            "method_invocation" => {
                let name = recv
                    .child_by_field_name("name")
                    .map(|node| java_node_text(node, self.src))
                    .unwrap_or("");
                if name == "command" {
                    let argv = self.argv_from_invocation(recv, frame);
                    if !argv.is_empty() {
                        return argv;
                    }
                }
                recv.child_by_field_name("object")
                    .map(|object| self.process_builder_argv(object, frame))
                    .unwrap_or_default()
            }
            "parenthesized_expression" | "cast_expression" => recv
                .child_by_field_name("value")
                .or_else(|| recv.named_child(0))
                .map(|value| self.process_builder_argv(value, frame))
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    pub(super) fn process_builder_cwd(
        &self,
        recv: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Option<ResourceExpr> {
        match recv.kind() {
            "identifier" => frame
                .process_cwd
                .get(java_node_text(recv, self.src))
                .cloned(),
            "method_invocation" => {
                let name = recv
                    .child_by_field_name("name")
                    .map(|node| java_node_text(node, self.src))
                    .unwrap_or("");
                if name == "directory"
                    && let Some(argument) = first_argument(recv)
                {
                    return Some(recover_typed_java_resource(
                        argument,
                        self.src,
                        &frame.env,
                        &self.file.constants,
                        &frame.types,
                    ));
                }
                recv.child_by_field_name("object")
                    .and_then(|object| self.process_builder_cwd(object, frame))
            }
            "parenthesized_expression" | "cast_expression" => recv
                .child_by_field_name("value")
                .or_else(|| recv.named_child(0))
                .and_then(|value| self.process_builder_cwd(value, frame)),
            _ => None,
        }
    }

    pub(super) fn argv_from_creation(
        &self,
        creation: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        let Some(args) = creation.child_by_field_name("arguments") else {
            return Vec::new();
        };
        self.argv_from_argument_list(args, frame)
    }

    fn argv_from_invocation(
        &self,
        invocation: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        let Some(args) = invocation.child_by_field_name("arguments") else {
            return Vec::new();
        };
        self.argv_from_argument_list(args, frame)
    }

    fn argv_from_argument_list(
        &self,
        args: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        let mut cursor = args.walk();
        let children: Vec<_> = args.named_children(&mut cursor).collect();
        if children.len() == 1 {
            let flattened = self.argv_from_expr(children[0], frame);
            if !flattened.is_empty() {
                return flattened;
            }
        }
        children
            .into_iter()
            .flat_map(|child| {
                let words = self.argv_from_expr(child, frame);
                if words.is_empty() {
                    vec![recover_typed_java_resource(
                        child,
                        self.src,
                        &frame.env,
                        &self.file.constants,
                        &frame.types,
                    )]
                } else {
                    words
                }
            })
            .collect()
    }

    pub(super) fn argv_from_expr(
        &self,
        n: Node<'a>,
        frame: &JavaMethodFrame<'a>,
    ) -> Vec<ResourceExpr> {
        match n.kind() {
            "string_literal" => vec![fs_path_resource(&unquote_java_string(java_node_text(
                n, self.src,
            )))],
            "identifier" => {
                let name = java_node_text(n, self.src);
                if let Some(argv) = frame.arrays.get(name) {
                    return argv.clone();
                }
                match frame.env.get(name).cloned().or_else(|| {
                    self.file
                        .constants
                        .get(name)
                        .map(|value| fs_path_resource(value))
                }) {
                    Some(ResourceExpr::Union { alternatives }) => alternatives,
                    Some(other) => vec![other],
                    None => vec![ResourceExpr::Parameter {
                        name: name.to_string(),
                    }],
                }
            }
            "array_initializer" => {
                let mut cursor = n.walk();
                n.named_children(&mut cursor)
                    .flat_map(|child| self.argv_from_expr(child, frame))
                    .collect()
            }
            "array_creation_expression" => n
                .named_children(&mut n.walk())
                .find(|child| child.kind() == "array_initializer")
                .map(|initializer| self.argv_from_expr(initializer, frame))
                .unwrap_or_default(),
            "method_invocation" => {
                let name = n
                    .child_by_field_name("name")
                    .map(|node| java_node_text(node, self.src))
                    .unwrap_or("");
                let object = n
                    .child_by_field_name("object")
                    .map(|node| java_node_text(node, self.src))
                    .unwrap_or("");
                let object_tail = object.rsplit('.').next().unwrap_or(object);
                if matches!(name, "of" | "asList") && matches!(object_tail, "List" | "Arrays") {
                    return n
                        .child_by_field_name("arguments")
                        .map(|args| self.argv_from_argument_list(args, frame))
                        .unwrap_or_default();
                }
                Vec::new()
            }
            "object_creation_expression" => {
                let ty = n
                    .child_by_field_name("type")
                    .map(|node| bare_java_type(java_node_text(node, self.src)))
                    .unwrap_or_default();
                if matches!(ty.as_str(), "ArrayList" | "LinkedList")
                    && let Some(args) = n.child_by_field_name("arguments")
                {
                    let mut cursor = args.walk();
                    if let Some(first) = args.named_children(&mut cursor).next() {
                        return self.argv_from_expr(first, frame);
                    }
                }
                Vec::new()
            }
            "parenthesized_expression" | "cast_expression" => n
                .child_by_field_name("value")
                .or_else(|| n.named_child(0))
                .map(|value| self.argv_from_expr(value, frame))
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

/// Drop recovered process argv for `name`. Reassignment must not keep a stale
/// first value as fact.
pub(super) fn invalidate_argv_local(name: &str, frame: &mut JavaMethodFrame<'_>) {
    frame.arrays.remove(name);
    frame.process_argv.remove(name);
    frame.process_cwd.remove(name);
}
