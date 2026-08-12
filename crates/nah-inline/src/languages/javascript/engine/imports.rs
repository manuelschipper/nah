//! JavaScript import binding, type-only exports, and accessor-safe property reads.

use super::*;

impl Interpreter<'_> {
    pub(super) fn bind_import(&mut self, node: &HirNode, state: &mut State) {
        if self.text(node).trim_start().starts_with("import type ") {
            return;
        }
        let source = node
            .child(HirField::Source)
            .map(|source| self.text(source).to_owned());
        let module = source
            .as_deref()
            .and_then(|source| self.decode_string(source))
            .as_deref()
            .and_then(|source| {
                if matches!(source, "module" | "node:module") {
                    Some(Value::NodeModule)
                } else {
                    module_from_source(source).map(Value::Module)
                }
            })
            .filter(|_| {
                matches!(
                    self.profile.ownership,
                    RuntimeOwnership::Node | RuntimeOwnership::Bun
                )
            });
        if module.is_none() {
            self.complete = false;
        }
        let Some(clause) = named_children(node).find(|child| child.kind() == HirKind::ImportClause)
        else {
            return;
        };
        for child in named_children(clause) {
            match child.kind() {
                HirKind::Identifier => {
                    state.declare(self.text(child), module.clone().unwrap_or(Value::Unknown));
                }
                HirKind::NamespaceImport => {
                    if let Some(name) = named_children(child).next() {
                        state.declare(self.text(name), module.clone().unwrap_or(Value::Unknown));
                    }
                }
                HirKind::NamedImports => {
                    for specifier in named_children(child)
                        .filter(|child| child.kind() == HirKind::ImportSpecifier)
                    {
                        if self.text(specifier).trim_start().starts_with("type ") {
                            continue;
                        }
                        let Some(name_node) = specifier.child(HirField::Name) else {
                            continue;
                        };
                        let imported = self.text(name_node);
                        let local = specifier
                            .child(HirField::Alias)
                            .map_or(imported, |alias| self.text(alias));
                        let value = module.as_ref().map_or(Value::Unknown, |module| {
                            property_value(module, imported, state)
                        });
                        state.declare(local, value);
                    }
                }
                _ => {}
            }
        }
    }

    pub(super) fn type_only_export(&self, node: &HirNode) -> bool {
        self.text(node).trim_start().starts_with("export type ")
            || named_children(node).all(|child| child.kind() == HirKind::TypeOnly)
    }

    pub(super) fn read_property(&mut self, value: &Value, property: &str, state: &State) -> Value {
        let selected = property_value(value, property, state);
        if accessor_value(&selected)
            || matches!(&selected, Value::Known(function) if direct_receiver_required(function))
        {
            self.complete = false;
            Value::Unknown
        } else {
            selected
        }
    }

    pub(super) fn method_accessor_kind(&self, node: &HirNode) -> Option<&'static str> {
        if let Some(kind) = node.child(HirField::Kind) {
            return match self.text(kind) {
                "get" => Some("get"),
                "set" => Some("set"),
                _ => None,
            };
        }
        let source = self.text(node).trim_start();
        if source.starts_with("get ") {
            Some("get")
        } else if source.starts_with("set ") {
            Some("set")
        } else {
            None
        }
    }
}
