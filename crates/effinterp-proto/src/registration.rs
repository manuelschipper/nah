//! Declaration evidence shared by frontend roots and repository discovery.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistrationKind {
    Route {
        method: Option<String>,
        path: Option<String>,
    },
    Command {
        name: Option<String>,
    },
}

/// Labels are declaration-local; `None` is unresolved, never a literal question mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub kind: RegistrationKind,
    pub file: String,
    pub owner: String,
    pub primary_handler: String,
    /// Ordered roots on this declaration, including its primary handler.
    pub selected_handlers: Vec<String>,
    /// Source byte ranges retained when identical declaration tuples deduplicate.
    pub spans: Vec<(u32, u32)>,
    pub unresolved: Vec<String>,
}

impl Registration {
    /// Encode each literal component before joining; raw `?` means unresolved.
    pub fn id(&self) -> String {
        fn component(value: &str) -> String {
            let mut out = String::new();
            for byte in value.bytes() {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    out.push(byte as char);
                } else {
                    use std::fmt::Write;
                    write!(out, "%{byte:02X}").unwrap();
                }
            }
            out
        }
        let label = |value: &Option<String>| value.as_deref().map(component).unwrap_or("?".into());
        let (prefix, labels) = match &self.kind {
            RegistrationKind::Route { method, path } => {
                ("route", format!("{}:{}", label(method), label(path)))
            }
            RegistrationKind::Command { name } => ("cmd", label(name)),
        };
        format!(
            "{prefix}:{}:{}:{labels}:{}",
            component(&self.file),
            component(&self.owner),
            component(&self.primary_handler)
        )
    }

    /// Local label excludes externally mounted prefixes and parent commands.
    pub fn label(&self) -> String {
        match &self.kind {
            RegistrationKind::Route { method, path } => format!(
                "{} {}",
                method.as_deref().unwrap_or("?"),
                path.as_deref().unwrap_or("?")
            ),
            RegistrationKind::Command { name } => name.as_deref().unwrap_or("?").to_string(),
        }
    }
}
