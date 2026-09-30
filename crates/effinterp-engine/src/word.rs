/// An abstract argv word. The exec frontend produces fully literal words;
/// the shell frontend produces words whose expansions could not be resolved
/// statically. Adjacent literal parts are merged on construction, so a fully
/// literal word always has exactly one part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub parts: Vec<WordPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordPart {
    Literal(String),
    /// An environment variable whose value is unknown at analysis time.
    Env(String),
    /// Captured stdout with a modeled resource value; display remains opaque.
    Value(effinterp_proto::ResourceExpr),
    /// Unquoted text containing glob metacharacters, kept as pattern text.
    Glob(String),
    /// Exactly one of a finite set of complete words.
    Union(Vec<Word>),
    /// A value the frontend could not recover (command substitution output,
    /// unsupported expansion, ...).
    Unknown,
}

impl Word {
    pub fn literal(text: impl Into<String>) -> Self {
        Self {
            parts: vec![WordPart::Literal(text.into())],
        }
    }

    pub fn new(parts: Vec<WordPart>) -> Self {
        let mut merged: Vec<WordPart> = Vec::new();
        for part in parts {
            match (merged.last_mut(), part) {
                (Some(WordPart::Literal(acc)), WordPart::Literal(next)) => acc.push_str(&next),
                (_, part) => merged.push(part),
            }
        }
        Self { parts: merged }
    }

    /// The word's text if it is fully literal.
    pub fn as_literal(&self) -> Option<&str> {
        match self.parts.as_slice() {
            [WordPart::Literal(text)] => Some(text),
            [] => Some(""),
            _ => None,
        }
    }

    /// The word's leading literal text, empty when the word starts with a
    /// symbolic part. A symbolic word still shows its option prefix this way,
    /// so `-c"$(curl …)"` is recognized as an attached inline-source option.
    pub fn literal_prefix(&self) -> &str {
        match self.parts.first() {
            Some(WordPart::Literal(text)) => text,
            _ => "",
        }
    }

    /// An approximate source rendering, used to record the argv of a nested
    /// invocation for display. Symbolic parts render back to shell-ish text
    /// (`$VAR`, the glob pattern, `?` for unrecoverable values); this is a
    /// label for the plan, not a re-parseable command.
    pub fn render_raw(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                WordPart::Literal(text) => out.push_str(text),
                WordPart::Env(name) => {
                    out.push('$');
                    out.push_str(name);
                }
                WordPart::Glob(pattern) => out.push_str(pattern),
                WordPart::Union(alternatives) => {
                    out.push_str("one_of(");
                    out.push_str(
                        &alternatives
                            .iter()
                            .map(Word::render_raw)
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    out.push(')');
                }
                WordPart::Value(_) | WordPart::Unknown => out.push('?'),
            }
        }
        out
    }

    /// Split `NAME=value` while preserving symbolic parts in `value`.
    pub fn split_assignment(&self) -> Option<(&str, Self)> {
        let WordPart::Literal(first) = self.parts.first()? else {
            return None;
        };
        let (name, first_value) = first.split_once('=')?;
        let mut parts = self.parts[1..].to_vec();
        if !first_value.is_empty() {
            parts.insert(0, WordPart::Literal(first_value.to_string()));
        }
        Some((name, Self::new(parts)))
    }
}
