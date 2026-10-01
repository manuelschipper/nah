//! Characters that make a command's displayed text differ from the text that
//! runs: control bytes a terminal acts on, bidirectional overrides that reorder
//! what follows them, and invisible format characters.

/// The black flag that begins an emoji tag sequence such as a subdivision flag.
const TAG_BASE: char = '\u{1F3F4}';
/// The cancel tag that ends an emoji tag sequence.
const CANCEL_TAG: char = '\u{E007F}';

/// Whether `text` holds a character that makes its display differ from what
/// runs:
/// - C0 controls other than tab, line feed and carriage return, DEL, and C1
///   controls (U+0080–U+009F);
/// - bidi embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069);
/// - the invisible format characters U+200B, U+2060, U+FEFF and U+180E;
/// - Unicode tag characters (U+E0000–U+E007F) outside a subdivision flag.
///
/// Joiners (U+200C, U+200D), variation selectors, the directional marks LRM,
/// RLM and ALM, and escapes spelled as text (`\e[31m`) are ordinary text.
pub fn has_hidden_characters(text: &str) -> bool {
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        rest = &rest[character.len_utf8()..];
        if character == TAG_BASE
            && let Some(after) = after_subdivision_tags(rest)
        {
            rest = after;
        } else if hidden(character) {
            return true;
        }
    }
    false
}

fn hidden(character: char) -> bool {
    matches!(
        character,
        '\u{0}'..='\u{8}'
            | '\u{B}'
            | '\u{C}'
            | '\u{E}'..='\u{1F}'
            | '\u{7F}'..='\u{9F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200B}'
            | '\u{2060}'
            | '\u{FEFF}'
            | '\u{180E}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// The text after the tags of an emoji subdivision flag that follows its black
/// flag: 3 to 7 tag letters or digits, the shape of a Unicode subdivision id
/// such as `gbsct`, then the cancel tag. Any other tag run is hidden text.
fn after_subdivision_tags(text: &str) -> Option<&str> {
    let end = text
        .find(
            |character| !matches!(character, '\u{E0030}'..='\u{E0039}' | '\u{E0061}'..='\u{E007A}'),
        )
        .unwrap_or(text.len());
    let rest = text[end..].strip_prefix(CANCEL_TAG)?;
    (3..=7)
        .contains(&text[..end].chars().count())
        .then_some(rest)
}
