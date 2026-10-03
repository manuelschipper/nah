//! Characters that make a command's displayed text differ from the text that
//! runs: control bytes a terminal acts on, bidirectional overrides that reorder
//! what follows them, and invisible format and filler characters.

/// The black flag that begins an emoji tag sequence such as a subdivision flag.
const TAG_BASE: char = '\u{1F3F4}';
/// The tags after the black flag, through the cancel tag, of the only
/// recommended (RGI) subdivision flags: England `gbeng`, Scotland `gbsct` and
/// Wales `gbwls`. Any other tag sequence, valid flag or not, is hidden text.
const RGI_FLAG_TAGS: [&str; 3] = [
    "\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
    "\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
    "\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}",
];

/// Whether `text` holds a character that makes its display differ from what
/// runs:
/// - C0 controls other than tab and line feed, DEL, and C1 controls
///   (U+0080–U+009F);
/// - a carriage return followed by text other than a line feed, which
///   returns the cursor so that text overwrites the line; a Windows CRLF line
///   ending, and a final carriage return that overwrites nothing, are ordinary;
/// - bidi embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069);
/// - the invisible format characters U+200B, U+2060, U+FEFF, U+180E and the
///   soft hyphen U+00AD;
/// - the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0, which render as
///   blank space and which composed or decomposed Korean text never uses;
/// - Unicode tag characters (U+E0000–U+E007F) outside the flags of England,
///   Scotland and Wales.
///
/// Joiners (U+200C, U+200D), variation selectors, the directional marks LRM,
/// RLM and ALM, and escapes spelled as text (`\e[31m`) are ordinary text.
pub fn has_hidden_characters(text: &str) -> bool {
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        rest = &rest[character.len_utf8()..];
        if character == TAG_BASE
            && let Some(after) = RGI_FLAG_TAGS
                .iter()
                .find_map(|tags| rest.strip_prefix(tags))
        {
            rest = after;
        } else if hidden(character)
            || (character == '\r' && rest.chars().next().is_some_and(|next| next != '\n'))
        {
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
            | '\u{AD}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
    )
}
