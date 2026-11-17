//! Completed bytes of a batch whose disjoint replacements match the original file.

use effinterp_proto::FileEditEntry;
use unicode_normalization::UnicodeNormalization;

pub(super) enum OriginalEditResult {
    Applied(String),
    Rejected,
    Unknown,
    TooLarge,
}

pub(super) fn apply(source: &str, edits: &[FileEditEntry], max_bytes: u64) -> OriginalEditResult {
    use OriginalEditResult::{Applied, Rejected, TooLarge, Unknown};
    let (bom, source) = source
        .strip_prefix('\u{feff}')
        .map_or(("", source), |source| ("\u{feff}", source));
    let crlf = source
        .find("\r\n")
        .zip(source.find('\n'))
        .is_some_and(|(crlf, lf)| crlf < lf);
    let source = normalize_lf(source);
    let fuzzy_source = normalize_fuzzy(&source);
    let mut replacements = Vec::new();
    let mut unknown = false;
    for edit in edits {
        let old = normalize_lf(&edit.old);
        if old.is_empty() {
            return Rejected;
        }
        if edit.replace_all {
            return Unknown;
        }
        let fuzzy_old = normalize_fuzzy(&old);
        if fuzzy_old.is_empty() {
            return Unknown;
        }
        if fuzzy_source.matches(&fuzzy_old).count() > 1 {
            return Rejected;
        }
        let Some(offset) = source.find(&old) else {
            if !fuzzy_source.contains(&fuzzy_old) {
                return Rejected;
            }
            // A fuzzy hit changes the coordinate space of every edit. Exact
            // matches alone cannot establish that completed document.
            unknown = true;
            continue;
        };
        replacements.push((offset, old, normalize_lf(&edit.new)));
    }
    if unknown {
        return Unknown;
    }
    replacements.sort_by_key(|(offset, _, _)| *offset);
    if replacements
        .windows(2)
        .any(|pair| pair[0].0 + pair[0].1.len() > pair[1].0)
    {
        return Rejected;
    }
    let mut bytes = source.len();
    let mut newlines = source.matches('\n').count();
    for (_, old, new) in &replacements {
        bytes = bytes - old.len() + new.len();
        newlines = newlines - old.matches('\n').count() + new.matches('\n').count();
    }
    if bytes
        .saturating_add(if crlf { newlines } else { 0 })
        .saturating_add(bom.len()) as u64
        > max_bytes
    {
        return TooLarge;
    }
    let mut result = source.clone();
    for (offset, old, new) in replacements.into_iter().rev() {
        result.replace_range(offset..offset + old.len(), &new);
    }
    if result == source {
        return Rejected;
    }
    let result = if crlf {
        result.replace('\n', "\r\n")
    } else {
        result
    };
    Applied(format!("{bom}{result}"))
}

fn normalize_lf(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Pi counts duplicates in NFKC/trimmed/typographic-normalized text even
/// when all edits found exact matches. This does not apply fuzzy edits.
fn normalize_fuzzy(text: &str) -> String {
    let text: String = text.nfkc().collect();
    text.split('\n')
        .map(|line| {
            line.trim_end_matches(|ch| {
                matches!(
                    ch,
                    '\u{0009}'..='\u{000d}'
                        | ' '
                        | '\u{00a0}'
                        | '\u{1680}'
                        | '\u{2000}'..='\u{200a}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{202f}'
                        | '\u{205f}'
                        | '\u{3000}'
                        | '\u{feff}'
                )
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
        .chars()
        .map(|ch| match ch {
            '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => '\'',
            '\u{201c}' | '\u{201d}' | '\u{201e}' | '\u{201f}' => '"',
            '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
            '\u{00a0}' | '\u{2002}'..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}' => ' ',
            ch => ch,
        })
        .collect()
}
