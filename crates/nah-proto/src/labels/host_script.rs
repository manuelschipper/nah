//! Lookalike hostnames: a DNS label that mixes Unicode scripts, the shape of
//! `gіthub.com` spelled with a Cyrillic `і`.

use icu_properties::props::Script;
use icu_properties::script::ScriptWithExtensions;
use idna::uts46::{AsciiDenyList, Hyphens, Uts46};

/// Whether any DNS label of the URL host `host` mixes scripts, judged on the
/// name a URL client resolves: `%XX` escapes decoded, then UTS #46 mapping,
/// which folds compatibility forms such as mathematical letters, decodes
/// punycode (`xn--`) labels and turns the ideographic full stops into dots. A
/// label that does not map, such as invalid punycode, keeps what it can and
/// marks the rest U+FFFD, which belongs to every script.
///
/// A label mixes scripts per UTS #39 revision 34 (Unicode 18.0.0) mixed-script
/// detection: the intersection of each character's augmented
/// Script_Extensions is empty. Common and Inherited characters (digits,
/// hyphen, combining marks) belong to every script, and Han joins Bopomofo,
/// Hiragana and Katakana, Hangul, or Latin as one writing system.
pub fn mixes_scripts(host: &str) -> bool {
    let decoded = percent_decoded(host);
    let (host, _) = Uts46::new().to_unicode(&decoded, AsciiDenyList::EMPTY, Hyphens::Allow);
    host.split('.').any(label_mixes_scripts)
}

/// `host` with each `%XX` escape decoded to its byte, as URL clients decode a
/// host before resolving it.
fn percent_decoded(host: &str) -> Vec<u8> {
    let bytes = host.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = bytes
            .get(index + 1..index + 3)
            .filter(|hex| bytes[index] == b'%' && hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    decoded
}

/// A script, or one of the UTS #39 writing systems that join Han with the
/// scripts written beside it.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Writing {
    Script(Script),
    HanWithBopomofo,
    HanWithLatin,
    Japanese,
    Korean,
}

fn label_mixes_scripts(label: &str) -> bool {
    let extensions = ScriptWithExtensions::new();
    let mut resolved: Option<Vec<Writing>> = None;
    for character in label.chars() {
        let scripts = extensions.get_script_extensions_val(character);
        if scripts.contains(&Script::Common) || scripts.contains(&Script::Inherited) {
            continue;
        }
        let augmented = scripts
            .iter()
            .flat_map(|script| {
                let systems: &[Writing] = if script == Script::Han {
                    &[
                        Writing::HanWithBopomofo,
                        Writing::HanWithLatin,
                        Writing::Japanese,
                        Writing::Korean,
                    ]
                } else if script == Script::Hiragana || script == Script::Katakana {
                    &[Writing::Japanese]
                } else if script == Script::Hangul {
                    &[Writing::Korean]
                } else if script == Script::Bopomofo {
                    &[Writing::HanWithBopomofo]
                } else if script == Script::Latin {
                    &[Writing::HanWithLatin]
                } else {
                    &[]
                };
                std::iter::once(Writing::Script(script)).chain(systems.iter().copied())
            })
            .collect::<Vec<_>>();
        match &mut resolved {
            Some(resolved) => resolved.retain(|writing| augmented.contains(writing)),
            None => resolved = Some(augmented),
        }
    }
    resolved.is_some_and(|resolved| resolved.is_empty())
}
