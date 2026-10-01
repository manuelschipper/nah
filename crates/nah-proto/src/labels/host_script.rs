//! Lookalike hostnames: a DNS label that mixes Unicode scripts, the shape of
//! `gіthub.com` spelled with a Cyrillic `і`.

use icu_properties::props::Script;
use icu_properties::script::ScriptWithExtensions;

/// Whether any DNS label of `host` mixes scripts, per UTS #39 mixed-script
/// detection: the label's resolved script set, the intersection of each
/// character's augmented Script_Extensions, is empty. Common and Inherited
/// characters (digits, hyphen, combining marks) belong to every script, and
/// Han with Hiragana, Katakana, Hangul or Bopomofo is one writing system
/// (Japanese, Korean or Chinese). A punycode (`xn--`) label is judged on its
/// decoded form; one that does not decode is judged as written, all ASCII.
pub fn mixes_scripts(host: &str) -> bool {
    // UTS #46 treats the ideographic and fullwidth full stops as dots.
    host.split(['.', '\u{3002}', '\u{FF0E}', '\u{FF61}'])
        .any(|label| {
            let decoded = label
                .get(..4)
                .filter(|prefix| prefix.eq_ignore_ascii_case("xn--"))
                .and_then(|_| idna::punycode::decode_to_string(&label[4..]));
            label_mixes_scripts(decoded.as_deref().unwrap_or(label))
        })
}

/// A script, or one of the UTS #39 writing systems that join Han with the
/// scripts written beside it.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Writing {
    Script(Script),
    HanWithBopomofo,
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
                    &[Writing::HanWithBopomofo, Writing::Japanese, Writing::Korean]
                } else if script == Script::Hiragana || script == Script::Katakana {
                    &[Writing::Japanese]
                } else if script == Script::Hangul {
                    &[Writing::Korean]
                } else if script == Script::Bopomofo {
                    &[Writing::HanWithBopomofo]
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
