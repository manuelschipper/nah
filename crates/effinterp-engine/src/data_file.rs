//! A path a program reads out of a data file the call names: the whole of a
//! one-line file (`cat FILE`, `$(< FILE)`), or one string a JSON or YAML key
//! lookup selects (`jq -r .out FILE`, Python's `json.load(open(FILE))['out']`).
//! The frontends recognize the read and serve the file's bytes; this module
//! answers what text the read yields, and whether that text is one path
//! word, which is all a caller recovers. Anything else stays unresolved, so
//! a value that is not plainly one path never stands in for what the program
//! prints.

/// The format a key lookup parses its file as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataFormat {
    Json,
    Yaml,
}

/// The longest text recovered as a path: Linux's `PATH_MAX`.
const MAX_PATH_BYTES: usize = 4096;

/// `text` when it is one path word: a non-empty name of path characters
/// only, with no whitespace, quoting, glob or other shell character, that
/// does not start as an option or a home (`~`) does. Whatever reads it, as
/// an operand, a word or code, it can mean nothing but that one name.
pub(crate) fn one_path_word(text: &str) -> Option<&str> {
    (!text.is_empty()
        && text.len() <= MAX_PATH_BYTES
        && !text.starts_with(['-', '~'])
        && text
            .chars()
            .all(|c| c.is_alphanumeric() || "/._-~:@+,=%".contains(c)))
    .then_some(text)
}

/// The string the key path `keys` selects in `text` parsed as `format`, when
/// it is one path word. A missing key, a value of any other type, or text
/// the parser rejects selects nothing.
pub(crate) fn key_value(text: &str, format: DataFormat, keys: &[String]) -> Option<String> {
    match format {
        DataFormat::Json => {
            let mut value = &serde_json::from_str::<serde_json::Value>(text).ok()?;
            for key in keys {
                value = value.as_object()?.get(key)?;
            }
            one_path_word(value.as_str()?).map(str::to_owned)
        }
        DataFormat::Yaml => {
            let documents = yaml_rust2::YamlLoader::load_from_str(text).ok()?;
            let [document] = documents.as_slice() else {
                return None;
            };
            let mut value = document;
            for key in keys {
                value = value
                    .as_hash()?
                    .get(&yaml_rust2::Yaml::String(key.clone()))?;
            }
            let text = value.as_str()?;
            (!yaml_1_1_typed(text)).then_some(())?;
            one_path_word(text).map(str::to_owned)
        }
    }
}

/// Whether a scalar this parser, which follows YAML 1.2, reads as a string
/// may be another type to PyYAML, which follows YAML 1.1: booleans such as
/// `yes` and `off`, and numbers, dates and base-60 values, which all start
/// with a digit or a sign, or are `.inf`, `.nan` or a dot and a digit.
fn yaml_1_1_typed(text: &str) -> bool {
    matches!(
        text.to_ascii_lowercase().as_str(),
        "y" | "n" | "yes" | "no" | "on" | "off" | "true" | "false" | "null" | "~"
    ) || text.starts_with(|c: char| c.is_ascii_digit() || c == '+')
        || matches!(text.to_ascii_lowercase().as_str(), ".inf" | ".nan")
        || text
            .strip_prefix('.')
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::{DataFormat, key_value, one_path_word};

    /// A key path selects one string; anything that is not plainly one path
    /// name, or that PyYAML would read as another type, selects nothing.
    #[test]
    fn a_key_lookup_yields_only_one_path_word() {
        let keys = |keys: &[&str]| keys.iter().map(|key| key.to_string()).collect::<Vec<_>>();
        let json = r#"{"out": "build/x", "n": {"dir": "dist"}, "list": ["a"], "sp": "a b"}"#;
        assert_eq!(
            key_value(json, DataFormat::Json, &keys(&["out"])).as_deref(),
            Some("build/x")
        );
        assert_eq!(
            key_value(json, DataFormat::Json, &keys(&["n", "dir"])).as_deref(),
            Some("dist")
        );
        assert_eq!(key_value(json, DataFormat::Json, &keys(&["list"])), None);
        assert_eq!(key_value(json, DataFormat::Json, &keys(&["sp"])), None);
        assert_eq!(key_value(json, DataFormat::Json, &keys(&["missing"])), None);
        let yaml = "out: victim-dir\nflag: yes\ndate: 2001-12-14\nhidden: .cache\nrel: ./out\n";
        assert_eq!(
            key_value(yaml, DataFormat::Yaml, &keys(&["out"])).as_deref(),
            Some("victim-dir")
        );
        assert_eq!(key_value(yaml, DataFormat::Yaml, &keys(&["flag"])), None);
        assert_eq!(key_value(yaml, DataFormat::Yaml, &keys(&["date"])), None);
        assert_eq!(
            key_value(yaml, DataFormat::Yaml, &keys(&["hidden"])).as_deref(),
            Some(".cache")
        );
        assert_eq!(key_value("v: .5\n", DataFormat::Yaml, &keys(&["v"])), None);
        assert_eq!(
            key_value(yaml, DataFormat::Yaml, &keys(&["rel"])).as_deref(),
            Some("./out")
        );
        assert_eq!(
            key_value("a: 1\n---\na: 2\n", DataFormat::Yaml, &keys(&["a"])),
            None
        );
        assert_eq!(one_path_word("-rf"), None);
        assert_eq!(one_path_word("a;b"), None);
        assert_eq!(one_path_word("$HOME"), None);
        assert_eq!(one_path_word("~/x"), None);
    }
}
