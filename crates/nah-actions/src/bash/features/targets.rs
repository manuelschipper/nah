//! Classifies HOME-root path selection; it does not resolve or access host paths.

use nah_proto::action::pattern_bound;
use nah_proto::ctx::Platform;

pub(crate) fn selects_home(requested: &str, home: &str, platform: Platform, pattern: bool) -> bool {
    let (requested, home, separator) = if platform == Platform::Windows {
        (
            requested.to_ascii_lowercase(),
            home.to_ascii_lowercase(),
            '\\',
        )
    } else {
        (requested.to_owned(), home.to_owned(), '/')
    };
    if requested == home {
        return true;
    }
    let home_prefix = if requested.ends_with(separator) {
        requested.clone()
    } else {
        format!("{requested}{separator}")
    };
    if home.starts_with(&home_prefix) {
        return true;
    }
    if !pattern {
        return false;
    }
    // An expanded pattern reaches whatever its literal prefix leaves open. That
    // is home itself when the prefix stops short of home, and every entry of
    // home when the pattern names home's own children (`~/*`, `~/.*`).
    let bound = pattern_bound(&requested);
    if home.starts_with(bound) {
        return true;
    }
    bound
        .rsplit_once(separator)
        .is_some_and(|(directory, name)| directory == home && matches!(name, "" | "."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_select_home_only_where_they_can_reach_it() {
        for (requested, pattern, expected) in [
            ("/home/test", false, true),
            ("/home", false, true),
            ("/home/test/*", true, true),
            ("/home/test/.*", true, true),
            ("/home/test/{*,.*}", true, true),
            ("/home/test/{,.ssh}", true, true),
            ("/home/tes?", true, true),
            ("/home/*", true, true),
            // `.*` cannot expand to `test`, and a named prefix under home picks
            // entries rather than home itself.
            ("/home/.*", true, false),
            ("/home/test/.na?", true, false),
            ("/workspace/project/*", true, false),
            // Quoted patterns name one file and keep the literal rules.
            ("/home/test/*", false, false),
        ] {
            assert_eq!(
                selects_home(requested, "/home/test", Platform::Linux, pattern),
                expected,
                "{requested}"
            );
        }
        assert!(selects_home(
            r"C:\Users\Test\*",
            r"C:\Users\Test",
            Platform::Windows,
            true
        ));
    }
}
