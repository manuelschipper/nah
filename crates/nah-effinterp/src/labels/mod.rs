// UNDOCUMENTED-EFFINTERP: copied pure identity classifiers for plan annotations.

pub mod host_integrity;
pub mod runtime_cli;
pub mod scope;
pub mod sensitivity;
pub mod tier;

use nah_proto::action::pattern_bound;
use nah_proto::ctx::Platform;

pub(crate) fn contains(base: &str, path: &str, platform: Platform) -> bool {
    let normalize = |value: &str| {
        if platform == Platform::Windows {
            value
                .trim_end_matches(['/', '\\'])
                .replace('\\', "/")
                .to_ascii_lowercase()
        } else {
            value.trim_end_matches('/').to_owned()
        }
    };
    let base = normalize(base);
    let path = normalize(path);
    path == base
        || path
            .strip_prefix(&base)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(crate) fn join(base: &str, relative: &str, platform: Platform) -> String {
    let (base, relative, separator) = if platform == Platform::Windows {
        (
            base.trim_end_matches(['/', '\\']),
            relative.replace('/', "\\"),
            '\\',
        )
    } else {
        (base.trim_end_matches('/'), relative.to_owned(), '/')
    };
    format!("{base}{separator}{relative}")
}

pub(crate) fn selects(known: &str, path: &str, platform: Platform, pattern: bool) -> bool {
    if contains(known, path, platform) {
        return true;
    }
    let normalize = |value: &str| {
        if platform == Platform::Windows {
            value.replace('\\', "/").to_ascii_lowercase()
        } else {
            value.to_owned()
        }
    };
    let bound = normalize(pattern_bound(path));
    let name = bound
        .rsplit_once('/')
        .map_or(bound.as_str(), |(_, name)| name);
    pattern && !matches!(name, "" | ".") && normalize(known).starts_with(&bound)
}

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
    let bound = pattern_bound(&requested);
    home.starts_with(bound)
        || bound
            .rsplit_once(separator)
            .is_some_and(|(directory, name)| directory == home && matches!(name, "" | "."))
}
