//! Lexical path identity: how Nah compares, contains, joins and normalizes host
//! paths by their spelling alone, and where Nah's binary is installed. Nothing
//! here resolves a symlink or reads the host.
//!
//! A backslash separates components only on Windows; on other platforms it is
//! part of a name, so a spelling that uses one there names a different file.

use crate::ctx::Platform;

/// The spelling two paths are compared by: on Windows, `/` separators and
/// ASCII lowercase, because Windows paths are case-insensitive.
pub fn fold(path: &str, platform: Platform) -> String {
    if platform == Platform::Windows {
        path.replace('\\', "/").to_ascii_lowercase()
    } else {
        path.to_owned()
    }
}

/// `fold` without trailing separators, except the root's own.
pub(crate) fn comparison_key(path: &str, platform: Platform) -> String {
    let folded = fold(path, platform);
    if folded == "/" {
        folded
    } else {
        folded.trim_end_matches('/').to_owned()
    }
}

/// Collapses `.` and `..` components and repeated separators. A `..` never
/// climbs above the root: `/`, a drive or a UNC server and share. The case and
/// whether the path is rooted are kept.
pub fn lexically_normalized(path: &str, platform: Platform) -> String {
    let windows = platform == Platform::Windows;
    let separator = |character: char| character == '/' || windows && character == '\\';
    let unc = windows && path.starts_with(separator) && path[1..].starts_with(separator);
    let rooted = path.starts_with(separator);
    let floor = if unc {
        2
    } else if windows
        && path
            .split(separator)
            .find(|component| !component.is_empty())
            .is_some_and(|component| component.ends_with(':'))
    {
        1
    } else {
        0
    };
    let mut components = Vec::new();
    for component in path.split(separator) {
        match component {
            "" | "." => {}
            ".." if components.len() > floor => {
                components.pop();
            }
            ".." => {}
            component => components.push(component),
        }
    }
    if windows {
        let path = components.join("\\");
        if unc {
            format!(r"\\{path}")
        } else if rooted {
            format!(r"\{path}")
        } else {
            path
        }
    } else if rooted {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    }
}

/// Reports whether `path` is `base` itself or sits under it.
pub fn contains(base: &str, path: &str, platform: Platform) -> bool {
    let base = comparison_key(base, platform);
    let path = comparison_key(path, platform);
    path == base
        || path
            .strip_prefix(&base)
            .is_some_and(|suffix| suffix.starts_with('/') || base.ends_with('/'))
}

/// Reports whether two spellings name the same path.
pub fn same_path(left: &str, right: &str, platform: Platform) -> bool {
    comparison_key(left, platform) == comparison_key(right, platform)
}

/// Joins a relative path onto a base with the platform's separator.
pub fn join(base: &str, relative: &str, platform: Platform) -> String {
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

/// Nah's standard installed binary locations for `home`.
pub fn installed_binary_paths(home: &str, platform: Platform) -> Vec<String> {
    let binary = if platform == Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    let mut paths = [".local/bin", ".cargo/bin"]
        .iter()
        .map(|directory| join(&join(home, directory, platform), binary, platform))
        .collect::<Vec<_>>();
    if platform == Platform::Windows {
        paths.push(join(
            &join(home, "AppData/Local/Programs/nah", platform),
            binary,
            platform,
        ));
    } else {
        paths.extend(
            ["/usr/local/bin/nah", "/usr/bin/nah"]
                .iter()
                .map(ToString::to_string),
        );
    }
    paths
}
