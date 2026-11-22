//! The temporary and cache roots, where recursive deletion is routine cleanup.

use super::lexical_path::{fold_path_spelling, join_lexical_path, lexically_contains};
use super::pattern::pattern_reaches;
use crate::ctx::{AbsolutePath, Platform};

/// The Unix temporary roots. macOS links /tmp and /var/tmp into /private and
/// keeps each user's `$TMPDIR` under /var/folders; the rule sees the canonical
/// target, or the spelling when the path was not observed.
const UNIX_TEMPORARY_ROOTS: [&str; 6] = [
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// The user and package caches under home, whose entries a tool downloads or
/// rebuilds on demand.
const HOME_CACHE_ROOTS: [&str; 7] = [
    ".cache",
    "Library/Caches",
    ".npm/_cacache",
    ".cargo/registry",
    ".gradle/caches",
    ".m2/repository",
    "go/pkg/mod",
];

/// The profile temporary directory, matched below any Windows folder.
const WINDOWS_PROFILE_TEMP: [&str; 3] = ["appdata", "local", "temp"];

/// Whether `target` lies strictly below a temporary or cache root: a Unix
/// temporary root, a Windows drive's `Windows\Temp`, a profile's
/// `AppData\Local\Temp`, a cache under `home`, or the observed temporary
/// directory (`$TMPDIR`, or `%TEMP%` on Windows). A target is compared by its
/// canonical path, so `observed_roots` adds the other spellings the host
/// observed: the temporary directory as the environment spells it, and the
/// canonical path of it and of each [`named_temporary_roots`] entry, which a
/// link above the root makes differ from its name. A root itself and every
/// ancestor of one are not below it, so deleting `/tmp` or `~/.cargo` is not
/// cleanup. Roots nest, as `$TMPDIR` does below `/tmp` or macOS's
/// `/private/var/folders`, so a path that holds any listed root is never
/// below another one.
pub fn lies_under_temporary_root(
    target: &str,
    home: &str,
    observed_roots: &[&str],
    platform: Platform,
) -> bool {
    !holds_temporary_root(target, home, observed_roots, platform)
        && (listed_roots(home, observed_roots, platform)
            .any(|root| lexically_contains(&root, target, platform))
            || windows_components(target, |components| {
                components.starts_with(&["windows", "temp"])
                    || components
                        .windows(WINDOWS_PROFILE_TEMP.len())
                        .any(|window| window == WINDOWS_PROFILE_TEMP)
            }))
}

/// Whether `path` is a temporary or cache root or an ancestor of one, as
/// [`lies_under_temporary_root`] lists them.
pub fn holds_temporary_root(
    path: &str,
    home: &str,
    observed_roots: &[&str],
    platform: Platform,
) -> bool {
    listed_roots(home, observed_roots, platform)
        .any(|root| lexically_contains(path, &root, platform))
        || windows_components(path, |components| {
            ["windows", "temp"].starts_with(components)
                || (1..=WINDOWS_PROFILE_TEMP.len())
                    .any(|count| components.ends_with(&WINDOWS_PROFILE_TEMP[..count]))
        })
}

/// Whether a recursive delete of the expanded `pattern` can select a
/// temporary or cache root, or a folder above one, as
/// [`lies_under_temporary_root`] lists them: the pattern matches the root or
/// one of its ancestors component by component, so `/tmp/*` selects a
/// `$TMPDIR` at `/tmp/session/T` through `session`. Where that reading is not
/// exact (`**`, braces, extglobs, Windows), every root that starts with the
/// pattern's literal prefix counts.
pub fn pattern_reaches_temporary_root(
    pattern: &str,
    home: &str,
    observed_roots: &[&str],
    platform: Platform,
) -> bool {
    let bound = fold_path_spelling(crate::action::pattern_bound(pattern), platform);
    listed_roots(home, observed_roots, platform).any(|root| {
        pattern_reaches(pattern, &root, false, platform)
            .unwrap_or_else(|| fold_path_spelling(&root, platform).starts_with(&bound))
    })
}

/// The temporary and cache roots that are named paths: the Unix temporary
/// roots and home's caches.
pub fn named_temporary_roots(home: &str, platform: Platform) -> impl Iterator<Item = String> + '_ {
    UNIX_TEMPORARY_ROOTS
        .iter()
        .map(|root| (*root).to_owned())
        .chain(
            HOME_CACHE_ROOTS
                .iter()
                .map(move |cache| join_lexical_path(home, cache, platform)),
        )
}

/// The roots that are paths: the named roots and each observed spelling. An
/// observed spelling that is home or holds it names no disposable tree and
/// is left out.
fn listed_roots<'a>(
    home: &'a str,
    observed_roots: &'a [&'a str],
    platform: Platform,
) -> impl Iterator<Item = String> + 'a {
    named_temporary_roots(home, platform).chain(
        observed_roots
            .iter()
            .filter(move |directory| {
                AbsolutePath::new(platform, **directory).is_ok()
                    && !lexically_contains(directory, home, platform)
            })
            .map(|directory| (*directory).to_owned()),
    )
}

/// Applies `test` to the folded components below a Windows drive root; false
/// for any other path. The Windows roots are read in the Windows spelling on
/// every host.
fn windows_components(path: &str, test: impl FnOnce(&[&str]) -> bool) -> bool {
    let path = fold_path_spelling(path, Platform::Windows);
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'/' {
        return false;
    }
    let components = path[3..]
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    test(&components)
}
