//! The temporary and cache roots, where recursive deletion is routine cleanup.

use super::lexical_path::{fold_path_spelling, join_lexical_path, lexically_contains, same_path};
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

/// A cache folder: what lies below it is downloaded again or rebuilt by the
/// tool that owns it. `whole` says the folder itself may be deleted too: one
/// tool owns it and recreates it, so clearing it whole is routine cleanup.
struct Cache {
    path: &'static str,
    whole: bool,
}

/// The user, package-manager and build caches under home.
const HOME_CACHES: [Cache; 13] = [
    // Each of the user caches holds many tools' caches, so the folder itself
    // is not one tool's to clear.
    Cache {
        path: ".cache",
        whole: false,
    },
    Cache {
        path: "Library/Caches",
        whole: false,
    },
    // npm's content-addressed package cache (`npm cache clean --force`
    // empties it); npm fetches each package from the registry again.
    Cache {
        path: ".npm/_cacache",
        whole: true,
    },
    // The packages npx installs to run a command; npx installs them again.
    Cache {
        path: ".npm/_npx",
        whole: true,
    },
    // Cargo's downloaded crate archives, sources and registry index; Cargo
    // fetches them again. Deleting the registry folder itself stays a
    // reviewed block: only what lies below it is cleanup.
    Cache {
        path: ".cargo/registry",
        whole: false,
    },
    // Gradle's dependency, transform and build caches; Gradle downloads and
    // rebuilds them.
    Cache {
        path: ".gradle/caches",
        whole: true,
    },
    // Maven's local repository: dependencies Maven downloads again, and
    // artifacts `mvn install` put there, which their projects build again.
    Cache {
        path: ".m2/repository",
        whole: true,
    },
    // Go's module cache (`go clean -modcache` clears it); Go downloads the
    // modules again. Only what lies below it is cleanup.
    Cache {
        path: "go/pkg/mod",
        whole: false,
    },
    // Xcode's build products, indexes and logs; Xcode rebuilds them.
    Cache {
        path: "Library/Developer/Xcode/DerivedData",
        whole: true,
    },
    // Yarn's package archive cache; Yarn fetches the archives again.
    Cache {
        path: ".yarn/cache",
        whole: true,
    },
    // pnpm's content-addressable package store; pnpm fetches packages again,
    // and projects keep the files they already link.
    Cache {
        path: ".pnpm-store",
        whole: true,
    },
    // Bun's package cache; Bun fetches packages again.
    Cache {
        path: ".bun/install/cache",
        whole: true,
    },
    // A local Buildx build cache kept beside Buildx's state (`--cache-to
    // type=local,dest=...`); the builder rebuilds the layers.
    Cache {
        path: ".docker/buildx/cache",
        whole: true,
    },
];

/// The system package caches.
const SYSTEM_CACHES: [Cache; 1] = [
    // APT's downloaded package archives (`apt-get clean` empties it); APT
    // downloads them again and recreates the folder.
    Cache {
        path: "/var/cache/apt/archives",
        whole: true,
    },
];

/// The profile temporary directory, matched below any Windows folder.
const WINDOWS_PROFILE_TEMP: [&str; 3] = ["appdata", "local", "temp"];

/// Whether `target` lies below a temporary or cache root: a Unix temporary
/// root, a Windows drive's `Windows\Temp`, a profile's `AppData\Local\Temp`,
/// a cache under `home` or a system package cache, or the observed temporary
/// directory (`$TMPDIR`, or `%TEMP%` on Windows). A target is compared by its
/// canonical path, so `observed_roots` adds the other spellings the host
/// observed: the temporary directory as the environment spells it, and the
/// canonical path of it and of each [`named_temporary_roots`] entry, which a
/// link above the root makes differ from its name. A root itself and every
/// ancestor of one are not below it, so deleting `/tmp`, `~/.cache` or
/// `~/.cargo` is not cleanup; a cache its tool recreates whole is the
/// exception, so `~/.gradle/caches` itself is cleanup. Roots
/// nest, as `$TMPDIR` does below `/tmp` or macOS's `/private/var/folders`, so
/// a path that holds any other listed root is never below another one.
pub fn lies_under_temporary_root(
    target: &str,
    home: &str,
    observed_roots: &[&str],
    platform: Platform,
) -> bool {
    !holds_root(target, home, observed_roots, platform, true)
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
    holds_root(path, home, observed_roots, platform, false)
}

/// [`holds_temporary_root`], where `cache_itself` leaves out a cache that
/// may be deleted whole when the path names it itself.
fn holds_root(
    path: &str,
    home: &str,
    observed_roots: &[&str],
    platform: Platform,
    cache_itself: bool,
) -> bool {
    let tool_cache = cache_itself
        && cache_paths(home, platform, true).any(|cache| same_path(&cache, path, platform));
    listed_roots(home, observed_roots, platform).any(|root| {
        lexically_contains(path, &root, platform)
            && !(tool_cache && same_path(&root, path, platform))
    }) || windows_components(path, |components| {
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
/// roots, home's caches and the system package caches.
pub fn named_temporary_roots(home: &str, platform: Platform) -> impl Iterator<Item = String> + '_ {
    UNIX_TEMPORARY_ROOTS
        .iter()
        .map(|root| (*root).to_owned())
        .chain(cache_paths(home, platform, false))
}

/// The cache folders as paths, or with `whole` only those that may be
/// deleted themselves. macOS links /var into /private, so there a system
/// cache has both spellings.
fn cache_paths(home: &str, platform: Platform, whole: bool) -> impl Iterator<Item = String> + '_ {
    let private = (platform == Platform::Macos).then_some("/private");
    HOME_CACHES
        .iter()
        .filter(move |cache| !whole || cache.whole)
        .map(move |cache| join_lexical_path(home, cache.path, platform))
        .chain(
            SYSTEM_CACHES
                .iter()
                .filter(move |cache| !whole || cache.whole)
                .flat_map(move |cache| {
                    std::iter::once(cache.path.to_owned())
                        .chain(private.map(|private| format!("{private}{}", cache.path)))
                }),
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
