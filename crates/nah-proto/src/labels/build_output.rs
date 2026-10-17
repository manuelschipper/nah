//! Names the directories and files build tools regenerate.

/// Whether a directory path's last component is one a build tool, package
/// manager or test runner creates and refills: dependencies, compiled output
/// and caches. Such a directory is taken to hold nothing its tool cannot
/// produce again; any other name says nothing about what it holds.
pub fn build_output_directory(path: &str) -> bool {
    const NAMES: &[&str] = &[
        ".angular",
        ".build",
        ".cache",
        ".eggs",
        ".gradle",
        ".mypy_cache",
        ".next",
        ".nuxt",
        ".nyc_output",
        ".parcel-cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svelte-kit",
        ".tox",
        ".turbo",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "htmlcov",
        "node_modules",
        "out",
        "target",
        "venv",
    ];
    let name = path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    NAMES.contains(&name) || name.ends_with(".egg-info")
}

/// Whether a file path's name is one a tool writes as a by-product and
/// writes again when it next runs: compiled objects, logs, caches and desktop
/// metadata. Any other ignored file may be local state nothing regenerates,
/// such as configuration, a development database, or what an editor or
/// `patch` leaves to recover work from (a swap file, `.orig`, `.rej`).
pub fn build_output_file(path: &str) -> bool {
    const NAMES: &[&str] = &[
        ".DS_Store",
        ".coverage",
        ".eslintcache",
        ".stylelintcache",
        "Thumbs.db",
        "npm-debug.log",
        "yarn-error.log",
    ];
    const EXTENSIONS: &[&str] = &[
        "a",
        "class",
        "d",
        "dylib",
        "log",
        "o",
        "obj",
        "pyc",
        "pyo",
        "rlib",
        "so",
        "tsbuildinfo",
    ];
    let name = path.rsplit(['/', '\\']).next().unwrap_or_default();
    NAMES.contains(&name)
        || name
            .rsplit_once('.')
            .is_some_and(|(stem, extension)| !stem.is_empty() && EXTENSIONS.contains(&extension))
}
