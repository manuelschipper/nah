//! Python source layout: the dotted module key of a file relative to its source
//! root, including non-package `src/` layout roots.

use std::collections::BTreeSet;

/// The Python dotted module key for a file path, computed relative to its source
/// root. A non-package `src/` directory is a layout root (`src/pkg/mod.py` is
/// `pkg.mod` even without `__init__.py`). Otherwise the source root is the first
/// ancestor that is not a package (`__init__.py` or an implicit namespace
/// directory). `/` maps to `.` and `.py`/trailing `.__init__` are dropped.
pub(super) fn python_module_key(
    path: &str,
    package_dirs: &BTreeSet<String>,
    explicit_packages: &BTreeSet<String>,
) -> String {
    // A `src/` directory that is not itself a package is a layout root (it is
    // on sys.path). Key relative to it so `src/pkg/mod.py` is `pkg.mod` even
    // when `src/pkg` has no `__init__.py`. Only an explicit `__init__.py`
    // makes `src` a package; implicit `.py` files under it do not.
    if let Some(rel) = strip_src_root(path, explicit_packages) {
        return module_stem(rel);
    }
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    // Walk up while the current directory is a package; the first ancestor that
    // is NOT a package is the source root.
    let mut root = dir;
    while package_dirs.contains(root) {
        match root.rsplit_once('/') {
            Some((parent, _)) => root = parent,
            None => {
                root = "";
                break;
            }
        }
    }
    let rel = if root.is_empty() {
        path
    } else {
        path.strip_prefix(root)
            .and_then(|r| r.strip_prefix('/'))
            .unwrap_or(path)
    };
    module_stem(rel)
}

/// The path relative to a non-package `src/` layout root, if `path` lives under
/// one (`src/pkg/mod.py` or `packages/foo/src/pkg/mod.py`).
fn strip_src_root<'a>(path: &'a str, package_dirs: &BTreeSet<String>) -> Option<&'a str> {
    if let Some(rel) = path.strip_prefix("src/")
        && !package_dirs.contains("src")
    {
        return Some(rel);
    }
    let bytes = path.as_bytes();
    let mut from = 0;
    while let Some(rel_at) = path[from..].find("/src/") {
        let slash = from + rel_at;
        let root = &path[..slash + 4];
        if !package_dirs.contains(root) {
            return Some(&path[slash + 5..]);
        }
        from = slash + 5;
        if from >= bytes.len() {
            break;
        }
    }
    None
}

fn module_stem(rel: &str) -> String {
    let stem = rel.strip_suffix(".py").unwrap_or(rel);
    let stem = stem.strip_suffix("/__init__").unwrap_or(stem);
    stem.replace('/', ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_module_key_uses_source_root() {
        // No packages: a flat file keys to its bare stem.
        let none = BTreeSet::new();
        assert_eq!(python_module_key("util.py", &none, &none), "util");

        // src-layout: `src` is not a package but `src/black` is, so the source
        // root is `src` and the key is relative to it.
        let pkgs: BTreeSet<String> = ["src/black".to_string(), "pkg".to_string()]
            .into_iter()
            .collect();
        assert_eq!(
            python_module_key("src/black/files.py", &pkgs, &pkgs),
            "black.files"
        );
        assert_eq!(
            python_module_key("src/black/__init__.py", &pkgs, &pkgs),
            "black"
        );
        assert_eq!(python_module_key("pkg/mod.py", &pkgs, &pkgs), "pkg.mod");
        assert_eq!(python_module_key("pkg/__init__.py", &pkgs, &pkgs), "pkg");
    }

    #[test]
    fn python_module_key_src_layout_without_init() {
        // `src/pkg` has no `__init__.py` (PEP 420 / src-layout ownership).
        let implicit: BTreeSet<String> = ["src/pkg".to_string(), "src/pkg/console".to_string()]
            .into_iter()
            .collect();
        let none = BTreeSet::new();
        assert_eq!(
            python_module_key("src/pkg/console/application.py", &implicit, &none),
            "pkg.console.application"
        );
        assert_eq!(
            python_module_key("src/pkg/__main__.py", &implicit, &none),
            "pkg.__main__"
        );
    }

    #[test]
    fn python_module_key_implicit_namespace_outside_src() {
        let implicit: BTreeSet<String> = ["pkg".to_string()].into_iter().collect();
        let none = BTreeSet::new();
        assert_eq!(python_module_key("pkg/mod.py", &implicit, &none), "pkg.mod");
    }
}
