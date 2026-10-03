//! JS/TS workspace packages: package.json discovery and the package `exports`,
//! `main` and `module` targets a bare import specifier resolves through.

use std::collections::BTreeMap;
use std::path::Path;

use crate::CRAWL_SKIP_DIRS;

pub(super) const JS_BUILD_DIRS: [&str; 5] = ["build", "dist", "lib", "out", "output"];

/// One JS/TS workspace package: the directory that owns a `package.json`
/// `name`, plus the export/main/bin surface used to map specifiers to files.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct JsPackage {
    pub name: Option<String>,
    /// Repo-relative package directory (empty at the repo root).
    pub dir: String,
    pub exports: Option<serde_json::Value>,
    pub main: Option<String>,
    pub module_field: Option<String>,
    /// Package-relative `bin` targets.
    pub bins: Vec<String>,
}

/// Every package.json under `root` (skipping vendored/test trees). First
/// (shallowest) declaration of a name wins when building the name map.
pub(crate) fn collect_js_packages(
    root: &Path,
    admit: &mut dyn FnMut(&Path) -> bool,
) -> Vec<JsPackage> {
    fn walk(
        root: &Path,
        dir: &Path,
        depth: u32,
        out: &mut Vec<JsPackage>,
        admit: &mut dyn FnMut(&Path) -> bool,
    ) {
        if depth > 4 || out.len() >= 256 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let path = entry.path();
            if crate::canonical_repo_path(root, &path).is_none() {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if CRAWL_SKIP_DIRS.contains(&name.as_str())
                    || matches!(
                        name.as_str(),
                        "tests" | "testdata" | "fixtures" | "examples" | "dist" | "build"
                    )
                {
                    continue;
                }
                walk(root, &path, depth + 1, out, admit);
            } else if ft.is_file()
                && entry.file_name() == "package.json"
                && admit(&path)
                && let Some(pkg) = parse_js_package(root, &path)
            {
                out.push(pkg);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, 0, &mut out, admit);
    out
}

pub(super) fn named_js_packages(
    root: &Path,
    admit: &mut dyn FnMut(&Path) -> bool,
) -> BTreeMap<String, JsPackage> {
    let mut out = BTreeMap::new();
    for pkg in collect_js_packages(root, admit) {
        if let Some(name) = pkg.name.clone() {
            out.entry(name).or_insert(pkg);
        }
    }
    out
}

fn parse_js_package(root: &Path, path: &Path) -> Option<JsPackage> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let dir = path
        .parent()
        .unwrap_or(root)
        .strip_prefix(root)
        .unwrap_or(path.parent().unwrap_or(root))
        .to_string_lossy()
        .replace('\\', "/");
    let norm = |s: &str| s.trim_start_matches("./").to_string();
    let bins = match json.get("bin") {
        Some(serde_json::Value::Object(map)) => {
            map.values().filter_map(|v| v.as_str()).map(norm).collect()
        }
        Some(serde_json::Value::String(s)) => vec![norm(s)],
        _ => Vec::new(),
    };
    Some(JsPackage {
        name: json
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        dir,
        exports: json.get("exports").cloned(),
        main: json.get("main").and_then(|v| v.as_str()).map(norm),
        module_field: json.get("module").and_then(|v| v.as_str()).map(norm),
        bins,
    })
}

/// Split `@scope/name/sub` into (`@scope/name`, `./sub`) and `name` into
/// (`name`, `.`).
pub(super) fn split_npm_spec(spec: &str) -> (&str, String) {
    let slash = if let Some(rest) = spec.strip_prefix('@') {
        rest.find('/')
            .and_then(|scope| spec[scope + 2..].find('/').map(|j| scope + 2 + j))
    } else {
        spec.find('/')
    };
    match slash {
        Some(i) => (&spec[..i], format!(".{}", &spec[i..])),
        None => (spec, ".".to_string()),
    }
}

/// Package-relative artifact a subpath (`.` / `./changelog`) names.
pub(crate) fn js_package_artifact(pkg: &JsPackage, sub: &str) -> Option<String> {
    js_package_artifact_for(pkg, sub, false)
}

pub(super) fn js_package_artifact_for(
    pkg: &JsPackage,
    sub: &str,
    commonjs: bool,
) -> Option<String> {
    if let Some(exports) = &pkg.exports {
        return match exports {
            serde_json::Value::String(s) if sub == "." => {
                Some(s.trim_start_matches("./").to_string())
            }
            serde_json::Value::Object(map) => {
                let target = if let Some(value) = map.get(sub) {
                    export_target(value, commonjs)
                } else if sub == "." && map.keys().all(|key| !key.starts_with('.')) {
                    export_target(exports, commonjs)
                } else {
                    export_pattern_target(map, sub, commonjs)
                }?;
                Some(target.trim_start_matches("./").to_string())
            }
            _ => None,
        };
    }
    if sub != "." {
        return None;
    }
    if commonjs {
        pkg.main.clone().or_else(|| pkg.module_field.clone())
    } else {
        pkg.module_field.clone().or_else(|| pkg.main.clone())
    }
}

fn export_pattern_target(
    map: &serde_json::Map<String, serde_json::Value>,
    sub: &str,
    commonjs: bool,
) -> Option<String> {
    let mut matches = Vec::new();
    for (pattern, value) in map {
        let Some((prefix, suffix)) = pattern.split_once('*') else {
            continue;
        };
        let Some(middle) = sub
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
        else {
            continue;
        };
        let Some(target) = export_target(value, commonjs) else {
            continue;
        };
        let replaced = target.replace('*', middle);
        matches.push((prefix.len() + suffix.len(), pattern.len(), replaced));
    }
    matches.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    let best = matches.first()?;
    if matches
        .get(1)
        .is_some_and(|next| (next.0, next.1) == (best.0, best.1) && next.2 != best.2)
    {
        return None;
    }
    Some(best.2.clone())
}

/// Resolve a (possibly conditional) exports target: prefer ESM `import`, then
/// `node` / `default` / `module` / `require`. `types` is never a runtime file.
fn export_target(value: &serde_json::Value, commonjs: bool) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => {
            let keys = if commonjs {
                ["require", "node", "default", "module", "import"]
            } else {
                ["import", "node", "default", "module", "require"]
            };
            for key in keys {
                if let Some(v) = map.get(key)
                    && let Some(t) = export_target(v, commonjs)
                {
                    return Some(t);
                }
            }
            None
        }
        _ => None,
    }
}
