//! Go modules from `go.mod`, the package a Go file declares, and the module that
//! owns a directory.

use std::collections::BTreeMap;
use std::path::Path;

use crate::{CRAWL_SKIP_DIRS, walked_repo_path};

pub(super) fn go_module_source(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        line.strip_prefix("module ")
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
    })
}

fn go_module_path(path: &Path) -> Option<String> {
    go_module_source(&std::fs::read_to_string(path).ok()?)
}

pub(super) fn collect_go_modules(
    root: &Path,
    admit: &mut dyn FnMut(&Path) -> bool,
) -> BTreeMap<String, String> {
    fn visit(
        root: &Path,
        dir: &Path,
        modules: &mut BTreeMap<String, String>,
        admit: &mut dyn FnMut(&Path) -> bool,
    ) {
        let mut entries: Vec<_> = match std::fs::read_dir(dir) {
            Ok(entries) => entries.filter_map(Result::ok).collect(),
            Err(_) => return,
        };
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            if crate::canonical_repo_path(root, &path).is_none() {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !CRAWL_SKIP_DIRS.contains(&name.as_str()) && name != ".claude" {
                    visit(root, &path, modules, admit);
                }
            } else if file_type.is_file()
                && entry.file_name() == "go.mod"
                && admit(&path)
                && let Some(module) = go_module_path(&path)
            {
                let dir = path
                    .parent()
                    .map(|parent| walked_repo_path(root, parent))
                    .unwrap_or_default();
                modules.insert(dir, module);
            }
        }
    }

    let mut modules = BTreeMap::new();
    visit(root, root, &mut modules, admit);
    modules
}

pub(super) fn go_package_name(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("package ")?.trim_start();
        let name: String = rest
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    })
}

pub(super) fn go_module_for_dir<'a>(
    dir: &str,
    go_modules: &'a BTreeMap<String, String>,
) -> Option<(&'a String, &'a String)> {
    let mut module_dir = dir;
    loop {
        if let Some(entry) = go_modules.get_key_value(module_dir) {
            return Some(entry);
        }
        if module_dir.is_empty() {
            return None;
        }
        module_dir = module_dir
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
    }
}
