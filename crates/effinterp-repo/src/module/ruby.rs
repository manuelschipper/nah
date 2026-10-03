use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use effinterp_engine::Lang;
use effinterp_proto::content_digest;

use super::{ModuleFile, ModuleRegistry, ruby_shebang};
use crate::index::{CrawlLimits, IndexBudget};
use crate::snapshot::InputRecord;
use crate::{CRAWL_SKIP_DIRS, walked_repo_path};

fn ruby_loader_work(budget: &mut IndexBudget, work: usize, bytes: usize) -> bool {
    budget.charge(work as u64, bytes as u64).is_ok()
}

impl ModuleRegistry {
    pub(crate) fn ruby_resolution_digest(&self) -> String {
        effinterp_proto::stable_hash(
            "effinterp/ruby-resolution/v1",
            &(
                &self.ruby_load_paths,
                &self.ruby_file_load_paths,
                &self.ruby_closure_load_paths,
                &self.ruby_conventional_load_paths,
                &self.ruby_gems,
                &self.ruby_gem_sources,
            ),
        )
    }

    /// Refresh Ruby loader evidence only from admitted inputs and proven launch wrappers.
    pub(crate) fn reindex_ruby_inputs(
        &mut self,
        root: &Path,
        inputs: &[InputRecord],
        launches: &[crate::discover::LaunchEdge],
        budget: &mut IndexBudget,
    ) {
        self.ruby_loader_incomplete = true;
        self.ruby_metadata_load_paths.clear();
        self.ruby_conventional_load_paths.clear();
        self.ruby_launch_load_paths.clear();
        self.ruby_gems.clear();
        self.ruby_gem_sources.clear();
        for input in inputs {
            if !ruby_loader_work(budget, 1, 0) {
                return;
            }
            let path = Path::new(&input.path);
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let metadata = matches!(name, "Gemfile" | "Gemfile.lock")
                || path.extension().is_some_and(|ext| ext == "gemspec");
            let ruby = self
                .files
                .get(&input.path)
                .is_some_and(|file| file.lang == Lang::Ruby);
            let targets: Vec<_> = launches
                .iter()
                .filter(|edge| edge.wrapper == input.path && edge.launched.ends_with(".rb"))
                .collect();
            if !metadata && !ruby && targets.is_empty() {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(root.join(&input.path)) else {
                continue;
            };
            if !ruby_loader_work(budget, source.len(), source.len()) {
                return;
            }
            let dir = input
                .path
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or("");
            if metadata {
                if name == "Gemfile.lock" {
                    let mut specs = false;
                    for line in source.lines() {
                        if line == "  specs:" {
                            specs = true;
                        } else if !line.starts_with(' ') && !line.is_empty() {
                            specs = false;
                        } else if specs
                            && line.starts_with("    ")
                            && !line.starts_with("     ")
                            && let Some((gem, version)) = line.trim().split_once(" (")
                            && let Some(version) = version.strip_suffix(')')
                        {
                            self.ruby_gems.insert(gem.into(), version.into());
                            self.ruby_gem_sources.insert(gem.into(), input.path.clone());
                        }
                    }
                } else {
                    if let Some(lib) = ruby_root(dir, "lib") {
                        self.ruby_conventional_load_paths.insert(lib);
                    }
                    let (paths, gems) = effinterp_engine::ruby_package_metadata(&source);
                    self.ruby_metadata_load_paths
                        .extend(paths.iter().filter_map(|path| ruby_root(dir, path)));
                    for (gem, version) in gems {
                        if !self.ruby_gems.contains_key(&gem) {
                            self.ruby_gems.insert(gem.clone(), version);
                            self.ruby_gem_sources.insert(gem, input.path.clone());
                        }
                    }
                }
            }
            if ruby && ruby_shebang(&source) {
                let roots = ruby_launch_paths(source.lines().next().unwrap_or(""));
                self.add_ruby_launch_paths(&input.path, dir, roots);
            }
            let rubylib_paths = if !targets.is_empty() && source.contains("RUBYLIB") {
                effinterp_engine::shell_rubylib_paths(&source)
            } else {
                Vec::new()
            };
            for edge in targets {
                let Some(process) = &edge.process else {
                    continue;
                };
                let effinterp_proto::ResourceExpr::Concrete {
                    identity:
                        effinterp_proto::ResourceIdentity::Process {
                            executable,
                            argv,
                            cwd,
                            ..
                        },
                } = &process.resource
                else {
                    continue;
                };
                if executable.rsplit('/').next() != Some("ruby") {
                    continue;
                }
                let launch_dir = match cwd.as_deref() {
                    Some(effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    }) => path.as_str(),
                    _ => dir,
                };
                let words: Vec<_> = argv
                    .iter()
                    .map(|arg| match arg {
                        effinterp_proto::ResourceExpr::Literal { value } => value.as_str(),
                        _ => "",
                    })
                    .collect();
                self.add_ruby_launch_paths(&edge.launched, launch_dir, ruby_option_paths(&words));
                self.add_ruby_launch_paths(&edge.launched, launch_dir, rubylib_paths.clone());
            }
        }
        self.reindex_ruby_sources(budget);
    }

    pub(super) fn reindex_ruby_sources(&mut self, budget: &mut IndexBudget) {
        self.ruby_loader_incomplete = true;
        self.ruby_closure_load_paths.clear();
        self.ruby_import_candidates.clear();
        self.ruby_load_paths = self.ruby_metadata_load_paths.clone();
        self.ruby_file_load_paths = self.ruby_launch_load_paths.clone();
        for file in self.files.values().filter(|file| file.lang == Lang::Ruby) {
            if !ruby_loader_work(
                budget,
                file.summary.load_path_roots.len() + 1,
                file.summary
                    .load_path_roots
                    .iter()
                    .map(|root| root.len() + file.dir.len() + 32)
                    .sum(),
            ) {
                return;
            }
            self.ruby_file_load_paths
                .entry(file.path.clone())
                .or_default()
                .extend(
                    file.summary
                        .load_path_roots
                        .iter()
                        .filter_map(|path| ruby_root(&file.dir, path)),
                );
        }
        for roots in self.ruby_file_load_paths.values() {
            self.ruby_load_paths.extend(roots.iter().cloned());
        }
        // Resolve each direct import once. Closure walks share these edges instead of
        // scanning every load path again for every importer reaching the same file.
        let mut requires = BTreeMap::new();
        for file in self.files.values().filter(|file| file.lang == Lang::Ruby) {
            let mut targets = Vec::new();
            for import in file
                .summary
                .imports
                .iter()
                .chain(&file.summary.scoped_imports)
            {
                let probes = self
                    .ruby_file_load_paths
                    .get(&file.path)
                    .map_or(0, BTreeSet::len)
                    + self.ruby_load_paths.len()
                    + self.ruby_conventional_load_paths.len()
                    + 1;
                if !ruby_loader_work(budget, probes, 0) {
                    return;
                }
                if let [(_, target)] = self.ruby_direct_candidates(file, &import.module).as_slice()
                    && let Some(target) = self.files.get(target)
                {
                    targets.push(target.as_ref());
                }
            }
            requires.insert(file.path.as_str(), targets);
        }
        let mut closures = BTreeMap::new();
        for file in self.files.values().filter(|file| file.lang == Lang::Ruby) {
            let Some(roots) = self.ruby_require_roots(file, &requires, budget) else {
                return;
            };
            let bytes = file.path.len() + 32;
            if !ruby_loader_work(budget, 1, bytes) {
                return;
            }
            closures.insert(file.path.clone(), roots);
        }
        self.ruby_closure_load_paths = closures;
        self.reindex_ruby_import_candidates(budget);
    }

    pub(super) fn reindex_ruby_import_candidates(&mut self, budget: &mut IndexBudget) {
        self.ruby_loader_incomplete = true;
        self.ruby_import_candidates.clear();
        // Composition repeatedly revisits require closures for class and receiver
        // lookup. Cache the final tiered answer, including misses and ambiguity.
        let mut candidates = BTreeMap::new();
        for file in self.files.values().filter(|file| file.lang == Lang::Ruby) {
            let mut imports = BTreeMap::new();
            for import in file
                .summary
                .imports
                .iter()
                .chain(&file.summary.scoped_imports)
            {
                if imports.contains_key(&import.module) {
                    continue;
                }
                let probes = self
                    .ruby_closure_load_paths
                    .get(&file.path)
                    .map_or(0, BTreeSet::len)
                    + self.ruby_load_paths.len()
                    + self.ruby_conventional_load_paths.len()
                    + 1;
                if !ruby_loader_work(budget, probes, 0) {
                    return;
                }
                let resolved = self.ruby_uncached_require_candidates(file, &import.module);
                let bytes = import.module.len()
                    + 32
                    + resolved
                        .iter()
                        .map(|(root, target)| root.len() + target.len() + 48)
                        .sum::<usize>();
                if !ruby_loader_work(budget, 0, bytes) {
                    return;
                }
                imports.insert(import.module.clone(), resolved);
            }
            candidates.insert(file.path.clone(), imports);
        }
        self.ruby_import_candidates = candidates;
        self.ruby_loader_incomplete = false;
    }

    fn add_ruby_launch_paths(&mut self, file: &str, dir: &str, paths: Vec<String>) {
        let roots: BTreeSet<_> = paths
            .iter()
            .filter_map(|path| ruby_root(dir, path))
            .collect();
        self.ruby_launch_load_paths
            .entry(file.into())
            .or_default()
            .extend(roots);
    }

    pub(crate) fn ruby_gem(&self, module: &str) -> Option<(&str, &str, &str)> {
        let head = module.split('/').next()?.replace('-', "_");
        self.ruby_gems
            .iter()
            .find(|(name, _)| name.replace('-', "_") == head)
            .map(|(name, version)| {
                (
                    name.as_str(),
                    version.as_str(),
                    self.ruby_gem_sources[name].as_str(),
                )
            })
    }

    fn ruby_candidates(&self, roots: &BTreeSet<String>, module: &str) -> Vec<(String, String)> {
        let stem = module.strip_suffix(".rb").unwrap_or(module);
        roots
            .iter()
            .filter_map(|root| {
                let candidate = format!("{}.rb", ruby_root(root, stem)?);
                self.files
                    .contains_key(&candidate)
                    .then(|| (root.clone(), candidate))
            })
            .collect()
    }

    fn ruby_direct_candidates(&self, importer: &ModuleFile, module: &str) -> Vec<(String, String)> {
        if module.starts_with('.') || module.starts_with('/') {
            return self.ruby_candidates(&BTreeSet::from([importer.dir.clone()]), module);
        }
        if let Some(roots) = self.ruby_file_load_paths.get(&importer.path) {
            let candidates = self.ruby_candidates(roots, module);
            if !candidates.is_empty() {
                return candidates;
            }
        }
        let candidates = self.ruby_candidates(&self.ruby_load_paths, module);
        if !candidates.is_empty() {
            return candidates;
        }
        let conventional = self.ruby_candidates(&self.ruby_conventional_load_paths, module);
        if !conventional.is_empty() {
            return conventional;
        }
        self.ruby_candidates(&BTreeSet::from([String::new()]), module)
    }

    fn ruby_require_roots<'a>(
        &self,
        importer: &'a ModuleFile,
        requires: &BTreeMap<&str, Vec<&'a ModuleFile>>,
        budget: &mut IndexBudget,
    ) -> Option<BTreeSet<String>> {
        let mut roots = BTreeSet::new();
        let mut pending = vec![importer];
        let mut seen = BTreeSet::new();
        while let Some(file) = pending.pop() {
            if seen.len() >= 128 {
                break;
            }
            if !ruby_loader_work(budget, 1, 0) {
                return None;
            }
            if !seen.insert(file.path.as_str()) {
                continue;
            }
            if let Some(file_roots) = self.ruby_file_load_paths.get(&file.path) {
                if !ruby_loader_work(budget, file_roots.len(), 0) {
                    return None;
                }
                for root in file_roots {
                    if !roots.contains(root) {
                        if !ruby_loader_work(budget, 0, root.len() + 32) {
                            return None;
                        }
                        roots.insert(root.clone());
                    }
                }
            }
            if let Some(targets) = requires.get(file.path.as_str()) {
                pending.extend(targets.iter().copied());
            }
        }
        Some(roots)
    }

    fn ruby_require_candidates(
        &self,
        importer: &ModuleFile,
        module: &str,
    ) -> Vec<(String, String)> {
        // Finalization also resolves imports. An interrupted loader pass must not
        // restart its work there or resolve against only part of the root evidence.
        if self.ruby_loader_incomplete {
            return Vec::new();
        }
        if let Some(candidates) = self
            .ruby_import_candidates
            .get(&importer.path)
            .and_then(|imports| imports.get(module))
        {
            return candidates.clone();
        }
        self.ruby_uncached_require_candidates(importer, module)
    }

    fn ruby_uncached_require_candidates(
        &self,
        importer: &ModuleFile,
        module: &str,
    ) -> Vec<(String, String)> {
        if module.starts_with('.') || module.starts_with('/') {
            return self.ruby_direct_candidates(importer, module);
        }
        let roots = self.ruby_closure_load_paths.get(&importer.path);
        let candidates = roots
            .map(|roots| self.ruby_candidates(roots, module))
            .unwrap_or_default();
        if !candidates.is_empty() {
            return candidates;
        }
        self.ruby_direct_candidates(importer, module)
    }

    pub(crate) fn ruby_import_diagnostic(
        &self,
        importer: &ModuleFile,
        module: &str,
    ) -> Option<String> {
        if importer.lang != Lang::Ruby {
            return None;
        }
        if self.ruby_loader_incomplete {
            return Some("Ruby loader evidence is incomplete".into());
        }
        let candidates = self.ruby_require_candidates(importer, module);
        (candidates.len() > 1).then(|| {
            format!(
                "require {module:?} is ambiguous across load paths {}",
                candidates
                    .into_iter()
                    .map(|(root, _)| if root.is_empty() { ".".into() } else { root })
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    }

    pub(super) fn resolve_ruby(&self, importer: &ModuleFile, module: &str) -> Option<String> {
        match self.ruby_require_candidates(importer, module).as_slice() {
            [(_, target)] => Some(target.clone()),
            _ => None,
        }
    }
}

fn ruby_root(dir: &str, path: &str) -> Option<String> {
    if path.starts_with('/') || path.contains(['$', '`']) {
        return None;
    }
    let mut parts: Vec<_> = dir.split('/').filter(|part| !part.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

fn ruby_launch_paths(command: &str) -> Vec<String> {
    let words: Vec<_> = command.split_whitespace().collect();
    let Some(ruby) = words
        .iter()
        .position(|word| word.rsplit('/').next() == Some("ruby"))
    else {
        return Vec::new();
    };
    ruby_option_paths(&words[ruby + 1..])
}

fn ruby_option_paths(words: &[&str]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        if !word.starts_with('-') || matches!(word, "--" | "-e") {
            break;
        }
        let value = if word == "-I" {
            index += 1;
            words.get(index).copied()
        } else if matches!(word, "-r" | "-E" | "--encoding") {
            index += 1;
            None
        } else {
            word.strip_prefix("-I")
        };
        if let Some(value) = value {
            paths.extend(
                value
                    .trim_matches(['\'', '"'])
                    .split(':')
                    .filter(|path| !path.is_empty())
                    .map(str::to_string),
            );
        }
        index += 1;
    }
    paths
}

pub(super) fn collect_ruby_metadata(
    root: &Path,
    admitted: Option<&BTreeSet<String>>,
    limits: &CrawlLimits,
    admit: &mut dyn FnMut(&Path) -> bool,
) -> Vec<InputRecord> {
    let metadata_path = |path: &Path| {
        matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("Gemfile" | "Gemfile.lock")
        ) || path.extension().is_some_and(|ext| ext == "gemspec")
    };
    let mut candidates = Vec::new();
    if let Some(admitted) = admitted {
        candidates.extend(
            admitted
                .iter()
                .filter(|path| metadata_path(Path::new(path)))
                .map(|path| root.join(path)),
        );
    } else {
        let mut pending = vec![(root.to_path_buf(), 0)];
        let mut visited = 0;
        while let Some((dir, depth)) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                visited += 1;
                if visited > limits.max_files {
                    pending.clear();
                    break;
                }
                let path = entry.path();
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_symlink() || crate::canonical_repo_path(root, &path).is_none() {
                    continue;
                }
                if kind.is_dir() && depth < limits.max_depth {
                    if !CRAWL_SKIP_DIRS.contains(&entry.file_name().to_string_lossy().as_ref()) {
                        pending.push((path, depth + 1));
                    }
                } else if kind.is_file() && metadata_path(&path) {
                    candidates.push(path);
                }
            }
        }
    }
    candidates.sort();
    candidates
        .into_iter()
        .filter_map(|path| {
            if !admit(&path) {
                return None;
            }
            let source = std::fs::read(&path).ok()?;
            Some(InputRecord {
                path: walked_repo_path(root, &path),
                digest: content_digest(&source),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use effinterp_engine::{ImportBinding, ModuleSummary};

    use super::*;
    use crate::index::RepositoryLimits;

    // Loader graph construction used to bypass repository budgets.
    #[test]
    fn ruby_loader_obeys_repository_limits() {
        let mut registry = ModuleRegistry::default();
        for i in 0..200 {
            registry.insert(ModuleFile {
                path: format!("f{i}.rb"),
                dir: String::new(),
                lang: Lang::Ruby,
                summary: ModuleSummary {
                    load_path_roots: vec![format!("root{i}")],
                    imports: (1..=8)
                        .map(|j| ImportBinding {
                            local: String::new(),
                            module: format!("f{}", (i + j) % 200),
                            imported: None,
                        })
                        .collect(),
                    ..ModuleSummary::default()
                },
                digest: String::new(),
            });
        }
        registry.reindex_ruby_sources(&mut IndexBudget::new(RepositoryLimits::default()));
        assert_eq!(registry.ruby_closure_load_paths.len(), 200);
        assert_eq!(
            registry.resolve_ruby(&registry.files["f0.rb"], "f1"),
            Some("f1.rb".into())
        );
        for (limits, expected) in [
            (
                RepositoryLimits {
                    max_repo_work_units: 1_000,
                    ..RepositoryLimits::default()
                },
                "repository.max_repo_work_units",
            ),
            (
                RepositoryLimits {
                    max_index_bytes: 100,
                    ..RepositoryLimits::default()
                },
                "repository.max_index_bytes",
            ),
        ] {
            let mut budget = IndexBudget::new(limits);
            registry.reindex_ruby_sources(&mut budget);
            assert_eq!(budget.charge(0, 0), Err(expected));
            assert!(registry.ruby_closure_load_paths.is_empty());
        }
    }
}
