use std::io;
use std::path::{Path, PathBuf};

use effinterp_engine::{
    SourceNamespace, SourcePurpose, SourceRefusal, SourceRequest, SourceResolver, SourceResponse,
    UnavailableReason,
};
use effinterp_proto::native_extension_candidate;

use crate::is_executable;

/// Reads invocation-selected files and explicit dependencies beneath one canonical cwd root.
pub struct ShallowSourceResolver {
    root: PathBuf,
    anchor: String,
    max_source_bytes: u64,
    inventory: std::sync::OnceLock<Option<Vec<String>>>,
}

impl ShallowSourceResolver {
    /// Create a resolver rooted at `root`; `anchor` must be the subject's
    /// normalized cwd in the engine's path namespace.
    pub fn new(root: &Path, anchor: &str, max_source_bytes: u64) -> io::Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
            anchor: anchor.to_string(),
            max_source_bytes,
            inventory: std::sync::OnceLock::new(),
        })
    }

    fn relative<'a>(&self, request: SourceRequest<'a>) -> Result<&'a str, SourceRefusal> {
        let relative = match request.namespace {
            SourceNamespace::Host if self.anchor.is_empty() => {
                return Err(SourceRefusal::Unavailable(
                    UnavailableReason::NamespaceDenied,
                ));
            }
            SourceNamespace::Host => {
                if request.path == self.anchor {
                    ""
                } else if self.anchor == "/" {
                    request
                        .path
                        .strip_prefix('/')
                        .ok_or(SourceRefusal::Unavailable(
                            UnavailableReason::NamespaceDenied,
                        ))?
                } else {
                    request
                        .path
                        .strip_prefix(&format!("{}/", self.anchor.trim_end_matches('/')))
                        .ok_or(SourceRefusal::Unavailable(
                            if request.purpose == SourcePurpose::DependencySource {
                                UnavailableReason::Escapes
                            } else {
                                UnavailableReason::NamespaceDenied
                            },
                        ))?
                }
            }
            SourceNamespace::Repository if self.anchor.is_empty() => request.path,
            SourceNamespace::Repository => {
                return Err(SourceRefusal::Unavailable(
                    UnavailableReason::NamespaceDenied,
                ));
            }
        };
        if request.purpose == SourcePurpose::DependencySource
            && relative.split('/').any(|part| part == "..")
        {
            return Err(SourceRefusal::Unavailable(UnavailableReason::Escapes));
        }
        Ok(relative)
    }

    fn target(&self, request: SourceRequest<'_>) -> Result<PathBuf, SourceRefusal> {
        let target = self.root.join(self.relative(request)?);
        let canonical = target
            .canonicalize()
            .map_err(|_| SourceRefusal::Unavailable(UnavailableReason::Missing))?;
        if !canonical.starts_with(&self.root) {
            return Err(SourceRefusal::Unavailable(UnavailableReason::Escapes));
        }
        Ok(canonical)
    }
}

impl SourceResolver for ShallowSourceResolver {
    fn matching(&self, pattern: &effinterp_engine::SourcePattern) -> Option<Vec<String>> {
        let inventory = self
            .inventory
            .get_or_init(|| {
                let mut pending = vec![self.root.clone()];
                let mut files = Vec::new();
                let max_files = crate::index::CrawlLimits::default().max_files as usize;
                let mut visited = 0;
                while let Some(directory) = pending.pop() {
                    for entry in std::fs::read_dir(directory).ok()? {
                        let entry = entry.ok()?;
                        if entry.file_name() == ".git" {
                            continue;
                        }
                        visited += 1;
                        if visited > max_files {
                            return None;
                        }
                        let kind = entry.file_type().ok()?;
                        if kind.is_dir() {
                            pending.push(entry.path());
                        }
                        if kind.is_file() {
                            let path = entry.path();
                            let relative = path.strip_prefix(&self.root).ok()?.to_str()?;
                            files.push(if self.anchor.is_empty() {
                                relative.to_string()
                            } else {
                                format!("{}/{relative}", self.anchor.trim_end_matches('/'))
                            });
                        }
                    }
                }
                files.sort();
                Some(files)
            })
            .as_ref()?;
        Some(
            inventory
                .iter()
                .filter(|path| pattern.matches(path))
                .cloned()
                .collect(),
        )
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        let target = match self.target(request) {
            Ok(target) => target,
            Err(refusal) => return SourceResponse::Refused(refusal),
        };
        let metadata = match target.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                return SourceResponse::Refused(SourceRefusal::Unavailable(
                    UnavailableReason::Missing,
                ));
            }
        };
        if !metadata.is_file() {
            return SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NotAFile,
            ));
        }
        if request.purpose == SourcePurpose::ExecutableInput && !is_executable(&metadata) {
            return SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NotAFile,
            ));
        }
        if metadata.len() > self.max_source_bytes {
            return SourceResponse::Refused(SourceRefusal::Limit {
                limit: "max_source_bytes",
            });
        }
        match std::fs::read(target) {
            Ok(source) => SourceResponse::Source(source),
            Err(_) => {
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
            }
        }
    }

    fn source_mutation_disjoint(
        &self,
        resource: &effinterp_proto::ResourceExpr,
        request: SourceRequest<'_>,
    ) -> bool {
        use effinterp_proto::{ResourceExpr, ResourceIdentity};
        match resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => {
                let written = SourceRequest {
                    path,
                    namespace: if path.starts_with('/') {
                        SourceNamespace::Host
                    } else {
                        SourceNamespace::Repository
                    },
                    ..request
                };
                let Ok(source) = self.relative(request) else {
                    return false;
                };
                match self.relative(written) {
                    Ok(written) => source_paths_disjoint(&self.root, written, &self.root, source),
                    // Repository-relative sources and a host cwd matching the
                    // physical root can observe absolute mutation metadata, never
                    // source bytes outside the admitted root.
                    Err(_)
                        if (self.anchor.is_empty()
                            || Path::new(&self.anchor).canonicalize().ok().as_ref()
                                == Some(&self.root))
                            && path.starts_with('/') =>
                    {
                        source_paths_disjoint(Path::new("/"), path, &self.root, source)
                    }
                    Err(_) => false,
                }
            }
            ResourceExpr::Concrete { .. } => true,
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            } if !glob.contains(['*', '?', '[', '{', '\\']) => self.source_mutation_disjoint(
                &ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: glob.clone() },
                },
                request,
            ),
            ResourceExpr::Union { alternatives } => alternatives
                .iter()
                .all(|resource| self.source_mutation_disjoint(resource, request)),
            ResourceExpr::Join { parts } if request.namespace == SourceNamespace::Repository => {
                let mut parts = parts.as_slice();
                if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")
                {
                    parts = &parts[1..];
                }
                let Some(parts) = parts
                    .iter()
                    .map(|part| match part {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } => Some(path.as_str()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                source_paths_disjoint(&self.root, &parts.join("/"), &self.root, request.path)
            }
            _ => false,
        }
    }

    fn python_native_candidates_absent(&self, request: SourceRequest<'_>) -> bool {
        self.relative(request)
            .is_ok_and(|relative| python_native_candidates_absent(&self.root, relative))
    }

    fn siblings(&self, _path: &str) -> Option<Vec<String>> {
        None
    }
}

// Missing leaf files still have an observed parent: predict their location
// without inventing the target of a dangling symlink or leaving the source root.
fn source_canonical_location(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = root.join(relative);
    let mut existing = path.as_path();
    let canonical = loop {
        match existing.canonicalize() {
            Ok(canonical) => break canonical,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if existing.symlink_metadata().is_ok() {
                    return None;
                }
                existing = existing.parent()?;
            }
            Err(_) => return None,
        }
    };
    if !canonical.starts_with(root) {
        return None;
    }
    let suffix = path.strip_prefix(existing).ok()?;
    // Joining an empty suffix adds a slash: metadata on an existing file
    // would then fail with NotADirectory instead of observing its identity.
    Some(if suffix.as_os_str().is_empty() {
        canonical
    } else {
        canonical.join(suffix)
    })
}

fn source_paths_disjoint(
    written_root: &Path,
    written: &str,
    source_root: &Path,
    source: &str,
) -> bool {
    let (Some(written), Some(source)) = (
        source_canonical_location(written_root, written),
        source_canonical_location(source_root, source),
    ) else {
        return false;
    };
    if source.starts_with(&written) {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let written = match written.metadata() {
            Ok(metadata) => metadata,
            Err(error) => return error.kind() == io::ErrorKind::NotFound,
        };
        // File identity catches hardlinks and case aliases. Ancestors also
        // matter when a mutation replaces a directory containing the source.
        for ancestor in source.ancestors() {
            match ancestor.metadata() {
                Ok(metadata)
                    if metadata.dev() == written.dev() && metadata.ino() == written.ino() =>
                {
                    return false;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return false,
            }
        }
        true
    }
    #[cfg(not(unix))]
    false
}

/// Directory entries one native-extension observation may read before the
/// answer is unproven.
const DIRECTORY_ENTRY_LIMIT: usize = 256;

/// Observe only the directory of a demanded Python module/package stem. Never
/// infer a build suffix list from the files admitted by repository indexing.
pub(crate) fn python_native_candidates_absent(root: &Path, relative: &str) -> bool {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return false;
    }
    let Some(stem) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let parent = root.join(path.parent().unwrap_or(Path::new("")));
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    let mut existing = parent.as_path();
    let directory = loop {
        match existing.canonicalize() {
            Ok(directory) => break directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(ancestor) = existing.parent() else {
                    return false;
                };
                existing = ancestor;
            }
            Err(_) => return false,
        }
    };
    if !directory.starts_with(&root) {
        return false;
    }
    if existing != parent {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return false;
    };
    for (index, entry) in entries.enumerate() {
        if index >= DIRECTORY_ENTRY_LIMIT {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if native_extension_candidate(name, stem) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "effinterp-shallow-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn request<'a>(
        path: &'a str,
        namespace: SourceNamespace,
        purpose: SourcePurpose,
    ) -> SourceRequest<'a> {
        SourceRequest {
            path,
            namespace,
            purpose,
            requester_language: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_inventory_excludes_symlinks_git_and_nonfiles() {
        let temp = TempRoot::new();
        std::fs::create_dir(temp.0.join(".git")).unwrap();
        std::fs::create_dir(temp.0.join("directory.sh")).unwrap();
        std::fs::write(temp.0.join(".git/hidden.sh"), "touch /hidden").unwrap();
        std::fs::write(temp.0.join("a.sh"), "touch /selected").unwrap();
        std::os::unix::fs::symlink(temp.0.join("a.sh"), temp.0.join("link.sh")).unwrap();
        std::os::unix::fs::symlink(&temp.0, temp.0.join("cycle")).unwrap();
        let cwd = temp.0.to_str().unwrap();
        let plan = effinterp_engine::Engine::new()
            .with_resolver(Box::new(
                ShallowSourceResolver::new(&temp.0, cwd, 1024).unwrap(),
            ))
            .analyze(&effinterp_proto::Subject::Shell {
                source: "source \"${ROOT}/${NAME}.sh\"".into(),
                cwd: Some(cwd.into()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        let paths: Vec<_> = plan
            .execution_graph
            .nodes
            .iter()
            .filter_map(|node| node.selected_source_path())
            .collect();
        assert_eq!(paths, vec![format!("{cwd}/a.sh")]);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.metadata"
                    && effinterp_proto::display_resource(&effect.resource).contains("/selected")
                    && effect.condition.is_none())
        );
    }

    #[test]
    fn saturated_source_inventory_never_selects_a_partial_match() {
        let temp = TempRoot::new();
        std::fs::write(temp.0.join("selected.sh"), "touch /selected").unwrap();
        for index in 0..crate::index::CrawlLimits::default().max_files {
            std::fs::write(temp.0.join(format!("file-{index}")), "").unwrap();
        }
        let cwd = temp.0.to_str().unwrap();
        let plan = effinterp_engine::Engine::new()
            .with_resolver(Box::new(
                ShallowSourceResolver::new(&temp.0, cwd, 1024).unwrap(),
            ))
            .analyze(&effinterp_proto::Subject::Shell {
                source: "source \"${ROOT}/selected.sh\"".into(),
                cwd: Some(cwd.into()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unresolved_source"
                && boundary
                    .detail
                    .as_ref()
                    .is_some_and(|detail| detail.contains("max_files"))
        }));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.metadata")
        );
    }

    #[test]
    fn host_requests_are_confined_to_the_anchor_and_root() {
        let temp = TempRoot::new();
        let root = temp.0.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("script.py"), b"\xffsource").unwrap();
        let resolver = ShallowSourceResolver::new(&root, "/work", 32).unwrap();

        assert_eq!(
            resolver.resolve(request(
                "/work/script.py",
                SourceNamespace::Host,
                SourcePurpose::InvocationInput,
            )),
            SourceResponse::Source(b"\xffsource".to_vec())
        );
        assert_eq!(
            resolver.resolve(request(
                "/elsewhere/script.py",
                SourceNamespace::Host,
                SourcePurpose::InvocationInput,
            )),
            SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NamespaceDenied
            ))
        );
        assert_eq!(
            resolver.resolve(request(
                "script.py",
                SourceNamespace::Repository,
                SourcePurpose::InvocationInput,
            )),
            SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NamespaceDenied
            ))
        );
        assert_eq!(
            resolver.python_extension_suffixes("python3.12", Some("/work")),
            None,
        );
    }

    #[test]
    fn empty_anchor_rejects_host_requests() {
        let temp = TempRoot::new();
        std::fs::create_dir(temp.0.join("etc")).unwrap();
        std::fs::write(temp.0.join("etc/passwd.py"), b"shadow").unwrap();
        let resolver = ShallowSourceResolver::new(&temp.0, "", 32).unwrap();

        assert_eq!(
            resolver.resolve(request(
                "/etc/passwd.py",
                SourceNamespace::Host,
                SourcePurpose::InvocationInput,
            )),
            SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NamespaceDenied
            ))
        );
    }

    #[test]
    fn dependency_and_file_limits_are_typed_refusals() {
        let temp = TempRoot::new();
        std::fs::write(temp.0.join("large.py"), b"12345").unwrap();
        std::fs::write(temp.0.join("cli.js"), b"x").unwrap();
        std::fs::create_dir(temp.0.join("dir")).unwrap();
        let resolver = ShallowSourceResolver::new(&temp.0, "", 4).unwrap();

        assert_eq!(
            resolver.resolve(request(
                "missing.py",
                SourceNamespace::Repository,
                SourcePurpose::DependencySource,
            )),
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
        );
        assert_eq!(
            resolver.resolve(request(
                "large.py",
                SourceNamespace::Repository,
                SourcePurpose::InvocationInput,
            )),
            SourceResponse::Refused(SourceRefusal::Limit {
                limit: "max_source_bytes"
            })
        );
        assert_eq!(
            resolver.resolve(request(
                "dir",
                SourceNamespace::Repository,
                SourcePurpose::InvocationInput,
            )),
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::NotAFile))
        );
        assert_eq!(
            resolver.resolve(request(
                "cli.js",
                SourceNamespace::Repository,
                SourcePurpose::DependencySource
            )),
            SourceResponse::Source(b"x".to_vec())
        );
        assert!(resolver.siblings("large.py").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn executable_requests_require_an_executable_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempRoot::new();
        let path = temp.0.join("hook");
        std::fs::write(&path, b"#!/bin/sh\ntrue\n").unwrap();
        let resolver = ShallowSourceResolver::new(&temp.0, "", 32).unwrap();
        let executable = || {
            request(
                "hook",
                SourceNamespace::Repository,
                SourcePurpose::ExecutableInput,
            )
        };

        assert_eq!(
            resolver.resolve(executable()),
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::NotAFile))
        );
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert_eq!(
            resolver.resolve(executable()),
            SourceResponse::Source(b"#!/bin/sh\ntrue\n".to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_paths_reject_symlink_and_parent_escapes() {
        use std::os::unix::fs::symlink;

        let temp = TempRoot::new();
        let root = temp.0.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(temp.0.join("outside.py"), b"outside").unwrap();
        symlink(temp.0.join("outside.py"), root.join("linked.py")).unwrap();
        let resolver = ShallowSourceResolver::new(&root, "", 32).unwrap();

        for path in ["linked.py", "../outside.py"] {
            assert_eq!(
                resolver.resolve(request(
                    path,
                    SourceNamespace::Repository,
                    SourcePurpose::InvocationInput,
                )),
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Escapes))
            );
        }
    }

    #[test]
    fn live_python_source_winners_require_observed_native_absence() {
        use effinterp_proto::{
            ExecutionAssurance, ExecutionContent, ExecutionInputRole, ExecutionPhase,
            ExecutionSelector, Subject,
        };
        let temp = TempRoot::new();
        let cwd = temp.0.to_str().unwrap();
        let source = "import os\nos.remove('/selected-effect')\nimport payload\n";
        std::fs::write(
            temp.0.join("payload.py"),
            "import os\nos.remove('/deeper-effect')",
        )
        .unwrap();
        for (module, package, startup) in [
            ("struct", false, false),
            ("struct", true, false),
            ("sitecustomize", false, true),
            ("sitecustomize", true, true),
        ] {
            let relative = if package {
                format!("{module}/__init__.py")
            } else {
                format!("{module}.py")
            };
            let path = temp.0.join(&relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, source).unwrap();
            for (launcher, flags, selected) in [
                ("python3", vec![], true),
                ("python3.12", vec![], true),
                ("python3.12", vec!["-I"], false),
                (
                    "python3.12",
                    if startup { vec!["-E"] } else { vec!["-P"] },
                    false,
                ),
            ] {
                let mut context = effinterp_proto::HostContext::default();
                if startup {
                    context
                        .env
                        .insert("PYTHONPATH".to_string(), cwd.to_string());
                }
                let mut argv = vec![launcher.to_string()];
                if !startup {
                    argv.push("-S".to_string());
                }
                argv.extend(flags.into_iter().map(str::to_string));
                argv.extend([
                    "-c".to_string(),
                    if startup { "pass" } else { "import base64" }.to_string(),
                ]);
                let plan = effinterp_engine::Engine::new()
                    .with_resolver(Box::new(
                        ShallowSourceResolver::new(&temp.0, cwd, 4096).unwrap(),
                    ))
                    .analyze(&Subject::Exec {
                        argv,
                        cwd: Some(cwd.to_string()),
                        context,
                    })
                    .unwrap();
                effinterp_proto::validate_plan(&plan).unwrap();
                let nodes: Vec<_> = plan
                    .execution_graph
                    .nodes
                    .iter()
                    .filter(|node| node.selected_source_path() == path.to_str())
                    .collect();
                assert_eq!(nodes.len(), usize::from(selected), "{launcher} {relative}");
                assert_eq!(
                    plan.effects
                        .iter()
                        .filter(|effect| effinterp_proto::display_resource(&effect.resource)
                            .contains("selected-effect"))
                        .count(),
                    usize::from(selected)
                );
                assert!(!plan.effects.iter().any(|effect| {
                    effinterp_proto::display_resource(&effect.resource).contains("deeper-effect")
                }));
                if selected {
                    let input = nodes[0].input.as_ref().unwrap();
                    assert_eq!(input.role, ExecutionInputRole::UnexpectedSelected);
                    assert_eq!(
                        input.phase,
                        if startup {
                            ExecutionPhase::Startup
                        } else {
                            ExecutionPhase::Import
                        }
                    );
                    assert_eq!(input.assurance, ExecutionAssurance::Exact);
                    assert_eq!(
                        input.content,
                        ExecutionContent::Observed {
                            digest: effinterp_proto::content_digest(source.as_bytes())
                        }
                    );
                    assert_eq!(input.requester_component, launcher);
                    assert!(matches!(
                        input.selection,
                        effinterp_proto::ExecutionSelection::Search {
                            selected: Some(_),
                            ..
                        }
                    ));
                    assert!(plan.execution_graph.nodes.iter().any(|node| {
                        node.input.as_ref().is_some_and(|input| {
                            input.role == ExecutionInputRole::DependencyRequest
                                && input.selector
                                    == ExecutionSelector::Dependency {
                                        specifier: "payload".to_string(),
                                    }
                        })
                    }));
                }
            }
            std::fs::remove_file(path).unwrap();
        }
        let resolver = ShallowSourceResolver::new(&temp.0, cwd, 4096).unwrap();
        let stem = format!("{cwd}/struct");
        let observed = || {
            resolver.python_native_candidates_absent(request(
                &stem,
                SourceNamespace::Host,
                SourcePurpose::InvocationInput,
            ))
        };
        assert!(observed());
        std::fs::write(temp.0.join("struct.abi3.so"), b"native").unwrap();
        assert!(!observed());
        std::fs::remove_file(temp.0.join("struct.abi3.so")).unwrap();
        for index in 0..257 {
            std::fs::write(temp.0.join(format!("unused-{index}")), b"").unwrap();
        }
        assert!(!observed());
    }

    #[test]
    fn unobserved_python_suffixes_do_not_claim_cwd_struct() {
        let temp = TempRoot::new();
        let source = "import payload\nimport os\nos.remove('/selected-effect')\n";
        std::fs::write(temp.0.join("struct.py"), source).unwrap();
        std::fs::write(
            temp.0.join("struct.cpython-312-x86_64-linux-gnu.so"),
            b"\x7fELF",
        )
        .unwrap();
        let cwd = temp.0.to_str().unwrap();
        let resolver = ShallowSourceResolver::new(&temp.0, cwd, 4096).unwrap();
        assert!(
            resolver
                .python_extension_suffixes("python3.12", Some(cwd))
                .is_none()
        );
        for launcher in ["python3", "python3.12"] {
            let plan = effinterp_engine::Engine::new()
                .with_resolver(Box::new(
                    ShallowSourceResolver::new(&temp.0, cwd, 4096).unwrap(),
                ))
                .analyze(&effinterp_proto::Subject::Exec {
                    argv: vec![
                        launcher.to_string(),
                        "-S".to_string(),
                        "-c".to_string(),
                        "import base64".to_string(),
                    ],
                    cwd: Some(cwd.to_string()),
                    context: Default::default(),
                })
                .unwrap();
            effinterp_proto::validate_plan(&plan).unwrap();
            let selected = format!("{cwd}/struct.py");
            let tagged = format!("{cwd}/struct.cpython-312-x86_64-linux-gnu.so");
            assert!(plan.execution_graph.nodes.iter().all(|node| {
                node.selected_source_path() != Some(selected.as_str())
                    && node.selected_source_path() != Some(tagged.as_str())
            }));
            assert!(!plan.effects.iter().any(|effect| {
                effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
            }));
            assert!(plan.execution_graph.nodes.iter().any(|node| {
                node.boundary.is_some()
                    && node.input.as_ref().is_some_and(|input| {
                        input.phase == effinterp_proto::ExecutionPhase::Import
                            && input.selected.is_none()
                            && matches!(
                                input.content,
                                effinterp_proto::ExecutionContent::Unobserved { .. }
                            )
                    })
            }));
        }
    }
}
