//! Following a dependency source: the file a JavaScript or Ruby module load
//! names, found by the engine's modeled path search, then analyzed as a
//! nested `Import` execution.
//!
//! The JavaScript loader owner (`js/module_load.rs`) decides which calls load
//! a module and what specifier each names; this module turns that specifier
//! into a file. Only an extensionless CommonJS `require` follows Node's own
//! order: the extensionless search (`follow_extensionless_require`),
//! `package.json` `main` (`js_package_candidates`), and what Node does with a
//! `.json` or `.node` file (`RequireFormat`). Every other search is the
//! fixed suffix list in `follow_dependency`, which is not a runtime's
//! resolver: an extensionless static `import` also tries `.js`, `.cjs`,
//! `.mjs`, `.ts` and `/index.js`, files Node's ES module resolver would
//! refuse because it requires the extension. Bare package names are never
//! searched for: they are recorded as untraversed dependencies.

use effinterp_proto::{ExecutionEdgeKind, ResourceExpr, Subject};

use super::{Nest, SourceResolution, SourceSearchObservation, Transition, translate_mount};
use crate::builder::PlanBuilder;
use crate::{SourceNamespace, SourcePurpose, SourceRefusal};

/// How a source loads a dependency. It decides which suffixes the search for
/// an extensionless path tries: a JavaScript `Require` follows Node's
/// CommonJS order, a `DynamicImport` adds none, and a `Static` import, which
/// is also Ruby's `require`, tries the engine's fixed suffix list for the
/// language (`.rb` for Ruby). A path with an extension is tried as written.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DependencyLoad {
    Static,
    Require,
    DynamicImport,
}

impl Nest<'_> {
    /// Launched scripts follow every module load. Inline source follows
    /// every load in that launch's dependency graph, static or dynamic.
    /// Repository entrypoints do not: the linker owns their imports, and a
    /// load there is not a dependency gap.
    pub(crate) fn follows_js_dependencies(&self, builder: &PlanBuilder) -> bool {
        builder.current_execution_is_launched_source()
            || (self.follow_root_js_dependencies && builder.current_dependency_launch().0 == 0)
    }

    /// Follow explicit dependency paths. Bare names need runtime search.
    pub(crate) fn follow_dependency(
        &self,
        builder: &mut PlanBuilder,
        specifier: &str,
        language: &str,
        load: DependencyLoad,
    ) {
        let follows = if language == "js" {
            self.follows_js_dependencies(builder)
        } else {
            builder.current_execution_is_launched_source()
        };
        if !follows {
            return;
        }
        let is_path = crate::dependency_calls::is_path_specifier(specifier);
        if self.resolver.is_none() || self.source_resolution_disabled.get() || !is_path {
            self.record_untraversed_dependency(builder, specifier);
            return;
        }
        let extensionless = std::path::Path::new(specifier).extension().is_none();
        if language == "js" && load == DependencyLoad::Require && extensionless {
            self.follow_extensionless_require(builder, specifier);
            return;
        }
        let mut paths = vec![specifier.to_string()];
        if load != DependencyLoad::DynamicImport && extensionless {
            for suffix in match language {
                "js" => &[".js", ".cjs", ".mjs", ".ts", "/index.js"][..],
                "ruby" => &[".rb"][..],
                _ => &[],
            } {
                paths.push(format!("{specifier}{suffix}"));
            }
        }
        let Some(candidates) = self.dependency_candidates(builder, &paths) else {
            return;
        };
        let input = self.source_input(
            builder,
            specifier,
            SourcePurpose::DependencySource,
            effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::ResolverUnavailable,
            },
            &builder.current_execution_component(),
        );
        let (resolved, _) = self.resolve_execution_search(
            builder,
            candidates,
            SourcePurpose::DependencySource,
            input,
            true,
        );
        if let SourceResolution::Source { origin, source } = resolved {
            self.nest_dependency_source(builder, language, specifier, origin, source);
        }
    }

    /// Dependency paths joined onto the requiring file's directory, in the
    /// resolver's namespace. `None` once a path outside every bind mount of
    /// the current container has been recorded as a boundary.
    fn dependency_candidates(
        &self,
        builder: &mut PlanBuilder,
        paths: &[String],
    ) -> Option<Vec<(SourceNamespace, String)>> {
        let candidates = self.joined_candidates(paths);
        self.realm_candidates(builder, candidates)
    }

    /// Dependency paths joined onto the requiring file's directory, in the
    /// requiring realm's own namespace.
    fn joined_candidates(&self, paths: &[String]) -> Vec<(SourceNamespace, String)> {
        paths
            .iter()
            .filter_map(|path| {
                crate::paths::join_source_path(self.current_source_cwd().as_deref(), path)
            })
            .collect()
    }

    /// `realm_candidates` for a CommonJS search, keeping what Node does with
    /// each file. Node judges that by the name it asked for, so the format
    /// is read before a bind mount translates the path to a host file that
    /// may be named differently.
    fn require_candidates(
        &self,
        builder: &mut PlanBuilder,
        candidates: Vec<(SourceNamespace, String)>,
    ) -> Option<Vec<RequireCandidate>> {
        let formats = candidates
            .iter()
            .map(|(_, path)| RequireFormat::of(path))
            .collect::<Vec<_>>();
        let translated = self.realm_candidates(builder, candidates)?;
        Some(formats.into_iter().zip(translated).collect())
    }

    /// Candidates already joined in the current realm, translated through its
    /// bind mounts when that realm is a container.
    fn realm_candidates(
        &self,
        builder: &mut PlanBuilder,
        mut candidates: Vec<(SourceNamespace, String)>,
    ) -> Option<Vec<(SourceNamespace, String)>> {
        if builder.is_host_realm() {
            return Some(candidates);
        }
        let mounts = self.mounts.borrow().last().cloned().unwrap_or_default();
        for (namespace, path) in &mut candidates {
            let Some(host_path) = translate_mount(path, &mounts) else {
                self.record_source_boundary(
                    builder,
                    path,
                    SourcePurpose::DependencySource,
                    effinterp_proto::ExecutionContent::Unobserved {
                        reason: effinterp_proto::ExecutionInputReason::NamespaceDenied,
                    },
                    &builder.current_execution_component(),
                );
                return None;
            };
            *namespace = if host_path.starts_with('/') {
                SourceNamespace::Host
            } else {
                SourceNamespace::Repository
            };
            *path = host_path;
        }
        Some(candidates)
    }

    /// `require(X)` of an extensionless path, in Node's order: the file X,
    /// X.js, X.json, X.node, then X as a directory.
    /// <https://nodejs.org/api/modules.html#all-together>
    ///
    /// Bun, Deno and tsx add extensions of their own, such as `.ts` and
    /// `.cjs`, in orders the engine does not model. Under any runtime but
    /// Node, a file only such a runtime may load is a dependency gap.
    fn follow_extensionless_require(&self, builder: &mut PlanBuilder, specifier: &str) {
        let node = builder.launching_command().is_none_or(|command| {
            crate::models::folded_program(command).as_deref() == Some("node") || command == "nodejs"
        });
        if !node {
            let other = [".ts", ".tsx", ".mts", ".cts", ".jsx", ".mjs", ".cjs"]
                .iter()
                .flat_map(|suffix| {
                    [
                        format!("{specifier}{suffix}"),
                        format!("{specifier}/index{suffix}"),
                    ]
                })
                .collect::<Vec<_>>();
            let Some(other) = self.dependency_candidates(builder, &other) else {
                return;
            };
            if !matches!(
                self.observe_source_search(builder, &other, SourcePurpose::DependencySource),
                SourceSearchObservation::Missing
            ) {
                self.record_untraversed_dependency(builder, specifier);
                return;
            }
        }
        let files = ["", ".js", ".json", ".node"].map(|suffix| format!("{specifier}{suffix}"));
        let files = self.joined_candidates(&files);
        let Some(files) = self.require_candidates(builder, files) else {
            return;
        };
        if self.require_search(builder, specifier, files) {
            return;
        }
        let Ok(entry) = self.js_package_candidates(builder, specifier) else {
            self.record_untraversed_dependency(builder, specifier);
            return;
        };
        if !self.require_search(builder, specifier, entry.clone()) {
            // Nothing in the directory: record the miss on its first
            // candidate, the declared `main` or `index.js`.
            self.code_search(builder, specifier, vec![entry[0].1.clone()], true);
        }
    }

    /// Node loads the first of `candidates` that is a file. A `.json` file is
    /// data and runs nothing; a `.node` file is native code the engine cannot
    /// read, so it is a dependency gap. `true` once the search has ended: a
    /// file was found, or a gap was recorded.
    fn require_search(
        &self,
        builder: &mut PlanBuilder,
        specifier: &str,
        candidates: Vec<RequireCandidate>,
    ) -> bool {
        let mut code = Vec::new();
        for (format, candidate) in candidates {
            let data = format == RequireFormat::Data;
            if format == RequireFormat::Code {
                code.push(candidate);
                continue;
            }
            if !code.is_empty()
                && self.code_search(builder, specifier, std::mem::take(&mut code), false)
            {
                return true;
            }
            match self.observe_source_search(
                builder,
                std::slice::from_ref(&candidate),
                SourcePurpose::DependencySource,
            ) {
                SourceSearchObservation::Missing => {}
                SourceSearchObservation::Found { .. } if data => return true,
                _ => {
                    self.record_untraversed_dependency(builder, specifier);
                    return true;
                }
            }
        }
        !code.is_empty() && self.code_search(builder, specifier, code, false)
    }

    /// One ordered search of JavaScript files, following the one it selects.
    /// `true` unless every path was missing. A miss records a boundary only
    /// when `record_missing` is set.
    fn code_search(
        &self,
        builder: &mut PlanBuilder,
        specifier: &str,
        paths: Vec<(SourceNamespace, String)>,
        record_missing: bool,
    ) -> bool {
        let input = self.source_input(
            builder,
            specifier,
            SourcePurpose::DependencySource,
            effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::Missing,
            },
            &builder.current_execution_component(),
        );
        let (resolved, exhausted) = self.resolve_execution_search(
            builder,
            paths,
            SourcePurpose::DependencySource,
            input,
            record_missing,
        );
        if let SourceResolution::Source { origin, source } = resolved {
            self.nest_dependency_source(builder, "js", specifier, origin, source);
        }
        !exhausted
    }

    /// Follow one dependency whose bytes were already read.
    fn nest_dependency_source(
        &self,
        builder: &mut PlanBuilder,
        language: &str,
        specifier: &str,
        origin: String,
        source: String,
    ) {
        let parent = crate::paths::parent_dir(&origin);
        let dialect = (language == "js").then(|| crate::models::nodeexec::js_dialect(&origin));
        self.dependency_calls.record_followed(
            crate::dependency_calls::DependencyRequestKey {
                source_cwd: self.current_source_cwd(),
                language: if language == "js" { "js" } else { "ruby" },
                specifier: specifier.to_string(),
            },
            crate::dependency_calls::FollowedDependency {
                launch: builder.current_dependency_launch(),
                path: origin.clone(),
                digest: effinterp_proto::content_digest(source.as_bytes()),
                lang: match dialect {
                    Some(dialect) => crate::Lang::Js(dialect),
                    None => crate::Lang::Ruby,
                },
                source: source.clone(),
            },
        );
        let argv = builder.current_execution_argv().to_vec();
        let evidence = builder.current_execution_evidence().to_vec();
        let depth = builder.execution_depth() - 1;
        self.nest(
            builder,
            Transition::file(Subject::Source {
                language: language.to_string(),
                source,
                dialect,
                cwd: self.current_runtime_cwd(),
                context: Default::default(),
            })
            .kind(ExecutionEdgeKind::Import)
            .origin(origin)
            .source_cwd(Some(&parent))
            .argv(argv),
            &evidence,
            depth,
        );
    }

    /// The files a CommonJS directory load tries, in order, in the resolver's
    /// namespace. A missing `package.json` is X/index.js, X/index.json and
    /// X/index.node. A string `main` is that file. `exports`, a non-string
    /// `main`, or a `package.json` that cannot be read is a dependency gap:
    /// `index.js` would be the wrong file.
    fn js_package_candidates(
        &self,
        builder: &mut PlanBuilder,
        specifier: &str,
    ) -> Result<Vec<RequireCandidate>, ()> {
        let Some((namespace, dir)) =
            crate::paths::join_source_path(self.current_source_cwd().as_deref(), specifier)
        else {
            return Err(());
        };
        let package = self
            .realm_candidates(builder, vec![(namespace, format!("{dir}/package.json"))])
            .ok_or(())?;
        let (package_namespace, package) = &package[0];
        let paths = match self.resolve_host_data_file(builder, package, *package_namespace) {
            SourceResolution::Refused(SourceRefusal::Unavailable(
                crate::UnavailableReason::Missing,
            )) => package_index_candidates(&dir),
            SourceResolution::Source { source, .. } => package_main_candidates(&dir, &source)?,
            _ => return Err(()),
        };
        // Package paths are already joined in the requiring realm. Joining
        // them onto the requiring file again turns `lib/cli/index.js` into
        // `bin/lib/cli/index.js`.
        let paths = paths
            .into_iter()
            .map(|path| {
                let namespace = if path.starts_with('/') {
                    SourceNamespace::Host
                } else {
                    namespace
                };
                (namespace, path)
            })
            .collect();
        self.require_candidates(builder, paths).ok_or(())
    }

    pub(crate) fn record_dependency_request(&self, builder: &mut PlanBuilder, specifier: &str) {
        if builder.current_execution_is_launched_source() {
            self.record_untraversed_dependency(builder, specifier);
        }
    }

    fn record_untraversed_dependency(&self, builder: &mut PlanBuilder, specifier: &str) {
        if builder.dependency_request_recorded(specifier) {
            return;
        }
        let mut input = self.source_input(
            builder,
            specifier,
            SourcePurpose::DependencySource,
            effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::DependencyNotTraversed,
            },
            &builder.current_execution_component(),
        );
        // Package names require runtime search. Only a literal path request
        // with an explicit extension identifies a candidate without opening it.
        input.selected = if specifier.starts_with('/')
            || (specifier.starts_with('.') && std::path::Path::new(specifier).extension().is_some())
        {
            crate::paths::join_source_path(self.current_source_cwd().as_deref(), specifier).map(
                |(_, path)| ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                },
            )
        } else {
            None
        };
        self.record_input_boundary(builder, specifier, input);
    }
}

/// A CommonJS search candidate in the resolver's namespace, with what Node
/// does with it.
type RequireCandidate = (RequireFormat, (SourceNamespace, String));

/// What Node does with a file a CommonJS search selects, by the extension of
/// the path it asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequireFormat {
    /// JavaScript it runs.
    Code,
    /// `.json`: data, which runs nothing.
    Data,
    /// `.node`: native code the engine cannot read.
    Native,
}

impl RequireFormat {
    fn of(path: &str) -> Self {
        if path.ends_with(".json") {
            RequireFormat::Data
        } else if path.ends_with(".node") {
            RequireFormat::Native
        } else {
            RequireFormat::Code
        }
    }
}

/// X/index.js, X/index.json and X/index.node: Node's LOAD_INDEX.
fn package_index_candidates(dir: &str) -> Vec<String> {
    ["js", "json", "node"]
        .map(|extension| format!("{dir}/index.{extension}"))
        .to_vec()
}

/// Files `main` names inside a package directory. `exports` is not resolved:
/// following `main` beside it would claim the wrong file.
fn package_main_candidates(dir: &str, text: &str) -> Result<Vec<String>, ()> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    let obj = value.as_object().ok_or(())?;
    if obj.contains_key("exports") {
        return Err(());
    }
    let Some(main) = obj.get("main") else {
        return Ok(package_index_candidates(dir));
    };
    let main = main.as_str().ok_or(())?;
    if main.is_empty() {
        return Ok(package_index_candidates(dir));
    }
    let joined = if main.starts_with('/') {
        main.to_string()
    } else {
        crate::paths::join_cwd(dir, main)
    };
    if main == "." || std::path::Path::new(&joined).extension().is_none() {
        // Node searches additional formats and directory entries for this
        // main. Without that search, any one candidate could be the wrong file.
        return Err(());
    }
    Ok(vec![joined])
}
