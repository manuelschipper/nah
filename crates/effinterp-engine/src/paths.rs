use effinterp_proto::{HostContext, PathPlatform, ResourceExpr, ResourceIdentity};

/// Whether a filesystem resource still carries the ambient cwd parameter.
pub(crate) fn fs_resource_uses_cwd(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Parameter { name } => name == "cwd",
        ResourceExpr::Property { base, .. } => fs_resource_uses_cwd(base),
        ResourceExpr::Join { parts } => parts.iter().any(fs_resource_uses_cwd),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(fs_resource_uses_cwd),
        _ => false,
    }
}

pub(crate) fn fs_word_uses_cwd(word: &crate::word::Word) -> bool {
    match word.parts.first() {
        Some(crate::word::WordPart::Literal(text)) => !text.starts_with('/'),
        Some(crate::word::WordPart::Glob(pattern)) => !fs_glob_is_absolute(pattern),
        Some(crate::word::WordPart::Union(alternatives)) => {
            alternatives.iter().any(fs_word_uses_cwd)
        }
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PathAnchoring {
    Anchored,
    Relative,
    DriveRelative,
}

pub(crate) fn path_platform(base: Option<&str>) -> PathPlatform {
    if base.is_some_and(|path| {
        effinterp_proto::is_absolute_path(path, PathPlatform::Windows)
            && !effinterp_proto::is_absolute_path(path, PathPlatform::Posix)
    }) {
        PathPlatform::Windows
    } else {
        PathPlatform::Posix
    }
}

/// Whether a resolved path is anchored on the platform its own spelling names:
/// `/…` on POSIX, or a drive root such as `C:/…` on Windows.
pub(crate) fn is_absolute(path: &str) -> bool {
    effinterp_proto::is_absolute_path(path, path_platform(Some(path)))
}

pub(crate) fn normalize_cwd(path: &str) -> String {
    effinterp_proto::normalize_path(path, path_platform(Some(path)))
}

fn resource_path_platform(cwd: Option<&ResourceExpr>) -> PathPlatform {
    path_platform(cwd.and_then(|cwd| match cwd {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.as_str()),
        _ => None,
    }))
}

fn path_anchoring(path: &str, platform: PathPlatform) -> PathAnchoring {
    if effinterp_proto::is_absolute_path(path, platform) {
        return PathAnchoring::Anchored;
    }
    if platform == PathPlatform::Windows {
        // Classify the canonical prefix produced by the proto normalizer so
        // drive spelling and separator handling keep one owner.
        let normalized = effinterp_proto::normalize_path(path, platform);
        let drive_qualified = normalized.as_bytes().get(1) == Some(&b':');
        if drive_qualified {
            return if normalized.len() == 2 {
                PathAnchoring::Anchored
            } else {
                PathAnchoring::DriveRelative
            };
        }
    }
    PathAnchoring::Relative
}

pub(crate) fn directory_change_uses_cwd(path: &str, platform: PathPlatform) -> bool {
    path_anchoring(path, platform) == PathAnchoring::Relative
}

fn filesystem_path(path: &str, cwd: Option<ResourceExpr>, platform: PathPlatform) -> ResourceExpr {
    match path_anchoring(path, platform) {
        PathAnchoring::Anchored => ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: effinterp_proto::normalize_path(path, platform),
            },
        },
        PathAnchoring::DriveRelative => ResourceExpr::Unresolved {
            family: effinterp_proto::ResourceFamily::new("filesystem"),
        },
        PathAnchoring::Relative => effinterp_proto::filesystem_path(path, cwd, platform),
    }
}

/// Resolve a command operand to a filesystem resource expression. A relative
/// operand with an unknown cwd stays symbolic: `join(<cwd>, operand)`.
pub(crate) fn resolve_fs_path(operand: &str, cwd: Option<&str>) -> ResourceExpr {
    let platform = path_platform(cwd);
    let cwd = cwd.map(|cwd| ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: effinterp_proto::normalize_path(cwd, platform),
        },
    });
    filesystem_path(operand, cwd, platform)
}

/// Resolve a command operand against a cwd expression that may be symbolic.
pub(crate) fn resolve_fs_path_with_cwd(operand: &str, cwd: Option<ResourceExpr>) -> ResourceExpr {
    let platform = resource_path_platform(cwd.as_ref());
    filesystem_path(operand, cwd, platform)
}

/// Resolve a literal symlink target in the directory that owns the link.
pub(crate) fn resolve_symlink_target(target: &str, link: &ResourceExpr) -> Option<ResourceExpr> {
    if target.starts_with('/') {
        return Some(resolve_fs_path(target, None));
    }
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = link
    else {
        return None;
    };
    Some(resolve_fs_path(target, Some(&parent_dir(path))))
}

/// A tool resource and the host environment names used to resolve it.
pub(crate) struct ToolPath {
    pub resource: ResourceExpr,
}

/// Native typed tool operands are argv-like values: `$` and `~` are filename
/// bytes. Shell source uses a separate expanding resolver.
pub(crate) fn resolve_literal_tool_path(
    operand: &str,
    cwd: Option<&str>,
    _context: Option<&HostContext>,
) -> ToolPath {
    ToolPath {
        resource: typed_tool_resource(resolve_fs_word(&crate::word::Word::literal(operand), cwd)),
    }
}

pub(crate) fn resolve_literal_tool_path_under_root(
    operand: &str,
    root: &str,
    cwd: Option<&str>,
    context: Option<&HostContext>,
) -> ToolPath {
    let root = resolve_literal_tool_path(root, cwd, context);
    ToolPath {
        resource: typed_tool_resource(resolve_fs_word_with_cwd(
            &crate::word::Word::literal(operand),
            Some(root.resource),
        )),
    }
}

fn typed_tool_resource(resource: ResourceExpr) -> ResourceExpr {
    if effinterp_proto::resource_domain(&resource) == Some("filesystem") {
        return resource;
    }
    ResourceExpr::Join {
        parts: vec![
            resource,
            ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("filesystem"),
            },
        ],
    }
}

pub(crate) fn resolve_literal_tool_pattern(
    pattern: &str,
    root: Option<&str>,
    cwd: Option<&str>,
    context: Option<&HostContext>,
) -> ToolPath {
    let base = root
        .map(|root| resolve_literal_tool_path(root, cwd, context).resource)
        .or_else(|| cwd.map(|cwd| resolve_fs_path(cwd, Some(cwd))))
        .unwrap_or_else(|| ResourceExpr::Parameter {
            name: "cwd".to_string(),
        });
    let literal = pattern;
    if fs_glob_is_absolute(literal) {
        return ToolPath {
            resource: ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: literal.to_string(),
                },
            },
        };
    }
    let resource = match base {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if is_absolute(&path) => ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: format!(
                    "{}/{literal}",
                    escape_fs_glob_path(path.trim_end_matches('/'))
                ),
            },
        },
        base => ResourceExpr::Join {
            parts: vec![
                base,
                ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath {
                        glob: literal.to_string(),
                    },
                },
            ],
        },
    };
    ToolPath { resource }
}

/// Resolve a possibly symbolic word to a filesystem resource expression.
/// Fully literal words resolve like plain operands; symbolic words become a
/// join whose literal head (if relative) is still resolved against cwd.
pub(crate) fn resolve_fs_word(word: &crate::word::Word, cwd: Option<&str>) -> ResourceExpr {
    let platform = path_platform(cwd);
    let cwd = cwd.map(|cwd| ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: effinterp_proto::normalize_path(cwd, platform),
        },
    });
    resolve_fs_word_with_cwd_on_platform(word, cwd, platform)
}

/// Resolve a word against a cwd that may itself be symbolic.
pub(crate) fn resolve_fs_word_with_cwd(
    word: &crate::word::Word,
    cwd: Option<ResourceExpr>,
) -> ResourceExpr {
    let platform = resource_path_platform(cwd.as_ref());
    resolve_fs_word_with_cwd_on_platform(word, cwd, platform)
}

pub(crate) fn resolve_fs_word_with_cwd_on_platform(
    word: &crate::word::Word,
    cwd: Option<ResourceExpr>,
    platform: PathPlatform,
) -> ResourceExpr {
    use crate::word::WordPart;
    if let Some(text) = word.as_literal() {
        return filesystem_path(text, cwd, platform);
    }
    if let [WordPart::Glob(pattern)] = word.parts.as_slice() {
        return filesystem_glob(pattern, cwd);
    }
    if let [WordPart::Union(alternatives)] = word.parts.as_slice() {
        return ResourceExpr::Union {
            alternatives: alternatives
                .iter()
                .map(|word| resolve_fs_word_with_cwd_on_platform(word, cwd.clone(), platform))
                .collect(),
        };
    }
    let mut parts = Vec::new();
    for (i, part) in word.parts.iter().enumerate() {
        parts.push(match part {
            WordPart::Literal(text) if i == 0 && text.is_empty() => cwd
                .clone()
                .unwrap_or_else(|| ResourceExpr::Parameter { name: "cwd".into() }),
            WordPart::Literal(text)
                if i == 0 && path_anchoring(text, platform) == PathAnchoring::DriveRelative =>
            {
                ResourceExpr::Unresolved {
                    family: effinterp_proto::ResourceFamily::new("filesystem"),
                }
            }
            WordPart::Literal(text)
                if i == 0 && path_anchoring(text, platform) == PathAnchoring::Relative =>
            {
                ResourceExpr::Join {
                    parts: vec![
                        cwd.clone()
                            .unwrap_or_else(|| ResourceExpr::Parameter { name: "cwd".into() }),
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: if platform == PathPlatform::Windows {
                                    effinterp_proto::normalize_path(text, platform)
                                } else {
                                    text.clone()
                                },
                            },
                        },
                    ],
                }
            }
            WordPart::Literal(text) if i > 0 && !text.starts_with('/') => ResourceExpr::Literal {
                value: text.clone(),
            },
            WordPart::Literal(text) if i > 0 => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: text.clone() },
            },
            WordPart::Literal(text) => ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: if platform == PathPlatform::Windows {
                        effinterp_proto::normalize_path(text, platform)
                    } else {
                        text.clone()
                    },
                },
            },
            WordPart::Glob(pattern) if i == 0 => filesystem_glob(pattern, cwd.clone()),
            WordPart::Glob(pattern) => ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: pattern.clone(),
                },
            },
            WordPart::Union(alternatives) => ResourceExpr::Union {
                alternatives: alternatives
                    .iter()
                    .map(|word| resolve_fs_word_with_cwd_on_platform(word, cwd.clone(), platform))
                    .collect(),
            },
            WordPart::Env(name) => ResourceExpr::Environment { name: name.clone() },
            WordPart::Value(ResourceExpr::Literal { value }) if i == 0 => {
                resolve_fs_word_with_cwd_on_platform(
                    &crate::word::Word::literal(value),
                    cwd.clone(),
                    platform,
                )
            }
            WordPart::Value(ResourceExpr::Union { alternatives }) if i == 0 => {
                ResourceExpr::Union {
                    alternatives: alternatives
                        .iter()
                        .map(|value| {
                            resolve_fs_word_with_cwd_on_platform(
                                &crate::word::Word::new(vec![WordPart::Value(value.clone())]),
                                cwd.clone(),
                                platform,
                            )
                        })
                        .collect(),
                }
            }
            WordPart::Value(value) => value.clone(),
            WordPart::Unknown => ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("filesystem"),
            },
        });
    }
    if parts.len() == 1 {
        return parts.pop().unwrap();
    }
    ResourceExpr::Join { parts }
}

fn fs_glob_is_absolute(pattern: &str) -> bool {
    // The shared glob grammar treats an escaped slash as a filesystem separator.
    pattern.starts_with('/') || pattern.starts_with(r"\/")
}

pub(crate) fn filesystem_glob(pattern: &str, cwd: Option<ResourceExpr>) -> ResourceExpr {
    let leaf = ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath {
            glob: pattern.to_string(),
        },
    };
    if fs_glob_is_absolute(pattern) {
        return leaf;
    }
    match cwd {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) if is_absolute(&path) => ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: format!(
                    "{}/{pattern}",
                    escape_fs_glob_path(path.trim_end_matches('/'))
                ),
            },
        },
        cwd => ResourceExpr::Join {
            parts: vec![
                cwd.unwrap_or_else(|| ResourceExpr::Parameter {
                    name: "cwd".to_string(),
                }),
                leaf,
            ],
        },
    }
}

/// Lexically normalize a path keeping its anchoring: `/a/./b` -> `/a/b`,
/// `a/../b` -> `b`. Relative paths stay relative (a repo-rooted namespace
/// uses them alongside `/`-anchored ones).
pub(crate) fn normalize_path(path: &str) -> String {
    effinterp_proto::normalize_path(path, PathPlatform::Posix)
}

/// Join a file spec onto a base directory: an anchored spec stands alone; a
/// relative spec needs a known base (which may itself be relative). None when
/// a relative spec has no base to resolve against.
pub(crate) fn join_file(base: Option<&str>, spec: &str) -> Option<String> {
    let platform = path_platform(base);
    match path_anchoring(spec, platform) {
        PathAnchoring::Anchored => {
            return Some(effinterp_proto::normalize_path(spec, platform));
        }
        PathAnchoring::DriveRelative => return None,
        PathAnchoring::Relative => {}
    }
    let base = base?;
    Some(if base.is_empty() {
        effinterp_proto::normalize_path(spec, platform)
    } else {
        effinterp_proto::normalize_path(&format!("{base}/{spec}"), platform)
    })
}

/// Resolve a launched source operand only when the command names it relative
/// to a known repository directory. An absolute runtime path does not
/// identify a repository file without mount evidence. The empty base is the
/// repository root; no base means the cwd is unknown.
pub(crate) fn join_relative_file(base: Option<&str>, spec: &str) -> Option<String> {
    let platform = path_platform(base);
    if base.is_some_and(|base| effinterp_proto::is_absolute_path(base, platform))
        || path_anchoring(spec, platform) != PathAnchoring::Relative
    {
        None
    } else {
        join_file(base, spec)
    }
}

/// Resolve a source path while retaining whether it names the host or the
/// repository namespace.
pub(crate) fn join_source_path(
    base: Option<&str>,
    spec: &str,
) -> Option<(crate::SourceNamespace, String)> {
    let base = base?;
    let platform = path_platform(Some(base));
    if path_anchoring(spec, platform) == PathAnchoring::DriveRelative {
        return None;
    }
    let namespace = if effinterp_proto::is_absolute_path(base, platform)
        || path_anchoring(spec, platform) == PathAnchoring::Anchored
    {
        crate::SourceNamespace::Host
    } else {
        crate::SourceNamespace::Repository
    };
    join_file(Some(base), spec).map(|path| (namespace, path))
}

/// The directory of a path within its namespace: `/a/b` -> `/a`, `a/b` -> `a`,
/// a bare name -> "" (the namespace root).
pub(crate) fn parent_dir(path: &str) -> String {
    match path.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((dir, _)) => dir.to_string(),
        None => String::new(),
    }
}

/// Join a relative directory change onto a known cwd.
pub(crate) fn join_cwd(cwd: &str, dir: &str) -> String {
    let platform = path_platform(Some(cwd));
    match path_anchoring(dir, platform) {
        PathAnchoring::Anchored | PathAnchoring::DriveRelative => {
            effinterp_proto::normalize_path(dir, platform)
        }
        PathAnchoring::Relative if cwd.is_empty() => effinterp_proto::normalize_path(dir, platform),
        PathAnchoring::Relative => {
            effinterp_proto::normalize_path(&format!("{cwd}/{dir}"), platform)
        }
    }
}

/// The executable identity for argv[0]: a bare name resolves via PATH (a
/// host fact we do not have), so only operands containing `/` get a path.
pub(crate) fn executable_identity(argv0: &str, cwd: Option<&str>) -> ResourceIdentity {
    process_identity(&[crate::word::Word::literal(argv0)], cwd)
}

/// The canonical process identity for one recovered command vector.
pub(crate) fn process_identity(argv: &[crate::word::Word], cwd: Option<&str>) -> ResourceIdentity {
    let cwd = cwd.map(|cwd| ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: effinterp_proto::normalize_path(cwd, PathPlatform::Posix),
        },
    });
    process_identity_with_cwd(argv, cwd)
}

pub(crate) fn process_identity_with_cwd(
    argv: &[crate::word::Word],
    cwd: Option<ResourceExpr>,
) -> ResourceIdentity {
    let argv0 = argv
        .first()
        .and_then(crate::word::Word::as_literal)
        .unwrap_or("");
    let executable = argv0.rsplit('/').next().unwrap_or(argv0).to_string();
    let path = if argv0.contains('/') {
        match effinterp_proto::filesystem_path(argv0, cwd.clone(), PathPlatform::Posix) {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path),
            _ => None,
        }
    } else {
        None
    };
    ResourceIdentity::Process {
        executable,
        path,
        argv: argv
            .iter()
            .skip(1)
            .map(|word| command_word(word, cwd.as_ref()))
            .collect(),
        cwd: cwd.map(Box::new),
    }
}

fn command_word(word: &crate::word::Word, cwd: Option<&ResourceExpr>) -> ResourceExpr {
    if word
        .parts
        .iter()
        .any(|part| matches!(part, crate::word::WordPart::Glob(_)))
    {
        return resolve_fs_word_with_cwd(word, cwd.cloned());
    }
    use crate::word::WordPart;
    if let Some(value) = word.as_literal() {
        return ResourceExpr::Literal {
            value: value.to_string(),
        };
    }
    ResourceExpr::Join {
        parts: word
            .parts
            .iter()
            .map(|part| match part {
                WordPart::Literal(value) => ResourceExpr::Literal {
                    value: value.clone(),
                },
                WordPart::Env(name) => ResourceExpr::Environment { name: name.clone() },
                WordPart::Value(value) => value.clone(),
                WordPart::Glob(pattern) => ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath {
                        glob: pattern.clone(),
                    },
                },
                WordPart::Union(alternatives) => ResourceExpr::Union {
                    alternatives: alternatives
                        .iter()
                        .map(|word| command_word(word, cwd))
                        .collect(),
                },
                WordPart::Unknown => ResourceExpr::Unresolved {
                    family: effinterp_proto::ResourceFamily::new("process"),
                },
            })
            .collect(),
    }
}

/// Escape a literal filesystem path before embedding it in the shared glob grammar.
pub(crate) fn escape_fs_glob_path(path: &str) -> String {
    let mut escaped = String::new();
    for c in path.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// Bounded source operand alternatives. A leading wildcard spans directories;
/// subsequent wildcards cannot cross a path separator.
#[derive(Debug, Clone)]
pub struct SourcePattern {
    patterns: Vec<String>,
}

impl SourcePattern {
    pub(crate) fn from_word(word: &crate::word::Word, base: Option<&str>) -> Option<Self> {
        let mut pattern = Self::derive(word, true)?;
        // Captured path values already carry the cwd used by their producer.
        let base = if matches!(word.parts.first(), Some(crate::word::WordPart::Value(_))) {
            Some("")
        } else {
            base
        };
        for path in &mut pattern.patterns {
            if !path.starts_with('\0') {
                *path = join_file(base, path)?;
            }
        }
        Some(pattern)
    }

    pub(crate) fn from_command_word(word: &crate::word::Word) -> Option<Self> {
        if !word
            .parts
            .iter()
            .any(|part| matches!(part, crate::word::WordPart::Literal(text) if !text.is_empty()))
        {
            return None;
        }
        Self::derive(word, false)
    }

    fn derive(word: &crate::word::Word, fixed_basename: bool) -> Option<Self> {
        use crate::word::WordPart;
        fn expand(word: &crate::word::Word) -> Option<Vec<String>> {
            let mut out = vec![String::new()];
            for part in &word.parts {
                let pieces = match part {
                    WordPart::Literal(text) if !text.contains('\0') => vec![text.clone()],
                    WordPart::Value(value) => {
                        fn resource_word(value: &ResourceExpr) -> crate::word::Word {
                            use crate::word::Word;
                            match value {
                                ResourceExpr::Literal { value } => Word::literal(value),
                                ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                } => Word::literal(path),
                                ResourceExpr::Join { parts } => Word::new(
                                    parts
                                        .iter()
                                        .flat_map(|part| resource_word(part).parts)
                                        .collect(),
                                ),
                                ResourceExpr::Union { alternatives } => {
                                    Word::new(vec![WordPart::Union(
                                        alternatives.iter().map(resource_word).collect(),
                                    )])
                                }
                                _ => Word::new(vec![WordPart::Unknown]),
                            }
                        }
                        expand(&resource_word(value))?
                    }
                    WordPart::Union(words) => {
                        let mut pieces = Vec::new();
                        for word in words {
                            pieces.extend(expand(word)?);
                            if pieces.len() > 256 {
                                return None;
                            }
                        }
                        pieces
                    }
                    _ => vec!["\0".to_string()],
                };
                if out.len().saturating_mul(pieces.len()) > 256 {
                    return None;
                }
                out = out
                    .iter()
                    .flat_map(|prefix| pieces.iter().map(move |piece| format!("{prefix}{piece}")))
                    .collect();
            }
            Some(out)
        }
        let mut patterns = Vec::new();
        for pattern in expand(word)? {
            let basename = pattern.rsplit('/').next()?;
            if fixed_basename && (basename.is_empty() || basename.ends_with('\0')) {
                continue;
            }
            let mut components = Vec::new();
            let mut after_free_prefix = false;
            for (index, component) in pattern.split('/').enumerate() {
                if after_free_prefix && matches!(component, "." | "..") {
                    // The parent of an arbitrary-depth prefix ending in literal text
                    // (`${A}x/..`) is itself an arbitrary prefix, so the literal
                    // suffix is gone; a bare leading wildcard absorbs '..' unchanged.
                    if component == ".." {
                        components[0] = "\0";
                    }
                    continue;
                }
                // Only the leading wildcard spans directories; other wildcards
                // are single components that normalize_path can cancel with '..'.
                after_free_prefix = index == 0 && component.starts_with('\0');
                components.push(component);
            }
            patterns.push(normalize_path(&components.join("/")));
        }
        (!patterns.is_empty()).then_some(Self { patterns })
    }

    /// Match a normalized path in the resolver's namespace, without filesystem I/O.
    pub fn matches(&self, path: &str) -> bool {
        self.patterns
            .iter()
            .flat_map(|pattern| {
                std::iter::once(pattern.as_str()).chain(pattern.strip_prefix("\0/"))
            })
            .any(|pattern| {
                let mut previous = vec![false; path.len() + 1];
                previous[0] = true;
                for (index, byte) in pattern.bytes().enumerate() {
                    let mut next = vec![false; path.len() + 1];
                    if byte == 0 {
                        next[0] = previous[0];
                        for (offset, candidate) in path.bytes().enumerate() {
                            next[offset + 1] = previous[offset + 1]
                                || (next[offset] && (index == 0 || candidate != b'/'));
                        }
                    } else {
                        for (offset, candidate) in path.bytes().enumerate() {
                            next[offset + 1] = previous[offset] && byte == candidate;
                        }
                    }
                    previous = next;
                }
                previous[path.len()]
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_patterns_bound_components_and_reanchor_unknown_prefixes() {
        use crate::word::{Word, WordPart};
        let word = |tail: &str| {
            Word::new(vec![
                WordPart::Env("ROOT".into()),
                WordPart::Literal(tail.into()),
            ])
        };
        let pattern = SourcePattern::from_word(&word("/../lib/util.sh"), Some("")).unwrap();
        assert!(pattern.matches("lib/util.sh"));
        assert!(pattern.matches("a/b/lib/util.sh"));
        assert!(!pattern.matches("lib/util.sh.old"));
        let command = Word::new(vec![
            WordPart::Literal("lib/".into()),
            WordPart::Unknown,
            WordPart::Literal(".sh".into()),
        ]);
        let pattern = SourcePattern::from_word(&command, Some("/work")).unwrap();
        assert!(pattern.matches("/work/lib/a.sh"));
        assert!(!pattern.matches("/work/lib/sub/a.sh"));
        for (tail, expected) in [
            ("/../x.sh", "lib/x.sh"),
            ("/./../x.sh", "lib/x.sh"),
            ("/../../x.sh", "x.sh"),
            ("/./x.sh", "lib/sub/x.sh"),
        ] {
            let operand = Word::new(vec![
                WordPart::Literal("lib/".into()),
                WordPart::Unknown,
                WordPart::Literal(tail.into()),
            ]);
            let pattern = SourcePattern::from_word(&operand, Some("")).unwrap();
            assert!(pattern.matches(expected), "{tail}: {pattern:?}");
            assert!(!pattern.matches("lib/sub/deep/x.sh"));
            if tail.contains("..") {
                assert!(!pattern.matches("lib/sub/x.sh"));
                assert!(!pattern.matches("lib/other/x.sh"));
            }
        }
        let pattern = SourcePattern::from_word(&word("/./../../include.sh"), Some("")).unwrap();
        assert!(pattern.matches("test/e2e/include.sh"));
        for tail in ["x/../y.sh", "x/./../y.sh", "x/../../y.sh"] {
            let pattern = SourcePattern::from_word(&word(tail), Some("")).unwrap();
            assert!(pattern.matches("y.sh"), "{tail}: {pattern:?}");
            assert!(pattern.matches("lib/y.sh"), "{tail}: {pattern:?}");
        }
        let pattern = SourcePattern::from_word(&word("x/./y.sh"), Some("")).unwrap();
        assert!(pattern.matches("barx/y.sh"));
        assert!(!pattern.matches("y.sh"));
        let captured = Word::new(vec![
            WordPart::Value(ResourceExpr::Literal {
                value: "test/e2e/sub".into(),
            }),
            WordPart::Literal("/../include.sh".into()),
        ]);
        let pattern = SourcePattern::from_word(&captured, Some("test/e2e")).unwrap();
        assert!(pattern.matches("test/e2e/include.sh"));
        assert!(SourcePattern::from_word(&word(""), Some("")).is_none());
    }

    #[test]
    fn normalizes_dots_and_parents() {
        assert_eq!(normalize_path("/a/./b//c/../d"), "/a/b/d");
        assert_eq!(normalize_path("/../x"), "/x");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn relative_without_cwd_stays_symbolic() {
        assert!(matches!(
            resolve_fs_path("cache", None),
            ResourceExpr::Join { .. }
        ));
    }

    #[test]
    fn repo_namespace_joins_preserve_leading_parent_components() {
        assert_eq!(join_file(Some("dir"), ".."), Some(".".to_string()));
        assert_eq!(
            join_file(Some("dir"), "../../outside"),
            Some("../outside".to_string())
        );
    }

    #[test]
    fn launched_source_paths_must_be_relative() {
        assert_eq!(
            join_relative_file(Some("app"), "job.py"),
            Some("app/job.py".to_string())
        );
        assert_eq!(
            join_relative_file(Some(""), "job.py"),
            Some("job.py".to_string())
        );
        assert_eq!(join_relative_file(None, "job.py"), None);
        assert_eq!(join_relative_file(Some("app"), "/app/job.py"), None);
        assert_eq!(join_relative_file(Some("/app"), "job.py"), None);
    }

    #[test]
    fn source_paths_retain_their_namespace() {
        assert_eq!(
            join_source_path(Some("app"), "job.py"),
            Some((crate::SourceNamespace::Repository, "app/job.py".to_string()))
        );
        assert_eq!(
            join_source_path(Some("/work"), "job.py"),
            Some((crate::SourceNamespace::Host, "/work/job.py".to_string()))
        );
        assert_eq!(
            join_source_path(Some("app"), "/work/job.py"),
            Some((crate::SourceNamespace::Host, "/work/job.py".to_string()))
        );
        assert_eq!(join_source_path(None, "job.py"), None);
    }
}
