/// How a resolution was obtained. Later variants are weaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Assurance {
    Exact,
    Alternatives,
    Heuristic,
}

/// Frontend-supplied value-namespace identity.
#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScopeKey {
    Module { key: String },
    GoPackage { key: String },
    RustModule { key: String },
}

/// Where a summarized value came from: a module-level binding, a function local,
/// or one call site's result, so repository composition can join values across files.
#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValueOrigin {
    Module {
        scope: ScopeKey,
        name: String,
    },
    Local {
        file: String,
        function: String,
        name: String,
    },
    Site {
        file: String,
        function: String,
        ordinal: u32,
        result_index: usize,
    },
}

/// A value's static type: a class defined in a repository file, or an external
/// type named by its import path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TypeRef {
    Repo { file: String, name: String },
    External { path: String },
}
