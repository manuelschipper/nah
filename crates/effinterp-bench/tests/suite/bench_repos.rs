//! Validity of the bench repository manifest (`bench/repos/corpus.toml`): the
//! strata vocabulary, pinned SHAs, expectation paths under
//! `bench/repos/expectations/`, and the per-language floor the bench design
//! commits to.
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use effinterp_bench::repos::score::{NoCheckpoints, load_manifest, score_repos};
use serde::Deserialize;

const LANGUAGES: [&str; 8] = ["python", "js", "go", "rust", "ruby", "php", "java", "shell"];
const SETS: [&str; 7] = [
    "v1",
    "holdout",
    "semantic-depth",
    "field-trial-1",
    "field-trial-3",
    "field-trial-4",
    "new",
];
const VENDORABLE_LICENSES: [&str; 9] = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "PostgreSQL",
    "CC0-1.0",
    "Unlicense",
    "MPL-2.0",
];
const MIN_PER_LANGUAGE: usize = 8;

#[derive(Deserialize)]
struct Manifest {
    corpus: String,
    repo: Vec<Repo>,
}

#[derive(Deserialize)]
struct Repo {
    name: String,
    url: String,
    sha: String,
    language: String,
    shapes: Vec<String>,
    era: String,
    created: String,
    license: String,
    vendorable: bool,
    split: String,
    set: String,
    expectations: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

#[test]
fn bench_repos_manifest_is_valid() {
    let root = workspace_root();
    let text = std::fs::read_to_string(root.join("bench/repos/corpus.toml"))
        .expect("read bench/repos/corpus.toml");
    let manifest: Manifest = toml::from_str(&text).expect("parse bench/repos/corpus.toml");
    assert_eq!(manifest.corpus, "bench");
    assert_eq!(
        manifest.repo.len(),
        100,
        "bench manifest must pin exactly 100 repos"
    );

    let mut names = HashSet::new();
    let mut per_language: BTreeMap<&str, usize> = BTreeMap::new();
    let mut expectations = BTreeSet::new();
    for repo in &manifest.repo {
        let name = &repo.name;
        assert!(names.insert(name.as_str()), "{name}: duplicate repo name");
        assert_eq!(
            repo.url,
            format!("https://github.com/{name}"),
            "{name}: url"
        );
        assert!(
            repo.sha.len() == 40
                && repo
                    .sha
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{name}: sha `{}` is not 40 lowercase hex",
            repo.sha
        );
        assert!(
            LANGUAGES.contains(&repo.language.as_str()),
            "{name}: language `{}`",
            repo.language
        );
        assert!(!repo.shapes.is_empty(), "{name}: shapes must not be empty");
        assert!(
            matches!(repo.era.as_str(), "pre-ai" | "post-ai"),
            "{name}: era `{}`",
            repo.era
        );
        assert!(
            repo.created.len() == 7 && repo.created.as_bytes()[4] == b'-',
            "{name}: created `{}` is not YYYY-MM",
            repo.created
        );
        assert!(
            matches!(repo.split.as_str(), "dev" | "hidden"),
            "{name}: split `{}`",
            repo.split
        );
        assert!(
            SETS.contains(&repo.set.as_str()),
            "{name}: set `{}`",
            repo.set
        );
        assert_eq!(
            repo.vendorable,
            VENDORABLE_LICENSES.contains(&repo.license.as_str()),
            "{name}: vendorable disagrees with license `{}`",
            repo.license
        );
        if repo.expectations != "none" {
            assert_eq!(
                repo.expectations,
                format!("bench/repos/expectations/{}.toml", name.replace('/', "__")),
                "{name}: expectations path"
            );
            assert!(
                root.join(&repo.expectations).is_file(),
                "{name}: expectations file `{}` is missing",
                repo.expectations
            );
            expectations.insert(repo.expectations.clone());
        }
        *per_language.entry(repo.language.as_str()).or_default() += 1;
    }
    // The repos corpus digest covers the whole directory: no orphan files.
    let files: BTreeSet<String> = std::fs::read_dir(root.join("bench/repos/expectations"))
        .expect("read bench/repos/expectations")
        .map(|entry| {
            format!(
                "bench/repos/expectations/{}",
                entry.unwrap().file_name().to_string_lossy()
            )
        })
        .collect();
    assert_eq!(files, expectations);
    for language in LANGUAGES {
        let count = per_language.get(language).copied().unwrap_or(0);
        assert!(
            count >= MIN_PER_LANGUAGE,
            "{language}: {count} repos, bench floor is {MIN_PER_LANGUAGE}"
        );
    }
}

/// A hidden-split row is never analyzed without an unlock label: naming it is
/// refused before any checkout touches the cache or the network.
#[test]
fn hidden_rows_are_refused_without_unlock() {
    let dir = workspace_root().join("bench/repos");
    let manifest = load_manifest(&dir).unwrap();
    let hidden = manifest
        .repo
        .iter()
        .find(|repo| repo.split == "hidden")
        .expect("the corpus has a hidden split")
        .name
        .clone();
    let cache = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hidden-refusal-cache");
    let _ = std::fs::remove_dir_all(&cache);
    let error = score_repos(&dir, &cache, &[hidden], None, None, &mut NoCheckpoints).unwrap_err();
    assert!(error.contains("hidden split"), "{error}");
    assert!(!cache.exists(), "a refused run must not create the cache");
}
