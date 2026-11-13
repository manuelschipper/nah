use super::support::{init_repo, run};
use crate::ignored_entries::{Listings, observe_ignored_entries};
use nah_proto::observation::Observed;
use std::fs;
use std::path::Path;
use std::process::Command;

/// The entries reported for `directory` as `path <- rule file: pattern`, or
/// None when the observation does not answer.
fn ignored(directory: &Path) -> Option<Vec<String>> {
    match observe_ignored_entries(
        directory.to_str().expect("unicode test path"),
        &mut Listings::new(),
    ) {
        Observed::Ok { value } => Some(
            value
                .entries()
                .iter()
                .map(|entry| {
                    format!(
                        "{} <- {}: {}",
                        entry.path(),
                        entry.rule_file().unwrap_or("(outside)"),
                        entry.pattern()
                    )
                })
                .collect(),
        ),
        Observed::Error { .. } => None,
    }
}

/// A search is delegated past a secret on this answer, so it may list only
/// what ripgrep leaves out: an entry a rule matches, not one a later `!`
/// rule re-includes, and nothing at all where ripgrep reads the rules
/// differently from Git (a directory that is itself ignored, an excludes file
/// only the repository's configuration names, a `!` line in a `.ignore` above
/// the entries, no repository).
#[test]
fn only_entries_ripgrep_leaves_out_are_listed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    for directory in ["deps/pkg", "kept", "nested", "sub"] {
        fs::create_dir_all(repo.join(directory)).expect("directory");
    }
    fs::write(repo.join(".gitignore"), "local.cfg\ndeps/\n").expect("ignore rules");
    fs::write(repo.join("kept/.gitignore"), "!local.cfg\n").expect("re-inclusion");
    fs::write(repo.join("nested/.gitignore"), "/secret.txt\n").expect("nested rules");
    for file in [
        "local.cfg",
        "deps/pkg/index.js",
        "kept/local.cfg",
        "nested/secret.txt",
        "sub/local.cfg",
        "sub/main.rs",
    ] {
        fs::write(repo.join(file), "x\n").expect("file");
    }

    assert_eq!(
        ignored(&repo).expect("a repository is observable"),
        [
            "deps/ <- .gitignore: deps/",
            "local.cfg <- .gitignore: local.cfg",
            "nested/secret.txt <- nested/.gitignore: /secret.txt",
            "sub/local.cfg <- .gitignore: local.cfg",
        ]
    );
    // The rule file lies above the directory asked about.
    assert_eq!(
        ignored(&repo.join("sub")).expect("a subdirectory is observable"),
        ["local.cfg <- (outside): local.cfg"]
    );
    // ripgrep searches a directory it was pointed at even when a rule
    // ignores that directory.
    fs::write(repo.join("deps/pkg/.gitignore"), "index.js\n").expect("rules inside");
    for inside in ["deps", "deps/pkg"] {
        assert!(ignored(&repo.join(inside)).is_none_or(|entries| entries.is_empty()));
    }
    assert_eq!(ignored(temp.path()), None);

    // ripgrep takes the global excludes file from the user's configuration,
    // never from the repository's.
    fs::write(temp.path().join("excludes"), "main.rs\n").expect("excludes file");
    run(Command::new("git")
        .args(["config", "core.excludesFile"])
        .arg(temp.path().join("excludes"))
        .current_dir(&repo));
    assert_eq!(
        ignored(&repo.join("sub")).expect("a subdirectory is observable"),
        ["local.cfg <- (outside): local.cfg"]
    );

    fs::write(repo.join("sub/.ignore"), "*.tmp\n").expect("plain search ignore");
    assert!(ignored(&repo.join("sub")).is_some());
    fs::write(repo.join(".rgignore"), "!local.cfg\n").expect("search re-inclusion");
    assert_eq!(ignored(&repo), None);
    assert_eq!(ignored(&repo.join("sub")), None);
}

/// The same answer must not follow Git where ripgrep reads a rule file Git
/// reads differently: a rule whose case differs from the entry's under
/// `core.ignorecase`, and an ignore file that is a symbolic link, which
/// ripgrep opens and Git either refuses (`.gitignore`) or never reads
/// (`.rgignore`). Each would hand a search a file listed here as left out.
/// The files the answer rests on are named, so a later write to one is seen.
#[cfg(unix)]
#[test]
fn rules_ripgrep_reads_differently_list_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    run(Command::new("git")
        .args(["config", "core.ignorecase", "true"])
        .current_dir(&repo));
    for directory in ["plain", "linked-search", "linked-git"] {
        fs::create_dir_all(repo.join(directory)).expect("directory");
        fs::write(repo.join(directory).join("local.cfg"), "x\n").expect("file");
    }
    fs::write(
        repo.join(".gitignore"),
        "local.cfg\nUPPER.CFG\nmixed.cfg\n!MIXED.CFG\n",
    )
    .expect("ignore rules");
    fs::write(repo.join("upper.cfg"), "x\n").expect("case-mismatched file");
    fs::write(repo.join("mixed.cfg"), "x\n").expect("file a folded negation would keep");
    fs::write(temp.path().join("rules"), "!local.cfg\n").expect("linked rules");
    for link in ["linked-search/.rgignore", "linked-git/.gitignore"] {
        std::os::unix::fs::symlink(temp.path().join("rules"), repo.join(link)).expect("link");
    }

    let Observed::Ok { value } = observe_ignored_entries(
        repo.to_str().expect("unicode test path"),
        &mut Listings::new(),
    ) else {
        panic!("a repository is observable")
    };
    assert_eq!(
        value
            .entries()
            .iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        ["mixed.cfg", "plain/local.cfg"]
    );
    let rules = fs::canonicalize(repo.join(".gitignore")).expect("rule file");
    assert!(
        value
            .rule_files()
            .iter()
            .any(|file| Path::new(file) == rules)
    );

    // A linked `.gitignore` at or above the searched directory may re-include
    // anything below it.
    assert_eq!(ignored(&repo.join("linked-git")), None);
}

/// Read without Git, the rules list what ripgrep skips: a tracked file a
/// rule matches too, and the rules of a linked worktree's repository. A
/// gitignored `.env` that ripgrep reads anyway is never listed: inside a
/// nested repository, whose search stops at its own `.git`, below a
/// `.rgignore` that re-includes it, beside a `.ignore` negation, or in a
/// directory with no repository at all.
#[test]
fn rules_are_read_as_ripgrep_reads_them() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::write(repo.join(".gitignore"), ".env\ntarget/\ntracked\n").expect("ignore rules");
    init_repo(&repo.join("nested"));
    for directory in ["app", "lib", "target"] {
        fs::create_dir_all(repo.join(directory)).expect("directory");
    }
    fs::write(repo.join("app/.rgignore"), "!.env\n").expect("search re-inclusion");
    for directory in ["", "nested/", "app/", "lib/", "target/"] {
        fs::write(repo.join(format!("{directory}.env")), "TOKEN=1\n").expect("secret");
    }

    assert_eq!(
        ignored(&repo).expect("a repository is observable"),
        [
            ".env <- .gitignore: .env",
            "lib/.env <- .gitignore: .env",
            "target/ <- .gitignore: target/",
            "tracked <- .gitignore: tracked",
        ]
    );
    fs::write(repo.join("lib/.ignore"), "!.env\n").expect("search re-inclusion");
    assert_eq!(ignored(&repo.join("lib")), None);
    assert!(
        !ignored(&repo)
            .expect("a repository is observable")
            .iter()
            .any(|entry| entry.starts_with("lib/"))
    );

    let outside = temp.path().join("outside");
    fs::create_dir(&outside).expect("directory");
    fs::write(outside.join(".gitignore"), ".env\n").expect("ignore rules");
    fs::write(outside.join(".env"), "TOKEN=1\n").expect("secret");
    assert_eq!(ignored(&outside), None);

    let worktree = temp.path().join("worktree");
    run(Command::new("git")
        .args(["worktree", "add", "-q", "--detach"])
        .arg(&worktree)
        .current_dir(&repo));
    fs::write(repo.join(".git/info/exclude"), "local.txt\n").expect("exclude rules");
    fs::write(worktree.join("local.txt"), "x\n").expect("excluded file");
    assert_eq!(
        ignored(&worktree).expect("a linked worktree is observable"),
        ["local.txt <- (outside): local.txt"]
    );
}

/// The answer runs inside the hook's budget, so every read it makes is
/// bounded: a wide directory, the root included, uses up the walk and
/// answers nothing, and an ignore file that is a FIFO answers nothing
/// rather than waiting for a writer.
#[cfg(unix)]
#[test]
fn bounded_reads_answer_nothing_rather_than_wait() {
    use crate::ignored_entries::observe_ignored_entries_within;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::write(repo.join(".gitignore"), ".env\n").expect("ignore rules");
    fs::write(repo.join(".env"), "TOKEN=1\n").expect("secret");
    let within = |entries| {
        matches!(
            observe_ignored_entries_within(
                repo.to_str().expect("unicode test path"),
                entries,
                &mut Listings::new(),
            ),
            Observed::Ok { .. }
        )
    };
    // `.env`, `.git`, `.gitignore` and `tracked`.
    assert!(within(4));
    assert!(!within(3));

    run(Command::new("mkfifo").arg(repo.join(".ignore")));
    assert_eq!(ignored(&repo), None);
}

/// The global excludes file is taken only from a line ripgrep's own
/// reading cannot take differently.
#[test]
fn global_excludes_file_is_named_plainly_or_not_credited() {
    use crate::ignored_entries::excludes_file_line;
    use std::path::PathBuf;

    let home = Some(Path::new("/home/user"));
    let named = |text| excludes_file_line(text, home);
    assert_eq!(named("[user]\n\tname = x\n"), None);
    assert_eq!(
        named("[core]\n\tExcludesFile = ~/.gitignore_global\r\n"),
        Some(Some(PathBuf::from("/home/user/.gitignore_global")))
    );
    for text in [
        "[core]\n\texcludesfile = \"/home/user/ignore\"\n",
        "[core]\n\texcludesfile = /home/user/my ignore\n",
        "# excludesfile = /home/user/ignore\n",
        "[core]\n\texcludesfile = relative/ignore\n",
    ] {
        assert_eq!(named(text), Some(None), "{text}");
    }
}
