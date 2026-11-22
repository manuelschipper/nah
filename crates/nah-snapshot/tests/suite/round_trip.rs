//! Snapshots restore unsaved work byte for byte after a discard, and never
//! change the repository they read.

use crate::support::{Fixture, generous, tree};
use nah_snapshot::{FileKind, NotSavedReason, Origin};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn discarded_work_returns_byte_for_byte_and_the_undo_is_undoable() {
    let fixture = Fixture::repository();
    fixture.write("edited.txt", "one\ntwo\n");
    fixture.write("staged.txt", "base\n");
    fixture.write("deleted.txt", "gone soon\n");
    fixture.write("tool.sh", "#!/bin/sh\n");
    fixture.write(".gitignore", "*.log\n.env\n");
    fixture.commit_all("base");

    fixture.write("edited.txt", "one\nTWO\nthree\n");
    // Staged content that differs from the work tree's.
    fixture.write("staged.txt", "staged\n");
    fixture.git(&["add", "staged.txt"]);
    fixture.write("staged.txt", "work tree\n");
    fs::remove_file(fixture.path("deleted.txt")).unwrap();
    fixture.make_executable("tool.sh");
    fixture.write("notes/new.txt", "untracked\n");
    // Marked to be added later, with nothing staged.
    fixture.write("intent.txt", "planned\n");
    fixture.git(&["add", "--intent-to-add", "intent.txt"]);
    std::os::unix::fs::symlink("edited.txt", fixture.path("link")).unwrap();
    // Over the plain-copy threshold, and binary.
    let large = (0..11 * 1024 * 1024)
        .map(|byte| (byte % 251) as u8)
        .collect::<Vec<_>>();
    fixture.write("large.bin", &large);
    fixture.write("node_modules/pkg/index.js", "regenerated\n");
    fixture.write(".env", "TOKEN=secret\n");
    fixture.write("debug.log", "ignored but named\n");

    let before = tree(&fixture.project, &[".git"]);
    let index = fixture.git(&["ls-files", "-s"]);
    let git_dir = tree(&fixture.path(".git"), &[]);
    let snapshot = nah_snapshot::save(
        &fixture.context,
        &fixture.project,
        &[fixture.path("debug.log"), fixture.path(".env")],
        generous(),
    )
    .unwrap();
    assert_eq!(
        tree(&fixture.path(".git"), &[]),
        git_dir,
        "the save wrote to .git"
    );

    let origin = |path: &str| {
        snapshot
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .map(|entry| entry.origin)
    };
    assert_eq!(origin("edited.txt"), Some(Origin::Tracked));
    assert_eq!(origin("notes/new.txt"), Some(Origin::Untracked));
    assert_eq!(origin("debug.log"), Some(Origin::Named));
    assert_eq!(origin(".env"), None, "a secret file was saved");
    let reason = |path: &str| {
        snapshot
            .not_saved
            .iter()
            .find(|left_out| left_out.path == path)
            .map(|left_out| left_out.reason)
    };
    assert_eq!(reason(".env"), Some(NotSavedReason::Secret));
    assert_eq!(
        reason("debug.log"),
        None,
        "a saved file is listed as left out"
    );
    assert_eq!(reason("node_modules/"), Some(NotSavedReason::SkipList));
    // 3 in edited.txt, 2 in staged.txt, 1 in deleted.txt and a line in each new text file.
    assert_eq!(snapshot.summary.lines_changed, Some(9));

    fixture.git(&["reset", "-q", "--hard"]);
    fixture.git(&["clean", "-q", "-fd"]);
    let discarded = tree(&fixture.project, &[".git"]);
    let discarded_index = fixture.git(&["ls-files", "-s"]);
    assert_ne!(discarded, before);

    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(restored.staged, ["intent.txt", "staged.txt"]);
    assert!(
        restored
            .removed
            .contains(&fixture.path("deleted.txt").display().to_string())
    );
    let mut expected = before.clone();
    // Clean removed the untracked skip-list folder, which is regenerated.
    expected.retain(|path, _| !path.starts_with("node_modules"));
    assert_eq!(tree(&fixture.project, &[".git"]), expected);
    assert_eq!(fixture.git(&["ls-files", "-s"]), index);

    let back = restored
        .before_undo
        .expect("the undo saved the state it replaced");
    let undone =
        nah_snapshot::undo(&fixture.context, &fixture.project, &back, None, generous()).unwrap();
    assert!(undone.conflicts.is_empty(), "{:?}", undone.conflicts);
    assert_eq!(tree(&fixture.project, &[".git"]), discarded);
    assert_eq!(fixture.git(&["ls-files", "-s"]), discarded_index);
}

#[test]
fn an_unborn_branch_and_a_plain_folder_round_trip() {
    let fixture = Fixture::repository();
    fixture.write("first.txt", "first\n");
    fixture.git(&["add", "first.txt"]);
    fixture.write("loose.txt", "loose\n");
    let before = tree(&fixture.project, &[".git"]);
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    let repository = snapshot.repository.as_ref().unwrap();
    assert_eq!(
        (repository.head.as_deref(), repository.branch.as_deref()),
        (None, Some("main"))
    );
    fixture.git(&["rm", "-q", "--cached", "first.txt"]);
    fs::remove_file(fixture.path("first.txt")).unwrap();
    fs::remove_file(fixture.path("loose.txt")).unwrap();
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(tree(&fixture.project, &[".git"]), before);
    assert_eq!(
        fixture.git(&["diff", "--cached", "--name-only"]),
        "first.txt\n"
    );

    let folder = Fixture::folder();
    folder.write("src/main.rs", "fn main() {}\n");
    folder.write("run", "#!/bin/sh\n");
    folder.make_executable("run");
    std::os::unix::fs::symlink("src/main.rs", folder.path("main")).unwrap();
    folder.write("target/debug/app", "build output\n");
    folder.write("vendor/.git/HEAD", "ref: refs/heads/main\n");
    folder.write("vendor/lib.rs", "nested repository\n");
    folder.write(".env.local", "KEY=1\n");
    let saved = nah_snapshot::save(&folder.context, &folder.project, &[], generous()).unwrap();
    assert!(saved.repository.is_none());
    let paths = saved
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["main", "run", "src/main.rs"]);
    let before = tree(&folder.project, &["target", "vendor", ".env.local"]);
    for name in ["src", "run", "main"] {
        let path = folder.path(name);
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }
    let restored = nah_snapshot::undo(
        &folder.context,
        &folder.project,
        &saved.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(
        tree(&folder.project, &["target", "vendor", ".env.local"]),
        before
    );
}

#[test]
fn a_converting_checkout_still_counts_as_a_discard_and_submodule_commits_are_saved() {
    let library = Fixture::repository();
    library.write("lib.c", "int lib;\n");
    library.commit_all("library");
    let first = library.git(&["rev-parse", "HEAD"]);
    library.write("extra.c", "int extra;\n");
    library.commit_all("more");
    let fixture = Fixture::repository();
    fixture.write(".gitattributes", "*.txt text eol=crlf\n");
    fixture.write("notes.txt", "one\ntwo\n");
    fixture.commit_all("base");
    let library_path = library.project.display().to_string();
    fixture.git(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        &library_path,
        "lib",
    ]);
    fixture.commit_all("submodule");
    fixture.write("notes.txt", "one\r\ntwo\r\nthree\r\n");
    // The superproject stages the submodule's earlier commit.
    let in_library = |args: &[&str]| {
        let mut args = args.to_vec();
        args.splice(0..0, ["-C", "lib"]);
        fixture.git(&args)
    };
    in_library(&["checkout", "-q", first.trim()]);
    fixture.git(&["add", "lib"]);
    fixture.write("lib/lib.c", "int lib = 2;\n");
    let edited = tree(&fixture.project, &[".git", "lib"]);
    let index = fixture.git(&["ls-files", "-s"]);
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    assert!(
        snapshot
            .not_saved
            .iter()
            .any(|left_out| left_out.path == "lib/" && left_out.reason == NotSavedReason::Submodule)
    );

    // The checkout writes HEAD's version with CRLF endings, bytes no blob has.
    fixture.git(&["reset", "-q", "--hard"]);
    assert!(
        fs::read(fixture.path("notes.txt"))
            .unwrap()
            .starts_with(b"one\r\n")
    );
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(tree(&fixture.project, &[".git", "lib"]), edited);
    assert_eq!(fixture.git(&["ls-files", "-s"]), index);
}

#[test]
fn links_in_the_work_tree_are_never_followed_and_type_changes_round_trip() {
    let fixture = Fixture::repository();
    fixture.write("alias/settings", "committed\n");
    fixture.write("dir/a", "base\n");
    fixture.write("shape", "a file\n");
    fixture.commit_all("base");
    let elsewhere = fixture.home.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("settings"), "outside the project\n").unwrap();

    // A folder becomes a link to elsewhere, a file a folder, and a file goes.
    fs::remove_dir_all(fixture.path("alias")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fixture.path("alias")).unwrap();
    fs::remove_file(fixture.path("shape")).unwrap();
    fixture.write("shape/new.txt", "in a folder now\n");
    fs::remove_file(fixture.path("dir/a")).unwrap();
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    let entry = |path: &str| {
        snapshot
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap()
    };
    assert!(
        entry("alias/settings").worktree.is_none(),
        "the save read through a link"
    );
    assert_eq!(
        entry("alias").worktree.as_ref().map(|saved| saved.kind),
        Some(FileKind::Symlink)
    );

    fixture.git(&["reset", "-q", "--hard"]);
    // The deleted file's folder is now a link to a file of the same bytes.
    let other = fixture.home.join("other");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("a"), "base\n").unwrap();
    fs::remove_dir_all(fixture.path("dir")).unwrap();
    std::os::unix::fs::symlink(&other, fixture.path("dir")).unwrap();
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert!(other.join("a").exists(), "the undo deleted through a link");
    assert_eq!(fs::read_link(fixture.path("alias")).unwrap(), elsewhere);
    assert_eq!(
        fs::read_to_string(fixture.path("shape/new.txt")).unwrap(),
        "in a folder now\n"
    );
}

#[test]
fn files_status_looks_away_from_and_unmerged_stages_are_saved() {
    let fixture = Fixture::repository();
    fixture.write("assumed.txt", "base\n");
    fixture.write("skipped.txt", "base\n");
    fixture.write("conflicted.txt", "base\n");
    fixture.write("mode.sh", "#!/bin/sh\n");
    std::os::unix::fs::symlink("assumed.txt", fixture.path("link")).unwrap();
    fixture.commit_all("base");
    fixture.git(&["checkout", "-q", "-b", "other"]);
    fixture.write("conflicted.txt", "theirs\n");
    fixture.commit_all("theirs");
    fixture.git(&["checkout", "-q", "main"]);
    fixture.write("conflicted.txt", "ours\n");
    fixture.commit_all("ours");
    assert!(!fixture.try_git(&["merge", "-q", "other"]));
    fixture.write("conflicted.txt", "resolved, not yet staged\n");

    // Status compares neither file with its index entry.
    fixture.git(&["update-index", "--assume-unchanged", "assumed.txt"]);
    fixture.write("assumed.txt", "unsaved\n");
    fixture.git(&["update-index", "--skip-worktree", "skipped.txt"]);
    fixture.write("skipped.txt", "unsaved too\n");
    // A file holding exactly the bytes of the link it replaced.
    fixture.git(&["update-index", "--assume-unchanged", "link"]);
    fs::remove_file(fixture.path("link")).unwrap();
    fixture.write("link", "assumed.txt");
    // Staged executable, then not executable in the work tree: the versions
    // share their bytes and differ in mode.
    fixture.make_executable("mode.sh");
    fixture.git(&["add", "mode.sh"]);
    fs::set_permissions(fixture.path("mode.sh"), fs::Permissions::from_mode(0o644)).unwrap();
    // A file of the user's where a restore into a folder puts index versions.
    fixture.write(".nah-index/1/conflicted.txt", "the user's\n");
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    let paths = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            ".nah-index/1/conflicted.txt",
            "assumed.txt",
            "conflicted.txt",
            "link",
            "mode.sh",
            "skipped.txt"
        ]
    );

    let into = fixture.home.join("restored");
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        Some(&into),
        generous(),
    )
    .unwrap();
    assert_eq!(restored.staged, ["conflicted.txt", "mode.sh"]);
    let read = |path: &str| fs::read_to_string(into.join(path)).unwrap();
    assert_eq!(read("assumed.txt"), "unsaved\n");
    assert_eq!(read("skipped.txt"), "unsaved too\n");
    assert_eq!(read("conflicted.txt"), "resolved, not yet staged\n");
    assert_eq!(read(".nah-index/1/conflicted.txt"), "the user's\n");
    assert_eq!(read(".nah-index-2/1/conflicted.txt"), "base\n");
    assert_eq!(read(".nah-index-2/2/conflicted.txt"), "ours\n");
    assert_eq!(read(".nah-index-2/3/conflicted.txt"), "theirs\n");
    let staged_mode = fs::metadata(into.join(".nah-index-2/0/mode.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(staged_mode & 0o777, 0o755);
}

#[test]
fn undo_keeps_newer_staged_files_that_restaging_would_replace() {
    let fixture = Fixture::repository();
    fixture.write("base.txt", "base\n");
    fixture.commit_all("base");
    fixture.write("p/a", "saved under a folder\n");
    fixture.write("q", "saved as a file\n");
    fixture.git(&["add", "p/a", "q"]);
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();

    // After the discard, newer work stages a file where the snapshot has a
    // folder, and the reverse.
    fixture.git(&["reset", "-q", "--hard"]);
    fixture.write("p", "newer file\n");
    fixture.write("q/a", "newer, under a folder\n");
    fixture.git(&["add", "p", "q/a"]);
    let index = fixture.git(&["ls-files", "-s"]);
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.staged.is_empty(), "{:?}", restored.staged);
    let mut conflicts = restored
        .conflicts
        .iter()
        .map(|conflict| conflict.path.as_str())
        .collect::<Vec<_>>();
    // Each path conflicts in the work tree and in the index.
    conflicts.sort();
    assert_eq!(conflicts, ["p/a", "p/a", "q", "q"]);
    assert_eq!(fixture.git(&["ls-files", "-s"]), index);
}

#[test]
fn a_file_replacing_a_submodule_is_saved_and_restored() {
    let library = Fixture::repository();
    library.write("lib.c", "int lib;\n");
    library.commit_all("library");
    let fixture = Fixture::repository();
    fixture.write("base.txt", "base\n");
    fixture.commit_all("base");
    let library_path = library.project.display().to_string();
    fixture.git(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        &library_path,
        "lib",
    ]);
    fixture.commit_all("submodule");

    fs::remove_dir_all(fixture.path("lib")).unwrap();
    fixture.write("lib", "replacement, not staged\n");
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();
    assert_eq!(
        snapshot
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        ["lib"]
    );

    fixture.git(&["reset", "-q", "--hard"]);
    assert!(fixture.path("lib").is_dir());
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(
        fs::read_to_string(fixture.path("lib")).unwrap(),
        "replacement, not staged\n"
    );
}

#[test]
fn many_staged_edits_restage_however_their_index_queries_split() {
    let fixture = Fixture::repository();
    // More paths than one index query takes, under one folder.
    for number in 0..600 {
        fixture.write(&format!("src/f{number:04}"), "base\n");
    }
    fixture.commit_all("base");
    for number in 0..600 {
        fixture.write(&format!("src/f{number:04}"), "staged\n");
    }
    fixture.git(&["add", "src"]);
    let index = fixture.git(&["ls-files", "-s"]);
    let snapshot = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();

    fixture.git(&["reset", "-q", "--hard"]);
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(restored.conflicts.is_empty(), "{:?}", restored.conflicts);
    assert_eq!(restored.staged.len(), 600);
    assert_eq!(fixture.git(&["ls-files", "-s"]), index);
}
