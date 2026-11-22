//! The freshness check reuses unchanged content, and undo leaves newer edits
//! alone.

use crate::support::{Fixture, generous, tree};
use nah_snapshot::{Content, Freshness};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn fresh_reuses_unchanged_content_and_undo_keeps_newer_edits() {
    let fixture = Fixture::repository();
    fixture.write("a.txt", "base\n");
    fixture.write("tool.sh", "#!/bin/sh\nexit 0\n");
    fixture.commit_all("base");
    fixture.write("a.txt", "mine\n");
    fixture.write("tool.sh", "#!/bin/sh\nexit 1\n");
    fixture.write("data.bin", vec![1u8; 64 * 1024]);
    let first = nah_snapshot::save(&fixture.context, &fixture.project, &[], generous()).unwrap();

    let Freshness::Current { snapshot } =
        nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap()
    else {
        panic!("an unchanged project needed a new snapshot");
    };
    assert_eq!(snapshot.id, first.id);

    fixture.write("a.txt", "mine, longer\n");
    let Freshness::Saved { snapshot } =
        nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap()
    else {
        panic!("a changed project kept its old snapshot");
    };
    assert_ne!(snapshot.id, first.id);
    assert_eq!(snapshot.summary.new_bytes, "mine, longer\n".len() as u64);

    // Someone else edits a.txt after the snapshot: undo must not overwrite it.
    fixture.write("a.txt", "someone else's edit\n");
    fs::remove_file(fixture.path("data.bin")).unwrap();
    // HEAD's bytes, as a discard leaves them, made executable since.
    fixture.write("tool.sh", "#!/bin/sh\nexit 0\n");
    fixture.make_executable("tool.sh");
    // A file of the user's under the name a restore might write through.
    fixture.write(".data.bin.nah-undo-0", "the user's\n");
    let restored = nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &first.id,
        None,
        generous(),
    )
    .unwrap();
    assert_eq!(
        restored
            .conflicts
            .iter()
            .map(|conflict| conflict.path.as_str())
            .collect::<Vec<_>>(),
        ["a.txt", "tool.sh"]
    );
    assert_eq!(
        fs::metadata(fixture.path("tool.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_to_string(fixture.path("a.txt")).unwrap(),
        "someone else's edit\n"
    );
    assert_eq!(
        fs::read(fixture.path("data.bin")).unwrap(),
        vec![1u8; 64 * 1024]
    );
    assert_eq!(
        restored.written,
        [fixture.path("data.bin").display().to_string()]
    );
    assert_eq!(
        fs::read_to_string(fixture.path(".data.bin.nah-undo-0")).unwrap(),
        "the user's\n"
    );

    // `--into` restores the whole snapshot elsewhere and touches nothing else.
    let project = tree(&fixture.project, &[".git"]);
    let into = fixture.home.join("restored");
    nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &first.id,
        Some(&into),
        generous(),
    )
    .unwrap();
    assert_eq!(fs::read_to_string(into.join("a.txt")).unwrap(), "mine\n");
    assert_eq!(
        fs::read(into.join("data.bin")).unwrap(),
        vec![1u8; 64 * 1024]
    );
    assert_eq!(tree(&fixture.project, &[".git"]), project);
}

/// The pre-call check trusts the latest snapshot without walking the tree
/// only when the change journal shows nothing changed since the freshness
/// check that left it: an edit made just before the check must still count,
/// or a discard would destroy work no snapshot holds.
#[cfg(target_os = "macos")]
#[test]
fn the_change_journal_vouches_only_for_an_unchanged_tree() {
    let fixture = Fixture::repository();
    fixture.write("a.txt", "base\n");
    fixture.commit_all("base");
    // The journal may also answer "changed" when it cannot show otherwise,
    // which only costs a walk, so an unchanged tree need not be trusted
    // every time; an edit must never be missed.
    let mut trusted_unchanged = 0;
    for round in 0..20 {
        nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap();
        let trusted =
            nah_snapshot::unchanged(&fixture.context, &fixture.project, crate::support::far())
                .unwrap();
        trusted_unchanged += usize::from(trusted.is_some());
        fixture.write("a.txt", format!("edit {round}\n"));
        let trusted =
            nah_snapshot::unchanged(&fixture.context, &fixture.project, crate::support::far())
                .unwrap();
        assert!(
            trusted.is_none(),
            "round {round}: the journal missed an edit"
        );
    }
    assert!(trusted_unchanged > 0, "an unchanged tree was never trusted");
}

// After a file tool's write only that file's entry is looked at again. The
// result holds the file as it is now; where a change journal shows nothing
// else changed, it is what a full check finds, whatever else changed.
#[test]
fn a_single_file_refresh_holds_the_file_and_misses_no_other_change() {
    let fixture = Fixture::repository();
    fixture.write(".gitignore", "ignored/\n");
    fixture.write("a.txt", "base\n");
    fixture.write("b.txt", "base\n");
    fixture.commit_all("base");
    fixture.write("ignored/local.txt", "local\n");
    nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap();
    // The file refreshed, what is written, and whether a snapshot saves it.
    let rounds: [(&str, &[&str], bool); 5] = [
        ("a.txt", &["a.txt"], true),
        ("a.txt", &["a.txt", "b.txt"], true),
        ("new.txt", &["new.txt"], true),
        ("ignored/local.txt", &["ignored/local.txt"], false),
        ("a.txt", &[], false),
    ];
    for (round, (file, written, saved)) in rounds.into_iter().enumerate() {
        for path in written {
            fixture.write(path, format!("round {round}\n"));
        }
        if written.is_empty() {
            fixture.write(file, "base\n");
        }
        let (Freshness::Saved { snapshot } | Freshness::Current { snapshot }) =
            nah_snapshot::refresh_file(&fixture.context, &fixture.path(file), generous()).unwrap();
        let held = snapshot
            .entries
            .iter()
            .find(|entry| entry.path == file)
            .and_then(|entry| entry.worktree.as_ref())
            .map(|saved| saved.content.clone());
        let now = Content::Blob {
            oid: fixture.git(&["hash-object", "--", file]).trim().to_owned(),
        };
        assert_eq!(held, saved.then_some(now), "round {round}: {file}");
        let checked = nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap();
        if cfg!(target_os = "macos") {
            assert!(
                matches!(checked, Freshness::Current { .. }),
                "round {round}: the refresh of {file} missed a change"
            );
        }
    }
}

// A slow wipe deletes unsaved files one call at a time, so no discard is
// ever saved before: the rolling copy must keep each file's last copy, and
// a file the session labels as secret must never reach the store.
#[test]
fn the_rolling_copy_keeps_deleted_unsaved_files_and_never_a_labelled_one() {
    let mut fixture = Fixture::repository();
    fixture.write("tracked.txt", "base\n");
    fixture.commit_all("base");
    fixture.write("tracked.txt", "edited\n");
    fixture.write("notes.txt", "unsaved notes\n");
    fixture.write("draft.txt", "unsaved draft\n");
    fixture.write("export.txt", "TOKEN=secret\n");
    let export = fixture.path("export.txt");
    // Another session labels the file after this save's scan read it: the
    // save is refused rather than keep the secret.
    let reads = Arc::new(AtomicUsize::new(0));
    fixture.context.labelled = Box::new({
        let (reads, export) = (reads.clone(), export.clone());
        move || match reads.fetch_add(1, Ordering::SeqCst) {
            0 => Ok(Vec::new()),
            _ => Ok(vec![export.clone()]),
        }
    });
    assert!(nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).is_err());
    assert!(reads.load(Ordering::SeqCst) >= 2);
    fixture.context.labelled = Box::new(move || Ok(vec![export.clone()]));
    let first = nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap();
    let Freshness::Saved { snapshot: first } = first else {
        panic!("a project with unsaved work had no snapshot");
    };
    assert!(first.entries.iter().all(|entry| entry.path != "export.txt"));

    fs::remove_file(fixture.path("notes.txt")).unwrap();
    fs::remove_file(fixture.path("tracked.txt")).unwrap();
    nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap();
    fs::remove_file(fixture.path("draft.txt")).unwrap();
    fixture.write("notes.txt", "rewritten\n");
    let Freshness::Saved { snapshot } =
        nah_snapshot::fresh(&fixture.context, &fixture.project, generous()).unwrap()
    else {
        panic!("a deletion left the copy current");
    };
    // Each later snapshot carries what was deleted before it; a path that
    // exists again holds its new content instead.
    let deleted: Vec<&str> = snapshot
        .deleted
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(deleted, ["draft.txt", "tracked.txt"]);

    let into = fixture.home.join("recovered");
    nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        Some(&into),
        generous(),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(into.join("draft.txt")).unwrap(),
        "unsaved draft\n"
    );
    assert_eq!(
        fs::read_to_string(into.join("tracked.txt")).unwrap(),
        "edited\n"
    );
    assert_eq!(
        fs::read_to_string(into.join("notes.txt")).unwrap(),
        "rewritten\n"
    );
    assert!(!into.join("export.txt").exists());
    // In place, an undo leaves deleted files deleted.
    nah_snapshot::undo(
        &fixture.context,
        &fixture.project,
        &snapshot.id,
        None,
        generous(),
    )
    .unwrap();
    assert!(!fixture.path("draft.txt").exists());
}
