//! Snapshots of commits bring dropped stash entries and deleted refs back,
//! after git has pruned their objects, and never change the repository they
//! read.

use crate::support::{Fixture, generous, tree};
use nah_snapshot::{Budget, Deleting, Refusal};

/// A repository with three stash entries: one of a tracked edit, one with
/// a staged file, one with an untracked file.
fn stashed() -> Fixture {
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    fixture.write("lib.rs", "oldest\n");
    fixture.git(&["stash", "push", "-q", "-m", "oldest edit"]);
    fixture.write("staged.rs", "staged\n");
    fixture.git(&["add", "staged.rs"]);
    fixture.git(&["stash", "push", "-q"]);
    fixture.write("notes.txt", "untracked\n");
    fixture.git(&["stash", "push", "-q", "-u", "-m", "newest   notes"]);
    fixture
}

fn undo(fixture: &Fixture, id: &str) -> nah_snapshot::UndoOutcome {
    nah_snapshot::undo(&fixture.context, &fixture.project, id, None, generous()).unwrap()
}

/// Whether git still has the object `oid`.
fn has(fixture: &Fixture, oid: &str) -> bool {
    fixture.try_git(&["cat-file", "-e", oid])
}

#[test]
fn dropped_and_cleared_stash_entries_return_after_gc_and_the_undo_is_undoable() {
    let fixture = stashed();
    let listed = fixture.git(&["stash", "list"]);
    let middle = fixture.git(&["rev-parse", "stash@{1}"]).trim().to_owned();
    let git_dir = tree(&fixture.path(".git"), &[]);

    let dropped = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::StashEntry(1)],
        generous(),
    )
    .unwrap();
    assert_eq!(
        tree(&fixture.path(".git"), &[]),
        git_dir,
        "the save wrote to .git"
    );
    let commits = dropped.commits.as_ref().unwrap();
    assert_eq!(commits.refs.len(), 1);
    assert_eq!(commits.refs[0].oid, middle);
    // The entry's own commit and its index commit; HEAD keeps the base.
    assert_eq!(commits.count, 2);
    assert!(
        fixture
            .snapshots()
            .iter()
            .any(|listed| listed.id == dropped.id),
        "the snapshot is not listed"
    );
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    assert!(!has(&fixture, &middle), "gc kept the dropped entry");

    let outcome = undo(&fixture, &dropped.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    assert_eq!(fixture.git(&["stash", "list"]), listed);
    assert_eq!(fixture.git(&["rev-parse", "stash@{1}"]).trim(), middle);
    // The entry applies as it did.
    fixture.git(&["stash", "apply", "-q", "--index", "stash@{1}"]);
    assert_eq!(fixture.git(&["show", ":staged.rs"]), "staged\n");
    fixture.git(&["reset", "-q", "--hard"]);

    // Undoing the undo takes away only what it restored.
    let before = outcome.before_undo.unwrap();
    undo(&fixture, &before);
    assert_eq!(
        fixture.git(&["stash", "list"]),
        listed
            .lines()
            .filter(|line| !line.starts_with("stash@{1}"))
            .enumerate()
            .map(|(position, line)| format!(
                "stash@{{{position}}}{}\n",
                line.split_once('}').unwrap().1
            ))
            .collect::<String>()
    );
    undo(&fixture, &dropped.id);
    assert_eq!(fixture.git(&["stash", "list"]), listed);

    // A clear: every entry comes back in its order, with its message.
    let cleared = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::Stash],
        generous(),
    )
    .unwrap();
    assert_eq!(cleared.commits.as_ref().unwrap().refs.len(), 3);
    fixture.git(&["stash", "clear"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    assert!(!has(&fixture, &middle), "gc kept a cleared entry");
    undo(&fixture, &cleared.id);
    assert_eq!(fixture.git(&["stash", "list"]), listed);
    fixture.git(&["stash", "apply", "-q", "stash@{0}"]);
    assert_eq!(
        std::fs::read_to_string(fixture.path("notes.txt")).unwrap(),
        "untracked\n"
    );
    // Saves of the same commits share one pack in the store.
    let copies = tree(&fixture.context.snapshots_dir, &[])
        .into_keys()
        .filter(|path| path.contains("/snapshots/") && path.ends_with(".pack"))
        .collect::<Vec<_>>();
    assert!(copies.is_empty(), "{copies:?}");
}

#[test]
fn a_restored_entry_goes_back_above_the_older_entries_and_a_kept_one_saves_no_commits() {
    let fixture = stashed();
    let entry = |position: usize| {
        fixture
            .git(&["rev-parse", &format!("stash@{{{position}}}")])
            .trim()
            .to_owned()
    };
    let (newest, middle, oldest) = (entry(0), entry(1), entry(2));
    let dropped = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::StashEntry(1)],
        generous(),
    )
    .unwrap();
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    // A newer entry since: the restored one goes back above the one entry
    // that was older than it, not to its old position from the top.
    fixture.write("lib.rs", "newer\n");
    fixture.git(&["stash", "push", "-q", "-m", "newer"]);
    let newer = entry(0);
    undo(&fixture, &dropped.id);
    assert_eq!(
        (0..4).map(entry).collect::<Vec<_>>(),
        [newer, newest, middle.clone(), oldest]
    );

    // An entry a branch reaches loses nothing: no commit is copied.
    fixture.git(&["branch", "kept", &middle]);
    let kept = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::StashEntry(2)],
        generous(),
    )
    .unwrap();
    let commits = kept.commits.unwrap();
    assert_eq!((commits.count, commits.pack), (0, None));

    // A deleted branch comes back; one that names another commit is left.
    let deleted = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::Ref("refs/heads/kept".to_owned())],
        generous(),
    )
    .unwrap();
    fixture.git(&["branch", "-q", "-D", "kept"]);
    let outcome = undo(&fixture, &deleted.id);
    assert_eq!(fixture.git(&["rev-parse", "kept"]).trim(), middle);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    fixture.git(&["branch", "-q", "-f", "kept", "HEAD"]);
    let outcome = undo(&fixture, &deleted.id);
    assert_eq!(outcome.conflicts.len(), 1);
    assert_ne!(fixture.git(&["rev-parse", "kept"]).trim(), middle);
}

#[test]
fn a_save_of_commits_over_its_budget_is_refused() {
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    // Bytes that do not compress.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let noise = (0..64 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect::<Vec<_>>();
    fixture.write("noise.bin", noise);
    fixture.git(&["stash", "push", "-q", "-u"]);
    let refused = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::Stash],
        Budget {
            bytes: 16 * 1024,
            ..generous()
        },
    );
    assert!(
        matches!(refused, Err(Refusal::OverBudget { .. })),
        "{refused:?}"
    );
    assert!(fixture.snapshots().is_empty());
    assert!(fixture.pending().is_empty());
}

/// The commit `stash@{n}` names.
fn entry(fixture: &Fixture, position: usize) -> String {
    fixture
        .git(&["rev-parse", &format!("stash@{{{position}}}")])
        .trim()
        .to_owned()
}

fn save(fixture: &Fixture, deleting: &[Deleting]) -> nah_snapshot::Manifest {
    nah_snapshot::save_commits(&fixture.context, &fixture.project, deleting, generous()).unwrap()
}

#[test]
fn an_entry_goes_back_below_every_original_newer_one_and_a_duplicate_is_its_own_entry() {
    // Distinct entries: middle is saved and dropped, then oldest is dropped
    // and a new entry pushed. The original newest stays above middle.
    let fixture = stashed();
    let (newest, middle) = (entry(&fixture, 0), entry(&fixture, 1));
    let dropped = save(&fixture, &[Deleting::StashEntry(1)]);
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    fixture.write("lib.rs", "new\n");
    fixture.git(&["stash", "push", "-q", "-m", "new"]);
    let new = entry(&fixture, 0);
    undo(&fixture, &dropped.id);
    assert_eq!(
        (0..3)
            .map(|position| entry(&fixture, position))
            .collect::<Vec<_>>(),
        [new, newest, middle]
    );

    // The newest and oldest entries are the same commit with the same
    // message; dropping the newest leaves an identical survivor, and the
    // undo still puts the dropped one back.
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    fixture.write("lib.rs", "same\n");
    fixture.git(&["stash", "push", "-q", "-m", "same"]);
    let same = entry(&fixture, 0);
    fixture.write("lib.rs", "between\n");
    fixture.git(&["stash", "push", "-q", "-m", "between"]);
    fixture.git(&["stash", "store", "-q", "-m", "On main: same", &same]);
    let listed = fixture.git(&["stash", "list"]);
    let dropped = save(&fixture, &[Deleting::StashEntry(0)]);
    fixture.git(&["stash", "drop", "-q"]);
    let outcome = undo(&fixture, &dropped.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    assert_eq!(fixture.git(&["stash", "list"]), listed);
    // Undoing that undo takes out the entry it put back, not the survivor.
    undo(&fixture, &outcome.before_undo.unwrap());
    assert_eq!(
        fixture.git(&["stash", "list", "--format=%H %gs"]),
        format!(
            "{} On main: between\n{same} On main: same\n",
            entry(&fixture, 0)
        )
    );
}

#[test]
fn ref_snapshots_keep_annotated_tags_and_undoing_their_undo_deletes_only_what_it_created() {
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    // An annotated tag on a commit HEAD keeps: only the tag object is lost.
    fixture.git(&["tag", "-a", "-m", "release", "v1"]);
    let tag = fixture.git(&["rev-parse", "v1"]).trim().to_owned();
    let saved = save(&fixture, &[Deleting::Ref("refs/tags/v1".to_owned())]);
    assert!(saved.commits.as_ref().unwrap().pack.is_some());
    fixture.git(&["tag", "-d", "v1"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    assert!(!has(&fixture, &tag), "gc kept the tag object");
    undo(&fixture, &saved.id);
    assert_eq!(fixture.git(&["cat-file", "-t", "v1"]).trim(), "tag");

    // Two branches saved; only one is deleted, so the undo creates only
    // that one, and undoing the undo deletes only that one.
    for (branch, content) in [("left", "left\n"), ("right", "right\n")] {
        fixture.git(&["checkout", "-q", "-b", branch, "main"]);
        fixture.write("lib.rs", content);
        fixture.commit_all(branch);
    }
    fixture.git(&["checkout", "-q", "main"]);
    let both = save(
        &fixture,
        &[
            Deleting::Ref("refs/heads/left".to_owned()),
            Deleting::Ref("refs/heads/right".to_owned()),
        ],
    );
    fixture.git(&["branch", "-q", "-D", "right"]);
    let outcome = undo(&fixture, &both.id);
    assert!(fixture.try_git(&["rev-parse", "--verify", "-q", "right"]));
    undo(&fixture, &outcome.before_undo.unwrap());
    assert!(fixture.try_git(&["rev-parse", "--verify", "-q", "left"]));
    assert!(!fixture.try_git(&["rev-parse", "--verify", "-q", "right"]));
}

#[test]
fn deleted_branches_and_remote_refs_return_after_gc_even_the_branch_head_named() {
    let fixture = Fixture::repository();
    // No reflog keeps a deleted ref's commits from `gc`.
    fixture.git(&["config", "core.logAllRefUpdates", "false"]);
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    let commit_on = |name: &str, content: &str| {
        fixture.git(&["checkout", "-q", "--detach", "main"]);
        fixture.write("lib.rs", content);
        fixture.commit_all(name);
        fixture.git(&["update-ref", name, "HEAD"]);
        fixture.git(&["rev-parse", "HEAD"]).trim().to_owned()
    };
    let topic = commit_on("refs/heads/topic", "topic\n");
    let fetched = commit_on("refs/remotes/origin/main", "fetched\n");
    fixture.git(&[
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    ]);
    fixture.git(&[
        "config",
        "remote.origin.fetch",
        "+refs/heads/*:refs/remotes/origin/*",
    ]);
    // HEAD names the deleted branch, so it keeps nothing.
    fixture.git(&["checkout", "-q", "topic"]);
    let saved = save(
        &fixture,
        &[
            Deleting::Ref("HEAD".to_owned()),
            Deleting::Remote("origin".to_owned()),
        ],
    );
    let commits = saved.commits.as_ref().unwrap();
    assert_eq!(
        commits
            .refs
            .iter()
            .map(|saved| saved.name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/topic", "refs/remotes/origin/main"]
    );
    assert_eq!(commits.count, 2);
    fixture.git(&["checkout", "-q", "--detach", "main"]);
    fixture.git(&["update-ref", "-d", "refs/heads/topic"]);
    fixture.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    fixture.git(&["symbolic-ref", "--delete", "refs/remotes/origin/HEAD"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    assert!(!has(&fixture, &topic) && !has(&fixture, &fetched));
    let outcome = undo(&fixture, &saved.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    assert_eq!(fixture.git(&["rev-parse", "topic"]).trim(), topic);
    assert_eq!(fixture.git(&["rev-parse", "origin/main"]).trim(), fetched);

    // A detached HEAD's own commit is lost with it: Nah cannot tell.
    fixture.git(&["checkout", "-q", "--detach", "topic"]);
    let refused = nah_snapshot::save_commits(
        &fixture.context,
        &fixture.project,
        &[Deleting::Ref("HEAD".to_owned())],
        generous(),
    );
    assert!(
        matches!(refused, Err(Refusal::Invalid { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_deleted_branch_returns_with_a_commit_only_its_reflog_recorded_as_an_old_value() {
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    fixture.git(&["checkout", "-q", "--detach", "main"]);
    fixture.write("lib.rs", "former\n");
    fixture.commit_all("former tip");
    let former = fixture.git(&["rev-parse", "HEAD"]).trim().to_owned();
    fixture.git(&["checkout", "-q", "main"]);
    // The branch's reflog alone keeps its former tip once it is moved back
    // to a commit another ref holds, and once the entry that created it
    // expires, only as the old value of the move.
    fixture.git(&["update-ref", "refs/heads/topic", &former]);
    fixture.git(&["update-ref", "refs/heads/topic", "main"]);
    fixture.git(&["reflog", "delete", "refs/heads/topic@{1}"]);
    let saved = save(&fixture, &[Deleting::Itself("refs/heads/topic".to_owned())]);
    let commits = saved.commits.as_ref().unwrap();
    assert!(
        commits
            .refs
            .iter()
            .any(|saved| saved.name == format!("reflog/{former}")),
        "{:?}",
        commits.refs
    );
    fixture.git(&["branch", "-D", "topic"]);
    expire_and_prune(&fixture);
    assert!(!has(&fixture, &former));
    let outcome = undo(&fixture, &saved.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    assert!(has(&fixture, &former));
    assert!(
        fixture
            .git(&["for-each-ref", "--format=%(objectname)", "refs/nah/"])
            .contains(&former)
    );
    assert_eq!(
        fixture.git(&["rev-parse", "topic"]).trim(),
        fixture.git(&["rev-parse", "main"]).trim()
    );
}

#[test]
fn an_undo_reads_objects_another_snapshot_holds_and_restores_a_stash_with_no_reflog() {
    // Two entries of the same edit: the first save leaves out the tree the
    // other entry keeps, and the second save holds it.
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    for message in ["one", "two"] {
        fixture.write("lib.rs", "edit\n");
        fixture.git(&["stash", "push", "-q", "-m", message]);
    }
    let first = save(&fixture, &[Deleting::StashEntry(0)]);
    fixture.git(&["stash", "drop", "-q"]);
    save(&fixture, &[Deleting::StashEntry(0)]);
    fixture.git(&["stash", "drop", "-q"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    let outcome = undo(&fixture, &first.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    fixture.git(&["stash", "apply", "-q"]);
    assert_eq!(
        std::fs::read_to_string(fixture.path("lib.rs")).unwrap(),
        "edit\n"
    );
    fixture.git(&["checkout", "-q", "--", "lib.rs"]);

    // A stash whose reflog expired lists no entry, yet its tip is the only
    // copy: a bare drop deletes the ref, and so does a clear. Each saves
    // that tip as the ref.
    fixture.git(&["reflog", "expire", "--expire=now", "refs/stash"]);
    let tip = fixture.git(&["rev-parse", "refs/stash"]).trim().to_owned();
    assert_eq!(fixture.git(&["stash", "list"]), "");
    let dropped = save(&fixture, &[Deleting::StashEntry(0)]);
    fixture.git(&["stash", "drop", "-q"]);
    assert!(!fixture.try_git(&["rev-parse", "--verify", "-q", "refs/stash"]));
    fixture.git(&["gc", "-q", "--prune=now"]);
    assert!(!has(&fixture, &tip), "gc kept the stash tip");
    undo(&fixture, &dropped.id);
    assert_eq!(fixture.git(&["rev-parse", "refs/stash"]).trim(), tip);
    let cleared = save(&fixture, &[Deleting::Stash]);
    fixture.git(&["update-ref", "-d", "refs/stash"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    undo(&fixture, &cleared.id);
    assert_eq!(fixture.git(&["rev-parse", "refs/stash"]).trim(), tip);
}

/// The stash as Git lists it, with who wrote each entry and when.
fn stash_entries(fixture: &Fixture) -> String {
    fixture.git(&[
        "stash",
        "list",
        "--date=raw",
        "--format=%H %gd %gn <%ge> %gs",
    ])
}

#[test]
fn entries_of_one_commit_each_come_back_and_an_entry_stored_since_stays() {
    // Adjacent entries of one commit with different messages, which a drop
    // between them leaves; a clear and an undo bring back all three.
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    fixture.write("lib.rs", "edit\n");
    fixture.git(&["stash", "push", "-q", "-m", "edit"]);
    let edit = entry(&fixture, 0);
    fixture.write("lib.rs", "between\n");
    fixture.git(&["stash", "push", "-q", "-m", "between"]);
    fixture.git(&["stash", "store", "-q", "-m", "again", &edit]);
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    fixture.write("notes.txt", "notes\n");
    fixture.git(&["stash", "push", "-q", "-u", "-m", "newest"]);
    let listed = stash_entries(&fixture);
    let cleared = save(&fixture, &[Deleting::Stash]);
    fixture.git(&["stash", "clear"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
    undo(&fixture, &cleared.id);
    assert_eq!(stash_entries(&fixture), listed);

    // Entries alike in every field, written in one second: dropping the
    // older still leaves one to bring back.
    let fixture = Fixture::repository();
    let at = "1700000000 +0000";
    fixture.write("lib.rs", "base\n");
    fixture.commit_all("base");
    fixture.write("lib.rs", "oldest\n");
    fixture.git_at(at, &["stash", "push", "-q", "-m", "oldest"]);
    fixture.write("lib.rs", "same\n");
    fixture.git_at(at, &["stash", "push", "-q", "-m", "same"]);
    let same = entry(&fixture, 0);
    fixture.write("lib.rs", "between\n");
    fixture.git_at(at, &["stash", "push", "-q", "-m", "between"]);
    fixture.git_at(at, &["stash", "store", "-q", "-m", "On main: same", &same]);
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    let listed = stash_entries(&fixture);
    assert_eq!(listed.lines().count(), 3);
    let dropped = save(&fixture, &[Deleting::StashEntry(1)]);
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    undo(&fixture, &dropped.id);
    assert_eq!(stash_entries(&fixture), listed);

    // The entry an undo put back is dropped, and the same commit stored
    // again with the same message: undoing the undo leaves that new entry.
    let fixture = stashed();
    let top = entry(&fixture, 0);
    let dropped = save(&fixture, &[Deleting::StashEntry(0)]);
    fixture.git(&["stash", "drop", "-q"]);
    let before = undo(&fixture, &dropped.id).before_undo.unwrap();
    fixture.git(&["stash", "drop", "-q"]);
    fixture.git_at(
        "1800000000 +0000",
        &[
            "stash",
            "store",
            "-q",
            "-m",
            "On main: newest   notes",
            &top,
        ],
    );
    let stored = stash_entries(&fixture);
    let outcome = undo(&fixture, &before);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    assert_eq!(stash_entries(&fixture), stored);
}

#[test]
fn an_undo_writes_an_empty_message_and_its_own_undo_returns_every_entry_before_it() {
    // A survivor whose message Git keeps empty.
    let fixture = stashed();
    let middle = entry(&fixture, 1);
    fixture.git(&["stash", "store", "-q", "-m", "   ", &middle]);
    fixture.write("lib.rs", "top\n");
    fixture.git(&["stash", "push", "-q", "-m", "top"]);
    let listed = stash_entries(&fixture);
    let dropped = save(&fixture, &[Deleting::StashEntry(0)]);
    fixture.git(&["stash", "drop", "-q"]);
    let after_drop = stash_entries(&fixture);
    fixture.git(&["gc", "-q", "--prune=now"]);
    let outcome = undo(&fixture, &dropped.id);
    assert_eq!(stash_entries(&fixture), listed);

    // Entries the rewrite should have kept are gone, as after an undo
    // stopped partway: undoing the snapshot it saved first returns them.
    fixture.git(&["stash", "drop", "-q", "stash@{2}"]);
    fixture.git(&["stash", "drop", "-q", "stash@{1}"]);
    undo(&fixture, &outcome.before_undo.unwrap());
    assert_eq!(stash_entries(&fixture), after_drop);
}

/// Runs what a user runs to be rid of rewritten history for good.
fn expire_and_prune(fixture: &Fixture) {
    fixture.git(&["reflog", "expire", "--expire=now", "--all"]);
    fixture.git(&["gc", "-q", "--prune=now"]);
}

#[test]
fn rewritten_history_returns_under_recovery_refs_and_leaves_the_branches_alone() {
    let fixture = Fixture::repository();
    fixture.write("lib.rs", "one\n");
    fixture.commit_all("one");
    let first = fixture.git(&["rev-parse", "HEAD"]).trim().to_owned();
    fixture.git(&["branch", "kept"]);
    fixture.write("lib.rs", "two\n");
    fixture.commit_all("two");
    fixture.write("lib.rs", "three\n");
    fixture.commit_all("three");
    let tip = fixture.git(&["rev-parse", "HEAD"]).trim().to_owned();

    // A reset back over two commits. Any local branch may move, so the
    // save holds every commit only local branches reach.
    let reset = save(&fixture, &[Deleting::Branches]);
    assert_eq!(reset.commits.as_ref().unwrap().count, 3);
    fixture.git(&["reset", "-q", "--hard", &first]);
    expire_and_prune(&fixture);
    assert!(!has(&fixture, &tip), "gc kept the commits the reset left");
    let outcome = undo(&fixture, &reset.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    let recovered = format!("refs/nah/{}/heads/main", reset.id);
    assert_eq!(fixture.git(&["rev-parse", &recovered]).trim(), tip);
    // The branches stay where the user left them; `kept` never moved.
    assert_eq!(fixture.git(&["rev-parse", "main"]).trim(), first);
    assert_eq!(fixture.git(&["rev-parse", "kept"]).trim(), first);
    assert_eq!(outcome.refs.len(), 1, "{:?}", outcome.refs);
    // Undoing the undo takes the recovery ref away.
    undo(&fixture, &outcome.before_undo.unwrap());
    assert!(!fixture.try_git(&["rev-parse", "--verify", "-q", &recovered]));

    // A forced filter-branch writes a new backup over the old one.
    fixture.git(&["update-ref", "refs/original/refs/heads/main", &tip]);
    fixture.git(&["branch", "-D", "kept"]);
    let backups = save(&fixture, &[Deleting::Backups]);
    fixture.git(&["update-ref", "refs/original/refs/heads/main", &first]);
    expire_and_prune(&fixture);
    assert!(!has(&fixture, &tip));
    undo(&fixture, &backups.id);
    let recovered = format!("refs/nah/{}/original/refs/heads/main", backups.id);
    assert_eq!(fixture.git(&["rev-parse", &recovered]).trim(), tip);

    // A whole history, with a commit only HEAD's reflog records: a rewrite
    // of every commit that also drops the old branch keeps none of it.
    fixture.git(&["update-ref", "-d", &recovered]);
    fixture.git(&["update-ref", "-d", "refs/original/refs/heads/main"]);
    fixture.git(&["commit", "-q", "--amend", "-m", "amended"]);
    let amended = fixture.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let history = save(&fixture, &[Deleting::History]);
    fixture.git(&["checkout", "-q", "--orphan", "rewritten"]);
    fixture.commit_all("rewritten");
    fixture.git(&["branch", "-D", "main"]);
    expire_and_prune(&fixture);
    assert!(!has(&fixture, &first) && !has(&fixture, &amended));
    let outcome = undo(&fixture, &history.id);
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    let id = &history.id;
    assert_eq!(
        fixture
            .git(&["rev-parse", &format!("refs/nah/{id}/heads/main")])
            .trim(),
        amended
    );
    // The commit the amend replaced, `first`, only HEAD's reflog recorded.
    assert_eq!(
        fixture
            .git(&[
                "for-each-ref",
                "--format=%(objectname)",
                &format!("refs/nah/{id}/reflog/"),
            ])
            .trim(),
        first
    );
    assert_eq!(
        fixture.git(&["rev-parse", "HEAD"]),
        fixture.git(&["rev-parse", "rewritten"])
    );
}
