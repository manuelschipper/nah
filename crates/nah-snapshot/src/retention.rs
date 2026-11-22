//! Which snapshots a store keeps, and removing the rest with the content no
//! kept snapshot refers to.
//!
//! Every save waits for the store's lock, so a prune decides without it and
//! takes it only in short holds to apply what it decided. Published snapshots
//! never change and only a prune, which holds the retention lock, removes
//! them or their content, so the survey reads the store unlocked: which
//! snapshots go, what the rest refer to, and the plain files, loose objects
//! and packs nothing refers to. Each hold first reads the snapshots published
//! since, so nothing a new one refers to is deleted, and stops deleting
//! content at all once a new snapshot of commits appears, whose objects only
//! a walk tells, and keeps a snapshot Nah named as an undo point since the
//! survey read when it was last named. A pack only some of whose objects are
//! still referred to is rewritten without the lock as a new pack in `repack/`
//! holding just those, and replaces the old one in a later hold. A process stopped at any point
//! leaves every kept snapshot whole: a snapshot is moved out of `snapshots/`
//! before it is deleted, and a pack is deleted only once nothing refers to
//! it or its replacement is in place.

use crate::manifest::{Content, Entry, Manifest, Stage};
use crate::store::{self, Store, private_dir};
use crate::work_tree::GITLINK;
use crate::{Context, Refusal, git, locate, store_failure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a project's snapshots are kept, and how large its store may grow.
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    pub age: Duration,
    pub bytes: u64,
}

/// The limits a save applies: 14 days, then the oldest first until the
/// store is under 2 GB.
pub const RETENTION: Retention = Retention {
    age: Duration::from_secs(14 * 24 * 60 * 60),
    bytes: 2 * 1024 * 1024 * 1024,
};

/// What a prune removes.
#[derive(Clone, Copy, Debug)]
pub enum Prune {
    /// Snapshots older than the age, then the oldest until the store is
    /// under the size. A snapshot's age counts from when it was saved or,
    /// if later, when Nah last named it as an undo point. Never the latest
    /// rolling snapshot, or one an unfinished decision names, nor, for the
    /// size, the snapshot Nah last gave as an undo.
    Retain(Retention),
    /// Every snapshot.
    All,
}

/// A decision a hook began and never finished, in `directory`: the
/// command may have run without a fresh copy, and the agent is told the
/// latest snapshot there to undo it with.
#[derive(Clone, Debug)]
pub struct Unfinished {
    pub directory: PathBuf,
    /// Milliseconds since the Unix epoch when it began.
    pub started_ms: u64,
}

/// What a prune did.
#[derive(Clone, Debug, Serialize)]
pub struct Pruned {
    /// The snapshots removed, newest first.
    pub removed: Vec<String>,
    /// How many snapshots remain.
    pub kept: usize,
    /// Bytes the store takes on disk afterwards.
    pub bytes: u64,
}

/// Removes the snapshots of `project` that `prune` does not keep, and the
/// content no remaining snapshot refers to. The snapshots `unfinished`
/// decisions name are kept unless `prune` removes all.
pub fn prune(
    context: &Context,
    project: &Path,
    prune: Prune,
    unfinished: &[Unfinished],
    deadline: Instant,
) -> Result<Pruned, Refusal> {
    let project = locate(context, project, deadline)?;
    let root = context.snapshots_dir.join(&project.id);
    if !root.join("snapshots").is_dir() {
        return Ok(Pruned {
            removed: Vec::new(),
            kept: 0,
            bytes: 0,
        });
    }
    // One prune at a time: `removed/` and `repack/` are its own, and what
    // a crashed one left there is deleted first.
    let _retaining = store::lock(&root.join("retention-lock"), deadline)?;
    for own in [REMOVED, REPACK] {
        let dir = root.join(own);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(store_failure)?;
        }
    }
    let store = store::unlocked(root.clone());
    let manifests = store.manifests()?;
    let named = manifests
        .iter()
        .map(|manifest| Ok((manifest.id.clone(), store.named_ms(&manifest.id)?)))
        .collect::<Result<HashMap<_, _>, Refusal>>()?;
    let promised = store.promised()?;
    let over = store_bytes(&root).map_err(store_failure)? > limit(prune);
    let removing = match prune {
        Prune::All => manifests
            .iter()
            .map(|manifest| manifest.id.clone())
            .collect(),
        Prune::Retain(retention) => {
            let kept = protected(
                context,
                &store,
                &project.id,
                &manifests,
                unfinished,
                deadline,
            )?;
            expired(
                context,
                &store,
                &manifests,
                &named,
                &kept,
                promised.as_deref(),
                retention,
                over,
                deadline,
            )?
        }
    };
    let kept = manifests
        .iter()
        .filter(|manifest| !removing.contains(&manifest.id))
        .collect::<Vec<_>>();
    let mut references = References::default();
    for manifest in &kept {
        references.add(manifest);
    }
    let (content, partial) = if removing.is_empty() && !over && !matches!(prune, Prune::All) {
        (Vec::new(), Vec::new())
    } else {
        references.reached_by_commits(context, &store, &kept, deadline)?;
        survey(&store, &references)?
    };
    let mut apply = Apply {
        store: &store,
        known: manifests
            .iter()
            .map(|manifest| manifest.id.clone())
            .collect(),
        references,
        named,
        spared: HashSet::new(),
        stale: false,
        deadline,
    };
    let mut steps = removing
        .iter()
        .cloned()
        .map(Step::Snapshot)
        .chain(content)
        .collect::<VecDeque<_>>();
    apply.run(&mut steps)?;
    if !partial.is_empty() && !apply.stale {
        let mut swaps = repack(context, &root, partial, deadline)?;
        apply.run(&mut swaps)?;
    }
    for own in [REMOVED, REPACK] {
        let dir = root.join(own);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(store_failure)?;
        }
    }
    let removed = manifests
        .into_iter()
        .filter(|manifest| removing.contains(&manifest.id) && !apply.spared.contains(&manifest.id))
        .map(|manifest| manifest.id)
        .collect::<Vec<_>>();
    Ok(Pruned {
        kept: apply.known.len() - removed.len(),
        removed,
        bytes: store_bytes(&root).map_err(store_failure)?,
    })
}

/// Where a prune moves the snapshots it removes, and builds new packs.
const REMOVED: &str = "removed";
const REPACK: &str = "repack";

/// How long one hold of the store's lock lasts at most, beyond the step in
/// progress, and the pause after it in which a waiting save takes the lock.
const HOLD: Duration = Duration::from_millis(50);
const PAUSE: Duration = Duration::from_millis(20);

fn limit(prune: Prune) -> u64 {
    match prune {
        Prune::Retain(retention) => retention.bytes,
        Prune::All => u64::MAX,
    }
}

/// The ids a retention keeps whatever their age: the latest rolling
/// snapshot, and for each unfinished decision in this project the snapshot
/// that was latest when it began and every one since.
fn protected(
    context: &Context,
    store: &Store,
    id: &str,
    manifests: &[Manifest],
    unfinished: &[Unfinished],
    deadline: Instant,
) -> Result<HashSet<String>, Refusal> {
    let mut kept = store
        .latest()?
        .map(|latest| latest.id)
        .into_iter()
        .collect::<HashSet<_>>();
    for decision in unfinished {
        // A folder that is gone holds no project.
        let Ok(project) = locate(context, &decision.directory, deadline) else {
            continue;
        };
        if project.id != id {
            continue;
        }
        let since = manifests
            .iter()
            .map(|manifest| manifest.created_ms)
            .filter(|created| *created <= decision.started_ms)
            .max()
            .unwrap_or(decision.started_ms);
        kept.extend(
            manifests
                .iter()
                .filter(|manifest| manifest.created_ms >= since)
                .map(|manifest| manifest.id.clone()),
        );
    }
    Ok(kept)
}

/// The snapshots among `manifests` (newest first) that `retention` removes:
/// those older than its age, then, when the store is `over` its size, the
/// oldest until what the rest refer to is under it, but the one Nah last
/// gave as an undo (`promised`). Each one's age counts from when it was
/// saved or, if later, when it was last `named` as an undo point.
#[allow(clippy::too_many_arguments)]
fn expired(
    context: &Context,
    store: &Store,
    manifests: &[Manifest],
    named: &HashMap<String, Option<u64>>,
    kept: &HashSet<String>,
    promised: Option<&str>,
    retention: Retention,
    over: bool,
    deadline: Instant,
) -> Result<BTreeSet<String>, Refusal> {
    let oldest = now_ms().saturating_sub(retention.age.as_millis() as u64);
    let since = |manifest: &Manifest| {
        named
            .get(&manifest.id)
            .copied()
            .flatten()
            .map_or(manifest.created_ms, |named| named.max(manifest.created_ms))
    };
    let mut removing = manifests
        .iter()
        .filter(|manifest| since(manifest) < oldest && !kept.contains(&manifest.id))
        .map(|manifest| manifest.id.clone())
        .collect::<BTreeSet<_>>();
    if !over {
        return Ok(removing);
    }
    // What each remaining snapshot refers to, and how many refer to each.
    let sizes = Sizes::of(context, store, deadline)?;
    let held = manifests
        .iter()
        .map(|manifest| sizes.units(store, manifest))
        .collect::<Vec<_>>();
    let mut holders = HashMap::<&Unit, usize>::new();
    for (manifest, units) in manifests.iter().zip(&held) {
        if !removing.contains(&manifest.id) {
            for (unit, _) in units {
                *holders.entry(unit).or_default() += 1;
            }
        }
    }
    let mut bytes = held
        .iter()
        .flatten()
        .filter(|(unit, _)| holders.contains_key(unit))
        .map(|(unit, size)| (unit, *size))
        .collect::<HashMap<_, _>>()
        .values()
        .sum::<u64>();
    let mut oldest_first = manifests.iter().zip(&held).rev().collect::<Vec<_>>();
    oldest_first.sort_by_key(|(manifest, _)| since(manifest));
    for (manifest, units) in oldest_first {
        if bytes <= retention.bytes {
            break;
        }
        if kept.contains(&manifest.id)
            || promised == Some(manifest.id.as_str())
            || !removing.insert(manifest.id.clone())
        {
            continue;
        }
        for (unit, size) in units {
            let count = holders.get_mut(unit).expect("a kept unit has holders");
            *count -= 1;
            if *count == 0 {
                bytes -= size;
            }
        }
    }
    Ok(removing)
}

/// One piece of stored content a snapshot refers to, which it shares with
/// every other snapshot that refers to it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Unit {
    Object(String),
    File(String),
    Pack(String),
    Manifest(String),
}

/// What each object of the store takes on disk.
struct Sizes {
    objects: HashMap<String, u64>,
}

impl Sizes {
    fn of(context: &Context, store: &Store, deadline: Instant) -> Result<Self, Refusal> {
        let mut command = git::store(&context.git, &store.git_dir(), None);
        command.args([
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objectsize:disk)",
        ]);
        let listed = git::output(command, Vec::new(), deadline).map_err(git::GitFailure::store)?;
        let objects = String::from_utf8_lossy(&listed)
            .lines()
            .filter_map(|line| {
                let (oid, size) = line.split_once(' ')?;
                Some((oid.to_owned(), size.parse().ok()?))
            })
            .collect();
        Ok(Sizes { objects })
    }

    /// The content `manifest` refers to that the store holds, with sizes.
    fn units(&self, store: &Store, manifest: &Manifest) -> Vec<(Unit, u64)> {
        let mut references = References::default();
        references.add(manifest);
        let file_size = |path: PathBuf| fs::metadata(path).ok().map(|metadata| metadata.len());
        let mut units = vec![(
            Unit::Manifest(manifest.id.clone()),
            file_size(
                store
                    .root
                    .join("snapshots")
                    .join(&manifest.id)
                    .join("manifest.json"),
            )
            .unwrap_or(0),
        )];
        units.extend(references.oids.into_iter().filter_map(|oid| {
            let size = *self.objects.get(&oid)?;
            Some((Unit::Object(oid), size))
        }));
        units.extend(references.files.into_iter().filter_map(|sha256| {
            let size = file_size(store.plain_file(&sha256))?;
            Some((Unit::File(sha256), size))
        }));
        units.extend(references.packs.into_iter().map(|pack| {
            let size = pack_files(&store.git_dir().join("objects/pack"), &pack)
                .iter()
                .filter_map(|path| file_size(path.clone()))
                .sum();
            (Unit::Pack(pack), size)
        }));
        units
    }
}

/// What a set of snapshots refers to in the store.
#[derive(Default)]
struct References {
    /// Git objects: saved blobs, and the staged and HEAD versions named.
    oids: HashSet<String>,
    /// Plain copies under `files/`, by SHA-256.
    files: HashSet<String>,
    /// Packs a snapshot of commits keeps whole.
    packs: HashSet<String>,
}

impl References {
    fn add(&mut self, manifest: &Manifest) {
        for entry in manifest.entries.iter().chain(&manifest.deleted) {
            self.saved(entry);
            for version in entry.head.iter().chain(&entry.index) {
                self.stage(version);
            }
        }
        for result in manifest.discard_results.values() {
            for version in result.worktree.iter().chain(result.index.iter().flatten()) {
                self.stage(version);
            }
        }
        if let Some(pack) = manifest
            .commits
            .as_ref()
            .and_then(|commits| commits.pack.as_ref())
        {
            self.packs.insert(pack.clone());
        }
    }

    /// Adds every object of the store the commits of `manifests` reach: a
    /// snapshot of commits packs only what no ref kept at its save reached,
    /// so an undo may need objects an older snapshot's pack holds once the
    /// repository no longer has them. The walk follows the commits the store
    /// holds; one it lacks the repository held, and ends its line.
    fn reached_by_commits(
        &mut self,
        context: &Context,
        store: &Store,
        manifests: &[&Manifest],
        deadline: Instant,
    ) -> Result<(), Refusal> {
        let mut frontier = manifests
            .iter()
            .filter_map(|manifest| manifest.commits.as_ref())
            .flat_map(|commits| {
                commits
                    .refs
                    .iter()
                    .map(|saved| saved.oid.clone())
                    .chain(commits.stash.iter().map(|listed| listed.oid.clone()))
                    .chain(
                        commits
                            .undoing
                            .iter()
                            .flat_map(|undoing| &undoing.created)
                            .map(|saved| saved.oid.clone()),
                    )
            })
            .collect::<Vec<_>>();
        if frontier.is_empty() {
            return Ok(());
        }
        let store_git = || git::store(&context.git, &store.git_dir(), None);
        // Each commit and tag the store holds, with what it points to.
        let mut command = store_git();
        command.args([
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
        ]);
        let listed = git::output(command, Vec::new(), deadline).map_err(git::GitFailure::store)?;
        let mut input = Vec::new();
        for line in String::from_utf8_lossy(&listed).lines() {
            if let Some((oid, "commit" | "tag")) = line.split_once(' ') {
                input.extend_from_slice(oid.as_bytes());
                input.push(b'\n');
            }
        }
        let mut command = store_git();
        command.args(["cat-file", "--batch"]);
        let bodies = git::output(command, input, deadline).map_err(git::GitFailure::store)?;
        let pointed = pointers(&bodies);
        let mut commits = Vec::new();
        while let Some(oid) = frontier.pop() {
            let Some((kind, targets)) = pointed.get(&oid) else {
                continue;
            };
            if !self.oids.insert(oid.clone()) {
                continue;
            }
            if *kind == "commit" {
                commits.push(oid);
            }
            frontier.extend(targets.iter().cloned());
        }
        if commits.is_empty() {
            return Ok(());
        }
        // Each reached commit's trees and blobs the store holds.
        let mut command = store_git();
        command.args([
            "rev-list",
            "--objects",
            "--no-walk",
            "--missing=allow-any",
            "--stdin",
        ]);
        let mut input = Vec::new();
        for commit in &commits {
            input.extend_from_slice(commit.as_bytes());
            input.push(b'\n');
        }
        let listed = git::output(command, input, deadline).map_err(git::GitFailure::store)?;
        for line in String::from_utf8_lossy(&listed).lines() {
            if let Some(oid) = line.split(' ').next().filter(|oid| !oid.is_empty()) {
                self.oids.insert(oid.to_owned());
            }
        }
        Ok(())
    }

    fn stage(&mut self, stage: &Stage) {
        if stage.mode != GITLINK {
            self.oids.insert(stage.oid.clone());
        }
    }

    fn saved(&mut self, entry: &Entry) {
        match entry.worktree.as_ref().map(|saved| &saved.content) {
            Some(Content::Blob { oid }) => {
                self.oids.insert(oid.clone());
            }
            Some(Content::File { sha256 }) => {
                self.files.insert(sha256.clone());
            }
            None => {}
        }
    }
}

/// From `git cat-file --batch` output of commits and tags, each one's kind
/// and the commits and tags it points to: a commit's parents (its tree is
/// listed by `rev-list`), a tag's object.
fn pointers(bodies: &[u8]) -> HashMap<String, (&'static str, Vec<String>)> {
    let mut pointed = HashMap::new();
    let mut rest = bodies;
    while let Some(end) = rest.iter().position(|byte| *byte == b'\n') {
        let header = String::from_utf8_lossy(&rest[..end]).into_owned();
        let mut fields = header.split(' ');
        let (Some(oid), Some(kind), Some(size)) = (fields.next(), fields.next(), fields.next())
        else {
            break;
        };
        let Some(body) = size
            .parse::<usize>()
            .ok()
            .and_then(|size| rest.get(end + 1..end + 1 + size))
        else {
            break;
        };
        rest = rest.get(end + 2 + body.len()..).unwrap_or_default();
        let (kind, field) = match kind {
            "commit" => ("commit", "parent "),
            "tag" => ("tag", "object "),
            _ => continue,
        };
        // The header ends at the first blank line; a message may hold
        // anything.
        let targets = body
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty())
            .filter_map(|line| std::str::from_utf8(line).ok()?.strip_prefix(field))
            .map(str::to_owned)
            .collect();
        pointed.insert(oid.to_owned(), (kind, targets));
    }
    pointed
}

/// A pack some of whose objects are still referred to: what it holds, and
/// those of them to keep.
struct Partial {
    name: String,
    held: Vec<String>,
    keep: BTreeSet<String>,
}

/// One change a prune makes to the store under its lock.
enum Step {
    /// Moves a snapshot out of `snapshots/`.
    Snapshot(String),
    /// Deletes a plain file, by SHA-256, nothing refers to.
    File(String),
    /// Deletes a loose object nothing refers to.
    Loose { oid: String, path: PathBuf },
    /// Deletes a pack nothing refers to, with the objects it holds.
    Pack { name: String, held: Vec<String> },
    /// Replaces a pack with the one built in `built`.
    Swap { partial: Partial, built: PathBuf },
}

/// The content nothing in `references` refers to, as steps deleting it,
/// and the packs it refers to in part. Read without the store's lock: a
/// pack whose files are not all there may be one a save is moving in, and
/// is left alone.
fn survey(store: &Store, references: &References) -> Result<(Vec<Step>, Vec<Partial>), Refusal> {
    let mut steps = Vec::new();
    for entry in fs::read_dir(store.root.join("files")).map_err(store_failure)? {
        let name = entry.map_err(store_failure)?.file_name();
        if let Some(name) = name.to_str()
            && !references.files.contains(name)
        {
            steps.push(Step::File(name.to_owned()));
        }
    }
    let objects = store.git_dir().join("objects");
    for fanout in fs::read_dir(&objects).map_err(store_failure)? {
        let fanout = fanout.map_err(store_failure)?;
        let Some(prefix) = fanout
            .file_name()
            .to_str()
            .filter(|name| name.len() == 2 && name.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(str::to_owned)
        else {
            continue;
        };
        for object in fs::read_dir(fanout.path()).map_err(store_failure)? {
            let object = object.map_err(store_failure)?;
            let oid = format!("{prefix}{}", object.file_name().to_string_lossy());
            if !references.oids.contains(&oid) {
                steps.push(Step::Loose {
                    oid,
                    path: object.path(),
                });
            }
        }
    }
    let pack_dir = objects.join("pack");
    let mut partial = Vec::new();
    for (name, files) in packs(&pack_dir).map_err(store_failure)? {
        let complete =
            files.contains(&format!("{name}.idx")) && files.contains(&format!("{name}.pack"));
        if !complete || references.packs.contains(&name) {
            continue;
        }
        // An index this does not read is left alone.
        let Some(held) =
            pack_objects(&pack_dir.join(format!("{name}.idx"))).map_err(store_failure)?
        else {
            continue;
        };
        let keep = held
            .iter()
            .filter(|oid| references.oids.contains(*oid))
            .cloned()
            .collect::<BTreeSet<_>>();
        if keep.is_empty() {
            steps.push(Step::Pack { name, held });
        } else if keep.len() < held.len() {
            partial.push(Partial { name, held, keep });
        }
    }
    Ok((steps, partial))
}

/// Applies a prune's steps in short holds of the store's lock.
struct Apply<'s> {
    store: &'s Store,
    /// Every snapshot id seen, those removed included.
    known: HashSet<String>,
    /// What the kept snapshots, and those published since, refer to.
    references: References,
    /// When each snapshot was last named as an undo point, as the survey
    /// read it.
    named: HashMap<String, Option<u64>>,
    /// The snapshots kept after all, as named since the survey.
    spared: HashSet<String>,
    /// A snapshot of commits was published since the survey: what it
    /// reaches is unknown, so no more content is deleted.
    stale: bool,
    deadline: Instant,
}

impl Apply<'_> {
    fn run(&mut self, steps: &mut VecDeque<Step>) -> Result<(), Refusal> {
        while !steps.is_empty() {
            // The lock file alone, so a store deleted meanwhile is not made
            // again.
            let lock = store::lock(&self.store.root.join("lock"), self.deadline)?;
            self.catch_up()?;
            let began = Instant::now();
            while began.elapsed() < HOLD
                && let Some(step) = steps.pop_front()
            {
                self.step(step)?;
            }
            drop(lock);
            if !steps.is_empty() {
                std::thread::sleep(PAUSE);
            }
        }
        Ok(())
    }

    /// Reads the snapshots published since the last hold.
    fn catch_up(&mut self) -> Result<(), Refusal> {
        for id in self.store.ids()? {
            if !self.known.insert(id.clone()) {
                continue;
            }
            match self.store.find(&id)? {
                Some(manifest) if manifest.commits.is_some() => self.stale = true,
                Some(manifest) => self.references.add(&manifest),
                None => {}
            }
        }
        Ok(())
    }

    fn step(&mut self, step: Step) -> Result<(), Refusal> {
        let root = &self.store.root;
        let referred = |oid: &String| self.references.oids.contains(oid);
        match step {
            // A save named it as an undo point since the survey, under this
            // lock, and so promised it for the full age from then.
            Step::Snapshot(id)
                if self.store.named_ms(&id)? != self.named.get(&id).copied().flatten() =>
            {
                match self.store.find(&id)? {
                    Some(manifest) if manifest.commits.is_some() => self.stale = true,
                    Some(manifest) => self.references.add(&manifest),
                    None => {}
                }
                self.spared.insert(id);
            }
            Step::Snapshot(id) => {
                private_dir(&root.join(REMOVED)).map_err(store_failure)?;
                fs::rename(
                    root.join("snapshots").join(&id),
                    root.join(REMOVED).join(&id),
                )
                .map_err(store_failure)?;
                // A later snapshot may take its id.
                if fs::read_to_string(root.join("latest")).is_ok_and(|latest| latest == id) {
                    for file in ["latest", "journal-mark"] {
                        remove_if_present(&root.join(file)).map_err(store_failure)?;
                    }
                }
                if self
                    .store
                    .promised()?
                    .is_some_and(|promised| promised == id)
                {
                    remove_if_present(&root.join("promised")).map_err(store_failure)?;
                }
            }
            _ if self.stale => {}
            Step::File(sha256) => {
                if !self.references.files.contains(&sha256) {
                    remove_if_present(&self.store.plain_file(&sha256)).map_err(store_failure)?;
                }
            }
            Step::Loose { oid, path } => {
                if !referred(&oid) {
                    remove_if_present(&path).map_err(store_failure)?;
                }
            }
            Step::Pack { name, held } => {
                if !self.references.packs.contains(&name) && !held.iter().any(referred) {
                    remove_pack(&self.store.git_dir().join("objects/pack"), &name)
                        .map_err(store_failure)?;
                }
            }
            Step::Swap { partial, built } => {
                // A save since may refer to more of the old pack than its
                // replacement holds; the next prune tries again.
                if self.references.packs.contains(&partial.name)
                    || partial
                        .held
                        .iter()
                        .any(|oid| referred(oid) && !partial.keep.contains(oid))
                {
                    return Ok(());
                }
                let pack_dir = self.store.git_dir().join("objects/pack");
                let mut files = fs::read_dir(&built)
                    .map_err(store_failure)?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<io::Result<Vec<_>>>()
                    .map_err(store_failure)?;
                // The index last, so git never sees one without its pack.
                files.sort_by_key(|path| {
                    path.extension().is_some_and(|extension| extension == "idx")
                });
                for file in files {
                    let target = pack_dir.join(file.file_name().expect("a pack file has a name"));
                    if !target.exists() {
                        fs::rename(&file, &target).map_err(store_failure)?;
                    }
                }
                remove_pack(&pack_dir, &partial.name).map_err(store_failure)?;
            }
        }
        Ok(())
    }
}

/// Builds, without the store's lock, a pack of the objects each `partial`
/// pack keeps, and returns the steps that swap them in.
fn repack(
    context: &Context,
    root: &Path,
    partial: Vec<Partial>,
    deadline: Instant,
) -> Result<VecDeque<Step>, Refusal> {
    let mut swaps = VecDeque::new();
    for (number, partial) in partial.into_iter().enumerate() {
        let built = root.join(REPACK).join(number.to_string());
        private_dir(&built).map_err(store_failure)?;
        let mut command = git::store(&context.git, &root.join("git"), None);
        command.args(["pack-objects", "-q"]).arg(built.join("pack"));
        let mut input = Vec::new();
        for oid in &partial.keep {
            input.extend_from_slice(oid.as_bytes());
            input.push(b'\n');
        }
        git::output(command, input, deadline).map_err(git::GitFailure::store)?;
        swaps.push_back(Step::Swap { partial, built });
    }
    Ok(swaps)
}

/// Every pack in `pack_dir` by name (`pack-<hash>`), with its files' names.
fn packs(pack_dir: &Path) -> io::Result<BTreeMap<String, BTreeSet<String>>> {
    let mut packs = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in fs::read_dir(pack_dir)? {
        let file = entry?.file_name().to_string_lossy().into_owned();
        if let Some((name, _)) = file.split_once('.')
            && name.starts_with("pack-")
        {
            packs.entry(name.to_owned()).or_default().insert(file);
        }
    }
    Ok(packs)
}

fn pack_files(pack_dir: &Path, name: &str) -> Vec<PathBuf> {
    packs(pack_dir)
        .ok()
        .and_then(|mut packs| packs.remove(name))
        .into_iter()
        .flatten()
        .map(|file| pack_dir.join(file))
        .collect()
}

/// Deletes the pack `name`, its index first, so git stops looking in it
/// before anything it reads is gone.
fn remove_pack(pack_dir: &Path, name: &str) -> io::Result<()> {
    let mut files = pack_files(pack_dir, name);
    files.sort_by_key(|path| path.extension().is_none_or(|extension| extension != "idx"));
    for file in files {
        remove_if_present(&file)?;
    }
    Ok(())
}

/// The objects a version 2 pack index names, `None` for an index in any
/// other form. The store's objects are named by SHA-1.
fn pack_objects(idx: &Path) -> io::Result<Option<Vec<String>>> {
    let bytes = match fs::read(idx) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    const FANOUT_END: usize = 8 + 256 * 4;
    if bytes.len() < FANOUT_END || bytes[..8] != [0xff, b't', b'O', b'c', 0, 0, 0, 2] {
        return Ok(None);
    }
    let count = u32::from_be_bytes(
        bytes[FANOUT_END - 4..FANOUT_END]
            .try_into()
            .expect("four bytes"),
    ) as usize;
    let Some(names) = bytes.get(FANOUT_END..FANOUT_END + count * 20) else {
        return Ok(None);
    };
    Ok(Some(names.chunks(20).map(store::hex).collect()))
}

/// Bytes every file of the store at `root` takes, but what `tmp/`,
/// `removed/` and `repack/` hold for a moment. Read without the store's lock:
/// a file a save renames away meanwhile, such as `latest.partial`, counts as
/// gone.
fn store_bytes(root: &Path) -> io::Result<u64> {
    let mut total = 0;
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder)? {
            let entry = entry?;
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.is_dir() {
                if folder != root
                    || !matches!(entry.file_name().to_str(), Some("tmp" | REMOVED | REPACK))
                {
                    folders.push(entry.path());
                }
            } else {
                total += metadata.len();
            }
        }
    }
    Ok(total)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}
