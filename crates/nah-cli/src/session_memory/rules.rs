//! The session rules, applied to one delegated call against the session's
//! state, and the changes the call proposes to leave behind.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use nah_proto::ctx::{GuardLevel, GuardSettings};
use nah_proto::effinterp_proto::{FsEntryKind, content_digest, glob_match};

use super::facts::{CallFacts, Selected, Selection, Staging};
use super::judge::Judged;
use super::ledger::{Change, ContentVerdict, Fetched, Pending, SessionState};
use super::post_call::{file_state, fingerprint};
use super::world::{DIGEST, TEXT, World};
use super::{JudgedWrite, base_name, runs_later, within};

/// The shipped rules that own the session rules with no flagging rule:
/// running code fetched this session and writes Nah cannot see onto a
/// pending path, secret bytes leaving, read back, and entries that run
/// outside the session.
const UNTRUSTED_CODE: &str = "untrusted-code/remote-script-run";
const EXFILTRATION: &str = "exfiltration/secret-upload";
const SECRETS: &str = "secrets/env-files-read";
const PERSISTENCE: &str = "persistence/startup-item-add";

/// At most this many files a call touches are hashed to find labelled copies.
const MAX_HASHED_FILES: usize = 64;

pub(super) struct Block {
    /// The session rule's id, such as `flagged-content-run`, which the
    /// ledger's block record keeps.
    pub(super) rule: &'static str,
    /// The shipped rule the block reports under; `None` for a structural
    /// block.
    pub(super) guard: Option<String>,
    pub(super) reason: String,
    /// What the block rested on beside the session's ledger, its settings
    /// and the effects of the call's plan; `None` where the rule cannot
    /// say.
    pub(super) rested_on: Option<Vec<Basis>>,
}

/// One answer a block rested on, as a replay's facts export refers to it
/// when its state could not give the answer.
#[derive(Clone)]
pub(crate) enum Basis {
    /// The world's answer to `question` (`world::TEXT`, `world::DIGEST`)
    /// about `subject`.
    World {
        question: &'static str,
        subject: String,
    },
    /// Which file a path of the plan names: whether it or a folder above it
    /// is a link, and where that leads.
    Path(String),
}

impl Block {
    pub(super) fn structural(rule: &'static str, reason: String) -> Self {
        Block {
            rule,
            guard: None,
            reason,
            rested_on: None,
        }
    }

    /// The block, resting on `basis` alone.
    pub(super) fn resting_on(self, basis: Vec<Basis>) -> Self {
        Block {
            rested_on: Some(basis),
            ..self
        }
    }

    fn under(rule: &'static str, guard: &str, reason: String) -> Self {
        let reason = format!("nah session memory ({rule}): {reason}");
        // Self-protection and structural verdicts of judged content report
        // as they did when judged: self-protection's reason leads with its
        // `self` rule.
        if guard == "structural" {
            Block::structural(rule, reason)
        } else if nah_proto::decision::led_by_self_rule(guard) {
            Block::structural(rule, format!("{guard}: {reason}"))
        } else {
            Block {
                rule,
                guard: Some(guard.to_owned()),
                reason,
                rested_on: None,
            }
        }
    }
}

/// Where this call's secret bytes go.
#[derive(Default)]
pub(super) struct Labelling {
    /// Files this call writes secret bytes into.
    pub(super) labelled: Vec<String>,
    /// Effects of this call that carry a labelled file's bytes.
    pub(super) sources: Vec<usize>,
    /// The labelled file each folder or glob read among `sources` takes.
    pub(super) selected: Vec<(usize, String)>,
    /// Labelled files a stated write replaces with content no secret flowed
    /// into, with that content's digest.
    pub(super) unlabelled: Vec<(String, String)>,
}

/// The ledger entries the rules found and used for one call, as they found
/// them, and the calls in flight whose proposals the state counted: what a
/// replay's export says the ledger held.
#[derive(Default, serde::Serialize)]
pub(crate) struct Consulted {
    pub(super) flagged: BTreeMap<String, ContentVerdict>,
    pub(super) written: BTreeMap<String, String>,
    pub(super) pending: BTreeMap<String, Pending>,
    pub(super) labels: BTreeMap<String, Option<String>>,
    pub(super) label_digests: BTreeSet<String>,
    pub(super) fetched: BTreeMap<String, Fetched>,
    pub(super) fetched_digests: BTreeSet<String>,
    pub(super) in_flight: Vec<String>,
}

/// One call as the session rules see it: what its plan does, the writes
/// judged before the ledger was locked, and the session's state under that
/// lock. `check` runs only for a delegated call.
pub(super) struct Call<'a> {
    /// The session's state with every call in flight counted as run.
    pub(super) memory: &'a SessionState,
    pub(super) facts: &'a CallFacts,
    pub(super) judged: &'a [JudgedWrite],
    pub(super) policy: &'a GuardSettings,
    /// The decision context's home.
    pub(super) home: &'a str,
    pub(super) world: &'a dyn World,
    pub(super) consulted: &'a RefCell<Consulted>,
}

impl<'a> Call<'a> {
    /// The first rule that blocks the call.
    pub(super) fn check(&self, labelling: &Labelling) -> Option<Block> {
        self.flagged_content_run()
            .or_else(|| self.pending_launch())
            .or_else(|| self.secret_label(labelling))
            .or_else(|| self.fetched_code_run())
    }

    /// A saved judgment follows the rule that flagged it. Structural and
    /// self-protection verdicts are outside the shipped rule settings.
    fn flagging_rule_live(&self, rule: &str) -> bool {
        crate::catalog::shipped_guards()
            .parts(rule)
            .map(|part| part.applies_at)
            .min()
            .is_none_or(|level| self.policy.rule_level(rule) >= level)
    }

    /// Rule 1, `flagged-content-run`: flagged content reaching an
    /// interpreter as its program, by its digest, or by path where the
    /// content cannot be hashed. Only the targets or scripts the run selects
    /// decide, and the block follows the guards that flagged the content.
    fn flagged_content_run(&self) -> Option<Block> {
        for program in &self.facts.programs {
            let verdict = match (&program.digest, &program.path) {
                (Some(digest), _) => self.flagged(digest),
                (None, Some(path)) => self.written(path).and_then(|digest| self.flagged(digest)),
                (None, None) => None,
            };
            let Some(verdict) = verdict else {
                continue;
            };
            let guards = selected_guards(verdict, &program.argv);
            let Some(owner) = guards.iter().find(|guard| self.flagging_rule_live(guard)) else {
                continue;
            };
            let name = program.path.as_deref().map_or("a program", base_name);
            // By digest, the content is known; by path, the file there was
            // not hashed, and what it holds now may not be what was judged.
            let basis = match (&program.digest, &program.path) {
                (None, Some(path)) => vec![
                    Basis::World {
                        question: DIGEST,
                        subject: path.clone(),
                    },
                    Basis::Path(path.clone()),
                ],
                _ => Vec::new(),
            };
            return Some(
                Block::under(
                    "flagged-content-run",
                    owner,
                    format!(
                        "this command runs {name}, whose content was judged unsafe to run when it was written in this session ({}); do not run it another way; ask the operator, who can inspect `nah session`",
                        guards.join(", ")
                    ),
                )
                .resting_on(basis),
            );
        }
        None
    }

    /// Rule 2, `pending-launch`: a write onto a path a launch waits to run,
    /// of flagged content or of content Nah cannot state, and flagged
    /// content placed where something runs it later outside the session.
    fn pending_launch(&self) -> Option<Block> {
        let pending = |path: &str| {
            self.pending_at(path)
                .map(|pending| (pending.via.as_str(), pending.scheduled))
                .or_else(|| {
                    self.facts
                        .launches
                        .iter()
                        .find(|(launched, _, _)| launched == path)
                        .map(|(_, via, scheduled)| (via.as_str(), *scheduled))
                })
        };
        let home = self.home;
        for write in self.judged {
            if write.judged != Judged::Flagged {
                continue;
            }
            let flagging = write
                .verdict
                .guards
                .iter()
                .find(|guard| self.flagging_rule_live(guard));
            let name = base_name(&write.path);
            let guards = write.verdict.guards.join(", ");
            if let Some((via, scheduled)) = pending(&write.path) {
                let owner = if scheduled {
                    Some(PERSISTENCE)
                        .filter(|guard| self.policy.rule_level(guard) >= GuardLevel::Core)
                } else {
                    flagging.map(String::as_str)
                };
                if let Some(owner) = owner {
                    return Some(Block::under(
                        "pending-launch",
                        owner,
                        format!(
                            "{name} is waiting to be run by a {via} launch in this session, and the content written here is unsafe to run ({guards}); ask the operator"
                        ),
                    ));
                }
            }
            if let Some(owner) = flagging
                && runs_later(&write.path, home, self.world)
            {
                return Some(Block::under(
                    "pending-launch",
                    owner,
                    format!(
                        "{} is a place something runs later, outside this session, and the content written here is unsafe to run ({guards}); ask the operator",
                        write.path
                    ),
                ));
            }
        }
        // A crontab or launch agent entry runs outside every session, so no
        // content Nah cannot state may reach it. A launch in the session
        // meets only content no one has read: a download, a decode or
        // unpack, or a copy of fetched content. A build, a formatter, a
        // checkout, a program's output or a copy of a local file is what
        // local code makes from local files, as the same commands sent as
        // two calls make it.
        let mut unseen = None;
        for opaque in &self.facts.opaque {
            let Some((via, scheduled)) = pending(&opaque.path) else {
                continue;
            };
            // A copy whose source was judged decides above.
            if self
                .judged
                .iter()
                .any(|write| write.path == opaque.path && write.judged != Judged::Unjudged)
            {
                continue;
            }
            if !scheduled
                && !unseen
                    .get_or_insert_with(|| self.unseen_content())
                    .contains(&opaque.path)
            {
                continue;
            }
            let owner = if scheduled {
                PERSISTENCE
            } else {
                UNTRUSTED_CODE
            };
            if self.policy.rule_level(owner) >= GuardLevel::Core {
                let block = Block::under(
                    "pending-launch",
                    owner,
                    format!(
                        "{} is waiting to be run by a {via} launch in this session, and this command writes content nah cannot see onto it (a download, decode or copy); write it with content nah can read, or ask the operator",
                        base_name(&opaque.path)
                    ),
                );
                // A copy whose source was read but could not be judged
                // rests on that judgment, which does not say what it read.
                if self.judged.iter().any(|write| write.path == opaque.path) {
                    return Some(block);
                }
                // Otherwise the content is unstated by the plan (a
                // download or decode), a copy's source could not be read, or
                // was fetched, or an append's file could not be read before
                // it.
                let mut basis = vec![Basis::Path(opaque.path.clone())];
                if opaque.unread_before {
                    basis.push(Basis::World {
                        question: TEXT,
                        subject: opaque.path.clone(),
                    });
                }
                if let Some(source) = &opaque.source {
                    basis.push(Basis::World {
                        question: if scheduled { TEXT } else { DIGEST },
                        subject: source.clone(),
                    });
                    basis.push(Basis::Path(source.clone()));
                }
                return Some(block.resting_on(basis));
            }
        }
        None
    }

    /// Files this call writes with content no one has read: what its
    /// downloads, network responses, decodes and unpacks write, and its
    /// copies of fetched content.
    fn unseen_content(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .fetched_here()
            .into_iter()
            .map(|(path, ..)| path)
            .collect();
        paths.extend(self.reached_writes(&self.facts.unseen));
        paths
    }

    /// Rule 3, `secret-label`: a file secret bytes flowed into, staged or
    /// committed, uploaded, or read back into the agent's context.
    fn secret_label(&self, labelling: &Labelling) -> Option<Block> {
        let all: Vec<&str> = self
            .memory
            .labels
            .keys()
            .map(String::as_str)
            .chain(labelling.labelled.iter().map(String::as_str))
            .collect();
        let exfiltration = self.policy.rule_level(EXFILTRATION) >= GuardLevel::Core;
        if exfiltration {
            for staging in &self.facts.staging {
                // A file `git add` names is staged as named. A folder it names,
                // or a whole-tree selection, stages the labelled files below
                // that git selects, and a commit records the labelled bytes
                // the index already holds.
                let staged = all.iter().find(|path| {
                    let worktree = within(path, &staging.worktree);
                    let below = staging.paths.iter().any(|named| within(path, named))
                        || staging.unnamed && worktree;
                    !staging.commit && staging.paths.iter().any(|named| named == *path)
                        || below && staged_whole(staging, path, self.world)
                        || staging.commit
                            && worktree
                            && self.world.index_holds_label(
                                &staging.worktree,
                                path,
                                &self.memory.label_digests,
                            )
                });
                if let Some(path) = staged {
                    self.labelled(path);
                    return Some(Block::under(
                        "secret-label",
                        EXFILTRATION,
                        format!(
                            "{} holds secret material written earlier in this session, and this command stages or commits it; history is hard to clean once committed; leave it out, or ask the operator",
                            base_name(path)
                        ),
                    ));
                }
            }
        }
        let flow = self.facts.flow.as_ref()?;
        if labelling.sources.is_empty() {
            return None;
        }
        let path_of = |effect: usize| {
            labelling
                .selected
                .iter()
                .find(|(selection, _)| *selection == effect)
                .map(|(_, path)| path)
                .or_else(|| {
                    self.facts
                        .touches
                        .iter()
                        .find(|touch| touch.effect == effect)
                        .map(|touch| &touch.path)
                })
                .map_or("a labelled file", |path| base_name(path))
        };
        if exfiltration && self.facts.sends && flow.reaches_network(&labelling.sources) {
            return Some(Block::under(
                "secret-label",
                EXFILTRATION,
                format!(
                    "{} holds secret material written earlier in this session, and this command sends its bytes over the network; ask the operator",
                    path_of(labelling.sources[0])
                ),
            ));
        }
        if self.policy.rule_level(SECRETS) >= GuardLevel::Core {
            let read_back = match self.facts.tool.as_str() {
                "Read" | "Grep" | "NotebookRead" => labelling.sources.first().copied(),
                _ => labelling
                    .sources
                    .iter()
                    .copied()
                    .find(|effect| flow.reaches_output(*effect)),
            };
            if let Some(effect) = read_back {
                return Some(Block::under(
                    "secret-label",
                    SECRETS,
                    format!(
                        "{} holds secret material written earlier in this session; reading it back discloses the secret; ask the operator for the specific non-secret value needed",
                        path_of(effect)
                    ),
                ));
            }
        }
        None
    }

    /// Rule 4, `fetched-code-run`, strict: running code a download, a clone
    /// or the extraction of a fetched archive put on disk this session, or a
    /// copy of it, or placing downloaded content where something runs it
    /// later.
    fn fetched_code_run(&self) -> Option<Block> {
        let part = &nah_policy::FETCHED_CODE_RUN;
        if self.policy.rule_level(part.rule) < part.applies_at {
            return None;
        }
        let fetched_here = self.fetched_here();
        let here = |path: &str| {
            fetched_here
                .iter()
                .any(|(known, _, tree)| known == path || *tree && within(path, known))
        };
        let block = |what: &str| {
            Some(Block::under(
                "fetched-code-run",
                part.rule,
                format!(
                    "{}. This command runs {what} from a download, clone, extracted archive, or copy. Review the code first, or ask the operator",
                    part.reason
                ),
            ))
        };
        for program in &self.facts.programs {
            let Some(path) = &program.path else {
                continue;
            };
            let in_this_call = here(path);
            if in_this_call || self.fetched_before(path, program.digest.as_deref()) {
                // Fetched code is met by where it is, or by a known digest;
                // a file fetched before is also met by its path alone when
                // the file there was not hashed.
                let mut basis = vec![Basis::Path(path.clone())];
                if !in_this_call
                    && program.digest.is_none()
                    && !self
                        .memory
                        .fetched
                        .iter()
                        .any(|(known, fetched)| fetched.tree && within(path, known))
                {
                    basis.push(Basis::World {
                        question: DIGEST,
                        subject: path.clone(),
                    });
                }
                return block(base_name(path)).map(|block| block.resting_on(basis));
            }
        }
        for folder in &self.facts.builds {
            if let Some((known, fetched)) = self
                .memory
                .fetched
                .iter()
                .find(|(known, fetched)| fetched.tree && within(folder, known))
            {
                self.note_fetched(known, fetched);
                return block(&format!("a build or install in {folder}"))
                    .map(|block| block.resting_on(vec![Basis::Path(folder.clone())]));
            }
        }
        let home = self.home;
        if let Some((path, ..)) = fetched_here
            .iter()
            .find(|(path, source, _)| *source != "copy" && runs_later(path, home, self.world))
        {
            return Some(Block::under(
                "fetched-code-run",
                part.rule,
                format!(
                    "{}. This command downloads into {path}, where the content runs later outside this session. Ask the operator",
                    part.reason
                ),
            ));
        }
        None
    }

    /// Where this call's secret bytes flow: from secret reads and from
    /// files already labelled into the files it writes, following each new
    /// label into the reads after it.
    pub(super) fn label_flow(&self) -> Labelling {
        let mut labelling = Labelling::default();
        let Some(flow) = &self.facts.flow else {
            return labelling;
        };
        let facts = self.facts;
        let mut hashed = 0;
        let mut labelled_now = |touch: &super::facts::Touch| {
            let path = touch.path.as_str();
            // A read after this call replaced the file sees only the call's
            // own content; a label it carries is followed below.
            if let Some(own) = touch.own.as_ref().filter(|_| touch.replaced) {
                return self.labelled_digest(own);
            }
            let own = touch.own.as_ref();
            if self.labelled(path) {
                return true;
            }
            if self.memory.label_digests.is_empty() {
                return false;
            }
            let digest = own.cloned().or_else(|| {
                hashed += 1;
                (hashed <= MAX_HASHED_FILES)
                    .then(|| self.world.digest(path))
                    .flatten()
            });
            digest.is_some_and(|digest| self.labelled_digest(&digest))
        };
        labelling.sources = facts
            .touches
            .iter()
            .filter(|touch| touch.carries && labelled_now(touch))
            .map(|touch| touch.effect)
            .collect();
        // A folder walk or glob read takes every labelled file it selects.
        for selection in &facts.selections {
            if let Some(path) = self
                .memory
                .labels
                .keys()
                .find(|path| selects(selection, path, self.world))
            {
                self.labelled(path);
                labelling.sources.push(selection.effect);
                labelling.selected.push((selection.effect, path.clone()));
            }
        }
        let writes: Vec<usize> = facts
            .write_effects
            .iter()
            .map(|(effect, _)| *effect)
            .collect();
        // A stated write that holds a credential variable's value carries
        // it, whatever the graph shows of how it got there.
        for write in &facts.writes {
            if facts
                .secret_values
                .iter()
                .any(|value| write.content.contains(value.as_str()))
                && !labelling.labelled.contains(&write.path)
            {
                labelling.labelled.push(write.path.clone());
            }
        }
        // An edit keeps a labelled file's label: Nah cannot tell whether the
        // secret bytes survive it, and only a whole new content clears one.
        for write in &facts.writes {
            if write.in_place
                && self.labelled(&write.path)
                && !labelling.labelled.contains(&write.path)
            {
                labelling.labelled.push(write.path.clone());
            }
        }
        // Each round adds sources or stops, and a plan has finitely many
        // effects, so this runs until no label is left to follow.
        loop {
            let sources: Vec<usize> = facts
                .secret_sources
                .iter()
                .chain(&labelling.sources)
                .copied()
                .collect();
            for effect in flow.reached_effects(&sources, &writes) {
                if let Some((_, path)) = facts
                    .write_effects
                    .iter()
                    .find(|(write, _)| *write == effect)
                    && !labelling.labelled.contains(path)
                {
                    labelling.labelled.push(path.clone());
                }
            }
            // A file labelled earlier in the call carries the label into
            // the reads after its write.
            let first_write = |path: &str| {
                facts
                    .write_effects
                    .iter()
                    .find(|(_, written)| written == path)
                    .map(|(effect, _)| *effect)
            };
            let more: Vec<usize> = facts
                .touches
                .iter()
                .filter(|touch| {
                    touch.carries
                        && !labelling.sources.contains(&touch.effect)
                        && labelling.labelled.contains(&touch.path)
                        && first_write(&touch.path).is_some_and(|write| write < touch.effect)
                })
                .map(|touch| touch.effect)
                .collect();
            let mut selected: Vec<(usize, String)> = Vec::new();
            for selection in &facts.selections {
                if labelling.sources.contains(&selection.effect) {
                    continue;
                }
                if let Some(path) = labelling.labelled.iter().find(|path| {
                    selects(selection, path, self.world)
                        && first_write(path).is_some_and(|write| write < selection.effect)
                }) {
                    selected.push((selection.effect, path.clone()));
                }
            }
            if more.is_empty() && selected.is_empty() {
                break;
            }
            labelling.sources.extend(more);
            labelling
                .sources
                .extend(selected.iter().map(|(effect, _)| *effect));
            labelling.selected.extend(selected);
        }
        for write in facts.writes.iter().rev() {
            if write.replaces
                && self.labelled(&write.path)
                && !labelling.labelled.contains(&write.path)
                && !labelling
                    .unlabelled
                    .iter()
                    .any(|(path, _)| *path == write.path)
            {
                labelling
                    .unlabelled
                    .push((write.path.clone(), content_digest(write.content.as_bytes())));
            }
        }
        labelling
    }

    /// What the call proposes to leave behind.
    pub(super) fn changes(&self, labelling: &Labelling) -> Vec<Change> {
        let mut changes = Vec::new();
        // The last judged state of each path is what a later run meets.
        let mut seen = Vec::new();
        for write in self.judged.iter().rev() {
            if seen.contains(&write.path.as_str()) {
                continue;
            }
            seen.push(write.path.as_str());
            // A clean write matters only where it replaces flagged content.
            if write.judged == Judged::Flagged || self.written(&write.path).is_some() {
                changes.push(Change::Wrote {
                    path: write.path.clone(),
                    digest: write.digest.clone(),
                });
            }
        }
        for (path, via, scheduled) in &self.facts.launches {
            // A launch that ends with the call and whose file Nah read leaves
            // nothing to wait for.
            if *scheduled || self.facts.background || self.world.digest(path).is_none() {
                changes.push(Change::Launch {
                    path: path.clone(),
                    via: via.clone(),
                    scheduled: *scheduled,
                });
            }
        }
        changes.extend(labelling.labelled.iter().map(|path| Change::Label {
            path: path.clone(),
            found: file_state(path, self.world),
        }));
        changes.extend(
            labelling
                .unlabelled
                .iter()
                .map(|(path, digest)| Change::Unlabel {
                    path: path.clone(),
                    digest: digest.clone(),
                }),
        );
        let fetched = self.fetched_here();
        for (path, source, tree) in &fetched {
            changes.push(Change::Fetched {
                path: path.clone(),
                source: (*source).into(),
                tree: *tree,
                found: fingerprint(path, *tree, self.world),
            });
        }
        for (archive, folder) in &self.facts.extractions {
            let fetched_archive = fetched.iter().any(|(path, ..)| path == archive)
                || self.fetched_at(archive)
                || self
                    .world
                    .digest(archive)
                    .is_some_and(|digest| self.fetched_digest(&digest));
            if fetched_archive {
                changes.push(Change::Fetched {
                    path: folder.clone(),
                    source: "extract".into(),
                    tree: true,
                    found: fingerprint(folder, true, self.world),
                });
            }
        }
        changes
    }

    /// What this call fetches, by path, source and whether it is a folder:
    /// the files its downloads write and the folders its clones fill, then
    /// each copy or move it makes of a fetched file or of a file below a
    /// fetched folder, which keeps where its bytes came from.
    fn fetched_here(&self) -> Vec<(String, &'static str, bool)> {
        let mut fetched: Vec<(String, &'static str, bool)> = self
            .reached_writes(&self.facts.downloads)
            .into_iter()
            .map(|path| {
                let clone = self.facts.clones.contains(&path);
                (path, if clone { "clone" } else { "download" }, clone)
            })
            .collect();
        for opaque in &self.facts.opaque {
            let Some(source) = opaque.source.as_deref() else {
                continue;
            };
            let from_fetched = fetched
                .iter()
                .any(|(known, _, tree)| known == source || *tree && within(source, known))
                || self.fetched_before(source, self.world.digest(source).as_deref());
            if from_fetched && !fetched.iter().any(|(known, ..)| *known == opaque.path) {
                fetched.push((opaque.path.clone(), "copy", self.world.is_dir(source)));
            }
        }
        fetched
    }

    /// Whether an earlier call of the session fetched `path`, or the content
    /// `digest`.
    fn fetched_before(&self, path: &str, digest: Option<&str>) -> bool {
        if digest.is_some_and(|digest| self.fetched_digest(digest)) {
            return true;
        }
        let found = self.memory.fetched.iter().find(|(known, fetched)| {
            if fetched.tree {
                within(path, known)
            } else {
                *known == path
                    && (digest.is_none()
                        || fetched.digest.is_none()
                        || fetched.digest.as_deref() == digest)
            }
        });
        if let Some((known, fetched)) = found {
            self.note_fetched(known, fetched);
        }
        found.is_some()
    }

    /// Files the content of the effects `sources` is written to.
    fn reached_writes(&self, sources: &[usize]) -> Vec<String> {
        let Some(flow) = &self.facts.flow else {
            return Vec::new();
        };
        let writes: Vec<usize> = self
            .facts
            .write_effects
            .iter()
            .map(|(effect, _)| *effect)
            .collect();
        flow.reached_effects(sources, &writes)
            .into_iter()
            .filter_map(|effect| {
                self.facts
                    .write_effects
                    .iter()
                    .find(|(write, _)| *write == effect)
                    .map(|(_, path)| path.clone())
            })
            .collect()
    }

    fn flagged(&self, digest: &str) -> Option<&ContentVerdict> {
        self.judged
            .iter()
            .find(|write| write.judged == Judged::Flagged && write.digest == digest)
            .map(|write| &write.verdict)
            .or_else(|| {
                let verdict = self.memory.flagged.get(digest)?;
                self.consulted
                    .borrow_mut()
                    .flagged
                    .insert(digest.to_owned(), verdict.clone());
                Some(verdict)
            })
    }

    /// The digest of flagged content the ledger says `path` last held.
    fn written(&self, path: &str) -> Option<&'a String> {
        let digest = self.memory.written.get(path)?;
        self.consulted
            .borrow_mut()
            .written
            .insert(path.to_owned(), digest.clone());
        Some(digest)
    }

    /// The launch the ledger says waits to run `path`.
    fn pending_at(&self, path: &str) -> Option<&'a Pending> {
        let pending = self.memory.pending.get(path)?;
        self.consulted
            .borrow_mut()
            .pending
            .insert(path.to_owned(), pending.clone());
        Some(pending)
    }

    /// Whether the ledger labels `path`.
    fn labelled(&self, path: &str) -> bool {
        let Some(found) = self.memory.labels.get(path) else {
            return false;
        };
        self.consulted
            .borrow_mut()
            .labels
            .insert(path.to_owned(), found.clone());
        true
    }

    /// Whether the ledger holds `digest` as labelled content.
    fn labelled_digest(&self, digest: &str) -> bool {
        let held = self.memory.label_digests.contains(digest);
        if held {
            self.consulted
                .borrow_mut()
                .label_digests
                .insert(digest.to_owned());
        }
        held
    }

    /// Whether the ledger holds `path` as fetched, by exactly that path.
    fn fetched_at(&self, path: &str) -> bool {
        let Some(fetched) = self.memory.fetched.get(path) else {
            return false;
        };
        self.note_fetched(path, fetched);
        true
    }

    fn note_fetched(&self, path: &str, fetched: &Fetched) {
        self.consulted
            .borrow_mut()
            .fetched
            .insert(path.to_owned(), fetched.clone());
    }

    /// Whether the ledger holds `digest` as fetched content.
    fn fetched_digest(&self, digest: &str) -> bool {
        let held = self.memory.fetched_digests.contains(digest);
        if held {
            self.consulted
                .borrow_mut()
                .fetched_digests
                .insert(digest.to_owned());
        }
        held
    }
}

/// The guards a run of flagged content blocks on, given the targets or
/// scripts its launching program selects.
fn selected_guards(verdict: &ContentVerdict, argv: &[String]) -> Vec<String> {
    if verdict.entries.is_empty() {
        return verdict.guards.clone();
    }
    let Some(names) = selected_entries(argv, &verdict.entries) else {
        return verdict.guards.clone();
    };
    let mut guards: Vec<String> = Vec::new();
    for (name, entry_guards) in &verdict.entries {
        if names.contains(name) {
            for guard in entry_guards {
                if !guards.contains(guard) {
                    guards.push(guard.clone());
                }
            }
        }
    }
    guards
}

/// The Makefile targets or manifest scripts `argv` runs, or `None` when the
/// launching program is neither `make` nor a package manager it knows.
fn selected_entries(argv: &[String], entries: &[(String, Vec<String>)]) -> Option<Vec<String>> {
    let program = base_name(argv.first()?);
    let words = &argv[1..];
    match program {
        "make" | "gmake" => {
            let mut targets = Vec::new();
            let mut words = words.iter().map(String::as_str).peekable();
            let mut options = true;
            while let Some(word) = words.next() {
                if !options || !word.starts_with('-') || word == "-" {
                    if !word.contains('=') {
                        targets.push(word.to_owned());
                    }
                    continue;
                }
                if word == "--" {
                    options = false;
                } else if let Some(long) = word.strip_prefix("--") {
                    // A long option's operand follows it unless attached;
                    // `--jobs` and `--load-average` take a count only when
                    // the next word is one.
                    let takes_operand = matches!(
                        long,
                        "file"
                            | "makefile"
                            | "directory"
                            | "include-dir"
                            | "old-file"
                            | "assume-old"
                            | "new-file"
                            | "assume-new"
                            | "what-if"
                            | "eval"
                    );
                    let takes_count = matches!(long, "jobs" | "load-average" | "max-load")
                        && words.peek().is_some_and(|next| next.parse::<f64>().is_ok());
                    if takes_operand || takes_count {
                        words.next();
                    }
                } else {
                    // In a cluster like `-sf FILE` the operand belongs to
                    // the first letter that takes one: the rest of the word
                    // if any, else the next word. `-j` and `-l` take a count
                    // only when the next word is one.
                    let letters = &word[1..];
                    if let Some(at) = letters.find(['f', 'C', 'I', 'o', 'W', 'E']) {
                        if at + 1 == letters.len() {
                            words.next();
                        }
                    } else if letters.ends_with(['j', 'l'])
                        && words.peek().is_some_and(|next| next.parse::<f64>().is_ok())
                    {
                        words.next();
                    }
                }
            }
            if targets.is_empty() {
                targets.extend(entries.first().map(|(name, _)| name.clone()));
            }
            // A word taken for a target the Makefile does not name may be an
            // option's operand this parse missed: the whole file decides.
            if targets
                .iter()
                .any(|target| !entries.iter().any(|(name, _)| name == target))
            {
                return None;
            }
            Some(targets)
        }
        "npm" | "pnpm" | "yarn" | "bun" => {
            let around =
                |name: &str| vec![format!("pre{name}"), name.to_owned(), format!("post{name}")];
            let mut words = words.iter().filter(|word| !word.starts_with('-'));
            Some(match words.next().map(String::as_str) {
                Some("run" | "run-script") => around(words.next()?),
                Some(name @ ("test" | "t" | "start" | "stop" | "restart")) => {
                    around(if name == "t" { "test" } else { name })
                }
                Some("install" | "i" | "ci" | "add") | None => {
                    ["preinstall", "install", "postinstall", "prepare"]
                        .map(str::to_owned)
                        .to_vec()
                }
                Some("pack" | "publish") => [
                    "prepack",
                    "prepare",
                    "postpack",
                    "prepublishOnly",
                    "prepublish",
                    "publish",
                    "postpublish",
                ]
                .map(str::to_owned)
                .to_vec(),
                // `yarn build` runs the script named `build`.
                Some(name) if program == "yarn" => around(name),
                Some(_) => return None,
            })
        }
        _ => None,
    }
}

/// Whether a folder walk or glob read takes the content of `path`, under
/// the filters its plan states. A filter Nah cannot read leaves nothing out.
fn selects(selection: &Selection, path: &str, world: &dyn World) -> bool {
    let rest = match &selection.what {
        Selected::Glob(glob, narrowing) => {
            return glob_match(glob, path) != Ok(false)
                && narrowing.admits(FsEntryKind::File, base_name(path));
        }
        Selected::Below(folder) => match path
            .strip_prefix(folder.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
        {
            Some(rest) if !rest.is_empty() => rest,
            _ => return false,
        },
    };
    if selection.hidden_skipped && rest.split('/').any(|part| part.starts_with('.')) {
        return false;
    }
    // A glob without `/` matches the file's name, as ripgrep's do.
    let matched = |glob: &str| {
        let target = if glob.contains('/') {
            rest
        } else {
            base_name(rest)
        };
        glob_match(glob, target)
    };
    let (excludes, includes): (Vec<&String>, Vec<&String>) = selection
        .search_globs
        .iter()
        .partition(|glob| glob.starts_with('!'));
    if excludes.iter().any(|glob| matched(&glob[1..]) == Ok(true)) {
        return false;
    }
    if !includes.is_empty() && includes.iter().all(|glob| matched(glob) == Ok(false)) {
        return false;
    }
    !(selection.ignores_honoured && git_ignores(path, world))
}

/// Whether git ignores `path` in its work tree.
fn git_ignores(path: &str, world: &dyn World) -> bool {
    let Some(folder) = Path::new(path).parent().and_then(Path::to_str) else {
        return false;
    };
    world.git_check_ignore(folder, path) == Some(true)
}

/// Whether staging a folder or the whole tree, by `git add` or a commit (`-a`,
/// a folder pathspec), takes the labelled file `path`: a commit takes it when
/// tracked, `git add` when git does not ignore it or the add is forced.
fn staged_whole(staging: &Staging, path: &str, world: &dyn World) -> bool {
    if staging.forced {
        return true;
    }
    let answer = if staging.commit {
        world.git_tracked(&staging.worktree, path)
    } else {
        world.git_check_ignore(&staging.worktree, path)
    };
    // Unknown: a secret is not staged on a guess that it is ignored.
    answer.is_none_or(|success| success == staging.commit)
}
