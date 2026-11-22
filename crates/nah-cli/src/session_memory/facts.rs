//! What one call's plan says it reads, writes, runs, fetches and stages, for
//! the session rules and the ledger.

use std::collections::BTreeMap;

use nah_proto::effect_annotation::{EffectAnnotation, PathLabel};
use nah_proto::effinterp_proto::{
    AttrValue, ExecutionContent, ExecutionNode, FsNarrowing, Plan, ResourceExpr, ResourceIdentity,
    ResourcePattern, content_digest,
};
use nah_proto::labels::Sensitivity;

use super::flow::Flow;
use serde::Serialize;

use super::base_name;
use super::world::World;

/// Programs that build, install or test a folder and so run code from it,
/// whether or not the plan names the files they run.
const BUILD_TOOLS: &[&str] = &[
    "pip", "pip3", "pipx", "uv", "poetry", "pdm", "hatch", "tox", "nox", "pytest", "npm", "npx",
    "pnpm", "yarn", "bun", "deno", "cargo", "go", "make", "gmake", "cmake", "bundle", "rake",
    "gradle", "gradlew", "mvn", "mvnw", "composer", "mix", "swift", "dotnet",
];

/// A state a write leaves a file in, where the plan states the content.
#[derive(Serialize)]
pub(super) struct Written {
    /// Plan position of the write.
    pub(super) at: usize,
    pub(super) path: String,
    /// Exported as its digest.
    #[serde(rename = "digest", serialize_with = "digest")]
    pub(super) content: String,
    /// The write replaces the file rather than adding to it.
    pub(super) replaces: bool,
    /// The content is the file's own, edited in place (`Edit`, `sed -i`),
    /// so what it held before may survive in it.
    pub(super) in_place: bool,
}

/// A write whose content the plan does not state: a copy, a move, a
/// download, a decode or a program's output.
#[derive(Serialize)]
pub(super) struct Opaque {
    pub(super) at: usize,
    pub(super) path: String,
    /// The file a copy or move takes its bytes from, when the plan names it.
    pub(super) source: Option<String>,
    /// An append whose content is unknown only because what the file held
    /// before could not be read.
    #[serde(skip)]
    pub(super) unread_before: bool,
}

/// A file content an interpreter runs as its program.
#[derive(Serialize)]
pub(super) struct Program {
    pub(super) path: Option<String>,
    /// The content's digest, where the plan, an earlier write of the call or
    /// the file on disk gives it.
    pub(super) digest: Option<String>,
    /// The launching program's arguments, which select a Makefile's targets
    /// or a manifest's scripts.
    pub(super) argv: Vec<String>,
}

/// A filesystem effect on one concrete path, with what its content view is.
#[derive(Serialize)]
pub(super) struct Touch {
    pub(super) effect: usize,
    pub(super) path: String,
    /// A read, move or delete, whose content can flow on.
    pub(super) carries: bool,
    /// The digest of the call's own content written there earlier, which
    /// this effect sees instead of what was on disk.
    pub(super) own: Option<String>,
    /// That content replaced the file, so none of what it held before the
    /// call is left; an append keeps it.
    pub(super) replaced: bool,
}

/// A read of the content of every file a folder walk or a glob selects,
/// rather than of one named file: `grep -r`, `tar`, `zip -r`, `cat dir/*`.
#[derive(Serialize)]
pub(super) struct Selection {
    pub(super) effect: usize,
    pub(super) what: Selected,
    /// Ripgrep-style `--glob` filters over each file's path below the folder;
    /// one starting with `!` leaves its matches out.
    pub(super) search_globs: Vec<String>,
    /// Entries whose name starts with `.` are skipped.
    pub(super) hidden_skipped: bool,
    /// Files git ignores are skipped.
    pub(super) ignores_honoured: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Selected {
    /// Every file below this folder.
    Below(String),
    /// Every file this glob matches, less what the producer left out.
    Glob(String, FsNarrowing),
}

/// `git add` or `git commit`, by what it takes into the index or history.
#[derive(Serialize)]
pub(super) struct Staging {
    pub(super) worktree: String,
    /// The paths it takes from the working tree: those the plan shows `git
    /// add` reading, or a commit's pathspecs. A folder takes what is below.
    pub(super) paths: Vec<String>,
    /// It takes files no path names: `git add -A`, every tracked change
    /// (`commit -a`, `--patch`), or a pathspec Nah cannot read.
    pub(super) unnamed: bool,
    /// A commit, which takes only tracked files from the working tree, and
    /// what the index holds. Only a commit of pathspecs alone leaves the
    /// index out, but an option's value Nah misreads as a pathspec would
    /// then hide it, so every commit counts the index.
    pub(super) commit: bool,
    /// Ignored files too (`git add -f`).
    pub(super) forced: bool,
}

#[derive(Default, Serialize)]
pub(crate) struct CallFacts {
    pub(super) tool: String,
    pub(super) writes: Vec<Written>,
    pub(super) opaque: Vec<Opaque>,
    /// Every concrete filesystem effect, with its content view.
    pub(super) touches: Vec<Touch>,
    /// Content reads of a whole folder or glob.
    pub(super) selections: Vec<Selection>,
    pub(super) programs: Vec<Program>,
    /// Paths a launch or an installed entry will run, as `(path, via,
    /// scheduled)`: the program, scheduler or job that runs it, and whether
    /// it is a crontab or launch agent entry, which runs outside any session.
    pub(super) launches: Vec<(String, String, bool)>,
    pub(super) runs_code: bool,
    /// Effects that read secret material.
    pub(super) secret_sources: Vec<usize>,
    /// The values of credential variables the call reads, which a stated
    /// write that contains them copies. Exported as their count alone.
    #[serde(serialize_with = "count")]
    pub(super) secret_values: Vec<String>,
    /// Every write to a concrete path, by effect.
    pub(super) write_effects: Vec<(usize, String)>,
    pub(super) downloads: Vec<usize>,
    /// Network responses, decodes and unpacks: effects besides `downloads`
    /// whose bytes no one has read.
    pub(super) unseen: Vec<usize>,
    /// Folders a clone writes.
    pub(super) clones: Vec<String>,
    /// Archives the call reads and the folder it extracts them into.
    pub(super) extractions: Vec<(String, String)>,
    pub(super) staging: Vec<Staging>,
    /// Folders a build or install tool works on, by its cwd and arguments.
    pub(super) builds: Vec<String>,
    pub(super) sends: bool,
    /// The call may leave a launch running after it returns.
    pub(super) background: bool,
    #[serde(skip)]
    pub(super) flow: Option<Flow>,
    /// Paths, hosts, variables, credential stores and patterns the call
    /// touches, for the block record.
    pub(super) resources: Vec<String>,
}

fn digest<S: serde::Serializer>(content: &str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&content_digest(content.as_bytes()))
}

fn count<S: serde::Serializer>(values: &[String], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(values.len() as u64)
}

impl CallFacts {
    pub(super) fn of(
        tool: &str,
        input: &serde_json::Value,
        plan: Option<(&Plan, &[EffectAnnotation])>,
        world: &dyn World,
    ) -> Self {
        let mut facts = CallFacts {
            tool: tool.to_owned(),
            background: input
                .get("run_in_background")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || input
                    .get("command")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(leaves_running),
            ..Self::default()
        };
        if let Some((plan, annotations)) = plan {
            facts.add_plan(plan, annotations, world);
            facts.flow = Some(Flow::of(plan));
            let flow = facts.flow.as_ref().expect("set above");
            // A read whose bytes reach an interpreter as its program is a
            // run of that content, whatever route carries it there.
            let mut reached = Vec::new();
            for touch in &facts.touches {
                // A launch's own read of its program is that launch, whose
                // arguments select what of it runs.
                let launched = facts
                    .programs
                    .iter()
                    .any(|program| program.path.as_ref() == Some(&touch.path));
                if !launched
                    && plan.effects[touch.effect].operation.as_str() == "filesystem.read"
                    && flow.reaches_program(touch.effect)
                {
                    reached.push(Program {
                        path: Some(touch.path.clone()),
                        digest: touch.own.clone().or_else(|| world.digest(&touch.path)),
                        argv: Vec::new(),
                    });
                }
            }
            facts.runs_code |= !reached.is_empty();
            facts.programs.extend(reached);
        }
        facts
    }

    fn add_plan(&mut self, plan: &Plan, annotations: &[EffectAnnotation], world: &dyn World) {
        let argv = |node: u32| -> Vec<String> {
            plan.execution_graph
                .nodes
                .get(node as usize)
                .map(|node| {
                    node.argv
                        .iter()
                        .filter_map(literal)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        // The content each file holds so far in this call: absent before the
        // call writes it, `None` once a write leaves it unknown.
        let mut contents: BTreeMap<String, Option<String>> = BTreeMap::new();
        // Each stated write, in plan order: its position, path and the
        // content it leaves (`None` when unknown).
        let mut history: Vec<(usize, String, Option<String>)> = Vec::new();
        // Files this call has replaced with content it states.
        let mut replaced: Vec<String> = Vec::new();
        for (index, effect) in plan.effects.iter().enumerate() {
            let operation = effect.operation.as_str();
            let path = concrete_path(&effect.resource).map(|path| world.canonical(path));
            if let Some(path) = &path
                && !self.resources.contains(path)
                && self.resources.len() < 8
                && operation != "process.exec"
            {
                self.resources.push(path.clone());
            }
            if let Some(name) = resource_name(&effect.resource, world)
                && self.resources.len() < 8
                && !self.resources.contains(&name)
            {
                self.resources.push(name);
            }
            if operation.starts_with("filesystem.")
                && let Some(path) = &path
            {
                let own = contents
                    .get(path)
                    .and_then(Option::as_ref)
                    .map(|content| content_digest(content.as_bytes()));
                self.touches.push(Touch {
                    effect: index,
                    path: path.clone(),
                    carries: matches!(
                        operation,
                        "filesystem.read" | "filesystem.move" | "filesystem.delete"
                    ),
                    replaced: own.is_some() && replaced.contains(path),
                    own,
                });
            }
            match operation {
                // A native patch tool that adds a file, as Codex's
                // `apply_patch` does, states its content on the create.
                "filesystem.write" | "filesystem.create"
                    if operation == "filesystem.write"
                        || self.tool == "apply_patch"
                            && effect.attributes.contains_key("written_content") =>
                {
                    match path {
                        Some(path) => {
                            self.write_effects.push((index, path.clone()));
                            let content = resulting_content(
                                &effect.attributes,
                                &path,
                                contents.get(&path),
                                world,
                            );
                            let appends = matches!(
                                effect.attributes.get("append"),
                                Some(AttrValue::Bool(true))
                            );
                            // `resulting_content` read the file's text, and
                            // only that failed.
                            let unread_before = content.is_none()
                                && appends
                                && !contents.contains_key(&path)
                                && !matches!(
                                    effect.attributes.get("resulting_content"),
                                    Some(AttrValue::String(_))
                                )
                                && matches!(
                                    effect.attributes.get("written_content"),
                                    Some(AttrValue::String(_))
                                );
                            if content.is_none() {
                                replaced.retain(|known| *known != path);
                            } else if !appends && !replaced.contains(&path) {
                                replaced.push(path.clone());
                            }
                            match &content {
                                Some(content) => self.writes.push(Written {
                                    at: index,
                                    path: path.clone(),
                                    content: content.clone(),
                                    replaces: !matches!(
                                        effect.attributes.get("append"),
                                        Some(AttrValue::Bool(true))
                                    ),
                                    in_place: matches!(
                                        effect.attributes.get("in_place"),
                                        Some(AttrValue::Bool(true))
                                    ),
                                }),
                                None => self.opaque.push(Opaque {
                                    at: index,
                                    path: path.clone(),
                                    source: None,
                                    unread_before,
                                }),
                            }
                            history.push((index, path.clone(), content.clone()));
                            contents.insert(path, content);
                        }
                        // An archive extracted into a folder writes a pattern
                        // under it.
                        None => {
                            if let Some(folder) = pattern_folder(&effect.resource) {
                                for read in plan.effects[..index].iter().rev() {
                                    if read.execution == effect.execution
                                        && read.operation.as_str() == "filesystem.read"
                                        && let Some(archive) = concrete_path(&read.resource)
                                    {
                                        self.extractions.push((
                                            world.canonical(archive),
                                            world.canonical(&folder),
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                "filesystem.move" => {}
                "process.code_execution" => self.runs_code = true,
                "network.listen" => {}
                "network.download" => {
                    self.downloads.push(index);
                    self.sends = true;
                }
                "network.request" => {
                    self.unseen.push(index);
                    self.sends = true;
                }
                "process.stream_transform"
                    if matches!(
                        effect.attributes.get("transform"),
                        Some(AttrValue::String(transform)) if transform == "decode" || transform == "extract"
                    ) =>
                {
                    self.unseen.push(index);
                }
                _ if operation.starts_with("network.") => self.sends = true,
                _ if operation.starts_with("credential.read") => self.secret_sources.push(index),
                "environment.read" => {
                    if let Some(name) = secret_environment(&effect.resource) {
                        self.secret_sources.push(index);
                        if name != "*"
                            && let Some(value) = world.env(&name)
                            && value.len() >= 8
                        {
                            self.secret_values.push(value);
                        }
                    }
                }
                "git.index_write" | "git.ref_update" | "git.history_rewrite" => {
                    if let Some(staging) = staging(plan, index, world) {
                        self.staging.push(staging);
                    }
                }
                _ => {}
            }
            if operation == "filesystem.read"
                && let Some(selection) = selection(index, effect, world)
            {
                self.selections.push(selection);
            }
            if operation == "filesystem.read"
                && let Some(Some(PathLabel::Resolved { sensitivity, .. })) =
                    annotations.get(index).map(|annotation| &annotation.path)
                && matches!(
                    sensitivity,
                    Sensitivity::EnvironmentSecret
                        | Sensitivity::CredentialSecret
                        | Sensitivity::KeyMaterial
                )
            {
                self.secret_sources.push(index);
            }
        }
        for effect in &plan.effects {
            if effect.operation.as_str() == "git.remote_sync"
                && matches!(effect.attributes.get("clone"), Some(AttrValue::Bool(true)))
            {
                self.clones.extend(
                    self.write_effects
                        .iter()
                        .filter(|(write, _)| plan.effects[*write].execution == effect.execution)
                        .map(|(_, path)| path.clone()),
                );
            }
        }
        // A move or copy names its source by the transfer edge into its
        // destination; the plan lists the source's read or delete first in
        // the same execution.
        for opaque in &mut self.opaque {
            let execution = plan.effects[opaque.at].execution;
            opaque.source = plan.effects[..opaque.at]
                .iter()
                .rev()
                .take_while(|effect| effect.execution == execution)
                .find(|effect| {
                    matches!(
                        effect.operation.as_str(),
                        "filesystem.read" | "filesystem.delete"
                    ) && effect
                        .attributes
                        .get("access_purpose")
                        .is_none_or(|purpose| {
                            matches!(purpose, AttrValue::String(purpose) if purpose == "program_input")
                        })
                })
                .and_then(|effect| concrete_path(&effect.resource))
                .map(|path| world.canonical(path))
                .filter(|source| *source != opaque.path);
        }
        for (position, node) in plan.execution_graph.nodes.iter().enumerate() {
            let Some(input) = &node.input else {
                continue;
            };
            let path = node
                .selected_source_path()
                .map(|path| world.canonical(path));
            // The launch runs at its first effect, or its requester's (the
            // interpreter that reads it), so a write after that does not
            // change what it ran.
            let runs_at = plan
                .effects
                .iter()
                .position(|effect| {
                    let node = effect.execution.0 as usize;
                    node == position || node == input.requester.0 as usize
                })
                .unwrap_or(plan.effects.len());
            // What the launch runs: the plan's content, the call's own
            // earlier write, or the file on disk. A file outside the work
            // tree the plan does not read is hashed here.
            let digest =
                match &input.content {
                    ExecutionContent::Observed { digest }
                    | ExecutionContent::Predicted { digest, .. } => Some(digest.clone()),
                    ExecutionContent::Unobserved { .. } => path.as_deref().and_then(|path| {
                        match history
                            .iter()
                            .rev()
                            .find(|(at, written, _)| *at < runs_at && written == path)
                        {
                            Some((_, _, Some(content))) => Some(content_digest(content.as_bytes())),
                            Some((_, _, None)) => None,
                            None => world.digest(path),
                        }
                    }),
                };
            if let Some(path) = &path {
                self.launches
                    .push((path.clone(), input.requester_component.clone(), false));
            }
            self.programs.push(Program {
                path,
                digest,
                argv: argv(input.requester.0),
            });
            self.runs_code = true;
        }
        for node in &plan.execution_graph.nodes {
            self.add_scheduled_launches(plan, node, world);
            let words: Vec<&str> = node.argv.iter().filter_map(literal).collect();
            if words
                .first()
                .is_some_and(|program| BUILD_TOOLS.contains(&base_name(program)))
            {
                self.runs_code = true;
                let cwd = node
                    .cwd
                    .as_ref()
                    .and_then(concrete_path)
                    .map(|path| world.canonical(path));
                if let Some(cwd) = &cwd {
                    self.builds.push(cwd.clone());
                    self.builds.extend(
                        words[1..]
                            .iter()
                            .filter(|word| !word.starts_with('-') && word.contains('/'))
                            .map(|word| {
                                world.canonical(&if word.starts_with('/') {
                                    (*word).to_owned()
                                } else {
                                    format!("{cwd}/{word}")
                                })
                            }),
                    );
                }
            }
        }
    }

    /// `crontab FILE` and `launchctl load|bootstrap ... PLIST` install entries
    /// that run their programs later, outside any hooked call. The engine
    /// reads neither file's command lines, so their absolute paths are read
    /// here, from what the source holds when the scheduler reads it: this
    /// call's last earlier write, else the file on disk.
    fn add_scheduled_launches(&mut self, plan: &Plan, node: &ExecutionNode, world: &dyn World) {
        let argv: Vec<&str> = node.argv.iter().filter_map(literal).collect();
        let Some(program) = argv.first().map(|program| base_name(program)) else {
            return;
        };
        let file = match program {
            "crontab" => argv[1..]
                .iter()
                .find(|arg| !arg.starts_with('-'))
                .copied()
                .filter(|_| !argv.iter().any(|arg| matches!(*arg, "-l" | "-r" | "-e"))),
            "launchctl"
                if argv
                    .get(1)
                    .is_some_and(|verb| matches!(*verb, "load" | "bootstrap")) =>
            {
                argv.last().copied().filter(|arg| arg.ends_with(".plist"))
            }
            _ => None,
        };
        let Some(file) = file else {
            return;
        };
        let cwd = node.cwd.as_ref().and_then(concrete_path).unwrap_or("/");
        let file = world.canonical(&if file.starts_with('/') {
            file.to_owned()
        } else {
            format!("{cwd}/{file}")
        });
        let node_index = plan
            .execution_graph
            .nodes
            .iter()
            .position(|candidate| std::ptr::eq(candidate, node))
            .unwrap_or(usize::MAX);
        let installed_at = plan
            .effects
            .iter()
            .position(|effect| effect.execution.0 as usize == node_index)
            .unwrap_or(usize::MAX);
        let content = self
            .writes
            .iter()
            .rev()
            .find(|write| write.path == file && write.at < installed_at)
            .map(|write| write.content.clone())
            .or_else(|| world.text(&file).ok());
        let Some(content) = content else {
            return;
        };
        // The entry runs whatever the file holds when it fires, so every
        // path it names is pending, present or not.
        for path in scheduled_paths(&content, program == "crontab") {
            let path = world.canonical(&path);
            self.launches.push((path.clone(), program.to_owned(), true));
            self.programs.push(Program {
                digest: world.digest(&path),
                path: Some(path),
                argv: Vec::new(),
            });
            self.runs_code = true;
        }
    }

    /// Whether the call reads, writes, runs or sends anything a rule reads
    /// the ledger for.
    pub(super) fn needs_ledger(&self) -> bool {
        self.runs_code
            || self.sends
            || !self.touches.is_empty()
            || !self.staging.is_empty()
            || !self.launches.is_empty()
    }
}

/// The folder or glob a read takes the content of every selected file from;
/// `None` for a read of one file, a listing, or a search that prints only
/// names or counts.
fn selection(
    index: usize,
    effect: &nah_proto::effinterp_proto::Effect,
    world: &dyn World,
) -> Option<Selection> {
    let attribute = |name: &str| effect.attributes.get(name);
    let flag = |name: &str| attribute(name) == Some(&AttrValue::Bool(true));
    let names_only = matches!(
        attribute("output_mode"),
        Some(AttrValue::String(mode)) if mode != "content"
    );
    if flag("metadata") || names_only {
        return None;
    }
    let what = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if flag("recursive") => Selected::Below(world.canonical(path)),
        ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob, narrowing },
        } => Selected::Glob(glob.clone(), narrowing.clone()),
        _ => return None,
    };
    let search_globs = match attribute("search_globs") {
        Some(AttrValue::List(globs)) => globs
            .iter()
            .filter_map(|glob| match glob {
                AttrValue::String(glob) => Some(glob.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some(Selection {
        effect: index,
        what,
        search_globs,
        hidden_skipped: flag("hidden_entries_skipped"),
        ignores_honoured: flag("ignore_files_honoured"),
    })
}

/// `git add` (or `git stage`) staging files, or `git commit` (an amend too)
/// committing them.
fn staging(plan: &Plan, index: usize, world: &dyn World) -> Option<Staging> {
    let effect = &plan.effects[index];
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let worktree = world.canonical(concrete_path(worktree)?);
    let node = plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)?;
    // A word Nah cannot read is `None`.
    let words: Vec<Option<&str>> = node.argv.iter().map(literal).collect();
    let subcommand = words
        .iter()
        .position(|word| matches!(word, Some("add" | "stage" | "commit")))?;
    let commit = words[subcommand] == Some("commit");
    if commit
        != matches!(
            effect.operation.as_str(),
            "git.ref_update" | "git.history_rewrite"
        )
    {
        return None;
    }
    let options = &words[subcommand + 1..];
    if !commit {
        let reads: Vec<String> = plan
            .effects
            .iter()
            .filter(|read| {
                read.execution == effect.execution && read.operation.as_str() == "filesystem.read"
            })
            .filter_map(|read| concrete_path(&read.resource))
            .map(|path| world.canonical(path))
            .collect();
        let forced = options
            .iter()
            .take_while(|word| **word != Some("--"))
            .flatten()
            .any(|word| {
                word.strip_prefix("--")
                    .map_or(word.starts_with('-') && word.contains('f'), |long| {
                        !long.is_empty() && "force".starts_with(long)
                    })
            });
        return Some(Staging {
            worktree,
            unnamed: reads.is_empty(),
            paths: reads,
            commit: false,
            forced,
        });
    }
    // Pathspecs are relative to where git runs: the call's folder, moved by
    // each `-C` before the subcommand.
    let mut base = node
        .cwd
        .as_ref()
        .and_then(concrete_path)
        .map_or_else(|| worktree.clone(), str::to_owned);
    for pair in words[..subcommand].windows(2) {
        if let [Some("-C"), Some(folder)] = pair {
            base = if folder.starts_with('/') {
                (*folder).to_owned()
            } else {
                format!("{base}/{folder}")
            };
        }
    }
    let (pathspecs, all) = commit_selection(options)?;
    let unnamed = all
        || pathspecs.iter().any(|spec| {
            spec.is_none_or(|spec| spec.starts_with(':') || spec.contains(['*', '?', '[']))
        });
    Some(Staging {
        worktree,
        paths: pathspecs
            .into_iter()
            .flatten()
            .map(|spec| {
                world.canonical(&if spec.starts_with('/') {
                    spec.to_owned()
                } else {
                    format!("{base}/{spec}")
                })
            })
            .collect(),
        unnamed,
        commit: true,
        forced: false,
    })
}

/// A commit's pathspecs, `None` where Nah cannot read one, and whether it
/// takes every tracked change (`-a`, `--patch`, `--interactive`). `None` for
/// a dry run, which commits nothing.
fn commit_selection<'a>(words: &[Option<&'a str>]) -> Option<(Vec<Option<&'a str>>, bool)> {
    // Long options whose value is the next word unless attached with `=`.
    const VALUED: &[&str] = &[
        "message",
        "file",
        "reuse-message",
        "reedit-message",
        "fixup",
        "squash",
        "author",
        "date",
        "template",
        "cleanup",
        "trailer",
        "pathspec-from-file",
    ];
    let (mut pathspecs, mut all) = (Vec::new(), false);
    let mut words = words.iter().copied();
    let mut options = true;
    while let Some(word) = words.next() {
        let Some(text) = word.filter(|text| options && text.starts_with('-') && *text != "-")
        else {
            pathspecs.push(word);
            continue;
        };
        if text == "--" {
            options = false;
        } else if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            match name {
                "all" | "patch" | "interactive" => all = true,
                "dry-run" => return None,
                // The paths are in a file Nah does not read.
                "pathspec-from-file" => pathspecs.push(None),
                _ => {}
            }
            if VALUED.contains(&name) && !attached {
                words.next();
            }
        } else {
            // In a cluster like `-am MSG` or `-CHEAD`, a letter that takes a
            // value takes the rest of the word, else the next word.
            let letters = &text[1..];
            for (at, letter) in letters.char_indices() {
                match letter {
                    'a' | 'p' => all = true,
                    'm' | 'F' | 'C' | 'c' | 't' => {
                        if at + 1 == letters.len() {
                            words.next();
                        }
                        break;
                    }
                    // A value that is only ever attached.
                    'u' | 'S' => break,
                    _ => {}
                }
            }
        }
    }
    Some((pathspecs, all))
}

/// Whether a shell command can leave something it launches running after
/// the call returns: a background `&`, `nohup`, `setsid`, `disown`, or a
/// detached multiplexer.
fn leaves_running(command: &str) -> bool {
    let bytes = command.as_bytes();
    let mut quote = None;
    for (index, byte) in bytes.iter().enumerate() {
        match (quote, byte) {
            (Some(open), _) if *byte == open => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(*byte),
            (None, b'&') => {
                let before = index.checked_sub(1).map(|at| bytes[at]);
                let after = bytes.get(index + 1);
                if !matches!(before, Some(b'&' | b'>' | b'<'))
                    && !matches!(after, Some(b'&' | b'>'))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    command
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .any(|word| matches!(word, "nohup" | "setsid" | "disown" | "daemonize"))
        || command.contains("tmux new") && command.contains("-d")
        || command.contains("screen -d")
}

/// Absolute paths in a crontab's command fields or a plist's strings.
fn scheduled_paths(content: &str, crontab: bool) -> Vec<String> {
    let words: Vec<&str> = if crontab {
        content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| {
                let first = line.split_whitespace().next().unwrap_or_default();
                !first.contains('=')
            })
            .flat_map(|line| {
                let skip = if line.starts_with('@') { 1 } else { 5 };
                line.split_whitespace().skip(skip)
            })
            .collect()
    } else {
        content
            .split("<string>")
            .skip(1)
            .filter_map(|rest| rest.split("</string>").next())
            .collect()
    };
    words
        .into_iter()
        .map(|word| word.trim_matches(['"', '\'', ';']))
        .filter(|word| word.starts_with('/') && word.len() > 1)
        .map(str::to_owned)
        .collect()
}

/// The content a write leaves at `path`: the plan's resulting content, or
/// the written bytes, after what an earlier write of this call left there
/// (`earlier`) or else what is on disk when the write appends. `None` when
/// the plan does not state it.
fn resulting_content(
    attributes: &BTreeMap<String, AttrValue>,
    path: &str,
    earlier: Option<&Option<String>>,
    world: &dyn World,
) -> Option<String> {
    let text = |name: &str| match attributes.get(name) {
        Some(AttrValue::String(value)) => Some(value.clone()),
        _ => None,
    };
    if let Some(content) = text("resulting_content") {
        return Some(content);
    }
    let written = text("written_content")?;
    if !matches!(attributes.get("append"), Some(AttrValue::Bool(true))) {
        return Some(written);
    }
    let existing = match earlier {
        Some(earlier) => earlier.clone()?,
        None => match world.text(path) {
            Ok(existing) => existing,
            Err(std::io::ErrorKind::NotFound) => String::new(),
            Err(_) => return None,
        },
    };
    Some(existing + &written)
}

/// How the block record names a resource other than a file: a host, a
/// repository, an environment variable or credential store (never its
/// value), or a pattern.
fn resource_name(resource: &ResourceExpr, world: &dyn World) -> Option<String> {
    match resource {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::NetworkEndpoint { host, .. } => Some(host.clone()),
            ResourceIdentity::EnvironmentVariable { name } => Some(format!("env:{name}")),
            ResourceIdentity::GitRepository {
                worktree, git_dir, ..
            } => worktree
                .as_deref()
                .or(git_dir.as_deref())
                .and_then(concrete_path)
                .map(|path| format!("git:{}", world.canonical(path))),
            ResourceIdentity::CredentialStore {
                provider, store, ..
            } => Some(match store {
                Some(store) => format!("credential:{provider}/{store}"),
                None => format!("credential:{provider}"),
            }),
            _ => None,
        },
        ResourceExpr::Pattern { pattern } => Some(pattern.to_string()),
        _ => None,
    }
}

/// The variable an environment read can disclose a credential through: `*`
/// for every variable, or a name that says it holds one.
fn secret_environment(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        } => {
            let upper = name.to_ascii_uppercase();
            ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL"]
                .iter()
                .any(|word| upper.contains(word))
                .then(|| name.clone())
        }
        ResourceExpr::Pattern { .. } => Some("*".into()),
        _ => None,
    }
}

/// The folder above a filesystem pattern's first wildcard.
fn pattern_folder(resource: &ResourceExpr) -> Option<String> {
    let ResourceExpr::Pattern { pattern } = resource else {
        return None;
    };
    let glob = serde_json::to_value(pattern)
        .ok()?
        .get("glob")?
        .as_str()?
        .to_owned();
    let fixed = &glob[..glob.find(['*', '?', '[']).unwrap_or(glob.len())];
    let folder = fixed.trim_end_matches('/');
    (folder.starts_with('/') && folder.len() > 1).then(|| folder.to_owned())
}

pub(super) fn concrete_path(resource: &ResourceExpr) -> Option<&str> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn literal(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Literal { value } => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::leaves_running;

    #[test]
    fn a_launch_left_running_is_told_apart_from_sequencing_and_redirection() {
        assert!(leaves_running("(sleep 30; sh later.sh) &"));
        assert!(leaves_running("nohup ./serve.sh > log 2>&1"));
        assert!(!leaves_running("make test && make lint"));
        assert!(!leaves_running("sh run.sh > out.log 2>&1"));
        assert!(!leaves_running("echo 'a & b'"));
    }
}
