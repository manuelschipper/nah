use effinterp_proto::{ResourceExpr, ResourceIdentity, Subject};

use crate::nest::{Transition, word_resource};
use crate::word::{Word, WordPart};

use super::super::model::{RubyModeledSend, effect, exe};
use super::super::spawn_resources::ruby_spawn_command_text;
use super::RubyWalker;

fn ruby_resource_to_word(expr: &ResourceExpr) -> Word {
    match expr {
        ResourceExpr::Literal { value } => Word::literal(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Word::literal(path.clone()),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

fn resource_leading_text(expr: &ResourceExpr) -> Option<String> {
    ruby_spawn_command_text(expr)?
        .split_whitespace()
        .next()
        .filter(|word| !word.is_empty())
        .map(str::to_string)
}

fn resource_cwd_path(cwd: &Option<ResourceExpr>) -> Option<String> {
    cwd.as_ref().and_then(ruby_spawn_command_text)
}

impl RubyWalker<'_> {
    /// A nested spawn at execution level: literal commands nest a full
    /// sub-analysis; a dynamic command is a process.exec on an unresolved (or
    /// name-only) executable.
    pub(super) fn spawn_guarded(
        &mut self,
        spawn: RubyModeledSend,
        mut condition: Option<effinterp_proto::Condition>,
        begin: usize,
        end: usize,
    ) {
        if let Some(guard) = &mut condition {
            guard.rebind(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(&self.ctx.source_digest, begin, end),
            ));
            self.builder.push_condition(guard.clone());
        }
        self.spawned(spawn, begin, end, false);
        if condition.is_some() {
            self.builder.pop_condition();
        }
    }

    /// `captured` spawns return their stdout to the program as a value, as
    /// backticks do, so it does not reach the program's own stdout.
    pub(super) fn spawned(&mut self, m: RubyModeledSend, begin: usize, end: usize, captured: bool) {
        let stdout = match &m {
            RubyModeledSend::ShellSpawn { stdout, .. }
            | RubyModeledSend::ExecSpawn { stdout, .. } => stdout.clone(),
            _ => None,
        };
        let child = self.builder.next_execution();
        let inherited_stdout = self.builder.inherited_execution_streams().stdout;
        let captured_streams =
            (captured || stdout.is_some()).then(|| effinterp_proto::ExecutionStreams {
                stdout: None,
                ..self.builder.inherited_execution_streams()
            });
        let capture = |transition: Transition| match captured_streams.clone() {
            Some(streams) => transition.streams(streams),
            None => transition,
        };
        match m {
            RubyModeledSend::ShellSpawn { source, cwd, .. } => {
                let node = self.span(begin, end);
                let cwd_path = resource_cwd_path(&cwd).or_else(|| self.cwd.map(str::to_string));
                match ruby_spawn_command_text(&source) {
                    Some(cmd) => {
                        let source_cwd = self.nest.current_source_cwd();
                        {
                            let subject = Subject::Shell {
                                source: cmd,
                                cwd: cwd_path,
                                context: Default::default(),
                            };
                            let runtime_cwd =
                                crate::nest::subject_cwd(&subject).map(str::to_string);
                            self.nest.nest(
                                self.builder,
                                capture(
                                    Transition::file(subject)
                                        .source_cwd(source_cwd.as_deref())
                                        .runtime_cwd(runtime_cwd.as_deref())
                                        .cwd(cwd, None),
                                ),
                                &[node],
                                self.depth,
                            );
                        };
                    }
                    None => {
                        if let Some(exe_name) = resource_leading_text(&source) {
                            {
                                let words: &[Word] = &[Word::literal(exe_name)];
                                self.nest.nest(
                                    self.builder,
                                    capture(
                                        Transition::exec(
                                            words.iter().map(word_resource).collect(),
                                            words.to_vec(),
                                        )
                                        .exec_cwd(cwd_path.as_deref().or(self.cwd))
                                        .cwd(
                                            self.builder.current_execution_cwd(),
                                            (self.nest.current_runtime_cwd().as_deref()
                                                == cwd_path.as_deref().or(self.cwd))
                                            .then(|| self.nest.current_cwd_node())
                                            .flatten(),
                                        )
                                        .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                                    ),
                                    &[node],
                                    self.depth,
                                )
                            };
                        } else {
                            self.emit(effect("process.exec", exe(None), false), begin, end);
                        }
                    }
                }
            }
            RubyModeledSend::ExecSpawn { argv, cwd, .. } => {
                let node = self.span(begin, end);
                let words: Vec<Word> = argv
                    .iter()
                    .map(|argument| {
                        if self.builder.current_execution_argv().is_empty() {
                            ruby_resource_to_word(argument)
                        } else {
                            crate::nest::argument_word(argument)
                        }
                    })
                    .collect();
                let cwd_path = resource_cwd_path(&cwd);
                self.nest.nest(
                    self.builder,
                    capture(
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .exec_cwd(cwd_path.as_deref().or(self.cwd))
                            .cwd(
                                self.builder.current_execution_cwd(),
                                (self.nest.current_runtime_cwd().as_deref()
                                    == cwd_path.as_deref().or(self.cwd))
                                .then(|| self.nest.current_cwd_node())
                                .flatten(),
                            )
                            .runtime_cwd(self.nest.current_runtime_cwd().as_deref()),
                    ),
                    &[node],
                    self.depth,
                );
            }
            RubyModeledSend::SpawnUnresolved(argv0) => {
                self.emit(
                    effect("process.exec", exe(argv0.as_deref()), false),
                    begin,
                    end,
                );
            }
            _ => {}
        }
        if captured && child != self.builder.next_execution() {
            self.captured_outputs
                .insert((begin, end), (child, inherited_stdout));
        }
        // `out:` opens the file and hands it to the child as its stdout.
        if let Some(path) = stdout
            && child != self.builder.next_execution()
        {
            self.builder.push_execution(child);
            let write = self.emit(effect("filesystem.write", path, false), begin, end);
            self.builder.pop_execution();
            let Some(write) = write else { return };
            let node = self.span(begin, end);
            self.builder.flow_stage(crate::flow::FlowStage {
                execution: Some(child),
                effects: vec![write],
                bindings: vec![crate::flow::PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: crate::flow::BindEnd::Port(effinterp_proto::Port::Stdout),
                    to: crate::flow::BindEnd::Effect(write),
                }],
                provenance: vec![node],
            });
        }
    }
}
