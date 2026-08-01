//! Lowers shell words and connects their substitution provenance to command stages.

use nah_parse::{Substitution, Word};

use crate::shell_word::referenced_env_names;

use super::{Lowered, Lowerer};

impl Lowerer {
    pub(super) fn lower_words(&mut self, words: &[Word]) -> Lowered {
        self.refuse_parameter_assignment_words(words.iter().map(Word::raw));
        let mut lowered = Lowered::default();
        for word in words {
            let (word, _) = self.lower_word_with_origins(word);
            lowered.extend(word);
        }
        lowered
    }

    pub(super) fn lower_word_with_origins(&mut self, word: &Word) -> (Lowered, Vec<usize>) {
        for name in referenced_env_names(word.raw()) {
            self.prepare_variable_reference(&name);
        }
        let mut origins = self.variable_origins(word.raw());
        let mut lowered = Lowered::default();
        for substitution in word.substitutions() {
            let state = self.state.clone();
            let nested = self.lower_statements(substitution.statements());
            self.state = state;
            if matches!(
                substitution,
                Substitution::Command { .. } | Substitution::Backtick { .. }
            ) {
                origins.extend(nested.outputs.iter().copied());
            }
            lowered.extend(nested);
        }
        (lowered, self.bounded_origins(origins))
    }

    pub(super) fn connect_command_substitution_flows(
        &mut self,
        stage: usize,
        substitutions: &[(&Substitution, Lowered)],
    ) {
        for (substitution, nested) in substitutions {
            if nested.stages.is_empty() {
                self.complete = false;
                continue;
            }
            match substitution {
                Substitution::ProcessOutput { .. } => {
                    for input in &nested.inputs {
                        self.flows.push((stage, *input));
                    }
                }
                Substitution::Command { .. }
                | Substitution::Backtick { .. }
                | Substitution::ProcessInput { .. } => {
                    for output in &nested.outputs {
                        self.flows.push((*output, stage));
                    }
                }
            }
        }
    }
}
