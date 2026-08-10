//! Owns resolved Bash argument and redirect word materialization.

use super::filesystem::exact_redirect_process_substitution;
use nah_parse::{Redirect, Word};

use crate::bash_content::substitution_output;
use crate::bash_model::{ResolvedWord, UnresolvedCause, VariableValue};
use crate::shell_word::{ExpansionContext, materialize_word, resolve_word};

use super::{Lowerer, PositionalExpansion};

impl Lowerer {
    pub(super) fn word_resolution(&self, word: &Word, context: ExpansionContext) -> ResolvedWord {
        let variables = self.visible_variables();
        resolve_word(
            word.raw(),
            word.substitutions(),
            &variables,
            context,
            substitution_output,
        )
    }

    pub(super) fn resolved_arguments(
        &mut self,
        arguments: &[Word],
    ) -> (Vec<Word>, Vec<ResolvedWord>) {
        let mut words = Vec::new();
        let mut resolutions = Vec::new();
        for argument in arguments {
            match self.positional_expansion(argument, &[]) {
                PositionalExpansion::Exact(expanded) => {
                    for value in expanded {
                        let VariableValue::Static(value) = value.value else {
                            unreachable!("exact positional expansion is static");
                        };
                        words.push(Word::from_literal(&value));
                        resolutions.push(ResolvedWord::Static {
                            value,
                            changed: true,
                        });
                    }
                    continue;
                }
                PositionalExpansion::Unresolved => {
                    self.complete = false;
                    words.push(argument.clone());
                    resolutions.push(ResolvedWord::Unresolved {
                        literal_prefix: String::new(),
                        may_be_absolute: true,
                        cause: if matches!(argument.raw(), "$@" | "${@}") {
                            UnresolvedCause::ShellTransformation
                        } else {
                            UnresolvedCause::UnknownValue
                        },
                    });
                    continue;
                }
                PositionalExpansion::NotPositional => {}
            }
            let resolved = self.word_resolution(argument, ExpansionContext::ShellWord);
            if !resolved.is_complete() {
                self.complete = false;
            }
            if let Some(word) = materialize_word(argument, &resolved) {
                words.push(word);
                resolutions.push(resolved);
            }
        }
        (words, resolutions)
    }

    pub(super) fn resolved_redirects(&mut self, redirects: &[Redirect]) -> Vec<Redirect> {
        redirects
            .iter()
            .map(|redirect| {
                let Some(raw) = redirect.target() else {
                    return redirect.clone();
                };
                let exact_process_substitution =
                    exact_redirect_process_substitution(redirect).is_some();
                let variables = self.visible_variables();
                let resolved = resolve_word(
                    raw,
                    redirect.target_substitutions(),
                    &variables,
                    ExpansionContext::ShellWord,
                    substitution_output,
                );
                if !resolved.is_complete() && !exact_process_substitution {
                    self.complete = false;
                }
                if exact_process_substitution {
                    return redirect.clone();
                }
                match resolved {
                    ResolvedWord::Static {
                        value,
                        changed: true,
                    } => redirect
                        .clone()
                        .with_target_word(Word::from_literal(&value)),
                    ResolvedWord::Pattern {
                        value,
                        changed: true,
                    } => redirect
                        .clone()
                        .with_target_word(Word::from_expanded_pattern(&value)),
                    ResolvedWord::Absent
                    | ResolvedWord::Static { changed: false, .. }
                    | ResolvedWord::Pattern { changed: false, .. }
                    | ResolvedWord::Unresolved { .. } => redirect.clone(),
                }
            })
            .collect()
    }

    pub(super) fn resolve_local_argument(&self, argument: &Word) -> Word {
        let resolved = self.word_resolution(argument, ExpansionContext::ShellWord);
        materialize_word(argument, &resolved).unwrap_or_else(|| Word::from_literal(""))
    }
}
