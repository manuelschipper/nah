//! Composes one Bash command through preparation, effect lowering, and commit.

use nah_parse::{Redirect, Substitution, Word};

use super::{CommandContext, Lowered, Lowerer};

impl Lowerer {
    pub(in crate::bash) fn lower_command(
        &mut self,
        name: &str,
        name_substitutions: &[Substitution],
        assignments: &[(String, Word)],
        arguments: &[Word],
        redirects: &[Redirect],
        context: CommandContext<'_>,
    ) -> Lowered {
        let prepared = self.prepare_command(
            name,
            name_substitutions,
            assignments,
            arguments,
            redirects,
            context,
        );
        let analyzed = self.lower_command_effects(prepared);
        self.commit_command(analyzed)
    }
}
