//! For-list iterations: when a `for` loop's body can be walked once per
//! member of a fixed list instead of once under an unknown binding. That needs
//! a body that reaches its end on every iteration.

use crate::builder::PlanBuilder;

use super::eval::variable_binding::bind_for_var;
use super::lex::Seg;
use super::parse::ShellItem;
use super::shell_env::ShellEnv;
use super::{Shell, Termination, parse};

/// Whether a loop body reaches its end on every iteration. `break`,
/// `continue`, `return` and `exit` each leave part of the body reached only
/// on some paths, and a construct this frontend does not walk could hold one,
/// so only a body free of all of them turns a fixed iteration list into a
/// fixed sequence of unconditional iterations.
pub(super) fn body_runs_every_iteration(items: &[ShellItem]) -> bool {
    items.iter().all(|item| match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().all(|cmd| {
            !cmd.words
                .first()
                .and_then(parse::literal_text)
                .is_some_and(|name| {
                    matches!(name.as_str(), "break" | "continue" | "return" | "exit")
                })
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            body_runs_every_iteration(items)
        }
        ShellItem::Alternatives { arms, .. } => {
            arms.iter().all(|arm| body_runs_every_iteration(arm))
        }
        ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => true,
        ShellItem::Unsupported { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    })
}

/// Whether a loop body runs `ssh` or `scp`, read off a literal command head.
/// A loop with such a remote command in its body is not walked once per
/// member: it keeps the single walk under an unknown binding.
pub(super) fn body_has_remote_command(items: &[ShellItem]) -> bool {
    items.iter().any(|item| match item {
        ShellItem::Pipeline { cmds, .. } => cmds.iter().any(|cmd| {
            cmd.words
                .first()
                .and_then(parse::literal_text)
                .is_some_and(|head| matches!(head.as_str(), "ssh" | "scp"))
        }),
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => {
            body_has_remote_command(items)
        }
        ShellItem::Alternatives { arms, .. } => arms.iter().any(|arm| body_has_remote_command(arm)),
        ShellItem::Function { .. } | ShellItem::UnboundedSpawn { .. } => false,
        ShellItem::Unsupported { .. }
        | ShellItem::UnwalkedExpansion { .. }
        | ShellItem::ParseError { .. } => false,
    })
}

impl Shell<'_> {
    /// A `for` over `"$@"` or `"${ARRAY[@]}"` with known members walks its
    /// body once per member, bound to it; `None` when the loop is not of that
    /// form. Kept out of line: `walk_items` recurses once per nested group, so
    /// its frame size bounds nesting.
    #[inline(never)]
    pub(super) fn walk_for_members(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        item: &ShellItem,
        force_conditional: bool,
        walk_depth: u32,
        hazard_depth: Option<crate::builder::HazardDepth>,
    ) -> Option<Option<(Termination, u32)>> {
        let ShellItem::For {
            var: Some((name, span)),
            values: Some(values),
            items,
            ..
        } = item
        else {
            return None;
        };
        let members = match values.as_slice() {
            [value] => match value.segs.as_slice() {
                [Seg::AllArgs { quoted: true }] => env.positional.clone(),
                [
                    Seg::ArrayAll {
                        name: array,
                        quoted: true,
                    },
                ] => env
                    .arrays
                    .get(array)
                    .and_then(|array| match array.candidates() {
                        [members] => Some(members.clone()),
                        _ => None,
                    }),
                _ => None,
            },
            _ => None,
        }?;
        if members.is_empty() || !body_runs_every_iteration(items) || body_has_remote_command(items)
        {
            return None;
        }
        for (iteration, member) in members.into_iter().enumerate() {
            bind_for_var(
                builder,
                env,
                name.clone(),
                Some(member.word),
                *span,
                member.producers,
            );
            let instance = self.enter_loop_iteration(builder, items, iteration as u32);
            let termination = self.walk(builder, env, items, force_conditional, walk_depth + 1);
            if let Some(previous) = instance {
                builder.leave_condition_call(previous);
            }
            if let Some(depth) = hazard_depth {
                builder.truncate_source_hazards(depth);
            }
            if termination.is_some() {
                return Some(termination);
            }
        }
        Some(None)
    }
}
