//! Deletion operands and File::Find callbacks that delete each visited entry.

use super::{
    MAX_NESTING, PerlCompiler, PerlFailure, PerlImports, PerlPendingEffect, PerlPendingStep,
    PerlToken, matching_brace, perl_literal_text, split_at_lowest_operator,
};
use crate::lang::perl::token_shapes::{call_end, split_list_items};

fn tree_removal(name: &str, imports: &PerlImports) -> bool {
    matches!(
        name,
        "remove_tree" | "rmtree" | "File::Path::remove_tree" | "File::Path::rmtree"
    ) && imports.owns(name)
}

/// Strip only a complete call's parentheses. A suffix belongs to the enclosing
/// statement compiler, which checks whether it can affect the call.
fn arguments(tokens: &[PerlToken]) -> Option<&[PerlToken]> {
    if tokens.get(1) == Some(&PerlToken::Punct('(')) {
        (call_end(tokens) == Some(tokens.len())).then(|| &tokens[2..tokens.len() - 1])
    } else {
        Some(&tokens[1..])
    }
}

/// No predicates, rebinding or unknown calls may narrow the visited entries.
/// An `unlink ... or rmdir ...` chain still tries deletion on every entry.
fn deletes_entry(tokens: &[PerlToken], imports: &PerlImports, depth: u32) -> bool {
    if depth >= MAX_NESTING {
        return false;
    }
    if let Some((left, operator, right)) = split_at_lowest_operator(tokens) {
        return matches!(operator, "or" | "||")
            && deletes_entry(left, imports, depth + 1)
            && deletes_entry(right, imports, depth + 1);
    }
    let Some(PerlToken::Name(name)) = tokens.first() else {
        return false;
    };
    let builtin = matches!(name.as_str(), "unlink" | "rmdir");
    if !builtin && !tree_removal(name, imports) {
        return false;
    }
    let Some(args) = arguments(tokens) else {
        return false;
    };
    (builtin && args.is_empty())
        || matches!(args, [PerlToken::Variable(name)] if matches!(name.as_str(), "_" | "File::Find::name"))
}

impl PerlCompiler<'_, '_> {
    pub(super) fn file_deletion(
        &mut self,
        statement: &[PerlToken],
    ) -> Option<Result<(), PerlFailure>> {
        let PerlToken::Name(name) = statement.first()? else {
            return None;
        };
        let walk = matches!(
            name.as_str(),
            "find" | "finddepth" | "File::Find::find" | "File::Find::finddepth"
        ) && self.imports.owns(name);
        let recursive = walk || tree_removal(name, &self.imports);
        if !recursive && !matches!(name.as_str(), "unlink" | "rmdir") {
            return None;
        }
        let args = arguments(statement)?;
        Some(self.delete_arguments(name, args, walk, recursive))
    }

    fn delete_arguments(
        &mut self,
        name: &str,
        mut args: &[PerlToken],
        walk: bool,
        recursive: bool,
    ) -> Result<(), PerlFailure> {
        if walk {
            let [PerlToken::Name(sub), PerlToken::Punct('{'), ..] = args else {
                return Err("Perl File::Find callback is not a modeled anonymous sub".into());
            };
            if sub != "sub" {
                return Err("Perl File::Find callback is not a modeled anonymous sub".into());
            }
            let close = 1 + matching_brace(&args[1..])?;
            let body = args[2..close]
                .strip_suffix(&[PerlToken::Punct(';')])
                .unwrap_or(&args[2..close]);
            if body.is_empty()
                || !body
                    .split(|token| *token == PerlToken::Punct(';'))
                    .all(|statement| deletes_entry(statement, &self.imports, 0))
            {
                return Err("Perl File::Find callback does not delete each visited entry".into());
            }
            args = args[close + 1..]
                .strip_prefix(&[PerlToken::Punct(',')])
                .ok_or("Perl File::Find call lacks roots")?;
        }
        let operands = split_list_items(args);
        if operands.is_empty() || (name == "rmdir" && operands.len() != 1) {
            return Err("Perl deletion call lacks a modeled path list".into());
        }
        // An unknown argument may prevent the entire call. Publish only after
        // every root or operand has been established.
        let mut effects = Vec::new();
        for operand in operands {
            let (path, glob) = self.deletion_path(operand)?;
            let mut effect = PerlPendingEffect::new("filesystem.delete", path);
            effect.recursive = recursive;
            effect.glob = glob;
            effects.push(PerlPendingStep::Effect(effect));
        }
        self.pending.extend(effects);
        Ok(())
    }

    fn deletion_path(&mut self, tokens: &[PerlToken]) -> Result<(String, bool), PerlFailure> {
        let glob = matches!(tokens.first(), Some(PerlToken::Name(name)) if name == "glob");
        let operand = if glob {
            arguments(tokens).ok_or("Perl glob has an unmodeled argument shape")?
        } else {
            tokens
        };
        let mut path = perl_literal_text(operand, &self.variables, self.budget)?;
        if glob {
            // Perl's glob also splits words, expands braces and interprets
            // quoting. Those forms need their own expansion, not a literal path.
            if path.contains(char::is_whitespace) || path.contains(['{', '}', '\\', '\'', '"']) {
                return Err("Perl glob word splitting, braces or quoting is not modeled".into());
            }
            if let Some(tail) = path.strip_prefix('~') {
                if !tail.is_empty() && !tail.starts_with('/') {
                    return Err("Perl glob of another user's home is not modeled".into());
                }
                let home =
                    (self.env)("HOME").ok_or("Perl environment value \"HOME\" is not supplied")?;
                let bytes = home.len().saturating_add(tail.len());
                if bytes > self.max_bytes {
                    return Err(PerlFailure::SourceBytes);
                }
                if !self.budget.try_charge_bytes(bytes as u64) {
                    return Err(PerlFailure::AnalysisBytes);
                }
                path = format!("{home}{tail}");
            }
        }
        if path.is_empty() || path.contains('\0') {
            return Err("Perl path is empty or contains NUL".into());
        }
        let pattern = glob && path.contains(['*', '?', '[']);
        Ok((path, pattern))
    }
}
