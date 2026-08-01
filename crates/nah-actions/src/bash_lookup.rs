//! Tracks exact, same-call Bash command lookup mutations; it performs no I/O.

use std::collections::BTreeSet;

const MAX_BINDINGS: usize = 256;
const MAX_VARIANTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Certainty {
    No,
    Yes,
    Maybe,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NamedValues<T> {
    name: String,
    values: Vec<T>,
    absent: bool,
    unknown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LookupState {
    expand_aliases: Certainty,
    aliases: Vec<NamedValues<String>>,
    aliases_unknown: bool,
    hashes: Vec<NamedValues<String>>,
    hashes_unknown: bool,
    hashall: Certainty,
    builtins: Vec<NamedValues<bool>>,
    builtins_unknown: bool,
}

impl Default for LookupState {
    fn default() -> Self {
        Self {
            expand_aliases: Certainty::No,
            aliases: Vec::new(),
            aliases_unknown: false,
            hashes: Vec::new(),
            hashes_unknown: false,
            hashall: Certainty::Yes,
            builtins: Vec::new(),
            builtins_unknown: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AliasSnapshot {
    expand_aliases: Certainty,
    aliases: Vec<NamedValues<String>>,
    aliases_unknown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AliasResolution {
    pub(crate) replacements: Vec<String>,
    pub(crate) unexpanded: bool,
    pub(crate) variants_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Update {
    Exact,
    Partial,
    Refused,
}

impl Update {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Refused, _) | (_, Self::Refused) => Self::Refused,
            (Self::Partial, _) | (_, Self::Partial) => Self::Partial,
            (Self::Exact, Self::Exact) => Self::Exact,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FunctionPresence {
    Absent,
    Present,
    Possible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LookupMode {
    Normal,
    Command,
    CommandDefaultPath,
    BuiltinOnly,
    External,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LookupTarget {
    Function,
    Builtin,
    Hashed(String),
    Path(String),
    DirectPath(String),
    MissingBuiltin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeResolution {
    pub(crate) targets: Vec<LookupTarget>,
    // A PATH target is a complete lexical candidate. This is false only when
    // a visible lookup mutation may have introduced an unlisted target.
    pub(crate) variants_complete: bool,
    pub(crate) command_not_found_possible: bool,
}

impl LookupState {
    pub(crate) fn merge(states: &[Self]) -> Result<Self, ()> {
        let Some(first) = states.first() else {
            return Err(());
        };
        let expand_aliases = if states
            .iter()
            .all(|state| state.expand_aliases == first.expand_aliases)
        {
            first.expand_aliases
        } else {
            Certainty::Maybe
        };
        let hashall = if states.iter().all(|state| state.hashall == first.hashall) {
            first.hashall
        } else {
            Certainty::Maybe
        };
        Ok(Self {
            expand_aliases,
            aliases: merge_named(states.iter().map(|state| state.aliases.as_slice()))?,
            aliases_unknown: states.iter().any(|state| state.aliases_unknown),
            hashes: merge_named(states.iter().map(|state| state.hashes.as_slice()))?,
            hashes_unknown: states.iter().any(|state| state.hashes_unknown),
            hashall,
            builtins: merge_builtins(states)?,
            builtins_unknown: states.iter().any(|state| state.builtins_unknown),
        })
    }

    pub(crate) fn alias_snapshot(&self) -> AliasSnapshot {
        AliasSnapshot {
            expand_aliases: self.expand_aliases,
            aliases: self.aliases.clone(),
            aliases_unknown: self.aliases_unknown,
        }
    }

    pub(crate) fn apply_builtin(&mut self, program: &str, arguments: &[String]) -> Update {
        match program {
            "alias" => self.update_aliases(arguments),
            "unalias" => self.update_unaliases(arguments),
            "shopt" => self.update_shopt(arguments),
            "hash" => self.update_hashes(arguments),
            "enable" => self.update_builtins(arguments),
            "set" => self.update_hashall(arguments),
            _ => Update::Exact,
        }
    }

    pub(crate) fn invalidate_builtin(&mut self, program: &str) -> Update {
        match program {
            "alias" => self.aliases_unknown = true,
            "unalias" => {
                for binding in &mut self.aliases {
                    binding.absent = true;
                }
            }
            "hash" if self.hashall == Certainty::No => return Update::Exact,
            "hash" => self.hashes_unknown = true,
            "enable" => self.builtins_unknown = true,
            "shopt" => {
                self.expand_aliases = Certainty::Maybe;
                self.hashall = Certainty::Maybe;
            }
            "set" => self.hashall = Certainty::Maybe,
            _ => return Update::Exact,
        }
        Update::Partial
    }

    pub(crate) fn invalidate_all(&mut self) -> Update {
        self.expand_aliases = Certainty::Maybe;
        self.aliases_unknown = true;
        self.hashes_unknown = true;
        self.hashall = Certainty::Maybe;
        self.builtins_unknown = true;
        Update::Partial
    }

    pub(crate) fn apply_path_change(&mut self, changed: Certainty) -> Update {
        match changed {
            Certainty::No => Update::Exact,
            Certainty::Yes => {
                self.hashes.clear();
                self.hashes_unknown = false;
                Update::Exact
            }
            Certainty::Maybe => {
                for binding in &mut self.hashes {
                    binding.absent = true;
                }
                Update::Partial
            }
        }
    }

    pub(crate) fn resolve(
        &self,
        name: &str,
        mode: LookupMode,
        function: FunctionPresence,
    ) -> RuntimeResolution {
        if name.contains('/') {
            if mode == LookupMode::BuiltinOnly {
                return RuntimeResolution {
                    targets: vec![LookupTarget::MissingBuiltin],
                    variants_complete: true,
                    command_not_found_possible: false,
                };
            }
            return RuntimeResolution {
                targets: vec![LookupTarget::DirectPath(name.to_owned())],
                variants_complete: true,
                command_not_found_possible: false,
            };
        }
        if mode == LookupMode::External {
            return RuntimeResolution {
                targets: vec![LookupTarget::Path(name.to_owned())],
                variants_complete: true,
                command_not_found_possible: false,
            };
        }
        let mut targets = Vec::new();
        let mut variants_complete = true;
        let normal_functions = mode == LookupMode::Normal;
        if normal_functions && function != FunctionPresence::Absent {
            targets.push(LookupTarget::Function);
            if function == FunctionPresence::Present {
                return RuntimeResolution {
                    targets,
                    variants_complete,
                    command_not_found_possible: false,
                };
            }
        }

        let (builtin_enabled, builtin_disabled, builtin_complete) = self.builtin_availability(name);
        variants_complete &= builtin_complete;
        if mode == LookupMode::BuiltinOnly {
            if builtin_enabled {
                targets.push(LookupTarget::Builtin);
            }
            if builtin_disabled || !is_shell_builtin(name) {
                targets.push(LookupTarget::MissingBuiltin);
            }
            finish_resolution(targets, variants_complete)
        } else {
            if builtin_enabled {
                targets.push(LookupTarget::Builtin);
            }
            let external_possible = !is_shell_builtin(name) || builtin_disabled;
            if external_possible {
                if mode == LookupMode::CommandDefaultPath {
                    targets.push(LookupTarget::Path(name.to_owned()));
                } else {
                    self.add_hashed_targets(name, &mut targets, &mut variants_complete);
                }
            }
            finish_resolution(targets, variants_complete)
        }
    }

    fn update_aliases(&mut self, arguments: &[String]) -> Update {
        let mut print_all = false;
        let mut options = true;
        let mut update = Update::Exact;
        let mut definitions = Vec::new();
        for argument in arguments {
            if options && argument == "--" {
                options = false;
                continue;
            }
            if options && argument == "-p" {
                print_all = true;
                continue;
            }
            if options && argument.starts_with('-') {
                return Update::Partial;
            }
            options = false;
            let Some((name, value)) = argument.split_once('=') else {
                continue;
            };
            if !valid_alias_name(name) {
                update = update.combine(Update::Partial);
                continue;
            }
            definitions.push((name, value));
        }
        if print_all {
            return Update::Exact;
        }
        for (name, value) in definitions {
            update = update.combine(set_exact(&mut self.aliases, name, value.to_owned()));
        }
        update
    }

    fn update_unaliases(&mut self, arguments: &[String]) -> Update {
        let mut all = false;
        let mut names = Vec::new();
        let mut options = true;
        for argument in arguments {
            if options && argument == "--" {
                options = false;
            } else if options && argument == "-a" {
                all = true;
            } else if options && argument.starts_with('-') {
                return Update::Partial;
            } else {
                options = false;
                names.push(argument);
            }
        }
        if all {
            self.aliases.clear();
            self.aliases_unknown = false;
        } else {
            self.aliases
                .retain(|binding| !names.contains(&&binding.name));
        }
        Update::Exact
    }

    fn update_shopt(&mut self, arguments: &[String]) -> Update {
        let mut set = false;
        let mut unset = false;
        let mut set_options = false;
        let mut names = Vec::new();
        let mut options = true;
        for argument in arguments {
            if options && argument == "--" {
                options = false;
            } else if options && argument.starts_with('-') {
                for option in argument[1..].chars() {
                    match option {
                        's' => set = true,
                        'u' => unset = true,
                        'o' => set_options = true,
                        'p' | 'q' => {}
                        _ => return Update::Partial,
                    }
                }
            } else {
                options = false;
                names.push(argument.as_str());
            }
        }
        if set == unset {
            return Update::Exact;
        }
        let requested = if set { Certainty::Yes } else { Certainty::No };
        if set_options {
            if names.contains(&"hashall") {
                self.hashall = requested;
            }
        } else if names.contains(&"expand_aliases") {
            self.expand_aliases = requested;
        }
        Update::Exact
    }

    fn update_hashes(&mut self, arguments: &[String]) -> Update {
        match self.hashall {
            Certainty::No => return Update::Exact,
            Certainty::Yes => return self.update_enabled_hashes(arguments),
            Certainty::Maybe => {}
        }

        let before = self.hashes.clone();
        let before_unknown = self.hashes_unknown;
        let update = self.update_enabled_hashes(arguments);
        if update == Update::Refused {
            return update;
        }
        let after = std::mem::take(&mut self.hashes);
        self.hashes = match merge_named([before.as_slice(), after.as_slice()].into_iter()) {
            Ok(hashes) => hashes,
            Err(()) => return Update::Refused,
        };
        self.hashes_unknown |= before_unknown;
        update.combine(Update::Partial)
    }

    fn update_enabled_hashes(&mut self, arguments: &[String]) -> Update {
        let mut reset = false;
        let mut delete = false;
        let mut list = false;
        let mut trace = false;
        let mut pathname = None;
        let mut names = Vec::new();
        let mut options = true;
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            if options && argument == "--" {
                options = false;
            } else if options && argument.len() > 1 && argument.starts_with('-') {
                for (offset, flag) in argument[1..].char_indices() {
                    match flag {
                        'd' => delete = true,
                        'l' => list = true,
                        'r' => reset = true,
                        't' => trace = true,
                        'p' => {
                            let value_start = 1 + offset + flag.len_utf8();
                            if value_start < argument.len() {
                                pathname = Some(argument[value_start..].to_owned());
                            } else {
                                index += 1;
                                let Some(value) = arguments.get(index) else {
                                    return Update::Partial;
                                };
                                pathname = Some(value.clone());
                            }
                            break;
                        }
                        _ => return Update::Partial,
                    }
                }
            } else {
                options = false;
                names.push(argument.clone());
            }
            index += 1;
        }
        if (trace || (delete && pathname.is_none())) && names.is_empty() {
            return Update::Exact;
        }
        if reset {
            self.hashes.clear();
            self.hashes_unknown = false;
        }
        if trace {
            return Update::Exact;
        }
        if let Some(pathname) = pathname {
            return names.into_iter().fold(Update::Exact, |update, name| {
                update.combine(set_exact(&mut self.hashes, &name, pathname.clone()))
            });
        }
        if delete {
            self.hashes.retain(|binding| !names.contains(&binding.name));
            return Update::Exact;
        }
        if list || names.is_empty() {
            return Update::Exact;
        }
        names.into_iter().fold(Update::Exact, |update, name| {
            update.combine(set_unknown(&mut self.hashes, &name))
        })
    }

    fn update_builtins(&mut self, arguments: &[String]) -> Update {
        let mut disable = false;
        let mut print_reusable = false;
        let mut names = Vec::new();
        let mut options = true;
        for argument in arguments {
            if options && argument == "--" {
                options = false;
                continue;
            }
            if options && argument.starts_with('-') {
                if argument[1..].contains(['f', 'd']) {
                    self.builtins_unknown = true;
                    return Update::Refused;
                }
                if !argument[1..]
                    .chars()
                    .all(|option| matches!(option, 'a' | 'n' | 'p' | 's'))
                {
                    self.builtins_unknown = true;
                    return Update::Partial;
                }
                disable |= argument[1..].contains('n');
                print_reusable |= argument[1..].contains('p');
                continue;
            }
            options = false;
            names.push(argument);
        }
        if print_reusable || names.is_empty() {
            return Update::Exact;
        }
        names
            .into_iter()
            .filter(|name| is_shell_builtin(name))
            .fold(Update::Exact, |update, name| {
                update.combine(set_exact(&mut self.builtins, name, !disable))
            })
    }

    fn update_hashall(&mut self, arguments: &[String]) -> Update {
        let original = self.hashall;
        let mut requested = original;
        let mut uncertain = false;
        let mut options = true;
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            if options && argument == "--" {
                options = false;
            } else if options
                && argument.len() > 1
                && matches!(argument.as_bytes().first(), Some(b'-' | b'+'))
            {
                let enabled = argument.starts_with('-');
                let flags = &argument[1..];
                let mut flag_index = 0;
                while flag_index < flags.len() {
                    let flag = flags[flag_index..].chars().next().expect("flag");
                    flag_index += flag.len_utf8();
                    if flag == 'o' {
                        let attached = &flags[flag_index..];
                        let name = if attached.is_empty() {
                            if let Some(name) = arguments.get(index + 1) {
                                index += 1;
                                Some(name.as_str())
                            } else {
                                None
                            }
                        } else {
                            Some(attached)
                        };
                        if let Some(name) = name {
                            if name == "hashall" {
                                requested = certainty(enabled);
                            } else if !is_set_long_option(name) {
                                uncertain = true;
                            }
                        }
                        break;
                    }
                    if flag == 'h' {
                        requested = certainty(enabled);
                    } else if !is_set_short_option(flag) {
                        uncertain = true;
                    }
                }
            } else {
                options = false;
            }
            index += 1;
        }
        if uncertain {
            self.hashall = merge_certainty(original, requested);
            Update::Partial
        } else {
            self.hashall = requested;
            Update::Exact
        }
    }

    fn builtin_availability(&self, name: &str) -> (bool, bool, bool) {
        if !is_shell_builtin(name) {
            return (self.builtins_unknown, true, !self.builtins_unknown);
        }
        let Some(binding) = find(&self.builtins, name) else {
            return (true, self.builtins_unknown, !self.builtins_unknown);
        };
        (
            binding.values.contains(&true),
            binding.values.contains(&false) || binding.absent || self.builtins_unknown,
            !binding.unknown && !self.builtins_unknown,
        )
    }

    fn add_hashed_targets(
        &self,
        name: &str,
        targets: &mut Vec<LookupTarget>,
        variants_complete: &mut bool,
    ) {
        if self.hashall == Certainty::No {
            targets.push(LookupTarget::Path(name.to_owned()));
            return;
        }
        let Some(binding) = find(&self.hashes, name) else {
            targets.push(LookupTarget::Path(name.to_owned()));
            *variants_complete &= !self.hashes_unknown;
            return;
        };
        targets.extend(binding.values.iter().cloned().map(LookupTarget::Hashed));
        if binding.absent
            || binding.unknown
            || self.hashes_unknown
            || self.hashall == Certainty::Maybe
        {
            targets.push(LookupTarget::Path(name.to_owned()));
        }
        *variants_complete &= !binding.unknown && !self.hashes_unknown;
    }
}

impl AliasSnapshot {
    pub(crate) fn resolve(&self, name: &str, eligible: bool) -> AliasResolution {
        if !eligible || self.expand_aliases == Certainty::No {
            return AliasResolution {
                replacements: Vec::new(),
                unexpanded: true,
                variants_complete: true,
            };
        }
        let binding = find(&self.aliases, name);
        let mut replacements = binding
            .map(|binding| binding.values.clone())
            .unwrap_or_default();
        replacements.sort();
        replacements.dedup();
        let maybe_disabled = self.expand_aliases == Certainty::Maybe;
        let unexpanded = maybe_disabled
            || self.aliases_unknown
            || binding.is_none_or(|binding| binding.absent || binding.unknown);
        AliasResolution {
            replacements,
            unexpanded,
            variants_complete: !self.aliases_unknown
                && binding.is_none_or(|binding| !binding.unknown),
        }
    }
}

fn merge_named<'a, T>(
    states: impl Iterator<Item = &'a [NamedValues<T>]>,
) -> Result<Vec<NamedValues<T>>, ()>
where
    T: Clone + Ord + 'a,
{
    let states = states.collect::<Vec<_>>();
    let names = states
        .iter()
        .flat_map(|state| state.iter().map(|binding| binding.name.clone()))
        .collect::<BTreeSet<_>>();
    if names.len() > MAX_BINDINGS {
        return Err(());
    }
    let mut merged = Vec::new();
    for name in names {
        let mut values = Vec::new();
        let mut absent = false;
        let mut unknown = false;
        for state in &states {
            if let Some(binding) = find(state, &name) {
                values.extend(binding.values.iter().cloned());
                absent |= binding.absent;
                unknown |= binding.unknown;
            } else {
                absent = true;
            }
        }
        values.sort();
        values.dedup();
        if values.len() > MAX_VARIANTS {
            return Err(());
        }
        if !values.is_empty() || unknown {
            merged.push(NamedValues {
                name,
                values,
                absent,
                unknown,
            });
        }
    }
    Ok(merged)
}

fn merge_builtins(states: &[LookupState]) -> Result<Vec<NamedValues<bool>>, ()> {
    let names = states
        .iter()
        .flat_map(|state| state.builtins.iter().map(|binding| binding.name.clone()))
        .collect::<BTreeSet<_>>();
    if names.len() > MAX_BINDINGS {
        return Err(());
    }
    let mut merged = Vec::new();
    for name in names {
        let mut values = Vec::new();
        let mut unknown = false;
        for state in states {
            if let Some(binding) = find(&state.builtins, &name) {
                values.extend(binding.values.iter().copied());
                unknown |= binding.unknown;
            } else {
                values.push(true);
            }
        }
        values.sort();
        values.dedup();
        merged.push(NamedValues {
            name,
            values,
            absent: false,
            unknown,
        });
    }
    Ok(merged)
}

fn set_exact<T: Clone>(bindings: &mut Vec<NamedValues<T>>, name: &str, value: T) -> Update {
    if let Some(binding) = bindings.iter_mut().find(|binding| binding.name == name) {
        binding.values = vec![value];
        binding.absent = false;
        binding.unknown = false;
        return Update::Exact;
    }
    if bindings.len() == MAX_BINDINGS {
        return Update::Refused;
    }
    bindings.push(NamedValues {
        name: name.to_owned(),
        values: vec![value],
        absent: false,
        unknown: false,
    });
    Update::Exact
}

fn set_unknown<T>(bindings: &mut Vec<NamedValues<T>>, name: &str) -> Update {
    if let Some(binding) = bindings.iter_mut().find(|binding| binding.name == name) {
        binding.values.clear();
        binding.absent = true;
        binding.unknown = true;
        return Update::Partial;
    }
    if bindings.len() == MAX_BINDINGS {
        return Update::Refused;
    }
    bindings.push(NamedValues {
        name: name.to_owned(),
        values: Vec::new(),
        absent: true,
        unknown: true,
    });
    Update::Partial
}

fn find<'a, T>(bindings: &'a [NamedValues<T>], name: &str) -> Option<&'a NamedValues<T>> {
    bindings.iter().find(|binding| binding.name == name)
}

fn finish_resolution(mut targets: Vec<LookupTarget>, variants_complete: bool) -> RuntimeResolution {
    targets.sort();
    targets.dedup();
    let command_not_found_possible = targets
        .iter()
        .any(|target| matches!(target, LookupTarget::Path(_)));
    RuntimeResolution {
        targets,
        variants_complete,
        command_not_found_possible,
    }
}

fn certainty(value: bool) -> Certainty {
    if value { Certainty::Yes } else { Certainty::No }
}

fn merge_certainty(left: Certainty, right: Certainty) -> Certainty {
    if left == right {
        left
    } else {
        Certainty::Maybe
    }
}

fn is_set_short_option(option: char) -> bool {
    matches!(
        option,
        'a' | 'b'
            | 'e'
            | 'f'
            | 'h'
            | 'k'
            | 'm'
            | 'n'
            | 'p'
            | 't'
            | 'u'
            | 'v'
            | 'x'
            | 'B'
            | 'C'
            | 'E'
            | 'H'
            | 'P'
            | 'T'
    )
}

fn is_set_long_option(option: &str) -> bool {
    matches!(
        option,
        "allexport"
            | "braceexpand"
            | "emacs"
            | "errexit"
            | "errtrace"
            | "functrace"
            | "hashall"
            | "histexpand"
            | "history"
            | "ignoreeof"
            | "interactive-comments"
            | "keyword"
            | "monitor"
            | "noclobber"
            | "noexec"
            | "noglob"
            | "nolog"
            | "notify"
            | "nounset"
            | "onecmd"
            | "physical"
            | "pipefail"
            | "posix"
            | "privileged"
            | "verbose"
            | "vi"
            | "xtrace"
    )
}

fn valid_alias_name(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(|character| {
            character.is_whitespace()
                || matches!(
                    character,
                    '/' | '$'
                        | '`'
                        | '='
                        | '\\'
                        | '\''
                        | '"'
                        | '|'
                        | '&'
                        | ';'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                )
        })
}

fn is_shell_builtin(name: &str) -> bool {
    matches!(
        name,
        "." | ":"
            | "["
            | "alias"
            | "bg"
            | "bind"
            | "break"
            | "builtin"
            | "caller"
            | "cd"
            | "command"
            | "compgen"
            | "complete"
            | "compopt"
            | "continue"
            | "declare"
            | "dirs"
            | "disown"
            | "echo"
            | "enable"
            | "eval"
            | "exec"
            | "exit"
            | "export"
            | "false"
            | "fc"
            | "fg"
            | "getopts"
            | "hash"
            | "help"
            | "history"
            | "jobs"
            | "kill"
            | "let"
            | "local"
            | "logout"
            | "mapfile"
            | "popd"
            | "printf"
            | "pushd"
            | "pwd"
            | "read"
            | "readarray"
            | "readonly"
            | "return"
            | "set"
            | "shift"
            | "shopt"
            | "source"
            | "suspend"
            | "test"
            | "times"
            | "trap"
            | "true"
            | "type"
            | "typeset"
            | "ulimit"
            | "umask"
            | "unalias"
            | "unset"
            | "wait"
    )
}

#[cfg(test)]
mod tests;
