//! Saturation memos: the keys under which a structurally saturated walk
//! remembers function calls, command heads and variable bindings it has
//! already retained, so repeated work is recorded once.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{ProvenanceRef, ResourceExpr};

use crate::word::{Word, WordPart};

use super::function_definition::FnEntry;
use super::referenced_inputs::{ReferencedInputs, expanded_referenced_inputs_bounded};
use super::shell_env::ShellEnv;
use super::{Converted, MAX_SATURATED_FUNCTION_STEPS};

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct WordKey(Vec<WordPartKey>);

#[derive(Clone, PartialEq, Eq, Hash)]
enum WordPartKey {
    Literal(String),
    Env(String),
    Glob(String),
    Value(String),
    Union(Vec<WordKey>),
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct FunctionHeadKey {
    entry: u64,
    args: blake3::Hash,
    vars: blake3::Hash,
    cwd: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct FunctionHeadGroupKey {
    entry: u64,
    head: Option<WordKey>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct CommandHeadKey {
    pub(super) node: ProvenanceRef,
    pub(super) head: WordKey,
    pub(super) cwd: Option<String>,
}

#[derive(Clone, Default)]
pub(super) struct SaturationMemos {
    pub(super) function_commands: HashSet<CommandHeadKey>,
    pub(super) functions: HashSet<FunctionHeadKey>,
    pub(super) function_groups: HashMap<FunctionHeadGroupKey, usize>,
    pub(super) function_steps: usize,
    /// Substitution source bytes parsed during saturated head recovery.
    pub(super) substitution_parse_steps: usize,
    /// Non-head argv words hashed for saturated function memo keys.
    pub(super) function_arg_steps: usize,
    /// Child environments cloned for saturated function stages.
    pub(super) function_env_clones: usize,
    pub(super) unresolved_heads: usize,
}

pub(super) fn function_head_key(
    entry: &Rc<FnEntry>,
    inputs: &ReferencedInputs,
    args: &[Converted],
    env: &ShellEnv,
    max_callee_depth: u64,
) -> Option<FunctionHeadKey> {
    let mut memos = env.saturation_memos.borrow_mut();
    let (args_key, args_work) = function_args_key_bounded(
        args,
        MAX_SATURATED_FUNCTION_STEPS - memos.function_arg_steps,
    )?;
    memos.function_arg_steps += args_work;
    let Some((vars, _, work)) = expanded_referenced_inputs_bounded(
        &inputs.vars,
        &inputs.calls,
        &inputs.command_vars,
        &inputs.command_head_patterns,
        env,
        max_callee_depth,
        MAX_SATURATED_FUNCTION_STEPS - memos.function_steps,
    ) else {
        memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
        return None;
    };
    memos.function_steps += work;
    drop(memos);

    let mut var_hasher = blake3::Hasher::new();
    for name in &vars {
        var_hasher.update(&(name.len() as u64).to_le_bytes());
        var_hasher.update(name.as_bytes());
        if let Some(entry) = env.vars.get(name) {
            var_hasher.update(&[1]);
            var_hasher.update(entry.saturation_key.as_bytes());
        } else {
            var_hasher.update(&[0]);
        }
    }
    Some(FunctionHeadKey {
        entry: entry.id,
        args: args_key,
        vars: var_hasher.finalize(),
        cwd: resource_key(env.cwd_resource.as_ref()),
    })
}

fn function_args_key_bounded(args: &[Converted], max_work: usize) -> Option<(blake3::Hash, usize)> {
    // The first positional word already selects the bounded function group.
    let work = args.len().saturating_sub(1);
    if work > max_work {
        return None;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(args.len() as u64).to_le_bytes());
    for arg in args {
        hash_word(&mut hasher, &arg.word);
    }
    Some((hasher.finalize(), work))
}

fn hash_word(hasher: &mut blake3::Hasher, word: &Word) {
    hasher.update(&(word.parts.len() as u64).to_le_bytes());
    for part in &word.parts {
        let (tag, value) = match part {
            WordPart::Literal(value) => (0, Some(value.as_str())),
            WordPart::Env(name) => (1, Some(name.as_str())),
            WordPart::Glob(pattern) => (2, Some(pattern.as_str())),
            WordPart::Value(value) => {
                hasher.update(&[5]);
                let value = resource_key(Some(value)).unwrap();
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
                continue;
            }
            WordPart::Unknown => (3, None),
            WordPart::Union(alternatives) => {
                hasher.update(&[4]);
                hasher.update(&(alternatives.len() as u64).to_le_bytes());
                for alternative in alternatives {
                    hash_word(hasher, alternative);
                }
                continue;
            }
        };
        hasher.update(&[tag]);
        if let Some(value) = value {
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
}

pub(super) fn variable_saturation_key(
    value: Option<&str>,
    may: &BTreeSet<String>,
    word: Option<&Word>,
    script_may_set: bool,
    unresolved_default_override: bool,
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[
        u8::from(script_may_set),
        u8::from(unresolved_default_override),
    ]);
    if let Some(value) = value {
        hasher.update(&[1]);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    } else {
        hasher.update(&[0]);
    }
    for value in may {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    if let Some(word) = word {
        hash_word(&mut hasher, word);
    }
    hasher.finalize()
}

pub(super) fn function_head_group_key(entry: &FnEntry, args: &[Converted]) -> FunctionHeadGroupKey {
    FunctionHeadGroupKey {
        entry: entry.id,
        head: args.first().map(|arg| word_key(&arg.word)),
    }
}

pub(super) fn word_key(word: &Word) -> WordKey {
    WordKey(
        word.parts
            .iter()
            .map(|part| match part {
                WordPart::Literal(value) => WordPartKey::Literal(value.clone()),
                WordPart::Env(name) => WordPartKey::Env(name.clone()),
                WordPart::Glob(pattern) => WordPartKey::Glob(pattern.clone()),
                WordPart::Union(alternatives) => {
                    WordPartKey::Union(alternatives.iter().map(word_key).collect())
                }
                WordPart::Value(value) => WordPartKey::Value(resource_key(Some(value)).unwrap()),
                WordPart::Unknown => WordPartKey::Unknown,
            })
            .collect(),
    )
}

pub(super) fn resource_key(resource: Option<&ResourceExpr>) -> Option<String> {
    resource.map(|resource| format!("{resource:?}"))
}
