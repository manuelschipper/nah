//! Secret store identities and operations, including credential groups of cloud CLIs.
use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, Port, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan};
use crate::models::common::{
    Attrs, arg_effect, arg_node, credential_full, fs_full_no_spawn, program_input_attrs,
};
use crate::models::{CommandModel, InvocationCtx, ModelBindingEnd, ModelCausalBinding};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};
use effinterp_model_schema::EffectSelection;

pub(crate) const CREDENTIAL_READ: &str = "credential.read";
pub(crate) const CREDENTIAL_WRITE: &str = "credential.write";
pub(crate) const CREDENTIAL_DELETE: &str = "credential.delete";
pub(crate) const CREDENTIAL_READ_REQUEST: &str = "credential.read_request";
pub(crate) const CREDENTIAL_DELETE_REQUEST: &str = "credential.delete_request";

pub(super) fn credential_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Vault),
        Box::new(Doppler),
        Box::new(Infisical),
        Box::new(Op),
        Box::new(Security),
        Box::new(Bitwarden),
        Box::new(Bws),
        Box::new(Pass),
        Box::new(Gopass),
        Box::new(Sops),
    ]
}

const SECURITY_DUMP_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-o"],
    known_flags: &["-a", "-d", "-h", "-i", "-r"],
};
// Item lookups select by attribute. `-g` and `-w` disclose the stored value;
// without them the lookup prints only the item's attributes.
const SECURITY_FIND_GENERIC_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-a", "-c", "-C", "-D", "-G", "-j", "-l", "-s"],
    known_flags: &["-g", "-w"],
};
const SECURITY_FIND_INTERNET_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "-a", "-c", "-C", "-d", "-D", "-j", "-l", "-p", "-P", "-r", "-s", "-t",
    ],
    known_flags: &["-g", "-w"],
};

/// The position of the subcommand, after `security`'s own options. Only `-q`
/// and `-v` are accepted: they change diagnostics, not what the subcommand
/// prints. Interactive (`-i`, `-p`), leak-checking (`-l`) and unknown options
/// leave the subcommand unfound, and the model bounds the call.
fn security_subcommand(argv: &[Word]) -> Option<usize> {
    let mut index = 1;
    loop {
        let word = argv.get(index)?.as_literal()?;
        if word == "--" {
            return Some(index + 1);
        }
        let Some(options) = word.strip_prefix('-') else {
            return Some(index);
        };
        if options.is_empty() || !options.chars().all(|option| matches!(option, 'q' | 'v')) {
            return None;
        }
        index += 1;
    }
}

/// The subcommand's position, its flag grammar, and whether it is an item
/// lookup. Other subcommands scan as `dump-keychain` and stay unmodeled; an
/// unfound subcommand is reported at position 1, which names none.
fn security_flags(argv: &[Word]) -> (usize, &'static FlagSpec<'static>, bool) {
    let subcommand = security_subcommand(argv).unwrap_or(1);
    let (spec, find) = match argv.get(subcommand).and_then(Word::as_literal) {
        Some("find-generic-password") => (&SECURITY_FIND_GENERIC_FLAGS, true),
        Some("find-internet-password") => (&SECURITY_FIND_INTERNET_FLAGS, true),
        _ => (&SECURITY_DUMP_FLAGS, false),
    };
    (subcommand, spec, find)
}

struct Security;
impl CommandModel for Security {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "filesystem", "process"]
    }
    fn id(&self) -> &'static str {
        "credential/security@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["security"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let (subcommand, spec, find) = security_flags(argv);
        let args = scan(argv.get(subcommand..).unwrap_or_default(), spec);
        let mut bindings = read_output(args.has(&["-o"]));
        if find && !args.has(&["-w"]) {
            // `-g` alone prints the value to stderr, beside the attributes.
            for binding in &mut bindings {
                binding.to = ModelBindingEnd::Port(Port::Stderr);
            }
        }
        bindings.push(ModelCausalBinding {
            assurance: effinterp_proto::CausalAssurance::Conservative,
            from: ModelBindingEnd::Effect {
                operation: "filesystem.read".into(),
                selection: EffectSelection::All,
            },
            to: ModelBindingEnd::Effect {
                operation: CREDENTIAL_READ.into(),
                selection: EffectSelection::All,
            },
        });
        bindings
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        credential_full(builder);
        let (subcommand, spec, find) = security_flags(ctx.argv);
        let args = scan(ctx.argv.get(subcommand..).unwrap_or_default(), spec);
        let subcommand_name = ctx.argv.get(subcommand).and_then(Word::as_literal);
        let dump = subcommand_name == Some("dump-keychain");
        let discloses = args.has(&["-g", "-w"]);
        // Only a lookup's attribute values may be symbolic: an unknown service
        // still selects one item whose value is disclosed. A detached value is
        // its own word. An attached one (`-s"$SERVICE"`) is proven by the
        // flag's literal spelling, but getopt takes the next word instead if
        // it expands empty, so it is admitted only when some literal text
        // keeps it non-empty or no word follows it.
        let symbolic_value = |index: usize| {
            find && args.flags.iter().any(|flag| {
                let Some(value_index) = flag.value_index else {
                    return false;
                };
                value_index as usize + subcommand == index
                    && (value_index != flag.index
                        || index + 1 == ctx.argv.len()
                        || flag.value.as_ref().is_some_and(|value| {
                            value.parts.iter().any(
                                |part| matches!(part, WordPart::Literal(text) if !text.is_empty()),
                            )
                        }))
            })
        };
        // Apple's getopt stops at the first keychain operand. Do not reinterpret
        // later dashed filenames as controls, or certify interactive ACL edits.
        // A lookup without `-g` or `-w` prints only attributes of the item it
        // finds, which discloses no stored value, so it is not a keychain
        // read the credential guard should stop.
        if !(dump || find && discloses)
            || !args.unknown_flags.is_empty()
            || args.has(&["-i"])
            || ctx
                .argv
                .iter()
                .enumerate()
                .any(|(index, word)| word.as_literal().is_none() && !symbolic_value(index))
            || args
                .operands
                .iter()
                .any(|(_, word)| word.as_literal() == Some(""))
            || args.flags.iter().any(|flag| {
                (spec.value_flags.contains(&flag.name) && flag.value.is_none())
                    || args.operands.first().is_some_and(|(i, _)| *i < flag.index)
            })
        {
            builder.boundary(Boundary {
                reason: if dump || find && discloses {
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS
                } else {
                    BoundaryReason::UNMODELED_SUBCOMMAND
                },
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: crate::builder::KNOWN_DOMAINS
                    .into_iter()
                    .map(Domain::new)
                    .collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(
                    "security supports noninteractive dump-keychain arguments and \
                     find-generic-password or find-internet-password value reads (-g or -w)"
                        .into(),
                ),
            });
            return;
        }
        if args.has(&["-h"]) {
            return;
        }
        let output = args.value_of(&["-o"]);
        let mut attributes = Attrs::from([
            (
                "mode".into(),
                AttrValue::String(
                    if find || args.has(&["-d"]) {
                        "value"
                    } else {
                        "metadata"
                    }
                    .into(),
                ),
            ),
            ("workflow".into(), AttrValue::String("ordinary".into())),
            ("purpose".into(), AttrValue::String("explicit".into())),
            (
                "selector".into(),
                AttrValue::String(if find { "item" } else { "store" }.into()),
            ),
            (
                "output".into(),
                AttrValue::String(
                    if output.is_some() {
                        "file"
                    } else if find && !args.has(&["-w"]) {
                        "stderr"
                    } else {
                        "stdout"
                    }
                    .into(),
                ),
            ),
        ]);
        if find {
            // The item's identity, where the invocation names it literally.
            let server = subcommand_name == Some("find-internet-password");
            for (name, flag) in [
                (if server { "server" } else { "service" }, "-s"),
                ("account", "-a"),
                ("label", "-l"),
            ] {
                if let Some(value) = args
                    .value_of(&[flag])
                    .and_then(Word::as_literal)
                    .filter(|value| !value.is_empty())
                {
                    attributes.insert(name.into(), AttrValue::String(value.into()));
                }
            }
        }
        // No operands means the configured search list, not a fixed login file.
        // SecKeychainOpen resolves relative names under ~/Library/Keychains.
        let targets: Vec<_> = if args.operands.is_empty() {
            vec![(subcommand as u32, None)]
        } else {
            args.operands
                .iter()
                .map(|(i, word)| (i + subcommand as u32, Some(*word)))
                .collect()
        };
        for (index, target) in targets {
            let mut provenance = vec![node];
            let path = target.and_then(|word| {
                let name = word.as_literal()?;
                if name.starts_with('/') {
                    return Some(word.clone());
                }
                if let Some(input) = ctx.nest.current_environment_node("HOME") {
                    provenance.push(input);
                }
                match ctx.environment_value("HOME") {
                    Some(ResourceExpr::Literal { value }) if value.starts_with('/') => {
                        Some(Word::literal(crate::paths::join_cwd(
                            &value,
                            &format!("Library/Keychains/{name}"),
                        )))
                    }
                    _ => None,
                }
            });
            if let Some(path) = &path {
                arg_effect(
                    builder,
                    ctx,
                    node,
                    index,
                    "filesystem.read",
                    ctx.resolve_fs_word(path),
                    Attrs::from([(
                        "access_purpose".into(),
                        AttrValue::String("program_input".into()),
                    )]),
                );
            } else {
                builder.boundary(Boundary {
                    reason: BoundaryReason::PARTIAL_ANALYSIS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(unresolved_resource("filesystem")),
                    callee: None,
                    domains: if target.is_none() {
                        vec![Domain::new("filesystem")]
                    } else {
                        vec![Domain::new("filesystem"), Domain::new("credential")]
                    },
                    provenance: provenance.clone(),
                    limit: None,
                    detail: Some(if target.is_none() {
                        "keychain selection requires the configured search list".into()
                    } else {
                        "relative keychain location requires the user's HOME/Library/Keychains"
                            .into()
                    }),
                });
                if target.is_some() {
                    continue;
                }
            }
            let target = resource(
                "macos-keychain",
                Some(path.as_ref().unwrap_or(&Word::literal("search-list"))),
                None,
            );
            for (operation, request_assurance, modality) in [
                (
                    CREDENTIAL_READ_REQUEST,
                    effinterp_proto::RequestAssurance::Exact,
                    Modality::MustOnSuccess,
                ),
                (
                    CREDENTIAL_READ,
                    effinterp_proto::RequestAssurance::Conservative,
                    Modality::May,
                ),
            ] {
                let mut provenance = provenance.clone();
                provenance.push(arg_node(builder, ctx, index));
                builder.effect(Effect {
                    id: Default::default(),
                    operation: Operation::new(operation),
                    resource: target.clone(),
                    attributes: attributes.clone(),
                    request_assurance,
                    modality,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance,
                });
            }
        }
        if let Some(output) = output {
            arg_effect(
                builder,
                ctx,
                node,
                subcommand as u32,
                "filesystem.write",
                ctx.resolve_fs_word(output),
                Attrs::new(),
            );
        }
    }
}

// Value flags are removed before interpreting positional verbs and names. Keep
// words intact so symbolic names cannot accidentally become concrete secrets.
struct Args {
    operands: Vec<Word>,
    flags: BTreeMap<String, Word>,
}
impl Args {
    fn parse(argv: &[Word], value_flags: &[&str]) -> Self {
        let mut args = Self {
            operands: Vec::new(),
            flags: BTreeMap::new(),
        };
        let mut words = argv.iter().skip(1);
        while let Some(word) = words.next() {
            let Some(WordPart::Literal(first)) = word.parts.first() else {
                args.operands.push(word.clone());
                continue;
            };
            if first == "--" {
                args.operands.extend(words.cloned());
                break;
            }
            if first.starts_with('-') {
                if let Some((flag, value)) = first.split_once('=') {
                    let mut parts = vec![WordPart::Literal(value.into())];
                    parts.extend_from_slice(&word.parts[1..]);
                    args.flags.insert(flag.into(), Word::new(parts));
                } else if value_flags.contains(&first.as_str()) {
                    args.flags.insert(
                        first.clone(),
                        words
                            .next()
                            .cloned()
                            .unwrap_or_else(|| Word::new(vec![WordPart::Unknown])),
                    );
                } else {
                    args.flags.insert(first.clone(), Word::literal("true"));
                }
            } else {
                args.operands.push(word.clone());
            }
        }
        args
    }
    fn verb(&self, index: usize) -> Option<&str> {
        self.operands.get(index).and_then(Word::as_literal)
    }
    fn flag(&self, name: &str) -> Option<&Word> {
        self.flags.get(name)
    }
    fn attr(&self, attrs: &mut Attrs, name: &str, flags: &[&str]) {
        if let Some(value) = flags
            .iter()
            .find_map(|flag| self.flag(flag))
            .and_then(Word::as_literal)
        {
            attrs.insert(name.into(), AttrValue::String(value.into()));
        }
    }
}

/// How many words an AWS list option consumes: a list takes only the adjacent
/// words following its flag, so positional words elsewhere must not become
/// extra list items.
fn adjacent_list_len(argv: &[Word], flag: &str) -> usize {
    argv.iter()
        .position(|word| {
            word.as_literal()
                .is_some_and(|text| text == flag || text.starts_with(&format!("{flag}=")))
        })
        .map_or(0, |index| {
            usize::from(argv[index].as_literal().unwrap().contains('='))
                + argv[index + 1..]
                    .iter()
                    .take_while(|word| word.as_literal().is_some_and(|text| !text.starts_with('-')))
                    .count()
        })
}

fn audited_args(args: &Args, allowed: &[&str], value_flags: &[&str]) -> bool {
    args.flags.iter().all(|(name, value)| {
        allowed.contains(&name.as_str())
            && (!value_flags.contains(&name.as_str())
                || value.as_literal().is_some_and(|text| !text.is_empty()))
    })
}

// Global options that only shape how each cloud CLI prints its response. They
// never change which secret is requested; `output_prints` decides whether the
// printed response still carries the value.
const AWS_OUTPUT_VALUES: &[&str] = &["--query", "--output"];
const AWS_OUTPUT_SWITCHES: &[&str] = &["--no-cli-pager"];
const AZ_OUTPUT_VALUES: &[&str] = &["--query", "--output", "-o"];
const AZ_OUTPUT_SWITCHES: &[&str] = &["--only-show-errors"];
const GCLOUD_OUTPUT_VALUES: &[&str] = &["--format", "--verbosity"];
// The output formats each CLI accepts that print the response; `off` and
// `none` print nothing, and any other value is rejected.
const AWS_PRINTING_FORMATS: &[&str] = &["json", "text", "table", "yaml", "yaml-stream"];
const AZ_PRINTING_FORMATS: &[&str] = &["json", "jsonc", "table", "tsv", "yaml", "yamlc"];

// An output option keeps a read exact only while the printed response still
// carries the secret value: a query naming another field, or silenced output,
// proves no value read.
fn output_prints(args: &Args, flags: &[&str], prints: impl Fn(&str) -> bool) -> bool {
    flags
        .iter()
        .filter_map(|flag| args.flag(flag))
        .all(|value| value.as_literal().is_some_and(&prints))
}

// A gcloud format is `printer[attributes](projection)`. It prints the accessed
// secret only when the printer writes the resource (`none` and `disable` write
// nothing) and, with a projection, one projected key selects the payload data
// or the `payload` object containing it. What follows a key's `:` (`label=`,
// `sort=`) only names or orders a column.
fn gcloud_format_prints(format: &str) -> bool {
    let name_end = format
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(format.len());
    let (printer, mut rest) = format.split_at(name_end);
    if let Some(attributes) = rest.strip_prefix('[') {
        let Some((_, after)) = attributes.split_once(']') else {
            return false;
        };
        rest = after;
    }
    if rest.is_empty() {
        return matches!(printer, "json" | "yaml");
    }
    let Some(projection) = rest
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    // Quoted label text could hide separators, so it is not interpreted.
    if projection.contains(['"', '\'']) {
        return false;
    }
    let mut keys = Vec::new();
    let (mut depth, mut start) = (0, 0);
    for (index, c) in projection.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                keys.push(&projection[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    keys.push(&projection[start..]);
    matches!(
        printer,
        "json" | "yaml" | "value" | "get" | "csv" | "table" | "list" | "flattened" | "text"
    ) && keys.into_iter().any(|key| {
        let key = key.split_once(':').map_or(key, |(key, _)| key).trim();
        matches!(
            key,
            "payload" | "payload.data" | "payload.data.decode(base64)"
        )
    })
}

// A step on the path from a CLI response's root to the secret value: an
// object key, or every element of a list, with the most elements the list can
// hold when the request bounds it.
#[derive(Clone, Copy, PartialEq)]
enum Step {
    Key(&'static str),
    Each(Option<usize>),
}

// Whether a JMESPath `--query` prints the value found at `path`: it selects
// the value itself or an object or list containing it, directly or inside a
// multiselect list or hash. Only key paths, `[]`/`[*]`/`[N]` list steps and
// multiselects are recognized; any other query proves nothing. An index past a
// bounded list selects null, which contains no value.
fn query_prints(query: &str, path: &[Step]) -> bool {
    let mut query = Query {
        text: query.as_bytes(),
        at: 0,
    };
    query
        .expression(path, Some(0), 0)
        .is_some_and(|reached| reached.is_some() && query.end())
}

// Multiselects nested deeper than this are left unrecognized, so an analyzed
// query cannot recurse the recognizer off the stack.
const QUERY_DEPTH_LIMIT: usize = 32;

struct Query<'a> {
    text: &'a [u8],
    at: usize,
}
impl<'a> Query<'a> {
    fn space(&mut self) {
        while self.text.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }
    fn end(&mut self) -> bool {
        self.space();
        self.at == self.text.len()
    }
    fn eat(&mut self, byte: u8) -> bool {
        self.space();
        let hit = self.text.get(self.at) == Some(&byte);
        self.at += usize::from(hit);
        hit
    }
    fn identifier(&mut self) -> Option<&'a str> {
        self.space();
        let start = self.at;
        while self
            .text
            .get(self.at)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.at += 1;
        }
        (self.at > start && !self.text[start].is_ascii_digit())
            .then(|| std::str::from_utf8(&self.text[start..self.at]).unwrap())
    }
    // `[]`, `[*]` or `[N]`: a step into a list's elements, `Some(None)` for
    // every element and `Some(Some(N))` for index N.
    fn list_step(&mut self) -> Option<Option<usize>> {
        let start = self.at;
        if self.eat(b'[') {
            let step = if self.eat(b'*') {
                Some(None)
            } else {
                self.space();
                let digits = self.at;
                while self.text.get(self.at).is_some_and(u8::is_ascii_digit) {
                    self.at += 1;
                }
                if self.at == digits {
                    Some(None)
                } else {
                    std::str::from_utf8(&self.text[digits..self.at])
                        .unwrap()
                        .parse()
                        .ok()
                        .map(Some)
                }
            };
            if step.is_some() && self.eat(b']') {
                return step;
            }
        }
        self.at = start;
        None
    }
    // Follows one expression from `at`, the step reached on `path`, and
    // returns the step its result stands at: `Some(None)` once it selects
    // something that does not contain the value, `None` for an unrecognized
    // query.
    fn expression(
        &mut self,
        path: &[Step],
        mut at: Option<usize>,
        depth: usize,
    ) -> Option<Option<usize>> {
        if depth > QUERY_DEPTH_LIMIT {
            return None;
        }
        let advance = |at: Option<usize>, index: Option<usize>| {
            at.filter(|&at| match path.get(at) {
                Some(Step::Each(Some(bound))) => index.is_none_or(|index| index < *bound),
                Some(Step::Each(None)) => true,
                _ => false,
            })
            .map(|at| at + 1)
        };
        let mut first = true;
        loop {
            let first_step = if first { self.list_step() } else { None };
            if let Some(index) = first_step {
                at = advance(at, index);
            } else if self.eat(b'[') {
                return self.multiselect(path, at, b']', false, depth);
            } else if self.eat(b'{') {
                return self.multiselect(path, at, b'}', true, depth);
            } else {
                let key = self.identifier()?;
                at = at
                    .filter(|&at| matches!(path.get(at), Some(Step::Key(name)) if *name == key))
                    .map(|at| at + 1);
            }
            first = false;
            while let Some(index) = self.list_step() {
                at = advance(at, index);
            }
            if !self.eat(b'.') {
                return Some(at);
            }
        }
    }
    fn multiselect(
        &mut self,
        path: &[Step],
        at: Option<usize>,
        close: u8,
        hash: bool,
        depth: usize,
    ) -> Option<Option<usize>> {
        let mut prints = false;
        loop {
            if hash && (self.identifier().is_none() || !self.eat(b':')) {
                return None;
            }
            prints |= self.expression(path, at, depth + 1)?.is_some();
            if self.eat(close) {
                return Some(prints.then_some(path.len()));
            }
            if !self.eat(b',') {
                return None;
            }
        }
    }
}

fn strict_args(argv: &[Word], values: &[&str], booleans: &[&str]) -> bool {
    strict_repeated_args(argv, values, booleans, &[])
}
// `repeated` names value flags whose every occurrence adds to one list.
fn strict_repeated_args(
    argv: &[Word],
    values: &[&str],
    booleans: &[&str],
    repeated: &[&str],
) -> bool {
    let mut index = 1;
    let mut seen = std::collections::BTreeSet::new();
    while index < argv.len() {
        let Some(text) = argv[index].as_literal() else {
            return false;
        };
        if text == "--" {
            return false;
        }
        if !text.starts_with('-') {
            index += 1;
            continue;
        }
        let key = text.split_once('=').map_or(text, |(key, _)| key);
        if !seen.insert(key) && !repeated.contains(&key) {
            return false;
        }
        if booleans.contains(&key) {
            if text.contains('=') {
                return false;
            }
        } else if values.contains(&key) {
            let value = text.split_once('=').map(|(_, value)| value).or_else(|| {
                index += 1;
                argv.get(index).and_then(Word::as_literal)
            });
            if value.is_none_or(|value| value.is_empty() || value.starts_with('-')) {
                return false;
            }
        } else {
            return false;
        }
        index += 1;
    }
    true
}
fn resource(provider: &str, store: Option<&Word>, path: Option<&Word>) -> ResourceExpr {
    if store
        .into_iter()
        .chain(path)
        .any(|word| word.as_literal().is_none_or(str::is_empty))
    {
        return unresolved_resource("credential");
    }
    ResourceExpr::Concrete {
        identity: ResourceIdentity::CredentialStore {
            provider: provider.into(),
            store: store.and_then(Word::as_literal).map(str::to_owned),
            path: path.and_then(Word::as_literal).map(str::to_owned),
        },
    }
}
fn named(provider: &str, store: Option<&Word>, path: Option<&Word>) -> ResourceExpr {
    path.map_or_else(
        || unresolved_resource("credential"),
        |path| resource(provider, store, Some(path)),
    )
}
fn store_resource(provider: &str, store: Option<&Word>) -> ResourceExpr {
    store.map_or_else(
        || unresolved_resource("credential"),
        |store| resource(provider, Some(store), None),
    )
}
fn join_store(first: Option<&Word>, second: Option<&Word>) -> Option<Word> {
    let words: Vec<_> = first.into_iter().chain(second).collect();
    if words.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for word in words {
        if !parts.is_empty() {
            parts.push(WordPart::Literal("/".into()));
        }
        parts.extend(word.parts.clone());
    }
    Some(Word::new(parts))
}
fn flag(attrs: &mut Attrs, name: &str) {
    attrs.insert(name.into(), AttrValue::Bool(true));
    if name == "destroy" {
        attrs.insert("deletion".into(), AttrValue::String("permanent".into()));
    }
}
// A delete the provider documents as reversible, so a reader never has to infer
// the mode from the verb the way it can for `destroy`.
fn recoverable(attrs: &mut Attrs) {
    attrs.insert("deletion".into(), AttrValue::String("recoverable".into()));
}
/// Emit a credential verb's conservative effects on `targets`, plus the
/// unresolved provider request. `request_exact` is the caller's certification
/// that the command grammar was fully audited: for a read or delete it adds an
/// Exact, MustOnSuccess `credential.read_request`/`credential.delete_request`
/// for each target. Returns that same certification, which cloud dispatch
/// uses for coverage; it does not report whether a request was emitted.
fn emit_credential_effects(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    operation: &str,
    targets: Vec<ResourceExpr>,
    attributes: Attrs,
    request_exact: bool,
) -> bool {
    emit_store_effects(
        builder,
        ctx,
        node,
        operation,
        targets,
        attributes,
        request_exact,
        true,
    )
}
/// `emit_credential_effects` for a store the invocation may reach without a
/// provider request: a local store such as `pass` makes none.
#[allow(clippy::too_many_arguments)]
fn emit_store_effects(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    operation: &str,
    targets: Vec<ResourceExpr>,
    attributes: Attrs,
    request_exact: bool,
    network: bool,
) -> bool {
    credential_full(builder);
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    let mut provenance = vec![node];
    provenance.extend((1..ctx.argv.len()).map(|i| arg_node(builder, ctx, i as u32)));
    for (operation, resource, attributes) in targets
        .into_iter()
        .map(|target| (operation, target, attributes.clone()))
        .chain(network.then(|| {
            (
                "network.request",
                unresolved_resource("network"),
                Attrs::new(),
            )
        }))
    {
        if request_exact {
            let request_operation = match operation {
                CREDENTIAL_READ => Some(CREDENTIAL_READ_REQUEST),
                CREDENTIAL_DELETE => Some(CREDENTIAL_DELETE_REQUEST),
                _ => None,
            };
            if let Some(request_operation) = request_operation {
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Exact,
                    id: Default::default(),
                    operation: Operation::new(request_operation),
                    resource: resource.clone(),
                    attributes: attributes.clone(),
                    modality: Modality::MustOnSuccess,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: provenance.clone(),
                });
            }
        }
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: provenance.clone(),
        });
    }
    request_exact
}

fn unmodeled(builder: &mut PlanBuilder, node: ProvenanceRef) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNMODELED_SUBCOMMAND,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("credential"), Domain::new("network")],
        provenance: vec![node],
        limit: None,
        detail: None,
    });
    builder.declare_coverage(Domain::new("credential"), CoverageLevel::Partial);
}
pub(crate) fn read_output(to_file: bool) -> Vec<ModelCausalBinding> {
    // Only the audited request certifies where the selected read is emitted.
    // A conservative read can also exist for unsupported or unresolved controls.
    [
        (
            CREDENTIAL_READ,
            effinterp_proto::CausalAssurance::Conservative,
        ),
        (
            CREDENTIAL_READ_REQUEST,
            effinterp_proto::CausalAssurance::Exact,
        ),
    ]
    .into_iter()
    .map(|(operation, assurance)| ModelCausalBinding {
        assurance,
        from: ModelBindingEnd::Effect {
            operation: operation.into(),
            selection: EffectSelection::All,
        },
        to: if to_file {
            ModelBindingEnd::Effect {
                operation: "filesystem.write".into(),
                selection: EffectSelection::All,
            }
        } else {
            ModelBindingEnd::Port(Port::Stdout)
        },
    })
    .collect()
}

struct Vault;
impl CommandModel for Vault {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "credential/vault@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["vault"]
    }
    fn causal_bindings(&self, _: &[Word]) -> Vec<ModelCausalBinding> {
        read_output(false)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        // The generic verbs send one request to the path they name; a KV
        // destroy route there is the same request `vault kv` would send.
        let verb = ctx.argv.get(1).and_then(Word::as_literal);
        if let Some(verb @ ("delete" | "write")) = verb
            && let Some(path) = vault_request_path(ctx.argv)
            && let Some(target) = vault_kv_destroy_target(path, verb == "delete")
        {
            let delete = verb == "delete";
            emit_store_effects(
                builder,
                ctx,
                node,
                CREDENTIAL_DELETE,
                vec![target],
                vault_kv_destroy_attrs(delete),
                true,
                delete,
            );
            // A write keeps its ordinary effects: see `vault_kv_destroy_target`.
            if delete {
                return;
            }
        }
        let args = Args::parse(
            ctx.argv,
            &[
                "-mount",
                "-version",
                "-versions",
                "-format",
                "-field",
                "-address",
                "-namespace",
            ],
        );
        let mut attrs = Attrs::new();
        let mut request_exact = false;
        args.attr(&mut attrs, "version", &["-version", "-versions"]);
        let (operation, position) = match (args.verb(0), args.verb(1), args.verb(2)) {
            (Some("kv"), Some("get"), _) => (CREDENTIAL_READ, 2),
            (Some("kv"), Some("put"), _) => (CREDENTIAL_WRITE, 2),
            (Some("kv"), Some("undelete"), _) => {
                flag(&mut attrs, "undelete");
                (CREDENTIAL_WRITE, 2)
            }
            (Some("kv"), Some("delete"), _) => {
                // The kv v2 engine marks the versions deleted and keeps the
                // payload until `kv destroy`; `kv undelete` restores it.
                recoverable(&mut attrs);
                (CREDENTIAL_DELETE, 2)
            }
            (Some("kv"), Some("destroy"), _) => {
                flag(&mut attrs, "destroy");
                (CREDENTIAL_DELETE, 2)
            }
            (Some("kv"), Some("metadata"), Some("delete")) => {
                flag(&mut attrs, "destroy");
                attrs.insert("mode".into(), AttrValue::String("metadata".into()));
                (CREDENTIAL_DELETE, 3)
            }
            (Some("read"), _, _) => {
                attrs.insert("mode".into(), AttrValue::String("value".into()));
                attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
                attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
                attrs.insert("selector".into(), AttrValue::String("path".into()));
                attrs.insert("output".into(), AttrValue::String("stdout".into()));
                args.attr(&mut attrs, "field", &["-field"]);
                args.attr(&mut attrs, "format", &["-format"]);
                (CREDENTIAL_READ, 1)
            }
            (Some("write"), _, _) => (CREDENTIAL_WRITE, 1),
            (Some("delete"), _, _) => (CREDENTIAL_DELETE, 1),
            (Some("secrets"), Some("disable"), _) => {
                flag(&mut attrs, "destroy");
                let mount = args.operands.get(2).map(|word| {
                    word.as_literal()
                        .map(|s| Word::literal(s.trim_end_matches('/')))
                        .unwrap_or_else(|| word.clone())
                });
                let target = store_resource("vault", mount.as_ref());
                if args.operands.len() == 3
                    && strict_args(ctx.argv, &["-address", "-namespace"], &[])
                    && !matches!(target, ResourceExpr::Unresolved { .. })
                {
                    request_exact = true;
                }
                emit_credential_effects(
                    builder,
                    ctx,
                    node,
                    CREDENTIAL_DELETE,
                    vec![target],
                    attrs,
                    request_exact,
                );
                return;
            }
            _ => {
                unmodeled(builder, node);
                return;
            }
        };
        if matches!(args.verb(0), Some("kv")) {
            match args.verb(1) {
                Some("get") => {
                    attrs.insert("mode".into(), AttrValue::String("value".into()));
                    attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
                    attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
                }
                Some("delete" | "destroy" | "metadata") => {}
                _ => {}
            }
        }
        let target = if let Some(mount) = args.flag("-mount") {
            named("vault", Some(mount), args.operands.get(position))
        } else if let Some(path) = args.operands.get(position).and_then(Word::as_literal) {
            let (mount, path) = path
                .split_once('/')
                .map_or((path, None), |(m, p)| (m, Some(Word::literal(p))));
            resource("vault", Some(&Word::literal(mount)), path.as_ref())
        } else {
            unresolved_resource("credential")
        };
        let value_flags: &[&str] = match (args.verb(0), args.verb(1), args.verb(2)) {
            (Some("kv"), Some("get"), _) => &[
                "-mount",
                "-version",
                "-format",
                "-field",
                "-address",
                "-namespace",
            ],
            (Some("kv"), Some("delete"), _) => &[
                "-mount",
                "-versions",
                "-format",
                "-field",
                "-address",
                "-namespace",
            ],
            (Some("kv"), Some("destroy"), _) => {
                &["-mount", "-versions", "-format", "-address", "-namespace"]
            }
            (Some("kv"), Some("metadata"), Some("delete")) => &["-mount", "-address", "-namespace"],
            // The generic `read` takes a full path, so it has no `-mount`.
            (Some("read"), _, _) => &["-format", "-field", "-address", "-namespace"],
            _ => &[],
        };
        // Vault parses flags after the leaf command and stops at the first
        // operand. The general credential parser accepts interspersed flags.
        let prefix_ok = (0..position)
            .all(|index| ctx.argv.get(index + 1).and_then(Word::as_literal) == args.verb(index));
        let mut index = position + 1;
        while index < ctx.argv.len().saturating_sub(1) {
            let Some(text) = ctx.argv[index].as_literal() else {
                break;
            };
            let key = text.split_once('=').map_or(text, |(key, _)| key);
            if !value_flags.contains(&key) {
                break;
            }
            index += if text.contains('=') { 1 } else { 2 };
        }
        // `-versions` is a string slice flag: every occurrence adds versions.
        let mut versions = Vec::new();
        let mut words = ctx.argv.iter().skip(1);
        while let Some(word) = words.next() {
            match word.as_literal() {
                Some("-versions") => versions.push(words.next().and_then(Word::as_literal)),
                Some(text) => versions.extend(text.strip_prefix("-versions=").map(Some)),
                None => {}
            }
        }
        if versions.len() > 1
            && let Some(joined) = versions
                .iter()
                .copied()
                .collect::<Option<Vec<_>>>()
                .map(|versions| versions.join(","))
        {
            attrs.insert("version".into(), AttrValue::String(joined));
        }
        let versions_ok = versions.iter().all(|word| {
            word.is_some_and(|text| {
                text.split(',').all(|version| {
                    version
                        .trim()
                        .parse::<u64>()
                        .is_ok_and(|version| version > 0)
                })
            })
        }) && (args.verb(1) != Some("destroy") || !versions.is_empty());
        let version_ok = args.flag("-version").is_none_or(|word| {
            word.as_literal().is_some_and(|text| {
                text.parse::<u64>()
                    .is_ok_and(|version| version <= i64::MAX as u64)
            })
        });
        let format_ok = args.flag("-format").is_none_or(|word| {
            matches!(
                word.as_literal(),
                Some("table" | "json" | "yaml" | "pretty")
            )
        });
        if !value_flags.is_empty()
            && prefix_ok
            && index + 1 == ctx.argv.len()
            && audited_args(&args, value_flags, value_flags)
            && strict_repeated_args(ctx.argv, value_flags, &[], &["-versions"])
            && versions_ok
            && version_ok
            && format_ok
            && !matches!(target, ResourceExpr::Unresolved { .. })
            && args.operands.len() == position + 1
        {
            request_exact = true;
        }
        emit_credential_effects(
            builder,
            ctx,
            node,
            operation,
            vec![target],
            attrs,
            request_exact,
        );
    }
}

/// The path a generic `vault delete` or `vault write` sends its request to.
/// Vault parses its options before the path and stops at the first operand;
/// a delete takes nothing after the path, and a write's later words are its
/// data, which never change the path. A write without data is refused before
/// any request ("Must supply data or use -force").
fn vault_request_path(argv: &[Word]) -> Option<&str> {
    let mut index = 2;
    loop {
        let text = argv.get(index)?.as_literal()?;
        if !text.starts_with('-') {
            break;
        }
        let (key, value) = match text.split_once('=') {
            Some((key, value)) => (key, value),
            None => {
                index += 1;
                (text, argv.get(index)?.as_literal()?)
            }
        };
        if !matches!(key, "-address" | "-namespace") || value.is_empty() {
            return None;
        }
        index += 1;
    }
    let delete = argv[1].as_literal() == Some("delete");
    (delete == (index + 1 == argv.len()))
        .then(|| argv[index].as_literal())
        .flatten()
}

/// The secret a KV request to `path` permanently destroys, if the path is a
/// documented KV destroy route: a DELETE of `<mount>/metadata/<secret>` or a
/// write to `<mount>/destroy/<secret>`. The route is the earliest segment,
/// after the first, that names any KV v2 route, and the mount is every
/// segment before it; a later `metadata` or `destroy` is part of a secret's
/// name under that route (`secret/data/app/metadata/x`). The mount's KV
/// version is not visible here. A v2 metadata delete removes every version
/// and a v2 destroy removes the named versions. A v1 mount at that or any
/// shorter prefix deletes the secret stored at the rest of the path, which v1
/// keeps no copy of, so the delete is permanent either way. A v1 mount would
/// store the write as a secret instead; Nah cannot rule that out, so a write
/// keeps its ordinary effects beside the documented destroy. `sys`, `auth` and
/// `identity` are Vault's own mounts, never KV.
pub(crate) fn vault_kv_destroy_target(path: &str, delete: bool) -> Option<ResourceExpr> {
    const KV_ROUTES: &[&str] = &[
        "data", "metadata", "delete", "undelete", "destroy", "subkeys", "config",
    ];
    let path = path.strip_prefix('/').unwrap_or(path);
    let segments = path.split('/').collect::<Vec<_>>();
    let expected = if delete { "metadata" } else { "destroy" };
    let route = (1..segments.len()).find(|index| KV_ROUTES.contains(&segments[*index]))?;
    if segments[route] != expected {
        return None;
    }
    let (mount, secret) = (&segments[..route], &segments[route + 1..]);
    (!matches!(mount[0], "sys" | "auth" | "identity")
        && !secret.is_empty()
        && mount
            .iter()
            .chain(secret)
            .all(|segment| !matches!(*segment, "" | "." | "..")))
    .then(|| {
        resource(
            "vault",
            Some(&Word::literal(mount.join("/"))),
            Some(&Word::literal(secret.join("/"))),
        )
    })
}

/// The attributes `vault kv metadata delete` and `vault kv destroy` give the
/// same destruction.
fn vault_kv_destroy_attrs(delete: bool) -> Attrs {
    let mut attrs = Attrs::new();
    flag(&mut attrs, "destroy");
    if delete {
        attrs.insert("mode".into(), AttrValue::String("metadata".into()));
    }
    attrs
}

/// A Vault HTTP API request that destroys the KV secret `target`, sent by a
/// generic HTTP client whose own model emits the network request.
pub(crate) fn vault_http_destroy(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    target: ResourceExpr,
    delete: bool,
) {
    emit_store_effects(
        builder,
        ctx,
        node,
        CREDENTIAL_DELETE,
        vec![target],
        vault_kv_destroy_attrs(delete),
        true,
        false,
    );
}

// Cloud dispatch uses the validated request grammar to close invocation coverage.
pub(crate) fn aws_secretsmanager(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    let args = Args::parse(
        ctx.argv,
        &[
            "--secret-id",
            "--secret-id-list",
            "--filters",
            "--name",
            "--version-id",
            "--version-stage",
            "--recovery-window-in-days",
            "--secret-string",
            "--secret-binary",
            "--region",
            "--profile",
            "--endpoint-url",
            "--query",
            "--output",
        ],
    );
    // A batch read names its secrets in the words following --secret-id-list.
    let batch = args.verb(1) == Some("batch-get-secret-value");
    let batch_ids: Vec<_> = if batch {
        args.flag("--secret-id-list")
            .into_iter()
            .chain(args.operands.iter().skip(2))
            .collect()
    } else {
        Vec::new()
    };
    // AWS expands parameter-file URLs before interpreting the secret selector
    // or version controls; the URL itself is not a secret identity.
    if [
        "--secret-id",
        "--version-id",
        "--version-stage",
        "--recovery-window-in-days",
    ]
    .iter()
    .filter_map(|name| args.flag(name))
    .chain(batch_ids.iter().copied())
    .filter_map(Word::as_literal)
    .any(|value| value.starts_with("file://") || value.starts_with("fileb://"))
    {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOVERABLE_SOURCE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: ["credential", "filesystem", "network"]
                .into_iter()
                .map(Domain::new)
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some("AWS Secrets Manager parameter values come from an unread file".into()),
        });
        return false;
    }
    let mut attrs = Attrs::new();
    let mut request_exact = false;
    let operation = match args.verb(1) {
        Some("get-secret-value") => {
            args.attr(&mut attrs, "version", &["--version-id", "--version-stage"]);
            attrs.insert("mode".into(), AttrValue::String("value".into()));
            attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            let values = [
                &[
                    "--secret-id",
                    "--version-id",
                    "--version-stage",
                    "--region",
                    "--profile",
                    "--endpoint-url",
                ][..],
                AWS_OUTPUT_VALUES,
            ]
            .concat();
            let controls_ok =
                audited_args(&args, &[&values[..], AWS_OUTPUT_SWITCHES].concat(), &values);
            if controls_ok
                && strict_args(ctx.argv, &values, AWS_OUTPUT_SWITCHES)
                && output_prints(&args, &["--query"], |query| {
                    query_prints(query, &[Step::Key("SecretString")])
                        || query_prints(query, &[Step::Key("SecretBinary")])
                })
                && output_prints(&args, &["--output"], |output| {
                    AWS_PRINTING_FORMATS.contains(&output)
                })
                && args.flag("--secret-id").is_some()
                && args.operands.len() == 2
            {
                request_exact = true;
            }
            CREDENTIAL_READ
        }
        // The response lists each secret found under `SecretValues`, and at
        // most one per requested name. --filters selects secrets the
        // invocation does not name.
        Some("batch-get-secret-value") => {
            attrs.insert("mode".into(), AttrValue::String("value".into()));
            attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            let values = [
                &[
                    "--secret-id-list",
                    "--region",
                    "--profile",
                    "--endpoint-url",
                ][..],
                AWS_OUTPUT_VALUES,
            ]
            .concat();
            let bound = Some(batch_ids.len());
            if strict_args(ctx.argv, &values, AWS_OUTPUT_SWITCHES)
                && output_prints(&args, &["--query"], |query| {
                    ["SecretString", "SecretBinary"].iter().any(|field| {
                        query_prints(
                            query,
                            &[
                                Step::Key("SecretValues"),
                                Step::Each(bound),
                                Step::Key(field),
                            ],
                        )
                    })
                })
                && output_prints(&args, &["--output"], |output| {
                    AWS_PRINTING_FORMATS.contains(&output)
                })
                && (1..=20).contains(&batch_ids.len())
                // Secret names and ARNs use only these characters; anything
                // else, such as a JSON list, is not one secret id.
                && batch_ids.iter().all(|id| {
                    id.as_literal().is_some_and(|text| {
                        !text.is_empty()
                            && text.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || b"/_+=.@-:".contains(&byte)
                            })
                    })
                })
                && adjacent_list_len(ctx.argv, "--secret-id-list") == batch_ids.len()
                && args.operands.len() == 1 + batch_ids.len()
            {
                request_exact = true;
            }
            CREDENTIAL_READ
        }
        Some("put-secret-value" | "create-secret") => CREDENTIAL_WRITE,
        Some("restore-secret") => {
            flag(&mut attrs, "restore");
            CREDENTIAL_WRITE
        }
        Some("delete-secret") => {
            args.attr(
                &mut attrs,
                "recovery_window",
                &["--recovery-window-in-days"],
            );
            let mut destroy = false;
            let controls_ok = audited_args(
                &args,
                &[
                    "--secret-id",
                    "--recovery-window-in-days",
                    "--region",
                    "--profile",
                    "--endpoint-url",
                    "--force-delete-without-recovery",
                    "--no-force-delete-without-recovery",
                ],
                &[
                    "--secret-id",
                    "--recovery-window-in-days",
                    "--region",
                    "--profile",
                    "--endpoint-url",
                ],
            );
            let strict_controls = strict_args(
                ctx.argv,
                &[
                    "--secret-id",
                    "--recovery-window-in-days",
                    "--region",
                    "--profile",
                    "--endpoint-url",
                ],
                &[
                    "--force-delete-without-recovery",
                    "--no-force-delete-without-recovery",
                ],
            );
            let mut controls_known = true;
            for word in ctx.argv {
                // Cloud dispatch expands readable request input into options;
                // input still here was not read and may set the force mode.
                if word.as_literal().is_none() || word.literal_prefix().starts_with("--cli-input-")
                {
                    controls_known = false;
                }
                if matches!(
                    word.as_literal(),
                    Some("--force-delete-without-recovery" | "--no-force-delete-without-recovery")
                ) || word
                    .literal_prefix()
                    .starts_with("--force-delete-without-recovery=")
                {
                    destroy = matches!(
                        word.as_literal(),
                        Some(
                            "--force-delete-without-recovery"
                                | "--force-delete-without-recovery=true"
                        )
                    );
                }
            }
            if destroy {
                flag(&mut attrs, "destroy");
            } else if controls_known {
                // Without the force flag the secret sits in its recovery window
                // and `restore-secret` brings it back.
                recoverable(&mut attrs);
            }
            if controls_known {
                let recovery_ok = args.flag("--recovery-window-in-days").is_none_or(|word| {
                    word.as_literal().is_some_and(|text| {
                        text.parse::<u32>()
                            .is_ok_and(|days| (7..=30).contains(&days))
                    }) && args.flag("--force-delete-without-recovery").is_none()
                        && args.flag("--no-force-delete-without-recovery").is_none()
                });
                if controls_ok
                    && strict_controls
                    && recovery_ok
                    && args.flag("--secret-id").is_some()
                    && args.operands.len() == 2
                {
                    request_exact = true;
                }
            }
            CREDENTIAL_DELETE
        }
        _ => {
            unmodeled(builder, node);
            return false;
        }
    };
    let targets = if batch && !batch_ids.is_empty() && args.flag("--filters").is_none() {
        batch_ids
            .into_iter()
            .map(|id| named("aws-secretsmanager", None, Some(id)))
            .collect()
    } else {
        vec![named(
            "aws-secretsmanager",
            None,
            args.flag("--secret-id").or_else(|| args.flag("--name")),
        )]
    };
    emit_credential_effects(builder, ctx, node, operation, targets, attrs, request_exact)
}
pub(crate) fn aws_ssm_parameters(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    let args = Args::parse(
        ctx.argv,
        &[
            "--name",
            "--names",
            "--path",
            "--value",
            "--type",
            "--region",
            "--profile",
            "--endpoint-url",
            "--query",
            "--output",
        ],
    );
    let mut attrs = Attrs::new();
    let mut request_exact = false;
    let operation = match args.verb(1) {
        Some("get-parameter" | "get-parameters") => CREDENTIAL_READ,
        // A hierarchy read returns every parameter under the path, and with
        // --recursive every parameter below it.
        Some("get-parameters-by-path") => {
            if args.flag("--recursive").is_some() && args.flag("--no-recursive").is_none() {
                flag(&mut attrs, "recursive");
            }
            CREDENTIAL_READ
        }
        Some("put-parameter") => CREDENTIAL_WRITE,
        Some("delete-parameter" | "delete-parameters") => {
            flag(&mut attrs, "destroy");
            CREDENTIAL_DELETE
        }
        _ => {
            unmodeled(builder, node);
            return false;
        }
    };
    let names: Vec<_> = if matches!(args.verb(1), Some("get-parameters" | "delete-parameters")) {
        args.flag("--names")
            .into_iter()
            .chain(args.operands.iter().skip(2))
            .collect()
    } else if args.verb(1) == Some("get-parameters-by-path") {
        args.flag("--path").into_iter().collect()
    } else {
        args.flag("--name").into_iter().collect()
    };
    if matches!(operation, CREDENTIAL_READ | CREDENTIAL_DELETE) {
        let plural = matches!(args.verb(1), Some("get-parameters" | "delete-parameters"));
        let by_path = args.verb(1) == Some("get-parameters-by-path");
        let name_flag = match (plural, by_path) {
            (true, _) => "--names",
            (_, true) => "--path",
            _ => "--name",
        };
        let values = [&[name_flag, "--region", "--profile"][..], AWS_OUTPUT_VALUES].concat();
        let booleans = match (operation, by_path) {
            (CREDENTIAL_READ, true) => &[
                "--with-decryption",
                "--no-with-decryption",
                "--recursive",
                "--no-recursive",
            ][..],
            (CREDENTIAL_READ, false) => &["--with-decryption", "--no-with-decryption"][..],
            _ => &[][..],
        };
        let adjacent_names = adjacent_list_len(ctx.argv, name_flag);
        // get-parameter responds with one `Parameter`; the plural and path
        // reads respond with a `Parameters` list, which for get-parameters
        // holds at most one parameter per requested name.
        let bound = plural.then_some(names.len());
        let value_path: &[Step] = if plural || by_path {
            &[
                Step::Key("Parameters"),
                Step::Each(bound),
                Step::Key("Value"),
            ]
        } else {
            &[Step::Key("Parameter"), Step::Key("Value")]
        };
        // What the response prints decides only whether a read discloses the
        // value; a deletion happens whatever its response shows.
        let exact = strict_args(ctx.argv, &values, &[booleans, AWS_OUTPUT_SWITCHES].concat())
            && (operation != CREDENTIAL_READ
                || output_prints(&args, &["--query"], |query| query_prints(query, value_path))
                    && output_prints(&args, &["--output"], |output| {
                        AWS_PRINTING_FORMATS.contains(&output)
                    }))
            && !names.is_empty()
            && names.len() <= if plural { 10 } else { 1 }
            && args.operands.len() == 2 + if plural { names.len() - 1 } else { 0 }
            && (!plural || adjacent_names == names.len())
            && !(args.flag("--with-decryption").is_some()
                && args.flag("--no-with-decryption").is_some())
            && !(args.flag("--recursive").is_some() && args.flag("--no-recursive").is_some())
            && names.iter().all(|name| {
                name.as_literal().is_some_and(|text| {
                    !text.is_empty()
                        && text.len() <= 2048
                        && text.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'/' | b':' | b'.' | b'_' | b'-')
                        })
                        && !text.starts_with("file:")
                        && !text.starts_with("fileb:")
                })
            });
        if exact {
            request_exact = true;
            if operation == CREDENTIAL_READ {
                // Without --with-decryption a SecureString comes back
                // encrypted and a String parameter may be plain
                // configuration, so only a decrypting read proves the value.
                if args.flag("--with-decryption").is_some() {
                    attrs.insert("mode".into(), AttrValue::String("value".into()));
                }
                attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
                attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            }
        } else {
            unmodeled(builder, node);
        }
    }
    let targets = if names.is_empty() {
        vec![unresolved_resource("credential")]
    } else {
        names
            .into_iter()
            .map(|name| named("aws-ssm", None, Some(name)))
            .collect()
    };
    emit_credential_effects(builder, ctx, node, operation, targets, attrs, request_exact)
}
const AZ_KEYVAULT_VALUES: &[&str] = &[
    "--vault-name",
    "--name",
    "-n",
    "--id",
    "--value",
    "--subscription",
    "--version",
    "--query",
    "--output",
    "-o",
    "--location",
    "-l",
    "--resource-group",
    "-g",
    "--file",
    "-f",
    "--encoding",
    "-e",
];
/// Whether `az keyvault secret download` writes the secret to its own
/// standard output.
pub(crate) fn az_download_to_stdout(argv: &[Word]) -> bool {
    let args = Args::parse(argv, AZ_KEYVAULT_VALUES);
    args.flag("--file")
        .or_else(|| args.flag("-f"))
        .is_some_and(names_stdout_device)
}
pub(crate) fn az_keyvault(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    let args = Args::parse(ctx.argv, AZ_KEYVAULT_VALUES);
    let name = args.flag("--name").or_else(|| args.flag("-n"));
    // A data-plane object ID is https://VAULT.vault.azure.net/COLLECTION/NAME[/VERSION];
    // the SDK reads the vault, name and version from it whatever the collection.
    let id = args.flag("--id").map(|id| {
        id.as_literal()
            .and_then(|id| id.strip_prefix("https://"))
            .and_then(|id| id.split_once(".vault.azure.net/"))
            .and_then(|(vault, path)| {
                let mut segments = path.trim_end_matches('/').split('/').skip(1);
                let object = segments.next().filter(|name| !name.is_empty())?;
                let version = segments.next();
                segments
                    .next()
                    .is_none()
                    .then(|| (Word::literal(vault), Word::literal(object), version))
            })
    });
    let mut attrs = Attrs::new();
    let mut request_exact = false;
    let (operation, target) = match (args.verb(1), args.verb(2)) {
        (Some(verb @ ("purge" | "delete")), None) => {
            if verb == "purge" {
                flag(&mut attrs, "destroy");
            } else {
                // A deleted vault stays recoverable until it is purged or its
                // retention period ends.
                recoverable(&mut attrs);
            }
            (CREDENTIAL_DELETE, store_resource("azure-keyvault", name))
        }
        (
            Some(kind @ ("secret" | "key" | "certificate")),
            Some(verb @ ("show" | "set" | "delete" | "purge" | "download")),
        ) if kind == "secret" || matches!(verb, "delete" | "purge") => {
            let operation = match verb {
                "show" | "download" => CREDENTIAL_READ,
                "set" => CREDENTIAL_WRITE,
                _ => CREDENTIAL_DELETE,
            };
            match verb {
                "purge" => flag(&mut attrs, "destroy"),
                // Key Vault soft delete is not optional: a deleted object stays
                // recoverable until it is purged or the retention period ends.
                "delete" => recoverable(&mut attrs),
                _ => {}
            }
            let (vault, object) = match &id {
                Some(Some((vault, object, version))) => {
                    if let Some(version) = version {
                        attrs.insert("version".into(), AttrValue::String((*version).into()));
                    }
                    (Some(vault), Some(object))
                }
                Some(None) => (None, None),
                None => (args.flag("--vault-name"), name),
            };
            // Secrets, keys and certificates share a vault but not a namespace.
            let object = object.map(|object| {
                if kind == "secret" {
                    object.clone()
                } else {
                    join_store(Some(&Word::literal(format!("{kind}s"))), Some(object)).unwrap()
                }
            });
            let target = if vault.is_none() {
                unresolved_resource("credential")
            } else {
                named("azure-keyvault", vault, object.as_ref())
            };
            (operation, target)
        }
        _ => {
            unmodeled(builder, node);
            return false;
        }
    };
    let file = args.flag("--file").or_else(|| args.flag("-f"));
    let exact = match (args.verb(1), args.verb(2)) {
        (Some("purge"), None) => {
            strict_args(
                ctx.argv,
                &["--name", "-n", "--location", "-l", "--subscription"],
                &[],
            ) && name.is_some()
        }
        (Some("delete"), None) => {
            strict_args(
                ctx.argv,
                &["--name", "-n", "--resource-group", "-g", "--subscription"],
                &[],
            ) && name.is_some()
        }
        (Some(_), Some(verb @ ("show" | "delete" | "purge" | "download"))) => {
            let mut values = [&["--subscription"][..], AZ_OUTPUT_VALUES].concat();
            if id.is_some() {
                values.push("--id");
            } else {
                values.extend(["--vault-name", "--name", "-n"]);
            }
            if verb == "download" {
                values.extend(["--file", "-f", "--encoding", "-e"]);
            }
            args.operands.len() == 3
                // --file and -f are one option whose last spelling wins.
                && (verb != "download"
                    || file.is_some() && !(args.flag("--file").is_some() && args.flag("-f").is_some()))
                && (id.is_some() || args.flag("--vault-name").is_some() && name.is_some())
                && strict_args(ctx.argv, &values, AZ_OUTPUT_SWITCHES)
                && (verb != "show"
                    || output_prints(&args, &["--query"], |query| {
                        query_prints(query, &[Step::Key("value")])
                    }) && output_prints(&args, &["--output", "-o"], |output| {
                        AZ_PRINTING_FORMATS.contains(&output)
                    }))
        }
        _ => false,
    };
    let exact = exact
        && !matches!(target, ResourceExpr::Unresolved { .. })
        && [args.flag("--vault-name"), name]
            .into_iter()
            .flatten()
            .all(|word| {
                word.as_literal().is_some_and(|text| {
                    !text.is_empty()
                        && text
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            });
    if operation == CREDENTIAL_READ && args.verb(2) == Some("download") {
        let output = if file.is_some_and(names_stdout_device) {
            "stdout"
        } else {
            "file"
        };
        attrs.insert("output".into(), AttrValue::String(output.into()));
        if let Some(file) = file {
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
            arg_effect(
                builder,
                ctx,
                node,
                0,
                "filesystem.write",
                ctx.resolve_fs_word(file),
                Attrs::new(),
            );
        }
    }
    if exact {
        request_exact = true;
        if operation == CREDENTIAL_READ {
            attrs.insert("mode".into(), AttrValue::String("value".into()));
            attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
        }
    } else if matches!(operation, CREDENTIAL_READ | CREDENTIAL_DELETE) {
        unmodeled(builder, node);
    }
    args.attr(&mut attrs, "version", &["--version"]);
    emit_credential_effects(
        builder,
        ctx,
        node,
        operation,
        vec![target],
        attrs,
        request_exact,
    )
}
pub(crate) fn gcloud_secrets(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
) -> bool {
    let mut args = Args::parse(
        ctx.argv,
        &[
            "--secret",
            "--project",
            "--account",
            "--configuration",
            "--data-file",
            "--etag",
            "--location",
            "--format",
            "--verbosity",
        ],
    );
    // The alpha and beta release tracks run the same secrets commands.
    if matches!(args.verb(0), Some("alpha" | "beta")) {
        args.operands.remove(0);
    }
    let mut attrs = Attrs::new();
    let mut request_exact = false;
    let (operation, name) = match (args.verb(1), args.verb(2)) {
        (Some("create"), _) => (CREDENTIAL_WRITE, args.operands.get(2)),
        (Some("delete"), _) => {
            flag(&mut attrs, "destroy");
            (CREDENTIAL_DELETE, args.operands.get(2))
        }
        (Some("versions"), Some(verb @ ("access" | "add" | "destroy"))) => {
            let operation = match verb {
                "access" => CREDENTIAL_READ,
                "add" => CREDENTIAL_WRITE,
                _ => CREDENTIAL_DELETE,
            };
            // Version destruction is immediate unless the secret's
            // server-side delayed-destruction policy keeps the version
            // restorable for its TTL: that remote setting, not the
            // invocation, decides recovery.
            if verb == "destroy" {
                attrs.insert("deletion".into(), AttrValue::String("remote_policy".into()));
            }
            if verb == "access" {
                attrs.insert("mode".into(), AttrValue::String("value".into()));
                attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
                attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            }
            if let Some(version) = args.verb(3) {
                attrs.insert("version".into(), AttrValue::String(version.into()));
            }
            (operation, args.flag("--secret"))
        }
        _ => {
            unmodeled(builder, node);
            return false;
        }
    };
    let exact = match (args.verb(1), args.verb(2)) {
        // --etag deletes only the secret's current revision; --location names
        // a regional secret.
        (Some("delete"), Some(_)) => {
            args.operands.len() == 3
                && strict_args(
                    ctx.argv,
                    &[
                        "--project",
                        "--account",
                        "--configuration",
                        "--etag",
                        "--location",
                    ],
                    &["--quiet"],
                )
        }
        (Some("versions"), Some("access" | "destroy")) => {
            args.operands.len() == 4
                && args.flag("--secret").is_some()
                && args.verb(3).is_some_and(|version| {
                    (version == "latest" && operation == CREDENTIAL_READ)
                        || version.parse::<u64>().is_ok_and(|version| version > 0)
                })
                && strict_args(
                    ctx.argv,
                    &[
                        &["--secret", "--project", "--account", "--configuration"][..],
                        GCLOUD_OUTPUT_VALUES,
                    ]
                    .concat(),
                    &["--quiet"],
                )
                && (operation != CREDENTIAL_READ
                    || output_prints(&args, &["--format"], gcloud_format_prints))
        }
        _ => false,
    };
    let exact = exact
        && name.and_then(Word::as_literal).is_some_and(|text| {
            !text.is_empty()
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        });
    if exact {
        request_exact = true;
    } else if matches!(operation, CREDENTIAL_READ | CREDENTIAL_DELETE) {
        unmodeled(builder, node);
    }
    emit_credential_effects(
        builder,
        ctx,
        node,
        operation,
        vec![named("gcloud", args.flag("--location"), name)],
        attrs,
        request_exact,
    )
}

struct Doppler;
impl CommandModel for Doppler {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "credential/doppler@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["doppler"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let args = Args::parse(argv, DOPPLER_VALUE_FLAGS);
        read_output(
            args.verb(1) == Some("download")
                && args.flag("--no-file").and_then(Word::as_literal) != Some("true"),
        )
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let args = Args::parse(ctx.argv, DOPPLER_VALUE_FLAGS);
        let mut attrs = Attrs::new();
        let mut request_exact = false;
        let project = args.flag("--project").or_else(|| args.flag("-p"));
        let config = args.flag("--config").or_else(|| args.flag("-c"));
        let store = join_store(project, config);
        if args.verb(0) == Some("run") {
            doppler_run(builder, ctx, node, store.as_ref());
            return;
        }
        // Listing prints every secret's value unless its last --only-names is true.
        let names_only = args
            .flag("--only-names")
            .is_some_and(|value| value.as_literal() != Some("false"));
        let (operation, targets) = match (args.verb(0), args.verb(1)) {
            (Some("secrets"), None) if !names_only => (
                CREDENTIAL_READ,
                vec![resource("doppler", store.as_ref(), None)],
            ),
            (Some("secrets"), Some(verb @ ("get" | "download" | "set" | "delete"))) => {
                let operation = match verb {
                    "get" | "download" => CREDENTIAL_READ,
                    "set" => CREDENTIAL_WRITE,
                    _ => CREDENTIAL_DELETE,
                };
                if verb == "delete" {
                    // Secret deletions can be rolled back from the config log.
                    recoverable(&mut attrs);
                }
                (
                    operation,
                    if verb == "download" {
                        vec![resource("doppler", store.as_ref(), None)]
                    } else {
                        secret_names(
                            "doppler",
                            store.as_ref(),
                            &args.operands[2..],
                            verb == "set",
                            verb == "get",
                        )
                    },
                )
            }
            (Some("projects"), Some("delete")) => {
                flag(&mut attrs, "destroy");
                (
                    CREDENTIAL_DELETE,
                    vec![store_resource("doppler", args.operands.get(2).or(project))],
                )
            }
            // A config, or an environment with every config in it, is deleted
            // with its secrets; neither has a restore command.
            (Some("configs" | "environments"), Some("delete")) => {
                flag(&mut attrs, "destroy");
                let name = if args.verb(0) == Some("configs") {
                    args.operands.get(2).or(config)
                } else {
                    args.operands.get(2)
                };
                (
                    CREDENTIAL_DELETE,
                    vec![match (project, name) {
                        (Some(_), Some(_)) => {
                            store_resource("doppler", join_store(project, name).as_ref())
                        }
                        _ => unresolved_resource("credential"),
                    }],
                )
            }
            _ => {
                unmodeled(builder, node);
                return;
            }
        };
        if operation == CREDENTIAL_READ {
            attrs.insert("mode".into(), AttrValue::String("value".into()));
            attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            let download = args.verb(1) == Some("download");
            let to_file =
                download && args.flag("--no-file").and_then(Word::as_literal) != Some("true");
            attrs.insert(
                "selector".into(),
                AttrValue::String(
                    if download || args.operands.len() <= 2 {
                        "store"
                    } else {
                        "secret_name"
                    }
                    .into(),
                ),
            );
            attrs.insert(
                "output".into(),
                AttrValue::String(if to_file { "file" } else { "stdout" }.into()),
            );
            if download {
                args.attr(&mut attrs, "format", &["--format"]);
                if to_file {
                    // Download writes encrypted secrets; its status message is not the payload.
                    let default = match args.flag("--format").and_then(Word::as_literal) {
                        None | Some("json") => Word::literal("doppler.json"),
                        Some("dotnet-json") => Word::literal("appsettings.json"),
                        Some("env" | "docker" | "env-no-quotes") => Word::literal("doppler.env"),
                        Some("yaml") => Word::literal("secrets.yaml"),
                        _ => Word::new(vec![WordPart::Unknown]),
                    };
                    let output = args.operands.get(2).unwrap_or(&default);
                    arg_effect(
                        builder,
                        ctx,
                        node,
                        0,
                        "filesystem.write",
                        ctx.resolve_fs_word(output),
                        Attrs::new(),
                    );
                }
            } else if args.flag("--json").and_then(Word::as_literal) == Some("true") {
                attrs.insert("format".into(), AttrValue::String("json".into()));
            } else if args.flag("--plain").and_then(Word::as_literal) == Some("true") {
                attrs.insert("format".into(), AttrValue::String("plain".into()));
            }
        }
        // An omitted --project or --config is resolved from the local doppler
        // configuration: the request is still exact, but its target then
        // names only the part the invocation gives.
        let exact = match (args.verb(0), args.verb(1)) {
            (Some("secrets"), None) => args.operands.len() == 1,
            (Some("secrets"), Some("get" | "delete")) => true,
            (Some("secrets"), Some("download")) => args.operands.len() <= 3,
            (Some("projects"), Some("delete")) => {
                args.operands.len() == 3 || args.operands.len() == 2 && project.is_some()
            }
            (Some("configs"), Some("delete")) => {
                args.operands.len() == 3 || args.operands.len() == 2 && config.is_some()
            }
            (Some("environments"), Some("delete")) => args.operands.len() == 3,
            _ => false,
        };
        // The last --only-names decides, so its repetitions are one control.
        let controls: Vec<_> = ctx
            .argv
            .iter()
            .filter(|word| {
                args.verb(1).is_some()
                    || word
                        .as_literal()
                        .is_none_or(|text| text.split('=').next() != Some("--only-names"))
            })
            .cloned()
            .collect();
        if exact
            && (args.flag("--no-file").is_none() || args.verb(1) == Some("download"))
            && strict_args(
                &controls,
                &[
                    "--project",
                    "-p",
                    "--config",
                    "-c",
                    "--token",
                    "--format",
                    "--configuration",
                ],
                &[
                    "--plain",
                    "--raw",
                    "--json",
                    "--silent",
                    "--yes",
                    "-y",
                    "--no-file",
                ],
            )
            && targets
                .iter()
                .all(|target| !matches!(target, ResourceExpr::Unresolved { .. }))
        {
            request_exact = true;
        }
        emit_credential_effects(builder, ctx, node, operation, targets, attrs, request_exact);
    }
}
/// `doppler run [options] -- command…` and `doppler run [options] --command
/// STRING` fetch the selected config's secrets and run the command with each
/// one added to its environment under a name the invocation does not state.
/// The child's environment records the read as its injection, so a read of
/// that environment reaching output discloses the secrets. Mounts and fallback
/// files change where the secrets land, and stay unmodeled.
fn doppler_run(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    store: Option<&Word>,
) {
    const VALUES: &[&str] = &[
        "--project",
        "-p",
        "--config",
        "-c",
        "--token",
        "--configuration",
    ];
    let separator = ctx
        .argv
        .iter()
        .position(|word| word.as_literal() == Some("--"));
    // The word that selects the child (`--` or `--command`) and the first
    // word naming it.
    let (words, option_index, child_index) = match separator {
        Some(separator) if strict_args(&ctx.argv[..separator], VALUES, &[]) => {
            (ctx.argv[separator + 1..].to_vec(), separator, separator + 1)
        }
        Some(_) => (Vec::new(), 0, 0),
        None => doppler_command(ctx.argv, &[VALUES, &["--command"]].concat()),
    };
    if words.is_empty() {
        unmodeled(builder, node);
        return;
    }
    let mut attrs = Attrs::new();
    let request_exact = true;
    attrs.insert("mode".into(), AttrValue::String("value".into()));
    attrs.insert("workflow".into(), AttrValue::String("run".into()));
    attrs.insert("purpose".into(), AttrValue::String("program_input".into()));
    attrs.insert("selector".into(), AttrValue::String("store".into()));
    let start = builder.effects_len() as u32;
    emit_credential_effects(
        builder,
        ctx,
        node,
        CREDENTIAL_READ,
        vec![resource("doppler", store, None)],
        attrs,
        request_exact,
    );
    let reads = (start..builder.effects_len() as u32)
        .filter(|effect| {
            matches!(
                builder.effect_operation(*effect as usize),
                Some(CREDENTIAL_READ | CREDENTIAL_READ_REQUEST)
            )
        })
        .collect::<Vec<_>>();
    let producer = builder.pending_flow_stage(crate::flow::FlowStage {
        execution: Some(builder.current_execution()),
        effects: reads.clone(),
        bindings: reads
            .iter()
            .map(|read| crate::flow::PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: crate::flow::BindEnd::Effect(*read),
                to: crate::flow::BindEnd::Port(Port::Stdout),
            })
            .collect(),
        provenance: vec![node],
    }) as u32;
    let injection = arg_node(builder, ctx, option_index as u32);
    builder.register_environment_value_producers(
        injection,
        &[crate::flow::FlowRef {
            stage: producer,
            port: Port::Stdout,
        }],
    );
    let arg = arg_node(builder, ctx, child_index as u32);
    let argv_provenance = if separator.is_some() {
        ctx.argv_provenance_range(builder, child_index..ctx.argv.len())
    } else {
        vec![ctx.argv_provenance_at(builder, child_index); words.len()]
    };
    let (cwd, cwd_resource, runtime_cwd, cwd_node) = ctx.command_cwd(builder, None);
    ctx.nest.nest(
        builder,
        crate::nest::Transition::exec(
            words.iter().map(crate::nest::word_resource).collect(),
            words.to_vec(),
        )
        .exec_cwd(cwd.as_deref())
        .cwd(cwd_resource, cwd_node)
        .stdin(ctx.stdin)
        .runtime_cwd(runtime_cwd.as_deref())
        .argv_provenance(Some(argv_provenance.as_slice()))
        .kind(effinterp_proto::ExecutionEdgeKind::ToolModel)
        .environment(
            BTreeMap::new(),
            BTreeMap::from([(crate::nest::INJECTED_ENVIRONMENT.to_string(), injection)]),
            Default::default(),
        ),
        &[node, arg],
        ctx.depth,
    );
}

// Doppler runs a `--command` string through `$SHELL -c` when SHELL names bash,
// dash, fish, zsh, ksh, csh or tcsh, and through `sh -c` otherwise. Nah does
// not observe SHELL, so only a string without shell syntax, which each of those
// shells splits into the same plain words, resolves: to those words, with the
// indices of the option and of the argument holding them. Anything else
// resolves to no words.
fn doppler_command(argv: &[Word], values: &[&str]) -> (Vec<Word>, usize, usize) {
    let Some(index) = argv.iter().position(|word| {
        word.as_literal()
            .is_some_and(|text| text == "--command" || text.starts_with("--command="))
    }) else {
        return (Vec::new(), 0, 0);
    };
    let args = Args::parse(argv, values);
    let Some(command) = args.flag("--command").and_then(Word::as_literal) else {
        return (Vec::new(), 0, 0);
    };
    // A newline would end the command, so only blanks separate words.
    let words: Vec<_> = command
        .split([' ', '\t'])
        .filter(|word| !word.is_empty())
        .collect();
    let plain = words.iter().enumerate().all(|(position, word)| {
        word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'.' | b'/' | b':' | b',' | b'+' | b'-')
                // csh would run `NAME=value` as a command, not an assignment.
                || byte == b'=' && position > 0
        })
    });
    if !plain || args.operands.len() != 1 || !strict_args(argv, values, &[]) {
        return (Vec::new(), 0, 0);
    }
    let value = index + usize::from(!argv[index].as_literal().unwrap().contains('='));
    (words.into_iter().map(Word::literal).collect(), index, value)
}

const DOPPLER_VALUE_FLAGS: &[&str] = &[
    "--project",
    "-p",
    "--config",
    "-c",
    "--format",
    "--token",
    "--configuration",
];

fn secret_names(
    provider: &str,
    store: Option<&Word>,
    names: &[Word],
    assignments: bool,
    store_read: bool,
) -> Vec<ResourceExpr> {
    if names.is_empty() {
        return vec![if store_read {
            resource(provider, store, None)
        } else {
            unresolved_resource("credential")
        }];
    }
    names
        .iter()
        .map(|name| {
            let key = if assignments {
                // Only the key identifies the secret; a symbolic value is still a known write.
                match name.parts.first() {
                    Some(WordPart::Literal(text)) if text.contains('=') => {
                        Word::literal(text.split_once('=').unwrap().0)
                    }
                    _ => name.clone(),
                }
            } else {
                name.clone()
            };
            named(provider, store, Some(&key))
        })
        .collect()
}
struct Infisical;
impl CommandModel for Infisical {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "credential/infisical@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["infisical"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let args = Args::parse(
            argv,
            &[
                "--projectId",
                "--env",
                "--format",
                "--path",
                "--name",
                "--token",
                "--output-file",
            ],
        );
        read_output(args.verb(0) == Some("export") && args.flag("--output-file").is_some())
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let args = Args::parse(
            ctx.argv,
            &[
                "--projectId",
                "--env",
                "--format",
                "--path",
                "--name",
                "--token",
                "--output-file",
            ],
        );
        let store = join_store(args.flag("--projectId"), args.flag("--env"));
        // Secrets and folders live under a folder path; the root adds nothing.
        let folder = args.flag("--path").map(|path| {
            path.as_literal().map_or_else(
                || path.clone(),
                |path| Word::literal(path.trim_matches('/')),
            )
        });
        let folder = folder.filter(|path| path.as_literal() != Some(""));
        let in_folder = |name: &Word| {
            folder.as_ref().map_or_else(
                || name.clone(),
                |folder| join_store(Some(folder), Some(name)).unwrap(),
            )
        };
        let mut attrs = Attrs::new();
        let mut request_exact = false;
        let (operation, targets) = match (args.verb(0), args.verb(1), args.verb(2)) {
            // Listing a folder's secrets prints their values.
            (Some("export"), _, _) | (Some("secrets"), None, _) => (
                CREDENTIAL_READ,
                vec![resource("infisical", store.as_ref(), folder.as_ref())],
            ),
            (Some("secrets"), Some("folders"), Some("delete")) => {
                // Commit history retains deleted folders and secrets for restoration.
                recoverable(&mut attrs);
                (
                    CREDENTIAL_DELETE,
                    vec![named(
                        "infisical",
                        store.as_ref(),
                        args.flag("--name").map(in_folder).as_ref(),
                    )],
                )
            }
            (Some("secrets"), Some(verb @ ("get" | "set" | "delete")), _) => {
                let operation = match verb {
                    "get" => CREDENTIAL_READ,
                    "set" => CREDENTIAL_WRITE,
                    _ => CREDENTIAL_DELETE,
                };
                if verb == "delete" {
                    recoverable(&mut attrs);
                }
                (
                    operation,
                    secret_names(
                        "infisical",
                        store.as_ref(),
                        &args.operands[2..].iter().map(in_folder).collect::<Vec<_>>(),
                        verb == "set",
                        false,
                    ),
                )
            }
            _ => {
                unmodeled(builder, node);
                return;
            }
        };
        if operation == CREDENTIAL_READ {
            attrs.insert("mode".into(), AttrValue::String("value".into()));
            attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            attrs.insert(
                "selector".into(),
                AttrValue::String(
                    if args.verb(1).is_none() {
                        "store"
                    } else {
                        "secret_name"
                    }
                    .into(),
                ),
            );
            let output = if args.verb(0) == Some("export") {
                args.flag("--output-file")
            } else {
                None
            };
            attrs.insert(
                "output".into(),
                AttrValue::String(if output.is_some() { "file" } else { "stdout" }.into()),
            );
            if let Some(output) = output {
                // Export also accepts directories; without filesystem evidence the
                // destination may be a file inside the named directory.
                arg_effect(
                    builder,
                    ctx,
                    node,
                    0,
                    "filesystem.write",
                    unresolved_resource("filesystem"),
                    Attrs::new(),
                );
                if let Some(path) = output.as_literal() {
                    attrs.insert("output_path".into(), AttrValue::String(path.into()));
                }
            }
            args.attr(&mut attrs, "format", &["--format"]);
            if args.flag("--plain").and_then(Word::as_literal) == Some("true") {
                attrs.insert("format".into(), AttrValue::String("plain".into()));
            }
        }
        // Infisical addresses a secret by project, environment and folder path.
        let exact = match (args.verb(0), args.verb(1), args.verb(2)) {
            (Some("export" | "secrets"), None, _) => args.operands.len() == 1,
            (Some("secrets"), Some("folders"), Some("delete")) => args.operands.len() == 3,
            (Some("secrets"), Some("get" | "delete"), _) => true,
            _ => false,
        };
        if exact
            && (args.flag("--output-file").is_none() || args.verb(0) == Some("export"))
            && args.flag("--projectId").is_some()
            && args.flag("--env").is_some()
            && strict_args(
                ctx.argv,
                &[
                    "--projectId",
                    "--env",
                    "--format",
                    "--path",
                    "--name",
                    "--token",
                    "--output-file",
                ],
                if args.verb(1) == Some("get") {
                    &["--plain", "--silent"]
                } else {
                    &[]
                },
            )
            && targets
                .iter()
                .all(|target| !matches!(target, ResourceExpr::Unresolved { .. }))
        {
            request_exact = true;
        }
        emit_credential_effects(builder, ctx, node, operation, targets, attrs, request_exact);
    }
}
const OP_VALUE_FLAGS: &[&str] = &["--vault", "--account", "--format", "--out-file", "--fields"];

struct Op;
impl CommandModel for Op {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "credential/op@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["op"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        let args = Args::parse(argv, OP_VALUE_FLAGS);
        read_output(
            matches!(
                (args.verb(0), args.verb(1)),
                (Some("read"), _) | (Some("document"), Some("get"))
            ) && args.flag("--out-file").is_some(),
        )
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let args = Args::parse(ctx.argv, OP_VALUE_FLAGS);
        let mut attrs = Attrs::new();
        let mut request_exact = false;
        let (operation, target) = match (args.verb(0), args.verb(1)) {
            (Some("read"), _) => {
                let target = args
                    .verb(1)
                    .and_then(|s| s.strip_prefix("op://"))
                    .and_then(|s| s.split_once('/'))
                    .map(|(vault, path)| {
                        resource(
                            "1password",
                            Some(&Word::literal(vault)),
                            Some(&Word::literal(path)),
                        )
                    })
                    .unwrap_or_else(|| unresolved_resource("credential"));
                (CREDENTIAL_READ, target)
            }
            // A document is an item whose payload is a file.
            (Some("item" | "document"), Some(verb @ ("get" | "delete"))) => {
                // Ordinary deletes enter Recently Deleted. `--archive` moves
                // the item to the vault's Archive instead, where it stays
                // intact and can be restored, so it changes the item rather
                // than deleting it.
                let archive = verb == "delete"
                    && op_archive(ctx.argv).is_some_and(|archive| archive == Some(true));
                if archive {
                    flag(&mut attrs, "archive");
                } else if verb == "delete" {
                    recoverable(&mut attrs);
                }
                (
                    if verb == "get" {
                        CREDENTIAL_READ
                    } else if archive {
                        CREDENTIAL_WRITE
                    } else {
                        CREDENTIAL_DELETE
                    },
                    named("1password", args.flag("--vault"), args.operands.get(2)),
                )
            }
            (Some("vault"), Some("delete")) => {
                flag(&mut attrs, "destroy");
                (
                    CREDENTIAL_DELETE,
                    store_resource("1password", args.operands.get(2)),
                )
            }
            _ => {
                unmodeled(builder, node);
                return;
            }
        };
        if matches!(args.verb(0), Some("item" | "document")) && args.operands.len() != 3 {
            unmodeled(builder, node);
            return;
        }
        let writes_file = matches!(
            (args.verb(0), args.verb(1)),
            (Some("read"), _) | (Some("document"), Some("get"))
        );
        if operation == CREDENTIAL_READ {
            attrs.insert("mode".into(), AttrValue::String("value".into()));
            attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
            attrs.insert(
                "selector".into(),
                AttrValue::String(
                    args.verb(0)
                        .map_or("path", |verb| match verb {
                            "read" => "path",
                            other => other,
                        })
                        .into(),
                ),
            );
            let output = if writes_file {
                args.flag("--out-file")
            } else {
                None
            };
            attrs.insert(
                "output".into(),
                AttrValue::String(if output.is_some() { "file" } else { "stdout" }.into()),
            );
            args.attr(&mut attrs, "format", &["--format"]);
            if let Some(output) = output {
                arg_effect(
                    builder,
                    ctx,
                    node,
                    0,
                    "filesystem.write",
                    ctx.resolve_fs_word(output),
                    Attrs::new(),
                );
            }
        }
        // An item name without a vault is looked up in every vault the account
        // can see: the request is still exact, but its target names no vault.
        let (values, booleans): (&[&str], &[&str]) = match (args.verb(0), args.verb(1)) {
            (Some("read"), _) => (&["--account", "--out-file"], &["-n", "--no-newline"]),
            (Some("item"), Some("get")) => (
                &["--vault", "--account", "--format", "--fields"],
                &["--reveal", "--otp"],
            ),
            (Some("item"), Some("delete")) => {
                (&["--vault", "--account", "--format"], &["--archive"])
            }
            (Some("document"), Some("get")) => (&["--vault", "--account", "--out-file"], &[]),
            (Some("document"), Some("delete")) => (&["--vault", "--account"], &["--archive"]),
            _ => (&["--vault", "--account", "--format"], &[]),
        };
        let exact = match (args.verb(0), args.verb(1)) {
            (Some("read"), Some(_)) => args.operands.len() == 2,
            (Some("item" | "document"), Some("get" | "delete")) => true,
            (Some("vault"), Some("delete")) => args.operands.len() == 3,
            _ => false,
        };
        // An explicit `--archive=<bool>` is as settled as the bare switch.
        let controls: Vec<_> = ctx
            .argv
            .iter()
            .map(|word| {
                match word
                    .as_literal()
                    .and_then(|text| text.strip_prefix("--archive="))
                {
                    Some(value) if go_bool(value).is_some() => Word::literal("--archive"),
                    _ => word.clone(),
                }
            })
            .collect();
        if exact
            && op_archive(ctx.argv).is_some()
            && strict_args(&controls, values, booleans)
            && !matches!(target, ResourceExpr::Unresolved { .. })
        {
            request_exact = true;
        }
        emit_credential_effects(
            builder,
            ctx,
            node,
            operation,
            vec![target],
            attrs,
            request_exact,
        );
    }
}

/// strconv.ParseBool, which cobra uses for `--flag=<bool>`.
fn go_bool(text: &str) -> Option<bool> {
    match text {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// The `--archive` setting the op CLI ends with: `Some(None)` when absent,
/// `Some(Some(value))` for the last spelling, and None when a value is not a
/// literal boolean, which the CLI rejects or leaves unknown.
fn op_archive(argv: &[Word]) -> Option<Option<bool>> {
    let mut archive = Some(None);
    for word in &argv[1..] {
        let Some(text) = word.as_literal() else {
            if word.literal_prefix().starts_with("--archive") {
                return None;
            }
            continue;
        };
        if text == "--" {
            break;
        }
        if text == "--archive" {
            archive = Some(Some(true));
        } else if let Some(value) = text.strip_prefix("--archive=") {
            archive = Some(Some(go_bool(value)?));
        }
    }
    archive
}

/// Whether an output file option names the program's own standard output.
fn names_stdout_device(word: &Word) -> bool {
    matches!(
        word.as_literal(),
        Some("/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1")
    )
}

/// Mark a value read the invocation asks for by name, as the cloud secret
/// reads do.
fn value_read(attrs: &mut Attrs) {
    attrs.insert("mode".into(), AttrValue::String("value".into()));
    attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
    attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
}

// Global options of the Bitwarden password-manager CLI that do not change what
// `get` prints. `--quiet` silences the output and `--response` wraps it.
const BW_VALUES: &[&str] = &["--session"];
const BW_SWITCHES: &[&str] = &["--raw", "--pretty", "--nointeraction", "--cleanexit"];

struct Bitwarden;
impl CommandModel for Bitwarden {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }
    fn id(&self) -> &'static str {
        "credential/bw@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["bw"]
    }
    fn causal_bindings(&self, _: &[Word]) -> Vec<ModelCausalBinding> {
        read_output(false)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let args = Args::parse(ctx.argv, BW_VALUES);
        // `get password|notes` print that field of the matching item; `get
        // item` prints the whole item, login password included. A search term
        // matching several items fails rather than choosing one.
        if !(args.verb(0) == Some("get")
            && matches!(args.verb(1), Some("password" | "notes" | "item")))
        {
            unmodeled(builder, node);
            return;
        }
        let mut attrs = Attrs::new();
        value_read(&mut attrs);
        let target = named("bitwarden", None, args.operands.get(2));
        let exact = args.operands.len() == 3
            && strict_args(ctx.argv, BW_VALUES, BW_SWITCHES)
            && !matches!(target, ResourceExpr::Unresolved { .. });
        if !exact {
            unmodeled(builder, node);
        }
        emit_credential_effects(
            builder,
            ctx,
            node,
            CREDENTIAL_READ,
            vec![target],
            attrs,
            exact,
        );
    }
}

// Options of the Bitwarden Secrets Manager CLI that do not change which
// secret `secret get` prints. Its `--output none` prints nothing.
const BWS_VALUES: &[&str] = &[
    "--output",
    "-o",
    "--color",
    "--profile",
    "--access-token",
    "-t",
];
const BWS_PRINTING_FORMATS: &[&str] = &["json", "yaml", "env", "table", "tsv"];

struct Bws;
impl CommandModel for Bws {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }
    fn id(&self) -> &'static str {
        "credential/bws@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["bws"]
    }
    fn causal_bindings(&self, _: &[Word]) -> Vec<ModelCausalBinding> {
        read_output(false)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let args = Args::parse(ctx.argv, BWS_VALUES);
        if (args.verb(0), args.verb(1)) != (Some("secret"), Some("get")) {
            unmodeled(builder, node);
            return;
        }
        let mut attrs = Attrs::new();
        value_read(&mut attrs);
        let target = named("bitwarden-secrets-manager", None, args.operands.get(2));
        let exact = args.operands.len() == 3
            && strict_args(ctx.argv, BWS_VALUES, &[])
            && output_prints(&args, &["--output", "-o"], |output| {
                BWS_PRINTING_FORMATS.contains(&output)
            })
            && !matches!(target, ResourceExpr::Unresolved { .. });
        if !exact {
            unmodeled(builder, node);
        }
        emit_credential_effects(
            builder,
            ctx,
            node,
            CREDENTIAL_READ,
            vec![target],
            attrs,
            exact,
        );
    }
}

// pass's own commands; any other first word runs a system extension of that
// name when one is installed (whatever PASSWORD_STORE_ENABLE_EXTENSIONS says),
// or else is shown as an entry.
const PASS_COMMANDS: &[&str] = &[
    "init", "help", "version", "show", "ls", "list", "find", "search", "grep", "insert", "add",
    "edit", "generate", "delete", "rm", "remove", "rename", "mv", "copy", "cp", "git",
];

/// A variable's value as this invocation sees it: `Some(Some(text))` when
/// known, `Some(None)` when known to be unset, and `None` when unobserved.
fn observed_env(ctx: &InvocationCtx, name: &str) -> Option<Option<String>> {
    match ctx.environment_value(name) {
        Some(ResourceExpr::Literal { value }) => Some(Some(value)),
        Some(_) => None,
        None => ctx
            .nest
            .current_environment_unsets()
            .contains(name)
            .then_some(None),
    }
}

struct Pass;
impl CommandModel for Pass {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "filesystem", "process"]
    }
    fn id(&self) -> &'static str {
        "credential/pass@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["pass"]
    }
    fn causal_bindings(&self, _: &[Word]) -> Vec<ModelCausalBinding> {
        read_output(false)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let first = ctx.argv.get(1).map(Word::as_literal);
        // `pass NAME` shows NAME unless an installed extension of that name
        // runs instead, which the engine cannot observe.
        let bare = matches!(first, Some(Some(word)) if !word.starts_with('-') && !PASS_COMMANDS.contains(&word));
        let shown = if bare {
            &ctx.argv[1..]
        } else if first == Some(Some("show")) {
            &ctx.argv[2..]
        } else {
            unmodeled(builder, node);
            return;
        };
        // Options (`--clip`, `--qrcode`) send the entry elsewhere, and no name
        // prints the store's tree.
        let name = match shown {
            [name] if name.as_literal().is_none_or(|text| !text.starts_with('-')) => name,
            _ => {
                unmodeled(builder, node);
                return;
            }
        };
        let mut unobserved = Vec::new();
        let mut env = |name: &str| {
            let value = observed_env(ctx, name);
            if value.is_none() {
                unobserved.push(ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
                });
            }
            value
        };
        // The store is PASSWORD_STORE_DIR, or ~/.password-store when it is
        // unset or empty. A bare name is never exact, so it needs no store.
        let store = if bare {
            None
        } else {
            match env("PASSWORD_STORE_DIR") {
                Some(Some(dir)) if !dir.is_empty() => Some(dir),
                Some(_) => match env("HOME") {
                    Some(Some(home)) => Some(crate::paths::join_cwd(&home, ".password-store")),
                    _ => None,
                },
                None => None,
            }
        };
        // `show` prints the tree instead when the name is a directory of the
        // store and not also an entry, so only an observed non-directory
        // proves a value read. pass strips one trailing slash and rejects `..`.
        let entry = name.as_literal().filter(|text| {
            !text.is_empty()
                && !text.starts_with('/')
                && !text.ends_with('/')
                && !text.split('/').any(|part| part == "..")
        });
        let listing_ruled_out = match (&store, entry) {
            (Some(store), Some(entry)) if store.starts_with('/') => {
                super::sysutils::find_observe(builder, &crate::paths::join_cwd(store, entry), node)
                    .is_some_and(|fact| {
                        let kind = if fact.kind == effinterp_proto::PathKind::Symlink {
                            fact.followed
                                .known()
                                .and_then(|target| target.kind.known().copied())
                        } else {
                            Some(fact.kind)
                        };
                        kind.is_some_and(|kind| kind != effinterp_proto::PathKind::Directory)
                    })
            }
            _ => false,
        };
        let exact = listing_ruled_out;
        if !exact {
            let observed = unobserved.is_empty();
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: (!observed).then_some(ResourceExpr::Union {
                        alternatives: unobserved,
                    }),
                    callee: None,
                    domains: std::iter::once("credential")
                        .chain((!observed).then_some("environment"))
                        .map(Domain::new)
                        .collect(),
                    provenance: vec![node],
                    limit: None,
                    detail: Some(
                        "pass runs an installed extension for a bare name, and prints the store's tree for a directory; neither was ruled out"
                            .into(),
                    ),
                },
                CoverageLevel::Partial,
            );
        }
        let mut attrs = Attrs::new();
        value_read(&mut attrs);
        emit_store_effects(
            builder,
            ctx,
            node,
            CREDENTIAL_READ,
            vec![named("pass", None, Some(name))],
            attrs,
            exact,
            false,
        );
    }
}

struct Gopass;
impl CommandModel for Gopass {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "network", "process"]
    }
    fn id(&self) -> &'static str {
        "credential/gopass@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["gopass"]
    }
    fn causal_bindings(&self, _: &[Word]) -> Vec<ModelCausalBinding> {
        read_output(false)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let args = Args::parse(ctx.argv, &[]);
        // `gopass NAME` shows NAME; no gopass command contains a slash.
        let name = match args.verb(0) {
            Some("show") => args.operands.get(1),
            Some(word) if word.contains('/') && ctx.argv.len() == 2 => args.operands.first(),
            _ => None,
        };
        let Some(name) = name else {
            unmodeled(builder, node);
            return;
        };
        // Like pass, gopass lists a folder given its name. Its store root and
        // mounts come from its configuration file, which the engine does not
        // read, so no invocation proves the name is an entry.
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("credential")],
                provenance: vec![node],
                limit: None,
                detail: Some("gopass stores and mounts come from its unread configuration".into()),
            },
            CoverageLevel::Partial,
        );
        let mut attrs = Attrs::new();
        value_read(&mut attrs);
        emit_credential_effects(
            builder,
            ctx,
            node,
            CREDENTIAL_READ,
            vec![named("gopass", None, Some(name))],
            attrs,
            false,
        );
    }
}

// sops options that do not change what a decryption prints: `--extract`
// selects part of the decrypted document, and the types and configuration
// only shape how it is parsed and printed.
const SOPS_VALUES: &[&str] = &[
    "--output",
    "--extract",
    "--input-type",
    "--output-type",
    "--config",
];
const SOPS_SWITCHES: &[&str] = &["-d", "--decrypt", "--ignore-mac", "--verbose"];

/// Whether sops decrypts, and the file it writes to instead of standard output.
fn sops_decrypt(argv: &[Word]) -> (bool, Option<Word>) {
    let args = Args::parse(argv, SOPS_VALUES);
    let decrypt = args.verb(0) == Some("decrypt")
        || args.flag("-d").is_some()
        || args.flag("--decrypt").is_some();
    let output = args
        .flag("--output")
        .filter(|word| !names_stdout_device(word))
        .cloned();
    (decrypt, output)
}

struct Sops;
impl CommandModel for Sops {
    fn domains(&self) -> &'static [&'static str] {
        &["credential", "filesystem", "network", "process"]
    }
    fn id(&self) -> &'static str {
        "credential/sops@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["sops"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        read_output(sops_decrypt(argv).1.is_some())
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let (decrypt, output) = sops_decrypt(ctx.argv);
        if !decrypt {
            unmodeled(builder, node);
            return;
        }
        let args = Args::parse(ctx.argv, SOPS_VALUES);
        let files = &args.operands[usize::from(args.verb(0) == Some("decrypt"))..];
        // A decryption reads the encrypted file and unwraps its data key,
        // locally or through a key service.
        let exact = files.len() == 1
            && files[0].as_literal().is_some_and(|file| !file.is_empty())
            && strict_args(ctx.argv, SOPS_VALUES, SOPS_SWITCHES);
        if !exact {
            unmodeled(builder, node);
        }
        if let [file] = files {
            arg_effect(
                builder,
                ctx,
                node,
                0,
                "filesystem.read",
                ctx.resolve_fs_word(file),
                program_input_attrs(),
            );
        }
        let mut attrs = Attrs::new();
        value_read(&mut attrs);
        attrs.insert(
            "output".into(),
            AttrValue::String(if output.is_some() { "file" } else { "stdout" }.into()),
        );
        if let Some(output) = &output {
            arg_effect(
                builder,
                ctx,
                node,
                0,
                "filesystem.write",
                ctx.resolve_fs_word(output),
                Attrs::new(),
            );
        }
        emit_credential_effects(
            builder,
            ctx,
            node,
            CREDENTIAL_READ,
            vec![named("sops", None, files.first().filter(|_| exact))],
            attrs,
            exact,
        );
    }
}
