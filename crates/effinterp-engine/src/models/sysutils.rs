//! System utilities whose destructive potential matters to a guard: `find`
//! (traversal, `-delete`, `-exec`), process signals (`kill`/`killall`/`pkill`),
//! filesystem mounting, archive (un)zipping, immutable-attribute changes, and
//! ACL edits (`setfacl`, macOS `chmod +a`, Windows `icacls`).

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, ObservationOutcome,
    ObservationQuery, PathFact, PathKind, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use super::archive::extraction_target;
use crate::builder::{PlanBuilder, WrittenSource};
use crate::models::args::{FlagSpec, scan, scan_operand_flags, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, arg_node, boundary, fs_arg_effect, fs_full_no_spawn, operand_effect,
    program_input_attrs, program_output_attrs, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx, ModelCausalBinding};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

pub(super) fn sysutils_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Find),
        Box::new(Kill),
        Box::new(Mount),
        Box::new(Zip),
        Box::new(Attr),
        Box::new(Icacls),
    ]
}

/// `find [roots...] [expression]`: leading non-flag operands are search roots
/// (a traversal read); `-delete` deletes them recursively; `-exec CMD {} ;`
/// runs a command per match, nested with the match path scoped to the roots.
struct Find;

impl CommandModel for Find {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "findutils/find@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["find"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // Leading options come before the start paths: -H, -L and -P choose
        // how symbolic links are treated (the last one wins), -D takes a
        // debug option list and -O an attached optimisation level.
        let mut traversal = FindTraversal::Physical;
        let mut i = 1;
        while let Some(option) = ctx.argv.get(i).and_then(Word::as_literal) {
            match option {
                "-L" => traversal = FindTraversal::Logical,
                "-H" => traversal = FindTraversal::StartPaths,
                "-P" => traversal = FindTraversal::Physical,
                "-D" => i += 1,
                _ if option.starts_with("-O") => {}
                _ => break,
            }
            i += 1;
        }
        let plain_traversal = i == 1;
        // Roots: leading operands before the first predicate (`-...`).
        let mut roots: Vec<(u32, Word)> = Vec::new();
        while i < ctx.argv.len() {
            match ctx.argv[i].as_literal() {
                Some(t) if t.starts_with('-') || t == "!" || t == "(" => break,
                _ => {
                    roots.push((i as u32, ctx.argv[i].clone()));
                    i += 1;
                }
            }
        }
        if roots.is_empty() {
            // Default root is the current directory.
            roots.push((0, Word::literal(".")));
        }

        // `-exec`/`-ok` run until a `;` or `+` terminator. Without one the
        // action is incomplete, and find reports a usage error and exits
        // before it traverses anything.
        // Each action keeps the tests that precede it, which decide whether
        // it runs for a visited path.
        let mut actions: Vec<(usize, usize, Vec<Word>)> = Vec::new();
        let mut tests: Vec<Word> = Vec::new();
        let mut output_files: Vec<(u32, &Word)> = Vec::new();
        // The tests before the first `-delete`, and whether an earlier action,
        // whose exit status the tests leave out, also decides whether it runs.
        let mut delete_tests: Option<(Vec<Word>, bool)> = None;
        let mut unresolved_selector = roots.iter().any(|(_, root)| root.as_literal().is_none());
        let mut j = i;
        while j < ctx.argv.len() {
            if ctx.argv[j]
                .as_literal()
                .is_some_and(|word| FIND_VALUE_TESTS.contains(&word))
            {
                tests.extend(ctx.argv[j..ctx.argv.len().min(j + 2)].iter().cloned());
                j += 2;
                continue;
            }
            // `-fprint`, `-fprint0` and `-fls` create or truncate the file
            // they name, and `-fprintf` takes a format after it. find opens
            // the file while it parses the expression, whatever the tests
            // later select.
            if let Some(action @ ("-fprint" | "-fprint0" | "-fls" | "-fprintf")) =
                ctx.argv[j].as_literal()
            {
                if let Some(file) = ctx.argv.get(j + 1) {
                    output_files.push(((j + 1) as u32, file));
                }
                j += if action == "-fprintf" { 3 } else { 2 };
                continue;
            }
            unresolved_selector |= ctx.argv[j].as_literal().is_none();
            if matches!(
                ctx.argv[j].as_literal(),
                Some("-exec" | "-execdir" | "-ok" | "-okdir")
            ) {
                let start = j + 1;
                let Some(end) = ctx.argv[start..]
                    .iter()
                    .position(|w| matches!(w.as_literal(), Some(";" | "+")))
                    .map(|p| start + p)
                else {
                    fs_full_no_spawn(builder);
                    return;
                };
                actions.push((start, end, tests.clone()));
                j = end + 1;
            } else {
                if ctx.argv[j].as_literal() == Some("-delete") && delete_tests.is_none() {
                    delete_tests = Some((tests.clone(), !actions.is_empty()));
                }
                tests.push(ctx.argv[j].clone());
                j += 1;
            }
        }

        for (index, file) in output_files {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.write",
                Default::default(),
            );
        }
        let has_delete = ctx.argv[i..]
            .iter()
            .any(|w| w.as_literal() == Some("-delete"));
        // `-follow` is the expression spelling of -L.
        if ctx.argv[i..]
            .iter()
            .any(|word| word.as_literal() == Some("-follow"))
        {
            traversal = FindTraversal::Logical;
        }
        // -mindepth and -maxdepth hold for the whole expression wherever they
        // are spelled. A depth that does not read as a number bounds nothing.
        let depth_option = |option| {
            ctx.argv[i..]
                .windows(2)
                .filter(|pair| pair[0].as_literal() == Some(option))
                .next_back()
                .and_then(|pair| pair[1].as_literal()?.parse::<usize>().ok())
        };
        let depths = FindDepths {
            min: depth_option("-mindepth").unwrap_or(0),
            max: depth_option("-maxdepth"),
        };
        // `-maxdepth 0` applies the tests and actions to the starting points
        // only, so the expression never descends past the named roots.
        let roots_only = depths.max == Some(0);

        let selector = positive_delete_selector(ctx.argv, i);
        let mut unmodeled_tests = false;
        let root_facts: Vec<Option<PathFact>> = roots
            .iter()
            .map(|(_, root)| match ctx.resolve_fs_word(root) {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => find_observe(builder, &path, model_node),
                _ => None,
            })
            .collect();
        for ((index, root), root_fact) in roots.iter().zip(&root_facts) {
            // Under -P a linked start path is examined as the link itself:
            // find reads nothing it points at, unless a trailing slash makes
            // the start path the directory the link points at.
            // `link/` and `link/.` both start in the directory the link
            // points at.
            let trailing_slash = root.as_literal().is_some_and(|root| {
                crate::models::common::trailing_slash_follows_link(root)
                    || root
                        .trim_end_matches('/')
                        .strip_suffix('.')
                        .is_some_and(crate::models::common::trailing_slash_follows_link)
            });
            let unfollowed_link = traversal == FindTraversal::Physical
                && !trailing_slash
                && root_fact
                    .as_ref()
                    .is_some_and(|fact| fact.kind == PathKind::Symlink);
            if !unfollowed_link {
                // Under -L the traversal also reads what the links below the
                // root name, so the read says it follows them.
                let mut read_attrs = if builder.stdout_unconsumed
                    && ctx.argv[i..]
                        .iter()
                        .all(|word| matches!(word.as_literal(), Some("-print" | "-print0" | "-ls")))
                {
                    attr_bool("metadata")
                } else {
                    program_input_attrs()
                };
                if traversal == FindTraversal::Logical {
                    read_attrs.insert("follow_links".into(), AttrValue::Bool(true));
                }
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    root,
                    "filesystem.read",
                    read_attrs,
                );
            }
            // `-delete` removes the entries its tests select, as an
            // `-exec rm {} +` there would be passed them. Tests that select
            // every entry, or may select the start path, keep the model of
            // its whole tree. Where a test the model does not apply, or a
            // depth bound, may leave part of that tree in place, the whole
            // tree is not established and the boundary says so.
            let named = delete_tests.as_ref().and_then(|(tests, after_action)| {
                let conjunction = find_conjunction(tests);
                // A name or path that every entry matches narrows nothing.
                let selects_all = conjunction.as_ref().is_some_and(|conjunction| {
                    conjunction.types.is_empty()
                        && !conjunction.filtered
                        && !conjunction
                            .names
                            .iter()
                            .any(|(name, _)| name.chars().any(|character| character != '*'))
                        && root.as_literal().is_some_and(|spelled| {
                            conjunction
                                .paths
                                .iter()
                                .all(|(path, _)| find_path_selects_every_entry(path, spelled))
                        })
                });
                if selects_all && !after_action {
                    unmodeled_tests |= depths.max.is_some_and(|max| max > 0);
                    return None;
                }
                // Every regular file below the start path is the whole of
                // what the tree holds, so the delete stays one of the tree.
                if find_selects_every_file(tests, depths) {
                    unmodeled_tests = true;
                    return None;
                }
                // The name globs do not spell a case-insensitive test here.
                if conjunction.is_some_and(|conjunction| {
                    conjunction
                        .names
                        .iter()
                        .chain(&conjunction.paths)
                        .any(|(_, fold)| *fold)
                }) {
                    unmodeled_tests = true;
                    return None;
                }
                let (matches, unmodeled) = find_action_matches(
                    builder,
                    ctx,
                    model_node,
                    tests,
                    root,
                    root_fact.as_ref(),
                    depths,
                    traversal,
                    false,
                );
                let narrowing = find_expression(tests)
                    .and_then(|expression| find_narrowing(&expression, traversal))
                    .unwrap_or_default()
                    .0;
                let whole_root = matches.iter().any(|matched| {
                    matched == root
                        || *matched == find_root_matches(ctx, root, roots_only, &narrowing)
                });
                // The delete of the whole tree below does not say which
                // entries a narrowed selection leaves in place.
                let unmodeled = unmodeled || *after_action || whole_root && !narrowing.is_none();
                if whole_root {
                    unmodeled_tests |= unmodeled;
                    return None;
                }
                Some((matches, unmodeled))
            });
            if let Some((matches, unmodeled)) = named {
                unmodeled_tests |= unmodeled;
                for matched in matches {
                    let arg = crate::models::common::fs_arg_node(builder, ctx, *index, root);
                    builder.effect(effinterp_proto::Effect {
                        request_assurance: effinterp_proto::RequestAssurance::Exact,
                        id: Default::default(),
                        operation: effinterp_proto::Operation::new("filesystem.delete"),
                        resource: ctx.resolve_fs_word(&matched),
                        attributes: Attrs::new(),
                        modality: effinterp_proto::Modality::May,
                        realm: effinterp_proto::ExecutionRealm::Host,
                        condition: None,
                        execution: effinterp_proto::ExecutionNodeRef(0),
                        provenance: vec![arg, model_node],
                    });
                }
            } else if has_delete {
                let mut resource = selector
                    .and_then(|(predicate, value)| {
                        find_name_selection(ctx, root, predicate, value, roots_only)
                    })
                    .unwrap_or_else(|| {
                        if selector.is_some() {
                            ctx.resolve_fs_word(&find_root_matches(
                                ctx,
                                root,
                                roots_only,
                                &Default::default(),
                            ))
                        } else {
                            ctx.resolve_fs_word(root)
                        }
                    });
                // `find link/ -delete` starts in the directory the link points
                // at and deletes everything below it.
                if selector.is_none() && trailing_slash {
                    crate::models::common::follow_final_link(builder, &mut resource, &[model_node]);
                }
                // `find link/.. -delete` starts in the parent of the link's
                // target, as its read does; a start path that cannot be
                // traversed deletes nothing. When the host leaves that parent
                // unresolved, the lexical collapse stays, beside the boundary.
                if selector.is_none() {
                    let lexical = resource.clone();
                    if !crate::models::common::follow_parent_links(
                        builder,
                        ctx,
                        root,
                        &mut resource,
                        &[model_node],
                    ) {
                        continue;
                    }
                    if matches!(resource, ResourceExpr::Unresolved { .. }) {
                        resource = lexical;
                    }
                }
                fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    root,
                    "filesystem.delete",
                    resource,
                    if roots_only || selector.is_some() {
                        Attrs::new()
                    } else {
                        attr_bool("recursive")
                    },
                );
            }
        }
        fs_full_no_spawn(builder);

        // Each start path runs the action on its own matches, so every root
        // keeps a deletion the guards can observe on its own rather than one
        // union of roots. Every root's matches are found before any action
        // runs, so no action's mutation stales what another root observed.
        let mut prepared = Vec::new();
        // Only an unfiltered single-root NUL listing, bounded at most by
        // depth, can supply path operands. Predicates, traversal options and
        // other expressions keep xargs input unknown, as do indirect consumers
        // and other delimiter modes.
        if builder.stdout_paths_to_xargs
            && plain_traversal
            && roots.len() == 1
            && ctx.argv[2..]
                .iter()
                .map(Word::as_literal)
                .collect::<Option<Vec<_>>>()
                .is_some_and(|expression| find_depth_bounded_print0(&expression))
            // A missing start point prints nothing. The conservative action
            // bound below must not certify it as an xargs operand.
            && root_facts[0]
                .as_ref()
                .is_none_or(|fact| fact.kind != PathKind::Missing)
        {
            let (_, root) = &roots[0];
            let fact = root_facts[0].as_ref();
            let output_depths = FindDepths {
                min: depths.min,
                max: if fact.is_some_and(|fact| fact.kind == PathKind::File) {
                    Some(0)
                } else {
                    depths.max
                },
            };
            let (matches, unmodeled) = find_action_matches(
                builder,
                ctx,
                model_node,
                &tests,
                root,
                fact,
                output_depths,
                traversal,
                false,
            );
            unmodeled_tests |= unmodeled;
            if !unmodeled {
                builder.record_stdout_paths(crate::models::PrintedPaths {
                    paths: matches,
                    nul: true,
                    under: None,
                });
            }
        }
        for (start, end, tests) in &actions {
            for ((root_index, root), root_fact) in roots.iter().zip(&root_facts) {
                let (matches, unmodeled) = find_action_matches(
                    builder,
                    ctx,
                    model_node,
                    tests,
                    root,
                    root_fact.as_ref(),
                    depths,
                    traversal,
                    // The command an action runs removes what it is passed.
                    ctx.argv[*start].as_literal().is_some_and(|command| {
                        matches!(
                            crate::models::args::basename(command),
                            "rm" | "unlink" | "shred"
                        )
                    }),
                );
                unmodeled_tests |= unmodeled;
                prepared.push((*start, *end, root_index, matches));
            }
        }
        for (start, end, root_index, matches) in prepared {
            for match_word in matches {
                let cmd: Vec<Word> = ctx.argv[start..end]
                    .iter()
                    .map(|w| match w.as_literal() {
                        Some("{}") => match_word.clone(),
                        _ => w.clone(),
                    })
                    .collect();
                if cmd.is_empty() {
                    continue;
                }
                let mut argv_provenance = ctx.argv_provenance_range(builder, start..end);
                let root_provenance = ctx.argv_provenance_at(builder, *root_index as usize);
                for (index, word) in ctx.argv[start..end].iter().enumerate() {
                    if word.as_literal() == Some("{}") {
                        argv_provenance[index] = root_provenance.clone();
                    }
                }
                let arg = arg_node(builder, ctx, start as u32);
                ctx.nest_exec(
                    builder,
                    &cmd,
                    ctx.cwd,
                    Some(argv_provenance.as_slice()),
                    &[model_node, arg],
                );
            }
        }
        // -L descends through symbolic links, so a match spelled below a start
        // path may be a file of another tree.
        if traversal == FindTraversal::Logical {
            builder.boundary(effinterp_proto::Boundary {
                reason: effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE,
                class: effinterp_proto::BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![model_node],
                limit: None,
                detail: Some("find -L follows symbolic links out of its start paths".into()),
            });
        }
        if unmodeled_tests {
            builder.boundary(effinterp_proto::Boundary {
                reason: effinterp_proto::BoundaryReason::MODEL_COVERAGE,
                class: effinterp_proto::BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: crate::builder::KNOWN_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some("find tests the model cannot apply may narrow its matches".into()),
            });
        }
        if unresolved_selector {
            builder.boundary(effinterp_proto::Boundary {
                reason: effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: effinterp_proto::BoundaryClass::Unresolved,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: crate::builder::KNOWN_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some("find expression may select deletion or nested execution".into()),
            });
        }
    }
}

/// A positive selector before `-delete` limits which visited entries reach the
/// action. Disjunction and negation can instead make deletion run when the
/// selector is false, so those expressions retain the whole-root model.
fn positive_delete_selector(argv: &[Word], start: usize) -> Option<(&str, &Word)> {
    let delete = argv[start..]
        .iter()
        .position(|word| word.as_literal() == Some("-delete"))?
        + start;
    let expression = &argv[start..delete];
    if expression
        .iter()
        .any(|word| matches!(word.as_literal(), Some("!" | "-not" | "-o" | "-or" | ",")))
    {
        return None;
    }
    expression.windows(2).find_map(|pair| {
        let predicate = pair[0].as_literal()?;
        if matches!(predicate, "-name" | "-path") && pair[1].as_literal() == Some("*") {
            return None;
        }
        matches!(predicate, "-name" | "-path" | "-newer").then_some((predicate, &pair[1]))
    })
}

/// `-print0` after nothing but numeric `-mindepth`/`-maxdepth` options: find
/// prints every path in the depth range, NUL-terminated.
fn find_depth_bounded_print0(expression: &[&str]) -> bool {
    let Some((&"-print0", mut options)) = expression.split_last() else {
        return false;
    };
    while let ["-mindepth" | "-maxdepth", depth, rest @ ..] = options {
        if depth.is_empty() || !depth.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        options = rest;
    }
    options.is_empty()
}

/// Tests that take one value word. The expression scan skips the value so a
/// value spelled like an operator is not read as one.
const FIND_VALUE_TESTS: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-regex",
    "-iregex",
    "-type",
    "-xtype",
    "-perm",
    "-user",
    "-group",
    "-uid",
    "-gid",
    "-size",
    "-mtime",
    "-atime",
    "-ctime",
    "-mmin",
    "-amin",
    "-cmin",
    "-newer",
    "-maxdepth",
    "-mindepth",
];

/// How find treats symbolic links: -P never follows one, -H follows only the
/// start paths, and -L follows every link it meets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FindTraversal {
    Physical,
    StartPaths,
    Logical,
}

/// The depths an action applies at: 0 is a start path, 1 an entry directly
/// below it. `max` is unbounded when absent.
#[derive(Clone, Copy)]
struct FindDepths {
    min: usize,
    max: Option<usize>,
}

/// The conjunction of tests before an action; an entry reaches the action
/// only when every one holds.
#[derive(Default)]
struct FindTests {
    /// `-name` and `-iname` patterns, each with whether it ignores case.
    names: Vec<(String, bool)>,
    /// `-path` and `-wholename` patterns and their case-insensitive forms.
    paths: Vec<(String, bool)>,
    /// `-type` values, each a comma-separated list of type letters.
    types: Vec<String>,
    /// Whether another test, such as `-size` or `-newer`, may be false.
    filtered: bool,
}

impl FindTests {
    /// Whether the tests hold for an entry find spells `path`, whose type
    /// letter is `kind` when known; `None` when a test is not decided.
    fn hold(&self, path: &str, kind: Option<char>) -> Option<bool> {
        let name = find_entry_name(path);
        let mut decided = !self.filtered;
        let patterns = self
            .names
            .iter()
            .map(|(pattern, fold)| (pattern, name, *fold))
            .chain(
                self.paths
                    .iter()
                    .map(|(pattern, fold)| (pattern, path, *fold)),
            );
        for (pattern, text, fold) in patterns {
            match find_fnmatch(pattern, text, fold) {
                Some(false) => return Some(false),
                Some(true) => {}
                None => decided = false,
            }
        }
        for types in &self.types {
            match kind {
                Some(kind) if !types.split(',').any(|letter| letter == kind.to_string()) => {
                    return Some(false);
                }
                Some(_) => {}
                None => decided = false,
            }
        }
        decided.then_some(true)
    }

    /// The name patterns an entry must match at any depth: each `-name`, and
    /// the final component of a `-path` when no wildcard can span its `/`.
    fn name_patterns(&self) -> Vec<(String, bool)> {
        let mut patterns = self.names.clone();
        patterns.extend(self.paths.iter().filter_map(|(pattern, fold)| {
            let (_, name) = pattern.rsplit_once('/')?;
            (!name.is_empty() && !name.contains(['*', '?', '[', '\\']))
                .then(|| (name.to_owned(), *fold))
        }));
        patterns
    }
}

/// The tests before an action as one conjunction. Negation, disjunction and
/// the comma operator can run the action when a test fails, so those
/// expressions, and words that are not literal, have none.
fn find_conjunction(tests: &[Word]) -> Option<FindTests> {
    let mut conjunction = FindTests::default();
    let mut k = 0;
    while k < tests.len() {
        let test = tests[k].as_literal()?;
        let value = || {
            tests
                .get(k + 1)
                .and_then(Word::as_literal)
                .map(str::to_owned)
        };
        match test {
            "-name" => conjunction.names.push((value()?, false)),
            "-iname" => conjunction.names.push((value()?, true)),
            "-path" | "-wholename" => conjunction.paths.push((value()?, false)),
            "-ipath" | "-iwholename" => conjunction.paths.push((value()?, true)),
            "-type" => conjunction.types.push(value()?),
            // Depths hold for the whole expression, not at their position.
            "-mindepth" | "-maxdepth" => {}
            _ if FIND_VALUE_TESTS.contains(&test) => conjunction.filtered = true,
            "!" | "-not" | "-o" | "-or" | "," => return None,
            // Grouping, `-a`, and options and actions that are always true.
            "("
            | ")"
            | "-a"
            | "-and"
            | "-true"
            | "-print"
            | "-print0"
            | "-ls"
            | "-prune"
            | "-depth"
            | "-d"
            | "-xdev"
            | "-mount"
            | "-noleaf"
            | "-follow"
            | "-daystart"
            | "-ignore_readdir_race"
            | "-noignore_readdir_race"
            | "-warn"
            | "-nowarn" => {}
            _ => conjunction.filtered = true,
        }
        k += if FIND_VALUE_TESTS.contains(&test) {
            2
        } else {
            1
        };
    }
    Some(conjunction)
}

/// The name find tests with `-name`: the last component, trailing slashes
/// ignored.
fn find_entry_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() && path.starts_with('/') {
        return "/";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

enum FindToken {
    Literal(char),
    Any,
    Star,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

/// Whether an unanchored exclusion pattern (GNU tar's default, Info-ZIP's
/// `-x`) drops the member `name` and so its whole subtree: the pattern, whose
/// `*` also matches `/`, matches the name or a trailing run of its
/// components. `None` for a pattern this does not read.
pub(super) fn unanchored_exclusion_drops(pattern: &str, name: &str) -> Option<bool> {
    let name = name.trim_matches('/');
    let mut suffix = name;
    loop {
        if find_fnmatch(pattern, suffix, false)? {
            return Some(true);
        }
        match suffix.split_once('/') {
            Some((_, rest)) => suffix = rest,
            None => return Some(false),
        }
    }
}

/// Whether an anchored exclusion pattern (Info-ZIP's `-x`, matched against
/// the whole name, `*` also matching `/`) drops the member `name` however it
/// is stored, with or without its leading `/`. `None` for a pattern this does
/// not read.
pub(super) fn anchored_exclusion_drops(pattern: &str, name: &str) -> Option<bool> {
    Some(
        find_fnmatch(pattern, name, false)?
            && find_fnmatch(pattern, name.trim_start_matches('/'), false)?,
    )
}

/// find's shell pattern test, fnmatch without FNM_PATHNAME or FNM_PERIOD:
/// `*`, `?` and bracket expressions also match `/` and a leading dot. C-locale
/// named classes such as `[[:alpha:]]` are read; `None` for a bracket
/// expression this does not read, a collating symbol (`[.`), an equivalence
/// class (`[=`) or an unknown class name (see `find_bracket`).
fn find_fnmatch(pattern: &str, text: &str, fold: bool) -> Option<bool> {
    let fold_case = |value: &str| {
        if fold {
            value.to_lowercase()
        } else {
            value.to_owned()
        }
    };
    let tokens = find_pattern_tokens(&fold_case(pattern))?;
    let text: Vec<char> = fold_case(text).chars().collect();
    let mut row = vec![false; text.len() + 1];
    row[0] = true;
    for token in &tokens {
        let mut next = vec![false; text.len() + 1];
        if matches!(token, FindToken::Star) {
            next[0] = row[0];
            for i in 0..text.len() {
                next[i + 1] = row[i + 1] || next[i];
            }
        } else {
            for (i, character) in text.iter().enumerate() {
                next[i + 1] = row[i]
                    && match token {
                        FindToken::Literal(literal) => literal == character,
                        FindToken::Class { negated, ranges } => {
                            ranges
                                .iter()
                                .any(|(start, end)| start <= character && character <= end)
                                != *negated
                        }
                        FindToken::Any | FindToken::Star => true,
                    };
            }
        }
        row = next;
    }
    Some(row[text.len()])
}

fn find_pattern_tokens(pattern: &str) -> Option<Vec<FindToken>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut k = 0;
    while k < chars.len() {
        tokens.push(match chars[k] {
            '*' => FindToken::Star,
            '?' => FindToken::Any,
            '\\' if k + 1 < chars.len() => {
                k += 1;
                FindToken::Literal(chars[k])
            }
            '[' => match find_bracket(&chars[k + 1..])? {
                Some((negated, ranges, length)) => {
                    k += length;
                    FindToken::Class { negated, ranges }
                }
                None => FindToken::Literal('['),
            },
            character => FindToken::Literal(character),
        });
        k += 1;
    }
    Some(tokens)
}

/// A bracket expression after its `[`: whether it is negated, its ranges,
/// and how many characters it spans through its `]`. `Some(None)` when no
/// `]` closes it, so the `[` is literal. Named classes read as the C
/// locale's; `None` for a collating element or equivalence class.
#[allow(clippy::type_complexity)]
fn find_bracket(chars: &[char]) -> Option<Option<(bool, Vec<(char, char)>, usize)>> {
    let negated = matches!(chars.first(), Some('!' | '^'));
    let mut k = usize::from(negated);
    let mut ranges = Vec::new();
    // A range endpoint, `\` escaping the character after it.
    let endpoint = |k: &mut usize| -> Option<char> {
        let character = *chars.get(*k)?;
        if character == '\\' {
            *k += 1;
        }
        let character = *chars.get(*k)?;
        *k += 1;
        Some(character)
    };
    loop {
        let Some(&character) = chars.get(k) else {
            return Some(None);
        };
        if character == ']' && !ranges.is_empty() {
            return Some(Some((negated, ranges, k + 1)));
        }
        if character == '[' && matches!(chars.get(k + 1), Some('.' | '=')) {
            return None;
        }
        if character == '[' && chars.get(k + 1) == Some(&':') {
            let rest: String = chars[k + 2..].iter().collect();
            let Some((name, _)) = rest.split_once(":]") else {
                return Some(None);
            };
            ranges.extend(find_named_class(name)?);
            k += name.chars().count() + 4;
            continue;
        }
        let Some(start) = endpoint(&mut k) else {
            return Some(None);
        };
        if chars.get(k) == Some(&'-') && chars.get(k + 1).is_some_and(|next| *next != ']') {
            k += 1;
            let Some(end) = endpoint(&mut k) else {
                return Some(None);
            };
            ranges.push((start, end));
        } else {
            ranges.push((start, start));
        }
    }
}

/// The C locale's characters of a named bracket class.
fn find_named_class(name: &str) -> Option<Vec<(char, char)>> {
    Some(match name {
        "alpha" => vec![('A', 'Z'), ('a', 'z')],
        "digit" => vec![('0', '9')],
        "alnum" => vec![('0', '9'), ('A', 'Z'), ('a', 'z')],
        "upper" => vec![('A', 'Z')],
        "lower" => vec![('a', 'z')],
        "xdigit" => vec![('0', '9'), ('A', 'F'), ('a', 'f')],
        "space" => vec![(' ', ' '), ('\t', '\r')],
        "blank" => vec![(' ', ' '), ('\t', '\t')],
        "punct" => vec![('!', '/'), (':', '@'), ('[', '`'), ('{', '~')],
        "cntrl" => vec![('\0', '\x1f'), ('\x7f', '\x7f')],
        "print" => vec![(' ', '~')],
        "graph" => vec![('!', '~')],
        _ => return None,
    })
}

/// Every name a pattern without `*` or `?` matches, when there are at most
/// sixteen, so each can be looked up as an exact entry.
fn find_pattern_names(pattern: &str, fold: bool) -> Option<Vec<String>> {
    const MAX_NAMES: usize = 16;
    let mut names = vec![String::new()];
    for token in find_pattern_tokens(pattern)? {
        let mut choices: Vec<char> = match token {
            FindToken::Literal(character) => vec![character],
            FindToken::Class {
                negated: false,
                ranges,
            } => {
                let mut choices = Vec::new();
                for (start, end) in ranges {
                    if (end as u32).saturating_sub(start as u32) as usize >= MAX_NAMES {
                        return None;
                    }
                    choices.extend(start..=end);
                }
                choices
            }
            _ => return None,
        };
        if fold {
            if !choices.iter().all(char::is_ascii) {
                return None;
            }
            choices = choices
                .iter()
                .flat_map(|character| {
                    [
                        character.to_ascii_lowercase(),
                        character.to_ascii_uppercase(),
                    ]
                })
                .collect();
        }
        choices.sort_unstable();
        choices.dedup();
        if names.len() * choices.len() > MAX_NAMES {
            return None;
        }
        names = names
            .iter()
            .flat_map(|name| choices.iter().map(move |choice| format!("{name}{choice}")))
            .collect();
    }
    // No entry has an empty name, one with `/`, or the names `.` and `..`.
    names.retain(|name| !matches!(name.as_str(), "" | "." | "..") && !name.contains('/'));
    Some(names)
}

/// Filesystem globs for the entries a `-name` pattern matches. The glob's
/// wildcards do not match a leading dot, so a pattern that can match a
/// hidden name also gets globs that spell the dot. `None` when the pattern
/// does not translate.
pub(super) fn find_name_globs(pattern: &str, fold: bool) -> Option<Vec<String>> {
    // A locale-dependent equivalence class can select more than its written
    // character. Keep a simple surrounding name bound and allow any text
    // there; the caller still reports the unread predicate boundary.
    let mut tokens = find_pattern_tokens(pattern).or_else(|| {
        let (prefix, class) = pattern.split_once("[[=")?;
        let (class, suffix) = class.split_once("=]]")?;
        if class.is_empty()
            || [prefix, class, suffix]
                .iter()
                .any(|part| part.contains(['[', ']', '\\']))
        {
            return None;
        }
        find_pattern_tokens(&format!("{prefix}*{suffix}"))
    })?;
    tokens
        .dedup_by(|next, previous| matches!((next, previous), (FindToken::Star, FindToken::Star)));
    // `-`, `!` and `^` are special only inside a bracket expression.
    let spell_char = |character: char, bracketed: bool, glob: &mut String| {
        if matches!(character, '*' | '?' | '[' | ']' | '\\')
            || bracketed && matches!(character, '-' | '!' | '^')
        {
            glob.push('\\');
        }
        glob.push(character);
    };
    let spell = |tokens: &[FindToken]| -> Option<String> {
        let mut glob = String::new();
        for token in tokens {
            match token {
                FindToken::Literal('/') => return None,
                FindToken::Literal(character) if fold && character.is_ascii_alphabetic() => {
                    glob.push('[');
                    glob.push(character.to_ascii_lowercase());
                    glob.push(character.to_ascii_uppercase());
                    glob.push(']');
                }
                FindToken::Literal(character) => spell_char(*character, false, &mut glob),
                FindToken::Any => glob.push('?'),
                FindToken::Star => glob.push('*'),
                FindToken::Class { negated, ranges } => {
                    glob.push('[');
                    if *negated {
                        glob.push('!');
                    }
                    for &(start, end) in ranges {
                        if start > end {
                            return None;
                        }
                        let mut cases = vec![(start, end)];
                        if fold && start.is_ascii_alphabetic() && end.is_ascii_alphabetic() {
                            cases.push((start.to_ascii_lowercase(), end.to_ascii_lowercase()));
                            cases.push((start.to_ascii_uppercase(), end.to_ascii_uppercase()));
                        }
                        for (start, end) in cases {
                            spell_char(start, true, &mut glob);
                            if start != end {
                                glob.push('-');
                                spell_char(end, true, &mut glob);
                            }
                        }
                    }
                    glob.push(']');
                }
            }
        }
        Some(glob)
    };
    let mut globs = vec![spell(&tokens)?];
    let admits_dot = match tokens.first() {
        Some(FindToken::Star) => {
            // `*` may match the dot and more, or nothing before a dot.
            globs.push(format!(".{}", spell(&tokens)?));
            if matches!(tokens.get(1), Some(FindToken::Literal('.'))) {
                globs.push(spell(&tokens[1..])?);
            }
            false
        }
        Some(FindToken::Any) => true,
        Some(FindToken::Class { negated, ranges }) => {
            ranges
                .iter()
                .any(|&(start, end)| start <= '.' && '.' <= end)
                != *negated
        }
        _ => false,
    };
    if admits_dot {
        globs.push(format!(".{}", spell(&tokens[1..])?));
    }
    globs
        .iter()
        .all(|glob| effinterp_proto::validate_glob(glob).is_ok())
        .then_some(globs)
}

/// Whether a `-path` pattern holds for every entry below the start path
/// find spells `root`: the root's spelling and a `/`, then only `*`.
fn find_path_selects_every_entry(pattern: &str, root: &str) -> bool {
    let rest = if root.ends_with('/') {
        pattern.strip_prefix(root)
    } else {
        pattern
            .strip_prefix(root)
            .and_then(|rest| rest.strip_prefix('/'))
    };
    rest.unwrap_or(pattern)
        .chars()
        .all(|character| character == '*')
        && pattern.contains('*')
}

/// A glob for every entry below `base` that a `-path` test with `pattern` can
/// pass, where the start path is spelled `spelled`. find matches the pattern
/// against the whole path it prints, the start path as spelled and the entry
/// below it, and its `*` crosses `/`: `*/.ssh/*` passes everything below any
/// `.ssh` directory, `BASE/**/.ssh/**`, and `./util/*` from `.` everything
/// below `BASE/util`. The glob may match more than the pattern passes, never
/// less.
///
/// `None` for a pattern this does not spell: one that ignores case, has a
/// wildcard other than a whole `*` between slashes, does not begin with `*`
/// or the start path, or names a directory the start path already lies
/// under.
fn find_path_glob(pattern: &str, fold: bool, spelled: &str, base: &str) -> Option<String> {
    if fold || pattern.contains(['?', '[', '\\']) || spelled.contains(['*', '?', '[', '\\']) {
        return None;
    }
    let start = format!("{}/", spelled.trim_end_matches('/'));
    let below = match pattern.strip_prefix(start.as_str()) {
        Some(below) => below,
        None if pattern.starts_with("*/") => pattern,
        None => return None,
    };
    let mut glob = base.to_owned();
    for segment in below.split('/') {
        if segment == "*" {
            glob.push_str("/**");
        } else if segment.is_empty()
            || segment.contains('*')
            || format!("/{start}").contains(&format!("/{segment}/"))
        {
            return None;
        } else {
            glob.push('/');
            glob.push_str(&crate::paths::escape_fs_glob_path(segment));
        }
    }
    Some(glob)
}

/// The host's answer for `path` as the command starts, recorded in the
/// plan's provenance. `None` without a host to ask, when the host does not
/// answer, or when the command may already have changed the path.
pub(super) fn find_observe(
    builder: &mut PlanBuilder,
    path: &str,
    use_site: ProvenanceRef,
) -> Option<PathFact> {
    let budget = builder.budget();
    if budget.observations.is_none()
        || !builder.is_host_realm()
        || !path.starts_with('/')
        || !matches!(
            builder.written_source(path, |_, _| false),
            WrittenSource::Host
        )
    {
        return None;
    }
    let outcome = budget.observe_path(path);
    builder.node(
        ProvenanceKind::HostObservation {
            query: ObservationQuery::Path {
                path: path.to_owned(),
            },
            outcome: outcome.clone(),
        },
        &[use_site],
    );
    match outcome {
        ObservationOutcome::Path(fact) => Some(fact),
        ObservationOutcome::Listing(_) | ObservationOutcome::Refused(_) => None,
    }
}

/// The `-type` letter of an observed entry, of its link's target when
/// `follow`.
fn find_kind(fact: &PathFact, follow: bool) -> Option<char> {
    let kind = if follow && fact.kind == PathKind::Symlink {
        *fact.followed.known()?.kind.known()?
    } else {
        fact.kind
    };
    match kind {
        PathKind::Directory => Some('d'),
        PathKind::File => Some('f'),
        PathKind::Symlink => Some('l'),
        PathKind::Fifo => Some('p'),
        PathKind::Missing | PathKind::Other => None,
    }
}

/// The paths an action guarded by `tests` receives from the start path
/// `root`, each passed on its own, and whether some test the model cannot
/// apply may narrow them (the caller then raises a boundary).
///
/// A start path the tests may select keeps the whole-tree word, since the
/// action then reaches it and everything below; that word states the entry
/// kinds and names the tests leave out (`find_narrowing`), so a reader can
/// tell `find DIR -type d` from `find DIR`. Otherwise only entries below
/// it can match. An entry whose exact name the tests spell is looked up, and
/// passed as that path when it exists and passes every test; deeper entries
/// are selected by the name's glob within the depth bounds. A glob cannot
/// carry `-type`, a `-path` or another filter. An entry type, negation or
/// alternatives are applied to the entries the host lists
/// (`find_listed_matches`); without a listing, a selection those narrow keeps
/// the name's globs and is reported as possibly narrower. Without a name, a
/// selection of every entry is spelled as the start path's children.
#[allow(clippy::too_many_arguments)]
fn find_action_matches(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    tests: &[Word],
    root: &Word,
    root_fact: Option<&PathFact>,
    depths: FindDepths,
    traversal: FindTraversal,
    removes: bool,
) -> (Vec<Word>, bool) {
    let roots_only = depths.max == Some(0);
    let conjunction = find_conjunction(tests);
    // What the tests say of every entry the action runs for, which the
    // root-wide selection below carries instead of losing.
    let (narrowing, exact) = match find_expression(tests) {
        Some(expression) => match find_narrowing(&expression, traversal) {
            Some(narrowing) => narrowing,
            None => return (Vec::new(), false),
        },
        None => Default::default(),
    };
    let resolved = match (root.as_literal(), ctx.resolve_fs_word(root)) {
        (
            Some(spelled),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            },
        ) => Some((spelled, path)),
        _ => None,
    };
    // A glob carries a name. An entry type, a path test, or an expression
    // with negation or alternatives, is applied to the entries the host
    // lists. A command that removes every regular file below the start path
    // empties the tree however few entries it holds now, so it is passed the
    // tree below rather than a list of files.
    if let Some((spelled, path)) = &resolved
        && !(removes && find_selects_every_file(tests, depths))
        && conjunction.as_ref().is_none_or(|tests| {
            !tests.types.is_empty()
                // A path test that every entry passes narrows nothing, and
                // the action then works through the whole tree.
                || tests
                    .paths
                    .iter()
                    .any(|(pattern, _)| !find_path_selects_every_entry(pattern, spelled))
        })
        && let Some(listed) = find_listed_matches(
            builder, ctx, model_node, tests, root, spelled, path, root_fact, depths, traversal,
        )
    {
        return listed;
    }
    // -P tests a linked start path as the link itself and does not descend
    // through it; -H and -L follow it.
    let unfollowed_link = traversal == FindTraversal::Physical
        && root_fact.is_some_and(|fact| fact.kind == PathKind::Symlink);
    // Removing every regular file below a directory is the loss of its tree,
    // so the command is passed the tree, narrowed to the kinds the tests
    // admit, rather than a glob of the entries below it. The start path
    // itself stays, which the boundary reports.
    if removes
        && resolved.is_some()
        && !roots_only
        && !unfollowed_link
        && root_fact
            .is_none_or(|fact| find_kind(fact, traversal != FindTraversal::Physical) == Some('d'))
        && find_selects_every_file(tests, depths)
    {
        return (
            vec![find_root_matches(ctx, root, roots_only, &narrowing)],
            true,
        );
    }
    // The selection names the start path whatever the tests say of it, so it
    // is exact only where the narrowing admits that path too.
    let start_admitted = resolved.as_ref().is_some_and(|(spelled, _)| {
        root_fact
            .and_then(|fact| find_kind(fact, traversal != FindTraversal::Physical))
            .and_then(|kind| match kind {
                'd' => Some(effinterp_proto::FsEntryKind::Directory),
                'f' => Some(effinterp_proto::FsEntryKind::File),
                'l' => Some(effinterp_proto::FsEntryKind::Symlink),
                _ => None,
            })
            .is_some_and(|kind| narrowing.admits(kind, find_entry_name(spelled)))
    });
    let (Some(tests), Some((spelled, path))) = (conjunction, resolved) else {
        return (
            vec![find_root_matches(ctx, root, roots_only, &narrowing)],
            !(exact && depths.min == 0 && start_admitted),
        );
    };
    // A pattern this matcher does not read leaves every test answer open.
    let unread = tests
        .names
        .iter()
        .chain(&tests.paths)
        .any(|(pattern, _)| find_pattern_tokens(pattern).is_none());
    if depths.max.is_some_and(|max| max < depths.min) {
        return (Vec::new(), unread);
    }
    let root_kind = match root_fact {
        Some(fact) => find_kind(fact, traversal != FindTraversal::Physical),
        None => (matches!(spelled, "." | ".." | "/") || spelled.ends_with('/')).then_some('d'),
    };
    let start_selected = tests.hold(spelled, root_kind);
    if depths.min == 0 && start_selected != Some(false) {
        let matches = if unfollowed_link {
            root.clone()
        } else {
            find_root_matches(ctx, root, roots_only, &narrowing)
        };
        // The subtree carries entry kinds and excluded names. Any other
        // filter, or a start path the tests are not known to select, keeps
        // its conservative reach behind the selection boundary.
        return (
            vec![matches],
            !(exact && start_selected == Some(true))
                && (unread || !tests.types.is_empty() || tests.filtered),
        );
    }
    if roots_only || unfollowed_link || root_kind.is_some_and(|kind| kind != 'd') {
        return (Vec::new(), unread);
    }

    let base = crate::paths::escape_fs_glob_path(path.trim_end_matches('/'));
    let glob = |pattern: String| Word::new(vec![WordPart::Glob(pattern)]);
    let names = tests.name_patterns();
    // Tests a name glob cannot carry. A `-path '*/NAME'` only restates a name.
    let narrowed = !tests.types.is_empty()
        || tests.filtered
        || tests.paths.iter().any(|(pattern, _)| {
            !pattern
                .strip_prefix("*/")
                .is_some_and(|name| names.iter().any(|(named, _)| named == name))
        });
    let mut unmodeled = unread || narrowed;
    // A `-path '*/DIR/*'` passes only entries below a `DIR` directory. Unless
    // the start path already passes through one, that directory lies below
    // it, between the start path and the entry.
    let through = tests.paths.iter().find_map(|(pattern, fold)| {
        let dir = pattern.strip_prefix("*/")?.strip_suffix("/*")?;
        (!*fold
            && !dir.is_empty()
            && !dir.contains(['*', '?', '[', '\\', '/'])
            && !format!("{spelled}/").contains(&format!("/{dir}/")))
        .then(|| crate::paths::escape_fs_glob_path(dir))
    });
    // Every entry below the start path, when no narrower selection is spelled.
    let descendants = || vec![glob(format!("{base}/*/**")), glob(format!("{base}/.*/**"))];
    let chosen = names
        .iter()
        .find(|(pattern, fold)| find_pattern_names(pattern, *fold).is_some())
        .or(names.first());
    let Some((pattern, fold)) = chosen else {
        if depths.min <= 1
            && tests.types.is_empty()
            && !tests.filtered
            && tests
                .paths
                .iter()
                .all(|(pattern, _)| find_path_selects_every_entry(pattern, spelled))
        {
            let mut matches = vec![glob(format!("{base}/*")), glob(format!("{base}/.*"))];
            if depths.max.is_none_or(|max| max >= 2) {
                matches.push(glob(format!("{base}/*/**")));
                matches.push(glob(format!("{base}/.*/**")));
            }
            return (matches, unmodeled);
        }
        // Tests no glob carries exactly, with no listing to apply them to
        // (the host refused one, or they selected more entries than are
        // passed one by one): the action receives some of the entries below
        // the start path, possibly none, and the selection says so rather
        // than naming them all.
        let subset = |pattern: String, subset: effinterp_proto::FsSubset| {
            Word::new(vec![WordPart::Value(ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: pattern,
                    narrowing: effinterp_proto::FsNarrowing {
                        subset,
                        ..narrowing.clone()
                    },
                },
            })])
        };
        // A path test names the directories its entries lie under, which the
        // glob keeps. One whose pattern no glob spells keeps every entry
        // below the start path, as the whole selection.
        let paths = tests
            .paths
            .iter()
            .filter(|(pattern, _)| !find_path_selects_every_entry(pattern, spelled))
            .collect::<Vec<_>>();
        if let Some(named) = paths
            .iter()
            .find_map(|(pattern, fold)| find_path_glob(pattern, *fold, spelled, &base))
        {
            return (
                vec![subset(named, effinterp_proto::FsSubset::Named)],
                unmodeled,
            );
        }
        let below = |pattern: String| {
            if narrowed && paths.is_empty() {
                subset(pattern, effinterp_proto::FsSubset::Unnamed)
            } else {
                glob(pattern)
            }
        };
        let min = depths.min.max(1);
        if narrowed && min == 1 && depths.max.is_none() {
            return (vec![below(format!("{base}/**"))], unmodeled);
        }
        return match find_depth_globs(builder, &base, min, depths.max, None) {
            Some(globs) => (globs.into_iter().map(below).collect(), unmodeled),
            None => (
                vec![
                    below(format!("{base}/*/**")),
                    below(format!("{base}/.*/**")),
                ],
                true,
            ),
        };
    };
    let globs = find_name_globs(pattern, *fold);
    let mut matches = Vec::new();
    // The name globs from depth `min`. A test they cannot carry keeps them,
    // and the caller's boundary says they may select less. A name they cannot
    // spell keeps every entry, and more levels than the globs are allowed to
    // spell keep every depth.
    let mut select = |builder: &mut PlanBuilder, min: usize, matches: &mut Vec<Word>| {
        if depths.max.is_some_and(|max| max < min) {
            return;
        }
        let Some(globs) = &globs else {
            unmodeled = true;
            matches.extend(
                find_depth_globs(builder, &base, min, depths.max, None)
                    .map_or_else(descendants, |globs| globs.into_iter().map(glob).collect()),
            );
            return;
        };
        for name in globs {
            if let Some(dir) = &through
                && depths.max.is_none()
                && min <= 2
            {
                matches.push(glob(format!("{base}/**/{dir}/**/{name}")));
                continue;
            }
            match find_depth_globs(builder, &base, min, depths.max, Some(name)) {
                Some(selected) => matches.extend(selected.into_iter().map(glob)),
                None => {
                    unmodeled = true;
                    matches.push(glob(format!("{base}/**/{name}")));
                }
            }
        }
    };
    if let Some(literals) = find_pattern_names(pattern, *fold) {
        let literals: Vec<String> = literals
            .into_iter()
            .filter(|name| {
                names
                    .iter()
                    .all(|(pattern, fold)| find_fnmatch(pattern, name, *fold) != Some(false))
            })
            .collect();
        if literals.is_empty() {
            return (Vec::new(), unread);
        }
        if depths.min <= 1 {
            for name in &literals {
                let entry = format!("{}/{name}", path.trim_end_matches('/'));
                let entry_spelling = if spelled.ends_with('/') {
                    format!("{spelled}{name}")
                } else {
                    format!("{spelled}/{name}")
                };
                let fact = find_observe(builder, &entry, model_node);
                if fact
                    .as_ref()
                    .is_some_and(|fact| fact.kind == PathKind::Missing)
                {
                    continue;
                }
                let kind = fact
                    .as_ref()
                    .and_then(|fact| find_kind(fact, traversal == FindTraversal::Logical));
                if tests.hold(&entry_spelling, kind) != Some(false) {
                    matches.push(Word::literal(entry));
                }
            }
        }
        select(builder, depths.min.max(2), &mut matches);
    } else {
        select(builder, depths.min.max(1), &mut matches);
    }
    (matches, unmodeled)
}

/// Whether the tests leave every regular file below a start path selected:
/// only `-type` tests that admit regular files (`-type f`, `! -type d`), with
/// no name, path or other filter, and depth bounds that reach below the first
/// level.
fn find_selects_every_file(tests: &[Word], depths: FindDepths) -> bool {
    depths.min <= 1
        && depths.max.is_none_or(|max| max >= 2)
        && find_expression(tests)
            .and_then(|expression| find_narrowing(&expression, FindTraversal::Physical))
            .is_some_and(|(narrowing, exact)| {
                exact
                    && narrowing.excluded_names.is_empty()
                    && narrowing
                        .kinds
                        .contains(&effinterp_proto::FsEntryKind::File)
            })
}

/// What an expression's top-level conjunction says of every entry its action
/// runs for: the entry kinds a `-type` or its negation admits and the names a
/// negated `-name` leaves out. The second value is whether that is everything
/// the expression tests, so the narrowed selection is exactly what the action
/// receives. `None` when its `-type` tests admit no kind in common
/// (`-type f ! -type f`), so the action runs for nothing.
///
/// Under `-L` a `-type` test reads what a link points at, so a link may pass
/// any of them. A name pattern is carried only where the selection's glob
/// grammar reads it as find does.
fn find_narrowing(
    expression: &FindExpr,
    traversal: FindTraversal,
) -> Option<(effinterp_proto::FsNarrowing, bool)> {
    use effinterp_proto::FsEntryKind;
    /// The kinds the type letters admit, or with `negated` the kinds they
    /// leave. A letter for a FIFO, socket or device is only part of `Other`,
    /// so it is admitted whole and never left out.
    fn kinds(types: &str, negated: bool, follows: bool, exact: &mut bool) -> Vec<FsEntryKind> {
        let mut named = Vec::new();
        for letter in types.split(',') {
            named.push(match letter {
                "f" => FsEntryKind::File,
                "d" => FsEntryKind::Directory,
                "l" => FsEntryKind::Symlink,
                _ => {
                    *exact = false;
                    if negated {
                        continue;
                    }
                    FsEntryKind::Other
                }
            });
        }
        let mut kinds: Vec<FsEntryKind> = [
            FsEntryKind::File,
            FsEntryKind::Directory,
            FsEntryKind::Symlink,
            FsEntryKind::Other,
        ]
        .into_iter()
        .filter(|kind| named.contains(kind) != negated)
        .collect();
        if follows {
            *exact = false;
            if !kinds.contains(&FsEntryKind::Symlink) {
                kinds.push(FsEntryKind::Symlink);
            }
        }
        kinds
    }
    fn collect(
        expression: &FindExpr,
        follows: bool,
        narrowing: &mut effinterp_proto::FsNarrowing,
        typed: &mut bool,
        exact: &mut bool,
    ) {
        // Every `-type` test of the conjunction must hold, so an entry's
        // kind is one that all of them admit.
        let mut admit = |kinds: Vec<FsEntryKind>| {
            if *typed {
                narrowing.kinds.retain(|kind| kinds.contains(kind));
            } else {
                narrowing.kinds = kinds;
                *typed = true;
            }
        };
        match expression {
            FindExpr::Always | FindExpr::Action => {}
            FindExpr::Type(types) => admit(kinds(types, false, follows, exact)),
            FindExpr::Not(inner) => match &**inner {
                FindExpr::Type(types) => admit(kinds(types, true, follows, exact)),
                FindExpr::Name(pattern, false)
                    if !pattern.contains(['{', '}', '(', ')', '[', ']', '\\'])
                        && effinterp_proto::validate_glob(pattern).is_ok() =>
                {
                    narrowing.excluded_names.push(pattern.clone());
                }
                _ => *exact = false,
            },
            FindExpr::And(terms) => {
                for term in terms {
                    collect(term, follows, narrowing, typed, exact);
                }
            }
            FindExpr::Or(alternatives) if alternatives.len() == 1 => {
                collect(&alternatives[0], follows, narrowing, typed, exact);
            }
            _ => *exact = false,
        }
    }
    let mut narrowing = effinterp_proto::FsNarrowing::default();
    let (mut typed, mut exact) = (false, true);
    collect(
        expression,
        traversal == FindTraversal::Logical,
        &mut narrowing,
        &mut typed,
        &mut exact,
    );
    (!(typed && narrowing.kinds.is_empty())).then_some((narrowing, exact))
}

/// A find expression up to one action, read for whether that action runs for
/// an entry.
enum FindExpr {
    /// An option, or an action that always succeeds.
    Always,
    /// A test the model does not apply.
    Undecided,
    /// `-name` or `-iname`, with whether it ignores case.
    Name(String, bool),
    /// `-path` or `-wholename`, with whether it ignores case.
    Path(String, bool),
    /// `-type`, a comma-separated list of type letters.
    Type(String),
    Prune,
    /// The action the expression is read for.
    Action,
    Not(Box<FindExpr>),
    And(Vec<FindExpr>),
    Or(Vec<FindExpr>),
}

/// Whether evaluating an expression for one entry gets to a primary: not at
/// all, only if an undecided test goes one way, or always.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FindReach {
    No,
    Maybe,
    Yes,
}

impl FindExpr {
    /// The expression's value for an entry find spells `path`, whose type
    /// letter is `kind` when known; `None` when a test is not decided.
    /// Evaluation short-circuits as find's does, and records in `action` and
    /// `prune` whether it gets to those primaries. `certain` is whether find
    /// evaluates this expression at all.
    fn eval(
        &self,
        path: &str,
        kind: Option<char>,
        certain: bool,
        action: &mut FindReach,
        prune: &mut FindReach,
    ) -> Option<bool> {
        let reached = if certain {
            FindReach::Yes
        } else {
            FindReach::Maybe
        };
        match self {
            Self::Always => Some(true),
            Self::Undecided => None,
            Self::Name(pattern, fold) => find_fnmatch(pattern, find_entry_name(path), *fold),
            Self::Path(pattern, fold) => find_fnmatch(pattern, path, *fold),
            Self::Type(types) => {
                kind.map(|kind| types.split(',').any(|letter| letter == kind.to_string()))
            }
            Self::Prune => {
                *prune = (*prune).max(reached);
                Some(true)
            }
            Self::Action => {
                *action = (*action).max(reached);
                Some(true)
            }
            Self::Not(inner) => inner
                .eval(path, kind, certain, action, prune)
                .map(|value| !value),
            // Each operand is evaluated only while the ones before it leave
            // the result open: `-a` stops at a false one and `-o` at a true
            // one.
            Self::And(terms) | Self::Or(terms) => {
                let stop = matches!(self, Self::Or(_));
                let mut certain = certain;
                let mut value = Some(!stop);
                for term in terms {
                    match term.eval(path, kind, certain, action, prune) {
                        Some(result) if result == stop => return Some(stop),
                        Some(_) => {}
                        None => {
                            certain = false;
                            value = None;
                        }
                    }
                }
                value
            }
        }
    }
}

/// The tests before an action as an expression that ends in the action, so
/// evaluating it says whether the action runs. Words after the action cannot
/// change that, so a group the action sits in need not be closed. `None` for
/// a word that is not literal, the comma operator or a malformed expression.
fn find_expression(tests: &[Word]) -> Option<FindExpr> {
    fn or(words: &[&str], at: &mut usize, placed: &mut bool) -> Option<FindExpr> {
        let mut alternatives = vec![and(words, at, placed)?];
        while matches!(words.get(*at), Some(&("-o" | "-or"))) {
            *at += 1;
            alternatives.push(and(words, at, placed)?);
        }
        Some(FindExpr::Or(alternatives))
    }
    fn and(words: &[&str], at: &mut usize, placed: &mut bool) -> Option<FindExpr> {
        let mut terms = Vec::new();
        loop {
            match words.get(*at) {
                None => {
                    if !*placed {
                        *placed = true;
                        terms.push(FindExpr::Action);
                    }
                    break;
                }
                Some(&("-o" | "-or" | ")")) => break,
                Some(&("-a" | "-and")) => *at += 1,
                Some(_) => terms.push(primary(words, at, placed)?),
            }
        }
        (!terms.is_empty()).then_some(FindExpr::And(terms))
    }
    fn primary(words: &[&str], at: &mut usize, placed: &mut bool) -> Option<FindExpr> {
        let word = *words.get(*at)?;
        *at += 1;
        let mut value = || {
            let value = words.get(*at).map(|value| (*value).to_owned());
            *at += 1;
            value
        };
        Some(match word {
            "!" | "-not" => FindExpr::Not(Box::new(primary(words, at, placed)?)),
            "(" => {
                let group = or(words, at, placed)?;
                match words.get(*at) {
                    Some(&")") => *at += 1,
                    None => {}
                    Some(_) => return None,
                }
                group
            }
            "," => return None,
            "-name" => FindExpr::Name(value()?, false),
            "-iname" => FindExpr::Name(value()?, true),
            "-path" | "-wholename" => FindExpr::Path(value()?, false),
            "-ipath" | "-iwholename" => FindExpr::Path(value()?, true),
            "-type" => FindExpr::Type(value()?),
            // Depths hold for the whole expression, not at their position.
            "-mindepth" | "-maxdepth" => {
                value()?;
                FindExpr::Always
            }
            _ if FIND_VALUE_TESTS.contains(&word) => {
                value()?;
                FindExpr::Undecided
            }
            "-prune" => FindExpr::Prune,
            "-true"
            | "-print"
            | "-print0"
            | "-ls"
            | "-depth"
            | "-d"
            | "-xdev"
            | "-mount"
            | "-noleaf"
            | "-follow"
            | "-daystart"
            | "-ignore_readdir_race"
            | "-noignore_readdir_race"
            | "-warn"
            | "-nowarn" => FindExpr::Always,
            _ => FindExpr::Undecided,
        })
    }
    let words = tests
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    let (mut at, mut placed) = (0, false);
    let expression = or(&words, &mut at, &mut placed)?;
    (at == words.len() && placed).then_some(expression)
}

/// The most entries a listing passes to an action one by one. A larger
/// selection keeps its globs.
const FIND_MAX_LISTED_MATCHES: usize = 64;

/// The entries an action guarded by `tests` receives from the start path
/// `root`, read from the host's listing of it, and whether a test the model
/// cannot apply may narrow them. The listing holds each entry's type, so
/// `-type`, `-path`, negation, alternatives and `-prune` are applied to the
/// entries themselves, which a glob cannot do.
///
/// `None` when the listing cannot say what find visits: the host gives none,
/// `-L` meets a link, the expression is not read, or more entries match than
/// are passed one by one. `None` too when the tests may select a start path
/// find descends from, so the caller keeps its whole-tree word. The caller
/// then keeps its globs.
#[allow(clippy::too_many_arguments)]
fn find_listed_matches(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    tests: &[Word],
    root: &Word,
    spelled: &str,
    path: &str,
    root_fact: Option<&PathFact>,
    depths: FindDepths,
    traversal: FindTraversal,
) -> Option<(Vec<Word>, bool)> {
    let expression = find_expression(tests)?;
    let root_fact = root_fact?;
    if depths.max.is_some_and(|max| max < depths.min) {
        return Some((Vec::new(), false));
    }
    // -P tests a linked start path as the link itself and does not descend
    // through it; -H and -L follow it.
    let unfollowed_link =
        traversal == FindTraversal::Physical && root_fact.kind == PathKind::Symlink;
    let root_kind = find_kind(root_fact, traversal != FindTraversal::Physical)?;
    let descends = depths.max != Some(0) && !unfollowed_link && root_kind == 'd';
    let entries = if !descends {
        Vec::new()
    } else {
        if !builder.is_host_realm()
            || !matches!(
                builder.written_source(path, |_, _| false),
                WrittenSource::Host
            )
        {
            return None;
        }
        let depth = depths
            .max
            .and_then(|max| u32::try_from(max).ok())
            .filter(|max| *max <= effinterp_proto::MAX_LISTING_DEPTH as u32);
        let budget = builder.budget();
        let outcome = budget.observe_listing(path, depth, budget.unmodeled_steps());
        builder.node(
            ProvenanceKind::HostObservation {
                query: ObservationQuery::Listing {
                    path: path.to_owned(),
                    depth,
                },
                outcome: outcome.clone(),
            },
            &[model_node],
        );
        let ObservationOutcome::Listing(listing) = outcome else {
            return None;
        };
        // -L descends through each link, into what the listing does not hold.
        if traversal == FindTraversal::Logical
            && listing
                .entries
                .iter()
                .any(|entry| entry.kind == PathKind::Symlink)
        {
            return None;
        }
        if !budget.try_charge_steps(listing.entries.len() as u64) {
            builder.note_saturated("max_analysis_steps");
            return None;
        }
        listing.entries
    };
    // -depth and -delete visit a directory after what it holds, so -prune
    // skips nothing.
    let prunes = !ctx
        .argv
        .iter()
        .any(|word| matches!(word.as_literal(), Some("-depth" | "-d" | "-delete")));
    let mut matches = Vec::new();
    // -xdev and -mount stay on the start path's filesystem, and the listing
    // does not say where another one is mounted, so entries below a mount
    // point are listed although find skips them.
    let mut unmodeled = descends
        && ctx
            .argv
            .iter()
            .any(|word| matches!(word.as_literal(), Some("-xdev" | "-mount")));
    let mut pruned: Vec<String> = Vec::new();
    let mut visit = |spelled: &str, kind: Option<char>| {
        let (mut action, mut prune) = (FindReach::No, FindReach::No);
        expression.eval(spelled, kind, true, &mut action, &mut prune);
        unmodeled |= action == FindReach::Maybe || prunes && prune == FindReach::Maybe;
        (
            action != FindReach::No,
            prunes && prune == FindReach::Yes && kind == Some('d'),
        )
    };
    if depths.min == 0 {
        let kind = if unfollowed_link { 'l' } else { root_kind };
        let (selected, prune) = visit(spelled, Some(kind));
        if selected {
            // An action that takes the start path and entries below it works
            // through the whole tree, which the list of its entries would not
            // say.
            if descends && !prune {
                return None;
            }
            matches.push(root.clone());
        }
        if prune {
            return Some((matches, unmodeled));
        }
    }
    for entry in &entries {
        let depth = entry.path.split('/').count();
        if depth < depths.min
            || pruned.iter().any(|directory| {
                entry
                    .path
                    .strip_prefix(directory.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            })
        {
            continue;
        }
        let kind = match entry.kind {
            PathKind::Directory => Some('d'),
            PathKind::File => Some('f'),
            PathKind::Symlink => Some('l'),
            PathKind::Fifo => Some('p'),
            PathKind::Missing | PathKind::Other => None,
        };
        let entry_spelling = if spelled.ends_with('/') {
            format!("{spelled}{}", entry.path)
        } else {
            format!("{spelled}/{}", entry.path)
        };
        let (selected, prune) = visit(&entry_spelling, kind);
        if selected {
            if matches.len() == FIND_MAX_LISTED_MATCHES {
                return None;
            }
            matches.push(Word::literal(format!(
                "{}/{}",
                path.trim_end_matches('/'),
                entry.path
            )));
        }
        if prune {
            pruned.push(entry.path.clone());
        }
    }
    Some((matches, unmodeled))
}

/// Globs for the entries from depth `min` (at least 1) to `max` below `base`
/// whose name glob `name` matches, or every entry for `None`. A glob's `*`
/// skips hidden entries, so each level is spelled both as `*` and `.*`.
/// `None` once that would take more than sixteen globs, checked before each
/// level doubles them, or when the plan's step budget runs out.
fn find_depth_globs(
    builder: &mut PlanBuilder,
    base: &str,
    min: usize,
    max: Option<usize>,
    name: Option<&str>,
) -> Option<Vec<String>> {
    const MAX_GLOBS: usize = 16;
    // The levels spelled before the glob's end: a name sits one level below
    // them, and an unbounded glob ends in `**`.
    let (first, last) = match (max, name) {
        (Some(max), Some(_)) => (min - 1, max - 1),
        (Some(max), None) => (min, max),
        (None, Some(_)) => (min - 1, min - 1),
        (None, None) => (min, min),
    };
    let mut prefixes = vec![String::new()];
    let mut globs = Vec::new();
    for depth in 0..=last {
        if depth >= first {
            if globs.len() + prefixes.len() > MAX_GLOBS {
                return None;
            }
            if !builder.budget().try_charge_steps(prefixes.len() as u64) {
                builder.note_saturated("max_analysis_steps");
                return None;
            }
            globs.extend(prefixes.iter().map(|prefix| match (max, name) {
                (Some(_), Some(name)) => format!("{base}{prefix}/{name}"),
                (Some(_), None) => format!("{base}{prefix}"),
                (None, Some(name)) => format!("{base}{prefix}/**/{name}"),
                (None, None) => format!("{base}{prefix}/**"),
            }));
        }
        if depth < last {
            if globs.len() + prefixes.len() * 2 > MAX_GLOBS {
                return None;
            }
            prefixes = prefixes
                .iter()
                .flat_map(|prefix| [format!("{prefix}/*"), format!("{prefix}/.*")])
                .collect();
        }
    }
    Some(globs)
}

/// The start path and everything below it: the root-wide selection of an
/// action that works through the whole tree. `narrowing` states which of the
/// entries below the start path the tests leave out.
fn find_root_matches(
    ctx: &InvocationCtx,
    root: &Word,
    roots_only: bool,
    narrowing: &effinterp_proto::FsNarrowing,
) -> Word {
    if roots_only {
        return root.clone();
    }
    match find_descendant_matches(ctx, root, narrowing) {
        Some(descendants) => Word::new(vec![WordPart::Union(vec![root.clone(), descendants])]),
        None => Word::new(vec![WordPart::Unknown]),
    }
}

/// Every path strictly below `root` that `narrowing` admits, when `root`
/// resolves to one path.
fn find_descendant_matches(
    ctx: &InvocationCtx,
    root: &Word,
    narrowing: &effinterp_proto::FsNarrowing,
) -> Option<Word> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = ctx.resolve_fs_word(root)
    else {
        return None;
    };
    let glob = format!(
        "{}/**",
        crate::paths::escape_fs_glob_path(path.trim_end_matches('/'))
    );
    // A glob word carries only its text, so a narrowed selection is passed as
    // the resource it resolves to.
    Some(Word::new(vec![if narrowing.is_none() {
        WordPart::Glob(glob)
    } else {
        WordPart::Value(ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob,
                narrowing: narrowing.clone(),
            },
        })
    }]))
}

fn find_name_selection(
    ctx: &InvocationCtx,
    root: &Word,
    predicate: &str,
    value: &Word,
    roots_only: bool,
) -> Option<ResourceExpr> {
    if predicate != "-name" || roots_only {
        return None;
    }
    let name = value.as_literal()?;
    if name == "*" || name.contains('/') {
        return None;
    }
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = ctx.resolve_fs_word(root)
    else {
        return None;
    };
    let descendants = ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath {
            glob: format!(
                "{}/**/{name}",
                crate::paths::escape_fs_glob_path(path.trim_end_matches('/'))
            ),
            narrowing: Default::default(),
        },
    };
    let root_name = root.as_literal().map(crate::models::args::basename);
    if root_name.is_some_and(|root_name| effinterp_proto::glob_match(name, root_name) == Ok(true)) {
        Some(ResourceExpr::Union {
            alternatives: vec![ctx.resolve_fs_word(root), descendants],
        })
    } else {
        Some(descendants)
    }
}

/// `kill`/`killall`/`pkill`: send a signal to a process. `kill` targets pids
/// (opaque process identities); `killall`/`pkill` target executable names.
struct Kill;

impl CommandModel for Kill {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "util/kill@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["kill", "killall", "pkill"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let by_name = ctx.argv[0].as_literal() != Some("kill");
        let args = scan(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &["-s", "--signal"],
                known_flags: &[],
            },
        );
        let mut attributes: Attrs = Attrs::new();
        // -9 / -KILL / -s 9 / -SIGKILL force a hard kill.
        let force = ctx.argv[1..]
            .iter()
            .any(|w| matches!(w.as_literal(), Some("-9" | "-KILL" | "-SIGKILL")))
            || args
                .value_of(&["-s", "--signal"])
                .and_then(Word::as_literal)
                .is_some_and(|signal| matches!(signal, "9" | "KILL" | "SIGKILL"));
        if force {
            attributes.insert("force".to_string(), AttrValue::Bool(true));
        }
        for (index, operand) in args.operands {
            let resource = if by_name {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable: operand.render_raw(),
                        path: None,
                        argv: Vec::new(),
                        cwd: None,
                    },
                }
            } else {
                // A numeric pid is not a name we can resolve to an executable.
                unresolved_resource("process")
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "process.signal",
                resource,
                attributes.clone(),
            );
        }
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    }
}

/// `mount [device] mountpoint` / `umount target`: changes the filesystem
/// namespace at the mountpoint.
struct Mount;

impl CommandModel for Mount {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "util/mount@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mount", "umount"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let unmount = ctx.argv[0].as_literal() == Some("umount");
        // Value-taking flags whose argument is not a mountpoint.
        let value_flags = ["-t", "-o", "-O", "--types", "--options"];
        let mut operands: Vec<(u32, &Word)> = Vec::new();
        let mut i = 1;
        while i < ctx.argv.len() {
            match ctx.argv[i].as_literal() {
                Some(t) if value_flags.contains(&t) => i += 2,
                Some(t) if t.starts_with('-') && t.len() > 1 => i += 1,
                _ => {
                    operands.push((i as u32, &ctx.argv[i]));
                    i += 1;
                }
            }
        }
        // The mountpoint is the last operand (`mount dev dir` / `umount dir`).
        if let Some((index, target)) = operands.last() {
            let op = if unmount {
                "filesystem.unmount"
            } else {
                "filesystem.mount"
            };
            operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                target,
                op,
                Default::default(),
            );
        }
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    }
}

/// `zip`/`unzip`/`gzip`/`gunzip`: archive members are unknown statically, so
/// extraction writes a pattern under the target directory.
struct Zip;

const GZIP_VALUE_FLAGS: &[&str] = &["-S", "--suffix", "-b", "--bits"];
const GZIP_KNOWN_FLAGS: &[&str] = &[
    "-a",
    "--ascii",
    "-c",
    "--stdout",
    "--to-stdout",
    "-d",
    "--decompress",
    "--uncompress",
    "-f",
    "--force",
    "-h",
    "-H",
    "-?",
    "--help",
    "-k",
    "--keep",
    "-l",
    "--list",
    "-L",
    "--license",
    "-m",
    "-M",
    "-n",
    "--no-name",
    "-N",
    "--name",
    "-q",
    "--quiet",
    "--silent",
    "-r",
    "--recursive",
    "--rsyncable",
    "--synchronous",
    "-t",
    "--test",
    "-v",
    "--verbose",
    "-V",
    "--version",
    "-Z",
    "--lzw",
    "-1",
    "--fast",
    "-2",
    "-3",
    "-4",
    "-5",
    "-6",
    "-7",
    "-8",
    "-9",
    "--best",
];
const GZIP_SPEC: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: true,
    value_flags: GZIP_VALUE_FLAGS,
    known_flags: GZIP_KNOWN_FLAGS,
};

struct GzipInvocation {
    operands: Vec<(u32, Word)>,
    unknown: Vec<(u32, String)>,
    suffix: Word,
    stdout: bool,
    decompress: bool,
    force: bool,
    keep: bool,
    recursive: bool,
    list: bool,
    test: bool,
    informational: bool,
    unsupported: bool,
    restore_name: bool,
    exact_options: bool,
}

fn gzip_invocation(argv: &[Word]) -> GzipInvocation {
    let scanned = scan_with_value_indices(argv, &GZIP_SPEC, true);
    let mut unknown = scanned.unknown_flags.clone();
    let option_end = scanned.dashdash.unwrap_or(argv.len() as u32);
    for (index, word) in argv.iter().enumerate().skip(1) {
        if index as u32 >= option_end {
            break;
        }
        let Some(text) = word.as_literal() else {
            continue;
        };
        let Some((name, _)) = text.split_once('=') else {
            continue;
        };
        if GZIP_KNOWN_FLAGS.contains(&name) {
            unknown.push((index as u32, text.to_string()));
        }
    }
    if scanned
        .flags
        .iter()
        .any(|flag| matches!(flag.name, "-S" | "--suffix") && flag.value.is_none())
    {
        unknown.push((0, "missing gzip suffix".into()));
    }

    let suffix = scanned
        .value_of(&["-S", "--suffix"])
        .cloned()
        .unwrap_or_else(|| Word::literal(".gz"));
    let suffix_valid = suffix
        .as_literal()
        .is_some_and(|suffix| !suffix.is_empty() && suffix.len() <= 30 && !suffix.contains('/'));
    let exact_long_options = argv
        .iter()
        .take(option_end as usize)
        .skip(1)
        .filter_map(Word::as_literal)
        .filter(|word| word.starts_with("--") && *word != "--")
        .all(|word| {
            let name = word.split_once('=').map_or(word, |(name, _)| name);
            GZIP_VALUE_FLAGS.contains(&name) || GZIP_KNOWN_FLAGS.contains(&name)
        });
    let stdout = scanned.has(&["-c", "--stdout", "--to-stdout"]);
    let decompress = argv.first().and_then(Word::as_literal) == Some("gunzip")
        || scanned.has(&["-d", "--decompress", "--uncompress"]);
    let force = scanned.has(&["-f", "--force"]);
    let keep = scanned.has(&["-k", "--keep"]);
    let recursive = scanned.has(&["-r", "--recursive"]);
    let list = scanned.has(&["-l", "--list"]);
    let test = scanned.has(&["-t", "--test"]);
    let informational = scanned.has(&[
        "-h",
        "-H",
        "-?",
        "--help",
        "-L",
        "--license",
        "-V",
        "--version",
    ]);
    let unsupported = scanned.has(&["-Z", "--lzw"]);
    let restore_name = scanned
        .flags
        .iter()
        .filter(|flag| matches!(flag.name, "-n" | "--no-name" | "-N" | "--name"))
        .next_back()
        .is_some_and(|flag| matches!(flag.name, "-N" | "--name"));
    let exact_options =
        unknown.is_empty() && suffix_valid && exact_long_options && !scanned.has(&["-b", "--bits"]);

    GzipInvocation {
        operands: scanned
            .operands
            .into_iter()
            .map(|(index, word)| (index, word.clone()))
            .collect(),
        suffix,
        stdout,
        decompress,
        force,
        keep,
        recursive,
        list,
        test,
        informational,
        unsupported,
        restore_name,
        exact_options,
        unknown,
    }
}

fn gzip_known_suffix<'a>(name: &str, suffix: &'a str) -> Option<&'a str> {
    let lower = name.to_ascii_lowercase();
    let suffix_lower = suffix.to_ascii_lowercase();
    let builtins = [".gz", ".z", ".taz", ".tgz", "-gz", "-z", "_z"];
    let custom_after_builtins = builtins
        .iter()
        .any(|builtin| builtin.len() > suffix.len() && builtin.ends_with(&suffix_lower));
    let mut candidates = Vec::with_capacity(builtins.len() + 1);
    if !custom_after_builtins {
        candidates.push(suffix);
    }
    candidates.extend(builtins);
    if custom_after_builtins {
        candidates.push(suffix);
    }
    candidates.into_iter().find(|candidate| {
        let candidate = candidate.to_ascii_lowercase();
        lower.len() > candidate.len()
            && lower.ends_with(&candidate)
            && lower.as_bytes()[lower.len() - candidate.len() - 1] != b'/'
    })
}

enum GzipDerivedOutput {
    Derived(Word),
    Unchanged,
    Unresolved { operand_may_transform: bool },
}

fn gzip_tail_could_complete_suffix(tail: &str, suffix: &str) -> bool {
    let tail = tail.to_ascii_lowercase();
    [suffix, ".gz", ".z", ".taz", ".tgz", "-gz", "-z", "_z"]
        .into_iter()
        .any(|candidate| candidate.to_ascii_lowercase().ends_with(&tail))
}

fn gzip_glob_literal_tail(pattern: &str) -> Option<&str> {
    let bytes = pattern.as_bytes();
    let mut tail = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                if index == bytes.len() {
                    return None;
                }
            }
            b'*' | b'?' | b'[' | b']' => tail = index + 1,
            _ => {}
        }
        index += 1;
    }
    let tail = &pattern[tail..];
    (!tail.is_empty() && !tail.contains('\\')).then_some(tail)
}

fn gzip_append_suffix(input: &Word, suffix: &str) -> Word {
    let mut parts = input.parts.clone();
    match parts.last_mut() {
        Some(WordPart::Literal(tail) | WordPart::Glob(tail)) => tail.push_str(suffix),
        _ => parts.push(WordPart::Literal(suffix.to_string())),
    }
    Word::new(parts)
}

fn gzip_replace_suffix(input: &Word, matched: &str) -> Word {
    let mut parts = input.parts.clone();
    let replacement =
        if matched.eq_ignore_ascii_case(".tgz") || matched.eq_ignore_ascii_case(".taz") {
            ".tar"
        } else {
            ""
        };
    match parts.last_mut() {
        Some(WordPart::Literal(tail) | WordPart::Glob(tail)) => {
            tail.truncate(tail.len() - matched.len());
            tail.push_str(replacement);
        }
        _ => unreachable!("matched suffix requires a textual tail"),
    }
    Word::new(parts)
}

fn gzip_derived_output(
    input: &Word,
    suffix: &Word,
    decompress: bool,
    force: bool,
) -> GzipDerivedOutput {
    let Some(suffix_literal) = suffix.as_literal() else {
        return GzipDerivedOutput::Unresolved {
            operand_may_transform: false,
        };
    };
    if let Some(input_literal) = input.as_literal() {
        if decompress {
            let Some(matched) = gzip_known_suffix(input_literal, suffix_literal) else {
                return GzipDerivedOutput::Unresolved {
                    operand_may_transform: false,
                };
            };
            let prefix = &input_literal[..input_literal.len() - matched.len()];
            return GzipDerivedOutput::Derived(Word::literal(
                if matched.eq_ignore_ascii_case(".tgz") || matched.eq_ignore_ascii_case(".taz") {
                    format!("{prefix}.tar")
                } else {
                    prefix.to_string()
                },
            ));
        }
        if !force && gzip_known_suffix(input_literal, suffix_literal).is_some() {
            return GzipDerivedOutput::Unchanged;
        }
        return GzipDerivedOutput::Derived(Word::literal(format!(
            "{input_literal}{suffix_literal}"
        )));
    }
    if let [WordPart::Union(alternatives)] = input.parts.as_slice() {
        let mut outputs = Vec::with_capacity(alternatives.len());
        let mut unchanged = 0;
        for alternative in alternatives {
            match gzip_derived_output(alternative, suffix, decompress, force) {
                GzipDerivedOutput::Derived(output) => outputs.push(output),
                GzipDerivedOutput::Unchanged => unchanged += 1,
                GzipDerivedOutput::Unresolved { .. } => {
                    return GzipDerivedOutput::Unresolved {
                        operand_may_transform: false,
                    };
                }
            }
        }
        if unchanged == alternatives.len() {
            return GzipDerivedOutput::Unchanged;
        }
        if unchanged != 0 {
            return GzipDerivedOutput::Unresolved {
                operand_may_transform: false,
            };
        }
        return GzipDerivedOutput::Derived(Word::new(vec![WordPart::Union(outputs)]));
    }
    if !decompress && force {
        return GzipDerivedOutput::Derived(gzip_append_suffix(input, suffix_literal));
    }
    let (tail, glob_tail) = match input.parts.last() {
        Some(WordPart::Literal(tail)) => (tail.as_str(), false),
        Some(WordPart::Glob(pattern)) => {
            let Some(tail) = gzip_glob_literal_tail(pattern) else {
                return GzipDerivedOutput::Unresolved {
                    operand_may_transform: false,
                };
            };
            (tail, true)
        }
        _ => {
            return GzipDerivedOutput::Unresolved {
                operand_may_transform: true,
            };
        }
    };
    if let Some(matched) = gzip_known_suffix(tail, suffix_literal) {
        return if decompress {
            GzipDerivedOutput::Derived(gzip_replace_suffix(input, matched))
        } else {
            GzipDerivedOutput::Unchanged
        };
    }
    if gzip_tail_could_complete_suffix(tail, suffix_literal) {
        return GzipDerivedOutput::Unresolved {
            operand_may_transform: !glob_tail,
        };
    }
    if decompress {
        GzipDerivedOutput::Unresolved {
            operand_may_transform: false,
        }
    } else {
        GzipDerivedOutput::Derived(gzip_append_suffix(input, suffix_literal))
    }
}

fn gzip_environment_preserves_endpoints(ctx: &InvocationCtx) -> bool {
    let Some(value) = ctx.environment_value("GZIP") else {
        return true;
    };
    let ResourceExpr::Literal { value } = value else {
        return false;
    };
    value.split_ascii_whitespace().all(|option| {
        matches!(
            option,
            "-1" | "-2"
                | "-3"
                | "-4"
                | "-5"
                | "-6"
                | "-7"
                | "-8"
                | "-9"
                | "--fast"
                | "--best"
                | "--rsyncable"
                | "--synchronous"
        ) || option.starts_with('-')
            && option.len() > 2
            && option[1..].bytes().all(|byte| matches!(byte, b'1'..=b'9'))
    })
}

fn value_dependency_binding(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    read: u32,
    write: u32,
    exact: bool,
) {
    use crate::flow::{BindEnd, FlowStage, PortBinding};

    builder.flow_stage(FlowStage {
        execution: Some(builder.current_execution()),
        effects: vec![read, write],
        bindings: vec![PortBinding {
            assurance: if exact {
                effinterp_proto::CausalAssurance::Exact
            } else {
                effinterp_proto::CausalAssurance::Conservative
            },
            from: BindEnd::Effect(read),
            to: BindEnd::Effect(write),
        }],
        provenance: vec![model_node],
    });
}

impl CommandModel for Zip {
    fn domains(&self) -> &'static [&'static str] {
        &["environment", "filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "archive/zip@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["zip", "unzip", "gzip", "gunzip"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let cmd = ctx.argv[0]
            .as_literal()
            .and_then(|name| name.rsplit('/').next())
            .unwrap_or("");
        match cmd {
            "unzip" => self.unzip(builder, ctx, model_node),
            "zip" => self.zip(builder, ctx, model_node),
            _ => self.gzip(builder, ctx, model_node, cmd == "gunzip"),
        }
        fs_full_no_spawn(builder);
    }
}

impl Zip {
    fn unzip(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // unzip [flags] ARCHIVE [members...] [-d DIR]
        let mut dir: Option<(u32, Word)> = None;
        let mut archive: Option<(u32, &Word)> = None;
        // `-p` and `-c` extract members to stdout rather than to files.
        let mut to_stdout = false;
        let mut i = 1;
        while i < ctx.argv.len() {
            match ctx.argv[i].as_literal() {
                Some("-d") => {
                    dir = ctx
                        .argv
                        .get(i + 1)
                        .cloned()
                        .map(|word| ((i + 1) as u32, word));
                    i += 2;
                }
                Some(t) if t.starts_with('-') && t.len() > 1 => {
                    to_stdout |= !t.starts_with("--") && t[1..].contains(['p', 'c']);
                    i += 1;
                }
                _ => {
                    if archive.is_none() {
                        archive = Some((i as u32, &ctx.argv[i]));
                    }
                    i += 1;
                }
            }
        }
        let read = archive.and_then(|(index, arch)| {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                arch,
                "filesystem.read",
                Default::default(),
            )
        });
        let (target_index, target_word) = dir.unwrap_or_else(|| (0, Word::literal(".")));
        let target = extraction_target(Some(&target_word), ctx.cwd_resource());
        let write = if ctx.tracks_host_context_environment() {
            fs_arg_effect(
                builder,
                ctx,
                model_node,
                target_index,
                &target_word,
                "filesystem.write",
                target,
                program_output_attrs(),
            )
        } else {
            arg_effect(
                builder,
                ctx,
                model_node,
                0,
                "filesystem.write",
                target,
                program_output_attrs(),
            )
        };
        // Extracted members carry the archive's bytes, to stdout or to files.
        let Some(read) = read else {
            return;
        };
        if to_stdout {
            use crate::flow::{BindEnd, FlowStage, PortBinding};

            builder.flow_stage(FlowStage {
                execution: Some(builder.current_execution()),
                effects: vec![read],
                bindings: vec![PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: BindEnd::Effect(read),
                    to: BindEnd::Port(effinterp_proto::Port::Stdout),
                }],
                provenance: vec![model_node],
            });
        } else if let Some(write) = write {
            value_dependency_binding(builder, model_node, read, write, false);
        }
    }

    fn zip(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        const STDIN_SPEC: FlagSpec<'static> = FlagSpec {
            allow_abbreviation: false,
            value_flags: &[],
            known_flags: &[
                "-@",
                "--names-stdin",
                "-q",
                "--quiet",
                "-j",
                "--junk-paths",
                "-0",
                "-1",
                "-2",
                "-3",
                "-4",
                "-5",
                "-6",
                "-7",
                "-8",
                "-9",
            ],
        };
        let parsed = scan(ctx.argv, &STDIN_SPEC);
        if parsed.has(&["-@", "--names-stdin"]) {
            unrecognized_arguments_boundary(
                builder,
                model_node,
                &["filesystem"],
                &parsed.unknown_flags,
            );
            if !parsed.unknown_flags.is_empty() {
                return;
            }
            let Some((archive_index, archive_word)) = parsed.operands.first() else {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &["filesystem"],
                    &[(0, "zip requires an archive operand".into())],
                );
                return;
            };
            if archive_word.as_literal() == Some("-") {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &["filesystem"],
                    &[(
                        0,
                        "zip stdin member list with stdout archive is unmodeled".into(),
                    )],
                );
                return;
            }
            // Zip supplies .zip only when the archive's basename has no extension.
            let archive_word = match archive_word.as_literal() {
                Some(path) if !path.rsplit('/').next().unwrap_or(path).contains('.') => {
                    Word::literal(format!("{path}.zip"))
                }
                _ => (*archive_word).clone(),
            };
            let archive = operand_effect(
                builder,
                ctx,
                model_node,
                *archive_index,
                &archive_word,
                "filesystem.write",
                Default::default(),
            );
            let Some(list) = ctx.stdin_literal() else {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                        class: BoundaryClass::Unresolved,
                        scope: effinterp_proto::BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some(
                            "zip member paths are selected by the unresolved stdin list".into(),
                        ),
                    },
                    CoverageLevel::Partial,
                );
                return;
            };
            let mut antecedents = vec![model_node];
            antecedents.extend(
                ctx.stdin
                    .into_iter()
                    .flat_map(|stdin| stdin.provenance.iter())
                    .copied(),
            );
            let list_node = builder.node(
                effinterp_proto::ProvenanceKind::ModelApplication {
                    model: self.id().into(),
                },
                &antecedents,
            );
            let members = parsed
                .operands
                .iter()
                .skip(1)
                .map(|(index, word)| (*index, (*word).clone()))
                .chain(
                    list.split_terminator('\n')
                        .filter(|line| !line.is_empty())
                        .map(|line| (0, Word::literal(line))),
                );
            for (index, member) in members {
                if !crate::nest::charge_analysis_steps(builder, ctx.nest.budget, 1, None) {
                    break;
                }
                let source = operand_effect(
                    builder,
                    ctx,
                    list_node,
                    index,
                    &member,
                    "filesystem.read",
                    program_input_attrs(),
                );
                if let (Some(source), Some(archive)) = (source, archive) {
                    value_dependency_binding(builder, list_node, source, archive, true);
                }
            }
            return;
        }
        // zip [flags] ARCHIVE files...
        let certified = parsed.unknown_flags.is_empty()
            && ctx.argv.iter().all(|word| word.as_literal().is_some())
            && parsed.operands.len() >= 2
            && parsed
                .operands
                .iter()
                .all(|(_, word)| word.as_literal() != Some("-"))
            && builder.execution_is_exact(builder.current_execution());
        let operands = scan_operand_flags(ctx.argv, &OPERAND_FLAGS).operands;
        let parsed_zip = zip_arguments(ctx.argv);
        let mut it = operands.into_iter();
        let archive = it.next().filter(|_| !parsed_zip.list_only);
        // A `-` archive is written to standard output, not to a file.
        let stdout_archive = archive.is_some_and(|(_, word)| word.as_literal() == Some("-"));
        let archive = archive
            .filter(|_| !stdout_archive)
            .and_then(|(index, archive)| {
                let archive = match archive.as_literal() {
                    Some(path) if !path.rsplit('/').next().unwrap_or(path).contains('.') => {
                        Word::literal(format!("{path}.zip"))
                    }
                    _ => archive.clone(),
                };
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    &archive,
                    "filesystem.write",
                    program_output_attrs(),
                )
            });
        // zip reads each member's contents. `-r` takes a directory member's
        // whole tree, hidden entries included, and stores what each link names
        // unless `-y` keeps links.
        let mut attributes = program_input_attrs();
        if parsed_zip.recursive && !parsed_zip.recurse_patterns {
            attributes.insert("recursive".into(), AttrValue::Bool(true));
            attributes.insert("follow_links".into(), AttrValue::Bool(!parsed_zip.symlinks));
        }
        // Each member's bytes end up in the archive the command writes.
        for (index, file) in it {
            let source = operand_effect(
                builder,
                ctx,
                model_node,
                index,
                file,
                "filesystem.read",
                attributes.clone(),
            );
            if let (Some(source), Some(archive)) = (source, archive) {
                value_dependency_binding(builder, model_node, source, archive, certified);
            } else if let Some(source) = source.filter(|_| stdout_archive) {
                use crate::flow::{BindEnd, FlowStage, PortBinding};
                builder.flow_stage(FlowStage {
                    execution: Some(builder.current_execution()),
                    effects: vec![source],
                    bindings: vec![PortBinding {
                        assurance: effinterp_proto::CausalAssurance::Conservative,
                        from: BindEnd::Effect(source),
                        to: BindEnd::Port(effinterp_proto::Port::Stdout),
                    }],
                    provenance: vec![model_node],
                });
            }
        }
        zip_move_deletions(builder, ctx, model_node, &parsed_zip);
    }

    fn gzip(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        _gunzip: bool,
    ) {
        arg_effect(
            builder,
            ctx,
            model_node,
            0,
            "environment.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: "GZIP".into(),
                },
            },
            Default::default(),
        );
        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
        let args = gzip_invocation(ctx.argv);
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "process"],
            &args.unknown,
        );
        if args.informational || !args.unknown.is_empty() {
            return;
        }
        if args.unsupported {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unsupported,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("gzip lzw output is unsupported".into()),
                },
                CoverageLevel::Partial,
            );
            return;
        }
        let suffix_valid = args.suffix.as_literal().is_some_and(|suffix| {
            !suffix.is_empty() && suffix.len() <= 30 && !suffix.contains('/')
        });
        if !suffix_valid {
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unsupported,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("gzip suffix is not a supported literal suffix".into()),
                },
                CoverageLevel::Partial,
            );
            return;
        }
        if !gzip_environment_preserves_endpoints(ctx) {
            for (index, file) in &args.operands {
                if file.as_literal() != Some("-") {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        file,
                        "filesystem.read",
                        Default::default(),
                    );
                }
            }
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unresolved,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("GZIP may change gzip processing or output identity".into()),
                },
                CoverageLevel::Partial,
            );
            return;
        }
        if args.recursive {
            for (index, file) in &args.operands {
                if file.as_literal() == Some("-") {
                    continue;
                }
                let mut attributes = program_input_attrs();
                attributes.insert("recursive".into(), AttrValue::Bool(true));
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.read",
                    attributes,
                );
            }
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::MODEL_COVERAGE,
                    class: BoundaryClass::Unmodeled,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("filesystem")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "gzip recursive output identities depend on discovered file kinds".into(),
                    ),
                },
                CoverageLevel::Partial,
            );
            return;
        }
        let stream_output = args.stdout
            || args.operands.is_empty()
            || args
                .operands
                .iter()
                .any(|(_, operand)| operand.as_literal() == Some("-"));
        let mut stream_reads = Vec::new();
        let mut stream_exact = args.exact_options
            && args.operands.len() <= 1
            && ctx.argv.iter().all(|word| word.as_literal().is_some())
            && builder.execution_is_exact(builder.current_execution());
        for (index, file) in &args.operands {
            if file.as_literal() == Some("-") {
                continue;
            }
            let derived = gzip_derived_output(file, &args.suffix, args.decompress, args.force);
            if args.list || args.test || args.stdout {
                let possible_read = !args.decompress
                    || !matches!(
                        &derived,
                        GzipDerivedOutput::Unresolved {
                            operand_may_transform: false
                        }
                    );
                if possible_read {
                    let read = operand_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        file,
                        "filesystem.read",
                        program_input_attrs(),
                    );
                    if args.stdout
                        && let Some(read) = read
                    {
                        stream_reads.push(read);
                    }
                }
                if args.decompress && matches!(&derived, GzipDerivedOutput::Unresolved { .. }) {
                    stream_exact = false;
                    builder.boundary_with_coverage(
                        Boundary {
                            reason: BoundaryReason::MODEL_COVERAGE,
                            class: BoundaryClass::Unresolved,
                            scope: effinterp_proto::BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("filesystem")],
                            provenance: vec![model_node],
                            limit: None,
                            detail: Some(
                                "gzip may select an input by appending a compressed suffix".into(),
                            ),
                        },
                        CoverageLevel::Partial,
                    );
                }
                continue;
            }
            if args.decompress && args.restore_name {
                let possible_read = !matches!(
                    derived,
                    GzipDerivedOutput::Unresolved {
                        operand_may_transform: false
                    }
                );
                if possible_read {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        *index,
                        file,
                        "filesystem.read",
                        program_input_attrs(),
                    );
                    if !args.keep {
                        operand_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            file,
                            "filesystem.delete",
                            Default::default(),
                        );
                    }
                }
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::MODEL_COVERAGE,
                        class: BoundaryClass::Unresolved,
                        scope: effinterp_proto::BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some(
                            "gzip may restore the output basename from the compressed header"
                                .into(),
                        ),
                    },
                    CoverageLevel::Partial,
                );
                continue;
            }
            let output = match derived {
                GzipDerivedOutput::Derived(output) => output,
                GzipDerivedOutput::Unchanged => continue,
                GzipDerivedOutput::Unresolved {
                    operand_may_transform,
                } => {
                    if operand_may_transform {
                        operand_effect(
                            builder,
                            ctx,
                            model_node,
                            *index,
                            file,
                            "filesystem.read",
                            program_input_attrs(),
                        );
                        if !args.keep {
                            operand_effect(
                                builder,
                                ctx,
                                model_node,
                                *index,
                                file,
                                "filesystem.delete",
                                Default::default(),
                            );
                        }
                    }
                    builder.boundary_with_coverage(
                        Boundary {
                            reason: BoundaryReason::MODEL_COVERAGE,
                            class: BoundaryClass::Unresolved,
                            scope: effinterp_proto::BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("filesystem")],
                            provenance: vec![model_node],
                            limit: None,
                            detail: Some(
                                if args.decompress {
                                    "gzip input or derived output name is not statically recoverable"
                                } else {
                                    "gzip derived output name is not statically recoverable"
                                }
                                .into(),
                            ),
                        },
                        CoverageLevel::Partial,
                    );
                    continue;
                }
            };
            let read = operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                file,
                "filesystem.read",
                program_input_attrs(),
            );
            let write = operand_effect(
                builder,
                ctx,
                model_node,
                *index,
                &output,
                "filesystem.write",
                program_output_attrs(),
            );
            if let (Some(read), Some(write)) = (read, write) {
                value_dependency_binding(
                    builder,
                    model_node,
                    read,
                    write,
                    args.operands.len() == 1
                        && args.exact_options
                        && file.as_literal().is_some()
                        && builder.execution_is_exact(builder.current_execution()),
                );
            }
            if !args.keep {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    file,
                    "filesystem.delete",
                    Default::default(),
                );
            }
        }
        if stream_output && !args.list && !args.test && args.operands.len() <= 1 {
            use crate::flow::{BindEnd, FlowStage, PortBinding};
            use effinterp_proto::{CausalAssurance, Port};

            let assurance = if stream_exact {
                CausalAssurance::Exact
            } else {
                CausalAssurance::Conservative
            };
            // Nah types decompression as decoding. Compression keeps its direct
            // byte dependency without adding an untranslatable semantic effect.
            let transform = if args.decompress {
                builder.effect(effinterp_proto::Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Exact,
                    id: Default::default(),
                    operation: effinterp_proto::Operation::new("process.stream_transform"),
                    resource: crate::models::common::code_execution_resource(ctx),
                    attributes: std::collections::BTreeMap::from([(
                        "transform".into(),
                        AttrValue::String("decode".into()),
                    )]),
                    modality: effinterp_proto::Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: vec![model_node],
                })
            } else {
                None
            };
            let mut effects = stream_reads.clone();
            let mut bindings = stream_reads
                .iter()
                .map(|read| PortBinding {
                    assurance,
                    from: BindEnd::Effect(*read),
                    to: BindEnd::Port(Port::Stdout),
                })
                .collect::<Vec<_>>();
            if let Some(transform) = transform {
                effects.push(transform);
                bindings.extend(stream_reads.iter().map(|read| PortBinding {
                    assurance,
                    from: BindEnd::Effect(*read),
                    to: BindEnd::Effect(transform),
                }));
                bindings.push(PortBinding {
                    assurance,
                    from: BindEnd::Effect(transform),
                    to: BindEnd::Port(Port::Stdout),
                });
            }
            if args.operands.is_empty()
                || args
                    .operands
                    .iter()
                    .any(|(_, operand)| operand.as_literal() == Some("-"))
            {
                bindings.push(PortBinding {
                    assurance,
                    from: BindEnd::Port(Port::Stdin),
                    to: BindEnd::Port(Port::Stdout),
                });
                if let Some(transform) = transform {
                    bindings.push(PortBinding {
                        assurance,
                        from: BindEnd::Port(Port::Stdin),
                        to: BindEnd::Effect(transform),
                    });
                }
            }
            if !bindings.is_empty() {
                builder.flow_stage(FlowStage {
                    execution: Some(builder.current_execution()),
                    effects,
                    bindings,
                    provenance: vec![model_node],
                });
            }
        }
    }
}

/// `chattr`/`setfacl`: change file metadata (e.g. the immutable bit, ACLs).
struct Attr;

impl CommandModel for Attr {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "util/fileattr@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["chattr", "setfacl"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let command = ctx.argv[0]
            .as_literal()
            .and_then(|name| name.rsplit('/').next())
            .unwrap_or("");
        let mut unknown_flags = Vec::new();
        // Each operand with whether the change is recursive and whether it
        // leaves the file's `other` entry granting write.
        let operands: Vec<(u32, &Word, bool, bool)> = if command == "setfacl" {
            // acl's setfacl parses with getopt_long, so an unambiguous long
            // prefix such as `--rec` selects `--recursive`.
            let scanned = scan(
                ctx.argv,
                &FlagSpec {
                    allow_abbreviation: true,
                    value_flags: &[
                        "-m",
                        "--modify",
                        "-x",
                        "--remove",
                        "-s",
                        "--set",
                        "-M",
                        "--modify-file",
                        "-X",
                        "--remove-file",
                        "--set-file",
                        "--restore",
                    ],
                    known_flags: &[
                        "-b",
                        "--remove-all",
                        "-k",
                        "--remove-default",
                        "-n",
                        "--no-mask",
                        "--mask",
                        "-d",
                        "--default",
                        "-R",
                        "--recursive",
                        "-L",
                        "--logical",
                        "-P",
                        "--physical",
                        "-t",
                        "--test",
                        "-v",
                        "--version",
                        "-h",
                        "--help",
                    ],
                },
            );
            let operations = setfacl_operations(&scanned);
            unknown_flags = scanned.unknown_flags;
            operations
        } else {
            let (recursive, files) = chattr_arguments(ctx.argv);
            files
                .into_iter()
                .map(|(index, operand)| (index, operand, recursive, false))
                .collect()
        };
        for (index, operand, recursive, world_write) in operands {
            // An ACL edit is a permission change: the owner, group and other
            // entries are the file's mode bits, and every other entry grants
            // or revokes access the way chmod does (acl(5)).
            let action = if command == "setfacl" {
                "chmod"
            } else {
                command
            };
            let mut attributes: Attrs = [("action".into(), AttrValue::String(action.into()))]
                .into_iter()
                .collect();
            if recursive {
                attributes.insert("recursive".into(), AttrValue::Bool(true));
            }
            if world_write {
                attributes.insert("world_write".into(), AttrValue::Bool(true));
            }
            // setfacl's whole argv was reviewed, so each operand is exactly
            // a file it edits.
            if command == "setfacl" && unknown_flags.is_empty() {
                let arg = crate::models::common::fs_arg_node(builder, ctx, index, operand);
                builder.effect(effinterp_proto::Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Exact,
                    id: Default::default(),
                    operation: effinterp_proto::Operation::new("filesystem.metadata"),
                    resource: ctx.resolve_fs_word(operand),
                    attributes,
                    modality: effinterp_proto::Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: vec![arg, model_node],
                });
            } else {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    operand,
                    "filesystem.metadata",
                    attributes,
                );
            }
        }
        fs_full_no_spawn(builder);
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown_flags);
    }
}

/// The files chattr changes, and whether a valid invocation recurses, parsed
/// the way e2fsprogs' chattr.c `decode_arg` reads its arguments. Words are
/// read in order until `--` or the first word that does not start with `-`,
/// `+` or `=`; every later word is a file. In a `-` word, R, V and f are
/// options, p and v each take the next word as their value, and any other
/// letter is an attribute to remove, so `-Ri` recurses and `-Rv 1` consumes
/// the `1`. `+` and `=` words hold attribute letters only, so `+R` is not
/// recursion. chattr prints usage and changes nothing on an unknown letter, a
/// missing or malformed value, no mode, `=` mixed with `-` or `+`, or a letter
/// both added and removed. A value that is not a literal cannot be checked and
/// is taken as valid.
///
/// Only the returned recursion is certified by that validity check. The files
/// are returned even when chattr would reject the invocation, so callers keep
/// them as conservative targets rather than a validated change set.
fn chattr_arguments(argv: &[Word]) -> (bool, Vec<(u32, &Word)>) {
    const ATTRIBUTES: &str = "ASDacmdeijPsutTCxF";
    let (mut recursive, mut valid, mut value) = (false, true, false);
    let (mut add, mut set) = (false, false);
    let (mut added, mut removed) = (String::new(), String::new());
    let mut index = 1;
    while let Some(text) = argv.get(index).and_then(Word::as_literal) {
        if text == "--" {
            index += 1;
            break;
        }
        let mut letters = text.chars();
        match letters.next() {
            Some('-') => {
                for letter in letters {
                    match letter {
                        'R' => recursive = true,
                        'V' | 'f' => {}
                        'p' | 'v' => {
                            index += 1;
                            value = true;
                            valid &= argv
                                .get(index)
                                .is_some_and(|word| word.as_literal().is_none_or(chattr_number));
                        }
                        _ => {
                            valid &= ATTRIBUTES.contains(letter);
                            removed.push(letter);
                        }
                    }
                }
            }
            Some(mode @ ('+' | '=')) => {
                add |= mode == '+';
                set |= mode == '=';
                let letters = letters.as_str();
                valid &= letters.chars().all(|letter| ATTRIBUTES.contains(letter));
                added.push_str(letters);
            }
            _ => break,
        }
        index += 1;
    }
    let remove = !removed.is_empty();
    valid &= (add || remove || set || value)
        && !(set && (add || remove))
        && !removed.chars().any(|letter| added.contains(letter));
    let files = (index..argv.len())
        .map(|index| (index as u32, &argv[index]))
        .collect();
    (recursive && valid, files)
}

/// Whether chattr accepts `text` as a `-p` or `-v` value: `strtol(text,
/// &end, 0)` must consume all of it. Leading whitespace and a sign are
/// allowed, `0x` selects hex and a leading `0` octal, so `0x1f`, ` -7` and
/// `017` pass while `08`, `1junk`, `1 ` and `--` do not.
fn chattr_number(text: &str) -> bool {
    let rest = text.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let rest = rest.strip_prefix(['+', '-']).unwrap_or(rest);
    let (digits, radix) = match rest.strip_prefix("0x").or(rest.strip_prefix("0X")) {
        Some(hex) if hex.starts_with(|digit: char| digit.is_ascii_hexdigit()) => (hex, 16),
        _ if rest.starts_with('0') => (rest, 8),
        _ => (rest, 10),
    };
    // strtol converts nothing in an empty string and leaves `end` at its
    // terminator, which chattr accepts.
    text.is_empty() || (!digits.is_empty() && digits.chars().all(|digit| digit.is_digit(radix)))
}

/// The files setfacl changes, in argument order, with the recursion and
/// other-write grant in force for each. setfacl.c reads options and files in
/// the order given: each file receives the ACL changes collected since the
/// last file, and the next option starts a fresh collection. A file with no
/// collected change, `--version` or `--help` ends the run. `-d` makes every later entry a default
/// entry, which only seeds files created later; `-R` and `--test` hold for
/// every later file.
fn setfacl_operations<'a>(
    scanned: &crate::models::args::Scanned<'a>,
) -> Vec<(u32, &'a Word, bool, bool)> {
    enum SetfaclEvent<'s, 'a> {
        Flag(&'s crate::models::args::Flag<'a>),
        File(u32, &'a Word),
    }
    let mut events: Vec<(u32, SetfaclEvent<'_, 'a>)> = scanned
        .flags
        .iter()
        .map(|flag| (flag.index, SetfaclEvent::Flag(flag)))
        .chain(
            scanned
                .operands
                .iter()
                .map(|(index, operand)| (*index, SetfaclEvent::File(*index, operand))),
        )
        .collect();
    // Stable, so options clustered in one word keep their order.
    events.sort_by_key(|(index, _)| *index);
    let mut operations = Vec::new();
    let (mut recursive, mut test, mut promote) = (false, false, false);
    let (mut collected, mut granted, mut saw_files) = (false, false, false);
    for (_, event) in events {
        match event {
            SetfaclEvent::Flag(flag) => {
                if std::mem::take(&mut saw_files) {
                    collected = false;
                    granted = false;
                }
                match flag.name {
                    // Both print and exit where they appear; files already
                    // processed keep their changes.
                    "-v" | "--version" | "-h" | "--help" => break,
                    "-R" | "--recursive" => recursive = true,
                    "-t" | "--test" => test = true,
                    "-d" | "--default" => promote = true,
                    "-b" | "--remove-all" | "-k" | "--remove-default" => collected = true,
                    "-m" | "--modify" | "-s" | "--set" | "-x" | "--remove" => {
                        collected = true;
                        granted = setfacl_other_write(flag, promote, granted);
                    }
                    // An ACL file's contents are not observed.
                    "-M" | "--modify-file" | "-X" | "--remove-file" | "--set-file" => {
                        collected = true;
                        granted = false;
                    }
                    "--restore" => saw_files = true,
                    _ => {}
                }
            }
            SetfaclEvent::File(index, operand) => {
                if !collected {
                    break;
                }
                saw_files = true;
                if !test {
                    operations.push((index, operand, recursive, granted));
                }
            }
        }
    }
    operations
}

/// Whether the access ACL's `other` entry grants write after one `-m`,
/// `--set` or `-x` ACL, given whether it did before. setfacl(1) spells the
/// entry `[d[efault]:]o[ther][:]:perms`, perms as `rwxX-` letters or one
/// octal digit; the ACL mask never limits it. `--set` replaces the access
/// ACL only when it names an access entry. An ACL that is not literal or a
/// removed `other` entry leaves the grant unproven.
fn setfacl_other_write(flag: &crate::models::args::Flag<'_>, promote: bool, granted: bool) -> bool {
    let Some(acl) = flag.value.as_ref().and_then(Word::as_literal) else {
        return false;
    };
    let access: Vec<Vec<&str>> = acl
        .split([',', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            let mut fields: Vec<_> = entry.split(':').collect();
            let default = matches!(fields[0], "d" | "default");
            if default {
                fields.remove(0);
            }
            (!default && !promote).then_some(fields)
        })
        .collect();
    let replaced = matches!(flag.name, "-s" | "--set") && !access.is_empty();
    let mut granted = granted && !replaced;
    for fields in access {
        if !matches!(fields.first(), Some(&("o" | "other"))) {
            continue;
        }
        let perms = match fields.as_slice() {
            _ if matches!(flag.name, "-x" | "--remove") => None,
            [_, perms] | [_, "", perms] => Some(*perms),
            _ => None,
        };
        granted = perms.is_some_and(|perms| match perms.as_bytes() {
            [digit] if digit.is_ascii_digit() => digit.wrapping_sub(b'0') & 2 != 0,
            _ => perms.contains('w'),
        });
    }
    granted
}

/// Adds macOS chmod's ACL edits and its rejection of long options to the
/// compiled `coreutils/chmod@v1` document, whose grammar is GNU's.
pub(super) fn with_macos_acl(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(MacosAclChmod { owner })
}

struct MacosAclChmod {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for MacosAclChmod {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn records_process(&self) -> bool {
        self.owner.records_process()
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.stdout_value_bindings(argv)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn descriptor_operands(&self, argv: &[Word]) -> Vec<(u32, Word)> {
        self.owner.descriptor_operands(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx.os_dialect(builder) == effinterp_proto::OsDialect::Macos
            && macos_rejects_long_option(ctx.argv)
        {
            // chmod exits with a usage error before changing any file.
            fs_full_no_spawn(builder);
            return;
        }
        let Some(edit) = macos_acl_edit(ctx.argv) else {
            self.owner.apply(builder, ctx, model_node);
            return;
        };
        // An ACL entry grants or revokes access the way a mode bit does, so
        // the edit is a permission change (acl(5)).
        let mut attributes: Attrs = [("action".into(), AttrValue::String("chmod".into()))]
            .into_iter()
            .collect();
        if edit.recursive {
            attributes.insert("recursive".into(), AttrValue::Bool(true));
        }
        // Only an invocation chmod is known to accept certifies its grant.
        let certified = edit.accepted && edit.world_write.is_some();
        if certified && edit.world_write == Some(true) {
            attributes.insert("world_write".into(), AttrValue::Bool(true));
        }
        for (index, file) in edit.files {
            if certified {
                exact_metadata_effect(builder, ctx, model_node, index, file, attributes.clone());
            } else {
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    file,
                    "filesystem.metadata",
                    attributes.clone(),
                );
            }
        }
        fs_full_no_spawn(builder);
        if !certified {
            boundary(
                builder,
                model_node,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &["filesystem"],
                "chmod ACL edit is not understood",
            );
        }
    }
}

/// Whether macOS chmod stops with a usage error on a GNU long option such as
/// `--rec`. file_cmds' chmod.c reads options with getopt(3), which has no long
/// options: `--rec` is the option letter `-`, which it rejects. Options come
/// first, up to `--` or the first other word; a word such as `-w` is a mode,
/// which ends them too. Only the system directories certainly hold Apple's
/// chmod: a bare `chmod` may find GNU coreutils' first on `PATH`.
fn macos_rejects_long_option(argv: &[Word]) -> bool {
    if !argv[0].as_literal().is_some_and(|path| path.contains('/'))
        || !crate::exec::established_program(&argv[0])
    {
        return false;
    }
    for word in &argv[1..] {
        let Some(text) = word.as_literal() else {
            return false;
        };
        if text.len() > 2 && text.starts_with("--") {
            return true;
        }
        match text.strip_prefix('-') {
            Some(letters)
                if !letters.is_empty()
                    && letters.chars().all(|letter| "fhvRHLP".contains(letter)) => {}
            _ => return false,
        }
    }
    false
}

/// A macOS chmod ACL edit and the files it applies to.
struct MacosAclEdit<'a> {
    /// Whether chmod accepts the edit's options and position; false when a
    /// word it validates is not literal.
    accepted: bool,
    recursive: bool,
    /// Whether the edit adds an entry granting everyone write; `None` when
    /// the entries are not ones this model understands.
    world_write: Option<bool>,
    files: Vec<(u32, &'a Word)>,
}

/// The ACL edit in a macOS chmod invocation, read the way file_cmds'
/// chmod.c reads it. Options from `fhvRHLP` come first, up to `--` or the
/// first other word. That word is an ACL edit when it is `+a` (add), `-a`
/// (remove) or `=a` (rewrite), followed by any number of `i` (the entry is
/// marked inherited) and then optionally `#`, which ends the modifiers and
/// takes the next word as the entry's position. `-a#` removes by position
/// alone; every other form takes the entries next. Every later word is a
/// file. Anything else is left to the mode grammar, and so is an edit chmod
/// rejects before changing anything: another modifier letter, `-R` with
/// `-h`, or a literal position it cannot read.
fn macos_acl_edit(argv: &[Word]) -> Option<MacosAclEdit<'_>> {
    let mut index = 1;
    let (mut recursive, mut no_follow) = (false, false);
    loop {
        let text = argv.get(index)?.as_literal()?;
        if text == "--" {
            index += 1;
            break;
        }
        match text.strip_prefix('-') {
            Some(letters)
                if !letters.is_empty()
                    && letters.chars().all(|letter| "fhvRHLP".contains(letter)) =>
            {
                recursive |= letters.contains('R');
                no_follow |= letters.contains('h');
                index += 1;
            }
            _ => break,
        }
    }
    let edit = argv.get(index)?.as_literal()?;
    let (operation, suffix) = match edit.as_bytes() {
        [operation @ (b'+' | b'-' | b'='), b'a', ..] => (*operation, &edit[2..]),
        _ => return None,
    };
    let ordered = match suffix.trim_start_matches('i') {
        "" => false,
        rest if rest.starts_with('#') => true,
        _ => return None,
    };
    if recursive && no_follow {
        return None;
    }
    index += 1;
    let mut accepted = true;
    if ordered {
        match argv.get(index)?.as_literal() {
            Some(position) if !macos_acl_position(position) => return None,
            Some(_) => {}
            None => accepted = false,
        }
        index += 1;
    }
    let world_write = if operation == b'-' && ordered {
        Some(false)
    } else {
        index += 1;
        argv.get(index - 1)?
            .as_literal()
            .and_then(macos_acl_grants_everyone_write)
            // Removing entries never grants access.
            .map(|granted| granted && operation != b'-')
    };
    let files: Vec<_> = (index..argv.len())
        .map(|index| (index as u32, &argv[index]))
        .collect();
    (!files.is_empty()).then_some(MacosAclEdit {
        accepted,
        recursive,
        world_write,
        files,
    })
}

/// Whether chmod accepts `text` as an ACL entry position: `strtol(text,
/// &end, 0)` must consume all of it without overflow and give 0 through
/// `ACL_MAX_ENTRIES` (128). Leading whitespace and a sign are allowed, `0x`
/// selects hex and a leading `0` octal; an empty word converts nothing and
/// reads as 0.
fn macos_acl_position(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let rest = text.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (negative, rest) = match rest.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, rest.strip_prefix('+').unwrap_or(rest)),
    };
    let (digits, radix) = match rest.strip_prefix("0x").or(rest.strip_prefix("0X")) {
        Some(hex) if hex.starts_with(|digit: char| digit.is_ascii_hexdigit()) => (hex, 16),
        _ if rest.starts_with('0') => (rest, 8),
        _ => (rest, 10),
    };
    !digits.is_empty()
        && digits.chars().all(|digit| digit.is_digit(radix))
        && u64::from_str_radix(digits, radix)
            .is_ok_and(|position| position <= 128 && (!negative || position == 0))
}

/// Whether chmod's ACL argument grants everyone write: chmod.c's
/// `parse_acl_entries` reads one entry per line and skips empty lines.
/// `None` when an entry is not one chmod accepts, or there is none.
fn macos_acl_grants_everyone_write(acl: &str) -> Option<bool> {
    let mut entries = acl.split('\n').filter(|entry| !entry.is_empty()).peekable();
    entries.peek()?;
    entries.try_fold(false, |granted, entry| {
        Some(granted | macos_ace_grants_everyone_write(entry)?)
    })
}

/// Whether a chmod(1) ACL entry grants everyone write to the file it is
/// applied to, read the way chmod_acl.c's `parse_entry` reads it. After an
/// optional `user:` or `group:` prefix, the name ends at the first `:` when
/// the rest holds one and at the first space otherwise; the tag, `allow` or
/// `deny`, ends at the next `:` or space; the rest is a comma-separated list
/// of permissions and flags whose empty fields are skipped, and which must
/// name at least one. `None` when the entry is not one chmod accepts. Write
/// means changing contents or entries, or the ACL or owner that decide who
/// may; an `only_inherit` entry applies only to files created later.
fn macos_ace_grants_everyone_write(entry: &str) -> Option<bool> {
    const PERMISSIONS: [&str; 22] = [
        "read",
        "write",
        "append",
        "execute",
        "list",
        "search",
        "add_file",
        "add_subdirectory",
        "delete_child",
        "delete",
        "readattr",
        "writeattr",
        "readextattr",
        "writeextattr",
        "readsecurity",
        "writesecurity",
        "chown",
        "file_inherit",
        "directory_inherit",
        "limit_inherit",
        "only_inherit",
        "inherited",
    ];
    const WRITE: [&str; 7] = [
        "write",
        "append",
        "add_file",
        "add_subdirectory",
        "delete_child",
        "writesecurity",
        "chown",
    ];
    // The group every user belongs to, by name or by its fixed UUID.
    const EVERYONE: [&str; 2] = ["everyone", "abcdefab-cdef-abcd-efab-cdef0000000c"];
    let entry = entry
        .strip_prefix("user:")
        .or_else(|| entry.strip_prefix("group:"))
        .unwrap_or(entry);
    let delimiter = if entry.contains(':') { ':' } else { ' ' };
    let (name, rest) = entry.split_once(delimiter)?;
    let (kind, permissions) = rest.split_once([':', ' '])?;
    let allow = match kind {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    let permissions: Vec<&str> = permissions
        .split(',')
        .filter(|permission| !permission.is_empty())
        .collect();
    if name.is_empty()
        || permissions.is_empty()
        || !permissions
            .iter()
            .all(|permission| PERMISSIONS.contains(permission))
    {
        return None;
    }
    Some(
        allow
            && EVERYONE.contains(&name.to_ascii_lowercase().as_str())
            && !permissions.contains(&"only_inherit")
            && permissions
                .iter()
                .any(|permission| WRITE.contains(permission)),
    )
}

/// Windows `icacls FILE [switches]`: `/grant`, `/deny`, `/remove`, `/reset`
/// and `/inheritance` edit the file's ACL, `/setowner` its owner, and `/T`
/// extends either to everything beneath it. With neither, icacls only
/// displays (`/verify`, `/findsid` check) the ACLs, or `/save`s them to a
/// file.
struct Icacls;

impl CommandModel for Icacls {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "windows/icacls@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["icacls", "icacls.exe"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        let Some(target) = ctx
            .argv
            .get(1)
            .filter(|word| word.as_literal().is_none_or(|text| !text.starts_with('/')))
        else {
            boundary(
                builder,
                model_node,
                BoundaryReason::MISSING_REQUIRED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &["filesystem"],
                "icacls names no file",
            );
            return;
        };
        let switch = |word: &Word| word.as_literal().is_some_and(|text| text.starts_with('/'));
        let (mut recursive, mut acl, mut owner, mut world_write, mut unproven) =
            (false, false, false, false, false);
        let mut saved = None;
        let mut unknown = Vec::new();
        let mut index = 2;
        while let Some(word) = ctx.argv.get(index) {
            let text = word.as_literal().unwrap_or("<dynamic>");
            let name = text.to_ascii_lowercase();
            index += 1;
            if !switch(word) {
                unknown.push((index as u32 - 1, text.to_string()));
                continue;
            }
            // The words up to the next switch are this switch's values.
            let end = ctx.argv[index..]
                .iter()
                .position(switch)
                .map_or(ctx.argv.len(), |offset| index + offset);
            let values = &ctx.argv[index..end];
            match name.as_str() {
                "/t" => recursive = true,
                // Continue past errors, act on a link itself, stay quiet.
                "/c" | "/l" | "/q" | "/verify" => {}
                "/grant" | "/grant:r" | "/deny" | "/remove" | "/remove:g" | "/remove:d"
                    if !values.is_empty() =>
                {
                    acl = true;
                    if name.starts_with("/grant") {
                        for value in values {
                            match value.as_literal().and_then(icacls_grants_everyone_write) {
                                Some(grant) => world_write |= grant,
                                None => unproven = true,
                            }
                        }
                    }
                    index = end;
                }
                "/reset" | "/inheritance:e" | "/inheritance:d" | "/inheritance:r" => acl = true,
                "/setowner" if !values.is_empty() => {
                    owner = true;
                    index += 1;
                }
                "/findsid" if !values.is_empty() => index += 1,
                "/save" if !values.is_empty() => {
                    saved = Some(index as u32);
                    index += 1;
                }
                _ => unknown.push((index as u32 - 1, text.to_string())),
            }
        }
        let text = target.as_literal().unwrap_or_default();
        if text.contains(['*', '?']) {
            boundary(
                builder,
                model_node,
                BoundaryReason::MODEL_COVERAGE,
                BoundaryClass::Unmodeled,
                &["filesystem"],
                "icacls matches its wildcard against the directory at run time",
            );
        }
        let mut attributes = Attrs::new();
        if recursive {
            attributes.insert("recursive".into(), AttrValue::Bool(true));
        }
        // An unrecognized switch may still edit the ACL, so the edit stays.
        let changes = [
            (acl || !unknown.is_empty(), "chmod", world_write),
            (owner, "chown", false),
        ];
        if changes.iter().any(|(changed, _, _)| *changed) {
            for (_, action, world_write) in changes.into_iter().filter(|change| change.0) {
                let mut attributes = attributes.clone();
                attributes.insert("action".into(), AttrValue::String(action.into()));
                if world_write {
                    attributes.insert("world_write".into(), AttrValue::Bool(true));
                }
                if unknown.is_empty() && !unproven {
                    exact_metadata_effect(builder, ctx, model_node, 1, target, attributes);
                } else {
                    operand_effect(
                        builder,
                        ctx,
                        model_node,
                        1,
                        target,
                        "filesystem.metadata",
                        attributes,
                    );
                }
            }
        } else {
            attributes.insert("metadata".into(), AttrValue::Bool(true));
            operand_effect(
                builder,
                ctx,
                model_node,
                1,
                target,
                "filesystem.read",
                attributes,
            );
        }
        if let Some(index) = saved {
            operand_effect(
                builder,
                ctx,
                model_node,
                index,
                &ctx.argv[index as usize],
                "filesystem.write",
                program_output_attrs(),
            );
        }
        if unproven {
            boundary(
                builder,
                model_node,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &["filesystem"],
                "icacls grant entry is not understood",
            );
        }
        unrecognized_arguments_boundary(builder, model_node, &["filesystem"], &unknown);
    }
}

/// Whether an icacls `/grant` entry, `sid:perm`, grants everyone write to
/// the file itself. The SID is `Everyone` or its string form `*S-1-1-0`. The
/// permission is a run of parenthesized groups, each an inheritance flag
/// (`OI`, `CI`, `IO`, `NP`, `I`), a simple right, or comma-separated
/// specific rights, and at most one bare sequence of simple rights such as
/// `RX` or `RW`. `None` when the entry is not one icacls accepts. Write means changing contents or entries, or the ACL or owner
/// that decide who may; an `IO` entry applies only to files created later.
fn icacls_grants_everyone_write(entry: &str) -> Option<bool> {
    const INHERITANCE: [&str; 5] = ["OI", "CI", "IO", "NP", "I"];
    const RIGHTS: [&str; 27] = [
        "N", "F", "M", "RX", "R", "W", "D", "DE", "RC", "WDAC", "WO", "S", "AS", "MA", "GR", "GW",
        "GE", "GA", "RD", "WD", "AD", "REA", "WEA", "X", "DC", "RA", "WA",
    ];
    const WRITE: [&str; 11] = [
        "F", "M", "W", "WDAC", "WO", "MA", "GW", "GA", "WD", "AD", "DC",
    ];
    let (sid, mut permission) = entry.rsplit_once(':')?;
    let mut tokens = Vec::new();
    while !permission.is_empty() {
        let group = match permission.strip_prefix('(') {
            Some(rest) => {
                let (group, rest) = rest.split_once(')')?;
                permission = rest;
                group
            }
            None => {
                tokens.extend(icacls_simple_rights(std::mem::take(&mut permission))?);
                continue;
            }
        };
        tokens.extend(group.split(',').map(str::to_ascii_uppercase));
    }
    if tokens.is_empty()
        || !tokens
            .iter()
            .all(|token| INHERITANCE.contains(&token.as_str()) || RIGHTS.contains(&token.as_str()))
    {
        return None;
    }
    Some(
        matches!(sid.to_ascii_lowercase().as_str(), "everyone" | "*s-1-1-0")
            && !tokens.iter().any(|token| token == "IO")
            && tokens.iter().any(|token| WRITE.contains(&token.as_str())),
    )
}

/// A bare icacls permission as its simple rights (`N`, `F`, `M`, `RX`, `R`,
/// `W`, `D`), read left to right; `None` when it holds anything else.
fn icacls_simple_rights(sequence: &str) -> Option<Vec<String>> {
    let mut rights = Vec::new();
    let mut rest = sequence.to_ascii_uppercase();
    while !rest.is_empty() {
        let length = if rest.starts_with("RX") {
            2
        } else if rest.starts_with(['N', 'F', 'M', 'R', 'W', 'D']) {
            1
        } else {
            return None;
        };
        rights.push(rest[..length].to_string());
        rest.drain(..length);
    }
    Some(rights)
}

/// A metadata change whose whole argv was reviewed, so `operand` is exactly
/// an entry it edits.
fn exact_metadata_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operand: &Word,
    attributes: Attrs,
) {
    let arg = crate::models::common::fs_arg_node(builder, ctx, index, operand);
    builder.effect(effinterp_proto::Effect {
        request_assurance: effinterp_proto::RequestAssurance::Exact,
        id: Default::default(),
        operation: effinterp_proto::Operation::new("filesystem.metadata"),
        resource: ctx.resolve_fs_word(operand),
        attributes,
        modality: effinterp_proto::Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: vec![arg, model_node],
    });
}

fn attr_bool(key: &str) -> Attrs {
    let mut a = Attrs::new();
    a.insert(key.to_string(), AttrValue::Bool(true));
    a
}

/// Info-ZIP's command line as far as `-m` deletion depends on it: the
/// archive, the input members, and the options that change which members are
/// removed. Options may follow operands; `--` ends them. A detached `-x` or
/// `-i` takes the words after it as a pattern list, ended by the next option
/// or a lone `@`. Short options cluster, including the two-letter ones
/// (`-rmsf`). Only a detached `-x` list ended by an option or the command
/// line is used to prove a member is kept; an attached pattern (`-xPAT`,
/// `--exclude=PAT`, `-x@file`), an `@`-ended list, or an include leaves the
/// selection unresolved.
#[derive(Default)]
struct ZipArguments<'a> {
    members: Vec<(u32, &'a Word)>,
    moves: bool,
    recursive: bool,
    /// `-R`/`--recurse-patterns`: the operands are patterns matched across
    /// the current directory's tree, not paths.
    recurse_patterns: bool,
    /// `-y`/`--symlinks` stores a link as the link instead of what it names.
    symlinks: bool,
    /// `-sf`/`--show-files` (and the Unicode variants) list and exit.
    list_only: bool,
    /// Modes whose operands are archive entries or that rewrite the archive
    /// alone: `-d`, `-U`, `-F`, `-FF`, `-FS`.
    entry_mode: bool,
    /// Detached `-x` list patterns; `None` for one that is not literal.
    exclusions: Vec<Option<&'a str>>,
    /// An include, a pattern-recursion (`-R`) selection, or an exclusion this
    /// does not prove narrows the members in a way not read here.
    selection_unresolved: bool,
    /// `-ws`, `-nw`, `-w` or `-ic` change how patterns match, or a symbolic
    /// word before `--` may be such an option.
    matching_changed: bool,
    unknown: bool,
}

fn zip_arguments(argv: &[Word]) -> ZipArguments<'_> {
    // Short options that take the rest of their word or the next word.
    const VALUE: &str = "bnstPZO";
    const BOOLEAN: &str = "0123456789ADJLSTXcefghjklmoqruvyz$";
    const LIST_ONLY: &[&str] = &["sf", "su", "sU", "-show-files"];
    const ENTRY_MODES: &[&str] = &["d", "U", "F", "FF", "FS", "-delete", "-copy-entries"];
    const MATCHING: &[&str] = &[
        "ws",
        "nw",
        "w",
        "ic",
        "-wild-stop-dirs",
        "-no-wild",
        "-ignore-case",
    ];
    const TWO_LETTER_BOOLEAN: &[&str] = &[
        "sc", "sd", "so", "sp", "sv", "sb", "la", "li", "ll", "lu", "db", "dc", "dd", "dg", "du",
        "dv", "fz", "AC", "AS", "MM",
    ];
    const TWO_LETTER_VALUE: &[&str] = &["tt", "TT", "lf", "ds"];
    const LONG_BOOLEAN: &[&str] = &[
        "--quiet",
        "--verbose",
        "--junk-paths",
        "--symlinks",
        "--test",
        "--no-extra",
        "--fix",
        "--grow",
        "--freshen",
        "--update",
        "--encrypt",
    ];
    const LONG_VALUE: &[&str] = &[
        "--temp-path",
        "--suffixes",
        "--from-date",
        "--before-date",
        "--password",
        "--compression-method",
        "--split-size",
        "--output-file",
        "--unzip-command",
        "--logfile-path",
    ];
    let mut parsed = ZipArguments::default();
    let mut archive_seen = false;
    let mut options = true;
    // Whether the words that follow belong to a `-x` or `-i` list.
    let mut list: Option<bool> = None;
    let mut i = 1;
    while i < argv.len() {
        let word = &argv[i];
        let index = i as u32;
        i += 1;
        let prefix = word.literal_prefix();
        if options && word.as_literal().is_none() {
            parsed.matching_changed = true;
        }
        if list.is_some() && word.as_literal() == Some("@") {
            list = None;
            parsed.selection_unresolved = true;
            continue;
        }
        if !(options && prefix.starts_with('-') && prefix != "-") {
            match list {
                Some(true) => parsed.exclusions.push(word.as_literal()),
                Some(false) => parsed.selection_unresolved = true,
                None if !archive_seen => archive_seen = true,
                None => parsed.members.push((index, word)),
            }
            continue;
        }
        list = None;
        let Some(text) = word.as_literal() else {
            parsed.unknown = true;
            continue;
        };
        if text == "--" {
            options = false;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let dashed = format!("-{name}");
            match name {
                "move" => parsed.moves = true,
                "recurse-paths" => parsed.recursive = true,
                "recurse-patterns" => {
                    parsed.recursive = true;
                    parsed.recurse_patterns = true;
                    parsed.selection_unresolved = true;
                }
                "symlinks" => parsed.symlinks = true,
                "exclude" | "include" => match value {
                    Some(_) => parsed.selection_unresolved = true,
                    None => list = Some(name == "exclude"),
                },
                _ if LIST_ONLY.contains(&dashed.as_str()) => parsed.list_only = true,
                _ if ENTRY_MODES.contains(&dashed.as_str()) => parsed.entry_mode = true,
                _ if MATCHING.contains(&dashed.as_str()) => parsed.matching_changed = true,
                _ if LONG_BOOLEAN.contains(&text) => {}
                _ if LONG_VALUE.contains(&format!("--{name}").as_str()) => {
                    if value.is_none() {
                        i += 1;
                    }
                }
                _ => parsed.unknown = true,
            }
            continue;
        }
        let letters = &text[1..];
        let mut offset = 0;
        while offset < letters.len() {
            let rest = &letters[offset..];
            let (option, width) = match rest.get(..2) {
                Some(two)
                    if LIST_ONLY.contains(&two)
                        || ENTRY_MODES.contains(&two)
                        || MATCHING.contains(&two)
                        || TWO_LETTER_BOOLEAN.contains(&two)
                        || TWO_LETTER_VALUE.contains(&two) =>
                {
                    (two, 2)
                }
                _ => {
                    let width = rest.chars().next().map_or(1, char::len_utf8);
                    (&rest[..width], width)
                }
            };
            offset += width;
            let attached = &letters[offset..];
            match option {
                _ if LIST_ONLY.contains(&option) => parsed.list_only = true,
                _ if ENTRY_MODES.contains(&option) => parsed.entry_mode = true,
                _ if MATCHING.contains(&option) => parsed.matching_changed = true,
                _ if TWO_LETTER_BOOLEAN.contains(&option) => {}
                _ if TWO_LETTER_VALUE.contains(&option) || VALUE.contains(option) => {
                    if attached.is_empty() {
                        i += 1;
                    }
                    break;
                }
                "x" | "i" => {
                    if attached.is_empty() {
                        list = Some(option == "x");
                    } else {
                        parsed.selection_unresolved = true;
                    }
                    break;
                }
                "m" => parsed.moves = true,
                "r" => parsed.recursive = true,
                "R" => {
                    parsed.recursive = true;
                    parsed.recurse_patterns = true;
                    parsed.selection_unresolved = true;
                }
                "y" => parsed.symlinks = true,
                _ if BOOLEAN.contains(option) => {}
                _ => {
                    parsed.unknown = true;
                    break;
                }
            }
        }
    }
    parsed
}

/// `zip -m` deletes each input member once the archive is written, and `-r`
/// takes a directory member's whole tree with it. A member a literal `-x`
/// pattern matches under the default matching is kept, and only when every
/// option was read. Otherwise the deletion stays and a boundary says the
/// selection may be narrower.
fn zip_move_deletions(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    parsed: &ZipArguments<'_>,
) {
    if !parsed.moves || parsed.list_only || parsed.entry_mode {
        return;
    }
    let mut narrowed = parsed.unknown || parsed.selection_unresolved || parsed.matching_changed;
    // Only the default matching, over a command line read in full, proves an
    // exclusion drops a member.
    let proofs = !narrowed;
    for (index, member) in &parsed.members {
        let dropped = member.as_literal().filter(|_| proofs).and_then(|name| {
            parsed
                .exclusions
                .iter()
                .try_fold(false, |dropped, pattern| {
                    Some(dropped || anchored_exclusion_drops((*pattern)?, name)?)
                })
        });
        if dropped == Some(true) {
            continue;
        }
        narrowed |= !parsed.exclusions.is_empty();
        operand_effect(
            builder,
            ctx,
            model_node,
            *index,
            member,
            "filesystem.delete",
            std::collections::BTreeMap::from([(
                "recursive".into(),
                effinterp_proto::AttrValue::Bool(parsed.recursive),
            )]),
        );
    }
    if narrowed {
        builder.boundary(Boundary {
            reason: BoundaryReason::MODEL_COVERAGE,
            class: BoundaryClass::Unmodeled,
            scope: effinterp_proto::BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("filesystem")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "zip -m options or include/exclude patterns may narrow the members it deletes"
                    .into(),
            ),
        });
    }
}

const OPERAND_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[],
    known_flags: &[
        "-k", "--keep", "-c", "--stdout", "-a", "-b", "-d", "-e", "-f", "-g", "-h", "-i", "-j",
        "-l", "-m", "-n", "-o", "-p", "-q", "-r", "-s", "-t", "-u", "-v", "-w", "-x", "-y", "-z",
        "-A", "-B", "-C", "-D", "-E", "-F", "-G", "-H", "-I", "-J", "-K", "-L", "-M", "-N", "-O",
        "-P", "-Q", "-R", "-S", "-T", "-U", "-V", "-W", "-X", "-Y", "-Z",
    ],
};
