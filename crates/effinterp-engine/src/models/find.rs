//! `find`: the traversal read of its search roots, the expression that
//! selects entries (`-name`, `-path`, `-type`, `-prune`, depth limits), and
//! what its actions do to each match (`-delete`, `-exec CMD {} ;`, printing).
//! The pattern matchers here also serve the archive and coreutils models'
//! exclusion and name globs.

use effinterp_proto::{
    AttrValue, Domain, ObservationOutcome, ObservationQuery, PathFact, PathKind, ProvenanceKind,
    ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use super::sysutils::attr_bool;
use crate::builder::{PlanBuilder, WrittenSource};
use crate::models::common::{
    Attrs, arg_node, fs_arg_effect, fs_full_no_spawn, operand_effect, program_input_attrs,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::{Word, WordPart};

/// `find [roots...] [expression]`: leading non-flag operands are search roots
/// (a traversal read); `-delete` deletes them recursively; `-exec CMD {} ;`
/// runs a command per match, nested with the match path scoped to the roots.
pub(super) struct Find;

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
            // Whether the tests select every entry, or every regular file,
            // below the start path, so no test is a selector of some of them.
            let mut whole = false;
            let named = delete_tests.as_ref().and_then(|(tests, after_action)| {
                let conjunction = find_conjunction(tests);
                // A name or path that every entry matches narrows nothing,
                // nor does a negated one that only the start path matches.
                let selects_all = find_expression(tests)
                    .and_then(|expression| {
                        find_narrowing(&expression, traversal, Some(root.as_literal()?))
                    })
                    .is_some_and(|(narrowing, exact)| exact && narrowing.is_none())
                    || conjunction.as_ref().is_some_and(|conjunction| {
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
                    whole = true;
                    return None;
                }
                // Every regular file below the start path is the whole of
                // what the tree holds, so the delete stays one of the tree.
                if find_selects_every_file(tests, depths, root.as_literal()) {
                    unmodeled_tests = true;
                    whole = true;
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
                    .and_then(|expression| find_narrowing(&expression, traversal, None))
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
                let selector = selector.filter(|_| !whole);
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
        // Only a single-root NUL listing whose tests are a conjunction of
        // depth bounds and name, path and type tests can supply path operands,
        // and only where the model applies every one of them. Other
        // predicates, operators, traversal options and actions keep xargs
        // input unknown, as do indirect consumers and other delimiter modes.
        if builder.stdout_paths_to_xargs
            && plain_traversal
            && roots.len() == 1
            && ctx.argv[2..]
                .iter()
                .map(Word::as_literal)
                .collect::<Option<Vec<_>>>()
                .is_some_and(|expression| find_tested_print0(&expression))
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
                    // The command an action runs removes or empties what it is passed.
                    ctx.argv[*start].as_literal().is_some_and(|command| {
                        matches!(
                            crate::models::args::basename(command),
                            "rm" | "unlink" | "shred" | "truncate"
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

/// `-print0` after nothing but numeric `-mindepth`/`-maxdepth` options and
/// name, path and type tests: find prints, NUL-terminated, every path in the
/// depth range that passes them all.
fn find_tested_print0(expression: &[&str]) -> bool {
    let Some((&"-print0", mut tests)) = expression.split_last() else {
        return false;
    };
    loop {
        tests = match tests {
            [] => return true,
            ["-mindepth" | "-maxdepth", depth, rest @ ..]
                if !depth.is_empty() && depth.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                rest
            }
            [
                "-name" | "-iname" | "-path" | "-ipath" | "-wholename" | "-iwholename" | "-type",
                _,
                rest @ ..,
            ] => rest,
            _ => return false,
        };
    }
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
/// tell `find DIR -type d` from `find DIR`. A start path selected by its
/// name is passed as itself, beside the entries of that name below it.
/// Otherwise only entries below
/// it can match. An entry whose exact name the tests spell is looked up, and
/// passed as that path when it exists and passes every test; deeper entries
/// are selected by the name's glob within the depth bounds. A glob cannot
/// carry `-type`, a `-path` or another filter. An entry type, negation or
/// alternatives are applied to the entries the host lists
/// (`find_listed_matches`); without a listing, a selection those narrow keeps
/// the name's globs and is reported as possibly narrower. Without a name, a
/// selection of every entry is spelled as the start path's children, as is
/// a listing whose every top-level entry a removing command is passed.
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
        Some(expression) => match find_narrowing(&expression, traversal, None) {
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
        && !(removes && find_selects_every_file(tests, depths, Some(spelled)))
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
            removes,
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
        && find_selects_every_file(
            tests,
            depths,
            resolved.as_ref().map(|(spelled, _)| *spelled),
        )
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
    let mut matches = Vec::new();
    // A name test the start path passes selects it and the entries of that
    // name below it, not everything it holds: the start path is passed as
    // itself, and the name's globs below select the rest.
    if depths.min == 0
        && start_selected == Some(true)
        && !roots_only
        && !unfollowed_link
        && !tests.name_patterns().is_empty()
    {
        matches.push(root.clone());
    } else if depths.min == 0 && start_selected != Some(false) {
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
        return (matches, unread);
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
            return (matches, unread);
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
/// no other filter, and depth bounds that reach below the first level. A name
/// or path test that every entry below the start path spelled `root` passes
/// (`-name '*'`, `-path './*'`) is no filter.
fn find_selects_every_file(tests: &[Word], depths: FindDepths, root: Option<&str>) -> bool {
    depths.min <= 1
        && depths.max.is_none_or(|max| max >= 2)
        && find_expression(tests)
            .and_then(|expression| find_narrowing(&expression, FindTraversal::Physical, root))
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
///
/// With `below`, the spelling of a start path, the narrowing is read for the
/// entries below that path only: a name or path test each of them passes
/// (`-name '*'`, `-path './*'`, `! -name .`) then tests nothing, although
/// the start path itself may fail it.
fn find_narrowing(
    expression: &FindExpr,
    traversal: FindTraversal,
    below: Option<&str>,
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
        below: Option<&str>,
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
            FindExpr::Name(pattern, _)
                if below.is_some()
                    && !pattern.is_empty()
                    && pattern.chars().all(|character| character == '*') => {}
            FindExpr::Path(pattern, _)
                if below.is_some_and(|root| find_path_selects_every_entry(pattern, root)) => {}
            FindExpr::Type(types) => admit(kinds(types, false, follows, exact)),
            FindExpr::Not(inner) => match &**inner {
                // No entry below a start path is named `.` or has the start
                // path's own spelling.
                FindExpr::Name(pattern, _) if below.is_some() && pattern == "." => {}
                FindExpr::Path(pattern, _) if below == Some(pattern.as_str()) => {}
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
                    collect(term, follows, below, narrowing, typed, exact);
                }
            }
            FindExpr::Or(alternatives) if alternatives.len() == 1 => {
                collect(&alternatives[0], follows, below, narrowing, typed, exact);
            }
            _ => *exact = false,
        }
    }
    let mut narrowing = effinterp_proto::FsNarrowing::default();
    let (mut typed, mut exact) = (false, true);
    collect(
        expression,
        traversal == FindTraversal::Logical,
        below,
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
    /// The expression with each `-prune` read as the true it evaluates to.
    fn without_prune(&self) -> FindExpr {
        let all = |terms: &[FindExpr]| terms.iter().map(FindExpr::without_prune).collect();
        match self {
            Self::Always | Self::Prune => Self::Always,
            Self::Undecided => Self::Undecided,
            Self::Name(pattern, fold) => Self::Name(pattern.clone(), *fold),
            Self::Path(pattern, fold) => Self::Path(pattern.clone(), *fold),
            Self::Type(types) => Self::Type(types.clone()),
            Self::Action => Self::Action,
            Self::Not(inner) => Self::Not(Box::new(inner.without_prune())),
            Self::And(terms) => Self::And(all(terms)),
            Self::Or(terms) => Self::Or(all(terms)),
        }
    }

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
/// Where a command that `removes` is passed every entry directly below the
/// start path and not the start path itself (`find . ! -name . -exec rm`),
/// the selection is the start path's children, `ROOT/*` and `ROOT/.*`, rather
/// than a list of them: the directory is emptied, however few entries it
/// holds now, which is what a reader of the removal asks about. The children
/// carry the entry kinds and names the tests leave out (`find_narrowing`),
/// and tests that narrowing cannot state keep the list. Every deeper entry
/// selected too, with no depth bound, is everything below the start path.
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
    removes: bool,
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
    // The selected entries below the start path, each with its depth.
    let mut below: Vec<(usize, Word)> = Vec::new();
    // How many entries the start path holds directly, and whether an entry at
    // any depth is left out.
    let (mut children, mut left_out) = (0, false);
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
        children += usize::from(depth == 1);
        if depth < depths.min
            || pruned.iter().any(|directory| {
                entry
                    .path
                    .strip_prefix(directory.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            })
        {
            left_out = true;
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
            below.push((
                depth,
                Word::literal(format!("{}/{}", path.trim_end_matches('/'), entry.path)),
            ));
        } else {
            left_out = true;
        }
        if prune {
            pruned.push(entry.path.clone());
        }
    }
    if removes
        && matches.is_empty()
        && children > 0
        && below.iter().filter(|(depth, _)| *depth == 1).count() == children
        // Every entry directly below the start path was visited and
        // selected, so a `-prune` among the tests held nothing of them back.
        && let Some((narrowing, true)) =
            find_narrowing(&expression.without_prune(), traversal, Some(spelled))
    {
        let base = crate::paths::escape_fs_glob_path(path.trim_end_matches('/'));
        // A glob word carries only its text, so a narrowed selection is
        // passed as the resource it resolves to.
        let glob = |glob: String| {
            Word::new(vec![if narrowing.is_none() {
                WordPart::Glob(glob)
            } else {
                WordPart::Value(ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath {
                        glob,
                        narrowing: narrowing.clone(),
                    },
                })
            }])
        };
        matches.extend([glob(format!("{base}/*")), glob(format!("{base}/.*"))]);
        if !left_out && depths.max.is_none() {
            matches.extend([glob(format!("{base}/*/**")), glob(format!("{base}/.*/**"))]);
            return Some((matches, unmodeled));
        }
        below.retain(|(depth, _)| *depth > 1);
    }
    if matches.len() + below.len() > FIND_MAX_LISTED_MATCHES {
        return None;
    }
    matches.extend(below.into_iter().map(|(_, entry)| entry));
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
