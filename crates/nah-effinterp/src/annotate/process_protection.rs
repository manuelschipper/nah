//! The self-protection tier a launched process carries: a Nah control
//! command, a runtime's hook wiring, Cargo replacing Nah's binary, or a launch
//! environment that bypasses the hook.

use effinterp_proto::{AttrValue, Effect, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::ctx::AbsolutePath;
use nah_proto::effects::Knowledge;
use nah_proto::labels::tier;

use super::executed_identity::executed_identity;
use super::strongest_protection;
use crate::plan_view::PlanView;
use crate::runtime_cli;

/// The agent runtime whose CLI a launched process is recognized as reaching
/// Nah's wiring through (`runtime_cli::recognize_runtime_cli`), or `"nah"`.
/// `None` for any other launch, and for one with an argument that is not a
/// literal.
pub(crate) fn annotate_process_with_authority(
    plan: &Plan,
    effect: &Effect,
    home: &AbsolutePath,
    platform: nah_proto::ctx::Platform,
) -> Option<String> {
    let (executable, _, argv) = process_argv(plan, effect)?;
    let literal = literal_argv(argv)?;
    let control = if nah_proto::labels::normalized_program(executable) == "nah" {
        nah_control(plan, effect, argv)
    } else {
        stated_control(plan, effect)
    };
    runtime_cli::recognize_runtime_cli(executable, &literal, control.is_some(), home, platform)
        .map(str::to_owned)
}

/// The entry id of the engine's model of Nah's own CLI
/// (`effinterp-engine/models/v1/tranche/command-state/nah.json`).
const NAH_MODEL: &str = "cli/nah@v1";

/// The provenance nodes where the engine applied its model of Nah's CLI to
/// this launch's program argument; empty when it analyzed the launch without it.
fn nah_model_applications(plan: &Plan, effect: &Effect) -> Vec<usize> {
    use effinterp_proto::ProvenanceKind::{Argument, Execution, ModelApplication};
    let node =
        |reference: &effinterp_proto::ProvenanceRef| plan.provenance.get(reference.0 as usize);
    plan.provenance
        .iter()
        .enumerate()
        .filter(|(_, application)| {
            matches!(&application.kind, ModelApplication { model }
            if model.split_once('#').map_or(model.as_str(), |(id, _)| id) == NAH_MODEL)
                && application
                    .antecedents
                    .iter()
                    .filter_map(node)
                    .any(|argument| {
                        matches!(argument.kind, Argument { index: 0 })
                    && argument.antecedents.iter().filter_map(node).any(|execution| {
                        matches!(execution.kind, Execution { node } if node == effect.execution.0)
                    })
                    })
        })
        .map(|(index, _)| index)
        .collect()
}

/// Whether the engine stated this effect through a model it applied although
/// PATH left the launched executable's identity unresolved. Self-protection
/// still reads such an effect's typed facts, but it does not establish what
/// the program touches for the other guards.
pub(crate) fn model_identity_unresolved(plan: &Plan, effect: &Effect) -> bool {
    let mut marked = Vec::with_capacity(plan.provenance.len());
    for node in &plan.provenance {
        marked.push(
            matches!(&node.kind, effinterp_proto::ProvenanceKind::ModelApplication { model }
                if model == effinterp_engine::UNRESOLVED_IDENTITY_MODEL)
                || node
                    .antecedents
                    .iter()
                    .any(|antecedent| marked.get(antecedent.0 as usize) == Some(&true)),
        );
    }
    effect
        .provenance
        .iter()
        .any(|reference| marked.get(reference.0 as usize) == Some(&true))
}

/// The change to Nah's own state or hook wiring that the engine's model of a
/// launched program states on the effects it gives that launch, as their
/// `nah_control` attribute. A nap suspends protection and is Permanent;
/// every other change is Critical.
fn stated_control(plan: &Plan, effect: &Effect) -> Option<nah_proto::labels::NahProtectionTier> {
    use nah_proto::labels::NahProtectionTier::{Critical, Permanent};
    plan.effects
        .iter()
        .filter(|candidate| candidate.execution == effect.execution && candidate.realm.is_host())
        .filter_map(|candidate| match candidate.attributes.get("nah_control") {
            Some(AttrValue::String(kind)) if kind == "nap" => Some(Permanent),
            Some(AttrValue::String(_)) => Some(Critical),
            _ => None,
        })
        .fold(None, |strongest, tier| {
            strongest_protection(strongest, Some(tier))
        })
}

/// The Nah control command a launch would run if its program is Nah. The
/// engine's model of Nah's CLI states it for a launch the engine analyzed with
/// that model. A launch it did not (a `nah` whose PATH it could not search, or
/// a program Nah may identify as its own binary under another name) takes the
/// tier of Nah's own command table over the literal prefix of its arguments,
/// so self-protection does not go silent where the engine is. Neither does
/// a launch whose arguments the model reports it could not recognize, such as
/// an unknown flag, which suppresses the model's stated changes.
pub(crate) fn nah_control(
    plan: &Plan,
    effect: &Effect,
    argv: &[ResourceExpr],
) -> Option<nah_proto::labels::NahProtectionTier> {
    let applications = nah_model_applications(plan, effect);
    let table = || nah_proto::labels::nah_prefix_protection_tier(&literal_words(argv));
    if applications.is_empty() {
        return table();
    }
    let unrecognized = plan.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .provenance
                .iter()
                .any(|node| applications.contains(&(node.0 as usize)))
    });
    let stated = stated_control(plan, effect);
    if unrecognized {
        strongest_protection(stated, table())
    } else {
        stated
    }
}

/// Selects the structural tier an executed process carries. A runtime's model
/// states a change to Nah's wiring, and Cargo's the binaries it installs or
/// removes. Nah's control commands (`nah_control`) count only for a process
/// identified as an installed nah binary. The identity is the engine's
/// resolved path, read through Nah's host observation of it when this plan
/// has not changed that path before the launch. `Unknown` means the arguments
/// would be a nah control command but the process could not be identified.
pub(crate) fn process_protection_tier(
    view: &PlanView<'_>,
    effect: &Effect,
) -> Knowledge<Option<nah_proto::labels::NahProtectionTier>> {
    let plan = view.plan();
    let Some((executable, path, argv)) = process_argv(plan, effect) else {
        return Knowledge::Known(None);
    };
    let executable =
        nah_proto::labels::package_launch_program(executable, launched_package(view, effect));
    let authority = view.authority();
    // Runtime and cargo invocations are recognized by the program they name.
    // A `nah` spelling is excluded here: Nah's control commands own it.
    let spelled_nah = nah_proto::labels::normalized_program(executable) == "nah";
    let literal = literal_argv(argv);
    if !spelled_nah
        && let Some(tier) = stated_control(plan, effect)
            .or_else(|| cargo_protection_tier(view, effect))
            .or_else(|| {
                let argv = literal.as_ref()?;
                nah_proto::runtime_protection::runtime_launch_bypass(
                    executable,
                    argv,
                    Some(authority.home().as_str()),
                    Some(authority.platform()),
                )
                .then_some(nah_proto::labels::NahProtectionTier::Critical)
            })
            .or_else(|| environment_protection_tier(view, effect, executable, literal.as_ref()?))
    {
        return Knowledge::Known(Some(tier));
    }
    // An argument the engine could not resolve (`nah guard disable "$X"`)
    // still leaves a program spelled `nah` its control command.
    let control = (literal.is_some() || spelled_nah)
        .then(|| nah_control(plan, effect, argv))
        .flatten();
    let Some(control) = control else {
        return Knowledge::Known(None);
    };
    let installed = |path: &str| {
        tier::is_installed_nah(
            path,
            authority.installed_executables(),
            authority.home(),
            authority.platform(),
        )
    };
    match path.map(|path| (path, executed_identity(view, effect, path))) {
        Some((path, _)) if installed(path) => Knowledge::Known(Some(control)),
        // A PATH search the engine certified names the realpath of the file it
        // selects, so that path is the identity.
        Some(_) if path_search_certified(plan, effect) => Knowledge::Known(None),
        Some((_, Some(identity))) if installed(identity) => Knowledge::Known(Some(control)),
        // On a Windows host a POSIX-rooted path such as `/usr/bin/nah` names
        // whatever the shell running it maps it to (Git Bash's mount table,
        // WSL, a terminal session elsewhere), not the entry at the root of the
        // cwd's drive that Nah observed, so that entry not being Nah does not
        // show the launch is not Nah. A `//` path is UNC.
        Some((path, Some(_)))
            if authority.platform() != nah_proto::ctx::Platform::Windows
                || !path.starts_with('/')
                || path.starts_with("//") =>
        {
            Knowledge::Known(None)
        }
        // Self-protection fails closed: a `nah` without an identity
        // certificate keeps the tier its spelling gave it, because treating it
        // as unrelated could let a real nah control command through, while
        // stopping an unrelated executable named `nah` costs little. That is a
        // bare `nah` whose PATH search certified nothing (PATH unknown, unset
        // or computed; nothing found; or a candidate this plan changed before
        // the launch, the host did not answer, or that is not an executable
        // file), and a path this plan rewrote before running it
        // (`cp other nah; ./nah trust`) or whose host observation failed.
        _ if spelled_nah => Knowledge::Known(Some(control)),
        _ => Knowledge::Unknown,
    }
}

/// The package operand a package launcher (`npx`, `bunx`, `bun x`, `pnpm dlx`)
/// ran this launch for: its argv[0], when the edge that created its execution
/// carries the engine's binary-inference certificate. An explicit command
/// (`npx --package=P -- CMD`) and any other launch have none, even one whose
/// path spells a package name.
fn launched_package<'a>(view: &PlanView<'a>, effect: &Effect) -> Option<&'a str> {
    let plan = view.plan();
    let edge = view.parent_edge(effect.execution)?;
    let launched = edge.kind == effinterp_proto::ExecutionEdgeKind::ToolModel
        && edge.evidence.iter().any(|reference| {
            matches!(
                plan.provenance.get(reference.0 as usize).map(|node| &node.kind),
                Some(effinterp_proto::ProvenanceKind::ModelApplication { model })
                    if model == effinterp_engine::PACKAGE_BINARY_INFERENCE_MODEL
            )
        });
    match plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)?
        .argv
        .first()?
    {
        ResourceExpr::Literal { value } if launched => Some(value),
        _ => None,
    }
}

/// Whether the engine's PATH search certified this launch's executable path.
fn path_search_certified(plan: &Plan, effect: &Effect) -> bool {
    effect.provenance.iter().any(|reference| {
        matches!(
            plan.provenance.get(reference.0 as usize).map(|node| &node.kind),
            Some(effinterp_proto::ProvenanceKind::ModelApplication { model })
                if model == effinterp_engine::PATH_SEARCH_MODEL
        )
    })
}

/// Cargo replacing or removing Nah's binary. An uninstall removes it when it
/// selects Nah's package or a binary named `nah`, and one that asks for either
/// still counts when the install root's registry does not record it, a
/// `--config` leaves that root unknown, or an option the model does not read
/// is present. A binary named `nah` counts by its stated name, whatever root
/// Cargo computes.
/// An install writes it when it selects Nah's package, Nah's source tree or a
/// binary named `nah`, and the binary directory is an ancestor of protected
/// Nah state or already holds one of Nah's standard installed binaries (such
/// as `/usr/local/bin/nah` under `--root /usr/local`), which the install
/// replaces even though that directory was never observed. Cargo's model
/// states the selection on each binary it writes or removes.
fn cargo_protection_tier(
    view: &PlanView<'_>,
    effect: &Effect,
) -> Option<nah_proto::labels::NahProtectionTier> {
    use nah_proto::labels::lexical_path::{
        installed_binary_paths, join_lexical_path, lexically_normalized, same_path,
    };
    let authority = view.authority();
    let (home, platform) = (authority.home().as_str(), authority.platform());
    let binary = if platform == nah_proto::ctx::Platform::Windows {
        "nah.exe"
    } else {
        "nah"
    };
    let installed = installed_binary_paths(home, platform);
    fn attr_text<'a>(candidate: &'a Effect, key: &str) -> Option<&'a str> {
        match candidate.attributes.get(key) {
            Some(AttrValue::String(value)) => Some(value.as_str()),
            _ => None,
        }
    }
    view.plan()
        .effects
        .iter()
        .any(|candidate| {
            if candidate.execution != effect.execution
                || !candidate.realm.is_host()
                || attr_text(candidate, "package_manager") != Some("cargo")
            {
                return false;
            }
            let path = match &candidate.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some(path.as_str()),
                _ => None,
            };
            // The binary directory, when the selection is Nah's binary.
            let selection = attr_text(candidate, "selection");
            let directory = match selection {
                Some("package_binaries" | "installed_binaries") => attr_text(candidate, "package")
                    .is_some_and(nah_proto::labels::nah_package_spec)
                    .then_some(path),
                Some("requested") => (attr_text(candidate, "package")
                    .is_some_and(nah_proto::labels::nah_package_spec)
                    || attr_text(candidate, "binary") == Some("nah"))
                .then_some(path),
                Some("manifest_binaries") => attr_text(candidate, "source_path")
                    .is_some_and(nah_proto::labels::nah_source_path)
                    .then_some(path),
                Some("named") => (attr_text(candidate, "binary") == Some("nah")).then(|| {
                    path.and_then(|path| path.rsplit_once(['/', '\\']))
                        .map(|(directory, _)| directory)
                }),
                _ => None,
            };
            let Some(directory) = directory else {
                return false;
            };
            match candidate.operation.as_str() {
                "filesystem.delete" => true,
                // An uninstall asked to remove Nah counts even when Cargo will
                // refuse it or the root it removes from is unknown.
                "filesystem.read" => selection == Some("requested"),
                "filesystem.write" => directory.is_some_and(|directory| {
                    nah_proto::labels::protected_path_ancestor(
                        directory,
                        home,
                        authority.critical_paths(),
                        platform,
                    ) || installed.iter().any(|installed| {
                        same_path(
                            installed,
                            &lexically_normalized(
                                &join_lexical_path(directory, binary, platform),
                                platform,
                            ),
                            platform,
                        )
                    })
                }),
                _ => false,
            }
        })
        .then_some(nah_proto::labels::NahProtectionTier::Critical)
}

/// Classifies the hook bypass a runtime's launch environment configures. The
/// execution node states the environment the child actually receives, and the
/// analyzed subject states the environment it inherited.
fn environment_protection_tier(
    view: &PlanView<'_>,
    effect: &Effect,
    executable: &str,
    argv: &[String],
) -> Option<nah_proto::labels::NahProtectionTier> {
    if nah_proto::labels::runtime_terminal_information(argv) {
        return None;
    }
    let plan = view.plan();
    let node = view.execution(effect.execution);
    let configured = |name: &str| match node.environment.get(name) {
        Some(Some(ResourceExpr::Literal { value })) => Some(value.as_str()),
        _ => None,
    };
    let inherited = |name: &str| {
        subject_context(&plan.subject).and_then(|context| context.env.get(name).map(String::as_str))
    };
    let cwd = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { cwd: Some(cwd), .. },
        } => match cwd.as_ref() {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        },
        _ => None,
    };
    nah_proto::runtime_protection::environment_operation(
        executable,
        configured,
        inherited,
        view.authority().home().as_str(),
        cwd,
        view.authority().critical_paths(),
        view.authority().platform(),
    )
    .map(|_| nah_proto::labels::NahProtectionTier::Critical)
}

/// The host context a subject was analyzed in; a SQL subject has none.
fn subject_context(subject: &effinterp_proto::Subject) -> Option<&effinterp_proto::HostContext> {
    use effinterp_proto::Subject;
    match subject {
        Subject::Exec { context, .. }
        | Subject::Shell { context, .. }
        | Subject::Source { context, .. }
        | Subject::ToolCall { context, .. } => Some(context),
        Subject::Sql { .. } => None,
    }
}

/// The structural tier of a program typed into another terminal and not yet
/// submitted. Only a program spelled `nah` is classified: the receiver's PATH
/// decides which file that name runs, and nothing here observes it.
pub(crate) fn terminal_input_tier(effect: &Effect) -> Option<nah_proto::labels::NahProtectionTier> {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::Process {
            executable, argv, ..
        },
    } = &effect.resource
    else {
        return None;
    };
    if nah_proto::labels::normalized_program(executable) != "nah" {
        return None;
    }
    nah_proto::labels::nah_prefix_protection_tier(&literal_words(argv))
}

/// A launched process's program, spelled path and argument expressions.
fn process_argv<'a>(
    plan: &'a Plan,
    effect: &'a Effect,
) -> Option<(&'a str, Option<&'a str>, &'a [ResourceExpr])> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::Process {
                executable,
                path,
                argv,
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let argv = if argv.is_empty() {
        plan.execution_graph
            .nodes
            .get(effect.execution.0 as usize)
            .map(|node| node.argv.as_slice())
            .unwrap_or_default()
    } else {
        argv
    };
    Some((executable, path.as_deref(), argv))
}

/// Every argument's literal text, `None` when any argument is not a literal.
pub(crate) fn literal_argv(argv: &[ResourceExpr]) -> Option<Vec<String>> {
    literal_words(argv).into_iter().collect()
}

/// Each argument's literal text, `None` for an argument that is not a literal.
pub(super) fn literal_words(argv: &[ResourceExpr]) -> Vec<Option<String>> {
    argv.iter()
        .map(|argument| match argument {
            ResourceExpr::Literal { value } => Some(value.clone()),
            _ => None,
        })
        .collect()
}
