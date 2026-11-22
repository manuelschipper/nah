//! Declarative definitions for the secret disclosure and secret-store guards;
//! they do not detect secret-shaped content.

use crate::flow_guards;
use crate::guard_evaluation::QueryQualifier;
use crate::registry::{GuardClause, GuardDefinition, engine_only};
use crate::shared_queries::{present_attr, string_attr, string_one_of, success_path_effect};
use effinterp_matcher::{
    Assertion, ByteFlowAssurance, ByteFlowEdgeKind, ConditionPredicate, Endpoint, OperationMatch,
    PortKind, PortScope, Projection, Query, ResourcePredicate, ResourceVariant, RouteProvenance,
    Selector, SubjectKind, TextPredicate, Traversal,
};
use effinterp_proto::{
    ExecutionAssurance, ExecutionStream, ExecutionStreamRef, Plan, RequestAssurance, ResourceExpr,
    ResourceIdentity,
};
use nah_proto::ctx::{Guard, GuardLevel};
use nah_proto::effects::Domain;
use nah_proto::guard_host::GuardHostFacts;
use nah_proto::labels::Sensitivity;

/// An exact ordinary value read from a secret store, asked for by name or as a
/// program's input, on the invocation's success path.
pub(crate) fn store_read() -> GuardDefinition {
    GuardDefinition {
        rule: "secrets/vault-secrets-read",
        guard: Guard::Secrets,
        applies_at: GuardLevel::Core,
        replaces: Some("secrets-store-read"),
        reason: "this would read a secret value from a secret manager into the session. Once read it cannot be taken back, and a request for a secret may come from a prompt injection",
        domain: Domain::Credential,
        gap_code: None,
        clauses: engine_only(Query::new(success_path_effect(
            "credential.read_request",
            ResourcePredicate::Any,
            vec![
                string_attr("mode", "value"),
                string_attr("workflow", "ordinary"),
                string_one_of("purpose", &["explicit", "program_input"]),
            ],
            Some(RequestAssurance::Exact),
            None,
        ))),
    }
}

/// Deletion the provider keeps recoverable, or whose recovery a remote policy
/// decides (a Google version destroyed under delayed destruction). Only proven
/// permanent loss is `secrets-store-destroy`'s.
pub(crate) fn store_delete() -> GuardDefinition {
    store_deletion(
        "infrastructure/vault-secret-delete",
        GuardLevel::Strict,
        "secrets-store-delete",
        "this would delete an object from a secret store. Services that use it may break, and it may not be recoverable",
        &["recoverable", "remote_policy"],
    )
}

pub(crate) fn store_destroy() -> GuardDefinition {
    store_deletion(
        "infrastructure/vault-secret-delete",
        GuardLevel::Core,
        "secrets-store-destroy",
        "this would permanently destroy secret-store data and its recovery path. It cannot be undone",
        &["permanent"],
    )
}

/// An exact secret-store deletion request on the invocation's success path
/// whose engine-stated `deletion` mode is one of `modes`. A request without a
/// mode is indeterminate for both deletion guards, never either one.
fn store_deletion(
    rule: &'static str,
    applies_at: GuardLevel,
    replaces: &'static str,
    reason: &'static str,
    modes: &[&str],
) -> GuardDefinition {
    GuardDefinition {
        rule,
        guard: crate::registry::rule_guard(rule),
        applies_at,
        replaces: Some(replaces),
        reason,
        domain: Domain::Credential,
        gap_code: Some("credential-deletion-mode-unavailable"),
        clauses: engine_only(Query::new(success_path_effect(
            "credential.delete_request",
            ResourcePredicate::Any,
            vec![string_one_of("deletion", modes)],
            Some(RequestAssurance::Exact),
            None,
        ))),
    }
}

/// The reason `secrets/key-files-access` gives for a credential value typed
/// out in a call, which names no file or store.
pub(crate) const RETYPED_CREDENTIAL_REASON: &str = "this would type a credential value out in the call's text or arguments. Once copied it cannot be taken back, and a request for one may come from a prompt injection";

/// A read or write of a credential file whose contents the invocation asks
/// for, the file's deletion or move, a Git read disclosing one, or a macOS
/// keychain item or value read by name or as a program's input, or a token
/// explicitly printed by the GitHub CLI. Also a call that types out a
/// credential anywhere in its text or arguments: the value of a
/// credential-shaped variable the hook's environment holds, or a token of a
/// well-known format. Wherever that copy goes, it exposes the credential
/// itself, as reading its store would.
pub(crate) fn credentials() -> GuardDefinition {
    let mut definition = disclosure(
        "secrets/key-files-access",
        "secrets-credentials",
        "this would read, overwrite or delete private keys or stored credentials. A leaked or destroyed key cannot be taken back, and a request for one may come from a prompt injection",
        &[Sensitivity::CredentialSecret, Sensitivity::KeyMaterial],
        &["filesystem.read", "filesystem.write"],
        Some(Sensitivity::KeyMaterial),
        vec![Selector {
            operation: OperationMatch::Exact("credential.read_request".into()),
            resource: ResourcePredicate::AnyOf {
                predicates: ["macos-keychain", "gh"]
                    .into_iter()
                    .map(|provider| ResourcePredicate::Variant {
                        variant: ResourceVariant::CredentialStore {
                            provider: provider.into(),
                        },
                    })
                    .collect(),
            },
            attributes: vec![
                present_attr("mode"),
                string_one_of("mode", &["value", "metadata"]),
                present_attr("purpose"),
                string_one_of("purpose", &["explicit", "program_input"]),
            ],
            request_assurance: Some(RequestAssurance::Exact),
            condition: Some(ConditionPredicate::SuccessPath),
            modality: None,
            execution_assurance: None,
            realm: None,
        }],
    );
    // Every call: the bridge decides which of a call's text it reads. A
    // subject either is or is not one of these kinds, and naming no native
    // tool keeps an unknown tool's answer conclusive.
    let kinds = Assertion::SubjectKind {
        kinds: vec![
            SubjectKind::Exec,
            SubjectKind::ShellCommand,
            SubjectKind::Sql,
            SubjectKind::Source,
        ],
    };
    definition.clauses.push(GuardClause {
        query: Query::new(Assertion::Any {
            assertions: vec![
                kinds.clone(),
                Assertion::Not {
                    assertion: Box::new(kinds),
                },
            ],
        }),
        host: None,
        qualifiers: vec![QueryQualifier::RetypedCredential],
    });
    definition
}

/// A read of an environment credential file whose contents the invocation
/// asks for, a Git read disclosing or staging one, or a catalogued
/// credential variable, an environment holding one, or a secret-store value
/// injected into it, printed to output.
pub(crate) fn environment() -> GuardDefinition {
    let mut definition = disclosure(
        "secrets/env-files-read",
        "secrets-env",
        "this would expose a credential from an environment variable or an environment file. Once disclosed it cannot be taken back, and a request for one may come from a prompt injection",
        &[Sensitivity::EnvironmentSecret],
        &["filesystem.read"],
        None,
        vec![
            flow_guards::printed_environment(flow_guards::credential_variables()),
            flow_guards::printed_environment(flow_guards::sensitivity_label(
                Sensitivity::EnvironmentSecret,
            )),
        ],
    );
    definition.clauses.push(GuardClause {
        query: Query::new(flow_guards::printed_injected_secret()),
        host: None,
        qualifiers: Vec::new(),
    });
    // A read that may happen discloses the file whenever it does, as a
    // delete that may happen loses it: the labeled read matches on any arm
    // whose condition is complete (a branch, a loop value that may run), and
    // the host rule drops an arm no assignment of the call's conditions
    // reaches. A label carried from an earlier access stays unconditional.
    if let Assertion::Any { assertions } = &mut definition.clauses[0].query.assertion {
        for assertion in assertions {
            if let Assertion::Effect { selector, .. } | Assertion::BindEffect { selector, .. } =
                assertion
                && selector.condition == Some(ConditionPredicate::SuccessPath)
            {
                selector.condition = Some(ConditionPredicate::Complete);
            }
        }
    }
    definition.clauses[0].host = Some(crate::filesystem_guards::HostRule {
        feasible_condition: true,
        reach: None,
    });
    // A count of the file's lines or bytes answers no chosen question about
    // them, whether `wc` opens the file or `cat` hands it over.
    definition.clauses[0]
        .qualifiers
        .push(QueryQualifier::BeyondCount);
    // Only the verdict answers a chosen literal probe: a match stays a visible
    // block. Quiet and filename-only grep keep their content-read protection.
    definition.clauses[0]
        .qualifiers
        .push(QueryQualifier::BeyondNonMatchingGrep);
    // A file that does not exist, and that nothing else in the call may
    // create, has nothing to disclose: `cat .env` in a project without one.
    definition.clauses[0]
        .qualifiers
        .push(QueryQualifier::BeyondMissingFile);
    // A copy that keeps a labeled name discloses nothing: whatever reads the
    // copy is decided as a read of the secret. A private key's copy is a
    // second key, so `secrets-credentials` takes no such exemption.
    definition.clauses[0]
        .qualifiers
        .push(QueryQualifier::BeyondKeptCopy(Box::new(
            flow_guards::kept_copy(&[Sensitivity::EnvironmentSecret]),
        )));
    // A sourced file whose variables nothing reads back is loaded, not
    // disclosed. The qualifier is the one a kept copy uses: only a match
    // exempts the read.
    definition.clauses[0]
        .qualifiers
        .push(QueryQualifier::BeyondKeptCopy(Box::new(loaded_source())));
    definition
}

/// A read that only loads variable assignments, none of which is read back:
/// `source .env && npm start` loads the file into the shell
/// that starts the app and prints nothing. The engine states such a read
/// (`sourced_assignments="unexpanded"`) and restates it as `expanded` once a
/// word expands a variable the file set, or a command is launched that does
/// more than start a stored program (`node -e`, `ls`). What is left to
/// decide here is what the shell's own listings print (`declare`,
/// `readonly -p`), which depend on the read through the variables they
/// list, and what a started program whose source was read prints of its
/// environment. Only a match exempts: a plan whose routes are not all
/// established keeps the block.
fn loaded_source() -> Query {
    const SOURCED: &str = "sourced";
    let effect = |operation, attributes| Selector {
        operation,
        resource: ResourcePredicate::Any,
        attributes,
        request_assurance: None,
        condition: None,
        modality: None,
        execution_assurance: None,
        realm: None,
    };
    let flows = |source, destination| Assertion::Flow {
        source,
        destination,
        traversal: Traversal::ByteFlow {
            assurance: ByteFlowAssurance::Conservative,
            edges: vec![
                ByteFlowEdgeKind::ValueDependency,
                ByteFlowEdgeKind::ContentPreservingTransfer,
            ],
        },
        provenance: RouteProvenance::Any,
    };
    let port = |kind| Endpoint::Port {
        kind,
        scope: PortScope::AnyExecution,
    };
    // A printed listing of the whole environment names no variable, and one
    // the file set may have been exported before the shell started, so the
    // listing is taken to print it.
    let mut listing = effect(
        OperationMatch::Exact("environment.read".into()),
        vec![present_attr("output"), string_attr("output", "stdout")],
    );
    listing.resource = ResourcePredicate::Rendered {
        projection: Projection::Resource,
        text: TextPredicate::Equals("environment:*".into()),
    };
    // The engine proves that the read only loads bindings and marks a later
    // shell expansion. A capture's internal stdout transports those bindings;
    // it is not a disclosure. Child programs can read their inherited values
    // without a shell expansion, so their environment reads still need checking.
    let read_back = [
        PortKind::Stdout,
        PortKind::NetworkRequest,
        PortKind::ConsumedStdin,
    ]
    .into_iter()
    .map(|kind| {
        flows(
            Endpoint::Interaction(effect(
                OperationMatch::Exact("environment.read".into()),
                Vec::new(),
            )),
            port(kind),
        )
    })
    .chain([
        flows(Endpoint::Interaction(listing), port(PortKind::Stdout)),
        // An analysis that stopped at a limit did not walk every word, so
        // it cannot say that none expanded a variable the file set.
        Assertion::Boundary {
            reason: "limit_saturated".into(),
            class: None,
            domains: None,
            detail: None,
            provenance: None,
        },
    ])
    .collect();
    Query::new(Assertion::BindEffect {
        name: SOURCED.into(),
        related: None,
        closure: None,
        selector: effect(
            OperationMatch::Exact("filesystem.read".into()),
            vec![
                present_attr("sourced_assignments"),
                string_attr("sourced_assignments", "unexpanded"),
            ],
        ),
        assertion: Box::new(Assertion::Not {
            assertion: Box::new(Assertion::Any {
                assertions: read_back,
            }),
        }),
    })
}

/// The reason `secrets/env-files-read` gives for the file read it matched at `effect`,
/// naming what the agent can act on. A recursive read or a glob names no
/// credential file itself, so the text says what to leave out and raises no
/// injection alarm over a routine search. A read of one named file says
/// which file, and keeps the alarm: something asked for a credential.
pub(crate) fn file_reason(
    rule: &str,
    plan: &Plan,
    host: &dyn GuardHostFacts,
    effect: usize,
) -> Option<String> {
    let read = &plan.effects[effect];
    if rule != "secrets/env-files-read" || read.operation.as_str() != "filesystem.read" {
        return None;
    }
    match &read.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if !host.selects_recursively(effect) => {
            let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
            Some(format!(
                "this would read the credentials in {name}. Once disclosed they cannot be taken back, and a request for them may come from a prompt injection"
            ))
        }
        _ => Some(
            "this read includes an environment credential file (.env, .env.*, .pypirc, .pgpass or .boto), whose secrets cannot be taken back once disclosed. Leave that file out or name a narrower path"
                .into(),
        ),
    }
}

/// The reason a `secrets` rule gives when the access it matched at `effect`
/// stages a secret file into Git rather than disclosing it: `git add` or a
/// commit's staging selection, or the file a staging call names and reads.
/// It names the files and how to leave them out; the read reason's prompt
/// injection alarm does not fit an ordinary `git add -A`.
pub(crate) fn staging_reason(
    rule: &str,
    plan: &Plan,
    host: &dyn GuardHostFacts,
    effect: usize,
) -> Option<String> {
    if !matches!(rule, "secrets/env-files-read" | "secrets/key-files-access") {
        return None;
    }
    let (key, purpose) = nah_proto::observation::GIT_STAGING_PURPOSE;
    let staging = |read: &effinterp_proto::Effect| {
        read.operation.as_str() == "git.read"
            && read.attributes.contains_key("content_selection")
            && read.attributes.get(key) == Some(&effinterp_proto::AttrValue::String(purpose.into()))
    };
    let access = &plan.effects[effect];
    let selection = plan
        .effects
        .iter()
        .find(|read| read.execution == access.execution && staging(read))?;
    let paths = if staging(access) {
        host.git_selected_paths(effect)
    } else {
        match &access.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if access.operation.as_str() == "filesystem.read" => vec![path.clone()],
            _ => return None,
        }
    };
    // Each file as the command's own directory spells it, which is how
    // `.gitignore` and `git rm --cached` take it from there; one outside
    // that directory keeps its whole path.
    let directory = match selection.attributes.get("content_directory") {
        Some(effinterp_proto::AttrValue::String(directory)) => directory.as_str(),
        _ => "",
    };
    let mut names = paths
        .iter()
        .map(|path| {
            path.strip_prefix(directory)
                .and_then(|rest| rest.strip_prefix(['/', '\\']))
                .filter(|_| !directory.is_empty())
                .unwrap_or(path)
                .to_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    let (files, them) = match names.as_slice() {
        [] => ("a secret file".to_owned(), "it"),
        [name] => (name.clone(), "it"),
        [rest @ .., last] => (format!("{} and {last}", rest.join(", ")), "them"),
    };
    // A forced add stages what `.gitignore` lists, so that advice is moot.
    let advice = if selection.attributes.get("content_selection")
        == Some(&effinterp_proto::AttrValue::String("addable-all".into()))
    {
        "drop `--force` (`-f`), which stages files .gitignore lists, and stage the other files by name"
            .to_owned()
    } else {
        format!(
            "list {them} in .gitignore (and run `git rm --cached` on {them} if Git tracks {them}), or stage the other files by name"
        )
    };
    Some(format!(
        "this would stage {files} into Git, where a commit and push would publish the secret and history keeps it. Leave {them} out: {advice}"
    ))
}

/// Whether the plan effect at `effect` is a read whose bytes reach only a
/// count: `cat` reads the file into a pipe, and the pipe's reader is `wc`
/// with nothing but counting options. `cat` prints what it reads and nothing
/// else, and such a `wc` prints only numbers, so the pair discloses what
/// `wc -l FILE` does. Any other producer answers a question of its own
/// (`grep KEY .env | wc -l` counts matches of a chosen pattern), and a `wc`
/// with a file operand or another option may report its input back
/// (`--files0-from=-` names each line it could not open).
pub(crate) fn only_counted(plan: &Plan, effect: usize) -> bool {
    // `-l`, `-c`, `-m`, `-w`, `-L`, clustered or spelled out; `--`, which
    // only ends the options; and `-`, the operand that names standard input.
    let counts = |option: &&str| match option.strip_prefix("--") {
        Some(long) => ["", "lines", "bytes", "chars", "words", "max-line-length"].contains(&long),
        None => option
            .strip_prefix('-')
            .is_some_and(|flags| flags.chars().all(|flag| "lcmwL".contains(flag))),
    };
    // The words of an exactly resolved launch after its program's name,
    // when that name is `name` and every word is literal.
    fn arguments<'a>(node: &'a effinterp_proto::ExecutionNode, name: &str) -> Option<Vec<&'a str>> {
        let words = node
            .argv
            .iter()
            .map(|word| match word {
                ResourceExpr::Literal { value } => Some(value.as_str()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        (node.assurance == ExecutionAssurance::Exact
            && words.first()?.rsplit('/').next() == Some(name))
        .then(|| words[1..].to_vec())
    }
    let effect = &plan.effects[effect];
    let nodes = &plan.execution_graph.nodes;
    let Some(reader) = nodes.get(effect.execution.0 as usize) else {
        return false;
    };
    let Some(ExecutionStreamRef {
        node: counter,
        stream: ExecutionStream::Stdin,
    }) = &reader.streams.stdout
    else {
        return false;
    };
    let Some(counter) = nodes.get(counter.0 as usize) else {
        return false;
    };
    effect.operation.as_str() == "filesystem.read"
        && arguments(reader, "cat").is_some()
        && arguments(counter, "wc").is_some_and(|options| options.iter().all(counts))
}

/// A disclosure guard: a file carrying one of `labels` whose contents the
/// invocation asks for, a Git read of one, or one of the `stored` selections.
/// A file carrying `removed` also matches when it is deleted or moved away:
/// a private key nothing can reissue is lost, and a moved one no longer
/// carries its label for a later read. Every disclosure rule applies at core.
fn disclosure(
    rule: &'static str,
    replaces: &'static str,
    reason: &'static str,
    labels: &[Sensitivity],
    operations: &[&str],
    removed: Option<Sensitivity>,
    stored: Vec<Selector>,
) -> GuardDefinition {
    let mut files = operations
        .iter()
        .flat_map(|operation| flow_guards::disclosed_filesystem(operation, labels, None))
        .collect::<Vec<_>>();
    if let Some(label) = removed {
        files.extend(flow_guards::removed_filesystem(label));
    }
    let mut clauses = vec![Assertion::Any { assertions: files }];
    clauses.extend(
        labels
            .iter()
            .flat_map(|label| {
                [
                    flow_guards::git_contents(*label),
                    flow_guards::git_staged(*label),
                ]
            })
            .chain(stored)
            .map(|selector| Assertion::Effect {
                closure: None,
                selector,
            }),
    );
    GuardDefinition {
        rule,
        guard: crate::registry::rule_guard(rule),
        applies_at: GuardLevel::Core,
        replaces: Some(replaces),
        reason,
        domain: Domain::Filesystem,
        gap_code: None,
        clauses: clauses
            .into_iter()
            .enumerate()
            .map(|(index, assertion)| GuardClause {
                query: Query::new(assertion),
                host: (index == 0).then(flow_guards::eligible_filesystem),
                qualifiers: Vec::new(),
            })
            .collect(),
    }
}
