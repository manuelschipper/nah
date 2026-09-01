//! Classifies static `kubectl delete` resource selections.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::shell_word::static_word;

pub(crate) struct Classification {
    pub(crate) complete: bool,
    pub(crate) system_states: Vec<SemanticCode>,
}

impl Classification {
    fn complete(system_states: Vec<SemanticCode>) -> Self {
        Self {
            complete: true,
            system_states,
        }
    }

    fn incomplete(system_states: Vec<SemanticCode>) -> Self {
        Self {
            complete: false,
            system_states,
        }
    }
}

pub(crate) fn classify(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Word)],
    path_overridden: bool,
    qualified_program: bool,
) -> Option<Classification> {
    if program != "kubectl" {
        return None;
    }
    if !qualified_program && (path_overridden || assignments.iter().any(|(name, _)| name == "PATH"))
    {
        return Some(Classification::incomplete(Vec::new()));
    }
    let Some(arguments) = static_arguments(arguments) else {
        return Some(Classification::incomplete(Vec::new()));
    };
    let command_index = match kubectl_subcommand(&arguments) {
        Subcommand::Delete(index) => index,
        Subcommand::Other | Subcommand::NonExecuting => {
            return Some(Classification::complete(Vec::new()));
        }
        Subcommand::Incomplete => return Some(Classification::incomplete(Vec::new())),
    };
    Some(classify_delete(&arguments[command_index + 1..]))
}

enum Subcommand {
    Delete(usize),
    Other,
    NonExecuting,
    Incomplete,
}

fn kubectl_subcommand(arguments: &[String]) -> Subcommand {
    let mut options = DeleteOptions::default();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            return Subcommand::Incomplete;
        }
        if argument.starts_with('-') {
            let Some(consumed) = consume_option(arguments, index, false, &mut options) else {
                return Subcommand::Incomplete;
            };
            let Ok(consumed) = consumed else {
                return Subcommand::Incomplete;
            };
            index += consumed;
            continue;
        }
        if options.help || options.version {
            return Subcommand::NonExecuting;
        }
        return match argument.as_str() {
            "delete" => Subcommand::Delete(index),
            "help" | "options" | "version" => Subcommand::NonExecuting,
            _ => Subcommand::Other,
        };
    }
    if options.help || options.version {
        Subcommand::NonExecuting
    } else {
        Subcommand::Other
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum DryRun {
    #[default]
    None,
    ClientOrServer,
}

#[derive(Default)]
struct DeleteOptions {
    help: bool,
    version: bool,
    all: bool,
    all_namespaces: bool,
    selector: bool,
    external_selection: bool,
    recursive: bool,
    dry_run: DryRun,
}

fn classify_delete(arguments: &[String]) -> Classification {
    let mut parsed = DeleteOptions::default();
    let mut operands = Vec::new();
    let mut index = 0;
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument.starts_with('-') {
            let Some(consumed) = consume_option(arguments, index, true, &mut parsed) else {
                return Classification::incomplete(Vec::new());
            };
            let Ok(consumed) = consumed else {
                return Classification::incomplete(Vec::new());
            };
            index += consumed;
            continue;
        }
        operands.push(argument.as_str());
        index += 1;
    }
    if parsed.help || parsed.version {
        return Classification::complete(Vec::new());
    }
    if parsed.external_selection || parsed.recursive {
        return Classification::incomplete(Vec::new());
    }
    let Some(selection) = resource_selection(&operands, &parsed) else {
        return Classification::incomplete(Vec::new());
    };
    let mut system_states = Vec::new();
    let mut complete = true;
    for resource in selection.resources {
        match resource_scope(resource) {
            Some(ResourceScope::Namespace) => {
                system_states.push(SemanticCode::INFRA_K8S_NAMESPACE_DELETE);
            }
            Some(ResourceScope::Cluster) => {
                system_states.push(SemanticCode::INFRA_K8S_CLUSTER_RESOURCE_DELETE);
            }
            Some(ResourceScope::Namespaced) if selection.bulk => {
                system_states.push(SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE);
            }
            Some(ResourceScope::Namespaced) => {}
            None => complete = false,
        }
    }
    system_states.sort_unstable();
    system_states.dedup();
    if parsed.dry_run == DryRun::ClientOrServer {
        system_states.clear();
    }
    if complete {
        Classification::complete(system_states)
    } else {
        Classification::incomplete(system_states)
    }
}

struct ResourceSelection<'a> {
    resources: Vec<&'a str>,
    bulk: bool,
}

fn resource_selection<'a>(
    operands: &[&'a str],
    options: &DeleteOptions,
) -> Option<ResourceSelection<'a>> {
    if operands.iter().any(|operand| operand.is_empty()) {
        return None;
    }
    let first = *operands.first()?;
    let bulk = options.all || options.selector || options.all_namespaces;
    if first.contains('/') {
        if bulk {
            return None;
        }
        let mut resources = Vec::with_capacity(operands.len());
        for operand in operands {
            let mut parts = operand.split('/');
            let resource = parts.next()?;
            let name = parts.next()?;
            if resource.is_empty() || name.is_empty() || parts.next().is_some() {
                return None;
            }
            resources.push(resource);
        }
        return Some(ResourceSelection { resources, bulk });
    }
    let resources = first.split(',').collect::<Vec<_>>();
    let names = operands.len() > 1;
    if resources.iter().any(|resource| resource.is_empty())
        || operands.iter().skip(1).any(|name| name.contains('/'))
        || names && bulk
        || !names && !options.all && !options.selector
        || options.all && options.selector
    {
        return None;
    }
    Some(ResourceSelection { resources, bulk })
}

#[derive(Clone, Copy)]
enum ResourceScope {
    Namespace,
    Cluster,
    Namespaced,
}

fn resource_scope(resource: &str) -> Option<ResourceScope> {
    match resource {
        "namespace" | "namespaces" | "ns" => Some(ResourceScope::Namespace),
        "node"
        | "nodes"
        | "no"
        | "persistentvolume"
        | "persistentvolumes"
        | "pv"
        | "customresourcedefinition"
        | "customresourcedefinitions"
        | "crd"
        | "crds"
        | "clusterrole"
        | "clusterroles"
        | "clusterrolebinding"
        | "clusterrolebindings" => Some(ResourceScope::Cluster),
        "all"
        | "pod"
        | "pods"
        | "po"
        | "deployment"
        | "deployments"
        | "deploy"
        | "statefulset"
        | "statefulsets"
        | "sts"
        | "daemonset"
        | "daemonsets"
        | "ds"
        | "replicaset"
        | "replicasets"
        | "rs"
        | "job"
        | "jobs"
        | "cronjob"
        | "cronjobs"
        | "cj"
        | "service"
        | "services"
        | "svc"
        | "configmap"
        | "configmaps"
        | "cm"
        | "secret"
        | "secrets"
        | "persistentvolumeclaim"
        | "persistentvolumeclaims"
        | "pvc"
        | "ingress"
        | "ingresses"
        | "ing"
        | "role"
        | "roles"
        | "rolebinding"
        | "rolebindings"
        | "serviceaccount"
        | "serviceaccounts"
        | "sa" => Some(ResourceScope::Namespaced),
        _ => None,
    }
}

fn consume_option(
    arguments: &[String],
    index: usize,
    delete: bool,
    parsed: &mut DeleteOptions,
) -> Option<Result<usize, ()>> {
    let argument = &arguments[index];
    if let Some(value) = boolean_option(argument, "--help") {
        return Some(value.map(|value| {
            parsed.help = value;
            1
        }));
    }
    if argument == "--version" || argument.starts_with("--version=") {
        parsed.version = true;
        return Some(Ok(1));
    }
    if delete {
        if argument == "--dry-run" {
            return Some(Err(()));
        }
        if let Some(value) = argument.strip_prefix("--dry-run=") {
            return Some(match value {
                "none" => {
                    parsed.dry_run = DryRun::None;
                    Ok(1)
                }
                "client" | "server" => {
                    parsed.dry_run = DryRun::ClientOrServer;
                    Ok(1)
                }
                _ => Err(()),
            });
        }
        if argument == "--cascade" {
            return Some(Ok(1));
        }
        if let Some(value) = argument.strip_prefix("--cascade=") {
            return Some(
                matches!(value, "background" | "foreground" | "orphan")
                    .then_some(1)
                    .ok_or(()),
            );
        }
        if let Some(value) = boolean_option(argument, "--all") {
            return Some(value.map(|value| {
                parsed.all = value;
                1
            }));
        }
        if let Some(value) = boolean_option(argument, "--all-namespaces") {
            return Some(value.map(|value| {
                parsed.all_namespaces = value;
                1
            }));
        }
        for name in [
            "--force",
            "--ignore-not-found",
            "--interactive",
            "--now",
            "--wait",
        ] {
            if let Some(value) = boolean_option(argument, name) {
                return Some(value.map(|_| 1));
            }
        }
        if let Some(value) = boolean_option(argument, "--recursive") {
            return Some(value.map(|value| {
                parsed.recursive = value;
                1
            }));
        }
        if let Some(consumed) = value_option(arguments, index, &["--field-selector", "--selector"])
        {
            return Some(consumed.inspect(|_| {
                parsed.selector = true;
            }));
        }
        if let Some(consumed) =
            value_option(arguments, index, &["--filename", "--kustomize", "--raw"])
        {
            return Some(consumed.inspect(|_| {
                parsed.external_selection = true;
            }));
        }
        if let Some(consumed) = value_option(
            arguments,
            index,
            &["--grace-period", "--output", "--timeout"],
        ) {
            return Some(consumed);
        }
    }
    if let Some(consumed) = value_option(
        arguments,
        index,
        &[
            "--as",
            "--as-group",
            "--as-uid",
            "--as-user-extra",
            "--cache-dir",
            "--certificate-authority",
            "--client-certificate",
            "--client-key",
            "--cluster",
            "--context",
            "--kubeconfig",
            "--kuberc",
            "--log-flush-frequency",
            "--namespace",
            "--password",
            "--profile",
            "--profile-output",
            "--proxy-url",
            "--request-timeout",
            "--server",
            "--tls-server-name",
            "--token",
            "--user",
            "--username",
            "--v",
            "--vmodule",
        ],
    ) {
        return Some(consumed);
    }
    for name in [
        "--disable-compression",
        "--insecure-skip-tls-verify",
        "--match-server-version",
        "--warnings-as-errors",
    ] {
        if let Some(value) = boolean_option(argument, name) {
            return Some(value.map(|_| 1));
        }
    }
    short_options(arguments, index, delete, parsed)
}

fn short_options(
    arguments: &[String],
    index: usize,
    delete: bool,
    parsed: &mut DeleteOptions,
) -> Option<Result<usize, ()>> {
    let cluster = arguments[index].strip_prefix('-')?;
    if cluster.is_empty() || cluster.starts_with('-') {
        return None;
    }
    let mut options = cluster.char_indices().peekable();
    while let Some((_, option)) = options.next() {
        let value_start = options.peek().map_or(cluster.len(), |(index, _)| *index);
        let remainder = &cluster[value_start..];
        if option == 'h' || delete && matches!(option, 'A' | 'i' | 'R') {
            let value = if let Some(value) = remainder.strip_prefix('=') {
                options = "".char_indices().peekable();
                let Some(value) = parse_bool(value) else {
                    return Some(Err(()));
                };
                value
            } else {
                true
            };
            match option {
                'h' => parsed.help = value,
                'A' => parsed.all_namespaces = value,
                'R' => parsed.recursive = value,
                'i' => {}
                _ => unreachable!("reviewed boolean short options are exhaustive"),
            }
            continue;
        }
        if matches!(option, 'n' | 's' | 'v') || delete && matches!(option, 'f' | 'k' | 'l' | 'o') {
            let attached = remainder.strip_prefix('=').unwrap_or(remainder);
            let (consumed, value) = if attached.is_empty() {
                let Some(value) = arguments.get(index + 1).map(String::as_str) else {
                    return Some(Err(()));
                };
                (2, value)
            } else {
                (1, attached)
            };
            if value.is_empty() {
                return Some(Err(()));
            }
            match option {
                'f' | 'k' => parsed.external_selection = true,
                'l' => parsed.selector = true,
                _ => {}
            }
            return Some(Ok(consumed));
        }
        return Some(Err(()));
    }
    Some(Ok(1))
}

fn boolean_option(argument: &str, name: &str) -> Option<Result<bool, ()>> {
    if argument == name {
        return Some(Ok(true));
    }
    argument
        .strip_prefix(name)
        .and_then(|tail| tail.strip_prefix('='))
        .map(|value| parse_bool(value).ok_or(()))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn value_option(arguments: &[String], index: usize, names: &[&str]) -> Option<Result<usize, ()>> {
    let argument = &arguments[index];
    let name = names.iter().find(|name| {
        argument == **name
            || argument
                .strip_prefix(**name)
                .is_some_and(|tail| tail.starts_with('='))
    })?;
    if argument == *name {
        return Some(
            arguments
                .get(index + 1)
                .filter(|value| !value.is_empty())
                .map(|_| 2)
                .ok_or(()),
        );
    }
    Some(
        argument
            .strip_prefix(*name)
            .and_then(|tail| tail.strip_prefix('='))
            .filter(|value| !value.is_empty())
            .map(|_| 1)
            .ok_or(()),
    )
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect()
}
