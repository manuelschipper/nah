use super::{
    CommandModel, InvocationCtx, ModelCausalBinding,
    common::{arg_node, symbolic_expr, unrecognized_arguments_boundary},
    infrastructure::{
        emit, emit_with_attributes, environment_gap, gap, parse_data, read_input, scoped_gap,
    },
};
use crate::{builder::PlanBuilder, value::unresolved_resource, word::Word};
use effinterp_proto::{
    BoundaryReason, BoundaryScope, KubernetesNamespace, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

struct KubernetesResourceApi {
    owner: Box<dyn CommandModel>,
}

// Keep exec's declarative argument and realm semantics under the same catalog owner
// as the typed Kubernetes API operations.
pub(super) fn with_resource_api(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(KubernetesResourceApi { owner })
}

impl CommandModel for KubernetesResourceApi {
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

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model: ProvenanceRef) {
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "-h")
        ) {
            return;
        }
        if self.owner.matches_subcommand(ctx.argv, "exec") {
            self.owner.apply(builder, ctx, model);
        } else {
            for domain in ["container", "network"] {
                builder.declare_coverage(
                    effinterp_proto::Domain::new(domain),
                    effinterp_proto::CoverageLevel::Full,
                );
            }
            apply(builder, ctx, model);
        }
    }
}

// Ordinary aliases share one owner; group-qualified names retain their API group.
const KINDS: &[(&[&str], &str, &str, bool)] = &[
    (&["all"], "all", "", false),
    (&["namespace", "namespaces", "ns"], "Namespace", "", true),
    (&["pod", "pods", "po"], "Pod", "", false),
    (&["job", "jobs"], "Job", "batch", false),
    (&["service", "services", "svc"], "Service", "", false),
    (&["configmap", "configmaps", "cm"], "ConfigMap", "", false),
    (&["secret", "secrets"], "Secret", "", false),
    (
        &["persistentvolume", "persistentvolumes", "pv"],
        "PersistentVolume",
        "",
        true,
    ),
    (&["node", "nodes", "no"], "Node", "", true),
    (
        &["storageclass", "storageclasses", "sc"],
        "StorageClass",
        "storage.k8s.io",
        true,
    ),
    (
        &["clusterrole", "clusterroles"],
        "ClusterRole",
        "rbac.authorization.k8s.io",
        true,
    ),
    (
        &["clusterrolebinding", "clusterrolebindings"],
        "ClusterRoleBinding",
        "rbac.authorization.k8s.io",
        true,
    ),
    (
        &[
            "customresourcedefinition",
            "customresourcedefinitions",
            "crd",
            "crds",
        ],
        "CustomResourceDefinition",
        "apiextensions.k8s.io",
        true,
    ),
    (
        &["deployment", "deployments", "deploy"],
        "Deployment",
        "apps",
        false,
    ),
    (
        &["statefulset", "statefulsets", "sts"],
        "StatefulSet",
        "apps",
        false,
    ),
    (
        &["daemonset", "daemonsets", "ds"],
        "DaemonSet",
        "apps",
        false,
    ),
];

#[derive(Default)]
struct Options {
    namespace: Option<ResourceExpr>,
    server: Option<ResourceExpr>,
    context: Option<ResourceExpr>,
    raw: Option<Word>,
    files: Vec<(usize, Word)>,
    operands: Vec<(usize, Word)>,
    dry_run: Option<String>,
    dry_run_requested: bool,
    grammar_known: bool,
    prune: bool,
    force: bool,
    uncertain: bool,
    all: bool,
    all_namespaces: bool,
    selector: Option<ResourceExpr>,
    selector_text: Option<String>,
    selector_kind: Option<&'static str>,
}

pub(super) fn apply(builder: &mut PlanBuilder, ctx: &InvocationCtx, model: ProvenanceRef) {
    let mut opts = Options {
        grammar_known: true,
        ..Options::default()
    };
    let mut copy_options_known = true;
    let mut cluster_override = false;
    let words = expand_short_clusters(ctx.argv);
    let mut position = 0;
    while position < words.len() {
        let (mut i, word) = (words[position].0, &words[position].1);
        let raw = word.render_raw();
        if !raw.starts_with('-') || raw == "-" {
            if word.as_literal().is_none()
                && (opts.operands.is_empty() || word.literal_prefix().starts_with('-'))
            {
                opts.grammar_known = false;
                opts.uncertain = true;
            }
            opts.operands.push((i, word.clone()));
            position += 1;
            continue;
        }
        let (flag, assigned) = word
            .split_assignment()
            .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
        copy_options_known &= matches!(
            flag,
            "-n" | "--namespace"
                | "--context"
                | "--server"
                | "-s"
                | "--request-timeout"
                | "--kubeconfig"
                | "--insecure-skip-tls-verify"
        );
        let value_flag = matches!(
            flag,
            "-n" | "--namespace"
                | "--context"
                | "--server"
                | "-s"
                | "--cluster"
                | "--user"
                | "--token"
                | "--as"
                | "--as-group"
                | "--as-uid"
                | "--as-user-extra"
                | "--certificate-authority"
                | "--client-certificate"
                | "--client-key"
                | "--tls-server-name"
                | "--profile"
                | "--profile-output"
                | "-v"
                | "--v"
                | "-f"
                | "--filename"
                | "-o"
                | "--output"
                | "--field-manager"
                | "--grace-period"
                | "--cascade"
                | "--to-revision"
                | "--request-timeout"
                | "--kubeconfig"
                | "-l"
                | "--selector"
                | "--field-selector"
                | "-k"
                | "--kustomize"
                | "--subresource"
                | "--timeout"
                | "--validate"
                | "--raw"
        );
        let bool_flag = matches!(
            flag,
            "--ignore-not-found"
                | "--wait"
                | "--force"
                | "--server-side"
                | "--force-conflicts"
                | "--prune"
                | "--all"
                | "--all-namespaces"
                | "-A"
                | "--show-managed-fields"
                | "--insecure-skip-tls-verify"
                | "--now"
                | "-i"
                | "--interactive"
        );
        if bool_flag
            && assigned.is_some()
            && !matches!(
                assigned.as_ref().and_then(Word::as_literal),
                Some("true" | "false")
            )
        {
            opts.grammar_known = false;
            opts.uncertain = true;
            gap(
                builder,
                &[model],
                &["container"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Kubernetes boolean option value is invalid",
            );
        }
        let value = if flag == "--dry-run" && assigned.is_none() {
            Some(Word::literal("client"))
        } else if value_flag {
            if let Some(value) = assigned.clone() {
                if value.render_raw().starts_with('-') && value.as_literal() != Some("-") {
                    opts.grammar_known = false;
                    opts.uncertain = true;
                }
                Some(value)
            } else if words.len() <= position + 1 {
                // A value option with no argument at all is rejected while the
                // command line is parsed, before a kubeconfig or API server is reached.
                return;
            } else if let Some((index, next)) = words
                .get(position + 1)
                .filter(|(_, w)| !w.render_raw().starts_with('-') || w.as_literal() == Some("-"))
            {
                position += 1;
                i = *index;
                Some(next.clone())
            } else {
                opts.uncertain = true;
                opts.grammar_known = false;
                None
            }
        } else if bool_flag || flag == "--dry-run" {
            assigned
        } else {
            unrecognized_arguments_boundary(
                builder,
                model,
                &["container", "filesystem", "network", "process"],
                &[(i as u32, raw)],
            );
            opts.uncertain = true;
            opts.grammar_known = false;
            break;
        };
        let expr = value.as_ref().map(|v| symbolic_expr(v, "value"));
        match flag {
            "-n" | "--namespace" => {
                if expr
                    .as_ref()
                    .is_none_or(|value| !matches!(value, ResourceExpr::Literal { .. }))
                {
                    opts.grammar_known = false;
                    opts.uncertain = true;
                    gap(
                        builder,
                        &[model],
                        &["container"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        "Kubernetes namespace is symbolic or unresolved",
                    );
                }
                opts.namespace = expr;
            }
            "--server" | "-s" => opts.server = expr,
            "--context" => opts.context = expr,
            // The named kubeconfig cluster replaces the context's cluster.
            "--cluster" => cluster_override = true,
            // Any profile other than `none` writes the profile output file.
            "--profile" => {
                opts.uncertain |= value.as_ref().and_then(Word::as_literal) != Some("none");
            }
            "--raw" => opts.raw = value,
            "-f" | "--filename" => {
                if let Some(value) = value {
                    opts.files.push((i, value));
                }
            }
            "--prune" => opts.prune = value.as_ref().and_then(Word::as_literal) != Some("false"),
            "--force" => opts.force = value.as_ref().and_then(Word::as_literal) != Some("false"),
            "-l" | "--selector" | "--field-selector" => {
                let text = value.as_ref().map(Word::render_raw);
                let kind = if flag == "--field-selector" {
                    "field"
                } else {
                    "label"
                };
                if opts
                    .selector_text
                    .as_ref()
                    .is_some_and(|old| text.as_ref() != Some(old))
                    || opts.selector_kind.is_some_and(|old| old != kind)
                {
                    opts.grammar_known = false;
                    opts.uncertain = true;
                }
                if value.as_ref().and_then(Word::as_literal).is_none() {
                    opts.grammar_known = false;
                    opts.uncertain = true;
                }
                opts.selector = expr;
                opts.selector_text = text;
                opts.selector_kind = Some(kind);
            }
            "--dry-run" => {
                let mode = value.as_ref().and_then(Word::as_literal);
                match mode {
                    Some("none") => {
                        opts.dry_run = None;
                        opts.dry_run_requested = false;
                    }
                    Some("client" | "server") => {
                        opts.dry_run = mode.map(str::to_string);
                        opts.dry_run_requested = true;
                    }
                    _ => {
                        opts.dry_run_requested = true;
                        opts.grammar_known = false;
                        opts.uncertain = true;
                    }
                }
            }
            "--all" => opts.all = value.as_ref().and_then(Word::as_literal) != Some("false"),
            "--all-namespaces" | "-A" => {
                opts.all_namespaces = value.as_ref().and_then(Word::as_literal) != Some("false");
            }
            "-k" | "--kustomize" | "--subresource" | "--kubeconfig" => opts.uncertain = true,
            _ => {}
        }
        position += 1;
    }
    if cluster_override {
        opts.context = None;
    }
    let arguments_unresolved = opts.uncertain;
    if opts.all_namespaces {
        // A cross-namespace request cannot retain a single namespace selector.
        opts.namespace = None;
        opts.uncertain = true;
    }
    let verb = opts.operands.first().and_then(|(_, w)| w.as_literal());
    let (operations, skip): (&[&str], usize) = match verb {
        Some("get") => (&["container.resource.read"], 1),
        Some("create") => (&["container.resource.create"], 1),
        Some("apply") => (
            &["container.resource.create", "container.resource.update"],
            1,
        ),
        Some("delete") => (&["container.resource.delete"], 1),
        Some("rollout") => match opts.operands.get(1).and_then(|(_, w)| w.as_literal()) {
            Some("restart") => (&["container.resource.restart"], 2),
            Some("pause") => (&["container.resource.pause"], 2),
            Some("resume") => (&["container.resource.unpause"], 2),
            Some("undo") => (&["container.resource.rollback"], 2),
            Some("status" | "history") => (&["container.resource.read"], 2),
            _ => (&[], 2),
        },
        _ => (&[], 1),
    };
    let mut provenance = vec![model];
    for index in 1..ctx.argv.len() {
        provenance.push(arg_node(builder, ctx, index as u32));
    }
    builder.boundary(effinterp_proto::Boundary {
        reason: effinterp_proto::BoundaryReason::CLUSTER_API,
        class: effinterp_proto::BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Environment,
        affected_resource: None, callee: None,
        domains: vec![effinterp_proto::Domain::new("container"), effinterp_proto::Domain::new("network")],
        provenance: provenance.clone(), limit: None,
        detail: Some("Kubernetes kubeconfig, live inventory, admission and controller effects are unresolved".into()),
    });
    if opts.dry_run.as_deref() != Some("client") {
        let mut scope =
            effinterp_proto::ResourceScope::new(effinterp_proto::NamespaceKind::Unsupported);
        if let Some(server) = &opts.server {
            super::scope::endpoint_evidence(
                &mut scope,
                effinterp_proto::ScopeEvidenceKind::Endpoint,
                effinterp_proto::ScopeValue::value(server.clone()),
            );
        }
        emit(
            builder,
            &provenance,
            "network.request",
            super::scope::network_resource(&scope),
        );
    }
    if verb == Some("cp") {
        copy(builder, ctx, model, opts, copy_options_known);
        return;
    }
    if opts.uncertain || operations.is_empty() {
        let (reason, scope) = if arguments_unresolved || operations.is_empty() {
            (BoundaryReason::PARTIAL_ANALYSIS, BoundaryScope::Invocation)
        } else {
            (BoundaryReason::LIVE_INVENTORY, BoundaryScope::Environment)
        };
        scoped_gap(
            builder,
            &provenance,
            &["container", "network"],
            reason,
            scope,
            "Kubernetes arguments or resource inventory are unresolved",
        );
    }
    let mut targets = Vec::new();
    if verb == Some("delete")
        && let Some(raw) = &opts.raw
    {
        if let Some((kind, group, name, namespace)) = raw.as_literal().and_then(raw_api_target) {
            targets.push(target(
                builder,
                &provenance,
                &opts,
                kind,
                group,
                ResourceExpr::Literal { value: name.into() },
                namespace,
            ));
        } else {
            gap(
                builder,
                &provenance,
                &["container"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Kubernetes raw resource endpoint is symbolic or unresolved",
            );
        }
    }
    for (_, file) in &opts.files {
        if let Some((source, source_node)) = read_input(builder, ctx, &provenance, file) {
            provenance.push(source_node);
            match parse_data(builder, &source) {
                Ok(documents) => {
                    for document in documents {
                        manifest(builder, &provenance, &opts, &document, &mut targets, 0);
                    }
                }
                Err(()) => {
                    targets.push(unresolved_resource("container"));
                    gap(
                        builder,
                        &provenance,
                        &["container"],
                        BoundaryReason::PARTIAL_ANALYSIS,
                        "Kubernetes manifest syntax, aliases, duplicate fields or nesting are unresolved",
                    );
                }
            }
        } else {
            targets.push(unresolved_resource("container"));
        }
    }
    let mut resource_type = None;
    for (_, word) in opts.operands.iter().skip(skip) {
        if word.as_literal().is_none() && word.literal_prefix().contains('/') {
            let (kind, first) = word.literal_prefix().split_once('/').unwrap();
            let mut parts = word.parts.clone();
            parts[0] = crate::word::WordPart::Literal(first.into());
            targets.push(target(
                builder,
                &provenance,
                &opts,
                kind,
                None,
                symbolic_expr(&Word::new(parts), "container"),
                None,
            ));
        } else if let Some((kind, name)) = word.as_literal().and_then(|s| s.split_once('/')) {
            targets.push(target(
                builder,
                &provenance,
                &opts,
                kind,
                None,
                ResourceExpr::Literal { value: name.into() },
                None,
            ));
        } else if resource_type.is_none() {
            resource_type = Some(word);
        } else if let Some(kinds) = resource_type.and_then(Word::as_literal) {
            // `TYPE1,TYPE2 NAME...` names each listed type for every name.
            for kind in kinds.split(',') {
                targets.push(target(
                    builder,
                    &provenance,
                    &opts,
                    kind,
                    None,
                    symbolic_expr(word, "container"),
                    None,
                ));
            }
        }
    }
    if targets.is_empty() || opts.uncertain {
        if let Some(kinds) = resource_type.and_then(Word::as_literal) {
            for kind in kinds.split(',') {
                targets.push(target(
                    builder,
                    &provenance,
                    &opts,
                    kind,
                    None,
                    unresolved_resource("container"),
                    None,
                ));
            }
        } else {
            targets.push(unresolved_resource("container"));
        }
        let (reason, scope) = if arguments_unresolved
            || operations.is_empty()
            || !opts.files.is_empty()
            || resource_type.and_then(Word::as_literal).is_none()
            || !(opts.all || opts.selector.is_some() || verb == Some("get"))
        {
            (BoundaryReason::PARTIAL_ANALYSIS, BoundaryScope::Invocation)
        } else {
            (BoundaryReason::LIVE_INVENTORY, BoundaryScope::Environment)
        };
        scoped_gap(
            builder,
            &provenance,
            &["container"],
            reason,
            scope,
            "Kubernetes target or manifest inventory is unresolved",
        );
    }
    // Aliases in one kind list (`namespace,ns`) name the same objects once.
    let mut unique = Vec::with_capacity(targets.len());
    for resource in targets {
        if !unique.contains(&resource) {
            unique.push(resource);
        }
    }
    for resource in unique {
        for operation in operations {
            if opts.dry_run.is_none() || *operation == "container.resource.read" {
                if *operation == "container.resource.delete" {
                    if opts.dry_run_requested || !opts.grammar_known {
                        continue;
                    }
                    let scope = delete_scope(&opts, verb, &resource);
                    let selection = if opts.selector.is_some() {
                        "pattern"
                    } else if opts.all {
                        "whole"
                    } else {
                        "named"
                    };
                    emit_with_attributes(
                        builder,
                        &provenance,
                        operation,
                        resource.clone(),
                        delete_attributes(scope, selection, &opts),
                    );
                } else {
                    emit(builder, &provenance, operation, resource.clone());
                }
            }
        }
    }
    if opts.dry_run.is_none() && verb == Some("apply") && (opts.prune || opts.force) {
        let scope = target(
            builder,
            &provenance,
            &opts,
            "*",
            None,
            unresolved_resource("container"),
            None,
        );
        emit(
            builder,
            &provenance,
            "container.resource.delete",
            scope.clone(),
        );
        if opts.force {
            emit(builder, &provenance, "container.resource.create", scope);
        }
        environment_gap(
            builder,
            &provenance,
            &["container"],
            BoundaryReason::LIVE_INVENTORY,
            "Kubernetes pruning or force replacement may affect unlisted resources",
        );
    }
}

/// Split pflag short-option clusters into one word per option, each keeping
/// its argv index: `-Ailapp=web` is `-A`, `-i`, `-l=app=web`, and a value
/// option takes the rest of the word (`-nplatform` is `-n=platform`). A word
/// with an unknown shorthand stays whole for the option loop to reject.
fn expand_short_clusters(argv: &[Word]) -> Vec<(usize, Word)> {
    let mut words = Vec::new();
    for (index, word) in argv.iter().enumerate().skip(1) {
        let Some(text) = word
            .as_literal()
            .filter(|text| text.len() > 2 && text.starts_with('-') && !text.starts_with("--"))
        else {
            words.push((index, word.clone()));
            continue;
        };
        let mut expanded = Vec::new();
        for (offset, short) in text.char_indices().skip(1) {
            let rest = &text[offset + short.len_utf8()..];
            match short {
                'A' | 'i' if !rest.starts_with('=') => expanded.push(format!("-{short}")),
                'A' | 'i' | 'n' | 'f' | 'o' | 'l' | 'k' | 's' | 'v' => {
                    let rest = rest.strip_prefix('=').unwrap_or(rest);
                    expanded.push(if rest.is_empty() {
                        format!("-{short}")
                    } else {
                        format!("-{short}={rest}")
                    });
                    break;
                }
                _ => {
                    expanded.clear();
                    break;
                }
            }
        }
        if expanded.is_empty() {
            words.push((index, word.clone()));
        } else {
            words.extend(
                expanded
                    .into_iter()
                    .map(|text| (index, Word::literal(text))),
            );
        }
    }
    words
}

fn raw_api_target(path: &str) -> Option<(&str, Option<&str>, &str, Option<&str>)> {
    let path = path.split('?').next()?;
    let segments = path
        .strip_prefix('/')?
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    match segments.as_slice() {
        ["api", _, "namespaces", name] => Some(("namespaces", Some(""), name, None)),
        ["api", _, "namespaces", namespace, kind, name] => {
            Some((kind, Some(""), name, Some(namespace)))
        }
        ["api", _, kind, name] => Some((kind, Some(""), name, None)),
        ["apis", group, _, "namespaces", namespace, kind, name] => {
            Some((kind, Some(group), name, Some(namespace)))
        }
        ["apis", group, _, kind, name] => Some((kind, Some(group), name, None)),
        _ => None,
    }
}

fn copy(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model: ProvenanceRef,
    opts: Options,
    options_known: bool,
) {
    let operands = &opts.operands[1..];
    let endpoints = operands
        .iter()
        .map(|(_, word)| word.as_literal())
        .collect::<Option<Vec<_>>>();
    let endpoints = endpoints.as_deref().unwrap_or_default();
    let valid = opts.grammar_known && options_known && endpoints.len() == 2;
    if !valid || endpoints.iter().filter(|value| value.contains(':')).count() != 1 {
        gap(
            builder,
            &[model],
            &["container", "filesystem", "process"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Kubernetes copy requires one literal local path and one literal [namespace/]pod:path; options or endpoints are unresolved",
        );
        return;
    }
    let remote_index = usize::from(!endpoints[0].contains(':'));
    let (pod, path) = endpoints[remote_index].split_once(':').unwrap();
    let (namespace, pod) = pod
        .split_once('/')
        .map_or((None, pod), |(namespace, pod)| (Some(namespace), pod));
    if pod.is_empty()
        || pod.contains('/')
        || path.is_empty()
        || namespace == Some("")
        || endpoints[1 - remote_index].is_empty()
    {
        gap(
            builder,
            &[model],
            &["container", "filesystem", "process"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Kubernetes copy endpoint syntax is invalid",
        );
        return;
    }
    let mut attributes = std::collections::BTreeMap::from([
        ("pod".into(), effinterp_proto::AttrValue::String(pod.into())),
        (
            "path".into(),
            effinterp_proto::AttrValue::String(path.into()),
        ),
    ]);
    if let Some(namespace) = namespace.or(match &opts.namespace {
        Some(ResourceExpr::Literal { value }) => Some(value.as_str()),
        _ => None,
    }) {
        attributes.insert(
            "namespace".into(),
            effinterp_proto::AttrValue::String(namespace.into()),
        );
    }
    let remote = super::common::arg_effect(
        builder,
        ctx,
        model,
        operands[remote_index].0 as u32,
        "container.copy",
        unresolved_resource("container"),
        attributes,
    );
    let (index, local) = &operands[1 - remote_index];
    let host = super::common::operand_effect(
        builder,
        ctx,
        model,
        *index as u32,
        local,
        if remote_index == 0 {
            "filesystem.write"
        } else {
            "filesystem.read"
        },
        Default::default(),
    );
    if let (Some(remote), Some(host)) = (remote, host) {
        let (source, destination) = if remote_index == 0 {
            (remote, host)
        } else {
            (host, remote)
        };
        builder.transfer_binding(crate::resource_transfer::TransferBinding::new(
            source,
            destination,
        ));
    }
    gap(
        builder,
        &[model],
        &["container", "filesystem", "process"],
        BoundaryReason::PARTIAL_ANALYSIS,
        "Kubernetes copy invokes tar in the selected container; container selection, archive contents and destination directory expansion are unresolved",
    );
}

fn delete_attributes(
    scope: &str,
    selection: &str,
    opts: &Options,
) -> std::collections::BTreeMap<String, effinterp_proto::AttrValue> {
    let active = opts.dry_run.is_none();
    let mut attributes: std::collections::BTreeMap<String, effinterp_proto::AttrValue> = [
        ("mode", effinterp_proto::AttrValue::String("delete".into())),
        ("scope", effinterp_proto::AttrValue::String(scope.into())),
        (
            "selection",
            effinterp_proto::AttrValue::String(selection.into()),
        ),
        (
            "provider",
            effinterp_proto::AttrValue::String("kubernetes".into()),
        ),
        ("active", effinterp_proto::AttrValue::Bool(active)),
        ("preview", effinterp_proto::AttrValue::Bool(false)),
        ("help", effinterp_proto::AttrValue::Bool(false)),
        ("dry_run", effinterp_proto::AttrValue::Bool(!active)),
        ("all", effinterp_proto::AttrValue::Bool(opts.all)),
        (
            "all_namespaces",
            effinterp_proto::AttrValue::Bool(opts.all_namespaces),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value))
    .collect();
    if let Some(selector) = &opts.selector_text {
        attributes.insert(
            "selector".into(),
            effinterp_proto::AttrValue::String(selector.clone()),
        );
    }
    if let Some(kind) = opts.selector_kind {
        attributes.insert(
            "selector_kind".into(),
            effinterp_proto::AttrValue::String(kind.into()),
        );
    }
    attributes
}

fn delete_scope(opts: &Options, verb: Option<&str>, resource: &ResourceExpr) -> &'static str {
    if verb != Some("delete") {
        return "unknown";
    }
    if let ResourceExpr::Concrete {
        identity: ResourceIdentity::KubernetesResource { kind, name, .. },
    } = resource
    {
        if kind == "Namespace" {
            return if opts.all
                || opts.selector.is_some()
                || matches!(name.as_ref(), ResourceExpr::Literal { .. })
            {
                "namespace"
            } else {
                "unknown"
            };
        }
        // A kind's scope is the one the API server publishes for it, the same
        // fact `target` reads when it decides whether the resource carries a
        // namespace at all.
        if KINDS.iter().any(|(_, canonical, _, cluster)| {
            *cluster && canonical.eq_ignore_ascii_case(kind.as_str())
        }) {
            return "cluster";
        }
        return "namespaced";
    }
    if opts.uncertain {
        "unknown"
    } else {
        "namespaced"
    }
}

fn target(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    opts: &Options,
    kind: &str,
    group: Option<&str>,
    mut name: ResourceExpr,
    namespace: Option<&str>,
) -> ResourceExpr {
    if kind.is_empty() {
        gap(
            builder,
            provenance,
            &["container"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Kubernetes resource kind is missing",
        );
        return unresolved_resource("container");
    }
    if matches!(&name, ResourceExpr::Literal { value } if value.is_empty() || value.contains('/')) {
        gap(
            builder,
            provenance,
            &["container"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Kubernetes resource name or subresource is unresolved",
        );
        name = unresolved_resource("container");
    }
    let (short, suffix) = kind
        .split_once('.')
        .map_or((kind, None), |(k, g)| (k, Some(g)));
    let entry = KINDS.iter().find(|(aliases, canonical, _, _)| {
        aliases.contains(&short.to_ascii_lowercase().as_str())
            || canonical.eq_ignore_ascii_case(short)
    });
    let (kind, inferred_group, cluster) = entry
        .map_or((short, "", false), |(_, kind, group, cluster)| {
            (*kind, *group, *cluster)
        });
    let group = group.or(suffix).unwrap_or(inferred_group);
    let namespace = if entry.is_none() || group != inferred_group {
        gap(
            builder,
            provenance,
            &["container"],
            BoundaryReason::KUBERNETES_TARGET_API,
            "Kubernetes custom API schema and namespace scope are unresolved",
        );
        KubernetesNamespace::Unknown {
            namespace: Box::new(
                namespace
                    .map(|value| ResourceExpr::Literal {
                        value: value.into(),
                    })
                    .or_else(|| opts.namespace.clone())
                    .unwrap_or_else(|| unresolved_resource("container")),
            ),
        }
    } else if cluster {
        KubernetesNamespace::Cluster
    } else {
        let manifest_namespace = namespace.map(|value| ResourceExpr::Literal {
            value: value.into(),
        });
        if let (Some(cli), Some(manifest)) = (&opts.namespace, &manifest_namespace)
            && cli != manifest
        {
            gap(
                builder,
                provenance,
                &["container"],
                BoundaryReason::PARTIAL_ANALYSIS,
                "Kubernetes CLI and manifest namespaces conflict",
            );
            return unresolved_resource("container");
        }
        KubernetesNamespace::Namespaced {
            namespace: Box::new(
                manifest_namespace
                    .or_else(|| opts.namespace.clone())
                    .unwrap_or_else(|| unresolved_resource("container")),
            ),
        }
    };
    ResourceExpr::Concrete {
        identity: ResourceIdentity::KubernetesResource {
            api_group: group.into(),
            kind: kind.into(),
            name: Box::new(name),
            namespace,
            server: Box::new(
                opts.server
                    .clone()
                    .unwrap_or_else(|| unresolved_resource("network")),
            ),
            context: Box::new(
                opts.context
                    .clone()
                    .unwrap_or_else(|| unresolved_resource("value")),
            ),
        },
    }
}

fn manifest(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    opts: &Options,
    value: &serde_json::Value,
    targets: &mut Vec<ResourceExpr>,
    depth: usize,
) {
    if depth > 32 || !builder.budget().try_charge_steps(1) {
        gap(
            builder,
            provenance,
            &["container"],
            BoundaryReason::PARTIAL_ANALYSIS,
            "Kubernetes List nesting or item budget exhausted",
        );
        return;
    }
    if value.get("kind").and_then(|v| v.as_str()) == Some("List")
        && let Some(items) = value.get("items").and_then(|v| v.as_array())
    {
        for item in items {
            manifest(builder, provenance, opts, item, targets, depth + 1);
        }
        return;
    }
    let fields = (
        value.get("apiVersion").and_then(|v| v.as_str()),
        value.get("kind").and_then(|v| v.as_str()),
        value.pointer("/metadata/name").and_then(|v| v.as_str()),
    );
    if let (Some(api), Some(kind), Some(name)) = fields
        && !name.is_empty()
        && !kind.is_empty()
        && !api.is_empty()
    {
        let group = api.split_once('/').map_or("", |(group, _)| group);
        targets.push(target(
            builder,
            provenance,
            opts,
            kind,
            Some(group),
            ResourceExpr::Literal { value: name.into() },
            value
                .pointer("/metadata/namespace")
                .and_then(|v| v.as_str()),
        ));
        return;
    }
    targets.push(unresolved_resource("container"));
    gap(
        builder,
        provenance,
        &["container"],
        BoundaryReason::PARTIAL_ANALYSIS,
        "Kubernetes manifest identity is missing, generated or malformed",
    );
}
