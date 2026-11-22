use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{Attrs, boundary};
use crate::value::unresolved_resource;

/// Emit datastore effects as conservative host effects.
pub(super) fn datastore_effect(
    builder: &mut PlanBuilder,
    provenance: Vec<ProvenanceRef>,
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) {
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
        provenance,
    });
}

/// Copy literal key-value pairs into string-valued effect attributes.
pub(super) fn datastore_text_attrs(pairs: &[(&str, &str)]) -> Attrs {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), AttrValue::String(value.to_string())))
        .collect()
}

/// A database-level resource; with neither server nor database known it
/// names nothing, so it stays unresolved.
pub(super) fn datastore_database_resource(
    server: Option<String>,
    database: Option<String>,
) -> ResourceExpr {
    if server.is_none() && database.is_none() {
        return unresolved_resource("db");
    }
    ResourceExpr::Concrete {
        identity: ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema: None,
        },
    }
}

/// A named table resource, even when its enclosing database scope is incomplete.
pub(super) fn datastore_table_resource(
    server: Option<String>,
    database: Option<String>,
    schema: Option<String>,
    table: String,
) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::DatabaseTable {
            server,
            database,
            schema,
            table,
        },
    }
}

/// Emit a connection with a supplied scheme and a port only when the host operand names one.
pub(super) fn datastore_connect_effect(
    builder: &mut PlanBuilder,
    provenance: Vec<ProvenanceRef>,
    host: &str,
    scheme: &str,
) {
    let (host, port) = datastore_host_port(host);
    datastore_effect(
        builder,
        provenance,
        "network.connect",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme.to_string()),
                port,
                path: None,
            },
        },
        Attrs::new(),
    );
}

/// Split an explicit numeric port from a single-colon host operand.
pub(super) fn datastore_host_port(text: &str) -> (String, Option<u16>) {
    match text.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => match port.parse() {
            Ok(port) => (host.to_string(), Some(port)),
            Err(_) => (text.to_string(), None),
        },
        _ => (text.to_string(), None),
    }
}

/// An unmodeled datastore subcommand leaves process coverage partial and
/// every other domain uncovered.
pub(super) fn unmodeled_datastore_subcommand(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    detail: &str,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    for domain in KNOWN_DOMAINS {
        if domain != "process" {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
        }
    }
    let domains = KNOWN_DOMAINS
        .iter()
        .copied()
        .chain(["dataflow"])
        .collect::<Vec<_>>();
    boundary(
        builder,
        model_node,
        BoundaryReason::UNMODELED_SUBCOMMAND,
        BoundaryClass::Unmodeled,
        &domains,
        detail,
    );
}

/// Coverage for a recognized cloud-database command: the call reaches the
/// service over an endpoint the invocation does not name.
pub(super) fn cloud_database_coverage(builder: &mut PlanBuilder, provenance: Vec<ProvenanceRef>) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    datastore_effect(
        builder,
        provenance,
        "network.connect",
        unresolved_resource("network"),
        Attrs::new(),
    );
}
