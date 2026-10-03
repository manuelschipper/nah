//! Forge API route matching for destructive repository requests.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use effinterp_model_schema::{
    ApiRouteSegmentKind, ApiRouteShapeDeclaration, AttributeDeclaration, Declaration,
    DeclarationDocument, EffectSourceDeclaration, ValueDeclaration,
};
use effinterp_proto::AttrValue;

use super::PROMOTED_MODEL_SOURCES;
use super::literals::{percent_decode, safe_route_component};
use super::validate::command_behaviors;

fn valid_api_url_suffix(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(0x21..=0x7e).contains(&byte) || byte == b'\\' {
            return false;
        }
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn api_route_components(route: &str) -> Option<Vec<String>> {
    let route = route.strip_prefix('/').unwrap_or(route);
    if route.starts_with('/') {
        return None;
    }
    let (route, fragment) = route
        .split_once('#')
        .map_or((route, None), |(path, suffix)| (path, Some(suffix)));
    if fragment.is_some_and(|fragment| !valid_api_url_suffix(fragment)) {
        return None;
    }
    let (path, query) = route
        .split_once('?')
        .map_or((route, None), |(path, suffix)| (path, Some(suffix)));
    if query.is_some_and(|query| !valid_api_url_suffix(query)) {
        return None;
    }

    // glab expands these documented multi-segment placeholders and path-escapes
    // the resulting repository name into one project-id segment before dispatch.
    let path = path
        .replace(":group/:namespace/:repo", ":group%2F:namespace%2F:repo")
        .replace(":namespace/:repo", ":namespace%2F:repo");
    path.split('/').map(percent_decode).collect()
}

#[derive(Clone, PartialEq, Eq)]
struct ForgeRepositoryDeleteRoute {
    provider: String,
    shapes: Vec<ApiRouteShapeDeclaration>,
    attributes: BTreeMap<String, AttrValue>,
}

pub(super) fn api_route_matches(route: &str, shapes: &[ApiRouteShapeDeclaration]) -> bool {
    let Some(components) = api_route_components(route) else {
        return false;
    };
    shapes.iter().any(|shape| {
        if components.len() != shape.segments.len() + 1 || components[0] != shape.prefix {
            return false;
        }
        shape
            .segments
            .iter()
            .zip(components.iter().skip(1))
            .all(|(shape, component)| {
                if shape
                    .literal
                    .as_deref()
                    .is_some_and(|literal| literal != component.as_str())
                {
                    return false;
                }
                match shape.kind {
                    ApiRouteSegmentKind::Nonempty => safe_route_component(component),
                    ApiRouteSegmentKind::DecimalId => {
                        !component.is_empty()
                            && component.bytes().all(|byte| byte.is_ascii_digit())
                            && component.bytes().any(|byte| byte != b'0')
                    }
                    ApiRouteSegmentKind::HexId => {
                        !component.is_empty()
                            && component.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }
                    ApiRouteSegmentKind::ProjectPath => {
                        component.split('/').all(safe_route_component)
                    }
                }
            })
    })
}

fn forge_repository_delete_routes() -> Vec<ForgeRepositoryDeleteRoute> {
    let mut routes = Vec::new();
    for source in PROMOTED_MODEL_SOURCES
        .iter()
        .filter(|source| source.contains("\"api_route\""))
    {
        let document: DeclarationDocument =
            serde_json::from_str(source).expect("bundled promoted model must deserialize");
        for command in document
            .entries
            .into_iter()
            .filter_map(|entry| match entry {
                Declaration::Command(command) => Some(command),
                _ => None,
            })
        {
            for behavior in command_behaviors(&command) {
                for rule in &behavior.effects {
                    let Some(condition) =
                        rule.when.api_route.as_ref().filter(|route| route.matches)
                    else {
                        continue;
                    };
                    let EffectSourceDeclaration::Positional { name: target } = &condition.source
                    else {
                        continue;
                    };
                    for emission in rule.emit.iter().filter(|emission| {
                        emission.operation == "network.delete_request"
                            && emission.request_assurance
                                == effinterp_proto::RequestAssurance::Exact
                            && emission.modality == effinterp_proto::Modality::MustOnSuccess
                    }) {
                        let mut attributes = BTreeMap::new();
                        let accepted = emission.attributes.iter().all(|(name, declaration)| {
                            let value = match declaration {
                                AttributeDeclaration::ConstantBool { value } => {
                                    AttrValue::Bool(*value)
                                }
                                AttributeDeclaration::ConstantInt { value } => {
                                    AttrValue::Int(*value)
                                }
                                AttributeDeclaration::ConstantString { value } => {
                                    AttrValue::String(value.clone())
                                }
                                AttributeDeclaration::Value {
                                    value: ValueDeclaration::Positional { name },
                                } if name == target => AttrValue::String(String::new()),
                                _ => return false,
                            };
                            attributes.insert(name.clone(), value);
                            true
                        });
                        let provider = match attributes.get("hosted_provider") {
                            Some(AttrValue::String(provider)) if accepted => provider.clone(),
                            _ => continue,
                        };
                        if attributes.get("hosted_target_kind")
                            != Some(&AttrValue::String("repository".into()))
                            || attributes.get("hosted_object_kind")
                                != Some(&AttrValue::String("repository".into()))
                        {
                            continue;
                        }
                        let route = ForgeRepositoryDeleteRoute {
                            provider,
                            shapes: condition.shapes.clone(),
                            attributes,
                        };
                        if !routes.contains(&route) {
                            routes.push(route);
                        }
                    }
                }
            }
        }
    }
    routes
}

pub(crate) fn forge_repository_delete_attributes(
    host: &str,
    path: &str,
) -> Option<BTreeMap<String, AttrValue>> {
    static ROUTES: LazyLock<Vec<ForgeRepositoryDeleteRoute>> =
        LazyLock::new(forge_repository_delete_routes);
    ROUTES.iter().find_map(|candidate| {
        let route = match candidate.provider.as_str() {
            "github" if host.eq_ignore_ascii_case("api.github.com") => path.strip_prefix('/')?,
            "gitlab" if host.eq_ignore_ascii_case("gitlab.com") => path.strip_prefix("/api/v4/")?,
            _ => return None,
        };
        api_route_matches(route, &candidate.shapes).then(|| {
            let mut attributes = candidate.attributes.clone();
            attributes.insert("hosted_target".into(), AttrValue::String(route.to_string()));
            attributes
        })
    })
}
