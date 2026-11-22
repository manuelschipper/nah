use effinterp_proto::{ResourceExpr, ResourceIdentity};

use crate::models::common::symbolic_expr;
use crate::word::{Word, WordPart};

/// Classify a literal or symbolic object-store URL before local path
/// resolution.
pub(super) fn object_store_target(word: &Word) -> Option<ResourceExpr> {
    if let Some(text) = word.as_literal() {
        let (scheme, rest) = text.split_once("://")?;
        let provider = match scheme {
            "s3" => Some("aws".to_string()),
            "gs" => Some("gcp".to_string()),
            "az" => Some("azure".to_string()),
            "https" if text.contains(".blob.core.windows.net") => Some("azure".to_string()),
            _ => return None,
        };
        if scheme == "https" {
            let (host, path) = rest.split_once('/')?;
            let account = host.strip_suffix(".blob.core.windows.net")?;
            if account.is_empty() || account.contains(['.', '@', ':']) {
                return None;
            }
            let (bucket, key) = path.split_once('/').map_or((path, None), |(b, k)| {
                (b, (!k.is_empty()).then(|| k.to_string()))
            });
            if bucket.is_empty() {
                return None;
            }
            let mut scope = effinterp_proto::object_scope(Some("azure"));
            scope.identity.insert(
                effinterp_proto::ScopeDimension::StorageAccount,
                effinterp_proto::ScopeValue::value(ResourceExpr::Literal {
                    value: account.to_string(),
                }),
            );
            crate::models::scope::endpoint_evidence(
                &mut scope,
                effinterp_proto::ScopeEvidenceKind::Endpoint,
                effinterp_proto::ScopeValue::value(ResourceExpr::Literal {
                    value: text.to_string(),
                }),
            );
            return Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::ObjectStore {
                    scope: Box::new(scope),
                    provider,
                    bucket: bucket.to_string(),
                    key,
                },
            });
        }
        let (bucket, key) = match rest.split_once('/') {
            Some((b, k)) if !k.is_empty() => (b.to_string(), Some(k.to_string())),
            _ => (rest.trim_end_matches('/').to_string(), None),
        };
        if bucket.is_empty() {
            return None;
        }
        return Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore {
                scope: Box::new(effinterp_proto::object_scope(provider.as_deref())),
                provider,
                bucket,
                key,
            },
        });
    }

    let WordPart::Literal(first) = word.parts.first()? else {
        return None;
    };
    let (prefix, provider) = [("s3://", "aws"), ("gs://", "gcp"), ("az://", "azure")]
        .into_iter()
        .find(|(prefix, _)| first.starts_with(prefix))?;
    let mut url_parts = word.parts.clone();
    let WordPart::Literal(first) = &mut url_parts[0] else {
        unreachable!();
    };
    *first = first.strip_prefix(prefix).unwrap().to_string();

    let (bucket_parts, key_parts) = split_object_parts(&url_parts);
    let bucket = Word::new(nonempty_literals(bucket_parts));
    if bucket.parts.is_empty() {
        return None;
    }
    if let Some(bucket) = bucket.as_literal() {
        if bucket.is_empty() {
            return None;
        }
        let base = ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore {
                scope: Box::new(effinterp_proto::object_scope(Some(provider))),
                provider: Some(provider.to_string()),
                bucket: bucket.to_string(),
                key: None,
            },
        };
        let mut parts = vec![base.clone()];
        parts.extend(symbolic_parts(key_parts, "cloud"));
        return Some(if parts.len() == 1 {
            base
        } else {
            ResourceExpr::Join { parts }
        });
    }

    let mut parts = vec![ResourceExpr::Literal {
        value: prefix.to_string(),
    }];
    parts.extend(symbolic_parts(url_parts, "cloud"));
    Some(ResourceExpr::Join { parts })
}

fn split_object_parts(parts: &[WordPart]) -> (Vec<WordPart>, Vec<WordPart>) {
    let mut bucket = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if let WordPart::Literal(value) = part
            && let Some((before, after)) = value.split_once('/')
        {
            if !before.is_empty() {
                bucket.push(WordPart::Literal(before.to_string()));
            }
            let mut key = Vec::new();
            if !after.is_empty() {
                key.push(WordPart::Literal(after.to_string()));
            }
            key.extend_from_slice(&parts[index + 1..]);
            return (bucket, key);
        }
        bucket.push(part.clone());
    }
    (bucket, Vec::new())
}

fn nonempty_literals(parts: Vec<WordPart>) -> Vec<WordPart> {
    parts
        .into_iter()
        .filter(|part| !matches!(part, WordPart::Literal(value) if value.is_empty()))
        .collect()
}

fn symbolic_parts(parts: Vec<WordPart>, family: &str) -> Vec<ResourceExpr> {
    let word = Word::new(nonempty_literals(parts));
    if word.parts.is_empty() {
        return Vec::new();
    }
    match symbolic_expr(&word, family) {
        ResourceExpr::Join { parts } => parts,
        part => vec![part],
    }
}
