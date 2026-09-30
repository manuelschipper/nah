//! Computes the custom-guard memo key: which request, activation, producer,
//! evidence, and observation a cached response may answer for.

use crate::bundle::ExtensionBundle;
use nah_proto::ctx::{AbsolutePath, ActivationProjection, Ctx};
use nah_proto::effects::GuardEvidence;
use nah_proto::exec_v2::ExecV2Request;
use nah_proto::observation::Observation;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The producer, model, limits, and input identity a memo key covers alongside the
/// guard activation and its request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MemoContext {
    producer: String,
    model: Option<String>,
    limits: BTreeMap<String, u64>,
    input_fingerprint: String,
    source_identity: String,
}

impl MemoContext {
    pub fn new(
        producer: impl Into<String>,
        model: Option<String>,
        limits: BTreeMap<String, u64>,
        input_fingerprint: impl Into<String>,
        source_identity: impl Into<String>,
    ) -> Self {
        Self {
            producer: producer.into(),
            model,
            limits,
            input_fingerprint: input_fingerprint.into(),
            source_identity: source_identity.into(),
        }
    }
}

/// Memo key: lowercase hex SHA-256 over the length-prefixed JSON of each input,
/// in a fixed order; any change to an input's bytes selects a different entry.
pub(crate) fn memo_key(
    request: &ExecV2Request,
    ctx: &Ctx,
    extension: &ExtensionBundle,
    memo_context: &MemoContext,
    evidence: &GuardEvidence,
    observation: &Observation,
) -> String {
    #[derive(Serialize)]
    struct RelevantCtx<'a> {
        activation: &'a ActivationProjection,
        #[serde(skip_serializing_if = "Option::is_none")]
        trusted_root: Option<&'a AbsolutePath>,
    }

    let trusted_root = extension
        .projection()
        .identity()
        .trusted_root()
        .and_then(|identity| {
            ctx.trust()
                .trusted_roots()
                .iter()
                .find(|root| root.identity() == identity)
                .map(|root| root.path())
        });
    let relevant_ctx = RelevantCtx {
        activation: extension.projection(),
        trusted_root,
    };
    let mut hash = Sha256::new();
    hash.update(b"nah-exec-v2-memo-key\0");
    for bytes in [
        serde_json::to_vec(request).expect("validated exec request serializes"),
        serde_json::to_vec(&relevant_ctx).expect("validated extension context serializes"),
        serde_json::to_vec(memo_context).expect("validated memo context serializes"),
        serde_json::to_vec(&(evidence.graph(), evidence.public_selection()))
            .expect("validated evidence serializes"),
        serde_json::to_vec(observation).expect("validated observation serializes"),
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    format!("{:x}", hash.finalize())
}
