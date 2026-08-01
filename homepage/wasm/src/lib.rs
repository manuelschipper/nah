//! The homepage "Try it yourself" engine: the real decision pipeline compiled
//! to wasm32, deciding against a fixed synthetic machine instead of a live one.
//!
//! The synthetic machine is deliberately boring — an empty project directory,
//! no git repo, no dotfiles, shipped defaults with every guard on — so the
//! page demos exactly what a fresh install would say. Observations answer the
//! way the corpus fixtures do: paths are missing, env is unset except HOME.

use nah_cli::{all_shipped_guard_states_enabled, decide_with, POLICY_VERSION};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    DescendantObservation, EnvObservation, Observation, ObservationFact, ObservationQuery,
    ObservationRequest, ObservationValue, Observed, PathKind, PathObservation,
    ProjectGuardDeclaration, ProjectGuardObservation,
};
use nah_proto::tool::ToolCallInput;

const HOME: &str = "/home/you";
const CWD: &str = "/home/you/project";

/// Decide one Bash command and render the fields the page consumes.
pub fn decide_json(command: &str) -> String {
    match decide_core(command) {
        Ok(value) => value,
        Err(error) => serde_json::json!({ "error": error }).to_string(),
    }
}

fn decide_core(command: &str) -> Result<String, String> {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({ "command": command }),
        CWD,
        None,
    )
    .map_err(|error| format!("invalid command: {error}"))?;
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        AbsolutePath::new(Platform::Linux, HOME).map_err(|error| error.to_string())?,
        all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).map_err(|error| error.to_string())?,
        POLICY_VERSION,
    )
    .map_err(|error| error.to_string())?;
    let result = decide_with(&input, &ctx, observe);
    let value = serde_json::json!({
        "verdict": result.core().verdict(),
        "reason": result.core().reason(),
        "guards": result
            .core()
            .policy_attributions()
            .iter()
            .map(nah_proto::decision::GuardAttribution::name)
            .collect::<Vec<_>>(),
        "effects": result
            .action_stream()
            .effects()
            .iter()
            .map(|effect| serde_json::json!({
                "id": effect.id().as_str(),
                "kind": effect.kind(),
            }))
            .collect::<Vec<_>>(),
        "failures": result
            .failures()
            .iter()
            .map(|failure| format!(
                "{}/{}/{}",
                failure.source(),
                failure.component(),
                failure.code()
            ))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

/// Answer an observation request for the synthetic machine.
fn observe(request: &ObservationRequest) -> Result<Observation, String> {
    let absolute =
        |path: &str| AbsolutePath::new(Platform::Linux, path).map_err(|error| error.to_string());
    let mut facts = Vec::new();
    for query in request.queries().iter().cloned() {
        let value = match &query {
            ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                observed: Observed::Ok {
                    value: absolute(CWD)?,
                },
            },
            ObservationQuery::Roots { .. } => ObservationValue::Roots {
                observed: Observed::Ok { value: vec![] },
            },
            ObservationQuery::Env { name, .. } => ObservationValue::Env {
                observed: Observed::Ok {
                    value: if name == "HOME" {
                        EnvObservation::Value { text: HOME.into() }
                    } else {
                        EnvObservation::Unset
                    },
                },
            },
            ObservationQuery::Path {
                requested,
                inspect_descendants,
                ..
            } => {
                let mut value =
                    PathObservation::new(absolute(&resolve(requested))?, None, PathKind::Missing);
                if *inspect_descendants {
                    value = value.with_descendants(
                        DescendantObservation::new(vec![], true)
                            .map_err(|error| error.to_string())?,
                    );
                }
                ObservationValue::Path {
                    observed: Observed::Ok { value },
                }
            }
            ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                observation: ProjectGuardObservation::new(None, ProjectGuardDeclaration::Absent)
                    .map_err(|error| error.to_string())?,
            },
        };
        facts.push(ObservationFact::new(query, value).map_err(|error| error.to_string())?);
    }
    Observation::new(SchemaVersion::V1, request.request_id(), facts)
        .map_err(|error| error.to_string())
}

/// Resolve a requested path against the synthetic HOME and CWD, collapsing
/// `.` and `..` lexically — there is no filesystem to consult.
fn resolve(requested: &str) -> String {
    let joined = if requested.starts_with('/') {
        requested.to_owned()
    } else if requested == "~" {
        HOME.to_owned()
    } else if let Some(rest) = requested.strip_prefix("~/") {
        format!("{HOME}/{rest}")
    } else {
        format!("{CWD}/{requested}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

// ---- wasm ABI: one in-flight result buffer, single-threaded by nature ----

#[cfg(target_arch = "wasm32")]
mod wasm_abi {
    use std::cell::RefCell;

    thread_local! {
        static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    /// Allocate `len` bytes the host can write a command into.
    #[unsafe(no_mangle)]
    pub extern "C" fn nah_alloc(len: usize) -> *mut u8 {
        let mut buffer = Vec::with_capacity(len);
        let pointer = buffer.as_mut_ptr();
        std::mem::forget(buffer);
        pointer
    }

    /// Decide the UTF-8 command at `pointer..pointer+len`; returns the length
    /// of the JSON result, readable at `nah_result_ptr` until the next call.
    ///
    /// # Safety
    /// `pointer` must come from `nah_alloc(len)` with the command written.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn nah_decide(pointer: *mut u8, len: usize) -> usize {
        let bytes = unsafe { Vec::from_raw_parts(pointer, len, len) };
        let command = String::from_utf8_lossy(&bytes);
        let json = super::decide_json(&command);
        RESULT.with(|result| {
            *result.borrow_mut() = json.into_bytes();
            result.borrow().len()
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nah_result_ptr() -> *const u8 {
        RESULT.with(|result| result.borrow().as_ptr())
    }
}
