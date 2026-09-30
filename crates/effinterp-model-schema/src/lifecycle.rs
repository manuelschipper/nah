use serde::{Deserialize, Serialize};
/// What a lifecycle signature does with a user callable: registers it, attaches
/// it to an object, derives a dispatcher from it, or dispatches to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigRole {
    Registers,
    Attaches,
    DerivesDispatcher,
    Dispatches,
}
/// The evidence a lifecycle signature requires before it applies: a typed
/// receiver, a matching name and import, or an exact import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigEvidence {
    TypedReceiver,
    NameAndImport,
    ExactImport,
}
