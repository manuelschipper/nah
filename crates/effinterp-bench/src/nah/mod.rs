//! The nah corpus in corpus/: loading, effect goldens, the shipped guard
//! queries evaluated against them, parity classification,
//! silent-drop mutants, and the parity report folded into the scoreboard.

pub mod classify;
pub mod corpus;
pub mod flow;
pub mod goldens;
pub mod guard_queries;
pub mod mutate;
pub mod normalize;
pub mod report;
