#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Pure Bash parser boundary. Tree-sitter nodes never escape this crate;
//! callers receive only the owned syntax model exported here.

mod model;
mod parser;

pub use model::{
    CaseArm, CaseTermination, ConditionalBranch, LoopControlKind, LoopKind, Redirect, Statement,
    Substitution, Syntax, UnmodeledStateExpansion, Word,
};
pub use parser::{MAX_SOURCE_BYTES, MAX_SYNTAX_DEPTH, ParseError, normalize, syntax_is_clean};
