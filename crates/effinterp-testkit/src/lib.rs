//! Fixtures shared by the crates' test suites: repository checkouts, generated
//! repository trees, and the selected-code cases under `bench/selected-code/`. Test
//! support only — nothing here ships.
// Test support: reads fixture repositories and checkouts from disk.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

pub mod checkout;
pub mod repo_fixture;
pub mod selected_code;
