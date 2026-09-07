// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-actions --test suite <module>::`.

mod support;

mod bash_ambient;
mod bash_artifact_provenance;
mod bash_binding;
mod bash_child_startup;
mod bash_core;
mod bash_descendants;
mod bash_descriptors;
mod bash_environment_disclosure;
mod bash_executable_identity;
mod bash_execution;
mod bash_filesystem;
mod bash_functions;
mod bash_git;
mod bash_git_config;
mod bash_host_power;
mod bash_infrastructure;
mod bash_kubernetes;
mod bash_local_utilities;
mod bash_lookup;
mod bash_nested_executors;
mod bash_network;
mod bash_positionals;
mod bash_project;
mod bash_protected_mutators;
mod bash_python_language;
mod bash_registry;
mod bash_remote_source_control;
mod bash_secret_store;
mod bash_secrets;
mod bash_self_protection;
mod bash_semantics;
mod bash_socat;
mod bash_source_eval;
mod bash_startup_persistence;
mod bash_storage;
mod bash_tar;
mod bash_transforms;
mod bash_unresolved_filesystem;
mod bash_values;
mod bash_variable_provenance;
mod bash_visible_content;
mod bash_wrappers;
mod native;
mod visible_ipython;
mod visible_python;
mod visible_windows;
