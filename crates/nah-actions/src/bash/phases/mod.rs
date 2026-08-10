use super::{
    AliasInvocation, AssignmentUpdate, CommandContext, InjectedOrigins, Lowered, Lowerer,
    PayloadExecution, PositionalCommand, PositionalExpansion, VisibleExecutionState, VisibleStdin,
};

mod assignments;
mod child_shell;
mod command;
mod command_builtins;
mod command_classification;
mod command_commit;
mod command_descriptors;
mod command_effects;
mod command_payload;
mod command_preparation;
mod command_resources;
mod control_flow;
mod filesystem;
mod function_state;
mod invocation_flow;
mod payload;
mod positionals;
mod tar_state;
mod variables;
mod word_resolution;
mod words;
