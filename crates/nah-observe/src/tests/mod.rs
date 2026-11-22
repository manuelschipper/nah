mod descendants;
#[cfg(unix)]
mod directory_entries;
mod dispatcher;
mod env;
#[cfg(unix)]
mod git_hooks;
#[cfg(unix)]
mod git_read;
mod git_state;
mod ignored_entries;
mod installed_packages;
#[cfg(unix)]
mod listing;
mod nested_repository;
mod path_facts;
mod ref_deletion;
#[cfg(unix)]
mod repository_configuration;
mod roots;
mod support;
mod user_homes;
