//! The fixture registry corpus cases refer to by name. The fixtures
//! themselves are `nah_cli::supplied_state`, which session replay shares.

use std::collections::BTreeMap;
use std::path::Path;

use nah_cli::supplied_state::{ContextFixture, ObservationFixture};
use serde::Deserialize;

/// The named context and observation fixtures corpus cases refer to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRegistry {
    v: u32,
    pub(crate) ctx_fixtures: BTreeMap<String, ContextFixture>,
    pub(crate) observation_fixtures: BTreeMap<String, ObservationFixture>,
}

/// Reads and validates the fixture registry at `path`.
pub fn load_fixtures(path: &Path) -> Result<FixtureRegistry, String> {
    let registry: FixtureRegistry = serde_json::from_str(
        &std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read fixture registry: {error}"))?,
    )
    .map_err(|error| format!("invalid fixture registry: {error}"))?;
    registry.validate()?;
    Ok(registry)
}

impl FixtureRegistry {
    /// The context fixture a corpus case names in `ctx_fixture`.
    pub fn ctx_fixture(&self, name: &str) -> Option<&ContextFixture> {
        self.ctx_fixtures.get(name)
    }

    fn validate(&self) -> Result<(), String> {
        if self.v != 1 {
            return Err("fixture registry version is not 1".into());
        }
        for fixture in self.ctx_fixtures.values() {
            fixture.validate()?;
        }
        for (name, fixture) in &self.observation_fixtures {
            fixture
                .validate()
                .map_err(|error| format!("observation fixture `{name}`: {error}"))?;
        }
        Ok(())
    }
}
