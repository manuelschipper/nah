// UNDOCUMENTED-EFFINTERP: hidden operator command for the private shadow switch.

use crate::effinterp_state::{load, set, state_path};
use crate::live_state::{home, host_platform};

pub(crate) fn configure(enabled: bool) -> Result<String, String> {
    let platform = host_platform();
    let home = home(platform)?;
    set(&state_path(&home, platform), enabled)?;
    Ok(format!(
        "effinterp shadow is {}",
        if enabled { "on" } else { "off" }
    ))
}

pub(crate) fn status() -> Result<String, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let enabled = load(&state_path(&home, platform))?;
    Ok(format!(
        "effinterp shadow is {}",
        if enabled { "on" } else { "off" }
    ))
}
