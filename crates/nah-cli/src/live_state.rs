//! Live HOME-derived context, extension catalog, and memo-cache construction.

use nah_proto::ctx::{AbsolutePath, Ctx, Platform, TrustProjection};

use crate::catalog::{configured_guard_states, shipped_defaults, shipped_names};
use crate::nap::{self, ActiveNap};
use crate::shipped_state::{ShippedState, state_path};
use crate::state_protection::ensure_nah_state_directory;

pub(crate) struct LiveState {
    pub(crate) ctx: Ctx,
    pub(crate) extensions: nah_extensions::ActiveExtensionCatalog,
    pub(crate) cache: nah_extensions::MemoCache,
    pub(crate) nap: Option<ActiveNap>,
    pub(crate) extension_state_unavailable: bool,
    pub(crate) warnings: Vec<String>,
    #[cfg(feature = "effinterp")]
    pub(crate) effinterp_enabled: bool,
}

/// Damaged state must never be treated better than absent state: every loader
/// that cannot be read degrades to the safe default a fresh install uses, and
/// says so, so that the guards still run.
pub(crate) fn load() -> Result<LiveState, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let mut warnings = Vec::new();
    let trust_path = nah_extensions::trust_database_path(&home, platform);
    let trust = match nah_extensions::TrustDatabase::load(&trust_path, platform)
        .and_then(|database| database.projection())
    {
        Ok(trust) => trust,
        Err(error) => {
            warnings.push(format!("{error}; no project root is trusted"));
            TrustProjection::new(vec![]).expect("the empty trust projection is valid")
        }
    };
    let activation_path = nah_extensions::activation_database_path(&home, platform);
    let (activations, activation_state_unavailable) =
        match nah_extensions::ActivationDatabase::load(&activation_path) {
            Ok(activations) => (activations, false),
            Err(error) => {
                warnings.push(format!("{error}; extension guard state unavailable"));
                (nah_extensions::ActivationDatabase::empty(), true)
            }
        };
    let reserved_names = shipped_names();
    let extensions = match nah_extensions::load_active_extensions(
        &home,
        platform,
        &trust,
        &activations,
        &reserved_names,
    ) {
        Ok(extensions) => extensions,
        Err(error) => {
            warnings.push(format!("{error}; extension catalog unavailable"));
            nah_extensions::ActiveExtensionCatalog::empty()
        }
    };
    let activated_bundle_unavailable = extensions.extensions().len() != activations.records().len();
    if activated_bundle_unavailable {
        warnings.push("one or more activated extension guards could not be loaded".into());
    }
    let extension_state_unavailable = activation_state_unavailable || activated_bundle_unavailable;
    let shipped_state = match ShippedState::load(&state_path(&home, platform), &shipped_defaults())
    {
        Ok(shipped_state) => shipped_state,
        Err(error) => {
            warnings.push(format!("{error}; shipped defaults apply"));
            ShippedState::defaults()
        }
    };
    let ctx = Ctx::new(
        platform,
        home.clone(),
        configured_guard_states(&shipped_state),
        extensions.activations(),
        trust,
    )
    .map_err(|error| error.to_string())?;
    let cache = nah_extensions::MemoCache::new(nah_extensions::memo_cache_path(&home, platform));
    let nap = match nap::load(&home, platform) {
        Ok(nap) => nap,
        Err(error) => {
            warnings.push(format!("{error}; self-protection remains awake"));
            None
        }
    };
    #[cfg(feature = "effinterp")]
    let effinterp_enabled =
        match crate::effinterp_state::enabled(&crate::effinterp_state::state_path(&home, platform))
        {
            Ok(enabled) => enabled,
            Err(error) => {
                warnings.push(format!("{error}; effinterp shadow remains off"));
                false
            }
        };
    Ok(LiveState {
        ctx,
        extensions,
        cache,
        nap,
        extension_state_unavailable,
        warnings,
        #[cfg(feature = "effinterp")]
        effinterp_enabled,
    })
}

pub(crate) fn home(platform: Platform) -> Result<AbsolutePath, String> {
    let home = configured_home(platform, |name| std::env::var_os(name))?;
    let home =
        std::fs::canonicalize(home).map_err(|_| "home directory cannot be resolved".to_owned())?;
    let home = home
        .to_str()
        .ok_or_else(|| "home directory is not UTF-8".to_owned())?;
    let home = if platform == Platform::Windows {
        nah_observe::normalize_windows_observed_path(home)
    } else {
        home.to_owned()
    };
    let home = AbsolutePath::new(platform, home).map_err(|error| error.to_string())?;
    if platform == Platform::Windows {
        ensure_nah_state_directory(&home, platform)
            .map_err(|_| "nah-state-protection-failed".to_owned())?;
    }
    Ok(home)
}

fn configured_home<F>(platform: Platform, mut get: F) -> Result<std::ffi::OsString, String>
where
    F: FnMut(&str) -> Option<std::ffi::OsString>,
{
    if platform == Platform::Windows {
        get("USERPROFILE").or_else(|| get("HOME"))
    } else {
        get("HOME")
    }
    .ok_or_else(|| "home directory is unavailable".to_owned())
}

pub(crate) const fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_home_prefers_userprofile_and_falls_back_to_home() {
        let selected = configured_home(Platform::Windows, |name| match name {
            "USERPROFILE" => Some(r"C:\Users\test".into()),
            "HOME" => Some(r"C:\fallback".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(selected, std::ffi::OsString::from(r"C:\Users\test"));

        let fallback = configured_home(Platform::Windows, |name| {
            (name == "HOME").then(|| r"C:\fallback".into())
        })
        .unwrap();
        assert_eq!(fallback, std::ffi::OsString::from(r"C:\fallback"));
    }
}
