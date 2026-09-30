use std::{io, process::Command};

#[cfg(target_os = "linux")]
use std::fs;

use serde::{Deserialize, Serialize};

/// Hardware and toolchain behind a measurement. It is published in the
/// scoreboard, so it records nothing that identifies the host or its owner.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Machine {
    cpu_model: String,
    vcpus: usize,
    ram_bytes: u64,
    kernel: String,
    rustc: String,
    profile: String,
    os: String,
    filesystem: String,
}

fn command(program: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} failed: {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn kib_field(input: &str, key: &str) -> io::Result<u64> {
    input
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value * 1024)
        .ok_or_else(|| io::Error::other(format!("missing Linux memory field: {key}")))
}

/// VmHWM excludes memory inherited from the parent before exec.
#[cfg(target_os = "linux")]
pub fn peak_rss_bytes() -> io::Result<u64> {
    kib_field(&fs::read_to_string("/proc/self/status")?, "VmHWM:")
}

/// Darwin reports the process-lifetime RSS high-water mark in bytes.
#[cfg(target_os = "macos")]
pub fn peak_rss_bytes() -> io::Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { usage.assume_init() }.ru_maxrss as u64)
}

#[cfg(target_os = "macos")]
pub fn identity() -> io::Result<Machine> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(c"/".as_ptr(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let filesystem = unsafe { filesystem.assume_init() };
    Ok(Machine {
        cpu_model: command("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])?,
        vcpus: std::thread::available_parallelism()?.get(),
        ram_bytes: command("/usr/sbin/sysctl", &["-n", "hw.memsize"])?
            .parse()
            .map_err(io::Error::other)?,
        kernel: command("/usr/bin/uname", &["-r"])?,
        rustc: env!("EFFINTERP_BUILD_RUSTC").to_string(),
        profile: env!("EFFINTERP_BUILD_PROFILE").to_string(),
        os: command("/usr/bin/sw_vers", &[])?,
        filesystem: unsafe { std::ffi::CStr::from_ptr(filesystem.f_fstypename.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    })
}

#[cfg(target_os = "linux")]
pub fn identity() -> io::Result<Machine> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let cpu_model = cpuinfo
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "model name").then(|| value.trim().to_string())
        })
        .ok_or_else(|| io::Error::other("missing CPU model"))?;
    Ok(Machine {
        cpu_model,
        vcpus: std::thread::available_parallelism()?.get(),
        ram_bytes: kib_field(&fs::read_to_string("/proc/meminfo")?, "MemTotal:")?,
        kernel: command("uname", &["-r"])?,
        rustc: env!("EFFINTERP_BUILD_RUSTC").to_string(),
        profile: env!("EFFINTERP_BUILD_PROFILE").to_string(),
        os: fs::read_to_string("/etc/os-release")?,
        filesystem: command("stat", &["-f", "-c", "%T", "/"])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_identity_and_peak_rss_are_measurable() {
        let machine = identity().unwrap();
        assert!(!machine.cpu_model.is_empty());
        assert!(!machine.os.is_empty());
        assert!(!machine.filesystem.is_empty());
        assert!(machine.vcpus > 0);
        assert!(machine.ram_bytes > 0);
        // Touch pages so a KiB/byte conversion error cannot look like a
        // successful memory measurement on either host.
        let pages = vec![1u8; 16 * 1024 * 1024];
        std::hint::black_box(&pages);
        assert!(peak_rss_bytes().unwrap() >= pages.len() as u64);
    }
}
