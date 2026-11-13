//! The process CPU clock the interactive analysis budget is charged against.

use std::time::Duration;

/// CPU time this process has consumed, across all its threads. Child
/// processes such as `git` are not included: nah waits on them under their
/// own timeouts and the analysis wall ceiling.
#[cfg(all(unix, not(target_os = "redox")))]
pub(crate) fn process_cpu_time() -> Option<Duration> {
    let spent = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let seconds = u64::try_from(spent.tv_sec).ok()?;
    let nanos = u32::try_from(spent.tv_nsec).ok()?;
    (nanos < 1_000_000_000).then(|| Duration::new(seconds, nanos))
}

/// Hosts without a process CPU clock keep the wall-clock budget.
#[cfg(not(all(unix, not(target_os = "redox"))))]
pub(crate) fn process_cpu_time() -> Option<Duration> {
    None
}

#[cfg(all(test, unix, not(target_os = "redox")))]
mod tests {
    use super::process_cpu_time;

    // The clock is process-wide and the test harness runs other tests on
    // other threads, so only monotonic growth under this thread's own work
    // is asserted; that sleeping is not charged is the clock's definition.
    #[test]
    fn process_cpu_time_is_monotonic_and_charges_busy_work() {
        let before = process_cpu_time().expect("unix reports process CPU time");
        let mut acc = 0u64;
        let wall_limit = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            acc = std::hint::black_box(acc.wrapping_add(1));
            let after = process_cpu_time().expect("unix reports process CPU time");
            assert!(after >= before);
            if after > before {
                break;
            }
            assert!(
                std::time::Instant::now() < wall_limit,
                "process CPU clock did not advance during busy work"
            );
        }
    }
}
