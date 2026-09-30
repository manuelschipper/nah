//! Fake analyzer child used by evaluator isolation self-tests.
//!
//! Modes: success | nonzero | signal | timeout | malformed | oversized | allocate.
// Development bench: measures, spawns children, and records runs on disk.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::io::{self, Write};

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "success" => {
            println!("{{\"status\":\"analyzed\",\"ok\":true}}");
        }
        "nonzero" => {
            eprintln!("fake analyzer exiting nonzero");
            std::process::exit(7);
        }
        "signal" => {
            std::process::abort();
        }
        "timeout" => loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        },
        "malformed" => {
            println!("this is not a json envelope");
        }
        "oversized" => {
            let chunk = vec![b'X'; 64 * 1024];
            let mut out = io::stdout().lock();
            for _ in 0..32 {
                let _ = out.write_all(&chunk);
            }
            let _ = out.flush();
        }
        "allocate" => {
            let allocation = vec![1u8; 256 * 1024 * 1024];
            std::hint::black_box(&allocation);
            // Hold touched pages long enough for the resident-memory watchdog.
            std::thread::sleep(std::time::Duration::from_secs(10));
            std::hint::black_box(allocation);
        }
        other => {
            eprintln!("unknown fake analyzer mode: {other}");
            std::process::exit(2);
        }
    }
}
