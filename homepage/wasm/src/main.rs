//! Diff harness: decide stdin commands (one per line) through the same code
//! the wasm build ships, printing one JSON result per line. Compare against
//! `nah test --json` to prove the browser demo tells the truth.

use std::io::BufRead;

fn main() {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin is readable");
        if line.trim().is_empty() {
            continue;
        }
        println!("{}", nah_home_wasm::decide_json(&line));
    }
}
