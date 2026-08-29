#![allow(clippy::disallowed_types)]

use std::time::{Duration, Instant};

use nah_parse::normalize;

#[test]
fn fork_bomb_evidence_is_structural_and_ignores_literals_and_comments() {
    for source in [
        ":(){ :|:& };:",
        "bomb(){ bomb|bomb& }; bomb",
        "bomb(){ bomb& bomb& }; bomb",
        "bomb(){ bomb & }; bomb",
        "while true; do work & done",
        "while :; do work & done",
        "while /bin/true; do work & done",
        "until false; do work & done",
        "until /usr/bin/false; do work & done",
        "for ((;;)); do work & done",
        "for ((i=0;;i++)); do work & done",
        "for ((; ; i++)); do work & done",
        "while [[ 1 ]]; do work & done",
        "while [ true ]; do work & done",
        "while [[ false ]]; do work & done",
        "while [ x ]; do work & done",
        "while test x; do work & done",
        "while ((1)); do work & done",
        "while ((2)); do work & done",
        "for ((i=0;1;i++)); do work & done",
        "first(){ second & }; second(){ first; }; first",
        "first(){ second; }; second(){ third & }; third(){ first; }; first",
        "first(){ second & }; second(){ first; }; first; later(){ echo done; }",
        "while true; do work & wait; work & done",
        "while true; do work & if false; then wait; fi; done",
        "while true; do work & (wait); done",
        "while true; do first & wait; second & done",
        "while true; do wait; sleep 1 & disown; done",
        "while true; do sleep 1 & disown; wait; done",
        "while true; do work & if false; then break; fi; done",
        "while true; do (work &) ; wait; done",
    ] {
        assert!(normalize(source).unwrap().fork_bomb(), "{source}");
    }
    for source in [
        "echo ':(){ :|:& };:'",
        "echo ok # :(){ :|:& };:",
        "bomb(){ bomb; }; bomb",
        "bomb(){ bomb; echo later & }; bomb",
        "for item in 1 2 3; do work & done",
        "for ((i=0;i<3;i++)); do work & done",
        "while running; do work & done",
        "while true && false; do work & done",
        "while true; do work & break; done",
        "while true; do sleep 1 & wait; done",
        "while true; do sleep 1 & wait $!; done",
        "while true; do sleep 1 & wait \"$!\"; done",
        "while true; do sleep 1 & wait -n; done",
        "while true; do wait; sleep 1 & done",
        "while true; do work & wait; work & wait; done",
        "while true; do (work & wait); done",
        "while true; do work & exit; done",
        "while [[ $running ]]; do work & done",
        "while ((running)); do work & done",
        "while ((0)); do work & done",
        "while [ '' ]; do work & done",
        "while [true]; do work & done",
        "while [[true]]; do work & done",
        "first(){ second; }; second(){ first; }; first",
        "first(){ helper & }; helper(){ echo done; }; first",
        "first(){ second & }; second(){ first; }",
        "first(){ second & }; first; second(){ first; }",
        "first(){ first & }; second(){ first; }",
        "first(){ second(){ first & }; }; first",
        "echo 'while true; do work & done'",
        "echo ok # while true; do work & done",
    ] {
        assert!(!normalize(source).unwrap().fork_bomb(), "{source}");
    }
}

#[test]
fn opaque_background_loop_conditions_reduce_coverage_instead_of_being_guessed() {
    for source in [
        "while [[ $running ]]; do work & done",
        "while opaque_condition; do work & done",
        "for ((i=0;running;i++)); do work & done",
        "first(){ second & }; first(){ second & }; second(){ first; }; first",
    ] {
        let syntax = normalize(source).unwrap();
        assert!(!syntax.complete(), "{source}");
        assert!(!syntax.fork_bomb(), "{source}");
    }
}

fn large_visible_function_graph() -> String {
    let function_count = 1500;
    let mut source = (0..function_count - 1)
        .map(|index| format!("f{index}(){{ f{}; }}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    source.push_str(&format!("\nf{}(){{ f0 & }}\nf0", function_count - 1));
    source
}

#[test]
fn a_large_visible_function_graph_is_scanned_without_recursive_graph_walks() {
    assert!(
        normalize(&large_visible_function_graph())
            .unwrap()
            .fork_bomb()
    );
}

#[test]
#[ignore = "release-mode KPI; run isolated with --release --ignored --test-threads=1"]
fn a_large_visible_function_graph_is_scanned_inside_its_documented_bound() {
    let source = large_visible_function_graph();
    let started = Instant::now();
    assert!(normalize(&source).unwrap().fork_bomb());
    let elapsed = started.elapsed();
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(1500)
    } else {
        Duration::from_millis(500)
    };
    assert!(
        elapsed <= limit,
        "1500-function call-graph scan {elapsed:?} exceeds {limit:?}"
    );
}
