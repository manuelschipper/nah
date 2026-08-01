//! Thin executable entry point. Application orchestration belongs to the
//! `nah_cli` library so the binary never becomes another decision layer.

fn main() -> std::process::ExitCode {
    nah_cli::run()
}
