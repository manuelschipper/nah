//! Nah's CLI, run by the corpus hook rows as `nah hook <runtime> run`.

fn main() -> std::process::ExitCode {
    nah_cli::run()
}
