// Development tool: reads and rewrites model documents on disk.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::env;
use std::path::Path;

use effinterp_model_factory::{
    FactoryError, migrate_fixture, normalize_candidate, promote_file, repin_directory,
    seed_assertions, verify_directory_with_options,
};
use effinterp_proto::content_digest;

fn run() -> Result<(), FactoryError> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, directory] if command == "repin" => repin_directory(Path::new(directory), None),
        [command, directory, option, evidence] if command == "repin" && option == "--evidence" => repin_directory(Path::new(directory), Some(Path::new(evidence))),
        [command, directory, options @ ..] if command == "verify" => {
            let mut minimum = None;
            let mut with_builtin = false;
            let mut options = options.iter();
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--with-builtin" if !with_builtin => with_builtin = true,
                    "--min-promoted" if minimum.is_none() => {
                        minimum = Some(options.next().and_then(|value| value.parse::<usize>().ok())
                            .ok_or_else(|| FactoryError::Usage("--min-promoted must be a nonnegative integer".to_string()))?);
                    }
                    _ => return Err(FactoryError::Usage(format!("unknown or repeated verify option {option:?}"))),
                }
            }
            verify_directory_with_options(Path::new(directory), minimum.unwrap_or(0), with_builtin)
        }
        [command, candidate] if command == "normalize" => {
            let source = std::fs::read_to_string(candidate).map_err(|error| FactoryError::Io {
                path: candidate.into(),
                detail: error.to_string(),
            })?;
            print!("{}", normalize_candidate(&source)?);
            Ok(())
        }
        [command, candidate] if command == "identity" => {
            let source = std::fs::read_to_string(candidate).map_err(|error| FactoryError::Io {
                path: candidate.into(),
                detail: error.to_string(),
            })?;
            let normalized = normalize_candidate(&source)?;
            let candidate: effinterp_model_schema::CandidateDocument = serde_json::from_str(&normalized)
                .map_err(|error| FactoryError::Json(error.to_string()))?;
            let mut promoted = candidate.promoted(String::new());
            promoted.identity = effinterp_model_schema::document_content_identity(&promoted);
            println!("{}", promoted.identity);
            Ok(())
        }
        [command, candidate, output] if command == "promote" => {
            promote_file(Path::new(candidate), Path::new(output))
        }
        [command, input, output] if command == "migrate-fixture" => {
            migrate_fixture(Path::new(input), Path::new(output))
        }
        [command, fixture] if command == "seed-assertions" => {
            seed_assertions(Path::new(fixture), None)
        }
        [command, fixture, option, document]
            if command == "seed-assertions" && option == "--document" =>
        {
            seed_assertions(Path::new(fixture), Some(Path::new(document)))
        }
        [command, path] if command == "digest" => {
            let bytes = std::fs::read(path).map_err(|error| FactoryError::Io {
                path: path.into(),
                detail: error.to_string(),
            })?;
            println!("{}", content_digest(&bytes));
            Ok(())
        }
        _ => Err(FactoryError::Usage(
            "usage: effinterp-model-factory <repin DIR [--evidence FILE]|verify DIR [--with-builtin] [--min-promoted N]|normalize CANDIDATE|identity CANDIDATE|promote CANDIDATE OUTPUT|migrate-fixture INPUT OUTPUT|seed-assertions FIXTURE [--document DOCUMENT]|digest FILE>".to_string(),
        )),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
