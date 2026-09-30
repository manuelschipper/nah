mod walkdir;
use walkdir::Walkdir;

use gosyn::parse_dir;
use gosyn::Parser;

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn parse_source<P: AsRef<Path>>(path: P) -> anyhow::Result<Duration> {
    let clock = Instant::now();
    Parser::from_file(path)?
        .parse_file()
        .map(|_| clock.elapsed())
}

#[test]
fn pprof_parser() -> anyhow::Result<()> {
    let dir = match env::var("GOSYN_PPROF_TEST") {
        Ok(path) => path,
        _ => return Ok(()),
    };

    let mut wlk = Walkdir::new(&dir)?.with_ext([".go"], [])?;
    let guard = pprof::ProfilerGuard::new(1000).unwrap();

    let mut total = Duration::from_millis(0);
    while let Some(path) = wlk.next_file()? {
        let elapsed = parse_source(&path)?;
        println!("  {:?} {:?}ms", &path, elapsed.as_millis());
        total += elapsed;
    }

    println!("{:?} total elapsed {:?}ms", &dir, total.as_millis());

    let report = guard.report().build().unwrap();
    let file = fs::File::create("flamegraph.svg").unwrap();
    report.flamegraph(file).unwrap();

    Ok(())
}

#[test]
fn test_third_party_projects() -> anyhow::Result<()> {
    match env::var("GOSYN_THIRD_PARTY") {
        Ok(val) => val.split(";").try_for_each(|dir| -> anyhow::Result<()> {
            let mut walk = Walkdir::new(dir)?.with_ext([".go"], [".pb.go"])?;
            println!("parsing {} ...", dir);
            while let Some(path) = walk.next_file()? {
                println!(
                    "  {}: {}μs",
                    path.as_path().strip_prefix(dir).unwrap().display(),
                    parse_source(&path)?.as_micros(),
                );
            }
            Ok(())
        }),
        _ => Ok(()),
    }
}

#[test]
fn test_parse_directory() -> anyhow::Result<()> {
    let root = match env::var("GOSYN_TEST_DIR") {
        Ok(dir) => PathBuf::from(dir),
        _ => return Ok(()),
    };

    for (name, pkg) in parse_dir(root)? {
        println!("package {}:", name);
        for file in pkg.files {
            println!("  {:?}", &file.path);
        }
    }

    Ok(())
}
