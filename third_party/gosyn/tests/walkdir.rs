use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct Walkdir {
    dirs: Vec<fs::ReadDir>,
}

impl Walkdir {
    pub fn new<P: AsRef<Path>>(root: P) -> io::Result<Walkdir> {
        let root = root.as_ref();
        let dirs = vec![root.read_dir()?];

        Ok(Walkdir { dirs })
    }

    pub fn with_ext<S: AsRef<OsStr>, const N1: usize, const N2: usize>(
        self,
        include: [S; N1],
        exclude: [S; N2],
    ) -> io::Result<Walkext<S, N1, N2>> {
        let dir = self;
        Ok(Walkext { dir, include, exclude })
    }

    pub fn next_file(&mut self) -> io::Result<Option<PathBuf>> {
        match self.dirs.pop() {
            None => Ok(None),
            Some(mut dir) => match dir.next() {
                None => self.next_file(),
                Some(entry) => {
                    self.dirs.push(dir);
                    match entry {
                        Err(err) => Err(err),
                        Ok(file) => match file.path() {
                            path if path.ends_with("testdata") => self.next_file(),
                            path if path.is_file() => Ok(Some(path)),
                            path if path.is_dir() => {
                                let dir2 = path.read_dir()?;
                                self.dirs.push(dir2);
                                self.next_file()
                            }
                            _ => self.next_file(),
                        },
                    }
                }
            },
        }
    }
}

pub struct Walkext<S: AsRef<OsStr>, const N1: usize, const N2: usize> {
    dir: Walkdir,

    include: [S; N1],
    exclude: [S; N2],
}

impl<S: AsRef<OsStr>, const N1: usize, const N2: usize> Walkext<S, N1, N2> {
    pub fn next_file(&mut self) -> io::Result<Option<PathBuf>> {
        while let Some(file) = self.dir.next_file()? {
            if !self.include.iter().any(|ext| {
                // TODO: find better way to compare path extension
                let ext = ext.as_ref().to_str().unwrap();
                let filename = file.to_str().unwrap();
                filename.ends_with(ext)
            }) {
                continue;
            }

            if self.exclude.iter().any(|ext| {
                let ext = ext.as_ref().to_str().unwrap();
                let filename = file.to_str().unwrap();
                filename.ends_with(ext)
            }) {
                continue;
            }

            return Ok(Some(file));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Walkdir;
    use std::env;
    use std::fs;
    use std::io;

    #[test]
    fn list_files() -> io::Result<()> {
        let temp = env::temp_dir();
        let dir = temp.join("walkdir_test");
        fs::create_dir_all(&dir)?;

        println!("list all files...");
        let mut walk = Walkdir::new(&dir)?;
        while let Ok(Some(path)) = walk.next_file() {
            println!("{:?}", path);
        }

        println!("list go files...");
        let mut walk = Walkdir::new(&dir)?.with_ext(["go"], [])?;
        while let Ok(Some(path)) = walk.next_file() {
            println!("{:?}", path);
        }

        Ok(())
    }
}
