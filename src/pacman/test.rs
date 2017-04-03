use chan::Receiver;
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::BufReader;
use std::io::prelude::*;
use time;

use datatype::{Error, Package, InstallCode};
use pacman::{InstallOutcome, PacMan};


impl PacMan {
    /// Creates a new Test Package Manager that writes to a temporary file.
    pub fn new_tpm(succeeds: bool) -> Self {
        let name = format!("/tmp/sota-tpm-{}", time::precise_time_ns().to_string());
        if succeeds {
            let _ = File::create(name.clone()).expect("create tpm");
        }
        PacMan::Test { filename: name, succeeds: succeeds }
    }
}


/// Encapsulate a directory whose contents will be destroyed when it drops out of scope.
pub struct TestDir(pub String);

impl TestDir {
    /// Create a new test directory that will be destroyed when it drops out of scope.
    pub fn new(reason: &str) -> TestDir {
        let dir = format!("/tmp/{}-{}", reason, time::precise_time_ns().to_string());
        fs::create_dir_all(dir.clone()).expect("create tempdir");
        TestDir(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0.clone()).expect("remove tempdir");
    }
}


/// For each item in the list, assert that it equals the next `Receiver` value.
pub fn assert_rx<X: PartialEq + Debug>(rx: &Receiver<X>, xs: &[X]) {
    let n = xs.len();
    let mut xs = xs.iter();
    for _ in 0..n {
        let val = rx.recv().expect("assert_rx expected another val");
        assert_eq!(val, *xs.next().expect(&format!("assert_rx: no match for val: {:?}", val)));
    }
}


/// Returns a list of installed packages from a format of `<name> <version>`.
pub fn installed_packages(path: &str) -> Result<Vec<Package>, Error> {
    let reader = BufReader::new(File::open(path)?);
    Ok(reader.lines().filter_map(|line| {
        let line = line.expect("bad line");
        let mut parts = line.split(' ');
        if let (Some(name), Some(version), None) = (parts.next(), parts.next(), parts.next()) {
            Some(Package { name: name.into(), version: version.into() })
        } else {
            None
        }
    }).collect::<Vec<Package>>())
}

/// Installs a package to the specified path when succeeds is true, or fails otherwise.
pub fn install_package(path: &str, pkg: &str, succeeds: bool) -> Result<InstallOutcome, Error> {
    if succeeds {
        let mut file = OpenOptions::new().create(true).write(true).append(true).open(path).unwrap();
        file.write_all(format!("{}\n", pkg).as_bytes())?;
        Ok(InstallOutcome::new(InstallCode::OK, "".into(), "".into()))
    } else {
        Ok(InstallOutcome::new(InstallCode::INSTALL_FAILED, "".into(), "".into()))
    }
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::prelude::*;

    use super::*;
    use datatype::Package;


    fn pkg1() -> Package {
        Package {
            name:    "apa".to_string(),
            version: "0.0.0".to_string()
        }
    }

    fn pkg2() -> Package {
        Package {
            name:    "bepa".to_string(),
            version: "1.0.0".to_string()
        }
    }


    #[test]
    fn get_installed_packages() {
        let dir   = TestDir::new("sota-tpm-test-1");
        let path  = format!("{}/tpm", dir.0);
        let mut f = File::create(path.clone()).unwrap();
        f.write(b"apa 0.0.0\n").unwrap();
        f.write(b"bepa 1.0.0").unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![pkg1(), pkg2()]);
    }

    #[test]
    fn ignore_bad_installed_packages() {
        let dir   = TestDir::new("sota-tpm-test-2");
        let path  = format!("{}/tpm", dir.0);
        let mut f = File::create(path.clone()).unwrap();
        f.write(b"cepa-2.0.0\n").unwrap();
        assert_eq!(installed_packages(&path).unwrap(), Vec::new());
    }

    #[test]
    fn install_packages() {
        let dir  = TestDir::new("sota-tpm-test-3");
        let path = format!("{}/tpm", dir.0);
        install_package(&path, "apa 0.0.0", true).unwrap();
        install_package(&path, "bepa 1.0.0", true).unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![pkg1(), pkg2()]);
    }

    #[test]
    fn failed_installation() {
        let dir  = TestDir::new("sota-tpm-test-4");
        let path = format!("{}/tpm", dir.0);
        install_package(&path, "apa 0.0.0", false).unwrap();
        install_package(&path, "bepa 1.0.0", true).unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![pkg2()]);
    }
}
