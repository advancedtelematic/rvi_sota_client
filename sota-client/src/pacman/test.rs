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
            let _ = File::create(&name).expect("create tpm");
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
        fs::create_dir_all(&dir).expect("create tempdir");
        TestDir(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove tempdir");
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
pub fn install_package(path: &str, package: &str, succeeds: bool) -> Result<InstallOutcome, Error> {
    if succeeds {
        let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
        writeln!(&mut file, "{}", package)?;
        Ok(InstallOutcome::new(InstallCode::OK, "".into(), "".into()))
    } else {
        Ok(InstallOutcome::new(InstallCode::INSTALL_FAILED, "".into(), "".into()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use datatype::Package;


    fn apa() -> Package {
        Package { name: "apa".into(), version: "0.0.0".into() }
    }

    fn bepa() -> Package {
        Package { name: "bepa".into(), version: "1.0.0".into() }
    }

    #[test]
    fn get_installed_packages() {
        let dir  = TestDir::new("sota-tpm-test-1");
        let path = format!("{}/tpm", dir.0);
        let mut file = File::create(path.clone()).unwrap();
        writeln!(&mut file, "apa 0.0.0").unwrap();
        writeln!(&mut file, "bepa 1.0.0").unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![apa(), bepa()]);
    }

    #[test]
    fn ignore_bad_installed_packages() {
        let dir  = TestDir::new("sota-tpm-test-2");
        let path = format!("{}/tpm", dir.0);
        let mut file = File::create(path.clone()).unwrap();
        writeln!(&mut file, "cepa-2.0.0").unwrap();
        assert_eq!(installed_packages(&path).unwrap(), Vec::new());
    }

    #[test]
    fn install_packages() {
        let dir  = TestDir::new("sota-tpm-test-3");
        let path = format!("{}/tpm", dir.0);
        install_package(&path, "apa 0.0.0", true).unwrap();
        install_package(&path, "bepa 1.0.0", true).unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![apa(), bepa()]);
    }

    #[test]
    fn failed_installation() {
        let dir  = TestDir::new("sota-tpm-test-4");
        let path = format!("{}/tpm", dir.0);
        install_package(&path, "apa 0.0.0", false).unwrap();
        install_package(&path, "bepa 1.0.0", true).unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![bepa()]);
    }
}
