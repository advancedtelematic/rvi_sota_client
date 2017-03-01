use chan::Receiver;
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::prelude::*;
use time;

use datatype::{Error, Package, UpdateResultCode};
use package_manager::package_manager::{InstallOutcome, PackageManager};


impl PackageManager {
    /// Creates a new Test Package Manager that writes to a temporary file.
    pub fn new_tpm(succeeds: bool) -> Self {
        let name = format!("/tmp/sota-tpm-{}", time::precise_time_ns().to_string());
        if succeeds {
            let _ = File::create(name.clone()).expect("couldn't create Test Package Manager file");
        }
        PackageManager::Test { filename: name, succeeds: succeeds }
    }
}


/// Encapsulate a directory whose contents will be destroyed when it drops out of scope.
pub struct TestDir(pub String);

impl TestDir {
    /// Create a new test directory that will be destroyed when it drops out of scope.
    pub fn new(reason: &str) -> TestDir {
        let dir = format!("/tmp/{}-{}", reason, time::precise_time_ns().to_string());
        fs::create_dir_all(dir.clone()).expect("couldn't create TempDir");
        TestDir(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0.clone()).expect("couldn't remove TempDir");
    }
}


/// For each item in the list, assert that it equals the next `Receiver` value.
pub fn assert_rx<X: PartialEq + Debug>(rx: Receiver<X>, xs: &[X]) {
    let n      = xs.len();
    let mut xs = xs.iter();
    for _ in 0..n {
        let val = rx.recv().expect("assert_rx expected another val");
        let x   = xs.next().expect(&format!("assert_rx: no match for val: {:?}", val));
        assert_eq!(val, *x);
    }
}


/// Returns a list of installed packages from a format of `<name> <version>`.
pub fn installed_packages(path: &str) -> Result<Vec<Package>, Error> {
    let f        = try!(File::open(path));
    let reader   = BufReader::new(f);
    let mut pkgs = Vec::new();

    for line in reader.lines() {
        let line  = try!(line);
        let parts = line.split(' ');

        if parts.clone().count() == 2 {
            if let Some(name) = parts.clone().nth(0) {
                if let Some(version) = parts.clone().nth(1) {
                    pkgs.push(Package {
                        name:    name.to_string(),
                        version: version.to_string()
                    });
                }
            }
        }
    }

    Ok(pkgs)
}

/// Installs a package to the specified path when succeeds is true, or fails otherwise.
pub fn install_package(path: &str, pkg: &str, succeeds: bool) -> Result<InstallOutcome, InstallOutcome> {
    if !succeeds {
        return Err((UpdateResultCode::INSTALL_FAILED, "failed".to_string()))
    }

    let outcome = || -> Result<(), Error> {
        let mut f = OpenOptions::new().create(true).write(true).append(true).open(path).unwrap();
        try!(f.write(pkg.as_bytes()));
        try!(f.write(b"\n"));
        Ok(())
    }();

    match outcome {
        Ok(_)    => Ok((UpdateResultCode::OK, "".to_string())),
        Err(err) => Err((UpdateResultCode::INSTALL_FAILED, format!("{:?}", err)))
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
        assert!(install_package(&path, "apa 0.0.0", false).is_err());
        install_package(&path, "bepa 1.0.0", true).unwrap();
        assert_eq!(installed_packages(&path).unwrap(), vec![pkg2()]);
    }
}
