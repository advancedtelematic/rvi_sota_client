pub mod deb;
pub mod ostree;
pub mod rpm;
pub mod test;
pub mod uptane;


use serde::de::{Deserialize, Deserializer, Error as SerdeError};
use serde_json as json;
use std::str::FromStr;

use datatype::{Error, Package, InstallOutcome};
use http::Client;


/// HTTP client and credentials for use by a package manager.
pub struct Credentials<'c> {
    pub client:    &'c Client,
    pub token:     Option<String>,
    pub ca_file:   Option<String>,
    pub cert_file: Option<String>,
    pub pkey_file: Option<String>,
}


/// An enumeration of all available package managers for installing new packages.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PacMan {
    Off,
    Deb,
    Rpm,
    Ostree,
    Uptane,
    Test { filename: String, succeeds: bool }
}

impl PacMan {
    /// Return a list of installed packages from a package manager.
    pub fn installed_packages(&self) -> Result<Vec<Package>, Error> {
        match *self {
            PacMan::Off => Err(Error::PacMan("no package manager".into())),
            PacMan::Deb => deb::installed_packages(),
            PacMan::Rpm => rpm::installed_packages(),
            PacMan::Ostree => ostree::installed_packages(),
            PacMan::Uptane => uptane::installed_packages(),
            PacMan::Test { ref filename, .. } => test::installed_packages(filename)
        }
    }

    /// Use a package manager to install a new package.
    pub fn install_package(&self, path: &str, creds: &Credentials) -> Result<InstallOutcome, Error> {
        match *self {
            PacMan::Off => Err(Error::PacMan("no package manager".into())),
            PacMan::Deb => deb::install_package(path),
            PacMan::Rpm => rpm::install_package(path),
            PacMan::Ostree => ostree::install_package(path, creds),
            PacMan::Uptane => uptane::install_package(path, creds),
            PacMan::Test { ref filename, succeeds } => test::install_package(filename, path, succeeds)
        }
    }

    /// Searches the result of `installed_packages` for a specific package.
    pub fn is_installed(&self, package: &Package) -> bool {
        self.installed_packages().map(|packages| packages.contains(package)).unwrap_or(false)
    }
}

impl FromStr for PacMan {
    type Err = Error;

    fn from_str(s: &str) -> Result<PacMan, Error> {
        match s.to_lowercase().as_str() {
            "off" => Ok(PacMan::Off),
            "deb" => Ok(PacMan::Deb),
            "rpm" => Ok(PacMan::Rpm),
            "ostree" => Ok(PacMan::Ostree),
            "uptane" => Ok(PacMan::Uptane),
            test if test.len() > 5 && test[..5] == *"test:" => {
                Ok(PacMan::Test { filename: test[5..].into(), succeeds: true })
            },
            _ => Err(Error::Parse(format!("unknown package manager: {}", s)))
        }
    }
}

impl Deserialize for PacMan {
    fn deserialize<D: Deserializer>(de: D) -> Result<PacMan, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("invalid package manager: {}", err)))
        } else {
            Err(SerdeError::custom("Not a package manager."))
        }
    }
}


/// Split each line by a the first space and return as list of package name and version.
pub fn parse_packages(stdout: &str) -> Result<Vec<Package>, Error> {
    stdout.lines()
        .map(|line| line.trim_left_matches('\''))
        .filter(|line| !line.is_empty())
        .map(|line| {
            let parts = line.splitn(2, ' ').collect::<Vec<_>>();
            if parts.len() == 2 {
                Ok(Package { name: parts[0].into(), version: parts[1].into() })
            } else {
                Err(Error::Parse(format!("couldn't parse package: {}", line)))
            }
        })
        .collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use datatype::Package;


    #[test]
    fn test_single_package() {
        assert_eq!(parse_packages("uuid-runtime 2.20.1-5.1ubuntu20.7").unwrap(), vec![
            Package { name: "uuid-runtime".into(), version: "2.20.1-5.1ubuntu20.7".into() }
        ]);
    }

    #[test]
    fn test_multiple_packages() {
        assert_eq!(parse_packages("\n\none 1\ntwo 2\n\n").unwrap(), vec![
            Package { name: "one".into(), version: "1".into() },
            Package { name: "two".into(), version: "2".into() },
        ]);
    }

    #[test]
    fn test_version_with_spaces() {
        assert_eq!(parse_packages("vim 2.1 foobar").unwrap(), vec![
            Package { name: "vim".to_string(), version: "2.1 foobar".to_string() }
        ]);
    }

    #[test]
    fn test_error_message() {
        let expect = "Parse error: couldn't parse package: foobar".to_string();
        assert_eq!(expect, format!("{}", parse_packages("foobar").unwrap_err()));
    }
}
