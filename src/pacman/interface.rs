use serde::de::{Deserialize, Deserializer, Error as SerdeError};
use serde_json as json;
use std::str::FromStr;

use datatype::{Error, Package, UpdateResultCode};
use pacman::{deb, ostree, rpm, test};


/// The outcome when installing a package as a tuple of the `UpdateResultCode`
/// and any stdout/stderr output.
pub type InstallOutcome = (UpdateResultCode, String);

/// Optional credentials for forwarding the to package manager.
#[derive(Default)]
pub struct Credentials {
    pub access_token: Option<String>,
    pub ca_file:      Option<String>,
    pub cert_file:    Option<String>,
    pub pkey_file:    Option<String>,
}


/// An enumeration of the available package managers for querying and installing
/// new packages.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PackageManager {
    Off,
    Deb,
    Rpm,
    Ostree,
    Uptane,
    Test { filename: String, succeeds: bool }
}

impl PackageManager {
    /// Delegates to the package manager specific function for returning a list
    /// of installed packages.
    pub fn installed_packages(&self) -> Result<Vec<Package>, Error> {
        match *self {
            PackageManager::Off => Err(Error::Pacman("no package manager".into())),
            PackageManager::Deb => deb::installed_packages(),
            PackageManager::Rpm => rpm::installed_packages(),

            PackageManager::Uptane |
            PackageManager::Ostree => ostree::installed_packages(),

            PackageManager::Test { ref filename, .. } => test::installed_packages(filename)
        }
    }

    /// Delegates to the package manager specific function for installing a new
    /// package on the device.
    pub fn install_package(&self, path: &str, creds: &Credentials) -> Result<InstallOutcome, InstallOutcome> {
        match *self {
            PackageManager::Off => unreachable!("no package manager"),
            PackageManager::Deb => deb::install_package(path),
            PackageManager::Rpm => rpm::install_package(path),

            PackageManager::Uptane |
            PackageManager::Ostree => ostree::install_package(path, creds),

            PackageManager::Test { ref filename, succeeds } => {
                test::install_package(filename, path, succeeds)
            }
        }
    }

    /// Indicates whether a specific package is installed on the device.
    pub fn is_installed(&self, package: &Package) -> bool {
        self.installed_packages().map(|packages| packages.contains(package))
            .unwrap_or_else(|err| { error!("couldn't get a list of packages: {}", err); false })
    }

    /// Returns a string representation of the package manager's extension.
    pub fn extension(&self) -> String {
        match *self {
            PackageManager::Off => unreachable!("no package manager"),
            PackageManager::Deb => "deb".to_string(),
            PackageManager::Rpm => "rpm".to_string(),
            PackageManager::Ostree => "ostree".to_string(),
            PackageManager::Uptane => "uptane".to_string(),
            PackageManager::Test { ref filename, .. } => filename.to_string()
        }
    }
}

impl FromStr for PackageManager {
    type Err = Error;

    fn from_str(s: &str) -> Result<PackageManager, Error> {
        match s.to_lowercase().as_str() {
            "off" => Ok(PackageManager::Off),
            "deb" => Ok(PackageManager::Deb),
            "rpm" => Ok(PackageManager::Rpm),
            "uptane" => Ok(PackageManager::Uptane),

            // old treehub-manager alias and current ostree one.
            "thm" | "ostree" => Ok(PackageManager::Ostree),

            test if test.len() > 5 && test[..5].as_bytes() == b"test:" => {
                Ok(PackageManager::Test { filename: test[5..].to_string(), succeeds: true })
            },

            _ => Err(Error::Parse(format!("unknown package manager: {}", s)))
        }
    }
}

impl Deserialize for PackageManager {
    fn deserialize<D: Deserializer>(de: D) -> Result<PackageManager, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("invalid PackageManager: {}", err)))
        } else {
            Err(SerdeError::custom("Not a PackageManager"))
        }
    }
}

pub fn parse_package(line: &str) -> Result<Package, Error> {
    match line.splitn(2, ' ').collect::<Vec<_>>() {
        ref parts if parts.len() == 2 => {
            // HACK: strip left single quotes from stdout
            Ok(Package {
                name:    String::from(parts[0].trim_left_matches('\'')),
                version: String::from(parts[1])
            })
        },
        _ => Err(Error::Parse(format!("couldn't parse package: {}", line)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use datatype::Package;


    #[test]
    fn test_parses_normal_package() {
        let pkg = Package { name: "uuid-runtime".to_string(), version: "2.20.1-5.1ubuntu20.7".to_string() };
        assert_eq!(pkg, parse_package("uuid-runtime 2.20.1-5.1ubuntu20.7").unwrap())
    }

    #[test]
    fn test_separates_name_and_version_correctly() {
        let pkg = Package { name: "vim".to_string(), version: "2.1 foobar".to_string() };
        assert_eq!(pkg, parse_package("vim 2.1 foobar").unwrap());
    }

    #[test]
    fn test_rejects_bogus_input() {
        let expect = "Parse error: couldn't parse package: foobar".to_string();
        assert_eq!(expect, format!("{}", parse_package("foobar").unwrap_err()));
    }
}
