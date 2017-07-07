use json;
use std::fs::File;
use std::io::{BufReader, Read};

use datatype::{Error, OstreePackage, Package};
use pacman::{Credentials, InstallOutcome, parse_packages};


const PACKAGES_FILE: &'static str = "/usr/package.manifest";

pub fn installed_packages() -> Result<Vec<Package>, Error> {
    let mut file = File::open(PACKAGES_FILE)?;
    let mut packages = String::new();
    file.read_to_string(&mut packages)?;
    parse_packages(&packages)
}

pub fn install_package(path: &str, creds: &Credentials) -> Result<InstallOutcome, Error> {
    let pkg: OstreePackage = json::from_reader(BufReader::new(File::open(path)?))?;
    pkg.install(creds)
}
