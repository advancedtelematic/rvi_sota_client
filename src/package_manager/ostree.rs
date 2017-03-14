use serde_json as json;
use std::fs::File;
use std::io::{BufReader, Read};

use datatype::{Error, OstreePackage, Package, UpdateResultCode};
use package_manager::{Credentials, InstallOutcome, parse_package};


const PACKAGES_FILE: &'static str = "/usr/package.manifest";

pub fn installed_packages() -> Result<Vec<Package>, Error> {
    let mut file = File::open(PACKAGES_FILE)?;
    let mut packages = String::new();
    file.read_to_string(&mut packages)?;
    packages.lines()
        .map(parse_package)
        .filter(|package| package.is_ok())
        .collect::<Result<Vec<Package>, _>>()
}

pub fn install_package(path: &str, creds: &Credentials) -> Result<InstallOutcome, InstallOutcome> {
    let file = File::open(path).map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}", err)))?;
    let pkg: OstreePackage = json::from_reader(BufReader::new(file))
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", err)))?;
    pkg.install(creds)
}
