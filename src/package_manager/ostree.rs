use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;

use datatype::{Error, Ostree, OstreePackage, Package, UpdateResultCode};
use package_manager::{Credentials, InstallOutcome};


pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Ostree::get_installed()
}

pub fn install_package(path: &str, creds: Credentials) -> Result<InstallOutcome, InstallOutcome> {
    let mut file = File::open(path)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}", err)))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", err)))?;
    let pkg = json::decode::<OstreePackage>(&content)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("parsing file {:?}", err)))?;
    pkg.install(creds)
}
