use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;

use datatype::{AccessToken, Error, Ostree, OstreePackage, Package, UpdateResultCode};
use package_manager::package_manager::InstallOutcome;


pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Ostree::get_installed()
}

pub fn install_package(path: &str, token: Option<&AccessToken>) -> Result<InstallOutcome, InstallOutcome> {
    let mut file = File::open(path)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}", err)))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", err)))?;
    let pkg = json::decode::<OstreePackage>(&content)
        .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("parsing file {:?}", e)))?;

    debug!("installing ostree package: {:?}", pkg);
    Ostree::install(pkg, token)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("uptane install failed: {:?}", err)))
        .and_then(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            if (stdout).contains("already installed") {
                Ok((UpdateResultCode::ALREADY_PROCESSED, String::from(stdout)))
            } else {
                Ok((UpdateResultCode::OK, stdout))
            }
        })
}
