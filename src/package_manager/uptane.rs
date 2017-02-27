use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;

use datatype::{AccessToken, Error, OstreePackage, Package, UpdateResultCode,
               ostree_install, ostree_installed_packages};
use package_manager::package_manager::InstallOutcome;


pub fn installed_packages() -> Result<Vec<Package>, Error> {
    ostree_installed_packages()
}

pub fn install_package(path: &str, token: Option<&AccessToken>) -> Result<InstallOutcome, InstallOutcome> {
    let mut file = File::open(path)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}", err)))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", err)))?;
    let pkg = json::decode::<OstreePackage>(&content)
        .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("parsing file {:?}", e)))?;

    debug!("installing uptane package: {:?}", pkg);
    ostree_install(pkg, token)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("uptane ostree_install failed: {:?}", err)))
        .and_then(|stdout| {
            if (&stdout).contains("already installed") {
                Ok((UpdateResultCode::ALREADY_PROCESSED, stdout))
            } else {
                Ok((UpdateResultCode::OK, stdout))
            }
        })
}
