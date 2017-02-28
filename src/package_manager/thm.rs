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
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("parsing file {:?}", err)))?;

    let output = Ostree::install(pkg, token)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("installing package: {}", err)))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    match output.status.code() {
        Some(0) => {
            if (&stdout).contains("already installed") {
                Ok((UpdateResultCode::ALREADY_PROCESSED, stdout))
            } else {
                Ok((UpdateResultCode::OK, stdout))
            }
        }

        _ => {
            let out = format!("stdout: {}\nstderr: {}", stdout, stderr);
            Err((UpdateResultCode::INSTALL_FAILED, out))
        }
    }
}
