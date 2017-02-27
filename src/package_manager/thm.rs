use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;
use std::process::Command;

use datatype::{AccessToken, Error, OstreePackage, Package, UpdateResultCode,
               ostree_installed_packages};
use package_manager::package_manager::InstallOutcome;


pub fn installed_packages() -> Result<Vec<Package>, Error> {
    ostree_installed_packages()
}

pub fn install_package(path: &str, token: Option<&AccessToken>) -> Result<InstallOutcome, InstallOutcome> {
    let mut file = try!(File::open(path)
                        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}", err))));
    let mut content = String::new();
    try!(file.read_to_string(&mut content)
         .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", err))));
    let pkg = try!(json::decode::<OstreePackage>(&content)
                   .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("parsing file {:?}", e))));
    let mut command = Command::new("sota_ostree.sh");
    command.env("COMMIT", pkg.commit)
           .env("REF_NAME", pkg.refName)
           .env("DESCRIPTION", pkg.description)
           .env("PULL_URI", pkg.pullUri);
    token.map(|t| command.env("AUTHPLUS_ACCESS_TOKEN", t.access_token.clone()));
    let output = try!(command.output()
                      .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("running script {:?}", e))));

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
