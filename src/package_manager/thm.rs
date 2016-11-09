use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;
use std::process::Command;

use datatype::{Error, Package, UpdateResultCode};
use package_manager::package_manager::InstallOutcome;

pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Ok(vec![])
}

#[derive(RustcDecodable)]
#[allow(non_snake_case)] // RustcDecodable don't allow us to rename fields yet
struct TreeHubPackage {
    commit: String,
    refName: String,
    description: String,
    pullUri: String,
}

pub fn install_package(path: &str) -> Result<InstallOutcome, InstallOutcome> {
    let mut file = try!(File::open(path)
      .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}",e))));
    let mut content = String::new();
    try!(file.read_to_string(&mut content)
         .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", e))));
    let pkg = try!(json::decode::<TreeHubPackage>(&content)
                   .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("parsing file {:?}", e))));
    let output = try!(Command::new("sota_ostree.sh")
        .env("COMMIT", pkg.commit)
        .env("REF_NAME", pkg.refName)
        .env("DESCRIPTION", pkg.description)
        .env("PULL_URI", pkg.pullUri)
        .output()
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
