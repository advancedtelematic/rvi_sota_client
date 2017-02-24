use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;
use std::process::Command;

use datatype::{Error, Package, UpdateResultCode};
use datatype::auth::AccessToken;
use package_manager::package_manager::{InstallOutcome, parse_package};


pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Command::new("cat")
        .arg("/usr/package.manifest")
        .output()
        .map_err(|e| Error::Package(format!("Error fetching packages: {}", e)))
        .and_then(|c| {
            String::from_utf8(c.stdout)
                .map_err(|e| Error::Parse(format!("Error parsing package: {}", e)))
                .map(|s| s.lines().map(String::from).collect::<Vec<String>>())
        })
        .and_then(|lines| {
            lines.iter()
                 .map(|line| parse_package(line))
                 .filter(|pkg| pkg.is_ok())
                 .collect::<Result<Vec<Package>, _>>()
        })
}

#[derive(RustcDecodable)]
#[allow(non_snake_case)]
struct OstreePackage {
    commit:      String,
    refName:     String,
    description: String,
    pullUri:     String,
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
