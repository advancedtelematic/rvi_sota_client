use rustc_serialize::json;
use std::fs::File;
use std::io::prelude::*;

use datatype::{Error, OstreePackage, Package, UpdateResultCode};
use package_manager::{Credentials, InstallOutcome, parse_package};


pub fn installed_packages() -> Result<Vec<Package>, Error> {
    let mut file = File::open("/usr/packages.manifest")
        .map_err(|err| Error::Config(format!("couldn't open `/usr/packages.manifest`: {}", err)))?;
    let mut packages = String::new();
    file.read_to_string(&mut packages)
        .map_err(|err| Error::Package(format!("couldn't read `/usr/packages.manifest`: {}", err)))?;

    packages.lines()
        .map(|line| parse_package(line))
        .filter(|pkg| pkg.is_ok())
        .collect::<Result<Vec<Package>, _>>()
}

pub fn install_package(path: &str, creds: Credentials) -> Result<InstallOutcome, InstallOutcome> {
    let mut file = File::open(path)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("open file: {:?}", err)))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("reading file: {:?}", err)))?;
    let pkg = json::decode::<OstreePackage>(&content)
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("parsing file: {:?}", err)))?;

    match pkg.install(creds) {
        Ok(out @ (UpdateResultCode::INSTALL_FAILED, _)) => Err(out),
        Ok(out) => Ok(out),
        Err(err) => {
            error!("couldn't install ostree package: {}", err);
            Err((UpdateResultCode::GENERAL_ERROR, format!("installing package: {:?}", err)))
        }
    }
}
