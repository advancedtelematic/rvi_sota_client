use std::process::Command;

use datatype::{AccessToken, Error, Package};
use package_manager::package_manager::parse_package;


/// Generate a new system information report.
pub fn system_info(cmd: &str) -> Result<String, Error> {
    Command::new(cmd)
        .output()
        .map_err(|err| Error::SystemInfo(err.to_string()))
        .and_then(|info| String::from_utf8(info.stdout).map_err(Error::FromUtf8))
}


/// Details of a remote OsTree package to pull.
#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
pub struct OstreePackage {
    pub commit:      String,
    pub refName:     String,
    pub description: String,
    pub pullUri:     String
}


/// Install the specified `OstreePackage`.
pub fn ostree_install(pkg: OstreePackage, token: Option<&AccessToken>) -> Result<String, Error> {
    let mut command = Command::new("sota_ostree.sh");
    command.env("COMMIT", pkg.commit)
        .env("REF_NAME", pkg.refName)
        .env("DESCRIPTION", pkg.description)
        .env("PULL_URI", pkg.pullUri);
    token.map(|t| command.env("AUTHPLUS_ACCESS_TOKEN", t.access_token.clone()));

    command.output()
        .map_err(|err| Error::OstreeCommand(err.to_string()))
        .and_then(|ok| String::from_utf8(ok.stdout).map_err(Error::FromUtf8))
}


/// Return a list of installed ostree packages from `/usr/package.manifest`.
pub fn ostree_installed_packages() -> Result<Vec<Package>, Error> {
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
