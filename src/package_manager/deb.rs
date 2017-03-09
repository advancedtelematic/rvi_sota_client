use std::process::Command;

use datatype::{Error, Package, UpdateResultCode};
use package_manager::{InstallOutcome, parse_package};


/// Returns a list of installed DEB packages with
/// `dpkg-query -f='${Package} ${Version}\n' -W`.
pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Command::new("dpkg-query").arg("-f='${Package} ${Version}\n'").arg("-W")
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

/// Installs a new DEB package.
pub fn install_package(path: &str) -> Result<InstallOutcome, InstallOutcome> {
    let output = try!(Command::new("dpkg").arg("-E").arg("-i").arg(path)
        .output()
        .map_err(|e| (UpdateResultCode::GENERAL_ERROR, format!("{:?}", e))));

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
