use std::process::Command;

use datatype::{Error, Package, UpdateResultCode};
use pacman::{InstallOutcome, parse_package};


/// Returns a list of installed DEB packages with
/// `dpkg-query -f='${Package} ${Version}\n' -W`.
pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Command::new("dpkg-query").arg("-f='${Package} ${Version}\n'").arg("-W")
        .output()
        .map_err(|err| Error::Pacman(format!("Error fetching packages: {}", err)))
        .and_then(|c| {
            String::from_utf8(c.stdout)
                .map_err(|err| Error::Parse(format!("Error parsing package: {}", err)))
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
    let output = Command::new("dpkg").arg("-E").arg("-i").arg(path)
        .output()
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("{:?}", err)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exists = (&stdout).contains("already installed");

    match output.status.code() {
        Some(0) if exists => Ok((UpdateResultCode::ALREADY_PROCESSED, stdout)),
        Some(0)           => Ok((UpdateResultCode::OK, stdout)),
        _                 => Err((UpdateResultCode::INSTALL_FAILED,
                                  format!("stdout: {}\nstderr: {}", stdout, stderr)))
    }
}
