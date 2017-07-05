use std::process::Command;

use datatype::{Error, Package, InstallCode};
use pacman::{InstallOutcome, parse_packages};


/// Returns a list of installed DEB packages with
/// `dpkg-query -f='${Package} ${Version}\n' -W`.
pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Command::new("dpkg-query")
        .arg("-f='${Package} ${Version}\n'")
        .arg("-W")
        .output()
        .map_err(|err| Error::PacMan(format!("{}", err)))
        .and_then(|output| Ok(String::from_utf8(output.stdout)?))
        .and_then(|stdout| parse_packages(&stdout))
}

/// Installs a new DEB package.
pub fn install_package(path: &str) -> Result<InstallOutcome, Error> {
    let output = Command::new("dpkg").arg("-E").arg("-i").arg(path).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exists = (&stdout).contains("already installed");

    match output.status.code() {
        Some(0) if exists => Ok(InstallOutcome::new(InstallCode::ALREADY_PROCESSED, stdout, stderr)),
        Some(0)           => Ok(InstallOutcome::new(InstallCode::OK, stdout, stderr)),
        _                 => Ok(InstallOutcome::new(InstallCode::INSTALL_FAILED, stdout, stderr))
    }
}
