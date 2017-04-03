use std::process::Command;
use std::str;

use datatype::{Error, Package, InstallCode};
use pacman::{InstallOutcome, parse_packages};


/// Returns a list of installed RPM packages with
/// `rpm -qa --queryformat ${NAME} ${VERSION}\n`.
pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Command::new("rpm")
        .arg("-qa")
        .arg("--queryformat")
        .arg("%{NAME} %{VERSION}\n")
        .output()
        .map_err(|err| Error::PacMan(format!("{}", err)))
        .and_then(|output| Ok(String::from_utf8(output.stdout)?))
        .and_then(|stdout| parse_packages(&stdout))
}

/// Installs a new RPM package with `rpm -Uvh --force <package-path>`.
pub fn install_package(path: &str) -> Result<InstallOutcome, Error> {
    let output = Command::new("rpm").arg("-Uvh").arg("--force").arg(path).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exists = (&stdout).contains("already installed");

    match output.status.code() {
        Some(_) if exists => Ok(InstallOutcome::new(InstallCode::ALREADY_PROCESSED, stdout, stderr)),
        Some(0) => {
            let _ = Command::new("sync").status().map_err(|err| error!("couldn't run 'sync': {}", err));
            Ok(InstallOutcome::new(InstallCode::OK, stdout, stderr))
        }
        _ => Ok(InstallOutcome::new(InstallCode::INSTALL_FAILED, stdout, stderr))
    }
}
