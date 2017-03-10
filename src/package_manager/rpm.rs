use std::process::Command;

use datatype::{Error, Package, UpdateResultCode};
use package_manager::{InstallOutcome, parse_package};


/// Returns a list of installed RPM packages with
/// `rpm -qa --queryformat ${NAME} ${VERSION}\n`.
pub fn installed_packages() -> Result<Vec<Package>, Error> {
    Command::new("rpm").arg("-qa").arg("--queryformat").arg("%{NAME} %{VERSION}\n")
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
                 .filter(|item| item.is_ok())
                 .collect::<Result<Vec<Package>, _>>()
        })
}

/// Installs a new RPM package with `rpm -Uvh --force <package-path>`.
pub fn install_package(path: &str) -> Result<InstallOutcome, InstallOutcome> {
    let output = Command::new("rpm").arg("-Uvh").arg("--force").arg(path)
        .output()
        .map_err(|err| (UpdateResultCode::GENERAL_ERROR, format!("{:?}", err)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    match output.status.code() {
        Some(0) => {
            let _ = Command::new("sync").status().map_err(|err| error!("couldn't run 'sync': {}", err));
            Ok((UpdateResultCode::OK, stdout))
        }

        _ => {
            let out = format!("stdout: {}\nstderr: {}", stdout, stderr);
            if (&stderr).contains("already installed") {
                Ok((UpdateResultCode::ALREADY_PROCESSED, out))
            } else {
                Err((UpdateResultCode::INSTALL_FAILED, out))
            }
        }
    }
}
