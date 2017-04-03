pub mod auth;
pub mod command;
pub mod config;
pub mod download;
pub mod error;
pub mod event;
pub mod install;
pub mod network;
pub mod ostree;
pub mod tuf;
pub mod verify;

pub use self::auth::{AccessToken, Auth, ClientCredentials};
pub use self::command::Command;
pub use self::config::{AuthConfig, CoreConfig, Config, DBusConfig, DeviceConfig,
                       GatewayConfig, RviConfig, TlsConfig, UptaneConfig};
pub use self::download::{DownloadComplete, DownloadFailed, Package, RequestStatus,
                         UpdateAvailable, UpdateRequest};
pub use self::error::Error;
pub use self::event::Event;
pub use self::install::{InstallCode, InstallOutcome, InstallReport, InstallResult,
                        InstalledFirmware, InstalledPackage, InstalledSoftware};
pub use self::network::{Method, SocketAddr, Url};
pub use self::ostree::OstreePackage;
pub use self::tuf::{EcuCustom, EcuManifests, EcuVersion, Key, KeyValue, PrivateKey,
                    RoleData, RoleName, RoleMeta, Signature, TufCustom, TufImage,
                    TufMeta, TufRole, TufSigned};
pub use self::verify::{KeyType, SigType, Verified, Verifier};


// TODO remove this ugly hack ASAP
use std::process::{Command as ShellCommand, Stdio};
use std::io::Write;
/// Shell exec out to Python to get canonical json bytes
pub fn canonicalize_json(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut child = ShellCommand::new("canonical_json.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| Error::Command(format!("couldn't run canonical_json.py: {}", err)))?;

    match child.stdin.as_mut() {
        Some(mut stdin) => {
            stdin.write_all(bytes)?;
            stdin.flush()?;
        }
        None => return Err(Error::Command(String::from("unable to write to stdin"))),
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Command(format!("canonical_json.py exit {}: stdout: {}, stderr: {}", output.status, stdout, stderr)))
    } else {
        Ok(output.stdout)
    }
}
