pub mod auth;
pub mod command;
pub mod config;
pub mod dbus;
pub mod error;
pub mod event;
pub mod json_rpc;
pub mod network;
pub mod report;
pub mod request;
pub mod ostree;
pub mod tuf;
pub mod verify;

pub use self::auth::{AccessToken, Auth, ClientCredentials};
pub use self::command::Command;
pub use self::config::{AuthConfig, CoreConfig, Config, DBusConfig, DeviceConfig,
                       GatewayConfig, RviConfig, TlsConfig, UptaneConfig};
pub use self::error::Error;
pub use self::event::Event;
pub use self::json_rpc::{RpcRequest, RpcOk, RpcErr};
pub use self::network::{Method, SocketAddr, Url};
pub use self::report::{DeviceReport, InstalledFirmware, InstalledPackage, InstalledSoftware,
                       OperationResult, UpdateResultCode, UpdateReport, system_info};
pub use self::request::{ChunkReceived, DownloadComplete, DownloadFailed, DownloadStarted, Package,
                        UpdateAvailable, UpdateRequest, UpdateRequestId, UpdateRequestStatus};
pub use self::ostree::{Ostree, OstreeBranch, OstreePackage};
pub use self::tuf::{EcuManifests, EcuVersion, Key, KeyValue, PrivateKey, Role, RoleData,
                    Root, Signature, Snapshot, Targets, Timestamp, TufCustom, TufImage,
                    TufMeta, TufRole, TufSigned};
pub use self::verify::{KeyType, SigType, Verifier};


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
            stdin.write(bytes)?;
            stdin.flush()?;
        }
        None => return Err(Error::Command(String::from("unable to write to stdin"))),
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        Err(Error::Command(format!("Error with canonical_json.py: exit: {} out: {} err: {}",
                                   output.status,
                                   String::from_utf8(output.stdout).unwrap_or("<stdout not utf8>".to_string()),
                                   String::from_utf8(output.stderr).unwrap_or("<stderr not utf8>".to_string()))))
    } else {
        Ok(output.stdout)
    }
}
