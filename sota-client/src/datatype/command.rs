use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use uuid::Uuid;

use datatype::{Auth, ClientCredentials, Error, InstallCode, InstallReport,
               InstallResult, InstalledSoftware, Manifests, Package};
use uptane::Verified;


/// System-wide commands that are sent to the interpreter.
#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub enum Command {
    /// Authenticate with the auth server.
    Authenticate(Auth),
    /// Shutdown the client immediately.
    Shutdown,

    /// Check for any pending or in-flight updates.
    GetUpdateRequests,

    /// List the installed packages on the system.
    ListInstalledPackages,
    /// List the system information.
    ListSystemInfo,

    /// Start downloading an update.
    StartDownload(Uuid),
    /// Start installing an update.
    StartInstall(Uuid),

    /// Send a list of installed packages.
    SendInstalledPackages(Vec<Package>),
    /// Send a list of installed packages and firmware.
    SendInstalledSoftware(InstalledSoftware),
    /// Send a hardware report.
    SendSystemInfo,
    /// Send an installation report.
    SendInstallReport(InstallReport),

    /// Send signed reports from ECUs to the Director server.
    UptaneSendManifest(Option<Manifests>),
    /// Install the verified targets.json metadata to their respective ECUs.
    UptaneStartInstall(Box<Verified>),
}

impl FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Command, Error> {
        let mut args = s.split_whitespace();
        let cmd = args.next().unwrap_or("");
        let args = args.collect::<Vec<_>>();

        match cmd {
            "Authenticate" => match args.len() {
                0 => Err(Error::Command("usage: Authenticate <type> | Authenticate <client-id> <client-secret>".to_string())),
                1 if args[0] == "none" => Ok(Command::Authenticate(Auth::None)),
                1 if args[0] == "cert" => Ok(Command::Authenticate(Auth::Certificate)),
                2 => {
                    let creds = ClientCredentials { client_id: args[0].into(), client_secret: args[1].into() };
                    Ok(Command::Authenticate(Auth::Credentials(creds)))
                },
                _ => Err(Error::Command(format!("unexpected Authenticate args: {:?}", args))),
            },

            "GetUpdateRequests" => match args.len() {
                0 => Ok(Command::GetUpdateRequests),
                _ => Err(Error::Command(format!("unexpected GetUpdateRequests args: {:?}", args))),
            },

            "ListInstalledPackages" => match args.len() {
                0 => Ok(Command::ListInstalledPackages),
                _ => Err(Error::Command(format!("unexpected ListInstalledPackages args: {:?}", args))),
            },

            "ListSystemInfo" => match args.len() {
                0 => Ok(Command::ListSystemInfo),
                _ => Err(Error::Command(format!("unexpected ListSystemInfo args: {:?}", args))),
            },

            "SendInstalledPackages" => match args.len() {
                0 | 1 => Err(Error::Command("usage: SendInstalledPackages (<name> <version>)+".to_string())),
                n if n % 2 == 0 => {
                    let packages = args.chunks(2)
                        .map(|chunk| Package { name: chunk[0].into(), version: chunk[1].into() })
                        .collect::<Vec<Package>>();
                    Ok(Command::SendInstalledPackages(packages))
                }
                _ => Err(Error::Command("SendInstalledPackages expects an even number of 'name version' pairs".into())),
            },

            "SendInstalledSoftware" => match args.len() {
                // FIXME(PRO-1160): args
                _ => Err(Error::Command(format!("unexpected SendInstalledSoftware args: {:?}", args))),
            },

            "SendSystemInfo" => match args.len() {
                0 => Ok(Command::SendSystemInfo),
                _ => Err(Error::Command(format!("unexpected SendSystemInfo args: {:?}", args))),
            },

            "SendInstallReport" => match args.len() {
                0 | 1 => Err(Error::Command("usage: SendInstallReport <update-id> <result-code>".to_string())),
                2 => {
                    let code = args[1].parse::<InstallCode>().map_err(|err| Error::Command(format!("couldn't parse InstallCode: {}", err)))?;
                    Ok(Command::SendInstallReport(InstallResult::new(args[0].into(), code, "".to_string()).into_report()))
                }
                _ => Err(Error::Command(format!("unexpected SendInstallReport args: {:?}", args))),
            },

            "Shutdown" => match args.len() {
                0 => Ok(Command::Shutdown),
                _ => Err(Error::Command(format!("unexpected Shutdown args: {:?}", args))),
            },

            "StartDownload" => match args.len() {
                0 => Err(Error::Command("usage: StartDownload <id>".to_string())),
                1 => {
                    let uuid = args[0].parse::<Uuid>().map_err(|err| Error::Command(format!("couldn't parse UpdateResultId: {}", err)))?;
                    Ok(Command::StartDownload(uuid))
                }
                _ => Err(Error::Command(format!("unexpected StartDownload args: {:?}", args))),
            },

            "StartInstall" => match args.len() {
                0 => Err(Error::Command("usage: StartInstall <id>".to_string())),
                1 => {
                    let uuid = args[0].parse::<Uuid>().map_err(|err| Error::Command(format!("couldn't parse UpdateResultId: {}", err)))?;
                    Ok(Command::StartInstall(uuid))
                }
                _ => Err(Error::Command(format!("unexpected StartInstall args: {:?}", args))),
            },

            "UptaneSendManifest" => match args.len() {
                // FIXME(PRO-1160): args
                _ => Err(Error::Command(format!("unexpected UptaneSendManifest args: {:?}", args))),
            },

            "UptaneStartInstall" => match args.len() {
                _ => Err(Error::Command(format!("unexpected UptaneStartInstall args: {:?}", args))),
            },

            _ => Err(Error::Command(format!("unknown command: {}", cmd)))
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Command::SendInstalledPackages(_) => write!(f, "SendInstalledPackages"),
            Command::UptaneStartInstall(ref verified) => {
                write!(f, "UptaneStartInstall(role: {}, data: {:?}, new_ver: {}, old_ver: {})",
                       verified.role, verified.data, verified.new_ver, verified.old_ver)
            }
            _ => write!(f, "{:?}", self)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use datatype::{Auth, Command, ClientCredentials, Package, InstallCode};


    const DEFAULT_UUID: &'static str = "00000000-0000-0000-0000-000000000000";

    #[test]
    fn authenticate_test() {
        assert_eq!("Authenticate none".parse::<Command>().unwrap(), Command::Authenticate(Auth::None));
        assert!("Authenticate".parse::<Command>().is_err());
        assert!("Authenticate one".parse::<Command>().is_err());
        assert_eq!("Authenticate cert".parse::<Command>().unwrap(), Command::Authenticate(Auth::Certificate));
        assert_eq!("Authenticate user pass".parse::<Command>().unwrap(),
                   Command::Authenticate(Auth::Credentials(ClientCredentials {
                       client_id:     "user".to_string(),
                       client_secret: "pass".to_string(),
                   })));
        assert!("Authenticate one two three".parse::<Command>().is_err());
    }

    #[test]
    fn get_update_requests_test() {
        assert_eq!("GetUpdateRequests".parse::<Command>().unwrap(), Command::GetUpdateRequests);
        assert!("GetUpdateRequests old".parse::<Command>().is_err());
    }

    #[test]
    fn list_installed_test() {
        assert_eq!("ListInstalledPackages".parse::<Command>().unwrap(), Command::ListInstalledPackages);
        assert!("ListInstalledPackages some".parse::<Command>().is_err());
    }

    #[test]
    fn list_system_info_test() {
        assert_eq!("ListSystemInfo".parse::<Command>().unwrap(), Command::ListSystemInfo);
        assert!("ListSystemInfo please".parse::<Command>().is_err());
    }

    #[test]
    fn send_install_report_test() {
        assert_eq!("SendInstallReport id 0".parse::<Command>().unwrap(),
                   Command::SendInstallReport(InstallResult::new("id".into(), InstallCode::OK, "".to_string()).into_report()));
        assert_eq!("SendInstallReport 123 19".parse::<Command>().unwrap(),
                   Command::SendInstallReport(InstallResult::new("123".into(), InstallCode::GENERAL_ERROR, "".to_string()).into_report()));
        assert!("SendInstallReport id 20".parse::<Command>().is_err());
        assert!("SendInstallReport id 0 extra".parse::<Command>().is_err());
    }

    #[test]
    fn send_installed_packages_test() {
        assert_eq!("SendInstalledPackages n1 v1 n2 v2".parse::<Command>().unwrap(),
                   Command::SendInstalledPackages(vec![
                       Package { name: "n1".into(), version: "v1".into() },
                       Package { name: "n2".into(), version: "v2".into() },
                   ]));
        assert!("SendInstalledPackages".parse::<Command>().is_err());
        assert!("SendInstalledPackages n1 v1 n2".parse::<Command>().is_err());
    }

    #[test]
    fn send_installed_software_test() {
        assert!("SendInstalledSoftware".parse::<Command>().is_err());
        assert!("SendInstalledSoftware some".parse::<Command>().is_err());
    }

    #[test]
    fn send_system_info_test() {
        assert_eq!("SendSystemInfo".parse::<Command>().unwrap(), Command::SendSystemInfo);
        assert!("SendSystemInfo please".parse::<Command>().is_err());
    }

    #[test]
    fn shutdown_test() {
        assert_eq!("Shutdown".parse::<Command>().unwrap(), Command::Shutdown);
        assert!("Shutdown now".parse::<Command>().is_err());
    }

    #[test]
    fn start_download_test() {
        assert_eq!(format!("StartDownload {}", DEFAULT_UUID).parse::<Command>().unwrap(),
                   Command::StartDownload(Uuid::default()));
        assert!("StartDownload".parse::<Command>().is_err());
        assert!(format!("StartDownload {} extra", DEFAULT_UUID).parse::<Command>().is_err());
    }

    #[test]
    fn start_install_test() {
        assert_eq!(format!("StartInstall {}", DEFAULT_UUID).parse::<Command>().unwrap(),
                   Command::StartInstall(Uuid::default()));
        assert!("StartInstall".parse::<Command>().is_err());
        assert!(format!("StartInstall {} extra", DEFAULT_UUID).parse::<Command>().is_err());
    }

    #[test]
    fn uptane_send_manifest_test() {
        assert!("UptaneSendManifest".parse::<Command>().is_err());
    }

    #[test]
    fn uptane_start_install_test() {
        assert!("UptaneStartInstall".parse::<Command>().is_err());
    }
}
