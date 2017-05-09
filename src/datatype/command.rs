use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use uuid::Uuid;

use datatype::{Auth, ClientCredentials, Error, InstallCode, InstallReport, InstallResult,
               InstalledSoftware, OstreePackage, Package, TufSigned};


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

    /// Send the current manifest to the Director server.
    UptaneSendManifest(Vec<TufSigned>),
    /// Install a list of OSTree packages to their respective ECUs.
    UptaneStartInstall(OstreePackage),
    /// Notification from a remote ECU of an installation outcome.
    UptaneInstallOutcome(TufSigned),
}

impl FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Command, Error> {
        let mut args = s.split_whitespace();
        let arg = args.next().unwrap_or("");
        let cmd = match arg {
            "Authenticate"          => Command::Authenticate(Auth::None),
            "GetUpdateRequests"     => Command::GetUpdateRequests,
            "ListInstalledPackages" => Command::ListInstalledPackages,
            "ListSystemInfo"        => Command::ListSystemInfo,
            "SendInstalledPackages" => Command::SendInstalledPackages(Vec::new()),
            "SendInstalledSoftware" => Command::SendInstalledSoftware(InstalledSoftware::default()),
            "SendSystemInfo"        => Command::SendSystemInfo,
            "SendInstallReport"     => Command::SendInstallReport(InstallReport::default()),
            "Shutdown"              => Command::Shutdown,
            "StartDownload"         => Command::StartDownload(Uuid::default()),
            "StartInstall"          => Command::StartInstall(Uuid::default()),
            "UptaneInstallOutcome"  => Command::UptaneInstallOutcome(TufSigned::default()),
            "UptaneSendManifest"    => Command::UptaneSendManifest(vec![TufSigned::default()]),
            "UptaneStartInstall"    => Command::UptaneStartInstall(OstreePackage::default()),
            _ => return Err(Error::Command(format!("unknown command: {}", arg)))
        };
        parse_arguments(cmd, args.collect::<Vec<_>>())
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Command::SendInstalledPackages(_) => write!(f, "SendInstalledPackages"),
            _ => write!(f, "{:?}", self)
        }
    }
}

fn parse_arguments(cmd: Command, args: Vec<&str>) -> Result<Command, Error> {
    match cmd {
        Command::Authenticate(_) => match args.len() {
            0 => Err(Error::Command("usage: Authenticate <type> | Authenticate <client-id> <client-secret>".to_string())),
            1 if args[0] == "none" => Ok(Command::Authenticate(Auth::None)),
            1 if args[0] == "cert" => Ok(Command::Authenticate(Auth::Certificate)),
            2 => Ok(Command::Authenticate(Auth::Credentials(ClientCredentials {
                client_id:     args[0].to_string(),
                client_secret: args[1].to_string()
            }))),
            _ => Err(Error::Command(format!("unexpected Authenticate args: {:?}", args))),
        },

        Command::GetUpdateRequests => match args.len() {
            0 => Ok(Command::GetUpdateRequests),
            _ => Err(Error::Command(format!("unexpected GetUpdateRequests args: {:?}", args))),
        },

        Command::ListInstalledPackages => match args.len() {
            0 => Ok(Command::ListInstalledPackages),
            _ => Err(Error::Command(format!("unexpected ListInstalledPackages args: {:?}", args))),
        },

        Command::ListSystemInfo => match args.len() {
            0 => Ok(Command::ListSystemInfo),
            _ => Err(Error::Command(format!("unexpected ListSystemInfo args: {:?}", args))),
        },

        Command::SendInstalledPackages(_) => match args.len() {
            0 | 1 => Err(Error::Command("usage: SendInstalledPackages (<name> <version> )+".to_string())),
            n if n % 2 == 0 => {
                let (names, versions): (Vec<(_, &str)>, Vec<(_, &str)>) =
                    args.into_iter().enumerate().partition(|&(n, _)| n % 2 == 0);
                let packages = names.into_iter().zip(versions.into_iter())
                    .map(|((_, name), (_, version))| Package {
                        name:    name.to_string(),
                        version: version.to_string()
                    }).collect::<Vec<Package>>();
                Ok(Command::SendInstalledPackages(packages))
            }
            _ => Err(Error::Command("SendInstalledPackages expects an even number of 'name version' pairs".into())),
        },

        Command::SendInstalledSoftware(_) => match args.len() {
            // FIXME(PRO-1160): args
            _ => Err(Error::Command(format!("unexpected SendInstalledSoftware args: {:?}", args))),
        },

        Command::SendSystemInfo => match args.len() {
            0 => Ok(Command::SendSystemInfo),
            _ => Err(Error::Command(format!("unexpected SendSystemInfo args: {:?}", args))),
        },

        Command::SendInstallReport(_) => match args.len() {
            0 | 1 => Err(Error::Command("usage: SendInstallReport <update-id> <result-code>".to_string())),
            2 => {
                let code = args[1].parse::<InstallCode>().map_err(|err| Error::Command(format!("couldn't parse InstallCode: {}", err)))?;
                Ok(Command::SendInstallReport(InstallResult::new(args[0].into(), code, "".to_string()).into_report()))
            }
            _ => Err(Error::Command(format!("unexpected SendInstallReport args: {:?}", args))),
        },

        Command::Shutdown => match args.len() {
            0 => Ok(Command::Shutdown),
            _ => Err(Error::Command(format!("unexpected Shutdown args: {:?}", args))),
        },

        Command::StartDownload(_) => match args.len() {
            0 => Err(Error::Command("usage: StartDownload <id>".to_string())),
            1 => {
                let uuid = args[0].parse::<Uuid>().map_err(|err| Error::Command(format!("couldn't parse UpdateResultId: {}", err)))?;
                Ok(Command::StartDownload(uuid))
            }
            _ => Err(Error::Command(format!("unexpected StartDownload args: {:?}", args))),
        },

        Command::StartInstall(_) => match args.len() {
            0 => Err(Error::Command("usage: StartInstall <id>".to_string())),
            1 => {
                let uuid = args[0].parse::<Uuid>().map_err(|err| Error::Command(format!("couldn't parse UpdateResultId: {}", err)))?;
                Ok(Command::StartInstall(uuid))
            }
            _ => Err(Error::Command(format!("unexpected StartInstall args: {:?}", args))),
        },

        Command::UptaneInstallOutcome(_) => match args.len() {
            // FIXME(PRO-1160): args
            _ => Err(Error::Command(format!("unexpected UptaneInstallOutcome args: {:?}", args))),
        },

        Command::UptaneSendManifest(_) => match args.len() {
            // FIXME(PRO-1160): args
            _ => Err(Error::Command(format!("unexpected UptaneSendManifest args: {:?}", args))),
        },

        Command::UptaneStartInstall(_) => match args.len() {
            0 | 1 | 2 => Err(Error::Command("usage: UptaneStartInstall <serial> <refname> <commit>".to_string())),
            3 => Ok(Command::UptaneStartInstall(OstreePackage {
                ecu_serial:  args[0].to_string(),
                refName:     args[1].to_string(),
                commit:      args[2].to_string(),
                description: "".to_string(),
                pullUri:     "".to_string(),
            })),
            _ => Err(Error::Command(format!("unexpected UptaneStartInstall args: {:?}", args))),
        },
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use datatype::{Auth, Command, ClientCredentials, OstreePackage, Package, InstallCode};


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
                   Command::SendInstalledPackages(vec![Package {
                       name:    "n1".to_string(),
                       version: "v1".to_string()
                   }, Package {
                       name:    "n2".to_string(),
                       version: "v2".to_string()
                   }]));
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
    fn uptane_install_outcome_test() {
        assert!("UptaneInstallOutcome".parse::<Command>().is_err());
    }

    #[test]
    fn uptane_send_manifest_test() {
        assert!("UptaneSendManifest".parse::<Command>().is_err());
    }

    #[test]
    fn uptane_start_install_test() {
        assert_eq!("UptaneStartInstall serial ref commit".parse::<Command>().unwrap(),
                   Command::UptaneStartInstall(OstreePackage {
                       ecu_serial:  "serial".into(),
                       refName:     "ref".into(),
                       commit:      "commit".into(),
                       description: "".into(),
                       pullUri:     "".into()
                   }));
        assert!("UptaneStartInstall".parse::<Command>().is_err());
        assert!("UptaneStartInstall this".parse::<Command>().is_err());
    }
}
