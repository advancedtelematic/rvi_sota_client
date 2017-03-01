use std::fmt::{self, Display, Formatter};
use std::str;
use std::str::FromStr;

use nom::{IResult, space, eof};
use datatype::{Auth, ClientCredentials, RegistrationCredentials, Error, InstalledSoftware,
               OstreePackage, Package, UpdateReport, UpdateRequestId, UpdateResultCode};


/// System-wide commands that are sent to the interpreter.
#[derive(RustcDecodable, RustcEncodable, PartialEq, Eq, Debug, Clone)]
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
    StartDownload(UpdateRequestId),
    /// Start installing an update.
    StartInstall(UpdateRequestId),

    /// Install an OSTree package.
    OstreeInstall(OstreePackage),

    /// Send a list of packages to the Core server.
    SendInstalledPackages(Vec<Package>),
    /// Send a list of all packages and firmware to the Core server.
    SendInstalledSoftware(InstalledSoftware),
    /// Send the system information to the Core server.
    SendSystemInfo,
    /// Send a package update report to the Core server.
    SendUpdateReport(UpdateReport),
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let text = match *self {
            //Command::Authenticate(_) => format!("Authenticate ({})", self),
            Command::SendInstalledPackages(_) => format!("{}", "SendInstalledPackages"),
            _ => format!("{:?}", self)
        };
        write!(f, "{}", text)
    }
}

impl FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Command, Error> {
        match command(s.as_bytes()) {
            IResult::Done(_, cmd) => parse_arguments(cmd.0, cmd.1.clone()),
            _                     => Err(Error::Command(format!("bad command: {}", s)))
        }
    }
}


named!(command <(Command, Vec<&str>)>, chain!(
    space?
    ~ cmd: alt!(
        alt_complete!(tag!("Authenticate") | tag!("auth"))
            => { |_| Command::Authenticate(Auth::None) }
        | alt_complete!(tag!("GetUpdateRequests") | tag!("getreq"))
            => { |_| Command::GetUpdateRequests }
        | alt_complete!(tag!("ListInstalledPackages") | tag!("ls"))
            => { |_| Command::ListInstalledPackages }
        | alt_complete!(tag!("ListSystemInfo") | tag!("info"))
            => { |_| Command::ListSystemInfo }
        | alt_complete!(tag!("OstreeInstall") | tag!("osti"))
            => { |_| Command::OstreeInstall(OstreePackage::default()) }
        | alt_complete!(tag!("Shutdown") | tag!("shutdown"))
            => { |_| Command::Shutdown }
        | alt_complete!(tag!("SendInstalledPackages") | tag!("sendpack"))
            => { |_| Command::SendInstalledPackages(Vec::new()) }
        | alt_complete!(tag!("SendInstalledSoftware") | tag!("sendinst"))
            => { |_| Command::SendInstalledSoftware(InstalledSoftware::default()) }
        | alt_complete!(tag!("SendSystemInfo") | tag!("sendinfo"))
            => { |_| Command::SendSystemInfo }
        | alt_complete!(tag!("SendUpdateReport") | tag!("sendup"))
            => { |_| Command::SendUpdateReport(UpdateReport::default()) }
        | alt_complete!(tag!("StartDownload") | tag!("dl"))
            => { |_| Command::StartDownload("".to_string()) }
        | alt_complete!(tag!("StartInstall") | tag!("inst"))
            => { |_| Command::StartInstall("".to_string()) }
    )
        ~ args: arguments
        ~ alt!(eof | tag!("\r") | tag!("\n") | tag!(";")),
    move || { (cmd, args) }
));

named!(arguments <&[u8], Vec<&str> >, chain!(
    args: many0!(chain!(
        space?
        ~ text: map_res!(is_not!(" \t\r\n;"), str::from_utf8)
        ~ space?,
        || { text }
    )),
    move || {
        args.into_iter()
            .filter(|arg| arg.len() > 0)
            .collect()
    }
));

fn parse_arguments(cmd: Command, args: Vec<&str>) -> Result<Command, Error> {
    match cmd {
        Command::Authenticate(_) => match args.len() {
            0 => Ok(Command::Authenticate(Auth::None)),
            1 => Ok(Command::Authenticate(Auth::Registration(RegistrationCredentials {
                client_id:     args[0].to_string()
            }))),
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

        Command::OstreeInstall(_) => match args.len() {
            0 | 1 | 2 => Err(Error::Command("usage: osti <uri> <refname> <commit>".to_string())),
            3 => Ok(Command::OstreeInstall(OstreePackage {
                commit:      args[2].to_string(),
                refName:     args[1].to_string(),
                description: "".to_string(),
                pullUri:     args[0].to_string(),
            })),
            _ => Err(Error::Command(format!("unexpected OstreeInstall args: {:?}", args))),
        },

        Command::SendInstalledPackages(_) => match args.len() {
            0 | 1 => Err(Error::Command("usage: sendpack (<name> <version> )+".to_string())),
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
            _ => Err(Error::Command(format!("SendInstalledPackages expects an even number of 'name version' pairs"))),
        },

        Command::SendInstalledSoftware(_) => match args.len() {
            // FIXME(PRO-1160): args
            _ => Err(Error::Command(format!("unexpected SendInstalledSoftware args: {:?}", args))),
        },

        Command::SendSystemInfo => match args.len() {
            0 => Ok(Command::SendSystemInfo),
            _ => Err(Error::Command(format!("unexpected SendSystemInfo args: {:?}", args))),
        },

        Command::SendUpdateReport(_) => match args.len() {
            0 | 1 => Err(Error::Command("usage: sendup <update-id> <result-code>".to_string())),
            2 => {
                if let Ok(code) = args[1].parse::<UpdateResultCode>() {
                    Ok(Command::SendUpdateReport(UpdateReport::single(args[0].to_string(), code, "".to_string())))
                } else {
                    Err(Error::Command("couldn't parse 2nd argument as an UpdateResultCode".to_string()))
                }
            }
            _ => Err(Error::Command(format!("unexpected SendUpdateReport args: {:?}", args))),
        },

        Command::Shutdown => match args.len() {
            0 => Ok(Command::Shutdown),
            _ => Err(Error::Command(format!("unexpected Shutdown args: {:?}", args))),
        },

        Command::StartDownload(_) => match args.len() {
            0 => Err(Error::Command("usage: dl <id>".to_string())),
            1 => Ok(Command::StartDownload(args[0].to_string())),
            _ => Err(Error::Command(format!("unexpected StartDownload args: {:?}", args))),
        },

        Command::StartInstall(_) => match args.len() {
            0 => Err(Error::Command("usage: inst <id>".to_string())),
            1 => Ok(Command::StartInstall(args[0].to_string())),
            _ => Err(Error::Command(format!("unexpected StartInstall args: {:?}", args))),
        },
    }
}


#[cfg(test)]
mod tests {
    use super::{command, arguments};
    use datatype::{Auth, Command, ClientCredentials, OstreePackage, Package,
                   UpdateReport, UpdateResultCode};
    use nom::IResult;


    #[test]
    fn parse_command_test() {
        assert_eq!(command(&b"auth foo bar"[..]),
                   IResult::Done(&b""[..], (Command::Authenticate(Auth::None), vec!["foo", "bar"])));
        assert_eq!(command(&b"dl 1"[..]),
                   IResult::Done(&b""[..], (Command::StartDownload("".to_string()), vec!["1"])));
        assert_eq!(command(&b"ls;\n"[..]),
                   IResult::Done(&b"\n"[..], (Command::ListInstalledPackages, Vec::new())));
    }

    #[test]
    fn parse_arguments_test() {
        assert_eq!(arguments(&b"one"[..]), IResult::Done(&b""[..], vec!["one"]));
        assert_eq!(arguments(&b"foo bar"[..]), IResult::Done(&b""[..], vec!["foo", "bar"]));
        assert_eq!(arguments(&b"n=5"[..]), IResult::Done(&b""[..], vec!["n=5"]));
        assert_eq!(arguments(&b""[..]), IResult::Done(&b""[..], Vec::new()));
        assert_eq!(arguments(&b" \t some"[..]), IResult::Done(&b""[..], vec!["some"]));
        assert_eq!(arguments(&b";"[..]), IResult::Done(&b";"[..], Vec::new()));
    }


    #[test]
    fn authenticate_test() {
        assert_eq!("Authenticate".parse::<Command>().unwrap(), Command::Authenticate(Auth::None));
        assert_eq!("auth".parse::<Command>().unwrap(), Command::Authenticate(Auth::None));
        assert_eq!("auth user pass".parse::<Command>().unwrap(),
                   Command::Authenticate(Auth::Credentials(ClientCredentials {
                       client_id:     "user".to_string(),
                       client_secret: "pass".to_string(),
                   })));
        assert!("auth one two three".parse::<Command>().is_err());
    }

    #[test]
    fn get_update_requests_test() {
        assert_eq!("GetUpdateRequests".parse::<Command>().unwrap(), Command::GetUpdateRequests);
        assert_eq!("getreq".parse::<Command>().unwrap(), Command::GetUpdateRequests);
        assert!("getreq now".parse::<Command>().is_err());
    }

    #[test]
    fn list_installed_test() {
        assert_eq!("ListInstalledPackages".parse::<Command>().unwrap(), Command::ListInstalledPackages);
        assert_eq!("ls".parse::<Command>().unwrap(), Command::ListInstalledPackages);
        assert!("ls some".parse::<Command>().is_err());
    }

    #[test]
    fn list_system_info_test() {
        assert_eq!("ListSystemInfo".parse::<Command>().unwrap(), Command::ListSystemInfo);
        assert_eq!("info".parse::<Command>().unwrap(), Command::ListSystemInfo);
        assert!("ListSystemInfo 1 2".parse::<Command>().is_err());
        assert!("info please".parse::<Command>().is_err());
    }

    #[test]
    fn ostree_install_test() {
        assert_eq!("OstreeInstall uri ref commit".parse::<Command>().unwrap(),
                   Command::OstreeInstall(OstreePackage {
                       commit:      "commit".to_string(),
                       refName:     "ref".to_string(),
                       description: "".to_string(),
                       pullUri:     "uri".to_string()
                   }));
        assert_eq!("osti 123 456 789".parse::<Command>().unwrap(),
                   Command::OstreeInstall(OstreePackage {
                       commit:      "789".to_string(),
                       refName:     "456".to_string(),
                       description: "".to_string(),
                       pullUri:     "123".to_string()
                   }));
        assert!("OstreeInstall this".parse::<Command>().is_err());
        assert!("osti this that".parse::<Command>().is_err());
    }

    #[test]
    fn send_installed_packages_test() {
        assert_eq!("SendInstalledPackages myname myversion".parse::<Command>().unwrap(),
                   Command::SendInstalledPackages(vec![Package {
                       name:    "myname".to_string(),
                       version: "myversion".to_string()
                   }]));
        assert_eq!("sendpack n1 v1 n2 v2".parse::<Command>().unwrap(),
                   Command::SendInstalledPackages(vec![Package {
                       name:    "n1".to_string(),
                       version: "v1".to_string()
                   }, Package {
                       name:    "n2".to_string(),
                       version: "v2".to_string()
                   }]));
        assert!("SendInstalledPackages some".parse::<Command>().is_err());
        assert!("sendpack 1 2 3".parse::<Command>().is_err());
    }

    #[test]
    fn send_installed_software_test() {
        assert!("SendInstalledSoftware".parse::<Command>().is_err());
        assert!("sendsoft some".parse::<Command>().is_err());
    }

    #[test]
    fn send_system_info_test() {
        assert_eq!("SendSystemInfo".parse::<Command>().unwrap(), Command::SendSystemInfo);
        assert_eq!("sendinfo".parse::<Command>().unwrap(), Command::SendSystemInfo);
        assert!("SendSystemInfo 1 2".parse::<Command>().is_err());
        assert!("sendinfo please".parse::<Command>().is_err());
    }

    #[test]
    fn send_update_report_test() {
        assert_eq!("SendUpdateReport myid OK".parse::<Command>().unwrap(), Command::SendUpdateReport(
            UpdateReport::single("myid".to_string(), UpdateResultCode::OK, "".to_string())));
        assert_eq!("sendup myid 19".parse::<Command>().unwrap(), Command::SendUpdateReport(
            UpdateReport::single("myid".to_string(), UpdateResultCode::GENERAL_ERROR, "".to_string())));
        assert!("sendup myid 20".parse::<Command>().is_err());
        assert!("SendInstalledPackages".parse::<Command>().is_err());
        assert!("sendup 1 2 3".parse::<Command>().is_err());
    }

    #[test]
    fn shutdown_test() {
        assert_eq!("Shutdown".parse::<Command>().unwrap(), Command::Shutdown);
        assert_eq!("shutdown".parse::<Command>().unwrap(), Command::Shutdown);
        assert!("Shutdown 1 2".parse::<Command>().is_err());
        assert!("shutdown now".parse::<Command>().is_err());
    }

    #[test]
    fn start_download_test() {
        assert_eq!("StartDownload this".parse::<Command>().unwrap(), Command::StartDownload("this".to_string()));
        assert_eq!("dl that".parse::<Command>().unwrap(), Command::StartDownload("that".to_string()));
        assert!("StartDownload this and that".parse::<Command>().is_err());
        assert!("dl".parse::<Command>().is_err());
    }

    #[test]
    fn start_install_test() {
        assert_eq!("StartInstall 123".parse::<Command>().unwrap(), Command::StartInstall("123".to_string()));
        assert_eq!("inst this".parse::<Command>().unwrap(), Command::StartInstall("this".to_string()));
        assert!("StartInstall".parse::<Command>().is_err());
        assert!("inst more than one".parse::<Command>().is_err());
    }
}
