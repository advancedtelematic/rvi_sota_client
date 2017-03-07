use chan::{Sender, Receiver};
use std;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex};

use datatype::{Auth, Command, Config, Error, Event, OstreePackage, Package, UpdateReport,
               UpdateRequestStatus as Status, UpdateResultCode, system_info};
use gateway::Interpret;
use http::{AuthClient, Client};
use authenticate::oauth2;
use package_manager::PackageManager;
use rvi::Services;
use sota::Sota;
use uptane::Uptane;


/// An `Interpreter` loops over any incoming values, on receipt of which it
/// delegates to the `interpret` function which will respond with output values.
pub trait Interpreter<I, O>: Display {
    fn interpret(&mut self, input: I, otx: &Sender<O>);

    fn run(&mut self, irx: Receiver<I>, otx: Sender<O>) {
        debug!("starting {}", self);
        loop {
            self.interpret(irx.recv().expect("interpreter sender closed"), &otx);
        }
    }
}


/// The `EventInterpreter` listens for `Event`s and may respond `Command`s.
pub struct EventInterpreter {
    pub initial: Auth,
    pub pacman:  PackageManager,
    pub auto_dl: bool,
    pub sysinfo: Option<String>,
}

impl Display for EventInterpreter {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", "EventInterpreter")
    }
}

impl Interpreter<Event, Command> for EventInterpreter {
    fn interpret(&mut self, event: Event, ctx: &Sender<Command>) {
        info!("EventInterpreter received: {}", event);

        match event {
            Event::Authenticated => {
                if self.pacman != PackageManager::Off {
                    self.pacman.installed_packages()
                        .map(|pkgs| ctx.send(Command::SendInstalledPackages(pkgs)))
                        .unwrap_or_else(|err| error!("couldn't send a list of packages: {}", err));
                }

                self.sysinfo.as_ref().map(|_| ctx.send(Command::SendSystemInfo));
            }

            Event::NotAuthenticated => {
                info!("Trying to authenticate again...");
                ctx.send(Command::Authenticate(self.initial.clone()));
            }

            Event::UpdatesReceived(requests) => {
                for request in requests {
                    let id = request.requestId.clone();
                    match request.status {
                        Status::Pending if self.auto_dl => {
                            ctx.send(Command::StartDownload(id));
                        },

                        Status::InFlight if self.pacman != PackageManager::Off => {
                            if self.pacman.is_installed(&request.packageId) {
                                let report = UpdateReport::single(id, UpdateResultCode::OK, "".to_string());
                                return ctx.send(Command::SendUpdateReport(report));
                            }
                            ctx.send(Command::StartDownload(id));
                        }

                        _ => ()
                    }
                }
            }

            Event::DownloadComplete(dl) => {
                if self.pacman != PackageManager::Off {
                    ctx.send(Command::StartInstall(dl.update_id.clone()));
                }
            }

            Event::DownloadFailed(id, reason) => {
                let report = UpdateReport::single(id, UpdateResultCode::GENERAL_ERROR, reason);
                ctx.send(Command::SendUpdateReport(report));
            }

            Event::InstallComplete(report) | Event::InstallFailed(report) => {
                ctx.send(Command::SendUpdateReport(report));
            }

            Event::UpdateReportSent => {
                if self.pacman != PackageManager::Off {
                    self.pacman.installed_packages().map(|packages| {
                        ctx.send(Command::SendInstalledPackages(packages));
                    }).unwrap_or_else(|err| error!("couldn't send a list of packages: {}", err));
                }
            }

            Event::UptaneTargetsUpdated(targets) => {
                for (refname, meta) in targets {
                    let _ = OstreePackage::from(refname, "sha256", meta)
                        .map(|package| ctx.send(Command::OstreeInstall(package)))
                        .map_err(|err| error!("{}", err));
                }
            }

            _ => ()
        }
    }
}


/// The `IntermediateInterpreter` listens for `Command`s and wraps them with a
/// response channel for sending to the `CommandInterpreter`.
pub struct IntermediateInterpreter {
    pub resp_tx: Option<Arc<Mutex<Sender<Event>>>>
}

impl Display for IntermediateInterpreter {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", "IntermediateInterpreter")
    }
}

impl Interpreter<Command, Interpret> for IntermediateInterpreter {
    fn interpret(&mut self, cmd: Command, itx: &Sender<Interpret>) {
        info!("IntermediateInterpreter received: {}", &cmd);
        itx.send(Interpret { command: cmd, resp_tx: self.resp_tx.clone() });
    }
}


/// The `CommandMode` toggles the `Command` handling procedure.
pub enum CommandMode {
    Sota,
    Rvi(Box<Services>),
    Uptane(Uptane)
}

/// The `CommandInterpreter` interprets the `Command` inside incoming `Interpret`
/// messages, broadcasting `Event`s globally and (optionally) sending the final
/// outcome `Event` to the `Interpret` response channel.
pub struct CommandInterpreter {
    pub mode:   CommandMode,
    pub config: Config,
    pub auth:   Auth,
    pub http:   Box<Client>
}

impl Display for CommandInterpreter {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", "CommandInterpreter")
    }
}

impl Interpreter<Interpret, Event> for CommandInterpreter {
    fn interpret(&mut self, interpret: Interpret, etx: &Sender<Event>) {
        info!("CommandInterpreter received: {}", &interpret.command);
        let outcome = match self.auth {
            Auth::None        |
            Auth::Token(_)    |
            Auth::Certificate => self.process_command(interpret.command, etx),

            Auth::Provision      |
            Auth::Credentials(_) => self.authenticate(interpret.command)
        };

        let final_ev = match outcome {
            Ok(ev) => ev,

            Err(Error::HttpAuth(resp)) => {
                error!("HTTP authorization failed: {}", resp);
                Event::NotAuthenticated
            },

            Err(err) => Event::Error(format!("{}", err))
        };
        etx.send(final_ev.clone());
        interpret.resp_tx.map(|tx| tx.lock().unwrap().send(final_ev));
    }
}

impl CommandInterpreter {
    fn process_command(&mut self, cmd: Command, etx: &Sender<Event>) -> Result<Event, Error> {
        let mut sota = Sota::new(&self.config, self.http.as_ref());

        Ok(match cmd {
            Command::Authenticate(_) => Event::AlreadyAuthenticated,

            Command::GetUpdateRequests => {
                match self.mode {
                    CommandMode::Sota   |
                    CommandMode::Rvi(_) => {
                        let mut updates = sota.get_update_requests()?;
                        if updates.is_empty() {
                            Event::NoUpdateRequests
                        } else {
                            updates.sort_by_key(|u| u.installPos);
                            Event::UpdatesReceived(updates)
                        }
                    }

                    CommandMode::Uptane(ref mut uptane) => {
                        // FIXME: put manifest only on startup and after install
                        let client = self.http.as_ref();
                        uptane.put_manifest(client)?;
                        let _ = uptane.get_root(client, true)?;

                        let (_, ts_new) = uptane.get_timestamp(client, true)?;
                        if ts_new {
                            let (targets, _) = uptane.get_targets(client, true)?;
                            Event::UptaneTargetsUpdated(targets.targets)
                        } else {
                            Event::UptaneTimestampUpdated
                        }
                    }

                }
            }

            Command::ListInstalledPackages => {
                let mut packages: Vec<Package> = Vec::new();
                if self.config.device.package_manager != PackageManager::Off {
                    packages = try!(self.config.device.package_manager.installed_packages());
                }
                Event::FoundInstalledPackages(packages)
            }

            Command::ListSystemInfo => {
                let cmd = self.config.device.system_info.as_ref().expect("system_info command not set");
                Event::FoundSystemInfo(try!(system_info(&cmd)))
            }

            Command::OstreeInstall(pkg) => {
                let id = pkg.commit.clone();
                let token = if let Auth::Token(ref t) = self.auth { Some(t) } else { None };
                match pkg.install(token) {
                    Ok((code, out))  => Event::InstallComplete(UpdateReport::single(id, code, out)),
                    Err((code, out)) => Event::InstallFailed(UpdateReport::single(id, code, out))
                }
            }

            Command::SendInstalledPackages(packages) => {
                try!(sota.send_installed_packages(&packages));
                Event::InstalledPackagesSent
            }

            Command::SendInstalledSoftware(sw) => {
                match self.mode {
                    CommandMode::Rvi(ref rvi) => {
                        let _ = rvi.remote.lock().unwrap().send_installed_software(sw);
                        Event::InstalledSoftwareSent
                    }

                    _ => Event::InstalledSoftwareSent
                }
            }

            Command::SendSystemInfo => {
                let cmd = self.config.device.system_info.as_ref().expect("system_info command not set");
                try!(sota.send_system_info(&try!(system_info(&cmd))));
                Event::SystemInfoSent
            }

            Command::SendUpdateReport(report) => {
                match self.mode {
                    CommandMode::Rvi(ref rvi) => {
                        let _ = rvi.remote.lock().unwrap().send_update_report(report);
                        Event::UpdateReportSent
                    }

                    _ => {
                        sota.send_update_report(&report)?;
                        Event::UpdateReportSent
                    }
                }
            }

            Command::StartDownload(id) => {
                match self.mode {
                    CommandMode::Rvi(ref rvi) => {
                        let _ = rvi.remote.lock().unwrap().send_download_started(id.clone());
                        Event::DownloadingUpdate(id)
                    }

                    _ => {
                        etx.send(Event::DownloadingUpdate(id.clone()));
                        match sota.download_update(id.clone()) {
                            Ok(dl)   => Event::DownloadComplete(dl),
                            Err(err) => Event::DownloadFailed(id, format!("{}", err))
                        }
                    }
                }
            }

            Command::StartInstall(id) => {
                match self.mode {
                    CommandMode::Rvi(ref rvi) => {
                        let _ = rvi.remote.lock().unwrap().send_download_started(id.clone());
                        Event::DownloadingUpdate(id)
                    }

                    _ => {
                        etx.send(Event::InstallingUpdate(id.clone()));
                        let token = if let Auth::Token(ref t) = self.auth { Some(t) } else { None };
                        match sota.install_update(token, id) {
                            Ok(report)  => Event::InstallComplete(report),
                            Err(report) => Event::InstallFailed(report)
                        }
                    }
                }
            }

            Command::Shutdown => std::process::exit(0),
        })
    }

    fn authenticate(&mut self, cmd: Command) -> Result<Event, Error> {
        Ok(match cmd {
            Command::Authenticate(Auth::None)        |
            Command::Authenticate(Auth::Token(_))    |
            Command::Authenticate(Auth::Certificate) => Event::Authenticated,

            Command::Authenticate(Auth::Credentials(creds)) => {
                let cfg = self.config.auth.as_ref().expect("auth config required");
                if !self.http.is_testing() {
                    self.http = Box::new(AuthClient::from(Auth::Credentials(creds)));
                }

                let token = oauth2(cfg.server.join("/token"), self.http.as_ref())?;
                self.auth = Auth::Token(token.clone());
                if !self.http.is_testing() {
                    self.http = Box::new(AuthClient::from(Auth::Token(token)));
                }

                Event::Authenticated
            }

            Command::Authenticate(Auth::Provision) => {
                self.auth = Auth::Certificate;
                if !self.http.is_testing() {
                    self.http = Box::new(AuthClient::from(Auth::Certificate));
                }

                Event::Authenticated
            }

            Command::Shutdown => std::process::exit(0),

            _ => Event::NotAuthenticated
        })
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use chan::{Sender, Receiver};
    use std::thread;

    use super::*;
    use datatype::{Auth, Command, Config, DownloadComplete, Event,
                   UpdateReport, UpdateResultCode};
    use gateway::Interpret;
    use http::test_client::TestClient;
    use package_manager::{PackageManager, assert_rx};


    fn new_interpreter(mut ci: CommandInterpreter) -> (Sender<Command>, Receiver<Event>) {
        let (etx, erx) = chan::sync::<Event>(0);
        let (ctx, crx) = chan::sync::<Command>(0);

        thread::spawn(move || {
            loop {
                match crx.recv() {
                    Some(cmd) => ci.interpret(Interpret { command: cmd, resp_tx: None }, &etx),
                    None      => break
                }
            }
        });

        (ctx, erx)
    }

    #[test]
    fn already_authenticated() {
        let vec: Vec<String> = Vec::new();
        let mut ci = CommandInterpreter {
            mode:   CommandMode::Sota,
            config: Config::default(),
            auth:   Auth::None,
            http:   Box::new(TestClient::from(vec))
        };
        ci.config.device.package_manager = PackageManager::new_tpm(true);
        let (ctx, erx) = new_interpreter(ci);

        ctx.send(Command::Authenticate(Auth::None));
        assert_rx(erx, &[Event::AlreadyAuthenticated]);
    }

    #[test]
    fn download_updates() {
        let mut ci = CommandInterpreter {
            mode:   CommandMode::Sota,
            config: Config::default(),
            auth:   Auth::None,
            http:   Box::new(TestClient::from(vec!["[]".to_string(); 10]))
        };
        ci.config.device.package_manager = PackageManager::new_tpm(true);
        let (ctx, erx) = new_interpreter(ci);

        ctx.send(Command::StartDownload("1".to_string()));
        assert_rx(erx, &[
            Event::DownloadingUpdate("1".to_string()),
            Event::DownloadComplete(DownloadComplete {
                update_id:    "1".to_string(),
                update_image: "/tmp/1".to_string(),
                signature:    "".to_string()
            })
        ]);
    }

    #[test]
    fn install_update_success() {
        let mut ci = CommandInterpreter {
            mode:   CommandMode::Sota,
            config: Config::default(),
            auth:   Auth::None,
            http:   Box::new(TestClient::from(vec!["[]".to_string(); 10]))
        };
        ci.config.device.package_manager = PackageManager::new_tpm(true);
        let (ctx, erx) = new_interpreter(ci);

        ctx.send(Command::StartInstall("1".to_string()));
        assert_rx(erx, &[
            Event::InstallingUpdate("1".to_string()),
            Event::InstallComplete(
                UpdateReport::single("1".to_string(), UpdateResultCode::OK, "".to_string())
            )
        ]);
    }

    #[test]
    fn install_update_failed() {
        let mut ci = CommandInterpreter {
            mode:   CommandMode::Sota,
            config: Config::default(),
            auth:   Auth::None,
            http:   Box::new(TestClient::from(vec!["[]".to_string(); 10]))
        };
        ci.config.device.package_manager = PackageManager::new_tpm(false);
        let (ctx, erx) = new_interpreter(ci);

        ctx.send(Command::StartInstall("1".to_string()));
        assert_rx(erx, &[
            Event::InstallingUpdate("1".to_string()),
            Event::InstallFailed(
                UpdateReport::single("1".to_string(), UpdateResultCode::INSTALL_FAILED, "failed".to_string())
            )
        ]);
    }
}
